// (c) Javier Fernandez @ JotaSoft 2026
//! CTAPHID over the key's native USB full-speed device.
//!
//! One HID interface with the FIDO report descriptor (usage page `0xF1D0`, usage `0x01`,
//! 64-byte input and output reports on interrupt endpoints). Reports go straight into the
//! core's [`CtapHid`] state machine; complete requests go to the authenticator task, and
//! replies and keepalives come back as 64-byte reports. Nothing else is ever sent on USB:
//! the log goes over SWD (defmt RTT).

use embassy_futures::join::join;
use embassy_futures::select::{Either4, select4};
use embassy_stm32::peripherals::USB;
use embassy_stm32::usb::Driver;
use embassy_time::{Instant, Timer};
use embassy_usb::class::hid::{Config as HidConfig, HidBootProtocol, HidReaderWriter, HidSubclass, State};
use embassy_usb::{Builder, Config};
use heapless::Vec;
use jotakey_core::status::Status;
use jotakey_core::transport::ctaphid::{CtapHid, HidEvent, PACKET_SIZE, Packet};
use static_cell::StaticCell;

use crate::link::{CANCEL, KEEPALIVE, LED, LedState, REPLY, REQUESTS};

/// pid.codes test VID/PID: development only, to be replaced by an allocated PID before any
/// release.
const VID: u16 = 0x1209;
const PID: u16 = 0x0001;

/// FIDO Alliance HID report descriptor (CTAP 2.1 §11.2.8.1).
#[rustfmt::skip]
const REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01,       // Usage (CTAPHID)
    0xA1, 0x01,       // Collection (Application)
    0x09, 0x20,       //   Usage (Input Report Data)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8)
    0x95, 0x40,       //   Report Count (64)
    0x81, 0x02,       //   Input (Data, Var, Abs)
    0x09, 0x21,       //   Usage (Output Report Data)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8)
    0x95, 0x40,       //   Report Count (64)
    0x91, 0x02,       //   Output (Data, Var, Abs)
    0xC0,             // End Collection
];

static CONFIG_DESCRIPTOR: StaticCell<[u8; 64]> = StaticCell::new();
static BOS_DESCRIPTOR: StaticCell<[u8; 32]> = StaticCell::new();
static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
static HID_STATE: StaticCell<State<'static>> = StaticCell::new();
static HID: StaticCell<CtapHid> = StaticCell::new();

#[embassy_executor::task]
pub async fn usb_task(driver: Driver<'static, USB>) {
    let mut config = Config::new(VID, PID);
    config.manufacturer = Some("JotaSoft");
    config.product = Some("jotakey");
    config.serial_number = None; // no per-device identifier on the bus
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 64]),
        BOS_DESCRIPTOR.init([0; 32]),
        &mut [], // no Microsoft OS descriptors
        CONTROL_BUF.init([0; 64]),
    );
    let hid_config = HidConfig {
        report_descriptor: &REPORT_DESCRIPTOR,
        request_handler: None,
        poll_ms: 5,
        max_packet_size: 64,
        hid_subclass: HidSubclass::No,
        hid_boot_protocol: HidBootProtocol::None,
    };
    let hid_io =
        HidReaderWriter::<_, PACKET_SIZE, PACKET_SIZE>::new(&mut builder, HID_STATE.init(State::new()), hid_config);
    let mut device = builder.build();
    let (mut reader, mut writer) = hid_io.split();

    let ctap = async {
        let hid = HID.init(CtapHid::new());
        let mut busy_channel: Option<u32> = None;
        let mut report: Packet = [0; PACKET_SIZE];
        loop {
            let now = Instant::now().as_millis();
            match select4(reader.read(&mut report), REPLY.receive(), KEEPALIVE.wait(), Timer::after_millis(50)).await {
                Either4::First(Ok(PACKET_SIZE)) => match hid.handle_packet(&report, now) {
                    HidEvent::Request { channel } => {
                        let mut data = Vec::new();
                        let _ = data.extend_from_slice(hid.request());
                        if REQUESTS.try_send(data).is_ok() {
                            busy_channel = Some(channel);
                        } else {
                            hid.respond(channel, &[Status::ChannelBusy.code()]);
                        }
                    }
                    HidEvent::Cancel { .. } | HidEvent::Abort { .. } => CANCEL.signal(()),
                    HidEvent::Wink => LED.signal(LedState::Wink),
                    HidEvent::None => {}
                },
                // Short reports and bus errors are dropped; the host retries or times out.
                Either4::First(_) => {}
                Either4::Second(reply) => {
                    if let Some(channel) = busy_channel.take() {
                        hid.respond(channel, &reply);
                    }
                }
                Either4::Third(status) => hid.keepalive(status),
                Either4::Fourth(()) => hid.poll_timeout(now),
            }
            while let Some(p) = hid.next_packet() {
                if writer.write(&p).await.is_err() {
                    break;
                }
            }
        }
    };
    join(device.run(), ctap).await;
}
