// (c) Javier Fernandez @ JotaSoft 2026
//! FIDO over BLE (CTAP 2.0 §8.3) with trouBLE.
//!
//! Security posture:
//! - BLE is **off** until the user holds the button for 3 s while the device is idle. Then
//!   the device advertises for [`BLE_WINDOW`] or until a central connects.
//! - The FIDO characteristics require an **encrypted** link (LE Secure Connections). The
//!   device has no display or keypad, so pairing is "Just Works": encrypted against
//!   eavesdroppers, but not authenticated against an active man-in-the-middle *during
//!   pairing*. Every signature still requires a touch on the device itself.
//! - Bonds are kept in RAM only (MVP). After a power cycle the host must pair again.

use core::cell::RefCell;

use embassy_futures::join::join;
use embassy_futures::select::{Either, Either3, select, select3};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use heapless::Vec;
use jotakey_core::status::Status;
use jotakey_core::transport::ble::{BleEvent, BleFramer, MAX_FRAGMENT, MIN_FRAGMENT};
use trouble_host::prelude::*;

use crate::link::{BLE_KEEPALIVE, BLE_REPLY, CANCEL, REQUESTS, Request, Transport};

/// How long the device advertises after the user enables BLE.
pub const BLE_WINDOW: Duration = Duration::from_secs(120);
/// Fragment size we offer (`fidoControlPointLength`). The minimum is always valid,
/// whatever ATT MTU the central negotiates.
const FRAGMENT: usize = MIN_FRAGMENT;

/// Raised by the authenticator task on a 3-second button hold.
pub static BLE_ENABLE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;

#[gatt_server]
struct Server {
    fido: FidoService,
    info: DeviceInfo,
}

/// FIDO service (16-bit UUID 0xFFFD, assigned to the FIDO Alliance).
#[gatt_service(uuid = "fffd")]
struct FidoService {
    /// fidoControlPoint: host → device request fragments.
    #[characteristic(uuid = "f1d0fff1-deb4-4f7a-b2a1-4e1e56d32e4d", write, permissions(write = encrypted))]
    control_point: Vec<u8, MAX_FRAGMENT>,
    /// fidoStatus: device → host response fragments.
    #[characteristic(uuid = "f1d0fff2-deb4-4f7a-b2a1-4e1e56d32e4d", notify, permissions(cccd = encrypted))]
    status: Vec<u8, MAX_FRAGMENT>,
    /// fidoControlPointLength (big-endian).
    #[characteristic(uuid = "f1d0fff3-deb4-4f7a-b2a1-4e1e56d32e4d", read, value = [0, FRAGMENT as u8])]
    control_point_length: [u8; 2],
    /// fidoServiceRevisionBitfield: bit 5 = FIDO2.
    #[characteristic(uuid = "f1d0fff4-deb4-4f7a-b2a1-4e1e56d32e4d", read, write, value = 0x20)]
    revision: u8,
}

/// Device Information Service (required by the FIDO BLE profile).
#[gatt_service(uuid = service::DEVICE_INFORMATION)]
struct DeviceInfo {
    #[characteristic(uuid = characteristic::MANUFACTURER_NAME_STRING, read, value = *b"Jotakey")]
    manufacturer: [u8; 7],
    #[characteristic(uuid = characteristic::MODEL_NUMBER_STRING, read, value = *b"C6-v1")]
    model: [u8; 5],
    #[characteristic(uuid = characteristic::FIRMWARE_REVISION_STRING, read, value = *b"0.1.0")]
    firmware: [u8; 5],
}

/// Run the BLE stack forever.
pub async fn run<C: Controller>(controller: C, address: [u8; 6]) {
    let mut resources: HostResources<C, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random(address))
        .set_io_capabilities(IoCapabilities::NoInputNoOutput)
        .build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();
    let Ok(server) = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "Jotakey",
        appearance: &appearance::UNKNOWN,
    })) else {
        log::error!("ble: GATT server creation failed");
        return;
    };

    // The Device Information service is static; it only has to exist in the table.
    let _ = &server.info;
    let framer = RefCell::new(BleFramer::new(FRAGMENT));
    let _ = join(
        async {
            loop {
                if runner.run().await.is_err() {
                    Timer::after_secs(1).await;
                }
            }
        },
        async {
            loop {
                BLE_ENABLE.wait().await;
                let until = Instant::now() + BLE_WINDOW;
                while Instant::now() < until {
                    match select(advertise(&mut peripheral, &server), Timer::at(until)).await {
                        Either::First(Ok(conn)) => {
                            framer.borrow_mut().reset(FRAGMENT);
                            serve(&server, &conn, &framer).await;
                            CANCEL.signal(Transport::Ble);
                        }
                        Either::First(Err(_)) => Timer::after_secs(1).await,
                        Either::Second(()) => break,
                    }
                }
            }
        },
    )
    .await;
}

async fn advertise<'v, 's, C: Controller>(
    peripheral: &mut Peripheral<'v, C, DefaultPacketPool>,
    server: &'s Server<'v>,
) -> Result<GattConnection<'v, 's, DefaultPacketPool>, BleHostError<C::Error>> {
    let mut adv = [0u8; 31];
    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteServiceUuids16(&[[0xfd, 0xff]]),
            // FIDO service data: bit 7 = pairing mode.
            AdStructure::ServiceData16 { uuid: [0xfd, 0xff], data: &[0x80] },
            AdStructure::CompleteLocalName(b"Jotakey"),
        ],
        &mut adv[..],
    )?;
    let advertiser = peripheral
        .advertise(
            &AdvertisementParameters::default(),
            Advertisement::ConnectableScannableUndirected { adv_data: adv.get(..len).unwrap_or(&[]), scan_data: &[] },
        )
        .await?;
    let conn = advertiser.accept().await?.with_attribute_server(server)?;
    Ok(conn)
}

/// Handle one connection until it closes.
async fn serve<P: PacketPool>(server: &Server<'_>, conn: &GattConnection<'_, '_, P>, framer: &RefCell<BleFramer>) {
    let cp = &server.fido.control_point;
    let status = &server.fido.status;
    let mut note = [0u8; MAX_FRAGMENT];
    loop {
        let event = select3(conn.next(), BLE_REPLY.receive(), BLE_KEEPALIVE.wait()).await;
        match event {
            Either3::First(GattConnectionEvent::Disconnected { .. }) => return,
            Either3::First(GattConnectionEvent::Gatt { event }) => {
                let mut forward: Option<Vec<u8, MAX_FRAGMENT>> = None;
                let mut reject = false;
                if let GattEvent::Write(w) = &event
                    && w.handle() == cp.handle
                {
                    // Defence in depth: the attribute permission already demands encryption.
                    let encrypted = conn.raw().security_level().map(|l| l.encrypted()).unwrap_or(false);
                    if encrypted {
                        w.with_data(|_, data| {
                            let mut v = Vec::new();
                            if v.extend_from_slice(data).is_ok() {
                                forward = Some(v);
                            }
                        });
                    } else {
                        reject = true;
                    }
                }
                let reply = if reject { event.reject(AttErrorCode::INSUFFICIENT_ENCRYPTION) } else { event.accept() };
                if let Ok(r) = reply {
                    r.send().await;
                }
                if let Some(data) = forward {
                    let now = Instant::now().as_millis();
                    let ev = framer.borrow_mut().handle_write(&data, now);
                    match ev {
                        BleEvent::Request => {
                            let mut req = Vec::new();
                            let _ = req.extend_from_slice(framer.borrow().request());
                            if REQUESTS.try_send(Request { transport: Transport::Ble, data: req }).is_err() {
                                framer.borrow_mut().respond(&[Status::ChannelBusy.code()]);
                            }
                        }
                        BleEvent::Cancel => CANCEL.signal(Transport::Ble),
                        BleEvent::None => {}
                    }
                }
            }
            Either3::First(_) => {}
            Either3::Second(reply) => framer.borrow_mut().respond(&reply),
            Either3::Third(s) => framer.borrow_mut().keepalive(s),
        }
        framer.borrow_mut().poll_timeout(Instant::now().as_millis());
        loop {
            let n = framer.borrow_mut().next_notification(&mut note);
            let Some(n) = n else { break };
            let mut v: Vec<u8, MAX_FRAGMENT> = Vec::new();
            let _ = v.extend_from_slice(note.get(..n).unwrap_or(&[]));
            if status.notify(conn, &v, false).await.is_err() {
                return;
            }
        }
    }
}
