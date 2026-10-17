// (c) Javier Fernandez @ JotaSoft 2026
//! CTAPHID over the USB-Serial/JTAG port.
//!
//! Bytes from the host pass through the core's serial [`Deframer`] (COBS + CRC-32) and
//! [`CtapHid`] state machine. Complete requests go to the authenticator task, and replies
//! and keepalives are fragmented back into framed 64-byte reports.

use embassy_futures::select::{Either4, select4};
use embassy_time::{Instant, Timer};
use embedded_io_async::{Read, Write};
use esp_hal::Async;
use esp_hal::usb::usb_serial_jtag::UsbSerialJtag;
use heapless::Vec;
use jotakey_core::status::Status;
use jotakey_core::transport::ctaphid::{CtapHid, HidEvent};
use jotakey_core::transport::serial::{Deframer, encode};
use static_cell::StaticCell;

use crate::link::{CANCEL, LED, LedState, REQUESTS, Request, Transport, USB_KEEPALIVE, USB_REPLY};

static HID: StaticCell<CtapHid> = StaticCell::new();

#[embassy_executor::task]
pub async fn usb_task(usb: UsbSerialJtag<'static, Async>) {
    let (mut rx, mut tx) = usb.split();
    let hid = HID.init(CtapHid::new());
    let mut deframer = Deframer::new();
    let mut busy_channel: Option<u32> = None;
    let mut buf = [0u8; 64];

    loop {
        let now = Instant::now().as_millis();
        match select4(rx.read(&mut buf), USB_REPLY.receive(), USB_KEEPALIVE.wait(), Timer::after_millis(50)).await {
            Either4::First(Ok(n)) => {
                for &b in buf.get(..n).unwrap_or(&[]) {
                    let Some(pkt) = deframer.push(b) else { continue };
                    match hid.handle_packet(&pkt, now) {
                        HidEvent::Request { channel } => {
                            let mut data = Vec::new();
                            let _ = data.extend_from_slice(hid.request());
                            if REQUESTS.try_send(Request { transport: Transport::Usb, data }).is_ok() {
                                busy_channel = Some(channel);
                            } else {
                                // The authenticator is serving BLE right now.
                                hid.respond(channel, &[Status::ChannelBusy.code()]);
                            }
                        }
                        HidEvent::Cancel { .. } | HidEvent::Abort { .. } => CANCEL.signal(Transport::Usb),
                        HidEvent::Wink => LED.signal(LedState::Wink),
                        HidEvent::None => {}
                    }
                }
            }
            Either4::First(Err(_)) => {}
            Either4::Second(reply) => {
                if let Some(channel) = busy_channel.take() {
                    hid.respond(channel, &reply);
                }
            }
            Either4::Third(status) => hid.keepalive(status),
            Either4::Fourth(()) => hid.poll_timeout(now),
        }
        while let Some(p) = hid.next_packet() {
            let (frame, n) = encode(&p);
            if tx.write_all(frame.get(..n).unwrap_or(&[])).await.is_err() {
                break;
            }
        }
        let _ = tx.flush().await;
    }
}
