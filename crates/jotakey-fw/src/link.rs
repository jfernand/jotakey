//! Channels between the transport tasks (USB, BLE) and the authenticator task.
//!
//! Exactly one CTAP request is processed at a time. A transport that receives a request
//! while another is in flight answers `CTAP1_ERR_CHANNEL_BUSY` itself.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use heapless::Vec;
use jotakey_core::MAX_MSG_SIZE;

/// Which transport a request came from (and where its answer goes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// CTAPHID tunnelled over USB-Serial/JTAG.
    Usb,
    /// FIDO over BLE GATT.
    Ble,
}

/// A complete CTAP2 request (command byte ‖ CBOR).
pub struct Request {
    /// Origin.
    pub transport: Transport,
    /// Bytes.
    pub data: Vec<u8, MAX_MSG_SIZE>,
}

/// A complete CTAP2 response (status ‖ CBOR).
pub type Reply = Vec<u8, MAX_MSG_SIZE>;

/// What the status LED shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedState {
    /// Nothing to report (LED off).
    Idle,
    /// Touch the button now (amber blink).
    Touch,
    /// WINK: identify this device (blue blink).
    Wink,
    /// Self test or hardware failure: authenticator disabled (solid red).
    Fault,
    /// Running with the INSECURE development key (magenta flash at boot).
    #[cfg(feature = "dev-key")]
    DevKey,
}

/// Requests from both transports to the authenticator.
pub static REQUESTS: Channel<CriticalSectionRawMutex, Request, 1> = Channel::new();
/// Replies for the USB transport.
pub static USB_REPLY: Channel<CriticalSectionRawMutex, Reply, 1> = Channel::new();
/// Replies for the BLE transport.
pub static BLE_REPLY: Channel<CriticalSectionRawMutex, Reply, 1> = Channel::new();
/// Keepalive status for the USB transport (`PROCESSING` / `UP_NEEDED`).
pub static USB_KEEPALIVE: Signal<CriticalSectionRawMutex, u8> = Signal::new();
/// Keepalive status for the BLE transport.
pub static BLE_KEEPALIVE: Signal<CriticalSectionRawMutex, u8> = Signal::new();
/// The host cancelled (or abandoned) the request from this transport.
pub static CANCEL: Signal<CriticalSectionRawMutex, Transport> = Signal::new();
/// LED commands.
pub static LED: Signal<CriticalSectionRawMutex, LedState> = Signal::new();

/// Deliver a reply to the transport a request came from. Never blocks: if the transport
/// has gone away, the reply is dropped and the host times out.
pub fn reply(to: Transport, data: &[u8]) {
    let mut v = Vec::new();
    if v.extend_from_slice(data).is_err() {
        return;
    }
    let ch = match to {
        Transport::Usb => &USB_REPLY,
        Transport::Ble => &BLE_REPLY,
    };
    let _ = ch.try_send(v);
}

/// Send a keepalive to the transport a request came from.
pub fn keepalive(to: Transport, status: u8) {
    match to {
        Transport::Usb => USB_KEEPALIVE.signal(status),
        Transport::Ble => BLE_KEEPALIVE.signal(status),
    }
}
