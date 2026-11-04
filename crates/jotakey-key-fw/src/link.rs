// (c) Javier Fernandez @ JotaSoft 2026
//! Channels between the USB task and the authenticator task.
//!
//! Exactly one CTAP request is processed at a time. The key has one transport (CTAPHID over
//! native USB, no BLE), so a request that arrives while another is in flight is answered
//! `CTAP1_ERR_CHANNEL_BUSY` by the CTAPHID layer itself.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use heapless::Vec;
use jotakey_core::MAX_MSG_SIZE;

/// A complete CTAP2 request (command byte ‖ CBOR).
pub type Request = Vec<u8, MAX_MSG_SIZE>;

/// A complete CTAP2 response (status ‖ CBOR).
pub type Reply = Vec<u8, MAX_MSG_SIZE>;

/// What the status LED shows. The LED is a single red one, so states are blink patterns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, defmt::Format)]
pub enum LedState {
    /// Nothing to report (LED off).
    Idle,
    /// Touch the key now (slow blink).
    Touch,
    /// WINK: identify this device (fast blink).
    Wink,
    /// Self test or hardware failure: authenticator disabled (solid on).
    Fault,
    /// Running with the INSECURE development key (triple flash at boot).
    #[cfg(feature = "dev-key")]
    DevKey,
}

/// Requests from USB to the authenticator.
pub static REQUESTS: Channel<CriticalSectionRawMutex, Request, 1> = Channel::new();
/// Replies to USB.
pub static REPLY: Channel<CriticalSectionRawMutex, Reply, 1> = Channel::new();
/// Keepalive status for USB (`PROCESSING` / `UP_NEEDED`).
pub static KEEPALIVE: Signal<CriticalSectionRawMutex, u8> = Signal::new();
/// The host cancelled (or abandoned) the request in flight.
pub static CANCEL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// LED commands.
pub static LED: Signal<CriticalSectionRawMutex, LedState> = Signal::new();

/// Deliver a reply. Never blocks: if the USB task has gone away, the reply is dropped and
/// the host times out.
pub fn reply(data: &[u8]) {
    let mut v = Vec::new();
    if v.extend_from_slice(data).is_err() {
        return;
    }
    let _ = REPLY.try_send(v);
}
