//! FIDO BLE framing (CTAP 2.0 §8.3) as a pure state machine.
//!
//! ```text
//! initial fragment: CMD (1) ‖ HLEN ‖ LLEN ‖ DATA(fragment_size - 3)
//! continuation:     SEQ 0..=0x7F (1)     ‖ DATA(fragment_size - 1)
//! ```
//!
//! The host writes request fragments to `fidoControlPoint`; the device answers with
//! notifications on `fidoStatus`. A BLE link carries one client, so there are no channels.
//! The same limits apply as for CTAPHID: messages ≤ [`MAX_MSG_SIZE`], one transaction at a
//! time, and every input yields a defined state.

use crate::MAX_MSG_SIZE;

/// Smallest fragment size (ATT default MTU 23 − 3).
pub const MIN_FRAGMENT: usize = 20;
/// Largest fragment size we support (`fidoControlPointLength` upper bound).
pub const MAX_FRAGMENT: usize = 512;
/// Maximum gap between fragments of one message.
pub const FRAGMENT_TIMEOUT_MS: u64 = 1_000;

/// BLE frame commands.
pub mod cmd {
    /// Echo.
    pub const PING: u8 = 0x81;
    /// Authenticator still working (device → host).
    pub const KEEPALIVE: u8 = 0x82;
    /// CTAP message.
    pub const MSG: u8 = 0x83;
    /// Cancel the outstanding request.
    pub const CANCEL: u8 = 0xBE;
    /// Framing error (device → host).
    pub const ERROR: u8 = 0xBF;
}

/// ERROR codes.
pub mod err {
    /// Unknown command.
    pub const INVALID_CMD: u8 = 0x01;
    /// Bad length.
    pub const INVALID_LEN: u8 = 0x03;
    /// Bad sequence number.
    pub const INVALID_SEQ: u8 = 0x04;
    /// Message not completed in time.
    pub const REQ_TIMEOUT: u8 = 0x05;
    /// A request is already being processed.
    pub const BUSY: u8 = 0x06;
}

/// KEEPALIVE status codes.
pub mod keepalive {
    /// Processing.
    pub const PROCESSING: u8 = 0x01;
    /// Waiting for the user's touch.
    pub const UP_NEEDED: u8 = 0x02;
}

/// What the application must do after a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BleEvent {
    /// Nothing; maybe a reply was queued.
    None,
    /// A complete CTAP2 request is available in [`BleFramer::request`].
    Request,
    /// The host cancelled the in-flight request.
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rx {
    Idle,
    Receiving { cmd: u8, total: usize, got: usize, seq: u8, last_ms: u64 },
    Busy,
}

#[derive(Clone, Copy, Debug)]
struct Tx {
    cmd: u8,
    len: usize,
    sent: usize,
    seq: u8,
    active: bool,
}

/// The BLE framing state machine.
#[derive(Debug)]
pub struct BleFramer {
    rx: Rx,
    rx_buf: [u8; MAX_MSG_SIZE],
    req_len: usize,
    tx: Tx,
    tx_buf: [u8; MAX_MSG_SIZE],
    urgent: Option<[u8; 4]>,
    fragment: usize,
}

impl BleFramer {
    /// New framer with `fragment_size` clamped to `[MIN_FRAGMENT, MAX_FRAGMENT]`.
    #[must_use]
    pub fn new(fragment_size: usize) -> Self {
        Self {
            rx: Rx::Idle,
            rx_buf: [0; MAX_MSG_SIZE],
            req_len: 0,
            tx: Tx { cmd: 0, len: 0, sent: 0, seq: 0, active: false },
            tx_buf: [0; MAX_MSG_SIZE],
            urgent: None,
            fragment: fragment_size.clamp(MIN_FRAGMENT, MAX_FRAGMENT),
        }
    }

    /// Current fragment size (`fidoControlPointLength`).
    #[must_use]
    pub const fn fragment_size(&self) -> usize {
        self.fragment
    }

    /// Reset everything (new connection).
    pub fn reset(&mut self, fragment_size: usize) {
        *self = Self::new(fragment_size);
    }

    /// The complete request announced by [`BleEvent::Request`].
    #[must_use]
    pub fn request(&self) -> &[u8] {
        if self.rx == Rx::Busy { self.rx_buf.get(..self.req_len).unwrap_or(&[]) } else { &[] }
    }

    fn error(&mut self, code: u8) {
        self.rx = Rx::Idle;
        self.urgent = Some([cmd::ERROR, 0, 1, code]);
    }

    /// Queue a keepalive while a request is being processed.
    pub fn keepalive(&mut self, status: u8) {
        if self.rx == Rx::Busy {
            self.urgent = Some([cmd::KEEPALIVE, 0, 1, status]);
        }
    }

    /// Send the authenticator's answer. Ignored if nothing is in flight.
    pub fn respond(&mut self, data: &[u8]) {
        if self.rx != Rx::Busy {
            return;
        }
        self.rx = Rx::Idle;
        if let Some(dst) = self.tx_buf.get_mut(..data.len()) {
            dst.copy_from_slice(data);
            self.tx = Tx { cmd: cmd::MSG, len: data.len(), sent: 0, seq: 0, active: true };
        } else {
            self.error(err::INVALID_LEN);
        }
    }

    /// Abandon a message whose fragments stopped arriving.
    pub fn poll_timeout(&mut self, now_ms: u64) {
        if let Rx::Receiving { last_ms, .. } = self.rx
            && now_ms.saturating_sub(last_ms) > FRAGMENT_TIMEOUT_MS
        {
            self.error(err::REQ_TIMEOUT);
        }
    }

    /// Process one write to `fidoControlPoint`.
    pub fn handle_write(&mut self, data: &[u8], now_ms: u64) -> BleEvent {
        let Some((&b0, rest)) = data.split_first() else {
            self.error(err::INVALID_LEN);
            return BleEvent::None;
        };
        if data.len() > self.fragment {
            self.error(err::INVALID_LEN);
            return BleEvent::None;
        }
        if b0 & 0x80 == 0 {
            return self.handle_cont(b0, rest, now_ms);
        }
        if b0 == cmd::CANCEL {
            return if self.rx == Rx::Busy { BleEvent::Cancel } else { BleEvent::None };
        }
        match self.rx {
            Rx::Busy => {
                // Keep the in-flight request; only report the conflict.
                self.urgent = Some([cmd::ERROR, 0, 1, err::BUSY]);
                return BleEvent::None;
            }
            Rx::Receiving { .. } => {
                self.error(err::INVALID_SEQ);
                return BleEvent::None;
            }
            Rx::Idle => {}
        }
        if b0 != cmd::PING && b0 != cmd::MSG {
            self.error(err::INVALID_CMD);
            return BleEvent::None;
        }
        let Some((len_bytes, payload)) = rest.split_first_chunk::<2>() else {
            self.error(err::INVALID_LEN);
            return BleEvent::None;
        };
        let total = usize::from(u16::from_be_bytes(*len_bytes));
        if total > MAX_MSG_SIZE || payload.len() > total {
            self.error(err::INVALID_LEN);
            return BleEvent::None;
        }
        if let Some(dst) = self.rx_buf.get_mut(..payload.len()) {
            dst.copy_from_slice(payload);
        }
        self.rx = Rx::Receiving { cmd: b0, total, got: payload.len(), seq: 0, last_ms: now_ms };
        self.maybe_dispatch()
    }

    fn handle_cont(&mut self, seq_in: u8, payload: &[u8], now_ms: u64) -> BleEvent {
        let Rx::Receiving { cmd: command, total, got, seq, .. } = self.rx else {
            if self.rx == Rx::Idle {
                self.error(err::INVALID_SEQ);
            }
            return BleEvent::None;
        };
        if seq_in != seq {
            self.error(err::INVALID_SEQ);
            return BleEvent::None;
        }
        let end = got.saturating_add(payload.len());
        if end > total {
            self.error(err::INVALID_LEN);
            return BleEvent::None;
        }
        if let Some(dst) = self.rx_buf.get_mut(got..end) {
            dst.copy_from_slice(payload);
        }
        // Sequence numbers wrap 0x7F → 0x00 (CTAP 2.0 §8.3.4).
        let next = if seq >= 0x7F { 0 } else { seq.saturating_add(1) };
        self.rx = Rx::Receiving { cmd: command, total, got: end, seq: next, last_ms: now_ms };
        self.maybe_dispatch()
    }

    fn maybe_dispatch(&mut self) -> BleEvent {
        let Rx::Receiving { cmd: command, total, got, .. } = self.rx else {
            return BleEvent::None;
        };
        if got < total {
            return BleEvent::None;
        }
        if command == cmd::PING {
            self.rx = Rx::Idle;
            if let (Some(d), Some(s)) = (self.tx_buf.get_mut(..total), self.rx_buf.get(..total)) {
                d.copy_from_slice(s);
                self.tx = Tx { cmd: cmd::PING, len: total, sent: 0, seq: 0, active: true };
            }
            return BleEvent::None;
        }
        if total == 0 {
            self.error(err::INVALID_LEN);
            return BleEvent::None;
        }
        self.req_len = total;
        self.rx = Rx::Busy;
        BleEvent::Request
    }

    /// Next notification for `fidoStatus`; returns its length in `out`.
    pub fn next_notification(&mut self, out: &mut [u8; MAX_FRAGMENT]) -> Option<usize> {
        if let Some(u) = self.urgent.take() {
            out[..4].copy_from_slice(&u);
            return Some(4);
        }
        if !self.tx.active {
            return None;
        }
        let t = self.tx;
        let (hdr, room) = if t.sent == 0 {
            (3usize, self.fragment.saturating_sub(3))
        } else {
            (1usize, self.fragment.saturating_sub(1))
        };
        if t.sent == 0 {
            #[allow(clippy::cast_possible_truncation)] // len <= MAX_MSG_SIZE < 65536.
            let [h, l] = (t.len as u16).to_be_bytes();
            out[..3].copy_from_slice(&[t.cmd, h, l]);
        } else {
            out[0] = t.seq;
            self.tx.seq = if t.seq >= 0x7F { 0 } else { t.seq.saturating_add(1) };
        }
        let n = t.len.saturating_sub(t.sent).min(room);
        let end = t.sent.saturating_add(n);
        if let (Some(dst), Some(src)) = (out.get_mut(hdr..hdr.saturating_add(n)), self.tx_buf.get(t.sent..end)) {
            dst.copy_from_slice(src);
        }
        self.tx.sent = end;
        if end >= t.len {
            self.tx.active = false;
        }
        Some(hdr.saturating_add(n))
    }
}
