// (c) Javier Fernandez @ JotaSoft 2026
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
enum ReceiveState {
    Idle,
    Receiving { command: u8, total: usize, received: usize, next_sequence: u8, last_packet_ms: u64 },
    Busy,
}

#[derive(Clone, Copy, Debug)]
struct TransmitState {
    command: u8,
    length: usize,
    sent: usize,
    next_sequence: u8,
    active: bool,
}

/// The BLE framing state machine.
#[derive(Debug)]
pub struct BleFramer {
    receive_state: ReceiveState,
    receive_buffer: [u8; MAX_MSG_SIZE],
    request_length: usize,
    transmit_state: TransmitState,
    transmit_buffer: [u8; MAX_MSG_SIZE],
    urgent: Option<[u8; 4]>,
    fragment: usize,
}

impl BleFramer {
    /// New framer with `fragment_size` clamped to `[MIN_FRAGMENT, MAX_FRAGMENT]`.
    #[must_use]
    pub fn new(fragment_size: usize) -> Self {
        Self {
            receive_state: ReceiveState::Idle,
            receive_buffer: [0; MAX_MSG_SIZE],
            request_length: 0,
            transmit_state: TransmitState { command: 0, length: 0, sent: 0, next_sequence: 0, active: false },
            transmit_buffer: [0; MAX_MSG_SIZE],
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
        if self.receive_state == ReceiveState::Busy {
            self.receive_buffer.get(..self.request_length).unwrap_or(&[])
        } else {
            &[]
        }
    }

    fn error(&mut self, code: u8) {
        self.receive_state = ReceiveState::Idle;
        self.urgent = Some([cmd::ERROR, 0, 1, code]);
    }

    /// Queue a keepalive while a request is being processed.
    pub fn keepalive(&mut self, status: u8) {
        if self.receive_state == ReceiveState::Busy {
            self.urgent = Some([cmd::KEEPALIVE, 0, 1, status]);
        }
    }

    /// Send the authenticator's answer. Ignored if nothing is in flight.
    pub fn respond(&mut self, data: &[u8]) {
        if self.receive_state != ReceiveState::Busy {
            return;
        }
        self.receive_state = ReceiveState::Idle;
        if let Some(dst) = self.transmit_buffer.get_mut(..data.len()) {
            dst.copy_from_slice(data);
            self.transmit_state =
                TransmitState { command: cmd::MSG, length: data.len(), sent: 0, next_sequence: 0, active: true };
        } else {
            self.error(err::INVALID_LEN);
        }
    }

    /// Abandon a message whose fragments stopped arriving.
    pub fn poll_timeout(&mut self, now_ms: u64) {
        if let ReceiveState::Receiving { last_packet_ms, .. } = self.receive_state
            && now_ms.saturating_sub(last_packet_ms) > FRAGMENT_TIMEOUT_MS
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
            return if self.receive_state == ReceiveState::Busy { BleEvent::Cancel } else { BleEvent::None };
        }
        match self.receive_state {
            ReceiveState::Busy => {
                // Keep the in-flight request; only report the conflict.
                self.urgent = Some([cmd::ERROR, 0, 1, err::BUSY]);
                return BleEvent::None;
            }
            ReceiveState::Receiving { .. } => {
                self.error(err::INVALID_SEQ);
                return BleEvent::None;
            }
            ReceiveState::Idle => {}
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
        if let Some(dst) = self.receive_buffer.get_mut(..payload.len()) {
            dst.copy_from_slice(payload);
        }
        self.receive_state = ReceiveState::Receiving {
            command: b0,
            total,
            received: payload.len(),
            next_sequence: 0,
            last_packet_ms: now_ms,
        };
        self.maybe_dispatch()
    }

    fn handle_cont(&mut self, sequence_in: u8, payload: &[u8], now_ms: u64) -> BleEvent {
        let ReceiveState::Receiving { command, total, received, next_sequence, .. } = self.receive_state else {
            if self.receive_state == ReceiveState::Idle {
                self.error(err::INVALID_SEQ);
            }
            return BleEvent::None;
        };
        if sequence_in != next_sequence {
            self.error(err::INVALID_SEQ);
            return BleEvent::None;
        }
        let end = received.saturating_add(payload.len());
        if end > total {
            self.error(err::INVALID_LEN);
            return BleEvent::None;
        }
        if let Some(dst) = self.receive_buffer.get_mut(received..end) {
            dst.copy_from_slice(payload);
        }
        // Sequence numbers wrap 0x7F → 0x00 (CTAP 2.0 §8.3.4).
        let next = if next_sequence >= 0x7F { 0 } else { next_sequence.saturating_add(1) };
        self.receive_state =
            ReceiveState::Receiving { command, total, received: end, next_sequence: next, last_packet_ms: now_ms };
        self.maybe_dispatch()
    }

    fn maybe_dispatch(&mut self) -> BleEvent {
        let ReceiveState::Receiving { command, total, received, .. } = self.receive_state else {
            return BleEvent::None;
        };
        if received < total {
            return BleEvent::None;
        }
        if command == cmd::PING {
            self.receive_state = ReceiveState::Idle;
            if let (Some(d), Some(s)) = (self.transmit_buffer.get_mut(..total), self.receive_buffer.get(..total)) {
                d.copy_from_slice(s);
                self.transmit_state =
                    TransmitState { command: cmd::PING, length: total, sent: 0, next_sequence: 0, active: true };
            }
            return BleEvent::None;
        }
        if total == 0 {
            self.error(err::INVALID_LEN);
            return BleEvent::None;
        }
        self.request_length = total;
        self.receive_state = ReceiveState::Busy;
        BleEvent::Request
    }

    /// Next notification for `fidoStatus`; returns its length in `out`.
    pub fn next_notification(&mut self, out: &mut [u8; MAX_FRAGMENT]) -> Option<usize> {
        if let Some(u) = self.urgent.take() {
            out[..4].copy_from_slice(&u);
            return Some(4);
        }
        if !self.transmit_state.active {
            return None;
        }
        let t = self.transmit_state;
        let (hdr, room) = if t.sent == 0 {
            (3usize, self.fragment.saturating_sub(3))
        } else {
            (1usize, self.fragment.saturating_sub(1))
        };
        if t.sent == 0 {
            #[allow(clippy::cast_possible_truncation)] // len <= MAX_MSG_SIZE < 65536.
            let [h, l] = (t.length as u16).to_be_bytes();
            out[..3].copy_from_slice(&[t.command, h, l]);
        } else {
            out[0] = t.next_sequence;
            self.transmit_state.next_sequence =
                if t.next_sequence >= 0x7F { 0 } else { t.next_sequence.saturating_add(1) };
        }
        let n = t.length.saturating_sub(t.sent).min(room);
        let end = t.sent.saturating_add(n);
        if let (Some(dst), Some(src)) = (out.get_mut(hdr..hdr.saturating_add(n)), self.transmit_buffer.get(t.sent..end))
        {
            dst.copy_from_slice(src);
        }
        self.transmit_state.sent = end;
        if end >= t.length {
            self.transmit_state.active = false;
        }
        Some(hdr.saturating_add(n))
    }
}
