// (c) Javier Fernandez @ JotaSoft 2026
//! CTAPHID framing (CTAP 2.0 §8.1) as a pure state machine.
//!
//! ```text
//! init packet: CID(4) ‖ CMD|0x80 (1) ‖ BCNTH ‖ BCNTL ‖ DATA(57)
//! cont packet: CID(4) ‖ SEQ 0..=0x7F (1)  ‖ DATA(59)
//! ```
//!
//! One transaction is in flight at a time (invariant 5). While channel A is receiving or
//! waiting for the authenticator, an init packet on channel B is answered with
//! `ERR_CHANNEL_BUSY` and does not touch A's state. Stray continuation packets are ignored.
//! Messages are limited to [`MAX_MSG_SIZE`] bytes (invariant 4). The model in
//! `formal/Jotakey/CtapHid.lean` mirrors [`CtapHid::handle_packet`].
//!
//! Channel IDs are allocated sequentially. They are not a security boundary: any process
//! that can open the HID device can talk to the authenticator, as with every FIDO key.

use crate::MAX_MSG_SIZE;

/// HID report size.
pub const PACKET_SIZE: usize = 64;
/// Payload bytes in an init packet.
pub const INIT_DATA: usize = PACKET_SIZE - 7;
/// Payload bytes in a continuation packet.
pub const CONT_DATA: usize = PACKET_SIZE - 5;
/// Broadcast channel, used only for `CTAPHID_INIT`.
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;
/// Maximum gap between packets of one message before it is abandoned.
pub const PACKET_TIMEOUT_MS: u64 = 500;

/// One HID report.
pub type Packet = [u8; PACKET_SIZE];

// A maximum-size message needs fewer than 128 continuation packets, so the 7-bit sequence
// number never wraps and no wrap handling is needed (or reachable).
const _: () = assert!(MAX_MSG_SIZE <= INIT_DATA + 128 * CONT_DATA);

/// CTAPHID command codes (without the init bit).
pub mod cmd {
    /// Echo.
    pub const PING: u8 = 0x01;
    /// CTAP1/U2F message (not supported: the device advertises NMSG).
    pub const MSG: u8 = 0x03;
    /// Channel lock (not supported).
    pub const LOCK: u8 = 0x04;
    /// Allocate or resynchronise a channel.
    pub const INIT: u8 = 0x06;
    /// Identify the device (blink the LED).
    pub const WINK: u8 = 0x08;
    /// CTAP2 request.
    pub const CBOR: u8 = 0x10;
    /// Cancel the outstanding request on this channel.
    pub const CANCEL: u8 = 0x11;
    /// Authenticator still working (device → host).
    pub const KEEPALIVE: u8 = 0x3B;
    /// Transport error (device → host).
    pub const ERROR: u8 = 0x3F;
}

/// CTAPHID_ERROR codes.
pub mod err {
    /// Unknown command.
    pub const INVALID_CMD: u8 = 0x01;
    /// Bad length field.
    pub const INVALID_LEN: u8 = 0x03;
    /// Wrong sequence number or unexpected init packet.
    pub const INVALID_SEQ: u8 = 0x04;
    /// Message not completed in time.
    pub const MSG_TIMEOUT: u8 = 0x05;
    /// Another channel owns the transaction.
    pub const CHANNEL_BUSY: u8 = 0x06;
    /// Channel not allocated.
    pub const INVALID_CHANNEL: u8 = 0x0B;
    /// Anything else.
    pub const OTHER: u8 = 0x7F;
}

/// KEEPALIVE status codes.
pub mod keepalive {
    /// Processing.
    pub const PROCESSING: u8 = 0x01;
    /// Waiting for the user's touch.
    pub const UP_NEEDED: u8 = 0x02;
}

/// Capability flags in the INIT response: WINK | CBOR | NMSG.
pub const CAPABILITIES: u8 = 0x01 | 0x04 | 0x08;
/// Firmware version reported in the INIT response.
pub const VERSION: (u8, u8, u8) = (0, 1, 0);

/// What the application must do after a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HidEvent {
    /// Nothing; maybe a reply was queued.
    None,
    /// A complete CTAP2 request is available in [`CtapHid::request`]. Answer with
    /// [`CtapHid::respond`].
    Request {
        /// Channel the request arrived on.
        channel: u32,
    },
    /// The host cancelled the in-flight request on `channel`.
    Cancel {
        /// Channel.
        channel: u32,
    },
    /// The in-flight request on `channel` was abandoned (INIT resync); drop it silently.
    Abort {
        /// Channel.
        channel: u32,
    },
    /// Blink so the user can identify this device.
    Wink,
}

/// Receive-side state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveState {
    /// Ready for a new transaction.
    Idle,
    /// Reassembling a message.
    Receiving {
        /// Owning channel.
        channel: u32,
        /// Command.
        command: u8,
        /// Announced total length.
        total: usize,
        /// Bytes received so far.
        received: usize,
        /// Next expected sequence number.
        next_sequence: u8,
        /// Time of the last packet.
        last_packet_ms: u64,
    },
    /// A CBOR request was handed to the application and has not been answered yet.
    Busy {
        /// Owning channel.
        channel: u32,
    },
}

/// Transmit-side state of the (single) outgoing message.
#[derive(Clone, Copy, Debug)]
struct TransmitState {
    channel: u32,
    command: u8,
    length: usize,
    sent: usize,
    next_sequence: u8,
    active: bool,
}

/// The CTAPHID state machine.
#[derive(Debug)]
pub struct CtapHid {
    receive_state: ReceiveState,
    receive_buffer: [u8; MAX_MSG_SIZE],
    transmit_state: TransmitState,
    transmit_buffer: [u8; MAX_MSG_SIZE],
    /// Single-packet replies (errors, keepalives) sent ahead of the main message.
    urgent: Option<Packet>,
    next_channel: u32,
    /// Length of the request in `receive_buffer` while `Busy`.
    request_length: usize,
}

impl Default for CtapHid {
    fn default() -> Self {
        Self::new()
    }
}

fn read_channel(p: &Packet) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

fn single_packet(channel: u32, command: u8, data: &[u8]) -> Packet {
    let mut p = [0u8; PACKET_SIZE];
    let (hdr, body) = p.split_at_mut(7);
    let c = channel.to_be_bytes();
    #[allow(clippy::cast_possible_truncation)] // data.len() <= INIT_DATA is enforced below.
    let n = data.len().min(INIT_DATA) as u16;
    let [bh, bl] = n.to_be_bytes();
    hdr.copy_from_slice(&[c[0], c[1], c[2], c[3], command | 0x80, bh, bl]);
    if let (Some(dst), Some(src)) = (body.get_mut(..usize::from(n)), data.get(..usize::from(n))) {
        dst.copy_from_slice(src);
    }
    p
}

impl CtapHid {
    /// Fresh state: no channels allocated.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            receive_state: ReceiveState::Idle,
            receive_buffer: [0; MAX_MSG_SIZE],
            transmit_state: TransmitState {
                channel: 0,
                command: 0,
                length: 0,
                sent: 0,
                next_sequence: 0,
                active: false,
            },
            transmit_buffer: [0; MAX_MSG_SIZE],
            urgent: None,
            next_channel: 1,
            request_length: 0,
        }
    }

    /// Current receive state (for tests and the Lean differential harness).
    #[must_use]
    pub const fn receive_state(&self) -> ReceiveState {
        self.receive_state
    }

    /// The complete request announced by [`HidEvent::Request`].
    #[must_use]
    pub fn request(&self) -> &[u8] {
        match self.receive_state {
            ReceiveState::Busy { .. } => self.receive_buffer.get(..self.request_length).unwrap_or(&[]),
            _ => &[],
        }
    }

    fn is_allocated(&self, channel: u32) -> bool {
        channel != 0 && channel != BROADCAST_CID && channel < self.next_channel
    }

    fn error(&mut self, channel: u32, code: u8) {
        self.urgent = Some(single_packet(channel, cmd::ERROR, &[code]));
    }

    /// Queue a keepalive for the busy channel (call every ~100 ms while waiting).
    pub fn keepalive(&mut self, status: u8) {
        if let ReceiveState::Busy { channel } = self.receive_state {
            self.urgent = Some(single_packet(channel, cmd::KEEPALIVE, &[status]));
        }
    }

    fn queue(&mut self, channel: u32, command: u8, data: &[u8]) {
        if self.transmit_state.active {
            // The previous response is still draining; the host must retry.
            self.error(channel, err::CHANNEL_BUSY);
            return;
        }
        let Some(dst) = self.transmit_buffer.get_mut(..data.len()) else {
            self.error(channel, err::OTHER);
            return;
        };
        dst.copy_from_slice(data);
        self.transmit_state =
            TransmitState { channel, command, length: data.len(), sent: 0, next_sequence: 0, active: true };
    }

    /// Send the authenticator's answer to the request on `channel`. Ignored if the request was
    /// aborted or cancelled in the meantime.
    pub fn respond(&mut self, channel: u32, data: &[u8]) {
        if self.receive_state == (ReceiveState::Busy { channel }) {
            self.receive_state = ReceiveState::Idle;
            self.queue(channel, cmd::CBOR, data);
        }
    }

    /// Abandon a message whose packets stopped arriving.
    pub fn poll_timeout(&mut self, now_ms: u64) {
        if let ReceiveState::Receiving { channel, last_packet_ms, .. } = self.receive_state
            && now_ms.saturating_sub(last_packet_ms) > PACKET_TIMEOUT_MS
        {
            self.receive_state = ReceiveState::Idle;
            self.error(channel, err::MSG_TIMEOUT);
        }
    }

    /// Process one HID output report from the host.
    pub fn handle_packet(&mut self, p: &Packet, now_ms: u64) -> HidEvent {
        let channel = read_channel(p);
        if channel == 0 {
            self.error(channel, err::INVALID_CHANNEL);
            return HidEvent::None;
        }
        if p[4] & 0x80 == 0 {
            return self.handle_cont(channel, p, now_ms);
        }
        let command = p[4] & 0x7F;
        let announced_length = usize::from(u16::from_be_bytes([p[5], p[6]]));

        if command == cmd::INIT {
            return self.handle_init(channel, announced_length, p);
        }
        if !self.is_allocated(channel) {
            self.error(channel, err::INVALID_CHANNEL);
            return HidEvent::None;
        }
        match self.receive_state {
            ReceiveState::Busy { channel: owner } if owner == channel => {
                if command == cmd::CANCEL {
                    return HidEvent::Cancel { channel };
                }
                self.error(channel, err::CHANNEL_BUSY);
                return HidEvent::None;
            }
            ReceiveState::Receiving { channel: owner, .. } if owner == channel => {
                // A new init packet in the middle of our own message.
                self.receive_state = ReceiveState::Idle;
                self.error(channel, err::INVALID_SEQ);
                return HidEvent::None;
            }
            ReceiveState::Busy { .. } | ReceiveState::Receiving { .. } => {
                if command != cmd::CANCEL {
                    self.error(channel, err::CHANNEL_BUSY);
                }
                return HidEvent::None;
            }
            ReceiveState::Idle => {}
        }
        if command == cmd::CANCEL {
            // Nothing to cancel; CANCEL never gets a reply.
            return HidEvent::None;
        }
        if announced_length > MAX_MSG_SIZE {
            self.error(channel, err::INVALID_LEN);
            return HidEvent::None;
        }
        let first = announced_length.min(INIT_DATA);
        if let (Some(dst), Some(src)) = (self.receive_buffer.get_mut(..first), p.get(7..7usize.saturating_add(first))) {
            dst.copy_from_slice(src);
        }
        self.receive_state = ReceiveState::Receiving {
            channel,
            command,
            total: announced_length,
            received: first,
            next_sequence: 0,
            last_packet_ms: now_ms,
        };
        self.maybe_dispatch()
    }

    fn handle_init(&mut self, channel: u32, announced_length: usize, p: &Packet) -> HidEvent {
        if announced_length != 8 {
            self.error(channel, err::INVALID_LEN);
            return HidEvent::None;
        }
        let mut event = HidEvent::None;
        let new_channel = if channel == BROADCAST_CID {
            if self.next_channel == BROADCAST_CID {
                self.error(channel, err::OTHER);
                return HidEvent::None;
            }
            let c = self.next_channel;
            self.next_channel = self.next_channel.saturating_add(1);
            c
        } else if self.is_allocated(channel) {
            // Resynchronise: abandon whatever this channel was doing.
            match self.receive_state {
                ReceiveState::Busy { channel: owner } if owner == channel => {
                    self.receive_state = ReceiveState::Idle;
                    event = HidEvent::Abort { channel };
                }
                ReceiveState::Receiving { channel: owner, .. } if owner == channel => {
                    self.receive_state = ReceiveState::Idle
                }
                _ => {}
            }
            channel
        } else {
            self.error(channel, err::INVALID_CHANNEL);
            return HidEvent::None;
        };
        let c = new_channel.to_be_bytes();
        let (maj, min, build) = VERSION;
        let resp = [
            p[7],
            p[8],
            p[9],
            p[10],
            p[11],
            p[12],
            p[13],
            p[14], // nonce
            c[0],
            c[1],
            c[2],
            c[3],
            2,
            maj,
            min,
            build,
            CAPABILITIES,
        ];
        self.urgent = Some(single_packet(channel, cmd::INIT, &resp));
        event
    }

    fn handle_cont(&mut self, channel: u32, p: &Packet, now_ms: u64) -> HidEvent {
        let ReceiveState::Receiving { channel: owner, command, total, received, next_sequence, .. } =
            self.receive_state
        else {
            return HidEvent::None;
        };
        if owner != channel {
            return HidEvent::None;
        }
        if p[4] != next_sequence {
            self.receive_state = ReceiveState::Idle;
            self.error(channel, err::INVALID_SEQ);
            return HidEvent::None;
        }
        let n = total.saturating_sub(received).min(CONT_DATA);
        let end = received.saturating_add(n);
        if let (Some(dst), Some(src)) = (self.receive_buffer.get_mut(received..end), p.get(5..5usize.saturating_add(n)))
        {
            dst.copy_from_slice(src);
        }
        // Sequence numbers never pass 0x7F: see the assertion on MAX_MSG_SIZE below.
        self.receive_state = ReceiveState::Receiving {
            channel,
            command,
            total,
            received: end,
            next_sequence: next_sequence.saturating_add(1),
            last_packet_ms: now_ms,
        };
        self.maybe_dispatch()
    }

    fn maybe_dispatch(&mut self) -> HidEvent {
        let ReceiveState::Receiving { channel, command, total, received, .. } = self.receive_state else {
            return HidEvent::None;
        };
        if received < total {
            return HidEvent::None;
        }
        self.request_length = total;
        match command {
            cmd::PING => {
                self.receive_state = ReceiveState::Idle;
                if self.transmit_state.active {
                    self.error(channel, err::CHANNEL_BUSY);
                    return HidEvent::None;
                }
                if let (Some(d), Some(s)) = (self.transmit_buffer.get_mut(..total), self.receive_buffer.get(..total)) {
                    d.copy_from_slice(s);
                    self.transmit_state = TransmitState {
                        channel,
                        command: cmd::PING,
                        length: total,
                        sent: 0,
                        next_sequence: 0,
                        active: true,
                    };
                }
                HidEvent::None
            }
            cmd::WINK => {
                self.receive_state = ReceiveState::Idle;
                if total != 0 {
                    self.error(channel, err::INVALID_LEN);
                    return HidEvent::None;
                }
                self.urgent = Some(single_packet(channel, cmd::WINK, &[]));
                HidEvent::Wink
            }
            cmd::CBOR => {
                if total == 0 {
                    self.receive_state = ReceiveState::Idle;
                    self.error(channel, err::INVALID_LEN);
                    return HidEvent::None;
                }
                self.receive_state = ReceiveState::Busy { channel };
                HidEvent::Request { channel }
            }
            _ => {
                self.receive_state = ReceiveState::Idle;
                self.error(channel, err::INVALID_CMD);
                HidEvent::None
            }
        }
    }

    /// Next HID input report to send to the host, if any.
    pub fn next_packet(&mut self) -> Option<Packet> {
        if let Some(p) = self.urgent.take() {
            return Some(p);
        }
        if !self.transmit_state.active {
            return None;
        }
        let t = self.transmit_state;
        let remaining = t.length.saturating_sub(t.sent);
        let mut p = [0u8; PACKET_SIZE];
        let c = t.channel.to_be_bytes();
        let (hdr_len, room): (usize, usize) = if t.sent == 0 { (7, INIT_DATA) } else { (5, CONT_DATA) };
        let n = remaining.min(room);
        if t.sent == 0 {
            #[allow(clippy::cast_possible_truncation)] // len <= MAX_MSG_SIZE < 65536.
            let [bh, bl] = (t.length as u16).to_be_bytes();
            p[..7].copy_from_slice(&[c[0], c[1], c[2], c[3], t.command | 0x80, bh, bl]);
        } else {
            p[..5].copy_from_slice(&[c[0], c[1], c[2], c[3], t.next_sequence]);
            self.transmit_state.next_sequence = t.next_sequence.saturating_add(1);
        }
        let end = t.sent.saturating_add(n);
        if let (Some(dst), Some(src)) =
            (p.get_mut(hdr_len..hdr_len.saturating_add(n)), self.transmit_buffer.get(t.sent..end))
        {
            dst.copy_from_slice(src);
        }
        self.transmit_state.sent = end;
        if end >= t.length {
            self.transmit_state.active = false;
        }
        Some(p)
    }
}
