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
        cid: u32,
    },
    /// The host cancelled the in-flight request on `cid`.
    Cancel {
        /// Channel.
        cid: u32,
    },
    /// The in-flight request on `cid` was abandoned (INIT resync); drop it silently.
    Abort {
        /// Channel.
        cid: u32,
    },
    /// Blink so the user can identify this device.
    Wink,
}

/// Receive-side state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx {
    /// Ready for a new transaction.
    Idle,
    /// Reassembling a message.
    Receiving {
        /// Owning channel.
        cid: u32,
        /// Command.
        cmd: u8,
        /// Announced total length.
        total: usize,
        /// Bytes received so far.
        got: usize,
        /// Next expected sequence number.
        seq: u8,
        /// Time of the last packet.
        last_ms: u64,
    },
    /// A CBOR request was handed to the application and has not been answered yet.
    Busy {
        /// Owning channel.
        cid: u32,
    },
}

/// Transmit-side state of the (single) outgoing message.
#[derive(Clone, Copy, Debug)]
struct Tx {
    cid: u32,
    cmd: u8,
    len: usize,
    sent: usize,
    seq: u8,
    active: bool,
}

/// The CTAPHID state machine.
#[derive(Debug)]
pub struct CtapHid {
    rx: Rx,
    rx_buf: [u8; MAX_MSG_SIZE],
    tx: Tx,
    tx_buf: [u8; MAX_MSG_SIZE],
    /// Single-packet replies (errors, keepalives) sent ahead of the main message.
    urgent: Option<Packet>,
    next_cid: u32,
    /// Length of the request in `rx_buf` while `Busy`.
    req_len: usize,
}

impl Default for CtapHid {
    fn default() -> Self {
        Self::new()
    }
}

fn read_cid(p: &Packet) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

fn single_packet(cid: u32, cmd: u8, data: &[u8]) -> Packet {
    let mut p = [0u8; PACKET_SIZE];
    let (hdr, body) = p.split_at_mut(7);
    let c = cid.to_be_bytes();
    #[allow(clippy::cast_possible_truncation)] // data.len() <= INIT_DATA is enforced below.
    let n = data.len().min(INIT_DATA) as u16;
    let [bh, bl] = n.to_be_bytes();
    hdr.copy_from_slice(&[c[0], c[1], c[2], c[3], cmd | 0x80, bh, bl]);
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
            rx: Rx::Idle,
            rx_buf: [0; MAX_MSG_SIZE],
            tx: Tx { cid: 0, cmd: 0, len: 0, sent: 0, seq: 0, active: false },
            tx_buf: [0; MAX_MSG_SIZE],
            urgent: None,
            next_cid: 1,
            req_len: 0,
        }
    }

    /// Current receive state (for tests and the Lean differential harness).
    #[must_use]
    pub const fn rx_state(&self) -> Rx {
        self.rx
    }

    /// The complete request announced by [`HidEvent::Request`].
    #[must_use]
    pub fn request(&self) -> &[u8] {
        match self.rx {
            Rx::Busy { .. } => self.rx_buf.get(..self.req_len).unwrap_or(&[]),
            _ => &[],
        }
    }

    fn is_allocated(&self, cid: u32) -> bool {
        cid != 0 && cid != BROADCAST_CID && cid < self.next_cid
    }

    fn error(&mut self, cid: u32, code: u8) {
        self.urgent = Some(single_packet(cid, cmd::ERROR, &[code]));
    }

    /// Queue a keepalive for the busy channel (call every ~100 ms while waiting).
    pub fn keepalive(&mut self, status: u8) {
        if let Rx::Busy { cid } = self.rx {
            self.urgent = Some(single_packet(cid, cmd::KEEPALIVE, &[status]));
        }
    }

    fn queue(&mut self, cid: u32, command: u8, data: &[u8]) {
        if self.tx.active {
            // The previous response is still draining; the host must retry.
            self.error(cid, err::CHANNEL_BUSY);
            return;
        }
        let Some(dst) = self.tx_buf.get_mut(..data.len()) else {
            self.error(cid, err::OTHER);
            return;
        };
        dst.copy_from_slice(data);
        self.tx = Tx { cid, cmd: command, len: data.len(), sent: 0, seq: 0, active: true };
    }

    /// Send the authenticator's answer to the request on `cid`. Ignored if the request was
    /// aborted or cancelled in the meantime.
    pub fn respond(&mut self, cid: u32, data: &[u8]) {
        if self.rx == (Rx::Busy { cid }) {
            self.rx = Rx::Idle;
            self.queue(cid, cmd::CBOR, data);
        }
    }

    /// Abandon a message whose packets stopped arriving.
    pub fn poll_timeout(&mut self, now_ms: u64) {
        if let Rx::Receiving { cid, last_ms, .. } = self.rx
            && now_ms.saturating_sub(last_ms) > PACKET_TIMEOUT_MS
        {
            self.rx = Rx::Idle;
            self.error(cid, err::MSG_TIMEOUT);
        }
    }

    /// Process one HID output report from the host.
    pub fn handle_packet(&mut self, p: &Packet, now_ms: u64) -> HidEvent {
        let cid = read_cid(p);
        if cid == 0 {
            self.error(cid, err::INVALID_CHANNEL);
            return HidEvent::None;
        }
        if p[4] & 0x80 == 0 {
            return self.handle_cont(cid, p, now_ms);
        }
        let command = p[4] & 0x7F;
        let bcnt = usize::from(u16::from_be_bytes([p[5], p[6]]));

        if command == cmd::INIT {
            return self.handle_init(cid, bcnt, p);
        }
        if !self.is_allocated(cid) {
            self.error(cid, err::INVALID_CHANNEL);
            return HidEvent::None;
        }
        match self.rx {
            Rx::Busy { cid: owner } if owner == cid => {
                if command == cmd::CANCEL {
                    return HidEvent::Cancel { cid };
                }
                self.error(cid, err::CHANNEL_BUSY);
                return HidEvent::None;
            }
            Rx::Receiving { cid: owner, .. } if owner == cid => {
                // A new init packet in the middle of our own message.
                self.rx = Rx::Idle;
                self.error(cid, err::INVALID_SEQ);
                return HidEvent::None;
            }
            Rx::Busy { .. } | Rx::Receiving { .. } => {
                if command != cmd::CANCEL {
                    self.error(cid, err::CHANNEL_BUSY);
                }
                return HidEvent::None;
            }
            Rx::Idle => {}
        }
        if command == cmd::CANCEL {
            // Nothing to cancel; CANCEL never gets a reply.
            return HidEvent::None;
        }
        if bcnt > MAX_MSG_SIZE {
            self.error(cid, err::INVALID_LEN);
            return HidEvent::None;
        }
        let first = bcnt.min(INIT_DATA);
        if let (Some(dst), Some(src)) = (self.rx_buf.get_mut(..first), p.get(7..7usize.saturating_add(first))) {
            dst.copy_from_slice(src);
        }
        self.rx = Rx::Receiving { cid, cmd: command, total: bcnt, got: first, seq: 0, last_ms: now_ms };
        self.maybe_dispatch()
    }

    fn handle_init(&mut self, cid: u32, bcnt: usize, p: &Packet) -> HidEvent {
        if bcnt != 8 {
            self.error(cid, err::INVALID_LEN);
            return HidEvent::None;
        }
        let mut event = HidEvent::None;
        let new_cid = if cid == BROADCAST_CID {
            if self.next_cid == BROADCAST_CID {
                self.error(cid, err::OTHER);
                return HidEvent::None;
            }
            let c = self.next_cid;
            self.next_cid = self.next_cid.saturating_add(1);
            c
        } else if self.is_allocated(cid) {
            // Resynchronise: abandon whatever this channel was doing.
            match self.rx {
                Rx::Busy { cid: owner } if owner == cid => {
                    self.rx = Rx::Idle;
                    event = HidEvent::Abort { cid };
                }
                Rx::Receiving { cid: owner, .. } if owner == cid => self.rx = Rx::Idle,
                _ => {}
            }
            cid
        } else {
            self.error(cid, err::INVALID_CHANNEL);
            return HidEvent::None;
        };
        let c = new_cid.to_be_bytes();
        let (maj, min, build) = VERSION;
        let resp = [
            p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], // nonce
            c[0], c[1], c[2], c[3], 2, maj, min, build, CAPABILITIES,
        ];
        self.urgent = Some(single_packet(cid, cmd::INIT, &resp));
        event
    }

    fn handle_cont(&mut self, cid: u32, p: &Packet, now_ms: u64) -> HidEvent {
        let Rx::Receiving { cid: owner, cmd: command, total, got, seq, .. } = self.rx else {
            return HidEvent::None;
        };
        if owner != cid {
            return HidEvent::None;
        }
        if p[4] != seq {
            self.rx = Rx::Idle;
            self.error(cid, err::INVALID_SEQ);
            return HidEvent::None;
        }
        let n = total.saturating_sub(got).min(CONT_DATA);
        let end = got.saturating_add(n);
        if let (Some(dst), Some(src)) = (self.rx_buf.get_mut(got..end), p.get(5..5usize.saturating_add(n))) {
            dst.copy_from_slice(src);
        }
        // Sequence numbers never pass 0x7F: see the assertion on MAX_MSG_SIZE below.
        self.rx = Rx::Receiving { cid, cmd: command, total, got: end, seq: seq.saturating_add(1), last_ms: now_ms };
        self.maybe_dispatch()
    }

    fn maybe_dispatch(&mut self) -> HidEvent {
        let Rx::Receiving { cid, cmd: command, total, got, .. } = self.rx else {
            return HidEvent::None;
        };
        if got < total {
            return HidEvent::None;
        }
        self.req_len = total;
        match command {
            cmd::PING => {
                self.rx = Rx::Idle;
                if self.tx.active {
                    self.error(cid, err::CHANNEL_BUSY);
                    return HidEvent::None;
                }
                if let (Some(d), Some(s)) = (self.tx_buf.get_mut(..total), self.rx_buf.get(..total)) {
                    d.copy_from_slice(s);
                    self.tx = Tx { cid, cmd: cmd::PING, len: total, sent: 0, seq: 0, active: true };
                }
                HidEvent::None
            }
            cmd::WINK => {
                self.rx = Rx::Idle;
                if total != 0 {
                    self.error(cid, err::INVALID_LEN);
                    return HidEvent::None;
                }
                self.urgent = Some(single_packet(cid, cmd::WINK, &[]));
                HidEvent::Wink
            }
            cmd::CBOR => {
                if total == 0 {
                    self.rx = Rx::Idle;
                    self.error(cid, err::INVALID_LEN);
                    return HidEvent::None;
                }
                self.rx = Rx::Busy { cid };
                HidEvent::Request { cid }
            }
            _ => {
                self.rx = Rx::Idle;
                self.error(cid, err::INVALID_CMD);
                HidEvent::None
            }
        }
    }

    /// Next HID input report to send to the host, if any.
    pub fn next_packet(&mut self) -> Option<Packet> {
        if let Some(p) = self.urgent.take() {
            return Some(p);
        }
        if !self.tx.active {
            return None;
        }
        let t = self.tx;
        let remaining = t.len.saturating_sub(t.sent);
        let mut p = [0u8; PACKET_SIZE];
        let c = t.cid.to_be_bytes();
        let (hdr_len, room): (usize, usize) = if t.sent == 0 { (7, INIT_DATA) } else { (5, CONT_DATA) };
        let n = remaining.min(room);
        if t.sent == 0 {
            #[allow(clippy::cast_possible_truncation)] // len <= MAX_MSG_SIZE < 65536.
            let [bh, bl] = (t.len as u16).to_be_bytes();
            p[..7].copy_from_slice(&[c[0], c[1], c[2], c[3], t.cmd | 0x80, bh, bl]);
        } else {
            p[..5].copy_from_slice(&[c[0], c[1], c[2], c[3], t.seq]);
            self.tx.seq = t.seq.saturating_add(1);
        }
        let end = t.sent.saturating_add(n);
        if let (Some(dst), Some(src)) = (p.get_mut(hdr_len..hdr_len.saturating_add(n)), self.tx_buf.get(t.sent..end)) {
            dst.copy_from_slice(src);
        }
        self.tx.sent = end;
        if end >= t.len {
            self.tx.active = false;
        }
        Some(p)
    }
}
