//! End-to-end test support for Jotakey.
//!
//! * [`Client`]: a host-side CTAPHID client, written independently of the device code: it
//!   uses its own CBOR codec ([`cbor`]) and only the core's *public constants*.
//! * [`SimDevice`]: the device side running in-process. It is wired exactly like the
//!   firmware's USB task: serial framing → `CtapHid` → `Authenticator`, with keepalives
//!   while "waiting for the touch".
//! * [`Hidraw`]: talks to a real Jotakey through `jotakey-bridge` and `/dev/hidrawN`.
//! * [`webauthn`]: relying-party-side checks (authData parsing, COSE key, signatures).

pub mod cbor;
pub mod webauthn;

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use jotakey_core::ctap::{Authenticator, Outcome};
use jotakey_core::mock::MockPlatform;
use jotakey_core::platform::UpResult;
use jotakey_core::transport::ctaphid::{CtapHid, HidEvent, PACKET_SIZE, Packet, keepalive};
use jotakey_core::transport::serial::{Deframer, encode};
use jotakey_core::{AAGUID, MAX_MSG_SIZE};

/// One 64-byte HID report in each direction.
pub trait ReportIo {
    /// Send an output report.
    fn send(&mut self, report: &Packet) -> io::Result<()>;
    /// Receive an input report, waiting at most `timeout`.
    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Packet>>;
}

const BROADCAST: u32 = 0xFFFF_FFFF;
const CMD_PING: u8 = 0x01;
const CMD_INIT: u8 = 0x06;
const CMD_WINK: u8 = 0x08;
const CMD_CBOR: u8 = 0x10;
const CMD_CANCEL: u8 = 0x11;
const CMD_KEEPALIVE: u8 = 0x3B;
const CMD_ERROR: u8 = 0x3F;

/// Result of a CBOR command.
#[derive(Debug)]
pub struct CborReply {
    /// CTAP status byte.
    pub status: u8,
    /// CBOR body (empty on error).
    pub body: Vec<u8>,
    /// How many `UP_NEEDED` keepalives arrived before the answer.
    pub up_keepalives: usize,
}

/// Host-side CTAPHID client.
pub struct Client<T: ReportIo> {
    io: T,
    cid: u32,
    /// Overall timeout per transaction.
    pub timeout: Duration,
}

impl<T: ReportIo> Client<T> {
    /// Allocate a channel with `CTAPHID_INIT`.
    pub fn connect(io: T) -> io::Result<Self> {
        let mut c = Self { io, cid: BROADCAST, timeout: Duration::from_secs(40) };
        let nonce = *b"jotanonc";
        let (cmd, data) = c.transact(CMD_INIT, &nonce)?;
        if cmd != CMD_INIT || data.len() < 17 || data[..8] != nonce {
            return Err(io::Error::other("bad INIT response"));
        }
        c.cid = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        Ok(c)
    }

    /// Allocated channel id.
    pub fn cid(&self) -> u32 {
        self.cid
    }

    /// Access the underlying I/O (e.g. to change the simulated user's behaviour).
    pub fn io_mut(&mut self) -> &mut T {
        &mut self.io
    }

    fn send_message(&mut self, cmd: u8, data: &[u8]) -> io::Result<()> {
        let mut p = [0u8; PACKET_SIZE];
        p[..4].copy_from_slice(&self.cid.to_be_bytes());
        p[4] = cmd | 0x80;
        p[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let first = data.len().min(57);
        p[7..7 + first].copy_from_slice(&data[..first]);
        self.io.send(&p)?;
        for (seq, chunk) in data[first..].chunks(59).enumerate() {
            let mut p = [0u8; PACKET_SIZE];
            p[..4].copy_from_slice(&self.cid.to_be_bytes());
            p[4] = seq as u8;
            p[5..5 + chunk.len()].copy_from_slice(chunk);
            self.io.send(&p)?;
        }
        Ok(())
    }

    /// Send a message and collect the reply, counting keepalives.
    fn transact_counting(&mut self, cmd: u8, data: &[u8]) -> io::Result<(u8, Vec<u8>, usize)> {
        self.send_message(cmd, data)?;
        let deadline = Instant::now() + self.timeout;
        let mut keepalives = 0;
        let mut msg: Option<(u8, usize, Vec<u8>)> = None;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "no reply"));
            }
            let Some(p) = self.io.recv(left)? else { continue };
            let cid = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
            if cid != self.cid {
                continue;
            }
            if p[4] & 0x80 != 0 {
                let c = p[4] & 0x7F;
                let total = usize::from(u16::from_be_bytes([p[5], p[6]]));
                if c == CMD_KEEPALIVE {
                    if p[7] == keepalive::UP_NEEDED {
                        keepalives += 1;
                    }
                    continue;
                }
                let mut buf = p[7..7 + total.min(57)].to_vec();
                if buf.len() == total {
                    return Ok((c, buf, keepalives));
                }
                buf.reserve(total);
                msg = Some((c, total, buf));
            } else if let Some((c, total, buf)) = msg.as_mut() {
                let n = (*total - buf.len()).min(59);
                buf.extend_from_slice(&p[5..5 + n]);
                if buf.len() == *total {
                    return Ok((*c, std::mem::take(buf), keepalives));
                }
            }
        }
    }

    fn transact(&mut self, cmd: u8, data: &[u8]) -> io::Result<(u8, Vec<u8>)> {
        self.transact_counting(cmd, data).map(|(c, d, _)| (c, d))
    }

    /// `CTAPHID_PING`.
    pub fn ping(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        match self.transact(CMD_PING, data)? {
            (CMD_PING, d) => Ok(d),
            (c, d) => Err(io::Error::other(format!("unexpected reply {c:#x} {d:?}"))),
        }
    }

    /// `CTAPHID_WINK`.
    pub fn wink(&mut self) -> io::Result<()> {
        match self.transact(CMD_WINK, &[])? {
            (CMD_WINK, _) => Ok(()),
            (c, d) => Err(io::Error::other(format!("unexpected reply {c:#x} {d:?}"))),
        }
    }

    /// Send a CTAP2 command (`cmd` byte + CBOR parameters).
    pub fn cbor(&mut self, cmd: u8, params: &[u8]) -> io::Result<CborReply> {
        let mut req = vec![cmd];
        req.extend_from_slice(params);
        match self.transact_counting(CMD_CBOR, &req)? {
            (CMD_CBOR, d, up_keepalives) if !d.is_empty() => {
                Ok(CborReply { status: d[0], body: d[1..].to_vec(), up_keepalives })
            }
            (CMD_ERROR, d, _) => Err(io::Error::other(format!("CTAPHID error {d:?}"))),
            (c, d, _) => Err(io::Error::other(format!("unexpected reply {c:#x} {d:?}"))),
        }
    }

    /// `CTAPHID_CANCEL` for this channel (no reply expected).
    pub fn cancel(&mut self) -> io::Result<()> {
        let mut p = [0u8; PACKET_SIZE];
        p[..4].copy_from_slice(&self.cid.to_be_bytes());
        p[4] = CMD_CANCEL | 0x80;
        self.io.send(&p)
    }
}

/// How the simulated user behaves when a touch is requested.
#[derive(Clone, Copy, Debug)]
pub enum User {
    /// Touch after this many keepalives.
    TouchAfter(u32),
    /// Never touch (the request times out).
    Absent,
}

/// The device side, in-process: serial framing, CTAPHID, authenticator, mock platform.
pub struct SimDevice {
    hid: CtapHid,
    auth: Authenticator,
    /// Platform (counter, epoch, uptime are inspectable and adjustable).
    pub platform: MockPlatform,
    wire_in: Deframer,
    wire_out: Deframer,
    to_host: VecDeque<Packet>,
    waiting: Option<(u32, u32)>,
    cancelled: bool,
    /// Simulated user.
    pub user: User,
    out: Box<[u8; MAX_MSG_SIZE]>,
}

impl SimDevice {
    /// New device whose behaviour is determined by `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            hid: CtapHid::new(),
            auth: Authenticator::new(AAGUID),
            platform: MockPlatform::new(seed),
            wire_in: Deframer::new(),
            wire_out: Deframer::new(),
            to_host: VecDeque::new(),
            waiting: None,
            cancelled: false,
            user: User::TouchAfter(2),
            out: Box::new([0; MAX_MSG_SIZE]),
        }
    }

    fn drain(&mut self) {
        while let Some(p) = self.hid.next_packet() {
            // Over the "wire" and back, exactly like firmware + bridge.
            let (frame, n) = encode(&p);
            for &b in &frame[..n] {
                if let Some(r) = self.wire_out.push(b) {
                    self.to_host.push_back(r);
                }
            }
        }
    }

    fn step_presence(&mut self) {
        let Some((cid, ticks)) = self.waiting else { return };
        let up = if std::mem::take(&mut self.cancelled) {
            Some(UpResult::Cancelled)
        } else {
            match self.user {
                User::TouchAfter(n) if ticks >= n => Some(UpResult::Confirmed),
                User::Absent if ticks >= 5 => Some(UpResult::Timeout),
                _ => None,
            }
        };
        match up {
            Some(up) => {
                self.waiting = None;
                let n = self.auth.complete(&mut self.platform, up, &mut self.out);
                self.hid.respond(cid, &self.out[..n]);
            }
            None => {
                self.hid.keepalive(keepalive::UP_NEEDED);
                self.waiting = Some((cid, ticks + 1));
            }
        }
        self.drain();
    }
}

impl ReportIo for SimDevice {
    fn send(&mut self, report: &Packet) -> io::Result<()> {
        let (frame, n) = encode(report);
        for &b in &frame[..n] {
            let Some(pkt) = self.wire_in.push(b) else { continue };
            match self.hid.handle_packet(&pkt, 0) {
                HidEvent::Request { cid } => {
                    let req = self.hid.request().to_vec();
                    match self.auth.process(&mut self.platform, &req, &mut self.out) {
                        Outcome::Response(n) => self.hid.respond(cid, &self.out[..n]),
                        Outcome::NeedsUserPresence => self.waiting = Some((cid, 0)),
                    }
                }
                HidEvent::Cancel { .. } => self.cancelled = true,
                HidEvent::Abort { .. } => {
                    self.auth.abort();
                    self.waiting = None;
                }
                HidEvent::Wink | HidEvent::None => {}
            }
        }
        self.drain();
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> io::Result<Option<Packet>> {
        if self.to_host.is_empty() {
            self.step_presence();
        }
        match self.to_host.pop_front() {
            Some(p) => Ok(Some(p)),
            None if self.waiting.is_none() => Err(io::Error::new(io::ErrorKind::TimedOut, "device idle")),
            None => Ok(None),
        }
    }
}

/// A real Jotakey seen through `jotakey-bridge` as `/dev/hidrawN`.
pub struct Hidraw {
    file: File,
}

impl Hidraw {
    /// Find the bridge's hidraw node (vendor 0x1209, product 0x0001) via sysfs.
    pub fn find() -> io::Result<PathBuf> {
        for entry in std::fs::read_dir("/sys/class/hidraw")? {
            let entry = entry?;
            let uevent = std::fs::read_to_string(entry.path().join("device/uevent")).unwrap_or_default();
            if uevent.lines().any(|l| l.eq_ignore_ascii_case("HID_ID=0003:00001209:00000001")) {
                return Ok(Path::new("/dev").join(entry.file_name()));
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "no Jotakey hidraw device (is jotakey-bridge running?)"))
    }

    /// Open a hidraw node.
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self { file: OpenOptions::new().read(true).write(true).open(path)? })
    }
}

impl ReportIo for Hidraw {
    fn send(&mut self, report: &Packet) -> io::Result<()> {
        let mut buf = [0u8; PACKET_SIZE + 1]; // report ID 0 + report
        buf[1..].copy_from_slice(report);
        self.file.write_all(&buf)
    }

    fn recv(&mut self, _timeout: Duration) -> io::Result<Option<Packet>> {
        // hidraw reads block until a report arrives; the device sends keepalives at least
        // every 100 ms while it works, so this never blocks for long during a transaction.
        let mut buf = [0u8; PACKET_SIZE];
        let n = self.file.read(&mut buf)?;
        Ok((n == PACKET_SIZE).then_some(buf))
    }
}
