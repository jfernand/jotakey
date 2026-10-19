// (c) Javier Fernandez @ JotaSoft 2026
//! A CTAPHID client (CTAP 2.1 §11.2) with timeouts, for keys that may not answer.

use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};

/// HID report size.
pub const PACKET_SIZE: usize = 64;
/// One HID report.
pub type Packet = [u8; PACKET_SIZE];

const BROADCAST: u32 = 0xFFFF_FFFF;
/// CTAPHID command bytes.
pub mod cmd {
    /// Echo.
    pub const PING: u8 = 0x01;
    /// U2F (CTAP1) APDU.
    pub const MSG: u8 = 0x03;
    /// Channel allocation.
    pub const INIT: u8 = 0x06;
    /// Identify the device (blink, beep).
    pub const WINK: u8 = 0x08;
    /// CTAP2 command.
    pub const CBOR: u8 = 0x10;
    /// Still working.
    pub const KEEPALIVE: u8 = 0x3B;
    /// Error reply.
    pub const ERROR: u8 = 0x3F;
}

/// Capability bits from the INIT reply.
pub mod capability {
    /// Supports WINK.
    pub const WINK: u8 = 0x01;
    /// Supports CBOR (CTAP2).
    pub const CBOR: u8 = 0x04;
    /// Does *not* support MSG (no U2F/CTAP1).
    pub const NMSG: u8 = 0x08;
}

/// Something that moves 64-byte HID reports.
pub trait Transport {
    /// Send one output report.
    fn send(&mut self, packet: &Packet) -> io::Result<()>;
    /// Receive one input report, or `None` if nothing arrived within `timeout`.
    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Packet>>;
}

/// A hidraw device node.
pub struct Hidraw {
    file: File,
}

impl Hidraw {
    /// Open `/dev/hidrawN` for reading and writing.
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self { file: OpenOptions::new().read(true).write(true).open(path)? })
    }
}

impl Transport for Hidraw {
    fn send(&mut self, packet: &Packet) -> io::Result<()> {
        let mut report = [0u8; PACKET_SIZE + 1]; // report ID 0, then the report
        report[1..].copy_from_slice(packet);
        self.file.write_all(&report)
    }

    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Packet>> {
        let ts = Timespec::try_from(timeout).map_err(|_| io::Error::other("timeout out of range"))?;
        let mut fds = [PollFd::new(&self.file, PollFlags::IN)];
        if poll(&mut fds, Some(&ts))? == 0 {
            return Ok(None);
        }
        let mut buf = [0u8; PACKET_SIZE];
        let n = self.file.read(&mut buf)?;
        Ok((n == PACKET_SIZE).then_some(buf))
    }
}

/// Why a transaction failed.
#[derive(Debug)]
pub enum Error {
    /// The device node could not be used.
    Io(io::Error),
    /// No (complete) reply in time.
    Timeout,
    /// The device answered `CTAPHID_ERROR` with this code.
    Device(u8),
    /// The reply did not make sense.
    Protocol(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                write!(f, "permission denied (needs a udev rule or uaccess; see scripts/99-jotakey.rules)")
            }
            Self::Io(e) => write!(f, "{e}"),
            Self::Timeout => f.write_str("no reply (timed out)"),
            Self::Device(code) => write!(f, "CTAPHID error {code:#04x} ({})", hid_error_name(*code)),
            Self::Protocol(m) => f.write_str(m),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// CTAPHID error code names (CTAP 2.1 §11.2.9.1.6).
pub fn hid_error_name(code: u8) -> &'static str {
    match code {
        0x01 => "invalid command",
        0x02 => "invalid parameter",
        0x03 => "invalid length",
        0x04 => "invalid sequence",
        0x05 => "message timeout",
        0x06 => "channel busy",
        0x0A => "lock required",
        0x0B => "invalid channel",
        _ => "other",
    }
}

/// What `CTAPHID_INIT` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitInfo {
    /// The channel allocated to us.
    pub channel: u32,
    /// CTAPHID protocol version (2).
    pub protocol_version: u8,
    /// Device version: major, minor, build. Vendor-defined.
    pub device_version: (u8, u8, u8),
    /// Capability bits ([`capability`]).
    pub capabilities: u8,
}

/// A CTAPHID channel to one device.
pub struct Client<T: Transport> {
    io: T,
    channel: u32,
    /// Per-transaction limit, extended by keepalives up to [`Client::max_wait`].
    pub timeout: Duration,
    /// Hard limit for a transaction that keeps sending keepalives.
    pub max_wait: Duration,
}

impl<T: Transport> Client<T> {
    /// Allocate a channel. Fails if the device does not answer INIT in time.
    pub fn connect(io: T) -> Result<(Self, InitInfo), Error> {
        let mut c = Self { io, channel: BROADCAST, timeout: Duration::from_secs(2), max_wait: Duration::from_secs(10) };
        let nonce = random_nonce();
        let reply = c.transact(cmd::INIT, &nonce)?;
        if reply.len() < 17 || reply[..8] != nonce {
            return Err(Error::Protocol(format!("bad INIT reply ({} bytes)", reply.len())));
        }
        let info = InitInfo {
            channel: u32::from_be_bytes([reply[8], reply[9], reply[10], reply[11]]),
            protocol_version: reply[12],
            device_version: (reply[13], reply[14], reply[15]),
            capabilities: reply[16],
        };
        if info.channel == 0 || info.channel == BROADCAST {
            return Err(Error::Protocol(format!("device allocated an invalid channel {:#010x}", info.channel)));
        }
        c.channel = info.channel;
        Ok((c, info))
    }

    /// `CTAPHID_PING`: the device echoes `data`.
    pub fn ping(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.transact(cmd::PING, data)
    }

    /// `CTAPHID_WINK`: the device identifies itself (an LED blink, usually).
    pub fn wink(&mut self) -> Result<(), Error> {
        self.transact(cmd::WINK, &[]).map(|_| ())
    }

    /// `CTAPHID_CBOR`: a CTAP2 command. Returns (status, CBOR body).
    pub fn cbor(&mut self, command: u8, params: &[u8]) -> Result<(u8, Vec<u8>), Error> {
        let mut req = Vec::with_capacity(1 + params.len());
        req.push(command);
        req.extend_from_slice(params);
        let reply = self.transact(cmd::CBOR, &req)?;
        let (&status, body) = reply.split_first().ok_or_else(|| Error::Protocol("empty CBOR reply".into()))?;
        Ok((status, body.to_vec()))
    }

    /// `CTAPHID_MSG`: a U2F APDU. Returns the response including the status word.
    pub fn msg(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        self.transact(cmd::MSG, apdu)
    }

    fn send_message(&mut self, command: u8, data: &[u8]) -> Result<(), Error> {
        let len = u16::try_from(data.len()).map_err(|_| Error::Protocol("message too long".into()))?;
        let mut p = [0u8; PACKET_SIZE];
        p[..4].copy_from_slice(&self.channel.to_be_bytes());
        p[4] = command | 0x80;
        p[5..7].copy_from_slice(&len.to_be_bytes());
        let first = data.len().min(PACKET_SIZE - 7);
        p[7..7 + first].copy_from_slice(&data[..first]);
        self.io.send(&p)?;
        for (seq, chunk) in data[first..].chunks(PACKET_SIZE - 5).enumerate() {
            let seq = u8::try_from(seq).ok().filter(|s| *s < 0x80).ok_or_else(|| Error::Protocol("message too long".into()))?;
            let mut p = [0u8; PACKET_SIZE];
            p[..4].copy_from_slice(&self.channel.to_be_bytes());
            p[4] = seq;
            p[5..5 + chunk.len()].copy_from_slice(chunk);
            self.io.send(&p)?;
        }
        Ok(())
    }

    /// Send `command` and return the reply's payload. Replies on other channels are
    /// ignored; keepalives extend the wait up to `max_wait`.
    fn transact(&mut self, command: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.send_message(command, data)?;
        let start = Instant::now();
        let mut deadline = start + self.timeout;
        let mut msg: Option<(u8, usize, Vec<u8>, u8)> = None; // command, total, data, next seq
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Timeout);
            }
            let Some(p) = self.io.recv(left)? else { continue };
            if u32::from_be_bytes([p[0], p[1], p[2], p[3]]) != self.channel {
                continue;
            }
            if p[4] & 0x80 != 0 {
                let c = p[4] & 0x7F;
                let total = usize::from(u16::from_be_bytes([p[5], p[6]]));
                match c {
                    cmd::KEEPALIVE => {
                        deadline = (Instant::now() + self.timeout).min(start + self.max_wait);
                        continue;
                    }
                    cmd::ERROR => return Err(Error::Device(p[7])),
                    _ => {}
                }
                if c != command {
                    return Err(Error::Protocol(format!("reply to {command:#04x} was command {c:#04x}")));
                }
                // INIT replies come on the broadcast channel and must echo our nonce;
                // anything else is a different client's reply.
                if command == cmd::INIT && p[7..15] != data[..8] {
                    continue;
                }
                let mut buf = p[7..7 + total.min(PACKET_SIZE - 7)].to_vec();
                if buf.len() == total {
                    return Ok(buf);
                }
                buf.reserve(total - buf.len());
                msg = Some((c, total, buf, 0));
            } else if let Some((_, total, buf, next)) = msg.as_mut() {
                if p[4] != *next {
                    return Err(Error::Protocol(format!("continuation {} out of order (expected {next})", p[4])));
                }
                *next += 1;
                let n = (*total - buf.len()).min(PACKET_SIZE - 5);
                buf.extend_from_slice(&p[5..5 + n]);
                if buf.len() == *total {
                    return Ok(std::mem::take(buf));
                }
            }
        }
    }
}

/// Eight unpredictable bytes for INIT, from the standard library's hasher seed.
fn random_nonce() -> [u8; 8] {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(Instant::now().elapsed().as_nanos());
    h.finish().to_be_bytes()
}
