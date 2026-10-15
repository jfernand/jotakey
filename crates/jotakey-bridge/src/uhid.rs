//! Minimal Linux `/dev/uhid` client (see `linux/uhid.h`), safe Rust, no bindgen.
//!
//! Only the events the bridge needs: `CREATE2`, `INPUT2`, `DESTROY` (written) and
//! `OUTPUT`, `GET_REPORT`, `SET_REPORT` (read). All structs are `__packed__`, so offsets
//! below are plain byte arithmetic.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};

const UHID_DESTROY: u32 = 1;
const UHID_OUTPUT: u32 = 6;
const UHID_GET_REPORT: u32 = 9;
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_SET_REPORT: u32 = 13;
const UHID_SET_REPORT_REPLY: u32 = 14;

const DATA_MAX: usize = 4096;
/// `sizeof(struct uhid_event)`: 4-byte type + largest union member (`uhid_create2_req`).
pub const EVENT_SIZE: usize = 4 + 128 + 64 + 64 + 2 + 2 + 4 * 4 + DATA_MAX;
/// `BUS_USB` from `linux/input.h`.
const BUS_USB: u16 = 0x03;
/// `O_NONBLOCK` on Linux (all mainstream architectures).
const O_NONBLOCK: i32 = 0o4000;
/// `EIO`, returned for get/set-report requests we do not implement.
const EIO: u16 = 5;

/// Device identity for `UHID_CREATE2`.
pub struct Identity<'a> {
    pub name: &'a str,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub report_descriptor: &'a [u8],
}

/// What the kernel told us.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// The host wrote an output report.
    Output(Vec<u8>),
    /// Something we acknowledge or ignore (start/stop/open/close, handled get/set report).
    Other,
}

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Encode `UHID_CREATE2`.
pub fn create2(id: &Identity<'_>) -> io::Result<Vec<u8>> {
    if id.report_descriptor.len() > DATA_MAX || id.name.len() >= 128 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "descriptor or name too long"));
    }
    let mut ev = vec![0u8; EVENT_SIZE];
    put(&mut ev, 0, &UHID_CREATE2.to_ne_bytes());
    put(&mut ev, 4, id.name.as_bytes()); // name[128], NUL-padded
    let rd_size = u16::try_from(id.report_descriptor.len()).map_err(io::Error::other)?;
    let o = 4 + 128 + 64 + 64;
    put(&mut ev, o, &rd_size.to_ne_bytes());
    put(&mut ev, o + 2, &BUS_USB.to_ne_bytes());
    put(&mut ev, o + 4, &id.vendor.to_ne_bytes());
    put(&mut ev, o + 8, &id.product.to_ne_bytes());
    put(&mut ev, o + 12, &id.version.to_ne_bytes());
    put(&mut ev, o + 16, &0u32.to_ne_bytes()); // country
    put(&mut ev, o + 20, id.report_descriptor);
    Ok(ev)
}

/// Encode `UHID_INPUT2` carrying one input report.
pub fn input2(report: &[u8]) -> Vec<u8> {
    let mut ev = vec![0u8; EVENT_SIZE];
    put(&mut ev, 0, &UHID_INPUT2.to_ne_bytes());
    let n = report.len().min(DATA_MAX);
    put(&mut ev, 4, &(n as u16).to_ne_bytes());
    put(&mut ev, 6, &report[..n]);
    ev
}

fn reply(kind: u32, id: u32) -> Vec<u8> {
    let mut ev = vec![0u8; EVENT_SIZE];
    put(&mut ev, 0, &kind.to_ne_bytes());
    put(&mut ev, 4, &id.to_ne_bytes());
    put(&mut ev, 8, &EIO.to_ne_bytes());
    ev
}

/// Decode an event read from the kernel. Returns the event and, for get/set-report
/// requests, the reply that must be written back.
pub fn decode(ev: &[u8]) -> (Event, Option<Vec<u8>>) {
    if ev.len() < 4 {
        return (Event::Other, None);
    }
    let kind = u32::from_ne_bytes([ev[0], ev[1], ev[2], ev[3]]);
    match kind {
        UHID_OUTPUT if ev.len() >= 4 + DATA_MAX + 2 => {
            let size = usize::from(u16::from_ne_bytes([ev[4 + DATA_MAX], ev[5 + DATA_MAX]])).min(DATA_MAX);
            (Event::Output(ev[4..4 + size].to_vec()), None)
        }
        UHID_GET_REPORT | UHID_SET_REPORT if ev.len() >= 8 => {
            let id = u32::from_ne_bytes([ev[4], ev[5], ev[6], ev[7]]);
            let r = if kind == UHID_GET_REPORT { UHID_GET_REPORT_REPLY } else { UHID_SET_REPORT_REPLY };
            (Event::Other, Some(reply(r, id)))
        }
        _ => (Event::Other, None),
    }
}

/// An open virtual HID device. Destroyed on drop.
pub struct Device {
    file: File,
}

impl Device {
    /// Open `/dev/uhid` (non-blocking) and create the device.
    pub fn create(id: &Identity<'_>) -> io::Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).custom_flags(O_NONBLOCK).open("/dev/uhid")?;
        file.write_all(&create2(id)?)?;
        Ok(Self { file })
    }

    /// Wrap an already open, non-blocking event channel (tests use a datagram socket pair).
    #[cfg(test)]
    pub fn from_file(file: File) -> Self {
        Self { file }
    }

    /// Send one input report to the host.
    pub fn send(&mut self, report: &[u8]) -> io::Result<()> {
        self.file.write_all(&input2(report))
    }

    /// Next event, or `Ok(None)` if none is queued.
    pub fn next_event(&mut self) -> io::Result<Option<Event>> {
        let mut buf = vec![0u8; EVENT_SIZE];
        match self.file.read(&mut buf) {
            Ok(n) => {
                let (event, answer) = decode(&buf[..n]);
                if let Some(a) = answer {
                    self.file.write_all(&a)?;
                }
                Ok(Some(event))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl AsRawFd for Device {
    /// For `poll(2)`: readable when the kernel has an event for us.
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        let mut ev = vec![0u8; EVENT_SIZE];
        put(&mut ev, 0, &UHID_DESTROY.to_ne_bytes());
        let _ = self.file.write_all(&ev);
    }
}

/// Test helper: the `UHID_OUTPUT` event the kernel sends when the host writes `report`.
#[cfg(test)]
pub fn output_event(report: &[u8]) -> Vec<u8> {
    let mut ev = vec![0u8; EVENT_SIZE];
    put(&mut ev, 0, &UHID_OUTPUT.to_ne_bytes());
    put(&mut ev, 4, report);
    put(&mut ev, 4 + DATA_MAX, &(report.len() as u16).to_ne_bytes());
    ev
}

/// Test helper: the report carried by a `UHID_INPUT2` event, if `ev` is one.
#[cfg(test)]
pub fn input2_report(ev: &[u8]) -> Option<Vec<u8>> {
    if ev.len() < 6 || u32::from_ne_bytes([ev[0], ev[1], ev[2], ev[3]]) != UHID_INPUT2 {
        return None;
    }
    let n = usize::from(u16::from_ne_bytes([ev[4], ev[5]]));
    ev.get(6..6 + n).map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_size_matches_kernel() {
        // sizeof(struct uhid_event) on Linux: 4 + sizeof(struct uhid_create2_req).
        assert_eq!(EVENT_SIZE, 4376);
    }

    #[test]
    fn create2_layout() {
        let ev = create2(&Identity { name: "x", vendor: 0x1209, product: 1, version: 2, report_descriptor: &[9, 8, 7] })
            .unwrap();
        assert_eq!(u32::from_ne_bytes(ev[0..4].try_into().unwrap()), UHID_CREATE2);
        assert_eq!(ev[4], b'x');
        assert_eq!(ev[5], 0);
        let o = 4 + 256;
        assert_eq!(u16::from_ne_bytes([ev[o], ev[o + 1]]), 3);
        assert_eq!(u16::from_ne_bytes([ev[o + 2], ev[o + 3]]), BUS_USB);
        assert_eq!(u32::from_ne_bytes(ev[o + 4..o + 8].try_into().unwrap()), 0x1209);
        assert_eq!(&ev[o + 20..o + 23], &[9, 8, 7]);
    }

    #[test]
    fn output_and_report_requests() {
        let mut ev = vec![0u8; EVENT_SIZE];
        put(&mut ev, 0, &UHID_OUTPUT.to_ne_bytes());
        put(&mut ev, 4, &[0, 1, 2, 3]);
        put(&mut ev, 4 + DATA_MAX, &4u16.to_ne_bytes());
        assert_eq!(decode(&ev), (Event::Output(vec![0, 1, 2, 3]), None));

        let mut ev = vec![0u8; EVENT_SIZE];
        put(&mut ev, 0, &UHID_GET_REPORT.to_ne_bytes());
        put(&mut ev, 4, &77u32.to_ne_bytes());
        let (e, answer) = decode(&ev);
        assert_eq!(e, Event::Other);
        let a = answer.unwrap();
        assert_eq!(u32::from_ne_bytes(a[0..4].try_into().unwrap()), UHID_GET_REPORT_REPLY);
        assert_eq!(u32::from_ne_bytes(a[4..8].try_into().unwrap()), 77);
        assert_eq!(u16::from_ne_bytes([a[8], a[9]]), EIO);
    }

    #[test]
    fn short_events_are_ignored() {
        assert_eq!(decode(&[1, 2]), (Event::Other, None));
        assert_eq!(decode(&UHID_OUTPUT.to_ne_bytes()), (Event::Other, None));
    }
}
