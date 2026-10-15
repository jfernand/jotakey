//! Serial framing for tunnelling 64-byte CTAPHID reports over the USB-Serial/JTAG port.
//!
//! The ESP32-C6 cannot be a USB HID device. Reports therefore travel as frames on a byte
//! stream, and `jotakey-bridge` turns them into a virtual HID device on the host:
//!
//! ```text
//! frame = COBS( report[64] ‖ CRC-32/ISO-HDLC(report) as little-endian u32 ) ‖ 0x00
//! ```
//!
//! COBS removes every zero byte from the body, so `0x00` always marks a frame boundary and
//! the receiver resynchronises after any corruption. The CRC catches corruption on the
//! wire. It is an integrity check, **not** a security mechanism: the host side is untrusted
//! anyway, and every CTAP message is validated by the core. Corrupt frames are dropped
//! silently and the host's CTAPHID timeouts take care of retries.

use super::ctaphid::{PACKET_SIZE, Packet};

/// Report plus CRC.
pub const RAW_LEN: usize = PACKET_SIZE + 4;
/// Maximum COBS-encoded length of [`RAW_LEN`] bytes (one overhead byte per 254), plus the
/// delimiter.
pub const FRAME_MAX: usize = RAW_LEN + 1 + 1;

/// CRC-32/ISO-HDLC (the zlib/Ethernet CRC), bitwise. Small and fast enough for 64 bytes.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Encode one report as a complete frame (including the trailing `0x00`).
/// Returns the buffer and the number of valid bytes.
#[must_use]
pub fn encode(report: &Packet) -> ([u8; FRAME_MAX], usize) {
    let mut raw = [0u8; RAW_LEN];
    let (r, c) = raw.split_at_mut(PACKET_SIZE);
    r.copy_from_slice(report);
    c.copy_from_slice(&crc32(report).to_le_bytes());

    let mut out = [0u8; FRAME_MAX];
    let mut code_idx = 0usize;
    let mut code = 1u8;
    let mut w = 1usize;
    for &b in &raw {
        if b == 0 {
            if let Some(slot) = out.get_mut(code_idx) {
                *slot = code;
            }
            code_idx = w;
            w = w.saturating_add(1);
            code = 1;
        } else {
            if let Some(slot) = out.get_mut(w) {
                *slot = b;
            }
            w = w.saturating_add(1);
            code = code.saturating_add(1);
            if code == 0xFF {
                if let Some(slot) = out.get_mut(code_idx) {
                    *slot = code;
                }
                code_idx = w;
                w = w.saturating_add(1);
                code = 1;
            }
        }
    }
    if let Some(slot) = out.get_mut(code_idx) {
        *slot = code;
    }
    // `w` is now the length without the delimiter; the delimiter is the zero already there.
    (out, w.saturating_add(1).min(FRAME_MAX))
}

/// Decode a COBS body (without the delimiter) into `out`; returns the decoded length.
fn cobs_decode(body: &[u8], out: &mut [u8; RAW_LEN]) -> Option<usize> {
    let mut r = 0usize;
    let mut w = 0usize;
    while r < body.len() {
        let code = *body.get(r)?;
        if code == 0 {
            return None;
        }
        r = r.checked_add(1)?;
        let n = usize::from(code).checked_sub(1)?;
        let end = r.checked_add(n)?;
        let src = body.get(r..end)?;
        let wend = w.checked_add(n)?;
        out.get_mut(w..wend)?.copy_from_slice(src);
        w = wend;
        r = end;
        if code != 0xFF && r < body.len() {
            *out.get_mut(w)? = 0;
            w = w.checked_add(1)?;
        }
    }
    Some(w)
}

/// Streaming frame decoder. Feed bytes as they arrive; complete, CRC-valid reports come out.
#[derive(Debug)]
pub struct Deframer {
    buf: [u8; FRAME_MAX],
    len: usize,
    overflow: bool,
    /// Frames dropped for bad length, COBS or CRC (diagnostics only).
    pub dropped: u32,
}

impl Default for Deframer {
    fn default() -> Self {
        Self::new()
    }
}

impl Deframer {
    /// Empty decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: [0; FRAME_MAX], len: 0, overflow: false, dropped: 0 }
    }

    /// Process one byte; returns a report when a valid frame ends with this byte.
    pub fn push(&mut self, b: u8) -> Option<Packet> {
        if b != 0 {
            if let Some(slot) = self.buf.get_mut(self.len) {
                *slot = b;
                self.len = self.len.saturating_add(1);
            } else {
                self.overflow = true;
            }
            return None;
        }
        let (len, overflow) = (self.len, self.overflow);
        self.len = 0;
        self.overflow = false;
        if len == 0 {
            return None; // idle delimiter
        }
        let report = if overflow { None } else { self.decode(len) };
        if report.is_none() {
            self.dropped = self.dropped.saturating_add(1);
        }
        report
    }

    fn decode(&self, len: usize) -> Option<Packet> {
        let mut raw = [0u8; RAW_LEN];
        let n = cobs_decode(self.buf.get(..len)?, &mut raw)?;
        if n != RAW_LEN {
            return None;
        }
        let (report, crc) = raw.split_at(PACKET_SIZE);
        let crc: [u8; 4] = crc.try_into().ok()?;
        if crc32(report) != u32::from_le_bytes(crc) {
            return None;
        }
        report.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::vec::Vec;

    #[test]
    fn crc_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    fn roundtrip(report: &Packet) -> Option<Packet> {
        let (frame, n) = encode(report);
        assert!(frame[..n - 1].iter().all(|&b| b != 0), "COBS body must be zero-free");
        assert_eq!(frame[n - 1], 0);
        let mut d = Deframer::new();
        let mut got = None;
        for &b in &frame[..n] {
            if let Some(p) = d.push(b) {
                got = Some(p);
            }
        }
        got
    }

    #[test]
    fn all_zero_and_no_zero_reports() {
        assert_eq!(roundtrip(&[0; 64]), Some([0; 64]));
        assert_eq!(roundtrip(&[0xAB; 64]), Some([0xAB; 64]));
    }

    #[test]
    fn corruption_is_dropped_and_stream_resyncs() {
        let a = [7u8; 64];
        let b = [9u8; 64];
        let (fa, na) = encode(&a);
        let (fb, nb) = encode(&b);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend_from_slice(b"garbage log line\n");
        stream.push(0);
        let mut bad = fa[..na].to_vec();
        bad[10] ^= 0x40;
        stream.extend_from_slice(&bad);
        stream.extend_from_slice(&fb[..nb]);
        let mut d = Deframer::new();
        let out: Vec<Packet> = stream.iter().filter_map(|&x| d.push(x)).collect();
        assert_eq!(out, std::vec![b]);
        assert_eq!(d.dropped, 2);
    }

    proptest! {
        #[test]
        fn any_report_roundtrips(v in proptest::collection::vec(any::<u8>(), 64)) {
            let report: Packet = v.try_into().unwrap();
            prop_assert_eq!(roundtrip(&report), Some(report));
        }

        #[test]
        fn arbitrary_bytes_never_panic(data: Vec<u8>) {
            let mut d = Deframer::new();
            for b in data {
                let _ = d.push(b);
            }
        }
    }
}
