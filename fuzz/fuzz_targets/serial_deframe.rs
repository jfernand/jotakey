// (c) Javier Fernandez @ JotaSoft 2026
//! Serial deframer: arbitrary byte streams never panic, every report it emits came from
//! wire bytes that are exactly `encode(report)` (same COBS body, valid CRC, so no corrupted
//! frame and no second encoding is accepted), and an intact frame always gets through,
//! whatever came before it.
//!
//! Random bytes almost never carry a valid CRC, so the input is a script that builds the
//! stream: records `[op, ...]`.
//! - op % 3 == 0: `op / 3` raw bytes follow (boot text, garbage, stray delimiters);
//! - op % 3 == 1: a 64-byte report follows; send its frame intact;
//! - op % 3 == 2: a 64-byte report and a `(position, value)` pair follow; send its frame
//!   with that byte overwritten.

#![no_main]

use jotakey_core::transport::ctaphid::{PACKET_SIZE, Packet};
use jotakey_core::transport::serial::{Deframer, FRAME_MAX, encode};
use libfuzzer_sys::fuzz_target;

fn report(rest: &mut &[u8]) -> Option<Packet> {
    let r: Packet = rest.get(..PACKET_SIZE)?.try_into().ok()?;
    *rest = &rest[PACKET_SIZE..];
    Some(r)
}

fuzz_target!(|data: &[u8]| {
    // The wire, and for each intact frame the index of its closing delimiter.
    let mut wire: Vec<u8> = Vec::new();
    let mut intact: Vec<(usize, Packet)> = Vec::new();
    let mut rest = data;
    while let Some((&op, tail)) = rest.split_first() {
        rest = tail;
        match op % 3 {
            0 => {
                let n = usize::from(op / 3).min(rest.len());
                wire.extend_from_slice(&rest[..n]);
                rest = &rest[n..];
            }
            1 => {
                let Some(r) = report(&mut rest) else { break };
                let (frame, n) = encode(&r);
                wire.extend_from_slice(&frame[..n]);
                intact.push((wire.len() - 1, r));
            }
            _ => {
                let Some(r) = report(&mut rest) else { break };
                let [pos, val, tail @ ..] = rest else { break };
                rest = tail;
                let (mut frame, n) = encode(&r);
                frame[usize::from(*pos) % n] = *val;
                wire.extend_from_slice(&frame[..n]);
            }
        }
    }

    let mut d = Deframer::new();
    let mut segment: Vec<u8> = Vec::new(); // bytes since the last delimiter
    let mut expected = intact.iter().peekable();
    for (i, &b) in wire.iter().enumerate() {
        let got = d.push(b);
        if b != 0 {
            segment.push(b);
            assert!(got.is_none(), "report emitted before its delimiter");
            continue;
        }
        if let Some(r) = got {
            // frame = 0x00 ‖ COBS(report ‖ CRC) ‖ 0x00
            let (frame, n) = encode(&r);
            assert!(segment.len() < FRAME_MAX, "accepted an overlong frame");
            assert_eq!(&frame[1..n - 1], &segment[..], "accepted bytes are not the frame's encoding");
        }
        if let Some(&&(end, r)) = expected.peek() {
            if end == i {
                expected.next();
                assert_eq!(got, Some(r), "intact frame lost");
            }
        }
        segment.clear();
    }
});
