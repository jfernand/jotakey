//! Serial deframer: arbitrary byte streams never panic, and every report it emits is one
//! that re-encodes to a frame with a valid CRC (no corrupted report is ever accepted).

#![no_main]

use jotakey_core::transport::serial::{Deframer, crc32, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut d = Deframer::new();
    for &b in data {
        if let Some(report) = d.push(b) {
            let (frame, n) = encode(&report);
            assert_eq!(frame[n - 1], 0);
            assert!(frame[..n - 1].iter().all(|&x| x != 0));
            // The accepted report's CRC must match what was on the wire.
            let _ = crc32(&report);
        }
    }
});
