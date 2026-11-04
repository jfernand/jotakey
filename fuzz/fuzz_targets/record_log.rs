// (c) Javier Fernandez @ JotaSoft 2026
//! Record log under power cuts (invariant 2): whatever the schedule of appends, cuts and
//! remounts, a remount never goes below the last confirmed sequence number, the confirmed
//! record reads back with its payload, confirmed numbers strictly increase, and while the
//! power holds every append succeeds (so the log never breaks the flash's programming
//! rules, which the mock enforces: whole units, each programmed once).
//!
//! Input: `[config, ops...]`. `config` bit 0 picks the programming unit (4 or 8), bits 1–2
//! the payload size (4, 32 or 36 bytes, the sizes the platforms store). Each op:
//! - op % 3 == 0: append a payload filled with `op`;
//! - op % 3 == 1: two bytes follow, a little-endian step count; cut the power after that
//!   many steps and append until a write fails;
//! - op % 3 == 2: restore power and remount.

#![no_main]

use jotakey_core::storage::RecordLog;
use jotakey_core::storage::mock::MockFlash;
use libfuzzer_sys::fuzz_target;

/// Append `[fill; N]`; on success check and record the confirmed value.
fn append<const N: usize>(
    log: &mut RecordLog<N>,
    f: &mut MockFlash,
    confirmed: &mut Option<(u32, [u8; N])>,
    fill: u8,
) -> bool {
    match log.append(f, &[fill; N]) {
        Ok(seq) => {
            assert!(confirmed.is_none_or(|(s, _)| seq > s), "sequence number did not increase");
            *confirmed = Some((seq, [fill; N]));
            true
        }
        Err(_) => false,
    }
}

fn run<const N: usize>(unit: u32, mut ops: &[u8]) {
    let mut f = MockFlash::with_unit(unit);
    let mut log = RecordLog::<N>::mount(&mut f, 0).expect("mount of an erased flash");
    let mut confirmed: Option<(u32, [u8; N])> = None;
    while let Some((&op, rest)) = ops.split_first() {
        ops = rest;
        match op % 3 {
            0 => {
                if !f.dead {
                    assert!(append(&mut log, &mut f, &mut confirmed, op), "append failed with the power on");
                }
            }
            1 => {
                let [lo, hi, rest @ ..] = ops else { break };
                ops = rest;
                f.cut_after = Some(u32::from(u16::from_le_bytes([*lo, *hi])));
                while append(&mut log, &mut f, &mut confirmed, op) {}
            }
            _ => {
                f.power_on();
                log = RecordLog::<N>::mount(&mut f, 0).expect("mount after a power cut");
                if let Some((seq, payload)) = confirmed {
                    let got = log.latest().copied();
                    assert!(got.is_some_and(|(s, _)| s >= seq), "remount lost a confirmed value");
                    if got.is_some_and(|(s, _)| s == seq) {
                        assert_eq!(got.map(|g| g.1), Some(payload), "confirmed payload changed");
                    }
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&config, ops)) = data.split_first() else { return };
    let unit = if config & 1 == 0 { 4 } else { 8 };
    match (config >> 1) % 3 {
        0 => run::<4>(unit, ops),
        1 => run::<32>(unit, ops),
        _ => run::<36>(unit, ops),
    }
});
