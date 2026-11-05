// (c) Javier Fernandez @ JotaSoft 2026
//! The OPTIGA driver against an attacker on the I2C bus (invariants 2 and 4 on the key).
//!
//! Input: `[mode, nonce byte, ops..., 0xFF, tap script...]`.
//!
//! - `mode` bit 0 clear: the attacker sits between the driver and a genuine (simulated)
//!   OPTIGA and, per read transaction, passes it through, flips a bit, replays an earlier
//!   read, answers garbage, or NACKs, as the tap script says. Oracles: every counter value the
//!   driver returns is the OPTIGA's real value and exceeds every earlier one, and every
//!   derived secret is the real `PRF(K_root, input)`: the attacker can make operations fail,
//!   never succeed wrongly.
//! - `mode` bit 0 set: the attacker *is* the bus (no OPTIGA; every read is script bytes).
//!   Oracle: without the binding secret no session is ever established, so nothing succeeds.
//!
//! Each op byte: `% 3 == 0` increment the counter, `1` derive from `K_root`, `2` re-establish
//! the session. Operations that fail re-establish (at most a few times), as the platform does.
//! No operation may panic, whatever the bytes (the driver's parsers are total).

#![no_main]

use jotakey_core::crypto::tls_prf_sha256;
use jotakey_core::optiga::apdu::OID_ROOT;
use jotakey_core::optiga::device::Optiga;
use jotakey_core::optiga::sim::SimOptiga;
use jotakey_core::optiga::{BusError, I2c};
use libfuzzer_sys::fuzz_target;

const BINDING: [u8; 64] = [0x11; 64];
const FRESH: [u8; 64] = [0x22; 64];
const ROOT: [u8; 64] = [0x33; 64];

struct Tap<'a> {
    sim: Option<SimOptiga>,
    script: &'a [u8],
    reads: Vec<Vec<u8>>,
}

impl Tap<'_> {
    fn next(&mut self) -> u8 {
        match self.script.split_first() {
            Some((&b, rest)) => {
                self.script = rest;
                b
            }
            None => 0,
        }
    }
}

impl I2c for Tap<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), BusError> {
        match &mut self.sim {
            Some(sim) => sim.write(bytes),
            None => Ok(()),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(), BusError> {
        let c = self.next();
        if let Some(sim) = &mut self.sim {
            sim.read(buf)?;
        } else {
            for b in buf.iter_mut() {
                *b = self.next();
            }
        }
        match c % 8 {
            5 if !buf.is_empty() => {
                let i = usize::from(self.next()) % buf.len();
                buf[i] ^= 1 << (c >> 5);
            }
            6 if !self.reads.is_empty() => {
                let at = usize::from(self.next()) % self.reads.len();
                let old = &self.reads[at];
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = old.get(i).copied().unwrap_or(0xFF);
                }
            }
            7 => return Err(BusError::Nack),
            _ => {}
        }
        if self.reads.len() < 512 {
            self.reads.push(buf.to_vec());
        }
        Ok(())
    }

    fn delay_us(&mut self, _us: u32) {}
}

fuzz_target!(|data: &[u8]| {
    let [mode, nonce_byte, rest @ ..] = data else { return };
    let split = rest.iter().position(|&b| b == 0xFF).unwrap_or(rest.len());
    let (ops, script) = rest.split_at(split);
    let ops = &ops[..ops.len().min(16)];
    let attacker_only = mode & 1 == 1;
    let sim = (!attacker_only).then(|| SimOptiga::provisioned(*nonce_byte, &BINDING, &FRESH, &ROOT));
    let mut o = Optiga::new(Tap { sim, script, reads: Vec::new() });

    let mut nonce = [*nonce_byte; 32];
    let mut establish = |o: &mut Optiga<Tap>, round: u8| {
        nonce[0] = round;
        // The platform pulses the OPTIGA's reset line before every session.
        if let Some(sim) = &mut o.bus_mut().sim {
            sim.reset();
        }
        let ok = o.open().is_ok() && o.establish(&BINDING, &FRESH, &nonce).is_ok();
        assert!(!(ok && attacker_only), "a session with no OPTIGA behind the bus");
        ok
    };

    let mut round = 0u8;
    establish(&mut o, round);
    let mut last: Option<u32> = None;
    for &op in ops {
        if !o.is_live() {
            round = round.wrapping_add(1);
            if !establish(&mut o, round) {
                continue;
            }
        }
        match op % 3 {
            0 => {
                if let Ok(v) = o.increment_counter() {
                    assert!(!attacker_only);
                    let real = o.bus_mut().sim.as_ref().map(SimOptiga::counter_value);
                    assert_eq!(Some(v), real, "counter value not the OPTIGA's");
                    assert!(last.is_none_or(|l| v > l), "counter went backwards");
                    last = Some(v);
                }
            }
            1 => {
                let input = [op; 40];
                let mut out = [0u8; 32];
                if o.derive(OID_ROOT, &[&input], &mut out).is_ok() {
                    assert!(!attacker_only);
                    let mut want = [0u8; 32];
                    tls_prf_sha256(&ROOT, &[&input], &mut want).unwrap();
                    assert_eq!(out, want, "derived secret not the OPTIGA's");
                }
            }
            _ => {
                round = round.wrapping_add(1);
                establish(&mut o, round);
            }
        }
    }
});
