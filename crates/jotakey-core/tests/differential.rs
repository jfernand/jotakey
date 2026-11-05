// (c) Javier Fernandez @ JotaSoft 2026
//! Differential tests: Rust code against the executable Lean specification.
//!
//! - The CBOR decoder: the Lean definitions `decodeHead` and `validate` are the ones the
//!   theorems in `formal/Jotakey/Cbor/` are proved about. Tens of thousands of inputs go to
//!   both implementations, which must give identical verdicts (accept + consumed length, or
//!   reject).
//! - The presence gate (`presence.rs` ↔ `Presence.lean`): the same reading sequences must
//!   give the same steps.
//! - The record log (`storage.rs` ↔ `RecordLog.lean`): from the same flash contents, mount
//!   followed by a completed append must return the same sequence number and leave the same
//!   slots, at both programming units.
//!
//! Agreement links the proofs to the code that ships.
//!
//! Needs the spec binary: `cd formal && lake build`. The path defaults to
//! `formal/.lake/build/bin/jotakey-spec`; override with `JOTAKEY_SPEC`. Without the binary
//! the test reports that it skipped. Set `JOTAKEY_REQUIRE_SPEC=1` to turn that into a failure.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use common::V;
use jotakey_core::cbor::Decoder;
use jotakey_core::optiga::device::release_counter;
use jotakey_core::optiga::shielded::{Handshake, Purpose, SCTR_RECORD, Session};
use jotakey_core::optiga::sim::SlaveSession;
use jotakey_core::presence::{GateStep, PresenceGate};
use jotakey_core::storage::mock::MockFlash;
use jotakey_core::storage::{Flash, RecordLog, SECTOR_SIZE};
use jotakey_core::transport::serial::crc32;

/// Small deterministic PRNG (xorshift64*) so failures are reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const EDGE: [u64; 14] = [
    0,
    1,
    23,
    24,
    255,
    256,
    65_535,
    65_536,
    0xFFFF_FFFF,
    0x1_0000_0000,
    (1 << 63) - 1,
    1 << 63,
    u64::MAX - 1,
    u64::MAX,
];

fn gen_uint(r: &mut Rng) -> u64 {
    if r.below(2) == 0 { EDGE[r.below(EDGE.len() as u64) as usize] } else { r.below(1000) }
}

fn gen_text(r: &mut Rng) -> String {
    const POOL: [&str; 8] = ["id", "type", "name", "displayName", "alg", "rk", "é", "public-key"];
    POOL[r.below(POOL.len() as u64) as usize].to_string()
}

fn gen_value(r: &mut Rng, depth: u32) -> V {
    let leaf = depth >= 6 || r.below(3) == 0;
    match if leaf { r.below(6) } else { r.below(8) } {
        0 => V::U(gen_uint(r)),
        1 => V::N(-1 - (gen_uint(r) >> 1) as i64),
        2 => V::B((0..r.below(5)).map(|_| r.next() as u8).collect()),
        3 => V::T(gen_text(r)),
        4 => V::Bool(r.below(2) == 0),
        5 => V::Null,
        6 => V::A((0..r.below(4)).map(|_| gen_value(r, depth + 1)).collect()),
        _ => V::M(
            (0..r.below(4))
                .map(|_| {
                    let k = if r.below(2) == 0 { V::int(r.below(30) as i64 - 10) } else { V::T(gen_text(r)) };
                    (k, gen_value(r, depth + 1))
                })
                .collect(),
        ),
    }
}

fn mutate(r: &mut Rng, mut b: Vec<u8>) -> Vec<u8> {
    for _ in 0..r.below(3) {
        match r.below(5) {
            0 if !b.is_empty() => {
                let i = r.below(b.len() as u64) as usize;
                b[i] = r.next() as u8;
            }
            1 if !b.is_empty() => {
                let n = r.below(b.len() as u64) as usize;
                b.truncate(n);
            }
            2 => b.push(r.next() as u8),
            3 if b.len() > 1 => {
                let i = r.below(b.len() as u64 - 1) as usize;
                b.swap(i, i + 1);
            }
            _ => {
                let i = r.below(b.len() as u64 + 1) as usize;
                b.insert(i, [0x5f, 0xff, 0xf7, 0xc0, 0xf9, 0x1c, 0x18][r.below(7) as usize]);
            }
        }
    }
    b
}

fn rust_validate(b: &[u8]) -> String {
    let mut d = Decoder::new(b);
    match d.skip(0) {
        Ok(()) => format!("ok {}", d.position()),
        Err(_) => "err".into(),
    }
}

fn rust_head(b: &[u8]) -> String {
    let mut d = Decoder::new(b);
    match d.head() {
        Ok((m, a)) => format!("ok {m} {a} {}", d.position()),
        Err(_) => "err".into(),
    }
}

fn spec_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("JOTAKEY_SPEC") {
        return Some(PathBuf::from(p));
    }
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../formal/.lake/build/bin/jotakey-spec");
    p.exists().then_some(p)
}

#[test]
fn rust_decoder_agrees_with_lean_spec() {
    let Some(spec) = spec_or_skip() else { return };

    let mut rng = Rng(0x6a6f_7461_6b65_7921);
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for _ in 0..20_000 {
        let v = gen_value(&mut rng, 0).encode();
        inputs.push(v.clone());
        inputs.push(mutate(&mut rng, v));
    }
    for _ in 0..10_000 {
        let n = rng.below(12) as usize;
        inputs.push((0..n).map(|_| rng.next() as u8).collect());
    }
    // Every single byte and every byte followed by 8 zero/0xff bytes: covers all heads.
    for b in 0..=255u8 {
        inputs.push(vec![b]);
        inputs.push([vec![b], vec![0; 8]].concat());
        inputs.push([vec![b], vec![0xff; 8]].concat());
    }

    let queries: Vec<(String, String)> = inputs
        .iter()
        .flat_map(|b| {
            let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
            [(format!("validate {hex}"), rust_validate(b)), (format!("head {hex}"), rust_head(b))]
        })
        .collect();
    let queries = agree_with_spec(&spec, queries);
    let accepted = queries.iter().filter(|(_, rust)| rust.starts_with("ok")).count();
    eprintln!("differential: {} CBOR queries agree ({accepted} accepted)", queries.len());
    assert!(accepted > queries.len() / 10, "corpus should exercise the accepting paths");
}

/// Send each `(query, Rust answer)` to the spec and require the spec to answer the same.
fn agree_with_spec(spec: &PathBuf, queries: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut child =
        Command::new(spec).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("spawn jotakey-spec");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        for (q, _) in queries.iter() {
            writeln!(stdin, "{q}").unwrap();
        }
        queries
    });
    let reader = BufReader::new(child.stdout.take().unwrap());
    let answers: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();
    let queries = writer.join().unwrap();
    child.wait().unwrap();
    assert_eq!(answers.len(), queries.len(), "spec answered a different number of queries");
    for ((q, rust), lean) in queries.iter().zip(&answers) {
        assert_eq!(rust, lean, "Rust and Lean disagree on `{q}`");
    }
    queries
}

fn spec_or_skip() -> Option<PathBuf> {
    let spec = spec_path();
    if spec.is_none() {
        assert!(std::env::var("JOTAKEY_REQUIRE_SPEC").is_err(), "Lean spec binary required but missing");
        eprintln!("SKIPPED: build the Lean spec first (cd formal && lake build)");
    }
    spec
}

#[test]
fn presence_gate_agrees_with_lean_spec() {
    let Some(spec) = spec_or_skip() else { return };
    let mut rng = Rng(0x7072_6573_656e_6365);
    let mut queries = Vec::new();
    let mut confirmed = 0;
    for _ in 0..5_000 {
        let start = rng.below(100_000);
        let mut now = start;
        let mut readings = Vec::new();
        for _ in 0..rng.below(40) {
            // Mostly a clock moving forward in poll steps; sometimes a jump or a step back.
            now = match rng.below(20) {
                0 => now + 30_000,
                1 => now.saturating_sub(rng.below(50_000)),
                _ => now + rng.below(60),
            };
            // Runs of presses and releases, as a finger produces them.
            let pressed = if rng.below(4) == 0 {
                rng.below(2) == 0
            } else {
                readings.last().is_some_and(|r: &(u64, bool)| r.1) ^ (rng.below(3) == 0)
            };
            readings.push((now, pressed));
        }
        let mut gate = PresenceGate::new(start);
        let steps: Vec<&str> = readings
            .iter()
            .map(|&(t, p)| match gate.poll(t, p) {
                GateStep::Waiting => "w",
                GateStep::Confirmed => "c",
                GateStep::Timeout => "t",
            })
            .collect();
        confirmed += usize::from(steps.contains(&"c"));
        let words: Vec<String> = readings.iter().map(|&(t, p)| format!("{t}:{}", u8::from(p))).collect();
        queries.push((format!("presence {start} {}", words.join(" ")).trim_end().to_string(), steps.join(" ")));
    }
    let queries = agree_with_spec(&spec, queries);
    eprintln!("differential: {} presence sequences agree ({confirmed} confirm)", queries.len());
    assert!(confirmed > queries.len() / 10, "corpus should exercise confirmations");
}

/// A slot of the record-log model: erased, torn, or a valid record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Erased,
    Torn,
    Record(u32),
}

fn show(slots: &[Slot]) -> String {
    let words: Vec<String> = slots
        .iter()
        .map(|s| match s {
            Slot::Erased => "e".into(),
            Slot::Torn => "t".into(),
            Slot::Record(n) => n.to_string(),
        })
        .collect();
    words.join(",")
}

/// Lay `slots` out at `stride` from `base`, as `RecordLog` writes them (payload `fill`).
fn lay_out(flash: &mut MockFlash, base: usize, stride: usize, n: usize, slots: &[Slot]) {
    for (i, slot) in slots.iter().enumerate() {
        let at = base + i * stride;
        let rec = &mut flash.mem[at..at + stride];
        rec.fill(0xFF);
        let seq = match slot {
            Slot::Erased => continue,
            Slot::Torn => 7,
            Slot::Record(seq) => *seq,
        };
        {
            rec[..4].copy_from_slice(b"JKR1");
            rec[4..8].copy_from_slice(&seq.to_le_bytes());
            rec[8..8 + n].fill(0xAB);
            let crc = crc32(&rec[..8 + n]) ^ u32::from(matches!(slot, Slot::Torn));
            rec[8 + n..12 + n].copy_from_slice(&crc.to_le_bytes());
        }
    }
}

/// Read slots back the way `mount` classifies them.
fn read_back(flash: &mut MockFlash, base: usize, stride: usize, n: usize, capacity: usize) -> Vec<Slot> {
    (0..capacity)
        .map(|i| {
            let mut rec = vec![0; stride];
            flash.read((base + i * stride) as u32, &mut rec).unwrap();
            let body = &rec[..8 + n];
            let crc = u32::from_le_bytes(rec[8 + n..12 + n].try_into().unwrap());
            if &body[..4] == b"JKR1" && crc32(body) == crc {
                Slot::Record(u32::from_le_bytes(body[4..8].try_into().unwrap()))
            } else if rec.iter().all(|&b| b == 0xFF) {
                Slot::Erased
            } else {
                Slot::Torn
            }
        })
        .collect()
}

fn gen_sector(r: &mut Rng, capacity: usize, newest: &mut u32) -> Vec<Slot> {
    let mut slots = vec![Slot::Erased; capacity];
    match r.below(4) {
        // Erased.
        0 => {}
        // A run of consecutive records from the start, maybe ending in a torn one.
        1 | 2 => {
            let k = if r.below(3) == 0 { capacity } else { r.below(capacity as u64 + 1) as usize };
            let first = *newest + 1 + r.below(3) as u32;
            for (i, slot) in slots.iter_mut().take(k).enumerate() {
                *slot = Slot::Record(first + i as u32);
            }
            *newest = first + k as u32;
            if k < capacity && r.below(3) == 0 {
                slots[k] = Slot::Torn;
            }
        }
        // Anything, as a cut erase or corruption leaves it.
        _ => {
            for slot in slots.iter_mut() {
                *slot = match r.below(4) {
                    0 => Slot::Torn,
                    1 => Slot::Record(1 + r.below(2000) as u32),
                    _ => Slot::Erased,
                };
            }
        }
    }
    slots
}

fn append_case<const N: usize>(r: &mut Rng, unit: u32) -> (String, String) {
    let stride = (12 + N).next_multiple_of(unit as usize);
    let capacity = SECTOR_SIZE as usize / stride;
    let mut newest = r.below(1000) as u32;
    let (a, b) = (gen_sector(r, capacity, &mut newest), gen_sector(r, capacity, &mut newest));
    let (zero, one) = if r.below(2) == 0 { (a, b) } else { (b, a) };
    let query = format!("append {} {}", show(&zero), show(&one));
    let mut flash = MockFlash::with_unit(unit);
    lay_out(&mut flash, 0, stride, N, &zero);
    lay_out(&mut flash, SECTOR_SIZE as usize, stride, N, &one);
    let answer = match RecordLog::<N>::mount(&mut flash, 0).and_then(|mut log| log.append(&mut flash, &[0x5A; N])) {
        Ok(seq) => {
            let zero = read_back(&mut flash, 0, stride, N, capacity);
            let one = read_back(&mut flash, SECTOR_SIZE as usize, stride, N, capacity);
            format!("{seq} {} {}", show(&zero), show(&one))
        }
        Err(_) => "err".into(),
    };
    (query, answer)
}

#[test]
fn record_log_agrees_with_lean_spec() {
    let Some(spec) = spec_or_skip() else { return };
    let mut rng = Rng(0x7265_636f_7264_6c6f);
    let mut queries = Vec::new();
    for _ in 0..500 {
        queries.push(append_case::<4>(&mut rng, 4));
        queries.push(append_case::<32>(&mut rng, 4));
        queries.push(append_case::<32>(&mut rng, 8));
        queries.push(append_case::<36>(&mut rng, 8));
    }
    let queries = agree_with_spec(&spec, queries);
    eprintln!("differential: {} record-log appends agree", queries.len());
}

/// One event of the shielded-session model (`formal/Jotakey/Shielded.lean`, `Event`).
enum SessionEvent {
    Handshake(u32),
    Check { sctr: u8, seq: u32, authentic: bool, correct: bool },
    Use { sctr: u8, seq: u32, authentic: bool },
    Fail,
}

/// The real `Session` driven the way `Optiga` drives it: a refusal drops the session; a
/// live-session check that is accepted makes it live only if its value was right.
fn run_sessions(events: &[SessionEvent], rng: &mut Rng) -> String {
    let binding = [0x5Au8; 64];
    let mut current: Option<(Session, SlaveSession)> = None;
    let mut out = Vec::new();
    for e in events {
        let mut used = false;
        match *e {
            SessionEvent::Handshake(sseq) => {
                let rnd: [u8; 32] = core::array::from_fn(|_| rng.below(256) as u8);
                let slave = SlaveSession::new(&binding, rnd);
                let hs = Handshake::start(&binding, &slave.hello(sseq)).expect("hello");
                let mseq = rng.below(1 << 16) as u32;
                let session = hs.finish(&slave.finished(mseq)).expect("finished");
                current = Some((session, slave));
            }
            SessionEvent::Check { sctr, seq, authentic, correct } => {
                if let Some((s, slave)) = current.as_mut() {
                    let (mut msg, n) = slave.record(sctr, seq, &[0, 0, 0, 32], authentic);
                    match s.accept(&mut msg[..n], Purpose::Freshness) {
                        Ok(_) if correct => s.mark_fresh(),
                        _ => current = None,
                    }
                }
            }
            SessionEvent::Use { sctr, seq, authentic } => {
                if let Some((s, slave)) = current.as_mut() {
                    let (mut msg, n) = slave.record(sctr, seq, &[0, 0, 0, 0], authentic);
                    match s.accept(&mut msg[..n], Purpose::Use) {
                        Ok(_) => used = true,
                        Err(_) => current = None,
                    }
                }
            }
            SessionEvent::Fail => current = None,
        }
        let state = match &current {
            None => "-".to_string(),
            Some((s, _)) => format!("{}/{}", s.last_sseq(), u8::from(s.is_fresh())),
        };
        out.push(if used { format!("{state}!") } else { state });
    }
    out.join(" ")
}

#[test]
fn shielded_session_agrees_with_lean_spec() {
    let Some(spec) = spec_or_skip() else { return };
    let mut rng = Rng(0x7368_6965_6c64_6564);
    let mut queries = Vec::new();
    let mut uses = 0;
    for _ in 0..3_000 {
        let mut events = Vec::new();
        let mut words = Vec::new();
        // The test's own idea of the window, to aim most sequence numbers near it.
        let mut last: u32 = 0;
        // Most histories start the way the driver does: a handshake, then the check.
        if rng.below(4) != 0 {
            let sseq = rng.below(1 << 16) as u32;
            last = sseq + 1;
            events.push(SessionEvent::Handshake(sseq));
            events.push(SessionEvent::Check { sctr: SCTR_RECORD, seq: last, authentic: true, correct: true });
            words.push(format!("h{sseq}"));
            words.push(format!("c{SCTR_RECORD}:{last}:1:1"));
        }
        for _ in 0..rng.below(30) {
            let sctr = match rng.below(30) {
                0 => 0x22,
                1 => 0x40,
                _ => SCTR_RECORD,
            };
            let seq = match rng.below(12) {
                0 => last.saturating_sub(rng.below(3) as u32),
                1 => last + 3 + rng.below(3) as u32,
                2 => last + 2,
                _ => last + 1,
            };
            let authentic = rng.below(20) != 0;
            match rng.below(40) {
                0 | 1 => {
                    let sseq = rng.below(1 << 16) as u32;
                    last = sseq;
                    events.push(SessionEvent::Handshake(sseq));
                    words.push(format!("h{sseq}"));
                }
                2 => {
                    let correct = rng.below(5) != 0;
                    events.push(SessionEvent::Check { sctr, seq, authentic, correct });
                    words.push(format!("c{sctr}:{seq}:{}:{}", u8::from(authentic), u8::from(correct)));
                    last = seq.max(last);
                }
                3 => {
                    events.push(SessionEvent::Fail);
                    words.push("f".to_string());
                }
                _ => {
                    events.push(SessionEvent::Use { sctr, seq, authentic });
                    words.push(format!("u{sctr}:{seq}:{}", u8::from(authentic)));
                    last = seq.max(last);
                }
            }
        }
        let rust = run_sessions(&events, &mut rng);
        uses += rust.matches('!').count();
        queries.push((format!("shielded {}", words.join(" ")).trim_end().to_string(), rust));
    }
    let queries = agree_with_spec(&spec, queries);
    eprintln!("differential: {} shielded-session histories agree ({uses} responses used)", queries.len());
    assert!(uses > queries.len(), "corpus should use responses");
}

#[test]
fn counter_release_agrees_with_lean_spec() {
    let Some(spec) = spec_or_skip() else { return };
    let mut rng = Rng(0x0063_6f75_6e74_6572);
    let mut queries = Vec::new();
    for _ in 0..2_000 {
        let mut v = rng.below(1000) as u32;
        let mut values = Vec::new();
        for _ in 0..rng.below(20) {
            v = match rng.below(6) {
                0 => v.saturating_sub(rng.below(5) as u32),
                1 => v,
                2 => [0, u32::MAX, u32::MAX - 1][rng.below(3) as usize],
                _ => v.saturating_add(1 + rng.below(3) as u32),
            };
            values.push(v);
        }
        let mut mark = None;
        let tokens: Vec<&str> = values
            .iter()
            .map(|&x| {
                let (m, ok) = release_counter(mark, x);
                mark = m;
                if ok { "r" } else { "-" }
            })
            .collect();
        let words: Vec<String> = values.iter().map(u32::to_string).collect();
        queries.push((format!("release {}", words.join(" ")).trim_end().to_string(), tokens.join(" ")));
    }
    let queries = agree_with_spec(&spec, queries);
    eprintln!("differential: {} counter sequences agree", queries.len());
}
