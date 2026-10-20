// (c) Javier Fernandez @ JotaSoft 2026
//! Differential test: the Rust CBOR decoder against the executable Lean specification.
//!
//! The Lean definitions `decodeHead` and `validate` are the ones the theorems in
//! `formal/Jotakey/Cbor/` are proved about. This test sends tens of thousands of inputs to
//! both implementations and requires identical verdicts (accept + consumed length, or
//! reject). Agreement links the proofs to the code that ships.
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
    let Some(spec) = spec_path() else {
        assert!(std::env::var("JOTAKEY_REQUIRE_SPEC").is_err(), "Lean spec binary required but missing");
        eprintln!("SKIPPED: build the Lean spec first (cd formal && lake build)");
        return;
    };

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

    let mut child =
        Command::new(&spec).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("spawn jotakey-spec");
    let mut stdin = child.stdin.take().unwrap();
    let queries: Vec<(String, String)> = inputs
        .iter()
        .flat_map(|b| {
            let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
            [(format!("validate {hex}"), rust_validate(b)), (format!("head {hex}"), rust_head(b))]
        })
        .collect();
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
    let mut accepted = 0;
    for ((q, rust), lean) in queries.iter().zip(&answers) {
        assert_eq!(rust, lean, "Rust and Lean disagree on `{q}`");
        accepted += usize::from(rust.starts_with("ok"));
    }
    eprintln!("differential: {} queries agree ({accepted} accepted)", queries.len());
    assert!(accepted > queries.len() / 10, "corpus should exercise the accepting paths");
}
