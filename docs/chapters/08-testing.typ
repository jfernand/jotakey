// (c) Javier Fernandez @ JotaSoft 2026
#import "../isss-template.typ": *
#import "../lib.typ": *

= Testing: five nets, different holes

No single technique catches everything, so Jotakey stretches several nets with different
holes one above another. Chapter 9 adds the last one, proof.

#dtable(
  columns: (1.05fr, 1.9fr, 1.3fr),
  ("Net", "What it catches", "Where"),
  ([Unit & scenario tests], [Known behaviours, spec examples, every error path.], [`crates/*/tests`, `#[cfg(test)]`]),
  ([Property tests], [Laws that must hold for *all* inputs: round trips, bounds, monotonicity.], [`proptest` in the core]),
  ([Fuzzing], [Crashes, hangs and invariant violations on inputs nobody imagined.], [`fuzz/` (6 targets)]),
  ([Mutation testing], [Gaps in the *tests themselves*: code whose breakage no test notices.], [`cargo mutants`]),
  ([On-device tests], [What only silicon can show: the TRNG, the HMAC key, real flash, timing.], [`crates/jotakey-testfw`]),
  ([End-to-end], [The whole chain as a relying party sees it.], [`crates/jotakey-host-tests`, `scripts/fido2_check.py`]),
)

== Unit, scenario and property tests

96 tests run on the host in a few seconds (`just test`). Highlights:

- *CBOR:* every integer example from RFC 8949 Appendix A; rejection of non-minimal heads,
  indefinite lengths, tags, floats, `undefined`, invalid UTF-8, unsorted and duplicate map
  keys, nesting deeper than 4; huge announced lengths fail fast instead of looping.
  Properties: head and integer round trips; "accepted heads re-encode to the same bytes";
  "the decoder never panics on arbitrary bytes".
- *CTAP:* full register → authenticate flows with signatures verified against the public
  key parsed from authData; RP binding (`evil.example` gets `NO_CREDENTIALS`); tampered
  IDs; exclude lists; every option combination; algorithm negotiation; PIN probes; missing
  and wrongly typed parameters; reset window boundaries; and *fail closed*: a failing RNG,
  key derivation or counter write yields `CTAP1_ERR_OTHER` and *never* moves the counter.
- *Transports:* CTAPHID at every size boundary (1, 57, 58, 116, 117, 118 … 1200 bytes),
  channel busy and isolation, resync via INIT, sequence errors, timeouts, keepalives,
  cancel; BLE at every fragment size from 20 to 512. Two thousand random packet streams
  check that receive state stays well-formed.
- *Storage:* append and remount across sector switches; a property test that cuts power at
  random byte offsets, including in the middle of a sector erase, and checks that no
  confirmed counter value is lost or reissued.
- *Self tests:* known-answer tests for SHA-256, HMAC, HKDF and ECDSA (RFC 6979 §A.2.5),
  plus *fault injection*: corrupting each KAT result in turn must be detected, exactly as
  FIPS 140-3 expects a self-test implementation to demonstrate.

== Fuzzing

`cargo fuzz` (libFuzzer with AddressSanitizer) drives six targets. Each target checks
security properties, not just "no crash":

#dtable(
  columns: (0.95fr, 2.5fr),
  ("Target", "Oracle"),
  ([`cbor_decode`], [No panic; anything accepted re-encodes to *exactly* the input bytes (canonical uniqueness, the theorem of §9.5, checked on real code).]),
  ([`ctap_dispatch`], [Raw and template-mutated requests through the authenticator. The counter moves *only* on a successful makeCredential/getAssertion completed with a confirmed touch, and by exactly one; success bodies are canonical CBOR; nothing stays parked.]),
  ([`ctaphid_stack`], [Arbitrary 64-byte packet streams on several channels, with clock jumps and absent users, through CTAPHID *and* the authenticator. Buffers stay within bounds, no request is left unanswered, output is bounded.]),
  ([`ble_stream`], [Arbitrary GATT write sequences and fragment sizes, through the BLE framer and the authenticator.]),
  ([`serial_deframe`], [Arbitrary byte streams through the COBS/CRC deframer; every report emitted is a valid frame.]),
  ([`credential_unwrap`], [Accepted IDs are exactly what `wrap` mints; minted IDs always unwrap.]),
)

Smoke runs during development covered roughly 8 million CBOR, 6 million CTAPHID, 4
million BLE, 4.7 million serial, 23 million credential and 2 million full CTAP executions,
with no failures. Corpora grow over time. Inputs captured from real browsers through the
bridge make good seeds.

== Mutation testing

A test suite can pass while testing very little. *Mutation testing* measures this.
`cargo mutants` makes hundreds of small deliberate bugs in the code: it flips `<` to `<=`,
deletes a `!`, replaces a function body with a constant, deletes a `match` arm. It then
runs the test suite against each one. A mutant that survives is a change to the code that
no test notices.

#dtable(
  columns: (1fr, 0.6fr, 2fr),
  ("Run", "Missed", "What changed"),
  ([First run], [61 / 459], [Revealed untested boundaries (user-ID length 64/65, reset window at exactly 10 000 ms), optional members whose *type* was never checked, CTAPHID resync corners, status codes only compared with themselves, and self tests whose failure branch could never run.]),
  ([After fixes], [0], [New targeted tests; an unreachable branch replaced by a compile-time assertion; dead API removed; fault injection added to the self tests.]),
  ([Storage added], [11], [The new record log passed its functional tests, yet its on-flash *format*, CRC rejection and sector-switch schedule were unpinned: mutants that wasted slots or erased too often survived. Fixed with a golden layout test, an erase-count schedule test and corruption tests.]),
  ([Current], [*0 / 530*], [452 caught, 72 unviable (do not compile), 6 time out (infinite loops, counted as caught).]),
)

The policy (`AGENTS.md` §4) is *zero unexplained survivors*. The only excluded class is
documented in `.cargo/mutants.toml`: replacing `|` with `^` where the operands are disjoint
bit fields (`cmd | 0x80` with `cmd < 0x80`), which produces identical values; one
comparison between sequence numbers that are unique by construction; and the mock flash,
which is test scaffolding. Mutants that
make code loop forever are caught by timeouts.

#callout(kind: "info", "Why bother, with proofs available?")[
  Mutation testing found that the self tests' failure paths were never exercised: a broken
  `run_kats` that always returned `Ok` would have passed every test. Proofs about the
  protocol model would not have noticed either, because the self tests are not part of it.
  Each net has holes the others cover.
]

== On-device test firmware

Some properties exist only on silicon. `crates/jotakey-testfw` is a separate firmware
built with `embedded-test` and run by `probe-rs` through the C6's built-in USB-JTAG. No
extra debug probe is needed. Each test is flashed, the chip is reset, the test runs, and
pass/fail comes back over semihosting with logs over RTT.

#dtable(
  columns: (1.2fr, 2.3fr),
  ("Test", "Checks"),
  ([`known_answer_tests_pass_on_target`], [The KATs on the RISC-V target (endianness, compiler, crypto backends).]),
  ([`injected_faults_are_detected_on_target`], [Each injected self-test fault is detected on the target.]),
  ([`trng_health_and_statistics`], [SP 800-90B start-up test; 64 KiB through the continuous tests; byte χ² and monobit within ±6σ.]),
  ([`efuse_root_key_hmac`], [HMAC peripheral with eFuse KEY0: deterministic, label-separated. *Skipped with a warning* on unprovisioned boards.]),
  ([`record_log_on_real_flash`], [600 appends across sector switches on real NOR flash; a torn record is ignored; uses a scratch area that never touches production data.]),
  ([`ctap_register_and_authenticate_on_target`], [Full makeCredential + getAssertion on the chip with the real TRNG; the signature verifies; no touch, no signature.]),
  ([`ecdsa_timing_budget`], [Sign + verify under 400 ms per operation at full clock.]),
  ([`status_led_accepts_frames`], [WS2812 frames via RMT.]),
  ([`user_presence_button` (interactive)], [Press BOOT within 30 s (`--features interactive`).]),
)

== End to end

`jotakey-host-tests` contains a CTAPHID *client* written independently of the device code.
It has its own CBOR codec, so a bug that is symmetric in the device's encoder and decoder
cannot hide. It also contains relying-party checks as a WebAuthn server would perform them
(authData layout, COSE key, packed self-attestation, signatures, counters). The client runs
against two devices:

- *the simulator*, an in-process device wired exactly like the firmware's USB task:
  serial framing → CTAPHID → authenticator, with keepalives while "waiting for the touch".
  This runs in every `just test`.
- *a real Jotakey* through `jotakey-bridge` and `/dev/hidrawN` (ignored by default; run with
  `just host-tests` while touching the button when asked).

Finally, `scripts/fido2_check.py` drives the device with Yubico's *python-fido2*, both as
client *and* as relying-party server. That is a completely independent implementation of
both ends of the protocol.

== Static checks

- `#![forbid(unsafe_code)]` in the core; Clippy denies `unwrap`, `expect`, `panic!`,
  unchecked indexing and unchecked arithmetic in shipped core code.
- `overflow-checks = true` in every profile, release included.
- `cargo deny`: no known-vulnerable or yanked crates, allowed licences only, crates.io
  only. Exceptions are documented with reasons: two unmaintained crates that run only at
  build time (a proc-macro and a build-script YAML parser) and never ship in the firmware.
