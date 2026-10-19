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

Every byte that reaches the key from the host is chosen by someone who may be an attacker:
the browser, the operating system, the bridge, any program that can open the HID device or
reach the BLE link. Invariant 4 demands that the parsers handle *every* byte string,
not just the ones the specification describes. Unit tests check the inputs their authors
thought of. A *fuzzer* generates inputs nobody thought of, by the million, and watches what
happens.

=== How a coverage-guided fuzzer works

Jotakey uses `cargo fuzz`, which drives *libFuzzer*, the fuzzer built into LLVM. A *fuzz
target* is a function that takes a byte slice and feeds it to the code under test. The
compiler instruments every branch of the program, so after each run the fuzzer knows which
edges of the control-flow graph that input reached. The loop is:

#layers(
  caption: "One iteration of libFuzzer's loop, millions of times per run",
  ("1. Pick", [An input from the *corpus*, the set of inputs kept so far (initially the seeds).], "light"),
  ("2. Mutate", [Flip bits, insert, erase or copy bytes, splice two inputs, write "interesting" values (0, 0xFF, lengths), or insert a *dictionary* entry.], "light"),
  ("3. Run", [Call the target. Sanitizers and assertions watch every operation.], "amber"),
  ("4. Observe", [A crash, panic, timeout or out-of-memory stops the run and saves the input. Otherwise: did this input reach an edge (or an edge count) never seen before?], "dark"),
  ("5. Keep", [If it did, add it to the corpus: it is a stepping stone toward deeper code.], "dark"),
)

The fifth step is what makes the search *coverage-guided* rather than random. An input
that gets one byte further into a CBOR map is kept, and its mutations get further still.
The fuzzer climbs into the program a branch at a time, the way a person learns a format by
trial and error, only a million times faster.

Comparison tracing helps it over walls. The instrumentation also records the operands of
every comparison the program makes, so when the deframer compares a computed CRC with the
one on the wire, the fuzzer learns the value it needed and tries it next. The "recommended
dictionary" libFuzzer prints at the end of a run is the record of these values: for the
serial target it is full of 4-byte CRCs.

What counts as a failure:

- *Panics.* The core is built with `overflow-checks = true`, so an arithmetic overflow is a
  panic, not a silent wrap. An out-of-range index, a failed `expect` in the target, or an
  assertion is also a panic. libFuzzer treats each as a crash.
- *Memory errors.* AddressSanitizer is on. The core has no `unsafe`, so this mostly guards
  the dependencies and the harness.
- *Hangs and blow-ups.* A run that exceeds the time limit (unbounded loops, invariant 4's
  "no unbounded recursion") or the memory limit is reported as a failure.

=== Oracles: from "no crash" to "no wrong answer"

A fuzzer only notices what goes wrong loudly. Code that returns a wrong answer quietly,
such as accepting a malformed message, signing without a touch, or moving the counter twice, passes
unnoticed. *Oracles* fix this: assertions in the target that turn a violated property into
a crash. They are what make Jotakey's fuzzing a security test instead of a robustness test.

Take `cbor_decode`. "The decoder does not panic" is the obvious property. The oracle adds a
stronger one: whatever the strict decoder accepts is re-encoded item by item, and the
result must equal the input *byte for byte*. If two different byte strings decoded to the
same value, an attacker could produce a second encoding of a signed message, and
canonical CBOR exists to rule that out. The oracle is the statement of the Lean theorem
`decodeHead_accepts_only_canonical` (§9.5), checked on the real Rust code, which the proof
never sees.

The other oracles follow the same idea: each states a security invariant in executable
form.

=== Reaching deep code

Random bytes rarely get far. A CTAPHID request must arrive on an allocated channel in
packets whose sequence numbers count up. A serial frame must carry a CRC-32 that random
data matches once in four billion tries. A makeCredential must be a well-formed CBOR map
with sorted keys before any credential logic runs. A target that only ever hits the first
`return Err` tests very little. Four techniques get the inputs through:

- *Inputs as scripts.* The fuzzer's bytes are read as instructions that *build* a valid
  outer layer, rather than as the outer layer itself. In `ctaphid_stack` the first byte of
  each 65-byte record picks the channel (mostly ones already allocated), whether the clock
  jumps past the packet timeout, and whether the user touches or times out. The
  `serial_deframe` input says "send these raw bytes", "send an intact frame of this
  report" or "send this frame with one byte changed".
- *Templates.* In `ctap_dispatch` an odd first byte means "take a valid makeCredential or
  getAssertion and overwrite these positions with these values". Every mutation starts
  one step from a valid request, so the deep validation paths are hit from the first run.
- *A genuine credential.* `ctap_dispatch` registers one credential once (`OnceLock`) and
  puts its real ID in the getAssertion template, so mutated assertions can *succeed*, and
  the oracles about successful signatures get exercised.
- *Seeds.* `fuzz/make_seeds.py` writes real transactions in each target's input format to
  `fuzz/seeds/` (tracked in git): a CTAPHID INIT followed by getInfo or makeCredential,
  the same over BLE, boot text followed by frames. `just fuzz` hands them to libFuzzer next
  to the working corpus in `fuzz/corpus/` (not tracked: it is regenerated by fuzzing).

#callout(kind: "trap", "An oracle that never fires tests nothing")[
  Coverage numbers can look healthy while the important path is never taken. Writing this
  chapter, we counted what each corpus actually reaches. The `serial_deframe` target had
  run millions of times without ever accepting a frame: no random input had a valid CRC,
  so its oracle about accepted frames had never once been evaluated (and was weak anyway:
  it computed a CRC and threw it away). The CTAPHID corpus never got a request through to
  the authenticator, and the BLE corpus never produced a successful response.
  The fixes are the script format of `serial_deframe`, a stronger oracle, and seeds. After
  them the serial corpus accepts about 10 000 frames per pass, and the transport targets
  start from successful makeCredential and getInfo exchanges. To check that the new oracle
  has teeth, we disabled the deframer's CRC comparison: the fuzzer reported "accepted
  bytes are not the frame's encoding" within seconds. A fuzz target is code too, and it
  needs its own test.
]

=== The six targets

Each target runs the real core code against `MockPlatform`, a deterministic stand-in for
the hardware: its random numbers come from a seeded generator and its key store is
software HMAC, so every crash reproduces exactly. Its failure switches (`fail_rng`,
`fail_counter`, `fail_derive`) are what the unit tests use for the fail-closed paths.

#breakable-code[
#dtable(
  columns: (0.9fr, 1.4fr, 2.2fr, 0.45fr),
  ("Target", "Input", "Oracle (beyond: no panic, no hang)", "Inv."),
  ([`cbor_decode`], [Raw bytes to the strict CBOR decoder.], [Anything accepted re-encodes to *exactly* the input bytes: no value has two encodings.], [4]),
  ([`ctap_dispatch`], [`[mode, presence, …]`: a raw request, or byte overwrites of a valid makeCredential/getAssertion template; the presence byte picks touch, timeout or cancel.], [The counter moves only on a successful makeCredential/getAssertion, by exactly one. A signature produced after parking needed a confirmed touch; one produced without parking is a getAssertion with the UP flag clear. Success bodies are canonical CBOR with no trailing bytes. Nothing stays parked. Responses are 1 to `MAX_MSG_SIZE` bytes.], [1, 2, 4]),
  ([`ctaphid_stack`], [Records `[flags, packet(64)]`: channel choice, clock jumps, touch or timeout.], [The full USB path: reassembly, the authenticator, fragmentation. Receive state stays within bounds; no request is left unanswered; output is bounded.], [4, 5]),
  ([`ble_stream`], [A fragment size, then GATT writes of chosen lengths with clock advances.], [The BLE framer and the authenticator together. No notification exceeds the fragment size.], [4]),
  ([`serial_deframe`], [A script of raw bytes, intact frames and frames with one byte overwritten.], [Every report emitted came from wire bytes that are exactly its encoding (so its CRC was valid and no second encoding is accepted); nothing is emitted before a delimiter; an intact frame always gets through, whatever garbage came before it.], [4]),
  ([`credential_unwrap`], [A tag key, an `rpIdHash` and a candidate credential ID.], [An accepted ID is exactly what `wrap` mints for the recovered nonce at that RP; a minted ID always unwraps to its nonce.], [3]),
)
]

The `serial_deframe` property "an intact frame always gets through" is the regression test
for the bridge startup hang of chapter 6: before every frame began with a delimiter, boot text
in front of a frame made it undecodable.

=== Running, reproducing, fixing

```sh
just fuzz ctap_dispatch          # one target, 5 minutes (just fuzz T SECONDS)
just fuzz-all 120                # every target, 2 minutes each
python3 fuzz/make_seeds.py       # regenerate the seeds after a format change
```

Fuzzing needs a nightly toolchain (for the sanitizers) and `cargo install cargo-fuzz`.
When a target fails, libFuzzer stops, prints the panic message and saves the input as
`fuzz/artifacts/<target>/crash-<hash>`. Then:

+ *Reproduce:* `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`
  replays exactly that input. `MockPlatform` is deterministic, so it fails the same way
  every time.
+ *Minimise:* `cargo +nightly fuzz tmin <target> <crash file>` shrinks the input to the
  smallest one that still fails, usually a handful of bytes that make the bug obvious.
+ *Fix, and keep a unit test.* The minimised input becomes an ordinary test in
  `jotakey-core`, so the bug stays fixed even when nobody is fuzzing. The serial framing
  test `boot_text_before_the_first_frame_does_not_swallow_it` is an example.

`cargo +nightly fuzz cmin <target>` prunes a corpus to the inputs that still add coverage,
and `cargo +nightly fuzz coverage <target>` produces a line-coverage report of what the
corpus reaches. That report is the first thing to look at when a target seems too quiet.

=== Why it helps, and what it cannot do

- *It finds the inputs nobody imagined.* People who write tests share the blind spots of
  the people who wrote the code, and are often the same people. The fuzzer has no
  expectations: it will send a map with 2³² announced entries, a continuation packet on a
  channel that never started, or a frame split across a reboot, because the coverage told it
  those paths exist.
- *It checks properties, not examples.* One oracle covers every input the fuzzer will ever
  produce. Adding a property costs a few lines; the fuzzer then tests it millions of
  times an hour, unattended.
- *It ties the proofs to the code.* The Lean models of chapters 9 and 10 are proved for
  *all* inputs, but they are models: hand transcriptions of the Rust. The fuzz oracles state
  the same theorems and check them on the real code (chapter 10 pairs each oracle with its
  theorem). The two
  nets have different holes: the proofs cover every input of the model, the fuzzer many
  inputs of the real implementation.
- *It complements mutation testing.* Mutation testing asks whether the tests notice a
  broken program. Fuzzing asks whether the program breaks on inputs the tests do not
  contain. The section below shows the first; the trap above shows a fuzz target that,
  like a weak test, could not have noticed anything.

The limits are as important:

- *No guarantee.* A fuzzer that finds nothing has found nothing *yet*. It cannot guess a
  128-bit tag, and a bug behind such a check is out of its reach; proofs and review cover
  those.
- *Host only.* Targets run on x86 against the mock platform. The firmware adapters (esp-hal
  drivers, flash, the HMAC peripheral, and on the key the OPTIGA driver once it exists) are
  not fuzzed; the on-device
  tests and end-to-end tests below cover them.
- *Functional properties only.* Timing leaks, power side channels and fault injection are
  invisible to a fuzzer. Invariant 9 relies on `subtle`, RustCrypto and review.

The latest run, two minutes per target from the seeds with no failures:

#dtable(
  columns: (1fr, 1fr, 1fr, 1fr, 1fr, 1fr),
  ("cbor_decode", "ctap_dispatch", "ctaphid_stack", "ble_stream", "serial_deframe", "credential_unwrap"),
  ([14.9 M], [2.7 M], [0.6 M], [2.6 M], [2.2 M], [35.4 M]),
)

Executions per run depend on how much code each input reaches: a CTAPHID input carries
whole transactions through the authenticator, including ECDSA signatures, while a
credential ID check is one HMAC. Longer runs before a release are worth their time, and
inputs captured from real browsers through the bridge make good seeds.

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
