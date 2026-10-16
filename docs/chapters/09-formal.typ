#import "../isss-template.typ": *
#import "../lib.typ": *

= Formal verification, from the ground up

This chapter assumes no background in formal methods. It explains what formal
verification is, surveys the techniques, teaches enough Lean 4 to read Jotakey's proofs,
walks through those proofs, and is explicit about what they do *not* guarantee.

== What a proof buys you

Every test in chapter 8 checks *some* inputs. A fuzzer may run a billion of them, but a
CTAP message has more possible values than there are atoms in the universe. As Dijkstra
put it in 1970, "program testing can be used to show the presence of bugs, but never to
show their absence."

A *formal proof* is different in kind. It is a mathematical argument, checked mechanically
by a computer, that a property holds for *every* input, *every* sequence of events, *every*
possible state. When we prove "no execution of the authenticator state machine produces a
signature without a confirmed touch", we are not sampling executions. We have shown that
such an execution cannot exist.

The catch is the word *model*. A proof is about a precise mathematical description of a
system. If that description differs from the real system, the proof says nothing about the
difference. Much of the craft lies in choosing what to model, and in closing the gap
between model and code (§9.7).

#keypoint[Testing samples behaviours. Proof covers all of them, for the model it is about.]

== The landscape of techniques

Formal methods form a spectrum, from cheap and automatic to expensive and complete. They
are complements, not rivals. Jotakey uses several at once.

#dtable(
  columns: (1.05fr, 2fr, 1.4fr),
  ("Technique", "What it does", "Examples"),
  ([Type systems], [Rule out whole classes of errors at compile time. Rust's ownership types rule out use-after-free and data races in safe code.], [Rust, Haskell, OCaml]),
  ([Property-based testing], [Check a stated property on many random inputs, shrinking failures to a minimal example.], [proptest, QuickCheck, Hypothesis]),
  ([Fuzzing], [Coverage-guided random inputs search for crashes and violated assertions.], [libFuzzer, AFL++, cargo-fuzz]),
  ([Model checking], [Exhaustively explore every state of a finite (or bounded) model, and produce a counterexample trace if a property fails.], [TLA+/TLC, SPIN, CBMC, *Kani* (Rust)]),
  ([Abstract interpretation], [Over-approximate all behaviours to prove the absence of run-time errors.], [Astrée (Airbus flight software), MIRAI]),
  ([Deductive verification], [Annotate code with pre/postconditions and invariants; an SMT solver discharges the proof obligations automatically.], [Dafny, Why3, Frama-C, *Verus*, *Creusot*, *Prusti*]),
  ([Interactive theorem proving], [Write definitions and proofs in a rich logic; a small kernel checks every step. Most expressive and most laborious.], [Rocq (Coq), Isabelle/HOL, *Lean 4*, F\*]),
)

Landmark results show what the strong end can reach:

- *seL4* (Isabelle/HOL, 2009–): an operating-system microkernel whose C implementation is
  proved to refine its specification, down to the compiled binary.
- *CompCert* (Coq): a C compiler proved never to miscompile. In a large compiler-testing
  study, it was the only compiler in which no wrong-code bugs were found in the verified
  parts.
- *HACL\** and *Fiat-Crypto*: verified cryptographic code now running in Firefox, the
  Linux kernel, Chrome and BoringSSL.
- *Amazon Web Services*: TLA+ for distributed protocols; the Cedar authorization language,
  whose specification and proofs are written in Lean.

== Lean 4 in twenty minutes

Lean 4 is both a functional programming language and a proof assistant. That duality is
exactly what we need: the *same* definitions can be run (as an executable specification)
and reasoned about (as mathematics).

=== Data and functions

Types are defined by listing their constructors, and functions by pattern matching:

#codepanel(title: "Data and functions")[
```lean
inductive PresenceResult where       -- result of waiting for a touch
  | confirmed | timeout | cancelled

def toLittleEndian : Nat → Nat → List Nat   -- the low `width` bytes, least significant first
  | 0,         _     => []
  | width + 1, value => value % 256 :: toLittleEndian width (value / 256)

#eval toLittleEndian 2 1000          -- [232, 3]
```
]

Lean insists that every function *terminates* and handles *every* case. A function that
could loop or crash is rejected at definition time. For our CBOR decoder that is already a
theorem: the definition compiles, so the decoder terminates on every input.

=== Propositions are types, proofs are programs

The central idea, the *Curry–Howard correspondence*, is that a statement is a type, and
a proof of the statement is a value of that type. `2 + 2 = 4` is a type. `rfl` ("by
reflexivity") is a value of it. A theorem is a definition whose type is the statement:

#codepanel(title: "A first theorem")[
```lean
theorem toLittleEndian_length (width value : Nat) :
    (toLittleEndian width value).length = width := by
  induction width generalizing value with
  | zero          => rfl                         -- the empty list has length 0
  | succ width ih => simp [toLittleEndian, ih]   -- one byte, plus `width` by induction
```
]

The part after `by` is a *tactic script*. Instead of writing the proof term by hand, we
issue commands that build it step by step:

#dtable(
  columns: (0.6fr, 2.4fr),
  ("Tactic", "What it does"),
  ([`intro`], [Assume the premise of an implication ("suppose P …").]),
  ([`cases`, `match`], [Split into one case per constructor ("either it timed out, or …").]),
  ([`induction`], [Prove for 0 (or `[]`), then for `n+1` assuming `n` (or `x :: xs` assuming `xs`).]),
  ([`simp`], [Rewrite with known equations until the goal simplifies away.]),
  ([`omega`], [Decide linear arithmetic over integers and naturals, including `/` and `%` by constants.]),
  ([`rfl`, `decide`], [Close a goal that holds by computation.]),
  ([`exact`, `apply`], [Use an existing lemma to finish, or reduce, the goal.]),
)

=== Who checks the checker?

Tactics are elaborate and could contain bugs. That does not matter. Every tactic only
*proposes* a proof term, and a small, separate *kernel* type-checks the final term. Only
the kernel must be trusted (the "de Bruijn criterion"). Lean also records which *axioms* a
proof relies on. `#print axioms` lists them, and `formal/AxiomAudit.lean` checks every
Jotakey theorem:

#codepanel(title: "lake env lean AxiomAudit.lean (excerpt)")[
```
'Jotakey.Authenticator.signature_requires_confirmed_touch' depends on axioms:
    [propext, Quot.sound]
'Jotakey.Authenticator.trace_signature_counters_increase' depends on axioms:
    [propext, Classical.choice, Quot.sound]
'Jotakey.CtapHid.fragmented_message_is_reassembled' depends on axioms: [propext, Quot.sound]
'Jotakey.Cbor.decodeHead_accepts_only_canonical' depends on axioms: [propext, Quot.sound]
```
]

These are the three standard axioms of Lean's logic (propositional extensionality,
quotient soundness, and choice), the same ones all of mathlib uses. Two markers would mean
trouble: `sorryAx`, which records an unfinished proof, and `Lean.ofReduceBool`, which
records a proof that trusts the compiler. Neither appears, and `just lean` fails the build
if either ever does.

== Modelling: deciding what to prove about

A model is a deliberate simplification. Jotakey's models follow three rules:

+ *Mirror the code's structure.* The Lean `receivePacket` function for CTAPHID has the same cases,
  in the same order, as `CtapHid::handle_packet`. Reviewers can compare them line by line.
+ *Abstract what the property does not depend on.* The authenticator model does not
  parse CBOR or compute ECDSA. A request arrives already classified as
  `makeCredential relyingParty`, `getAssertion relyingParty credential`, `rejected` and so on. "No signature without a
  touch" does not depend on how parsing works, so the parser is not part of that model.
  (It has its own model, below.)
+ *Make assumptions explicit.* Cryptography cannot be proved in Lean. The credential model
  takes the MAC as a *parameter*, and any theorem that needs a cryptographic property
  states it as a hypothesis, visible in the theorem's signature.

== Case study: CBOR has exactly one encoding

The first model, `formal/Jotakey/Cbor/`, mirrors the decoder of §5.1. The key
theorem says that whatever bytes the decoder accepts are *exactly* the canonical
encoding of what it returned:

#codepanel(title: "formal/Jotakey/Cbor/Heads.lean")[
```lean
theorem decodeHead_accepts_only_canonical (bytes : List Nat) (majorType argument : Nat)
    (rest : List Nat)
    (hBytes : ∀ byte ∈ bytes, byte < 256)                       -- these really are bytes
    (h : decodeHead bytes = some (majorType, argument, rest)) : -- the decoder accepted them
    bytes = encodeHead majorType argument ++ rest               -- … so they ARE canonical
```
]

Read it as: "for every byte list `bytes`, if the decoder accepts it, then it is exactly the
canonical encoding of the result, followed by the unread rest." Two different byte strings
can therefore never decode to the same head. The ambiguity attacks of §5.1 are impossible
for any parser that implements this model.

The proof splits on the width of the argument (immediate, 1, 2, 4 or 8 bytes). In each
case it uses a lemma about big-endian numbers, `bigEndian_bytes_roundtrip`: reading `k`
bytes as a number and writing the number back as `k` bytes gives the same bytes. The minimality check is
what makes the case split work. A value accepted from the 2-byte form is ≥ 256, so
`encodeHead` also chooses the 2-byte form. Without that check in the decoder, the theorem
would be *false*, and Lean would refuse the proof. That is the point: the proof would not
have gone through for a lax decoder.

Its companion, `decodeHead_inverts_encodeHead`, proves the round trip in the other
direction. The full validator `skipItem`, which handles maps, key ordering, UTF-8 and
depth, is defined in `Cbor.lean`, next to it. Lean's termination checker accepts it, so
the decoder provably terminates on every input.

== Case study: the security state machines

=== No signature without a touch, ever

`formal/Jotakey/Authenticator.lean` models `Authenticator::process` and `complete` as
pure functions `processRequest` and `completePresence` on a `State` (pending command,
signature counter, reset epoch, fault flag), driven by `Event`s: requests and presence
results. A *trace* is any list of events, in any order, of
any length. The theorems quantify over all of them:

#codepanel(title: "formal/Jotakey/Authenticator.lean")[
```lean
-- Invariant 1.
theorem signature_requires_confirmed_touch (state : State) (event : Event)
    (relyingParty counter : Nat)
    (hSigned : (handleEvent state event).2 = .signature relyingParty counter) :
    event = .presence .confirmed ∧ state.faulted = false ∧
      (state.pending = .makeCredential relyingParty ∨
        ∃ credential, state.pending = .getAssertion relyingParty credential)

theorem one_touch_signs_at_most_once (state : State) (first second : PresenceResult)
    (relyingParty counter : Nat) :
    (completePresence (completePresence state first).1 second).2 ≠
      .signature relyingParty counter

-- Invariant 2, over every possible trace.
theorem trace_signature_counters_increase (state : State) (events : List Event) :
    (signatureCounters (runTrace state events).2).Pairwise (· < ·)
```
]

In words:

- A signature comes *only* from a confirmed presence event that completes a parked
  makeCredential or getAssertion for *that* relying party, on a healthy device.
- One touch completes at most one command. A second "confirmed" event right after
  produces nothing.
- In *any* interleaving of requests, touches, timeouts, cancellations and resets, the
  counters of emitted signatures form a strictly increasing sequence.

`epoch_change_requires_reset_in_window` proves invariant 6 over traces. If the epoch ever
changes, the trace contains a reset request that arrived within 10 seconds of power-up.
`faulted_stays_faulted_and_never_signs` proves that the fault state of invariant 7 is
absorbing.

=== Channel isolation and exact reassembly

`formal/Jotakey/CtapHid.lean` models the CTAPHID receive path.
`receivePackets_ignores_other_channels` proves that any sequence of packets from other
channels leaves the owning channel's transaction exactly as it was.
`receivePacket_preserves_well_formed` proves that buffers never exceed the announced
length or the 1200-byte limit. `fragmented_message_is_reassembled` proves that a message
fragmented the way a host must fragment it is delivered intact:

#codepanel(title: "formal/Jotakey/CtapHid.lean")[
```lean
theorem fragmented_message_is_reassembled (channel command : Nat) (message : List Nat)
    (hMaxSize : message.length ≤ maxMessageSize) :
    receivePackets .idle (fragmentMessage channel command message) = .busy channel message
```
]

While writing this proof, Lean pointed out that a hypothesis we had added,
`0 < message.length`, was never used. The theorem also holds for empty messages. Proof
assistants often teach you something about your own design this way.

=== Credential binding, with the assumption on the table

#codepanel(title: "formal/Jotakey/Credential.lean")[
```lean
theorem unwrap_accepts_only_wrapped_ids (key relyingParty credentialId nonce : List Nat)
    (h : unwrap mac key relyingParty credentialId = some nonce) :
    credentialId = wrap mac key relyingParty nonce ∧ nonce.length = nonceLength

theorem credential_bound_to_relying_party
    (hNoCrossSiteCollision : ∀ key party party' nonce,          -- the cryptographic
      party ≠ party' → mac key party nonce ≠ mac key party' nonce)  -- assumption
    (key relyingParty otherParty nonce : List Nat) (hNonceLength : nonce.length = nonceLength)
    (hDifferentParty : relyingParty ≠ otherParty) :
    unwrap mac key otherParty (wrap mac key relyingParty nonce) = none
```
]

`unwrap_accepts_only_wrapped_ids` needs no assumption at all: the construction accepts
nothing but its own outputs. `credential_bound_to_relying_party` needs the MAC not to
collide across relying parties, and says so in its signature. That division is what a proof should give you: everything that can be
established by logic is, and the rest is named.

== Closing the gap between model and code

The proofs are about Lean functions. The device runs Rust. How do we know they agree?
There are three increasingly strong answers. Jotakey implements the first two today and
plans the third.

=== 1. Faithful transcription and review

Each model mirrors its Rust counterpart's structure (§9.4), and every Rust module states
which Lean file models it. Changes to one require changes to the other (`AGENTS.md` §4).
This is the weakest link: it relies on human care.

=== 2. Differential testing against an executable specification

Lean definitions are executable. The very functions the CBOR theorems are about are
compiled into a program, and a Rust test asks it and the Rust decoder the same 101 536
questions. Every answer must match. Any future change to the Rust decoder that departs
from the proved model fails this test. Differential testing does not prove equivalence,
but it ties the proofs to the code with a mechanical check rather than review alone.
§9.8 shows how it works.

The fuzz targets play a similar role for the other models: their oracles are the theorem
statements ("counter moves only on a confirmed signature", "reassembly never exceeds the
announced length") checked on the real Rust code.

=== 3. Translating the Rust itself: Aeneas (planned experiment)

*Aeneas* (Ho & Protzenko, Inria/Microsoft) translates Rust into pure Lean functions,
using the *Charon* front end to extract the compiler's internal representation. Rust's
ownership discipline is what makes this possible: a program without aliasing of mutable
data can be expressed as a pure function that takes a value and returns the updated one.
With Aeneas, we would no longer *write* `receivePacket` in Lean. We would *generate* it from
`ctaphid.rs` and prove that the generated function refines the hand-written model (or
prove the theorems directly about it). That removes link 1 entirely. Microsoft has used
this route to verify parts of its Rust cryptography library (SymCrypt).

Aeneas supports a subset of Rust. `jotakey-core` is written to stay close to it: no trait
objects, no interior mutability, simple loops with explicit bounds (`AGENTS.md` §4). A few
closures remain in the CTAP layer (`find_in_list`, `write_success`). Rewriting them as plain
loops is the first step of the experiment. The
experiment is recorded in the roadmap. Other tools could close the same gap differently:

#dtable(
  columns: (0.8fr, 2.3fr),
  ("Tool", "Approach"),
  ([Aeneas], [Rust → pure Lean (or F\*, Coq, HOL4); interactive proofs about the translation.]),
  ([hax], [Rust → F\* or Rocq; used for the verified ML-KEM in the `libcrux` library.]),
  ([Verus], [Annotated Rust, verified by an SMT solver; good for low-level code with loop invariants.]),
  ([Kani], [Bounded model checking of Rust (CBMC); proves absence of panics and assertion failures for bounded inputs, with no annotations.]),
  ([Creusot, Prusti], [Deductive verification of annotated Rust (Why3 and Viper backends).]),
)

Kani is the cheapest next step. It could prove, for all inputs up to a bound, that
`Decoder::skip` and `CtapHid::handle_packet` never panic, directly on the Rust code.

== Differential testing, step by step

*Differential testing* gives the same input to two implementations of the same thing and
compares their answers. It needs no expected outputs: each implementation is the other's
oracle, and any disagreement means at least one of them is wrong. The technique is old
(McKeeman named it in 1998), and it is how tools like Csmith found hundreds of bugs in
GCC and LLVM by comparing compilers against each other.

Jotakey uses a stronger version. One side is the shipped Rust decoder. The other side is
not a second hand-written decoder but *the Lean model itself*, the functions `decodeHead`
and `validate` that §9.5 proves theorems about. A test failure therefore means one precise
thing: the Rust code does something the proved model does not.

=== Step 1: the model becomes a program

Lean is a programming language as well as a prover, so the same definitions that appear
in the theorems can be compiled. `formal/Main.lean` wraps them in a short program,
`jotakey-spec`, that reads one question per line and answers it:

#codepanel(title: "A conversation with jotakey-spec")[
```text
head 1817            →  err          0x18 says "1-byte argument", but 0x17 = 23 fits in the
                                      initial byte: non-minimal, rejected
head 1818            →  ok 0 24 2    major 0 (unsigned), value 24, 2 bytes consumed
head 190100          →  ok 0 256 3   2-byte argument 0x0100 = 256
validate a201000200  →  ok 5         map {1: 0, 2: 0}: keys in canonical order
validate a202000100  →  err          map {2: 0, 1: 0}: keys out of order
validate 5f          →  err          indefinite-length byte string: not canonical
```
]

`head` asks for one CBOR head: major type, argument, and how many bytes it used. `validate`
asks whether the input starts with one complete, canonical data item, and how long it is.
The program contains no decoding logic of its own. Hex parsing and printing are the only
code between the question and the proved definitions.

=== Step 2: the same questions to Rust

`crates/jotakey-core/tests/differential.rs` asks `Decoder::head` and `Decoder::skip` the
same questions and prints the answers in the same format. It starts `jotakey-spec` as a
child process, writes every question to its input, reads every answer back, and compares
the two strings exactly.

#sequence(
  ("Rust test", "Rust decoder", "jotakey-spec (Lean)"),
  (
    (0, 0, [generate 50 768 inputs (fixed seed)]),
    (0, 1, [Decoder::head / skip]),
    (1, 0, [`ok 0 256 3`]),
    (0, 2, [`head 190100`]),
    (2, 0, [`ok 0 256 3`]),
    (0, 0, [equal? next input : fail with both answers]),
  ),
  caption: [One round of the differential test. All questions are sent in one batch.],
)

Agreement means more than "both accepted". They must agree on the decoded values and on
the *number of bytes consumed*. A decoder that accepted the right item but stopped one byte
early would leave that byte to be misread as the next item. That is how parser
differentials are exploited, so it is checked.

=== Step 3: questions worth asking

Purely random bytes are almost always rejected in the first byte or two, so they would
test little more than the error path. The test builds four families of inputs:

#dtable(
  columns: (1.15fr, 0.55fr, 2.3fr),
  ("Family", "Inputs", "What it exercises"),
  ([Generated values], [20 000], [Random nested arrays, maps, integers, byte and text strings, booleans and null, encoded by the Rust encoder. Half of the integers are boundary values: 0, 23, 24, 255, 256, 65 535, 65 536, 2³²−1, 2³², 2⁶³−1, 2⁶³, 2⁶⁴−2, 2⁶⁴−1. These exercise the accepting paths deep inside maps and arrays.]),
  ([Mutated values], [20 000], [Each generated value again, with up to two random edits: overwrite a byte, truncate, append, swap two neighbours, or insert a byte known to be dangerous (`5f` indefinite length, `ff` break, `f7` undefined, `c0` tag, `f9` half float, `1c` reserved, `18` one-byte head). These land just beside valid inputs, where bugs live.]),
  ([Random bytes], [10 000], [0 to 11 random bytes.]),
  ([All heads], [768], [Every possible initial byte 0x00–0xFF, alone, followed by eight `00` bytes, and followed by eight `ff` bytes. Together these cover every head shape, every width and both extremes of every argument.]),
)

Each input is asked both ways, as `head` and as `validate`, which gives 101 536 questions.
They take about a quarter of a second. The generator uses a fixed seed, so a failure is
reproducible. The test also checks that more than a tenth of the answers are
acceptances; at present 80 069 are. Otherwise a broken generator could produce only
garbage, both sides would answer `err` to everything, and the test would pass while
testing nothing.

=== Seeing it catch a bug

To check that the test has teeth, we broke the Rust decoder on purpose. In `Decoder::head`,
a 2-byte argument must be at least 256, otherwise it should have used one byte. We changed
`if v <= 0xFF` to `if v < 0xFF`, a one-character off-by-one that lets exactly one
non-canonical encoding through. The differential test failed at once:

#codepanel(title: "cargo test -p jotakey-core --test differential")[
```text
assertion `left == right` failed: Rust and Lean disagree on `validate 3900ff4bc5d540`
  left: "ok 3"
 right: "err"
```
]

`39` is major type 1 (negative integer) with a 2-byte argument, `00 ff`. That is 255,
which fits in one byte, so the encoding is not canonical. The broken Rust accepted it
(`ok 3`); the model refused it (`err`). The input came from the "mutated values" family.

The same bug was also caught by a unit test, `rejects_non_minimal_heads`, which checks this
exact boundary (`19 00 ff`) by hand. The random property test
`accepted_heads_are_canonical` did *not* catch it: random bytes rarely land on a value of
exactly 255 after a `39`. Each net has different holes.

=== What a pass does and does not mean

A pass means: on 101 536 inputs, chosen to sit on the boundaries, the shipped decoder gives
exactly the answers of a function proved to have canonical uniqueness, termination and the
round-trip property. It is the strongest link between the proofs and the Rust code that
Jotakey has today. It does not mean:

- *Equivalence on all inputs.* The test samples. An input outside the four families could
  still differ. The Aeneas route of §9.7 would close this gap with a proof.
- *Coverage of the other models.* Only the CBOR decoder has an executable specification so
  far. The state-machine models are linked to the Rust code by fuzz oracles that check the
  theorem statements (chapter 8), not by differential tests.
- *Protection against a shared misreading of the standard.* If the model and the Rust code
  both misunderstand RFC 8949 in the same way, they agree and the test passes. The theorems
  help here because they state the intended properties independently of either
  implementation. Reviewing the model against the standard remains a human job.

The Lean compiler and runtime that build `jotakey-spec` are also trusted, but they would
have to fail in a way that exactly mimics a Rust bug for the test to wrongly pass.

Running it takes two commands. Without the spec binary the test reports that it skipped;
setting `JOTAKEY_REQUIRE_SPEC=1` turns a missing binary into a failure, which is the right
setting for continuous integration.

#codepanel(title: "Running the differential test")[
```sh
cd formal && lake build jotakey-spec && cd ..
cargo test -p jotakey-core --test differential -- --nocapture
# differential: 101536 queries agree (80069 accepted)
```
]

== What remains trusted

A verified system is only as trustworthy as its *trusted computing base*, the parts that
are assumed rather than proved. For Jotakey:

#dtable(
  columns: (1fr, 2.4fr),
  ("Trusted component", "Why we accept it, and mitigations"),
  ([Lean kernel + 3 axioms], [Small, widely used, independently re-checkable (external checkers exist).]),
  ([The models' faithfulness], [Mirrored structure, review, the differential test, fuzz oracles. Aeneas would remove most of this.]),
  ([The specification itself], [A proof that the code meets a wrong spec is worthless. Our specs are short, written in the vocabulary of the CTAP text, and reviewed against it.]),
  ([rustc + LLVM], [Not verified. Overflow checks stay on in release builds. On-device tests run the actual binary.]),
  ([RustCrypto `p256`, `sha2`, `hmac`, `hkdf`], [Audited, widely deployed; checked at boot against published test vectors.]),
  ([Cryptographic hardness], [ECDLP on P-256, SHA-256 collision resistance. Named explicitly (e.g. `credential_bound_to_relying_party`'s hypothesis).]),
  ([The silicon], [See chapter 7: fault injection is outside what any proof here can address.]),
)

== Working with the proofs

#codepanel(title: "Everyday commands")[
```sh
cd formal && lake build                    # check every proof (seconds)
lake env lean AxiomAudit.lean              # which axioms each theorem uses
lake exe jotakey-spec <<< "validate a10102" # run the executable specification
just lean                                  # build + reject sorry, axioms, native_decide
just diff                                  # Rust vs Lean differential test
```
]

To change a model, edit the Lean file, run `lake build` and read the first error. Lean
shows the exact goal it could not prove, which is usually the precise case your change
broke. To *add* a property, state it as a `theorem`. If you get stuck, write `sorry` to
continue exploring. Lean itself only warns about `sorry`, but `just lean` *rejects* it, so an
unfinished proof cannot pass the project's checks.
