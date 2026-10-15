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
inductive Up where              -- result of waiting for a touch
  | confirmed | timeout | cancelled

def toLE : Nat → Nat → List Nat -- the low k bytes of n, least significant first
  | 0,     _ => []
  | k + 1, n => n % 256 :: toLE k (n / 256)

#eval toLE 2 1000               -- [232, 3]
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
theorem length_toLE (k n : Nat) : (toLE k n).length = k := by
  induction k generalizing n with
  | zero      => rfl                      -- toLE 0 n = [], whose length is 0
  | succ k ih => simp [toLE, ih]          -- one byte, plus k by the induction hypothesis
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
'Jotakey.Authenticator.signature_needs_touch' depends on axioms: [propext, Quot.sound]
'Jotakey.Authenticator.trace_counters_increasing' depends on axioms: [propext, Classical.choice, Quot.sound]
'Jotakey.CtapHid.reassemble_fragment' depends on axioms: [propext, Quot.sound]
'Jotakey.Cbor.encodeHead_of_decodeHead' depends on axioms: [propext, Quot.sound]
```
]

These are the three standard axioms of Lean's logic (propositional extensionality,
quotient soundness, and choice), the same ones all of mathlib uses. Two markers would mean
trouble: `sorryAx`, which records an unfinished proof, and `Lean.ofReduceBool`, which
records a proof that trusts the compiler. Neither appears, and `just lean` fails the build
if either ever does.

== Modelling: deciding what to prove about

A model is a deliberate simplification. Jotakey's models follow three rules:

+ *Mirror the code's structure.* The Lean `step` function for CTAPHID has the same cases,
  in the same order, as `CtapHid::handle_packet`. Reviewers can compare them line by line.
+ *Abstract what the property does not depend on.* The authenticator model does not
  parse CBOR or compute ECDSA. A request arrives already classified as
  `makeCredential rp`, `getAssertion rp cred`, `rejected` and so on. "No signature without a
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
theorem encodeHead_of_decodeHead (l : List Nat) (major arg : Nat) (rest : List Nat)
    (hb : ∀ b ∈ l, b < 256)                         -- l is a list of bytes
    (h : decodeHead l = some (major, arg, rest)) :  -- the decoder accepted it
    l = encodeHead major arg ++ rest                -- … so l IS the canonical encoding
```
]

Read it as: "for every byte list `l`, if the decoder accepts it, then `l` is exactly the
canonical encoding of the result, followed by the unread rest." Two different byte strings
can therefore never decode to the same head. The ambiguity attacks of §5.1 are impossible
for any parser that implements this model.

The proof splits on the width of the argument (immediate, 1, 2, 4 or 8 bytes). In each
case it uses a lemma about big-endian numbers, `toBE_fromBE`: reading `k` bytes as a number
and writing the number back as `k` bytes gives the same bytes. The minimality check is
what makes the case split work. A value accepted from the 2-byte form is ≥ 256, so
`encodeHead` also chooses the 2-byte form. Without that check in the decoder, the theorem
would be *false*, and Lean would refuse the proof. That is the point: the proof would not
have gone through for a lax decoder.

Its companion, `decodeHead_encodeHead`, proves the round trip in the other direction. The
full validator `skipItem`, which handles maps, key ordering, UTF-8 and depth, is defined in
the same file. Lean's termination checker accepts it, so the decoder provably terminates on
every input.

== Case study: the security state machines

=== No signature without a touch, ever

`formal/Jotakey/Authenticator.lean` models `Authenticator::process` and `complete` as
pure functions on a `State` (pending command, counter, epoch, fault flag), driven by
`Event`s: requests and presence results. A *trace* is any list of events, in any order, of
any length. The theorems quantify over all of them:

#codepanel(title: "formal/Jotakey/Authenticator.lean")[
```lean
/-- Invariant 1. -/
theorem signature_needs_touch (s : State) (e : Event) (rp n : Nat)
    (h : (step s e).2 = .signature rp n) :
    e = .presence .confirmed ∧ s.faulted = false ∧
      (s.pending = .makeCredential rp ∨ ∃ cred, s.pending = .getAssertion rp cred)

theorem no_double_sign (s : State) (r r' : Up) (rp n : Nat) :
    (complete (complete s r).1 r').2 ≠ .signature rp n

/-- Invariant 2, over every possible trace. -/
theorem trace_counters_increasing (s : State) (es : List Event) :
    (sigCounters (trace s es).2).Pairwise (· < ·)
```
]

In words:

- A signature comes *only* from a confirmed presence event that completes a parked
  makeCredential or getAssertion for *that* relying party, on a healthy device.
- One touch completes at most one command. A second "confirmed" event right after
  produces nothing.
- In *any* interleaving of requests, touches, timeouts, cancellations and resets, the
  counters of emitted signatures form a strictly increasing sequence.

`reset_needs_window` proves invariant 6 over traces. If the epoch ever changes, the trace
contains a reset request that arrived within 10 seconds of power-up. `faulted_never_signs`
proves that the fault state of invariant 7 is absorbing.

=== Channel isolation and exact reassembly

`formal/Jotakey/CtapHid.lean` models the CTAPHID receive path. `run_isolated` proves that
any sequence of packets from other channels leaves the owning channel's transaction
exactly as it was. `step_wf` proves that buffers never exceed the announced length or the
1200-byte limit. `reassemble_fragment` proves that a message fragmented the way a host must
fragment it is delivered intact:

#codepanel(title: "formal/Jotakey/CtapHid.lean")[
```lean
theorem reassemble_fragment (cid cmd : Nat) (msg : List Nat)
    (hmax : msg.length ≤ maxMsg) :
    run .idle (fragment cid cmd msg) = .busy cid msg
```
]

While writing this proof, Lean pointed out that a hypothesis we had added,
`0 < msg.length`, was never used. The theorem also holds for empty messages. Proof
assistants often teach you something about your own design this way.

=== Credential binding, with the assumption on the table

#codepanel(title: "formal/Jotakey/Credential.lean")[
```lean
theorem unwrap_sound (key rp id nonce : List Nat)
    (h : unwrap mac key rp id = some nonce) :
    id = wrap mac key rp nonce ∧ nonce.length = nonceLen

theorem rp_binding
    (hcr : ∀ k r r' n, r ≠ r' → mac k r n ≠ mac k r' n)   -- the cryptographic assumption
    (key rp rp' nonce : List Nat) (hn : nonce.length = nonceLen) (hne : rp ≠ rp') :
    unwrap mac key rp' (wrap mac key rp nonce) = none
```
]

`unwrap_sound` needs no assumption at all: the construction accepts nothing but its own
outputs. `rp_binding` needs the MAC not to collide across relying parties, and says so in
its signature. That division is what a proof should give you: everything that can be
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

Lean definitions are executable. `formal/Main.lean` compiles the CBOR model into a
program, `jotakey-spec`. The Rust test `tests/differential.rs` sends it about 100 000
inputs: structured CBOR, random mutations of it, random bytes, and every possible head
byte. It requires the Rust decoder and the Lean model to agree on *every* one: accept or
reject, and how many bytes were consumed. They do. Any future change to the Rust decoder
that departs from the proved model fails this test. Differential testing does not prove
equivalence, but it ties the proofs to the code with a mechanical check rather than
review alone.

The fuzz targets play a similar role for the other models: their oracles are the theorem
statements ("counter moves only on a confirmed signature", "reassembly never exceeds the
announced length") checked on the real Rust code.

=== 3. Translating the Rust itself: Aeneas (planned experiment)

*Aeneas* (Ho & Protzenko, Inria/Microsoft) translates Rust into pure Lean functions,
using the *Charon* front end to extract the compiler's internal representation. Rust's
ownership discipline is what makes this possible: a program without aliasing of mutable
data can be expressed as a pure function that takes a value and returns the updated one.
With Aeneas, we would no longer *write* `step` in Lean. We would *generate* it from
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
  ([Cryptographic hardness], [ECDLP on P-256, SHA-256 collision resistance. Named explicitly (e.g. `rp_binding`'s hypothesis).]),
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
