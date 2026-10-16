/-!
# The authenticator state machine

Formal model of `crates/jotakey-core/src/ctap/mod.rs` (`Authenticator::process`,
`Authenticator::complete`, `Pending`).

Parsing and cryptography are abstracted away. A request arrives already classified as a
`Cmd` (`Cmd.rejected` stands for every request the parser refuses). A signature is the
output `Out.signature rp counter`. This is the level at which the user-presence and counter
invariants live.

Results (invariants 1, 2, 6, 7 of `AGENTS.md`):
* `request_never_signs`: processing a request never produces a signature.
* `signature_needs_touch`: a signature is produced only by a *confirmed* presence event
  completing a parked makeCredential/getAssertion.
* `no_double_sign`: one touch completes at most one command.
* `trace_counters_increasing`: along *any* sequence of events, signature counters are
  strictly increasing and all above the starting counter.
* `reset_needs_window_and_touch`: the epoch changes only after a reset request inside the
  10 s window, completed by a confirmed touch (`reset_needs_touch` + `reset_needs_window`).
* `faulted_never_signs`: once faulted, never a signature again.

Most proofs here have the same shape: split into every combination of state and input
(`cases … <;> …`), let `simp` compute what `process`/`complete` return in each, and observe
that the claim holds in each case. The trace theorems then lift single-step facts to whole
event sequences by induction on the list of events.

Each theorem's doc comment says what it **proves** and **how**. *Syntax* comments
introduce notation not already explained in `Jotakey/Cbor/Heads.lean` and `CtapHid.lean`.
-/

namespace Jotakey.Authenticator

/-- `RESET_WINDOW_MS`. -/
def resetWindow : Nat := 10000

/-- Result of waiting for the user (`UpResult`). -/
inductive Up where
  | confirmed | timeout | cancelled
  deriving DecidableEq, Repr

/-- A request after parsing and validation. -/
inductive Cmd where
  | getInfo
  /-- makeCredential that passed validation for relying party `rp`. -/
  | makeCredential (rp : Nat)
  /-- getAssertion whose allow list contained an authentic credential `cred` for `rp`. -/
  | getAssertion (rp cred : Nat)
  /-- makeCredential that hit the exclude list. -/
  | excluded
  /-- Zero-length pinAuth probe. -/
  | pinProbe
  | reset
  /-- Anything the parser or policy refuses (immediate error status). -/
  | rejected
  deriving DecidableEq, Repr

/-- Parked command (`Pending`). -/
inductive Pending where
  | idle
  | makeCredential (rp : Nat)
  | getAssertion (rp cred : Nat)
  | excluded
  | pinProbe
  | reset
  deriving DecidableEq, Repr

/-- Authenticator state. `counter` is the persisted signature counter, `epoch` the reset
generation. -/
structure State where
  -- Syntax: `structure` is a Rust `struct` with named fields, read as `s.counter`.
  pending : Pending
  counter : Nat
  epoch : Nat
  faulted : Bool
  deriving DecidableEq, Repr

/-- Observable outputs. -/
inductive Out where
  | info
  | needsPresence
  | error
  | signature (rp counter : Nat)
  | resetDone
  deriving DecidableEq, Repr

/-- Inputs: a request (with the uptime at arrival) or the outcome of a presence wait. -/
inductive Event where
  | request (c : Cmd) (uptime : Nat)
  | presence (r : Up)
  deriving DecidableEq, Repr

/-- `Authenticator::process`. A new request always clears whatever was parked. -/
def process (s : State) (c : Cmd) (uptime : Nat) : State × Out :=
  -- Syntax: `{ s with pending := .idle }` is a copy of `s` with one field changed, like
  -- Rust's `State { pending: Pending::Idle, ..s }`.
  if s.faulted then ({ s with pending := .idle }, .error)
  else
    match c with
    | .getInfo => ({ s with pending := .idle }, .info)
    | .rejected => ({ s with pending := .idle }, .error)
    | .makeCredential rp => ({ s with pending := .makeCredential rp }, .needsPresence)
    | .getAssertion rp cred => ({ s with pending := .getAssertion rp cred }, .needsPresence)
    | .excluded => ({ s with pending := .excluded }, .needsPresence)
    | .pinProbe => ({ s with pending := .pinProbe }, .needsPresence)
    | .reset =>
      if uptime ≤ resetWindow then ({ s with pending := .reset }, .needsPresence)
      else ({ s with pending := .idle }, .error)

/-- `Authenticator::complete`. The parked command is consumed whatever the outcome. -/
def complete (s : State) (r : Up) : State × Out :=
  if s.faulted then ({ s with pending := .idle }, .error)
  else
    match s.pending, r with
    | .makeCredential rp, .confirmed =>
      ({ s with pending := .idle, counter := s.counter + 1 }, .signature rp (s.counter + 1))
    | .getAssertion rp _, .confirmed =>
      ({ s with pending := .idle, counter := s.counter + 1 }, .signature rp (s.counter + 1))
    | .reset, .confirmed => ({ s with pending := .idle, epoch := s.epoch + 1 }, .resetDone)
    | _, _ => ({ s with pending := .idle }, .error)

/-- One event. -/
def step (s : State) : Event → State × Out
  | .request c u => process s c u
  | .presence r => complete s r

/-- Run a trace, collecting outputs. -/
def trace : State → List Event → State × List Out
  | s, [] => (s, [])
  | s, e :: es =>
    -- Syntax: `let (a, b) := e` destructures a pair, as in Rust.
    let (s₁, o) := step s e
    let (s₂, os) := trace s₁ es
    (s₂, o :: os)

/-- Counters of the signatures in an output list. -/
def sigCounters : List Out → List Nat
  | [] => []
  | .signature _ n :: os => n :: sigCounters os
  | _ :: os => sigCounters os

/-! ## Single-step facts -/

/-- **Proves:** `process` (a request arriving) never outputs a signature, whatever the state,
command or uptime. Signing is unreachable from the request path, as `AGENTS.md` requires.

**How:** try every case: faulted or not (`cases hf : s.faulted`) × every command
(`cases c`). In each, `simp` computes the output (`.error`, `.info` or `.needsPresence`)
and sees that it is a different constructor from `.signature`. The `reset` case has one
more `if` (the uptime window), which `try split` splits before the last `simp`. -/
theorem request_never_signs (s : State) (c : Cmd) (u rp n : Nat) :
    (process s c u).2 ≠ .signature rp n := by
  -- Syntax: for a pair `p`, `p.1` is its first component and `p.2` its second (here the
  -- output). `try t` runs `t` and carries on even if `t` fails.
  unfold process
  cases hf : s.faulted <;> cases c <;> simp <;> (try split) <;> simp

/-- **Proves:** after `complete`, nothing is parked (`pending = .idle`), whatever the outcome.

**How:** if faulted, `complete` sets `.idle`; otherwise `split` goes through the `match`
arms of `complete`, each of which builds its state with `pending := .idle`. -/
theorem complete_pending_idle (s : State) (r : Up) : (complete s r).1.pending = .idle := by
  unfold complete
  cases hf : s.faulted <;> simp
  split <;> rfl

/-- **Invariant 1.** A signature comes only from a confirmed presence event that completes a
parked makeCredential or getAssertion, on a healthy authenticator.

**Proves:** if a step outputs `.signature rp n`, then the event was a *confirmed* touch, the
authenticator was not faulted, and the parked command was a makeCredential or getAssertion
**for that same `rp`**. A touch can't be redirected to sign for a different site.

**How:** a request can't sign (`request_never_signs`), which contradicts `h`. For a presence
event: if faulted, the output is `.error`, again contradicting `h`. Otherwise try every
parked command × every presence outcome (`cases hp : s.pending <;> cases r`); `simp_all`
computes `complete` in each of the 18 cases. Only makeCredential/confirmed and
getAssertion/confirmed produce a signature, and there the signature's `rp` is the parked
one; in all others `h` is contradictory. -/
theorem signature_needs_touch (s : State) (e : Event) (rp n : Nat)
    (h : (step s e).2 = .signature rp n) :
    e = .presence .confirmed ∧ s.faulted = false ∧
      ((s.pending = .makeCredential rp) ∨ (∃ cred, s.pending = .getAssertion rp cred)) := by
  -- Syntax: `∨` is "or"; `∃ cred, P cred` is "there is some `cred` with `P cred`".
  cases e with
  | request c u => exact absurd h (request_never_signs s c u rp n)
    -- Syntax: `absurd h nh` proves anything from `h : P` and `nh : ¬P`.
  | presence r =>
    simp only [step, complete] at h
    cases hf : s.faulted <;> simp only [hf, Bool.false_eq_true, ↓reduceIte] at h
    · cases hp : s.pending <;> cases r <;> simp_all
      -- Syntax: `simp_all` simplifies every hypothesis and the goal with each other until
      -- nothing changes: it solves the goal or exposes a contradiction among hypotheses.
    · simp at h

/-- **One touch, one signature.** After any presence event nothing is parked, so a second
touch cannot produce another signature.

**Proves:** completing twice in a row (two presence events, no new request between them)
never yields a signature on the second completion.

**How:** by contradiction. Assume the second completion signs (`intro h`). Then
`signature_needs_touch` says a makeCredential or getAssertion was parked before it. But
`complete_pending_idle` says nothing was parked after the first completion. `rcases`
takes the two possibilities apart, and in each `cases h1` sees that `.idle` can't equal a
different constructor. -/
theorem no_double_sign (s : State) (r r' : Up) (rp n : Nat) :
    (complete (complete s r).1 r').2 ≠ .signature rp n := by
  intro h
  have hidle := complete_pending_idle s r
  have := signature_needs_touch (complete s r).1 (.presence r') rp n h
  rcases this.2.2 with h1 | ⟨_, h1⟩ <;> rw [hidle] at h1 <;> cases h1
  -- Syntax: `rcases h with h1 | ⟨_, h1⟩` takes apart `h : A ∨ (∃ x, B x)`: one goal with
  -- `h1 : A`, one with `h1 : B x` (the `_` discards the name of `x`). `cases h1` on an
  -- equation between two different constructors closes the goal: it can't happen.

/-- **Proves:** a single step never decreases the persisted counter.

**How:** every case, as in `request_never_signs`: each branch of `process`/`complete` either
keeps `counter` or sets it to `counter + 1`. -/
theorem step_counter_mono (s : State) (e : Event) : s.counter ≤ (step s e).1.counter := by
  cases e with
  | request c u =>
    simp only [step, process]
    cases hf : s.faulted <;> cases c <;> simp <;> (try split) <;> simp
  | presence r =>
    simp only [step, complete]
    cases hf : s.faulted <;> simp
    split <;> simp

/-- **Invariant 2 (single step).** A signature carries `old counter + 1`, which is also the
new persisted counter.

**Proves:** if a step outputs `.signature rp n` then `n = s.counter + 1` and the new state's
counter is `n`. In the Rust code this is the write-ahead rule: `N + 1` is persisted before
the signature carrying `N + 1` is released.

**How:** the same case analysis as `signature_needs_touch`; in the two signing cases the
output and the new state are read off the definition of `complete`. -/
theorem signature_counter (s : State) (e : Event) (rp n : Nat)
    (h : (step s e).2 = .signature rp n) :
    n = s.counter + 1 ∧ (step s e).1.counter = n := by
  cases e with
  | request c u => exact absurd h (request_never_signs s c u rp n)
  | presence r =>
    simp only [step, complete] at h ⊢
    -- Syntax: `at h ⊢` simplifies both `h` and the goal (`⊢` stands for the goal).
    cases hf : s.faulted <;> simp only [hf, Bool.false_eq_true, ↓reduceIte] at h ⊢
    · cases hp : s.pending <;> cases r <;> simp_all
    · simp at h

/-! ## Traces -/

/-- **Proves:** along any sequence of events, the final counter is at least the starting one.

**How:** induction on the event list, for every starting state (`generalizing s`). One step
doesn't decrease it (`step_counter_mono`), the rest of the trace doesn't either (induction
hypothesis), and `≤` chains (`Nat.le_trans`). -/
theorem trace_counter_mono (s : State) (es : List Event) : s.counter ≤ (trace s es).1.counter := by
  induction es generalizing s with
  | nil => exact Nat.le_refl _
  | cons e es ih =>
    simp only [trace]
    exact Nat.le_trans (step_counter_mono s e) (ih _)

/-- Every signature in a trace carries a counter above the starting counter and at most the
final one.

**Proves:** for every counter `n` among a trace's signatures,
`start counter < n ≤ final counter`.

**How:** induction on the event list. This is a stronger statement than we finally want, and
that is deliberate: `trace_counters_increasing` needs to know where the *later* counters lie,
and this bound is what lets its induction go through (a common technique, called
*strengthening the induction hypothesis*). For a trace `e :: es`:
* if the first output is a signature with counter `m`, then `m = s.counter + 1`, which is
  above the start, and `m` is the counter after the step, so it is at most the final counter
  (`trace_counter_mono`);
* every later signature lies above the counter after the first step (induction hypothesis),
  which is itself at least `s.counter` (`step_counter_mono`). -/
theorem trace_counters_bounded (s : State) (es : List Event) :
    ∀ n ∈ sigCounters (trace s es).2, s.counter < n ∧ n ≤ (trace s es).1.counter := by
  induction es generalizing s with
  | nil => simp [trace, sigCounters]
  | cons e es ih =>
    intro n hn
    -- Syntax: the goal starts with `∀ n ∈ …,`; `intro n hn` takes an arbitrary `n` and the
    -- proof `hn` of its membership, leaving the rest as the goal.
    simp only [trace] at hn ⊢
    have hmono := trace_counter_mono (step s e).1 es
    have hstep := step_counter_mono s e
    cases ho : (step s e).2 with
    | signature rp m =>
      rw [ho] at hn
      simp only [sigCounters, List.mem_cons] at hn
      have hc := signature_counter s e rp m ho
      rcases hn with rfl | hn
      · exact ⟨by omega, by omega⟩
      · have := ih (step s e).1 n hn; omega
    | _ =>
      -- Syntax: `| _ =>` handles every remaining constructor (all non-signature outputs) at once.
      rw [ho] at hn
      simp only [sigCounters] at hn
      have := ih (step s e).1 n hn; omega

/-- **Invariant 2 (traces).** Along any sequence of requests, touches, timeouts, cancels and
resets, the counters of emitted signatures are strictly increasing. A relying party
therefore never sees a counter repeat or go backwards.

**Proves:** the list of signature counters in the outputs of any trace is `Pairwise (· < ·)`:
every counter is smaller than every counter emitted after it.

**How:** induction on the event list. A list is pairwise increasing when its head is below
every later element and its tail is pairwise increasing (`List.pairwise_cons`). The tail is
the induction hypothesis. If the first output is a signature with counter `m`, `m` is the
counter right after the first step (`signature_counter`), and every later signature counter
is strictly above that (`trace_counters_bounded`). If the first output is not a signature,
it adds nothing to the list and the induction hypothesis is the whole answer. -/
theorem trace_counters_increasing (s : State) (es : List Event) :
    (sigCounters (trace s es).2).Pairwise (· < ·) := by
  -- Syntax: `(· < ·)` is `fun a b => a < b`, each `·` standing for the next argument.
  induction es generalizing s with
  | nil => simp [trace, sigCounters]
  | cons e es ih =>
    simp only [trace]
    have hrest := ih (step s e).1
    cases ho : (step s e).2 with
    | signature rp m =>
      simp only [sigCounters, List.pairwise_cons]
      refine ⟨fun n hn => ?_, hrest⟩
      -- The `?_` is a hole: the new goal is `m < n` for a later counter `n`.
      have hc := signature_counter s e rp m ho
      have := trace_counters_bounded (step s e).1 es n hn
      omega
    | _ => simpa [sigCounters] using hrest

/-! ## Reset and faults -/

/-- **Proves:** if processing a request leaves a reset parked, the request was a reset that
arrived inside the 10 s window.

**How:** if faulted, `process` parks nothing, so `h` is impossible. Otherwise try every
command: all but `reset` park something else (contradicting `h`), and for `reset` the
uptime `if` either parks it (the branch condition is the window bound we want) or parks
nothing (contradiction). -/
theorem process_pending_reset (s : State) (c : Cmd) (u : Nat)
    (h : (process s c u).1.pending = .reset) : c = .reset ∧ u ≤ resetWindow := by
  unfold process at h
  cases hf : s.faulted <;> simp only [hf, Bool.false_eq_true, ↓reduceIte] at h
  · cases c <;> simp at h
    · split at h
      · constructor; rfl; assumption
        -- Syntax: `constructor` splits a goal `A ∧ B` into goals `A` and `B`, solved here in
        -- order by `rfl` and `assumption`.
      · simp at h
  · simp at h

/-- **Invariant 6 (single step).** The epoch, and so every credential, changes only when a
confirmed touch completes a parked reset.

**Proves:** if a step changes the epoch, the event was a confirmed touch and a reset was
parked.

**How:** requests never touch `epoch`: prove the epochs equal case by case (`exfalso; apply h`
turns "the epochs differ, find the contradiction" into "show the epochs are equal"). For a
presence event, try every parked command × outcome; only reset/confirmed changes `epoch`. -/
theorem reset_needs_touch (s : State) (e : Event) (h : (step s e).1.epoch ≠ s.epoch) :
    e = .presence .confirmed ∧ s.pending = .reset := by
  cases e with
  | request c u =>
    exfalso; apply h
    -- Syntax: `exfalso` replaces the goal with `False` (anything follows from a
    -- contradiction). `h : a ≠ b` is a function from `a = b` to `False`, so `apply h` leaves
    -- the goal `a = b`.
    simp only [step, process]
    cases hf : s.faulted <;> cases c <;> simp <;> (try split) <;> simp
  | presence r =>
    simp only [step, complete] at h
    cases hf : s.faulted <;> simp only [hf, Bool.false_eq_true, ↓reduceIte] at h
    · cases hp : s.pending <;> cases r <;> simp_all
    · simp at h

/-- **Invariant 6 (traces).** Starting from any state with no reset parked (in particular
from power-up), if the epoch ever changes then the trace contains a reset request that
arrived inside the 10 s window.

**Proves:** if a trace changes the epoch and no reset was parked at the start, some event in
the trace is `request .reset u` with `u ≤ 10000` ms. Together with `reset_needs_touch`: a
reset needs both the window and a touch.

**How:** induction on the event list, for every starting state. Look at the first event `e`:
* if it changed the epoch, `reset_needs_touch` says a reset was parked at the start,
  contradicting `hs`;
* otherwise the change happens in the rest of the trace (`rw [← he] at h` restates `h` from
  the state after `e`). To use the induction hypothesis there, we need "no reset parked"
  after `e`:
  - a presence event leaves nothing parked (`complete_pending_idle`);
  - a request that parked a reset *is* the witness (`process_pending_reset` gives the
    window bound), and it is the head of the list;
  - any other request leaves no reset parked, so the induction hypothesis finds the
    witness in the tail. -/
theorem reset_needs_window (s : State) (es : List Event) (hs : s.pending ≠ .reset)
    (h : (trace s es).1.epoch ≠ s.epoch) :
    ∃ u, u ≤ resetWindow ∧ Event.request .reset u ∈ es := by
  induction es generalizing s with
  | nil => simp [trace] at h
  | cons e es ih =>
    simp only [trace] at h
    by_cases he : (step s e).1.epoch = s.epoch
    · rw [← he] at h
      cases e with
      | presence r =>
        have hidle : (step s (.presence r)).1.pending ≠ .reset := by
          simp only [step, complete_pending_idle]; intro h'; cases h'
        obtain ⟨u, hu, hmem⟩ := ih _ hidle h
        -- Syntax: `obtain ⟨u, hu, hmem⟩ := e` unpacks `e : ∃ u, A u ∧ B u` into the witness
        -- `u` and the two facts about it.
        exact ⟨u, hu, List.mem_cons_of_mem _ hmem⟩
        -- An `∃` is proved by giving the witness and the facts: `⟨u, hu, …⟩`.
      | request c u =>
        by_cases hp : (process s c u).1.pending = .reset
        · obtain ⟨rfl, hu⟩ := process_pending_reset s c u hp
          exact ⟨u, hu, List.mem_cons_self⟩
        · obtain ⟨u', hu', hmem⟩ := ih _ hp h
          exact ⟨u', hu', List.mem_cons_of_mem _ hmem⟩
    · exact absurd (reset_needs_touch s e he).2 hs

/-- **Invariant 7.** A faulted authenticator stays faulted and never signs.

**Proves:** if `faulted` is set, then after any event it is still set and the output is not
a signature. Applied at each event in turn, it means a faulted device never signs again in
any trace; that induction is not written out as a separate theorem.

**How:** with `hf`, both `process` and `complete` take their first branch, which keeps
`faulted` and outputs `.error`; `simp` computes this directly. -/
theorem faulted_never_signs (s : State) (e : Event) (hf : s.faulted = true) :
    (step s e).1.faulted = true ∧ ∀ rp n, (step s e).2 ≠ .signature rp n := by
  cases e with
  | request c u => simp [step, process, hf]
  | presence r => simp [step, complete, hf]

end Jotakey.Authenticator
