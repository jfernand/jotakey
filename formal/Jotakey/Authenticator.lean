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
  10 s window, completed by a confirmed touch.
* `faulted_never_signs`: once faulted, never a signature again.
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
    let (s₁, o) := step s e
    let (s₂, os) := trace s₁ es
    (s₂, o :: os)

/-- Counters of the signatures in an output list. -/
def sigCounters : List Out → List Nat
  | [] => []
  | .signature _ n :: os => n :: sigCounters os
  | _ :: os => sigCounters os

/-! ## Single-step facts -/

theorem request_never_signs (s : State) (c : Cmd) (u rp n : Nat) :
    (process s c u).2 ≠ .signature rp n := by
  unfold process
  cases hf : s.faulted <;> cases c <;> simp <;> (try split) <;> simp

theorem complete_pending_idle (s : State) (r : Up) : (complete s r).1.pending = .idle := by
  unfold complete
  cases hf : s.faulted <;> simp
  split <;> rfl

/-- **Invariant 1.** A signature comes only from a confirmed presence event that completes a
parked makeCredential or getAssertion, on a healthy authenticator. -/
theorem signature_needs_touch (s : State) (e : Event) (rp n : Nat)
    (h : (step s e).2 = .signature rp n) :
    e = .presence .confirmed ∧ s.faulted = false ∧
      ((s.pending = .makeCredential rp) ∨ (∃ cred, s.pending = .getAssertion rp cred)) := by
  cases e with
  | request c u => exact absurd h (request_never_signs s c u rp n)
  | presence r =>
    simp only [step, complete] at h
    cases hf : s.faulted <;> simp only [hf, Bool.false_eq_true, ↓reduceIte] at h
    · cases hp : s.pending <;> cases r <;> simp_all
    · simp at h

/-- **One touch, one signature.** After any presence event nothing is parked, so a second
touch cannot produce another signature. -/
theorem no_double_sign (s : State) (r r' : Up) (rp n : Nat) :
    (complete (complete s r).1 r').2 ≠ .signature rp n := by
  intro h
  have hidle := complete_pending_idle s r
  have := signature_needs_touch (complete s r).1 (.presence r') rp n h
  rcases this.2.2 with h1 | ⟨_, h1⟩ <;> rw [hidle] at h1 <;> cases h1

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
new persisted counter. -/
theorem signature_counter (s : State) (e : Event) (rp n : Nat)
    (h : (step s e).2 = .signature rp n) :
    n = s.counter + 1 ∧ (step s e).1.counter = n := by
  cases e with
  | request c u => exact absurd h (request_never_signs s c u rp n)
  | presence r =>
    simp only [step, complete] at h ⊢
    cases hf : s.faulted <;> simp only [hf, Bool.false_eq_true, ↓reduceIte] at h ⊢
    · cases hp : s.pending <;> cases r <;> simp_all
    · simp at h

/-! ## Traces -/

theorem trace_counter_mono (s : State) (es : List Event) : s.counter ≤ (trace s es).1.counter := by
  induction es generalizing s with
  | nil => exact Nat.le_refl _
  | cons e es ih =>
    simp only [trace]
    exact Nat.le_trans (step_counter_mono s e) (ih _)

/-- Every signature in a trace carries a counter above the starting counter and at most the
final one. -/
theorem trace_counters_bounded (s : State) (es : List Event) :
    ∀ n ∈ sigCounters (trace s es).2, s.counter < n ∧ n ≤ (trace s es).1.counter := by
  induction es generalizing s with
  | nil => simp [trace, sigCounters]
  | cons e es ih =>
    intro n hn
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
      rw [ho] at hn
      simp only [sigCounters] at hn
      have := ih (step s e).1 n hn; omega

/-- **Invariant 2 (traces).** Along any sequence of requests, touches, timeouts, cancels and
resets, the counters of emitted signatures are strictly increasing. A relying party
therefore never sees a counter repeat or go backwards. -/
theorem trace_counters_increasing (s : State) (es : List Event) :
    (sigCounters (trace s es).2).Pairwise (· < ·) := by
  induction es generalizing s with
  | nil => simp [trace, sigCounters]
  | cons e es ih =>
    simp only [trace]
    have hrest := ih (step s e).1
    cases ho : (step s e).2 with
    | signature rp m =>
      simp only [sigCounters, List.pairwise_cons]
      refine ⟨fun n hn => ?_, hrest⟩
      have hc := signature_counter s e rp m ho
      have := trace_counters_bounded (step s e).1 es n hn
      omega
    | _ => simpa [sigCounters] using hrest

/-! ## Reset and faults -/

theorem process_pending_reset (s : State) (c : Cmd) (u : Nat)
    (h : (process s c u).1.pending = .reset) : c = .reset ∧ u ≤ resetWindow := by
  unfold process at h
  cases hf : s.faulted <;> simp only [hf, Bool.false_eq_true, ↓reduceIte] at h
  · cases c <;> simp at h
    · split at h
      · constructor; rfl; assumption
      · simp at h
  · simp at h

/-- **Invariant 6 (single step).** The epoch, and so every credential, changes only when a
confirmed touch completes a parked reset. -/
theorem reset_needs_touch (s : State) (e : Event) (h : (step s e).1.epoch ≠ s.epoch) :
    e = .presence .confirmed ∧ s.pending = .reset := by
  cases e with
  | request c u =>
    exfalso; apply h
    simp only [step, process]
    cases hf : s.faulted <;> cases c <;> simp <;> (try split) <;> simp
  | presence r =>
    simp only [step, complete] at h
    cases hf : s.faulted <;> simp only [hf, Bool.false_eq_true, ↓reduceIte] at h
    · cases hp : s.pending <;> cases r <;> simp_all
    · simp at h

/-- **Invariant 6 (traces).** Starting from any state with no reset parked (in particular
from power-up), if the epoch ever changes then the trace contains a reset request that
arrived inside the 10 s window. -/
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
        exact ⟨u, hu, List.mem_cons_of_mem _ hmem⟩
      | request c u =>
        by_cases hp : (process s c u).1.pending = .reset
        · obtain ⟨rfl, hu⟩ := process_pending_reset s c u hp
          exact ⟨u, hu, List.mem_cons_self⟩
        · obtain ⟨u', hu', hmem⟩ := ih _ hp h
          exact ⟨u', hu', List.mem_cons_of_mem _ hmem⟩
    · exact absurd (reset_needs_touch s e he).2 hs

/-- **Invariant 7.** A faulted authenticator stays faulted and never signs. -/
theorem faulted_never_signs (s : State) (e : Event) (hf : s.faulted = true) :
    (step s e).1.faulted = true ∧ ∀ rp n, (step s e).2 ≠ .signature rp n := by
  cases e with
  | request c u => simp [step, process, hf]
  | presence r => simp [step, complete, hf]

end Jotakey.Authenticator
