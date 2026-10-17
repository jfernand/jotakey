-- (c) Javier Fernandez @ JotaSoft 2026
/-!
# The authenticator state machine

Formal model of `crates/jotakey-core/src/ctap/mod.rs` (`Authenticator::process`,
`Authenticator::complete`, `Pending`).

Parsing and cryptography are abstracted away. A request arrives already classified as a
`Command` (`Command.rejected` stands for every request the parser refuses). A signature is the
output `Output.signature relyingParty counter`. This is the level at which the user-presence
and counter invariants live. Relying parties and credentials are identified by plain numbers:
the model only needs to tell them apart.

Results (invariants 1, 2, 6, 7 of `AGENTS.md`):
* `processRequest_never_signs`: processing a request never produces a signature.
* `signature_requires_confirmed_touch`: a signature is produced only by a *confirmed* presence
  event completing a parked makeCredential/getAssertion.
* `one_touch_signs_at_most_once`: one touch completes at most one command.
* `trace_signature_counters_increase`: along *any* sequence of events, signature counters are
  strictly increasing and all above the starting counter.
* `epoch_change_requires_confirmed_touch` + `epoch_change_requires_reset_in_window`: the epoch
  changes only after a reset request inside the 10 s window, completed by a confirmed touch.
* `faulted_stays_faulted_and_never_signs`: once faulted, never a signature again.

Most proofs here have the same shape: split into every combination of state and input
(`cases … <;> …`), let `simp` compute what `processRequest`/`completePresence` return in each,
and observe that the claim holds in each case. The trace theorems then lift single-step facts
to whole event sequences by induction on the list of events.

Each theorem's doc comment says what it **proves** and **how**. *Syntax* comments
introduce notation not already explained in `Jotakey/Cbor/Heads.lean` and `CtapHid.lean`.
-/

namespace Jotakey.Authenticator

/-- `RESET_WINDOW_MS`: a reset is accepted only this many milliseconds after power-up. -/
def resetWindowMs : Nat := 10000

/-- Result of waiting for the user (`PresenceResult` in Rust). -/
inductive PresenceResult where
  | confirmed | timeout | cancelled
  deriving DecidableEq, Repr

/-- A request after parsing and validation. -/
inductive Command where
  | getInfo
  /-- makeCredential that passed validation for `relyingParty`. -/
  | makeCredential (relyingParty : Nat)
  /-- getAssertion whose allow list contained an authentic `credential` for `relyingParty`. -/
  | getAssertion (relyingParty credential : Nat)
  /-- makeCredential that hit the exclude list. -/
  | excluded
  /-- Zero-length pinAuth probe. -/
  | pinProbe
  | reset
  /-- Anything the parser or policy refuses (immediate error status). -/
  | rejected
  deriving DecidableEq, Repr

/-- The command parked while waiting for a touch (`Pending`). -/
inductive PendingCommand where
  | idle
  | makeCredential (relyingParty : Nat)
  | getAssertion (relyingParty credential : Nat)
  | excluded
  | pinProbe
  | reset
  deriving DecidableEq, Repr

/-- Authenticator state. `signCounter` is the persisted signature counter, `resetEpoch` the
reset generation. -/
structure State where
  -- Syntax: `structure` is a Rust `struct` with named fields, read as `s.signCounter`.
  pending : PendingCommand
  signCounter : Nat
  resetEpoch : Nat
  faulted : Bool
  deriving DecidableEq, Repr

/-- Observable outputs. -/
inductive Output where
  | info
  | needsPresence
  | error
  | signature (relyingParty counter : Nat)
  | resetDone
  deriving DecidableEq, Repr

/-- Inputs: a request (with the uptime at arrival) or the outcome of a presence wait. -/
inductive Event where
  | request (command : Command) (uptimeMs : Nat)
  | presence (result : PresenceResult)
  deriving DecidableEq, Repr

/-- `Authenticator::process`. A new request always clears whatever was parked. -/
def processRequest (state : State) (command : Command) (uptimeMs : Nat) : State × Output :=
  -- Syntax: `{ state with pending := .idle }` is a copy of `state` with one field changed,
  -- like Rust's `State { pending: Pending::Idle, ..state }`.
  if state.faulted then ({ state with pending := .idle }, .error)
  else
    match command with
    | .getInfo => ({ state with pending := .idle }, .info)
    | .rejected => ({ state with pending := .idle }, .error)
    | .makeCredential relyingParty =>
      ({ state with pending := .makeCredential relyingParty }, .needsPresence)
    | .getAssertion relyingParty credential =>
      ({ state with pending := .getAssertion relyingParty credential }, .needsPresence)
    | .excluded => ({ state with pending := .excluded }, .needsPresence)
    | .pinProbe => ({ state with pending := .pinProbe }, .needsPresence)
    | .reset =>
      if uptimeMs ≤ resetWindowMs then ({ state with pending := .reset }, .needsPresence)
      else ({ state with pending := .idle }, .error)

/-- `Authenticator::complete`. The parked command is consumed whatever the outcome. -/
def completePresence (state : State) (result : PresenceResult) : State × Output :=
  if state.faulted then ({ state with pending := .idle }, .error)
  else
    match state.pending, result with
    | .makeCredential relyingParty, .confirmed =>
      ({ state with pending := .idle, signCounter := state.signCounter + 1 },
        .signature relyingParty (state.signCounter + 1))
    | .getAssertion relyingParty _, .confirmed =>
      ({ state with pending := .idle, signCounter := state.signCounter + 1 },
        .signature relyingParty (state.signCounter + 1))
    | .reset, .confirmed =>
      ({ state with pending := .idle, resetEpoch := state.resetEpoch + 1 }, .resetDone)
    | _, _ => ({ state with pending := .idle }, .error)

/-- One event. -/
def handleEvent (state : State) : Event → State × Output
  | .request command uptimeMs => processRequest state command uptimeMs
  | .presence result => completePresence state result

/-- Run a sequence of events, collecting the outputs. -/
def runTrace : State → List Event → State × List Output
  | state, [] => (state, [])
  | state, event :: events =>
    -- Syntax: `let (a, b) := e` destructures a pair, as in Rust.
    let (afterEvent, output) := handleEvent state event
    let (finalState, outputs) := runTrace afterEvent events
    (finalState, output :: outputs)

/-- Counters of the signatures in an output list. -/
def signatureCounters : List Output → List Nat
  | [] => []
  | .signature _ counter :: outputs => counter :: signatureCounters outputs
  | _ :: outputs => signatureCounters outputs

/-! ## Single-step facts -/

/-- **Proves:** `processRequest` (a request arriving) never outputs a signature, whatever the
state, command or uptime. Signing is unreachable from the request path, as `AGENTS.md`
requires.

**How:** try every case: faulted or not (`cases hFaulted : state.faulted`) × every command
(`cases command`). In each, `simp` computes the output (`.error`, `.info` or
`.needsPresence`) and sees that it is a different constructor from `.signature`. The `reset`
case has one more `if` (the uptime window), which `try split` splits before the last
`simp`. -/
theorem processRequest_never_signs (state : State) (command : Command)
    (uptimeMs relyingParty counter : Nat) :
    (processRequest state command uptimeMs).2 ≠ .signature relyingParty counter := by
  -- Syntax: for a pair `p`, `p.1` is its first component and `p.2` its second (here the
  -- output). `try t` runs `t` and carries on even if `t` fails.
  unfold processRequest
  cases hFaulted : state.faulted <;> cases command <;> simp <;> (try split) <;> simp

/-- **Proves:** after `completePresence`, nothing is parked (`pending = .idle`), whatever the
outcome.

**How:** if faulted, `completePresence` sets `.idle`; otherwise `split` goes through its
`match` arms, each of which builds its state with `pending := .idle`. -/
theorem completePresence_clears_pending (state : State) (result : PresenceResult) :
    (completePresence state result).1.pending = .idle := by
  unfold completePresence
  cases hFaulted : state.faulted <;> simp
  split <;> rfl

/-- **Invariant 1.** A signature comes only from a confirmed presence event that completes a
parked makeCredential or getAssertion, on a healthy authenticator.

**Proves:** if an event outputs `.signature relyingParty counter`, then the event was a
*confirmed* touch, the authenticator was not faulted, and the parked command was a
makeCredential or getAssertion **for that same `relyingParty`**. A touch can't be
redirected to sign for a different site.

**How:** a request can't sign (`processRequest_never_signs`), which contradicts `hSigned`.
For a presence event: if faulted, the output is `.error`, again a contradiction. Otherwise
try every parked command × every presence result (`cases hPending : … <;> cases result`);
`simp_all` computes `completePresence` in each of the 18 cases. Only makeCredential/confirmed
and getAssertion/confirmed produce a signature, and there the signature's relying party is
the parked one; in all others `hSigned` is contradictory. -/
theorem signature_requires_confirmed_touch (state : State) (event : Event)
    (relyingParty counter : Nat)
    (hSigned : (handleEvent state event).2 = .signature relyingParty counter) :
    event = .presence .confirmed ∧ state.faulted = false ∧
      ((state.pending = .makeCredential relyingParty) ∨
        (∃ credential, state.pending = .getAssertion relyingParty credential)) := by
  -- Syntax: `∨` is "or"; `∃ x, P x` is "there is some `x` with `P x`".
  cases event with
  | request command uptimeMs =>
    exact absurd hSigned (processRequest_never_signs state command uptimeMs relyingParty counter)
    -- Syntax: `absurd h nh` proves anything from `h : P` and `nh : ¬P`.
  | presence result =>
    simp only [handleEvent, completePresence] at hSigned
    cases hFaulted : state.faulted <;>
      simp only [hFaulted, Bool.false_eq_true, ↓reduceIte] at hSigned
    · cases hPending : state.pending <;> cases result <;> simp_all
      -- Syntax: `simp_all` simplifies every hypothesis and the goal with each other until
      -- nothing changes: it solves the goal or exposes a contradiction among hypotheses.
    · simp at hSigned

/-- **One touch, one signature.** After any presence event nothing is parked, so a second
touch cannot produce another signature.

**Proves:** completing twice in a row (two presence events, no new request between them)
never yields a signature on the second completion.

**How:** by contradiction. Assume the second completion signs (`intro hSigned`). Then
`signature_requires_confirmed_touch` says a makeCredential or getAssertion was parked before
it. But `completePresence_clears_pending` says nothing was parked after the first completion.
`rcases` takes the two possibilities apart, and in each `cases` sees that `.idle` can't equal
a different constructor. -/
theorem one_touch_signs_at_most_once (state : State) (first second : PresenceResult)
    (relyingParty counter : Nat) :
    (completePresence (completePresence state first).1 second).2 ≠
      .signature relyingParty counter := by
  intro hSigned
  have hIdle := completePresence_clears_pending state first
  have := signature_requires_confirmed_touch (completePresence state first).1
    (.presence second) relyingParty counter hSigned
  rcases this.2.2 with hParked | ⟨_, hParked⟩ <;> rw [hIdle] at hParked <;> cases hParked
  -- Syntax: `rcases h with h1 | ⟨_, h1⟩` takes apart `h : A ∨ (∃ x, B x)`: one goal with
  -- `h1 : A`, one with `h1 : B x` (the `_` discards the name of `x`). `cases h1` on an
  -- equation between two different constructors closes the goal: it can't happen.

/-- **Proves:** a single event never decreases the persisted signature counter.

**How:** every case, as in `processRequest_never_signs`: each branch of `processRequest` /
`completePresence` either keeps `signCounter` or sets it to `signCounter + 1`. -/
theorem handleEvent_never_lowers_counter (state : State) (event : Event) :
    state.signCounter ≤ (handleEvent state event).1.signCounter := by
  cases event with
  | request command uptimeMs =>
    simp only [handleEvent, processRequest]
    cases hFaulted : state.faulted <;> cases command <;> simp <;> (try split) <;> simp
  | presence result =>
    simp only [handleEvent, completePresence]
    cases hFaulted : state.faulted <;> simp
    split <;> simp

/-- **Invariant 2 (single step).** A signature carries `old counter + 1`, which is also the
new persisted counter.

**Proves:** if an event outputs `.signature relyingParty counter` then
`counter = state.signCounter + 1` and the new state's `signCounter` is `counter`. In the Rust
code this is the write-ahead rule: `N + 1` is persisted before the signature carrying `N + 1`
is released.

**How:** the same case analysis as `signature_requires_confirmed_touch`; in the two signing
cases the output and the new state are read off the definition of `completePresence`. -/
theorem signature_carries_next_counter (state : State) (event : Event)
    (relyingParty counter : Nat)
    (hSigned : (handleEvent state event).2 = .signature relyingParty counter) :
    counter = state.signCounter + 1 ∧ (handleEvent state event).1.signCounter = counter := by
  cases event with
  | request command uptimeMs =>
    exact absurd hSigned (processRequest_never_signs state command uptimeMs relyingParty counter)
  | presence result =>
    simp only [handleEvent, completePresence] at hSigned ⊢
    -- Syntax: `at h ⊢` simplifies both `h` and the goal (`⊢` stands for the goal).
    cases hFaulted : state.faulted <;>
      simp only [hFaulted, Bool.false_eq_true, ↓reduceIte] at hSigned ⊢
    · cases hPending : state.pending <;> cases result <;> simp_all
    · simp at hSigned

/-! ## Traces -/

/-- **Proves:** along any sequence of events, the final counter is at least the starting one.

**How:** induction on the event list, for every starting state (`generalizing state`). One
event doesn't decrease it (`handleEvent_never_lowers_counter`), the rest of the trace doesn't
either (induction hypothesis), and `≤` chains (`Nat.le_trans`). -/
theorem runTrace_never_lowers_counter (state : State) (events : List Event) :
    state.signCounter ≤ (runTrace state events).1.signCounter := by
  induction events generalizing state with
  | nil => exact Nat.le_refl _
  | cons event events ih =>
    simp only [runTrace]
    exact Nat.le_trans (handleEvent_never_lowers_counter state event) (ih _)

/-- Every signature in a trace carries a counter above the starting counter and at most the
final one.

**Proves:** every `counter` carried by a signature in the trace satisfies
`starting counter < counter ≤ final counter`.

**How:** induction on the event list. This is a stronger statement than we finally want, and
that is deliberate: `trace_signature_counters_increase` needs to know where the *later*
counters lie, and this bound is what lets its induction go through (a common technique,
called *strengthening the induction hypothesis*). For a trace `event :: events`:
* if the first output is a signature with counter `first`, then
  `first = state.signCounter + 1`, which is above the start, and `first` is the counter
  after the event, so it is at most the final counter (`runTrace_never_lowers_counter`);
* every later signature lies above the counter after the first event (induction
  hypothesis), which is itself at least `state.signCounter`
  (`handleEvent_never_lowers_counter`). -/
theorem trace_signature_counters_bounded (state : State) (events : List Event) :
    ∀ counter ∈ signatureCounters (runTrace state events).2,
      state.signCounter < counter ∧ counter ≤ (runTrace state events).1.signCounter := by
  induction events generalizing state with
  | nil => simp [runTrace, signatureCounters]
  | cons event events ih =>
    intro counter hMember
    -- Syntax: the goal starts with `∀ counter ∈ …,`; `intro counter hMember` takes an
    -- arbitrary `counter` and the proof `hMember` of its membership, leaving the rest as the
    -- goal.
    simp only [runTrace] at hMember ⊢
    have hRestMono := runTrace_never_lowers_counter (handleEvent state event).1 events
    have hEventMono := handleEvent_never_lowers_counter state event
    cases hOutput : (handleEvent state event).2 with
    | signature relyingParty first =>
      rw [hOutput] at hMember
      simp only [signatureCounters, List.mem_cons] at hMember
      have hNext := signature_carries_next_counter state event relyingParty first hOutput
      rcases hMember with rfl | hLater
      · exact ⟨by omega, by omega⟩
      · have := ih (handleEvent state event).1 counter hLater; omega
    | _ =>
      -- Syntax: `| _ =>` handles every remaining constructor (all non-signature outputs) at once.
      rw [hOutput] at hMember
      simp only [signatureCounters] at hMember
      have := ih (handleEvent state event).1 counter hMember; omega

/-- **Invariant 2 (traces).** Along any sequence of requests, touches, timeouts, cancels and
resets, the counters of emitted signatures are strictly increasing. A relying party
therefore never sees a counter repeat or go backwards.

**Proves:** the list of signature counters in the outputs of any trace is
`Pairwise (· < ·)`: every counter is smaller than every counter emitted after it.

**How:** induction on the event list. A list is pairwise increasing when its head is below
every later element and its tail is pairwise increasing (`List.pairwise_cons`). The tail is
the induction hypothesis. If the first output is a signature with counter `first`, `first` is
the counter right after the first event (`signature_carries_next_counter`), and every later
signature counter is strictly above that (`trace_signature_counters_bounded`). If the first
output is not a signature, it adds nothing to the list and the induction hypothesis is the
whole answer. -/
theorem trace_signature_counters_increase (state : State) (events : List Event) :
    (signatureCounters (runTrace state events).2).Pairwise (· < ·) := by
  -- Syntax: `(· < ·)` is `fun a b => a < b`, each `·` standing for the next argument.
  induction events generalizing state with
  | nil => simp [runTrace, signatureCounters]
  | cons event events ih =>
    simp only [runTrace]
    have hRest := ih (handleEvent state event).1
    cases hOutput : (handleEvent state event).2 with
    | signature relyingParty first =>
      simp only [signatureCounters, List.pairwise_cons]
      refine ⟨fun counter hLater => ?_, hRest⟩
      -- The `?_` is a hole: the new goal is `first < counter` for any later `counter`.
      have hNext := signature_carries_next_counter state event relyingParty first hOutput
      have := trace_signature_counters_bounded (handleEvent state event).1 events counter hLater
      omega
    | _ => simpa [signatureCounters] using hRest

/-! ## Reset and faults -/

/-- **Proves:** if processing a request leaves a reset parked, the request was a reset that
arrived inside the 10 s window.

**How:** if faulted, `processRequest` parks nothing, so `hParked` is impossible. Otherwise
try every command: all but `reset` park something else (contradicting `hParked`), and for
`reset` the uptime `if` either parks it (the branch condition is the window bound we want) or
parks nothing (contradiction). -/
theorem parked_reset_was_requested_in_window (state : State) (command : Command) (uptimeMs : Nat)
    (hParked : (processRequest state command uptimeMs).1.pending = .reset) :
    command = .reset ∧ uptimeMs ≤ resetWindowMs := by
  unfold processRequest at hParked
  cases hFaulted : state.faulted <;>
    simp only [hFaulted, Bool.false_eq_true, ↓reduceIte] at hParked
  · cases command <;> simp at hParked
    · split at hParked
      · constructor; rfl; assumption
        -- Syntax: `constructor` splits a goal `A ∧ B` into goals `A` and `B`, solved here in
        -- order by `rfl` and `assumption`.
      · simp at hParked
  · simp at hParked

/-- **Invariant 6 (single step).** The epoch, and so every credential, changes only when a
confirmed touch completes a parked reset.

**Proves:** if an event changes the reset epoch, the event was a confirmed touch and a reset
was parked.

**How:** requests never touch `resetEpoch`: prove the epochs equal case by case
(`exfalso; apply hChanged` turns "the epochs differ, find the contradiction" into "show the
epochs are equal"). For a presence event, try every parked command × result; only
reset/confirmed changes `resetEpoch`. -/
theorem epoch_change_requires_confirmed_touch (state : State) (event : Event)
    (hChanged : (handleEvent state event).1.resetEpoch ≠ state.resetEpoch) :
    event = .presence .confirmed ∧ state.pending = .reset := by
  cases event with
  | request command uptimeMs =>
    exfalso; apply hChanged
    -- Syntax: `exfalso` replaces the goal with `False` (anything follows from a
    -- contradiction). `hChanged : a ≠ b` is a function from `a = b` to `False`, so
    -- `apply hChanged` leaves the goal `a = b`.
    simp only [handleEvent, processRequest]
    cases hFaulted : state.faulted <;> cases command <;> simp <;> (try split) <;> simp
  | presence result =>
    simp only [handleEvent, completePresence] at hChanged
    cases hFaulted : state.faulted <;>
      simp only [hFaulted, Bool.false_eq_true, ↓reduceIte] at hChanged
    · cases hPending : state.pending <;> cases result <;> simp_all
    · simp at hChanged

/-- **Invariant 6 (traces).** Starting from any state with no reset parked (in particular
from power-up), if the epoch ever changes then the trace contains a reset request that
arrived inside the 10 s window.

**Proves:** if a trace changes the reset epoch and no reset was parked at the start, some
event in the trace is `request .reset uptimeMs` with `uptimeMs ≤ 10000`. Together with
`epoch_change_requires_confirmed_touch`: a reset needs both the window and a touch.

**How:** induction on the event list, for every starting state. Look at the first event:
* if it changed the epoch, `epoch_change_requires_confirmed_touch` says a reset was parked at
  the start, contradicting `hNoParkedReset`;
* otherwise the change happens in the rest of the trace (`rw [← hSameEpoch] at hChanged`
  restates `hChanged` from the state after the event). To use the induction hypothesis
  there, we need "no reset parked" after the event:
  - a presence event leaves nothing parked (`completePresence_clears_pending`);
  - a request that parked a reset *is* the witness (`parked_reset_was_requested_in_window`
    gives the window bound), and it is the head of the list;
  - any other request leaves no reset parked, so the induction hypothesis finds the
    witness in the tail. -/
theorem epoch_change_requires_reset_in_window (state : State) (events : List Event)
    (hNoParkedReset : state.pending ≠ .reset)
    (hChanged : (runTrace state events).1.resetEpoch ≠ state.resetEpoch) :
    ∃ uptimeMs, uptimeMs ≤ resetWindowMs ∧ Event.request .reset uptimeMs ∈ events := by
  induction events generalizing state with
  | nil => simp [runTrace] at hChanged
  | cons event events ih =>
    simp only [runTrace] at hChanged
    by_cases hSameEpoch : (handleEvent state event).1.resetEpoch = state.resetEpoch
    · rw [← hSameEpoch] at hChanged
      cases event with
      | presence result =>
        have hIdle : (handleEvent state (.presence result)).1.pending ≠ .reset := by
          simp only [handleEvent, completePresence_clears_pending]; intro h; cases h
        obtain ⟨uptimeMs, hInWindow, hMember⟩ := ih _ hIdle hChanged
        -- Syntax: `obtain ⟨x, hx, hy⟩ := e` unpacks `e : ∃ x, A x ∧ B x` into the witness
        -- `x` and the two facts about it.
        exact ⟨uptimeMs, hInWindow, List.mem_cons_of_mem _ hMember⟩
        -- An `∃` is proved by giving the witness and the facts: `⟨x, hx, …⟩`.
      | request command uptimeMs =>
        by_cases hParked : (processRequest state command uptimeMs).1.pending = .reset
        · obtain ⟨rfl, hInWindow⟩ :=
            parked_reset_was_requested_in_window state command uptimeMs hParked
          exact ⟨uptimeMs, hInWindow, List.mem_cons_self⟩
        · obtain ⟨laterUptime, hInWindow, hMember⟩ := ih _ hParked hChanged
          exact ⟨laterUptime, hInWindow, List.mem_cons_of_mem _ hMember⟩
    · exact absurd (epoch_change_requires_confirmed_touch state event hSameEpoch).2 hNoParkedReset

/-- **Invariant 7.** A faulted authenticator stays faulted and never signs.

**Proves:** if `faulted` is set, then after any event it is still set and the output is not
a signature. Applied at each event in turn, it means a faulted device never signs again in
any trace; that induction is not written out as a separate theorem.

**How:** with `hFaulted`, both `processRequest` and `completePresence` take their first
branch, which keeps `faulted` and outputs `.error`; `simp` computes this directly. -/
theorem faulted_stays_faulted_and_never_signs (state : State) (event : Event)
    (hFaulted : state.faulted = true) :
    (handleEvent state event).1.faulted = true ∧
      ∀ relyingParty counter,
        (handleEvent state event).2 ≠ .signature relyingParty counter := by
  cases event with
  | request command uptimeMs => simp [handleEvent, processRequest, hFaulted]
  | presence result => simp [handleEvent, completePresence, hFaulted]

end Jotakey.Authenticator
