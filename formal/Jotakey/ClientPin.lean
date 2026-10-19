-- (c) Javier Fernandez @ JotaSoft 2026
/-!
# PIN lockout

Formal model of the retry rules in `crates/jotakey-core/src/ctap/client_pin.rs`
(`check_pin`, `usable_pin`, `PinSession`, `set_pin`, `change_pin`) and of the PIN half of
`reset::complete`.

The cryptography is abstracted away: a PIN is a number, and an *attempt* is a request whose
PIN reached the comparison, already authenticated and decrypted (getPinUvAuthToken… or
changePIN). The persistent state is the PIN and the retry counter; the mismatch count lives
in RAM and is lost at every power cycle.

Results (invariant 10 of `AGENTS.md`):
* `wrong_pins_between_successes_le_eight`: along any trace, at most 8 wrong PINs are compared
  between one correct entry (or setting the PIN, or a reset) and the next, power cycles and
  interrupted attempts included.
* `wrong_pins_in_a_row_le_three`: at most 3 wrong PINs are compared in a row without a power
  cycle or a correct PIN in between.
* `blocked_until_reset`: once the counter reaches 0, no PIN is accepted until a reset.
* `comparison_needs_a_counted_retry`: a PIN is compared only when a retry was left and it was
  counted: a wrong one leaves the counter one lower.

`.interruptedAttempt` is power failing after the attempt was counted and before anything
else happened. Because the Rust code stores the counter *before* it compares, no event
exists where a comparison happens and its cost does not: that is the property the
`retries_at_pin_check` oracle checks on the Rust side.
-/

namespace Jotakey.ClientPin

/-- `PIN_RETRIES_MAX`. -/
def maxRetries : Nat := 8

/-- `MISMATCHES_PER_POWER_CYCLE`. -/
def mismatchesPerPowerCycle : Nat := 3

/-- The PIN state: `pin` and `retries` are persisted (`PinRecord`); `mismatches` is RAM
(`PinSession::mismatches`). -/
structure State where
  pin : Option Nat
  retries : Nat
  mismatches : Nat
  deriving DecidableEq, Repr

/-- Inputs. -/
inductive Event where
  /-- getPinUvAuthToken… with this PIN. -/
  | attempt (guess : Nat)
  /-- changePIN from `guess` to `newPin`. -/
  | changePin (guess newPin : Nat)
  /-- An attempt during which the power fails right after it is counted. -/
  | interruptedAttempt
  | powerCycle
  | setPin (pin : Nat)
  | reset
  deriving DecidableEq, Repr

/-- Outputs. `wrongPin` is every compared-and-rejected PIN, whatever the status code
(`PIN_INVALID`, or `PIN_AUTH_BLOCKED`/`PIN_BLOCKED` when it was the last allowed). -/
inductive Output where
  | accepted | wrongPin | blocked | authBlocked | notSet | notAllowed
  | pinSet | resetDone | poweredUp | interrupted
  deriving DecidableEq, Repr

/-- `usable_pin` then `check_pin`: refuse if no PIN, blocked, or blocked for this power
cycle; otherwise count the attempt, then compare. -/
def attempt (state : State) (guess : Nat) : State × Output :=
  match state.pin with
  | none => (state, .notSet)
  | some pin =>
    if state.retries = 0 then (state, .blocked)
    else if mismatchesPerPowerCycle ≤ state.mismatches then (state, .authBlocked)
    else
      -- Syntax: `let x := e` names a value, as in Rust.
      let counted := { state with retries := state.retries - 1 }
      if guess = pin then ({ counted with retries := maxRetries, mismatches := 0 }, .accepted)
      else ({ counted with mismatches := state.mismatches + 1 }, .wrongPin)

/-- One event. -/
def handleEvent (state : State) : Event → State × Output
  | .attempt guess => attempt state guess
  | .changePin guess newPin =>
    match attempt state guess with
    | (after, .accepted) => ({ after with pin := some newPin }, .accepted)
    | other => other
  | .interruptedAttempt =>
    match state.pin with
    | none => (state, .notSet)
    | some _ =>
      if state.retries = 0 then (state, .blocked)
      else if mismatchesPerPowerCycle ≤ state.mismatches then (state, .authBlocked)
      else ({ state with retries := state.retries - 1, mismatches := 0 }, .interrupted)
  | .powerCycle => ({ state with mismatches := 0 }, .poweredUp)
  | .setPin pin =>
    match state.pin with
    | none => ({ state with pin := some pin, retries := maxRetries }, .pinSet)
    | some _ => (state, .notAllowed)
  | .reset => ({ pin := none, retries := maxRetries, mismatches := 0 }, .resetDone)

/-- Run a sequence of events, collecting the outputs. -/
def runTrace : State → List Event → State × List Output
  | state, [] => (state, [])
  | state, event :: events =>
    let (afterEvent, output) := handleEvent state event
    let (finalState, outputs) := runTrace afterEvent events
    (finalState, output :: outputs)

/-- Wrong PINs since the last correct entry, setting of the PIN, or reset. -/
def nextRun (wrong : Nat) : Output → Nat
  | .accepted | .pinSet | .resetDone => 0
  | .wrongPin => wrong + 1
  | _ => wrong

/-- `nextRun` over a list of outputs, starting from `wrong`. -/
def wrongRun (wrong : Nat) : List Output → Nat
  | [] => wrong
  | output :: outputs => wrongRun (nextRun wrong output) outputs

/-- Wrong PINs in a row, without a correct entry, a power cycle (also the one an interrupted
attempt causes) or a reset between them. -/
def nextStreak (wrong : Nat) : Output → Nat
  | .accepted | .resetDone | .poweredUp | .interrupted => 0
  | .wrongPin => wrong + 1
  | _ => wrong

/-- `nextStreak` over a list of outputs, starting from `wrong`. -/
def wrongStreak (wrong : Nat) : List Output → Nat
  | [] => wrong
  | output :: outputs => wrongStreak (nextStreak wrong output) outputs

/-! ## Single steps -/

/-- **Proves:** one event keeps `wrong + retries ≤ 8`: a wrong PIN adds one to the run and
takes one from the counter, and everything that clears the run also refills the counter.

**How:** every event; inside `attempt`, every branch (`split`), then `omega` on the
arithmetic. `changePin` is `attempt` followed, on success only, by a change of PIN, which
leaves the counter alone. -/
theorem attempt_keeps_budget (state : State) (guess wrong : Nat)
    (hBudget : wrong + state.retries ≤ maxRetries) :
    nextRun wrong (attempt state guess).2 + (attempt state guess).1.retries ≤ maxRetries := by
  unfold attempt
  unfold maxRetries at hBudget ⊢
  cases hPin : state.pin with
  | none => simpa [nextRun] using hBudget
  | some pin =>
    simp only
    by_cases hZero : state.retries = 0
    · simpa [hZero, nextRun] using hBudget
    · by_cases hBlocked : mismatchesPerPowerCycle ≤ state.mismatches
      · simpa [hZero, hBlocked, nextRun] using hBudget
      · by_cases hRight : guess = pin
        · simp [hZero, hBlocked, hRight, nextRun]
        · simp only [hZero, hBlocked, hRight, ite_false, nextRun]
          omega

theorem handleEvent_keeps_budget (state : State) (event : Event) (wrong : Nat)
    (hBudget : wrong + state.retries ≤ maxRetries) :
    nextRun wrong (handleEvent state event).2 + (handleEvent state event).1.retries ≤ maxRetries := by
  cases event with
  | attempt guess => exact attempt_keeps_budget state guess wrong hBudget
  | changePin guess newPin =>
    have h := attempt_keeps_budget state guess wrong hBudget
    simp only [handleEvent]
    -- Syntax: `cases hA : e with | mk a b` names the two halves of the pair `e` and
    -- replaces `e` by `(a, b)` in the goal, remembering `hA : e = (a, b)`.
    cases hA : attempt state guess with
    | mk after output =>
      rw [hA] at h
      cases output <;> simpa [nextRun] using h
  | interruptedAttempt =>
    simp only [handleEvent]
    unfold maxRetries at hBudget ⊢
    cases state.pin <;> simp only <;> (try split) <;> (try split) <;> simp_all [nextRun] <;> omega
  | powerCycle => simpa [handleEvent, nextRun] using hBudget
  | setPin pin =>
    simp only [handleEvent]
    unfold maxRetries at hBudget ⊢
    cases state.pin <;> simp [nextRun] <;> omega
  | reset => simp [handleEvent, nextRun, maxRetries]

/-- **Proves:** a wrong PIN or an accepted one was compared only with a retry left and below
the per-power-cycle limit, and a wrong one leaves the counter exactly one lower. With
`interruptedAttempt` also costing a retry, there is no way to have a PIN compared for free.

**How:** unfold `attempt` and take every branch; only the last two compare. -/
theorem comparison_needs_a_counted_retry (state : State) (guess : Nat) :
    ((attempt state guess).2 = .wrongPin ∨ (attempt state guess).2 = .accepted) →
      0 < state.retries ∧ state.mismatches < mismatchesPerPowerCycle ∧
        ((attempt state guess).2 = .wrongPin → (attempt state guess).1.retries + 1 = state.retries) := by
  unfold attempt
  cases state.pin with
  | none => simp
  | some pin =>
    simp only
    by_cases hZero : state.retries = 0
    · simp [hZero]
    · by_cases hBlocked : mismatchesPerPowerCycle ≤ state.mismatches
      · simp [hZero, hBlocked]
      · by_cases hRight : guess = pin <;> simp [hZero, hBlocked, hRight] <;> omega

/-- **Proves:** one event keeps `streak ≤ mismatches ≤ 3`.

**How:** as `handleEvent_keeps_budget`; a wrong PIN needs `mismatches < 3`, and every event
that ends a streak also clears `mismatches` (or leaves both alone). -/
theorem attempt_keeps_streak (state : State) (guess streak : Nat)
    (hStreak : streak ≤ state.mismatches ∧ state.mismatches ≤ mismatchesPerPowerCycle) :
    nextStreak streak (attempt state guess).2 ≤ (attempt state guess).1.mismatches ∧
      (attempt state guess).1.mismatches ≤ mismatchesPerPowerCycle := by
  unfold attempt
  cases state.pin with
  | none => simpa [nextStreak] using hStreak
  | some pin =>
    simp only
    by_cases hZero : state.retries = 0
    · simpa [hZero, nextStreak] using hStreak
    · by_cases hBlocked : mismatchesPerPowerCycle ≤ state.mismatches
      · simpa [hZero, hBlocked, nextStreak] using hStreak
      · by_cases hRight : guess = pin
        · simp [hZero, hBlocked, hRight, nextStreak]
        · simp only [hZero, hBlocked, hRight, ite_false, nextStreak]
          omega

theorem handleEvent_keeps_streak (state : State) (event : Event) (streak : Nat)
    (hStreak : streak ≤ state.mismatches ∧ state.mismatches ≤ mismatchesPerPowerCycle) :
    nextStreak streak (handleEvent state event).2 ≤ (handleEvent state event).1.mismatches ∧
      (handleEvent state event).1.mismatches ≤ mismatchesPerPowerCycle := by
  cases event with
  | attempt guess => exact attempt_keeps_streak state guess streak hStreak
  | changePin guess newPin =>
    have h := attempt_keeps_streak state guess streak hStreak
    simp only [handleEvent]
    cases hA : attempt state guess with
    | mk after output =>
      rw [hA] at h
      cases output <;> simpa [nextStreak] using h
  | interruptedAttempt =>
    simp only [handleEvent]
    cases state.pin <;> simp only <;> (try split) <;> (try split) <;>
      simp_all [nextStreak, mismatchesPerPowerCycle]
  | powerCycle => simp [handleEvent, nextStreak, mismatchesPerPowerCycle]
  | setPin pin =>
    simp only [handleEvent]
    cases state.pin <;> simpa [nextStreak] using hStreak
  | reset => simp [handleEvent, nextStreak, mismatchesPerPowerCycle]

/-! ## Traces -/

/-- The budget `wrong + retries ≤ 8` holds after any trace that starts within it.

**How:** induction on the events, one `handleEvent_keeps_budget` per step. -/
theorem runTrace_keeps_budget (state : State) (events : List Event) (wrong : Nat)
    (hBudget : wrong + state.retries ≤ maxRetries) :
    wrongRun wrong (runTrace state events).2 + (runTrace state events).1.retries ≤ maxRetries := by
  induction events generalizing state wrong with
  | nil => simpa [runTrace, wrongRun] using hBudget
  | cons event events ih =>
    simp only [runTrace, wrongRun]
    exact ih _ _ (handleEvent_keeps_budget state event wrong hBudget)

/-- **Invariant 10 (guesses).** From any state with at most 8 retries (a new device has
exactly 8), every trace of attempts, PIN changes, power cycles, interrupted attempts and
resets compares at most 8 wrong PINs since the last correct entry, setting of the PIN or
reset. As every prefix of a trace is a trace, this holds at every point.

**How:** `runTrace_keeps_budget` with an empty run, and `retries ≥ 0`. -/
theorem wrong_pins_between_successes_le_eight (state : State) (events : List Event)
    (hStart : state.retries ≤ maxRetries) :
    wrongRun 0 (runTrace state events).2 ≤ maxRetries := by
  have := runTrace_keeps_budget state events 0 (by omega)
  omega

/-- **Invariant 10 (pace).** From power-up (no mismatches), at most 3 wrong PINs are
compared in a row without a correct entry, a power cycle or a reset between them. A script
on the host must make the user unplug the key after every three guesses.

**How:** induction with `streak ≤ mismatches ≤ 3`, one `handleEvent_keeps_streak` per step. -/
theorem runTrace_keeps_streak (state : State) (events : List Event) (streak : Nat)
    (hStreak : streak ≤ state.mismatches ∧ state.mismatches ≤ mismatchesPerPowerCycle) :
    wrongStreak streak (runTrace state events).2 ≤ mismatchesPerPowerCycle := by
  induction events generalizing state streak with
  | nil => simp only [runTrace, wrongStreak]; omega
  | cons event events ih =>
    simp only [runTrace, wrongStreak]
    exact ih _ _ (handleEvent_keeps_streak state event streak hStreak)

theorem wrong_pins_in_a_row_le_three (state : State) (events : List Event)
    (hPowerUp : state.mismatches = 0) :
    wrongStreak 0 (runTrace state events).2 ≤ mismatchesPerPowerCycle :=
  runTrace_keeps_streak state events 0 (by simp [hPowerUp, mismatchesPerPowerCycle])

/-- **Proves:** a blocked PIN (set, counter 0) stays blocked under every event but a reset,
and accepts nothing meanwhile.

**How:** every event; with `retries = 0` each one either refuses or, for `setPin`, sees a
PIN already set. -/
theorem blocked_step (state : State) (event : Event) (hNotReset : event ≠ .reset)
    (hSet : state.pin.isSome) (hZero : state.retries = 0) :
    (handleEvent state event).1.pin.isSome ∧ (handleEvent state event).1.retries = 0 ∧
      (handleEvent state event).2 ≠ .accepted := by
  obtain ⟨pin, hPin⟩ := Option.isSome_iff_exists.mp hSet
  cases event with
  | attempt guess => simp [handleEvent, attempt, hPin, hZero]
  | changePin guess newPin => simp [handleEvent, attempt, hPin, hZero]
  | interruptedAttempt => simp [handleEvent, hPin, hZero]
  | powerCycle => simp [handleEvent, hPin, hZero]
  | setPin newPin => simp [handleEvent, hPin, hZero]
  | reset => exact absurd rfl hNotReset

/-- **Invariant 10 (blocking).** Once the counter reaches 0 with a PIN set, no trace without
a reset ever accepts a PIN. A reset removes the PIN and, with the epoch, every credential.

**How:** induction on the events, one `blocked_step` per step. -/
theorem blocked_until_reset (state : State) (events : List Event)
    (hNoReset : ∀ event ∈ events, event ≠ .reset)
    (hSet : state.pin.isSome) (hZero : state.retries = 0) :
    Output.accepted ∉ (runTrace state events).2 := by
  induction events generalizing state with
  | nil => simp [runTrace]
  | cons event events ih =>
    simp only [runTrace, List.mem_cons, not_or]
    have hStep := blocked_step state event (hNoReset event (by simp)) hSet hZero
    exact ⟨fun h => hStep.2.2 h.symm,
      ih _ (fun e he => hNoReset e (by simp [he])) hStep.1 hStep.2.1⟩

end Jotakey.ClientPin
