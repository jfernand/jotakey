-- (c) Javier Fernandez @ JotaSoft 2026
/-!
# The user-presence gate

Formal model of `crates/jotakey-core/src/presence.rs` (`PresenceGate::new`,
`PresenceGate::poll`): the rule that decides, from the readings of the sensor (the C6's
button, the key's touch electrode), when a touch counts.

`Authenticator.lean` takes a `PresenceResult.confirmed` as an input and proves that signatures
carrying the UP flag need one. This file proves where a confirmation can come from:

* `confirmed_needs_release_then_debounced_press`: the gate confirms only if, since the
  request arrived, the sensor was seen released and then pressed for the last
  `debouncePolls` readings in a row, and no reading had reached the deadline.
* `press_held_from_the_start_never_confirms`: a sensor pressed at every reading (taped down,
  or held since an earlier request) never confirms anything.
* `timeout_at_deadline` and `timeout_is_final`: from a reading at or past the deadline on,
  every poll times out, whatever times later readings report.

Readings are pairs `(nowMs, pressed)`, and a history lists them **newest first**, so that the
reading just taken is the head of the list (`::`) and induction runs from the oldest one.
The Rust deadline saturates at `u64::MAX` and the Rust press count at 255; with natural
numbers neither limit exists, and below them the two compute the same steps
(`tests/differential.rs`).

Each theorem's doc comment says what it **proves** and **how**.
-/

namespace Jotakey.Presence

/-- `UP_TIMEOUT_MS`: how long the user has to touch the device. -/
def upTimeoutMs : Nat := 30000

/-- `DEBOUNCE_POLLS`: consecutive pressed readings needed after a release. -/
def debouncePolls : Nat := 2

/-- What one poll decided (`GateStep`). -/
inductive Step where
  | waiting | confirmed | timeout
  deriving DecidableEq, Repr

/-- The gate's state (`PresenceGate`). -/
structure Gate where
  deadlineMs : Nat
  expired : Bool
  releasedSeen : Bool
  pressedPolls : Nat
  deriving DecidableEq, Repr

/-- `PresenceGate::new`: the gate for a request that arrived at `nowMs`. -/
def start (nowMs : Nat) : Gate :=
  { deadlineMs := nowMs + upTimeoutMs, expired := false, releasedSeen := false, pressedPolls := 0 }

/-- `PresenceGate::poll`: feed one reading taken at `nowMs`. -/
def poll (gate : Gate) (nowMs : Nat) (pressed : Bool) : Gate × Step :=
  if gate.expired || gate.deadlineMs ≤ nowMs then ({ gate with expired := true }, .timeout)
  else if !pressed then ({ gate with releasedSeen := true, pressedPolls := 0 }, .waiting)
  else if gate.releasedSeen then
    if debouncePolls ≤ gate.pressedPolls + 1 then
      ({ gate with pressedPolls := gate.pressedPolls + 1 }, .confirmed)
    else ({ gate with pressedPolls := gate.pressedPolls + 1 }, .waiting)
  else (gate, .waiting)

/-- The gate after the readings of `history` (newest first), for a request at `startMs`. -/
def gateAfter (startMs : Nat) : List (Nat × Bool) → Gate
  | [] => start startMs
  | (nowMs, pressed) :: older => (poll (gateAfter startMs older) nowMs pressed).1

/-- How many of the newest readings in a row are presses. -/
def leadingPresses : List (Nat × Bool) → Nat
  | (_, true) :: older => leadingPresses older + 1
  | _ => 0

/-- What the gate's state says about the history behind it. -/
structure Accounts (startMs : Nat) (history : List (Nat × Bool)) (gate : Gate) : Prop where
  deadline : gate.deadlineMs = startMs + upTimeoutMs
  /-- Not expired: every reading so far came before the deadline. -/
  inTime : gate.expired = false → ∀ reading ∈ history, reading.1 < startMs + upTimeoutMs
  /-- A reading at or past the deadline expires the gate. -/
  expiredLate : (∃ reading ∈ history, startMs + upTimeoutMs ≤ reading.1) → gate.expired = true
  /-- A release was seen: some reading in the history is a release. -/
  released : gate.releasedSeen = true → ∃ reading ∈ history, reading.2 = false
  /-- Until it expires, the press count never exceeds the run of presses at the head of the
  history. (An expired gate keeps its count, but it only ever answers `.timeout`.) -/
  presses : gate.expired = false → gate.pressedPolls ≤ leadingPresses history

/-- **Proves:** `Accounts` holds for the gate after any history.

**How:** induction on the history. The empty history is the fresh gate, for which every
field is immediate. For a new reading `(nowMs, pressed)`, unfold `poll` and split on its
branches (`split`); in each, the new state's fields follow from the old `Accounts` and from
the branch condition, `simp_all` doing the bookkeeping and `omega` the arithmetic. -/
theorem gateAfter_accounts (startMs : Nat) :
    ∀ history, Accounts startMs history (gateAfter startMs history) := by
  intro history
  induction history with
  | nil =>
    exact ⟨by simp [gateAfter, start], by simp, by simp, by simp [gateAfter, start],
      fun _ => by simp [gateAfter, start, leadingPresses]⟩
  | cons reading older ih =>
    obtain ⟨nowMs, pressed⟩ := reading
    obtain ⟨hDeadline, hInTime, hExpiredLate, hReleased, hPresses⟩ := ih
    simp only [gateAfter, poll]
    split
    · -- Timeout: the gate expires.
      rename_i hLate
      refine ⟨by simp [hDeadline], by simp, by simp, ?_, ?_⟩
      · intro h
        obtain ⟨r, hr, hr2⟩ := hReleased h
        exact ⟨r, List.mem_cons_of_mem _ hr, hr2⟩
      · simp
    · rename_i hInWindow
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true] at hInWindow
      obtain ⟨hNotExpired, hBefore⟩ := hInWindow
      have hNowIn : nowMs < startMs + upTimeoutMs := by omega
      have hOlderIn := hInTime hNotExpired
      have hAllIn : ∀ r ∈ (nowMs, pressed) :: older, r.1 < startMs + upTimeoutMs := by
        intro r hr
        rcases List.mem_cons.mp hr with h | h
        · subst h; exact hNowIn
        · exact hOlderIn r h
      have hNoLate : ¬ ∃ r ∈ (nowMs, pressed) :: older, startMs + upTimeoutMs ≤ r.1 := by
        rintro ⟨r, hr, hLate⟩
        have := hAllIn r hr
        omega
      split
      · -- A release.
        rename_i hReleaseNow
        have hFalse : pressed = false := by simpa using hReleaseNow
        subst hFalse
        exact ⟨by simp [hDeadline], fun _ => hAllIn, fun h => absurd h hNoLate,
          fun _ => ⟨(nowMs, false), List.mem_cons_self, rfl⟩, fun _ => by simp⟩
      · rename_i hPressNow
        have hTrue : pressed = true := by simpa using hPressNow
        subst hTrue
        split
        · rename_i hSeen
          split <;>
          exact ⟨by simp [hDeadline], fun _ => hAllIn, fun h => absurd h hNoLate,
            fun _ => by
              obtain ⟨r, hr, hr2⟩ := hReleased hSeen
              exact ⟨r, List.mem_cons_of_mem _ hr, hr2⟩,
            fun _ => by have := hPresses hNotExpired; simp [leadingPresses]; omega⟩
        · rename_i hNotSeen
          exact ⟨hDeadline, fun _ => hAllIn, fun h => absurd h hNoLate,
            fun h => absurd h hNotSeen,
            fun _ => by have := hPresses hNotExpired; simp [leadingPresses]; omega⟩

/-- **Proves:** if the poll of a new reading `(nowMs, pressed)` confirms, then that reading is
a press, the last `debouncePolls` readings (this one included) are all presses, an older
reading since the request is a release, and every reading came before the deadline.

**How:** a confirmation comes from exactly one branch of `poll`: not expired, before the
deadline, pressed, a release seen, and the count reached `debouncePolls`. `Accounts` of the
older history turns "a release seen" into a release in that history, and bounds the old count
by the run of presses at its head, which this press extends by one. -/
theorem confirmed_needs_release_then_debounced_press (startMs nowMs : Nat) (pressed : Bool)
    (older : List (Nat × Bool))
    (hConfirmed : (poll (gateAfter startMs older) nowMs pressed).2 = .confirmed) :
    pressed = true ∧
      debouncePolls ≤ leadingPresses ((nowMs, pressed) :: older) ∧
      (∃ reading ∈ older, reading.2 = false) ∧
      ∀ reading ∈ (nowMs, pressed) :: older, reading.1 < startMs + upTimeoutMs := by
  have hAccounts := gateAfter_accounts startMs older
  obtain ⟨hDeadline, hInTime, -, hReleased, hPresses⟩ := hAccounts
  unfold poll at hConfirmed
  split at hConfirmed
  · simp at hConfirmed
  · rename_i hInWindow
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true] at hInWindow
    obtain ⟨hNotExpired, hBefore⟩ := hInWindow
    split at hConfirmed
    · simp at hConfirmed
    · rename_i hPressNow
      have hTrue : pressed = true := by simpa using hPressNow
      subst hTrue
      split at hConfirmed
      · rename_i hSeen
        split at hConfirmed
        · rename_i hCount
          refine ⟨rfl, ?_, hReleased hSeen, ?_⟩
          · have := hPresses hNotExpired
            simp only [leadingPresses]; omega
          · intro r hr
            rcases List.mem_cons.mp hr with h | h
            · subst h; simp only; omega
            · exact hInTime hNotExpired r h
        · simp at hConfirmed
      · simp at hConfirmed

/-- **Proves:** a sensor pressed at every reading since the request never confirms.

**How:** `confirmed_needs_release_then_debounced_press` would give a release among the
readings, and there is none. -/
theorem press_held_from_the_start_never_confirms (startMs nowMs : Nat) (older : List (Nat × Bool))
    (hHeld : ∀ reading ∈ older, reading.2 = true) :
    (poll (gateAfter startMs older) nowMs true).2 ≠ .confirmed := by
  intro hConfirmed
  obtain ⟨-, -, ⟨r, hr, hRelease⟩, -⟩ :=
    confirmed_needs_release_then_debounced_press startMs nowMs true older hConfirmed
  have := hHeld r hr
  simp_all

/-- **Proves:** a reading at or past the deadline times out.

**How:** `Accounts` fixes the deadline at `startMs + upTimeoutMs`, so `poll` takes its first
branch. -/
theorem timeout_at_deadline (startMs nowMs : Nat) (pressed : Bool) (older : List (Nat × Bool))
    (hLate : startMs + upTimeoutMs ≤ nowMs) :
    (poll (gateAfter startMs older) nowMs pressed).2 = .timeout := by
  have hDeadline := (gateAfter_accounts startMs older).deadline
  unfold poll
  simp [hDeadline, hLate]

/-- **Proves:** once any reading has reached the deadline, every later poll times out,
whatever time it reports.

**How:** `Accounts.expiredLate` says the gate is expired, and `poll` answers an expired gate
with `.timeout` before looking at the reading. -/
theorem timeout_is_final (startMs nowMs : Nat) (pressed : Bool) (older : List (Nat × Bool))
    (hLateBefore : ∃ reading ∈ older, startMs + upTimeoutMs ≤ reading.1) :
    (poll (gateAfter startMs older) nowMs pressed).2 = .timeout := by
  have hExpired := (gateAfter_accounts startMs older).expiredLate hLateBefore
  unfold poll
  simp [hExpired]

end Jotakey.Presence
