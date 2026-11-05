-- (c) Javier Fernandez @ JotaSoft 2026
/-!
# The OPTIGA's shielded session and the counter it reports

Formal model of the master side of the shielded connection to the jotakey key's OPTIGA
(`crates/jotakey-core/src/optiga/shielded.rs`, `Session::accept`; `device.rs`,
`Optiga::establish`, `Optiga::command`, `release_counter`).

The cryptography is not modelled: a response either carries a tag that verifies under the
session keys (`authentic`) or not. What is modelled is the rule that decides which responses
the key *uses*, and it is proved that

* `accept_needs_everything`: a response is accepted only with the record SCTR, an SSEQ in the
  window above the last accepted one, and a tag that verifies, and, unless it is the answer to
  the live-session check, only in a live session;
* `accept_moves_forward`: accepting moves the window strictly forward, and only by the window;
* `live_needs_check`: a session is live only if, since the last handshake, a live-session check
  came back right (an old recorded session cannot pass it, `shielded.rs` explains why);
* `used_needs_live`: a response is used only in a live session, and only if it is authentic;
* `used_strictly_increase`: within a session, the SSEQs of the responses used strictly
  increase: no response is used twice, none out of order;
* `released_strictly_increase`: the counter values the key releases strictly increase, whatever
  values the OPTIGA (or anyone) reports.

Histories list events **newest first**, as in `Presence.lean`. Sequence numbers are natural
numbers; the Rust code's `u32` arithmetic stays below `SEQ_LIMIT`, where the two agree
(`tests/differential.rs`).
-/

namespace Jotakey.Shielded

/-- `SEQ_WINDOW`: how far above the last accepted SSEQ a response may be. -/
def seqWindow : Nat := 3

/-- `SEQ_LIMIT`: sequence numbers above this end the session. -/
def seqLimit : Nat := 0xFFFFFFF0

/-- `SCTR_RECORD`: a record with both payloads protected. -/
def recordSctr : Nat := 0x23

/-- `in_window`. -/
def inWindow (last seq : Nat) : Bool :=
  decide (last < seq) && decide (seq ≤ last + seqWindow) && decide (seq ≤ seqLimit)

/-- The master's session state (`Session`, without its keys). -/
structure Session where
  lastSseq : Nat
  fresh : Bool
  deriving DecidableEq, Repr

/-- `Purpose`. -/
inductive Purpose where
  | freshness | use
  deriving DecidableEq, Repr

/-- A response as `Session::accept` sees it. -/
structure Response where
  sctr : Nat
  seq : Nat
  /-- The CCM tag verifies under the session keys. -/
  authentic : Bool
  deriving DecidableEq, Repr

/-- `Session::accept`: the new state if the response is accepted, `none` if refused. -/
def accept (s : Session) (r : Response) (p : Purpose) : Option Session :=
  if p = .use ∧ s.fresh = false then none
  else if r.sctr ≠ recordSctr then none
  else if inWindow s.lastSseq r.seq = false then none
  else if r.authentic = false then none
  else some { s with lastSseq := r.seq }

/-- **Proves:** an accepted response has the record SCTR, an SSEQ in the window, a tag that
verifies, and, for any use but the live-session check, a live session; the new state is the
old one with the window moved to its SSEQ.

**How:** `accept` refuses each missing condition in turn; `split` at each `if`. -/
theorem accept_needs_everything (s s' : Session) (r : Response) (p : Purpose)
    (h : accept s r p = some s') :
    (p = .use → s.fresh = true) ∧ r.sctr = recordSctr ∧ inWindow s.lastSseq r.seq = true ∧
      r.authentic = true ∧ s' = { s with lastSseq := r.seq } := by
  unfold accept at h
  split at h
  · simp at h
  · rename_i hUse
    split at h
    · simp at h
    · rename_i hSctr
      split at h
      · simp at h
      · rename_i hWin
        split at h
        · simp at h
        · rename_i hAuth
          simp only [Option.some.injEq] at h
          refine ⟨fun hp => ?_, by simpa using hSctr, by simpa using hWin, by simpa using hAuth,
            h.symm⟩
          cases hf : s.fresh
          · exact absurd ⟨hp, hf⟩ hUse
          · rfl

/-- **Proves:** accepting moves the window strictly forward, by at most `seqWindow`, and does
not change whether the session is live.

**How:** from `accept_needs_everything`, unfolding `inWindow`. -/
theorem accept_moves_forward (s s' : Session) (r : Response) (p : Purpose)
    (h : accept s r p = some s') :
    s.lastSseq < s'.lastSseq ∧ s'.lastSseq ≤ s.lastSseq + seqWindow ∧ s'.fresh = s.fresh := by
  obtain ⟨-, -, hWin, -, rfl⟩ := accept_needs_everything s s' r p h
  simp only [inWindow, Bool.and_eq_true, decide_eq_true_eq] at hWin
  exact ⟨hWin.1.1, hWin.1.2, rfl⟩

/-- What happens on the bus, as the device layer sees it. -/
inductive Event where
  /-- A completed handshake (`Handshake::finish`): a new session, not live, its window at the
  OPTIGA's Hello SSEQ. -/
  | handshake (sseq : Nat)
  /-- The answer to the live-session check; `correct` says whether it equals the value the MCU
  computed itself. -/
  | check (r : Response) (correct : Bool)
  /-- The response to any other command. -/
  | use (r : Response)
  /-- A failure outside the presentation layer (timeout, bus, status): the session is dropped. -/
  | fail
  deriving DecidableEq, Repr

/-- One event: the new session state (`none`: no session) and the SSEQ of the response used,
if one was. Any refusal drops the session (`Optiga::protected`). -/
def step : Option Session → Event → Option Session × Option Nat
  | _, .handshake sseq => (some ⟨sseq, false⟩, none)
  | none, _ => (none, none)
  | some s, .check r correct =>
    match accept s r .freshness with
    | some s' => if correct then (some { s' with fresh := true }, none) else (none, none)
    | none => (none, none)
  | some s, .use r =>
    match accept s r .use with
    | some s' => (some s', some r.seq)
    | none => (none, none)
  | some _, .fail => (none, none)

/-- The session after a history (newest first), from power-up (no session). -/
def stateAfter : List Event → Option Session
  | [] => none
  | e :: older => (step (stateAfter older) e).1

/-- The SSEQ of the response used at the newest event, if any. -/
def usedAt : List Event → Option Nat
  | [] => none
  | e :: older => (step (stateAfter older) e).2

/-- The SSEQs used since the last handshake, newest first. -/
def used : List Event → List Nat
  | [] => []
  | .handshake _ :: _ => []
  | e :: older =>
    match (step (stateAfter older) e).2 with
    | some q => q :: used older
    | none => used older

/-- A live-session check came back right since the last handshake. -/
def checkSinceHandshake : List Event → Prop
  | [] => False
  | .handshake _ :: _ => False
  | .check _ true :: _ => True
  | _ :: older => checkSinceHandshake older

/-- **Proves:** a session is live only if a live-session check came back right since the last
handshake.

**How:** induction on the history. A handshake makes a session that is not live; only a
`check` with `correct = true` sets `fresh`; every other event either keeps the session (and
`fresh`, `accept_moves_forward`) or drops it. -/
theorem live_needs_check :
    ∀ (history : List Event) (s : Session), stateAfter history = some s → s.fresh = true →
      checkSinceHandshake history := by
  intro history
  induction history with
  | nil => intro s h; simp [stateAfter] at h
  | cons e older ih =>
    intro s hState hFresh
    cases e with
    | handshake sseq =>
      simp only [stateAfter, step, Option.some.injEq] at hState
      subst hState
      simp at hFresh
    | fail =>
      cases hOld : stateAfter older <;> simp [stateAfter, step, hOld] at hState
    | check r correct =>
      cases correct with
      | true => simp [checkSinceHandshake]
      | false =>
        cases hOld : stateAfter older with
        | none => simp [stateAfter, step, hOld] at hState
        | some s0 =>
          simp only [stateAfter, step, hOld] at hState
          split at hState <;> simp at hState
    | use r =>
      cases hOld : stateAfter older with
      | none => simp [stateAfter, step, hOld] at hState
      | some s0 =>
        simp only [stateAfter, step, hOld] at hState
        split at hState
        · rename_i s' hAcc
          simp only [Option.some.injEq] at hState
          subst hState
          have hSame := (accept_moves_forward s0 s' r .use hAcc).2.2
          exact ih s0 hOld (hSame ▸ hFresh)
        · simp at hState

/-- **Proves:** a response is used only in a live session and only if its tag verifies, its SCTR
is the record's and its SSEQ is in the window; the SSEQ reported is the response's.

**How:** `usedAt` is `some` only through `step`'s `use` branch with `accept … .use` succeeding;
`accept_needs_everything` gives the rest. -/
theorem used_needs_live (older : List Event) (e : Event) (q : Nat)
    (h : usedAt (e :: older) = some q) :
    ∃ s r, stateAfter older = some s ∧ e = .use r ∧ s.fresh = true ∧ r.authentic = true ∧
      r.sctr = recordSctr ∧ inWindow s.lastSseq r.seq = true ∧ q = r.seq := by
  simp only [usedAt] at h
  cases hOld : stateAfter older with
  | none => cases e <;> simp [step, hOld] at h
  | some s =>
    cases e with
    | handshake _ => simp [step] at h
    | fail => simp [step, hOld] at h
    | check r c =>
      simp only [step, hOld] at h
      split at h
      · split at h <;> simp at h
      · simp at h
    | use r =>
      simp only [step, hOld] at h
      split at h
      · rename_i s' hAcc
        simp only [Option.some.injEq] at h
        obtain ⟨hFresh, hSctr, hWin, hAuth, -⟩ := accept_needs_everything s s' r .use hAcc
        exact ⟨s, r, rfl, rfl, hFresh rfl, hAuth, hSctr, hWin, h.symm⟩
      · simp at h

/-- What the session state says about the SSEQs used since the last handshake. -/
def Bounded (history : List Event) : Prop :=
  ∀ s, stateAfter history = some s → ∀ q ∈ used history, q ≤ s.lastSseq

/-- **Proves:** while a session exists, every SSEQ used since the last handshake is at most the
window's position, and once the session is dropped nothing more is used until the next
handshake.

**How:** induction on the history. A handshake empties `used`. Accepting a response puts its
SSEQ at the head of `used` and moves the window exactly there (`accept_needs_everything`); the
older SSEQs were below the old position, which is below the new one. A dropped session adds
nothing. -/
theorem used_bounded : ∀ history : List Event, Bounded history := by
  intro history
  induction history with
  | nil => intro s h; simp [stateAfter] at h
  | cons e older ih =>
    intro s hState q hq
    cases e with
    | handshake sseq => simp [used] at hq
    | fail => cases hOld : stateAfter older <;> simp [stateAfter, step, hOld] at hState
    | check r c =>
      cases hOld : stateAfter older with
      | none => simp [stateAfter, step, hOld] at hState
      | some s0 =>
        cases hAcc : accept s0 r .freshness with
        | none => simp [stateAfter, step, hOld, hAcc] at hState
        | some s' =>
          cases c with
          | false => simp [stateAfter, step, hOld, hAcc] at hState
          | true =>
            simp only [stateAfter, step, hOld, hAcc, ite_true, Option.some.injEq] at hState
            subst hState
            have hq' : q ∈ used older := by
              simpa [used, step, hOld, hAcc] using hq
            have hFwd := accept_moves_forward s0 s' r .freshness hAcc
            have := ih s0 hOld q hq'
            simp only
            omega
    | use r =>
      cases hOld : stateAfter older with
      | none => simp [stateAfter, step, hOld] at hState
      | some s0 =>
        simp only [stateAfter, step, hOld] at hState
        split at hState
        · rename_i s' hAcc
          simp only [Option.some.injEq] at hState
          subst hState
          obtain ⟨-, -, -, -, hEq⟩ := accept_needs_everything s0 s' r .use hAcc
          have hFwd := accept_moves_forward s0 s' r .use hAcc
          simp only [used, step, hOld, hAcc, List.mem_cons] at hq
          rcases hq with hq | hq
          · subst hq; rw [hEq]; simp
          · have := ih s0 hOld q hq
            omega
        · simp at hState

/-- **Proves:** the SSEQs of the responses used since the last handshake strictly increase
(newest first, each is greater than every older one): no response is used twice or out of
order.

**How:** induction on the history with `used_bounded`: a newly used SSEQ is above the window's
old position, and every older used SSEQ is at most that position. -/
theorem used_strictly_increase : ∀ history : List Event, (used history).Pairwise (· > ·) := by
  intro history
  induction history with
  | nil => simp [used]
  | cons e older ih =>
    cases e with
    | handshake _ => simp [used]
    | fail =>
      cases hOld : stateAfter older <;> simpa [used, step, hOld] using ih
    | check r c =>
      cases hOld : stateAfter older with
      | none => simpa [used, step, hOld] using ih
      | some s0 =>
        have hNone : (step (some s0) (.check r c)).2 = none := by
          simp only [step]; split <;> (try split) <;> rfl
        simpa [used, hOld, hNone] using ih
    | use r =>
      cases hOld : stateAfter older with
      | none => simpa [used, step, hOld] using ih
      | some s0 =>
        cases hAcc : accept s0 r .use with
        | none => simpa [used, step, hOld, hAcc] using ih
        | some s' =>
          simp only [used, step, hOld, hAcc, List.pairwise_cons]
          refine ⟨fun q hq => ?_, ih⟩
          have hFwd := accept_moves_forward s0 s' r .use hAcc
          obtain ⟨-, -, -, -, hEq⟩ := accept_needs_everything s0 s' r .use hAcc
          have := used_bounded older s0 hOld q hq
          have hSeq : s'.lastSseq = r.seq := by rw [hEq]
          omega

/-- `release_counter`: a counter value read back is released only above the last one released;
returns the new high-water mark and whether the value is released. -/
def release (last : Option Nat) (value : Nat) : Option Nat × Bool :=
  match last with
  | some l => if value ≤ l then (some l, false) else (some value, true)
  | none => (some value, true)

/-- The high-water mark after values read back (newest first), from power-up. -/
def markAfter : List Nat → Option Nat
  | [] => none
  | v :: older => (release (markAfter older) v).1

/-- The values released, newest first. -/
def released : List Nat → List Nat
  | [] => []
  | v :: older => if (release (markAfter older) v).2 then v :: released older else released older

/-- **Proves:** every released value is at most the high-water mark, and there is a mark as
soon as anything was released.

**How:** induction; `release` raises the mark to a released value and never lowers it. -/
theorem released_le_mark : ∀ (values : List Nat) (q : Nat), q ∈ released values →
    ∃ m, markAfter values = some m ∧ q ≤ m := by
  intro values
  induction values with
  | nil => intro q h; simp [released] at h
  | cons v older ih =>
    intro q hq
    cases hm : markAfter older with
    | none =>
      simp only [released, markAfter, hm, release, ite_true, List.mem_cons] at hq ⊢
      rcases hq with rfl | hq
      · exact ⟨q, rfl, Nat.le_refl q⟩
      · obtain ⟨m, hm', -⟩ := ih q hq
        simp [hm] at hm'
    | some l =>
      by_cases hle : v ≤ l
      · simp only [released, markAfter, hm, release, hle, ite_true, Bool.false_eq_true,
          ite_false] at hq ⊢
        obtain ⟨m, hm', hqm⟩ := ih q hq
        simp only [hm, Option.some.injEq] at hm'
        exact ⟨l, rfl, hm' ▸ hqm⟩
      · simp only [released, markAfter, hm, release, hle, ite_false, ite_true,
          List.mem_cons] at hq ⊢
        rcases hq with rfl | hq
        · exact ⟨q, rfl, Nat.le_refl q⟩
        · obtain ⟨m, hm', hqm⟩ := ih q hq
          simp only [hm, Option.some.injEq] at hm'
          exact ⟨v, rfl, by omega⟩

/-- **Proves:** the counter values the key releases strictly increase (newest first, each is
greater than every older one), whatever sequence of values is read back.

**How:** induction with `released_le_mark`: a value is released only above the mark, and every
older released value is at most the mark. -/
theorem released_strictly_increase : ∀ values : List Nat, (released values).Pairwise (· > ·) := by
  intro values
  induction values with
  | nil => simp [released]
  | cons v older ih =>
    simp only [released]
    split
    · rename_i hRel
      refine List.pairwise_cons.mpr ⟨fun q hq => ?_, ih⟩
      obtain ⟨m, hm, hqm⟩ := released_le_mark older q hq
      simp only [release, hm] at hRel
      split at hRel
      · simp at hRel
      · omega
    · exact ih

end Jotakey.Shielded
