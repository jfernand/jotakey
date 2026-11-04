-- (c) Javier Fernandez @ JotaSoft 2026
/-!
# The power-loss-safe record log

Formal model of `crates/jotakey-core/src/storage.rs` (`RecordLog::mount`,
`RecordLog::append`), which persists the signature counter on the ESP32-C6 (and, until the
OPTIGA counter replaces it, on the jotakey key), and the reset epoch and the PIN record on both.

`Authenticator.lean` proves that signature counters increase given a persisted counter. This
file proves that the log *is* one under power loss (invariant 2): whatever power cuts
interrupt the appends, a remount never finds a value older than the last one `append`
confirmed.

The model works at the level of **slots**. A sector holds `capacity` slots (the sector size
divided by the record stride, `record length rounded up to the flash programming unit`), and
each slot is erased, torn (anything that fails the CRC), or a valid record with its sequence
number. Payloads are left out; `fuzz/fuzz_targets/record_log.rs` checks them. That a slot is
an independent unit of failure is the byte-level fact the Rust tests pin
(`mock_flash_refuses_partial_and_repeated_programming`, `eight_byte_units_pad_each_record`):
records sit at stride-aligned offsets, each covers whole programming units, and no unit is
programmed twice, so a cut while writing one record damages that record's slot alone.

A power cut is nondeterministic (`AppendStep.cut`):
* during an erase, every slot of the sector being erased may end up as it was, erased, or torn;
* during a write, the slot being written may end up erased, torn, or holding the new record
  (programmed, but `append` never confirmed it); every other slot keeps its value.

Results:
* `mount_fits`: what `mount` computes describes the flash correctly (`Fits`).
* `append_preserves_latest`: no append outcome, cut or not, lowers the latest record.
* `append_ok`: a confirmed append returns `latest + 1` and leaves a log that still `Fits`.
* `trace_never_loses_confirmed`: along any sequence of appends, power cuts and remounts, every
  confirmed sequence number exceeds all earlier ones, and the latest record on flash is never
  below the last confirmed one.

Sequence numbers start at 1; `0` stands for "no record" (Rust's `None`).
-/

namespace Jotakey.RecordLog

/-- One record-sized slot of flash. -/
inductive Slot where
  | erased
  | torn
  | record (sequence : Nat)
  deriving DecidableEq, Repr

/-- The two sectors of one log. -/
structure Flash where
  zero : List Slot
  one : List Slot
  deriving DecidableEq, Repr

/-- Sector `false` is the first, `true` the second. -/
def Flash.get (flash : Flash) : Bool → List Slot
  | false => flash.zero
  | true => flash.one

/-- Replace one sector. -/
def Flash.set (flash : Flash) : Bool → List Slot → Flash
  | false, slots => { flash with zero := slots }
  | true, slots => { flash with one := slots }

/-- The highest valid sequence number in a sector, `0` if none. -/
def maxSequence : List Slot → Nat
  | [] => 0
  | .record sequence :: rest => max sequence (maxSequence rest)
  | _ :: rest => maxSequence rest

/-- The highest valid sequence number on the flash. -/
def latestOf (flash : Flash) : Nat := max (maxSequence flash.zero) (maxSequence flash.one)

/-- `scan_end`: the slot after the last slot that is not erased. -/
def scanEnd : List Slot → Nat
  | [] => 0
  | slot :: rest => if scanEnd rest = 0 ∧ slot = .erased then 0 else scanEnd rest + 1

/-- The in-memory log (`RecordLog`): latest sequence number, active sector, next free slot. -/
structure Log where
  latest : Nat
  active : Bool
  next : Nat
  deriving DecidableEq, Repr

/-- `RecordLog::mount`: scan both sectors. The active sector is the one holding the highest
record (the first sector on a tie, as Rust scans it first and keeps a strictly higher one). -/
def mount (flash : Flash) : Log :=
  let active := decide (maxSequence flash.zero < maxSequence flash.one)
  { latest := latestOf flash, active, next := scanEnd (flash.get active) }

/-- Where `append` writes: the sector, whether it erases it first, and the slot. -/
def target (capacity : Nat) (log : Log) : Bool × Bool × Nat :=
  if capacity ≤ log.next ∨ (log.latest = 0 ∧ 0 < log.next) then
    (if log.latest = 0 then log.active else !log.active, true, 0)
  else (log.active, false, log.next)

/-- A sector of `capacity` erased slots. -/
def erasedSector (capacity : Nat) : List Slot := List.replicate capacity .erased

/-- The new contents of the target sector after a confirmed append. -/
def written (capacity : Nat) (old : List Slot) (erase : Bool) (slot sequence : Nat) : List Slot :=
  (if erase then erasedSector capacity else old).set slot (.record sequence)

/-- What a cut may leave in slot `index` of the target sector, whose old value was `old`. -/
def CutSlot (erase : Bool) (slot sequence index : Nat) (old new : Slot) : Prop :=
  new = old ∨
    ((erase = true ∨ index = slot) ∧ (new = .torn ∨ new = .erased)) ∨
    (index = slot ∧ new = .record sequence)

/-- One `append` of sequence number `log.latest + 1`, and what it may do to the flash. -/
inductive AppendStep (capacity : Nat) (log : Log) (flash : Flash) : Flash → Option Nat → Prop where
  /-- It completed and verified: `Ok(sequence)`. -/
  | ok :
      AppendStep capacity log flash
        (flash.set (target capacity log).1
          (written capacity (flash.get (target capacity log).1) (target capacity log).2.1
            (target capacity log).2.2 (log.latest + 1)))
        (some (log.latest + 1))
  /-- The power failed during it: `Err`, and the target sector is damaged as `CutSlot` allows. -/
  | cut (damaged : List Slot)
      (hLength : damaged.length = (flash.get (target capacity log).1).length)
      (hSlots : ∀ index (old new : Slot),
        (flash.get (target capacity log).1)[index]? = some old → damaged[index]? = some new →
        CutSlot (target capacity log).2.1 (target capacity log).2.2 (log.latest + 1) index old new) :
      AppendStep capacity log flash (flash.set (target capacity log).1 damaged) none

/-- The log describes the flash: its latest number is the flash's, the active sector holds it,
everything from `next` on in the active sector is erased, and both sectors have `capacity`
slots. -/
structure Fits (capacity : Nat) (log : Log) (flash : Flash) : Prop where
  zeroLength : flash.zero.length = capacity
  oneLength : flash.one.length = capacity
  latest : log.latest = latestOf flash
  activeHoldsLatest : maxSequence (flash.get log.active) = log.latest
  nextInRange : log.next ≤ capacity
  erasedFromNext : ∀ index slot, log.next ≤ index → (flash.get log.active)[index]? = some slot →
    slot = .erased

/-! ## Facts about sectors -/

theorem le_maxSequence {slots : List Slot} {sequence : Nat} (h : .record sequence ∈ slots) :
    sequence ≤ maxSequence slots := by
  induction slots with
  | nil => simp at h
  | cons head rest ih =>
    rcases List.mem_cons.mp h with hHead | hRest
    · subst hHead; simp only [maxSequence]; omega
    · have := ih hRest
      cases head <;> simp only [maxSequence] <;> omega

theorem maxSequence_mem {slots : List Slot} (h : 0 < maxSequence slots) :
    .record (maxSequence slots) ∈ slots := by
  induction slots with
  | nil => simp [maxSequence] at h
  | cons head rest ih =>
    cases head with
    | erased => simp only [maxSequence] at h ⊢; exact List.mem_cons_of_mem _ (ih h)
    | torn => simp only [maxSequence] at h ⊢; exact List.mem_cons_of_mem _ (ih h)
    | record sequence =>
      simp only [maxSequence] at h ⊢
      by_cases hle : maxSequence rest ≤ sequence
      · rw [Nat.max_eq_left hle]; exact List.mem_cons_self
      · rw [Nat.max_eq_right (by omega)]
        exact List.mem_cons_of_mem _ (ih (by omega))

/-- Every record in a sector is at most its maximum, and the maximum bounds from above. -/
theorem maxSequence_le {slots : List Slot} {bound : Nat}
    (h : ∀ sequence, .record sequence ∈ slots → sequence ≤ bound) : maxSequence slots ≤ bound := by
  by_cases hPos : 0 < maxSequence slots
  · exact h _ (maxSequence_mem hPos)
  · omega

theorem scanEnd_le_length (slots : List Slot) : scanEnd slots ≤ slots.length := by
  induction slots with
  | nil => simp [scanEnd]
  | cons head rest ih => simp only [scanEnd, List.length_cons]; split <;> omega

theorem erased_from_scanEnd (slots : List Slot) :
    ∀ index slot, scanEnd slots ≤ index → slots[index]? = some slot → slot = .erased := by
  induction slots with
  | nil => intro index slot _ h; simp at h
  | cons head rest ih =>
    intro index slot hIndex hSlot
    simp only [scanEnd] at hIndex
    split at hIndex
    · rename_i hEmpty
      obtain ⟨hRest, hHead⟩ := hEmpty
      cases index with
      | zero => simp at hSlot; rw [← hSlot, hHead]
      | succ index => exact ih index slot (by omega) (by simpa using hSlot)
    · cases index with
      | zero => omega
      | succ index => exact ih index slot (by omega) (by simpa using hSlot)

theorem get_set_same (flash : Flash) (sector : Bool) (slots : List Slot) :
    (flash.set sector slots).get sector = slots := by
  cases sector <;> rfl

theorem get_set_other (flash : Flash) (sector other : Bool) (slots : List Slot)
    (h : other ≠ sector) : (flash.set sector slots).get other = flash.get other := by
  cases sector <;> cases other <;> simp_all [Flash.set, Flash.get]

theorem latestOf_eq (flash : Flash) :
    latestOf flash = max (maxSequence (flash.get false)) (maxSequence (flash.get true)) := rfl

/-- A record in either sector is at most the latest. -/
theorem le_latestOf {flash : Flash} {sector : Bool} {sequence : Nat}
    (h : .record sequence ∈ flash.get sector) : sequence ≤ latestOf flash := by
  have := le_maxSequence h
  cases sector <;> simp only [Flash.get] at this <;> simp only [latestOf] <;> omega

/-! ## Mount -/

/-- **Proves:** a freshly mounted log fits the flash it was mounted from.

**How:** `latest` is `latestOf` by definition; the active sector is the one whose maximum is
the larger of the two, so it holds `latestOf`; `next` is `scanEnd` of that sector, past which
`erased_from_scanEnd` says every slot is erased and which `scanEnd_le_length` bounds. -/
theorem mount_fits (capacity : Nat) (flash : Flash) (hZero : flash.zero.length = capacity)
    (hOne : flash.one.length = capacity) : Fits capacity (mount flash) flash := by
  refine ⟨hZero, hOne, rfl, ?_, ?_, ?_⟩
  · simp only [mount, latestOf]
    by_cases h : maxSequence flash.zero < maxSequence flash.one
    · simp [h, Flash.get]; omega
    · simp [h, Flash.get]; omega
  · simp only [mount]
    have := scanEnd_le_length (flash.get (decide (maxSequence flash.zero < maxSequence flash.one)))
    cases hActive : decide (maxSequence flash.zero < maxSequence flash.one) <;>
      simp only [hActive, Flash.get] at this ⊢ <;> omega
  · exact erased_from_scanEnd _

/-! ## Append -/

/-- Where the latest record of a fitting log lives: in the active sector, before `next`. -/
theorem latest_located {capacity : Nat} {log : Log} {flash : Flash} (hFits : Fits capacity log flash)
    (hPos : 0 < log.latest) :
    ∃ index, index < log.next ∧ (flash.get log.active)[index]? = some (.record log.latest) := by
  have hMem := maxSequence_mem (slots := flash.get log.active) (by rw [hFits.activeHoldsLatest]; exact hPos)
  rw [hFits.activeHoldsLatest] at hMem
  obtain ⟨index, hIndex, hGet⟩ := List.getElem_of_mem hMem
  have hAt : (flash.get log.active)[index]? = some (.record log.latest) := by
    rw [List.getElem?_eq_getElem hIndex, hGet]
  refine ⟨index, ?_, hAt⟩
  by_cases hLt : index < log.next
  · exact hLt
  · have := hFits.erasedFromNext index _ (by omega) hAt
    simp at this

/-- **Proves:** no outcome of an append, completed or cut at any point, lowers the latest
record on the flash.

**How:** if there is no record yet there is nothing to lose. Otherwise `latest_located` puts
the latest record in the active sector, before `next`. If the append erases, it erases the
*other* sector (`target`: a log with a record never erases its active sector), so the active
sector is untouched. If it does not erase, it writes slot `next` of the active sector, which is
past the latest record's slot, and `CutSlot` / `written` leave every other slot as it was.
Either way the latest record survives, and `le_latestOf` bounds the new latest from below. -/
theorem append_preserves_latest {capacity : Nat} {log : Log} {flash flash' : Flash}
    {result : Option Nat} (hFits : Fits capacity log flash)
    (hStep : AppendStep capacity log flash flash' result) : latestOf flash ≤ latestOf flash' := by
  by_cases hPos : 0 < log.latest
  case neg => have := hFits.latest; omega
  obtain ⟨index, hBefore, hAt⟩ := latest_located hFits hPos
  obtain ⟨⟨sector, erase, slot⟩, hTarget⟩ : ∃ t, target capacity log = t := ⟨_, rfl⟩
  -- A log with a record erases only the other sector, and otherwise writes slot `next`.
  have hCase : (erase = true ∧ sector = !log.active) ∨
      (erase = false ∧ sector = log.active ∧ slot = log.next) := by
    unfold target at hTarget
    split at hTarget <;> simp only [Prod.mk.injEq] at hTarget
    · left
      obtain ⟨h1, h2, -⟩ := hTarget
      refine ⟨h2.symm, ?_⟩
      rw [← h1]
      simp [Nat.ne_of_gt hPos]
    · right
      obtain ⟨h1, h2, h3⟩ := hTarget
      exact ⟨h2.symm, h1.symm, h3.symm⟩
  have hKeep : (flash'.get log.active)[index]? = some (.record log.latest) := by
    rcases hCase with ⟨hErase, hSector⟩ | ⟨hErase, hSector, hSlot⟩
    · -- The append erases the other sector; the active one is untouched.
      have hOther : log.active ≠ sector := by rw [hSector]; cases log.active <;> simp
      cases hStep with
      | ok => simp only [hTarget]; rw [get_set_other _ _ _ _ hOther]; exact hAt
      | cut damaged _ _ => simp only [hTarget]; rw [get_set_other _ _ _ _ hOther]; exact hAt
    · subst hErase hSector hSlot
      cases hStep with
      | ok =>
        simp only [hTarget]
        rw [get_set_same]
        simp only [written, Bool.false_eq_true, ↓reduceIte]
        rw [List.getElem?_set_ne (by omega)]
        exact hAt
      | cut damaged hLength hSlots =>
        simp only [hTarget] at hLength hSlots ⊢
        rw [get_set_same]
        have hIn : index < damaged.length := by
          rw [hLength]; exact (List.getElem?_eq_some_iff.mp hAt).1
        obtain ⟨new, hNew⟩ : ∃ new, damaged[index]? = some new :=
          ⟨damaged[index], List.getElem?_eq_getElem hIn⟩
        have := hSlots index _ new hAt hNew
        simp only [CutSlot, Bool.false_eq_true, false_or] at this
        rcases this with h | ⟨h, _⟩ | ⟨h, _⟩
        · rw [hNew, h]
        · omega
        · omega
  have hMem : .record log.latest ∈ flash'.get log.active := List.mem_of_getElem? hKeep
  have := le_latestOf hMem
  have := hFits.latest
  omega

/-- **Proves:** a confirmed append returns `latest + 1`, which becomes the latest record on the
flash, and the log as `append` updates it (active = the sector written, next = the slot after
the one written, latest = the new number) fits the new flash.

**How:** every record already on the flash is at most `latest` (`le_latestOf`); the written
sector holds those (or none, if it was erased) plus the new record, so its maximum and the
flash's are `latest + 1`. The slots after the one written are erased: in an erased sector all
are, and otherwise they were erased already (`Fits.erasedFromNext`). Lengths are kept by
`List.set` and `erasedSector`. -/
theorem append_ok {capacity : Nat} {log : Log} {flash flash' : Flash} {sequence : Nat}
    (hFits : Fits capacity log flash) (hCapacity : 0 < capacity)
    (hStep : AppendStep capacity log flash flash' (some sequence)) :
    sequence = log.latest + 1 ∧ latestOf flash' = log.latest + 1 ∧
      Fits capacity
        { latest := sequence, active := (target capacity log).1, next := (target capacity log).2.2 + 1 }
        flash' := by
  cases hStep with
  | ok =>
  refine ⟨rfl, ?_⟩
  -- Name the pieces of the target.
  generalize hTarget : target capacity log = t
  obtain ⟨sector, erase, slot⟩ := t
  have hSlot : slot < capacity ∧ (erase = false → slot = log.next) ∧ (erase = true → slot = 0) := by
    unfold target at hTarget
    split at hTarget <;> simp only [Prod.mk.injEq] at hTarget <;> obtain ⟨-, h2, h3⟩ := hTarget
    · subst h2 h3; exact ⟨hCapacity, by simp, fun _ => rfl⟩
    · subst h2 h3
      rename_i hNo
      exact ⟨by omega, fun _ => rfl, by simp⟩
  have hSectorActive : erase = false → sector = log.active := by
    intro h
    unfold target at hTarget
    split at hTarget <;> simp only [Prod.mk.injEq] at hTarget <;> obtain ⟨h1, h2, -⟩ := hTarget
    · subst h2; simp at h
    · exact h1.symm
  simp only
  have hOldLength : (flash.get sector).length = capacity := by
    cases sector
    · exact hFits.zeroLength
    · exact hFits.oneLength
  obtain ⟨newSector, hNewSector⟩ :
      ∃ newSector, newSector = written capacity (flash.get sector) erase slot (log.latest + 1) :=
    ⟨_, rfl⟩
  rw [← hNewSector]
  have hNewLength : newSector.length = capacity := by
    simp only [hNewSector, written, List.length_set]
    cases erase <;> simp [erasedSector, hOldLength]
  have hNewAt : newSector[slot]? = some (.record (log.latest + 1)) := by
    simp only [hNewSector, written]
    rw [List.getElem?_set_self]
    cases erase <;> simp [erasedSector, hOldLength, hSlot.1]
  have hNewRecords : ∀ s, .record s ∈ newSector → s ≤ log.latest + 1 := by
    intro s hs
    simp only [hNewSector, written] at hs
    rcases List.mem_or_eq_of_mem_set hs with h | h
    · cases erase
      · have := le_latestOf (sector := sector) (flash := flash) (by simpa using h)
        have := hFits.latest; omega
      · simp [erasedSector] at h
    · simp at h; omega
  have hNewMax : maxSequence newSector = log.latest + 1 := by
    have h1 := maxSequence_le hNewRecords
    have h2 := le_maxSequence (List.mem_of_getElem? hNewAt)
    omega
  have hOtherRecords : ∀ s, .record s ∈ flash.get (!sector) → s ≤ log.latest := by
    intro s hs; have := le_latestOf hs; have := hFits.latest; omega
  have hLatest' : latestOf (flash.set sector newSector) = log.latest + 1 := by
    have hOther := maxSequence_le hOtherRecords
    cases sector <;>
      simp only [latestOf, Flash.set, Flash.get, Bool.not_false, Bool.not_true] at hNewMax hOther ⊢ <;>
      omega
  refine ⟨hLatest', ⟨?_, ?_, hLatest'.symm, ?_, by simp only; have := hSlot.1; omega, ?_⟩⟩
  · cases sector
    · simpa [Flash.set] using hNewLength
    · simpa [Flash.set] using hFits.zeroLength
  · cases sector
    · simpa [Flash.set] using hFits.oneLength
    · simpa [Flash.set] using hNewLength
  · rw [get_set_same]; exact hNewMax
  · intro index s hIndex hGet
    simp only at hIndex
    rw [get_set_same] at hGet
    simp only [hNewSector, written] at hGet
    rw [List.getElem?_set_ne (by omega)] at hGet
    cases hErase : erase
    · simp only [hErase, Bool.false_eq_true, ↓reduceIte] at hGet
      have hs := hSlot.2.1 hErase
      rw [hSectorActive hErase] at hGet
      exact hFits.erasedFromNext index s (by omega) hGet
    · simp only [hErase, ↓reduceIte, erasedSector] at hGet
      exact (List.mem_replicate.mp (List.mem_of_getElem? hGet)).2

/-! ## Traces -/

/-- An event the log lives through: an append (with whatever outcome the flash allows), or a
power cycle followed by a remount. -/
inductive Event where
  | append
  | remount

/-- The firmware's view after a run: the flash, the in-memory log, and the last confirmed
sequence number (`0` if none). After a failed append the firmware remounts (the documented
contract of `RecordLog::append`), so a cut is followed by `mount`. -/
inductive Run (capacity : Nat) : List Event → Flash → Log → Nat → Prop where
  | start : Run capacity [] ⟨erasedSector capacity, erasedSector capacity⟩
      (mount ⟨erasedSector capacity, erasedSector capacity⟩) 0
  | appendOk {events flash log confirmed flash' sequence} :
      Run capacity events flash log confirmed →
      AppendStep capacity log flash flash' (some sequence) →
      Run capacity (.append :: events) flash'
        { latest := sequence, active := (target capacity log).1, next := (target capacity log).2.2 + 1 }
        sequence
  | appendCut {events flash log confirmed flash'} :
      Run capacity events flash log confirmed →
      AppendStep capacity log flash flash' none →
      Run capacity (.append :: events) flash' (mount flash') confirmed
  | remount {events flash log confirmed} :
      Run capacity events flash log confirmed →
      Run capacity (.remount :: events) flash (mount flash) confirmed

/-- The damaged sector of a cut has `capacity` slots, like the one it replaced. -/
theorem cut_lengths {capacity : Nat} {log : Log} {flash flash' : Flash}
    (hFits : Fits capacity log flash) (hStep : AppendStep capacity log flash flash' none) :
    flash'.zero.length = capacity ∧ flash'.one.length = capacity := by
  cases hStep with
  | cut damaged hLength _ =>
    cases hSector : (target capacity log).1 <;> rw [hSector] at hLength <;>
      simp only [Flash.set, Flash.get] at hLength ⊢
    · exact ⟨by rw [hLength, hFits.zeroLength], hFits.oneLength⟩
    · exact ⟨hFits.zeroLength, by rw [hLength, hFits.oneLength]⟩

/-- **Proves:** along any run, the in-memory log fits the flash, the latest record on the flash
is at least the last confirmed sequence number, and every confirmed number is larger than the
one confirmed before it.

**How:** induction on the run. The start is an erased flash, which `mount_fits`. A confirmed
append is `append_ok`: it returns `latest + 1`, where `latest` is at least the previous
confirmed number, and leaves a fitting log. A cut is `append_preserves_latest`, after which
the remount fits by `mount_fits` (`cut_lengths` keeps the sectors' size). A remount changes no
flash and fits by `mount_fits`. -/
theorem trace_never_loses_confirmed (capacity : Nat) (hCapacity : 0 < capacity) :
    ∀ {events flash log confirmed}, Run capacity events flash log confirmed →
      Fits capacity log flash ∧ confirmed ≤ latestOf flash := by
  intro events flash log confirmed hRun
  induction hRun with
  | start =>
    exact ⟨mount_fits capacity _ (by simp [erasedSector]) (by simp [erasedSector]), Nat.zero_le _⟩
  | appendOk _ hStep ih =>
    obtain ⟨hFits, _⟩ := ih
    obtain ⟨hSequence, hLatest, hFits'⟩ := append_ok hFits hCapacity hStep
    exact ⟨hFits', by omega⟩
  | appendCut _ hStep ih =>
    obtain ⟨hFits, hConfirmed⟩ := ih
    have := append_preserves_latest hFits hStep
    obtain ⟨hZero, hOne⟩ := cut_lengths hFits hStep
    exact ⟨mount_fits capacity _ hZero hOne, by omega⟩
  | remount _ ih =>
    obtain ⟨hFits, hConfirmed⟩ := ih
    exact ⟨mount_fits capacity _ hFits.zeroLength hFits.oneLength, hConfirmed⟩

/-- **Proves:** a confirmed append returns a number strictly above the last confirmed one
(invariant 2: confirmed counters strictly increase across power loss).

**How:** `append_ok` says it returns `latest + 1`, and `trace_never_loses_confirmed` says the
in-memory `latest` (which fits the flash) is at least the last confirmed number. -/
theorem confirmed_strictly_increases (capacity : Nat) (hCapacity : 0 < capacity)
    {events flash log confirmed flash' sequence}
    (hRun : Run capacity events flash log confirmed)
    (hStep : AppendStep capacity log flash flash' (some sequence)) : confirmed < sequence := by
  obtain ⟨hFits, hConfirmed⟩ := trace_never_loses_confirmed capacity hCapacity hRun
  obtain ⟨hSequence, -, -⟩ := append_ok hFits hCapacity hStep
  have := hFits.latest
  omega

end Jotakey.RecordLog
