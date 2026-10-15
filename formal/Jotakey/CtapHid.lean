/-!
# CTAPHID reassembly

Formal model of the receive path of `crates/jotakey-core/src/transport/ctaphid.rs`
(`CtapHid::handle_packet`, `handle_cont`, `maybe_dispatch`).

Scope of the model: packets that carry a transaction (CBOR, PING, ...). Channel allocation
(`INIT`), `CANCEL` and the answer path are handled outside this state machine in the Rust
code too. In both, a delivered request is `busy` until the authenticator responds.

Results (invariants 4 and 5 of `AGENTS.md`):
* `step_isolated` / `run_isolated`: packets on other channels never change the state of the
  channel that owns the transaction.
* `step_wf`: buffers never exceed the announced length or `maxMsg`.
* `reassemble_fragment`: a message fragmented the way a host must fragment it is delivered
  intact: no byte lost, duplicated or reordered.
-/

namespace Jotakey.CtapHid

/-- `MAX_MSG_SIZE`. -/
def maxMsg : Nat := 1200
/-- Payload bytes in an init packet. -/
def initData : Nat := 57
/-- Payload bytes in a continuation packet. -/
def contData : Nat := 59

/-- A host→device packet, already split into fields. -/
inductive Pkt where
  | init (cid cmd bcnt : Nat) (data : List Nat)
  | cont (cid seq : Nat) (data : List Nat)

/-- Channel of a packet. -/
def Pkt.cid : Pkt → Nat
  | .init c _ _ _ => c
  | .cont c _ _ => c

/-- Receive state (`Rx` in Rust). -/
inductive Rx where
  | idle
  | receiving (cid cmd total : Nat) (buf : List Nat) (seq : Nat)
  | busy (cid : Nat) (msg : List Nat)
  deriving DecidableEq, Repr

/-- The channel that owns the current transaction, if any. -/
def Rx.owner : Rx → Option Nat
  | .idle => none
  | .receiving c _ _ _ _ => some c
  | .busy c _ => some c

/-- Deliver once all announced bytes are in (`maybe_dispatch`). -/
def settle (cid cmd total : Nat) (buf : List Nat) (seq : Nat) : Rx :=
  if buf.length < total then .receiving cid cmd total buf seq else .busy cid buf

/-- One packet (`handle_packet`). -/
def step : Rx → Pkt → Rx
  | .idle, .init c cmd bcnt d =>
    if bcnt > maxMsg then .idle else settle c cmd bcnt (d.take (min bcnt initData)) 0
  | .idle, .cont _ _ _ => .idle
  | .receiving o cmd total buf seq, .init c _ _ _ =>
    if c = o then .idle else .receiving o cmd total buf seq
  | .receiving o cmd total buf seq, .cont c sq d =>
    if c ≠ o then .receiving o cmd total buf seq
    else if sq ≠ seq then .idle
    else settle o cmd total (buf ++ d.take (min (total - buf.length) contData)) (seq + 1)
  | .busy o m, _ => .busy o m

/-- Feed a list of packets. -/
def run (s : Rx) (ps : List Pkt) : Rx := ps.foldl step s

/-! ## Isolation -/

theorem step_isolated (s : Rx) (p : Pkt) (o : Nat)
    (hown : s.owner = some o) (hcid : p.cid ≠ o) : step s p = s := by
  cases s with
  | idle => simp [Rx.owner] at hown
  | receiving c cmd total buf seq =>
    simp only [Rx.owner, Option.some.injEq] at hown
    subst hown
    cases p with
    | init c' _ _ _ => simp only [Pkt.cid] at hcid; simp [step, hcid]
    | cont c' _ _ => simp only [Pkt.cid] at hcid; simp [step, hcid]
  | busy c m => cases p <;> rfl

/-- **Channel isolation (invariant 5).** Any interleaving of packets from other channels
leaves the owner's transaction exactly as it was. -/
theorem run_isolated (s : Rx) (qs : List Pkt) (o : Nat)
    (hown : s.owner = some o) (hcids : ∀ q ∈ qs, q.cid ≠ o) : run s qs = s := by
  induction qs generalizing s with
  | nil => rfl
  | cons q qs ih =>
    simp only [run, List.foldl_cons]
    rw [step_isolated s q o hown (hcids q (by simp))]
    exact ih s hown (fun q' hq' => hcids q' (by simp [hq']))

/-! ## Well-formedness -/

/-- Buffers are bounded: a partial message is shorter than announced, the announced length
is at most `maxMsg`, and a delivered message fits in `maxMsg`. -/
def WF : Rx → Prop
  | .idle => True
  | .receiving _ _ total buf _ => buf.length < total ∧ total ≤ maxMsg
  | .busy _ m => m.length ≤ maxMsg

theorem settle_wf (cid cmd total : Nat) (buf : List Nat) (seq : Nat)
    (h1 : buf.length ≤ total) (h2 : total ≤ maxMsg) : WF (settle cid cmd total buf seq) := by
  unfold settle
  split
  · exact ⟨by assumption, h2⟩
  · show buf.length ≤ maxMsg; omega

/-- **Bounded memory (invariant 4).** Every step preserves `WF`. -/
theorem step_wf (s : Rx) (p : Pkt) (h : WF s) : WF (step s p) := by
  cases s with
  | idle =>
    cases p with
    | init c cmd bcnt d =>
      simp only [step]
      split
      · trivial
      · apply settle_wf
        · simp; omega
        · omega
    | cont => trivial
  | receiving o cmd total buf seq =>
    obtain ⟨h1, h2⟩ := h
    cases p with
    | init c _ _ _ =>
      simp only [step]
      split
      · trivial
      · exact ⟨h1, h2⟩
    | cont c sq d =>
      simp only [step]
      split
      · exact ⟨h1, h2⟩
      · split
        · trivial
        · apply settle_wf _ _ _ _ _ _ h2
          simp only [List.length_append, List.length_take]
          omega
  | busy => cases p <;> exact h

theorem run_wf (s : Rx) (ps : List Pkt) (h : WF s) : WF (run s ps) := by
  induction ps generalizing s with
  | nil => exact h
  | cons p ps ih => exact ih _ (step_wf s p h)

/-! ## Fragmentation and reassembly -/

/-- Continuation packets for `rest`, starting at sequence number `seq` (host side). -/
def conts (cid seq : Nat) (rest : List Nat) : List Pkt :=
  if h : rest = [] then []
  else .cont cid seq (rest.take contData) :: conts cid (seq + 1) (rest.drop contData)
  termination_by rest.length
  decreasing_by
    have : rest.length ≠ 0 := by simpa using h
    simp [contData]; omega

/-- How a host fragments a message on channel `cid` (CTAP 2.0 §8.1.4). -/
def fragment (cid cmd : Nat) (msg : List Nat) : List Pkt :=
  .init cid cmd msg.length (msg.take initData) :: conts cid 0 (msg.drop initData)

theorem take_take_min (l : List Nat) (n : Nat) : (l.take n).take (min l.length n) = l.take n := by
  rw [List.take_take]
  by_cases h : l.length ≤ n
  · rw [show min (min l.length n) n = l.length by omega, List.take_of_length_le (Nat.le_refl _),
      List.take_of_length_le h]
  · rw [show min (min l.length n) n = n by omega]

theorem conts_nil (cid seq : Nat) : conts cid seq [] = [] := by
  rw [conts]; simp

theorem run_conts (cid cmd seq : Nat) (msg buf rest : List Nat)
    (hmsg : buf ++ rest = msg) (hlt : buf.length < msg.length) :
    run (.receiving cid cmd msg.length buf seq) (conts cid seq rest) = .busy cid msg := by
  have hlen : msg.length = buf.length + rest.length := by rw [← hmsg, List.length_append]
  have hrest : rest ≠ [] := by
    intro h; subst h; simp at hlen; omega
  rw [conts]
  simp only [hrest, ↓reduceDIte]
  simp only [run, List.foldl_cons]
  have hstep : step (.receiving cid cmd msg.length buf seq) (.cont cid seq (rest.take contData)) =
      settle cid cmd msg.length (buf ++ rest.take contData) (seq + 1) := by
    simp only [step, ne_eq, not_true_eq_false, ↓reduceIte]
    have : msg.length - buf.length = rest.length := by omega
    rw [this, take_take_min]
  rw [hstep]
  unfold settle
  split
  · rename_i hbuf'
    have hfin : ¬ rest.length ≤ contData := by
      intro hle; simp only [List.length_append, List.length_take] at hbuf'; omega
    exact run_conts cid cmd (seq + 1) msg (buf ++ rest.take contData) (rest.drop contData)
      (by rw [List.append_assoc, List.take_append_drop]; exact hmsg) hbuf'
  · rename_i hbuf'
    have hfin : rest.length ≤ contData := by
      simp only [List.length_append, List.length_take] at hbuf'; omega
    rw [List.take_of_length_le hfin, hmsg, List.drop_eq_nil_of_le hfin, conts_nil]
    rfl
termination_by rest.length
decreasing_by
  all_goals (simp only [List.length_drop]; unfold contData at *;
             have : rest.length ≠ 0 := by simpa using hrest
             omega)

/-- **Reassembly is exact.** Any message of at most `maxMsg` bytes, fragmented on one channel the
way the host must fragment it, is delivered intact and in order. -/
theorem reassemble_fragment (cid cmd : Nat) (msg : List Nat)
    (hmax : msg.length ≤ maxMsg) :
    run .idle (fragment cid cmd msg) = .busy cid msg := by
  simp only [fragment, run, List.foldl_cons, step, show ¬ msg.length > maxMsg by omega,
    ↓reduceIte, take_take_min]
  unfold settle
  split
  · rename_i hbuf
    exact run_conts cid cmd 0 msg _ _ (List.take_append_drop _ _) hbuf
  · rename_i hbuf
    have hs : msg.length ≤ initData := by simp at hbuf; omega
    rw [List.take_of_length_le hs, List.drop_eq_nil_of_le hs, conts_nil]
    rfl

end Jotakey.CtapHid
