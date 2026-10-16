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

Each theorem's doc comment says what it **proves** and **how**. *Syntax* comments
introduce notation not already explained in `Jotakey/Cbor/Heads.lean` and `Cbor.lean`.
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
  -- Syntax: `inductive` declares a type by listing its constructors, like a Rust `enum`
  -- whose variants carry fields. A value is built as `Pkt.init c cmd n d`, or `.init c cmd n d`
  -- where Lean already knows the expected type is `Pkt`.
  | init (cid cmd bcnt : Nat) (data : List Nat)
  | cont (cid seq : Nat) (data : List Nat)

/-- Channel of a packet. -/
def Pkt.cid : Pkt → Nat
  -- Syntax: naming a function `Pkt.cid` puts it in the `Pkt` namespace, so `p.cid` calls it
  -- for any `p : Pkt`, like a method in an `impl` block.
  | .init c _ _ _ => c
  | .cont c _ _ => c

/-- Receive state (`Rx` in Rust). -/
inductive Rx where
  | idle
  | receiving (cid cmd total : Nat) (buf : List Nat) (seq : Nat)
  | busy (cid : Nat) (msg : List Nat)
  deriving DecidableEq, Repr
  -- Syntax: `deriving` is Rust's `#[derive]`. `DecidableEq` gives a computable `==`
  -- (Rust's `PartialEq`), `Repr` a printable form (Rust's `Debug`).

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
-- Syntax: `ps.foldl step s` is Rust's `ps.iter().fold(s, step)`: start from `s` and apply
-- `step` to each packet in turn.

/-! ## Isolation -/

/-- **Proves:** while channel `o` owns a transaction, a single packet from any other channel
leaves the receive state exactly unchanged (`step s p = s`).

**How:** case analysis on the state. `idle` has no owner, so `hown` is false and the case
is impossible. In `receiving`, `hown` says the owner is the state's own `cid`; substitute
it, then for either kind of packet `step` first compares the packet's channel with the
owner, and `hcid` says they differ, so `simp` picks the "unchanged" branch. In `busy`,
`step` ignores every packet, so both sides are already equal (`rfl`). -/
theorem step_isolated (s : Rx) (p : Pkt) (o : Nat)
    (hown : s.owner = some o) (hcid : p.cid ≠ o) : step s p = s := by
  cases s with
  -- Syntax: `cases s with | idle => … | receiving … => …` proves the goal separately for
  -- each constructor `s` could have been built with, naming the constructor's fields.
  | idle => simp [Rx.owner] at hown
  | receiving c cmd total buf seq =>
    simp only [Rx.owner, Option.some.injEq] at hown
    subst hown
    -- Syntax: `subst h` with `h : x = y` (one side a variable) replaces that variable by the
    -- other side everywhere and drops `h`.
    cases p with
    | init c' _ _ _ => simp only [Pkt.cid] at hcid; simp [step, hcid]
    | cont c' _ _ => simp only [Pkt.cid] at hcid; simp [step, hcid]
  | busy c m => cases p <;> rfl
    -- Syntax: `t1 <;> t2` runs `t2` on every goal that `t1` produces (here: both packet kinds).

/-- **Channel isolation (invariant 5).** Any interleaving of packets from other channels
leaves the owner's transaction exactly as it was.

**Proves:** if channel `o` owns the transaction and none of the packets `qs` is on channel
`o`, then running all of them leaves the state unchanged: `run s qs = s`. An attacker on
another channel cannot inject, drop, reorder or abort anything in `o`'s message.

**How:** induction on the packet list. The first packet leaves `s` unchanged by
`step_isolated`, so the rest of the list runs from the same `s`, and the induction
hypothesis (for the shorter list) finishes. -/
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
  -- Syntax: a function returning `Prop` is a *predicate*: `WF s` is a statement about `s`
  -- that may or may not be provable. `True` is the statement with a trivial proof.
  | .idle => True
  | .receiving _ _ total buf _ => buf.length < total ∧ total ≤ maxMsg
  | .busy _ m => m.length ≤ maxMsg

/-- **Proves:** `settle` produces a well-formed state from a buffer no longer than the
announced total, when that total is within `maxMsg`.

**How:** unfold and split the `if`. Still receiving: `buf.length < total` is the branch
condition and `h2` is given. Delivered: `buf.length ≤ total ≤ maxMsg` (`omega`). -/
theorem settle_wf (cid cmd total : Nat) (buf : List Nat) (seq : Nat)
    (h1 : buf.length ≤ total) (h2 : total ≤ maxMsg) : WF (settle cid cmd total buf seq) := by
  unfold settle
  split
  · exact ⟨by assumption, h2⟩
    -- Syntax: `assumption` closes the goal with any hypothesis of exactly that type (here the
    -- branch condition, which `split` added without a name).
  · show buf.length ≤ maxMsg; omega
    -- Syntax: `show P` restates the goal in an equivalent form (here: what `WF (.busy …)`
    -- unfolds to), so the next tactic sees the plain inequality.

/-- **Bounded memory (invariant 4).** Every step preserves `WF`.

**Proves:** if the state is well-formed, it is still well-formed after any packet, however
malformed or hostile.

**How:** case analysis on state × packet, following `step`:
* idle + init: rejected (back to `idle`) if the announced length exceeds `maxMsg`;
  otherwise the stored payload is `d.take (min bcnt 57)`, at most `bcnt` long, so
  `settle_wf` applies;
* idle + cont: stays `idle`;
* receiving + init: aborts to `idle` or leaves the state unchanged;
* receiving + cont: other channel → unchanged; wrong sequence → `idle`; otherwise the bytes
  appended are cut to `total - buf.length`, so the new buffer is at most `total` long and
  `settle_wf` applies;
* busy: unchanged. -/
theorem step_wf (s : Rx) (p : Pkt) (h : WF s) : WF (step s p) := by
  cases s with
  | idle =>
    cases p with
    | init c cmd bcnt d =>
      simp only [step]
      split
      · trivial
        -- Syntax: `trivial` proves easy goals such as `True`.
      · apply settle_wf
        -- Syntax: `apply lemma` matches the goal with the lemma's conclusion and leaves its
        -- hypotheses (here `h1`, `h2` of `settle_wf`) as new goals, solved by the `·` below.
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

/-- **Proves:** well-formedness holds after any sequence of packets.

**How:** induction on the packet list, applying `step_wf` at each packet. -/
theorem run_wf (s : Rx) (ps : List Pkt) (h : WF s) : WF (run s ps) := by
  induction ps generalizing s with
  | nil => exact h
  | cons p ps ih => exact ih _ (step_wf s p h)

/-! ## Fragmentation and reassembly -/

/-- Continuation packets for `rest`, starting at sequence number `seq` (host side). -/
def conts (cid seq : Nat) (rest : List Nat) : List Pkt :=
  -- Syntax: `if h : c then … else …` also names the condition: inside the branches, `h`
  -- proves `c` (or `¬c`). The termination proof below uses it.
  if h : rest = [] then []
  else .cont cid seq (rest.take contData) :: conts cid (seq + 1) (rest.drop contData)
  termination_by rest.length
  decreasing_by
    -- Syntax: `decreasing_by` proves by hand that the measure shrinks at the recursive
    -- call: `(rest.drop 59).length < rest.length`, true because `rest` is not empty.
    have : rest.length ≠ 0 := by simpa using h
    simp [contData]; omega

/-- How a host fragments a message on channel `cid` (CTAP 2.0 §8.1.4). -/
def fragment (cid cmd : Nat) (msg : List Nat) : List Pkt :=
  .init cid cmd msg.length (msg.take initData) :: conts cid 0 (msg.drop initData)

/-- **Proves:** `(l.take n).take (min l.length n) = l.take n`. The device cuts each payload to
`min (bytes still expected) 59`; this lemma says that cut removes nothing from a packet the
host built with `take 59`.

**How:** `List.take_take` merges the two `take`s into `take (min (min l.length n) n)`. If
`l.length ≤ n` that is `take l.length`, the whole list, as is `take n`; otherwise it is
`take n` directly. -/
theorem take_take_min (l : List Nat) (n : Nat) : (l.take n).take (min l.length n) = l.take n := by
  rw [List.take_take]
  by_cases h : l.length ≤ n
  · rw [show min (min l.length n) n = l.length by omega, List.take_of_length_le (Nat.le_refl _),
      List.take_of_length_le h]
    -- Syntax: `show P by tac` (inside `rw [...]`) proves an equation on the spot and uses
    -- it as a rewrite rule.
  · rw [show min (min l.length n) n = n by omega]

/-- **Proves:** an empty remainder needs no continuation packets.
**How:** unfold `conts` once; its `if rest = []` is true. -/
theorem conts_nil (cid seq : Nat) : conts cid seq [] = [] := by
  rw [conts]; simp

/-- **Proves:** the heart of reassembly. Suppose the device is in the middle of receiving `msg`
on `cid`: it holds `buf`, the bytes still to come are `rest` (`buf ++ rest = msg`), and the
message is not complete yet. Then the continuation packets the host sends for `rest`,
starting at the expected sequence number, take the device to `busy cid msg`: exactly the
host's message.

**How:** this proof is *recursive*: it calls itself, which is how Lean writes induction
over something other than a plain list or number. `termination_by rest.length` says the
recursive call is on a shorter `rest`, which makes it a valid induction.
1. `rest` is not empty, since `buf` is shorter than `msg`, so `conts` emits a first packet
   carrying `rest.take 59`.
2. The device appends that payload, cut to the remaining length; `take_take_min` shows the
   cut changes nothing (`hstep`).
3. If the buffer is still short of `msg.length`, the rest of the packets are exactly the
   continuation packets for `rest.drop 59` with the next sequence number: the recursive
   call (the induction hypothesis) finishes.
4. Otherwise `rest` fitted in this one packet: the buffer is now `buf ++ rest = msg`, no
   packets remain (`conts_nil`) and the state is `busy cid msg`. -/
theorem run_conts (cid cmd seq : Nat) (msg buf rest : List Nat)
    (hmsg : buf ++ rest = msg) (hlt : buf.length < msg.length) :
    run (.receiving cid cmd msg.length buf seq) (conts cid seq rest) = .busy cid msg := by
  have hlen : msg.length = buf.length + rest.length := by rw [← hmsg, List.length_append]
  -- Syntax: `rw [← h]` rewrites with `h` right-to-left.
  have hrest : rest ≠ [] := by
    intro h; subst h; simp at hlen; omega
    -- Syntax: to prove `a ≠ b` (that is, `a = b → False`), `intro h` assumes `h : a = b`
    -- and the goal becomes `False`; `omega` then finds the contradiction.
  rw [conts]
  simp only [hrest, ↓reduceDIte]
  -- `↓reduceDIte` is `↓reduceIte` for the `if h : …` form.
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
    -- Syntax: `rename_i h` gives a name to the newest unnamed hypothesis (here the branch
    -- condition from `split`).
    have hfin : ¬ rest.length ≤ contData := by
      intro hle; simp only [List.length_append, List.length_take] at hbuf'; omega
    exact run_conts cid cmd (seq + 1) msg (buf ++ rest.take contData) (rest.drop contData)
      (by rw [List.append_assoc, List.take_append_drop]; exact hmsg) hbuf'
      -- The recursive call: the induction hypothesis for the shorter remainder.
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
way the host must fragment it, is delivered intact and in order.

**Proves:** starting idle, running the packets of `fragment cid cmd msg` ends in
`busy cid msg`: the device holds exactly `msg`, ready to dispatch.

**How:** the init packet is accepted because `msg.length ≤ maxMsg`, and the device stores
its payload `msg.take 57` (`take_take_min` again). If that was the whole message, `settle`
delivers it and no continuation packets follow. Otherwise the device is receiving with
`buf = msg.take 57` and `rest = msg.drop 57`, which is exactly the situation of
`run_conts`. -/
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
