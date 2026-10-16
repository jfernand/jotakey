/-!
# CTAPHID reassembly

Formal model of the receive path of `crates/jotakey-core/src/transport/ctaphid.rs`
(`CtapHid::handle_packet`, `handle_cont`, `maybe_dispatch`).

Scope of the model: packets that carry a transaction (CBOR, PING, ...). Channel allocation
(`INIT`), `CANCEL` and the answer path are handled outside this state machine in the Rust
code too. In both, a delivered request is `busy` until the authenticator responds.

Results (invariants 4 and 5 of `AGENTS.md`):
* `receivePacket_ignores_other_channels` / `receivePackets_ignores_other_channels`: packets on
  other channels never change the state of the channel that owns the transaction.
* `receivePacket_preserves_well_formed`: buffers never exceed the announced length or
  `maxMessageSize`.
* `fragmented_message_is_reassembled`: a message fragmented the way a host must fragment it is
  delivered intact: no byte lost, duplicated or reordered.

Each theorem's doc comment says what it **proves** and **how**. *Syntax* comments
introduce notation not already explained in `Jotakey/Cbor/Heads.lean` and `Cbor.lean`.
-/

namespace Jotakey.CtapHid

/-- `MAX_MSG_SIZE`. -/
def maxMessageSize : Nat := 1200
/-- Payload bytes in an init packet. -/
def initPayloadSize : Nat := 57
/-- Payload bytes in a continuation packet. -/
def continuationPayloadSize : Nat := 59

/-- A host→device packet, already split into fields. -/
inductive Packet where
  -- Syntax: `inductive` declares a type by listing its constructors, like a Rust `enum`
  -- whose variants carry fields. A value is built as `Packet.init …`, or `.init …` where
  -- Lean already knows the expected type is `Packet`.
  | init (channel command announcedLength : Nat) (payload : List Nat)
  | continuation (channel sequence : Nat) (payload : List Nat)

/-- Channel of a packet. -/
def Packet.channel : Packet → Nat
  -- Syntax: naming a function `Packet.channel` puts it in the `Packet` namespace, so
  -- `p.channel` calls it for any `p : Packet`, like a method in an `impl` block.
  | .init channel _ _ _ => channel
  | .continuation channel _ _ => channel

/-- Receive state (`Rx` in Rust). -/
inductive ReceiveState where
  | idle
  /-- Part of a message has arrived on `channel`; `total` bytes were announced. -/
  | receiving (channel command total : Nat) (buffer : List Nat) (nextSequence : Nat)
  /-- A complete message is waiting for the authenticator. -/
  | busy (channel : Nat) (message : List Nat)
  deriving DecidableEq, Repr
  -- Syntax: `deriving` is Rust's `#[derive]`. `DecidableEq` gives a computable `==`
  -- (Rust's `PartialEq`), `Repr` a printable form (Rust's `Debug`).

/-- The channel that owns the current transaction, if any. -/
def ReceiveState.owner : ReceiveState → Option Nat
  | .idle => none
  | .receiving channel _ _ _ _ => some channel
  | .busy channel _ => some channel

/-- Deliver once all announced bytes are in (`maybe_dispatch`). -/
def deliverIfComplete (channel command total : Nat) (buffer : List Nat) (nextSequence : Nat) :
    ReceiveState :=
  if buffer.length < total then .receiving channel command total buffer nextSequence
  else .busy channel buffer

/-- One packet (`handle_packet`). -/
def receivePacket : ReceiveState → Packet → ReceiveState
  | .idle, .init channel command announcedLength payload =>
    if announcedLength > maxMessageSize then .idle
    else deliverIfComplete channel command announcedLength
      (payload.take (min announcedLength initPayloadSize)) 0
  | .idle, .continuation _ _ _ => .idle
  | .receiving owner command total buffer nextSequence, .init channel _ _ _ =>
    if channel = owner then .idle else .receiving owner command total buffer nextSequence
  | .receiving owner command total buffer nextSequence, .continuation channel sequence payload =>
    if channel ≠ owner then .receiving owner command total buffer nextSequence
    else if sequence ≠ nextSequence then .idle
    else deliverIfComplete owner command total
      (buffer ++ payload.take (min (total - buffer.length) continuationPayloadSize))
      (nextSequence + 1)
  | .busy owner message, _ => .busy owner message

/-- Feed a list of packets. -/
def receivePackets (state : ReceiveState) (packets : List Packet) : ReceiveState :=
  packets.foldl receivePacket state
-- Syntax: `packets.foldl receivePacket state` is Rust's
-- `packets.iter().fold(state, receive_packet)`: start from `state` and apply `receivePacket` to
-- each packet in turn.

/-! ## Isolation -/

/-- **Proves:** while channel `owner` owns a transaction, a single packet from any other
channel leaves the receive state exactly unchanged.

**How:** case analysis on the state. `idle` has no owner, so `hOwner` is false and the case
is impossible. In `receiving`, `hOwner` says the owner is the state's own channel; substitute
it, then for either kind of packet `receivePacket` first compares the packet's channel with
the owner, and `hOtherChannel` says they differ, so `simp` picks the "unchanged" branch. In
`busy`, `receivePacket` ignores every packet, so both sides are already equal (`rfl`). -/
theorem receivePacket_ignores_other_channels (state : ReceiveState) (packet : Packet)
    (owner : Nat) (hOwner : state.owner = some owner) (hOtherChannel : packet.channel ≠ owner) :
    receivePacket state packet = state := by
  cases state with
  -- Syntax: `cases state with | idle => … | receiving … => …` proves the goal separately for
  -- each constructor `state` could have been built with, naming the constructor's fields.
  | idle => simp [ReceiveState.owner] at hOwner
  | receiving channel command total buffer nextSequence =>
    simp only [ReceiveState.owner, Option.some.injEq] at hOwner
    subst hOwner
    -- Syntax: `subst h` with `h : x = y` (one side a variable) replaces that variable by the
    -- other side everywhere and drops `h`.
    cases packet with
    | init packetChannel _ _ _ =>
      simp only [Packet.channel] at hOtherChannel; simp [receivePacket, hOtherChannel]
    | continuation packetChannel _ _ =>
      simp only [Packet.channel] at hOtherChannel; simp [receivePacket, hOtherChannel]
  | busy channel message => cases packet <;> rfl
    -- Syntax: `t1 <;> t2` runs `t2` on every goal that `t1` produces (here: both packet kinds).

/-- **Channel isolation (invariant 5).** Any interleaving of packets from other channels
leaves the owner's transaction exactly as it was.

**Proves:** if channel `owner` owns the transaction and none of `packets` is on that channel,
then receiving all of them leaves the state unchanged. An attacker on another channel cannot
inject, drop, reorder or abort anything in the owner's message.

**How:** induction on the packet list. The first packet leaves `state` unchanged by
`receivePacket_ignores_other_channels`, so the rest of the list runs from the same `state`,
and the induction hypothesis (for the shorter list) finishes. -/
theorem receivePackets_ignores_other_channels (state : ReceiveState) (packets : List Packet)
    (owner : Nat) (hOwner : state.owner = some owner)
    (hOtherChannels : ∀ other ∈ packets, other.channel ≠ owner) :
    receivePackets state packets = state := by
  induction packets generalizing state with
  | nil => rfl
  | cons packet packets ih =>
    simp only [receivePackets, List.foldl_cons]
    rw [receivePacket_ignores_other_channels state packet owner hOwner
      (hOtherChannels packet (by simp))]
    exact ih state hOwner (fun other hMember => hOtherChannels other (by simp [hMember]))

/-! ## Well-formedness -/

/-- Buffers are bounded: a partial message is shorter than announced, the announced length
is at most `maxMessageSize`, and a delivered message fits in `maxMessageSize`. -/
def WellFormed : ReceiveState → Prop
  -- Syntax: a function returning `Prop` is a *predicate*: `WellFormed s` is a statement about
  -- `s` that may or may not be provable. `True` is the statement with a trivial proof.
  | .idle => True
  | .receiving _ _ total buffer _ => buffer.length < total ∧ total ≤ maxMessageSize
  | .busy _ message => message.length ≤ maxMessageSize

/-- **Proves:** `deliverIfComplete` produces a well-formed state from a buffer no longer than
the announced total, when that total is within `maxMessageSize`.

**How:** unfold and split the `if`. Still receiving: `buffer.length < total` is the branch
condition and `hTotal` is given. Delivered: `buffer.length ≤ total ≤ maxMessageSize`
(`omega`). -/
theorem deliverIfComplete_is_well_formed (channel command total : Nat) (buffer : List Nat)
    (nextSequence : Nat) (hBuffer : buffer.length ≤ total) (hTotal : total ≤ maxMessageSize) :
    WellFormed (deliverIfComplete channel command total buffer nextSequence) := by
  unfold deliverIfComplete
  split
  · exact ⟨by assumption, hTotal⟩
    -- Syntax: `assumption` closes the goal with any hypothesis of exactly that type (here the
    -- branch condition, which `split` added without a name).
  · show buffer.length ≤ maxMessageSize; omega
    -- Syntax: `show P` restates the goal in an equivalent form (here: what
    -- `WellFormed (.busy …)` unfolds to), so the next tactic sees the plain inequality.

/-- **Bounded memory (invariant 4).** Every packet preserves `WellFormed`.

**Proves:** if the state is well-formed, it is still well-formed after any packet, however
malformed or hostile.

**How:** case analysis on state × packet, following `receivePacket`:
* idle + init: rejected (back to `idle`) if the announced length exceeds `maxMessageSize`;
  otherwise the stored payload is `payload.take (min announcedLength 57)`, at most
  `announcedLength` long, so `deliverIfComplete_is_well_formed` applies;
* idle + continuation: stays `idle`;
* receiving + init: aborts to `idle` or leaves the state unchanged;
* receiving + continuation: other channel → unchanged; wrong sequence → `idle`; otherwise the
  bytes appended are cut to `total - buffer.length`, so the new buffer is at most `total`
  long and `deliverIfComplete_is_well_formed` applies;
* busy: unchanged. -/
theorem receivePacket_preserves_well_formed (state : ReceiveState) (packet : Packet)
    (hWellFormed : WellFormed state) : WellFormed (receivePacket state packet) := by
  cases state with
  | idle =>
    cases packet with
    | init channel command announcedLength payload =>
      simp only [receivePacket]
      split
      · trivial
        -- Syntax: `trivial` proves easy goals such as `True`.
      · apply deliverIfComplete_is_well_formed
        -- Syntax: `apply lemma` matches the goal with the lemma's conclusion and leaves its
        -- hypotheses (here `hBuffer`, `hTotal`) as new goals, solved by the `·` below.
        · simp; omega
        · omega
    | continuation => trivial
  | receiving owner command total buffer nextSequence =>
    obtain ⟨hShort, hTotal⟩ := hWellFormed
    cases packet with
    | init channel _ _ _ =>
      simp only [receivePacket]
      split
      · trivial
      · exact ⟨hShort, hTotal⟩
    | continuation channel sequence payload =>
      simp only [receivePacket]
      split
      · exact ⟨hShort, hTotal⟩
      · split
        · trivial
        · apply deliverIfComplete_is_well_formed _ _ _ _ _ _ hTotal
          simp only [List.length_append, List.length_take]
          omega
  | busy => cases packet <;> exact hWellFormed

/-- **Proves:** well-formedness holds after any sequence of packets.

**How:** induction on the packet list, applying `receivePacket_preserves_well_formed` at each
packet. -/
theorem receivePackets_preserves_well_formed (state : ReceiveState) (packets : List Packet)
    (hWellFormed : WellFormed state) : WellFormed (receivePackets state packets) := by
  induction packets generalizing state with
  | nil => exact hWellFormed
  | cons packet packets ih =>
    exact ih _ (receivePacket_preserves_well_formed state packet hWellFormed)

/-! ## Fragmentation and reassembly -/

/-- Continuation packets for `rest`, starting at sequence number `sequence` (host side). -/
def continuationPackets (channel sequence : Nat) (rest : List Nat) : List Packet :=
  -- Syntax: `if h : c then … else …` also names the condition: inside the branches, `h`
  -- proves `c` (or `¬c`). The termination proof below uses it.
  if hEmpty : rest = [] then []
  else .continuation channel sequence (rest.take continuationPayloadSize) ::
    continuationPackets channel (sequence + 1) (rest.drop continuationPayloadSize)
  termination_by rest.length
  decreasing_by
    -- Syntax: `decreasing_by` proves by hand that the measure shrinks at the recursive
    -- call: `(rest.drop 59).length < rest.length`, true because `rest` is not empty.
    have : rest.length ≠ 0 := by simpa using hEmpty
    simp [continuationPayloadSize]; omega

/-- How a host fragments a message on `channel` (CTAP 2.0 §8.1.4). -/
def fragmentMessage (channel command : Nat) (message : List Nat) : List Packet :=
  .init channel command message.length (message.take initPayloadSize) ::
    continuationPackets channel 0 (message.drop initPayloadSize)

/-- **Proves:** `(bytes.take n).take (min bytes.length n) = bytes.take n`. The device cuts
each payload to `min (bytes still expected) 59`; this lemma says that cut removes nothing
from a packet the host built with `take 59`.

**How:** `List.take_take` merges the two `take`s into `take (min (min bytes.length n) n)`.
If `bytes.length ≤ n` that is `take bytes.length`, the whole list, as is `take n`; otherwise
it is `take n` directly. -/
theorem trimming_keeps_host_payload (bytes : List Nat) (n : Nat) :
    (bytes.take n).take (min bytes.length n) = bytes.take n := by
  rw [List.take_take]
  by_cases hShort : bytes.length ≤ n
  · rw [show min (min bytes.length n) n = bytes.length by omega,
      List.take_of_length_le (Nat.le_refl _), List.take_of_length_le hShort]
    -- Syntax: `show P by tac` (inside `rw [...]`) proves an equation on the spot and uses
    -- it as a rewrite rule.
  · rw [show min (min bytes.length n) n = n by omega]

/-- **Proves:** an empty remainder needs no continuation packets.
**How:** unfold `continuationPackets` once; its `if rest = []` is true. -/
theorem continuationPackets_of_empty (channel sequence : Nat) :
    continuationPackets channel sequence [] = [] := by
  rw [continuationPackets]; simp

/-- **Proves:** the heart of reassembly. Suppose the device is in the middle of receiving
`message` on `channel`: it holds `buffer`, the bytes still to come are `rest`
(`buffer ++ rest = message`), and the message is not complete yet. Then the continuation
packets the host sends for `rest`, starting at the expected sequence number, take the device
to `busy channel message`: exactly the host's message.

**How:** this proof is *recursive*: it calls itself, which is how Lean writes induction
over something other than a plain list or number. `termination_by rest.length` says the
recursive call is on a shorter `rest`, which makes it a valid induction.
1. `rest` is not empty, since `buffer` is shorter than `message`, so `continuationPackets`
   emits a first packet carrying `rest.take 59`.
2. The device appends that payload, cut to the remaining length; `trimming_keeps_host_payload`
   shows the cut changes nothing (`hFirstPacket`).
3. If the buffer is still short of `message.length`, the rest of the packets are exactly the
   continuation packets for `rest.drop 59` with the next sequence number: the recursive
   call (the induction hypothesis) finishes.
4. Otherwise `rest` fitted in this one packet: the buffer is now `buffer ++ rest = message`,
   no packets remain (`continuationPackets_of_empty`) and the state is `busy channel message`. -/
theorem continuations_complete_message (channel command sequence : Nat)
    (message buffer rest : List Nat)
    (hSplit : buffer ++ rest = message) (hIncomplete : buffer.length < message.length) :
    receivePackets (.receiving channel command message.length buffer sequence)
      (continuationPackets channel sequence rest) = .busy channel message := by
  have hLength : message.length = buffer.length + rest.length := by
    rw [← hSplit, List.length_append]
  -- Syntax: `rw [← h]` rewrites with `h` right-to-left.
  have hRestNonEmpty : rest ≠ [] := by
    intro hEmpty; subst hEmpty; simp at hLength; omega
    -- Syntax: to prove `a ≠ b` (that is, `a = b → False`), `intro h` assumes `h : a = b`
    -- and the goal becomes `False`; `omega` then finds the contradiction.
  rw [continuationPackets]
  simp only [hRestNonEmpty, ↓reduceDIte]
  -- `↓reduceDIte` is `↓reduceIte` for the `if h : …` form.
  simp only [receivePackets, List.foldl_cons]
  have hFirstPacket :
      receivePacket (.receiving channel command message.length buffer sequence)
        (.continuation channel sequence (rest.take continuationPayloadSize)) =
      deliverIfComplete channel command message.length
        (buffer ++ rest.take continuationPayloadSize) (sequence + 1) := by
    simp only [receivePacket, ne_eq, not_true_eq_false, ↓reduceIte]
    have : message.length - buffer.length = rest.length := by omega
    rw [this, trimming_keeps_host_payload]
  rw [hFirstPacket]
  unfold deliverIfComplete
  split
  · rename_i hStillShort
    -- Syntax: `rename_i h` gives a name to the newest unnamed hypothesis (here the branch
    -- condition from `split`).
    have hMoreThanOnePacket : ¬ rest.length ≤ continuationPayloadSize := by
      intro hFits; simp only [List.length_append, List.length_take] at hStillShort; omega
    exact continuations_complete_message channel command (sequence + 1) message
      (buffer ++ rest.take continuationPayloadSize) (rest.drop continuationPayloadSize)
      (by rw [List.append_assoc, List.take_append_drop]; exact hSplit) hStillShort
      -- The recursive call: the induction hypothesis for the shorter remainder.
  · rename_i hComplete
    have hOnePacket : rest.length ≤ continuationPayloadSize := by
      simp only [List.length_append, List.length_take] at hComplete; omega
    rw [List.take_of_length_le hOnePacket, hSplit, List.drop_eq_nil_of_le hOnePacket,
      continuationPackets_of_empty]
    rfl
termination_by rest.length
decreasing_by
  all_goals (simp only [List.length_drop]; unfold continuationPayloadSize at *;
             have : rest.length ≠ 0 := by simpa using hRestNonEmpty
             omega)

/-- **Reassembly is exact.** Any message of at most `maxMessageSize` bytes, fragmented on one
channel the way the host must fragment it, is delivered intact and in order.

**Proves:** starting idle, receiving the packets of `fragmentMessage channel command message`
ends in `busy channel message`: the device holds exactly `message`, ready to dispatch.

**How:** the init packet is accepted because `message.length ≤ maxMessageSize`, and the device
stores its payload `message.take 57` (`trimming_keeps_host_payload` again). If that was the
whole message, `deliverIfComplete` delivers it and no continuation packets follow. Otherwise
the device is receiving with `buffer = message.take 57` and `rest = message.drop 57`, which is
exactly the situation of `continuations_complete_message`. -/
theorem fragmented_message_is_reassembled (channel command : Nat) (message : List Nat)
    (hMaxSize : message.length ≤ maxMessageSize) :
    receivePackets .idle (fragmentMessage channel command message) = .busy channel message := by
  simp only [fragmentMessage, receivePackets, List.foldl_cons, receivePacket,
    show ¬ message.length > maxMessageSize by omega, ↓reduceIte, trimming_keeps_host_payload]
  unfold deliverIfComplete
  split
  · rename_i hStillShort
    exact continuations_complete_message channel command 0 message _ _
      (List.take_append_drop _ _) hStillShort
  · rename_i hComplete
    have hOnePacket : message.length ≤ initPayloadSize := by simp at hComplete; omega
    rw [List.take_of_length_le hOnePacket, List.drop_eq_nil_of_le hOnePacket,
      continuationPackets_of_empty]
    rfl

end Jotakey.CtapHid
