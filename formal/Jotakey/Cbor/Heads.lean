/-!
# CBOR heads

Formal model of the head functions of `crates/jotakey-core/src/cbor.rs`:
`encodeHead` / `decodeHead` mirror `Encoder::head` / `Decoder::head`.

Bytes are modelled as `Nat`s. Theorems that need it assume every element is `< 256`.

Main results:
* `decodeHead_encodeHead`: decoding an encoded head gives back exactly what was encoded.
* `encodeHead_of_decodeHead`: **canonical uniqueness**. If the decoder accepts some bytes,
  they are exactly the encoding of the decoded value. No head has two accepted encodings,
  so two parsers that implement this model can never disagree about a message.
* `decodeHead_shrinks`: every accepted head consumes input, so the decoder always
  terminates.
-/

namespace Jotakey.Cbor

/-! ## Big-endian integers

Defined through little-endian lists and `reverse` so that every proof is a plain list
induction. -/

/-- `toLE k n`: the low `k` bytes of `n`, least significant first. -/
def toLE : Nat → Nat → List Nat
  | 0,     _ => []
  | k + 1, n => n % 256 :: toLE k (n / 256) -- :: puts an element in front of a list

#guard toLE 2 1000 == [232, 3]
#guard toLE 4 1000 == [232, 3, 0, 0]

/-- Interpret a byte list as a little-endian number. -/
def fromLE : List Nat → Nat
  | [] => 0
  | b :: t => b + 256 * fromLE t

#guard fromLE [232, 3] == 1000

/-- `toBE k n`: the low `k` bytes of `n`, most significant first. -/
def toBE (k n : Nat) : List Nat := (toLE k n).reverse

#guard toBE 2 1000 == [3, 232]
#guard toBE 4 1000 == [0, 0, 3, 232]

/-- Interpret a byte list as a big-endian number. -/
def fromBE (l : List Nat) : Nat := fromLE l.reverse

/-- Prove that the length of the list returned by toLE is k.
    `induction k` introduces two goals; `generalizing n` makes the induction hypothesis
    hold for every n, not just the n we started with:
    zero case: (toLE 0 n).length = 0
    succ k ih case: (toLE (k+1) n).length = k + 1, with ih : ∀ n, (toLE k n).length = k -/
theorem length_toLE (k n : Nat) : (toLE k n).length = k := by
  induction k generalizing n with
  | zero => rfl -- (toLE 0 n).length is 0 by the base case
  | succ k ih => simp [toLE, ih] -- toLE (k+1) n = n % 256 :: toLE k (n / 256), so its length is
                                 -- (toLE k (n / 256)).length + 1. ih applied to n / 256 rewrites
                                 -- that to k + 1, leaving k + 1 = k + 1.

/-- Prove that the length of a list returned by toBE is k -/
theorem length_toBE (k n : Nat) : (toBE k n).length = k := by
  simp [toBE, length_toLE]

/-- Prove that converting a number to LE and back yields the same number -/
theorem fromLE_toLE (k n : Nat) (h : n < 256 ^ k) : fromLE (toLE k n) = n := by -- round trip only works if n < 256 ^ k
  induction k generalizing n with
  | zero => simp [toLE, fromLE]; omega
  | succ k ih =>
    have hk : n / 256 < 256 ^ k := by
      rw [Nat.pow_succ] at h
      exact (Nat.div_lt_iff_lt_mul (by decide)).mpr h
    simp only [toLE, fromLE, ih _ hk]
    omega

/-- Prove that converting a number to BE and back yields the same number -/
theorem fromBE_toBE (k n : Nat) (h : n < 256 ^ k) : fromBE (toBE k n) = n := by
  simp [fromBE, toBE, fromLE_toLE k n h]

/-- Prove that the number returned by fromLE l is < 256 ^ l.length.
    We need it further down (`fromBE_take_lt`): the argument bytes the decoder reads always
    give a number that fits back into the same number of bytes, so re-encoding it loses
    nothing (`encodeHead_of_decodeHead`). -/
theorem fromLE_lt (l : List Nat) (hb : ∀ b ∈ l, b < 256) : fromLE l < (256 ^ l.length) := by -- hb restricts the elements of l from Nats to bytes
  induction l with
  | nil => simp [fromLE]
  | cons b t ih =>
    have h1 := ih (fun x hx => hb x (by simp [hx]))
    have h2 : b < 256 := hb b (by simp)
    simp only [fromLE, List.length_cons, Nat.pow_succ]
    have : 256 * fromLE t + 256 ≤ 256 * 256 ^ t.length := by
      have := Nat.mul_le_mul_left 256 h1
      omega
    rw [Nat.mul_comm (256 ^ t.length)]
    omega

/-- Prove that the number returned by fromBE l is < 256 ^ l.length -/
theorem fromBE_lt (l : List Nat) (hb : ∀ b ∈ l, b < 256) : fromBE l < 256 ^ l.length := by
  have := fromLE_lt l.reverse (fun b h => hb b (List.mem_reverse.mp h))
  simpa [fromBE] using this

/-- Prove that converting an LE list to a number and back yields the same list.
    A property test only checks the inputs it happens to generate; this proof covers every
    byte list. We have both: `accepted_heads_are_canonical` in `cbor.rs` is the Rust property
    test (decode random bytes, re-encode, compare), and the differential test ties the Rust
    decoder to this model. -/
theorem toLE_fromLE (l : List Nat) (hb : ∀ b ∈ l, b < 256) : toLE l.length (fromLE l) = l := by
  induction l with
  | nil => rfl
  | cons b t ih =>
    have h2 : b < 256 := hb b (by simp)
    have ih' := ih (fun x hx => hb x (by simp [hx]))
    simp only [List.length_cons, toLE, fromLE]
    have e1 : (b + 256 * fromLE t) % 256 = b := by omega
    have e2 : (b + 256 * fromLE t) / 256 = fromLE t := by omega
    rw [e1, e2, ih']

/-- Prove that converting a BE list to a number and back yields the same list -/
theorem toBE_fromBE (l : List Nat) (hb : ∀ b ∈ l, b < 256) : toBE l.length (fromBE l) = l := by
  have := toLE_fromLE l.reverse (fun b h => hb b (List.mem_reverse.mp h))
  simp only [List.length_reverse] at this
  simp [toBE, fromBE, this]

/-! ## Heads

A head is the first 1–9 bytes of every CBOR data item. The initial byte holds the _major_
type in its top 3 bits and the additional _info_ in its low 5 bits: `ib = major * 32 + info`.
The _argument_ (an integer value, a length or a count, depending on the major type) is:
* info < 24: the info value itself (immediate, no further bytes);
* info 24, 25, 26, 27: the next 1, 2, 4 or 8 bytes, big-endian;
* info 28‥30: reserved, rejected; info 31: indefinite length, rejected by our strict decoder. -/

/-- Largest argument representable in a head (64-bit). -/
def argLimit : Nat := 2 ^ 64

/-- Shortest-form head for `major` (0‥7, it must fit in 3 bits) and `arg` (< 2⁶⁴), as
`Encoder::head` emits it. -/
def encodeHead (major arg : Nat) : List Nat :=
  if arg < 24 then [major * 32 + arg]
  else if arg < 2 ^ 8 then (major * 32 + 24) :: toBE 1 arg
  else if arg < 2 ^ 16 then (major * 32 + 25) :: toBE 2 arg
  else if arg < 2 ^ 32 then (major * 32 + 26) :: toBE 4 arg
  else (major * 32 + 27) :: toBE 8 arg

/-- Read a `k`-byte big-endian argument, rejecting it unless it is `≥ lo` (minimality). -/
def readArg (k lo : Nat) (l : List Nat) : Option (Nat × List Nat) :=
  if l.length < k then none
  else if fromBE (l.take k) < lo then none
  else some (fromBE (l.take k), l.drop k)

/-- `Decoder::head`: `(major, argument, rest)` or `none`.

Rejects: empty input, floats/extended simple values (major 7, info 24‥27), non-minimal
arguments, reserved info 28‥30 and indefinite lengths (31). -/
def decodeHead : List Nat → Option (Nat × Nat × List Nat)
  | [] => none
  | ib :: rest =>
    let major := ib / 32
    let info := ib % 32
    if major = 7 ∧ 24 ≤ info ∧ info ≤ 27 then none
    else if info < 24 then some (major, info, rest)
    else if info = 24 then (readArg 1 24 rest).map fun (v, r) => (major, v, r)
    else if info = 25 then (readArg 2 (2 ^ 8) rest).map fun (v, r) => (major, v, r)
    else if info = 26 then (readArg 4 (2 ^ 16) rest).map fun (v, r) => (major, v, r)
    else if info = 27 then (readArg 8 (2 ^ 32) rest).map fun (v, r) => (major, v, r)
    else none

theorem readArg_toBE (k lo v : Nat) (rest : List Nat) (hlo : lo ≤ v) (hv : v < 256 ^ k) :
    readArg k lo (toBE k v ++ rest) = some (v, rest) := by
  have hlen := length_toBE k v
  have htake : (toBE k v ++ rest).take k = toBE k v := by
    rw [List.take_append_of_le_length (by omega), List.take_of_length_le (by omega)]
  have hdrop : (toBE k v ++ rest).drop k = rest := by
    rw [List.drop_append_of_le_length (by omega), List.drop_of_length_le (by omega)]
    simp
  simp only [readArg, List.length_append, hlen, htake, fromBE_toBE k v hv, hdrop]
  simp
  omega

/-- **Round trip.** For data-carrying major types (0‥6) and any 64-bit argument, decoding
the encoded head returns the major type, the argument and the untouched remainder. -/
theorem decodeHead_encodeHead (major arg : Nat) (rest : List Nat)
    (hm : major < 7) (ha : arg < argLimit) : -- 0 ≤ major ≤ 6: the decoder rejects major 7
                                              -- with info 24‥27 (floats)
    decodeHead (encodeHead major arg ++ rest) = some (major, arg, rest) := by
  unfold encodeHead argLimit at *
  by_cases h0 : arg < 24
  · simp only [h0, ↓reduceIte, List.singleton_append, decodeHead]
    have e1 : (major * 32 + arg) / 32 = major := by omega
    have e2 : (major * 32 + arg) % 32 = arg := by omega
    simp [e1, e2, h0]
    omega
  by_cases h1 : arg < 2 ^ 8
  · simp only [h0, h1, ↓reduceIte, ↓reduceIte, List.cons_append, decodeHead]
    have e1 : (major * 32 + 24) / 32 = major := by omega
    have e2 : (major * 32 + 24) % 32 = 24 := by omega
    simp only [e1, e2]
    rw [readArg_toBE 1 24 arg rest (by omega) (by simpa using h1)]
    simp; omega
  by_cases h2 : arg < 2 ^ 16
  · simp only [h0, h1, h2, ↓reduceIte, ↓reduceIte, List.cons_append, decodeHead]
    have e1 : (major * 32 + 25) / 32 = major := by omega
    have e2 : (major * 32 + 25) % 32 = 25 := by omega
    simp only [e1, e2]
    rw [readArg_toBE 2 (2 ^ 8) arg rest (by omega) (by simpa using h2)]
    simp; omega
  by_cases h4 : arg < 2 ^ 32
  · simp only [h0, h1, h2, h4, ↓reduceIte, ↓reduceIte, List.cons_append, decodeHead]
    have e1 : (major * 32 + 26) / 32 = major := by omega
    have e2 : (major * 32 + 26) % 32 = 26 := by omega
    simp only [e1, e2]
    rw [readArg_toBE 4 (2 ^ 16) arg rest (by omega) (by simpa using h4)]
    simp; omega
  · simp only [h0, h1, h2, h4, ↓reduceIte, List.cons_append, decodeHead]
    have e1 : (major * 32 + 27) / 32 = major := by omega
    have e2 : (major * 32 + 27) % 32 = 27 := by omega
    simp only [e1, e2]
    rw [readArg_toBE 8 (2 ^ 32) arg rest (by omega) (by simpa using ha)]
    simp; omega

theorem readArg_spec {k lo : Nat} {l : List Nat} {v : Nat} {r : List Nat}
    (h : readArg k lo l = some (v, r)) :
    k ≤ l.length ∧ lo ≤ v ∧ v = fromBE (l.take k) ∧ r = l.drop k := by
  unfold readArg at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      refine ⟨by omega, by omega, rfl, rfl⟩

/-- Re-encoding the first `k` bytes of a byte list gives them back. -/
theorem take_bytes_eq (tl : List Nat) (k : Nat) (hk : k ≤ tl.length) (hb : ∀ b ∈ tl, b < 256) :
    toBE k (fromBE (tl.take k)) ++ tl.drop k = tl := by
  have h1 : (tl.take k).length = k := by simp; omega
  have h2 := toBE_fromBE (tl.take k) (fun b hb' => hb b (List.mem_of_mem_take hb'))
  rw [h1] at h2
  rw [h2, List.take_append_drop]

theorem fromBE_take_lt (tl : List Nat) (k : Nat) (hk : k ≤ tl.length) (hb : ∀ b ∈ tl, b < 256) :
    fromBE (tl.take k) < 256 ^ k := by
  have h1 : (tl.take k).length = k := by simp; omega
  have := fromBE_lt (tl.take k) (fun b hb' => hb b (List.mem_of_mem_take hb'))
  rwa [h1] at this

theorem encodeHead_w1 (m a : Nat) (h1 : 24 ≤ a) (h2 : a < 2 ^ 8) :
    encodeHead m a = (m * 32 + 24) :: toBE 1 a := by
  unfold encodeHead; repeat' split
  all_goals first | rfl | omega

theorem encodeHead_w2 (m a : Nat) (h1 : 2 ^ 8 ≤ a) (h2 : a < 2 ^ 16) :
    encodeHead m a = (m * 32 + 25) :: toBE 2 a := by
  unfold encodeHead; repeat' split
  all_goals first | rfl | omega

theorem encodeHead_w4 (m a : Nat) (h1 : 2 ^ 16 ≤ a) (h2 : a < 2 ^ 32) :
    encodeHead m a = (m * 32 + 26) :: toBE 4 a := by
  unfold encodeHead; repeat' split
  all_goals first | rfl | omega

theorem encodeHead_w8 (m a : Nat) (h1 : 2 ^ 32 ≤ a) :
    encodeHead m a = (m * 32 + 27) :: toBE 8 a := by
  unfold encodeHead; repeat' split
  all_goals first | rfl | omega

/-- Shape of an accepted extended-width head. -/
theorem decodeHead_ext {k lo : Nat} {ib : Nat} {tl : List Nat} {major arg : Nat} {rest : List Nat}
    (h : (readArg k lo tl).map (fun (v, r) => (ib / 32, v, r)) = some (major, arg, rest)) :
    major = ib / 32 ∧ k ≤ tl.length ∧ lo ≤ arg ∧ arg = fromBE (tl.take k) ∧ rest = tl.drop k := by
  cases hr : readArg k lo tl with
  | none => simp [hr] at h
  | some p =>
    obtain ⟨v, r⟩ := p
    simp only [hr, Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl, rfl⟩ := h
    have := readArg_spec hr
    exact ⟨rfl, this.1, this.2.1, this.2.2.1, this.2.2.2⟩

/-- **Canonical uniqueness.** Whatever `decodeHead` accepts (for bytes `< 256` and data
major types) is *exactly* `encodeHead` of the decoded values followed by the rest. -/
theorem encodeHead_of_decodeHead (l : List Nat) (major arg : Nat) (rest : List Nat)
    (hb : ∀ b ∈ l, b < 256) (h : decodeHead l = some (major, arg, rest)) :
    l = encodeHead major arg ++ rest := by
  match l, hb, h with
  | ib :: tl, hb, h =>
    have hib : ib < 256 := hb ib (by simp)
    have htl : ∀ b ∈ tl, b < 256 := fun b hb' => hb b (by simp [hb'])
    simp only [decodeHead] at h
    split at h
    · simp at h
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      unfold encodeHead
      repeat' split
      all_goals first | omega | (simp only [List.singleton_append, List.cons.injEq, and_true]; omega)
    split at h
    · obtain ⟨rfl, hk, hlo, rfl, rfl⟩ := decodeHead_ext h
      have hlt := fromBE_take_lt tl 1 hk htl
      rw [encodeHead_w1 _ _ hlo (by simpa using hlt), List.cons_append, take_bytes_eq tl 1 hk htl]
      congr 1; omega
    split at h
    · obtain ⟨rfl, hk, hlo, rfl, rfl⟩ := decodeHead_ext h
      have hlt := fromBE_take_lt tl 2 hk htl
      rw [encodeHead_w2 _ _ hlo (by simpa using hlt), List.cons_append, take_bytes_eq tl 2 hk htl]
      congr 1; omega
    split at h
    · obtain ⟨rfl, hk, hlo, rfl, rfl⟩ := decodeHead_ext h
      have hlt := fromBE_take_lt tl 4 hk htl
      rw [encodeHead_w4 _ _ hlo (by simpa using hlt), List.cons_append, take_bytes_eq tl 4 hk htl]
      congr 1; omega
    split at h
    · obtain ⟨rfl, hk, hlo, rfl, rfl⟩ := decodeHead_ext h
      rw [encodeHead_w8 _ _ hlo, List.cons_append, take_bytes_eq tl 8 hk htl]
      congr 1; omega
    · simp at h

/-- Every accepted head consumes at least one byte. -/
theorem decodeHead_shrinks {l : List Nat} {m a : Nat} {r : List Nat}
    (h : decodeHead l = some (m, a, r)) : r.length < l.length := by
  match l, h with
  | ib :: tl, h =>
    simp only [decodeHead] at h
    split at h
    · simp at h
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨-, -, rfl⟩ := h; simp
    repeat' split at h
    all_goals first
      | (simp at h; done)
      | (obtain ⟨-, hk, -, -, rfl⟩ := decodeHead_ext h; simp; omega)

end Jotakey.Cbor
