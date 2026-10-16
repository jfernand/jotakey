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
* `decodeHead_shrinks`: every accepted head consumes input, so a loop that reads heads
  always moves forward.

## Reading the proofs

Every theorem below carries a doc comment with two parts: **Proves** (the statement in
words) and **How** (the proof idea). Comments marked *Syntax* introduce Lean notation the
first time it appears. A few things hold everywhere:

* `theorem name (x : T) (h : P x) : Q x := proof` reads "for every `x` of type `T`, if `P x`
  holds then `Q x` holds". Arguments named `h…` are hypotheses: evidence that a condition
  is true, passed in like any other argument.
* `:= by` starts a *tactic proof*: a script of steps, each of which transforms the current
  goal (what is left to prove) until nothing remains. In an editor with the Lean extension,
  placing the cursor on a line shows the goals at that point (the "infoview"). This is the
  best way to follow a proof.
* `omega` proves any goal that follows from the hypotheses by linear arithmetic over `Nat`
  and `Int` (`+`, `-`, `*` and `/` and `%` by constants, `<`, `≤`, `=`). It is used a lot.
* `simp [lemmas]` rewrites the goal with the given definitions and lemmas (plus Lean's
  standard simplification set) until it can't anymore; `simp only [lemmas]` uses only the
  ones listed. `at h` rewrites hypothesis `h` instead of the goal.
-/

namespace Jotakey.Cbor
-- Syntax: everything until `end Jotakey.Cbor` is named `Jotakey.Cbor.…`, like a Rust `mod`.

/-! ## Big-endian integers

Defined through little-endian lists and `reverse` so that every proof is a plain list
induction. -/

/-- `toLE k n`: the low `k` bytes of `n`, least significant first. -/
def toLE : Nat → Nat → List Nat
  -- Syntax: `Nat → Nat → List Nat` is a function taking two `Nat`s and returning a list.
  -- The definition is by pattern matching on the arguments: one line per case, tried in order.
  -- `k + 1` matches any number other than 0 and binds `k` to its predecessor.
  | 0,     _ => []
  | k + 1, n => n % 256 :: toLE k (n / 256) -- :: puts an element in front of a list

-- Syntax: `#guard e` evaluates the boolean `e` while building and fails the build if it is
-- false. These are executable examples, not proofs.
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

/-- **Proves:** `toLE k n` always has exactly `k` elements.

**How:** induction on `k`. `induction k` introduces two goals; `generalizing n` makes the
induction hypothesis hold for every `n`, not just the `n` we started with (we need it at
`n / 256`):
* zero case: `(toLE 0 n).length = 0`;
* `succ k ih` case: `(toLE (k+1) n).length = k + 1`, with `ih : ∀ n, (toLE k n).length = k`. -/
theorem length_toLE (k n : Nat) : (toLE k n).length = k := by
  induction k generalizing n with
  | zero => rfl -- (toLE 0 n).length is 0 by the base case
                -- Syntax: `rfl` closes a goal `a = b` when both sides compute to the same value.
  | succ k ih => simp [toLE, ih] -- toLE (k+1) n = n % 256 :: toLE k (n / 256), so its length is
                                 -- (toLE k (n / 256)).length + 1. ih applied to n / 256 rewrites
                                 -- that to k + 1, leaving k + 1 = k + 1.

/-- **Proves:** `toBE k n` always has exactly `k` elements.

**How:** `toBE` is `toLE` reversed, reversing keeps the length (`List.length_reverse`, a
standard `simp` lemma), and `length_toLE` gives the length of `toLE`. -/
theorem length_toBE (k n : Nat) : (toBE k n).length = k := by
  simp [toBE, length_toLE]

/-- **Proves:** converting a number to `k` little-endian bytes and back yields the same
number, provided the number fits in `k` bytes (`n < 256 ^ k`). Without that hypothesis the
high bytes would be cut off and the round trip would fail.

**How:** induction on `k`, for every `n`.
* `k = 0`: `n < 256 ^ 0 = 1`, so `n = 0`, and `fromLE (toLE 0 n) = fromLE [] = 0`.
* `k + 1`: from `n < 256 ^ (k+1)` derive `n / 256 < 256 ^ k`, so the induction hypothesis
  applies to `n / 256`. Unfolding one step of each function leaves
  `n % 256 + 256 * (n / 256) = n`, which is division with remainder (`omega`). -/
theorem fromLE_toLE (k n : Nat) (h : n < 256 ^ k) : fromLE (toLE k n) = n := by -- round trip only works if n < 256 ^ k
  induction k generalizing n with
  | zero => simp [toLE, fromLE]; omega
    -- Syntax: `t1; t2` runs two tactics one after the other on the same line.
  | succ k ih =>
    -- Syntax: `have name : P := proof` proves an intermediate fact and adds it as hypothesis
    -- `name`. Here the proof is itself a small tactic block (`by` …).
    have hk : n / 256 < 256 ^ k := by
      rw [Nat.pow_succ] at h
      -- Syntax: `rw [lemma] at h` rewrites `h` with an equation, left side → right side.
      -- `Nat.pow_succ : b ^ (n+1) = b ^ n * b` turns `h` into `n < 256 ^ k * 256`.
      exact (Nat.div_lt_iff_lt_mul (by decide)).mpr h
      -- Syntax: `exact e` closes the goal with the proof term `e`. The library lemma says
      -- `n / c < m ↔ n < m * c` when `0 < c`; `(by decide)` proves `0 < 256` by computation,
      -- and `.mpr` uses the "←" direction of the `↔`.
    simp only [toLE, fromLE, ih _ hk]
    -- Syntax: `ih _ hk` applies the induction hypothesis; `_` asks Lean to infer the
    -- argument (`n / 256`) from the type of `hk`.
    omega

/-- **Proves:** the big-endian round trip, `fromBE (toBE k n) = n` for `n < 256 ^ k`.

**How:** `fromBE (toBE k n)` unfolds to `fromLE (toLE k n).reverse.reverse`; the two
reverses cancel (`List.reverse_reverse`, a `simp` lemma) and `fromLE_toLE` finishes. -/
theorem fromBE_toBE (k n : Nat) (h : n < 256 ^ k) : fromBE (toBE k n) = n := by
  simp [fromBE, toBE, fromLE_toLE k n h]

/-- **Proves:** the number `fromLE l` is `< 256 ^ l.length` when every element of `l` is a
byte. We need it further down (`fromBE_take_lt`): the argument bytes the decoder reads always
give a number that fits back into the same number of bytes, so re-encoding it loses nothing
(`encodeHead_of_decodeHead`).

**How:** induction on the list.
* `[]`: `fromLE [] = 0 < 1 = 256 ^ 0`.
* `b :: t`: the induction hypothesis gives `fromLE t < 256 ^ t.length`, so
  `fromLE t + 1 ≤ 256 ^ t.length`. Multiplying by 256 and using `b < 256`:
  `b + 256 * fromLE t < 256 * (fromLE t + 1) ≤ 256 * 256 ^ t.length = 256 ^ (t.length + 1)`. -/
theorem fromLE_lt (l : List Nat) (hb : ∀ b ∈ l, b < 256) : fromLE l < (256 ^ l.length) := by -- hb restricts the elements of l from Nats to bytes
  -- Syntax: `∀ b ∈ l, b < 256` is short for `∀ b, b ∈ l → b < 256`. A proof of it is a
  -- function: give it `b` and a proof of `b ∈ l`, get back a proof of `b < 256`.
  induction l with
  | nil => simp [fromLE]
  | cons b t ih =>
    have h1 := ih (fun x hx => hb x (by simp [hx]))
    -- The hypothesis `ih` itself needs "every element of `t` is a byte". We build that proof
    -- as a function (`fun x hx => …`): an element `x` of `t` is also an element of `b :: t`
    -- (`by simp [hx]`), so `hb` applies to it.
    have h2 : b < 256 := hb b (by simp)
    simp only [fromLE, List.length_cons, Nat.pow_succ]
    have : 256 * fromLE t + 256 ≤ 256 * 256 ^ t.length := by
      have := Nat.mul_le_mul_left 256 h1
      -- Syntax: `have := e` without a name creates a hypothesis called `this`.
      -- `h1 : fromLE t < 256 ^ _` is `fromLE t + 1 ≤ 256 ^ _` for `Nat`, and the lemma
      -- multiplies both sides by 256.
      omega
    rw [Nat.mul_comm (256 ^ t.length)]
    -- `omega` treats `256 ^ t.length` as an opaque number, so both products must be written
    -- the same way round (`256 * …`) for it to see they are the same term.
    omega

/-- **Proves:** the number `fromBE l` is `< 256 ^ l.length` when every element is a byte.

**How:** apply `fromLE_lt` to `l.reverse`. Its elements are the elements of `l`
(`List.mem_reverse`) and its length is `l.length`, which `simpa` rewrites away. -/
theorem fromBE_lt (l : List Nat) (hb : ∀ b ∈ l, b < 256) : fromBE l < 256 ^ l.length := by
  have := fromLE_lt l.reverse (fun b h => hb b (List.mem_reverse.mp h))
  simpa [fromBE] using this
  -- Syntax: `simpa [..] using e` simplifies both the goal and the type of `e`, then closes
  -- the goal with `e` if they now match.

/-- **Proves:** converting a list of bytes to a number and back to the same number of bytes
yields the same list. Together with `fromLE_toLE` this says bytes ↔ numbers is a bijection
for a fixed width.

A property test only checks the inputs it happens to generate; this proof covers every
byte list. We have both: `accepted_heads_are_canonical` in `cbor.rs` is the Rust property
test (decode random bytes, re-encode, compare), and the differential test ties the Rust
decoder to this model.

**How:** induction on the list. For `b :: t` the number is `b + 256 * fromLE t`. Its
remainder mod 256 is `b` (because `b < 256`) and its quotient is `fromLE t`, so `toLE`
produces `b` followed by `toLE t.length (fromLE t)`, which is `t` by the induction
hypothesis. -/
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

/-- **Proves:** the big-endian version of `toLE_fromLE`:
`toBE l.length (fromBE l) = l` for a list of bytes.

**How:** `toLE_fromLE` on `l.reverse`, then unfold `toBE`/`fromBE` and cancel the reverses. -/
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
  -- Syntax: `Option α` is Rust's `Option<T>` (`none` / `some x`); `α × β` is a pair `(a, b)`.
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
    -- Syntax: `o.map f` applies `f` inside an `Option` (`none` stays `none`), like Rust's
    -- `Option::map`. `fun (v, r) => …` is a closure that destructures its pair argument.
    else if info = 24 then (readArg 1 24 rest).map fun (v, r) => (major, v, r)
    else if info = 25 then (readArg 2 (2 ^ 8) rest).map fun (v, r) => (major, v, r)
    else if info = 26 then (readArg 4 (2 ^ 16) rest).map fun (v, r) => (major, v, r)
    else if info = 27 then (readArg 8 (2 ^ 32) rest).map fun (v, r) => (major, v, r)
    else none

/-- **Proves:** `readArg` reads back a big-endian argument written by `toBE`: if `v` fits in
`k` bytes and is at least `lo`, then reading `toBE k v ++ rest` gives `v` and leaves exactly
`rest`.

**How:** `toBE k v` has length `k` (`length_toBE`), so `take k` returns it and `drop k`
returns `rest` (the two `have`s, by standard list lemmas). Its value is `v`
(`fromBE_toBE`). Then both rejection tests in `readArg` are false — the input is long
enough and `v ≥ lo` — and `omega` discharges those two comparisons. -/
theorem readArg_toBE (k lo v : Nat) (rest : List Nat) (hlo : lo ≤ v) (hv : v < 256 ^ k) :
    readArg k lo (toBE k v ++ rest) = some (v, rest) := by
  have hlen := length_toBE k v
  have htake : (toBE k v ++ rest).take k = toBE k v := by
    rw [List.take_append_of_le_length (by omega), List.take_of_length_le (by omega)]
    -- Syntax: a lemma with hypotheses can be given their proofs inline, as `(by omega)`.
  have hdrop : (toBE k v ++ rest).drop k = rest := by
    rw [List.drop_append_of_le_length (by omega), List.drop_of_length_le (by omega)]
    simp
  simp only [readArg, List.length_append, hlen, htake, fromBE_toBE k v hv, hdrop]
  simp
  omega

/-- **Round trip.** For data-carrying major types (0‥6) and any 64-bit argument, decoding
the encoded head returns the major type, the argument and the untouched remainder.

**Proves:** `decodeHead (encodeHead major arg ++ rest) = some (major, arg, rest)` whenever
`major < 7` and `arg < 2⁶⁴`. The decoder never misreads what the encoder wrote, and never
reads past the head into `rest`.

**How:** split into the five width classes that `encodeHead` distinguishes (`arg < 24`,
`< 2⁸`, `< 2¹⁶`, `< 2³²`, otherwise). In each class:
1. the initial byte `major * 32 + info` splits back into `major` (÷ 32) and `info` (mod 32);
   `omega` proves both, since `info < 32`;
2. for the extended widths, `readArg_toBE` reads the argument back; its `lo` hypothesis
   holds because the class excludes smaller values (that is the minimality check);
3. the final `simp; omega` clears the remaining tests in `decodeHead`, notably the float
   check `major = 7 ∧ …`, which is false because `major < 7`. -/
theorem decodeHead_encodeHead (major arg : Nat) (rest : List Nat)
    (hm : major < 7) (ha : arg < argLimit) : -- 0 ≤ major ≤ 6: the decoder rejects major 7
                                              -- with info 24‥27 (floats)
    decodeHead (encodeHead major arg ++ rest) = some (major, arg, rest) := by
  unfold encodeHead argLimit at *
  -- Syntax: `unfold f at *` replaces `f` by its definition in the goal and every hypothesis.
  by_cases h0 : arg < 24
  -- Syntax: `by_cases h : P` splits the proof in two: one goal with `h : P`, one with
  -- `h : ¬P`. A `·` (centred dot) focuses on the next goal; the indented block under it must
  -- solve that goal completely. Here the unbulleted lines after each `·` block continue with
  -- the `¬P` goal, which is split again by the next `by_cases`.
  · simp only [h0, ↓reduceIte, List.singleton_append, decodeHead]
    -- Syntax: `↓reduceIte` is a simp procedure: it rewrites `if c then a else b` to `a` or
    -- `b` once `c` is known to be true or false (here thanks to `h0`).
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

/-- **Proves:** the converse of `readArg_toBE`. If `readArg` succeeds with `(v, r)`, then the
input had at least `k` bytes, `v ≥ lo`, `v` is the value of the first `k` bytes, and `r` is
what follows them. Proofs about `decodeHead` use this to learn what an accepted input looks
like.

**How:** unfold `readArg` and follow its `if`s with `split at h`. In both rejecting branches
`h` claims `none = some (v, r)`, which `simp at h` recognises as impossible, closing the
goal. In the accepting branch `h` says `some (fromBE …, l.drop k) = some (v, r)`, so `v` and
`r` *are* those expressions; substituting them leaves facts that are already hypotheses. -/
theorem readArg_spec {k lo : Nat} {l : List Nat} {v : Nat} {r : List Nat}
    (h : readArg k lo l = some (v, r)) :
    k ≤ l.length ∧ lo ≤ v ∧ v = fromBE (l.take k) ∧ r = l.drop k := by
  -- Syntax: arguments in `{ }` are *implicit*: callers don't write them, Lean infers them
  -- from the other arguments (here from the type of `h`).
  unfold readArg at h
  split at h
  -- Syntax: `split at h` splits on the first `if`/`match` inside `h`, giving one goal per
  -- branch, each with the branch condition as a new hypothesis.
  · simp at h
  · split at h
    · simp at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      -- `some a = some b` becomes `a = b`, and `(a, b) = (c, d)` becomes `a = c ∧ b = d`.
      obtain ⟨rfl, rfl⟩ := h
      -- Syntax: `obtain ⟨p, q⟩ := h` splits `h : P ∧ Q` into its two parts. Writing `rfl`
      -- for a part that is an equation `x = e` substitutes `e` for `x` everywhere.
      refine ⟨by omega, by omega, rfl, rfl⟩
      -- Syntax: `⟨a, b, c, d⟩` builds a proof of `A ∧ B ∧ C ∧ D` from proofs of each part;
      -- `refine` is `exact` that also accepts `?_` holes to be proved afterwards.

/-- **Proves:** re-encoding the first `k` bytes of a byte list, then putting the remaining
bytes back, rebuilds the list. This is the step that turns "the decoder read these bytes"
into "the bytes are what the encoder would write".

**How:** `tl.take k` has length `k` (because `k ≤ tl.length`), so `toBE_fromBE` turns
`toBE k (fromBE (tl.take k))` back into `tl.take k`; then `take ++ drop` is the whole list
(`List.take_append_drop`). -/
theorem take_bytes_eq (tl : List Nat) (k : Nat) (hk : k ≤ tl.length) (hb : ∀ b ∈ tl, b < 256) :
    toBE k (fromBE (tl.take k)) ++ tl.drop k = tl := by
  have h1 : (tl.take k).length = k := by simp; omega
  have h2 := toBE_fromBE (tl.take k) (fun b hb' => hb b (List.mem_of_mem_take hb'))
  rw [h1] at h2
  rw [h2, List.take_append_drop]

/-- **Proves:** the number in the first `k` bytes of a byte list is `< 256 ^ k`, i.e. the
argument the decoder reads always fits in the width it was read from.

**How:** `fromBE_lt` on `tl.take k`, whose length is `k`. -/
theorem fromBE_take_lt (tl : List Nat) (k : Nat) (hk : k ≤ tl.length) (hb : ∀ b ∈ tl, b < 256) :
    fromBE (tl.take k) < 256 ^ k := by
  have h1 : (tl.take k).length = k := by simp; omega
  have := fromBE_lt (tl.take k) (fun b hb' => hb b (List.mem_of_mem_take hb'))
  rwa [h1] at this
  -- Syntax: `rwa` is `rw` followed by `assumption` (close the goal with a matching hypothesis).

/-- **Proves:** for `24 ≤ a < 2⁸`, `encodeHead` picks the 1-byte form (info 24). The next
three lemmas do the same for the 2-, 4- and 8-byte forms. `encodeHead_of_decodeHead` uses them
to name the encoder's output once it knows which range the argument is in.

**How:** unfold `encodeHead` and split every `if` (`repeat' split`). In the branch that
matches the range the two sides are identical (`rfl`); every other branch carries a condition
contradicting `h1`/`h2`, which `omega` refutes. -/
theorem encodeHead_w1 (m a : Nat) (h1 : 24 ≤ a) (h2 : a < 2 ^ 8) :
    encodeHead m a = (m * 32 + 24) :: toBE 1 a := by
  unfold encodeHead; repeat' split
  -- Syntax: `repeat' t` applies `t` again and again, to every goal it creates, until it
  -- fails. `all_goals t` runs `t` on every open goal; `first | t1 | t2` tries `t1` and, if it
  -- fails, `t2`.
  all_goals first | rfl | omega

/-- **Proves:** for `2⁸ ≤ a < 2¹⁶`, `encodeHead` picks the 2-byte form (info 25).
**How:** as `encodeHead_w1`. -/
theorem encodeHead_w2 (m a : Nat) (h1 : 2 ^ 8 ≤ a) (h2 : a < 2 ^ 16) :
    encodeHead m a = (m * 32 + 25) :: toBE 2 a := by
  unfold encodeHead; repeat' split
  all_goals first | rfl | omega

/-- **Proves:** for `2¹⁶ ≤ a < 2³²`, `encodeHead` picks the 4-byte form (info 26).
**How:** as `encodeHead_w1`. -/
theorem encodeHead_w4 (m a : Nat) (h1 : 2 ^ 16 ≤ a) (h2 : a < 2 ^ 32) :
    encodeHead m a = (m * 32 + 26) :: toBE 4 a := by
  unfold encodeHead; repeat' split
  all_goals first | rfl | omega

/-- **Proves:** for `2³² ≤ a`, `encodeHead` picks the 8-byte form (info 27). No upper bound is
needed: the last branch of `encodeHead` takes everything that is left.
**How:** as `encodeHead_w1`. -/
theorem encodeHead_w8 (m a : Nat) (h1 : 2 ^ 32 ≤ a) :
    encodeHead m a = (m * 32 + 27) :: toBE 8 a := by
  unfold encodeHead; repeat' split
  all_goals first | rfl | omega

/-- Shape of an accepted extended-width head.

**Proves:** if one of the `info = 24‥27` branches of `decodeHead` accepted, giving
`(major, arg, rest)`, then `major` is the top bits of the initial byte, the argument bytes
were present (`k ≤ tl.length`), the argument passed the minimality check (`lo ≤ arg`), it is
the value of the next `k` bytes, and `rest` is everything after them.

**How:** look at what `readArg` returned (`cases hr : …`). `none` is impossible, since
`none.map f = none ≠ some _`. For `some (v, r)`, the equation `h` says
`(ib / 32, v, r) = (major, arg, rest)`; substitute, then `readArg_spec` supplies the rest. -/
theorem decodeHead_ext {k lo : Nat} {ib : Nat} {tl : List Nat} {major arg : Nat} {rest : List Nat}
    (h : (readArg k lo tl).map (fun (v, r) => (ib / 32, v, r)) = some (major, arg, rest)) :
    major = ib / 32 ∧ k ≤ tl.length ∧ lo ≤ arg ∧ arg = fromBE (tl.take k) ∧ rest = tl.drop k := by
  cases hr : readArg k lo tl with
  -- Syntax: `cases hr : e with | none => … | some p => …` does one case per constructor of
  -- `e`'s type and records which one in `hr` (e.g. `hr : readArg k lo tl = none`).
  | none => simp [hr] at h
  | some p =>
    obtain ⟨v, r⟩ := p
    simp only [hr, Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl, rfl⟩ := h
    have := readArg_spec hr
    exact ⟨rfl, this.1, this.2.1, this.2.2.1, this.2.2.2⟩
    -- Syntax: for `this : A ∧ B ∧ C ∧ D` (which is `A ∧ (B ∧ (C ∧ D))`), `.1` is `A`,
    -- `.2.1` is `B`, `.2.2.1` is `C` and `.2.2.2` is `D`.

/-- **Canonical uniqueness.** Whatever `decodeHead` accepts (for bytes `< 256` and data
major types) is *exactly* `encodeHead` of the decoded values followed by the rest.

**Proves:** if `decodeHead l = some (major, arg, rest)` and every element of `l` is a byte,
then `l = encodeHead major arg ++ rest`. Since `encodeHead` is a function, each
`(major, arg)` has exactly one accepted encoding: no non-minimal argument, no alternative
width, no reserved info value gets through. This is the property the differential-test
input `3900ff…` (a non-minimal −256) exercises.

**How:** follow `decodeHead`'s chain of `if`s with `split at h`, one branch at a time:
* float / extended simple value, and info 28‥31: `h` says `none = some …`, impossible;
* `info < 24`: `major = ib / 32`, `arg = ib % 32`, `rest = tl`. `encodeHead` takes its first
  branch (`arg < 24`) and `ib = (ib / 32) * 32 + ib % 32` is division with remainder;
* `info = 24, 25, 26, 27`: `decodeHead_ext` says `arg` is the value of the next `k` bytes and
  at least `lo`; `fromBE_take_lt` says it is below `256 ^ k`. So `arg` lies in the range
  where `encodeHead_wK` names the encoder's output, `take_bytes_eq` shows those `k` bytes
  re-encode to themselves, and only the initial byte is left to compare (`congr 1`, `omega`).
-/
theorem encodeHead_of_decodeHead (l : List Nat) (major arg : Nat) (rest : List Nat)
    (hb : ∀ b ∈ l, b < 256) (h : decodeHead l = some (major, arg, rest)) :
    l = encodeHead major arg ++ rest := by
  match l, hb, h with
  -- Syntax: `match` inside a proof pattern-matches on `l` and re-states the hypotheses that
  -- mention it. Only the `ib :: tl` case is written: for `[]`, `h` would read
  -- `none = some …`, and Lean discards that impossible case by itself.
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
      -- Syntax: `congr 1` reduces `a :: s = b :: s` to `a = b` (the tails already agree).
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

/-- Every accepted head consumes at least one byte.

**Proves:** if `decodeHead l = some (m, a, r)` then `r` is strictly shorter than `l`. No
head is zero-width, so a loop that reads heads always makes progress through the input.

**How:** the same case analysis as `encodeHead_of_decodeHead`. Rejecting branches are
impossible. For an immediate argument `r` is the tail after the initial byte. For an
extended one `r = tl.drop k`, which is no longer than `tl`, itself one shorter than `l`. -/
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
      -- Syntax: `-` in an `obtain` pattern throws that part away.
    repeat' split at h
    all_goals first
      | (simp at h; done)
      | (obtain ⟨-, hk, -, -, rfl⟩ := decodeHead_ext h; simp; omega)
      -- `done` fails unless no goal is left, so the first alternative only "succeeds" on the
      -- impossible branches, and the extended-width branches fall through to the second.

end Jotakey.Cbor
