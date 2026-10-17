-- (c) Javier Fernandez @ JotaSoft 2026
/-!
# CBOR heads

Formal model of the head functions of `crates/jotakey-core/src/cbor.rs`:
`encodeHead` / `decodeHead` mirror `Encoder::head` / `Decoder::head`.

Bytes are modelled as `Nat`s. Theorems that need it assume every element is `< 256`.

Main results:
* `decodeHead_inverts_encodeHead`: decoding an encoded head gives back exactly what was
  encoded.
* `decodeHead_accepts_only_canonical`: **canonical uniqueness**. If the decoder accepts some
  bytes, they are exactly the encoding of the decoded value. No head has two accepted
  encodings, so two parsers that implement this model can never disagree about a message.
* `decodeHead_consumes_input`: every accepted head consumes input, so a loop that reads heads
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
* `ih` is the conventional name for an *induction hypothesis*: the statement for the smaller
  case, available while proving the larger one.
-/

namespace Jotakey.Cbor
-- Syntax: everything until `end Jotakey.Cbor` is named `Jotakey.Cbor.…`, like a Rust `mod`.

/-! ## Big-endian integers

Defined through little-endian lists and `reverse` so that every proof is a plain list
induction. -/

/-- `toLittleEndian width value`: the low `width` bytes of `value`, least significant first. -/
def toLittleEndian : Nat → Nat → List Nat
  -- Syntax: `Nat → Nat → List Nat` is a function taking two `Nat`s and returning a list.
  -- The definition is by pattern matching on the arguments: one line per case, tried in order.
  -- `width + 1` matches any number other than 0 and binds `width` to its predecessor.
  | 0,         _     => []
  | width + 1, value => value % 256 :: toLittleEndian width (value / 256)
  -- `::` puts an element in front of a list

-- Syntax: `#guard e` evaluates the boolean `e` while building and fails the build if it is
-- false. These are executable examples, not proofs.
#guard toLittleEndian 2 1000 == [232, 3]
#guard toLittleEndian 4 1000 == [232, 3, 0, 0]

/-- Interpret a byte list as a little-endian number. -/
def fromLittleEndian : List Nat → Nat
  | [] => 0
  | byte :: tail => byte + 256 * fromLittleEndian tail

#guard fromLittleEndian [232, 3] == 1000

/-- `toBigEndian width value`: the low `width` bytes of `value`, most significant first. -/
def toBigEndian (width value : Nat) : List Nat := (toLittleEndian width value).reverse

#guard toBigEndian 2 1000 == [3, 232]
#guard toBigEndian 4 1000 == [0, 0, 3, 232]

/-- Interpret a byte list as a big-endian number. -/
def fromBigEndian (bytes : List Nat) : Nat := fromLittleEndian bytes.reverse

/-- **Proves:** `toLittleEndian width value` always has exactly `width` elements.

**How:** induction on `width`. `induction width` introduces two goals; `generalizing value`
makes the induction hypothesis hold for every `value`, not just the one we started with (we
need it at `value / 256`):
* zero case: `(toLittleEndian 0 value).length = 0`;
* `succ width ih` case: `(toLittleEndian (width+1) value).length = width + 1`, with
  `ih : ∀ value, (toLittleEndian width value).length = width`. -/
theorem toLittleEndian_length (width value : Nat) :
    (toLittleEndian width value).length = width := by
  induction width generalizing value with
  | zero => rfl -- (toLittleEndian 0 value).length is 0 by the base case
                -- Syntax: `rfl` closes a goal `a = b` when both sides compute to the same value.
  | succ width ih => simp [toLittleEndian, ih]
    -- toLittleEndian (width+1) value = value % 256 :: toLittleEndian width (value / 256), so
    -- its length is (toLittleEndian width (value / 256)).length + 1. ih applied to
    -- value / 256 rewrites that to width + 1, leaving width + 1 = width + 1.

/-- **Proves:** `toBigEndian width value` always has exactly `width` elements.

**How:** `toBigEndian` is `toLittleEndian` reversed, reversing keeps the length
(`List.length_reverse`, a standard `simp` lemma), and `toLittleEndian_length` gives the length
of `toLittleEndian`. -/
theorem toBigEndian_length (width value : Nat) : (toBigEndian width value).length = width := by
  simp [toBigEndian, toLittleEndian_length]

/-- **Proves:** converting a number to `width` little-endian bytes and back yields the same
number, provided the number fits in `width` bytes (`value < 256 ^ width`). Without that
hypothesis the high bytes would be cut off and the round trip would fail.

**How:** induction on `width`, for every `value`.
* `width = 0`: `value < 256 ^ 0 = 1`, so `value = 0`, and converting `[]` back gives `0`.
* `width + 1`: from `value < 256 ^ (width+1)` derive `value / 256 < 256 ^ width`, so the
  induction hypothesis applies to `value / 256`. Unfolding one step of each function leaves
  `value % 256 + 256 * (value / 256) = value`, which is division with remainder (`omega`). -/
theorem littleEndian_number_roundtrip (width value : Nat) (hFits : value < 256 ^ width) :
    fromLittleEndian (toLittleEndian width value) = value := by
  induction width generalizing value with
  | zero => simp [toLittleEndian, fromLittleEndian]; omega
    -- Syntax: `t1; t2` runs two tactics one after the other on the same line.
  | succ width ih =>
    -- Syntax: `have name : P := proof` proves an intermediate fact and adds it as hypothesis
    -- `name`. Here the proof is itself a small tactic block (`by` …).
    have hQuotientFits : value / 256 < 256 ^ width := by
      rw [Nat.pow_succ] at hFits
      -- Syntax: `rw [lemma] at h` rewrites `h` with an equation, left side → right side.
      -- `Nat.pow_succ : b ^ (n+1) = b ^ n * b` turns `hFits` into `value < 256 ^ width * 256`.
      exact (Nat.div_lt_iff_lt_mul (by decide)).mpr hFits
      -- Syntax: `exact e` closes the goal with the proof term `e`. The library lemma says
      -- `n / c < m ↔ n < m * c` when `0 < c`; `(by decide)` proves `0 < 256` by computation,
      -- and `.mpr` uses the "←" direction of the `↔`.
    simp only [toLittleEndian, fromLittleEndian, ih _ hQuotientFits]
    -- Syntax: `ih _ hQuotientFits` applies the induction hypothesis; `_` asks Lean to infer
    -- the argument (`value / 256`) from the type of `hQuotientFits`.
    omega

/-- **Proves:** the big-endian round trip, `fromBigEndian (toBigEndian width value) = value`
for `value < 256 ^ width`.

**How:** the left side unfolds to `fromLittleEndian` of `toLittleEndian width value` reversed
twice; the two reverses cancel (`List.reverse_reverse`, a `simp` lemma) and
`littleEndian_number_roundtrip` finishes. -/
theorem bigEndian_number_roundtrip (width value : Nat) (hFits : value < 256 ^ width) :
    fromBigEndian (toBigEndian width value) = value := by
  simp [fromBigEndian, toBigEndian, littleEndian_number_roundtrip width value hFits]

/-- **Proves:** the number `fromLittleEndian bytes` is `< 256 ^ bytes.length` when every
element is a byte. We need it further down (`prefix_value_fits_width`): the argument bytes the
decoder reads always give a number that fits back into the same number of bytes, so
re-encoding it loses nothing (`decodeHead_accepts_only_canonical`).

**How:** induction on the list.
* `[]`: the value is `0 < 1 = 256 ^ 0`.
* `byte :: tail`: the induction hypothesis gives `fromLittleEndian tail < 256 ^ tail.length`,
  so `fromLittleEndian tail + 1 ≤ 256 ^ tail.length`. Multiplying by 256 and using
  `byte < 256`: `byte + 256 * fromLittleEndian tail < 256 * (fromLittleEndian tail + 1)
  ≤ 256 * 256 ^ tail.length = 256 ^ (tail.length + 1)`. -/
theorem fromLittleEndian_fits_width (bytes : List Nat) (hBytes : ∀ byte ∈ bytes, byte < 256) :
    fromLittleEndian bytes < 256 ^ bytes.length := by
  -- Syntax: `∀ byte ∈ bytes, byte < 256` is short for `∀ byte, byte ∈ bytes → byte < 256`.
  -- A proof of it is a function: give it `byte` and a proof of `byte ∈ bytes`, get back a
  -- proof of `byte < 256`. It is what restricts these `Nat`s to bytes.
  induction bytes with
  | nil => simp [fromLittleEndian]
  | cons byte tail ih =>
    have hTailFits := ih (fun element hMember => hBytes element (by simp [hMember]))
    -- The hypothesis `ih` itself needs "every element of `tail` is a byte". We build that
    -- proof as a function (`fun element hMember => …`): an element of `tail` is also an
    -- element of `byte :: tail` (`by simp [hMember]`), so `hBytes` applies to it.
    have hByte : byte < 256 := hBytes byte (by simp)
    simp only [fromLittleEndian, List.length_cons, Nat.pow_succ]
    have : 256 * fromLittleEndian tail + 256 ≤ 256 * 256 ^ tail.length := by
      have := Nat.mul_le_mul_left 256 hTailFits
      -- Syntax: `have := e` without a name creates a hypothesis called `this`.
      -- `hTailFits : fromLittleEndian tail < 256 ^ _` is `fromLittleEndian tail + 1 ≤ 256 ^ _`
      -- for `Nat`, and the lemma multiplies both sides by 256.
      omega
    rw [Nat.mul_comm (256 ^ tail.length)]
    -- `omega` treats `256 ^ tail.length` as an opaque number, so both products must be
    -- written the same way round (`256 * …`) for it to see they are the same term.
    omega

/-- **Proves:** the number `fromBigEndian bytes` is `< 256 ^ bytes.length` when every element
is a byte.

**How:** apply `fromLittleEndian_fits_width` to `bytes.reverse`. Its elements are the
elements of `bytes` (`List.mem_reverse`) and its length is `bytes.length`, which `simpa`
rewrites away. -/
theorem fromBigEndian_fits_width (bytes : List Nat) (hBytes : ∀ byte ∈ bytes, byte < 256) :
    fromBigEndian bytes < 256 ^ bytes.length := by
  have := fromLittleEndian_fits_width bytes.reverse
    (fun element hMember => hBytes element (List.mem_reverse.mp hMember))
  simpa [fromBigEndian] using this
  -- Syntax: `simpa [..] using e` simplifies both the goal and the type of `e`, then closes
  -- the goal with `e` if they now match.

/-- **Proves:** converting a list of bytes to a number and back to the same number of bytes
yields the same list. Together with `littleEndian_number_roundtrip` this says bytes ↔ numbers
is a bijection for a fixed width.

A property test only checks the inputs it happens to generate; this proof covers every
byte list. We have both: `accepted_heads_are_canonical` in `cbor.rs` is the Rust property
test (decode random bytes, re-encode, compare), and the differential test ties the Rust
decoder to this model.

**How:** induction on the list. For `byte :: tail` the number is
`byte + 256 * fromLittleEndian tail`. Its remainder mod 256 is `byte` (because `byte < 256`)
and its quotient is `fromLittleEndian tail`, so `toLittleEndian` produces `byte` followed by
the conversion of `fromLittleEndian tail`, which is `tail` by the induction hypothesis. -/
theorem littleEndian_bytes_roundtrip (bytes : List Nat) (hBytes : ∀ byte ∈ bytes, byte < 256) :
    toLittleEndian bytes.length (fromLittleEndian bytes) = bytes := by
  induction bytes with
  | nil => rfl
  | cons byte tail ih =>
    have hByte : byte < 256 := hBytes byte (by simp)
    have ihTail := ih (fun element hMember => hBytes element (by simp [hMember]))
    simp only [List.length_cons, toLittleEndian, fromLittleEndian]
    have hRemainder : (byte + 256 * fromLittleEndian tail) % 256 = byte := by omega
    have hQuotient : (byte + 256 * fromLittleEndian tail) / 256 = fromLittleEndian tail := by omega
    rw [hRemainder, hQuotient, ihTail]

/-- **Proves:** the big-endian version of `littleEndian_bytes_roundtrip`:
`toBigEndian bytes.length (fromBigEndian bytes) = bytes` for a list of bytes.

**How:** `littleEndian_bytes_roundtrip` on `bytes.reverse`, then unfold `toBigEndian` /
`fromBigEndian` and cancel the reverses. -/
theorem bigEndian_bytes_roundtrip (bytes : List Nat) (hBytes : ∀ byte ∈ bytes, byte < 256) :
    toBigEndian bytes.length (fromBigEndian bytes) = bytes := by
  have := littleEndian_bytes_roundtrip bytes.reverse
    (fun element hMember => hBytes element (List.mem_reverse.mp hMember))
  simp only [List.length_reverse] at this
  simp [toBigEndian, fromBigEndian, this]

/-! ## Heads

A head is the first 1–9 bytes of every CBOR data item. The initial byte holds the _major
type_ in its top 3 bits and the _additional info_ in its low 5 bits:
`initialByte = majorType * 32 + additionalInfo`. The _argument_ (an integer value, a length or
a count, depending on the major type) is:
* additional info < 24: the info value itself (immediate, no further bytes);
* additional info 24, 25, 26, 27: the next 1, 2, 4 or 8 bytes, big-endian;
* 28‥30: reserved, rejected; 31: indefinite length, rejected by our strict decoder. -/

/-- Arguments must be below this (they are 64-bit). -/
def argumentLimit : Nat := 2 ^ 64

/-- Shortest-form head for `majorType` (0‥7, it must fit in 3 bits) and `argument` (< 2⁶⁴), as
`Encoder::head` emits it. -/
def encodeHead (majorType argument : Nat) : List Nat :=
  if argument < 24 then [majorType * 32 + argument]
  else if argument < 2 ^ 8 then (majorType * 32 + 24) :: toBigEndian 1 argument
  else if argument < 2 ^ 16 then (majorType * 32 + 25) :: toBigEndian 2 argument
  else if argument < 2 ^ 32 then (majorType * 32 + 26) :: toBigEndian 4 argument
  else (majorType * 32 + 27) :: toBigEndian 8 argument

/-- Read a `width`-byte big-endian argument, rejecting it unless it is `≥ minimum`
(the minimality rule: smaller values have a shorter encoding). -/
def readArgument (width minimum : Nat) (bytes : List Nat) : Option (Nat × List Nat) :=
  -- Syntax: `Option α` is Rust's `Option<T>` (`none` / `some x`); `α × β` is a pair `(a, b)`.
  if bytes.length < width then none
  else if fromBigEndian (bytes.take width) < minimum then none
  else some (fromBigEndian (bytes.take width), bytes.drop width)

/-- `Decoder::head`: `(majorType, argument, rest)` or `none`.

Rejects: empty input, floats/extended simple values (major type 7, info 24‥27), non-minimal
arguments, reserved info 28‥30 and indefinite lengths (31). -/
def decodeHead : List Nat → Option (Nat × Nat × List Nat)
  | [] => none
  | initialByte :: rest =>
    let majorType := initialByte / 32
    let additionalInfo := initialByte % 32
    if majorType = 7 ∧ 24 ≤ additionalInfo ∧ additionalInfo ≤ 27 then none
    else if additionalInfo < 24 then some (majorType, additionalInfo, rest)
    -- Syntax: `o.map f` applies `f` inside an `Option` (`none` stays `none`), like Rust's
    -- `Option::map`. `fun (v, r) => …` is a closure that destructures its pair argument.
    else if additionalInfo = 24 then
      (readArgument 1 24 rest).map fun (value, after) => (majorType, value, after)
    else if additionalInfo = 25 then
      (readArgument 2 (2 ^ 8) rest).map fun (value, after) => (majorType, value, after)
    else if additionalInfo = 26 then
      (readArgument 4 (2 ^ 16) rest).map fun (value, after) => (majorType, value, after)
    else if additionalInfo = 27 then
      (readArgument 8 (2 ^ 32) rest).map fun (value, after) => (majorType, value, after)
    else none

/-- **Proves:** `readArgument` reads back a big-endian argument written by `toBigEndian`: if
`value` fits in `width` bytes and is at least `minimum`, then reading
`toBigEndian width value ++ rest` gives `value` and leaves exactly `rest`.

**How:** `toBigEndian width value` has length `width` (`toBigEndian_length`), so `take width`
returns it and `drop width` returns `rest` (the two `have`s, by standard list lemmas). Its
value is `value` (`bigEndian_number_roundtrip`). Then both rejection tests in `readArgument`
are false — the input is long enough and `value ≥ minimum` — and `omega` discharges those two
comparisons. -/
theorem readArgument_reads_encoded (width minimum value : Nat) (rest : List Nat)
    (hMinimal : minimum ≤ value) (hFits : value < 256 ^ width) :
    readArgument width minimum (toBigEndian width value ++ rest) = some (value, rest) := by
  have hLength := toBigEndian_length width value
  have hTake : (toBigEndian width value ++ rest).take width = toBigEndian width value := by
    rw [List.take_append_of_le_length (by omega), List.take_of_length_le (by omega)]
    -- Syntax: a lemma with hypotheses can be given their proofs inline, as `(by omega)`.
  have hDrop : (toBigEndian width value ++ rest).drop width = rest := by
    rw [List.drop_append_of_le_length (by omega), List.drop_of_length_le (by omega)]
    simp
  simp only [readArgument, List.length_append, hLength, hTake,
    bigEndian_number_roundtrip width value hFits, hDrop]
  simp
  omega

/-- **Round trip.** For data-carrying major types (0‥6) and any 64-bit argument, decoding
the encoded head returns the major type, the argument and the untouched remainder.

**Proves:** `decodeHead (encodeHead majorType argument ++ rest) = some (majorType, argument, rest)`
whenever `majorType < 7` and `argument < 2⁶⁴`. The decoder never misreads what the encoder
wrote, and never reads past the head into `rest`.

**How:** split into the five width classes that `encodeHead` distinguishes (`argument < 24`,
`< 2⁸`, `< 2¹⁶`, `< 2³²`, otherwise). In each class:
1. the initial byte `majorType * 32 + info` splits back into `majorType` (÷ 32) and `info`
   (mod 32); `omega` proves both, since `info < 32`;
2. for the extended widths, `readArgument_reads_encoded` reads the argument back; its
   `minimum` hypothesis holds because the class excludes smaller values (that is the
   minimality check);
3. the final `simp; omega` clears the remaining tests in `decodeHead`, notably the float
   check `majorType = 7 ∧ …`, which is false because `majorType < 7`. -/
theorem decodeHead_inverts_encodeHead (majorType argument : Nat) (rest : List Nat)
    (hDataType : majorType < 7) (hFits64 : argument < argumentLimit) :
    -- hDataType: 0 ≤ majorType ≤ 6, because the decoder rejects major type 7 with info
    -- 24‥27 (floats)
    decodeHead (encodeHead majorType argument ++ rest) = some (majorType, argument, rest) := by
  unfold encodeHead argumentLimit at *
  -- Syntax: `unfold f at *` replaces `f` by its definition in the goal and every hypothesis.
  by_cases hImmediate : argument < 24
  -- Syntax: `by_cases h : P` splits the proof in two: one goal with `h : P`, one with
  -- `h : ¬P`. A `·` (centred dot) focuses on the next goal; the indented block under it must
  -- solve that goal completely. Here the unbulleted lines after each `·` block continue with
  -- the `¬P` goal, which is split again by the next `by_cases`.
  · simp only [hImmediate, ↓reduceIte, List.singleton_append, decodeHead]
    -- Syntax: `↓reduceIte` is a simp procedure: it rewrites `if c then a else b` to `a` or
    -- `b` once `c` is known to be true or false (here thanks to `hImmediate`).
    have hMajor : (majorType * 32 + argument) / 32 = majorType := by omega
    have hInfo : (majorType * 32 + argument) % 32 = argument := by omega
    simp [hMajor, hInfo, hImmediate]
    omega
  by_cases hOneByte : argument < 2 ^ 8
  · simp only [hImmediate, hOneByte, ↓reduceIte, ↓reduceIte, List.cons_append, decodeHead]
    have hMajor : (majorType * 32 + 24) / 32 = majorType := by omega
    have hInfo : (majorType * 32 + 24) % 32 = 24 := by omega
    simp only [hMajor, hInfo]
    rw [readArgument_reads_encoded 1 24 argument rest (by omega) (by simpa using hOneByte)]
    simp; omega
  by_cases hTwoBytes : argument < 2 ^ 16
  · simp only [hImmediate, hOneByte, hTwoBytes, ↓reduceIte, ↓reduceIte, List.cons_append,
      decodeHead]
    have hMajor : (majorType * 32 + 25) / 32 = majorType := by omega
    have hInfo : (majorType * 32 + 25) % 32 = 25 := by omega
    simp only [hMajor, hInfo]
    rw [readArgument_reads_encoded 2 (2 ^ 8) argument rest (by omega) (by simpa using hTwoBytes)]
    simp; omega
  by_cases hFourBytes : argument < 2 ^ 32
  · simp only [hImmediate, hOneByte, hTwoBytes, hFourBytes, ↓reduceIte, ↓reduceIte,
      List.cons_append, decodeHead]
    have hMajor : (majorType * 32 + 26) / 32 = majorType := by omega
    have hInfo : (majorType * 32 + 26) % 32 = 26 := by omega
    simp only [hMajor, hInfo]
    rw [readArgument_reads_encoded 4 (2 ^ 16) argument rest (by omega) (by simpa using hFourBytes)]
    simp; omega
  · simp only [hImmediate, hOneByte, hTwoBytes, hFourBytes, ↓reduceIte, List.cons_append,
      decodeHead]
    have hMajor : (majorType * 32 + 27) / 32 = majorType := by omega
    have hInfo : (majorType * 32 + 27) % 32 = 27 := by omega
    simp only [hMajor, hInfo]
    rw [readArgument_reads_encoded 8 (2 ^ 32) argument rest (by omega) (by simpa using hFits64)]
    simp; omega

/-- **Proves:** the converse of `readArgument_reads_encoded`. If `readArgument` succeeds with
`(value, after)`, then the input had at least `width` bytes, `value ≥ minimum`, `value` is the
number in the first `width` bytes, and `after` is what follows them. Proofs about
`decodeHead` use this to learn what an accepted input looks like.

**How:** unfold `readArgument` and follow its `if`s with `split at h`. In both rejecting
branches `h` claims `none = some (value, after)`, which `simp at h` recognises as impossible,
closing the goal. In the accepting branch `h` says
`some (fromBigEndian …, bytes.drop width) = some (value, after)`, so `value` and `after` *are*
those expressions; substituting them leaves facts that are already hypotheses. -/
theorem readArgument_accepted_facts {width minimum : Nat} {bytes : List Nat} {value : Nat}
    {after : List Nat} (h : readArgument width minimum bytes = some (value, after)) :
    width ≤ bytes.length ∧ minimum ≤ value ∧ value = fromBigEndian (bytes.take width) ∧
      after = bytes.drop width := by
  -- Syntax: arguments in `{ }` are *implicit*: callers don't write them, Lean infers them
  -- from the other arguments (here from the type of `h`).
  unfold readArgument at h
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

/-- **Proves:** re-encoding the first `width` bytes of a byte list, then putting the remaining
bytes back, rebuilds the list. This is the step that turns "the decoder read these bytes"
into "the bytes are what the encoder would write".

**How:** `bytes.take width` has length `width` (because `width ≤ bytes.length`), so
`bigEndian_bytes_roundtrip` turns the re-encoding back into `bytes.take width`; then
`take ++ drop` is the whole list (`List.take_append_drop`). -/
theorem reencoded_prefix_restores_bytes (bytes : List Nat) (width : Nat)
    (hLongEnough : width ≤ bytes.length) (hBytes : ∀ byte ∈ bytes, byte < 256) :
    toBigEndian width (fromBigEndian (bytes.take width)) ++ bytes.drop width = bytes := by
  have hPrefixLength : (bytes.take width).length = width := by simp; omega
  have hRoundtrip := bigEndian_bytes_roundtrip (bytes.take width)
    (fun element hMember => hBytes element (List.mem_of_mem_take hMember))
  rw [hPrefixLength] at hRoundtrip
  rw [hRoundtrip, List.take_append_drop]

/-- **Proves:** the number in the first `width` bytes of a byte list is `< 256 ^ width`, i.e.
the argument the decoder reads always fits in the width it was read from.

**How:** `fromBigEndian_fits_width` on `bytes.take width`, whose length is `width`. -/
theorem prefix_value_fits_width (bytes : List Nat) (width : Nat)
    (hLongEnough : width ≤ bytes.length) (hBytes : ∀ byte ∈ bytes, byte < 256) :
    fromBigEndian (bytes.take width) < 256 ^ width := by
  have hPrefixLength : (bytes.take width).length = width := by simp; omega
  have := fromBigEndian_fits_width (bytes.take width)
    (fun element hMember => hBytes element (List.mem_of_mem_take hMember))
  rwa [hPrefixLength] at this
  -- Syntax: `rwa` is `rw` followed by `assumption` (close the goal with a matching hypothesis).

/-- **Proves:** for `24 ≤ argument < 2⁸`, `encodeHead` picks the 1-byte form (info 24). The
next three lemmas do the same for the 2-, 4- and 8-byte forms.
`decodeHead_accepts_only_canonical` uses them to name the encoder's output once it knows which
range the argument is in.

**How:** unfold `encodeHead` and split every `if` (`repeat' split`). In the branch that
matches the range the two sides are identical (`rfl`); every other branch carries a condition
contradicting `hAbove`/`hBelow`, which `omega` refutes. -/
theorem encodeHead_one_byte_form (majorType argument : Nat)
    (hAbove : 24 ≤ argument) (hBelow : argument < 2 ^ 8) :
    encodeHead majorType argument = (majorType * 32 + 24) :: toBigEndian 1 argument := by
  unfold encodeHead; repeat' split
  -- Syntax: `repeat' t` applies `t` again and again, to every goal it creates, until it
  -- fails. `all_goals t` runs `t` on every open goal; `first | t1 | t2` tries `t1` and, if it
  -- fails, `t2`.
  all_goals first | rfl | omega

/-- **Proves:** for `2⁸ ≤ argument < 2¹⁶`, `encodeHead` picks the 2-byte form (info 25).
**How:** as `encodeHead_one_byte_form`. -/
theorem encodeHead_two_byte_form (majorType argument : Nat)
    (hAbove : 2 ^ 8 ≤ argument) (hBelow : argument < 2 ^ 16) :
    encodeHead majorType argument = (majorType * 32 + 25) :: toBigEndian 2 argument := by
  unfold encodeHead; repeat' split
  all_goals first | rfl | omega

/-- **Proves:** for `2¹⁶ ≤ argument < 2³²`, `encodeHead` picks the 4-byte form (info 26).
**How:** as `encodeHead_one_byte_form`. -/
theorem encodeHead_four_byte_form (majorType argument : Nat)
    (hAbove : 2 ^ 16 ≤ argument) (hBelow : argument < 2 ^ 32) :
    encodeHead majorType argument = (majorType * 32 + 26) :: toBigEndian 4 argument := by
  unfold encodeHead; repeat' split
  all_goals first | rfl | omega

/-- **Proves:** for `2³² ≤ argument`, `encodeHead` picks the 8-byte form (info 27). No upper
bound is needed: the last branch of `encodeHead` takes everything that is left.
**How:** as `encodeHead_one_byte_form`. -/
theorem encodeHead_eight_byte_form (majorType argument : Nat) (hAbove : 2 ^ 32 ≤ argument) :
    encodeHead majorType argument = (majorType * 32 + 27) :: toBigEndian 8 argument := by
  unfold encodeHead; repeat' split
  all_goals first | rfl | omega

/-- Shape of an accepted extended-width head.

**Proves:** if one of the info 24‥27 branches of `decodeHead` accepted, giving
`(majorType, argument, rest)`, then `majorType` is the top bits of the initial byte, the
argument bytes were present (`width ≤ tail.length`), the argument passed the minimality check
(`minimum ≤ argument`), it is the number in the next `width` bytes, and `rest` is everything
after them.

**How:** look at what `readArgument` returned (`cases hRead : …`). `none` is impossible,
since `none.map f = none ≠ some _`. For `some (value, after)`, the equation `h` says
`(initialByte / 32, value, after) = (majorType, argument, rest)`; substitute, then
`readArgument_accepted_facts` supplies the rest. -/
theorem decodeHead_extended_facts {width minimum initialByte : Nat} {tail : List Nat}
    {majorType argument : Nat} {rest : List Nat}
    (h : (readArgument width minimum tail).map
        (fun (value, after) => (initialByte / 32, value, after)) =
      some (majorType, argument, rest)) :
    majorType = initialByte / 32 ∧ width ≤ tail.length ∧ minimum ≤ argument ∧
      argument = fromBigEndian (tail.take width) ∧ rest = tail.drop width := by
  cases hRead : readArgument width minimum tail with
  -- Syntax: `cases hRead : e with | none => … | some p => …` does one case per constructor
  -- of `e`'s type and records which one in `hRead` (e.g. `hRead : readArgument … = none`).
  | none => simp [hRead] at h
  | some result =>
    obtain ⟨value, after⟩ := result
    simp only [hRead, Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl, rfl⟩ := h
    have := readArgument_accepted_facts hRead
    exact ⟨rfl, this.1, this.2.1, this.2.2.1, this.2.2.2⟩
    -- Syntax: for `this : A ∧ B ∧ C ∧ D` (which is `A ∧ (B ∧ (C ∧ D))`), `.1` is `A`,
    -- `.2.1` is `B`, `.2.2.1` is `C` and `.2.2.2` is `D`.

/-- **Canonical uniqueness.** Whatever `decodeHead` accepts (for bytes `< 256`) is *exactly*
`encodeHead` of the decoded values followed by the rest.

**Proves:** if `decodeHead bytes = some (majorType, argument, rest)` and every element of
`bytes` is a byte, then `bytes = encodeHead majorType argument ++ rest`. Since `encodeHead` is
a function, each `(majorType, argument)` has exactly one accepted encoding: no non-minimal
argument, no alternative width, no reserved info value gets through. This is the property
the differential-test input `3900ff…` (a non-minimal −256) exercises.

**How:** follow `decodeHead`'s chain of `if`s with `split at h`, one branch at a time:
* float / extended simple value, and info 28‥31: `h` says `none = some …`, impossible;
* info < 24: `majorType = initialByte / 32`, `argument = initialByte % 32`, `rest = tail`.
  `encodeHead` takes its first branch (`argument < 24`) and
  `initialByte = (initialByte / 32) * 32 + initialByte % 32` is division with remainder;
* info 24, 25, 26, 27: `decodeHead_extended_facts` says `argument` is the number in the next
  `width` bytes and at least `minimum`; `prefix_value_fits_width` says it is below
  `256 ^ width`. So `argument` lies in the range where the matching `encodeHead_…_form` lemma
  names the encoder's output, `reencoded_prefix_restores_bytes` shows those bytes re-encode to
  themselves, and only the initial byte is left to compare (`congr 1`, `omega`).
-/
theorem decodeHead_accepts_only_canonical (bytes : List Nat) (majorType argument : Nat)
    (rest : List Nat) (hBytes : ∀ byte ∈ bytes, byte < 256)
    (h : decodeHead bytes = some (majorType, argument, rest)) :
    bytes = encodeHead majorType argument ++ rest := by
  match bytes, hBytes, h with
  -- Syntax: `match` inside a proof pattern-matches on `bytes` and re-states the hypotheses
  -- that mention it. Only the `initialByte :: tail` case is written: for `[]`, `h` would read
  -- `none = some …`, and Lean discards that impossible case by itself.
  | initialByte :: tail, hBytes, h =>
    have hInitialByte : initialByte < 256 := hBytes initialByte (by simp)
    have hTailBytes : ∀ byte ∈ tail, byte < 256 :=
      fun element hMember => hBytes element (by simp [hMember])
    simp only [decodeHead] at h
    split at h
    · simp at h
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      unfold encodeHead
      repeat' split
      all_goals first
        | omega
        | (simp only [List.singleton_append, List.cons.injEq, and_true]; omega)
    split at h
    · obtain ⟨rfl, hLongEnough, hMinimal, rfl, rfl⟩ := decodeHead_extended_facts h
      have hFits := prefix_value_fits_width tail 1 hLongEnough hTailBytes
      rw [encodeHead_one_byte_form _ _ hMinimal (by simpa using hFits), List.cons_append,
        reencoded_prefix_restores_bytes tail 1 hLongEnough hTailBytes]
      congr 1; omega
      -- Syntax: `congr 1` reduces `a :: s = b :: s` to `a = b` (the tails already agree).
    split at h
    · obtain ⟨rfl, hLongEnough, hMinimal, rfl, rfl⟩ := decodeHead_extended_facts h
      have hFits := prefix_value_fits_width tail 2 hLongEnough hTailBytes
      rw [encodeHead_two_byte_form _ _ hMinimal (by simpa using hFits), List.cons_append,
        reencoded_prefix_restores_bytes tail 2 hLongEnough hTailBytes]
      congr 1; omega
    split at h
    · obtain ⟨rfl, hLongEnough, hMinimal, rfl, rfl⟩ := decodeHead_extended_facts h
      have hFits := prefix_value_fits_width tail 4 hLongEnough hTailBytes
      rw [encodeHead_four_byte_form _ _ hMinimal (by simpa using hFits), List.cons_append,
        reencoded_prefix_restores_bytes tail 4 hLongEnough hTailBytes]
      congr 1; omega
    split at h
    · obtain ⟨rfl, hLongEnough, hMinimal, rfl, rfl⟩ := decodeHead_extended_facts h
      rw [encodeHead_eight_byte_form _ _ hMinimal, List.cons_append,
        reencoded_prefix_restores_bytes tail 8 hLongEnough hTailBytes]
      congr 1; omega
    · simp at h

/-- Every accepted head consumes at least one byte.

**Proves:** if `decodeHead bytes = some (majorType, argument, rest)` then `rest` is strictly
shorter than `bytes`. No head is zero-width, so a loop that reads heads always makes
progress through the input.

**How:** the same case analysis as `decodeHead_accepts_only_canonical`. Rejecting branches
are impossible. For an immediate argument `rest` is the tail after the initial byte. For an
extended one `rest = tail.drop width`, which is no longer than `tail`, itself one shorter than
`bytes`. -/
theorem decodeHead_consumes_input {bytes : List Nat} {majorType argument : Nat}
    {rest : List Nat} (h : decodeHead bytes = some (majorType, argument, rest)) :
    rest.length < bytes.length := by
  match bytes, h with
  | initialByte :: tail, h =>
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
      | (obtain ⟨-, hLongEnough, -, -, rfl⟩ := decodeHead_extended_facts h; simp; omega)
      -- `done` fails unless no goal is left, so the first alternative only "succeeds" on the
      -- impossible branches, and the extended-width branches fall through to the second.

end Jotakey.Cbor
