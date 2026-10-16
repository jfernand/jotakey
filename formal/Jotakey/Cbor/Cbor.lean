import Jotakey.Cbor.Heads

/-!
# The strict CTAP2 CBOR decoder

Formal model of `Decoder::skip` in `crates/jotakey-core/src/cbor.rs`, built on the heads of
`Jotakey/Cbor/Heads.lean`. `skipItem` is the whole strict validator: canonical heads,
definite lengths, UTF-8 text, canonically ordered unique map keys, depth ≤ 4, only
`false`/`true`/`null` simple values.

This file has no theorems. Its definitions are the executable specification that
`jotakey-spec` (`Main.lean`) runs in the differential test against the Rust decoder, and the
`#guard`s at the end check them on hand-picked inputs at build time.
-/

namespace Jotakey.Cbor

/-! ## The strict validator (`Decoder::skip`) -/

/-- Maximum container nesting (`MAX_DEPTH`). -/
def maxNestingDepth : Nat := 4

/-- Split off exactly `count` bytes, or fail if fewer remain (`Decoder::read_slice`). -/
def takeExactly (count : Nat) (bytes : List Nat) : Option (List Nat × List Nat) :=
  if bytes.length < count then none else some (bytes.take count, bytes.drop count)

/-- UTF-8 validity, as Rust's `core::str::from_utf8` checks it. -/
def isValidUtf8 (bytes : List Nat) : Bool :=
  -- Syntax: `⟨x⟩` builds a structure from its fields in order (here a `ByteArray` from an
  -- `Array UInt8`), like `ByteArray { data: x }` in Rust.
  ByteArray.validateUTF8 ⟨(bytes.map Nat.toUInt8).toArray⟩

/-- Bytewise lexicographic order: is the first list strictly before the second? -/
def lexicographicLess : List Nat → List Nat → Bool
  -- Syntax: `Bool` is a computable true/false, as in Rust, with `||`, `&&` and `==`. It is
  -- distinct from `Prop` (`∧`, `∨`, `=`), the type of statements that theorems prove.
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | x :: xs, y :: ys => x < y || (x == y && lexicographicLess xs ys)

/-- CTAP2 canonical key order: shorter encoding first, then bytewise. -/
def canonicalKeyLess (first second : List Nat) : Bool :=
  first.length < second.length ||
    (first.length == second.length && lexicographicLess first second)

/-- A map key: integer fitting in `i64`, or valid text. Returns the rest of the input. -/
def readMapKey (bytes : List Nat) : Option (List Nat) :=
  match decodeHead bytes with
  -- Syntax: patterns nest, as in Rust: `some (0, argument, rest)` matches only a decoded
  -- head whose major type is 0, binding the argument and the remainder. `_` matches
  -- anything left over.
  | some (0, argument, rest) => if argument < 2 ^ 63 then some rest else none
  | some (1, argument, rest) => if argument < 2 ^ 63 then some rest else none
  | some (3, length, rest) =>
    match takeExactly length rest with
    | some (text, afterText) => if isValidUtf8 text then some afterText else none
    | none => none
  | _ => none

-- Syntax: `mutual … end` groups definitions that call each other (an array holds items, an
-- item may be an array). Lean accepts recursive definitions only if it can see they
-- terminate. Each `termination_by` gives a *measure*: a value that must get smaller at every
-- recursive call. Here the measures are pairs, compared lexicographically (first component
-- first, the second breaking ties):
--   * skipItem (fuel+1) → skipArray/skipMap fuel:   (fuel+1, 0) > (fuel, count+1)  first drops;
--   * skipArray/skipMap fuel (count+1) → skipItem:   (fuel, count+1) > (fuel, 0)    second drops;
--   * skipArray/skipMap fuel (count+1) → itself:     (fuel, count+1) > (fuel, count).
-- So every call chain ends, and Lean checks this before accepting the definitions.
mutual
/-- Validate one complete data item at nesting `depth`; return the remaining input.
`fuel` only bounds nesting (it decreases on entering a container) and is never the
binding limit when ≥ `maxNestingDepth + 2`. -/
def skipItem : Nat → Nat → List Nat → Option (List Nat)
  | 0, _, _ => none
  | fuel + 1, depth, bytes =>
    match decodeHead bytes with
    | none => none
    | some (majorType, argument, rest) =>
      if majorType == 0 || majorType == 1 then some rest
      -- Syntax: `(·.2)` is shorthand for `fun p => p.2`: keep the second half of the pair.
      else if majorType == 2 then (takeExactly argument rest).map (·.2)
      else if majorType == 3 then
        match takeExactly argument rest with
        | some (text, afterText) => if isValidUtf8 text then some afterText else none
        | none => none
      else if majorType == 4 then
        if depth + 1 > maxNestingDepth then none else skipArray fuel (depth + 1) argument rest
      else if majorType == 5 then
        if depth + 1 > maxNestingDepth then none
        else skipMap fuel (depth + 1) argument [] false rest
      else if majorType == 7 then
        if argument == 20 || argument == 21 || argument == 22 then some rest else none
      else none
  termination_by fuel _ _ => (fuel, 0)
  -- `fuel _ _ =>` names the function's three arguments (the first is the whole fuel, i.e.
  -- `fuel + 1` in the second pattern above); `_` ignores the other two.

/-- Validate `count` consecutive items. -/
def skipArray : Nat → Nat → Nat → List Nat → Option (List Nat)
  | _, _, 0, bytes => some bytes
  | fuel, depth, count + 1, bytes =>
    match skipItem fuel depth bytes with
    | none => none
    | some rest => skipArray fuel depth count rest
  termination_by fuel _ count _ => (fuel, count + 1)

/-- Validate `count` key/value pairs; keys strictly increasing in canonical order.
`previousKey` holds the encoded bytes of the last key read, if `hasPreviousKey`. -/
def skipMap : Nat → Nat → Nat → List Nat → Bool → List Nat → Option (List Nat)
  | _, _, 0, _, _, bytes => some bytes
  | fuel, depth, count + 1, previousKey, hasPreviousKey, bytes =>
    match readMapKey bytes with
    | none => none
    | some afterKey =>
      let keyBytes := bytes.take (bytes.length - afterKey.length)
      -- `keyBytes` is the key's own encoding: what `readMapKey` consumed.
      if hasPreviousKey && !canonicalKeyLess previousKey keyBytes then none
      else
        match skipItem fuel depth afterKey with
        | none => none
        | some afterValue => skipMap fuel depth count keyBytes true afterValue
  termination_by fuel _ count _ _ _ => (fuel, count + 1)
end

/-- `Decoder::new(bytes).skip(0)`: `some consumed` if the input starts with one valid item. -/
def validate (bytes : List Nat) : Option Nat :=
  (skipItem (maxNestingDepth + 2) 0 bytes).map fun rest => bytes.length - rest.length

/-! ### Sanity checks, evaluated at build time (`#guard` fails the build if false) -/

-- Syntax: `0xa2` is a hexadecimal `Nat` literal, as in Rust.
#guard validate [0xa2, 0x01, 0x00, 0x02, 0x00] == some 5       -- {1: 0, 2: 0}
#guard validate [0xa2, 0x02, 0x00, 0x01, 0x00] == none         -- keys out of order
#guard validate [0xa2, 0x01, 0x00, 0x01, 0x00] == none         -- duplicate key
#guard validate [0x81, 0x81, 0x81, 0x81, 0x00] == some 5       -- depth 4: allowed
#guard validate [0x81, 0x81, 0x81, 0x81, 0x81, 0x00] == none   -- depth 5: too deep
#guard validate [0x18, 0x17] == none                           -- 23 in two bytes: not minimal
#guard validate [0x5f] == none                                 -- indefinite-length bytes
#guard validate [0xf9, 0x3c, 0x00] == none                     -- half-precision float 1.0
#guard validate [0xf5, 0x00] == some 1                         -- `true`; trailing byte left

end Jotakey.Cbor
