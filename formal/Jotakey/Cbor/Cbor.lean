import Jotakey.Cbor.Heads

/-!
# The strict CTAP2 CBOR decoder

Formal model of `Decoder::skip` in `crates/jotakey-core/src/cbor.rs`, built on the heads of
`Jotakey/Cbor/Heads.lean`. `skipItem` is the whole strict validator: canonical heads,
definite lengths, UTF-8 text, canonically ordered unique map keys, depth ≤ 4, only
`false`/`true`/`null` simple values.
-/

namespace Jotakey.Cbor

/-! ## The strict validator (`Decoder::skip`) -/

/-- Maximum container nesting (`MAX_DEPTH`). -/
def maxDepth : Nat := 4

/-- Split off exactly `n` bytes, or fail if fewer remain (`Decoder::read_slice`). -/
def takeN (n : Nat) (l : List Nat) : Option (List Nat × List Nat) :=
  if l.length < n then none else some (l.take n, l.drop n)

/-- UTF-8 validity, as Rust's `core::str::from_utf8` checks it. -/
def validUtf8 (l : List Nat) : Bool :=
  ByteArray.validateUTF8 ⟨(l.map Nat.toUInt8).toArray⟩

/-- Bytewise lexicographic order. -/
def lexLt : List Nat → List Nat → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => a < b || (a == b && lexLt as bs)

/-- CTAP2 canonical key order: shorter encoding first, then bytewise. -/
def canonicalLt (a b : List Nat) : Bool :=
  a.length < b.length || (a.length == b.length && lexLt a b)

/-- A map key: integer fitting in `i64`, or valid text. Returns the rest of the input. -/
def readKey (l : List Nat) : Option (List Nat) :=
  match decodeHead l with
  | some (0, a, r) => if a < 2 ^ 63 then some r else none
  | some (1, a, r) => if a < 2 ^ 63 then some r else none
  | some (3, a, r) =>
    match takeN a r with
    | some (t, r') => if validUtf8 t then some r' else none
    | none => none
  | _ => none

mutual
/-- Validate one complete data item at nesting `depth`; return the remaining input.
`fuel` only bounds nesting (it decreases on entering a container) and is never the
binding limit when ≥ `maxDepth + 2`. -/
def skipItem : Nat → Nat → List Nat → Option (List Nat)
  | 0, _, _ => none
  | fuel + 1, depth, l =>
    match decodeHead l with
    | none => none
    | some (m, a, r) =>
      if m == 0 || m == 1 then some r
      else if m == 2 then (takeN a r).map (·.2)
      else if m == 3 then
        match takeN a r with
        | some (t, r') => if validUtf8 t then some r' else none
        | none => none
      else if m == 4 then
        if depth + 1 > maxDepth then none else skipArray fuel (depth + 1) a r
      else if m == 5 then
        if depth + 1 > maxDepth then none else skipMap fuel (depth + 1) a [] false r
      else if m == 7 then
        if a == 20 || a == 21 || a == 22 then some r else none
      else none
  termination_by fuel _ _ => (fuel, 0)

/-- Validate `n` consecutive items. -/
def skipArray : Nat → Nat → Nat → List Nat → Option (List Nat)
  | _, _, 0, l => some l
  | fuel, depth, n + 1, l =>
    match skipItem fuel depth l with
    | none => none
    | some r => skipArray fuel depth n r
  termination_by fuel _ n _ => (fuel, n + 1)

/-- Validate `n` key/value pairs; keys strictly increasing in canonical order. -/
def skipMap : Nat → Nat → Nat → List Nat → Bool → List Nat → Option (List Nat)
  | _, _, 0, _, _, l => some l
  | fuel, depth, n + 1, prev, hasPrev, l =>
    match readKey l with
    | none => none
    | some r =>
      let raw := l.take (l.length - r.length)
      if hasPrev && !canonicalLt prev raw then none
      else
        match skipItem fuel depth r with
        | none => none
        | some r' => skipMap fuel depth n raw true r'
  termination_by fuel _ n _ _ _ => (fuel, n + 1)
end

/-- `Decoder::new(l).skip(0)`: `some consumed` if the input starts with one valid item. -/
def validate (l : List Nat) : Option Nat :=
  (skipItem (maxDepth + 2) 0 l).map fun r => l.length - r.length

/-! ### Sanity checks, evaluated at build time (`#guard` fails the build if false) -/

#guard validate [0xa2, 0x01, 0x00, 0x02, 0x00] == some 5
#guard validate [0xa2, 0x02, 0x00, 0x01, 0x00] == none
#guard validate [0xa2, 0x01, 0x00, 0x01, 0x00] == none
#guard validate [0x81, 0x81, 0x81, 0x81, 0x00] == some 5
#guard validate [0x81, 0x81, 0x81, 0x81, 0x81, 0x00] == none
#guard validate [0x18, 0x17] == none
#guard validate [0x5f] == none
#guard validate [0xf9, 0x3c, 0x00] == none
#guard validate [0xf5, 0x00] == some 1

end Jotakey.Cbor
