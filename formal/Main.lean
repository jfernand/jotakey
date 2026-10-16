import Jotakey.Cbor.Cbor

/-!
# `jotakey-spec`: the executable CBOR specification

Used by `crates/jotakey-core/tests/differential.rs`. One query per line on stdin:

```
validate <hex>   →  ok <consumed> | err        (Decoder::skip(0) on the input)
head <hex>       →  ok <major> <arg> <consumed> | err   (Decoder::head)
```

The answers come from the very definitions the theorems in `Jotakey/Cbor/` (`Heads.lean`, `Cbor.lean`) are about,
so agreement with Rust on many inputs ties the proofs to the shipped decoder.
-/

open Jotakey.Cbor
-- Syntax: `open` lets us write `validate` instead of `Jotakey.Cbor.validate` (Rust's `use`).

def hexDigit (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

def parseHex : List Char → Option (List Nat)
  | [] => some []
  -- Syntax: `do` notation in `Option`: each `let x ← e` unwraps `e`, or returns `none` from
  -- the whole block if `e` is `none` (Rust's `let x = e?;`). `pure v` is `some v`.
  | a :: b :: rest => do
    let hi ← hexDigit a
    let lo ← hexDigit b
    let tl ← parseHex rest
    pure ((hi * 16 + lo) :: tl)
  | [_] => none

def answer (line : String) : String :=
  -- Syntax: list patterns such as `["validate", hex]` match a list of exactly two strings, the
  -- first being "validate". `s!"ok {n}"` is string interpolation (Rust's `format!`).
  match line.trimAscii.toString.splitOn " " with
  | ["validate", hex] =>
    match parseHex hex.toList with
    | some bytes => match validate bytes with
      | some n => s!"ok {n}"
      | none => "err"
    | none => "bad"
  | ["validate"] => match validate [] with
      | some n => s!"ok {n}"
      | none => "err"
  | ["head", hex] =>
    match parseHex hex.toList with
    | some bytes => match decodeHead bytes with
      | some (m, a, r) => s!"ok {m} {a} {bytes.length - r.length}"
      | none => "err"
    | none => "bad"
  | ["head"] => "err"
  | _ => "bad"

-- Syntax: `partial def` lets a function recurse without a termination proof (it reads until
-- end of input). Lean then refuses to unfold it inside proofs, which is fine: no theorem is
-- about `loop`. `IO Unit` is the type of a program with side effects returning nothing; in
-- an `IO` `do` block, `let x ← act` runs `act` and binds its result, and `(← act)` does the
-- same inline.
partial def loop (stdin : IO.FS.Stream) (stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return
  stdout.putStrLn (answer line)
  loop stdin stdout

def main : IO Unit := do
  let stdout ← IO.getStdout
  loop (← IO.getStdin) stdout
  stdout.flush
