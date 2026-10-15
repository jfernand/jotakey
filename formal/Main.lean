import Jotakey.Cbor

/-!
# `jotakey-spec`: the executable CBOR specification

Used by `crates/jotakey-core/tests/differential.rs`. One query per line on stdin:

```
validate <hex>   →  ok <consumed> | err        (Decoder::skip(0) on the input)
head <hex>       →  ok <major> <arg> <consumed> | err   (Decoder::head)
```

The answers come from the very definitions the theorems in `Jotakey/Cbor.lean` are about,
so agreement with Rust on many inputs ties the proofs to the shipped decoder.
-/

open Jotakey.Cbor

def hexDigit (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

def parseHex : List Char → Option (List Nat)
  | [] => some []
  | a :: b :: rest => do
    let hi ← hexDigit a
    let lo ← hexDigit b
    let tl ← parseHex rest
    pure ((hi * 16 + lo) :: tl)
  | [_] => none

def answer (line : String) : String :=
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

partial def loop (stdin : IO.FS.Stream) (stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return
  stdout.putStrLn (answer line)
  loop stdin stdout

def main : IO Unit := do
  let stdout ← IO.getStdout
  loop (← IO.getStdin) stdout
  stdout.flush
