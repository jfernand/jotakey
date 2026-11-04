-- (c) Javier Fernandez @ JotaSoft 2026
import Jotakey.Cbor.Cbor
import Jotakey.Presence
import Jotakey.RecordLog

/-!
# `jotakey-spec`: the executable CBOR specification

Used by `crates/jotakey-core/tests/differential.rs`. One query per line on stdin:

```
validate <hex>   →  ok <consumed> | err        (Decoder::skip(0) on the input)
head <hex>       →  ok <major> <arg> <consumed> | err   (Decoder::head)
presence <start> <ms>:<0|1> ...  →  <w|c|t> ...  (PresenceGate::new, then poll per reading)
append <sector0> <sector1>  →  <sequence> <sector0> <sector1>  (mount, then one append that
                                completes; a sector is a comma list of slots `e`, `t`, `<seq>`)
```

The answers come from the very definitions the theorems in `Jotakey/Cbor/` (`Heads.lean`,
`Cbor.lean`), `Presence.lean` and `RecordLog.lean` are about, so agreement with Rust on many
inputs ties the proofs to the shipped code.
-/

open Jotakey.Cbor
-- Syntax: `open` lets us write `validate` instead of `Jotakey.Cbor.validate` (Rust's `use`).

def hexDigit (digit : Char) : Option Nat :=
  if '0' ≤ digit ∧ digit ≤ '9' then some (digit.toNat - '0'.toNat)
  else if 'a' ≤ digit ∧ digit ≤ 'f' then some (digit.toNat - 'a'.toNat + 10)
  else if 'A' ≤ digit ∧ digit ≤ 'F' then some (digit.toNat - 'A'.toNat + 10)
  else none

def parseHex : List Char → Option (List Nat)
  | [] => some []
  -- Syntax: `do` notation in `Option`: each `let x ← e` unwraps `e`, or returns `none` from
  -- the whole block if `e` is `none` (Rust's `let x = e?;`). `pure v` is `some v`.
  | highDigit :: lowDigit :: rest => do
    let high ← hexDigit highDigit
    let low ← hexDigit lowDigit
    let restBytes ← parseHex rest
    pure ((high * 16 + low) :: restBytes)
  | [_] => none

def stepLetter : Jotakey.Presence.Step → String
  | .waiting => "w"
  | .confirmed => "c"
  | .timeout => "t"

/-- Parse `<ms>:<0|1>`. -/
def parseReading (word : String) : Option (Nat × Bool) :=
  match word.splitOn ":" with
  | [ms, "0"] => ms.toNat?.map (·, false)
  | [ms, "1"] => ms.toNat?.map (·, true)
  | _ => none

/-- Poll a fresh gate with each reading in order (oldest first, as they arrive). -/
def presenceSteps (gate : Jotakey.Presence.Gate) : List (Nat × Bool) → List String
  | [] => []
  | (nowMs, pressed) :: later =>
    let (gate', step) := Jotakey.Presence.poll gate nowMs pressed
    stepLetter step :: presenceSteps gate' later

def parseSlot (word : String) : Option Jotakey.RecordLog.Slot :=
  if word == "e" then some .erased
  else if word == "t" then some .torn
  else word.toNat?.map .record

def showSlot : Jotakey.RecordLog.Slot → String
  | .erased => "e"
  | .torn => "t"
  | .record sequence => toString sequence

def parseSector (word : String) : Option (List Jotakey.RecordLog.Slot) :=
  (word.splitOn ",").mapM parseSlot

def showSector (slots : List Jotakey.RecordLog.Slot) : String :=
  ",".intercalate (slots.map showSlot)

/-- Mount, then the append that completes (`AppendStep.ok`). -/
def appendAnswer (zero one : List Jotakey.RecordLog.Slot) : String :=
  open Jotakey.RecordLog in
  let capacity := zero.length
  let flash : Flash := ⟨zero, one⟩
  let log := mount flash
  let (sector, erase, slot) := target capacity log
  let flash' := flash.set sector (written capacity (flash.get sector) erase slot (log.latest + 1))
  s!"{log.latest + 1} {showSector flash'.zero} {showSector flash'.one}"

def answer (line : String) : String :=
  -- Syntax: list patterns such as `["validate", hex]` match a list of exactly two strings, the
  -- first being "validate". `s!"ok {consumed}"` is string interpolation (Rust's `format!`).
  match line.trimAscii.toString.splitOn " " with
  | ["validate", hex] =>
    match parseHex hex.toList with
    | some bytes => match validate bytes with
      | some consumed => s!"ok {consumed}"
      | none => "err"
    | none => "bad"
  | ["validate"] => match validate [] with
      | some consumed => s!"ok {consumed}"
      | none => "err"
  | ["head", hex] =>
    match parseHex hex.toList with
    | some bytes => match decodeHead bytes with
      | some (majorType, argument, rest) =>
        s!"ok {majorType} {argument} {bytes.length - rest.length}"
      | none => "err"
    | none => "bad"
  | ["head"] => "err"
  | "presence" :: start :: readings =>
    match start.toNat?, readings.mapM parseReading with
    | some startMs, some parsed => " ".intercalate (presenceSteps (Jotakey.Presence.start startMs) parsed)
    | _, _ => "bad"
  | ["append", zero, one] =>
    match parseSector zero, parseSector one with
    | some zero, some one =>
      if zero.length = one.length ∧ 0 < zero.length then appendAnswer zero one else "bad"
    | _, _ => "bad"
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
