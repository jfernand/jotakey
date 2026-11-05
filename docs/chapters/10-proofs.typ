// (c) Javier Fernandez @ JotaSoft 2026
#import "../isss-template.typ": *
#import "../lib.typ": *

= The proofs

Chapter 9 explained what formal verification is and showed the headline results. This
chapter is the companion for reading the proofs themselves. It goes through every theorem
in `formal/`, in the order the files are best read, and for each one gives the statement,
what it means, how the proof works, and which later theorem relies on it. The source files
carry the same explanations in their doc comments (*Proves* and *How*), so the chapter and
the code can be read side by side.

There are 85 theorems in eight files. Most are *lemmas*: stepping stones, proved because a
bigger proof needs them. Following the dependencies from each lemma to the theorems that
use it, we eventually reach theorems that nothing else uses. These are the *key theorems*:
the conclusions the whole development exists to establish. There are twenty-four.

#let inv(body) = text(size: 7pt, fill: fg-muted)[#body]

#dtable(
  columns: (1.25fr, 1fr),
  ("Key theorem: what it says", "Why it matters"),
  ([`decodeHead_accepts_only_canonical` #inv[· invariant 4] \ Whatever the decoder accepts is exactly the canonical encoding of what it returned.],
    [No value has two accepted encodings, so two parties can never read the same bytes differently. This removes a whole class of parser-confusion attacks.]),
  ([`decodeHead_inverts_encodeHead` #inv[· invariant 4] \ Decoding an encoded head returns what was encoded and leaves the rest untouched.],
    [The strictness above does not reject anything legitimate: every canonical head is accepted.]),
  ([`decodeHead_consumes_input` #inv[· invariant 4] \ Every accepted head consumes at least one byte.],
    [Reading cannot stall in place. This is the basis of the decoder's time bound.]),
  ([`receivePackets_ignores_other_channels` #inv[· invariant 5] \ Packets on other channels never change a transaction in progress.],
    [Malware talking to the key on its own channel cannot inject into, truncate or abort another program's request.]),
  ([`receivePackets_preserves_well_formed` #inv[· invariant 4] \ After any packet sequence, buffers are within the announced length and 1200 bytes.],
    [Memory use is bounded by a constant, whatever the host sends. Firmware without a heap needs exactly this.]),
  ([`fragmented_message_is_reassembled` #inv[· functional] \ A correctly fragmented message is delivered intact.],
    [It rules out a model that is "safe" only because it accepts nothing (see below).]),
  ([`one_touch_signs_at_most_once` #inv[· invariant 1] \ One touch completes at most one command.],
    [Malware cannot queue a second signature behind a touch the user gave for something else.]),
  ([`trace_signature_counters_increase` #inv[· invariant 2] \ In any sequence of events, signature counters strictly increase.],
    [Relying parties use the counter to detect cloned keys. A repeated or decreasing counter would raise false alarms or hide a clone.]),
  ([`epoch_change_requires_reset_in_window` #inv[· invariant 6] \ The reset epoch changes only if a reset request arrived in the first 10 s after power-up.],
    [Software on the host cannot wipe every credential remotely. A reset needs the key to be replugged.]),
  ([`faulted_stays_faulted_and_never_signs` #inv[· invariant 7] \ A faulted device stays faulted and never signs.],
    [Fail closed: after a self-test failure, no signature is produced from possibly broken crypto.]),
  ([`unwrap_recovers_nonce` #inv[· functional] \ A credential ID unwraps, at its own site, to the nonce it was minted with.],
    [Legitimate credentials keep working. This is the anti-vacuity partner of the next theorem.]),
  ([`credential_bound_to_relying_party` #inv[· invariant 3] \ An ID minted for one relying party is rejected at any other, assuming the MAC does not collide.],
    [Phishing resistance at the credential level: an ID is useless outside the site that created it.]),
  ([`wrong_pins_between_successes_le_eight` #inv[· invariant 10] \ At most 8 wrong PINs are compared between correct entries, whatever happens in between.],
    [A thief gets 8 guesses at the PIN, not 10 000. Power cycles and interrupted attempts do not add any.]),
  ([`wrong_pins_in_a_row_le_three` #inv[· invariant 10] \ At most 3 wrong PINs in a row without a power cycle.],
    [Guessing runs at the pace of a human unplugging the key.]),
  ([`blocked_until_reset` #inv[· invariant 10] \ A blocked PIN accepts nothing until a reset.],
    [The only way past a blocked PIN is a reset, which also ends every credential.]),
  ([`comparison_needs_a_counted_retry` #inv[· invariant 10] \ A PIN is compared only after a retry was counted for it.],
    [The rule that makes the counter mean something; the Rust side checks the same order.]),
  ([`press_held_from_the_start_never_confirms` #inv[· invariant 1] \ A button or electrode pressed at every reading since the request never confirms.],
    [A taped-down button, or a finger left on the key after an earlier request, cannot approve anything.]),
  ([`timeout_at_deadline` #inv[· invariant 1] \ A reading at or past the 30 s deadline times out.],
    [A request waiting for a touch cannot be kept open indefinitely, to catch a touch meant for something else.]),
  ([`timeout_is_final` #inv[· invariant 1] \ After one reading past the deadline, every later poll times out, whatever time it reports.],
    [A clock that jumps back cannot reopen a request that already timed out.]),
  ([`confirmed_strictly_increases` #inv[· invariant 2] \ Through any appends, power cuts and remounts, each confirmed counter value exceeds the previous one.],
    [The persistence step under the counter: pulling the plug at any moment cannot make the key repeat a counter value.]),
  ([`live_needs_check` #inv[· invariants 2, 7] \ The OPTIGA session is live only if, since the last handshake, a live-session check came back right.],
    [A recorded session replayed on the bus never becomes live, so its old answers are never used.]),
  ([`used_needs_live` #inv[· invariants 2, 7] \ A response from the OPTIGA is used only in a live session, and only if it authenticated and is in the sequence window.],
    [Nothing a bus attacker forges or replays reaches the authenticator.]),
  ([`used_strictly_increase` #inv[· invariants 2, 7] \ Within a session, the sequence numbers of the responses used strictly increase.],
    [No response is used twice or out of order, so an old answer cannot stand in for a new one.]),
  ([`released_strictly_increase` #inv[· invariant 2] \ The counter values the key releases strictly increase, whatever values are read back.],
    [On the key, even an OPTIGA that misbehaved could not make it sign with a counter that went back.]),
)

The invariant numbers are those of `AGENTS.md`, §2. Two of the key theorems prove no
security invariant: `fragmented_message_is_reassembled` and `unwrap_recovers_nonce`. They are there because safety properties are easy to satisfy by doing nothing.
A device that dropped every packet would trivially satisfy channel isolation and bounded
memory. A device that rejected every credential ID could never sign for the wrong site.
*Functional* theorems like these two show the model also does its job, so the safety
theorems are not true for an empty reason.

"Nothing else uses it" is a good way to find the conclusions, but it is not a definition
of importance. Seven lemmas deserve the same attention, even though another theorem builds
on them:

- `signature_requires_confirmed_touch` *is* invariant 1, the most important property of
  the device: no signature without a confirmed touch, for the parked relying party. It
  drops off the key list only because `one_touch_signs_at_most_once` is proved from it.
- `receivePacket_preserves_well_formed` is the statement for a single packet. It matches
  what each call of the Rust `handle_packet` must preserve, and
  `receivePackets_preserves_well_formed` extends it to any sequence of packets.
- `epoch_change_requires_confirmed_touch` is the other half of invariant 6: a reset needs
  a *touch*, as well as the time window.
- `unwrap_accepts_only_wrapped_ids` says that `unwrap` accepts nothing but `wrap`'s own
  outputs, with no assumption about the MAC at all. `credential_bound_to_relying_party` is
  a corollary.
- `confirmed_needs_release_then_debounced_press` is the main statement about the presence
  gate (a confirmation needs a release, then a debounced press, all before the deadline);
  `press_held_from_the_start_never_confirms` is its corollary.
- `trace_never_loses_confirmed` is the main statement about the record log (the latest
  record on flash is never below the last confirmed one); `confirmed_strictly_increases`
  is proved from it.
- `accept_needs_everything` is the shielded session's acceptance rule itself: a response is
  accepted only with the record header, a sequence number in the window and a tag that
  verifies, and outside the live-session check only in a live session.

All twenty-four key theorems and these seven are listed in `formal/AxiomAudit.lean`, which checks
on every build that they rest only on Lean's three standard axioms (§9.3). The panels
below show which theorem is proved from which; key theorems are at the left margin.

#codepanel(title: "Who uses whom: CBOR heads (each line is proved using the lines below it)")[
```
decodeHead_inverts_encodeHead
└─ readArgument_reads_encoded
   ├─ toBigEndian_length ─ toLittleEndian_length
   └─ bigEndian_number_roundtrip ─ littleEndian_number_roundtrip
decodeHead_accepts_only_canonical
├─ reencoded_prefix_restores_bytes
│  └─ bigEndian_bytes_roundtrip ─ littleEndian_bytes_roundtrip
├─ prefix_value_fits_width
│  └─ fromBigEndian_fits_width ─ fromLittleEndian_fits_width
├─ encodeHead_one_byte_form, _two_byte_form, _four_byte_form, _eight_byte_form
└─ decodeHead_extended_facts ─ readArgument_accepted_facts
decodeHead_consumes_input
└─ decodeHead_extended_facts
```
]

#codepanel(title: "Who uses whom: CTAPHID, authenticator, credentials, PIN")[
```
receivePackets_ignores_other_channels ─ receivePacket_ignores_other_channels
receivePackets_preserves_well_formed
└─ receivePacket_preserves_well_formed ─ deliverIfComplete_is_well_formed
fragmented_message_is_reassembled
├─ continuations_complete_message (and itself, on a shorter remainder)
└─ trimming_keeps_host_payload, continuationPackets_of_empty

one_touch_signs_at_most_once
├─ signature_requires_confirmed_touch ─ processRequest_never_signs_with_presence
├─ completePresence_signs_with_presence
└─ completePresence_clears_pending
trace_signature_counters_increase
├─ trace_signature_counters_bounded
│  └─ runTrace_never_lowers_counter ─ handleEvent_never_lowers_counter
└─ signature_carries_next_counter
epoch_change_requires_reset_in_window
└─ epoch_change_requires_confirmed_touch, parked_reset_was_requested_in_window,
   completePresence_clears_pending
faulted_stays_faulted_and_never_signs   (direct)

unwrap_recovers_nonce                   (direct)
credential_bound_to_relying_party ─ unwrap_accepts_only_wrapped_ids

wrong_pins_between_successes_le_eight
└─ runTrace_keeps_budget ─ handleEvent_keeps_budget ─ attempt_keeps_budget
wrong_pins_in_a_row_le_three
└─ runTrace_keeps_streak ─ handleEvent_keeps_streak ─ attempt_keeps_streak
blocked_until_reset ─ blocked_step
comparison_needs_a_counted_retry        (direct)
```
]

#codepanel(title: "Who uses whom: presence gate, record log")[
```
press_held_from_the_start_never_confirms
└─ confirmed_needs_release_then_debounced_press ─ gateAfter_accounts
timeout_at_deadline ─ gateAfter_accounts
timeout_is_final ─ gateAfter_accounts

confirmed_strictly_increases
├─ trace_never_loses_confirmed
│  ├─ mount_fits ─ scanEnd_le_length, erased_from_scanEnd
│  ├─ append_ok ─ le_latestOf, maxSequence_le, le_maxSequence, maxSequence_mem
│  ├─ append_preserves_latest ─ latest_located, le_latestOf, get_set_other
│  └─ cut_lengths
└─ append_ok
```
]

#codepanel(title: "Who uses whom: the OPTIGA session and counter")[
```
live_needs_check ─ accept_moves_forward ─ accept_needs_everything
used_needs_live ─ accept_needs_everything
used_strictly_increase
├─ used_bounded ─ accept_moves_forward, accept_needs_everything
└─ accept_moves_forward, accept_needs_everything
released_strictly_increase ─ released_le_mark
```
]

The reading order follows the files: numbers and bytes first (§10.2), then CBOR heads
(§10.3) and the validator built on them (§10.4), CTAPHID (§10.5), the authenticator state
machine (§10.6), credential IDs (§10.7), the PIN lockout (§10.8), the presence gate
(§10.9), the record log (§10.10) and the OPTIGA session (§10.11). §10.12 lists what the
proofs leave out, and §10.13 maps
every Rust name to its Lean counterpart. The Lean
syntax is introduced in the same order in the comments of the source files, and
`formal/Jotakey.lean` repeats the order.

== Before you start

The best way to read a Lean proof is in an editor. With the Lean 4 extension for VS Code,
open the `formal/` folder, place the cursor on any line of a proof, and the *infoview*
panel shows the hypotheses available at that point and the goal still to be proved. A
proof that seems cryptic on paper becomes a sequence of small, visible steps. The tactics
used are summarised in §9.3; `omega` (linear arithmetic) and `simp` (rewriting) do most of
the routine work.

Four conventions run through all the files:

- *Names say what things are.* Functions are named after what they do (`receivePacket`,
  `completePresence`), theorems after what they state
  (`decodeHead_accepts_only_canonical`), and variables after what they hold (`width`,
  `relyingParty`, `nextSequence`). The one deliberate exception is `ih`, the conventional
  name for an induction hypothesis. The Rust code follows the same rule in its own
  conventions; §10.13 translates between the two.
- *Hypotheses are arguments.* `(hFits : value < 256 ^ width)` in a theorem's signature
  means "assuming the value fits in `width` bytes". Hypothesis names start with `h` and
  say what they assume. Calling the theorem requires a proof of each, so every assumption
  is visible where the theorem is used.
- *Bytes are natural numbers.* The models use `List Nat` for byte strings. Where a theorem
  needs real bytes, it says so with `(hBytes : ∀ byte ∈ bytes, byte < 256)`. In Rust the
  type `u8` guarantees this, so the hypothesis always holds for the real code.
- *Inversion lemmas.* Several lemmas start from "the function returned `some …`" and
  conclude what the input must have looked like. The proof follows the function's
  branches with `split at h`, throws away the branches that return `none`, and reads the
  facts off the branch that remains. `readArgument_accepted_facts`,
  `decodeHead_extended_facts`, `parked_reset_was_requested_in_window` and
  `unwrap_accepts_only_wrapped_ids` all work this way.

== Bytes and numbers

*File:* `formal/Jotakey/Cbor/Heads.lean`, first half. CBOR stores multi-byte arguments
big-endian. Before we can say anything about heads, we need four conversion functions and
the facts relating them.

#codepanel(title: "Heads.lean: the conversion functions")[
```lean
def toLittleEndian : Nat → Nat → List Nat    -- the low `width` bytes of `value`
  | 0,         _     => []
  | width + 1, value => value % 256 :: toLittleEndian width (value / 256)

def fromLittleEndian : List Nat → Nat        -- little-endian bytes to a number
  | [] => 0
  | byte :: tail => byte + 256 * fromLittleEndian tail

def toBigEndian (width value : Nat) : List Nat := (toLittleEndian width value).reverse
def fromBigEndian (bytes : List Nat) : Nat := fromLittleEndian bytes.reverse
```
]

The big-endian functions are defined through the little-endian ones and `reverse`. That
is a deliberate modelling choice. Little-endian functions peel one byte off the front of a
list, which is exactly the shape of a list induction. Every big-endian fact then follows
from its little-endian twin plus the library facts that `reverse` keeps length and
membership and undoes itself. Eight theorems come in four pairs:

#dtable(
  columns: (1.3fr, 2.2fr),
  ("Theorems", "Statement"),
  ([`toLittleEndian_length`, \ `toBigEndian_length`], [The conversion always produces exactly `width` bytes.]),
  ([`littleEndian_number_roundtrip`, \ `bigEndian_number_roundtrip`], [If `value < 256 ^ width`, converting it to `width` bytes and back gives `value`: a number that fits survives the round trip.]),
  ([`fromLittleEndian_fits_width`, \ `fromBigEndian_fits_width`], [For a list of bytes, the number it holds is `< 256 ^ bytes.length`: `k` bytes always hold a number that fits in `k` bytes.]),
  ([`littleEndian_bytes_roundtrip`, \ `bigEndian_bytes_roundtrip`], [For a list of bytes, converting to a number and back to the same width gives the same list: bytes survive the round trip.]),
)

*`toLittleEndian_length`.* Induction on `width`, for every `value` (`generalizing value`,
because the recursive call is at `value / 256`, not `value`). For `0` the list is empty.
For `width + 1` the list is one byte followed by `toLittleEndian width (value / 256)`, whose
length the induction hypothesis gives as `width`. *`toBigEndian_length`* is one `simp`
call: `toBigEndian` reverses, reversing keeps length, done. Used by
`readArgument_reads_encoded`.

*`littleEndian_number_roundtrip`.* Its hypothesis, that `value` fits in `width` bytes, is
essential. For example, one byte of 1000 is `toLittleEndian 1 1000 = [232]`, which reads
back as 232, not 1000: without the hypothesis the high bytes are cut off. The proof is
induction on `width`:

#codepanel(title: "Heads.lean")[
```lean
theorem littleEndian_number_roundtrip (width value : Nat) (hFits : value < 256 ^ width) :
    fromLittleEndian (toLittleEndian width value) = value := by
  induction width generalizing value with
  | zero => simp [toLittleEndian, fromLittleEndian]; omega      -- value < 1, so value = 0
  | succ width ih =>
    have hQuotientFits : value / 256 < 256 ^ width := by       -- the rest fits in width bytes
      rw [Nat.pow_succ] at hFits
      exact (Nat.div_lt_iff_lt_mul (by decide)).mpr hFits
    simp only [toLittleEndian, fromLittleEndian, ih _ hQuotientFits]
    omega                                -- value % 256 + 256 * (value / 256) = value
```
]

In the `succ` case the induction hypothesis can only be used for numbers that fit in
`width` bytes, so the proof first shows that `value / 256` does (`hQuotientFits`).
Unfolding one step of each function, and replacing the inner round trip by `value / 256`,
leaves `value % 256 + 256 * (value / 256) = value`, which is division with remainder, and
`omega` knows it. *`bigEndian_number_roundtrip`* reduces to it because the two `reverse`s
cancel. Used by `readArgument_reads_encoded`.

*`fromLittleEndian_fits_width`.* Induction on the list. The empty list gives `0 < 1`. For
`byte :: tail`, the induction hypothesis says the tail's number `T` is below
`256 ^ tail.length`, which for natural numbers is `T + 1 ≤ 256 ^ tail.length`. Multiplying
by 256, and using `byte < 256`: `byte + 256 · T < 256 · (T + 1) ≤ 256 · 256 ^ tail.length`.
The proof writes these steps as `have`s and lets `omega` combine them. One detail shows
how `omega` works: it treats `256 ^ tail.length` as an unknown, opaque number. `256 * x`
and `x * 256` are then different terms to it, so the proof first rewrites one into the
other with `Nat.mul_comm`. *`fromBigEndian_fits_width`* applies it to the reversed list.
Used, through `prefix_value_fits_width`, in the canonical-uniqueness proof: an argument
read from `k` bytes fits back into `k` bytes.

*`littleEndian_bytes_roundtrip`.* Induction on the list again. For `byte :: tail` the
number is `byte + 256 · T`. Because `byte < 256`, its remainder modulo 256 is `byte` and its
quotient is `T` (two `omega` facts, `hRemainder` and `hQuotient`). So `toLittleEndian`
emits `byte`, then converts `T` back into `tail.length` bytes, which is `tail` by the
induction hypothesis. *`bigEndian_bytes_roundtrip`* is its big-endian twin. Used, through
`reencoded_prefix_restores_bytes`, in the canonical-uniqueness proof.

== CBOR heads

*File:* `formal/Jotakey/Cbor/Heads.lean`, second half. A *head* starts every CBOR item: an
initial byte `majorType · 32 + additionalInfo` and, for additional info 24 to 27, an
argument of 1, 2, 4 or 8 big-endian bytes (§5.1). The model has three functions:

#codepanel(title: "Heads.lean: encoder and decoder")[
```lean
def encodeHead (majorType argument : Nat) : List Nat :=      -- always the shortest form
  if argument < 24 then [majorType * 32 + argument]
  else if argument < 2 ^ 8 then (majorType * 32 + 24) :: toBigEndian 1 argument
  else if argument < 2 ^ 16 then (majorType * 32 + 25) :: toBigEndian 2 argument
  else if argument < 2 ^ 32 then (majorType * 32 + 26) :: toBigEndian 4 argument
  else (majorType * 32 + 27) :: toBigEndian 8 argument

def readArgument (width minimum : Nat) (bytes : List Nat) : Option (Nat × List Nat) :=
  if bytes.length < width then none                              -- truncated
  else if fromBigEndian (bytes.take width) < minimum then none   -- not minimal
  else some (fromBigEndian (bytes.take width), bytes.drop width)

def decodeHead : List Nat → Option (Nat × Nat × List Nat)
  | [] => none
  | initialByte :: rest =>
    let majorType := initialByte / 32
    let additionalInfo := initialByte % 32
    if majorType = 7 ∧ 24 ≤ additionalInfo ∧ additionalInfo ≤ 27 then none   -- floats
    else if additionalInfo < 24 then some (majorType, additionalInfo, rest)
    else if additionalInfo = 24 then
      (readArgument 1 24 rest).map fun (value, after) => (majorType, value, after)
    -- … the same for 25, 26, 27 with widths 2, 4, 8 and minimums 2^8, 2^16, 2^32
    else none                                       -- reserved, indefinite
```
]

The `minimum` argument of `readArgument` is the minimality rule: a value read from the
2-byte form must be at least `2⁸`, because anything smaller has a shorter encoding. That
single comparison is what the canonical-uniqueness theorem depends on.

=== The round trip

*`readArgument_reads_encoded`.* Suppose the value is at least `minimum` and fits in
`width` bytes. Then reading its encoding followed by `rest` returns the value and leaves
exactly `rest`. The encoding has length
`width` (`toBigEndian_length`), so `take width` returns it and `drop width` returns `rest`
(two `have`s using library lemmas about `take`/`drop` of an append). Its value is `value`
(`bigEndian_number_roundtrip`). Both rejection tests then fail: the input is long enough,
and `value ≥ minimum`.

*`decodeHead_inverts_encodeHead`* (key theorem). For `majorType < 7` and
`argument < 2⁶⁴`:

#codepanel(title: "Heads.lean")[
```lean
theorem decodeHead_inverts_encodeHead (majorType argument : Nat) (rest : List Nat)
    (hDataType : majorType < 7) (hFits64 : argument < argumentLimit) :
    decodeHead (encodeHead majorType argument ++ rest) = some (majorType, argument, rest)
```
]

The proof has five cases, chosen with `by_cases` to match the five branches of
`encodeHead`: `argument < 24`, `< 2⁸`, `< 2¹⁶`, `< 2³²`, and the rest. Each case has the
same three steps:

+ The initial byte `majorType · 32 + info` splits back into `majorType` (division by 32)
  and `info` (remainder), proved by `omega` because `info < 32` (`hMajor`, `hInfo`).
+ For the extended forms, `readArgument_reads_encoded` reads the argument back. Its
  hypothesis `minimum ≤ argument` holds because the case excludes the smaller values. For
  example, in the 2-byte case we know `¬ argument < 2⁸` (the negation of `hOneByte`).
+ A final `simp; omega` clears the remaining tests in `decodeHead`. The float test
  `majorType = 7 ∧ …` is false because of `hDataType`.

The hypothesis `hDataType` excludes major type 7 because the decoder rejects info 24 to 27
there (floats). Jotakey only uses major-type-7 simple values below 24 (`false`, `true`,
`null`), which the decoder does accept, but the theorem does not cover them. `hBytes` is
not needed here: `encodeHead` always produces bytes, since `toBigEndian` takes every byte
modulo 256.

=== Canonical uniqueness

The converse direction, from accepted bytes to the encoder, needs more scaffolding. Its
lemmas each answer one question the main proof will ask:

- *`readArgument_accepted_facts`*: if `readArgument` returned `some (value, after)`, then
  the input had at least `width` bytes, `minimum ≤ value`, `value` is the number in the
  first `width` bytes, and `after` is what follows them. An inversion lemma. `split at h`
  follows the two `if`s. In the rejecting branches `h` claims `none = some (value, after)`,
  which `simp` recognises as impossible. In the accepting branch `obtain ⟨rfl, rfl⟩`
  substitutes `value` and `after` by the expressions they equal, and what is left is
  already known.
- *`decodeHead_extended_facts`*: the same for the four extended branches of `decodeHead`.
  If one of them accepted, giving `(majorType, argument, rest)`, then
  `majorType = initialByte / 32` and the four facts above hold. The proof looks at what
  `readArgument` returned (`cases hRead : …`); `none` cannot map to `some`.
- *`prefix_value_fits_width`*: for a byte list with at least `width` elements, the number
  in its first `width` bytes is `< 256 ^ width`. This is `fromBigEndian_fits_width` applied
  to that prefix.
- *`reencoded_prefix_restores_bytes`*: for the same list, re-encoding the first `width`
  bytes and appending the rest gives the list back (`bigEndian_bytes_roundtrip`, then
  `take ++ drop` is the whole list).
- *`encodeHead_one_byte_form`, `_two_byte_form`, `_four_byte_form`, `_eight_byte_form`*:
  given the range of `argument`, which branch `encodeHead` takes. For example, if
  `2⁸ ≤ argument < 2¹⁶`, then the encoding is `(majorType · 32 + 25)` followed by
  `toBigEndian 2 argument`. Each proof unfolds `encodeHead`, splits every `if`
  (`repeat' split`), and closes each branch with `rfl` (the matching branch) or `omega`
  (the branch conditions contradict the range).

*`decodeHead_accepts_only_canonical`* (key theorem):

#codepanel(title: "Heads.lean")[
```lean
theorem decodeHead_accepts_only_canonical (bytes : List Nat) (majorType argument : Nat)
    (rest : List Nat) (hBytes : ∀ byte ∈ bytes, byte < 256)
    (h : decodeHead bytes = some (majorType, argument, rest)) :
    bytes = encodeHead majorType argument ++ rest
```
]

The proof follows `decodeHead`'s chain of `if`s with `split at h`, one branch at a time:

- *Rejected branches* (floats, info 28 to 31): `h` says `none = some …`. Impossible.
- *Immediate argument* (info < 24): `majorType` and `argument` are the quotient and
  remainder of the initial byte by 32, and `rest` is the tail. `encodeHead` takes its first
  branch because `argument < 24`, and quotient · 32 + remainder is the initial byte again.
- *Extended argument* (info 24 to 27, so `width` is 1, 2, 4 or 8): by
  `decodeHead_extended_facts`, the argument is the number in the next `width` bytes and is
  at least `minimum`; by `prefix_value_fits_width`, it is below `256 ^ width`. That is
  exactly the range where the matching `encodeHead_…_form` lemma applies, so the goal
  becomes: the input is the initial byte, then `toBigEndian width argument`, then the rest.
  By `reencoded_prefix_restores_bytes`, re-encoding the argument gives back the bytes it
  was read from. `congr 1` leaves only the initial bytes to compare, and `omega` checks
  them.

The proof does not say "the decoder is strict" anywhere. Strictness is *forced* by the
statement. Take the non-minimal head `19 00 05`: 5 written in two bytes. A decoder
without the minimality check would accept it as `(0, 5)`, but `encodeHead 0 5 = [05]`, so
the theorem would be false and no proof would exist. In the info-25 case, the proof uses
`hMinimal : 2⁸ ≤ argument` to apply `encodeHead_two_byte_form`, and that fact comes only
from the minimality check. §9.8 shows the differential test catching exactly this bug in
Rust.

The hypothesis `hBytes` is needed as well. Without it, `[0x18, 300]` (a "byte" of 300)
decodes as `(0, 300)`, but `encodeHead 0 300` is the three bytes `[0x19, 1, 44]`. In Rust
the type `u8` makes `hBytes` hold automatically.

*`decodeHead_consumes_input`* (key theorem) says an accepted head always leaves less input
than it found: if `decodeHead` returns `rest`, then `rest.length < bytes.length`. The proof
is the same case analysis, simpler: an immediate head leaves the tail after one byte, and
an extended one leaves `tail.drop width`, no longer than the tail. The proof ends with
`all_goals first | (simp at h; done) | (…)`: on every remaining branch, first try to show
the branch is impossible, and if that does not close it, use `decodeHead_extended_facts`
and arithmetic. Every head consumes input, so a loop over heads always moves forward. In
Rust this is the reason an array claiming 2⁶⁴ elements runs out of input after at most as
many iterations as there are bytes. The model does not yet state that work bound for the
whole validator; this lemma is the step it would be built from.

== The strict validator

*File:* `formal/Jotakey/Cbor/Cbor.lean`. This file defines the whole validator
(`skipItem`, `skipArray`, `skipMap`, `validate`, with helpers such as `readMapKey`,
`canonicalKeyLess` and `isValidUtf8`) on top of the heads, and contains *no theorems*. Two
guarantees come from it anyway.

*Termination.* The three `skip` functions call each other (an array contains items, an
item may be an array), so they are defined together in a `mutual` block. Lean accepts
them only after checking that every recursive call decreases a measure. Here the measure
is a pair `(fuel, count)`, compared lexicographically. Entering a container lowers `fuel`;
moving to the next element of an array or map keeps `fuel` and lowers the count; and an
item (count 0) is always below the array that contains it (count `count + 1`). The
definition compiling is therefore a proof that `validate` terminates on every input.

*An executable specification.* `validate` and `decodeHead` are what `jotakey-spec` runs in
the differential test (§9.8). Agreement on 101,536 queries ties the Rust decoder to the
same definitions the head theorems are about. The nine `#guard` lines at the end of the
file are build-time checks on hand-picked inputs: correct and misordered maps, duplicate
keys, depth 4 and 5, a non-minimal head, an indefinite length, a float, and `true` followed
by a trailing byte.

Which properties of the validator are *not* proved? Map-key order, rejection of duplicate
keys, the depth limit, and UTF-8 validity are checked by the `#guard`s, the differential
test, and the Rust tests and fuzzers. No theorem about them exists. They would be natural
next theorems: for instance, "if `validate` accepts, the keys of every map are strictly
increasing in canonical order".

== CTAPHID reassembly

*File:* `formal/Jotakey/CtapHid.lean`. A `ReceiveState` is `idle`, `receiving` (owner
channel, command, announced total, buffer so far, next expected sequence number) or `busy`
(a complete message waiting for the authenticator). `receivePacket` handles one `ParsedPacket` (a packet already split into its fields),
and `receivePackets` folds it over a list of packets.

=== Isolation

*`receivePacket_ignores_other_channels`*: if channel `owner` owns the transaction
(`hOwner : state.owner = some owner`) and the packet is on another channel
(`hOtherChannel`), then `receivePacket state packet = state`. The proof is a case
analysis on the state. `idle` has no owner, so `hOwner` is false. In `receiving`, every
branch of `receivePacket` first compares the packet's channel with the owner, and
`hOtherChannel` says they differ, so `simp` picks the branch that returns the state
unchanged. In `busy`, `receivePacket` ignores every packet, and `cases packet <;> rfl`
checks both packet kinds.

*`receivePackets_ignores_other_channels`* (key theorem): if `owner` owns the transaction
and every packet in the list is on another channel, then receiving them all leaves the
state unchanged. Induction on the list: the first packet changes nothing
(`receivePacket_ignores_other_channels`), so the rest runs from the same state. Any number
of foreign packets, of any kind, in any order, are invisible to the owner. The model has
no outputs or timers. The "channel busy" errors the Rust code sends back to the other
channels are outside it.

=== Bounded memory

`WellFormed` is a predicate on receive states: in `receiving`, the buffer is shorter than
the announced total and the total is at most 1200; in `busy`, the message is at most 1200
bytes.

- *`deliverIfComplete_is_well_formed`*: `deliverIfComplete`, which delivers a message once
  all its bytes are in, produces a well-formed state from a buffer no longer than its
  total. Either the buffer is still short (still receiving), or it is delivered and
  `buffer.length ≤ total ≤ 1200`.
- *`receivePacket_preserves_well_formed`*: one packet preserves `WellFormed`. Case analysis
  on state and packet. The two cases where data is stored need an argument. An init
  packet is refused if it announces more than 1200 bytes; otherwise it stores at most
  `announcedLength` bytes of its payload. A continuation packet stores at most
  `total - buffer.length` more bytes. In both, `deliverIfComplete_is_well_formed` applies.
- *`receivePackets_preserves_well_formed`* (key theorem): any packet sequence preserves
  `WellFormed`. Induction, with `receivePacket_preserves_well_formed` at each packet.

Note what makes the proof work: the device cuts every payload to what it still expects,
whatever the packet claims. A model that appended the full 59 bytes of every continuation
packet would make `receivePacket_preserves_well_formed` false at the last packet of a
message.

=== Exact reassembly

The host side is modelled too. `fragmentMessage channel command message` builds the
packets a host must send: an init packet with the first 57 bytes, then
`continuationPackets` with 59 bytes each and sequence numbers 0, 1, 2 and so on.

- *`trimming_keeps_host_payload`*: `(bytes.take n).take (min bytes.length n) = bytes.take n`.
  The device cuts each payload to the bytes it still expects; this lemma says that cut
  removes nothing from a packet the host built.
- *`continuationPackets_of_empty`*: no bytes left means no continuation packets.
- *`continuations_complete_message`*: the core lemma. If the device is receiving `message`
  and holds a prefix `buffer`, with `buffer ++ rest = message` and `buffer` shorter than
  `message`, then the host's continuation packets for `rest` take it to
  `busy channel message`.

`continuations_complete_message` is proved by *calling itself*. That is how Lean expresses
an induction that is not over a plain list or number, here the length of `rest`.
`termination_by rest.length` names the measure, and `decreasing_by` proves it drops: the
recursive call uses `rest.drop 59`, shorter because `rest` is not empty
(`hRestNonEmpty`). The body handles one packet. The device appends `rest.take 59`
(`trimming_keeps_host_payload` shows the cut is harmless). If the buffer is still short,
the remaining packets are exactly those for `rest.drop 59` with the next sequence number,
and the recursive call finishes. Otherwise `rest` fitted in this one packet, the buffer is
`buffer ++ rest = message`, and no packets remain.

*`fragmented_message_is_reassembled`* (key theorem) says that any message of at most 1200
bytes, fragmented the way a host must fragment it, arrives intact:

#codepanel(title: "CtapHid.lean")[
```lean
theorem fragmented_message_is_reassembled (channel command : Nat) (message : List Nat)
    (hMaxSize : message.length ≤ maxMessageSize) :
    receivePackets .idle (fragmentMessage channel command message) = .busy channel message
```
]

The init packet is accepted and stores `message.take 57`. If that is the whole message, it
is delivered at once. Otherwise `continuations_complete_message` applies, with
`buffer = message.take 57` and `rest = message.drop 57`. This includes the empty message:
an early version of the theorem required `0 < message.length`, and Lean showed that
hypothesis was never used (§9.6).

== The authenticator state machine

*File:* `formal/Jotakey/Authenticator.lean`. Parsing and cryptography are abstracted away.
A request arrives as a `Command` already classified by the parser, and a signature is the
output `signature relyingParty counter`. Relying parties and credentials are plain numbers:
the model only needs to tell them apart. `processRequest` handles a request and may park a
command that needs a touch; `completePresence` handles the outcome of the wait for a
touch; `handleEvent` dispatches one event to either, and `runTrace` runs any list of
events. The `State` holds the `pending` command, the persisted `signCounter`, the
`resetEpoch` and the `faulted` flag.

Most single-event proofs have the same shape: split into every combination of state and
input (`cases … <;> …`), let `simp` compute what `processRequest` or `completePresence`
returns, and see that the claim holds in each case. There are dozens of cases, and Lean
checks all of them. If a command is ever added to `Command`, `cases` includes it
automatically, and the proof fails if the new command breaks the property.

=== User presence (invariant 1)

- *`processRequest_never_signs_with_presence`*: whatever the state, command and uptime,
  `processRequest` never outputs a signature carrying the UP flag. The proof tries faulted
  or not × every command, plus the uptime `if` for reset; every output is an error,
  `info`, `needsPresence`, or (for a silent assertion) a signature with the flag `false`.
- *`request_signs_only_silently`*: the only request that signs at all is a silent
  assertion on a healthy device, for its own relying party, and its signature has the UP
  flag clear. This is the model of the client pre-flight (§5.2).
- *`completePresence_signs_with_presence`*: every signature a completed touch produces
  carries the UP flag.
- *`completePresence_clears_pending`*: after `completePresence`, nothing is parked,
  whatever the outcome. Every branch sets `pending := .idle`.
- *`signature_requires_confirmed_touch`*: if an event outputs a signature carrying the UP
  flag for `relyingParty`, then the event was `presence .confirmed`, the device was not
  faulted, and the parked command was a makeCredential or getAssertion *for that same
  relying party*. A request cannot sign with the flag
  (`processRequest_never_signs_with_presence`). For a presence event, the
  proof tries every parked command × every result (18 cases, `simp_all` computes each).
  Only the two confirmed signing cases produce a signature, and there the relying party is
  the parked one.
- *`one_touch_signs_at_most_once`* (key theorem): `completePresence` applied twice never
  signs the second time, with or without the flag. Suppose it did; the signature would
  carry the flag (`completePresence_signs_with_presence`). `signature_requires_confirmed_touch` says a
  signing command was parked before the second completion, but
  `completePresence_clears_pending` says nothing was. `rcases` takes the two possibilities
  apart (makeCredential, or getAssertion with some credential), and in each `cases` sees
  that `.idle` cannot equal a different constructor.

=== The signature counter (invariant 2)

- *`handleEvent_never_lowers_counter`*: one event never lowers `signCounter`. Every branch
  keeps it or adds 1.
- *`signature_carries_next_counter`*: if an event signs with `counter`, then
  `counter = state.signCounter + 1` and the new state's `signCounter` is `counter`. In the
  Rust code this is the write-ahead rule: `N + 1` is persisted before the signature that
  carries it is released.
- *`runTrace_never_lowers_counter`*: over a whole trace, the final counter is at least the
  start. Induction, chaining single events with `Nat.le_trans`.
- *`trace_signature_counters_bounded`*: every signature `counter` in a trace satisfies
  `start < counter ≤ final`.
- *`trace_signature_counters_increase`* (key theorem): the signature counters of any trace
  are `Pairwise (· < ·)`, so each is smaller than every counter that comes after it.

#codepanel(title: "Authenticator.lean")[
```lean
theorem trace_signature_counters_increase (state : State) (events : List Event) :
    (signatureCounters (runTrace state events).2).Pairwise (· < ·)
```
]

`trace_signature_counters_bounded` exists only to make this proof go through, and it shows
a technique worth knowing: *strengthening the induction hypothesis*. Try to prove
`trace_signature_counters_increase` directly by induction on the events. The tail of the
trace is pairwise increasing by the induction hypothesis. But if the first event signs
with counter `first`, we must also show that `first` is below every *later* counter, and
"pairwise increasing" says nothing about where the later counters lie. So we first prove
the stronger `trace_signature_counters_bounded`, "every counter lies strictly above the
start and at most at the end", and that is enough. The first signature's `first` is the
counter right after the first event (`signature_carries_next_counter`). Every later
signature lies strictly above that counter, because the bounded lemma applies to the rest
of the trace, which starts there. Proving something stronger to make an induction work is
very common.

The trace is *any* list of events: requests of every kind, touches, timeouts,
cancellations and resets, in any order. A reset changes the epoch but not the counter, so
counters keep increasing across resets too, as relying parties require.

=== Reset (invariant 6) and faults (invariant 7)

- *`parked_reset_was_requested_in_window`*: if processing a request leaves a reset parked,
  the request was `reset` with `uptimeMs ≤ 10000`. Inversion over every command and the
  uptime `if`.
- *`epoch_change_requires_confirmed_touch`*: if an event changes the reset epoch, the
  event was a confirmed touch and a reset was parked. Requests never change the epoch.
  The proof shows that case by case, after `exfalso; apply hChanged` turns "find the
  contradiction" into "show the epochs are equal". For presence events, only
  reset/confirmed changes it.
- *`epoch_change_requires_reset_in_window`* (key theorem): start from a state with no
  reset parked (the hypothesis `hNoParkedReset`; power-up has none). If the epoch ever
  changes, the trace contains a reset request whose uptime was at most 10,000 ms. Induction on the events. If
  the first event changed the epoch, `epoch_change_requires_confirmed_touch` says a reset
  was parked at the start, which contradicts `hNoParkedReset`. Otherwise the change happens
  later, and to use the induction hypothesis we need "no reset parked" after the first
  event. A touch leaves nothing parked (`completePresence_clears_pending`). A request that
  parked a reset *is* the witness we are looking for
  (`parked_reset_was_requested_in_window` supplies the bound). Any other request leaves no
  reset parked, and the induction hypothesis finds the witness further on.
- *`faulted_stays_faulted_and_never_signs`* (key theorem): if `faulted` is set, then after
  any event it is still set and the output is not a signature. Both `processRequest` and
  `completePresence` take their first branch; `simp` sees it directly. Applying it at each
  event in turn shows that a faulted device never signs again in any trace. That induction
  is not written out as a separate theorem.

== Credential IDs

*File:* `formal/Jotakey/Credential.lean`. A credential ID is
`[1] ++ nonce ++ mac key relyingParty nonce`. The MAC is a *parameter*, declared once with
`variable (mac : …)`: every theorem holds for any function of that type, HMAC-SHA256
included, and states as a hypothesis whatever it needs from it.

- *`unwrap_recovers_nonce`* (key theorem): assume the MAC always returns 16 bytes (the
  hypothesis `hTagLength`) and the nonce has 32. Then unwrapping a freshly wrapped ID at
  the same relying party returns the nonce. Direct computation: the length is
  1 + 32 + 16, the version byte matches, splitting after 32 bytes gives back the nonce and
  the tag, and the recomputed tag equals the stored one.
- *`unwrap_accepts_only_wrapped_ids`*: if `unwrap` accepts `credentialId` and returns
  `nonce`, then `credentialId = wrap mac key relyingParty nonce` and the nonce has 32
  bytes. No assumption about the MAC. An inversion proof: the accepting branch says the
  version is right, the length is 49, and the recomputed MAC of `rest.take 32` equals
  `rest.drop 32`. Putting the pieces back together (`List.take_append_drop`) gives exactly
  `wrap`'s output. `unwrap` accepts nothing else: not a different version byte, not a
  longer ID with trailing bytes, not a near miss.
- *`credential_bound_to_relying_party`* (key theorem):

#codepanel(title: "Credential.lean")[
```lean
theorem credential_bound_to_relying_party
    (hNoCrossSiteCollision : ∀ key party party' nonce,
      party ≠ party' → mac key party nonce ≠ mac key party' nonce)
    (key relyingParty otherParty nonce : List Nat) (hNonceLength : nonce.length = nonceLength)
    (hDifferentParty : relyingParty ≠ otherParty) :
    unwrap mac key otherParty (wrap mac key relyingParty nonce) = none
```
]

The proof is by contradiction. Suppose `unwrap` at `otherParty` returned some `recovered`
nonce. By `unwrap_accepts_only_wrapped_ids` the ID also equals `wrap` at `otherParty` for
`recovered`: the nonce followed by its tag at `relyingParty` equals `recovered` followed
by its tag at `otherParty`. Both nonces are 32 bytes, so `List.append_inj` splits the equation into
`nonce = recovered` and equal tags for the two relying parties, which
`hNoCrossSiteCollision` rules out because they differ.

#callout(kind: "info", "The assumption is an idealisation")[
Stated for *all* inputs, `hNoCrossSiteCollision` is false for any real 16-byte MAC. There
are more relying parties than tags, so some pair must collide. What cryptography provides
is that nobody can *find* such a collision, except with probability about 2⁻¹²⁸ per
attempt. Read the theorem as: a MAC collision is the only way a credential ID can be
accepted at a site it was not minted for. The ID format, the parsing and the comparison
add no other way. Proving the probabilistic statement itself would need a framework for
cryptographic proofs, such as EasyCrypt or SSProve, and is outside the scope of this
project.
]

== PIN lockout

*File:* `formal/Jotakey/ClientPin.lean`. A PIN is only as strong as the limit on guessing
it: a 4-digit PIN with unlimited tries falls in 10 000 attempts. The model keeps the
persisted state (the PIN and the retry counter, starting at 8) and the RAM state (wrong PINs
in this power cycle). An *attempt* counts itself first, storing `retries - 1`, and then
compares. A correct PIN refills the counter and clears the mismatches; a wrong one adds a
mismatch. At 0 retries the PIN is blocked; at 3 mismatches PIN entry stops until the next
power cycle. The events are attempts, changes of PIN, setting it, power cycles, resets, and
`interruptedAttempt`: power lost after the attempt was counted.

- *`comparison_needs_a_counted_retry`*: a PIN is compared, rightly or wrongly, only with a
  retry left and fewer than 3 mismatches, and a wrong one leaves the counter exactly one
  lower. Case analysis over `attempt`.
- *`wrong_pins_between_successes_le_eight`* (key theorem): along *any* trace from a state
  with at most 8 retries, at most 8 wrong PINs are compared between one correct entry (or
  setting the PIN, or a reset) and the next. The induction carries the budget
  `wrong + retries ≤ 8`: a wrong PIN adds one to `wrong` and removes one retry, and every
  event that clears `wrong` refills the counter. Since `retries` cannot go below 0, `wrong`
  stays at most 8. An interrupted attempt removes a retry without comparing anything, which
  only helps.
- *`wrong_pins_in_a_row_le_three`*: from power-up, at most 3 wrong PINs are compared in a
  row without a correct entry, a power cycle or a reset between them. Same shape, with the
  invariant `streak ≤ mismatches ≤ 3`.
- *`blocked_until_reset`* (key theorem): once the counter is 0 with a PIN set, no trace
  without a reset accepts a PIN. Every other event either refuses or, for `setPin`, sees a
  PIN already set, and none of them raises the counter.

What makes "counted before compared" matter is the power cut: if the device compared first
and stored afterwards, unplugging it at the right moment would give an attacker a free
guess. The model has no event in which a comparison happens without its cost, because
`attempt` lowers the counter in the same step. On the Rust side the order is checked
directly: the mock platform records the stored counter at the moment the PIN is first
processed, and both a unit test and the `client_pin` fuzz target require it to be one
lower already. A planted bug that compared first was caught by both.

== When a touch counts

`Presence.lean` models `PresenceGate` (`presence.rs`), the rule both firmwares feed their
sensor readings to while a request waits for the user: the C6's BOOT button and the key's
touch electrode. `Authenticator.lean` takes a confirmed touch as an input; this model says
where one can come from. A gate starts when the request arrives (`start nowMs` sets the
deadline 30 s later) and `poll gate nowMs pressed` handles one reading: past the deadline,
or once expired, it times out; a release resets the press count and records that a release
was seen; a press after a release counts, and the second in a row confirms.

The history of readings is a list, *newest first*, so the reading just taken is the head
(`::`) and induction starts at the oldest one. `gateAfter startMs history` is the gate after
that history.

- *`gateAfter_accounts`*: the gate after any history satisfies `Accounts`, five facts
  about how its state relates to the history behind it: the deadline is `startMs + 30000`;
  if not expired, every reading so far came before it; a reading at or past it expires the
  gate; if a release was seen, the history contains one; and, until it expires, the press
  count is at most the run of presses at the head of the history (`leadingPresses`).
  Induction on the history, splitting `poll` into its branches. That last field needs the
  "until it expires": an expired gate keeps its count while later readings change, which
  is harmless because it only ever answers `timeout`. The first version of the invariant
  missed this and `omega` produced the counterexample.
- *`confirmed_needs_release_then_debounced_press`*: if the poll of a new reading confirms,
  that reading is a press, the last two readings are presses, an older reading since the
  request is a release, and every reading came before the deadline. A confirmation comes
  from one branch of `poll`; `Accounts` of the older history turns its conditions into
  statements about the readings.
- *`press_held_from_the_start_never_confirms`* (key theorem): a sensor pressed at every
  reading never confirms. The previous theorem would need a release, and there is none.
- *`timeout_at_deadline`* and *`timeout_is_final`* (key theorems): a reading at or past
  the deadline times out, and so does every poll after it, whatever time it reports. The
  Rust gate keeps an `expired` flag for exactly this.

#codepanel(title: "Presence.lean")[
```lean
theorem confirmed_needs_release_then_debounced_press (startMs nowMs : Nat) (pressed : Bool)
    (older : List (Nat × Bool))
    (hConfirmed : (poll (gateAfter startMs older) nowMs pressed).2 = .confirmed) :
    pressed = true ∧
      debouncePolls ≤ leadingPresses ((nowMs, pressed) :: older) ∧
      (∃ reading ∈ older, reading.2 = false) ∧
      ∀ reading ∈ (nowMs, pressed) :: older, reading.1 < startMs + upTimeoutMs
```
]

The readings' times may come in any order: the theorems do not assume a monotonic clock.
The differential test (§9.8) feeds both implementations sequences with jumps forward and
back, and they agree step by step.

== The record log under power loss

`RecordLog.lean` models `RecordLog` (`storage.rs`), which persists the signature counter
on the C6 (and in the key's `dev-key` builds), the reset epoch, the PIN record and the key's
pairing secret. `Authenticator.lean` assumes a persisted counter; this model proves the
log is one, whatever power cuts interrupt it.

The model works at the level of *slots*: a sector holds `capacity` slots, each `erased`,
`torn` (anything that fails the CRC) or `record sequence`. The byte layout below that is
the Rust tests' job: records sit at stride-aligned offsets and cover whole programming
units, each programmed once, so a cut while writing one record damages its slot alone
(`mock_flash_refuses_partial_and_repeated_programming`). `mount` computes the latest
sequence number, the active sector and the next free slot exactly as Rust does, and
`target` where the next append goes.

A power cut is *nondeterministic*. `AppendStep` is a relation, not a function: `ok`, or a
`cut` that may leave each slot of the target sector as `CutSlot` allows. During an erase,
every slot may end up as it was, erased or torn; during a write, the slot being written may
end up erased, torn or holding the new record, and every other slot keeps its value. Each
theorem holds for every outcome the relation allows.

- *`mount_fits`*: a freshly mounted log fits the flash it came from (`Fits`): its latest
  number is the flash's, the active sector holds it, everything from `next` on in the active
  sector is erased, and both sectors have `capacity` slots.
- *`append_preserves_latest`*: no outcome of an append, completed or cut, lowers the latest
  record on the flash. If the append erases, it erases the *other* sector, since a log with
  a record never erases its active one; if it writes, it writes past the latest record's
  slot. Either way that record survives.
- *`append_ok`*: a confirmed append returns `latest + 1`, which becomes the latest record,
  and the log as Rust updates it still fits.
- *`trace_never_loses_confirmed`*: a `Run` is any sequence of appends, cuts and remounts
  from an erased flash, where a failed append is followed by a remount (the documented
  contract of `RecordLog::append`, which every platform keeps). Along any run, the log fits
  the flash and the latest record is at least the last confirmed number. Induction on the
  run.
- *`confirmed_strictly_increases`* (key theorem): every confirmed number exceeds the one
  confirmed before it.

#codepanel(title: "RecordLog.lean")[
```lean
theorem confirmed_strictly_increases (capacity : Nat) (hCapacity : 0 < capacity)
    {events flash log confirmed flash' sequence}
    (hRun : Run capacity events flash log confirmed)
    (hStep : AppendStep capacity log flash flash' (some sequence)) : confirmed < sequence
```
]

The differential test checks `mount` and a completed append against the Rust code on
generated flash contents (realistic runs, torn records, and the debris a cut erase
leaves), at both programming units. The cut outcomes are checked by the `record_log` fuzz
target and the power-cut property tests instead, because a relation has no single answer
to compare.

== The OPTIGA session

`Shielded.lean` models how the jotakey key decides what to believe from its secure element
(`optiga/shielded.rs`, `optiga/device.rs`; §6.3 explains the protocol). The cryptography is
not modelled: a response either carries a tag that verifies under the session keys
(`authentic`) or does not. What is modelled is the *rule*, and the rule is where a replay or
a reordering would slip through.

`accept` is `Session::accept`: refuse a response for any use but the live-session check
while the session is not live; refuse anything but the record header; refuse a sequence
number outside `(last, last + 3]`; refuse a tag that does not verify; and only then move
`last`. `step` is how the driver uses it, event by event: a handshake opens a session that is
not live; the live-session check's answer makes it live only if accepted *and* equal to the
MCU's own value; any refusal or other failure drops the session. Histories are lists of
events, newest first.

- *`accept_needs_everything`* and *`accept_moves_forward`*: an accepted response met every
  condition, and accepting moves the window strictly forward, by at most three.
- *`live_needs_check`* (key theorem): if the session after a history is live, then since the
  last handshake a live-session check came back right. Induction on the history: a handshake
  makes a session that is not live, only a correct check sets `fresh`, and everything else
  keeps the flag (`accept_moves_forward`) or drops the session.
- *`used_needs_live`* (key theorem): a response is used only in a live session, authentic, in
  the window, and the number reported is its own.
- *`used_strictly_increase`* (key theorem): the sequence numbers used since the last
  handshake strictly increase. Its invariant `used_bounded` says they all lie at or below the
  window's position while the session exists, and nothing more is used once it is dropped.
- *`released_strictly_increase`* (key theorem): `release` is the counter rule of
  `Optiga::increment_counter`; whatever values are read back, the values released strictly
  increase.

#codepanel(title: "Shielded.lean")[
```lean
theorem live_needs_check :
    ∀ (history : List Event) (s : Session), stateAfter history = some s → s.fresh = true →
      checkSinceHandshake history
theorem used_strictly_increase : ∀ history : List Event, (used history).Pairwise (· > ·)
theorem released_strictly_increase : ∀ values : List Nat, (released values).Pairwise (· > ·)
```
]

What these theorems give is conditional on the cryptography, as always: an old recording
fails the check because it cannot contain a PRF value for a nonce chosen after it was made,
and a forged response fails because its tag does not verify. The differential test drives the
real `Session`, with real CCM tags (some damaged), through generated event histories and
compares every state with `step`; the `optiga_bus` fuzz target puts an attacker between the
driver and a simulated OPTIGA and checks the same properties end to end.

== What the proofs leave out

Each model makes choices about what to leave out (§9.4), and those choices are as important
as the theorems. In one place:

#dtable(
  columns: (0.9fr, 2.6fr),
  ("Model", "Not covered by a theorem"),
  ([CBOR], [The validator's map-key order, duplicate-key rejection, depth limit and UTF-8 checks. They are checked by `#guard`s, the differential test and the Rust tests and fuzzers, not proved. Major type 7 is outside the head round trip.]),
  ([CTAPHID], [`INIT`, `CANCEL`, timeouts and the response path. A combined theorem — owner packets interleaved with foreign ones give the same result as the owner packets alone — would follow from the existing lemmas but is not stated.]),
  ([Authenticator], [The parser's classification of requests into `Command`, the clock that provides `uptimeMs`, flash write failures, and keepalives. Fault absorption is proved per event, not over traces.]),
  ([Credentials], [The cryptography: the MAC is a parameter, and `hNoCrossSiteCollision` idealises collision resistance. Key derivation (HKDF, P-256 scalars) is not modelled.]),
  ([PIN lockout], [The PIN protocol's cryptography (key agreement, encryption, MACs) and the tokens: which requests count as attempts is taken from the code, not derived. Storage write failures are not modelled (in Rust they stop the attempt before the comparison). The reset here is unconditional; its window and touch are proved in the authenticator model.]),
  ([Presence gate], [Cancellation, which the firmware checks before each poll, and the sensor: whether one reading is a press (the key's `TouchDetector` thresholds) is outside the model. Rust saturates the deadline at `u64::MAX` and the press count at 255; the model has no such limits.]),
  ([Record log], [Payloads (checked by the fuzz target), and the byte layout under the slots (checked by the Rust tests). A transient flash error with the power still on is modelled only through the remount contract. Sequence numbers past `u32::MAX` (Rust refuses to append).]),
  ([OPTIGA session], [The cryptography (CCM, the PRF; a tag is a flag), the OPTIGA itself (that it picks `RND` at random, and that its counter only goes up, which holds once the unit is locked), the I2C data link and APDU parsers (total by construction and fuzzed, not proved), and that each response answers the request just sent (true because the driver sends one request at a time and drops the session on any failure). Sequence numbers are naturals; Rust's stay below `SEQ_LIMIT`.]),
  ([Link to Rust], [The CBOR, presence, record-log and OPTIGA-session models are tied to the code by differential testing (§9.8). The others are tied by careful transcription, review, and the tests and fuzz oracles of chapter 8 that check the same properties on the real code (§9.7). The planned Aeneas experiment would replace transcription with translation.]),
)

None of these gaps is hidden: each is either a hypothesis in a theorem's signature or a
part of the system that no theorem mentions. That is the standard to keep as the models
grow. When a new feature is added, its invariant goes into the model first, the proof
goes into `AxiomAudit.lean`, and anything the proof assumes stays visible in the
signature.

== Rust and Lean names

Each side follows its own language's conventions. Rust writes functions in `snake_case`
and constants in `SCREAMING_SNAKE_CASE`; Lean writes definitions in `lowerCamelCase` and
names theorems in `snake_case` after what they state. Constants that quote the CTAP
specification (`BROADCAST_CID`, `cmd::CBOR`) keep the spec's spelling in Rust. Everything
else uses descriptive words on both sides, so most names differ only in casing. The tables
below list every modelled item (Rust paths are under `crates/jotakey-core/src`, Lean
paths under `formal/Jotakey`); `formal/NAMES.md` holds the same table next to the code,
and `AGENTS.md` requires both to change together with any rename.

#breakable-code[
#dtable(
  columns: (1.3fr, 1.3fr, 1.4fr),
  ("Rust", "Lean", "Notes"),
  ([*CBOR*], [], []),
  ([`Decoder::head`, `Encoder::head`], [`decodeHead`, `encodeHead`], [Rust advances a cursor; Lean returns the rest of the input.]),
  ([`Decoder::read_be` + minimality check], [`readArgument`], []),
  ([`Decoder::skip(depth)`], [`skipItem`, `skipArray`, `skipMap`], [One function with loops; three mutually recursive ones.]),
  ([`skip(0)` + `position()`], [`validate`], [Answers `validate <hex>` in `jotakey-spec`.]),
  ([`read_slice`, `next_key`, `canonical_lt`], [`takeExactly`, `readMapKey`, `canonicalKeyLess`], []),
  ([`core::str::from_utf8`, `MAX_DEPTH`], [`isValidUtf8`, `maxNestingDepth`], []),
  ([*CTAPHID*], [], []),
  ([`ReceiveState` (`Idle`, `Receiving`, `Busy`)], [`ReceiveState` (`idle`, `receiving`, `busy`)], [Same names.]),
  ([`Receiving { channel, command, total, received, next_sequence, last_packet_ms }`], [`receiving channel command total buffer nextSequence`], [Rust counts the bytes received; Lean holds them. Lean has no clock.]),
  ([`Busy { channel }`], [`busy channel message`], [Rust keeps the message in `receive_buffer`.]),
  ([`CtapHid::handle_packet`, `maybe_dispatch`], [`receivePacket`, `deliverIfComplete`], [Lean leaves out INIT, CANCEL and timeouts.]),
  ([`Packet` (raw `[u8; 64]`)], [`ParsedPacket` (`init`, `continuation`)], [Different on purpose: the model starts after parsing.]),
  ([`MAX_MSG_SIZE`, `INIT_DATA`, `CONT_DATA`], [`maxMessageSize`, `initPayloadSize`, `continuationPayloadSize`], []),
  ([—], [`receivePackets`, `WellFormed`, `fragmentMessage`, `continuationPackets`], [Model only: packet sequences, the invariant, the host side.]),
  ([*Authenticator*], [], []),
  ([`Authenticator::process`, `complete`], [`processRequest`, `completePresence`], [Rust parses CBOR; Lean receives a classified `Command`.]),
  ([`PresenceResult`], [`PresenceResult`], [Same name.]),
  ([`Pending`], [`PendingCommand`], [Same variants. Their `user_verified` (UV) is not modelled here.]),
  ([`PendingOrSilent::Silent`], [`Command.silentAssertion`], [getAssertion with `up: false`: signed in `process`, never parked.]),
  ([`sign(…, user_present, …)`], [`Output.signature … userPresent`], [The UP flag; `true` only from `complete` under `Confirmed`.]),
  ([`Outcome` + response bytes], [`Output`], []),
  ([`Platform::increment_counter`, `rotate_epoch`, `uptime_ms`], [`State.signCounter`, `State.resetEpoch`, `uptimeMs`], [Rust keeps them behind the platform trait.]),
  ([`RESET_WINDOW_MS`], [`resetWindowMs`], []),
  ([—], [`Command`, `Event`, `handleEvent`, `runTrace`, `signatureCounters`], [Model only.]),
  ([*Credential IDs*], [], []),
  ([`wrap`, `unwrap` (`tagger`, `rp_id_hash`, `id`)], [`wrap`, `unwrap` (`mac key`, `relyingParty`, `credentialId`)], [Lean takes the MAC as a parameter `mac`; Rust's `Tagger` plays `mac key`. Rust's `unwrap` can also fail when the hardware does, which the model leaves out.]),
  ([`VERSION`, `NONCE_LEN`, `TAG_LEN`], [`formatVersion`, `nonceLength`, `tagLength`], []),
  ([return type `[u8; TAG_LEN]`], [hypothesis `MacOutputsTagLength mac`], [The Rust type guarantees what Lean must assume.]),
  ([*PIN lockout*], [], []),
  ([`PinRecord`, `PinSession::mismatches`], [`State` (`pin`, `retries`, `mismatches`)], [The verifier becomes the PIN; no cryptography.]),
  ([`check_pin`, `change_pin`, `set_pin`], [`attempt`, `Event.changePin`, `Event.setPin`], [`attempt` counts, then compares.]),
  ([`PIN_RETRIES_MAX`, `MISMATCHES_PER_POWER_CYCLE`], [`maxRetries`, `mismatchesPerPowerCycle`], []),
  ([power lost after `store_pin`], [`Event.interruptedAttempt`], []),
  ([PIN statuses after a comparison], [`Output.wrongPin`], [Whatever the status code.]),
  ([*Presence gate*], [], []),
  ([`PresenceGate::new`, `poll`], [`start`, `poll`], [Same names.]),
  ([`PresenceGate { deadline_ms, expired, released_seen, pressed_polls }`], [`Gate { deadlineMs, expired, releasedSeen, pressedPolls }`], []),
  ([`GateStep` (`Waiting`, `Confirmed`, `Timeout`)], [`Step` (`waiting`, `confirmed`, `timeout`)], []),
  ([`UP_TIMEOUT_MS`, `DEBOUNCE_POLLS`], [`upTimeoutMs`, `debouncePolls`], []),
  ([—], [`gateAfter`, `leadingPresses`, `Accounts`], [Model only: histories, newest first.]),
  ([*Record log*], [], []),
  ([`RecordLog::mount`, `append`], [`mount`, `AppendStep` (`ok`, `cut`)], [Lean's append is a relation: a cut has many outcomes.]),
  ([`RecordLog { active, next, latest }`], [`Log { active, next, latest }`], [`latest` is a number, `0` for `None`; payloads are left out.]),
  ([`scan_end`], [`scanEnd`], []),
  ([the sector switch in `append`], [`target`], []),
  ([the two sectors of a log (`Flash` trait, `MockFlash`)], [`Flash { zero, one }` of `Slot`s], [Slots are record-sized; `program_unit` sets the stride.]),
  ([—], [`Fits`, `CutSlot`, `Run`, `latestOf`, `maxSequence`], [Model only.]),
  ([*OPTIGA session*], [], []),
  ([`Session::accept`], [`accept`], [The tag check is the flag `Response.authentic`.]),
  ([`Session { last_sseq, fresh }`], [`Session { lastSseq, fresh }`], [The keys are left out.]),
  ([`Purpose`, `in_window`], [`Purpose`, `inWindow`], []),
  ([`SEQ_WINDOW`, `SEQ_LIMIT`, `SCTR_RECORD`], [`seqWindow`, `seqLimit`, `recordSctr`], []),
  ([`Optiga::establish`, `command` (drop on failure)], [`step` over `Event`], [`handshake`, `check`, `use`, `fail`.]),
  ([`release_counter`], [`release`], []),
  ([—], [`stateAfter`, `used`, `checkSinceHandshake`, `Bounded`, `released`], [Model only: histories, newest first.]),
)
]

The properties line up the same way: the Rust tests and fuzz oracles check on the real code
what the Lean theorems prove about the model.

#breakable-code[
#dtable(
  columns: (1.6fr, 1.4fr),
  ("Rust test or fuzz oracle", "Lean theorem"),
  ([`head_roundtrip`], [`decodeHead_inverts_encodeHead`]),
  ([`accepted_heads_are_canonical`, `cbor_decode` oracle], [`decodeHead_accepts_only_canonical`]),
  ([`other_channel_gets_busy…`, `ctaphid_stack`], [`receivePackets_ignores_other_channels`]),
  ([`ctaphid_stack` buffer assertions], [`receivePackets_preserves_well_formed`]),
  ([`no_signature_without_presence`, `ctap_dispatch` oracle], [`signature_requires_confirmed_touch`, `one_touch_signs_at_most_once`]),
  ([`monotonic_across_power_cuts`], [`trace_signature_counters_increase`]),
  ([`reset_window_and_effect`], [`epoch_change_requires_confirmed_touch`, `epoch_change_requires_reset_in_window`]),
  ([`fails_closed`], [`faulted_stays_faulted_and_never_signs`]),
  ([`roundtrip`, `bound_to_rp` (`credential.rs`)], [`unwrap_recovers_nonce`, `credential_bound_to_relying_party`]),
  ([`wrong_pins_are_counted_and_block`, `client_pin` model], [`wrong_pins_between_successes_le_eight`, `wrong_pins_in_a_row_le_three`, `blocked_until_reset`]),
  ([`an_attempt_is_stored_before_the_pin_is_compared`, `retries_at_pin_check` oracle], [`comparison_needs_a_counted_retry`]),
  ([`confirmation_needs_release_then_debounced_press`, `a_press_held_from_the_start_never_confirms`], [`confirmed_needs_release_then_debounced_press`, `press_held_from_the_start_never_confirms`]),
  ([`deadline_is_thirty_seconds_after_the_request`], [`timeout_at_deadline`, `timeout_is_final`]),
  ([`monotonic_across_power_cuts_any_unit`, `record_log` fuzz oracle], [`trace_never_loses_confirmed`, `confirmed_strictly_increases`]),
  ([`accepted_sequence_numbers_increase`, `replays_forgeries_and_alerts_are_refused`], [`accept_needs_everything`, `accept_moves_forward`, `used_strictly_increase`]),
  ([`a_replayed_session_is_not_live`, `nothing_is_used_before_the_session_is_live`, `optiga_bus` oracles], [`live_needs_check`, `used_needs_live`]),
  ([`counter_release_rule`, `a_counter_that_goes_back_is_refused`, `optiga_bus` counter oracle], [`released_strictly_increase`]),
)
]
