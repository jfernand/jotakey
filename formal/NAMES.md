# Rust ↔ Lean names

The Lean models in this directory mirror code in `crates/jotakey-core`. Each side follows
its own language's conventions, so names differ in predictable ways. This table is the
translation. **Keep it current:** a rename on either side updates this file and chapter 10
of `docs/jotakey.typ` in the same change (`AGENTS.md` §4).

## Conventions

| | Rust | Lean |
|---|---|---|
| Functions | `snake_case`: `handle_packet` | `lowerCamelCase`: `receivePacket` |
| Types | `UpperCamelCase`: `ReceiveState` | `UpperCamelCase`: `ReceiveState` |
| Enum variants / constructors | `ReceiveState::Busy` | `.busy` (`ReceiveState.busy`) |
| Constants | `SCREAMING_SNAKE_CASE`: `MAX_MSG_SIZE` | `lowerCamelCase`: `maxMessageSize` |
| Struct / variant fields | `next_sequence` | `nextSequence` |
| Properties | tests: `bound_to_rp` | theorems: `credential_bound_to_relying_party` |

Names taken from the CTAP specification stay as the spec writes them in Rust
(`BROADCAST_CID`, `cmd::CBOR`, `err::INVALID_SEQ`, `CtapHid`); the models don't use them.

## CBOR (`src/cbor.rs` ↔ `Jotakey/Cbor/`)

| Rust | Lean | Notes |
|---|---|---|
| `Decoder::head` | `decodeHead` | Rust advances a cursor; Lean returns the rest of the input. |
| `Encoder::head` | `encodeHead` | |
| `Decoder::read_be` + the minimality check in `head` | `readArgument` | |
| (big-endian arithmetic inside `read_be`) | `toBigEndian`, `fromBigEndian`, `toLittleEndian`, `fromLittleEndian` | Lean-only helpers for the proofs. |
| `Decoder::skip(depth)` | `skipItem`, `skipArray`, `skipMap` | One Rust function with loops = three mutually recursive Lean functions. |
| `Decoder::new(b).skip(0)` + `position()` | `validate` | What `jotakey-spec` answers for `validate <hex>`. |
| `Decoder::read_slice` | `takeExactly` | |
| `Decoder::next_key` / `MapState` | `readMapKey` + the `previousKey` argument of `skipMap` | |
| `canonical_lt` | `canonicalKeyLess` (with `lexicographicLess`) | |
| `core::str::from_utf8` | `isValidUtf8` | |
| `MAX_DEPTH` | `maxNestingDepth` | |
| `major`, `arg` (in `Encoder::head`) | `majorType`, `argument` | |

## CTAPHID (`src/transport/ctaphid.rs` ↔ `Jotakey/CtapHid.lean`)

| Rust | Lean | Notes |
|---|---|---|
| `ReceiveState` | `ReceiveState` | Same name. |
| `ReceiveState::Idle` / `Receiving` / `Busy` | `.idle` / `.receiving` / `.busy` | |
| `Receiving { channel, command, total, received, next_sequence, last_packet_ms }` | `receiving channel command total buffer nextSequence` | Rust counts the bytes `received` (they live in `receive_buffer`); Lean holds the bytes as `buffer`. Lean has no clock. |
| `Busy { channel }` | `busy channel message` | Rust keeps the message in `receive_buffer`. |
| `CtapHid::handle_packet` (+ `handle_init`, `handle_cont`) | `receivePacket` | Lean leaves out INIT, CANCEL and timeouts. |
| `CtapHid::maybe_dispatch` | `deliverIfComplete` | |
| `Packet` (`[u8; 64]`, a raw report) | `ParsedPacket` (`init` / `continuation`, fields already split) | Different on purpose: the model starts after parsing. |
| `HidEvent::Request { channel }` etc. | — | The model has no outputs. |
| `announced_length` (local in `handle_packet`) | `announcedLength` | The spec calls it BCNT. |
| `MAX_MSG_SIZE` (`src/lib.rs`) | `maxMessageSize` | |
| `INIT_DATA`, `CONT_DATA` | `initPayloadSize`, `continuationPayloadSize` | |
| — | `receivePackets`, `WellFormed`, `fragmentMessage`, `continuationPackets` | Lean-only: a sequence of packets, the invariant, and the host side. |

The BLE framer (`src/transport/ble.rs`) uses the same private names (`ReceiveState`,
`TransmitState`, `received`, `next_sequence`, `last_packet_ms`) but has no Lean model yet.

## Authenticator (`src/ctap/mod.rs`, `src/platform.rs` ↔ `Jotakey/Authenticator.lean`)

| Rust | Lean | Notes |
|---|---|---|
| `Authenticator::process` | `processRequest` | Rust parses CBOR bytes; Lean receives an already-classified `Command`. |
| `Authenticator::complete` | `completePresence` | |
| `PresenceResult` (`Confirmed`, `Timeout`, `Cancelled`) | `PresenceResult` (`confirmed`, `timeout`, `cancelled`) | Same name. |
| `Pending` | `PendingCommand` | Variants match: `Idle`, `MakeCredential`, `GetAssertion`, `Excluded`, `PinProbe`, `Reset`. |
| `Pending::MakeCredential { rp_id_hash, client_data_hash }` | `.makeCredential relyingParty` | The model only needs to tell relying parties apart. |
| `Outcome` + response bytes | `Output` (`info`, `needsPresence`, `error`, `signature`, `resetDone`) | |
| `Authenticator.faulted` / `fault()` | `State.faulted` | |
| `Platform::increment_counter` | `State.signCounter` | In Rust the counter lives behind the platform trait (flash). |
| `Platform::rotate_epoch` | `State.resetEpoch` | Same. |
| `Platform::uptime_ms` | the `uptimeMs` of `Event.request` | |
| `RESET_WINDOW_MS` | `resetWindowMs` | |
| — | `Command`, `Event`, `handleEvent`, `runTrace`, `signatureCounters` | Lean-only: the abstraction and traces. |

## Credential IDs (`src/credential.rs` ↔ `Jotakey/Credential.lean`)

| Rust | Lean | Notes |
|---|---|---|
| `wrap(tagger, rp_id_hash, nonce)` | `wrap mac key relyingParty nonce` | Lean takes the MAC as a parameter; Rust's `Tagger` is `mac key` (the hardware key store, or `HmacTagger` in tests). |
| `unwrap(tagger, rp_id_hash, id)` | `unwrap mac key relyingParty credentialId` | Rust returns `Result<Option<_>>`: `Err` only when the tagger (hardware) fails, which the model leaves out. |
| `tag` (HMAC-SHA256, truncated) | `mac` | Any function in Lean. |
| `VERSION`, `NONCE_LEN`, `TAG_LEN`, `CRED_ID_LEN` | `formatVersion`, `nonceLength`, `tagLength`, `1 + nonceLength + tagLength` | |
| `[u8; TAG_LEN]` return type | hypothesis `MacOutputsTagLength mac` | The Rust type guarantees what Lean must assume. |

## Properties: Rust tests ↔ Lean theorems

| Rust test / fuzz oracle | Lean theorem |
|---|---|
| `head_roundtrip` (proptest) | `decodeHead_inverts_encodeHead` |
| `accepted_heads_are_canonical` (proptest), `cbor_decode` fuzz oracle | `decodeHead_accepts_only_canonical` |
| `other_channel_gets_busy…`, `ctaphid_stack` fuzz target | `receivePackets_ignores_other_channels` |
| `ctaphid_stack` buffer assertions | `receivePackets_preserves_well_formed` |
| `no_signature_without_presence`, `ctap_dispatch` oracle | `signature_requires_confirmed_touch`, `one_touch_signs_at_most_once` |
| `monotonic_across_power_cuts` | `trace_signature_counters_increase` |
| `reset_window_and_effect` | `epoch_change_requires_confirmed_touch`, `epoch_change_requires_reset_in_window` |
| `fails_closed` | `faulted_stays_faulted_and_never_signs` |
| `roundtrip`, `bound_to_rp` (proptests in `credential.rs`) | `unwrap_recovers_nonce`, `credential_bound_to_relying_party` |
