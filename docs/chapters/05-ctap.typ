#import "../isss-template.typ": *
#import "../lib.typ": *

= CTAP2: talking to the authenticator

WebAuthn is the browser's API. *CTAP*, the Client-to-Authenticator Protocol, is what the
browser actually sends to the key. CTAP2 messages are a command byte followed by a
*CBOR* map. The answer is a status byte followed by a CBOR map.

== CBOR, and why strictness matters

CBOR (RFC 8949) is a binary JSON: integers, byte strings, text strings, arrays, maps,
booleans. Each item starts with a *head* byte: 3 bits of major type and 5 bits of
"additional information". The latter holds a small value directly (0–23) or announces
1, 2, 4 or 8 following bytes.

#bytefield(
  caption: "A CBOR head: major type 3 (text), length 11 in the low bits, then 11 bytes of UTF-8",
  ("major", "3 bits", 1),
  ("info", "5 bits", 1.6),
  ("argument", "0, 1, 2, 4 or 8 B", 3),
  ("payload", "…", 4),
)

The same value can often be written in several ways: `24` as `0x18 0x18`, as
`0x19 0x00 0x18`, and so on. Map keys can appear in any order or twice. For a parser that
guards keys, this freedom is dangerous. If the authenticator and some other component
disagree about which of two duplicate `rpId` keys counts, an attacker can show one value to
one component and another to the other. CTAP2 therefore requires *canonical* CBOR.
Jotakey's decoder rejects everything else:

- every integer, length and count in its shortest form;
- definite lengths only;
- map keys strictly increasing in canonical order (shorter encoding first, then bytewise),
  which also rules out duplicates;
- no tags, floats or `undefined`; nesting depth at most 4.

The Lean model of this decoder carries two theorems (§9.5). *Round trip*: decoding an
encoded head returns exactly the encoded value. *Uniqueness*: anything the decoder
accepts is exactly the canonical encoding of what it decoded. A differential test checks
that the Rust decoder and the Lean model agree on over 100 000 inputs.

== Commands

#dtable(
  columns: (0.5fr, 1.5fr, 2.5fr),
  ("Byte", "Command", "Jotakey MVP"),
  ([0x01], [authenticatorMakeCredential], [Yes. ES256 only; `rk` and `uv` options refused.]),
  ([0x02], [authenticatorGetAssertion], [Yes. Allow list required (non-resident credentials).]),
  ([0x04], [authenticatorGetInfo], [Yes. Versions, AAGUID, options, limits.]),
  ([0x06], [authenticatorClientPIN], [No (roadmap). Zero-length `pinAuth` probes get `PIN_NOT_SET` after a touch.]),
  ([0x07], [authenticatorReset], [Yes. Within 10 s of power-up, with a touch.]),
  ([0x08], [authenticatorGetNextAssertion], [Not needed without resident keys.]),
)

#codepanel(title: "authenticatorGetInfo response, as Jotakey sends it (diagnostic notation)")[
```
{ 1: ["FIDO_2_0"],                         ; versions
  3: h'6a6f74616b65792d7630312d63360001',  ; AAGUID
  4: {"rk": false, "up": true, "plat": false},
  5: 1200,                                  ; maxMsgSize
  7: 8,                                     ; maxCredentialCountInList
  8: 49 }                                   ; maxCredentialIdLength
```
]

One deliberate deviation from the specification: CTAP allows `getAssertion` with option
`up: false`, a *silent* assertion that produces a valid signature without a touch.
Platforms use it to probe whether a credential exists. A relying party that forgets to
check the UP flag would accept such a signature as a login. Jotakey refuses `up: false`
with `CTAP2_ERR_UNSUPPORTED_OPTION`, so *every* signature it ever makes carries a fresh
touch.

== CTAPHID: CTAP over USB

USB security keys are HID devices, like keyboards. Each report is exactly 64 bytes, so
longer messages are split into an *initialization packet* and *continuation packets*:

#bytefield(
  caption: "Initialization packet (57 payload bytes)",
  ("CID", "4 B", 2),
  ("CMD | 0x80", "1 B", 1.5),
  ("BCNT", "2 B", 1.2),
  ("DATA", "57 B", 7),
)
#bytefield(
  caption: "Continuation packet (59 payload bytes)",
  ("CID", "4 B", 2),
  ("SEQ 0–127", "1 B", 1.5),
  ("DATA", "59 B", 8.2),
)

Several applications may talk to the key at once, so CTAPHID multiplexes *channels*,
identified by a 4-byte CID that `CTAPHID_INIT` allocates. Only one transaction runs at a
time. A packet from another channel during a transaction is answered with
`ERR_CHANNEL_BUSY` and must not disturb the transaction in progress. This is *channel
isolation* (invariant 5), proved for the Lean model in §9.6. While waiting for the user,
the device sends a `KEEPALIVE` with status `UPNEEDED` at least every 100 ms, so the browser
can show "touch your security key". `CTAPHID_CANCEL` aborts the wait.

== FIDO over BLE

Over Bluetooth Low Energy, the authenticator exposes a GATT service with UUID `0xFFFD` and
four characteristics. The host writes request fragments to `fidoControlPoint`. The device
answers with notifications on `fidoStatus`. `fidoControlPointLength` sets the fragment
size, and `fidoServiceRevisionBitfield` advertises FIDO2 support. Framing works like
CTAPHID without channels: an initial fragment `CMD ‖ HLEN ‖ LLEN ‖ DATA`, then `SEQ ‖ DATA`.
The link must be encrypted (LE Secure Connections) before the FIDO characteristics accept
anything.
