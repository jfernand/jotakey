// (c) Javier Fernandez @ JotaSoft 2026
#import "../isss-template.typ": *
#import "../lib.typ": *

#set heading(numbering: "A.1")
#counter(heading).update(0)

= Invariant traceability

Every invariant of `AGENTS.md` §2, with where it is enforced, tested and proved.

#breakable-code[
#dtable(
  columns: (0.25fr, 1.3fr, 1.3fr, 1.15fr),
  ("#", "Enforced in", "Tested / fuzzed", "Proved (formal/Jotakey/…)"),
  ([1], [`ctap/mod.rs` `complete` (only UP=1 signing path); silent `up:false` assertions signed with UP clear; `presence.rs` fresh debounced press], [`no_signature_without_presence`, `processing_parks_and_complete_consumes`, `silent_assertion_signs_at_once_without_the_up_flag`; `ctap_dispatch` oracle], [`Authenticator.signature_requires_confirmed_touch`, `request_signs_only_silently`, `one_touch_signs_at_most_once`]),
  ([2], [`increment_counter` before signing; `storage.rs` append + read-back (C6); OPTIGA up-counter (key)], [`register_then_authenticate…`, `monotonic_across_power_cuts`, on-device torn write], [`Authenticator.trace_signature_counters_increase`]),
  ([3], [`credential.rs` tag over rpIdHash, `ct_eq`], [`bound_to_rp`, `any_bit_flip_is_rejected`, `credential_is_bound_to_rp`; `credential_unwrap`], [`Credential.unwrap_accepts_only_wrapped_ids`, `credential_bound_to_relying_party`]),
  ([4], [`cbor.rs` strict decoder; `MAX_MSG_SIZE` everywhere; no-panic lints], [`decoder_never_panics`, size boundaries; all fuzz targets; differential test], [`Cbor.decodeHead_accepts_only_canonical`, `decodeHead_consumes_input`; `CtapHid.receivePackets_preserves_well_formed`]),
  ([5], [`ctaphid.rs` single transaction, owner checks], [`other_channel_gets_busy…`, `hid_init_resync_only_touches…`; `ctaphid_stack`], [`CtapHid.receivePackets_ignores_other_channels`, `fragmented_message_is_reassembled`]),
  ([6], [`ctap/reset.rs` window + touch; epoch rotation], [`reset_window_and_effect`, `reset_window_boundary_is_inclusive`], [`Authenticator.epoch_change_requires_confirmed_touch`, `epoch_change_requires_reset_in_window`]),
  ([7], [`main.rs` boot sequence; `Authenticator::fault`; `RngHealth` on every byte], [`fails_closed`, `every_injected_fault_is_detected`, on-device KATs and TRNG], [`Authenticator.faulted_stays_faulted_and_never_signs`]),
  ([8], [`Zeroizing` secrets; HMAC peripheral (C6) or OPTIGA (key); no `Debug` of secrets], [Review; `cargo deny`], [—]),
  ([9], [`subtle::ConstantTimeEq`; RustCrypto `p256`], [Review], [—]),
)
]

= Repository map

#dtable(
  columns: (1.3fr, 2.4fr),
  ("Path", "Contents"),
  ([`AGENTS.md`], [Normative requirements and security rules for anyone (human or AI) changing the code.]),
  ([`crates/jotakey-core`], [Protocol core; `tests/` (CTAP, transports, differential).]),
  ([`crates/jotakey-fw`], [Firmware; `partitions.csv`; `deny.toml` with documented exceptions.]),
  ([`crates/jotakey-testfw`], [On-device tests (`cargo test` with the board attached).]),
  ([`crates/jotakey-bridge`], [Linux serial ⇄ uhid bridge.]),
  ([`crates/jotakey-host-tests`], [Independent client, simulator, RP checks, hardware tests.]),
  ([`fuzz/`], [Six cargo-fuzz targets; `seeds/` written by `make_seeds.py`.]),
  ([`formal/`], [Lean 4: `Cbor`, `CtapHid`, `Authenticator`, `Credential`; `Main.lean` (executable spec); `AxiomAudit.lean`.]),
  ([`scripts/`], [`provision.sh` (irreversible, human-only), udev rules, `fido2_check.py`.]),
  ([`docs/`], [This report (`typst compile docs/jotakey.typ`).]),
)

= Getting started

#codepanel(title: "From clone to a working key (development build)")[
```sh
rustup target add riscv32imac-unknown-none-elf
cargo install espflash probe-rs-tools cargo-fuzz cargo-mutants cargo-deny just
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh

just test && just lean && just diff          # host tests, proofs, Rust-vs-Lean
cd crates/jotakey-fw
cargo run --release --features dev-key       # INSECURE dev key; logs on the UART port
cd ../.. && just bridge /dev/ttyACM0         # needs /dev/uhid access (scripts/99-jotakey.rules)
python3 scripts/fido2_check.py               # or register at https://webauthn.io
```
]

= Glossary

#dtable(
  columns: (0.9fr, 2.6fr),
  ("Term", "Meaning"),
  ([AAGUID], [Authenticator Attestation GUID: 16 bytes identifying the authenticator model.]),
  ([Assertion], [The signed response of an authentication ceremony.]),
  ([authData], [authenticatorData: rpIdHash, flags, counter, optional credential data.]),
  ([CBOR], [Concise Binary Object Representation (RFC 8949).]),
  ([COSE_Key], [CBOR encoding of a public key (RFC 9052/9053).]),
  ([CTAP], [Client-to-Authenticator Protocol (FIDO Alliance).]),
  ([CTAPHID], [CTAP over USB HID: 64-byte reports, channels.]),
  ([Discoverable credential], [Resident key: stored on the authenticator with the user handle; a "passkey".]),
  ([KAT], [Known-answer test: compute on fixed input, compare with a published result.]),
  ([Relying party (RP)], [The website or service that registers and verifies credentials.]),
  ([RP ID], [The domain a credential is scoped to.]),
  ([UP / UV], [User presence (a touch) / user verification (PIN or biometric).]),
  ([WebAuthn], [W3C Web Authentication API, the browser side of FIDO2.]),
)

= References

#set text(size: 8.4pt)
- FIDO Alliance. *Client to Authenticator Protocol (CTAP)*, versions 2.0 (2019), 2.1 (2021), 2.2.
- W3C. *Web Authentication: An API for accessing Public Key Credentials*, Levels 2 and 3.
- C. Bormann, P. Hoffman. *RFC 8949: Concise Binary Object Representation*, 2020.
- T. Pornin. *RFC 6979: Deterministic Usage of DSA and ECDSA*, 2013.
- H. Krawczyk, P. Eronen. *RFC 5869: HKDF*, 2010.
- NIST. *SP 800-90B: Recommendation for the Entropy Sources Used for Random Bit Generation*, 2018.
- Espressif. *ESP32-C6 Technical Reference Manual*; *Security Advisory AR2023-007* (2024).
- W. M. McKeeman. *Differential Testing for Software*, Digital Technical Journal 10(1), 1998.
- X. Yang, Y. Chen, E. Eide, J. Regehr. *Finding and Understanding Bugs in C Compilers (Csmith)*, PLDI 2011.
- G. Klein et al. *seL4: Formal Verification of an OS Kernel*, SOSP 2009.
- X. Leroy. *Formal verification of a realistic compiler*, CACM 2009.
- J.-K. Zinzindohoué et al. *HACL\*: A Verified Modern Cryptographic Library*, CCS 2017.
- A. Erbsen et al. *Simple High-Level Code for Cryptographic Arithmetic (Fiat-Crypto)*, S&P 2019.
- S. Ho, J. Protzenko. *Aeneas: Rust Verification by Functional Translation*, ICFP 2022.
- L. de Moura, S. Ullrich. *The Lean 4 Theorem Prover and Programming Language*, CADE 2021.
- E. W. Dijkstra. *Notes on Structured Programming*, 1970.
