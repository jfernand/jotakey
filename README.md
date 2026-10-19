# Jotakey

A FIDO2 / WebAuthn security key, in the family of the YubiKey, written in Rust and
engineered as security-critical software: tested, fuzzed, mutation-tested, and with its
security-critical state machines proved in Lean 4.

It runs on two platforms:

- **The jotakey key** (`hardware/`): a USB-A dongle with an STM32L432 microcontroller and an
  Infineon OPTIGA Trust M secure element. Hardware 0.1.0 is designed and ready to order; its
  firmware port is next.
- **The Espressif ESP32-C6 DevKit**: the development platform, where the MVP firmware runs
  today (CTAP 2.0, non-resident credentials, USB through a Linux bridge, and BLE).

## Where to start

| | |
|---|---|
| `docs/jotakey.pdf` | The design report: FIDO and passkeys from first principles, the threat model, the key hierarchy, testing and formal verification. `docs/jotakey-print.pdf` is the same for paper. |
| `AGENTS.md` | The normative rules: security invariants, key hierarchy, coding rules, commands. |
| `hardware/HARDWARE.md` | The board: part choices against their datasheets. |
| `hardware/MANUFACTURING.md` | How to order a hardware release from JLCPCB. |
| `crates/jotakey-core` | The protocol core: `no_std`, no allocation, no `unsafe`. |
| `formal/` | Lean 4 models and proofs. |
| `crates/jotakey-explorer` | `just explore`: a terminal browser for the FIDO keys attached to this computer, any make. |
| `examples/webauthn-topcoat` | A demo web app: register a Jotakey and sign in with it, on `localhost`. |

## Versions

Hardware and firmware are versioned separately: hardware releases are tagged `hw-vX.Y.Z`,
firmware releases `fw-vX.Y.Z`. Each release publishes both versions of the report.

## Copyright

(c) Javier Fernandez @ JotaSoft 2026. All rights reserved.

Third-party documents cited by the design are not part of this repository; see
`docs/references/README.md` and `hardware/datasheets/README.md` for where to obtain them.
