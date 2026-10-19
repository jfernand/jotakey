// (c) Javier Fernandez @ JotaSoft 2026
#import "isss-template.typ": *
#import "lib.typ": *

#show: isss-doc.with(
  title: "Jotakey",
  subtitle: "A formally specified FIDO2 security key",
  author: "Javier Fernandez",
  contact: "jfernand@me.com",
  date: "2026-10-14",
  docid: "JK-TR-001 · rev 0.1",
  running: "Jotakey — FIDO2, passkeys and formal verification",
  copyright: "(c) Javier Fernandez @ JotaSoft 2026",
  abstract: [
    Jotakey is a hardware security key, in the family of the YubiKey, with firmware written in
    Rust. It runs on its own board, the jotakey key (an STM32L432 microcontroller with an
    OPTIGA Trust M secure element), and on an Espressif ESP32-C6 DevKit.

    We explain from first principles how FIDO2, WebAuthn and *passkeys* work, and why they
    defeat phishing where passwords and one-time codes fail. We also document the design
    of Jotakey: its threat model, key hierarchy, transports, and the honest limits of each
    platform against an attacker who holds the device. Finally, we describe how the device is
    *assured*: Unit and property tests, coverage-guided fuzzing, mutation testing, and test
    firmware. Formal verification in the
    Lean 4 theorem prover is also covered. We assume no prior knowledge of formal methods.
  ],
  meta: (
    ("Status", [MVP firmware on the ESP32-C6: CTAP 2.0, non-resident credentials, USB (via bridge) and BLE. Jotakey key: hardware 0.1.0; firmware port next]),
    ("Hardware", [Jotakey key, hardware 0.1.0 (STM32L432KC + OPTIGA Trust M V1, USB-A); Espressif ESP32-C6-DevKitC-1 / M-1]),
    ("Repository", [`crates/` (Rust), `formal/` (Lean 4), `docs/` (this report)]),
    ("Normative rules", [`AGENTS.md` — security invariants 1–9]),
  ),
)

#outline(title: none, depth: 2, indent: 1em)
#pagebreak()

#include "chapters/01-goals.typ"
#include "chapters/02-crypto.typ"
#include "chapters/03-fido.typ"
#include "chapters/04-webauthn.typ"
#include "chapters/05-ctap.typ"
#include "chapters/06-architecture.typ"
#include "chapters/07-hardware.typ"
#include "chapters/08-testing.typ"
#include "chapters/09-formal.typ"
#include "chapters/10-proofs.typ"
#include "chapters/11-roadmap.typ"
#include "chapters/appendix.typ"
