#import "isss-template.typ": *
#import "lib.typ": *

#show: isss-doc.with(
  title: "Jotakey",
  subtitle: "A formally specified FIDO2 security key on the ESP32-C6",
  author: "Javier",
  contact: "jfernand@me.com",
  date: "2026-10-14",
  docid: "JK-TR-001 · rev 0.1",
  running: "Jotakey — FIDO2, passkeys and formal verification",
  abstract: [
    Jotakey is a hardware security key, in the family of the YubiKey, built on an Espressif
    ESP32-C6 DevKit and written entirely in Rust. This report has three aims. First, it
    explains from first principles how FIDO2, WebAuthn and *passkeys* work, and why they
    defeat phishing where passwords and one-time codes fail. Second, it documents the design
    of Jotakey: its threat model, key hierarchy, transports, and the honest limits of a
    microcontroller without a secure element. Third, it describes how the device is
    *assured*. Unit and property tests, coverage-guided fuzzing, mutation testing, and a test
    firmware that runs on the chip itself are all covered. So is formal verification in the
    Lean 4 theorem prover. The report assumes no prior knowledge of formal methods, and its
    longest chapter is a self-contained introduction to them, built on the proofs that
    actually ship with the device.
  ],
  meta: (
    ("Status", [MVP: CTAP 2.0, non-resident credentials, USB (via bridge) and BLE]),
    ("Hardware", [Espressif ESP32-C6-DevKitC-1 / M-1 (two USB-C ports)]),
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
#include "chapters/10-roadmap.typ"
#include "chapters/appendix.typ"
