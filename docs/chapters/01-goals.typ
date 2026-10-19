// (c) Javier Fernandez @ JotaSoft 2026
#import "../isss-template.typ": *
#import "../lib.typ": *

= Goals and threat model

== Project scope

A *security key* is a small device that holds private keys and uses them to prove the
holder's identity to websites, without ever letting those keys out. You plug it in (or
bring it close, or pair it over Bluetooth), the browser asks it to sign a challenge, a
light blinks, you touch it, and you are logged in. The YubiKey is the best-known example.

Jotakey does the same job on two platforms. *jotakey* is its own hardware: a
USB-A dongle with an STM32L432 microcontroller, which talks to the computer directly as a
USB security key, and an Infineon *OPTIGA Trust M* secure element, which holds the root
secret. A capacitive touch pad is its "touch" sensor and a red LED its only display
(`hardware/HARDWARE.md`).

The *ESP32-C6 DevKit* is an inexpensive, commonly available, open development board: a
160 MHz RISC-V microcontroller with Wi-Fi 6, Bluetooth LE and 802.15.4 radios, 512 KiB of
SRAM and 4–8 MiB of flash. It has two USB-C ports and two buttons, *BOOT* and *RESET*, plus
one addressable RGB LED; Jotakey uses the BOOT button as its touch sensor. The DevKit has no
secure element and needs a host bridge for USB (§6.1), so it serves as the development
platform, and jotakey is the device to carry.

#spec(
  ("Protocol", [FIDO2: CTAP 2.0 authenticator, WebAuthn-compatible]),
  ("Algorithms", [ES256 (ECDSA P-256 with SHA-256), HMAC-SHA256, HKDF-SHA256]),
  ("Transports", [CTAPHID over USB (native on the key; through a host bridge on the C6), FIDO over BLE (C6)]),
  ("Credentials", [Non-resident ("server-side") credentials, unlimited in number]),
  ("User presence", [Touch pad (key) or BOOT button (C6), debounced, fresh press required for every signature]),
  ("Root of trust", [OPTIGA Trust M secure element (key); eFuse HMAC key (C6)]),
  ("Language", [Rust, `no_std`, no heap in the protocol core, no `unsafe` in the core]),
  ("Verification", [Lean 4 models and proofs of the security-critical state machines]),
)

== Correctness

A user believes they are protected when using this device. There are three ways in which this trust would be broken:

+ *Key compromise.* If an attacker learns a credential's private key, they can log in as
  the user from anywhere, forever, and the user cannot tell.
+ *Silent use.* If the key can be made to sign without the user's knowledge (no touch, or a
  touch meant for something else), an attacker who controls the computer can log in to any
  account registered with the key.
+ *Denial of service, and confusion.* Crashes, lockups or ambiguous parsing let a malicious host wedge
  the device, or worse, make two components disagree about what was signed.

The rest of this report is about making these failures impossible by construction where we
can, unlikely where we cannot, and *documented* everywhere.

== Threat model

We assume a strong attacker.

#dtable(
  columns: (1.15fr, 2fr, 1.2fr),
  ("Attacker", "Capabilities", "Outcome for Jotakey"),
  ([Phishing site], [Lures the user to `examp1e.com` and relays their login to `example.com`.],
    [*Defeated.* Credentials are bound to the RP ID. The browser enforces the origin; the key
     enforces the binding (§4.3, invariant 3).]),
  ([Malware on the host], [Full control of the computer and browser: can send any CTAP
    message at any time, read every response.],
    [*Contained.* It cannot extract keys. It can ask for signatures, but each one needs a fresh
     physical touch (invariant 1). It can trick the user into touching for the wrong site.
     That is inherent to every security key without a display.]),
  ([Malicious USB/BLE peer], [Sends malformed, oversized or out-of-order frames.],
    [*Defeated.* Total parsers, bounded buffers, strict canonical CBOR, channel isolation
     (invariants 4–5). Verified by fuzzing and Lean proofs.]),
  ([Network eavesdropper], [Sees all WebAuthn traffic between browser and website.],
    [*Irrelevant.* Only public keys and signatures over fresh challenges travel.]),
  ([Database breach at the RP], [Steals every stored public key and credential ID.],
    [*Irrelevant.* Public keys cannot be used to log in; credential IDs are useless without
     the device's root key.]),
  ([Thief, casual], [Holds the device for minutes, no lab.],
    [*Defeated with a PIN; partially without.* With a PIN set, every login that asks for
     user verification needs it, and the key blocks after 8 wrong guesses (3 per power
     cycle, invariant 10). Without a PIN, or where a site asks only for presence, the thief
     can log in where the user only needs a security key. Accounts that also require a
     password stay safe.]),
  ([Thief, laboratory], [Decapsulation, voltage/EM fault injection, power analysis.],
    [*Jotakey key: partially defeated.* The root secret and the counter stay in the OPTIGA
     secure element (EAL6+ hardware). A thief who breaks the STM32 can *use* the key while holding
     it, and copy a credential only if they also obtain its ID from the website; they
     cannot copy the key as a whole (§7.5). *ESP32-C6: not defeated.* Published attacks
     bypass secure boot and flash encryption on this chip family (§7.4).]),
  ([Supply chain], [Tampered board or toolchain before provisioning.],
    [*Out of scope* for the MVP; partially mitigated by reproducible builds and secure boot.]),
)

#callout(kind: "trap", "Summary")[
  Jotakey is a strong defence against *remote* attackers: phishing, malware and network
  attackers, which are the most common. Against a well-equipped attacker with
  physical possession, the two platforms differ. *jotakey* keeps its root secret in a
  certified secure element, so a stolen key cannot be cloned as a whole, although an
  attacker who breaks its microcontroller can use it while they hold it. The ESP32-C6 has no secure
  element and gives its secrets up as stated in the threat model, in `AGENTS.md`,
  and in the roadmap.
]

== Security invariants

The design is centered around ten invariants. They are written in `AGENTS.md` (normative for
anyone changing the code). Each is enforced in code and checked by tests. Where marked
⊢, they are also proved in Lean. Appendix A traces each invariant to its implementation,
tests and theorems.

#dtable(
  columns: (0.3fr, 2.6fr, 0.35fr),
  ("#", "Invariant", "Lean"),
  ([1], [No signature carrying the UP flag without a user-presence event consumed within the same command.], [⊢]),
  ([2], [The signature counter strictly increases, across power loss.], [⊢]),
  ([3], [A credential ID unwraps only for the relying party it was minted for.], [⊢]),
  ([4], [Parsers are total and bounded: every input yields a result, never a crash.], [⊢]),
  ([5], [CTAPHID channels are isolated from each other.], [⊢]),
  ([6], [Reset only within 10 s of power-up, and only with a touch.], [⊢]),
  ([7], [Fail closed: failed self tests disable the authenticator permanently.], [⊢]),
  ([8], [The root secret never leaves its hardware key store (OPTIGA or eFuse HMAC); secrets are zeroized, never logged.], []),
  ([9], [No secret-dependent branches or memory accesses in our code.], []),
  ([10], [At most 8 wrong PINs between correct ones, 3 per power cycle; every attempt is counted durably before the PIN is compared.], [⊢]),
)
