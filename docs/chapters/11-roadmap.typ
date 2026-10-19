// (c) Javier Fernandez @ JotaSoft 2026
#import "../isss-template.typ": *
#import "../lib.typ": *

= Roadmap

The MVP is deliberately small: every line of it is tested, fuzzed, mutation-tested, and,
for the security-critical state machines, proved. The next steps, in order, each follow
the same discipline: model, prove, implement, test, fuzz, mutate.

== Full CTAP 2.1 passkeys

Discoverable credentials ("username-less passkeys") need the authenticator to *store*
something per credential, and need a PIN, because a discoverable credential with only
presence would let anyone holding the key list your accounts. The steps:

+ *Resident-key store.* A fixed-capacity table in the `jotakey` partition (for example 64
  entries). Each entry holds `rpIdHash`, the user handle (≤ 64 bytes), user name and
  display name (truncated), a creation counter, and the credential nonce. The private key
  is still derived, not stored. Entries live in a record log like the counter's, so writes
  stay power-safe. Lean: model the store as a finite map, and prove capacity bounds and
  that deletion really deletes.
+ *makeCredential with `rk: true`.* Store the entry *before* returning the response.
  Replace an existing entry for the same (`rpIdHash`, user handle). Return
  `CTAP2_ERR_KEY_STORE_FULL` when full. Advertise `options.rk = true`.
+ *getAssertion without allow list.* Find all entries for the RP, newest first. Return the
  first with `numberOfCredentials`, then serve `authenticatorGetNextAssertion` (0x08) from a
  short-lived iterator that a new command or a 30 s timeout invalidates. Include `user` in
  the response (only `id` unless UV was performed).
+ *clientPIN, protocol 2.* _Done_ (§6.5). getPINRetries, getKeyAgreement, setPIN, changePIN,
  getPINToken and getPinUvAuthTokenUsingPinWithPermissions with the `mc` and `ga`
  permissions; tokens in makeCredential and getAssertion set the UV flag. The lockout rules
  are invariant 10, proved in Lean (§10.8) and checked by a model-based fuzz target. What
  remains:
  - *On the key, enforce the PIN in the OPTIGA.* Today the microcontroller compares the PIN
    and keeps the counter, so an attacker who runs code on it can skip both. The OPTIGA's
    monotonic counters and access conditions may let the secure element refuse to derive
    a credential's seed unless the PIN was presented, which would make the PIN protect
    against a laboratory thief too. Whether the Trust M V1 can do this is open.
  - *`FIDO_2_1`.* Advertising it needs the rest of CTAP 2.1: `authenticatorSelection`,
    credential management for resident keys, and the getInfo members that go with them.
  - *Built-in verification* (a fingerprint sensor) would add `uv`, getUVRetries and
    getPinUvAuthTokenUsingUvWithPermissions; the PIN stays as the fallback CTAP requires.
+ *credentialManagement (0x0A).* Enumerate RPs and credentials, delete credentials, update
  user info. Requires a `pinUvAuthToken` with the `cm` permission.
+ *Extensions.* `credProtect` (levels 1–3: hide credentials from assertion without UV),
  `hmac-secret` (symmetric secrets for disk encryption and password managers, derived per
  credential with a salt from the platform), and later `largeBlob`.
+ *U2F / CTAP1 compatibility.* `U2F_REGISTER` and `U2F_AUTHENTICATE` over `CTAPHID_MSG`,
  for older relying parties. Clear the `NMSG` capability bit.
+ *Versions and conformance.* Advertise `FIDO_2_1` and pass the FIDO Alliance conformance
  tools for the implemented feature set.

== Hardware

The jotakey key (§7.5) delivered the two largest hardware steps of the original plan: a
secure element holding the root, generated on the device, and native USB without a bridge.
What follows:

- *Firmware for the jotakey key.* The core already derives per credential (§6.3), on both
  platforms. Next come the STM32 adapters: USB HID, the touch sensor, the LED, the OPTIGA
  driver with its shielded connection, and the provisioning build.
- *Signed firmware updates (exploration).* Production keys are locked and never updated
  (§7.5). An alternative worth studying is a small, immutable bootloader that installs only
  firmware signed with an offline key. It would let fixes reach deployed keys, at the price
  of a bootloader that is itself security-critical code to design, test and prove.
- *OPTIGA Trust M V3*, once it is in stock: the same package and pinout, with HMAC, HKDF and
  AES. `F` would become HMAC-SHA256 on both platforms.
- *Signing inside the secure element*, which would stop a thief who breaks the
  microcontroller from using the key at all. It needs a secure element that can sign with
  derived keys, or a fixed-size store of per-credential keys.
- *Persistent BLE bonds* on the C6, in the encrypted partition, so phones and laptops do not
  have to re-pair after a power cycle.

== Assurance

- *Aeneas experiment* (§9.7): translate `ctaphid.rs` and `cbor.rs` to Lean with
  Charon/Aeneas, and prove that the generated functions refine the hand-written models.
  The core is already written in the supported Rust subset.
- *Kani harnesses*: prove absence of panics in the decoders and state machines for all
  inputs up to a bound, directly on the Rust code.
- *Lean models for the record log* (power-loss safety as a theorem over interleavings of
  writes and cuts) and for the BLE framer.
- *Reproducible firmware builds* and published hashes, so a user can check that the
  binary they flash is the one that was reviewed.
- *Side-channel evaluation* of the signing path with a ChipWhisperer-class setup, to put
  numbers on chapter 7.
