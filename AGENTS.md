# AGENTS.md — Jotakey

Jotakey is a **high-security FIDO2 authenticator** (a YubiKey-like security key) written in Rust
for two platforms:

- the **jotakey key** (`hardware/jotakey-key`, primary): a USB-A dongle with an STM32L432KC
  microcontroller and an Infineon OPTIGA Trust M V1 secure element;
- the **Espressif ESP32-C6 DevKit** (the board with two USB-C ports, secondary): a development
  platform without a secure element.

It must be engineered as security-critical software: correctness and key secrecy outrank
features, speed and convenience. If a change trades away an invariant below, it is wrong.
Stop and ask a human.

## 1. Product requirements (distilled)

- Act as a FIDO2 / WebAuthn authenticator ("passkey" device) for websites and operating systems.
- Rust everywhere. Firmware is `no_std`: `esp-hal` on the ESP32-C6. The jotakey key's firmware
  is not written yet; its HAL is chosen with the port (§4, new dependencies).
- **Transport-agnostic CTAP core.** Implement **CTAPHID** and **BLE** transports.
  - The jotakey key is a native USB full-speed device: CTAPHID over USB HID, no bridge. It has
    no radio, so no BLE.
  - The C6's native USB is a fixed-function **USB-Serial/JTAG** block. It **cannot** be a HID
    device. HID reaches the host through `jotakey-bridge`, a Linux daemon that tunnels CTAPHID
    64-byte reports over the serial port and exposes a virtual FIDO HID device through `/dev/uhid`.
    The bridge is **untrusted** (as the host always is in FIDO). Security must never depend on it.
    BLE exists only on the C6.
- **MVP scope = minimal CTAP2.0**: `authenticatorGetInfo`, `authenticatorMakeCredential`,
  `authenticatorGetAssertion`, `authenticatorReset`. Credentials are non-resident and there is no PIN.
  The full CTAP2.1 passkey roadmap (resident keys, clientPIN v2, credMgmt, hmac-secret, credProtect,
  U2F) is documented in `docs/jotakey.typ` and is next.
- Documentation: `docs/jotakey.typ` (Typst, **ISSS design system**, template `docs/isss-template.typ`).
  It explains FIDO/passkeys, the design, the threat model, and formal verification in depth
  for a reader new to the field. The board is documented in `hardware/HARDWARE.md`.
- Assurance: unit + property tests, **fuzzing**, **mutation testing**, **on-device test firmware**,
  and **Lean 4 formal models** with proofs and differential testing against the Rust code.

## 2. Security invariants (non-negotiable)

Each invariant is enforced in code, tested, and (where marked ⊢) proved in the Lean model in `formal/`.

1. ⊢ **User presence:** no signature carrying the UP flag is produced without a user-presence
   event (the touch electrode on the key, the BOOT button on the C6) consumed *within the same
   command*. A UP timeout yields `CTAP2_ERR_USER_ACTION_TIMEOUT`. getAssertion with
   `up: false` (a silent assertion, the pre-flight probe clients such as python-fido2 and
   browsers send) is answered at once with the UP flag clear; WebAuthn requires relying
   parties to reject such an assertion. In the core, UP=1 signatures happen only in
   `Authenticator::complete` under `PresenceResult::Confirmed`; the silent path is
   `get_assertion::sign(…, user_present: false, …)` from `Authenticator::process`.
2. ⊢ **Monotonic counter:** the signature counter strictly increases across power loss.
   Persist `N+1` *before* releasing a signature that carries `N+1`. On the key the counter is
   an OPTIGA hardware up-counter, which cannot go down even under a compromised MCU; on the
   C6 it is a flash record log.
3. ⊢ **RP binding:** a credential ID unwraps only for the `rpIdHash` it was minted for. Tag
   comparison is constant-time (`subtle`).
4. ⊢ **Total parsers:** every byte string from the host yields `Ok` or `Err`. No panic, no
   unbounded recursion or allocation. Limits: CBOR depth ≤ 4, CTAP message ≤ `MAX_MSG_SIZE`
   = 1200 bytes (advertised as `maxMsgSize`; below the 7609-byte CTAPHID ceiling), canonical
   CBOR only (shortest-form heads, sorted unique map keys, no tags/floats/indefinite lengths).
5. ⊢ **CTAPHID channel isolation:** traffic on one CID never alters a transaction on another.
   Busy, cancel and timeout semantics follow the CTAP spec.
6. ⊢ **Reset:** `authenticatorReset` is allowed only within 10 s of power-up and only with UP.
7. **Fail closed:** if power-on KATs or RNG health tests fail, or (on the key) the OPTIGA cannot
   be reached over its shielded connection, refuse all crypto and show the fault pattern on the LED.
8. **Secrets:** the root secret never leaves its hardware key store: the OPTIGA on the key,
   the eFuse HMAC peripheral on the C6. Derived keys are `Zeroize`d on drop. No secret,
   private key, nonce or tag is ever logged, printed, `Debug`-formatted, or returned in an error.
9. **Constant time:** branching and memory access on secret data are forbidden in our own code.
   Use `subtle` for comparisons and RustCrypto for scalar arithmetic.

## 3. Key hierarchy (do not change without updating doc + Lean model)

Both platforms share one hierarchy; only the root and the function that derives from it differ.

- **Root.**
  - Key: `K_root`, 64 bytes in OPTIGA data object `0xF1D0` (type `PRESSEC`). Created *on the
    device* at provisioning as `SHA-512(OPTIGA TRNG(64) ‖ STM32 RNG(64))`, written once, then
    locked: read `NEV`, change `NEV`, execute `Conf(0xE140)` (only over the shielded connection).
  - C6: `K_dev`, 256-bit key in an eFuse key block, purpose `HMAC_UP`, read-protected.
- `epoch`: 32 random bytes in flash (key: STM32 flash under readout protection; C6: encrypted
  flash), regenerated by `authenticatorReset`.
- **Per-credential derivation, inside the hardware key store.** For a credential with nonce
  `nonce` at relying party `rpIdHash`:
  `tag = F(root, "jotakey/tag/v1" ‖ epoch ‖ 0x01 ‖ rpIdHash ‖ nonce)[..16]`,
  `seed = F(root, "jotakey/seed/v1" ‖ epoch ‖ rpIdHash ‖ nonce)[..32]`, where `F` is
  TLS1.2-PRF-SHA256 run by the OPTIGA (`DeriveKey`, result returned over the shielded
  connection) on the key, and HMAC-SHA256 run by the HMAC peripheral on the C6. The MCU never
  holds a secret that covers more than one credential: an attacker running code on it can
  use the key while holding it, and copy only the credentials whose IDs it also obtains from
  the relying parties, never the key as a whole. A reset invalidates every credential while
  the root stays immutable.
- makeCredential: `nonce ← TRNG(32)`.
  `priv = P256 scalar from HKDF-SHA256(ikm=seed, salt=rpIdHash, info="jotakey/cred/v1"‖nonce)`
  (rejection-sampled until the value is a valid nonzero scalar). Signing runs on the MCU.
  The seed is derived only after the tag has verified.
- `credId = 0x01 ‖ nonce(32) ‖ tag(16)`.
- **In code:** `Platform::derive_secret(label, context, out)` computes
  `F(root, label ‖ epoch ‖ context)`; labels `CredentialTag` and `CredentialSeed`. The core
  asks for one credential at a time (`ctap::PlatformTagger`, `ctap::credential_seed`), and a
  failing derivation is an error, never "not our credential".
- **Shielded connection (key):** OPTIGA ↔ STM32 traffic for the root and the counter is
  encrypted and authenticated with a 64-byte platform binding secret, held in OPTIGA object
  `0xE140` (read `NEV`, change `NEV`) and in STM32 flash. It is created on the device at
  provisioning, like the root.
- **Signature counter (key):** OPTIGA monotonic up-counter `0xE120`, threshold 600 000 (the
  rated endurance). At the threshold it freezes and the key refuses to sign.
- Attestation: `packed` self-attestation. Persistent MCU state: the key stores the epoch and
  the binding secret; the C6 stores the counter and the epoch.

## 3a. Design decisions made during implementation (keep consistent)

- **Core is a resumable state machine:** `process` → `NeedsUserPresence` → `complete(PresenceResult)`.
  Signing with the UP flag is reachable only from `complete` with `Confirmed`; the one other
  signing path is the silent assertion, which signs with the flag clear. Do not add others.
- **User presence:** the sensor must be seen released after the request, then pressed for
  ≥ 40 ms; 30 s timeout; keepalive `UP_NEEDED` every ≤ 100 ms. The key reads its touch
  electrode with the STM32 touch-sensing controller (TSC); the C6 reads its BOOT button.
- **Self tests** take an explicit fault-injection parameter (`run_kats(None)` in production)
  so tests can prove the fail-closed path.

The jotakey key:

- **Production units are locked and never updated.** Provisioning ends with STM32 readout
  protection level 2: debug is disabled permanently and the firmware is frozen, like a YubiKey.
  A security fix means a new key. Development boards stay at level 0. Signed firmware updates
  are a documented future exploration, not a feature.
- **Provisioning runs on the device**, started by a human: pair the shielded connection,
  create and lock `K_root`, configure the counter, write the epoch; then a human sets
  readout protection level 2. Secrets are generated on the device and never leave it.
- **Pins:** touch on PB4/PB5 (TSC group 2), LED on PA3, OPTIGA on I2C1 (PA9 SCL, PA10 SDA)
  with reset on PA5, USB on PA11/PA12, SWD on the five bottom-side test pads.
  `hardware/HARDWARE.md` is the reference.

The ESP32-C6:

- **Two USB ports, two roles:** "USB" (USB-Serial/JTAG) carries *only* framed CTAPHID
  reports (`transport/serial.rs`: COBS + CRC-32, `0x00`-delimited). Logs and panics go to the
  "UART" port. Never print on the USB-Serial/JTAG port in the firmware.
- **BLE is off by default;** a 3 s button hold while idle enables advertising for 120 s.
  FIDO characteristics require an encrypted link (LESC, Just Works; no display). Bonds are
  RAM-only in the MVP.
- **Persistent state** = counter + epoch only, each in a two-sector `storage::RecordLog`
  (append + read-back verify; never erase the sector holding the latest record). Region:
  `jotakey` partition at 0x3F0000 (`crates/jotakey-fw/partitions.csv`). The test firmware
  uses only the scratch half at 0x3F8000.
- **`dev-key` feature** = INSECURE software root key (magenta LED at boot). Never ship it.

## 4. Coding rules

- `crates/jotakey-core` holds **all protocol logic**. It is `no_std`, has no `alloc`, uses
  `#![forbid(unsafe_code)]`, and must have no `unwrap`/`expect`/`panic!`/unchecked indexing.
  Clippy denies these. Firmware crates are thin adapters behind the `platform` traits.
- Write core code in an **Aeneas-friendly** style: no trait objects or closures in hot logic,
  simple loops, explicit bounds. This keeps a future Rust→Lean translation (Charon/Aeneas)
  possible. That experiment is planned and not yet done.
- `overflow-checks = true` in every profile. Prefer `checked_*`/`saturating_*` and explicit errors.
- New dependencies need justification (security review, `cargo deny check`). Prefer RustCrypto.
- **Never take an irreversible step from automation:** do not burn eFuses, enable secure boot
  or flash encryption, or run `espefuse` (C6); do not set STM32 readout protection level 1 or 2,
  write-protect flash, or change OPTIGA lifecycle states or lock its objects (key).
  `scripts/provision.sh` documents the C6 steps for a human to run.
- Every change to protocol logic needs: tests, a fuzz target that reaches it (verify that it
  does: an oracle that never fires tests nothing; doc chapter 8), no new surviving
  mutants (`cargo mutants -p jotakey-core` → 0 missed; exclusions in `.cargo/mutants.toml`
  need a written reason), and an update to the Lean model if it touches an invariant.
- Names: Rust and Lean each follow their own conventions, and `formal/NAMES.md` is the
  translation table between them. Any rename or new modelled item on either side updates
  `formal/NAMES.md` and the table in chapter 10 of the doc in the same change. Prefer
  descriptive names over spec abbreviations (`channel`, not `cid`), except for constants
  that quote the CTAP spec (`BROADCAST_CID`, `cmd::CBOR`).
- Lean: no `sorry`, no new `axiom`, no `native_decide`; `formal/AxiomAudit.lean` must list only
  `propext`, `Quot.sound`, `Classical.choice`. Keep `jotakey-spec` and the Rust decoder in
  agreement (`just diff`).
- Firmware dependency versions are pinned to a combination known to work together
  (esp-hal 1.2, esp-rtos 0.4, esp-radio 1.0.0-beta.1, trouble-host 0.7 / bt-hci 0.9).
  Upgrade them together, never one at a time.
- Hardware and firmware are versioned separately (`hardware/HARDWARE.md` §8): the board's
  version is the KiCad text variable `HW_VERSION`, tagged `hw-vX.Y.Z`; the firmware's is the
  Cargo workspace version, tagged `fw-vX.Y.Z`.

## 5. Commands

```sh
just test          # cargo test -p jotakey-core (+ proptest)
just fuzz T        # cargo +nightly fuzz run T with fuzz/seeds/T (targets in fuzz/fuzz_targets)
just mutants       # cargo mutants -p jotakey-core
just lean          # cd formal && lake build && no-sorry check
just diff          # differential tests Rust vs Lean (needs formal/.lake/build/bin/jotakey-spec)
just fw            # build firmware for riscv32imac-unknown-none-elf
just flash         # espflash flash --monitor
just testfw        # on-device tests via probe-rs (embedded-test); board on the "USB" port
just host-tests    # end-to-end against a real device through the bridge (touch when asked)
just deny          # cargo deny (licences, advisories); firmware: cd crates/jotakey-fw && cargo deny check
just bridge        # run the uhid bridge (Linux; needs /dev/uhid access)
just explore       # terminal browser for attached FIDO keys, any make (read-only; --dump prints)
just doc           # typst compile docs/jotakey.typ
just doc-print     # the same, for paper: plain white pages (docs/jotakey-print.pdf)
```

The `fw`, `flash`, `testfw`, `host-tests` and `bridge` recipes target the ESP32-C6.

## 6. Layout

```
crates/jotakey-core      protocol core (CBOR, CTAP2, CTAPHID, BLE framing, credentials, PIN protocol, self-tests)
crates/jotakey-fw        ESP32-C6 firmware (esp-hal, embassy, BLE via esp-radio + trouble-host)
crates/jotakey-testfw    on-device test firmware (embedded-test + probe-rs)
crates/jotakey-bridge    Linux serial↔uhid bridge
crates/jotakey-host-tests end-to-end tests against a real device through the bridge
crates/jotakey-explorer  ratatui browser for FIDO keys over hidraw: INIT, getInfo, PIN retries, U2F VERSION
fuzz/                    cargo-fuzz targets; seeds/ from make_seeds.py
formal/                  Lean 4 models, proofs, executable spec; NAMES.md maps Rust ↔ Lean names
docs/                    Typst document (ISSS design)
hardware/                the jotakey key: HARDWARE.md, KiCad project, layout/route/silk scripts
examples/webauthn-topcoat a demo relying party (Topcoat + webauthn-rs) for trying the key in a browser
scripts/provision.sh     human-run, irreversible device provisioning (dry-run by default)
scripts/fido2_check.py   independent check with python-fido2 (client + RP server)
scripts/99-jotakey.rules udev rules for /dev/uhid and the bridge's hidraw device
```

## 7. Hardware notes

The jotakey key (`hardware/HARDWARE.md`):

- Touch electrode = the user-presence sensor. Single red LED on PA3: blink patterns for touch
  requested, OK and fault.
- The OPTIGA Trust M is built on Common Criteria EAL6+ certified hardware. The STM32L432 is not hardened:
  published fault-injection attacks on STM32 readout protection mean a well-equipped thief
  may run code on the MCU. They can then *use* the key while holding it, and copy credentials
  whose IDs they also obtain, but cannot extract `K_root`, roll back the counter or copy the
  key as a whole (§3). The threat model says so.
- SWD (SWDIO, SWCLK, NRST, 3V3, GND) on bottom-side test pads, for a pogo-pin jig; disabled
  for good by readout protection level 2 on production units.

ESP32-C6 DevKit:

- BOOT button = GPIO9 (active low): the user-presence button.
- Addressable RGB LED = GPIO8 (WS2812, driven by RMT). Amber blink = touch requested,
  green = OK, red = fault.
- "USB" port = USB-Serial/JTAG: CTAPHID tunnel (COBS + CRC-32 framing), flashing, probe-rs.
- "UART" port = USB-to-UART bridge chip; unused in production.
- No secure element. Known EM and voltage fault-injection attacks on C3/C6-class parts are
  documented in the threat model; a thief with lab equipment can extract `K_dev`.
