#import "../isss-template.typ": *
#import "../lib.typ": *

= Jotakey's architecture

== The board, and the USB problem

The ESP32-C6 DevKit has two USB-C ports. The one labelled *UART* goes through a USB-to-serial
bridge chip to the C6's UART0. The one labelled *USB* is wired to the C6's own USB
peripheral. On the C6, that peripheral is the *USB-Serial/JTAG controller*, a
fixed-function block implemented entirely in hardware. It can be a serial port and a JTAG
debug probe, and nothing else. In particular, it *cannot enumerate as a USB HID device*.
Every USB security key is a HID device. (Chips such as the ESP32-S3 have a general USB OTG
controller. The C6 does not.)

Jotakey therefore splits USB into two halves. The device speaks the exact CTAPHID protocol,
with the same 64-byte reports, but sends them over the serial port inside a small framing
layer. On the host, a tiny Linux daemon, `jotakey-bridge`, creates a *virtual* HID device
through the kernel's `/dev/uhid` interface and copies reports in both directions. Browsers
see an ordinary FIDO security key.

#layers(
  caption: "The USB path, top to bottom",
  ("Browser / python-fido2", [Opens `/dev/hidrawN`, speaks CTAPHID, unaware of the bridge.], "light"),
  ("Linux HID core", [Virtual device created via `/dev/uhid` with the FIDO usage page (0xF1D0).], "light"),
  ("jotakey-bridge", [≈200 lines, std Rust: uhid ⇄ serial, COBS + CRC-32 framing. *Outside the security boundary.*], "dark"),
  ("USB-Serial/JTAG", [The DevKit's "USB" port: fixed-function serial channel.], "dark"),
  ("Firmware: usb task", [Deframer → CtapHid → authenticator, and back.], "amber"),
)

#callout(kind: "info", "Why the bridge does not weaken security")[
  FIDO already treats the host as hostile: the authenticator trusts nothing it receives, and
  every signature needs a touch on the device itself. The bridge runs *on* the host, so it
  can do nothing that host malware could not do anyway. It never sees key material, only the
  same CTAP messages any USB host sees. The cost is convenience: the bridge is Linux-only.
  The roadmap (§10) lists a small USB-capable co-processor as the path to a standalone,
  OS-independent device.
]

The framing on the serial line is deliberately simple:

#bytefield(
  caption: "One frame on the serial line: COBS(report ‖ CRC-32) followed by 0x00",
  ("COBS-encoded body (no zero bytes)", "64-byte report + 4-byte CRC-32/ISO-HDLC, ≤ 70 B", 9),
  ("0x00", "delimiter", 1.4),
)

COBS (Consistent Overhead Byte Stuffing) removes every zero byte from the body, so a zero
*always* marks the end of a frame. After line noise or a half-written frame, the receiver
resynchronises at the next zero. The CRC catches corruption. It is an integrity check, not
a security mechanism. Corrupt frames are silently dropped, and CTAPHID's own timeouts take
over. Logs never mix with frames: the firmware prints only to the *UART* port. That gives
the two ports clean roles: "USB" carries the authenticator, "UART" carries diagnostics.

== Software layers

#layers(
  caption: "Crates and their trust levels",
  ("jotakey-core", [`no_std`, no allocation, `#![forbid(unsafe_code)]`, no `unwrap`/`panic!`/unchecked indexing or arithmetic (enforced by Clippy). CBOR, CTAP2 commands, CTAPHID, BLE framing, serial framing, credential wrapping, power-safe storage, self tests. *All* bytes from the host are interpreted here.], "amber"),
  ("jotakey-fw", [ESP32-C6 firmware (esp-hal, embassy, trouBLE). Thin adapters: TRNG, eFuse HMAC key, flash, button, LED, USB-Serial/JTAG, BLE GATT. Implements the core's `Platform` trait.], "dark"),
  ("jotakey-testfw", [On-device test firmware (embedded-test + probe-rs).], "light"),
  ("jotakey-bridge", [Linux host daemon (serial ⇄ uhid).], "light"),
  ("formal/", [Lean 4 models, proofs, and the executable CBOR specification.], "light"),
)

The core is written so that it does not know it runs on a microcontroller. Hardware is
reached only through one trait:

#codepanel(title: "crates/jotakey-core/src/platform.rs (abridged)")[
```rust
pub trait Platform {
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), PlatformError>;
    fn derive_secret(&mut self, label: SecretLabel, out: &mut [u8; 32]) -> Result<(), PlatformError>;
    fn increment_counter(&mut self) -> Result<u32, PlatformError>;   // persisted before return
    fn rotate_epoch(&mut self) -> Result<(), PlatformError>;
    fn uptime_ms(&self) -> u64;
}
```
]

User presence is deliberately *not* in the trait. Waiting for a button is asynchronous and
involves keepalives and cancellation, and none of that belongs inside the protocol logic.
Instead, the core is a *resumable state machine*. `Authenticator::process` validates a
request completely. If it needs a touch, it parks the validated parameters in a `Pending`
value and returns `NeedsUserPresence`. The firmware blinks the LED, sends keepalives,
watches the button and the cancel signal, then calls `Authenticator::complete` with
`Confirmed`, `Timeout` or `Cancelled`. Signing code is reachable *only* from `complete`
under `Confirmed`. That structural fact is what the Lean model formalises (§9.6).

== The key hierarchy

#layers(
  caption: "From the eFuse root key to a credential's private key",
  ("K_dev (eFuse BLOCK_KEY0)", [256-bit root key, purpose HMAC_UP, read-protected by hardware. Software can only ask the HMAC peripheral to *use* it.], "amber"),
  ("epoch (encrypted flash)", [32 random bytes, replaced by authenticatorReset. Makes reset possible even though eFuses are write-once.], "dark"),
  ("K_mac, K_seed", [HMAC(K_dev, "jotakey/mac/v1" ‖ epoch), HMAC(K_dev, "jotakey/seed/v1" ‖ epoch). Derived per operation, zeroized after use.], "dark"),
  ("credential key d", [HKDF-SHA256(K_seed, salt = rpIdHash, info = "jotakey/cred/v1" ‖ nonce ‖ ctr) → valid P-256 scalar.], "light"),
)

Nothing secret is ever *stored* in flash except the epoch. With flash encryption enabled,
the epoch is unreadable off-chip, and it is useless without `K_dev` anyway. There is no
credential database to steal, fill up or corrupt. The number of credentials is unlimited.

== Credential IDs: keys by derivation

For a non-resident credential the website stores the credential ID and hands it back at
login. Jotakey makes the ID carry everything it needs to *re-derive* the private key, and
authenticates it so that it cannot be forged:

#bytefield(
  caption: "Jotakey credential ID: 49 bytes",
  ("ver", "0x01", 1),
  ("nonce", "32 random bytes", 8),
  ("tag", "HMAC-SHA256(K_mac, ver ‖ rpIdHash ‖ nonce)[..16]", 6),
)

At `getAssertion`, Jotakey recomputes the tag for the *requesting* RP and compares it in
constant time. An ID minted for `example.com` presented by `examp1e.com` fails the check,
because the RP ID hash is inside the tag (invariant 3). A forged or foreign ID fails too.
The nonce is not secret, and the private key is never in the ID, not even encrypted.

#callout(kind: "ok", "Proved in Lean (§9.6)")[
  `unwrap_sound`: anything `unwrap` accepts is *exactly* `wrap(rp, nonce)` for the recovered
  nonce. `rp_binding`: an ID minted for one RP never unwraps at another, *assuming* the MAC
  does not collide across RPs. That assumption is the cryptographic part. It holds for
  HMAC-SHA256/128 except with probability ≈ 2#super[−128], and it is stated explicitly as a
  hypothesis of the theorem rather than hidden.
]

== Persistent state

Only two values persist: the signature counter and the epoch. Each lives in its own
power-loss-safe *record log* of two flash sectors. A new value is appended as a record
`MAGIC ‖ seq ‖ payload ‖ CRC-32` after the last one. When a sector fills, the *other* sector
is erased and the record goes there. The sector holding the current value is never erased.

The append operation reads the record back and only reports success once it verifies.
The authenticator only releases a signature carrying counter $N+1$ after that success.
If power fails mid-write, the torn record is ignored at the next boot. That is harmless,
because nothing carrying $N+1$ was ever released. A property test cuts power at random
byte offsets (including in the middle of a sector erase) across thousands of runs and
checks that no confirmed counter value is ever lost or handed out twice. The test firmware
repeats the torn-write check on real NOR flash.

== User experience

#dtable(
  columns: (1fr, 2.4fr),
  ("LED", "Meaning"),
  ([off], [Idle, healthy.]),
  ([amber blink], [A website is asking: touch BOOT to approve. Times out after 30 s.]),
  ([blue blink], [CTAPHID_WINK: the platform asks the device to identify itself.]),
  ([solid red], [Self test or hardware fault. The authenticator refuses everything until reset; the UART log says why.]),
  ([magenta at boot], [*INSECURE* development build (`dev-key` feature, root key derived from the MAC address).]),
)

A touch counts only if the button is seen *released* after the request arrived, then held
for two consecutive 20 ms polls. A button taped down, or still held from a previous
request, never approves anything. Holding BOOT for 3 s while idle turns on BLE for two
minutes, so the radio is never exposed without the owner's intent.
