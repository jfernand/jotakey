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
  ("jotakey-bridge", [≈330 lines, std Rust: uhid ⇄ serial, COBS + CRC-32 framing. *Outside the security boundary.*], "dark"),
  ("USB-Serial/JTAG", [The DevKit's "USB" port: fixed-function serial channel.], "dark"),
  ("Firmware: usb task", [Deframer → CtapHid → authenticator, and back.], "amber"),
)

#callout(kind: "info", "Why the bridge does not weaken security")[
  FIDO already treats the host as hostile: the authenticator trusts nothing it receives, and
  every signature needs a touch on the device itself. The bridge runs *on* the host, so it
  can do nothing that host malware could not do anyway. It never sees key material, only the
  same CTAP messages any USB host sees. The cost is convenience: the bridge is Linux-only.
  The roadmap (§11) lists a small USB-capable co-processor as the path to a standalone,
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
the two ports clean roles: "USB" carries the authenticator, "UART" carries diagnostics. §6.7 describes the bridge and the framing in full detail.

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
  `unwrap_accepts_only_wrapped_ids`: anything `unwrap` accepts is *exactly* `wrap(rp, nonce)` for the recovered
  nonce. `credential_bound_to_relying_party`: an ID minted for one RP never unwraps at another, *assuming* the MAC
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

== The USB bridge in detail

§6.1 introduced `jotakey-bridge` in one paragraph. This section describes it completely:
what happens to a request on its way from the browser to the chip, what each layer does,
what goes wrong and how it recovers, and what a hostile bridge could and could not do. The
technique is general. Any microcontroller with a serial port but no USB device controller
can appear to Linux as a HID device this way, which makes it useful well beyond Jotakey.

The guiding rule is that the bridge *understands nothing*. It does not parse CTAPHID,
CBOR or CTAP. It moves opaque 64-byte reports between two places and checks only that
they arrived intact. Every protocol decision is made on the device, by the same core code
that is tested, fuzzed and modelled in Lean. The bridge is about 330 lines in total:
`main.rs` (127) and `uhid.rs` (202, including tests).

=== The journey of one request

#sequence(
  ("Browser", "Linux HID", "jotakey-bridge", "Firmware usb task", "Authenticator"),
  (
    (0, 1, [write 64 B to hidraw]),
    (1, 2, [UHID_OUTPUT event]),
    (2, 3, [COBS(report ‖ CRC) ‖ 00]),
    (3, 3, [deframe, CRC ok; CtapHid reassembles]),
    (3, 4, [complete CTAP request]),
    (4, 3, [keepalive UP_NEEDED / reply]),
    (3, 2, [framed reports]),
    (2, 1, [UHID_INPUT2 event]),
    (1, 0, [read 64 B from hidraw]),
  ),
  caption: [A request and its answer. Messages larger than one report repeat the top half per packet.],
)

The browser cannot tell this apart from a USB key. It opens `/dev/hidrawN` and writes
64-byte output reports. The kernel hands each one to the bridge as a `UHID_OUTPUT` event.
The bridge wraps the report in a frame and writes it to the serial port. On the chip, the
usb task deframes it, checks the CRC, and feeds the report to the `CtapHid` state machine,
which reassembles multi-packet messages. A complete request goes to the authenticator
task. Replies and keepalives travel the same path backwards: `CtapHid` splits them into
reports, the usb task frames them, the bridge unframes them and injects each one into the
kernel with `UHID_INPUT2`, and the browser reads it from hidraw.

=== On the host: a virtual HID device through uhid

`uhid` is a Linux kernel interface for implementing HID devices in user space. A program
opens `/dev/uhid` and exchanges fixed-size `struct uhid_event` records with the kernel. To
the rest of the system, the result is a normal HID device. It gets a hidraw node, udev sees
it, and browsers enumerate it. The bridge uses only a handful of events:

#dtable(
  columns: (1.1fr, 0.55fr, 2.4fr),
  ("Event", "Direction", "Use in the bridge"),
  ([`UHID_CREATE2`], [write], [Once at start: name "Jotakey FIDO2 (bridge)", bus USB, VID:PID `1209:0001`, and the report descriptor below.]),
  ([`UHID_OUTPUT`], [read], [The host wrote a report. Forwarded to the serial port.]),
  ([`UHID_INPUT2`], [write], [Deliver a report from the device to the host.]),
  ([`UHID_GET_REPORT`, `UHID_SET_REPORT`], [read], [Feature-report requests, which FIDO does not use. Answered at once with `EIO`, because the kernel waits for a reply.]),
  ([`UHID_START`, `OPEN`, `CLOSE`, …], [read], [Notifications. Ignored.]),
  ([`UHID_DESTROY`], [write], [On exit (Rust `Drop`), so the virtual key disappears with the bridge.]),
)

The *report descriptor* is what makes the device a FIDO key. It declares the FIDO
Alliance usage page `0xF1D0`, usage `CTAPHID`, and one 64-byte input and one 64-byte
output report, exactly as CTAP 2.0 §8.1.8.2 prescribes. Browsers and libraries look for
that usage page, not for a vendor or product ID. systemd's `fido_id` helper recognises the
same descriptor and grants the logged-in user access to the hidraw node. The VID:PID pair
`1209:0001` is the pid.codes test identifier, suitable for development but not for a
product.

The bridge has its own uhid encoder (`uhid.rs`) instead of a crate. The obvious crate,
`uhid-virt`, needs `libclang` at build time to generate bindings. The structures are
packed, so the encoder is plain byte arithmetic, with no `unsafe` and no C bindings. Unit
tests pin the layout against the kernel's: an event is exactly 4 376 bytes, and the
`CREATE2` fields sit at the right offsets. One subtlety: depending on the path a report
takes through the kernel, an output report from a device without report IDs can arrive
with a leading report-number byte of 0. The bridge accepts 64 or 65 bytes and strips that
byte. Anything else is ignored.

=== On the wire: one frame, byte by byte

The serial link is a byte stream, so reports need boundaries. Each report travels as one
frame: `COBS(report ‖ CRC-32(report)) ‖ 0x00`. This is the actual frame for the first
packet every browser sends, a `CTAPHID_INIT` on the broadcast channel with an 8-byte
nonce. It was produced by the core's `serial::encode` and cross-checked against an
independent Python implementation:

#codepanel(title: "CTAPHID_INIT request: 64-byte report → 70-byte frame")[
```text
report   ff ff ff ff 86 00 08 11 22 33 44 55 66 77 88 00 … 00     (49 zero bytes)
          └ CID ─────┘ cmd └len┘ └ nonce ──────────────┘
CRC-32   a5 9f 94 f7 → appended little-endian: f7 94 9f a5

frame    06 ff ff ff ff 86                    5 data bytes, then a zero
         0a 08 11 22 33 44 55 66 77 88        9 data bytes, then a zero
         01 01 01 … 01                        48 × "no data, then a zero"
         05 f7 94 9f a5                       4 data bytes (the CRC), end of body
         00                                   delimiter
```
]

*COBS* (Consistent Overhead Byte Stuffing) removes every zero byte from the body. Each
code byte `n` means "copy the next `n − 1` bytes, then output a zero", except at the very
end. Because the body never contains `0x00`, a zero on the wire *always* means "end of
frame". A receiver that starts listening mid-stream, or sees a corrupted byte, recovers at
the next zero. The overhead is bounded: one code byte per 254 data bytes plus the
delimiter, so a frame is at most 70 bytes for a 64-byte report.

The *CRC-32* (the ISO-HDLC polynomial used by zlib and Ethernet; check value
`CBF43926`) detects corruption: noise, a dropped byte, or two frames merged by a lost
delimiter. It is not a security mechanism. Anyone on the host can compute a valid CRC, and
nothing here needs to keep the host out, because the device validates every message
anyway.

The receiver, `serial::Deframer`, is a 70-byte buffer and a little state. It collects
bytes until a zero. Empty frames, which are just idle delimiters, are ignored. A frame that
overflows the buffer, fails COBS decoding, has the wrong length or fails the CRC is
dropped and counted. Nothing is ever retransmitted. CTAPHID already has timeouts and
retries, and duplicating them in the framing layer would only add states. A unit test
feeds a log line, a corrupted frame and a good frame in one stream, and checks that
exactly the good one comes out. The `serial_deframe` fuzz target has pushed millions of
arbitrary byte streams through the same code.

Two properties of the C6's USB-Serial/JTAG port matter for the host side. The baud rate is
meaningless, because the data moves at USB full speed whatever the port is told. More
importantly, the DTR and RTS control lines are wired to the chip's reset logic (that is
how flashing tools reset it), so opening the port the usual way can reboot the
authenticator. The bridge opens the port with DTR off and clears RTS.

=== On the device: the usb task

On the chip, `crates/jotakey-fw/src/usb.rs` runs one task that waits on four things at
once: bytes from the serial port, a reply from the authenticator, a keepalive request, and
a 50 ms timer. Incoming bytes go through the `Deframer` into `CtapHid::handle_packet`.
`CtapHid` implements channel allocation, reassembly, busy and cancel handling, and
transaction timeouts. The timer drives those timeouts even when no bytes arrive. Each
outgoing packet `CtapHid` produces is framed and written back.

This placement is deliberate. The whole CTAPHID state machine runs on the device, in the
core, so channel isolation (invariant 5) is enforced by code the Lean model of §9.6
describes, not by the bridge. A bridge that misbehaved could not break isolation between
two host applications. It could only feed the device packets, which any USB host can do.

The firmware has one authenticator and two transports. If a USB request arrives while a
BLE request is being processed, the usb task answers `CTAP1_ERR_CHANNEL_BUSY` itself, and
the host retries. The firmware never prints anything on this port. Logs go to the
*UART* port only, so the CTAPHID stream contains nothing but frames.

=== Lifecycle and failure modes

The bridge creates the virtual device once, then loops: open the serial port, pump reports
until the port hangs up or fails, wait 500 ms, try again.

#dtable(
  columns: (1.15fr, 2.4fr),
  ("Situation", "What happens"),
  ([Board unplugged], [The serial port errors and the bridge goes back to waiting. The virtual key *stays*, so the browser still sees a key, but its requests time out. Reports the host writes meanwhile queue in the kernel (uhid buffers a limited number of events) and may be delivered after the board returns.]),
  ([Board reset or replugged], [The bridge reconnects within about 500 ms. The firmware has forgotten all channels, so packets on old channel IDs get `ERR_INVALID_CHANNEL`. Host libraries then send a fresh `CTAPHID_INIT`.]),
  ([Line noise or a half-written frame], [The CRC or COBS check fails, the frame is dropped, the stream resynchronises at the next zero, and CTAPHID timeouts recover the transaction.]),
  ([Bridge stopped], [`UHID_DESTROY` removes the virtual key. If the process is killed outright, the kernel removes it when `/dev/uhid` is closed.]),
  ([Wrong serial port], [The bridge would send frames to some other device. Use the stable name under `/dev/serial/by-id/` (the entry for the Espressif USB JTAG/serial unit) rather than `/dev/ttyACM0`, whose number depends on plug order.]),
  ([Two bridges on one port], [Both read the same stream and each gets part of it. Frames break and are dropped. Run exactly one.]),
)

=== What a hostile bridge can and cannot do

The bridge is outside the security boundary, like the rest of the host. Treating it as an
attacker gives this picture:

#dtable(
  columns: (1fr, 1fr),
  ("A malicious or compromised bridge can…", "…but it cannot"),
  ([Drop, delay, reorder or replay any report (denial of service).], [Obtain a signature without a touch on the device (invariant 1, proved in §9.6).]),
  ([Send the device any request of its choosing, for any website.], [Learn any private key or root key. Neither ever leaves the chip.]),
  ([Read all CTAP traffic: relying-party ID hashes, credential IDs, and the user name and display name sent in makeCredential.], [Use a credential for another website. IDs are bound to `rpIdHash` (invariant 3).]),
  ([Pretend to be a security key itself, since it is software that creates HID devices.], [Make the device skip its checks. Every message is parsed and validated by the core.]),
)

Everything in the left column is also available to any program with root on the host,
or to a malicious USB host. That is the threat model FIDO is designed for. The bridge adds
no new attack on the key. It is a new place for host-side malware to hide, which is one
more reason the roadmap replaces it with a USB co-processor.

#callout(kind: "trap", "Access to /dev/uhid is powerful")[
  A process that can write to `/dev/uhid` can create *any* HID device, including a
  keyboard that types commands. `scripts/99-jotakey.rules` gives the `plugdev` group that
  access, which is convenient on a development machine. On a shared or long-lived system,
  run the bridge as a dedicated system user that alone has access to `/dev/uhid` and the
  serial port, for example as a systemd service, rather than widening a group most users
  belong to.
]

=== Running it

#codepanel(title: "Bridge setup on Linux")[
```sh
sudo cp scripts/99-jotakey.rules /etc/udev/rules.d/ && sudo udevadm control --reload
sudo usermod -aG plugdev,dialout "$USER"     # uhid + serial access; log in again
                                              # (the serial group is uucp on Arch)
ls /dev/serial/by-id/                         # find the Espressif USB JTAG/serial entry
just bridge /dev/serial/by-id/usb-Espressif…  # or: cargo run -p jotakey-bridge --release -- <port>
# jotakey-bridge: virtual FIDO device created; waiting for …
# jotakey-bridge: connected to …
```
]

With the bridge running, `python3 scripts/fido2_check.py`, `just host-tests` and any
browser on the machine see the key. Stop the bridge with Ctrl-C.

=== How it is tested, and current status

#dtable(
  columns: (1.1fr, 2.4fr),
  ("Part", "Evidence"),
  ([uhid encoding], [Unit tests pin the event size (4 376 bytes) and the `CREATE2` layout to the kernel's, and check `OUTPUT` decoding and the `EIO` replies.]),
  ([Framing], [Round trip of every possible report (property test), all-zero and zero-free reports, corruption and resynchronisation, and the `serial_deframe` fuzz target.]),
  ([Pump loop], [The real `pump` runs between a fake uhid (a datagram socket pair, which keeps event boundaries like `/dev/uhid`) and a pseudo-terminal standing in for the serial port. The test checks one report in each direction, that the idle bridge wakes at most twice in 300 ms (the earlier 5 ms polling loop woke 60 times), and that a hang-up ends the pump so the bridge can reconnect.]),
  ([Whole path], [`jotakey-host-tests` runs a simulated device wired exactly like the usb task (framing → `CtapHid` → authenticator), so every simulated request crosses the real framing code in both directions.]),
  ([On hardware], [*Not yet run.* No board was attached while it was written, and `/dev/uhid` needs the permissions above. `just host-tests` with a board attached is the first check to run.]),
)

The bridge sleeps in `poll(2)` on both file descriptors, the uhid device and the serial
port, with no timeout. It wakes only when the host writes a report or the board sends
bytes, forwards them at once, and uses no CPU while idle. It needs no timer of its own,
because all CTAPHID timeouts run on the device. A hang-up or error on the serial port ends
the loop, and the bridge goes back to waiting for the board.

One limitation is known. The bridge is *Linux-only*, because `uhid` is a Linux interface;
other systems would need their own virtual-HID mechanism.
