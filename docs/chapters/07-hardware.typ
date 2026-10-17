// (c) Javier Fernandez @ JotaSoft 2026
#import "../isss-template.typ": *
#import "../lib.typ": *

= Hardware security

Software can be proved correct. Silicon can be attacked. This chapter describes what the
ESP32-C6 offers, how Jotakey uses it, and where it falls short (§7.1–7.4). It then describes
the jotakey key, which adds the secure element the C6 lacks (§7.5), and how its board is
designed (§7.6).

== What the chip provides

#dtable(
  columns: (1.1fr, 2.4fr),
  ("Feature", "Role in Jotakey"),
  ([eFuse key blocks (6 × 256 bit)], [One-time-programmable. `K_dev` is burned into BLOCK_KEY0 with purpose `HMAC_UP`. Keys with this purpose are read-protected: the CPU cannot read them, only the HMAC peripheral can use them.]),
  ([HMAC peripheral], [Computes HMAC-SHA256 with an eFuse key the CPU never sees. Jotakey's only access to `K_dev`.]),
  ([Secure Boot v2], [The ROM verifies the bootloader's RSA-3072 signature, and the bootloader verifies the app's, against a key digest in eFuse. Only firmware signed by the owner runs.]),
  ([Flash encryption], [XTS-AES encryption of flash contents with an on-chip key generated at first boot. Protects the firmware image and the `jotakey` partition (epoch, counter) against off-chip reading.]),
  ([TRNG], [Hardware entropy from SAR ADC and RF noise; health-tested continuously (§2.4).]),
  ([JTAG / download-mode fuses], [Burned at provisioning so a physical attacker cannot attach a debugger or dump flash through the ROM loader.]),
)

== Provisioning

Provisioning is a one-way trip: eFuses cannot be unburned. `scripts/provision.sh`
documents every step and *prints* the commands by default. It executes one step at a time,
only when a human passes `--execute <step>` and types the chip's MAC address to confirm.
`AGENTS.md` forbids automation from ever running it.

+ *Root key.* 32 random bytes generated in RAM (`/dev/shm`), burned with
  `espefuse.py burn_key BLOCK_KEY0 … HMAC_UP`, then shredded. The key then exists only
  inside the chip. A better future option is to generate it on the device, so it never
  touches the host.
+ *Secure Boot v2.* An RSA-3072 signing key kept offline. A signed bootloader built with
  ESP-IDF, and signed application images.
+ *Flash encryption, release mode.* The key is generated on-chip at first boot, and
  plaintext reflashing is disabled.
+ *Lockdown.* Disable pad and USB JTAG (the USB *serial* function stays, because it carries
  the CTAPHID tunnel). Switch ROM download mode to "secure download".

Until step 1 is done, the firmware refuses to operate: the HMAC peripheral rejects an
unprovisioned key, the boot self check fails, and the LED goes red. For development, the
`dev-key` cargo feature substitutes a software key derived from the MAC address. It is
loudly announced at boot and must never hold real credentials.

== Side channels

- *Timing.* All comparisons of secret data are constant-time. Scalar multiplication
  uses RustCrypto's constant-time implementation in software, rather than the C6's ECC
  accelerator, whose side-channel behaviour is undocumented.
- *Power and EM.* A microcontroller without dedicated countermeasures leaks information
  through its power draw. An attacker with an oscilloscope and physical access can, in
  principle, extract an ECDSA key from enough traces. Hedged nonces reduce, but do not
  remove, that risk.

== Fault injection: the limit of this chip

#callout(kind: "trap", "Published attack: Espressif advisory AR2023-007")[
  In January 2024 Espressif published *AR2023-007*, "Security Advisory Concerning Bypassing
  Secure Boot and Flash Encryption using CPA and FI attack on ESP32-C3 and ESP32-C6". It
  combines correlation power analysis with voltage-glitch fault injection. An attacker with
  physical access and lab equipment can run code before Secure Boot rejects it, and then
  extract device secrets. Earlier advisories (AR2023-005, CVE-2019-15894) describe similar
  attacks on the original ESP32. Treat a stolen Jotakey as compromised if the thief is
  well-resourced, and revoke its credentials at your relying parties.
]

This is why the threat model (§1.3) marks laboratory attackers as *not defeated*. The
standard answer is a *secure element*: a small chip designed and certified (Common
Criteria EAL5+/EAL6+) to resist exactly these attacks. It holds the keys and performs the
signatures internally, so even full control of the microcontroller does not reveal them.

#dtable(
  columns: (1fr, 1.5fr, 1.5fr),
  ("Candidate", "Strengths", "Considerations"),
  ([Microchip ATECC608B], [Cheap, I²C, P-256 ECDSA and ECDH in hardware, monotonic counters, widely used.], [Small slot count: suits a root key plus derived keys, not many stored keys. Configuration is locked once.]),
  ([NXP SE050], [EAL6+, P-256 and many curves, larger storage, applet model.], [More complex driver; NDA-free host library available.]),
  ([Infineon OPTIGA Trust M], [EAL6+, P-256, shielded I²C, monotonic counters.], [Smaller key store than SE050.]),
)

The jotakey key puts the third of these on its own board, next to an STM32L432
microcontroller (§7.5).

== The jotakey key: a secure element

The jotakey key (`hardware/HARDWARE.md`) pairs two chips with different jobs. The
*STM32L432KC*, an Arm Cortex-M4 at 80 MHz, runs the firmware: USB, CTAP, the touch sensor,
the LED and the ECDSA signatures. The *Infineon OPTIGA Trust M V1*, built on Common Criteria
EAL6+ certified hardware, keeps the secrets: the root, and the signature counter. The two
talk over I²C.

#dtable(
  columns: (1.1fr, 2.4fr),
  ("Feature", "Role in Jotakey"),
  ([OPTIGA data object `0xF1D0`], [Holds `K_root`, 64 bytes, as a pre-shared secret. After provisioning its access conditions say: never readable, never changeable, usable only over the shielded connection.]),
  ([OPTIGA `DeriveKey`], [Runs the TLS 1.2 PRF (HMAC-SHA256 inside) over `K_root` and returns the result: one credential's tag or seed (§6.3). About 50 ms each.]),
  ([OPTIGA monotonic counter `0xE120`], [The signature counter (invariant 2). The chip only lets it go up, survives power loss by construction, and freezes it at a threshold set to its rated 600 000 updates.]),
  ([OPTIGA shielded connection], [Encrypts and authenticates the I²C traffic with a 64-byte platform binding secret shared between the two chips. A probe on the bus sees ciphertext; a swapped chip on either side cannot talk to the other.]),
  ([OPTIGA and STM32 random generators], [Both feed every random value, mixed with SHA-512, so one weak generator is not enough to weaken the key. The STM32's generator reports its own health errors (invariant 7).]),
  ([STM32 readout protection], [Level 2 on production units: the debug port, booting from RAM and the factory bootloader are disabled for good, and the flash cannot be read out. The setting is irreversible.]),
)

=== Provisioning

Provisioning happens on the device itself, from a provisioning build of the firmware that
a human starts. The secrets are generated on the device and never leave it:

+ *Pair.* Generate a 64-byte platform binding secret, write it into the OPTIGA (`0xE140`)
  and into the STM32's flash, and lock the OPTIGA's copy.
+ *Root.* Generate `K_root` from both random generators, write it into `0xF1D0`, and lock it.
+ *Counter and epoch.* Set the counter's threshold; write a random epoch to flash.
+ *Lock.* A human sets readout protection level 2 with STM32CubeProgrammer, over the SWD
  test pads. From then on the firmware is frozen: Jotakey keys, like YubiKeys, are not
  updated in the field. A security fix means a new key. (Signed updates are a roadmap
  exploration, §11.)

Development boards stop before the last step and stay open to the debugger. `AGENTS.md`
forbids automation from taking any of the irreversible steps: locking OPTIGA objects or
setting readout protection.

=== What a physical attacker gets

The STM32L432 is an ordinary microcontroller. Fault-injection attacks against STM32 readout
protection have been published for several families. So we assume a well-equipped thief
can, in the end, run their own code on it, with the binding secret and the epoch in hand.
What they get then:

#dtable(
  columns: (1.3fr, 2fr),
  ("They can", "They cannot"),
  ([Use the key while they hold it, for any credential whose ID they present: the hardware computes its tag and seed on request.], [Read `K_root`: the OPTIGA never releases it, and attacks on the OPTIGA itself are what its certification is about.]),
  ([Copy a credential, if they also obtain its ID from the website (the ID is not secret).], [Copy the key as a whole: no secret on the STM32 covers more than one credential, so nothing they take away lets them compute the others or mint new ones.]),
  ([Make the key unusable (for example, by resetting it).], [Roll the signature counter back: it lives in the OPTIGA and only goes up, so relying parties that check it can notice a copied credential.]),
)

This is the honest boundary of a two-chip design. A key whose secure element also performed
the signatures would close the first row. The Trust M V1 cannot import a derived private key
to sign with it, and storing one key per credential would cap the number of credentials.
The threat model (§1.3) records the result as *partially defeated*.

The OPTIGA Trust M V3 adds HMAC, HKDF and AES. It was out of stock when the board's parts
were chosen, so the key uses the V1, whose TLS PRF does the same job here. The two share a
package and pinout, so a later board can switch; `F` would then become HMAC, as on the C6.

== The jotakey key board

The jotakey key is a two-layer board whose own edge is the USB plug. Hardware 0.1.0 (git tag
`hw-v0.1.0`) is described here; `hardware/HARDWARE.md` records the part choices against
their datasheets, and `hardware/MANUFACTURING.md` the order.

#board-views(
  caption: [The jotakey key, hardware 0.1.0, rendered from the KiCad design: 47 × 18 mm, 2.0 mm thick, black solder mask. The back is drawn as seen from below.],
  ("figures/jotakey-key-front.png", [Front]),
  ("figures/jotakey-key-back.png", [Back]),
)

=== Outline and parts

The narrow end is a USB-A plug: a 12 mm tongue carrying four gold contacts laid out as in
the USB 2.0 Series "A" plug drawing, with VBUS and GND longer than the data contacts so
they mate first. The board is 2.0 mm thick, so the tongue sits firmly in a receptacle, and
the contacts' edge is bevelled. The 18 mm body ends in a semicircle whose centre is the
centre of the touch electrode.

#dtable(
  columns: (0.55fr, 1.35fr, 2.1fr),
  ("Ref", "Part", "Role"),
  ([U1], [STM32L432KCU6, QFN-32], [The microcontroller: USB full speed without a crystal (its clock is trimmed against the host's USB frames), the touch-sensing controller, I²C to the secure element, ECDSA signing.]),
  ([U2], [OPTIGA Trust M V1, USON-10], [The secure element: the root secret, per-credential derivation and the signature counter (§7.5).]),
  ([U3], [XC6206 3.3 V LDO, SOT-23], [Power from the USB 5 V.]),
  ([U4], [USBLC6-2SC6, SOT-23-6], [ESD protection on D+, D− and VBUS, next to the contacts.]),
  ([E1], [10 mm copper disc], [The touch electrode, user presence (invariant 1). The bolt logo is cut out of the copper.]),
  ([D1], [Red LED, 0603], [The only display: touch requested, OK, fault.]),
  ([TP1–5], [Test pads, bottom], [SWD (DIO, CLK, RST, 3V3, GND) for a pogo-pin jig.]),
)

=== Layout decisions

- *The tongue carries contacts and nothing else.* No vias and no copper on its back: it slides
  against the receptacle's metal shell.
- *One crossing for USB.* The plug has D− on the left; the microcontroller's pins put D− on
  the right. The two lines cross once, between the ESD chip and the microcontroller, where D+
  drops to the back for a few millimetres. The ESD chip sits on the board's axis, and its
  two identical channels are assigned so the crossing stays off the tongue.
- *The touch electrode follows ST's AN4312.* Nothing on the top layer comes within 4 mm of
  it except its own trace (the note asks for at least 2 mm, 4–5 mm recommended), which
  arrives at 45°. Behind it, the back carries a ground hatch of 10 % copper instead of a
  solid plane, trading a little noise immunity for sensitivity. Keeping that gap is why the
  board is 47 mm long and not 45.5.
- *The secure element sits in the corner* next to the microcontroller's I²C pins, rotated so
  its clock, reset and supply pins face the microcontroller.
- *Ground pours on both layers,* tied together under each chip's exposed pad.

=== Silkscreen

The mask is black, which hides the contrast between copper and bare board. So the bolt cut
out of the electrode's copper is also printed in white, exactly over the cut-out. The front
names the chips by function (MCU, OPTIGA, LDO, ESD); the reference designators live on the
assembly drawing instead, because next to 0402 parts on a board this size they cannot avoid
covering pads. The back carries the hardware version, the SWD pad names, and the two places
where JLCPCB prints its marks: `JLCJLCJLCJLC` for the order number and a solid block for
each board's serial number.

=== How the board is made

The layout is reproducible from scripts in `hardware/jotakey-key/tools/`, each run with
KiCad's own Python or command line. `layout.py` draws the outline and places every part;
`route.py` lays down the keep-outs and the hand-routed nets (USB, power, the touch trace,
the parts under the microcontroller), lets the Freerouting autorouter connect the rest, and
pours the ground; `silk.py` adds the silkscreen; `fab.py` refuses to build unless the
schematic and board checks pass, then writes the Gerber, BOM and placement files for
JLCPCB; `render.py` draws the figures above. The hardware version is set in one place, the
KiCad project variable `HW_VERSION`, which the title blocks and the back of the board
display.

