#import "../isss-template.typ": *
#import "../lib.typ": *

= Hardware security

Software can be proved correct. Silicon can be attacked. This chapter describes what the
ESP32-C6 offers, how Jotakey uses it, and where it falls short.

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

In the planned design, the secure element replaces the eFuse HMAC key as the root of the
hierarchy and performs every credential signature. The core's `Platform` trait already
isolates exactly the operations that would move into it.
