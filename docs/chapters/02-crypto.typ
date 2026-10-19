// (c) Javier Fernandez @ JotaSoft 2026
#import "../isss-template.typ": *
#import "../lib.typ": *

= Cryptography primer

FIDO2 uses a handful of standard primitives. This chapter explains just enough of each to
follow the rest of the report. No mathematics beyond arithmetic is required.

== Hash functions

A *hash function* such as SHA-256 maps any input to a fixed 32-byte *digest*. It is easy to
compute and, as far as anyone knows, impossible to run backwards. It is also infeasible to
find two inputs with the same digest (a *collision*). Hashes are used as compact,
tamper-evident fingerprints. WebAuthn hashes the RP ID (`rpIdHash`) and the client data
(`clientDataHash`), and the authenticator signs those hashes, not the raw data.

== Message authentication codes

A *MAC* is a hash with a secret key: `HMAC-SHA256(key, message)` produces a tag that only
someone holding `key` can compute. Changing a single bit of the message changes the tag
unpredictably. Jotakey uses HMAC in two ways:

- to *derive* independent keys from one root key, with a different label for each purpose
  (`"jotakey/tag/v1"`, `"jotakey/seed/v1"`);
- to *authenticate* credential IDs, so the device can recognise its own IDs and reject
  forged or foreign ones (§6.4).

*HKDF* (RFC 5869) is a standard construction built from HMAC. It turns key material plus a
salt and a context string into as many independent-looking bytes as needed. Jotakey uses
it to derive each credential's private key.

== Digital signatures: ECDSA on P-256

A *signature scheme* has a private key, which signs, and a public key, which verifies.
Anyone can check a signature, but only the private-key holder can produce one. WebAuthn's
default algorithm, *ES256*, is ECDSA over the NIST P-256 elliptic curve with SHA-256.

- A *private key* is a random number $d$ with $1 <= d < n$, where $n approx 2^256$ is the
  order of the curve.
- The *public key* is the point $Q = d dot G$: the fixed generator point $G$ "added to
  itself" $d$ times. Computing $Q$ from $d$ is fast. Recovering $d$ from $Q$ is the elliptic
  curve discrete logarithm problem, believed infeasible.
- To *sign* a hash $z$, pick a secret one-time number $k$ (the *nonce*), compute the point
  $k dot G$, and from it two numbers $(r, s)$. Verification checks an equation using only
  $Q$.

#callout(kind: "trap", "The nonce")[
  If two signatures ever share the same $k$, or if $k$ is even slightly predictable, simple
  algebra recovers the private key. This is how Sony's PlayStation 3 signing key leaked in 2010.

  Jotakey therefore uses *hedged* nonces (RFC 6979 §3.6): $k$ is derived
  deterministically from the private key and the message, *and* mixed with 32 fresh bytes
  from the hardware random number generator. A broken RNG cannot cause nonce reuse, because
  the deterministic part protects. A fault attack that skips or repeats part of the
  computation cannot exploit determinism, because the random part protects. The
  known-answer self test checks the deterministic path against the RFC's published vector
  at every boot.
]

== Protecting a PIN in transit

The PIN (§6.5) travels from the computer to the key over USB, where other software on
the computer can watch it. CTAP's *PIN/UV auth protocol two* first agrees a secret, then uses
it to encrypt and authenticate:

- *ECDH (elliptic-curve Diffie–Hellman).* Each side has a P-256 key pair and sends the
  other its public key. Each multiplies its own secret scalar by the other's public point;
  both arrive at the same point, which an eavesdropper who saw only the public keys cannot
  compute. The authenticator's key pair lasts one power cycle; the computer's lasts one command.
- *HKDF* turns the shared point's x-coordinate into two independent 32-byte keys: one for
  HMAC, one for AES.
- *AES-256-CBC* encrypts the PIN (padded to 64 bytes) and, later, the token the key hands
  back. A fresh random IV goes in front of every ciphertext. No padding scheme is needed
  because every message is a whole number of 16-byte blocks.
- *HMAC-SHA256* tags each request, proving that it came from the side that holds the
  shared secret.

Jotakey's implementation (`pin_protocol.rs`) is checked byte for byte against
python-fido2's, an independent implementation that browsers' test suites also use. The AES is RustCrypto's bitsliced software AES,
which has no secret-dependent table lookups.

== Randomness

Keys and nonces need *unpredictable* bits. The ESP32-C6 has a hardware true random number
generator (TRNG) fed by thermal noise in the SAR ADC and in the radio. Hardware noise
sources can fail: a stuck bit, a broken oscillator, a fault-injection glitch. NIST SP
800-90B specifies two cheap *health tests* that catch such failures continuously:

- *Repetition count test.* The same byte repeated too many times in a row (6, for an
  assumed 4 bits of entropy per byte) means the source is stuck.
- *Adaptive proportion test.* In each window of 512 bytes, the first byte must not recur 62
  or more times. This catches a source that has become biased.

The cutoffs are computed exactly from the binomial distribution for a false-alarm rate of
$2^(-20)$ (see `selftest.rs`). Jotakey runs both tests over 1024 bytes at boot and on every
byte it uses afterwards. Any failure permanently disables the authenticator (invariant 7).

== Constant time

An attacker who can measure *how long* an operation takes, or how much power it draws, can
learn secrets if the code's behaviour depends on them. The classic bug is comparing a
secret tag with `==`, which stops at the first differing byte and so leaks how many bytes
matched. Jotakey compares tags with `subtle::ConstantTimeEq` and uses the RustCrypto `p256`
crate, whose scalar arithmetic is written to be constant-time. Its own code never branches
on secret data (invariant 9).
