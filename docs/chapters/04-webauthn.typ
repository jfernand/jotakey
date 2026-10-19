// (c) Javier Fernandez @ JotaSoft 2026
#import "../isss-template.typ": *
#import "../lib.typ": *

= WebAuthn: the two ceremonies

WebAuthn defines two *ceremonies* (the spec's word for a protocol that includes a human):
*registration* creates a credential, *authentication* uses it. Both follow the same
pattern: the RP sends a challenge, the browser wraps it, the authenticator signs, and the
RP verifies.

== Registration

#sequence(
  ("Relying party", "Browser", "Jotakey", "User"),
  (
    (0, 1, [challenge, rp.id, user, algorithms]),
    (1, 1, [clientDataJSON; rp.id vs origin]),
    (1, 2, [makeCredential(cdh, rp, user)]),
    (2, 3, [LED blinks amber: "touch me"]),
    (3, 2, [press BOOT]),
    (2, 2, [new key; counter+1; sign]),
    (2, 1, [attestationObject]),
    (1, 0, [clientData, attestation]),
    (0, 0, [verify; store key]),
  ),
  caption: "Registration (navigator.credentials.create)",
)

The browser computes `clientDataJSON`, a small JSON document that records the operation
type (`webauthn.create`), the RP's challenge and the *origin* of the page:

#codepanel(title: "clientDataJSON (built by the browser, never by the website)")[
```json
{"type":"webauthn.create","challenge":"q5sJ…7w","origin":"https://example.com","crossOrigin":false}
```
]

The authenticator never sees this JSON, only its SHA-256, the `clientDataHash`. It signs
over that hash together with its own `authenticatorData`. The RP later checks that the
challenge is the one it issued and the origin is its own. A phishing page at `examp1e.com`
can relay the challenge, but cannot make the browser write a different origin.

== The RP ID

Every credential is created for an *RP ID*, a domain such as `example.com`. The browser
only lets a page use an RP ID equal to its own host, or a registrable suffix of it:
`login.example.com` may use `example.com`, `examp1e.com` may not. The authenticator hashes
the RP ID into the credential (Jotakey binds it into the credential ID's authentication
tag, §6.4) and refuses to use the credential for any other RP ID. So there are two
independent checks: the browser checks origin against RP ID, and the key checks RP ID
against credential.

== authenticatorData

Both ceremonies return the same binary structure, which the authenticator builds and
signs:

#bytefield(
  caption: "authenticatorData, assertion form: 37 bytes",
  ("rpIdHash", "32 B · SHA-256(rp.id)", 8),
  ("flags", "1 B", 1.6),
  ("signCount", "4 B · big-endian", 2.6),
)

#bytefield(
  caption: "…plus attestedCredentialData at registration (Jotakey: 181 bytes in total)",
  ("aaguid", "16 B", 3),
  ("idLen", "2 B", 1.2),
  ("credentialId", "49 B", 4.5),
  ("credentialPublicKey", "77 B · COSE_Key", 5),
)

#dtable(
  columns: (0.4fr, 0.4fr, 2.4fr),
  ("Bit", "Flag", "Meaning"),
  ([0], [UP], [User Present: someone physically interacted with the authenticator. *Jotakey always sets it* (invariant 1).]),
  ([2], [UV], [User Verified: PIN or biometric checked. Not supported in the MVP.]),
  ([3–4], [BE/BS], [Backup eligible / backed up (synced passkeys). Always 0 for Jotakey.]),
  ([6], [AT], [Attested credential data included (registration only).]),
  ([7], [ED], [Extension data included. Not used.]),
)

The *signature counter* lets an RP detect a cloned authenticator. If an assertion arrives
with a counter not larger than the last one seen, two devices may share a key. Jotakey's
counter is global, persisted to flash *before* any signature carrying it is released, and
proved monotonic in Lean (§9.6).

== Authentication

#sequence(
  ("Relying party", "Browser", "Jotakey", "User"),
  (
    (0, 1, [challenge, rpId, allow list]),
    (1, 2, [getAssertion(rpId, cdh, allowList)]),
    (2, 2, [find our credId for rpId]),
    (2, 3, [LED blinks amber]),
    (3, 2, [press BOOT]),
    (2, 2, [derive key; counter+1; sign]),
    (2, 1, [authData, signature]),
    (1, 0, [clientData, authData, sig]),
    (0, 0, [verify; check counter]),
  ),
  caption: "Authentication (navigator.credentials.get)",
)

The signature covers `authenticatorData ‖ clientDataHash`. The RP verifies it with the
public key it stored at registration, checks the UP flag, the RP ID hash, the challenge,
the origin, and that the counter increased.

== Attestation

At registration the authenticator can also prove *what kind of device* it is, by signing
with a per-model *attestation key* whose certificate chains to the manufacturer. Formats
include `packed`, `tpm`, `android-key`, `fido-u2f`, `apple` and `none`. Attestation serves
enterprises that must allow only certified models. It costs privacy (keys of one batch are
linkable) and requires a certificate authority.

Jotakey uses *packed self-attestation*: the attestation statement is signed with the new
credential's own private key. This proves possession of the key and nothing about the
device. Most consumer RPs request no attestation (`"none"`) anyway.
