#import "../isss-template.typ": *
#import "../lib.typ": *

= From passwords to passkeys

== What is wrong with passwords

A password is a *shared secret*: the user knows it and the website stores something
derived from it. Every login sends the secret, or something equivalent to it, to whoever
is on the other end. That design has three structural flaws:

- *Phishing.* The user cannot reliably tell `example.com` from `examp1e.com`. Whatever
  they type on the fake site, the attacker replays on the real one. One-time codes from an
  app or SMS do not help: the fake site relays them in real time.
- *Reuse.* A breach at one site exposes the password everywhere it was reused.
- *Server breaches.* The site's database is a treasure chest of password hashes, which
  attackers crack offline.

== Public-key login

Public-key authentication removes the shared secret. At registration, a fresh key pair is
created *for that one site*. The site stores the public key. At login, the site sends a
random *challenge*, and the user's device signs it with the private key. The private key
never leaves the device, and the site stores nothing worth stealing.

That alone does not stop phishing: a fake site could relay the challenge too. FIDO adds the
missing piece. The *browser*, which reliably knows which site it is talking to, includes
the site's origin in what is signed. The *authenticator* only uses a credential for the
site it was created for. A signature obtained on `examp1e.com` names `examp1e.com`, and
`example.com` rejects it. Phishing stops working, not because users get better at spotting
fakes, but because the protocol never asks them to.

#keypoint[The user is no longer the last line of defence against phishing. The protocol is.]

== A short history

#dtable(
  columns: (0.55fr, 2.2fr),
  ("Year", "Milestone"),
  ([2012], [The *FIDO Alliance* is founded (PayPal, Lenovo, Nok Nok Labs, Validity, Infineon, Agnitio; Google and Yubico join in 2013).]),
  ([2014], [*U2F* (Universal 2nd Factor): a USB key as a second factor next to the password. Google deploys it internally; in 2018 it reports that no employee account had been phished since security keys became mandatory in early 2017.]),
  ([2018], [*FIDO2* = W3C *WebAuthn* (browser API, Recommendation in 2019) + *CTAP2* (Client-to-Authenticator Protocol). Adds resident (discoverable) credentials, user verification by PIN or biometrics, and passwordless login.]),
  ([2021], [*CTAP 2.1*: credential management, PIN protocol v2, hmac-secret, enterprise attestation.]),
  ([2022], [Apple, Google and Microsoft commit to *passkeys*: FIDO credentials synchronised across a user's devices by the platform.]),
  ([2023–25], [*CTAP 2.2*: the *hybrid* transport (scan a QR code, phone acts as authenticator over BLE plus a cloud relay); passkeys become the default sign-in option on major sites.]),
)

== Passkeys, precisely

"Passkey" is the user-facing name for a *discoverable FIDO credential*. The word covers two
deployment models with very different security properties:

#dtable(
  columns: (1fr, 1.6fr, 1.6fr),
  ("", "Synced passkey", "Device-bound passkey"),
  ([Where the key lives], [In the platform's cloud keychain (iCloud Keychain, Google Password Manager, 1Password …), end-to-end encrypted, copied to all the user's devices.], [In one hardware authenticator (a security key or a TPM), never copied.]),
  ([Survives losing the device], [Yes], [No; register a backup key.]),
  ([Trust anchor], [The platform account and its recovery process.], [Possession of the physical device.]),
  ([Typical use], [Consumer accounts], [High-assurance accounts, administrators, regulated environments.]),
)

Jotakey is a *device-bound* authenticator. The MVP implements *non-discoverable*
credentials: the website must name the credential (send its ID) at login. This is how
security keys work as a second factor, and how many enterprise deployments use them.
*Discoverable* credentials, where the device stores the user handle so the website does
not need to send an ID ("username-less" passkeys), are the first item on the roadmap
(§10). Their implementation is laid out step by step there.

== The three parties

#layers(
  caption: "The roles in every FIDO ceremony",
  ("Relying party (RP)", [The website, e.g. `example.com`. Stores public keys and credential IDs, issues challenges, verifies signatures. Identified by its *RP ID*, a domain.], "light"),
  ("Client / platform", [The browser plus the operating system. Knows the true origin of the page, builds `clientDataJSON`, talks to authenticators over USB, NFC, BLE or hybrid. Speaks WebAuthn upward and CTAP downward.], "dark"),
  ("Authenticator", [The key: Jotakey. Holds or derives private keys, checks user presence, signs. Trusts nothing it receives.], "amber"),
)
