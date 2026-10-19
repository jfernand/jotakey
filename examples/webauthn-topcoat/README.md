# webauthn-topcoat: sign in to your own web app with a Jotakey

(c) Javier Fernandez @ JotaSoft 2026

A minimal relying party, the server side of WebAuthn, written with
[Topcoat](https://github.com/tokio-rs/topcoat) and
[webauthn-rs](https://github.com/kanidm/webauthn-rs). One page lets you register a security
key under a username and then sign in with it. It runs on `localhost` and is meant for trying
a Jotakey in a real browser.

## Run it

```sh
just bridge                                  # C6 DevKit: expose the key to the browser (Linux)
cd examples/webauthn-topcoat && cargo run    # needs OpenSSL headers (libssl-dev)
```

Open **http://localhost:3000**. Use `localhost`, not `127.0.0.1`: WebAuthn needs a domain
name as the RP ID, and browsers allow plain HTTP only on `localhost`. Pick a username, click
**Register a key**, and touch the key when it blinks. Then click **Sign in** and touch it
again. The page shows the signature counter, which goes up by one with every sign-in.

`PORT=8080 cargo run` serves on another port.

The DevKit runs the `dev-key` build, whose root key is not secret. Use it with this demo,
never with real accounts.

## How it works

```
page (src/app.js) ──JSON──▶ Topcoat routes (src/main.rs) ──▶ webauthn-rs
      │                                                        challenge, origin, RP ID,
navigator.credentials                                          UP flag, signature, counter
      │
browser ──CTAPHID──▶ Jotakey
```

Each ceremony is two round trips:

| Step | Registration | Sign-in |
|---|---|---|
| 1 | `POST /api/register/start {username}` → options with a fresh challenge | `POST /api/login/start {username}` → options listing the user's credential IDs (`allowCredentials`) |
| 2 | `navigator.credentials.create(options)`: the key makes a credential after a touch | `navigator.credentials.get(options)`: the key signs the challenge after a touch |
| 3 | `POST /api/register/finish`: webauthn-rs verifies it; the server stores the credential ID, public key and counter | `POST /api/login/finish`: webauthn-rs verifies the signature, the UP flag and the counter; the server starts a session |

The server keeps each ceremony's state (the challenge) and uses it once. The browser only
carries an opaque ceremony ID. After a sign-in, Topcoat issues a session cookie (`__Host-`,
`Secure`, `HttpOnly`). The server stores only the token's hash.

## Options that matter for a Jotakey

The firmware implements CTAP 2.0 with non-discoverable credentials and no PIN. The demo
uses webauthn-rs's *security key* flow, which matches that:

- `residentKey: "discouraged"`. The key does not store credentials, so sign-in starts with
  a username and the server sends that user's credential IDs.
- `userVerification: "discouraged"`, and no `credProtect` extension. Jotakey checks
  presence (a touch) but has no PIN, which webauthn-rs calls a *user-presence-only security
  key* (the `danger-user-presence-only-security-keys` feature). Without that setting,
  webauthn-rs requests credProtect "userVerificationRequired", and Chrome refuses the
  registration: "Requested protection policy is inconsistent or incongruent with other
  requested parameters". A relying party that *requires* UV cannot use a Jotakey yet.
- `attestation: "none"` and ES256 (`-7`), the only algorithm Jotakey implements.

## Before you put this in front of users

This is a demo. Everything lives in memory and vanishes on restart. A real deployment needs:

- **HTTPS** and your real domain: `rp_id` = your domain, origin = `https://` URL.
- **Persistent storage** for accounts, credentials (serialise `SecurityKey` with serde), the
  counter, and sessions.
- **Expiry** for abandoned ceremonies, and rate limiting.
- **Two keys per user**, or another recovery path: a credential cannot be copied off a
  Jotakey, so a lost key is a lost login.
