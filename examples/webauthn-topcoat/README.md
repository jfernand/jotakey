# webauthn-topcoat: sign in to your own web app with a Jotakey

(c) Javier Fernandez @ JotaSoft 2026

A minimal relying party, the server side of WebAuthn, written with
[Topcoat](https://github.com/tokio-rs/topcoat) and
[webauthn-rs](https://github.com/kanidm/webauthn-rs). One page lets you register a security
key under a username and then sign in with it. It runs on `localhost` for trying a Jotakey
in a real browser, or on your own domain, with its state in DynamoDB (for AWS Lambda).

## Run it

```sh
just bridge                                  # C6 DevKit: expose the key to the browser (Linux)
cd examples/webauthn-topcoat && cargo run    # needs OpenSSL headers (libssl-dev)
```

Open **http://localhost:3000**. Use `localhost`, not `127.0.0.1`: WebAuthn needs a domain
name as the RP ID, and browsers allow plain HTTP only on `localhost`. Pick a username, click
**Register a key**, and touch the key when it blinks. Then click **Sign in** and touch it
again. The page shows the signature counter, which goes up by one with every sign-in.
Signed out, the page also lists the registered users: click a name to sign in with its key.

`PORT=8080 cargo run` serves on another port.

## Configuration

Everything is optional and comes from the environment:

| Variable | Default | Meaning |
|---|---|---|
| `ORIGIN` | `http://localhost:PORT` | the URL the browser shows, e.g. `https://jotakey.casaroja.es`; anything but `localhost` must be `https` |
| `RP_ID` | the origin's host | the WebAuthn relying party ID; credentials are bound to it, so changing it later strands every registered key |
| `PORT`, `HOST` | `3000`, `127.0.0.1` | where to listen |
| `DYNAMODB_TABLE` | unset: state in memory | keep accounts, ceremonies and sessions in this DynamoDB table (needs the `dynamodb` feature) |

On your own domain, behind something that terminates HTTPS:

```sh
ORIGIN=https://jotakey.casaroja.es cargo run
```

## On AWS

`infra/` deploys the demo to https://jotakey.casaroja.es: Lambda behind an API Gateway HTTP
API, with the state in DynamoDB. `infra/README.md` has the steps.

## State in DynamoDB

`cargo build --features dynamodb` adds a DynamoDB backend (`src/store/dynamo.rs`). Set
`DYNAMODB_TABLE`, and the server keeps its state there, so any number of instances (AWS
Lambda starts and stops them as it likes) can serve one ceremony's start and finish. The AWS
SDK takes its credentials and region from the usual places (on Lambda: the function's role).

The table has one string partition key, `pk`, and time-to-live on the `ttl` attribute:

| `pk` | Holds |
|---|---|
| `account#<username>` | user handle, keys (JSON), last counter, a `version` for conditional updates |
| `credential#<credential ID>` | the owning username: a credential belongs to one account |
| `ceremony#<id>` | a registration or sign-in in progress (its challenge), for 5 minutes |
| `session#<token hash>` | a signed-in session (username and user handle), for an hour |

A ceremony is deleted as it is read, so of two finish requests only one gets its state.
Account updates are conditional on `version` and retried, so concurrent sign-ins never lose
a counter.

To try it locally against DynamoDB Local:

```sh
docker run --rm -p 8765:8000 amazon/dynamodb-local -jar DynamoDBLocal.jar -inMemory -sharedDb
export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_REGION=eu-west-1 \
       AWS_ENDPOINT_URL=http://localhost:8765
aws dynamodb create-table --table-name jotakey-rp --billing-mode PAY_PER_REQUEST \
    --attribute-definitions AttributeName=pk,AttributeType=S --key-schema AttributeName=pk,KeyType=HASH
DYNAMODB_TABLE=jotakey-rp cargo run --features dynamodb
```

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

A signed-in user can remove any of their keys (`POST /api/keys/remove`). The server forgets
the credential and frees its ID; the key itself stored nothing, since its credentials are
not discoverable. Removing the last key deletes the account, frees the username, and ends
the session. A session and a sign-in ceremony record the account's user handle as well as
its username, and count only while the account still has that handle: if someone registers
the freed username, a session left open elsewhere for the old account does not sign in to
the new one.

## Options that matter for a Jotakey

The firmware implements CTAP 2.0 with non-discoverable credentials, plus the CTAP 2.1 client
PIN. By default the demo asks only for a touch, never the PIN, and uses webauthn-rs's
*security key* flow, which matches that:

- `residentKey: "discouraged"`. The key does not store credentials, so sign-in starts with
  a username and the server sends that user's credential IDs.
- `userVerification: "discouraged"`, and no `credProtect` extension: a touch and no PIN,
  which webauthn-rs calls a *user-presence-only security key* (the
  `danger-user-presence-only-security-keys` feature). Without that setting,
  webauthn-rs requests credProtect "userVerificationRequired", and Chrome refuses the
  registration: "Requested protection policy is inconsistent or incongruent with other
  requested parameters". **Register with PIN** asks for UV another way (below).
- `attestation: "direct"` and ES256 (`-7`), the only algorithm Jotakey implements. With
  `"none"`, Chrome zeroes the AAGUID, so the page could not name the model. A Jotakey answers
  with packed self-attestation: signed by the new credential's own key, with no certificate,
  so it identifies no one. webauthn-rs verifies the signature; with no list of trusted CAs
  it accepts any attestation that verifies. Synced passkeys still answer `"none"`.
- No `hints`. The security-key flow sends `hints: ["security-key"]`, and Safari then offers
  only an NFC or USB key, so an iPhone's own passkeys fail with `NotAllowedError`. The server
  drops the hint, and browsers offer every kind of authenticator, Jotakey included.
- Transports kept. At registration the browser reports how it reached the authenticator
  (`usb`, `nfc`, `internal`, `hybrid`). webauthn-rs drops that for `attestation: "none"`, and
  without it in `allowCredentials` Safari looks for an NFC or USB key and reports "a security
  key that is not registered". The server stores the transports and sends them back. They
  only steer the browser's prompt; no check depends on them.

### Register with PIN

**Register with PIN** (or **Add a key with PIN**, once signed in) makes a key that must
verify the user, with its PIN, at registration and at every sign-in after. WebAuthn gives a
site no way to set an authenticator's PIN: the browser does that. The registration asks for
`userVerification: "required"`, so Chrome asks for the Jotakey's PIN, or offers to create one
if the key has none. Jotakey then sets the UV flag, which it does only for a request whose
`pinUvAuthParam` verifies against the PIN token.

The request changes, but not webauthn-rs's flow, so still no `credProtect`; the server
checks the result itself:

- At registration, a response without the UV flag is refused ("the key did not verify you").
- The stored credential is marked as registered with policy "required". At every sign-in,
  webauthn-rs refuses an assertion with that credential whose UV flag is clear, whatever the
  browser was asked for.
- A sign-in asks for `userVerification: "required"` when all of the user's keys need it, and
  `"preferred"` when some do, so the browser asks for the PIN of a key that has one.

The page shows **PIN required** for each key. A PIN on the key stays until
`authenticatorReset`, which also invalidates every credential the key made.

After signing in, the page lists everything the server stores about the account: the user
handle, and per key the credential ID, whether it is a synced passkey or device-bound,
transports, algorithm, attestation format, whether it needs the PIN, when it was registered
and last used, and the counter, with what the authenticator reported at this sign-in.

It also recognises a Jotakey (`src/model.rs`). At registration the server reads the AAGUID,
the 16-byte model ID in the authenticator data, with Jotakey's own CBOR decoder
(`jotakey_core::cbor`, the one the key runs). That decoder accepts only CTAP2 canonical CBOR:
if the browser's attestation object breaks a rule (keys out of order, a non-shortest number),
the key still registers, and the page says so: "Hmm, it looks like your browser just sent bad
CBOR: its map keys are not in canonical order." A Jotakey's is ASCII, `jotakey-` followed by
the model (`jotakey_core::AAGUID`, e.g. `jotakey-v01-c6`). A sign-in does not carry the
AAGUID, so the page looks up the key used: "You signed in with a Jotakey (v01-c6)". If the
browser zeroed the AAGUID, a 49-byte credential ID starting with `0x01`, Jotakey's format,
still marks it as probably a Jotakey. Neither is proof: with self-attestation, any
authenticator could claim the AAGUID, so nothing relies on it.

## Versions

The demo has its own version (`Cargo.toml`), shown in the page's footer with the commit it
was built from. Releases are tagged `webauthn-topcoat-vX.Y.Z`, apart from the board's
`hw-v*` and the firmware's `fw-v*` tags.

## Before you put this in front of users

This is a demo. A real deployment also needs:

- **HTTPS** in front of it, and `ORIGIN` set to your `https://` URL (see Configuration).
- **Persistent storage:** the `dynamodb` feature, or another backend in `src/store/`.
  Ceremonies expire after 5 minutes and sessions after an hour in either backend.
- **No list of users.** The sign-in page lists every username, so anyone can see who has
  an account. That suits a demo; a real site keeps it private (`Store::usernames`).
- **Rate limiting** on the five `/api` routes. The server has none; the AWS deployment
  throttles the whole API at API Gateway.
- **Two keys per user**, or another recovery path: a credential cannot be copied off a
  Jotakey, so a lost key is a lost login.
