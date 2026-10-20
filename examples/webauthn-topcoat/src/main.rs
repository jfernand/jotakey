// (c) Javier Fernandez @ JotaSoft 2026
//! A minimal WebAuthn relying party for trying a Jotakey in a real browser.
//!
//! One page: choose a username (or pick one from the list), register a security key, sign
//! in with it, remove it again. Topcoat serves the page and five JSON routes; webauthn-rs does every check a relying party must make
//! (challenge, origin, RP ID hash, user presence, signature, counter). Accounts, keys,
//! ceremonies and sessions live in a [`store::Store`]: in memory by default, in DynamoDB
//! when `DYNAMODB_TABLE` is set (the `dynamodb` feature, for AWS Lambda).
//!
//! Configuration, all optional, from the environment:
//! - `ORIGIN`: the URL the browser shows, such as `https://jotakey.casaroja.es`.
//!   Default `http://localhost:PORT`.
//! - `RP_ID`: the WebAuthn relying party ID. Default: the origin's host. Credentials are
//!   bound to it, so changing it later strands every registered key.
//! - `PORT`, `HOST`: where to listen (Topcoat's defaults are 3000 and 127.0.0.1).
//! - `DYNAMODB_TABLE`: keep the state in this DynamoDB table instead of memory.
//!
//! The options match what the Jotakey firmware supports today: non-discoverable
//! credentials (the browser is told which credential IDs to use), ES256, and a touch
//! without the PIN, or with it: "Register with PIN" makes a key that must verify the user
//! at registration and at every sign-in after.

mod model;
mod profile;
mod store;

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use topcoat::{
    Result,
    context::{Cx, app_context},
    cookie::RouterBuilderCookieExt,
    router::{
        Router,
        content::{Css, Js, Json},
        error::{SeeOther, see_other},
        page, route,
    },
    session::{self, RouterBuilderSessionExt, SessionConfig},
    view::{View, view},
};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::UserVerificationPolicy;

use store::{Account, AddKey, Ceremony, Key, RemoveKey, Store};

/// The commit this binary was built from, set by infra/build.sh; unset for a local build.
const COMMIT: Option<&str> = option_env!("JOTAKEY_COMMIT");
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long a sign-in lasts.
const SESSION_LIFETIME: Duration = Duration::from_secs(60 * 60);

#[tokio::main]
async fn main() {
    // WebAuthn needs a domain, not an IP address: locally, browse to http://localhost:PORT.
    // Browsers treat localhost as a secure context, so plain HTTP is allowed there; anywhere
    // else the origin must be https.
    let origin = match std::env::var("ORIGIN") {
        Ok(origin) => Url::parse(&origin).expect("ORIGIN must be a URL, such as https://jotakey.casaroja.es"),
        Err(_) => {
            let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
            Url::parse(&format!("http://localhost:{port}")).expect("origin URL")
        }
    };
    let rp_id = match std::env::var("RP_ID") {
        Ok(rp_id) => rp_id,
        Err(_) => origin.host_str().expect("ORIGIN must have a host").to_owned(),
    };
    let webauthn = WebauthnBuilder::new(&rp_id, &origin)
        .expect("RP_ID must be the origin's host or a parent domain of it")
        .rp_name("Jotakey demo")
        // Touch, no PIN: no credProtect extension, userVerification "discouraged".
        .danger_set_user_presence_only_security_keys(true)
        .build()
        .expect("WebAuthn configuration");
    let store = match std::env::var("DYNAMODB_TABLE") {
        Ok(table) => dynamo(table).await,
        Err(_) => Store::Memory(Default::default()),
    };
    let persistence = if store.persistent() { "DynamoDB" } else { "memory" };

    let router = Router::builder()
        .page(home)
        .route(app_js)
        .route(app_css)
        .route(register_start)
        .route(register_finish)
        .route(login_start)
        .route(login_finish)
        .route(remove_key)
        .route(logout)
        .cookies()
        .sessions(SessionConfig::builder().lifetime(SESSION_LIFETIME).build())
        .app_context(App { webauthn, store })
        .build();
    println!("Jotakey demo relying party: {origin} (RP ID {rp_id}, state in {persistence})");
    topcoat::start(router).await.expect("server");
}

#[cfg(feature = "dynamodb")]
async fn dynamo(table: String) -> Store {
    Store::Dynamo(store::dynamo::Store::connect(table).await)
}

#[cfg(not(feature = "dynamodb"))]
async fn dynamo(_table: String) -> Store {
    panic!("DYNAMODB_TABLE is set, but this build lacks the dynamodb feature")
}

struct App {
    webauthn: Webauthn,
    store: Store,
}

fn app(cx: &Cx) -> &App {
    app_context(cx)
}

/// Log a storage failure; the client learns only that storage is unavailable.
fn unavailable(e: store::Error) -> Json<Value> {
    eprintln!("store: {e}");
    failed("the server's storage is unavailable; try again")
}

/// Unwrap a storage result in a route, or answer with [`unavailable`].
macro_rules! stored {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => return Ok(unavailable(e)),
        }
    };
}

/// The signed-in username and account, if the request carries an unexpired session for an
/// account that still exists (`Store::signed_in`). A storage failure counts as signed out.
async fn current_user(cx: &Cx) -> Result<Option<(String, Account)>> {
    let Some(hash) = session::token_hash(cx).await? else { return Ok(None) };
    Ok(app(cx).store.signed_in(&hash).await.unwrap_or_else(|e| {
        eprintln!("store: {e}");
        None
    }))
}

/// End the request's session, if any.
async fn end_session(cx: &Cx) -> Result<()> {
    if let Some(hash) = session::stop(cx).await?
        && let Err(e) = app(cx).store.end_session(&hash).await
    {
        eprintln!("store: {e}");
    }
    Ok(())
}

#[page("/")]
async fn home(cx: &Cx) -> Result<impl View> {
    let user = current_user(cx).await?;
    let store = &app(cx).store;
    let signed_in = user.is_some();
    let name = user.as_ref().map(|(name, _)| name.clone()).unwrap_or_default();
    let sections = match &user {
        Some((name, account)) => profile::sections(name, account),
        None => Vec::new(),
    };
    let jotakey = user.as_ref().and_then(|(_, account)| profile::signed_in_with_jotakey(account));
    let last_key = if user.as_ref().is_some_and(|(_, account)| account.keys.len() == 1) { "yes" } else { "no" };
    // Signed out: everyone who can sign in, to pick from.
    let usernames = if signed_in {
        Vec::new()
    } else {
        store.usernames().await.unwrap_or_else(|e| {
            eprintln!("store: {e}");
            Vec::new()
        })
    };
    let in_memory = !store.persistent();
    let commit_url = COMMIT.map(|c| format!("https://github.com/jfernand/jotakey/commit/{c}"));
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>"Jotakey demo"</title>
                <link rel="stylesheet" href="/app.css">
                <script type="module" src="/app.js"></script>
            </head>
            <body>
                <main class=(if signed_in { "signed-in" } else { "" })>
                    <h1>"Jotakey demo"</h1>
                    <p class="lead">"A relying party demo. Register a security key, then sign in with it."</p>
                    if signed_in {
                        <section class="card ok">
                            <h2>"Signed in as " (name.as_str())</h2>
                            if let Some(jotakey) = &jotakey {
                                <p class="jotakey">(jotakey.as_str())</p>
                            }
                            <p class="note">"This is everything the server stores about you. It keeps no name, email address, IP address or browser."</p>
                            for section in &sections {
                                <h3>(section.title.as_str())</h3>
                                <dl>
                                    for (label, value) in &section.rows {
                                        <dt>(*label)</dt><dd>(value.as_str())</dd>
                                    }
                                </dl>
                                if let Some(credential) = &section.credential {
                                    <button class="quiet remove" data-credential=(credential.as_str()) data-last=(last_key)>"Remove this key"</button>
                                }
                            }
                            <div class="row">
                                <button id="register" data-username=(name.as_str())>"Add another key"</button>
                                <button id="register-pin" data-username=(name.as_str()) data-pin="">"Add a key with PIN"</button>
                                <form method="post" action="/logout"><button class="quiet">"Sign out"</button></form>
                            </div>
                        </section>
                    } else {
                        <section class="card">
                            <label for="username">"Username"</label>
                            <input id="username" autocomplete="username" placeholder="alice" required="">
                            <div class="row">
                                <button id="register">"Register a key"</button>
                                <button id="register-pin" data-pin="">"Register with PIN"</button>
                                <button id="login">"Sign in"</button>
                            </div>
                        </section>
                        if !usernames.is_empty() {
                            <section class="card">
                                <h2>"Registered users"</h2>
                                <p class="note">"Click a name to sign in with its key."</p>
                                <div class="row">
                                    for user in &usernames {
                                        <button class="quiet user" data-username=(user.as_str())>(user.as_str())</button>
                                    }
                                </div>
                            </section>
                        }
                    }
                    <p id="status" role="status"></p>
                    <p class="note">"Touch the key when it blinks. With PIN, the browser first asks for the key's PIN, and offers to set one if it has none."
                        if in_memory { " Accounts live in memory until the server stops." }
                    </p>
                    <footer class="note">
                        "webauthn-topcoat " (VERSION) " · "
                        if let (Some(commit), Some(url)) = (COMMIT, commit_url.as_deref()) {
                            <a href=(url)>(commit.get(..7).unwrap_or(commit))</a>
                        } else {
                            "local build"
                        }
                    </footer>
                </main>
            </body>
        </html>
    })
}

#[route(GET "/app.js")]
async fn app_js() -> Result<Js<&'static str>> {
    Ok(Js(include_str!("app.js")))
}

#[route(GET "/app.css")]
async fn app_css() -> Result<Css<&'static str>> {
    Ok(Css(include_str!("app.css")))
}

#[derive(Deserialize)]
struct Start {
    username: String,
    /// Registration only: require user verification for this key (PIN, fingerprint or face).
    #[serde(default)]
    pin: bool,
}

#[derive(Deserialize)]
struct Finish<T> {
    ceremony: Uuid,
    credential: T,
}

fn failed(message: impl std::fmt::Display) -> Json<Value> {
    Json(json!({ "ok": false, "error": message.to_string() }))
}

/// Drop the `security-key` hint webauthn-rs's security-key flow adds, so the browser offers
/// every authenticator: a Jotakey, a phone, the platform's own passkeys. Safari follows the
/// hint strictly and offers only an NFC or USB key, which fails on an iPhone without one.
/// The hint is UI only; the server's checks do not depend on it.
trait AnyAuthenticator {
    fn clear_hints(&mut self);
}

impl AnyAuthenticator for CreationChallengeResponse {
    fn clear_hints(&mut self) {
        self.public_key.hints = None;
    }
}

impl AnyAuthenticator for RequestChallengeResponse {
    fn clear_hints(&mut self) {
        self.public_key.hints = None;
    }
}

fn any_authenticator<T: AnyAuthenticator>(mut options: T) -> T {
    options.clear_hints();
    options
}

/// Ask for "direct" attestation instead of webauthn-rs's "none". With "none", Chrome zeroes
/// the AAGUID, so the page cannot name the model. A Jotakey's attestation is packed
/// self-attestation: signed by the new credential's own key, with no certificate, so it
/// identifies no one; webauthn-rs verifies that signature, and with no list of trusted
/// CAs it accepts any attestation that verifies. Synced passkeys still answer "none".
fn ask_for_model(mut options: CreationChallengeResponse) -> CreationChallengeResponse {
    options.public_key.attestation = Some(webauthn_rs_proto::AttestationConveyancePreference::Direct);
    options
}

/// Ask the authenticator to verify the user: `userVerification: "required"`, so the browser
/// asks for the key's PIN (or offers to set one). Only the request changes: webauthn-rs's
/// security-key flow still asks for no `credProtect` (Chrome refuses Jotakey's registration
/// with it), so the server checks the UV flag itself, in [`require_pin`].
fn ask_for_pin(mut options: CreationChallengeResponse) -> CreationChallengeResponse {
    options.public_key.authenticator_selection.get_or_insert_with(Default::default).user_verification =
        UserVerificationPolicy::Required;
    options
}

/// A key registered with PIN: refuse it unless the authenticator verified the user, and
/// record its policy as "required", so webauthn-rs refuses every later sign-in with it that
/// is not verified (`finish_securitykey_authentication` checks the policy each credential
/// was registered with).
fn require_pin(key: SecurityKey) -> std::result::Result<SecurityKey, &'static str> {
    let mut credential = Credential::from(key);
    if !credential.user_verified {
        return Err("the key did not verify you (no PIN was entered), so it was not registered");
    }
    credential.registration_policy = UserVerificationPolicy::Required;
    Ok(SecurityKey::from(credential))
}

/// Whether every sign-in with this key must verify the user.
pub fn pin_required(key: &SecurityKey) -> bool {
    Credential::from(key.clone()).registration_policy == UserVerificationPolicy::Required
}

/// What a sign-in asks the browser for: verification if every key needs it, verification
/// when the key can do it if some do (so a key registered with PIN gets the PIN prompt),
/// otherwise a touch only. A hint for the browser: webauthn-rs enforces each key's policy.
fn sign_in_verification(keys: &[SecurityKey]) -> UserVerificationPolicy {
    match keys.iter().filter(|k| pin_required(k)).count() {
        0 => UserVerificationPolicy::Discouraged_DO_NOT_USE,
        n if n == keys.len() => UserVerificationPolicy::Required,
        _ => UserVerificationPolicy::Preferred,
    }
}

/// Keep the transports the browser reported at registration (`getTransports()`: usb, nfc,
/// internal, hybrid...). webauthn-rs drops them unless the attestation is packed or tpm, and
/// without them in `allowCredentials` Safari looks for an NFC or USB key instead of the
/// phone's own passkey: "a security key that is not registered". They are an unsigned hint
/// for the browser's UI, which WebAuthn says to store and send back; no check relies on them.
fn with_transports(key: SecurityKey, registration: &RegisterPublicKeyCredential) -> SecurityKey {
    let mut credential = Credential::from(key);
    if credential.transports.is_none() {
        credential.transports = registration.response.transports.clone();
    }
    SecurityKey::from(credential)
}

fn valid_username(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.chars().all(|c| c.is_alphanumeric() || "._-@".contains(c))
}

/// Begin registering a key: for a new username, or another key for the signed-in user.
#[route(POST "/api/register/start")]
async fn register_start(cx: &Cx, Json(req): Json<Start>) -> Result<Json<Value>> {
    let username = req.username.trim().to_owned();
    if !valid_username(&username) {
        return Ok(failed("choose a username: letters, digits and ._-@, up to 64"));
    }
    let signed_in = current_user(cx).await?;
    let app = app(cx);
    let (user_id, exclude) = match stored!(app.store.account(&username).await) {
        // Adding a key to an existing account needs that account's session.
        Some(account) if signed_in.as_ref().map(|(name, _)| name.as_str()) == Some(username.as_str()) => {
            (account.user_id, Some(account.keys.iter().map(|k| k.key.cred_id().clone()).collect()))
        }
        Some(_) => return Ok(failed("that username is taken; sign in to add a key to it")),
        None => (Uuid::new_v4(), None),
    };
    let (options, state) =
        match app.webauthn.start_securitykey_registration(user_id, &username, &username, exclude, None, None) {
            Ok(r) => r,
            Err(e) => return Ok(failed(e)),
        };
    let options = ask_for_model(any_authenticator(options));
    let options = if req.pin { ask_for_pin(options) } else { options };
    let ceremony = Uuid::new_v4();
    let pin = req.pin;
    stored!(app.store.begin(ceremony, Ceremony::Registration { username, user_id, pin, state }).await);
    Ok(Json(json!({ "ok": true, "ceremony": ceremony, "options": options })))
}

#[route(POST "/api/register/finish")]
async fn register_finish(cx: &Cx, Json(req): Json<Finish<RegisterPublicKeyCredential>>) -> Result<Json<Value>> {
    let app = app(cx);
    // Each ceremony's state is used once, whatever the outcome.
    let Some(Ceremony::Registration { username, user_id, pin, state }) = stored!(app.store.take(req.ceremony).await)
    else {
        return Ok(failed("unknown or expired registration; start again"));
    };
    let key = match app.webauthn.finish_securitykey_registration(&req.credential, &state) {
        Ok(k) => with_transports(k, &req.credential),
        Err(e) => return Ok(failed(e)),
    };
    let key = if pin {
        match require_pin(key) {
            Ok(k) => k,
            Err(e) => return Ok(failed(e)),
        }
    } else {
        key
    };
    // The model is a label: if Jotakey's strict decoder rejects the browser's CBOR, the key
    // still registers (webauthn-rs accepted it), and the page says what was wrong.
    let (aaguid, unread) = match model::aaguid(req.credential.response.attestation_object.as_ref()) {
        Ok(aaguid) => (aaguid, None),
        Err(why) => (None, Some(model::unread_message(&why))),
    };
    let model = model::describe(aaguid.as_ref(), unread.as_deref(), key.cred_id().as_ref());
    let reply = json!({ "ok": true, "username": username, "model": model, "warning": unread });
    // A credential ID belongs to one account only; a username to one user handle.
    match stored!(app.store.add_key(&username, user_id, Key::new(key, aaguid, unread)).await) {
        AddKey::Added(keys) => {
            let mut reply = reply;
            reply["keys"] = json!(keys);
            Ok(Json(reply))
        }
        AddKey::Taken => Ok(failed("that username was taken meanwhile; choose another")),
        AddKey::Duplicate => Ok(failed("this credential is already registered")),
    }
}

#[route(POST "/api/login/start")]
async fn login_start(cx: &Cx, Json(req): Json<Start>) -> Result<Json<Value>> {
    let username = req.username.trim().to_owned();
    let app = app(cx);
    let Some(account) = stored!(app.store.account(&username).await) else {
        return Ok(failed("no such user; register a key first"));
    };
    // allowCredentials lists this user's keys: Jotakey's credentials are not discoverable.
    let keys: Vec<SecurityKey> = account.keys.iter().map(|k| k.key.clone()).collect();
    let (options, state) = match app.webauthn.start_securitykey_authentication(&keys) {
        Ok(r) => r,
        Err(e) => return Ok(failed(e)),
    };
    let mut options = any_authenticator(options);
    options.public_key.user_verification = sign_in_verification(&keys);
    let ceremony = Uuid::new_v4();
    let user_id = account.user_id;
    stored!(app.store.begin(ceremony, Ceremony::Authentication { username, user_id, state }).await);
    Ok(Json(json!({ "ok": true, "ceremony": ceremony, "options": options })))
}

#[route(POST "/api/login/finish")]
async fn login_finish(cx: &Cx, Json(req): Json<Finish<PublicKeyCredential>>) -> Result<Json<Value>> {
    let app = app(cx);
    let Some(Ceremony::Authentication { username, user_id, state }) = stored!(app.store.take(req.ceremony).await)
    else {
        return Ok(failed("unknown or expired sign-in; start again"));
    };
    // Checks the challenge, origin, RP ID hash, UP flag, signature and counter, and the UV
    // flag for a key registered with PIN.
    let result = match app.webauthn.finish_securitykey_authentication(&req.credential, &state) {
        Ok(r) => r,
        Err(e) => return Ok(failed(e)),
    };
    // Store the new counter before the session starts.
    if !stored!(app.store.record_sign_in(&username, user_id, &result).await) {
        return Ok(failed("this key or account was removed during sign-in"));
    }
    let new_session = session::start(cx).await?;
    stored!(app.store.start_session(&new_session.token_hash, &username, user_id, new_session.expires_at).await);
    Ok(Json(json!({ "ok": true, "username": username, "counter": result.counter() })))
}

#[derive(Deserialize)]
struct Remove {
    /// The key's credential ID, base64url.
    credential: String,
}

/// Unregister one of the signed-in user's keys. Removing the last one deletes the account,
/// frees the username, and ends the session.
#[route(POST "/api/keys/remove")]
async fn remove_key(cx: &Cx, Json(req): Json<Remove>) -> Result<Json<Value>> {
    let Some((username, account)) = current_user(cx).await? else {
        return Ok(failed("sign in to remove a key"));
    };
    match stored!(app(cx).store.remove_key(&username, account.user_id, &req.credential).await) {
        RemoveKey::Removed(keys) => Ok(Json(json!({ "ok": true, "keys": keys }))),
        RemoveKey::AccountDeleted => {
            end_session(cx).await?;
            Ok(Json(json!({ "ok": true, "keys": 0 })))
        }
        RemoveKey::NotFound => Ok(failed("this account has no such key")),
    }
}

#[route(POST "/logout")]
async fn logout(cx: &Cx) -> Result<SeeOther> {
    end_session(cx).await?;
    Ok(see_other("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored ES256 key, registered with or without user verification.
    fn key(user_verified: bool) -> SecurityKey {
        let (x, y) = ([1u8; 32], [2u8; 32]);
        let credential = json!({
            "cred_id": "AQID",
            "cred": { "type_": "ES256", "key": { "EC_EC2": { "curve": "SECP256R1", "x": x, "y": y } } },
            "counter": 0,
            "transports": null,
            "user_verified": user_verified,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "discouraged",
            "extensions": { "cred_protect": "NotRequested", "hmac_create_secret": "NotRequested" },
            "attestation": { "data": "None", "metadata": "None" },
            "attestation_format": "none",
        });
        SecurityKey::from(serde_json::from_value::<Credential>(credential).expect("credential JSON"))
    }

    #[test]
    fn a_pin_key_must_be_verified() {
        assert!(require_pin(key(false)).is_err(), "no UV at registration");
        let with_pin = require_pin(key(true)).expect("verified");
        assert!(pin_required(&with_pin));
        assert!(!pin_required(&key(true)), "verified, but registered without PIN");
    }

    #[test]
    fn sign_in_asks_for_the_pin_when_a_key_needs_it() {
        let with_pin = require_pin(key(true)).expect("verified");
        assert_eq!(sign_in_verification(&[key(false)]), UserVerificationPolicy::Discouraged_DO_NOT_USE);
        assert_eq!(sign_in_verification(std::slice::from_ref(&with_pin)), UserVerificationPolicy::Required);
        assert_eq!(sign_in_verification(&[key(false), with_pin]), UserVerificationPolicy::Preferred);
    }

    #[test]
    fn registration_with_pin_requires_uv() {
        let origin = Url::parse("http://localhost:3000").unwrap();
        let builder = WebauthnBuilder::new("localhost", &origin).unwrap();
        let webauthn = builder.danger_set_user_presence_only_security_keys(true).build().unwrap();
        let (options, _) =
            webauthn.start_securitykey_registration(Uuid::new_v4(), "a", "a", None, None, None).unwrap();
        let options = serde_json::to_value(ask_for_pin(options)).unwrap();
        assert_eq!(options["publicKey"]["authenticatorSelection"]["userVerification"], "required");
        assert!(options["publicKey"].get("extensions").is_none_or(|e| e.get("credentialProtectionPolicy").is_none()));
    }
}
