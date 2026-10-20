// (c) Javier Fernandez @ JotaSoft 2026
//! A minimal WebAuthn relying party for trying a Jotakey in a real browser.
//!
//! One page: choose a username, register a security key, sign in with it. Topcoat serves
//! the page and four JSON routes; webauthn-rs does every check a relying party must make
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
//! without the PIN.

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

use store::{AddKey, Ceremony, Store};

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

/// The signed-in username, if the request carries an unexpired session. A storage failure
/// counts as signed out.
async fn current_user(cx: &Cx) -> Result<Option<String>> {
    let Some(hash) = session::token_hash(cx).await? else { return Ok(None) };
    Ok(app(cx).store.session_user(&hash).await.unwrap_or_else(|e| {
        eprintln!("store: {e}");
        None
    }))
}

#[page("/")]
async fn home(cx: &Cx) -> Result<impl View> {
    let user = current_user(cx).await?;
    let store = &app(cx).store;
    let account = match &user {
        Some(u) => store.account(u).await.unwrap_or_else(|e| {
            eprintln!("store: {e}");
            None
        }),
        None => None,
    };
    let signed_in = user.is_some();
    let name = user.clone().unwrap_or_default();
    let sections = match &account {
        Some(account) => profile::sections(&name, account),
        None => Vec::new(),
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
                <main>
                    <h1>"Jotakey demo"</h1>
                    <p class="lead">"A relying party demo. Register a security key, then sign in with it."</p>
                    if signed_in {
                        <section class="card ok">
                            <h2>"Signed in as " (name.as_str())</h2>
                            <p class="note">"This is everything the server stores about you. It keeps no name, email address, IP address or browser."</p>
                            for section in &sections {
                                <h3>(section.title.as_str())</h3>
                                <dl>
                                    for (label, value) in &section.rows {
                                        <dt>(*label)</dt><dd>(value.as_str())</dd>
                                    }
                                </dl>
                            }
                            <div class="row">
                                <button id="register" data-username=(name.as_str())>"Add another key"</button>
                                <form method="post" action="/logout"><button class="quiet">"Sign out"</button></form>
                            </div>
                        </section>
                    } else {
                        <section class="card">
                            <label for="username">"Username"</label>
                            <input id="username" autocomplete="username" placeholder="alice" required="">
                            <div class="row">
                                <button id="register">"Register a key"</button>
                                <button id="login">"Sign in"</button>
                            </div>
                        </section>
                    }
                    <p id="status" role="status"></p>
                    <p class="note">"Touch the key when it blinks."
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
        Some(account) if signed_in.as_deref() == Some(username.as_str()) => {
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
    let options = any_authenticator(options);
    let ceremony = Uuid::new_v4();
    stored!(app.store.begin(ceremony, Ceremony::Registration { username, user_id, state }).await);
    Ok(Json(json!({ "ok": true, "ceremony": ceremony, "options": options })))
}

#[route(POST "/api/register/finish")]
async fn register_finish(cx: &Cx, Json(req): Json<Finish<RegisterPublicKeyCredential>>) -> Result<Json<Value>> {
    let app = app(cx);
    // Each ceremony's state is used once, whatever the outcome.
    let Some(Ceremony::Registration { username, user_id, state }) = stored!(app.store.take(req.ceremony).await) else {
        return Ok(failed("unknown or expired registration; start again"));
    };
    let key = match app.webauthn.finish_securitykey_registration(&req.credential, &state) {
        Ok(k) => with_transports(k, &req.credential),
        Err(e) => return Ok(failed(e)),
    };
    // A credential ID belongs to one account only; a username to one user handle.
    match stored!(app.store.add_key(&username, user_id, key).await) {
        AddKey::Added(keys) => Ok(Json(json!({ "ok": true, "username": username, "keys": keys }))),
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
    let options = any_authenticator(options);
    let ceremony = Uuid::new_v4();
    stored!(app.store.begin(ceremony, Ceremony::Authentication { username, state }).await);
    Ok(Json(json!({ "ok": true, "ceremony": ceremony, "options": options })))
}

#[route(POST "/api/login/finish")]
async fn login_finish(cx: &Cx, Json(req): Json<Finish<PublicKeyCredential>>) -> Result<Json<Value>> {
    let app = app(cx);
    let Some(Ceremony::Authentication { username, state }) = stored!(app.store.take(req.ceremony).await) else {
        return Ok(failed("unknown or expired sign-in; start again"));
    };
    // Checks the challenge, origin, RP ID hash, UP flag, signature and counter.
    let result = match app.webauthn.finish_securitykey_authentication(&req.credential, &state) {
        Ok(r) => r,
        Err(e) => return Ok(failed(e)),
    };
    // Store the new counter before the session starts.
    if !stored!(app.store.record_sign_in(&username, &result).await) {
        return Ok(failed("account removed during sign-in"));
    }
    let new_session = session::start(cx).await?;
    stored!(app.store.start_session(&new_session.token_hash, &username, new_session.expires_at).await);
    Ok(Json(json!({ "ok": true, "username": username, "counter": result.counter() })))
}

#[route(POST "/logout")]
async fn logout(cx: &Cx) -> Result<SeeOther> {
    if let Some(hash) = session::stop(cx).await?
        && let Err(e) = app(cx).store.end_session(&hash).await
    {
        eprintln!("store: {e}");
    }
    Ok(see_other("/"))
}
