// (c) Javier Fernandez @ JotaSoft 2026
//! A minimal WebAuthn relying party for trying a Jotakey in a real browser.
//!
//! One page: choose a username, register a security key, sign in with it. Topcoat serves
//! the page and four JSON routes; webauthn-rs does every check a relying party must make
//! (challenge, origin, RP ID hash, user presence, signature, counter). Accounts, keys,
//! ceremonies and sessions live in memory and vanish when the server stops.
//!
//! The options match what the Jotakey firmware supports today: non-discoverable
//! credentials (the browser is told which credential IDs to use), ES256, no PIN.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

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
    session::{self, RouterBuilderSessionExt, SessionConfig, TokenHash},
    view::{View, view},
};
use webauthn_rs::prelude::*;

/// How long a sign-in lasts.
const SESSION_LIFETIME: Duration = Duration::from_secs(60 * 60);

#[tokio::main]
async fn main() {
    // WebAuthn needs a domain, not an IP address: browse to http://localhost:PORT.
    // Browsers treat localhost as a secure context, so plain HTTP is allowed there.
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let origin = Url::parse(&format!("http://localhost:{port}")).expect("origin URL");
    let webauthn = WebauthnBuilder::new("localhost", &origin)
        .expect("RP ID matches the origin")
        .rp_name("Jotakey demo")
        .build()
        .expect("WebAuthn configuration");

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
        .app_context(App { webauthn, store: Mutex::new(Store::default()) })
        .build();
    println!("Jotakey demo relying party: {origin}");
    topcoat::start(router).await.expect("server");
}

struct App {
    webauthn: Webauthn,
    store: Mutex<Store>,
}

#[derive(Default)]
struct Store {
    accounts: HashMap<String, Account>,
    /// Registrations in progress, by ceremony ID: (username, user handle, state).
    registrations: HashMap<Uuid, (String, Uuid, SecurityKeyRegistration)>,
    /// Sign-ins in progress, by ceremony ID: (username, state).
    authentications: HashMap<Uuid, (String, SecurityKeyAuthentication)>,
    /// Signed-in sessions: token hash -> (username, expiry).
    sessions: HashMap<TokenHash, (String, SystemTime)>,
}

struct Account {
    /// The WebAuthn user handle: random, never the username.
    user_id: Uuid,
    keys: Vec<SecurityKey>,
    last_sign_in: Option<SignIn>,
}

struct SignIn {
    counter: u32,
    user_verified: bool,
}

fn app(cx: &Cx) -> &App {
    app_context(cx)
}

/// The signed-in username, if the request carries an unexpired session.
async fn current_user(cx: &Cx) -> Result<Option<String>> {
    let Some(hash) = session::token_hash(cx).await? else { return Ok(None) };
    let store = app(cx).store.lock().expect("store lock");
    Ok(store
        .sessions
        .get(&hash)
        .filter(|(_, expires)| *expires > SystemTime::now())
        .map(|(user, _)| user.clone()))
}

#[page("/")]
async fn home(cx: &Cx) -> Result<impl View> {
    let user = current_user(cx).await?;
    let (signed_in, name, keys, counter, uv) = {
        let store = app(cx).store.lock().expect("store lock");
        let account = user.as_ref().and_then(|u| store.accounts.get(u));
        let last = account.and_then(|a| a.last_sign_in.as_ref());
        (
            user.is_some(),
            user.clone().unwrap_or_default(),
            account.map_or(0, |a| a.keys.len()),
            last.map_or(0, |s| s.counter),
            last.is_some_and(|s| s.user_verified),
        )
    };
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
                    <p class="lead">"A relying party on your own machine: register a security key, then sign in with it."</p>
                    if signed_in {
                        <section class="card ok">
                            <h2>"Signed in as " (name.as_str())</h2>
                            <dl>
                                <dt>"Registered keys"</dt><dd>(keys)</dd>
                                <dt>"Signature counter"</dt><dd>(counter)</dd>
                                <dt>"User verified"</dt><dd>(if uv { "yes" } else { "no (touch only)" })</dd>
                            </dl>
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
                    <p class="note">"Touch the key when it blinks. Accounts live in memory until the server stops."</p>
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
    let mut store = app.store.lock().expect("store lock");
    let (user_id, exclude) = match store.accounts.get(&username) {
        // Adding a key to an existing account needs that account's session.
        Some(account) if signed_in.as_deref() == Some(username.as_str()) => {
            (account.user_id, Some(account.keys.iter().map(|k| k.cred_id().clone()).collect()))
        }
        Some(_) => return Ok(failed("that username is taken; sign in to add a key to it")),
        None => (Uuid::new_v4(), None),
    };
    let (options, state) =
        match app.webauthn.start_securitykey_registration(user_id, &username, &username, exclude, None, None) {
            Ok(r) => r,
            Err(e) => return Ok(failed(e)),
        };
    let ceremony = Uuid::new_v4();
    store.registrations.insert(ceremony, (username, user_id, state));
    Ok(Json(json!({ "ok": true, "ceremony": ceremony, "options": options })))
}

#[route(POST "/api/register/finish")]
async fn register_finish(cx: &Cx, Json(req): Json<Finish<RegisterPublicKeyCredential>>) -> Result<Json<Value>> {
    let app = app(cx);
    let mut store = app.store.lock().expect("store lock");
    // Each ceremony's state is used once, whatever the outcome.
    let Some((username, user_id, state)) = store.registrations.remove(&req.ceremony) else {
        return Ok(failed("unknown or expired registration; start again"));
    };
    let key = match app.webauthn.finish_securitykey_registration(&req.credential, &state) {
        Ok(k) => k,
        Err(e) => return Ok(failed(e)),
    };
    // A credential ID belongs to one account only.
    if store.accounts.values().flat_map(|a| &a.keys).any(|k| k.cred_id() == key.cred_id()) {
        return Ok(failed("this credential is already registered"));
    }
    let account = store
        .accounts
        .entry(username.clone())
        .or_insert_with(|| Account { user_id, keys: Vec::new(), last_sign_in: None });
    account.keys.push(key);
    let keys = account.keys.len();
    Ok(Json(json!({ "ok": true, "username": username, "keys": keys })))
}

#[route(POST "/api/login/start")]
async fn login_start(cx: &Cx, Json(req): Json<Start>) -> Result<Json<Value>> {
    let username = req.username.trim().to_owned();
    let app = app(cx);
    let mut store = app.store.lock().expect("store lock");
    let Some(account) = store.accounts.get(&username) else {
        return Ok(failed("no such user; register a key first"));
    };
    // allowCredentials lists this user's keys: Jotakey's credentials are not discoverable.
    let (options, state) = match app.webauthn.start_securitykey_authentication(&account.keys) {
        Ok(r) => r,
        Err(e) => return Ok(failed(e)),
    };
    let ceremony = Uuid::new_v4();
    store.authentications.insert(ceremony, (username, state));
    Ok(Json(json!({ "ok": true, "ceremony": ceremony, "options": options })))
}

#[route(POST "/api/login/finish")]
async fn login_finish(cx: &Cx, Json(req): Json<Finish<PublicKeyCredential>>) -> Result<Json<Value>> {
    let app = app(cx);
    let (username, result) = {
        let mut store = app.store.lock().expect("store lock");
        let Some((username, state)) = store.authentications.remove(&req.ceremony) else {
            return Ok(failed("unknown or expired sign-in; start again"));
        };
        // Checks the challenge, origin, RP ID hash, UP flag, signature and counter.
        let result = match app.webauthn.finish_securitykey_authentication(&req.credential, &state) {
            Ok(r) => r,
            Err(e) => return Ok(failed(e)),
        };
        let Some(account) = store.accounts.get_mut(&username) else {
            return Ok(failed("account removed during sign-in"));
        };
        for key in &mut account.keys {
            key.update_credential(&result); // stores the new counter
        }
        account.last_sign_in = Some(SignIn { counter: result.counter(), user_verified: result.user_verified() });
        (username, result)
    };
    let new_session = session::start(cx).await?;
    app.store
        .lock()
        .expect("store lock")
        .sessions
        .insert(new_session.token_hash, (username.clone(), new_session.expires_at));
    Ok(Json(json!({ "ok": true, "username": username, "counter": result.counter() })))
}

#[route(POST "/logout")]
async fn logout(cx: &Cx) -> Result<SeeOther> {
    if let Some(hash) = session::stop(cx).await? {
        app(cx).store.lock().expect("store lock").sessions.remove(&hash);
    }
    Ok(see_other("/"))
}
