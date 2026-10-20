// (c) Javier Fernandez @ JotaSoft 2026
//! Where the relying party keeps its state: accounts and their keys, ceremonies in progress,
//! and signed-in sessions.
//!
//! Two backends with the same operations: [`memory`] (one process; everything vanishes when
//! it stops) and, with the `dynamodb` feature, [`dynamo`] (shared by every Lambda instance).
//! Each operation is safe against concurrent requests on its own, so the routes never hold
//! a lock across two of them.

use std::fmt;
use std::time::{Duration, SystemTime};

use topcoat::session::TokenHash;
use webauthn_rs::prelude::*;

#[cfg(feature = "dynamodb")]
pub mod dynamo;
pub mod memory;

/// How long a ceremony may take between its start and finish requests.
pub const CEREMONY_LIFETIME: Duration = Duration::from_secs(5 * 60);

pub struct Account {
    /// The WebAuthn user handle: random, never the username.
    pub user_id: Uuid,
    pub keys: Vec<SecurityKey>,
    pub last_sign_in: Option<SignIn>,
}

#[derive(Clone, Copy)]
pub struct SignIn {
    pub counter: u32,
    pub user_verified: bool,
}

/// A ceremony between its start and finish requests: the server's half of the challenge.
pub enum Ceremony {
    Registration { username: String, user_id: Uuid, state: SecurityKeyRegistration },
    Authentication { username: String, state: SecurityKeyAuthentication },
}

pub enum AddKey {
    /// The key was added; the account now has this many.
    Added(usize),
    /// The username belongs to another user handle.
    Taken,
    /// The credential ID is already registered, to this account or another.
    Duplicate,
}

/// The backend failed (unreachable, throttled, corrupt item). The message is for the log,
/// never for the client.
#[derive(Debug)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub enum Store {
    Memory(memory::Store),
    #[cfg(feature = "dynamodb")]
    Dynamo(dynamo::Store),
}

impl Store {
    /// Whether the state outlives the process.
    pub fn persistent(&self) -> bool {
        !matches!(self, Store::Memory(_))
    }

    pub async fn account(&self, username: &str) -> Result<Option<Account>> {
        match self {
            Store::Memory(s) => Ok(s.account(username)),
            #[cfg(feature = "dynamodb")]
            Store::Dynamo(s) => s.account(username).await,
        }
    }

    /// Keep a ceremony until [`take`](Self::take) or [`CEREMONY_LIFETIME`], whichever is first.
    pub async fn begin(&self, id: Uuid, ceremony: Ceremony) -> Result<()> {
        let expires = SystemTime::now() + CEREMONY_LIFETIME;
        match self {
            Store::Memory(s) => {
                s.begin(id, ceremony, expires);
                Ok(())
            }
            #[cfg(feature = "dynamodb")]
            Store::Dynamo(s) => s.begin(id, ceremony, expires).await,
        }
    }

    /// Remove a ceremony and return it if it has not expired. Each ceremony is taken once,
    /// whatever the outcome, so a challenge never verifies twice.
    pub async fn take(&self, id: Uuid) -> Result<Option<Ceremony>> {
        match self {
            Store::Memory(s) => Ok(s.take(id)),
            #[cfg(feature = "dynamodb")]
            Store::Dynamo(s) => s.take(id).await,
        }
    }

    /// Add a verified key to `username`, creating the account with `user_id` if it is new.
    pub async fn add_key(&self, username: &str, user_id: Uuid, key: SecurityKey) -> Result<AddKey> {
        match self {
            Store::Memory(s) => Ok(s.add_key(username, user_id, key)),
            #[cfg(feature = "dynamodb")]
            Store::Dynamo(s) => s.add_key(username, user_id, key).await,
        }
    }

    /// Record a verified sign-in: the key's new counter and the sign-in shown on the page.
    /// `false` if the account no longer exists.
    pub async fn record_sign_in(&self, username: &str, result: &AuthenticationResult) -> Result<bool> {
        match self {
            Store::Memory(s) => Ok(s.record_sign_in(username, result)),
            #[cfg(feature = "dynamodb")]
            Store::Dynamo(s) => s.record_sign_in(username, result).await,
        }
    }

    pub async fn start_session(&self, hash: &TokenHash, username: &str, expires: SystemTime) -> Result<()> {
        match self {
            Store::Memory(s) => {
                s.start_session(hash, username, expires);
                Ok(())
            }
            #[cfg(feature = "dynamodb")]
            Store::Dynamo(s) => s.start_session(hash, username, expires).await,
        }
    }

    /// The session's username, if it exists and has not expired.
    pub async fn session_user(&self, hash: &TokenHash) -> Result<Option<String>> {
        match self {
            Store::Memory(s) => Ok(s.session_user(hash)),
            #[cfg(feature = "dynamodb")]
            Store::Dynamo(s) => s.session_user(hash).await,
        }
    }

    pub async fn end_session(&self, hash: &TokenHash) -> Result<()> {
        match self {
            Store::Memory(s) => {
                s.end_session(hash);
                Ok(())
            }
            #[cfg(feature = "dynamodb")]
            Store::Dynamo(s) => s.end_session(hash).await,
        }
    }
}

/// Apply a verified sign-in to an account's keys and last sign-in. Counters only go up
/// (`update_credential` ignores a lower one), so applying it again after a lost race is safe.
fn apply_sign_in(account: &mut Account, result: &AuthenticationResult) {
    for key in &mut account.keys {
        key.update_credential(result);
    }
    account.last_sign_in = Some(SignIn { counter: result.counter(), user_verified: result.user_verified() });
}
