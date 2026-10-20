// (c) Javier Fernandez @ JotaSoft 2026
//! The in-memory backend: one process, one mutex, nothing kept when the server stops.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use topcoat::session::TokenHash;
use webauthn_rs::prelude::*;

use super::{Account, AddKey, Ceremony, Key, RemoveKey, apply_sign_in, now, without_key};

#[derive(Default)]
pub struct Store(Mutex<Inner>);

#[derive(Default)]
struct Inner {
    accounts: HashMap<String, Account>,
    /// Ceremonies in progress, by ID, with their expiry.
    ceremonies: HashMap<Uuid, (Ceremony, SystemTime)>,
    /// Signed-in sessions: token hash -> (username, user handle, expiry).
    sessions: HashMap<TokenHash, (String, Uuid, SystemTime)>,
}

impl Store {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().expect("store lock")
    }

    pub fn account(&self, username: &str) -> Option<Account> {
        self.lock().accounts.get(username).map(|a| Account {
            user_id: a.user_id,
            created: a.created,
            keys: a.keys.clone(),
            last_sign_in: a.last_sign_in.clone(),
        })
    }

    pub fn begin(&self, id: Uuid, ceremony: Ceremony, expires: SystemTime) {
        let mut inner = self.lock();
        // Abandoned ceremonies go when the next one starts.
        let now = SystemTime::now();
        inner.ceremonies.retain(|_, (_, expires)| *expires > now);
        inner.ceremonies.insert(id, (ceremony, expires));
    }

    pub fn take(&self, id: Uuid) -> Option<Ceremony> {
        let (ceremony, expires) = self.lock().ceremonies.remove(&id)?;
        (expires > SystemTime::now()).then_some(ceremony)
    }

    pub fn add_key(&self, username: &str, user_id: Uuid, key: Key) -> AddKey {
        let mut inner = self.lock();
        if inner.accounts.values().flat_map(|a| &a.keys).any(|k| k.key.cred_id() == key.key.cred_id()) {
            return AddKey::Duplicate;
        }
        let account = inner.accounts.entry(username.to_owned()).or_insert_with(|| Account {
            user_id,
            created: now(),
            keys: Vec::new(),
            last_sign_in: None,
        });
        if account.user_id != user_id {
            return AddKey::Taken;
        }
        account.keys.push(key);
        AddKey::Added(account.keys.len())
    }

    pub fn remove_key(&self, username: &str, user_id: Uuid, credential: &str) -> RemoveKey {
        let mut inner = self.lock();
        let Some(account) = inner.accounts.get_mut(username).filter(|a| a.user_id == user_id) else {
            return RemoveKey::NotFound;
        };
        if without_key(account, credential).is_none() {
            return RemoveKey::NotFound;
        }
        if account.keys.is_empty() {
            inner.accounts.remove(username);
            return RemoveKey::AccountDeleted;
        }
        RemoveKey::Removed(account.keys.len())
    }

    pub fn usernames(&self) -> Vec<String> {
        self.lock().accounts.keys().cloned().collect()
    }

    pub fn record_sign_in(&self, username: &str, user_id: Uuid, result: &AuthenticationResult) -> bool {
        let mut inner = self.lock();
        let Some(account) = inner.accounts.get_mut(username).filter(|a| a.user_id == user_id) else { return false };
        apply_sign_in(account, result)
    }

    pub fn start_session(&self, hash: &TokenHash, username: &str, user_id: Uuid, expires: SystemTime) {
        let mut inner = self.lock();
        let now = SystemTime::now();
        inner.sessions.retain(|_, (_, _, expires)| *expires > now);
        inner.sessions.insert(hash.clone(), (username.to_owned(), user_id, expires));
    }

    pub fn session_user(&self, hash: &TokenHash) -> Option<(String, Uuid)> {
        self.lock()
            .sessions
            .get(hash)
            .filter(|(_, _, expires)| *expires > SystemTime::now())
            .map(|(user, user_id, _)| (user.clone(), *user_id))
    }

    pub fn end_session(&self, hash: &TokenHash) {
        self.lock().sessions.remove(hash);
    }
}
