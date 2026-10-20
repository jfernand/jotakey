// (c) Javier Fernandez @ JotaSoft 2026
//! The DynamoDB backend, for running on AWS Lambda, where instances come and go and any of
//! them may serve a ceremony's finish request.
//!
//! One table, keyed by a string `pk`, with time-to-live on the `ttl` attribute:
//!
//! | `pk` | attributes |
//! |---|---|
//! | `account#<username>` | `user_id`, `created`, `keys` (JSON), `last_sign_in` (JSON), `version` |
//! | `credential#<credential ID>` | `username`: makes a credential ID belong to one account |
//! | `ceremony#<id>` | `kind`, `username`, `user_id`, `state` (JSON), `ttl` |
//! | `session#<token hash>` | `username`, `ttl` |
//!
//! DynamoDB deletes expired items only eventually, so every read checks `ttl` itself.
//! Account updates are conditional on `version` and retried, so concurrent sign-ins never
//! lose a counter.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::DisplayErrorContext;
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::types::{AttributeValue, Put, ReturnValue, TransactWriteItem};
use topcoat::session::TokenHash;
use webauthn_rs::prelude::*;

use super::{Account, AddKey, Ceremony, Error, Key, Result, apply_sign_in, now};

/// Attempts at an optimistic account update before giving up.
const ATTEMPTS: usize = 5;

type Item = HashMap<String, AttributeValue>;

pub struct Store {
    client: Client,
    table: String,
}

impl Store {
    /// Connect with the default AWS configuration (on Lambda: the function's role and region).
    pub async fn connect(table: String) -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Store { client: Client::new(&config), table }
    }

    pub async fn account(&self, username: &str) -> Result<Option<Account>> {
        Ok(self.load_account(username).await?.map(|(account, _)| account))
    }

    pub async fn begin(&self, id: Uuid, ceremony: Ceremony, expires: SystemTime) -> Result<()> {
        let mut item = Item::new();
        item.insert("pk".into(), s(format!("ceremony#{id}")));
        item.insert("ttl".into(), n(epoch(expires)));
        match ceremony {
            Ceremony::Registration { username, user_id, state } => {
                item.insert("kind".into(), s("registration"));
                item.insert("username".into(), s(username));
                item.insert("user_id".into(), s(user_id.to_string()));
                item.insert("state".into(), s(json(&state)?));
            }
            Ceremony::Authentication { username, state } => {
                item.insert("kind".into(), s("authentication"));
                item.insert("username".into(), s(username));
                item.insert("state".into(), s(json(&state)?));
            }
        }
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await
            .map_err(failed)?;
        Ok(())
    }

    pub async fn take(&self, id: Uuid) -> Result<Option<Ceremony>> {
        // One conditional-free delete that returns the old item: of two concurrent finish
        // requests, only one gets the state.
        let out = self
            .client
            .delete_item()
            .table_name(&self.table)
            .key("pk", s(format!("ceremony#{id}")))
            .return_values(ReturnValue::AllOld)
            .send()
            .await
            .map_err(failed)?;
        let Some(item) = out.attributes() else { return Ok(None) };
        if !live(item)? {
            return Ok(None);
        }
        let username = get_s(item, "username")?.to_owned();
        let state = get_s(item, "state")?;
        Ok(Some(match get_s(item, "kind")? {
            "registration" => Ceremony::Registration {
                username,
                user_id: uuid(get_s(item, "user_id")?)?,
                state: from_json(state)?,
            },
            "authentication" => Ceremony::Authentication { username, state: from_json(state)? },
            other => return Err(Error(format!("ceremony {id}: unknown kind {other:?}"))),
        }))
    }

    pub async fn add_key(&self, username: &str, user_id: Uuid, key: Key) -> Result<AddKey> {
        let credential = credential_pk(&key.key)?;
        for _ in 0..ATTEMPTS {
            let (mut account, version) = match self.load_account(username).await? {
                Some((account, version)) => (account, Some(version)),
                None => (Account { user_id, created: now(), keys: Vec::new(), last_sign_in: None }, None),
            };
            if account.user_id != user_id {
                return Ok(AddKey::Taken);
            }
            account.keys.push(key.clone());
            let claim = Put::builder()
                .table_name(&self.table)
                .item("pk", s(credential.clone()))
                .item("username", s(username))
                .condition_expression("attribute_not_exists(pk)")
                .build()
                .map_err(failed)?;
            match self.transact(vec![claim, self.account_put(username, &account, version)?]).await? {
                None => return Ok(AddKey::Added(account.keys.len())),
                Some(checks) if checks.first() == Some(&true) => return Ok(AddKey::Duplicate),
                // The account changed since we read it: read it again.
                Some(_) => {}
            }
        }
        Err(Error(format!("add_key: account {username:?} kept changing")))
    }

    pub async fn record_sign_in(&self, username: &str, result: &AuthenticationResult) -> Result<bool> {
        for _ in 0..ATTEMPTS {
            let Some((mut account, version)) = self.load_account(username).await? else { return Ok(false) };
            apply_sign_in(&mut account, result);
            let put = self.account_put(username, &account, Some(version))?;
            if self.transact(vec![put]).await?.is_none() {
                return Ok(true);
            }
            // The account changed since we read it: read it again.
        }
        Err(Error(format!("record_sign_in: account {username:?} kept changing")))
    }

    pub async fn start_session(&self, hash: &TokenHash, username: &str, expires: SystemTime) -> Result<()> {
        self.client
            .put_item()
            .table_name(&self.table)
            .item("pk", s(session_pk(hash)))
            .item("username", s(username))
            .item("ttl", n(epoch(expires)))
            .send()
            .await
            .map_err(failed)?;
        Ok(())
    }

    pub async fn session_user(&self, hash: &TokenHash) -> Result<Option<String>> {
        let Some(item) = self.get(session_pk(hash)).await? else { return Ok(None) };
        if !live(&item)? {
            return Ok(None);
        }
        Ok(Some(get_s(&item, "username")?.to_owned()))
    }

    pub async fn end_session(&self, hash: &TokenHash) -> Result<()> {
        self.client
            .delete_item()
            .table_name(&self.table)
            .key("pk", s(session_pk(hash)))
            .send()
            .await
            .map_err(failed)?;
        Ok(())
    }

    async fn get(&self, pk: String) -> Result<Option<Item>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("pk", s(pk))
            .consistent_read(true)
            .send()
            .await
            .map_err(failed)?;
        Ok(out.item)
    }

    /// Write `puts` all or none. `None` if they were written; otherwise which of them failed
    /// their condition.
    async fn transact(&self, puts: Vec<Put>) -> Result<Option<Vec<bool>>> {
        let count = puts.len();
        let items = puts.into_iter().map(|p| TransactWriteItem::builder().put(p).build()).collect();
        let Err(e) = self.client.transact_write_items().set_transact_items(Some(items)).send().await else {
            return Ok(None);
        };
        match e.into_service_error() {
            TransactWriteItemsError::TransactionCanceledException(c) => {
                let reasons = c.cancellation_reasons();
                let failed_checks: Vec<bool> = (0..count)
                    .map(|i| reasons.get(i).and_then(|r| r.code()) == Some("ConditionalCheckFailed"))
                    .collect();
                // Cancelled for another reason (a conflicting transaction, throttling).
                if !failed_checks.contains(&true) {
                    return Err(failed(c));
                }
                Ok(Some(failed_checks))
            }
            e => Err(failed(e)),
        }
    }

    /// The account and its version, for a conditional update.
    async fn load_account(&self, username: &str) -> Result<Option<(Account, u64)>> {
        let Some(item) = self.get(account_pk(username)).await? else { return Ok(None) };
        let keys = get_s(&item, "keys")?;
        // Accounts written before keys had their own record hold bare SecurityKeys.
        let keys = match from_json::<Vec<Key>>(keys) {
            Ok(keys) => keys,
            Err(e) => match from_json::<Vec<SecurityKey>>(keys) {
                Ok(bare) => bare
                    .into_iter()
                    .map(|key| Key { key, registered: 0, sign_ins: 0, last_used: None, aaguid: None, unread: None })
                    .collect(),
                Err(_) => return Err(e),
            },
        };
        let account = Account {
            user_id: uuid(get_s(&item, "user_id")?)?,
            created: if item.contains_key("created") { get_n(&item, "created")? } else { 0 },
            keys,
            last_sign_in: match item.get("last_sign_in") {
                Some(_) => Some(from_json(get_s(&item, "last_sign_in")?)?),
                None => None,
            },
        };
        Ok(Some((account, get_n(&item, "version")?)))
    }

    /// A put of the whole account item that succeeds only if the stored version is still
    /// `version` (`None`: only if there is no account yet).
    fn account_put(&self, username: &str, account: &Account, version: Option<u64>) -> Result<Put> {
        let next = version.map_or(Some(1), |v| v.checked_add(1)).ok_or_else(|| Error("version overflow".into()))?;
        let mut put = Put::builder()
            .table_name(&self.table)
            .item("pk", s(account_pk(username)))
            .item("user_id", s(account.user_id.to_string()))
            .item("created", n(account.created))
            .item("keys", s(json(&account.keys)?))
            .item("version", n(next));
        if let Some(last) = &account.last_sign_in {
            put = put.item("last_sign_in", s(json(last)?));
        }
        put = match version {
            Some(v) => put.condition_expression("version = :v").expression_attribute_values(":v", n(v)),
            None => put.condition_expression("attribute_not_exists(pk)"),
        };
        put.build().map_err(failed)
    }
}

fn account_pk(username: &str) -> String {
    format!("account#{username}")
}

fn session_pk(hash: &TokenHash) -> String {
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("session#{hex}")
}

/// The credential ID, base64url, as webauthn-rs serialises it.
fn credential_pk(key: &SecurityKey) -> Result<String> {
    match serde_json::to_value(key.cred_id()) {
        Ok(serde_json::Value::String(id)) => Ok(format!("credential#{id}")),
        other => Err(Error(format!("credential ID did not serialise to a string: {other:?}"))),
    }
}

/// Whether an item with a `ttl` has not expired yet.
fn live(item: &Item) -> Result<bool> {
    Ok(get_n::<u64>(item, "ttl")? > epoch(SystemTime::now()))
}

fn epoch(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn s(value: impl Into<String>) -> AttributeValue {
    AttributeValue::S(value.into())
}

fn n(value: impl ToString) -> AttributeValue {
    AttributeValue::N(value.to_string())
}

fn get_s<'a>(item: &'a Item, name: &str) -> Result<&'a str> {
    match item.get(name) {
        Some(AttributeValue::S(v)) => Ok(v),
        _ => Err(Error(format!("item attribute {name:?}: missing or not a string"))),
    }
}

fn get_n<T: std::str::FromStr>(item: &Item, name: &str) -> Result<T> {
    match item.get(name) {
        Some(AttributeValue::N(v)) => v.parse().map_err(|_| Error(format!("item attribute {name:?}: bad number"))),
        _ => Err(Error(format!("item attribute {name:?}: missing or not a number"))),
    }
}

fn uuid(value: &str) -> Result<Uuid> {
    Uuid::parse_str(value).map_err(failed)
}

fn json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(failed)
}

fn from_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(failed)
}

fn failed(e: impl std::error::Error) -> Error {
    Error(DisplayErrorContext(e).to_string())
}
