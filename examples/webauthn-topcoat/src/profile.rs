// (c) Javier Fernandez @ JotaSoft 2026
//! Everything the server stores about a signed-in user, as labelled rows for the page.

use webauthn_rs::prelude::*;

use crate::model;
use crate::store::{Account, Key, credential_id};

/// A titled list of (label, value) rows.
pub struct Section {
    pub title: String,
    pub rows: Vec<(&'static str, String)>,
}

pub fn sections(username: &str, account: &Account) -> Vec<Section> {
    let mut out = vec![Section {
        title: "Account".into(),
        rows: vec![
            ("Username", username.to_owned()),
            ("User handle", format!("{} (random: what the key stores instead of your name)", account.user_id)),
            ("Created", when(account.created)),
            ("Registered keys", account.keys.len().to_string()),
        ],
    }];
    if let Some(last) = &account.last_sign_in {
        let used = account.keys.iter().position(|k| credential_id(k.key.cred_id()) == last.credential);
        let with = match used {
            Some(i) => format!("key {} ({})", i + 1, short(&last.credential)),
            None => short(&last.credential),
        };
        out.push(Section {
            title: "This sign-in".into(),
            rows: vec![
                ("When", when(last.at)),
                ("With", with),
                ("Signature counter", counter(last.counter)),
                ("User verified", verified(last.user_verified)),
                ("Backed up", yes_no(last.backup_state).into()),
            ],
        });
    }
    for (i, key) in account.keys.iter().enumerate() {
        out.push(Section { title: format!("Key {}", i + 1), rows: key_rows(key) });
    }
    out
}

/// "Signed in with a Jotakey", if the key used for the latest sign-in is one.
pub fn signed_in_with_jotakey(account: &Account) -> Option<String> {
    let last = account.last_sign_in.as_ref()?;
    let key = account.keys.iter().find(|k| credential_id(k.key.cred_id()) == last.credential)?;
    match model::verdict(key.aaguid.as_ref(), key.key.cred_id().as_ref()) {
        model::Verdict::Jotakey(m) if m.is_empty() => Some("You signed in with a Jotakey.".into()),
        model::Verdict::Jotakey(m) => Some(format!("You signed in with a Jotakey ({m}).")),
        model::Verdict::ProbablyJotakey => Some("You signed in with what looks like a Jotakey.".into()),
        model::Verdict::Other => None,
    }
}

fn key_rows(key: &Key) -> Vec<(&'static str, String)> {
    let cred = Credential::from(key.key.clone());
    let kind = if cred.backup_eligible {
        "synced passkey: the provider may copy it to your other devices"
    } else {
        "device-bound: it never leaves the authenticator"
    };
    vec![
        ("Model", model::describe(key.aaguid.as_ref(), key.unread.as_deref(), cred.cred_id.as_ref())),
        ("Credential ID", credential_id(&cred.cred_id)),
        ("Kind", kind.into()),
        ("Backed up", yes_no(cred.backup_state).into()),
        ("Transports", transports(&cred)),
        ("Algorithm", format!("{:?}", key.key.cred_algorithm())),
        ("Discoverable", discoverable(&cred)),
        ("Verified at registration", verified(cred.user_verified)),
        ("PIN required", pin(crate::pin_required(&key.key))),
        ("Attestation", format!("{:?}", cred.attestation_format).to_lowercase()),
        ("Registered", when(key.registered)),
        ("Last used", key.last_used.map_or_else(|| "never".into(), when)),
        ("Sign-ins", key.sign_ins.to_string()),
        ("Signature counter", counter(cred.counter)),
    ]
}

/// How the browser said it reached the authenticator at registration (usb, nfc, ble,
/// internal, hybrid); passed back at sign-in so it looks in the right place.
fn transports(cred: &Credential) -> String {
    let names: Vec<String> = cred
        .transports
        .iter()
        .flatten()
        .filter_map(|t| match serde_json::to_value(t) {
            Ok(serde_json::Value::String(name)) => Some(name),
            _ => None,
        })
        .collect();
    if names.is_empty() { "not reported".into() } else { names.join(", ") }
}

/// The credProps extension: the browser's (unsigned) word on whether the key stored the
/// credential, so it can sign in without a username.
fn discoverable(cred: &Credential) -> String {
    let rk = serde_json::to_value(&cred.extensions.cred_props)
        .ok()
        .and_then(|v| v.get("Set").and_then(|s| s.get("rk")).and_then(serde_json::Value::as_bool));
    match rk {
        Some(true) => "yes, the browser says".into(),
        Some(false) => "no, the browser says".into(),
        None => "not reported".into(),
    }
}

fn counter(n: u32) -> String {
    if n == 0 { "0 (this authenticator keeps no counter)".into() } else { n.to_string() }
}

fn verified(uv: bool) -> String {
    if uv { "yes: PIN, fingerprint or face".into() } else { "no: presence only".into() }
}

fn pin(required: bool) -> String {
    if required {
        "yes: every sign-in must verify you (PIN, fingerprint or face)".into()
    } else {
        "no: a touch is enough".into()
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn short(id: &str) -> String {
    match id.get(..12) {
        Some(head) if id.len() > 12 => format!("{head}…"),
        _ => id.to_owned(),
    }
}

/// Seconds since 1970 as a UTC date and time; 0 means not recorded.
fn when(t: u64) -> String {
    if t == 0 {
        return "not recorded".into();
    }
    let (days, secs) = (t / 86_400, t % 86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", secs / 3600, secs % 3600 / 60)
}

/// Days since 1970-01-01 to a Gregorian (year, month, day): Howard Hinnant's algorithm.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(when(0), "not recorded");
        assert_eq!(when(1), "1970-01-01 00:00 UTC");
        assert_eq!(when(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(when(1_792_502_500), "2026-10-20 13:21 UTC");
    }

    #[test]
    fn short_ids() {
        assert_eq!(short("abc"), "abc");
        assert_eq!(short("0123456789abcdef"), "0123456789ab…");
    }
}
