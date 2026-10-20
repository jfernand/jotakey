// (c) Javier Fernandez @ JotaSoft 2026
//! Which authenticator a key is, as far as the server can tell: the AAGUID it reported at
//! registration, and for a Jotakey the shape of its credential ID.
//!
//! None of this is proof. Jotakey uses self-attestation, so its AAGUID is a claim any
//! authenticator could copy; it names the model for the page, and no check relies on it.

use std::collections::BTreeMap;

use serde_cbor_2::Value;
use webauthn_rs::prelude::Uuid;

/// Jotakey AAGUIDs are ASCII: "jotakey-", the model (e.g. "v01-c6", NUL-padded), then a
/// version byte (`jotakey_core::AAGUID`).
const JOTAKEY_PREFIX: &[u8] = b"jotakey-";

/// A Jotakey credential ID: 0x01 ‖ nonce (32) ‖ tag (16) (AGENTS.md section 3).
const JOTAKEY_CREDENTIAL_LEN: usize = 49;
const JOTAKEY_CREDENTIAL_VERSION: u8 = 0x01;

/// authData: rpIdHash (32) ‖ flags (1) ‖ signCount (4) ‖ AAGUID (16) ‖ ...
const AAGUID_AT: usize = 37;
const FLAG_ATTESTED: u8 = 0x40;

/// The AAGUID in a registration's attestation object (the CBOR map with `authData`), if the
/// authenticator data carries attested credential data.
pub fn aaguid(attestation_object: &[u8]) -> Option<Uuid> {
    let map: BTreeMap<String, Value> = serde_cbor_2::from_slice(attestation_object).ok()?;
    let Some(Value::Bytes(auth_data)) = map.get("authData") else { return None };
    let flags = *auth_data.get(32)?;
    if flags & FLAG_ATTESTED == 0 {
        return None;
    }
    let bytes: [u8; 16] = auth_data.get(AAGUID_AT..AAGUID_AT + 16)?.try_into().ok()?;
    Some(Uuid::from_bytes(bytes))
}

/// The Jotakey model an AAGUID names, e.g. "v01-c6"; None if it is not a Jotakey's.
pub fn jotakey_model(aaguid: &Uuid) -> Option<String> {
    let rest = aaguid.as_bytes().strip_prefix(JOTAKEY_PREFIX)?;
    let model: String = rest.iter().take_while(|&&b| b.is_ascii_graphic()).map(|&b| char::from(b)).collect();
    Some(model)
}

/// Whether a credential ID has a Jotakey's shape.
pub fn jotakey_credential(id: &[u8]) -> bool {
    id.len() == JOTAKEY_CREDENTIAL_LEN && id.first() == Some(&JOTAKEY_CREDENTIAL_VERSION)
}

/// Is this key a Jotakey? Yes by its AAGUID, probably by its credential ID when the browser
/// hid the AAGUID.
pub enum Verdict {
    Jotakey(String),
    ProbablyJotakey,
    Other,
}

pub fn verdict(aaguid: Option<&Uuid>, credential_id: &[u8]) -> Verdict {
    match aaguid.and_then(jotakey_model) {
        Some(model) => Verdict::Jotakey(model),
        None if aaguid.is_none_or(Uuid::is_nil) && jotakey_credential(credential_id) => Verdict::ProbablyJotakey,
        None => Verdict::Other,
    }
}

/// A line for the page.
pub fn describe(aaguid: Option<&Uuid>, credential_id: &[u8]) -> String {
    match (verdict(aaguid, credential_id), aaguid) {
        (Verdict::Jotakey(model), _) if model.is_empty() => "Jotakey".into(),
        (Verdict::Jotakey(model), _) => format!("Jotakey {model}"),
        (Verdict::ProbablyJotakey, _) => "probably a Jotakey (its credential ID format; the model was not reported)".into(),
        (Verdict::Other, None) => "not recorded".into(),
        (Verdict::Other, Some(id)) if id.is_nil() => "not reported (AAGUID all zeros)".into(),
        (Verdict::Other, Some(id)) => format!("AAGUID {id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// jotakey_core::AAGUID, the ESP32-C6 build.
    const C6: [u8; 16] = *b"jotakey-v01-c6\x00\x01";

    fn attestation_object(flags: u8, aaguid: [u8; 16]) -> Vec<u8> {
        let mut auth_data = vec![0u8; 32];
        auth_data.push(flags);
        auth_data.extend([0, 0, 0, 7]);
        auth_data.extend(aaguid);
        auth_data.extend([0, 0]);
        let map: BTreeMap<String, Value> = [
            ("fmt".to_owned(), Value::Text("none".into())),
            ("attStmt".to_owned(), Value::Map(BTreeMap::new())),
            ("authData".to_owned(), Value::Bytes(auth_data)),
        ]
        .into();
        serde_cbor_2::to_vec(&map).unwrap()
    }

    #[test]
    fn reads_the_aaguid() {
        assert_eq!(aaguid(&attestation_object(0x41, C6)), Some(Uuid::from_bytes(C6)));
        assert_eq!(aaguid(&attestation_object(0x01, C6)), None, "no attested credential data");
        assert_eq!(aaguid(b"not cbor"), None);
    }

    #[test]
    fn names_the_model() {
        let c6 = Uuid::from_bytes(C6);
        assert_eq!(jotakey_model(&c6).as_deref(), Some("v01-c6"));
        assert_eq!(describe(Some(&c6), &[0; 20]), "Jotakey v01-c6");
        let mut jotakey_id = vec![0x01];
        jotakey_id.extend([0xaa; 48]);
        assert!(describe(Some(&Uuid::nil()), &jotakey_id).starts_with("probably a Jotakey"));
        assert!(describe(None, &jotakey_id).starts_with("probably a Jotakey"));
        assert_eq!(describe(Some(&Uuid::nil()), &[0; 20]), "not reported (AAGUID all zeros)");
        let other = Uuid::parse_str("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4").unwrap();
        assert_eq!(describe(Some(&other), &jotakey_id), "AAGUID ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4");
    }
}
