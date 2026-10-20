// (c) Javier Fernandez @ JotaSoft 2026
//! Which authenticator a key is, as far as the server can tell: the AAGUID it reported at
//! registration, and for a Jotakey the shape of its credential ID.
//!
//! The attestation object is read with Jotakey's own CBOR decoder (`jotakey_core::cbor`),
//! the one the key runs. It accepts only CTAP2 canonical CBOR, so a browser that re-encodes
//! the object differently is caught, and the page says so.
//!
//! None of this is proof. Jotakey uses self-attestation, so its AAGUID is a claim any
//! authenticator could copy; it names the model for the page, and no check relies on it.

use jotakey_core::cbor::{CborError, Decoder, Key};
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

/// Why the attestation object gave no AAGUID.
#[derive(Debug, PartialEq, Eq)]
pub enum Unread {
    /// Jotakey's decoder rejected the CBOR.
    BadCbor(CborError),
    /// Well-formed, but no `authData` byte string.
    NoAuthData,
}

/// The AAGUID in a registration's attestation object (a CBOR map with `fmt`, `attStmt` and
/// `authData`). `Ok(None)` if the authenticator data has no attested credential data.
pub fn aaguid(attestation_object: &[u8]) -> Result<Option<Uuid>, Unread> {
    let auth_data = auth_data(attestation_object).map_err(Unread::BadCbor)?.ok_or(Unread::NoAuthData)?;
    let Some(&flags) = auth_data.get(32) else { return Err(Unread::NoAuthData) };
    if flags & FLAG_ATTESTED == 0 {
        return Ok(None);
    }
    let bytes = auth_data.get(AAGUID_AT..AAGUID_AT + 16).ok_or(Unread::NoAuthData)?;
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| Unread::NoAuthData)?;
    Ok(Some(Uuid::from_bytes(bytes)))
}

/// The `authData` byte string. Every other value is skipped, but still checked as strictly.
fn auth_data(object: &[u8]) -> Result<Option<&[u8]>, CborError> {
    let mut decoder = Decoder::new(object);
    let mut map = decoder.map()?;
    let mut found = None;
    while let Some(key) = decoder.next_key(&mut map)? {
        match key {
            Key::Text("authData") => found = Some(decoder.bytes()?),
            _ => decoder.skip(1)?,
        }
    }
    decoder.finish()?;
    Ok(found)
}

/// What a CBOR rule violation means, for the page.
pub fn cbor_problem(e: CborError) -> &'static str {
    match e {
        CborError::Truncated => "it ends in the middle of an item",
        CborError::NonMinimal => "a number is not in its shortest encoding",
        CborError::Indefinite => "it uses indefinite lengths",
        CborError::Malformed => "it uses a reserved header value",
        CborError::Unsupported => "it contains a tag, a float or another value CTAP never uses",
        CborError::InvalidUtf8 => "a text string is not valid UTF-8",
        CborError::TooDeep => "it nests more than 4 levels deep",
        CborError::NonCanonicalMap => "its map keys are not in canonical order",
        CborError::BadKeyType => "a map key is neither a number nor text",
        CborError::UnexpectedType => "an item has the wrong type",
        CborError::TrailingBytes => "there are bytes after its end",
        CborError::BufferFull => "it is too large",
    }
}

/// The message for a registration whose attestation object Jotakey's decoder could not read.
pub fn unread_message(why: &Unread) -> String {
    match why {
        Unread::BadCbor(e) => format!(
            "Hmm, it looks like your browser just sent bad CBOR: {}. Jotakey's strict decoder \
             rejects that, so the model is unknown.",
            cbor_problem(*e)
        ),
        Unread::NoAuthData => "Hmm, your browser's attestation object has no authenticator data, \
                               so the model is unknown."
            .into(),
    }
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

/// A line for the page. `unread` is why the AAGUID could not be read at registration.
pub fn describe(aaguid: Option<&Uuid>, unread: Option<&str>, credential_id: &[u8]) -> String {
    match (verdict(aaguid, credential_id), aaguid, unread) {
        (Verdict::Jotakey(model), _, _) if model.is_empty() => "Jotakey".into(),
        (Verdict::Jotakey(model), _, _) => format!("Jotakey {model}"),
        (Verdict::ProbablyJotakey, _, _) => {
            "probably a Jotakey (its credential ID format; the model was not reported)".into()
        }
        (Verdict::Other, None, Some(why)) => format!("unknown: {why}"),
        (Verdict::Other, None, None) => "not recorded".into(),
        (Verdict::Other, Some(id), _) if id.is_nil() => "not reported (AAGUID all zeros)".into(),
        (Verdict::Other, Some(id), _) => format!("AAGUID {id}"),
    }
}

#[cfg(test)]
mod tests {
    use jotakey_core::cbor::Encoder;

    use super::*;

    /// jotakey_core::AAGUID, the ESP32-C6 build.
    const C6: [u8; 16] = *b"jotakey-v01-c6\x00\x01";

    fn auth_data(flags: u8, aaguid: [u8; 16]) -> Vec<u8> {
        let mut auth_data = vec![0u8; 32];
        auth_data.push(flags);
        auth_data.extend([0, 0, 0, 7]);
        auth_data.extend(aaguid);
        auth_data.extend([0, 0]);
        auth_data
    }

    /// A canonical attestation object: keys sorted shortest first ("fmt", "attStmt", "authData").
    fn canonical(auth_data: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let mut e = Encoder::new(&mut buf);
        e.map(3).unwrap();
        e.text("fmt").unwrap();
        e.text("none").unwrap();
        e.text("attStmt").unwrap();
        e.map(0).unwrap();
        e.text("authData").unwrap();
        e.bytes(auth_data).unwrap();
        let n = e.len();
        buf[..n].to_vec()
    }

    #[test]
    fn reads_the_aaguid() {
        assert_eq!(aaguid(&canonical(&auth_data(0x41, C6))), Ok(Some(Uuid::from_bytes(C6))));
        assert_eq!(aaguid(&canonical(&auth_data(0x01, C6))), Ok(None), "no attested credential data");
        assert_eq!(aaguid(&canonical(&[0; 10])), Err(Unread::NoAuthData));
    }

    #[test]
    fn rejects_non_canonical_cbor() {
        let mut object = canonical(&auth_data(0x41, C6));
        assert_eq!(aaguid(&[0x01]), Err(Unread::BadCbor(CborError::UnexpectedType)), "not a map");
        assert_eq!(aaguid(b"not cbor"), Err(Unread::BadCbor(CborError::Truncated)));
        // Keys in the order many encoders write them, not canonical CTAP2 order.
        let mut buf = [0u8; 256];
        let mut e = Encoder::new(&mut buf);
        e.map(3).unwrap();
        e.text("authData").unwrap();
        e.bytes(&auth_data(0x41, C6)).unwrap();
        e.text("fmt").unwrap();
        e.text("none").unwrap();
        e.text("attStmt").unwrap();
        e.map(0).unwrap();
        let n = e.len();
        assert_eq!(aaguid(&buf[..n]), Err(Unread::BadCbor(CborError::NonCanonicalMap)));
        object.push(0);
        assert_eq!(aaguid(&object), Err(Unread::BadCbor(CborError::TrailingBytes)));
        assert!(unread_message(&Unread::BadCbor(CborError::NonCanonicalMap)).starts_with(
            "Hmm, it looks like your browser just sent bad CBOR: its map keys are not in canonical order."
        ));
    }

    #[test]
    fn names_the_model() {
        let c6 = Uuid::from_bytes(C6);
        assert_eq!(jotakey_model(&c6).as_deref(), Some("v01-c6"));
        assert_eq!(describe(Some(&c6), None, &[0; 20]), "Jotakey v01-c6");
        let mut jotakey_id = vec![0x01];
        jotakey_id.extend([0xaa; 48]);
        assert!(describe(Some(&Uuid::nil()), None, &jotakey_id).starts_with("probably a Jotakey"));
        assert!(describe(None, None, &jotakey_id).starts_with("probably a Jotakey"));
        assert_eq!(describe(Some(&Uuid::nil()), None, &[0; 20]), "not reported (AAGUID all zeros)");
        assert_eq!(describe(None, Some("bad CBOR"), &[0; 20]), "unknown: bad CBOR");
        let other = Uuid::parse_str("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4").unwrap();
        assert_eq!(describe(Some(&other), None, &jotakey_id), "AAGUID ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4");
    }
}
