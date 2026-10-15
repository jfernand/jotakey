//! Relying-party checks, as a WebAuthn server would perform them (WebAuthn §7.1, §7.2).

use ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::cbor::Value;

/// `pubKeyCredParams` entry for ES256.
pub fn es256() -> Value {
    Value::Map(vec![(Value::t("alg"), Value::Int(-7)), (Value::t("type"), Value::t("public-key"))])
}

/// makeCredential parameters.
pub fn make_credential(rp: &str, client_data_hash: &[u8; 32], exclude: &[&[u8]]) -> Vec<u8> {
    let mut m = vec![
        (Value::Int(1), Value::Bytes(client_data_hash.to_vec())),
        (Value::Int(2), Value::Map(vec![(Value::t("id"), Value::t(rp)), (Value::t("name"), Value::t(rp))])),
        (
            Value::Int(3),
            Value::Map(vec![
                (Value::t("id"), Value::Bytes(b"user-1234".to_vec())),
                (Value::t("name"), Value::t("alice@example.com")),
                (Value::t("displayName"), Value::t("Alice")),
            ]),
        ),
        (Value::Int(4), Value::Array(vec![es256()])),
    ];
    if !exclude.is_empty() {
        m.push((Value::Int(5), Value::Array(exclude.iter().map(|id| descriptor(id)).collect())));
    }
    Value::Map(m).encode()
}

/// getAssertion parameters.
pub fn get_assertion(rp: &str, client_data_hash: &[u8; 32], allow: &[&[u8]]) -> Vec<u8> {
    Value::Map(vec![
        (Value::Int(1), Value::t(rp)),
        (Value::Int(2), Value::Bytes(client_data_hash.to_vec())),
        (Value::Int(3), Value::Array(allow.iter().map(|id| descriptor(id)).collect())),
    ])
    .encode()
}

fn descriptor(id: &[u8]) -> Value {
    Value::Map(vec![(Value::t("id"), Value::Bytes(id.to_vec())), (Value::t("type"), Value::t("public-key"))])
}

/// A registered credential as the relying party stores it.
#[derive(Clone, Debug)]
pub struct Registered {
    /// Credential ID.
    pub id: Vec<u8>,
    /// Public key.
    pub key: VerifyingKey,
    /// Signature counter at registration.
    pub counter: u32,
}

/// Verify a makeCredential response the way a relying party would.
pub fn verify_registration(rp: &str, cdh: &[u8; 32], body: &[u8]) -> Result<Registered, String> {
    let (resp, used) = Value::decode(body).ok_or("response is not CBOR")?;
    if used != body.len() {
        return Err("trailing bytes".into());
    }
    if resp.get(&Value::Int(1)) != Some(&Value::t("packed")) {
        return Err("fmt is not packed".into());
    }
    let ad = resp.get(&Value::Int(2)).and_then(Value::bytes).ok_or("no authData")?;
    if ad.len() < 55 {
        return Err("authData too short".into());
    }
    if ad[..32] != Sha256::digest(rp.as_bytes())[..] {
        return Err("rpIdHash mismatch".into());
    }
    if ad[32] & 0x01 == 0 || ad[32] & 0x40 == 0 {
        return Err("UP or AT flag missing".into());
    }
    let counter = u32::from_be_bytes(ad[33..37].try_into().map_err(|_| "counter")?);
    let id_len = usize::from(u16::from_be_bytes([ad[53], ad[54]]));
    let id = ad.get(55..55 + id_len).ok_or("credential id truncated")?.to_vec();
    let (cose, n) = Value::decode(&ad[55 + id_len..]).ok_or("COSE key")?;
    if 55 + id_len + n != ad.len() {
        return Err("trailing authData".into());
    }
    if cose.get(&Value::Int(1)) != Some(&Value::Int(2))
        || cose.get(&Value::Int(3)) != Some(&Value::Int(-7))
        || cose.get(&Value::Int(-1)) != Some(&Value::Int(1))
    {
        return Err("COSE key is not EC2/ES256/P-256".into());
    }
    let x = cose.get(&Value::Int(-2)).and_then(Value::bytes).ok_or("x")?;
    let y = cose.get(&Value::Int(-3)).and_then(Value::bytes).ok_or("y")?;
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| format!("bad point: {e}"))?;
    // Packed self-attestation: alg must match and sig verifies with the credential key.
    let att = resp.get(&Value::Int(3)).ok_or("no attStmt")?;
    if att.get(&Value::t("alg")) != Some(&Value::Int(-7)) {
        return Err("attStmt alg".into());
    }
    let sig = att.get(&Value::t("sig")).and_then(Value::bytes).ok_or("attStmt sig")?;
    verify_sig(&key, &[ad, cdh], sig)?;
    Ok(Registered { id, key, counter })
}

/// Verify a getAssertion response; returns the new counter.
pub fn verify_assertion(rp: &str, cdh: &[u8; 32], cred: &Registered, body: &[u8]) -> Result<u32, String> {
    let (resp, _) = Value::decode(body).ok_or("response is not CBOR")?;
    let id = resp.get(&Value::Int(1)).and_then(|c| c.get(&Value::t("id"))).and_then(Value::bytes);
    if id != Some(&cred.id[..]) {
        return Err("credential id mismatch".into());
    }
    let ad = resp.get(&Value::Int(2)).and_then(Value::bytes).ok_or("no authData")?;
    if ad.len() != 37 || ad[..32] != Sha256::digest(rp.as_bytes())[..] {
        return Err("authData malformed or wrong RP".into());
    }
    if ad[32] & 0x01 == 0 {
        return Err("UP flag missing".into());
    }
    let counter = u32::from_be_bytes(ad[33..37].try_into().map_err(|_| "counter")?);
    let sig = resp.get(&Value::Int(3)).and_then(Value::bytes).ok_or("no signature")?;
    verify_sig(&cred.key, &[ad, cdh], sig)?;
    Ok(counter)
}

fn verify_sig(key: &VerifyingKey, parts: &[&[u8]], sig: &[u8]) -> Result<(), String> {
    let sig = DerSignature::from_bytes(sig).map_err(|e| format!("signature not DER: {e}"))?;
    key.verify(&parts.concat(), &sig).map_err(|_| "signature does not verify".to_string())
}
