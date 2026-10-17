// (c) Javier Fernandez @ JotaSoft 2026
//! authenticatorGetAssertion (CTAP 2.0 §5.2), non-resident credentials only.
//!
//! **Deliberate deviation:** `up: false` (silent assertion) is refused with
//! `CTAP2_ERR_UNSUPPORTED_OPTION`. Every signature this device produces carries a fresh
//! touch (invariant 1), even if a relying party forgets to check the UP flag.

use super::parse::{self, PARAM_DEPTH};
use super::{Pending, PlatformTagger, Response, credential_seed, write_success};
use crate::authdata::{self, FLAG_UP};
use crate::cbor::{Decoder, Key};
use crate::credential::{self, CRED_ID_LEN, NONCE_LEN};
use crate::crypto;
use crate::platform::Platform;
use crate::status::Status;

struct Request<'a> {
    rp_id_hash: [u8; 32],
    client_data_hash: [u8; 32],
    allow_list: Option<&'a [u8]>,
    options: parse::Options,
    pin_auth: Option<&'a [u8]>,
}

fn parse(params: &[u8]) -> Result<Request<'_>, Status> {
    let mut d = Decoder::new(params);
    let mut m = d.map()?;
    let mut rp_id_hash = None;
    let mut cdh = None;
    let mut allow_list = None;
    let mut options = parse::Options::default();
    let mut pin_auth = None;
    while let Some(k) = d.next_key(&mut m)? {
        match k {
            Key::Int(0x01) => rp_id_hash = Some(crypto::sha256(&[d.text()?.as_bytes()])),
            Key::Int(0x02) => cdh = Some(parse::hash32(&mut d)?),
            Key::Int(0x03) => allow_list = Some(parse::descriptor_list(&mut d)?),
            Key::Int(0x04) => parse::extensions(&mut d)?,
            Key::Int(0x05) => options = parse::options(&mut d)?,
            Key::Int(0x06) => pin_auth = Some(d.bytes()?),
            Key::Int(0x07) => {
                d.unsigned()?;
            }
            _ => d.skip(PARAM_DEPTH)?,
        }
    }
    d.finish()?;
    let (Some(rp_id_hash), Some(client_data_hash)) = (rp_id_hash, cdh) else {
        return Err(Status::MissingParameter);
    };
    Ok(Request { rp_id_hash, client_data_hash, allow_list, options, pin_auth })
}

/// Validate the request, find our credential in the allow list, and park it.
pub fn process<P: Platform>(platform: &mut P, params: &[u8]) -> Result<Pending, Status> {
    let req = parse(params)?;

    if let Some(pa) = req.pin_auth {
        return if pa.is_empty() { Ok(Pending::PinProbe) } else { Err(Status::PinAuthInvalid) };
    }
    if req.options.rk.is_some() {
        return Err(Status::InvalidOption);
    }
    if req.options.uv == Some(true) || req.options.up == Some(false) {
        return Err(Status::UnsupportedOption);
    }

    // Without resident keys an assertion needs an allow list containing one of our IDs.
    let Some(raw) = req.allow_list else {
        return Err(Status::NoCredentials);
    };
    // Each candidate's tag comes from the hardware; a hardware failure stops the search with
    // an error instead of reading as "not ours".
    let mut tagger = PlatformTagger(platform);
    let found = parse::find_in_list(raw, |desc| {
        if !desc.is_public_key {
            return None;
        }
        match credential::unwrap(&mut tagger, &req.rp_id_hash, desc.id) {
            Ok(Some(nonce)) => {
                let id: [u8; CRED_ID_LEN] = desc.id.try_into().ok()?;
                Some(Ok((id, nonce)))
            }
            Ok(None) => None,
            Err(_) => Some(Err(Status::Other)),
        }
    })?;
    let Some((cred_id, nonce)) = found.transpose()? else {
        return Err(Status::NoCredentials);
    };
    Ok(Pending::GetAssertion { rp_id_hash: req.rp_id_hash, client_data_hash: req.client_data_hash, cred_id, nonce })
}

/// Sign the assertion after the user touched the device.
pub fn complete<P: Platform>(
    platform: &mut P,
    rp_id_hash: &[u8; 32],
    client_data_hash: &[u8; 32],
    cred_id: &[u8; CRED_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    out: &mut Response,
) -> Result<usize, Status> {
    let seed = credential_seed(platform, rp_id_hash, nonce)?;
    let sk = crypto::derive_credential_key(&seed, rp_id_hash, nonce).map_err(|_| Status::Other)?;

    // Invariant 2: persist the counter before the signature exists.
    let count = platform.increment_counter().map_err(|_| Status::Other)?;
    let ad = authdata::assertion(rp_id_hash, FLAG_UP, count);

    let mut entropy = zeroize::Zeroizing::new([0u8; 32]);
    platform.random_bytes(entropy.as_mut()).map_err(|_| Status::Other)?;
    let sig = crypto::sign(&sk, &[&ad, client_data_hash], &entropy).map_err(|_| Status::Other)?;

    write_success(out, |e| {
        e.map(3)?;
        e.unsigned(0x01)?;
        e.map(2)?;
        e.text("id")?;
        e.bytes(cred_id)?;
        e.text("type")?;
        e.text("public-key")?;
        e.unsigned(0x02)?;
        e.bytes(&ad)?;
        e.unsigned(0x03)?;
        e.bytes(sig.as_bytes())
    })
}
