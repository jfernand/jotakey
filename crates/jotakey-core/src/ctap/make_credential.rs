// (c) Javier Fernandez @ JotaSoft 2026
//! authenticatorMakeCredential (CTAP 2.0 §5.1).

use super::parse::{self, EntityId, PARAM_DEPTH};
use super::{Pending, PlatformTagger, Response, credential_seed, write_success};
use crate::authdata;
use crate::cbor::{Decoder, Key};
use crate::credential::{self, NONCE_LEN};
use crate::crypto::{self, COSE_ALG_ES256};
use crate::platform::Platform;
use crate::status::Status;

/// Validated request.
struct Request<'a> {
    client_data_hash: [u8; 32],
    rp_id_hash: [u8; 32],
    es256_offered: bool,
    exclude_list: Option<&'a [u8]>,
    options: parse::Options,
    pin_auth: Option<&'a [u8]>,
}

fn parse(params: &[u8]) -> Result<Request<'_>, Status> {
    let mut d = Decoder::new(params);
    let mut m = d.map()?;
    let mut cdh = None;
    let mut rp_id_hash = None;
    let mut user_seen = false;
    let mut algs_seen = false;
    let mut es256_offered = false;
    let mut exclude_list = None;
    let mut options = parse::Options::default();
    let mut pin_auth = None;
    while let Some(k) = d.next_key(&mut m)? {
        match k {
            Key::Int(0x01) => cdh = Some(parse::hash32(&mut d)?),
            Key::Int(0x02) => {
                let EntityId::Text(id) = parse::entity(&mut d, false)? else {
                    return Err(Status::CborUnexpectedType);
                };
                rp_id_hash = Some(crypto::sha256(&[id.as_bytes()]));
            }
            Key::Int(0x03) => {
                let EntityId::Bytes(id) = parse::entity(&mut d, true)? else {
                    return Err(Status::CborUnexpectedType);
                };
                if id.len() > 64 {
                    return Err(Status::InvalidLength);
                }
                user_seen = true;
            }
            Key::Int(0x04) => {
                let n = d.array()?;
                for _ in 0..n {
                    let mut pm = d.map()?;
                    let mut alg = None;
                    let mut ty = None;
                    while let Some(pk) = d.next_key(&mut pm)? {
                        match pk {
                            Key::Text("alg") => alg = Some(d.int()?),
                            Key::Text("type") => ty = Some(d.text()?),
                            _ => d.skip(PARAM_DEPTH.saturating_add(2))?,
                        }
                    }
                    let (Some(alg), Some(ty)) = (alg, ty) else {
                        return Err(Status::MissingParameter);
                    };
                    es256_offered |= ty == "public-key" && alg == COSE_ALG_ES256;
                }
                algs_seen = true;
            }
            Key::Int(0x05) => exclude_list = Some(parse::descriptor_list(&mut d)?),
            Key::Int(0x06) => parse::extensions(&mut d)?,
            Key::Int(0x07) => options = parse::options(&mut d)?,
            Key::Int(0x08) => pin_auth = Some(d.bytes()?),
            Key::Int(0x09) => {
                d.unsigned()?;
            }
            _ => d.skip(PARAM_DEPTH)?,
        }
    }
    d.finish()?;
    let (Some(client_data_hash), Some(rp_id_hash)) = (cdh, rp_id_hash) else {
        return Err(Status::MissingParameter);
    };
    if !user_seen || !algs_seen {
        return Err(Status::MissingParameter);
    }
    Ok(Request { client_data_hash, rp_id_hash, es256_offered, exclude_list, options, pin_auth })
}

/// Validate the request and decide what to park.
pub fn process<P: Platform>(platform: &mut P, params: &[u8]) -> Result<Pending, Status> {
    let req = parse(params)?;

    // Zero-length pinAuth is the platform's "touch to select this device" probe.
    if let Some(pa) = req.pin_auth {
        return if pa.is_empty() { Ok(Pending::PinProbe) } else { Err(Status::PinAuthInvalid) };
    }

    // Step 1: the exclude list. If any ID is ours for this RP, report it after a touch.
    if let Some(raw) = req.exclude_list {
        let mut tagger = PlatformTagger(platform);
        let hit = parse::find_in_list(raw, |desc| {
            if !desc.is_public_key {
                return None;
            }
            match credential::unwrap(&mut tagger, &req.rp_id_hash, desc.id) {
                Ok(Some(_)) => Some(Ok(())),
                Ok(None) => None,
                Err(_) => Some(Err(Status::Other)),
            }
        })?;
        if hit.transpose()?.is_some() {
            return Ok(Pending::Excluded);
        }
    }

    // Step 2: algorithms.
    if !req.es256_offered {
        return Err(Status::UnsupportedAlgorithm);
    }

    // Step 3: options. No resident keys, no user verification in the MVP.
    if req.options.rk == Some(true) || req.options.uv == Some(true) {
        return Err(Status::UnsupportedOption);
    }
    if req.options.up.is_some() {
        return Err(Status::InvalidOption);
    }

    Ok(Pending::MakeCredential { rp_id_hash: req.rp_id_hash, client_data_hash: req.client_data_hash })
}

/// Mint the credential after the user touched the device.
pub fn complete<P: Platform>(
    platform: &mut P,
    aaguid: &[u8; 16],
    rp_id_hash: &[u8; 32],
    client_data_hash: &[u8; 32],
    out: &mut Response,
) -> Result<usize, Status> {
    let mut nonce = [0u8; NONCE_LEN];
    platform.random_bytes(&mut nonce).map_err(|_| Status::Other)?;
    let cred_id = credential::wrap(&mut PlatformTagger(&mut *platform), rp_id_hash, &nonce).map_err(|_| Status::Other)?;
    let seed = credential_seed(platform, rp_id_hash, &nonce)?;
    let sk = crypto::derive_credential_key(&seed, rp_id_hash, &nonce).map_err(|_| Status::Other)?;

    // Invariant 2: the counter is persisted before any signature carrying it exists.
    let count = platform.increment_counter().map_err(|_| Status::Other)?;

    let mut ad = [0u8; authdata::MAX_LEN];
    let ad_len = authdata::registration(&mut ad, rp_id_hash, count, aaguid, &cred_id, &sk.public_key())
        .map_err(|_| Status::Other)?;
    let ad = ad.get(..ad_len).ok_or(Status::Other)?;

    let mut entropy = zeroize::Zeroizing::new([0u8; 32]);
    platform.random_bytes(entropy.as_mut()).map_err(|_| Status::Other)?;
    let sig = crypto::sign(&sk, &[ad, client_data_hash], &entropy).map_err(|_| Status::Other)?;

    write_success(out, |e| {
        e.map(3)?;
        e.unsigned(0x01)?;
        e.text("packed")?;
        e.unsigned(0x02)?;
        e.bytes(ad)?;
        e.unsigned(0x03)?;
        e.map(2)?;
        e.text("alg")?;
        e.int(COSE_ALG_ES256)?;
        e.text("sig")?;
        e.bytes(sig.as_bytes())
    })
}
