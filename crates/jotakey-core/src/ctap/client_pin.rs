// (c) Javier Fernandez @ JotaSoft 2026
//! authenticatorClientPIN (CTAP 2.1 §6.5) with PIN/UV auth protocol two.
//!
//! The platform sets a PIN, later proves knowledge of it, and receives a *pinUvAuthToken*:
//! 32 random bytes, valid for one power cycle at most, that it uses to MAC the
//! `clientDataHash` of the next makeCredential or getAssertion. A request MACed with the
//! token is signed with the UV flag.
//!
//! **PIN lockout (invariant 10).** The persistent retry counter starts at 8. Every PIN check
//! first stores the counter *minus one* and only then compares, so cutting the power at
//! any point cannot buy an uncounted guess. A correct PIN restores the counter to 8; at 0
//! the PIN is blocked until `authenticatorReset`. Independently, three wrong PINs in one
//! power cycle refuse further attempts until the key is unplugged
//! (`CTAP2_ERR_PIN_AUTH_BLOCKED`), which slows a script down to a human pace.
//! `formal/Jotakey/ClientPin.lean` models these rules and proves the bounds.
//!
//! **Storage.** The device keeps no PIN and no PIN hash, only
//! `F(root, "jotakey/pin/v1" ‖ epoch ‖ LEFT(SHA-256(PIN), 16))` from the hardware key store
//! (`SecretLabel::PinVerifier`). A copy of the flash therefore does not allow guessing the
//! PIN offline, and rotating the epoch at reset leaves no verifier that can match.
//!
//! **What is supported.** Sub-commands getPINRetries, getKeyAgreement, setPIN, changePIN,
//! getPINToken and getPinUvAuthTokenUsingPinWithPermissions, protocol two only, and the
//! permissions `mc` and `ga`. There is no built-in user verification, so the sub-commands
//! that use it answer `CTAP2_ERR_INVALID_SUBCOMMAND`.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use super::parse::PARAM_DEPTH;
use super::{Response, write_status, write_success};
use crate::cbor::{Decoder, Key};
use crate::crypto;
use crate::pin_protocol::{self, BLOCK_LEN, KeyAgreementKey, SharedSecret, TAG_LEN};
use crate::platform::{PIN_RETRIES_MAX, Platform, PinRecord, SecretLabel};
use crate::status::Status;

/// clientPIN sub-command numbers (CTAP 2.1 §6.5.5).
pub mod subcommand {
    /// getPINRetries
    pub const GET_PIN_RETRIES: u64 = 0x01;
    /// getKeyAgreement
    pub const GET_KEY_AGREEMENT: u64 = 0x02;
    /// setPIN
    pub const SET_PIN: u64 = 0x03;
    /// changePIN
    pub const CHANGE_PIN: u64 = 0x04;
    /// getPINToken (CTAP 2.0; the permissions `mc` and `ga`, for any RP)
    pub const GET_PIN_TOKEN: u64 = 0x05;
    /// getPinUvAuthTokenUsingPinWithPermissions
    pub const GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS: u64 = 0x09;
}

/// pinUvAuthToken permission bits (CTAP 2.1 §6.5.5.7).
pub mod permission {
    /// `mc`: makeCredential.
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    /// `ga`: getAssertion.
    pub const GET_ASSERTION: u8 = 0x02;
}

/// Permissions this authenticator can grant.
const SUPPORTED_PERMISSIONS: u64 = (permission::MAKE_CREDENTIAL | permission::GET_ASSERTION) as u64;

/// Wrong PINs allowed per power cycle before `CTAP2_ERR_PIN_AUTH_BLOCKED`.
pub const MISMATCHES_PER_POWER_CYCLE: u8 = 3;

/// Shortest PIN accepted, in Unicode code points (advertised as `minPINLength`).
pub const MIN_PIN_LENGTH: u8 = 4;

/// Length of `paddedNewPin`, the PIN padded with zero bytes.
pub const PADDED_PIN_LEN: usize = 64;

/// How long a pinUvAuthToken stays usable after it is issued: ten minutes.
pub const TOKEN_LIFETIME_MS: u64 = 600_000;

/// Length of `LEFT(SHA-256(PIN), 16)`.
const PIN_HASH_LEN: usize = 16;

/// Length of an encrypted pinUvAuthToken: IV and two blocks.
const ENCRYPTED_TOKEN_LEN: usize = 48;
const _: () = assert!(ENCRYPTED_TOKEN_LEN == BLOCK_LEN + TAG_LEN);

/// A pinUvAuthToken and the use it was issued for.
struct Token {
    key: Zeroizing<[u8; 32]>,
    permissions: u8,
    /// Set by the `rpId` parameter, or by the first request that uses the token.
    rp_id_hash: Option<[u8; 32]>,
    issued_ms: u64,
}

/// The clientPIN state that lasts one power cycle, in RAM only.
pub struct PinSession {
    key_agreement: Option<KeyAgreementKey>,
    token: Option<Token>,
    mismatches: u8,
}

impl core::fmt::Debug for PinSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Invariant 8: neither key is printed.
        f.debug_struct("PinSession")
            .field("token", &self.token.is_some())
            .field("mismatches", &self.mismatches)
            .finish_non_exhaustive()
    }
}

impl Default for PinSession {
    fn default() -> Self {
        Self::new()
    }
}

impl PinSession {
    /// The state at power-up: no key-agreement key yet, no token, no wrong PINs.
    #[must_use]
    pub const fn new() -> Self {
        Self { key_agreement: None, token: None, mismatches: 0 }
    }

    /// Wrong PINs so far in this power cycle (since the last correct one).
    #[must_use]
    pub const fn mismatches(&self) -> u8 {
        self.mismatches
    }

    /// Whether a pinUvAuthToken is outstanding.
    #[must_use]
    pub const fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Check a request's `pinUvAuthParam` (CTAP 2.1 §6.1.2 step 11, §6.2.2 step 9): it must
    /// be `authenticate(token, clientDataHash)` for a live token with `permission`, issued
    /// for `rp_id_hash` or for no RP yet, in which case the token is bound to it now.
    ///
    /// # Errors
    /// [`Status::PinAuthInvalid`] for every failure, as the spec prescribes.
    pub fn authorize(
        &mut self,
        now_ms: u64,
        permission: u8,
        rp_id_hash: &[u8; 32],
        client_data_hash: &[u8; 32],
        param: &[u8],
    ) -> Result<(), Status> {
        let Some(token) = self.token.as_mut() else {
            return Err(Status::PinAuthInvalid);
        };
        if now_ms.saturating_sub(token.issued_ms) > TOKEN_LIFETIME_MS {
            self.token = None;
            return Err(Status::PinAuthInvalid);
        }
        if !pin_protocol::verify(&token.key, &[client_data_hash], param) || token.permissions & permission == 0 {
            return Err(Status::PinAuthInvalid);
        }
        match token.rp_id_hash {
            Some(bound) if bound != *rp_id_hash => Err(Status::PinAuthInvalid),
            Some(_) => Ok(()),
            None => {
                token.rp_id_hash = Some(*rp_id_hash);
                Ok(())
            }
        }
    }

    /// A touch completed a command authorized with the token: its `mc` and `ga` permissions
    /// are spent (CTAP 2.1 `clearPinUvAuthTokenPermissionsExceptLbw`), which with no other
    /// permission supported retires the token.
    pub fn spend_token(&mut self) {
        self.token = None;
    }
}

/// Validated parameters (CTAP 2.1 §6.5.5).
#[derive(Default)]
struct Request<'a> {
    protocol: Option<u64>,
    subcommand: Option<u64>,
    key_agreement: Option<p256::PublicKey>,
    pin_uv_auth_param: Option<&'a [u8]>,
    new_pin_enc: Option<&'a [u8]>,
    pin_hash_enc: Option<&'a [u8]>,
    permissions: Option<u64>,
    rp_id: Option<&'a str>,
}

fn parse(params: &[u8]) -> Result<Request<'_>, Status> {
    let mut d = Decoder::new(params);
    let mut m = d.map()?;
    let mut r = Request::default();
    while let Some(k) = d.next_key(&mut m)? {
        match k {
            Key::Int(0x01) => r.protocol = Some(d.unsigned()?),
            Key::Int(0x02) => r.subcommand = Some(d.unsigned()?),
            Key::Int(0x03) => r.key_agreement = Some(pin_protocol::parse_public_key(&mut d, PARAM_DEPTH)?),
            Key::Int(0x04) => r.pin_uv_auth_param = Some(d.bytes()?),
            Key::Int(0x05) => r.new_pin_enc = Some(d.bytes()?),
            Key::Int(0x06) => r.pin_hash_enc = Some(d.bytes()?),
            Key::Int(0x09) => r.permissions = Some(d.unsigned()?),
            Key::Int(0x0A) => r.rp_id = Some(d.text()?),
            _ => d.skip(PARAM_DEPTH)?,
        }
    }
    d.finish()?;
    Ok(r)
}

/// Handle one clientPIN request; every sub-command answers at once.
///
/// Checks run in this order, so that the cheapest and least revealing come first: CBOR and
/// parameter types (the key-agreement point must be on the curve); the sub-command; the
/// protocol; the sub-command's mandatory parameters; then each sub-command's own steps.
///
/// # Errors
/// The CTAP status to return.
pub fn process<P: Platform>(
    platform: &mut P,
    session: &mut PinSession,
    params: &[u8],
    out: &mut Response,
) -> Result<usize, Status> {
    let req = parse(params)?;
    let sub = req.subcommand.ok_or(Status::MissingParameter)?;
    if sub == subcommand::GET_PIN_RETRIES {
        let retries = platform.load_pin().map_err(|_| Status::Other)?.retries;
        return write_success(out, |e| {
            e.map(1)?;
            e.unsigned(0x03)?;
            e.unsigned(u64::from(retries))
        });
    }
    if !matches!(
        sub,
        subcommand::GET_KEY_AGREEMENT
            | subcommand::SET_PIN
            | subcommand::CHANGE_PIN
            | subcommand::GET_PIN_TOKEN
            | subcommand::GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS
    ) {
        return Err(Status::InvalidSubcommand);
    }
    if req.protocol.ok_or(Status::MissingParameter)? != pin_protocol::PROTOCOL {
        return Err(Status::InvalidParameter);
    }
    match sub {
        subcommand::GET_KEY_AGREEMENT => get_key_agreement(platform, session, out),
        subcommand::SET_PIN => set_pin(platform, session, &req, out),
        subcommand::CHANGE_PIN => change_pin(platform, session, &req, out),
        _ => get_token(platform, session, &req, sub, out),
    }
}

fn get_key_agreement<P: Platform>(platform: &mut P, session: &mut PinSession, out: &mut Response) -> Result<usize, Status> {
    let key = match &session.key_agreement {
        Some(k) => k,
        None => session.key_agreement.insert(KeyAgreementKey::generate(platform).map_err(|_| Status::Other)?),
    };
    write_success(out, |e| {
        e.map(1)?;
        e.unsigned(0x01)?;
        key.encode_public(e)
    })
}

/// The secret shared with the platform. Without a key-agreement key the platform cannot
/// know the secret, so the request cannot be authentic.
fn shared_secret(session: &PinSession, peer: &p256::PublicKey) -> Result<SharedSecret, Status> {
    let key = session.key_agreement.as_ref().ok_or(Status::PinAuthInvalid)?;
    key.shared_secret(peer).map_err(|_| Status::Other)
}

/// The verifier the hardware key store makes from `LEFT(SHA-256(PIN), 16)`.
fn verifier<P: Platform>(platform: &mut P, pin_hash: &[u8; PIN_HASH_LEN]) -> Result<[u8; 32], Status> {
    let mut v = [0u8; 32];
    platform.derive_secret(SecretLabel::PinVerifier, pin_hash, &mut v).map_err(|_| Status::Other)?;
    Ok(v)
}

/// Decrypt `newPinEnc` and apply the PIN policy; returns `LEFT(SHA-256(PIN), 16)`.
///
/// The PIN is the bytes before the first zero of the 64-byte `paddedNewPin`; everything
/// after it must be zero. It must be at most 63 bytes and at least [`MIN_PIN_LENGTH`]
/// code points long, counted as the bytes that are not UTF-8 continuation bytes. The scan
/// is branch-free over all 64 bytes (invariant 9), but SHA-256 over the PIN itself takes
/// one block below 56 bytes and two above, so timing can tell very long PINs from short ones.
fn new_pin_hash(shared: &SharedSecret, new_pin_enc: &[u8]) -> Result<[u8; PIN_HASH_LEN], Status> {
    if new_pin_enc.len() != BLOCK_LEN + PADDED_PIN_LEN {
        return Err(Status::InvalidParameter);
    }
    let mut padded = Zeroizing::new([0u8; PADDED_PIN_LEN]);
    shared.decrypt(new_pin_enc, padded.as_mut()).map_err(|_| Status::InvalidParameter)?;

    let mut ended = Choice::from(0); // a zero byte has been seen
    let mut bad_padding = Choice::from(0); // a nonzero byte after the end
    let mut bytes = 0u8;
    let mut code_points = 0u8;
    for &b in padded.iter() {
        ended |= b.ct_eq(&0);
        bad_padding |= ended & !b.ct_eq(&0);
        let counted = !ended;
        bytes = u8::conditional_select(&bytes, &bytes.wrapping_add(1), counted);
        let starts_code_point = counted & !(b & 0xC0).ct_eq(&0x80);
        code_points = u8::conditional_select(&code_points, &code_points.wrapping_add(1), starts_code_point);
    }
    // The result of the policy is public (it is the response), so branching on it is fine.
    if bool::from(bad_padding | !ended) || code_points < MIN_PIN_LENGTH {
        return Err(Status::PinPolicyViolation);
    }
    let pin = padded.get(..usize::from(bytes)).ok_or(Status::Other)?;
    let digest = Zeroizing::new(crypto::sha256(&[pin]));
    let mut hash = [0u8; PIN_HASH_LEN];
    hash.copy_from_slice(digest.get(..PIN_HASH_LEN).ok_or(Status::Other)?);
    Ok(hash)
}

/// Count a PIN attempt durably, then compare (invariant 10). On a match the counter is
/// restored; on a mismatch the key-agreement key is replaced, so the platform must start
/// over, and the status says how close the PIN is to blocking.
fn check_pin<P: Platform>(
    platform: &mut P,
    session: &mut PinSession,
    shared: &SharedSecret,
    stored: &[u8; 32],
    retries: u8,
    pin_hash_enc: &[u8],
) -> Result<(), Status> {
    if pin_hash_enc.len() != BLOCK_LEN + PIN_HASH_LEN {
        return Err(Status::InvalidParameter);
    }
    let left = retries.checked_sub(1).ok_or(Status::PinBlocked)?;
    platform.store_pin(&PinRecord { verifier: Some(*stored), retries: left }).map_err(|_| Status::Other)?;

    let mut pin_hash = Zeroizing::new([0u8; PIN_HASH_LEN]);
    shared.decrypt(pin_hash_enc, pin_hash.as_mut()).map_err(|_| Status::Other)?;
    let candidate = Zeroizing::new(verifier(platform, &pin_hash)?);
    if bool::from(candidate.ct_eq(stored)) {
        session.mismatches = 0;
        platform.store_pin(&PinRecord { verifier: Some(*stored), retries: PIN_RETRIES_MAX }).map_err(|_| Status::Other)?;
        return Ok(());
    }
    session.key_agreement = KeyAgreementKey::generate(platform).ok();
    session.mismatches = session.mismatches.saturating_add(1);
    Err(if left == 0 {
        Status::PinBlocked
    } else if session.mismatches >= MISMATCHES_PER_POWER_CYCLE {
        Status::PinAuthBlocked
    } else {
        Status::PinInvalid
    })
}

/// The PIN must be set and not blocked, for good or for this power cycle.
fn usable_pin<P: Platform>(platform: &mut P, session: &PinSession) -> Result<([u8; 32], u8), Status> {
    let record = platform.load_pin().map_err(|_| Status::Other)?;
    let stored = record.verifier.ok_or(Status::PinNotSet)?;
    if record.retries == 0 {
        return Err(Status::PinBlocked);
    }
    if session.mismatches >= MISMATCHES_PER_POWER_CYCLE {
        return Err(Status::PinAuthBlocked);
    }
    Ok((stored, record.retries))
}

/// setPIN (CTAP 2.1 §6.5.5.5): only when no PIN is set.
fn set_pin<P: Platform>(
    platform: &mut P,
    session: &mut PinSession,
    req: &Request<'_>,
    out: &mut Response,
) -> Result<usize, Status> {
    let (Some(peer), Some(new_pin_enc), Some(param)) = (&req.key_agreement, req.new_pin_enc, req.pin_uv_auth_param)
    else {
        return Err(Status::MissingParameter);
    };
    if platform.load_pin().map_err(|_| Status::Other)?.verifier.is_some() {
        return Err(Status::NotAllowed);
    }
    let shared = shared_secret(session, peer)?;
    if !shared.verify(&[new_pin_enc], param) {
        return Err(Status::PinAuthInvalid);
    }
    let pin_hash = Zeroizing::new(new_pin_hash(&shared, new_pin_enc)?);
    let v = verifier(platform, &pin_hash)?;
    platform.store_pin(&PinRecord { verifier: Some(v), retries: PIN_RETRIES_MAX }).map_err(|_| Status::Other)?;
    Ok(write_status(out, Status::Success))
}

/// changePIN (CTAP 2.1 §6.5.5.6): the current PIN is checked like any PIN entry. Any
/// outstanding token is revoked.
fn change_pin<P: Platform>(
    platform: &mut P,
    session: &mut PinSession,
    req: &Request<'_>,
    out: &mut Response,
) -> Result<usize, Status> {
    let (Some(peer), Some(pin_hash_enc), Some(new_pin_enc), Some(param)) =
        (&req.key_agreement, req.pin_hash_enc, req.new_pin_enc, req.pin_uv_auth_param)
    else {
        return Err(Status::MissingParameter);
    };
    let (stored, retries) = usable_pin(platform, session)?;
    let shared = shared_secret(session, peer)?;
    if !shared.verify(&[new_pin_enc, pin_hash_enc], param) {
        return Err(Status::PinAuthInvalid);
    }
    check_pin(platform, session, &shared, &stored, retries, pin_hash_enc)?;
    session.token = None;
    let pin_hash = Zeroizing::new(new_pin_hash(&shared, new_pin_enc)?);
    let v = verifier(platform, &pin_hash)?;
    platform.store_pin(&PinRecord { verifier: Some(v), retries: PIN_RETRIES_MAX }).map_err(|_| Status::Other)?;
    Ok(write_status(out, Status::Success))
}

/// getPINToken (0x05) and getPinUvAuthTokenUsingPinWithPermissions (0x09, CTAP 2.1
/// §6.5.5.7). Issues a fresh token, replacing any previous one, encrypted to the platform.
fn get_token<P: Platform>(
    platform: &mut P,
    session: &mut PinSession,
    req: &Request<'_>,
    sub: u64,
    out: &mut Response,
) -> Result<usize, Status> {
    let (Some(peer), Some(pin_hash_enc)) = (&req.key_agreement, req.pin_hash_enc) else {
        return Err(Status::MissingParameter);
    };
    let permissions = if sub == subcommand::GET_PIN_TOKEN {
        // CTAP 2.0's form: implicit mc and ga for any RP, and no room for either parameter.
        if req.permissions.is_some() || req.rp_id.is_some() {
            return Err(Status::InvalidParameter);
        }
        SUPPORTED_PERMISSIONS
    } else {
        req.permissions.ok_or(Status::MissingParameter)?
    };
    if permissions == 0 {
        return Err(Status::InvalidParameter);
    }
    if permissions & !SUPPORTED_PERMISSIONS != 0 {
        return Err(Status::UnauthorizedPermission);
    }
    let (stored, retries) = usable_pin(platform, session)?;
    let shared = shared_secret(session, peer)?;
    check_pin(platform, session, &shared, &stored, retries, pin_hash_enc)?;

    let mut key = Zeroizing::new([0u8; 32]);
    platform.random_bytes(key.as_mut()).map_err(|_| Status::Other)?;
    let mut iv = [0u8; BLOCK_LEN];
    platform.random_bytes(&mut iv).map_err(|_| Status::Other)?;
    let mut encrypted = [0u8; ENCRYPTED_TOKEN_LEN];
    let n = shared.encrypt(&iv, key.as_ref(), &mut encrypted).map_err(|_| Status::Other)?;
    session.token = Some(Token {
        key,
        // `permissions` ≤ SUPPORTED_PERMISSIONS here, so it fits a byte.
        permissions: u8::try_from(permissions).map_err(|_| Status::Other)?,
        rp_id_hash: req.rp_id.map(|id| crypto::sha256(&[id.as_bytes()])),
        issued_ms: platform.uptime_ms(),
    });
    let encrypted = encrypted.get(..n).ok_or(Status::Other)?;
    write_success(out, |e| {
        e.map(1)?;
        e.unsigned(0x02)?;
        e.bytes(encrypted)
    })
}
