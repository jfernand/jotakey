// (c) Javier Fernandez @ JotaSoft 2026
//! authenticatorClientPIN against a reference model, driven by a real platform-side client.
//!
//! Random bytes cannot get past ECDH and an HMAC, so this target *is* the platform: it
//! does key agreement, encrypts PINs and MACs requests properly, and the input only chooses
//! what to do next. The input is a script; each step is one operation, its parameters taken
//! from the following bytes:
//!
//! | op % 10 | operation |
//! |---|---|
//! | 0 | getKeyAgreement |
//! | 1 | setPIN with a fuzzer-chosen padded PIN |
//! | 2 | changePIN (current PIN or a guess) to a fuzzer-chosen PIN |
//! | 3 | getPinUvAuthTokenUsingPinWithPermissions or getPINToken (PIN or guess; permissions; RP) |
//! | 4 | makeCredential with the token (maybe a corrupted MAC; maybe the touch times out) |
//! | 5 | getAssertion with the token (maybe silent, corrupted, or timed out) |
//! | 6 | power cycle |
//! | 7 | authenticatorReset |
//! | 8 | getPINRetries |
//! | 9 | toggle "PIN storage writes fail" |
//!
//! Oracle: a plain model of CTAP 2.1's PIN rules (`Model`) predicts the exact status of
//! every step, and after every step the stored retry counter, the mismatch count, whether a
//! token exists, and the UV flag of every signature must equal the model's. In particular
//! the model never lets more than 8 wrong PINs through between correct ones, and never
//! three in a power cycle.

#![no_main]

use std::sync::OnceLock;

use jotakey_core::authdata::{FLAG_AT, FLAG_UP, FLAG_UV};
use jotakey_core::cbor::{Decoder, Encoder, Key};
use jotakey_core::crypto::sha256;
use jotakey_core::ctap::{Authenticator, Outcome, command};
use jotakey_core::mock::MockPlatform;
use jotakey_core::pin_protocol::{self, KeyAgreementKey, SharedSecret};
use jotakey_core::platform::{PinRecord, PresenceResult};
use jotakey_core::status::Status;
use jotakey_core::{AAGUID, MAX_MSG_SIZE};
use libfuzzer_sys::fuzz_target;

const RPS: [&str; 2] = ["a.example", "b.example"];
const CDH: [u8; 32] = [0xCD; 32];

/// The script, read a byte at a time (zeros once it runs out).
struct Script<'a>(&'a [u8]);

impl Script<'_> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }
    fn take(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ModelToken {
    permissions: u8,
    rp: Option<usize>,
    serial: u32,
}

/// CTAP 2.1's PIN rules, written plainly.
#[derive(Default, Debug)]
struct Model {
    /// `LEFT(SHA-256(PIN), 16)` of the PIN, if set.
    pin: Option<[u8; 16]>,
    /// The PIN record outlived a reset whose second half failed: it can never match.
    pin_dead: bool,
    retries: u8,
    mismatches: u8,
    token: Option<ModelToken>,
    /// The authenticator has a key-agreement key, and the client's secret matches it.
    have_key: bool,
    agreed: bool,
    credentials_alive: bool,
    serial: u32,
    store_fails: bool,
}

impl Model {
    fn new() -> Self {
        Self { retries: 8, credentials_alive: true, ..Self::default() }
    }

    fn power_cycle(&mut self) {
        self.mismatches = 0;
        self.token = None;
        self.have_key = false;
        self.agreed = false;
    }

    /// The PIN policy on a padded PIN; the PIN hash if it passes.
    fn policy(padded: &[u8; 64]) -> Result<[u8; 16], Status> {
        let end = padded.iter().position(|&b| b == 0).ok_or(Status::PinPolicyViolation)?;
        if padded[end..].iter().any(|&b| b != 0) {
            return Err(Status::PinPolicyViolation);
        }
        let code_points = padded[..end].iter().filter(|&&b| b & 0xC0 != 0x80).count();
        if code_points < 4 {
            return Err(Status::PinPolicyViolation);
        }
        Ok(sha256(&[&padded[..end]])[..16].try_into().unwrap())
    }

    /// A PIN entry: counted first, then compared.
    fn check(&mut self, guess: &[u8; 16]) -> Result<(), Status> {
        if self.store_fails {
            return Err(Status::Other);
        }
        self.retries -= 1;
        if self.agreed && !self.pin_dead && self.pin == Some(*guess) {
            self.mismatches = 0;
            self.retries = 8;
            return Ok(());
        }
        self.agreed = false; // the authenticator replaced its key
        self.mismatches += 1;
        Err(if self.retries == 0 {
            Status::PinBlocked
        } else if self.mismatches >= 3 {
            Status::PinAuthBlocked
        } else {
            Status::PinInvalid
        })
    }

    fn usable(&self) -> Result<(), Status> {
        if self.pin.is_none() {
            return Err(Status::PinNotSet);
        }
        if self.retries == 0 {
            return Err(Status::PinBlocked);
        }
        if self.mismatches >= 3 {
            return Err(Status::PinAuthBlocked);
        }
        if !self.have_key {
            return Err(Status::PinAuthInvalid);
        }
        Ok(())
    }

    fn set_pin(&mut self, padded: &[u8; 64]) -> Result<(), Status> {
        if self.pin.is_some() {
            return Err(Status::NotAllowed);
        }
        if !self.have_key || !self.agreed {
            return Err(Status::PinAuthInvalid);
        }
        let hash = Self::policy(padded)?;
        if self.store_fails {
            return Err(Status::Other);
        }
        self.pin = Some(hash);
        self.pin_dead = false;
        self.retries = 8;
        Ok(())
    }

    fn change_pin(&mut self, guess: &[u8; 16], padded: &[u8; 64]) -> Result<(), Status> {
        self.usable()?;
        if !self.agreed {
            return Err(Status::PinAuthInvalid);
        }
        self.check(guess)?;
        self.token = None;
        let hash = Self::policy(padded)?;
        // A store that fails here would have failed the decrement first.
        self.pin = Some(hash);
        Ok(())
    }

    fn get_token(&mut self, permissions: u64, rp: Option<usize>, guess: &[u8; 16]) -> Result<ModelToken, Status> {
        if permissions == 0 {
            return Err(Status::InvalidParameter);
        }
        if permissions & !3 != 0 {
            return Err(Status::UnauthorizedPermission);
        }
        self.usable()?;
        self.check(guess)?;
        self.serial += 1;
        let t = ModelToken { permissions: permissions as u8, rp, serial: self.serial };
        self.token = Some(t);
        Ok(t)
    }

    /// The pinUvAuthParam check of makeCredential/getAssertion.
    fn authorize(&mut self, held: Option<ModelToken>, corrupt: bool, permission: u8, rp: usize) -> Result<(), Status> {
        let Some(t) = self.token.as_mut() else { return Err(Status::PinAuthInvalid) };
        if corrupt || held.map(|h| h.serial) != Some(t.serial) || t.permissions & permission == 0 {
            return Err(Status::PinAuthInvalid);
        }
        match t.rp {
            Some(bound) if bound != rp => Err(Status::PinAuthInvalid),
            _ => {
                t.rp = Some(rp);
                Ok(())
            }
        }
    }
}

/// The platform side.
struct Client {
    key: KeyAgreementKey,
    shared: Option<SharedSecret>,
    token: Option<([u8; 32], ModelToken)>,
}

struct World {
    platform: MockPlatform,
    auth: Authenticator,
    out: Box<[u8; MAX_MSG_SIZE]>,
    model: Model,
    client: Client,
    credentials: [Vec<u8>; 2],
}

fn encode(f: impl FnOnce(&mut Encoder<'_>) -> Result<(), jotakey_core::cbor::CborError>) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let mut e = Encoder::new(&mut buf);
    f(&mut e).expect("request fits");
    let n = e.len();
    buf.truncate(n);
    buf
}

/// Member `key` of the response map, as raw bytes of a byte string.
fn member_bytes(body: &[u8], key: i64) -> Vec<u8> {
    let mut d = Decoder::new(body);
    let mut m = d.map().unwrap();
    while let Some(k) = d.next_key(&mut m).unwrap() {
        if k == Key::Int(key) {
            return d.bytes().unwrap().to_vec();
        }
        d.skip(1).unwrap();
    }
    panic!("member {key} missing")
}

impl World {
    /// Send a request, touching (or timing out) if asked. Returns (status, body).
    fn send(&mut self, request: &[u8], presence: PresenceResult) -> (Status, Vec<u8>, bool) {
        let mut parked = false;
        let n = match self.auth.process(&mut self.platform, request, &mut self.out) {
            Outcome::Response(n) => n,
            Outcome::NeedsUserPresence => {
                parked = true;
                self.auth.complete(&mut self.platform, presence, &mut self.out)
            }
        };
        let status = status_of(self.out[0]);
        (status, self.out[1..n].to_vec(), parked)
    }

    fn client_pin(&mut self, members: impl FnOnce(&mut Encoder<'_>) -> Result<(), jotakey_core::cbor::CborError>) -> (Status, Vec<u8>) {
        let mut req = vec![command::CLIENT_PIN];
        req.extend(encode(members));
        let (st, body, parked) = self.send(&req, PresenceResult::Confirmed);
        assert!(!parked, "clientPIN never waits for a touch");
        (st, body)
    }

    /// The client's public key, CBOR-encoded.
    fn key_agreement(&self) -> Vec<u8> {
        encode(|e| self.client.key.encode_public(e))
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 16 + plaintext.len()];
        match &self.client.shared {
            Some(s) => {
                s.encrypt(&[0x1C; 16], plaintext, &mut out).unwrap();
            }
            None => out.fill(0x5A), // nothing agreed: send noise of the right size
        }
        out
    }

    fn mac(&self, parts: &[&[u8]]) -> Vec<u8> {
        match &self.client.shared {
            Some(s) => s.authenticate(parts).unwrap().to_vec(),
            None => vec![0x5A; 32],
        }
    }
}

fn status_of(b: u8) -> Status {
    use Status::*;
    for s in [
        Success, InvalidCommand, InvalidParameter, InvalidLength, MissingParameter, CborUnexpectedType, InvalidCbor,
        NotAllowed, PinInvalid, PinBlocked, PinAuthInvalid, PinAuthBlocked, PinNotSet, PinPolicyViolation,
        InvalidSubcommand, UnauthorizedPermission, UserActionTimeout, NoCredentials, Other,
    ] {
        if s.code() == b {
            return s;
        }
    }
    panic!("unexpected status {b:#04x}")
}

fn result(st: Status) -> Result<(), Status> {
    if st == Status::Success { Ok(()) } else { Err(st) }
}

fn make_credential_request(rp: &str, pin_auth: &[u8]) -> Vec<u8> {
    let mut r = vec![command::MAKE_CREDENTIAL];
    r.extend(encode(|e| {
        e.map(6)?;
        e.unsigned(1)?;
        e.bytes(&CDH)?;
        e.unsigned(2)?;
        e.map(1)?;
        e.text("id")?;
        e.text(rp)?;
        e.unsigned(3)?;
        e.map(1)?;
        e.text("id")?;
        e.bytes(&[1, 2, 3])?;
        e.unsigned(4)?;
        e.array(1)?;
        e.map(2)?;
        e.text("alg")?;
        e.int(-7)?;
        e.text("type")?;
        e.text("public-key")?;
        e.unsigned(8)?;
        e.bytes(pin_auth)?;
        e.unsigned(9)?;
        e.unsigned(2)
    }));
    r
}

fn get_assertion_request(rp: &str, credential: &[u8], silent: bool, pin_auth: &[u8]) -> Vec<u8> {
    let mut r = vec![command::GET_ASSERTION];
    r.extend(encode(|e| {
        e.map(if silent { 6 } else { 5 })?;
        e.unsigned(1)?;
        e.text(rp)?;
        e.unsigned(2)?;
        e.bytes(&CDH)?;
        e.unsigned(3)?;
        e.array(1)?;
        e.map(2)?;
        e.text("id")?;
        e.bytes(credential)?;
        e.text("type")?;
        e.text("public-key")?;
        if silent {
            e.unsigned(5)?;
            e.map(1)?;
            e.text("up")?;
            e.boolean(false)?;
        }
        e.unsigned(6)?;
        e.bytes(pin_auth)?;
        e.unsigned(7)?;
        e.unsigned(2)
    }));
    r
}

static BASE: OnceLock<(MockPlatform, [Vec<u8>; 2])> = OnceLock::new();

/// A platform with one credential at each RP, registered without a PIN.
fn setup() -> (MockPlatform, [Vec<u8>; 2]) {
    let mut platform = MockPlatform::new(11);
    let mut auth = Authenticator::new(AAGUID);
    let mut out = Box::new([0u8; MAX_MSG_SIZE]);
    let mut ids = [vec![], vec![]];
    for (i, rp) in RPS.iter().enumerate() {
        let mut req = make_credential_request(rp, &[]);
        // Drop the pinUvAuthParam/protocol members: {…6 members} → 4, cut the tail.
        req[1] = 0xA4;
        req.truncate(req.len() - 4);
        assert_eq!(auth.process(&mut platform, &req, &mut out), Outcome::NeedsUserPresence);
        let n = auth.complete(&mut platform, PresenceResult::Confirmed, &mut out);
        assert_eq!(out[0], 0);
        ids[i] = member_bytes(&out[1..n], 2)[55..55 + 49].to_vec();
    }
    (platform, ids)
}

/// A padded PIN: usually digits, sometimes raw bytes, so the policy sees every shape.
fn padded_pin(s: &mut Script<'_>) -> [u8; 64] {
    let shape = s.byte();
    let mut p = [0u8; 64];
    if shape & 0x80 != 0 {
        p.copy_from_slice(&s.take(64));
    } else {
        let len = usize::from(shape % 66).min(64);
        for (i, b) in s.take(len).into_iter().enumerate() {
            p[i] = if shape & 0x40 != 0 { b } else { b'0' + b % 10 };
        }
    }
    p
}

/// The current PIN's hash, or a guess.
fn guess(s: &mut Script<'_>, model: &Model) -> [u8; 16] {
    match (s.byte() % 4, model.pin) {
        (0..=2, Some(pin)) => pin,
        _ => {
            let digits: Vec<u8> = s.take(4).iter().map(|b| b'0' + b % 10).collect();
            sha256(&[&digits])[..16].try_into().unwrap()
        }
    }
}

fn step(w: &mut World, s: &mut Script<'_>) {
    match s.byte() % 10 {
        0 => {
            let (st, body) = w.client_pin(|e| {
                e.map(2)?;
                e.unsigned(1)?;
                e.unsigned(2)?;
                e.unsigned(2)?;
                e.unsigned(2)
            });
            assert_eq!(st, Status::Success);
            let mut d = Decoder::new(&body);
            let mut m = d.map().unwrap();
            assert_eq!(d.next_key(&mut m).unwrap(), Some(Key::Int(1)));
            let theirs = pin_protocol::parse_public_key(&mut d, 1).unwrap();
            w.client.shared = Some(w.client.key.shared_secret(&theirs).unwrap());
            w.model.have_key = true;
            w.model.agreed = true;
        }
        1 => {
            let padded = padded_pin(s);
            let enc = w.encrypt(&padded);
            let mac = w.mac(&[&enc]);
            let ka = w.key_agreement();
            let req = encode(|e| {
                e.map(5)?;
                e.unsigned(1)?;
                e.unsigned(2)?;
                e.unsigned(2)?;
                e.unsigned(3)?;
                e.unsigned(3)?;
                e.raw(&ka)?;
                e.unsigned(4)?;
                e.bytes(&mac)?;
                e.unsigned(5)?;
                e.bytes(&enc)
            });
            let (st, _) = w.client_pin(|e| e.raw(&req));
            assert_eq!(result(st), w.model.set_pin(&padded), "setPIN");
        }
        2 => {
            let g = guess(s, &w.model);
            let padded = padded_pin(s);
            let pin_hash_enc = w.encrypt(&g);
            let new_pin_enc = w.encrypt(&padded);
            let mac = w.mac(&[&new_pin_enc, &pin_hash_enc]);
            let ka = w.key_agreement();
            let req = encode(|e| {
                e.map(6)?;
                e.unsigned(1)?;
                e.unsigned(2)?;
                e.unsigned(2)?;
                e.unsigned(4)?;
                e.unsigned(3)?;
                e.raw(&ka)?;
                e.unsigned(4)?;
                e.bytes(&mac)?;
                e.unsigned(5)?;
                e.bytes(&new_pin_enc)?;
                e.unsigned(6)?;
                e.bytes(&pin_hash_enc)
            });
            let (st, _) = w.client_pin(|e| e.raw(&req));
            assert_eq!(result(st), w.model.change_pin(&g, &padded), "changePIN");
        }
        3 => {
            let legacy = s.byte() % 4 == 0;
            let permissions = match s.byte() {
                p @ 0..=200 => u64::from(p % 4),
                p => u64::from(p),
            };
            let rp = match s.byte() % 3 {
                2 => None,
                i => Some(usize::from(i)),
            };
            let g = guess(s, &w.model);
            let pin_hash_enc = w.encrypt(&g);
            let ka = w.key_agreement();
            let req = encode(|e| {
                let extra = if legacy { 0 } else { 1 + u64::from(rp.is_some()) };
                e.map(4 + extra)?;
                e.unsigned(1)?;
                e.unsigned(2)?;
                e.unsigned(2)?;
                e.unsigned(if legacy { 5 } else { 9 })?;
                e.unsigned(3)?;
                e.raw(&ka)?;
                e.unsigned(6)?;
                e.bytes(&pin_hash_enc)?;
                if !legacy {
                    e.unsigned(9)?;
                    e.unsigned(permissions)?;
                    if let Some(i) = rp {
                        e.unsigned(0x0A)?;
                        e.text(RPS[i])?;
                    }
                }
                Ok(())
            });
            let (st, body) = w.client_pin(|e| e.raw(&req));
            let expected = if legacy { w.model.get_token(3, None, &g) } else { w.model.get_token(permissions, rp, &g) };
            assert_eq!(result(st), expected.map(|_| ()), "getToken");
            if let Ok(t) = expected {
                let enc = member_bytes(&body, 2);
                assert_eq!(enc.len(), 48);
                let mut key = [0u8; 32];
                assert_eq!(w.client.shared.as_ref().unwrap().decrypt(&enc, &mut key), Ok(32));
                w.client.token = Some((key, t));
            }
        }
        4 | 5 => {
            let assertion = s.byte() % 2 == 1; // op 4 and 5 both reach either command
            let flags = s.byte();
            let (corrupt, timeout, silent) = (flags & 1 != 0, flags & 2 != 0, assertion && flags & 4 != 0);
            let rp = usize::from(flags >> 6) % 2;
            let key = w.client.token.map_or([0u8; 32], |t| t.0);
            let mut mac = pin_protocol::authenticate(&key, &[&CDH]).unwrap();
            if corrupt {
                mac[0] ^= 1;
            }
            let req = if assertion {
                get_assertion_request(RPS[rp], &w.credentials[rp].clone(), silent, &mac)
            } else {
                make_credential_request(RPS[rp], &mac)
            };
            let presence = if timeout { PresenceResult::Timeout } else { PresenceResult::Confirmed };
            let (st, body, parked) = w.send(&req, presence);
            let permission = if assertion { 2 } else { 1 };
            let expected = w.model.authorize(w.client.token.map(|t| t.1), corrupt, permission, rp).and_then(|()| {
                if assertion && !w.model.credentials_alive {
                    return Err(Status::NoCredentials);
                }
                if silent {
                    return Ok(());
                }
                if timeout {
                    return Err(Status::UserActionTimeout);
                }
                w.model.token = None; // the touch spends it
                Ok(())
            });
            assert_eq!(result(st), expected, "{} with token", if assertion { "getAssertion" } else { "makeCredential" });
            assert_eq!(parked, expected.is_ok() && !silent || st == Status::UserActionTimeout);
            if st == Status::Success {
                let ad = member_bytes(&body, 2);
                let want = match (assertion, silent) {
                    (false, _) => FLAG_UP | FLAG_UV | FLAG_AT,
                    (true, false) => FLAG_UP | FLAG_UV,
                    (true, true) => FLAG_UV,
                };
                assert_eq!(ad[32], want);
            }
        }
        6 => {
            w.auth = Authenticator::new(AAGUID);
            w.model.power_cycle();
        }
        7 => {
            let (st, _, parked) = w.send(&[command::RESET], PresenceResult::Confirmed);
            assert!(parked);
            w.model.power_cycle();
            w.model.credentials_alive = false;
            if w.model.store_fails {
                assert_eq!(st, Status::Other);
                w.model.pin_dead = w.model.pin.is_some();
            } else {
                assert_eq!(st, Status::Success);
                w.model.pin = None;
                w.model.pin_dead = false;
                w.model.retries = 8;
            }
        }
        8 => {
            let (st, body) = w.client_pin(|e| {
                e.map(1)?;
                e.unsigned(2)?;
                e.unsigned(1)
            });
            assert_eq!(st, Status::Success);
            assert_eq!(body, [0xA1, 0x03, w.model.retries]);
        }
        _ => {
            w.model.store_fails = !w.model.store_fails;
            w.platform.fail_pin_store = w.model.store_fails;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let (platform, credentials) = BASE.get_or_init(setup).clone();
    let mut w = World {
        platform,
        auth: Authenticator::new(AAGUID),
        out: Box::new([0u8; MAX_MSG_SIZE]),
        model: Model::new(),
        client: Client { key: KeyAgreementKey::from_scalar(&[0x33; 32]).unwrap(), shared: None, token: None },
        credentials,
    };
    let mut s = Script(data);
    let mut wrong_since_correct = 0u32;
    let mut steps = 0;
    while !s.0.is_empty() && steps < 64 {
        let retries_before = w.model.retries;
        let attempts_before = w.platform.pin_writes;
        w.platform.retries_at_pin_check = None;
        let op = s.0.first().copied().unwrap_or(0) % 10;
        step(&mut w, &mut s);
        // A changePIN or token request that got as far as processing the PIN did so only
        // once the attempt was stored (invariant 10).
        if matches!(op, 2 | 3) && w.platform.retries_at_pin_check.is_some() {
            assert!(w.platform.pin_writes > attempts_before);
            assert_eq!(w.platform.retries_at_pin_check, Some(retries_before - 1), "PIN processed before the attempt was counted");
        }
        steps += 1;
        // The device agrees with the model…
        let record = PinRecord::from_bytes(&w.platform.pin).unwrap();
        assert_eq!(record.retries, w.model.retries, "retries");
        assert_eq!(record.verifier.is_some(), w.model.pin.is_some(), "PIN set");
        assert_eq!(w.auth.pin_session().mismatches(), w.model.mismatches, "mismatches");
        assert_eq!(w.auth.pin_session().has_token(), w.model.token.is_some(), "token");
        // …and the model keeps the lockout bounds.
        assert!(w.model.mismatches <= 3);
        if w.model.retries < retries_before && w.model.retries != 8 {
            wrong_since_correct += 1;
        } else if w.model.retries == 8 {
            wrong_since_correct = 0;
        }
        assert!(wrong_since_correct <= 8);
    }
});
