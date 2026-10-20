// (c) Javier Fernandez @ JotaSoft 2026
//! authenticatorClientPIN end to end against the mock platform, driven by a platform-side
//! client written here directly on RustCrypto, independent of `pin_protocol.rs`.

mod common;

use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use common::*;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use jotakey_core::authdata::{FLAG_AT, FLAG_UP, FLAG_UV};
use jotakey_core::ctap::client_pin::{MISMATCHES_PER_POWER_CYCLE, TOKEN_LIFETIME_MS};
use jotakey_core::ctap::command::*;
use jotakey_core::ctap::{Authenticator, Outcome};
use jotakey_core::platform::{PIN_RETRIES_MAX, PinRecord, Platform, PresenceResult};
use jotakey_core::status::Status;
use sha2::{Digest, Sha256};

const MC: u64 = 0x01;
const GA: u64 = 0x02;

/// The platform side of PIN/UV auth protocol two.
struct Client {
    secret: p256::SecretKey,
    hmac_key: [u8; 32],
    aes_key: [u8; 32],
}

fn cose(pk: &p256::PublicKey) -> V {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let p = pk.to_encoded_point(false);
    V::M(vec![
        (V::U(1), V::U(2)),
        (V::U(3), V::int(-25)),
        (V::int(-1), V::U(1)),
        (V::int(-2), V::B(p.x().unwrap().to_vec())),
        (V::int(-3), V::B(p.y().unwrap().to_vec())),
    ])
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn padded(pin: &[u8]) -> [u8; 64] {
    let mut p = [0u8; 64];
    p[..pin.len()].copy_from_slice(pin);
    p
}

fn pin_hash(pin: &[u8]) -> [u8; 16] {
    Sha256::digest(pin)[..16].try_into().unwrap()
}

impl Client {
    /// getKeyAgreement and ECDH: a client ready to talk to the authenticator.
    fn connect(h: &mut Harness) -> Self {
        let (st, body) =
            h.run(&request(CLIENT_PIN, vec![(V::U(1), V::U(2)), (V::U(2), V::U(2))]), PresenceResult::Confirmed);
        assert_eq!(st, 0, "getKeyAgreement");
        let (resp, _) = V::decode(&body);
        let key = resp.get(&V::U(1)).unwrap();
        assert_eq!(key.get(&V::U(1)), Some(&V::U(2)));
        assert_eq!(key.get(&V::U(3)), Some(&V::int(-25)));
        assert_eq!(key.get(&V::int(-1)), Some(&V::U(1)));
        let mut sec1 = vec![4u8];
        sec1.extend(key.get(&V::int(-2)).unwrap().bytes());
        sec1.extend(key.get(&V::int(-3)).unwrap().bytes());
        let theirs = p256::PublicKey::from_sec1_bytes(&sec1).unwrap();
        let secret = p256::SecretKey::from_bytes(&[0x33u8; 32].into()).unwrap();
        let z = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), theirs.as_affine());
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z.raw_secret_bytes());
        let (mut hmac_key, mut aes_key) = ([0u8; 32], [0u8; 32]);
        hk.expand(b"CTAP2 HMAC key", &mut hmac_key).unwrap();
        hk.expand(b"CTAP2 AES key", &mut aes_key).unwrap();
        Self { secret, hmac_key, aes_key }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let aes = Aes256::new_from_slice(&self.aes_key).unwrap();
        let mut out = vec![0x1Cu8; 16]; // a fixed IV is fine for a test
        let mut chain = [0x1Cu8; 16];
        for block in plaintext.chunks(16) {
            let mut b: [u8; 16] = block.try_into().unwrap();
            for (x, c) in b.iter_mut().zip(chain) {
                *x ^= c;
            }
            aes.encrypt_block((&mut b).into());
            out.extend(b);
            chain = b;
        }
        out
    }

    fn decrypt(&self, message: &[u8]) -> Vec<u8> {
        let aes = Aes256::new_from_slice(&self.aes_key).unwrap();
        let (iv, ct) = message.split_at(16);
        let mut chain: [u8; 16] = iv.try_into().unwrap();
        let mut out = Vec::new();
        for block in ct.chunks(16) {
            let mut b: [u8; 16] = block.try_into().unwrap();
            let next = b;
            aes.decrypt_block((&mut b).into());
            for (x, c) in b.iter_mut().zip(chain) {
                *x ^= c;
            }
            out.extend(b);
            chain = next;
        }
        out
    }

    fn key_agreement(&self) -> V {
        cose(&self.secret.public_key())
    }

    fn set_pin_request(&self, padded_pin: &[u8]) -> Vec<u8> {
        let new_pin_enc = self.encrypt(padded_pin);
        let param = hmac(&self.hmac_key, &[&new_pin_enc]);
        request(
            CLIENT_PIN,
            vec![
                (V::U(1), V::U(2)),
                (V::U(2), V::U(3)),
                (V::U(3), self.key_agreement()),
                (V::U(4), V::B(param.to_vec())),
                (V::U(5), V::B(new_pin_enc)),
            ],
        )
    }

    fn set_pin(&self, h: &mut Harness, pin: &str) -> u8 {
        h.status(&self.set_pin_request(&padded(pin.as_bytes())))
    }

    fn change_pin(&self, h: &mut Harness, old: &str, new: &str) -> u8 {
        let pin_hash_enc = self.encrypt(&pin_hash(old.as_bytes()));
        let new_pin_enc = self.encrypt(&padded(new.as_bytes()));
        let param = hmac(&self.hmac_key, &[&new_pin_enc, &pin_hash_enc]);
        h.status(&request(
            CLIENT_PIN,
            vec![
                (V::U(1), V::U(2)),
                (V::U(2), V::U(4)),
                (V::U(3), self.key_agreement()),
                (V::U(4), V::B(param.to_vec())),
                (V::U(5), V::B(new_pin_enc)),
                (V::U(6), V::B(pin_hash_enc)),
            ],
        ))
    }

    /// getPinUvAuthTokenUsingPinWithPermissions; the token, or the error status.
    fn token(&self, h: &mut Harness, pin: &str, permissions: u64, rp: Option<&str>) -> Result<[u8; 32], u8> {
        let mut params = vec![
            (V::U(1), V::U(2)),
            (V::U(2), V::U(9)),
            (V::U(3), self.key_agreement()),
            (V::U(6), V::B(self.encrypt(&pin_hash(pin.as_bytes())))),
            (V::U(9), V::U(permissions)),
        ];
        if let Some(rp) = rp {
            params.push((V::U(0x0A), V::t(rp)));
        }
        self.token_from(h, params)
    }

    fn token_from(&self, h: &mut Harness, params: Vec<(V, V)>) -> Result<[u8; 32], u8> {
        let (st, body) = h.run(&request(CLIENT_PIN, params), PresenceResult::Confirmed);
        if st != 0 {
            return Err(st);
        }
        let (resp, _) = V::decode(&body);
        let encrypted = resp.get(&V::U(2)).unwrap().bytes();
        assert_eq!(encrypted.len(), 48);
        Ok(self.decrypt(encrypted).try_into().unwrap())
    }
}

fn retries(h: &mut Harness) -> u64 {
    let (st, body) =
        h.run(&request(CLIENT_PIN, vec![(V::U(1), V::U(2)), (V::U(2), V::U(1))]), PresenceResult::Confirmed);
    assert_eq!(st, 0);
    match V::decode(&body).0.get(&V::U(3)) {
        Some(V::U(n)) => *n,
        other => panic!("pinRetries: {other:?}"),
    }
}

fn client_pin_set(h: &mut Harness) -> bool {
    let (_, body) = h.run(&[GET_INFO], PresenceResult::Confirmed);
    V::decode(&body).0.get(&V::U(4)).unwrap().get(&V::t("clientPin")) == Some(&V::Bool(true))
}

fn power_cycle(h: &mut Harness) {
    h.auth = Authenticator::new(jotakey_core::AAGUID);
}

fn with_token(mut params: Vec<(V, V)>, token: &[u8; 32], protocol_key: u64) -> Vec<(V, V)> {
    params.push((V::U(protocol_key - 1), V::B(hmac(token, &[&CDH]).to_vec())));
    params.push((V::U(protocol_key), V::U(2)));
    params
}

/// makeCredential authorized by `token`; (status, flags, credential id).
fn register_uv(h: &mut Harness, rp: &str, token: &[u8; 32]) -> (u8, u8, Vec<u8>) {
    let (st, body) =
        h.run(&request(MAKE_CREDENTIAL, with_token(make_credential_params(rp), token, 9)), PresenceResult::Confirmed);
    if st != 0 {
        return (st, 0, vec![]);
    }
    let ad = V::decode(&body).0.get(&V::U(2)).unwrap().bytes().to_vec();
    (st, ad[32], ad[55..55 + 49].to_vec())
}

fn register(h: &mut Harness, rp: &str) -> Vec<u8> {
    let (st, body) = h.run(&request(MAKE_CREDENTIAL, make_credential_params(rp)), PresenceResult::Confirmed);
    assert_eq!(st, 0);
    let ad = V::decode(&body).0.get(&V::U(2)).unwrap().bytes().to_vec();
    assert_eq!(ad[32], FLAG_UP | FLAG_AT, "no token, no UV");
    ad[55..55 + 49].to_vec()
}

/// getAssertion authorized by `token`, with or without `up: false`; (status, flags).
fn assert_uv(h: &mut Harness, rp: &str, id: &[u8], token: &[u8; 32], silent: bool) -> (u8, u8) {
    let mut params = with_token(get_assertion_params(rp, &[id]), token, 7);
    if silent {
        params.push((V::U(5), V::M(vec![(V::t("up"), V::Bool(false))])));
    }
    let (st, body) = h.run(&request(GET_ASSERTION, params), PresenceResult::Confirmed);
    if st != 0 {
        return (st, 0);
    }
    (st, V::decode(&body).0.get(&V::U(2)).unwrap().bytes()[32])
}

#[test]
fn get_info_advertises_the_pin() {
    let mut h = Harness::new();
    let (_, body) = h.run(&[GET_INFO], PresenceResult::Confirmed);
    let info = V::decode(&body).0;
    let opts = info.get(&V::U(4)).unwrap();
    assert_eq!(opts.get(&V::t("clientPin")), Some(&V::Bool(false)));
    assert_eq!(opts.get(&V::t("pinUvAuthToken")), Some(&V::Bool(true)));
    assert_eq!(opts.get(&V::t("makeCredUvNotRqd")), Some(&V::Bool(true)));
    assert_eq!(opts.get(&V::t("uv")), None);
    assert_eq!(info.get(&V::U(6)), Some(&V::A(vec![V::U(2)])));
    assert_eq!(info.get(&V::U(0x0D)), Some(&V::U(4)));
    jotakey_core::cbor::Decoder::new(&body).skip(0).unwrap();
    Client::connect(&mut h).set_pin(&mut h, "1234");
    assert!(client_pin_set(&mut h));
    h.platform.fail_pin = true;
    assert_eq!(h.status(&[GET_INFO]), Status::Other.code());
}

#[test]
fn set_pin_then_verified_registration_and_assertion() {
    let mut h = Harness::new();
    assert!(!client_pin_set(&mut h));
    assert_eq!(retries(&mut h), 8);
    let c = Client::connect(&mut h);
    assert_eq!(c.set_pin(&mut h, "1234"), 0);
    assert!(client_pin_set(&mut h));
    assert_eq!(retries(&mut h), 8);
    assert!(PinRecord::from_bytes(&h.platform.pin).unwrap().verifier.is_some());

    // Without a token: still allowed (makeCredUvNotRqd), UV clear.
    let plain_id = register(&mut h, RP);

    let token = c.token(&mut h, "1234", MC | GA, Some(RP)).unwrap();
    assert!(h.auth.pin_session().has_token());
    let (st, flags, id) = register_uv(&mut h, RP, &token);
    assert_eq!((st, flags), (0, FLAG_UP | FLAG_UV | FLAG_AT));
    // The touch spent the token.
    assert!(!h.auth.pin_session().has_token());
    assert_eq!(register_uv(&mut h, RP, &token).0, Status::PinAuthInvalid.code());

    let token = c.token(&mut h, "1234", GA, None).unwrap();
    // A silent assertion with the token: UV without UP, and the token survives.
    assert_eq!(assert_uv(&mut h, RP, &id, &token, true), (0, FLAG_UV));
    assert_eq!(assert_uv(&mut h, RP, &plain_id, &token, false), (0, FLAG_UP | FLAG_UV));
    assert_eq!(assert_uv(&mut h, RP, &id, &token, false).0, Status::PinAuthInvalid.code());

    // A touch that times out does not spend the token, and signs nothing.
    let token = c.token(&mut h, "1234", GA, None).unwrap();
    let params = with_token(get_assertion_params(RP, &[&id]), &token, 7);
    assert_eq!(h.run(&request(GET_ASSERTION, params), PresenceResult::Timeout).0, Status::UserActionTimeout.code());
    assert_eq!(assert_uv(&mut h, RP, &id, &token, false), (0, FLAG_UP | FLAG_UV));

    // Power cycle: the PIN persists, the token does not.
    let token = c.token(&mut h, "1234", GA, None).unwrap();
    power_cycle(&mut h);
    assert!(client_pin_set(&mut h));
    assert_eq!(assert_uv(&mut h, RP, &id, &token, false).0, Status::PinAuthInvalid.code());
}

#[test]
fn the_token_is_bound_to_its_permissions_and_relying_party() {
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");
    let id = register(&mut h, RP);
    let other = register(&mut h, "other.example");

    // mc only: no assertions.
    let token = c.token(&mut h, "1234", MC, None).unwrap();
    assert_eq!(assert_uv(&mut h, RP, &id, &token, true).0, Status::PinAuthInvalid.code());
    // ga only: no registrations.
    let token = c.token(&mut h, "1234", GA, None).unwrap();
    assert_eq!(register_uv(&mut h, RP, &token).0, Status::PinAuthInvalid.code());
    // An rpId fixes the RP.
    let token = c.token(&mut h, "1234", GA, Some("other.example")).unwrap();
    assert_eq!(assert_uv(&mut h, RP, &id, &token, true).0, Status::PinAuthInvalid.code());
    assert_eq!(assert_uv(&mut h, "other.example", &other, &token, true), (0, FLAG_UV));
    // Without one, the first use fixes it.
    let token = c.token(&mut h, "1234", GA, None).unwrap();
    assert_eq!(assert_uv(&mut h, RP, &id, &token, true), (0, FLAG_UV));
    assert_eq!(assert_uv(&mut h, "other.example", &other, &token, true).0, Status::PinAuthInvalid.code());
    assert_eq!(assert_uv(&mut h, RP, &id, &token, true), (0, FLAG_UV));
    // The MAC must be over this clientDataHash with this token.
    let mut params = get_assertion_params(RP, &[&id]);
    params.push((V::U(6), V::B(hmac(&token, &[&[0u8; 32]]).to_vec())));
    params.push((V::U(7), V::U(2)));
    assert_eq!(h.status(&request(GET_ASSERTION, params)), Status::PinAuthInvalid.code());
    let mut params = get_assertion_params(RP, &[&id]);
    params.push((V::U(6), V::B(hmac(&token, &[&CDH])[..16].to_vec())));
    params.push((V::U(7), V::U(2)));
    assert_eq!(
        h.status(&request(GET_ASSERTION, params)),
        Status::PinAuthInvalid.code(),
        "a truncated (protocol one) tag"
    );

    // A new token replaces the old one.
    let first = c.token(&mut h, "1234", GA, None).unwrap();
    let second = c.token(&mut h, "1234", GA, None).unwrap();
    assert_ne!(first, second);
    assert_eq!(assert_uv(&mut h, RP, &id, &first, true).0, Status::PinAuthInvalid.code());
    assert_eq!(assert_uv(&mut h, RP, &id, &second, true), (0, FLAG_UV));
}

#[test]
fn tokens_expire() {
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");
    let id = register(&mut h, RP);
    h.platform.uptime = 1_000;
    let token = c.token(&mut h, "1234", GA, None).unwrap();
    assert_eq!(TOKEN_LIFETIME_MS, 600_000, "ten minutes");
    h.platform.uptime = 1_000 + 600_000;
    assert_eq!(assert_uv(&mut h, RP, &id, &token, true), (0, FLAG_UV));
    h.platform.uptime += 1;
    assert_eq!(assert_uv(&mut h, RP, &id, &token, true).0, Status::PinAuthInvalid.code());
    assert!(!h.auth.pin_session().has_token(), "an expired token is dropped");
}

#[test]
fn the_legacy_get_pin_token() {
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");
    let id = register(&mut h, RP);
    let legacy = |extra: Vec<(V, V)>| {
        let mut p = vec![
            (V::U(1), V::U(2)),
            (V::U(2), V::U(5)),
            (V::U(3), c.key_agreement()),
            (V::U(6), V::B(c.encrypt(&pin_hash(b"1234")))),
        ];
        p.extend(extra);
        p
    };
    let token = c.token_from(&mut h, legacy(vec![])).unwrap();
    assert_eq!(assert_uv(&mut h, RP, &id, &token, true), (0, FLAG_UV));
    let token = c.token_from(&mut h, legacy(vec![])).unwrap();
    assert_eq!(register_uv(&mut h, "any.example", &token).1, FLAG_UP | FLAG_UV | FLAG_AT);
    let bad = Status::InvalidParameter.code();
    assert_eq!(c.token_from(&mut h, legacy(vec![(V::U(9), V::U(GA))])), Err(bad));
    assert_eq!(c.token_from(&mut h, legacy(vec![(V::U(0x0A), V::t(RP))])), Err(bad));
    assert_eq!(retries(&mut h), 8, "rejected requests count no attempt");
}

#[test]
fn permissions_are_checked() {
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");
    assert_eq!(c.token(&mut h, "1234", 0, None), Err(Status::InvalidParameter.code()));
    for unsupported in [0x04, 0x08, 0x10, 0x20, 0x40, 0x100] {
        assert_eq!(c.token(&mut h, "1234", unsupported | GA, None), Err(Status::UnauthorizedPermission.code()));
    }
    assert_eq!(retries(&mut h), 8);
    let mut no_permissions = vec![
        (V::U(1), V::U(2)),
        (V::U(2), V::U(9)),
        (V::U(3), c.key_agreement()),
        (V::U(6), V::B(c.encrypt(&pin_hash(b"1234")))),
    ];
    assert_eq!(c.token_from(&mut h, no_permissions.clone()), Err(Status::MissingParameter.code()));
    no_permissions.push((V::U(9), V::U(MC)));
    assert!(c.token_from(&mut h, no_permissions).is_ok());
}

#[test]
fn wrong_pins_are_counted_and_block() {
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");

    // A wrong PIN costs a retry and replaces the key-agreement key.
    assert_eq!(c.token(&mut h, "0000", GA, None), Err(Status::PinInvalid.code()));
    assert_eq!(retries(&mut h), 7);
    assert_eq!(h.auth.pin_session().mismatches(), 1);
    // So the right PIN under the old shared secret decrypts to garbage: another mismatch.
    assert_eq!(c.token(&mut h, "1234", GA, None), Err(Status::PinInvalid.code()));
    assert_eq!(retries(&mut h), 6);
    // The third mismatch in a power cycle blocks PIN entry until a power cycle.
    let c = Client::connect(&mut h);
    assert_eq!(c.token(&mut h, "9999", GA, None), Err(Status::PinAuthBlocked.code()));
    assert_eq!(h.auth.pin_session().mismatches(), MISMATCHES_PER_POWER_CYCLE);
    let c = Client::connect(&mut h);
    assert_eq!(c.token(&mut h, "1234", GA, None), Err(Status::PinAuthBlocked.code()));
    assert_eq!(c.change_pin(&mut h, "1234", "5678"), Status::PinAuthBlocked.code());
    assert_eq!(retries(&mut h), 5, "a blocked attempt costs nothing");

    // A power cycle allows three more; the right PIN restores the counter.
    power_cycle(&mut h);
    let c = Client::connect(&mut h);
    assert_eq!(c.token(&mut h, "0000", GA, None), Err(Status::PinInvalid.code()));
    let c = Client::connect(&mut h);
    assert!(c.token(&mut h, "1234", GA, None).is_ok());
    assert_eq!(retries(&mut h), 8);
    assert_eq!(h.auth.pin_session().mismatches(), 0);

    // Eight wrong PINs in a row block the PIN for good.
    for left in (0..8u64).rev() {
        if left % 3 == 1 {
            power_cycle(&mut h);
        }
        let c = Client::connect(&mut h);
        let st = c.token(&mut h, "0000", GA, None).unwrap_err();
        assert_eq!(retries(&mut h), left);
        let expected = if left == 0 {
            Status::PinBlocked
        } else if h.auth.pin_session().mismatches() >= MISMATCHES_PER_POWER_CYCLE {
            Status::PinAuthBlocked
        } else {
            Status::PinInvalid
        };
        assert_eq!(st, expected.code(), "{left} left");
    }
    power_cycle(&mut h);
    let c = Client::connect(&mut h);
    assert_eq!(c.token(&mut h, "1234", GA, None), Err(Status::PinBlocked.code()));
    assert_eq!(c.change_pin(&mut h, "1234", "5678"), Status::PinBlocked.code());
    assert_eq!(retries(&mut h), 0);

    // Only a reset, which also ends every credential, makes the key usable with a PIN again.
    assert_eq!(h.status(&[RESET]), 0);
    assert!(!client_pin_set(&mut h));
    assert_eq!(retries(&mut h), 8);
    let c = Client::connect(&mut h);
    assert_eq!(c.set_pin(&mut h, "4321"), 0);
}

#[test]
fn an_attempt_is_stored_before_the_pin_is_compared() {
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");
    let writes = h.platform.pin_writes;
    h.platform.retries_at_pin_check = None;
    assert!(c.token(&mut h, "1234", GA, None).is_ok());
    assert_eq!(h.platform.pin_writes, writes + 2, "decrement, then restore");
    assert_eq!(h.platform.retries_at_pin_check, Some(7), "the PIN was processed only after the decrement was stored");
    h.platform.retries_at_pin_check = None;
    let c = Client::connect(&mut h);
    assert_eq!(c.change_pin(&mut h, "1234", "1234"), 0);
    assert_eq!(h.platform.retries_at_pin_check, Some(7));
    let writes = h.platform.pin_writes;
    let c = Client::connect(&mut h);
    c.token(&mut h, "0000", GA, None).unwrap_err();
    assert_eq!(h.platform.pin_writes, writes + 1);

    // If the attempt cannot be stored, there is no comparison: no token, no mismatch.
    power_cycle(&mut h);
    h.platform.fail_pin_store = true;
    let c = Client::connect(&mut h);
    assert_eq!(c.token(&mut h, "1234", GA, None), Err(Status::Other.code()));
    assert_eq!(c.token(&mut h, "0000", GA, None), Err(Status::Other.code()));
    assert_eq!(h.auth.pin_session().mismatches(), 0);
    assert!(!h.auth.pin_session().has_token());
    assert_eq!(c.change_pin(&mut h, "1234", "5678"), Status::Other.code());
    assert_eq!(c.set_pin(&mut h, "1234"), Status::NotAllowed.code());
    h.platform.fail_pin_store = false;
    assert_eq!(retries(&mut h), 7);
    assert!(c.token(&mut h, "1234", GA, None).is_ok());

    // Unreadable PIN state fails closed everywhere.
    h.platform.fail_pin = true;
    assert_eq!(h.status(&request(CLIENT_PIN, vec![(V::U(1), V::U(2)), (V::U(2), V::U(1))])), Status::Other.code());
    assert_eq!(c.token(&mut h, "1234", GA, None), Err(Status::Other.code()));
    assert_eq!(c.set_pin(&mut h, "1234"), Status::Other.code());
    h.platform.fail_pin = false;
    // So does a record that does not decode.
    h.platform.pin[0] = 2;
    assert_eq!(c.token(&mut h, "1234", GA, None), Err(Status::Other.code()));
}

#[test]
fn a_failed_restore_after_a_correct_pin_issues_no_token() {
    // The decrement is stored, the restore is not: the attempt stays counted.
    struct FailSecond(jotakey_core::mock::MockPlatform, u32);
    impl Platform for FailSecond {
        fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), jotakey_core::platform::PlatformError> {
            self.0.random_bytes(out)
        }
        fn derive_secret(
            &mut self,
            l: jotakey_core::platform::SecretLabel,
            c: &[u8],
            o: &mut [u8; 32],
        ) -> Result<(), jotakey_core::platform::PlatformError> {
            self.0.derive_secret(l, c, o)
        }
        fn increment_counter(&mut self) -> Result<u32, jotakey_core::platform::PlatformError> {
            self.0.increment_counter()
        }
        fn rotate_epoch(&mut self) -> Result<(), jotakey_core::platform::PlatformError> {
            self.0.rotate_epoch()
        }
        fn load_pin(&mut self) -> Result<PinRecord, jotakey_core::platform::PlatformError> {
            self.0.load_pin()
        }
        fn store_pin(&mut self, r: &PinRecord) -> Result<(), jotakey_core::platform::PlatformError> {
            self.1 += 1;
            if self.1 == 2 { Err(jotakey_core::platform::PlatformError) } else { self.0.store_pin(r) }
        }
        fn uptime_ms(&self) -> u64 {
            self.0.uptime_ms()
        }
    }
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");
    let mut p = FailSecond(h.platform.clone(), 0);
    let mut out = [0u8; jotakey_core::MAX_MSG_SIZE];
    let req = request(
        CLIENT_PIN,
        vec![
            (V::U(1), V::U(2)),
            (V::U(2), V::U(9)),
            (V::U(3), c.key_agreement()),
            (V::U(6), V::B(c.encrypt(&pin_hash(b"1234")))),
            (V::U(9), V::U(GA)),
        ],
    );
    assert_eq!(h.auth.process(&mut p, &req, &mut out), Outcome::Response(1));
    assert_eq!(out[0], Status::Other.code());
    assert!(!h.auth.pin_session().has_token());
    assert_eq!(PinRecord::from_bytes(&p.0.pin).unwrap().retries, PIN_RETRIES_MAX - 1);
}

#[test]
fn change_pin() {
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    assert_eq!(c.change_pin(&mut h, "1234", "5678"), Status::PinNotSet.code());
    c.set_pin(&mut h, "1234");
    let id = register(&mut h, RP);
    let token = c.token(&mut h, "1234", GA, None).unwrap();

    // A bad MAC is refused before the PIN is looked at.
    let pin_hash_enc = c.encrypt(&pin_hash(b"1234"));
    let new_pin_enc = c.encrypt(&padded(b"5678"));
    let bad = hmac(&c.hmac_key, &[&pin_hash_enc, &new_pin_enc]); // wrong order
    let req = |param: &[u8]| {
        request(
            CLIENT_PIN,
            vec![
                (V::U(1), V::U(2)),
                (V::U(2), V::U(4)),
                (V::U(3), c.key_agreement()),
                (V::U(4), V::B(param.to_vec())),
                (V::U(5), V::B(new_pin_enc.clone())),
                (V::U(6), V::B(pin_hash_enc.clone())),
            ],
        )
    };
    assert_eq!(h.status(&req(&bad)), Status::PinAuthInvalid.code());
    assert_eq!(retries(&mut h), 8);

    assert_eq!(c.change_pin(&mut h, "0000", "5678"), Status::PinInvalid.code());
    assert_eq!(retries(&mut h), 7);
    let c = Client::connect(&mut h);
    // A new PIN that breaks the policy: the old PIN was right, so the counter is restored,
    // but nothing changes.
    assert_eq!(c.change_pin(&mut h, "1234", "567"), Status::PinPolicyViolation.code());
    assert_eq!(retries(&mut h), 8);
    assert!(!h.auth.pin_session().has_token(), "the outstanding token was revoked");
    assert_eq!(assert_uv(&mut h, RP, &id, &token, true).0, Status::PinAuthInvalid.code());
    assert_eq!(c.change_pin(&mut h, "1234", "5678"), 0);
    assert_eq!(c.token(&mut h, "1234", GA, None), Err(Status::PinInvalid.code()));
    let c = Client::connect(&mut h);
    assert!(c.token(&mut h, "5678", GA, None).is_ok());
    // Missing members.
    let mut short = vec![(V::U(1), V::U(2)), (V::U(2), V::U(4)), (V::U(3), c.key_agreement())];
    assert_eq!(h.status(&request(CLIENT_PIN, short.clone())), Status::MissingParameter.code());
    short.push((V::U(4), V::B(vec![0; 32])));
    short.push((V::U(5), V::B(vec![0; 80])));
    assert_eq!(h.status(&request(CLIENT_PIN, short)), Status::MissingParameter.code());
}

#[test]
fn set_pin_rules() {
    let mut h = Harness::new();
    // Before any getKeyAgreement there is no shared secret, so no MAC can verify.
    let early = Client::connect(&mut Harness::new());
    assert_eq!(early.set_pin(&mut h, "1234"), Status::PinAuthInvalid.code());

    let c = Client::connect(&mut h);
    let policy = Status::PinPolicyViolation.code();
    assert_eq!(c.set_pin(&mut h, "123"), policy, "three digits");
    assert_eq!(c.set_pin(&mut h, ""), policy);
    assert_eq!(c.set_pin(&mut h, "ñññ"), policy, "six bytes but three code points");
    assert_eq!(h.status(&c.set_pin_request(&[b'7'; 64])), policy, "no terminating zero");
    let mut gap = padded(b"1234");
    gap[10] = 1;
    assert_eq!(h.status(&c.set_pin_request(&gap)), policy, "nonzero padding");
    assert_eq!(h.status(&c.set_pin_request(&[b'7'; 48])), Status::InvalidParameter.code(), "not 64 bytes");
    assert_eq!(h.status(&c.set_pin_request(&[b'7'; 80])), Status::InvalidParameter.code(), "not 64 bytes");
    assert!(!client_pin_set(&mut h));
    // 63 bytes is the longest PIN.
    let long = "9".repeat(63);
    assert_eq!(c.set_pin(&mut h, &long), 0);
    assert_eq!(c.set_pin(&mut h, "1234"), Status::NotAllowed.code());
    assert!(c.token(&mut h, &long, GA, None).is_ok());

    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    assert_eq!(c.set_pin(&mut h, "ññññ"), 0, "four code points");
    assert!(c.token(&mut h, "ññññ", GA, None).is_ok());

    // A bad MAC sets nothing.
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    let new_pin_enc = c.encrypt(&padded(b"1234"));
    let req = request(
        CLIENT_PIN,
        vec![
            (V::U(1), V::U(2)),
            (V::U(2), V::U(3)),
            (V::U(3), c.key_agreement()),
            (V::U(4), V::B(hmac(&c.aes_key, &[&new_pin_enc]).to_vec())),
            (V::U(5), V::B(new_pin_enc)),
        ],
    );
    assert_eq!(h.status(&req), Status::PinAuthInvalid.code());
    assert!(!client_pin_set(&mut h));
}

#[test]
fn request_shape_and_sub_commands() {
    let mut h = Harness::new();
    let st = |h: &mut Harness, p: Vec<(V, V)>| h.status(&request(CLIENT_PIN, p));
    // getPINRetries does not need the protocol; everything else does, and only protocol two.
    assert_eq!(st(&mut h, vec![(V::U(2), V::U(1))]), 0);
    assert_eq!(st(&mut h, vec![(V::U(2), V::U(2))]), Status::MissingParameter.code());
    assert_eq!(st(&mut h, vec![(V::U(1), V::U(1)), (V::U(2), V::U(2))]), Status::InvalidParameter.code());
    assert_eq!(st(&mut h, vec![(V::U(1), V::U(2))]), Status::MissingParameter.code());
    for unsupported in [0, 6, 7, 8, 10, 0x100] {
        assert_eq!(
            st(&mut h, vec![(V::U(1), V::U(2)), (V::U(2), V::U(unsupported))]),
            Status::InvalidSubcommand.code()
        );
    }
    // Members are type-checked, unknown ones skipped.
    assert_eq!(st(&mut h, vec![(V::U(1), V::t("two")), (V::U(2), V::U(2))]), Status::CborUnexpectedType.code());
    assert_eq!(st(&mut h, vec![(V::U(1), V::U(2)), (V::U(2), V::U(2)), (V::U(7), V::A(vec![]))]), 0);
    for (k, v) in [(4, V::U(1)), (5, V::U(1)), (6, V::U(1)), (9, V::t("x")), (10, V::B(vec![]))] {
        assert_eq!(st(&mut h, vec![(V::U(2), V::U(1)), (V::U(k), v)]), Status::CborUnexpectedType.code(), "{k}");
    }
    // The platform key must be a P-256 point.
    let c = Client::connect(&mut h);
    let mut key = c.key_agreement();
    if let V::M(m) = &mut key {
        m[4].1 = V::B(vec![0; 32]);
    }
    assert_eq!(
        st(&mut h, vec![(V::U(1), V::U(2)), (V::U(2), V::U(3)), (V::U(3), key)]),
        Status::InvalidParameter.code()
    );
    // getKeyAgreement returns the same key until a mismatch replaces it.
    let a = h.run(&request(CLIENT_PIN, vec![(V::U(1), V::U(2)), (V::U(2), V::U(2))]), PresenceResult::Confirmed);
    let b = h.run(&request(CLIENT_PIN, vec![(V::U(1), V::U(2)), (V::U(2), V::U(2))]), PresenceResult::Confirmed);
    assert_eq!(a, b);
    c.set_pin(&mut h, "1234");
    c.token(&mut h, "0000", GA, None).unwrap_err();
    let after = h.run(&request(CLIENT_PIN, vec![(V::U(1), V::U(2)), (V::U(2), V::U(2))]), PresenceResult::Confirmed);
    assert_ne!(a, after);
    // A failing RNG cannot make a key.
    let mut h = Harness::new();
    h.platform.fail_rng = true;
    assert_eq!(st(&mut h, vec![(V::U(1), V::U(2)), (V::U(2), V::U(2))]), Status::Other.code());
}

#[test]
fn pin_hash_enc_must_be_one_block() {
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");
    for len in [16, 48] {
        let p = vec![
            (V::U(1), V::U(2)),
            (V::U(2), V::U(9)),
            (V::U(3), c.key_agreement()),
            (V::U(6), V::B(vec![0; len])),
            (V::U(9), V::U(GA)),
        ];
        assert_eq!(c.token_from(&mut h, p), Err(Status::InvalidParameter.code()));
    }
    assert_eq!(retries(&mut h), 8, "malformed attempts are not counted");
    let mut p = vec![(V::U(1), V::U(2)), (V::U(2), V::U(9)), (V::U(3), c.key_agreement()), (V::U(9), V::U(GA))];
    assert_eq!(c.token_from(&mut h, p.clone()), Err(Status::MissingParameter.code()));
    p.remove(2);
    p.push((V::U(6), V::B(c.encrypt(&pin_hash(b"1234")))));
    assert_eq!(c.token_from(&mut h, p), Err(Status::MissingParameter.code()));
    // No PIN, no token.
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    assert_eq!(c.token(&mut h, "1234", GA, None), Err(Status::PinNotSet.code()));
}

#[test]
fn probe_and_reset_with_a_pin() {
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");
    let id = register(&mut h, RP);
    let mut p = make_credential_params(RP);
    p.push((V::U(8), V::B(vec![])));
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, p)), Status::PinInvalid.code());
    h.platform.fail_pin = true;
    let mut p = make_credential_params(RP);
    p.push((V::U(8), V::B(vec![])));
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, p)), Status::Other.code());
    h.platform.fail_pin = false;

    // Reset removes the PIN and every token, and the credentials with them.
    let token = c.token(&mut h, "1234", GA, None).unwrap();
    assert_eq!(h.status(&[RESET]), 0);
    assert!(!client_pin_set(&mut h));
    assert!(!h.auth.pin_session().has_token());
    assert_eq!(assert_uv(&mut h, RP, &id, &token, true).0, Status::PinAuthInvalid.code());
    assert_eq!(h.status(&request(GET_ASSERTION, get_assertion_params(RP, &[&id]))), Status::NoCredentials.code());
    // A PIN store that fails after the epoch rotated: the reset reports failure.
    h.platform.fail_pin_store = true;
    assert_eq!(h.status(&[RESET]), Status::Other.code());
}

#[test]
fn the_session_does_not_print_its_keys() {
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");
    c.token(&mut h, "1234", GA, None).unwrap();
    assert_eq!(format!("{:?}", h.auth.pin_session()), "PinSession { token: true, mismatches: 0, .. }");
    assert!(format!("{:?}", h.auth).contains("PinSession { token: true"));
}

#[test]
fn the_verifier_is_bound_to_the_epoch() {
    // Power lost between the two halves of a reset: the epoch is new, the PIN record old.
    let mut h = Harness::new();
    let c = Client::connect(&mut h);
    c.set_pin(&mut h, "1234");
    h.platform.rotate_epoch().unwrap();
    assert_eq!(c.token(&mut h, "1234", GA, None), Err(Status::PinInvalid.code()));
    // And the stored verifier is the hardware key store's, not a bare hash.
    let record = PinRecord::from_bytes(&h.platform.pin).unwrap();
    assert_ne!(record.verifier.unwrap()[..16], pin_hash(b"1234"));
}
