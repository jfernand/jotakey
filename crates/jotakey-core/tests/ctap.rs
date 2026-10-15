//! End-to-end CTAP2 behaviour of the core against the mock platform.

mod common;

use common::*;
use jotakey_core::authdata::{FLAG_AT, FLAG_UP};
use jotakey_core::cbor::Decoder;
use jotakey_core::crypto::{sha256, verify};
use jotakey_core::ctap::{Outcome, Pending, command::*};
use jotakey_core::platform::UpResult;
use jotakey_core::status::Status;

/// Register a credential; returns (credential id, public key, authData counter).
fn register(h: &mut Harness, rp: &str) -> (Vec<u8>, p256::PublicKey, u32) {
    let (st, body) = h.run(&request(MAKE_CREDENTIAL, make_credential_params(rp)), UpResult::Confirmed);
    assert_eq!(st, 0, "makeCredential failed");
    // Strict decoder must accept our own response.
    let mut d = Decoder::new(&body);
    d.skip(0).unwrap();
    d.finish().unwrap();

    let (resp, _) = V::decode(&body);
    assert_eq!(resp.get(&V::U(1)), Some(&V::t("packed")));
    let ad = resp.get(&V::U(2)).unwrap().bytes().to_vec();
    assert_eq!(&ad[..32], &sha256(&[rp.as_bytes()]));
    assert_eq!(ad[32], FLAG_UP | FLAG_AT);
    let counter = u32::from_be_bytes(ad[33..37].try_into().unwrap());
    assert_eq!(&ad[37..53], &jotakey_core::AAGUID);
    let id_len = u16::from_be_bytes(ad[53..55].try_into().unwrap()) as usize;
    let id = ad[55..55 + id_len].to_vec();
    let (cose, used) = V::decode(&ad[55 + id_len..]);
    assert_eq!(55 + id_len + used, ad.len());
    let x = cose.get(&V::int(-2)).unwrap().bytes();
    let y = cose.get(&V::int(-3)).unwrap().bytes();
    let mut sec1 = vec![4u8];
    sec1.extend(x);
    sec1.extend(y);
    let pk = p256::PublicKey::from_sec1_bytes(&sec1).unwrap();

    // Packed self-attestation: signature by the credential key over authData ‖ cdh.
    let att = resp.get(&V::U(3)).unwrap();
    assert_eq!(att.get(&V::t("alg")), Some(&V::int(-7)));
    assert!(verify(&pk, &[&ad, &CDH], att.get(&V::t("sig")).unwrap().bytes()));
    (id, pk, counter)
}

fn assert_ok(h: &mut Harness, rp: &str, id: &[u8], pk: &p256::PublicKey) -> u32 {
    let (st, body) = h.run(&request(GET_ASSERTION, get_assertion_params(rp, &[id])), UpResult::Confirmed);
    assert_eq!(st, 0);
    let (resp, _) = V::decode(&body);
    let cred = resp.get(&V::U(1)).unwrap();
    assert_eq!(cred.get(&V::t("id")).unwrap().bytes(), id);
    let ad = resp.get(&V::U(2)).unwrap().bytes();
    assert_eq!(ad.len(), 37);
    assert_eq!(ad[32], FLAG_UP);
    assert!(verify(pk, &[ad, &CDH], resp.get(&V::U(3)).unwrap().bytes()));
    u32::from_be_bytes(ad[33..37].try_into().unwrap())
}

#[test]
fn get_info() {
    let mut h = Harness::new();
    let (st, body) = h.run(&[GET_INFO], UpResult::Confirmed);
    assert_eq!(st, 0);
    let (info, _) = V::decode(&body);
    assert_eq!(info.get(&V::U(1)), Some(&V::A(vec![V::t("FIDO_2_0")])));
    assert_eq!(info.get(&V::U(3)), Some(&V::B(jotakey_core::AAGUID.to_vec())));
    let opts = info.get(&V::U(4)).unwrap();
    assert_eq!(opts.get(&V::t("rk")), Some(&V::Bool(false)));
    assert_eq!(opts.get(&V::t("up")), Some(&V::Bool(true)));
    assert_eq!(opts.get(&V::t("uv")), None);
    assert_eq!(info.get(&V::U(5)), Some(&V::U(1200)));
    Decoder::new(&body).skip(0).unwrap();
    assert_eq!(h.status(&[GET_INFO, 0xa0]), Status::InvalidLength.code());
}

#[test]
fn register_then_authenticate_with_monotonic_counter() {
    let mut h = Harness::new();
    let (id, pk, c0) = register(&mut h, RP);
    assert_eq!(id.len(), 49);
    let c1 = assert_ok(&mut h, RP, &id, &pk);
    let c2 = assert_ok(&mut h, RP, &id, &pk);
    assert!(c0 < c1 && c1 < c2);
    assert_eq!(h.platform.counter, c2);
}

#[test]
fn credential_is_bound_to_rp() {
    let mut h = Harness::new();
    let (id, _, _) = register(&mut h, RP);
    let st = h.status(&request(GET_ASSERTION, get_assertion_params("evil.example", &[&id])));
    assert_eq!(st, Status::NoCredentials.code());
}

#[test]
fn foreign_and_tampered_ids_are_rejected_and_first_valid_is_used() {
    let mut h = Harness::new();
    let (id, pk, _) = register(&mut h, RP);
    let mut bad = id.clone();
    bad[10] ^= 1;
    let st = h.status(&request(GET_ASSERTION, get_assertion_params(RP, &[&bad, &[0u8; 64]])));
    assert_eq!(st, Status::NoCredentials.code());
    let (st, body) = h.run(&request(GET_ASSERTION, get_assertion_params(RP, &[&bad, &id])), UpResult::Confirmed);
    assert_eq!(st, 0);
    let (resp, _) = V::decode(&body);
    assert_eq!(resp.get(&V::U(1)).unwrap().get(&V::t("id")).unwrap().bytes(), &id[..]);
    let ad = resp.get(&V::U(2)).unwrap().bytes();
    assert!(verify(&pk, &[ad, &CDH], resp.get(&V::U(3)).unwrap().bytes()));
}

#[test]
fn no_signature_without_presence() {
    let mut h = Harness::new();
    let (id, _, _) = register(&mut h, RP);
    let counter = h.platform.counter;
    for (up, want) in [(UpResult::Timeout, Status::UserActionTimeout), (UpResult::Cancelled, Status::KeepaliveCancel)] {
        let (st, body) = h.run(&request(GET_ASSERTION, get_assertion_params(RP, &[&id])), up);
        assert_eq!(st, want.code());
        assert!(body.is_empty());
        let (st, body) = h.run(&request(MAKE_CREDENTIAL, make_credential_params(RP)), up);
        assert_eq!(st, want.code());
        assert!(body.is_empty());
    }
    assert_eq!(h.platform.counter, counter, "counter must not move without a signature");
}

#[test]
fn processing_parks_and_complete_consumes() {
    let mut h = Harness::new();
    let req = request(MAKE_CREDENTIAL, make_credential_params(RP));
    assert_eq!(h.auth.process(&mut h.platform, &req, &mut h.out), Outcome::NeedsUserPresence);
    assert!(matches!(h.auth.pending(), Pending::MakeCredential { .. }));
    // A new request supersedes the parked one.
    assert!(matches!(h.auth.process(&mut h.platform, &[GET_INFO], &mut h.out), Outcome::Response(_)));
    assert_eq!(h.auth.pending(), &Pending::Idle);
    // Completing with nothing pending is an error, never a signature.
    let n = h.auth.complete(&mut h.platform, UpResult::Confirmed, &mut h.out);
    assert_eq!((n, h.out[0]), (1, Status::Other.code()));
    // Completing twice signs at most once.
    assert_eq!(h.auth.process(&mut h.platform, &req, &mut h.out), Outcome::NeedsUserPresence);
    let n = h.auth.complete(&mut h.platform, UpResult::Confirmed, &mut h.out);
    assert!(n > 1);
    let n = h.auth.complete(&mut h.platform, UpResult::Confirmed, &mut h.out);
    assert_eq!((n, h.out[0]), (1, Status::Other.code()));
}

#[test]
fn exclude_list() {
    let mut h = Harness::new();
    let (id, _, _) = register(&mut h, RP);
    let mut params = make_credential_params(RP);
    params.push((V::U(5), V::A(vec![descriptor(&[9; 49]), descriptor(&id)])));
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, params.clone())), Status::CredentialExcluded.code());
    // Same id under a different RP is not excluded.
    let mut other = make_credential_params("other.example");
    other.push((V::U(5), V::A(vec![descriptor(&id)])));
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, other)), 0);
}

#[test]
fn options_policy() {
    let mut h = Harness::new();
    let (id, _, _) = register(&mut h, RP);
    let with_opts = |base: Vec<(V, V)>, key: u64, opts: Vec<(V, V)>| {
        let mut p = base;
        p.push((V::U(key), V::M(opts)));
        p
    };
    let mc = |o| request(MAKE_CREDENTIAL, with_opts(make_credential_params(RP), 7, o));
    let ga = |o| request(GET_ASSERTION, with_opts(get_assertion_params(RP, &[&id]), 5, o));
    assert_eq!(h.status(&mc(vec![(V::t("rk"), V::Bool(true))])), Status::UnsupportedOption.code());
    assert_eq!(h.status(&mc(vec![(V::t("uv"), V::Bool(true))])), Status::UnsupportedOption.code());
    assert_eq!(h.status(&mc(vec![(V::t("up"), V::Bool(true))])), Status::InvalidOption.code());
    assert_eq!(h.status(&mc(vec![(V::t("rk"), V::Bool(false)), (V::t("uv"), V::Bool(false))])), 0);
    assert_eq!(h.status(&ga(vec![(V::t("up"), V::Bool(false))])), Status::UnsupportedOption.code());
    assert_eq!(h.status(&ga(vec![(V::t("uv"), V::Bool(true))])), Status::UnsupportedOption.code());
    assert_eq!(h.status(&ga(vec![(V::t("rk"), V::Bool(false))])), Status::InvalidOption.code());
    assert_eq!(h.status(&ga(vec![(V::t("up"), V::Bool(true))])), 0);
    // Option values must be booleans.
    assert_eq!(h.status(&ga(vec![(V::t("xx"), V::U(1))])), Status::CborUnexpectedType.code());
}

#[test]
fn algorithm_negotiation() {
    let mut h = Harness::new();
    let mut p = make_credential_params(RP);
    p[3].1 = V::A(vec![V::M(vec![(V::t("alg"), V::int(-8)), (V::t("type"), V::t("public-key"))])]);
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, p.clone())), Status::UnsupportedAlgorithm.code());
    p[3].1 = V::A(vec![
        V::M(vec![(V::t("alg"), V::int(-8)), (V::t("type"), V::t("public-key"))]),
        V::M(vec![(V::t("alg"), V::int(-7)), (V::t("type"), V::t("public-key"))]),
    ]);
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, p)), 0);
}

#[test]
fn pin_auth_probe() {
    let mut h = Harness::new();
    let mut p = make_credential_params(RP);
    p.push((V::U(8), V::B(vec![])));
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, p.clone())), Status::PinNotSet.code());
    p.last_mut().unwrap().1 = V::B(vec![1; 16]);
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, p)), Status::PinAuthInvalid.code());
}

#[test]
fn missing_and_malformed_parameters() {
    let mut h = Harness::new();
    for drop in 0..4 {
        let mut p = make_credential_params(RP);
        p.remove(drop);
        assert_eq!(h.status(&request(MAKE_CREDENTIAL, p)), Status::MissingParameter.code(), "drop {drop}");
    }
    let mut p = make_credential_params(RP);
    p[0].1 = V::B(vec![0; 31]);
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, p)), Status::InvalidLength.code());
    let mut p = make_credential_params(RP);
    p[0].1 = V::t("not bytes");
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, p)), Status::CborUnexpectedType.code());
    // Non-canonical: keys out of order.
    let mut raw = vec![MAKE_CREDENTIAL, 0xa2, 0x09, 0x00, 0x08, 0x40]; // {9: 0, 8: h''}
    assert_eq!(h.status(&raw), Status::InvalidCbor.code());
    // Trailing garbage.
    raw = request(GET_ASSERTION, get_assertion_params(RP, &[&[0; 49]]));
    raw.push(0);
    assert_eq!(h.status(&raw), Status::InvalidCbor.code());
    // Empty request and unknown command.
    assert_eq!(h.status(&[]), Status::InvalidLength.code());
    assert_eq!(h.status(&[0x42]), Status::InvalidCommand.code());
    assert_eq!(h.status(&[CLIENT_PIN, 0xa0]), Status::InvalidCommand.code());
    // No allow list: nothing to sign with.
    assert_eq!(
        h.status(&request(GET_ASSERTION, vec![(V::U(1), V::t(RP)), (V::U(2), V::B(CDH.to_vec()))])),
        Status::NoCredentials.code()
    );
}

#[test]
fn reset_window_and_effect() {
    let mut h = Harness::new();
    let (id, _, _) = register(&mut h, RP);
    h.platform.uptime = 10_001;
    assert_eq!(h.status(&[RESET]), Status::NotAllowed.code());
    h.platform.uptime = 9_000;
    assert_eq!(h.run(&[RESET], UpResult::Timeout).0, Status::UserActionTimeout.code());
    let counter = h.platform.counter;
    assert_eq!(h.status(&[RESET]), 0);
    assert_eq!(h.platform.counter, counter, "reset never rewinds the counter");
    assert_eq!(h.status(&request(GET_ASSERTION, get_assertion_params(RP, &[&id]))), Status::NoCredentials.code());
    assert_eq!(h.status(&[RESET, 0x00]), Status::InvalidLength.code());
}

#[test]
fn fails_closed() {
    let mut h = Harness::new();
    let (id, _, _) = register(&mut h, RP);
    h.platform.fail_counter = true;
    let before = h.platform.counter;
    assert_eq!(h.status(&request(GET_ASSERTION, get_assertion_params(RP, &[&id]))), Status::Other.code());
    assert_eq!(h.platform.counter, before);
    h.platform.fail_counter = false;
    h.platform.fail_rng = true;
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, make_credential_params(RP))), Status::Other.code());
    h.platform.fail_rng = false;
    h.platform.fail_derive = true;
    assert_eq!(h.status(&request(GET_ASSERTION, get_assertion_params(RP, &[&id]))), Status::Other.code());
    h.platform.fail_derive = false;
    h.auth.fault();
    assert_eq!(h.status(&[GET_INFO]), Status::Other.code());
}

// ---------- Tests driven by mutation testing (each pins a behaviour a mutant broke) ----------

#[test]
fn status_codes_match_the_spec() {
    // Literal values from CTAP 2.0 §6.3, so a broken `Status::code` cannot hide behind
    // tests that compare against `Status::X.code()`.
    let table = [
        (Status::Success, 0x00),
        (Status::InvalidCommand, 0x01),
        (Status::InvalidLength, 0x03),
        (Status::CborUnexpectedType, 0x11),
        (Status::InvalidCbor, 0x12),
        (Status::MissingParameter, 0x14),
        (Status::CredentialExcluded, 0x19),
        (Status::UnsupportedAlgorithm, 0x26),
        (Status::UnsupportedOption, 0x2B),
        (Status::InvalidOption, 0x2C),
        (Status::KeepaliveCancel, 0x2D),
        (Status::NoCredentials, 0x2E),
        (Status::UserActionTimeout, 0x2F),
        (Status::NotAllowed, 0x30),
        (Status::PinAuthInvalid, 0x33),
        (Status::PinNotSet, 0x35),
        (Status::Other, 0x7F),
    ];
    for (s, code) in table {
        assert_eq!(s.code(), code, "{s:?}");
    }
    let mut h = Harness::new();
    assert_eq!(h.status(&[0x42]), 0x01);
}

#[test]
fn fault_and_abort_accessors() {
    let mut h = Harness::new();
    assert!(!h.auth.is_faulted());
    let req = request(MAKE_CREDENTIAL, make_credential_params(RP));
    assert_eq!(h.auth.process(&mut h.platform, &req, &mut h.out), Outcome::NeedsUserPresence);
    h.auth.abort();
    assert_eq!(h.auth.pending(), &Pending::Idle);
    let n = h.auth.complete(&mut h.platform, UpResult::Confirmed, &mut h.out);
    assert_eq!((n, h.out[0]), (1, 0x7F), "aborted command must not complete");
    h.auth.fault();
    assert!(h.auth.is_faulted());
}

#[test]
fn complete_with_nothing_pending_is_other_whatever_the_presence_result() {
    let mut h = Harness::new();
    for up in [UpResult::Confirmed, UpResult::Timeout, UpResult::Cancelled] {
        let n = h.auth.complete(&mut h.platform, up, &mut h.out);
        assert_eq!((n, h.out[0]), (1, 0x7F), "{up:?}");
    }
}

#[test]
fn optional_members_are_type_checked() {
    let mut h = Harness::new();
    let (id, _, _) = register(&mut h, RP);
    let with = |mut p: Vec<(V, V)>, k: u64, v: V| {
        p.push((V::U(k), v));
        p
    };
    let unexpected = Status::CborUnexpectedType.code();
    // makeCredential: extensions (6) must be a map, pinProtocol (9) an unsigned integer.
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, with(make_credential_params(RP), 6, V::U(1)))), unexpected);
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, with(make_credential_params(RP), 6, V::M(vec![])))), 0);
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, with(make_credential_params(RP), 9, V::t("one")))), unexpected);
    // getAssertion: extensions (4), pinAuth (6), pinProtocol (7).
    let ga = || get_assertion_params(RP, &[&id]);
    assert_eq!(h.status(&request(GET_ASSERTION, with(ga(), 4, V::U(1)))), unexpected);
    assert_eq!(h.status(&request(GET_ASSERTION, with(ga(), 4, V::M(vec![])))), 0);
    assert_eq!(h.status(&request(GET_ASSERTION, with(ga(), 6, V::B(vec![])))), Status::PinNotSet.code());
    assert_eq!(h.status(&request(GET_ASSERTION, with(ga(), 6, V::B(vec![1; 16])))), Status::PinAuthInvalid.code());
    assert_eq!(h.status(&request(GET_ASSERTION, with(ga(), 7, V::t("one")))), unexpected);
    // Entity members and descriptor transports are type-checked too.
    let mut p = make_credential_params(RP);
    p[1].1 = V::M(vec![(V::t("id"), V::t(RP)), (V::t("name"), V::U(5))]);
    assert_eq!(h.status(&request(MAKE_CREDENTIAL, p)), unexpected);
    let bad_desc = V::M(vec![
        (V::t("id"), V::B(id.clone())),
        (V::t("type"), V::t("public-key")),
        (V::t("transports"), V::A(vec![V::U(1)])),
    ]);
    assert_eq!(h.status(&request(GET_ASSERTION, vec![(V::U(1), V::t(RP)), (V::U(2), V::B(CDH.to_vec())), (V::U(3), V::A(vec![bad_desc]))])), unexpected);
    let good_desc = V::M(vec![
        (V::t("id"), V::B(id.clone())),
        (V::t("type"), V::t("public-key")),
        (V::t("transports"), V::A(vec![V::t("usb")])),
    ]);
    assert_eq!(h.status(&request(GET_ASSERTION, vec![(V::U(1), V::t(RP)), (V::U(2), V::B(CDH.to_vec())), (V::U(3), V::A(vec![good_desc]))])), 0);
}

#[test]
fn user_id_length_boundary() {
    let mut h = Harness::new();
    for (len, want) in [(64usize, 0u8), (65, Status::InvalidLength.code())] {
        let mut p = make_credential_params(RP);
        p[2].1 = V::M(vec![(V::t("id"), V::B(vec![7; len]))]);
        assert_eq!(h.status(&request(MAKE_CREDENTIAL, p)), want, "user.id of {len} bytes");
    }
}

#[test]
fn reset_window_boundary_is_inclusive() {
    let mut h = Harness::new();
    h.platform.uptime = 10_000;
    assert_eq!(h.status(&[RESET]), 0);
}
