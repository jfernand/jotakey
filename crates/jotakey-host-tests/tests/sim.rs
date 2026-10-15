//! End-to-end WebAuthn flows against the in-process simulated device. Same code path as
//! firmware + bridge, minus the hardware.

use jotakey_host_tests::cbor::Value;
use jotakey_host_tests::webauthn::{self, verify_assertion, verify_registration};
use jotakey_host_tests::{Client, SimDevice, User};

const RP: &str = "login.example.com";
const MC: u8 = 0x01;
const GA: u8 = 0x02;
const INFO: u8 = 0x04;
const RESET: u8 = 0x07;

fn client() -> Client<SimDevice> {
    Client::connect(SimDevice::new(42)).expect("INIT")
}

#[test]
fn ping_and_wink() {
    let mut c = client();
    let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    assert_eq!(c.ping(&data).unwrap(), data);
    c.wink().unwrap();
}

#[test]
fn get_info_advertises_fido2() {
    let mut c = client();
    let r = c.cbor(INFO, &[]).unwrap();
    assert_eq!(r.status, 0);
    let (info, _) = Value::decode(&r.body).unwrap();
    assert_eq!(info.get(&Value::Int(1)), Some(&Value::Array(vec![Value::t("FIDO_2_0")])));
}

#[test]
fn register_and_authenticate_like_a_relying_party() {
    let mut c = client();
    let cdh = [1u8; 32];
    let r = c.cbor(MC, &webauthn::make_credential(RP, &cdh, &[])).unwrap();
    assert_eq!(r.status, 0, "makeCredential");
    assert!(r.up_keepalives >= 1, "device must ask for a touch with UP_NEEDED keepalives");
    let cred = verify_registration(RP, &cdh, &r.body).unwrap();

    let mut last = cred.counter;
    for i in 0..5u8 {
        let cdh = [i; 32];
        let r = c.cbor(GA, &webauthn::get_assertion(RP, &cdh, &[&cred.id])).unwrap();
        assert_eq!(r.status, 0, "getAssertion {i}");
        let counter = verify_assertion(RP, &cdh, &cred, &r.body).unwrap();
        assert!(counter > last, "counter must increase");
        last = counter;
    }

    // Phishing site: same credential id, different RP → no credentials.
    let r = c.cbor(GA, &webauthn::get_assertion("login.examp1e.com", &cdh, &[&cred.id])).unwrap();
    assert_eq!(r.status, 0x2E);
    // Exclude list recognises the credential.
    let r = c.cbor(MC, &webauthn::make_credential(RP, &cdh, &[&cred.id])).unwrap();
    assert_eq!(r.status, 0x19);
}

#[test]
fn absent_user_times_out() {
    let mut c = client();
    let cdh = [3u8; 32];
    c.io_mut().user = User::Absent;
    let r = c.cbor(MC, &webauthn::make_credential(RP, &cdh, &[])).unwrap();
    assert_eq!(r.status, 0x2F, "CTAP2_ERR_USER_ACTION_TIMEOUT");
    assert_eq!(c.io_mut().platform.counter, 0, "no signature, no counter movement");
}

#[test]
fn reset_invalidates_credentials() {
    let mut c = client();
    let cdh = [5u8; 32];
    let r = c.cbor(MC, &webauthn::make_credential(RP, &cdh, &[])).unwrap();
    let cred = verify_registration(RP, &cdh, &r.body).unwrap();
    assert_eq!(c.cbor(RESET, &[]).unwrap().status, 0);
    let r = c.cbor(GA, &webauthn::get_assertion(RP, &cdh, &[&cred.id])).unwrap();
    assert_eq!(r.status, 0x2E);
    c.io_mut().platform.uptime = 60_000;
    assert_eq!(c.cbor(RESET, &[]).unwrap().status, 0x30, "reset only within 10 s of power-up");
}
