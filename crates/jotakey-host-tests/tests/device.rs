// (c) Javier Fernandez @ JotaSoft 2026
//! End-to-end tests against a **real** Jotakey through `jotakey-bridge`.
//!
//! Ignored by default. With the board on the USB-Serial/JTAG port and the bridge running:
//!
//! ```sh
//! cargo run -p jotakey-bridge --release -- /dev/ttyACM0 &
//! cargo test -p jotakey-host-tests --test device -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! Touch the BOOT button whenever the LED blinks amber.

use jotakey_host_tests::cbor::Value;
use jotakey_host_tests::webauthn::{self, verify_assertion, verify_registration};
use jotakey_host_tests::{Client, Hidraw};

const RP: &str = "jotakey.test";

fn client() -> Client<Hidraw> {
    let path = Hidraw::find().expect("bridge device");
    Client::connect(Hidraw::open(&path).expect("open hidraw")).expect("INIT")
}

#[test]
#[ignore = "needs a Jotakey and jotakey-bridge"]
fn device_info_and_ping() {
    let mut c = client();
    assert_eq!(c.ping(b"jotakey").unwrap(), b"jotakey");
    let r = c.cbor(0x04, &[]).unwrap();
    assert_eq!(r.status, 0);
    let (info, _) = Value::decode(&r.body).unwrap();
    assert_eq!(info.get(&Value::Int(1)), Some(&Value::Array(vec![Value::t("FIDO_2_0")])));
}

#[test]
#[ignore = "needs a Jotakey and jotakey-bridge; touch the button twice"]
fn device_register_and_authenticate() {
    let mut c = client();
    let cdh = [0x11; 32];
    eprintln!(">>> touch the button to REGISTER");
    let r = c.cbor(0x01, &webauthn::make_credential(RP, &cdh, &[])).unwrap();
    assert_eq!(r.status, 0);
    let cred = verify_registration(RP, &cdh, &r.body).unwrap();
    eprintln!(">>> touch the button to AUTHENTICATE");
    let r = c.cbor(0x02, &webauthn::get_assertion(RP, &cdh, &[&cred.id])).unwrap();
    assert_eq!(r.status, 0);
    let counter = verify_assertion(RP, &cdh, &cred, &r.body).unwrap();
    assert!(counter > cred.counter);
}

#[test]
#[ignore = "needs a Jotakey and jotakey-bridge; do NOT touch the button (30 s)"]
fn device_times_out_without_touch() {
    let mut c = client();
    eprintln!(">>> do NOT touch the button; waiting for the 30 s timeout");
    let r = c.cbor(0x01, &webauthn::make_credential(RP, &[0x22; 32], &[])).unwrap();
    assert_eq!(r.status, 0x2F);
    assert!(r.up_keepalives > 0);
}
