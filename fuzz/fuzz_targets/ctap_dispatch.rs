// (c) Javier Fernandez @ JotaSoft 2026
//! CTAP2 command layer with invariant oracles.
//!
//! Input layout: `[mode, up, ...rest]`.
//! - mode even: `rest` is a raw request.
//! - mode odd: `rest` mutates a valid makeCredential/getAssertion template (byte overwrites),
//!   so the fuzzer reaches deep validation paths without a corpus.
//!
//! Oracles:
//! - no panic; response length is 1..=MAX_MSG_SIZE;
//! - the counter moves only on a successful makeCredential/getAssertion, and then by exactly
//!   one (invariant 2);
//! - a signature that was parked needed `PresenceResult::Confirmed`; one produced without
//!   parking is a getAssertion whose signed data has the UP flag clear (invariant 1);
//! - every successful response body is canonical CBOR (strict decoder accepts it);
//! - nothing stays parked once a response has been produced;
//! - no single request can set, change or spend the PIN (a fresh authenticator has no
//!   key-agreement key, so nothing can be authenticated), and nothing signs with UV.

#![no_main]

use jotakey_core::authdata::{FLAG_UP, FLAG_UV};
use jotakey_core::cbor::{Decoder, Encoder, Key};
use jotakey_core::ctap::{Authenticator, Outcome, command};
use jotakey_core::mock::MockPlatform;
use jotakey_core::platform::PresenceResult;
use jotakey_core::{AAGUID, MAX_MSG_SIZE};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn template(get_assertion: bool, cred_id: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let mut e = Encoder::new(&mut buf);
    let r: Result<(), _> = (|| {
        if get_assertion {
            e.raw(&[command::GET_ASSERTION])?;
            e.map(4)?;
            e.unsigned(1)?;
            e.text("example.com")?;
            e.unsigned(2)?;
            e.bytes(&[0xCD; 32])?;
            e.unsigned(3)?;
            e.array(1)?;
            e.map(2)?;
            e.text("id")?;
            e.bytes(cred_id)?;
            e.text("type")?;
            e.text("public-key")?;
            // options {"up": true}: one byte (0xf5 -> 0xf4) away from a silent assertion.
            e.unsigned(5)?;
            e.map(1)?;
            e.text("up")?;
            e.boolean(true)
        } else {
            e.raw(&[command::MAKE_CREDENTIAL])?;
            e.map(5)?;
            e.unsigned(1)?;
            e.bytes(&[0xCD; 32])?;
            e.unsigned(2)?;
            e.map(1)?;
            e.text("id")?;
            e.text("example.com")?;
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
            e.unsigned(5)?;
            e.array(1)?;
            e.map(2)?;
            e.text("id")?;
            e.bytes(cred_id)?;
            e.text("type")?;
            e.text("public-key")
        }
    })();
    r.expect("template fits");
    let n = e.len();
    buf.truncate(n);
    buf
}

static BASE: OnceLock<(MockPlatform, Vec<u8>)> = OnceLock::new();

fn setup() -> (MockPlatform, Vec<u8>) {
    let mut platform = MockPlatform::new(7);
    let mut auth = Authenticator::new(AAGUID);
    let mut out = Box::new([0u8; MAX_MSG_SIZE]);
    let mc = template(false, &[0u8; 49]);
    let _ = auth.process(&mut platform, &mc, &mut out);
    let n = auth.complete(&mut platform, PresenceResult::Confirmed, &mut out);
    assert_eq!(out[0], 0, "template registration must succeed");
    // authData is map key 2: 0x02, then a byte-string head 0x58 <len>.
    let body = &out[1..n];
    let pos = body.windows(2).position(|w| w == [0x02, 0x58]).expect("authData key");
    let ad = &body[pos + 3..];
    (platform, ad[55..55 + 49].to_vec())
}

/// The flags byte of the authenticator data in a getAssertion response (key 2).
fn assertion_flags(body: &[u8]) -> u8 {
    let mut d = Decoder::new(body);
    let mut m = d.map().expect("response map");
    while let Some(k) = d.next_key(&mut m).expect("response key") {
        if k == Key::Int(2) {
            return d.bytes().expect("authData")[32];
        }
        d.skip(1).expect("response value");
    }
    panic!("getAssertion response without authData")
}

fuzz_target!(|data: &[u8]| {
    let [mode, up, rest @ ..] = data else { return };
    let up = match up % 3 {
        0 => PresenceResult::Confirmed,
        1 => PresenceResult::Timeout,
        _ => PresenceResult::Cancelled,
    };
    // A genuine credential (computed once) so mutated getAssertions reach the success path.
    let (base_platform, cred_id) = BASE.get_or_init(setup);
    let mut platform = base_platform.clone();
    platform.uptime = u64::from(*mode) * 100; // sometimes inside the reset window
    let mut auth = Authenticator::new(AAGUID);
    let mut out = Box::new([0u8; MAX_MSG_SIZE]);

    let request: Vec<u8> = if mode % 2 == 0 {
        rest.to_vec()
    } else {
        let mut t = template(mode % 4 == 1, cred_id);
        for pair in rest.chunks(2) {
            if let [pos, val] = pair {
                let i = usize::from(*pos) % t.len();
                t[i] = *val;
            }
        }
        t
    };

    let before = platform.counter;
    let pin_before = platform.pin;
    let mut parked = false;
    let n = match auth.process(&mut platform, &request, &mut out) {
        Outcome::Response(n) => n,
        Outcome::NeedsUserPresence => {
            parked = true;
            auth.complete(&mut platform, up, &mut out)
        }
    };
    assert!((1..=MAX_MSG_SIZE).contains(&n));
    let status = out[0];
    let cmd = request.first().copied();
    let signing_cmd = matches!(cmd, Some(command::MAKE_CREDENTIAL | command::GET_ASSERTION));
    if status == 0 && signing_cmd {
        if parked {
            assert_eq!(up, PresenceResult::Confirmed, "signature without user presence");
        } else {
            assert_eq!(cmd, Some(command::GET_ASSERTION), "only getAssertion signs silently");
            assert_eq!(assertion_flags(&out[1..n]) & FLAG_UP, 0, "silent signature with UP set");
        }
        assert_eq!(platform.counter, before + 1, "counter must move by exactly one");
        // makeCredential's authData is member 2 as well.
        assert_eq!(assertion_flags(&out[1..n]) & FLAG_UV, 0, "UV without a token");
    } else {
        assert_eq!(platform.counter, before, "counter moved without a signature");
    }
    if status == 0 && n > 1 {
        let mut d = Decoder::new(&out[1..n]);
        d.skip(0).expect("response must be canonical CBOR");
        d.finish().expect("no trailing bytes in response");
    }
    assert_eq!(platform.pin, pin_before, "the PIN record changed");
    // Nothing may remain parked after complete.
    assert_eq!(auth.pending(), &jotakey_core::ctap::Pending::Idle);
});
