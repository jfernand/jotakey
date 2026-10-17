// (c) Javier Fernandez @ JotaSoft 2026
//! Credential IDs: arbitrary bytes never panic, and anything accepted is exactly the ID
//! `wrap` would mint for the recovered nonce at the same RP (no alternate encodings).

#![no_main]

use jotakey_core::credential::{unwrap, wrap};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let (key, rest) = data.split_at(32);
    let (rp, id) = rest.split_at(32);
    let key: [u8; 32] = key.try_into().unwrap();
    let rp: [u8; 32] = rp.try_into().unwrap();
    if let Some(nonce) = unwrap(&key, &rp, id) {
        assert_eq!(&wrap(&key, &rp, &nonce).unwrap()[..], id);
    }
    // Round trip with the fuzzer-chosen nonce as well.
    if id.len() >= 32 {
        let nonce: [u8; 32] = id[..32].try_into().unwrap();
        let minted = wrap(&key, &rp, &nonce).unwrap();
        assert_eq!(unwrap(&key, &rp, &minted), Some(nonce));
    }
});
