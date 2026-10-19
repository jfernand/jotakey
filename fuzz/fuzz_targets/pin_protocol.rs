// (c) Javier Fernandez @ JotaSoft 2026
//! PIN/UV auth protocol two: the platform's key-agreement key and the encrypted and
//! authenticated messages that follow it.
//!
//! Input: `scalar(32) ‖ n(1) ‖ cose_key(n) ‖ message`. The scalar is the authenticator's
//! key-agreement key. A rejected COSE key falls back to the authenticator's own public key,
//! so the cipher paths run on every input. Oracles:
//! - an accepted key round-trips through the encoder, and a 78-byte key (no extra labels)
//!   is byte-for-byte the canonical encoding (no alternate encodings of the same key);
//! - `decrypt` accepts exactly `iv ‖ whole blocks`, and re-encrypting the plaintext under
//!   the same IV gives the message back (CBC is a bijection);
//! - `verify` accepts the tag `authenticate` makes and rejects the message's own first
//!   32 bytes unless they are that tag.

#![no_main]

use jotakey_core::cbor::{Decoder, Encoder};
use jotakey_core::pin_protocol::{BLOCK_LEN, KeyAgreementKey, TAG_LEN, parse_public_key};
use libfuzzer_sys::fuzz_target;

fn encode(key: &p256::PublicKey) -> ([u8; 128], usize) {
    let mut buf = [0u8; 128];
    let mut e = Encoder::new(&mut buf);
    jotakey_core::crypto::encode_cose_key_with_alg(key, -25, &mut e).unwrap();
    let n = e.len();
    (buf, n)
}

fuzz_target!(|data: &[u8]| {
    let Some((scalar, rest)) = data.split_first_chunk::<32>() else { return };
    let Some(ours) = KeyAgreementKey::from_scalar(scalar) else { return };
    let Some((&n, rest)) = rest.split_first() else { return };
    let (cose, message) = rest.split_at(usize::from(n).min(rest.len()));

    let mut d = Decoder::new(cose);
    let parsed = parse_public_key(&mut d, 1).ok().filter(|_| d.finish().is_ok());
    let peer = match parsed {
        Some(peer) => {
            let (buf, len) = encode(&peer);
            let mut again = Decoder::new(&buf[..len]);
            assert_eq!(parse_public_key(&mut again, 1).ok(), Some(peer));
            if cose.len() == 78 {
                assert_eq!(&buf[..len], cose, "an accepted 78-byte key is the canonical encoding");
            }
            peer
        }
        None => {
            // The authenticator's own public key, read back from its encoding.
            let mut buf = [0u8; 128];
            let mut e = Encoder::new(&mut buf);
            ours.encode_public(&mut e).unwrap();
            let len = e.len();
            parse_public_key(&mut Decoder::new(&buf[..len]), 1).unwrap()
        }
    };
    let secret = ours.shared_secret(&peer).unwrap();

    let mut plain = [0u8; 2048];
    let well_formed = message.len() >= BLOCK_LEN && (message.len() - BLOCK_LEN) % BLOCK_LEN == 0;
    match secret.decrypt(message, &mut plain) {
        Ok(len) => {
            assert!(well_formed);
            assert_eq!(len, message.len() - BLOCK_LEN);
            let iv: [u8; BLOCK_LEN] = message[..BLOCK_LEN].try_into().unwrap();
            let mut again = [0u8; 2048 + BLOCK_LEN];
            assert_eq!(secret.encrypt(&iv, &plain[..len], &mut again), Ok(message.len()));
            assert_eq!(&again[..message.len()], message);
        }
        Err(_) => assert!(!well_formed || message.len() > plain.len() + BLOCK_LEN),
    }

    let tag = secret.authenticate(&[message]).unwrap();
    assert!(secret.verify(&[message], &tag));
    let claimed = &message[..message.len().min(TAG_LEN)];
    assert_eq!(secret.verify(&[message], claimed), claimed == tag);
});
