// (c) Javier Fernandez @ JotaSoft 2026
//! Stateless credential IDs ("key wrapping by derivation").
//!
//! A credential ID is `version ‖ nonce ‖ tag`:
//!
//! ```text
//! byte 0        version (0x01)
//! bytes 1..33   nonce   (32 random bytes chosen at makeCredential)
//! bytes 33..49  tag     = HMAC-SHA256(K_mac, version ‖ rpIdHash ‖ nonce)[..16]
//! ```
//!
//! The private key is never stored or exported, encrypted or otherwise. It is re-derived
//! from `K_seed`, the rpIdHash and the nonce whenever the ID is presented with a valid tag.
//! The tag binds the ID to its relying party (invariant 3). Without `K_mac` an attacker
//! cannot forge an ID for any RP, and cannot replay an ID minted for one RP at another.

use subtle::ConstantTimeEq;

use crate::crypto::{CryptoError, hmac_sha256};

/// Format version byte.
pub const VERSION: u8 = 0x01;
/// Nonce length.
pub const NONCE_LEN: usize = 32;
/// Truncated tag length (128-bit security against forgery).
pub const TAG_LEN: usize = 16;
/// Total credential-ID length.
pub const CRED_ID_LEN: usize = 1 + NONCE_LEN + TAG_LEN;

fn tag(mac_key: &[u8; 32], rp_id_hash: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Result<[u8; TAG_LEN], CryptoError> {
    let full = hmac_sha256(mac_key, &[&[VERSION], rp_id_hash, nonce])?;
    let mut t = [0u8; TAG_LEN];
    let src = full.get(..TAG_LEN).ok_or(CryptoError)?;
    t.copy_from_slice(src);
    Ok(t)
}

/// Mint the credential ID for `nonce` at relying party `rp_id_hash`.
///
/// # Errors
/// [`CryptoError`] on internal failure.
pub fn wrap(mac_key: &[u8; 32], rp_id_hash: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Result<[u8; CRED_ID_LEN], CryptoError> {
    let t = tag(mac_key, rp_id_hash, nonce)?;
    let mut id = [0u8; CRED_ID_LEN];
    let (v, rest) = id.split_at_mut(1);
    let (n, tg) = rest.split_at_mut(NONCE_LEN);
    v.copy_from_slice(&[VERSION]);
    n.copy_from_slice(nonce);
    tg.copy_from_slice(&t);
    Ok(id)
}

/// Check `id` against `rp_id_hash` and return its nonce if it is authentic.
///
/// Length and version are public and checked first. The tag comparison is constant-time.
/// Any failure (wrong length, unknown version, foreign ID, ID for another RP) returns `None`.
#[must_use]
pub fn unwrap(mac_key: &[u8; 32], rp_id_hash: &[u8; 32], id: &[u8]) -> Option<[u8; NONCE_LEN]> {
    let id: &[u8; CRED_ID_LEN] = id.try_into().ok()?;
    let (v, rest) = id.split_at(1);
    if v != [VERSION] {
        return None;
    }
    let (n, given_tag) = rest.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = n.try_into().ok()?;
    let expected = tag(mac_key, rp_id_hash, &nonce).ok()?;
    if bool::from(expected.ct_eq(given_tag)) { Some(nonce) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::vec::Vec;

    const K: [u8; 32] = [0x42; 32];

    #[test]
    fn layout() {
        let id = wrap(&K, &[1; 32], &[2; 32]).unwrap();
        assert_eq!(id[0], VERSION);
        assert_eq!(&id[1..33], &[2; 32]);
        assert_eq!(id.len(), 49);
    }

    #[test]
    fn rejects_bad_version_and_length() {
        let mut id = wrap(&K, &[1; 32], &[2; 32]).unwrap();
        assert!(unwrap(&K, &[1; 32], &id[..48]).is_none());
        id[0] = 2;
        assert!(unwrap(&K, &[1; 32], &id).is_none());
    }

    proptest! {
        #[test]
        fn roundtrip(rp: [u8; 32], nonce: [u8; 32]) {
            let id = wrap(&K, &rp, &nonce).unwrap();
            prop_assert_eq!(unwrap(&K, &rp, &id), Some(nonce));
        }

        #[test]
        fn bound_to_rp(rp: [u8; 32], other: [u8; 32], nonce: [u8; 32]) {
            prop_assume!(rp != other);
            let id = wrap(&K, &rp, &nonce).unwrap();
            prop_assert_eq!(unwrap(&K, &other, &id), None);
        }

        #[test]
        fn bound_to_key(rp: [u8; 32], nonce: [u8; 32]) {
            let id = wrap(&K, &rp, &nonce).unwrap();
            prop_assert_eq!(unwrap(&[0x43; 32], &rp, &id), None);
        }

        #[test]
        fn any_bit_flip_is_rejected(rp: [u8; 32], nonce: [u8; 32], bit in 0usize..(CRED_ID_LEN * 8)) {
            let mut id = wrap(&K, &rp, &nonce).unwrap();
            id[bit / 8] ^= 1 << (bit % 8);
            prop_assert_eq!(unwrap(&K, &rp, &id), None);
        }

        #[test]
        fn arbitrary_bytes_never_panic(data: Vec<u8>) {
            let _ = unwrap(&K, &[0; 32], &data);
        }
    }
}
