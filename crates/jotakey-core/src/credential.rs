// (c) Javier Fernandez @ JotaSoft 2026
//! Stateless credential IDs ("key wrapping by derivation").
//!
//! A credential ID is `version ‖ nonce ‖ tag`:
//!
//! ```text
//! byte 0        version (0x01)
//! bytes 1..33   nonce   (32 random bytes chosen at makeCredential)
//! bytes 33..49  tag     = a MAC of version ‖ rpIdHash ‖ nonce, truncated to 16 bytes
//! ```
//!
//! The MAC is a [`Tagger`]. On a device it is the hardware key store, which computes
//! `F(root, "jotakey/tag/v1" ‖ epoch ‖ version ‖ rpIdHash ‖ nonce)` one credential at a time
//! (`AGENTS.md` §3); [`HmacTagger`] is a fixed-key HMAC for self tests, tests and fuzzing.
//!
//! The private key is never stored or exported, encrypted or otherwise. It is re-derived
//! from the credential's seed whenever the ID is presented with a valid tag. The tag binds
//! the ID to its relying party (invariant 3): without the root an attacker cannot forge an ID
//! for any RP, and cannot replay an ID minted for one RP at another.

use subtle::ConstantTimeEq;

use crate::crypto::hmac_sha256;

/// Format version byte.
pub const VERSION: u8 = 0x01;
/// Nonce length.
pub const NONCE_LEN: usize = 32;
/// Truncated tag length (128-bit security against forgery).
pub const TAG_LEN: usize = 16;
/// Total credential-ID length.
pub const CRED_ID_LEN: usize = 1 + NONCE_LEN + TAG_LEN;
/// Length of the MAC input: `version ‖ rpIdHash ‖ nonce`.
pub const TAG_INPUT_LEN: usize = 1 + 32 + NONCE_LEN;

/// The MAC could not be computed (hardware failure). Carries no detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TagError;

/// Computes credential tags.
pub trait Tagger {
    /// The full MAC of `input` (`version ‖ rpIdHash ‖ nonce`, see [`tag_input`]); the
    /// credential ID keeps its first [`TAG_LEN`] bytes.
    ///
    /// # Errors
    /// [`TagError`] if the MAC cannot be computed.
    fn mac(&mut self, input: &[u8; TAG_INPUT_LEN]) -> Result<[u8; 32], TagError>;
}

/// A fixed-key HMAC-SHA256 tagger, for self tests, tests and fuzzing.
pub struct HmacTagger(pub [u8; 32]);

impl Tagger for HmacTagger {
    fn mac(&mut self, input: &[u8; TAG_INPUT_LEN]) -> Result<[u8; 32], TagError> {
        hmac_sha256(&self.0, &[input]).map_err(|_| TagError)
    }
}

/// The MAC input for `nonce` at relying party `rp_id_hash`: `version ‖ rpIdHash ‖ nonce`.
#[must_use]
pub fn tag_input(rp_id_hash: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; TAG_INPUT_LEN] {
    let mut input = [0u8; TAG_INPUT_LEN];
    let (v, rest) = input.split_at_mut(1);
    let (rp, n) = rest.split_at_mut(32);
    v.copy_from_slice(&[VERSION]);
    rp.copy_from_slice(rp_id_hash);
    n.copy_from_slice(nonce);
    input
}

fn tag<T: Tagger>(tagger: &mut T, rp_id_hash: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Result<[u8; TAG_LEN], TagError> {
    let full = tagger.mac(&tag_input(rp_id_hash, nonce))?;
    let mut t = [0u8; TAG_LEN];
    let src = full.get(..TAG_LEN).ok_or(TagError)?;
    t.copy_from_slice(src);
    Ok(t)
}

/// Mint the credential ID for `nonce` at relying party `rp_id_hash`.
///
/// # Errors
/// [`TagError`] if the tagger fails.
pub fn wrap<T: Tagger>(
    tagger: &mut T,
    rp_id_hash: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<[u8; CRED_ID_LEN], TagError> {
    let t = tag(tagger, rp_id_hash, nonce)?;
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
/// Length and version are public and checked first, without asking the tagger. The tag
/// comparison is constant-time. Any mismatch (wrong length, unknown version, foreign ID, ID
/// for another RP) is `Ok(None)`; only a failing tagger is an error, so a hardware fault is
/// never mistaken for "not our credential".
///
/// # Errors
/// [`TagError`] if the tagger fails.
pub fn unwrap<T: Tagger>(
    tagger: &mut T,
    rp_id_hash: &[u8; 32],
    id: &[u8],
) -> Result<Option<[u8; NONCE_LEN]>, TagError> {
    let Ok(id): Result<&[u8; CRED_ID_LEN], _> = id.try_into() else {
        return Ok(None);
    };
    let (v, rest) = id.split_at(1);
    if v != [VERSION] {
        return Ok(None);
    }
    let (n, given_tag) = rest.split_at(NONCE_LEN);
    let Ok(nonce): Result<[u8; NONCE_LEN], _> = n.try_into() else {
        return Ok(None);
    };
    let expected = tag(tagger, rp_id_hash, &nonce)?;
    Ok(if bool::from(expected.ct_eq(given_tag)) { Some(nonce) } else { None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::vec::Vec;

    const K: [u8; 32] = [0x42; 32];

    fn k() -> HmacTagger {
        HmacTagger(K)
    }

    struct Broken;
    impl Tagger for Broken {
        fn mac(&mut self, _: &[u8; TAG_INPUT_LEN]) -> Result<[u8; 32], TagError> {
            Err(TagError)
        }
    }

    #[test]
    fn a_failing_tagger_is_an_error_not_a_mismatch() {
        let id = wrap(&mut k(), &[1; 32], &[2; 32]).unwrap();
        assert_eq!(unwrap(&mut Broken, &[1; 32], &id), Err(TagError));
        assert_eq!(wrap(&mut Broken, &[1; 32], &[2; 32]), Err(TagError));
        // Length and version are checked before the tagger is asked.
        assert_eq!(unwrap(&mut Broken, &[1; 32], &id[..48]), Ok(None));
    }

    #[test]
    fn layout() {
        let id = wrap(&mut k(), &[1; 32], &[2; 32]).unwrap();
        assert_eq!(id[0], VERSION);
        assert_eq!(&id[1..33], &[2; 32]);
        assert_eq!(id.len(), 49);
    }

    #[test]
    fn rejects_bad_version_and_length() {
        let mut id = wrap(&mut k(), &[1; 32], &[2; 32]).unwrap();
        assert!(unwrap(&mut k(), &[1; 32], &id[..48]).unwrap().is_none());
        id[0] = 2;
        assert!(unwrap(&mut k(), &[1; 32], &id).unwrap().is_none());
    }

    proptest! {
        #[test]
        fn roundtrip(rp: [u8; 32], nonce: [u8; 32]) {
            let id = wrap(&mut k(), &rp, &nonce).unwrap();
            prop_assert_eq!(unwrap(&mut k(), &rp, &id), Ok(Some(nonce)));
        }

        #[test]
        fn bound_to_rp(rp: [u8; 32], other: [u8; 32], nonce: [u8; 32]) {
            prop_assume!(rp != other);
            let id = wrap(&mut k(), &rp, &nonce).unwrap();
            prop_assert_eq!(unwrap(&mut k(), &other, &id), Ok(None));
        }

        #[test]
        fn bound_to_key(rp: [u8; 32], nonce: [u8; 32]) {
            let id = wrap(&mut k(), &rp, &nonce).unwrap();
            prop_assert_eq!(unwrap(&mut HmacTagger([0x43; 32]), &rp, &id), Ok(None));
        }

        #[test]
        fn any_bit_flip_is_rejected(rp: [u8; 32], nonce: [u8; 32], bit in 0usize..(CRED_ID_LEN * 8)) {
            let mut id = wrap(&mut k(), &rp, &nonce).unwrap();
            id[bit / 8] ^= 1 << (bit % 8);
            prop_assert_eq!(unwrap(&mut k(), &rp, &id), Ok(None));
        }

        #[test]
        fn arbitrary_bytes_never_panic(data: Vec<u8>) {
            let _ = unwrap(&mut k(), &[0; 32], &data);
        }
    }
}
