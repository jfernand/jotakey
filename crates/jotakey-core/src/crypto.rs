//! Cryptographic primitives, all from audited RustCrypto crates.
//!
//! Nothing here branches on secret data. Secret scalars are held in [`p256::SecretKey`],
//! which zeroizes on drop. Byte-array secrets are wrapped in [`zeroize::Zeroizing`] by
//! callers.

use ecdsa::hazmat::{SignPrimitive, bits2field};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{NistP256, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::{CborError, Encoder};

/// A primitive failed (bad key material or an internal library error). Carries no detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoError;

/// DER-encoded ECDSA signature (at most 72 bytes for P-256).
pub type DerSignature = ecdsa::der::Signature<NistP256>;

/// Domain-separation label for per-credential key derivation.
const CRED_KEY_INFO: &[u8] = b"jotakey/cred/v1";

/// SHA-256 over the concatenation of `parts`.
#[must_use]
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-SHA256 over the concatenation of `parts`.
///
/// # Errors
/// Never in practice (HMAC accepts any key length); kept fallible to avoid `unwrap`.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], CryptoError> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| CryptoError)?;
    for p in parts {
        m.update(p);
    }
    Ok(m.finalize().into_bytes().into())
}

/// Derive the P-256 private key of a credential.
///
/// `priv = HKDF-SHA256(ikm = seed, salt = rpIdHash, info = label ‖ nonce ‖ ctr)` for the first
/// counter value whose output is a valid nonzero scalar. The probability that the first
/// candidate is rejected is about 2⁻³², so the loop practically never repeats. It is
/// bounded at 256 iterations.
///
/// # Errors
/// [`CryptoError`] if all 256 candidates are invalid (probability ≈ 2⁻⁸¹⁹²).
pub fn derive_credential_key(
    seed: &[u8; 32],
    rp_id_hash: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<SecretKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(rp_id_hash), seed);
    let mut okm = Zeroizing::new([0u8; 32]);
    for ctr in 0u8..=255 {
        hk.expand_multi_info(&[CRED_KEY_INFO, nonce, &[ctr]], okm.as_mut())
            .map_err(|_| CryptoError)?;
        if let Ok(sk) = SecretKey::from_bytes(&(*okm).into()) {
            return Ok(sk);
        }
    }
    Err(CryptoError)
}

/// Hedged ECDSA-P256-SHA256 signature over the concatenation of `msg_parts`.
///
/// The nonce is RFC 6979 deterministic with `entropy` mixed in as additional data
/// (RFC 6979 §3.6). Deterministic nonces protect against a broken RNG. The extra
/// entropy makes fault attacks that rely on repeating the same signature much harder.
///
/// # Errors
/// [`CryptoError`] on internal failure.
pub fn sign(sk: &SecretKey, msg_parts: &[&[u8]], entropy: &[u8; 32]) -> Result<DerSignature, CryptoError> {
    sign_with_ad(sk, msg_parts, entropy)
}

/// ECDSA with explicit RFC 6979 additional data. Empty `ad` gives the deterministic
/// RFC 6979 signature (used only by the known-answer test).
///
/// # Errors
/// [`CryptoError`] on internal failure.
pub fn sign_with_ad(sk: &SecretKey, msg_parts: &[&[u8]], ad: &[u8]) -> Result<DerSignature, CryptoError> {
    let digest = sha256(msg_parts);
    let z = bits2field::<NistP256>(&digest).map_err(|_| CryptoError)?;
    let scalar = sk.to_nonzero_scalar();
    let (sig, _) = scalar
        .as_ref()
        .try_sign_prehashed_rfc6979::<Sha256>(&z, ad)
        .map_err(|_| CryptoError)?;
    Ok(sig.to_der())
}

/// Verify a DER signature. Used by the self tests (pairwise consistency) and in tests.
#[must_use]
pub fn verify(public: &p256::PublicKey, msg_parts: &[&[u8]], sig_der: &[u8]) -> bool {
    use ecdsa::signature::hazmat::PrehashVerifier;
    let Ok(sig) = ecdsa::Signature::<NistP256>::from_der(sig_der) else {
        return false;
    };
    let vk = ecdsa::VerifyingKey::<NistP256>::from(public);
    vk.verify_prehash(&sha256(msg_parts), &sig).is_ok()
}

/// COSE algorithm identifier for ES256.
pub const COSE_ALG_ES256: i64 = -7;

/// Encode `public` as a COSE_Key (RFC 9053): `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.
///
/// # Errors
/// [`CborError::BufferFull`] if `enc` is out of space, or [`CborError::Unsupported`] for the
/// identity point (impossible for a key derived from a nonzero scalar).
pub fn encode_cose_key(public: &p256::PublicKey, enc: &mut Encoder<'_>) -> Result<(), CborError> {
    let point = public.to_encoded_point(false);
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        return Err(CborError::Unsupported);
    };
    enc.map(5)?;
    enc.int(1)?; // kty
    enc.int(2)?; //   EC2
    enc.int(3)?; // alg
    enc.int(COSE_ALG_ES256)?;
    enc.int(-1)?; // crv
    enc.int(1)?; //   P-256
    enc.int(-2)?; // x
    enc.bytes(x)?;
    enc.int(-3)?; // y
    enc.bytes(y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn sha256_abc() {
        assert_eq!(
            sha256(&[b"a", b"bc"]),
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn hmac_rfc4231_case2() {
        assert_eq!(
            hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]).unwrap(),
            hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn credential_key_is_deterministic_and_separated() {
        let seed = [7u8; 32];
        let a = derive_credential_key(&seed, &[1; 32], &[2; 32]).unwrap();
        let b = derive_credential_key(&seed, &[1; 32], &[2; 32]).unwrap();
        let c = derive_credential_key(&seed, &[9; 32], &[2; 32]).unwrap();
        let d = derive_credential_key(&seed, &[1; 32], &[3; 32]).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert_ne!(a.to_bytes(), c.to_bytes());
        assert_ne!(a.to_bytes(), d.to_bytes());
    }

    #[test]
    fn sign_verify_roundtrip_and_entropy_changes_signature() {
        let sk = derive_credential_key(&[5; 32], &[1; 32], &[2; 32]).unwrap();
        let s1 = sign(&sk, &[b"auth", b"data"], &[0; 32]).unwrap();
        let s2 = sign(&sk, &[b"auth", b"data"], &[1; 32]).unwrap();
        assert!(verify(&sk.public_key(), &[b"authdata"], s1.as_bytes()));
        assert!(verify(&sk.public_key(), &[b"authdata"], s2.as_bytes()));
        assert_ne!(s1.as_bytes(), s2.as_bytes());
        assert!(!verify(&sk.public_key(), &[b"authdatA"], s1.as_bytes()));
    }

    #[test]
    fn cose_key_is_canonical() {
        let sk = derive_credential_key(&[5; 32], &[1; 32], &[2; 32]).unwrap();
        let mut buf = [0u8; 128];
        let mut e = Encoder::new(&mut buf);
        encode_cose_key(&sk.public_key(), &mut e).unwrap();
        let n = e.len();
        assert_eq!(n, 77);
        let mut d = crate::cbor::Decoder::new(&buf[..n]);
        d.skip(0).unwrap();
        d.finish().unwrap();
    }
}
