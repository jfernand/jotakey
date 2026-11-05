// (c) Javier Fernandez @ JotaSoft 2026
//! Cryptographic primitives, all from audited RustCrypto crates.
//!
//! Nothing here branches on secret data. Secret scalars are held in [`p256::SecretKey`],
//! which zeroizes on drop. Byte-array secrets are wrapped in [`zeroize::Zeroizing`] by
//! callers.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use p256::{NistP256, SecretKey, elliptic_curve::sec1::ToSec1Point};
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
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| CryptoError)?;
    for p in parts {
        m.update(p);
    }
    Ok(m.finalize().into_bytes().into())
}

/// Longest output [`tls_prf_sha256`] produces (the OPTIGA's limit for an exported secret).
pub const TLS_PRF_MAX_OUT: usize = 256;

/// The TLS 1.2 PRF with SHA-256 (RFC 5246 §5): `P_SHA256(secret, seed)`, where `seed` is the
/// concatenation of `seed_parts` (TLS's `label ‖ seed`).
///
/// `P_SHA256(S, x) = HMAC(S, A(1) ‖ x) ‖ HMAC(S, A(2) ‖ x) ‖ …` with `A(0) = x` and
/// `A(i) = HMAC(S, A(i−1))`, cut to `out.len()` bytes. This is the function `F` of the
/// jotakey key (AGENTS.md §3): the OPTIGA's `DeriveKey` computes it over `K_root`, and the
/// shielded connection derives its session keys with it. The MCU computes it only over
/// secrets it holds itself (the binding and freshness secrets, `optiga::shielded`).
///
/// # Errors
/// [`CryptoError`] if `out` is longer than [`TLS_PRF_MAX_OUT`].
pub fn tls_prf_sha256(secret: &[u8], seed_parts: &[&[u8]], out: &mut [u8]) -> Result<(), CryptoError> {
    if out.len() > TLS_PRF_MAX_OUT {
        return Err(CryptoError);
    }
    let mut a = Zeroizing::new(hmac_seed(secret, None, seed_parts)?);
    for chunk in out.chunks_mut(32) {
        let block = Zeroizing::new(hmac_seed(secret, Some(&a), seed_parts)?);
        chunk.copy_from_slice(block.get(..chunk.len()).ok_or(CryptoError)?);
        *a = hmac_sha256(secret, &[a.as_ref()])?;
    }
    Ok(())
}

/// `HMAC(secret, prefix ‖ seed_parts…)`.
fn hmac_seed(secret: &[u8], prefix: Option<&[u8; 32]>, seed_parts: &[&[u8]]) -> Result<[u8; 32], CryptoError> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).map_err(|_| CryptoError)?;
    if let Some(p) = prefix {
        m.update(p);
    }
    for p in seed_parts {
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
        hk.expand_multi_info(&[CRED_KEY_INFO, nonce, &[ctr]], okm.as_mut()).map_err(|_| CryptoError)?;
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
    let (sig, _) = ecdsa::hazmat::sign_prehashed_rfc6979::<NistP256, Sha256>(&sk.to_nonzero_scalar(), &digest, ad);
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
    encode_cose_key_with_alg(public, COSE_ALG_ES256, enc)
}

/// Encode `public` as a P-256 COSE_Key labelled with algorithm `alg`.
///
/// # Errors
/// As [`encode_cose_key`].
pub fn encode_cose_key_with_alg(public: &p256::PublicKey, alg: i64, enc: &mut Encoder<'_>) -> Result<(), CborError> {
    let point = public.to_sec1_point(false);
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        return Err(CborError::Unsupported);
    };
    enc.map(5)?;
    enc.int(1)?; // kty
    enc.int(2)?; //   EC2
    enc.int(3)?; // alg
    enc.int(alg)?;
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
        assert_eq!(sha256(&[b"a", b"bc"]), hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    }

    #[test]
    fn hmac_rfc4231_case2() {
        assert_eq!(
            hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]).unwrap(),
            hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    /// The TLS 1.2 PRF-SHA256 test vector (IETF TLS WG; recomputed independently with
    /// Python's `hmac`): secret, label "test label", seed, 100 bytes.
    #[test]
    fn tls_prf_sha256_known_answer() {
        let secret = hex!("9bbe436ba940f017b17652849a71db35");
        let seed = hex!("a0ba9f936cda311827a6f796ffd5198c");
        let mut out = [0u8; 100];
        tls_prf_sha256(&secret, &[b"test label", &seed], &mut out).unwrap();
        assert_eq!(
            out,
            hex!(
                "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
            )
        );
        // Shorter outputs are prefixes; the seed may be split anywhere.
        let mut short = [0u8; 40];
        tls_prf_sha256(&secret, &[b"test ", b"label", &seed[..3], &seed[3..]], &mut short).unwrap();
        assert_eq!(short, out[..40]);
        let mut too_long = [0u8; TLS_PRF_MAX_OUT + 1];
        assert_eq!(tls_prf_sha256(&secret, &[], &mut too_long), Err(CryptoError));
        let mut max = [0u8; TLS_PRF_MAX_OUT];
        assert!(tls_prf_sha256(&secret, &[], &mut max).is_ok());
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
