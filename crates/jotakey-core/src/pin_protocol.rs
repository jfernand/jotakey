// (c) Javier Fernandez @ JotaSoft 2026
//! PIN/UV auth protocol two (CTAP 2.1 §6.5.7): the cryptography under authenticatorClientPIN.
//!
//! The platform and the authenticator agree on a shared secret by ECDH on P-256: the
//! authenticator's key-agreement key lives for one power cycle, the platform's for one
//! command. The x-coordinate of the shared point goes through HKDF-SHA256 twice, giving an
//! HMAC key and an AES key:
//!
//! ```text
//! hmacKey = HKDF(salt = 0³², ikm = Z, info = "CTAP2 HMAC key")
//! aesKey  = HKDF(salt = 0³², ikm = Z, info = "CTAP2 AES key")
//! encrypt(m) = iv ‖ AES-256-CBC(aesKey, iv, m)      (iv random, m a multiple of 16 bytes)
//! authenticate(k, m) = HMAC-SHA256(k, m)             (all 32 bytes)
//! ```
//!
//! PINs, PIN hashes and pinUvAuthTokens travel encrypted; requests that use a token carry
//! `authenticate(token, …)` as `pinUvAuthParam`. This module holds only the primitives.
//! The clientPIN command, PIN storage and retry counters build on it (doc chapter 11).
//!
//! The AES implementation is RustCrypto's bitsliced software AES (no table lookups), so
//! it runs in constant time on cores without AES instructions, which includes both targets.

use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey, SecretKey};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::cbor::{CborError, Decoder, Encoder, Key};
use crate::crypto::{self, CryptoError};
use crate::platform::{Platform, PlatformError};
use crate::status::Status;

/// The protocol number, as `pinUvAuthProtocol` carries it.
pub const PROTOCOL: u64 = 2;

/// COSE algorithm the key-agreement keys are labelled with (ECDH-ES + HKDF-256). The spec
/// keeps this label although the KDF above is what is actually used.
pub const COSE_ALG_ECDH_ES_HKDF_256: i64 = -25;

/// Check a command's `pinUvAuthProtocol` when it carries a `pinUvAuthParam`.
///
/// # Errors
/// [`Status::MissingParameter`] if absent, [`Status::InvalidParameter`] if not [`PROTOCOL`].
pub fn check_version(protocol: Option<u64>) -> Result<(), Status> {
    match protocol {
        None => Err(Status::MissingParameter),
        Some(PROTOCOL) => Ok(()),
        Some(_) => Err(Status::InvalidParameter),
    }
}

/// AES block size; also the IV length.
pub const BLOCK_LEN: usize = 16;

/// Length of `authenticate` output, and of a pinUvAuthToken.
pub const TAG_LEN: usize = 32;

const HKDF_SALT: [u8; 32] = [0; 32];
const HMAC_KEY_INFO: &[u8] = b"CTAP2 HMAC key";
const AES_KEY_INFO: &[u8] = b"CTAP2 AES key";

/// The authenticator's key-agreement key pair. The secret scalar zeroizes on drop.
#[derive(Clone)]
pub struct KeyAgreementKey {
    secret: SecretKey,
}

impl core::fmt::Debug for KeyAgreementKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyAgreementKey(..)") // invariant 8: never print the scalar
    }
}

impl KeyAgreementKey {
    /// A fresh key pair from the platform RNG.
    ///
    /// A random 32-byte string is a valid scalar unless it is zero or at least the group
    /// order, which happens with probability about 2⁻³²; the loop is bounded at 8 tries.
    ///
    /// # Errors
    /// [`PlatformError`] if the RNG fails, or if 8 candidates in a row are invalid.
    pub fn generate<P: Platform>(platform: &mut P) -> Result<Self, PlatformError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        for _ in 0..8u8 {
            platform.random_bytes(bytes.as_mut())?;
            if let Ok(secret) = SecretKey::from_bytes(&(*bytes).into()) {
                return Ok(Self { secret });
            }
        }
        Err(PlatformError)
    }

    /// A key pair with a chosen scalar, for known-answer tests and fuzzing.
    #[cfg(any(test, feature = "mock"))]
    #[must_use]
    pub fn from_scalar(bytes: &[u8; 32]) -> Option<Self> {
        SecretKey::from_bytes(&(*bytes).into()).ok().map(|secret| Self { secret })
    }

    /// The public key, as getKeyAgreement returns it:
    /// `{1: 2, 3: -25, -1: 1, -2: x, -3: y}`.
    ///
    /// # Errors
    /// [`CborError::BufferFull`] if `enc` is out of space.
    pub fn encode_public(&self, enc: &mut Encoder<'_>) -> Result<(), CborError> {
        crypto::encode_cose_key_with_alg(&self.secret.public_key(), COSE_ALG_ECDH_ES_HKDF_256, enc)
    }

    /// The secret shared with the holder of `peer`.
    ///
    /// # Errors
    /// [`CryptoError`] if HKDF fails (it cannot for 32-byte outputs).
    pub fn shared_secret(&self, peer: &PublicKey) -> Result<SharedSecret, CryptoError> {
        let z = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        SharedSecret::derive(z.raw_secret_bytes())
    }
}

/// The two keys that protocol two derives from an ECDH result. Zeroized on drop.
pub struct SharedSecret {
    hmac_key: Zeroizing<[u8; 32]>,
    aes_key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(..)")
    }
}

impl SharedSecret {
    /// Protocol two's `kdf(Z)`.
    fn derive(z: &[u8]) -> Result<Self, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(&HKDF_SALT), z);
        let mut hmac_key = Zeroizing::new([0u8; 32]);
        let mut aes_key = Zeroizing::new([0u8; 32]);
        hk.expand(HMAC_KEY_INFO, hmac_key.as_mut()).map_err(|_| CryptoError)?;
        hk.expand(AES_KEY_INFO, aes_key.as_mut()).map_err(|_| CryptoError)?;
        Ok(Self { hmac_key, aes_key })
    }

    /// The 64 bytes `hmacKey ‖ aesKey`, as the spec writes the shared secret. Tests only.
    #[cfg(test)]
    fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(self.hmac_key.as_ref());
        b[32..].copy_from_slice(self.aes_key.as_ref());
        b
    }

    /// Write `iv ‖ AES-256-CBC(aesKey, iv, plaintext)` to the start of `out` and return its
    /// length. `iv` must come from the RNG; it is a parameter so that tests can fix it.
    ///
    /// # Errors
    /// [`CryptoError`] if `plaintext` is not a whole number of blocks or `out` is too small.
    pub fn encrypt(&self, iv: &[u8; BLOCK_LEN], plaintext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if !plaintext.len().is_multiple_of(BLOCK_LEN) {
            return Err(CryptoError);
        }
        let len = BLOCK_LEN.checked_add(plaintext.len()).ok_or(CryptoError)?;
        let (head, body) = out.get_mut(..len).ok_or(CryptoError)?.split_at_mut(BLOCK_LEN);
        head.copy_from_slice(iv);
        body.copy_from_slice(plaintext);
        let cipher = Aes256::new_from_slice(self.aes_key.as_ref()).map_err(|_| CryptoError)?;
        let mut chain = *iv;
        for block in body.as_chunks_mut::<BLOCK_LEN>().0 {
            xor_into(block, &chain);
            cipher.encrypt_block(block.into());
            chain = *block;
        }
        Ok(len)
    }

    /// Decrypt `iv ‖ ciphertext` into the start of `out` and return the plaintext length.
    ///
    /// # Errors
    /// [`CryptoError`] if `message` is shorter than an IV, the ciphertext is not a whole
    /// number of blocks, or `out` is too small.
    pub fn decrypt(&self, message: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        let (iv, ciphertext) = message.split_first_chunk::<BLOCK_LEN>().ok_or(CryptoError)?;
        if !ciphertext.len().is_multiple_of(BLOCK_LEN) {
            return Err(CryptoError);
        }
        let body = out.get_mut(..ciphertext.len()).ok_or(CryptoError)?;
        body.copy_from_slice(ciphertext);
        let cipher = Aes256::new_from_slice(self.aes_key.as_ref()).map_err(|_| CryptoError)?;
        let mut chain = *iv;
        for block in body.as_chunks_mut::<BLOCK_LEN>().0 {
            let next = *block;
            cipher.decrypt_block(block.into());
            xor_into(block, &chain);
            chain = next;
        }
        Ok(ciphertext.len())
    }

    /// `authenticate(hmacKey, parts…)`.
    ///
    /// # Errors
    /// Never in practice; see [`crypto::hmac_sha256`].
    pub fn authenticate(&self, parts: &[&[u8]]) -> Result<[u8; TAG_LEN], CryptoError> {
        authenticate(&self.hmac_key, parts)
    }

    /// Whether `param` is `authenticate(hmacKey, parts…)`, compared in constant time.
    #[must_use]
    pub fn verify(&self, parts: &[&[u8]], param: &[u8]) -> bool {
        verify(&self.hmac_key, parts, param)
    }
}

/// `authenticate(key, parts…)` = HMAC-SHA256, all 32 bytes. With a pinUvAuthToken as `key`
/// this is the `pinUvAuthParam` of makeCredential and getAssertion.
///
/// # Errors
/// Never in practice; see [`crypto::hmac_sha256`].
pub fn authenticate(key: &[u8; 32], parts: &[&[u8]]) -> Result<[u8; TAG_LEN], CryptoError> {
    crypto::hmac_sha256(key, parts)
}

/// Whether `param` equals `authenticate(key, parts…)`. The comparison is constant-time; a
/// `param` of the wrong length is rejected (its length is public).
#[must_use]
pub fn verify(key: &[u8; 32], parts: &[&[u8]], param: &[u8]) -> bool {
    match authenticate(key, parts) {
        Ok(expected) => expected.as_slice().ct_eq(param).into(),
        Err(_) => false,
    }
}

fn xor_into(block: &mut [u8; BLOCK_LEN], with: &[u8; BLOCK_LEN]) {
    for (b, w) in block.iter_mut().zip(with) {
        *b ^= w;
    }
}

/// Parse the platform's key-agreement key, a COSE_Key map at `depth`:
/// `{1: 2 (EC2), 3: -25, -1: 1 (P-256), -2: x (32 bytes), -3: y (32 bytes)}`. Other labels
/// are validated and ignored. The point must lie on the curve.
///
/// # Errors
/// CBOR errors as usual, [`Status::MissingParameter`] if a member is absent, and
/// [`Status::InvalidParameter`] for any other key type, algorithm, curve, coordinate length,
/// or a point not on P-256.
pub fn parse_public_key(d: &mut Decoder<'_>, depth: u8) -> Result<PublicKey, Status> {
    let mut m = d.map()?;
    let (mut kty, mut alg, mut crv, mut x, mut y) = (None, None, None, None, None);
    while let Some(k) = d.next_key(&mut m)? {
        match k {
            Key::Int(1) => kty = Some(d.int()?),
            Key::Int(3) => alg = Some(d.int()?),
            Key::Int(-1) => crv = Some(d.int()?),
            Key::Int(-2) => x = Some(d.bytes()?),
            Key::Int(-3) => y = Some(d.bytes()?),
            _ => d.skip(depth.saturating_add(1))?,
        }
    }
    let (Some(kty), Some(alg), Some(crv), Some(x), Some(y)) = (kty, alg, crv, x, y) else {
        return Err(Status::MissingParameter);
    };
    if kty != 2 || alg != COSE_ALG_ECDH_ES_HKDF_256 || crv != 1 {
        return Err(Status::InvalidParameter);
    }
    let (Ok(x), Ok(y)) = (<&[u8; 32]>::try_from(x), <&[u8; 32]>::try_from(y)) else {
        return Err(Status::InvalidParameter);
    };
    let point = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    Option::from(PublicKey::from_encoded_point(&point)).ok_or(Status::InvalidParameter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockPlatform;
    use hex_literal::hex;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    // Computed with python-fido2's PinProtocolV2 (fido2.ctap2.pin) and `cryptography`:
    // authenticator scalar 01..20, platform scalar 41..60, PIN "1234" padded to 64 bytes,
    // IV a0..af, message 0xff×32 ‖ 0x06.
    const A_SCALAR: [u8; 32] = hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const B_SCALAR: [u8; 32] = hex!("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60");
    const A_X: [u8; 32] = hex!("515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f");
    const A_Y: [u8; 32] = hex!("4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354");
    const B_X: [u8; 32] = hex!("261efbd3550cf068ef013ed7366ba32f5d6fe557b4b2abce8ade58cba168a55e");
    const B_Y: [u8; 32] = hex!("1788a0b29a56a6abec4084c0c96bd3dcbca6b507f35dbea9e985708479d8bdc9");
    const SHARED: [u8; 64] = hex!(
        "5b4dc4fd77c1fc021373268f1cd1ebacaa7458aeff93ac401926d6fb5ad595ce"
        "14ab2c3995135bf5c80fd1757f6b9819974a0afa9786bd23ff118f13f8c6cd30"
    );
    const IV: [u8; 16] = hex!("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    const CT: [u8; 80] = hex!(
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf8291a56a04b2f8b88b9f3732e3635b2c"
        "830437c66240d732de4f761d7801110ab6026bdb0f02c92fd38b430ce0688e32"
        "049329fa5b574ebf107fc915f3776e2b"
    );
    const MAC: [u8; 32] = hex!("be8064665669d2dc9908411e5ac27f3274942e7c7f52a5632b170c2917d3dbd4");

    fn padded_pin() -> [u8; 64] {
        let mut p = [0u8; 64];
        p[..4].copy_from_slice(b"1234");
        p
    }

    fn cose(kty: i64, alg: i64, crv: i64, x: &[u8], y: &[u8]) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 128];
        let mut e = Encoder::new(&mut buf);
        e.map(5).unwrap();
        e.int(1).unwrap();
        e.int(kty).unwrap();
        e.int(3).unwrap();
        e.int(alg).unwrap();
        e.int(-1).unwrap();
        e.int(crv).unwrap();
        e.int(-2).unwrap();
        e.bytes(x).unwrap();
        e.int(-3).unwrap();
        e.bytes(y).unwrap();
        let n = e.len();
        buf[..n].to_vec()
    }

    fn parse(bytes: &[u8]) -> Result<PublicKey, Status> {
        let mut d = Decoder::new(bytes);
        let k = parse_public_key(&mut d, 1)?;
        d.finish()?;
        Ok(k)
    }

    fn shared() -> SharedSecret {
        let a = KeyAgreementKey::from_scalar(&A_SCALAR).unwrap();
        a.shared_secret(&parse(&cose(2, -25, 1, &B_X, &B_Y)).unwrap()).unwrap()
    }

    #[test]
    fn shared_secret_matches_python_fido2_from_both_sides() {
        assert_eq!(shared().to_bytes(), SHARED);
        let b = KeyAgreementKey::from_scalar(&B_SCALAR).unwrap();
        let a_pub = parse(&cose(2, -25, 1, &A_X, &A_Y)).unwrap();
        assert_eq!(b.shared_secret(&a_pub).unwrap().to_bytes(), SHARED);
    }

    #[test]
    fn public_key_encoding_is_the_spec_cose_key() {
        let a = KeyAgreementKey::from_scalar(&A_SCALAR).unwrap();
        let mut buf = [0u8; 128];
        let mut e = Encoder::new(&mut buf);
        a.encode_public(&mut e).unwrap();
        let n = e.len();
        assert_eq!(&buf[..n], &cose(2, -25, 1, &A_X, &A_Y)[..]);
    }

    #[test]
    fn encrypt_and_decrypt_match_python_fido2() {
        let s = shared();
        let mut out = [0u8; 96];
        assert_eq!(s.encrypt(&IV, &padded_pin(), &mut out), Ok(80));
        assert_eq!(out[..80], CT);
        let mut pt = [0u8; 64];
        assert_eq!(s.decrypt(&CT, &mut pt), Ok(64));
        assert_eq!(pt, padded_pin());
    }

    #[test]
    fn authenticate_and_verify_match_python_fido2() {
        let s = shared();
        let msg = [&[0xffu8; 32][..], &[0x06]];
        assert_eq!(s.authenticate(&msg), Ok(MAC));
        assert!(s.verify(&msg, &MAC));
        let mut bad = MAC;
        bad[31] ^= 1;
        assert!(!s.verify(&msg, &bad));
        assert!(!s.verify(&msg, &MAC[..16]), "protocol one's truncated tag is not accepted");
        assert!(!s.verify(&[&[0xffu8; 32][..], &[0x07]], &MAC));
    }

    #[test]
    fn token_authenticate_is_hmac_with_the_whole_token() {
        let token = [0x42u8; 32];
        let tag = authenticate(&token, &[b"cdh"]).unwrap();
        assert_eq!(tag, crypto::hmac_sha256(&token, &[b"cdh"]).unwrap());
        assert!(verify(&token, &[b"c", b"dh"], &tag));
        assert!(!verify(&[0x43; 32], &[b"cdh"], &tag));
        assert!(!verify(&token, &[b"cdh"], &[]));
    }

    #[test]
    fn ciphertexts_that_are_not_whole_blocks_are_refused() {
        let s = shared();
        let mut out = [0u8; 128];
        assert_eq!(s.decrypt(&CT[..15], &mut out), Err(CryptoError), "shorter than the IV");
        assert_eq!(s.decrypt(&CT[..79], &mut out), Err(CryptoError));
        assert_eq!(s.decrypt(&CT[..16], &mut out), Ok(0), "an IV alone is an empty message");
        assert_eq!(s.decrypt(&CT, &mut out[..63]), Err(CryptoError), "output too small");
        assert_eq!(s.encrypt(&IV, &[0; 15], &mut out), Err(CryptoError));
        assert_eq!(s.encrypt(&IV, &[0; 64], &mut out[..79]), Err(CryptoError), "output too small");
        assert_eq!(s.encrypt(&IV, &[], &mut out), Ok(16));
    }

    #[test]
    fn cbc_chains_blocks() {
        // Equal plaintext blocks give different ciphertext blocks, and each IV bit matters.
        let s = shared();
        let mut out = [0u8; 48];
        s.encrypt(&IV, &[7; 32], &mut out).unwrap();
        assert_ne!(out[16..32], out[32..48]);
        let mut other = [0u8; 48];
        let mut iv = IV;
        iv[0] ^= 1;
        s.encrypt(&iv, &[7; 32], &mut other).unwrap();
        assert_ne!(out[16..], other[16..]);
        // Decrypting with a flipped IV bit flips the same plaintext bit only.
        let mut tampered = out;
        tampered[0] ^= 0x80;
        let mut pt = [0u8; 32];
        s.decrypt(&tampered, &mut pt).unwrap();
        assert_eq!(pt[0], 7 ^ 0x80);
        assert_eq!(pt[1..], [7; 31]);
    }

    #[test]
    fn peer_keys_must_be_p256_ecdh_points_on_the_curve() {
        assert!(parse(&cose(2, -25, 1, &B_X, &B_Y)).is_ok());
        assert_eq!(parse(&cose(3, -25, 1, &B_X, &B_Y)).err(), Some(Status::InvalidParameter), "kty");
        assert_eq!(parse(&cose(2, -7, 1, &B_X, &B_Y)).err(), Some(Status::InvalidParameter), "alg");
        assert_eq!(parse(&cose(2, -25, 2, &B_X, &B_Y)).err(), Some(Status::InvalidParameter), "crv");
        assert_eq!(parse(&cose(2, -25, 1, &B_X[..31], &B_Y)).err(), Some(Status::InvalidParameter), "x len");
        assert_eq!(parse(&cose(2, -25, 1, &B_X, &B_Y[..31])).err(), Some(Status::InvalidParameter), "y len");
        let mut off = B_Y;
        off[31] ^= 1;
        assert_eq!(parse(&cose(2, -25, 1, &B_X, &off)).err(), Some(Status::InvalidParameter), "not on the curve");
        assert_eq!(parse(&cose(2, -25, 1, &[0; 32], &[0; 32])).err(), Some(Status::InvalidParameter), "origin");
    }

    #[test]
    fn peer_keys_need_every_member_and_tolerate_extra_labels() {
        // {1: 2, 3: -25, -1: 1, -2: x} without y.
        let full = cose(2, -25, 1, &B_X, &B_Y);
        let mut no_y = full[..full.len() - 35].to_vec();
        no_y[0] = 0xA4;
        assert_eq!(parse(&no_y).err(), Some(Status::MissingParameter));
        // An extra label -4 (sorted last) is skipped.
        let mut extra = full.clone();
        extra[0] = 0xA6;
        extra.extend([0x23, 0x80]); // -4: []
        assert!(parse(&extra).is_ok());
        // Wrong member types are CBOR type errors.
        let mut bad = full;
        bad[2] = 0x40; // kty: h'' instead of 2
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn generated_keys_agree_and_differ_per_call() {
        let mut p = MockPlatform::new(1);
        let a = KeyAgreementKey::generate(&mut p).unwrap();
        let b = KeyAgreementKey::generate(&mut p).unwrap();
        assert_ne!(a.secret.to_bytes(), b.secret.to_bytes());
        let ab = a.shared_secret(&b.secret.public_key()).unwrap().to_bytes();
        assert_eq!(ab, b.shared_secret(&a.secret.public_key()).unwrap().to_bytes());
        // The key is the platform's RNG output read as a scalar.
        let mut q = MockPlatform::new(1);
        let mut expect = [0u8; 32];
        q.random_bytes(&mut expect).unwrap();
        assert_eq!(a.secret.to_bytes()[..], expect);
        assert_eq!(a.secret.public_key().to_encoded_point(false).x().unwrap().len(), 32);
        p.fail_rng = true;
        assert!(KeyAgreementKey::generate(&mut p).is_err());
    }

    #[test]
    fn secrets_do_not_print() {
        let a = KeyAgreementKey::from_scalar(&A_SCALAR).unwrap();
        assert_eq!(std::format!("{a:?}"), "KeyAgreementKey(..)");
        assert_eq!(std::format!("{:?}", shared()), "SharedSecret(..)");
    }
}
