// (c) Javier Fernandez @ JotaSoft 2026
//! Power-on known-answer tests and continuous RNG health tests (invariant 7).
//!
//! The firmware runs [`run_kats`] and [`startup_rng_test`] at boot before the authenticator
//! answers any request, and feeds every TRNG byte through [`RngHealth`]. Any failure puts
//! the authenticator in its permanent fault state.

use hex_literal::hex;

use crate::credential;
use crate::crypto::{self, hmac_sha256, sha256};

/// Which self test failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfTestError {
    /// SHA-256 KAT.
    Sha256,
    /// HMAC-SHA256 KAT.
    Hmac,
    /// HKDF-SHA256 KAT.
    Hkdf,
    /// ECDSA P-256 RFC 6979 KAT or pairwise consistency.
    Ecdsa,
    /// Credential wrap/unwrap consistency.
    Credential,
    /// Repetition count test.
    RngRepetition,
    /// Adaptive proportion test.
    RngProportion,
}

/// Run all cryptographic known-answer tests.
///
/// `inject` deliberately corrupts the result of one test, as FIPS 140-3 asks of self-test
/// implementations. It shows that a failure is detected and makes the device fail closed.
/// Production code passes `None`. The host tests and the on-device test firmware pass each
/// variant in turn.
///
/// # Errors
/// The first failing test.
pub fn run_kats(inject: Option<SelfTestError>) -> Result<(), SelfTestError> {
    let corrupt = |t: SelfTestError| inject == Some(t);
    // FIPS 180-4 example "abc".
    let mut digest = sha256(&[b"abc"]);
    if corrupt(SelfTestError::Sha256) {
        digest = [0; 32];
    }
    if digest != hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
        return Err(SelfTestError::Sha256);
    }
    // RFC 4231 test case 2.
    let mut mac = hmac_sha256(b"Jefe", &[b"what do ya want for nothing?"]).map_err(|_| SelfTestError::Hmac)?;
    if corrupt(SelfTestError::Hmac) {
        mac = [0; 32];
    }
    if mac != hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") {
        return Err(SelfTestError::Hmac);
    }
    // RFC 5869 test case 1.
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&hex!("000102030405060708090a0b0c")), &[0x0b; 22]);
    let mut okm = [0u8; 42];
    hk.expand(&hex!("f0f1f2f3f4f5f6f7f8f9"), &mut okm).map_err(|_| SelfTestError::Hkdf)?;
    if corrupt(SelfTestError::Hkdf) {
        okm = [0; 42];
    }
    if okm != hex!("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865") {
        return Err(SelfTestError::Hkdf);
    }
    ecdsa_kat(corrupt(SelfTestError::Ecdsa))?;
    credential_kat(corrupt(SelfTestError::Credential))
}

/// RFC 6979 §A.2.5, P-256, SHA-256, message "sample": deterministic signature (no extra
/// entropy), then a hedged signature that must verify (pairwise consistency).
fn ecdsa_kat(corrupt: bool) -> Result<(), SelfTestError> {
    let sk = p256::SecretKey::from_bytes(&hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721").into())
        .map_err(|_| SelfTestError::Ecdsa)?;
    let msg: &[u8] = if corrupt { b"samplE" } else { b"sample" };
    let sig = crypto::sign_with_ad(&sk, &[msg], &[]).map_err(|_| SelfTestError::Ecdsa)?;
    let expected = ecdsa::Signature::<p256::NistP256>::from_scalars(
        hex!("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"),
        hex!("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
    )
    .map_err(|_| SelfTestError::Ecdsa)?;
    if sig.as_bytes() != expected.to_der().as_bytes() {
        return Err(SelfTestError::Ecdsa);
    }
    let hedged = crypto::sign(&sk, &[b"pairwise"], &[0xA5; 32]).map_err(|_| SelfTestError::Ecdsa)?;
    if !crypto::verify(&sk.public_key(), &[b"pairwise"], hedged.as_bytes()) {
        return Err(SelfTestError::Ecdsa);
    }
    if crypto::verify(&sk.public_key(), &[b"pairwisE"], hedged.as_bytes()) {
        return Err(SelfTestError::Ecdsa);
    }
    Ok(())
}

fn credential_kat(corrupt: bool) -> Result<(), SelfTestError> {
    let mut id = credential::wrap(&[1; 32], &[2; 32], &[3; 32]).map_err(|_| SelfTestError::Credential)?;
    if corrupt {
        id = [0; credential::CRED_ID_LEN];
    }
    if credential::unwrap(&[1; 32], &[2; 32], &id) != Some([3; 32]) {
        return Err(SelfTestError::Credential);
    }
    if credential::unwrap(&[1; 32], &[4; 32], &id).is_some() {
        return Err(SelfTestError::Credential);
    }
    Ok(())
}

/// Assumed min-entropy per TRNG byte for the health-test cutoffs (conservative; the ESP32-C6
/// TRNG with the radio enabled is specified as a full-entropy source).
pub const ASSUMED_ENTROPY_BITS: u32 = 4;
/// Repetition count cutoff: `1 + ⌈20 / H⌉` for a false-alarm rate of 2⁻²⁰ (SP 800-90B §4.4.1).
pub const RCT_CUTOFF: u16 = 6;
/// Adaptive proportion window (SP 800-90B §4.4.2, non-binary sources).
pub const APT_WINDOW: u16 = 512;
/// Adaptive proportion cutoff: `1 + CRITBINOM(512, 2⁻⁴, 1 − 2⁻²⁰)`.
pub const APT_CUTOFF: u16 = 62;
/// Samples examined by the start-up test (SP 800-90B §4.3: at least 1024).
pub const STARTUP_SAMPLES: usize = 1024;

/// Streaming SP 800-90B repetition count and adaptive proportion tests.
#[derive(Clone, Debug)]
pub struct RngHealth {
    rct_last: Option<u8>,
    rct_count: u16,
    apt_first: u8,
    apt_count: u16,
    apt_index: u16,
}

impl Default for RngHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl RngHealth {
    /// Fresh test state.
    #[must_use]
    pub const fn new() -> Self {
        Self { rct_last: None, rct_count: 0, apt_first: 0, apt_count: 0, apt_index: 0 }
    }

    /// Examine one sample.
    ///
    /// # Errors
    /// The test that tripped. The caller must stop using the RNG.
    pub fn feed(&mut self, b: u8) -> Result<(), SelfTestError> {
        if self.rct_last == Some(b) {
            self.rct_count = self.rct_count.saturating_add(1);
            if self.rct_count >= RCT_CUTOFF {
                return Err(SelfTestError::RngRepetition);
            }
        } else {
            self.rct_last = Some(b);
            self.rct_count = 1;
        }

        if self.apt_index == 0 {
            self.apt_first = b;
            self.apt_count = 1;
        } else if b == self.apt_first {
            self.apt_count = self.apt_count.saturating_add(1);
            if self.apt_count >= APT_CUTOFF {
                return Err(SelfTestError::RngProportion);
            }
        }
        self.apt_index = self.apt_index.saturating_add(1);
        if self.apt_index >= APT_WINDOW {
            self.apt_index = 0;
        }
        Ok(())
    }

    /// Examine every byte of `samples`.
    ///
    /// # Errors
    /// As [`RngHealth::feed`].
    pub fn feed_all(&mut self, samples: &[u8]) -> Result<(), SelfTestError> {
        samples.iter().try_for_each(|&b| self.feed(b))
    }
}

/// Start-up health test over at least [`STARTUP_SAMPLES`] fresh samples.
///
/// # Errors
/// As [`RngHealth::feed`], or [`SelfTestError::RngProportion`] if too few samples are given.
pub fn startup_rng_test(samples: &[u8]) -> Result<(), SelfTestError> {
    if samples.len() < STARTUP_SAMPLES {
        return Err(SelfTestError::RngProportion);
    }
    RngHealth::new().feed_all(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kats_pass() {
        run_kats(None).unwrap();
    }

    #[test]
    fn every_injected_fault_is_detected() {
        use SelfTestError::*;
        for t in [Sha256, Hmac, Hkdf, Ecdsa, Credential] {
            assert_eq!(run_kats(Some(t)), Err(t));
        }
    }

    #[test]
    fn startup_needs_enough_samples() {
        let mut good = std::vec::Vec::new();
        let mut ctr = 0u64;
        while good.len() < STARTUP_SAMPLES + 32 {
            good.extend_from_slice(&sha256(&[&ctr.to_le_bytes()]));
            ctr += 1;
        }
        startup_rng_test(&good[..STARTUP_SAMPLES]).unwrap();
        assert!(startup_rng_test(&good[..STARTUP_SAMPLES - 1]).is_err());
    }

    #[test]
    fn rng_health_detects_stuck_and_biased_sources() {
        assert_eq!(startup_rng_test(&[0u8; 2048]), Err(SelfTestError::RngRepetition));
        // Alternating two values never repeats consecutively but is heavily biased.
        let biased: std::vec::Vec<u8> = (0..2048).map(|i| if i % 2 == 0 { 7 } else { (i % 251) as u8 }).collect();
        assert_eq!(startup_rng_test(&biased), Err(SelfTestError::RngProportion));
        assert!(startup_rng_test(&[1u8; 10]).is_err());
    }

    #[test]
    fn rng_health_accepts_good_source() {
        let mut good = std::vec::Vec::new();
        let mut ctr = 0u64;
        while good.len() < 64 * 1024 {
            good.extend_from_slice(&sha256(&[&ctr.to_le_bytes()]));
            ctr += 1;
        }
        startup_rng_test(&good).unwrap();
    }

    #[test]
    fn rct_boundary() {
        let mut h = RngHealth::new();
        for _ in 0..(RCT_CUTOFF - 1) {
            h.feed(9).unwrap();
        }
        assert_eq!(h.feed(9), Err(SelfTestError::RngRepetition));
    }
}
