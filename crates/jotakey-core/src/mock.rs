// (c) Javier Fernandez @ JotaSoft 2026
//! Deterministic [`Platform`] for tests, fuzzing and differential testing.
//!
//! **Never use in firmware.** Its "random" bytes are a hash chain and its root key is in RAM.

use crate::crypto::{hmac_sha256, sha256};
use crate::platform::{Platform, PlatformError, SecretLabel};

/// A software platform with fault-injection switches.
#[derive(Clone, Debug)]
pub struct MockPlatform {
    /// Stand-in for the eFuse key.
    pub root: [u8; 32],
    /// Reset generation secret.
    pub epoch: [u8; 32],
    /// Persisted signature counter.
    pub counter: u32,
    /// Milliseconds since "power-up".
    pub uptime: u64,
    /// Make every RNG call fail.
    pub fail_rng: bool,
    /// Make every counter increment fail.
    pub fail_counter: bool,
    /// Make every secret derivation fail.
    pub fail_derive: bool,
    rng_seed: [u8; 32],
    rng_ctr: u64,
}

impl MockPlatform {
    /// A platform whose behaviour is fully determined by `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let s = seed.to_le_bytes();
        Self {
            root: sha256(&[b"root", &s]),
            epoch: sha256(&[b"epoch", &s]),
            counter: 0,
            uptime: 0,
            fail_rng: false,
            fail_counter: false,
            fail_derive: false,
            rng_seed: sha256(&[b"rng", &s]),
            rng_ctr: 0,
        }
    }
}

impl Platform for MockPlatform {
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), PlatformError> {
        if self.fail_rng {
            return Err(PlatformError);
        }
        for chunk in out.chunks_mut(32) {
            let block = sha256(&[&self.rng_seed, &self.rng_ctr.to_le_bytes()]);
            self.rng_ctr = self.rng_ctr.wrapping_add(1);
            let src = block.get(..chunk.len()).ok_or(PlatformError)?;
            chunk.copy_from_slice(src);
        }
        Ok(())
    }

    fn derive_secret(&mut self, label: SecretLabel, context: &[u8], out: &mut [u8; 32]) -> Result<(), PlatformError> {
        if self.fail_derive {
            return Err(PlatformError);
        }
        *out = hmac_sha256(&self.root, &[label.as_bytes(), &self.epoch, context]).map_err(|_| PlatformError)?;
        Ok(())
    }

    fn increment_counter(&mut self) -> Result<u32, PlatformError> {
        if self.fail_counter {
            return Err(PlatformError);
        }
        self.counter = self.counter.checked_add(1).ok_or(PlatformError)?;
        Ok(self.counter)
    }

    fn rotate_epoch(&mut self) -> Result<(), PlatformError> {
        let mut e = [0u8; 32];
        self.random_bytes(&mut e)?;
        self.epoch = e;
        Ok(())
    }

    fn uptime_ms(&self) -> u64 {
        self.uptime
    }
}
