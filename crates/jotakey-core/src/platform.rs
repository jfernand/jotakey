//! The boundary between the core and the hardware.
//!
//! The firmware implements [`Platform`] on top of the ESP32-C6 peripherals; tests implement
//! it with deterministic mocks. User presence is deliberately *not* part of this trait: the
//! core returns [`crate::ctap::Outcome::NeedsUserPresence`] and the caller resumes it with a
//! [`PresenceResult`]. That keeps the core synchronous and makes "no signature without presence"
//! a property of a pure state machine rather than of an async callback.

/// A hardware or storage failure. Carries no detail so nothing sensitive can leak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformError;

/// Label of a root-derived secret. Each label yields an independent 32-byte key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretLabel {
    /// Key for credential-ID authentication tags.
    CredentialMac,
    /// Input keying material for per-credential private keys.
    CredentialSeed,
}

impl SecretLabel {
    /// Domain-separation string passed to the root HMAC.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::CredentialMac => b"jotakey/mac/v1",
            Self::CredentialSeed => b"jotakey/seed/v1",
        }
    }
}

/// Result of waiting for the user to touch the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceResult {
    /// The button was pressed after the request arrived.
    Confirmed,
    /// Nobody pressed the button before the deadline.
    Timeout,
    /// The host cancelled the request (CTAPHID_CANCEL / BLE CANCEL).
    Cancelled,
}

/// Hardware services the core needs.
pub trait Platform {
    /// Fill `out` with output of the hardware TRNG, after health tests.
    ///
    /// # Errors
    /// Returns `PlatformError` if the RNG is unhealthy; the core then fails closed.
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), PlatformError>;

    /// Compute `HMAC-SHA256(K_dev, label ‖ epoch)` where `K_dev` never leaves the eFuse HMAC
    /// peripheral and `epoch` is the reset generation secret stored in encrypted flash.
    ///
    /// # Errors
    /// Returns `PlatformError` if the HMAC peripheral or storage fails.
    fn derive_secret(&mut self, label: SecretLabel, out: &mut [u8; 32]) -> Result<(), PlatformError>;

    /// Durably increment the global signature counter and return the *new* value.
    ///
    /// The value must be persisted before this returns (invariant 2).
    ///
    /// # Errors
    /// Returns `PlatformError` if the write fails or the counter is exhausted.
    fn increment_counter(&mut self) -> Result<u32, PlatformError>;

    /// Replace the reset epoch with a fresh random secret, invalidating every credential
    /// minted before.
    ///
    /// # Errors
    /// Returns `PlatformError` if the RNG or storage fails.
    fn rotate_epoch(&mut self) -> Result<(), PlatformError>;

    /// Milliseconds since power-up (monotonic).
    fn uptime_ms(&self) -> u64;
}
