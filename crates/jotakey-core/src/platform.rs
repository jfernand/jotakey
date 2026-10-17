// (c) Javier Fernandez @ JotaSoft 2026
//! The boundary between the core and the hardware.
//!
//! Each firmware implements [`Platform`] on top of its hardware (the ESP32-C6's eFuse HMAC
//! peripheral, the jotakey key's OPTIGA); tests implement it with deterministic mocks. User presence is deliberately *not* part of this trait: the
//! core returns [`crate::ctap::Outcome::NeedsUserPresence`] and the caller resumes it with a
//! [`PresenceResult`]. That keeps the core synchronous and makes "no signature without presence"
//! a property of a pure state machine rather than of an async callback.

/// A hardware or storage failure. Carries no detail so nothing sensitive can leak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformError;

/// Label of a root-derived, per-credential secret (`AGENTS.md` §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretLabel {
    /// A credential ID's tag; context `version ‖ rpIdHash ‖ nonce`.
    CredentialTag,
    /// A credential's private-key seed; context `rpIdHash ‖ nonce`.
    CredentialSeed,
}

impl SecretLabel {
    /// Domain-separation string that starts the derivation input.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::CredentialTag => b"jotakey/tag/v1",
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

    /// Compute `F(root, label ‖ epoch ‖ context)` for one credential, inside the hardware key
    /// store: `HMAC-SHA256(K_dev, …)` in the ESP32-C6's eFuse HMAC peripheral,
    /// `TLS1.2-PRF-SHA256(K_root, …)` in the jotakey key's OPTIGA. The root never leaves the
    /// hardware, and no output covers more than one credential. `epoch` is the reset
    /// generation secret.
    ///
    /// # Errors
    /// Returns `PlatformError` if the hardware or storage fails.
    fn derive_secret(&mut self, label: SecretLabel, context: &[u8], out: &mut [u8; 32]) -> Result<(), PlatformError>;

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
