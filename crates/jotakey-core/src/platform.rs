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
    /// The stored form of the PIN; context `LEFT(SHA-256(PIN), 16)`. Keyed by the root, so a
    /// copy of the flash does not allow guessing the PIN offline; bound to the epoch, so a
    /// reset leaves no PIN that still verifies.
    PinVerifier,
}

impl SecretLabel {
    /// Domain-separation string that starts the derivation input.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::CredentialTag => b"jotakey/tag/v1",
            Self::CredentialSeed => b"jotakey/seed/v1",
            Self::PinVerifier => b"jotakey/pin/v1",
        }
    }
}

/// Wrong PIN entries allowed before the PIN blocks (CTAP 2.1 §6.5.2.1, `maxPinRetries`).
pub const PIN_RETRIES_MAX: u8 = 8;

/// The persistent PIN state (CTAP 2.1 §6.5.2).
///
/// Stored as 36 bytes: `set (1) ‖ retries (1) ‖ 0 0 ‖ verifier (32)`; [`PinRecord::to_bytes`]
/// and [`PinRecord::from_bytes`] are the only encoder and decoder, so every platform stores
/// the same format.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PinRecord {
    /// [`SecretLabel::PinVerifier`] of the PIN, or `None` when no PIN is set.
    pub verifier: Option<[u8; 32]>,
    /// Wrong entries left; [`PIN_RETRIES_MAX`] when unset and after every correct entry.
    pub retries: u8,
}

impl core::fmt::Debug for PinRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Invariant 8: the verifier is never printed.
        f.debug_struct("PinRecord").field("set", &self.verifier.is_some()).field("retries", &self.retries).finish()
    }
}

/// Length of an encoded [`PinRecord`].
pub const PIN_RECORD_LEN: usize = 36;

impl PinRecord {
    /// No PIN: the state of a new device and after a reset.
    pub const UNSET: Self = Self { verifier: None, retries: PIN_RETRIES_MAX };

    /// The storage encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PIN_RECORD_LEN] {
        let mut b = [0u8; PIN_RECORD_LEN];
        let (head, verifier) = b.split_at_mut(4);
        head.copy_from_slice(&[u8::from(self.verifier.is_some()), self.retries, 0, 0]);
        if let Some(v) = &self.verifier {
            verifier.copy_from_slice(v);
        }
        b
    }

    /// Decode the storage encoding. Anything [`PinRecord::to_bytes`] cannot produce is
    /// rejected, and the caller fails closed.
    #[must_use]
    pub fn from_bytes(b: &[u8; PIN_RECORD_LEN]) -> Option<Self> {
        let (head, verifier) = b.split_first_chunk::<4>()?;
        let verifier: [u8; 32] = verifier.try_into().ok()?;
        let [set, retries, 0, 0] = *head else { return None };
        if retries > PIN_RETRIES_MAX {
            return None;
        }
        match set {
            0 if verifier == [0; 32] => Some(Self { verifier: None, retries }),
            1 => Some(Self { verifier: Some(verifier), retries }),
            _ => None,
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

    /// Read the persistent PIN state ([`PinRecord::UNSET`] on a new device).
    ///
    /// # Errors
    /// Returns `PlatformError` if storage fails or holds a record that does not decode.
    fn load_pin(&mut self) -> Result<PinRecord, PlatformError>;

    /// Durably replace the PIN state. Returns `Ok` only once the record is persisted: the
    /// core counts a PIN attempt with this *before* comparing the PIN, so that cutting the
    /// power cannot buy an uncounted guess.
    ///
    /// # Errors
    /// Returns `PlatformError` if the write fails.
    fn store_pin(&mut self, record: &PinRecord) -> Result<(), PlatformError>;

    /// Milliseconds since power-up (monotonic).
    fn uptime_ms(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_record_layout_is_pinned() {
        assert_eq!(PinRecord::UNSET.to_bytes(), {
            let mut b = [0u8; PIN_RECORD_LEN];
            b[1] = 8;
            b
        });
        let set = PinRecord { verifier: Some([0xAB; 32]), retries: 5 };
        let b = set.to_bytes();
        assert_eq!(b[..4], [1, 5, 0, 0]);
        assert_eq!(b[4..], [0xAB; 32]);
        assert_eq!(PinRecord::from_bytes(&b), Some(set));
        assert_eq!(PinRecord::from_bytes(&PinRecord::UNSET.to_bytes()), Some(PinRecord::UNSET));
        let zero_retries = PinRecord { verifier: Some([1; 32]), retries: 0 };
        assert_eq!(PinRecord::from_bytes(&zero_retries.to_bytes()), Some(zero_retries));
        // A set PIN may have an all-zero verifier; the flag decides.
        let zero_verifier = PinRecord { verifier: Some([0; 32]), retries: 8 };
        assert_eq!(PinRecord::from_bytes(&zero_verifier.to_bytes()), Some(zero_verifier));
    }

    #[test]
    fn malformed_pin_records_are_rejected() {
        let good = PinRecord { verifier: Some([7; 32]), retries: PIN_RETRIES_MAX }.to_bytes();
        for (i, v) in [(0, 2), (0, 0xFF), (1, PIN_RETRIES_MAX + 1), (1, 0xFF), (2, 1), (3, 1)] {
            let mut b = good;
            b[i] = v;
            assert_eq!(PinRecord::from_bytes(&b), None, "byte {i} = {v}");
        }
        // Erased flash (all 0xFF) and an unset record carrying a verifier.
        assert_eq!(PinRecord::from_bytes(&[0xFF; PIN_RECORD_LEN]), None);
        let mut b = PinRecord::UNSET.to_bytes();
        b[35] = 1;
        assert_eq!(PinRecord::from_bytes(&b), None);
        let mut b = PinRecord::UNSET.to_bytes();
        b[1] = PIN_RETRIES_MAX;
        assert!(PinRecord::from_bytes(&b).is_some());
    }

    #[test]
    fn pin_records_do_not_print_the_verifier() {
        let r = PinRecord { verifier: Some([0xAB; 32]), retries: 3 };
        assert_eq!(std::format!("{r:?}"), "PinRecord { set: true, retries: 3 }");
    }

    #[test]
    fn labels_are_distinct() {
        assert_eq!(SecretLabel::PinVerifier.as_bytes(), b"jotakey/pin/v1");
        assert_ne!(SecretLabel::PinVerifier.as_bytes(), SecretLabel::CredentialTag.as_bytes());
        assert_ne!(SecretLabel::PinVerifier.as_bytes(), SecretLabel::CredentialSeed.as_bytes());
    }
}
