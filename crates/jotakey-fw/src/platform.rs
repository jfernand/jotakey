//! [`Platform`] implementation on the ESP32-C6: TRNG with continuous health tests, the
//! eFuse-keyed HMAC peripheral, and the power-safe record logs in the `jotakey` flash
//! partition.

use embassy_time::Instant;
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use esp_hal::hmac::{Hmac, HmacPurpose, KeyId};
use esp_hal::rng::Trng;
use esp_storage::FlashStorage;
use jotakey_core::platform::{Platform, PlatformError, SecretLabel};
use jotakey_core::selftest::RngHealth;
use jotakey_core::storage::{Flash, RecordLog, SECTOR_SIZE};
use zeroize::Zeroizing;

/// Offset of the `jotakey` data partition (must match `partitions.csv`).
pub const REGION_OFFSET: u32 = 0x3F_0000;
/// eFuse key block holding `K_dev` (purpose `HMAC_UP`). See `scripts/provision.sh`.
pub const ROOT_KEY: KeyId = KeyId::Key0;
/// Counter log: sectors 0–1 of the region. Epoch log: sectors 2–3.
const COUNTER_BASE: u32 = 0;
const EPOCH_BASE: u32 = 2 * SECTOR_SIZE;

/// The `jotakey` partition seen through the core's [`Flash`] trait.
pub struct Region<'d> {
    storage: FlashStorage<'d>,
}

impl<'d> Region<'d> {
    /// Wrap the flash driver.
    pub fn new(storage: FlashStorage<'d>) -> Self {
        Self { storage }
    }

    fn abs(offset: u32) -> Result<u32, PlatformError> {
        if offset >= 4 * SECTOR_SIZE {
            return Err(PlatformError);
        }
        REGION_OFFSET.checked_add(offset).ok_or(PlatformError)
    }
}

impl Flash for Region<'_> {
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), PlatformError> {
        let len = u32::try_from(buf.len()).map_err(|_| PlatformError)?;
        Self::abs(offset.checked_add(len).ok_or(PlatformError)?.saturating_sub(1))?;
        ReadNorFlash::read(&mut self.storage, Self::abs(offset)?, buf).map_err(|_| PlatformError)
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), PlatformError> {
        NorFlash::write(&mut self.storage, Self::abs(offset)?, data).map_err(|_| PlatformError)
    }

    fn erase(&mut self, offset: u32) -> Result<(), PlatformError> {
        let from = Self::abs(offset)?;
        NorFlash::erase(&mut self.storage, from, from.checked_add(SECTOR_SIZE).ok_or(PlatformError)?)
            .map_err(|_| PlatformError)
    }
}

/// Where the root key comes from.
pub enum RootKey<'d> {
    /// The eFuse key block, usable only through the HMAC peripheral (production).
    #[cfg_attr(feature = "dev-key", allow(dead_code))]
    Efuse(Hmac<'d>),
    /// **INSECURE** software key derived from the chip MAC (`dev-key` feature only).
    #[cfg(feature = "dev-key")]
    Insecure(Zeroizing<[u8; 32]>),
}

/// Hardware services for the authenticator core.
pub struct EspPlatform<'d> {
    trng: Trng,
    health: RngHealth,
    rng_failed: bool,
    root: RootKey<'d>,
    flash: Region<'d>,
    counter: RecordLog<4>,
    epoch_log: RecordLog<32>,
    epoch: Zeroizing<[u8; 32]>,
}

impl<'d> EspPlatform<'d> {
    /// Mount the record logs, creating the epoch on first boot.
    ///
    /// # Errors
    /// Flash or RNG failure.
    pub fn new(trng: Trng, root: RootKey<'d>, mut flash: Region<'d>) -> Result<Self, PlatformError> {
        let counter = RecordLog::<4>::mount(&mut flash, COUNTER_BASE)?;
        let epoch_log = RecordLog::<32>::mount(&mut flash, EPOCH_BASE)?;
        let mut p = Self {
            trng,
            health: RngHealth::new(),
            rng_failed: false,
            root,
            flash,
            counter,
            epoch_log,
            epoch: Zeroizing::new([0; 32]),
        };
        match p.epoch_log.latest() {
            Some((_, e)) => p.epoch.copy_from_slice(e),
            None => p.rotate_epoch()?,
        }
        Ok(p)
    }

    /// Draw `buf.len()` raw TRNG bytes *without* consuming them for crypto (start-up test).
    pub fn raw_samples(&mut self, buf: &mut [u8]) {
        self.trng.read(buf);
    }

    /// Current persisted counter (diagnostics).
    pub fn counter_value(&self) -> u32 {
        self.counter.latest().map_or(0, |l| l.0)
    }

    fn hmac_efuse(hmac: &mut Hmac<'d>, msg: &[u8], out: &mut [u8; 32]) -> Result<(), PlatformError> {
        hmac.init();
        nb::block!(hmac.configure(HmacPurpose::ToUser, ROOT_KEY)).map_err(|_| PlatformError)?;
        let mut rest = msg;
        while !rest.is_empty() {
            rest = nb::block!(hmac.update(rest)).map_err(|_| PlatformError)?;
        }
        nb::block!(hmac.finalize(out.as_mut_slice())).map_err(|_| PlatformError)
    }
}

impl Platform for EspPlatform<'_> {
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), PlatformError> {
        if self.rng_failed {
            return Err(PlatformError);
        }
        self.trng.read(out);
        // Continuous SP 800-90B health tests on every byte handed out (invariant 7).
        if self.health.feed_all(out).is_err() {
            self.rng_failed = true;
            out.fill(0);
            return Err(PlatformError);
        }
        Ok(())
    }

    fn derive_secret(&mut self, label: SecretLabel, out: &mut [u8; 32]) -> Result<(), PlatformError> {
        let l = label.as_bytes();
        let mut msg = Zeroizing::new([0u8; 64]);
        let n = l.len().checked_add(32).ok_or(PlatformError)?;
        msg.get_mut(..l.len()).ok_or(PlatformError)?.copy_from_slice(l);
        msg.get_mut(l.len()..n).ok_or(PlatformError)?.copy_from_slice(self.epoch.as_ref());
        let msg = msg.get(..n).ok_or(PlatformError)?;
        match &mut self.root {
            RootKey::Efuse(hmac) => Self::hmac_efuse(hmac, msg, out),
            #[cfg(feature = "dev-key")]
            RootKey::Insecure(k) => {
                *out = jotakey_core::crypto::hmac_sha256(k.as_ref(), &[msg]).map_err(|_| PlatformError)?;
                Ok(())
            }
        }
    }

    fn increment_counter(&mut self) -> Result<u32, PlatformError> {
        let next = self.counter_value().checked_add(1).ok_or(PlatformError)?;
        match self.counter.append(&mut self.flash, &next.to_le_bytes()) {
            Ok(seq) => Ok(seq),
            Err(e) => {
                // Re-mount so the in-memory view matches flash again.
                if let Ok(c) = RecordLog::<4>::mount(&mut self.flash, COUNTER_BASE) {
                    self.counter = c;
                }
                Err(e)
            }
        }
    }

    fn rotate_epoch(&mut self) -> Result<(), PlatformError> {
        let mut fresh = Zeroizing::new([0u8; 32]);
        self.random_bytes(fresh.as_mut())?;
        self.epoch_log.append(&mut self.flash, &fresh)?;
        self.epoch.copy_from_slice(fresh.as_ref());
        Ok(())
    }

    fn uptime_ms(&self) -> u64 {
        // The embassy time driver starts at power-up.
        Instant::now().as_millis()
    }
}
