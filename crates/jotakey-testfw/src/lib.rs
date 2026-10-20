// (c) Javier Fernandez @ JotaSoft 2026
//! Support for the on-device tests: app descriptor, RTT logger, and a test platform that
//! uses the real TRNG with a software key (so CTAP flows run on silicon without touching
//! the eFuse key or the production flash region).

#![no_std]

use defmt_rtt as _;
use esp_hal::rng::Trng;
use jotakey_core::crypto::hmac_sha256;
use jotakey_core::platform::{PinRecord, Platform, PlatformError, SecretLabel};
use jotakey_core::selftest::RngHealth;
use jotakey_core::storage::{Flash, SECTOR_SIZE};

esp_bootloader_esp_idf::esp_app_desc!();

/// Scratch flash area for storage tests: the second half of the `jotakey` partition, which
/// the firmware never uses (its logs occupy the first six sectors at 0x3F0000).
pub const SCRATCH_OFFSET: u32 = 0x3F_8000;

/// Real TRNG + software root key + RAM counter and PIN state.
pub struct TargetPlatform {
    /// Hardware TRNG.
    pub trng: Trng,
    health: RngHealth,
    key: [u8; 32],
    epoch: [u8; 32],
    /// RAM counter.
    pub counter: u32,
    /// RAM PIN state.
    pub pin: PinRecord,
}

impl TargetPlatform {
    /// New platform with a fixed test key.
    pub fn new(trng: Trng) -> Self {
        Self { trng, health: RngHealth::new(), key: [0x5A; 32], epoch: [0; 32], counter: 0, pin: PinRecord::UNSET }
    }
}

impl Platform for TargetPlatform {
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), PlatformError> {
        self.trng.read(out);
        self.health.feed_all(out).map_err(|_| PlatformError)
    }
    fn derive_secret(&mut self, label: SecretLabel, context: &[u8], out: &mut [u8; 32]) -> Result<(), PlatformError> {
        *out = hmac_sha256(&self.key, &[label.as_bytes(), &self.epoch, context]).map_err(|_| PlatformError)?;
        Ok(())
    }
    fn increment_counter(&mut self) -> Result<u32, PlatformError> {
        self.counter = self.counter.checked_add(1).ok_or(PlatformError)?;
        Ok(self.counter)
    }
    fn rotate_epoch(&mut self) -> Result<(), PlatformError> {
        let mut e = [0u8; 32];
        self.random_bytes(&mut e)?;
        self.epoch = e;
        Ok(())
    }
    fn load_pin(&mut self) -> Result<PinRecord, PlatformError> {
        Ok(self.pin)
    }
    fn store_pin(&mut self, record: &PinRecord) -> Result<(), PlatformError> {
        self.pin = *record;
        Ok(())
    }
    fn uptime_ms(&self) -> u64 {
        esp_hal::time::Instant::now().duration_since_epoch().as_millis()
    }
}

/// The scratch region on real NOR flash, through the core's [`Flash`] trait.
pub struct Scratch<'d> {
    /// Flash driver.
    pub storage: esp_storage::FlashStorage<'d>,
}

impl Flash for Scratch<'_> {
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), PlatformError> {
        embedded_storage::nor_flash::ReadNorFlash::read(&mut self.storage, SCRATCH_OFFSET + offset, buf)
            .map_err(|_| PlatformError)
    }
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), PlatformError> {
        embedded_storage::nor_flash::NorFlash::write(&mut self.storage, SCRATCH_OFFSET + offset, data)
            .map_err(|_| PlatformError)
    }
    fn erase(&mut self, offset: u32) -> Result<(), PlatformError> {
        let from = SCRATCH_OFFSET + offset;
        embedded_storage::nor_flash::NorFlash::erase(&mut self.storage, from, from + SECTOR_SIZE)
            .map_err(|_| PlatformError)
    }
}
