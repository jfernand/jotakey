// (c) Javier Fernandez @ JotaSoft 2026
//! [`Platform`] implementation on the jotakey key's STM32L432: the RNG peripheral with
//! continuous health tests, the root key, and the record logs in internal flash.
//!
//! Milestone 1: the OPTIGA driver does not exist yet. Without the `dev-key` feature there is
//! no root, `derive_secret` fails, and the boot probe puts the key in its permanent fault
//! state (invariant 7). The signature counter is a flash record log until milestone 2 moves
//! it to the OPTIGA's monotonic counter `0xE120` (AGENTS.md §3).

use embassy_stm32::pac;
use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::Rng;
use embassy_time::Instant;
use jotakey_core::platform::{PIN_RECORD_LEN, PinRecord, Platform, PlatformError, SecretLabel};
use jotakey_core::selftest::RngHealth;
use jotakey_core::storage::{RecordLog, SECTOR_SIZE};
use zeroize::Zeroizing;

use crate::flash::Region;

/// Counter log (milestone 1 only): logical sectors 0–1. Epoch log: 2–3. PIN log: 4–5.
/// Sectors 6–7 are reserved for the OPTIGA platform binding secret (milestone 2).
const COUNTER_BASE: u32 = 0;
const EPOCH_BASE: u32 = 2 * SECTOR_SIZE;
const PIN_BASE: u32 = 4 * SECTOR_SIZE;

/// Status polls before a missing RNG word counts as a failure. A word takes about 42 RNG
/// clock cycles (RM0394 §24.3); this is several milliseconds at 80 MHz.
const RNG_POLLS: u32 = 100_000;

/// Where the root key comes from.
pub enum RootKey {
    /// No root reachable: every derivation fails (production build in milestone 1, until the
    /// OPTIGA driver exists).
    #[cfg_attr(feature = "dev-key", allow(dead_code))]
    Unavailable,
    /// **INSECURE** software key derived from the STM32 unique ID (`dev-key` feature only).
    #[cfg(feature = "dev-key")]
    Insecure(Zeroizing<[u8; 32]>),
}

/// The STM32 RNG, read register by register so that every seed or clock error is reported
/// (embassy's blocking reader resets the peripheral and carries on).
pub struct TrueRng {
    /// Keeps the peripheral clocked; dropping it disables the RNG.
    _driver: Rng<'static, RNG>,
}

impl TrueRng {
    /// Take the enabled driver.
    pub fn new(driver: Rng<'static, RNG>) -> Self {
        Self { _driver: driver }
    }

    fn word(&mut self) -> Result<u32, PlatformError> {
        let rng = pac::RNG;
        for _ in 0..RNG_POLLS {
            let sr = rng.sr().read();
            if sr.seis() || sr.ceis() || sr.secs() || sr.cecs() {
                return Err(PlatformError);
            }
            if sr.drdy() {
                let w = rng.dr().read();
                // RM0394: a zero word means a seed error is about to be flagged.
                return if w == 0 { Err(PlatformError) } else { Ok(w) };
            }
        }
        Err(PlatformError)
    }

    /// Fill `out` with raw RNG output (no health test).
    ///
    /// # Errors
    /// The peripheral reported a seed or clock error, or produced nothing.
    pub fn fill(&mut self, out: &mut [u8]) -> Result<(), PlatformError> {
        for chunk in out.chunks_mut(4) {
            let w = self.word()?.to_le_bytes();
            chunk.copy_from_slice(w.get(..chunk.len()).ok_or(PlatformError)?);
        }
        Ok(())
    }
}

/// Hardware services for the authenticator core.
pub struct KeyPlatform<'d> {
    rng: TrueRng,
    health: RngHealth,
    rng_failed: bool,
    root: RootKey,
    flash: Region<'d>,
    counter: RecordLog<4>,
    epoch_log: RecordLog<32>,
    epoch: Zeroizing<[u8; 32]>,
    pin_log: RecordLog<PIN_RECORD_LEN>,
}

impl<'d> KeyPlatform<'d> {
    /// Mount the record logs, creating the epoch on first boot.
    ///
    /// # Errors
    /// Flash or RNG failure.
    pub fn new(rng: TrueRng, root: RootKey, mut flash: Region<'d>) -> Result<Self, PlatformError> {
        let counter = RecordLog::<4>::mount(&mut flash, COUNTER_BASE)?;
        let epoch_log = RecordLog::<32>::mount(&mut flash, EPOCH_BASE)?;
        let pin_log = RecordLog::<PIN_RECORD_LEN>::mount(&mut flash, PIN_BASE)?;
        let mut p = Self {
            rng,
            health: RngHealth::new(),
            rng_failed: false,
            root,
            flash,
            counter,
            epoch_log,
            epoch: Zeroizing::new([0; 32]),
            pin_log,
        };
        match p.epoch_log.latest() {
            Some((_, e)) => p.epoch.copy_from_slice(e),
            None => p.rotate_epoch()?,
        }
        Ok(p)
    }

    /// Draw raw RNG bytes *without* consuming them for crypto (start-up test).
    ///
    /// # Errors
    /// The peripheral reported an error.
    pub fn raw_samples(&mut self, buf: &mut [u8]) -> Result<(), PlatformError> {
        self.rng.fill(buf)
    }

    /// Current persisted counter (diagnostics).
    pub fn counter_value(&self) -> u32 {
        self.counter.latest().map_or(0, |l| l.0)
    }
}

impl Platform for KeyPlatform<'_> {
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), PlatformError> {
        if self.rng_failed {
            return Err(PlatformError);
        }
        // Continuous SP 800-90B health tests on every byte handed out (invariant 7), and any
        // error the peripheral reports, latch the failure.
        if self.rng.fill(out).is_err() || self.health.feed_all(out).is_err() {
            self.rng_failed = true;
            out.fill(0);
            return Err(PlatformError);
        }
        Ok(())
    }

    fn derive_secret(&mut self, label: SecretLabel, context: &[u8], out: &mut [u8; 32]) -> Result<(), PlatformError> {
        // label ‖ epoch ‖ context: at most 15 + 32 + 65 bytes (AGENTS.md §3).
        let l = label.as_bytes();
        let mut msg = Zeroizing::new([0u8; 128]);
        let e = l.len().checked_add(32).ok_or(PlatformError)?;
        let n = e.checked_add(context.len()).ok_or(PlatformError)?;
        msg.get_mut(..l.len()).ok_or(PlatformError)?.copy_from_slice(l);
        msg.get_mut(l.len()..e).ok_or(PlatformError)?.copy_from_slice(self.epoch.as_ref());
        msg.get_mut(e..n).ok_or(PlatformError)?.copy_from_slice(context);
        let msg = msg.get(..n).ok_or(PlatformError)?;
        match &self.root {
            RootKey::Unavailable => {
                let _ = (msg, out);
                Err(PlatformError)
            }
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
        if let Err(e) = self.epoch_log.append(&mut self.flash, &fresh) {
            // Re-mount, as after every failed append (`RecordLog::append`; the contract
            // `formal/Jotakey/RecordLog.lean` proves the log safe under).
            if let Ok(l) = RecordLog::<32>::mount(&mut self.flash, EPOCH_BASE) {
                self.epoch_log = l;
            }
            return Err(e);
        }
        self.epoch.copy_from_slice(fresh.as_ref());
        Ok(())
    }

    fn load_pin(&mut self) -> Result<PinRecord, PlatformError> {
        match self.pin_log.latest() {
            // A key that never had a PIN has an empty log.
            None => Ok(PinRecord::UNSET),
            Some((_, bytes)) => PinRecord::from_bytes(bytes).ok_or(PlatformError),
        }
    }

    fn store_pin(&mut self, record: &PinRecord) -> Result<(), PlatformError> {
        // `append` returns only after reading the record back from flash.
        match self.pin_log.append(&mut self.flash, &record.to_bytes()) {
            Ok(_) => Ok(()),
            Err(e) => {
                if let Ok(l) = RecordLog::<PIN_RECORD_LEN>::mount(&mut self.flash, PIN_BASE) {
                    self.pin_log = l;
                }
                Err(e)
            }
        }
    }

    fn uptime_ms(&self) -> u64 {
        // The embassy time driver starts at power-up.
        Instant::now().as_millis()
    }
}
