// (c) Javier Fernandez @ JotaSoft 2026
//! [`Platform`] implementation on the jotakey key's STM32L432: the RNG peripheral with
//! continuous health tests, the root key in the OPTIGA, the signature counter in the OPTIGA,
//! and the record logs in internal flash.
//!
//! Production (milestone 2): `derive_secret` and `increment_counter` go to the OPTIGA over a
//! live shielded session (`jotakey_core::optiga`), established with the pairing secret kept
//! in flash. A unit without a pairing secret (not provisioned) has no root and stays in its
//! fault state (invariant 7). The INSECURE `dev-key` build keeps milestone 1's software root
//! and flash counter, and never touches the OPTIGA.

use embassy_stm32::pac;
use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::Rng;
use embassy_time::Instant;
use jotakey_core::optiga::OptigaError;
use jotakey_core::optiga::apdu::OID_ROOT;
use jotakey_core::optiga::device::NONCE_LEN;
use jotakey_core::optiga::provision::{self, MCU_RANDOM_LEN, Pairing, ProvisionError};
use jotakey_core::optiga::shielded::SECRET_LEN;
use jotakey_core::platform::{PIN_RECORD_LEN, PinRecord, Platform, PlatformError, SecretLabel};
use jotakey_core::selftest::RngHealth;
use jotakey_core::storage::{RecordLog, SECTOR_SIZE};
use zeroize::Zeroizing;

use crate::flash::Region;
use crate::optiga::SecureElement;

/// Counter log (`dev-key` builds only; production counts in the OPTIGA): logical sectors 0–1.
/// Epoch log: 2–3. PIN log: 4–5. Pairing secret log: 6–7.
const COUNTER_BASE: u32 = 0;
const EPOCH_BASE: u32 = 2 * SECTOR_SIZE;
const PIN_BASE: u32 = 4 * SECTOR_SIZE;
const PAIRING_BASE: u32 = 6 * SECTOR_SIZE;

/// Status polls before a missing RNG word counts as a failure. A word takes about 42 RNG
/// clock cycles (RM0394 §24.3); this is several milliseconds at 80 MHz.
const RNG_POLLS: u32 = 100_000;

/// Where the root key comes from.
pub enum RootKey {
    /// No root reachable: every derivation fails.
    #[allow(dead_code)]
    Unavailable,
    /// **INSECURE** software key derived from the STM32 unique ID (`dev-key` feature only).
    #[cfg(feature = "dev-key")]
    Insecure(Zeroizing<[u8; 32]>),
    /// `K_root` in the OPTIGA.
    #[cfg_attr(feature = "dev-key", allow(dead_code))]
    Optiga(SecureElement),
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
    /// The live-session check failed: possibly a replayed session on the bus. Every root
    /// operation fails until the next power-up.
    optiga_suspect: bool,
    flash: Region<'d>,
    counter: RecordLog<4>,
    epoch_log: RecordLog<32>,
    epoch: Zeroizing<[u8; 32]>,
    pin_log: RecordLog<PIN_RECORD_LEN>,
    pairing_log: RecordLog<SECRET_LEN>,
}

impl<'d> KeyPlatform<'d> {
    /// Mount the record logs, creating the epoch on first boot, and give the OPTIGA its
    /// pairing secret if the unit is provisioned.
    ///
    /// # Errors
    /// Flash or RNG failure.
    pub fn new(rng: TrueRng, mut root: RootKey, mut flash: Region<'d>) -> Result<Self, PlatformError> {
        let counter = RecordLog::<4>::mount(&mut flash, COUNTER_BASE)?;
        let epoch_log = RecordLog::<32>::mount(&mut flash, EPOCH_BASE)?;
        let pin_log = RecordLog::<PIN_RECORD_LEN>::mount(&mut flash, PIN_BASE)?;
        let pairing_log = RecordLog::<SECRET_LEN>::mount(&mut flash, PAIRING_BASE)?;
        if let (RootKey::Optiga(se), Some((_, p))) = (&mut root, pairing_log.latest()) {
            se.set_pairing(Pairing::from_bytes(p));
        }
        let mut p = Self {
            rng,
            health: RngHealth::new(),
            rng_failed: false,
            root,
            optiga_suspect: false,
            flash,
            counter,
            epoch_log,
            epoch: Zeroizing::new([0; 32]),
            pin_log,
            pairing_log,
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

    /// Whether the root is the OPTIGA and the unit holds a pairing secret.
    pub fn is_provisioned(&self) -> bool {
        matches!(&self.root, RootKey::Optiga(se) if se.is_paired()) && self.pairing_log.latest().is_some()
    }

    /// Whether the root is the OPTIGA (a production build).
    pub fn uses_optiga(&self) -> bool {
        matches!(self.root, RootKey::Optiga(_))
    }

    /// The OPTIGA with a live session: (re-)established here if needed, with a fresh nonce
    /// from the health-tested RNG.
    fn live_optiga(&mut self) -> Result<&mut SecureElement, PlatformError> {
        if self.optiga_suspect {
            return Err(PlatformError);
        }
        let live = match &mut self.root {
            RootKey::Optiga(se) => se.optiga().is_live(),
            _ => return Err(PlatformError),
        };
        if !live {
            let mut nonce = [0u8; NONCE_LEN];
            self.random_bytes(&mut nonce)?;
            let RootKey::Optiga(se) = &mut self.root else { return Err(PlatformError) };
            match se.connect(&nonce) {
                Ok(()) => {}
                Err(OptigaError::NotFresh) => {
                    defmt::error!("OPTIGA session failed the live-session check: possible replay on the bus");
                    self.optiga_suspect = true;
                    return Err(PlatformError);
                }
                Err(e) => {
                    defmt::warn!("OPTIGA session not established: {}", defmt::Debug2Format(&e));
                    return Err(PlatformError);
                }
            }
        }
        match &mut self.root {
            RootKey::Optiga(se) => Ok(se),
            _ => Err(PlatformError),
        }
    }

    /// Provision the OPTIGA (the `provision` build only; `jotakey_core::optiga::provision`),
    /// then store the pairing secret, read back from flash before this returns.
    ///
    /// # Errors
    /// [`ProvisionError`] from the OPTIGA, or a flash or RNG failure (as
    /// [`ProvisionError::Optiga`] of [`OptigaError::Bus`]).
    #[cfg_attr(not(feature = "provision"), allow(dead_code))]
    pub fn provision(&mut self) -> Result<(), ProvisionError> {
        let mut r = Zeroizing::new([0u8; MCU_RANDOM_LEN]);
        self.random_bytes(r.as_mut()).map_err(|_| OptigaError::Bus)?;
        let RootKey::Optiga(se) = &mut self.root else { return Err(OptigaError::NoSession.into()) };
        se.hard_reset();
        let pairing = provision::provision(se.optiga(), &r)?;
        if let Err(PlatformError) = self.pairing_log.append(&mut self.flash, pairing.as_bytes()) {
            if let Ok(l) = RecordLog::<SECRET_LEN>::mount(&mut self.flash, PAIRING_BASE) {
                self.pairing_log = l;
            }
            return Err(OptigaError::Bus.into());
        }
        if let RootKey::Optiga(se) = &mut self.root {
            se.set_pairing(pairing);
        }
        Ok(())
    }

    /// **IRREVERSIBLE.** Lock the provisioned OPTIGA (`provision-lock` build only).
    ///
    /// # Errors
    /// No live session, or an OPTIGA error.
    #[cfg_attr(not(feature = "provision-lock"), allow(dead_code))]
    pub fn lock(&mut self) -> Result<(), PlatformError> {
        let se = self.live_optiga()?;
        provision::lock(se.optiga()).map_err(|_| PlatformError)
    }

    /// Current persisted counter of the flash log (diagnostics, `dev-key` builds).
    pub fn counter_value(&self) -> u32 {
        self.counter.latest().map_or(0, |l| l.0)
    }

    fn flash_increment_counter(&mut self) -> Result<u32, PlatformError> {
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
        if self.uses_optiga() {
            // F = TLS1.2-PRF-SHA256(K_root, label ‖ epoch ‖ context), run by the OPTIGA
            // (AGENTS.md §3). One retry over a new session if the first attempt failed.
            for _ in 0..2 {
                let se = self.live_optiga()?;
                if se.optiga().derive(OID_ROOT, &[msg], out).is_ok() {
                    return Ok(());
                }
            }
            out.fill(0);
            return Err(PlatformError);
        }
        match &self.root {
            #[cfg(feature = "dev-key")]
            RootKey::Insecure(k) => {
                *out = jotakey_core::crypto::hmac_sha256(k.as_ref(), &[msg]).map_err(|_| PlatformError)?;
                Ok(())
            }
            _ => {
                let _ = (msg, out);
                Err(PlatformError)
            }
        }
    }

    fn increment_counter(&mut self) -> Result<u32, PlatformError> {
        if !self.uses_optiga() {
            return self.flash_increment_counter();
        }
        // The OPTIGA's monotonic counter 0xE120: counted, then read back through the live
        // session, and released only above every value released since power-up (invariant 2;
        // `formal/Jotakey/Shielded.lean`). A retry after a failure counts again, which only
        // skips a value.
        for _ in 0..2 {
            let se = self.live_optiga()?;
            match se.optiga().increment_counter() {
                Ok(v) => return Ok(v),
                Err(OptigaError::CounterNotIncreasing) => {
                    defmt::error!("OPTIGA counter did not increase");
                    return Err(PlatformError);
                }
                Err(_) => {}
            }
        }
        Err(PlatformError)
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
