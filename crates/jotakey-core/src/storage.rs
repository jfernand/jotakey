//! Power-loss-safe persistent records (signature counter, reset epoch).
//!
//! Each [`RecordLog`] owns two flash sectors and appends fixed-size records:
//!
//! ```text
//! record = MAGIC (4) ‖ seq (4, LE) ‖ payload (N) ‖ CRC-32 (4, LE) over magic‖seq‖payload
//! ```
//!
//! The current value is the valid record with the highest `seq`. A new value is appended
//! after the last record of the active sector. When that sector is full, the *other*
//! sector is erased and the record goes there. The sector holding the current value is
//! never erased, so at least one valid copy survives at every instant.
//!
//! **Invariant 2.** [`RecordLog::append`] reads the record back and only returns `Ok` after
//! the bytes in flash verify. If power fails during the write, the record is torn and
//! ignored at the next mount. The caller never released the new value, so handing out the
//! same `seq` again later is safe. Values returned by `Ok` are strictly increasing for the
//! life of the device.
//!
//! On the ESP32-C6, flash encryption makes these sectors unreadable off-chip. That matters
//! for the epoch secret.

use crate::platform::PlatformError;
use crate::transport::serial::crc32;

/// Erase granularity of the flash.
pub const SECTOR_SIZE: u32 = 4096;
/// Record marker ("JKR1").
const MAGIC: [u8; 4] = *b"JKR1";

/// NOR flash as the record log needs it. Programming can only clear bits; erase sets a
/// whole sector to `0xFF`. Offsets are relative to the start of the log's region.
pub trait Flash {
    /// Read `buf.len()` bytes at `offset`.
    ///
    /// # Errors
    /// Hardware failure.
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), PlatformError>;
    /// Program `data` at `offset` (4-byte aligned, multiple of 4 bytes).
    ///
    /// # Errors
    /// Hardware failure.
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), PlatformError>;
    /// Erase the sector starting at `offset`.
    ///
    /// # Errors
    /// Hardware failure.
    fn erase(&mut self, offset: u32) -> Result<(), PlatformError>;
}

/// A two-sector append-only log of `N`-byte payloads (`N` a multiple of 4, `N ≤ 64`).
#[derive(Clone, Debug)]
pub struct RecordLog<const N: usize> {
    base: u32,
    /// Sector (0 or 1) holding the latest record.
    active: u32,
    /// Offset inside the active sector where the next record goes.
    next: u32,
    latest: Option<(u32, [u8; N])>,
}

const fn record_len(n: usize) -> u32 {
    #[allow(clippy::cast_possible_truncation, clippy::arithmetic_side_effects)] // n ≤ 64.
    let len = (4 + 4 + n + 4) as u32;
    len
}

impl<const N: usize> RecordLog<N> {
    const LEN: u32 = record_len(N);
    const PER_SECTOR: u32 = SECTOR_SIZE / Self::LEN;
    const _CHECK: () = assert!(N.is_multiple_of(4) && N <= 64, "payload must be a multiple of 4 and ≤ 64");

    fn encode(seq: u32, payload: &[u8; N]) -> Result<[u8; 76], PlatformError> {
        let mut rec = [0xFFu8; 76];
        let body_end = 8usize.checked_add(N).ok_or(PlatformError)?;
        rec.get_mut(..4).ok_or(PlatformError)?.copy_from_slice(&MAGIC);
        rec.get_mut(4..8).ok_or(PlatformError)?.copy_from_slice(&seq.to_le_bytes());
        rec.get_mut(8..body_end).ok_or(PlatformError)?.copy_from_slice(payload);
        let crc = crc32(rec.get(..body_end).ok_or(PlatformError)?);
        let crc_end = body_end.checked_add(4).ok_or(PlatformError)?;
        rec.get_mut(body_end..crc_end).ok_or(PlatformError)?.copy_from_slice(&crc.to_le_bytes());
        Ok(rec)
    }

    fn decode(raw: &[u8]) -> Option<(u32, [u8; N])> {
        let body_end = 8usize.checked_add(N)?;
        let body = raw.get(..body_end)?;
        let crc: [u8; 4] = raw.get(body_end..body_end.checked_add(4)?)?.try_into().ok()?;
        if body.get(..4)? != MAGIC || crc32(body) != u32::from_le_bytes(crc) {
            return None;
        }
        let seq = u32::from_le_bytes(body.get(4..8)?.try_into().ok()?);
        let payload: [u8; N] = body.get(8..body_end)?.try_into().ok()?;
        Some((seq, payload))
    }

    /// Scan both sectors and recover the latest valid record.
    ///
    /// # Errors
    /// Flash read failure.
    pub fn mount<F: Flash>(flash: &mut F, base: u32) -> Result<Self, PlatformError> {
        let () = Self::_CHECK;
        let mut log = Self { base, active: 0, next: 0, latest: None };
        let mut buf = [0u8; 76];
        let len = usize::try_from(Self::LEN).map_err(|_| PlatformError)?;
        for sector in 0..2u32 {
            for i in 0..Self::PER_SECTOR {
                let off = i.checked_mul(Self::LEN).ok_or(PlatformError)?;
                let rec = buf.get_mut(..len).ok_or(PlatformError)?;
                flash.read(log.sector_base(sector)?.checked_add(off).ok_or(PlatformError)?, rec)?;
                if let Some((seq, payload)) = Self::decode(rec)
                    && log.latest.is_none_or(|(s, _)| seq > s)
                {
                    log.latest = Some((seq, payload));
                    log.active = sector;
                }
            }
        }
        log.next = log.scan_end(flash, log.active)?;
        Ok(log)
    }

    fn sector_base(&self, sector: u32) -> Result<u32, PlatformError> {
        self.base.checked_add(sector.checked_mul(SECTOR_SIZE).ok_or(PlatformError)?).ok_or(PlatformError)
    }

    fn scan_end<F: Flash>(&self, flash: &mut F, sector: u32) -> Result<u32, PlatformError> {
        let mut buf = [0u8; 76];
        let len = usize::try_from(Self::LEN).map_err(|_| PlatformError)?;
        let mut end = 0u32;
        for i in 0..Self::PER_SECTOR {
            let off = i.checked_mul(Self::LEN).ok_or(PlatformError)?;
            let rec = buf.get_mut(..len).ok_or(PlatformError)?;
            flash.read(self.sector_base(sector)?.checked_add(off).ok_or(PlatformError)?, rec)?;
            if rec.iter().any(|&b| b != 0xFF) {
                end = off.checked_add(Self::LEN).ok_or(PlatformError)?;
            }
        }
        Ok(end)
    }

    /// Latest `(seq, payload)`, if any record was ever written.
    #[must_use]
    pub const fn latest(&self) -> Option<&(u32, [u8; N])> {
        self.latest.as_ref()
    }

    /// Durably append `payload` with sequence number `latest + 1` (or 1 for an empty log).
    /// Returns the new sequence number only after the record has been read back intact.
    ///
    /// # Errors
    /// Flash failure, verification failure, or sequence exhaustion. After an error the log
    /// must be re-mounted before further use.
    pub fn append<F: Flash>(&mut self, flash: &mut F, payload: &[u8; N]) -> Result<u32, PlatformError> {
        let seq = match self.latest {
            Some((s, _)) => s.checked_add(1).ok_or(PlatformError)?,
            None => 1,
        };
        let mut sector = self.active;
        let mut next = self.next;
        let room = SECTOR_SIZE.saturating_sub(next);
        if room < Self::LEN || self.latest.is_none() && next > 0 {
            // Switch to the other sector; it never holds the latest value.
            sector = if self.latest.is_none() { self.active } else { 1u32.saturating_sub(self.active) };
            flash.erase(self.sector_base(sector)?)?;
            next = 0;
        }
        let rec = Self::encode(seq, payload)?;
        let len = usize::try_from(Self::LEN).map_err(|_| PlatformError)?;
        let rec = rec.get(..len).ok_or(PlatformError)?;
        let addr = self.sector_base(sector)?.checked_add(next).ok_or(PlatformError)?;
        flash.write(addr, rec)?;
        let mut check = [0u8; 76];
        let check = check.get_mut(..len).ok_or(PlatformError)?;
        flash.read(addr, check)?;
        if check != rec {
            return Err(PlatformError);
        }
        self.active = sector;
        self.next = next.checked_add(Self::LEN).ok_or(PlatformError)?;
        self.latest = Some((seq, *payload));
        Ok(seq)
    }
}

/// In-memory NOR flash with power-cut injection, for tests and fuzzing.
/// Test scaffolding: exempt from the no-panic lints that bind shipped code.
#[cfg(any(test, feature = "mock"))]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing, clippy::cast_possible_truncation)]
pub mod mock {
    use super::{Flash, SECTOR_SIZE};
    use crate::platform::PlatformError;

    /// Two-sector-per-log RAM flash. `cut_after` (if set) is the number of byte-program or
    /// sector-erase steps after which "power fails": the step is applied partially and
    /// every later operation fails.
    #[derive(Clone, Debug)]
    pub struct MockFlash {
        /// Flash contents.
        pub mem: [u8; 4 * SECTOR_SIZE as usize],
        /// Remaining steps before the simulated power cut.
        pub cut_after: Option<u32>,
        /// Whether power has failed.
        pub dead: bool,
        /// Number of completed sector erases.
        pub erases: u32,
    }

    impl Default for MockFlash {
        fn default() -> Self {
            Self { mem: [0xFF; 4 * SECTOR_SIZE as usize], cut_after: None, dead: false, erases: 0 }
        }
    }

    impl MockFlash {
        fn tick(&mut self) -> bool {
            if self.dead {
                return false;
            }
            match &mut self.cut_after {
                Some(0) => {
                    self.dead = true;
                    false
                }
                Some(n) => {
                    *n -= 1;
                    true
                }
                None => true,
            }
        }

        /// Restore power (the contents stay as the cut left them).
        pub fn power_on(&mut self) {
            self.dead = false;
            self.cut_after = None;
        }
    }

    impl Flash for MockFlash {
        fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), PlatformError> {
            if self.dead {
                return Err(PlatformError);
            }
            let o = offset as usize;
            buf.copy_from_slice(self.mem.get(o..o + buf.len()).ok_or(PlatformError)?);
            Ok(())
        }

        fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), PlatformError> {
            for (i, &b) in data.iter().enumerate() {
                if !self.tick() {
                    return Err(PlatformError);
                }
                let cell = self.mem.get_mut(offset as usize + i).ok_or(PlatformError)?;
                *cell &= b; // NOR: programming only clears bits
            }
            Ok(())
        }

        fn erase(&mut self, offset: u32) -> Result<(), PlatformError> {
            let o = offset as usize;
            let sector = self.mem.get_mut(o..o + SECTOR_SIZE as usize).ok_or(PlatformError)?;
            if self.dead {
                return Err(PlatformError);
            }
            match self.cut_after {
                Some(0) => {
                    // Power fails mid-erase: half the sector is erased.
                    sector[..SECTOR_SIZE as usize / 2].fill(0xFF);
                    self.dead = true;
                    Err(PlatformError)
                }
                _ => {
                    sector.fill(0xFF);
                    self.erases += 1;
                    let _ = self.tick();
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockFlash;
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_then_append_and_remount() {
        let mut f = MockFlash::default();
        let mut log = RecordLog::<4>::mount(&mut f, 0).unwrap();
        assert!(log.latest().is_none());
        for i in 1..=500u32 {
            assert_eq!(log.append(&mut f, &i.to_le_bytes()).unwrap(), i);
        }
        let log = RecordLog::<4>::mount(&mut f, 0).unwrap();
        assert_eq!(log.latest().map(|l| l.0), Some(500));
        assert_eq!(log.latest().map(|l| l.1), Some(500u32.to_le_bytes()));
    }

    /// Pins the on-flash format and the sector-switch schedule.
    #[test]
    fn layout_and_erase_schedule() {
        let mut f = MockFlash::default();
        let mut log = RecordLog::<4>::mount(&mut f, 0).unwrap();
        for i in 1..=256u32 {
            log.append(&mut f, &(i * 3).to_le_bytes()).unwrap();
        }
        // 256 records of 16 bytes fill sector 0 exactly, with no erase needed.
        assert_eq!(f.erases, 0);
        let rec1 = &f.mem[0..16];
        assert_eq!(&rec1[..4], b"JKR1");
        assert_eq!(&rec1[4..8], &1u32.to_le_bytes());
        assert_eq!(&rec1[8..12], &3u32.to_le_bytes());
        assert_eq!(&rec1[12..16], &crc32(&rec1[..12]).to_le_bytes());
        assert_eq!(&f.mem[16..20], b"JKR1");
        assert_eq!(&f.mem[20..24], &2u32.to_le_bytes());
        // Record 257 goes to the start of sector 1 after one erase.
        log.append(&mut f, &[9; 4]).unwrap();
        assert_eq!(f.erases, 1);
        let s1 = SECTOR_SIZE as usize;
        assert_eq!(&f.mem[s1..s1 + 4], b"JKR1");
        assert_eq!(&f.mem[s1 + 4..s1 + 8], &257u32.to_le_bytes());
        assert_eq!(&f.mem[s1 + 16..s1 + 20], &[0xFF; 4]);
        // Fill sector 1; record 513 erases and reuses sector 0.
        for _ in 258..=513u32 {
            log.append(&mut f, &[7; 4]).unwrap();
        }
        assert_eq!(f.erases, 2);
        assert_eq!(&f.mem[4..8], &513u32.to_le_bytes());
        assert_eq!(&f.mem[16..20], &[0xFF; 4]);
        assert_eq!(RecordLog::<4>::mount(&mut f, 0).unwrap().latest().map(|l| l.0), Some(513));
    }

    #[test]
    fn corrupted_latest_record_falls_back_to_previous() {
        let mut f = MockFlash::default();
        let mut log = RecordLog::<4>::mount(&mut f, 0).unwrap();
        log.append(&mut f, &[1; 4]).unwrap();
        log.append(&mut f, &[2; 4]).unwrap();
        f.mem[16 + 9] ^= 0x01; // payload of record 2: CRC no longer matches
        assert_eq!(RecordLog::<4>::mount(&mut f, 0).unwrap().latest(), Some(&(1, [1; 4])));
        f.mem[16 + 9] ^= 0x01;
        f.mem[16] = b'X'; // magic broken, CRC recomputed over the broken magic
        let crc = crc32(&f.mem[16..28]).to_le_bytes();
        f.mem[28..32].copy_from_slice(&crc);
        assert_eq!(RecordLog::<4>::mount(&mut f, 0).unwrap().latest(), Some(&(1, [1; 4])));
    }

    #[test]
    fn garbage_in_an_empty_log_is_erased_first() {
        let mut f = MockFlash::default();
        f.mem[..8].copy_from_slice(b"JKR1\x05\x00\x00\x00"); // torn first record
        let mut log = RecordLog::<4>::mount(&mut f, 0).unwrap();
        assert!(log.latest().is_none());
        assert_eq!(log.append(&mut f, &[4; 4]).unwrap(), 1);
        assert_eq!(f.erases, 1);
        assert_eq!(&f.mem[4..8], &1u32.to_le_bytes(), "record written at the start of the erased sector");
        assert_eq!(&f.mem[16..20], &[0xFF; 4]);
    }

    #[test]
    fn two_logs_in_one_flash_are_independent() {
        let mut f = MockFlash::default();
        let mut a = RecordLog::<4>::mount(&mut f, 0).unwrap();
        let mut b = RecordLog::<32>::mount(&mut f, 2 * SECTOR_SIZE).unwrap();
        a.append(&mut f, &[1; 4]).unwrap();
        b.append(&mut f, &[2; 32]).unwrap();
        a.append(&mut f, &[3; 4]).unwrap();
        let a = RecordLog::<4>::mount(&mut f, 0).unwrap();
        let b = RecordLog::<32>::mount(&mut f, 2 * SECTOR_SIZE).unwrap();
        assert_eq!(a.latest(), Some(&(2, [3; 4])));
        assert_eq!(b.latest(), Some(&(1, [2; 32])));
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 300, ..ProptestConfig::default() })]

        /// Invariant 2 under power loss: across any number of power cuts at any point,
        /// every sequence number that `append` confirmed is strictly greater than all
        /// confirmed before it, and a remount never goes below the last confirmed value.
        #[test]
        fn monotonic_across_power_cuts(cuts in proptest::collection::vec(0u32..2000, 1..12)) {
            let mut f = MockFlash::default();
            let mut last_confirmed = 0u32;
            for cut in cuts {
                f.power_on();
                let mut log = RecordLog::<4>::mount(&mut f, 0).unwrap();
                let recovered = log.latest().map_or(0, |l| l.0);
                prop_assert!(recovered >= last_confirmed, "remount lost a confirmed value");
                f.cut_after = Some(cut);
                while let Ok(seq) = log.append(&mut f, &[0xAB; 4]) {
                    prop_assert!(seq > last_confirmed);
                    last_confirmed = seq;
                }
            }
            f.power_on();
            let log = RecordLog::<4>::mount(&mut f, 0).unwrap();
            prop_assert!(log.latest().map_or(0, |l| l.0) >= last_confirmed);
        }
    }
}
