// (c) Javier Fernandez @ JotaSoft 2026
//! The record-log region of the STM32L432's internal flash, through the core's [`Flash`]
//! trait.
//!
//! - The region is the top 32 KB of the 256 KB flash, from `0x0803_8000`; `memory.x` keeps
//!   it out of the image. A logical sector ([`SECTOR_SIZE`], 4 KB) is two 2 KB pages, erased
//!   together.
//! - The flash programs aligned 64-bit double-words, each once between erases, with ECC.
//!   [`Flash::program_unit`] is 8, so the record logs pad every record to whole double-words.
//! - A double-word whose programming was cut by a power loss can fail its ECC check. Reading
//!   it raises an NMI with `FLASH_ECCR.ECCD` set. As in ST's EEPROM emulation (AN4894),
//!   [`NonMaskableInt`] clears the flag and records the fault, and [`Region::read`] then
//!   hands back zeros, which fail the record's CRC: the record is torn, as the log expects.
//!   Any other NMI is a hardware fault and stops the key.
//! - Erasing stalls the CPU (one bank): a logical sector takes about 45 ms, inside the 100 ms
//!   keepalive budget.
//!
//! The ECC path is proved only on a board; it is on the list of on-device tests.

use core::sync::atomic::{AtomicBool, Ordering};

use cortex_m_rt::exception;
use embassy_stm32::flash::{Blocking, Flash as Driver};
use embassy_stm32::pac;
use jotakey_core::platform::PlatformError;
use jotakey_core::storage::{Flash, SECTOR_SIZE};

/// Offset of the region from the start of flash (`0x0800_0000`).
pub const REGION_OFFSET: u32 = 0x3_8000;
/// Logical sectors in the region (8 × 4 KB = 32 KB).
pub const REGION_SECTORS: u32 = 8;

/// Set by the NMI handler when a read hit an uncorrectable ECC error.
static ECC_FAULT: AtomicBool = AtomicBool::new(false);

/// The record-log region.
pub struct Region<'d> {
    flash: Driver<'d, Blocking>,
}

impl<'d> Region<'d> {
    /// Wrap the flash driver.
    pub fn new(flash: Driver<'d, Blocking>) -> Self {
        Self { flash }
    }

    /// Flash offset of `offset..offset + len` in the region, if it lies inside.
    fn abs(offset: u32, len: usize) -> Result<u32, PlatformError> {
        let len = u32::try_from(len).map_err(|_| PlatformError)?;
        let end = offset.checked_add(len).ok_or(PlatformError)?;
        if end > REGION_SECTORS.checked_mul(SECTOR_SIZE).ok_or(PlatformError)? {
            return Err(PlatformError);
        }
        REGION_OFFSET.checked_add(offset).ok_or(PlatformError)
    }
}

impl Flash for Region<'_> {
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), PlatformError> {
        let at = Self::abs(offset, buf.len())?;
        ECC_FAULT.store(false, Ordering::SeqCst);
        self.flash.blocking_read(at, buf).map_err(|_| PlatformError)?;
        if ECC_FAULT.swap(false, Ordering::SeqCst) {
            // A torn double-word: what was read is not data.
            buf.fill(0);
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), PlatformError> {
        let at = Self::abs(offset, data.len())?;
        self.flash.blocking_write(at, data).map_err(|_| PlatformError)
    }

    fn erase(&mut self, offset: u32) -> Result<(), PlatformError> {
        let from = Self::abs(offset, usize::try_from(SECTOR_SIZE).map_err(|_| PlatformError)?)?;
        let to = from.checked_add(SECTOR_SIZE).ok_or(PlatformError)?;
        self.flash.blocking_erase(from, to).map_err(|_| PlatformError)
    }

    fn program_unit(&self) -> u32 {
        8
    }
}

/// NMI: an uncorrectable flash ECC error during a read is recorded and cleared; anything
/// else halts the key (its LED stays as it was, and the host sees it stop answering).
#[exception]
unsafe fn NonMaskableInt() {
    let flash = pac::FLASH;
    if flash.eccr().read().eccd() {
        // ECCD is cleared by writing 1; the other bits keep their values.
        flash.eccr().modify(|w| w.set_eccd(true));
        ECC_FAULT.store(true, Ordering::SeqCst);
        return;
    }
    loop {
        cortex_m::asm::wfi();
    }
}
