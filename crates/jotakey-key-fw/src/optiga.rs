// (c) Javier Fernandez @ JotaSoft 2026
//! The OPTIGA Trust M on I2C1 (PA9 SCL, PA10 SDA; 4.7 kΩ pull-ups on the board) with its
//! active-low reset on PA5 (HARDWARE.md §3).
//!
//! This is the hardware half only: the bus behind the core's [`jotakey_core::optiga::I2c`]
//! trait and the reset line. Everything that interprets bytes from the OPTIGA is in
//! `jotakey_core::optiga` (sans-IO, tested against a simulated OPTIGA, fuzzed with an attacker
//! on the bus, and modelled in `formal/Jotakey/Shielded.lean`).
//!
//! The bus is blocking. A `DeriveKey` takes about 50 ms (more when the OPTIGA's security
//! monitor throttles), during which the authenticator task waits; USB runs on its own
//! interrupt-priority executor (`main.rs`) so enumeration and CTAPHID framing never stall.

use embassy_stm32::gpio::Output;
use embassy_stm32::i2c::{self, I2c, Master};
use embassy_stm32::mode::Blocking;
use embassy_time::{Duration, block_for};
use jotakey_core::optiga::device::{NONCE_LEN, Optiga};
use jotakey_core::optiga::provision::Pairing;
use jotakey_core::optiga::{BusError, I2C_ADDRESS, OptigaError};

/// I2C clock: Fast mode, the OPTIGA's default `SM & FM` mode (IFX I2C protocol Table 2-3).
pub const I2C_HZ: u32 = 400_000;
/// Reset pulse: at least 10 µs (datasheet Table 14, `t1`).
const RESET_LOW_US: u64 = 1000;
/// From reset release to the first transaction: at least 15 ms, 20 ms after an NVM write
/// (datasheet §5.1.4.2).
const STARTUP_MS: u64 = 25;

/// The I2C bus to the OPTIGA.
pub struct OptigaBus {
    i2c: I2c<'static, Blocking, Master>,
}

impl OptigaBus {
    /// Wrap the configured bus.
    pub fn new(i2c: I2c<'static, Blocking, Master>) -> Self {
        Self { i2c }
    }
}

fn bus_error(e: i2c::Error) -> BusError {
    match e {
        i2c::Error::Nack => BusError::Nack,
        _ => BusError::Other,
    }
}

impl jotakey_core::optiga::I2c for OptigaBus {
    fn write(&mut self, bytes: &[u8]) -> Result<(), BusError> {
        self.i2c.blocking_write(I2C_ADDRESS, bytes).map_err(bus_error)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(), BusError> {
        self.i2c.blocking_read(I2C_ADDRESS, buf).map_err(bus_error)
    }

    fn delay_us(&mut self, us: u32) {
        block_for(Duration::from_micros(u64::from(us)));
    }
}

/// The OPTIGA with its reset line and, once provisioned, the pairing secret.
pub struct SecureElement {
    optiga: Optiga<OptigaBus>,
    reset: Output<'static>,
    pairing: Option<Pairing>,
}

impl SecureElement {
    /// Take the bus and the reset line (driven low until [`SecureElement::hard_reset`]).
    pub fn new(bus: OptigaBus, reset: Output<'static>) -> Self {
        Self { optiga: Optiga::new(bus), reset, pairing: None }
    }

    /// Pulse the reset line and wait for the OPTIGA to start. Everything volatile in it (the
    /// session, the open application) is gone afterwards.
    pub fn hard_reset(&mut self) {
        self.reset.set_low();
        block_for(Duration::from_micros(RESET_LOW_US));
        self.reset.set_high();
        block_for(Duration::from_millis(STARTUP_MS));
    }

    /// Set the pairing secret read from flash (or just created by provisioning).
    pub fn set_pairing(&mut self, pairing: Pairing) {
        self.pairing = Some(pairing);
    }

    /// Whether a pairing secret is set.
    pub fn is_paired(&self) -> bool {
        self.pairing.is_some()
    }

    /// Reset the OPTIGA, open its application and establish a live shielded session.
    /// `nonce` must be fresh, health-tested RNG output.
    ///
    /// # Errors
    /// [`OptigaError::NoSession`] without a pairing secret; any error of the OPTIGA driver.
    pub fn connect(&mut self, nonce: &[u8; NONCE_LEN]) -> Result<(), OptigaError> {
        let pairing = self.pairing.as_ref().ok_or(OptigaError::NoSession)?;
        let binding = pairing.binding()?;
        let freshness = pairing.freshness()?;
        self.hard_reset();
        self.optiga.open()?;
        self.optiga.establish(&binding, &freshness, nonce)
    }

    /// The driver.
    pub fn optiga(&mut self) -> &mut Optiga<OptigaBus> {
        &mut self.optiga
    }
}
