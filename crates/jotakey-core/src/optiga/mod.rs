// (c) Javier Fernandez @ JotaSoft 2026
//! Driver for the Infineon OPTIGA Trust M V1, the jotakey key's secure element.
//!
//! The OPTIGA holds the root `K_root` and the signature counter (AGENTS.md §3). The MCU
//! reaches it over I2C through the *IFX I2C protocol*: a register interface ([`physical`]),
//! a framed, checksummed and acknowledged data link ([`frame`], [`link`]), a one-byte network
//! and transport header, the *shielded connection* that encrypts and authenticates every
//! command and response ([`shielded`]), and the command APDUs ([`apdu`]). [`device::Optiga`]
//! puts them together.
//!
//! The bus runs over exposed copper on the board, so every byte read from it is treated
//! like bytes from the host: parsers are total, every length is checked, and nothing read
//! from the OPTIGA is used before the shielded connection has authenticated it, *in a
//! session the MCU has checked is live* (the freshness check, [`device::Optiga::establish`]).
//! A bus attacker can make the key fail (it then refuses to sign), but cannot make it accept
//! a forged or replayed response.
//!
//! Everything here is `no_std`, allocation-free and sans-IO: the firmware supplies the bus
//! through the [`I2c`] trait, and the tests a software OPTIGA ([`sim`]).
//!
//! Sources: *IFX I2C Protocol Specification* v2.03 and the *OPTIGA Trust M Solution Reference
//! Manual* v3.60 (`hardware/datasheets/README.md`). Where the two disagree with Infineon's
//! host library (the frame checksum's byte order), the code follows the library, which is
//! what runs against real chips; each such place says so.

pub mod apdu;
pub mod crc;
pub mod device;
pub mod frame;
pub mod link;
pub mod physical;
pub mod provision;
pub mod shielded;
#[cfg(any(test, feature = "mock"))]
pub mod sim;

/// The OPTIGA Trust M's 7-bit I2C address.
pub const I2C_ADDRESS: u8 = 0x30;

/// Why a bus transaction failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusError {
    /// The OPTIGA did not acknowledge its address: it is busy (the protocol's "late
    /// acknowledge") or absent. The caller retries for a bounded time.
    Nack,
    /// Any other bus failure (arbitration lost, timeout, bus error).
    Other,
}

/// The I2C bus to the OPTIGA, one transaction at a time, always at [`I2C_ADDRESS`].
pub trait I2c {
    /// Write `bytes` in one transaction (start, address, bytes, stop).
    ///
    /// # Errors
    /// [`BusError::Nack`] if the address is not acknowledged; [`BusError::Other`] otherwise.
    fn write(&mut self, bytes: &[u8]) -> Result<(), BusError>;

    /// Read exactly `buf.len()` bytes in one transaction.
    ///
    /// # Errors
    /// As [`I2c::write`].
    fn read(&mut self, buf: &mut [u8]) -> Result<(), BusError>;

    /// Wait at least `us` microseconds.
    fn delay_us(&mut self, us: u32);
}

/// Why an OPTIGA operation failed. Carries no data read from the device and no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptigaError {
    /// The bus failed, or the OPTIGA stayed busy past the protocol's retry budget.
    Bus,
    /// No (valid) response within the timeout.
    Timeout,
    /// A frame, packet or message is malformed (length, checksum, header, chaining).
    Malformed,
    /// The data link was reset by the OPTIGA (resync frame): the session is gone.
    Resync,
    /// The shielded connection could not be set up, or a protected message failed to
    /// authenticate, came out of order, or was an alert. The session is dropped.
    Integrity,
    /// The live-session check after the handshake failed: possibly a replayed session.
    NotFresh,
    /// No shielded session is established (or it was dropped after an error).
    NoSession,
    /// The OPTIGA answered a command with an error status.
    Status,
    /// A sequence number or counter would wrap.
    Exhausted,
    /// The counter the OPTIGA reported did not exceed the last one released this boot.
    CounterNotIncreasing,
    /// A caller-side buffer or argument does not fit the protocol's limits.
    Length,
}
