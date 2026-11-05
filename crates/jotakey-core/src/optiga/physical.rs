// (c) Javier Fernandez @ JotaSoft 2026
//! The physical layer (IFX I2C protocol §2): registers under the one I2C address.
//!
//! A register write is one transaction `reg ‖ data`. A register read writes `reg`, then reads
//! in a second transaction. The OPTIGA does not acknowledge its address while it is busy
//! ("late acknowledge", §2): every transaction is retried on [`BusError::Nack`], at most
//! [`NACK_RETRIES`] times [`NACK_INTERVAL_US`] apart, as Infineon's host library does. After
//! each read the master waits [`GUARD_TIME_US`] before the next write (`GUARD_TIME`, §8.3).

use super::frame::FRAME_SIZE;
use super::{BusError, I2c, OptigaError};

/// The data register: frames are written to and read from it.
pub const REG_DATA: u8 = 0x80;
/// The data register's length (2 bytes, big-endian).
pub const REG_DATA_REG_LEN: u8 = 0x81;
/// The state register (4 bytes): busy and response-ready flags, and the length of the frame
/// waiting to be read.
pub const REG_I2C_STATE: u8 = 0x82;

/// Retries of a NACKed transaction (`PL_POLLING_MAX_CNT` in the host library).
pub const NACK_RETRIES: u32 = 200;
/// Wait between them (`PL_POLLING_INVERVAL_US`).
pub const NACK_INTERVAL_US: u32 = 1000;
/// Minimum time from the end of a read to the next write (`GUARD_TIME` default, §8.3).
pub const GUARD_TIME_US: u32 = 500;

const STATE_RESP_RDY: u8 = 0x40;
const STATE_BUSY: u8 = 0x80;

/// The decoded `I2C_STATE` register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    /// The OPTIGA is executing a command.
    pub busy: bool,
    /// A frame is waiting to be read.
    pub response_ready: bool,
    /// Its length in bytes.
    pub length: u16,
}

impl State {
    /// Decode the register's four bytes.
    #[must_use]
    pub fn from_bytes(b: [u8; 4]) -> Self {
        Self {
            busy: b[0] & STATE_BUSY != 0,
            response_ready: b[0] & STATE_RESP_RDY != 0,
            length: u16::from_be_bytes([b[2], b[3]]),
        }
    }
}

/// Run one transaction, retrying while the address is not acknowledged.
fn retry_write<B: I2c>(bus: &mut B, bytes: &[u8]) -> Result<(), OptigaError> {
    for _ in 0..NACK_RETRIES {
        match bus.write(bytes) {
            Ok(()) => return Ok(()),
            Err(BusError::Nack) => bus.delay_us(NACK_INTERVAL_US),
            Err(BusError::Other) => return Err(OptigaError::Bus),
        }
    }
    Err(OptigaError::Bus)
}

fn retry_read<B: I2c>(bus: &mut B, buf: &mut [u8]) -> Result<(), OptigaError> {
    for _ in 0..NACK_RETRIES {
        match bus.read(buf) {
            Ok(()) => {
                bus.delay_us(GUARD_TIME_US);
                return Ok(());
            }
            Err(BusError::Nack) => bus.delay_us(NACK_INTERVAL_US),
            Err(BusError::Other) => return Err(OptigaError::Bus),
        }
    }
    Err(OptigaError::Bus)
}

/// Write `data` to register `reg`.
///
/// # Errors
/// [`OptigaError::Length`] if `data` exceeds a frame; [`OptigaError::Bus`] on a bus failure
/// or if the OPTIGA stays busy.
pub fn write_register<B: I2c>(bus: &mut B, reg: u8, data: &[u8]) -> Result<(), OptigaError> {
    let mut buf = [0u8; FRAME_SIZE + 1];
    let end = data.len().checked_add(1).ok_or(OptigaError::Length)?;
    buf.get_mut(1..end).ok_or(OptigaError::Length)?.copy_from_slice(data);
    buf[0] = reg;
    retry_write(bus, buf.get(..end).ok_or(OptigaError::Length)?)
}

/// Read `out.len()` bytes from register `reg`.
///
/// # Errors
/// [`OptigaError::Bus`] on a bus failure or if the OPTIGA stays busy.
pub fn read_register<B: I2c>(bus: &mut B, reg: u8, out: &mut [u8]) -> Result<(), OptigaError> {
    retry_write(bus, &[reg])?;
    retry_read(bus, out)
}

/// Read `I2C_STATE`.
///
/// # Errors
/// As [`read_register`].
pub fn state<B: I2c>(bus: &mut B) -> Result<State, OptigaError> {
    let mut b = [0u8; 4];
    read_register(bus, REG_I2C_STATE, &mut b)?;
    Ok(State::from_bytes(b))
}

/// Ask for [`FRAME_SIZE`]-byte frames and check what the OPTIGA accepted (it answers with
/// its maximum if it cannot take the value, §2.1). Returns the frame size to use.
///
/// # Errors
/// [`OptigaError::Bus`] on a bus failure; [`OptigaError::Malformed`] if the OPTIGA's frame
/// size is too small for the APDUs this driver sends (under [`MIN_FRAME_SIZE`]).
pub fn negotiate_frame_size<B: I2c>(bus: &mut B) -> Result<usize, OptigaError> {
    let wanted = u16::try_from(FRAME_SIZE).map_err(|_| OptigaError::Length)?;
    write_register(bus, REG_DATA_REG_LEN, &wanted.to_be_bytes())?;
    let mut b = [0u8; 2];
    read_register(bus, REG_DATA_REG_LEN, &mut b)?;
    let got = usize::from(u16::from_be_bytes(b));
    if got < MIN_FRAME_SIZE {
        return Err(OptigaError::Malformed);
    }
    Ok(got.min(FRAME_SIZE))
}

/// The smallest frame that carries this driver's longest protected APDU (a `DeriveKey` with
/// [`super::apdu::MAX_DERIVATION_DATA`] bytes of derivation data) without chaining.
pub const MIN_FRAME_SIZE: usize = super::apdu::MAX_COMMAND
    + super::shielded::RECORD_OVERHEAD
    + 1 // PCTR
    + super::frame::OVERHEAD;

// The frame this driver asks for carries its longest command.
const _: () = assert!(MIN_FRAME_SIZE <= FRAME_SIZE);

#[cfg(test)]
mod tests {
    use super::*;

    /// A bus that NACKs a number of times, then records.
    struct Flaky {
        nacks: u32,
        other: bool,
        writes: std::vec::Vec<std::vec::Vec<u8>>,
        delays: u64,
        reply: std::vec::Vec<u8>,
    }

    impl I2c for Flaky {
        fn write(&mut self, bytes: &[u8]) -> Result<(), BusError> {
            if self.other {
                return Err(BusError::Other);
            }
            if self.nacks > 0 {
                self.nacks -= 1;
                return Err(BusError::Nack);
            }
            self.writes.push(bytes.to_vec());
            Ok(())
        }
        fn read(&mut self, buf: &mut [u8]) -> Result<(), BusError> {
            if self.nacks > 0 {
                self.nacks -= 1;
                return Err(BusError::Nack);
            }
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.reply.get(i).copied().unwrap_or(0xFF);
            }
            Ok(())
        }
        fn delay_us(&mut self, us: u32) {
            self.delays += u64::from(us);
        }
    }

    fn flaky(nacks: u32) -> Flaky {
        Flaky { nacks, other: false, writes: std::vec![], delays: 0, reply: std::vec![] }
    }

    #[test]
    fn late_acknowledge_is_retried_for_a_bounded_time() {
        let mut bus = flaky(NACK_RETRIES - 1);
        write_register(&mut bus, REG_DATA, &[1, 2, 3]).unwrap();
        assert_eq!(bus.writes, [std::vec![REG_DATA, 1, 2, 3]]);
        assert_eq!(bus.delays, u64::from(NACK_RETRIES - 1) * u64::from(NACK_INTERVAL_US));

        let mut bus = flaky(NACK_RETRIES);
        assert_eq!(write_register(&mut bus, REG_DATA, &[1]), Err(OptigaError::Bus));
        assert!(bus.writes.is_empty());

        let mut bus = flaky(0);
        bus.other = true;
        assert_eq!(write_register(&mut bus, REG_DATA, &[1]), Err(OptigaError::Bus));
        assert_eq!(bus.delays, 0, "other errors are not retried");
    }

    #[test]
    fn reads_wait_the_guard_time() {
        let mut bus = flaky(0);
        bus.reply = std::vec![0xC0, 0x00, 0x01, 0x15];
        let s = state(&mut bus).unwrap();
        assert_eq!(s, State { busy: true, response_ready: true, length: 0x0115 });
        assert_eq!(State::from_bytes([0x80, 0xFF, 0, 1]), State { busy: true, response_ready: false, length: 1 });
        assert_eq!(State::from_bytes([0x40, 0, 2, 0]), State { busy: false, response_ready: true, length: 0x200 });
        assert_eq!(State::from_bytes([0x3F, 0, 0, 0]), State { busy: false, response_ready: false, length: 0 });
        assert_eq!(bus.writes, [std::vec![REG_I2C_STATE]]);
        assert_eq!(bus.delays, u64::from(GUARD_TIME_US));
        // A read that is NACKed until the budget runs out fails.
        let mut bus = flaky(NACK_RETRIES + 1);
        assert_eq!(read_register(&mut bus, REG_I2C_STATE, &mut [0; 4]), Err(OptigaError::Bus));
    }

    #[test]
    fn frame_size_negotiation() {
        let mut bus = flaky(0);
        bus.reply = std::vec![0x01, 0x15];
        assert_eq!(negotiate_frame_size(&mut bus), Ok(FRAME_SIZE));
        assert_eq!(bus.writes[0], std::vec![REG_DATA_REG_LEN, 0x01, 0x15]);
        // A device that accepts more is held to what was asked for.
        bus.reply = std::vec![0x06, 0x15];
        assert_eq!(negotiate_frame_size(&mut bus), Ok(FRAME_SIZE));
        let ok = u16::try_from(MIN_FRAME_SIZE).unwrap();
        bus.reply = ok.to_be_bytes().to_vec();
        assert_eq!(negotiate_frame_size(&mut bus), Ok(MIN_FRAME_SIZE));
        bus.reply = (ok - 1).to_be_bytes().to_vec();
        assert_eq!(negotiate_frame_size(&mut bus), Err(OptigaError::Malformed));
    }

    #[test]
    fn the_minimum_frame_carries_the_longest_protected_command() {
        // DeriveKey with 128 bytes of derivation data (148) + SCTR, SEQ and tag (13) + PCTR
        // (1) + FCTR, LEN and FCS (5).
        assert_eq!(MIN_FRAME_SIZE, 167);
    }

    #[test]
    fn oversized_register_writes_are_refused() {
        let mut bus = flaky(0);
        assert_eq!(write_register(&mut bus, REG_DATA, &[0; FRAME_SIZE + 1]), Err(OptigaError::Length));
        assert!(write_register(&mut bus, REG_DATA, &[0; FRAME_SIZE]).is_ok());
    }
}
