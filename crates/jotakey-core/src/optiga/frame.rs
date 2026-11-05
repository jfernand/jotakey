// (c) Javier Fernandez @ JotaSoft 2026
//! Data link frames (IFX I2C protocol §3): `FCTR ‖ LEN ‖ packet ‖ FCS`.
//!
//! ```text
//! FCTR   1 byte   bit 7 FTYPE (0 data, 1 control), bits 6:5 SEQCTR (00 ACK, 01 NAK,
//!                 10 resync), bit 4 RFU (0), bits 3:2 FRNR (data frame number),
//!                 bits 1:0 ACKNR (frame acknowledged)
//! LEN    2 bytes  packet length, big-endian
//! packet LEN bytes (none in a control frame)
//! FCS    2 bytes  CRC-16 (`crc`) over FCTR ‖ LEN ‖ packet
//! ```
//!
//! The FCS goes **high byte first**. The protocol specification says "low byte ‖ high byte",
//! but Infineon's host library, which is what runs against real chips, writes and checks
//! `crc >> 8` first; this code follows the library.
//!
//! [`decode`] is total: any byte string gives a [`Frame`] or [`OptigaError::Malformed`].

use super::OptigaError;
use super::crc::crc16;

/// The frame size requested in `DATA_REG_LEN` (Infineon's default for the Trust M).
pub const FRAME_SIZE: usize = 277;
/// `FCTR ‖ LEN`.
pub const HEADER_LEN: usize = 3;
/// Header plus FCS: a frame's bytes beyond its packet.
pub const OVERHEAD: usize = 5;
/// The longest packet in a frame of [`FRAME_SIZE`] bytes (`MAX_PACKET_SIZE`).
pub const MAX_PACKET: usize = FRAME_SIZE - OVERHEAD;
/// Frame numbers count modulo 4.
pub const FRAME_NUMBER_MASK: u8 = 0b11;

const FTYPE_CONTROL: u8 = 0x80;
const SEQCTR_MASK: u8 = 0x60;
const SEQCTR_ACK: u8 = 0x00;
const SEQCTR_NAK: u8 = 0x20;
const SEQCTR_RESYNC: u8 = 0x40;
const RFU_BIT: u8 = 0x10;
const FRNR_SHIFT: u8 = 2;

/// The resync control frame's FCTR ("reset frame counters", §8.2.1).
pub const FCTR_RESYNC: u8 = 0xC0;

/// Acknowledge or not-acknowledge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ack {
    /// The frame numbered `ack_number` arrived intact.
    Ack,
    /// The frame numbered `ack_number` is missing or damaged: send it again.
    Nak,
}

/// A decoded frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A numbered data frame, with an acknowledgement piggy-backed.
    Data {
        /// This frame's number (0–3).
        number: u8,
        /// The number of the frame acknowledged (0–3).
        ack_number: u8,
        /// ACK or NAK for `ack_number`.
        ack: Ack,
        /// The packet (at least one byte: the PCTR).
        packet: &'a [u8],
    },
    /// An acknowledgement on its own.
    Control {
        /// The number of the frame acknowledged (0–3).
        ack_number: u8,
        /// ACK or NAK for `ack_number`.
        ack: Ack,
    },
    /// Reset both frame counters.
    Resync,
}

fn seqctr(ack: Ack) -> u8 {
    match ack {
        Ack::Ack => SEQCTR_ACK,
        Ack::Nak => SEQCTR_NAK,
    }
}

/// Put LEN and FCS around the FCTR already in `out[0]` and the `len` packet bytes after it;
/// return the frame length.
fn seal(out: &mut [u8], len: usize) -> Result<usize, OptigaError> {
    let len16 = u16::try_from(len).map_err(|_| OptigaError::Length)?;
    out.get_mut(1..HEADER_LEN).ok_or(OptigaError::Length)?.copy_from_slice(&len16.to_be_bytes());
    let body = len.checked_add(HEADER_LEN).ok_or(OptigaError::Length)?;
    let total = body.checked_add(2).ok_or(OptigaError::Length)?;
    let crc = crc16(out.get(..body).ok_or(OptigaError::Length)?);
    out.get_mut(body..total).ok_or(OptigaError::Length)?.copy_from_slice(&crc.to_be_bytes());
    Ok(total)
}

/// Encode a data frame carrying `packet` into `out`; return its length.
///
/// # Errors
/// [`OptigaError::Length`] if `packet` is empty, longer than [`MAX_PACKET`], or `out` is too
/// short.
pub fn encode_data(number: u8, ack_number: u8, packet: &[u8], out: &mut [u8]) -> Result<usize, OptigaError> {
    if packet.is_empty() || packet.len() > MAX_PACKET {
        return Err(OptigaError::Length);
    }
    let end = packet.len().checked_add(HEADER_LEN).ok_or(OptigaError::Length)?;
    out.get_mut(HEADER_LEN..end).ok_or(OptigaError::Length)?.copy_from_slice(packet);
    *out.first_mut().ok_or(OptigaError::Length)? =
        seqctr(Ack::Ack) | ((number & FRAME_NUMBER_MASK) << FRNR_SHIFT) | (ack_number & FRAME_NUMBER_MASK);
    seal(out, packet.len())
}

/// Encode a control frame acknowledging (or not) frame `ack_number`.
#[must_use]
pub fn encode_control(ack_number: u8, ack: Ack) -> [u8; OVERHEAD] {
    let mut out = [FTYPE_CONTROL | seqctr(ack) | (ack_number & FRAME_NUMBER_MASK), 0, 0, 0, 0];
    let crc = crc16(&[out[0], 0, 0]).to_be_bytes();
    out[3] = crc[0];
    out[4] = crc[1];
    out
}

/// Encode the resync control frame.
#[must_use]
pub fn encode_resync() -> [u8; OVERHEAD] {
    let crc = crc16(&[FCTR_RESYNC, 0, 0]).to_be_bytes();
    [FCTR_RESYNC, 0, 0, crc[0], crc[1]]
}

/// Decode one frame. Total: every input gives `Ok` or `Err`.
///
/// # Errors
/// [`OptigaError::Malformed`] for a wrong length, checksum, reserved bit or SEQCTR value, a
/// control frame with a frame number or a packet, or an empty data frame.
pub fn decode(bytes: &[u8]) -> Result<Frame<'_>, OptigaError> {
    let n = bytes.len();
    if !(OVERHEAD..=FRAME_SIZE).contains(&n) {
        return Err(OptigaError::Malformed);
    }
    let body = n.checked_sub(2).ok_or(OptigaError::Malformed)?;
    let (head, fcs) = bytes.split_at_checked(body).ok_or(OptigaError::Malformed)?;
    let fcs: [u8; 2] = fcs.try_into().map_err(|_| OptigaError::Malformed)?;
    if crc16(head) != u16::from_be_bytes(fcs) {
        return Err(OptigaError::Malformed);
    }
    let &[fctr, len_hi, len_lo] = head.get(..HEADER_LEN).ok_or(OptigaError::Malformed)? else {
        return Err(OptigaError::Malformed);
    };
    let packet = head.get(HEADER_LEN..).ok_or(OptigaError::Malformed)?;
    if usize::from(u16::from_be_bytes([len_hi, len_lo])) != packet.len() || fctr & RFU_BIT != 0 {
        return Err(OptigaError::Malformed);
    }
    let number = (fctr >> FRNR_SHIFT) & FRAME_NUMBER_MASK;
    let ack_number = fctr & FRAME_NUMBER_MASK;
    let ack = match fctr & SEQCTR_MASK {
        SEQCTR_ACK => Ack::Ack,
        SEQCTR_NAK => Ack::Nak,
        SEQCTR_RESYNC if fctr == FCTR_RESYNC && packet.is_empty() => return Ok(Frame::Resync),
        _ => return Err(OptigaError::Malformed),
    };
    if fctr & FTYPE_CONTROL != 0 {
        if number != 0 || !packet.is_empty() {
            return Err(OptigaError::Malformed);
        }
        Ok(Frame::Control { ack_number, ack })
    } else if packet.is_empty() {
        Err(OptigaError::Malformed)
    } else {
        Ok(Frame::Data { number, ack_number, ack, packet })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn control_frames_match_the_encoding_table() {
        // §8.2.1: 0x80–0x83 ACK, 0xA0–0xA3 NAK, 0xC0 resync.
        assert_eq!(encode_control(2, Ack::Ack)[0], 0x82);
        assert_eq!(encode_control(3, Ack::Nak)[0], 0xA3);
        assert_eq!(encode_resync()[0], 0xC0);
        assert_eq!(decode(&encode_control(1, Ack::Ack)), Ok(Frame::Control { ack_number: 1, ack: Ack::Ack }));
        assert_eq!(decode(&encode_control(0, Ack::Nak)), Ok(Frame::Control { ack_number: 0, ack: Ack::Nak }));
        assert_eq!(decode(&encode_resync()), Ok(Frame::Resync));
    }

    #[test]
    fn data_frame_layout() {
        let mut out = [0u8; FRAME_SIZE];
        let n = encode_data(1, 3, &[0x00, 0xF0, 0x00], &mut out).unwrap();
        assert_eq!(n, 8);
        // FCTR: data frame 1, ACK for frame 3 = 0x07 (§8.2.1); LEN 3, big-endian.
        assert_eq!(&out[..6], &[0x07, 0x00, 0x03, 0x00, 0xF0, 0x00]);
        // FCS high byte first, as Infineon's host library sends it.
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), crc16(&out[..6]));
        assert_eq!(
            decode(&out[..n]),
            Ok(Frame::Data { number: 1, ack_number: 3, ack: Ack::Ack, packet: &[0x00, 0xF0, 0x00] })
        );
    }

    #[test]
    fn encoding_limits() {
        let mut out = [0u8; FRAME_SIZE];
        assert_eq!(encode_data(0, 0, &[], &mut out), Err(OptigaError::Length));
        assert_eq!(encode_data(0, 0, &[0; MAX_PACKET + 1], &mut out), Err(OptigaError::Length));
        assert_eq!(encode_data(0, 0, &[0; MAX_PACKET], &mut out), Ok(FRAME_SIZE));
        assert_eq!(encode_data(0, 0, &[0; 4], &mut out[..8]), Err(OptigaError::Length));
        assert_eq!(encode_data(0, 0, &[0; 4], &mut out[..9]), Ok(9));
    }

    #[test]
    fn malformed_frames_are_refused() {
        let good = encode_control(0, Ack::Ack);
        let mut bad = good;
        bad[4] ^= 1;
        assert_eq!(decode(&bad), Err(OptigaError::Malformed), "checksum");
        assert_eq!(decode(&good[..4]), Err(OptigaError::Malformed), "too short");
        assert_eq!(decode(&[0u8; FRAME_SIZE + 1]), Err(OptigaError::Malformed), "too long");
        let reseal = |fctr: u8, packet: &[u8]| {
            let mut v = std::vec![fctr];
            v.extend_from_slice(&u16::try_from(packet.len()).unwrap().to_be_bytes());
            v.extend_from_slice(packet);
            let crc = crc16(&v).to_be_bytes();
            v.extend_from_slice(&crc);
            v
        };
        assert_eq!(decode(&reseal(0x90, &[])), Err(OptigaError::Malformed), "RFU bit");
        assert_eq!(decode(&reseal(0xE0, &[])), Err(OptigaError::Malformed), "SEQCTR 11");
        assert_eq!(decode(&reseal(0x60, &[1])), Err(OptigaError::Malformed), "SEQCTR 11, data");
        assert_eq!(decode(&reseal(0x40, &[1])), Err(OptigaError::Malformed), "resync in a data frame");
        assert_eq!(decode(&reseal(0xC1, &[])), Err(OptigaError::Malformed), "resync with an ACKNR");
        assert_eq!(decode(&reseal(0xC0, &[1])), Err(OptigaError::Malformed), "resync with a packet");
        assert_eq!(decode(&reseal(0x84, &[])), Err(OptigaError::Malformed), "control frame number");
        assert_eq!(decode(&reseal(0x80, &[1])), Err(OptigaError::Malformed), "control frame packet");
        assert_eq!(decode(&reseal(0x00, &[])), Err(OptigaError::Malformed), "empty data frame");
        assert!(decode(&reseal(0x2D, &[9])).is_ok(), "data frame 3 NAK for 1");
        // LEN disagreeing with the bytes present.
        let mut v = reseal(0x00, &[1, 2]);
        v[2] = 3;
        let body = v.len() - 2;
        let crc = crc16(&v[..body]).to_be_bytes();
        v[body..].copy_from_slice(&crc);
        assert_eq!(decode(&v), Err(OptigaError::Malformed), "LEN");
    }

    proptest! {
        #[test]
        fn decode_is_total(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = decode(&bytes);
        }

        #[test]
        fn data_frames_round_trip(
            number in 0u8..4,
            ack_number in 0u8..4,
            packet in proptest::collection::vec(any::<u8>(), 1..=MAX_PACKET),
        ) {
            let mut out = [0u8; FRAME_SIZE];
            let n = encode_data(number, ack_number, &packet, &mut out).unwrap();
            prop_assert_eq!(
                decode(&out[..n]),
                Ok(Frame::Data { number, ack_number, ack: Ack::Ack, packet: &packet })
            );
        }

        #[test]
        fn a_flipped_bit_is_detected(packet in proptest::collection::vec(any::<u8>(), 1..64), bit in 0usize..512) {
            let mut out = [0u8; FRAME_SIZE];
            let n = encode_data(0, 0, &packet, &mut out).unwrap();
            let bit = bit % (n * 8);
            out[bit / 8] ^= 1 << (bit % 8);
            // A single flipped bit is always caught (CRC-16 detects all odd-weight errors).
            prop_assert!(decode(&out[..n]).is_err());
        }
    }
}
