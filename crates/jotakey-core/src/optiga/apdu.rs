// (c) Javier Fernandez @ JotaSoft 2026
//! OPTIGA command and response APDUs (Solution Reference Manual §4.4).
//!
//! A command is `Cmd ‖ Param ‖ InLen[2] ‖ InData`, a response `Sta ‖ UnDef ‖ OutLen[2] ‖
//! OutData` (lengths big-endian). Command codes are sent with bit 7 set, which also clears
//! the OPTIGA's "last error code", as Infineon's host library does. [`parse_response`] is
//! total. Commands may carry secrets (a secret being written, derivation input), so
//! [`Apdu`] is zeroized on drop.

use zeroize::Zeroize;

use super::OptigaError;

/// `GetDataObject`.
pub const CMD_GET_DATA_OBJECT: u8 = 0x81;
/// `SetDataObject`.
pub const CMD_SET_DATA_OBJECT: u8 = 0x82;
/// `GetRandom`.
pub const CMD_GET_RANDOM: u8 = 0x8C;
/// `DeriveKey`.
pub const CMD_DERIVE_KEY: u8 = 0xB4;
/// `OpenApplication`.
pub const CMD_OPEN_APPLICATION: u8 = 0xF0;

/// `GetDataObject` / `SetDataObject` Param: the data.
pub const PARAM_DATA: u8 = 0x00;
/// The metadata.
pub const PARAM_METADATA: u8 = 0x01;
/// `SetDataObject` Param: count (monotonic counters).
pub const PARAM_COUNT: u8 = 0x02;
/// `SetDataObject` Param: erase, then write.
pub const PARAM_ERASE_AND_WRITE: u8 = 0x40;
/// `DeriveKey` Param: TLS PRF SHA256.
pub const PARAM_TLS_PRF_SHA256: u8 = 0x01;
/// `GetRandom` Param: TRNG.
pub const PARAM_TRNG: u8 = 0x00;

/// The authentication application's identifier (`RID ‖ PIX`, Table 78).
pub const APPLICATION_ID: [u8; 16] =
    [0xD2, 0x76, 0x00, 0x00, 0x04, 0x47, 0x65, 0x6E, 0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6C];

/// Monotonic counter 1: the signature counter.
pub const OID_COUNTER: u16 = 0xE120;
/// The shared platform binding secret.
pub const OID_BINDING: u16 = 0xE140;
/// `K_root`.
pub const OID_ROOT: u16 = 0xF1D0;
/// The freshness secret (`device::Optiga::establish`).
pub const OID_FRESHNESS: u16 = 0xF1D1;

/// Longest derivation data (`label ‖ seed`) this driver sends: AGENTS.md §3's
/// `label ‖ epoch ‖ context` is at most 15 + 32 + 65 bytes.
pub const MAX_DERIVATION_DATA: usize = 128;
/// Longest command APDU: a `DeriveKey` with [`MAX_DERIVATION_DATA`].
pub const MAX_COMMAND: usize = 4 + 5 + 5 + 3 + MAX_DERIVATION_DATA + 3;
/// Shortest derivation data the OPTIGA accepts for the TLS PRF.
pub const MIN_DERIVATION_DATA: usize = 8;

/// A command APDU under construction. Zeroized on drop.
pub struct Apdu {
    buf: [u8; MAX_COMMAND],
    len: usize,
}

impl Drop for Apdu {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl Apdu {
    fn new(cmd: u8, param: u8) -> Self {
        let mut buf = [0u8; MAX_COMMAND];
        buf[0] = cmd;
        buf[1] = param;
        Self { buf, len: 4 }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), OptigaError> {
        let end = self.len.checked_add(bytes.len()).ok_or(OptigaError::Length)?;
        self.buf.get_mut(self.len..end).ok_or(OptigaError::Length)?.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn tlv(&mut self, tag: u8, value: &[&[u8]]) -> Result<(), OptigaError> {
        let mut n: usize = 0;
        for v in value {
            n = n.checked_add(v.len()).ok_or(OptigaError::Length)?;
        }
        let n = u16::try_from(n).map_err(|_| OptigaError::Length)?;
        self.push(&[tag])?;
        self.push(&n.to_be_bytes())?;
        for v in value {
            self.push(v)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Self, OptigaError> {
        let n = self.len.checked_sub(4).ok_or(OptigaError::Length)?;
        let n = u16::try_from(n).map_err(|_| OptigaError::Length)?.to_be_bytes();
        self.buf[2] = n[0];
        self.buf[3] = n[1];
        Ok(self)
    }

    /// The encoded command.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

/// `OpenApplication`: initialise a clean context of the authentication application.
///
/// # Errors
/// Never in practice.
pub fn open_application() -> Result<Apdu, OptigaError> {
    let mut a = Apdu::new(CMD_OPEN_APPLICATION, 0x00);
    a.push(&APPLICATION_ID)?;
    a.finish()
}

/// `GetDataObject`: all of object `oid`'s data, or its metadata.
///
/// # Errors
/// Never in practice.
pub fn get_data(oid: u16, metadata: bool) -> Result<Apdu, OptigaError> {
    let mut a = Apdu::new(CMD_GET_DATA_OBJECT, if metadata { PARAM_METADATA } else { PARAM_DATA });
    a.push(&oid.to_be_bytes())?;
    a.finish()
}

/// `SetDataObject`: erase object `oid`, then write `data` from offset 0.
///
/// # Errors
/// [`OptigaError::Length`] if `data` does not fit a command.
pub fn set_data(oid: u16, data: &[u8]) -> Result<Apdu, OptigaError> {
    let mut a = Apdu::new(CMD_SET_DATA_OBJECT, PARAM_ERASE_AND_WRITE);
    a.push(&oid.to_be_bytes())?;
    a.push(&[0, 0])?;
    a.push(data)?;
    a.finish()
}

/// `SetDataObject` (metadata): set the metadata tags in `tags` (simple TLVs, wrapped here in
/// the constructed `0x20` TLV). Only the tags given change.
///
/// # Errors
/// [`OptigaError::Length`] if `tags` is longer than 127 bytes.
pub fn set_metadata(oid: u16, tags: &[u8]) -> Result<Apdu, OptigaError> {
    let len = u8::try_from(tags.len()).ok().filter(|&l| l < 0x80).ok_or(OptigaError::Length)?;
    let mut a = Apdu::new(CMD_SET_DATA_OBJECT, PARAM_METADATA);
    a.push(&oid.to_be_bytes())?;
    a.push(&[0, 0, 0x20, len])?;
    a.push(tags)?;
    a.finish()
}

/// `SetDataObject` (count): advance counter `oid` by `by` (non-zero).
///
/// # Errors
/// [`OptigaError::Length`] if `by` is 0.
pub fn count(oid: u16, by: u8) -> Result<Apdu, OptigaError> {
    if by == 0 {
        return Err(OptigaError::Length);
    }
    let mut a = Apdu::new(CMD_SET_DATA_OBJECT, PARAM_COUNT);
    a.push(&oid.to_be_bytes())?;
    a.push(&[0, 0, by])?;
    a.finish()
}

/// `GetRandom`: `n` bytes (8 to 256) from the TRNG.
///
/// # Errors
/// [`OptigaError::Length`] outside 8–256.
pub fn get_random(n: usize) -> Result<Apdu, OptigaError> {
    if !(8..=256).contains(&n) {
        return Err(OptigaError::Length);
    }
    let n = u16::try_from(n).map_err(|_| OptigaError::Length)?;
    let mut a = Apdu::new(CMD_GET_RANDOM, PARAM_TRNG);
    a.push(&n.to_be_bytes())?;
    a.finish()
}

/// `DeriveKey` with the TLS PRF SHA256 from the pre-shared secret in `oid`, over derivation
/// data `parts` (concatenated), `out_len` bytes, returned to the MCU. TLVs in the host
/// library's order: secret OID, length, derivation data, export.
///
/// # Errors
/// [`OptigaError::Length`] if the derivation data is outside
/// [`MIN_DERIVATION_DATA`]–[`MAX_DERIVATION_DATA`] or `out_len` outside 16–256.
pub fn derive_key(oid: u16, parts: &[&[u8]], out_len: u16) -> Result<Apdu, OptigaError> {
    let mut n: usize = 0;
    for p in parts {
        n = n.checked_add(p.len()).ok_or(OptigaError::Length)?;
    }
    if !(MIN_DERIVATION_DATA..=MAX_DERIVATION_DATA).contains(&n) || !(16..=256).contains(&out_len) {
        return Err(OptigaError::Length);
    }
    let mut a = Apdu::new(CMD_DERIVE_KEY, PARAM_TLS_PRF_SHA256);
    a.tlv(0x01, &[&oid.to_be_bytes()])?;
    a.tlv(0x03, &[&out_len.to_be_bytes()])?;
    a.tlv(0x02, parts)?;
    a.tlv(0x07, &[])?;
    a.finish()
}

/// The data of a successful response. Total.
///
/// # Errors
/// [`OptigaError::Status`] if `Sta` is not 0; [`OptigaError::Malformed`] if the response is
/// shorter than its header or `OutLen` disagrees with its length.
pub fn parse_response(resp: &[u8]) -> Result<&[u8], OptigaError> {
    let (head, data) = resp.split_at_checked(4).ok_or(OptigaError::Malformed)?;
    let &[sta, _undef, hi, lo] = head else {
        return Err(OptigaError::Malformed);
    };
    if usize::from(u16::from_be_bytes([hi, lo])) != data.len() {
        return Err(OptigaError::Malformed);
    }
    if sta != 0 {
        return Err(OptigaError::Status);
    }
    Ok(data)
}

/// Metadata tags and values (Solution Reference Manual Tables 66, 67, 71, 74).
pub mod metadata {
    /// Life cycle state of the object (`LcsO`).
    pub const LCSO: u8 = 0xC0;
    /// Change access condition.
    pub const CHANGE: u8 = 0xD0;
    /// Read access condition.
    pub const READ: u8 = 0xD1;
    /// Execute access condition.
    pub const EXECUTE: u8 = 0xD3;
    /// Data object type.
    pub const DATA_TYPE: u8 = 0xE8;
    /// Access condition "always".
    pub const ALW: u8 = 0x00;
    /// Access condition "never".
    pub const NEV: u8 = 0xFF;
    /// Access condition "only over the shielded connection keyed by", followed by an OID.
    pub const CONF: u8 = 0x20;
    /// Life cycle "operational": irreversible, it freezes the metadata.
    pub const LCS_OPERATIONAL: u8 = 0x07;
    /// Data object type "pre-shared secret" (`PRESSEC`).
    pub const TYPE_PRESSEC: u8 = 0x21;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use proptest::prelude::*;

    #[test]
    fn command_encodings() {
        assert_eq!(open_application().unwrap().as_bytes(), hex!("F0 00 0010 D2760000044765 6E417574684170706C"));
        assert_eq!(get_data(OID_COUNTER, false).unwrap().as_bytes(), hex!("81 00 0002 E120"));
        assert_eq!(get_data(OID_ROOT, true).unwrap().as_bytes(), hex!("81 01 0002 F1D0"));
        assert_eq!(count(OID_COUNTER, 1).unwrap().as_bytes(), hex!("82 02 0005 E120 0000 01"));
        assert_eq!(set_data(OID_BINDING, &[0xAB; 2]).unwrap().as_bytes(), hex!("82 40 0006 E140 0000 ABAB"));
        assert_eq!(
            set_metadata(OID_ROOT, &[metadata::READ, 1, metadata::NEV]).unwrap().as_bytes(),
            hex!("82 01 0009 F1D0 0000 20 03 D1 01 FF")
        );
        assert_eq!(get_random(64).unwrap().as_bytes(), hex!("8C 00 0002 0040"));
        assert_eq!(
            derive_key(OID_FRESHNESS, &[b"abcd", b"efgh"], 32).unwrap().as_bytes(),
            hex!("B4 01 0018 01 0002 F1D1 03 0002 0020 02 0008 6162636465666768 07 0000")
        );
    }

    #[test]
    fn command_limits() {
        assert!(count(OID_COUNTER, 0).is_err());
        assert!(get_random(7).is_err());
        assert!(get_random(257).is_err());
        assert!(get_random(8).is_ok() && get_random(256).is_ok());
        assert!(derive_key(OID_ROOT, &[&[0; 7]], 32).is_err());
        assert!(derive_key(OID_ROOT, &[&[0; 8]], 32).is_ok());
        assert!(derive_key(OID_ROOT, &[&[0; MAX_DERIVATION_DATA]], 32).is_ok());
        assert_eq!(derive_key(OID_ROOT, &[&[0; MAX_DERIVATION_DATA]], 32).unwrap().as_bytes().len(), MAX_COMMAND);
        assert!(derive_key(OID_ROOT, &[&[0; 64], &[0; MAX_DERIVATION_DATA - 63]], 32).is_err());
        assert!(derive_key(OID_ROOT, &[&[0; 32]], 15).is_err());
        assert!(derive_key(OID_ROOT, &[&[0; 32]], 257).is_err());
        assert!(derive_key(OID_ROOT, &[&[0; 32]], 256).is_ok());
        assert!(set_metadata(OID_ROOT, &[0; 127]).is_ok());
        assert!(set_metadata(OID_ROOT, &[0; 128]).is_err());
        assert!(set_data(OID_ROOT, &[0; MAX_COMMAND - 8]).is_ok());
        assert!(set_data(OID_ROOT, &[0; MAX_COMMAND - 7]).is_err());
    }

    #[test]
    fn responses() {
        assert_eq!(parse_response(&hex!("00 00 0000")), Ok(&[][..]));
        assert_eq!(parse_response(&hex!("00 5A 0002 0102")), Ok(&[1u8, 2][..]));
        assert_eq!(parse_response(&hex!("FF 00 0000")), Err(OptigaError::Status));
        assert_eq!(parse_response(&hex!("00 00 0003 0102")), Err(OptigaError::Malformed));
        assert_eq!(parse_response(&hex!("00 00 0001 0102")), Err(OptigaError::Malformed));
        assert_eq!(parse_response(&hex!("00 00 00")), Err(OptigaError::Malformed));
        // A failing response may not carry data either.
        assert_eq!(parse_response(&hex!("FF 00 0001 07")), Err(OptigaError::Status));
    }

    proptest! {
        #[test]
        fn parse_response_is_total(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            if let Ok(data) = parse_response(&bytes) {
                prop_assert_eq!(bytes[0], 0);
                prop_assert_eq!(data.len() + 4, bytes.len());
            }
        }
    }
}
