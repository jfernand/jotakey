//! `authenticatorData` (WebAuthn §6.1).
//!
//! ```text
//! rpIdHash (32) ‖ flags (1) ‖ signCount (4, big-endian) ‖ [attestedCredentialData]
//! attestedCredentialData = aaguid (16) ‖ credIdLen (2, BE) ‖ credId ‖ COSE_Key
//! ```

use crate::cbor::{CborError, Encoder};
use crate::credential::CRED_ID_LEN;
use crate::crypto::encode_cose_key;

/// User Present.
pub const FLAG_UP: u8 = 0x01;
/// User Verified.
pub const FLAG_UV: u8 = 0x04;
/// Attested credential data included.
pub const FLAG_AT: u8 = 0x40;
/// Extension data included.
pub const FLAG_ED: u8 = 0x80;

/// Length of authenticator data without attested credential data.
pub const BASE_LEN: usize = 32 + 1 + 4;
/// Upper bound of authenticator data with attested credential data for our credentials.
pub const MAX_LEN: usize = BASE_LEN + 16 + 2 + CRED_ID_LEN + 77;

/// Build assertion authenticator data (no attested credential).
#[must_use]
pub fn assertion(rp_id_hash: &[u8; 32], flags: u8, sign_count: u32) -> [u8; BASE_LEN] {
    let mut out = [0u8; BASE_LEN];
    let (h, rest) = out.split_at_mut(32);
    let (f, c) = rest.split_at_mut(1);
    h.copy_from_slice(rp_id_hash);
    f.copy_from_slice(&[flags]);
    c.copy_from_slice(&sign_count.to_be_bytes());
    out
}

/// Build registration authenticator data into `buf`; returns the length used.
///
/// # Errors
/// [`CborError::BufferFull`] if `buf` is too small (it never is with [`MAX_LEN`]).
pub fn registration(
    buf: &mut [u8; MAX_LEN],
    rp_id_hash: &[u8; 32],
    sign_count: u32,
    aaguid: &[u8; 16],
    cred_id: &[u8; CRED_ID_LEN],
    public: &p256::PublicKey,
) -> Result<usize, CborError> {
    let mut e = Encoder::new(buf);
    e.raw(&assertion(rp_id_hash, FLAG_UP | FLAG_AT, sign_count))?;
    e.raw(aaguid)?;
    #[allow(clippy::cast_possible_truncation)] // CRED_ID_LEN is 49.
    e.raw(&(CRED_ID_LEN as u16).to_be_bytes())?;
    e.raw(cred_id)?;
    encode_cose_key(public, &mut e)?;
    Ok(e.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_layout() {
        let a = assertion(&[0xAA; 32], FLAG_UP, 0x0102_0304);
        assert_eq!(&a[..32], &[0xAA; 32]);
        assert_eq!(a[32], FLAG_UP);
        assert_eq!(&a[33..], &[1, 2, 3, 4]);
    }

    #[test]
    fn registration_layout() {
        let sk = crate::crypto::derive_credential_key(&[1; 32], &[2; 32], &[3; 32]).unwrap();
        let mut buf = [0u8; MAX_LEN];
        let n = registration(&mut buf, &[0xAA; 32], 7, &[0x11; 16], &[0x22; CRED_ID_LEN], &sk.public_key()).unwrap();
        assert_eq!(n, MAX_LEN);
        assert_eq!(buf[32], FLAG_UP | FLAG_AT);
        assert_eq!(&buf[33..37], &[0, 0, 0, 7]);
        assert_eq!(&buf[37..53], &[0x11; 16]);
        assert_eq!(&buf[53..55], &[0, 49]);
        assert_eq!(&buf[55..104], &[0x22; 49]);
    }
}
