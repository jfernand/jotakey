// (c) Javier Fernandez @ JotaSoft 2026
//! authenticatorGetInfo (CTAP 2.1 §6.4).

use super::client_pin::MIN_PIN_LENGTH;
use super::{MAX_CREDENTIAL_COUNT_IN_LIST, Response, write_success};
use crate::MAX_MSG_SIZE;
use crate::credential::CRED_ID_LEN;
use crate::pin_protocol;
use crate::status::Status;

/// Write the getInfo response.
///
/// ```text
/// {1: ["FIDO_2_0"], 3: aaguid,
///  4: {"rk": false, "up": true, "plat": false, "clientPin": pin_set,
///      "pinUvAuthToken": true, "makeCredUvNotRqd": true},
///  5: maxMsgSize, 6: [2], 7: maxCredentialCountInList, 8: maxCredentialIdLength,
///  13: minPINLength}
/// ```
/// `uv` is absent: there is no built-in user verification, only the PIN. The versions stay
/// at `FIDO_2_0` until the rest of CTAP 2.1 (credential management, `authenticatorSelection`)
/// is in; the 2.1 members above are understood by clients regardless.
pub fn run(aaguid: &[u8; 16], pin_set: bool, out: &mut Response) -> Result<usize, Status> {
    write_success(out, |e| {
        e.map(8)?;
        e.unsigned(0x01)?;
        e.array(1)?;
        e.text("FIDO_2_0")?;
        e.unsigned(0x03)?;
        e.bytes(aaguid)?;
        e.unsigned(0x04)?;
        e.map(6)?;
        e.text("rk")?;
        e.boolean(false)?;
        e.text("up")?;
        e.boolean(true)?;
        e.text("plat")?;
        e.boolean(false)?;
        e.text("clientPin")?;
        e.boolean(pin_set)?;
        e.text("pinUvAuthToken")?;
        e.boolean(true)?;
        e.text("makeCredUvNotRqd")?;
        e.boolean(true)?;
        e.unsigned(0x05)?;
        e.unsigned(MAX_MSG_SIZE as u64)?;
        e.unsigned(0x06)?;
        e.array(1)?;
        e.unsigned(pin_protocol::PROTOCOL)?;
        e.unsigned(0x07)?;
        e.unsigned(MAX_CREDENTIAL_COUNT_IN_LIST)?;
        e.unsigned(0x08)?;
        e.unsigned(CRED_ID_LEN as u64)?;
        e.unsigned(0x0D)?;
        e.unsigned(u64::from(MIN_PIN_LENGTH))
    })
}
