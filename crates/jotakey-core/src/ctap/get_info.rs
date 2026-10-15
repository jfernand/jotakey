//! authenticatorGetInfo (CTAP 2.0 §5.4).

use super::{MAX_CREDENTIAL_COUNT_IN_LIST, Response, write_success};
use crate::MAX_MSG_SIZE;
use crate::credential::CRED_ID_LEN;
use crate::status::Status;

/// Write the getInfo response.
///
/// ```text
/// {1: ["FIDO_2_0"], 3: aaguid, 4: {"rk": false, "up": true, "plat": false},
///  5: maxMsgSize, 7: maxCredentialCountInList, 8: maxCredentialIdLength}
/// ```
/// `uv` and `clientPin` are absent: the MVP has neither capability.
pub fn run(aaguid: &[u8; 16], out: &mut Response) -> Result<usize, Status> {
    write_success(out, |e| {
        e.map(6)?;
        e.unsigned(0x01)?;
        e.array(1)?;
        e.text("FIDO_2_0")?;
        e.unsigned(0x03)?;
        e.bytes(aaguid)?;
        e.unsigned(0x04)?;
        e.map(3)?;
        e.text("rk")?;
        e.boolean(false)?;
        e.text("up")?;
        e.boolean(true)?;
        e.text("plat")?;
        e.boolean(false)?;
        e.unsigned(0x05)?;
        e.unsigned(MAX_MSG_SIZE as u64)?;
        e.unsigned(0x07)?;
        e.unsigned(MAX_CREDENTIAL_COUNT_IN_LIST)?;
        e.unsigned(0x08)?;
        e.unsigned(CRED_ID_LEN as u64)
    })
}
