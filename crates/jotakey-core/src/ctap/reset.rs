// (c) Javier Fernandez @ JotaSoft 2026
//! authenticatorReset (CTAP 2.0 §5.6).
//!
//! Invariant 6: reset is accepted only within [`RESET_WINDOW_MS`] of power-up and only after
//! a touch. Rotating the epoch secret changes `K_mac` and `K_seed`, so every credential
//! minted before the reset stops unwrapping. The signature counter is *not* reset; it
//! stays monotonic for the device's lifetime.

use super::{Pending, RESET_WINDOW_MS, Response, write_status};
use crate::platform::Platform;
use crate::status::Status;

/// Check the time window and park the reset.
pub fn process<P: Platform>(platform: &mut P, params: &[u8]) -> Result<Pending, Status> {
    if !params.is_empty() {
        return Err(Status::InvalidLength);
    }
    if platform.uptime_ms() > RESET_WINDOW_MS {
        return Err(Status::NotAllowed);
    }
    Ok(Pending::Reset)
}

/// Perform the reset after the touch.
pub fn complete<P: Platform>(platform: &mut P, out: &mut Response) -> Result<usize, Status> {
    platform.rotate_epoch().map_err(|_| Status::Other)?;
    Ok(write_status(out, Status::Success))
}
