// (c) Javier Fernandez @ JotaSoft 2026
//! User presence: the BOOT button (GPIO9, active low).
//!
//! Each poll's reading goes to the core's [`PresenceGate`], which decides when a press
//! counts: the button seen *released* after the request arrived, then held down for
//! `DEBOUNCE_POLLS` consecutive polls, before the 30 s deadline (proved in
//! `formal/Jotakey/Presence.lean`). A button held down since before the request (taped down,
//! or pressed for an earlier request) never confirms anything.

use embassy_time::{Duration, Instant, Timer};
use esp_hal::gpio::Input;
use jotakey_core::platform::PresenceResult;
use jotakey_core::presence::{GateStep, PresenceGate};

use crate::link::{self, CANCEL, Transport};

/// Poll interval.
const POLL: Duration = Duration::from_millis(20);
/// Keepalive interval (CTAPHID requires < 100 ms between keepalives while waiting).
const KEEPALIVE_EVERY: u32 = 4; // 4 × 20 ms

/// Wait for a fresh, debounced press, sending `UP_NEEDED` keepalives to `transport`.
pub async fn wait(button: &mut Input<'_>, transport: Transport, keepalive_status: u8) -> PresenceResult {
    let mut gate = PresenceGate::new(Instant::now().as_millis());
    let mut tick = 0u32;
    loop {
        if CANCEL.signaled() && CANCEL.try_take() == Some(transport) {
            return PresenceResult::Cancelled;
        }
        match gate.poll(Instant::now().as_millis(), button.is_low()) {
            GateStep::Confirmed => return PresenceResult::Confirmed,
            GateStep::Timeout => return PresenceResult::Timeout,
            GateStep::Waiting => {}
        }
        if tick.is_multiple_of(KEEPALIVE_EVERY) {
            link::keepalive(transport, keepalive_status);
        }
        tick = tick.wrapping_add(1);
        Timer::after(POLL).await;
    }
}
