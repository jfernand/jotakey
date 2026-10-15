//! User presence: the BOOT button (GPIO9, active low).
//!
//! A touch counts only if the button is seen *released* after the request arrived and then
//! held down for [`DEBOUNCE_POLLS`] consecutive polls. A button held down since before the
//! request (taped down, or pressed for an earlier request) never confirms anything.

use embassy_time::{Duration, Instant, Timer};
use esp_hal::gpio::Input;
use jotakey_core::platform::UpResult;

use crate::link::{self, CANCEL, Transport};

/// How long the user has to touch the device (CTAP recommends ≥ 30 s).
pub const UP_TIMEOUT: Duration = Duration::from_secs(30);
/// Poll interval.
const POLL: Duration = Duration::from_millis(20);
/// Consecutive "pressed" polls required (40 ms debounce).
pub const DEBOUNCE_POLLS: u8 = 2;
/// Keepalive interval (CTAPHID requires < 100 ms between keepalives while waiting).
const KEEPALIVE_EVERY: u32 = 4; // 4 × 20 ms

/// Wait for a fresh, debounced press, sending `UP_NEEDED` keepalives to `transport`.
pub async fn wait(button: &mut Input<'_>, transport: Transport, keepalive_status: u8) -> UpResult {
    let deadline = Instant::now() + UP_TIMEOUT;
    let mut released_seen = false;
    let mut pressed_polls = 0u8;
    let mut tick = 0u32;
    loop {
        if CANCEL.signaled() && CANCEL.try_take() == Some(transport) {
            return UpResult::Cancelled;
        }
        if Instant::now() >= deadline {
            return UpResult::Timeout;
        }
        if button.is_high() {
            released_seen = true;
            pressed_polls = 0;
        } else if released_seen {
            pressed_polls = pressed_polls.saturating_add(1);
            if pressed_polls >= DEBOUNCE_POLLS {
                return UpResult::Confirmed;
            }
        }
        if tick.is_multiple_of(KEEPALIVE_EVERY) {
            link::keepalive(transport, keepalive_status);
        }
        tick = tick.wrapping_add(1);
        Timer::after(POLL).await;
    }
}
