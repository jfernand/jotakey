// (c) Javier Fernandez @ JotaSoft 2026
//! The red status LED on PA3 (active high, 1 kΩ). One colour, so each state is a pattern:
//! touch requested = slow blink, wink = fast blink, fault = solid on, `dev-key` build =
//! three quick flashes at boot.

use embassy_futures::select::{Either, select};
use embassy_stm32::gpio::Output;
use embassy_time::{Duration, Timer};

use crate::link::{LED, LedState};

/// Blink half-periods.
const TOUCH_HALF: Duration = Duration::from_millis(400);
const WINK_HALF: Duration = Duration::from_millis(100);
/// A wink lasts this many blinks, then the LED goes back to idle.
const WINK_BLINKS: u32 = 10;

#[embassy_executor::task]
pub async fn led_task(mut led: Output<'static>) {
    let mut state = LedState::Idle;
    loop {
        match state {
            LedState::Idle => {
                led.set_low();
                state = LED.wait().await;
            }
            LedState::Fault => {
                // Terminal: the fault state is never left.
                led.set_high();
                loop {
                    Timer::after_secs(3600).await;
                }
            }
            LedState::Touch => {
                state = match select(blink(&mut led, TOUCH_HALF, u32::MAX), LED.wait()).await {
                    Either::First(()) => LedState::Idle,
                    Either::Second(s) => s,
                };
            }
            LedState::Wink => {
                state = match select(blink(&mut led, WINK_HALF, WINK_BLINKS), LED.wait()).await {
                    Either::First(()) => LedState::Idle,
                    Either::Second(s) => s,
                };
            }
            #[cfg(feature = "dev-key")]
            LedState::DevKey => {
                blink(&mut led, Duration::from_millis(80), 3).await;
                state = LedState::Idle;
            }
        }
    }
}

async fn blink(led: &mut Output<'_>, half: Duration, times: u32) {
    for _ in 0..times {
        led.set_high();
        Timer::after(half).await;
        led.set_low();
        Timer::after(half).await;
    }
}
