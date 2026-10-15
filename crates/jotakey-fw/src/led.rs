//! Status LED: the DevKit's WS2812 on GPIO8, driven by the RMT peripheral.

use embassy_time::{Duration, Timer};
use esp_hal::Async;
use esp_hal::gpio::Level;
use esp_hal::rmt::{Channel, PulseCode, Tx};

use crate::link::{LED, LedState};

/// RMT at 80 MHz with divider 1: one tick = 12.5 ns. WS2812 timing:
/// 0 = 0.4 µs high + 0.85 µs low, 1 = 0.8 µs high + 0.45 µs low.
const T0H: u16 = 32;
const T0L: u16 = 68;
const T1H: u16 = 64;
const T1L: u16 = 36;

fn frame(rgb: (u8, u8, u8)) -> [PulseCode; 25] {
    let (r, g, b) = rgb;
    let grb = (u32::from(g) << 16) | (u32::from(r) << 8) | u32::from(b);
    let mut out = [PulseCode::end_marker(); 25];
    for (i, slot) in out.iter_mut().take(24).enumerate() {
        let bit = (grb >> (23 - i)) & 1;
        *slot = if bit == 1 {
            PulseCode::new(Level::High, T1H, Level::Low, T1L)
        } else {
            PulseCode::new(Level::High, T0H, Level::Low, T0L)
        };
    }
    out
}

async fn show(ch: &mut Channel<'static, Async, Tx>, rgb: (u8, u8, u8)) {
    let _ = ch.transmit(&frame(rgb)).await;
}

const OFF: (u8, u8, u8) = (0, 0, 0);
const AMBER: (u8, u8, u8) = (40, 18, 0);
const BLUE: (u8, u8, u8) = (0, 0, 40);
const RED: (u8, u8, u8) = (40, 0, 0);
#[cfg(feature = "dev-key")]
const MAGENTA: (u8, u8, u8) = (30, 0, 30);

#[embassy_executor::task]
pub async fn led_task(mut ch: Channel<'static, Async, Tx>) {
    let mut state = LedState::Idle;
    let mut phase = false;
    loop {
        if let Some(s) = LED.try_take() {
            // Fault is sticky: nothing may hide it.
            if state != LedState::Fault {
                state = s;
            }
        }
        match state {
            LedState::Idle => show(&mut ch, OFF).await,
            LedState::Fault => show(&mut ch, RED).await,
            LedState::Touch => show(&mut ch, if phase { AMBER } else { OFF }).await,
            LedState::Wink => {
                for _ in 0..4 {
                    show(&mut ch, BLUE).await;
                    Timer::after(Duration::from_millis(150)).await;
                    show(&mut ch, OFF).await;
                    Timer::after(Duration::from_millis(150)).await;
                }
                state = LedState::Idle;
            }
            #[cfg(feature = "dev-key")]
            LedState::DevKey => {
                for _ in 0..6 {
                    show(&mut ch, MAGENTA).await;
                    Timer::after(Duration::from_millis(100)).await;
                    show(&mut ch, OFF).await;
                    Timer::after(Duration::from_millis(100)).await;
                }
                state = LedState::Idle;
            }
        }
        phase = !phase;
        Timer::after(Duration::from_millis(250)).await;
    }
}
