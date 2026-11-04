// (c) Javier Fernandez @ JotaSoft 2026
//! User presence: the capacitive touch electrode (TSC group 2: PB4 sampling capacitor, PB5
//! electrode through 1 kΩ).
//!
//! Whether one reading is a touch is the core's [`TouchDetector`], calibrated at boot. When a
//! touch counts is the core's [`PresenceGate`]: the electrode seen *released* after the
//! request arrived, then touched for `DEBOUNCE_POLLS` consecutive polls (≥ 40 ms), before the
//! 30 s deadline (proved in `formal/Jotakey/Presence.lean`). A finger resting on the key since
//! before the request never confirms anything.

use embassy_stm32::mode::Blocking;
use embassy_stm32::peripherals::TSC;
use embassy_stm32::tsc::{self, Tsc};
use embassy_time::{Duration, Instant, Timer};
use jotakey_core::platform::PresenceResult;
use jotakey_core::presence::{GateStep, PresenceGate};
use jotakey_core::touch::TouchDetector;

use crate::link::{CANCEL, KEEPALIVE};

/// Poll interval.
const POLL: Duration = Duration::from_millis(20);
/// Keepalive interval (CTAPHID requires < 100 ms between keepalives while waiting).
const KEEPALIVE_EVERY: u32 = 4; // 4 × 20 ms
/// Acquisition attempts per reading before it counts as failed.
const ACQUIRE_POLLS: u32 = 10_000;

/// The touch electrode: the TSC and its detector.
pub struct TouchSensor {
    tsc: Tsc<'static, TSC, Blocking>,
    channel: tsc::IOPin,
    detector: TouchDetector,
}

impl TouchSensor {
    /// Wrap the configured TSC.
    pub fn new(tsc: Tsc<'static, TSC, Blocking>, channel: tsc::IOPin) -> Self {
        Self { tsc, channel, detector: TouchDetector::new() }
    }

    /// One acquisition count, 0 if it failed.
    fn acquire(&mut self) -> u16 {
        self.tsc.set_active_channels_mask(self.channel.into());
        self.tsc.start();
        let mut polls = 0u32;
        while self.tsc.get_state() == tsc::State::Busy {
            polls = polls.saturating_add(1);
            if polls >= ACQUIRE_POLLS {
                self.tsc.stop();
                return 0;
            }
        }
        let value = match self.tsc.group_get_status(self.channel.group()) {
            tsc::GroupStatus::Complete => self.tsc.group_get_value(self.channel.group()),
            tsc::GroupStatus::Ongoing => 0,
        };
        // Discharge the sampling capacitor for the next acquisition.
        self.tsc.discharge_io(true);
        value
    }

    /// Take a reading; return whether the electrode is touched.
    pub fn touched(&mut self) -> bool {
        let count = self.acquire();
        self.detector.feed(count)
    }

    /// Take readings until the detector has its baseline (at boot; the key is assumed
    /// untouched while it powers up).
    pub async fn calibrate(&mut self) {
        let mut tries = 0u32;
        while !self.detector.is_calibrated() && tries < 100 {
            let _ = self.touched();
            tries = tries.saturating_add(1);
            Timer::after(POLL).await;
        }
    }
}

/// Wait for a fresh, debounced touch, sending `UP_NEEDED` keepalives.
pub async fn wait(sensor: &mut TouchSensor, keepalive_status: u8) -> PresenceResult {
    let mut gate = PresenceGate::new(Instant::now().as_millis());
    let mut tick = 0u32;
    loop {
        if CANCEL.signaled() {
            CANCEL.reset();
            return PresenceResult::Cancelled;
        }
        let touched = sensor.touched();
        match gate.poll(Instant::now().as_millis(), touched) {
            GateStep::Confirmed => return PresenceResult::Confirmed,
            GateStep::Timeout => return PresenceResult::Timeout,
            GateStep::Waiting => {}
        }
        if tick.is_multiple_of(KEEPALIVE_EVERY) {
            KEEPALIVE.signal(keepalive_status);
        }
        tick = tick.wrapping_add(1);
        Timer::after(POLL).await;
    }
}
