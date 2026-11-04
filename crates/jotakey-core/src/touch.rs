// (c) Javier Fernandez @ JotaSoft 2026
//! Capacitive touch detection for the jotakey key's electrode.
//!
//! The STM32 touch sensing controller (TSC) reports, for each acquisition, how many charge
//! transfers it took to fill the sampling capacitor. A finger adds capacitance to the
//! electrode, so the count *drops*. [`TouchDetector`] turns the stream of counts into
//! "touched" or "not touched":
//!
//! - the first [`CALIBRATION_SAMPLES`] readings set the baseline (the key is assumed
//!   untouched while it powers up; a finger held on it then only makes the key blind to that
//!   finger, never confirms anything);
//! - a reading at least [`ENTER_PER_MILLE`] below the baseline is a touch, and the touch
//!   lasts until the reading comes back within [`EXIT_PER_MILLE`] (hysteresis, so noise at
//!   the threshold does not chatter);
//! - while untouched, the baseline follows slow drift (temperature, humidity), never while
//!   touched, so a resting finger cannot become the new baseline.
//!
//! This only says whether the electrode is touched. The rule that turns touches into user
//! presence (seen released after the request, then touched for ≥ 40 ms) stays in the
//! firmware's presence loop, and `PresenceResult::Confirmed` is consumed only by
//! `Authenticator::complete` (invariant 1). The thresholds are provisional until measured
//! on a board.

/// Readings averaged into the first baseline.
pub const CALIBRATION_SAMPLES: u32 = 8;
/// A drop of this many thousandths of the baseline starts a touch.
pub const ENTER_PER_MILLE: u32 = 40;
/// A touch ends once the drop is below this many thousandths of the baseline.
pub const EXIT_PER_MILLE: u32 = 20;
/// The baseline moves `1 / 2^DRIFT_SHIFT` of the way to each untouched reading.
pub const DRIFT_SHIFT: u32 = 4;
/// Fixed-point scale of the baseline (4 fractional bits), so slow drift is not rounded away.
const SCALE_SHIFT: u32 = 4;

/// Touch state from TSC acquisition counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TouchDetector {
    /// Readings taken so far during calibration (saturates at [`CALIBRATION_SAMPLES`]).
    calibrated: u32,
    /// Sum of the calibration readings, then the baseline scaled by `2^SCALE_SHIFT`.
    baseline: u32,
    touched: bool,
}

impl Default for TouchDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TouchDetector {
    /// An uncalibrated detector: it reports no touch until calibrated.
    #[must_use]
    pub const fn new() -> Self {
        Self { calibrated: 0, baseline: 0, touched: false }
    }

    /// Whether the baseline is set.
    #[must_use]
    pub const fn is_calibrated(&self) -> bool {
        self.calibrated >= CALIBRATION_SAMPLES
    }

    /// The baseline in counts (0 before calibration).
    #[must_use]
    pub const fn baseline(&self) -> u32 {
        if self.is_calibrated() { self.baseline >> SCALE_SHIFT } else { 0 }
    }

    /// Feed one acquisition count; return whether the electrode is touched now.
    ///
    /// A count of 0 is a failed acquisition (the TSC's max-count error): no touch, and the
    /// state is otherwise unchanged.
    pub fn feed(&mut self, count: u16) -> bool {
        let count = u32::from(count);
        if count == 0 {
            self.touched = false;
            return false;
        }
        if !self.is_calibrated() {
            self.baseline = self.baseline.saturating_add(count);
            self.calibrated = self.calibrated.saturating_add(1);
            if self.is_calibrated() {
                // Mean of the readings, in fixed point.
                self.baseline = (self.baseline / CALIBRATION_SAMPLES).saturating_mul(1 << SCALE_SHIFT);
            }
            return false;
        }
        let base = self.baseline >> SCALE_SHIFT;
        let drop = base.saturating_sub(count);
        // Thresholds in counts; the baseline fits in 16 bits, so these cannot overflow.
        let enter = base.saturating_mul(ENTER_PER_MILLE) / 1000;
        let exit = base.saturating_mul(EXIT_PER_MILLE) / 1000;
        self.touched = if self.touched { drop >= exit.max(1) } else { drop >= enter.max(1) };
        if !self.touched && drop < exit {
            // Untouched and near the baseline: follow the drift.
            let target = count.saturating_mul(1 << SCALE_SHIFT);
            if target > self.baseline {
                self.baseline = self.baseline.saturating_add(target.saturating_sub(self.baseline) >> DRIFT_SHIFT);
            } else {
                self.baseline = self.baseline.saturating_sub(self.baseline.saturating_sub(target) >> DRIFT_SHIFT);
            }
        }
        self.touched
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn calibrated(at: u16) -> TouchDetector {
        let mut d = TouchDetector::new();
        for _ in 0..CALIBRATION_SAMPLES {
            assert!(!d.feed(at));
        }
        assert!(d.is_calibrated());
        assert_eq!(d.baseline(), u32::from(at));
        d
    }

    #[test]
    fn calibration_averages_and_never_reports_a_touch() {
        let mut d = TouchDetector::new();
        assert_eq!(d.baseline(), 0);
        for c in [1000u16, 1010, 990, 1000, 1005, 995, 1000, 1000] {
            assert!(!d.is_calibrated());
            // Even a very low reading during calibration is not a touch.
            assert!(!d.feed(c));
        }
        assert_eq!(d.baseline(), 1000);
        assert!(TouchDetector::default() == TouchDetector::new());
    }

    #[test]
    fn a_drop_past_the_threshold_is_a_touch_with_hysteresis() {
        let mut d = calibrated(1000);
        assert!(!d.feed(961), "3.9 % is below the 4 % threshold");
        let mut d = calibrated(1000);
        assert!(d.feed(960), "4 % drop");
        assert!(d.feed(975), "still touched above the exit threshold");
        assert!(d.feed(980), "2 % drop is still a touch");
        assert!(!d.feed(981), "released below the 2 % exit threshold");
        assert!(!d.feed(975), "2.5 % is not enough to start a new touch");
        assert!(d.feed(900));
    }

    #[test]
    fn baseline_follows_drift_only_while_untouched() {
        let mut d = calibrated(1000);
        for _ in 0..200 {
            assert!(!d.feed(1010));
        }
        assert_eq!(d.baseline(), 1009, "baseline drifted up to the new level");
        for _ in 0..200 {
            assert!(!d.feed(995));
        }
        assert_eq!(d.baseline(), 995, "and down again");
        // A resting finger never becomes the baseline.
        for _ in 0..1000 {
            assert!(d.feed(900));
        }
        assert_eq!(d.baseline(), 995);
        // Readings in the hysteresis band of an untouched detector do not move it, down to
        // and including the exit threshold itself.
        for reading in [970, 980] {
            let mut d = calibrated(1000);
            for _ in 0..100 {
                assert!(!d.feed(reading));
            }
            assert_eq!(d.baseline(), 1000, "reading {reading}");
        }
        // Just inside the exit threshold it drifts.
        let mut d = calibrated(1000);
        for _ in 0..100 {
            assert!(!d.feed(981));
        }
        assert!(d.baseline() < 1000);
    }

    #[test]
    fn failed_acquisitions_are_never_touches() {
        let mut d = TouchDetector::new();
        assert!(!d.feed(0));
        assert!(!d.is_calibrated(), "a failed acquisition is not a calibration sample");
        let mut d = calibrated(1000);
        assert!(d.feed(500));
        assert!(!d.feed(0));
        assert_eq!(d.baseline(), 1000);
    }

    #[test]
    fn tiny_baselines_still_need_a_drop() {
        let mut d = calibrated(10);
        assert!(!d.feed(10));
        assert!(d.feed(9), "thresholds round up to one count");
        assert!(!d.feed(10));
        let mut d = calibrated(u16::MAX);
        assert!(!d.feed(u16::MAX));
        assert!(d.feed(u16::MAX - 2700));
    }

    proptest! {
        /// Noise within ±1.5 % of the calibration level is never a touch: the baseline can
        /// drift to either edge of the band, and the far edge is still under 4 % away.
        #[test]
        fn small_noise_is_never_a_touch(
            base in 1000u16..60000,
            noise in proptest::collection::vec(-15i32..=15, 1..500),
        ) {
            let mut d = calibrated(base);
            for n in noise {
                let c = (i32::from(base) + i32::from(base) * n / 1000) as u16;
                prop_assert!(!d.feed(c));
            }
        }

        /// A touch is reported only for a reading below the baseline, and never during
        /// calibration.
        #[test]
        fn touches_are_always_drops(counts in proptest::collection::vec(any::<u16>(), 1..300)) {
            let mut d = TouchDetector::new();
            for c in counts {
                let was_calibrated = d.is_calibrated();
                let base = d.baseline();
                let t = d.feed(c);
                if t {
                    prop_assert!(was_calibrated);
                    prop_assert!(u32::from(c) < base);
                }
            }
        }
    }
}
