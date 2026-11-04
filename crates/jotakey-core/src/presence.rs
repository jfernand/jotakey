// (c) Javier Fernandez @ JotaSoft 2026
//! The user-presence rule (invariant 1, at the sensor): when a touch counts.
//!
//! Each firmware polls its sensor (the C6's BOOT button, the key's touch electrode) and
//! feeds every reading to a [`PresenceGate`] created when the request arrived. The gate
//! answers [`GateStep::Confirmed`] only if the sensor was seen *released* after the request
//! and then held for [`DEBOUNCE_POLLS`] consecutive polls (≥ 40 ms at the 20 ms poll), and
//! [`GateStep::Timeout`] once [`UP_TIMEOUT_MS`] have passed. A button held down since before
//! the request (taped down, or pressed for an earlier request) never confirms anything.
//!
//! Cancellation is the firmware's: it checks for CANCEL before each poll and answers
//! `PresenceResult::Cancelled` without asking the gate.
//!
//! Modelled in `formal/Jotakey/Presence.lean` (`Gate`, `poll`), which proves that a
//! confirmation needs a release followed by a debounced touch inside the deadline, and that a
//! touch held from the start never confirms; `tests/differential.rs` checks that the two
//! agree.

/// How long the user has to touch the device (CTAP recommends ≥ 30 s).
pub const UP_TIMEOUT_MS: u64 = 30_000;
/// Consecutive "pressed" polls required after a release.
pub const DEBOUNCE_POLLS: u8 = 2;

/// What one poll decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateStep {
    /// No decision yet; poll again.
    Waiting,
    /// A fresh, debounced touch: the request may complete with `PresenceResult::Confirmed`.
    Confirmed,
    /// The deadline passed.
    Timeout,
}

/// The release-then-touch rule for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresenceGate {
    deadline_ms: u64,
    /// The deadline was seen: every later poll times out, whatever time it reports.
    expired: bool,
    released_seen: bool,
    pressed_polls: u8,
}

impl PresenceGate {
    /// A gate for a request that arrived at `now_ms`. Nothing seen before this counts.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        Self {
            deadline_ms: now_ms.saturating_add(UP_TIMEOUT_MS),
            expired: false,
            released_seen: false,
            pressed_polls: 0,
        }
    }

    /// Feed one sensor reading taken at `now_ms`.
    pub fn poll(&mut self, now_ms: u64, pressed: bool) -> GateStep {
        if self.expired || now_ms >= self.deadline_ms {
            self.expired = true;
            return GateStep::Timeout;
        }
        if !pressed {
            self.released_seen = true;
            self.pressed_polls = 0;
        } else if self.released_seen {
            self.pressed_polls = self.pressed_polls.saturating_add(1);
            if self.pressed_polls >= DEBOUNCE_POLLS {
                return GateStep::Confirmed;
            }
        }
        GateStep::Waiting
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn run(start: u64, readings: &[(u64, bool)]) -> std::vec::Vec<GateStep> {
        let mut g = PresenceGate::new(start);
        readings.iter().map(|&(t, p)| g.poll(t, p)).collect()
    }

    #[test]
    fn release_then_two_presses_confirms() {
        use GateStep::{Confirmed, Waiting};
        assert_eq!(run(0, &[(0, false), (20, true), (40, true)]), [Waiting, Waiting, Confirmed]);
        // A single press is not enough; a release in between starts over.
        assert_eq!(
            run(0, &[(0, false), (20, true), (40, false), (60, true), (80, true)]),
            [Waiting, Waiting, Waiting, Waiting, Confirmed]
        );
    }

    #[test]
    fn a_press_held_from_the_start_never_confirms() {
        let readings: std::vec::Vec<_> = (0..2000).map(|i| (i * 20, true)).collect();
        assert!(!run(0, &readings).contains(&GateStep::Confirmed));
        // Released afterwards, then pressed again: that is a fresh touch.
        let mut g = PresenceGate::new(0);
        assert_eq!(g.poll(100, true), GateStep::Waiting);
        assert_eq!(g.poll(120, false), GateStep::Waiting);
        assert_eq!(g.poll(140, true), GateStep::Waiting);
        assert_eq!(g.poll(160, true), GateStep::Confirmed);
    }

    #[test]
    fn deadline_is_thirty_seconds_after_the_request() {
        let mut g = PresenceGate::new(1000);
        assert_eq!(g.poll(30_999, false), GateStep::Waiting);
        assert_eq!(g.poll(31_000, true), GateStep::Timeout);
        // Even a debounced touch arriving at the deadline is too late.
        let mut g = PresenceGate::new(0);
        assert_eq!(g.poll(29_960, false), GateStep::Waiting);
        assert_eq!(g.poll(29_980, true), GateStep::Waiting);
        assert_eq!(g.poll(30_000, true), GateStep::Timeout);
        // Once timed out, always timed out, even if a later reading reports an earlier time.
        assert_eq!(g.poll(29_000, false), GateStep::Timeout);
        assert_eq!(g.poll(29_020, true), GateStep::Timeout);
        assert_eq!(g.poll(29_040, true), GateStep::Timeout);
        // A request near the end of time cannot overflow the deadline.
        let mut g = PresenceGate::new(u64::MAX - 5);
        assert_eq!(g.poll(u64::MAX - 5, false), GateStep::Waiting);
        assert_eq!(g.poll(u64::MAX, false), GateStep::Timeout);
    }

    #[test]
    fn many_presses_saturate() {
        let mut g = PresenceGate::new(0);
        assert_eq!(g.poll(0, false), GateStep::Waiting);
        for t in 1..400 {
            let step = g.poll(t, true);
            assert_eq!(step, if t == 1 { GateStep::Waiting } else { GateStep::Confirmed });
        }
    }

    proptest! {
        /// Confirmed only right after a release followed by `DEBOUNCE_POLLS` presses, and
        /// only while no reading has reached the deadline, whatever order the times come in.
        #[test]
        fn confirmation_needs_release_then_debounced_press(
            readings in proptest::collection::vec((0u64..40_000, any::<bool>()), 0..200),
        ) {
            let steps = run(0, &readings);
            for (i, step) in steps.iter().enumerate() {
                if *step == GateStep::Confirmed {
                    let presses = usize::from(DEBOUNCE_POLLS);
                    prop_assert!(i + 1 >= presses);
                    prop_assert!(readings[i + 1 - presses..=i].iter().all(|r| r.1));
                    prop_assert!(readings[..=i].iter().any(|r| !r.1));
                    prop_assert!(readings[..=i].iter().all(|r| r.0 < UP_TIMEOUT_MS));
                }
                if readings[..=i].iter().any(|r| r.0 >= UP_TIMEOUT_MS) {
                    prop_assert_eq!(*step, GateStep::Timeout);
                }
            }
        }
    }
}
