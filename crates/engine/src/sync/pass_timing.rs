//! How long each leg of a sync pass ran, for a host that asks
//! ([`Engine::with_pass_timings`](crate::Engine::with_pass_timings)).
//!
//! Read off the scheduler clock seam, so the engine reads no clock of its own.
//! A report names legs and durations only: no name, key, CID or token.

use std::rc::Rc;

use crate::seams::UnixMillis;

use super::TickCause;

/// One pass's leg durations, in the order the legs ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassTimings {
    /// What woke the pass.
    pub cause: TickCause,
    /// Each leg's label and its duration in milliseconds.
    pub legs: Vec<(&'static str, u64)>,
}

impl PassTimings {
    /// The whole pass, in milliseconds.
    #[must_use]
    pub fn total_ms(&self) -> u64 {
        self.legs.iter().map(|(_, ms)| ms).sum()
    }
}

/// Where a host takes each pass's [`PassTimings`].
pub type PassTimingSink = Rc<dyn Fn(&PassTimings)>;

/// The laps of one pass, against the clock readings its caller takes.
pub(crate) struct LegClock {
    at: UnixMillis,
    timings: PassTimings,
}

impl LegClock {
    pub(crate) fn start(cause: TickCause, now: UnixMillis) -> Self {
        Self {
            at: now,
            timings: PassTimings {
                cause,
                legs: Vec::new(),
            },
        }
    }

    /// Ends `leg` at `now`. A clock that steps back counts the leg as zero.
    pub(crate) fn lap(&mut self, leg: &'static str, now: UnixMillis) {
        self.timings
            .legs
            .push((leg, now.0.saturating_sub(self.at.0)));
        self.at = now;
    }

    pub(crate) fn finish(self) -> PassTimings {
        self.timings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_lap_measures_from_the_end_of_the_leg_before_it() {
        let mut clock = LegClock::start(TickCause::Manual, UnixMillis(1_000));
        clock.lap("root", UnixMillis(1_250));
        clock.lap("focus", UnixMillis(31_250));
        clock.lap("drain", UnixMillis(31_200));
        let timings = clock.finish();

        assert_eq!(
            timings.legs,
            vec![("root", 250), ("focus", 30_000), ("drain", 0)]
        );
        assert_eq!(timings.total_ms(), 30_250);
        assert_eq!(timings.cause, TickCause::Manual);
    }
}
