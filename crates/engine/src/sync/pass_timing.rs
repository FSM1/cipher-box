//! Each leg of a sync pass as it ends, for a host that asks
//! ([`Engine::with_pass_timings`](crate::Engine::with_pass_timings)).
//!
//! Read off the scheduler clock seam. An event names a leg and a duration only
//! (`cipherbox_desktop_seams::Timed` states the rule for the host log).

use std::rc::Rc;

use crate::seams::UnixMillis;

use super::TickCause;

/// The legs of [`TickPass::run`](crate::sync::pass::TickPass), in the order
/// they run.
pub const PASS_LEGS: [&str; 13] = [
    "settings",
    "scope-pointers",
    "received-pointers",
    "floors",
    "root",
    "scope-walk",
    "focus",
    "assembly",
    "drain",
    "mailbox",
    "claims",
    "claim-repost",
    "received-shares",
];

/// One step of one pass, sent when it happens: a pass that never ends still
/// shows the leg it is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassEvent {
    /// A pass began. Its first leg is `PASS_LEGS[0]`.
    Started {
        /// This session's pass count, from 1.
        pass: u64,
        /// What woke the pass.
        cause: TickCause,
    },
    /// One leg ended.
    LegEnded {
        /// The pass it belongs to.
        pass: u64,
        /// The leg that ended.
        leg: &'static str,
        /// How long it ran, in milliseconds.
        millis: u64,
        /// The leg that runs now; `None` when the pass ended.
        next: Option<&'static str>,
    },
}

/// Where a host takes each [`PassEvent`].
pub type PassTimingSink = Rc<dyn Fn(&PassEvent)>;

/// The laps of one pass, against the clock readings its caller takes.
pub(crate) struct LegClock<'a> {
    sink: &'a PassTimingSink,
    pass: u64,
    at: UnixMillis,
    leg: usize,
}

impl<'a> LegClock<'a> {
    pub(crate) fn start(
        sink: &'a PassTimingSink,
        pass: u64,
        cause: TickCause,
        now: UnixMillis,
    ) -> Self {
        sink(&PassEvent::Started { pass, cause });
        Self {
            sink,
            pass,
            at: now,
            leg: 0,
        }
    }

    /// Ends the current leg at `now`. A clock that steps back counts the leg
    /// as zero; a lap past the last leg sends nothing.
    pub(crate) fn lap(&mut self, now: UnixMillis) {
        let Some(leg) = PASS_LEGS.get(self.leg) else {
            return;
        };
        self.leg += 1;
        (self.sink)(&PassEvent::LegEnded {
            pass: self.pass,
            leg,
            millis: now.0.saturating_sub(self.at.0),
            next: PASS_LEGS.get(self.leg).copied(),
        });
        self.at = now;
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use super::*;

    #[test]
    fn each_lap_is_sent_as_it_ends_and_names_the_leg_after_it() {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let into = seen.clone();
        let sink: PassTimingSink = Rc::new(move |event: &PassEvent| into.borrow_mut().push(*event));

        let mut clock = LegClock::start(&sink, 3, TickCause::Manual, UnixMillis(1_000));
        clock.lap(UnixMillis(1_250));
        clock.lap(UnixMillis(1_200));
        assert_eq!(
            *seen.borrow(),
            [
                PassEvent::Started {
                    pass: 3,
                    cause: TickCause::Manual
                },
                PassEvent::LegEnded {
                    pass: 3,
                    leg: "settings",
                    millis: 250,
                    next: Some("scope-pointers")
                },
                PassEvent::LegEnded {
                    pass: 3,
                    leg: "scope-pointers",
                    millis: 0,
                    next: Some("received-pointers")
                },
            ]
        );

        for _ in 2..=PASS_LEGS.len() {
            clock.lap(UnixMillis(2_000));
        }
        assert_eq!(seen.borrow().len(), 1 + PASS_LEGS.len());
        assert_eq!(
            seen.borrow().last(),
            Some(&PassEvent::LegEnded {
                pass: 3,
                leg: "received-shares",
                millis: 0,
                next: None
            })
        );
    }
}
