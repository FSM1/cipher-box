//! `Scheduler` — timers, background tasks, wall clock (blueprint/engine.md).

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

/// Milliseconds since the Unix epoch, as reported by the host wall clock
/// (or the virtual clock in tests). Journaled verbatim on an intent op's
/// `authored_at`, hence serializable.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct UnixMillis(pub u64);

impl UnixMillis {
    /// This instant advanced by `duration`, saturating at the maximum.
    /// Sub-millisecond remainders round **up**, so a non-zero duration
    /// always advances the instant (a deadline never truncates to "now").
    pub fn saturating_add(self, duration: Duration) -> Self {
        let millis = u64::try_from(duration.as_nanos().div_ceil(1_000_000)).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(millis))
    }
}

/// A boxed background task handed to [`Scheduler::spawn`].
///
/// Deliberately not `Send`: the engine is the single writer and runs pinned
/// to one execution context on every host (the worker on web, a
/// single-threaded task context on desktop), so seam futures never cross
/// threads and the same code compiles to WASM unchanged.
pub type BoxedTask = Pin<Box<dyn Future<Output = ()> + 'static>>;

/// Jittered timers, background task execution, and the wall clock.
///
/// The only source of time in the engine (determinism law): timestamps for
/// core's pure functions come from [`Scheduler::now`], delays from
/// [`Scheduler::sleep`]. Jitter is computed by the engine from injected
/// entropy — hosts sleep exactly the duration asked. Hosts: worker timers
/// (web, coarse throttling tolerated), tokio (desktop); the test kit ships
/// a virtual clock.
pub trait Scheduler {
    /// Current wall-clock time.
    fn now(&self) -> UnixMillis;

    /// Resolves after at least `duration` of host time has passed.
    async fn sleep(&self, duration: Duration);

    /// Runs a background task to completion on the engine's execution
    /// context. Fire-and-forget: completion is observed only through the
    /// task's own effects.
    fn spawn(&self, task: BoxedTask);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturating_add_rounds_sub_millisecond_durations_up() {
        let base = UnixMillis(10);
        assert_eq!(base.saturating_add(Duration::ZERO), UnixMillis(10));
        assert_eq!(
            base.saturating_add(Duration::from_micros(1)),
            UnixMillis(11),
            "a non-zero duration must advance the instant"
        );
        assert_eq!(
            base.saturating_add(Duration::from_micros(1_500)),
            UnixMillis(12)
        );
        assert_eq!(
            UnixMillis(u64::MAX).saturating_add(Duration::from_secs(1)),
            UnixMillis(u64::MAX)
        );
    }
}
