//! The caller-side bound every rotation runs under.
//!
//! A rotation failure's own classifier answers *could a retry clear this*, and
//! several of them answer yes to a verdict that need never clear: a cross-parent
//! `scope_id`-to-`ipns_name` disagreement is retryable because the write-rotation
//! re-point wave repairs both parent indexes, but a permanent or adversarial one
//! never self-heals. Classification alone therefore admits a livelock; the bound
//! is the other half of the contract, and it lives here rather than at each
//! caller so there is one of it (the lazy wave's own bound is
//! [`run_sweep`](super::sweep::run_sweep)).

use core::time::Duration;

use super::cascade::CascadeError;
use super::rotate::RotateError;
use super::rotate_write::WriteRotateError;
use super::trigger::RotateOnCutError;
use crate::seams::Scheduler;

/// How many times a rotation is re-driven on a retryable verdict before the
/// caller reports a terminal failure.
pub const MAX_ROTATION_ATTEMPTS: u32 = 3;

/// A rotation failure that classifies itself on the retryable-vs-trust axis
/// (AGENTS.md rule 6), so [`bounded`] never re-drives a verdict.
pub trait Retryable {
    /// Whether re-running the rotation could clear this failure.
    fn is_retryable(&self) -> bool;
}

macro_rules! retryable {
    ($($error:ty),+ $(,)?) => {
        $(impl Retryable for $error {
            fn is_retryable(&self) -> bool {
                <$error>::is_retryable(self)
            }
        })+
    };
}

retryable!(
    RotateError,
    RotateOnCutError,
    CascadeError,
    WriteRotateError
);

/// Re-drive `attempt` while it fails with a verdict its own classifier calls
/// retryable, at most `max_attempts` times, spacing attempts on `scheduler`.
///
/// The last verdict is returned rather than a bound-specific error: a caller
/// that has exhausted the bound still owes its host the reason, and a permanent
/// label conflict reads the same at attempt one and attempt three.
pub async fn bounded<S, V, E, A>(
    scheduler: &S,
    cadence: Duration,
    max_attempts: u32,
    mut attempt: A,
) -> Result<V, E>
where
    S: Scheduler,
    E: Retryable,
    A: AsyncFnMut() -> Result<V, E>,
{
    let mut attempts = 1u32;
    loop {
        match attempt().await {
            Err(e) if e.is_retryable() && attempts < max_attempts => {
                attempts += 1;
                scheduler.sleep(cadence).await;
            }
            settled => return settled,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    use super::super::eager_set::ResolveFailure;
    use super::*;
    use crate::testkit::fakes::VirtualScheduler;

    const CADENCE: Duration = Duration::from_secs(1);

    /// Drives `attempt` to completion against `scheduler`'s virtual clock, which
    /// is what wakes the spacing between attempts.
    fn settle<V, E: Retryable>(
        scheduler: &VirtualScheduler,
        attempt: impl AsyncFnMut() -> Result<V, E>,
    ) -> Result<V, E> {
        let mut rotation = pin!(bounded(scheduler, CADENCE, MAX_ROTATION_ATTEMPTS, attempt));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..(MAX_ROTATION_ATTEMPTS + 2) {
            if let Poll::Ready(settled) = rotation.as_mut().poll(&mut cx) {
                return settled;
            }
            scheduler.advance(CADENCE);
        }
        panic!("the rotation never settled inside its own retry bound");
    }

    /// A cross-parent label disagreement is classified retryable because the
    /// re-point wave repairs it — but a permanent one never self-heals, so an
    /// unbounded caller would spin on it forever. The bound is what turns it into
    /// a terminal failure the host is told about.
    #[test]
    fn a_permanent_label_conflict_stops_at_the_retry_bound() {
        let scheduler = VirtualScheduler::default();
        let attempts = Cell::new(0u32);
        let conflict = RotateError::Resolve(ResolveFailure::ConflictingChildLabel);

        let settled = settle(&scheduler, async || {
            attempts.set(attempts.get() + 1);
            Err::<(), RotateError>(conflict.clone())
        });

        assert_eq!(settled, Err(conflict), "the caller surfaces the verdict");
        assert_eq!(
            attempts.get(),
            MAX_ROTATION_ATTEMPTS,
            "the bound is what ends the livelock, not the verdict itself"
        );
    }

    /// A gate rejection is a trust verdict no retry can clear, so it is surfaced
    /// on the first attempt rather than spent against the bound.
    #[test]
    fn a_rejected_record_is_never_retried() {
        let scheduler = VirtualScheduler::default();
        let attempts = Cell::new(0u32);

        let settled = settle(&scheduler, async || {
            attempts.set(attempts.get() + 1);
            Err::<(), RotateError>(RotateError::Resolve(ResolveFailure::Rejected))
        });

        assert!(settled.is_err());
        assert_eq!(attempts.get(), 1, "a trust verdict is not an outage");
    }

    /// A stall that clears inside the bound converges: the bound caps a
    /// livelock, it does not cap recovery.
    #[test]
    fn a_transient_stall_converges_inside_the_retry_bound() {
        let scheduler = VirtualScheduler::default();
        let attempts = Cell::new(0u32);

        let settled = settle(&scheduler, async || {
            attempts.set(attempts.get() + 1);
            match attempts.get() {
                1 => Err(RotateError::Resolve(ResolveFailure::Unavailable)),
                _ => Ok(()),
            }
        });

        assert_eq!(settled, Ok(()));
        assert_eq!(attempts.get(), 2);
    }
}
