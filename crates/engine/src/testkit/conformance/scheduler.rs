//! Conformance kit: [`Scheduler`] clock/timer coherence.

use core::time::Duration;

use crate::seams::Scheduler;

/// Runs the `Scheduler` contract against an implementation.
///
/// Works for real schedulers and the virtual clock alike; run the virtual
/// clock in auto-advance mode (nothing else drives time inside the kit).
/// `spawn` is fire-and-forget by contract, so the kit only asserts it
/// accepts a task — execution semantics are host-suite territory.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<S>(scheduler: &S)
where
    S: Scheduler,
{
    let before = scheduler.now();

    // A zero sleep resolves.
    scheduler.sleep(Duration::ZERO).await;

    // A real sleep resolves and the clock never runs backwards across it.
    scheduler.sleep(Duration::from_millis(25)).await;
    let after = scheduler.now();
    assert!(
        after >= before,
        "the clock must not run backwards across a sleep"
    );

    scheduler.spawn(Box::pin(async {}));
}
