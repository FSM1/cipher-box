//! The virtual-clock [`Scheduler`] fake.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::sync::{Arc, Mutex};

use crate::seams::{BoxedTask, Scheduler, UnixMillis};

/// One parked sleep: its deadline, the identity of the owning
/// [`SleepFuture`], and the waker from its latest poll.
struct Sleeper {
    deadline: UnixMillis,
    sleep_id: u64,
    waker: Waker,
}

struct Inner {
    now: UnixMillis,
    auto_advance: bool,
    next_sleep_id: u64,
    sleepers: Vec<Sleeper>,
    tasks: Vec<BoxedTask>,
}

impl Inner {
    /// Moves the clock to `target` (never backwards) and takes the wakers
    /// of every sleep whose deadline has been reached. The caller wakes
    /// them outside the lock.
    fn advance_and_take_due(&mut self, target: UnixMillis) -> Vec<Waker> {
        self.now = self.now.max(target);
        let now = self.now;
        let (due, pending): (Vec<_>, Vec<_>) = std::mem::take(&mut self.sleepers)
            .into_iter()
            .partition(|sleeper| sleeper.deadline <= now);
        self.sleepers = pending;
        due.into_iter().map(|sleeper| sleeper.waker).collect()
    }

    /// Registers (or, on a re-poll of the same future, replaces) the parked
    /// waker for one sleep — one entry per live [`SleepFuture`], so
    /// re-polling never accumulates duplicates and only the latest waker
    /// fires (the futures contract).
    fn park(&mut self, sleep_id: u64, deadline: UnixMillis, waker: Waker) {
        match self
            .sleepers
            .iter_mut()
            .find(|sleeper| sleeper.sleep_id == sleep_id)
        {
            Some(sleeper) => sleeper.waker = waker,
            None => self.sleepers.push(Sleeper {
                deadline,
                sleep_id,
                waker,
            }),
        }
    }
}

/// A deterministic virtual clock: time moves only when a test advances it.
///
/// Clones share the same clock, so every device in a [`super::super::FakeWorld`]
/// steps on one timeline. Two modes:
///
/// - **Manual** (default): `sleep` parks until [`advance`] /
///   [`advance_to`] moves virtual time past its deadline — the simulation
///   harness's stepping lever.
/// - **Auto-advance** ([`with_auto_advance`]): a polled sleep immediately
///   jumps the clock to its own deadline and resolves — multi-day
///   timelines execute in microseconds with no external driver.
///
/// [`advance`]: VirtualScheduler::advance
/// [`advance_to`]: VirtualScheduler::advance_to
/// [`with_auto_advance`]: VirtualScheduler::with_auto_advance
#[derive(Clone)]
pub struct VirtualScheduler {
    inner: Arc<Mutex<Inner>>,
}

impl VirtualScheduler {
    /// A manual-mode clock starting at `UnixMillis(0)`.
    pub fn new() -> Self {
        Self::starting_at(UnixMillis(0))
    }

    /// A manual-mode clock starting at an arbitrary instant.
    // `BoxedTask` is deliberately `!Send` (the engine runs pinned to one
    // execution context), which makes `Mutex<Inner>` `!Send + !Sync`; the
    // `Arc` exists only for same-thread handle cloning, matching how every
    // fake models "one shared backing".
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn starting_at(now: UnixMillis) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                now,
                auto_advance: false,
                next_sleep_id: 0,
                sleepers: Vec::new(),
                tasks: Vec::new(),
            })),
        }
    }

    /// Switches this clock (and every clone of it) to auto-advance mode.
    #[must_use]
    pub fn with_auto_advance(self) -> Self {
        self.inner.lock().expect("lock").auto_advance = true;
        self
    }

    /// Moves virtual time forward by `duration`, waking every sleep whose
    /// deadline is reached.
    pub fn advance(&self, duration: Duration) {
        let target = self.now().saturating_add(duration);
        self.advance_to(target);
    }

    /// Moves virtual time to `instant` (never backwards), waking every
    /// sleep whose deadline is reached.
    pub fn advance_to(&self, instant: UnixMillis) {
        let woken = self
            .inner
            .lock()
            .expect("lock")
            .advance_and_take_due(instant);
        for waker in woken {
            waker.wake();
        }
    }

    /// Takes every task handed to [`Scheduler::spawn`] so far; the test
    /// decides when (and whether) to drive them.
    pub fn take_spawned_tasks(&self) -> Vec<BoxedTask> {
        std::mem::take(&mut self.inner.lock().expect("lock").tasks)
    }

    /// How many sleeps are currently parked (manual mode introspection).
    pub fn pending_sleepers(&self) -> usize {
        self.inner.lock().expect("lock").sleepers.len()
    }
}

impl Default for VirtualScheduler {
    fn default() -> Self {
        Self::new()
    }
}

struct SleepFuture {
    scheduler: VirtualScheduler,
    deadline: UnixMillis,
    /// Identity in `Inner::sleepers`, assigned on first park so a re-poll
    /// replaces this future's waker instead of accumulating duplicates.
    sleep_id: Option<u64>,
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let woken: Vec<Waker>;
        let result = {
            let mut inner = this.scheduler.inner.lock().expect("lock");
            if inner.now >= this.deadline {
                woken = Vec::new();
                Poll::Ready(())
            } else if inner.auto_advance {
                woken = inner.advance_and_take_due(this.deadline);
                Poll::Ready(())
            } else {
                let sleep_id = *this.sleep_id.get_or_insert_with(|| {
                    let id = inner.next_sleep_id;
                    inner.next_sleep_id += 1;
                    id
                });
                inner.park(sleep_id, this.deadline, cx.waker().clone());
                woken = Vec::new();
                Poll::Pending
            }
        };
        for waker in woken {
            waker.wake();
        }
        result
    }
}

impl Scheduler for VirtualScheduler {
    fn now(&self) -> UnixMillis {
        self.inner.lock().expect("lock").now
    }

    async fn sleep(&self, duration: Duration) {
        let deadline = self.now().saturating_add(duration);
        SleepFuture {
            scheduler: self.clone(),
            deadline,
            sleep_id: None,
        }
        .await;
    }

    fn spawn(&self, task: BoxedTask) {
        self.inner.lock().expect("lock").tasks.push(task);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::pin::pin;

    fn noop_context() -> Context<'static> {
        Context::from_waker(Waker::noop())
    }

    #[test]
    fn manual_sleep_parks_until_advanced() {
        let scheduler = VirtualScheduler::new();
        let mut sleep = pin!(scheduler.sleep(Duration::from_millis(100)));
        let mut cx = noop_context();

        assert!(sleep.as_mut().poll(&mut cx).is_pending());
        scheduler.advance(Duration::from_millis(99));
        assert!(sleep.as_mut().poll(&mut cx).is_pending());
        scheduler.advance(Duration::from_millis(1));
        assert!(sleep.as_mut().poll(&mut cx).is_ready());
        assert_eq!(scheduler.now(), UnixMillis(100));
    }

    #[test]
    fn advance_wakes_registered_sleepers() {
        use crate::testkit::executor::FlagWaker;

        let scheduler = VirtualScheduler::new();
        let flag = FlagWaker::new();
        let waker = Waker::from(Arc::clone(&flag));
        let mut cx = Context::from_waker(&waker);

        let mut sleep = pin!(scheduler.sleep(Duration::from_millis(10)));
        assert!(sleep.as_mut().poll(&mut cx).is_pending());
        assert_eq!(scheduler.pending_sleepers(), 1);

        scheduler.advance(Duration::from_millis(10));
        assert!(flag.fired(), "advance must wake the sleeper");
        assert!(sleep.as_mut().poll(&mut cx).is_ready());
        assert_eq!(scheduler.pending_sleepers(), 0);
    }

    #[test]
    fn repolling_one_sleep_registers_exactly_one_sleeper() {
        let scheduler = VirtualScheduler::new();
        let mut sleep = pin!(scheduler.sleep(Duration::from_millis(100)));
        let mut cx = noop_context();

        assert!(sleep.as_mut().poll(&mut cx).is_pending());
        scheduler.advance(Duration::from_millis(50));
        assert!(sleep.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            scheduler.pending_sleepers(),
            1,
            "a re-poll must replace the parked waker, not accumulate"
        );
    }

    #[test]
    fn two_sleeps_sharing_a_deadline_both_wake() {
        let scheduler = VirtualScheduler::new();
        let mut cx = noop_context();
        let mut sleep_a = pin!(scheduler.sleep(Duration::from_millis(10)));
        let mut sleep_b = pin!(scheduler.sleep(Duration::from_millis(10)));

        assert!(sleep_a.as_mut().poll(&mut cx).is_pending());
        assert!(sleep_b.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            scheduler.pending_sleepers(),
            2,
            "distinct futures park separately"
        );

        scheduler.advance(Duration::from_millis(10));
        assert!(sleep_a.as_mut().poll(&mut cx).is_ready());
        assert!(sleep_b.as_mut().poll(&mut cx).is_ready());
        assert_eq!(scheduler.pending_sleepers(), 0);
    }

    #[test]
    fn auto_advance_resolves_multi_day_sleeps_instantly() {
        let scheduler = VirtualScheduler::new().with_auto_advance();
        crate::testkit::block_on(scheduler.sleep(Duration::from_secs(90 * 24 * 3600)));
        assert_eq!(scheduler.now(), UnixMillis(90 * 24 * 3600 * 1000));
    }

    #[test]
    fn spawn_queues_tasks_for_the_test_to_drive() {
        let scheduler = VirtualScheduler::new();
        scheduler.spawn(Box::pin(async {}));
        scheduler.spawn(Box::pin(async {}));
        assert_eq!(scheduler.take_spawned_tasks().len(), 2);
        assert!(scheduler.take_spawned_tasks().is_empty());
    }

    #[test]
    fn clones_share_one_timeline() {
        let a = VirtualScheduler::starting_at(UnixMillis(1_000));
        let b = a.clone();
        b.advance(Duration::from_millis(500));
        assert_eq!(a.now(), UnixMillis(1_500));
    }
}
