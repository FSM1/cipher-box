//! A minimal single-future executor for native test processes.

use std::future::{Future, IntoFuture};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use crate::seams::BoxedTask;

const MAX_POLL_PASSES: usize = 10_000;

struct ThreadWaker(Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Drives one future to completion on the current thread.
///
/// Enough executor for the whole test kit — fakes never touch real timers
/// or I/O, so nothing needs a runtime. Native test processes only; WASM
/// hosts (the browser suite) await kit futures on their own harness
/// instead.
pub fn block_on<F: IntoFuture>(future: F) -> F::Output {
    let mut future = pin!(future.into_future());
    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::park(),
        }
    }
}

/// A waker that records only that it fired — enough to tell a cooperative
/// yield (which wakes itself) from a parked sleep (which does not).
pub(crate) struct FlagWaker(AtomicBool);

impl FlagWaker {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(AtomicBool::new(false)))
    }

    pub(crate) fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }

    pub(crate) fn fired(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Wake for FlagWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Poll every spawned loop exactly once, leaving a yielded pass mid-flight,
/// and report each loop's verdict.
///
/// The waker is a no-op so the caller owns every step: a manual re-poll is what
/// drives the virtual clock's parked sleeps.
pub fn poll_tasks_once(tasks: &mut [BoxedTask]) -> Vec<Poll<()>> {
    let mut cx = Context::from_waker(Waker::noop());
    tasks.iter_mut().map(|t| t.as_mut().poll(&mut cx)).collect()
}

/// Poll every spawned loop until each parks on a timer rather than on a
/// cooperative yield — the fixpoint one scheduler tick settles at.
pub fn poll_tasks_until_parked(tasks: &mut [BoxedTask]) {
    let flag = FlagWaker::new();
    let waker = Waker::from(Arc::clone(&flag));
    let mut cx = Context::from_waker(&waker);
    // A loop that never parks is a bug in the loop, not a slow fixpoint; bound
    // the search so the suite reports it instead of hanging out to a CI timeout.
    for _ in 0..MAX_POLL_PASSES {
        flag.reset();
        for task in tasks.iter_mut() {
            let _ = task.as_mut().poll(&mut cx);
        }
        if !flag.fired() {
            return;
        }
    }
    panic!("tasks kept self-waking after {MAX_POLL_PASSES} polling passes");
}

#[cfg(test)]
mod tests {
    use super::{BoxedTask, Poll, block_on, poll_tasks_until_parked};

    fn self_waking_task() -> BoxedTask {
        Box::pin(std::future::poll_fn(|cx| {
            cx.waker().wake_by_ref();
            Poll::Pending
        }))
    }

    #[test]
    fn returns_once_every_task_parks() {
        let mut tasks: Vec<BoxedTask> = vec![Box::pin(std::future::pending())];
        poll_tasks_until_parked(&mut tasks);
    }

    #[test]
    #[should_panic(expected = "kept self-waking")]
    fn bounds_a_task_that_never_parks() {
        let mut tasks = vec![self_waking_task()];
        poll_tasks_until_parked(&mut tasks);
    }

    #[test]
    fn drives_a_ready_future() {
        assert_eq!(block_on(async { 41 + 1 }), 42);
    }

    #[test]
    fn survives_cross_thread_wakes() {
        let out = block_on(async {
            let (tx, rx) = futures_channel::oneshot::channel::<u32>();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(10));
                tx.send(7).expect("receiver alive");
            });
            rx.await.expect("sender completed")
        });
        assert_eq!(out, 7);
    }
}
