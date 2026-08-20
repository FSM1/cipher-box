//! A minimal single-future executor for native test processes.

use std::future::{Future, IntoFuture};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use crate::seams::BoxedTask;

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
/// The waker is a no-op, so nothing self-wakes and the caller owns every step:
/// a manual re-poll is what drives the virtual clock's parked sleeps, and an
/// auto-advancing driver would spin a loop that yields inside a pass.
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
    loop {
        flag.reset();
        for task in tasks.iter_mut() {
            let _ = task.as_mut().poll(&mut cx);
        }
        if !flag.fired() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::block_on;

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
