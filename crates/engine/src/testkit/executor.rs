//! A minimal single-future executor for native test processes.

use std::future::{Future, IntoFuture};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

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
