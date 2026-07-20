//! Manually driven [`RefreshHintSource`] fake.

use core::task::{Poll, Waker};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::seams::{RefreshHint, RefreshHintSource};

#[derive(Default)]
struct Inner {
    queue: VecDeque<RefreshHint>,
    wakers: Vec<Waker>,
    closed: bool,
}

/// A hint source the test drives by hand: [`push_hint`] delivers one hint,
/// [`close`] ends the stream.
///
/// [`push_hint`]: ManualHintSource::push_hint
/// [`close`]: ManualHintSource::close
#[derive(Clone, Default)]
pub struct ManualHintSource {
    inner: Arc<Mutex<Inner>>,
}

impl ManualHintSource {
    /// Delivers one refresh hint to the listener.
    pub fn push_hint(&self) {
        let woken: Vec<Waker> = {
            let mut inner = self.inner.lock().expect("lock");
            inner.queue.push_back(RefreshHint);
            std::mem::take(&mut inner.wakers)
        };
        for waker in woken {
            waker.wake();
        }
    }

    /// Closes the stream: pending and future `next_hint` calls resolve to
    /// `None` once the queue drains.
    pub fn close(&self) {
        let woken: Vec<Waker> = {
            let mut inner = self.inner.lock().expect("lock");
            inner.closed = true;
            std::mem::take(&mut inner.wakers)
        };
        for waker in woken {
            waker.wake();
        }
    }
}

impl RefreshHintSource for ManualHintSource {
    async fn next_hint(&mut self) -> Option<RefreshHint> {
        core::future::poll_fn(|cx| {
            let mut inner = self.inner.lock().expect("lock");
            if let Some(hint) = inner.queue.pop_front() {
                return Poll::Ready(Some(hint));
            }
            if inner.closed {
                return Poll::Ready(None);
            }
            inner.wakers.push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;

    #[test]
    fn queued_hints_are_delivered_then_close_ends_the_stream() {
        let source = ManualHintSource::default();
        source.push_hint();
        source.push_hint();
        source.close();

        let mut listener = source.clone();
        assert_eq!(block_on(listener.next_hint()), Some(RefreshHint));
        assert_eq!(block_on(listener.next_hint()), Some(RefreshHint));
        assert_eq!(block_on(listener.next_hint()), None);
    }

    #[test]
    fn push_wakes_a_parked_listener() {
        let source = ManualHintSource::default();
        let mut listener = source.clone();

        let pusher = {
            let source = source.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(10));
                source.push_hint();
            })
        };

        assert_eq!(block_on(listener.next_hint()), Some(RefreshHint));
        pusher.join().expect("pusher thread");
    }
}
