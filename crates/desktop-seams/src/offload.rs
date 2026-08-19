//! Moving a blocking host call off the engine's executor thread, in order.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;

use cipherbox_engine::seams::{SeamError, SeamResult};
use futures_channel::oneshot;
use zeroize::Zeroize;

/// A worker result whose caller may never take it. The worker thread is then
/// the value's last owner, so it wipes any secret bytes there — zeroize at the
/// terminal owner, never in a callee holding a caller's buffer.
pub(crate) trait WipeUndelivered {
    /// Wipes the value. Called only when no receiver took it.
    fn wipe_undelivered(&mut self);
}

impl WipeUndelivered for () {
    fn wipe_undelivered(&mut self) {}
}

impl WipeUndelivered for Option<Vec<u8>> {
    fn wipe_undelivered(&mut self) {
        self.zeroize();
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// One worker thread draining a queue: submitted work runs off the calling
/// executor **and in submission order**.
///
/// The engine is a single-writer brain on a current-thread executor with
/// `!Send` futures (blueprint/engine.md), so a seam body that blocks freezes
/// every timer and sync tick until it returns. An OS keyring call can block on
/// a user-facing unlock prompt, which is unbounded.
///
/// Order is a security property, not an optimization: a credential write still
/// waiting on an unlock prompt must never land after the logout delete that was
/// issued later. A queue gives that unconditionally — the position is held by
/// the queue, so a caller whose future is dropped mid-flight neither cancels its
/// work nor lets a later submission overtake it.
///
/// A thread rather than a blocking pool: the seam conformance kits drive this
/// under an executor that has none, and keyring calls happen only at login and
/// token rotation.
#[derive(Debug)]
pub(crate) struct Offload {
    jobs: mpsc::Sender<Job>,
}

impl Offload {
    /// Starts the worker thread. `name` labels the thread and its errors.
    pub(crate) fn start(name: &'static str) -> SeamResult<Self> {
        let (jobs, queue) = mpsc::channel::<Job>();
        // Builder, not `thread::spawn`: a refused thread is an `Err` the caller
        // can surface, never a panic that unwinds the engine's serve loop.
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                while let Ok(job) = queue.recv() {
                    job();
                }
            })
            .map_err(|err| SeamError::new(format!("{name}: spawn worker thread: {err}")))?;
        Ok(Self { jobs })
    }

    /// Queues `work` and yields its result. Queueing happens here rather than on
    /// first poll, so call order is execution order.
    pub(crate) fn run<T, F>(
        &self,
        what: &'static str,
        work: F,
    ) -> impl Future<Output = SeamResult<T>> + use<T, F>
    where
        T: WipeUndelivered + Send + 'static,
        F: FnOnce() -> SeamResult<T> + Send + 'static,
    {
        let (sender, receiver) = oneshot::channel();
        let queued = self.jobs.send(Box::new(move || {
            // One job's panic must not take the shared worker down with it.
            let outcome = catch_unwind(AssertUnwindSafe(work))
                .unwrap_or_else(|_| Err(SeamError::new(format!("{what}: the worker panicked"))));
            if let Err(Ok(mut undelivered)) = sender.send(outcome) {
                undelivered.wipe_undelivered();
            }
        }));
        async move {
            queued.map_err(|_| SeamError::new(format!("{what}: the worker thread is gone")))?;
            receiver
                .await
                .map_err(|_| SeamError::new(format!("{what}: the worker ended without a result")))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Offload, WipeUndelivered};
    use cipherbox_engine::testkit::block_on;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;

    /// Records that the worker wiped a result nobody took.
    struct WipeProbe {
        wiped: Arc<AtomicBool>,
    }

    impl WipeUndelivered for WipeProbe {
        fn wipe_undelivered(&mut self) {
            self.wiped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn the_work_runs_off_the_calling_thread() {
        let caller = thread::current().id();
        let (sender, receiver) = mpsc::channel();
        let offload = Offload::start("probe").expect("worker started");

        let value = block_on(offload.run("probe", move || {
            sender.send(thread::current().id()).expect("receiver alive");
            Ok(Some(vec![7u8]))
        }))
        .expect("work completed");

        assert_eq!(value, Some(vec![7u8]));
        assert_ne!(receiver.recv().expect("worker reported"), caller);
    }

    #[test]
    fn an_error_from_the_work_reaches_the_caller() {
        let offload = Offload::start("probe").expect("worker started");
        let error = block_on(offload.run::<(), _>("probe", || {
            Err(cipherbox_engine::seams::SeamError::new("no such entry"))
        }))
        .expect_err("work failed");
        assert!(error.to_string().contains("no such entry"), "{error}");
    }

    #[test]
    fn a_panicking_work_body_fails_the_call_instead_of_hanging_it() {
        let offload = Offload::start("probe").expect("worker started");
        let error = block_on(offload.run::<(), _>("probe", || panic!("keyring exploded")))
            .expect_err("panic surfaced as a seam error");
        assert!(error.to_string().contains("probe"), "{error}");

        // The queue outlives the panic, so a later submission still runs.
        block_on(offload.run("probe", || Ok(()))).expect("worker survived");
    }

    #[test]
    fn a_dropped_caller_neither_cancels_its_work_nor_yields_its_place() {
        let offload = Offload::start("probe").expect("worker started");
        let (release, held) = mpsc::channel::<()>();
        let order = Arc::new(Mutex::new(Vec::new()));

        let first = offload.run("first", {
            let order = Arc::clone(&order);
            move || {
                held.recv().expect("release signal");
                order.lock().expect("order").push("first");
                Ok(())
            }
        });
        let second = offload.run("second", {
            let order = Arc::clone(&order);
            move || {
                order.lock().expect("order").push("second");
                Ok(())
            }
        });

        // The first caller goes away while the host call is still blocked, as a
        // seam future cancelled by logout or quit does.
        drop(first);
        release.send(()).expect("worker waiting");
        block_on(second).expect("second ran");

        assert_eq!(*order.lock().expect("order"), ["first", "second"]);
    }

    #[test]
    fn a_result_no_caller_took_is_wiped_on_the_worker() {
        let offload = Offload::start("probe").expect("worker started");
        let (release, held) = mpsc::channel::<()>();
        let wiped = Arc::new(AtomicBool::new(false));

        let pending = offload.run("load", {
            let wiped = Arc::clone(&wiped);
            move || {
                held.recv().expect("release signal");
                Ok(WipeProbe { wiped })
            }
        });
        drop(pending);
        release.send(()).expect("worker waiting");

        // FIFO: this result proves the abandoned job already ran to completion.
        block_on(offload.run("fence", || Ok(()))).expect("fence ran");
        assert!(
            wiped.load(Ordering::SeqCst),
            "the orphaned result was wiped"
        );
    }

    #[test]
    fn wiping_a_loaded_secret_drops_its_bytes() {
        let mut loaded = Some(b"fixture-token".to_vec());
        loaded.wipe_undelivered();
        assert_eq!(loaded, None);
    }
}
