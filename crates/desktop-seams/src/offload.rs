//! Moving a blocking host call off the engine's executor thread.

use cipherbox_engine::seams::{SeamError, SeamResult};
use futures_channel::oneshot;

/// Runs `work` on a worker thread and awaits its result.
///
/// The engine is a single-writer brain on a current-thread executor with
/// `!Send` futures (blueprint/engine.md), so a seam body that blocks freezes
/// every timer and sync tick until it returns. An OS keyring call can block on
/// a user-facing unlock prompt, which is unbounded.
///
/// A thread per call rather than a blocking pool: the seam conformance kits
/// drive this under an executor that has none, and keyring calls happen only
/// at login and token rotation. The work is detached — dropping the returned
/// future does not cancel it.
pub(crate) async fn off_thread<T, F>(what: &'static str, work: F) -> SeamResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> SeamResult<T> + Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    // Builder, not `thread::spawn`: a refused thread is an `Err` the caller can
    // surface, never a panic that unwinds the engine's serve loop.
    std::thread::Builder::new()
        .name(what.to_owned())
        .spawn(move || {
            let _ = sender.send(work());
        })
        .map_err(|err| SeamError::new(format!("{what}: spawn worker thread: {err}")))?;
    match receiver.await {
        Ok(result) => result,
        Err(_) => Err(SeamError::new(format!(
            "{what}: the worker thread ended without a result"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::off_thread;
    use cipherbox_engine::testkit::block_on;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn the_work_runs_off_the_calling_thread() {
        let caller = thread::current().id();
        let (sender, receiver) = mpsc::channel();

        let value = block_on(off_thread("probe", move || {
            sender.send(thread::current().id()).expect("receiver alive");
            Ok(7u32)
        }))
        .expect("work completed");

        assert_eq!(value, 7);
        assert_ne!(receiver.recv().expect("worker reported"), caller);
    }

    #[test]
    fn an_error_from_the_work_reaches_the_caller() {
        let error = block_on(off_thread::<(), _>("probe", || {
            Err(cipherbox_engine::seams::SeamError::new("no such entry"))
        }))
        .expect_err("work failed");
        assert!(error.to_string().contains("no such entry"), "{error}");
    }

    #[test]
    fn a_panicking_work_body_fails_the_call_instead_of_hanging_it() {
        let error = block_on(off_thread::<(), _>("probe", || panic!("keyring exploded")))
            .expect_err("panic surfaced as a seam error");
        assert!(error.to_string().contains("probe"), "{error}");
    }
}
