//! Desktop [`Scheduler`]: timers, background tasks, and the wall clock on
//! Tokio.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use cipherbox_engine::seams::{BoxedTask, Scheduler, UnixMillis};

/// Timers, background task execution, and the wall clock, backed by
/// Tokio (blueprint/engine.md "Scheduler", desktop column).
///
/// The only source of time in the engine on desktop: [`now`](Self::now)
/// reads the system wall clock, [`sleep`](Self::sleep) delegates to
/// `tokio::time::sleep`; this seam sleeps exactly the duration asked.
///
/// Because [`BoxedTask`] is deliberately `!Send` (the single-writer engine
/// is pinned to one execution context), [`spawn`](Self::spawn) uses
/// `tokio::task::spawn_local` and therefore must run inside a Tokio
/// `LocalSet` on a current-thread runtime — exactly the shape the desktop
/// host runs the engine in.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioScheduler;

impl TokioScheduler {
    /// A new scheduler handle. Cheap and copyable; carries no state.
    pub fn new() -> Self {
        Self
    }
}

impl Scheduler for TokioScheduler {
    fn now(&self) -> UnixMillis {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or(0);
        UnixMillis(u64::try_from(millis).unwrap_or(u64::MAX))
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    fn spawn(&self, task: BoxedTask) {
        // Fire-and-forget: dropping the JoinHandle detaches the task, which
        // keeps running (the seam contract observes completion only through
        // the task's own effects).
        tokio::task::spawn_local(task);
    }
}
