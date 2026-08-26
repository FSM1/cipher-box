//! The manual-refresh trigger — the focus-window tick's second wake source
//! (blueprint/engine.md "Sync core"; CONTEXT.md "Sync and refresh").
//!
//! `Command::ManualRefresh` files a request here and awaits the verdict of the
//! pass that answers it. The tick loop is the only pass executor, so a request
//! can never run a pass alongside the poll leg; it only ever brings the next
//! pass forward.
//!
//! Requests coalesce rather than stack: a request filed while a manual pass is
//! running joins that pass, and every request filed before a pass starts is
//! answered by that one pass. Two clicks therefore cost one network pass, never
//! two.

use core::cell::RefCell;
use core::task::{Context, Poll, Waker};
use std::rc::Rc;

use futures_channel::oneshot;

use crate::facade::EngineError;

/// What a manual refresh reports back to the host. The two failures stay
/// distinct all the way out: a host retries availability and must never retry a
/// trust verdict (rule 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshVerdict {
    /// The pass reconciled gate-passing state off the record plane.
    Reconciled,
    /// No endpoint served a record this pass could adopt. Availability, and
    /// never a silent success off the cache the pass skipped.
    Unreachable,
    /// The record plane served a record the adoption gate rejected —
    /// fail-closed, not staleness.
    Rejected,
}

impl RefreshVerdict {
    /// The verdict a pass settles when its legs disagree: the worst one. A
    /// rejection outranks availability, so a leg that reconciled can never mask
    /// one that fail-closed into the retry a trust verdict must never get
    /// (rule 6).
    pub(crate) fn worst(self, other: Self) -> Self {
        match (self, other) {
            (Self::Rejected, _) | (_, Self::Rejected) => Self::Rejected,
            (Self::Unreachable, _) | (_, Self::Unreachable) => Self::Unreachable,
            (Self::Reconciled, Self::Reconciled) => Self::Reconciled,
        }
    }
}

/// A filed pass, waiting for the verdict of the tick that answers it.
///
/// Owns nothing of the engine, so a host that also serves a kernel awaits the
/// network legs off the loop it filed them from rather than freezing every
/// callback behind them (blueprint/desktop.md "the never-block law").
pub struct ForcedPass(oneshot::Receiver<RefreshVerdict>);

impl ForcedPass {
    /// What the pass reconciled, in the verdicts
    /// [`Command::ManualRefresh`](crate::facade::Command::ManualRefresh)
    /// reports — this is where that mapping lives.
    pub async fn landed(self) -> Result<(), EngineError> {
        match self.0.await {
            Ok(RefreshVerdict::Reconciled) => Ok(()),
            Ok(RefreshVerdict::Unreachable) => Err(EngineError::RefreshFailed {
                message: "no endpoint served a record this pass could adopt".to_owned(),
            }),
            // Fail-closed, and reported as the verdict it is: a host retries
            // availability and must never retry a rejection (rule 6).
            Ok(RefreshVerdict::Rejected) => Err(EngineError::TrustViolation {
                message: "the record plane served a record the adoption gate rejected".to_owned(),
            }),
            Err(_) => Err(EngineError::RefreshFailed {
                message: "the sync loop stopped before the pass ran".to_owned(),
            }),
        }
    }
}

#[derive(Default)]
struct Inner {
    /// Requests no pass has taken yet; the next pass answers all of them.
    queued: Vec<oneshot::Sender<RefreshVerdict>>,
    /// Requests the running manual pass answers. `Some` only while one runs.
    running: Option<Vec<oneshot::Sender<RefreshVerdict>>>,
    /// The parked tick loop, woken by the first queued request.
    waker: Option<Waker>,
    /// Whether a tick loop is live to answer requests at all.
    armed: bool,
}

/// The shared handle both the tick loop and the command path hold.
#[derive(Clone, Default)]
pub(crate) struct ManualRefresh {
    inner: Rc<RefCell<Inner>>,
}

impl ManualRefresh {
    /// Marks a tick loop live, so requests are answerable.
    pub(crate) fn arm(&self) {
        self.inner.borrow_mut().armed = true;
    }

    /// Files a request, handing back the verdict channel of the pass that will
    /// answer it. `None` when no tick loop is running — a caller must fail
    /// rather than park on a pass that will never come.
    pub(crate) fn request(&self) -> Option<oneshot::Receiver<RefreshVerdict>> {
        let (sender, receiver) = oneshot::channel();
        let waker = {
            let mut inner = self.inner.borrow_mut();
            if !inner.armed {
                return None;
            }
            match &mut inner.running {
                // Join the running pass rather than queueing a second: two
                // clicks cost one network pass.
                Some(running) => {
                    running.push(sender);
                    None
                }
                None => {
                    inner.queued.push(sender);
                    inner.waker.take()
                }
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        Some(receiver)
    }

    /// Files a request as a pass its caller can await without holding the
    /// engine. `None` for the reason [`request`](Self::request) gives.
    pub(crate) fn filed(&self) -> Option<ForcedPass> {
        self.request().map(ForcedPass)
    }

    /// Whether a request is waiting for a pass to start.
    pub(crate) fn poll_requested(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut inner = self.inner.borrow_mut();
        if !inner.queued.is_empty() {
            return Poll::Ready(());
        }
        inner.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Takes every queued request as the starting pass's own.
    pub(crate) fn begin(&self) {
        let mut inner = self.inner.borrow_mut();
        let taken = core::mem::take(&mut inner.queued);
        inner.running = Some(taken);
    }

    /// Answers every request the running pass took. A no-op on a poll pass,
    /// which never took any.
    pub(crate) fn settle(&self, verdict: RefreshVerdict) {
        let running = self.inner.borrow_mut().running.take();
        for sender in running.into_iter().flatten() {
            let _ = sender.send(verdict);
        }
    }

    /// Drops every outstanding request and disarms: no pass will answer them,
    /// so their receivers must fail rather than park past the engine.
    pub(crate) fn close(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.armed = false;
        inner.queued.clear();
        inner.running = None;
        inner.waker = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;
    use core::future::poll_fn;

    fn requested(manual: &ManualRefresh) -> bool {
        let mut ready = false;
        block_on(poll_fn(|cx| {
            ready = manual.poll_requested(cx).is_ready();
            Poll::Ready(())
        }));
        ready
    }

    #[test]
    fn the_worst_leg_settles_the_pass() {
        use RefreshVerdict::{Reconciled, Rejected, Unreachable};
        assert_eq!(Reconciled.worst(Reconciled), Reconciled);
        for verdict in [Reconciled, Unreachable, Rejected] {
            assert_eq!(
                verdict.worst(Rejected),
                Rejected,
                "a rejection is never masked by another leg"
            );
            assert_eq!(Rejected.worst(verdict), Rejected);
        }
        assert_eq!(Reconciled.worst(Unreachable), Unreachable);
        assert_eq!(Unreachable.worst(Reconciled), Unreachable);
    }

    /// A filed pass carries the verdict mapping, so a host that awaits it off
    /// its loop reports exactly what `Command::ManualRefresh` would have.
    #[test]
    fn a_filed_pass_reports_the_verdict_the_command_would_have() {
        for (verdict, expected) in [
            (RefreshVerdict::Reconciled, Ok(())),
            (
                RefreshVerdict::Unreachable,
                Err(EngineError::RefreshFailed {
                    message: "no endpoint served a record this pass could adopt".to_owned(),
                }),
            ),
            (
                RefreshVerdict::Rejected,
                Err(EngineError::TrustViolation {
                    message: "the record plane served a record the adoption gate rejected"
                        .to_owned(),
                }),
            ),
        ] {
            let manual = ManualRefresh::default();
            manual.arm();
            let pass = manual.filed().expect("armed");
            manual.begin();
            manual.settle(verdict);
            assert_eq!(block_on(pass.landed()), expected, "{verdict:?}");
        }
    }

    /// A pass no tick will answer must fail rather than park past the engine —
    /// the host awaiting it off its loop has nothing else to end its wait.
    #[test]
    fn a_pass_a_closed_loop_abandoned_fails_rather_than_parking() {
        let manual = ManualRefresh::default();
        manual.arm();
        let pass = manual.filed().expect("armed");
        manual.close();
        assert!(matches!(
            block_on(pass.landed()),
            Err(EngineError::RefreshFailed { .. })
        ));
    }

    #[test]
    fn an_unarmed_trigger_refuses_a_request() {
        let manual = ManualRefresh::default();
        assert!(manual.request().is_none());
        manual.arm();
        assert!(manual.request().is_some());
    }

    #[test]
    fn requests_before_a_pass_share_the_one_pass_that_starts() {
        let manual = ManualRefresh::default();
        manual.arm();
        let first = manual.request().expect("armed");
        let second = manual.request().expect("armed");
        assert!(requested(&manual));

        manual.begin();
        assert!(
            !requested(&manual),
            "the starting pass took both requests, leaving none to start another"
        );
        manual.settle(RefreshVerdict::Reconciled);

        assert_eq!(block_on(first), Ok(RefreshVerdict::Reconciled));
        assert_eq!(block_on(second), Ok(RefreshVerdict::Reconciled));
    }

    #[test]
    fn a_request_during_a_running_pass_joins_it_rather_than_queueing_another() {
        let manual = ManualRefresh::default();
        manual.arm();
        let first = manual.request().expect("armed");
        manual.begin();

        let second = manual.request().expect("armed");
        assert!(
            !requested(&manual),
            "the late request coalesced onto the running pass"
        );

        manual.settle(RefreshVerdict::Unreachable);
        assert_eq!(block_on(first), Ok(RefreshVerdict::Unreachable));
        assert_eq!(block_on(second), Ok(RefreshVerdict::Unreachable));
    }

    #[test]
    fn a_request_after_a_pass_settled_waits_for_the_next_one() {
        let manual = ManualRefresh::default();
        manual.arm();
        let first = manual.request().expect("armed");
        manual.begin();
        manual.settle(RefreshVerdict::Reconciled);
        assert_eq!(block_on(first), Ok(RefreshVerdict::Reconciled));

        let second = manual.request().expect("armed");
        assert!(requested(&manual), "the drain window queues a fresh pass");
        manual.begin();
        manual.settle(RefreshVerdict::Reconciled);
        assert_eq!(block_on(second), Ok(RefreshVerdict::Reconciled));
    }

    #[test]
    fn close_cancels_every_outstanding_request() {
        let manual = ManualRefresh::default();
        manual.arm();
        let queued = manual.request().expect("armed");
        manual.begin();
        let running = manual.request().expect("armed");

        manual.close();
        assert_eq!(block_on(queued), Err(oneshot::Canceled));
        assert_eq!(block_on(running), Err(oneshot::Canceled));
        assert!(manual.request().is_none(), "a closed trigger is disarmed");
    }
}
