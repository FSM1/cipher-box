//! The focus-window tick — the one sync model driven by two trigger sources
//! (blueprint/engine.md "Sync core"; CONTEXT.md "Focus window"; #33 D2).
//!
//! One model, two triggers: web drives it from navigation and the poll timer,
//! desktop from FUSE-op TTL checks — the loop is identical. A tick refreshes
//! the **focus window**: the vault pointer, the open folder, its full ancestor
//! chain to root, the scope pointers of open shared scopes, and the mailbox
//! poll — everything else refreshes on access past the staleness threshold, so
//! there is no background churn over the whole tree. Immediate ticks fire on a
//! [`RefreshHintSource`] event; the poll cadence is jittered from injected
//! entropy (the engine never sleeps a raw library default and never reads an
//! RNG directly).

use core::future::Future;
use core::pin::pin;
use core::task::Poll;
use core::time::Duration;

use crate::entropy::Entropy;
use crate::facade::NodeId;
use crate::profile::SyncTimingProfile;
use crate::seams::{RefreshHintSource, Scheduler, UnixMillis};
use crate::sync::model::Snapshot;

/// The maximum jitter added to the poll cadence, as a fraction denominator: the
/// tick sleeps `[cadence, cadence + cadence/JITTER_DIVISOR)` so concurrent
/// clients spread their polls (thundering-herd avoidance) without ever
/// polling *faster* than the cadence.
const JITTER_DIVISOR: u32 = 2;

/// The open focus of the UI: the folder in view and any open shared scopes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FocusWindow {
    /// The open folder driving the window; `None` when no folder is open.
    pub open_folder: Option<NodeId>,
    /// Scope roots of shared scopes currently open (their scope pointers ride
    /// the tick, #38 D4).
    pub open_shared_scopes: Vec<NodeId>,
}

/// One target a tick refreshes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FocusTarget {
    /// The indexed vault pointer (the cold-boot entry point; every tick).
    VaultPointer,
    /// An open shared scope's scope pointer (polled, not fallback).
    ScopePointer(NodeId),
    /// The mailbox poll rides the same tick (#34 D5).
    MailboxPoll,
    /// A folder record (the open folder and each ancestor to root).
    Folder(NodeId),
}

/// What woke a tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickCause {
    /// The jittered poll timer elapsed.
    Poll,
    /// A [`RefreshHintSource`] event forced an immediate tick.
    Hint,
    /// A host `ManualRefresh` — resolves with nocache semantics everywhere.
    Manual,
}

/// How a tick resolves records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
    /// Cache-first: last-known-good renders immediately, reconcile behind it.
    CacheFirst,
    /// Nocache: bypass the cache and resolve fresh (manual refresh, #33 D4).
    NoCache,
}

/// The resolve mode for a tick cause: manual refresh is nocache everywhere,
/// every other cause is cache-first.
pub fn resolve_mode(cause: TickCause) -> ResolveMode {
    match cause {
        TickCause::Manual => ResolveMode::NoCache,
        TickCause::Poll | TickCause::Hint => ResolveMode::CacheFirst,
    }
}

/// The focus set a tick refreshes, in deterministic order: vault pointer, open
/// shared-scope pointers, mailbox poll, open folder, ancestors to root.
/// Everything else is out of the window (on-access refresh only).
pub fn focus_set(snapshot: &Snapshot, focus: &FocusWindow) -> Vec<FocusTarget> {
    let mut targets = vec![FocusTarget::VaultPointer];
    for scope in &focus.open_shared_scopes {
        targets.push(FocusTarget::ScopePointer(*scope));
    }
    targets.push(FocusTarget::MailboxPoll);
    if let Some(open) = focus.open_folder {
        targets.push(FocusTarget::Folder(open));
        for ancestor in snapshot.ancestors(open) {
            targets.push(FocusTarget::Folder(ancestor));
        }
    }
    targets
}

/// Whether a cached folder outside the focus window is due for an on-access
/// refresh: it was last refreshed longer ago than the staleness threshold. No
/// background churn — this fires only when the folder is actually accessed.
pub fn on_access_refresh_due(
    now: UnixMillis,
    last_refreshed: UnixMillis,
    profile: &SyncTimingProfile,
) -> bool {
    now.0.saturating_sub(last_refreshed.0) >= crate::sync::duration_millis(profile.stale_after)
}

/// The poll cadence with jitter drawn from injected entropy:
/// `[cadence, cadence + cadence/JITTER_DIVISOR)`. Deterministic for a given
/// entropy stream (the determinism law); a zero cadence stays zero.
pub fn jittered_cadence(cadence: Duration, entropy: &mut dyn Entropy) -> Duration {
    let span = cadence / JITTER_DIVISOR;
    if span.is_zero() {
        return cadence;
    }
    let mut bytes = [0u8; 8];
    // Jitter is best-effort scheduling: a fill error degrades to the un-jittered
    // cadence rather than propagating — it costs herd spread, never correctness.
    if entropy.fill(&mut bytes).is_err() {
        return cadence;
    }
    let span_nanos = span.as_nanos().max(1);
    let offset = (u128::from(u64::from_le_bytes(bytes)) % span_nanos) as u64;
    cadence + Duration::from_nanos(offset)
}

/// A tick loop's control signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickControl {
    /// Keep polling.
    Continue,
    /// Stop the loop (logout / shutdown).
    Stop,
}

/// What woke the tick-loop wait.
enum TickWake {
    /// The jittered timer elapsed.
    Timer,
    /// A hint arrived (`None` = the source closed for good).
    Hint(bool),
}

/// Wait for the next tick: whichever of the jittered timer or the next refresh
/// hint fires first. The hint is polled first, so an already-queued hint yields
/// an immediate tick without waiting on the timer.
async fn wait_for_tick<Sch, H>(scheduler: &Sch, hints: &mut H, delay: Duration) -> TickWake
where
    Sch: Scheduler,
    H: RefreshHintSource,
{
    let mut sleep = pin!(scheduler.sleep(delay));
    let mut hint = pin!(hints.next_hint());
    core::future::poll_fn(|cx| {
        if let Poll::Ready(h) = hint.as_mut().poll(cx) {
            return Poll::Ready(TickWake::Hint(h.is_some()));
        }
        if sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(TickWake::Timer);
        }
        Poll::Pending
    })
    .await
}

/// Run the focus-window tick loop until `on_tick` returns [`TickControl::Stop`]
/// or the hint source closes. Each iteration sleeps a freshly-jittered cadence
/// but wakes immediately on a refresh hint; `on_tick` performs the actual focus
/// resolve (the net/pointer wiring the caller composes) and decides whether to
/// continue.
pub async fn run_tick_loop<Sch, H, F, Fut>(
    scheduler: &Sch,
    hints: &mut H,
    entropy: &mut dyn Entropy,
    profile: &SyncTimingProfile,
    mut on_tick: F,
) where
    Sch: Scheduler,
    H: RefreshHintSource,
    F: FnMut(TickCause) -> Fut,
    Fut: Future<Output = TickControl>,
{
    loop {
        let delay = jittered_cadence(profile.poll_cadence, entropy);
        let cause = match wait_for_tick(scheduler, hints, delay).await {
            TickWake::Timer => TickCause::Poll,
            TickWake::Hint(true) => TickCause::Hint,
            // The source closed for good: stop listening (host shutdown).
            TickWake::Hint(false) => break,
        };
        if on_tick(cause).await == TickControl::Stop {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use crate::facade::NodeKind;
    use crate::sync::model::NodeMeta;
    use crate::testkit::fakes::{ManualHintSource, VirtualScheduler};
    use crate::testkit::{SeededEntropy, block_on};

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    #[test]
    fn focus_set_is_vault_scopes_mailbox_then_the_folder_chain() {
        let mut snap = Snapshot::new(id(0));
        snap.upsert_node(NodeMeta::new(id(1), "a", NodeKind::Folder));
        snap.upsert_node(NodeMeta::new(id(2), "b", NodeKind::Folder));
        snap.link(id(0), id(1), 1);
        snap.link(id(1), id(2), 1);

        let focus = FocusWindow {
            open_folder: Some(id(2)),
            open_shared_scopes: vec![id(7)],
        };
        assert_eq!(
            focus_set(&snap, &focus),
            vec![
                FocusTarget::VaultPointer,
                FocusTarget::ScopePointer(id(7)),
                FocusTarget::MailboxPoll,
                FocusTarget::Folder(id(2)),
                FocusTarget::Folder(id(1)),
                FocusTarget::Folder(id(0)),
            ]
        );
    }

    #[test]
    fn focus_set_with_no_open_folder_is_pointer_and_mailbox_only() {
        let snap = Snapshot::new(id(0));
        assert_eq!(
            focus_set(&snap, &FocusWindow::default()),
            vec![FocusTarget::VaultPointer, FocusTarget::MailboxPoll]
        );
    }

    #[test]
    fn manual_refresh_is_nocache_others_cache_first() {
        assert_eq!(resolve_mode(TickCause::Manual), ResolveMode::NoCache);
        assert_eq!(resolve_mode(TickCause::Poll), ResolveMode::CacheFirst);
        assert_eq!(resolve_mode(TickCause::Hint), ResolveMode::CacheFirst);
    }

    #[test]
    fn on_access_refresh_only_past_the_threshold() {
        let p = SyncTimingProfile::PRODUCTION; // stale_after 90 s
        assert!(!on_access_refresh_due(
            UnixMillis(89_000),
            UnixMillis(0),
            &p
        ));
        assert!(on_access_refresh_due(UnixMillis(90_000), UnixMillis(0), &p));
    }

    #[test]
    fn jitter_is_deterministic_and_bounded() {
        let cadence = Duration::from_secs(30);
        let a = jittered_cadence(cadence, &mut SeededEntropy::new(42));
        let b = jittered_cadence(cadence, &mut SeededEntropy::new(42));
        assert_eq!(a, b, "same entropy stream, same jitter");
        assert!(a >= cadence, "jitter never polls faster than the cadence");
        assert!(a < cadence + cadence / JITTER_DIVISOR, "jitter is bounded");
    }

    #[test]
    fn jitter_zero_cadence_stays_zero() {
        assert_eq!(
            jittered_cadence(Duration::ZERO, &mut SeededEntropy::new(1)),
            Duration::ZERO
        );
    }

    #[test]
    fn a_queued_hint_forces_an_immediate_tick_without_advancing_time() {
        let scheduler = VirtualScheduler::new(); // manual clock, never advanced here
        let source = ManualHintSource::default();
        let mut listener = source.clone();
        let mut entropy = SeededEntropy::new(1);
        let causes = RefCell::new(Vec::new());

        source.push_hint();
        source.push_hint();
        source.close();

        block_on(run_tick_loop(
            &scheduler,
            &mut listener,
            &mut entropy,
            &SyncTimingProfile::PRODUCTION,
            |cause| {
                causes.borrow_mut().push(cause);
                async { TickControl::Continue }
            },
        ));

        assert_eq!(
            causes.into_inner(),
            vec![TickCause::Hint, TickCause::Hint],
            "both hints ticked immediately; the close stopped the loop"
        );
        assert_eq!(scheduler.now(), UnixMillis(0), "no timer ever elapsed");
    }

    #[test]
    fn the_poll_timer_ticks_on_the_jittered_cadence() {
        let scheduler = VirtualScheduler::new().with_auto_advance();
        let source = ManualHintSource::default(); // no hints
        let mut listener = source.clone();
        let mut entropy = SeededEntropy::new(7);
        let ticks = RefCell::new(0u32);

        block_on(run_tick_loop(
            &scheduler,
            &mut listener,
            &mut entropy,
            &SyncTimingProfile::CI,
            |cause| {
                assert_eq!(cause, TickCause::Poll);
                *ticks.borrow_mut() += 1;
                let stop = *ticks.borrow() == 3;
                async move {
                    if stop {
                        TickControl::Stop
                    } else {
                        TickControl::Continue
                    }
                }
            },
        ));

        assert_eq!(ticks.into_inner(), 3, "the timer drove three poll ticks");
        assert!(scheduler.now() > UnixMillis(0), "virtual time advanced");
    }
}
