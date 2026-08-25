//! The focus-window tick — the one sync model driven by two trigger sources
//! (blueprint/engine.md "Sync core"; CONTEXT.md "Focus window"; #33 D2).
//!
//! One model, two triggers: the poll timer and a host `ManualRefresh`, which
//! brings the next pass forward. A tick refreshes
//! the **focus window**: the vault pointer, the open folder, its full ancestor
//! chain to root, the scope pointers of open shared scopes, and the mailbox
//! poll — everything else refreshes on access past the staleness threshold, so
//! there is no background churn over the whole tree.

use core::pin::pin;
use core::task::Poll;
use core::time::Duration;
use std::collections::BTreeMap;

use crate::facade::NodeId;
use crate::profile::SyncTimingProfile;
use crate::seams::{Scheduler, UnixMillis};
use crate::sync::model::Snapshot;
use crate::sync::pointer::{ConsultReason, should_consult};
use crate::sync::refresh::{ManualRefresh, RefreshVerdict};

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
    /// The poll timer elapsed.
    Poll,
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
        TickCause::Poll => ResolveMode::CacheFirst,
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

/// The focus window's folder targets **below** the scope root, nearest first.
/// The root rides the vault-pointer leg of the same tick, so it is not a folder
/// target here; every remaining entry is a child record resolved through the
/// child gate.
pub fn focus_folders(snapshot: &Snapshot, focus: &FocusWindow) -> Vec<NodeId> {
    focus_set(snapshot, focus)
        .into_iter()
        .filter_map(|target| match target {
            FocusTarget::Folder(node) if node != snapshot.root => Some(node),
            _ => None,
        })
        .collect()
}

/// The scope pointers a tick consults, in deterministic order: the vault
/// anchor's first, then each open shared scope's, deduplicated.
///
/// The anchor rides every tick because a **write-only** rotation leaves the read
/// epoch untouched, so it mints no superseded scope root for the sweep's
/// event-driven consult to notice — this polled leg is the only path that
/// advances the anchor scope's write-epoch floor in-session, and with it evicts
/// the `writeScopeSeed` that rotation retired (#38 D4).
pub fn consult_scopes(snapshot: &Snapshot, focus: &FocusWindow) -> Vec<NodeId> {
    let mut scopes = vec![snapshot.root];
    for target in focus_set(snapshot, focus) {
        if let FocusTarget::ScopePointer(scope) = target
            && !scopes.contains(&scope)
        {
            scopes.push(scope);
        }
    }
    scopes
}

/// The scope pointers this tick consults: those in the window
/// ([`consult_scopes`]) whose [`SyncTimingProfile::pointer_consult_interval`]
/// has elapsed, so a poll cadence shorter than the interval does not re-resolve
/// every pointer every tick. A scope no pass has consulted is due at once.
///
/// Routes [`ConsultReason::FocusTick`] and nothing else: cold start is the boot
/// anchor's reason and on-access is the navigation leg's, neither of which the
/// tick decides.
pub fn consult_scopes_due(
    snapshot: &Snapshot,
    focus: &FocusWindow,
    last_consulted: &BTreeMap<NodeId, UnixMillis>,
    now: UnixMillis,
    profile: &SyncTimingProfile,
) -> Vec<NodeId> {
    consult_scopes(snapshot, focus)
        .into_iter()
        .filter(|scope| {
            let due = last_consulted
                .get(scope)
                .is_none_or(|last| elapsed_at_least(now, *last, profile.pointer_consult_interval));
            should_consult(false, due, false) == Some(ConsultReason::FocusTick)
        })
        .collect()
}

/// Whether `interval` has fully elapsed between `since` and `now` — the one
/// comparison every timing bar in this module is stated over. Saturating, so a
/// clock that stepped backwards reads as no time passed rather than as an
/// enormous gap.
fn elapsed_at_least(now: UnixMillis, since: UnixMillis, interval: Duration) -> bool {
    now.0.saturating_sub(since.0) >= crate::sync::duration_millis(interval)
}

/// The focus window's folders due for an on-access refresh: those no pass has
/// touched inside the staleness threshold ([`on_access_refresh_due`]). The poll
/// leg refreshes the whole window regardless; this is the navigation leg's
/// damper.
pub fn focus_folders_due(
    snapshot: &Snapshot,
    focus: &FocusWindow,
    last_refreshed: &BTreeMap<NodeId, UnixMillis>,
    now: UnixMillis,
    profile: &SyncTimingProfile,
) -> Vec<NodeId> {
    focus_folders(snapshot, focus)
        .into_iter()
        .filter(|folder| {
            last_refreshed
                .get(folder)
                .is_none_or(|last| on_access_refresh_due(now, *last, profile))
        })
        .collect()
}

/// Whether an operation-stream focus window has gone quiet past the profile's
/// focus horizon, so the folder it holds stops counting as open. `None` is a
/// window nothing has touched, which nothing has to close.
///
/// A window is closed by the tick, not by the host that opened it: an operation
/// stream that stops arriving produces no call to close it with.
pub fn focus_window_expired(
    now: UnixMillis,
    touched: Option<UnixMillis>,
    profile: &SyncTimingProfile,
) -> bool {
    touched.is_some_and(|last| elapsed_at_least(now, last, profile.focus_horizon))
}

/// Whether a cached folder outside the focus window is due for an on-access
/// refresh: it was last refreshed longer ago than the staleness threshold. No
/// background churn — this fires only when the folder is actually accessed.
pub fn on_access_refresh_due(
    now: UnixMillis,
    last_refreshed: UnixMillis,
    profile: &SyncTimingProfile,
) -> bool {
    elapsed_at_least(now, last_refreshed, profile.stale_after)
}

/// A tick loop's control signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickControl {
    /// Keep polling.
    Continue,
    /// Stop the loop (logout / shutdown).
    Stop,
}

/// Wait for the next tick: whichever of the poll timer or a filed manual
/// refresh comes first. The request is polled first, so one already waiting
/// ticks immediately instead of sitting out the cadence.
async fn wait_for_tick<Sch>(scheduler: &Sch, manual: &ManualRefresh, cadence: Duration) -> TickCause
where
    Sch: Scheduler,
{
    let mut sleep = pin!(scheduler.sleep(cadence));
    core::future::poll_fn(|cx| {
        if manual.poll_requested(cx).is_ready() {
            return Poll::Ready(TickCause::Manual);
        }
        if sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(TickCause::Poll);
        }
        Poll::Pending
    })
    .await
}

/// Run the focus-window tick loop until `on_tick` returns [`TickControl::Stop`].
/// Each iteration sleeps the poll cadence but wakes early on a manual refresh;
/// `on_tick` performs the actual focus resolve (the net/pointer wiring the
/// caller composes) and decides whether to continue.
///
/// Settles the requests the pass took after `on_tick` returns, so a pass that
/// stopped before settling them itself still answers them (see
/// [`ManualRefresh`]).
pub(crate) async fn run_tick_loop<Sch>(
    scheduler: &Sch,
    manual: &ManualRefresh,
    cadence: Duration,
    mut on_tick: impl AsyncFnMut(TickCause) -> TickControl,
) where
    Sch: Scheduler,
{
    loop {
        let cause = wait_for_tick(scheduler, manual, cadence).await;
        if cause == TickCause::Manual {
            manual.begin();
        }
        let control = on_tick(cause).await;
        manual.settle(RefreshVerdict::Unreachable);
        if control == TickControl::Stop {
            break;
        }
    }
    manual.close();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn a_window_closes_only_once_the_horizon_has_fully_elapsed() {
        let profile = SyncTimingProfile::CI;
        let horizon = crate::sync::duration_millis(profile.focus_horizon);
        let touched = UnixMillis(1_000);

        assert!(
            !focus_window_expired(UnixMillis(1_000), Some(touched), &profile),
            "traffic that just arrived holds the window open"
        );
        assert!(!focus_window_expired(
            UnixMillis(1_000 + horizon - 1),
            Some(touched),
            &profile
        ));
        assert!(focus_window_expired(
            UnixMillis(1_000 + horizon),
            Some(touched),
            &profile
        ));
    }

    #[test]
    fn a_window_nothing_ever_touched_needs_no_closing() {
        assert!(!focus_window_expired(
            UnixMillis(u64::MAX),
            None,
            &SyncTimingProfile::CI
        ));
    }

    use crate::facade::NodeKind;
    use crate::sync::model::NodeMeta;
    use crate::testkit::block_on;
    use crate::testkit::fakes::VirtualScheduler;

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    /// The vault anchor always rides the consult leg — a write-only rotation
    /// re-points its scope pointer and mints no superseded root for the sweep —
    /// and each open shared scope joins it once, in window order.
    #[test]
    fn consult_scopes_are_the_anchor_then_the_open_shared_scopes() {
        let snap = Snapshot::new(id(0));
        assert_eq!(
            consult_scopes(&snap, &FocusWindow::default()),
            vec![id(0)],
            "a session with no shared scope open still consults its own anchor",
        );

        let focus = FocusWindow {
            open_folder: None,
            open_shared_scopes: vec![id(7), id(0), id(7)],
        };
        assert_eq!(
            consult_scopes(&snap, &focus),
            vec![id(0), id(7)],
            "the anchor leads, and neither it nor a repeat is consulted twice",
        );
    }

    /// `pointer_consult_interval` is the consult's pace, not the poll cadence.
    #[test]
    fn a_consult_is_due_once_the_interval_has_fully_elapsed() {
        let profile = SyncTimingProfile::PRODUCTION;
        let interval = crate::sync::duration_millis(profile.pointer_consult_interval);
        let snap = Snapshot::new(id(0));
        let focus = FocusWindow::default();
        let due = |now: u64, stamped: Option<u64>| {
            let mut last = BTreeMap::new();
            if let Some(at) = stamped {
                last.insert(id(0), UnixMillis(at));
            }
            !consult_scopes_due(&snap, &focus, &last, UnixMillis(now), &profile).is_empty()
        };

        assert!(due(u64::MAX, None), "a scope no pass has consulted is due");
        assert!(!due(1_000, Some(1_000)));
        assert!(!due(1_000 + interval - 1, Some(1_000)));
        assert!(due(1_000 + interval, Some(1_000)));
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
    fn focus_folders_are_the_chain_below_the_root_nearest_first() {
        let mut snap = Snapshot::new(id(0));
        snap.upsert_node(NodeMeta::new(id(1), "a", NodeKind::Folder));
        snap.upsert_node(NodeMeta::new(id(2), "b", NodeKind::Folder));
        snap.link(id(0), id(1), 1);
        snap.link(id(1), id(2), 1);

        let focus = FocusWindow {
            open_folder: Some(id(2)),
            open_shared_scopes: vec![id(7)],
        };
        assert_eq!(focus_folders(&snap, &focus), vec![id(2), id(1)]);
        assert!(focus_folders(&snap, &FocusWindow::default()).is_empty());
    }

    #[test]
    fn focus_folders_due_damps_a_repeat_visit_inside_the_threshold() {
        let mut snap = Snapshot::new(id(0));
        snap.upsert_node(NodeMeta::new(id(1), "a", NodeKind::Folder));
        snap.upsert_node(NodeMeta::new(id(2), "b", NodeKind::Folder));
        snap.link(id(0), id(1), 1);
        snap.link(id(1), id(2), 1);
        let focus = FocusWindow {
            open_folder: Some(id(2)),
            open_shared_scopes: Vec::new(),
        };
        let profile = SyncTimingProfile::PRODUCTION; // stale_after 90 s
        let due = |stamps: &BTreeMap<NodeId, UnixMillis>, now| {
            focus_folders_due(&snap, &focus, stamps, UnixMillis(now), &profile)
        };

        assert_eq!(
            due(&BTreeMap::new(), 0),
            vec![id(2), id(1)],
            "a never-refreshed window is due whole"
        );

        let stamps = BTreeMap::from([(id(2), UnixMillis(0))]);
        assert_eq!(
            due(&stamps, 89_000),
            vec![id(1)],
            "the stamped folder is damped, its unstamped ancestor is not"
        );
        assert_eq!(due(&stamps, 90_000), vec![id(2), id(1)]);
    }

    #[test]
    fn focus_folders_on_the_root_itself_is_empty() {
        let snap = Snapshot::new(id(0));
        let focus = FocusWindow {
            open_folder: Some(id(0)),
            open_shared_scopes: Vec::new(),
        };
        assert!(
            focus_folders(&snap, &focus).is_empty(),
            "the root rides the vault-pointer leg, never the child gate"
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
    fn manual_refresh_is_nocache_and_a_poll_is_cache_first() {
        assert_eq!(resolve_mode(TickCause::Manual), ResolveMode::NoCache);
        assert_eq!(resolve_mode(TickCause::Poll), ResolveMode::CacheFirst);
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
    fn a_filed_manual_refresh_ticks_immediately_without_advancing_time() {
        let scheduler = VirtualScheduler::new(); // manual clock, never advanced here
        let manual = ManualRefresh::default();
        manual.arm();
        let causes = RefCell::new(Vec::new());

        let first = manual.request().expect("armed");
        let second = manual.request().expect("armed");

        block_on(run_tick_loop(
            &scheduler,
            &manual,
            SyncTimingProfile::PRODUCTION.poll_cadence,
            async |cause| {
                causes.borrow_mut().push(cause);
                manual.settle(RefreshVerdict::Reconciled);
                TickControl::Stop
            },
        ));

        assert_eq!(
            causes.into_inner(),
            vec![TickCause::Manual],
            "two requests before the pass started cost exactly one pass"
        );
        assert_eq!(scheduler.now(), UnixMillis(0), "no timer ever elapsed");
        assert_eq!(block_on(first), Ok(RefreshVerdict::Reconciled));
        assert_eq!(block_on(second), Ok(RefreshVerdict::Reconciled));
    }

    #[test]
    fn a_pass_that_stops_without_settling_still_answers_its_requests() {
        let scheduler = VirtualScheduler::new();
        let manual = ManualRefresh::default();
        manual.arm();
        let waiter = manual.request().expect("armed");

        block_on(run_tick_loop(
            &scheduler,
            &manual,
            SyncTimingProfile::PRODUCTION.poll_cadence,
            async |_| TickControl::Stop,
        ));

        assert_eq!(block_on(waiter), Ok(RefreshVerdict::Unreachable));
    }

    #[test]
    fn a_stopped_loop_disarms_the_trigger() {
        let scheduler = VirtualScheduler::new().with_auto_advance();
        let manual = ManualRefresh::default();
        manual.arm();

        block_on(run_tick_loop(
            &scheduler,
            &manual,
            SyncTimingProfile::CI.poll_cadence,
            async |_| TickControl::Stop,
        ));

        assert!(
            manual.request().is_none(),
            "no loop remains to answer a request"
        );
    }

    #[test]
    fn the_poll_timer_ticks_on_the_cadence() {
        let scheduler = VirtualScheduler::new().with_auto_advance();
        let manual = ManualRefresh::default();
        let ticks = RefCell::new(0u32);

        block_on(run_tick_loop(
            &scheduler,
            &manual,
            SyncTimingProfile::CI.poll_cadence,
            async |cause| {
                assert_eq!(cause, TickCause::Poll);
                *ticks.borrow_mut() += 1;
                if *ticks.borrow() == 3 {
                    TickControl::Stop
                } else {
                    TickControl::Continue
                }
            },
        ));

        assert_eq!(ticks.into_inner(), 3, "the timer drove three poll ticks");
        assert_eq!(
            scheduler.now(),
            UnixMillis(3 * crate::sync::duration_millis(SyncTimingProfile::CI.poll_cadence)),
            "each tick slept exactly the cadence"
        );
    }
}
