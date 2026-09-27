//! The staleness ladder and the withheld-update escalation (blueprint/
//! engine.md "Sync core: Staleness ladder"; #33 D4/D7, #38 D2).
//!
//! Availability staleness keeps cached views usable indefinitely — it is never
//! an error. Errors are exactly two things: a trust violation (the adoption
//! gate's job, never surfaced here) and an empty-cache cold start. The ladder
//! is a pure function of the injected clock ([`Scheduler::now`]), the last
//! successful reconcile, and connectivity — the engine never reads a clock
//! directly.
//!
//! The withheld-update escalation is the sharper, shared-scope-only signal:
//! one name pinned past the escalation window *while other resolves succeed*
//! is not mere staleness — it is a targeted stale-view pin (it also covers the
//! pointer-plane network-suppression residual, #38 D2).

use crate::facade::Staleness;
use crate::profile::SyncTimingProfile;
use crate::seams::UnixMillis;
use crate::sync::tick::elapsed_at_least;

/// Host connectivity as the engine observes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connectivity {
    /// The network is reachable.
    Online,
    /// The network is unreachable (the offline banner rung).
    Offline,
}

/// Classify the [`Staleness`] rung, in precedence order: `Offline`, then
/// `Reconciling`, then `Stale`/`Fresh` split on the profile's `stale_after`
/// (≈ 3 missed poll cycles).
///
/// `reconcile_started` is when the pass in flight began; it shows
/// `Reconciling` for one [`SyncTimingProfile::refresh_deadline`] only.
///
/// A cold cache (`last_success` is `None`) with no reconcile in flight while
/// online reports `Reconciling`: the empty-cache cold-start *error* is the
/// caller's separate concern, not a staleness rung.
pub fn classify(
    now: UnixMillis,
    last_success: Option<UnixMillis>,
    reconcile_started: Option<UnixMillis>,
    connectivity: Connectivity,
    profile: &SyncTimingProfile,
) -> Staleness {
    if connectivity == Connectivity::Offline {
        return Staleness::Offline;
    }
    if reconcile_started
        .is_some_and(|started| !elapsed_at_least(now, started, profile.refresh_deadline))
    {
        return Staleness::Reconciling;
    }
    match last_success {
        None => Staleness::Reconciling,
        Some(last) => {
            let stale_after_ms = crate::sync::duration_millis(profile.stale_after);
            if now.0.saturating_sub(last.0) >= stale_after_ms {
                Staleness::Stale
            } else {
                Staleness::Fresh
            }
        }
    }
}

/// The next instant after `now` at which [`classify`] changes rung with no new
/// input: the end of the in-flight rung, or the stale threshold.
pub(crate) fn next_boundary(
    now: UnixMillis,
    last_success: Option<UnixMillis>,
    reconcile_started: Option<UnixMillis>,
    profile: &SyncTimingProfile,
) -> Option<UnixMillis> {
    [
        reconcile_started.map(|started| (started, profile.refresh_deadline)),
        last_success.map(|last| (last, profile.stale_after)),
    ]
    .into_iter()
    .flatten()
    .map(|(since, after)| since.0.saturating_add(crate::sync::duration_millis(after)))
    .filter(|&at| at > now.0)
    .min()
    .map(UnixMillis)
}

/// Whether a shared-scope name pinned since `pinned_since` should raise the
/// withheld-update escalation: shared scope, other resolves succeeding, and the
/// pin older than the escalation window. A non-shared scope or a session where
/// nothing else resolves never escalates (that is ordinary offline staleness).
pub fn withheld_escalation(
    now: UnixMillis,
    pinned_since: UnixMillis,
    is_shared_scope: bool,
    other_resolves_succeeding: bool,
    profile: &SyncTimingProfile,
) -> bool {
    is_shared_scope
        && other_resolves_succeeding
        && now.0.saturating_sub(pinned_since.0)
            >= crate::sync::duration_millis(profile.escalation_window)
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: SyncTimingProfile = SyncTimingProfile::PRODUCTION; // stale_after 90 s, escalation 600 s

    #[test]
    fn offline_beats_every_other_rung() {
        assert_eq!(
            classify(
                UnixMillis(0),
                Some(UnixMillis(0)),
                Some(UnixMillis(0)),
                Connectivity::Offline,
                &P
            ),
            Staleness::Offline
        );
    }

    #[test]
    fn reconcile_in_flight_shows_reconciling() {
        assert_eq!(
            classify(
                UnixMillis(1_000),
                Some(UnixMillis(0)),
                Some(UnixMillis(0)),
                Connectivity::Online,
                &P
            ),
            Staleness::Reconciling
        );
    }

    /// A pass that outruns the refresh deadline reads as the age of the last
    /// success, so a stalled pass cannot hold the indicator on `Reconciling`.
    #[test]
    fn a_reconcile_past_the_refresh_deadline_reads_as_the_last_success() {
        let deadline_ms = crate::sync::duration_millis(P.refresh_deadline);
        let started = Some(UnixMillis(0));
        let rung = |now| {
            classify(
                UnixMillis(now),
                Some(UnixMillis(0)),
                started,
                Connectivity::Online,
                &P,
            )
        };
        assert_eq!(rung(deadline_ms - 1), Staleness::Reconciling);
        assert_eq!(rung(deadline_ms), Staleness::Fresh);
        assert_eq!(
            rung(crate::sync::duration_millis(P.stale_after)),
            Staleness::Stale
        );
    }

    #[test]
    fn the_next_boundary_is_the_nearest_rung_change_ahead() {
        let deadline = crate::sync::duration_millis(P.refresh_deadline);
        let stale = crate::sync::duration_millis(P.stale_after);
        let boundary =
            |now, started| next_boundary(UnixMillis(now), Some(UnixMillis(0)), started, &P);
        assert_eq!(boundary(0, Some(UnixMillis(0))), Some(UnixMillis(deadline)));
        assert_eq!(
            boundary(deadline, Some(UnixMillis(0))),
            Some(UnixMillis(stale)),
            "a boundary reached is not the next one"
        );
        assert_eq!(boundary(stale, None), None, "nothing changes past stale");
    }

    #[test]
    fn fresh_then_stale_across_the_threshold() {
        let last = UnixMillis(0);
        // 89 s < 90 s → fresh.
        assert_eq!(
            classify(
                UnixMillis(89_000),
                Some(last),
                None,
                Connectivity::Online,
                &P
            ),
            Staleness::Fresh
        );
        // 90 s ≥ 90 s → stale.
        assert_eq!(
            classify(
                UnixMillis(90_000),
                Some(last),
                None,
                Connectivity::Online,
                &P
            ),
            Staleness::Stale
        );
    }

    #[test]
    fn cold_cache_online_is_reconciling_not_an_error_rung() {
        assert_eq!(
            classify(UnixMillis(10_000), None, None, Connectivity::Online, &P),
            Staleness::Reconciling
        );
    }

    #[test]
    fn escalation_needs_shared_scope_and_other_successes() {
        // 600 s pinned, shared, others succeeding → escalate.
        assert!(withheld_escalation(
            UnixMillis(600_000),
            UnixMillis(0),
            true,
            true,
            &P
        ));
        // Not shared → never.
        assert!(!withheld_escalation(
            UnixMillis(600_000),
            UnixMillis(0),
            false,
            true,
            &P
        ));
        // Nothing else resolving → ordinary offline staleness, not a targeted pin.
        assert!(!withheld_escalation(
            UnixMillis(600_000),
            UnixMillis(0),
            true,
            false,
            &P
        ));
        // Within the window → not yet.
        assert!(!withheld_escalation(
            UnixMillis(599_000),
            UnixMillis(0),
            true,
            true,
            &P
        ));
    }
}
