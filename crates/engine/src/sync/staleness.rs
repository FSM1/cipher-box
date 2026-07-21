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

/// Host connectivity as the engine observes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connectivity {
    /// The network is reachable.
    Online,
    /// The network is unreachable (the offline banner rung).
    Offline,
}

/// Classify the staleness rung. The ladder, top to bottom:
///
/// - `Offline` — connectivity is down.
/// - `Reconciling` — a background reconcile is in flight (quiet indicator).
/// - `Stale` — online and idle, but the last success is older than the
///   profile threshold (`stale_after` ≈ 3 missed poll cycles).
/// - `Fresh` — online and within the freshness window.
///
/// A cold cache (`last_success` is `None`) with no reconcile in flight while
/// online is reported as `Reconciling`: the first tick is implied, and the
/// empty-cache cold-start *error* is the caller's separate concern, not a
/// staleness rung.
pub fn classify(
    now: UnixMillis,
    last_success: Option<UnixMillis>,
    reconcile_in_flight: bool,
    connectivity: Connectivity,
    profile: &SyncTimingProfile,
) -> Staleness {
    if connectivity == Connectivity::Offline {
        return Staleness::Offline;
    }
    if reconcile_in_flight {
        return Staleness::Reconciling;
    }
    match last_success {
        None => Staleness::Reconciling,
        Some(last) => {
            let stale_after_ms = duration_ms(profile.stale_after);
            if now.0.saturating_sub(last.0) >= stale_after_ms {
                Staleness::Stale
            } else {
                Staleness::Fresh
            }
        }
    }
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
        && now.0.saturating_sub(pinned_since.0) >= duration_ms(profile.escalation_window)
}

/// A [`core::time::Duration`] as whole milliseconds, saturating (mirrors the
/// scheduler's millisecond clock).
fn duration_ms(duration: core::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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
                true,
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
                true,
                Connectivity::Online,
                &P
            ),
            Staleness::Reconciling
        );
    }

    #[test]
    fn fresh_then_stale_across_the_threshold() {
        let last = UnixMillis(0);
        // 89 s < 90 s → fresh.
        assert_eq!(
            classify(
                UnixMillis(89_000),
                Some(last),
                false,
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
                false,
                Connectivity::Online,
                &P
            ),
            Staleness::Stale
        );
    }

    #[test]
    fn cold_cache_online_is_reconciling_not_an_error_rung() {
        assert_eq!(
            classify(UnixMillis(10_000), None, false, Connectivity::Online, &P),
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
