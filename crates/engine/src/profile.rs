//! The sync timing profile — environment-scoped timing policy
//! (blueprint/engine.md "Sync core", blueprint/testing.md "The DX hook").

use core::time::Duration;

/// The environment-scoped bundle of sync timing policy (#33 D3).
///
/// Policy is injected: the engine never hardcodes a timing constant — every
/// TTL, cadence, and threshold reads from the profile handed to the
/// constructor. The profile is the CI-DX hook: the [`CI`] profile makes
/// cross-client e2e flows run at speed, the [`PRODUCTION`] profile is the
/// shipped policy.
///
/// There is deliberately **no `Default`**: v1 fell into a silent 5-minute
/// library default through an unset TTL, so every construction site states
/// its profile explicitly and [`record_ttl`] is always a real value — never
/// zero, never unset.
///
/// [`CI`]: SyncTimingProfile::CI
/// [`PRODUCTION`]: SyncTimingProfile::PRODUCTION
/// [`record_ttl`]: SyncTimingProfile::record_ttl
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncTimingProfile {
    /// TTL embedded in every published IPNS record. Always explicit;
    /// independent of the 90-day EOL.
    pub record_ttl: Duration,
    /// Focus-window poll tick cadence.
    pub poll_cadence: Duration,
    /// Staleness-ladder threshold: a view unrefreshed this long shows the
    /// stale badge (~3 missed poll cycles per #33 D4).
    pub stale_after: Duration,
    /// Withheld-update escalation window: a shared-scope name pinned this
    /// long while other resolves succeed raises the stronger warning
    /// (#33 D7).
    pub escalation_window: Duration,
    /// Scope-pointer consult interval — polled, not fallback (#38 D4);
    /// bounds the read-only-survivor residual.
    pub pointer_consult_interval: Duration,
    /// Idle cadence of the lazy-wave sweep job
    /// ([`run_sweep_job`](crate::rotation::run_sweep_job)). Deliberately far
    /// coarser than [`poll_cadence`]: the sweep is background hygiene that
    /// ordinary writes advance for free, and it shares the record transport
    /// with the focus-window tick.
    ///
    /// [`poll_cadence`]: SyncTimingProfile::poll_cadence
    pub sweep_cadence: Duration,
    /// Ceiling on the vault settings load. A settings record that will not
    /// resolve must never block cold start, so once this elapses the load
    /// yields the device's last-known-good settings, or the documented defaults
    /// where it has none (v1's 10 s, carried forward).
    pub settings_load_budget: Duration,
}

impl SyncTimingProfile {
    /// Shipped policy: TTL 1 minute, 30 s poll (#33 D3).
    ///
    /// `escalation_window`, `pointer_consult_interval` and `sweep_cadence`
    /// are placeholders pending the measurement process fixed in
    /// blueprint/testing.md ("The profile is where measured constants land");
    /// each lands as a profile-constant change with its measurement linked.
    pub const PRODUCTION: Self = Self {
        record_ttl: Duration::from_secs(60),
        poll_cadence: Duration::from_secs(30),
        stale_after: Duration::from_secs(90),
        escalation_window: Duration::from_secs(600),
        pointer_consult_interval: Duration::from_secs(30),
        sweep_cadence: Duration::from_secs(900),
        settings_load_budget: Duration::from_secs(10),
    };

    /// CI policy: record TTL 1–5 s (small but nonzero) and compressed
    /// cadences (blueprint/testing.md "The DX hook").
    pub const CI: Self = Self {
        record_ttl: Duration::from_secs(2),
        poll_cadence: Duration::from_secs(1),
        stale_after: Duration::from_secs(3),
        escalation_window: Duration::from_secs(5),
        pointer_consult_interval: Duration::from_secs(1),
        sweep_cadence: Duration::from_secs(2),
        settings_load_budget: Duration::from_secs(1),
    };
}

#[cfg(test)]
// These tests deliberately assert on constants: they are the guard-rail
// that a future edit to a profile value cannot drift silently past the
// blueprint's ranges.
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    #[test]
    fn production_matches_design_values() {
        let p = SyncTimingProfile::PRODUCTION;
        assert_eq!(
            p.record_ttl,
            Duration::from_secs(60),
            "TTL 1 minute per #33 D3"
        );
        assert_eq!(
            p.poll_cadence,
            Duration::from_secs(30),
            "30 s poll per #33 D3"
        );
        assert_eq!(
            p.stale_after,
            Duration::from_secs(90),
            "stale badge after ~3 missed 30 s cycles"
        );
    }

    #[test]
    fn ci_ttl_is_small_but_nonzero() {
        let ttl = SyncTimingProfile::CI.record_ttl;
        assert!(
            ttl >= Duration::from_secs(1) && ttl <= Duration::from_secs(5),
            "CI record TTL must be 1-5 s per blueprint/testing.md"
        );
    }

    #[test]
    fn the_sweep_idles_coarser_than_the_focus_window_tick() {
        for profile in [SyncTimingProfile::PRODUCTION, SyncTimingProfile::CI] {
            assert!(
                profile.sweep_cadence > profile.poll_cadence,
                "background hygiene must not contend with interactive polling"
            );
        }
    }

    #[test]
    fn every_duration_is_nonzero_in_both_profiles() {
        for profile in [SyncTimingProfile::PRODUCTION, SyncTimingProfile::CI] {
            assert!(
                !profile.record_ttl.is_zero(),
                "TTL is always explicit, never zero"
            );
            assert!(!profile.poll_cadence.is_zero());
            assert!(!profile.stale_after.is_zero());
            assert!(!profile.escalation_window.is_zero());
            assert!(!profile.pointer_consult_interval.is_zero());
            assert!(!profile.sweep_cadence.is_zero());
            assert!(
                !profile.settings_load_budget.is_zero(),
                "a zero budget would time out every settings load"
            );
        }
    }
}
