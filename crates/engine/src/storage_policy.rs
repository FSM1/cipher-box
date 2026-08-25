//! The storage policy — the per-device split of measured storage headroom
//! (CONTEXT.md "Storage policy"; blueprint/engine.md "Host seams").
//!
//! Distinct from the [sync timing profile](crate::SyncTimingProfile), which is
//! a named constant set: a measured byte count has no name. The split is
//! computed once at construction from a headroom figure the host measures, so
//! no staging read-modify-write ever queries the host mid-flight.
//!
//! Origin eviction is all-or-nothing (Storage Standard §7), so a read cache
//! that grows to fill the quota takes the op queue and every staged byte with
//! it. The cache is therefore the one consumer that gets a ceiling, reserved
//! off headroom before the staging fraction; the op queue, snapshot cache, and
//! floors stay demand-driven with first claim on what the fractions leave.

/// The platform-fixed caps and fractions the split is computed from.
///
/// Fractions are integer percents: the engine reads no floats, so one headroom
/// figure always yields one budget on every host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoragePlatform {
    /// Hard ceiling on the staging budget however large headroom is.
    pub staging_cap_bytes: u64,
    /// Percent of post-reservation headroom the staging budget may take.
    pub staging_percent: u32,
    /// Hard ceiling on the read cache's reservation.
    pub cache_cap_bytes: u64,
    /// Percent of headroom reserved for the read cache.
    pub cache_percent: u32,
}

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

impl StoragePlatform {
    /// Browser origin storage: a single quota shared by every consumer, so the
    /// staging fraction is the larger half of what the cache reservation leaves.
    pub const WEB: Self = Self {
        staging_cap_bytes: GIB,
        staging_percent: 50,
        cache_cap_bytes: 512 * MIB,
        cache_percent: 10,
    };

    /// The desktop data volume. The lower fraction is not caution: sealed FUSE
    /// write-spill files double the peak footprint of a staged upload
    /// (blueprint/desktop.md), so 25% of headroom occupies about the same share
    /// of the volume as web's single-copy 50%.
    pub const DESKTOP: Self = Self {
        staging_cap_bytes: 16 * GIB,
        staging_percent: 25,
        cache_cap_bytes: 2 * GIB,
        cache_percent: 10,
    };
}

/// Where a [`StoragePolicy`]'s budgets came from. Both states admit the same
/// uploads; they differ only in what a caller may say about a rejection
/// (CONTEXT.md "Storage policy").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Headroom {
    /// The host reported a byte figure and the budgets are its split.
    Measured,
    /// The host could not measure headroom.
    Unmeasured,
}

/// The measured storage split, injected whole at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoragePolicy {
    /// Staged upload bytes ceiling: past it new uploads fail fast, while
    /// metadata ops queue unbounded (#33 D6).
    pub staging_budget_bytes: u64,
    /// The sealed-block read cache's ceiling, reserved off headroom before the
    /// staging fraction and enforced by the cache itself.
    pub read_cache_ceiling_bytes: u64,
    /// The platform's hard staging cap this split was computed under. Carried so
    /// a refused write can say *which* limit it hit — the platform ceiling this
    /// device will never exceed, or a budget this device's measured headroom cut
    /// below it. The two call for different user actions.
    pub staging_cap_bytes: u64,
    /// Where the budgets above came from.
    pub headroom: Headroom,
}

impl StoragePolicy {
    /// Split `headroom_bytes` under `platform`'s caps and fractions.
    ///
    /// There is deliberately **no floor-up**: a device with little headroom
    /// honestly gets a small budget and an honest over-budget rejection,
    /// rather than a promised ceiling the host cannot honour.
    pub fn measured(platform: StoragePlatform, headroom_bytes: u64) -> Self {
        let read_cache_ceiling_bytes =
            percent_of(headroom_bytes, platform.cache_percent).min(platform.cache_cap_bytes);
        let stageable = headroom_bytes.saturating_sub(read_cache_ceiling_bytes);
        Self {
            staging_budget_bytes: percent_of(stageable, platform.staging_percent)
                .min(platform.staging_cap_bytes),
            read_cache_ceiling_bytes,
            staging_cap_bytes: platform.staging_cap_bytes,
            headroom: Headroom::Measured,
        }
    }

    /// The policy for a host that cannot measure headroom: zero budgets —
    /// inventing one is the floor-up this policy rules out — and
    /// [`Headroom::Unmeasured`] so a rejection says "unknown", not "full".
    pub const UNMEASURED: Self = Self {
        staging_budget_bytes: 0,
        read_cache_ceiling_bytes: 0,
        staging_cap_bytes: 0,
        headroom: Headroom::Unmeasured,
    };

    /// CI policy: a staging budget small enough that budget exhaustion is
    /// reachable in a test (blueprint/testing.md "The DX hook").
    pub const CI: Self = Self {
        staging_budget_bytes: 256 * 1024,
        read_cache_ceiling_bytes: 256 * 1024,
        staging_cap_bytes: 256 * 1024,
        headroom: Headroom::Measured,
    };

    /// The slice of the staging budget preserved dead letters may hold.
    ///
    /// A preserved version's blocks are staged bytes like any other, so without
    /// a ceiling of their own each preserved loser permanently shrinks what
    /// `beginWrite` can admit — a device losing races through an outage ends up
    /// refusing every new upload with nothing but dead letters to show for the
    /// budget. This is the share it can lose that way.
    #[must_use]
    pub fn preserved_budget_bytes(&self) -> u64 {
        percent_of(self.staging_budget_bytes, PRESERVED_PERCENT)
    }
}

/// Percent of the staging budget preserved dead letters may hold. Leaves the
/// larger share for live writes on any device, measured or small.
const PRESERVED_PERCENT: u32 = 25;

/// `bytes * percent / 100` in u128, so a large headroom cannot wrap.
fn percent_of(bytes: u64, percent: u32) -> u64 {
    u64::try_from(u128::from(bytes) * u128::from(percent) / 100).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    #[test]
    fn a_generous_headroom_lands_on_the_platform_cap() {
        let web = StoragePolicy::measured(StoragePlatform::WEB, 64 * GIB);
        assert_eq!(web.staging_budget_bytes, GIB);
        assert_eq!(web.read_cache_ceiling_bytes, 512 * MIB);

        let desktop = StoragePolicy::measured(StoragePlatform::DESKTOP, 1024 * GIB);
        assert_eq!(desktop.staging_budget_bytes, 16 * GIB);
        assert_eq!(desktop.read_cache_ceiling_bytes, 2 * GIB);
    }

    #[test]
    fn the_cache_reservation_comes_off_headroom_before_the_staging_fraction() {
        // 2 GiB headroom: 10% reserves 204.8 MiB, and staging takes half of
        // what is left rather than half of the whole.
        let headroom = 2 * GIB;
        let policy = StoragePolicy::measured(StoragePlatform::WEB, headroom);
        assert_eq!(policy.read_cache_ceiling_bytes, headroom / 10);
        assert_eq!(
            policy.staging_budget_bytes,
            (headroom - headroom / 10) / 2,
            "the fraction applies to post-reservation headroom"
        );
        assert!(
            policy.staging_budget_bytes < StoragePlatform::WEB.staging_cap_bytes,
            "2 GiB of headroom no longer reaches the 1 GiB cap"
        );
    }

    #[test]
    fn a_tiny_headroom_yields_a_tiny_budget_and_never_floors_up() {
        let policy = StoragePolicy::measured(StoragePlatform::WEB, 1000);
        assert_eq!(policy.read_cache_ceiling_bytes, 100);
        assert_eq!(policy.staging_budget_bytes, 450);
    }

    #[test]
    fn a_measured_zero_headroom_yields_no_budget_and_stays_measured() {
        let policy = StoragePolicy::measured(StoragePlatform::WEB, 0);
        assert_eq!(policy.staging_budget_bytes, 0);
        assert_eq!(policy.read_cache_ceiling_bytes, 0);
        assert_eq!(policy.headroom, Headroom::Measured);
    }

    #[test]
    fn an_unmeasurable_host_is_distinguishable_from_a_full_one() {
        // Same budgets — no floor-up invents one — but the two are not the
        // same state, and only one of them means "the disk is full".
        assert_eq!(
            StoragePolicy::UNMEASURED.staging_budget_bytes,
            StoragePolicy::measured(StoragePlatform::WEB, 0).staging_budget_bytes
        );
        assert_eq!(StoragePolicy::UNMEASURED.headroom, Headroom::Unmeasured);
        assert_ne!(
            StoragePolicy::UNMEASURED,
            StoragePolicy::measured(StoragePlatform::WEB, 0)
        );
    }

    #[test]
    fn a_headroom_near_the_integer_ceiling_does_not_wrap() {
        let policy = StoragePolicy::measured(StoragePlatform::DESKTOP, u64::MAX);
        assert_eq!(policy.staging_budget_bytes, 16 * GIB);
        assert_eq!(policy.read_cache_ceiling_bytes, 2 * GIB);
    }

    #[test]
    fn every_shipped_platform_splits_within_its_headroom() {
        for platform in [StoragePlatform::WEB, StoragePlatform::DESKTOP] {
            assert!(platform.staging_percent <= 100 && platform.cache_percent <= 100);
            // The two claims come off one headroom figure, so together they must
            // not promise more storage than was measured.
            let policy = StoragePolicy::measured(platform, 1 << 40);
            assert!(policy.staging_budget_bytes + policy.read_cache_ceiling_bytes <= 1 << 40);
        }
    }

    #[test]
    fn ci_keeps_budget_exhaustion_reachable() {
        assert!(StoragePolicy::CI.staging_budget_bytes > 0);
        assert!(
            StoragePolicy::CI.staging_budget_bytes <= 1024 * 1024,
            "CI budget must be small enough to exhaust in a test"
        );
    }
}
