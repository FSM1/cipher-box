//! Quota pre-flight and version retention (blueprint/engine.md "Content plane").
//!
//! Retention is keep-all by default — nothing here evicts a version
//! automatically; the network is authoritative on quota (enforced at the API
//! upload endpoint) and [`pre_flight_quota_check`] only fails *fast*, before
//! bytes move. Reclaiming space is the explicit user op [`plan_prune`], which is
//! pure: it selects retire targets, and the net plane runs the retire.

use core::num::NonZeroU64;

use crate::api::Quota;
use crate::content::PinMode;

/// A pre-flight quota rejection: the hosted account cannot admit `needed_bytes`.
/// A write that takes no hosted byte path never produces this — its bytes live
/// on the member's own provider and are counted, never gated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaExceeded {
    /// Bytes already counted against the account.
    pub used_bytes: u64,
    /// The account's limit.
    pub limit_bytes: u64,
    /// The bytes this upload would add.
    pub needed_bytes: u64,
}

/// Fail fast before bytes move if a hosted upload of `needed_bytes` would exceed
/// the account limit.
///
/// The gate is this write's own byte path, not the account's server-side flag:
/// [`PinMode::External`] sends nothing to the hosted store and so is never
/// gated, while [`PinMode::Dual`] is, because its hosted leg is a real hosted
/// upload however the account is classified. `quota.advisory` is a display hint
/// — it lags the vaulted mode, which is the source of truth, so gating on it
/// admits a hosted upload the ingress then refuses (and refuses an external one
/// it would never see). The API upload endpoint remains the authoritative gate;
/// this is the fail-fast pre-flight, not the enforcement.
pub fn pre_flight_quota_check(
    needed_bytes: u64,
    quota: &Quota,
    mode: PinMode,
) -> Result<(), QuotaExceeded> {
    if matches!(mode, PinMode::External) {
        return Ok(());
    }
    // Saturating so a pathological used+needed can never wrap under the limit.
    if quota.used_bytes.saturating_add(needed_bytes) > quota.limit_bytes {
        return Err(QuotaExceeded {
            used_bytes: quota.used_bytes,
            limit_bytes: quota.limit_bytes,
            needed_bytes,
        });
    }
    Ok(())
}

/// How many versions of a file's content the vault retains — the member-set
/// policy that rides the vault settings record and drives [`plan_prune`].
///
/// `KeepLatest` carries a [`NonZeroU64`]: keeping zero versions would plan the
/// retire of the live version along with its history, so the state is
/// unrepresentable rather than guarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetentionPolicy {
    /// Keep every version within quota (blueprint/engine.md "Content plane").
    #[default]
    KeepAll,
    /// Keep the newest `n` versions; an explicit prune retires the rest.
    KeepLatest(NonZeroU64),
}

/// One retained content version: its root `contentCid` (the retire target, as it
/// rides [`crate::api::ApiClient::retire`]) and its pinned byte size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentVersion {
    /// The version's root content CID (multibase string), the retire target.
    pub content_cid: String,
    /// The version's pinned size in bytes (what a prune reclaims).
    pub size_bytes: u64,
}

/// The result of the explicit prune op: the versions to retire and the bytes
/// reclaiming them frees.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrunePlan {
    /// Content CIDs to retire, oldest first.
    pub retire_targets: Vec<String>,
    /// Bytes freed by retiring [`Self::retire_targets`].
    pub reclaimed_bytes: u64,
}

/// Plan the explicit user-initiated prune: keep the newest `keep_latest`
/// versions and retire the rest. `versions_newest_first` is the version history
/// ordered newest to oldest. Pure and deterministic — the net plane runs the
/// retire against the returned targets. Keeping at least as many as exist prunes
/// nothing (an empty plan).
pub fn plan_prune(versions_newest_first: &[ContentVersion], keep_latest: usize) -> PrunePlan {
    let doomed = versions_newest_first.iter().skip(keep_latest);
    let mut plan = PrunePlan {
        retire_targets: Vec::with_capacity(doomed.len()),
        ..PrunePlan::default()
    };
    // Emit oldest-first so retirement proceeds from the tail of history.
    for version in doomed.rev() {
        plan.retire_targets.push(version.content_cid.clone());
        plan.reclaimed_bytes = plan.reclaimed_bytes.saturating_add(version.size_bytes);
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosted(used: u64, limit: u64) -> Quota {
        Quota {
            used_bytes: used,
            limit_bytes: limit,
            advisory: false,
        }
    }

    #[test]
    fn admits_an_upload_that_fits() {
        assert!(pre_flight_quota_check(100, &hosted(400, 1000), PinMode::Hosted).is_ok());
    }

    #[test]
    fn rejects_an_upload_that_would_exceed_the_limit() {
        let err = pre_flight_quota_check(700, &hosted(400, 1000), PinMode::Hosted).unwrap_err();
        assert_eq!(
            err,
            QuotaExceeded {
                used_bytes: 400,
                limit_bytes: 1000,
                needed_bytes: 700
            }
        );
    }

    #[test]
    fn exactly_filling_the_limit_is_admitted() {
        assert!(pre_flight_quota_check(600, &hosted(400, 1000), PinMode::Hosted).is_ok());
    }

    /// The write's own byte path decides, not the account's advisory flag: a
    /// mode that sends nothing to the hosted store is never gated, and one that
    /// does is gated however the server classified the account.
    #[test]
    fn the_gate_follows_the_byte_path_not_the_advisory_flag() {
        let advisory = Quota {
            used_bytes: 400,
            limit_bytes: 1000,
            advisory: true,
        };
        assert!(
            pre_flight_quota_check(u64::MAX, &advisory, PinMode::External).is_ok(),
            "external sends no hosted byte"
        );
        assert!(
            pre_flight_quota_check(700, &advisory, PinMode::Dual).is_err(),
            "dual's hosted leg is a hosted upload"
        );
        assert!(
            pre_flight_quota_check(700, &advisory, PinMode::Hosted).is_err(),
            "an advisory flag does not open the hosted store"
        );
        assert!(
            pre_flight_quota_check(u64::MAX, &hosted(0, 1000), PinMode::External).is_ok(),
            "a non-advisory account on external is still never gated"
        );
    }

    fn version(cid: &str, size: u64) -> ContentVersion {
        ContentVersion {
            content_cid: cid.into(),
            size_bytes: size,
        }
    }

    #[test]
    fn prune_keeps_the_newest_and_retires_the_rest_oldest_first() {
        // Newest -> oldest: v3, v2, v1.
        let history = vec![version("v3", 30), version("v2", 20), version("v1", 10)];
        let plan = plan_prune(&history, 1);
        assert_eq!(
            plan.retire_targets,
            vec!["v1", "v2"],
            "oldest first, newest kept"
        );
        assert_eq!(plan.reclaimed_bytes, 30);
    }

    #[test]
    fn keeping_all_or_more_prunes_nothing() {
        let history = vec![version("v2", 20), version("v1", 10)];
        assert_eq!(plan_prune(&history, 2), PrunePlan::default());
        assert_eq!(
            plan_prune(&history, 5),
            PrunePlan::default(),
            "keep>len is a no-op"
        );
    }
}
