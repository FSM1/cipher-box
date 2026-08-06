//! Quota pre-flight and version retention (blueprint/engine.md "Content plane").
//!
//! Retention is keep-all by default — nothing here evicts a version
//! automatically; the network is authoritative on quota (enforced at the API
//! upload endpoint) and [`pre_flight_quota_check`] only fails *fast*, before
//! bytes move. Reclaiming space is the explicit user op [`plan_prune`], which is
//! pure: it selects retire targets, and the net plane runs the retire.

use core::num::NonZeroU64;

use cipherbox_core::content::{decode_content_cid_str, encode_content_cid_str, verify_cid};
use cipherbox_core::error::CodecError;

use super::budget::sealed_total_bytes;
use super::chunk::SEALED_LEAF_OVERHEAD;
use super::dag::{DagError, decode_root};
use super::limits::MAX_RESOLVED_RECORD_BYTES;
use super::profile::ContentProfile;
use super::read::{ContentPlane, is_plane_anchor};
use crate::api::Quota;

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

/// Fail fast before bytes move if a hosted upload of `needed_bytes` would
/// exceed the account limit.
///
/// The gate is `hosted_leg` — whether *this write* puts bytes in the hosted
/// store — not `quota.advisory`, which is a display hint that lags the vaulted
/// mode. Gating on the flag would admit a hosted upload the ingress then refuses
/// and refuse an external one it would never see. The API upload endpoint
/// remains the authoritative gate; this is the fail-fast pre-flight.
pub fn pre_flight_quota_check(
    needed_bytes: u64,
    quota: &Quota,
    hosted_leg: bool,
) -> Result<(), QuotaExceeded> {
    if !hosted_leg {
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
/// rides [`crate::api::ApiClient::retire`]) and the **pinned** bytes retiring it
/// frees.
///
/// Pinned bytes are not the version's plaintext size — the number a version
/// record carries ([`cipherbox_core::seal::Version::size`]). Sealing adds a
/// nonce and a tag to every leaf and stages a root block besides, and pinned
/// bytes are what the registry charges. [`ContentVersion::from_plaintext_size`]
/// is the conversion between the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentVersion {
    /// The version's root content CID (multibase string), the retire target.
    pub content_cid: String,
    /// The version's pinned size in bytes — what a prune reclaims.
    pub pinned_bytes: u64,
}

impl ContentVersion {
    /// Convert a version record's plaintext `size` into the pinned total a
    /// retire frees, under the `profile` the version was framed at. Fails closed
    /// on the flat-DAG ceiling, so a version whose root could never be read back
    /// is never quoted a reclaim figure.
    pub fn from_plaintext_size(
        content_cid: String,
        plaintext_bytes: u64,
        profile: &ContentProfile,
    ) -> Result<Self, DagError> {
        Ok(Self {
            content_cid,
            pinned_bytes: sealed_total_bytes(plaintext_bytes, profile)?,
        })
    }
}

/// The result of the explicit prune op: the versions to retire and the bytes
/// reclaiming them frees.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrunePlan {
    /// The doomed versions' **root** content CIDs, oldest first. Each is an
    /// [`expand_retire_targets`] input, not a retire target on its own.
    pub retire_targets: Vec<String>,
    /// Pinned bytes freed by retiring the expansion of [`Self::retire_targets`].
    pub reclaimed_bytes: u64,
}

/// Plan the explicit user-initiated prune: keep the newest `keep_latest`
/// versions and retire the rest. `versions_newest_first` is the version history
/// ordered newest to oldest. Pure and deterministic — the net plane runs the
/// retire against the returned targets. Keeping at least as many as exist prunes
/// nothing (an empty plan).
pub fn plan_prune(versions_newest_first: &[ContentVersion], keep_latest: NonZeroU64) -> PrunePlan {
    // Clamped: a keep-count past `usize` on a 32-bit target keeps everything.
    let keep = usize::try_from(keep_latest.get()).unwrap_or(usize::MAX);
    let doomed = versions_newest_first.iter().skip(keep);
    let mut plan = PrunePlan {
        retire_targets: Vec::with_capacity(doomed.len()),
        ..PrunePlan::default()
    };
    // Emit oldest-first so retirement proceeds from the tail of history.
    for version in doomed.rev() {
        plan.retire_targets.push(version.content_cid.clone());
        plan.reclaimed_bytes = plan.reclaimed_bytes.saturating_add(version.pinned_bytes);
    }
    plan
}

/// Why a doomed root could not be expanded into its retire targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandError {
    /// The version's `contentCid` is not a canonical `dag-cbor` root address, so
    /// no block can be checked against it.
    MalformedRootCid,
    /// The block does not address to the version's `contentCid`. Reading targets
    /// out of it would retire CIDs this version never named.
    TrustViolation(CodecError),
    /// The block addresses correctly but is not a readable root manifest.
    Root(DagError),
    /// The manifest accounts for a different pinned total than the plan quoted.
    PinnedBytesMismatch {
        /// The doomed version's [`ContentVersion::pinned_bytes`].
        planned: u64,
        /// The total the root block and its link list actually account for.
        manifest: u64,
    },
}

impl From<DagError> for ExpandError {
    fn from(error: DagError) -> Self {
        Self::Root(error)
    }
}

/// Expand a doomed version into the full set of CIDs a retire must name, in
/// retire order: every leaf, then the root **last**.
///
/// The registry deletes rows for exactly the CIDs handed to it and never
/// interprets content, so a root-only retire leaves every sealed leaf pinned and
/// charged forever. `root_block` is the plaintext det-CBOR root that `version`'s
/// `contentCid` addresses — no key is needed to read the leaf list.
///
/// The root block is the only record of its own leaf list, so it retires last: a
/// drain that dies mid-expansion can re-expand from a root that is still pinned,
/// where a root-first order would leave its leaves unnameable and charged.
///
/// Fail-closed throughout. The block is refused past the resolved-block ceiling
/// before it is hashed, verified against `version.content_cid`, decoded, and
/// finally held to the pinned total the plan quoted — a version whose bytes
/// cannot be accounted for is never retired.
pub fn expand_retire_targets(
    version: &ContentVersion,
    root_block: &[u8],
) -> Result<Vec<String>, ExpandError> {
    if root_block.len() > MAX_RESOLVED_RECORD_BYTES {
        return Err(DagError::RootTooLarge {
            size: root_block.len(),
            limit: MAX_RESOLVED_RECORD_BYTES,
        }
        .into());
    }
    let expected =
        decode_content_cid_str(&version.content_cid).map_err(|_| ExpandError::MalformedRootCid)?;
    if !is_plane_anchor(&version.content_cid, &expected, ContentPlane::Root) {
        return Err(ExpandError::MalformedRootCid);
    }
    verify_cid(&expected, root_block).map_err(ExpandError::TrustViolation)?;
    let manifest = decode_root(root_block)?;

    let accounted = manifest
        .size
        .saturating_add((manifest.leaf_cids.len() as u64).saturating_mul(SEALED_LEAF_OVERHEAD))
        .saturating_add(root_block.len() as u64);
    if accounted != version.pinned_bytes {
        return Err(ExpandError::PinnedBytesMismatch {
            planned: version.pinned_bytes,
            manifest: accounted,
        });
    }

    let mut targets = Vec::with_capacity(manifest.leaf_cids.len() + 1);
    targets.extend(
        manifest
            .leaf_cids
            .iter()
            .map(|cid| encode_content_cid_str(cid)),
    );
    targets.push(version.content_cid.clone());
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::dag::{DAG_ROOT_CODEC, assemble};
    use crate::net::REGISTRY_BATCH_MAX;
    use crate::testkit::frame_version;
    use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};
    use cipherbox_core::suite::aead::KEY_LEN;

    fn hosted(used: u64, limit: u64) -> Quota {
        Quota {
            used_bytes: used,
            limit_bytes: limit,
            advisory: false,
        }
    }

    #[test]
    fn admits_an_upload_that_fits() {
        assert!(pre_flight_quota_check(100, &hosted(400, 1000), true).is_ok());
    }

    #[test]
    fn rejects_an_upload_that_would_exceed_the_limit() {
        let err = pre_flight_quota_check(700, &hosted(400, 1000), true).unwrap_err();
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
        assert!(pre_flight_quota_check(600, &hosted(400, 1000), true).is_ok());
    }

    /// The write's own byte path decides, not the account's advisory flag.
    #[test]
    fn the_gate_follows_the_byte_path_not_the_advisory_flag() {
        let advisory = Quota {
            used_bytes: 400,
            limit_bytes: 1000,
            advisory: true,
        };
        assert!(
            pre_flight_quota_check(u64::MAX, &advisory, false).is_ok(),
            "a write with no hosted leg is never gated"
        );
        assert!(
            pre_flight_quota_check(700, &advisory, true).is_err(),
            "an advisory flag does not open the hosted store"
        );
        assert!(
            pre_flight_quota_check(u64::MAX, &hosted(0, 1000), false).is_ok(),
            "nor does a non-advisory one gate what it never receives"
        );
    }

    fn version(cid: &str, pinned: u64) -> ContentVersion {
        ContentVersion {
            content_cid: cid.into(),
            pinned_bytes: pinned,
        }
    }

    fn keep(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).expect("nonzero")
    }

    #[test]
    fn prune_keeps_the_newest_and_retires_the_rest_oldest_first() {
        // Newest -> oldest: v3, v2, v1.
        let history = vec![version("v3", 30), version("v2", 20), version("v1", 10)];
        let plan = plan_prune(&history, keep(1));
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
        for keep_latest in [keep(2), keep(5), keep(u64::MAX)] {
            assert_eq!(
                plan_prune(&history, keep_latest),
                PrunePlan::default(),
                "keeping at least as many as exist retires nothing"
            );
        }
    }

    /// The plaintext size a version record carries is never the pinned size.
    #[test]
    fn the_pinned_size_exceeds_the_plaintext_size_it_is_built_from() {
        let profile = ContentProfile::PRODUCTION;
        let plaintext = 10 * (1 << 20);
        let version = ContentVersion::from_plaintext_size("v1".into(), plaintext, &profile)
            .expect("under the ceiling");
        assert!(
            version.pinned_bytes > plaintext,
            "sealing adds a nonce and a tag per leaf, plus the root block"
        );
    }

    #[test]
    fn a_version_past_the_flat_dag_ceiling_is_never_quoted_a_reclaim_figure() {
        assert!(matches!(
            ContentVersion::from_plaintext_size("v1".into(), u64::MAX, &ContentProfile::PRODUCTION),
            Err(DagError::RootTooLarge { .. })
        ));
    }

    /// A version framed by the same writer the drain uses: the doomed
    /// `ContentVersion`, its root block, and the leaf CIDs as the registry spells
    /// them.
    fn sealed_version(plaintext: &[u8]) -> (ContentVersion, Vec<u8>, Vec<String>) {
        let (_, root_block, content) = frame_version(plaintext, [9u8; KEY_LEN], 11);
        let doomed = ContentVersion::from_plaintext_size(
            encode_content_cid_str(content.content_cid()),
            plaintext.len() as u64,
            &ContentProfile::CI,
        )
        .expect("under the ceiling");
        let leaf_cids = content
            .leaf_cids()
            .iter()
            .map(|cid| encode_content_cid_str(cid))
            .collect();
        (doomed, root_block, leaf_cids)
    }

    #[test]
    fn expansion_retires_every_leaf_and_puts_the_root_last() {
        let plaintext: Vec<u8> = (0..100u8).collect();
        let (doomed, root_block, leaf_cids) = sealed_version(&plaintext);
        assert!(
            leaf_cids.len() > 1,
            "a multi-chunk version is the normal case"
        );

        let expected: Vec<String> = leaf_cids
            .into_iter()
            .chain([doomed.content_cid.clone()])
            .collect();
        assert_eq!(
            expand_retire_targets(&doomed, &root_block).expect("expands"),
            expected,
            "every leaf in file order, then the expansion key last"
        );
    }

    /// At the frozen 1 MiB framing a 1 GiB version expands past the registry's
    /// batch cap, so a prune spanning several batches is the normal case rather
    /// than an edge one — and the root must still land in the last batch.
    #[test]
    fn a_gibibyte_version_expands_past_one_retire_batch_with_the_root_last() {
        let profile = ContentProfile::PRODUCTION;
        let leaves = 1024usize;
        // Address-only: a 1 GiB version's leaf *blocks* are irrelevant to an
        // expansion, which reads the root's link list alone.
        let leaf_cids: Vec<Vec<u8>> = (0..leaves)
            .map(|i| compute_cid(CONTENT_CID_CODEC, &(i as u64).to_be_bytes()))
            .collect();
        let plaintext_len = leaves as u64 * profile.chunk_size() as u64;
        let dag = assemble(&leaf_cids, plaintext_len, &profile).expect("assembles");
        let doomed = ContentVersion::from_plaintext_size(
            encode_content_cid_str(&dag.content_cid),
            plaintext_len,
            &profile,
        )
        .expect("under the ceiling");

        let targets = expand_retire_targets(&doomed, &dag.root_block).expect("expands");
        assert_eq!(targets.len(), leaves + 1);
        assert!(
            targets.len() > REGISTRY_BATCH_MAX,
            "the expansion cannot ride one retire call"
        );
        assert_eq!(
            targets.last().expect("non-empty"),
            &doomed.content_cid,
            "the root rides the final batch, after every leaf it names"
        );
    }

    /// The plan-time figure derives the pinned total from the framing profile;
    /// the drain-time figure measures it off the manifest. A prune that quotes
    /// one and frees the other is the misreport, so the expansion refuses to
    /// proceed unless they agree.
    #[test]
    fn a_planned_reclaim_that_the_manifest_cannot_account_for_is_refused() {
        for size in [0usize, 1, 15, 16, 17, 40, 100] {
            let (doomed, root_block, _) = sealed_version(&vec![3u8; size]);
            assert!(
                expand_retire_targets(&doomed, &root_block).is_ok(),
                "size {size}: the two derivations must agree"
            );

            let overstated = ContentVersion {
                pinned_bytes: doomed.pinned_bytes + 1,
                ..doomed.clone()
            };
            assert_eq!(
                expand_retire_targets(&overstated, &root_block),
                Err(ExpandError::PinnedBytesMismatch {
                    planned: doomed.pinned_bytes + 1,
                    manifest: doomed.pinned_bytes,
                }),
                "size {size}: bytes the manifest cannot account for are never retired"
            );
        }
    }

    /// The root block is the expansion key, so a substituted one would retire
    /// CIDs the version never named.
    #[test]
    fn a_block_that_does_not_address_to_its_root_cid_is_refused() {
        let (doomed, root_block, _) = sealed_version(&[1u8; 40]);
        let (other, ..) = sealed_version(&[2u8; 40]);
        assert_ne!(doomed.content_cid, other.content_cid);
        assert!(matches!(
            expand_retire_targets(&other, &root_block),
            Err(ExpandError::TrustViolation(_))
        ));
    }

    /// A leaf CID names a `raw` block, so spelling one as the doomed root must be
    /// refused rather than verified against a root-plane block.
    #[test]
    fn a_root_cid_off_the_dag_cbor_plane_is_refused() {
        let (_, root_block, leaf_cids) = sealed_version(&[5u8; 40]);
        let off_plane = ContentVersion {
            content_cid: leaf_cids[0].clone(),
            pinned_bytes: 0,
        };
        assert_eq!(
            expand_retire_targets(&off_plane, &root_block),
            Err(ExpandError::MalformedRootCid)
        );
    }

    #[test]
    fn an_oversized_block_is_refused_before_it_is_decoded() {
        let (doomed, ..) = sealed_version(&[6u8; 40]);
        assert!(matches!(
            expand_retire_targets(&doomed, &vec![0u8; MAX_RESOLVED_RECORD_BYTES + 1]),
            Err(ExpandError::Root(DagError::RootTooLarge { .. }))
        ));
    }

    /// A correctly-addressed block that is not a root manifest must fail closed,
    /// never expand to a bare root that reports the version freed.
    #[test]
    fn a_correctly_addressed_non_manifest_block_is_refused() {
        let junk = b"not a root manifest";
        let doomed = ContentVersion {
            content_cid: encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, junk)),
            pinned_bytes: 0,
        };
        assert!(matches!(
            expand_retire_targets(&doomed, junk),
            Err(ExpandError::Root(_))
        ));
    }
}
