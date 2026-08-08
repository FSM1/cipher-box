//! Quota pre-flight and version retention (blueprint/engine.md "Content plane").
//!
//! Retention is keep-all by default — nothing here evicts a version
//! automatically; the network is authoritative on quota (enforced at the API
//! upload endpoint) and [`pre_flight_quota_check`] only fails *fast*, before
//! bytes move. Reclaiming space is the explicit user op [`plan_prune`], which is
//! pure: it selects retire targets, and the net plane runs the retire.

use core::num::NonZeroU64;
use std::collections::BTreeSet;

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

/// The result of the explicit prune op: the versions to retire, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrunePlan {
    /// The doomed versions, oldest first. Each is an [`expand_retire_targets`]
    /// input, not a retire target on its own.
    pub retire_targets: Vec<ContentVersion>,
}

impl PrunePlan {
    /// Pinned bytes retiring the expansion of every target frees.
    #[must_use]
    pub fn reclaimed_bytes(&self) -> u64 {
        self.retire_targets.iter().fold(0u64, |total, version| {
            total.saturating_add(version.pinned_bytes)
        })
    }
}

/// Plan the explicit user-initiated prune: keep the newest `keep_latest`
/// versions and retire the rest. `versions_newest_first` is the version history
/// ordered newest to oldest. Pure and deterministic — the net plane runs the
/// retire against the returned targets. Keeping at least as many as exist prunes
/// nothing (an empty plan).
pub fn plan_prune(versions_newest_first: &[ContentVersion], keep_latest: NonZeroU64) -> PrunePlan {
    // Clamped: a keep-count past `usize` on a 32-bit target keeps everything.
    let keep = usize::try_from(keep_latest.get()).unwrap_or(usize::MAX);
    PrunePlan {
        // Oldest first, so retirement proceeds from the tail of history and any
        // prefix of it leaves a valid suffix.
        retire_targets: versions_newest_first
            .iter()
            .skip(keep)
            .rev()
            .cloned()
            .collect(),
    }
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
    /// The manifest is not a version this engine framed: its chunk size is not
    /// this build's, or it accounts for a different pinned total than the plan
    /// quoted. Either way its link list is not the one the retire may name.
    ForeignManifest,
}

/// Where a version's root rides in the CID set that names it. The caller says
/// which, because only the caller knows whether the root is its expansion key
/// (see [`expand_retire_targets`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootPlacement {
    /// The root first, then every leaf in file order — registration.
    First,
    /// Every leaf in file order, then the root — retirement.
    Last,
}

/// Every CID one version pins, spelled as the registry names them.
///
/// The one derivation both the register and the retire path go through: every
/// block is its own accountable pin row (blueprint/api.md "Pin/name registry"),
/// so a retirement naming fewer CIDs than the registration claimed spends
/// account quota forever, and one naming more unpins live blocks.
///
/// # Panics
/// If any CID is not the frozen content-plane CIDv1 framing.
#[must_use]
pub fn version_cids<'a>(
    root_cid: &[u8],
    leaf_cids: impl IntoIterator<Item = &'a [u8]>,
    root: RootPlacement,
) -> Vec<String> {
    let root_cid = encode_content_cid_str(root_cid);
    let leaves = leaf_cids.into_iter().map(encode_content_cid_str);
    match root {
        RootPlacement::First => core::iter::once(root_cid).chain(leaves).collect(),
        RootPlacement::Last => leaves.chain(core::iter::once(root_cid)).collect(),
    }
}

/// One block a retire must name, and what its own pin row charges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireTarget {
    /// The block's content CID (multibase string).
    pub cid: String,
    /// The pinned bytes this block's row accounts for.
    pub pinned_bytes: u64,
}

/// One doomed version's whole retire set and what retiring it frees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expansion {
    /// Every leaf in file order, then the root **last**.
    pub targets: Vec<RetireTarget>,
    /// The pinned bytes the targets account for.
    pub pinned_bytes: u64,
}

impl Expansion {
    /// The targets as the registry names them, in retire order.
    #[must_use]
    pub fn cids(&self) -> Vec<String> {
        self.targets
            .iter()
            .map(|target| target.cid.clone())
            .collect()
    }

    /// Split at the retained boundary: what a retire may still name, and the
    /// targets a retained version holds hostage (deduplicated — a manifest may
    /// repeat a link).
    ///
    /// A pin row is keyed `(account, cid)` and physical unpin fires at global
    /// refcount zero (blueprint/api.md "Pin/name registry"), so retiring a CID a
    /// retained version also names unpins live content. Which versions are
    /// retained is a whole-plan property the prune op decides, never one a
    /// single root's expansion can see. A held target frees nothing, so the
    /// total is re-summed rather than kept in the manifest's closed form.
    #[must_use]
    pub fn split_retained(&self, retained: &BTreeSet<String>) -> (Self, Vec<String>) {
        let (held, retirable): (Vec<RetireTarget>, Vec<RetireTarget>) = self
            .targets
            .iter()
            .cloned()
            .partition(|target| retained.contains(&target.cid));
        (
            Self {
                pinned_bytes: sum_pinned(&retirable),
                targets: retirable,
            },
            held.into_iter()
                .map(|target| target.cid)
                .collect::<BTreeSet<String>>()
                .into_iter()
                .collect(),
        )
    }

    /// What a retire may still name once every retained target is out of it.
    #[must_use]
    pub fn minus_retained(&self, retained: &BTreeSet<String>) -> Self {
        self.split_retained(retained).0
    }
}

/// What a target set accounts for, saturating so a hand-framed manifest can
/// never wrap the figure to a small one.
fn sum_pinned(targets: &[RetireTarget]) -> u64 {
    targets.iter().fold(0u64, |total, target| {
        total.saturating_add(target.pinned_bytes)
    })
}

impl From<DagError> for ExpandError {
    fn from(error: DagError) -> Self {
        Self::Root(error)
    }
}

/// Expand a doomed version's root `contentCid` into the full set of CIDs a
/// retire must name, in retire order: every leaf, then the root **last**.
///
/// The registry deletes rows for exactly the CIDs handed to it and never
/// interprets content, so a root-only retire leaves every sealed leaf pinned and
/// charged forever. `root_block` is the plaintext det-CBOR root that
/// `content_cid` addresses — no key is needed to read the leaf list.
///
/// The root block is the only record of its own leaf list, so it retires last: a
/// drain that dies mid-expansion can re-expand from a root that is still pinned,
/// where a root-first order would leave its leaves unnameable and charged.
///
/// The manifest is held to `profile`'s framing and to `pinned_bytes`, the total
/// the plan quoted, which bounds the link count to what that framing implies —
/// without them a root framed under a `chunkSize` of its own choosing could name
/// up to [`MAX_RESOLVED_RECORD_BYTES`]-worth of CIDs. Neither bound establishes
/// *provenance*: anyone holding the scope's write seed authors both the root and
/// the record `size` the plan quotes from, so the links can still be CIDs of
/// that author's choosing. Keeping those off the retire is
/// [`Expansion::split_retained`]'s job, at the plan that knows what it keeps.
pub fn expand_retire_targets(
    content_cid: &str,
    root_block: &[u8],
    profile: &ContentProfile,
    pinned_bytes: u64,
) -> Result<Expansion, ExpandError> {
    if root_block.len() > MAX_RESOLVED_RECORD_BYTES {
        return Err(DagError::RootTooLarge {
            size: root_block.len(),
            limit: MAX_RESOLVED_RECORD_BYTES,
        }
        .into());
    }
    let expected =
        decode_content_cid_str(content_cid).map_err(|_| ExpandError::MalformedRootCid)?;
    if !is_plane_anchor(content_cid, &expected, ContentPlane::Root) {
        return Err(ExpandError::MalformedRootCid);
    }
    verify_cid(&expected, root_block).map_err(ExpandError::TrustViolation)?;
    let manifest = decode_root(root_block)?;
    if manifest.chunk_size != profile.chunk_size() as u64 {
        return Err(ExpandError::ForeignManifest);
    }

    // Every leaf but the tail carries a whole chunk; the tail carries what is
    // left. Per-target rather than the manifest's closed form, because a
    // subtracted target must be able to drop its own bytes out of the total.
    let leaf_bytes = |index: usize| {
        manifest
            .size
            .saturating_sub((index as u64).saturating_mul(manifest.chunk_size))
            .min(manifest.chunk_size)
            .saturating_add(SEALED_LEAF_OVERHEAD)
    };
    let targets: Vec<RetireTarget> = version_cids(
        &expected,
        manifest.leaf_cids.iter().map(|cid| &cid[..]),
        RootPlacement::Last,
    )
    .into_iter()
    .zip(
        (0..manifest.leaf_cids.len())
            .map(leaf_bytes)
            .chain([root_block.len() as u64]),
    )
    .map(|(cid, pinned_bytes)| RetireTarget { cid, pinned_bytes })
    .collect();

    let accounted = sum_pinned(&targets);
    if accounted != pinned_bytes {
        return Err(ExpandError::ForeignManifest);
    }
    Ok(Expansion {
        targets,
        pinned_bytes: accounted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::dag::{DAG_ROOT_CODEC, assemble};
    use crate::net::REGISTRY_BATCH_MAX;
    use crate::testkit::doomed_version;
    use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};

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
            vec![version("v1", 10), version("v2", 20)],
            "oldest first, newest kept"
        );
        assert_eq!(plan.reclaimed_bytes(), 30);
    }

    /// The figure a prune quotes is the sum of what its own targets account for,
    /// so it cannot drift from the bytes the retire frees.
    #[test]
    fn the_quoted_reclaim_saturates_rather_than_wrapping_to_a_small_figure() {
        let history = vec![
            version("v3", 1),
            version("v2", u64::MAX),
            version("v1", u64::MAX),
        ];
        assert_eq!(plan_prune(&history, keep(1)).reclaimed_bytes(), u64::MAX);
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

    #[test]
    fn expansion_retires_every_leaf_and_puts_the_root_last() {
        let plaintext: Vec<u8> = (0..100u8).collect();
        let (doomed, root_block, leaf_cids) = doomed_version(&plaintext);
        assert!(
            leaf_cids.len() > 1,
            "a multi-chunk version is the normal case"
        );

        let expansion = expand(&doomed, &root_block).expect("expands");
        assert_eq!(
            expansion.cids(),
            leaf_cids
                .into_iter()
                .chain([doomed.content_cid.clone()])
                .collect::<Vec<_>>(),
            "every leaf in file order, then the expansion key last"
        );
        assert_eq!(expansion.pinned_bytes, doomed.pinned_bytes);
    }

    /// The register and the retire path must name the same blocks: naming fewer
    /// on retire spends account quota forever, naming more unpins live blocks.
    /// Only their order differs, and it differs because the caller says so.
    #[test]
    fn the_retire_expansion_names_exactly_what_registration_pinned() {
        let plaintext: Vec<u8> = (0..100u8).collect();
        let (doomed, root_block, _) = doomed_version(&plaintext);
        let root = decode_content_cid_str(&doomed.content_cid).expect("a canonical root address");
        let leaves = decode_root(&root_block)
            .expect("a root manifest")
            .leaf_cid_vecs();

        let registered = version_cids(
            &root,
            leaves.iter().map(Vec::as_slice),
            RootPlacement::First,
        );
        let retired = expand(&doomed, &root_block).expect("expands").cids();

        assert_ne!(registered, retired, "the two orders are not the same order");
        assert_eq!(
            BTreeSet::from_iter(registered.iter().cloned()),
            BTreeSet::from_iter(retired.iter().cloned()),
            "a retire batch names exactly what a register batch claimed"
        );
        assert_eq!(
            registered.len(),
            retired.len(),
            "and names each of them once"
        );
    }

    /// A pin row is keyed `(account, cid)`, so a doomed root naming a CID a
    /// retained version also names would unpin live content.
    #[test]
    fn a_target_a_retained_version_also_names_is_never_retired() {
        let plaintext: Vec<u8> = (0..100u8).collect();
        let (doomed, root_block, leaf_cids) = doomed_version(&plaintext);
        let expansion = expand(&doomed, &root_block).expect("expands");

        let retained = BTreeSet::from([leaf_cids[0].clone()]);
        let reduced = expansion.minus_retained(&retained);

        assert!(
            !reduced.cids().contains(&leaf_cids[0]),
            "the retained leaf is not a retire target"
        );
        assert_eq!(
            reduced.cids(),
            leaf_cids[1..]
                .iter()
                .cloned()
                .chain([doomed.content_cid.clone()])
                .collect::<Vec<_>>(),
            "everything else keeps its retire order"
        );
    }

    /// The figure a prune quotes must be what the retire frees, so a subtracted
    /// target takes its own bytes out of the total rather than leaving the
    /// manifest's closed form standing.
    #[test]
    fn the_reclaim_figure_counts_only_the_targets_a_retire_still_names() {
        for size in [0usize, 1, 15, 16, 17, 40, 100] {
            let (doomed, root_block, leaf_cids) = doomed_version(&vec![3u8; size]);
            let expansion = expand(&doomed, &root_block).expect("expands");

            let all_leaves = BTreeSet::from_iter(leaf_cids.iter().cloned());
            let root_only = expansion.minus_retained(&all_leaves);
            assert_eq!(
                root_only.pinned_bytes,
                root_block.len() as u64,
                "size {size}: an all-aliased expansion frees its root block alone"
            );

            let nothing = expansion.minus_retained(&BTreeSet::new());
            assert_eq!(
                nothing, expansion,
                "size {size}: subtracting nothing changes nothing"
            );

            let whole = BTreeSet::from_iter(expansion.cids());
            assert_eq!(
                expansion.minus_retained(&whole).pinned_bytes,
                0,
                "size {size}: an expansion that frees nothing quotes nothing"
            );
        }
    }

    /// The expansion under the framing the fixture used.
    fn expand(doomed: &ContentVersion, root_block: &[u8]) -> Result<Expansion, ExpandError> {
        expand_retire_targets(
            &doomed.content_cid,
            root_block,
            &ContentProfile::CI,
            doomed.pinned_bytes,
        )
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

        let targets = expand_retire_targets(
            &doomed.content_cid,
            &dag.root_block,
            &profile,
            doomed.pinned_bytes,
        )
        .expect("expands")
        .cids();
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

    /// The plan quotes a pinned total predicted from the framing profile; the
    /// manifest accounts for one measured off the block. A prune may only free
    /// the bytes it reported, so the expansion refuses unless the two agree.
    #[test]
    fn a_manifest_that_cannot_account_for_the_quoted_total_is_refused() {
        for size in [0usize, 1, 15, 16, 17, 40, 100] {
            let (doomed, root_block, _) = doomed_version(&vec![3u8; size]);
            assert_eq!(
                expand(&doomed, &root_block).expect("expands").pinned_bytes,
                doomed.pinned_bytes,
                "size {size}: the two derivations must agree"
            );

            let overstated = ContentVersion {
                pinned_bytes: doomed.pinned_bytes + 1,
                ..doomed.clone()
            };
            assert_eq!(
                expand(&overstated, &root_block),
                Err(ExpandError::ForeignManifest),
                "size {size}: bytes the manifest cannot account for are never retired"
            );
        }
    }

    /// The link count is only pinned to `size` *through* `chunkSize`, which the
    /// manifest carries. A root framed at a chunk size this build never writes
    /// can therefore name a leaf list of its own choosing, so it is refused
    /// before its links are read.
    #[test]
    fn a_manifest_framed_at_a_foreign_chunk_size_is_refused() {
        let leaves = 64usize;
        let leaf_cids: Vec<Vec<u8>> = (0..leaves)
            .map(|i| compute_cid(CONTENT_CID_CODEC, &(i as u64).to_be_bytes()))
            .collect();
        let foreign = ContentProfile::new(1).expect("nonzero");
        let dag = assemble(&leaf_cids, leaves as u64, &foreign).expect("assembles");
        let doomed = ContentVersion {
            content_cid: encode_content_cid_str(&dag.content_cid),
            pinned_bytes: leaves as u64
                + leaves as u64 * SEALED_LEAF_OVERHEAD
                + dag.root_block.len() as u64,
        };
        assert_eq!(
            expand(&doomed, &dag.root_block),
            Err(ExpandError::ForeignManifest),
            "a leaf list this build's framing cannot produce is never retired"
        );
    }

    /// The root block is the expansion key, so a substituted one would retire
    /// CIDs the version never named.
    #[test]
    fn a_block_that_does_not_address_to_its_root_cid_is_refused() {
        let (doomed, root_block, _) = doomed_version(&[1u8; 40]);
        let (other, ..) = doomed_version(&[2u8; 40]);
        assert_ne!(doomed.content_cid, other.content_cid);
        assert!(matches!(
            expand(&other, &root_block),
            Err(ExpandError::TrustViolation(_))
        ));
    }

    /// A leaf CID names a `raw` block, so spelling one as the doomed root must be
    /// refused rather than verified against a root-plane block.
    #[test]
    fn a_root_cid_off_the_dag_cbor_plane_is_refused() {
        let (doomed, root_block, leaf_cids) = doomed_version(&[5u8; 40]);
        let off_plane = ContentVersion {
            content_cid: leaf_cids[0].clone(),
            ..doomed
        };
        assert_eq!(
            expand(&off_plane, &root_block),
            Err(ExpandError::MalformedRootCid)
        );
    }

    #[test]
    fn an_oversized_block_is_refused_before_it_is_decoded() {
        let (doomed, ..) = doomed_version(&[6u8; 40]);
        assert!(matches!(
            expand(&doomed, &vec![0u8; MAX_RESOLVED_RECORD_BYTES + 1]),
            Err(ExpandError::Root(DagError::RootTooLarge { .. }))
        ));
    }

    /// A correctly-addressed block that is not a root manifest must fail closed,
    /// never expand to a bare root that reports the version freed.
    #[test]
    fn a_correctly_addressed_non_manifest_block_is_refused() {
        let junk = b"not a root manifest";
        let addressed = ContentVersion {
            content_cid: encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, junk)),
            pinned_bytes: 0,
        };
        assert!(matches!(
            expand(&addressed, junk),
            Err(ExpandError::Root(_))
        ));
    }
}
