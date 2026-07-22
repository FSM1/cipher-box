//! Owner-revocation eager cascade — the fresh-seed descendant re-key that
//! **completes** a read revoke (blueprint/engine.md "rotateScope", L243-252;
//! the **eager set law** #26 D2 as amended by #38 D5).
//!
//! # What the cascade is
//!
//! On an **owner read-revocation**, `rotateScope` must fully re-key the rotated
//! scope root **plus every transitively-reachable descendant scope root**, each
//! with a **fresh random override seed** — grant blobs re-sealed for the
//! committed set, owner blob, history-link ratchet, and ascent link under the
//! **parent's new derivation**. Cost is O(descendant scope count), never tree
//! size. This module is that whole rotation: [`cascade_rotate_scope`] re-keys the
//! root (the thread head) and then walks the descendant tree top-down, re-keying
//! every descendant through the shared [`reseal_scope_root`] helper with
//! `prev = Some(fresh seed)`.
//!
//! # Why the fresh-seed cascade — and only it — completes a revoke
//!
//! A party who cached a *descendant* scope root's override seed can open that
//! descendant's records at **any** epoch: the descendant's structure keys derive
//! from its own override seed, and the epoch lives only in the AAD. Raising the
//! epoch floor and letting the **sweep** converge each descendant does **not**
//! lock that party out — the sweep re-seals metadata reusing each descendant's
//! **existing** seed (`prev = None`), so a floor-raise + sweep merely walks the
//! revoked reader's cached seed forward to the new epoch. Only minting a
//! **fresh** seed per descendant — this cascade — actually revokes the cached
//! access. This is the cross-slice invariant: **revocation re-keys descendants
//! via the fresh-seed cascade, never via floor-raise + sweep** (the seed changes;
//! it is not an epoch bump over the same seed).
//!
//! # Top-down seed threading
//!
//! A descendant's ascent link is sealed to a keypair derived from its **parent
//! node seed** = `node_seed(parent_override_seed, child_scope_id)`
//! (`crates/engine/src/gate/adoption.rs`, the ascent-authority derive-and-verify).
//! When the parent is re-keyed to a fresh override seed, that parent node seed
//! changes, so the child's ascent link **must** be re-sealed under the parent's
//! **new** derivation — else an ancestor descending with the parent's new seed
//! could not reach the child, and (worse) the child's ascent link would still
//! open under the parent's *stale* seed, leaving a revoked ancestor a path in.
//! The cascade therefore walks **top-down**, minting the root's fresh seed first
//! and threading each parent's freshly-minted seed to its children. The
//! [`CascadeTarget`] a descendant resolves to deliberately carries **no**
//! `parent_node_seed`: it is always threaded, never taken from the descendant's
//! own (stale) published record.
//!
//! # Fail-closed completeness
//!
//! An owner-revocation rotation that skips any reachable descendant is a **silent
//! revocation hole**, not staleness. The walk mirrors [`enumerate_eager_set`]'s
//! discipline — canonicalized frontiers, a `scope_id`-keyed visited set for
//! diamond/cycle termination, and a **hard abort** naming the first descendant it
//! cannot resolve, re-seal, publish, or floor-raise. It never returns a partial
//! [`CascadeOutcome`] a caller could mistake for a complete revoke. Some durable
//! re-keys may already have landed before an abort (there is no distributed
//! transaction); that is safe and retryable — every re-key is monotonic (a fresh
//! seed at a higher epoch) — and the `Err` tells the caller the revoke is
//! incomplete and must be retried, so success is never *claimed* on a partial
//! cascade.
//!
//! # Determinism
//!
//! Entropy enters only through the [`Entropy`] seam (every fresh seed) and time
//! only through the [`Scheduler`] seam (the enqueued sweep); the walk itself reads
//! no clock and samples no randomness of its own. The sole impure edges are the
//! injected [`CascadeResealResolver`] (resolve + gate + unseal a descendant's
//! re-seal material) and [`ScopeRootPublisher`] (CAS-publish) — the same two
//! edges `rotate_scope` and the sweep carry. The real network/gate wiring of the
//! resolver is #745/#746; this slice fakes it and proves the cascade in
//! simulation.
//!
//! [`enumerate_eager_set`]: super::eager_set::enumerate_eager_set

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use cipherbox_core::kdf;
use cipherbox_core::seal::{ChildScopeRef, GrantLedgerEntry, GrantSetCommitment, SignedSealed};
use cipherbox_core::suite::ecdsa::SIGNATURE_LEN as ECDSA_SIG_LEN;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::X25519Public;

use super::eager_set::ResolveFailure;
use super::reseal::{
    CommittedSet, PrevEpochSeed, ResealError, ResealSeeds, ScopeRootIdentity, reseal_scope_root,
};
use super::rotate::{
    ResealedScopeRoot, RotateScopePlan, ScopeRootPublishError, ScopeRootPublisher,
};
use crate::entropy::Entropy;
use crate::hex::hex_lower;
use crate::seams::{BoxedTask, FloorStore, Scheduler, SeamError};

/// One descendant scope root's current re-seal material, as resolved from its
/// published record — everything [`reseal_scope_root`] needs **except** the
/// parent node seed.
///
/// The omission is deliberate and load-bearing: the cascade re-seals each
/// descendant's ascent link under its **parent's freshly-minted** derivation
/// (`node_seed(parent_fresh_seed, child_scope_id)`), threaded top-down — never
/// under the descendant's own stale published parent seed. Carrying a
/// `parent_node_seed` here would invite re-sealing under the wrong (stale)
/// derivation, the exact bug the cascade exists to avoid (contrast
/// [`SweepTarget`](super::sweep::SweepTarget), which *does* carry it because the
/// sweep reuses the published derivation rather than threading a new one).
///
/// Owns its secrets so the cascade is their terminal owner: the seed fields are
/// [`Zeroizing`] and the pseudonym signer zeroizes on drop. Seeds are handed to
/// `reseal_scope_root` **by borrow**; that callee never zeroes caller-owned
/// buffers (AGENTS.md rule 7).
pub struct CascadeTarget {
    /// The envelope format+suite version.
    pub v: u64,
    /// The scope-root node id (== scope id).
    pub scope_id: [u8; 16],
    /// The scope root's opaque `ipnsName` bytes.
    pub ipns_name: Vec<u8>,
    /// The published record's current read epoch — the new record publishes at
    /// `+ 1`, and this seed+epoch become the fresh history link's prior.
    pub current_read_epoch: u64,
    /// The vault owner's X25519 encryption-subkey public (owner-blob recipient).
    pub owner_enc_pub: X25519Public,
    /// The owner-committed writer pseudonym signer (re-sealer identity).
    pub pseudonym_signer: Ed25519Signer,
    /// The scope's **current** override (read scope) seed — becomes the fresh
    /// history link's prior; the cascade mints a new seed to replace it.
    pub override_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The write-plane scope seed (unchanged by a read-plane rotation).
    pub write_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The stable per-scope pointer read key carried in every grant blob.
    pub pointer_read_key: Zeroizing<[u8; SECRET_LEN]>,
    /// The write epoch (unchanged by a read-plane rotation).
    pub write_epoch: u64,
    /// The owner-signed, epoch-free commitment.
    pub commitment: GrantSetCommitment,
    /// The 64-byte compact ECDSA owner signature over `commitment`.
    pub commitment_sig: [u8; ECDSA_SIG_LEN],
    /// The authoritative grant ledger (one blob re-wrapped per entry).
    pub grant_ledger: Vec<GrantLedgerEntry>,
    /// The opaque write-plane history-link blob (carried through).
    pub write_history_link: Vec<u8>,
    /// This scope root's own direct-child-scope index — the next-level
    /// enumeration adjacency the walk descends into.
    pub direct_child_scope_index: Vec<ChildScopeRef>,
    /// The scope's existing per-epoch history links, carried verbatim (the
    /// cascade appends one fresh link on the epoch bump).
    pub carried_history_links: Vec<SignedSealed>,
}

/// The impure edge that resolves a descendant scope root's current re-seal
/// material — the cascade's analogue of the eager-set walk's `ChildIndexResolver`
/// and the sweep's [`SweepResolver`](super::sweep::SweepResolver). Resolve +
/// adoption-gate + unseal live behind this trait; the real network/gate wiring is
/// #745/#746 and tests fake it. A resolve either yields the full
/// [`CascadeTarget`] or a fail-closed [`ResolveFailure`] — a partial or
/// gate-failing record is never a work-list entry.
pub trait CascadeResealResolver {
    /// Resolve `scope`'s current re-seal material, or a fail-closed
    /// [`ResolveFailure`] if its record cannot be authoritatively obtained.
    ///
    /// # Binding contract (obligation on the real resolver, #745/#746)
    ///
    /// `scope`'s `ipns_name` is the **sole gated identity edge** (the adoption
    /// gate binds `ipns_name -> record` via the Ed25519 key derived from the
    /// name). The returned material's `ipns_name` — the CAS **publish**
    /// destination — MUST be that gated name, equal to `commitment.ipns_name`, and
    /// MUST NOT be swayed by any network-supplied hint. The cascade re-seals and
    /// publishes under the enumerated parent-index `scope_id` (never a
    /// resolver-returned one), so a mismatched name/commitment could only mint a
    /// record its own resolve-time gate rejects — but binding the two here keeps
    /// that fail-closed at the source.
    async fn resolve(&self, scope: &ChildScopeRef) -> Result<CascadeTarget, ResolveFailure>;
}

/// One scope root re-keyed by the cascade: its id and the epochs it now sits at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyedScope {
    /// The scope-root node id (== scope id).
    pub scope_id: [u8; 16],
    /// The new read epoch the scope was cut to (`current_read_epoch + 1`).
    pub new_read_epoch: u64,
    /// The durable `minReadEpoch` floor after the raise (`>= new_read_epoch`).
    pub epoch_floor: u64,
}

/// A completed owner-revocation cascade. Holding one is proof every reachable
/// descendant was re-keyed with a fresh seed — an incomplete cascade returns
/// [`CascadeError`] instead. `rekeyed[0]` is always the rotated root; the rest
/// are its descendants in the deterministic top-down walk order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CascadeOutcome {
    /// Every re-keyed scope root, root first, then descendants (walk order).
    pub rekeyed: Vec<RekeyedScope>,
}

impl CascadeOutcome {
    /// The number of descendant scope roots re-keyed (excludes the root).
    pub fn descendant_count(&self) -> usize {
        self.rekeyed.len().saturating_sub(1)
    }
}

/// A fail-closed cascade failure. Returned instead of a partial [`CascadeOutcome`]
/// whenever the cascade cannot prove every reachable descendant was re-keyed —
/// the completeness guarantee. Each variant names the offending scope.
/// [`CascadeError::is_retryable`] distinguishes an availability stall from a
/// trust violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CascadeError {
    /// A reachable descendant's re-seal material could not be authoritatively
    /// resolved (gate rejection or host unavailability), so the cascade is not
    /// provably complete.
    Resolve {
        /// The descendant scope root that could not be resolved.
        scope_id: [u8; 16],
        /// Why the resolve failed.
        reason: ResolveFailure,
    },
    /// Re-sealing a scope root failed a trust invariant (divergent ledger,
    /// uncommitted signer, unusable recipient key) or entropy failed. Nothing was
    /// published for it. Trust rejections are fatal; entropy is retryable.
    Reseal {
        /// The scope that could not be legitimately re-sealed.
        scope_id: [u8; 16],
        /// The underlying re-seal rejection.
        error: ResealError,
    },
    /// A re-sealed record did not land (register-first/PUT failed, or a concurrent
    /// writer won the CAS). For a revocation the fresh seed MUST install, so both
    /// failure modes abort — a lost race is fatal to *this* attempt, not tolerated
    /// as it is in the idempotent sweep. Availability, retryable.
    Publish {
        /// The scope whose record did not land.
        scope_id: [u8; 16],
        /// The publish failure.
        error: ScopeRootPublishError,
    },
    /// The durable epoch floor could not be raised after a confirmed publish. The
    /// record is published (no lockout); the cut completes on retry. Retryable.
    Floor {
        /// The scope whose floor could not be raised.
        scope_id: [u8; 16],
        /// The underlying seam error.
        error: SeamError,
    },
    /// A scope's read epoch is exhausted (`current_read_epoch == u64::MAX`).
    /// Rotating would reuse the epoch with fresh key material, violating
    /// key-regression monotonicity, so nothing is minted or published for it.
    /// Unreachable in practice. Fatal.
    EpochExhausted {
        /// The scope whose epoch is exhausted.
        scope_id: [u8; 16],
    },
}

impl core::fmt::Display for CascadeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CascadeError::Resolve { scope_id, reason } => write!(
                f,
                "cascade resolve of scope [{}] failed: {reason}",
                hex_lower(scope_id)
            ),
            CascadeError::Reseal { scope_id, error } => write!(
                f,
                "cascade re-seal of scope [{}] rejected: {error}",
                hex_lower(scope_id)
            ),
            CascadeError::Publish { scope_id, error } => write!(
                f,
                "cascade publish of scope [{}] failed: {error}",
                hex_lower(scope_id)
            ),
            CascadeError::Floor { scope_id, error } => write!(
                f,
                "cascade epoch-floor raise of scope [{}] failed: {error}",
                hex_lower(scope_id)
            ),
            CascadeError::EpochExhausted { scope_id } => write!(
                f,
                "cascade read epoch of scope [{}] exhausted (u64::MAX)",
                hex_lower(scope_id)
            ),
        }
    }
}

impl std::error::Error for CascadeError {}

impl CascadeError {
    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            CascadeError::Resolve { .. } => "resolve-failed",
            CascadeError::Reseal { .. } => "reseal-rejected",
            CascadeError::Publish { .. } => "publish-failed",
            CascadeError::Floor { .. } => "floor-raise-failed",
            CascadeError::EpochExhausted { .. } => "epoch-exhausted",
        }
    }

    /// The offending scope id.
    pub fn scope_id(&self) -> [u8; 16] {
        match self {
            CascadeError::Resolve { scope_id, .. }
            | CascadeError::Reseal { scope_id, .. }
            | CascadeError::Publish { scope_id, .. }
            | CascadeError::Floor { scope_id, .. }
            | CascadeError::EpochExhausted { scope_id } => *scope_id,
        }
    }

    /// Whether re-running the cascade could clear this failure — an availability
    /// stall (unavailable resolve, publish not-landed/lost-race, floor-read I/O,
    /// or an entropy hiccup) — versus a trust violation (a gate-rejected record,
    /// a divergent ledger / uncommitted signer, an exhausted epoch), which no
    /// retry can fix.
    pub fn is_retryable(&self) -> bool {
        match self {
            CascadeError::Resolve { reason, .. } => *reason == ResolveFailure::Unavailable,
            CascadeError::Reseal { error, .. } => matches!(error, ResealError::Entropy(_)),
            CascadeError::Publish { .. } => true,
            CascadeError::Floor { .. } => true,
            CascadeError::EpochExhausted { .. } => false,
        }
    }
}

/// Re-key one scope root: mint a fresh override seed via `entropy`, re-seal at
/// `current_read_epoch + 1` with `prev = Some(current seed)` through
/// [`reseal_scope_root`], CAS-publish, and raise the durable `minReadEpoch`
/// floor — in that fixed **publish → raise-floor** order so a crash between the
/// two never demands an unpublished epoch (the lockout `rotate_scope` documents).
///
/// Returns the re-key outcome and the **fresh seed**, which the orchestrator
/// threads to this scope's children as their new parent derivation. The seed is
/// [`Zeroizing`]; the caller is its terminal owner.
async fn rekey_one<E, F, P>(
    entropy: &mut E,
    floors: &F,
    publisher: &P,
    plan: &RotateScopePlan<'_>,
) -> Result<(RekeyedScope, Zeroizing<[u8; SECRET_LEN]>), CascadeError>
where
    E: Entropy,
    F: FloorStore,
    P: ScopeRootPublisher,
{
    let scope_id = plan.identity.scope_id;

    // Fail-closed BEFORE minting: a saturating bump at u64::MAX would republish
    // fresh key material under the same epoch (a key-regression violation), so an
    // exhausted epoch is rejected rather than silently reused. Release-active
    // (runtime `Err`, never a debug_assert) per AGENTS.md rule 8.
    let new_read_epoch = plan
        .current_read_epoch
        .checked_add(1)
        .ok_or(CascadeError::EpochExhausted { scope_id })?;

    // Mint the fresh random override seed — the fresh-seed cut that revokes cached
    // access. `Zeroizing` wipes it on every return path, including a panic unwind.
    let mut fresh_seed = Zeroizing::new([0u8; SECRET_LEN]);
    entropy
        .fill(fresh_seed.as_mut())
        .map_err(|e| CascadeError::Reseal {
            scope_id,
            error: ResealError::Entropy(e),
        })?;

    let seeds = ResealSeeds {
        override_seed: &fresh_seed,
        read_epoch: new_read_epoch,
        // The epoch bump ratchets a fresh history link over the prior seed.
        prev: Some(PrevEpochSeed {
            seed: plan.current_override_seed,
            epoch: plan.current_read_epoch,
        }),
        write_scope_seed: plan.write_scope_seed,
        write_epoch: plan.write_epoch,
        pointer_read_key: plan.pointer_read_key,
    };

    let section = reseal_scope_root(
        entropy,
        &plan.identity,
        &seeds,
        &plan.committed,
        plan.carried_history_links,
    )
    .map_err(|error| CascadeError::Reseal { scope_id, error })?;

    let record = ResealedScopeRoot {
        scope_id,
        ipns_name: plan.identity.ipns_name.to_vec(),
        read_epoch: new_read_epoch,
        write_epoch: plan.write_epoch,
        section,
    };

    // Publish CAS. Both NotPublished and a LostRace abort: a revocation must
    // install the fresh seed, so a record that did not land is a fail-closed hole,
    // never a tolerated drop.
    publisher
        .publish_scope_root(&record)
        .await
        .map_err(|error| CascadeError::Publish { scope_id, error })?;

    // Raise the durable minReadEpoch floor — only after a confirmed publish.
    let epoch_floor = floors
        .raise_epoch_floor(&scope_id, new_read_epoch)
        .await
        .map_err(|error| CascadeError::Floor { scope_id, error })?;

    Ok((
        RekeyedScope {
            scope_id,
            new_read_epoch,
            epoch_floor,
        },
        fresh_seed,
    ))
}

/// Perform the owner-revocation `rotateScope`: re-key the root in `root_plan`
/// **and** every transitively-reachable descendant scope root with a fresh
/// override seed, then enqueue the lazy-wave sweep.
///
/// `root_child_index` is the root's own write-body direct-child-scope index (the
/// caller already holds it — the level-1 adjacency). The `resolver` supplies each
/// deeper descendant's re-seal material; `publisher` CAS-publishes each re-key;
/// `floors` raises each scope's `minReadEpoch`; `scheduler` receives the sweep
/// task from `make_sweep_task` on success.
///
/// Top-down and fail-closed: the root's fresh seed threads to its children as
/// their new parent derivation, and so on down the tree; any descendant that
/// cannot be resolved, re-sealed, published, or floor-raised aborts with a
/// [`CascadeError`] naming it — never a partial revoke reported as complete.
///
/// This is the read-revoke completion the sweep does **not** provide: it mints a
/// **fresh** seed per descendant (`prev = Some`), where the sweep reuses the
/// existing seed (`prev = None`). Feed it the read-revoke trigger's already-cut
/// committed set (`revoke_read_grant`) for the root; each descendant re-seals its
/// own unchanged committed set.
#[allow(clippy::too_many_arguments)]
pub async fn cascade_rotate_scope<E, F, S, R, P, Mk>(
    entropy: &mut E,
    floors: &F,
    scheduler: &S,
    resolver: &R,
    publisher: &P,
    root_plan: &RotateScopePlan<'_>,
    root_child_index: &[ChildScopeRef],
    make_sweep_task: Mk,
) -> Result<CascadeOutcome, CascadeError>
where
    E: Entropy,
    F: FloorStore,
    S: Scheduler,
    R: CascadeResealResolver,
    P: ScopeRootPublisher,
    Mk: FnOnce() -> BoxedTask,
{
    let root_scope_id = root_plan.identity.scope_id;

    // 1) Re-key the root — the thread head. Its fresh seed derives its children's
    //    new parent node seeds.
    let (root_rekeyed, root_fresh_seed) = rekey_one(entropy, floors, publisher, root_plan).await?;
    let mut outcome = CascadeOutcome {
        rekeyed: vec![root_rekeyed],
    };

    // 2) Top-down threaded walk over the descendant tree. Each frontier entry
    //    carries its parent's freshly-minted override seed so the child's ascent
    //    link re-seals under the parent's NEW derivation. Mirrors
    //    `enumerate_eager_set`: canonicalized frontiers (permutation-independent,
    //    first-seen parent wins a diamond) and a `scope_id`-keyed visited set that
    //    terminates diamonds and cycles. The re-key needs these ordered edges,
    //    which the flat `EagerSet` does not carry.
    let mut visited: BTreeSet<[u8; 16]> = BTreeSet::new();
    visited.insert(root_scope_id);

    let mut frontier = canonicalize_frontier(
        root_child_index
            .iter()
            .map(|child| (child.clone(), root_fresh_seed.clone()))
            .collect(),
    );
    drop(root_fresh_seed);

    while !frontier.is_empty() {
        let mut next: Vec<(ChildScopeRef, Zeroizing<[u8; SECRET_LEN]>)> = Vec::new();
        for (child, parent_seed) in &frontier {
            // A visited scope_id is a diamond re-encounter or a cycle back-edge:
            // never re-key it (it is already freshly sealed under its first-seen
            // parent's derivation). Termination + the O(descendant count) bound.
            if !visited.insert(child.scope_id) {
                continue;
            }

            // Fail-closed: an unresolvable reachable descendant aborts the cascade
            // rather than leaving a stale-seed hole.
            let target = resolver
                .resolve(child)
                .await
                .map_err(|reason| CascadeError::Resolve {
                    scope_id: child.scope_id,
                    reason,
                })?;

            // Thread: the child's ascent link re-seals under the parent's NEW
            // derivation, `node_seed(parent_fresh_seed, child_scope_id)`.
            let parent_seed_ref: &[u8; SECRET_LEN] = parent_seed;
            let child_parent_node_seed =
                Zeroizing::new(*kdf::node_seed(parent_seed_ref, &child.scope_id).as_bytes());

            let plan = RotateScopePlan {
                identity: ScopeRootIdentity {
                    v: target.v,
                    scope_id: target.scope_id,
                    ipns_name: &target.ipns_name,
                    owner_enc_pub: &target.owner_enc_pub,
                    parent_node_seed: Some(&child_parent_node_seed),
                    pseudonym_signer: &target.pseudonym_signer,
                },
                committed: CommittedSet {
                    commitment: &target.commitment,
                    commitment_sig: &target.commitment_sig,
                    grant_ledger: &target.grant_ledger,
                    write_history_link: &target.write_history_link,
                    direct_child_scope_index: &target.direct_child_scope_index,
                },
                current_override_seed: &target.override_seed,
                current_read_epoch: target.current_read_epoch,
                write_scope_seed: &target.write_scope_seed,
                write_epoch: target.write_epoch,
                pointer_read_key: &target.pointer_read_key,
                carried_history_links: &target.carried_history_links,
            };

            let (rekeyed, child_fresh_seed) = rekey_one(entropy, floors, publisher, &plan).await?;
            outcome.rekeyed.push(rekeyed);

            // Enqueue this child's children, threaded on THIS child's fresh seed.
            for grandchild in &target.direct_child_scope_index {
                next.push((grandchild.clone(), child_fresh_seed.clone()));
            }
        }
        frontier = canonicalize_frontier(next);
    }

    // 3) Enqueue the lazy-wave sweep — last, after the eager cascade is durable
    //    (blueprint/engine.md "republish the eager set, enqueue the sweep"). The
    //    cascade already re-keyed the whole eager set eagerly, so the sweep finds
    //    nothing lagging; it stays enqueued for index self-heal and idempotence.
    scheduler.spawn(make_sweep_task());

    Ok(outcome)
}

/// Sort a threaded frontier by `child.scope_id` (stable) and dedup by
/// `scope_id`, keeping the **first-seen** `(child, parent_seed)` pair. Matches
/// [`canonicalize`](crate::grants::child_index::canonicalize)'s convention so the
/// walk — and thus which parent's fresh seed threads a diamond descendant — is
/// permutation-independent. This is the frontier's sole normalization, so the
/// resolver-supplied child indexes feed in verbatim.
fn canonicalize_frontier(
    mut pairs: Vec<(ChildScopeRef, Zeroizing<[u8; SECRET_LEN]>)>,
) -> Vec<(ChildScopeRef, Zeroizing<[u8; SECRET_LEN]>)> {
    pairs.sort_by(|a, b| a.0.scope_id.cmp(&b.0.scope_id));
    let mut seen: Option<[u8; 16]> = None;
    pairs.retain(|(child, _)| {
        if seen == Some(child.scope_id) {
            false
        } else {
            seen = Some(child.scope_id);
            true
        }
    });
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_util::ct_eq_32;
    use crate::testkit::fakes::{InMemoryFloorStore, VirtualScheduler};
    use crate::testkit::{SeededEntropy, block_on};
    use cipherbox_core::seal::{
        AadContext, AscentLink, GrantSetEntry, Permission, STRUCT_TAG_ASCENT_LINK,
        STRUCT_TAG_OWNER_BLOB, open_ascent_link, open_owner_blob, sign_grant_set,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::x25519::X25519Secret;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    const V: u64 = 2;

    fn sid(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn childref(byte: u8) -> ChildScopeRef {
        ChildScopeRef::new(sid(byte), format!("ipns-{byte:02x}").into_bytes())
    }

    /// The single vault owner/pseudonym identity every scope commits to, so
    /// `reseal_scope_root`'s signer + committed-ledger guards pass.
    struct Owner {
        enc: X25519Secret,
        pseudonym: Ed25519Signer,
        ecdsa: EcdsaSigner,
        grantee: X25519Secret,
    }

    impl Owner {
        fn new() -> Self {
            Self {
                enc: X25519Secret::from_scalar([0x11; 32]),
                pseudonym: Ed25519Signer::from_seed([0x22; 32]),
                ecdsa: EcdsaSigner::from_scalar(&[0x33; 32]).unwrap(),
                grantee: X25519Secret::from_scalar([0x77; 32]),
            }
        }

        /// The committed set for scope `byte`: one owner-signed read grant to the
        /// shared grantee at `ipns-{byte}`. Shared by every scope fixture (both the
        /// descendant `FakeNet::scope` and the root `RootFx`) so the commitment
        /// shape lives in one place.
        #[allow(clippy::type_complexity)]
        fn committed(
            &self,
            byte: u8,
        ) -> (
            GrantSetCommitment,
            [u8; ECDSA_SIG_LEN],
            Vec<GrantLedgerEntry>,
        ) {
            let tag = [byte.wrapping_add(0xa0); 32];
            let commitment = GrantSetCommitment {
                ipns_name: format!("ipns-{byte:02x}").into_bytes(),
                owner_pseudonym_pk: self.pseudonym.verifying_key().to_bytes(),
                entries: vec![GrantSetEntry::new(tag, Permission::Read, [0x02; 32])],
                unknown: Vec::new(),
            };
            let commitment_sig = sign_grant_set(&self.ecdsa, &commitment)
                .unwrap()
                .to_compact();
            let grant_ledger = vec![GrantLedgerEntry::new(
                [0x02; 33],
                self.grantee.public().to_bytes(),
                Permission::Read,
                tag,
            )];
            (commitment, commitment_sig, grant_ledger)
        }
    }

    /// The immutable per-scope material a descendant resolves to, plus the mutable
    /// current epoch a publish advances. The `override_seed` is this scope's
    /// pre-cascade seed — the value the cascade must replace.
    struct NetScope {
        override_seed: [u8; 32],
        write_scope_seed: [u8; 32],
        pointer_read_key: [u8; 32],
        commitment: GrantSetCommitment,
        commitment_sig: [u8; ECDSA_SIG_LEN],
        grant_ledger: Vec<GrantLedgerEntry>,
        children: Vec<ChildScopeRef>,
        current_epoch: u64,
    }

    /// A fake resolver + publisher over one shared scope map — the cascade's fake
    /// "network". A publish records the re-sealed record (so a test can recover the
    /// fresh seed from its owner blob) and advances `current_epoch`. Injected
    /// faults script an unresolvable descendant or a publish that does not land.
    #[derive(Clone)]
    struct FakeNet {
        owner: Rc<Owner>,
        scopes: Rc<RefCell<HashMap<[u8; 16], NetScope>>>,
        published: Rc<RefCell<HashMap<[u8; 16], ResealedScopeRoot>>>,
        resolve_faults: Rc<RefCell<HashMap<[u8; 16], ResolveFailure>>>,
        publish_faults: Rc<RefCell<HashMap<[u8; 16], ScopeRootPublishError>>>,
    }

    impl FakeNet {
        fn new() -> Self {
            Self {
                owner: Rc::new(Owner::new()),
                scopes: Rc::new(RefCell::new(HashMap::new())),
                published: Rc::new(RefCell::new(HashMap::new())),
                resolve_faults: Rc::new(RefCell::new(HashMap::new())),
                publish_faults: Rc::new(RefCell::new(HashMap::new())),
            }
        }

        /// Register a scope root: one read grant to the shared grantee, `children`
        /// as its direct-child index, published at `current_epoch`, pre-cascade
        /// override seed `[byte; 32]`.
        fn scope(self, byte: u8, current_epoch: u64, children: &[u8]) -> Self {
            let (commitment, commitment_sig, grant_ledger) = self.owner.committed(byte);
            self.scopes.borrow_mut().insert(
                sid(byte),
                NetScope {
                    override_seed: [byte; 32],
                    write_scope_seed: [byte.wrapping_add(1); 32],
                    pointer_read_key: [byte.wrapping_add(2); 32],
                    commitment,
                    commitment_sig,
                    grant_ledger,
                    children: children.iter().map(|b| childref(*b)).collect(),
                    current_epoch,
                },
            );
            self
        }

        fn resolve_fault(self, byte: u8, reason: ResolveFailure) -> Self {
            self.resolve_faults.borrow_mut().insert(sid(byte), reason);
            self
        }

        fn publish_fault(self, byte: u8, error: ScopeRootPublishError) -> Self {
            self.publish_faults.borrow_mut().insert(sid(byte), error);
            self
        }

        fn pre_cascade_seed(&self, byte: u8) -> [u8; 32] {
            self.scopes
                .borrow()
                .get(&sid(byte))
                .expect("scope")
                .override_seed
        }

        /// Recover the fresh override seed the cascade published for `byte`, by
        /// opening its published record's owner blob with the owner's key.
        fn published_seed(&self, byte: u8) -> [u8; 32] {
            let published = self.published.borrow();
            let record = published.get(&sid(byte)).expect("published record");
            let ob = &record.section.owner_blob;
            let ctx = AadContext {
                v: V,
                id: sid(byte),
                scope: sid(byte),
                epoch: record.read_epoch,
                struct_tag: STRUCT_TAG_OWNER_BLOB,
            };
            let payload = open_owner_blob(&self.owner.enc, &ob.enc, &ctx, &ob.ciphertext)
                .expect("owner opens the published seed");
            *payload.override_seed()
        }

        /// Open `byte`'s published ascent link with `parent_node_seed`, returning
        /// the recovered override seed (or `None` if it does not open under that
        /// derivation).
        fn ascent_seed_under(&self, byte: u8, parent_node_seed: &[u8; 32]) -> Option<[u8; 32]> {
            let published = self.published.borrow();
            let record = published.get(&sid(byte)).expect("published record");
            let ascent = record
                .section
                .ascent_link
                .as_ref()
                .expect("interior ascent");
            let ctx = AadContext {
                v: V,
                id: sid(byte),
                scope: sid(byte),
                epoch: record.read_epoch,
                struct_tag: STRUCT_TAG_ASCENT_LINK,
            };
            let link = AscentLink {
                ascent_public: ascent.ascent_public,
                enc: ascent.enc,
                ciphertext: ascent.ciphertext.clone(),
                unknown: Vec::new(),
            };
            open_ascent_link(parent_node_seed, &ctx, &link)
                .ok()
                .map(|p| *p.override_seed())
        }

        fn published_epoch(&self, byte: u8) -> u64 {
            self.published
                .borrow()
                .get(&sid(byte))
                .expect("record")
                .read_epoch
        }

        fn history_len(&self, byte: u8) -> usize {
            self.published
                .borrow()
                .get(&sid(byte))
                .expect("record")
                .section
                .history_links
                .len()
        }
    }

    impl CascadeResealResolver for FakeNet {
        async fn resolve(&self, scope: &ChildScopeRef) -> Result<CascadeTarget, ResolveFailure> {
            if let Some(reason) = self.resolve_faults.borrow().get(&scope.scope_id) {
                return Err(*reason);
            }
            let scopes = self.scopes.borrow();
            let s = scopes
                .get(&scope.scope_id)
                .ok_or(ResolveFailure::Unavailable)?;
            Ok(CascadeTarget {
                v: V,
                scope_id: scope.scope_id,
                ipns_name: scope.ipns_name.clone(),
                current_read_epoch: s.current_epoch,
                owner_enc_pub: self.owner.enc.public(),
                pseudonym_signer: self.owner.pseudonym.clone(),
                override_seed: Zeroizing::new(s.override_seed),
                write_scope_seed: Zeroizing::new(s.write_scope_seed),
                pointer_read_key: Zeroizing::new(s.pointer_read_key),
                write_epoch: 1,
                commitment: s.commitment.clone(),
                commitment_sig: s.commitment_sig,
                grant_ledger: s.grant_ledger.clone(),
                write_history_link: Vec::new(),
                direct_child_scope_index: s.children.clone(),
                carried_history_links: Vec::new(),
            })
        }
    }

    impl ScopeRootPublisher for FakeNet {
        async fn publish_scope_root(
            &self,
            record: &ResealedScopeRoot,
        ) -> Result<(), ScopeRootPublishError> {
            if let Some(err) = self.publish_faults.borrow().get(&record.scope_id) {
                return Err(err.clone());
            }
            if let Some(s) = self.scopes.borrow_mut().get_mut(&record.scope_id) {
                s.current_epoch = record.read_epoch;
            }
            self.published
                .borrow_mut()
                .insert(record.scope_id, record.clone());
            Ok(())
        }
    }

    /// The root plan for scope `0x00` (a vault root — no ascent link), the
    /// read-grantee's committed set unchanged (the cut itself is exercised in
    /// `trigger.rs`; here the focus is the descendant cascade).
    struct RootFx {
        net: FakeNet,
        owner_pub: X25519Public,
        commitment: GrantSetCommitment,
        commitment_sig: [u8; ECDSA_SIG_LEN],
        grant_ledger: Vec<GrantLedgerEntry>,
        current_seed: [u8; 32],
        write_scope_seed: [u8; 32],
        pointer_read_key: [u8; 32],
    }

    impl RootFx {
        fn new(net: FakeNet) -> Self {
            let owner_pub = net.owner.enc.public();
            let (commitment, commitment_sig, grant_ledger) = net.owner.committed(0x00);
            Self {
                net,
                owner_pub,
                commitment,
                commitment_sig,
                grant_ledger,
                current_seed: [0x00; 32],
                write_scope_seed: [0x01; 32],
                pointer_read_key: [0x02; 32],
            }
        }

        fn plan<'a>(&'a self, root_children: &'a [ChildScopeRef]) -> RotateScopePlan<'a> {
            RotateScopePlan {
                identity: ScopeRootIdentity {
                    v: V,
                    scope_id: sid(0x00),
                    ipns_name: b"ipns-00",
                    owner_enc_pub: &self.owner_pub,
                    parent_node_seed: None,
                    pseudonym_signer: &self.net.owner.pseudonym,
                },
                committed: CommittedSet {
                    commitment: &self.commitment,
                    commitment_sig: &self.commitment_sig,
                    grant_ledger: &self.grant_ledger,
                    write_history_link: b"",
                    direct_child_scope_index: root_children,
                },
                current_override_seed: &self.current_seed,
                current_read_epoch: 4,
                write_scope_seed: &self.write_scope_seed,
                write_epoch: 3,
                pointer_read_key: &self.pointer_read_key,
                carried_history_links: &[],
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn run(
        net: FakeNet,
        root_children: &[u8],
    ) -> (
        Result<CascadeOutcome, CascadeError>,
        FakeNet,
        InMemoryFloorStore,
        usize,
    ) {
        let fx = RootFx::new(net.clone());
        let floors = InMemoryFloorStore::default();
        let scheduler = VirtualScheduler::new();
        let root_index: Vec<ChildScopeRef> = root_children.iter().map(|b| childref(*b)).collect();
        let outcome = block_on(async {
            let mut entropy = SeededEntropy::new(0xCA5CADE);
            let plan = fx.plan(&root_index);
            cascade_rotate_scope(
                &mut entropy,
                &floors,
                &scheduler,
                &net,
                &net,
                &plan,
                &root_index,
                || Box::pin(async {}),
            )
            .await
        });
        let spawned = scheduler.take_spawned_tasks().len();
        (outcome, net, floors, spawned)
    }

    #[test]
    fn every_descendant_gets_a_distinct_fresh_seed_and_root_first() {
        // root(0x00) -> A(0x0a) -> B(0x0b); A also -> C(0x0c).
        let net = FakeNet::new()
            .scope(0x0a, 4, &[0x0b, 0x0c])
            .scope(0x0b, 4, &[])
            .scope(0x0c, 4, &[]);
        let (outcome, net, floors, spawned) = run(net, &[0x0a]);
        let outcome = outcome.expect("cascade completes");

        // Root re-keyed first, then all three descendants.
        assert_eq!(outcome.rekeyed[0].scope_id, sid(0x00));
        assert_eq!(outcome.descendant_count(), 3);
        let rekeyed: Vec<[u8; 16]> = outcome.rekeyed.iter().map(|r| r.scope_id).collect();
        for s in [0x00u8, 0x0a, 0x0b, 0x0c] {
            assert!(rekeyed.contains(&sid(s)), "scope {s:#x} re-keyed");
        }

        // Every re-keyed scope's published seed is FRESH (differs from its
        // pre-cascade seed) and DISTINCT across scopes.
        let mut seeds = Vec::new();
        for s in [0x0au8, 0x0b, 0x0c] {
            let fresh = net.published_seed(s);
            assert!(
                !ct_eq_32(&fresh, &net.pre_cascade_seed(s)),
                "scope {s:#x} got a fresh seed, not its old one"
            );
            seeds.push(fresh);
        }
        seeds.push(net.published_seed(0x00));
        for i in 0..seeds.len() {
            for j in (i + 1)..seeds.len() {
                assert!(!ct_eq_32(&seeds[i], &seeds[j]), "seeds {i}/{j} distinct");
            }
        }

        // Each scope's floor rose to its new epoch (4 -> 5), and one sweep enqueued.
        for s in [0x00u8, 0x0a, 0x0b, 0x0c] {
            assert_eq!(block_on(floors.epoch_floor(&sid(s))).unwrap(), Some(5));
        }
        assert_eq!(spawned, 1, "one sweep enqueued after the cascade");
    }

    #[test]
    fn revocation_is_a_fresh_seed_cascade_not_an_epoch_bump() {
        // THE cross-slice invariant: revocation re-keys descendants via a FRESH
        // seed, never via floor-raise + sweep. A sweep would reuse the existing
        // seed (prev = None): the published seed would EQUAL the pre-cascade seed
        // and NO fresh history link would be appended. The cascade instead mints a
        // fresh seed (published seed CHANGES) and ratchets one history link — which
        // is exactly what locks out a reader holding the old descendant seed.
        let net = FakeNet::new().scope(0x0a, 4, &[]);
        let (outcome, net, _floors, _spawned) = run(net, &[0x0a]);
        outcome.expect("cascade completes");

        let old = net.pre_cascade_seed(0x0a);
        let published = net.published_seed(0x0a);
        assert!(
            !ct_eq_32(&published, &old),
            "a sweep would keep the old seed; the cascade minted a fresh one"
        );
        assert_eq!(net.published_epoch(0x0a), 5, "epoch bumped 4 -> 5");
        assert_eq!(
            net.history_len(0x0a),
            1,
            "the fresh-seed ratchet appended one history link (a sweep appends none)"
        );
    }

    #[test]
    fn old_descendant_seed_holder_is_locked_out() {
        // A reader who cached A's OLD seed can derive keys only from that seed.
        // Post-cascade, A's records seal under a FRESH seed, so every key the old
        // seed derives is stale — the reader is locked out. Proven at the seed
        // level: the published seed differs, so read_key(node_seed(old, id)) can no
        // longer match the current record's key.
        let net = FakeNet::new().scope(0x0a, 4, &[]);
        let (outcome, net, _f, _s) = run(net, &[0x0a]);
        outcome.expect("completes");

        let old = net.pre_cascade_seed(0x0a);
        let fresh = net.published_seed(0x0a);
        let id = sid(0x0a);
        let old_read_key = kdf::read_key(kdf::node_seed(&old, &id).as_bytes());
        let fresh_read_key = kdf::read_key(kdf::node_seed(&fresh, &id).as_bytes());
        assert!(
            !ct_eq_32(old_read_key.as_bytes(), fresh_read_key.as_bytes()),
            "the cached old seed no longer derives A's current read key"
        );
    }

    #[test]
    fn parent_child_seed_threading_is_correct() {
        // root -> A(0x0a) -> B(0x0b). B's published ascent link must open ONLY under
        // node_seed(A_fresh_seed, B_scope_id) — the parent's NEW derivation — and
        // NOT under node_seed(A_old_seed, B_scope_id). This is the threading proof
        // AND the ancestor-path lockout: an ancestor holding A's old derivation
        // cannot reach B.
        let net = FakeNet::new().scope(0x0a, 4, &[0x0b]).scope(0x0b, 4, &[]);
        let (outcome, net, _f, _s) = run(net, &[0x0a]);
        outcome.expect("completes");

        let a_fresh = net.published_seed(0x0a);
        let a_old = net.pre_cascade_seed(0x0a);
        let b_id = sid(0x0b);
        let b_fresh = net.published_seed(0x0b);

        let under_new = kdf::node_seed(&a_fresh, &b_id);
        let recovered = net
            .ascent_seed_under(0x0b, under_new.as_bytes())
            .expect("B's ascent opens under A's NEW parent derivation");
        assert!(
            ct_eq_32(&recovered, &b_fresh),
            "the ascent link carries B's fresh override seed"
        );

        let under_old = kdf::node_seed(&a_old, &b_id);
        assert!(
            net.ascent_seed_under(0x0b, under_old.as_bytes()).is_none(),
            "B's ascent must NOT open under A's stale parent derivation"
        );
    }

    #[test]
    fn diamond_descendant_rekeyed_once_under_first_seen_parent() {
        // root -> A(0x0a), B(0x0b); both A and B list D(0x0d). D is re-keyed exactly
        // once, threaded from the canonically-first parent A (0x0a < 0x0b).
        let net = FakeNet::new()
            .scope(0x0a, 4, &[0x0d])
            .scope(0x0b, 4, &[0x0d])
            .scope(0x0d, 4, &[]);
        let (outcome, net, _f, _s) = run(net, &[0x0a, 0x0b]);
        let outcome = outcome.expect("diamond completes");

        // A, B, D each appear exactly once (plus the root).
        let mut ids: Vec<[u8; 16]> = outcome.rekeyed.iter().map(|r| r.scope_id).collect();
        ids.sort();
        assert_eq!(ids, vec![sid(0x00), sid(0x0a), sid(0x0b), sid(0x0d)]);

        // D threads from A (first-seen), not B: its ascent opens under
        // node_seed(A_fresh, D) and not node_seed(B_fresh, D).
        let a_fresh = net.published_seed(0x0a);
        let b_fresh = net.published_seed(0x0b);
        let d_id = sid(0x0d);
        assert!(
            net.ascent_seed_under(0x0d, kdf::node_seed(&a_fresh, &d_id).as_bytes())
                .is_some(),
            "D threads from first-seen parent A"
        );
        assert!(
            net.ascent_seed_under(0x0d, kdf::node_seed(&b_fresh, &d_id).as_bytes())
                .is_none(),
            "D does not thread from the later parent B"
        );
    }

    #[test]
    fn cycle_back_edge_terminates() {
        // A -> B -> A (a corrupt/adversarial back-edge). The cascade must terminate
        // and re-key A and B once each.
        let net = FakeNet::new()
            .scope(0x0a, 4, &[0x0b])
            .scope(0x0b, 4, &[0x0a]);
        let (outcome, _net, _f, _s) = run(net, &[0x0a]);
        let outcome = outcome.expect("cyclic index terminates");
        assert_eq!(outcome.descendant_count(), 2);
    }

    #[test]
    fn unresolvable_descendant_aborts_fail_closed() {
        // root -> A -> B, but B fails the adoption gate. The cascade must abort,
        // naming B — never report a partial revoke as complete. This encode-side
        // fail-closed guard is release-active (a runtime `Err`, not a debug_assert).
        let net = FakeNet::new()
            .scope(0x0a, 4, &[0x0b])
            .scope(0x0b, 4, &[])
            .resolve_fault(0x0b, ResolveFailure::Rejected);
        let (outcome, _net, floors, spawned) = run(net, &[0x0a]);
        let err = outcome.expect_err("rejected descendant fails closed");
        assert_eq!(err.check(), "resolve-failed");
        assert_eq!(err.scope_id(), sid(0x0b));
        assert!(!err.is_retryable(), "a gate rejection is fatal");
        // No sweep enqueued on an aborted cascade (the enqueue is the last step).
        assert_eq!(spawned, 0, "no sweep enqueued on a fail-closed abort");
        // B never floored (it never published).
        assert_eq!(block_on(floors.epoch_floor(&sid(0x0b))).unwrap(), None);
    }

    #[test]
    fn publish_not_landed_aborts_fail_closed() {
        // A descendant whose re-key does not land aborts the cascade — a revocation
        // that cannot install the fresh seed is a hole, not a tolerated drop.
        let net = FakeNet::new()
            .scope(0x0a, 4, &[])
            .publish_fault(0x0a, ScopeRootPublishError::NotPublished);
        let (outcome, _net, _f, spawned) = run(net, &[0x0a]);
        let err = outcome.expect_err("unpublished descendant fails closed");
        assert_eq!(err.check(), "publish-failed");
        assert_eq!(err.scope_id(), sid(0x0a));
        assert!(err.is_retryable(), "not-landed is an availability stall");
        assert_eq!(spawned, 0);
    }

    #[test]
    fn lost_race_aborts_unlike_the_sweep() {
        // A lost CAS race aborts the revocation cascade (the fresh seed did not
        // install), where the idempotent sweep would merely drop and re-resolve.
        let net = FakeNet::new()
            .scope(0x0a, 4, &[])
            .publish_fault(0x0a, ScopeRootPublishError::LostRace);
        let (outcome, _net, _f, _s) = run(net, &[0x0a]);
        let err = outcome.expect_err("lost race aborts the cascade");
        assert_eq!(err.check(), "publish-failed");
        assert_eq!(err.scope_id(), sid(0x0a));
    }

    #[test]
    fn epoch_exhausted_descendant_aborts_release_active() {
        // A descendant at u64::MAX cannot bump without reusing the epoch with fresh
        // key material (a key-regression violation). Release-active fail-closed:
        // a runtime `Err`, never a debug_assert.
        let net = FakeNet::new().scope(0x0a, u64::MAX, &[]);
        let (outcome, net, _f, spawned) = run(net, &[0x0a]);
        let err = outcome.expect_err("exhausted epoch fails closed");
        assert_eq!(err.check(), "epoch-exhausted");
        assert_eq!(err.scope_id(), sid(0x0a));
        assert!(!err.is_retryable());
        assert_eq!(spawned, 0);
        // Nothing published for A on an exhausted epoch.
        assert!(!net.published.borrow().contains_key(&sid(0x0a)));
    }

    #[test]
    fn re_run_is_deterministic_and_locks_out_each_time() {
        // Idempotence/re-run safety consistent with the rotation module: two runs
        // over the same tree and entropy seed produce byte-identical published
        // seeds, and every run mints fresh seeds (a re-run never resurrects an old
        // seed).
        let build = || {
            let net = FakeNet::new().scope(0x0a, 4, &[0x0b]).scope(0x0b, 4, &[]);
            let (outcome, net, _f, _s) = run(net, &[0x0a]);
            outcome.expect("completes");
            (net.published_seed(0x0a), net.published_seed(0x0b))
        };
        let (a1, b1) = build();
        let (a2, b2) = build();
        assert!(
            ct_eq_32(&a1, &a2) && ct_eq_32(&b1, &b2),
            "same seed → same fresh seeds"
        );
        assert!(!ct_eq_32(&a1, &[0x0a; 32]), "A never keeps its old seed");
        assert!(!ct_eq_32(&b1, &[0x0b; 32]), "B never keeps its old seed");
    }

    #[test]
    fn leaf_root_with_no_descendants_still_rekeys_root_and_enqueues_sweep() {
        let net = FakeNet::new();
        let (outcome, net, floors, spawned) = run(net, &[]);
        let outcome = outcome.expect("leaf root completes");
        assert_eq!(outcome.descendant_count(), 0);
        assert_eq!(outcome.rekeyed[0].scope_id, sid(0x00));
        assert_eq!(block_on(floors.epoch_floor(&sid(0x00))).unwrap(), Some(5));
        assert_eq!(spawned, 1);
        assert!(!ct_eq_32(&net.published_seed(0x00), &[0x00; 32]));
    }
}
