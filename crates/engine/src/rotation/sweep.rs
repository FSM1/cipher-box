//! The sweep — idempotent lazy-wave epoch-lag convergence (blueprint/engine.md
//! "sweep", L269-278; #26 D2, #38 D6).
//!
//! # What the sweep is (and is not)
//!
//! The rotation architecture is an O(1) root cut plus a lazy wave (CONTEXT.md
//! "Lazy wave", "Epoch lag"). This module is the **lazy wave**: it walks the
//! eager set from a rotated root and, for every descendant scope root whose
//! published record epoch lags its scope's durable epoch floor, re-seals that
//! scope root's **metadata** up to the floor epoch — reusing the scope's
//! **existing** override seed, `prev = None`, minting no new seed, no new epoch,
//! and no new history link. Content bytes are never re-encrypted (#26 D6).
//!
//! It deliberately does **not** mint fresh descendant seeds. Fresh-seed
//! descendant re-keying — the part that defeats a revokee's *cached descendant
//! seeds* — is `rotateScope`'s **eager-set republish** on an owner-revocation
//! rotation (blueprint/engine.md "rotateScope", L243-252: "mint a random override
//! seed at the scope root, republish the eager set, enqueue the sweep"; each
//! descendant "fully rotated — fresh override seed"). That eager cascade is a
//! separate piece, currently deferred pending the resolver/tree wiring
//! (#745/#746). The sweep completes only the **epoch-lag convergence** and the
//! direct-child-scope index self-heal; it does not, on its own, complete a read
//! revoke, and re-sealing a descendant with its existing seed does not revoke a
//! cached descendant seed.
//!
//! # Completeness is fail-closed
//!
//! The work-list is computed purely from **published records** (the epoch-lag
//! predicate: record epoch `<` the scope's durable epoch floor). There is no
//! pending-rotation store, no job record, and no checkpoint — published records
//! are the sole source of truth, so a re-run reconstructs the identical
//! work-list and the pass is idempotent.
//!
//! A lagging descendant that cannot be enumerated, resolved, re-sealed, or
//! published is **never silently skipped** — under-enumeration is a silent hole,
//! not staleness. Mirroring the eager-set walk's hard-abort posture
//! ([`enumerate_eager_set`]), a pass aborts with a [`SweepError`] naming the
//! offending scope rather than returning a partial "converged" claim. The one
//! spec-mandated per-node exception is a **lost CAS race**: a concurrent write
//! won the sequence CAS for that node, so the loser drops it and re-resolves
//! (blueprint/engine.md L276-278). The winner is not necessarily a *sweeper* —
//! an ordinary metadata write bumps the sequence without advancing the read
//! epoch — so a dropped node is **not** proven converged by the drop alone. The
//! idle-cadence driver ([`run_sweep`]) therefore re-runs the idempotent pass
//! until a pass drops nothing (or the attempt cap is hit), which is what
//! actually confirms convergence. Availability failures (unavailable resolve,
//! transport `NotPublished`, floor-read error) abort the pass but are likewise
//! **retryable**. Trust failures (a rejected record, a divergent ledger, an
//! uncommitted signer) are fatal.
//!
//! # Determinism
//!
//! Time (the idle cadence) enters only through the [`Scheduler`] seam and entropy
//! only through the [`Entropy`] seam; the pass itself reads no clock and samples
//! no randomness of its own beyond what `reseal_scope_root` draws from the
//! injected entropy. The sole impure edges are the injected [`SweepResolver`]
//! (resolve + gate + unseal a scope root's re-seal material) and
//! [`ScopeRootPublisher`] (CAS-publish), mirroring `rotate_scope`; the real
//! network wiring is #745/#746 and tests fake both.

use core::time::Duration;
use std::cell::RefCell;
use std::collections::HashMap;

use zeroize::Zeroizing;

use cipherbox_core::seal::{ChildScopeRef, GrantLedgerEntry, GrantSetCommitment, SignedSealed};
use cipherbox_core::suite::ecdsa::SIGNATURE_LEN as ECDSA_SIG_LEN;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::X25519Public;

use super::eager_set::{ChildIndexResolver, EnumerationError, ResolveFailure, enumerate_eager_set};
use super::reseal::{CommittedSet, ResealError, ResealSeeds, ScopeRootIdentity, reseal_scope_root};
use super::rotate::{ResealedScopeRoot, ScopeRootPublishError, ScopeRootPublisher};
use crate::entropy::Entropy;
use crate::grants::child_index::canonicalize;
use crate::hex::hex_lower;
use crate::seams::{FloorStore, Scheduler, SeamError};

/// One scope root's current re-seal material, as resolved from its published
/// record: everything [`reseal_scope_root`] needs plus the record epoch the
/// epoch-lag predicate compares against the floor.
///
/// Owns its secrets so the sweep is their terminal owner: the seed fields are
/// [`Zeroizing`] and the pseudonym signer zeroizes on drop, so a resolved target
/// wipes its key material when it leaves the work-list. The seeds are handed to
/// `reseal_scope_root` **by borrow**; that callee never zeroes caller-owned
/// buffers (AGENTS.md rule 7).
pub struct SweepTarget {
    /// The envelope format+suite version.
    pub v: u64,
    /// The scope-root node id (== scope id).
    pub scope_id: [u8; 16],
    /// The scope root's opaque `ipnsName` bytes.
    pub ipns_name: Vec<u8>,
    /// The published record's current read epoch — the epoch-lag operand.
    pub current_read_epoch: u64,
    /// The vault owner's X25519 encryption-subkey public (owner-blob recipient).
    pub owner_enc_pub: X25519Public,
    /// The parent node seed the ascent link derives from; `None` at the vault
    /// root (which carries no ascent link).
    pub parent_node_seed: Option<Zeroizing<[u8; SECRET_LEN]>>,
    /// The owner-committed writer pseudonym signer (re-sealer identity).
    pub pseudonym_signer: Ed25519Signer,
    /// The scope's existing override (read scope) seed — reused verbatim; the
    /// sweep mints no fresh seed.
    pub override_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The write-plane scope seed (unchanged by a read-plane sweep).
    pub write_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The stable per-scope pointer read key carried in every grant blob.
    pub pointer_read_key: Zeroizing<[u8; SECRET_LEN]>,
    /// The write epoch (unchanged by a read-plane sweep).
    pub write_epoch: u64,
    /// The owner-signed, epoch-free commitment.
    pub commitment: GrantSetCommitment,
    /// The 64-byte compact ECDSA owner signature over `commitment`.
    pub commitment_sig: [u8; ECDSA_SIG_LEN],
    /// The authoritative grant ledger (one blob re-wrapped per entry).
    pub grant_ledger: Vec<GrantLedgerEntry>,
    /// The opaque write-plane history-link blob (carried through).
    pub write_history_link: Vec<u8>,
    /// This scope root's own direct-child-scope index — both the next-level
    /// enumeration adjacency and the index the sweep self-heals on re-seal.
    pub direct_child_scope_index: Vec<ChildScopeRef>,
    /// The scope's existing per-epoch history links, carried verbatim (a sweep
    /// appends none).
    pub carried_history_links: Vec<SignedSealed>,
}

/// The impure edge that resolves a scope root's current re-seal material — the
/// sweep's analogue of the eager-set walk's [`ChildIndexResolver`] and
/// `rotate_scope`'s [`ScopeRootPublisher`]. Resolve + adoption-gate + unseal live
/// behind this trait; the real network/gate wiring is #745/#746 and tests fake
/// it. A resolve either yields the full [`SweepTarget`] or a fail-closed
/// [`ResolveFailure`] — a partial or gate-failing record is never a work-list
/// entry.
pub trait SweepResolver {
    /// Resolve `scope`'s current re-seal material, or a fail-closed
    /// [`ResolveFailure`] if its record cannot be authoritatively obtained.
    ///
    /// One resolve returns the whole [`SweepTarget`] — the enumeration/lag
    /// fields (`ipns_name`, `current_read_epoch`, `direct_child_scope_index`)
    /// and the heavy re-seal material (seeds, signer, committed set). The real
    /// resolver (#745/#746) fetches and gates a scope root's record once, so
    /// unsealing the owner blob to hand back its seeds is incremental; splitting
    /// this into a light enumeration edge plus a heavy re-seal edge fetched only
    /// for lagging nodes is a designed-for optimization for that slice, not a
    /// correctness requirement here.
    ///
    /// # Binding contract (obligation on the real resolver, #745/#746)
    ///
    /// The same edge discipline [`ChildIndexResolver`] carries applies: `scope`'s
    /// `ipns_name` is the **sole gated identity edge** (the adoption gate binds
    /// `ipns_name -> record` via the Ed25519 key derived from the name), and the
    /// returned `SweepTarget.ipns_name` — the CAS **publish** destination — MUST be
    /// that gated name, equal to `commitment.ipns_name`, and MUST NOT be swayed by
    /// any network-supplied hint. The sweep re-seals and CAS-publishes under the
    /// enumerated parent-index `scope_id` (never a resolver-returned `scope_id`),
    /// so a resolver that returned a mismatched name/commitment could only mint a
    /// record its own resolve-time gate rejects — but binding the two here keeps
    /// that fail-closed at the source.
    async fn resolve(&self, scope: &ChildScopeRef) -> Result<SweepTarget, ResolveFailure>;
}

/// A completed sweep pass. Every reachable descendant is accounted for in exactly
/// one bucket — the fail-closed guarantee made observable: nothing is silently
/// dropped. (A pass that could not account for a node returns [`SweepError`]
/// instead of an outcome.)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Descendants that lagged and were re-sealed up to the floor this pass.
    pub converged: Vec<[u8; 16]>,
    /// Descendants already at or above the floor — no re-seal, a no-op.
    pub already_converged: Vec<[u8; 16]>,
    /// Descendants dropped because a concurrent writer won the CAS race; a
    /// fresher record for them already landed, so they re-resolve as converged.
    pub dropped_lost_race: Vec<[u8; 16]>,
    /// Descendants whose stored direct-child-scope index was non-canonical and
    /// was repaired (canonicalized) on re-seal — the index self-heal, surfaced
    /// to the host (#38 D6 "repaired and flagged").
    pub flagged_indexes: Vec<[u8; 16]>,
}

/// A fail-closed sweep failure. A pass returns this rather than a partial
/// [`SweepOutcome`] whenever it cannot prove every reachable descendant
/// converged — the completeness guarantee. [`SweepError::is_retryable`]
/// distinguishes an availability stall (the idle-cadence driver re-runs) from a
/// trust violation (fatal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepError {
    /// The eager set could not be enumerated — a reachable descendant's index
    /// was unobtainable, so the work-list is not provably complete.
    Enumeration(EnumerationError),
    /// Reading the durable epoch floor failed (host I/O). Availability, retryable.
    Floor(SeamError),
    /// Re-sealing a lagging descendant failed a trust invariant (divergent
    /// ledger, uncommitted signer, unusable recipient key). Fatal.
    Reseal {
        /// The scope that could not be legitimately re-sealed.
        scope_id: [u8; 16],
        /// The underlying re-seal rejection.
        error: ResealError,
    },
    /// A re-sealed record could not be published (register-first / PUT failed);
    /// nothing landed for that node. Availability, retryable.
    Publish {
        /// The scope whose record did not land.
        scope_id: [u8; 16],
        /// The publish failure (always [`ScopeRootPublishError::NotPublished`]; a
        /// lost race is not an error — it drops and re-resolves).
        error: ScopeRootPublishError,
    },
}

impl core::fmt::Display for SweepError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SweepError::Enumeration(e) => write!(f, "sweep enumeration incomplete: {e}"),
            SweepError::Floor(e) => write!(f, "sweep epoch-floor read failed: {e}"),
            SweepError::Reseal { scope_id, error } => write!(
                f,
                "sweep re-seal of scope [{}] rejected: {error}",
                hex_lower(scope_id)
            ),
            SweepError::Publish { scope_id, error } => write!(
                f,
                "sweep publish of scope [{}] failed: {error}",
                hex_lower(scope_id)
            ),
        }
    }
}

impl std::error::Error for SweepError {}

impl SweepError {
    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            SweepError::Enumeration(_) => "enumeration-incomplete",
            SweepError::Floor(_) => "floor-read-failed",
            SweepError::Reseal { .. } => "reseal-rejected",
            SweepError::Publish { .. } => "publish-failed",
        }
    }

    /// Whether re-running the idempotent pass could clear this failure — an
    /// availability stall (unavailable resolve, floor-read I/O, transport
    /// not-published) — versus a trust violation (a gate-rejected record, a
    /// divergent ledger / uncommitted signer), which no retry can fix.
    pub fn is_retryable(&self) -> bool {
        match self {
            SweepError::Enumeration(e) => e.reason == ResolveFailure::Unavailable,
            SweepError::Floor(_) => true,
            SweepError::Publish { .. } => true,
            SweepError::Reseal { .. } => false,
        }
    }
}

/// Adapts a [`SweepResolver`] to the eager-set walk's [`ChildIndexResolver`] and
/// caches each resolved [`SweepTarget`], so enumeration resolves every descendant
/// exactly once and the convergence pass reuses those targets (no double
/// resolve, no resolve/re-seal TOCTOU within a pass).
struct WalkAdapter<'a, R: SweepResolver> {
    resolver: &'a R,
    cache: RefCell<HashMap<[u8; 16], SweepTarget>>,
}

impl<'a, R: SweepResolver> WalkAdapter<'a, R> {
    fn new(resolver: &'a R) -> Self {
        Self {
            resolver,
            cache: RefCell::new(HashMap::new()),
        }
    }
}

impl<R: SweepResolver> ChildIndexResolver for WalkAdapter<'_, R> {
    async fn direct_child_index(
        &self,
        child: &ChildScopeRef,
    ) -> Result<Vec<ChildScopeRef>, ResolveFailure> {
        let target = self.resolver.resolve(child).await?;
        let adjacency = target.direct_child_scope_index.clone();
        // Borrow only after the await completes — never across a suspend point.
        self.cache.borrow_mut().insert(child.scope_id, target);
        Ok(adjacency)
    }
}

/// Run one idempotent sweep pass over the eager set rooted at `root_scope_id`
/// (whose level-1 adjacency is the caller-held `root_child_index`, e.g. the
/// just-cut root's write-body index).
///
/// Enumerates the eager set fail-closed via [`enumerate_eager_set`], then for
/// each descendant scope root whose current record epoch lags its durable epoch
/// floor, re-seals its metadata up to the floor epoch through
/// [`reseal_scope_root`] with the scope's **existing** seed and **`prev = None`**
/// (no fresh seed, no epoch bump, no new history link), CAS-publishes it, and
/// self-heals its direct-child-scope index. Returns a complete [`SweepOutcome`]
/// or a fail-closed [`SweepError`] — never a partial convergence claim.
pub async fn sweep_pass<E, F, R, P>(
    entropy: &mut E,
    floors: &F,
    resolver: &R,
    publisher: &P,
    root_scope_id: [u8; 16],
    root_child_index: &[ChildScopeRef],
) -> Result<SweepOutcome, SweepError>
where
    E: Entropy,
    F: FloorStore,
    R: SweepResolver,
    P: ScopeRootPublisher,
{
    let adapter = WalkAdapter::new(resolver);
    let eager_set = enumerate_eager_set(root_scope_id, root_child_index, &adapter)
        .await
        .map_err(SweepError::Enumeration)?;
    let mut cache = adapter.cache.into_inner();

    let mut outcome = SweepOutcome::default();

    for descendant in eager_set.descendants() {
        let scope_id = descendant.scope_id;
        // Enumeration resolves and caches every descendant before it can appear in
        // `descendants()` (the walk aborts on the first unresolvable node), so the
        // cache is 1:1 with the eager set — a miss is an internal invariant break,
        // never adversarial input.
        let target = cache
            .remove(&scope_id)
            .expect("every enumerated descendant was resolved into the cache");

        // Epoch-lag predicate, computed purely from published state: a node lags
        // when its record epoch is below its scope's durable floor. No floor (or
        // a record at/above it) means nothing to converge.
        let floor = floors
            .epoch_floor(&scope_id)
            .await
            .map_err(SweepError::Floor)?;
        let Some(floor_epoch) = floor else {
            outcome.already_converged.push(scope_id);
            continue;
        };
        if target.current_read_epoch >= floor_epoch {
            outcome.already_converged.push(scope_id);
            continue;
        }

        // Index self-heal: re-publish the direct-child-scope index in canonical,
        // deduplicated form; flag the node when the stored index needed repair
        // (#38 D6 "repaired and flagged"). The heal rides the re-seal, so it
        // reaches only nodes being re-sealed this pass — a converged node's index
        // heals on its next ordinary write ("ordinary writes advance it for
        // free"). Detecting a child *missing from a different parent's* index is
        // the resolver/tree wiring's job (#745/#746);
        // this slice heals each re-sealed node's own index.
        let canonical_index = canonicalize(&target.direct_child_scope_index);
        if canonical_index != target.direct_child_scope_index {
            outcome.flagged_indexes.push(scope_id);
        }

        let identity = ScopeRootIdentity {
            v: target.v,
            scope_id,
            ipns_name: &target.ipns_name,
            owner_enc_pub: &target.owner_enc_pub,
            parent_node_seed: target.parent_node_seed.as_deref(),
            pseudonym_signer: &target.pseudonym_signer,
        };
        let seeds = ResealSeeds {
            override_seed: &target.override_seed,
            read_epoch: floor_epoch,
            // The catch-up mints no new epoch, so no fresh history link.
            prev: None,
            write_scope_seed: &target.write_scope_seed,
            write_epoch: target.write_epoch,
            pointer_read_key: &target.pointer_read_key,
        };
        let committed = CommittedSet {
            commitment: &target.commitment,
            commitment_sig: &target.commitment_sig,
            grant_ledger: &target.grant_ledger,
            write_history_link: &target.write_history_link,
            direct_child_scope_index: &canonical_index,
        };

        let section = reseal_scope_root(
            entropy,
            &identity,
            &seeds,
            &committed,
            &target.carried_history_links,
        )
        .map_err(|error| SweepError::Reseal { scope_id, error })?;

        let record = ResealedScopeRoot {
            scope_id,
            // `target`'s borrows (identity/seeds/committed) all end at the
            // `reseal_scope_root` return above, so the name moves out here.
            ipns_name: target.ipns_name,
            read_epoch: floor_epoch,
            write_epoch: target.write_epoch,
            section,
        };

        match publisher.publish_scope_root(&record).await {
            Ok(()) => outcome.converged.push(scope_id),
            // A concurrent write won the sequence CAS: no clobber, and this pass
            // does not advance the node. The single spec-mandated non-abort
            // per-node path — but the winner may be a non-advancing ordinary
            // write, so the node is not proven converged; `run_sweep` re-resolves
            // it until a pass drops nothing.
            Err(ScopeRootPublishError::LostRace) => outcome.dropped_lost_race.push(scope_id),
            // Nothing landed: fail-closed rather than mark the node converged. The
            // idle-cadence driver re-runs the idempotent pass to retry.
            Err(error @ ScopeRootPublishError::NotPublished) => {
                return Err(SweepError::Publish { scope_id, error });
            }
        }
    }

    Ok(outcome)
}

/// Drive the sweep as an idle-cadence job: run [`sweep_pass`] and re-run it,
/// one `cadence` sleep apart via the [`Scheduler`] seam, until a pass both
/// succeeds **and** drops nothing to a lost race — the point convergence is
/// actually confirmed — or the `max_passes` cap is hit. A **retryable**
/// availability stall re-runs; a **lost CAS race** re-runs (the winner may be a
/// non-advancing write, so a drop is not proof of convergence); a **trust
/// failure** returns immediately.
///
/// Returns `Ok` on the first fully-converged pass. On cap exhaustion it returns
/// the last availability `Err`, or — if the final pass merely still had lost-race
/// drops — `Ok` with those scopes surfaced in
/// [`SweepOutcome::dropped_lost_race`], so a host racing a persistently hot
/// writer sees the residual rather than a false "complete".
///
/// Scheduling is engineering judgment (blueprint/engine.md L275-278): the cadence
/// and attempt cap are the host's, injected here; time enters only through the
/// scheduler seam so the harness runs multi-tick timelines in virtual time.
// Each seam is a distinct injected dependency (the determinism law keeps entropy,
// time, and the two network edges separate); bundling them into an ad-hoc struct
// purely to shrink the arg count would be abstraction for its own sake.
#[allow(clippy::too_many_arguments)]
pub async fn run_sweep<E, F, S, R, P>(
    entropy: &mut E,
    floors: &F,
    scheduler: &S,
    resolver: &R,
    publisher: &P,
    root_scope_id: [u8; 16],
    root_child_index: &[ChildScopeRef],
    cadence: Duration,
    max_passes: u32,
) -> Result<SweepOutcome, SweepError>
where
    E: Entropy,
    F: FloorStore,
    S: Scheduler,
    R: SweepResolver,
    P: ScopeRootPublisher,
{
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        match sweep_pass(
            entropy,
            floors,
            resolver,
            publisher,
            root_scope_id,
            root_child_index,
        )
        .await
        {
            // Fully converged: the pass succeeded and lost no race.
            Ok(outcome) if outcome.dropped_lost_race.is_empty() => return Ok(outcome),
            // A lost race leaves those nodes unproven-converged; re-resolve on the
            // next cadence. On cap exhaustion, surface the residual drops.
            Ok(outcome) => {
                if attempts >= max_passes {
                    return Ok(outcome);
                }
                scheduler.sleep(cadence).await;
            }
            Err(e) if e.is_retryable() && attempts < max_passes => {
                scheduler.sleep(cadence).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::UnixMillis;
    use crate::secret_util::ct_eq_32;
    use crate::testkit::fakes::{InMemoryFloorStore, VirtualScheduler};
    use crate::testkit::{SeededEntropy, block_on};
    use cipherbox_core::seal::{
        AadContext, GrantSetCommitment, GrantSetEntry, Permission, STRUCT_TAG_OWNER_BLOB,
        open_owner_blob, sign_grant_set,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::x25519::X25519Secret;
    use std::rc::Rc;

    const V: u64 = 2;

    fn sid(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn childref(byte: u8) -> ChildScopeRef {
        ChildScopeRef::new(sid(byte), format!("ipns-{byte:02x}").into_bytes())
    }

    /// The one vault owner/pseudonym identity every scope in a scenario commits
    /// to (so `reseal_scope_root`'s signer + committed-ledger guards pass).
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
    }

    /// The immutable per-scope material a scope root resolves to, plus the
    /// mutable current epoch and any injected CAS fault. Shared across the
    /// resolver and publisher so a publish advances what a re-resolve observes —
    /// the "network".
    struct NetScope {
        override_seed: [u8; 32],
        write_scope_seed: [u8; 32],
        pointer_read_key: [u8; 32],
        parent_node_seed: Option<[u8; 32]>,
        commitment: GrantSetCommitment,
        commitment_sig: [u8; ECDSA_SIG_LEN],
        grant_ledger: Vec<GrantLedgerEntry>,
        children: Vec<ChildScopeRef>,
        current_epoch: u64,
        fault: Option<ScopeRootPublishError>,
        /// A countdown of self-healing `NotPublished` failures — the next `n`
        /// publishes fail, then the node heals (drives the retry driver).
        fail_next: u32,
        /// A countdown of `LostRace` losses that do **not** advance the epoch —
        /// models a non-advancing ordinary writer winning the sequence CAS, so a
        /// drop does not converge the node until the sweep finally wins.
        lost_race_next: u32,
        publishes: u32,
    }

    /// A fake resolver + publisher over one shared scope map — the sweep's fake
    /// "network". A publish updates `current_epoch` so a re-resolve converges;
    /// an injected `fault` scripts a lost race or a not-published stall.
    #[derive(Clone)]
    struct FakeNet {
        owner: Rc<Owner>,
        scopes: Rc<RefCell<HashMap<[u8; 16], NetScope>>>,
        /// Scopes the resolver should fail (forged/unavailable subtree).
        resolve_faults: Rc<RefCell<HashMap<[u8; 16], ResolveFailure>>>,
    }

    impl FakeNet {
        fn new() -> Self {
            Self {
                owner: Rc::new(Owner::new()),
                scopes: Rc::new(RefCell::new(HashMap::new())),
                resolve_faults: Rc::new(RefCell::new(HashMap::new())),
            }
        }

        /// Register a scope root: one read grant to the shared grantee, `children`
        /// as its direct-child index, published at `current_epoch`.
        fn scope(self, byte: u8, current_epoch: u64, children: &[u8]) -> Self {
            self.scope_with_index(byte, current_epoch, children, false)
        }

        /// As [`Self::scope`] but optionally seeds a *non-canonical* stored index
        /// (a duplicate child) to exercise the self-heal.
        fn scope_with_index(
            self,
            byte: u8,
            current_epoch: u64,
            children: &[u8],
            non_canonical: bool,
        ) -> Self {
            let tag = [byte.wrapping_add(0xa0); 32];
            let commitment = GrantSetCommitment {
                ipns_name: format!("ipns-{byte:02x}").into_bytes(),
                owner_pseudonym_pk: self.owner.pseudonym.verifying_key().to_bytes(),
                entries: vec![GrantSetEntry::new(tag, Permission::Read, [0x02; 32])],
                unknown: Vec::new(),
            };
            let commitment_sig = sign_grant_set(&self.owner.ecdsa, &commitment)
                .unwrap()
                .to_compact();
            let grant_ledger = vec![GrantLedgerEntry::new(
                [0x02; 33],
                self.owner.grantee.public().to_bytes(),
                Permission::Read,
                tag,
            )];
            let mut index: Vec<ChildScopeRef> = children.iter().map(|b| childref(*b)).collect();
            if non_canonical {
                // A duplicate scope_id: canonicalize() drops it → flagged.
                if let Some(first) = children.first() {
                    index.push(ChildScopeRef::new(sid(*first), b"dup".to_vec()));
                }
            }
            self.scopes.borrow_mut().insert(
                sid(byte),
                NetScope {
                    override_seed: [byte; 32],
                    write_scope_seed: [byte.wrapping_add(1); 32],
                    pointer_read_key: [byte.wrapping_add(2); 32],
                    parent_node_seed: Some([byte.wrapping_add(3); 32]),
                    commitment,
                    commitment_sig,
                    grant_ledger,
                    children: index,
                    current_epoch,
                    fault: None,
                    fail_next: 0,
                    lost_race_next: 0,
                    publishes: 0,
                },
            );
            self
        }

        /// The next `n` publishes of `byte` lose the CAS without advancing the
        /// epoch (a non-advancing writer wins), then the sweep wins and converges.
        fn lost_race_next(self, byte: u8, n: u32) -> Self {
            self.scopes
                .borrow_mut()
                .get_mut(&sid(byte))
                .expect("scope")
                .lost_race_next = n;
            self
        }

        /// The next `n` publishes of `byte` fail `NotPublished`, then heal.
        fn fail_next(self, byte: u8, n: u32) -> Self {
            self.scopes
                .borrow_mut()
                .get_mut(&sid(byte))
                .expect("scope")
                .fail_next = n;
            self
        }

        fn fault(self, byte: u8, fault: ScopeRootPublishError) -> Self {
            self.scopes
                .borrow_mut()
                .get_mut(&sid(byte))
                .expect("scope")
                .fault = Some(fault);
            self
        }

        fn resolve_fault(self, byte: u8, reason: ResolveFailure) -> Self {
            self.resolve_faults.borrow_mut().insert(sid(byte), reason);
            self
        }

        fn clear_fault(&self, byte: u8) {
            self.scopes
                .borrow_mut()
                .get_mut(&sid(byte))
                .expect("scope")
                .fault = None;
        }

        fn current_epoch(&self, byte: u8) -> u64 {
            self.scopes
                .borrow()
                .get(&sid(byte))
                .expect("scope")
                .current_epoch
        }

        fn publishes(&self, byte: u8) -> u32 {
            self.scopes
                .borrow()
                .get(&sid(byte))
                .expect("scope")
                .publishes
        }
    }

    impl SweepResolver for FakeNet {
        async fn resolve(&self, scope: &ChildScopeRef) -> Result<SweepTarget, ResolveFailure> {
            if let Some(reason) = self.resolve_faults.borrow().get(&scope.scope_id) {
                return Err(*reason);
            }
            let scopes = self.scopes.borrow();
            let s = scopes
                .get(&scope.scope_id)
                .ok_or(ResolveFailure::Unavailable)?;
            Ok(SweepTarget {
                v: V,
                scope_id: scope.scope_id,
                ipns_name: scope.ipns_name.clone(),
                current_read_epoch: s.current_epoch,
                owner_enc_pub: self.owner.enc.public(),
                parent_node_seed: s.parent_node_seed.map(Zeroizing::new),
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
            let mut scopes = self.scopes.borrow_mut();
            let s = scopes.get_mut(&record.scope_id).expect("scope");
            s.publishes += 1;
            if s.fail_next > 0 {
                s.fail_next -= 1;
                return Err(ScopeRootPublishError::NotPublished);
            }
            if s.lost_race_next > 0 {
                // A non-advancing writer won the sequence CAS: the epoch does NOT
                // move, so a single drop does not converge the node.
                s.lost_race_next -= 1;
                return Err(ScopeRootPublishError::LostRace);
            }
            match s.fault {
                None => {
                    s.current_epoch = s.current_epoch.max(record.read_epoch);
                    Ok(())
                }
                // A persistent lost race modelling a concurrent *sweeper* winner:
                // the winner's record is at (at least) our epoch, so the node
                // re-resolves as converged on the next pass.
                Some(ScopeRootPublishError::LostRace) => {
                    s.current_epoch = s.current_epoch.max(record.read_epoch);
                    Err(ScopeRootPublishError::LostRace)
                }
                // Not published: nothing landed, epoch unchanged.
                Some(ScopeRootPublishError::NotPublished) => {
                    Err(ScopeRootPublishError::NotPublished)
                }
            }
        }
    }

    /// Raise the epoch floor for each scope byte to `epoch`.
    fn raise_floors(floors: &InMemoryFloorStore, scopes: &[u8], epoch: u64) {
        for b in scopes {
            block_on(floors.raise_epoch_floor(&sid(*b), epoch)).unwrap();
        }
    }

    fn run(
        net: &FakeNet,
        floors: &InMemoryFloorStore,
        seed: u64,
        root: u8,
        root_children: &[u8],
    ) -> Result<SweepOutcome, SweepError> {
        let index: Vec<ChildScopeRef> = root_children.iter().map(|b| childref(*b)).collect();
        block_on(async {
            let mut entropy = SeededEntropy::new(seed);
            sweep_pass(&mut entropy, floors, net, net, sid(root), &index).await
        })
    }

    #[test]
    fn completeness_every_reachable_descendant_converges_to_floor() {
        // root(00) -> A(01) -> B(02) -> C(03); all descendants lag at epoch 1,
        // floor raised to 5. One pass must converge every reachable descendant.
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01])
            .scope(0x01, 1, &[0x02])
            .scope(0x02, 1, &[0x03])
            .scope(0x03, 1, &[]);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01, 0x02, 0x03], 5);

        let outcome = run(&net, &floors, 1, 0x00, &[0x01]).expect("sweep");
        let mut converged = outcome.converged.clone();
        converged.sort();
        assert_eq!(
            converged,
            vec![sid(0x01), sid(0x02), sid(0x03)],
            "every reachable descendant converged"
        );
        // And the network now holds each descendant at the floor epoch: no node
        // left lagging.
        for b in [0x01, 0x02, 0x03] {
            assert_eq!(net.current_epoch(b), 5, "descendant re-keyed up to floor");
        }
    }

    #[test]
    fn rerun_is_idempotent_noop() {
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01])
            .scope(0x01, 1, &[0x02])
            .scope(0x02, 1, &[]);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01, 0x02], 5);

        let first = run(&net, &floors, 1, 0x00, &[0x01]).expect("first");
        assert_eq!(first.converged.len(), 2);

        let second = run(&net, &floors, 1, 0x00, &[0x01]).expect("second");
        assert!(second.converged.is_empty(), "nothing left to converge");
        let mut already = second.already_converged.clone();
        already.sort();
        assert_eq!(already, vec![sid(0x01), sid(0x02)], "all already converged");
    }

    #[test]
    fn already_converged_nodes_are_not_resealed() {
        // A(01) already at the floor; the sweep must not re-publish it.
        let net = FakeNet::new().scope(0x00, 5, &[0x01]).scope(0x01, 5, &[]);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01], 5);

        let outcome = run(&net, &floors, 1, 0x00, &[0x01]).expect("sweep");
        assert_eq!(outcome.already_converged, vec![sid(0x01)]);
        assert!(outcome.converged.is_empty());
        assert_eq!(net.publishes(0x01), 0, "converged node never re-published");
    }

    #[test]
    fn no_floor_means_not_lagging() {
        // No floor was ever raised for A → nothing to converge to.
        let net = FakeNet::new().scope(0x00, 5, &[0x01]).scope(0x01, 1, &[]);
        let floors = InMemoryFloorStore::default();
        let outcome = run(&net, &floors, 1, 0x00, &[0x01]).expect("sweep");
        assert_eq!(outcome.already_converged, vec![sid(0x01)]);
        assert_eq!(net.publishes(0x01), 0);
    }

    #[test]
    fn metadata_only_reuses_seed_no_epoch_bump_no_history_link() {
        // The crypto property: a swept descendant's owner blob still decrypts to
        // its EXISTING override seed, at exactly the floor epoch (not floor+1),
        // with no history link appended.
        let net = FakeNet::new().scope(0x00, 4, &[0x01]).scope(0x01, 2, &[]);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01], 4);

        // Capture the published record via a recording publisher wrapper.
        let published = Rc::new(RefCell::new(Vec::<ResealedScopeRoot>::new()));
        struct Recorder {
            net: FakeNet,
            log: Rc<RefCell<Vec<ResealedScopeRoot>>>,
        }
        impl SweepResolver for Recorder {
            async fn resolve(&self, scope: &ChildScopeRef) -> Result<SweepTarget, ResolveFailure> {
                self.net.resolve(scope).await
            }
        }
        impl ScopeRootPublisher for Recorder {
            async fn publish_scope_root(
                &self,
                record: &ResealedScopeRoot,
            ) -> Result<(), ScopeRootPublishError> {
                self.log.borrow_mut().push(record.clone());
                self.net.publish_scope_root(record).await
            }
        }
        let rec = Recorder {
            net: net.clone(),
            log: Rc::clone(&published),
        };
        let index = vec![childref(0x01)];
        block_on(async {
            let mut entropy = SeededEntropy::new(1);
            sweep_pass(&mut entropy, &floors, &rec, &rec, sid(0x00), &index).await
        })
        .expect("sweep");

        let log = published.borrow();
        assert_eq!(log.len(), 1);
        let record = &log[0];
        assert_eq!(
            record.read_epoch, 4,
            "re-sealed at the floor, no epoch bump"
        );
        assert_eq!(record.write_epoch, 1, "write epoch unchanged");
        assert!(
            record.section.history_links.is_empty(),
            "prev=None: no history link minted"
        );
        let ctx = AadContext {
            v: V,
            id: sid(0x01),
            scope: sid(0x01),
            epoch: 4,
            struct_tag: STRUCT_TAG_OWNER_BLOB,
        };
        let payload = open_owner_blob(
            &net.owner.enc,
            &record.section.owner_blob.enc,
            &ctx,
            &record.section.owner_blob.ciphertext,
        )
        .unwrap();
        assert!(
            ct_eq_32(payload.override_seed(), &[0x01; 32]),
            "sweep reused the existing seed, minted none"
        );
    }

    #[test]
    fn lost_cas_race_drops_node_and_continues() {
        // A(01) lost the CAS; B(02) still converges. The loser drops and
        // re-resolves converged — never a clobber or a hard abort.
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01, 0x02])
            .scope(0x01, 1, &[])
            .scope(0x02, 1, &[])
            .fault(0x01, ScopeRootPublishError::LostRace);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01, 0x02], 5);

        let outcome = run(&net, &floors, 1, 0x00, &[0x01, 0x02]).expect("sweep");
        assert_eq!(outcome.dropped_lost_race, vec![sid(0x01)]);
        assert_eq!(outcome.converged, vec![sid(0x02)]);
        // Re-resolve: the lost-race node reads converged (the winner advanced it).
        let second = run(&net, &floors, 1, 0x00, &[0x01, 0x02]).expect("second");
        assert!(second.converged.is_empty());
        assert!(second.dropped_lost_race.is_empty());
        let mut already = second.already_converged.clone();
        already.sort();
        assert_eq!(already, vec![sid(0x01), sid(0x02)]);
    }

    #[test]
    fn not_published_hard_aborts_fail_closed_never_silent_skip() {
        // A(01) cannot be published. The pass aborts naming A rather than marking
        // it converged — under-convergence must never be silently swallowed.
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01])
            .scope(0x01, 1, &[])
            .fault(0x01, ScopeRootPublishError::NotPublished);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01], 5);

        let err = run(&net, &floors, 1, 0x00, &[0x01]).expect_err("fails closed");
        assert_eq!(err.check(), "publish-failed");
        assert!(err.is_retryable(), "availability stall is retryable");
        match err {
            SweepError::Publish { scope_id, .. } => assert_eq!(scope_id, sid(0x01)),
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn enumeration_rejected_descendant_fails_closed_fatal() {
        // B(02) is a forged/rejected subtree. The pass aborts fail-closed and the
        // trust rejection is NOT retryable.
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01])
            .scope(0x01, 1, &[0x02])
            .scope(0x02, 1, &[])
            .resolve_fault(0x02, ResolveFailure::Rejected);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01, 0x02], 5);

        let err = run(&net, &floors, 1, 0x00, &[0x01]).expect_err("fails closed");
        assert_eq!(err.check(), "enumeration-incomplete");
        assert!(!err.is_retryable(), "a trust rejection is fatal");
    }

    #[test]
    fn enumeration_unavailable_descendant_is_retryable() {
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01])
            .scope(0x01, 1, &[])
            .resolve_fault(0x01, ResolveFailure::Unavailable);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01], 5);
        let err = run(&net, &floors, 1, 0x00, &[0x01]).expect_err("unavailable");
        assert_eq!(err.check(), "enumeration-incomplete");
        assert!(err.is_retryable());
    }

    #[test]
    fn reseal_trust_failure_is_fatal() {
        // Corrupt A(01)'s ledger so it diverges from the committed set: the
        // re-seal rejects it fail-closed and it is not retryable.
        let net = FakeNet::new().scope(0x00, 5, &[0x01]).scope(0x01, 1, &[]);
        net.scopes
            .borrow_mut()
            .get_mut(&sid(0x01))
            .unwrap()
            .grant_ledger
            .push(GrantLedgerEntry::new(
                [0x09; 33],
                X25519Secret::from_scalar([0x0f; 32]).public().to_bytes(),
                Permission::Write,
                [0xff; 32], // uncommitted tag
            ));
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01], 5);

        let err = run(&net, &floors, 1, 0x00, &[0x01]).expect_err("diverging ledger");
        assert_eq!(err.check(), "reseal-rejected");
        assert!(!err.is_retryable(), "a trust violation is fatal");
        match err {
            SweepError::Reseal { scope_id, error } => {
                assert_eq!(scope_id, sid(0x01));
                assert_eq!(error.check(), "ledger-diverges-from-commitment");
            }
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn self_heal_canonicalizes_index_and_flags() {
        // A(01)'s stored index carries a duplicate child scope_id (crash residue).
        // The sweep re-publishes it canonical and flags A.
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01])
            .scope_with_index(0x01, 1, &[0x02], true)
            .scope(0x02, 1, &[]);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01, 0x02], 5);

        let outcome = run(&net, &floors, 1, 0x00, &[0x01]).expect("sweep");
        assert_eq!(
            outcome.flagged_indexes,
            vec![sid(0x01)],
            "repaired index flagged"
        );
        // A converged canonical index is not re-flagged on a subsequent sweep.
        let again = run(&net, &floors, 1, 0x00, &[0x01]).expect("second");
        assert!(again.flagged_indexes.is_empty());
    }

    #[test]
    fn partial_sweep_then_resume_converges_all() {
        // A(01) publishes; B(02) is not-published this pass (abort after A). Heal,
        // re-run: A is already converged, B now converges. No node is stranded.
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01, 0x02])
            .scope(0x01, 1, &[])
            .scope(0x02, 1, &[])
            .fault(0x02, ScopeRootPublishError::NotPublished);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01, 0x02], 5);

        // First pass aborts on B, but A durably converged in the network.
        let err = run(&net, &floors, 1, 0x00, &[0x01, 0x02]).expect_err("partial");
        assert_eq!(err.check(), "publish-failed");
        assert_eq!(net.current_epoch(0x01), 5, "A converged before the abort");
        assert_eq!(net.current_epoch(0x02), 1, "B did not land");

        net.clear_fault(0x02);
        let outcome = run(&net, &floors, 1, 0x00, &[0x01, 0x02]).expect("resume");
        assert_eq!(
            outcome.converged,
            vec![sid(0x02)],
            "only B still needed work"
        );
        assert_eq!(outcome.already_converged, vec![sid(0x01)]);
        assert_eq!(net.current_epoch(0x02), 5, "B converged on resume");
    }

    #[test]
    fn run_sweep_retries_availability_until_converged() {
        // The idle-cadence driver: A(01)'s first publish is NotPublished (the pass
        // aborts), the node self-heals, and the driver's next pass — after one
        // cadence sleep on the virtual clock — converges it.
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01])
            .scope(0x01, 1, &[])
            .fail_next(0x01, 1);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01], 5);

        let scheduler = VirtualScheduler::new().with_auto_advance();
        let index = vec![childref(0x01)];
        let outcome = block_on(async {
            let mut entropy = SeededEntropy::new(1);
            run_sweep(
                &mut entropy,
                &floors,
                &scheduler,
                &net,
                &net,
                sid(0x00),
                &index,
                Duration::from_secs(30),
                4,
            )
            .await
        })
        .expect("driver converges after retry");
        assert_eq!(outcome.converged, vec![sid(0x01)]);
        assert_eq!(
            net.publishes(0x01),
            2,
            "one failed pass, one succeeding retry"
        );
        assert!(
            scheduler.now() >= UnixMillis(30_000),
            "the driver slept one cadence before the retry"
        );
    }

    #[test]
    fn run_sweep_gives_up_after_max_passes_on_persistent_stall() {
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01])
            .scope(0x01, 1, &[])
            .fault(0x01, ScopeRootPublishError::NotPublished);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01], 5);
        let scheduler = VirtualScheduler::new().with_auto_advance();
        let index = vec![childref(0x01)];
        let err = block_on(async {
            let mut entropy = SeededEntropy::new(1);
            run_sweep(
                &mut entropy,
                &floors,
                &scheduler,
                &net,
                &net,
                sid(0x00),
                &index,
                Duration::from_secs(30),
                3,
            )
            .await
        })
        .expect_err("persistent stall surfaces");
        assert_eq!(err.check(), "publish-failed");
        // Three attempts were made (one per allowed pass).
        assert_eq!(net.publishes(0x01), 3);
    }

    #[test]
    fn run_sweep_loops_past_non_advancing_lost_race_until_it_wins() {
        // The Finding-1 scenario: a non-advancing writer wins the sequence CAS
        // twice (the epoch never moves, so a single drop does NOT converge the
        // node). run_sweep must keep re-resolving — not return Ok on the drop —
        // until the sweep finally wins the CAS and the node truly converges.
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01])
            .scope(0x01, 1, &[])
            .lost_race_next(0x01, 2);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01], 5);

        let scheduler = VirtualScheduler::new().with_auto_advance();
        let index = vec![childref(0x01)];
        let outcome = block_on(async {
            let mut entropy = SeededEntropy::new(1);
            run_sweep(
                &mut entropy,
                &floors,
                &scheduler,
                &net,
                &net,
                sid(0x00),
                &index,
                Duration::from_secs(30),
                5,
            )
            .await
        })
        .expect("driver converges after two lost races");
        assert_eq!(outcome.converged, vec![sid(0x01)], "the sweep finally won");
        assert!(
            outcome.dropped_lost_race.is_empty(),
            "no residual drop once converged"
        );
        assert_eq!(net.current_epoch(0x01), 5, "node truly at the floor");
        assert_eq!(
            net.publishes(0x01),
            3,
            "two lost races, one winning publish"
        );
    }

    #[test]
    fn run_sweep_surfaces_residual_drop_on_cap_exhaustion() {
        // A persistently hot non-advancing writer: run_sweep exhausts its passes
        // and returns Ok, but surfaces the still-dropped node rather than a false
        // "complete".
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01])
            .scope(0x01, 1, &[])
            .lost_race_next(0x01, 10);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01], 5);
        let scheduler = VirtualScheduler::new().with_auto_advance();
        let index = vec![childref(0x01)];
        let outcome = block_on(async {
            let mut entropy = SeededEntropy::new(1);
            run_sweep(
                &mut entropy,
                &floors,
                &scheduler,
                &net,
                &net,
                sid(0x00),
                &index,
                Duration::from_secs(30),
                3,
            )
            .await
        })
        .expect("returns Ok with residual surfaced");
        assert_eq!(
            outcome.dropped_lost_race,
            vec![sid(0x01)],
            "residual lost-race node surfaced, not silently complete"
        );
        assert!(outcome.converged.is_empty());
        assert_eq!(net.publishes(0x01), 3, "one attempt per allowed pass");
    }

    #[test]
    fn concurrent_sweepers_converge_without_double_advance() {
        // Two sweepers over the same shared network. The first converges the
        // subtree; the second sees every node already converged — no re-publish,
        // no clobber, no floor double-advance.
        let net = FakeNet::new()
            .scope(0x00, 7, &[0x01])
            .scope(0x01, 3, &[0x02])
            .scope(0x02, 3, &[]);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01, 0x02], 7);

        let first = run(&net, &floors, 1, 0x00, &[0x01]).expect("sweeper 1");
        assert_eq!(first.converged.len(), 2);
        let p1 = (net.publishes(0x01), net.publishes(0x02));

        let second = run(&net, &floors, 2, 0x00, &[0x01]).expect("sweeper 2");
        assert!(second.converged.is_empty(), "second sweeper is a no-op");
        assert_eq!(second.already_converged.len(), 2);
        assert_eq!(
            (net.publishes(0x01), net.publishes(0x02)),
            p1,
            "no redundant re-publish by the second sweeper"
        );
    }

    #[test]
    fn diamond_shared_descendant_converged_once() {
        // root -> A(01), B(02); both -> D(04). D converges exactly once.
        let net = FakeNet::new()
            .scope(0x00, 5, &[0x01, 0x02])
            .scope(0x01, 1, &[0x04])
            .scope(0x02, 1, &[0x04])
            .scope(0x04, 1, &[]);
        let floors = InMemoryFloorStore::default();
        raise_floors(&floors, &[0x01, 0x02, 0x04], 5);

        let outcome = run(&net, &floors, 1, 0x00, &[0x01, 0x02]).expect("sweep");
        let mut converged = outcome.converged.clone();
        converged.sort();
        assert_eq!(converged, vec![sid(0x01), sid(0x02), sid(0x04)]);
        assert_eq!(net.publishes(0x04), 1, "shared descendant published once");
    }

    #[test]
    fn determinism_same_entropy_same_published_bytes() {
        let build = || {
            let net = FakeNet::new()
                .scope(0x00, 5, &[0x01])
                .scope(0x01, 1, &[0x02])
                .scope(0x02, 1, &[]);
            let floors = InMemoryFloorStore::default();
            raise_floors(&floors, &[0x01, 0x02], 5);
            let log = Rc::new(RefCell::new(Vec::<ResealedScopeRoot>::new()));
            struct Rec {
                net: FakeNet,
                log: Rc<RefCell<Vec<ResealedScopeRoot>>>,
            }
            impl SweepResolver for Rec {
                async fn resolve(
                    &self,
                    scope: &ChildScopeRef,
                ) -> Result<SweepTarget, ResolveFailure> {
                    self.net.resolve(scope).await
                }
            }
            impl ScopeRootPublisher for Rec {
                async fn publish_scope_root(
                    &self,
                    record: &ResealedScopeRoot,
                ) -> Result<(), ScopeRootPublishError> {
                    self.log.borrow_mut().push(record.clone());
                    self.net.publish_scope_root(record).await
                }
            }
            let rec = Rec {
                net: net.clone(),
                log: Rc::clone(&log),
            };
            let index = vec![childref(0x01)];
            block_on(async {
                let mut entropy = SeededEntropy::new(42);
                sweep_pass(&mut entropy, &floors, &rec, &rec, sid(0x00), &index).await
            })
            .expect("sweep");
            let mut records = log.borrow().clone();
            records.sort_by(|a, b| a.scope_id.cmp(&b.scope_id));
            records
        };
        assert_eq!(build(), build(), "same entropy → byte-identical publishes");
    }
}
