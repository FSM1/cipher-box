//! `rotateScope` — the read-plane root cut (blueprint/engine.md "Rotation
//! primitives: rotateScope", #26 D2/D8, #38 D4/D5).
//!
//! The read-plane rotation: mint a fresh random override seed at the scope root
//! (via the injected entropy seam — never a direct RNG), re-seal the scope root's
//! [`GrantSection`](cipherbox_core::seal::GrantSection) at the next read epoch
//! through the shared [`reseal_scope_root`] helper, publish it CAS through the
//! injected [`ScopeRootPublisher`] seam, raise the durable `minReadEpoch` floor,
//! and enqueue the lazy-wave sweep. **Read-plane only**: `minReadEpoch` moves,
//! `writeEpoch` does not — the write-plane name wave (`rotateScopeWrite`) is a
//! separate primitive.
//!
//! # Effect ordering is crash-safety
//!
//! The three durable effects run in a fixed order — **publish → raise floor →
//! enqueue sweep** — each returning before the next on failure, so no
//! partially-rotated, fail-open, or locked-out state is left behind:
//!
//! - Publishing the new-epoch record **before** raising the floor means a crash
//!   between them leaves the old-epoch records still gate-passing (the floor has
//!   not moved) rather than demanding an epoch no published record satisfies — a
//!   lockout. The rotation simply re-runs; it is monotonic (a fresh seed, a
//!   higher epoch) and idempotent-safe under CAS. Raising the floor first would
//!   invert this into that lockout.
//! - The residual window this accepts — a revoked reader whose old-epoch
//!   forgeries still pass until the floor rises on the completing run — is the
//!   documented read-only-survivor residual (#38, "~one pointer-consult
//!   interval"), never a lost revocation boundary.
//! - The sweep is enqueued **last**, only after the cut is durable; it is
//!   best-effort and idempotent, so losing it to a crash costs only a delayed
//!   lazy wave the next ordinary write or scheduled sweep advances.
//!
//! This primitive is the root cut alone; the descendant re-key runs through the
//! same [`reseal_scope_root`] helper in [`cascade`](super::cascade).

use cipherbox_core::codec::RedactedBytes;
use cipherbox_core::seal::{GrantSection, SignedSealed};
use cipherbox_core::suite::secret::SECRET_LEN;
use core::fmt;

use super::eager_set::ResolveFailure;
use super::reseal::{
    CommittedSet, PrevEpochSeed, ResealError, ResealSeeds, ScopeRootIdentity, WriteHistory,
    reseal_scope_root,
};
use crate::entropy::{Entropy, fresh_seed};
use crate::seams::{BoxedTask, FloorStore, Scheduler, SeamError};

/// A fully re-sealed scope-root record handed to the [`ScopeRootPublisher`]: its
/// identity, the epochs it publishes at, and the signed grant section. Assembling
/// the envelope bytes (read-body re-seal + IPNS record signing) and moving them
/// CAS over the content plane + `/routing/v1` transport is the publisher's job.
/// It carries no seed: the publisher recovers the freshly minted override seed
/// from `section`'s own owner blob, so this type is not a key-material carrier.
#[derive(Clone, PartialEq, Eq)]
pub struct ResealedScopeRoot {
    /// The scope-root node id (== scope id).
    pub scope_id: [u8; 16],
    /// The scope root's opaque `ipnsName` bytes.
    pub ipns_name: Vec<u8>,
    /// The read epoch this cut publishes at (bumped).
    pub read_epoch: u64,
    /// The write epoch (unchanged by a read rotation).
    pub write_epoch: u64,
    /// The freshly re-sealed, structure-signed grant section.
    pub section: GrantSection,
}

impl fmt::Debug for ResealedScopeRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResealedScopeRoot")
            .field("scope_id", &self.scope_id)
            .field("ipns_name", &RedactedBytes::of(&self.ipns_name))
            .field("read_epoch", &self.read_epoch)
            .field("write_epoch", &self.write_epoch)
            .field("section", &self.section)
            .finish()
    }
}

/// Why a **rotation's** publish did not durably land as the freshest record at
/// its name. Every variant means the rotation must not advance its floor —
/// nothing was cut.
///
/// The rotation primitives publish two kinds of record — a re-sealed scope root
/// and, on the sweep and grant-creation paths, a re-sealed interior node — and
/// this is the verdict on either. It is the *caller's* classification of an
/// attempt, on rule 6's retryable-vs-trust axis;
/// [`RecordPublishError`](crate::net::record_publish::RecordPublishError) is the
/// publish *pipeline's* own report of what went wrong on the wire, which the
/// rotation seams fold into this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationPublishError {
    /// Register-first or the record PUT failed; nothing durable landed. Retryable.
    NotPublished,
    /// A concurrent writer's record at a higher sequence won the CAS race; the
    /// caller re-resolves and rebases before retrying.
    LostRace,
    /// The record the publish had to read first failed the adoption gate — a
    /// fail-closed trust violation, never staleness (AGENTS.md rule 6). Kept
    /// distinct from [`Self::NotPublished`] so a forged or transplanted record
    /// is never retried as if it were a flaky endpoint.
    Rejected,
}

impl RotationPublishError {
    /// Whether re-running the publish could clear this: an availability stall or
    /// a lost race, but never a trust rejection.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::NotPublished | Self::LostRace)
    }

    /// The class label a reject vector carries for this failure.
    pub fn class(&self) -> &'static str {
        match self {
            Self::NotPublished | Self::LostRace => "availability",
            Self::Rejected => "trust",
        }
    }
}

impl core::fmt::Display for RotationPublishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RotationPublishError::NotPublished => f.write_str("rotation record not published"),
            RotationPublishError::LostRace => f.write_str("rotation publish lost the CAS race"),
            RotationPublishError::Rejected => {
                f.write_str("rotation record rejected by adoption gate")
            }
        }
    }
}

impl std::error::Error for RotationPublishError {}

/// The publish effect of a rotation: CAS-publish a re-sealed scope-root record.
///
/// The one impure edge of `rotate_scope` besides the seams, mirroring the
/// eager-set walk's `ChildIndexResolver`: the traversal/composition is pure and
/// deterministic, and only this edge touches the content plane and the
/// `/routing/v1` transport. The production implementation
/// ([`crate::net::rotation::OwnerRotationNet`]) wraps the content-plane block
/// store, register-first, and [`net::publish`](crate::net::publish) CAS; tests
/// fake it.
pub trait ScopeRootPublisher {
    /// Register-first CAS-publish `record` at its scope root's `ipnsName`. `Ok`
    /// means the record is durably the freshest at the name; `Err` means nothing
    /// was cut (the caller must not advance the floor).
    async fn publish_scope_root(
        &self,
        record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError>;
}

/// The inputs to one scope root's read-plane rotation: its identity, its current
/// committed set, its current read-plane state (seed + epoch, which become the
/// history link's prior), the unchanged write-plane material, and its carried
/// history links.
pub struct RotateScopePlan<'a> {
    /// The scope root's stable identity and the rotator's pseudonym signer.
    pub identity: ScopeRootIdentity<'a>,
    /// The owner-committed grant set to re-wrap for (unchanged for a grantee/
    /// manual rotation; already-pruned by `revoke_read_grant` for a read revoke).
    pub committed: CommittedSet<'a>,
    /// The scope's current override (read scope) seed — becomes the new record's
    /// history-link prior. Caller-owned; never zeroized here.
    pub current_override_seed: &'a [u8; SECRET_LEN],
    /// The scope's current read epoch — the new record publishes at `+ 1`.
    pub current_read_epoch: u64,
    /// The write-plane scope seed (unchanged by a read rotation).
    pub write_scope_seed: &'a [u8; SECRET_LEN],
    /// The write epoch (unchanged by a read rotation).
    pub write_epoch: u64,
    /// The root's existing write-plane history link. A read rotation cuts no
    /// write plane, so it is carried verbatim ([`WriteHistory::Carried`]).
    pub write_history_link: &'a [u8],
    /// The stable per-scope pointer read key carried in every grant blob.
    pub pointer_read_key: &'a [u8; SECRET_LEN],
    /// The scope's existing per-epoch history links, oldest first. Re-signed and
    /// pruned to the retained window by the re-seal — see
    /// [`reseal_scope_root`](super::reseal::reseal_scope_root).
    pub carried_history_links: &'a [SignedSealed],
}

/// A fail-closed rotation failure. On every variant nothing durable was left
/// half-done: the floor is advanced only after a confirmed publish, and the sweep
/// only after a confirmed floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateError {
    /// The scope root the rotation had to resolve yielded no plan: its record
    /// failed the adoption gate, or the rotator holds no seed source in it.
    /// Fail-closed on the resolve's own axis, so a trust verdict is never
    /// retried as an availability stall (AGENTS.md rule 6).
    Resolve(ResolveFailure),
    /// Re-sealing the scope root failed (divergent ledger, unusable recipient
    /// key, or entropy failure) — nothing was published.
    Reseal(ResealError),
    /// The scope-root record did not land — nothing was cut, retry later.
    Publish(RotationPublishError),
    /// The durable epoch floor could not be raised after a confirmed publish. The
    /// record is published (no lockout); the cut completes on retry.
    Floor(SeamError),
    /// The read epoch is exhausted (`current_read_epoch == u64::MAX`). Rotating
    /// would reuse the epoch with fresh key material, violating key-regression
    /// monotonicity, so nothing is minted or published. Unreachable in practice.
    EpochExhausted,
}

impl core::fmt::Display for RotateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RotateError::Resolve(e) => write!(f, "scope-root resolve failed: {e}"),
            RotateError::Reseal(e) => write!(f, "re-seal failed: {e}"),
            RotateError::Publish(e) => write!(f, "publish failed: {e}"),
            RotateError::Floor(e) => write!(f, "epoch-floor raise failed: {e}"),
            RotateError::EpochExhausted => f.write_str("read epoch exhausted (u64::MAX)"),
        }
    }
}

impl std::error::Error for RotateError {}

impl RotateError {
    /// Every read-plane root-cut check, in declaration order — the surface
    /// `crates/engine/tests/kat_rotation.rs` pins (see the module header for the
    /// prefix rule).
    pub const CHECKS: &'static [&'static str] = &[
        "rot-read-resolve-failed",
        "rot-read-reseal-failed",
        "rot-read-publish-failed",
        "rot-read-floor-raise-failed",
        "rot-read-epoch-exhausted",
    ];

    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            RotateError::Resolve(_) => "rot-read-resolve-failed",
            RotateError::Reseal(_) => "rot-read-reseal-failed",
            RotateError::Publish(_) => "rot-read-publish-failed",
            RotateError::Floor(_) => "rot-read-floor-raise-failed",
            RotateError::EpochExhausted => "rot-read-epoch-exhausted",
        }
    }

    /// The class label used in reject vectors. Exhaustive, so a new variant must
    /// state its class rather than inherit `"trust"`.
    pub fn class(&self) -> &'static str {
        match self {
            RotateError::Resolve(reason) => reason.class(),
            RotateError::Reseal(error) => error.class(),
            RotateError::Publish(error) => error.class(),
            RotateError::Floor(_) => "availability",
            RotateError::EpochExhausted => "over-cap",
        }
    }

    /// Whether re-running the rotation could clear this failure — an
    /// availability stall, or a C2 label conflict the re-point wave repairs —
    /// versus a trust violation no retry can fix. Mirrors
    /// [`CascadeError::is_retryable`](super::cascade::CascadeError::is_retryable);
    /// a caller MUST still bound its retries, because a permanent label
    /// disagreement is retryable and never self-heals.
    pub fn is_retryable(&self) -> bool {
        match self {
            RotateError::Resolve(reason) => matches!(
                reason,
                ResolveFailure::Unavailable | ResolveFailure::ConflictingChildLabel
            ),
            // A size refusal judges the record the next pass re-resolves, not
            // its trust: a permanent verdict there would let whoever grew that
            // root block the owner's revocation for good.
            RotateError::Reseal(error) => matches!(
                error,
                ResealError::Entropy(_) | ResealError::SectionNotResealable { .. }
            ),
            RotateError::Publish(error) => error.is_retryable(),
            RotateError::Floor(_) => true,
            RotateError::EpochExhausted => false,
        }
    }
}

/// The result of a completed read-plane root cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationOutcome {
    /// The new read epoch the scope was cut to (`current_read_epoch + 1`).
    pub new_read_epoch: u64,
    /// The durable `minReadEpoch` floor after the raise (`>= new_read_epoch`).
    pub epoch_floor: u64,
}

/// Perform the read-plane root cut for the scope root in `plan`.
///
/// Mints a fresh random override seed via `entropy` (determinism law: never a
/// direct RNG), re-seals through [`reseal_scope_root`], publishes CAS via
/// `publisher`, raises `minReadEpoch` via `floors`, and enqueues the sweep task
/// (`make_sweep_task`) on `scheduler` — in that fixed, crash-safe order (module
/// docs). Read-plane only: the write epoch is unchanged.
///
/// `make_sweep_task` is invoked only on the success path, after the floor is
/// durably raised, and its future is the Slice-3 lazy-wave sweep entry.
pub async fn rotate_scope<E, F, S, P, Mk>(
    entropy: &mut E,
    floors: &F,
    scheduler: &S,
    publisher: &P,
    plan: &RotateScopePlan<'_>,
    make_sweep_task: Mk,
) -> Result<RotationOutcome, RotateError>
where
    E: Entropy,
    F: FloorStore,
    S: Scheduler,
    P: ScopeRootPublisher,
    Mk: FnOnce() -> BoxedTask,
{
    // Fail-closed BEFORE minting: a saturating bump at u64::MAX would republish
    // fresh key material under the same epoch (a key-regression violation), so an
    // exhausted epoch is rejected rather than silently reused.
    let new_read_epoch = plan
        .current_read_epoch
        .checked_add(1)
        .ok_or(RotateError::EpochExhausted)?;

    // Mint the fresh random override seed at the scope root (the read-plane cut).
    // `rotate_scope` is this seed's terminal owner: `Zeroizing` wipes it on every
    // return path, including the error paths and a panic unwind.
    let new_override_seed =
        fresh_seed(entropy).map_err(|e| RotateError::Reseal(ResealError::Entropy(e)))?;

    let seeds = ResealSeeds {
        override_seed: &new_override_seed,
        read_epoch: new_read_epoch,
        prev: Some(PrevEpochSeed {
            seed: plan.current_override_seed,
            epoch: plan.current_read_epoch,
        }),
        write_scope_seed: plan.write_scope_seed,
        write_epoch: plan.write_epoch,
        write_history: WriteHistory::Carried(plan.write_history_link),
        pointer_read_key: plan.pointer_read_key,
    };

    let section = reseal_scope_root(
        entropy,
        &plan.identity,
        &seeds,
        &plan.committed,
        plan.carried_history_links,
    )
    .map_err(RotateError::Reseal)?;

    let record = ResealedScopeRoot {
        scope_id: plan.identity.scope_id,
        ipns_name: plan.identity.ipns_name.to_vec(),
        read_epoch: new_read_epoch,
        write_epoch: plan.write_epoch,
        section,
    };

    // 1) Publish CAS. Nothing durable is left on failure — the floor is untouched.
    publisher
        .publish_scope_root(&record)
        .await
        .map_err(RotateError::Publish)?;

    complete_cut(
        floors,
        scheduler,
        &plan.identity.scope_id,
        new_read_epoch,
        make_sweep_task,
    )
    .await
}

/// Steps 2 and 3 of [`rotate_scope`], once `new_read_epoch` is published at
/// `scope_id`'s root.
pub(crate) async fn complete_cut<F: FloorStore, S: Scheduler>(
    floors: &F,
    scheduler: &S,
    scope_id: &[u8; 16],
    new_read_epoch: u64,
    make_sweep_task: impl FnOnce() -> BoxedTask,
) -> Result<RotationOutcome, RotateError> {
    // 2) Raise the durable minReadEpoch floor — only after a confirmed publish, so
    // a crash between the two never demands an unpublished epoch (no lockout).
    let epoch_floor = floors
        .raise_epoch_floor(scope_id, new_read_epoch)
        .await
        .map_err(RotateError::Floor)?;

    // 3) Enqueue the lazy-wave sweep — last, only after the cut is durable.
    scheduler.spawn(make_sweep_task());

    Ok(RotationOutcome {
        new_read_epoch,
        epoch_floor,
    })
}

#[cfg(test)]
mod tests;
