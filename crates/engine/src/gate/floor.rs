//! The floor law — durable monotonic advancement of the per-scope epoch and
//! per-name sequence floors (blueprint/engine.md "Adoption gate and floors",
//! #39 D4 / #38 D4).
//!
//! Floors are engine state, held behind the [`FloorStore`] seam. Every read
//! goes through this module's accessors, and it is the only place that advances
//! them **from the record plane** — the owner-authored rotation cut raises the
//! read-epoch floor directly ([`crate::rotation::rotate`],
//! [`crate::rotation::cascade`]). The record-plane advances are the four the law
//! admits:
//!
//! 1. **Advance on AAD-confirmed unseal** ([`advance_on_unseal`] for
//!    gate-adopted roots, [`advance_sequence_on_unseal`] for child records) —
//!    the sole record-sourced paths. A record's sequence/epoch move the floors
//!    only after its body cryptographically unsealed (the adoption gate's
//!    stage 6), never from a claimed-but-unconfirmed field.
//! 2. **Cold-seed from a re-point object** ([`cold_seed`]) — the cold-start
//!    anchor. The owner-vouched `minReadEpoch` seeds the read-epoch floor (the
//!    revocation boundary) and `writeEpoch` the write-epoch floor. The
//!    [`RepointObject`] is authenticated by construction, so no floor moves on
//!    an unsigned or non-owner re-point (see [`cold_seed`]).
//! 3. **Pointer `writeEpoch` advances on sight** ([`advance_write_epoch_on_sight`])
//!    — an owner-vouched write epoch above the durable floor raises it the
//!    moment it is seen (#38 D4).
//! 4. **Regression is fail-closed** — every advance is monotonic-max via the
//!    store (raising below the stored floor is a no-op that keeps the max), so
//!    a floor can never move backward.
//! 5. **A minted scope seeds its own write-epoch floor**
//!    ([`seed_write_epoch_on_mint`]) — no pointer plane speaks for a scope that
//!    does not exist yet, so the device that mints one anchors it.
//!
//! A grant blob's epoch field is an advisory routing hint and has **no**
//! advancement path here — deliberately. Nothing reads it as authority.
//!
//! The body-revision mint counters squat in the sequence namespace
//! ([`mint_revision`]) — one per record family whose sealed body carries a
//! revision, each under its own `*-revision-mint/` prefix. Each is a local
//! write clock, never an adoption bar, so it raises the store directly; the bar
//! it feeds (`*-revision/`) moves only through [`advance_sequence_on_unseal`].

use core::cell::RefCell;
use core::marker::PhantomData;
use std::collections::BTreeSet;

use cipherbox_core::payload::RepointObject;

use crate::gate::{GateError, GateRejection, GateStage, RejectionReason};
use crate::seams::{FloorRaise, FloorStore, SeamError, SeamResult};

/// An owner-vouched epoch that regressed below a durable floor at cold-seed — a
/// rolled-back re-point object, a fail-closed trust violation and never mere
/// staleness (the floor law: revocation boundaries cannot be rolled back).
///
/// Where the read-epoch comparison is sound — and where it must not run — is
/// [`cold_seed_checked`]'s contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorRegression {
    /// The re-point's `minReadEpoch` is strictly below the durable read-epoch
    /// (revocation) floor — an attempt to roll back a revocation boundary.
    ReadEpoch {
        /// The durable read-epoch floor.
        floor: u64,
        /// The re-point's owner-vouched `minReadEpoch`.
        vouched: u64,
    },
    /// The re-point's `writeEpoch` is strictly below the durable write-epoch
    /// floor — a rolled-back owner-vouched write clock.
    WriteEpoch {
        /// The durable write-epoch floor.
        floor: u64,
        /// The re-point's owner-vouched `writeEpoch`.
        vouched: u64,
    },
}

impl core::fmt::Display for FloorRegression {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FloorRegression::ReadEpoch { floor, vouched } => write!(
                f,
                "read-epoch floor regression: vouched {vouched} below durable floor {floor}"
            ),
            FloorRegression::WriteEpoch { floor, vouched } => write!(
                f,
                "write-epoch floor regression: vouched {vouched} below durable floor {floor}"
            ),
        }
    }
}

impl std::error::Error for FloorRegression {}

/// Which pointer plane vouched the re-point under test (blueprint/engine.md
/// "Pointer planes").
///
/// The two planes carry the same `writeEpoch` field under different authority:
/// only one of them is a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerPlane {
    /// The indexed vault pointer — the cold-start anchor. The vault anchor's
    /// write rotation re-points it too, but after the scope pointer and not
    /// atomically with it, so this plane legitimately trails that one until the
    /// wave's next resume. Its `writeEpoch` is therefore never a clock.
    VaultPointer,
    /// The scope pointer — re-pointed by every write rotation, and the
    /// write-epoch floor's only owner-vouched clock (#38 D4).
    ScopePointer,
}

/// A cold-seed failure: a host floor-store I/O error (availability), or a
/// fail-closed [`FloorRegression`] (a trust violation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColdSeedError {
    /// A [`FloorStore`] seam failure — host I/O, retryable, never a trust verdict.
    Seam(SeamError),
    /// A fail-closed floor regression.
    Regression(FloorRegression),
}

impl core::fmt::Display for ColdSeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ColdSeedError::Seam(e) => write!(f, "{e}"),
            ColdSeedError::Regression(r) => write!(f, "{r}"),
        }
    }
}

impl std::error::Error for ColdSeedError {}

/// Suffix that distinguishes a scope's write-epoch floor key from its
/// read-epoch floor key inside the [`FloorStore`] epoch namespace. The
/// read-epoch floor (the revocation boundary the adoption gate's epoch stage
/// enforces against the envelope epoch tag) is keyed by the bare 16-byte scope
/// id; the write-epoch floor, an independent clock authored by owner-only write
/// rotations, is keyed by the scope id plus this suffix so the two never
/// collide.
const WRITE_EPOCH_SUFFIX: &[u8] = b"/write-epoch";

/// Suffix for the vault-pointer index high-water mark, squatting in the epoch
/// namespace beside the two epoch floors of the same scope. It is not an epoch:
/// it is the highest vault-pointer index this device has walked to, and it
/// ratchets on the same monotonic-max terms so a truncated walk cannot step
/// back onto an abandoned index ([`vault_pointer_index_floor`]).
const VAULT_POINTER_INDEX_SUFFIX: &[u8] = b"/vault-pointer-index";

/// `scope_id` under a fixed suffix. The store matches keys exactly and the
/// scope id is fixed-width, so two keys collide only if their suffixes are
/// equal; the suffixes here are distinct literals and nothing appends past
/// them.
fn suffixed(scope_id: &[u8; 16], suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(scope_id.len() + suffix.len());
    key.extend_from_slice(scope_id);
    key.extend_from_slice(suffix);
    key
}

/// The [`FloorStore`] epoch-namespace key for a scope's write-epoch floor.
fn write_epoch_key(scope_id: &[u8; 16]) -> Vec<u8> {
    suffixed(scope_id, WRITE_EPOCH_SUFFIX)
}

/// The scope's durable read-epoch floor (the revocation boundary), if ever
/// raised. This is the floor the adoption gate's epoch stage compares the
/// envelope epoch tag against.
pub async fn read_epoch_floor<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
) -> SeamResult<Option<u64>> {
    floors.epoch_floor(scope_id).await
}

/// The scope's durable write-epoch floor, if ever raised.
pub async fn write_epoch_floor<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
) -> SeamResult<Option<u64>> {
    floors.epoch_floor(&write_epoch_key(scope_id)).await
}

/// The highest vault-pointer index this device has adopted, if it has ever
/// walked the chain. `None` is a device that has not, which is why a first walk
/// is unbarred and every later one is not.
pub async fn vault_pointer_index_floor<F: FloorStore>(
    floors: &F,
    root_scope_id: &[u8; 16],
) -> SeamResult<Option<u64>> {
    floors
        .epoch_floor(&suffixed(root_scope_id, VAULT_POINTER_INDEX_SUFFIX))
        .await
}

/// Ratchet the vault-pointer index high-water mark to `index`, monotonic-max.
/// Only the owner can extend the chain and an index never descends, so this
/// only ever moves toward the owner's own recovery bump.
pub async fn advance_vault_pointer_index<F: FloorStore>(
    floors: &F,
    root_scope_id: &[u8; 16],
    index: u64,
) -> SeamResult<u64> {
    floors
        .raise_epoch_floor(&suffixed(root_scope_id, VAULT_POINTER_INDEX_SUFFIX), index)
        .await
}

/// The durable per-name sequence floor, if ever raised.
pub async fn sequence_floor<F: FloorStore>(
    floors: &F,
    ipns_name: &[u8],
) -> SeamResult<Option<u64>> {
    floors.sequence_floor(ipns_name).await
}

/// How [`check`]'s sequence comparison treats a record at exactly the durable
/// floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strictness {
    /// The adopt path: the sequence must be strictly above the floor (a record
    /// at the floor is our own current record, not an update).
    StrictlyNewer,
    /// The at-floor re-open path (our own current record / cached
    /// last-known-good): only exact equality is admitted — lower is a
    /// fail-closed replay, higher is a record that never passed an adopt.
    AtFloor,
    /// The replay bar alone: the floor or anything above it. The one read that
    /// takes it ([`crate::rotation::sweep`]'s interior nodes) must reach records
    /// the **epoch** stage refuses, so it runs [`check_sequence`] rather than
    /// [`check`] — and its bar is named here, beside the rest of the floor law,
    /// rather than hand-rolled at the call site.
    AtOrAboveFloor,
}

/// The per-name sequence floor alone — gate stage 4, per `strictness`.
pub async fn check_sequence<F: FloorStore>(
    floors: &F,
    ipns_name: &[u8],
    sequence: u64,
    strictness: Strictness,
) -> Result<(), GateError> {
    let floor = sequence_floor(floors, ipns_name)
        .await
        .map_err(GateError::Seam)?
        .unwrap_or(0);
    let replayed = match strictness {
        Strictness::StrictlyNewer => sequence <= floor,
        Strictness::AtFloor => sequence != floor,
        Strictness::AtOrAboveFloor => sequence < floor,
    };
    if replayed {
        return Err(GateError::Rejected(GateRejection {
            stage: GateStage::Sequence,
            reason: RejectionReason::SequenceNotNewer { floor, sequence },
        }));
    }
    Ok(())
}

/// The durable floor checks — gate stages 4/5: the per-name sequence floor
/// (per `strictness`) and the scope's read-epoch floor (the revocation
/// boundary, always `>=`). Shared by the root gate and the child pipeline.
pub async fn check<F: FloorStore>(
    floors: &F,
    ipns_name: &[u8],
    scope_id: &[u8; 16],
    sequence: u64,
    epoch: u64,
    strictness: Strictness,
) -> Result<(), GateError> {
    check_sequence(floors, ipns_name, sequence, strictness).await?;
    let epoch_floor = read_epoch_floor(floors, scope_id)
        .await
        .map_err(GateError::Seam)?
        .unwrap_or(0);
    if epoch < epoch_floor {
        return Err(GateError::Rejected(GateRejection {
            stage: GateStage::Epoch,
            reason: RejectionReason::EpochBelowFloor {
                floor: epoch_floor,
                epoch,
            },
        }));
    }
    Ok(())
}

/// Advance floors after an AAD-confirmed **root** unseal. Raises the per-scope
/// read-epoch floor to `epoch` and the per-name sequence floor to `sequence`,
/// both monotonic-max. Callers invoke this only after a successful unseal
/// behind the six-stage root gate: eagerly via [`adopt`](crate::gate::adopt),
/// or deferred via [`PendingAdoption::commit`](crate::gate::PendingAdoption::commit)
/// — so a record whose body never unsealed can never move a floor; the
/// provenance the plain scalar arguments cannot express is enforced at those
/// call sites. Child unseals go through [`advance_sequence_on_unseal`] instead.
///
/// **Fail-safe ordering.** The read-epoch (revocation) and sequence floors are
/// distinctly keyed. The batch lists the trust-critical **read-epoch
/// (revocation) floor first**, so on a backing without a cross-key transaction
/// an interrupted commit is epoch-advanced (fail-closed — old-epoch records
/// still reject) with only the sequence floor stale-low, whose sole effect is a
/// harmless idempotent re-adoption of the identical record on retry. A backing
/// that honors [`FloorStore::commit_floors`] atomically makes the pair
/// all-or-nothing instead; either way the monotonic-max, idempotent
/// raises let a retried `adopt` re-converge.
pub async fn advance_on_unseal<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    ipns_name: &[u8],
    sequence: u64,
    epoch: u64,
) -> SeamResult<()> {
    // Revocation floor first (see "Fail-safe ordering" above).
    floors
        .commit_floors(&[
            FloorRaise::epoch(scope_id.as_slice(), epoch),
            FloorRaise::sequence(ipns_name, sequence),
        ])
        .await?;
    Ok(())
}

/// Advance only the per-name sequence floor after an AAD-confirmed **child**
/// unseal. The scope read-epoch floor advances only from gate-adopted roots
/// ([`advance_on_unseal`]): a child's epoch is attested only by the
/// epoch-independent read key, so it must never move the revocation boundary
/// (blueprint/engine.md floor law).
pub async fn advance_sequence_on_unseal<F: FloorStore>(
    floors: &F,
    ipns_name: &[u8],
    sequence: u64,
) -> SeamResult<()> {
    floors.raise_sequence_floor(ipns_name, sequence).await?;
    Ok(())
}

/// Why a body-revision mint produced no value a reader would accept. Both
/// variants fail the publish closed: nothing is sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevisionMintError {
    /// The durable counter could not be read or raised. Host I/O, not a verdict.
    Store(SeamError),
    /// The counter did not advance, so the publish would seal a revision the
    /// reader refuses.
    Stalled,
}

/// Mint the next body revision for a record family whose sealed body carries
/// one, advancing the writer's durable counter at `mint_key` **before** the PUT.
///
/// Attempt-scoped, which is the whole point: a revision derived from the
/// confirm-gated sequence floor re-mints the same value on a retry and so cannot
/// tell two same-sequence forks apart. The writer's counter and the reader's
/// high-water at `adopted_key` stay separate durable values, so an attempt that
/// never landed advances only the former and never makes this device refuse the
/// live record it failed to replace.
///
/// AGENTS.md rule 8: the reader refuses a revision below its high-water, so a
/// counter that did not actually advance fails here, release-active, rather than
/// sealing bytes the reader would reject.
pub async fn mint_revision<F: FloorStore>(
    floors: &F,
    mint_key: &[u8],
    adopted_key: &[u8],
) -> Result<u64, RevisionMintError> {
    let read = |key| async move {
        sequence_floor(floors, key)
            .await
            .map(|floor| floor.unwrap_or(0))
            .map_err(RevisionMintError::Store)
    };
    let next = read(mint_key)
        .await?
        .max(read(adopted_key).await?)
        .checked_add(1)
        .ok_or(RevisionMintError::Stalled)?;
    // A local write clock, not a record-plane advance, so it raises the store
    // directly. Rule 8's guard is the compare: a store that reports a floor
    // other than the one we asked for did not take our value.
    let stored = floors
        .raise_sequence_floor(mint_key, next)
        .await
        .map_err(RevisionMintError::Store)?;
    if stored != next {
        return Err(RevisionMintError::Stalled);
    }
    Ok(next)
}

/// Cold-seed a scope's floors from an owner-vouched re-point object. Raises the
/// read-epoch floor to `minReadEpoch` (the revocation boundary) and the
/// write-epoch floor to `writeEpoch`, both monotonic-max — the two epoch floors
/// only.
///
/// The [`RepointObject`] argument is only obtainable from a successful
/// [`open_pointer_payload`](cipherbox_core::payload::open_pointer_payload),
/// which authenticates the owner identity signature and the seal — so a forged,
/// tampered, or non-owner re-point never produces one, and this function never
/// runs on unauthenticated input. As with [`advance_on_unseal`], the
/// trust-critical read-epoch (revocation) floor commits before the write-epoch
/// floor, so a partial seam failure leaves the fail-closed state (or none at
/// all, on a backing with an atomic [`FloorStore::commit_floors`]).
///
/// **The two epoch floors only.** [`RepointObject`] vouches no sequence, so
/// nothing here anchors the sequence namespace and a cold device meets a
/// long-lived name with a bar of 0 — the within-epoch staleness
/// blueprint/engine.md's floor law accepts. Closing it needs the owner to vouch
/// a sequence the way it vouches the epochs, which is a wire change.
pub async fn cold_seed<F: FloorStore>(floors: &F, repoint: &RepointObject) -> SeamResult<()> {
    // Revocation floor first (fail-safe ordering).
    floors
        .commit_floors(&[
            FloorRaise::epoch(repoint.scope_id.as_slice(), repoint.min_read_epoch),
            FloorRaise::epoch(write_epoch_key(&repoint.scope_id), repoint.write_epoch),
        ])
        .await?;
    Ok(())
}

/// The durable floor an owner-vouched re-point would roll back, if any — the
/// one definition of the two-stage rule, so the consume side
/// ([`cold_seed_checked`]) and the produce side that must refuse to sign such a
/// re-point cannot drift apart (AGENTS.md rule 8).
///
/// The read-epoch stage runs **only at the vault anchor**, selected from the
/// re-point's own scope id against `session_root_scope_id`. At the vault anchor
/// the read epoch is owner-authored, so a vouched `minReadEpoch` below the
/// durable floor is an unambiguous rollback. At a shared scope a grantee's
/// legitimate lazy rotation unseal-advances that same floor *past* the
/// owner-authored `minReadEpoch`, so the identical comparison would
/// false-positive into a self-inflicted bricked boot.
///
/// The write-epoch stage is narrowed on the other axis: only the scope pointer
/// authors that clock ([`PointerPlane::VaultPointer`]).
///
/// The exempt plane is guarded instead by the read-epoch stage above, the
/// durable [`vault_pointer_index_floor`], and the clock-checked scope-pointer
/// consult — not by a bound on the lag, which a wave that stops at the anchor
/// and is never resumed leaves unbounded.
pub async fn repoint_regression<F: FloorStore>(
    floors: &F,
    repoint: &RepointObject,
    session_root_scope_id: &[u8; 16],
    plane: PointerPlane,
) -> SeamResult<Option<FloorRegression>> {
    if repoint.scope_id == *session_root_scope_id
        && let Some(floor) = read_epoch_floor(floors, &repoint.scope_id).await?
        && repoint.min_read_epoch < floor
    {
        return Ok(Some(FloorRegression::ReadEpoch {
            floor,
            vouched: repoint.min_read_epoch,
        }));
    }
    match plane {
        PointerPlane::ScopePointer => {
            write_epoch_regression(floors, &repoint.scope_id, repoint.write_epoch).await
        }
        PointerPlane::VaultPointer => Ok(None),
    }
}

/// The durable write-epoch floor an owner-vouched `write_epoch` would roll back,
/// if any — the write half of [`repoint_regression`], split out for the consult,
/// which must not run the read stage.
pub async fn write_epoch_regression<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    write_epoch: u64,
) -> SeamResult<Option<FloorRegression>> {
    Ok(write_epoch_floor(floors, scope_id)
        .await?
        .filter(|floor| write_epoch < *floor)
        .map(|floor| FloorRegression::WriteEpoch {
            floor,
            vouched: write_epoch,
        }))
}

/// Cold-seed a scope's floors **fail-closed on regression** (the floor law) —
/// the single checked cold-seed seam production uses.
///
/// Reads the durable floors and rejects before any write if the re-point
/// regresses one ([`repoint_regression`]) — a replay past a revocation
/// boundary, a trust violation and never mere staleness. Only when nothing
/// regresses does it advance the floors via the monotonic-max [`cold_seed`].
///
/// Check-then-advance is deliberately not a CAS pair: the engine is the single
/// writer (blueprint/engine.md "Facade"), and the monotonic-max store backstops
/// it either way.
pub async fn cold_seed_checked<F: FloorStore>(
    floors: &F,
    repoint: &RepointObject,
    session_root_scope_id: &[u8; 16],
) -> Result<(), ColdSeedError> {
    // Cold-seeding *is* the vault-pointer path — both callers read that plane.
    let plane = PointerPlane::VaultPointer;
    if let Some(regression) = repoint_regression(floors, repoint, session_root_scope_id, plane)
        .await
        .map_err(ColdSeedError::Seam)?
    {
        return Err(ColdSeedError::Regression(regression));
    }
    cold_seed(floors, repoint)
        .await
        .map_err(ColdSeedError::Seam)
}

/// Advance the write-epoch floor on sight of an owner-vouched pointer
/// `writeEpoch` (floor law item 3). Monotonic-max: a value at or below the
/// durable floor is a no-op that reports the stored floor. Returns the
/// resulting floor.
///
/// **Takes the [`WriteEpochLease`] for the raise**, and defers when the scope is
/// already leased — returning the durable floor untouched and without waiting,
/// so the value returned is the floor in force, not the sighted epoch. The
/// sighting is dropped rather than queued; a floor only ever moves up, and the
/// focus tick's polled consult re-sights the same pointer next pass.
///
/// The lease is held *across* the raise, not merely tested before it: the host
/// store is asynchronous, and a publish that took the lease while a raise was
/// still in flight would guard against the pre-raise floor and sign below the
/// one that lands — the brick [`WriteEpochLease`] exists to prevent.
pub async fn advance_write_epoch_on_sight<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    write_epoch: u64,
) -> SeamResult<u64> {
    let Some(_lease) = acquire_write_epoch_lease(scope_id) else {
        return Ok(write_epoch_floor(floors, scope_id).await?.unwrap_or(0));
    };
    floors
        .raise_epoch_floor(&write_epoch_key(scope_id), write_epoch)
        .await
}

/// Seed the write-epoch floor of a scope this device is **minting** (floor law
/// item 5) — a grant's promoted scope root, which no pointer plane speaks for
/// until it exists. Returns the resulting floor.
///
/// A pre-advance, which [`WriteEpochLease`] forbids for a *rotation*: there the
/// target is an epoch the publish has yet to reach, so raising first would lock
/// the write plane out on a retryable failure. A read grant cuts no write scope,
/// so `write_epoch` here is the epoch the node's write plane already publishes
/// at, and the root about to be signed binds that same value as its
/// owner-write-blob AAD — raising after the signature is what would strand it.
pub async fn seed_write_epoch_on_mint<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    write_epoch: u64,
) -> SeamResult<u64> {
    advance_write_epoch_on_sight(floors, scope_id, write_epoch).await
}

/// Exclusion over one scope's write-epoch floor, held across a root publish so
/// the floor the publish guard read is still true when the record is signed.
///
/// `recover_write_scope_seed` (`crate::net::adopter`) binds that floor into the
/// owner-write-blob's AAD, so a root signed below a floor a concurrent advance
/// has already raised is permanently unopenable, and a signed record cannot be
/// unpublished (AGENTS.md rule 8).
///
/// Exclusion, deliberately not a pre-advance: raising the floor to the wave's
/// target before publishing would turn a retryable publish failure into a
/// permanent local write-plane lockout, since nothing can lower a floor again.
///
/// Held until dropped, with no expiry: a lease that lapsed before the publish
/// reached its signature would re-open that same permanent brick, while an
/// over-held lease costs only this session's rotations for the scope.
///
/// [`cold_seed`] raises the same floor without taking the lease: it is the boot
/// anchor, and holding it back would leave a session unable to seed.
#[derive(Debug)]
pub(crate) struct WriteEpochLease {
    scope_id: [u8; 16],
    /// The registry is thread-local, so a lease that crossed threads would
    /// release an entry in the wrong one.
    _not_send: PhantomData<*const ()>,
}

// The registry is execution-context-local because every engine future is `!Send`
// (the nets hold `&RefCell<E>` and `Engine` is saturated with `Rc`), so a
// publish and the consult that could race it always share one context.
thread_local! {
    static WRITE_EPOCH_LEASES: RefCell<BTreeSet<[u8; 16]>> =
        const { RefCell::new(BTreeSet::new()) };
}

/// Hold `scope_id`'s write-epoch floor still, or `None` when the scope is
/// already leased — a publish and a sighting raise on one scope are serialized
/// by refusal, never raced.
pub(crate) fn acquire_write_epoch_lease(scope_id: &[u8; 16]) -> Option<WriteEpochLease> {
    WRITE_EPOCH_LEASES.with(|leases| {
        leases
            .borrow_mut()
            .insert(*scope_id)
            .then(|| WriteEpochLease {
                scope_id: *scope_id,
                _not_send: PhantomData,
            })
    })
}

impl Drop for WriteEpochLease {
    fn drop(&mut self) {
        WRITE_EPOCH_LEASES.with(|leases| {
            leases.borrow_mut().remove(&self.scope_id);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryFloorStore;

    const SCOPE: [u8; 16] = [7u8; 16];
    const SHARED_SCOPE: [u8; 16] = [8u8; 16];
    const NAME: &[u8] = b"k51-scope-root-name";

    #[test]
    fn advance_on_unseal_raises_both_floors_monotonically() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            advance_on_unseal(&floors, &SCOPE, NAME, 5, 3)
                .await
                .unwrap();
            assert_eq!(sequence_floor(&floors, NAME).await.unwrap(), Some(5));
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(3));

            // A regression attempt is a no-op: the store keeps the max.
            advance_on_unseal(&floors, &SCOPE, NAME, 2, 1)
                .await
                .unwrap();
            assert_eq!(sequence_floor(&floors, NAME).await.unwrap(), Some(5));
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(3));
        });
    }

    #[test]
    fn advance_sequence_on_unseal_never_touches_the_epoch_floor() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            advance_sequence_on_unseal(&floors, NAME, 7).await.unwrap();
            assert_eq!(sequence_floor(&floors, NAME).await.unwrap(), Some(7));
            assert_eq!(
                read_epoch_floor(&floors, &SCOPE).await.unwrap(),
                None,
                "a child unseal must not move the scope read-epoch floor"
            );
        });
    }

    /// The adopt path's bar. A name with no floor admits its first record, and
    /// once the floor sits at that sequence the same record is no longer
    /// strictly newer — which is why a genesis root's sequence floor is left
    /// unseeded until its own first adopt raises it.
    #[test]
    fn strictly_newer_admits_a_first_record_then_refuses_it_at_the_floor() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            check_sequence(&floors, NAME, 1, Strictness::StrictlyNewer)
                .await
                .expect("an unseeded floor admits the first record");

            advance_sequence_on_unseal(&floors, NAME, 1).await.unwrap();
            let err = check_sequence(&floors, NAME, 1, Strictness::StrictlyNewer)
                .await
                .expect_err("a record at the floor is not strictly newer");
            assert!(
                matches!(
                    err,
                    GateError::Rejected(GateRejection {
                        stage: GateStage::Sequence,
                        reason: RejectionReason::SequenceNotNewer {
                            floor: 1,
                            sequence: 1
                        },
                    })
                ),
                "{err:?}"
            );
        });
    }

    #[test]
    fn at_floor_admits_only_the_exact_floor() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            advance_on_unseal(&floors, &SCOPE, NAME, 5, 1)
                .await
                .unwrap();
            check(&floors, NAME, &SCOPE, 5, 1, Strictness::AtFloor)
                .await
                .expect("the exact floor re-opens");
            for above_or_below in [4, 6] {
                let err = check(
                    &floors,
                    NAME,
                    &SCOPE,
                    above_or_below,
                    1,
                    Strictness::AtFloor,
                )
                .await
                .expect_err("anything but the exact floor is fail-closed");
                assert!(matches!(
                    err,
                    GateError::Rejected(GateRejection {
                        stage: GateStage::Sequence,
                        reason: RejectionReason::SequenceNotNewer { floor: 5, .. },
                    })
                ));
            }
        });
    }

    fn repoint(scope_id: [u8; 16], min_read_epoch: u64, write_epoch: u64) -> RepointObject {
        use cipherbox_core::ipns::IpnsName;
        use cipherbox_core::kdf;
        RepointObject {
            scope_id,
            current_root: IpnsName::from_public_key(
                &kdf::vault_pointer_index(b"root", 0).verifying_key(),
            ),
            write_epoch,
            min_read_epoch,
            prev_root: None,
        }
    }

    #[test]
    fn cold_seed_checked_seeds_a_fresh_scope_then_is_monotonic() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            // A fresh (unseeded) scope adopts the owner-vouched anchor.
            cold_seed_checked(&floors, &repoint(SCOPE, 5, 3), &SCOPE)
                .await
                .unwrap();
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(5));
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(3));
            // Re-seeding at or above the floor advances monotonically.
            cold_seed_checked(&floors, &repoint(SCOPE, 7, 3), &SCOPE)
                .await
                .unwrap();
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(7));
        });
    }

    /// The cold-start posture the floor law accepts, pinned so it is a decision
    /// rather than a drift: the anchor seeds the two epoch floors and nothing in
    /// the sequence namespace, because the re-point vouches no sequence. A cold
    /// device therefore meets a long-lived name with a bar of 0 and admits an
    /// older owner-signed record from the vouched epoch.
    #[test]
    fn a_cold_seed_anchors_the_epoch_floors_and_never_the_sequence_namespace() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            cold_seed_checked(&floors, &repoint(SCOPE, 5, 3), &SCOPE)
                .await
                .expect("a fresh scope seeds");

            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(5));
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(3));
            assert_eq!(
                sequence_floor(&floors, NAME).await.unwrap(),
                None,
                "no anchored sequence bar, so a cold device admits the first record it sees"
            );
            check_sequence(&floors, NAME, 1, Strictness::StrictlyNewer)
                .await
                .expect("an older record from the vouched epoch still clears stage 4");
        });
    }

    /// The vault-pointer index high-water mark ratchets and never descends, and
    /// it is keyed apart from the two epoch floors of the same scope.
    #[test]
    fn the_vault_pointer_index_floor_ratchets_and_is_keyed_apart() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            assert_eq!(
                vault_pointer_index_floor(&floors, &SCOPE).await.unwrap(),
                None,
                "a device that has never walked the chain has no bar"
            );

            advance_vault_pointer_index(&floors, &SCOPE, 2)
                .await
                .unwrap();
            advance_vault_pointer_index(&floors, &SCOPE, 1)
                .await
                .unwrap();
            assert_eq!(
                vault_pointer_index_floor(&floors, &SCOPE).await.unwrap(),
                Some(2),
                "monotonic-max: a lower index is a no-op"
            );
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), None);
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), None);
        });
    }

    #[test]
    fn cold_seed_checked_rejects_a_read_epoch_regression_fail_closed() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            cold_seed_checked(&floors, &repoint(SCOPE, 5, 3), &SCOPE)
                .await
                .unwrap();
            // A rolled-back re-point vouching a lower minReadEpoch is fail-closed.
            let err = cold_seed_checked(&floors, &repoint(SCOPE, 4, 3), &SCOPE)
                .await
                .expect_err("read-epoch regression is a trust violation");
            assert_eq!(
                err,
                ColdSeedError::Regression(FloorRegression::ReadEpoch {
                    floor: 5,
                    vouched: 4
                })
            );
            // The durable floor is untouched by the rejected seed.
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(5));
        });
    }

    #[test]
    fn a_scope_pointer_below_its_own_write_floor_is_fail_closed() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            advance_write_epoch_on_sight(&floors, &SCOPE, 6)
                .await
                .unwrap();
            let regression = repoint_regression(
                &floors,
                &repoint(SCOPE, 5, 4),
                &SCOPE,
                PointerPlane::ScopePointer,
            )
            .await
            .unwrap();
            assert_eq!(
                regression,
                Some(FloorRegression::WriteEpoch {
                    floor: 6,
                    vouched: 4
                })
            );
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(6));
        });
    }

    /// The read-epoch regression check is unrepresentable for a shared scope: a
    /// `minReadEpoch` far below the durable read-epoch floor (the legitimate
    /// steady state once grantee lazy rotation has unseal-advanced that floor)
    /// seeds cleanly instead of false-positiving into a fail-closed DoS. The
    /// same numbers at the vault anchor are fail-closed.
    #[test]
    fn cold_seed_checked_shared_scope_skips_the_read_epoch_check() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            // Grantee lazy rotation has driven both scopes' read-epoch floor to 9.
            advance_on_unseal(&floors, &SHARED_SCOPE, NAME, 1, 9)
                .await
                .unwrap();
            advance_on_unseal(&floors, &SCOPE, NAME, 1, 9)
                .await
                .unwrap();

            // A shared-scope cold-seed vouching minReadEpoch 4 (< floor 9) is the
            // normal steady state — it must NOT fire the read-epoch check.
            cold_seed_checked(&floors, &repoint(SHARED_SCOPE, 4, 2), &SCOPE)
                .await
                .expect("shared-scope cold-seed never runs the read-epoch check");
            // The monotonic-max floor is unmoved by the lower vouched read epoch;
            // the write-epoch floor still seeds.
            assert_eq!(
                read_epoch_floor(&floors, &SHARED_SCOPE).await.unwrap(),
                Some(9)
            );
            assert_eq!(
                write_epoch_floor(&floors, &SHARED_SCOPE).await.unwrap(),
                Some(2)
            );

            // The identical input at the vault anchor IS a fail-closed rollback.
            let err = cold_seed_checked(&floors, &repoint(SCOPE, 4, 2), &SCOPE)
                .await
                .expect_err("the read-epoch check is sound and active at the root anchor");
            assert_eq!(
                err,
                ColdSeedError::Regression(FloorRegression::ReadEpoch {
                    floor: 9,
                    vouched: 4
                })
            );
        });
    }

    /// Skipping the read-epoch *check* for a shared scope must not skip the
    /// unconditional `cold_seed`: a fresh (None) shared scope still seeds its
    /// read-epoch floor to `minReadEpoch` via the monotonic-max raise, exactly
    /// as the vault anchor does. Guards a future refactor from dropping the seed
    /// for a shared scope.
    #[test]
    fn cold_seed_checked_shared_scope_seeds_a_fresh_read_epoch_floor() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            cold_seed_checked(&floors, &repoint(SHARED_SCOPE, 5, 3), &SCOPE)
                .await
                .expect("a fresh shared scope seeds without running the read-epoch check");
            assert_eq!(
                read_epoch_floor(&floors, &SHARED_SCOPE).await.unwrap(),
                Some(5)
            );
            assert_eq!(
                write_epoch_floor(&floors, &SHARED_SCOPE).await.unwrap(),
                Some(3)
            );
        });
    }

    /// Exactly one re-point channel escapes the write-epoch floor, and the match
    /// below is exhaustive on purpose: a third channel stops this compiling until
    /// the law says which plane the new channel advances the clock of.
    #[test]
    fn only_the_vault_pointer_channel_escapes_the_write_epoch_floor() {
        use crate::rotation::RepointChannel;

        let floors = InMemoryFloorStore::default();
        block_on(async {
            advance_write_epoch_on_sight(&floors, &SCOPE, 6)
                .await
                .unwrap();
            for channel in [RepointChannel::ScopePointer, RepointChannel::VaultPointer] {
                let plane = match channel {
                    RepointChannel::ScopePointer => PointerPlane::ScopePointer,
                    RepointChannel::VaultPointer => PointerPlane::VaultPointer,
                };
                let regression = repoint_regression(&floors, &repoint(SCOPE, 5, 1), &SCOPE, plane)
                    .await
                    .unwrap();
                assert_eq!(
                    regression.is_none(),
                    channel == RepointChannel::VaultPointer,
                    "the write-epoch floor holds every channel but the anchor's"
                );
            }
        });
    }

    /// Measuring the two planes against one bar bricks the boot whenever a root
    /// write rotation stopped between its two flips, on honest state
    /// ([`PointerPlane`]).
    #[test]
    fn cold_seed_never_bars_the_vault_pointer_on_a_raised_write_floor() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            // A root write rotation's scope-pointer consult raised the floor.
            advance_write_epoch_on_sight(&floors, &SCOPE, 6)
                .await
                .unwrap();

            cold_seed_checked(&floors, &repoint(SCOPE, 5, 1), &SCOPE)
                .await
                .expect("the genesis vault pointer rolled back no plane it writes");
            assert_eq!(
                write_epoch_floor(&floors, &SCOPE).await.unwrap(),
                Some(6),
                "the monotonic-max raise leaves the higher floor standing"
            );

            // The identical numbers on the advancing plane stay fail-closed.
            assert_eq!(
                repoint_regression(
                    &floors,
                    &repoint(SCOPE, 5, 1),
                    &SCOPE,
                    PointerPlane::ScopePointer
                )
                .await
                .unwrap(),
                Some(FloorRegression::WriteEpoch {
                    floor: 6,
                    vouched: 1
                }),
                "a scope pointer below the floor it authors is a rollback"
            );
        });
    }

    /// The write bar is scope-blind: a shared scope's pointer is held to it on
    /// the same terms as the vault anchor's.
    #[test]
    fn a_shared_scopes_pointer_is_held_to_the_same_write_bar() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            advance_write_epoch_on_sight(&floors, &SHARED_SCOPE, 6)
                .await
                .unwrap();
            assert_eq!(
                repoint_regression(
                    &floors,
                    &repoint(SHARED_SCOPE, 5, 4),
                    &SCOPE,
                    PointerPlane::ScopePointer
                )
                .await
                .unwrap(),
                Some(FloorRegression::WriteEpoch {
                    floor: 6,
                    vouched: 4
                }),
                "write-epoch regression is fail-closed for every role"
            );
        });
    }

    #[test]
    fn read_and_write_epoch_floors_are_independent() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            advance_on_unseal(&floors, &SCOPE, NAME, 1, 4)
                .await
                .unwrap();
            advance_write_epoch_on_sight(&floors, &SCOPE, 9)
                .await
                .unwrap();
            // The write-epoch floor moving does not disturb the read-epoch floor.
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(4));
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(9));
        });
    }

    /// A sighting under a live lease leaves the floor where the guard read it,
    /// and returns rather than blocking on the publish it defers to.
    #[test]
    fn a_sighting_under_a_live_lease_defers_instead_of_racing_the_publish() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            advance_write_epoch_on_sight(&floors, &SCOPE, 4)
                .await
                .unwrap();

            let lease = acquire_write_epoch_lease(&SCOPE).expect("a free scope leases");
            assert_eq!(
                advance_write_epoch_on_sight(&floors, &SCOPE, 9)
                    .await
                    .unwrap(),
                4,
                "a leased scope reports the floor the publish guard read"
            );
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(4));

            // Releasing reopens the advance; the deferred sighting re-applies.
            drop(lease);
            assert_eq!(
                advance_write_epoch_on_sight(&floors, &SCOPE, 9)
                    .await
                    .unwrap(),
                9
            );
        });
    }

    /// A lease is scoped: it holds one scope's floor still and no other's.
    #[test]
    fn a_lease_defers_only_its_own_scope() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            let _lease = acquire_write_epoch_lease(&SCOPE).expect("leases");
            advance_write_epoch_on_sight(&floors, &SHARED_SCOPE, 7)
                .await
                .unwrap();
            assert_eq!(
                write_epoch_floor(&floors, &SHARED_SCOPE).await.unwrap(),
                Some(7)
            );
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), None);
        });
    }

    #[test]
    fn a_second_publish_on_one_scope_is_refused_not_raced() {
        let held = acquire_write_epoch_lease(&SCOPE).expect("the first publish leases");
        assert!(
            acquire_write_epoch_lease(&SCOPE).is_none(),
            "a concurrent publish on the same scope must not take the lease"
        );
        drop(held);
        assert!(
            acquire_write_epoch_lease(&SCOPE).is_some(),
            "the release frees the scope"
        );
    }

    /// The lease has no expiry, so nothing can release it out from under the
    /// publish it protects — the floor stays held until the guard drops, however
    /// long the publish's fan-out takes to reach its signature.
    #[test]
    fn only_the_drop_releases_a_lease() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            advance_write_epoch_on_sight(&floors, &SCOPE, 4)
                .await
                .unwrap();
            let lease = acquire_write_epoch_lease(&SCOPE).expect("leases");

            // However many sightings arrive, the floor stays where the guard read it.
            for sighted in [9, 11, 20] {
                advance_write_epoch_on_sight(&floors, &SCOPE, sighted)
                    .await
                    .unwrap();
            }
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(4));

            drop(lease);
            assert!(
                acquire_write_epoch_lease(&SCOPE).is_some(),
                "the drop is what frees the scope"
            );
        });
    }

    /// A floor store that reports whether the scope was leasable at the instant
    /// the raise was executing.
    #[derive(Default)]
    struct LeaseProbeFloorStore {
        inner: InMemoryFloorStore,
        leasable_mid_raise: Cell<bool>,
    }

    impl FloorStore for LeaseProbeFloorStore {
        async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
            self.inner.epoch_floor(scope_id).await
        }

        async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
            self.leasable_mid_raise
                .set(acquire_write_epoch_lease(&SCOPE).is_some());
            self.inner.raise_epoch_floor(scope_id, epoch).await
        }

        async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
            self.inner.sequence_floor(ipns_name).await
        }

        async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
            self.inner.raise_sequence_floor(ipns_name, sequence).await
        }

        async fn clear(&self) -> SeamResult<()> {
            self.inner.clear().await
        }
    }

    /// The lease covers the raise itself, not just the moment before it. A host
    /// store is asynchronous, so a publish that could take the lease while the
    /// raise is in flight would guard against the pre-raise floor and sign a
    /// root the landed floor leaves unopenable.
    #[test]
    fn a_sighting_holds_the_lease_across_the_raise() {
        let floors = LeaseProbeFloorStore::default();
        block_on(async {
            advance_write_epoch_on_sight(&floors, &SCOPE, 9)
                .await
                .unwrap();
        });
        assert!(
            !floors.leasable_mid_raise.get(),
            "a publish must not take the lease while a sighting raise is in flight"
        );
    }
}
