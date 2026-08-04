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
//!
//! A grant blob's epoch field is an advisory routing hint and has **no**
//! advancement path here — deliberately. Nothing reads it as authority.

use cipherbox_core::payload::RepointObject;

use crate::gate::{GateError, GateRejection, GateStage, RejectionReason};
use crate::seams::{FloorRaise, FloorStore, SeamError, SeamResult};

/// An owner-vouched epoch that regressed below a durable floor at cold-seed — a
/// rolled-back re-point object, a fail-closed trust violation and never mere
/// staleness (the floor law: revocation boundaries cannot be rolled back).
///
/// Where the read-epoch comparison is sound — and where it must not run — is
/// [`AnchorRole`]'s contract.
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

/// The scope role a cold-seed runs against — the gate on the read-epoch
/// (revocation) regression check, which is sound **only at the root/vault
/// anchor**.
///
/// At the root scope the read epoch is owner-authored, so
/// [`advance_on_unseal`] raises the read-epoch floor in lockstep with the owner
/// clock and a vouched `minReadEpoch` below the durable floor is an unambiguous
/// owner rollback (correct fail-closed). At a **shared** scope a grantee's
/// legitimate lazy-rotation unseal-advances that same floor *past* the
/// owner-authored `minReadEpoch`, so the identical comparison would
/// false-positive into a self-inflicted fail-closed **DoS** (a bricked boot) —
/// never a security hole, since no rollback is accepted and the write-epoch
/// check stays unconditionally sound. `Shared` therefore never runs the
/// read-epoch check; only `Root` does (#763).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorRole {
    /// The vault/root anchor: read-epoch check runs (alongside write-epoch).
    Root,
    /// A shared scope: read-epoch check skipped; only write-epoch runs.
    ///
    /// A production `Shared` caller MUST select this role from authenticated
    /// scope identity, never a network/`RepointObject` field (#775).
    Shared,
}

/// Suffix that distinguishes a scope's write-epoch floor key from its
/// read-epoch floor key inside the [`FloorStore`] epoch namespace. The
/// read-epoch floor (the revocation boundary the adoption gate's epoch stage
/// enforces against the envelope epoch tag) is keyed by the bare 16-byte scope
/// id; the write-epoch floor, an independent clock authored by owner-only write
/// rotations, is keyed by the scope id plus this suffix so the two never
/// collide.
const WRITE_EPOCH_SUFFIX: &[u8] = b"/write-epoch";

/// The [`FloorStore`] epoch-namespace key for a scope's write-epoch floor.
fn write_epoch_key(scope_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(scope_id.len() + WRITE_EPOCH_SUFFIX.len());
    key.extend_from_slice(scope_id);
    key.extend_from_slice(WRITE_EPOCH_SUFFIX);
    key
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
    let floor = sequence_floor(floors, ipns_name)
        .await
        .map_err(GateError::Seam)?
        .unwrap_or(0);
    let replayed = match strictness {
        Strictness::StrictlyNewer => sequence <= floor,
        Strictness::AtFloor => sequence != floor,
    };
    if replayed {
        return Err(GateError::Rejected(GateRejection {
            stage: GateStage::Sequence,
            reason: RejectionReason::SequenceNotNewer { floor, sequence },
        }));
    }
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
/// all-or-nothing instead (#685); either way the monotonic-max, idempotent
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

/// Cold-seed a scope's floors from an owner-vouched re-point object. Raises the
/// read-epoch floor to `minReadEpoch` (the revocation boundary) and the
/// write-epoch floor to `writeEpoch`, both monotonic-max.
///
/// The [`RepointObject`] argument is only obtainable from a successful
/// [`open_pointer_payload`](cipherbox_core::payload::open_pointer_payload),
/// which authenticates the owner identity signature and the seal — so a forged,
/// tampered, or non-owner re-point never produces one, and this function never
/// runs on unauthenticated input. As with [`advance_on_unseal`], the
/// trust-critical read-epoch (revocation) floor commits before the write-epoch
/// floor, so a partial seam failure leaves the fail-closed state (or none at
/// all, on a backing with an atomic [`FloorStore::commit_floors`]).
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

/// Cold-seed a scope's floors **fail-closed on regression** (the floor law) —
/// the single checked cold-seed seam production uses.
///
/// Reads the durable floors and rejects before any write if the owner-vouched
/// re-point would move one backward: a re-point whose `writeEpoch` (any role),
/// or whose `minReadEpoch` (root anchor only, see below), is strictly below the
/// durable floor is a rolled-back pointer (a replay past a revocation
/// boundary), a trust violation never mere staleness. Only when nothing
/// regresses does it advance the floors via the monotonic-max [`cold_seed`].
///
/// The read-epoch check runs under [`AnchorRole::Root`] only; the write-epoch
/// check is unconditional — see [`AnchorRole`] for why.
///
/// Check-then-advance is deliberately not a CAS pair: the engine is the single
/// writer (blueprint/engine.md "Facade"), and the monotonic-max store backstops
/// it either way.
pub async fn cold_seed_checked<F: FloorStore>(
    floors: &F,
    repoint: &RepointObject,
    role: AnchorRole,
) -> Result<(), ColdSeedError> {
    if role == AnchorRole::Root {
        if let Some(floor) = read_epoch_floor(floors, &repoint.scope_id)
            .await
            .map_err(ColdSeedError::Seam)?
        {
            if repoint.min_read_epoch < floor {
                return Err(ColdSeedError::Regression(FloorRegression::ReadEpoch {
                    floor,
                    vouched: repoint.min_read_epoch,
                }));
            }
        }
    }
    if let Some(floor) = write_epoch_floor(floors, &repoint.scope_id)
        .await
        .map_err(ColdSeedError::Seam)?
    {
        if repoint.write_epoch < floor {
            return Err(ColdSeedError::Regression(FloorRegression::WriteEpoch {
                floor,
                vouched: repoint.write_epoch,
            }));
        }
    }
    cold_seed(floors, repoint)
        .await
        .map_err(ColdSeedError::Seam)
}

/// Advance the write-epoch floor on sight of an owner-vouched pointer
/// `writeEpoch`. Monotonic-max: a value at or below the durable floor is a
/// no-op that reports the stored floor. Returns the resulting floor.
pub async fn advance_write_epoch_on_sight<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    write_epoch: u64,
) -> SeamResult<u64> {
    floors
        .raise_epoch_floor(&write_epoch_key(scope_id), write_epoch)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryFloorStore;

    const SCOPE: [u8; 16] = [7u8; 16];
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
            cold_seed_checked(&floors, &repoint(SCOPE, 5, 3), AnchorRole::Root)
                .await
                .unwrap();
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(5));
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(3));
            // Re-seeding at or above the floor advances monotonically.
            cold_seed_checked(&floors, &repoint(SCOPE, 7, 3), AnchorRole::Root)
                .await
                .unwrap();
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(7));
        });
    }

    #[test]
    fn cold_seed_checked_rejects_a_read_epoch_regression_fail_closed() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            cold_seed_checked(&floors, &repoint(SCOPE, 5, 3), AnchorRole::Root)
                .await
                .unwrap();
            // A rolled-back re-point vouching a lower minReadEpoch is fail-closed.
            let err = cold_seed_checked(&floors, &repoint(SCOPE, 4, 3), AnchorRole::Root)
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
    fn cold_seed_checked_rejects_a_write_epoch_regression_fail_closed() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            cold_seed_checked(&floors, &repoint(SCOPE, 5, 6), AnchorRole::Root)
                .await
                .unwrap();
            let err = cold_seed_checked(&floors, &repoint(SCOPE, 5, 4), AnchorRole::Root)
                .await
                .expect_err("write-epoch regression is a trust violation");
            assert_eq!(
                err,
                ColdSeedError::Regression(FloorRegression::WriteEpoch {
                    floor: 6,
                    vouched: 4
                })
            );
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(6));
        });
    }

    /// The read-epoch regression check is unrepresentable for a shared scope:
    /// under [`AnchorRole::Shared`] a `minReadEpoch` far below the durable
    /// read-epoch floor (the legitimate steady state once grantee lazy rotation
    /// has unseal-advanced that floor) seeds cleanly instead of false-positiving
    /// into a fail-closed DoS (#763). The same input under `Root` is fail-closed.
    #[test]
    fn cold_seed_checked_shared_scope_skips_the_read_epoch_check() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            // Grantee lazy rotation has driven the read-epoch floor to 9.
            advance_on_unseal(&floors, &SCOPE, NAME, 1, 9)
                .await
                .unwrap();

            // A shared-scope cold-seed vouching minReadEpoch 4 (< floor 9) is the
            // normal steady state — it must NOT fire the read-epoch check.
            cold_seed_checked(&floors, &repoint(SCOPE, 4, 2), AnchorRole::Shared)
                .await
                .expect("shared-scope cold-seed never runs the read-epoch check");
            // The monotonic-max floor is unmoved by the lower vouched read epoch;
            // the write-epoch floor still seeds.
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(9));
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(2));

            // The identical input at the root anchor IS a fail-closed rollback.
            let err = cold_seed_checked(&floors, &repoint(SCOPE, 4, 2), AnchorRole::Root)
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
    /// as `Root` does. Guards a future refactor from dropping the seed for
    /// `Shared`.
    #[test]
    fn cold_seed_checked_shared_scope_seeds_a_fresh_read_epoch_floor() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            cold_seed_checked(&floors, &repoint(SCOPE, 5, 3), AnchorRole::Shared)
                .await
                .expect("a fresh shared scope seeds without running the read-epoch check");
            assert_eq!(read_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(5));
            assert_eq!(write_epoch_floor(&floors, &SCOPE).await.unwrap(), Some(3));
        });
    }

    /// The write-epoch check stays unconditionally active — a shared-scope
    /// cold-seed still fails closed on a write-epoch rollback.
    #[test]
    fn cold_seed_checked_shared_scope_still_rejects_a_write_epoch_regression() {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            cold_seed_checked(&floors, &repoint(SCOPE, 5, 6), AnchorRole::Shared)
                .await
                .unwrap();
            let err = cold_seed_checked(&floors, &repoint(SCOPE, 5, 4), AnchorRole::Shared)
                .await
                .expect_err("write-epoch regression is fail-closed for every role");
            assert_eq!(
                err,
                ColdSeedError::Regression(FloorRegression::WriteEpoch {
                    floor: 6,
                    vouched: 4
                })
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
}
