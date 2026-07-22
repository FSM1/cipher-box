//! The floor law — durable monotonic advancement of the per-scope epoch and
//! per-name sequence floors (blueprint/engine.md "Adoption gate and floors",
//! #39 D4 / #38 D4).
//!
//! Floors are engine state, held behind the [`FloorStore`] seam. This module
//! is the *only* place that advances them, and it advances them only the four
//! ways the law admits:
//!
//! 1. **Advance on AAD-confirmed unseal** ([`advance_on_unseal`]) — the sole
//!    record-sourced path. A record's sequence/epoch move the floors only after
//!    its body cryptographically unsealed (the adoption gate's stage 6), never
//!    from a claimed-but-unconfirmed field.
//! 2. **Cold-seed from a re-point object** ([`cold_seed`]) — the cold-start
//!    anchor. The owner-vouched `minReadEpoch` seeds the read-epoch floor (the
//!    revocation boundary) and `writeEpoch` the write-epoch floor. The caller
//!    passes a [`RepointObject`] it already authenticated with
//!    [`open_pointer_payload`](cipherbox_core::payload::open_pointer_payload):
//!    the object type is only obtainable from that verified open, so an
//!    unsigned or non-owner re-point never reaches this function and no floor
//!    moves (fail-closed by construction).
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

use crate::seams::{FloorRaise, FloorStore, SeamResult};

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

/// Advance floors after an AAD-confirmed unseal — the only record-sourced
/// advancement. Raises the per-scope read-epoch floor to `epoch` and the
/// per-name sequence floor to `sequence`, both monotonic-max. Callers invoke
/// this exactly once, at the adoption gate's successful unseal stage (the gate
/// commits it — eagerly via [`adopt`](crate::gate::adopt), or deferred via
/// [`PendingAdoption::commit`](crate::gate::PendingAdoption::commit) — after a
/// confirmed unseal), so a record whose body never unsealed can never move a
/// floor — the provenance the plain scalar arguments cannot express is enforced
/// at that single call site.
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
