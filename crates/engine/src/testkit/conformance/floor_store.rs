//! Conformance kit: [`FloorStore`] monotonicity, durability, and
//! namespacing.

use crate::seams::{FloorRaise, FloorStore};

/// Runs the `FloorStore` contract against an implementation.
///
/// `open` must return a handle over the same durable backing on every call
/// (reopen semantics); the backing must start empty.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<S, F>(mut open: F)
where
    S: FloorStore,
    F: AsyncFnMut() -> S,
{
    let store = open().await;

    let scope_a = b"scope-a".as_slice();
    let scope_b = b"scope-b".as_slice();

    // Fresh backing: no floors.
    assert_eq!(
        store.epoch_floor(scope_a).await.unwrap(),
        None,
        "a never-raised epoch floor must be None"
    );
    assert_eq!(
        store.sequence_floor(scope_a).await.unwrap(),
        None,
        "a never-raised sequence floor must be None"
    );

    // Raise, then attempt a regression: monotonic-max must hold.
    assert_eq!(store.raise_epoch_floor(scope_a, 5).await.unwrap(), 5);
    assert_eq!(store.epoch_floor(scope_a).await.unwrap(), Some(5));
    assert_eq!(
        store.raise_epoch_floor(scope_a, 3).await.unwrap(),
        5,
        "raising below the stored floor must be a no-op reporting the stored floor"
    );
    assert_eq!(
        store.epoch_floor(scope_a).await.unwrap(),
        Some(5),
        "a floor must never regress"
    );
    assert_eq!(store.raise_epoch_floor(scope_a, 7).await.unwrap(), 7);

    // Idempotent raise to the same value.
    assert_eq!(store.raise_epoch_floor(scope_a, 7).await.unwrap(), 7);

    // Independent keys.
    assert_eq!(
        store.epoch_floor(scope_b).await.unwrap(),
        None,
        "epoch floors must be independent per key"
    );
    assert_eq!(store.raise_epoch_floor(scope_b, 2).await.unwrap(), 2);
    assert_eq!(store.epoch_floor(scope_a).await.unwrap(), Some(7));

    // Epoch and sequence namespaces must not collide on identical key
    // bytes.
    assert_eq!(
        store.sequence_floor(scope_a).await.unwrap(),
        None,
        "sequence floors must be namespaced apart from epoch floors"
    );
    assert_eq!(store.raise_sequence_floor(scope_a, 41).await.unwrap(), 41);
    assert_eq!(
        store.raise_sequence_floor(scope_a, 40).await.unwrap(),
        41,
        "sequence floors are monotonic-max too"
    );
    assert_eq!(store.epoch_floor(scope_a).await.unwrap(), Some(7));

    // Cross-key batch commit: a mixed-namespace batch raises every entry
    // monotonic-max and reports the resulting floors in order.
    let batch = store
        .commit_floors(&[
            FloorRaise::epoch(scope_a.to_vec(), 6), // below stored 7 → no-op, reports 7
            FloorRaise::epoch(scope_b.to_vec(), 8),
            FloorRaise::sequence(scope_a.to_vec(), 50),
        ])
        .await
        .unwrap();
    assert_eq!(
        batch,
        vec![7, 8, 50],
        "commit_floors must report each resulting floor in order, monotonic-max"
    );
    assert_eq!(
        store.epoch_floor(scope_a).await.unwrap(),
        Some(7),
        "a below-floor batch entry must not lower the floor"
    );
    assert_eq!(store.epoch_floor(scope_b).await.unwrap(), Some(8));
    assert_eq!(
        store.sequence_floor(scope_a).await.unwrap(),
        Some(50),
        "a batch entry must not leak across namespaces"
    );

    // Durability: a reopened handle sees every raised floor, batch-committed
    // ones included.
    let reopened = open().await;
    assert_eq!(
        reopened.epoch_floor(scope_a).await.unwrap(),
        Some(7),
        "epoch floors must survive reopen"
    );
    assert_eq!(
        reopened.epoch_floor(scope_b).await.unwrap(),
        Some(8),
        "batch-committed epoch floors must survive reopen"
    );
    assert_eq!(
        reopened.sequence_floor(scope_a).await.unwrap(),
        Some(50),
        "batch-committed sequence floors must survive reopen"
    );
}
