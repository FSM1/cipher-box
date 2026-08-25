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
    // monotonic-max, in its own namespace.
    store
        .commit_floors(&[
            FloorRaise::epoch(scope_a.to_vec(), 6), // below stored 7 → no-op
            FloorRaise::epoch(scope_b.to_vec(), 8),
            FloorRaise::sequence(scope_a.to_vec(), 50),
        ])
        .await
        .unwrap();
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

    // Retry convergence: re-committing a batch (as a caller retry after an
    // interrupted commit would) is idempotent — a re-applied entry never
    // double-advances and never regresses. This is the convergence property
    // every impl's `commit_floors` contract rests on, whether it closes the
    // hazard by all-or-nothing rollback, by roll-forward replay, or by the
    // ordered fail-safe fallback. `scope_b` advances so the retry has an
    // observable: a `commit_floors` that silently applied nothing fails here.
    reopened
        .commit_floors(&[
            FloorRaise::epoch(scope_a.to_vec(), 6), // still below 7 → no-op
            FloorRaise::epoch(scope_b.to_vec(), 9),
            FloorRaise::sequence(scope_a.to_vec(), 50),
        ])
        .await
        .unwrap();
    assert_eq!(
        reopened.epoch_floor(scope_b).await.unwrap(),
        Some(9),
        "a batch entry above its floor must advance on a retried commit"
    );
    assert_eq!(
        reopened.epoch_floor(scope_a).await.unwrap(),
        Some(7),
        "a re-applied at-or-below entry must neither regress nor double-advance"
    );
    assert_eq!(reopened.sequence_floor(scope_a).await.unwrap(), Some(50));

    // Two raises on one key inside a single batch: the last-wins maximum, in
    // either order — what makes the ordered fallback and an atomic backing
    // observationally equivalent.
    for pair in [[3u64, 12], [12, 3]] {
        let key = format!("batch-same-key-{}-{}", pair[0], pair[1]).into_bytes();
        reopened
            .commit_floors(&[
                FloorRaise::epoch(key.clone(), pair[0]),
                FloorRaise::epoch(key.clone(), pair[1]),
            ])
            .await
            .unwrap();
        assert_eq!(
            reopened.epoch_floor(&key).await.unwrap(),
            Some(12),
            "two raises on one key in a batch must settle at their maximum"
        );
    }

    // Clear ("forget this device") drops both namespaces, durably — the one
    // exit from the ratchet, so a floor left standing is a floor the device can
    // no longer explain. The reopened handle is what the assertions read: an
    // in-memory-only clear passes on the live one.
    reopened.clear().await.unwrap();
    assert_eq!(reopened.epoch_floor(scope_a).await.unwrap(), None);
    let after_clear = open().await;
    assert_eq!(after_clear.epoch_floor(scope_a).await.unwrap(), None);
    assert_eq!(after_clear.epoch_floor(scope_b).await.unwrap(), None);
    assert_eq!(
        after_clear.sequence_floor(scope_a).await.unwrap(),
        None,
        "clear must be durable across both namespaces"
    );

    // A cleared store still ratchets: the erase resets the floors, not the law.
    // A store that latched "cleared" and then took anything passes the raise
    // above and fails here.
    assert_eq!(after_clear.raise_epoch_floor(scope_a, 4).await.unwrap(), 4);
    assert_eq!(
        after_clear.raise_epoch_floor(scope_a, 1).await.unwrap(),
        4,
        "a re-raised floor after a clear must still refuse to regress"
    );
}
