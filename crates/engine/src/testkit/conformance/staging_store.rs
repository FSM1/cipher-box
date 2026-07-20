//! Conformance kit: [`StagingStore`] FIFO ordering, durability, and
//! orphan-GC support.

use crate::seams::StagingStore;

/// Runs the `StagingStore` contract against an implementation.
///
/// `open` must return a handle over the same durable backing on every call
/// (reopen semantics); the backing must start empty.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<S, F>(mut open: F)
where
    S: StagingStore,
    F: AsyncFnMut() -> S,
{
    let store = open().await;

    // Fresh backing.
    assert!(store.queued_ops().await.unwrap().is_empty());
    assert!(store.staged_keys().await.unwrap().is_empty());
    assert_eq!(store.staged_bytes_total().await.unwrap(), 0);

    // FIFO with strictly increasing ids.
    let id_a = store.enqueue_op(b"op-a").await.unwrap();
    let id_b = store.enqueue_op(b"op-b").await.unwrap();
    let id_c = store.enqueue_op(b"op-c").await.unwrap();
    assert!(
        id_a < id_b && id_b < id_c,
        "op ids must be strictly increasing"
    );

    let ops = store.queued_ops().await.unwrap();
    assert_eq!(
        ops,
        vec![
            (id_a, b"op-a".to_vec()),
            (id_b, b"op-b".to_vec()),
            (id_c, b"op-c".to_vec()),
        ],
        "queued ops must come back FIFO with payloads verbatim"
    );

    // Removal preserves the order of survivors; removing again is
    // idempotent.
    store.remove_op(id_b).await.unwrap();
    store.remove_op(id_b).await.unwrap();
    assert_eq!(
        store.queued_ops().await.unwrap(),
        vec![(id_a, b"op-a".to_vec()), (id_c, b"op-c".to_vec())],
        "removing one op must not disturb FIFO order"
    );

    // Staged bytes: verbatim round-trip, replacement, exact accounting.
    store.put_staged_bytes(b"key-1", b"12345").await.unwrap();
    store.put_staged_bytes(b"key-2", b"1234567").await.unwrap();
    assert_eq!(
        store.staged_bytes(b"key-1").await.unwrap(),
        Some(b"12345".to_vec())
    );
    assert_eq!(store.staged_bytes_total().await.unwrap(), 12);

    store.put_staged_bytes(b"key-1", b"123").await.unwrap();
    assert_eq!(
        store.staged_bytes_total().await.unwrap(),
        10,
        "replacing staged bytes must not double-count"
    );

    // Orphan-GC support: enumeration and removal are exact.
    let mut keys = store.staged_keys().await.unwrap();
    keys.sort();
    assert_eq!(keys, vec![b"key-1".to_vec(), b"key-2".to_vec()]);

    store.remove_staged_bytes(b"key-1").await.unwrap();
    store.remove_staged_bytes(b"key-1").await.unwrap(); // idempotent
    assert_eq!(store.staged_bytes(b"key-1").await.unwrap(), None);
    assert_eq!(store.staged_keys().await.unwrap(), vec![b"key-2".to_vec()]);
    assert_eq!(store.staged_bytes_total().await.unwrap(), 7);

    // Durability: queue order, staged bytes, and id progression survive
    // reopen.
    let reopened = open().await;
    assert_eq!(
        reopened.queued_ops().await.unwrap(),
        vec![(id_a, b"op-a".to_vec()), (id_c, b"op-c".to_vec())],
        "the op queue must survive reopen in order"
    );
    assert_eq!(
        reopened.staged_bytes(b"key-2").await.unwrap(),
        Some(b"1234567".to_vec()),
        "staged bytes must survive reopen"
    );
    let id_d = reopened.enqueue_op(b"op-d").await.unwrap();
    assert!(
        id_d > id_c,
        "op ids must never be reused, even across reopen"
    );
}
