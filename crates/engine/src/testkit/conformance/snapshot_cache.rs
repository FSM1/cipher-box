//! Conformance kit: [`SnapshotCache`] opacity, durability, and clearing.

use crate::seams::SnapshotCache;

/// Runs the `SnapshotCache` contract against an implementation.
///
/// `open` must return a handle over the same durable backing on every call
/// (reopen semantics); the backing must start empty.
///
/// Ciphertext-only-at-rest is asserted as **opacity**: the kit stores
/// deliberately non-decodable bytes and requires them back verbatim — a
/// store that parses, normalizes, or requires plaintext structure cannot
/// pass. (That the engine only ever hands this seam sealed bytes is the
/// engine's own invariant, exercised by engine tests.)
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<S, F>(mut open: F)
where
    S: SnapshotCache,
    F: AsyncFnMut() -> S,
{
    let store = open().await;

    assert_eq!(store.get(b"missing").await.unwrap(), None);

    // Garbage in, same garbage out: no plaintext structure required.
    let opaque = [0xFFu8, 0x00, 0x9F, 0x92, 0x96, 0x00, 0xFF, 0x7F];
    store.put(b"key-1", &opaque).await.unwrap();
    assert_eq!(
        store.get(b"key-1").await.unwrap(),
        Some(opaque.to_vec()),
        "arbitrary ciphertext must round-trip verbatim"
    );

    // Overwrite replaces.
    store.put(b"key-1", b"v2").await.unwrap();
    assert_eq!(store.get(b"key-1").await.unwrap(), Some(b"v2".to_vec()));

    // Independent keys; idempotent remove.
    store.put(b"key-2", b"other").await.unwrap();
    store.remove(b"key-1").await.unwrap();
    store.remove(b"key-1").await.unwrap();
    assert_eq!(store.get(b"key-1").await.unwrap(), None);
    assert_eq!(store.get(b"key-2").await.unwrap(), Some(b"other".to_vec()));

    // Durability: entries survive reopen.
    let reopened = open().await;
    assert_eq!(
        reopened.get(b"key-2").await.unwrap(),
        Some(b"other".to_vec()),
        "cache entries must survive reopen"
    );

    // Clear ("forget this device") empties the backing, durably.
    reopened.clear().await.unwrap();
    assert_eq!(reopened.get(b"key-2").await.unwrap(), None);
    let after_clear = open().await;
    assert_eq!(
        after_clear.get(b"key-2").await.unwrap(),
        None,
        "clear must be durable"
    );
}
