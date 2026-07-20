//! `SnapshotCache` — durable last-known-good cache (blueprint/engine.md).

use super::SeamResult;

/// Durable last-known-good record/metadata cache backing cache-first reads.
///
/// **Ciphertext-only at rest**: the engine only ever hands this store sealed
/// bytes and unseals on read — plaintext never lands in host storage
/// (blueprint/web-client.md seam table). The store must treat values as
/// opaque: arbitrary, non-decodable bytes round-trip verbatim; the
/// conformance kit feeds it garbage to prove the store never requires
/// parseable content. Only gate-passing records ever reach this cache — the
/// adoption gate runs upstream, in the engine.
///
/// Keys are opaque bytes chosen by the engine. Contents survive logout by
/// design (cache-first rendering after restart); an explicit
/// "forget this device" clears them via [`SnapshotCache::clear`].
pub trait SnapshotCache {
    /// Stores ciphertext under a key, replacing any previous value.
    async fn put(&self, cache_key: &[u8], ciphertext: &[u8]) -> SeamResult<()>;

    /// The ciphertext at a key, verbatim; `None` if absent.
    async fn get(&self, cache_key: &[u8]) -> SeamResult<Option<Vec<u8>>>;

    /// Removes one entry. Idempotent.
    async fn remove(&self, cache_key: &[u8]) -> SeamResult<()>;

    /// Removes every entry ("forget this device").
    async fn clear(&self) -> SeamResult<()>;
}
