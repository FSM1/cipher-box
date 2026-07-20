//! `FloorStore` — durable monotonic-max floors (blueprint/engine.md).

use super::SeamResult;

/// Durable monotonic-max per-scope epoch floors and per-name sequence
/// floors; regression rejects fail-closed.
///
/// The floor law (blueprint/engine.md, #39 D4) lives in the engine — this
/// seam only stores. Its contract, enforced by the conformance kit
/// (`testkit::conformance::floor_store` under the `test-kit` feature):
///
/// - **Monotonic-max**: a `raise_*` call never lowers a floor. Raising to a
///   value at or below the stored floor is a no-op that reports the stored
///   floor — the store is structurally incapable of regression.
/// - **Durable**: raised floors survive reopening the store (new session,
///   new handle over the same backing).
/// - **Namespaced**: epoch floors and sequence floors are independent maps;
///   identical key bytes in the two namespaces never collide.
///
/// Keys are opaque bytes chosen by the engine (scope identifiers for epoch
/// floors, `ipnsName` bytes for sequence floors); the store never interprets
/// them. Hosts: IndexedDB (web), local journal (desktop).
pub trait FloorStore {
    /// The durable epoch floor for a scope, if one was ever raised.
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>>;

    /// Raises the scope's epoch floor to `max(stored, epoch)`, durably, and
    /// returns the resulting stored floor.
    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64>;

    /// The durable sequence floor for a name, if one was ever raised.
    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>>;

    /// Raises the name's sequence floor to `max(stored, sequence)`, durably,
    /// and returns the resulting stored floor.
    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64>;
}
