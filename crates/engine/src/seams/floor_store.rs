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

    /// Commits a batch of monotonic-max floor raises across both namespaces,
    /// returning the resulting stored floor for each entry in order.
    ///
    /// A single floor advance raises several distinctly-keyed floors at once
    /// (read-epoch, write-epoch, per-name sequence). Where the backing offers a
    /// cross-key transaction the commit is **all-or-nothing**: a seam error
    /// leaves no entry durably changed, so a partial advance is never observable
    /// (#685). The default fallback applies the raises one key at a time in the
    /// given order — not atomic, but the caller passes the trust-critical
    /// (revocation) floor first, so an interrupted fallback fails toward *more*
    /// restriction and re-converges idempotently on retry, exactly the #682
    /// mitigation this method subsumes. Callers MUST order entries
    /// revocation-before-liveness for that guarantee to hold.
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<Vec<u64>> {
        let mut resulting = Vec::with_capacity(raises.len());
        for raise in raises {
            let floor = match raise.namespace {
                FloorNamespace::Epoch => self.raise_epoch_floor(&raise.key, raise.value).await?,
                FloorNamespace::Sequence => {
                    self.raise_sequence_floor(&raise.key, raise.value).await?
                }
            };
            resulting.push(floor);
        }
        Ok(resulting)
    }
}

/// Which of the two independent floor maps a [`FloorRaise`] targets. Identical
/// key bytes in the two namespaces never collide (the single-key methods keep
/// the same separation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorNamespace {
    /// Per-scope epoch floors ([`FloorStore::raise_epoch_floor`]).
    Epoch,
    /// Per-name sequence floors ([`FloorStore::raise_sequence_floor`]).
    Sequence,
}

/// One monotonic-max floor raise inside a [`FloorStore::commit_floors`] batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorRaise {
    /// The map this raise targets.
    pub namespace: FloorNamespace,
    /// Opaque engine-chosen key bytes (scope id or `ipnsName`).
    pub key: Vec<u8>,
    /// The floor value to raise to (`max(stored, value)`).
    pub value: u64,
}

impl FloorRaise {
    /// An epoch-namespace raise.
    pub fn epoch(key: impl Into<Vec<u8>>, value: u64) -> Self {
        Self {
            namespace: FloorNamespace::Epoch,
            key: key.into(),
            value,
        }
    }

    /// A sequence-namespace raise.
    pub fn sequence(key: impl Into<Vec<u8>>, value: u64) -> Self {
        Self {
            namespace: FloorNamespace::Sequence,
            key: key.into(),
            value,
        }
    }
}
