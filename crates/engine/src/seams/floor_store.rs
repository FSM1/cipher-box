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

    /// Commits a batch of monotonic-max floor raises across both namespaces.
    ///
    /// A single floor advance raises several distinctly-keyed floors at once
    /// (read-epoch, write-epoch, per-name sequence). An implementation closes the
    /// partial-advance hazard one of two ways: **transactionally** (a
    /// cross-key transaction leaves no entry durably changed on error) or by
    /// **roll-forward** (the desktop store fsyncs a batch intent record before any
    /// per-key write and replays it on reopen — it heals forward, never rewinds).
    ///
    /// The default fallback applies the raises one key at a time in the given
    /// order — not atomic. **Callers MUST order entries revocation-before-
    /// liveness**: an interrupted fallback then fails toward *more* restriction
    /// and re-converges idempotently on retry. The web IndexedDB seam rides this
    /// fallback — its JS boundary exposes only the per-key methods — and
    /// web-atomic commit is deferred as a durability/liveness concern, not a
    /// trust hole.
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<()> {
        for raise in raises {
            match raise.namespace {
                FloorNamespace::Epoch => self.raise_epoch_floor(&raise.key, raise.value).await?,
                FloorNamespace::Sequence => {
                    self.raise_sequence_floor(&raise.key, raise.value).await?
                }
            };
        }
        Ok(())
    }

    /// Drops every floor in both namespaces, durably ("forget this device") —
    /// the one exit from the monotonic ratchet. Floors survive logout by
    /// design; a cleared store re-seeds from the record plane on the next cold
    /// start, so a partial clear would leave the device pinned above records it
    /// can no longer explain — every leg runs even when one refuses, and the
    /// first refusal is what the caller sees.
    async fn clear(&self) -> SeamResult<()>;
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
