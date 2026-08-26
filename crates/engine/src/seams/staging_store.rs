//! `StagingStore` — durable op queue and staged bytes (blueprint/engine.md).

use super::SeamResult;

/// Store-assigned identifier of one queued op. Strictly increasing per
/// store, never reused — enqueue order is FIFO order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId(pub u64);

/// Durable op queue plus staged upload bytes, behind the sync-timing-profile
/// staging budget.
///
/// Every mutation rides the durable op queue (#33 D6); ops are opaque
/// encoded intent records — the engine owns their encoding, replay, rebase,
/// and dead-lettering. Staged upload bytes are keyed by opaque staging keys;
/// the engine knows which ops reference which keys, and drives orphan GC
/// through [`StagingStore::staged_keys`] / `remove_staged_bytes`. Budget
/// enforcement is engine policy fed by [`StagingStore::staged_bytes_total`].
///
/// Contract, enforced by the conformance kit: FIFO ordering with strictly
/// increasing ids that are never reused — not after the highest is removed,
/// not after the queue drains empty and the store reopens — the bytes at an id
/// being immutable for that id's lifetime, durability of queue and staged bytes
/// across reopen, and enumeration/removal exact enough that orphan GC is
/// implementable. The engine reads the id progression as evidence about the
/// queue, so a host that restarts or recycles ids is not merely untidy.
/// Hosts: IndexedDB + OPFS (web), local journal (desktop).
pub trait StagingStore {
    /// Appends an opaque op record to the durable FIFO queue and returns
    /// its id.
    async fn enqueue_op(&self, op: &[u8]) -> SeamResult<OpId>;

    /// Every queued op in FIFO (ascending-id) order.
    async fn queued_ops(&self) -> SeamResult<Vec<(OpId, Vec<u8>)>>;

    /// Removes one op (completed, rebased away, or dead-lettered).
    /// Idempotent: removing an unknown id succeeds.
    async fn remove_op(&self, op_id: OpId) -> SeamResult<()>;

    /// Stores staged bytes under an opaque staging key, replacing any
    /// previous bytes at that key.
    ///
    /// The replacement is failure-atomic: an `Err` leaves the previous bytes
    /// readable and byte-identical, and leaves a key that held none absent —
    /// never a truncated or half-written value. Callers store whole-set
    /// records here (the retire ledger's owed reclaims, the drain's op-id
    /// high-water marks), so a lost replacement is destroyed durable state,
    /// not a retryable hiccup.
    async fn put_staged_bytes(&self, staging_key: &[u8], bytes: &[u8]) -> SeamResult<()>;

    /// The staged bytes at a key, verbatim; `None` if absent.
    async fn staged_bytes(&self, staging_key: &[u8]) -> SeamResult<Option<Vec<u8>>>;

    /// Removes the staged bytes at a key. Idempotent.
    async fn remove_staged_bytes(&self, staging_key: &[u8]) -> SeamResult<()>;

    /// Every staging key currently holding bytes (orphan-GC enumeration).
    async fn staged_keys(&self) -> SeamResult<Vec<Vec<u8>>>;

    /// Total staged payload bytes across all keys (budget input).
    async fn staged_bytes_total(&self) -> SeamResult<u64>;

    /// Drops every queued op and every staged byte, durably
    /// ("forget this device").
    ///
    /// The id progression is **not** reset: ids stay strictly increasing and
    /// unreused across a clear, exactly as across a drain and reopen — the
    /// engine reads id order as evidence about the queue.
    ///
    /// The queue goes **before** the staged bytes, for the same reason removal
    /// ordering is a correctness property above: interrupted the other way
    /// round, the store is left holding ops that name bytes already gone, while
    /// this order can only orphan bytes that orphan GC reclaims. Both legs run
    /// even when one refuses, and the first refusal is what the caller sees.
    async fn clear(&self) -> SeamResult<()>;
}
