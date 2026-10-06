//! `StagingStore` — durable op queue and staged bytes (blueprint/engine.md).

use std::cell::Cell;
use std::rc::Rc;

use super::SeamResult;
use crate::sync::kept_op::is_kept_op_key;

/// Store-assigned identifier of one queued op. Strictly increasing per
/// store, never reused — enqueue order is FIFO order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, tsify::Tsify),
    serde(transparent),
    tsify(large_number_types_as_bigints)
)]
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
    /// its id. An `Err` after the commit point can leave the op queued, with
    /// its durability unknown.
    async fn enqueue_op(&self, op: &[u8]) -> SeamResult<OpId>;

    /// Appends several op records to the queue in one atomic write, in order,
    /// and returns their ids in that order. No reader, before or after a crash,
    /// ever sees part of the set. An `Err` leaves none of them queued, except
    /// an `Err` after the commit point, which, as for [`Self::enqueue_op`], can
    /// leave the whole set queued with its durability unknown. Each entry is stored as [`Self::enqueue_op`] stores one, so a
    /// reader of the queue cannot tell the two apart.
    async fn enqueue_ops(&self, ops: &[Vec<u8>]) -> SeamResult<Vec<OpId>>;

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
    /// This is the store's end of life, the bookkeeping it carries included:
    /// the retire ledger, the doomed-name journal and the scope-exit debt all
    /// go with it. The engine settles what it can ahead of this call and
    /// reports the residual, so the contracts those surfaces state hold up to
    /// the erase rather than being quietly ended by it
    /// ([`Command::ForgetDevice`](crate::facade::Command::ForgetDevice)).
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

/// A [`StagingStore`] that counts the durable-queue mutations made through it,
/// so a reader can tell that a queue it already read still stands without
/// enumerating it again.
///
/// The count is the render memo's queue key
/// ([`RenderMemo`](crate::sync::render::RenderMemo)): a desktop store answers
/// [`queued_ops`](StagingStore::queued_ops) with a directory listing plus one
/// file read per pending op, which a vfs pass would otherwise pay per
/// operation. Clones share the count, so a spawned drain pass's removals are
/// counted beside the command path's enqueues; the engine wraps the host's
/// store once, and every handle it hands out is a clone of that one.
///
/// Only the methods that change which ops are queued count. Staged bytes
/// are not an operand of the state law, and a live write handle churns them.
/// A write of the published-op mark or the kept-op notes moves a count of its
/// own ([`QueueGeneration::kept_generation`]).
pub struct QueueGenerationStore<S> {
    seam: S,
    generation: Rc<Cell<u64>>,
    kept_generation: Rc<Cell<u64>>,
}

impl<S> QueueGenerationStore<S> {
    /// Wraps `seam`, starting the count at its first generation.
    pub fn new(seam: S) -> Self {
        Self {
            seam,
            generation: Rc::new(Cell::new(0)),
            kept_generation: Rc::new(Cell::new(0)),
        }
    }

    /// The wrapped store, for a test that reaches a fake's failure injectors.
    /// Test-only: a queue mutation made through it is not counted, and the
    /// count is what tells a memoized read that its answer has expired.
    #[cfg(any(test, feature = "test-kit"))]
    pub fn inner(&self) -> &S {
        &self.seam
    }

    /// Counts one mutation. Charged before and after the store is asked, so a
    /// refusal that changed the queue anyway is still counted, and a read that
    /// keys itself mid-write is not served again — an extra render costs time,
    /// a missed one serves a view that never existed.
    fn mutating(&self) {
        self.generation.set(self.generation.get().wrapping_add(1));
    }

    /// Counts one write at `staging_key` if it holds the published-op mark or
    /// the kept-op notes, charged as [`Self::mutating`] is.
    fn staged_write(&self, staging_key: &[u8]) {
        if is_kept_op_key(staging_key) {
            self.kept_generation
                .set(self.kept_generation.get().wrapping_add(1));
        }
    }
}

impl<S: Clone> Clone for QueueGenerationStore<S> {
    fn clone(&self) -> Self {
        Self {
            seam: self.seam.clone(),
            generation: self.generation.clone(),
            kept_generation: self.kept_generation.clone(),
        }
    }
}

/// The durable op queue's generation: a constant-size read that says whether a
/// queue a reader already decoded still stands, so a memoized scan of it answers
/// without enumerating the queue at all.
pub trait QueueGeneration {
    /// How many queue mutations this store has been asked for.
    fn generation(&self) -> u64;

    /// How many writes of the published-op mark or the kept-op notes this
    /// store has been asked for: they decide which queued ops are kept
    /// (ADR 0069 D7), and they are not queue mutations.
    fn kept_generation(&self) -> u64;
}

impl<S> QueueGeneration for QueueGenerationStore<S> {
    fn generation(&self) -> u64 {
        self.generation.get()
    }

    fn kept_generation(&self) -> u64 {
        self.kept_generation.get()
    }
}

impl<S: StagingStore> StagingStore for QueueGenerationStore<S> {
    async fn enqueue_op(&self, op: &[u8]) -> SeamResult<OpId> {
        self.mutating();
        let done = self.seam.enqueue_op(op).await;
        self.mutating();
        done
    }

    async fn enqueue_ops(&self, ops: &[Vec<u8>]) -> SeamResult<Vec<OpId>> {
        self.mutating();
        let done = self.seam.enqueue_ops(ops).await;
        self.mutating();
        done
    }

    async fn queued_ops(&self) -> SeamResult<Vec<(OpId, Vec<u8>)>> {
        self.seam.queued_ops().await
    }

    async fn remove_op(&self, op_id: OpId) -> SeamResult<()> {
        self.mutating();
        let done = self.seam.remove_op(op_id).await;
        self.mutating();
        done
    }

    async fn put_staged_bytes(&self, staging_key: &[u8], bytes: &[u8]) -> SeamResult<()> {
        self.staged_write(staging_key);
        let done = self.seam.put_staged_bytes(staging_key, bytes).await;
        self.staged_write(staging_key);
        done
    }

    async fn staged_bytes(&self, staging_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        self.seam.staged_bytes(staging_key).await
    }

    async fn remove_staged_bytes(&self, staging_key: &[u8]) -> SeamResult<()> {
        self.staged_write(staging_key);
        let done = self.seam.remove_staged_bytes(staging_key).await;
        self.staged_write(staging_key);
        done
    }

    async fn staged_keys(&self) -> SeamResult<Vec<Vec<u8>>> {
        self.seam.staged_keys().await
    }

    async fn staged_bytes_total(&self) -> SeamResult<u64> {
        self.seam.staged_bytes_total().await
    }

    async fn clear(&self) -> SeamResult<()> {
        self.mutating();
        let done = self.seam.clear().await;
        self.mutating();
        done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryStagingStore;

    fn counted() -> QueueGenerationStore<InMemoryStagingStore> {
        QueueGenerationStore::new(InMemoryStagingStore::default())
    }

    #[test]
    fn every_queue_mutation_moves_the_generation_on() {
        let store = counted();
        let start = store.generation();

        let op = block_on(store.enqueue_op(b"op")).expect("enqueue");
        let enqueued = store.generation();
        block_on(store.remove_op(op)).expect("remove");
        let removed = store.generation();
        block_on(store.enqueue_ops(&[b"a".to_vec(), b"b".to_vec()])).expect("enqueue a set");
        let batched = store.generation();
        block_on(store.clear()).expect("clear");

        assert_ne!(enqueued, start);
        assert_ne!(removed, enqueued);
        assert_ne!(batched, removed);
        assert_ne!(store.generation(), batched);
    }

    #[test]
    fn reading_the_queue_leaves_the_generation_where_it_was() {
        let store = counted();
        block_on(store.enqueue_op(b"op")).expect("enqueue");
        let enqueued = store.generation();

        block_on(store.queued_ops()).expect("read");
        block_on(store.staged_keys()).expect("keys");

        assert_eq!(store.generation(), enqueued);
    }

    #[test]
    fn staged_bytes_are_not_a_queue_mutation() {
        let store = counted();
        let start = store.generation();

        block_on(store.put_staged_bytes(b"key", b"bytes")).expect("put");
        block_on(store.remove_staged_bytes(b"key")).expect("remove");

        assert_eq!(store.generation(), start);
    }

    #[test]
    fn only_a_kept_op_key_moves_the_kept_generation() {
        use crate::sync::drain::PUBLISHED_OP_MARK_PREFIX;
        use crate::sync::kept_op::KEPT_OP_NOTES_PREFIX;

        let store = counted();
        block_on(store.put_staged_bytes(b"block", b"bytes")).expect("put");
        assert_eq!(store.kept_generation(), 0);

        for prefix in [PUBLISHED_OP_MARK_PREFIX, KEPT_OP_NOTES_PREFIX] {
            let before = store.kept_generation();
            block_on(store.put_staged_bytes(prefix, b"bytes")).expect("put");
            let put = store.kept_generation();
            block_on(store.remove_staged_bytes(prefix)).expect("remove");
            assert_ne!(put, before);
            assert_ne!(store.kept_generation(), put);
        }
    }

    #[test]
    fn a_clone_shares_the_count_with_the_handle_it_came_from() {
        let store = counted();
        let spawned = store.clone();

        block_on(spawned.enqueue_op(b"op")).expect("enqueue");

        assert_eq!(store.generation(), spawned.generation());
        assert_ne!(store.generation(), 0);
    }

    #[test]
    fn a_refused_mutation_is_counted_too() {
        let store = counted();
        store.inner().fail_remove_op();
        let before = store.generation();

        block_on(store.remove_op(OpId(1))).expect_err("refused");

        assert_ne!(store.generation(), before);
    }
}
