//! `LiveSeam` — the durable-seam handle a spawned background pass writes
//! through.

use std::cell::Cell;
use std::rc::Rc;

use super::{FloorRaise, FloorStore, OpId, SeamError, SeamResult, SnapshotCache, StagingStore};

/// A durable seam handed to a spawned pass, gated on the engine's session-alive
/// latch: once that latch drops, every mutation is refused and only reads pass
/// through.
///
/// [`Scheduler::spawn`](super::Scheduler::spawn) is fire-and-forget, so a pass
/// parked on the network resumes with seam clones the engine can no longer
/// reach. Without this gate a resumed pass raises a floor or re-fills the cache
/// *behind* the erase a forget just ran, re-seeding the device with the state it
/// disowned. Same shape as the bearer cell's one-way seal
/// ([`SessionBearer::seal`](crate::content::SessionBearer)), applied to the
/// durable seams.
///
/// The latch is one-way per engine instance: set at construction, dropped by
/// `shut_down` (forget and `Drop`), never re-armed. The engine keeps the
/// unwrapped seam, so the erase itself is not gated by the latch it just
/// dropped.
pub(crate) struct LiveSeam<S> {
    seam: S,
    alive: Rc<Cell<bool>>,
}

impl<S> LiveSeam<S> {
    pub(crate) fn new(seam: S, alive: Rc<Cell<bool>>) -> Self {
        Self { seam, alive }
    }

    /// `Ok` while the session is live; the refusal a torn-down engine's seams
    /// answer every mutation with otherwise.
    fn writable(&self, op: &str) -> SeamResult<()> {
        if self.alive.get() {
            Ok(())
        } else {
            Err(SeamError::new(format!("{op}: this engine's session ended")))
        }
    }
}

impl<S: Clone> Clone for LiveSeam<S> {
    fn clone(&self) -> Self {
        Self {
            seam: self.seam.clone(),
            alive: self.alive.clone(),
        }
    }
}

impl<S: FloorStore> FloorStore for LiveSeam<S> {
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
        self.seam.epoch_floor(scope_id).await
    }

    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        self.writable("floor_store raise_epoch_floor")?;
        self.seam.raise_epoch_floor(scope_id, epoch).await
    }

    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        self.seam.sequence_floor(ipns_name).await
    }

    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        self.writable("floor_store raise_sequence_floor")?;
        self.seam.raise_sequence_floor(ipns_name, sequence).await
    }

    /// Forwarded whole rather than left to the trait's per-key fallback: the
    /// backing store's atomicity is the point of the batch.
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<()> {
        self.writable("floor_store commit_floors")?;
        self.seam.commit_floors(raises).await
    }

    async fn clear(&self) -> SeamResult<()> {
        self.seam.clear().await
    }
}

impl<S: SnapshotCache> SnapshotCache for LiveSeam<S> {
    async fn put(&self, cache_key: &[u8], ciphertext: &[u8]) -> SeamResult<()> {
        self.writable("snapshot_cache put")?;
        self.seam.put(cache_key, ciphertext).await
    }

    async fn get(&self, cache_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        self.seam.get(cache_key).await
    }

    async fn remove(&self, cache_key: &[u8]) -> SeamResult<()> {
        self.writable("snapshot_cache remove")?;
        self.seam.remove(cache_key).await
    }

    async fn clear(&self) -> SeamResult<()> {
        self.seam.clear().await
    }
}

impl<S: StagingStore> StagingStore for LiveSeam<S> {
    async fn enqueue_op(&self, op: &[u8]) -> SeamResult<OpId> {
        self.writable("staging_store enqueue_op")?;
        self.seam.enqueue_op(op).await
    }

    async fn queued_ops(&self) -> SeamResult<Vec<(OpId, Vec<u8>)>> {
        self.seam.queued_ops().await
    }

    async fn remove_op(&self, op_id: OpId) -> SeamResult<()> {
        self.writable("staging_store remove_op")?;
        self.seam.remove_op(op_id).await
    }

    async fn put_staged_bytes(&self, staging_key: &[u8], bytes: &[u8]) -> SeamResult<()> {
        self.writable("staging_store put_staged_bytes")?;
        self.seam.put_staged_bytes(staging_key, bytes).await
    }

    async fn staged_bytes(&self, staging_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        self.seam.staged_bytes(staging_key).await
    }

    async fn remove_staged_bytes(&self, staging_key: &[u8]) -> SeamResult<()> {
        self.writable("staging_store remove_staged_bytes")?;
        self.seam.remove_staged_bytes(staging_key).await
    }

    async fn staged_keys(&self) -> SeamResult<Vec<Vec<u8>>> {
        self.seam.staged_keys().await
    }

    async fn staged_bytes_total(&self) -> SeamResult<u64> {
        self.seam.staged_bytes_total().await
    }

    async fn clear(&self) -> SeamResult<()> {
        self.seam.clear().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testkit::block_on;
    use crate::testkit::fakes::{InMemoryFloorStore, InMemorySnapshotCache, InMemoryStagingStore};

    fn latch(alive: bool) -> Rc<Cell<bool>> {
        Rc::new(Cell::new(alive))
    }

    #[test]
    fn a_pass_that_outlives_the_session_cannot_raise_a_floor() {
        let backing = InMemoryFloorStore::default();
        let alive = latch(true);
        let seam = LiveSeam::new(backing.clone(), alive.clone());
        block_on(async {
            seam.raise_epoch_floor(b"scope", 4).await.unwrap();

            alive.set(false);

            seam.raise_epoch_floor(b"scope", 9).await.unwrap_err();
            seam.raise_sequence_floor(b"name", 9).await.unwrap_err();
            seam.commit_floors(&[FloorRaise::epoch(b"scope".to_vec(), 9)])
                .await
                .unwrap_err();
            assert_eq!(
                backing.epoch_floor(b"scope").await.unwrap(),
                Some(4),
                "a refused raise must not reach the store behind the seam"
            );
            assert_eq!(
                seam.epoch_floor(b"scope").await.unwrap(),
                Some(4),
                "reads stay open: only what re-seeds the device is refused"
            );
        });
    }

    #[test]
    fn a_pass_that_outlives_the_session_cannot_refill_the_cache() {
        let backing = InMemorySnapshotCache::default();
        let alive = latch(true);
        let seam = LiveSeam::new(backing.clone(), alive.clone());
        block_on(async {
            seam.put(b"key", b"sealed").await.unwrap();
            backing.clear().await.unwrap();

            alive.set(false);

            seam.put(b"key", b"sealed").await.unwrap_err();
            seam.remove(b"key").await.unwrap_err();
            assert_eq!(
                backing.get(b"key").await.unwrap(),
                None,
                "an erased cache must stay erased behind the seam"
            );
        });
    }

    #[test]
    fn a_pass_that_outlives_the_session_cannot_stage_anything() {
        let backing = InMemoryStagingStore::default();
        let alive = latch(true);
        let seam = LiveSeam::new(backing.clone(), alive.clone());
        block_on(async {
            let op = seam.enqueue_op(b"op").await.unwrap();
            backing.clear().await.unwrap();

            alive.set(false);

            seam.enqueue_op(b"op").await.unwrap_err();
            seam.put_staged_bytes(b"key", b"bytes").await.unwrap_err();
            seam.remove_op(op).await.unwrap_err();
            seam.remove_staged_bytes(b"key").await.unwrap_err();
            assert!(
                backing.queued_ops().await.unwrap().is_empty()
                    && backing.staged_keys().await.unwrap().is_empty(),
                "an erased queue must stay erased behind the seam"
            );
        });
    }

    /// The engine holds the seam unwrapped, so the latch `shut_down` drops
    /// cannot refuse the erase that follows it.
    #[test]
    fn the_erase_itself_is_not_gated_by_the_latch_it_drops() {
        let alive = latch(false);
        let floors = LiveSeam::new(InMemoryFloorStore::default(), alive.clone());
        let cache = LiveSeam::new(InMemorySnapshotCache::default(), alive.clone());
        let staging = LiveSeam::new(InMemoryStagingStore::default(), alive);
        block_on(async {
            FloorStore::clear(&floors).await.unwrap();
            SnapshotCache::clear(&cache).await.unwrap();
            StagingStore::clear(&staging).await.unwrap();
        });
    }
}
