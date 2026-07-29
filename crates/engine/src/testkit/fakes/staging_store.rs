//! In-memory [`StagingStore`] fake.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::seams::{OpId, SeamError, SeamResult, StagingStore};

struct Inner {
    next_op_id: u64,
    ops: Vec<(OpId, Vec<u8>)>,
    staged: BTreeMap<Vec<u8>, Vec<u8>>,
    fail_queued_ops: bool,
    fail_remove_op: bool,
    enqueue_budget: Option<u64>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            next_op_id: 1,
            ops: Vec::new(),
            staged: BTreeMap::new(),
            fail_queued_ops: false,
            fail_remove_op: false,
            enqueue_budget: None,
        }
    }
}

/// In-memory durable op queue + staged bytes. Clones share state
/// ("reopen").
#[derive(Clone, Default)]
pub struct InMemoryStagingStore {
    inner: Arc<Mutex<Inner>>,
}

impl InMemoryStagingStore {
    /// Makes `queued_ops` return a seam error, so tests can prove a caller's
    /// precondition guard runs before the staging read.
    pub fn fail_queued_ops(&self) {
        self.inner.lock().expect("lock").fail_queued_ops = true;
    }

    /// Makes `remove_op` return a seam error without dropping the record, so
    /// tests can prove a durable removal that fails after a successful
    /// dead-letter send leaves the op queued for the next boot.
    pub fn fail_remove_op(&self) {
        self.inner.lock().expect("lock").fail_remove_op = true;
    }

    /// Lets the next `budget` enqueues through and fails every one after, so a
    /// test can drop a durable-queue outage in the middle of a multi-op
    /// sequence and see what the earlier entries already committed.
    pub fn fail_enqueue_after(&self, budget: u64) {
        self.inner.lock().expect("lock").enqueue_budget = Some(budget);
    }
}

impl StagingStore for InMemoryStagingStore {
    async fn enqueue_op(&self, op: &[u8]) -> SeamResult<OpId> {
        let mut inner = self.inner.lock().expect("lock");
        match inner.enqueue_budget {
            Some(0) => return Err(SeamError::new("enqueue_op unavailable")),
            Some(budget) => inner.enqueue_budget = Some(budget - 1),
            None => {}
        }
        let op_id = OpId(inner.next_op_id);
        inner.next_op_id += 1;
        inner.ops.push((op_id, op.to_vec()));
        Ok(op_id)
    }

    async fn queued_ops(&self) -> SeamResult<Vec<(OpId, Vec<u8>)>> {
        let inner = self.inner.lock().expect("lock");
        if inner.fail_queued_ops {
            return Err(SeamError::new("queued_ops unavailable"));
        }
        Ok(inner.ops.clone())
    }

    async fn remove_op(&self, op_id: OpId) -> SeamResult<()> {
        let mut inner = self.inner.lock().expect("lock");
        if inner.fail_remove_op {
            return Err(SeamError::new("remove_op unavailable"));
        }
        inner.ops.retain(|(id, _)| *id != op_id);
        Ok(())
    }

    async fn put_staged_bytes(&self, staging_key: &[u8], bytes: &[u8]) -> SeamResult<()> {
        self.inner
            .lock()
            .expect("lock")
            .staged
            .insert(staging_key.to_vec(), bytes.to_vec());
        Ok(())
    }

    async fn staged_bytes(&self, staging_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        Ok(self
            .inner
            .lock()
            .expect("lock")
            .staged
            .get(staging_key)
            .cloned())
    }

    async fn remove_staged_bytes(&self, staging_key: &[u8]) -> SeamResult<()> {
        self.inner.lock().expect("lock").staged.remove(staging_key);
        Ok(())
    }

    async fn staged_keys(&self) -> SeamResult<Vec<Vec<u8>>> {
        Ok(self
            .inner
            .lock()
            .expect("lock")
            .staged
            .keys()
            .cloned()
            .collect())
    }

    async fn staged_bytes_total(&self) -> SeamResult<u64> {
        Ok(self
            .inner
            .lock()
            .expect("lock")
            .staged
            .values()
            .map(|bytes| bytes.len() as u64)
            .sum())
    }
}
