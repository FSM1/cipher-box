//! In-memory [`StagingStore`] fake.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::seams::{OpId, SeamError, SeamResult, StagingStore};

struct Inner {
    next_op_id: u64,
    ops: Vec<(OpId, Vec<u8>)>,
    staged: BTreeMap<Vec<u8>, Vec<u8>>,
    fail_queued_ops: bool,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            next_op_id: 1,
            ops: Vec::new(),
            staged: BTreeMap::new(),
            fail_queued_ops: false,
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
}

impl StagingStore for InMemoryStagingStore {
    async fn enqueue_op(&self, op: &[u8]) -> SeamResult<OpId> {
        let mut inner = self.inner.lock().expect("lock");
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
        self.inner
            .lock()
            .expect("lock")
            .ops
            .retain(|(id, _)| *id != op_id);
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
