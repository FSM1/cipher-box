//! In-memory [`SnapshotCache`] fake.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::seams::{SeamResult, SnapshotCache};

/// In-memory ciphertext cache. Clones share state ("reopen"). Stores bytes
/// verbatim and never inspects them — the ciphertext-only-at-rest posture.
#[derive(Clone, Default)]
pub struct InMemorySnapshotCache {
    inner: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl SnapshotCache for InMemorySnapshotCache {
    async fn put(&self, cache_key: &[u8], ciphertext: &[u8]) -> SeamResult<()> {
        self.inner
            .lock()
            .expect("lock")
            .insert(cache_key.to_vec(), ciphertext.to_vec());
        Ok(())
    }

    async fn get(&self, cache_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        Ok(self.inner.lock().expect("lock").get(cache_key).cloned())
    }

    async fn remove(&self, cache_key: &[u8]) -> SeamResult<()> {
        self.inner.lock().expect("lock").remove(cache_key);
        Ok(())
    }

    async fn clear(&self) -> SeamResult<()> {
        self.inner.lock().expect("lock").clear();
        Ok(())
    }
}
