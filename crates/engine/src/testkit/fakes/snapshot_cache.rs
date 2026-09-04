//! In-memory [`SnapshotCache`] fake.

use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::seams::{SeamError, SeamResult, SnapshotCache};

/// In-memory ciphertext cache. Clones share state ("reopen"). Stores bytes
/// verbatim and never inspects them — the ciphertext-only-at-rest posture.
#[derive(Clone, Default)]
pub struct InMemorySnapshotCache {
    inner: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
    reads: Arc<Mutex<Vec<Vec<u8>>>>,
    failing_puts: Arc<AtomicBool>,
}

impl InMemorySnapshotCache {
    /// Every cache key `get` was called with, in call order — how a test tells
    /// a cache-first resolve from a nocache one.
    pub fn reads(&self) -> Vec<Vec<u8>> {
        self.reads.lock().expect("lock").clone()
    }

    /// Make every `put` fail until [`heal_puts`](Self::heal_puts) clears it, so
    /// a test can drive a gate pass whose record never becomes last-known-good.
    pub fn fail_puts(&self) {
        self.failing_puts.store(true, Ordering::SeqCst);
    }

    /// Restore the injected `put` fault.
    pub fn heal_puts(&self) {
        self.failing_puts.store(false, Ordering::SeqCst);
    }

    /// The ciphertext held under `cache_key`, if any.
    pub fn peek(&self, cache_key: &[u8]) -> Option<Vec<u8>> {
        self.inner.lock().expect("lock").get(cache_key).cloned()
    }
}

impl SnapshotCache for InMemorySnapshotCache {
    async fn put(&self, cache_key: &[u8], ciphertext: &[u8]) -> SeamResult<()> {
        if self.failing_puts.load(Ordering::SeqCst) {
            return Err(SeamError::new("snapshot put injected to fail"));
        }
        self.inner
            .lock()
            .expect("lock")
            .insert(cache_key.to_vec(), ciphertext.to_vec());
        Ok(())
    }

    async fn get(&self, cache_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        self.reads.lock().expect("lock").push(cache_key.to_vec());
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
