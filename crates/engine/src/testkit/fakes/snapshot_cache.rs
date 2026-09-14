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
    /// Bytes served for every key, whatever is stored
    /// ([`serve_fixed_ciphertext`](InMemorySnapshotCache::serve_fixed_ciphertext)).
    fixed: Arc<Mutex<Option<Vec<u8>>>>,
    /// Whether every `get` parks for ever
    /// ([`stall_gets`](InMemorySnapshotCache::stall_gets)).
    stalling_gets: Arc<AtomicBool>,
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

    /// Answer every `get` with `ciphertext`, whatever key it names — the shape
    /// of a tampered or transplanted last-known-good entry.
    pub fn serve_fixed_ciphertext(&self, ciphertext: Vec<u8>) {
        *self.fixed.lock().expect("lock") = Some(ciphertext);
    }

    /// Park every `get` for ever — the shape of a stalled host store. The
    /// future stays `Pending`, so a deterministic executor parks on it rather
    /// than spinning.
    pub fn stall_gets(&self) {
        self.stalling_gets.store(true, Ordering::SeqCst);
    }

    /// Every ciphertext this cache holds, in cache-key order — what a test
    /// asserts the engine wrote, apart from the keys it wrote under.
    #[must_use]
    pub fn values(&self) -> Vec<Vec<u8>> {
        self.inner.lock().expect("lock").values().cloned().collect()
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
        if self.stalling_gets.load(Ordering::SeqCst) {
            return core::future::poll_fn(|_| core::task::Poll::Pending).await;
        }
        if let Some(fixed) = self.fixed.lock().expect("lock").clone() {
            return Ok(Some(fixed));
        }
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
