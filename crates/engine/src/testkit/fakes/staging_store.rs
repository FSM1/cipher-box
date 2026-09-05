//! In-memory [`StagingStore`] fake.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::seams::{OpId, SeamError, SeamResult, StagingStore};
use crate::testkit::conformance::staging_store::Backing;

struct Inner {
    next_op_id: u64,
    ops: Vec<(OpId, Vec<u8>)>,
    staged: BTreeMap<Vec<u8>, Vec<u8>>,
    fail_queued_ops: bool,
    fail_remove_op: bool,
    enqueue_budget: Option<u64>,
    staged_write_budget: Option<Arm>,
    destructive_write_budget: Option<Arm>,
    partial_write_budget: Option<Arm>,
    staged_removal_budget: Option<Arm>,
    dropped_removal_budget: Option<Arm>,
    key_listings: u64,
    queue_listings: u64,
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
            staged_write_budget: None,
            destructive_write_budget: None,
            partial_write_budget: None,
            staged_removal_budget: None,
            dropped_removal_budget: None,
            key_listings: 0,
            queue_listings: 0,
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

    /// Lets `budget` writes at `staging_key` through, fails the next one, then
    /// disarms — a caller dropped at an exact step whose retry still proceeds.
    pub fn interrupt_staged_write_after(&self, staging_key: &[u8], budget: u64) {
        self.inner.lock().expect("lock").staged_write_budget =
            Some(Arm::exact(staging_key, budget));
    }

    /// The same, over every key under `prefix` — for a family whose member the
    /// test cannot name in advance, like the per-version upload marks.
    pub fn interrupt_staged_write_family_after(&self, prefix: &[u8], budget: u64) {
        self.inner.lock().expect("lock").staged_write_budget = Some(Arm::family(prefix, budget));
    }

    /// Fails the next write at `staging_key` past `budget` **after** dropping
    /// the bytes already there — the truncate-in-place shape of a host whose
    /// replacement is not failure-atomic.
    pub fn destroy_staged_write_after(&self, staging_key: &[u8], budget: u64) {
        self.inner.lock().expect("lock").destructive_write_budget =
            Some(Arm::exact(staging_key, budget));
    }

    /// Fails the next write at `staging_key` past `budget`, landing half of the
    /// new bytes when the key held none — the write-in-place shape of a host
    /// that is failure-atomic on a replacement but strands a partial record on
    /// a create.
    pub fn strand_staged_write_after(&self, staging_key: &[u8], budget: u64) {
        self.inner.lock().expect("lock").partial_write_budget =
            Some(Arm::exact(staging_key, budget));
    }

    /// The removal counterpart of [`Self::interrupt_staged_write_after`]: the
    /// other side of every crash window between a durable write and a release.
    pub fn interrupt_staged_removal_after(&self, staging_key: &[u8], budget: u64) {
        self.inner.lock().expect("lock").staged_removal_budget =
            Some(Arm::exact(staging_key, budget));
    }

    /// How many whole-key-space enumerations this store has served. A desktop
    /// vault stages tens of thousands of keys, so a pass that lists more than
    /// once is paying for the same answer twice.
    pub fn key_listings(&self) -> u64 {
        self.inner.lock().expect("lock").key_listings
    }

    /// How many whole-queue enumerations this store has served. A desktop store
    /// answers one with a directory listing plus a file read per pending op, so
    /// this counts what a batch of reads costs the disk.
    pub fn queue_listings(&self) -> u64 {
        self.inner.lock().expect("lock").queue_listings
    }

    /// Reports the next removal at `staging_key` past `budget` as done without
    /// dropping the bytes — an unlink that never reached the disk while a later
    /// write did, which is what a host that releases staged bytes without a
    /// durability barrier leaves behind after a crash.
    pub fn drop_staged_removal_after(&self, staging_key: &[u8], budget: u64) {
        self.inner.lock().expect("lock").dropped_removal_budget =
            Some(Arm::exact(staging_key, budget));
    }
}

/// One armed one-shot failure: which key it answers for, and how many calls it
/// lets through first. Matching is **exact** unless the arming site asked for a
/// family, so widening one injector cannot silently fire another's arm on a key
/// that merely shares a prefix.
struct Arm {
    key: Vec<u8>,
    budget: u64,
    family: bool,
}

impl Arm {
    fn exact(key: &[u8], budget: u64) -> Self {
        Self {
            key: key.to_vec(),
            budget,
            family: false,
        }
    }

    fn family(prefix: &[u8], budget: u64) -> Self {
        Self {
            key: prefix.to_vec(),
            budget,
            family: true,
        }
    }

    fn answers_for(&self, staging_key: &[u8]) -> bool {
        match self.family {
            true => staging_key.starts_with(&self.key),
            false => staging_key == self.key,
        }
    }
}

/// Charge one call at `staging_key` against a one-shot injected failure.
/// `true` when this is the call that must fail, which also disarms it. Each
/// injector holds one armed key, so arming a second replaces the first.
fn interrupts(budget: &mut Option<Arm>, staging_key: &[u8]) -> bool {
    match budget {
        Some(arm) if !arm.answers_for(staging_key) => false,
        Some(Arm { budget: 0, .. }) => {
            *budget = None;
            true
        }
        Some(arm) => {
            arm.budget -= 1;
            false
        }
        None => false,
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
        let mut inner = self.inner.lock().expect("lock");
        inner.queue_listings += 1;
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
        let mut inner = self.inner.lock().expect("lock");
        if interrupts(&mut inner.staged_write_budget, staging_key) {
            return Err(SeamError::new("put_staged_bytes unavailable"));
        }
        if interrupts(&mut inner.destructive_write_budget, staging_key) {
            inner.staged.remove(staging_key);
            return Err(SeamError::new("put_staged_bytes unavailable"));
        }
        if interrupts(&mut inner.partial_write_budget, staging_key) {
            if !inner.staged.contains_key(staging_key) {
                let half = bytes[..bytes.len() / 2].to_vec();
                inner.staged.insert(staging_key.to_vec(), half);
            }
            return Err(SeamError::new("put_staged_bytes unavailable"));
        }
        inner.staged.insert(staging_key.to_vec(), bytes.to_vec());
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
        let mut inner = self.inner.lock().expect("lock");
        if interrupts(&mut inner.staged_removal_budget, staging_key) {
            return Err(SeamError::new("remove_staged_bytes unavailable"));
        }
        if interrupts(&mut inner.dropped_removal_budget, staging_key) {
            return Ok(());
        }
        inner.staged.remove(staging_key);
        Ok(())
    }

    async fn staged_keys(&self) -> SeamResult<Vec<Vec<u8>>> {
        let mut inner = self.inner.lock().expect("lock");
        inner.key_listings += 1;
        Ok(inner.staged.keys().cloned().collect())
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

    async fn clear(&self) -> SeamResult<()> {
        let mut inner = self.inner.lock().expect("lock");
        inner.ops.clear();
        inner.staged.clear();
        Ok(())
    }
}

/// One [`InMemoryStagingStore`] per conformance-kit [`Backing`]: what a kit
/// caller's `open` factory hands back, so every phase gets its own initially
/// empty backing while a repeat call for the same one reopens it.
#[derive(Clone, Default)]
pub struct InMemoryStagingBackings {
    stores: Arc<Mutex<BTreeMap<Backing, InMemoryStagingStore>>>,
}

impl InMemoryStagingBackings {
    /// The store backing `backing`, minted empty on first ask.
    pub fn open(&self, backing: Backing) -> InMemoryStagingStore {
        self.stores
            .lock()
            .expect("lock")
            .entry(backing)
            .or_default()
            .clone()
    }
}
