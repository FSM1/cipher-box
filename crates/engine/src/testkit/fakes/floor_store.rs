//! In-memory [`FloorStore`] fake.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::seams::{FloorNamespace, FloorRaise, FloorStore, OWNER_TAG_LEN, SeamError, SeamResult};

#[derive(Default)]
struct Inner {
    epoch: HashMap<Vec<u8>, u64>,
    sequence: HashMap<Vec<u8>, u64>,
    /// Floor keys whose raise is injected to fail.
    failing: HashSet<Vec<u8>>,
    /// Whether [`FloorStore::clear`] is injected to fail.
    failing_clear: bool,
}

impl Inner {
    /// Matched on the key with the owner tag stripped: the engine reaches this
    /// store through
    /// [`OwnerScopedFloorStore`](crate::seams::OwnerScopedFloorStore), and an
    /// injector names the floor, not the identity holding it. Exact past that,
    /// so a fault injected for one name cannot fire for another that ends in it.
    fn refuse(&self, key: &[u8]) -> Option<SeamError> {
        let floor = key.get(OWNER_TAG_LEN..)?;
        self.failing
            .contains(floor)
            .then(|| SeamError::new(format!("floor raise injected to fail for key {key:?}")))
    }
}

/// In-memory monotonic-max floor store. Clones share state ("reopen").
#[derive(Clone, Default)]
pub struct InMemoryFloorStore {
    inner: Arc<Mutex<Inner>>,
}

impl InMemoryFloorStore {
    /// Make every floor raise naming `key` fail until
    /// [`heal_floors`](Self::heal_floors) clears it. The raise is an adoption's
    /// durable last step, so this drives a self-adopt that fails after its
    /// record is already live at its name.
    pub fn fail_floor_raises_for(&self, key: &[u8]) {
        self.inner
            .lock()
            .expect("lock")
            .failing
            .insert(key.to_vec());
    }

    /// Restore every injected floor fault, the clear's included — one heal for
    /// every injector this fake offers.
    pub fn heal_floors(&self) {
        let mut inner = self.inner.lock().expect("lock");
        inner.failing.clear();
        inner.failing_clear = false;
    }

    /// Make [`FloorStore::clear`] fail, so a test can drive the erase leg of
    /// "forget this device" onto its refusal path with the floors left standing.
    pub fn fail_clear(&self) {
        self.inner.lock().expect("lock").failing_clear = true;
    }
}

fn raise(map: &mut HashMap<Vec<u8>, u64>, key: &[u8], value: u64) -> u64 {
    let entry = map.entry(key.to_vec()).or_insert(value);
    *entry = (*entry).max(value);
    *entry
}

impl FloorStore for InMemoryFloorStore {
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
        Ok(self
            .inner
            .lock()
            .expect("lock")
            .epoch
            .get(scope_id)
            .copied())
    }

    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        let mut inner = self.inner.lock().expect("lock");
        match inner.refuse(scope_id) {
            Some(error) => Err(error),
            None => Ok(raise(&mut inner.epoch, scope_id, epoch)),
        }
    }

    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        Ok(self
            .inner
            .lock()
            .expect("lock")
            .sequence
            .get(ipns_name)
            .copied())
    }

    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        let mut inner = self.inner.lock().expect("lock");
        match inner.refuse(ipns_name) {
            Some(error) => Err(error),
            None => Ok(raise(&mut inner.sequence, ipns_name, sequence)),
        }
    }

    /// Genuinely all-or-nothing: the whole batch applies under one lock guard,
    /// so no observer sees a partial commit (the atomic contract `commit_floors`
    /// asks of a transactional backing).
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<()> {
        let mut inner = self.inner.lock().expect("lock");
        if let Some(error) = raises.iter().find_map(|r| inner.refuse(&r.key)) {
            return Err(error);
        }
        for r in raises {
            match r.namespace {
                FloorNamespace::Epoch => raise(&mut inner.epoch, &r.key, r.value),
                FloorNamespace::Sequence => raise(&mut inner.sequence, &r.key, r.value),
            };
        }
        Ok(())
    }

    async fn clear(&self) -> SeamResult<()> {
        let mut inner = self.inner.lock().expect("lock");
        if inner.failing_clear {
            return Err(SeamError::new("floor clear injected to fail"));
        }
        inner.epoch.clear();
        inner.sequence.clear();
        Ok(())
    }
}
