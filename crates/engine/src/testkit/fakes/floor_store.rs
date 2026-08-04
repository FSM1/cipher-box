//! In-memory [`FloorStore`] fake.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::seams::{FloorNamespace, FloorRaise, FloorStore, SeamResult};

#[derive(Default)]
struct Inner {
    epoch: HashMap<Vec<u8>, u64>,
    sequence: HashMap<Vec<u8>, u64>,
}

/// In-memory monotonic-max floor store. Clones share state ("reopen").
#[derive(Clone, Default)]
pub struct InMemoryFloorStore {
    inner: Arc<Mutex<Inner>>,
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
        Ok(raise(
            &mut self.inner.lock().expect("lock").epoch,
            scope_id,
            epoch,
        ))
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
        Ok(raise(
            &mut self.inner.lock().expect("lock").sequence,
            ipns_name,
            sequence,
        ))
    }

    /// Genuinely all-or-nothing: the whole batch applies under one lock guard,
    /// so no observer sees a partial commit (the atomic contract #685 asks of a
    /// transactional backing).
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<()> {
        let mut inner = self.inner.lock().expect("lock");
        for r in raises {
            match r.namespace {
                FloorNamespace::Epoch => raise(&mut inner.epoch, &r.key, r.value),
                FloorNamespace::Sequence => raise(&mut inner.sequence, &r.key, r.value),
            };
        }
        Ok(())
    }
}
