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
    /// Whether every floor **read** is injected to fail.
    failing_reads: bool,
    /// Floor keys whose epoch **read** is injected to fail.
    failing_read_keys: HashSet<Vec<u8>>,
    /// Floor keys whose epoch **read** fails once a budget of earlier reads
    /// of the same bar is spent.
    read_budgets: HashMap<Vec<u8>, u64>,
    /// Whether [`FloorStore::commit_floors`] is injected to fail.
    failing_commit: bool,
    /// Raises still allowed before every later raise, on any key, fails.
    raise_budget: Option<u64>,
    /// Added to the floor a raise settles on before it is reported back.
    raise_report_skew: u64,
}

impl Inner {
    /// Matched on the key with the owner tag stripped: the engine reaches this
    /// store through
    /// [`OwnerScopedFloorStore`](crate::seams::OwnerScopedFloorStore), and an
    /// injector names the floor, not the identity holding it. Exact past that,
    /// so a fault injected for one name cannot fire for another that ends in it.
    /// A sequence floor is stored under its name label, so an injector names
    /// that label ([`sequence_floor_label`](crate::testkit::account::sequence_floor_label)).
    fn refuse(&self, key: &[u8]) -> Option<SeamError> {
        let floor = key.get(OWNER_TAG_LEN..)?;
        self.failing
            .contains(floor)
            .then(|| SeamError::new(format!("floor raise injected to fail for key {key:?}")))
    }

    /// Spend one raise of the injected budget, or refuse once it is spent.
    fn spend_raise(&mut self) -> Option<SeamError> {
        match self.raise_budget {
            Some(0) => Some(SeamError::new(
                "floor raise injected to fail past its budget",
            )),
            Some(remaining) => {
                self.raise_budget = Some(remaining - 1);
                None
            }
            None => None,
        }
    }

    /// The read-side twin of [`refuse`](Self::refuse). Matched on the whole key
    /// as well as on the owner-tag-stripped one, because a unit test drives this
    /// store bare while the engine reaches it through
    /// [`OwnerScopedFloorStore`](crate::seams::OwnerScopedFloorStore).
    fn refuse_read(&mut self, key: &[u8]) -> Option<SeamError> {
        if self.failing_reads {
            return Some(SeamError::new("floor read injected to fail"));
        }
        let untagged = key.get(OWNER_TAG_LEN..).unwrap_or_default().to_vec();
        if self.failing_read_keys.contains(key) || self.failing_read_keys.contains(&untagged) {
            return Some(SeamError::new(format!(
                "floor read injected to fail for key {key:?}"
            )));
        }
        if self.read_budgets.is_empty() {
            return None;
        }
        let budgeted = [key.to_vec(), untagged]
            .into_iter()
            .find(|candidate| self.read_budgets.contains_key(candidate))?;
        let budget = self.read_budgets.get_mut(&budgeted)?;
        if *budget == 0 {
            return Some(SeamError::new(format!(
                "floor read injected to fail for key {key:?} past its budget"
            )));
        }
        *budget -= 1;
        None
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

    /// Make every epoch-floor read naming `key` fail until
    /// [`heal_floors`](Self::heal_floors) clears it, so a test can fail one bar
    /// of a pass that reads several.
    pub fn fail_epoch_floor_reads_for(&self, key: &[u8]) {
        self.inner
            .lock()
            .expect("lock")
            .failing_read_keys
            .insert(key.to_vec());
    }

    /// Restore every injected floor fault, the clear's and the commit's
    /// included — one heal for every injector this fake offers.
    pub fn heal_floors(&self) {
        let mut inner = self.inner.lock().expect("lock");
        inner.failing.clear();
        inner.failing_clear = false;
        inner.failing_reads = false;
        inner.failing_read_keys.clear();
        inner.read_budgets.clear();
        inner.failing_commit = false;
        inner.raise_budget = None;
        inner.raise_report_skew = 0;
    }

    /// Let `budget` raises through, on any key, and fail every raise after, so
    /// a test can fault one leg of an advance that raises several floors.
    pub fn fail_floor_raises_after(&self, budget: u64) {
        self.inner.lock().expect("lock").raise_budget = Some(budget);
    }

    /// Make [`FloorStore::commit_floors`] fail before it touches a key, so a
    /// test can drive a transactional backing's all-or-nothing abort.
    pub fn fail_floor_commits(&self) {
        self.inner.lock().expect("lock").failing_commit = true;
    }

    /// Report every raise `skew` above the floor it settles on — the shape a
    /// non-monotonic counter would take, which a mint must refuse rather than
    /// publish behind.
    pub fn skew_reported_raises(&self, skew: u64) {
        self.inner.lock().expect("lock").raise_report_skew = skew;
    }

    /// Let `budget` epoch-floor reads naming `key` through and fail every one
    /// after, so a test can fail a later pass of a sequence that reads the same
    /// bar more than once.
    pub fn fail_epoch_floor_reads_after(&self, key: &[u8], budget: u64) {
        self.inner
            .lock()
            .expect("lock")
            .read_budgets
            .insert(key.to_vec(), budget);
    }

    /// Make every floor read fail, so a test can drive a consumer that must
    /// refuse rather than treat an unreadable floor as no floor.
    pub fn fail_floor_reads(&self) {
        self.inner.lock().expect("lock").failing_reads = true;
    }

    /// Make [`FloorStore::clear`] fail, so a test can drive the erase leg of
    /// "forget this device" onto its refusal path with the floors left standing.
    pub fn fail_clear(&self) {
        self.inner.lock().expect("lock").failing_clear = true;
    }

    /// Every epoch-namespace key this store holds, exactly as it was written —
    /// what a test asserts a durable key does not disclose.
    #[must_use]
    pub fn epoch_keys(&self) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .expect("lock")
            .epoch
            .keys()
            .cloned()
            .collect()
    }

    /// Every sequence-namespace key this store holds, exactly as it was written
    /// — [`epoch_keys`](Self::epoch_keys)'s twin for the namespace that would
    /// otherwise name a record.
    #[must_use]
    pub fn sequence_keys(&self) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .expect("lock")
            .sequence
            .keys()
            .cloned()
            .collect()
    }
}

fn raise(map: &mut HashMap<Vec<u8>, u64>, key: &[u8], value: u64) -> u64 {
    let entry = map.entry(key.to_vec()).or_insert(value);
    *entry = (*entry).max(value);
    *entry
}

impl FloorStore for InMemoryFloorStore {
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
        let mut inner = self.inner.lock().expect("lock");
        if let Some(error) = inner.refuse_read(scope_id) {
            return Err(error);
        }
        Ok(inner.epoch.get(scope_id).copied())
    }

    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        let mut inner = self.inner.lock().expect("lock");
        if let Some(error) = inner.refuse(scope_id).or_else(|| inner.spend_raise()) {
            return Err(error);
        }
        let skew = inner.raise_report_skew;
        Ok(raise(&mut inner.epoch, scope_id, epoch).saturating_add(skew))
    }

    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        let inner = self.inner.lock().expect("lock");
        if inner.failing_reads {
            return Err(SeamError::new("floor read injected to fail"));
        }
        Ok(inner.sequence.get(ipns_name).copied())
    }

    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        let mut inner = self.inner.lock().expect("lock");
        if let Some(error) = inner.refuse(ipns_name).or_else(|| inner.spend_raise()) {
            return Err(error);
        }
        let skew = inner.raise_report_skew;
        Ok(raise(&mut inner.sequence, ipns_name, sequence).saturating_add(skew))
    }

    /// Genuinely all-or-nothing: the whole batch applies under one lock guard,
    /// so no observer sees a partial commit (the atomic contract `commit_floors`
    /// asks of a transactional backing).
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<()> {
        let mut inner = self.inner.lock().expect("lock");
        if inner.failing_commit {
            return Err(SeamError::new("floor commit injected to fail"));
        }
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

/// [`InMemoryFloorStore`] with no [`FloorStore::commit_floors`] override, so an
/// advance runs the seam's non-atomic default and writes each floor on its own
/// — the split-write backing a transactional one is contrasted against.
#[derive(Clone, Default)]
pub struct SplitWriteFloorStore {
    floors: InMemoryFloorStore,
}

impl SplitWriteFloorStore {
    /// The backing store, for the injectors and the heal.
    #[must_use]
    pub fn floors(&self) -> &InMemoryFloorStore {
        &self.floors
    }
}

impl FloorStore for SplitWriteFloorStore {
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
        self.floors.epoch_floor(scope_id).await
    }

    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        self.floors.raise_epoch_floor(scope_id, epoch).await
    }

    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        self.floors.sequence_floor(ipns_name).await
    }

    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        self.floors.raise_sequence_floor(ipns_name, sequence).await
    }

    async fn clear(&self) -> SeamResult<()> {
        self.floors.clear().await
    }
}
