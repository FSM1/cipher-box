//! Cross-key atomic floor-commit durability (#685).
//!
//! A floor advance raises several distinctly-keyed floors (read-epoch,
//! per-name sequence) at once. This suite drives the engine's floor law
//! ([`advance_on_unseal`]) through two fault-injecting [`FloorStore`] backings
//! and contrasts them:
//!
//! - a backing whose [`FloorStore::commit_floors`] is transactional → a
//!   mid-advance seam fault leaves **no** floor moved (all-or-nothing, the #685
//!   fix);
//! - a backing on the seam's non-atomic default fallback → the same fault
//!   leaves a *partial* advance. That negative control makes the atomic
//!   assertion non-vacuous (it is what "the test fails with the atomic commit
//!   disabled" means here) while confirming #682's fail-safe ordering and
//!   idempotent re-convergence still hold.
//!
//! The desktop file store closes the same hazard by **roll-forward** replay
//! (write-ahead intent, heal-on-reopen) rather than transactional rollback; that
//! contract is exercised in `cipherbox-desktop-seams` (`floor_store` unit tests).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use cipherbox_engine::gate::floor::{advance_on_unseal, read_epoch_floor, sequence_floor};
use cipherbox_engine::seams::{FloorRaise, FloorStore, SeamError, SeamResult};
use cipherbox_engine::testkit::block_on;
use cipherbox_engine::testkit::fakes::InMemoryFloorStore;

const SCOPE: [u8; 16] = [7u8; 16];
const NAME: &[u8] = b"k51-scope-root-name";
const EPOCH: u64 = 3;
const SEQUENCE: u64 = 5;

/// Never-fault sentinel for the injected raise budget.
const DISARMED: usize = usize::MAX;

// ---------------------------------------------------------------------------
// A backing that faults the Nth single-key raise and does NOT override
// commit_floors — so an advance runs the seam's non-atomic default fallback,
// the pre-#685 split-write behaviour.
// ---------------------------------------------------------------------------

struct SplitFaultyStore {
    inner: InMemoryFloorStore,
    raises_until_fault: AtomicUsize,
}

impl SplitFaultyStore {
    /// Allows `budget` raises to succeed, then faults every raise after.
    fn allowing(budget: usize) -> Self {
        Self {
            inner: InMemoryFloorStore::default(),
            raises_until_fault: AtomicUsize::new(budget),
        }
    }

    fn disarm(&self) {
        self.raises_until_fault.store(DISARMED, Ordering::Relaxed);
    }

    fn tick(&self) -> SeamResult<()> {
        match self.raises_until_fault.load(Ordering::Relaxed) {
            0 => Err(SeamError::new("injected seam I/O fault (split raise)")),
            remaining => {
                if remaining != DISARMED {
                    self.raises_until_fault
                        .store(remaining - 1, Ordering::Relaxed);
                }
                Ok(())
            }
        }
    }
}

impl FloorStore for SplitFaultyStore {
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
        self.inner.epoch_floor(scope_id).await
    }

    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        self.tick()?;
        self.inner.raise_epoch_floor(scope_id, epoch).await
    }

    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        self.inner.sequence_floor(ipns_name).await
    }

    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        self.tick()?;
        self.inner.raise_sequence_floor(ipns_name, sequence).await
    }
}

// ---------------------------------------------------------------------------
// A backing with a genuinely atomic commit_floors: an armed fault aborts the
// whole batch before touching any key (a transactional store's all-or-nothing).
// ---------------------------------------------------------------------------

struct AtomicFaultyStore {
    inner: InMemoryFloorStore,
    fail_commit: AtomicBool,
}

impl AtomicFaultyStore {
    fn armed() -> Self {
        Self {
            inner: InMemoryFloorStore::default(),
            fail_commit: AtomicBool::new(true),
        }
    }

    fn disarm(&self) {
        self.fail_commit.store(false, Ordering::Relaxed);
    }
}

impl FloorStore for AtomicFaultyStore {
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
        self.inner.epoch_floor(scope_id).await
    }

    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        self.inner.raise_epoch_floor(scope_id, epoch).await
    }

    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        self.inner.sequence_floor(ipns_name).await
    }

    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        self.inner.raise_sequence_floor(ipns_name, sequence).await
    }

    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<()> {
        if self.fail_commit.load(Ordering::Relaxed) {
            return Err(SeamError::new("injected seam I/O fault (atomic commit)"));
        }
        self.inner.commit_floors(raises).await
    }
}

/// The fix: with an atomic commit, a mid-advance fault moves no floor at all,
/// and a retry converges the whole advance.
#[test]
fn advance_on_unseal_is_all_or_nothing_when_the_backing_commits_atomically() {
    let store = AtomicFaultyStore::armed();
    block_on(async {
        assert!(
            advance_on_unseal(&store, &SCOPE, NAME, SEQUENCE, EPOCH)
                .await
                .is_err(),
            "the injected commit fault must surface as a seam error"
        );
        assert_eq!(
            read_epoch_floor(&store, &SCOPE).await.unwrap(),
            None,
            "an atomic commit must leave the read-epoch floor untouched on a fault"
        );
        assert_eq!(
            sequence_floor(&store, NAME).await.unwrap(),
            None,
            "an atomic commit must leave NO partial floor state at all"
        );

        // Idempotent re-convergence once the fault clears.
        store.disarm();
        advance_on_unseal(&store, &SCOPE, NAME, SEQUENCE, EPOCH)
            .await
            .unwrap();
        assert_eq!(read_epoch_floor(&store, &SCOPE).await.unwrap(), Some(EPOCH));
        assert_eq!(sequence_floor(&store, NAME).await.unwrap(), Some(SEQUENCE));
    });
}

/// The negative control (atomic commit disabled): the same fault leaves a
/// PARTIAL advance — the hazard #685 closes. It also proves #682's fail-safe
/// ordering (revocation floor commits first, so the partial fails closed) and
/// idempotent re-convergence on retry.
#[test]
fn advance_on_unseal_leaves_a_fail_safe_partial_without_atomic_commit() {
    // Budget 1: the first raise (revocation floor) succeeds, the second
    // (sequence floor) faults.
    let store = SplitFaultyStore::allowing(1);
    block_on(async {
        assert!(
            advance_on_unseal(&store, &SCOPE, NAME, SEQUENCE, EPOCH)
                .await
                .is_err(),
            "the second (sequence) raise must fault"
        );
        assert_eq!(
            read_epoch_floor(&store, &SCOPE).await.unwrap(),
            Some(EPOCH),
            "fail-safe ordering: the revocation floor commits first, so a partial fails closed"
        );
        assert_eq!(
            sequence_floor(&store, NAME).await.unwrap(),
            None,
            "without an atomic commit the sequence floor is left stale — the observable partial"
        );

        // Idempotent re-convergence: retry with the fault cleared completes it.
        store.disarm();
        advance_on_unseal(&store, &SCOPE, NAME, SEQUENCE, EPOCH)
            .await
            .unwrap();
        assert_eq!(read_epoch_floor(&store, &SCOPE).await.unwrap(), Some(EPOCH));
        assert_eq!(sequence_floor(&store, NAME).await.unwrap(), Some(SEQUENCE));
    });
}

/// Monotonic-max holds through the atomic batch path: a lower retry never
/// lowers a floor already raised.
#[test]
fn atomic_commit_preserves_monotonic_max() {
    let store = AtomicFaultyStore::armed();
    store.disarm();
    block_on(async {
        advance_on_unseal(&store, &SCOPE, NAME, SEQUENCE, EPOCH)
            .await
            .unwrap();
        // A stale advance (lower epoch and sequence) is a no-op.
        advance_on_unseal(&store, &SCOPE, NAME, SEQUENCE - 1, EPOCH - 1)
            .await
            .unwrap();
        assert_eq!(read_epoch_floor(&store, &SCOPE).await.unwrap(), Some(EPOCH));
        assert_eq!(sequence_floor(&store, NAME).await.unwrap(), Some(SEQUENCE));
    });
}
