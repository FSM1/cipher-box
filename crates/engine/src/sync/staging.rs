//! Budgeted offline staging behind the [`StagingStore`] seam (blueprint/
//! engine.md "Sync core: Ops"; #33 D6).
//!
//! Web reaches full offline parity: uploads stage into OPFS/IndexedDB behind
//! the profile budget; **past the budget only new uploads fail fast, while
//! metadata ops queue unbounded**. The op queue is the durable divergence and
//! must never be capped — a delete or rename can always be journaled — but
//! staged upload *bytes* are bounded so an offline device cannot exhaust host
//! storage.

use crate::profile::SyncTimingProfile;
use crate::seams::{OpId, SeamError, SeamResult, StagingStore};
use crate::sync::op::Op;

/// The outcome of staging one op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    /// The op was journaled; on a content op its bytes were staged too.
    Queued {
        /// The durable op-queue id.
        op_id: OpId,
    },
    /// A content upload would exceed the profile staging budget: it fails fast
    /// and **nothing** is journaled or staged (the mutation did not happen).
    RejectedOverBudget {
        /// Staged bytes already held.
        staged: u64,
        /// The upload's own byte length.
        incoming: u64,
        /// The profile budget.
        budget: u64,
    },
}

/// Stage one op. Metadata ops (no upload bytes) always enqueue, regardless of
/// budget. A content op is fail-fast: if staged-total + its bytes would exceed
/// the budget, nothing is written; otherwise the bytes are staged under the
/// op's staging key and the op is enqueued.
///
/// `upload` is the **already-sealed** content payload (core's content-seal runs
/// upstream in the content plane); no plaintext user content ever lands in the
/// staging store at rest.
///
/// Fail-fast ordering: the budget is checked and the bytes staged **before**
/// the op is enqueued, so a rejected upload leaves no dangling queue entry and
/// an accepted one leaves no op referencing unstaged bytes.
pub async fn stage_op<S: StagingStore>(
    store: &S,
    profile: &SyncTimingProfile,
    op: &Op,
    upload: Option<&[u8]>,
) -> SeamResult<StageOutcome> {
    match (op.staging_key(), upload) {
        (Some(key), Some(bytes)) => {
            let staged = store.staged_bytes_total().await?;
            let incoming = bytes.len() as u64;
            // Saturating: an overflowing sum is unreachable under any real
            // budget, and must still read as "over budget", never wrap to a
            // spuriously-small total.
            if staged.saturating_add(incoming) > profile.staging_budget_bytes {
                return Ok(StageOutcome::RejectedOverBudget {
                    staged,
                    incoming,
                    budget: profile.staging_budget_bytes,
                });
            }
            store.put_staged_bytes(key, bytes).await?;
            let op_id = store.enqueue_op(&op.encode()).await?;
            Ok(StageOutcome::Queued { op_id })
        }
        // A content op (staging key present) with no bytes is a broken caller
        // contract: journaling it would leave a durable op referencing content
        // that was never staged. Fail closed — enqueue nothing.
        (Some(_), None) => Err(SeamError::new(
            "stage_op: content op carries a staging key but no upload bytes",
        )),
        // A metadata op (no staging key): journal unbounded.
        (None, _) => {
            let op_id = store.enqueue_op(&op.encode()).await?;
            Ok(StageOutcome::Queued { op_id })
        }
    }
}

/// Staging keys held by the store that no queued op references — orphan
/// residue from a rejected or superseded upload, safe to GC (#33 D6 staged-
/// bytes hygiene).
pub async fn orphan_staging_keys<S: StagingStore>(store: &S) -> SeamResult<Vec<Vec<u8>>> {
    let queued = store.queued_ops().await?;
    let mut referenced = std::collections::HashSet::new();
    for (_, bytes) in &queued {
        match Op::decode(bytes) {
            Ok(op) => {
                if let Some(key) = op.staging_key() {
                    referenced.insert(key.to_vec());
                }
            }
            // An undecodable entry dead-letters with its staged bytes preserved
            // (#33 D6); its staging key is unknowable, so nothing is safely an
            // orphan this pass — fail closed.
            Err(_) => return Ok(Vec::new()),
        }
    }
    let orphans = store
        .staged_keys()
        .await?
        .into_iter()
        .filter(|key| !referenced.contains(key))
        .collect();
    Ok(orphans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade::{NodeId, NodeKind};
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryStagingStore;

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    #[test]
    fn metadata_ops_queue_unbounded_past_the_budget() {
        let store = InMemoryStagingStore::default();
        // A budget of zero: no upload byte fits, yet metadata must still queue.
        let profile = SyncTimingProfile {
            staging_budget_bytes: 0,
            ..SyncTimingProfile::CI
        };
        block_on(async {
            for i in 0..5 {
                let out = stage_op(&store, &profile, &Op::rename(id(i), "n", 1), None)
                    .await
                    .unwrap();
                assert!(matches!(out, StageOutcome::Queued { .. }));
            }
            assert_eq!(store.queued_ops().await.unwrap().len(), 5);
        });
    }

    #[test]
    fn upload_over_budget_fails_fast_and_stages_nothing() {
        let store = InMemoryStagingStore::default();
        let profile = SyncTimingProfile {
            staging_budget_bytes: 8,
            ..SyncTimingProfile::CI
        };
        block_on(async {
            let op = Op::create(
                id(1),
                id(0),
                "big",
                NodeKind::File,
                1,
                Some(b"key".to_vec()),
            );
            let out = stage_op(&store, &profile, &op, Some(b"nine bytes"))
                .await
                .unwrap();
            assert!(matches!(out, StageOutcome::RejectedOverBudget { .. }));
            assert!(
                store.queued_ops().await.unwrap().is_empty(),
                "no dangling op"
            );
            assert_eq!(
                store.staged_bytes_total().await.unwrap(),
                0,
                "no bytes staged"
            );
        });
    }

    #[test]
    fn upload_within_budget_stages_bytes_and_queues_the_op() {
        let store = InMemoryStagingStore::default();
        let profile = SyncTimingProfile {
            staging_budget_bytes: 1024,
            ..SyncTimingProfile::CI
        };
        block_on(async {
            let op = Op::create(id(1), id(0), "f", NodeKind::File, 1, Some(b"key".to_vec()));
            let out = stage_op(&store, &profile, &op, Some(b"content"))
                .await
                .unwrap();
            assert!(matches!(out, StageOutcome::Queued { .. }));
            assert_eq!(
                store.staged_bytes(b"key").await.unwrap(),
                Some(b"content".to_vec())
            );
            assert_eq!(store.queued_ops().await.unwrap().len(), 1);
        });
    }

    #[test]
    fn budget_counts_cumulative_staged_bytes() {
        let store = InMemoryStagingStore::default();
        let profile = SyncTimingProfile {
            staging_budget_bytes: 10,
            ..SyncTimingProfile::CI
        };
        block_on(async {
            let first = Op::create(id(1), id(0), "a", NodeKind::File, 1, Some(b"k1".to_vec()));
            stage_op(&store, &profile, &first, Some(b"seven!!"))
                .await
                .unwrap(); // 7 bytes
            // 7 + 5 = 12 > 10: the second upload fails fast.
            let second = Op::create(id(2), id(0), "b", NodeKind::File, 1, Some(b"k2".to_vec()));
            let out = stage_op(&store, &profile, &second, Some(b"fifty"))
                .await
                .unwrap();
            assert!(matches!(out, StageOutcome::RejectedOverBudget { .. }));
        });
    }

    #[test]
    fn content_op_without_bytes_fails_closed_and_queues_nothing() {
        let store = InMemoryStagingStore::default();
        let profile = SyncTimingProfile {
            staging_budget_bytes: 1024,
            ..SyncTimingProfile::CI
        };
        block_on(async {
            // A Create carrying a staging key but no upload bytes — a broken
            // caller contract that must never journal a dangling content op.
            let op = Op::create(id(1), id(0), "f", NodeKind::File, 1, Some(b"key".to_vec()));
            let result = stage_op(&store, &profile, &op, None).await;
            assert!(result.is_err(), "content op with no bytes fails closed");
            assert!(
                store.queued_ops().await.unwrap().is_empty(),
                "nothing enqueued on the reject path"
            );
        });
    }

    #[test]
    fn undecodable_queue_entry_makes_orphan_gc_conservative() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            // An undecodable/forward-version queue entry whose staging key is
            // unknowable (its staged bytes are preserved by the dead-letter path).
            store.enqueue_op(b"not a valid op").await.unwrap();
            // A staged blob a naive scan would class as an orphan.
            store
                .put_staged_bytes(b"maybe-orphan", b"stale")
                .await
                .unwrap();

            let orphans = orphan_staging_keys(&store).await.unwrap();
            assert!(
                orphans.is_empty(),
                "an undecodable entry forbids classing anything an orphan"
            );
        });
    }

    #[test]
    fn orphan_keys_are_the_unreferenced_staged_bytes() {
        let store = InMemoryStagingStore::default();
        let profile = SyncTimingProfile {
            staging_budget_bytes: 1 << 20,
            ..SyncTimingProfile::CI
        };
        block_on(async {
            let op = Op::create(id(1), id(0), "f", NodeKind::File, 1, Some(b"live".to_vec()));
            stage_op(&store, &profile, &op, Some(b"data"))
                .await
                .unwrap();
            // A staged blob no op references (a rejected/superseded upload residue).
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            let orphans = orphan_staging_keys(&store).await.unwrap();
            assert_eq!(orphans, vec![b"orphan".to_vec()]);
        });
    }
}
