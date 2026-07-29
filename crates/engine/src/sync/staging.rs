//! Budgeted offline staging behind the [`StagingStore`] seam (blueprint/
//! engine.md "Sync core: Ops"; #33 D6).
//!
//! Web reaches full offline parity: uploads stage into OPFS/IndexedDB behind
//! the storage policy's budget; **past the budget only new uploads fail fast,
//! while metadata ops queue unbounded**. The op queue is the durable divergence
//! and must never be capped — a delete or rename can always be journaled — but
//! staged upload *bytes* are bounded so an offline device cannot exhaust host
//! storage.

use cipherbox_core::content::verify_cid;

use crate::seams::{OpId, SeamError, SeamResult, StagingStore};
use crate::storage_policy::{Headroom, StoragePolicy};
use crate::sync::drain::DRAINED_OP_MARK_KEY;
use crate::sync::op::Op;
use crate::sync::record::{RecordSeal, encode_op_record, record_content_root_cid};

/// The outcome of staging one op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    /// The op was journaled; on a content op its bytes were staged too.
    Queued {
        /// The durable op-queue id.
        op_id: OpId,
    },
    /// A content upload would exceed the staging budget: it fails fast and
    /// **nothing** is journaled or staged (the mutation did not happen).
    RejectedOverBudget {
        /// Staged bytes already held.
        staged: u64,
        /// The upload's own byte length.
        incoming: u64,
        /// The policy budget.
        budget: u64,
    },
    /// The host could not measure storage headroom, so no upload can be
    /// admitted. Distinct from [`Self::RejectedOverBudget`] at zero: nothing is
    /// known about this device's storage, rather than known to be full.
    RejectedStorageUnmeasured {
        /// The upload's own byte length.
        incoming: u64,
    },
}

/// Stage one op. Metadata ops (no upload bytes) always enqueue, regardless of
/// budget. A content op is fail-fast: if staged-total + its bytes would exceed
/// the budget, nothing is written; otherwise the bytes are staged under the
/// op's content root CID and the sealed record is enqueued.
///
/// `upload` is the **already-sealed** content payload (core's content-seal runs
/// upstream in the content plane); no plaintext user content ever lands in the
/// staging store at rest. It must content-address to the op's root CID.
///
/// Fail-fast ordering: the budget is checked and the bytes staged **before**
/// the record is enqueued, so a rejected upload leaves no dangling queue entry
/// and an accepted one leaves no op referencing unstaged bytes.
pub async fn stage_op<S: StagingStore>(
    store: &S,
    policy: &StoragePolicy,
    seal: RecordSeal<'_>,
    op: &Op,
    upload: Option<&[u8]>,
) -> SeamResult<StageOutcome> {
    let record = encode_op_record(seal, op).map_err(|e| SeamError::new(e.to_string()))?;
    match (op.content_root_cid(), upload) {
        (Some(cid), Some(bytes)) => {
            let incoming = bytes.len() as u64;
            if policy.headroom == Headroom::Unmeasured {
                return Ok(StageOutcome::RejectedStorageUnmeasured { incoming });
            }
            let staged = store.staged_bytes_total().await?;
            // Saturating: an overflowing sum is unreachable under any real
            // budget, and must still read as "over budget", never wrap to a
            // spuriously-small total.
            if staged.saturating_add(incoming) > policy.staging_budget_bytes {
                return Ok(StageOutcome::RejectedOverBudget {
                    staged,
                    incoming,
                    budget: policy.staging_budget_bytes,
                });
            }
            // The staging key *is* the block's content address, which is what
            // lets the drain compare the op's root against the version's
            // contentCid instead of recomputing it. Establish that binding
            // before anything is written, or the comparison is vacuous.
            verify_cid(cid, bytes).map_err(|_| {
                SeamError::new("stage_op: staged bytes do not address to the op's content root CID")
            })?;
            store.put_staged_bytes(cid, bytes).await?;
            let op_id = store.enqueue_op(&record).await?;
            Ok(StageOutcome::Queued { op_id })
        }
        // A content op (root CID present) with no bytes is a broken caller
        // contract: journaling it would leave a durable op referencing content
        // that was never staged. Fail closed — enqueue nothing.
        (Some(_), None) => Err(SeamError::new(
            "stage_op: content op carries a content root CID but no upload bytes",
        )),
        // Bytes with no root to key them by: the mirror of the arm above, and
        // the same broken caller contract. Staging them would leave residue no
        // op references; dropping them would silently lose a user's upload.
        (None, Some(_)) => Err(SeamError::new(
            "stage_op: upload bytes with no content root CID on the op",
        )),
        // A metadata op: journal unbounded.
        (None, None) => {
            let op_id = store.enqueue_op(&record).await?;
            Ok(StageOutcome::Queued { op_id })
        }
    }
}

/// Staging keys held by the store that no queued record references — orphan
/// residue from a rejected or superseded upload, safe to GC (#33 D6 staged-
/// bytes hygiene).
///
/// Keyless: a queued record's content root rides its clear header, so a foreign
/// account's staged bytes are counted as referenced rather than collected.
pub async fn orphan_staging_keys<S: StagingStore>(store: &S) -> SeamResult<Vec<Vec<u8>>> {
    let queued = store.queued_ops().await?;
    // The drain's completion mark is queue bookkeeping under a staging key, not
    // upload residue.
    let mut referenced = std::collections::HashSet::from([DRAINED_OP_MARK_KEY.to_vec()]);
    for (_, record) in &queued {
        match record_content_root_cid(record) {
            Ok(Some(cid)) => {
                referenced.insert(cid);
            }
            Ok(None) => {}
            // An unreadable record may still reference staged bytes, and its
            // root is unknowable — fail closed and class nothing an orphan.
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
    use crate::seams::UnixMillis;
    use crate::sync::op::StagedContent;
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryStagingStore;
    use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};
    use cipherbox_core::suite::x25519::X25519Secret;
    use std::sync::LazyLock;
    use zeroize::Zeroizing;

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    static OWNER: LazyLock<X25519Secret> = LazyLock::new(|| X25519Secret::from_scalar([42; 32]));

    fn seal(scalar: u8) -> RecordSeal<'static> {
        RecordSeal {
            owner_enc_secret: &OWNER,
            ephemeral_scalar: Zeroizing::new([scalar; 32]),
        }
    }

    /// The content address staged bytes must be keyed by.
    fn cid(bytes: &[u8]) -> Vec<u8> {
        compute_cid(CONTENT_CID_CODEC, bytes)
    }

    fn budget(bytes: u64) -> StoragePolicy {
        StoragePolicy {
            staging_budget_bytes: bytes,
            ..StoragePolicy::CI
        }
    }

    /// A content create whose root CID addresses the bytes it will stage.
    fn content_op(node: u8, upload: &[u8]) -> Op {
        Op::create(
            id(node),
            id(0),
            "f",
            NodeKind::File,
            1,
            UnixMillis(1),
            Some(StagedContent {
                root_cid: cid(upload),
                plaintext_size: upload.len() as u64,
            }),
        )
    }

    #[test]
    fn metadata_ops_queue_unbounded_past_the_budget() {
        let store = InMemoryStagingStore::default();
        // A budget of zero: no upload byte fits, yet metadata must still queue.
        block_on(async {
            for i in 0..5 {
                let op = Op::rename(id(i), "n", 1, UnixMillis(1));
                let out = stage_op(&store, &budget(0), seal(i), &op, None)
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
        block_on(async {
            let op = content_op(1, b"nine bytes");
            let out = stage_op(&store, &budget(8), seal(1), &op, Some(b"nine bytes"))
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
    fn an_unmeasurable_host_rejects_uploads_distinguishably_from_a_full_one() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let op = content_op(1, b"bytes");
            let out = stage_op(
                &store,
                &StoragePolicy::UNMEASURED,
                seal(1),
                &op,
                Some(b"bytes"),
            )
            .await
            .unwrap();
            assert_eq!(
                out,
                StageOutcome::RejectedStorageUnmeasured { incoming: 5 },
                "an unmeasurable device must not be reported as a full one"
            );
            assert!(store.queued_ops().await.unwrap().is_empty());
            assert_eq!(store.staged_bytes_total().await.unwrap(), 0);
        });
    }

    #[test]
    fn metadata_ops_still_queue_on_an_unmeasurable_host() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            // The op queue is the durable divergence and is never capped —
            // unmeasurable storage bounds uploads, not intent.
            let op = Op::rename(id(1), "n", 1, UnixMillis(1));
            let out = stage_op(&store, &StoragePolicy::UNMEASURED, seal(1), &op, None)
                .await
                .unwrap();
            assert!(matches!(out, StageOutcome::Queued { .. }));
        });
    }

    #[test]
    fn upload_within_budget_stages_bytes_under_the_content_root_cid() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let op = content_op(1, b"content");
            let out = stage_op(&store, &budget(1024), seal(1), &op, Some(b"content"))
                .await
                .unwrap();
            assert!(matches!(out, StageOutcome::Queued { .. }));
            assert_eq!(
                store.staged_bytes(&cid(b"content")).await.unwrap(),
                Some(b"content".to_vec()),
                "the staging key is the root's content address"
            );
            assert_eq!(store.queued_ops().await.unwrap().len(), 1);
        });
    }

    #[test]
    fn budget_counts_cumulative_staged_bytes() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            stage_op(
                &store,
                &budget(10),
                seal(1),
                &content_op(1, b"seven!!"),
                Some(b"seven!!"),
            )
            .await
            .unwrap(); // 7 bytes
            // 7 + 5 = 12 > 10: the second upload fails fast.
            let out = stage_op(
                &store,
                &budget(10),
                seal(2),
                &content_op(2, b"fifty"),
                Some(b"fifty"),
            )
            .await
            .unwrap();
            assert!(matches!(out, StageOutcome::RejectedOverBudget { .. }));
        });
    }

    #[test]
    fn metadata_op_with_stray_bytes_fails_closed_and_queues_nothing() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let op = Op::rename(id(1), "n", 1, UnixMillis(1));
            let result = stage_op(&store, &budget(1024), seal(1), &op, Some(b"bytes")).await;
            assert!(result.is_err(), "bytes with no root to key them by");
            assert!(store.queued_ops().await.unwrap().is_empty());
            assert_eq!(store.staged_bytes_total().await.unwrap(), 0);
        });
    }

    #[test]
    fn content_op_without_bytes_fails_closed_and_queues_nothing() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            // A Create carrying a root CID but no upload bytes — a broken
            // caller contract that must never journal a dangling content op.
            let result = stage_op(&store, &budget(1024), seal(1), &content_op(1, b"x"), None).await;
            assert!(result.is_err(), "content op with no bytes fails closed");
            assert!(
                store.queued_ops().await.unwrap().is_empty(),
                "nothing enqueued on the reject path"
            );
        });
    }

    #[test]
    fn upload_bytes_that_do_not_address_to_the_root_cid_fail_closed() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            // The op names one root; the caller hands over different bytes.
            // Staging them would make the drain's compare-not-recompute
            // contract a lie, so nothing is written.
            let op = content_op(1, b"declared");
            let result = stage_op(&store, &budget(1024), seal(1), &op, Some(b"delivered")).await;
            assert!(result.is_err(), "a mis-keyed upload fails closed");
            assert!(store.queued_ops().await.unwrap().is_empty());
            assert_eq!(store.staged_bytes_total().await.unwrap(), 0);
        });
    }

    #[test]
    fn an_unreadable_queue_entry_makes_orphan_gc_conservative() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            // A corrupt/forward-version queue entry whose root CID is
            // unknowable (its staged bytes are preserved by the dead-letter path).
            store.enqueue_op(b"not a valid record").await.unwrap();
            // A staged blob a naive scan would class as an orphan.
            store
                .put_staged_bytes(b"maybe-orphan", b"stale")
                .await
                .unwrap();

            let orphans = orphan_staging_keys(&store).await.unwrap();
            assert!(
                orphans.is_empty(),
                "an unreadable entry forbids classing anything an orphan"
            );
        });
    }

    /// Collecting the drain's completion mark would let a restored queue replay
    /// ops that already published (#860), so it is never orphan residue.
    #[test]
    fn the_drained_op_mark_is_never_classed_an_orphan() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            store
                .put_staged_bytes(DRAINED_OP_MARK_KEY, &7u64.to_be_bytes())
                .await
                .unwrap();

            assert!(orphan_staging_keys(&store).await.unwrap().is_empty());
        });
    }

    #[test]
    fn orphan_keys_are_the_unreferenced_staged_bytes() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            stage_op(
                &store,
                &budget(1 << 20),
                seal(1),
                &content_op(1, b"data"),
                Some(b"data"),
            )
            .await
            .unwrap();
            // A staged blob no op references (a rejected/superseded upload residue).
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            let orphans = orphan_staging_keys(&store).await.unwrap();
            assert_eq!(orphans, vec![b"orphan".to_vec()]);
        });
    }

    #[test]
    fn a_foreign_records_staged_root_is_never_collected() {
        let store = InMemoryStagingStore::default();
        let stranger = X25519Secret::from_scalar([7; 32]);
        block_on(async {
            let foreign = encode_op_record(
                RecordSeal {
                    owner_enc_secret: &stranger,
                    ephemeral_scalar: Zeroizing::new([3; 32]),
                },
                &content_op(1, b"their bytes"),
            )
            .unwrap();
            store.enqueue_op(&foreign).await.unwrap();
            store
                .put_staged_bytes(&cid(b"their bytes"), b"their bytes")
                .await
                .unwrap();
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert_eq!(
                orphan_staging_keys(&store).await.unwrap(),
                vec![b"orphan".to_vec()],
                "a foreign root is referenced, not collectible"
            );
        });
    }

    #[test]
    fn a_forward_version_records_staged_root_is_never_collected() {
        use cipherbox_core::codec::{Value, decode, encode};

        let store = InMemoryStagingStore::default();
        block_on(async {
            // A record written by a newer build on this device. Its clear
            // header is still readable — the framing is frozen across versions
            // — so GC pins its root instead of reclaiming it under the owner.
            let record = encode_op_record(seal(4), &content_op(1, b"their bytes")).unwrap();
            let value = decode(&record).unwrap();
            let mut map = value.as_map().unwrap().clone();
            map.insert(
                "v",
                Value::Unsigned(cipherbox_core::seal::op_record::OP_RECORD_V + 1),
            );
            store
                .enqueue_op(&encode(&Value::Map(map)).unwrap())
                .await
                .unwrap();
            store
                .put_staged_bytes(&cid(b"their bytes"), b"their bytes")
                .await
                .unwrap();
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert_eq!(
                orphan_staging_keys(&store).await.unwrap(),
                vec![b"orphan".to_vec()],
                "a retained record's root is referenced, not collectible"
            );
        });
    }
}
