//! Offline staging behind the [`StagingStore`] seam (blueprint/engine.md "Sync
//! core: Ops"; #33 D6).
//!
//! Web reaches full offline parity: uploads stage into OPFS/IndexedDB behind
//! the storage policy's budget; **past the budget only new uploads fail fast,
//! while metadata ops queue unbounded**. The op queue is the durable divergence
//! and must never be capped — a delete or rename can always be journaled — but
//! staged upload *bytes* are bounded so an offline device cannot exhaust host
//! storage. That bound is admitted whole at `beginWrite`
//! ([`crate::content::StagingLedger`]); this module owns the journal entry and
//! the staged-byte hygiene that outlives it.

use std::collections::{BTreeMap, HashSet};

use cipherbox_core::content::verify_cid;

use crate::content::decode_root;
use crate::facade::WriteHandle;
use crate::seams::{OpId, SeamError, SeamResult, StagingStore};
use crate::sync::drain::{DRAINED_OP_MARK_KEY, OP_ATTEMPTS_KEY, UPLOAD_MARK_KEY};
use crate::sync::op::Op;
use crate::sync::record::{RecordSeal, encode_op_record, record_content_root_cid};

/// Journal one op onto the durable queue, returning its id.
///
/// Metadata ops enqueue unbounded. A content op's blocks were already staged,
/// one staging key per block, by the write handle that framed them
/// ([`ContentWriter`](crate::content::ContentWriter)) under a reservation the
/// admission ledger granted at `beginWrite` — so no budget is consulted here.
/// What this path does establish is the binding the drain depends on: the op's
/// root CID must name bytes the store actually holds and that address to it,
/// or the drain would compare a version's `contentCid` against nothing.
///
/// Fail-closed: a content op whose root is missing or mis-keyed enqueues
/// nothing, so no durable op ever references content that was never staged.
pub async fn stage_op<S: StagingStore>(
    store: &S,
    seal: RecordSeal<'_>,
    op: &Op,
) -> SeamResult<OpId> {
    let record = encode_op_record(seal, op).map_err(|e| SeamError::new(e.to_string()))?;
    if let Some(cid) = op.content_root_cid() {
        let root = store.staged_bytes(cid).await?.ok_or_else(|| {
            SeamError::new("stage_op: content op references a root block the store does not hold")
        })?;
        verify_cid(cid, &root).map_err(|_| {
            SeamError::new("stage_op: staged root block does not address to the op's content root")
        })?;
    }
    store.enqueue_op(&record).await
}

/// The staging key holding the roots of dead-lettered versions whose bytes are
/// **preserved**: the op record that referenced them is gone from the queue, and
/// this record is what keeps orphan GC off them (#853).
///
/// It lives in the staging store for the same reason the drain's other
/// bookkeeping does — the roots and the blocks they name share one durability
/// domain — and [`orphan_staging_keys`] treats it as referenced.
pub const PRESERVED_ROOTS_KEY: &[u8] = b"cipherbox/preserved-roots";

/// The preserved-roots record's format tag. The staging store is shared with
/// whatever build wrote it, so bytes that merely happen to be well-shaped must
/// not parse as roots.
const PRESERVED_FORMAT_V1: u8 = 1;

/// Drop every staged block of one version: the leaves its root manifest lists,
/// in file order, then the root itself.
///
/// Staged bytes are released on exactly three verdicts — the user cancelled the
/// upload, the version is proven unopenable (#818), or its staged root cannot be
/// expanded — and preserved on the fourth, a terminally unrebasable op
/// (blueprint/engine.md; #33 D6). File order keeps the blocks that remain a
/// suffix at every step, which is the invariant the drain's resume reads.
///
/// Best-effort: a failed removal is orphan residue a later GC pass collects.
pub async fn release_version_blocks<S: StagingStore>(store: &S, root_cid: &[u8]) {
    for leaf_cid in version_leaf_cids(store, root_cid).await {
        let _ = store.remove_staged_bytes(&leaf_cid).await;
    }
    let _ = store.remove_staged_bytes(root_cid).await;
}

/// The leaves a staged root manifest lists, in file order. Empty when the root
/// is gone, fails its own CID, or does not decode — every caller is a
/// reconciliation path that must still make progress on a store that has lost
/// bytes.
pub async fn version_leaf_cids<S: StagingStore>(store: &S, root_cid: &[u8]) -> Vec<Vec<u8>> {
    let Ok(Some(block)) = store.staged_bytes(root_cid).await else {
        return Vec::new();
    };
    if verify_cid(root_cid, &block).is_err() {
        return Vec::new();
    }
    decode_root(&block).map(|m| m.leaf_cids).unwrap_or_default()
}

/// Record `root_cid` as a preserved dead letter, so orphan GC keeps its blocks
/// once the op that referenced them leaves the durable queue.
///
/// Fails closed on a preserved record this build cannot read: overwriting it
/// would drop the roots it already names, and those blocks are exactly what the
/// dead-letter contract promises to keep.
pub async fn preserve_staged_root<S: StagingStore>(store: &S, root_cid: &[u8]) -> SeamResult<()> {
    let mut roots = read_preserved_roots(store)
        .await?
        .ok_or_else(|| SeamError::new("preserve_staged_root: unreadable preserved-roots record"))?;
    if roots.iter().any(|root| root == root_cid) {
        return Ok(());
    }
    roots.push(root_cid.to_vec());
    write_preserved_roots(store, &roots).await
}

/// The preserved roots the store holds. `None` when the record is present but
/// not one this build wrote — the fail-safe direction is to preserve, so a
/// caller must freeze rather than treat it as empty.
async fn read_preserved_roots<S: StagingStore>(store: &S) -> SeamResult<Option<Vec<Vec<u8>>>> {
    let Some(stored) = store.staged_bytes(PRESERVED_ROOTS_KEY).await? else {
        return Ok(Some(Vec::new()));
    };
    let Some(mut rest) = stored.strip_prefix(&[PRESERVED_FORMAT_V1]) else {
        return Ok(None);
    };
    let mut roots = Vec::new();
    while let Some((&len, tail)) = rest.split_first() {
        let Some((cid, next)) = tail.split_at_checked(len as usize) else {
            return Ok(None);
        };
        roots.push(cid.to_vec());
        rest = next;
    }
    Ok(Some(roots))
}

/// Fails closed on a root too long to length-prefix: writing a truncated record
/// would silently unpin every root behind it (AGENTS.md rule 8).
///
/// An empty list removes the key rather than storing a tag-only record, so a
/// device that has never dead-lettered spends no staging budget on this.
async fn write_preserved_roots<S: StagingStore>(store: &S, roots: &[Vec<u8>]) -> SeamResult<()> {
    if roots.is_empty() {
        return store.remove_staged_bytes(PRESERVED_ROOTS_KEY).await;
    }
    let mut bytes = vec![PRESERVED_FORMAT_V1];
    for root in roots {
        let len = u8::try_from(root.len())
            .map_err(|_| SeamError::new("preserved root is not length-prefixable"))?;
        bytes.push(len);
        bytes.extend_from_slice(root);
    }
    store.put_staged_bytes(PRESERVED_ROOTS_KEY, &bytes).await
}

/// The staging keys write handles hold outside the durable queue.
///
/// A handle stages every block under its own content address before any op
/// references it, so nothing in the queue can vouch for those blocks and orphan
/// GC would otherwise collect a version mid-write. The handle records each key
/// here **before** the bytes are staged, and keeps them until its op is
/// journaled or its blocks are released.
#[derive(Default)]
pub(crate) struct LiveBlocks {
    by_handle: BTreeMap<WriteHandle, Vec<Vec<u8>>>,
    /// Handles opened so far — the handle-id source, and the evidence a GC sweep
    /// reads to tell that no handle opened while it was running.
    opened: u64,
}

impl LiveBlocks {
    /// Mint the next handle and start holding its staging keys.
    pub(crate) fn open(&mut self) -> WriteHandle {
        self.opened += 1;
        let handle = WriteHandle(self.opened);
        self.by_handle.insert(handle, Vec::new());
        handle
    }

    /// Hold one more staging key for `handle`, before its bytes are staged.
    pub(crate) fn record(&mut self, handle: WriteHandle, key: &[u8]) {
        if let Some(keys) = self.by_handle.get_mut(&handle) {
            keys.push(key.to_vec());
        }
    }

    /// Stop holding `handle`'s keys, returning them so a caller that is
    /// abandoning the write can release the blocks.
    pub(crate) fn close(&mut self, handle: WriteHandle) -> Vec<Vec<u8>> {
        self.by_handle.remove(&handle).unwrap_or_default()
    }

    /// Every key currently held, across all open handles.
    pub(crate) fn keys(&self) -> Vec<Vec<u8>> {
        self.by_handle.values().flatten().cloned().collect()
    }

    /// How many handles have ever been opened.
    pub(crate) fn opened(&self) -> u64 {
        self.opened
    }
}

/// One orphan-GC pass: expand every staged root into its leaf set and remove the
/// blocks nothing references (#828). Runs at cold start and after each drain
/// pass.
///
/// Best-effort throughout — a store that cannot enumerate or remove leaves its
/// residue for the next pass — and it also prunes [`PRESERVED_ROOTS_KEY`] of
/// roots whose bytes are already gone, so that record cannot grow without bound.
pub(crate) async fn collect_orphans<S: StagingStore>(
    store: &S,
    live: &core::cell::RefCell<LiveBlocks>,
) {
    let opened_before = live.borrow().opened();
    let live_keys = live.borrow().keys();
    let Ok(orphans) = orphan_staging_keys(store, &live_keys).await else {
        return;
    };
    for key in orphans {
        // A handle opened after the scan may be staging exactly these bytes.
        if live.borrow().opened() != opened_before {
            return;
        }
        let _ = store.remove_staged_bytes(&key).await;
    }
    prune_preserved_roots(store).await;
}

/// Drop preserved roots whose blocks the store no longer holds.
async fn prune_preserved_roots<S: StagingStore>(store: &S) {
    let Ok(Some(roots)) = read_preserved_roots(store).await else {
        return;
    };
    let mut live = Vec::with_capacity(roots.len());
    for root in &roots {
        if matches!(store.staged_bytes(root).await, Ok(Some(_))) {
            live.push(root.clone());
        }
    }
    // An unchanged record is not rewritten, so an idle sweep makes no store
    // write.
    if live.len() != roots.len() {
        let _ = write_preserved_roots(store, &live).await;
    }
}

/// Staging keys held by the store that nothing references — orphan residue from
/// a superseded or abandoned upload, safe to GC (#33 D6 staged-bytes hygiene).
///
/// Three things reference a block. A **queued record**'s content root rides its
/// clear header, and since a version stages one block per key, a root is
/// expanded into the leaf keys its own manifest lists — so a foreign account's
/// or a forward-version record's whole block set is retained. A **preserved
/// dead letter**'s root is expanded the same way, which is what keeps the bytes
/// the dead-letter contract promises once its op record is gone (#853). An
/// **open write handle**'s blocks are staged before any op is journaled, so they
/// are unreferenced by construction and must be passed in as `live`; collecting
/// them mid-write would publish a version whose manifest names blocks nothing
/// holds.
///
/// Fail-closed: an unreadable queue entry, an unreadable preserved-roots record,
/// or a referenced root the store cannot produce or this build cannot decode,
/// classes **nothing** an orphan. A root that cannot be expanded therefore
/// freezes the whole pass — self-clearing, because the drain classifies that
/// same root permanent and releases the version.
pub async fn orphan_staging_keys<S: StagingStore>(
    store: &S,
    live: &[Vec<u8>],
) -> SeamResult<Vec<Vec<u8>>> {
    let queued = store.queued_ops().await?;
    // The drain's own queue bookkeeping is not upload residue.
    let mut referenced = HashSet::from([
        DRAINED_OP_MARK_KEY.to_vec(),
        OP_ATTEMPTS_KEY.to_vec(),
        UPLOAD_MARK_KEY.to_vec(),
        PRESERVED_ROOTS_KEY.to_vec(),
    ]);
    referenced.extend(live.iter().cloned());
    let Some(preserved) = read_preserved_roots(store).await? else {
        return Ok(Vec::new());
    };
    let mut roots = preserved;
    for (_, record) in &queued {
        let Ok(root) = record_content_root_cid(record) else {
            // An unreadable record may still reference staged bytes, and its
            // root is unknowable.
            return Ok(Vec::new());
        };
        if let Some(root) = root {
            roots.push(root);
        }
    }
    for root in roots {
        // The drain removes each block as it uploads, so a root whose bytes are
        // gone is a finished upload with nothing left to expand.
        if let Some(block) = store.staged_bytes(&root).await? {
            let Ok(manifest) = decode_root(&block) else {
                return Ok(Vec::new());
            };
            referenced.extend(manifest.leaf_cids);
        }
        referenced.insert(root);
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
    use crate::content::SealedChunk;
    use crate::facade::NodeId;
    use crate::seams::UnixMillis;
    use crate::sync::op::{NewNode, StagedContent};
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{block_on, frame_version};
    use cipherbox_core::suite::aead::KEY_LEN;
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

    /// A framed version plus the op's staged-content reference to it.
    fn framed(plaintext: &[u8]) -> (Vec<SealedChunk>, Vec<u8>, StagedContent) {
        let (blocks, root_block, content) = frame_version(plaintext, [9u8; KEY_LEN], 1);
        let staged = StagedContent {
            root_cid: content.content_cid().to_vec(),
            plaintext_size: content.size(),
            sealed_content_key: b"sealed-key-blob".to_vec(),
            epoch: 1,
        };
        (blocks, root_block, staged)
    }

    /// Stage every block of a version, the way a write handle does.
    async fn put_blocks<S: StagingStore>(
        store: &S,
        blocks: &[SealedChunk],
        root_block: &[u8],
        staged: &StagedContent,
    ) {
        for block in blocks {
            store
                .put_staged_bytes(&block.cid, &block.sealed)
                .await
                .unwrap();
        }
        store
            .put_staged_bytes(&staged.root_cid, root_block)
            .await
            .unwrap();
    }

    fn content_op(node: u8, staged: StagedContent) -> Op {
        Op::create(
            id(node),
            id(0),
            "f",
            NewNode::File {
                content: Some(staged),
            },
            1,
            UnixMillis(1),
        )
    }

    #[test]
    fn metadata_ops_queue_unbounded() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            for i in 0..5 {
                let op = Op::rename(id(i), "n", 1, UnixMillis(1));
                stage_op(&store, seal(i), &op).await.unwrap();
            }
            assert_eq!(store.queued_ops().await.unwrap().len(), 5);
        });
    }

    #[test]
    fn a_content_op_enqueues_once_its_root_block_is_staged() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            stage_op(&store, seal(1), &content_op(1, staged.clone()))
                .await
                .unwrap();
            assert_eq!(store.queued_ops().await.unwrap().len(), 1);
            assert_eq!(
                store.staged_keys().await.unwrap().len(),
                blocks.len() + 1,
                "one staging key per block, root included"
            );
        });
    }

    #[test]
    fn a_content_op_whose_root_is_not_staged_fails_closed_and_queues_nothing() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (_, _, staged) = framed(b"content");
            assert!(
                stage_op(&store, seal(1), &content_op(1, staged))
                    .await
                    .is_err(),
                "journaling it would leave a durable op referencing nothing"
            );
            assert!(store.queued_ops().await.unwrap().is_empty());
        });
    }

    /// The leaf gate is the drain's, not this one's: staging is mutable between
    /// the journal entry and the upload, so a leaf sweep here would pass and
    /// still leave the drain re-reading every block. It re-verifies each leaf's
    /// CID as it uploads and dead-letters an absence past the durable mark
    /// (`crate::sync::drain`), which is the check that can actually hold.
    #[test]
    fn a_missing_leaf_still_enqueues_because_the_drain_owns_that_gate() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            store.remove_staged_bytes(&blocks[0].cid).await.unwrap();

            stage_op(&store, seal(1), &content_op(1, staged.clone()))
                .await
                .expect("the root is what this gate binds");
            assert_eq!(store.queued_ops().await.unwrap().len(), 1);
        });
    }

    #[test]
    fn a_root_block_that_does_not_address_to_the_ops_root_fails_closed() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            // The op names one root; the store holds different bytes under that
            // key, which would make the drain's compare-not-recompute a lie.
            let (_, _, staged) = framed(b"declared");
            store
                .put_staged_bytes(&staged.root_cid, b"delivered")
                .await
                .unwrap();
            assert!(
                stage_op(&store, seal(1), &content_op(1, staged))
                    .await
                    .is_err()
            );
            assert!(store.queued_ops().await.unwrap().is_empty());
        });
    }

    #[test]
    fn an_unreadable_queue_entry_makes_orphan_gc_conservative() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            // A corrupt queue entry whose root CID is unknowable (its staged
            // bytes are preserved by the dead-letter path).
            store.enqueue_op(b"not a valid record").await.unwrap();
            store
                .put_staged_bytes(b"maybe-orphan", b"stale")
                .await
                .unwrap();

            assert!(
                orphan_staging_keys(&store, &[]).await.unwrap().is_empty(),
                "an unreadable entry forbids classing anything an orphan"
            );
        });
    }

    /// Collecting the drain's completion mark would let a restored queue replay
    /// ops that already published (#860), so it is never orphan residue.
    #[test]
    fn the_drains_own_bookkeeping_is_never_classed_an_orphan() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            store
                .put_staged_bytes(DRAINED_OP_MARK_KEY, &7u64.to_be_bytes())
                .await
                .unwrap();
            store
                .put_staged_bytes(OP_ATTEMPTS_KEY, &[0u8; 12])
                .await
                .unwrap();

            assert!(orphan_staging_keys(&store, &[]).await.unwrap().is_empty());
        });
    }

    /// A version stages one block per key and only the root rides the op's clear
    /// header, so GC must expand the root's manifest — collecting a queued
    /// upload's leaves would publish an unreadable version.
    #[test]
    fn a_queued_uploads_leaves_are_referenced_through_its_root() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            assert!(blocks.len() > 1, "the fixture must be multi-leaf");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            stage_op(&store, seal(1), &content_op(1, staged))
                .await
                .unwrap();
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert_eq!(
                orphan_staging_keys(&store, &[]).await.unwrap(),
                vec![b"orphan".to_vec()],
                "every leaf the root lists is referenced"
            );
        });
    }

    /// A write handle's leaves are staged before any op is journaled, so nothing
    /// in the queue references them — collecting them mid-write would publish a
    /// version whose manifest names blocks nothing holds.
    #[test]
    fn an_open_write_handles_blocks_are_never_collected() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();
            let live: Vec<Vec<u8>> = blocks.iter().map(|block| block.cid.clone()).collect();

            assert_eq!(
                orphan_staging_keys(&store, &live).await.unwrap(),
                vec![staged.root_cid.clone(), b"orphan".to_vec()],
                "the handle's leaves are held; its uncommitted root is not yet referenced"
            );
            assert!(
                orphan_staging_keys(&store, &[]).await.unwrap().len() > live.len(),
                "without the live set every one of them would be collected"
            );
        });
    }

    #[test]
    fn a_foreign_records_whole_block_set_is_never_collected() {
        let store = InMemoryStagingStore::default();
        let stranger = X25519Secret::from_scalar([7; 32]);
        block_on(async {
            let (blocks, root_block, staged) = framed(b"their forty bytes of content ------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            let foreign = encode_op_record(
                RecordSeal {
                    owner_enc_secret: &stranger,
                    ephemeral_scalar: Zeroizing::new([3; 32]),
                },
                &content_op(1, staged),
            )
            .unwrap();
            store.enqueue_op(&foreign).await.unwrap();
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert_eq!(
                orphan_staging_keys(&store, &[]).await.unwrap(),
                vec![b"orphan".to_vec()],
                "a foreign root and its leaves are referenced, not collectible"
            );
        });
    }

    #[test]
    fn a_forward_version_records_block_set_is_never_collected() {
        use cipherbox_core::codec::{Value, decode, encode};

        let store = InMemoryStagingStore::default();
        block_on(async {
            // A record written by a newer build on this device. Its clear header
            // is still readable — the framing is frozen across versions — so GC
            // pins its blocks instead of reclaiming them under the owner.
            let (blocks, root_block, staged) = framed(b"their forty bytes of content ------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            let record = encode_op_record(seal(4), &content_op(1, staged)).unwrap();
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
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert_eq!(
                orphan_staging_keys(&store, &[]).await.unwrap(),
                vec![b"orphan".to_vec()],
                "a retained record's blocks are referenced, not collectible"
            );
        });
    }

    /// The dead-letter contract keeps a terminally unrebasable op's staged
    /// bytes, but the abandonment removes its op record — so without a second
    /// reference source GC reclaims exactly what was promised (#853).
    #[test]
    fn a_preserved_dead_letters_block_set_is_never_collected() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            preserve_staged_root(&store, &staged.root_cid)
                .await
                .unwrap();
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert_eq!(
                orphan_staging_keys(&store, &[]).await.unwrap(),
                vec![b"orphan".to_vec()],
                "the preserved root and every leaf it lists stay referenced"
            );
        });
    }

    /// The fail-safe direction here is to preserve, so a preserved-roots record
    /// this build cannot read must freeze the pass rather than read as empty.
    #[test]
    fn an_unreadable_preserved_roots_record_makes_orphan_gc_conservative() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            store
                .put_staged_bytes(PRESERVED_ROOTS_KEY, b"not a preserved-roots record")
                .await
                .unwrap();
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert!(orphan_staging_keys(&store, &[]).await.unwrap().is_empty());
            assert!(
                preserve_staged_root(&store, b"root").await.is_err(),
                "overwriting it would drop the roots it already names"
            );
        });
    }

    #[test]
    fn preserved_roots_round_trip_and_prune_to_the_blocks_the_store_still_holds() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            preserve_staged_root(&store, &staged.root_cid)
                .await
                .unwrap();
            preserve_staged_root(&store, b"gone").await.unwrap();
            assert_eq!(
                read_preserved_roots(&store).await.unwrap().unwrap(),
                vec![staged.root_cid.clone(), b"gone".to_vec()]
            );

            prune_preserved_roots(&store).await;
            assert_eq!(
                read_preserved_roots(&store).await.unwrap().unwrap(),
                vec![staged.root_cid.clone()],
                "a root whose blocks are gone preserves nothing"
            );

            release_version_blocks(&store, &staged.root_cid).await;
            prune_preserved_roots(&store).await;
            assert!(
                store
                    .staged_bytes(PRESERVED_ROOTS_KEY)
                    .await
                    .unwrap()
                    .is_none(),
                "an empty list spends no staging budget"
            );
        });
    }

    /// A release drops the whole set — every leaf the manifest lists, then the
    /// root — so an abandoned version holds no budget.
    #[test]
    fn releasing_a_version_drops_every_block_of_it() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            store.put_staged_bytes(b"other", b"kept").await.unwrap();

            release_version_blocks(&store, &staged.root_cid).await;
            assert_eq!(
                store.staged_keys().await.unwrap(),
                vec![b"other".to_vec()],
                "the version's whole block set goes, and nothing else"
            );
        });
    }

    /// A referenced root this build cannot decode hides an unknowable leaf set,
    /// so nothing may be classed an orphan against it.
    #[test]
    fn an_undecodable_referenced_root_makes_orphan_gc_conservative() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (_, _, staged) = framed(b"content");
            // Bytes that address to the op's root but are not a root manifest.
            let cid = cipherbox_core::content::compute_cid(
                crate::content::DAG_ROOT_CODEC,
                b"not a root manifest",
            );
            let staged = StagedContent {
                root_cid: cid.clone(),
                ..staged
            };
            store
                .put_staged_bytes(&cid, b"not a root manifest")
                .await
                .unwrap();
            stage_op(&store, seal(1), &content_op(1, staged))
                .await
                .unwrap();
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert!(orphan_staging_keys(&store, &[]).await.unwrap().is_empty());
        });
    }
}
