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
//!
//! One rule decides a staged version's fate, and it lives here: **preserved when
//! the engine gave up on the op, released when the user did**. Preserved on a
//! terminally unrebasable dead letter ([`preserve_dead_letter`]); released on a
//! cancel, on a version proven unopenable, and on a staged root that cannot be
//! expanded ([`release_version_blocks`]).

use std::collections::{BTreeMap, HashSet};

use cipherbox_core::content::verify_cid;

use crate::content::chunk::SEALED_LEAF_OVERHEAD;
use crate::content::dag::RootManifest;
use crate::content::decode_root;
use crate::facade::WriteHandle;
use crate::grants::{CONTACTS_PREFIX, INVITE_RECORDS_PREFIX, RECEIVED_SHARES_PREFIX};
use crate::net::RETIRE_LEDGER_PREFIX;
use crate::seams::{OpId, SeamError, SeamResult, StagingStore};
use crate::sync::drain::{
    DRAINED_OP_MARK_PREFIX, OP_ATTEMPTS_KEY, PUBLISHED_OP_MARK_PREFIX, UPLOAD_MARK_KEY,
};
use crate::sync::op::Op;
use crate::sync::rebase::DeadLetterReason;
use crate::sync::record::{RecordSeal, encode_op_record, record_content_root_cid};

/// Whether `key` is engine bookkeeping rather than upload residue: a
/// per-identity op-id high-water mark
/// ([`owner_scoped_key`](crate::sync::drain::owner_scoped_key)), a retire-ledger entry, a
/// received-shares list, a contact book, or the owner's invite records. All are per-owner, so their whole prefixes are
/// referenced — an entry this session cannot read belongs to the identity that
/// still needs it.
fn is_bookkeeping(key: &[u8]) -> bool {
    key.starts_with(DRAINED_OP_MARK_PREFIX)
        || key.starts_with(PUBLISHED_OP_MARK_PREFIX)
        || key.starts_with(RETIRE_LEDGER_PREFIX)
        || key.starts_with(RECEIVED_SHARES_PREFIX)
        || key.starts_with(CONTACTS_PREFIX)
        || key.starts_with(INVITE_RECORDS_PREFIX)
}

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

/// The staging key holding the **op records** of dead letters whose staged bytes
/// are preserved, `u32`-length-prefixed behind a one-byte format tag.
///
/// It holds the whole record, not just the root CID, because the record is the
/// only carrier of the version's content key — a KDF non-edge nothing can
/// re-derive. Preserving the blocks without it would keep ciphertext no
/// key ever opens, which is the condition that *releases* a version, not the one
/// that preserves it. Orphan GC reads each entry's root keylessly through the
/// same frozen clear header a queue entry exposes ([`record_content_root_cid`]),
/// and treats this key as referenced.
pub(crate) const PRESERVED_DEAD_LETTERS_KEY: &[u8] = b"cipherbox/preserved-dead-letters";

/// The preserved record's format tag. The staging store is shared with whatever
/// build wrote it, so bytes that merely happen to be well-shaped must not parse.
const PRESERVED_FORMAT_V1: u8 = 1;

/// Drop every staged block of one version: the leaves its root manifest lists,
/// in file order, then the root itself. File order keeps the blocks that remain
/// a suffix at every step, which is the invariant the drain's resume reads.
///
/// Best-effort: a failed removal is orphan residue a later GC pass collects.
pub(crate) async fn release_version_blocks<S: StagingStore>(store: &S, root_cid: &[u8]) {
    for leaf_cid in version_leaf_cids(store, root_cid).await {
        let _ = store.remove_staged_bytes(&leaf_cid).await;
    }
    let _ = store.remove_staged_bytes(root_cid).await;
}

/// The leaves a staged root manifest lists, in file order. Empty when the root
/// is gone, fails its own CID, or does not decode — every caller is a
/// reconciliation path that must still make progress on a store that has lost
/// bytes.
pub(crate) async fn version_leaf_cids<S: StagingStore>(store: &S, root_cid: &[u8]) -> Vec<Vec<u8>> {
    let Ok(Some(block)) = store.staged_bytes(root_cid).await else {
        return Vec::new();
    };
    if verify_cid(root_cid, &block).is_err() {
        return Vec::new();
    }
    decode_root(&block)
        .map(|m| m.leaf_cid_vecs())
        .unwrap_or_default()
}

/// How many dead letters may be preserved at once, however small each one is.
///
/// The byte ceiling alone does not bound the record: a thousand tiny versions
/// fit under it while making every orphan-GC pass expand a thousand roots.
const MAX_PRESERVED_DEAD_LETTERS: usize = 16;

/// What became of a dead letter's staged version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Preservation {
    /// The version's root still opens, and its record is held.
    Kept,
    /// The root is gone or no longer addresses to its own CID, so no read path
    /// can ever map the version's blocks. Nothing is held; whatever blocks
    /// linger are referenced by nothing and orphan GC reclaims them.
    ContentGone,
}

impl Preservation {
    /// The reason a member is shown. A version that can no longer be reassembled
    /// is unrecoverable content whatever stopped the op — the alternative is a
    /// notice promising bytes no read path reaches.
    pub(crate) fn observed(self, reason: DeadLetterReason) -> DeadLetterReason {
        match self {
            Self::Kept => reason,
            Self::ContentGone => DeadLetterReason::ContentUnrecoverable,
        }
    }
}

/// Keep one dead letter's op record after it leaves the durable queue, so orphan
/// GC keeps the blocks it names and the version stays openable.
///
/// Preserves only a version whose root still **opens** ([`version_is_openable`]).
/// A root the store cannot produce, or that no longer addresses to its own CID,
/// names blocks nothing can ever map — and the old check, root key present and
/// its bytes untrusted, kept exactly those forever. That is
/// [`Preservation::ContentGone`], reported as
/// [`DeadLetterReason::ContentUnrecoverable`](crate::sync::rebase::DeadLetterReason::ContentUnrecoverable);
/// no record is held, so orphan GC reclaims any blocks left behind.
///
/// Fails closed twice over: on a preserved record this build cannot read, since
/// overwriting it would drop the dead letters it already holds, and on a root it
/// cannot decode, since that record carries the only copy of the content key.
pub(crate) async fn preserve_dead_letter<S: StagingStore>(
    store: &S,
    record: &[u8],
    preserved_budget: u64,
) -> SeamResult<Preservation> {
    // First: an unreadable preserved record freezes this path, and must do so
    // before any verdict a caller would act on.
    let mut kept = read_preserved_dead_letters(store)
        .await?
        .ok_or_else(|| SeamError::new("preserve_dead_letter: unreadable preserved record"))?;
    let root = record_content_root_cid(record)
        .map_err(|_| SeamError::new("preserve_dead_letter: unreadable op record"))?;
    let mut appended_bytes = 0;
    if let Some(root) = &root {
        let Some(bytes) = version_is_openable(store, root).await? else {
            return Ok(Preservation::ContentGone);
        };
        appended_bytes = bytes;
    }
    if kept.iter().any(|held| held == record) {
        return Ok(Preservation::Kept);
    }
    kept.push(record.to_vec());
    evict_over_budget(store, &mut kept, appended_bytes, preserved_budget).await;
    write_preserved_dead_letters(store, &kept).await?;
    Ok(Preservation::Kept)
}

/// Whether `root_cid`'s version is still coherent, given the store's current key
/// set: the leaves it has left form a **suffix** of the manifest.
///
/// The upload loop releases each leaf as it confirms, strictly in file order, so
/// the blocks legitimately gone from a version are always a prefix — a leaf
/// missing from the *middle* was released by nothing and is the condition the
/// loop itself already reads as loss. Such a version can never be reassembled,
/// and keeping it only spends the staging budget forever, since the root's own
/// presence satisfies the prune.
///
/// Whether the version's root still opens, answering with its staged byte total
/// so one read serves both the verdict and the budget. `None` when the root is
/// gone or fails its own CID — the manifest is the only map from a `contentCid`
/// to the blocks under it, so without it the version is unreadable however many
/// leaves survive.
///
/// A root that addresses correctly but this build cannot **decode** is neither:
/// a newer build's format is a version this session cannot interpret, not one
/// that is lost, and destroying its record would destroy the only carrier of its
/// content key. That is an `Err`, so the caller freezes and the op stays queued
/// — the same fail-closed direction [`orphan_staging_keys`] takes on a
/// referenced root it cannot expand. A seam error propagates for the same
/// reason.
///
/// Deliberately says nothing about the leaves. The upload loop releases each one
/// as it confirms and tolerates a stranded release behind its resume mark
/// ([`UPLOAD_MARK_KEY`]), so which leaves are absent is only decidable against
/// that mark — which is single-slot and keyed to the head op, and so is gone by
/// the time a dead letter is judged.
async fn version_is_openable<S: StagingStore>(
    store: &S,
    root_cid: &[u8],
) -> SeamResult<Option<u64>> {
    let Some(root_block) = store.staged_bytes(root_cid).await? else {
        return Ok(None);
    };
    if verify_cid(root_cid, &root_block).is_err() {
        return Ok(None);
    }
    let manifest = decode_root(&root_block).map_err(|_| {
        SeamError::new("preserved dead letter: root manifest is not one this build decodes")
    })?;
    Ok(Some(version_bytes(&manifest, root_block.len())))
}

/// The staged bytes one version occupies: every leaf's sealed length plus the
/// root block's, arithmetic off the manifest rather than a read per leaf.
fn version_bytes(manifest: &RootManifest, root_block_len: usize) -> u64 {
    manifest
        .size
        .saturating_add((manifest.leaf_cids.len() as u64).saturating_mul(SEALED_LEAF_OVERHEAD))
        .saturating_add(root_block_len as u64)
}

/// The staged bytes one preserved record's version occupies. Zero for a record
/// naming no content, or a root the store lost.
async fn preserved_version_bytes<S: StagingStore>(store: &S, record: &[u8]) -> u64 {
    let Ok(Some(root)) = record_content_root_cid(record) else {
        return 0;
    };
    let Ok(Some(root_block)) = store.staged_bytes(&root).await else {
        return 0;
    };
    if verify_cid(&root, &root_block).is_err() {
        return 0;
    }
    let Ok(manifest) = decode_root(&root_block) else {
        return 0;
    };
    version_bytes(&manifest, root_block.len())
}

/// Trim `kept` to the count and byte ceilings, dropping oldest first and
/// releasing each evicted version's blocks so the budget is freed at once
/// rather than a GC pass later. The list is append-ordered, so its head is the
/// oldest entry.
///
/// The newest entry always survives, even alone over the byte ceiling: it is the
/// one the user is about to be told about, and a single version is already
/// bounded by the admission cap that let it stage at all.
async fn evict_over_budget<S: StagingStore>(
    store: &S,
    kept: &mut Vec<Vec<u8>>,
    appended_bytes: u64,
    budget: u64,
) {
    let mut sizes = Vec::with_capacity(kept.len());
    for record in &kept[..kept.len() - 1] {
        sizes.push(preserved_version_bytes(store, record).await);
    }
    // The caller just sized the appended record's root; no need to read it again.
    sizes.push(appended_bytes);
    let mut total = sizes.iter().copied().fold(0u64, u64::saturating_add);
    let mut evicted = 0usize;
    // Both clauses in one unit — how many entries would survive.
    while kept.len() - evicted > 1
        && (kept.len() - evicted > MAX_PRESERVED_DEAD_LETTERS || total > budget)
    {
        total = total.saturating_sub(sizes[evicted]);
        evicted += 1;
    }
    for record in kept.drain(..evicted) {
        if let Ok(Some(root)) = record_content_root_cid(&record) {
            release_version_blocks(store, &root).await;
        }
    }
}

/// The dead letters the store holds. `None` when the record is present but not
/// one this build wrote — the fail-safe direction is to preserve, so a caller
/// must freeze rather than treat it as empty.
async fn read_preserved_dead_letters<S: StagingStore>(
    store: &S,
) -> SeamResult<Option<Vec<Vec<u8>>>> {
    let Some(stored) = store.staged_bytes(PRESERVED_DEAD_LETTERS_KEY).await? else {
        return Ok(Some(Vec::new()));
    };
    let Some(mut rest) = stored.strip_prefix(&[PRESERVED_FORMAT_V1]) else {
        return Ok(None);
    };
    let mut kept = Vec::new();
    while !rest.is_empty() {
        let Some((len, tail)) = rest.split_at_checked(4) else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(len.try_into().expect("4 bytes")) as usize;
        // A zero-length entry is not a record, and would loop forever.
        let Some((record, next)) = tail.split_at_checked(len).filter(|_| len > 0) else {
            return Ok(None);
        };
        kept.push(record.to_vec());
        rest = next;
    }
    Ok(Some(kept))
}

/// Fails closed on a record too long to length-prefix, and on an empty one:
/// writing either would silently unpin every dead letter behind it, which the
/// reader hard-rejects (AGENTS.md rule 8).
///
/// An empty list removes the key rather than storing a tag-only record, so a
/// device that has never dead-lettered spends no staging budget on this.
async fn write_preserved_dead_letters<S: StagingStore>(
    store: &S,
    kept: &[Vec<u8>],
) -> SeamResult<()> {
    if kept.is_empty() {
        return store.remove_staged_bytes(PRESERVED_DEAD_LETTERS_KEY).await;
    }
    let mut bytes = vec![PRESERVED_FORMAT_V1];
    for record in kept {
        let len = u32::try_from(record.len())
            .ok()
            .filter(|len| *len > 0)
            .ok_or_else(|| SeamError::new("preserved dead letter is not length-prefixable"))?;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(record);
    }
    store
        .put_staged_bytes(PRESERVED_DEAD_LETTERS_KEY, &bytes)
        .await
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
    /// Bumped by every open and every recorded key. A GC sweep spans many
    /// awaits, so it reads this to tell that the live set it read is still the
    /// whole live set — counting only handles would miss an already-open one
    /// staging its tail and root mid-sweep.
    generation: u64,
}

impl LiveBlocks {
    /// Start holding `handle`'s staging keys.
    pub(crate) fn open(&mut self, handle: WriteHandle) {
        self.generation += 1;
        self.by_handle.insert(handle, Vec::new());
    }

    /// Hold one more staging key for `handle`, before its bytes are staged.
    pub(crate) fn record(&mut self, handle: WriteHandle, key: &[u8]) {
        self.generation += 1;
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

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

/// One orphan-GC pass: expand every staged root into its leaf set and remove the
/// blocks nothing references. Runs at cold start and after each drain pass.
///
/// Best-effort throughout — a store that cannot enumerate or remove leaves its
/// residue for the next pass — and it also prunes [`PRESERVED_DEAD_LETTERS_KEY`] of
/// roots whose bytes are already gone, so that record cannot grow without bound.
pub(crate) async fn collect_orphans<S: StagingStore>(
    store: &S,
    live: &core::cell::RefCell<LiveBlocks>,
) {
    let (generation, live_keys) = {
        let live = live.borrow();
        (live.generation(), live.keys())
    };
    let Ok(orphans) = orphan_staging_keys(store, &live_keys).await else {
        return;
    };
    for key in orphans {
        // A block staged since the scan is not in the live set this pass read,
        // and its owning handle has not journaled an op that references it —
        // abandoning the sweep is the only safe reading of that.
        if live.borrow().generation() != generation {
            return;
        }
        let _ = store.remove_staged_bytes(&key).await;
    }
    prune_preserved_dead_letters(store).await;
}

/// Drop preserved dead letters whose root no longer opens. Unreferenced from
/// here, the blocks they named become orphans the same pass collects.
async fn prune_preserved_dead_letters<S: StagingStore>(store: &S) {
    let Ok(Some(kept)) = read_preserved_dead_letters(store).await else {
        return;
    };
    let mut live = Vec::with_capacity(kept.len());
    for record in &kept {
        let Ok(Some(root)) = record_content_root_cid(record) else {
            continue;
        };
        match version_is_openable(store, &root).await {
            Ok(Some(_)) => live.push(record.clone()),
            Ok(None) => {}
            // A store that cannot answer decides nothing: keep the entry and let
            // the next pass judge it.
            Err(_) => live.push(record.clone()),
        }
    }
    if live.len() != kept.len() {
        let _ = write_preserved_dead_letters(store, &live).await;
    }
}

/// Staging keys held by the store that nothing references — orphan residue from
/// a superseded or abandoned upload, safe to GC (#33 D6 staged-bytes hygiene).
///
/// Three things reference a block. A **queued record**'s content root rides its
/// clear header, and since a version stages one block per key, a root is
/// expanded into the leaf keys its own manifest lists — so a foreign account's
/// or a forward-version record's whole block set is retained. A **preserved dead
/// letter**'s record is read the same way, which is what keeps the bytes the
/// contract promises once that record has left the queue. An **open write
/// handle**'s blocks are staged before any op is journaled, so they are
/// unreferenced by construction and must be passed in as `live`; collecting them
/// mid-write would publish a version whose manifest names blocks nothing holds.
///
/// Fail-closed: an unreadable queue entry, an unreadable preserved record, or a
/// referenced root the store cannot produce or this build cannot decode, classes
/// **nothing** an orphan. A root that cannot be expanded therefore freezes the
/// whole pass — self-clearing, because the drain classifies that same root
/// permanent and releases the version.
pub async fn orphan_staging_keys<S: StagingStore>(
    store: &S,
    live: &[Vec<u8>],
) -> SeamResult<Vec<Vec<u8>>> {
    // The drain's own queue bookkeeping is not upload residue.
    let mut referenced = HashSet::from([
        OP_ATTEMPTS_KEY.to_vec(),
        UPLOAD_MARK_KEY.to_vec(),
        PRESERVED_DEAD_LETTERS_KEY.to_vec(),
    ]);
    referenced.extend(live.iter().cloned());
    // Enumerated first, so an idle store answers without reading the queue at
    // all, and a version journaled mid-pass is decided by a queue read that
    // already covers it.
    let candidates: Vec<Vec<u8>> = store
        .staged_keys()
        .await?
        .into_iter()
        .filter(|key| !referenced.contains(key) && !is_bookkeeping(key))
        .collect();
    if candidates.is_empty() {
        return Ok(candidates);
    }
    let Some(preserved) = read_preserved_dead_letters(store).await? else {
        return Ok(Vec::new());
    };
    let queued = store.queued_ops().await?;
    let mut roots = Vec::new();
    for record in preserved.iter().chain(queued.iter().map(|(_, r)| r)) {
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
            referenced.extend(manifest.leaf_cid_vecs());
        }
        referenced.insert(root);
    }
    Ok(candidates
        .into_iter()
        .filter(|key| !referenced.contains(key))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::SealedChunk;
    use crate::content::dag::DAG_ROOT_CODEC;
    use crate::facade::NodeId;
    use crate::seams::UnixMillis;
    use crate::sync::op::{NewNode, StagedContent};
    use crate::sync::record::{RecordClass, RecordReader};
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{block_on, frame_version};
    use cipherbox_core::content::compute_cid;
    use cipherbox_core::suite::aead::KEY_LEN;
    use cipherbox_core::suite::x25519::X25519Secret;
    use std::sync::LazyLock;
    use zeroize::Zeroizing;

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    static OWNER: LazyLock<X25519Secret> = LazyLock::new(|| X25519Secret::from_scalar([42; 32]));

    /// A preserved-byte ceiling no test version can reach, so a case that means
    /// to exercise the count cap is not decided by the byte cap instead.
    const ROOMY: u64 = u64::MAX;

    fn seal(scalar: u8) -> RecordSeal<'static> {
        RecordSeal {
            owner_enc_secret: &OWNER,
            ephemeral_scalar: Zeroizing::new([scalar; 32]),
        }
    }

    /// A framed version plus the op's staged-content reference to it.
    fn framed(plaintext: &[u8]) -> (Vec<SealedChunk>, Vec<u8>, StagedContent) {
        framed_keyed(plaintext, 9)
    }

    /// A version under its own content key, the way production frames every
    /// version. Two versions sealed under *one* key address identical chunks to
    /// one CID, so a test that releases one would unpin the other's leaves.
    fn framed_keyed(plaintext: &[u8], key: u8) -> (Vec<SealedChunk>, Vec<u8>, StagedContent) {
        let (blocks, root_block, content) = frame_version(plaintext, [key; KEY_LEN], 1);
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

    /// A `StagedContent` naming a root the test staged by hand.
    fn foreign_staged(root_cid: &[u8]) -> StagedContent {
        StagedContent {
            root_cid: root_cid.to_vec(),
            plaintext_size: 1,
            sealed_content_key: b"sealed-key-blob".to_vec(),
            epoch: 1,
        }
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
    /// ops that already published, so it is never orphan residue.
    ///
    /// The same holds for a retire-ledger entry, whose collection would drop a
    /// pending reclaim debt and leak the pinned bytes it names, and for a
    /// received-shares list, whose collection would lose every accepted share
    /// whose mailbox item is already acked.
    ///
    /// Every prefix is per-identity, so this holds for an entry **this**
    /// session cannot read too: its owner is the identity that still needs it,
    /// and collecting it would discard their record.
    #[test]
    fn the_drains_own_bookkeeping_is_never_classed_an_orphan() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let foreign = |prefix: &[u8]| {
                let mut key = prefix.to_vec();
                key.extend_from_slice(&[7u8; 32]);
                key
            };
            for prefix in [
                DRAINED_OP_MARK_PREFIX,
                PUBLISHED_OP_MARK_PREFIX,
                RETIRE_LEDGER_PREFIX,
                RECEIVED_SHARES_PREFIX,
                CONTACTS_PREFIX,
                INVITE_RECORDS_PREFIX,
            ] {
                store
                    .put_staged_bytes(&foreign(prefix), &7u64.to_be_bytes())
                    .await
                    .unwrap();
            }
            store
                .put_staged_bytes(OP_ATTEMPTS_KEY, &[0u8; 12])
                .await
                .unwrap();
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert_eq!(
                orphan_staging_keys(&store, &[]).await.unwrap(),
                vec![b"orphan".to_vec()],
                "only the residue is collected, never anyone's bookkeeping"
            );
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
    /// reference source GC reclaims exactly what was promised.
    #[test]
    fn a_preserved_dead_letters_block_set_is_never_collected() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            let record = encode_op_record(seal(1), &content_op(1, staged)).unwrap();
            preserve_dead_letter(&store, &record, ROOMY).await.unwrap();
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert_eq!(
                orphan_staging_keys(&store, &[]).await.unwrap(),
                vec![b"orphan".to_vec()],
                "the preserved root and every leaf it lists stay referenced"
            );
        });
    }

    /// Preserving the whole record, not just the root, is what keeps the version
    /// openable: the sealed content key is a KDF non-edge and the record is its
    /// only carrier.
    #[test]
    fn a_preserved_dead_letter_still_carries_the_key_that_opens_its_version() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            let op = content_op(1, staged);
            preserve_dead_letter(&store, &encode_op_record(seal(1), &op).unwrap(), ROOMY)
                .await
                .unwrap();

            let kept = read_preserved_dead_letters(&store).await.unwrap().unwrap();
            assert_eq!(
                RecordReader::new(&OWNER).classify(&kept[0]),
                RecordClass::Mine(op),
                "the preserved bytes reopen to the intent, sealed key included"
            );
        });
    }

    /// The root manifest is the only map from a `contentCid` to the blocks under
    /// it, so a root the store lost names a version no read path can reach — and
    /// the old check, which asked only whether the root key was present, kept
    /// exactly those forever.
    #[test]
    fn a_version_whose_root_no_longer_opens_is_not_preserved() {
        block_on(async {
            for corrupt in [true, false] {
                let store = InMemoryStagingStore::default();
                let (blocks, root_block, staged) =
                    framed(b"forty bytes of content ------------------");
                put_blocks(&store, &blocks, &root_block, &staged).await;
                let root_cid = staged.root_cid.clone();
                let record = encode_op_record(seal(1), &content_op(1, staged)).unwrap();

                // Present but not the bytes it is addressed by, or gone outright.
                if corrupt {
                    store
                        .put_staged_bytes(&root_cid, b"not the root")
                        .await
                        .unwrap();
                } else {
                    store.remove_staged_bytes(&root_cid).await.unwrap();
                }

                assert_eq!(
                    preserve_dead_letter(&store, &record, ROOMY).await.unwrap(),
                    Preservation::ContentGone,
                    "corrupt root: {corrupt}"
                );
                assert!(
                    read_preserved_dead_letters(&store)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_empty(),
                    "nothing is held for a version nothing can map"
                );
            }
        });
    }

    /// A root a newer build wrote addresses correctly but does not decode here.
    /// That is a version this session cannot *interpret*, not one that is lost —
    /// and the record is the only carrier of its content key, so destroying it
    /// would make the `ContentUnrecoverable` it reports come true. The path
    /// freezes instead, leaving the op queued for a build that understands it.
    #[test]
    fn a_root_this_build_cannot_decode_is_retained_not_destroyed() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            let record = encode_op_record(seal(1), &content_op(1, staged)).unwrap();

            // Addressed to its own bytes, so `verify_cid` passes and only
            // `decode_root` refuses it.
            let foreign = b"a root format this build does not implement";
            let foreign_cid = compute_cid(DAG_ROOT_CODEC, foreign);
            store.put_staged_bytes(&foreign_cid, foreign).await.unwrap();
            assert!(
                version_is_openable(&store, &foreign_cid).await.is_err(),
                "an undecodable root is refused, never answered as a lost version"
            );

            // And the whole preserve path freezes on it rather than reporting
            // ContentGone, which would drop the record that holds the key.
            let held =
                encode_op_record(seal(2), &content_op(2, foreign_staged(&foreign_cid))).unwrap();
            assert!(preserve_dead_letter(&store, &held, ROOMY).await.is_err());
            assert_eq!(
                preserve_dead_letter(&store, &record, ROOMY).await.unwrap(),
                Preservation::Kept,
                "a decodable version alongside it is unaffected"
            );
        });
    }

    /// The paired case, so the refusal above cannot pass by refusing
    /// everything. A leaf released as it confirmed is progress, not loss, and
    /// the version is still openable — the check must not read it as a hole.
    #[test]
    fn a_version_missing_a_confirmed_leaf_is_still_preserved() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            let record = encode_op_record(seal(1), &content_op(1, staged)).unwrap();
            store.remove_staged_bytes(&blocks[0].cid).await.unwrap();

            assert_eq!(
                preserve_dead_letter(&store, &record, ROOMY).await.unwrap(),
                Preservation::Kept
            );
        });
    }

    /// Each preserved loser is a full ciphertext copy charged to the same
    /// `staged_bytes_total` admission reads, so an unbounded set is a device
    /// that ends up refusing every new upload with nothing but dead letters to
    /// show for its budget.
    #[test]
    fn the_preserved_set_evicts_oldest_first_past_the_count_cap() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let mut records = Vec::new();
            let mut roots = Vec::new();
            for i in 0..=MAX_PRESERVED_DEAD_LETTERS {
                let (blocks, root_block, staged) = framed_keyed(
                    format!("version {i} ------------------------------").as_bytes(),
                    i as u8,
                );
                put_blocks(&store, &blocks, &root_block, &staged).await;
                roots.push(staged.root_cid.clone());
                let record = encode_op_record(seal(i as u8), &content_op(i as u8, staged)).unwrap();
                preserve_dead_letter(&store, &record, ROOMY).await.unwrap();
                records.push(record);
            }

            let kept = read_preserved_dead_letters(&store).await.unwrap().unwrap();
            assert_eq!(kept.len(), MAX_PRESERVED_DEAD_LETTERS);
            assert_eq!(
                kept,
                records[1..],
                "the oldest entry is the one evicted, the newest always survives"
            );
            assert!(
                store.staged_bytes(&roots[0]).await.unwrap().is_none(),
                "eviction frees the budget at once, not a GC pass later"
            );
        });
    }

    /// The count cap alone does not bound bytes: sixteen large versions still
    /// swallow the device. Sized so one version fits the ceiling and two do not.
    #[test]
    fn the_preserved_set_evicts_oldest_first_past_the_byte_ceiling() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (first_blocks, first_root, first) =
                framed(b"forty bytes of content ------------------");
            put_blocks(&store, &first_blocks, &first_root, &first).await;
            let first_root_cid = first.root_cid.clone();
            let one_version = preserved_version_bytes(
                &store,
                &encode_op_record(seal(1), &content_op(1, first.clone())).unwrap(),
            )
            .await;
            // Room for one version and no more, so the second admission must
            // push the first out.
            let ceiling = one_version + 1;

            let first_record = encode_op_record(seal(1), &content_op(1, first)).unwrap();
            preserve_dead_letter(&store, &first_record, ceiling)
                .await
                .unwrap();

            let (second_blocks, second_root, second) =
                framed_keyed(b"another forty bytes of content ----------", 11);
            put_blocks(&store, &second_blocks, &second_root, &second).await;
            let second_record = encode_op_record(seal(2), &content_op(2, second)).unwrap();
            preserve_dead_letter(&store, &second_record, ceiling)
                .await
                .unwrap();

            assert_eq!(
                read_preserved_dead_letters(&store).await.unwrap().unwrap(),
                vec![second_record],
                "the byte ceiling evicts the oldest, independently of the count cap"
            );
            assert!(
                store.staged_bytes(&first_root_cid).await.unwrap().is_none(),
                "the evicted version's blocks leave the staging budget"
            );
        });
    }

    /// A single version over the ceiling still preserves: it is the dead letter
    /// the user is about to be told about, and admission already bounded it.
    #[test]
    fn the_newest_dead_letter_survives_a_ceiling_it_alone_exceeds() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            let record = encode_op_record(seal(1), &content_op(1, staged)).unwrap();
            preserve_dead_letter(&store, &record, 0).await.unwrap();
            assert_eq!(
                read_preserved_dead_letters(&store).await.unwrap().unwrap(),
                vec![record]
            );
        });
    }

    /// The prune is where a root lost *after* preservation is caught — and where
    /// a set preserved by a build that trusted the root's mere presence is
    /// reconciled.
    #[test]
    fn the_prune_drops_a_preserved_version_whose_root_stopped_opening() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            let root_cid = staged.root_cid.clone();
            let record = encode_op_record(seal(1), &content_op(1, staged)).unwrap();
            preserve_dead_letter(&store, &record, ROOMY).await.unwrap();

            // The key is still there, so a presence-only check would keep it.
            store
                .put_staged_bytes(&root_cid, b"not the root")
                .await
                .unwrap();
            prune_preserved_dead_letters(&store).await;

            assert!(
                read_preserved_dead_letters(&store)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_empty(),
                "a root that no longer addresses to its cid maps nothing"
            );
            assert_eq!(
                orphan_staging_keys(&store, &[]).await.unwrap().len(),
                blocks.len() + 1,
                "its blocks are referenced by nothing and become collectable"
            );
        });
    }

    /// The fail-safe direction here is to preserve, so a preserved record this
    /// build cannot read must freeze the pass rather than read as empty.
    #[test]
    fn an_unreadable_preserved_record_makes_orphan_gc_conservative() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();
            // A wrong tag, a length prefix past the end, and a zero-length entry
            // that would otherwise loop forever.
            for stored in [
                b"not a preserved record".to_vec(),
                vec![PRESERVED_FORMAT_V1, 0, 0, 0, 9, 1, 2],
                vec![PRESERVED_FORMAT_V1, 0, 0, 0, 0],
            ] {
                store
                    .put_staged_bytes(PRESERVED_DEAD_LETTERS_KEY, &stored)
                    .await
                    .unwrap();
                assert!(read_preserved_dead_letters(&store).await.unwrap().is_none());
                assert!(orphan_staging_keys(&store, &[]).await.unwrap().is_empty());
                assert!(
                    preserve_dead_letter(&store, b"record", ROOMY)
                        .await
                        .is_err(),
                    "overwriting it would drop the dead letters it already holds"
                );
            }
        });
    }

    #[test]
    fn preserved_dead_letters_round_trip_and_prune_to_the_blocks_still_held() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            let root_cid = staged.root_cid.clone();
            let held = encode_op_record(seal(1), &content_op(1, staged)).unwrap();
            let (gone_blocks, gone_root, gone) =
                framed_keyed(b"another forty bytes of content ----------", 11);
            put_blocks(&store, &gone_blocks, &gone_root, &gone).await;
            let gone_root_cid = gone.root_cid.clone();
            let collected = encode_op_record(seal(2), &content_op(2, gone)).unwrap();
            preserve_dead_letter(&store, &held, ROOMY).await.unwrap();
            preserve_dead_letter(&store, &collected, ROOMY)
                .await
                .unwrap();
            assert_eq!(
                read_preserved_dead_letters(&store).await.unwrap().unwrap(),
                vec![held.clone(), collected]
            );

            release_version_blocks(&store, &gone_root_cid).await;
            prune_preserved_dead_letters(&store).await;
            assert_eq!(
                read_preserved_dead_letters(&store).await.unwrap().unwrap(),
                vec![held],
                "a dead letter whose blocks are gone preserves nothing"
            );

            release_version_blocks(&store, &root_cid).await;
            prune_preserved_dead_letters(&store).await;
            assert!(
                store
                    .staged_bytes(PRESERVED_DEAD_LETTERS_KEY)
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
