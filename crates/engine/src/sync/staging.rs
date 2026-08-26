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

use core::time::Duration;
use std::collections::{BTreeMap, HashSet};

use cipherbox_core::content::verify_cid;

use crate::content::chunk::SEALED_LEAF_OVERHEAD;
use crate::content::dag::RootManifest;
use crate::content::decode_root;
use crate::facade::WriteHandle;
use crate::grants::{CONTACTS_PREFIX, INVITE_RECORDS_PREFIX, RECEIVED_SHARES_PREFIX};
use crate::net::RETIRE_LEDGER_PREFIX;
use crate::profile::SyncTimingProfile;
use crate::seams::{OpId, SeamError, SeamResult, StagingStore, UnixMillis};
use crate::storage_policy::StoragePolicy;
use crate::sync::drain::{DRAINED_OP_MARK_PREFIX, OP_ATTEMPTS_KEY, PUBLISHED_OP_MARK_PREFIX};
use crate::sync::op::Op;
use crate::sync::rebase::DeadLetterReason;
use crate::sync::record::{RecordSeal, encode_op_record, record_content_root_cid};
use crate::sync::tick::elapsed_at_least;
use crate::sync::upload_mark::{marked_leaves, upload_mark_key};

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
const PRESERVED_FORMAT_V2: u8 = 2;

/// One preserved dead letter: the op record, and when the engine parked it.
///
/// The stamp is durable for the same reason the record is — a reboot must not
/// reset the clock on a version that has been parked for a month.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreservedDeadLetter {
    preserved_at: UnixMillis,
    record: Vec<u8>,
}

/// What the preserved dead-letter set is held to on one reconcile pass: the
/// device's byte budget, the age bound, and the clock reading both are stated
/// against, taken once at the scheduler seam so a pass is a pure function of one
/// timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreservedBounds {
    budget_bytes: u64,
    ttl: Duration,
    now: UnixMillis,
}

impl PreservedBounds {
    /// The bounds this device holds its preserved set to at `now`. One
    /// constructor, so a fourth caller cannot derive them differently.
    pub(crate) fn at(now: UnixMillis, policy: &StoragePolicy, profile: &SyncTimingProfile) -> Self {
        Self {
            budget_bytes: policy.preserved_budget_bytes(),
            ttl: profile.preserved_dead_letter_ttl,
            now,
        }
    }

    fn expired(&self, entry: &PreservedDeadLetter) -> bool {
        elapsed_at_least(self.now, entry.preserved_at, self.ttl)
    }
}

/// Drop every staged block of one version: the leaves its root manifest lists,
/// in file order, then the root itself, then the version's upload mark. File
/// order keeps the blocks that remain a suffix at every step, which is the
/// invariant the drain's resume reads.
///
/// Best-effort: a failed removal is orphan residue a later GC pass collects.
pub(crate) async fn release_version_blocks<S: StagingStore>(store: &S, root_cid: &[u8]) {
    for leaf_cid in version_leaf_cids(store, root_cid).await {
        let _ = store.remove_staged_bytes(&leaf_cid).await;
    }
    let _ = store.remove_staged_bytes(root_cid).await;
    let _ = store.remove_staged_bytes(&upload_mark_key(root_cid)).await;
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

/// One pass's view of which staging keys the store still holds, borrowed from
/// the listing that pass took.
type StagedKeys<'a> = HashSet<&'a [u8]>;

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
/// Preserves only a version that still **opens** ([`open_version`]) and whose
/// leaves are all still reachable ([`has_a_hole`]). A root the store cannot
/// produce, or a leaf proven never to have reached a destination, names blocks
/// nothing can ever map. That is [`Preservation::ContentGone`], reported as
/// [`DeadLetterReason::ContentUnrecoverable`](crate::sync::rebase::DeadLetterReason::ContentUnrecoverable);
/// no record is held, so orphan GC reclaims any blocks left behind.
///
/// The byte and age bounds are [`reconcile_preserved_dead_letters`]'s, not this
/// path's. Only the count is held here, and only to keep one pass of dead
/// letters from rewriting a list that grows with every entry it appends.
///
/// Fails closed twice over: on a preserved record this build cannot read, since
/// overwriting it would drop the dead letters it already holds, and on a root it
/// cannot decode, since that record carries the only copy of the content key.
pub(crate) async fn preserve_dead_letter<S: StagingStore>(
    store: &S,
    record: &[u8],
    now: UnixMillis,
) -> SeamResult<Preservation> {
    // First: an unreadable preserved record freezes this path, and must do so
    // before any verdict a caller would act on.
    let mut kept = read_preserved_dead_letters(store)
        .await?
        .ok_or_else(|| SeamError::new("preserve_dead_letter: unreadable preserved record"))?;
    let root = record_content_root_cid(record)
        .map_err(|_| SeamError::new("preserve_dead_letter: unreadable op record"))?;
    if let Some(root) = &root {
        let Some((manifest, _)) = open_version(store, root).await? else {
            return Ok(Preservation::ContentGone);
        };
        if has_a_hole(store, root, &manifest).await? {
            return Ok(Preservation::ContentGone);
        }
    }
    if kept.iter().any(|held| held.record == record) {
        return Ok(Preservation::Kept);
    }
    kept.push(PreservedDeadLetter {
        preserved_at: now,
        record: record.to_vec(),
    });
    // Oldest-first, the order the byte and age bounds evict in. Their blocks go
    // unreferenced by this write, so the same tick's sweep reclaims them.
    let over = kept.len().saturating_sub(MAX_PRESERVED_DEAD_LETTERS);
    kept.drain(..over);
    write_preserved_dead_letters(store, &kept).await?;
    Ok(Preservation::Kept)
}

/// Whether this version has a leaf no read path can reach.
///
/// Two point reads, not a scan, both resting on the drain's release order: a
/// leaf is released only once the mark covers it, so the leaves still staged are
/// a suffix and the first one past the mark decides for all of them.
///
/// **Both reads must agree before this destroys anything.** The verdict drops
/// the version's only content-key carrier, so it is made on positive evidence
/// only: the mark says how many leaves were handed off, the first leaf past it
/// is absent, and the version's last leaf is absent too. A mark that is missing
/// or unreadable ([`marked_leaves`]) is not evidence that nothing was uploaded,
/// and a later leaf still staged means the store lost bytes rather than
/// releasing them — both preserve.
async fn has_a_hole<S: StagingStore>(
    store: &S,
    root_cid: &[u8],
    manifest: &RootManifest,
) -> SeamResult<bool> {
    let Some(mark) = store.staged_bytes(&upload_mark_key(root_cid)).await? else {
        return Ok(false);
    };
    let Some(uploaded) = marked_leaves(&mark, manifest.leaf_cids.len()) else {
        return Ok(false);
    };
    let (Some(first_unmarked), Some(last)) =
        (manifest.leaf_cids.get(uploaded), manifest.leaf_cids.last())
    else {
        return Ok(false);
    };
    Ok(store.staged_bytes(first_unmarked).await?.is_none()
        && store.staged_bytes(last).await?.is_none())
}

/// The version at `root_cid` when its root still opens: the decoded manifest and
/// the root block's own staged length. `None` when the root is gone or fails its
/// own CID — the manifest is the only map from a `contentCid` to the blocks under
/// it, so without it the version is unreadable however many leaves survive.
///
/// A root that addresses correctly but this build cannot **decode** is neither:
/// a newer build's format is a version this session cannot interpret, not one
/// that is lost, and destroying its record would destroy the only carrier of its
/// content key. That is an `Err`, so the caller freezes and the op stays queued
/// — the same fail-closed direction [`orphan_staging_keys`] takes on a
/// referenced root it cannot expand. A seam error propagates for the same
/// reason.
///
/// The leaves are [`has_a_hole`]'s question.
async fn open_version<S: StagingStore>(
    store: &S,
    root_cid: &[u8],
) -> SeamResult<Option<(RootManifest, usize)>> {
    let Some(root_block) = store.staged_bytes(root_cid).await? else {
        return Ok(None);
    };
    if verify_cid(root_cid, &root_block).is_err() {
        return Ok(None);
    }
    let manifest = decode_root(&root_block).map_err(|_| {
        SeamError::new("preserved dead letter: root manifest is not one this build decodes")
    })?;
    Ok(Some((manifest, root_block.len())))
}

/// The staged bytes one version still occupies: the root block, plus the sealed
/// length of every leaf `staged` shows the store **still holds**. A leaf the
/// upload loop released as it confirmed has already left staging, and charging it
/// would evict a neighbouring dead letter to reclaim space nothing is using.
///
/// Per-leaf plaintext is arithmetic off the manifest rather than a read per leaf:
/// [`decode_root`] holds the leaf count to `ceil(size / chunk_size)` at a nonzero
/// `chunk_size`, so every leaf but the last is exactly one chunk.
fn version_bytes(manifest: &RootManifest, root_block_len: usize, staged: &StagedKeys) -> u64 {
    let last = manifest.leaf_cids.len().saturating_sub(1);
    manifest
        .leaf_cids
        .iter()
        .enumerate()
        .filter(|(_, cid)| staged.contains(cid.as_slice()))
        .map(|(index, _)| {
            let plaintext = if index == last {
                manifest
                    .size
                    .saturating_sub(manifest.chunk_size.saturating_mul(last as u64))
            } else {
                manifest.chunk_size
            };
            plaintext.saturating_add(SEALED_LEAF_OVERHEAD)
        })
        .fold(root_block_len as u64, u64::saturating_add)
}

/// Split `sized` into the entries that stay and the roots of the versions that
/// go, against the age, count and byte bounds. The list is append-ordered, so
/// its head is the oldest entry.
///
/// Age goes first and exempts nothing: a parked version past the bound is
/// reclaimed whether or not the set is otherwise within its ceilings. The count
/// and byte ceilings then evict oldest-first, and the **newest survivor** always
/// stands, even alone over the byte ceiling — it is the one the user is about to
/// be told about, and a single version is already bounded by the admission cap
/// that let it stage at all.
fn trim_preserved(
    sized: Vec<(PreservedDeadLetter, Vec<u8>, u64)>,
    bounds: PreservedBounds,
) -> (Vec<PreservedDeadLetter>, Vec<Vec<u8>>) {
    let mut released = Vec::new();
    let mut live = Vec::with_capacity(sized.len());
    for (entry, root, bytes) in sized {
        match bounds.expired(&entry) {
            true => released.push(root),
            false => live.push((entry, root, bytes)),
        }
    }
    let mut total = live
        .iter()
        .map(|(_, _, bytes)| *bytes)
        .fold(0, u64::saturating_add);
    let mut evicted = 0usize;
    // Both clauses in one unit — how many entries would survive.
    while live.len() - evicted > 1
        && (live.len() - evicted > MAX_PRESERVED_DEAD_LETTERS || total > bounds.budget_bytes)
    {
        total = total.saturating_sub(live[evicted].2);
        evicted += 1;
    }
    released.extend(live.drain(..evicted).map(|(_, root, _)| root));
    (
        live.into_iter().map(|(entry, _, _)| entry).collect(),
        released,
    )
}

/// The dead letters the store holds. `None` when the record is present but not
/// one this build wrote — the fail-safe direction is to preserve, so a caller
/// must freeze rather than treat it as empty.
async fn read_preserved_dead_letters<S: StagingStore>(
    store: &S,
) -> SeamResult<Option<Vec<PreservedDeadLetter>>> {
    let Some(stored) = store.staged_bytes(PRESERVED_DEAD_LETTERS_KEY).await? else {
        return Ok(Some(Vec::new()));
    };
    let Some(mut rest) = stored.strip_prefix(&[PRESERVED_FORMAT_V2]) else {
        return Ok(None);
    };
    let mut kept = Vec::new();
    while !rest.is_empty() {
        let Some((stamp, tail)) = rest.split_first_chunk::<{ size_of::<u64>() }>() else {
            return Ok(None);
        };
        let Some((len, tail)) = tail.split_first_chunk::<4>() else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(*len) as usize;
        // A zero-length entry is not a record, and would loop forever.
        let Some((record, next)) = tail.split_at_checked(len).filter(|_| len > 0) else {
            return Ok(None);
        };
        kept.push(PreservedDeadLetter {
            preserved_at: UnixMillis(u64::from_be_bytes(*stamp)),
            record: record.to_vec(),
        });
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
    kept: &[PreservedDeadLetter],
) -> SeamResult<()> {
    if kept.is_empty() {
        return store.remove_staged_bytes(PRESERVED_DEAD_LETTERS_KEY).await;
    }
    let mut bytes = vec![PRESERVED_FORMAT_V2];
    for entry in kept {
        let len = u32::try_from(entry.record.len())
            .ok()
            .filter(|len| *len > 0)
            .ok_or_else(|| SeamError::new("preserved dead letter is not length-prefixable"))?;
        bytes.extend_from_slice(&entry.preserved_at.0.to_be_bytes());
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&entry.record);
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

/// One reconcile pass over staged bytes: remove the blocks nothing references,
/// then hold the preserved dead-letter set to its bounds. Runs at cold start and
/// once per drain tick, over a listing of this store's own.
pub(crate) async fn reconcile_staging<S: StagingStore>(
    store: &S,
    live: &core::cell::RefCell<LiveBlocks>,
    bounds: PreservedBounds,
) {
    let Ok(staged) = store.staged_keys().await else {
        return;
    };
    reconcile_staging_over(store, live, &staged, bounds).await;
}

/// The same pass over a key enumeration the caller already holds, so a tick that
/// reconciles several consumers pays for one listing. A key staged since it was
/// taken is simply not a candidate this pass, and one removed since is removed
/// again idempotently.
///
/// Best-effort throughout — a store that cannot expand or remove leaves its
/// residue for the next pass.
pub(crate) async fn reconcile_staging_over<S: StagingStore>(
    store: &S,
    live: &core::cell::RefCell<LiveBlocks>,
    staged: &[Vec<u8>],
    bounds: PreservedBounds,
) {
    let (generation, live_keys) = {
        let live = live.borrow();
        (live.generation(), live.keys())
    };
    let Ok(orphans) = orphan_staging_keys(store, staged, &live_keys).await else {
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
    reconcile_preserved_dead_letters(store, staged, bounds).await;
}

/// Hold the preserved dead-letter set to every bound it has: drop entries whose
/// root no longer opens, then [`trim_preserved`] it to age, count and bytes.
///
/// This is where those bounds are *enforced*, not merely where they are applied
/// again after a write. A set can go over without a write ever happening — a
/// budget cut at start, a restored data directory, a store that was already over
/// when this build opened it — and a ceiling nothing but the writer checks would
/// leave every one of those over budget forever.
///
/// The shortened list is durable before a byte of a dropped version is released:
/// `put_staged_bytes` replaces failure-atomically, so a failed write leaves the
/// *old* list — which still names those versions — and it must not be left naming
/// blocks that are already gone. The reverse order costs a lost release at worst,
/// which the next pass reclaims.
async fn reconcile_preserved_dead_letters<S: StagingStore>(
    store: &S,
    staged: &[Vec<u8>],
    bounds: PreservedBounds,
) {
    let Ok(Some(kept)) = read_preserved_dead_letters(store).await else {
        return;
    };
    if kept.is_empty() {
        return;
    }
    let staged: StagedKeys = staged.iter().map(Vec::as_slice).collect();
    let before = kept.len();
    let mut sized = Vec::with_capacity(before);
    for entry in kept {
        let Ok(Some(root)) = record_content_root_cid(&entry.record) else {
            continue;
        };
        match open_version(store, &root).await {
            Ok(Some((manifest, root_len))) => {
                let bytes = version_bytes(&manifest, root_len, &staged);
                sized.push((entry, root, bytes));
            }
            Ok(None) => {}
            // A store that cannot answer decides nothing: keep the entry, unsized,
            // and let the next pass judge it.
            Err(_) => sized.push((entry, root, 0)),
        }
    }
    let (live, released) = trim_preserved(sized, bounds);
    if live.len() == before {
        return;
    }
    if write_preserved_dead_letters(store, &live).await.is_err() {
        return;
    }
    for root in released {
        release_version_blocks(store, &root).await;
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
/// A version's upload mark is referenced by that version alone, so a mark whose
/// root nothing references is collected with it — which is what keeps the
/// per-version marks from accreting on a device that dead-letters.
///
/// `staged` is the caller's enumeration of the store's keys; the pass that drives
/// orphan GC owns it, so one tick pays for one listing.
///
/// Fail-closed: an unreadable queue entry, an unreadable preserved record, or a
/// referenced root the store cannot produce or this build cannot decode, classes
/// **nothing** an orphan. A root that cannot be expanded therefore freezes the
/// whole pass — self-clearing, because the drain classifies that same root
/// permanent and releases the version.
pub async fn orphan_staging_keys<S: StagingStore>(
    store: &S,
    staged: &[Vec<u8>],
    live: &[Vec<u8>],
) -> SeamResult<Vec<Vec<u8>>> {
    // The drain's own queue bookkeeping is not upload residue.
    let mut referenced: HashSet<Vec<u8>> = HashSet::from([
        OP_ATTEMPTS_KEY.to_vec(),
        PRESERVED_DEAD_LETTERS_KEY.to_vec(),
    ]);
    referenced.extend(live.iter().cloned());
    let candidates: Vec<&[u8]> = staged
        .iter()
        .map(Vec::as_slice)
        .filter(|key| !referenced.contains(*key) && !is_bookkeeping(key))
        .collect();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let Some(preserved) = read_preserved_dead_letters(store).await? else {
        return Ok(Vec::new());
    };
    let queued = store.queued_ops().await?;
    let mut roots = Vec::new();
    for record in preserved
        .iter()
        .map(|entry| &entry.record)
        .chain(queued.iter().map(|(_, r)| r))
    {
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
        referenced.insert(upload_mark_key(&root));
        referenced.insert(root);
    }
    Ok(candidates
        .into_iter()
        .filter(|key| !referenced.contains(*key))
        .map(<[u8]>::to_vec)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::SealedChunk;
    use crate::content::dag::DAG_ROOT_CODEC;
    use crate::facade::NodeId;
    use crate::seams::UnixMillis;
    use crate::settings::Placement;
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

    /// Far enough into the epoch that a test can park an entry either side of it.
    const NOW: UnixMillis = UnixMillis(1_000_000);

    /// Bounds no entry can age out of, so a case exercising the byte or count
    /// ceiling is not decided by expiry instead.
    fn bounds(budget_bytes: u64) -> PreservedBounds {
        PreservedBounds {
            budget_bytes,
            ttl: Duration::from_secs(u32::MAX as u64),
            now: NOW,
        }
    }

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

    /// [`orphan_staging_keys`] over a listing taken now, as the pass that drives
    /// it owns one.
    async fn sweep<S: StagingStore>(store: &S, live: &[Vec<u8>]) -> SeamResult<Vec<Vec<u8>>> {
        let staged = store.staged_keys().await?;
        orphan_staging_keys(store, &staged, live).await
    }

    /// One reconcile pass over a listing taken now.
    async fn reconcile<S: StagingStore>(store: &S, bounds: PreservedBounds) {
        let staged = store.staged_keys().await.unwrap();
        reconcile_preserved_dead_letters(store, &staged, bounds).await;
    }

    /// The op records the preserved set holds, oldest first.
    async fn kept_records<S: StagingStore>(store: &S) -> Vec<Vec<u8>> {
        read_preserved_dead_letters(store)
            .await
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|entry| entry.record)
            .collect()
    }

    /// Mark `count` of this version's leaves as having reached a destination, the
    /// way the drain's upload loop does as each one confirms.
    async fn mark_uploaded<S: StagingStore>(store: &S, root_cid: &[u8], count: u32) {
        let leaves = count as usize;
        let mark = crate::sync::upload_mark::encode_upload_mark(
            &Placement::Hosted.destinations(),
            leaves,
            leaves,
        )
        .expect("in range");
        store
            .put_staged_bytes(&upload_mark_key(root_cid), &mark)
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
                sweep(&store, &[]).await.unwrap().is_empty(),
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
                sweep(&store, &[]).await.unwrap(),
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
                sweep(&store, &[]).await.unwrap(),
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
                sweep(&store, &live).await.unwrap(),
                vec![staged.root_cid.clone(), b"orphan".to_vec()],
                "the handle's leaves are held; its uncommitted root is not yet referenced"
            );
            assert!(
                sweep(&store, &[]).await.unwrap().len() > live.len(),
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
                sweep(&store, &[]).await.unwrap(),
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
                sweep(&store, &[]).await.unwrap(),
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
            preserve_dead_letter(&store, &record, NOW).await.unwrap();
            store.put_staged_bytes(b"orphan", b"stale").await.unwrap();

            assert_eq!(
                sweep(&store, &[]).await.unwrap(),
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
            preserve_dead_letter(&store, &encode_op_record(seal(1), &op).unwrap(), NOW)
                .await
                .unwrap();

            let kept = kept_records(&store).await;
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
                    preserve_dead_letter(&store, &record, NOW).await.unwrap(),
                    Preservation::ContentGone,
                    "corrupt root: {corrupt}"
                );
                assert!(
                    kept_records(&store).await.is_empty(),
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
                open_version(&store, &foreign_cid).await.is_err(),
                "an undecodable root is refused, never answered as a lost version"
            );

            // And the whole preserve path freezes on it rather than reporting
            // ContentGone, which would drop the record that holds the key.
            let held =
                encode_op_record(seal(2), &content_op(2, foreign_staged(&foreign_cid))).unwrap();
            assert!(preserve_dead_letter(&store, &held, NOW).await.is_err());
            assert_eq!(
                preserve_dead_letter(&store, &record, NOW).await.unwrap(),
                Preservation::Kept,
                "a decodable version alongside it is unaffected"
            );
        });
    }

    /// A leaf absent from staging is progress or loss depending on one fact: did
    /// it ever reach a destination. The version's own upload mark answers that,
    /// and answers it long after another content op has taken the queue head —
    /// the verdict a single head-keyed slot could not reach.
    ///
    /// The verdict drops the only carrier of the version's content key, so it
    /// takes positive evidence from both point reads: an unmarked leaf missing
    /// *and* the version's last leaf missing with it. A leaf surviving past the
    /// gap is a damaged store, not an orderly release, and preserves.
    #[test]
    fn a_dead_letters_verdict_reads_the_versions_own_upload_mark() {
        // Marked leaves, whether the tail survives, and the verdict that follows
        // from removing leaf zero.
        let cases = [
            (Some(0u32), false, Preservation::ContentGone),
            (Some(0), true, Preservation::Kept),
            (Some(1), false, Preservation::Kept),
            (None, false, Preservation::Kept),
        ];
        block_on(async {
            for (marked, keep_tail, expected) in cases {
                let store = InMemoryStagingStore::default();
                let (blocks, root_block, staged) =
                    framed(b"forty bytes of content ------------------");
                put_blocks(&store, &blocks, &root_block, &staged).await;
                let root_cid = staged.root_cid.clone();
                let record = encode_op_record(seal(1), &content_op(1, staged)).unwrap();
                if let Some(marked) = marked {
                    mark_uploaded(&store, &root_cid, marked).await;
                }
                store.remove_staged_bytes(&blocks[0].cid).await.unwrap();
                if !keep_tail {
                    let last = blocks.last().expect("a multi-leaf version");
                    store.remove_staged_bytes(&last.cid).await.unwrap();
                }

                assert_eq!(
                    preserve_dead_letter(&store, &record, NOW).await.unwrap(),
                    expected,
                    "marked {marked:?} of {} leaves, tail kept: {keep_tail}",
                    blocks.len()
                );
            }
        });
    }

    /// A second content op marks its own progress beside the first's, so the
    /// first is still resumable — and still preservable — once it comes round
    /// again.
    #[test]
    fn a_second_content_op_does_not_erase_the_firsts_progress() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (first_blocks, first_root, first) =
                framed(b"forty bytes of content ------------------");
            put_blocks(&store, &first_blocks, &first_root, &first).await;
            let first_root_cid = first.root_cid.clone();
            let first_record = encode_op_record(seal(1), &content_op(1, first)).unwrap();
            mark_uploaded(&store, &first_root_cid, 1).await;
            store
                .remove_staged_bytes(&first_blocks[0].cid)
                .await
                .unwrap();

            let (second_blocks, second_root, second) =
                framed_keyed(b"another forty bytes of content ----------", 11);
            put_blocks(&store, &second_blocks, &second_root, &second).await;
            mark_uploaded(&store, &second.root_cid, 2).await;

            assert_eq!(
                preserve_dead_letter(&store, &first_record, NOW)
                    .await
                    .unwrap(),
                Preservation::Kept,
                "the second op's mark landed beside the first's, not over it"
            );
        });
    }

    /// A version's mark is referenced by that version alone, so it leaves with
    /// the blocks rather than accreting one key per dead letter forever.
    #[test]
    fn an_upload_mark_is_collected_with_the_version_it_marks() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (blocks, root_block, staged) = framed(b"forty bytes of content ------------------");
            put_blocks(&store, &blocks, &root_block, &staged).await;
            let root_cid = staged.root_cid.clone();
            mark_uploaded(&store, &root_cid, 1).await;
            let record = encode_op_record(seal(1), &content_op(1, staged)).unwrap();
            preserve_dead_letter(&store, &record, NOW).await.unwrap();

            assert!(
                !sweep(&store, &[])
                    .await
                    .unwrap()
                    .contains(&upload_mark_key(&root_cid)),
                "a referenced version's mark is referenced with it"
            );

            release_version_blocks(&store, &root_cid).await;
            assert!(
                store
                    .staged_bytes(&upload_mark_key(&root_cid))
                    .await
                    .unwrap()
                    .is_none(),
                "and the release that drops its blocks drops the mark"
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
                preserve_dead_letter(&store, &record, NOW).await.unwrap();
                records.push(record);
            }
            let kept = kept_records(&store).await;
            assert_eq!(kept.len(), MAX_PRESERVED_DEAD_LETTERS);
            assert_eq!(
                kept,
                records[1..],
                "the oldest entry is the one evicted, the newest always survives"
            );
            // The write path drops the entry; nothing references its blocks
            // afterwards, so the same tick's sweep is what reclaims them.
            let orphans = sweep(&store, &[]).await.unwrap();
            assert!(
                orphans.contains(&roots[0]),
                "the evicted version's blocks leave the staging budget"
            );
            assert!(
                roots[1..].iter().all(|root| !orphans.contains(root)),
                "and every surviving entry keeps its own"
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
            let staged = store.staged_keys().await.unwrap();
            let (manifest, root_len) = open_version(&store, &first_root_cid)
                .await
                .unwrap()
                .expect("the version opens");
            let one_version = version_bytes(
                &manifest,
                root_len,
                &staged.iter().map(Vec::as_slice).collect(),
            );
            // Room for one version and no more, so the second admission must
            // push the first out.
            let ceiling = one_version + 1;

            let first_record = encode_op_record(seal(1), &content_op(1, first)).unwrap();
            preserve_dead_letter(&store, &first_record, NOW)
                .await
                .unwrap();

            let (second_blocks, second_root, second) =
                framed_keyed(b"another forty bytes of content ----------", 11);
            put_blocks(&store, &second_blocks, &second_root, &second).await;
            let second_record = encode_op_record(seal(2), &content_op(2, second)).unwrap();
            preserve_dead_letter(&store, &second_record, NOW)
                .await
                .unwrap();
            reconcile(&store, bounds(ceiling)).await;

            assert_eq!(
                kept_records(&store).await,
                vec![second_record],
                "the byte ceiling evicts the oldest, independently of the count cap"
            );
            assert!(
                store.staged_bytes(&first_root_cid).await.unwrap().is_none(),
                "the evicted version's blocks leave the staging budget"
            );
        });
    }

    /// The eviction and the list that stops naming the evicted entry must not
    /// come apart: a failed list write leaves the *old* list durable, and that
    /// list still promises every version in it.
    #[test]
    fn a_failed_preserved_write_leaves_the_evicted_versions_blocks_alone() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (first_blocks, first_root, first) =
                framed(b"forty bytes of content ------------------");
            put_blocks(&store, &first_blocks, &first_root, &first).await;
            let first_root_cid = first.root_cid.clone();
            let first_record = encode_op_record(seal(1), &content_op(1, first)).unwrap();
            preserve_dead_letter(&store, &first_record, NOW)
                .await
                .unwrap();

            let (second_blocks, second_root, second) =
                framed_keyed(b"another forty bytes of content ----------", 11);
            put_blocks(&store, &second_blocks, &second_root, &second).await;
            let second_record = encode_op_record(seal(2), &content_op(2, second)).unwrap();
            preserve_dead_letter(&store, &second_record, NOW)
                .await
                .unwrap();
            // The list write that would drop the first entry fails; a ceiling of
            // zero is what would otherwise evict it.
            store.interrupt_staged_write_after(PRESERVED_DEAD_LETTERS_KEY, 0);
            reconcile(&store, bounds(0)).await;

            assert_eq!(
                kept_records(&store).await,
                vec![first_record, second_record],
                "the old list survives, still naming the first version"
            );
            assert!(
                store.staged_bytes(&first_root_cid).await.unwrap().is_some(),
                "so its blocks must survive with it"
            );
        });
    }

    /// A leaf the upload loop released on confirmation has left staging. Charging
    /// it would evict a recoverable neighbour to reclaim space nothing is using.
    #[test]
    fn a_released_leaf_is_not_charged_against_the_byte_ceiling() {
        let store = InMemoryStagingStore::default();
        block_on(async {
            let (first_blocks, first_root, first) =
                framed(b"forty bytes of content ------------------");
            put_blocks(&store, &first_blocks, &first_root, &first).await;
            let first_root_cid = first.root_cid.clone();
            let first_record = encode_op_record(seal(1), &content_op(1, first)).unwrap();

            let (second_blocks, second_root, second) =
                framed_keyed(b"another forty bytes of content ----------", 11);
            put_blocks(&store, &second_blocks, &second_root, &second).await;
            let second_root_cid = second.root_cid.clone();
            let second_record = encode_op_record(seal(2), &content_op(2, second)).unwrap();

            // The second version confirmed and released every leaf but its last,
            // so what it still occupies is the root plus that one leaf.
            let confirmed = second_blocks.len() - 1;
            mark_uploaded(&store, &second_root_cid, confirmed as u32).await;
            for block in &second_blocks[..confirmed] {
                store.remove_staged_bytes(&block.cid).await.unwrap();
            }
            // Measured off the blocks themselves, not the accounting under test:
            // exactly what the two versions still occupy, so charging the released
            // leaves puts the pair over and evicts the first.
            let ceiling = first_blocks
                .iter()
                .chain(second_blocks.last())
                .map(|block| block.sealed.len() as u64)
                .sum::<u64>()
                + first_root.len() as u64
                + second_root.len() as u64;

            preserve_dead_letter(&store, &first_record, NOW)
                .await
                .unwrap();
            preserve_dead_letter(&store, &second_record, NOW)
                .await
                .unwrap();
            reconcile(&store, bounds(ceiling)).await;

            assert_eq!(
                kept_records(&store).await,
                vec![first_record, second_record],
                "the released leaves left room for both"
            );
            assert!(
                store.staged_bytes(&first_root_cid).await.unwrap().is_some(),
                "and the older version keeps its blocks"
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
            preserve_dead_letter(&store, &record, NOW).await.unwrap();
            reconcile(&store, bounds(0)).await;
            assert_eq!(kept_records(&store).await, vec![record]);
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
            preserve_dead_letter(&store, &record, NOW).await.unwrap();

            // The key is still there, so a presence-only check would keep it.
            store
                .put_staged_bytes(&root_cid, b"not the root")
                .await
                .unwrap();
            reconcile(&store, bounds(ROOMY)).await;

            assert!(
                kept_records(&store).await.is_empty(),
                "a root that no longer addresses to its cid maps nothing"
            );
            assert_eq!(
                sweep(&store, &[]).await.unwrap().len(),
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
                vec![
                    PRESERVED_FORMAT_V2,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    1,
                    0,
                    0,
                    0,
                    9,
                    1,
                    2,
                ],
                vec![PRESERVED_FORMAT_V2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
            ] {
                store
                    .put_staged_bytes(PRESERVED_DEAD_LETTERS_KEY, &stored)
                    .await
                    .unwrap();
                assert!(read_preserved_dead_letters(&store).await.unwrap().is_none());
                assert!(sweep(&store, &[]).await.unwrap().is_empty());
                assert!(
                    preserve_dead_letter(&store, b"record", NOW).await.is_err(),
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
            preserve_dead_letter(&store, &held, NOW).await.unwrap();
            preserve_dead_letter(&store, &collected, NOW).await.unwrap();
            assert_eq!(kept_records(&store).await, vec![held.clone(), collected]);

            release_version_blocks(&store, &gone_root_cid).await;
            reconcile(&store, bounds(ROOMY)).await;
            assert_eq!(
                kept_records(&store).await,
                vec![held],
                "a dead letter whose blocks are gone preserves nothing"
            );

            release_version_blocks(&store, &root_cid).await;
            reconcile(&store, bounds(ROOMY)).await;
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

            assert!(sweep(&store, &[]).await.unwrap().is_empty());
        });
    }
}
