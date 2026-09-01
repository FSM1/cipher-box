//! Retirement (blueprint/engine.md "Resolve/publish pipeline: Retirement",
//! #34 D4).
//!
//! Retire = remove my registry rows; the timing is engine policy. Interior old
//! names batch-retire at name-wave completion (immediate, [`retire`]); the old
//! scope-root name lingers serving the tombstone until the migration window
//! closes ([`root_retire_ready`], stubbed — see below).
//!
//! A pruned version's bytes are the one retirement that outlives the op that
//! ordered it ([`drain_owed_retires`]).

use core::cell::RefCell;
use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::content::{
    decode_content_cid_str, encode_content_cid_str, is_wellformed_content_cid,
};
use cipherbox_core::seal::OwnerLocalKind;
use zeroize::Zeroizing;

use super::REGISTRY_BATCH_MAX;
use crate::api::{ApiClient, ApiError};
use crate::content::{
    ContentPlane, ContentProfile, Expansion, Gateway, expand_retire_targets, read_block,
};
use crate::net::publish::PublishError;
use crate::net::record_publish::RecordPublishError;
use crate::seams::{
    CredentialStore, Http, OwedRetire, OwingRecord, RetireLedger, SeamError, SeamResult,
    StagingStore,
};
use crate::sync::BookkeepingSeal;

/// Registry rows a pass left charged and unreachable, pending retirement: the
/// head blocks of a failed publish, and the names of a reclaimed subtree whose
/// retire the registry refused.
///
/// Session-lived and shared by every publisher — the drain clears it at the end
/// of a pass, the settings publish at the point of failure — so a retire the
/// registry refused goes out again rather than being lost.
#[derive(Debug, Default)]
pub struct OrphanHeads(RefCell<Vec<String>>);

impl OrphanHeads {
    /// Note one head block as orphaned, capped at [`REGISTRY_BATCH_MAX`] so a
    /// session whose retires keep failing bounds its leak, not its memory.
    pub fn record(&self, cid: &str) {
        let mut pending = self.0.borrow_mut();
        if pending.len() < REGISTRY_BATCH_MAX && !pending.iter().any(|held| held == cid) {
            pending.push(cid.to_owned());
        }
    }

    /// Retire what is pending. A refused retire keeps the set rather than
    /// losing the only record of what to retire; a successful one clears the
    /// heads it actually sent, so a head recorded by an overlapping publisher
    /// mid-flight stays pending instead of being dropped unsent.
    pub async fn retire_pending<H, C>(&self, api: &ApiClient<H, C>)
    where
        H: Http,
        C: CredentialStore,
    {
        let pending = self.0.borrow().clone();
        if pending.is_empty() {
            return;
        }
        if retire(api, &pending).await.is_ok() {
            self.0.borrow_mut().retain(|cid| !pending.contains(cid));
        }
    }

    /// What is still pending, for tests and diagnostics.
    #[must_use]
    pub fn pending(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

/// Whether a failed publish left its head block charged and unreachable: the
/// upload landed under its own pin row, no record naming it reached the
/// transport, and the retry re-authors under a fresh seal nonce
/// (blueprint/engine.md "Resolve/publish pipeline: Retirement").
#[must_use]
pub fn orphaned_head(error: &RecordPublishError) -> bool {
    match error {
        // A status answer is the server's own refusal, so it charged no row; a
        // dropped connection or an unreadable 2xx may have left one behind.
        RecordPublishError::Upload(error) => {
            matches!(error, ApiError::Transport(_) | ApiError::Decode(_))
        }
        RecordPublishError::HeadCidMismatch { .. } => true,
        RecordPublishError::Publish(error) => match error {
            // The head block is already uploaded and charged when publish
            // refuses, and no record naming it reached the transport.
            PublishError::Register(_)
            | PublishError::FloorRead(_)
            | PublishError::RecordTooLarge { .. } => true,
            // Nothing was ever addressed, so there is no CID to retire.
            PublishError::EmptyHeadCid | PublishError::EmptyInlineValue => false,
            // No ack is not proof nothing stored: unpinning a head a live
            // record may still name is loss, where the row is only a leak.
            PublishError::AllEndpointsFailed => false,
        },
    }
}

/// Batch-retire registry rows for `targets` (`ipnsName`s or CIDs). Idempotent
/// server-side (blueprint/api.md), so a replayed batch — a resumed name wave, or
/// a chunk a failed pass already sent — is a no-op, never an error. This is the
/// interior-name path: it retires the moment the caller says a name is dead.
///
/// Chunked to [`REGISTRY_BATCH_MAX`] **in the order given**; a failing chunk
/// leaves the earlier ones retired and returns `Err`. Callers whose order is
/// load-bearing — the prune expansion, whose root must outlive its leaves — get
/// it from that.
pub async fn retire<H, C>(api: &ApiClient<H, C>, targets: &[String]) -> Result<(), ApiError>
where
    H: Http,
    C: CredentialStore,
{
    retire_chunked(api, None, targets).await
}

/// The same, chunked the same way, under the record `ipns_name` names — `None`
/// being the account-wide form above, and the only one whose targets may name a
/// record ([`ApiClient::retire_for_record`]).
async fn retire_chunked<H, C>(
    api: &ApiClient<H, C>,
    ipns_name: Option<&str>,
    targets: &[String],
) -> Result<(), ApiError>
where
    H: Http,
    C: CredentialStore,
{
    for chunk in targets.chunks(REGISTRY_BATCH_MAX) {
        match ipns_name {
            Some(name) => api.retire_for_record(name, chunk).await?,
            None => api.retire(chunk).await?,
        };
    }
    Ok(())
}

/// The staging-key prefix the [`StagingRetireLedger`] journals under.
///
/// The ledger rides the staging store's opaque key space rather than its op
/// queue: the queue is FIFO, cancellable, and swept of what it cannot decode at
/// cold start, and an owed retirement is none of those things.
/// [`orphan_staging_keys`] treats the whole prefix as referenced, every owner's
/// entries included.
///
/// Kept short because an entry's key is the longest the staging space holds and
/// the desktop store spells one as a hex filename — twice its byte length,
/// inside Windows' whole-path budget.
///
/// [`orphan_staging_keys`]: crate::sync::orphan_staging_keys
pub const RETIRE_LEDGER_PREFIX: &[u8] = b"cbx/rl/";

/// One stored entry's fixed head: the owing node's id, the owed figure and the
/// manifest total as big-endian `u64`, then the owing-record class. The target's
/// binary CID follows, as the tail that binds the value to its key.
const ENTRY_HEAD_LEN: usize = NODE_ID_LEN + 2 * size_of::<u64>() + 1;

/// [`OwingRecord::Published`] as the entry stores it.
const OWING_PUBLISHED: u8 = 0;

/// [`OwingRecord::Retired`] as the entry stores it.
const OWING_RETIRED: u8 = 1;

/// The engine's location-independent node id, as the entry stores it.
const NODE_ID_LEN: usize = 16;

/// The [`RetireLedger`] every host gets for free, over the durable staging store
/// it already implements.
///
/// One key per entry, so `settle` is a single removal and a concurrent `owe` of
/// another target cannot lose it — there is no whole-set record to rewrite.
///
/// Each entry's value is sealed under [`OwnerLocalKind::RetireLedger`], the tier
/// rule for per-owner staging bookkeeping
/// ([`crate::sync::bookkeeping`]); the key stays clear, because orphan GC
/// enumerates it.
pub struct StagingRetireLedger<'a, St> {
    staging: &'a St,
    seal: BookkeepingSeal<'a>,
    listed: Option<&'a [Vec<u8>]>,
}

impl<'a, St: StagingStore> StagingRetireLedger<'a, St> {
    /// Wraps a staging store as the retire ledger, enumerating it on each
    /// [`owed`](RetireLedger::owed).
    pub fn new(staging: &'a St, seal: BookkeepingSeal<'a>) -> Self {
        Self {
            staging,
            seal,
            listed: None,
        }
    }

    /// The same ledger over a key enumeration the caller already holds, for a
    /// pass that reconciles several consumers off one listing. `listed` must
    /// cover every `owe` this pass has already journaled, or their debts wait
    /// for the next one.
    pub fn over(staging: &'a St, seal: BookkeepingSeal<'a>, listed: &'a [Vec<u8>]) -> Self {
        Self {
            staging,
            seal,
            listed: Some(listed),
        }
    }

    /// The keys `owed` reads entries out of.
    async fn keys(&self) -> SeamResult<Cow<'a, [Vec<u8>]>> {
        match self.listed {
            Some(listed) => Ok(Cow::Borrowed(listed)),
            None => Ok(Cow::Owned(self.staging.staged_keys().await?)),
        }
    }

    /// The key prefix every entry of one owner shares. The tag length is written
    /// in, so a shorter tag can never alias a longer one's entries.
    fn scope(owner_tag: &[u8]) -> SeamResult<Vec<u8>> {
        let len = u8::try_from(owner_tag.len())
            .map_err(|_| SeamError::new("retire-ledger owner tag is over 255 bytes"))?;
        let mut key = RETIRE_LEDGER_PREFIX.to_vec();
        key.push(len);
        key.extend_from_slice(owner_tag);
        Ok(key)
    }

    /// One entry's key, from the target's already-decoded binary CID.
    fn key_of(owner_tag: &[u8], cid: &[u8]) -> SeamResult<Vec<u8>> {
        let mut key = Self::scope(owner_tag)?;
        key.extend_from_slice(cid);
        Ok(key)
    }

    /// One entry's key. The target rides as its **binary** CID, a third shorter
    /// than the multibase spelling and the form the suffix decodes back from.
    pub fn key(owner_tag: &[u8], target: &str) -> SeamResult<Vec<u8>> {
        Self::key_of(owner_tag, &Self::cid(target)?)
    }

    /// The target's binary CID — the one shape an entry may be keyed by.
    fn cid(target: &str) -> SeamResult<Vec<u8>> {
        decode_content_cid_str(target)
            .map_err(|_| SeamError::new("retire-ledger target is not a content CID"))
    }

    /// One stored entry, or `None` for bytes this identity's key and this
    /// build's grammar do not both accept.
    ///
    /// The seal's AAD counts nothing per entry, so one legitimately sealed value
    /// opens under every key in this owner's ledger scope. The stored CID is
    /// what stops a value being moved onto another target's key: `owed` reads
    /// `target` from the key and `node` from the value, and a transplant would
    /// otherwise hand `drain_owed_retires` a debt whose liveness check is made
    /// against a record that never named it — the same hazard
    /// [`Reclamation::is_for`](crate::sync::doomed::Reclamation::is_for) closes
    /// on the doomed-name journal.
    async fn entry(&self, key: &[u8], cid: &[u8]) -> SeamResult<Option<OwedRetire>> {
        let Some(blob) = self.staging.staged_bytes(key).await? else {
            return Ok(None);
        };
        Ok(self
            .seal
            .open(OwnerLocalKind::RetireLedger, &blob)
            .and_then(|body| decode_entry(&body, cid)))
    }

    /// Write one entry, sealed and bound to `cid`.
    async fn put(&self, key: &[u8], cid: &[u8], entry: &OwedRetire) -> SeamResult<()> {
        let blob = self
            .seal
            .seal(OwnerLocalKind::RetireLedger, &encode_entry(entry, cid))?;
        self.staging.put_staged_bytes(key, &blob).await
    }
}

impl<St: StagingStore> RetireLedger for StagingRetireLedger<'_, St> {
    async fn owe(&self, owner_tag: &[u8], entries: &[OwedRetire]) -> SeamResult<()> {
        for entry in entries {
            let cid = Self::cid(&entry.target)?;
            let key = Self::key_of(owner_tag, &cid)?;
            // A held entry's figures stand, so a replayed prune cannot move what
            // the vault reports as pending; an unreadable one is repaired rather
            // than left to sit undrainable forever. The class is the exception:
            // it only ever advances to `Retired`, because a node whose record a
            // delete retired never publishes again, and keeping the stored
            // `Published` would leave that debt unsettleable.
            match self.entry(&key, &cid).await? {
                Some(held) if held.owing == entry.owing => continue,
                Some(held) if entry.owing == OwingRecord::Retired => {
                    let advanced = OwedRetire {
                        owing: OwingRecord::Retired,
                        ..held
                    };
                    self.put(&key, &cid, &advanced).await?;
                }
                Some(_) => continue,
                None => self.put(&key, &cid, entry).await?,
            }
        }
        Ok(())
    }

    async fn owed(&self, owner_tag: &[u8]) -> SeamResult<Vec<OwedRetire>> {
        let scope = Self::scope(owner_tag)?;
        let mut entries = Vec::new();
        for key in self.keys().await?.iter() {
            let Some(cid) = key
                .strip_prefix(&scope[..])
                .filter(|cid| is_wellformed_content_cid(cid))
            else {
                continue;
            };
            let Some(stored) = self.entry(key, cid).await? else {
                continue;
            };
            entries.push(OwedRetire {
                target: encode_content_cid_str(cid),
                ..stored
            });
        }
        // Store enumeration order is host-dependent, and a pass can stop early;
        // sorted, it at least stops at the same place on every host.
        entries.sort_by(|a, b| a.target.cmp(&b.target));
        Ok(entries)
    }

    async fn settle(&self, owner_tag: &[u8], targets: &[String]) -> SeamResult<()> {
        for target in targets {
            self.staging
                .remove_staged_bytes(&Self::key(owner_tag, target)?)
                .await?;
        }
        Ok(())
    }
}

/// One entry as the staging store holds it, inside the seal: the fixed head,
/// then the binary CID of the target it is keyed by.
///
/// Zeroizing because the plaintext side of a sealed value is exactly what the
/// tier exists to keep off the host ([`crate::sync::bookkeeping`]).
fn encode_entry(entry: &OwedRetire, cid: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut stored = Zeroizing::new(Vec::with_capacity(ENTRY_HEAD_LEN + cid.len()));
    stored.extend_from_slice(&entry.node);
    stored.extend_from_slice(&entry.owed_bytes.to_be_bytes());
    stored.extend_from_slice(&entry.manifest_bytes.to_be_bytes());
    stored.push(match entry.owing {
        OwingRecord::Published => OWING_PUBLISHED,
        OwingRecord::Retired => OWING_RETIRED,
    });
    stored.extend_from_slice(cid);
    stored
}

/// One entry's node, figures and owing-record class — or `None` for bytes this
/// build did not write, which read as unwritten rather than as figures of their
/// own. The `target` of what comes back is a placeholder: it lives in the key.
///
/// An unknown class byte reads as unwritten too: guessing it `Published` would
/// strand a hard delete's debt forever, and guessing it `Retired` would let a
/// live node's content unpin. So does a stored CID that is not `cid`, the one
/// the entry's own key names ([`StagingRetireLedger::entry`]).
fn decode_entry(stored: &[u8], cid: &[u8]) -> Option<OwedRetire> {
    let (head, bound) = stored.split_at_checked(ENTRY_HEAD_LEN)?;
    if bound != cid {
        return None;
    }
    let (node, rest) = head.split_first_chunk::<NODE_ID_LEN>()?;
    let (owed, rest) = rest.split_first_chunk::<{ size_of::<u64>() }>()?;
    let (manifest, owing) = rest.split_first_chunk::<{ size_of::<u64>() }>()?;
    let owing = match *owing.first()? {
        OWING_PUBLISHED => OwingRecord::Published,
        OWING_RETIRED => OwingRecord::Retired,
        _ => return None,
    };
    Some(OwedRetire {
        node: *node,
        owing,
        target: String::new(),
        owed_bytes: u64::from_be_bytes(*owed),
        manifest_bytes: u64::from_be_bytes(*manifest),
    })
}

/// The record a debt is owed by, as the settling pass established it.
///
/// The name is what scopes the retire: a leaf a doomed root aliased from another
/// node stays pinned, because the registry drops this record's reference edge
/// rather than the account's whole claim (blueprint/api.md "Pin/name registry").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveRecord {
    /// The owning node's write-plane IPNS name.
    pub name: String,
    /// Every content CID that node's currently published record still reaches.
    pub cids: BTreeSet<String>,
}

/// Work the ledger once and report what it left behind: the pinned bytes still
/// owed — the vault's pending-reclaim figure — and why every debt that did not
/// settle did not ([`ReclaimStall`]). `None` when the ledger could not be read,
/// so a store hiccup reports nothing rather than reporting no debt.
///
/// Each entry is expanded from its own root block, fetched keyless (plaintext
/// det-CBOR), and retired in [`expand_retire_targets`] order, less every CID
/// `live` reports for the entry's own node ([`Expansion::minus`]).
///
/// `live` answers "what does this node's **currently published** record still
/// reach, and under what name", read fresh so a version adopted since the prune
/// journaled its debt is in the answer. `None` is "this pass could not establish
/// it", and no entry retires without it, because retiring blind is loss where
/// waiting is a leak.
/// It is also what makes a debt safe to journal ahead of the shortened record: a
/// target the node's record still names has no landed shortening behind it.
///
/// `live` is told the node's [`OwingRecord`] class, because a hard-deleted node
/// has no record left to read and its debt would otherwise sit unsettleable
/// against a never-discard ledger. The class is a property of the node across
/// the whole pass, not of the entry carrying it: one hard delete retires the
/// record out from under every debt that node already owed.
///
/// An entry clears on the registry's own answer. Everything else — offline, an
/// expired token, a throttle, a root no source will serve — leaves the entry
/// owed and retries on a later pass; a registry that refused one batch stops the
/// pass from naming anything further, but every entry is still expanded, because
/// the expansion is also what the vault reports as pending. There is no attempt
/// budget and no dead-letter class: every failure is either self-clearing or
/// ours, and the byte figure is the only record of what was owed.
pub async fn drain_owed_retires<L, H, C>(
    ledger: &L,
    owner_tag: &[u8],
    api: &ApiClient<H, C>,
    gateway: &Gateway,
    http: &H,
    profile: &ContentProfile,
    live: impl AsyncFn([u8; 16], OwingRecord) -> Option<LiveRecord>,
) -> Option<ReclaimPass>
where
    L: RetireLedger,
    H: Http,
    C: CredentialStore,
{
    let owed = ledger.owed(owner_tag).await.ok()?;
    let mut stalls: Vec<ReclaimStall> = Vec::new();
    let retired: BTreeSet<[u8; 16]> = owed
        .iter()
        .filter(|entry| entry.owing == OwingRecord::Retired)
        .map(|entry| entry.node)
        .collect();
    let mut still_owed = 0u64;
    let mut registry_up = true;
    // One record read per owing node, not per entry — a prune drops several
    // versions of one file. A node's set grows only with what actually retired,
    // so a CID a deferred entry named is still reachable by the next one.
    let mut live_of: BTreeMap<[u8; 16], Option<LiveRecord>> = BTreeMap::new();
    // A CID two doomed roots both name is one pin row either way, so the figure
    // counts it once whether or not the retire that names it lands.
    let mut counted: BTreeSet<String> = BTreeSet::new();
    for entry in owed {
        let owing = if retired.contains(&entry.node) {
            OwingRecord::Retired
        } else {
            OwingRecord::Published
        };
        let node = match live_of.entry(entry.node) {
            Entry::Occupied(held) => held.into_mut(),
            Entry::Vacant(slot) => slot.insert(live(entry.node, owing).await),
        };
        // Bounded like every other batch this module reports: the reasons are
        // there to be acted on, and the figure is what counts the debt.
        let stall = |reason| ReclaimStall {
            node: entry.node,
            target: entry.target.clone(),
            reason,
        };
        let Some(node) = node else {
            still_owed = still_owed.saturating_add(entry.owed_bytes);
            if stalls.len() < REGISTRY_BATCH_MAX {
                stalls.push(stall(ReclaimStallReason::NodeUnreadable));
            }
            continue;
        };
        // A target its own node's record still reaches is one whose shortening
        // has not landed. Live content is not pending reclaim, so it adds
        // nothing to the figure and the entry waits for the record that drops
        // it.
        if node.cids.contains(&entry.target) {
            if stalls.len() < REGISTRY_BATCH_MAX {
                stalls.push(stall(ReclaimStallReason::TargetStillLive));
            }
            continue;
        }
        let Some(expansion) = expand_owed(&entry, gateway, http, profile).await else {
            still_owed = still_owed.saturating_add(entry.owed_bytes);
            if stalls.len() < REGISTRY_BATCH_MAX {
                stalls.push(stall(ReclaimStallReason::TargetUnexpandable));
            }
            continue;
        };
        let retirable = expansion.minus(&node.cids);
        let targets = retirable.cids();
        let pinned_bytes = retirable.minus(&counted).pinned_bytes;
        counted.extend(targets.iter().cloned());
        still_owed = still_owed.saturating_add(pinned_bytes);
        if !registry_up {
            continue;
        }
        match send_retire(&entry, &node.name, &targets, ledger, owner_tag, api).await {
            SendOutcome::Retired => {
                still_owed = still_owed.saturating_sub(pinned_bytes);
                node.cids.extend(targets);
            }
            SendOutcome::Deferred => {}
            SendOutcome::RegistryDown => registry_up = false,
        }
    }
    Some(ReclaimPass { still_owed, stalls })
}

/// What one reclaim pass left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimPass {
    /// The pinned bytes still owed after the pass — the vault's pending figure.
    pub still_owed: u64,
    /// One entry per debt the pass could not settle, in ledger order, capped at
    /// one registry batch.
    pub stalls: Vec<ReclaimStall>,
}

/// A debt the reclaim pass left owed, and why.
///
/// Reclaim is the one path with no attempt budget and no dead-letter class, so a
/// debt that never settles otherwise sits behind a byte figure that says nothing
/// is pending — a stall a host cannot tell from an empty ledger
/// (blueprint/engine.md "never a silent failure").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimStall {
    /// The node owing the debt.
    pub node: [u8; 16],
    /// The doomed version's root `contentCid`.
    pub target: String,
    /// What stopped it.
    pub reason: ReclaimStallReason,
}

/// Why a debt did not settle. Public-plane classification only — node ids and
/// content addresses, never key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimStallReason {
    /// The owing node's currently published record, or a version it names,
    /// could not be established this pass, so nothing may be named against it.
    /// Self-clearing while it is an outage; permanent while a version of that
    /// node has a root no source will serve, which anyone holding the scope's
    /// write seed can author.
    NodeUnreadable,
    /// The node's currently published record still names this doomed root, so
    /// the shortening it belongs to has not landed. Self-clearing on the
    /// publish that drops it; permanent where a retained version names it, which
    /// pins the debt for as long as that version stands.
    TargetStillLive,
    /// The doomed root itself could not be expanded — no source served the block,
    /// or the manifest is not this version's — so what the retire would name is
    /// unknown. The figure falls back to the ceiling the prune quoted.
    TargetUnexpandable,
}

/// One owed entry's whole expansion, off its own fetched root block. `None`
/// leaves the entry owed for the figure the prune quoted: a root no source
/// served, or a manifest that is not this version's.
async fn expand_owed<H: Http>(
    entry: &OwedRetire,
    gateway: &Gateway,
    http: &H,
    profile: &ContentProfile,
) -> Option<Expansion> {
    let expected = decode_content_cid_str(&entry.target).ok()?;
    let root_block = read_block(gateway, http, &entry.target, &expected, ContentPlane::Root)
        .await
        .ok()?;
    expand_retire_targets(&entry.target, &root_block, profile, entry.manifest_bytes).ok()
}

/// How one owed entry's registry call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    /// The entry is settled and owes nothing further.
    Retired,
    /// A store that would not take the settle, or a target set the entry cannot
    /// name in full. It stays owed and the pass moves on.
    Deferred,
    /// The registry refused or could not be reached — not this entry's fault,
    /// and not the next one's either.
    RegistryDown,
}

/// Hand `targets` to the registry on behalf of `owner_name` and settle the
/// entry. Every target is a content CID the owning record references, so the
/// whole set goes record-scoped ([`LiveRecord`]).
///
/// The settle lands **between** the leaf batches and the root's own final batch.
/// The root is the expansion key, so an entry still owed once its root is gone
/// could never be re-expanded and would owe forever; settling first trades that
/// for a bounded leak — one root block, on the narrow window where the final
/// batch never lands.
async fn send_retire<L, H, C>(
    entry: &OwedRetire,
    owner_name: &str,
    targets: &[String],
    ledger: &L,
    owner_tag: &[u8],
    api: &ApiClient<H, C>,
) -> SendOutcome
where
    L: RetireLedger,
    H: Http,
    C: CredentialStore,
{
    // The expansion key must ride the final batch, so an entry whose own root a
    // live record holds back cannot name the rest of its set either.
    let Some((root, leaves)) = targets.split_last() else {
        return SendOutcome::Deferred;
    };
    if root != &entry.target {
        return SendOutcome::Deferred;
    }
    if retire_chunked(api, Some(owner_name), leaves).await.is_err() {
        return SendOutcome::RegistryDown;
    }
    if ledger
        .settle(owner_tag, core::slice::from_ref(&entry.target))
        .await
        .is_err()
    {
        return SendOutcome::Deferred;
    }
    // Past the settle the debt is discharged, so a refused root batch is a leaked
    // pin row rather than a reason to re-own it.
    let _ = retire_chunked(api, Some(owner_name), core::slice::from_ref(root)).await;
    SendOutcome::Retired
}

/// Whether the old scope-root name may be retired yet. **Stubbed to `false`**
/// until two things land: a durable record of when the re-point published — the
/// instant the window is measured from — and a measured value for the window
/// itself, whose slot
/// ([`SyncTimingProfile::migration_window`](crate::profile::SyncTimingProfile::migration_window))
/// still carries a placeholder. Retirement is irreversible, so until both land
/// the root never auto-retires and a revokee or lagging reader can always chase
/// the tombstone to the new root (blueprint/engine.md "Open edges:
/// Migration-window closure").
pub fn root_retire_ready() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};

    use cipherbox_core::suite::x25519::X25519Secret;

    use super::*;
    use crate::api::RetireEntry;
    use crate::seams::{HttpMethod, HttpResponse};
    use crate::testkit::fakes::{InMemoryCredentialStore, InMemoryStagingStore, ScriptedHttp};
    use crate::testkit::{
        SeededEntropy, block_on, doomed_version, gateway, requested_cid, retire_targets,
    };

    fn client() -> (
        ScriptedHttp,
        ApiClient<ScriptedHttp, InMemoryCredentialStore>,
    ) {
        let http = ScriptedHttp::default();
        let client = ApiClient::new(
            http.clone(),
            InMemoryCredentialStore::default(),
            "http://api.test",
        );
        (http, client)
    }

    /// The registry's own answer to a retire, as the ledger's done-signal reads
    /// it. `None` is a refusal.
    fn retire_answer(retired: Option<u64>) -> HttpResponse {
        HttpResponse {
            status: if retired.is_some() { 200 } else { 503 },
            headers: Vec::new(),
            body: format!(
                r#"{{"retired":{},"unpinned":0}}"#,
                retired.unwrap_or_default()
            )
            .into_bytes(),
        }
    }

    #[test]
    fn empty_retire_is_a_no_op_with_no_request() {
        let (http, client) = client();
        block_on(retire(&client, &[])).expect("empty retire");
        assert!(http.requests().is_empty(), "no targets means no API call");
    }

    #[test]
    fn retire_posts_the_batch_to_the_registry() {
        let (http, client) = client();
        http.enqueue_response(retire_answer(Some(1)));
        block_on(retire(&client, &["k51interior".to_owned()])).expect("retire");
        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert!(requests[0].url.ends_with("/registry/retire"));
    }

    /// The account-wide form drops every record's edge, so it is reserved for a
    /// target no record owns: an orphaned head block, and the interior names a
    /// name wave retires.
    #[test]
    fn the_account_wide_retire_names_no_owning_record() {
        let (http, client) = client();
        http.enqueue_response(retire_answer(Some(1)));
        http.enqueue_response(retire_answer(Some(1)));

        block_on(retire(&client, &["k51interior".to_owned()])).expect("retire");
        let heads = OrphanHeads::default();
        heads.record("bafyorphanhead");
        block_on(heads.retire_pending(&client));

        assert_eq!(
            retire_entries(&http),
            vec![
                (None, vec!["k51interior".to_owned()]),
                (None, vec!["bafyorphanhead".to_owned()]),
            ],
            "neither target answers to a record, so every reference goes"
        );
    }

    /// A leaf a doomed root aliased from another live node stays pinned only if
    /// the registry knows whose edge to drop, which no client can decide.
    #[test]
    fn an_owed_retire_scopes_every_batch_to_the_owning_record() {
        let (entry, root_block, leaf_cids) = owed_version(&[3u8; 100]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (_, owed) = drain(&store, OWNER, &http);
        assert!(owed.is_empty(), "the pass settles the debt");

        let owner = Some(OWNER_NAME.to_owned());
        assert_eq!(
            retire_entries(&http),
            vec![
                (owner.clone(), leaf_cids),
                (owner, vec![entry.target.clone()]),
            ],
            "the leaves and the expansion key both name the record that owed them"
        );
    }

    #[test]
    fn an_oversize_batch_splits_into_chunks_the_server_accepts() {
        let (http, client) = client();
        let targets: Vec<String> = (0..REGISTRY_BATCH_MAX + 1)
            .map(|i| format!("cid{i}"))
            .collect();
        for _ in 0..2 {
            http.enqueue_response(retire_answer(Some(1)));
        }
        block_on(retire(&client, &targets)).expect("retire");

        let requests = http.requests();
        assert_eq!(requests.len(), 2, "the batch splits at the server's cap");
        let sent: Vec<String> = requests
            .iter()
            .flat_map(|request| {
                retire_targets(request.body.as_deref().expect("a retire call has a body"))
            })
            .collect();
        assert_eq!(
            sent, targets,
            "every target still reaches the registry once"
        );
    }

    // -----------------------------------------------------------------------
    // The retire ledger.
    // -----------------------------------------------------------------------

    const OWNER: &[u8] = b"owner-tag";
    const OTHER_OWNER: &[u8] = b"another-owner-tag";

    /// One test session's bookkeeping custody. The key is fixed so fixtures
    /// that write and read across separate sessions are one identity; the
    /// entropy stream is not, so no two seals in a run share an ephemeral.
    struct Session {
        secret: X25519Secret,
        entropy: RefCell<SeededEntropy>,
    }

    impl Session {
        fn new() -> Self {
            Self::of(0x5e)
        }

        fn of(scalar: u8) -> Self {
            static NEXT_SEED: AtomicU64 = AtomicU64::new(1);
            Self {
                secret: X25519Secret::from_scalar([scalar; 32]),
                entropy: RefCell::new(SeededEntropy::new(
                    NEXT_SEED.fetch_add(1, Ordering::Relaxed),
                )),
            }
        }

        fn ledger<'a>(
            &'a self,
            store: &'a InMemoryStagingStore,
        ) -> StagingRetireLedger<'a, InMemoryStagingStore> {
            StagingRetireLedger::new(store, BookkeepingSeal::new(&self.secret, &self.entropy))
        }
    }

    /// The node every fixture debt is owed against — one file's history, which
    /// is the shape a prune journals.
    const NODE: [u8; 16] = [0x3B; 16];

    /// The debt a prune journals for one sealed version.
    fn owed_version(plaintext: &[u8]) -> (OwedRetire, Vec<u8>, Vec<String>) {
        let (version, root_block, leaf_cids) = doomed_version(plaintext);
        (
            OwedRetire::whole(NODE, version.content_cid, version.pinned_bytes),
            root_block,
            leaf_cids,
        )
    }

    /// A transport serving each named root block off the gateway and answering
    /// the registry with `retired` — `None` being a refusal. A root the list
    /// omits is one no source will serve.
    fn blocks_http(blocks: Vec<(String, Vec<u8>)>, retired: Option<u64>) -> ScriptedHttp {
        let http = ScriptedHttp::default();
        for _ in 0..64 {
            let blocks = blocks.clone();
            http.enqueue_derived(move |request| {
                if request.url.ends_with("/registry/retire") {
                    return Ok(retire_answer(retired));
                }
                let requested = requested_cid(&request.url);
                match blocks.iter().find(|(cid, _)| *cid == requested) {
                    Some((_, block)) => Ok(HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: block.clone(),
                    }),
                    None => Err(SeamError::new("no such block")),
                }
            });
        }
        http
    }

    /// The single-entry case: an absent `root_block` is a root no source serves.
    fn ledger_http(
        entry: &OwedRetire,
        root_block: Option<Vec<u8>>,
        retired: Option<u64>,
    ) -> ScriptedHttp {
        let blocks = root_block
            .map(|block| vec![(entry.target.clone(), block)])
            .unwrap_or_default();
        blocks_http(blocks, retired)
    }

    /// The retire calls the pass made, one entry per batch, in order.
    fn retire_batches(http: &ScriptedHttp) -> Vec<Vec<String>> {
        retire_entries(http)
            .into_iter()
            .map(|(_, targets)| targets)
            .collect()
    }

    /// Every retire batch the pass sent, as the record it names and its targets.
    fn retire_entries(http: &ScriptedHttp) -> Vec<(Option<String>, Vec<String>)> {
        http.requests()
            .iter()
            .filter(|request| request.url.ends_with("/registry/retire"))
            .flat_map(|request| {
                serde_json::from_slice::<Vec<RetireEntry>>(
                    request.body.as_deref().expect("a retire call has a body"),
                )
                .expect("a retire body is a JSON array of entries")
            })
            .map(|entry| (entry.ipns_name, entry.targets))
            .collect()
    }

    /// Every target the pass handed the registry, batch order preserved.
    fn retired_targets(http: &ScriptedHttp) -> Vec<String> {
        retire_batches(http).into_iter().flatten().collect()
    }

    /// The owning record every test pass answers with: one node, so one name.
    const OWNER_NAME: &str = "k51qzowningrecord";

    /// What the drain's own `live` closure answers, over a fixed name.
    fn owning(cids: BTreeSet<String>) -> LiveRecord {
        LiveRecord {
            name: OWNER_NAME.to_owned(),
            cids,
        }
    }

    /// A pass over the ledger against `live` — the CIDs the owing node's
    /// published record still reaches, `None` being a pass that could not
    /// establish them.
    fn drain_against(
        store: &InMemoryStagingStore,
        owner: &[u8],
        http: &ScriptedHttp,
        live: Option<BTreeSet<String>>,
    ) -> (u64, Vec<OwedRetire>) {
        let session = Session::new();
        let ledger = session.ledger(store);
        let api = ApiClient::new(
            http.clone(),
            InMemoryCredentialStore::default(),
            "http://api.test",
        );
        let remaining = block_on(drain_owed_retires(
            &ledger,
            owner,
            &api,
            &gateway(),
            http,
            &ContentProfile::CI,
            async |_, _| live.clone().map(owning),
        ))
        .expect("the ledger reads");
        (
            remaining.still_owed,
            block_on(ledger.owed(owner)).expect("owed"),
        )
    }

    /// A pass whose node's record reaches nothing but the doomed versions.
    fn drain(
        store: &InMemoryStagingStore,
        owner: &[u8],
        http: &ScriptedHttp,
    ) -> (u64, Vec<OwedRetire>) {
        drain_against(store, owner, http, Some(BTreeSet::new()))
    }

    fn owe(store: &InMemoryStagingStore, owner: &[u8], entry: &OwedRetire) {
        let session = Session::new();
        block_on(
            session
                .ledger(store)
                .owe(owner, core::slice::from_ref(entry)),
        )
        .expect("owe");
    }

    #[test]
    fn a_drained_entry_retires_every_leaf_before_its_root_and_settles() {
        let plaintext: Vec<u8> = (0..100u8).collect();
        let (entry, root_block, leaf_cids) = owed_version(&plaintext);
        assert!(
            leaf_cids.len() > 1,
            "a multi-chunk version is the normal case"
        );
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);

        assert_eq!(
            retire_batches(&http),
            vec![leaf_cids, vec![entry.target.clone()]],
            "every leaf goes first; the expansion key rides its own final batch"
        );
        assert!(owed.is_empty(), "the registry's answer settles the entry");
        assert_eq!(remaining, 0, "nothing is still owed");
    }

    /// The root is the expansion key, so an entry still owed once its root is
    /// gone could never be re-expanded. The settle therefore lands *before* the
    /// root batch: a refused root leaks one pin row, where the other order owes
    /// forever.
    #[test]
    fn the_entry_settles_before_its_root_goes_so_a_refused_root_cannot_strand_it() {
        let (entry, root_block, leaf_cids) = owed_version(&[8u8; 40]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        // The leaf batch is answered; the root's own batch is not.
        let http = ScriptedHttp::default();
        let leaves = leaf_cids.clone();
        let cid = entry.target.clone();
        for _ in 0..32 {
            let (cid, leaves, root_block) = (cid.clone(), leaves.clone(), root_block.clone());
            http.enqueue_derived(move |request| {
                if request.url.ends_with("/registry/retire") {
                    let sent = retire_targets(request.body.as_deref().unwrap_or_default());
                    return Ok(retire_answer((sent == leaves).then_some(1)));
                }
                if requested_cid(&request.url) == cid {
                    return Ok(HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: root_block,
                    });
                }
                Err(SeamError::new("no such block"))
            });
        }
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert!(
            owed.is_empty(),
            "the debt is discharged once the leaves are gone"
        );
        assert_eq!(remaining, 0);
    }

    /// The done-signal is the registry's own answer, and a zero count is its
    /// positive form: the rows are gone, whether this call deleted them or a
    /// replay of a lost response did.
    #[test]
    fn a_retire_reporting_nothing_deleted_still_settles_the_entry() {
        let (entry, root_block, _) = owed_version(&[7u8; 40]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(0));
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert!(owed.is_empty());
        assert_eq!(remaining, 0);
    }

    #[test]
    fn a_refused_retire_keeps_the_debt_and_reports_it_as_pending() {
        let (entry, root_block, _) = owed_version(&[3u8; 40]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), None);
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert_eq!(owed, vec![entry.clone()], "a refusal discards nothing");
        assert_eq!(
            remaining, entry.owed_bytes,
            "the vault still owes what the retire did not free"
        );
    }

    /// The root is the expansion key. Without it the leaves are unnameable, so
    /// the entry backs off rather than retiring a root whose leaves would then
    /// be charged forever.
    #[test]
    fn an_unfetchable_root_retires_nothing_and_stays_owed() {
        let (entry, ..) = owed_version(&[4u8; 40]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, None, Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert!(
            retired_targets(&http).is_empty(),
            "a root that cannot be expanded retires nothing at all"
        );
        assert_eq!(owed, vec![entry.clone()]);
        assert_eq!(remaining, entry.owed_bytes);
    }

    /// Another account's token deletes no rows and answers the done-signal, so a
    /// pass under the wrong owner must never reach the debt.
    #[test]
    fn a_pass_under_another_owner_tag_neither_retires_nor_settles() {
        let (entry, root_block, _) = owed_version(&[5u8; 40]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OTHER_OWNER, &http);
        assert!(retired_targets(&http).is_empty());
        assert_eq!(remaining, 0, "the other owner owes nothing");
        assert!(owed.is_empty());
        assert_eq!(
            block_on(Session::new().ledger(&store).owed(OWNER)).expect("owed"),
            vec![entry],
            "the debt is untouched"
        );
    }

    /// A version past one batch is the normal case at the frozen framing, and
    /// resumability rests on the root surviving until every leaf is named.
    #[test]
    fn a_partially_retired_entry_stays_owed_and_replays_whole() {
        let (entry, root_block, leaf_cids) = owed_version(&[6u8; 100]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        // The first pass loses the registry.
        let failing = ledger_http(&entry, Some(root_block.clone()), None);
        let (remaining, owed) = drain(&store, OWNER, &failing);
        assert_eq!(owed, vec![entry.clone()]);
        assert_eq!(remaining, entry.owed_bytes);

        // The second re-expands from the still-pinned root and names the whole
        // set again — idempotent server-side, so a replay is a no-op.
        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert_eq!(
            retired_targets(&http),
            leaf_cids
                .into_iter()
                .chain([entry.target])
                .collect::<Vec<_>>()
        );
        assert!(owed.is_empty());
        assert_eq!(remaining, 0);
    }

    /// A doomed root's link list is not this device's word for what that version
    /// holds: anyone with the scope's write seed can author one naming leaves the
    /// account is living on. A CID the live set names must never reach the
    /// registry, and the vault must owe only what the rest frees.
    #[test]
    fn a_cid_a_live_record_still_reaches_is_never_named_by_the_retire() {
        let (entry, root_block, leaf_cids) = owed_version(&[9u8; 100]);
        let expansion = expand_retire_targets(
            &entry.target,
            &root_block,
            &ContentProfile::CI,
            entry.manifest_bytes,
        )
        .expect("expands");
        let hostage = leaf_cids[0].clone();
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain_against(
            &store,
            OWNER,
            &http,
            Some(BTreeSet::from([hostage.clone()])),
        );

        assert_eq!(
            retired_targets(&http),
            leaf_cids[1..]
                .iter()
                .cloned()
                .chain([entry.target.clone()])
                .collect::<Vec<_>>(),
            "the live target is skipped; everything else keeps its order"
        );
        assert!(owed.is_empty(), "the entry still settles");
        assert_eq!(remaining, 0);
        assert!(
            expansion.minus(&BTreeSet::from([hostage])).pinned_bytes < expansion.pinned_bytes,
            "an aliased expansion frees less than its manifest accounts for"
        );
    }

    /// The debt is journaled ahead of the shortened record, so an entry whose
    /// target a live record still reaches is one whose publish has not landed.
    /// Nothing is pending reclaim while that holds.
    #[test]
    fn an_entry_a_live_record_still_names_retires_nothing_and_owes_nothing_yet() {
        let (entry, root_block, _) = owed_version(&[4u8; 100]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain_against(
            &store,
            OWNER,
            &http,
            Some(BTreeSet::from([entry.target.clone()])),
        );

        assert!(
            retired_targets(&http).is_empty(),
            "a target a record still names retires nothing at all"
        );
        assert_eq!(owed, vec![entry], "and the debt waits for the shortening");
        assert_eq!(remaining, 0, "live content is not pending reclaim");
    }

    /// Without the live set a retire would unpin whatever it failed to read, so
    /// the pass stands down and reports the ledger's own figures.
    #[test]
    fn a_pass_that_cannot_establish_what_is_live_retires_nothing() {
        let (entry, root_block, _) = owed_version(&[5u8; 100]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain_against(&store, OWNER, &http, None);

        assert!(retired_targets(&http).is_empty());
        assert_eq!(owed, vec![entry.clone()], "the debt stands");
        assert_eq!(remaining, entry.owed_bytes);
    }

    /// A pin row is keyed `(account, cid)`, so a leaf two doomed roots both name
    /// is one row: the first entry to name it carries it, and the pass reports
    /// its bytes once.
    #[test]
    fn a_cid_two_entries_share_is_named_by_exactly_one_of_them() {
        let (first, first_block, first_leaves) = owed_version(&[6u8; 100]);
        let (second, second_block, _) = owed_version(&[7u8; 100]);
        let shared = first_leaves[0].clone();
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &first);
        owe(&store, OWNER, &second);

        // A second root that content-addresses correctly and names the first's
        // leading leaf — what a write-grantee can put on the wire.
        let http = blocks_http(
            vec![
                (first.target.clone(), first_block),
                (second.target.clone(), second_block),
            ],
            Some(1),
        );
        let (remaining, owed) = drain(&store, OWNER, &http);

        assert_eq!(
            retired_targets(&http)
                .iter()
                .filter(|cid| **cid == shared)
                .count(),
            1,
            "one pin row is named by one retire"
        );
        assert!(owed.is_empty(), "both entries settle");
        assert_eq!(remaining, 0);
    }

    /// The stored figure is the only record of what was owed, so bytes this
    /// build did not write read as no entry at all rather than as a figure.
    #[test]
    fn a_stored_entry_this_build_did_not_write_reads_as_nothing() {
        let (entry, ..) = owed_version(&[1u8; 40]);
        let cid = StagingRetireLedger::<InMemoryStagingStore>::cid(&entry.target).expect("a CID");
        let stored = encode_entry(&entry, &cid);
        assert_eq!(
            decode_entry(&stored, &cid),
            // The target rides the key, so the value round-trips without it.
            Some(OwedRetire {
                target: String::new(),
                ..entry.clone()
            }),
            "a round trip is the whole entry"
        );
        for bytes in [
            Vec::new(),
            vec![0u8; ENTRY_HEAD_LEN - 1],
            [&stored[..], &[7u8]].concat(),
        ] {
            assert_eq!(decode_entry(&bytes, &cid), None);
        }
    }

    /// A replayed prune must not move what the vault reports as pending.
    #[test]
    fn re_oweing_a_held_target_keeps_the_stored_figures() {
        let (entry, ..) = owed_version(&[2u8; 100]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);
        owe(
            &store,
            OWNER,
            &OwedRetire {
                owed_bytes: entry.owed_bytes + 99,
                manifest_bytes: entry.manifest_bytes + 99,
                ..entry.clone()
            },
        );
        assert_eq!(
            block_on(Session::new().ledger(&store).owed(OWNER)).expect("owed"),
            vec![entry]
        );
    }

    /// The class a hard delete journals is the one the pass asks `live` about,
    /// and it survives the store: without it the delete's debt would sit against
    /// a never-discard ledger forever.
    #[test]
    fn a_hard_deletes_debt_settles_against_an_empty_live_set() {
        let (version, root_block, leaf_cids) = doomed_version(&[8u8; 100]);
        let entry =
            OwedRetire::whole_retired(NODE, version.content_cid.clone(), version.pinned_bytes);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let asked: RefCell<Vec<OwingRecord>> = RefCell::new(Vec::new());
        let remaining = block_on(drain_owed_retires(
            &Session::new().ledger(&store),
            OWNER,
            &ApiClient::new(
                http.clone(),
                InMemoryCredentialStore::default(),
                "http://api.test",
            ),
            &gateway(),
            &http,
            &ContentProfile::CI,
            // What `live_owing_record` answers for a node the delete unlinked:
            // no live listing reaches it, whatever its lingering record names.
            async |_, owing| {
                asked.borrow_mut().push(owing);
                Some(owning(BTreeSet::new()))
            },
        ))
        .expect("the ledger reads");

        assert_eq!(
            asked.into_inner(),
            vec![OwingRecord::Retired],
            "the stored class reaches the live-set read"
        );
        let retired = retired_targets(&http);
        for leaf in leaf_cids {
            assert!(retired.contains(&leaf), "every leaf retires");
        }
        assert_eq!(remaining.still_owed, 0);
        assert!(remaining.stalls.is_empty(), "and stalls on nothing");
        assert!(
            block_on(Session::new().ledger(&store).owed(OWNER))
                .expect("owed")
                .is_empty(),
            "the debt settles instead of standing forever"
        );
    }

    /// A prune's debt against a node a later hard delete removed would otherwise
    /// be stranded: the class belongs to the node, not to the entry carrying it.
    #[test]
    fn one_hard_deleted_entry_settles_the_same_nodes_earlier_prune_debt() {
        let (pruned, pruned_block, _) = owed_version(&[9u8; 100]);
        let (version, deleted_block, _) = doomed_version(&[10u8; 100]);
        let deleted =
            OwedRetire::whole_retired(NODE, version.content_cid.clone(), version.pinned_bytes);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &pruned);
        owe(&store, OWNER, &deleted);

        let http = blocks_http(
            vec![
                (pruned.target.clone(), pruned_block),
                (deleted.target.clone(), deleted_block),
            ],
            Some(1),
        );
        let asked: RefCell<Vec<OwingRecord>> = RefCell::new(Vec::new());
        block_on(drain_owed_retires(
            &Session::new().ledger(&store),
            OWNER,
            &ApiClient::new(
                http.clone(),
                InMemoryCredentialStore::default(),
                "http://api.test",
            ),
            &gateway(),
            &http,
            &ContentProfile::CI,
            async |_, owing| {
                asked.borrow_mut().push(owing);
                Some(owning(BTreeSet::new()))
            },
        ))
        .expect("the ledger reads");

        assert_eq!(
            asked.into_inner(),
            vec![OwingRecord::Retired],
            "one read per node, and the delete decides its class"
        );
        assert!(
            block_on(Session::new().ledger(&store).owed(OWNER))
                .expect("owed")
                .is_empty(),
            "both debts settle"
        );
    }

    /// The class routes the read; it never overrides its answer. An entry
    /// mislabelled over a node that still publishes retires nothing that record
    /// names, because the live set the read returns is subtracted either way.
    #[test]
    fn a_mislabelled_hard_delete_cannot_unpin_what_a_live_record_names() {
        let (version, root_block, _) = doomed_version(&[11u8; 100]);
        let entry =
            OwedRetire::whole_retired(NODE, version.content_cid.clone(), version.pinned_bytes);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain_against(
            &store,
            OWNER,
            &http,
            Some(BTreeSet::from([entry.target.clone()])),
        );

        assert!(
            retired_targets(&http).is_empty(),
            "a target a live record still names retires nothing, whatever the entry claims"
        );
        assert_eq!(owed, vec![entry], "and the debt keeps waiting");
        assert_eq!(remaining, 0, "live content is not pending reclaim");
    }

    /// Per-owner staging bookkeeping joins the sealed tier
    /// ([`crate::sync::bookkeeping`]): the value at rest is an owner-local blob
    /// under this identity's `enc-subkey`, and a cleartext entry — the only
    /// shape a build that skipped the seal could write — reads as unwritten
    /// rather than as a debt.
    #[test]
    fn a_ledger_entry_is_sealed_at_rest() {
        let (entry, ..) = owed_version(&[21u8; 40]);
        let cid = StagingRetireLedger::<InMemoryStagingStore>::cid(&entry.target).expect("a CID");
        let key = StagingRetireLedger::<InMemoryStagingStore>::key(OWNER, &entry.target)
            .expect("a content CID keys an entry");
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let stored = block_on(store.staged_bytes(&key))
            .expect("read")
            .expect("the owe wrote it");
        assert_ne!(
            stored,
            encode_entry(&entry, &cid).to_vec(),
            "the entry grammar never reaches the store on its own"
        );
        assert_eq!(
            block_on(Session::new().ledger(&store).owed(OWNER)).expect("owed"),
            vec![entry.clone()],
            "and it round-trips under the owner's own key"
        );
        assert!(
            block_on(Session::of(0x21).ledger(&store).owed(OWNER))
                .expect("owed")
                .is_empty(),
            "another identity's key opens nothing"
        );

        block_on(store.put_staged_bytes(&key, &encode_entry(&entry, &cid))).expect("plant");
        assert!(
            block_on(Session::new().ledger(&store).owed(OWNER))
                .expect("owed")
                .is_empty(),
            "an unsealed value is no debt"
        );
    }

    /// The seal's AAD counts nothing per entry, so one sealed value opens under
    /// every key in this owner's scope. Moving one onto another target's key
    /// would hand the drain a debt whose liveness is judged against a record
    /// that never named it — so the stored CID must answer to the key's.
    #[test]
    fn a_ledger_value_transplanted_onto_another_target_reads_as_nothing() {
        let (mine, ..) = owed_version(&[31u8; 40]);
        let (theirs, ..) = owed_version(&[32u8; 40]);
        assert_ne!(mine.target, theirs.target, "two distinct doomed roots");

        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &mine);
        owe(&store, OWNER, &theirs);

        let from = StagingRetireLedger::<InMemoryStagingStore>::key(OWNER, &mine.target)
            .expect("a content CID keys an entry");
        let onto = StagingRetireLedger::<InMemoryStagingStore>::key(OWNER, &theirs.target)
            .expect("a content CID keys an entry");
        let blob = block_on(store.staged_bytes(&from))
            .expect("read")
            .expect("written");
        block_on(store.put_staged_bytes(&onto, &blob)).expect("transplant");

        assert_eq!(
            block_on(Session::new().ledger(&store).owed(OWNER)).expect("owed"),
            vec![mine],
            "the transplanted entry is no debt; its own key's entry still is"
        );
    }

    /// A class byte this build cannot read is not guessed: `Published` would
    /// strand a hard delete's debt and `Retired` would unpin a live node's
    /// content, so the entry reads as unwritten and is repaired by a re-owe.
    #[test]
    fn a_stored_entry_with_an_unknown_owing_class_reads_as_nothing() {
        let (entry, ..) = owed_version(&[12u8; 40]);
        let cid = StagingRetireLedger::<InMemoryStagingStore>::cid(&entry.target).expect("a CID");
        let mut stored = encode_entry(&entry, &cid).to_vec();
        stored[ENTRY_HEAD_LEN - 1] = 0xFE;
        assert_eq!(decode_entry(&stored, &cid), None);
    }

    #[test]
    fn root_never_auto_retires_pending_the_migration_window() {
        assert!(
            !root_retire_ready(),
            "the old root lingers until both a durable re-point instant and a measured migration window land"
        );
    }
}
