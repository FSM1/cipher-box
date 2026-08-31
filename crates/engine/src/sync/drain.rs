//! The metadata publish driver: turn queued intent ops into published,
//! resolvable records (blueprint/engine.md "Sync core", "Resolve/publish
//! pipeline").
//!
//! One pass rebases the durable queue onto gate-passing state ([`replay`]) and
//! publishes each applied op under one law: **a reference must never outlive
//! its referent**. Child before parent, dest-add before source-remove, and
//! strict FIFO stopping at the first failure — so a partial drain can leave an
//! unreferenced record but never a ref pointing at a name nothing resolves.
//!
//! Every published record is fed straight back through the adoption gate from
//! the bytes in hand: the write path skips the fetch, never the gate, and the
//! per-name sequence floor advances only as the gate's stage-6 consequence
//! (`gate/floor.rs` stays the only place floors move).
//!
//! What the pass does when a publish will not succeed is the failure valve
//! ([`Halt`]).
//!
//! A cross-scope relocation halts rather than publishing: its destination-epoch
//! re-seal is not a plan this driver authors. Its scope-exit trigger reaches
//! [`ReplayReport::scope_exit_triggers`](crate::sync::ReplayReport) all the
//! same, off the same [`replay`] this pass runs.

use core::cell::{Cell, RefCell};
use core::num::NonZeroU64;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::content::{
    decode_content_cid_str, encode_content_cid_str, is_wellformed_content_cid, verify_cid,
};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildRef, NodeKind, PreservedFields, ReadBody, Version, open_content_key, open_read_body,
};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::x25519::X25519Secret;
use futures_channel::mpsc;
use zeroize::Zeroizing;

use crate::api::{ApiClient, ApiError, QUOTA_EXCEEDED, REGISTRY_BATCH_REFUSED, UPLOAD_TOO_LARGE};
use crate::content::{
    ContentPlane, ContentProfile, ContentVersion, Expansion, Gateway, ProviderError, RootPlacement,
    SealedContent, expand_retire_targets, place_block, plan_prune, pre_flight_quota_check,
    read_block, validate_byo_config, version_cids,
};
use crate::entropy::{Entropy, fresh_nonce};
use crate::facade::{BlockProgress, Event, NodeId, OpPhase, emit_trust_violation};
use crate::gate::floor;
use crate::grants::{UndoDestAdd, undo_dest_add_versioned};
use crate::net::author::{
    AuthorError, AuthoredHead, ENVELOPE_V, EnvelopeAuthoring, NewNodeBody, author_child_envelope,
    author_scope_root_envelope, new_child,
};
use crate::net::publish::{PublishError, PublishOutcome, PublishReceipt};
use crate::net::record_publish::{
    HeadBinding, RecordPublishError, RecordPublishRequest, preflight, publish_record,
};
use crate::net::retire::{
    OrphanHeads, ReclaimStall, StagingRetireLedger, drain_owed_retires, orphaned_head, retire,
};
use crate::net::{
    Adopter, ChildAdopter, HeldKey, HeldRecord, HeldRecords, HeldValue, LocalHead, ResolveOutcome,
    RootAdopter, assemble_head_envelope, fanout_get_verify, resolve,
};
use crate::profile::SyncTimingProfile;
use crate::rotation::derive_write_name;
use crate::seams::{
    CredentialStore, FloorStore, Http, OpId, OwedRetire, OwingRecord, RecordTransport,
    RetireLedger, Scheduler, SeamResult, SnapshotCache, StagingStore,
};
use crate::session::SessionIdentity;
use crate::settings::{Destinations, Placement, PlacementDecision, SettingsRefusal};
use crate::storage_policy::StoragePolicy;
use crate::sync::BookkeepingSeal;
use crate::sync::cancel::UploadCancels;
use crate::sync::doomed::{
    MAX_JOURNAL_REPLAYS, MAX_QUARANTINE_ATTEMPTS, MAX_QUARANTINE_PROOFS, Quarantined, Reclamation,
    doomed_journal_key, journalled_keys, open_reclamation, record_matches_manifest,
    seal_reclamation,
};
use crate::sync::model::{Snapshot, collation_key};
use crate::sync::op::{NewNode, Op, OpKind, ScopeCrossing, StagedContent};
use crate::sync::overlay::apply_overlay;
use crate::sync::project::{project_child_version, project_folder};
use crate::sync::rebase::{AppliedOp, DeadLetterReason, decode_queue, replay};
use crate::sync::record::RecordReader;
use crate::sync::staging::{
    LiveBlocks, Preservation, PreservedBounds, preserve_dead_letter, reconcile_staging_over,
    release_version_blocks, version_leaf_cids,
};
use crate::sync::upload_mark::{Resume, encode_upload_mark, resume_from, upload_mark_key};

use crate::sync::tick::ResolveMode;

/// The staging-key prefix for the drained-op high-water mark: every op id at or
/// below the stored value has left this device's queue.
///
/// It lives in the staging store rather than the floors so the mark and the op
/// ids it names share one durability domain — a store that loses its queue
/// loses the mark with it, instead of retaining a mark that would delete every
/// id the restarted counter reissues.
pub const DRAINED_OP_MARK_PREFIX: &[u8] = b"cipherbox/drained-op/";

/// The staging-key prefix for the published-op high-water mark: every op id at
/// or below the stored value had the last record of its plan confirmed at its
/// name, so its version is live there even if the op is still queued. What it
/// is *for* is [`Drain::mark_published`].
pub const PUBLISHED_OP_MARK_PREFIX: &[u8] = b"cipherbox/published-op/";

/// One identity's key under `prefix`: the prefix followed directly by the owner
/// tag [`RecordReader`] classifies queue records against. Use it only where the
/// key ends at the tag — a prefix that appends a further suffix has to delimit
/// the tag itself, as [`StagingRetireLedger`](crate::net::StagingRetireLedger)
/// does.
///
/// The op-id high-water marks are the load-bearing case. The durable queue is
/// shared — a `RecordReader` holds another account's records as
/// [`Retained`](crate::sync::record::RecordClass::Retained) rather than
/// deleting them — and `OpId`s are per *store*, not per identity. A device-wide
/// high-water would therefore let one account's progress discard another's
/// queued op: as restore residue under the drained mark, or as already
/// published under the other.
///
/// [`orphan_staging_keys`] treats each such prefix as referenced, including
/// entries this session cannot read — their owner is exactly the identity that
/// still needs them.
///
/// [`orphan_staging_keys`]: crate::sync::staging::orphan_staging_keys
#[must_use]
pub fn owner_scoped_key(prefix: &[u8], enc_secret: &X25519Secret) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(&owner_tag(enc_secret));
    key
}

/// The tag every per-identity durable record this device keeps is scoped by —
/// the op-id marks and the retire ledger alike. One store is shared across
/// accounts, so an unscoped record would let one identity's progress reach
/// another's state.
#[must_use]
pub fn owner_tag(enc_secret: &X25519Secret) -> [u8; 32] {
    RecordReader::new(enc_secret).owner_tag()
}

/// What one drain pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DrainReport {
    /// Ops whose records published and self-adopted.
    pub(crate) published: Vec<OpId>,
    /// Ops rebase resolved away (already satisfied, or a lost race).
    pub(crate) dropped: Vec<OpId>,
    /// Terminally unrebasable ops, with the reason to surface.
    pub(crate) dead_letters: Vec<(OpId, NodeId, DeadLetterReason)>,
    /// Ops removed as restore residue: already drained on this device, so the
    /// queue that holds them is older than the completion record.
    pub(crate) restore_residue: Vec<OpId>,
    /// Delete targets this pass journaled, which the replay skips: their
    /// quarantine waits on a poll tick this pass has not had ([`Settle`]).
    pub(crate) journalled_deletes: Vec<NodeId>,
}

impl DrainReport {
    /// Whether the pass left the durable queue exactly as it found it.
    pub(crate) fn is_empty(&self) -> bool {
        self.published.is_empty()
            && self.dropped.is_empty()
            && self.dead_letters.is_empty()
            && self.restore_residue.is_empty()
    }
}

/// Per-op drain attempt counts, decoded from [`OP_ATTEMPTS_KEY`].
#[derive(Debug, Default)]
struct Attempts {
    counts: BTreeMap<OpId, u32>,
    /// Whether this pass changed the counts — an unchanged record is not
    /// rewritten, so an idle tick makes no staging write.
    dirty: bool,
}

impl Attempts {
    /// Decode the stored pairs. Bytes this build did not write decode as empty
    /// — the same rule the drained-op mark applies, and the fail-safe
    /// direction: an op is retried, never abandoned on unreadable bookkeeping.
    fn decode(stored: Option<Vec<u8>>) -> Self {
        let Some(bytes) = stored.filter(|bytes| {
            bytes.first() == Some(&ATTEMPT_FORMAT_V1) && bytes.len() % ATTEMPT_ENTRY_LEN == 1
        }) else {
            return Self::default();
        };
        Self {
            counts: bytes[1..]
                .chunks_exact(ATTEMPT_ENTRY_LEN)
                .map(|entry| {
                    let (id, count) = entry.split_at(8);
                    (
                        OpId(u64::from_be_bytes(id.try_into().expect("8 bytes"))),
                        u32::from_be_bytes(count.try_into().expect("4 bytes")),
                    )
                })
                .collect(),
            dirty: false,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.counts.len() * ATTEMPT_ENTRY_LEN);
        bytes.push(ATTEMPT_FORMAT_V1);
        for (op_id, count) in &self.counts {
            bytes.extend_from_slice(&op_id.0.to_be_bytes());
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        bytes
    }

    /// What `op_id` has been charged so far.
    fn charged_to(&self, op_id: OpId) -> u32 {
        self.counts.get(&op_id).copied().unwrap_or(0)
    }

    /// Charge one attempt to `op_id` and return its new count.
    fn charge(&mut self, op_id: OpId) -> u32 {
        self.dirty = true;
        let count = self.counts.entry(op_id).or_default();
        *count = count.saturating_add(1);
        *count
    }

    /// Drop every count whose op has left the queue, so the record cannot grow
    /// without bound and a reissued id inherits nothing.
    fn retain_live(&mut self, live: &BTreeSet<OpId>) {
        let before = self.counts.len();
        self.counts.retain(|op_id, _| live.contains(op_id));
        self.dirty |= self.counts.len() != before;
    }
}

/// What stopped a drain pass, and what the valve does about it. Strict
/// FIFO throughout: the op that stopped the pass keeps its place at the head of
/// the durable queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Halt {
    /// A reason the valve does not classify — a seam failure, an unreachable
    /// record plane, a load this pass could not do. Charged nothing and retried
    /// on the next tick, so an outage never abandons an op.
    Unclassified,
    /// The op's record reached the record plane and did not confirm. Charged
    /// against the attempt budget, because a retry re-signs at the same
    /// sequence and a jammed name would otherwise retry forever. The PUT was
    /// acked, so a record may be resolvable at the name and a spent budget
    /// hands nothing back — cutting a name a live record carries would leave a
    /// reference outliving its referent.
    Attempt,
    /// A refusal this pass cannot attribute, raised before the record it was
    /// authoring reached the transport: an upload, a registration, or a
    /// produce-side trust refusal. Charged like [`Halt::Attempt`], and a spent
    /// budget hands back a create's own derived name — the op's target is still
    /// unreachable, so no record a parent links names it.
    UploadAttempt,
    /// The authored head is over the block ceiling its own ingress enforces.
    /// Charged like an attempt, since no re-author shrinks it — a fresh nonce
    /// moves the sealed bytes and never their count — and hands back the same
    /// unreferenced create name [`Halt::UploadAttempt`] does, under its own
    /// dead-letter reason.
    HeadOversized,
    /// Classified-permanent: the same bytes are refused on every retry.
    Permanent(DeadLetterReason),
    /// The member's own settings were refused before any request was built.
    /// Not a failure of the op — it holds the head and its staging reservation
    /// until those settings change ([`SettingsHold`]).
    HeldBySettings(SettingsRefusal),
    /// Over the account quota. Not a failure of the op — it holds the head and
    /// its staging reservation until a quota probe reports room.
    Blocked {
        /// The byte count the refused upload asked for, and so the figure the
        /// resume probe must find room for.
        needed_bytes: u64,
    },
    /// The user cancelled the upload. The facade has already undone it, so the
    /// valve does nothing but stop the pass.
    Cancelled,
}

/// A failed publish, and whether its record nonetheless confirmed at its name.
/// The two are independent: the self-adopt and the snapshot-cache write both
/// run with the record already live, so a caller that compensates must branch on
/// the fact rather than re-read a name its own publish left stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublishHalt {
    halt: Halt,
    confirmed: bool,
}

impl PublishHalt {
    /// A failure raised before the record reached the transport.
    fn before_the_put(halt: Halt) -> Self {
        Self {
            halt,
            confirmed: false,
        }
    }

    /// A failure raised once the publish confirmed at its name.
    fn past_the_put(halt: Halt) -> Self {
        Self {
            halt,
            confirmed: true,
        }
    }
}

impl From<PublishHalt> for Halt {
    fn from(failure: PublishHalt) -> Self {
        failure.halt
    }
}

/// The one verdict every unrecoverable-content path returns: the version's key,
/// root, or a leaf is gone, and no retry brings any of them back.
const CONTENT_LOST: Halt = Halt::Permanent(DeadLetterReason::ContentUnrecoverable);

/// How many non-confirming publish attempts one op gets before it dead-letters.
///
/// Bounds a pathology, not a network outage — only [`Halt::Attempt`] and
/// [`Halt::UploadAttempt`] are charged.
const ATTEMPT_BUDGET: u32 = 5;

/// The staging key holding per-op drain attempt counts: a one-byte format tag
/// followed by `(op_id, attempts)` pairs, big-endian and fixed-width, rewritten
/// each pass over the live queue so a retired op's count leaves with it.
///
/// It lives in the staging store for the same reason [`DRAINED_OP_MARK_PREFIX`]
/// does — the counts and the op ids they name share one durability domain — and
/// [`orphan_staging_keys`] treats it as referenced. What the counts are *for* is
/// [`Drain::abandon`].
///
/// [`orphan_staging_keys`]: crate::sync::staging::orphan_staging_keys
pub const OP_ATTEMPTS_KEY: &[u8] = b"cipherbox/op-attempts";

/// The attempt record's format tag. The staging store is shared with whatever
/// build wrote it, so bytes that merely happen to be the right length must not
/// parse as counts — a fabricated count would abandon an op early.
const ATTEMPT_FORMAT_V1: u8 = 1;

/// One `(op_id, attempts)` pair as [`OP_ATTEMPTS_KEY`] stores it.
const ATTEMPT_ENTRY_LEN: usize = 12;

/// One read of the durable queue: this identity's decoded ops, and every id the
/// store holds — including other identities' and retained records', which the
/// attempt record must not reclaim.
struct Queue {
    mine: Vec<(OpId, Op)>,
    all_ids: BTreeSet<OpId>,
}

/// The queue head is held over rather than failed: the account quota refused
/// it, and it keeps its place and its staging reservation until a probe on a
/// later drain tick reports room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockedOp {
    /// The held op.
    pub op_id: OpId,
    /// The node the op targets, so a host can point at it.
    pub node: NodeId,
    /// The byte count the resume probe must find room for.
    pub needed_bytes: u64,
}

/// The queue head is held over rather than failed: the member's own settings
/// were refused before any request was built, so every retry reaches the same
/// verdict and charging one would spend the version's budget and then release
/// its staged blocks. It keeps its place and its staging reservation until the
/// settings name a placement that clears the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsHold {
    /// The held op.
    pub op_id: OpId,
    /// The node the op targets, so a host can point at it.
    pub node: NodeId,
    /// Which rule refused. Render it through [`SettingsRefusal::check`], which
    /// names the rule and never the endpoint or the bearer the settings carry.
    pub refusal: SettingsRefusal,
}

/// The owner-scope material one drain pass publishes under. Every field is
/// borrowed from the live session; the drain zeroizes none of it.
pub(crate) struct DrainScope<'a> {
    /// The vault root node — also the root scope id (the cold-start anchor).
    pub(crate) root: NodeId,
    /// The root's write-plane IPNS name.
    pub(crate) root_name: &'a IpnsName,
    /// The scope read seed per-node read keys derive from.
    pub(crate) read_scope_seed: &'a Zeroizing<[u8; 32]>,
    /// The scope write seed per-node IPNS names and signers derive from.
    pub(crate) write_scope_seed: &'a Zeroizing<[u8; 32]>,
    /// The owner's encryption secret (the root's own seed source, and the op
    /// queue's HPKE-to-self reader).
    pub(crate) enc_secret: &'a X25519Secret,
    /// The contact-anchored owner identity the gate verifies against.
    pub(crate) owner_identity: &'a EcdsaVerifier,
}

/// One drain pass over the durable queue, holding every seam it needs by
/// reference.
pub(crate) struct Drain<'a, T, H: Http, C: CredentialStore, F, S, St, Sch> {
    pub(crate) transport: &'a T,
    pub(crate) api: &'a ApiClient<H, C>,
    pub(crate) floors: &'a F,
    pub(crate) snapshot_cache: &'a S,
    pub(crate) staging: &'a St,
    pub(crate) scheduler: &'a Sch,
    pub(crate) http: &'a H,
    pub(crate) gateway: &'a Gateway,
    /// Where this session's bytes go. An `Err` holds every content op — the
    /// drain publishes no version it cannot place.
    pub(crate) placement: &'a PlacementDecision,
    pub(crate) profile: &'a SyncTimingProfile,
    /// Bounds what the preserved dead-letter set may hold, so abandoned versions
    /// cannot eat the device's staging budget.
    pub(crate) storage_policy: &'a StoragePolicy,
    /// Staging keys open write handles hold, which the pass's sweep must not
    /// collect.
    pub(crate) live_blocks: &'a RefCell<LiveBlocks>,
    /// The framing profile a version's pinned size is derived under — the same
    /// one the upload framed it at.
    pub(crate) content_profile: &'a ContentProfile,
    /// Seal nonces enter as injected entropy; the drain reads no RNG of its own.
    pub(crate) entropy: &'a RefCell<Box<dyn Entropy>>,
    /// The gate-passing base snapshot, repainted in place on each publish.
    pub(crate) base: &'a RefCell<Snapshot>,
    /// The live held-record set the liveness loop keeps alive.
    pub(crate) held: &'a RefCell<HeldRecords>,
    /// The over-quota hold, shared with the facade's read surface. It clears
    /// only here, on a quota probe reporting room.
    pub(crate) blocked: &'a RefCell<Option<BlockedOp>>,
    /// The settings-refused hold, shared with the facade's read surface. It
    /// clears only here, once `placement` no longer carries the refusal that
    /// took it.
    pub(crate) settings_hold: &'a RefCell<Option<SettingsHold>>,
    /// Pinned bytes the retire ledger still owes, shared with the facade's read
    /// surface. Rewritten at the end of every pass from the ledger itself.
    pub(crate) pending_reclaim: &'a Cell<u64>,
    /// Why the debts the last pass could not settle did not settle, shared with
    /// the facade's read surface. Replaced whole on every pass that reads the
    /// ledger, so a stall that clears stops being reported.
    pub(crate) reclaim_stalls: &'a RefCell<Vec<ReclaimStall>>,
    /// Head blocks this session's publishes orphaned, pending retirement.
    pub(crate) orphan_heads: &'a OrphanHeads,
    /// The upload-cancel interlock, shared with the facade's cancel command.
    pub(crate) cancels: &'a RefCell<UploadCancels>,
    /// The facade's outbound event stream, for upload progress.
    pub(crate) events: &'a mpsc::UnboundedSender<Event>,
}

/// One folder's current published state, carried across the ops of one pass so
/// each publish authors onto the previous one.
struct FolderState {
    /// The write-plane name this folder publishes under.
    name: IpnsName,
    /// The scope root carries the grant section and authors through a different
    /// envelope path; every other folder is a plain child record.
    is_scope_root: bool,
    envelope_unknown: PreservedFields,
    epoch_tag_unknown: PreservedFields,
    created_at: u64,
    modified_at: u64,
    children: Vec<ChildRef>,
    body_unknown: PreservedFields,
    /// The record sequence this folder was last loaded or published at.
    sequence: u64,
}

/// Where one child ref is going, under what name, and what it displaces —
/// rename, relink, and move all reduce to this.
struct MovePlan {
    /// The source parent the op anchored on.
    from_parent: NodeId,
    /// The destination parent; the source parent for a rename in place.
    dest: NodeId,
    /// `None` keeps the name the ref already carries. Zeroizing because the
    /// plan is destructured, so the field outlives the struct that held it.
    new_name: Option<Zeroizing<String>>,
    /// The node the rebase vacated at the destination name, if any.
    vacated: Option<NodeId>,
}

/// A published dest-add, as its compensation must invert it.
struct DestAdd {
    dest: NodeId,
    source: NodeId,
    target: NodeId,
    /// The ref the dest-add vacated in the same publish, if any.
    replaced: Option<ChildRef>,
    /// The dest sequence the add published at.
    cas_base: u64,
    modified_at: u64,
}

/// What one settle pass decided about a quarantined descendant.
enum Verdict {
    /// The proof held: the name and the debt are this delete's to spend.
    Release,
    /// A record this pass resolved does not answer to the owner's manifest, so
    /// the node is one a writer has moved on from.
    Refuse,
    /// Nothing this pass established decides it. It waits, under
    /// [`MAX_QUARANTINE_ATTEMPTS`].
    Retry,
}

/// Whether a settle pass may decide the reclamation's quarantined descendants,
/// and so what bounds the quarantine to one converged poll tick
/// (blueprint/engine.md "Retirement").
enum Settle<'a> {
    /// The delete's own pass. The snapshot it just repainted is this device's
    /// own work rather than a converged view of the plane.
    Hold,
    /// A later pass, with the proof budget it has left to spend.
    Decide(&'a mut usize),
}

/// One node a delete detaches: the name its record publishes under, and the
/// content roots its published history names ([`Drain::enumerate_doomed`]).
struct Doomed {
    node: NodeId,
    name: IpnsName,
    versions: Vec<ContentVersion>,
}

/// One node's record as loaded for re-authoring: the envelope fields a
/// republish must carry forward byte-stable (#27 D10) plus the opened body.
struct LoadedNode {
    name: IpnsName,
    sequence: u64,
    envelope_unknown: PreservedFields,
    epoch_tag_unknown: PreservedFields,
    body: ReadBody,
}

/// One version's blocks, uploaded and pinned.
struct UploadedVersion {
    /// The version the node's record carries.
    version: Version,
    /// Every content CID the registration names: the root first, then the
    /// leaves in file order.
    content_cids: Vec<String>,
    /// A dual write's external leg that did not take the bytes, reported rather
    /// than swallowed ([`OpPhase::ExternalPinFailed`]).
    external_failure: Option<ProviderError>,
    /// The mirror is short of blocks a previous pass released to a provider
    /// this session's settings no longer name ([`Resume::mirror_gap`]).
    mirror_gap: bool,
}

/// Attempts one op may spend on the member's own provider before its mirror is
/// abandoned for that version. A dual write completes when hosted succeeds and
/// external has either succeeded or exhausted its attempts (#34 D1), so the leg
/// needs attempts to spend — one refusal is a blip, not a verdict.
const MIRROR_ATTEMPTS: u32 = 3;

/// A dual write's best-effort mirror leg, carried across one op's blocks.
///
/// The budget is per op rather than per block because a provider that is down
/// refuses every block alike: spending a fresh budget on each would stall the
/// whole pass behind one dead endpoint, and a version the mirror has already
/// missed a block of is not one it can serve whatever the rest do.
struct MirrorLeg {
    /// Attempts left to spend. Reaching zero is what abandons the mirror: the
    /// block that spent the last one never landed on it.
    attempts: u32,
    /// The first refusal, reported once the leg is abandoned.
    refusal: Option<ProviderError>,
}

impl MirrorLeg {
    fn new() -> Self {
        Self {
            attempts: MIRROR_ATTEMPTS,
            refusal: None,
        }
    }

    /// Whether the mirror is short of this version. Refusals a later attempt
    /// recovered from are not: the block reached the provider.
    fn missed(&self) -> bool {
        self.attempts == 0
    }

    fn refused(&mut self, error: ProviderError) {
        self.attempts = self.attempts.saturating_sub(1);
        self.refusal.get_or_insert(error);
    }

    /// The refusal to report, which is one only where the mirror stayed short.
    fn failure(self) -> Option<ProviderError> {
        self.missed().then_some(self.refusal).flatten()
    }
}

/// One record as this pass published it.
struct Published {
    /// The sequence the self-adopt authenticated.
    sequence: u64,
    /// The live-set entry, held once something references the record.
    held: HeldRecord,
}

/// The scope state one pass mutates: the epoch every record is sealed at, and
/// the folders loaded so far in **ancestor-first load order**, which is also
/// the order the base repaint depends on.
struct Pass {
    epoch: u64,
    folders: Vec<(NodeId, FolderState)>,
    /// Delete targets this pass wrote a doomed-name journal entry for.
    journalled: Vec<NodeId>,
}

impl Pass {
    fn holds(&self, folder: NodeId) -> bool {
        self.folders.iter().any(|(id, _)| *id == folder)
    }

    fn insert(&mut self, folder: NodeId, state: FolderState) {
        self.folders.push((folder, state));
    }

    fn folder(&self, folder: NodeId) -> Result<&FolderState, Halt> {
        self.folders
            .iter()
            .find(|(id, _)| *id == folder)
            .map(|(_, state)| state)
            .ok_or(Halt::Unclassified)
    }

    fn folder_mut(&mut self, folder: NodeId) -> Result<&mut FolderState, Halt> {
        self.folders
            .iter_mut()
            .find(|(id, _)| *id == folder)
            .map(|(_, state)| state)
            .ok_or(Halt::Unclassified)
    }
}

impl<T, H, C, F, S, St, Sch> Drain<'_, T, H, C, F, S, St, Sch>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    S: SnapshotCache,
    St: StagingStore,
    Sch: Scheduler + Clone + 'static,
{
    /// This session's custody of its per-owner staging bookkeeping — the retire
    /// ledger and the doomed-name journal alike (`crate::sync::bookkeeping`).
    fn bookkeeping_seal<'s>(&'s self, scope: &'s DrainScope<'_>) -> BookkeepingSeal<'s> {
        BookkeepingSeal::new(scope.enc_secret, self.entropy)
    }

    /// Run one pass: rebase the queue onto gate-passing state and publish every
    /// applied op it can, stopping at the first it cannot, then clear what the
    /// pass orphaned.
    pub(crate) async fn run(&self, scope: &DrainScope<'_>) -> DrainReport {
        let report = self.drain_queue(scope).await;
        self.orphan_heads.retire_pending(self.api).await;
        // One enumeration serves every consumer below. A desktop vault stages
        // on the order of ten thousand keys, and each of these was listing the
        // whole set for itself. Taken after the queue loop, so a debt the pass
        // just journaled is in it.
        // A store that will not enumerate leaves both the ledger and the sweep
        // for the next pass: "no debt" and "no residue" are claims this one
        // cannot make.
        let Ok(staged) = self.staging.staged_keys().await else {
            return report;
        };
        // An X25519 base-point multiply, so the pass derives it once and threads
        // it through every consumer below.
        let owner = owner_tag(scope.enc_secret);
        let seal = self.bookkeeping_seal(scope);
        self.settle_journalled_deletes(scope, seal, &owner, &staged, &report.journalled_deletes)
            .await;
        if let Some(pass) = drain_owed_retires(
            &StagingRetireLedger::over(self.staging, seal, &staged),
            &owner,
            self.api,
            self.gateway,
            self.http,
            self.content_profile,
            async |node, owing| self.live_node_cids(scope, node, owing).await,
        )
        .await
        {
            self.pending_reclaim.set(pass.still_owed);
            *self.reclaim_stalls.borrow_mut() = pass.stalls;
        }
        reconcile_staging_over(
            self.staging,
            self.live_blocks,
            &staged,
            PreservedBounds::at(self.scheduler.now(), self.storage_policy, self.profile),
        )
        .await;
        report
    }

    async fn drain_queue(&self, scope: &DrainScope<'_>) -> DrainReport {
        let mut report = DrainReport::default();
        let Ok(Queue { mine, all_ids }) = self.queued_ops(scope, &mut report).await else {
            return report;
        };
        let queued = mine;
        if queued.is_empty() {
            self.clear_block();
            self.clear_settings_hold();
            return report;
        }
        let Ok(mut attempts) = self.load_attempts(&all_ids).await else {
            return report;
        };
        let _ = self.pass(scope, &queued, &mut report, &mut attempts).await;
        let _ = self.store_attempts(&attempts).await;
        let _ = self.mark_drained(scope, &queued, &report).await;
        report
    }

    async fn pass(
        &self,
        scope: &DrainScope<'_>,
        queued: &[(OpId, Op)],
        report: &mut DrainReport,
        attempts: &mut Attempts,
    ) -> Result<(), Halt> {
        if !self.quota_admits_the_held_head(queued).await {
            return Ok(());
        }
        if !self.settings_admit_the_held_head(queued) {
            return Ok(());
        }

        let mut pass = self.open_pass(scope).await?;
        let rebased = {
            let base = self.base.borrow();
            let ops: Vec<Op> = queued.iter().map(|(_, op)| op.clone()).collect();
            let local = apply_overlay(&base, &ops);
            // This session holds one scope, so its root is the only scope root
            // a full-depth exit walk can land on.
            replay(&base, &local, queued, &[scope.root])
        };

        for (op_id, reason) in &rebased.dead_letters {
            let Some((_, op)) = queued.iter().find(|(id, _)| id == op_id) else {
                continue;
            };
            // A terminally unrebasable op keeps its staged bytes, and this is
            // what keeps them reachable — and openable — once the abandonment
            // has dropped its record from the queue.
            let preserved = match op.content_root_cid() {
                Some(_) => self.preserve_dead_letter(*op_id).await?,
                None => Preservation::Kept,
            };
            self.abandon(scope, *op_id, op).await?;
            self.release_if_refused(preserved, op).await;
            report
                .dead_letters
                .push((*op_id, op.target, preserved.observed(*reason)));
        }
        // A drop is not an abandonment: `AlreadySatisfied` on a create is the
        // create having *landed*, so retiring its name would cut a live record
        // its parent already references.
        for (op_id, _) in &rebased.dropped {
            self.dequeue_op(*op_id).await?;
            report.dropped.push(*op_id);
        }

        for applied in &rebased.applied {
            let published = self
                .publish_applied(scope, &mut pass, applied, &rebased.rebased)
                .await;
            report.journalled_deletes.append(&mut pass.journalled);
            if let Err(halt) = published {
                self.apply_valve(scope, applied.op_id, &applied.op, halt, attempts, report)
                    .await;
                return Err(halt);
            }
            self.dequeue_op(applied.op_id).await?;
            self.cancels.borrow_mut().published(applied.op_id);
            report.published.push(applied.op_id);
        }
        Ok(())
    }

    /// Apply the failure valve to whatever stopped the pass at one op.
    async fn apply_valve(
        &self,
        scope: &DrainScope<'_>,
        op_id: OpId,
        op: &Op,
        halt: Halt,
        attempts: &mut Attempts,
        report: &mut DrainReport,
    ) {
        match halt {
            Halt::Unclassified => {}
            // The facade undid the op against the blocks it could see when the
            // cancel landed. One more can confirm inside that window — the
            // upload the drain was already awaiting — and it would be charged
            // with nothing left to reach it, so the complete set is retired
            // here. Idempotent, so the overlap with the facade's batch is a
            // no-op.
            //
            // The dequeue gates the retire on the rule the facade's own path
            // follows: the claim is published before that removal commits, so
            // an op reaching here may still be queued — and unpinning the
            // leading leaves of something still publishable would land a
            // version whose blocks are gone.
            Halt::Cancelled => {
                if self.dequeue_op(op_id).await.is_ok() {
                    self.retire_cancelled(op_id).await;
                }
            }
            Halt::Attempt | Halt::UploadAttempt | Halt::HeadOversized => {
                if attempts.charge(op_id) < ATTEMPT_BUDGET {
                    return;
                }
                // A spent budget is still a dead letter, so it keeps the
                // version and hands back at most the name no published record
                // ever reached ([`Halt`]).
                let (reason, owes_its_name) = match halt {
                    Halt::Attempt => (DeadLetterReason::AttemptsExhausted, false),
                    Halt::HeadOversized => (DeadLetterReason::HeadTooLarge, true),
                    _ => (DeadLetterReason::AttemptsExhausted, true),
                };
                let Ok(preserved) = self.preserve_dead_letter(op_id).await else {
                    return;
                };
                let handed_back = if owes_its_name {
                    self.retire_unreferenced_name(scope, op).await
                } else {
                    Ok(())
                };
                if handed_back.is_ok() && self.dequeue_op(op_id).await.is_ok() {
                    self.release_if_refused(preserved, op).await;
                    report
                        .dead_letters
                        .push((op_id, op.target, preserved.observed(reason)));
                }
            }
            // A conditional-edit loser keeps its staged version and retires
            // nothing: its own bytes may already be registered from a halted
            // upload of the version now at the name, and unpinning content a
            // live record names is loss where leaving rows charged is a leak.
            Halt::Permanent(reason @ DeadLetterReason::BaseSuperseded) => {
                let Ok(preserved) = self.preserve_dead_letter(op_id).await else {
                    return;
                };
                if self.dequeue_op(op_id).await.is_ok() {
                    self.release_if_refused(preserved, op).await;
                    report
                        .dead_letters
                        .push((op_id, op.target, preserved.observed(reason)));
                }
            }
            // A replayed create keeps its staged version for the same reason and
            // hands back the same name a spent budget does: the record standing
            // at it is one no published parent references, so its registry row
            // would otherwise be re-PUT for as long as the account holds it —
            // which for a restored replay keeps the resurrection candidate alive
            // at the owner's own expense.
            Halt::Permanent(reason @ DeadLetterReason::AlreadyPublished) => {
                let Ok(preserved) = self.preserve_dead_letter(op_id).await else {
                    return;
                };
                if self.retire_unreferenced_name(scope, op).await.is_ok()
                    && self.dequeue_op(op_id).await.is_ok()
                {
                    self.release_if_refused(preserved, op).await;
                    report
                        .dead_letters
                        .push((op_id, op.target, preserved.observed(reason)));
                }
            }
            Halt::Permanent(reason) => {
                self.dead_letter(scope, op_id, op, reason, report).await;
            }
            // One pass raises one halt, and each hold's own gate is what lets
            // go of it — so taking one drops the other rather than leaving two
            // cells claiming the same head for different reasons.
            Halt::Blocked { needed_bytes } => {
                self.clear_settings_hold();
                *self.blocked.borrow_mut() = Some(BlockedOp {
                    op_id,
                    node: op.target,
                    needed_bytes,
                });
            }
            Halt::HeldBySettings(refusal) => {
                self.clear_block();
                *self.settings_hold.borrow_mut() = Some(SettingsHold {
                    op_id,
                    node: op.target,
                    refusal,
                });
            }
        }
    }

    /// Whether a held head may be tried again this tick. A `GET /account/quota`
    /// probe reporting room is the hold's only exit, so an unanswered probe
    /// leaves it in place.
    async fn quota_admits_the_held_head(&self, queued: &[(OpId, Op)]) -> bool {
        let Some(blocked) = *self.blocked.borrow() else {
            return true;
        };
        if !still_queued(queued, blocked.op_id) {
            self.clear_block();
            return true;
        }
        let Ok(placement) = self.placement.as_ref() else {
            return false;
        };
        // Only the hosted leg is quota-gated, so no answer the quota endpoint
        // could give bears on a hold under a placement without one — and an
        // endpoint that will not answer would park the head on that question.
        if !placement.has_hosted_leg() {
            self.clear_block();
            return true;
        }
        let Ok(quota) = self.api.quota().await else {
            return false;
        };
        if pre_flight_quota_check(blocked.needed_bytes, &quota, true).is_err() {
            return false;
        }
        self.clear_block();
        true
    }

    fn clear_block(&self) {
        *self.blocked.borrow_mut() = None;
    }

    /// Whether a settings-held head may be tried again this tick: only once the
    /// placement this pass runs under stops reaching the verdict that took the
    /// hold.
    fn settings_admit_the_held_head(&self, queued: &[(OpId, Op)]) -> bool {
        let Some(hold) = *self.settings_hold.borrow() else {
            return true;
        };
        if still_queued(queued, hold.op_id)
            && settings_refusal(self.placement) == Some(hold.refusal)
        {
            return false;
        }
        self.clear_settings_hold();
        true
    }

    fn clear_settings_hold(&self) {
        *self.settings_hold.borrow_mut() = None;
    }

    /// This identity's queued ops, minus restore residue: an op at or below the
    /// durable drained-op mark already left this queue once, so the queue it
    /// came back in predates the completion record.
    async fn queued_ops(
        &self,
        scope: &DrainScope<'_>,
        report: &mut DrainReport,
    ) -> Result<Queue, Halt> {
        let raw = self.staging.queued_ops().await.map_err(seam)?;
        let all_ids = raw.iter().map(|(op_id, _)| *op_id).collect();
        let scan = decode_queue(&RecordReader::new(scope.enc_secret), &raw);
        if scan.mine.is_empty() {
            return Ok(Queue {
                mine: Vec::new(),
                all_ids,
            });
        }
        // `None` is "no op has ever drained here", not "id 0 drained": the seam
        // contract promises only strictly-increasing ids, so a host that starts
        // at 0 must not lose its first op.
        let drained = self.drained_mark(scope).await?;
        let published = published_op_mark(self.staging, scope.enc_secret)
            .await
            .map_err(seam)?;
        let mut mine = Vec::with_capacity(scan.mine.len());
        for (op_id, op) in scan.mine {
            if drained.is_some_and(|mark| op_id.0 <= mark) {
                self.dequeue_op(op_id).await?;
                report.restore_residue.push(op_id);
                continue;
            }
            // Its record publish was confirmed before the crash that left it
            // queued, so its version is already live: republishing it would
            // re-expose blocks a live record names to the cancel path.
            if published.is_some_and(|mark| op_id.0 <= mark) {
                self.dequeue_op(op_id).await?;
                self.release_staged_blocks(&op).await;
                report.dropped.push(op_id);
                continue;
            }
            mine.push((op_id, op));
        }
        Ok(Queue { mine, all_ids })
    }

    // -----------------------------------------------------------------------
    // Loading the folders a pass authors onto.
    // -----------------------------------------------------------------------

    /// Open a pass anchored on the scope root, whose epoch every record this
    /// pass seals is bound to.
    async fn open_pass(&self, scope: &DrainScope<'_>) -> Result<Pass, Halt> {
        let (root, epoch) = self.load_scope_root(scope).await?;
        let mut pass = Pass {
            epoch,
            folders: Vec::new(),
            journalled: Vec::new(),
        };
        self.repaint_folder(scope.root, &root.children, root.sequence, root.modified_at);
        pass.insert(scope.root, root);
        Ok(pass)
    }

    /// The scope root as currently published: its envelope's carried fields and
    /// its unsealed folder body, plus the scope epoch.
    async fn load_scope_root(&self, scope: &DrainScope<'_>) -> Result<(FolderState, u64), Halt> {
        let record_bytes = self
            .snapshot_cache
            .get(scope.root_name.as_str().as_bytes())
            .await
            .map_err(seam)?
            .ok_or(Halt::Unclassified)?;
        let (sequence, envelope) = assemble_head_envelope(
            self.gateway,
            self.http,
            scope.root_name,
            &record_bytes,
            None,
        )
        .await
        .map_err(|_| Halt::UploadAttempt)?;
        // The cache can be older than the floors — a restored data dir is
        // exactly that. The whole pass anchors here: this record's epoch
        // becomes the epoch every record it publishes is sealed at, so a
        // below-floor anchor would bind a stale epoch into the AAD while the
        // live session seed derives the key — records nobody can open. One
        // at-floor gate call covers both floors (encode-side of the gate's
        // stage-5 reject; security rule 8).
        floor::check(
            self.floors,
            scope.root_name.as_str().as_bytes(),
            &scope.root.0,
            sequence,
            envelope.epoch,
            floor::Strictness::AtFloor,
        )
        .await
        .map_err(|_| Halt::UploadAttempt)?;
        // Encode/decode fail-closed symmetry: this build authors exactly
        // `ENVELOPE_V`, so republishing a newer client's root would silently
        // downgrade `v` — the exact rollback the read-body AAD defends against.
        if envelope.v != ENVELOPE_V {
            return Err(Halt::Unclassified);
        }
        let read_key = self.node_read_key(scope, &scope.root.0);
        let body = open_read_body(&envelope, &read_key).map_err(|_| Halt::UploadAttempt)?;
        let ReadBody::Folder {
            created_at,
            modified_at,
            children,
            unknown,
        } = body
        else {
            return Err(Halt::Unclassified);
        };
        let epoch = envelope.epoch;
        Ok((
            FolderState {
                name: scope.root_name.clone(),
                is_scope_root: true,
                envelope_unknown: envelope.unknown,
                epoch_tag_unknown: envelope.epoch_tag_unknown,
                created_at,
                modified_at,
                children,
                body_unknown: unknown,
                sequence,
            },
            epoch,
        ))
    }

    /// Resolve the scope root through its own gate so the snapshot cache holds
    /// whatever the network now carries. Only a gate-passing adopt writes the
    /// cache, so a rejected or unreachable record leaves last-known-good.
    async fn refresh_scope_root_cache(&self, scope: &DrainScope<'_>) -> Result<(), Halt> {
        let adopter = RootAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            scope.enc_secret,
            scope.owner_identity,
            scope.root.0,
        );
        let resolved = resolve(
            self.transport,
            self.snapshot_cache,
            &adopter,
            scope.root_name,
            ResolveMode::CacheFirst,
        )
        .await
        .map_err(seam)?;
        // A gate failure is a trust violation, never staleness: re-authoring on
        // top of last-known-good while the record plane serves a rejected root
        // is exactly the fail-open this rule forbids.
        match resolved.outcome {
            ResolveOutcome::TrustViolation(_) => Err(Halt::Unclassified),
            _ => Ok(()),
        }
    }

    /// Resolve one non-root node's own record through the child pipeline and
    /// open it for re-authoring. The gate decides: only a record that passes
    /// the child bindings, the floors, and the AAD-bound unseal is authorable.
    async fn load_child_node(
        &self,
        scope: &DrainScope<'_>,
        epoch: u64,
        node: NodeId,
        mode: ResolveMode,
    ) -> Result<LoadedNode, Halt> {
        let name = derive_write_name(scope.write_scope_seed, &node.0);
        let adopter = ChildAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            scope.root.0,
            scope.read_scope_seed.clone(),
            node.0,
        );
        let resolved = resolve(self.transport, self.snapshot_cache, &adopter, &name, mode)
            .await
            .map_err(seam)?;
        let record_bytes = match resolved.outcome {
            // An adopt caches its own gate-passing bytes; the other two arms
            // carry theirs.
            ResolveOutcome::Adopted(_) => self
                .snapshot_cache
                .get(name.as_str().as_bytes())
                .await
                .map_err(seam)?
                .ok_or(Halt::Unclassified)?,
            ResolveOutcome::Current { record_bytes } => record_bytes,
            ResolveOutcome::NoUpdate => resolved.last_known_good.ok_or(Halt::Unclassified)?,
            ResolveOutcome::TrustViolation(_) => return Err(Halt::Unclassified),
        };
        let (adopted, envelope) = adopter
            .open_carried_at_floor(&name, &record_bytes)
            .await
            .map_err(|_| Halt::UploadAttempt)?;
        // The same two rollback guards the root load makes: this build authors
        // exactly `ENVELOPE_V`, and re-sealing a node at another epoch than the
        // scope's would cross the AAD epoch binding.
        if envelope.v != ENVELOPE_V || adopted.epoch != epoch {
            return Err(Halt::Unclassified);
        }
        Ok(LoadedNode {
            name,
            sequence: adopted.sequence,
            envelope_unknown: envelope.unknown,
            epoch_tag_unknown: envelope.epoch_tag_unknown,
            body: adopted.read_body,
        })
    }

    /// Make `folder` and every ancestor between it and the scope root available
    /// in `pass`, loading ancestor-first so the base repaint always has a parent
    /// to hang a projection off.
    async fn ensure_folder(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        folder: NodeId,
    ) -> Result<(), Halt> {
        if pass.holds(folder) {
            return Ok(());
        }
        let chain = {
            let base = self.base.borrow();
            let mut chain = base.ancestors(folder);
            chain.reverse();
            chain.push(folder);
            chain
        };
        // A folder whose chain does not reach the scope root is not a folder
        // this scope's write plane may author.
        if chain.first() != Some(&scope.root) {
            return Err(Halt::Unclassified);
        }
        for node in chain {
            if pass.holds(node) {
                continue;
            }
            let state = self.load_child_folder(scope, pass.epoch, node).await?;
            self.repaint_folder(node, &state.children, state.sequence, state.modified_at);
            pass.insert(node, state);
        }
        Ok(())
    }

    /// Load one non-root folder's state, refusing a node whose sealed body is
    /// not a folder (a kind transplant).
    async fn load_child_folder(
        &self,
        scope: &DrainScope<'_>,
        epoch: u64,
        folder: NodeId,
    ) -> Result<FolderState, Halt> {
        let loaded = self
            .load_child_node(scope, epoch, folder, ResolveMode::CacheFirst)
            .await?;
        let ReadBody::Folder {
            created_at,
            modified_at,
            children,
            unknown,
        } = loaded.body
        else {
            return Err(Halt::Unclassified);
        };
        Ok(FolderState {
            name: loaded.name,
            is_scope_root: false,
            envelope_unknown: loaded.envelope_unknown,
            epoch_tag_unknown: loaded.epoch_tag_unknown,
            created_at,
            modified_at,
            children,
            body_unknown: unknown,
            sequence: loaded.sequence,
        })
    }

    // -----------------------------------------------------------------------
    // The per-op publish plans.
    // -----------------------------------------------------------------------

    /// Publish one applied op's records, referent before reference.
    async fn publish_applied(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        rebased: &Snapshot,
    ) -> Result<(), Halt> {
        match &applied.op.kind {
            OpKind::Create { parent, node, .. } => {
                self.publish_create(scope, pass, applied, rebased, *parent, node)
                    .await
            }
            // The name lives only in the parent's child ref
            // (`crates/core/src/seal/body.rs`), so a rename never leaves the
            // folder it is already in.
            OpKind::Rename { .. } => {
                let parent = self.published_parent(applied.op.target)?;
                let plan = MovePlan {
                    from_parent: parent,
                    dest: parent,
                    new_name: Some(Zeroizing::new(
                        applied.effective_name.clone().ok_or(Halt::Unclassified)?,
                    )),
                    vacated: None,
                };
                self.publish_ref_move(scope, pass, applied, rebased, plan)
                    .await
            }
            OpKind::Delete { .. } => self.publish_delete(scope, pass, applied).await,
            OpKind::Relink {
                from_parent,
                new_parent,
                crossing: ScopeCrossing::Intra,
            } => {
                let plan = MovePlan {
                    from_parent: *from_parent,
                    dest: *new_parent,
                    new_name: None,
                    vacated: None,
                };
                self.publish_ref_move(scope, pass, applied, rebased, plan)
                    .await
            }
            OpKind::Move {
                from_parent,
                new_parent,
                crossing: ScopeCrossing::Intra,
                ..
            } => {
                let plan = MovePlan {
                    from_parent: *from_parent,
                    dest: *new_parent,
                    new_name: Some(Zeroizing::new(
                        applied.effective_name.clone().ok_or(Halt::Unclassified)?,
                    )),
                    // Only the node the rebase actually vacated loses its ref:
                    // one that won the conditional delete keeps its entry, and
                    // the move already resolved onto a name beside it.
                    vacated: applied.vacated,
                };
                self.publish_ref_move(scope, pass, applied, rebased, plan)
                    .await
            }
            OpKind::UpdateContent {
                content,
                base_version_cid,
            } => {
                self.publish_update_content(
                    scope,
                    pass,
                    applied,
                    content,
                    base_version_cid.as_deref(),
                )
                .await
            }
            OpKind::Prune { keep_latest } => {
                self.publish_prune(scope, pass, applied, *keep_latest).await
            }
            // A cross-scope relocation re-seals the moved subtree at the
            // destination epoch — a plan this driver does not author. Publishing
            // it as a plain ref move would carry the subtree into the
            // destination still sealed at the source epoch.
            OpKind::Relink { .. } | OpKind::Move { .. } => Err(Halt::Unclassified),
        }
    }

    /// Create: the new node's content blocks, then its own record, then the
    /// parent that names it — referent before reference at every step.
    async fn publish_create(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        rebased: &Snapshot,
        parent: NodeId,
        node: &NewNode,
    ) -> Result<(), Halt> {
        let name = Zeroizing::new(applied.effective_name.clone().ok_or(Halt::Unclassified)?);
        self.ensure_folder(scope, pass, parent).await?;
        // After the parent loads, so the scope-chain refusal precedes the
        // probe's own network read.
        if self
            .create_replays_a_publish(scope, applied.op_id, applied.op.target)
            .await?
        {
            return Err(Halt::Permanent(DeadLetterReason::AlreadyPublished));
        }

        let mut shortfall = None;
        let (body, content_cids) = match node {
            NewNode::Folder => (NewNodeBody::Folder, Vec::new()),
            NewNode::File { content: None } => (
                NewNodeBody::File {
                    versions: Vec::new(),
                },
                Vec::new(),
            ),
            NewNode::File {
                content: Some(staged),
            } => {
                let uploaded = self.upload_version(scope, applied, staged).await?;
                shortfall = mirror_shortfall(&uploaded);
                (
                    NewNodeBody::File {
                        versions: vec![uploaded.version],
                    },
                    uploaded.content_cids,
                )
            }
        };
        let child_id = applied.op.target;
        let child_name = derive_write_name(scope.write_scope_seed, &child_id.0);
        let child = new_child(
            child_id.0,
            name.to_string(),
            &child_name,
            body,
            rebased.max_link_counter(child_id),
            applied.op.authored_at.0,
        );
        let published = self
            .publish_node(
                scope,
                pass.epoch,
                child_id,
                &child_name,
                false,
                &child.body,
                content_cids,
                PreservedFields::new(),
                PreservedFields::new(),
                // The parent's record below is this plan's last: a mark raised
                // here would drop an op on restart whose child no parent names.
                None,
            )
            .await
            .map_err(Halt::from)?;

        // Referent published: only now does the parent gain the ref to it.
        pass.folder_mut(parent)?.children.push(child.child_ref);
        self.publish_folder(
            scope,
            pass,
            parent,
            applied.op.authored_at.0,
            Some(applied.op_id),
        )
        .await
        .map_err(Halt::from)?;
        self.release_staged_blocks(&applied.op).await;
        self.emit_mirror_shortfall(applied, shortfall);
        // The parent's repaint lifts the child in without what its own record
        // carries; the first edit of this file anchors on the version its
        // create published.
        if let Some(staged) = applied.op.staged_content() {
            project_child_version(
                &mut self.base.borrow_mut(),
                child_id,
                staged.plaintext_size,
                applied.op.authored_at.0,
                1,
                Some(&staged.root_cid),
            );
        }
        // Held only once the parent names it: a record nothing references is
        // not one the liveness loop should keep alive.
        self.hold(child_id.0, published.held);
        Ok(())
    }

    /// Delete: drop the parent's ref, then stop paying for what it detached.
    ///
    /// Everything reclaimable happens **after** the unlink publishes, which is
    /// the opposite of [`Self::publish_prune`]'s journal-first ordering and for
    /// the same law. A prune's node survives to name its own survivors, so the
    /// settlement pass can always tell a landed shortening from an unlanded one;
    /// a delete's node does not, so a debt journaled ahead of the publish would
    /// authorise an unpin the publish never earned. A crash in the window leaves
    /// bytes pinned that nothing names, and a pin row left charged is a leak
    /// where unpinning live content is loss (blueprint/engine.md "Retirement").
    ///
    /// What the unlink earns therefore goes to the doomed-name journal
    /// ([`crate::sync::doomed`]), which [`Self::settle_journalled_deletes`]
    /// replays.
    ///
    /// This is a reclamation and an availability cut, never a re-key. An
    /// unlinked node is in no eager set, so rotation never reaches it: its read
    /// key stays valid, and its content keys ride inline in the sealed bodies a
    /// grantee may already hold (CONTEXT.md "Content key"). Retiring the record
    /// and the pins ends CipherBox's own service of them — the record still
    /// resolves until its EOL lapses, and unpinned blocks stay fetchable from
    /// anyone else holding them.
    async fn publish_delete(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
    ) -> Result<(), Halt> {
        let target = applied.op.target;
        let parent = self.published_parent(target)?;
        self.ensure_folder(scope, pass, parent).await?;
        // Removing an absent ref is the op already satisfied, never a publish.
        let Some(kind) = pass
            .folder(parent)?
            .children
            .iter()
            .find(|child| child.id == target.0)
            .map(|child| child.kind)
        else {
            return Ok(());
        };

        let doomed = self
            .enumerate_doomed(scope, pass.epoch, parent, target, kind)
            .await?;
        pass.folder_mut(parent)?
            .children
            .retain(|child| child.id != target.0);
        self.publish_folder(
            scope,
            pass,
            parent,
            applied.op.authored_at.0,
            Some(applied.op_id),
        )
        .await
        .map_err(Halt::from)?;
        let reclamation = self.owed_by_delete(target, &doomed);
        let owner = owner_tag(scope.enc_secret);
        let seal = self.bookkeeping_seal(scope);
        let key = doomed_journal_key(&owner, target);
        let journalled = self.journal_doomed(seal, &key, target, &reclamation).await;
        if journalled {
            pass.journalled.push(target);
        }
        let residue = self
            .settle_reclamation(scope, seal, &owner, &reclamation, Settle::Hold)
            .await;
        match (journalled, residue) {
            (true, residue) => {
                self.update_journal(seal, &key, target, &reclamation, residue)
                    .await
            }
            // No durable entry to retry from, so the session-lived orphan set is
            // the only retry there is.
            (false, Some(residue)) => {
                for name in residue.names() {
                    self.orphan_heads.record(&name);
                }
            }
            (false, None) => {}
        }
        Ok(())
    }

    /// Write what the unlink just earned to the doomed-name journal, reporting
    /// whether it landed. Anything short of a durable entry — a store that will
    /// not take it, an entropy seam that will not seal it, or an entry the
    /// replay would refuse — leaves this pass's own retries as the only ones
    /// there are.
    ///
    /// Refusing what the replay would refuse is what keeps a build from writing
    /// an entry its own settle path always rejects.
    async fn journal_doomed(
        &self,
        seal: BookkeepingSeal<'_>,
        key: &[u8],
        target: NodeId,
        reclamation: &Reclamation,
    ) -> bool {
        if reclamation.is_empty() || !reclamation.is_for(target) {
            return false;
        }
        let Ok(entry) = seal_reclamation(seal, reclamation) else {
            return false;
        };
        self.staging.put_staged_bytes(key, &entry).await.is_ok()
    }

    /// Replace a journal entry with what its settle left owing: removed once
    /// nothing is, rewritten when a leg landed, untouched when none did.
    async fn update_journal(
        &self,
        seal: BookkeepingSeal<'_>,
        key: &[u8],
        target: NodeId,
        previous: &Reclamation,
        residue: Option<Reclamation>,
    ) {
        match residue {
            None => {
                let _ = self.staging.remove_staged_bytes(key).await;
            }
            // A residue the replay would refuse leaves the previous entry
            // standing, which the replay still accepts, rather than an entry
            // nothing can ever settle ([`Reclamation::is_for`]).
            Some(residue) if residue != *previous && residue.is_for(target) => {
                if let Ok(entry) = seal_reclamation(seal, &residue) {
                    let _ = self.staging.put_staged_bytes(key, &entry).await;
                }
            }
            Some(_) => {}
        }
    }

    /// Replay every delete this owner journaled and did not settle, off the
    /// pass's own key listing. An entry only leaves once its reclamation lands,
    /// so a crashed or refused confirm is settled here rather than lost.
    ///
    /// An entry that does not answer to the target its key names is refused
    /// rather than replayed ([`Reclamation::is_for`]).
    ///
    /// Bounded per pass by the entries it settles, never by the keys it lists
    /// ([`MAX_JOURNAL_REPLAYS`]). A refused or unreadable entry costs a local
    /// read and an HPKE open, but no slot: nothing sweeps this prefix, so
    /// charging it one would starve every entry sorting behind it for good.
    /// Settled entries leave, so the rest are reached on the next pass.
    ///
    /// The quarantine proofs the pass may spend are bounded across every entry
    /// together ([`MAX_QUARANTINE_PROOFS`]), because each one is a fresh resolve
    /// of a descendant's own record: a delete of a large subtree settles over
    /// several passes rather than holding one open.
    async fn settle_journalled_deletes(
        &self,
        scope: &DrainScope<'_>,
        seal: BookkeepingSeal<'_>,
        owner: &[u8; 32],
        staged: &[Vec<u8>],
        journalled_now: &[NodeId],
    ) {
        let mut replayed = 0usize;
        let mut proofs = MAX_QUARANTINE_PROOFS;
        for (key, target) in journalled_keys(owner, staged) {
            if replayed == MAX_JOURNAL_REPLAYS {
                break;
            }
            // This pass wrote and settled that entry moments ago, and its
            // quarantine is waiting on the poll tick this pass has not had. It
            // spends no slot either: no work is skipped, only repeated.
            if journalled_now.contains(&target) {
                continue;
            }
            let Ok(Some(entry)) = self.staging.staged_bytes(&key).await else {
                continue;
            };
            let Some(reclamation) = open_reclamation(seal, &entry).filter(|r| r.is_for(target))
            else {
                continue;
            };
            replayed += 1;
            let residue = self
                .settle_reclamation(
                    scope,
                    seal,
                    owner,
                    &reclamation,
                    Settle::Decide(&mut proofs),
                )
                .await;
            self.update_journal(seal, &key, target, &reclamation, residue)
                .await;
        }
    }

    /// Every node the delete of `target` detaches, refusing the whole operation
    /// if a descendant folder cannot be enumerated.
    ///
    /// Fail-closed on structure, best-effort per file — v1's locked law. A
    /// folder this pass cannot read hides an unknown subtree, and unlinking
    /// above it would strand records nothing can ever name again; a file whose
    /// own record will not open contributes no debt, since its history is
    /// exactly what this pass failed to read.
    ///
    /// What each node's history names is a quote, not yet a debt. Only the
    /// target's own debt is spent on this pass; [`Drain::owed_by_delete`] holds
    /// every descendant for the proof ([`Quarantined`]).
    async fn enumerate_doomed(
        &self,
        scope: &DrainScope<'_>,
        epoch: u64,
        parent: NodeId,
        target: NodeId,
        kind: NodeKind,
    ) -> Result<Vec<Doomed>, Halt> {
        let mut doomed = Vec::new();
        let mut seen = BTreeSet::from([parent.0]);
        let mut pending = vec![(target, kind)];
        while let Some((node, kind)) = pending.pop() {
            // Child refs are wire data, so a diamond or a cycle among them is
            // reachable: a node already walked is never walked again, which is
            // also what terminates the walk.
            if seen.contains(&node.0) {
                continue;
            }
            seen.insert(node.0);
            let (name, versions) = match self
                .load_child_node(scope, epoch, node, ResolveMode::CacheFirst)
                .await
            {
                Ok(loaded) => {
                    let versions = match loaded.body {
                        ReadBody::Folder { children, .. } => {
                            pending.extend(
                                children.iter().map(|child| (NodeId(child.id), child.kind)),
                            );
                            Vec::new()
                        }
                        // One version this device cannot frame costs that
                        // version's debt, never the rest of the history's.
                        ReadBody::File { versions, .. } => versions
                            .iter()
                            .filter_map(|version| {
                                self.pinned_history(core::slice::from_ref(version)).ok()
                            })
                            .flatten()
                            .collect(),
                    };
                    (loaded.name, versions)
                }
                // A `ChildRef.kind` is authored by any holder of the scope's
                // write seed, and an unreadable node's sealed body cannot
                // confirm it. Only a kind this device's own gate-passing state
                // also calls a file may license the best-effort arm; anything
                // else is unknown structure and fails closed.
                Err(halt)
                    if kind == NodeKind::Folder
                        || !self
                            .base
                            .borrow()
                            .node(node)
                            .is_some_and(|meta| meta.kind == crate::facade::NodeKind::File) =>
                {
                    return Err(halt);
                }
                Err(_) => (
                    derive_write_name(scope.write_scope_seed, &node.0),
                    Vec::new(),
                ),
            };
            doomed.push(Doomed {
                node,
                name,
                versions,
            });
        }
        Ok(doomed)
    }

    /// The owner-authored doomed manifest this delete just earned: the target's
    /// own name and content debt, and every descendant held in quarantine.
    ///
    /// The target's debt is withheld unless the base agrees it is now unlinked:
    /// [`Self::publish_delete`] read and repainted the parent's own listing on
    /// the way in, so for the target — and only for the target — that answer is
    /// drawn from a record this pass actually resolved. Every other node's
    /// detachment is unproven, so its name and its debt both wait for
    /// [`Drain::prove_quarantine`] on a later pass.
    fn owed_by_delete(&self, target: NodeId, doomed: &[Doomed]) -> Reclamation {
        let unlinked = self.base.borrow().links_to(target).is_empty();
        let mut reclamation = Reclamation::default();
        for node in doomed {
            // A version list is wire data and may name one root twice. The
            // ledger is keyed by target, so the second naming owes nothing the
            // first does not carry.
            let mut quoted: BTreeSet<&str> = BTreeSet::new();
            let owed: Vec<OwedRetire> = node
                .versions
                .iter()
                .filter(|version| quoted.insert(version.content_cid.as_str()))
                .map(|version| {
                    OwedRetire::whole_retired(
                        node.node.0,
                        version.content_cid.clone(),
                        version.pinned_bytes,
                    )
                })
                .collect();
            let name = node.name.as_str().to_owned();
            if node.node == target {
                reclamation.doomed.push((node.node, name));
                if unlinked {
                    reclamation.owed = owed;
                }
            } else {
                reclamation.quarantined.push(Quarantined {
                    node: node.node,
                    name,
                    owed,
                    attempts: 0,
                });
            }
        }
        reclamation
    }

    /// Settle one journaled reclamation, returning what it still owes — `None`
    /// once every leg has landed, which is what licenses dropping its journal
    /// entry. A refused registry call does not fail the op: the unlink is
    /// already live, and the residue is the retry.
    ///
    /// A leg that lands leaves the residue, so it never runs twice. The content
    /// debt in particular must not: the retire ledger settles and deletes its
    /// own entry, so re-owing a paid debt would re-inflate the pending-reclaim
    /// figure on every pass a name retire keeps failing.
    ///
    /// Idempotent on what it does replay: registry retirement is a server-side
    /// no-op on a repeat, and the local drops are removals.
    async fn settle_reclamation(
        &self,
        scope: &DrainScope<'_>,
        seal: BookkeepingSeal<'_>,
        owner: &[u8; 32],
        reclamation: &Reclamation,
        settle: Settle<'_>,
    ) -> Option<Reclamation> {
        let (proven, held_over) = match settle {
            Settle::Hold => (Vec::new(), reclamation.quarantined.clone()),
            Settle::Decide(budget) => {
                self.prove_quarantine(scope, &reclamation.quarantined, budget)
                    .await
            }
        };
        let mut owed = reclamation.owed.clone();
        owed.extend(proven.iter().flat_map(|entry| entry.owed.iter().cloned()));
        if !owed.is_empty()
            && StagingRetireLedger::new(self.staging, seal)
                .owe(owner, &owed)
                .await
                .is_err()
        {
            // Leaving the bytes pinned is the lawful side of this failure: the
            // unlink is already live, and an unpin the ledger never recorded is
            // one nothing can account for. The quarantine goes back whole, so a
            // descendant this pass proved is proved again rather than lost.
            return Some(reclamation.clone());
        }
        let mut doomed = reclamation.doomed.clone();
        doomed.extend(proven.into_iter().map(|entry| (entry.node, entry.name)));
        let names: Vec<String> = doomed.iter().map(|(_, name)| name.clone()).collect();
        let retired = retire(self.api, &names).await.is_ok();
        // Whatever the registry answered, this device must stop re-PUTting
        // records no parent references — but only those. The walk enumerates a
        // subtree it cannot prove is reached from here alone, so a node still
        // linked is one a surviving parent names and its record has to stay
        // alive.
        //
        // The removal cascades because the walk is preorder over wire child
        // refs: a diamond puts the shared child ahead of one of its parents,
        // and a shallow drop of that parent would leave the child in the
        // snapshot with no link at all.
        {
            let mut held = self.held.borrow_mut();
            let mut base = self.base.borrow_mut();
            let mut forget = |node: NodeId| {
                held.remove(&HeldKey::node(node.0));
                // A scope root's node id is its scope id, so a reclaimed root
                // also owns the pointer entry under those bytes; a non-root id
                // matches nothing in that plane.
                held.remove(&HeldKey::scope_pointer(node.0));
            };
            let detached = reclamation
                .doomed
                .iter()
                .map(|(node, _)| *node)
                .chain(reclamation.quarantined.iter().map(|entry| entry.node));
            for node in detached {
                if !base.links_to(node).is_empty() {
                    continue;
                }
                // A replay settles over a base rebuilt without the doomed node,
                // so the cascade reports nothing for it while its held entry is
                // still owed; what the cascade takes is owed from the report.
                forget(node);
                for dropped in base.remove_unreachable(node) {
                    forget(dropped);
                }
            }
        }
        match (retired, held_over.is_empty()) {
            (true, true) => None,
            // The names retired and the debt is paid, so only the quarantine is
            // left. The head — the delete's own target — rides with it because
            // the entry's key scopes it but does not authenticate it
            // ([`Reclamation::is_for`]); re-sending one retired name is the cost.
            (true, false) => Some(Reclamation {
                doomed: reclamation.doomed.iter().take(1).cloned().collect(),
                owed: Vec::new(),
                quarantined: held_over,
            }),
            (false, _) => Some(Reclamation {
                doomed,
                owed: Vec::new(),
                quarantined: held_over,
            }),
        }
    }

    /// Decide one pass's worth of quarantined descendants: those the proof
    /// releases, and those the pass's proof budget did not reach. What neither
    /// holds is refused for good — its name stays registered and its content
    /// stays pinned, which is what an unproven reclamation costs.
    ///
    /// Two conditions release, both fail-closed. The converged snapshot must no
    /// longer reach the node, which is decided off local state alone so a
    /// surviving namer this device renders never spends a proof; and the node's
    /// freshly resolved record must still match the owner's manifest
    /// ([`record_matches_manifest`]).
    async fn prove_quarantine(
        &self,
        scope: &DrainScope<'_>,
        quarantined: &[Quarantined],
        budget: &mut usize,
    ) -> (Vec<Quarantined>, Vec<Quarantined>) {
        // One root read serves every proof this entry spends. A root this pass
        // cannot establish decides nothing: the whole quarantine waits rather
        // than settling against an epoch this pass never read.
        let Ok((_, epoch)) = self.load_scope_root(scope).await else {
            return (Vec::new(), quarantined.to_vec());
        };
        let mut proven = Vec::new();
        let mut held_over = Vec::new();
        for entry in quarantined {
            let verdict = if self.base.borrow().contains(entry.node) {
                // Decided off local state alone, so a surviving namer this
                // device renders spends no proof. A link that is merely stale is
                // why it retries rather than refuses outright.
                Verdict::Retry
            } else if *budget == 0 {
                // The budget bounds the resolves one pass spends, never the
                // entry: one it does not reach waits with its attempts intact.
                held_over.push(entry.clone());
                continue;
            } else {
                *budget -= 1;
                self.decide_quarantined(scope, epoch, entry).await
            };
            match verdict {
                Verdict::Release => proven.push(entry.clone()),
                Verdict::Refuse => {}
                Verdict::Retry => {
                    let attempts = entry.attempts.saturating_add(1);
                    if attempts < MAX_QUARANTINE_ATTEMPTS {
                        held_over.push(Quarantined {
                            attempts,
                            ..entry.clone()
                        });
                    }
                }
            }
        }
        (proven, held_over)
    }

    /// One quarantined descendant's verdict, off its own freshly resolved
    /// record. Only a record this pass established decides anything.
    ///
    /// A folder quotes no root, so this half always holds for one and its
    /// release rests on the snapshot alone. A folder owns no pins, so what that
    /// costs is a name retire, never an unpin.
    async fn decide_quarantined(
        &self,
        scope: &DrainScope<'_>,
        epoch: u64,
        entry: &Quarantined,
    ) -> Verdict {
        let resolved = self.resolved_version_roots(scope, epoch, entry.node).await;
        if record_matches_manifest(&entry.manifest_roots(), resolved.as_ref()) {
            return Verdict::Release;
        }
        match resolved {
            // A record that resolved and disagreed is a writer that moved on,
            // which no later pass takes back.
            Some(_) => Verdict::Refuse,
            None => Verdict::Retry,
        }
    }

    /// The version roots one node's **freshly resolved** record names — the
    /// settle-time half of the quarantine proof.
    ///
    /// Nocache, because a cached body is the very state the manifest already
    /// quoted; the proof needs what the plane serves now. A folder reaches no
    /// content and answers the empty set. `None` is a record, or a version
    /// framing, this pass could not establish, and it refuses the proof.
    async fn resolved_version_roots(
        &self,
        scope: &DrainScope<'_>,
        epoch: u64,
        node: NodeId,
    ) -> Option<BTreeSet<String>> {
        let loaded = self
            .load_child_node(scope, epoch, node, ResolveMode::NoCache)
            .await
            .ok()?;
        let ReadBody::File { versions, .. } = loaded.body else {
            return Some(BTreeSet::new());
        };
        Some(
            self.pinned_history(&versions)
                .ok()?
                .into_iter()
                .map(|version| version.content_cid)
                .collect(),
        )
    }

    /// The one plan behind rename, relink, and move: relocate a child ref,
    /// dest-add before source-remove, so no window leaves the child absent from
    /// both parents. A source-remove that will not publish compensates its own
    /// dest-add rather than leaving a dual link. Source and destination being
    /// one folder collapses the whole plan into a single record.
    async fn publish_ref_move(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        rebased: &Snapshot,
        plan: MovePlan,
    ) -> Result<(), Halt> {
        let MovePlan {
            from_parent,
            dest,
            new_name,
            vacated,
        } = plan;
        let target = applied.op.target;
        let source = self.published_parent(target)?;
        // The op's own presence condition: a source the rebase did not resolve
        // against is a concurrent move this op lost (`sync/op.rs`), and removing
        // from it would clobber the winner.
        if source != from_parent && source != dest {
            return Err(Halt::Unclassified);
        }
        if source == dest && new_name.is_none() && vacated.is_none() {
            return Ok(());
        }
        // A cycle detaches the whole subtree from the scope root irrecoverably,
        // and no walk can find it again. Release-active, and refused again at
        // rebase so the op dead-letters instead of wedging the queue.
        if dest == target || self.base.borrow().ancestors(dest).contains(&target) {
            return Err(Halt::Unclassified);
        }
        let modified_at = applied.op.authored_at.0;

        self.ensure_folder(scope, pass, source).await?;
        self.ensure_folder(scope, pass, dest).await?;

        // The dest gains the source's own ref, so id/ipnsName/kind and any
        // newer client's fields ride verbatim.
        let mut moved = pass
            .folder(source)?
            .children
            .iter()
            .find(|child| child.id == target.0)
            .cloned()
            .ok_or(Halt::Unclassified)?;
        if let Some(new_name) = new_name {
            moved.rename(new_name.to_string());
        }
        if source != dest {
            // Only a newly-established link advances the counter, to the winner
            // replay allocated (#33 D5).
            moved.link_counter = rebased
                .winning_link(target)
                .map_or(moved.link_counter.saturating_add(1), |link| {
                    link.link_counter
                });
        }

        let dest_children = &mut pass.folder_mut(dest)?.children;
        // The one destructive step in the plan, so it re-checks against the
        // record the gate just handed us: the ref this drops must still be the
        // one holding the name the move is taking. A concurrent writer that
        // renamed it away made it a bystander.
        let replaced = vacated
            .and_then(|node| {
                dest_children.iter().position(|child| {
                    child.id == node.0 && collation_key(&child.name) == collation_key(&moved.name)
                })
            })
            .map(|at| dest_children.remove(at));
        // The rebase resolves against a dest it has not loaded yet, so a dest
        // already naming the target is reachable; a second ref would sign a
        // listing `author_child_envelope` rejects, wedging every retry.
        match dest_children.iter_mut().find(|child| child.id == target.0) {
            Some(existing) => *existing = moved,
            None => dest_children.push(moved),
        }
        // Only when one folder collapses the plan is the dest-add also its last
        // record; otherwise the source-remove below is.
        let single_record = source == dest;
        let cas_base = self
            .publish_folder(
                scope,
                pass,
                dest,
                modified_at,
                single_record.then_some(applied.op_id),
            )
            .await
            .map_err(Halt::from)?;
        if single_record {
            return Ok(());
        }

        pass.folder_mut(source)?
            .children
            .retain(|child| child.id != target.0);
        // The source-remove keeps its own classification through the
        // compensation: `Unclassified` is the one verdict that retries free and
        // forever, so a quota refusal, a permanent one, or a spent attempt must
        // not be flattened into it. Only the undo's own failure is genuinely
        // unclassified.
        if let Err(failure) = self
            .publish_folder(scope, pass, source, modified_at, Some(applied.op_id))
            .await
        {
            // A confirmed source-remove is the move complete on the network, so
            // undoing the dest-add would strip the child from the only parent
            // that still names it. The compensation decides that by re-reading
            // the source, which this very publish left stale in the cache; the
            // publish itself already knows.
            if !failure.confirmed {
                self.compensate_dest_add(
                    scope,
                    pass,
                    DestAdd {
                        dest,
                        source,
                        target,
                        replaced,
                        cas_base,
                        modified_at,
                    },
                )
                .await?;
            }
            return Err(failure.halt);
        }
        Ok(())
    }

    /// Undo a published dest-add when the source-remove did not follow it.
    ///
    /// Two fail-closed conditions, because undoing wrongly is the one error the
    /// ordering law cannot absorb — it leaves the child referenced by neither
    /// parent. The source must still name the child (the publish may have
    /// landed and only its self-adopt failed), and the dest must still be at
    /// the sequence our dest-add published; a dest that moved is re-read and
    /// the removal re-derived onto the winner's record rather than replayed
    /// over it.
    ///
    /// The undo also restores the ref the dest-add vacated: a dest keeping
    /// neither the moved node nor the one it replaced has lost an entry
    /// outright.
    async fn compensate_dest_add(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        add: DestAdd,
    ) -> Result<(), Halt> {
        let DestAdd {
            dest,
            source,
            target,
            replaced,
            cas_base,
            modified_at,
        } = add;
        self.reload_folder(scope, pass, source).await?;
        if !pass
            .folder(source)?
            .children
            .iter()
            .any(|child| child.id == target.0)
        {
            return Ok(());
        }

        let staged = pass.folder(dest)?.children.clone();
        // The version read is the record plane's own, never this device's cache:
        // a cache hit would answer with the bytes we just published and make the
        // compare vacuous.
        let observed = self.observed_sequence(&pass.folder(dest)?.name).await?;
        let drop_target = |children: &[ChildRef]| -> Vec<ChildRef> {
            children
                .iter()
                .filter(|child| child.id != target.0)
                .cloned()
                .collect()
        };
        let children = match undo_dest_add_versioned(&staged, drop_target, cas_base, observed) {
            // Our own bytes are still the head, so the undo is an exact inverse
            // of our own edit: the vacated ref goes back too.
            UndoDestAdd::Removed(mut children) => {
                if let Some(replaced) = replaced
                    && !children.iter().any(|child| child.id == replaced.id)
                {
                    children.push(replaced);
                }
                children
            }
            // A winner owns the dest and built on the listing our dest-add
            // published. Subtract our add and stop there — re-asserting a ref
            // whose absence the winner has already built on would resurrect it
            // against an intent that may be permanently retired.
            UndoDestAdd::Conflict => {
                self.reload_folder(scope, pass, dest).await?;
                drop_target(&pass.folder(dest)?.children)
            }
        };
        pass.folder_mut(dest)?.children = children;
        self.publish_folder(scope, pass, dest, modified_at, None)
            .await
            .map_err(Halt::from)?;
        Ok(())
    }

    /// The freshest sequence the record plane shows at `name` — the same
    /// record-verify read the publish confirm asserts against. Nothing
    /// resolvable fails closed: the compensation may not treat an unanswered
    /// name as "unchanged".
    async fn observed_sequence(&self, name: &IpnsName) -> Result<u64, Halt> {
        fanout_get_verify(self.transport, name)
            .await
            .map(|(verified, _)| verified.sequence)
            .ok_or(Halt::Unclassified)
    }

    /// Re-read a folder from the record plane, replacing this pass's copy.
    ///
    /// The scope root is otherwise read from the snapshot cache, which is this
    /// device's own — a compensation that read it there could never see the
    /// concurrent writer it exists to yield to — so the root is re-resolved
    /// through its own gate first.
    async fn reload_folder(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        folder: NodeId,
    ) -> Result<(), Halt> {
        let state = if folder == scope.root {
            self.refresh_scope_root_cache(scope).await?;
            let (state, epoch) = self.load_scope_root(scope).await?;
            // A rotation landing mid-pass moves the root's epoch while this pass
            // still seals at the one it opened on, and its grant section signs
            // the new one — bytes this build's own authoring refuses. The next
            // pass opens on one consistent epoch, so this stops rather than
            // spending the op's budget on a skew that heals itself.
            if epoch != pass.epoch {
                return Err(Halt::Unclassified);
            }
            state
        } else {
            self.load_child_folder(scope, pass.epoch, folder).await?
        };
        self.repaint_folder(folder, &state.children, state.sequence, state.modified_at);
        *pass.folder_mut(folder)? = state;
        Ok(())
    }

    /// `updateContent`: upload the new version's blocks, then republish the
    /// file's own record with the version at the head. Its parent holds no
    /// size/mtime mirror to republish (`crates/core/src/seal/body.rs`), so this
    /// plan authors exactly one record.
    async fn publish_update_content(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        staged: &StagedContent,
        base_version_cid: Option<&[u8]>,
    ) -> Result<(), Halt> {
        let target = applied.op.target;
        let modified_at = applied.op.authored_at.0;
        // This plan authors the target's own record and nothing else, so a
        // resolution that also needs a parent-side write — the rebase's
        // resurrect arm, which re-links under a resolved name — has no publish
        // plan here and must not report success.
        if applied.effective_name.is_some() {
            return Err(Halt::Unclassified);
        }
        // Same reachability rule every other plan gets from `ensure_folder`: a
        // node no parent links is not one this scope's write plane may author.
        self.ensure_folder(scope, pass, self.published_parent(target)?)
            .await?;
        // The conditional-edit rule against the live record, which the rebase's
        // snapshot can be stale about — first before spending an upload on an
        // edit that cannot land, then again with the upload behind us, because
        // the transfer is the widest window a version can land in unseen.
        let seen = self
            .load_child_node(scope, pass.epoch, target, ResolveMode::CacheFirst)
            .await?;
        if head_version_cid(&seen.body) != base_version_cid {
            return Err(Halt::Permanent(DeadLetterReason::BaseSuperseded));
        }
        let uploaded = self.upload_version(scope, applied, staged).await?;
        let loaded = self
            .load_child_node(scope, pass.epoch, target, ResolveMode::CacheFirst)
            .await?;
        let ReadBody::File {
            created_at,
            mut versions,
            unknown,
            ..
        } = loaded.body
        else {
            return Err(Halt::Unclassified);
        };
        if versions.first().map(|head| head.content_cid.as_slice()) != base_version_cid {
            return Err(Halt::Permanent(DeadLetterReason::BaseSuperseded));
        }
        let shortfall = mirror_shortfall(&uploaded);
        // Newest first, head is current (`crates/core/src/seal/body.rs`).
        versions.insert(0, uploaded.version);
        // Every retained version's root stays registered under this name, so a
        // republish never drops the pin that keeps an older version readable.
        let content_cids = uploaded
            .content_cids
            .into_iter()
            .chain(
                versions[1..]
                    .iter()
                    .map(|version| encode_content_cid_str(&version.content_cid)),
            )
            .collect();
        let version_count = versions.len() as u64;
        let body = ReadBody::File {
            created_at,
            modified_at,
            versions,
            unknown,
        };
        let published = self
            .publish_node(
                scope,
                pass.epoch,
                target,
                &loaded.name,
                false,
                &body,
                content_cids,
                loaded.envelope_unknown,
                loaded.epoch_tag_unknown,
                Some(applied.op_id),
            )
            .await
            .map_err(Halt::from)?;
        self.release_staged_blocks(&applied.op).await;
        self.emit_mirror_shortfall(applied, shortfall);
        self.project_published_file(
            target,
            staged.plaintext_size,
            modified_at,
            version_count,
            &staged.root_cid,
            published,
        );
        Ok(())
    }

    /// Repaint the base with the head this publish established, and hold the
    /// record. Without it this device would read its own publish as a concurrent
    /// writer, and the next edit of the file would have nothing to anchor on.
    fn project_published_file(
        &self,
        target: NodeId,
        plaintext_size: u64,
        modified_at: u64,
        version_count: u64,
        head_cid: &[u8],
        published: Published,
    ) {
        project_child_version(
            &mut self.base.borrow_mut(),
            target,
            plaintext_size,
            modified_at,
            version_count,
            Some(head_cid),
        );
        if let Some(node) = self.base.borrow_mut().node_mut(target) {
            node.record_sequence = published.sequence;
        }
        self.hold(target.0, published.held);
    }

    /// `prune`: journal what the plan drops to the retire ledger, then republish
    /// the file's record with its history shortened to the newest `keep_latest`
    /// versions.
    ///
    /// The journal happens **before** the publish, because everything after the
    /// record acks is a window a crash leaves the debt in: nothing readable
    /// names the dropped roots once the shortened history is live, so a journal
    /// lost there is lost for good. Holding the entry early is safe because
    /// [`drain_owed_retires`] retires nothing this node's published record still
    /// names ([`Self::live_node_cids`]) — an entry whose publish never lands
    /// simply never drains.
    async fn publish_prune(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        keep_latest: NonZeroU64,
    ) -> Result<(), Halt> {
        let target = applied.op.target;
        // This plan authors the target's own record and nothing else, so a
        // resolution that also needs a parent-side write has no plan here.
        if applied.effective_name.is_some() {
            return Err(Halt::Unclassified);
        }
        self.ensure_folder(scope, pass, self.published_parent(target)?)
            .await?;
        let loaded = self
            .load_child_node(scope, pass.epoch, target, ResolveMode::CacheFirst)
            .await?;
        let ReadBody::File {
            created_at,
            modified_at,
            mut versions,
            unknown,
        } = loaded.body
        else {
            return Err(Halt::Unclassified);
        };
        let history = self.pinned_history(&versions)?;
        let plan = plan_prune(&history, keep_latest);
        if plan.retire_targets.is_empty() {
            return Ok(());
        }
        let head = versions.first().ok_or(Halt::Unclassified)?;
        let (head_size, head_cid) = (head.size, head.content_cid.clone());
        // The plan named a suffix of the history, so the survivors are its
        // prefix — one count, never a second clamp that could disagree.
        let survivors = &history[..history.len() - plan.retire_targets.len()];
        // A version list is authored by anyone holding the scope's write seed,
        // and nothing on the wire forbids one `contentCid` appearing twice in
        // it. Retiring a CID a surviving version still names would unpin the
        // live file, so a repeated history is refused rather than pruned.
        let kept: BTreeSet<&str> = survivors
            .iter()
            .map(|version| version.content_cid.as_str())
            .collect();
        if plan
            .retire_targets
            .iter()
            .any(|doomed| kept.contains(doomed.content_cid.as_str()))
        {
            return Err(Halt::Permanent(DeadLetterReason::PayloadRefused));
        }
        // Ahead of the publish: a debt this pass cannot compute must leave the
        // history it was read from standing, not a shortened one it never
        // journaled.
        let owed = self.prune_debt(target, &plan.retire_targets).await?;
        StagingRetireLedger::new(self.staging, self.bookkeeping_seal(scope))
            .owe(&owner_tag(scope.enc_secret), &owed)
            .await
            .map_err(seam)?;
        versions.truncate(survivors.len());
        let content_cids = survivors
            .iter()
            .map(|version| version.content_cid.clone())
            .collect();
        let version_count = versions.len() as u64;
        // A prune removes history; it does not modify the file, so the record's
        // `modified_at` stays the head version's.
        let body = ReadBody::File {
            created_at,
            modified_at,
            versions,
            unknown,
        };
        let published = self
            .publish_node(
                scope,
                pass.epoch,
                target,
                &loaded.name,
                false,
                &body,
                content_cids,
                loaded.envelope_unknown,
                loaded.epoch_tag_unknown,
                Some(applied.op_id),
            )
            .await
            .map_err(Halt::from)?;
        self.project_published_file(
            target,
            head_size,
            modified_at,
            version_count,
            &head_cid,
            published,
        );
        Ok(())
    }

    /// A published history as [`ContentVersion`]s, newest first.
    fn pinned_history(&self, versions: &[Version]) -> Result<Vec<ContentVersion>, Halt> {
        versions
            .iter()
            .map(|version| {
                let content_cid =
                    encode_content_cid_str(checked_content_cid(&version.content_cid)?);
                ContentVersion::from_plaintext_size(content_cid, version.size, self.content_profile)
                    // A framed size with no readable root is a version this
                    // engine could not have published, and no retry reframes it.
                    .map_err(|_| Halt::Permanent(DeadLetterReason::PayloadRefused))
            })
            .collect()
    }

    /// What each doomed version owes the registry, as this prune can quote it.
    ///
    /// A quote, not a promise: what the retire may actually name is decided at
    /// drain time against the node's own published record
    /// ([`Self::live_node_cids`]), so the figure here is the ceiling a pass that
    /// cannot re-expand falls back on ([`OwedRetire::owed_bytes`]). It is quoted
    /// once per CID — a leaf two doomed roots both name is one pin row, and
    /// quoting it twice would over-report pending reclaim.
    ///
    /// Only *doomed* roots are fetched. A retained version is never expanded
    /// here: it is the drain's business what is live, and a version this device
    /// cannot expand would otherwise refuse a prune that has nothing to do with
    /// it.
    async fn prune_debt(
        &self,
        node: NodeId,
        doomed: &[ContentVersion],
    ) -> Result<Vec<OwedRetire>, Halt> {
        let mut owed = Vec::with_capacity(doomed.len());
        let mut charged: BTreeSet<String> = BTreeSet::new();
        let mut journaled: BTreeSet<&str> = BTreeSet::new();
        for version in doomed {
            // A history may name one root twice, and the ledger is keyed by
            // target: the second naming owes nothing the first does not carry.
            if !journaled.insert(version.content_cid.as_str()) {
                continue;
            }
            let expansion = self.expand_version(version).await?;
            owed.push(OwedRetire {
                node: node.0,
                // The prune shortens this node's history and leaves the node
                // itself published.
                owing: OwingRecord::Published,
                target: version.content_cid.clone(),
                owed_bytes: expansion.minus(&charged).pinned_bytes,
                manifest_bytes: expansion.pinned_bytes,
            });
            charged.extend(expansion.cids());
        }
        Ok(owed)
    }

    /// Every content CID one node's **currently published** record still reaches
    /// — the set a retire against that node may not name.
    ///
    /// Read on the pass that retires rather than frozen into the ledger, and
    /// resolved from the node's derived name rather than the base tree, which
    /// holds only what this session has already read or written. A root block is
    /// authored by anyone holding the scope's write seed, so a version adopted
    /// after the prune journaled its debt is live by the time the retire runs,
    /// and its leaves unpin under the owner's own token if the retire misses
    /// them. It is also the gate that lets the journal precede the publish: a
    /// target this record still names has no landed shortening behind it.
    ///
    /// `None` when the record or any version it names could not be established,
    /// which stands that node's entries down for the pass — a partial set unpins
    /// what it failed to read, where a pin row left charged is only a leak.
    ///
    /// [`OwingRecord::Retired`] is the one class answered without a read, and
    /// the entry's own existence is what earns that: [`Self::publish_delete`]
    /// journals it only after the unlink is live, so the detachment is already a
    /// published fact. Reading the node instead would settle nothing — a hard
    /// delete leaves the record resolvable at its own name until its EOL lapses,
    /// and it names its content the whole time.
    async fn live_node_cids(
        &self,
        scope: &DrainScope<'_>,
        node: [u8; 16],
        owing: OwingRecord,
    ) -> Option<BTreeSet<String>> {
        if owing == OwingRecord::Retired {
            return Some(BTreeSet::new());
        }
        let (_, epoch) = self.load_scope_root(scope).await.ok()?;
        // Nocache: the retire unpins, so what may be named is decided against
        // the freshest record the gate will pass, never a cached one a
        // concurrent writer has already moved past.
        let loaded = self
            .load_child_node(scope, epoch, NodeId(node), ResolveMode::NoCache)
            .await
            .ok()?;
        // A record carrying no version list reaches no content.
        let ReadBody::File { versions, .. } = loaded.body else {
            return Some(BTreeSet::new());
        };
        let mut live = BTreeSet::new();
        for version in self.pinned_history(&versions).ok()? {
            live.extend(self.expand_version(&version).await.ok()?.cids());
        }
        Some(live)
    }

    /// One published version's whole CID set, off its own fetched root block.
    async fn expand_version(&self, version: &ContentVersion) -> Result<Expansion, Halt> {
        let expected = decode_content_cid_str(&version.content_cid)
            .map_err(|_| Halt::Permanent(DeadLetterReason::PayloadRefused))?;
        let root_block = read_block(
            self.gateway,
            self.http,
            &version.content_cid,
            &expected,
            ContentPlane::Root,
        )
        .await
        // Charged, unlike a plain outage: a version whose root no source will
        // serve is authorable by anyone holding the scope's write seed, and an
        // uncharged retry would let one hold the whole queue behind its head.
        .map_err(|_| Halt::UploadAttempt)?;
        expand_retire_targets(
            &version.content_cid,
            &root_block,
            self.content_profile,
            version.pinned_bytes,
        )
        .map_err(|_| Halt::Permanent(DeadLetterReason::PayloadRefused))
    }

    // -----------------------------------------------------------------------
    // The content plane: staged blocks out, a published version back.
    // -----------------------------------------------------------------------

    /// One version's blocks, uploaded and pinned, with the transfer's progress
    /// reported on the event stream throughout.
    ///
    /// Publish entry — the point past which a cancel is refused — is the moment
    /// the last block confirms: everything after it authors and publishes the
    /// version's record with no further block boundary to stop at.
    async fn upload_version(
        &self,
        scope: &DrainScope<'_>,
        applied: &AppliedOp,
        staged: &StagedContent,
    ) -> Result<UploadedVersion, Halt> {
        let uploaded = match self.upload_blocks(scope, applied, staged).await {
            Ok(uploaded) => uploaded,
            Err(halt) => {
                // A cancel that landed inside one of the loop's awaits released
                // this version's blocks, so the halt it reported is that
                // cancel's shadow, not a failure of the upload.
                if self.cancels.borrow().is_cancelled(applied.op_id) {
                    return Err(Halt::Cancelled);
                }
                if let Some(error) = upload_failure(halt) {
                    self.emit_upload(applied, OpPhase::UploadFailed, None, Some(error));
                }
                return Err(halt);
            }
        };
        if !self.cancels.borrow_mut().enter_publish(applied.op_id) {
            return Err(Halt::Cancelled);
        }
        Ok(uploaded)
    }

    /// Classify an authoring refusal, naming a trust refusal on the event
    /// stream first. The produce side mirrors the gate's own verdicts on the
    /// bytes it is about to sign, so a refusal here is reported the way an
    /// arriving record's rejection is ([`emit_trust_violation`]).
    fn report_author_refusal(&self, name: &IpnsName, error: AuthorError) -> Halt {
        if error.is_trust_refusal() {
            emit_trust_violation(self.events, name.as_str(), &error);
        }
        classify_author(error)
    }

    /// Name a carried set this authoring had to cut. The cut only fires where
    /// the record resolved at this name already ran to the block ceiling, so
    /// what it reports is that someone's bytes at that name are costing this
    /// node its forward-compatible fields.
    fn report_carried_cut(&self, name: &IpnsName, cut: &[String]) {
        if cut.is_empty() {
            return;
        }
        emit_trust_violation(
            self.events,
            name.as_str(),
            format_args!(
                "carried fields dropped to fit the block ceiling: {}",
                cut.join(", ")
            ),
        );
    }

    /// Tell the member their mirror is short of this version — after the record
    /// published, because [`OpPhase::ExternalPinFailed`] promises the content is
    /// retrievable, which is only true once the record naming it is live.
    fn emit_mirror_shortfall(&self, applied: &AppliedOp, reason: Option<&'static str>) {
        if let Some(reason) = reason {
            self.emit_upload(applied, OpPhase::ExternalPinFailed, None, Some(reason));
        }
    }

    /// One version's blocks, uploaded and pinned: the `Version` its record
    /// carries and every content CID the registration must name.
    async fn upload_blocks(
        &self,
        scope: &DrainScope<'_>,
        applied: &AppliedOp,
        staged: &StagedContent,
    ) -> Result<UploadedVersion, Halt> {
        // Resolved before any byte moves: a session with no authenticated
        // destination publishes no version. What the refusal costs is
        // [`PlacementRefusal::holds`]'s to say — an outage this pass could not
        // resolve is retried uncharged rather than spending a budget that ends
        // by releasing the version's staged blocks.
        let placement = self.placement.as_ref().map_err(|refusal| {
            refusal
                .holds()
                .map_or(Halt::Unclassified, Halt::HeldBySettings)
        })?;
        // What the mark may claim, narrowed as the mirror misses blocks the mark
        // covers ([`Destinations::mirror_missed`]).
        let mut reached = placement.destinations();
        let mut mirror = MirrorLeg::new();
        let root_block = self
            .staged_block(&staged.root_cid)
            .await?
            .ok_or(CONTENT_LOST)?;
        let content = SealedContent::from_root_block(&root_block).map_err(|_| CONTENT_LOST)?;
        // The observed `pushChunk` total against the manifest the reader will
        // check the version's size against. The reachable mismatch is a backing
        // file truncated mid-upload, which would otherwise publish short bytes
        // as a success.
        if content.size() != staged.plaintext_size {
            return Err(CONTENT_LOST);
        }
        // A blob this build cannot *interpret* — one a newer build wrote — is
        // retained and retried, never destroyed: the same rule the op record
        // itself follows. Only a genuine crypto failure is unrecoverable.
        let key = open_content_key(
            scope.enc_secret,
            &scope.root.0,
            staged.epoch,
            &staged.root_cid,
            &staged.sealed_content_key,
        )
        .map_err(|error| match error.check() {
            "unsupported-record-version" | "unknown-record-field" => Halt::Unclassified,
            _ => CONTENT_LOST,
        })?;

        // File order, root last, each leaf removed on its confirmed
        // `UploadResult` — but a lost release can strand one staged anywhere
        // below the mark. An absence is only progress up to the durable
        // mark this pass keeps: past it, a missing block is loss, and the
        // version can never be assembled.
        let leaves = content.leaf_cids().len();
        let mark_key = upload_mark_key(&staged.root_cid);
        let Resume {
            uploaded,
            mirror_gap,
        } = self.upload_mark(placement, &mark_key, leaves).await?;
        if mirror_gap {
            reached.mirror_missed();
        }
        // The root manifest is block zero and goes up last, so the version's
        // whole block count is its leaves plus one.
        let total = blocks(leaves + 1);
        let emit = |phase: OpPhase, confirmed: u32| {
            self.emit_upload(
                applied,
                phase,
                Some(BlockProgress { confirmed, total }),
                None,
            );
        };
        emit(OpPhase::UploadStarted, blocks(uploaded));
        for (index, leaf_cid) in content.leaf_cids().iter().enumerate() {
            self.cancel_checkpoint(applied.op_id).await?;
            match self.staged_block(leaf_cid).await? {
                Some(block) => {
                    self.upload_block(placement, &mut mirror, applied.op_id, leaf_cid, &block)
                        .await?;
                    if mirror.missed() {
                        reached.mirror_missed();
                    }
                    // A leaf a lost release left staged behind the mark is
                    // re-uploaded here, and must not drag the mark back down
                    // over the leaves past it — those are released, so an
                    // uncovered one reads as loss.
                    if index + 1 > uploaded {
                        self.mark_uploaded(&reached, &mark_key, index + 1, leaves)
                            .await?;
                    }
                    self.staging
                        .remove_staged_bytes(leaf_cid)
                        .await
                        .map_err(seam)?;
                    emit(OpPhase::UploadProgress, blocks(index + 1));
                }
                // Absent and not covered by the mark: these bytes were never
                // uploaded and are simply gone.
                None if index >= uploaded => return Err(CONTENT_LOST),
                None => {}
            }
        }
        self.cancel_checkpoint(applied.op_id).await?;
        // The root goes up last and stays staged until the publish confirms: it
        // is the manifest every retry re-derives the plan from, so releasing it
        // before the record lands would strand a fully-uploaded version.
        self.upload_block(
            placement,
            &mut mirror,
            applied.op_id,
            &staged.root_cid,
            &root_block,
        )
        .await?;
        emit(OpPhase::UploadCompleted, total);

        let content_cids = version_cids(
            &staged.root_cid,
            content.leaf_cids().iter().map(Vec::as_slice),
            RootPlacement::First,
        );
        Ok(UploadedVersion {
            version: content.version(*key, applied.op.authored_at.0),
            content_cids,
            external_failure: mirror.failure(),
            mirror_gap,
        })
    }

    /// The block boundary a cancel gets to run at. Without the yield a whole
    /// version uploads inside one turn of the host's executor, and the cancel
    /// guarantee collapses to "only before the op starts".
    async fn cancel_checkpoint(&self, op_id: OpId) -> Result<(), Halt> {
        yield_now().await;
        match self.cancels.borrow().is_cancelled(op_id) {
            true => Err(Halt::Cancelled),
            false => Ok(()),
        }
    }

    /// Best-effort upload progress for the op driving this transfer (a dropped
    /// receiver is fine).
    fn emit_upload(
        &self,
        applied: &AppliedOp,
        phase: OpPhase,
        progress: Option<BlockProgress>,
        error: Option<&str>,
    ) {
        let _ = self.events.unbounded_send(Event::OpProgress {
            op_id: Some(applied.op_id),
            node: applied.op.target,
            phase,
            progress,
            error: error.map(str::to_owned),
        });
    }

    /// What a previous pass durably confirmed of this version's `leaves`
    /// ([`resume_from`]).
    async fn upload_mark(
        &self,
        placement: &Placement,
        mark_key: &[u8],
        leaves: usize,
    ) -> Result<Resume, Halt> {
        let here = placement.destinations();
        Ok(self
            .staging
            .staged_bytes(mark_key)
            .await
            .map_err(seam)?
            .map_or(Resume::default(), |stored| {
                resume_from(&stored, &here, leaves)
            }))
    }

    /// Record that `count` of this version's `leaves` have uploaded to
    /// `reached`. A high-water mark, written *before* the leaf is released: it
    /// may over-claim a leaf still staged, which the next pass re-uploads, but
    /// must never lag or regress below one already released — the hole guard
    /// would read those uploaded bytes as loss.
    ///
    /// `reached` is what the destinations *took*, not what the placement named:
    /// a mark may only claim a leg that actually holds every leaf it covers.
    async fn mark_uploaded(
        &self,
        reached: &Destinations,
        mark_key: &[u8],
        count: usize,
        leaves: usize,
    ) -> Result<(), Halt> {
        let mark = encode_upload_mark(reached, count, leaves).ok_or(Halt::Unclassified)?;
        self.staging
            .put_staged_bytes(mark_key, &mark)
            .await
            .map_err(seam)
    }

    /// The staged bytes at `key`, CID-verified fail-closed. The read path hard-
    /// rejects a block whose bytes do not address to its CID, so an unverified
    /// upload would turn host bit-rot into a permanently unreadable published
    /// version.
    async fn staged_block(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Halt> {
        let Some(block) = self.staging.staged_bytes(key).await.map_err(seam)? else {
            return Ok(None);
        };
        verify_cid(key, &block).map_err(|_| CONTENT_LOST)?;
        Ok(Some(block))
    }

    /// Upload one block to every leg `placement` names, under `cid` — its
    /// staging key and own content address — so each provider pins it where the
    /// published record points. A block is only ever removed from staging on a
    /// confirmed [`UploadResult`](crate::UploadResult), which is what makes the
    /// still-staged set a suffix.
    ///
    /// Only the hosted leg can fail the op — see [`OpPhase::ExternalPinFailed`]
    /// for why a dual write's mirror is reported instead. That mirror retries
    /// within the op out of `mirror`'s shared budget ([`MirrorLeg`]); an
    /// external-only write has no second leg to absorb a refusal, so its
    /// retries are the op-level valve's.
    async fn upload_block(
        &self,
        placement: &Placement,
        mirror: &mut MirrorLeg,
        op_id: OpId,
        cid: &[u8],
        block: &[u8],
    ) -> Result<(), Halt> {
        match placement {
            Placement::Hosted => {
                self.hosted_upload(cid, block).await?;
                self.charged(op_id, cid);
            }
            Placement::External(config) => {
                place_block(config, cid, block, self.http)
                    .await
                    .map_err(classify_placement)?;
                self.charged(op_id, cid);
            }
            Placement::Dual(config) => {
                self.hosted_upload(cid, block).await?;
                self.charged(op_id, cid);
                while !mirror.missed() {
                    // The budget spans several provider deadlines, so a cancel
                    // gets to run between them rather than only at the block
                    // boundary. The charge above is already recorded, so one
                    // landing here still retires these bytes.
                    self.cancel_checkpoint(op_id).await?;
                    match place_block(config, cid, block, self.http).await {
                        Ok(()) => break,
                        Err(error) => mirror.refused(error),
                    }
                }
            }
        }
        Ok(())
    }

    /// Record one block as on the network for `op_id`, which is the only
    /// evidence a cancel has that this upload charged for it
    /// ([`UploadCancels`]). Written the instant the leg that charges confirms,
    /// so no later await can abandon the upload with the charge unrecorded.
    fn charged(&self, op_id: OpId, cid: &[u8]) {
        self.cancels.borrow_mut().confirmed(op_id, cid);
    }

    /// One block to the hosted ingress, under its own content address.
    async fn hosted_upload(&self, cid: &[u8], block: &[u8]) -> Result<(), Halt> {
        self.api
            .upload(&encode_content_cid_str(cid), block)
            .await
            .map(drop)
            .map_err(|error| classify_upload(error, block.len() as u64))
    }

    /// Drop every staged block of an op's version — on a landed publish, and on
    /// a failure-valve abandonment, where the only copy of the version's content
    /// key rode the op record the abandonment deletes
    /// (`crate::sync::staging` owns the release-or-preserve rule).
    async fn release_staged_blocks(&self, op: &Op) {
        let Some(root_cid) = op.content_root_cid() else {
            return;
        };
        release_version_blocks(self.staging, root_cid).await;
    }

    /// The parent a node is published under, from the base the pass repaints as
    /// it goes — so an op rebases onto exactly what the ops before it published.
    fn published_parent(&self, node: NodeId) -> Result<NodeId, Halt> {
        self.base.borrow().parent_of(node).ok_or(Halt::Unclassified)
    }

    // -----------------------------------------------------------------------
    // Authoring and publishing one record.
    // -----------------------------------------------------------------------

    /// Re-author and publish one folder over its current children, self-adopt
    /// it, and repaint the base from the result. Returns its new sequence.
    async fn publish_folder(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        folder: NodeId,
        modified_at: u64,
        completes: Option<OpId>,
    ) -> Result<u64, PublishHalt> {
        let (name, is_scope_root, body, envelope_unknown, epoch_tag_unknown) = {
            let state = pass.folder(folder).map_err(PublishHalt::before_the_put)?;
            (
                state.name.clone(),
                state.is_scope_root,
                ReadBody::Folder {
                    created_at: state.created_at,
                    modified_at,
                    children: state.children.clone(),
                    unknown: state.body_unknown.clone(),
                },
                state.envelope_unknown.clone(),
                state.epoch_tag_unknown.clone(),
            )
        };
        let published = self
            .publish_node(
                scope,
                pass.epoch,
                folder,
                &name,
                is_scope_root,
                &body,
                Vec::new(),
                envelope_unknown,
                epoch_tag_unknown,
                completes,
            )
            .await?;

        let state = pass.folder_mut(folder).map_err(PublishHalt::past_the_put)?;
        state.sequence = published.sequence;
        state.modified_at = modified_at;
        let children = state.children.clone();
        self.repaint_folder(folder, &children, published.sequence, modified_at);
        self.hold(folder.0, published.held);
        Ok(published.sequence)
    }

    /// Author, publish and self-adopt one node's record. Only a confirmed
    /// publish reaches the gate: adopting an unconfirmed one would advance the
    /// sequence floor and destroy the idempotent-in-sequence retry.
    ///
    /// `completes` names the op this record is the **last** publish of, if any;
    /// see [`Drain::mark_published`] for why the ack rather than the adopt is
    /// where that op stops being replayable.
    #[expect(clippy::too_many_arguments, reason = "one record's full authoring")]
    async fn publish_node(
        &self,
        scope: &DrainScope<'_>,
        epoch: u64,
        node: NodeId,
        name: &IpnsName,
        is_scope_root: bool,
        body: &ReadBody,
        content_cids: Vec<String>,
        carried_unknown: PreservedFields,
        carried_epoch_tag_unknown: PreservedFields,
        completes: Option<OpId>,
    ) -> Result<Published, PublishHalt> {
        let read_key = self.node_read_key(scope, &node.0);
        let nonce = fresh_nonce(&mut *self.entropy.borrow_mut())
            .map_err(|_| PublishHalt::before_the_put(Halt::UploadAttempt))?;
        let authoring = EnvelopeAuthoring {
            node_id: node.0,
            scope_id: scope.root.0,
            epoch,
            read_key: &read_key,
            nonce: &nonce,
            body,
            carried_unknown,
            carried_epoch_tag_unknown,
        };
        let head = if is_scope_root {
            author_scope_root_envelope(authoring, name, scope.owner_identity)
        } else {
            author_child_envelope(authoring)
        }
        .map_err(|error| PublishHalt::before_the_put(self.report_author_refusal(name, error)))?;
        self.report_carried_cut(name, &head.cut);

        let record_bytes = self
            .publish_head(scope, name, &node.0, epoch, &head, content_cids.clone())
            .await
            .map_err(PublishHalt::before_the_put)?;
        if let Some(op_id) = completes {
            self.mark_published(scope, op_id).await;
        }
        // The record is live from here: everything below is a local step.
        let local = local_head(&head);
        let sequence = if is_scope_root {
            let adopter = RootAdopter::new(
                self.gateway,
                self.http,
                self.floors,
                scope.enc_secret,
                scope.owner_identity,
                scope.root.0,
            );
            adopter.hold_local_head(local);
            adopter
                .adopt(name, &record_bytes)
                .await
                .map_err(|_| PublishHalt::past_the_put(Halt::Unclassified))?
        } else {
            let adopter = ChildAdopter::new(
                self.gateway,
                self.http,
                self.floors,
                scope.root.0,
                scope.read_scope_seed.clone(),
                node.0,
            );
            adopter.hold_local_head(local);
            adopter
                .adopt(name, &record_bytes)
                .await
                .map_err(|_| PublishHalt::past_the_put(Halt::Unclassified))?
        }
        .adopted
        .sequence;

        // Cached implies gate-passing: these bytes just cleared the gate.
        self.snapshot_cache
            .put(name.as_str().as_bytes(), &record_bytes)
            .await
            .map_err(|e| PublishHalt::past_the_put(seam(e)))?;
        Ok(Published {
            sequence,
            held: HeldRecord {
                routing_key: name.as_str().to_owned(),
                record_bytes,
                signer: SessionIdentity::write_name_signer(scope.write_scope_seed, &node.0),
                value: HeldValue::Head(head.cid),
                // The same list the publish registered, so a sub-EOL renewal
                // re-pins exactly the content this record points at.
                content_cids,
            },
        })
    }

    /// Dry-run, publish, and return the signed bytes. `Ok` means the record
    /// confirmed at its name: an unconfirmed or race-losing publish is `Err`,
    /// because its bytes may never have landed.
    async fn publish_head(
        &self,
        scope: &DrainScope<'_>,
        name: &IpnsName,
        node_id: &[u8; 16],
        epoch: u64,
        head: &AuthoredHead,
        content_cids: Vec<String>,
    ) -> Result<Vec<u8>, Halt> {
        let binding = HeadBinding {
            node_id: *node_id,
            scope_id: scope.root.0,
            epoch,
        };
        let preflighted = preflight(&binding, &self.node_read_key(scope, node_id), head)
            .map_err(|_| Halt::UploadAttempt)?;
        // The name and the seed the signer comes from have independent sources
        // for the scope root — the vault pointer's `currentRoot` and the
        // owner-write-blob. Publishing under a name this signer cannot sign for
        // would burn a CAS sequence on a record nothing can verify.
        let signer = SessionIdentity::write_name_signer(scope.write_scope_seed, node_id);
        if IpnsName::from_public_key(&signer.verifying_key()) != *name {
            return Err(Halt::Unclassified);
        }
        let PublishReceipt {
            outcome,
            record_bytes,
        } = publish_record(
            self.transport,
            self.api,
            self.floors,
            self.scheduler,
            self.profile,
            &RecordPublishRequest {
                name,
                signer: &signer,
                head: &preflighted,
                content_cids,
                min_current_sequence: None,
            },
        )
        .await
        .map_err(|error| {
            if orphaned_head(&error) {
                self.record_orphan_head(preflighted.cid());
            }
            classify_publish(error, head.block.len() as u64)
        })?;
        match outcome {
            PublishOutcome::Published { .. } => Ok(record_bytes),
            // Both burned a CAS sequence at this name without a record we could
            // adopt, so both are charged against the attempt budget.
            PublishOutcome::Unconfirmed { .. } | PublishOutcome::LostRace { .. } => {
                Err(Halt::Attempt)
            }
        }
    }

    /// Merge one folder's published children into the base snapshot.
    fn repaint_folder(
        &self,
        folder: NodeId,
        children: &[ChildRef],
        sequence: u64,
        modified_at: u64,
    ) {
        project_folder(
            &mut self.base.borrow_mut(),
            folder,
            children,
            sequence,
            modified_at,
        );
    }

    /// Insert a just-published record into the live held set so the liveness
    /// loop keeps it alive.
    fn hold(&self, node_id: [u8; 16], held: HeldRecord) {
        self.held.borrow_mut().insert(HeldKey::node(node_id), held);
    }

    /// Remove a resolved op from the durable queue.
    async fn dequeue_op(&self, op_id: OpId) -> Result<(), Halt> {
        self.staging.remove_op(op_id).await.map_err(seam)
    }

    /// Note one head block as orphaned.
    ///
    /// A head the live set still names never enters the queue: its only
    /// consumer physically unpins, and unpinning a head a live record names is
    /// loss, where leaving the row charged is only a leak.
    fn record_orphan_head(&self, cid: &str) {
        if self
            .held
            .borrow()
            .values()
            .any(|record| record.head_cid() == Some(cid))
        {
            return;
        }
        self.orphan_heads.record(cid);
    }

    /// Retire every block a cancelled op put on the network. Best-effort: a
    /// refused batch leaves pin rows charged, which is a leak, where failing the
    /// pass over an op that is already gone would be a stuck queue.
    async fn retire_cancelled(&self, op_id: OpId) {
        let cids: Vec<String> = self
            .cancels
            .borrow()
            .uploaded_by(op_id)
            .iter()
            .map(|cid| encode_content_cid_str(cid))
            .collect();
        if !cids.is_empty() {
            let _ = retire(self.api, &cids).await;
        }
    }

    /// Copy one queued op's record into the preserved set before the
    /// abandonment removes it, so the version it stages stays both referenced
    /// and openable ([`preserve_dead_letter`]).
    async fn preserve_dead_letter(&self, op_id: OpId) -> Result<Preservation, Halt> {
        let queued = self.staging.queued_ops().await.map_err(seam)?;
        let Some((_, record)) = queued.iter().find(|(id, _)| *id == op_id) else {
            return Ok(Preservation::Kept);
        };
        preserve_dead_letter(self.staging, record, self.scheduler.now())
            .await
            .map_err(seam)
    }

    /// Drop the version a [`Preservation::Refused`] set could not hold, once the
    /// op has left the queue. The refusal keeps nothing and the record takes the
    /// version's only content key with it, so orphan GC — which the same
    /// unreadable set stands down — would never collect the blocks.
    ///
    /// Ordered after the abandonment, never before: [`Self::registered_by`]
    /// reads the manifest these blocks carry, and an abandonment that fails
    /// leaves the op queued and still publishable.
    async fn release_if_refused(&self, preserved: Preservation, op: &Op) {
        if preserved == Preservation::Refused {
            self.release_staged_blocks(op).await;
        }
    }

    /// Abandon one op: retire what its publish registered, then drop it from
    /// the queue.
    async fn abandon(&self, scope: &DrainScope<'_>, op_id: OpId, op: &Op) -> Result<(), Halt> {
        retire(self.api, &self.registered_by(scope, op).await)
            .await
            .map_err(|_| Halt::UploadAttempt)?;
        self.dequeue_op(op_id).await
    }

    /// Dead-letter one op. A failed retire leaves it queued for the next pass
    /// rather than dropping it with its registry rows still charged.
    async fn dead_letter(
        &self,
        scope: &DrainScope<'_>,
        op_id: OpId,
        op: &Op,
        reason: DeadLetterReason,
        report: &mut DrainReport,
    ) {
        if self.abandon(scope, op_id, op).await.is_ok() {
            self.release_staged_blocks(op).await;
            report.dead_letters.push((op_id, op.target, reason));
        }
    }

    /// Retire only the name half of [`Self::registered_by`], for an abandonment
    /// that keeps what the op uploaded.
    async fn retire_unreferenced_name(&self, scope: &DrainScope<'_>, op: &Op) -> Result<(), Halt> {
        let Some(name) = self.unreferenced_create_name(scope, op) else {
            return Ok(());
        };
        retire(self.api, &[name])
            .await
            .map_err(|_| Halt::UploadAttempt)
    }

    /// Whether this create would re-author a node the record plane already
    /// carries — the shape of a data directory restored from before its own
    /// drain, where the queue comes back and the marks that record what already
    /// published do not.
    ///
    /// The name derives from the node id this op minted, so a record that
    /// resolves there **and passes the child gate** is one this op published:
    /// the gate binds the record to this node id under this scope root, which
    /// nothing jammed at the name satisfies.
    ///
    /// What that alone cannot say is whether this device has *forgotten*
    /// publishing it, and two durable reads answer that before the network is
    /// touched. An op with a charged attempt is one this device remembers
    /// trying: an acked PUT whose confirm-by-re-resolve missed leaves exactly
    /// this record with exactly no floor, and the retry it is owed re-mints the
    /// same sequence. A raised sequence floor says the same for a publish that
    /// confirmed and then lost the parent naming it — the self-adopt raises the
    /// floor before that parent publishes, so a crash in the window re-authors
    /// as it always has. A restore rewinds both.
    ///
    /// A seam failure holds the op for a later pass rather than answering. Only
    /// an unresolvable name and a gate rejection read as "not published", and a
    /// create the drain cannot reach is one whose own publish would not land
    /// either.
    async fn create_replays_a_publish(
        &self,
        scope: &DrainScope<'_>,
        op_id: OpId,
        target: NodeId,
    ) -> Result<bool, Halt> {
        // The durable record, not this pass's copy: what a restore rewinds is
        // exactly what survives a restart.
        let attempts = Attempts::decode(
            self.staging
                .staged_bytes(OP_ATTEMPTS_KEY)
                .await
                .map_err(seam)?,
        );
        if attempts.charged_to(op_id) > 0 {
            return Ok(false);
        }
        let name = derive_write_name(scope.write_scope_seed, &target.0);
        if floor::sequence_floor(self.floors, name.as_str().as_bytes())
            .await
            .map_err(seam)?
            .is_some()
        {
            return Ok(false);
        }
        let adopter = ChildAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            scope.root.0,
            scope.read_scope_seed.clone(),
            target.0,
        );
        let resolved = resolve(
            self.transport,
            self.snapshot_cache,
            &adopter,
            &name,
            ResolveMode::NoCache,
        )
        .await
        .map_err(seam)?;
        Ok(matches!(resolved.outcome, ResolveOutcome::Adopted(_)))
    }

    /// The name a create derived, where nothing published references it yet: a
    /// name some published record already references would leave a reference
    /// outliving its referent, and the gate-passing base is the evidence — a
    /// created node reaches it only once a parent record naming it published.
    fn unreferenced_create_name(&self, scope: &DrainScope<'_>, op: &Op) -> Option<String> {
        let target_published = self.base.borrow().contains(op.target);
        (!target_published && matches!(op.kind, OpKind::Create { .. })).then(|| {
            derive_write_name(scope.write_scope_seed, &op.target.0)
                .as_str()
                .to_owned()
        })
    }

    /// The registry rows one op's publish registered, mirroring what the publish
    /// pipeline sends (`PublishRequest::registration`).
    ///
    /// The content CIDs go with **any** content-bearing op that reaches here: an
    /// abandonment only retires while the op's target is unreachable, so no
    /// record a parent links can name the version.
    ///
    /// Reads the manifest before [`Self::release_staged_blocks`] drops it: after
    /// that the leaf CIDs are recoverable from nowhere.
    async fn registered_by(&self, scope: &DrainScope<'_>, op: &Op) -> Vec<String> {
        let name = self.unreferenced_create_name(scope, op);
        let content = match op.content_root_cid() {
            Some(root_cid) => version_cids(
                root_cid,
                version_leaf_cids(self.staging, root_cid)
                    .await
                    .iter()
                    .map(Vec::as_slice),
                RootPlacement::First,
            ),
            None => Vec::new(),
        };
        name.into_iter().chain(content).collect()
    }

    /// The attempt record, pruned to the ops still queued. `live` is every id
    /// the store holds, not just this identity's, so one account's pass cannot
    /// reset a budget another account's ops are spending.
    async fn load_attempts(&self, live: &BTreeSet<OpId>) -> Result<Attempts, Halt> {
        let stored = self
            .staging
            .staged_bytes(OP_ATTEMPTS_KEY)
            .await
            .map_err(seam)?;
        let mut attempts = Attempts::decode(stored);
        if !attempts.counts.is_empty() {
            attempts.retain_live(live);
        }
        Ok(attempts)
    }

    async fn store_attempts(&self, attempts: &Attempts) -> Result<(), Halt> {
        if !attempts.dirty {
            return Ok(());
        }
        self.staging
            .put_staged_bytes(OP_ATTEMPTS_KEY, &attempts.encode())
            .await
            .map_err(seam)
    }

    /// Raise the completion mark over this pass's **contiguous** drained prefix.
    /// The mark is a high-water line, so it may only pass ops that have all
    /// left the queue: advancing it over a halted op would make a restored data
    /// dir discard that op as residue instead of publishing it.
    async fn mark_drained(
        &self,
        scope: &DrainScope<'_>,
        queued: &[(OpId, Op)],
        report: &DrainReport,
    ) -> Result<(), Halt> {
        let retired: BTreeSet<OpId> = report
            .published
            .iter()
            .chain(&report.dropped)
            .copied()
            .chain(report.dead_letters.iter().map(|(op_id, ..)| *op_id))
            .collect();
        let Some(mark) = queued
            .iter()
            .map_while(|(op_id, _)| retired.contains(op_id).then_some(op_id.0))
            .last()
        else {
            return Ok(());
        };
        // Monotonic by construction: the engine is the single writer, and the
        // mark only ever names ops that have already left the queue.
        self.raise_op_mark(
            &owner_scoped_key(DRAINED_OP_MARK_PREFIX, scope.enc_secret),
            mark,
        )
        .await
    }

    /// Raise this identity's published-op mark over `op_id`
    /// ([`PUBLISHED_OP_MARK_PREFIX`]).
    ///
    /// Raised the instant the op's **last** record publish confirms — before its
    /// self-adopt, and so before the block release — because everything from the
    /// ack onwards is a window a crash leaves a published op queued. Without it
    /// that op replays, re-uploads its leaves, and a cancel landing mid-replay
    /// unpins content a live record names; the session-scoped publish-entry
    /// interlock does not survive the reboot.
    ///
    /// Best-effort, unlike every other step of the publish: the record is
    /// already live by the time this runs, so failing the op over the mark would
    /// *cause* the replay the mark exists to prevent. The dequeue that follows
    /// is the primary guard; the mark is what survives losing it.
    async fn mark_published(&self, scope: &DrainScope<'_>, op_id: OpId) {
        let _ = self
            .raise_op_mark(
                &owner_scoped_key(PUBLISHED_OP_MARK_PREFIX, scope.enc_secret),
                op_id.0,
            )
            .await;
    }

    /// Raise the op-id high-water at `key` to `max(stored, mark)`.
    async fn raise_op_mark(&self, key: &[u8], mark: u64) -> Result<(), Halt> {
        let raised = mark.max(op_mark(self.staging, key).await.map_err(seam)?.unwrap_or(0));
        self.staging
            .put_staged_bytes(key, &raised.to_be_bytes())
            .await
            .map_err(seam)
    }

    /// The stored drained-op mark; `None` when nothing has drained on this
    /// device or the stored bytes are not a mark this build wrote.
    async fn drained_mark(&self, scope: &DrainScope<'_>) -> Result<Option<u64>, Halt> {
        op_mark(
            self.staging,
            &owner_scoped_key(DRAINED_OP_MARK_PREFIX, scope.enc_secret),
        )
        .await
        .map_err(seam)
    }

    /// The per-node read key (`node-seed` → `read-key`), owned by the caller of
    /// this fn — it is the terminal owner and zeroizes on drop.
    fn node_read_key(&self, scope: &DrainScope<'_>, node_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
        let node_seed = kdf::node_seed(scope.read_scope_seed, node_id);
        Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes())
    }
}

/// The `contentCid` of a file body's head version — the conditional-edit
/// anchor. `None` for a file with no version, and for a folder body, which the
/// publish plan refuses on its own.
fn head_version_cid(body: &ReadBody) -> Option<&[u8]> {
    match body {
        ReadBody::File { versions, .. } => versions.first().map(|head| head.content_cid.as_slice()),
        ReadBody::Folder { .. } => None,
    }
}

fn local_head(head: &AuthoredHead) -> LocalHead {
    LocalHead {
        cid: head.cid.clone(),
        block: head.block.clone(),
    }
}

fn seam(_: crate::seams::SeamError) -> Halt {
    Halt::Unclassified
}

/// Whether the op a hold names is still in this identity's queue — the shared
/// half of both hold gates, since a hold on an op that left is stale.
fn still_queued(queued: &[(OpId, Op)], held: OpId) -> bool {
    queued.iter().any(|(op_id, _)| *op_id == held)
}

/// Classify an authoring refusal for the valve. Exhaustive by construction: an
/// unclassified refusal retries free and forever, so a new variant must be
/// judged here rather than inheriting that arm.
///
/// A trust refusal is charged, not dead-lettered on sight: the scope root it is
/// authored from comes from the snapshot cache, which a later resolve replaces,
/// so an immediate permanent verdict would abandon a user's ops over a cache
/// another tick repairs.
///
/// An over-length head is charged on [`Halt::HeadOversized`]'s terms rather
/// than judged permanent, because the attacker-influenced side of a body must
/// never refuse an owner's publish outright (blueprint/core.md: an over-length
/// carry is truncated, never refused).
///
/// [`AuthorError::Seal`] is the one refusal left uncharged: it judges the body
/// *this* pass built, which a rebase onto other state may not build again.
fn classify_author(error: AuthorError) -> Halt {
    match error {
        AuthorError::GrantSectionOnChild
        | AuthorError::MissingGrantSection
        | AuthorError::InvalidGrantSection
        | AuthorError::CommitmentNameMismatch
        | AuthorError::CommitmentSignatureInvalid
        | AuthorError::SectionSignatureInvalid => Halt::UploadAttempt,
        // Charged on the same terms as an over-length head: re-authoring the
        // same section repeats it verbatim, so an uncharged retry would spin.
        AuthorError::HeadTooLarge { .. }
        | AuthorError::ScopeRootNotResealable { .. }
        | AuthorError::GrantSectionTooLarge => Halt::HeadOversized,
        AuthorError::Seal(_) => Halt::Unclassified,
    }
}

/// Hand control back to the host's executor once, so a facade command queued
/// behind this task gets a turn. The engine runs pinned to one execution
/// context, so a long await-free stretch is one the host cannot interrupt.
async fn yield_now() {
    let mut yielded = false;
    core::future::poll_fn(move |cx| {
        if yielded {
            return core::task::Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        core::task::Poll::Pending
    })
    .await;
}

/// Classify a publish failure for the valve. Only the head-block upload and the
/// register-first call carry a server verdict this pass can act on; everything
/// else is availability.
///
/// `refused_bytes` is what the upload asked for, so a block entered here records
/// the figure its resume probe must find room for.
fn classify_publish(error: RecordPublishError, refused_bytes: u64) -> Halt {
    match error {
        RecordPublishError::Upload(error) => classify_upload(error, refused_bytes),
        RecordPublishError::Publish(PublishError::Register(error)) => classify_register(error),
        RecordPublishError::HeadCidMismatch { .. } | RecordPublishError::Publish(_) => {
            Halt::Unclassified
        }
    }
}

/// The op-id high-water stored at `key`; `None` when nothing has been marked on
/// this device or the stored bytes are not a mark this build wrote.
async fn op_mark<St: StagingStore>(staging: &St, key: &[u8]) -> SeamResult<Option<u64>> {
    Ok(staging
        .staged_bytes(key)
        .await?
        .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
        .map(u64::from_be_bytes))
}

/// The published-op mark for `enc_secret`'s identity. Read by the drain and by
/// the facade's cancel command, which owe the same answer about an op whose
/// version is already live.
pub(crate) async fn published_op_mark<St: StagingStore>(
    staging: &St,
    enc_secret: &X25519Secret,
) -> SeamResult<Option<u64>> {
    op_mark(
        staging,
        &owner_scoped_key(PUBLISHED_OP_MARK_PREFIX, enc_secret),
    )
    .await
}

/// Classify a register-first refusal under [`classify_upload`]'s rule, over the
/// discriminator the registry stamps.
fn classify_register(error: ApiError) -> Halt {
    match error {
        ApiError::Status {
            status: 400, code, ..
        } if code.as_deref() == Some(REGISTRY_BATCH_REFUSED) => {
            Halt::Permanent(DeadLetterReason::PayloadRefused)
        }
        ApiError::MalformedContentCid => Halt::Permanent(DeadLetterReason::PayloadRefused),
        ApiError::Status { status, .. } if !answers_about_the_caller(status) => Halt::UploadAttempt,
        ApiError::Decode(_) => Halt::UploadAttempt,
        ApiError::Status { .. }
        | ApiError::Transport(_)
        | ApiError::Unauthorized
        | ApiError::Forbidden => Halt::Unclassified,
    }
}

/// A status that judges the caller's session or its request rate rather than the
/// bytes it carried, so it may not spend the version's attempt budget: five
/// charged ticks is under three minutes, and the drain would destroy a queued
/// write over a throttle window that clears on its own.
fn answers_about_the_caller(status: u16) -> bool {
    status == 429
}

/// Classify a content-upload failure for the valve. The same server verdicts a
/// head-block upload can carry, since content blocks and head blocks go through
/// one endpoint.
///
/// Exhaustive by construction, on one rule: a refusal that judged **these bytes**
/// is charged, so a standing refusal — the 503 an unreachable pin store answers —
/// escalates to a dead-letter instead of parking the strict-FIFO queue's head
/// forever. A failure that judged the transport, the session, or the request rate
/// is not.
fn classify_upload(error: ApiError, refused_bytes: u64) -> Halt {
    match error {
        // 413 covers two unrelated causes, so each verdict rests on **positive
        // evidence only**: the discriminators the API stamps. A response
        // carrying neither did not come from a gate that inspected these bytes —
        // a proxy body cap answers 413 with no code at all — and neither holding
        // the head nor abandoning the op is a conclusion it supports. The same
        // rule is why no bare status dead-letters: the API stamps no `code` on
        // its 400s, so one is indistinguishable from a proxy's.
        ApiError::Status {
            status: 413, code, ..
        } => match code.as_deref() {
            Some(QUOTA_EXCEEDED) => Halt::Blocked {
                needed_bytes: refused_bytes,
            },
            Some(UPLOAD_TOO_LARGE) => Halt::Permanent(DeadLetterReason::PayloadRefused),
            _ => Halt::UploadAttempt,
        },
        // Refused before a request was built, so the address this op would
        // re-send is what no retry changes.
        ApiError::MalformedContentCid => Halt::Permanent(DeadLetterReason::PayloadRefused),
        ApiError::Status { status, .. } if !answers_about_the_caller(status) => Halt::UploadAttempt,
        ApiError::Decode(_) => Halt::UploadAttempt,
        // A transport failure never reached a gate, and a session the client's
        // own refresh-then-retry could not revive is answered by a re-login
        // rather than by spending this version's attempt budget. A 403 judges
        // the caller's authorization the same way, so it is not these bytes'
        // to pay for.
        ApiError::Status { .. }
        | ApiError::Transport(_)
        | ApiError::Unauthorized
        | ApiError::Forbidden => Halt::Unclassified,
    }
}

/// Classify an external-only placement failure for the valve, on the same
/// positive-evidence rule [`classify_upload`] applies to the hosted leg: a
/// transport failure carries no verdict about these bytes, and charging the
/// attempt budget for one would spend the version's five tries on a condition
/// that repairs itself. Everything the provider *answered* is charged.
///
/// A policy verdict is neither: it is deterministic, so it holds the op rather
/// than charging it ([`SettingsHold`]).
fn classify_placement(error: ProviderError) -> Halt {
    if error.is_deterministic() {
        return Halt::HeldBySettings(SettingsRefusal::Byo(error));
    }
    match error {
        ProviderError::Unreachable => Halt::Unclassified,
        _ => Halt::UploadAttempt,
    }
}

/// The verdict this session's settings reach before any request is built,
/// which is what a [`Halt::HeldBySettings`] hold waits on changing. Two
/// sources, one axis: a placement that decided but names a config
/// [`validate_byo_config`] refuses, and one that could not decide at all.
///
/// Only the external-only leg can hold an op on its config: a dual write's
/// mirror is best-effort and never fails the op.
fn settings_refusal(placement: &PlacementDecision) -> Option<SettingsRefusal> {
    match placement {
        Ok(Placement::External(config)) => validate_byo_config(config)
            .err()
            .filter(ProviderError::is_deterministic)
            .map(SettingsRefusal::Byo),
        Ok(_) => None,
        Err(refusal) => refusal.holds(),
    }
}

/// A block count as [`BlockProgress`] carries it; the root manifest's own
/// ceiling bounds a version's leaves far below `u32::MAX`.
fn blocks(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// The key-free classification an [`OpPhase::UploadFailed`] carries, or `None`
/// where the halt is not a failed attempt: either hold keeps the op and its
/// reservation, and the host reads them from `SnapshotView::blocked` and
/// `SnapshotView::settings_hold`.
fn upload_failure(halt: Halt) -> Option<&'static str> {
    match halt {
        // A cancel reports `UploadCancelled` from the facade that ordered it.
        Halt::Blocked { .. } | Halt::HeldBySettings(_) | Halt::Cancelled => None,
        Halt::Unclassified => Some("the upload did not complete"),
        Halt::Attempt | Halt::UploadAttempt => {
            Some("the network refused it without a classification")
        }
        Halt::HeadOversized => Some("the record this change publishes is over the size limit"),
        Halt::Permanent(DeadLetterReason::PayloadRefused) => {
            Some("the network refused the payload")
        }
        Halt::Permanent(_) => Some("the staged version can never publish"),
    }
}

/// An [`OpPhase::ExternalPinFailed`] for a mirror that no request could have
/// filled: the blocks left staging for the provider the settings named at the
/// time, and only the leg that can fail the op still holds them.
const MIRROR_GAP: &str = "your own IPFS provider changed while this upload was in flight, so it never received \
     the blocks already sent";

/// What this version's mirror is short by. A live refusal outranks the standing
/// gap: it is the condition the member can still act on.
fn mirror_shortfall(uploaded: &UploadedVersion) -> Option<&'static str> {
    uploaded
        .external_failure
        .as_ref()
        .map(provider_failure)
        .or_else(|| uploaded.mirror_gap.then_some(MIRROR_GAP))
}

/// The key-free classification an [`OpPhase::ExternalPinFailed`] carries. It
/// names the leg, never the endpoint or the bearer the config carries.
///
/// Exhaustive by construction: a new [`ProviderError`] must be attributed here
/// rather than falling into whichever wording happened to be the catch-all.
fn provider_failure(error: &ProviderError) -> &'static str {
    match error {
        ProviderError::Unreachable => "your own IPFS provider could not be reached",
        ProviderError::Rejected { .. } => "your own IPFS provider refused the block",
        ProviderError::AddressMismatch => {
            "your own IPFS provider stored the block at a different address"
        }
        ProviderError::NoVerdict => "your own IPFS provider gave no usable answer",
        // Policy verdicts reached before any request is built, so the member's
        // own settings are what to fix, not their node.
        ProviderError::InvalidEndpoint
        | ProviderError::InsecureTransport
        | ProviderError::BlockedAddress
        | ProviderError::InvalidCredential => "your own IPFS provider settings were refused",
        ProviderError::MalformedBlockAddress => {
            "the block's address is not one any provider can be told to store"
        }
    }
}

/// A `contentCid` a resolved record carried, held to the frozen framing.
///
/// Core decodes the field as opaque bytes, so nothing upstream has rejected a
/// malformed one — and [`encode_content_cid_str`]'s own guard is a release-active
/// panic, which on the wasm leg takes the worker down.
fn checked_content_cid(cid: &[u8]) -> Result<&[u8], Halt> {
    is_wellformed_content_cid(cid)
        .then_some(cid)
        .ok_or(Halt::Permanent(DeadLetterReason::PayloadRefused))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{DefaultsReason, PlacementRefusal};

    fn attempts(pairs: &[(u64, u32)]) -> Attempts {
        let mut attempts = Attempts::default();
        for (op_id, count) in pairs {
            for _ in 0..*count {
                attempts.charge(OpId(*op_id));
            }
        }
        attempts
    }

    /// A budget only bounds a pathology if it survives the restart that a
    /// half-published op is most likely to hit.
    #[test]
    fn the_attempt_record_survives_a_round_trip() {
        let stored = attempts(&[(1, 2), (9, 1)]).encode();
        assert_eq!(
            Attempts::decode(Some(stored)).counts,
            BTreeMap::from([(OpId(1), 2), (OpId(9), 1)])
        );
    }

    /// The staging store is shared with whatever build and identity wrote it, so
    /// bytes this build did not write must read as no attempts — a fabricated
    /// count would spend another op's budget and abandon it early.
    #[test]
    fn bytes_this_build_did_not_write_read_as_no_attempts() {
        let foreign_but_well_sized = {
            let mut bytes = attempts(&[(1, 2)]).encode();
            bytes[0] = ATTEMPT_FORMAT_V1.wrapping_add(1);
            bytes
        };
        for stored in [
            None,
            Some(Vec::new()),
            Some(vec![0xAB; 7]),
            Some(vec![0xAB; ATTEMPT_ENTRY_LEN]),
            Some(foreign_but_well_sized),
        ] {
            assert!(Attempts::decode(stored).counts.is_empty());
        }
    }

    fn byo(endpoint: &str) -> crate::content::ByoIpfsConfig {
        crate::content::ByoIpfsConfig {
            endpoint: endpoint.to_owned(),
            kind: crate::content::ByoKind::Kubo,
            access_token: None,
        }
    }

    /// A transport failure carries no verdict about these bytes, so it must not
    /// spend the version's attempt budget — the hosted leg's own rule
    /// ([`classify_upload`]) applied to the member's provider.
    #[test]
    fn only_an_answered_placement_charges_the_attempt_budget() {
        assert_eq!(
            classify_placement(ProviderError::Unreachable),
            Halt::Unclassified,
        );
        for answered in [
            ProviderError::NoVerdict,
            ProviderError::Rejected { status: 500 },
            ProviderError::AddressMismatch,
        ] {
            assert_eq!(classify_placement(answered), Halt::UploadAttempt);
        }
    }

    #[test]
    fn a_config_refused_before_the_request_holds_the_op_rather_than_spending_its_budget() {
        for settings in [
            ProviderError::InvalidEndpoint,
            ProviderError::InsecureTransport,
            ProviderError::BlockedAddress,
            ProviderError::InvalidCredential,
        ] {
            assert_eq!(
                classify_placement(settings),
                Halt::HeldBySettings(SettingsRefusal::Byo(settings)),
                "{}",
                settings.check(),
            );
        }
    }

    /// The hold's exit is the settings, not a timer: it stands exactly while
    /// the placement this session runs under still reaches the same verdict.
    #[test]
    fn a_settings_hold_lets_go_only_once_the_placement_stops_refusing() {
        let refused = byo("file:///etc/passwd");
        assert_eq!(
            settings_refusal(&Ok(Placement::External(refused.clone()))),
            Some(SettingsRefusal::Byo(ProviderError::InvalidEndpoint)),
        );
        assert_eq!(
            settings_refusal(&Err(PlacementRefusal::NoProvider)),
            Some(SettingsRefusal::Placement(PlacementRefusal::NoProvider)),
        );
        for admitted in [
            Ok(Placement::External(byo("https://node.example"))),
            Ok(Placement::Hosted),
            // A dual write's mirror is best-effort, so no verdict on it holds
            // the op that the hosted leg is already carrying.
            Ok(Placement::Dual(refused)),
            // A degraded load repairs itself, so no member action is its exit.
            Err(PlacementRefusal::SettingsUnavailable(
                DefaultsReason::Suppressed,
            )),
        ] {
            assert_eq!(settings_refusal(&admitted), None);
        }
    }

    /// The report names what the member must fix. A verdict reached before any
    /// request is built is their own settings, not their node.
    #[test]
    fn a_policy_verdict_is_attributed_to_the_settings_not_the_node() {
        for settings in [
            ProviderError::InvalidEndpoint,
            ProviderError::InsecureTransport,
            ProviderError::BlockedAddress,
            ProviderError::InvalidCredential,
        ] {
            assert_eq!(
                provider_failure(&settings),
                "your own IPFS provider settings were refused",
            );
        }
        assert_ne!(
            provider_failure(&ProviderError::MalformedBlockAddress),
            "your own IPFS provider settings were refused",
            "a block this plane cannot address is not a settings mistake",
        );
    }

    #[test]
    fn a_retired_ops_count_leaves_with_it() {
        let mut attempts = attempts(&[(1, 3), (2, 1)]);
        attempts.retain_live(&BTreeSet::from([OpId(2)]));
        assert_eq!(attempts.counts, BTreeMap::from([(OpId(2), 1)]));
    }

    /// A refusal the API answered with no discriminator stamped on it.
    fn answered(status: u16) -> ApiError {
        ApiError::Status {
            status,
            message: None,
            code: None,
        }
    }

    /// Positive evidence only: one status covers the account-quota gate and the
    /// transport cap, so each verdict needs the API's own discriminator.
    #[test]
    fn each_413_verdict_rests_on_the_apis_own_code() {
        let refusal = |code: Option<&str>| {
            classify_publish(
                RecordPublishError::Upload(ApiError::Status {
                    status: 413,
                    message: Some("too large".to_owned()),
                    code: code.map(str::to_owned),
                }),
                4096,
            )
        };
        assert_eq!(
            refusal(Some(QUOTA_EXCEEDED)),
            Halt::Blocked { needed_bytes: 4096 }
        );
        assert_eq!(
            refusal(Some(UPLOAD_TOO_LARGE)),
            Halt::Permanent(DeadLetterReason::PayloadRefused)
        );
        for code in [None, Some("SOMETHING_NEW")] {
            assert_eq!(
                refusal(code),
                Halt::UploadAttempt,
                "a 413 the API did not stamp is a proxy, and supports neither verdict"
            );
        }
    }

    /// The destruction-critical arm: a fan-out that acked nothing may still
    /// have stored the record, so its head stays pinned. Everything else here
    /// stopped short of the transport with a charged row behind it, or with no
    /// row at all.
    #[test]
    fn only_a_publish_that_never_reached_the_transport_orphans_its_head() {
        use RecordPublishError::Upload;
        for (error, orphaned) in [
            (
                RecordPublishError::Publish(PublishError::AllEndpointsFailed),
                false,
            ),
            (
                RecordPublishError::Publish(PublishError::Register(ApiError::Unauthorized)),
                true,
            ),
            (
                RecordPublishError::Publish(PublishError::EmptyHeadCid),
                false,
            ),
            (
                RecordPublishError::Publish(PublishError::FloorRead(crate::seams::SeamError::new(
                    "floor",
                ))),
                true,
            ),
            (
                RecordPublishError::Publish(PublishError::RecordTooLarge {
                    size: 10_241,
                    limit: 10_240,
                }),
                true,
            ),
            (
                RecordPublishError::HeadCidMismatch {
                    expected: "a".to_owned(),
                    returned: "b".to_owned(),
                },
                true,
            ),
            (
                Upload(ApiError::Status {
                    status: 413,
                    message: None,
                    code: Some(UPLOAD_TOO_LARGE.to_owned()),
                }),
                false,
            ),
            (Upload(ApiError::Unauthorized), false),
            (
                Upload(ApiError::Transport(crate::seams::SeamError::new("dropped"))),
                true,
            ),
            (Upload(ApiError::Decode("short body".to_owned())), true),
        ] {
            assert_eq!(
                orphaned_head(&error),
                orphaned,
                "{error:?} orphans its head block: {orphaned}"
            );
        }
    }

    /// The compensation branches on this and nothing else: a failure carries
    /// its classification and, separately, whether the record it was publishing
    /// is live. Collapsing the two would undo a move that landed.
    #[test]
    fn a_publish_failure_keeps_its_verdict_and_its_confirmation_apart() {
        for halt in [Halt::Unclassified, Halt::Attempt] {
            assert_eq!(
                PublishHalt::before_the_put(halt),
                PublishHalt {
                    halt,
                    confirmed: false
                }
            );
            assert_eq!(
                PublishHalt::past_the_put(halt),
                PublishHalt {
                    halt,
                    confirmed: true
                }
            );
            assert_eq!(Halt::from(PublishHalt::past_the_put(halt)), halt);
        }
    }

    /// A failure that judged something other than these bytes is availability:
    /// retried indefinitely and charged nothing, so an unreachable network, a
    /// session a re-login revives, an authorization a re-grant restores, or a
    /// throttle window never abandons an op.
    #[test]
    fn a_failure_carrying_no_verdict_on_these_bytes_is_availability() {
        for error in [
            RecordPublishError::Upload(ApiError::Transport(crate::seams::SeamError::new("gone"))),
            RecordPublishError::Upload(ApiError::Unauthorized),
            RecordPublishError::Upload(ApiError::Forbidden),
            RecordPublishError::Upload(answered(429)),
            RecordPublishError::Publish(PublishError::Register(ApiError::Unauthorized)),
            RecordPublishError::Publish(PublishError::Register(ApiError::Forbidden)),
            RecordPublishError::Publish(PublishError::Register(answered(429))),
            RecordPublishError::HeadCidMismatch {
                expected: "a".to_owned(),
                returned: "b".to_owned(),
            },
            RecordPublishError::Publish(crate::net::PublishError::AllEndpointsFailed),
        ] {
            assert_eq!(classify_publish(error, 4096), Halt::Unclassified);
        }
    }

    /// A status with no discriminator carries no permanent verdict — the API
    /// stamps none on its 400s, so one is indistinguishable from a proxy's — but
    /// it did judge these bytes, so it costs an attempt. Uncharged, a standing
    /// 503 parks the strict-FIFO queue's head forever and the op never settles.
    #[test]
    fn a_refusal_of_these_bytes_costs_an_attempt_and_never_dead_letters_on_sight() {
        for status in [400, 409, 500, 502, 503] {
            for error in [
                RecordPublishError::Upload(answered(status)),
                RecordPublishError::Publish(PublishError::Register(answered(status))),
            ] {
                assert_eq!(
                    classify_publish(error, 4096),
                    Halt::UploadAttempt,
                    "a refusal answered {status} escalates by budget, not on sight"
                );
            }
        }
        assert_eq!(
            classify_publish(
                RecordPublishError::Upload(ApiError::MalformedContentCid),
                4096
            ),
            Halt::Permanent(DeadLetterReason::PayloadRefused),
            "an address no request could carry is the one client-side certainty"
        );
    }

    /// A trust refusal is charged so the queue stops at the budget instead of
    /// spinning free, and so is an over-length head, which no re-author can
    /// shrink — but the two spend that budget differently, so the size refusal
    /// keeps its own verdict. A refusal of the body *this pass* built is
    /// charged neither way: a rebase onto other state may never build it again.
    #[test]
    fn only_a_refusal_a_rebase_cannot_shed_is_charged_against_the_attempt_budget() {
        for (error, expected) in [
            (AuthorError::GrantSectionOnChild, Halt::UploadAttempt),
            (AuthorError::MissingGrantSection, Halt::UploadAttempt),
            (AuthorError::InvalidGrantSection, Halt::UploadAttempt),
            (AuthorError::CommitmentNameMismatch, Halt::UploadAttempt),
            (AuthorError::CommitmentSignatureInvalid, Halt::UploadAttempt),
            (AuthorError::SectionSignatureInvalid, Halt::UploadAttempt),
            (
                AuthorError::Seal(cipherbox_core::error::TrustViolation::DuplicateId.into()),
                Halt::Unclassified,
            ),
            (
                AuthorError::HeadTooLarge {
                    field: "envelope",
                    size: 2,
                    limit: 1,
                },
                Halt::HeadOversized,
            ),
            (AuthorError::GrantSectionTooLarge, Halt::HeadOversized),
        ] {
            let check = error.check();
            assert_eq!(classify_author(error), expected, "{check}");
        }
    }
}
