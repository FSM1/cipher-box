//! The metadata publish driver: turn queued intent ops into published,
//! resolvable records (blueprint/engine.md "Sync core", "Resolve/publish
//! pipeline").
//!
//! One pass rebases the durable queue onto gate-passing state ([`replay`]) and
//! publishes each applied op under one law: **a reference must never outlive
//! its referent** (#819). Child before parent, dest-add before source-remove,
//! and strict FIFO stopping at the first failure — so a partial drain can leave
//! an unreferenced record but never a ref pointing at a name nothing resolves.
//!
//! Every published record is fed straight back through the adoption gate from
//! the bytes in hand: the write path skips the fetch, never the gate, and the
//! per-name sequence floor advances only as the gate's stage-6 consequence
//! (#817; `gate/floor.rs` stays the only place floors move).
//!
//! What the pass does when a publish will not succeed is the failure valve
//! ([`Halt`], #867).
//!
//! Out of this slice: content bytes (#868), and cross-scope re-seal with the
//! scope-exit rotation trigger (#635).

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::codec::Value;
use cipherbox_core::content::{encode_content_cid_str, verify_cid};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{ChildRef, ReadBody, Version, open_content_key, open_read_body};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::x25519::X25519Secret;
use futures_channel::mpsc;
use zeroize::Zeroizing;

use crate::api::{ApiClient, ApiError, QUOTA_EXCEEDED, REGISTRY_BATCH_REFUSED, UPLOAD_TOO_LARGE};
use crate::content::{Gateway, SealedContent, pre_flight_quota_check};
use crate::entropy::Entropy;
use crate::facade::{BlockProgress, Event, NodeId, OpPhase};
use crate::gate::floor;
use crate::grants::{UndoDestAdd, undo_dest_add_versioned};
use crate::net::author::{
    AuthoredHead, ENVELOPE_V, EnvelopeAuthoring, NewNodeBody, author_child_envelope,
    author_scope_root_envelope, new_child,
};
use crate::net::publish::{PublishError, PublishOutcome, PublishReceipt};
use crate::net::record_publish::{
    HeadBinding, RecordPublishError, RecordPublishRequest, preflight, publish_record,
};
use crate::net::retire::retire;
use crate::net::{
    Adopter, ChildAdopter, HeldRecord, HeldRecords, LocalHead, REGISTRY_BATCH_MAX, ResolveOutcome,
    RootAdopter, assemble_head_envelope, fanout_get_verify, resolve,
};
use crate::profile::SyncTimingProfile;
use crate::rotation::derive_write_name;
use crate::seams::{
    CredentialStore, FloorStore, Http, OpId, RecordTransport, Scheduler, SnapshotCache,
    StagingStore,
};
use crate::session::SessionIdentity;
use crate::sync::model::{Snapshot, collation_key};
use crate::sync::op::{NewNode, Op, OpKind, StagedContent};
use crate::sync::overlay::apply_overlay;
use crate::sync::project::project_folder;
use crate::sync::rebase::{AppliedOp, DeadLetterReason, decode_queue, replay};
use crate::sync::record::RecordReader;

/// The staging key holding the drained-op high-water mark: every op id at or
/// below the stored value has left this device's queue (#860).
///
/// It lives in the staging store rather than the floors so the mark and the op
/// ids it names share one durability domain — a store that loses its queue
/// loses the mark with it, instead of retaining a mark that would delete every
/// id the restarted counter reissues. [`orphan_staging_keys`] treats it as
/// referenced so orphan GC never collects it.
///
/// [`orphan_staging_keys`]: crate::sync::staging::orphan_staging_keys
pub const DRAINED_OP_MARK_KEY: &[u8] = b"cipherbox/drained-op";

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
    /// queue that holds them is older than the completion record (#860).
    pub(crate) restore_residue: Vec<OpId>,
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

/// What stopped a drain pass, and what the valve does about it (#867). Strict
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
    /// sequence and a jammed name would otherwise retry forever.
    Attempt,
    /// An upload or registration refusal this pass cannot attribute. Charged
    /// like [`Halt::Attempt`], but raised strictly **before** the record PUT —
    /// so exhausting the budget may retire what the op uploaded, which an acked
    /// PUT's may not.
    UploadAttempt,
    /// Classified-permanent: the same bytes are refused on every retry.
    Permanent(DeadLetterReason),
    /// Over the account quota. Not a failure of the op — it holds the head and
    /// its staging reservation until a quota probe reports room (#841).
    Blocked {
        /// The byte count the refused upload asked for, and so the figure the
        /// resume probe must find room for.
        needed_bytes: u64,
    },
}

/// The one verdict every unrecoverable-content path returns: the version's key,
/// root, or a leaf is gone, and no retry brings any of them back.
const CONTENT_LOST: Halt = Halt::Permanent(DeadLetterReason::ContentUnrecoverable);

/// The staging key holding the head content op's upload progress: its root CID
/// followed by a big-endian `u32` leaf count.
///
/// Without it, a leaf missing before the first present one is indistinguishable
/// from one a previous pass uploaded — so an evicted or deleted prefix would
/// publish a version whose manifest names blocks nothing holds. It lives beside
/// the queue's other bookkeeping for the same reason [`DRAINED_OP_MARK_KEY`]
/// does, and [`orphan_staging_keys`] treats it as referenced.
///
/// [`orphan_staging_keys`]: crate::sync::staging::orphan_staging_keys
pub const UPLOAD_MARK_KEY: &[u8] = b"cipherbox/upload-mark";

/// How many non-confirming publish attempts one op gets before it dead-letters.
///
/// Bounds a pathology, not a network outage — only [`Halt::Attempt`] and
/// [`Halt::UploadAttempt`] are charged.
const ATTEMPT_BUDGET: u32 = 5;

/// The staging key holding per-op drain attempt counts: a one-byte format tag
/// followed by `(op_id, attempts)` pairs, big-endian and fixed-width, rewritten
/// each pass over the live queue so a retired op's count leaves with it.
///
/// It lives in the staging store for the same reason [`DRAINED_OP_MARK_KEY`]
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
/// later drain tick reports room (#841).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockedOp {
    /// The held op.
    pub op_id: OpId,
    /// The node the op targets, so a host can point at it.
    pub node: NodeId,
    /// The byte count the resume probe must find room for.
    pub needed_bytes: u64,
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
    pub(crate) profile: &'a SyncTimingProfile,
    /// Seal nonces enter as injected entropy; the drain reads no RNG of its own.
    pub(crate) entropy: &'a RefCell<Box<dyn Entropy>>,
    /// The gate-passing base snapshot, repainted in place on each publish.
    pub(crate) base: &'a RefCell<Snapshot>,
    /// The live held-record set the liveness loop keeps alive.
    pub(crate) held: &'a RefCell<HeldRecords>,
    /// The over-quota hold, shared with the facade's read surface. It clears
    /// only here, on a quota probe reporting room.
    pub(crate) blocked: &'a RefCell<Option<BlockedOp>>,
    /// Head blocks this session's publishes orphaned, pending retirement
    /// ([`Drain::retire_orphan_heads`]).
    pub(crate) orphan_heads: &'a RefCell<Vec<String>>,
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
    envelope_unknown: Vec<(String, Value)>,
    epoch_tag_unknown: Vec<(String, Value)>,
    created_at: u64,
    modified_at: u64,
    children: Vec<ChildRef>,
    body_unknown: Vec<(String, Value)>,
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
    /// `None` keeps the name the ref already carries.
    new_name: Option<String>,
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

/// One node's record as loaded for re-authoring: the envelope fields a
/// republish must carry forward byte-stable (#27 D10) plus the opened body.
struct LoadedNode {
    name: IpnsName,
    sequence: u64,
    envelope_unknown: Vec<(String, Value)>,
    epoch_tag_unknown: Vec<(String, Value)>,
    body: ReadBody,
}

/// One version's blocks, uploaded and pinned.
struct UploadedVersion {
    /// The version the node's record carries.
    version: Version,
    /// Every content CID the registration names: the root first, then the
    /// leaves in file order.
    content_cids: Vec<String>,
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
    /// Run one pass: rebase the queue onto gate-passing state and publish every
    /// applied op it can, stopping at the first it cannot, then clear what the
    /// pass orphaned.
    pub(crate) async fn run(&self, scope: &DrainScope<'_>) -> DrainReport {
        let report = self.drain_queue(scope).await;
        self.retire_orphan_heads().await;
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
            return report;
        }
        let Ok(mut attempts) = self.load_attempts(&all_ids).await else {
            return report;
        };
        let _ = self.pass(scope, &queued, &mut report, &mut attempts).await;
        let _ = self.store_attempts(&attempts).await;
        let _ = self.mark_drained(&queued, &report).await;
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

        let mut pass = self.open_pass(scope).await?;
        let rebased = {
            let base = self.base.borrow();
            let ops: Vec<Op> = queued.iter().map(|(_, op)| op.clone()).collect();
            let local = apply_overlay(&base, &ops);
            replay(&base, &local, queued)
        };

        for (op_id, reason) in &rebased.dead_letters {
            let Some((_, op)) = queued.iter().find(|(id, _)| id == op_id) else {
                continue;
            };
            self.abandon(scope, *op_id, op).await?;
            report.dead_letters.push((*op_id, op.target, *reason));
        }
        // A drop is not an abandonment: `AlreadySatisfied` on a create is the
        // create having *landed*, so retiring its name would cut a live record
        // its parent already references.
        for (op_id, _) in &rebased.dropped {
            self.dequeue_op(*op_id).await?;
            report.dropped.push(*op_id);
        }

        for applied in &rebased.applied {
            if let Err(halt) = self
                .publish_applied(scope, &mut pass, applied, &rebased.rebased)
                .await
            {
                self.apply_valve(scope, applied.op_id, &applied.op, halt, attempts, report)
                    .await;
                return Err(halt);
            }
            self.dequeue_op(applied.op_id).await?;
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
            Halt::Attempt | Halt::UploadAttempt => {
                if attempts.charge(op_id) < ATTEMPT_BUDGET {
                    return;
                }
                let reason = DeadLetterReason::AttemptsExhausted;
                if halt == Halt::UploadAttempt {
                    self.dead_letter(scope, op_id, op, reason, report).await;
                } else if self.dequeue_op(op_id).await.is_ok() {
                    // An acked PUT may be resolvable at the name, so nothing is
                    // retired: unpinning content a live record still names is
                    // loss, where leaving the rows charged is only a leak.
                    self.release_staged_blocks(op).await;
                    report.dead_letters.push((op_id, op.target, reason));
                }
            }
            Halt::Permanent(reason) => {
                self.dead_letter(scope, op_id, op, reason, report).await;
            }
            Halt::Blocked { needed_bytes } => {
                *self.blocked.borrow_mut() = Some(BlockedOp {
                    op_id,
                    node: op.target,
                    needed_bytes,
                });
            }
        }
    }

    /// Whether a held head may be tried again this tick. A `GET /account/quota`
    /// probe reporting room is the hold's only exit (#841), so an unanswered
    /// probe leaves it in place.
    async fn quota_admits_the_held_head(&self, queued: &[(OpId, Op)]) -> bool {
        let Some(blocked) = *self.blocked.borrow() else {
            return true;
        };
        if !queued.iter().any(|(op_id, _)| *op_id == blocked.op_id) {
            self.clear_block();
            return true;
        }
        let Ok(quota) = self.api.quota().await else {
            return false;
        };
        if pre_flight_quota_check(blocked.needed_bytes, &quota).is_err() {
            return false;
        }
        self.clear_block();
        true
    }

    fn clear_block(&self) {
        *self.blocked.borrow_mut() = None;
    }

    /// This identity's queued ops, minus restore residue: an op at or below the
    /// durable drained-op mark already left this queue once, so the queue it
    /// came back in predates the completion record (#860).
    async fn queued_ops(
        &self,
        scope: &DrainScope<'_>,
        report: &mut DrainReport,
    ) -> Result<Queue, Halt> {
        let raw = self.staging.queued_ops().await.map_err(seam)?;
        let all_ids = raw.iter().map(|(op_id, _)| *op_id).collect();
        let scan = decode_queue(&RecordReader::new(scope.enc_secret), &raw);
        // `None` is "no op has ever drained here", not "id 0 drained": the seam
        // contract promises only strictly-increasing ids, so a host that starts
        // at 0 must not lose its first op.
        let drained = self.drained_mark().await?;
        let mut mine = Vec::with_capacity(scan.mine.len());
        for (op_id, op) in scan.mine {
            if drained.is_some_and(|mark| op_id.0 <= mark) {
                self.dequeue_op(op_id).await?;
                report.restore_residue.push(op_id);
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
        .map_err(|_| Halt::Unclassified)?;
        // The cache can be older than the floors — a restored data dir is
        // exactly that (#860). The whole pass anchors here: this record's epoch
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
        .map_err(|_| Halt::Unclassified)?;
        // Encode/decode fail-closed symmetry: this build authors exactly
        // `ENVELOPE_V`, so republishing a newer client's root would silently
        // downgrade `v` — the exact rollback the read-body AAD defends against.
        if envelope.v != ENVELOPE_V {
            return Err(Halt::Unclassified);
        }
        let read_key = self.node_read_key(scope, &scope.root.0);
        let body = open_read_body(&envelope, &read_key).map_err(|_| Halt::Unclassified)?;
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
        let resolved = resolve(self.transport, self.snapshot_cache, &adopter, &name)
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
            .map_err(|_| Halt::Unclassified)?;
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
        let loaded = self.load_child_node(scope, epoch, folder).await?;
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
                    new_name: Some(applied.effective_name.clone().ok_or(Halt::Unclassified)?),
                    vacated: None,
                };
                self.publish_ref_move(scope, pass, applied, rebased, plan)
                    .await
            }
            OpKind::Delete { .. } => self.publish_delete(scope, pass, applied).await,
            OpKind::Relink {
                from_parent,
                new_parent,
                cross_scope: false,
                ..
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
                replacing,
                ..
            } => {
                let plan = MovePlan {
                    from_parent: *from_parent,
                    dest: *new_parent,
                    new_name: Some(applied.effective_name.clone().ok_or(Halt::Unclassified)?),
                    // Only the node the rebase actually vacated loses its ref:
                    // one that won the conditional delete keeps its entry, and
                    // the move already resolved onto a name beside it.
                    vacated: replacing
                        .map(|replaced| replaced.node)
                        .filter(|node| !rebased.contains(*node)),
                };
                self.publish_ref_move(scope, pass, applied, rebased, plan)
                    .await
            }
            OpKind::UpdateContent { content } => {
                self.publish_update_content(scope, pass, applied, content)
                    .await
            }
            // Cross-scope re-seal is #635's.
            OpKind::Relink { .. } => Err(Halt::Unclassified),
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
        let name = applied.effective_name.clone().ok_or(Halt::Unclassified)?;
        self.ensure_folder(scope, pass, parent).await?;

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
            name,
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
                Vec::new(),
                Vec::new(),
            )
            .await?;

        // Referent published: only now does the parent gain the ref to it.
        pass.folder_mut(parent)?.children.push(child.child_ref);
        self.publish_folder(scope, pass, parent, applied.op.authored_at.0)
            .await?;
        self.release_staged_blocks(&applied.op).await;
        // Held only once the parent names it: a record nothing references is
        // not one the liveness loop should keep alive.
        self.hold(child_id.0, published.held);
        Ok(())
    }

    /// Delete: drop the parent's ref. The name itself is retired only on
    /// abandonment (#819 as amended by #824), which is the failure-policy
    /// slice's (#867).
    async fn publish_delete(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
    ) -> Result<(), Halt> {
        let target = applied.op.target;
        let parent = self.published_parent(target)?;
        self.ensure_folder(scope, pass, parent).await?;
        let children = &mut pass.folder_mut(parent)?.children;
        let before = children.len();
        children.retain(|child| child.id != target.0);
        // Removing an absent ref is the op already satisfied, never a publish.
        if children.len() == before {
            return Ok(());
        }
        self.publish_folder(scope, pass, parent, applied.op.authored_at.0)
            .await?;
        Ok(())
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
            moved.name = new_name;
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
        let cas_base = self.publish_folder(scope, pass, dest, modified_at).await?;
        if source == dest {
            return Ok(());
        }

        pass.folder_mut(source)?
            .children
            .retain(|child| child.id != target.0);
        if self
            .publish_folder(scope, pass, source, modified_at)
            .await
            .is_err()
        {
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
            return Err(Halt::Unclassified);
        }
        Ok(())
    }

    /// Undo a published dest-add when the source-remove did not follow it.
    ///
    /// Two fail-closed conditions, because undoing wrongly is the one error the
    /// ordering law cannot absorb — it leaves the child referenced by neither
    /// parent. The source must still name the child (the publish may have
    /// landed and only its self-adopt failed), and the dest must still be at the
    /// sequence our dest-add published; a dest that moved is re-read and the
    /// removal re-derived onto the winner's record rather than replayed over it
    /// (#786).
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
        self.publish_folder(scope, pass, dest, modified_at).await?;
        Ok(())
    }

    /// The freshest sequence the record plane shows at `name` — the same
    /// record-verify read the publish confirm asserts against. Nothing
    /// resolvable fails closed: the compensation may not treat an unanswered
    /// name as "unchanged".
    async fn observed_sequence(&self, name: &IpnsName) -> Result<u64, Halt> {
        fanout_get_verify(self.transport, name)
            .await
            .map(|(sequence, _)| sequence)
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
            self.load_scope_root(scope).await?.0
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
        let loaded = self.load_child_node(scope, pass.epoch, target).await?;
        let ReadBody::File {
            created_at,
            mut versions,
            unknown,
            ..
        } = loaded.body
        else {
            return Err(Halt::Unclassified);
        };
        let uploaded = self.upload_version(scope, applied, staged).await?;
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
            )
            .await?;
        self.release_staged_blocks(&applied.op).await;
        if let Some(node) = self.base.borrow_mut().node_mut(target) {
            node.record_sequence = published.sequence;
            node.mtime = Some(modified_at);
            node.size = Some(staged.plaintext_size);
        }
        self.hold(target.0, published.held);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // The content plane: staged blocks out, a published version back.
    // -----------------------------------------------------------------------

    /// One version's blocks, uploaded and pinned, with the transfer's progress
    /// reported on the event stream throughout.
    async fn upload_version(
        &self,
        scope: &DrainScope<'_>,
        applied: &AppliedOp,
        staged: &StagedContent,
    ) -> Result<UploadedVersion, Halt> {
        let uploaded = self.upload_blocks(scope, applied, staged).await;
        if let Err(halt) = &uploaded
            && let Some(error) = upload_failure(*halt)
        {
            self.emit_upload(applied, OpPhase::UploadFailed, None, Some(error));
        }
        uploaded
    }

    /// One version's blocks, uploaded and pinned: the `Version` its record
    /// carries and every content CID the registration must name.
    async fn upload_blocks(
        &self,
        scope: &DrainScope<'_>,
        applied: &AppliedOp,
        staged: &StagedContent,
    ) -> Result<UploadedVersion, Halt> {
        let root_block = self
            .staged_block(&staged.root_cid)
            .await?
            .ok_or(CONTENT_LOST)?;
        let content = SealedContent::from_root_block(&root_block).map_err(|_| CONTENT_LOST)?;
        // The observed `pushChunk` total against the manifest the reader will
        // check the version's size against. The reachable mismatch is a backing
        // file truncated mid-upload, which would otherwise publish short bytes
        // as a success (#830).
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
        // below the mark (#924). An absence is only progress up to the durable
        // mark this pass keeps: past it, a missing block is loss, and the
        // version can never be assembled.
        let uploaded = self.upload_mark(&staged.root_cid).await?;
        // The root manifest is block zero and goes up last, so the version's
        // whole block count is its leaves plus one.
        let total = blocks(content.leaf_cids().len() + 1);
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
            match self.staged_block(leaf_cid).await? {
                Some(block) => {
                    self.upload_block(leaf_cid, &block).await?;
                    // A leaf a lost release left staged behind the mark is
                    // re-uploaded here, and must not drag the mark back down
                    // over the leaves past it — those are released, so an
                    // uncovered one reads as loss (#924).
                    if index + 1 > uploaded {
                        self.mark_uploaded(&staged.root_cid, index + 1).await?;
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
        // The root goes up last and stays staged until the publish confirms: it
        // is the manifest every retry re-derives the plan from, so releasing it
        // before the record lands would strand a fully-uploaded version.
        self.upload_block(&staged.root_cid, &root_block).await?;
        emit(OpPhase::UploadCompleted, total);

        let content_cids = registry_cids(&staged.root_cid, content.leaf_cids());
        Ok(UploadedVersion {
            version: content.version(*key, applied.op.authored_at.0),
            content_cids,
        })
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

    /// How many of this version's leaves a previous pass durably confirmed. A
    /// mark naming another version has nothing to say about this one, so it
    /// reads as zero and every absent leaf is loss.
    async fn upload_mark(&self, root_cid: &[u8]) -> Result<usize, Halt> {
        let Some(stored) = self
            .staging
            .staged_bytes(UPLOAD_MARK_KEY)
            .await
            .map_err(seam)?
        else {
            return Ok(0);
        };
        let Some((root, count)) = stored.split_at_checked(stored.len().saturating_sub(4)) else {
            return Ok(0);
        };
        if root != root_cid {
            return Ok(0);
        }
        Ok(<[u8; 4]>::try_from(count).map_or(0, |c| u32::from_be_bytes(c) as usize))
    }

    /// Record that `count` of this version's leaves have uploaded. A high-water
    /// mark, written *before* the leaf is released: it may over-claim a leaf
    /// still staged, which the next pass re-uploads, but must never lag or
    /// regress below one already released — the hole guard would read those
    /// uploaded bytes as loss (#924).
    async fn mark_uploaded(&self, root_cid: &[u8], count: usize) -> Result<(), Halt> {
        let mut mark = root_cid.to_vec();
        mark.extend_from_slice(&(count as u32).to_be_bytes());
        self.staging
            .put_staged_bytes(UPLOAD_MARK_KEY, &mark)
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

    /// The version manifest a staged root block carries. `None` when the block
    /// is gone or unreadable: both callers are reconciliation paths that must
    /// still make progress on a store that has lost bytes.
    async fn staged_manifest(&self, root_cid: &[u8]) -> Option<SealedContent> {
        let block = self.staged_block(root_cid).await.ok()??;
        SealedContent::from_root_block(&block).ok()
    }

    /// Upload one block to the pin provider under `cid`, its staging key and
    /// own content address, so the ingress pins it where the published record
    /// points (#906). A block is only ever removed from staging on a confirmed
    /// [`UploadResult`](crate::UploadResult), which is what makes the
    /// still-staged set a suffix.
    async fn upload_block(&self, cid: &[u8], block: &[u8]) -> Result<(), Halt> {
        self.api
            .upload(&encode_content_cid_str(cid), block)
            .await
            .map(drop)
            .map_err(|error| classify_upload(error, block.len() as u64))
    }

    /// Drop every staged block of an op's version.
    ///
    /// Called once its record publishes — the bytes are on the network — and on
    /// a failure-valve abandonment, where the blocks are not the user's
    /// recoverable work: the only copy of the version's content key rides the
    /// op record, which the abandonment deletes, so what survives is ciphertext
    /// nothing can ever open. Holding it would spend the staging budget forever
    /// (#818; the dead-letter event is what surfaces the loss). A terminally
    /// unrebasable op keeps its staged bytes instead (blueprint/engine.md, #33
    /// D6), so this is not called on that path.
    ///
    /// Best-effort: a failed removal is orphan residue a later GC pass collects,
    /// never a reason to fail a landed publish.
    async fn release_staged_blocks(&self, op: &Op) {
        let Some(staged) = op.staged_content() else {
            return;
        };
        if let Some(content) = self.staged_manifest(&staged.root_cid).await {
            for leaf_cid in content.leaf_cids() {
                let _ = self.staging.remove_staged_bytes(leaf_cid).await;
            }
        }
        let _ = self.staging.remove_staged_bytes(&staged.root_cid).await;
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
    ) -> Result<u64, Halt> {
        let (name, is_scope_root, body, envelope_unknown, epoch_tag_unknown) = {
            let state = pass.folder(folder)?;
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
            )
            .await?;

        let state = pass.folder_mut(folder)?;
        state.sequence = published.sequence;
        state.modified_at = modified_at;
        let children = state.children.clone();
        self.repaint_folder(folder, &children, published.sequence, modified_at);
        self.hold(folder.0, published.held);
        Ok(published.sequence)
    }

    /// Author, publish and self-adopt one node's record. Only a confirmed
    /// publish reaches the gate: adopting an unconfirmed one would advance the
    /// sequence floor and destroy the idempotent-in-sequence retry (#821).
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
        carried_unknown: Vec<(String, Value)>,
        carried_epoch_tag_unknown: Vec<(String, Value)>,
    ) -> Result<Published, Halt> {
        let read_key = self.node_read_key(scope, &node.0);
        let nonce = self.nonce()?;
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
            author_scope_root_envelope(authoring, name)
        } else {
            author_child_envelope(authoring)
        }
        .map_err(|_| Halt::Unclassified)?;

        let record_bytes = self
            .publish_head(scope, name, &node.0, epoch, &head, content_cids.clone())
            .await?;
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
                .map_err(|_| Halt::Unclassified)?
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
                .map_err(|_| Halt::Unclassified)?
        }
        .adopted
        .sequence;

        // Cached implies gate-passing: these bytes just cleared the gate.
        self.snapshot_cache
            .put(name.as_str().as_bytes(), &record_bytes)
            .await
            .map_err(seam)?;
        Ok(Published {
            sequence,
            held: HeldRecord {
                routing_key: name.as_str().to_owned(),
                record_bytes,
                signer: SessionIdentity::write_name_signer(scope.write_scope_seed, &node.0),
                head_cid: head.cid,
                // The same list the publish registered, so a sub-EOL renewal
                // re-pins exactly the content this record points at (#797).
                content_cids,
            },
        })
    }

    /// Dry-run, publish, and return the signed bytes.
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
            .map_err(|_| Halt::Unclassified)?;
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
        self.held.borrow_mut().insert(node_id, held);
    }

    /// Remove a resolved op from the durable queue.
    async fn dequeue_op(&self, op_id: OpId) -> Result<(), Halt> {
        self.staging.remove_op(op_id).await.map_err(seam)
    }

    /// Note one head block as orphaned, capped at [`REGISTRY_BATCH_MAX`] so a
    /// session whose retires keep failing bounds its leak, not its memory.
    fn record_orphan_head(&self, cid: &str) {
        let mut orphans = self.orphan_heads.borrow_mut();
        if orphans.len() < REGISTRY_BATCH_MAX {
            orphans.push(cid.to_owned());
        }
    }

    /// Retire the head blocks this session's publishes orphaned
    /// ([`orphaned_head`]). A refused retire keeps them pending for the next
    /// pass rather than losing the only record of what to retire.
    async fn retire_orphan_heads(&self) {
        let pending = self.orphan_heads.borrow().clone();
        if pending.is_empty() {
            return;
        }
        if retire(self.api, &pending).await.is_ok() {
            self.orphan_heads.borrow_mut().drain(..pending.len());
        }
    }

    /// Abandon one op: retire what its publish registered, then drop it from
    /// the queue (#819 as amended by #824).
    async fn abandon(&self, scope: &DrainScope<'_>, op_id: OpId, op: &Op) -> Result<(), Halt> {
        retire(self.api, &self.registered_by(scope, op).await)
            .await
            .map_err(|_| Halt::Unclassified)?;
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

    /// The registry rows one op's publish registered, mirroring what the publish
    /// pipeline sends (`PublishRequest::registration`).
    ///
    /// The child name goes only with an abandoned create whose target never
    /// became reachable: a name some published record already references would
    /// leave a reference outliving its referent, and the gate-passing base is
    /// the evidence — a created node reaches it only once a parent record naming
    /// it published. The content CIDs go with **any** content-bearing op that
    /// reaches here: an abandonment only retires when no PUT for the op was
    /// acked, so no record can link the version.
    ///
    /// Reads the manifest before [`Self::release_staged_blocks`] drops it: after
    /// that the leaf CIDs are recoverable from nowhere (#916).
    async fn registered_by(&self, scope: &DrainScope<'_>, op: &Op) -> Vec<String> {
        let target_published = self.base.borrow().contains(op.target);
        let name = (!target_published && matches!(op.kind, OpKind::Create { .. })).then(|| {
            derive_write_name(scope.write_scope_seed, &op.target.0)
                .as_str()
                .to_owned()
        });
        let content = match op.content_root_cid() {
            Some(root_cid) => {
                let manifest = self.staged_manifest(root_cid).await;
                registry_cids(
                    root_cid,
                    manifest.as_ref().map_or(&[], SealedContent::leaf_cids),
                )
            }
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
    /// dir discard that op as residue instead of publishing it (#860).
    async fn mark_drained(&self, queued: &[(OpId, Op)], report: &DrainReport) -> Result<(), Halt> {
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
        let raised = mark.max(self.drained_mark().await?.unwrap_or(0));
        self.staging
            .put_staged_bytes(DRAINED_OP_MARK_KEY, &raised.to_be_bytes())
            .await
            .map_err(seam)
    }

    /// The stored drained-op mark; `None` when nothing has drained on this
    /// device or the stored bytes are not a mark this build wrote.
    async fn drained_mark(&self) -> Result<Option<u64>, Halt> {
        let stored = self
            .staging
            .staged_bytes(DRAINED_OP_MARK_KEY)
            .await
            .map_err(seam)?;
        Ok(stored
            .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
            .map(u64::from_be_bytes))
    }

    /// The per-node read key (`node-seed` → `read-key`), owned by the caller of
    /// this fn — it is the terminal owner and zeroizes on drop.
    fn node_read_key(&self, scope: &DrainScope<'_>, node_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
        let node_seed = kdf::node_seed(scope.read_scope_seed, node_id);
        Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes())
    }

    /// A fresh injected seal nonce. Fails closed: a reused nonce under one key
    /// is a confidentiality break, never a degraded mode.
    fn nonce(&self) -> Result<[u8; 24], Halt> {
        let mut nonce = [0u8; 24];
        self.entropy
            .borrow_mut()
            .fill(&mut nonce)
            .map_err(|_| Halt::Unclassified)?;
        Ok(nonce)
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

/// Classify a register-first refusal on the discriminator the registry stamps,
/// never the status alone (the [`classify_upload`] discipline): the batch this
/// op builds is refused identically on every retry, and the queue is strict
/// FIFO, so an unclassified refusal parks the op at the head forever (#920).
fn classify_register(error: ApiError) -> Halt {
    let ApiError::Status {
        status: 400, code, ..
    } = error
    else {
        return Halt::Unclassified;
    };
    match code.as_deref() {
        Some(REGISTRY_BATCH_REFUSED) => Halt::Permanent(DeadLetterReason::PayloadRefused),
        _ => Halt::UploadAttempt,
    }
}

/// Whether a failed publish left its head block charged and unreachable: the
/// upload landed under its own pin row, no record naming it reached the
/// transport, and the retry re-authors under a fresh seal nonce
/// (blueprint/engine.md "Resolve/publish pipeline: Retirement", #921).
fn orphaned_head(error: &RecordPublishError) -> bool {
    match error {
        // A refused upload charged no row.
        RecordPublishError::Upload(_) => false,
        RecordPublishError::HeadCidMismatch { .. } => true,
        RecordPublishError::Publish(error) => match error {
            PublishError::Register(_) | PublishError::FloorRead(_) | PublishError::EmptyHeadCid => {
                true
            }
            // No ack is not proof nothing stored: unpinning a head a live
            // record may still name is loss, where the row is only a leak
            // (#916).
            PublishError::AllEndpointsFailed => false,
        },
    }
}

/// Classify a content-upload failure for the valve. The same server verdicts a
/// head-block upload can carry, since content blocks and head blocks go through
/// one endpoint.
fn classify_upload(error: ApiError, refused_bytes: u64) -> Halt {
    let ApiError::Status {
        status: 413, code, ..
    } = error
    else {
        return Halt::Unclassified;
    };
    // 413 covers two unrelated causes, so each verdict rests on **positive
    // evidence only**: the discriminators the API stamps (#848). A response
    // carrying neither did not come from a gate that inspected these bytes — a
    // proxy body cap answers 413 with no code at all — and neither holding the
    // head nor abandoning the op is a conclusion it supports.
    match code.as_deref() {
        Some(QUOTA_EXCEEDED) => Halt::Blocked {
            needed_bytes: refused_bytes,
        },
        Some(UPLOAD_TOO_LARGE) => Halt::Permanent(DeadLetterReason::PayloadRefused),
        _ => Halt::UploadAttempt,
    }
}

/// A block count as [`BlockProgress`] carries it; the root manifest's own
/// ceiling bounds a version's leaves far below `u32::MAX`.
fn blocks(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// The key-free classification an [`OpPhase::UploadFailed`] carries, or `None`
/// where the halt is not a failed attempt: an over-quota hold keeps the op and
/// its reservation, and the host reads it from `SnapshotView::blocked` (#841).
fn upload_failure(halt: Halt) -> Option<&'static str> {
    match halt {
        Halt::Blocked { .. } => None,
        Halt::Unclassified => Some("the upload did not complete"),
        // Both charge the attempt budget; which one it is decides only what
        // exhausting that budget retires, not what the host is told.
        Halt::Attempt | Halt::UploadAttempt => {
            Some("the network refused it without a classification")
        }
        Halt::Permanent(DeadLetterReason::PayloadRefused) => {
            Some("the network refused the payload")
        }
        Halt::Permanent(_) => Some("the staged version can never publish"),
    }
}

/// One version as the registry names it: the root first, then every leaf in
/// file order. Registration and retirement both go through here, so a retire
/// batch names exactly what a register batch claimed — and every block is its
/// own accountable pin row (blueprint/api.md "Pin/name registry"), so leaving
/// a leaf out of a retirement spends account quota forever.
fn registry_cids(root_cid: &[u8], leaf_cids: &[Vec<u8>]) -> Vec<String> {
    core::iter::once(root_cid)
        .chain(leaf_cids.iter().map(Vec::as_slice))
        .map(encode_content_cid_str)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn a_retired_ops_count_leaves_with_it() {
        let mut attempts = attempts(&[(1, 3), (2, 1)]);
        attempts.retain_live(&BTreeSet::from([OpId(2)]));
        assert_eq!(attempts.counts, BTreeMap::from([(OpId(2), 1)]));
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

    /// Every other publish failure is availability: retried indefinitely and
    /// charged nothing, so an unreachable network never abandons an op.
    #[test]
    fn a_failure_carrying_no_server_verdict_is_availability() {
        for error in [
            RecordPublishError::Upload(ApiError::Status {
                status: 503,
                message: None,
                code: None,
            }),
            RecordPublishError::Upload(ApiError::NotAuthenticated),
            RecordPublishError::HeadCidMismatch {
                expected: "a".to_owned(),
                returned: "b".to_owned(),
            },
            RecordPublishError::Publish(crate::net::PublishError::AllEndpointsFailed),
        ] {
            assert_eq!(classify_publish(error, 4096), Halt::Unclassified);
        }
    }
}
