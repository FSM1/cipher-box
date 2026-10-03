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
//! A cross-scope relocation re-seals the moved subtree into the destination
//! scope before the ref that names it publishes ([`Drain::reseal_into`]), and a
//! relocation that leaves a granted source cuts that source
//! ([`Drain::cut_exited_scopes`]). Both ends of a pass live on [`DrainScope`].

use core::cell::{Cell, RefCell};
use core::num::NonZeroU64;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use cipherbox_core::content::{
    decode_content_cid_str, encode_content_cid_str, is_wellformed_content_cid, verify_cid,
};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    BinEntry, BinIndex, ChildRef, Envelope, GrantSetCommitment, NodeKind, PreservedFields,
    ReadBody, SignedSealed, Version, decode_grant_section, grant_section_bytes, open_content_key,
    open_read_body,
};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use futures_channel::mpsc;
use zeroize::Zeroizing;

use crate::api::{ApiClient, ApiError, QUOTA_EXCEEDED, REGISTRY_BATCH_REFUSED, UPLOAD_TOO_LARGE};
use crate::bin_index::{
    BinIndexKeys, BinIndexLoad, BinIndexPublishError, BinnedNode, cached_bin_index, load_bin_index,
    publish_bin_index_placed,
};
use crate::content::limits::MAX_RESOLVED_RECORD_BYTES;
use crate::content::{
    ContentPlane, ContentProfile, ContentVersion, Expansion, Gateway, ProviderError,
    RetentionPolicy, RootPlacement, SealedContent, expand_retire_targets, place_block, plan_prune,
    pre_flight_quota_check, read_block, validate_byo_config, version_cids,
};
use crate::deadlines::DeadlinePolicy;
use crate::entropy::{Entropy, SharedEntropy, fresh_ephemeral, fresh_nonce};
use crate::facade::{
    BlockProgress, Event, MAX_NODE_NAME_BYTES, NodeId, OpPhase, RetainedDeadLetters,
    emit_trust_violation,
};
use crate::gate::GateStage;
use crate::gate::{
    Adopted, GateError, GateRejection, RejectionReason, floor, refuse_below_cut_floor,
};
use crate::grants::grafted::{FloorNamespace, GraftedPlane};
use crate::grants::{UndoDestAdd, undo_dest_add_versioned};
use crate::net::author::{
    AuthorError, AuthoredHead, EnvelopeAuthoring, NewNodeBody, author_child_envelope,
    author_scope_root_envelope, new_child, report_carried_cut,
};
use crate::net::last_known_good::keep_then_commit;
use crate::net::publish::{Observed, PublishError, PublishOutcome, PublishReceipt, PublishVerdict};
use crate::net::record_publish::{
    HeadBinding, MirrorLeg, RecordPublishError, RecordPublishRequest, preflight,
    publish_record_placed,
};
use crate::net::retire::{
    Acknowledged, LiveRecord, OrphanHeads, ReclaimStall, RootSource, StagingRetireLedger,
    drain_owed_retires, orphaned_head, retire,
};
use crate::net::{
    Adopter, ChildAdopter, FanoutRecord, GatedResolve, HeldKey, HeldRecord, HeldRecords, HeldValue,
    LocalHead, OwnScopeMaterial, ResolveOutcome, RootAdopter, assemble_head_envelope,
    fanout_get_classified, fanout_get_verify, observed_at, resolve, resolve_gated,
};
use crate::profile::SyncTimingProfile;
use crate::record_plane::{BinIndexHoldCheck, DefaultsReason, LoadSplit};
use crate::rotation::{LaggingSeedMiss, ScopeExitRotator, derive_write_name, lagging_read_seed};
use crate::seams::{
    CredentialStore, DebtOrigin, FloorStore, Http, OpId, OwedRetire, OwingRecord, RecordTransport,
    RetireLedger, Scheduler, SeamResult, SharerScopedFloorStore, SnapshotCache, StagingStore,
    UnixMillis,
};
use crate::session::SessionIdentity;
use crate::settings::{Destinations, Placement, PlacementDecision, SettingsHold};
use crate::storage_policy::StoragePolicy;
use crate::sync::BookkeepingSeal;
use crate::sync::cancel::UploadCancels;
use crate::sync::doomed::{
    MAX_BOOKKEEPING_OPENS, MAX_JOURNAL_REPLAYS, MAX_QUARANTINE_ATTEMPTS, MAX_QUARANTINE_PROOFS,
    Quarantined, Reclamation, doomed_journal_key, journalled_keys, open_reclamation,
    record_matches_manifest, seal_reclamation,
};
use crate::sync::kept_op::{
    KEPT_OP_NOTES_PREFIX, KeptNote, KeptNotes, KeptPlace, KeptVerdict, kept_verdict,
};
use crate::sync::model::{Snapshot, collation_key};
use crate::sync::op::{NewNode, Op, OpKind, ScopeCrossing, StagedContent};
use crate::sync::overlay::apply_overlay;
use crate::sync::project::{
    UnlinkedChild, project_child_version, project_folder, project_folder_partial,
};
use crate::sync::provision::GENESIS_EPOCH;
use crate::sync::rebase::{
    AppliedOp, DeadLetterReason, DropReason, ReplayReport, decode_queue, enclosing_scope_root,
    replay,
};
use crate::sync::record::{RecordReader, RecordSeal};
use crate::sync::render::BaseSnapshot;
use crate::sync::scope_exit_debt::{owe_cut, settle_owed_cuts};
use crate::sync::staging::{
    DEAD_LETTER_NOTICES_PREFIX, DroppedVersionDebts, LiveBlocks, Preservation, PreservedBounds,
    preserve_dead_letter, reconcile_staging, reconcile_staging_over, release_version_blocks,
    stage_op, version_leaf_cids,
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

/// One staged block, admitted on the read path's two checks.
///
/// The cap comes before the hash, because hash work is linear in the byte
/// count. The address then binds the bytes to the key the sealed op record
/// names, so a rewritten staging sidecar can neither publish other plaintext
/// under this version's content key nor hand the upload a block this build's
/// own reader would refuse (AGENTS.md rule 8). The staging seam reads a whole
/// value, so the cap bounds the hash and not the read itself.
fn admissible_staged_block(key: &[u8], block: Vec<u8>) -> Result<Vec<u8>, Halt> {
    if block.len() > MAX_RESOLVED_RECORD_BYTES {
        return Err(CONTENT_LOST);
    }
    verify_cid(key, &block).map_err(|_| CONTENT_LOST)?;
    Ok(block)
}

/// Whether `child` publishes under the name this scope's write seed derives.
///
/// A name check only: a granted scope root passes it, and [`in_this_scope`]
/// also excludes a proved scope root. Every other reader in the delete path
/// derives the child's name the same way and never reads this field, so a
/// child the comparison rejects is one this scope's write plane does not name
/// either.
fn names_this_scope(end: &ScopeEnd<'_>, child: &ChildRef) -> bool {
    end.write_name(&child.id).as_str().as_bytes() == child.ipns_name
}

/// Whether `child` is a node of this scope rather than a scope root. A granted
/// root keeps the name its parent derives, so only `scope_roots` marks it.
fn in_this_scope(end: &ScopeEnd<'_>, scope_roots: &[NodeId], child: &ChildRef) -> bool {
    !scope_roots.contains(&NodeId(child.id)) && names_this_scope(end, child)
}

/// A bin index load that did not establish the current index.
///
/// A refusal of bytes the plane actually served is charged, so a jammed bin
/// index cannot hold the queue head for good. A plane this pass could not read
/// is availability and waits uncharged — but it waits as a *reported* hold, so
/// a party who withholds one record does not stall the queue in silence
/// ([`QueueHoldReason::BinIndex`]).
///
/// A stranded mint is neither. The hold's only exit is the record resolving,
/// and on a single-device account nothing is left to publish it — so the op
/// dead-letters with the state named rather than waiting for ever.
fn halt_for_bin_load(reason: DefaultsReason) -> Halt {
    match reason.split() {
        LoadSplit::Verdict => Halt::Attempt,
        LoadSplit::StrandedMint => Halt::Permanent(DeadLetterReason::BinIndexStrandedMint),
        LoadSplit::Held(check) => Halt::HeldByBinIndex(check),
    }
}

/// A bin index publish that did not land, on the same split as
/// [`halt_for_bin_load`]: a seam or plane failure retries uncharged, and a body
/// or a confirm this build authored itself is charged.
fn halt_for_bin_publish(error: &BinIndexPublishError) -> Halt {
    match error {
        BinIndexPublishError::Codec(_)
        | BinIndexPublishError::Preflight(_)
        | BinIndexPublishError::Revision => Halt::Attempt,
        // A bin at its top rung takes no further entry until the expiry sweep
        // frees one, and no retry of this op shrinks the body. Its own reason,
        // so the host reads a full bin rather than a spent attempt budget.
        BinIndexPublishError::Full => Halt::Permanent(DeadLetterReason::BinIndexFull),
        // The member's own provider fails the bin head as it fails a record head.
        BinIndexPublishError::Publish(RecordPublishError::Placement(error)) => {
            classify_placement(*error)
        }
        // A lost CAS race is the ordinary outcome of two devices soft-deleting
        // at once, and a confirm the plane could not answer is availability
        // ([`PublishOutcome`](crate::net::publish::PublishOutcome)). Charging
        // either would let a remote party refuse the owner's delete for good.
        BinIndexPublishError::Unconfirmed
        | BinIndexPublishError::Entropy(_)
        | BinIndexPublishError::Publish(_)
        | BinIndexPublishError::Floor(_) => Halt::Unclassified,
    }
}

/// What one drain pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DrainReport {
    /// Ops whose records published and self-adopted. Each stays queued as a
    /// kept op until it shows from the live root (ADR 0069 D2).
    pub(crate) published: Vec<OpId>,
    /// Ops rebase resolved away (already satisfied, or a lost race), and kept
    /// ops that waited out their bound.
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
    /// Every op this pass took out of the durable queue, however it left. A
    /// published op is kept, so it is not one of them.
    fn left_the_queue(&self) -> BTreeSet<OpId> {
        self.dropped
            .iter()
            .chain(&self.restore_residue)
            .copied()
            .chain(self.dead_letters.iter().map(|(op_id, ..)| *op_id))
            .collect()
    }

    /// Whether the pass left the durable queue exactly as it found it.
    pub(crate) fn is_empty(&self) -> bool {
        self.published.is_empty()
            && self.dropped.is_empty()
            && self.dead_letters.is_empty()
            && self.restore_residue.is_empty()
    }
}

/// What one op has been charged: publish attempts, and passes that stopped on
/// a halt the valve could not attribute.
///
/// Two counts rather than one, because two ceilings read them
/// ([`ATTEMPT_BUDGET`], [`UNATTRIBUTED_BUDGET`]) and because
/// [`Drain::create_replays_a_publish`] treats a spent attempt as proof this
/// device already tried to publish — which an unreachable provider is not.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Charges {
    attempts: u32,
    unattributed: u32,
}

/// Per-op drain charges, decoded from [`OP_ATTEMPTS_KEY`].
#[derive(Debug, Default)]
struct Attempts {
    counts: BTreeMap<OpId, Charges>,
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
            bytes.first() == Some(&ATTEMPT_FORMAT_V2) && bytes.len() % ATTEMPT_ENTRY_LEN == 1
        }) else {
            return Self::default();
        };
        Self {
            counts: bytes[1..]
                .chunks_exact(ATTEMPT_ENTRY_LEN)
                .map(|entry| {
                    let (id, counts) = entry.split_at(8);
                    let (attempts, unattributed) = counts.split_at(4);
                    (
                        OpId(u64::from_be_bytes(id.try_into().expect("8 bytes"))),
                        Charges {
                            attempts: u32::from_be_bytes(attempts.try_into().expect("4 bytes")),
                            unattributed: u32::from_be_bytes(
                                unattributed.try_into().expect("4 bytes"),
                            ),
                        },
                    )
                })
                .collect(),
            dirty: false,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.counts.len() * ATTEMPT_ENTRY_LEN);
        bytes.push(ATTEMPT_FORMAT_V2);
        for (op_id, charges) in &self.counts {
            bytes.extend_from_slice(&op_id.0.to_be_bytes());
            bytes.extend_from_slice(&charges.attempts.to_be_bytes());
            bytes.extend_from_slice(&charges.unattributed.to_be_bytes());
        }
        bytes
    }

    /// How many publish attempts `op_id` has spent.
    fn charged_to(&self, op_id: OpId) -> u32 {
        self.counts
            .get(&op_id)
            .map_or(0, |charges| charges.attempts)
    }

    /// Charge one publish attempt to `op_id` and return its new count.
    fn charge(&mut self, op_id: OpId) -> u32 {
        self.dirty = true;
        let charges = self.counts.entry(op_id).or_default();
        charges.attempts = charges.attempts.saturating_add(1);
        charges.attempts
    }

    /// Charge one unattributed halt to `op_id` and return its new count.
    fn charge_unattributed(&mut self, op_id: OpId) -> u32 {
        self.dirty = true;
        let charges = self.counts.entry(op_id).or_default();
        charges.unattributed = charges.unattributed.saturating_add(1);
        charges.unattributed
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
    /// record plane, a load this pass could not do. Retried on the next tick
    /// against [`UNATTRIBUTED_BUDGET`] rather than the attempt budget, so an
    /// outage does not abandon an op while a halt that never clears still
    /// leaves the queue. A spent budget hands back no name: the class spans
    /// both sides of the PUT, and cutting a name a live record carries would
    /// leave a reference outliving its referent.
    Unclassified,
    /// A node this pass must re-author is still behind the scope's epoch, and
    /// this pass holds no backward ratchet to open it at its own epoch
    /// (CONTEXT.md "Epoch lag"). Charged nothing, and re-driven at the pass that
    /// reaches the node ([`halt_for_unreachable_epoch`]).
    EpochLagged,
    /// The op carries a folder whose interior move is owed (ADR 0063) out of
    /// the scope the move re-seals it into. Charged nothing, and re-driven at
    /// the pass after the one that lands the move.
    OwedMove,
    /// The bin entry belongs to another scope; only the identity-owning pass charges its wait.
    OtherBinScope,
    /// The op's record reached the record plane and did not confirm. Charged
    /// against the attempt budget, because a jammed name would otherwise retry
    /// forever. The PUT was
    /// acked, so a record may be resolvable at the name and a spent budget
    /// hands nothing back — cutting a name a live record carries would leave a
    /// reference outliving its referent.
    Attempt,
    /// A folder moved past the record this pass built on before the pass signed
    /// over it: a lost CAS race. Nothing was PUT, and the next pass builds on
    /// what the endpoints serve, so the retry signs higher. Charged like
    /// [`Halt::Unclassified`] and never against the attempt budget, which a
    /// busy sibling device would otherwise spend on a valid op.
    LostRace,
    /// A record this op builds on is at an envelope version this build does
    /// not read. Charged like [`Halt::Unclassified`], since an update clears
    /// it and no retry does, and a spent budget names the newer release.
    ForeignVersion,
    /// A refusal this pass cannot attribute, raised before the record it was
    /// authoring reached the transport: an upload, a registration, or a
    /// produce-side trust refusal. Charged like [`Halt::Attempt`], and a spent
    /// budget hands back a create's own derived name — the op's target is still
    /// unreachable, so no record a parent links names it.
    UploadAttempt,
    /// The adoption gate refused a record this op builds on. Reported on the
    /// event stream, and charged like [`Halt::UploadAttempt`]: re-reading the
    /// same record repeats the refusal, and nothing reached the transport.
    RecordRefused,
    /// The authored head is over the block ceiling its own ingress enforces.
    /// Charged like an attempt, since no re-author shrinks it — a fresh nonce
    /// moves the sealed bytes and never their count — and hands back the same
    /// unreferenced create name [`Halt::UploadAttempt`] does, under its own
    /// dead-letter reason.
    HeadOversized,
    /// The authored scope root fits the block ceiling but leaves no room for
    /// its own re-seal. Charged exactly like [`Halt::HeadOversized`] — no
    /// re-author shrinks it either — and reported under its own verdict,
    /// because the record is not too large and telling the member it is sends
    /// them looking for content to remove that is not the cause.
    ScopeRootNotResealable,
    /// Classified-permanent: the same bytes are refused on every retry.
    Permanent(DeadLetterReason),
    /// The member's own settings were refused before any request was built.
    /// Not a failure of the op — it holds the head and its staging reservation
    /// until those settings change ([`QueueHoldReason::Settings`]).
    HeldBySettings(SettingsHold),
    /// Over the account quota. Not a failure of the op — it holds the head and
    /// its staging reservation until a quota probe reports room.
    Blocked {
        /// The byte count the refused upload asked for, and so the figure the
        /// resume probe must find room for.
        needed_bytes: u64,
    },
    /// The bin index plane did not establish the current index, and the reason
    /// is availability rather than a verdict on bytes it served. Not a failure
    /// of the op — it holds the head and its staging reservation until the
    /// record resolves ([`QueueHoldReason::BinIndex`]).
    HeldByBinIndex(BinIndexHoldCheck),
    /// The user cancelled the upload. The facade has already undone it, so the
    /// valve does nothing but stop the pass.
    Cancelled,
    /// The op sits below a proved scope root whose record carries no write
    /// plane this device opens, so no pass takes it while that stands. Charged
    /// like [`Halt::Attempt`]: an uncharged hold here stalls the queue behind
    /// it for ever and surfaces nothing (ADR 0012 D6). Nothing was authored and
    /// nothing registered, so a spent budget hands back no name and the dead
    /// letter keeps the staged version.
    UnwritableScope,
}

/// Which halt an op below a scope root other than this pass's own takes.
///
/// Only a root this device holds keyless is charged: the op will not publish on
/// a later pass either, and the budget is what bounds the stall (ADR 0012 D6).
/// A root that is merely dark this pass, or one another pass of this tick owns,
/// leaves the op where it is with no charge.
///
/// The charge is the identity's rather than one scope's, so exactly one pass a
/// tick makes it ([`charge_the_identity_to_one_pass`]). Dividing it across
/// passes would make the divisor the number of write planes that happened to
/// open, and the dead-letter tick would then differ between replays of the same
/// op sequence.
fn halt_below_another_scope_root(
    keyless_roots: &[NodeId],
    charges_the_identity: bool,
    nearest: NodeId,
) -> Halt {
    if charges_the_identity && keyless_roots.contains(&nearest) {
        Halt::UnwritableScope
    } else {
        Halt::Unclassified
    }
}

/// Give the tick's identity-wide charge to its first pass.
///
/// Held apart from the vault root's own seeds: an owner holding neither vault
/// seed runs no vault-root pass, and an op below a keyless scope root would
/// then take [`Halt::Unclassified`] from every pass and hold the strict-FIFO
/// head on the wide outage budget, which reports a stall no outage explains
/// (ADR 0012 D6).
///
/// Never a grafted pass: the budget answers for an op under a keyless root of
/// **this vault's** own boundary set, which a pass over a scope another identity
/// owns proves nothing about.
fn charge_the_identity_to_one_pass(scopes: &mut [DrainScope<'_>]) {
    if let Some(first) = scopes.iter_mut().find(|scope| !scope.is_grafted()) {
        first.charges_the_identity = true;
    }
}

/// The order one tick's passes run in. The vault root's pass leads, because
/// [`Drain::settle`] reads the identity-wide bookkeeping under its material.
fn ordered(scopes: TickScopes<'_>) -> Vec<DrainScope<'_>> {
    let TickScopes {
        vault,
        interior,
        grafted,
    } = scopes;
    let mut passes: Vec<_> = vault.into_iter().chain(interior).chain(grafted).collect();
    charge_the_identity_to_one_pass(&mut passes);
    passes
}

/// The shared lagging seed walk ([`lagging_read_seed`]), or the halt this pass
/// takes instead of opening the node. A record above this pass's epoch is an
/// honest race with a fresher root, which the next pass anchors on.
fn seed_for_lagging(
    scope_id: [u8; 16],
    current_seed: &[u8; 32],
    anchor: Anchor<'_>,
    record_epoch: u64,
) -> Result<Zeroizing<[u8; 32]>, Halt> {
    lagging_read_seed(
        scope_id,
        current_seed,
        anchor.epoch,
        anchor.history_links,
        record_epoch,
    )
    .map_err(|miss| match miss {
        LaggingSeedMiss::AboveAnchor => Halt::Unclassified,
        LaggingSeedMiss::Unreachable => halt_for_unreachable_epoch(anchor.history_links),
    })
}

/// The halt a lagging node earns when this pass's backward ratchet cannot reach
/// the epoch its record was sealed at.
///
/// A walk this pass cannot complete is not proof the epoch is gone: the adoption
/// gate authenticates each link's signature and nothing about the chain's order
/// or walkability, and the anchor is a cached root a fresher one may supersede.
/// So a held link set that will not walk is charged against the attempt budget —
/// bounded, and its dead letter keeps the staged version — rather than made
/// permanent, which would let one publish destroy another device's queued write.
/// A pass holding no links at all holds no ratchet, so it takes the uncharged
/// hold that the pass reading those links still clears.
fn halt_for_unreachable_epoch(history_links: &[SignedSealed]) -> Halt {
    if history_links.is_empty() {
        Halt::EpochLagged
    } else {
        Halt::UploadAttempt
    }
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

/// One head publish that reached the transport.
enum HeadPublish {
    /// Our record confirmed at its name.
    Confirmed(Vec<u8>),
    /// A lost CAS race at `sequence`, with the winning record when the
    /// confirm read one.
    Lost {
        winner: Option<Vec<u8>>,
        sequence: u64,
    },
    /// Acknowledged at `sequence`, but the confirm did not see it.
    Unconfirmed { sequence: u64 },
}

/// What a name serves at its freshest sequence: that sequence, every distinct
/// record the endpoints serve at it, and the token of the record the gate
/// passed there, if any.
struct Served {
    sequence: u64,
    records: Vec<Vec<u8>>,
    observed: Option<Result<Observed, PublishError>>,
}

impl Served {
    fn new(
        sequence: u64,
        freshest: Vec<u8>,
        mut tied: Vec<Vec<u8>>,
        observed: Option<Result<Observed, PublishError>>,
    ) -> Self {
        tied.push(freshest);
        Self {
            sequence,
            records: tied,
            observed,
        }
    }

    /// Whether the name moved past the record a pass built on: a higher
    /// sequence, or that record's sequence served only with other bytes.
    fn moved_past(&self, (built_on, record): &(Observed, Vec<u8>)) -> bool {
        let sequence = built_on.sequence();
        self.sequence > sequence || (self.sequence == sequence && !self.records.contains(record))
    }
}

/// The one verdict every unrecoverable-content path returns: the version's key,
/// root, or a leaf is gone, and no retry brings any of them back.
const CONTENT_LOST: Halt = Halt::Permanent(DeadLetterReason::ContentUnrecoverable);

/// How many non-confirming publish attempts one op gets before it dead-letters.
///
/// Bounds a pathology, not a network outage: it is spent only by a halt the
/// valve could attribute to these bytes.
const ATTEMPT_BUDGET: u32 = 5;

/// How many passes may stop on one op under [`Halt::Unclassified`] before it
/// dead-letters.
///
/// The class carries real availability failures, so the ceiling is the outage a
/// device may sit through and still publish: at the production poll cadence it
/// is an hour of consecutive halted passes, where [`ATTEMPT_BUDGET`] would be
/// two and a half minutes. It is finite because strict FIFO means the op that
/// keeps halting holds every op behind it, and a queue with no exit is the
/// silent permanent stall the valve exists to remove.
pub const UNATTRIBUTED_BUDGET: u32 = 120;

/// The staging key holding per-op drain charges: a one-byte format tag followed
/// by `(op_id, attempts, unattributed)` triples, big-endian and fixed-width,
/// rewritten each pass over the live queue so a retired op's counts leave with
/// it.
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
const ATTEMPT_FORMAT_V2: u8 = 2;

/// One `(op_id, attempts, unattributed)` triple as [`OP_ATTEMPTS_KEY`] stores
/// it.
const ATTEMPT_ENTRY_LEN: usize = 16;

/// One read of the durable queue: this identity's decoded ops, and every id the
/// store holds — including other identities' and retained records', which the
/// attempt record must not reclaim.
struct Queue {
    mine: Vec<(OpId, Op)>,
    /// The kept ops that wait out of this pass, still queued.
    kept: Vec<OpId>,
    all_ids: BTreeSet<OpId>,
}

/// Why the queue head is held over rather than failed. Each reason names its
/// own exit, and [`Drain::hold_admits_the_head`] is the one gate that tries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueHoldReason {
    /// The account quota refused the upload. The exit is a probe on a later
    /// drain tick reporting room for `needed_bytes`.
    Quota {
        /// The byte count the resume probe must find room for.
        needed_bytes: u64,
    },
    /// The member's own settings were refused before any request was built, so
    /// every retry reaches the same verdict and charging one would spend the
    /// version's budget and then release its staged blocks. The exit is the
    /// one its [`SettingsRefusal`](crate::settings::SettingsRefusal) names.
    ///
    /// The hold's check names the rule and never the endpoint or the bearer
    /// the settings carry.
    Settings(SettingsHold),
    /// The bin index plane did not establish the current index. The exit is a
    /// load that establishes it.
    ///
    /// Reported, because a party who withholds the record — or one head block
    /// of it — otherwise stops every queued operation for the account with no
    /// cause the member can see (blueprint/engine.md "Bin index record").
    BinIndex(BinIndexHoldCheck),
}

/// The queue head is held over rather than failed: it keeps its place and its
/// staging reservation until its reason's own exit comes.
///
/// One cell, so one head cannot be claimed for two reasons at once and no arm
/// has another arm's state to clear. The cell belongs to the tick rather than
/// to one pass: a tick runs one pass per proved scope over one identity-wide
/// queue, so a hold one pass takes is still the head's when the next pass of
/// the same tick opens ([`bin_index_hold_exits`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueHold {
    /// The held op.
    pub op_id: OpId,
    /// The node the op targets, so a host can point at it.
    pub node: NodeId,
    /// What it waits on.
    pub reason: QueueHoldReason,
}

/// Whether a halt frees a [`QueueHoldReason::BinIndex`] hold.
///
/// The exit is a classified verdict on the held op itself. A pass whose scope
/// does not author that op takes [`Halt::Unclassified`] for it and knows
/// nothing about the bin plane, so a later pass of the same tick must not drop
/// the hold an earlier one took — the head would then wait with no cause the
/// member can see.
fn bin_index_hold_exits(hold: Option<QueueHold>, halted: OpId, halt: Halt) -> bool {
    let Some(hold) = hold else {
        return false;
    };
    matches!(hold.reason, QueueHoldReason::BinIndex(_))
        && hold.op_id == halted
        && !matches!(halt, Halt::HeldByBinIndex(_) | Halt::Unclassified)
}

/// The captures one pass adopts into the bin. A peer chooses both the trigger
/// and the count, so the pass takes a bounded share and the rest waits.
const MAX_BIN_ADOPTIONS: usize = 32;

/// What one session holds unadopted. The set is memory a peer's republishes
/// fill, so it is bounded like every other per-session set.
const MAX_HELD_CAPTURES: usize = 4096;

/// What one scope may hold of [`MAX_HELD_CAPTURES`], so a scope whose walk
/// never settles cannot crowd out the captures of every other scope. A capture
/// past it drops unbinned (blueprint/engine.md "Owner capture").
const MAX_HELD_CAPTURES_PER_SCOPE: usize = 1024;

/// The unanswered attempts a capture walk makes at one node read, one for each
/// pass, before it starts again.
const MAX_CAPTURE_READ_ATTEMPTS: u8 = 3;

/// Purges one tick queues for expired bin entries. A retention deadline can
/// come due for a whole bin at once, and a purge is an op like any other: the
/// queue takes a bounded share per tick and the rest waits for the next one.
///
/// Held by the tick rather than by the pass: a tick runs one pass per proved
/// scope, so a per-pass bound would multiply by a scope count the owner sets
/// ([`TickShare`]).
pub(crate) const MAX_BIN_EXPIRIES: usize = 32;

/// Milliseconds in one day, the unit the owner's bin retention is set in.
const DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;

/// The `deletedAt` at or below which an entry has outlived `retention_days`,
/// measured from `now`.
///
/// `None` turns expiry off: a retention this device cannot show is the owner's,
/// and a retention of `0`, which means the bin takes no new nodes rather than
/// that the entries already in it are destroyed. A deadline that has not yet
/// elapsed since the epoch also expires nothing.
fn bin_expiry_cutoff(now: UnixMillis, retention_days: Option<u32>) -> Option<u64> {
    let days = retention_days.filter(|days| *days > 0)?;
    now.0.checked_sub(u64::from(days) * DAY_MILLIS)
}

/// Charge a bin path's read of a record it cannot re-author.
///
/// A binned subtree takes no ordinary write and joins no eager set, so a scope
/// rotation can leave it sealed at an epoch the gate refuses for good
/// (ADR 0011) and no wave ever lifts it. Left uncharged —
/// unclassified, or held for that wave — such a read would hold the strict-FIFO
/// head for every pass thereafter, and the expiry sweep queues these ops without
/// an owner command. Charged, the op spends its attempt budget and dead-letters,
/// which keeps the entry and its content — a leak, never a loss.
fn charge_bin_read(halt: Halt) -> Halt {
    match halt {
        Halt::Unclassified | Halt::EpochLagged => Halt::UploadAttempt,
        other => other,
    }
}

/// Add what a read leg observed to the session's unadopted set, up to
/// [`MAX_HELD_CAPTURES`] and [`MAX_HELD_CAPTURES_PER_SCOPE`].
pub(crate) fn hold_captures(set: &RefCell<Vec<UnlinkedChild>>, observed: Vec<UnlinkedChild>) {
    let mut set = set.borrow_mut();
    let mut held: BTreeMap<[u8; 16], usize> = BTreeMap::new();
    for unlinked in set.iter() {
        *held.entry(unlinked.scope_id).or_default() += 1;
    }
    for unlinked in observed {
        let scope = held.entry(unlinked.scope_id).or_default();
        if set.len() < MAX_HELD_CAPTURES && *scope < MAX_HELD_CAPTURES_PER_SCOPE {
            *scope += 1;
            set.push(unlinked);
        }
    }
}

/// The node records one tick reads for capture walks, shared out across its
/// scope passes ([`TickShare`]). A peer chooses when a walk starts, so a walk
/// spends a bounded share and resumes on the next tick.
const MAX_CAPTURE_WALK_READS: usize = 128;

/// The nodes one capture walk may hold. A walk past this bound cannot prove
/// any capture, so the session drops the scope's captures and walks that scope
/// no more (blueprint/engine.md "Owner capture").
const MAX_CAPTURE_WALK_NODES: usize = 65_536;

/// A held capture as a proof names it: the node and the stamp its merge minted,
/// so a later departure of the same node needs a proof of its own.
type CaptureKey = (NodeId, u64);

fn capture_key(unlinked: &UnlinkedChild) -> CaptureKey {
    (unlinked.node, unlinked.deleted_at)
}

/// Whether `keys` holds a capture of `node`, under any stamp.
fn names_node(keys: &BTreeSet<CaptureKey>, node: NodeId) -> bool {
    keys.range((node, 0)..=(node, u64::MAX)).next().is_some()
}

/// One scope's proof that held captures left the tree.
#[derive(Default)]
pub(crate) struct CaptureProofs {
    /// Captures a settled walk proved, which wait for an adoption slot.
    proved: BTreeSet<CaptureKey>,
    /// The walk under way, if any.
    walk: Option<CaptureWalk>,
    /// A walk of this scope passed [`MAX_CAPTURE_WALK_NODES`].
    overflowed: bool,
}

/// A fresh read of every node of the vault, each proved scope under its own
/// end, then a second read of each, which proves which held captures of one
/// scope no folder names (blueprint/engine.md "Owner capture"). A node whose second read shows
/// another record moved during the walk, so the walk is not a snapshot and
/// starts again.
struct CaptureWalk {
    cohort: BTreeSet<CaptureKey>,
    /// Each node still to read, with the scope root whose end reads it.
    pending: Vec<(NodeId, NodeId)>,
    seen: BTreeSet<NodeId>,
    /// Cohort nodes some folder names.
    linked: BTreeSet<NodeId>,
    /// Each node read, as `pending` holds it, with the record read.
    read: Vec<((NodeId, NodeId), RecordMark)>,
    /// The anchor of each scope the walk entered, from its root's read, but
    /// the capture's own scope, whose pass holds its anchor.
    anchors: BTreeMap<NodeId, WalkAnchor>,
    /// How many of `read` the second read has confirmed.
    confirmed: usize,
    /// The unanswered attempts at the walk's next read: the last of `pending`,
    /// or `read[confirmed]` once every node is read one time.
    unanswered: u8,
    /// A folder names a child the walk cannot read: one at a name its scope's
    /// write seed does not derive, or a proved scope root this tick holds no
    /// end for. A settled walk then proves no capture.
    blind: bool,
}

/// What a scope root's read gives the reads below it.
struct WalkAnchor {
    epoch: u64,
    history_links: Vec<SignedSealed>,
}

impl WalkAnchor {
    fn anchor(&self) -> Anchor<'_> {
        Anchor {
            epoch: self.epoch,
            history_links: &self.history_links,
        }
    }
}

/// Which record a walk read: two reads with one mark read the same bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
struct RecordMark {
    sequence: u64,
    digest: [u8; 32],
}

/// One node of a capture walk, as the record plane serves it now.
struct WalkRead {
    mark: RecordMark,
    children: Vec<ChildRef>,
    /// Set when the node is a scope root.
    anchor: Option<WalkAnchor>,
}

/// Why a walk read gave no [`WalkRead`].
enum WalkReadFault {
    /// Any halt but a refusal, such as no answer or an `UploadAttempt`,
    /// `Unclassified` or `EpochLagged` halt: the read may land on a later pass.
    Unanswered,
    /// A refused record, or one served tied with other bytes at its sequence:
    /// what the walk read so far proves nothing.
    Untrusted,
}

/// Where one pass left a capture walk.
enum WalkStep {
    /// Reads remain for a later pass.
    Unfinished,
    /// Every node read twice to the same record.
    Settled,
    /// A node moved, its record was refused or tied, or its read went
    /// unanswered too long: the next pass starts again.
    Restart,
    /// The walk passed its node bound.
    Overflowed,
}

impl CaptureWalk {
    /// A walk of the whole vault from its root, so a link in a scope above or
    /// beside the capture's own scope counts. With no vault end this tick, the
    /// walk reads the capture's own scope and proves nothing.
    fn from_vault_root(
        scope: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        cohort: BTreeSet<CaptureKey>,
    ) -> Self {
        let vault = std::iter::once(&scope.source)
            .chain(ends)
            .find(|end| end.ascent_node_seed.is_none());
        let mut walk = Self::new(vault.map_or(scope.source.root, |end| end.root), cohort);
        walk.blind = vault.is_none();
        walk
    }

    fn new(root: NodeId, cohort: BTreeSet<CaptureKey>) -> Self {
        Self {
            cohort,
            pending: vec![(root, root)],
            seen: BTreeSet::from([root]),
            linked: BTreeSet::new(),
            read: Vec::new(),
            anchors: BTreeMap::new(),
            confirmed: 0,
            unanswered: 0,
            blind: false,
        }
    }

    /// Record what one folder of the scope at `end` names: a cohort node it
    /// links, and each child still to read. A child's kind is wire data, so a
    /// child marked as a file is read too: its body, not its ref, says if it
    /// names children. A scope root with an end in `ends` is read under that
    /// end. Answers `false` when the walk holds more than `bound` nodes.
    fn visit(
        &mut self,
        end: &ScopeEnd<'_>,
        ends: &[ScopeEnd<'_>],
        scope_roots: &[NodeId],
        children: &[ChildRef],
        bound: usize,
    ) -> bool {
        for child in children {
            let id = NodeId(child.id);
            if names_node(&self.cohort, id) {
                self.linked.insert(id);
            }
            if ends.iter().any(|below| below.root == id) {
                if self.seen.insert(id) {
                    self.pending.push((id, id));
                }
            } else if !in_this_scope(end, scope_roots, child) {
                self.blind = true;
            } else if self.seen.insert(id) {
                self.pending.push((id, end.root));
            }
        }
        self.seen.len() <= bound
    }
}

/// One scope's material: the root it is anchored on and the two seeds every
/// record of that scope is sealed and named under. Every field is borrowed from
/// the live session; the drain zeroizes none of it.
///
/// Copied to swap one field: a re-key into the bin publishes the doomed subtree
/// under the bin's held key, while the name plane and the scope id the AAD binds
/// stay the source scope's ([`Drain::rekey_into_bin`]).
#[derive(Clone, Copy)]
pub(crate) struct ScopeEnd<'a> {
    /// The scope root node — also the scope id every record of this end binds.
    pub(crate) root: NodeId,
    /// The root's write-plane IPNS name.
    pub(crate) root_name: &'a IpnsName,
    /// The scope read seed per-node read keys derive from.
    pub(crate) read_scope_seed: &'a Zeroizing<[u8; 32]>,
    /// The stamp of `read_scope_seed` (`deposit_seed`), or `None` where no
    /// stamp is known. Floors only rise, so a root that passes the floor check
    /// at the stamp is at the seed's own epoch.
    pub(crate) read_seed_stamp: Option<u64>,
    /// The scope write seed per-node IPNS names and signers derive from.
    pub(crate) write_scope_seed: &'a Zeroizing<[u8; 32]>,
    /// `nodeSeed(enclosingOverrideSeed, scopeId)` — the ascent authority the
    /// gate derives an interior scope root's expected ascent keypair from
    /// ([`RootAdopter::under_parent_node_seed`]). `None` at the vault root,
    /// which carries no ascent link.
    pub(crate) ascent_node_seed: Option<&'a Zeroizing<[u8; 32]>>,
    /// Whose namespace this end's epoch floors ratchet in, as
    /// [`floor_namespace`] picked it for this scope id.
    pub(crate) floor_namespace: FloorNamespace,
}

impl<'a> ScopeEnd<'a> {
    /// The floor namespace every epoch floor of this end ratchets in.
    fn floors<'f, F>(&self, floors: &'f F) -> SharerScopedFloorStore<'f, F> {
        self.floor_namespace.view(floors)
    }

    /// This end bound to the read epoch its records carry — everything one
    /// record's seal needs.
    fn at(self, epoch: u64) -> SealPlane<'a> {
        SealPlane { end: self, epoch }
    }

    /// This end with the bin's held key as its read seed, which has no stamp.
    fn under_held_key<'b>(self, held: &'b Zeroizing<[u8; 32]>) -> ScopeEnd<'b>
    where
        'a: 'b,
    {
        ScopeEnd {
            read_scope_seed: held,
            read_seed_stamp: None,
            ..self
        }
    }

    /// The per-node read key (`node-seed` → `read-key`) this scope's records are
    /// sealed under, owned by the caller — it is the terminal owner and
    /// zeroizes on drop.
    fn read_key(&self, node_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
        let node_seed = kdf::node_seed(self.read_scope_seed, node_id);
        Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes())
    }

    /// The write-plane name this scope publishes one node under.
    fn write_name(&self, node_id: &[u8; 16]) -> IpnsName {
        derive_write_name(self.write_scope_seed, node_id)
    }
}

/// A [`ScopeEnd`] bound to a read epoch: the unit every publish helper takes, so
/// the scope id, the epoch, the read key and the write name of one record can
/// only come from one scope. Mixing two scopes' parts authors a record that
/// scope's own adoption gate rejects.
///
/// The seal side of a pass. The read side is [`Anchor`], which names the epoch a
/// record is *opened* at and the backward ratchet that reaches the epochs below
/// it; a lagging record is opened at its own epoch and re-sealed at the plane's.
#[derive(Clone, Copy)]
pub(crate) struct SealPlane<'a> {
    pub(crate) end: ScopeEnd<'a>,
    /// The read epoch every record sealed under this plane binds, and so the
    /// epoch its read material belongs to (`ChildAdopter::with_seed_stamp`).
    pub(crate) epoch: u64,
}

impl SealPlane<'_> {
    /// The head binding one node's record carries under this plane.
    fn head_binding(&self, node_id: &[u8; 16]) -> HeadBinding {
        HeadBinding {
            node_id: *node_id,
            scope_id: self.end.root.0,
            epoch: self.epoch,
            write_epoch: None,
        }
    }
}

/// The two ends one drain pass publishes under, plus what the pass proves them
/// against. Every field is borrowed from the live session; the drain zeroizes
/// none of it.
#[derive(Clone, Copy)]
pub(crate) struct DrainScope<'a> {
    /// The scope the pass anchors on, and the one every intra-scope record seals
    /// under.
    pub(crate) source: ScopeEnd<'a>,
    /// The one interior end a queued crossing named, at the read epoch the
    /// tick's boundary walk proved for it ([`crate::rotation::scope_material`]).
    /// It is the end the crossing re-seals **into** on a move inward, and the
    /// end it re-seals **out of** on a move that leaves a granted scope.
    /// `None` on an intra-scope pass, where every node resolves onto `source`.
    pub(crate) destination: Option<SealPlane<'a>>,
    /// Every scope root this session proved, the source root included, so a walk
    /// over link ancestry can tell which scope owns a node
    /// ([`crate::sync::tick::scope_root_of`]).
    pub(crate) scope_roots: &'a [NodeId],
    /// The proved scope roots whose own records carry no write plane this
    /// device opens. No pass will ever take an op below one, so the valve
    /// charges rather than stalls ([`halt_below_another_scope_root`]).
    pub(crate) keyless_roots: &'a [NodeId],
    /// Whether this pass owns the tick's identity-wide charge for an op below a
    /// keyless scope root. Set on exactly one pass a tick
    /// ([`charge_the_identity_to_one_pass`]).
    pub(crate) charges_the_identity: bool,
    /// The owner's encryption secret (the root's own seed source, and the op
    /// queue's HPKE-to-self reader).
    ///
    /// One pair of ends, one owner: an interior scope exists only because this
    /// vault's owner granted a folder of it (CONTEXT.md "Scope"), so both ends
    /// seal under the same identity and open their own grant blob under the
    /// same secret.
    pub(crate) enc_secret: &'a X25519Secret,
    /// The contact-anchored owner identity the gate verifies against.
    pub(crate) owner_identity: &'a EcdsaVerifier,
    /// What a pass over a scope another identity granted carries beyond an own
    /// pass, and the one fact every grafted refusal reads. `None` on this
    /// vault's own planes; `Some` exactly when the source end ratchets under
    /// [`FloorNamespace::GrantedBy`].
    pub(crate) granted: Option<GrantedPass<'a>>,
}

/// The two facts a grafted pass reads that an own pass has no use for.
#[derive(Clone, Copy)]
pub(crate) struct GrantedPass<'a> {
    /// The granting contact's encryption subkey. This device's seed for the
    /// scope sits in the grant blob that contact's ECDH tag locates, not in an
    /// owner blob, so the pass self-adopts its own publish through it.
    pub(crate) sharer_enc: &'a X25519Public,
    /// The cross-plane rule every read leg below the grafted root applies. A
    /// repaint of a sharer-authored listing goes through it too, or the drain
    /// would link an id another plane holds.
    pub(crate) plane: GraftedPlane<'a>,
}

impl<'a> DrainScope<'a> {
    /// Whether this pass authors in a scope another identity owns and granted.
    ///
    /// Such a pass holds the sharer's two scope seeds and no vault root write
    /// seed, so every surface of **this** vault above the grafted root is out of
    /// its reach ([`Self::refuse_vault_surface`]).
    fn is_grafted(&self) -> bool {
        self.granted.is_some()
    }

    /// Refuse a grafted pass a surface that belongs to this vault rather than to
    /// the granted scope: the owner's bin index, the identity's retire ledger
    /// and doomed-name journal, and the cuts this vault owes on its own scopes.
    ///
    /// The grant carries no key for any of them — the bin index is owner-only by
    /// construction (CONTEXT.md), and every name in the ledger derives from the
    /// vault root's own write seed — so the same bytes are refused on every
    /// retry. Release-active and never a `debug_assert!` (AGENTS.md rule 8).
    fn refuse_vault_surface(&self) -> Result<(), Halt> {
        if self.is_grafted() {
            return Err(Halt::Permanent(DeadLetterReason::GraftedScopeVaultSurface));
        }
        Ok(())
    }

    /// The second end, or a refusal for a pair this pass may not seal under.
    ///
    /// Two ends rooted at one node name one scope under two sets of material,
    /// whose seeds and epochs need not agree. The pass would seal live records
    /// under whichever the resolver reached first, which a rotation on that
    /// scope makes a revoked seed. Neither end is the safe pick.
    ///
    /// A second end that is not a listed boundary is the other half of that: a
    /// node under it resolves onto the enclosing scope for every walk that asks,
    /// so the pass would name it here and seal it there. The two sets answer
    /// different questions ([`replay`](crate::sync::rebase::replay)) and this is
    /// the law that ties them.
    ///
    /// Charged, both of them: this build assembled the pair, and no later read
    /// changes it.
    fn second_end(&self) -> Result<Option<SealPlane<'a>>, Halt> {
        match self.destination {
            Some(destination)
                if destination.end.root == self.source.root
                    || !self.scope_roots.contains(&destination.end.root) =>
            {
                Err(Halt::UploadAttempt)
            }
            destination => Ok(destination),
        }
    }

    /// The end rooted at `root`, at the read epoch its records bind: `epoch` for
    /// the source end, which the pass proves from its own scope root record, and
    /// a destination end's own for that one. `None` names neither end.
    ///
    /// A scope root's subtree seals under that scope's own material and never
    /// its parent scope's (CONTEXT.md "Scope"), so this is what makes a chain
    /// that crosses into the destination scope seal there.
    fn plane_rooted_at(&self, epoch: u64, root: NodeId) -> Result<Option<SealPlane<'a>>, Halt> {
        Ok(match self.second_end()? {
            Some(destination) if destination.end.root == root => Some(destination),
            _ => (self.source.root == root).then(|| self.source.at(epoch)),
        })
    }

    /// The plane a folder this pass already loaded seals under, and so the plane
    /// of every node that folder parents: a node joins the scope of the parent
    /// that names it.
    ///
    /// A recorded plane root that names neither end is charged. The pass proved
    /// it against a gate-passing record of that very end, so no later read
    /// restores an end this scope no longer holds.
    fn folder_plane(&self, pass: &Pass, folder: NodeId) -> Result<SealPlane<'a>, Halt> {
        let plane_root = pass.folder(folder)?.plane_root;
        self.plane_rooted_at(pass.epoch, plane_root)?
            .ok_or(Halt::UploadAttempt)
    }

    /// The end a node belongs to, read off where the base places it: a node at
    /// or below the second end's root is that end's, and every other is the
    /// anchor's.
    ///
    /// A node's name and its read key both follow from its end alone, so the
    /// paths that hold no [`Pass`] — the failure valve, and the retire ledger's
    /// own reads — resolve an end here rather than a plane.
    fn end_of(&self, base: &Snapshot, node: NodeId) -> Result<ScopeEnd<'a>, Halt> {
        let Some(destination) = self.second_end()? else {
            return Ok(self.source);
        };
        let root = destination.end.root;
        Ok(if node == root || base.is_descendant_of(node, root) {
            destination.end
        } else {
            self.source
        })
    }
}

/// The scope roots a tick owes a cut for.
///
/// Everything pending except the vault root, which no share reaches and so
/// names no grantee to cut out — the one root a trigger may escalate to. Every
/// pass of a tick reaches the same session-lived debt set, so the vault root is
/// named here rather than taken from a pass's own anchor: a pass anchored on a
/// granted scope root would otherwise read that scope's own owed cut as the
/// escalation and drop it.
pub(crate) fn owed_cuts(pending: &BTreeSet<NodeId>, vault_root: NodeId) -> Vec<NodeId> {
    pending
        .iter()
        .copied()
        .filter(|root| *root != vault_root)
        .collect()
}

/// What a scope root whose own record sits at another epoch than the end's
/// plane or seed costs the op that met it.
///
/// The anchor's epoch is this pass's own, and a rotation that moved it heals at
/// the next pass boundary, so the op waits. A second end's comes from the tick's
/// boundary walk, and only a fresh walk changes it: charged, or a superseded end
/// holds the queue head for good.
fn epoch_skew(scope: &DrainScope<'_>, end: &ScopeEnd<'_>) -> Halt {
    if end.root == scope.source.root {
        Halt::Unclassified
    } else {
        Halt::UploadAttempt
    }
}

/// Refuse to author a record whose name or kind belongs to a scope other than
/// the one the plane binds into its AAD.
///
/// The encode-side half of the gate's own rejects: a name derived under another
/// scope's write seed publishes bytes this plane's reader never looks for, and
/// the other plane's reader refuses for the scope id. Release-active, never a
/// `debug_assert!` — a stripped check ships a build that publishes records no
/// reader can adopt (AGENTS.md rule 8).
///
/// A scope root's name and the seed its signer comes from have independent
/// sources — the vault pointer's `currentRoot` and the owner-write-blob — so a
/// disagreement there is a write rotation landing between the two reads, and the
/// next tick's session material heals it. A child's name has one source, so a
/// disagreement there is this pass mixing two ends and no retry changes it.
fn plane_seals(
    plane: &SealPlane<'_>,
    node: NodeId,
    name: &IpnsName,
    is_scope_root: bool,
) -> Result<(), Halt> {
    if is_scope_root != (node == plane.end.root) {
        return Err(Halt::UploadAttempt);
    }
    if plane.end.write_name(&node.0) == *name {
        return Ok(());
    }
    Err(if node == plane.end.root {
        Halt::Unclassified
    } else {
        Halt::UploadAttempt
    })
}

/// The charged form of a halt, for a refusal no retry of this pass clears.
///
/// [`Halt::Unclassified`] retries on the wide outage budget, which is right for
/// a read the next pass may win and wrong for one it will meet again unchanged.
/// A crossing that keeps taking it would hold the FIFO head for an hour of
/// passes over a refusal the first pass already settled.
fn charge_crossing_read(halt: Halt) -> Halt {
    match halt {
        Halt::Unclassified => Halt::UploadAttempt,
        other => other,
    }
}

/// Whether the crossing walk may re-seal `node` into the destination scope.
///
/// Two refusals, both release-active and never a `debug_assert!` (AGENTS.md rule
/// 8), because the walk descends through child refs anyone holding the source
/// scope's write seed authors:
///
/// - A **scope root** — either end's, or any this pass proved — re-authored as a
///   plain child loses the grant section its own readers gate on, which is what
///   the child pipeline rejects on the way in. One inside the moved subtree is
///   also a move no pass may make (`facade.rs::refuse_moving_a_scope_root`); it
///   reaches here when a grant mints a scope root under an already-queued op.
/// - A node the gate-passing base places **outside** the moved subtree is a
///   transplant. Re-sealing it would publish a wire-supplied body at that node's
///   own destination name, over whatever really lives there. A node the base
///   does not place at all is unproven either way and moves with the subtree, on
///   the same footing as the delete walk's own descendants.
fn crossing_may_reseal(
    base: &Snapshot,
    scope_roots: &[NodeId],
    source: &SealPlane<'_>,
    dest: &SealPlane<'_>,
    target: NodeId,
    node: NodeId,
) -> Result<(), Halt> {
    let a_scope_root =
        node == source.end.root || node == dest.end.root || scope_roots.contains(&node);
    let transplant = node != target && base.contains(node) && !base.is_descendant_of(node, target);
    if a_scope_root || transplant {
        return Err(Halt::UploadAttempt);
    }
    Ok(())
}

/// What enters the engine by injection, and what the engine builds over it once
/// per session. Every drain pass borrows it.
pub(crate) struct EngineSeams<T, H: Http, C: CredentialStore, F, S, St, Sch> {
    pub(crate) transport: T,
    pub(crate) api: Rc<ApiClient<H, C>>,
    pub(crate) floors: F,
    pub(crate) snapshot_cache: S,
    pub(crate) staging: St,
    pub(crate) scheduler: Sch,
    pub(crate) http: H,
    pub(crate) gateway: Gateway,
    pub(crate) entropy: Rc<RefCell<Box<dyn Entropy>>>,
    /// The session's outbound event stream.
    pub(crate) events: mpsc::UnboundedSender<Event>,
    /// The transport deadlines uploads and placements run under.
    pub(crate) deadlines: DeadlinePolicy,
    pub(crate) profile: SyncTimingProfile,
    /// Bounds what the preserved dead-letter set may hold, so abandoned versions
    /// cannot eat the device's staging budget.
    pub(crate) storage_policy: StoragePolicy,
    /// The framing profile a version's pinned size is derived under — the same
    /// one the upload framed it at.
    pub(crate) content_profile: ContentProfile,
}

/// The session cells a drain pass reads and writes, borrowed from
/// [`SessionState::drain_cells`](crate::session::SessionState::drain_cells),
/// which documents each cell.
pub(crate) struct DrainCells<'a> {
    pub(crate) live_blocks: &'a RefCell<LiveBlocks>,
    pub(crate) foreign_parked: &'a RefCell<BTreeSet<Vec<u8>>>,
    /// The session's base snapshot, repainted in place on each publish.
    pub(crate) base: &'a BaseSnapshot,
    /// The session's held records.
    pub(crate) held: &'a RefCell<HeldRecords>,
    /// The session's queue hold. It clears only here, when its reason's own
    /// exit comes.
    pub(crate) hold: &'a RefCell<Option<QueueHold>>,
    pub(crate) pending_reclaim: &'a Cell<u64>,
    pub(crate) reclaim_stalls: &'a RefCell<Vec<ReclaimStall>>,
    pub(crate) bookkeeping: &'a RefCell<BookkeepingCursors>,
    pub(crate) orphan_heads: &'a OrphanHeads,
    pub(crate) converged_tick: &'a Cell<bool>,
    pub(crate) cancels: &'a RefCell<UploadCancels>,
    pub(crate) dead_letters: &'a RefCell<RetainedDeadLetters>,
    pub(crate) observed_unlinks: &'a RefCell<Vec<UnlinkedChild>>,
    pub(crate) capture_proofs: &'a RefCell<BTreeMap<NodeId, CaptureProofs>>,
    pub(crate) pending_scope_exits: &'a RefCell<BTreeSet<NodeId>>,
    /// The names this drain is publishing right now, which the renewal walk
    /// stays clear of (ADR 0061 D3 step 2).
    pub(crate) publishing: &'a RefCell<BTreeSet<String>>,
}

/// Holds one name in [`DrainCells::publishing`] while its publish runs.
struct PublishingName<'a> {
    set: &'a RefCell<BTreeSet<String>>,
    name: String,
}

impl<'a> PublishingName<'a> {
    fn hold(set: &'a RefCell<BTreeSet<String>>, name: &IpnsName) -> Self {
        set.borrow_mut().insert(name.as_str().to_owned());
        Self {
            set,
            name: name.as_str().to_owned(),
        }
    }
}

impl Drop for PublishingName<'_> {
    fn drop(&mut self) {
        self.set.borrow_mut().remove(&self.name);
    }
}

/// The values one tick decides before its drain runs.
pub(crate) struct TickInputs<'a> {
    /// Where this session's bytes go. An `Err` holds every content op — the
    /// drain publishes no version it cannot place.
    pub(crate) placement: &'a PlacementDecision,
    /// The bin's own key material. The pass holds these derived edges rather
    /// than the login secret they come from.
    pub(crate) bin_keys: &'a BinIndexKeys,
    /// The owner's bin retention in days, or `None` when the settings load
    /// carried no member choice.
    ///
    /// Expiry is irreversible, so it acts only on a retention the owner set. A
    /// documented default is the right answer for the delete branch, which
    /// bins rather than destroys; here it would destroy on a settings record
    /// this device merely failed to read (blueprint/engine.md "Delete branch").
    pub(crate) bin_retention_days: Option<u32>,
    /// The version retention the owner chose, or [`RetentionPolicy::KeepAll`]
    /// when this session's settings load carried no member choice.
    ///
    /// Shortening history retires bytes, so it acts only on a retention this
    /// device can show is the owner's — the same rule the bin's expiry follows.
    pub(crate) retention: RetentionPolicy,
    /// The scopes this device owes an interior move at (ADR 0063), or `None`
    /// when the owed record did not read.
    pub(crate) owed_moves: Option<&'a [NodeId]>,
}

/// The passes one tick runs, by kind; `run_tick` fixes their order.
pub(crate) struct TickScopes<'a> {
    /// The vault root's own pass. `None` when this tick holds neither vault seed.
    pub(crate) vault: Option<DrainScope<'a>>,
    /// The passes over this vault's own interior scopes.
    pub(crate) interior: Vec<DrainScope<'a>>,
    /// The passes over scopes another identity granted.
    pub(crate) grafted: Vec<DrainScope<'a>>,
}

/// One tick's drain over the durable queue.
pub(crate) struct Drain<'a, T, H: Http, C: CredentialStore, F, S, St, Sch> {
    seams: &'a EngineSeams<T, H, C, F, S, St, Sch>,
    cells: DrainCells<'a>,
    inputs: TickInputs<'a>,
    /// The bin index this pass has established: the one it resolved, or the one
    /// its last confirmed publish left standing. Carried so a bulk soft delete
    /// costs one resolve rather than one per operation; the publish stays per
    /// operation, which is what keeps the entry ahead of its unlink.
    established_bin_index: RefCell<Option<BinIndex>>,
    /// What this tick may still queue in bin purges, shared out across its
    /// scope passes ([`MAX_BIN_EXPIRIES`]).
    bin_expiries: RefCell<TickShare>,
    /// What this tick may still read for capture walks, shared out across its
    /// scope passes ([`MAX_CAPTURE_WALK_READS`]).
    capture_reads: RefCell<TickShare>,
    /// The mirror of the op this pass publishes now.
    mirror: RefCell<OpMirror>,
    /// The nodes one capture walk may hold ([`MAX_CAPTURE_WALK_NODES`]).
    capture_walk_nodes: usize,
}

impl<'a, T, H: Http, C: CredentialStore, F, S, St, Sch> Drain<'a, T, H, C, F, S, St, Sch> {
    pub(crate) fn new(
        seams: &'a EngineSeams<T, H, C, F, S, St, Sch>,
        cells: DrainCells<'a>,
        inputs: TickInputs<'a>,
    ) -> Self {
        Self {
            seams,
            cells,
            inputs,
            established_bin_index: RefCell::new(None),
            bin_expiries: RefCell::new(TickShare::new(MAX_BIN_EXPIRIES, 1)),
            capture_reads: RefCell::new(TickShare::new(MAX_CAPTURE_WALK_READS, 1)),
            capture_walk_nodes: MAX_CAPTURE_WALK_NODES,
            mirror: RefCell::default(),
        }
    }

    /// The same drain under capture walk bounds a fixture can reach.
    #[cfg(test)]
    fn with_capture_walk_bounds(self, reads: usize, nodes: usize) -> Self {
        Self {
            capture_reads: RefCell::new(TickShare::new(reads, 1)),
            capture_walk_nodes: nodes,
            ..self
        }
    }
}

/// One folder's current published state, carried across the ops of one pass so
/// each publish authors onto the previous one.
struct FolderState {
    /// The root of the plane this folder was loaded under, and so the only plane
    /// it may be republished under.
    plane_root: NodeId,
    /// The write-plane name this folder publishes under.
    name: IpnsName,
    /// The record bytes this folder was last loaded or published from, which
    /// the pre-signature re-resolve holds the endpoints to.
    record: Vec<u8>,
    /// The grant-set commitment a scope root carries. A scope root authors
    /// through a different envelope path; a folder with none is a plain child
    /// record.
    commitment: Option<GrantSetCommitment>,
    envelope_unknown: PreservedFields,
    epoch_tag_unknown: PreservedFields,
    created_at: u64,
    modified_at: u64,
    children: Vec<ChildRef>,
    body_unknown: PreservedFields,
    /// The gated read this folder was last loaded or published at, which a
    /// republish builds on.
    observed: Observed,
}

/// The `modified_at` a plan republishes `folder` with: the op's authored time on
/// one of its [authored nodes](Op::authored_nodes), which the overlay stamps
/// from the same set, and the folder's own time otherwise.
fn stamped_modified_at(
    pass: &Pass,
    op: &Op,
    authored: &[NodeId],
    folder: NodeId,
) -> Result<u64, Halt> {
    if authored.contains(&folder) {
        Ok(op.authored_at.0)
    } else {
        Ok(pass.folder(folder)?.modified_at)
    }
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
    /// Where the destination sits relative to the source scope. A non-`Intra`
    /// plan re-seals the moved subtree into the destination scope before the
    /// dest-add names it (blueprint/engine.md "Sync core: Ops").
    crossing: ScopeCrossing,
}

/// What a crossing's re-seal published, held back until the move commits.
///
/// The live-set key is the node id alone
/// ([`HeldKey::Node`](crate::net::HeldKey::Node)), so installing a destination
/// record's hold evicts the source record's. Doing that before the ref moves
/// would leave the source record unrenewed while the source folder is still the
/// only parent naming it, which is the reference-outliving-its-referent law read
/// through the liveness loop.
#[derive(Default)]
struct Resealed {
    /// Source-plane names the move leaves unreferenced, once it commits.
    vacated: Vec<IpnsName>,
    /// Destination-plane names this re-seal published, which a rolled-back
    /// crossing leaves referenced by nothing.
    published: Vec<IpnsName>,
    /// The live-set entries, installed only once the move is durable.
    held: Vec<([u8; 16], HeldRecord)>,
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

/// Where the last pass stopped in each bounded bookkeeping loop, and whether
/// the reclaim figure it left behind prices the whole owed set.
///
/// Session-lived rather than durable: progress comes from rotation, so a
/// restart costs a pass its place in the listing and nothing more.
#[derive(Debug, Default)]
pub struct BookkeepingCursors {
    /// The retire-ledger key the last pass attempted
    /// ([`OwedPage::cursor`](crate::seams::OwedPage)).
    ledger: Option<Vec<u8>>,
    /// Whether that read stopped short of the whole owed set, so
    /// [`pending_reclaim_bytes`](crate::facade::Engine::pending_reclaim_bytes)
    /// is a floor on the debt rather than its total.
    ledger_partial: bool,
    /// Per scope root, the doomed-journal target the last pass attempted.
    journal: BTreeMap<[u8; 16], [u8; 16]>,
}

impl BookkeepingCursors {
    /// Whether the last reclaim pass priced only a window of the owed set.
    #[must_use]
    pub fn reclaim_is_partial(&self) -> bool {
        self.ledger_partial
    }
}

/// One tick's allowance for work its scope passes each want to do, shared out
/// evenly. A scope served first would otherwise spend every slot on its own
/// backlog, and the scopes behind it would wait on a queue they never reach the
/// head of.
pub(crate) struct TickShare {
    /// Slots left to the tick.
    left: usize,
    /// The most of them any one scope may take.
    per_scope: usize,
}

impl TickShare {
    /// `total` slots for a tick that runs `scopes` passes.
    pub(crate) fn new(total: usize, scopes: usize) -> Self {
        Self {
            left: total,
            per_scope: total.div_ceil(scopes.max(1)),
        }
    }

    /// What one pass may take: its share, and never more than the tick has
    /// left.
    fn share(&self) -> usize {
        self.per_scope.min(self.left)
    }

    /// Charge what one pass took.
    fn spend(&mut self, taken: usize) {
        self.left = self.left.saturating_sub(taken);
    }
}

/// What one tick's journal replay may spend across every scope it settles: the
/// entries it replays and the quarantine proofs those entries decide against.
/// Held by the whole tick rather than per scope, so a vault of many promoted
/// scopes costs a tick what a vault of one costs.
///
/// Shared out evenly all the same: a scope settled first would otherwise spend
/// every slot on its own backlog, and the reclamations of the scopes behind it
/// would wait on a queue they never reach the head of.
struct JournalBudget {
    /// Entries left to replay ([`MAX_JOURNAL_REPLAYS`]). Each costs a store
    /// read and a registry batch.
    replays: TickShare,
    /// Quarantine proofs left ([`MAX_QUARANTINE_PROOFS`]). Each costs a fresh
    /// resolve of one descendant's record, so a delete of a large subtree
    /// settles over several ticks rather than holding one open.
    proofs: usize,
    /// Open attempts left across every scope ([`MAX_BOOKKEEPING_OPENS`]).
    /// Charged whether or not the value opens, which is what bounds a prefix
    /// nothing sweeps.
    opens: usize,
}

impl JournalBudget {
    /// The budget for a tick that settles `scopes` scopes.
    fn new(scopes: usize) -> Self {
        Self {
            replays: TickShare::new(MAX_JOURNAL_REPLAYS, scopes),
            proofs: MAX_QUARANTINE_PROOFS,
            opens: MAX_BOOKKEEPING_OPENS,
        }
    }
}

/// Whether a settle pass may decide the reclamation's quarantined descendants,
/// and so what bounds the quarantine to one converged poll tick
/// (blueprint/engine.md "Retirement").
enum Settle<'a> {
    /// The delete's own pass, and every pass of a session whose base no poll
    /// has reconciled yet. The snapshot is this device's own work, or the empty
    /// one a restart opens, rather than a converged view of the plane.
    Hold,
    /// A later pass, with the proof budget it has left to spend.
    Decide(&'a mut usize),
}

/// Where a doomed walk stops descending.
#[derive(Clone, Copy)]
enum Boundary<'r> {
    /// Every child ref is walked. A descendant this pass cannot read is unknown
    /// structure and refuses the whole operation.
    None,
    /// A scope root, which the bin never re-keyed: its record does not open
    /// under the bin-held key, so it is not this purge's to reclaim
    /// ([`Drain::rekey_subtree`]). Holds the pass's proved scope roots.
    ScopeRoots(&'r [NodeId]),
}

impl Boundary<'_> {
    fn admits(self, end: &ScopeEnd<'_>, child: &ChildRef) -> bool {
        match self {
            Self::None => true,
            Self::ScopeRoots(scope_roots) => in_this_scope(end, scope_roots, child),
        }
    }
}

/// One node a delete detaches: the name its record publishes under, and the
/// content roots its published history names ([`Drain::enumerate_doomed`]).
struct Doomed {
    node: NodeId,
    name: IpnsName,
    versions: Vec<ContentVersion>,
}

/// What a record read is anchored to: the scope epoch the reader is at, and the
/// backward key-regression ratchet that reaches the epochs below it.
#[derive(Clone, Copy)]
struct Anchor<'a> {
    epoch: u64,
    history_links: &'a [SignedSealed],
}

/// The scope root a pass anchors on.
struct LoadedRoot {
    state: FolderState,
    /// The epoch every record this pass seals is bound to.
    epoch: u64,
    /// The root's carried read-plane history links ([`Pass::history_links`]).
    history_links: Vec<SignedSealed>,
}

impl LoadedRoot {
    fn anchor(&self) -> Anchor<'_> {
        Anchor {
            epoch: self.epoch,
            history_links: &self.history_links,
        }
    }
}

/// One node's record as loaded for re-authoring: the envelope fields a
/// republish must carry forward byte-stable (#27 D10) plus the opened body.
struct LoadedNode {
    name: IpnsName,
    record: Vec<u8>,
    /// The record a republish at `name` builds on.
    observed: Observed,
    /// The endpoints serve other bytes at the observed sequence too.
    tied: bool,
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
}

/// One op's mirror leg, and whether a previous pass left it short
/// ([`Resume::mirror_gap`]).
#[derive(Default)]
struct OpMirror {
    leg: MirrorLeg,
    gap: bool,
}

impl OpMirror {
    /// The mirror of heads a pass publishes outside any op, which no op reports.
    fn outside_op() -> Self {
        Self {
            leg: MirrorLeg::once(),
            gap: false,
        }
    }
}

/// One record as this pass published it.
struct Published {
    /// The token of the record the self-adopt gated.
    observed: Observed,
    /// The live-set entry, held once something references the record.
    held: HeldRecord,
}

/// The scope state one pass mutates: the source end's anchor epoch, and the
/// folders loaded so far in **ancestor-first load order**, which is also
/// the order the base repaint depends on.
struct Pass {
    /// The source end's scope root — the one scope this pass anchors on.
    root: NodeId,
    /// The read epoch the source end's records bind this pass, proved from the
    /// scope root record the pass opened on. A destination end brings its own.
    epoch: u64,
    /// The scope root's carried read-plane history links: the backward ratchet
    /// a node the lazy wave has not reached is opened through.
    history_links: Vec<SignedSealed>,
    /// The second end's own epoch and ratchet, as the scope root record that
    /// end publishes proved them ([`Drain::open_scope_root`]).
    second_ratchet: Option<(NodeId, u64, Vec<SignedSealed>)>,
    folders: Vec<(NodeId, FolderState)>,
    /// Delete targets this pass wrote a doomed-name journal entry for.
    journalled: Vec<NodeId>,
}

impl Pass {
    fn anchor(&self) -> Anchor<'_> {
        Anchor {
            epoch: self.epoch,
            history_links: &self.history_links,
        }
    }

    /// The read anchor of one seal plane: the epoch and the backward ratchet
    /// that plane's **own** scope root proved.
    ///
    /// A read is anchored and sealed on one scope or on neither. The ratchet
    /// walks history links a scope root signs, so another end's links open
    /// nothing, and the verdict that failure earns charges the member's op for
    /// a driver error rather than reporting one (blueprint/engine.md "Rotation
    /// primitives: the lazy wave"). Charged when the plane names an end whose
    /// root this pass never opened: the pass assembled the pair, and no later
    /// read changes it.
    fn anchor_for(&self, plane: &SealPlane<'_>) -> Result<Anchor<'_>, Halt> {
        if plane.end.root == self.root {
            return Ok(self.anchor());
        }
        match &self.second_ratchet {
            Some((root, epoch, links)) if *root == plane.end.root => Ok(Anchor {
                epoch: *epoch,
                history_links: links,
            }),
            _ => Err(Halt::UploadAttempt),
        }
    }

    /// Record the epoch and the ratchet one second end's scope root proved, so
    /// every later read under that plane walks that end's own links.
    fn hold_second_ratchet(&mut self, root: NodeId, epoch: u64, links: Vec<SignedSealed>) {
        self.second_ratchet = Some((root, epoch, links));
    }

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

    /// Refuse a folder this pass holds whose chain now re-roots onto another
    /// plane: its scope moved under the pass, and the name check cannot catch
    /// it, because the held name was derived under the same stale plane.
    fn keeps_its_plane(&self, folder: NodeId, plane: &SealPlane<'_>) -> Result<(), Halt> {
        if self.folder(folder)?.plane_root == plane.end.root {
            return Ok(());
        }
        Err(Halt::UploadAttempt)
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
        BookkeepingSeal::new(scope.enc_secret, &*self.seams.entropy)
    }

    fn retire_ledger<'s>(&'s self, scope: &'s DrainScope<'_>) -> StagingRetireLedger<'s, St> {
        StagingRetireLedger::new(&self.seams.staging, self.bookkeeping_seal(scope))
    }

    /// Hold `sequence` as `node`'s acknowledged sequence at `name`, retried
    /// once: a lost mark reopens the tie it guards.
    async fn hold_acknowledged(
        &self,
        scope: &DrainScope<'_>,
        node: NodeId,
        name: &IpnsName,
        sequence: u64,
    ) -> Result<(), Halt> {
        let ledger = self.retire_ledger(scope);
        let owner = owner_tag(scope.enc_secret);
        let hold = || ledger.acknowledge(&owner, node.0, name.as_str(), sequence);
        if hold().await.is_ok() {
            return Ok(());
        }
        hold().await.map_err(seam)
    }

    /// The custody a dropped version's debt is journaled under, over `reader`,
    /// which the caller builds once for the tick.
    fn dropped_version_debts<'s>(
        &'s self,
        scope: &'s DrainScope<'_>,
        reader: &'s RecordReader<'s>,
    ) -> DroppedVersionDebts<'s, St> {
        DroppedVersionDebts::new(
            &self.seams.staging,
            reader,
            self.bookkeeping_seal(scope),
            &self.seams.content_profile,
            self.cells.foreign_parked,
            &self.seams.events,
        )
    }

    /// One tick's drain: every pass in [`ordered`] order, each report surfaced
    /// as its pass ends, then the tick's bookkeeping once.
    pub(crate) async fn run_tick<R: ScopeExitRotator>(&self, scopes: TickScopes<'_>, exits: &R) {
        let vault_held = scopes.vault.is_some();
        let passes = ordered(scopes);
        *self.bin_expiries.borrow_mut() = TickShare::new(MAX_BIN_EXPIRIES, passes.len());
        *self.capture_reads.borrow_mut() = TickShare::new(MAX_CAPTURE_WALK_READS, passes.len());
        let mut journalled = Vec::new();
        let ends: Vec<ScopeEnd<'_>> = passes
            .iter()
            .filter(|scope| !scope.is_grafted())
            .map(|scope| scope.source)
            .collect();
        for scope in &passes {
            let mut report = self.run_queue(scope, &ends, exits).await;
            journalled.append(&mut report.journalled_deletes);
            self.surface_drain_report(&report);
        }
        // The retire ledger is the identity's and reads under the vault root's
        // material, so only a tick that holds that root settles.
        if vault_held && let Some(vault) = passes.first() {
            self.settle(vault, &passes, &journalled).await;
        } else {
            // Settle sweeps staging on its own listing. Without it, an
            // abandoned write handle's residue still needs reclaiming at the
            // poll cadence.
            let reader = passes
                .first()
                .map(|scope| RecordReader::new(scope.enc_secret));
            let debts = passes
                .first()
                .zip(reader.as_ref())
                .map(|(scope, reader)| self.dropped_version_debts(scope, reader));
            reconcile_staging(
                &self.seams.staging,
                self.cells.live_blocks,
                self.preserved_bounds(),
                debts.as_ref(),
            )
            .await;
        }
    }

    /// The bounds the preserved dead-letter set is held to at this moment.
    fn preserved_bounds(&self) -> PreservedBounds {
        PreservedBounds::at(
            self.seams.scheduler.now(),
            &self.seams.storage_policy,
            &self.seams.profile,
        )
    }

    /// Fold one pass's report into the host-visible surface: retain and emit
    /// every dead letter, and emit one [`Event::SnapshotUpdated`] if the pass
    /// moved anything off the queue (the overlay the host renders just shrank).
    /// Both sends are best-effort over the in-process channel — a dropped
    /// receiver is fine.
    fn surface_drain_report(&self, report: &DrainReport) {
        for (op_id, target, reason) in &report.dead_letters {
            self.cells
                .dead_letters
                .borrow_mut()
                .insert(*op_id, (Some(*target), *reason));
            let _ = self.seams.events.unbounded_send(Event::DeadLetter {
                op_id: *op_id,
                reason: *reason,
            });
        }
        if !report.is_empty() {
            let _ = self.seams.events.unbounded_send(Event::SnapshotUpdated);
        }
    }

    /// One scope's queue pass: rebase the queue onto gate-passing state and
    /// publish every applied op it can, stopping at the first it cannot, then
    /// clear what the pass orphaned in this scope's own bin. A tick runs one of
    /// these per scope it holds and [`settle`](Self::settle) once, because
    /// everything settle touches is keyed by the identity.
    async fn run_queue<'e, R: ScopeExitRotator>(
        &self,
        scope: &DrainScope<'e>,
        ends: &[ScopeEnd<'e>],
        exits: &R,
    ) -> DrainReport {
        let (report, queued_purges) = self.drain_queue(scope, exits).await;
        self.mirror.replace(OpMirror::outside_op());
        self.adopt_observed_unlinks(scope, ends).await;
        // A queue this pass could not read cannot say which purges are already
        // queued, and the sweep stages ops: it waits rather than duplicating.
        if let Some(queued) = queued_purges {
            self.expire_bin_entries(scope, &queued).await;
        }
        report
    }

    /// The bookkeeping a tick owes once the queues have run: the orphan heads,
    /// the retire ledger and the staging sweep, all of them the identity's, plus
    /// the reclamation journal, which is not. An entry settles only under the
    /// scope whose write seed derives its names and whose read seed opens the
    /// records behind them, so the replay runs once per scope in `scopes` and
    /// leaves every other scope's entries untouched.
    ///
    /// `vault` supplies the material for the identity-wide half: every name in
    /// the retire ledger derives from the vault root's own write seed.
    async fn settle(
        &self,
        vault: &DrainScope<'_>,
        scopes: &[DrainScope<'_>],
        journalled_deletes: &[NodeId],
    ) {
        self.cells
            .orphan_heads
            .retire_pending(&self.seams.api)
            .await;
        // One enumeration serves every consumer below. A desktop vault stages
        // on the order of ten thousand keys, and each of these was listing the
        // whole set for itself. Taken after the queue loop, so a debt the pass
        // just journaled is in it.
        // A store that will not enumerate leaves both the ledger and the sweep
        // for the next pass: "no debt" and "no residue" are claims this one
        // cannot make.
        let Ok(staged) = self.seams.staging.staged_keys().await else {
            return;
        };
        // An X25519 base-point multiply, so the pass derives it once and threads
        // it through every consumer below.
        let reader = RecordReader::new(vault.enc_secret);
        let owner = reader.owner_tag();
        let seal = self.bookkeeping_seal(vault);
        let mut budget = JournalBudget::new(scopes.len());
        let mut owed_now = BTreeSet::new();
        for scope in scopes {
            owed_now.extend(
                self.settle_journalled_deletes(
                    scope,
                    seal,
                    &owner,
                    &staged,
                    journalled_deletes,
                    &mut budget,
                )
                .await,
            );
        }
        let resume = self.cells.bookkeeping.borrow().ledger.clone();
        if let Some(pass) = drain_owed_retires(
            &StagingRetireLedger::over(&self.seams.staging, seal, &staged),
            &owner,
            &self.seams.api,
            &RootSource {
                gateway: &self.seams.gateway,
                http: &self.seams.http,
                profile: &self.seams.content_profile,
            },
            &owed_now,
            resume.as_deref(),
            async |node, owing| self.live_owing_record(vault, node, owing).await,
        )
        .await
        {
            self.cells.pending_reclaim.set(pass.still_owed);
            *self.cells.reclaim_stalls.borrow_mut() = pass.stalls;
            let mut bookkeeping = self.cells.bookkeeping.borrow_mut();
            bookkeeping.ledger = pass.cursor;
            bookkeeping.ledger_partial = pass.partial;
        }
        reconcile_staging_over(
            &self.seams.staging,
            self.cells.live_blocks,
            &staged,
            self.preserved_bounds(),
            Some(&self.dropped_version_debts(vault, &reader)),
        )
        .await;
    }

    /// The queue loop, reporting the purge targets it saw so the expiry leg does
    /// not queue a second purge for an entry one already names.
    async fn drain_queue<R: ScopeExitRotator>(
        &self,
        scope: &DrainScope<'_>,
        exits: &R,
    ) -> (DrainReport, Option<Vec<NodeId>>) {
        let mut report = DrainReport::default();
        let Ok(Queue {
            mine,
            kept,
            all_ids,
        }) = self.queued_ops(scope, &mut report).await
        else {
            return (report, None);
        };
        let queued = mine;
        if queued.is_empty() {
            self.release_hold();
            // A debt outlives the op that owed it, so an empty queue is still a
            // pass that drives the cuts this device owes.
            self.cut_exited_scopes(scope, exits).await;
            // A kept op that left on the scan leaves its count behind otherwise.
            if !report.left_the_queue().is_empty()
                && let Ok(mut attempts) = self.load_attempts(&all_ids).await
            {
                self.record_departures(scope, &queued, kept, &all_ids, &report, &mut attempts)
                    .await;
            }
            return (report, Some(Vec::new()));
        }
        let purges = queued
            .iter()
            .filter(|(_, op)| matches!(op.kind, OpKind::Purge { .. }))
            .map(|(_, op)| op.target)
            .collect();
        let Ok(mut attempts) = self.load_attempts(&all_ids).await else {
            return (report, Some(purges));
        };
        let _ = self
            .pass(scope, exits, &queued, &mut report, &mut attempts)
            .await;
        self.record_departures(scope, &queued, kept, &all_ids, &report, &mut attempts)
            .await;
        (report, Some(purges))
    }

    /// Prune the counts of the ops that left the queue and raise the drained
    /// mark over them.
    ///
    /// Pruned against this pass's own retirements, not just the queue it opened
    /// on: a count left behind for an op that has gone would park the whole
    /// record until some later pass happened to read the queue again.
    async fn record_departures(
        &self,
        scope: &DrainScope<'_>,
        queued: &[(OpId, Op)],
        kept: Vec<OpId>,
        all_ids: &BTreeSet<OpId>,
        report: &DrainReport,
        attempts: &mut Attempts,
    ) {
        let gone = report.left_the_queue();
        let live: BTreeSet<OpId> = all_ids.difference(&gone).copied().collect();
        attempts.retain_live(&live);
        let _ = self.store_attempts(attempts).await;
        let mut order: Vec<OpId> = queued.iter().map(|(op_id, _)| *op_id).chain(kept).collect();
        order.sort_unstable();
        let _ = self.mark_drained(scope, &order, report).await;
    }

    async fn pass<R: ScopeExitRotator>(
        &self,
        scope: &DrainScope<'_>,
        exits: &R,
        queued: &[(OpId, Op)],
        report: &mut DrainReport,
        attempts: &mut Attempts,
    ) -> Result<(), Halt> {
        let published = self.publish_queue(scope, queued, report, attempts).await;
        // Whatever the pass did with the queue, the cuts it owes are driven
        // once, on every exit from it.
        self.cut_exited_scopes(scope, exits).await;
        published
    }

    /// Rebase the queued ops onto gate-passing state and publish what applies,
    /// strict FIFO, stopping at the first failure.
    async fn publish_queue(
        &self,
        scope: &DrainScope<'_>,
        queued: &[(OpId, Op)],
        report: &mut DrainReport,
        attempts: &mut Attempts,
    ) -> Result<(), Halt> {
        if !self.hold_admits_the_head(queued).await {
            return Ok(());
        }

        let opened = self.open_rebased_pass(scope, queued).await;
        // A newer release rewrites the anchor on each write, so its halt must
        // reach the valve to be bounded and named.
        if let (Err(halt @ Halt::ForeignVersion), Some((op_id, op))) = (&opened, queued.first()) {
            self.apply_valve(scope, *op_id, op, *halt, attempts, report)
                .await;
        }
        let (mut pass, rebased) = opened?;
        for (op_id, reason) in &rebased.dead_letters {
            let Some((_, op)) = queued.iter().find(|(id, _)| id == op_id) else {
                continue;
            };
            // A terminally unrebasable op keeps its staged bytes, and this is
            // what keeps them reachable — and openable — once the abandonment
            // has dropped its record from the queue.
            let preserved = self.preserve_dead_letter(scope, *op_id, *reason).await?;
            self.abandon(scope, *op_id, op).await?;
            // The abandonment retired what the op registered.
            if preserved == Preservation::Refused {
                self.release_staged_blocks(op).await;
            }
            report
                .dead_letters
                .push((*op_id, op.target, preserved.observed(*reason)));
        }
        // A drop is not an abandonment: `AlreadySatisfied` on a create is the
        // create having *landed*, so retiring its name would cut a live record
        // its parent already references.
        for (op_id, reason) in &rebased.dropped {
            if *reason == DropReason::AlreadySatisfied
                && let Some((_, op)) = queued.iter().find(|(id, _)| id == op_id)
                && matches!(op.kind, OpKind::Delete { to_bin: true, .. })
            {
                self.mirror.replace(OpMirror::outside_op());
                if let Err(halt) = self.finish_binned_delete(scope, &pass, op.target).await {
                    self.apply_valve(scope, *op_id, op, halt, attempts, report)
                        .await;
                    return Err(halt);
                }
            }
            self.dequeue_op(*op_id).await?;
            report.dropped.push(*op_id);
        }
        // A dropped relocation is the move already landed, so its cut has no
        // publish left to derive the planes from and the replay's own verdict is
        // all there is.
        for root in &rebased.dropped_scope_exits {
            self.owe_scope_exit(scope, *root).await;
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
            self.cells.cancels.borrow_mut().published(applied.op_id);
            report.published.push(applied.op_id);
        }
        Ok(())
    }

    /// Cut every scope root this session owes a
    /// [`RotationTrigger`](crate::rotation::RotationTrigger)`::ScopeExit` for.
    ///
    /// After the publishes, never before: the cut raises the source scope's read
    /// epoch, and a pass still seals that scope's own records at the epoch it
    /// opened on.
    ///
    /// A root that will not cut stays owed rather than being dropped with the op
    /// that owed it — a scope exit that never rotates leaves the grantee it left
    /// holding a live read seed. The one exception is a trigger that escalated
    /// to the vault root, which no share reaches and which therefore names no
    /// grantee to cut out.
    ///
    /// The debt set is the session's, and every pass of a tick reaches this. So
    /// the vault root is read off the base rather than from the pass's own
    /// anchor: a pass anchored on a granted scope root would otherwise drop that
    /// scope's own owed cut as if it were the escalation.
    async fn cut_exited_scopes<R: ScopeExitRotator>(&self, scope: &DrainScope<'_>, exits: &R) {
        // The debt set is this vault's own, and the cut is a rotation of a scope
        // this vault owns. A grafted pass holds no material for one and would
        // spend the debt's only retry.
        if scope.is_grafted() {
            return;
        }
        let vault_root = self.cells.base.borrow().root;
        let still_owed = settle_owed_cuts(
            &self.seams.staging,
            self.bookkeeping_seal(scope),
            scope.enc_secret,
            exits,
            self.cells.pending_scope_exits,
            vault_root,
        )
        .await;
        // A scope this session could not cut is a revocation still outstanding,
        // so the member is told which one rather than left with a silent retry.
        for (root, detail) in still_owed {
            let _ = self.seams.events.unbounded_send(Event::ScopeExitCutOwed {
                scope_root: root,
                detail: detail.to_owned(),
            });
        }
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
        // The bin plane has no probe of its own — the load is the only one — so
        // its hold exits here, on a classified halt at the held op. Every other
        // reason has an exit the pre-pass gate can try.
        if bin_index_hold_exits(*self.cells.hold.borrow(), op_id, halt) {
            self.release_hold();
        }
        match halt {
            Halt::EpochLagged | Halt::OwedMove => {}
            Halt::OtherBinScope if !scope.charges_the_identity => {}
            // Its own budget, its own count: an outage must not spend the
            // attempt budget, and a spent attempt is what tells
            // [`Self::create_replays_a_publish`] this device already published.
            Halt::Unclassified | Halt::LostRace | Halt::OtherBinScope | Halt::ForeignVersion => {
                if attempts.charge_unattributed(op_id) < UNATTRIBUTED_BUDGET {
                    return;
                }
                let reason = if halt == Halt::ForeignVersion {
                    DeadLetterReason::NewerRelease
                } else {
                    DeadLetterReason::AttemptsExhausted
                };
                self.abandon_keeping_its_name(scope, op_id, op, reason, report)
                    .await;
            }
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
            Halt::Attempt
            | Halt::UploadAttempt
            | Halt::RecordRefused
            | Halt::HeadOversized
            | Halt::ScopeRootNotResealable
            | Halt::UnwritableScope => {
                if attempts.charge(op_id) < ATTEMPT_BUDGET {
                    return;
                }
                // A spent budget is still a dead letter, so it keeps the
                // version and hands back at most the name no published record
                // ever reached ([`Halt`]).
                let (reason, owes_its_name) = match halt {
                    Halt::Attempt | Halt::UnwritableScope => {
                        (DeadLetterReason::AttemptsExhausted, false)
                    }
                    Halt::HeadOversized => (DeadLetterReason::HeadTooLarge, true),
                    Halt::ScopeRootNotResealable => {
                        (DeadLetterReason::ScopeRootNotResealable, true)
                    }
                    _ => (DeadLetterReason::AttemptsExhausted, true),
                };
                let Ok(preserved) = self.preserve_dead_letter(scope, op_id, reason).await else {
                    return;
                };
                let handed_back = if owes_its_name {
                    self.retire_unreferenced_name(scope, op).await
                } else {
                    Ok(())
                };
                if handed_back.is_ok() && self.dequeue_op(op_id).await.is_ok() {
                    self.release_unpreserved(scope, preserved, op).await;
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
                self.abandon_keeping_its_name(scope, op_id, op, reason, report)
                    .await;
            }
            // A replayed create keeps its staged version for the same reason and
            // hands back the same name a spent budget does: the record standing
            // at it is one no published parent references, so its registry row
            // would otherwise be re-PUT for as long as the account holds it —
            // which for a restored replay keeps the resurrection candidate alive
            // at the owner's own expense.
            Halt::Permanent(reason @ DeadLetterReason::AlreadyPublished) => {
                let Ok(preserved) = self.preserve_dead_letter(scope, op_id, reason).await else {
                    return;
                };
                if self.retire_unreferenced_name(scope, op).await.is_ok()
                    && self.dequeue_op(op_id).await.is_ok()
                {
                    self.release_unpreserved(scope, preserved, op).await;
                    report
                        .dead_letters
                        .push((op_id, op.target, preserved.observed(reason)));
                }
            }
            Halt::Permanent(reason) => {
                self.dead_letter(scope, op_id, op, reason, report).await;
            }
            Halt::Blocked { needed_bytes } => {
                self.hold_head(op_id, op, QueueHoldReason::Quota { needed_bytes });
            }
            Halt::HeldBySettings(hold) => {
                self.hold_head(op_id, op, QueueHoldReason::Settings(hold));
            }
            Halt::HeldByBinIndex(check) => {
                self.hold_head(op_id, op, QueueHoldReason::BinIndex(check));
            }
        }
    }

    /// Whether the held head may be tried again this tick: the one gate over
    /// the one hold cell. A hold whose op has left the queue, or whose reason's
    /// own exit has come, lets go of the cell.
    async fn hold_admits_the_head(&self, queued: &[(OpId, Op)]) -> bool {
        let Some(hold) = *self.cells.hold.borrow() else {
            return true;
        };
        if still_queued(queued, hold.op_id) {
            match hold.reason {
                QueueHoldReason::Quota { needed_bytes } => {
                    if !self.quota_admits(needed_bytes).await {
                        return false;
                    }
                }
                QueueHoldReason::Settings(hold) => {
                    if settings_hold(self.inputs.placement) == Some(hold) {
                        return false;
                    }
                }
                // The bin index load is its own probe, so this reason neither
                // stops a pass nor clears before one: [`Self::apply_valve`] and
                // [`Self::establish_bin_index`] are its exits.
                QueueHoldReason::BinIndex(_) => return true,
            }
        }
        self.release_hold();
        true
    }

    /// Whether a `GET /account/quota` probe reports room for a held head. The
    /// probe is the hold's only exit, so an unanswered one leaves it in place.
    async fn quota_admits(&self, needed_bytes: u64) -> bool {
        let Ok(placement) = self.inputs.placement.as_ref() else {
            // A placement the settings themselves refuse is a verdict the pass
            // re-takes as its own hold, so the head stops waiting under a cause
            // the member cannot act on. An outage is not a verdict: it keeps
            // the head where it is rather than spending the unattributed budget
            // on a placement no pass can decide.
            return settings_hold(self.inputs.placement).is_some();
        };
        // Only the hosted leg is quota-gated, so no answer the quota endpoint
        // could give bears on a hold under a placement without one — and an
        // endpoint that will not answer would park the head on that question.
        if !placement.has_hosted_leg() {
            return true;
        }
        let Ok(quota) = self.seams.api.quota().await else {
            return false;
        };
        pre_flight_quota_check(needed_bytes, &quota, true).is_ok()
    }

    fn hold_head(&self, op_id: OpId, op: &Op, reason: QueueHoldReason) {
        *self.cells.hold.borrow_mut() = Some(QueueHold {
            op_id,
            node: op.target,
            reason,
        });
    }

    fn release_hold(&self) {
        *self.cells.hold.borrow_mut() = None;
    }

    /// This identity's queued ops, minus restore residue: an op at or below the
    /// durable drained-op mark already left this queue once, so the queue it
    /// came back in predates the completion record.
    async fn queued_ops(
        &self,
        scope: &DrainScope<'_>,
        report: &mut DrainReport,
    ) -> Result<Queue, Halt> {
        let raw = self.seams.staging.queued_ops().await.map_err(seam)?;
        let all_ids = raw.iter().map(|(op_id, _)| *op_id).collect();
        let scan = decode_queue(&RecordReader::new(scope.enc_secret), &raw);
        if scan.mine.is_empty() {
            return Ok(Queue {
                mine: Vec::new(),
                kept: Vec::new(),
                all_ids,
            });
        }
        // `None` is "no op has ever drained here", not "id 0 drained": the seam
        // contract promises only strictly-increasing ids, so a host that starts
        // at 0 must not lose its first op.
        let drained = self.drained_mark(scope).await?;
        let published = published_op_mark(&self.seams.staging, scope.enc_secret)
            .await
            .map_err(seam)?;
        let mut notes = self.kept_notes(scope).await?;
        let now = self.seams.scheduler.now();
        let mut mine = Vec::with_capacity(scan.mine.len());
        let mut kept = Vec::new();
        for (op_id, op) in scan.mine {
            if drained.is_some_and(|mark| op_id.0 <= mark) {
                self.dequeue_op(op_id).await?;
                report.restore_residue.push(op_id);
                continue;
            }
            if published.is_some_and(|mark| op_id.0 <= mark) {
                let place = self.kept_place(scope, &op).await?;
                match kept_verdict(notes.note_or_first_sight(op_id, now), place, now) {
                    KeptVerdict::Stay => {
                        kept.push(op_id);
                        continue;
                    }
                    KeptVerdict::Expired => {
                        self.dequeue_op(op_id).await?;
                        self.release_staged_blocks(&op).await;
                        notes.remove(op_id);
                        report.dropped.push(op_id);
                        continue;
                    }
                    KeptVerdict::Recheck => {}
                }
            }
            mine.push((op_id, op));
        }
        notes.retain_queued(&all_ids);
        self.store_kept_notes(scope, &notes).await?;
        Ok(Queue {
            mine,
            kept,
            all_ids,
        })
    }

    /// This identity's kept-op notes ([`KEPT_OP_NOTES_PREFIX`]).
    async fn kept_notes(&self, scope: &DrainScope<'_>) -> Result<KeptNotes, Halt> {
        let stored = self
            .seams
            .staging
            .staged_bytes(&owner_scoped_key(KEPT_OP_NOTES_PREFIX, scope.enc_secret))
            .await
            .map_err(seam)?;
        Ok(KeptNotes::decode(stored.as_deref()))
    }

    async fn store_kept_notes(
        &self,
        scope: &DrainScope<'_>,
        notes: &KeptNotes,
    ) -> Result<(), Halt> {
        if !notes.is_dirty() {
            return Ok(());
        }
        let key = owner_scoped_key(KEPT_OP_NOTES_PREFIX, scope.enc_secret);
        let stored = if notes.is_empty() {
            self.seams.staging.remove_staged_bytes(&key).await
        } else {
            self.seams
                .staging
                .put_staged_bytes(&key, &notes.encode())
                .await
        };
        stored.map_err(seam)
    }

    /// Where the write scope of a kept op stands for this pass: the nearest
    /// proved scope root above the node the op writes under, as
    /// [`Self::ensure_folder`] finds it.
    async fn kept_place(&self, scope: &DrainScope<'_>, op: &Op) -> Result<KeptPlace, Halt> {
        let anchor = match &op.kind {
            OpKind::Create { parent, .. } => *parent,
            OpKind::Restore { into, .. } => *into,
            _ => op.target,
        };
        let (nearest, anchor_name) = {
            let base = self.cells.base.borrow();
            let Some(meta) = base.node(anchor) else {
                return Ok(KeptPlace::Elsewhere);
            };
            let nearest = core::iter::once(anchor)
                .chain(base.ancestors(anchor))
                .find(|node| scope.scope_roots.contains(node));
            (nearest, meta.ipns_name.clone())
        };
        let Some(root) = nearest else {
            return Ok(KeptPlace::Elsewhere);
        };
        let end = match scope.second_end() {
            Ok(Some(destination)) if destination.end.root == root => destination.end,
            _ if scope.source.root == root => scope.source,
            _ if scope.keyless_roots.contains(&root) => return Ok(KeptPlace::Keyless),
            _ => return Ok(KeptPlace::Elsewhere),
        };
        // A write cut moves every node to a name of the new seed, so a base
        // entry at another name is a read from before the flip. The pass
        // repaints its own scope root from the live root before the rebase.
        let anchor_read_live = anchor == scope.source.root
            || anchor_name.as_deref() == Some(end.write_name(&anchor.0).as_str().as_bytes());
        Ok(KeptPlace::Writes {
            live_write_epoch: self.write_epoch_of(&end).await?,
            anchor_read_live,
        })
    }

    /// The write epoch this device has seen for `end`'s scope. A scope with no
    /// floor yet is at its first epoch.
    async fn write_epoch_of(&self, end: &ScopeEnd<'_>) -> Result<u64, Halt> {
        Ok(
            floor::write_epoch_floor(&end.floors(&self.seams.floors), &end.root.0)
                .await
                .map_err(seam)?
                .unwrap_or(GENESIS_EPOCH),
        )
    }

    /// Note the write epoch of `end` and the time for an op whose last record
    /// just confirmed, so the op stays queued as a kept op (ADR 0069 D2, D4).
    /// Written before the published-op mark rises, so an op at or below the
    /// mark has a note. Best-effort, as [`Self::mark_published`] is: an op with
    /// no note gets one check.
    async fn keep_published(&self, scope: &DrainScope<'_>, end: &ScopeEnd<'_>, op_id: OpId) {
        let (Ok(write_epoch), Ok(mut notes)) =
            (self.write_epoch_of(end).await, self.kept_notes(scope).await)
        else {
            return;
        };
        notes.insert(
            op_id,
            KeptNote {
                write_epoch,
                published_at: self.seams.scheduler.now(),
            },
        );
        let _ = self.store_kept_notes(scope, &notes).await;
    }

    // -----------------------------------------------------------------------
    // Loading the folders a pass authors onto.
    // -----------------------------------------------------------------------

    /// Open the pass and rebase the queue onto it.
    ///
    /// An endpoint split leaves two records at the floor, and a read can take
    /// our own losing record, which already carries the head op (ADR 0061 D3
    /// step 7). The pass then builds on a gated record of the scope root, or of
    /// a folder the head op writes, that the head op does not read as applied
    /// on, or on the resolved records when there is none.
    async fn open_rebased_pass(
        &self,
        scope: &DrainScope<'_>,
        queued: &[(OpId, Op)],
    ) -> Result<(Pass, ReplayReport), Halt> {
        let (resolved, others) = self.scope_root_candidates(scope).await?;
        let mut pass = self.open_pass(scope, &resolved).await?;
        let rebased = self.rebase_queue(scope, queued);
        if !head_reads_applied(&rebased, queued) {
            return Ok((pass, rebased));
        }
        let root = scope.source.root;
        let chosen = self
            .first_unapplied(scope, queued, root, &others, |bytes| {
                self.open_root_candidate(scope, bytes)
            })
            .await;
        if let Some((mut tied, state, rebased)) = chosen {
            tied.insert(root, state);
            return Ok((tied, rebased));
        }
        for folder in self.head_folders(queued) {
            if let Some(rebased) = self
                .rebase_on_tied_folder(scope, &mut pass, folder, queued)
                .await?
            {
                return Ok((pass, rebased));
            }
        }
        Ok((pass, self.rebase_queue(scope, queued)))
    }

    /// The folders among the head op's authored nodes: a tied record of any
    /// folder the op republishes can already carry the op.
    fn head_folders(&self, queued: &[(OpId, Op)]) -> Vec<NodeId> {
        let Some((_, op)) = queued.first() else {
            return Vec::new();
        };
        let base = self.cells.base.borrow();
        op.authored_nodes(|| {
            base.links_ranked(op.target)
                .iter()
                .map(|link| link.parent)
                .collect()
        })
        .into_iter()
        .filter(|node| {
            *node != base.root
                && base
                    .node(*node)
                    .is_some_and(|meta| meta.kind == crate::facade::NodeKind::Folder)
        })
        .collect()
    }

    /// Rebase onto another gated record `folder` serves at its sequence, when
    /// the head op does not read as applied on it. A folder this pass cannot
    /// load or read offers none, so a failed probe drops the head op as landed
    /// and does not stall the queue.
    async fn rebase_on_tied_folder(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        folder: NodeId,
        queued: &[(OpId, Op)],
    ) -> Result<Option<ReplayReport>, Halt> {
        let Ok(plane) = self.ensure_folder(scope, pass, folder).await else {
            return Ok(None);
        };
        if folder == plane.end.root {
            return Ok(None);
        }
        let name = plane.end.write_name(&folder.0);
        let Ok(Some(served)) = self.served_child(&plane, folder, &name).await else {
            return Ok(None);
        };
        let held = &pass.folder(folder)?.record;
        let others: Vec<Vec<u8>> = served
            .records
            .into_iter()
            .filter(|record| record != held)
            .collect();
        let anchor = pass.anchor_for(&plane)?;
        let plane = &plane;
        let chosen = self
            .first_unapplied(scope, queued, folder, &others, |bytes| async move {
                let state = self.open_tied_folder(plane, anchor, folder, bytes).await?;
                Ok(((), state))
            })
            .await;
        let Some(((), state, rebased)) = chosen else {
            return Ok(None);
        };
        *pass.folder_mut(folder)? = state;
        Ok(Some(rebased))
    }

    /// The first of `candidates` for `folder` on which the head op does not
    /// read as applied. Each try paints and replays a copy of the base, since
    /// a record that does not name a child would drop its subtree; only the
    /// chosen record reaches the base.
    async fn first_unapplied<'c, Opened, Fut>(
        &self,
        scope: &DrainScope<'_>,
        queued: &[(OpId, Op)],
        folder: NodeId,
        candidates: &'c [Vec<u8>],
        open: impl Fn(&'c [u8]) -> Fut,
    ) -> Option<(Opened, FolderState, ReplayReport)>
    where
        Fut: core::future::Future<Output = Result<(Opened, FolderState), Halt>>,
    {
        for bytes in candidates {
            let Ok((opened, state)) = open(bytes).await else {
                continue;
            };
            let mut trial = self.cells.base.borrow().clone();
            paint_folder(
                scope,
                &mut trial,
                folder,
                &state.children,
                state.observed.sequence(),
                state.modified_at,
            );
            let rebased = replay_on(scope, &trial, queued);
            if !head_reads_applied(&rebased, queued) {
                *self.cells.base.borrow_mut() = trial;
                return Some((opened, state, rebased));
            }
        }
        None
    }

    /// The queue replayed onto the base snapshot.
    fn rebase_queue(&self, scope: &DrainScope<'_>, queued: &[(OpId, Op)]) -> ReplayReport {
        replay_on(scope, &self.cells.base.borrow(), queued)
    }

    /// The source scope root [`resolved_bytes`] picks, and every other record
    /// the endpoints serve at the floor beside it that the gate admits.
    async fn scope_root_candidates(
        &self,
        scope: &DrainScope<'_>,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), Halt> {
        let end = &scope.source;
        let gated = self
            .gated_scope_root(scope, end, ResolveMode::CacheFirst)
            .await?;
        let served: Vec<Vec<u8>> = match &gated.resolved.outcome {
            ResolveOutcome::Current { record_bytes } => {
                gated.tied.iter().chain([record_bytes]).cloned().collect()
            }
            _ => Vec::new(),
        };
        let resolved = resolved_bytes(gated, end.root_name, &self.seams.events)?;
        let floors = end.floors(&self.seams.floors);
        let adopter = self.root_adopter(scope, &floors, end);
        let mut others = Vec::new();
        for bytes in served {
            if bytes != resolved && gates_at_floor(&adopter, end.root_name, &bytes).await {
                others.push(bytes);
            }
        }
        Ok((resolved, others))
    }

    /// Open a pass anchored on the scope root `record_bytes`, whose epoch every
    /// record this pass seals is bound to.
    async fn open_pass(&self, scope: &DrainScope<'_>, record_bytes: &[u8]) -> Result<Pass, Halt> {
        let (mut pass, state) = self.open_root_candidate(scope, record_bytes).await?;
        self.repaint_folder(
            scope,
            scope.source.root,
            &state.children,
            state.observed.sequence(),
            state.modified_at,
        );
        pass.insert(scope.source.root, state);
        Ok(pass)
    }

    /// A pass anchored on the scope root `record_bytes`, and that root's state,
    /// which neither the pass nor the base holds yet.
    async fn open_root_candidate(
        &self,
        scope: &DrainScope<'_>,
        record_bytes: &[u8],
    ) -> Result<(Pass, FolderState), Halt> {
        let root = self
            .open_root_record(Some(scope), &scope.source, record_bytes)
            .await?;
        let pass = Pass {
            root: scope.source.root,
            epoch: root.epoch,
            history_links: root.history_links,
            second_ratchet: None,
            folders: Vec::new(),
            journalled: Vec::new(),
        };
        Ok((pass, root.state))
    }

    /// One end's scope root as the record plane serves it ([`resolved_bytes`]),
    /// opened.
    async fn resolve_and_open_scope_root(
        &self,
        scope: &DrainScope<'_>,
        source: &ScopeEnd<'_>,
    ) -> Result<LoadedRoot, Halt> {
        let record_bytes = self.resolve_scope_root(scope, source).await?;
        self.open_root_record(Some(scope), source, &record_bytes)
            .await
    }

    /// The scope root as this device last held it: the cached record, opened.
    async fn load_scope_root(&self, source: &ScopeEnd<'_>) -> Result<LoadedRoot, Halt> {
        let record_bytes = self
            .seams
            .snapshot_cache
            .get(source.root_name.as_str().as_bytes())
            .await
            .map_err(seam)?
            .ok_or(Halt::Unclassified)?;
        self.open_root_record(None, source, &record_bytes).await
    }

    /// One scope root's record as currently published: its envelope's carried
    /// fields, its unsealed folder body, the scope epoch and the ratchet its
    /// grant section carries.
    ///
    /// `scope` is the pass that resolved the bytes, and `None` for the cached
    /// copy ([`Self::load_scope_root`]).
    async fn open_root_record(
        &self,
        scope: Option<&DrainScope<'_>>,
        source: &ScopeEnd<'_>,
        record_bytes: &[u8],
    ) -> Result<LoadedRoot, Halt> {
        let (sequence, envelope, _) = assemble_head_envelope(
            &self.seams.gateway,
            &self.seams.http,
            source.root_name,
            record_bytes,
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
            &source.floors(&self.seams.floors),
            source.root_name.as_str().as_bytes(),
            &source.root.0,
            sequence,
            envelope.epoch,
            floor::Strictness::AtFloor,
        )
        .await
        .map_err(|_| Halt::UploadAttempt)?;
        let observed = Observed::gated(source.root_name, sequence, envelope.v)
            .map_err(classify_publish_error)?;
        let read_key = source.read_key(&source.root.0);
        let Ok(body) = open_read_body(&envelope, &read_key) else {
            return Err(self
                .unopened_root(scope, source, record_bytes, envelope.epoch)
                .await);
        };
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
        // A scope root the root gate passed carries a decodable section; bytes
        // that do not are not a root this pass may anchor a ratchet on.
        let section = grant_section_bytes(&envelope)
            .and_then(|bytes| decode_grant_section(bytes).ok())
            .ok_or(Halt::Unclassified)?;
        Ok(LoadedRoot {
            state: FolderState {
                plane_root: source.root,
                name: source.root_name.clone(),
                record: record_bytes.to_vec(),
                commitment: Some(section.commitment),
                envelope_unknown: envelope.unknown,
                epoch_tag_unknown: envelope.epoch_tag_unknown,
                created_at,
                modified_at,
                children,
                body_unknown: unknown,
                observed,
            },
            epoch,
            history_links: section.history_links,
        })
    }

    /// What a scope root body that the session seed does not open costs.
    ///
    /// At another epoch than the seed's stamp the seed lags a rotation
    /// ([`epoch_skew`]). At the stamp epoch the gate recovers the record's own
    /// seed again, which re-opens the body: a seed that opens it is a rotation
    /// that raced ours, so the op waits. Any gate refusal of the record is
    /// refused and reported (AGENTS.md rule 6). The cached copy has no pass to
    /// recover through and reports nothing.
    async fn unopened_root(
        &self,
        scope: Option<&DrainScope<'_>>,
        source: &ScopeEnd<'_>,
        record_bytes: &[u8],
        epoch: u64,
    ) -> Halt {
        let Some(scope) = scope else {
            return Halt::UploadAttempt;
        };
        if source.read_seed_stamp != Some(epoch) {
            return epoch_skew(scope, source);
        }
        let floors = source.floors(&self.seams.floors);
        let adopter = self.root_adopter(scope, &floors, source);
        match recover_at_floor(&adopter, source.root_name, record_bytes).await {
            Err(GateError::Rejected(rejection)) => {
                refuse_record(&self.seams.events, source.root_name, &rejection)
            }
            Err(GateError::Seam(error)) => seam(error),
            _ => Halt::Unclassified,
        }
    }

    /// The scope-root adopter for one end: the owner's own seed source, and the
    /// ascent authority an interior root's gate stage needs.
    fn root_adopter<'e>(
        &'e self,
        scope: &'e DrainScope<'_>,
        floors: &'e SharerScopedFloorStore<'e, F>,
        end: &ScopeEnd<'_>,
    ) -> RootAdopter<'e, H, SharerScopedFloorStore<'e, F>> {
        let adopter = match scope.granted {
            Some(GrantedPass { sharer_enc, .. }) => RootAdopter::for_grantee(
                &self.seams.gateway,
                &self.seams.http,
                floors,
                scope.enc_secret,
                sharer_enc,
                scope.owner_identity,
                end.root.0,
            ),
            None => RootAdopter::new(
                &self.seams.gateway,
                &self.seams.http,
                floors,
                scope.enc_secret,
                scope.owner_identity,
                end.root.0,
            ),
        };
        match end.ascent_node_seed {
            Some(seed) => adopter.under_parent_node_seed(seed.clone()),
            None => adopter,
        }
    }

    /// The child adopter for `node` on one plane, its unseal bounded by the
    /// plane's epoch.
    fn child_adopter<'e>(
        &'e self,
        plane: &SealPlane<'_>,
        floors: &'e SharerScopedFloorStore<'e, F>,
        node: NodeId,
    ) -> ChildAdopter<'e, H, SharerScopedFloorStore<'e, F>> {
        ChildAdopter::new(
            &self.seams.gateway,
            &self.seams.http,
            floors,
            plane.end.root.0,
            plane.end.read_scope_seed.clone(),
            node.0,
        )
        .with_seed_stamp(Some(plane.epoch))
    }

    /// One end's scope root as the record plane now serves it, resolved through
    /// its own gate.
    ///
    /// The bytes come from the resolve rather than the cache: [`resolve_gated`]
    /// writes the cache only on an adopt or a recovered own-root `Current`, never
    /// on `NoUpdate`, so a root this device published through another path — a
    /// grant mint, a rotation — is current on the plane and stale in the cache.
    async fn resolve_scope_root(
        &self,
        scope: &DrainScope<'_>,
        end: &ScopeEnd<'_>,
    ) -> Result<Vec<u8>, Halt> {
        let resolved = self
            .gated_scope_root(scope, end, ResolveMode::CacheFirst)
            .await?;
        resolved_bytes(resolved, end.root_name, &self.seams.events)
    }

    /// One end's scope root through its own gate, under `mode`.
    async fn gated_scope_root(
        &self,
        scope: &DrainScope<'_>,
        end: &ScopeEnd<'_>,
        mode: ResolveMode,
    ) -> Result<GatedResolve, Halt> {
        let floors = end.floors(&self.seams.floors);
        let adopter = self.root_adopter(scope, &floors, end);
        resolve_gated(
            &self.seams.transport,
            &self.seams.snapshot_cache,
            &adopter,
            end.root_name,
            mode,
        )
        .await
        .map_err(seam)
    }

    /// Resolve one non-root node's own record through the child pipeline and
    /// open it for re-authoring. The gate decides: only a record that passes
    /// the child bindings, the floors, and the AAD-bound unseal is authorable.
    async fn load_child_node(
        &self,
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        node: NodeId,
        mode: ResolveMode,
    ) -> Result<LoadedNode, Halt> {
        let name = plane.end.write_name(&node.0);
        let floors = plane.end.floors(&self.seams.floors);
        let adopter = self.child_adopter(plane, &floors, node);
        let resolved = resolve_gated(
            &self.seams.transport,
            &self.seams.snapshot_cache,
            &adopter,
            &name,
            mode,
        )
        .await
        .map_err(seam)?;
        let tied = !resolved.tied.is_empty();
        // A drain publish is an ordinary write, so it carries the lazy wave
        // rather than refusing what a cut left behind: a record the epoch floor
        // rejects is re-read at the epoch it was sealed at, and the publish path
        // re-seals it at this pass's.
        let (record_bytes, lagging) = match &resolved.resolved.outcome {
            ResolveOutcome::TrustViolation(rejection) => match rejection.reason {
                RejectionReason::EpochBelowFloor { epoch, .. } => (
                    adopter
                        .assembled_record_bytes(&name)
                        .ok_or(Halt::EpochLagged)?,
                    Some(epoch),
                ),
                _ => return Err(refuse_record(&self.seams.events, &name, rejection)),
            },
            _ => (resolved_bytes(resolved, &name, &self.seams.events)?, None),
        };
        self.open_child_record(plane, anchor, &adopter, name, record_bytes, lagging, tied)
            .await
    }

    /// Open one non-root node's `record_bytes` for re-authoring.
    #[expect(clippy::too_many_arguments, reason = "one record's full opening")]
    async fn open_child_record(
        &self,
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        adopter: &ChildAdopter<'_, H, SharerScopedFloorStore<'_, F>>,
        name: IpnsName,
        record_bytes: Vec<u8>,
        lagging: Option<u64>,
        tied: bool,
    ) -> Result<LoadedNode, Halt> {
        let (adopted, envelope) = self
            .open_for_reauthor(plane, anchor, adopter, &name, &record_bytes, lagging)
            .await?;
        let observed =
            Observed::gated(&name, adopted.sequence, envelope.v).map_err(classify_publish_error)?;
        // Re-sealing a node at an epoch above the scope's would cross the AAD
        // epoch binding.
        if adopted.epoch > anchor.epoch {
            return Err(Halt::Unclassified);
        }
        Ok(LoadedNode {
            name,
            record: record_bytes,
            observed,
            tied,
            envelope_unknown: envelope.unknown,
            epoch_tag_unknown: envelope.epoch_tag_unknown,
            body: adopted.read_body,
        })
    }

    /// Open one node's record for re-authoring: at the durable floor, or — for a
    /// node the lazy wave has not reached — at the epoch it was sealed at, under
    /// the seed this scope's backward key-regression ratchet recovers for that
    /// epoch (CONTEXT.md "Lazy wave"). The publish path re-seals whatever comes
    /// back at the anchor's epoch, which carries the wave one node further.
    async fn open_for_reauthor(
        &self,
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        adopter: &ChildAdopter<'_, H, SharerScopedFloorStore<'_, F>>,
        name: &IpnsName,
        record_bytes: &[u8],
        lagging: Option<u64>,
    ) -> Result<(Adopted, Envelope), Halt> {
        let lagging = match lagging {
            Some(epoch) => epoch,
            None => match adopter.open_carried_at_floor(name, record_bytes).await {
                Ok(carried) => return Ok(carried),
                Err(GateError::Rejected(rejection)) => match rejection.reason {
                    RejectionReason::EpochBelowFloor { epoch, .. } => epoch,
                    _ => return Err(refuse_record(&self.seams.events, name, &rejection)),
                },
                Err(GateError::Seam(_)) => return Err(Halt::UploadAttempt),
            },
        };
        let seed = seed_for_lagging(plane.end.root.0, plane.end.read_scope_seed, anchor, lagging)?;
        adopter
            .open_interior_under(name, record_bytes, &seed)
            .await
            .map_err(|_| Halt::UploadAttempt)
    }

    /// Make `folder` and every ancestor between it and the root of the plane it
    /// resolves for available in `pass`, loading ancestor-first so the base
    /// repaint always has a parent to hang a projection off. Answers the plane
    /// `folder` itself seals under, which is also the plane of every node it
    /// parents.
    async fn ensure_folder<'s>(
        &self,
        scope: &DrainScope<'s>,
        pass: &mut Pass,
        folder: NodeId,
    ) -> Result<SealPlane<'s>, Halt> {
        if pass.holds(folder) {
            return scope.folder_plane(pass, folder);
        }
        let mut chain = {
            let base = self.cells.base.borrow();
            let mut chain = base.ancestors(folder);
            chain.reverse();
            chain.push(folder);
            chain
        };
        // A folder the nearest proved scope root above it does not put in this
        // pass is not a folder either of this pass's write planes may author.
        let Some(nearest) = chain
            .iter()
            .rposition(|node| scope.scope_roots.contains(node))
        else {
            return Err(Halt::Unclassified);
        };
        let plane = scope
            .plane_rooted_at(pass.epoch, chain[nearest])?
            .ok_or_else(|| {
                halt_below_another_scope_root(
                    scope.keyless_roots,
                    scope.charges_the_identity,
                    chain[nearest],
                )
            })?;
        chain.drain(..nearest);
        for node in chain {
            if pass.holds(node) {
                pass.keeps_its_plane(node, &plane)?;
                continue;
            }
            let state = if node == plane.end.root {
                self.open_scope_root(scope, pass, &plane).await?
            } else {
                self.load_child_folder(&plane, pass.anchor_for(&plane)?, node)
                    .await?
            };
            self.repaint_folder(
                scope,
                node,
                &state.children,
                state.observed.sequence(),
                state.modified_at,
            );
            pass.insert(node, state);
        }
        Ok(plane)
    }

    /// One end's scope root, proved against its own published record before
    /// anything is authored under that end.
    ///
    /// The anchor end proves its epoch at [`Self::open_pass`]; a second end's
    /// arrives from the tick's boundary walk, so this is the read that proves
    /// it. Without it an authoring with no prior load — a create, whose parent
    /// the pass has not read — would seal a live record under a seed a rotation
    /// has already revoked, and the self-adopt would catch it only past the PUT.
    ///
    /// The root goes through [`RootAdopter`]: it carries a grant section, which
    /// the child pipeline rejects.
    ///
    /// The ratchet the record carries is held on the pass beside the epoch it
    /// proved, so every later read under this plane walks this end's own
    /// history links ([`Pass::anchor_for`]).
    async fn open_scope_root(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        plane: &SealPlane<'_>,
    ) -> Result<FolderState, Halt> {
        let root = self.resolve_and_open_scope_root(scope, &plane.end).await?;
        if root.epoch != plane.epoch {
            return Err(epoch_skew(scope, &plane.end));
        }
        if plane.end.root != pass.root {
            pass.hold_second_ratchet(plane.end.root, root.epoch, root.history_links);
        }
        Ok(root.state)
    }

    /// Load one non-root folder's state.
    async fn load_child_folder(
        &self,
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        folder: NodeId,
    ) -> Result<FolderState, Halt> {
        let loaded = self
            .load_child_node(plane, anchor, folder, ResolveMode::CacheFirst)
            .await?;
        folder_state(plane, loaded)
    }

    /// One tied record of a non-root folder the head op writes, opened.
    async fn open_tied_folder(
        &self,
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        folder: NodeId,
        record_bytes: &[u8],
    ) -> Result<FolderState, Halt> {
        let name = plane.end.write_name(&folder.0);
        let floors = plane.end.floors(&self.seams.floors);
        let adopter = self.child_adopter(plane, &floors, folder);
        let loaded = self
            .open_child_record(
                plane,
                anchor,
                &adopter,
                name,
                record_bytes.to_vec(),
                None,
                true,
            )
            .await?;
        folder_state(plane, loaded)
    }

    // -----------------------------------------------------------------------
    // The per-op publish plans.
    // -----------------------------------------------------------------------

    /// Publish one applied op's records, referent before reference, and report
    /// once what its mirror is short of.
    async fn publish_applied(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        rebased: &Snapshot,
    ) -> Result<(), Halt> {
        self.mirror.take();
        self.publish_op(scope, pass, applied, rebased).await?;
        let shortfall = mirror_shortfall(&self.mirror.borrow());
        self.emit_mirror_shortfall(applied, shortfall);
        Ok(())
    }

    async fn publish_op(
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
                    crossing: ScopeCrossing::Intra,
                };
                self.publish_ref_move(scope, pass, applied, rebased, plan)
                    .await
            }
            OpKind::Delete { to_bin, .. } => {
                self.publish_delete(scope, pass, applied, *to_bin).await
            }
            OpKind::Restore { into, .. } => {
                self.publish_restore(scope, pass, applied, rebased, *into)
                    .await
            }
            OpKind::Purge { deleted_at } => {
                self.publish_purge(scope, pass, applied, *deleted_at).await
            }
            OpKind::Relink {
                from_parent,
                new_parent,
                crossing,
            } => {
                let plan = MovePlan {
                    from_parent: *from_parent,
                    dest: *new_parent,
                    new_name: None,
                    vacated: None,
                    crossing: *crossing,
                };
                self.publish_ref_move(scope, pass, applied, rebased, plan)
                    .await
            }
            OpKind::Move {
                from_parent,
                new_parent,
                crossing,
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
                    crossing: *crossing,
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
            OpKind::RestoreVersion { content_cid } => {
                self.publish_restore_version(scope, pass, applied, content_cid)
                    .await
            }
            OpKind::DeleteVersion { content_cid } => {
                self.publish_delete_version(scope, pass, applied, content_cid)
                    .await
            }
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
        let plane = self.ensure_folder(scope, pass, parent).await?;
        // After the parent loads, so the scope-chain refusal precedes the
        // probe's own network read.
        if self
            .create_replays_a_publish(&plane, applied.op_id, applied.op.target)
            .await?
        {
            return Err(Halt::Permanent(DeadLetterReason::AlreadyPublished));
        }

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
        let child_name = plane.end.write_name(&child_id.0);
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
                &plane,
                child_id,
                Observed::unread(&child_name),
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
        let authored = applied.op.authored_nodes(Vec::new);
        let modified_at = stamped_modified_at(pass, &applied.op, &authored, parent)?;
        self.publish_folder(scope, pass, parent, modified_at, Some(applied.op_id))
            .await
            .map_err(Halt::from)?;
        // The parent's repaint lifts the child in without what its own record
        // carries; the first edit of this file anchors on the version its
        // create published.
        if let Some(staged) = applied.op.staged_content() {
            project_child_version(
                &mut self.cells.base.borrow_mut(),
                child_id,
                staged.plaintext_size,
                applied.op.authored_at.0,
                1,
                Some(&staged.root_cid),
            );
        } else if let Some(meta) = self.cells.base.borrow_mut().node_mut(child_id) {
            applied.op.stamp_authored(meta);
        }
        // Held only once the parent names it: a record nothing references is
        // not one the liveness loop should keep alive.
        self.hold(child_id.0, published.held);
        Ok(())
    }

    /// Delete: drop the parent's ref, and either bin the node or stop paying
    /// for what the unlink detached (blueprint/engine.md "Delete branch").
    ///
    /// `to_bin` selects the soft branch, which writes one bin entry, re-keys the
    /// doomed subtree into the bin, and reclaims nothing: the record stays
    /// published and the content stays pinned. The re-key is what stops a
    /// current or revoked grantee of the source scope from reading a node the
    /// owner believes is binned. The rest of this block describes the hard
    /// branch.
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
        to_bin: bool,
    ) -> Result<(), Halt> {
        // The soft branch ends on the owner's bin index, a surface of this
        // vault. A grafted pass takes neither branch: a grantee's delete only
        // unlinks, and the owner's engine bins the node by owner capture
        // (CONTEXT.md), so the records and pins stay the owner's to settle.
        if to_bin {
            scope.refuse_vault_surface()?;
        }
        let target = applied.op.target;
        let mut unlink_from = Vec::new();
        let mut named = None;
        for parent in self.published_parents(scope, pass, target)? {
            self.ensure_folder(scope, pass, parent).await?;
            let Some(child) = pass
                .folder(parent)?
                .children
                .iter()
                .find(|child| child.id == target.0)
                .cloned()
            else {
                continue;
            };
            named.get_or_insert(child);
            unlink_from.push(parent);
        }
        let (Some(&origin), Some(child)) = (unlink_from.first(), named) else {
            // A peer can unlink while the authored delete's re-key is unfinished.
            if to_bin {
                self.finish_binned_delete(scope, pass, target).await?;
            }
            return Ok(());
        };

        // The bin entry, the re-key and the doomed manifest belong to the scope
        // the origin link resolved onto: a node joins the scope of the parent
        // that names it.
        let plane = scope.folder_plane(pass, origin)?;

        // The soft branch earns its bin entry and its re-key before the unlink;
        // the hard branch earns its doomed manifest. Both then unlink and
        // republish every parent, which is where the op completes.
        let doomed = if scope.is_grafted() {
            None
        } else if to_bin && names_this_scope(&plane.end, &child) {
            let unlinked = UnlinkedChild {
                scope_id: plane.end.root.0,
                // The highest-ranked link still standing: the folder a reader
                // resolves the node under, and so the one a restore returns it
                // to.
                parent: origin,
                node: target,
                name: child.name.clone(),
                kind: child.kind,
                ipns_name: child.ipns_name.clone(),
                deleted_at: applied.op.authored_at.0,
            };
            let deleted_at = self
                .record_bin_entry(&unlinked, applied.op.authored_at.0)
                .await?;
            self.rekey_into_bin(scope, &plane, pass.anchor_for(&plane)?, target, deleted_at)
                .await?;
            None
        } else {
            Some(
                self.enumerate_doomed(
                    &plane,
                    pass.anchor_for(&plane)?,
                    origin,
                    target,
                    child.kind,
                    Boundary::None,
                )
                .await?,
            )
        };
        // Only the last unlink completes the op. A pass that stops part-way
        // leaves the node binned and still linked, which is the residue the
        // entry-before-unlink order already settles on the retry.
        let count = unlink_from.len();
        let authored = applied.op.authored_nodes(|| unlink_from.clone());
        for (at, parent) in unlink_from.into_iter().enumerate() {
            let modified_at = stamped_modified_at(pass, &applied.op, &authored, parent)?;
            pass.folder_mut(parent)?
                .children
                .retain(|entry| entry.id != target.0);
            self.publish_folder(
                scope,
                pass,
                parent,
                modified_at,
                (at + 1 == count).then_some(applied.op_id),
            )
            .await
            .map_err(Halt::from)?;
        }
        let Some(doomed) = doomed else {
            return Ok(());
        };
        let reclamation = self.owed_by_delete(target, &doomed, None);
        let owner = owner_tag(scope.enc_secret);
        let seal = self.bookkeeping_seal(scope);
        // Keyed by the end the manifest belongs to, which is the end that
        // derives every name in it: a pass carrying that end as its source is
        // the only one that can settle the entry.
        let key = doomed_journal_key(&owner, plane.end.root, target);
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
                    self.cells.orphan_heads.record(&name);
                }
            }
            (false, None) => {}
        }
        Ok(())
    }

    /// A vanished parent link does not discharge the bin entry's access cut.
    async fn finish_binned_delete(
        &self,
        scope: &DrainScope<'_>,
        pass: &Pass,
        target: NodeId,
    ) -> Result<(), Halt> {
        if scope.is_grafted() {
            return Err(Halt::OtherBinScope);
        }
        let Some((entry, plane)) = self.bin_entry(scope, pass, target).await? else {
            return Ok(());
        };
        self.rekey_into_bin(
            scope,
            &plane,
            pass.anchor_for(&plane)?,
            target,
            entry.deleted_at,
        )
        .await
        .map_err(charge_bin_read)
    }

    /// Restore: re-key the subtree out of the bin, relink it, then drop the
    /// entry (ADR 0010 item 4).
    ///
    /// The re-key is what the destination's grantees read the node by again, and
    /// what ends the bin-held key's hold on it: every node of the subtree is
    /// re-sealed at the destination scope's current epoch, which is also the
    /// fresh key an unshared destination gets.
    ///
    /// The entry goes last. A pass that stops between the relink and the drop
    /// leaves a node that is both linked and binned, and the retry settles it;
    /// the reverse order leaves a node no folder names and no entry finds.
    async fn publish_restore(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        rebased: &Snapshot,
        into: NodeId,
    ) -> Result<(), Halt> {
        scope.refuse_vault_surface()?;
        let target = applied.op.target;
        let Some((entry, binned_under)) = self.bin_entry(scope, pass, target).await? else {
            // The entry left with an attempt that got past the drop below.
            return Ok(());
        };
        // A node some folder already links is one an earlier attempt of this op
        // relinked, or another device restored. Only the entry is left.
        if !self.cells.base.borrow().links_to(target).is_empty() {
            return self.drop_bin_entry(target).await;
        }
        let name = Zeroizing::new(applied.effective_name.clone().ok_or(Halt::Unclassified)?);
        let plane = self.ensure_folder(scope, pass, into).await?;
        // A restore re-keys in place: the names and the scope id the AAD binds
        // stay where the delete left them, so a destination in another scope is
        // a re-seal with no pass to author it, exactly as a move between two
        // shared folders is.
        if plane.end.root != binned_under.end.root {
            return Err(Halt::Permanent(DeadLetterReason::CrossingUnauthorable));
        }
        let held = self.inputs.bin_keys.held_key(&target.0, entry.deleted_at);
        let binned = SealPlane {
            end: plane.end.under_held_key(&held),
            ..plane
        };
        self.rekey_subtree(
            scope,
            &binned,
            &plane,
            pass.anchor_for(&binned_under)?,
            target,
        )
        .await
        .map_err(charge_bin_read)?;
        let child = ChildRef {
            id: target.0,
            name: name.to_string(),
            ipns_name: entry.ipns_name.clone(),
            kind: entry.kind,
            link_counter: rebased.max_link_counter(target),
            unknown: PreservedFields::new(),
        };
        let into_children = &mut pass.folder_mut(into)?.children;
        // The base is the focus window's, so a destination that already names
        // the target is reachable — an earlier attempt whose folder publish
        // landed and whose entry drop did not; a second ref would sign a
        // listing `author_child_envelope` rejects, wedging every retry.
        match into_children.iter_mut().find(|child| child.id == target.0) {
            Some(existing) => *existing = child,
            None => into_children.push(child),
        }
        let authored = applied.op.authored_nodes(Vec::new);
        let modified_at = stamped_modified_at(pass, &applied.op, &authored, into)?;
        self.publish_folder(
            scope,
            pass,
            into,
            modified_at,
            // The entry drop below is this plan's last act, not the relink: a
            // mark raised here would drop the op on the next pass and leave the
            // entry standing for a node the vault links again.
            None,
        )
        .await
        .map_err(Halt::from)?;
        self.drop_bin_entry(target).await
    }

    /// Purge: prove the node unlinked, journal what its subtree owes, drop the
    /// entry, then settle (ADR 0010 item 7).
    ///
    /// `deleted_at` is the entry this purge was formed against. An entry stamped
    /// otherwise is one this op never saw, and its subtree is sealed under
    /// another key, so the purge refuses rather than reclaiming the wrong thing.
    ///
    /// The journal lands before the entry does, so a pass that stops between the
    /// two retries over records nothing has retired yet. The entry drop is what
    /// completes the op; the settle replays off the journal on any later pass.
    async fn publish_purge(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        deleted_at: u64,
    ) -> Result<(), Halt> {
        scope.refuse_vault_surface()?;
        let target = applied.op.target;
        let Some((entry, binned_under)) = self.bin_entry(scope, pass, target).await? else {
            return Ok(());
        };
        if entry.deleted_at != deleted_at {
            return Err(Halt::Permanent(DeadLetterReason::TargetGone));
        }
        if !self
            .purge_target_is_unlinked(&binned_under, pass, target, NodeId(entry.origin_parent))
            .await?
        {
            return Err(Halt::Permanent(DeadLetterReason::TargetStillLinked));
        }
        let held = self.inputs.bin_keys.held_key(&target.0, deleted_at);
        let binned = SealPlane {
            end: binned_under.end.under_held_key(&held),
            ..binned_under
        };
        // The walk runs under the held key because that is what seals the whole
        // doomed subtree, and it stops at a scope root, which the bin never
        // re-keyed.
        let doomed = self
            .enumerate_doomed(
                &binned,
                pass.anchor_for(&binned_under)?,
                NodeId(entry.origin_parent),
                target,
                entry.kind,
                Boundary::ScopeRoots(scope.scope_roots),
            )
            .await
            .map_err(charge_bin_read)?;
        let reclamation = self.owed_by_delete(target, &doomed, Some(deleted_at));
        let owner = owner_tag(scope.enc_secret);
        let seal = self.bookkeeping_seal(scope);
        let key = doomed_journal_key(&owner, binned_under.end.root, target);
        // Nothing is reclaimed yet, so the entry is still the whole retry.
        // Dropping it over an unwritten journal would strand the subtree's names
        // and its pins with no durable handle to finish from.
        if !self.journal_doomed(seal, &key, target, &reclamation).await {
            return Err(Halt::Unclassified);
        }
        // Marked before the drop below, so a pass that halts there does not
        // settle the quarantine it has just journaled ([`Settle`]).
        pass.journalled.push(target);
        self.drop_bin_entry(target).await?;
        let residue = self
            .settle_reclamation(scope, seal, &owner, &reclamation, Settle::Hold)
            .await;
        self.update_journal(seal, &key, target, &reclamation, residue)
            .await;
        Ok(())
    }

    /// Whether any link this device knows still names the node.
    ///
    /// The rebase refused a target gate-passing state holds; this is the half
    /// the entry alone cannot supply. A soft delete writes the entry, unlinks,
    /// then republishes the parent, so a parent publish that spent its attempt
    /// budget leaves an entry standing for a node its folder still names.
    ///
    /// Two sources, because neither is complete on its own. The base carries
    /// every link this session rendered, including one from a folder the entry
    /// does not name, and it moves under the pass. The entry's own folder is
    /// read as a record, because the base is populated by the focus window and
    /// absence from it says only that this session never rendered that folder.
    /// A record this pass cannot establish decides nothing, and the read is
    /// charged so a folder that is gone for good dead-letters the purge rather
    /// than holding the queue head.
    async fn purge_target_is_unlinked(
        &self,
        plane: &SealPlane<'_>,
        pass: &Pass,
        target: NodeId,
        origin: NodeId,
    ) -> Result<bool, Halt> {
        // A node can carry a link from a folder other than the one it was
        // binned from, and the entry names only that one. Every link this
        // device knows is checked at the moment of action: the pass republishes
        // folders and repaints the base as it runs, so the rebase's own verdict
        // is already behind by here.
        if !self.cells.base.borrow().links_to(target).is_empty() {
            return Ok(false);
        }
        // The scope root is the record the pass opened on, and it publishes
        // under the scope's own name rather than a derived child name.
        let named = if origin == plane.end.root {
            pass.folder(plane.end.root)
                .map_err(charge_bin_read)?
                .children
                .iter()
                .any(|child| child.id == target.0)
        } else {
            self.load_child_folder(plane, pass.anchor_for(plane)?, origin)
                .await
                .map_err(charge_bin_read)?
                .children
                .iter()
                .any(|child| child.id == target.0)
        };
        Ok(!named)
    }

    /// What the standing bin entry for `node` says, or `None` when the bin holds
    /// no entry for it. The index is resolved fresh: only an established index
    /// may be published over, and both bin op plans publish one before they end.
    ///
    /// The bin is vault-level, so an entry may name a scope this pass does not
    /// hold; that entry waits for its owning pass. A mismatched `ipnsName` is
    /// refused: no bin path may re-key a name this scope's write seed cannot derive.
    async fn bin_entry<'s>(
        &self,
        scope: &DrainScope<'s>,
        pass: &Pass,
        node: NodeId,
    ) -> Result<Option<(BinnedNode, SealPlane<'s>)>, Halt> {
        let index = self.writable_bin_index().await?;
        let Some(entry) = BinnedNode::of(&index, &node.0) else {
            return Ok(None);
        };
        // The entry names the scope its delete resolved onto
        // ([`Self::record_bin_entry`]), so the restore and the purge read that
        // end rather than the one this pass anchors on.
        let entry_root = NodeId(entry.scope_id);
        let plane = scope
            .plane_rooted_at(pass.epoch, entry_root)?
            .ok_or_else(|| {
                if scope.charges_the_identity && scope.keyless_roots.contains(&entry_root) {
                    Halt::UnwritableScope
                } else {
                    Halt::OtherBinScope
                }
            })?;
        if plane.end.write_name(&node.0).as_str().as_bytes() != entry.ipns_name {
            return Err(Halt::Permanent(DeadLetterReason::TargetGone));
        }
        Ok(Some((entry, plane)))
    }

    /// Drop `node`'s bin entry and publish the index.
    ///
    /// The index is re-resolved rather than carried across the re-key and the
    /// publishes above: the record is rewritten whole, so a copy read before
    /// them would drop every entry another device added since.
    async fn drop_bin_entry(&self, node: NodeId) -> Result<(), Halt> {
        let mut index = self.writable_bin_index().await?;
        let before = index.entries.len();
        index.entries.retain(|entry| entry.node_id != node.0);
        if index.entries.len() == before {
            return Ok(());
        }
        self.publish_bin(index).await
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
        self.seams
            .staging
            .put_staged_bytes(key, &entry)
            .await
            .is_ok()
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
                let _ = self.seams.staging.remove_staged_bytes(key).await;
            }
            // A residue the replay would refuse leaves the previous entry
            // standing, which the replay still accepts, rather than an entry
            // nothing can ever settle ([`Reclamation::is_for`]).
            Some(residue) if residue != *previous && residue.is_for(target) => {
                if let Ok(entry) = seal_reclamation(seal, &residue) {
                    let _ = self.seams.staging.put_staged_bytes(key, &entry).await;
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
    /// Bounded twice ([`JournalBudget`]): by this scope's share of the tick's
    /// replay slots, which only a settled entry spends, and by the tick's open
    /// attempts, which every key it reaches spends whether or not the value
    /// opens. Nothing sweeps this prefix, so the open ceiling is what stops a
    /// run of entries this identity cannot read from spending the whole tick;
    /// the resume point is what stops it starving the entries behind them.
    ///
    /// Answers with every node it may have journaled a debt for. Those debts
    /// land after `staged` was taken, so the reclaim pass reading that listing
    /// holds their tombstones rather than sweeping them
    /// ([`drain_owed_retires`]).
    async fn settle_journalled_deletes(
        &self,
        scope: &DrainScope<'_>,
        seal: BookkeepingSeal<'_>,
        owner: &[u8; 32],
        staged: &[Vec<u8>],
        journalled_now: &[NodeId],
        budget: &mut JournalBudget,
    ) -> BTreeSet<[u8; 16]> {
        let mut owed_now = BTreeSet::new();
        // The journal and the retire ledger are the identity's, and every name
        // in them derives from a write seed of this vault's own. A grafted pass
        // settles neither, and spends none of the tick's budget looking.
        if scope.is_grafted() {
            return owed_now;
        }
        let mut mine = budget.replays.share();
        // Another scope's entry is that scope's to settle: its names derive from
        // a write seed this end does not hold, so every verdict here would be a
        // retry against a record this pass never read.
        let mut scoped: Vec<(Vec<u8>, NodeId)> = journalled_keys(owner, staged)
            .into_iter()
            .filter(|(_, scope_root, _)| *scope_root == scope.source.root)
            .map(|(key, _, target)| (key, target))
            .collect();
        if scoped.is_empty() {
            return owed_now;
        }
        // The listing is sorted, so the resume point names the same place on
        // every host; the read wraps, so an unopenable run costs one pass its
        // ceiling rather than starving the entries behind it for good.
        let resume = self
            .cells
            .bookkeeping
            .borrow()
            .journal
            .get(&scope.source.root.0)
            .copied();
        let from = resume.map_or(0, |after| {
            scoped.partition_point(|(_, target)| target.0 <= after)
        });
        let count = scoped.len();
        scoped.rotate_left(from % count);
        for (key, target) in scoped {
            if mine == 0 || budget.opens == 0 {
                break;
            }
            // This pass wrote and settled that entry moments ago, and its
            // quarantine is waiting on the poll tick this pass has not had. It
            // spends no slot either: no work is skipped, only repeated.
            if journalled_now.contains(&target) {
                continue;
            }
            budget.opens -= 1;
            self.cells
                .bookkeeping
                .borrow_mut()
                .journal
                .insert(scope.source.root.0, target.0);
            let Ok(Some(entry)) = self.seams.staging.staged_bytes(&key).await else {
                continue;
            };
            let Some(reclamation) = open_reclamation(seal, &entry).filter(|r| r.is_for(target))
            else {
                continue;
            };
            budget.replays.spend(1);
            mine -= 1;
            let settle = match self.cells.converged_tick.get() {
                true => Settle::Decide(&mut budget.proofs),
                false => Settle::Hold,
            };
            owed_now.extend(reclamation.owed.iter().map(|entry| entry.node));
            owed_now.extend(reclamation.quarantined.iter().map(|held| held.node.0));
            let residue = self
                .settle_reclamation(scope, seal, owner, &reclamation, settle)
                .await;
            self.update_journal(seal, &key, target, &reclamation, residue)
                .await;
        }
        owed_now
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
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        parent: NodeId,
        target: NodeId,
        kind: NodeKind,
        boundary: Boundary<'_>,
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
                .load_child_node(plane, anchor, node, ResolveMode::CacheFirst)
                .await
            {
                Ok(loaded) => {
                    let versions = match loaded.body {
                        ReadBody::Folder { children, .. } => {
                            pending.extend(
                                children
                                    .iter()
                                    .filter(|child| boundary.admits(&plane.end, child))
                                    .map(|child| (NodeId(child.id), child.kind)),
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
                            .cells
                            .base
                            .borrow()
                            .node(node)
                            .is_some_and(|meta| meta.kind == crate::facade::NodeKind::File) =>
                {
                    return Err(halt);
                }
                Err(_) => (plane.end.write_name(&node.0), Vec::new()),
            };
            doomed.push(Doomed {
                node,
                name,
                versions,
            });
        }
        Ok(doomed)
    }

    /// Add one soft-deleted node to the owner's bin index, reporting the
    /// `deletedAt` the index now carries for it.
    ///
    /// A retry over an entry that already landed reports that entry's own value,
    /// never `deleted_at`, because the held key is derived from it: a second
    /// value would re-key the subtree under a key the standing entry does not
    /// name. That is why the entry stands ahead of the re-key on this path: the
    /// queued op is what drives the retry, and the retry has to reach the same
    /// key.
    ///
    /// The index is rewritten whole, so only a load that established the
    /// current index may be written over (blueprint/engine.md "Bin index
    /// record"); every other outcome holds the op for a later tick.
    async fn record_bin_entry(&self, child: &UnlinkedChild, deleted_at: u64) -> Result<u64, Halt> {
        let mut index = self.carried_bin_index().await?;
        // A duplicate node id is a hard reject at encode, so a retry whose
        // entry already landed publishes nothing.
        if let Some(entry) = index
            .entries
            .iter()
            .find(|entry| entry.node_id == child.node.0)
        {
            return Ok(entry.deleted_at);
        }
        index.entries.push(BinEntry::new(
            child.node.0,
            child.ipns_name.clone(),
            child.kind,
            child.parent.0,
            child.name.clone(),
            deleted_at,
            child.scope_id,
            Some(*self.inputs.bin_keys.held_key(&child.node.0, deleted_at)),
        ));
        self.publish_bin(index).await?;
        Ok(deleted_at)
    }

    /// Bind the unlinks the poll leg observed into the owner's bin, and re-key
    /// each node out of the source scope's derivation (ADR 0010 item 5).
    /// Without the re-key, the grantee who unlinked the node keeps its read key.
    /// A capture bins only after [`Self::prove_captures`] proves it.
    ///
    /// The re-key runs **before** the entry, which is the opposite of the
    /// authored delete's order and for the opposite reason: the unlink has
    /// already published, so nothing waits on the entry, and an entry ahead of
    /// the re-key would claim a cut that may never run. A capture whose re-key
    /// or whose index publish does not land stays in the set and is retried,
    /// under the standing entry's timestamp, or its capture stamp if absent.
    ///
    /// The set is empty for a vault at retention `0`: the owner turned the bin
    /// off, and an adoption carries no owner command that could overrule that.
    ///
    /// One index load and one index publish serve the whole pass, and at most
    /// [`MAX_BIN_ADOPTIONS`] captures ride it, so a peer that unlinks a large
    /// folder cannot spend the tick.
    async fn adopt_observed_unlinks<'e>(&self, scope: &DrainScope<'e>, ends: &[ScopeEnd<'e>]) {
        let eligible = self.prune_captures(scope);
        let overflowed = self
            .cells
            .capture_proofs
            .borrow()
            .get(&scope.source.root)
            .is_some_and(|proofs| proofs.overflowed);
        // The bin index and the bin's held key are this vault's own, so binning
        // a node of a granted scope would re-key the sharer's node under a key
        // the sharer never derives. The captures are dropped rather than put
        // back: no pass of this vault will ever adopt them, and the owner's own
        // device bins what it unlinked. An overflowed scope's captures can never
        // be proved ([`MAX_CAPTURE_WALK_NODES`]).
        if scope.is_grafted() || overflowed {
            self.take_captures(scope, &eligible);
            return;
        }
        if eligible.is_empty() {
            self.cells
                .capture_proofs
                .borrow_mut()
                .remove(&scope.source.root);
            return;
        }
        let Ok(root) = self.load_scope_root(&scope.source).await else {
            return;
        };
        let proved = self.prove_captures(scope, ends, &root, eligible).await;
        let taken = self.take_captures(scope, &proved);
        if taken.is_empty() {
            return;
        }
        let Ok(mut index) = self.writable_bin_index().await else {
            self.return_captures(taken);
            return;
        };
        let mut added = Vec::new();
        let mut unfinished = Vec::new();
        for unlinked in taken {
            // A read leg may link the node again while this pass awaits.
            if self.cells.base.borrow().contains(unlinked.node) {
                continue;
            }
            let standing = index
                .entries
                .iter()
                .find(|entry| entry.node_id == unlinked.node.0);
            if standing.is_some_and(|entry| entry.scope_id != unlinked.scope_id) {
                unfinished.push(unlinked);
                continue;
            }
            let deleted_at = standing.map_or(unlinked.deleted_at, |entry| entry.deleted_at);
            if self
                .rekey_into_bin(
                    scope,
                    &scope.source.at(root.epoch),
                    root.anchor(),
                    unlinked.node,
                    deleted_at,
                )
                .await
                .is_err()
            {
                unfinished.push(unlinked);
                continue;
            }
            if standing.is_some() {
                continue;
            }
            index.entries.push(BinEntry::new(
                unlinked.node.0,
                unlinked.ipns_name.clone(),
                unlinked.kind,
                unlinked.parent.0,
                unlinked.name.clone(),
                unlinked.deleted_at,
                unlinked.scope_id,
                Some(
                    *self
                        .inputs
                        .bin_keys
                        .held_key(&unlinked.node.0, unlinked.deleted_at),
                ),
            ));
            added.push(unlinked);
        }
        if !added.is_empty() && self.publish_bin(index).await.is_err() {
            // Re-keyed with no entry to name them: the next pass re-keys to the
            // same key and writes the entries it could not write here.
            unfinished.extend(added);
        }
        self.return_captures(unfinished);
    }

    /// Queue a purge for every entry past the owner's bin retention, so
    /// retention is enforced rather than advisory (ADR 0010 item 6).
    ///
    /// The clock is the scheduler seam's and the verdict rides a journaled op,
    /// so a replay of the queue reproduces the same purge and the same
    /// reclamation. This is also the only thing that frees space in the bin
    /// index, whose body has a frozen ceiling.
    ///
    /// Reads the index rather than writing it, so a degraded load costs a tick
    /// and never an entry.
    async fn expire_bin_entries(&self, scope: &DrainScope<'_>, queued: &[NodeId]) {
        if scope.is_grafted() {
            return;
        }
        let now = self.seams.scheduler.now();
        let Some(cutoff) = bin_expiry_cutoff(now, self.inputs.bin_retention_days) else {
            return;
        };
        let Some(index) = self.expiry_bin_index().await else {
            return;
        };
        let share = self.bin_expiries.borrow().share();
        let expired: Vec<(NodeId, u64)> = {
            let base = self.cells.base.borrow();
            let terminal = self.cells.dead_letters.borrow();
            index
                .entries
                .iter()
                .filter(|entry| entry.deleted_at <= cutoff)
                // Every refusal the publish makes for good, applied here too: an
                // entry the sweep queues on every tick and the pass refuses on
                // every tick is an endless stream of dead letters
                // ([`Self::bin_entry`], `rebase_purge`).
                .filter(|entry| {
                    let node = NodeId(entry.node_id);
                    entry.scope_id == scope.source.root.0
                        && !base.contains(node)
                        && scope.source.write_name(&entry.node_id).as_str().as_bytes()
                            == entry.ipns_name()
                        && !terminal.values().any(|(target, _)| *target == Some(node))
                })
                .map(|entry| (NodeId(entry.node_id), entry.deleted_at))
                .filter(|(node, _)| !queued.contains(node))
                .take(share)
                .collect()
        };
        self.bin_expiries.borrow_mut().spend(expired.len());
        for (node, deleted_at) in expired {
            let Ok(ephemeral_scalar) = fresh_ephemeral(&mut *self.seams.entropy.borrow_mut())
            else {
                return;
            };
            let seal = RecordSeal {
                owner_enc_secret: scope.enc_secret,
                ephemeral_scalar,
            };
            // The base sequence anchors a rebase against the target's own
            // record, and a binned node has no record the snapshot renders.
            let op = Op::purge(node, deleted_at, 1, now);
            let _ = stage_op(&self.seams.staging, seal, &op).await;
        }
    }

    /// The index the expiry sweep decides against: this device's cached copy,
    /// and only on a device that has none does it cost a resolve.
    ///
    /// A cached copy is enough because the sweep decides nothing on its own — it
    /// queues an op, and the publish re-reads the resolved index and refuses an
    /// entry stamped otherwise. Retention is measured in days, so a copy that is
    /// a pass or two behind costs nothing but a pass or two.
    async fn expiry_bin_index(&self) -> Option<BinIndex> {
        if let Some(index) = self.established_bin_index.borrow().clone() {
            return Some(index);
        }
        if let Some(index) =
            cached_bin_index(&self.seams.snapshot_cache, self.inputs.bin_keys).await
        {
            return Some(index);
        }
        let observed = observed_at(self.cells.held, HeldKey::BinIndex);
        match load_bin_index(
            &self.seams.transport,
            &self.seams.gateway,
            &self.seams.http,
            &self.seams.floors,
            &self.seams.snapshot_cache,
            &self.seams.scheduler,
            &self.seams.profile,
            self.inputs.bin_keys,
        )
        .await
        .enrol(self.cells.held, observed)
        {
            BinIndexLoad::Resolved(index) | BinIndexLoad::Stale { index, .. } => Some(index),
            BinIndexLoad::Empty(_) => None,
        }
    }

    /// Drop the captures that can never bin, and answer the keys of the ones
    /// this scope may still bin. A node held twice keeps its first capture.
    ///
    /// A node the base still links did not leave the tree, and binning it would
    /// seal a live node under a key no reader derives. A capture of a scope
    /// root, proved or by its name, drops unbinned ([`in_this_scope`]). A name
    /// longer than this build ever authors is a peer's, and no entry carries it.
    fn prune_captures(&self, scope: &DrainScope<'_>) -> BTreeSet<CaptureKey> {
        let base = self.cells.base.borrow();
        let mut eligible = BTreeSet::new();
        self.cells.observed_unlinks.borrow_mut().retain(|unlinked| {
            // A capture belongs to whichever pass names its scope. One that no
            // listed root names is a capture no pass will ever adopt, and
            // holding it starves the bounded set. A listed scope this tick
            // could not drain keeps its captures for the tick that can, at the
            // cost of a share of that bound.
            if unlinked.scope_id != scope.source.root.0 {
                return scope.scope_roots.contains(&NodeId(unlinked.scope_id));
            }
            if base.contains(unlinked.node)
                || scope.scope_roots.contains(&unlinked.node)
                || names_node(&eligible, unlinked.node)
                || unlinked.name.len() > MAX_NODE_NAME_BYTES
                || scope
                    .source
                    .write_name(&unlinked.node.0)
                    .as_str()
                    .as_bytes()
                    != unlinked.ipns_name
            {
                return false;
            }
            eligible.insert(capture_key(unlinked));
            true
        });
        eligible
    }

    /// Remove and answer this scope's captures under the keys in `keys`.
    fn take_captures(
        &self,
        scope: &DrainScope<'_>,
        keys: &BTreeSet<CaptureKey>,
    ) -> Vec<UnlinkedChild> {
        let mut taken = Vec::new();
        self.cells.observed_unlinks.borrow_mut().retain(|unlinked| {
            if unlinked.scope_id != scope.source.root.0 || !keys.contains(&capture_key(unlinked)) {
                return true;
            }
            taken.push(unlinked.clone());
            false
        });
        taken
    }

    /// Run this pass's share of the scope's capture walk, and answer the
    /// captures proved to have left the tree, at most [`MAX_BIN_ADOPTIONS`].
    ///
    /// The cohort keeps only captures still held, so a walk proves nothing about
    /// a capture the set dropped. A capture some folder names leaves the set
    /// unbinned.
    async fn prove_captures<'e>(
        &self,
        scope: &DrainScope<'e>,
        ends: &[ScopeEnd<'e>],
        root: &LoadedRoot,
        eligible: BTreeSet<CaptureKey>,
    ) -> BTreeSet<CaptureKey> {
        let scope_root = scope.source.root;
        let mut proofs = self
            .cells
            .capture_proofs
            .borrow_mut()
            .remove(&scope_root)
            .unwrap_or_default();
        proofs.proved.retain(|key| eligible.contains(key));
        let unproved: BTreeSet<CaptureKey> = eligible.difference(&proofs.proved).copied().collect();
        let mut walk = proofs.walk.take().and_then(|mut walk| {
            walk.cohort.retain(|key| unproved.contains(key));
            (!walk.cohort.is_empty()).then_some(walk)
        });
        if walk.is_none() && !unproved.is_empty() {
            walk = Some(CaptureWalk::from_vault_root(scope, ends, unproved));
        }
        if let Some(mut walk) = walk {
            match self.step_walk(scope, ends, root, &mut walk).await {
                WalkStep::Unfinished => proofs.walk = Some(walk),
                WalkStep::Restart => {}
                WalkStep::Overflowed => {
                    proofs.overflowed = true;
                    proofs.proved.clear();
                    self.take_captures(scope, &eligible);
                }
                WalkStep::Settled => {
                    let (linked, proved): (BTreeSet<CaptureKey>, BTreeSet<CaptureKey>) = walk
                        .cohort
                        .iter()
                        .partition(|(node, _)| walk.linked.contains(node));
                    self.take_captures(scope, &linked);
                    if !walk.blind {
                        proofs.proved.extend(proved);
                    }
                }
            }
        }
        // A proof is spent once taken, so a capture given back waits for a new
        // walk.
        let ready: BTreeSet<CaptureKey> = std::iter::from_fn(|| proofs.proved.pop_first())
            .take(MAX_BIN_ADOPTIONS)
            .collect();
        self.cells
            .capture_proofs
            .borrow_mut()
            .insert(scope_root, proofs);
        ready
    }

    /// Spend this pass's share of the tick's walk reads on `walk`. `ends` are
    /// the tick's own scope ends, which read every scope the walk enters.
    async fn step_walk<'e>(
        &self,
        scope: &DrainScope<'e>,
        ends: &[ScopeEnd<'e>],
        root: &LoadedRoot,
        walk: &mut CaptureWalk,
    ) -> WalkStep {
        let share = self.capture_reads.borrow().share();
        let mut spent = 0;
        let step = loop {
            // A blind walk proves nothing, so its first pass, which finds every
            // link, is all it needs.
            if walk.pending.is_empty() && (walk.blind || walk.confirmed == walk.read.len()) {
                break WalkStep::Settled;
            }
            if spent == share {
                break WalkStep::Unfinished;
            }
            spent += 1;
            let second = walk.pending.is_empty();
            let (node, at) = match walk.pending.last() {
                Some(next) => *next,
                None => walk.read[walk.confirmed].0,
            };
            let (end, anchor) = if at == scope.source.root {
                (Some(scope.source), Some(root.anchor()))
            } else {
                (
                    ends.iter().find(|end| end.root == at).copied(),
                    walk.anchors.get(&at).map(WalkAnchor::anchor),
                )
            };
            let read = match end {
                Some(end) => self
                    .walk_read(scope, &end, anchor, node)
                    .await
                    .map(|read| (end, read)),
                None => Err(WalkReadFault::Unanswered),
            };
            let (end, read) = match read {
                Ok(read) => read,
                Err(WalkReadFault::Untrusted) => break WalkStep::Restart,
                Err(WalkReadFault::Unanswered) => {
                    walk.unanswered += 1;
                    break if walk.unanswered >= MAX_CAPTURE_READ_ATTEMPTS {
                        WalkStep::Restart
                    } else {
                        WalkStep::Unfinished
                    };
                }
            };
            walk.unanswered = 0;
            if second {
                if read.mark != walk.read[walk.confirmed].1 {
                    break WalkStep::Restart;
                }
                walk.confirmed += 1;
                continue;
            }
            walk.pending.pop();
            walk.read.push(((node, at), read.mark));
            if let Some(anchor) = read.anchor
                && at != scope.source.root
            {
                walk.anchors.insert(at, anchor);
            }
            if !walk.visit(
                &end,
                ends,
                scope.scope_roots,
                &read.children,
                self.capture_walk_nodes,
            ) {
                break WalkStep::Overflowed;
            }
        };
        self.capture_reads.borrow_mut().spend(spent);
        step
    }

    /// One node of the walk, read under `end` through the gate from the record
    /// plane and never from the cache. A node below the root needs the root's
    /// `anchor`. A file body names no children.
    async fn walk_read(
        &self,
        scope: &DrainScope<'_>,
        end: &ScopeEnd<'_>,
        anchor: Option<Anchor<'_>>,
        node: NodeId,
    ) -> Result<WalkRead, WalkReadFault> {
        let fault = |halt: Halt| match halt {
            Halt::RecordRefused => WalkReadFault::Untrusted,
            _ => WalkReadFault::Unanswered,
        };
        if node == end.root {
            let resolved = self
                .gated_scope_root(scope, end, ResolveMode::NoCache)
                .await
                .map_err(fault)?;
            if !resolved.tied.is_empty() {
                return Err(WalkReadFault::Untrusted);
            }
            let record =
                resolved_bytes(resolved, end.root_name, &self.seams.events).map_err(fault)?;
            let root = self
                .open_root_record(Some(scope), end, &record)
                .await
                .map_err(fault)?;
            return Ok(WalkRead {
                mark: RecordMark {
                    sequence: root.state.observed.sequence(),
                    digest: cipherbox_core::suite::hash::hash(&record),
                },
                children: root.state.children,
                anchor: Some(WalkAnchor {
                    epoch: root.epoch,
                    history_links: root.history_links,
                }),
            });
        }
        let anchor = anchor.ok_or(WalkReadFault::Unanswered)?;
        let loaded = self
            .load_child_node(&end.at(anchor.epoch), anchor, node, ResolveMode::NoCache)
            .await
            .map_err(fault)?;
        if loaded.tied {
            return Err(WalkReadFault::Untrusted);
        }
        Ok(WalkRead {
            mark: RecordMark {
                sequence: loaded.observed.sequence(),
                digest: cipherbox_core::suite::hash::hash(&loaded.record),
            },
            children: match loaded.body {
                ReadBody::Folder { children, .. } => children,
                ReadBody::File { .. } => Vec::new(),
            },
            anchor: None,
        })
    }

    /// Put back the captures this pass did not settle, up to the frozen bound
    /// on what one session holds unadopted.
    fn return_captures(&self, unfinished: Vec<UnlinkedChild>) {
        hold_captures(self.cells.observed_unlinks, unfinished);
    }

    /// The current bin index, ready to be written over.
    ///
    /// A fresh load every time: the index is rewritten whole, so a rewrite built
    /// on a copy read before an intervening publish drops that publish's
    /// entries. [`Self::carried_bin_index`] is the one caller that may build on
    /// what the pass already established.
    async fn writable_bin_index(&self) -> Result<BinIndex, Halt> {
        let observed = observed_at(self.cells.held, HeldKey::BinIndex);
        let index = load_bin_index(
            &self.seams.transport,
            &self.seams.gateway,
            &self.seams.http,
            &self.seams.floors,
            &self.seams.snapshot_cache,
            &self.seams.scheduler,
            &self.seams.profile,
            self.inputs.bin_keys,
        )
        .await
        .enrol(self.cells.held, observed)
        .writable()
        .map_err(|reason| {
            let halt = halt_for_bin_load(reason);
            if halt == Halt::Attempt {
                emit_trust_violation(
                    &self.seams.events,
                    self.inputs.bin_keys.name().as_str(),
                    format!("bin index refused: {reason:?}"),
                );
            }
            halt
        })?;
        self.establish_bin_index(index.clone());
        Ok(index)
    }

    /// The bin index a further entry may be appended to: the one this pass
    /// established, or a fresh load.
    ///
    /// Only the entry the soft delete writes builds on the carried copy, which
    /// is what makes a bulk soft delete cost one resolve rather than one per
    /// node (blueprint/engine.md "Bin index record"). The entry an op *removes*
    /// runs after a re-key and several publishes, so it resolves again.
    async fn carried_bin_index(&self) -> Result<BinIndex, Halt> {
        if let Some(index) = self.established_bin_index.borrow().clone() {
            return Ok(index);
        }
        self.writable_bin_index().await
    }

    /// Record the index a further entry may be appended to, and let go of the
    /// hold a refused load took.
    fn establish_bin_index(&self, index: BinIndex) {
        *self.established_bin_index.borrow_mut() = Some(index);
        // The load is the hold's own probe, so an index this pass established
        // is the exit whichever pass of the tick took the hold.
        if matches!(
            self.cells.hold.borrow().map(|hold| hold.reason),
            Some(QueueHoldReason::BinIndex(_))
        ) {
            self.release_hold();
        }
    }

    /// Publish the bin index and hold the confirmed record for renewal.
    async fn publish_bin(&self, index: BinIndex) -> Result<(), Halt> {
        // A publish that does not confirm leaves the standing index unknown, so
        // the next rewrite resolves rather than building on this attempt.
        *self.established_bin_index.borrow_mut() = None;
        let mut mirror = core::mem::take(&mut self.mirror.borrow_mut().leg);
        let held = publish_bin_index_placed(
            &self.seams.transport,
            &self.seams.api,
            &self.seams.floors,
            &self.seams.snapshot_cache,
            &self.seams.scheduler,
            &self.seams.profile,
            &mut SharedEntropy(&self.seams.entropy),
            self.cells.orphan_heads,
            self.inputs.bin_keys,
            &index,
            self.head_placement(),
            &mut mirror,
        )
        .await;
        self.mirror.borrow_mut().leg = mirror;
        let held = held.map_err(|error| halt_for_bin_publish(&error))?;
        self.cells.held.borrow_mut().insert(HeldKey::BinIndex, held);
        // The confirm re-resolved this session's own bytes at its own sequence,
        // so the published entries are the standing index.
        self.establish_bin_index(index);
        Ok(())
    }

    /// Re-seal the doomed subtree under the bin's held key, which is the access
    /// cut a soft delete owes (ADR 0010 item 3).
    async fn rekey_into_bin(
        &self,
        scope: &DrainScope<'_>,
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        root: NodeId,
        deleted_at: u64,
    ) -> Result<(), Halt> {
        let held = self.inputs.bin_keys.held_key(&root.0, deleted_at);
        let binned = SealPlane {
            end: plane.end.under_held_key(&held),
            ..*plane
        };
        self.rekey_subtree(scope, plane, &binned, anchor, root)
            .await
    }

    /// Re-seal every node of the subtree at `root` from the key `from` derives
    /// to the key `to` derives. Names, signers and the scope id the AAD binds do
    /// not move, so the bin entry's `ipnsName` stays the route back to the node.
    ///
    /// The whole subtree is re-keyed in this pass, not left to the lazy wave: a
    /// binned node takes no ordinary write, so nothing would ever carry it.
    ///
    /// A descendant that is a scope root is a boundary, not a member. Its
    /// subtree is sealed under its own scope's seed, which no grantee of the
    /// source scope holds, and cutting that scope's grantees is a rotation.
    ///
    /// Every failure returns before the caller publishes the link it is about
    /// to move, so a subtree this pass could not re-key stays as it was.
    async fn rekey_subtree(
        &self,
        scope: &DrainScope<'_>,
        from: &SealPlane<'_>,
        to: &SealPlane<'_>,
        anchor: Anchor<'_>,
        root: NodeId,
    ) -> Result<(), Halt> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            // Child refs are wire data, so a diamond or a cycle among them is
            // reachable; a node already walked terminates the walk.
            if !seen.insert(node.0) {
                continue;
            }
            let (loaded, already_moved) = self.load_doomed(from, to, anchor, node).await?;
            let LoadedNode {
                observed,
                envelope_unknown,
                epoch_tag_unknown,
                body,
                ..
            } = loaded;
            let content_cids = match &body {
                ReadBody::Folder { children, .. } => {
                    pending.extend(
                        children
                            .iter()
                            .filter(|child| in_this_scope(&from.end, scope.scope_roots, child))
                            .map(|child| NodeId(child.id)),
                    );
                    Vec::new()
                }
                // Every retained version stays registered under this name, so
                // the re-key never drops a pin the node still needs.
                ReadBody::File { versions, .. } => versions
                    .iter()
                    .map(|version| {
                        checked_content_cid(&version.content_cid).map(encode_content_cid_str)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            };
            if already_moved {
                continue;
            }
            let published = self
                .publish_node(
                    scope,
                    to,
                    node,
                    observed,
                    false,
                    &body,
                    content_cids,
                    envelope_unknown,
                    epoch_tag_unknown,
                    None,
                )
                .await
                .map_err(Halt::from)?;
            self.hold(node.0, published.held);
        }
        Ok(())
    }

    /// Load a doomed node under whichever key seals it now, reporting whether
    /// that was already the key the re-key is moving it to. A pass that stopped
    /// part-way leaves a subtree holding both, and the retry has to read both.
    async fn load_doomed(
        &self,
        from: &SealPlane<'_>,
        to: &SealPlane<'_>,
        anchor: Anchor<'_>,
        node: NodeId,
    ) -> Result<(LoadedNode, bool), Halt> {
        match self
            .load_child_node(from, anchor, node, ResolveMode::CacheFirst)
            .await
        {
            Ok(loaded) => Ok((loaded, false)),
            Err(halt) => self
                .load_child_node(to, anchor, node, ResolveMode::CacheFirst)
                .await
                .map(|loaded| (loaded, true))
                .map_err(|_| halt),
        }
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
    fn owed_by_delete(
        &self,
        target: NodeId,
        doomed: &[Doomed],
        binned_at: Option<u64>,
    ) -> Reclamation {
        let unlinked = self.cells.base.borrow().links_to(target).is_empty();
        let mut reclamation = Reclamation {
            binned_at,
            ..Reclamation::default()
        };
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
                    OwedRetire::whole(
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
            Settle::Decide(budget) => self.prove_quarantine(scope, reclamation, budget).await,
        };
        let mut owed = reclamation.owed.clone();
        owed.extend(proven.iter().flat_map(|entry| entry.owed.iter().cloned()));
        if !owed.is_empty() && !self.journal_debt(seal, owner, &owed).await {
            // Leaving the bytes pinned is the lawful side of this failure: the
            // unlink is already live, and an unpin the ledger never recorded is
            // one nothing can account for. The quarantine goes back whole, so a
            // descendant this pass proved is proved again rather than lost.
            return Some(reclamation.clone());
        }
        let mut doomed = reclamation.doomed.clone();
        doomed.extend(proven.into_iter().map(|entry| (entry.node, entry.name)));
        let names: Vec<String> = doomed.iter().map(|(_, name)| name.clone()).collect();
        let retired = retire(&self.seams.api, &names).await.is_ok();
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
            let mut held = self.cells.held.borrow_mut();
            let mut base = self.cells.base.borrow_mut();
            let mut forget = |node: NodeId| {
                held.remove(&HeldKey::Node(node.0));
                // A scope root's node id is its scope id, so a reclaimed root
                // also owns the pointer entry under those bytes; a non-root id
                // matches nothing in that plane.
                held.remove(&HeldKey::ScopePointer(node.0));
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
                binned_at: reclamation.binned_at,
            }),
            (false, _) => Some(Reclamation {
                doomed,
                owed: Vec::new(),
                quarantined: held_over,
                binned_at: reclamation.binned_at,
            }),
        }
    }

    /// Journal `owed` against the retire ledger, tombstoning every owing node
    /// first. These nodes are retired by construction — the unlink that detached
    /// them is already live — and a debt whose node reads as published waits on
    /// a record the delete retired out from under it. Answers whether both
    /// halves landed; the tombstone leads, so the pair can only fail toward a
    /// classification with no debt behind it yet.
    async fn journal_debt(
        &self,
        seal: BookkeepingSeal<'_>,
        owner: &[u8; 32],
        owed: &[OwedRetire],
    ) -> bool {
        let ledger = StagingRetireLedger::new(&self.seams.staging, seal);
        let nodes: BTreeSet<[u8; 16]> = owed.iter().map(|entry| entry.node).collect();
        for node in nodes {
            if ledger.tombstone(owner, node).await.is_err() {
                return false;
            }
        }
        ledger.owe(owner, owed).await.is_ok()
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
        reclamation: &Reclamation,
        budget: &mut usize,
    ) -> (Vec<Quarantined>, Vec<Quarantined>) {
        let quarantined = &reclamation.quarantined;
        if quarantined.is_empty() {
            return (Vec::new(), Vec::new());
        }
        // One root read serves every proof this entry spends. A root this pass
        // cannot establish decides nothing: the whole quarantine waits rather
        // than settling against an epoch this pass never read. The root is the
        // scope's own record whatever the entry holds, so it is read under the
        // scope key even for a purge.
        let Ok(root) = self.load_scope_root(&scope.source).await else {
            return (Vec::new(), quarantined.to_vec());
        };
        // A purge's descendants left the scope's derivation at the delete that
        // binned them, so the bin-held key is the only one that opens them.
        let held = reclamation
            .binned_at
            .zip(reclamation.doomed.first())
            .map(|(deleted_at, (target, _))| self.inputs.bin_keys.held_key(&target.0, deleted_at));
        let plane = scope.source.at(root.epoch);
        let sealed_under = held.as_ref().map_or(plane, |held| SealPlane {
            end: scope.source.under_held_key(held),
            ..plane
        });
        let mut proven = Vec::new();
        let mut held_over = Vec::new();
        for entry in quarantined {
            let verdict = if self.cells.base.borrow().contains(entry.node) {
                // Decided off local state alone, so a surviving namer this
                // device renders spends no proof. A link that is merely stale is
                // why it retries rather than refuses outright.
                Verdict::Retry
            } else if entry.name != sealed_under.end.write_name(&entry.node.0).as_str() {
                // The entry was authored under the plane its delete resolved
                // onto, and one settle carries one end. Deciding a name this end
                // does not derive would prove the retire against a record of
                // another scope. Retried rather than held: an entry no settle
                // can name would otherwise stand in the journal for good and
                // spend a replay slot on every tick.
                Verdict::Retry
            } else if *budget == 0 {
                // The budget bounds the resolves one pass spends, never the
                // entry: one it does not reach waits with its attempts intact.
                held_over.push(entry.clone());
                continue;
            } else {
                *budget -= 1;
                self.decide_quarantined(&sealed_under, root.anchor(), entry)
                    .await
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
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        entry: &Quarantined,
    ) -> Verdict {
        let resolved = self.resolved_version_roots(plane, anchor, entry.node).await;
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
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        node: NodeId,
    ) -> Option<BTreeSet<String>> {
        let loaded = self
            .load_child_node(plane, anchor, node, ResolveMode::NoCache)
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
            crossing,
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
        if dest == target || self.cells.base.borrow().ancestors(dest).contains(&target) {
            return Err(Halt::Unclassified);
        }
        // A crossing this pass carries no second end for is one it cannot
        // author, and the chain walk below would stall uncharged on the scope
        // root it cannot load. Charged by the pass holding the tick's
        // identity-wide charge, so a member watching a move that will never
        // publish reads a dead letter rather than a fresh vault; every other
        // pass leaves the op where it is, as it does for an op below another
        // pass's scope root (halt_below_another_scope_root).
        if !matches!(crossing, ScopeCrossing::Intra) && scope.second_end()?.is_none() {
            return Err(if scope.charges_the_identity {
                Halt::UploadAttempt
            } else {
                Halt::Unclassified
            });
        }
        let source_plane = self.ensure_folder(scope, pass, source).await?;
        let dest_plane = self.ensure_folder(scope, pass, dest).await?;
        // The two planes this pass resolved decide, not the crossing the command
        // journaled: a grant minted between the two turns a relocation journaled
        // intra-scope into one that leaves a scope somebody now reads, and
        // publishing it as a plain ref move would carry the subtree out still
        // sealed where that grantee opens it.
        let crosses = source_plane.end.root != dest_plane.end.root;
        if crosses {
            self.hold_an_owed_move(target)?;
        }

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
        // Referent before reference here too: the moved subtree publishes into
        // the destination scope before the ref that names it does.
        let resealed = if crosses {
            let resealed = self
                .reseal_into(scope, pass, &source_plane, &dest_plane, target)
                .await?;
            moved.repoint(dest_plane.end.write_name(&target.0).as_str().as_bytes());
            resealed
        } else {
            // A crossing whose two ends this pass resolves onto one scope is
            // one this pass cannot author. Charged: no later read changes the
            // pair of ends this build assembled.
            if !matches!(crossing, ScopeCrossing::Intra) {
                return Err(Halt::UploadAttempt);
            }
            Resealed::default()
        };
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
        // `source` is the base's winning parent, the one parent a rename or a
        // relocation stamps.
        let authored = applied.op.authored_nodes(|| vec![source]);
        let modified_at = stamped_modified_at(pass, &applied.op, &authored, dest)?;
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
            self.commit_crossing(scope, &source_plane, resealed).await;
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
        let source_modified_at = stamped_modified_at(pass, &applied.op, &authored, source)?;
        if let Err(failure) = self
            .publish_folder(scope, pass, source, source_modified_at, Some(applied.op_id))
            .await
        {
            // A confirmed source-remove is the move complete on the network, so
            // undoing the dest-add would strip the child from the only parent
            // that still names it. The compensation decides that by re-reading
            // the source, which this very publish left stale in the cache; the
            // publish itself already knows. Its published-op mark is raised,
            // so the next pass drops the op: what the re-seal published commits
            // here or never.
            if failure.confirmed {
                self.commit_crossing(scope, &source_plane, resealed).await;
                return Err(failure.halt);
            }
            let undone = self
                .compensate_dest_add(
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
                .await;
            // Whether the undo landed or not: nothing this pass leaves behind
            // references what the re-seal published, and its records keep the
            // source end's holds, so they are unrenewed. Standing their names
            // down is what keeps a rolled-back crossing from leaving the
            // subtree live under a scope the move did not reach.
            self.retire_names(&resealed.published);
            undone?;
            return Err(failure.halt);
        }
        // Last, and only here: the source-remove is what makes the subtree's
        // old records unreferenced, and retiring a name a live ref still points
        // at would leave that reference outliving its referent.
        self.commit_crossing(scope, &source_plane, resealed).await;
        Ok(())
    }

    /// Hold a crossing that carries a folder whose interior move is owed, at
    /// `target` or under it, until the move lands.
    fn hold_an_owed_move(&self, target: NodeId) -> Result<(), Halt> {
        let Some(owed_moves) = self.inputs.owed_moves else {
            return Err(Halt::Unclassified);
        };
        let base = self.cells.base.borrow();
        if owed_moves
            .iter()
            .any(|scope| *scope == target || base.is_descendant_of(*scope, target))
        {
            return Err(Halt::OwedMove);
        }
        Ok(())
    }

    /// Commit what a crossing re-sealed: the destination records take over the
    /// live set, the source names stand down, and a source scope somebody reads
    /// is owed a cut.
    ///
    /// The exit trigger is derived from the plane the pass proved, not from the
    /// crossing the command journaled: an interior scope root exists only
    /// because a grant cut one (CONTEXT.md "Scope"), so a move that leaves one
    /// owes it a rotation whatever the op says.
    async fn commit_crossing(
        &self,
        scope: &DrainScope<'_>,
        source_plane: &SealPlane<'_>,
        resealed: Resealed,
    ) {
        for (node_id, held) in resealed.held {
            self.hold(node_id, held);
        }
        self.retire_names(&resealed.vacated);
        // The plane pair is the evidence, not what this pass happened to
        // publish: a resume whose re-seal an earlier pass already landed
        // publishes nothing and owes the cut all the same.
        if source_plane.end.root != scope.source.root {
            self.owe_scope_exit(scope, source_plane.end.root).await;
        }
    }

    /// Stand down names a crossing left unreferenced. They go through the
    /// session's orphan set rather than a direct retire: the publish this
    /// follows is already durable, so a refused retire is a name to send again
    /// on a later pass, never a reason to fail an op nothing can undo.
    fn retire_names(&self, names: &[IpnsName]) {
        for name in names {
            self.cells.orphan_heads.record(name.as_str());
        }
    }

    /// Take on the cut a move out of `scope_root` owes ([`owe_cut`]).
    async fn owe_scope_exit(&self, scope: &DrainScope<'_>, scope_root: NodeId) {
        owe_cut(
            &self.seams.staging,
            self.bookkeeping_seal(scope),
            scope.enc_secret,
            self.cells.pending_scope_exits,
            scope_root,
        )
        .await;
    }

    /// Re-seal the subtree at `target` out of `source` and into `dest`.
    ///
    /// A cross-scope relocation re-seals the moved subtree at the destination
    /// scope's epoch (blueprint/engine.md "Sync core: Ops"). Every node
    /// therefore publishes again under the destination end's read key, scope id
    /// and epoch, at the name that end's write seed derives, with each folder's
    /// child refs repointed onto their own new names.
    ///
    /// What this cuts is **future** reads through the record plane. A grantee of
    /// the source scope who already opened a node keeps its inline content key
    /// and its content address (CONTEXT.md "Content key"), and where the two
    /// ends derive different names the record at the old one stays resolvable
    /// until its EOL lapses.
    ///
    /// Fail-closed on every node, where the delete walk is best-effort per file:
    /// a node this pass cannot read under either end is one it cannot re-seal,
    /// and a half-sealed subtree strands records under a scope the destination's
    /// readers never look in. Charged, because an uncharged refusal here would
    /// hold the queue head with nothing reported.
    async fn reseal_into(
        &self,
        scope: &DrainScope<'_>,
        pass: &Pass,
        source: &SealPlane<'_>,
        dest: &SealPlane<'_>,
        target: NodeId,
    ) -> Result<Resealed, Halt> {
        let (source_anchor, dest_anchor) = (pass.anchor_for(source)?, pass.anchor_for(dest)?);
        let mut loaded: BTreeMap<[u8; 16], LoadedNode> = BTreeMap::new();
        // Post-order, so a node publishes only after every node it names has —
        // which reverse discovery order does not give for a child two parents of
        // the subtree both name.
        let mut order: Vec<NodeId> = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![(target, false)];
        while let Some((node, expanded)) = stack.pop() {
            if expanded {
                order.push(node);
                continue;
            }
            // Child refs are wire data, so a diamond or a cycle among them is
            // reachable: a node already walked is never walked again, which is
            // also what terminates the walk.
            if !seen.insert(node.0) {
                continue;
            }
            crossing_may_reseal(
                &self.cells.base.borrow(),
                scope.scope_roots,
                source,
                dest,
                target,
                node,
            )?;
            let Some(node_body) = self
                .load_for_reseal(source, source_anchor, dest, dest_anchor, node)
                .await?
            else {
                // Already sealed into the destination by a pass that did not get
                // to finish. Its own refs are repointed, so the walk carries on
                // through them without publishing this node again.
                continue;
            };
            stack.push((node, true));
            if let ReadBody::Folder { children, .. } = &node_body.body {
                stack.extend(children.iter().map(|child| (NodeId(child.id), false)));
            }
            loaded.insert(node.0, node_body);
        }

        let mut resealed = Resealed::default();
        for node in order {
            let Some(node_loaded) = loaded.remove(&node.0) else {
                continue;
            };
            let mut body = node_loaded.body;
            if let ReadBody::Folder { children, .. } = &mut body {
                for child in children.iter_mut() {
                    child.repoint(dest.end.write_name(&child.id).as_str().as_bytes());
                }
            }
            // The same list the record's own history names, so a sub-EOL
            // renewal at the new name re-pins exactly what it points at.
            let content_cids = match &body {
                ReadBody::File { versions, .. } => versions
                    .iter()
                    .map(|version| {
                        checked_content_cid(&version.content_cid).map(encode_content_cid_str)
                    })
                    .collect::<Result<Vec<_>, Halt>>()?,
                ReadBody::Folder { .. } => Vec::new(),
            };
            let name = dest.end.write_name(&node.0);
            // Where both ends derive one name, the gated load is the basis, so
            // a write that lands after it loses this publish its CAS race.
            let observed = if node_loaded.name == name {
                node_loaded.observed
            } else {
                self.destination_observed(&name).await?
            };
            let published = self
                .publish_node(
                    scope,
                    dest,
                    node,
                    observed,
                    false,
                    &body,
                    content_cids,
                    node_loaded.envelope_unknown,
                    node_loaded.epoch_tag_unknown,
                    None,
                )
                .await
                .map_err(Halt::from)?;
            // Two ends sharing one write scope seed derive one name, and the
            // record just published holds it.
            if node_loaded.name != name {
                resealed.vacated.push(node_loaded.name);
            }
            resealed.published.push(name);
            resealed.held.push((node.0, published.held));
        }
        Ok(resealed)
    }

    /// What `name`, a name the crossing moves a node to, serves now: the basis
    /// the publish there signs above. Record-verified only, because the name can
    /// hold a record another scope sealed, which no gate of the destination end
    /// opens.
    async fn destination_observed(&self, name: &IpnsName) -> Result<Observed, Halt> {
        match fanout_get_classified(&self.seams.transport, name).await {
            FanoutRecord::Found(record, _) => Ok(Observed::record(name, record.sequence)),
            FanoutRecord::Absent => Ok(Observed::unread(name)),
            FanoutRecord::Unavailable(_) => Err(Halt::Unclassified),
        }
    }

    /// One node of the moved subtree, opened under the end it still belongs to.
    ///
    /// `None` means the node is already sealed into the destination: a pass that
    /// published it and then failed before the ref moved leaves exactly that,
    /// and re-reading it under the source end would be a scope transplant its
    /// own gate refuses. Answering the resume this way is what keeps the
    /// crossing idempotent instead of wedging on its own half-done work.
    async fn load_for_reseal(
        &self,
        source: &SealPlane<'_>,
        source_anchor: Anchor<'_>,
        dest: &SealPlane<'_>,
        dest_anchor: Anchor<'_>,
        node: NodeId,
    ) -> Result<Option<LoadedNode>, Halt> {
        match self
            .load_child_node(source, source_anchor, node, ResolveMode::CacheFirst)
            .await
        {
            Ok(loaded) => Ok(Some(loaded)),
            Err(halt) => {
                if self
                    .load_child_node(dest, dest_anchor, node, ResolveMode::CacheFirst)
                    .await
                    .is_ok()
                {
                    return Ok(None);
                }
                Err(charge_crossing_read(halt))
            }
        }
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
        fanout_get_verify(&self.seams.transport, name)
            .await
            .map(|(verified, _)| verified.sequence)
            .ok_or(Halt::Unclassified)
    }

    /// Re-read a folder from the record plane, replacing this pass's copy.
    ///
    /// A scope root is otherwise read from the snapshot cache, which is this
    /// device's own — a compensation that read it there could never see the
    /// concurrent writer it exists to yield to — so a root is re-resolved
    /// through its own gate first. A rotation landing mid-pass moves that
    /// root's epoch off the one this pass seals at, which
    /// [`Self::open_scope_root`] refuses.
    async fn reload_folder(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        folder: NodeId,
    ) -> Result<(), Halt> {
        let plane = scope.folder_plane(pass, folder)?;
        let state = if folder == plane.end.root {
            self.open_scope_root(scope, pass, &plane).await?
        } else {
            self.load_child_folder(&plane, pass.anchor_for(&plane)?, folder)
                .await?
        };
        self.repaint_folder(
            scope,
            folder,
            &state.children,
            state.observed.sequence(),
            state.modified_at,
        );
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
        let plane = self
            .ensure_folder(scope, pass, self.published_parent(target)?)
            .await?;
        // The conditional-edit rule against the live record, which the rebase's
        // snapshot can be stale about — first before spending an upload on an
        // edit that cannot land, then again with the upload behind us, because
        // the transfer is the widest window a version can land in unseen.
        let seen = self
            .load_child_node(
                &plane,
                pass.anchor_for(&plane)?,
                target,
                ResolveMode::CacheFirst,
            )
            .await?;
        if head_version_cid(&seen.body) != base_version_cid {
            return Err(Halt::Permanent(DeadLetterReason::BaseSuperseded));
        }
        let uploaded = self.upload_version(scope, applied, staged).await?;
        let loaded = self
            .load_child_node(
                &plane,
                pass.anchor_for(&plane)?,
                target,
                ResolveMode::CacheFirst,
            )
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
        // Newest first, head is current (`crates/core/src/seal/body.rs`).
        versions.insert(0, uploaded.version);
        // The retention rule applies where history grows (blueprint/engine.md
        // "Content plane"), so a vault keeping the newest N never accretes an
        // (N+1)th version even for the moment between a write and a prune.
        //
        // A history this build refuses to shorten publishes whole: the member's
        // own write is not the place to fail on a version list a co-writer
        // authored, and leaving history long retires nothing.
        if let RetentionPolicy::KeepLatest(keep_latest) = self.inputs.retention
            && let Err(halt) = self
                .shorten_history(scope, target, &mut versions, keep_latest)
                .await
            && !matches!(halt, Halt::Permanent(_))
        {
            return Err(halt);
        }
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
                &plane,
                target,
                loaded.observed,
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
            &mut self.cells.base.borrow_mut(),
            target,
            plaintext_size,
            modified_at,
            version_count,
            Some(head_cid),
        );
        if let Some(node) = self.cells.base.borrow_mut().node_mut(target) {
            node.record_sequence = published.observed.sequence();
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
    /// names ([`Self::live_owing_record`]) — an entry whose publish never lands
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
        let plane = self
            .ensure_folder(scope, pass, self.published_parent(target)?)
            .await?;
        let loaded = self
            .load_child_node(
                &plane,
                pass.anchor_for(&plane)?,
                target,
                ResolveMode::CacheFirst,
            )
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
        let head = versions.first().ok_or(Halt::Unclassified)?;
        let (head_size, head_cid) = (head.size, head.content_cid.clone());
        let survivors = self
            .shorten_history(scope, target, &mut versions, keep_latest)
            .await?;
        let Some(survivors) = survivors else {
            return Ok(());
        };
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
                &plane,
                target,
                loaded.observed,
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

    /// Shorten `versions` to the newest `keep_latest` and journal what the drop
    /// owes the registry. Returns the survivors, or `None` when the history was
    /// already inside the rule and the caller has nothing to shorten.
    ///
    /// The journal precedes the caller's publish for the reason
    /// [`Self::publish_prune`] states, and the caller must not publish a
    /// shortened history if this returns an error.
    async fn shorten_history(
        &self,
        scope: &DrainScope<'_>,
        target: NodeId,
        versions: &mut Vec<Version>,
        keep_latest: NonZeroU64,
    ) -> Result<Option<Vec<ContentVersion>>, Halt> {
        let history = self.pinned_history(versions)?;
        let plan = plan_prune(&history, keep_latest);
        if plan.retire_targets.is_empty() {
            return Ok(None);
        }
        // The plan named a suffix of the history, so the survivors are its
        // prefix — one count, never a second clamp that could disagree.
        let survivors = history[..history.len() - plan.retire_targets.len()].to_vec();
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
        self.journal_retire_debt(scope, target, &plan.retire_targets)
            .await?;
        versions.truncate(survivors.len());
        Ok(Some(survivors))
    }

    /// Hold what `doomed` owes the registry on the retire ledger.
    ///
    /// Ahead of the caller's publish: a debt this pass cannot compute must leave
    /// the history it was read from standing, not a shortened one it never
    /// journaled.
    async fn journal_retire_debt(
        &self,
        scope: &DrainScope<'_>,
        target: NodeId,
        doomed: &[ContentVersion],
    ) -> Result<(), Halt> {
        scope.refuse_vault_surface()?;
        let owed = self.prune_debt(target, doomed).await?;
        StagingRetireLedger::new(&self.seams.staging, self.bookkeeping_seal(scope))
            .owe(&owner_tag(scope.enc_secret), &owed)
            .await
            .map_err(seam)
    }

    /// `restoreVersion`: put one prior version back at the head and republish.
    ///
    /// A reorder of the sealed history, not an upload — every retained version's
    /// root stays registered under this record the whole time, so the restore
    /// moves no byte and retires none. The record's `modified_at` follows the
    /// head it establishes: no byte changed, so the restored version's own stamp
    /// is the only modification time there is.
    async fn publish_restore_version(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        content_cid: &[u8],
    ) -> Result<(), Halt> {
        let (plane, loaded) = self.open_file_record(scope, pass, applied).await?;
        let target = applied.op.target;
        let ReadBody::File {
            created_at,
            mut versions,
            unknown,
            ..
        } = loaded.body
        else {
            return Err(Halt::Unclassified);
        };
        let at = version_index(&versions, content_cid)?;
        // Already current: this restore landed, or a concurrent writer put the
        // same version back first.
        if at == 0 {
            return Ok(());
        }
        // A rotate rather than a remove-and-insert, so no version's content key
        // is moved out of the list it is owned by.
        versions[..=at].rotate_right(1);
        let head = versions.first().ok_or(Halt::Unclassified)?;
        let (head_size, head_cid, modified_at) =
            (head.size, head.content_cid.clone(), head.modified_at);
        let content_cids = self
            .pinned_history(&versions)?
            .into_iter()
            .map(|version| version.content_cid)
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
                &plane,
                target,
                loaded.observed,
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

    /// `deleteVersion`: drop one prior version from the history, journal what it
    /// owes the registry, and republish the shortened record.
    ///
    /// The head is never a target: a file's current content leaves with the
    /// file, never through its history.
    async fn publish_delete_version(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        content_cid: &[u8],
    ) -> Result<(), Halt> {
        let (plane, loaded) = self.open_file_record(scope, pass, applied).await?;
        let target = applied.op.target;
        let ReadBody::File {
            created_at,
            modified_at,
            mut versions,
            unknown,
        } = loaded.body
        else {
            return Err(Halt::Unclassified);
        };
        let at = version_index(&versions, content_cid)?;
        // The named version became the file's current content under this op, so
        // the history this op was formed against is gone.
        if at == 0 {
            return Err(Halt::Permanent(DeadLetterReason::BaseSuperseded));
        }
        let history = self.pinned_history(&versions)?;
        let doomed = history[at].clone();
        // Same rule as [`Self::shorten_history`]: a root a surviving version
        // still names must not be retired.
        if history
            .iter()
            .enumerate()
            .any(|(index, version)| index != at && version.content_cid == doomed.content_cid)
        {
            return Err(Halt::Permanent(DeadLetterReason::PayloadRefused));
        }
        self.journal_retire_debt(scope, target, core::slice::from_ref(&doomed))
            .await?;
        let head = versions.first().ok_or(Halt::Unclassified)?;
        let (head_size, head_cid) = (head.size, head.content_cid.clone());
        versions.remove(at);
        let content_cids = self
            .pinned_history(&versions)?
            .into_iter()
            .map(|version| version.content_cid)
            .collect();
        let version_count = versions.len() as u64;
        // A delete removes history; it does not modify the file, so the record's
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
                &plane,
                target,
                loaded.observed,
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

    /// Load the file record a history edit rewrites, with the plane it publishes
    /// under. A resolution that also needs a parent-side write has no plan here,
    /// the same rule every one-record publish gets.
    async fn open_file_record<'s>(
        &self,
        scope: &DrainScope<'s>,
        pass: &mut Pass,
        applied: &AppliedOp,
    ) -> Result<(SealPlane<'s>, LoadedNode), Halt> {
        if applied.effective_name.is_some() {
            return Err(Halt::Unclassified);
        }
        let target = applied.op.target;
        let plane = self
            .ensure_folder(scope, pass, self.published_parent(target)?)
            .await?;
        let loaded = self
            .load_child_node(
                &plane,
                pass.anchor_for(&plane)?,
                target,
                ResolveMode::CacheFirst,
            )
            .await?;
        Ok((plane, loaded))
    }

    /// A published history as [`ContentVersion`]s, newest first.
    fn pinned_history(&self, versions: &[Version]) -> Result<Vec<ContentVersion>, Halt> {
        versions
            .iter()
            .map(|version| {
                let content_cid =
                    encode_content_cid_str(checked_content_cid(&version.content_cid)?);
                ContentVersion::from_plaintext_size(
                    content_cid,
                    version.size,
                    &self.seams.content_profile,
                )
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
    /// ([`Self::live_owing_record`]), so the figure here is the ceiling a pass
    /// that cannot re-expand falls back on ([`OwedRetire::owed_bytes`]). It is
    /// quoted once per CID — a leaf two doomed roots both name is one pin row,
    /// and quoting it twice would over-report pending reclaim.
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
                target: version.content_cid.clone(),
                owed_bytes: expansion.minus(&charged).pinned_bytes,
                manifest_bytes: expansion.pinned_bytes,
                origin: DebtOrigin::Prune,
            });
            charged.extend(expansion.cids());
        }
        Ok(owed)
    }

    /// The record one node's debts are owed by: its write-plane name, which
    /// scopes the retire to that record's own reference edges, and every content
    /// CID its **currently published** record still reaches — the set a retire
    /// against that node may not name.
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
    async fn live_owing_record(
        &self,
        scope: &DrainScope<'_>,
        node: [u8; 16],
        owing: OwingRecord,
    ) -> Option<LiveRecord> {
        let end = scope.end_of(&self.cells.base.borrow(), NodeId(node)).ok()?;
        let write_name = end.write_name(&node);
        let reaching = |cids| {
            Some(LiveRecord {
                name: write_name.as_str().to_owned(),
                cids,
            })
        };
        if owing == OwingRecord::Retired {
            return reaching(BTreeSet::new());
        }
        let (plane, root) = self.ledger_plane(end).await?;
        let acked = match owing {
            OwingRecord::Unconfirmed => self
                .retire_ledger(scope)
                .acknowledged(&owner_tag(scope.enc_secret), node, write_name.as_str())
                .await
                .ok()?,
            _ => Acknowledged::Nothing,
        };
        // Nocache: the retire unpins, so what may be named is decided against
        // the freshest record the gate will pass, never a cached one a
        // concurrent writer has already moved past.
        let loaded = match self
            .load_child_node(&plane, root.anchor(), NodeId(node), ResolveMode::NoCache)
            .await
        {
            Ok(loaded) => loaded,
            Err(_)
                if owing == OwingRecord::Unconfirmed
                    && acked == Acknowledged::Nothing
                    && self.holds_no_record(&end, &write_name).await? =>
            {
                return reaching(BTreeSet::new());
            }
            Err(_) => return None,
        };
        if owing == OwingRecord::Unconfirmed
            && (loaded.tied
                || match acked {
                    Acknowledged::Nothing => false,
                    Acknowledged::At(acked) => loaded.observed.sequence() <= acked,
                    Acknowledged::Unreadable => true,
                })
        {
            return None;
        }
        // A record carrying no version list reaches no content.
        let ReadBody::File { versions, .. } = loaded.body else {
            return reaching(BTreeSet::new());
        };
        let mut live = BTreeSet::new();
        for version in self.pinned_history(&versions).ok()? {
            live.extend(self.expand_version(&version).await.ok()?.cids());
        }
        reaching(live)
    }

    /// Whether `name` holds no record by the [`OwingRecord::Unconfirmed`] rule:
    /// every endpoint answers that it holds none, and this device never adopted
    /// one there. `None` when the sequence floor will not read.
    async fn holds_no_record(&self, end: &ScopeEnd<'_>, name: &IpnsName) -> Option<bool> {
        let floors = end.floors(&self.seams.floors);
        if floor::sequence_floor(&floors, name.as_str().as_bytes())
            .await
            .ok()?
            .is_some()
        {
            return Some(false);
        }
        Some(matches!(
            fanout_get_classified(&self.seams.transport, name).await,
            FanoutRecord::Absent
        ))
    }

    /// The plane a retire-ledger entry's node reads under, and the root record
    /// that proved it: the node's own end, at that end's read epoch, walking
    /// that end's own backward ratchet. The ledger settles outside any pass, so
    /// both are read here rather than carried.
    async fn ledger_plane<'s>(&self, end: ScopeEnd<'s>) -> Option<(SealPlane<'s>, LoadedRoot)> {
        let root = self.load_scope_root(&end).await.ok()?;
        Some((end.at(root.epoch), root))
    }

    /// One published version's whole CID set, off its own fetched root block.
    async fn expand_version(&self, version: &ContentVersion) -> Result<Expansion, Halt> {
        let expected = decode_content_cid_str(&version.content_cid)
            .map_err(|_| Halt::Permanent(DeadLetterReason::PayloadRefused))?;
        let root_block = read_block(
            &self.seams.gateway,
            &self.seams.http,
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
            &self.seams.content_profile,
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
                if self.cells.cancels.borrow().is_cancelled(applied.op_id) {
                    return Err(Halt::Cancelled);
                }
                if let Some(error) = upload_failure(halt) {
                    self.emit_upload(applied, OpPhase::UploadFailed, None, Some(error));
                }
                return Err(halt);
            }
        };
        if !self.cells.cancels.borrow_mut().enter_publish(applied.op_id) {
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
            emit_trust_violation(&self.seams.events, name.as_str(), &error);
        }
        classify_author(error)
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
        // resolve spends the unattributed budget, never the attempt budget.
        let placement = self.inputs.placement.as_ref().map_err(|refusal| {
            refusal
                .holds()
                .map_or(Halt::Unclassified, Halt::HeldBySettings)
        })?;
        // What the mark may claim, narrowed as the mirror misses blocks the mark
        // covers ([`Destinations::mirror_missed`]).
        let mut reached = placement.destinations();
        let mut mirror = core::mem::take(&mut self.mirror.borrow_mut().leg);
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
        // Opened under the carried pair, never this pass's root
        // ([`StagedContent::scope`]).
        //
        // A blob this build cannot *interpret* — one a newer build wrote — is
        // retained and retried, never destroyed: the same rule the op record
        // itself follows. Only a genuine crypto failure is unrecoverable.
        let key = open_content_key(
            scope.enc_secret,
            &staged.scope.0,
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
                    self.seams
                        .staging
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
            content.leaf_cids().iter().map(|cid| cid.as_slice()),
            RootPlacement::First,
        );
        let mut op = self.mirror.borrow_mut();
        op.leg = mirror;
        op.gap |= mirror_gap;
        Ok(UploadedVersion {
            version: content.version(*key, applied.op.authored_at.0),
            content_cids,
        })
    }

    /// The block boundary a cancel gets to run at. Without the yield a whole
    /// version uploads inside one turn of the host's executor, and the cancel
    /// guarantee collapses to "only before the op starts".
    async fn cancel_checkpoint(&self, op_id: OpId) -> Result<(), Halt> {
        yield_now().await;
        match self.cells.cancels.borrow().is_cancelled(op_id) {
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
        let _ = self.seams.events.unbounded_send(Event::OpProgress {
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
            .seams
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
        self.seams
            .staging
            .put_staged_bytes(mark_key, &mark)
            .await
            .map_err(seam)
    }

    /// The staged bytes at `key`, admitted by [`admissible_staged_block`].
    async fn staged_block(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Halt> {
        let Some(block) = self.seams.staging.staged_bytes(key).await.map_err(seam)? else {
            return Ok(None);
        };
        admissible_staged_block(key, block).map(Some)
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
                place_block(config, cid, block, &self.seams.http, &self.seams.deadlines)
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
                    match place_block(config, cid, block, &self.seams.http, &self.seams.deadlines)
                        .await
                    {
                        Ok(()) => break,
                        Err(error) => mirror.refused(error),
                    }
                }
            }
        }
        Ok(())
    }

    /// Where this tick puts a record head. A refused decision keeps the hosted
    /// leg, as a publish with no decided placement does.
    fn head_placement(&self) -> &Placement {
        self.inputs.placement.as_ref().unwrap_or(&Placement::Hosted)
    }

    /// Record one block as on the network for `op_id`, which is the only
    /// evidence a cancel has that this upload charged for it
    /// ([`UploadCancels`]). Written the instant the leg that charges confirms,
    /// so no later await can abandon the upload with the charge unrecorded.
    fn charged(&self, op_id: OpId, cid: &[u8]) {
        self.cells.cancels.borrow_mut().confirmed(op_id, cid);
    }

    /// One block to the hosted ingress, under its own content address.
    async fn hosted_upload(&self, cid: &[u8], block: &[u8]) -> Result<(), Halt> {
        self.seams
            .api
            .upload(&encode_content_cid_str(cid), block)
            .await
            .map(drop)
            .map_err(|error| classify_upload(error, block.len() as u64))
    }

    /// Drop every staged block of an op's version — on a kept op that waited
    /// out its bound, and on a failure-valve abandonment, where the only copy of
    /// the version's content key rode the op record the abandonment deletes
    /// (`crate::sync::staging` owns the release-or-preserve rule).
    async fn release_staged_blocks(&self, op: &Op) {
        let Some(root_cid) = op.content_root_cid() else {
            return;
        };
        release_version_blocks(&self.seams.staging, root_cid).await;
    }

    /// The parent a node is published under, from the base the pass repaints as
    /// it goes — so an op rebases onto exactly what the ops before it published.
    fn published_parent(&self, node: NodeId) -> Result<NodeId, Halt> {
        self.cells
            .base
            .borrow()
            .parent_of(node)
            .ok_or(Halt::Unclassified)
    }

    /// Every parent the base links `node` under, winner first
    /// ([`Snapshot::links_ranked`]), once this pass has proved it can author
    /// each of them.
    ///
    /// A delete acts on the whole list, because it re-keys the node out of the
    /// scope: a link left standing names a record its own folder's readers can
    /// no longer open (blueprint/engine.md "Delete branch"). A pass carries two
    /// ends, so a folder in the second end's scope is this pass's to unlink and
    /// republishes under its own plane.
    ///
    /// A link neither end roots is never dropped: dropping it would publish the
    /// dangling link the rule exists to prevent. Where this pass authors none of
    /// the others, every link sits under one other scope root and that scope's
    /// own pass takes the op ([`halt_below_another_scope_root`]). Where it
    /// authors some, no pass reaches further, so the op is charged and reports
    /// rather than stalling the strict-FIFO head. The replay refuses the spans
    /// no pass will ever pair, so what reaches here is a boundary this tick
    /// proved no material for.
    fn published_parents(
        &self,
        scope: &DrainScope<'_>,
        pass: &Pass,
        node: NodeId,
    ) -> Result<Vec<NodeId>, Halt> {
        let base = self.cells.base.borrow();
        let mut parents = Vec::new();
        let mut beyond = None;
        for link in base.links_ranked(node) {
            // A chain that stops at no proved boundary roots at the parent
            // itself, which no end is anchored on.
            let root =
                enclosing_scope_root(&base, link.parent, scope.scope_roots).unwrap_or(link.parent);
            match scope.plane_rooted_at(pass.epoch, root)? {
                Some(_) => parents.push(link.parent),
                None => {
                    beyond = beyond.or(Some(halt_below_another_scope_root(
                        scope.keyless_roots,
                        scope.charges_the_identity,
                        root,
                    )));
                }
            }
        }
        match (parents.is_empty(), beyond) {
            (false, None) => Ok(parents),
            (false, Some(_)) => Err(Halt::UploadAttempt),
            (true, halt) => Err(halt.unwrap_or(Halt::Unclassified)),
        }
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
        let (name, commitment, built_on, body, envelope_unknown, epoch_tag_unknown) = {
            let state = pass.folder(folder).map_err(PublishHalt::before_the_put)?;
            (
                state.name.clone(),
                state.commitment.clone(),
                (state.observed.clone(), state.record.clone()),
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
        let plane = scope
            .folder_plane(pass, folder)
            .map_err(PublishHalt::before_the_put)?;
        let observed = self
            .reresolve_before_signing(scope, &plane, folder, &name, commitment.as_ref(), &built_on)
            .await
            .map_err(PublishHalt::before_the_put)?;
        let published = self
            .publish_node(
                scope,
                &plane,
                folder,
                observed,
                commitment.is_some(),
                &body,
                Vec::new(),
                envelope_unknown,
                epoch_tag_unknown,
                completes,
            )
            .await?;

        let sequence = published.observed.sequence();
        let state = pass.folder_mut(folder).map_err(PublishHalt::past_the_put)?;
        state.observed = published.observed;
        state.record.clone_from(&published.held.record_bytes);
        state.modified_at = modified_at;
        let children = state.children.clone();
        self.repaint_folder(scope, folder, &children, sequence, modified_at);
        self.hold(folder.0, published.held);
        Ok(sequence)
    }

    /// Re-resolve a folder just before signing over it, so the signature is
    /// minted above what the endpoints serve and not above this device's cache
    /// (blueprint/engine.md "Publish"). The adopt raises the durable floor the
    /// publish mints above. A record above `built_on`, or a sequence the
    /// endpoints serve only with other bytes, halts this attempt so the next
    /// pass rebases onto what they serve ([`publish_basis`]).
    ///
    /// A scope root's `commitment` is then held to the cut-epoch floor
    /// ([`refuse_below_cut_floor`]).
    async fn reresolve_before_signing(
        &self,
        scope: &DrainScope<'_>,
        plane: &SealPlane<'_>,
        folder: NodeId,
        name: &IpnsName,
        commitment: Option<&GrantSetCommitment>,
        built_on: &(Observed, Vec<u8>),
    ) -> Result<Observed, Halt> {
        let served = if commitment.is_some() {
            let resolved = self
                .gated_scope_root(scope, &plane.end, ResolveMode::NoCache)
                .await?;
            if let ResolveOutcome::TrustViolation(rejection) = &resolved.resolved.outcome {
                return Err(refuse_record(&self.seams.events, name, rejection));
            }
            resolved.held_record.map(|(record, bytes)| {
                Served::new(record.sequence, bytes, resolved.tied, resolved.observed)
            })
        } else {
            self.served_child(plane, folder, name).await?
        };
        let observed = publish_basis(served, built_on)?;
        let Some(commitment) = commitment else {
            return Ok(observed);
        };
        let floors = plane.end.floors(&self.seams.floors);
        match refuse_below_cut_floor(&floors, &plane.end.root.0, commitment).await {
            Ok(()) => Ok(observed),
            Err(GateError::Rejected(rejection)) => {
                Err(refuse_record(&self.seams.events, name, &rejection))
            }
            Err(GateError::Seam(error)) => Err(seam(error)),
        }
    }

    /// What an interior folder's name now serves, through the child gate. A
    /// record the epoch floor refuses is the lazy wave's to re-seal, as in
    /// [`Self::load_child_node`], so it counts; every other refusal is a trust
    /// violation.
    async fn served_child(
        &self,
        plane: &SealPlane<'_>,
        folder: NodeId,
        name: &IpnsName,
    ) -> Result<Option<Served>, Halt> {
        let floors = plane.end.floors(&self.seams.floors);
        let adopter = self.child_adopter(plane, &floors, folder);
        let resolved = resolve_gated(
            &self.seams.transport,
            &self.seams.snapshot_cache,
            &adopter,
            name,
            ResolveMode::NoCache,
        )
        .await
        .map_err(seam)?;
        let tied = resolved.tied;
        match &resolved.resolved.outcome {
            ResolveOutcome::TrustViolation(rejection) => match rejection.reason {
                RejectionReason::EpochBelowFloor { .. } => {
                    let bytes = adopter
                        .assembled_record_bytes(name)
                        .ok_or(Halt::EpochLagged)?;
                    let lagging = IpnsRecord::unmarshal(&bytes)
                        .and_then(|record| record.verify(name))
                        .map_err(|_| Halt::Unclassified)?;
                    Ok(Some(Served::new(lagging.sequence, bytes, tied, None)))
                }
                _ => Err(refuse_record(&self.seams.events, name, rejection)),
            },
            _ => Ok(resolved.held_record.map(|(record, bytes)| {
                Served::new(record.sequence, bytes, tied, resolved.observed)
            })),
        }
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
        plane: &SealPlane<'_>,
        node: NodeId,
        observed: Observed,
        is_scope_root: bool,
        body: &ReadBody,
        content_cids: Vec<String>,
        carried_unknown: PreservedFields,
        carried_epoch_tag_unknown: PreservedFields,
        completes: Option<OpId>,
    ) -> Result<Published, PublishHalt> {
        let name = &observed.name().clone();
        plane_seals(plane, node, name, is_scope_root).map_err(PublishHalt::before_the_put)?;
        let read_key = plane.end.read_key(&node.0);
        let nonce = fresh_nonce(&mut *self.seams.entropy.borrow_mut())
            .map_err(|_| PublishHalt::before_the_put(Halt::UploadAttempt))?;
        let authoring = EnvelopeAuthoring {
            node_id: node.0,
            scope_id: plane.end.root.0,
            epoch: plane.epoch,
            read_key: &read_key,
            nonce: &nonce,
            body,
            carried_unknown,
            carried_epoch_tag_unknown,
        };
        let head = if is_scope_root {
            // The duty is read off the material this end publishes under, never
            // off the section being carried: an end with an ascent authority is
            // an interior scope root, whose record the child gate refuses
            // without its link (`net/rotation.rs::gate_root_pass`).
            let owes_ascent_link = plane.end.ascent_node_seed.is_some();
            author_scope_root_envelope(authoring, name, scope.owner_identity, owes_ascent_link)
        } else {
            author_child_envelope(authoring)
        }
        .map_err(|error| PublishHalt::before_the_put(self.report_author_refusal(name, error)))?;
        report_carried_cut(&self.seams.events, name, &head.cut);

        let ledger = self.retire_ledger(scope);
        let owner = owner_tag(scope.enc_secret);
        let acked = ledger
            .acknowledged(&owner, node.0, name.as_str())
            .await
            .map_err(|error| PublishHalt::before_the_put(seam(error)))?;
        // A PUT of ours the ledger acknowledged may still surface, so the
        // signature clears it too.
        let observed = match acked {
            Acknowledged::Nothing => observed,
            Acknowledged::At(sequence) => observed.clearing(sequence),
            // Any sequence may hide behind it: clear the most one op's charged
            // attempts can have signed above the floor.
            Acknowledged::Unreadable => {
                let floor = floor::sequence_floor(
                    &plane.end.floors(&self.seams.floors),
                    name.as_str().as_bytes(),
                )
                .await
                .map_err(|error| PublishHalt::before_the_put(seam(error)))?;
                observed.clearing(floor.unwrap_or(0).saturating_add(u64::from(ATTEMPT_BUDGET)))
            }
        };
        let record_bytes = match self
            .publish_head(plane, &observed, &node.0, &head, content_cids.clone())
            .await
            .map_err(PublishHalt::before_the_put)?
        {
            HeadPublish::Confirmed(record_bytes) => {
                if acked != Acknowledged::Nothing {
                    let _ = ledger.forget_acknowledged(&owner, node.0).await;
                }
                record_bytes
            }
            // Its bytes may still surface at `sequence`, so the next publish
            // here signs above it rather than tying it.
            HeadPublish::Unconfirmed { sequence } => {
                self.hold_acknowledged(scope, node, name, sequence)
                    .await
                    .map_err(PublishHalt::before_the_put)?;
                return Err(PublishHalt::before_the_put(Halt::Attempt));
            }
            HeadPublish::Lost { winner, sequence } => {
                // A tie leaves our acked bytes standing beside the winner.
                self.hold_acknowledged(scope, node, name, sequence)
                    .await
                    .map_err(PublishHalt::before_the_put)?;
                // The retry must rebase onto the winner: the first-endpoint tie
                // can keep serving our own record, which already holds this op.
                // Our PUT was acked either way, so the halt stays an attempt.
                if let Some(winner) = winner {
                    let adopted = self
                        .adopt_node_record(scope, plane, node, name, is_scope_root, &winner, None)
                        .await;
                    if let Err(GateError::Rejected(rejection)) = adopted {
                        refuse_record(&self.seams.events, name, &rejection);
                    }
                }
                return Err(PublishHalt::before_the_put(Halt::Attempt));
            }
        };
        if let Some(op_id) = completes {
            self.keep_published(scope, &plane.end, op_id).await;
            self.mark_published(scope, op_id).await;
        }
        // The record is live from here: everything below is a local step.
        let Ok(Ok(observed)) = self
            .adopt_node_record(
                scope,
                plane,
                node,
                name,
                is_scope_root,
                &record_bytes,
                Some(local_head(&head)),
            )
            .await
        else {
            return Err(PublishHalt::past_the_put(Halt::Unclassified));
        };
        Ok(Published {
            observed,
            held: HeldRecord {
                routing_key: name.as_str().to_owned(),
                record_bytes,
                signer: SessionIdentity::write_name_signer(plane.end.write_scope_seed, &node.0),
                value: HeldValue::Head(head.cid),
                // The same list the publish registered, so a sub-EOL renewal
                // re-pins exactly the content this record points at.
                content_cids,
            },
        })
    }

    /// Gate one record at a node's name, leave it last-known-good, then move
    /// the floor (durable-first), and answer the token of the adopted record.
    /// `local` is the head this device just authored, so the gate need not
    /// fetch it back.
    #[expect(clippy::too_many_arguments, reason = "one node's full gate context")]
    async fn adopt_node_record(
        &self,
        scope: &DrainScope<'_>,
        plane: &SealPlane<'_>,
        node: NodeId,
        name: &IpnsName,
        is_scope_root: bool,
        record_bytes: &[u8],
        local: Option<LocalHead>,
    ) -> Result<Result<Observed, PublishError>, GateError> {
        let floors = plane.end.floors(&self.seams.floors);
        let adopted = if is_scope_root {
            let adopter = self.root_adopter(scope, &floors, &plane.end);
            if let Some(local) = local {
                adopter.hold_local_head(local);
            }
            adopter.adopt(name, record_bytes).await?
        } else {
            let adopter = self.child_adopter(plane, &floors, node);
            if let Some(local) = local {
                adopter.hold_local_head(local);
            }
            adopter.adopt(name, record_bytes).await?
        };
        let version = adopted.version;
        keep_then_commit(
            &self.seams.snapshot_cache,
            name,
            record_bytes,
            adopted.pass.commit(&floors),
        )
        .await
        .map(|adopted| Observed::gated(name, adopted.sequence, version))
        .map_err(GateError::Seam)
    }

    /// Dry-run and publish one head. Only [`HeadPublish::Confirmed`] bytes
    /// landed as ours; an unconfirmed publish is `Err`, because its bytes may
    /// never have landed.
    async fn publish_head(
        &self,
        plane: &SealPlane<'_>,
        observed: &Observed,
        node_id: &[u8; 16],
        head: &AuthoredHead,
        content_cids: Vec<String>,
    ) -> Result<HeadPublish, Halt> {
        let binding = plane.head_binding(node_id);
        let preflighted = preflight(&binding, &plane.end.read_key(node_id), head)
            .map_err(|_| Halt::UploadAttempt)?;
        let signer = SessionIdentity::write_name_signer(plane.end.write_scope_seed, node_id);
        let _publishing = PublishingName::hold(self.cells.publishing, observed.name());
        let mut mirror = core::mem::take(&mut self.mirror.borrow_mut().leg);
        let published = publish_record_placed(
            &self.seams.transport,
            &self.seams.api,
            &plane.end.floors(&self.seams.floors),
            &self.seams.scheduler,
            &self.seams.profile,
            &RecordPublishRequest {
                observed,
                signer: &signer,
                head: &preflighted,
                content_cids,
            },
            self.head_placement(),
            &mut mirror,
            None,
        )
        .await;
        self.mirror.borrow_mut().leg = mirror;
        let PublishReceipt {
            outcome,
            record_bytes,
            winner,
        } = published.map_err(|error| {
            if orphaned_head(&error) {
                self.record_orphan_head(preflighted.cid());
            }
            classify_publish(error, head.block.len() as u64)
        })?;
        match outcome {
            PublishOutcome::Published { .. } => Ok(HeadPublish::Confirmed(record_bytes)),
            PublishOutcome::LostRace {
                published_sequence, ..
            } => Ok(HeadPublish::Lost {
                winner,
                sequence: published_sequence,
            }),
            PublishOutcome::Unconfirmed { sequence } => Ok(HeadPublish::Unconfirmed { sequence }),
        }
    }

    /// Merge one folder's published children into the base snapshot, under
    /// the cross-plane rule when the pass is grafted.
    fn repaint_folder(
        &self,
        scope: &DrainScope<'_>,
        folder: NodeId,
        children: &[ChildRef],
        sequence: u64,
        modified_at: u64,
    ) {
        paint_folder(
            scope,
            &mut self.cells.base.borrow_mut(),
            folder,
            children,
            sequence,
            modified_at,
        );
    }

    /// Insert a just-published record into the live held set so the liveness
    /// loop keeps it alive.
    fn hold(&self, node_id: [u8; 16], held: HeldRecord) {
        self.cells
            .held
            .borrow_mut()
            .insert(HeldKey::Node(node_id), held);
    }

    /// Remove a resolved op from the durable queue.
    async fn dequeue_op(&self, op_id: OpId) -> Result<(), Halt> {
        self.seams.staging.remove_op(op_id).await.map_err(seam)
    }

    /// Note one head block as orphaned.
    ///
    /// A head the live set still names never enters the queue: its only
    /// consumer physically unpins, and unpinning a head a live record names is
    /// loss, where leaving the row charged is only a leak.
    fn record_orphan_head(&self, cid: &str) {
        if self
            .cells
            .held
            .borrow()
            .values()
            .any(|record| record.head_cid() == Some(cid))
        {
            return;
        }
        self.cells.orphan_heads.record(cid);
    }

    /// Retire every block a cancelled op put on the network. Best-effort: a
    /// refused batch leaves pin rows charged, which is a leak, where failing the
    /// pass over an op that is already gone would be a stuck queue.
    async fn retire_cancelled(&self, op_id: OpId) {
        let cids: Vec<String> = self
            .cells
            .cancels
            .borrow()
            .uploaded_by(op_id)
            .iter()
            .map(|cid| encode_content_cid_str(cid))
            .collect();
        if !cids.is_empty() {
            let _ = retire(&self.seams.api, &cids).await;
        }
    }

    /// Copy one queued op's record into the preserved set before the
    /// abandonment removes it, so the version it stages stays both referenced
    /// and openable ([`preserve_dead_letter`]).
    ///
    /// An op that staged no version takes a notice there instead, which is what
    /// makes it nameable again after a cold start.
    async fn preserve_dead_letter(
        &self,
        scope: &DrainScope<'_>,
        op_id: OpId,
        reason: DeadLetterReason,
    ) -> Result<Preservation, Halt> {
        let queued = self.seams.staging.queued_ops().await.map_err(seam)?;
        let Some((_, record)) = queued.iter().find(|(id, _)| *id == op_id) else {
            return Ok(Preservation::Kept);
        };
        preserve_dead_letter(
            &self.seams.staging,
            &owner_scoped_key(DEAD_LETTER_NOTICES_PREFIX, scope.enc_secret),
            op_id,
            reason,
            record,
            self.seams.scheduler.now(),
        )
        .await
        .map_err(seam)
    }

    /// Drop the version no preserved entry holds — [`Preservation::Refused`]
    /// or [`Preservation::ContentGone`] — once the op has left the queue, for a
    /// dead letter that kept the registry rows the version charged. The drop
    /// journals those rows first ([`DroppedVersionDebts::drop_version`]). A
    /// refused record takes the version's only content key with it, and orphan
    /// GC, which the same unreadable set stands down, would never collect the
    /// blocks.
    async fn release_unpreserved(&self, scope: &DrainScope<'_>, preserved: Preservation, op: &Op) {
        if preserved != Preservation::Kept {
            let reader = RecordReader::new(scope.enc_secret);
            self.dropped_version_debts(scope, &reader)
                .drop_version(op)
                .await;
        }
    }

    /// Abandon one op with its staged version preserved and its name left
    /// standing: the halt that took it gives no ground to believe no published
    /// record names the op's target, and cutting a name a live record carries
    /// would leave a reference outliving its referent.
    async fn abandon_keeping_its_name(
        &self,
        scope: &DrainScope<'_>,
        op_id: OpId,
        op: &Op,
        reason: DeadLetterReason,
        report: &mut DrainReport,
    ) {
        let Ok(preserved) = self.preserve_dead_letter(scope, op_id, reason).await else {
            return;
        };
        if self.dequeue_op(op_id).await.is_ok() {
            self.release_unpreserved(scope, preserved, op).await;
            report
                .dead_letters
                .push((op_id, op.target, preserved.observed(reason)));
        }
    }

    /// Abandon one op: retire what its publish registered, then drop it from
    /// the queue.
    async fn abandon(&self, scope: &DrainScope<'_>, op_id: OpId, op: &Op) -> Result<(), Halt> {
        retire(&self.seams.api, &self.registered_by(scope, op).await)
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
        retire(&self.seams.api, &[name])
            .await
            .map_err(|_| Halt::UploadAttempt)
    }

    /// Whether this create would re-author a node the record plane already
    /// carries — the shape of a data directory restored from before its own
    /// drain, where the queue comes back and the marks that record what already
    /// published do not.
    ///
    /// The name derives from the node id this op minted — 128 random bits from
    /// the injected entropy seam, public only once the record it names has
    /// published — so a record standing there is one this op published. A record
    /// that will not open is one too: a soft delete re-keys the node it bins out
    /// of this scope's derivation, and re-authoring over it would resurrect a
    /// binned node under the key the bin just cut.
    ///
    /// What that alone cannot say is whether this device has *forgotten*
    /// publishing it, and two durable reads answer that before the network is
    /// touched. An op with a charged attempt is one this device remembers
    /// trying: an acked PUT whose confirm-by-re-resolve missed leaves exactly
    /// this record with exactly no floor, and the retry it is owed signs above
    /// it. A raised sequence floor says the same for a publish that
    /// confirmed and then lost the parent naming it — the self-adopt raises the
    /// floor before that parent publishes, so a crash in the window re-authors
    /// as it always has. A restore rewinds both.
    ///
    /// A seam failure holds the op for a later pass rather than answering. An
    /// unresolvable name and a rejection before the unseal read as "not
    /// published", and a create the drain cannot reach is one whose own publish
    /// would not land either.
    async fn create_replays_a_publish(
        &self,
        plane: &SealPlane<'_>,
        op_id: OpId,
        target: NodeId,
    ) -> Result<bool, Halt> {
        // The durable record, not this pass's copy: what a restore rewinds is
        // exactly what survives a restart.
        let attempts = Attempts::decode(
            self.seams
                .staging
                .staged_bytes(OP_ATTEMPTS_KEY)
                .await
                .map_err(seam)?,
        );
        if attempts.charged_to(op_id) > 0 {
            return Ok(false);
        }
        let name = plane.end.write_name(&target.0);
        let floors = plane.end.floors(&self.seams.floors);
        if floor::sequence_floor(&floors, name.as_str().as_bytes())
            .await
            .map_err(seam)?
            .is_some()
        {
            return Ok(false);
        }
        let adopter = self.child_adopter(plane, &floors, target);
        let resolved = resolve(
            &self.seams.transport,
            &self.seams.snapshot_cache,
            &adopter,
            &name,
            ResolveMode::NoCache,
        )
        .await
        .map_err(seam)?;
        Ok(match resolved.outcome {
            ResolveOutcome::Adopted(_) => true,
            // A rejection at the unseal is a record that verified, cleared both
            // floors, and will not open under this scope's read key — a node a
            // soft delete re-keyed into the bin. An earlier stage says nothing
            // about what stands at the name.
            ResolveOutcome::TrustViolation(rejection) => rejection.stage == GateStage::Unseal,
            ResolveOutcome::Current { .. } | ResolveOutcome::NoUpdate => false,
        })
    }

    /// The name a create derived, where nothing published references it yet: a
    /// name some published record already references would leave a reference
    /// outliving its referent, and the gate-passing base is the evidence — a
    /// created node reaches it only once a parent record naming it published.
    ///
    /// The valve holds no [`Pass`], so the end comes from the parent's own
    /// chain ([`DrainScope::end_of`]) — a name follows from the write seed
    /// alone, with no epoch to prove.
    fn unreferenced_create_name(&self, scope: &DrainScope<'_>, op: &Op) -> Option<String> {
        let OpKind::Create { parent, .. } = &op.kind else {
            return None;
        };
        let base = self.cells.base.borrow();
        if base.contains(op.target) {
            return None;
        }
        let end = scope.end_of(&base, *parent).ok()?;
        Some(end.write_name(&op.target.0).as_str().to_owned())
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
                version_leaf_cids(&self.seams.staging, root_cid)
                    .await
                    .iter()
                    .map(|cid| cid.as_slice()),
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
            .seams
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
        // A record the pass emptied is dropped rather than rewritten as a bare
        // tag: [`orphan_staging_keys`] holds this key referenced, so a tag-only
        // body would park a staging row nothing ever reclaims.
        if attempts.counts.is_empty() {
            return self
                .seams
                .staging
                .remove_staged_bytes(OP_ATTEMPTS_KEY)
                .await
                .map_err(seam);
        }
        self.seams
            .staging
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
        queued: &[OpId],
        report: &DrainReport,
    ) -> Result<(), Halt> {
        let retired = report.left_the_queue();
        let Some(mark) = queued
            .iter()
            .map_while(|op_id| retired.contains(op_id).then_some(op_id.0))
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
        let raised = mark.max(
            op_mark(&self.seams.staging, key)
                .await
                .map_err(seam)?
                .unwrap_or(0),
        );
        self.seams
            .staging
            .put_staged_bytes(key, &raised.to_be_bytes())
            .await
            .map_err(seam)
    }

    /// The stored drained-op mark; `None` when nothing has drained on this
    /// device or the stored bytes are not a mark this build wrote.
    async fn drained_mark(&self, scope: &DrainScope<'_>) -> Result<Option<u64>, Halt> {
        op_mark(
            &self.seams.staging,
            &owner_scoped_key(DRAINED_OP_MARK_PREFIX, scope.enc_secret),
        )
        .await
        .map_err(seam)
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

/// Where `content_cid` sits in a file's history. A history that no longer names
/// it is one another writer has already shortened, and no retry brings the
/// version back.
fn version_index(versions: &[Version], content_cid: &[u8]) -> Result<usize, Halt> {
    versions
        .iter()
        .position(|version| version.content_cid == content_cid)
        .ok_or(Halt::Permanent(DeadLetterReason::BaseSuperseded))
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
        | AuthorError::SectionSignatureInvalid
        | AuthorError::MissingAscentLink => Halt::UploadAttempt,
        // Charged on the same terms as an over-length head: re-authoring the
        // same section repeats it verbatim, so an uncharged retry would spin.
        AuthorError::HeadTooLarge { .. } | AuthorError::GrantSectionTooLarge => Halt::HeadOversized,
        AuthorError::ScopeRootNotResealable { .. } => Halt::ScopeRootNotResealable,
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

/// Classify a publish failure for the valve. The head-block upload and the
/// register-first call carry a server verdict, and this build's own refusal of
/// the bytes it would sign repeats on every retry, so it is charged; everything
/// else is availability.
///
/// `refused_bytes` is what the upload asked for, so a block entered here records
/// the figure its resume probe must find room for.
fn classify_publish(error: RecordPublishError, refused_bytes: u64) -> Halt {
    match error {
        RecordPublishError::Upload(error) => classify_upload(error, refused_bytes),
        RecordPublishError::HeadCidMismatch { .. } => Halt::Unclassified,
        RecordPublishError::Placement(error) => classify_placement(error),
        RecordPublishError::Publish(error) => classify_publish_error(error),
    }
}

/// [`classify_publish`] for a failure past the upload.
fn classify_publish_error(error: PublishError) -> Halt {
    match error {
        PublishError::Register(error) => classify_register(error),
        PublishError::ForeignVersion { .. } => Halt::ForeignVersion,
        error => match error.verdict() {
            PublishVerdict::Refused
            | PublishVerdict::RefusedUnaddressed
            | PublishVerdict::RefusedOversized => Halt::UploadAttempt,
            PublishVerdict::RegistryRefused
            | PublishVerdict::NotLanded
            | PublishVerdict::PutUnacknowledged
            | PublishVerdict::PutRefused => Halt::Unclassified,
        },
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
/// than charging it ([`QueueHoldReason::Settings`]).
fn classify_placement(error: ProviderError) -> Halt {
    if let Some(hold) = SettingsHold::byo(error) {
        return Halt::HeldBySettings(hold);
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
fn settings_hold(placement: &PlacementDecision) -> Option<SettingsHold> {
    match placement {
        Ok(Placement::External(config)) => validate_byo_config(config)
            .err()
            .and_then(SettingsHold::byo),
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
/// where the halt is not a failed attempt: a hold keeps the op and its
/// reservation, and the host reads them from `SnapshotView::queue_hold`.
fn upload_failure(halt: Halt) -> Option<&'static str> {
    match halt {
        // A cancel reports `UploadCancelled` from the facade that ordered it.
        Halt::Blocked { .. }
        | Halt::HeldBySettings(_)
        | Halt::HeldByBinIndex(_)
        | Halt::Cancelled
        | Halt::OtherBinScope => None,
        Halt::Unclassified => Some("the upload did not complete"),
        Halt::ForeignVersion => Some("another device runs a newer release; update this app"),
        Halt::EpochLagged => Some("this folder is still being re-keyed after a key change"),
        Halt::OwedMove => Some("a sharing change on this folder is not finished yet"),
        Halt::Attempt | Halt::UploadAttempt | Halt::LostRace => {
            Some("the network refused it without a classification")
        }
        Halt::RecordRefused => Some("a record this change builds on failed verification"),
        Halt::UnwritableScope => {
            Some("this device cannot write to the shared folder this change is in")
        }
        Halt::HeadOversized => Some("the record this change publishes is over the size limit"),
        Halt::ScopeRootNotResealable => {
            Some("this shared folder's own record leaves no room for the re-key a revoke needs")
        }
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
fn mirror_shortfall(mirror: &OpMirror) -> Option<&'static str> {
    mirror
        .leg
        .failure()
        .as_ref()
        .map(provider_failure)
        .or_else(|| mirror.gap.then_some(MIRROR_GAP))
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
        | ProviderError::InvalidCredential
        | ProviderError::UnresolvedCredential
        | ProviderError::NoStoredCredential
        | ProviderError::RepointedCredential => "your own IPFS provider settings were refused",
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

/// Merge one folder's published children into `base`, under the cross-plane
/// rule when the pass is grafted.
fn paint_folder(
    scope: &DrainScope<'_>,
    base: &mut Snapshot,
    folder: NodeId,
    children: &[ChildRef],
    sequence: u64,
    modified_at: u64,
) {
    match scope.granted {
        Some(GrantedPass { plane, .. }) => {
            let split = plane.split(base, children);
            project_folder_partial(
                base,
                folder,
                &split.linkable,
                &split.withheld,
                sequence,
                modified_at,
            );
        }
        None => {
            project_folder(base, folder, children, sequence, modified_at);
        }
    }
}

/// The queue replayed onto `base`.
fn replay_on(scope: &DrainScope<'_>, base: &Snapshot, queued: &[(OpId, Op)]) -> ReplayReport {
    let ops: Vec<Op> = queued.iter().map(|(_, op)| op.clone()).collect();
    let local = apply_overlay(base, &ops);
    replay(base, &local, queued, scope.scope_roots)
}

/// A loaded node's state as a folder, refusing a node whose sealed body is not
/// a folder (a kind transplant).
fn folder_state(plane: &SealPlane<'_>, loaded: LoadedNode) -> Result<FolderState, Halt> {
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
        plane_root: plane.end.root,
        name: loaded.name,
        record: loaded.record,
        commitment: None,
        envelope_unknown: loaded.envelope_unknown,
        epoch_tag_unknown: loaded.epoch_tag_unknown,
        created_at,
        modified_at,
        children,
        body_unknown: unknown,
        observed: loaded.observed,
    })
}

/// Whether the gate admits `record_bytes` at exactly the durable floor, as
/// [`resolve_gated`] does for an equal-floor `Current`.
async fn gates_at_floor<A: Adopter>(adopter: &A, name: &IpnsName, record_bytes: &[u8]) -> bool {
    matches!(
        recover_at_floor(adopter, name, record_bytes).await,
        Ok(Some(_))
    )
}

/// The owner's own material the gate recovers from `record_bytes` at exactly
/// the durable floor, which re-opens the body under the record's own seed.
/// `Ok(None)` when the record is not at the floor or the reader recovers none.
async fn recover_at_floor<A: Adopter>(
    adopter: &A,
    name: &IpnsName,
    record_bytes: &[u8],
) -> Result<Option<OwnScopeMaterial>, GateError> {
    match adopter.adopt(name, record_bytes).await {
        Err(GateError::Rejected(rejection)) => match rejection.reason {
            RejectionReason::SequenceNotNewer { floor, sequence } if floor == sequence => {
                adopter.recover_own_scope_material(name, record_bytes).await
            }
            _ => Err(GateError::Rejected(rejection)),
        },
        Err(error) => Err(error),
        Ok(_) => Ok(None),
    }
}

/// Whether the replay drops the queue's head op as already landed.
fn head_reads_applied(rebased: &ReplayReport, queued: &[(OpId, Op)]) -> bool {
    queued.first().is_some_and(|(head, _)| {
        rebased
            .dropped
            .iter()
            .any(|(op_id, reason)| op_id == head && *reason == DropReason::AlreadySatisfied)
    })
}

/// The gate-passing bytes one resolve of `name` established.
///
/// A gate failure is a trust violation, never staleness: re-authoring on top
/// of last-known-good while the record plane serves a rejected record is
/// exactly the fail-open rule 6 forbids. An adopt carries the bytes this pass
/// gated, never the cache, which keeps a newer copy this pass did not gate.
///
/// At the floor, the cached copy wins while the endpoints still serve it: after
/// a lost tie it holds the winner, and the first endpoint can keep serving our
/// own losing record, which already carries the op being rebased.
fn resolved_bytes(
    gated: GatedResolve,
    name: &IpnsName,
    events: &mpsc::UnboundedSender<Event>,
) -> Result<Vec<u8>, Halt> {
    match gated.resolved.outcome {
        ResolveOutcome::Adopted(_) => gated
            .held_record
            .map(|(_, bytes)| bytes)
            .ok_or(Halt::Unclassified),
        ResolveOutcome::Current { record_bytes } => Ok(gated
            .resolved
            .last_known_good
            .filter(|cached| gated.tied.contains(cached))
            .unwrap_or(record_bytes)),
        ResolveOutcome::NoUpdate => gated.resolved.last_known_good.ok_or(Halt::Unclassified),
        ResolveOutcome::TrustViolation(rejection) => Err(refuse_record(events, name, &rejection)),
    }
}

/// The token a republish over `built_on` signs above, given what the name
/// serves now: the gate's token for the record it passed at `built_on`'s
/// sequence, else `built_on`'s own.
fn publish_basis(served: Option<Served>, built_on: &(Observed, Vec<u8>)) -> Result<Observed, Halt> {
    let Some(served) = served else {
        return Ok(built_on.0.clone());
    };
    if served.moved_past(built_on) {
        return Err(Halt::LostRace);
    }
    match served.observed {
        Some(gated) if served.sequence == built_on.0.sequence() => {
            gated.map_err(classify_publish_error)
        }
        _ => Ok(built_on.0.clone()),
    }
}

/// Report the gate's refusal of a record at `name` this pass must build on,
/// and the halt it takes.
fn refuse_record(
    events: &mpsc::UnboundedSender<Event>,
    name: &IpnsName,
    rejection: &GateRejection,
) -> Halt {
    emit_trust_violation(events, name.as_str(), rejection);
    Halt::RecordRefused
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use crate::net::author::ENVELOPE_V;
    use crate::net::record_publish::PreflightError;
    use crate::record_plane::{LapsedHead, Unopened};
    use crate::seams::SeamError;
    use crate::settings::{PlacementRefusal, SettingsRefusal};
    use crate::sync::model::NodeMeta;

    const SOURCE_ROOT: NodeId = NodeId([1; 16]);
    const DESTINATION_ROOT: NodeId = NodeId([2; 16]);
    const SOURCE_EPOCH: u64 = 7;
    const DESTINATION_EPOCH: u64 = 11;

    /// One end's session values, owned so a test can borrow them into a
    /// [`ScopeEnd`]. Each end takes unrelated seeds, as a real scope's are.
    struct End {
        root: NodeId,
        name: IpnsName,
        read_scope_seed: Zeroizing<[u8; 32]>,
        write_scope_seed: Zeroizing<[u8; 32]>,
    }

    impl End {
        fn new(root: NodeId, read: u8, write: u8) -> Self {
            let write_scope_seed = Zeroizing::new([write; 32]);
            Self {
                root,
                name: derive_write_name(&write_scope_seed, &root.0),
                read_scope_seed: Zeroizing::new([read; 32]),
                write_scope_seed,
            }
        }

        fn end(&self) -> ScopeEnd<'_> {
            ScopeEnd {
                root: self.root,
                root_name: &self.name,
                read_scope_seed: &self.read_scope_seed,
                read_seed_stamp: None,
                write_scope_seed: &self.write_scope_seed,
                ascent_node_seed: None,
                floor_namespace: FloorNamespace::Own,
            }
        }
    }

    /// The two owner seams a `DrainScope` holds and plane resolution never
    /// reads.
    struct OwnerSeams {
        enc_secret: X25519Secret,
        identity: EcdsaVerifier,
    }

    impl OwnerSeams {
        fn new() -> Self {
            Self {
                enc_secret: X25519Secret::from_scalar([5; 32]),
                identity: EcdsaSigner::from_scalar(&[6; 32])
                    .expect("a signing scalar below the group order")
                    .verifying_key(),
            }
        }
    }

    /// A source end and a destination end, each with its own seeds.
    fn ends() -> (End, End) {
        (
            End::new(SOURCE_ROOT, 3, 4),
            End::new(DESTINATION_ROOT, 13, 14),
        )
    }

    fn two_ended<'a>(
        seams: &'a OwnerSeams,
        source: &'a End,
        destination: &'a End,
        roots: &'a [NodeId],
    ) -> DrainScope<'a> {
        DrainScope {
            source: source.end(),
            destination: Some(destination.end().at(DESTINATION_EPOCH)),
            scope_roots: roots,
            keyless_roots: &[],
            charges_the_identity: true,
            enc_secret: &seams.enc_secret,
            owner_identity: &seams.identity,
            granted: None,
        }
    }

    /// The root and epoch one node resolves onto, which is what the pass seals
    /// and names every record of that node's subtree under.
    fn resolved(scope: &DrainScope<'_>, root: NodeId) -> Result<Option<(NodeId, u64)>, Halt> {
        Ok(scope
            .plane_rooted_at(SOURCE_EPOCH, root)?
            .map(|plane| (plane.end.root, plane.epoch)))
    }

    /// One folder as a pass holds it, loaded under the plane rooted at
    /// `plane_root`.
    fn pass_holding(folder: NodeId, plane_root: NodeId) -> Pass {
        let name = derive_write_name(&Zeroizing::new([4; 32]), &folder.0);
        Pass {
            root: SOURCE_ROOT,
            epoch: SOURCE_EPOCH,
            history_links: Vec::new(),
            second_ratchet: None,
            folders: vec![(
                folder,
                FolderState {
                    plane_root,
                    observed: Observed::gated(&name, 1, ENVELOPE_V)
                        .expect("this build's envelope version"),
                    name,
                    record: Vec::new(),
                    commitment: None,
                    envelope_unknown: PreservedFields::new(),
                    epoch_tag_unknown: PreservedFields::new(),
                    created_at: 1,
                    modified_at: 1,
                    children: Vec::new(),
                    body_unknown: PreservedFields::new(),
                },
            )],
            journalled: Vec::new(),
        }
    }

    /// A pass that adopts sequence 6 while the cache keeps a newer 7 authors on
    /// the 6 it gated, never on the cached copy it did not.
    #[test]
    fn an_adopt_authors_on_the_bytes_it_gated_not_the_cache() {
        let (gated, cached) = (b"record at 6".to_vec(), b"record at 7".to_vec());
        let resolved = GatedResolve {
            resolved: crate::net::Resolved {
                last_known_good: Some(cached),
                outcome: ResolveOutcome::Adopted(Adopted {
                    read_body: ReadBody::Folder {
                        created_at: 0,
                        modified_at: 0,
                        children: Vec::new(),
                        unknown: PreservedFields::new(),
                    },
                    sequence: 6,
                    epoch: 0,
                }),
                current_at_floor: None,
                fork: None,
            },
            hold: None,
            held_record: Some((
                cipherbox_core::ipns::VerifiedRecord {
                    value: Vec::new(),
                    validity: Vec::new(),
                    sequence: 6,
                    ttl: 0,
                    data: Vec::new(),
                },
                gated.clone(),
            )),
            read_scope_seed: None,
            tied: Vec::new(),
            absent: false,
            observed: None,
        };
        let (events, _rx) = mpsc::unbounded();
        assert_eq!(
            resolved_bytes(resolved, &refused_name(), &events),
            Ok(gated)
        );
    }

    /// At the floor, the cached copy is the base while an endpoint still serves
    /// it beside the freshest pick, and the freshest pick is the base once none
    /// does.
    #[test]
    fn at_the_floor_the_cached_copy_is_the_base_only_while_it_is_still_served() {
        let (first, cached) = (b"first endpoint".to_vec(), b"cached".to_vec());
        let at_floor = |tied: Vec<Vec<u8>>| GatedResolve {
            resolved: crate::net::Resolved {
                last_known_good: Some(cached.clone()),
                outcome: ResolveOutcome::Current {
                    record_bytes: first.clone(),
                },
                current_at_floor: None,
                fork: None,
            },
            hold: None,
            held_record: None,
            read_scope_seed: None,
            tied,
            absent: false,
            observed: None,
        };
        let (events, _rx) = mpsc::unbounded();
        assert_eq!(
            resolved_bytes(at_floor(vec![cached.clone()]), &refused_name(), &events),
            Ok(cached.clone())
        );
        assert_eq!(
            resolved_bytes(at_floor(Vec::new()), &refused_name(), &events),
            Ok(first.clone())
        );
    }

    fn refused_name() -> IpnsName {
        derive_write_name(&[0x21; 32], &[0x22; 16])
    }

    /// What `resolved_bytes` answers for `outcome` with nothing cached, and
    /// whether it reported a trust violation.
    fn resolved_bytes_of(outcome: ResolveOutcome) -> (Result<Vec<u8>, Halt>, bool) {
        let (events, mut rx) = mpsc::unbounded();
        let answer = resolved_bytes(
            GatedResolve {
                resolved: crate::net::Resolved {
                    last_known_good: None,
                    outcome,
                    current_at_floor: None,
                    fork: None,
                },
                hold: None,
                held_record: None,
                read_scope_seed: None,
                tied: Vec::new(),
                absent: false,
                observed: None,
            },
            &refused_name(),
            &events,
        );
        drop(events);
        let reported = core::iter::from_fn(|| rx.try_recv().ok())
            .any(|event| matches!(event, Event::AttributableAbuse { .. }));
        (answer, reported)
    }

    /// A record the gate refuses is a trust verdict on the op that builds on
    /// it: reported, and charged rather than waited out as an outage.
    #[test]
    fn a_refused_record_is_reported_and_charged() {
        let (answer, reported) = resolved_bytes_of(ResolveOutcome::TrustViolation(GateRejection {
            stage: GateStage::Sequence,
            reason: RejectionReason::SequenceNotNewer {
                floor: 7,
                sequence: 6,
            },
        }));
        assert_eq!(answer, Err(Halt::RecordRefused));
        assert!(reported);
    }

    /// A name that answered nothing is availability: uncharged, and nobody is
    /// accused.
    #[test]
    fn a_name_that_answered_nothing_accuses_nobody() {
        let (answer, reported) = resolved_bytes_of(ResolveOutcome::NoUpdate);
        assert_eq!(answer, Err(Halt::Unclassified));
        assert!(!reported);
    }

    /// A granted scope's subtree seals under that scope's own material and never
    /// its parent scope's, so the node a chain is rooted at is what decides the
    /// plane, and each end answers at its own epoch.
    #[test]
    fn each_end_answers_for_the_root_it_is_anchored_on() {
        let (source, destination) = ends();
        let seams = OwnerSeams::new();
        let roots = [SOURCE_ROOT, DESTINATION_ROOT];
        let scope = two_ended(&seams, &source, &destination, &roots);

        assert_eq!(
            resolved(&scope, SOURCE_ROOT),
            Ok(Some((SOURCE_ROOT, SOURCE_EPOCH))),
            "the source end seals at the epoch the pass proved from its own root"
        );
        assert_eq!(
            resolved(&scope, DESTINATION_ROOT),
            Ok(Some((DESTINATION_ROOT, DESTINATION_EPOCH))),
            "and the destination end at the epoch the boundary walk proved"
        );
        assert_eq!(
            resolved(&scope, NodeId([200; 16])),
            Ok(None),
            "a root neither end is anchored on resolves to no plane"
        );
    }

    /// One session-lived debt set, and every pass of a tick reaches it. Only the
    /// vault root drops: a trigger escalates to it because no share reaches it,
    /// while a granted scope root is a debt whatever pass is anchored there.
    #[test]
    fn only_the_vault_root_drops_out_of_the_owed_cuts() {
        let pending: BTreeSet<NodeId> = [SOURCE_ROOT, DESTINATION_ROOT].into_iter().collect();

        assert_eq!(
            owed_cuts(&pending, SOURCE_ROOT),
            [DESTINATION_ROOT],
            "the escalation to the vault root names no grantee"
        );
        assert_eq!(
            owed_cuts(&pending, NodeId([9; 16])),
            [SOURCE_ROOT, DESTINATION_ROOT],
            "and a pass anchored elsewhere still owes every granted scope"
        );
    }

    /// The set a pass seals under and the set it classifies against answer two
    /// questions. Every end the pass can seal under must also be a boundary a
    /// walk would stop at, or a node under it would resolve onto the enclosing
    /// scope and be sealed under that scope's material.
    #[test]
    fn a_second_end_no_walk_would_stop_at_seals_nothing() {
        let (source, destination) = ends();
        let seams = OwnerSeams::new();
        let scope = two_ended(
            &seams,
            &source,
            &destination,
            &[SOURCE_ROOT, DESTINATION_ROOT],
        );
        for root in [SOURCE_ROOT, DESTINATION_ROOT] {
            assert!(
                matches!(scope.plane_rooted_at(SOURCE_EPOCH, root), Ok(Some(_))),
                "{root:?} carries a seed pair, so it resolves a plane"
            );
        }

        let unlisted = two_ended(&seams, &source, &destination, &[SOURCE_ROOT]);
        assert_eq!(
            unlisted
                .plane_rooted_at(SOURCE_EPOCH, DESTINATION_ROOT)
                .err(),
            Some(Halt::UploadAttempt),
            "a second end no walk would stop at is charged, not published under"
        );
        assert_eq!(
            unlisted.plane_rooted_at(SOURCE_EPOCH, SOURCE_ROOT).err(),
            Some(Halt::UploadAttempt),
            "and the pair refuses as one: neither end publishes under it"
        );
    }

    /// Two ends rooted at one node name one scope under two sets of material.
    /// The pass would seal live records under whichever the resolver reached
    /// first, and a rotation on that scope makes one of the two a revoked seed.
    #[test]
    fn two_ends_rooted_at_the_same_node_resolve_no_plane() {
        let (source, destination) = (End::new(SOURCE_ROOT, 3, 4), End::new(SOURCE_ROOT, 13, 14));
        let seams = OwnerSeams::new();
        let roots = [SOURCE_ROOT];
        let scope = two_ended(&seams, &source, &destination, &roots);

        assert_eq!(
            resolved(&scope, SOURCE_ROOT),
            Err(Halt::UploadAttempt),
            "an overlapping pair publishes nothing under either end"
        );
        assert_eq!(
            scope
                .folder_plane(&pass_holding(SOURCE_ROOT, SOURCE_ROOT), SOURCE_ROOT)
                .err(),
            Some(Halt::UploadAttempt),
            "including for a folder the pass already holds"
        );
    }

    /// A folder carries the root of the plane its own load proved. A recorded
    /// plane root that names neither end is charged: the pass proved it against
    /// a gate-passing record of that very end, so no later read restores it.
    #[test]
    fn a_held_folder_whose_plane_root_names_neither_end_is_charged() {
        let (source, destination) = ends();
        let seams = OwnerSeams::new();
        let roots = [SOURCE_ROOT, DESTINATION_ROOT];
        let scope = two_ended(&seams, &source, &destination, &roots);
        let folder = NodeId([9; 16]);

        assert_eq!(
            scope
                .folder_plane(&pass_holding(folder, DESTINATION_ROOT), folder)
                .map(|plane| (plane.end.root, plane.epoch)),
            Ok((DESTINATION_ROOT, DESTINATION_EPOCH)),
            "a folder loaded under the destination end republishes there"
        );
        assert_eq!(
            scope
                .folder_plane(&pass_holding(folder, NodeId([200; 16])), folder)
                .err(),
            Some(Halt::UploadAttempt),
            "and one recording a root neither end holds publishes nothing"
        );
    }

    /// A record the drain seals under a resolved destination plane binds that
    /// scope's id and epoch, and opens under that end's read key alone. Sealing
    /// a crossing under the source end would leave the moved subtree readable by
    /// the source scope's grantees.
    #[test]
    fn a_record_sealed_under_the_destination_plane_opens_under_no_other_end() {
        let (source, destination) = ends();
        let (source_plane, destination_plane) = (
            source.end().at(SOURCE_EPOCH),
            destination.end().at(DESTINATION_EPOCH),
        );
        let node = NodeId([9; 16]);
        let body = ReadBody::Folder {
            created_at: 1,
            modified_at: 1,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let read_key = destination_plane.end.read_key(&node.0);
        let head = author_child_envelope(EnvelopeAuthoring {
            node_id: node.0,
            scope_id: destination_plane.end.root.0,
            epoch: destination_plane.epoch,
            read_key: &read_key,
            nonce: &[7; 24],
            body: &body,
            carried_unknown: PreservedFields::new(),
            carried_epoch_tag_unknown: PreservedFields::new(),
        })
        .expect("a child envelope over the destination plane");

        assert!(
            preflight(&destination_plane.head_binding(&node.0), &read_key, &head).is_ok(),
            "the plane that sealed it is the plane that opens it"
        );
        assert_eq!(
            preflight(
                &source_plane.head_binding(&node.0),
                &source_plane.end.read_key(&node.0),
                &head
            ),
            Err(PreflightError::BindingMismatch),
            "the source scope id and epoch are not what this record binds"
        );
        assert!(
            matches!(
                preflight(
                    &destination_plane.head_binding(&node.0),
                    &source_plane.end.read_key(&node.0),
                    &head
                ),
                Err(PreflightError::Unseal(_))
            ),
            "and the source end's read key does not open the body"
        );
    }

    /// The encode-side half of the gate's rejects, and release-active by rule 8:
    /// a name or a kind from another end authors a record no reader adopts, so
    /// the seal path refuses it before the record is built.
    #[test]
    fn the_seal_path_refuses_a_name_or_a_kind_from_another_end() {
        let (source, destination) = ends();
        let (source_plane, destination_plane) = (
            source.end().at(SOURCE_EPOCH),
            destination.end().at(DESTINATION_EPOCH),
        );
        let node = NodeId([9; 16]);

        assert_eq!(
            plane_seals(
                &destination_plane,
                node,
                &destination_plane.end.write_name(&node.0),
                false
            ),
            Ok(()),
            "the name this end's write seed derives is the one it publishes under"
        );
        assert_eq!(
            plane_seals(
                &destination_plane,
                node,
                &source_plane.end.write_name(&node.0),
                false
            ),
            Err(Halt::UploadAttempt),
            "a child name from the source end has one source, so no retry heals it"
        );
        assert_eq!(
            plane_seals(
                &destination_plane,
                node,
                &destination_plane.end.write_name(&node.0),
                true
            ),
            Err(Halt::UploadAttempt),
            "and only a plane's own root authors a scope root envelope"
        );
        assert_eq!(
            plane_seals(
                &destination_plane,
                DESTINATION_ROOT,
                destination_plane.end.root_name,
                true
            ),
            Ok(()),
            "which the plane's own root does"
        );
        assert_eq!(
            plane_seals(
                &destination_plane,
                DESTINATION_ROOT,
                destination_plane.end.root_name,
                false
            ),
            Err(Halt::UploadAttempt),
            "and an interior envelope never publishes over a scope root record"
        );
    }

    /// A folder the pass already holds keeps the plane its own load proved. One
    /// the chain re-roots is a node whose scope moved under the pass, and the
    /// name check cannot catch it: the held name came from the same stale plane.
    #[test]
    fn a_held_folder_the_chain_re_roots_refuses() {
        let (source, destination) = ends();
        let folder = NodeId([9; 16]);
        let pass = pass_holding(folder, SOURCE_ROOT);

        assert_eq!(
            pass.keeps_its_plane(folder, &source.end().at(SOURCE_EPOCH)),
            Ok(()),
            "the plane that loaded it republishes it"
        );
        assert_eq!(
            pass.keeps_its_plane(folder, &destination.end().at(DESTINATION_EPOCH)),
            Err(Halt::UploadAttempt),
            "and the other end publishes nothing for it"
        );
    }

    /// A scope root whose record has moved off the epoch its plane binds is one
    /// no publish under that plane may follow. The anchor's own skew heals at
    /// the next pass boundary and waits; a second end's comes from the boundary
    /// walk and is charged, or an end the walk will not refresh holds the queue
    /// head for good.
    #[test]
    fn only_a_second_ends_epoch_skew_costs_the_op_its_budget() {
        let (source, destination) = ends();
        let seams = OwnerSeams::new();
        let scope = two_ended(
            &seams,
            &source,
            &destination,
            &[SOURCE_ROOT, DESTINATION_ROOT],
        );

        assert_eq!(
            epoch_skew(&scope, &source.end()),
            Halt::Unclassified,
            "the anchor's epoch is the pass's own, and the next pass reopens on it"
        );
        assert_eq!(
            epoch_skew(&scope, &destination.end()),
            Halt::UploadAttempt,
            "a second end's is the walk's, and no retry of this pass refreshes it"
        );
    }

    /// A base that places `target` under the source root, one node below it,
    /// and one beside it — the three positions the crossing walk has to tell
    /// apart.
    fn crossing_base(target: NodeId, inside: NodeId, beside: NodeId) -> Snapshot {
        let mut base = Snapshot::new(SOURCE_ROOT);
        for (parent, node, name) in [
            (SOURCE_ROOT, target, "moved"),
            (target, inside, "under"),
            (SOURCE_ROOT, beside, "beside"),
        ] {
            base.upsert_node(NodeMeta::new(node, name, crate::facade::NodeKind::Folder));
            base.link_next(parent, node);
        }
        base
    }

    /// The crossing walk descends through child refs anyone holding the source
    /// scope's write seed authors, so a ref naming any node at all reaches the
    /// re-seal. Two of those the walk must refuse, both release-active so the
    /// refusal holds in a shipped build (AGENTS.md rule 8): a scope root, at
    /// either end or inside the moved subtree, and a node the base places
    /// outside that subtree, whose own destination record the re-seal would
    /// overwrite with a wire-supplied body.
    #[test]
    fn the_crossing_re_seal_refuses_a_scope_root_and_a_node_from_outside_the_subtree() {
        let (source, destination) = ends();
        let (source_plane, destination_plane) = (
            source.end().at(SOURCE_EPOCH),
            destination.end().at(DESTINATION_EPOCH),
        );
        let (target, inside, beside) = (NodeId([9; 16]), NodeId([10; 16]), NodeId([11; 16]));
        let base = crossing_base(target, inside, beside);
        let roots = [SOURCE_ROOT, DESTINATION_ROOT, inside];
        let may = |node| {
            crossing_may_reseal(
                &base,
                &roots,
                &source_plane,
                &destination_plane,
                target,
                node,
            )
        };

        for (root, why) in [
            (SOURCE_ROOT, "an end's own scope root"),
            (DESTINATION_ROOT, "at either end"),
            (
                inside,
                "and one a grant minted inside the moved subtree, which this pass can \
                 neither re-key nor re-index",
            ),
        ] {
            assert_eq!(
                may(root),
                Err(Halt::UploadAttempt),
                "{why} is never re-sealed as an interior node"
            );
        }
        assert_eq!(
            may(beside),
            Err(Halt::UploadAttempt),
            "a node the base places outside the subtree is a transplant"
        );
        for node in [target, NodeId([12; 16])] {
            assert_eq!(
                may(node),
                Ok(()),
                "the subtree itself, and a node the base does not place, re-seal"
            );
        }
    }

    /// A scope root's name and its signer seed have independent sources, so a
    /// disagreement is a write rotation landing between the two reads. The next
    /// tick's session material heals it, and charging it would spend the op's
    /// budget on a skew the op did not cause.
    #[test]
    fn a_scope_root_name_skew_waits_rather_than_charging() {
        let (source, destination) = ends();
        let source_plane = source.end().at(SOURCE_EPOCH);

        assert_eq!(
            plane_seals(
                &source_plane,
                SOURCE_ROOT,
                destination.end().root_name,
                true
            ),
            Err(Halt::Unclassified),
            "the root's two name sources disagree, which a refresh repairs"
        );
    }

    /// Retention decides an irreversible purge, so the boundary is stated once
    /// and read off the injected clock. Only a retention the owner chose expires
    /// anything: a `0` turns the bin off rather than emptying it, a settings
    /// load carrying no member choice destroys nothing, and a deadline the clock
    /// has not reached expires nothing.
    #[test]
    fn only_an_elapsed_retention_the_owner_chose_expires_a_bin_entry() {
        let day = DAY_MILLIS;
        assert_eq!(
            bin_expiry_cutoff(UnixMillis(30 * day), None),
            None,
            "a settings load with no member choice destroys nothing",
        );
        assert_eq!(
            bin_expiry_cutoff(UnixMillis(30 * day), Some(0)),
            None,
            "a vault that keeps no bin destroys none of the entries it already has",
        );
        assert_eq!(
            bin_expiry_cutoff(UnixMillis(29 * day), Some(30)),
            None,
            "a deadline the clock has not reached expires nothing",
        );
        assert_eq!(
            bin_expiry_cutoff(UnixMillis(31 * day), Some(30)),
            Some(day),
            "an entry stamped at or before the cutoff has outlived the retention",
        );
    }

    /// The bin index split decides retry against charge for every soft delete,
    /// so a wrong arm either abandons a delete the plane would have taken or
    /// holds the queue head for good. A plane this pass could not read waits
    /// uncharged, and it waits as a reported hold rather than in silence; a
    /// refusal of bytes the plane actually served is charged.
    #[test]
    fn only_a_refusal_of_bytes_the_plane_served_is_charged_against_the_bin_index() {
        for reason in [
            DefaultsReason::RolledBack {
                floor: 4,
                sequence: 2,
            },
            DefaultsReason::RevisionRolledBack {
                floor: 4,
                revision: 2,
            },
            DefaultsReason::Unreadable {
                sequence: 2,
                cause: Unopened::Malformed,
            },
        ] {
            assert_eq!(halt_for_bin_load(reason), Halt::Attempt, "{reason:?}");
        }
        for (reason, check) in [
            (
                DefaultsReason::UnprovenFirstRun,
                BinIndexHoldCheck::UnprovenFirstRun,
            ),
            (DefaultsReason::Suppressed, BinIndexHoldCheck::Suppressed),
            (
                DefaultsReason::Expired {
                    sequence: 2,
                    head: LapsedHead::Opened,
                },
                BinIndexHoldCheck::Expired,
            ),
            (DefaultsReason::TimedOut, BinIndexHoldCheck::TimedOut),
            (
                DefaultsReason::FloorUnreadable,
                BinIndexHoldCheck::FloorUnreadable,
            ),
        ] {
            assert_eq!(
                halt_for_bin_load(reason),
                Halt::HeldByBinIndex(check),
                "{reason:?}",
            );
            assert_eq!(
                upload_failure(halt_for_bin_load(reason)),
                None,
                "{reason:?}: a hold keeps the op rather than reporting a failed attempt",
            );
        }
        assert_eq!(
            halt_for_bin_load(DefaultsReason::StrandedMint),
            Halt::Permanent(DeadLetterReason::BinIndexStrandedMint),
            "a hold no device of a single-device account can lift is a dead letter",
        );
    }

    /// A bin the top rung no longer admits is the member's own state, not a
    /// codec defect and not a spent attempt budget: no re-author shrinks the
    /// body, so the op ends with a reason that names the full bin.
    #[test]
    fn a_bin_index_at_its_ceiling_dead_letters_under_its_own_reason() {
        assert_eq!(
            halt_for_bin_publish(&BinIndexPublishError::Full),
            Halt::Permanent(DeadLetterReason::BinIndexFull),
        );
    }

    /// The publish half of the same split. A lost race and an unanswered
    /// confirm are availability, so a remote party cannot spend the attempt
    /// budget and refuse the owner's delete for good.
    #[test]
    fn a_bin_index_publish_charges_only_what_this_build_authored() {
        assert_eq!(
            halt_for_bin_publish(&BinIndexPublishError::Revision),
            Halt::Attempt
        );
        assert_eq!(
            halt_for_bin_publish(&BinIndexPublishError::Unconfirmed),
            Halt::Unclassified
        );
        assert_eq!(
            halt_for_bin_publish(&BinIndexPublishError::Floor(SeamError::new("offline"))),
            Halt::Unclassified
        );
        assert_eq!(
            halt_for_bin_publish(&BinIndexPublishError::Publish(
                RecordPublishError::Placement(ProviderError::AddressMismatch)
            )),
            classify_publish(
                RecordPublishError::Placement(ProviderError::AddressMismatch),
                0
            ),
            "the member's node fails a bin head as it fails a record head",
        );
    }

    /// The publish leg admits exactly what the read path admits. A block past
    /// the ceiling is refused even though it addresses to its own key, so a
    /// rewritten sidecar buys no hash work and no upload of bytes this build's
    /// own reader rejects.
    #[test]
    fn a_staged_block_past_the_block_ceiling_is_refused_although_it_addresses_to_its_key() {
        let past = vec![7u8; MAX_RESOLVED_RECORD_BYTES + 1];
        let key = compute_cid(CONTENT_CID_CODEC, &past);
        assert_eq!(admissible_staged_block(&key, past), Err(CONTENT_LOST));
    }

    /// The ceiling is inclusive, so the refusal is of blocks past it and not of
    /// the largest block the plane carries.
    #[test]
    fn a_staged_block_at_the_block_ceiling_is_admitted() {
        let at = vec![7u8; MAX_RESOLVED_RECORD_BYTES];
        let key = compute_cid(CONTENT_CID_CODEC, &at);
        assert_eq!(admissible_staged_block(&key, at.clone()), Ok(at));
    }

    /// The address half: bytes the sidecar rewrote no longer answer to the key
    /// the sealed op record names.
    #[test]
    fn staged_bytes_that_do_not_address_to_their_key_are_refused() {
        let block = b"the bytes the op staged".to_vec();
        let key = compute_cid(CONTENT_CID_CODEC, &block);
        assert_eq!(
            admissible_staged_block(&key, b"other bytes entirely".to_vec()),
            Err(CONTENT_LOST)
        );
    }

    fn attempts(charges: &[(u64, u32, u32)]) -> Attempts {
        let mut attempts = Attempts::default();
        for (op_id, publishes, unattributed) in charges {
            for _ in 0..*publishes {
                attempts.charge(OpId(*op_id));
            }
            for _ in 0..*unattributed {
                attempts.charge_unattributed(OpId(*op_id));
            }
        }
        attempts
    }

    fn charges(attempts: u32, unattributed: u32) -> Charges {
        Charges {
            attempts,
            unattributed,
        }
    }

    /// A budget only bounds a pathology if it survives the restart that a
    /// half-published op is most likely to hit — and the two counts are read by
    /// two ceilings, so both have to survive it apart.
    #[test]
    fn the_attempt_record_survives_a_round_trip() {
        let stored = attempts(&[(1, 2, 3), (9, 0, 1)]).encode();
        assert_eq!(
            Attempts::decode(Some(stored)).counts,
            BTreeMap::from([(OpId(1), charges(2, 3)), (OpId(9), charges(0, 1))])
        );
    }

    /// The staging store is shared with whatever build and identity wrote it, so
    /// bytes this build did not write must read as no attempts — a fabricated
    /// count would spend another op's budget and abandon it early.
    #[test]
    fn bytes_this_build_did_not_write_read_as_no_attempts() {
        let foreign_but_well_sized = {
            let mut bytes = attempts(&[(1, 2, 0)]).encode();
            bytes[0] = ATTEMPT_FORMAT_V2.wrapping_add(1);
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
            access_token: crate::content::ByoBearer::None,
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
            assert!(
                matches!(
                    classify_placement(settings),
                    Halt::HeldBySettings(hold) if hold.refusal() == SettingsRefusal::Byo(settings)
                ),
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
            settings_hold(&Ok(Placement::External(refused.clone()))).map(|hold| hold.refusal()),
            Some(SettingsRefusal::Byo(ProviderError::InvalidEndpoint)),
        );
        assert_eq!(
            settings_hold(&Err(PlacementRefusal::NoProvider)).map(|hold| hold.refusal()),
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
            assert_eq!(settings_hold(&admitted), None);
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
        let mut attempts = attempts(&[(1, 3, 0), (2, 1, 4)]);
        attempts.retain_live(&BTreeSet::from([OpId(2)]));
        assert_eq!(attempts.counts, BTreeMap::from([(OpId(2), charges(1, 4))]));
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

    /// The destruction-critical arm: a fan-out that acked nothing, or that
    /// every endpoint refused, may still have stored the record, so its head
    /// stays pinned. Everything else here stopped short of the transport with a
    /// charged row behind it, or with no row at all.
    #[test]
    fn only_a_publish_that_never_reached_the_transport_orphans_its_head() {
        use RecordPublishError::Upload;
        for (error, orphaned) in [
            (
                RecordPublishError::Publish(PublishError::AllEndpointsFailed),
                false,
            ),
            (
                RecordPublishError::Publish(PublishError::AllEndpointsRefused),
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
        assert_eq!(
            classify_publish(
                RecordPublishError::Placement(ProviderError::AddressMismatch),
                4096
            ),
            Halt::UploadAttempt,
            "a member node that stores under another address is a provider fault, as for a content block",
        );
    }

    /// A fork at the sequence a pass built on, where the record the gate passed
    /// carries another envelope version, is no basis for a publish over it.
    /// At this build's version the pass builds on the gate's token at that
    /// sequence, which equals its own.
    #[test]
    fn a_fork_at_another_envelope_version_is_no_publish_basis() {
        let name = derive_write_name(&Zeroizing::new([4; 32]), &[5; 16]);
        let ours = b"our record at 3".to_vec();
        let built_on = (
            Observed::gated(&name, 3, ENVELOPE_V).expect("this build's version"),
            ours.clone(),
        );
        let forked = |version| {
            Some(Served::new(
                3,
                b"another record at 3".to_vec(),
                vec![ours.clone()],
                Some(Observed::gated(&name, 3, version)),
            ))
        };

        assert_eq!(
            publish_basis(forked(ENVELOPE_V + 1), &built_on),
            Err(Halt::ForeignVersion)
        );
        assert_eq!(
            publish_basis(forked(ENVELOPE_V), &built_on),
            Ok(built_on.0.clone())
        );
    }

    /// A record at another envelope version charges no attempt.
    #[test]
    fn a_foreign_version_refusal_charges_no_attempt() {
        assert_eq!(
            classify_publish(
                RecordPublishError::Publish(PublishError::ForeignVersion { version: 2 }),
                4096
            ),
            Halt::ForeignVersion
        );
    }

    /// A bin restore or purge over a record at another envelope version waits
    /// for the update like any other op: its read keeps the version class and
    /// does not dead-letter on the attempt budget.
    #[test]
    fn a_bin_read_over_another_envelope_version_is_not_charged() {
        let refused = RecordPublishError::Publish(PublishError::ForeignVersion { version: 2 });
        let halted = halted_op(
            charge_bin_read(classify_publish(refused, 4096)),
            ATTEMPT_BUDGET,
        );

        assert!(halted.report.dead_letters.is_empty());
        assert_eq!(halted.still_queued, vec![halted.op_id]);
    }

    /// A spent unattributed budget over a record at another envelope version
    /// tells the member to update, not that the op failed too many times.
    #[test]
    fn a_spent_budget_over_another_envelope_version_names_the_newer_release() {
        let halt = || {
            classify_publish(
                RecordPublishError::Publish(PublishError::ForeignVersion { version: 2 }),
                4096,
            )
        };
        let short = halted_op(halt(), UNATTRIBUTED_BUDGET - 1);
        assert!(short.report.dead_letters.is_empty());
        assert_eq!(short.still_queued, vec![short.op_id]);

        let halted = halted_op(halt(), UNATTRIBUTED_BUDGET);
        assert_eq!(
            dead_letter_reasons(&halted.report),
            vec![DeadLetterReason::NewerRelease]
        );
    }

    /// A newer release rewrites the scope root on each write, so the anchor
    /// itself is the record at another envelope version. Its halt reaches the
    /// valve: the head op is bounded by the unattributed budget and is named
    /// a newer release, never left at the head with no bound.
    #[test]
    fn an_anchor_at_another_envelope_version_dead_letters_the_head_as_a_newer_release() {
        let mut root = harness_root_envelope();
        root.v = ENVELOPE_V + 1;
        let harness = drain_harness(Some(root));
        let op = Op::rename(NodeId([9; 16]), "renamed.txt", 1, UnixMillis(0));
        let op_id = harness.queue_an_op(&op);
        let queued = vec![(op_id, op)];
        let drain = harness.drain();
        let scope = harness.scope();
        let mut attempts = Attempts::default();
        let mut report = DrainReport::default();

        let pass = |attempts: &mut Attempts, report: &mut DrainReport| {
            block_on(drain.publish_queue(&scope, &queued, report, attempts))
        };
        assert_eq!(pass(&mut attempts, &mut report), Err(Halt::ForeignVersion));
        assert!(
            report.dead_letters.is_empty(),
            "one pass is inside the budget"
        );
        // The budget's passes but the last, as earlier ticks spend them.
        for _ in 1..UNATTRIBUTED_BUDGET - 1 {
            attempts.charge_unattributed(op_id);
        }
        assert_eq!(pass(&mut attempts, &mut report), Err(Halt::ForeignVersion));

        assert_eq!(
            dead_letter_reasons(&report),
            vec![DeadLetterReason::NewerRelease]
        );
        assert!(harness.queued_op_ids().is_empty());
    }

    fn dead_letter_reasons(report: &DrainReport) -> Vec<DeadLetterReason> {
        report
            .dead_letters
            .iter()
            .map(|(_, _, reason)| *reason)
            .collect()
    }

    /// This build's own refusal of the bytes it would sign repeats on every
    /// retry over the same inputs, so it spends the attempt budget and is never
    /// an outage.
    #[test]
    fn a_produce_side_refusal_costs_an_attempt() {
        for error in [
            PublishError::SequenceExhausted,
            PublishError::BelowBar {
                floor: crate::net::BarFloor::Read,
                at: 2,
                epoch: 1,
            },
            PublishError::EmptyHeadCid,
            PublishError::EmptyInlineValue,
            PublishError::RecordTooLarge {
                size: 10_241,
                limit: 10_240,
            },
        ] {
            assert_eq!(
                classify_publish(RecordPublishError::Publish(error.clone()), 4096),
                Halt::UploadAttempt,
                "{error}"
            );
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

    /// A tick settling many scopes gives each of them a share of its replay
    /// slots: settled first, one scope's backlog would otherwise take them all
    /// and leave the reclamations of the scopes behind it pending.
    #[test]
    fn a_tick_shares_its_journal_replays_across_the_scopes_it_settles() {
        assert_eq!(
            JournalBudget::new(1).replays.share(),
            MAX_JOURNAL_REPLAYS,
            "one scope may spend the whole tick's slots"
        );
        let mut four = JournalBudget::new(4);
        assert!(
            four.replays.share() < MAX_JOURNAL_REPLAYS
                && four.replays.share() * 4 >= MAX_JOURNAL_REPLAYS,
            "four scopes divide them, and every slot is reachable"
        );
        four.replays.spend(MAX_JOURNAL_REPLAYS - 1);
        assert_eq!(
            four.replays.share(),
            1,
            "no scope takes more than the tick has left"
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
            (AuthorError::MissingAscentLink, Halt::UploadAttempt),
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
            (
                AuthorError::ScopeRootNotResealable { size: 2, limit: 1 },
                Halt::ScopeRootNotResealable,
            ),
        ] {
            let check = error.check();
            assert_eq!(classify_author(error), expected, "{check}");
        }
    }

    /// A root with no re-seal room is not an over-large record, and a member
    /// told it is one goes looking for content to remove that is not the cause.
    #[test]
    fn a_root_with_no_re_seal_room_reads_differently_to_the_host_than_an_over_large_one() {
        let no_room = upload_failure(Halt::ScopeRootNotResealable).expect("a reported verdict");
        let oversized = upload_failure(Halt::HeadOversized).expect("a reported verdict");
        assert_ne!(no_room, oversized);
    }

    /// A cut raises a scope's read-epoch floor at once and the lazy wave lifts
    /// the interior behind it, so a node the wave has not reached is below that
    /// floor by construction. The drain carries the wave itself, so the only
    /// lagging node it still holds is one this pass has no ratchet for — held,
    /// never charged, because the pass that reads the root's history links
    /// clears it without the op spending anything.
    #[test]
    fn a_pass_with_no_ratchet_holds_a_lagging_node_rather_than_charging_it() {
        assert_eq!(halt_for_unreachable_epoch(&[]), Halt::EpochLagged);
        assert!(
            upload_failure(Halt::EpochLagged).is_some(),
            "the member is told the write is waiting, never left with silence",
        );
    }

    /// The wave that clears an epoch-lag hold never reaches a binned subtree, so
    /// uncharged it would hold the strict-FIFO head for ever — the silent
    /// permanent stall this class exists to remove.
    #[test]
    fn a_bin_paths_epoch_lag_is_charged_because_no_wave_reaches_a_binned_subtree() {
        assert_eq!(charge_bin_read(Halt::EpochLagged), Halt::UploadAttempt);
        assert_eq!(charge_bin_read(Halt::Unclassified), Halt::UploadAttempt);
        assert_eq!(
            charge_bin_read(Halt::Permanent(DeadLetterReason::TargetGone)),
            Halt::Permanent(DeadLetterReason::TargetGone),
            "an attributable verdict keeps the one its own leg gave it",
        );
    }

    /// A record the retained window does not cover takes the charged verdict —
    /// the one [`ATTEMPT_BUDGET`] bounds and whose dead letter keeps the staged
    /// version — however far back it sits, and the member is told rather than
    /// left with silence.
    #[test]
    fn a_lagging_node_outside_the_retained_window_is_charged_and_bounded() {
        let links = [history_link()];
        let anchor = Anchor {
            epoch: 4,
            history_links: &links,
        };
        assert!(matches!(
            seed_for_lagging([0x44; 16], &[0x66; 32], anchor, 0),
            Err(Halt::UploadAttempt),
        ));
        assert!(upload_failure(Halt::UploadAttempt).is_some());
    }

    fn history_link() -> SignedSealed {
        SignedSealed {
            sealed: vec![0xAB; 40],
            signature: [0x11; 64],
            unknown: PreservedFields::new(),
        }
    }

    /// A record tagged above the pass's own epoch is not behind the wave at all,
    /// so it must not be read as an epoch the ratchet failed to reach: that
    /// would abandon a queued write over an honest race with a root this pass
    /// has not opened on yet.
    #[test]
    fn a_record_above_the_pass_epoch_is_raced_not_abandoned() {
        let links = [history_link()];
        let anchor = Anchor {
            epoch: 4,
            history_links: &links,
        };
        assert!(matches!(
            seed_for_lagging([0x44; 16], &[0x66; 32], anchor, 5),
            Err(Halt::Unclassified),
        ));
    }

    /// The pass's own epoch needs no ratchet step: the session's current seed is
    /// already the one that epoch was sealed at.
    #[test]
    fn a_record_at_the_pass_epoch_opens_without_walking_the_ratchet() {
        let anchor = Anchor {
            epoch: 4,
            history_links: &[],
        };
        assert!(seed_for_lagging([0x44; 16], &[0x66; 32], anchor, 4).is_ok());
    }

    /// A strict-FIFO stall with no dead letter is a liveness defect, never an
    /// accepted outcome (ADR 0012 D6). An op below a keyless scope root is
    /// charged, bounded and reported; one below a root another pass owns, or a
    /// root merely dark this pass, waits with no charge.
    #[test]
    fn an_op_below_a_keyless_scope_root_is_charged_rather_than_stalled() {
        let keyless = [NodeId([0x99; 16])];
        assert_eq!(
            halt_below_another_scope_root(&keyless, true, NodeId([0x99; 16])),
            Halt::UnwritableScope,
        );
        assert_eq!(
            halt_below_another_scope_root(&keyless, true, NodeId([0x22; 16])),
            Halt::Unclassified,
            "a root this pass proved a write plane for is another pass's to publish",
        );
        assert!(
            upload_failure(Halt::UnwritableScope).is_some(),
            "the member is told the write cannot land, never left with silence",
        );
    }

    /// Every pass of a tick reads the same queue and takes the same halt on the
    /// same op, so charging in each would divide the budget by however many
    /// scope write planes happened to open.
    #[test]
    fn only_the_charging_pass_of_a_tick_charges_an_op_below_a_keyless_scope_root() {
        let keyless = [NodeId([0x99; 16])];
        assert_eq!(
            halt_below_another_scope_root(&keyless, false, NodeId([0x99; 16])),
            Halt::Unclassified,
        );
    }

    /// The charge rides the first pass of the tick rather than the vault root's
    /// seeds: an owner holding neither vault seed runs no vault-root pass, and
    /// the op below a keyless scope root would then hold the strict-FIFO head
    /// for ever with no dead letter.
    #[test]
    fn exactly_one_pass_a_tick_takes_the_identity_charge() {
        let seams = OwnerSeams::new();
        let (source, destination) = ends();
        let roots = [SOURCE_ROOT, DESTINATION_ROOT];
        let uncharged = DrainScope {
            charges_the_identity: false,
            ..two_ended(&seams, &source, &destination, &roots)
        };

        for count in 1..=3 {
            let mut passes = vec![uncharged; count];
            charge_the_identity_to_one_pass(&mut passes);
            assert_eq!(
                passes
                    .iter()
                    .filter(|pass| pass.charges_the_identity)
                    .count(),
                1,
                "a tick of {count} passes charges once",
            );
            assert!(
                passes[0].charges_the_identity,
                "and it is the first pass that takes it",
            );
        }
    }

    /// A link that will not open is a walk this pass cannot complete, never a
    /// seed the caller then unseals under — charged and bounded, for the same
    /// reason a window too short to cover the epoch is.
    #[test]
    fn a_lagging_record_behind_a_link_that_will_not_open_is_charged_not_abandoned() {
        let links = [history_link()];
        let anchor = Anchor {
            epoch: 4,
            history_links: &links,
        };
        assert!(matches!(
            seed_for_lagging([0x44; 16], &[0x66; 32], anchor, 3),
            Err(Halt::UploadAttempt),
        ));
    }

    // -----------------------------------------------------------------------
    // The drain harness: one real `Drain` over the test kit's seam fakes, so
    // the pass's own reject arms are drivable from where they live.
    // -----------------------------------------------------------------------

    use core::time::Duration;

    use cipherbox_core::ipns::IpnsRecord;
    use cipherbox_core::seal::{encode_envelope, set_grant_section};
    use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;

    use crate::content::DAG_ROOT_CODEC;
    use crate::grants::grafted::{BookmarkedScopeRoots, ContestedNodes};
    use crate::rotation::{RotateError, RotationOutcome};
    use crate::seams::{EndpointId, OwnerScopedFloorStore, QueueGenerationStore};
    use crate::session::SessionState;
    use crate::testkit::fakes::{
        InMemoryCredentialStore, InMemoryFloorStore, InMemoryRecordStore, InMemorySnapshotCache,
        InMemoryStagingStore, ScriptedHttp, VirtualScheduler,
    };
    use crate::testkit::{
        OWNER_ROOT_EPOCH, OWNER_ROOT_POINTER_READ_KEY, OWNER_ROOT_SCOPE_SEED,
        OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootSpec, SeededEntropy, block_on, gateway,
        owner_root_fixture, owner_root_pseudonym, serve,
    };

    /// The login secret the harness's owner identity, enc secret and bin keys
    /// derive from.
    const HARNESS_SECRET: [u8; 32] = [7u8; 32];
    /// The scope and root node ids [`owner_root_fixture`] seals the vault root
    /// under.
    const HARNESS_SCOPE: [u8; 16] = [0u8; 16];
    const HARNESS_ROOT: NodeId = NodeId([0u8; 16]);
    /// The sequence the cached root record carries. `Strictness::AtFloor`
    /// admits the floor exactly, so the harness raises the floor to match.
    const HARNESS_SEQUENCE: u64 = 1;
    const HARNESS_TTL_NANOS: u64 = 2_000_000_000;
    const HARNESS_EOL: &str = "2099-01-01T00:00:00Z";

    type FakeDrain<'a> = Drain<
        'a,
        InMemoryRecordStore,
        ScriptedHttp,
        InMemoryCredentialStore,
        OwnerScopedFloorStore<InMemoryFloorStore>,
        InMemorySnapshotCache,
        QueueGenerationStore<InMemoryStagingStore>,
        VirtualScheduler,
    >;

    type FakeSeams = EngineSeams<
        InMemoryRecordStore,
        ScriptedHttp,
        InMemoryCredentialStore,
        OwnerScopedFloorStore<InMemoryFloorStore>,
        InMemorySnapshotCache,
        QueueGenerationStore<InMemoryStagingStore>,
        VirtualScheduler,
    >;

    /// Every value a [`Drain`] borrows, owned in one place so a test can hand
    /// out a pass and still drive the seams behind it.
    struct DrainHarness {
        seams: FakeSeams,
        state: SessionState,
        /// Held open: an events channel whose receiver dropped refuses sends.
        events: mpsc::UnboundedReceiver<Event>,
        placement: PlacementDecision,
        bin_keys: BinIndexKeys,
        /// The owner's bin retention, which the expiry sweep acts only on.
        bin_retention_days: Option<u32>,
        root_name: IpnsName,
        read_scope_seed: Zeroizing<[u8; 32]>,
        write_scope_seed: Zeroizing<[u8; 32]>,
        scope_roots: Vec<NodeId>,
        keyless_roots: Vec<NodeId>,
        enc_secret: X25519Secret,
        owner_identity: EcdsaVerifier,
        /// The namespace every pass this harness hands out ratchets its epoch
        /// floors in. `GrantedBy` makes each pass a grafted one.
        floor_namespace: FloorNamespace,
        /// What a grafted pass carries, read only under `GrantedBy`.
        sharer_enc: X25519Public,
        bookmarked_roots: BookmarkedScopeRoots,
        contested: ContestedNodes,
    }

    impl DrainHarness {
        fn drain(&self) -> FakeDrain<'_> {
            Drain::new(
                &self.seams,
                self.state.drain_cells(),
                TickInputs {
                    placement: &self.placement,
                    bin_keys: &self.bin_keys,
                    bin_retention_days: self.bin_retention_days,
                    retention: RetentionPolicy::KeepAll,
                    owed_moves: Some(&[]),
                },
            )
        }

        fn scope(&self) -> DrainScope<'_> {
            self.scope_at(HARNESS_ROOT, self.floor_namespace)
        }

        /// A pass anchored at `root`, grafted exactly when `floor_namespace`
        /// is another identity's. Its records need not resolve: an empty
        /// queue gives the pass nothing to open.
        fn scope_at(&self, root: NodeId, floor_namespace: FloorNamespace) -> DrainScope<'_> {
            DrainScope {
                source: ScopeEnd {
                    root,
                    root_name: &self.root_name,
                    read_scope_seed: &self.read_scope_seed,
                    read_seed_stamp: Some(OWNER_ROOT_EPOCH),
                    write_scope_seed: &self.write_scope_seed,
                    ascent_node_seed: None,
                    floor_namespace,
                },
                destination: None,
                scope_roots: &self.scope_roots,
                keyless_roots: &self.keyless_roots,
                charges_the_identity: false,
                enc_secret: &self.enc_secret,
                owner_identity: &self.owner_identity,
                granted: matches!(floor_namespace, FloorNamespace::GrantedBy(_)).then_some(
                    GrantedPass {
                        sharer_enc: &self.sharer_enc,
                        plane: GraftedPlane {
                            scope_id: root.0,
                            scope_roots: &self.bookmarked_roots,
                            contested: &self.contested,
                        },
                    },
                ),
            }
        }

        fn own_scope_at(&self, root: NodeId) -> DrainScope<'_> {
            self.scope_at(root, FloorNamespace::Own)
        }

        fn grafted_scope_at(&self, root: NodeId) -> DrainScope<'_> {
            self.scope_at(root, FloorNamespace::GrantedBy(sharer_label()))
        }

        /// One tick over `scopes`, with a rotator nothing asks to cut.
        fn tick(&self, scopes: TickScopes<'_>) {
            block_on(self.drain().run_tick(scopes, &RecordingRotator::default()));
        }

        /// Queue one op under the same owner secret the pass reads the queue
        /// with, and answer the id the store assigned it.
        fn queue_an_op(&self, op: &Op) -> OpId {
            block_on(stage_op(
                &self.seams.staging,
                RecordSeal {
                    owner_enc_secret: &self.enc_secret,
                    ephemeral_scalar: Zeroizing::new([0x5A; 32]),
                },
                op,
            ))
            .expect("the op queues")
        }

        fn queued_op_ids(&self) -> Vec<OpId> {
            block_on(self.seams.staging.queued_ops())
                .expect("the queue reads")
                .into_iter()
                .map(|(id, _)| id)
                .collect()
        }
    }

    /// The vault root this harness anchors on, as the fixture authors it.
    fn harness_root_envelope() -> Envelope {
        owner_root_fixture(OwnerRootSpec {
            owner_identity: &EcdsaSigner::from_scalar(&HARNESS_SECRET).expect("valid scalar"),
            owner_enc: &kdf::enc_subkey(&HARNESS_SECRET).public(),
            writer_pseudonym: &owner_root_pseudonym(),
            pointer_read_key: OWNER_ROOT_POINTER_READ_KEY,
            scope_id: HARNESS_SCOPE,
            root_id: HARNESS_ROOT.0,
            children: Vec::new(),
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants: Vec::new(),
        })
        .envelope
    }

    /// A harness whose snapshot cache holds `cached_root` at the scope-root
    /// name, with the head block that record anchors served over the gateway.
    ///
    /// `None` leaves the cache empty, which is the third arm of
    /// [`Drain::load_scope_root`]'s refusal.
    fn drain_harness(cached_root: Option<Envelope>) -> DrainHarness {
        let write_scope_seed = Zeroizing::new(OWNER_ROOT_WRITE_SCOPE_SEED);
        let root_name = derive_write_name(&write_scope_seed, &HARNESS_ROOT.0);
        let enc_secret = kdf::enc_subkey(&HARNESS_SECRET);

        let floors = OwnerScopedFloorStore::new(InMemoryFloorStore::default());
        floors.bind(&enc_secret, &kdf::contact_label_seed(&HARNESS_SECRET));
        let snapshot_cache = InMemorySnapshotCache::default();
        let mut blocks = BTreeMap::new();
        if let Some(envelope) = cached_root {
            let head_block = encode_envelope(&envelope).expect("the fixture encodes");
            let head_cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head_block));
            let signer = kdf::ipns_keypair(
                kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &HARNESS_ROOT.0).as_bytes(),
            );
            let record = IpnsRecord::create_v2(
                &signer,
                format!("/ipfs/{head_cid}").as_bytes(),
                HARNESS_SEQUENCE,
                HARNESS_TTL_NANOS,
                HARNESS_EOL,
            )
            .marshal();
            block_on(snapshot_cache.put(root_name.as_str().as_bytes(), &record))
                .expect("the record caches");
            block_on(floor::advance_on_unseal(
                &floors,
                &HARNESS_ROOT.0,
                root_name.as_str().as_bytes(),
                HARNESS_SEQUENCE,
                OWNER_ROOT_EPOCH,
            ))
            .expect("the floors seed");
            blocks.insert(head_cid, head_block);
        }

        let (events, event_stream) = mpsc::unbounded();
        DrainHarness {
            seams: EngineSeams {
                transport: InMemoryRecordStore::new(vec![EndpointId::new("fake:someguy")]),
                api: Rc::new(ApiClient::new(
                    ScriptedHttp::default(),
                    InMemoryCredentialStore::default(),
                    "",
                )),
                floors,
                snapshot_cache,
                staging: QueueGenerationStore::new(InMemoryStagingStore::default()),
                scheduler: VirtualScheduler::new(),
                http: serve(&blocks),
                gateway: gateway(),
                entropy: Rc::new(RefCell::new(Box::new(SeededEntropy::new(42)))),
                events,
                deadlines: DeadlinePolicy::default(),
                profile: SyncTimingProfile::CI,
                storage_policy: StoragePolicy::CI,
                content_profile: ContentProfile::CI,
            },
            state: SessionState::new(),
            events: event_stream,
            placement: Ok(Placement::Hosted),
            bin_keys: BinIndexKeys::derive(&HARNESS_SECRET),
            bin_retention_days: None,
            root_name,
            read_scope_seed: Zeroizing::new(OWNER_ROOT_SCOPE_SEED),
            write_scope_seed,
            scope_roots: vec![HARNESS_ROOT],
            keyless_roots: Vec::new(),
            enc_secret,
            owner_identity: EcdsaSigner::from_scalar(&HARNESS_SECRET)
                .expect("valid scalar")
                .verifying_key(),
            floor_namespace: FloorNamespace::Own,
            sharer_enc: kdf::enc_subkey(&[0x31; 32]).public(),
            bookmarked_roots: BookmarkedScopeRoots::new(),
            contested: ContestedNodes::new(),
        }
    }

    /// The same harness whose pass runs over a scope another identity granted.
    fn grafted_harness() -> DrainHarness {
        let mut harness = drain_harness(Some(harness_root_envelope()));
        harness.floor_namespace = FloorNamespace::GrantedBy(sharer_label());
        harness
    }

    /// The control the two reject arms are read against: the intact fixture
    /// reaches the grant-section read and comes back with the ratchet, so a
    /// refusal below is the section and not an earlier stage of the load.
    #[test]
    fn an_intact_scope_root_anchors_the_pass_on_its_carried_ratchet() {
        let harness = drain_harness(Some(harness_root_envelope()));
        let drain = harness.drain();
        let scope = harness.scope();

        let loaded = block_on(drain.load_scope_root(&scope.source)).expect("the root loads");

        assert_eq!(loaded.epoch, OWNER_ROOT_EPOCH);
        assert!(loaded.state.commitment.is_some());
    }

    /// A scope root whose grant section is absent or will not decode carries no
    /// backward ratchet, and a pass anchored on it would downgrade every
    /// lagging node of the scope to the uncharged epoch-lag hold instead of
    /// refusing. An absent cache entry is the same refusal for the same reason:
    /// there is no root to anchor on.
    #[test]
    fn a_scope_root_this_pass_cannot_anchor_a_ratchet_on_is_refused() {
        let mut undecodable = harness_root_envelope();
        set_grant_section(&mut undecodable, vec![0xFF; 8]);
        let mut absent = harness_root_envelope();
        let without_section: PreservedFields = absent
            .unknown
            .entries()
            .iter()
            .filter(|(key, _)| key != "grantSection")
            .cloned()
            .collect();
        absent.unknown = without_section;

        for (case, cached) in [
            ("a grant section that does not decode", Some(undecodable)),
            ("no grant section at all", Some(absent)),
            ("no cached record at the root name", None),
        ] {
            let harness = drain_harness(cached);
            let drain = harness.drain();
            let scope = harness.scope();

            assert_eq!(
                block_on(drain.load_scope_root(&scope.source)).err(),
                Some(Halt::Unclassified),
                "{case}",
            );
        }
    }

    /// Open `root` as the harness's cached scope root under a read seed that
    /// does not open it, stamped `stamp`, both as a pass anchor and as the
    /// cached copy: each halt, and how many abuse events it raised.
    fn open_under_a_foreign_seed(root: Envelope, stamp: Option<u64>) -> [(Option<Halt>, usize); 2] {
        let foreign = Zeroizing::new([0x77; 32]);
        let mut harness = drain_harness(Some(root));
        let record = block_on(
            harness
                .seams
                .snapshot_cache
                .get(harness.root_name.as_str().as_bytes()),
        )
        .expect("the cache reads")
        .expect("the root is cached");
        let open = |harness: &DrainHarness, cached: bool| {
            let drain = harness.drain();
            let base = harness.scope();
            let scope = DrainScope {
                source: ScopeEnd {
                    read_scope_seed: &foreign,
                    read_seed_stamp: stamp,
                    ..base.source
                },
                ..base
            };
            if cached {
                block_on(drain.load_scope_root(&scope.source)).err()
            } else {
                block_on(drain.open_root_candidate(&scope, &record)).err()
            }
        };
        [false, true].map(|cached| {
            let answer = open(&harness, cached);
            let reported = drain_events(&mut harness.events)
                .into_iter()
                .filter(|event| matches!(event, Event::AttributableAbuse { .. }))
                .count();
            (answer, reported)
        })
    }

    /// Another owner device rotated to the seed's epoch under its own seed,
    /// and the record's own owner blob opens its body: a race, not abuse. The
    /// anchor waits uncharged and nobody is accused.
    #[test]
    fn a_root_another_owner_seed_opens_at_the_seed_epoch_is_a_race() {
        let [anchored, cached] =
            open_under_a_foreign_seed(harness_root_envelope(), Some(OWNER_ROOT_EPOCH));
        assert_eq!(anchored, (Some(Halt::Unclassified), 0));
        assert_eq!(
            cached,
            (Some(Halt::UploadAttempt), 0),
            "the cached copy reports nothing"
        );
    }

    /// A root whose own owner blob names a seed that does not open its body is
    /// refused and reported at the seed's epoch.
    #[test]
    fn a_root_its_own_seed_does_not_open_at_the_seed_epoch_is_refused() {
        let mut broken = harness_root_envelope();
        let tag = broken.read_sealed.last_mut().expect("a sealed body");
        *tag ^= 0x01;
        let [anchored, cached] = open_under_a_foreign_seed(broken, Some(OWNER_ROOT_EPOCH));
        assert_eq!(anchored, (Some(Halt::RecordRefused), 1));
        assert_eq!(
            cached,
            (Some(Halt::UploadAttempt), 0),
            "the cached copy reports nothing"
        );
    }

    /// At another epoch, or with no stamp, the seed may lag a rotation: the
    /// anchor waits uncharged and nobody is accused.
    #[test]
    fn a_root_the_seed_does_not_open_at_another_epoch_is_a_skew() {
        for stamp in [Some(OWNER_ROOT_EPOCH - 1), None] {
            let [anchored, _] = open_under_a_foreign_seed(harness_root_envelope(), stamp);
            assert_eq!(anchored, (Some(Halt::Unclassified), 0), "stamp {stamp:?}");
        }
    }

    /// A quota hold's exit is a probe, and a placement the session cannot use
    /// answers that probe in two different ways. A refusal of the member's own
    /// settings is a verdict: the pass re-takes the hold its own rule names, so
    /// the member is not left reading "over quota" over a cause they cannot act
    /// on. An outage is not a verdict, and letting the head run would spend the
    /// unattributed budget on a placement no pass can decide.
    #[test]
    fn a_quota_hold_lets_go_of_a_refusing_placement_and_waits_out_an_undecided_one() {
        let node = NodeId([9; 16]);
        let queued = vec![(OpId(1), Op::rename(node, "renamed.txt", 1, UnixMillis(0)))];
        let over_quota = QueueHold {
            op_id: OpId(1),
            node,
            reason: QueueHoldReason::Quota { needed_bytes: 4096 },
        };

        let mut refusing = drain_harness(None);
        refusing.placement = Err(PlacementRefusal::NoProvider);
        *refusing.state.queue_hold.borrow_mut() = Some(over_quota);
        assert!(block_on(refusing.drain().hold_admits_the_head(&queued)));
        assert_eq!(
            *refusing.state.queue_hold.borrow(),
            None,
            "the settings refusal is what the next pass names",
        );

        let mut undecided = drain_harness(None);
        undecided.placement = Err(PlacementRefusal::SettingsUnavailable(
            DefaultsReason::Suppressed,
        ));
        *undecided.state.queue_hold.borrow_mut() = Some(over_quota);
        assert!(!block_on(undecided.drain().hold_admits_the_head(&queued)));
        assert_eq!(
            *undecided.state.queue_hold.borrow(),
            Some(over_quota),
            "an outage leaves the head held rather than charging it",
        );
    }

    /// The hold cell is the tick's, and a tick runs one pass per proved scope
    /// over one identity-wide queue. A pass whose scope does not author the
    /// held op halts on it with no verdict about the bin plane, so it must not
    /// drop the hold an earlier pass of the same tick took — the head would
    /// then wait with no cause the member can see.
    #[test]
    fn a_later_pass_of_the_same_tick_does_not_drop_another_pass_bin_index_hold() {
        let node = NodeId([9; 16]);
        let op = Op::rename(node, "renamed.txt", 1, UnixMillis(0));
        let held = QueueHold {
            op_id: OpId(1),
            node,
            reason: QueueHoldReason::BinIndex(BinIndexHoldCheck::Suppressed),
        };

        for (case, halted, halt) in [
            (
                "another scope's pass halts on an op of its own",
                OpId(2),
                Halt::Unclassified,
            ),
            (
                "a pass that cannot author the held op refuses it",
                OpId(1),
                Halt::Unclassified,
            ),
        ] {
            let harness = drain_harness(Some(harness_root_envelope()));
            *harness.state.queue_hold.borrow_mut() = Some(held);
            block_on(harness.drain().apply_valve(
                &harness.scope(),
                halted,
                &op,
                halt,
                &mut Attempts::default(),
                &mut DrainReport::default(),
            ));
            assert_eq!(*harness.state.queue_hold.borrow(), Some(held), "{case}");
        }

        let harness = drain_harness(Some(harness_root_envelope()));
        *harness.state.queue_hold.borrow_mut() = Some(held);
        block_on(harness.drain().apply_valve(
            &harness.scope(),
            OpId(1),
            &op,
            Halt::EpochLagged,
            &mut Attempts::default(),
            &mut DrainReport::default(),
        ));
        assert_eq!(
            *harness.state.queue_hold.borrow(),
            None,
            "a classified verdict on the held op is the hold's own exit",
        );
    }

    /// A grafted scope root is planted parentless, so the ancestor chain of
    /// anything below it never reaches the vault root and no walk from that
    /// root can prove it. The pass routes by its own listed roots, so the
    /// grafted root has to be one of them: without it the op halts
    /// unclassified, and the wide outage budget retries that halt while it
    /// holds the strict FIFO head.
    #[test]
    fn a_parentless_scope_root_classifies_only_when_the_pass_routes_by_it() {
        const VAULT: NodeId = NodeId([0x01; 16]);
        const FOLDER: NodeId = NodeId([0x6b; 16]);

        let mut grafted = Snapshot::new(VAULT);
        for (id, name) in [(HARNESS_ROOT, "shared"), (FOLDER, "sub")] {
            grafted.upsert_node(NodeMeta::new(id, name, crate::facade::NodeKind::Folder));
        }
        grafted.link_next(HARNESS_ROOT, FOLDER);

        for (case, roots, routed) in [
            ("the pass lists the grafted root", vec![HARNESS_ROOT], true),
            ("the pass lists the vault root only", vec![VAULT], false),
        ] {
            for (target, target_case) in [
                (HARNESS_ROOT, "at the grafted root"),
                (FOLDER, "below the grafted root"),
            ] {
                let mut harness = drain_harness(Some(harness_root_envelope()));
                harness.state.snapshot = Rc::new(BaseSnapshot::new(grafted.clone()));
                harness.scope_roots = roots.clone();
                let drain = harness.drain();
                let scope = harness.scope();
                let mut pass = Pass {
                    root: HARNESS_ROOT,
                    epoch: OWNER_ROOT_EPOCH,
                    history_links: Vec::new(),
                    second_ratchet: None,
                    folders: Vec::new(),
                    journalled: Vec::new(),
                };

                let plane = block_on(drain.ensure_folder(&scope, &mut pass, target));

                if target == HARNESS_ROOT {
                    match routed {
                        true => assert_eq!(
                            plane.map(|plane| plane.end.root).ok(),
                            Some(HARNESS_ROOT),
                            "{case}",
                        ),
                        false => assert_eq!(plane.err(), Some(Halt::Unclassified), "{case}"),
                    }
                }
                // The routing is the nearest listed root over the whole ancestor
                // chain, not the target itself: a folder below the parentless
                // root opens that root too. This harness serves no body for the
                // folder, so the root the pass holds is what the chain proves.
                assert_eq!(pass.holds(HARNESS_ROOT), routed, "{case}, {target_case}");
            }
        }
    }

    /// The bin sweep runs once per proved scope, so a per-pass bound would let
    /// a tick stage its whole share again for every scope the owner holds.
    #[test]
    fn a_tick_shares_its_bin_expiries_across_the_scopes_it_drains() {
        let one = TickShare::new(MAX_BIN_EXPIRIES, 1);
        assert_eq!(
            one.share(),
            MAX_BIN_EXPIRIES,
            "one scope may stage the whole tick's purges"
        );

        let mut four = TickShare::new(MAX_BIN_EXPIRIES, 4);
        let mut staged = 0;
        while four.share() > 0 {
            let taken = four.share();
            staged += taken;
            four.spend(taken);
        }
        assert_eq!(
            staged, MAX_BIN_EXPIRIES,
            "four passes divide one tick's purges rather than taking one each"
        );
    }

    /// What a run of halted passes over one queued op left behind.
    struct Halted {
        report: DrainReport,
        attempts: Attempts,
        op_id: OpId,
        still_queued: Vec<OpId>,
    }

    /// Queue one op, then stop `passes` passes on it under `halt`.
    fn halted_op(halt: Halt, passes: u32) -> Halted {
        let harness = drain_harness(Some(harness_root_envelope()));
        let op = Op::rename(NodeId([9; 16]), "renamed.txt", 1, UnixMillis(0));
        let op_id = harness.queue_an_op(&op);
        let drain = harness.drain();
        let scope = harness.scope();
        let mut attempts = Attempts::default();
        let mut report = DrainReport::default();

        for _ in 0..passes {
            block_on(drain.apply_valve(&scope, op_id, &op, halt, &mut attempts, &mut report));
        }
        Halted {
            report,
            attempts,
            op_id,
            still_queued: harness.queued_op_ids(),
        }
    }

    #[test]
    fn bin_recovery_without_an_owning_pass_exhausts_one_budget_per_tick() {
        let mut harness = drain_harness(Some(harness_root_envelope()));
        let target = NodeId([0x45; 16]);
        let op = Op::delete(target, 1, UnixMillis(0), 1, true);
        let op_id = harness.queue_an_op(&op);
        let mut index = BinIndex::new(1);
        index.entries.push(BinEntry::new(
            target.0,
            derive_write_name(&harness.write_scope_seed, &target.0)
                .as_str()
                .as_bytes()
                .to_vec(),
            NodeKind::File,
            HARNESS_ROOT.0,
            "stranded.txt".to_owned(),
            0,
            [0x99; 16],
            None,
        ));
        let block = cipherbox_core::seal::seal_bin_index(
            kdf::bin_index_seal_key(&HARNESS_SECRET).as_bytes(),
            &[0x55; 24],
            &index,
        )
        .unwrap();
        let cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));
        let record = IpnsRecord::create_v2(
            &kdf::bin_index_ipns_keypair(&HARNESS_SECRET),
            format!("/ipfs/{cid}").as_bytes(),
            1,
            HARNESS_TTL_NANOS,
            HARNESS_EOL,
        )
        .marshal();
        for endpoint in harness.seams.transport.endpoints() {
            harness.seams.transport.seed_record(
                &endpoint,
                harness.bin_keys.name().as_str(),
                record.clone(),
            );
        }
        harness.seams.http = ScriptedHttp::default();
        for _ in 0..UNATTRIBUTED_BUDGET * 3 {
            harness
                .seams
                .http
                .enqueue_response(crate::seams::HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: block.clone().into(),
                });
        }
        let drain = harness.drain();
        let first = DrainScope {
            charges_the_identity: true,
            ..harness.scope()
        };
        let later = harness.scope();
        let mut attempts = Attempts::default();
        let mut report = DrainReport::default();
        for _ in 0..UNATTRIBUTED_BUDGET - 1 {
            for scope in [&first, &later, &later] {
                let halt = block_on(drain.finish_binned_delete(scope, &harness_pass(), target))
                    .unwrap_err();
                assert_eq!(halt, Halt::OtherBinScope);
                block_on(drain.apply_valve(scope, op_id, &op, halt, &mut attempts, &mut report));
            }
        }
        assert_eq!(harness.queued_op_ids(), vec![op_id]);
        assert!(report.dead_letters.is_empty());
        let halt =
            block_on(drain.finish_binned_delete(&first, &harness_pass(), target)).unwrap_err();
        block_on(drain.apply_valve(&first, op_id, &op, halt, &mut attempts, &mut report));
        assert!(harness.queued_op_ids().is_empty());
        assert_eq!(
            report.dead_letters,
            vec![(op_id, target, DeadLetterReason::AttemptsExhausted)]
        );
    }

    /// An outage must not abandon an op, so a halt the valve cannot attribute
    /// keeps its place at the head of the queue for a whole outage's worth of
    /// passes — and then leaves, because strict FIFO means a halt that never
    /// clears holds every op behind it with nothing the member can act on.
    #[test]
    fn an_unattributed_halt_is_charged_on_its_own_budget_and_then_dead_letters() {
        let inside = halted_op(Halt::Unclassified, UNATTRIBUTED_BUDGET - 1);
        assert!(
            inside.report.dead_letters.is_empty(),
            "still inside the budget"
        );
        assert_eq!(
            inside.still_queued,
            vec![inside.op_id],
            "the op keeps its place at the head",
        );

        let spent = halted_op(Halt::Unclassified, UNATTRIBUTED_BUDGET);
        assert_eq!(
            spent.report.dead_letters,
            vec![(
                spent.op_id,
                NodeId([9; 16]),
                DeadLetterReason::AttemptsExhausted
            )],
        );
        assert!(spent.still_queued.is_empty(), "the queue moves on");
    }

    /// The two budgets are spent apart. A publish attempt is what tells
    /// [`Drain::create_replays_a_publish`] this device already reached the
    /// record plane, so an outage that spent one would suppress the
    /// already-published verdict a restored data directory depends on.
    #[test]
    fn an_unattributed_halt_leaves_the_publish_attempt_budget_untouched() {
        let outage = halted_op(Halt::Unclassified, ATTEMPT_BUDGET);
        assert_eq!(outage.attempts.charged_to(outage.op_id), 0);
        assert!(outage.report.dead_letters.is_empty());

        let refused = halted_op(Halt::UploadAttempt, ATTEMPT_BUDGET);
        assert_eq!(
            refused.attempts.charged_to(refused.op_id),
            ATTEMPT_BUDGET,
            "a refusal of these bytes still spends the tighter budget",
        );
        assert_eq!(refused.report.dead_letters.len(), 1);
    }

    // -----------------------------------------------------------------------
    // A grafted pass reaches no surface of this vault above its grafted root.
    // -----------------------------------------------------------------------

    /// A contact whose grant this vault holds, and the label its floors ratchet
    /// under.
    const SHARER_IDENTITY_PK: [u8; IDENTITY_PUBLIC_LEN] = [0x02; IDENTITY_PUBLIC_LEN];

    fn sharer_label() -> crate::seams::ContactLabel {
        crate::seams::ContactLabel::of(
            &kdf::contact_label_seed(&HARNESS_SECRET),
            &SHARER_IDENTITY_PK,
        )
    }

    /// An empty pass anchored on the harness's root, for the plans that refuse
    /// before they read anything.
    fn harness_pass() -> Pass {
        Pass {
            root: HARNESS_ROOT,
            epoch: OWNER_ROOT_EPOCH,
            history_links: Vec::new(),
            second_ratchet: None,
            folders: Vec::new(),
            journalled: Vec::new(),
        }
    }

    fn applied(op: Op, effective_name: Option<&str>) -> AppliedOp {
        AppliedOp {
            op_id: OpId(1),
            op,
            effective_name: effective_name.map(str::to_owned),
            suffixed: false,
            vacated: None,
        }
    }

    /// Every op plan that ends on the owner's bin index above the grafted root:
    /// a soft delete, a restore and a purge. A hard delete is a grantee's
    /// unlink, which reaches no such surface. The refusal is a plain `Err`
    /// return rather than an assertion, so it fires in every build profile
    /// (AGENTS.md rule 8).
    #[test]
    fn a_grafted_pass_is_refused_every_vault_level_op_plan() {
        const TARGET: NodeId = NodeId([0x41; 16]);
        let plans = [
            ("a soft delete writes the owner's bin index", {
                Op::delete(TARGET, 1, UnixMillis(0), 1, true)
            }),
            (
                "a restore reads the bin index and drops its entry",
                Op::restore(
                    TARGET,
                    HARNESS_ROOT,
                    "restored.txt",
                    crate::facade::NodeKind::File,
                    1,
                    UnixMillis(0),
                ),
            ),
            (
                "a purge reads the bin index and reclaims from it",
                Op::purge(TARGET, 7, 1, UnixMillis(0)),
            ),
        ];

        for (case, op) in plans {
            let grafted = grafted_harness();
            let refused = block_on(grafted.drain().publish_applied(
                &grafted.scope(),
                &mut harness_pass(),
                &applied(op.clone(), Some("restored.txt")),
                &Snapshot::new(HARNESS_ROOT),
            ));
            assert_eq!(
                refused.err(),
                Some(Halt::Permanent(DeadLetterReason::GraftedScopeVaultSurface)),
                "{case}",
            );

            let own = drain_harness(Some(harness_root_envelope()));
            let reached = block_on(own.drain().publish_applied(
                &own.scope(),
                &mut harness_pass(),
                &applied(op, Some("restored.txt")),
                &Snapshot::new(HARNESS_ROOT),
            ));
            assert_ne!(
                reached.err(),
                Some(Halt::Permanent(DeadLetterReason::GraftedScopeVaultSurface)),
                "an own-vault pass still reaches the surface: {case}",
            );
        }
    }

    /// The version plans reach the same ledger through their own door, ahead of
    /// the shortened history they journal for.
    #[test]
    fn a_grafted_pass_journals_no_retire_debt() {
        const TARGET: NodeId = NodeId([0x42; 16]);

        let grafted = grafted_harness();
        assert_eq!(
            block_on(
                grafted
                    .drain()
                    .journal_retire_debt(&grafted.scope(), TARGET, &[])
            )
            .err(),
            Some(Halt::Permanent(DeadLetterReason::GraftedScopeVaultSurface)),
        );

        let own = drain_harness(Some(harness_root_envelope()));
        block_on(own.drain().journal_retire_debt(&own.scope(), TARGET, &[]))
            .expect("an own-vault pass owes its own ledger");
    }

    /// One unlink a poll leg observed, named under the scope root's own write
    /// seed so [`Drain::take_captures`] admits it.
    fn capture(write_scope_seed: &[u8; 32]) -> UnlinkedChild {
        capture_of(write_scope_seed, NodeId([0x43; 16]))
    }

    /// [`capture`] of `node`.
    fn capture_of(write_scope_seed: &[u8; 32], node: NodeId) -> UnlinkedChild {
        UnlinkedChild {
            scope_id: HARNESS_ROOT.0,
            parent: NodeId([0x44; 16]),
            node,
            name: "departed.txt".to_owned(),
            kind: NodeKind::File,
            ipns_name: derive_write_name(write_scope_seed, &node.0)
                .as_str()
                .as_bytes()
                .to_vec(),
            deleted_at: 9,
        }
    }

    #[test]
    fn a_capture_with_a_standing_entry_in_another_scope_waits_before_rekeying() {
        for entry_scope in [HARNESS_ROOT.0, [0x99; 16]] {
            let mut harness = drain_harness(Some(harness_root_envelope()));
            let unlinked = capture(&harness.write_scope_seed);
            let target_name = derive_write_name(&harness.write_scope_seed, &unlinked.node.0);
            let mut index = BinIndex::new(1);
            index.entries.push(BinEntry::new(
                unlinked.node.0,
                unlinked.ipns_name.clone(),
                unlinked.kind,
                unlinked.parent.0,
                unlinked.name.clone(),
                1,
                entry_scope,
                None,
            ));
            let block = cipherbox_core::seal::seal_bin_index(
                kdf::bin_index_seal_key(&HARNESS_SECRET).as_bytes(),
                &[0x55; 24],
                &index,
            )
            .unwrap();
            let cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));
            let record = IpnsRecord::create_v2(
                &kdf::bin_index_ipns_keypair(&HARNESS_SECRET),
                format!("/ipfs/{cid}").as_bytes(),
                1,
                HARNESS_TTL_NANOS,
                HARNESS_EOL,
            )
            .marshal();
            serve_harness_root(&harness);
            for endpoint in harness.seams.transport.endpoints() {
                harness.seams.transport.seed_record(
                    &endpoint,
                    harness.bin_keys.name().as_str(),
                    record.clone(),
                );
            }
            let root = encode_envelope(&harness_root_envelope()).unwrap();
            let root_cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &root));
            harness.seams.http = serve(&BTreeMap::from([(cid, block), (root_cid, root)]));
            *harness.state.observed_unlinks.borrow_mut() = vec![unlinked.clone()];
            block_on(
                harness
                    .drain()
                    .adopt_observed_unlinks(&harness.scope(), &[]),
            );
            let retained = harness.state.observed_unlinks.borrow();
            assert_eq!(retained.len(), 1);
            assert_eq!(
                (
                    retained[0].node,
                    retained[0].scope_id,
                    retained[0].deleted_at
                ),
                (unlinked.node, unlinked.scope_id, unlinked.deleted_at)
            );
            assert_eq!(
                harness.seams.transport.get_count(target_name.as_str()) > 0,
                entry_scope == HARNESS_ROOT.0,
                "only a same-scope capture may begin resolving the subtree for re-keying",
            );
        }
    }

    /// An interior scope's walk starts at the vault root when the tick holds
    /// the vault end. With no vault end it cannot read the scopes above, so it
    /// proves nothing.
    #[test]
    fn an_interior_capture_walk_starts_at_the_vault_root_or_proves_nothing() {
        let harness = drain_harness(Some(harness_root_envelope()));
        let ascent = Zeroizing::new([0x31; 32]);
        let mut interior = harness.scope();
        interior.source.root = NodeId([0x32; 16]);
        interior.source.ascent_node_seed = Some(&ascent);
        let vault = harness.scope().source;
        let cohort = BTreeSet::from([(NodeId([0x43; 16]), 9)]);

        let walk = CaptureWalk::from_vault_root(&interior, &[], cohort.clone());
        assert!(walk.blind, "no vault end: the walk proves nothing");

        let walk = CaptureWalk::from_vault_root(&interior, &[interior.source, vault], cohort);
        assert!(!walk.blind);
        assert_eq!(walk.pending, vec![(vault.root, vault.root)]);
    }

    /// A read-granted scope root shares its parent scope's write seed, so its
    /// name passes the name check. Its capture still drops before any read.
    #[test]
    fn a_capture_of_a_proved_scope_root_drops_unread() {
        let mut harness = drain_harness(Some(harness_root_envelope()));
        let unlinked = capture(&harness.write_scope_seed);
        harness.scope_roots.push(unlinked.node);
        *harness.state.observed_unlinks.borrow_mut() = vec![unlinked.clone()];
        block_on(
            harness
                .drain()
                .adopt_observed_unlinks(&harness.scope(), &[]),
        );
        assert!(harness.state.observed_unlinks.borrow().is_empty());
        assert_eq!(
            harness
                .seams
                .transport
                .get_count(derive_write_name(&harness.write_scope_seed, &unlinked.node.0).as_str()),
            0,
            "the drain reads nothing for a scope root"
        );
    }

    /// Serve the harness root's cached record from the record plane, which the
    /// capture walk reads.
    fn serve_harness_root(harness: &DrainHarness) {
        let root_name = derive_write_name(&harness.write_scope_seed, &HARNESS_ROOT.0);
        let record = block_on(
            harness
                .seams
                .snapshot_cache
                .get(root_name.as_str().as_bytes()),
        )
        .unwrap()
        .expect("the harness caches its root");
        for endpoint in harness.seams.transport.endpoints() {
            harness
                .seams
                .transport
                .seed_record(&endpoint, root_name.as_str(), record.clone());
        }
    }

    /// A folder ref named under the harness scope's write seed.
    fn harness_folder_ref(folder: NodeId) -> ChildRef {
        ChildRef {
            id: folder.0,
            name: format!("folder {}", folder.0[0]),
            ipns_name: derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &folder.0)
                .as_str()
                .as_bytes()
                .to_vec(),
            kind: NodeKind::Folder,
            link_counter: 1,
            unknown: PreservedFields::new(),
        }
    }

    /// A block's CID, and the step to run when the drain fetches it.
    type BlockHook = Option<(String, Box<dyn FnOnce()>)>;

    thread_local! {
        /// A step a test runs inside the drain's await on one block, keyed by
        /// the block's CID.
        static ON_BLOCK: RefCell<BlockHook> = const { RefCell::new(None) };
    }

    /// Serve `blocks` for every read a walk makes, and run the [`ON_BLOCK`]
    /// step when its block is fetched.
    fn serve_walk_blocks(blocks: &BTreeMap<String, Vec<u8>>) -> ScriptedHttp {
        let blocks = std::sync::Arc::new(blocks.clone());
        ScriptedHttp::with_route(move |request| {
            let cid = crate::testkit::requested_cid(&request.url);
            let step = ON_BLOCK.with(|hook| {
                let mut hook = hook.borrow_mut();
                match hook.as_ref() {
                    Some((armed, _)) if *armed == cid => hook.take().map(|(_, step)| step),
                    _ => None,
                }
            });
            if let Some(step) = step {
                step();
            }
            Some(match blocks.get(&cid) {
                Some(block) => Ok(crate::seams::HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: block.clone().into(),
                }),
                None => Err(crate::seams::SeamError::new("no such block")),
            })
        })
    }

    /// Publish `folder` in the harness scope at `sequence` naming `children`,
    /// serve every block in `blocks` with its head block added, and answer
    /// that head block's CID.
    fn publish_harness_folder(
        harness: &mut DrainHarness,
        blocks: &mut BTreeMap<String, Vec<u8>>,
        folder: NodeId,
        sequence: u64,
        children: Vec<ChildRef>,
    ) -> String {
        let body = ReadBody::Folder {
            created_at: 1,
            modified_at: sequence,
            children,
            unknown: PreservedFields::new(),
        };
        let read_key = harness.scope().source.read_key(&folder.0);
        let head = author_child_envelope(EnvelopeAuthoring {
            node_id: folder.0,
            scope_id: HARNESS_ROOT.0,
            epoch: OWNER_ROOT_EPOCH,
            read_key: &read_key,
            nonce: &[7; 24],
            body: &body,
            carried_unknown: PreservedFields::new(),
            carried_epoch_tag_unknown: PreservedFields::new(),
        })
        .expect("a child folder record");
        let record = IpnsRecord::create_v2(
            &kdf::ipns_keypair(kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &folder.0).as_bytes()),
            format!("/ipfs/{}", head.cid).as_bytes(),
            sequence,
            HARNESS_TTL_NANOS,
            HARNESS_EOL,
        )
        .marshal();
        let name = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &folder.0);
        for endpoint in harness.seams.transport.endpoints() {
            harness
                .seams
                .transport
                .seed_record(&endpoint, name.as_str(), record.clone());
        }
        blocks.insert(head.cid.clone(), head.block.clone());
        harness.seams.http = serve_walk_blocks(blocks);
        head.cid.clone()
    }

    /// The one folder below the [`walk_harness`] root.
    const WALK_FOLDER: NodeId = NodeId([0x46; 16]);

    /// A harness whose root names one folder, `WALK_FOLDER`, published at sequence
    /// 1, with both records served from the record plane and one capture held.
    fn walk_harness() -> (DrainHarness, BTreeMap<String, Vec<u8>>) {
        walk_harness_of(&[WALK_FOLDER])
    }

    /// [`walk_harness`] whose root names each of `folders`.
    fn walk_harness_of(folders: &[NodeId]) -> (DrainHarness, BTreeMap<String, Vec<u8>>) {
        let envelope = owner_root_fixture(OwnerRootSpec {
            owner_identity: &EcdsaSigner::from_scalar(&HARNESS_SECRET).expect("valid scalar"),
            owner_enc: &kdf::enc_subkey(&HARNESS_SECRET).public(),
            writer_pseudonym: &owner_root_pseudonym(),
            pointer_read_key: OWNER_ROOT_POINTER_READ_KEY,
            scope_id: HARNESS_SCOPE,
            root_id: HARNESS_ROOT.0,
            children: folders.iter().copied().map(harness_folder_ref).collect(),
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants: Vec::new(),
        })
        .envelope;
        let root_block = encode_envelope(&envelope).expect("the fixture encodes");
        let mut blocks = BTreeMap::from([(
            encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &root_block)),
            root_block,
        )]);
        let mut harness = drain_harness(Some(envelope));
        serve_harness_root(&harness);
        for folder in folders {
            publish_harness_folder(&mut harness, &mut blocks, *folder, 1, Vec::new());
        }
        *harness.state.observed_unlinks.borrow_mut() = vec![capture(&harness.write_scope_seed)];
        (harness, blocks)
    }

    /// One pass of the drain's capture path under walk bounds a fixture reaches.
    fn walk_pass(harness: &DrainHarness, reads: usize, folders: usize) {
        block_on(
            harness
                .drain()
                .with_capture_walk_bounds(reads, folders)
                .adopt_observed_unlinks(&harness.scope(), &[]),
        );
    }

    fn reads_of(harness: &DrainHarness, node: NodeId) -> usize {
        harness
            .seams
            .transport
            .get_count(derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &node.0).as_str())
    }

    /// The second read of a folder serves another record at the sequence of the
    /// first. It names a folder the walk never read, and that folder names the
    /// capture, so the walk is no snapshot and starts again.
    #[test]
    fn a_second_read_of_another_record_at_one_sequence_starts_the_walk_again() {
        let (mut harness, mut blocks) = walk_harness();
        let target = capture(&harness.write_scope_seed).node;
        let hidden = NodeId([0x48; 16]);
        publish_harness_folder(
            &mut harness,
            &mut blocks,
            hidden,
            1,
            vec![harness_folder_ref(target)],
        );
        let folder = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &WALK_FOLDER.0);
        let endpoints = harness.seams.transport.endpoints();
        let served = harness
            .seams
            .transport
            .record_at(&endpoints[0], folder.as_str())
            .expect("the walk folder is published");
        publish_harness_folder(
            &mut harness,
            &mut blocks,
            WALK_FOLDER,
            1,
            vec![harness_folder_ref(hidden)],
        );
        let fork = harness
            .seams
            .transport
            .record_at(&endpoints[0], folder.as_str())
            .expect("the fork is published");
        for endpoint in &endpoints {
            harness
                .seams
                .transport
                .seed_record(endpoint, folder.as_str(), served.clone());
        }
        harness.seams.transport.serve_gets_for_after(
            folder.as_str(),
            endpoints.len(),
            endpoints.len(),
            Some(fork),
        );

        walk_pass(&harness, MAX_CAPTURE_WALK_READS, MAX_CAPTURE_WALK_NODES);

        assert_eq!(
            reads_of(&harness, hidden),
            0,
            "the walk never read the folder only the fork names"
        );
        assert_eq!(
            reads_of(&harness, target),
            0,
            "a walk that read two records at one sequence proves nothing"
        );
    }

    /// A read that goes unanswered for one pass is tried again, so the walk
    /// settles without a new start at the root.
    #[test]
    fn a_walk_retries_an_unanswered_read_rather_than_starting_again() {
        let (harness, _) = walk_harness();
        let target = capture(&harness.write_scope_seed).node;
        let folder = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &WALK_FOLDER.0);
        let endpoints = harness.seams.transport.endpoints().len();
        harness
            .seams
            .transport
            .serve_gets_for_after(folder.as_str(), 0, endpoints, None);

        walk_pass(&harness, MAX_CAPTURE_WALK_READS, MAX_CAPTURE_WALK_NODES);
        assert_eq!(reads_of(&harness, target), 0, "the walk has not settled");
        walk_pass(&harness, MAX_CAPTURE_WALK_READS, MAX_CAPTURE_WALK_NODES);

        assert_eq!(
            reads_of(&harness, HARNESS_ROOT),
            2,
            "one read and one second read of the root: no new walk"
        );
        assert!(
            reads_of(&harness, target) > 0,
            "the walk settled and the re-key started"
        );
    }

    /// One scope may hold only its share of the bounded set, so a scope whose
    /// walk never settles leaves room for the captures of another scope.
    #[test]
    fn a_scope_at_its_cap_leaves_room_for_another_scopes_capture() {
        let set = RefCell::new(Vec::new());
        let crowded = (0..MAX_HELD_CAPTURES as u64).map(|index| {
            let mut node = [0u8; 16];
            node[..8].copy_from_slice(&index.to_be_bytes());
            let mut unlinked = capture(&OWNER_ROOT_WRITE_SCOPE_SEED);
            unlinked.node = NodeId(node);
            unlinked
        });
        hold_captures(&set, crowded.collect());
        let mut other = capture(&OWNER_ROOT_WRITE_SCOPE_SEED);
        other.scope_id = [0x99; 16];
        hold_captures(&set, vec![other]);

        assert!(
            set.borrow()
                .iter()
                .any(|unlinked| unlinked.scope_id == [0x99; 16]),
            "the other scope's capture is held"
        );
    }

    /// A read leg can link a proved capture again while the drain awaits its
    /// re-keys. The base check before each re-key keeps that node out of the
    /// bin.
    #[test]
    fn a_node_a_read_leg_links_during_the_re_keys_is_not_re_keyed() {
        let (mut harness, mut blocks) = walk_harness();
        let first = capture(&harness.write_scope_seed).node;
        let second = NodeId([0x47; 16]);
        harness
            .state
            .observed_unlinks
            .borrow_mut()
            .push(capture_of(&harness.write_scope_seed, second));
        let first_head = publish_harness_folder(&mut harness, &mut blocks, first, 1, Vec::new());
        let base = Rc::clone(&harness.state.snapshot);
        let relink: Box<dyn FnOnce()> = Box::new(move || {
            let mut base = base.borrow_mut();
            base.upsert_node(crate::sync::model::NodeMeta::new(
                second,
                "relinked",
                crate::facade::NodeKind::File,
            ));
            base.link(HARNESS_ROOT, second, 1);
        });
        ON_BLOCK.with(|hook| *hook.borrow_mut() = Some((first_head, relink)));

        walk_pass(&harness, MAX_CAPTURE_WALK_READS, MAX_CAPTURE_WALK_NODES);

        assert!(
            ON_BLOCK.with(|hook| hook.borrow().is_none()),
            "the read leg ran inside the first re-key"
        );
        assert_eq!(
            reads_of(&harness, second),
            0,
            "the node linked during the re-keys is not re-keyed"
        );
    }

    /// One walk proves every held capture of its scope. The ones past the
    /// adoption bound keep their proof for a later slot.
    #[test]
    fn one_walk_proves_more_captures_than_one_pass_adopts() {
        let (harness, _) = walk_harness();
        let captures = (0..=MAX_BIN_ADOPTIONS as u8)
            .map(|index| capture_of(&harness.write_scope_seed, NodeId([0x60 + index; 16])))
            .collect();
        *harness.state.observed_unlinks.borrow_mut() = captures;

        walk_pass(&harness, MAX_CAPTURE_WALK_READS, MAX_CAPTURE_WALK_NODES);

        assert_eq!(
            harness.state.capture_proofs.borrow()[&HARNESS_ROOT]
                .proved
                .len(),
            1,
            "the capture past the adoption bound keeps its proof"
        );
    }

    /// A tick shares its capture walk reads across its passes, so one scope's
    /// walk reads only its pass's share.
    #[test]
    fn a_tick_shares_its_capture_walk_reads_across_its_passes() {
        let folders: Vec<NodeId> = (0..60u8).map(|index| NodeId([0x80 + index; 16])).collect();
        let (harness, _) = walk_harness_of(&folders);
        let drain = harness.drain();
        block_on(drain.run_tick(
            TickScopes {
                vault: None,
                interior: vec![
                    harness.own_scope_at(INTERIOR_ONE),
                    harness.own_scope_at(INTERIOR_TWO),
                ],
                grafted: vec![harness.grafted_scope_at(GRAFTED_ROOT)],
            },
            &RecordingRotator::default(),
        ));

        block_on(drain.adopt_observed_unlinks(&harness.scope(), &[]));

        let reads: usize = core::iter::once(HARNESS_ROOT)
            .chain(folders.iter().copied())
            .map(|node| reads_of(&harness, node))
            .sum();
        assert_eq!(
            reads,
            MAX_CAPTURE_WALK_READS.div_ceil(3),
            "a pass of a three-pass tick reads a third of the tick's share"
        );
    }

    /// A scope with more folders than a walk may hold proves no capture. Its
    /// captures leave the set unbinned, so they cannot fill the set for other
    /// scopes, and the session reads that scope no more.
    #[test]
    fn a_scope_past_the_walk_bound_drops_its_captures_and_is_not_walked_again() {
        let (harness, _) = walk_harness();
        let target = capture(&harness.write_scope_seed).node;

        walk_pass(&harness, MAX_CAPTURE_WALK_READS, 1);

        assert!(
            harness.state.observed_unlinks.borrow().is_empty(),
            "the unprovable capture leaves the set"
        );
        assert_eq!(
            reads_of(&harness, WALK_FOLDER),
            0,
            "the walk stopped at its bound"
        );
        assert_eq!(reads_of(&harness, target), 0, "no re-key starts");
        assert!(
            !harness
                .state
                .held_records
                .borrow()
                .contains_key(&HeldKey::BinIndex),
            "no bin index record was published",
        );

        *harness.state.observed_unlinks.borrow_mut() = vec![capture(&harness.write_scope_seed)];
        walk_pass(&harness, MAX_CAPTURE_WALK_READS, 1);
        assert!(harness.state.observed_unlinks.borrow().is_empty());
        assert_eq!(
            reads_of(&harness, HARNESS_ROOT),
            1,
            "a later capture of the scope costs no second walk"
        );
    }

    /// A walk spends one tick's read share and resumes on the next. A folder
    /// whose second read shows another sequence moved during the walk, so the
    /// walk starts again from the root, and only a walk that settles proves.
    #[test]
    fn a_walk_resumes_across_passes_and_restarts_when_a_folder_moves() {
        let (mut harness, mut blocks) = walk_harness();
        let target = capture(&harness.write_scope_seed).node;

        for _ in 0..3 {
            walk_pass(&harness, 1, MAX_CAPTURE_WALK_NODES);
        }
        assert_eq!(
            reads_of(&harness, HARNESS_ROOT),
            2,
            "one read for each pass"
        );
        assert_eq!(reads_of(&harness, WALK_FOLDER), 1);

        publish_harness_folder(&mut harness, &mut blocks, WALK_FOLDER, 2, Vec::new());
        walk_pass(&harness, 1, MAX_CAPTURE_WALK_NODES);
        assert_eq!(
            reads_of(&harness, target),
            0,
            "a moved folder proves nothing"
        );
        walk_pass(&harness, 1, MAX_CAPTURE_WALK_NODES);
        assert_eq!(
            reads_of(&harness, HARNESS_ROOT),
            3,
            "the walk starts again at the root"
        );

        for _ in 0..3 {
            walk_pass(&harness, 1, MAX_CAPTURE_WALK_NODES);
        }
        assert!(
            reads_of(&harness, target) > 0,
            "the settled walk proves the capture, and its re-key starts"
        );
    }

    /// A walk proves only captures it held from its start. A second departure
    /// of the same node is another capture, and a walk begun before it says
    /// nothing about it.
    #[test]
    fn a_new_departure_of_a_node_needs_a_walk_of_its_own() {
        let (harness, _) = walk_harness();
        walk_pass(&harness, 1, MAX_CAPTURE_WALK_NODES);
        assert_eq!(reads_of(&harness, HARNESS_ROOT), 1);

        harness.state.observed_unlinks.borrow_mut()[0].deleted_at = 10;
        walk_pass(&harness, 1, MAX_CAPTURE_WALK_NODES);
        assert_eq!(
            reads_of(&harness, HARNESS_ROOT),
            2,
            "the walk of the first departure does not carry the second"
        );
        assert_eq!(reads_of(&harness, WALK_FOLDER), 0);
    }

    /// A scope with no capture left holds no walk state.
    #[test]
    fn a_scope_whose_captures_left_the_set_keeps_no_walk() {
        let (harness, _) = walk_harness();
        walk_pass(&harness, 1, MAX_CAPTURE_WALK_NODES);
        assert!(!harness.state.capture_proofs.borrow().is_empty());

        harness.state.observed_unlinks.borrow_mut().clear();
        walk_pass(&harness, 1, MAX_CAPTURE_WALK_NODES);
        assert!(harness.state.capture_proofs.borrow().is_empty());
    }

    /// A departure inside a granted scope reaches the owner capture path now
    /// that a grafted root is a pass of its own. Binning it would seal the
    /// sharer's node under this vault's own held key, so the capture is dropped
    /// rather than adopted — and dropped rather than put back, because no pass
    /// of this vault will ever take it.
    #[test]
    fn a_grafted_pass_bins_no_capture_and_starves_no_set() {
        let grafted = grafted_harness();
        *grafted.state.observed_unlinks.borrow_mut() = vec![capture(&grafted.write_scope_seed)];
        block_on(
            grafted
                .drain()
                .adopt_observed_unlinks(&grafted.scope(), &[]),
        );
        assert!(
            grafted.state.observed_unlinks.borrow().is_empty(),
            "the capture leaves the bounded set rather than being held for ever",
        );
        assert!(
            !grafted
                .state
                .held_records
                .borrow()
                .contains_key(&HeldKey::BinIndex),
            "no bin index record was published",
        );

        let own = drain_harness(Some(harness_root_envelope()));
        *own.state.observed_unlinks.borrow_mut() = vec![capture(&own.write_scope_seed)];
        block_on(own.drain().adopt_observed_unlinks(&own.scope(), &[]));
        assert_eq!(
            own.state.observed_unlinks.borrow().len(),
            1,
            "an own-vault pass keeps the capture for the tick that can bin it",
        );
    }

    /// The retention sweep reads the owner's bin index and stages purges off it.
    #[test]
    fn a_grafted_pass_stages_no_bin_expiry() {
        const BINNED: NodeId = NodeId([0x45; 16]);

        let staged_purges = |harness: &DrainHarness| {
            let mut index = BinIndex::new(1);
            index.entries.push(BinEntry::new(
                BINNED.0,
                derive_write_name(&harness.write_scope_seed, &BINNED.0)
                    .as_str()
                    .as_bytes()
                    .to_vec(),
                NodeKind::File,
                HARNESS_ROOT.0,
                "binned.txt".to_owned(),
                0,
                HARNESS_ROOT.0,
                None,
            ));
            let drain = harness.drain();
            drain.establish_bin_index(index);
            block_on(drain.expire_bin_entries(&harness.scope(), &[]));
            harness.queued_op_ids().len()
        };

        let mut grafted = grafted_harness();
        let mut own = drain_harness(Some(harness_root_envelope()));
        for harness in [&mut grafted, &mut own] {
            harness.bin_retention_days = Some(1);
            harness
                .seams
                .scheduler
                .advance(Duration::from_secs(60 * 60 * 24 * 30));
        }

        assert_eq!(staged_purges(&grafted), 0);
        assert_eq!(
            staged_purges(&own),
            1,
            "an own-vault pass still enforces the owner's retention",
        );
    }

    /// A rotator that records every root a pass asked it to cut.
    #[derive(Default)]
    struct RecordingRotator(RefCell<Vec<NodeId>>);

    impl ScopeExitRotator for RecordingRotator {
        async fn rotate_on_scope_exit(
            &self,
            scope_root: NodeId,
        ) -> Result<RotationOutcome, RotateError> {
            self.0.borrow_mut().push(scope_root);
            Ok(RotationOutcome {
                new_read_epoch: 2,
                epoch_floor: 2,
            })
        }
    }

    /// A scope-exit cut is a rotation of a scope this vault owns, driven off a
    /// session-wide debt set every pass of a tick reaches. A grafted pass holds
    /// no material for one and would spend the debt's only retry.
    #[test]
    fn a_grafted_pass_drives_none_of_this_vaults_owed_cuts() {
        const EXITED: NodeId = NodeId([0x46; 16]);

        let cut_roots = |harness: &DrainHarness| {
            harness
                .state
                .pending_scope_exits
                .borrow_mut()
                .insert(EXITED);
            let exits = RecordingRotator(RefCell::new(Vec::new()));
            block_on(harness.drain().cut_exited_scopes(&harness.scope(), &exits));
            exits.0.into_inner()
        };

        assert!(cut_roots(&grafted_harness()).is_empty());
        assert_eq!(
            cut_roots(&drain_harness(Some(harness_root_envelope()))),
            vec![EXITED],
            "an own-vault pass still drives the cuts this session owes",
        );
    }

    /// The doomed-name journal is the identity's, keyed by its owner tag, and
    /// every name an entry holds derives from a write seed of this vault's own.
    /// A grafted pass replays none of it and spends none of the tick's bounded
    /// open budget looking for entries it could not settle.
    #[test]
    fn a_grafted_pass_replays_none_of_the_identitys_doomed_journal() {
        const TARGET: NodeId = NodeId([0x47; 16]);

        let opens_spent = |harness: &DrainHarness| {
            let drain = harness.drain();
            let scope = harness.scope();
            let owner = owner_tag(&harness.enc_secret);
            let seal = drain.bookkeeping_seal(&scope);
            let key = doomed_journal_key(&owner, HARNESS_ROOT, TARGET);
            let reclamation = Reclamation {
                doomed: vec![(
                    TARGET,
                    derive_write_name(&harness.write_scope_seed, &TARGET.0)
                        .as_str()
                        .to_owned(),
                )],
                ..Reclamation::default()
            };
            assert!(
                block_on(drain.journal_doomed(seal, &key, TARGET, &reclamation)),
                "the entry journals",
            );
            let staged = block_on(harness.seams.staging.staged_keys()).expect("the keys list");
            let mut budget = JournalBudget::new(1);
            let before = budget.opens;
            block_on(drain.settle_journalled_deletes(
                &scope,
                seal,
                &owner,
                &staged,
                &[],
                &mut budget,
            ));
            before - budget.opens
        };

        assert_eq!(opens_spent(&grafted_harness()), 0);
        assert_eq!(
            opens_spent(&drain_harness(Some(harness_root_envelope()))),
            1,
            "an own-vault pass still replays what it journaled",
        );
    }

    /// The refusal is per surface, not a blanket refusal of the grafted pass: an
    /// op that stays inside the sharer's own scope reaches the publish path.
    #[test]
    fn a_grafted_pass_is_refused_no_op_that_stays_in_the_sharers_scope() {
        let grafted = grafted_harness();

        let halt = block_on(grafted.drain().publish_applied(
            &grafted.scope(),
            &mut harness_pass(),
            &applied(
                Op::rename(NodeId([0x48; 16]), "renamed.txt", 1, UnixMillis(0)),
                Some("renamed.txt"),
            ),
            &Snapshot::new(HARNESS_ROOT),
        ));

        assert_ne!(
            halt.err(),
            Some(Halt::Permanent(DeadLetterReason::GraftedScopeVaultSurface)),
        );
    }

    /// The identity-wide charge answers for a keyless root of this vault's own
    /// boundary set, which a grafted pass proves nothing about.
    #[test]
    fn the_identity_wide_charge_never_lands_on_a_grafted_pass() {
        let own = drain_harness(Some(harness_root_envelope()));
        let grafted = grafted_harness();
        let mut passes = vec![grafted.scope(), own.scope()];

        charge_the_identity_to_one_pass(&mut passes);

        assert!(
            !passes[0].charges_the_identity,
            "the charge skips a grafted pass wherever it sits in the list",
        );
    }

    /// The floor namespace half: a grafted end raises and reads its epoch floors
    /// under the granting contact's label, which is the namespace every read leg
    /// below that root already uses (`grants::grafted::floor_namespace`). An own end
    /// is a pass-through, so this vault's own floors are byte-for-byte where
    /// they were.
    #[test]
    fn a_grafted_end_ratchets_where_the_read_legs_read_and_an_own_end_does_not_move() {
        const SHARED: [u8; 16] = [0x6a; 16];

        let harness = grafted_harness();
        let scope = harness.scope();
        let view = scope.source.floors(&harness.seams.floors);

        block_on(view.raise_epoch_floor(&SHARED, 9)).expect("the floor raises");

        let read_leg = SharerScopedFloorStore::granted_by(&harness.seams.floors, sharer_label());
        assert_eq!(
            block_on(read_leg.epoch_floor(&SHARED)).expect("floor read"),
            Some(9),
            "a read leg below the grafted root reads the floor the pass raised",
        );
        assert_eq!(
            block_on(SharerScopedFloorStore::own(&harness.seams.floors).epoch_floor(&SHARED))
                .expect("floor read"),
            None,
            "and this vault's own namespace is untouched by it",
        );

        let own = drain_harness(Some(harness_root_envelope()));
        let own_scope = own.scope();
        block_on(
            own_scope
                .source
                .floors(&own.seams.floors)
                .raise_epoch_floor(&SHARED, 4),
        )
        .expect("the floor raises");
        assert_eq!(
            block_on(own.seams.floors.epoch_floor(&SHARED)).expect("floor read"),
            Some(4),
            "an own pass keeps the plain scope-id key every other owner-side caller reads",
        );
    }

    /// The sequence namespace is shared by construction, so a grafted pass's
    /// post-publish raise bars a replay of the same record for every leg that
    /// reads that name.
    #[test]
    fn a_grafted_end_shares_one_sequence_ratchet_with_every_leg() {
        const NAME: &[u8] = b"k51-granted-scope-root";

        let harness = grafted_harness();
        let scope = harness.scope();

        block_on(
            scope
                .source
                .floors(&harness.seams.floors)
                .raise_sequence_floor(NAME, 6),
        )
        .expect("the floor raises");

        assert_eq!(
            block_on(harness.seams.floors.sequence_floor(NAME)).expect("floor read"),
            Some(6),
        );
    }

    // -----------------------------------------------------------------------
    // One tick's drain: the pass order and the bookkeeping `run_tick` owns.
    // -----------------------------------------------------------------------

    const INTERIOR_ONE: NodeId = NodeId([0x51; 16]);
    const INTERIOR_TWO: NodeId = NodeId([0x52; 16]);
    const GRAFTED_ROOT: NodeId = NodeId([0x53; 16]);
    const ORPHAN_KEY: &[u8] = b"an-abandoned-write-handle-block";

    fn roots(passes: &[DrainScope<'_>]) -> Vec<NodeId> {
        passes.iter().map(|pass| pass.source.root).collect()
    }

    fn charged(passes: &[DrainScope<'_>]) -> Vec<bool> {
        passes
            .iter()
            .map(|pass| pass.charges_the_identity)
            .collect()
    }

    fn drain_events(events: &mut mpsc::UnboundedReceiver<Event>) -> Vec<Event> {
        core::iter::from_fn(|| events.try_recv().ok()).collect()
    }

    #[test]
    fn a_tick_orders_the_vault_pass_first_and_the_grafted_passes_last() {
        let harness = drain_harness(Some(harness_root_envelope()));

        let full = ordered(TickScopes {
            vault: Some(harness.scope()),
            interior: vec![
                harness.own_scope_at(INTERIOR_ONE),
                harness.own_scope_at(INTERIOR_TWO),
            ],
            grafted: vec![harness.grafted_scope_at(GRAFTED_ROOT)],
        });
        assert_eq!(
            roots(&full),
            vec![HARNESS_ROOT, INTERIOR_ONE, INTERIOR_TWO, GRAFTED_ROOT],
        );
        assert_eq!(charged(&full), vec![true, false, false, false]);

        let unheld = ordered(TickScopes {
            vault: None,
            interior: vec![
                harness.own_scope_at(INTERIOR_ONE),
                harness.own_scope_at(INTERIOR_TWO),
            ],
            grafted: vec![harness.grafted_scope_at(GRAFTED_ROOT)],
        });
        assert_eq!(
            roots(&unheld),
            vec![INTERIOR_ONE, INTERIOR_TWO, GRAFTED_ROOT]
        );
        assert_eq!(
            charged(&unheld),
            vec![true, false, false],
            "the first interior pass takes the charge, never a grafted one",
        );

        let grafted_only = ordered(TickScopes {
            vault: None,
            interior: Vec::new(),
            grafted: vec![harness.grafted_scope_at(GRAFTED_ROOT)],
        });
        assert_eq!(charged(&grafted_only), vec![false]);
    }

    #[test]
    fn a_tick_shares_its_bin_expiries_over_the_final_pass_count() {
        let harness = drain_harness(Some(harness_root_envelope()));
        let drain = harness.drain();

        block_on(drain.run_tick(
            TickScopes {
                vault: None,
                interior: vec![
                    harness.own_scope_at(INTERIOR_ONE),
                    harness.own_scope_at(INTERIOR_TWO),
                ],
                grafted: vec![harness.grafted_scope_at(GRAFTED_ROOT)],
            },
            &RecordingRotator::default(),
        ));

        assert_eq!(
            drain.bin_expiries.borrow().per_scope,
            TickShare::new(MAX_BIN_EXPIRIES, 3).per_scope,
        );
    }

    /// The reclaim figure is the retire ledger's, which only settle reads, so a
    /// rewritten figure is the settle's own mark; the sweep runs either way.
    #[test]
    fn an_unheld_root_reconciles_staging_in_place_of_settle() {
        let tick = |vault: bool| {
            let harness = drain_harness(Some(harness_root_envelope()));
            block_on(
                harness
                    .seams
                    .staging
                    .put_staged_bytes(ORPHAN_KEY, b"residue"),
            )
            .expect("the block stages");
            harness.state.pending_reclaim.set(7);
            harness.tick(TickScopes {
                vault: vault.then(|| harness.scope()),
                interior: vec![harness.own_scope_at(INTERIOR_ONE)],
                grafted: Vec::new(),
            });
            let staged =
                block_on(harness.seams.staging.staged_bytes(ORPHAN_KEY)).expect("the store reads");
            (staged, harness.state.pending_reclaim.get())
        };

        assert_eq!(
            tick(false),
            (None, 7),
            "the sweep ran, and the ledger figure kept its value",
        );
        assert_eq!(
            tick(true),
            (None, 0),
            "the settle swept staging and rewrote the figure",
        );
    }

    #[test]
    fn a_tick_surfaces_each_pass_report_to_the_host() {
        let mut harness = drain_harness(Some(harness_root_envelope()));
        let op_id = harness.queue_an_op(&Op::rename(
            NodeId([9; 16]),
            "renamed.txt",
            1,
            UnixMillis(0),
        ));

        harness.tick(TickScopes {
            vault: Some(harness.scope()),
            interior: vec![harness.own_scope_at(INTERIOR_ONE)],
            grafted: Vec::new(),
        });

        // The base holds no such node, so the vault pass dead-letters the op.
        assert!(harness.queued_op_ids().is_empty(), "the op left the queue");
        let retained = harness.state.dead_letters.borrow().get(&op_id).copied();
        let Some((_, reason)) = retained else {
            panic!("the dead letter is retained");
        };
        let events = drain_events(&mut harness.events);
        assert!(events.contains(&Event::DeadLetter { op_id, reason }));
        assert!(events.contains(&Event::SnapshotUpdated));
    }

    /// A rotation on this device raises the floor while a drain child load
    /// waits on the network, after the pass proved its scope root. The record
    /// at the new floor is honest, so the load accuses nobody.
    #[test]
    fn a_floor_raised_during_a_drain_child_load_accuses_nobody() {
        use cipherbox_core::seal::seal_read_body;

        use crate::seams::HttpResponse;
        use crate::testkit::requested_cid;

        const CHILD: NodeId = NodeId([0xC7; 16]);
        const NEW_READ_SEED: [u8; 32] = [0xC8; 32];
        const NEW_EPOCH: u64 = OWNER_ROOT_EPOCH + 1;

        let mut harness = drain_harness(None);
        let backing = InMemoryFloorStore::default();
        let floors = OwnerScopedFloorStore::new(backing.clone());
        floors.bind(
            &harness.enc_secret,
            &kdf::contact_label_seed(&HARNESS_SECRET),
        );
        block_on(floors.raise_epoch_floor(&HARNESS_SCOPE, OWNER_ROOT_EPOCH))
            .expect("the floor raises");
        harness.seams.floors = floors;
        let [floor_key] =
            <[Vec<u8>; 1]>::try_from(backing.epoch_keys()).expect("one scope holds an epoch floor");

        let node_seed = kdf::node_seed(&NEW_READ_SEED, &CHILD.0);
        let envelope = seal_read_body(
            kdf::read_key(node_seed.as_bytes()).as_bytes(),
            &[0xC9; 24],
            1,
            CHILD.0,
            HARNESS_SCOPE,
            NEW_EPOCH,
            &ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children: Vec::new(),
                unknown: PreservedFields::new(),
            },
        )
        .expect("the body seals");
        let head_block = encode_envelope(&envelope).expect("the envelope encodes");
        let head_cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head_block));
        let name = derive_write_name(&harness.write_scope_seed, &CHILD.0);
        harness.seams.transport.seed_record(
            &EndpointId::new("fake:someguy"),
            name.as_str(),
            IpnsRecord::create_v2(
                &kdf::ipns_keypair(kdf::write_seed(&harness.write_scope_seed, &CHILD.0).as_bytes()),
                format!("/ipfs/{head_cid}").as_bytes(),
                1,
                HARNESS_TTL_NANOS,
                HARNESS_EOL,
            )
            .marshal(),
        );
        harness.seams.http = ScriptedHttp::with_route(move |request| {
            (requested_cid(&request.url) == head_cid).then(|| {
                block_on(backing.raise_epoch_floor(&floor_key, NEW_EPOCH))
                    .expect("the rotation raises the floor");
                Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: head_block.clone().into(),
                })
            })
        });

        let refused = {
            let scope = harness.scope();
            let loaded = block_on(harness.drain().load_child_node(
                &scope.source.at(OWNER_ROOT_EPOCH),
                Anchor {
                    epoch: OWNER_ROOT_EPOCH,
                    history_links: &[],
                },
                CHILD,
                ResolveMode::NoCache,
            ));
            matches!(loaded, Err(Halt::RecordRefused))
        };

        assert!(!refused, "the load is not charged as a refused record");
        assert!(
            drain_events(&mut harness.events)
                .iter()
                .all(|event| !matches!(event, Event::AttributableAbuse { .. })),
            "a record above the plane's epoch accuses nobody",
        );
    }
}
