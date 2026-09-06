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

use cipherbox_core::content::{
    decode_content_cid_str, encode_content_cid_str, is_wellformed_content_cid, verify_cid,
};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    BinEntry, BinIndex, ChildRef, Envelope, NodeKind, PreservedFields, ReadBody, SignedSealed,
    Version, decode_grant_section, grant_section_bytes, open_content_key, open_read_body,
};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::x25519::X25519Secret;
use futures_channel::mpsc;
use zeroize::Zeroizing;

use crate::api::{ApiClient, ApiError, QUOTA_EXCEEDED, REGISTRY_BATCH_REFUSED, UPLOAD_TOO_LARGE};
use crate::bin_index::{
    BinIndexKeys, BinIndexLoad, BinIndexPublishError, BinnedNode, cached_bin_index, load_bin_index,
    publish_bin_index,
};
use crate::content::limits::MAX_RESOLVED_RECORD_BYTES;
use crate::content::{
    ContentPlane, ContentProfile, ContentVersion, Expansion, Gateway, ProviderError, RootPlacement,
    SealedContent, expand_retire_targets, place_block, plan_prune, pre_flight_quota_check,
    read_block, validate_byo_config, version_cids,
};
use crate::entropy::{Entropy, SharedEntropy, fresh_ephemeral, fresh_nonce};
use crate::facade::{
    BlockProgress, Event, MAX_NODE_NAME_BYTES, NodeId, OpPhase, RetainedDeadLetters,
    emit_trust_violation,
};
use crate::gate::GateStage;
use crate::gate::{Adopted, GateError, RejectionReason, floor};
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
    LiveRecord, OrphanHeads, ReclaimStall, RootSource, StagingRetireLedger, drain_owed_retires,
    orphaned_head, retire,
};
use crate::net::{
    Adopter, ChildAdopter, HeldKey, HeldRecord, HeldRecords, HeldValue, LocalHead, ResolveOutcome,
    Resolved, RootAdopter, assemble_head_envelope, fanout_get_verify, resolve,
};
use crate::profile::SyncTimingProfile;
use crate::rotation::{ScopeExitRotator, derive_write_name, seed_at_epoch};
use crate::seams::{
    CredentialStore, FloorStore, Http, OpId, OwedRetire, OwingRecord, RecordTransport,
    RetireLedger, Scheduler, SeamResult, SnapshotCache, StagingStore, UnixMillis,
};
use crate::session::SessionIdentity;
use crate::settings::{
    DefaultsReason, Destinations, Placement, PlacementDecision, SettingsRefusal,
};
use crate::storage_policy::StoragePolicy;
use crate::sync::BookkeepingSeal;
use crate::sync::cancel::UploadCancels;
use crate::sync::doomed::{
    MAX_BOOKKEEPING_OPENS, MAX_JOURNAL_REPLAYS, MAX_QUARANTINE_ATTEMPTS, MAX_QUARANTINE_PROOFS,
    Quarantined, Reclamation, doomed_journal_key, journalled_keys, open_reclamation,
    record_matches_manifest, seal_reclamation,
};
use crate::sync::model::{Snapshot, collation_key};
use crate::sync::op::{NewNode, Op, OpKind, ScopeCrossing, StagedContent};
use crate::sync::overlay::apply_overlay;
use crate::sync::project::{UnlinkedChild, project_child_version, project_folder};
use crate::sync::rebase::{
    AppliedOp, DeadLetterReason, decode_queue, enclosing_scope_root, replay,
};
use crate::sync::record::{RecordReader, RecordSeal};
use crate::sync::scope_exit_debt::{owe_cut, settle_owed_cuts};
use crate::sync::staging::{
    DEAD_LETTER_NOTICES_PREFIX, LiveBlocks, Preservation, PreservedBounds, preserve_dead_letter,
    reconcile_staging_over, release_version_blocks, stage_op, version_leaf_cids,
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
/// A child that does not is a scope root: its subtree is sealed under a
/// grantee's own seed, and cutting that grantee needs a re-key the bin does not
/// carry, so a delete of it stays hard (ADR 0010 item 3). Every other reader in
/// the delete path derives the child's name the same way and never reads this
/// field, so a child the comparison rejects is one this scope's write plane
/// does not name either.
fn names_this_scope(end: &ScopeEnd<'_>, child: &ChildRef) -> bool {
    end.write_name(&child.id).as_str().as_bytes() == child.ipns_name
}

/// A bin index load that did not establish the current index.
///
/// A refusal of bytes the plane actually served is charged, so a jammed bin
/// index cannot hold the queue head for good. A plane this pass could not read
/// is availability and waits uncharged — but it waits as a *reported* hold, so
/// a party who withholds one record does not stall the queue in silence
/// ([`BinIndexHold`]).
///
/// A stranded mint is neither. The hold's only exit is the record resolving,
/// and on a single-device account nothing is left to publish it — so the op
/// dead-letters with the state named rather than waiting for ever.
fn halt_for_bin_load(reason: DefaultsReason) -> Halt {
    match reason {
        DefaultsReason::StrandedMint => Halt::Permanent(DeadLetterReason::BinIndexStrandedMint),
        _ if bin_load_is_a_verdict(reason) => Halt::Attempt,
        _ => Halt::HeldByBinIndex(reason),
    }
}

/// Whether a bin index load refused bytes the plane actually served, rather
/// than failing to reach it (blueprint/engine.md "Bin index record"). A caller
/// that retries on availability must not retry on a verdict.
pub(crate) fn bin_load_is_a_verdict(reason: DefaultsReason) -> bool {
    match reason {
        DefaultsReason::RolledBack { .. }
        | DefaultsReason::RevisionRolledBack { .. }
        | DefaultsReason::Unreadable => true,
        DefaultsReason::UnprovenFirstRun
        | DefaultsReason::Suppressed
        | DefaultsReason::StrandedMint
        | DefaultsReason::Expired
        | DefaultsReason::TimedOut
        | DefaultsReason::FloorUnreadable => false,
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
    /// A node this pass must re-author is still behind the scope's epoch, and
    /// this pass holds no backward ratchet to open it at its own epoch
    /// (CONTEXT.md "Epoch lag"). Charged nothing, and re-driven at the pass that
    /// reaches the node ([`halt_for_unreachable_epoch`]).
    EpochLagged,
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
    /// until those settings change ([`SettingsHold`]).
    HeldBySettings(SettingsRefusal),
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
    /// record resolves ([`BinIndexHold`]).
    HeldByBinIndex(DefaultsReason),
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
/// then take [`Halt::Unclassified`] from every pass, spend no attempt budget,
/// and hold the strict-FIFO head for ever with no dead letter (ADR 0012 D6).
pub(crate) fn charge_the_identity_to_one_pass(scopes: &mut [DrainScope<'_>]) {
    if let Some(first) = scopes.first_mut() {
        first.charges_the_identity = true;
    }
}

/// The scope read seed a node the lazy wave has not reached must be opened
/// under: the one its own epoch was sealed at, walked back over the scope root's
/// carried history links (CONTEXT.md "Lazy wave"), or the halt this pass takes
/// instead of opening it.
fn seed_for_lagging(
    scope_id: [u8; 16],
    current_seed: &[u8; 32],
    anchor: Anchor<'_>,
    record_epoch: u64,
) -> Result<Zeroizing<[u8; 32]>, Halt> {
    // A record above this pass's epoch is not lagging, and the ratchet only
    // walks backward: no seed here opens it. An honest race with a fresher root,
    // which the next pass anchors on.
    if record_epoch > anchor.epoch {
        return Err(Halt::Unclassified);
    }
    seed_at_epoch(
        ENVELOPE_V,
        scope_id,
        current_seed,
        anchor.epoch,
        anchor.history_links,
        record_epoch,
    )
    .ok_or_else(|| halt_for_unreachable_epoch(anchor.history_links))
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

/// The queue head is held over rather than failed: the bin index plane did not
/// establish the current index, so the op that needs it keeps its place and its
/// staging reservation until the record resolves.
///
/// Reported, because a party who withholds the record — or one head block of it
/// — otherwise stops every queued operation for the account with no cause the
/// member can see (blueprint/engine.md "Bin index record").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinIndexHold {
    /// The held op.
    pub op_id: OpId,
    /// The node the op targets, so a host can point at it.
    pub node: NodeId,
    /// Why the load did not establish the index.
    pub reason: DefaultsReason,
}

/// The captures one pass adopts into the bin. A peer chooses both the trigger
/// and the count, so the pass takes a bounded share and the rest waits.
const MAX_BIN_ADOPTIONS: usize = 32;

/// What one session holds unadopted. The set is memory a peer's republishes
/// fill, so it is bounded like every other per-session set.
const MAX_HELD_CAPTURES: usize = 4096;

/// Purges one pass queues for expired bin entries. A retention deadline can
/// come due for a whole bin at once, and a purge is an op like any other: the
/// queue takes a bounded share per pass and the rest waits for the next tick.
const MAX_BIN_EXPIRIES: usize = 32;

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
/// (FSM1/cipher-box-next ADR 0011) and no wave ever lifts it. Left uncharged —
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
/// [`MAX_HELD_CAPTURES`].
pub(crate) fn hold_captures(set: &RefCell<Vec<UnlinkedChild>>, observed: Vec<UnlinkedChild>) {
    let mut set = set.borrow_mut();
    let room = MAX_HELD_CAPTURES.saturating_sub(set.len());
    set.extend(observed.into_iter().take(room));
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
    /// The scope write seed per-node IPNS names and signers derive from.
    pub(crate) write_scope_seed: &'a Zeroizing<[u8; 32]>,
    /// `nodeSeed(enclosingOverrideSeed, scopeId)` — the ascent authority the
    /// gate derives an interior scope root's expected ascent keypair from
    /// ([`RootAdopter::under_parent_node_seed`]). `None` at the vault root,
    /// which carries no ascent link.
    pub(crate) ascent_node_seed: Option<&'a Zeroizing<[u8; 32]>>,
}

impl<'a> ScopeEnd<'a> {
    /// This end bound to the read epoch its records carry — everything one
    /// record's seal needs.
    fn at(self, epoch: u64) -> SealPlane<'a> {
        SealPlane { end: self, epoch }
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
    /// The read epoch every record sealed under this plane binds.
    pub(crate) epoch: u64,
}

impl SealPlane<'_> {
    /// The head binding one node's record carries under this plane.
    fn head_binding(&self, node_id: &[u8; 16]) -> HeadBinding {
        HeadBinding {
            node_id: *node_id,
            scope_id: self.end.root.0,
            epoch: self.epoch,
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
}

impl<'a> DrainScope<'a> {
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

/// What a scope root whose own record sits at another epoch than the plane
/// binds costs the op that met it.
///
/// The anchor's epoch is this pass's own, and a rotation that moved it heals at
/// the next pass boundary, so the op waits. A second end's comes from the tick's
/// boundary walk, and only a fresh walk changes it: charged, or a superseded end
/// holds the queue head for good.
fn epoch_skew(scope: &DrainScope<'_>, plane: &SealPlane<'_>) -> Halt {
    if plane.end.root == scope.source.root {
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
/// [`Halt::Unclassified`] retries free and forever, which is right for a read
/// the next pass may win and wrong for one it will meet again unchanged. A
/// crossing that keeps taking it would hold the FIFO head with nothing reported
/// — the very failure a classified halt exists to prevent.
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
    /// Where each bounded bookkeeping loop stopped, shared with the facade's
    /// read surface for the reclaim figure's own completeness bit.
    pub(crate) bookkeeping: &'a RefCell<BookkeepingCursors>,
    /// Head blocks this session's publishes orphaned, pending retirement.
    pub(crate) orphan_heads: &'a OrphanHeads,
    /// Whether a poll tick has reconciled the record plane since this session
    /// started ([`Settle`]).
    pub(crate) converged_tick: &'a Cell<bool>,
    /// The upload-cancel interlock, shared with the facade's cancel command.
    pub(crate) cancels: &'a RefCell<UploadCancels>,
    /// The facade's outbound event stream, for upload progress.
    pub(crate) events: &'a mpsc::UnboundedSender<Event>,
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
    /// The dead letters this session has surfaced, so the expiry sweep does not
    /// re-queue a purge for an entry whose own purge is already terminal.
    pub(crate) dead_letters: &'a RefCell<RetainedDeadLetters>,
    /// Unlinks the poll leg observed and this device did not author, shared
    /// with the tick loop that fills it. A capture leaves the set only once its
    /// bin entry has landed: the merge that saw it has already dropped the node
    /// from the base, so a set this pass emptied on failure would lose it.
    pub(crate) observed_unlinks: &'a RefCell<Vec<UnlinkedChild>>,
    /// The bin index record this session last published or resolved, shared
    /// with the facade's renewal slot. A load fills it too, so the sub-EOL
    /// renewal keeps the record alive on a session that publishes nothing.
    pub(crate) bin_index_record: &'a RefCell<Option<HeldRecord>>,
    /// The bin-index-refused hold, shared with the facade's read surface. It
    /// clears only here, on a load that establishes the index.
    pub(crate) bin_index_hold: &'a RefCell<Option<BinIndexHold>>,
    /// The bin index this pass has established: the one it resolved, or the one
    /// its last confirmed publish left standing. Carried so a bulk soft delete
    /// costs one resolve rather than one per operation; the publish stays per
    /// operation, which is what keeps the entry ahead of its unlink.
    pub(crate) established_bin_index: RefCell<Option<BinIndex>>,
    /// Scope roots this session owes a cut for ([`Drain::cut_exited_scopes`]).
    pub(crate) pending_scope_exits: &'a RefCell<BTreeSet<NodeId>>,
}

/// One folder's current published state, carried across the ops of one pass so
/// each publish authors onto the previous one.
struct FolderState {
    /// The root of the plane this folder was loaded under, and so the only plane
    /// it may be republished under.
    plane_root: NodeId,
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
    /// Where the destination sits relative to the source scope. A non-`Intra`
    /// plan re-seals the moved subtree into the destination scope before the
    /// dest-add names it (blueprint/engine.md "Sync core: Ops").
    crossing: ScopeCrossing,
}

/// What a crossing's re-seal published, held back until the move commits.
///
/// The live-set key is the node id alone
/// ([`HeldKey::node`](crate::net::HeldKey::node)), so installing a destination
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
    replays: usize,
    /// The most of them any one scope may take ([`Self::share`]).
    per_scope: usize,
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
            replays: MAX_JOURNAL_REPLAYS,
            per_scope: MAX_JOURNAL_REPLAYS.div_ceil(scopes.max(1)),
            proofs: MAX_QUARANTINE_PROOFS,
            opens: MAX_BOOKKEEPING_OPENS,
        }
    }

    /// What one scope may replay: its share of the tick's slots, and never more
    /// than the tick has left.
    fn share(&self) -> usize {
        self.per_scope.min(self.replays)
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
enum Boundary {
    /// Every child ref is walked. A descendant this pass cannot read is unknown
    /// structure and refuses the whole operation.
    None,
    /// A child that does not publish under a name this scope's write seed
    /// derives is a scope root, and the bin re-keyed no such child: its record
    /// does not open under the bin-held key, so it is not this purge's to
    /// reclaim ([`Drain::rekey_subtree`]).
    ScopeRoots,
}

impl Boundary {
    fn admits(self, end: &ScopeEnd<'_>, child: &ChildRef) -> bool {
        match self {
            Self::None => true,
            Self::ScopeRoots => names_this_scope(end, child),
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
        BookkeepingSeal::new(scope.enc_secret, self.entropy)
    }

    /// One scope's queue pass: rebase the queue onto gate-passing state and
    /// publish every applied op it can, stopping at the first it cannot, then
    /// clear what the pass orphaned in this scope's own bin. A tick runs one of
    /// these per scope it holds and [`settle`](Self::settle) once, because
    /// everything settle touches is keyed by the identity.
    pub(crate) async fn run_queue<R: ScopeExitRotator>(
        &self,
        scope: &DrainScope<'_>,
        exits: &R,
    ) -> DrainReport {
        let (report, queued_purges) = self.drain_queue(scope, exits).await;
        self.adopt_observed_unlinks(scope).await;
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
    pub(crate) async fn settle(
        &self,
        vault: &DrainScope<'_>,
        scopes: &[DrainScope<'_>],
        journalled_deletes: &[NodeId],
    ) {
        self.orphan_heads.retire_pending(self.api).await;
        // One enumeration serves every consumer below. A desktop vault stages
        // on the order of ten thousand keys, and each of these was listing the
        // whole set for itself. Taken after the queue loop, so a debt the pass
        // just journaled is in it.
        // A store that will not enumerate leaves both the ledger and the sweep
        // for the next pass: "no debt" and "no residue" are claims this one
        // cannot make.
        let Ok(staged) = self.staging.staged_keys().await else {
            return;
        };
        // An X25519 base-point multiply, so the pass derives it once and threads
        // it through every consumer below.
        let owner = owner_tag(vault.enc_secret);
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
        let resume = self.bookkeeping.borrow().ledger.clone();
        if let Some(pass) = drain_owed_retires(
            &StagingRetireLedger::over(self.staging, seal, &staged),
            &owner,
            self.api,
            &RootSource {
                gateway: self.gateway,
                http: self.http,
                profile: self.content_profile,
            },
            &owed_now,
            resume.as_deref(),
            async |node, owing| self.live_owing_record(vault, node, owing).await,
        )
        .await
        {
            self.pending_reclaim.set(pass.still_owed);
            *self.reclaim_stalls.borrow_mut() = pass.stalls;
            let mut bookkeeping = self.bookkeeping.borrow_mut();
            bookkeeping.ledger = pass.cursor;
            bookkeeping.ledger_partial = pass.partial;
        }
        reconcile_staging_over(
            self.staging,
            self.live_blocks,
            &staged,
            PreservedBounds::at(self.scheduler.now(), self.storage_policy, self.profile),
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
        let Ok(Queue { mine, all_ids }) = self.queued_ops(scope, &mut report).await else {
            return (report, None);
        };
        let queued = mine;
        if queued.is_empty() {
            self.clear_block();
            self.clear_settings_hold();
            self.clear_bin_index_hold();
            // A debt outlives the op that owed it, so an empty queue is still a
            // pass that drives the cuts this device owes.
            self.cut_exited_scopes(scope, exits).await;
            return (report, Some(Vec::new()));
        }
        // The hold names one op, so it goes as soon as that op does.
        if self
            .bin_index_hold
            .borrow()
            .is_some_and(|hold| !still_queued(&queued, hold.op_id))
        {
            self.clear_bin_index_hold();
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
        let _ = self.store_attempts(&attempts).await;
        let _ = self.mark_drained(scope, &queued, &report).await;
        (report, Some(purges))
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
            replay(&base, &local, queued, scope.scope_roots)
        };
        for (op_id, reason) in &rebased.dead_letters {
            let Some((_, op)) = queued.iter().find(|(id, _)| id == op_id) else {
                continue;
            };
            // A terminally unrebasable op keeps its staged bytes, and this is
            // what keeps them reachable — and openable — once the abandonment
            // has dropped its record from the queue.
            let preserved = self.preserve_dead_letter(scope, *op_id, *reason).await?;
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
            self.dequeue_op(applied.op_id).await?;
            self.cancels.borrow_mut().published(applied.op_id);
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
        let vault_root = self.base.borrow().root;
        let still_owed = settle_owed_cuts(
            self.staging,
            self.bookkeeping_seal(scope),
            scope.enc_secret,
            exits,
            self.pending_scope_exits,
            vault_root,
        )
        .await;
        // A scope this session could not cut is a revocation still outstanding,
        // so the member is told which one rather than left with a silent retry.
        for (root, detail) in still_owed {
            let _ = self.events.unbounded_send(Event::ScopeExitCutOwed {
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
        // its hold goes here, on the first halt that is not it. Every other
        // hold's own pre-pass gate is what lets go of it.
        if !matches!(halt, Halt::HeldByBinIndex(_)) {
            self.clear_bin_index_hold();
        }
        match halt {
            Halt::Unclassified | Halt::EpochLagged => {}
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
                let Ok(preserved) = self.preserve_dead_letter(scope, op_id, reason).await else {
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
                let Ok(preserved) = self.preserve_dead_letter(scope, op_id, reason).await else {
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
            // go of it — so taking one drops the others rather than leaving two
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
            Halt::HeldByBinIndex(reason) => {
                self.clear_block();
                self.clear_settings_hold();
                *self.bin_index_hold.borrow_mut() = Some(BinIndexHold {
                    op_id,
                    node: op.target,
                    reason,
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

    fn clear_bin_index_hold(&self) {
        *self.bin_index_hold.borrow_mut() = None;
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
        let root = self.load_scope_root(&scope.source).await?;
        let mut pass = Pass {
            root: scope.source.root,
            epoch: root.epoch,
            history_links: root.history_links,
            second_ratchet: None,
            folders: Vec::new(),
            journalled: Vec::new(),
        };
        let state = root.state;
        self.repaint_folder(
            scope.source.root,
            &state.children,
            state.sequence,
            state.modified_at,
        );
        pass.insert(scope.source.root, state);
        Ok(pass)
    }

    /// The scope root as this device last held it: the cached record, opened.
    async fn load_scope_root(&self, source: &ScopeEnd<'_>) -> Result<LoadedRoot, Halt> {
        let record_bytes = self
            .snapshot_cache
            .get(source.root_name.as_str().as_bytes())
            .await
            .map_err(seam)?
            .ok_or(Halt::Unclassified)?;
        self.open_root_record(source, &record_bytes).await
    }

    /// One scope root's record as currently published: its envelope's carried
    /// fields, its unsealed folder body, the scope epoch and the ratchet its
    /// grant section carries.
    ///
    /// Split from the cache read so a second end opens the bytes its own resolve
    /// returned: a root this device published through a grant mint or a rotation
    /// is current on the plane and stale in the cache.
    async fn open_root_record(
        &self,
        source: &ScopeEnd<'_>,
        record_bytes: &[u8],
    ) -> Result<LoadedRoot, Halt> {
        let (sequence, envelope, _) = assemble_head_envelope(
            self.gateway,
            self.http,
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
            self.floors,
            source.root_name.as_str().as_bytes(),
            &source.root.0,
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
        let read_key = source.read_key(&source.root.0);
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
        // A scope root the root gate passed carries a decodable section; bytes
        // that do not are not a root this pass may anchor a ratchet on.
        let history_links = grant_section_bytes(&envelope)
            .and_then(|bytes| decode_grant_section(bytes).ok())
            .ok_or(Halt::Unclassified)?
            .history_links;
        Ok(LoadedRoot {
            state: FolderState {
                plane_root: source.root,
                name: source.root_name.clone(),
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
            history_links,
        })
    }

    /// The scope-root adopter for one end: the owner's own seed source, and the
    /// ascent authority an interior root's gate stage needs.
    fn root_adopter<'e>(
        &'e self,
        scope: &'e DrainScope<'_>,
        end: &ScopeEnd<'_>,
    ) -> RootAdopter<'e, H, F> {
        let adopter = RootAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            scope.enc_secret,
            scope.owner_identity,
            end.root.0,
        );
        match end.ascent_node_seed {
            Some(seed) => adopter.under_parent_node_seed(seed.clone()),
            None => adopter,
        }
    }

    /// One end's scope root as the record plane now serves it, resolved through
    /// its own gate.
    ///
    /// The bytes come from the resolve rather than the cache: only an adopt
    /// writes the cache, so a root this device published through another path —
    /// a grant mint, a rotation — is current on the plane and stale in the
    /// cache.
    async fn resolve_scope_root(
        &self,
        scope: &DrainScope<'_>,
        end: &ScopeEnd<'_>,
    ) -> Result<Vec<u8>, Halt> {
        let adopter = self.root_adopter(scope, end);
        let resolved = resolve(
            self.transport,
            self.snapshot_cache,
            &adopter,
            end.root_name,
            ResolveMode::CacheFirst,
        )
        .await
        .map_err(seam)?;
        self.resolved_bytes(end.root_name, resolved).await
    }

    /// The gate-passing bytes one resolve established.
    ///
    /// A gate failure is a trust violation, never staleness: re-authoring on top
    /// of last-known-good while the record plane serves a rejected record is
    /// exactly the fail-open rule 6 forbids.
    async fn resolved_bytes(&self, name: &IpnsName, resolved: Resolved) -> Result<Vec<u8>, Halt> {
        match resolved.outcome {
            // An adopt caches its own gate-passing bytes; the other two arms
            // carry theirs.
            ResolveOutcome::Adopted(_) => self
                .snapshot_cache
                .get(name.as_str().as_bytes())
                .await
                .map_err(seam)?
                .ok_or(Halt::Unclassified),
            ResolveOutcome::Current { record_bytes } => Ok(record_bytes),
            ResolveOutcome::NoUpdate => resolved.last_known_good.ok_or(Halt::Unclassified),
            ResolveOutcome::TrustViolation(_) => Err(Halt::Unclassified),
        }
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
        let adopter = ChildAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            plane.end.root.0,
            plane.end.read_scope_seed.clone(),
            node.0,
        );
        let resolved = resolve(self.transport, self.snapshot_cache, &adopter, &name, mode)
            .await
            .map_err(seam)?;
        // A drain publish is an ordinary write, so it carries the lazy wave
        // rather than refusing what a cut left behind: a record the epoch floor
        // rejects is re-read at the epoch it was sealed at, and the publish path
        // re-seals it at this pass's.
        let (record_bytes, lagging) = match &resolved.outcome {
            ResolveOutcome::TrustViolation(rejection) => match rejection.reason {
                RejectionReason::EpochBelowFloor { epoch, .. } => (
                    adopter
                        .assembled_record_bytes(&name)
                        .ok_or(Halt::EpochLagged)?,
                    Some(epoch),
                ),
                // A trust violation or a rollback stays fail-closed.
                _ => return Err(Halt::Unclassified),
            },
            _ => (self.resolved_bytes(&name, resolved).await?, None),
        };
        let (adopted, envelope) = self
            .open_for_reauthor(plane, anchor, &adopter, &name, &record_bytes, lagging)
            .await?;
        // The same two rollback guards the root load makes: this build authors
        // exactly `ENVELOPE_V`, and re-sealing a node at an epoch above the
        // scope's would cross the AAD epoch binding.
        if envelope.v != ENVELOPE_V {
            return Err(Halt::Unclassified);
        }
        if adopted.epoch > anchor.epoch {
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

    /// Open one node's record for re-authoring: at the durable floor, or — for a
    /// node the lazy wave has not reached — at the epoch it was sealed at, under
    /// the seed this scope's backward key-regression ratchet recovers for that
    /// epoch (CONTEXT.md "Lazy wave"). The publish path re-seals whatever comes
    /// back at the anchor's epoch, which carries the wave one node further.
    async fn open_for_reauthor(
        &self,
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        adopter: &ChildAdopter<'_, H, F>,
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
                    _ => return Err(Halt::UploadAttempt),
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
            let base = self.base.borrow();
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
            self.repaint_folder(node, &state.children, state.sequence, state.modified_at);
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
        let record_bytes = self.resolve_scope_root(scope, &plane.end).await?;
        let root = self.open_root_record(&plane.end, &record_bytes).await?;
        if root.epoch != plane.epoch {
            return Err(epoch_skew(scope, plane));
        }
        if plane.end.root != pass.root {
            pass.hold_second_ratchet(plane.end.root, root.epoch, root.history_links);
        }
        Ok(root.state)
    }

    /// Load one non-root folder's state, refusing a node whose sealed body is
    /// not a folder (a kind transplant).
    async fn load_child_folder(
        &self,
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        folder: NodeId,
    ) -> Result<FolderState, Halt> {
        let loaded = self
            .load_child_node(plane, anchor, folder, ResolveMode::CacheFirst)
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
            plane_root: plane.end.root,
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
        // Removing an absent ref is the op already satisfied, never a publish.
        let (Some(&origin), Some(child)) = (unlink_from.first(), named) else {
            return Ok(());
        };

        // The bin entry, the re-key and the doomed manifest belong to the scope
        // the origin link resolved onto: a node joins the scope of the parent
        // that names it.
        let plane = scope.folder_plane(pass, origin)?;

        // The soft branch earns its bin entry and its re-key before the unlink;
        // the hard branch earns its doomed manifest. Both then unlink and
        // republish every parent, which is where the op completes.
        let doomed = if to_bin && names_this_scope(&plane.end, &child) {
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
        for (at, parent) in unlink_from.into_iter().enumerate() {
            pass.folder_mut(parent)?
                .children
                .retain(|entry| entry.id != target.0);
            self.publish_folder(
                scope,
                pass,
                parent,
                applied.op.authored_at.0,
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
                    self.orphan_heads.record(&name);
                }
            }
            (false, None) => {}
        }
        Ok(())
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
        let target = applied.op.target;
        let Some((entry, binned_under)) = self.bin_entry(scope, pass, target).await? else {
            // The entry left with an attempt that got past the drop below.
            return Ok(());
        };
        // A node some folder already links is one an earlier attempt of this op
        // relinked, or another device restored. Only the entry is left.
        if !self.base.borrow().links_to(target).is_empty() {
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
        let held = self.bin_keys.held_key(&target.0, entry.deleted_at);
        let binned = SealPlane {
            end: ScopeEnd {
                read_scope_seed: &held,
                ..plane.end
            },
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
        self.publish_folder(
            scope,
            pass,
            into,
            applied.op.authored_at.0,
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
        let held = self.bin_keys.held_key(&target.0, deleted_at);
        let binned = SealPlane {
            end: ScopeEnd {
                read_scope_seed: &held,
                ..binned_under.end
            },
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
                Boundary::ScopeRoots,
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
        if !self.base.borrow().links_to(target).is_empty() {
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
    /// hold, and its `ipnsName` is whatever the writer that binned the node put
    /// there. Both are refused: re-keying under the wrong scope's seed would
    /// seal a node to a key its readers never derive, and a name this write seed
    /// does not derive belongs to a scope root, which no bin path re-keys.
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
        // end rather than the one this pass anchors on. An entry naming neither
        // end, or a name that end's write seed does not derive, is one no pass
        // may act on.
        let plane = scope
            .plane_rooted_at(pass.epoch, NodeId(entry.scope_id))?
            .ok_or(Halt::Permanent(DeadLetterReason::TargetGone))?;
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
        let mut mine = budget.share();
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
            self.bookkeeping
                .borrow_mut()
                .journal
                .insert(scope.source.root.0, target.0);
            let Ok(Some(entry)) = self.staging.staged_bytes(&key).await else {
                continue;
            };
            let Some(reclamation) = open_reclamation(seal, &entry).filter(|r| r.is_for(target))
            else {
                continue;
            };
            budget.replays -= 1;
            mine -= 1;
            let settle = match self.converged_tick.get() {
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
        boundary: Boundary,
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
            Some(*self.bin_keys.held_key(&child.node.0, deleted_at)),
        ));
        self.publish_bin(index).await?;
        Ok(deleted_at)
    }

    /// Bind the unlinks the poll leg observed into the owner's bin, and re-key
    /// each node out of the source scope's derivation (ADR 0010 item 5).
    /// Without the re-key, the grantee who unlinked the node keeps its read key.
    ///
    /// The re-key runs **before** the entry, which is the opposite of the
    /// authored delete's order and for the opposite reason: the unlink has
    /// already published, so nothing waits on the entry, and an entry ahead of
    /// the re-key would claim a cut that may never run. A capture whose re-key
    /// or whose index publish does not land stays in the set and is retried,
    /// under the `deletedAt` it was stamped with, so the retry reaches the same
    /// key.
    ///
    /// The set is empty for a vault at retention `0`: the owner turned the bin
    /// off, and an adoption carries no owner command that could overrule that.
    ///
    /// One index load and one index publish serve the whole pass, and at most
    /// [`MAX_BIN_ADOPTIONS`] captures ride it, so a peer that unlinks a large
    /// folder cannot spend the tick.
    async fn adopt_observed_unlinks(&self, scope: &DrainScope<'_>) {
        let taken = self.take_captures(scope);
        if taken.is_empty() {
            return;
        }
        let Ok(root) = self.load_scope_root(&scope.source).await else {
            self.return_captures(taken);
            return;
        };
        let Ok(mut index) = self.writable_bin_index().await else {
            self.return_captures(taken);
            return;
        };
        let mut added = Vec::new();
        let mut unfinished = Vec::new();
        for unlinked in taken {
            let standing = index
                .entries
                .iter()
                .any(|entry| entry.node_id == unlinked.node.0);
            if self
                .rekey_into_bin(
                    scope,
                    &scope.source.at(root.epoch),
                    root.anchor(),
                    unlinked.node,
                    unlinked.deleted_at,
                )
                .await
                .is_err()
            {
                if !standing {
                    unfinished.push(unlinked);
                }
                continue;
            }
            if standing {
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
        let now = self.scheduler.now();
        let Some(cutoff) = bin_expiry_cutoff(now, self.bin_retention_days) else {
            return;
        };
        let Some(index) = self.expiry_bin_index().await else {
            return;
        };
        let expired: Vec<(NodeId, u64)> = {
            let base = self.base.borrow();
            let terminal = self.dead_letters.borrow();
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
                .take(MAX_BIN_EXPIRIES)
                .collect()
        };
        for (node, deleted_at) in expired {
            let Ok(ephemeral_scalar) = fresh_ephemeral(&mut *self.entropy.borrow_mut()) else {
                return;
            };
            let seal = RecordSeal {
                owner_enc_secret: scope.enc_secret,
                ephemeral_scalar,
            };
            // The base sequence anchors a rebase against the target's own
            // record, and a binned node has no record the snapshot renders.
            let op = Op::purge(node, deleted_at, 1, now);
            let _ = stage_op(self.staging, seal, &op).await;
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
        if let Some(index) = cached_bin_index(self.snapshot_cache, self.bin_keys).await {
            return Some(index);
        }
        let observed = self
            .bin_index_record
            .borrow()
            .as_ref()
            .map(|held| held.record_bytes.clone());
        match load_bin_index(
            self.transport,
            self.gateway,
            self.http,
            self.floors,
            self.snapshot_cache,
            self.scheduler,
            self.profile,
            self.bin_keys,
        )
        .await
        .enrol(self.bin_index_record, observed)
        {
            BinIndexLoad::Resolved(index) | BinIndexLoad::Stale { index, .. } => Some(index),
            BinIndexLoad::Empty(_) => None,
        }
    }

    /// The captures this pass may adopt, removed from the shared set.
    ///
    /// A node the base still links did not leave the tree — a move or a
    /// dual-link loser departs one parent and stays named by another — and
    /// binning it would seal a live node under a key no reader derives. A child
    /// that does not publish under a name this scope's write seed derives is a
    /// scope root, which the authored delete refuses for the same reason. A name
    /// longer than this build ever authors is a peer's, and no entry carries it.
    fn take_captures(&self, scope: &DrainScope<'_>) -> Vec<UnlinkedChild> {
        let base = self.base.borrow();
        let mut set = self.observed_unlinks.borrow_mut();
        let mut taken = Vec::new();
        set.retain(|unlinked| {
            // A capture belongs to whichever pass names its scope. One that no
            // proved root names — a grafted root's focus leg captures these,
            // and no pass ever drains a grafted root — is a capture no pass
            // will ever adopt, and holding it starves the bounded set. A proved
            // scope this tick could not drain keeps its captures for the tick
            // that can, at the cost of a share of that bound.
            if unlinked.scope_id != scope.source.root.0 {
                return scope.scope_roots.contains(&NodeId(unlinked.scope_id));
            }
            if base.contains(unlinked.node)
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
            if taken.len() == MAX_BIN_ADOPTIONS {
                return true;
            }
            taken.push(unlinked.clone());
            false
        });
        taken
    }

    /// Put back the captures this pass did not settle, up to the frozen bound
    /// on what one session holds unadopted.
    fn return_captures(&self, unfinished: Vec<UnlinkedChild>) {
        hold_captures(self.observed_unlinks, unfinished);
    }

    /// The current bin index, ready to be written over.
    ///
    /// A fresh load every time: the index is rewritten whole, so a rewrite built
    /// on a copy read before an intervening publish drops that publish's
    /// entries. [`Self::carried_bin_index`] is the one caller that may build on
    /// what the pass already established.
    async fn writable_bin_index(&self) -> Result<BinIndex, Halt> {
        let observed = self
            .bin_index_record
            .borrow()
            .as_ref()
            .map(|held| held.record_bytes.clone());
        let index = load_bin_index(
            self.transport,
            self.gateway,
            self.http,
            self.floors,
            self.snapshot_cache,
            self.scheduler,
            self.profile,
            self.bin_keys,
        )
        .await
        .enrol(self.bin_index_record, observed)
        .writable()
        .map_err(|reason| {
            let halt = halt_for_bin_load(reason);
            if halt == Halt::Attempt {
                emit_trust_violation(
                    self.events,
                    self.bin_keys.name().as_str(),
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
        self.clear_bin_index_hold();
    }

    /// Publish the bin index and hold the confirmed record for renewal.
    async fn publish_bin(&self, index: BinIndex) -> Result<(), Halt> {
        // A publish that does not confirm leaves the standing index unknown, so
        // the next rewrite resolves rather than building on this attempt.
        *self.established_bin_index.borrow_mut() = None;
        let held = publish_bin_index(
            self.transport,
            self.api,
            self.floors,
            self.snapshot_cache,
            self.scheduler,
            self.profile,
            &mut SharedEntropy(self.entropy),
            self.orphan_heads,
            self.bin_keys,
            &index,
        )
        .await
        .map_err(|error| halt_for_bin_publish(&error))?;
        *self.bin_index_record.borrow_mut() = Some(held);
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
        let held = self.bin_keys.held_key(&root.0, deleted_at);
        let binned = SealPlane {
            end: ScopeEnd {
                read_scope_seed: &held,
                ..plane.end
            },
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
                name,
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
                            .filter(|child| names_this_scope(&from.end, child))
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
                    &name,
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
        let unlinked = self.base.borrow().links_to(target).is_empty();
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
        let ledger = StagingRetireLedger::new(self.staging, seal);
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
            .map(|(deleted_at, (target, _))| self.bin_keys.held_key(&target.0, deleted_at));
        let plane = scope.source.at(root.epoch);
        let sealed_under = held.as_ref().map_or(plane, |held| SealPlane {
            end: ScopeEnd {
                read_scope_seed: held,
                ..scope.source
            },
            ..plane
        });
        let mut proven = Vec::new();
        let mut held_over = Vec::new();
        for entry in quarantined {
            let verdict = if self.base.borrow().contains(entry.node) {
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
        if dest == target || self.base.borrow().ancestors(dest).contains(&target) {
            return Err(Halt::Unclassified);
        }
        let modified_at = applied.op.authored_at.0;

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
        if let Err(failure) = self
            .publish_folder(scope, pass, source, modified_at, Some(applied.op_id))
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
            self.orphan_heads.record(name.as_str());
        }
    }

    /// Take on the cut a move out of `scope_root` owes ([`owe_cut`]).
    async fn owe_scope_exit(&self, scope: &DrainScope<'_>, scope_root: NodeId) {
        owe_cut(
            self.staging,
            self.bookkeeping_seal(scope),
            scope.enc_secret,
            self.pending_scope_exits,
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
                &self.base.borrow(),
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
            let published = self
                .publish_node(
                    scope,
                    dest,
                    node,
                    &name,
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
        fanout_get_verify(self.transport, name)
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
                &plane,
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
                &plane,
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
        let end = scope.end_of(&self.base.borrow(), NodeId(node)).ok()?;
        let name = end.write_name(&node).as_str().to_owned();
        let reaching = |cids| Some(LiveRecord { name, cids });
        if owing == OwingRecord::Retired {
            return reaching(BTreeSet::new());
        }
        let (plane, root) = self.ledger_plane(end).await?;
        // Nocache: the retire unpins, so what may be named is decided against
        // the freshest record the gate will pass, never a cached one a
        // concurrent writer has already moved past.
        let loaded = self
            .load_child_node(&plane, root.anchor(), NodeId(node), ResolveMode::NoCache)
            .await
            .ok()?;
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
            &scope.source.root.0,
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

    /// The staged bytes at `key`, admitted by [`admissible_staged_block`].
    async fn staged_block(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Halt> {
        let Some(block) = self.staging.staged_bytes(key).await.map_err(seam)? else {
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
        let base = self.base.borrow();
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
        let plane = scope
            .folder_plane(pass, folder)
            .map_err(PublishHalt::before_the_put)?;
        let published = self
            .publish_node(
                scope,
                &plane,
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
        plane: &SealPlane<'_>,
        node: NodeId,
        name: &IpnsName,
        is_scope_root: bool,
        body: &ReadBody,
        content_cids: Vec<String>,
        carried_unknown: PreservedFields,
        carried_epoch_tag_unknown: PreservedFields,
        completes: Option<OpId>,
    ) -> Result<Published, PublishHalt> {
        plane_seals(plane, node, name, is_scope_root).map_err(PublishHalt::before_the_put)?;
        let read_key = plane.end.read_key(&node.0);
        let nonce = fresh_nonce(&mut *self.entropy.borrow_mut())
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
            // without its link (`net/rotation.rs::gated_child_root`).
            let owes_ascent_link = plane.end.ascent_node_seed.is_some();
            author_scope_root_envelope(authoring, name, scope.owner_identity, owes_ascent_link)
        } else {
            author_child_envelope(authoring)
        }
        .map_err(|error| PublishHalt::before_the_put(self.report_author_refusal(name, error)))?;
        self.report_carried_cut(name, &head.cut);

        let record_bytes = self
            .publish_head(plane, name, &node.0, &head, content_cids.clone())
            .await
            .map_err(PublishHalt::before_the_put)?;
        if let Some(op_id) = completes {
            self.mark_published(scope, op_id).await;
        }
        // The record is live from here: everything below is a local step.
        let local = local_head(&head);
        let pass = if is_scope_root {
            let adopter = self.root_adopter(scope, &plane.end);
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
                plane.end.root.0,
                plane.end.read_scope_seed.clone(),
                node.0,
            );
            adopter.hold_local_head(local);
            adopter
                .adopt(name, &record_bytes)
                .await
                .map_err(|_| PublishHalt::past_the_put(Halt::Unclassified))?
        }
        .pass;

        // Cached implies gate-passing: these bytes just cleared the gate.
        self.snapshot_cache
            .put(name.as_str().as_bytes(), &record_bytes)
            .await
            .map_err(|e| PublishHalt::past_the_put(seam(e)))?;
        // Durable-first: the floor moves on the self-adopt that also left these
        // bytes as last-known-good.
        let sequence = pass
            .commit(self.floors)
            .await
            .map_err(|e| PublishHalt::past_the_put(seam(e)))?
            .sequence;
        Ok(Published {
            sequence,
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

    /// Dry-run, publish, and return the signed bytes. `Ok` means the record
    /// confirmed at its name: an unconfirmed or race-losing publish is `Err`,
    /// because its bytes may never have landed.
    async fn publish_head(
        &self,
        plane: &SealPlane<'_>,
        name: &IpnsName,
        node_id: &[u8; 16],
        head: &AuthoredHead,
        content_cids: Vec<String>,
    ) -> Result<Vec<u8>, Halt> {
        let binding = plane.head_binding(node_id);
        let preflighted = preflight(&binding, &plane.end.read_key(node_id), head)
            .map_err(|_| Halt::UploadAttempt)?;
        let signer = SessionIdentity::write_name_signer(plane.end.write_scope_seed, node_id);
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
    ///
    /// An op that staged no version takes a notice there instead, which is what
    /// makes it nameable again after a cold start.
    async fn preserve_dead_letter(
        &self,
        scope: &DrainScope<'_>,
        op_id: OpId,
        reason: DeadLetterReason,
    ) -> Result<Preservation, Halt> {
        let queued = self.staging.queued_ops().await.map_err(seam)?;
        let Some((_, record)) = queued.iter().find(|(id, _)| *id == op_id) else {
            return Ok(Preservation::Kept);
        };
        preserve_dead_letter(
            self.staging,
            &owner_scoped_key(DEAD_LETTER_NOTICES_PREFIX, scope.enc_secret),
            op_id,
            reason,
            record,
            self.scheduler.now(),
        )
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
    /// this record with exactly no floor, and the retry it is owed re-mints the
    /// same sequence. A raised sequence floor says the same for a publish that
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
            self.staging
                .staged_bytes(OP_ATTEMPTS_KEY)
                .await
                .map_err(seam)?,
        );
        if attempts.charged_to(op_id) > 0 {
            return Ok(false);
        }
        let name = plane.end.write_name(&target.0);
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
            plane.end.root.0,
            plane.end.read_scope_seed.clone(),
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
        let base = self.base.borrow();
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
/// where the halt is not a failed attempt: a hold keeps the op and its
/// reservation, and the host reads them from `SnapshotView::blocked`,
/// `SnapshotView::settings_hold` and `SnapshotView::bin_index_hold`.
fn upload_failure(halt: Halt) -> Option<&'static str> {
    match halt {
        // A cancel reports `UploadCancelled` from the facade that ordered it.
        Halt::Blocked { .. }
        | Halt::HeldBySettings(_)
        | Halt::HeldByBinIndex(_)
        | Halt::Cancelled => None,
        Halt::Unclassified => Some("the upload did not complete"),
        Halt::EpochLagged => Some("this folder is still being re-keyed after a key change"),
        Halt::Attempt | Halt::UploadAttempt => {
            Some("the network refused it without a classification")
        }
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
    use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use crate::net::record_publish::PreflightError;
    use crate::seams::SeamError;
    use crate::settings::PlacementRefusal;
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
                write_scope_seed: &self.write_scope_seed,
                ascent_node_seed: None,
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
        Pass {
            root: SOURCE_ROOT,
            epoch: SOURCE_EPOCH,
            history_links: Vec::new(),
            second_ratchet: None,
            folders: vec![(
                folder,
                FolderState {
                    plane_root,
                    name: derive_write_name(&Zeroizing::new([4; 32]), &folder.0),
                    is_scope_root: false,
                    envelope_unknown: PreservedFields::new(),
                    epoch_tag_unknown: PreservedFields::new(),
                    created_at: 1,
                    modified_at: 1,
                    children: Vec::new(),
                    body_unknown: PreservedFields::new(),
                    sequence: 1,
                },
            )],
            journalled: Vec::new(),
        }
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
            epoch_skew(&scope, &source.end().at(SOURCE_EPOCH)),
            Halt::Unclassified,
            "the anchor's epoch is the pass's own, and the next pass reopens on it"
        );
        assert_eq!(
            epoch_skew(&scope, &destination.end().at(DESTINATION_EPOCH)),
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
            DefaultsReason::Unreadable,
        ] {
            assert_eq!(halt_for_bin_load(reason), Halt::Attempt, "{reason:?}");
        }
        for reason in [
            DefaultsReason::UnprovenFirstRun,
            DefaultsReason::Suppressed,
            DefaultsReason::TimedOut,
            DefaultsReason::FloorUnreadable,
        ] {
            assert_eq!(
                halt_for_bin_load(reason),
                Halt::HeldByBinIndex(reason),
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

    /// A tick settling many scopes gives each of them a share of its replay
    /// slots: settled first, one scope's backlog would otherwise take them all
    /// and leave the reclamations of the scopes behind it pending.
    #[test]
    fn a_tick_shares_its_journal_replays_across_the_scopes_it_settles() {
        assert_eq!(
            JournalBudget::new(1).share(),
            MAX_JOURNAL_REPLAYS,
            "one scope may spend the whole tick's slots"
        );
        let mut four = JournalBudget::new(4);
        assert!(
            four.share() < MAX_JOURNAL_REPLAYS && four.share() * 4 >= MAX_JOURNAL_REPLAYS,
            "four scopes divide them, and every slot is reachable"
        );
        four.replays = 1;
        assert_eq!(
            four.share(),
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
}
