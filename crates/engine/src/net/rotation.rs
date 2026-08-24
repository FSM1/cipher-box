//! The production rotation seams: the owner arm of the impure edges the
//! read-plane rotation primitives run on (blueprint/engine.md "Rotation
//! primitives", "Pointer planes").
//!
//! [`crate::rotation`] is pure apart from a gated read of a descendant scope
//! root's own write-body index ([`ChildIndexResolver`]), the same read widened
//! to a descendant's whole re-seal material ([`CascadeResealResolver`]), and a
//! register-first CAS publish of a re-sealed scope root ([`ScopeRootPublisher`]).
//! All three land here, composed from the net plane already in place — fan-out
//! GET plus [`RootAdopter`] for the read, [`author`](super::author) plus
//! [`publish_record`] for the write. No crypto and no trust logic is added: the
//! adoption gate stays the only judge of a resolved record, and the publish
//! pipeline stays the only path to the transport.

use core::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::seal::{
    AadContext, ChildScopeRef, Envelope, GrantBlobPayload, GrantLedgerEntry, GrantSection,
    GrantSetCommitment, GrantSetEntry, Permission, PreservedFields, ReadBody,
    STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_WRITE_BODY, SignedSealed, WriteBody,
    decode_envelope, decode_write_body, has_grant_section, open_grant_blob, open_owner_blob,
    open_read_body, sign_grant_set, unseal,
};
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier, SIGNATURE_LEN as ECDSA_SIG_LEN};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use zeroize::Zeroizing;

use super::adopter::{LocalHead, RootAdopter, fetch_head_block, open_write_scope_seed_at};
use super::author::{
    AuthorError, ENVELOPE_V, EnvelopeAuthoring, author_child_envelope,
    author_scope_root_with_section,
};
use super::child::ChildAdopter;
use super::pointer_fetch::RecordPointerFetch;
use super::publish::{InlineRecordRequest, PublishError, PublishOutcome, publish_inline};
use super::record_publish::{
    HeadBinding, RecordPublishError, RecordPublishRequest, preflight, publish_record,
};
use super::retire::{retire, root_retire_ready};
use crate::api::ApiClient;
use crate::content::Gateway;
use crate::content::root_block_cid;
use crate::entropy::{Entropy, SharedEntropy};
use crate::facade::NodeId;
use crate::gate::{GateError, RejectionReason, floor};
use crate::grants::{
    UNATTESTED_IDENTITY_PK, bound_recipient, enforce_committed_ledger, mint_grant_row,
    recipient_self_location, row_is_owner_attested, self_locate_signed,
};
use crate::net::fanout_get_verify;
use crate::net::resolve::Adopter;
use crate::profile::SyncTimingProfile;
use crate::rotation::sweep::body_children;
use crate::rotation::{
    AscentAuthority, CascadeResealResolver, CascadeTarget, ChildIndexResolver, CommittedSet,
    LaggingNode, NodeRef, PrevEpochSeed, RepointChannel, RepublishedNode, ResealError, ResealSeeds,
    ResealedScopeRoot, ResolveFailure, ResumedWriteWave, RotateError, RotateScopePlan,
    RotationOutcome, RotationPublishError, ScopeExitRotator, ScopeRootIdentity, ScopeRootPublisher,
    SweepPublisher, SweepResolveFailure, SweepResolver, SweptChild, SweptNode, SweptScope,
    WriteHistory, WritePublishError, WriteScopeNode, WriteSubtreeResolver, WriteWavePublisher,
    derive_write_name, reseal_scope_root, rotate_scope, seed_at_epoch,
};
use crate::seams::{BoxedTask, CredentialStore, FloorStore, Http, RecordTransport, Scheduler};
use crate::session::SessionIdentity;
use crate::sync::pointer::{PointerFetch, open_repoint, scope_pointer_name, scope_pointer_signer};

/// The owner key material the rotation edges run under. The owner is the
/// terminal owner of its own key material, so nothing here is zeroized.
pub struct OwnerRotationKeys<'a> {
    /// Opens each scope root's owner blob — the owner's read-seed source, and
    /// the key the re-sealed section must reopen under before it is signed.
    pub enc_secret: &'a X25519Secret,
    /// The contact-anchored owner identity: the adoption gate's stage-2 anchor.
    pub identity: &'a EcdsaVerifier,
    /// The two per-scope derivations a re-seal needs, and no wider capability.
    pub scope_keys: &'a dyn OwnerScopeKeys,
}

/// The owner derivations the rotation resolves per scope. A cascade discovers
/// its scope ids at runtime, so it cannot be handed pre-derived values — but it
/// must not be handed the seeds they come from either: `ownerPointerSeed` also
/// derives the scope-pointer **signing** key, and the root secret is the owner's
/// master material. This narrows the rotation to exactly the two edges it uses
/// (store the narrowest derived capability).
pub trait OwnerScopeKeys {
    /// `pseudonym-sign` for this scope — the signer every re-sealed structure
    /// is detach-signed under, and which the record's commitment must name.
    fn writer_pseudonym(&self, scope_id: &[u8; 16]) -> Ed25519Signer;

    /// `pointer-read-key` for this scope — the stable key each grant blob
    /// carries.
    fn pointer_read_key(&self, scope_id: &[u8; 16]) -> Zeroizing<[u8; SECRET_LEN]>;
}

/// The owner-arm rotation seams over the live net plane.
pub struct OwnerRotationNet<'a, T, H: Http, C: CredentialStore, F, Sch, E> {
    /// The record-plane transport: fan-out GET for the read, CAS PUT for the
    /// publish.
    pub transport: &'a T,
    /// The API client: register-first and the head-block upload.
    pub api: &'a ApiClient<H, C>,
    /// Content read sources for the head block.
    pub gateway: &'a Gateway,
    /// The HTTP seam the content fetch rides.
    pub http: &'a H,
    /// The durable floors the adoption gate reads and advances.
    pub floors: &'a F,
    /// The scheduler the publish pipeline's background re-PUT rides.
    pub scheduler: &'a Sch,
    /// The publish pipeline's timing policy.
    pub profile: &'a SyncTimingProfile,
    /// Injected entropy — the per-seal nonce source (determinism law: engine
    /// logic never reaches for an RNG).
    pub entropy: &'a RefCell<E>,
    /// The owner material.
    pub keys: OwnerRotationKeys<'a>,
    /// The ancestor seeds every interior scope root's gated read needs.
    pub ancestry: RotationAncestry,
    /// Derives the scope pointer's name for the sweep's consult (owner-only
    /// material, never published). `None` on a pass that runs no sweep, so an
    /// arm that needs neither the pointer nor its signing key is never handed
    /// the seed that derives both (store the narrowest derived capability); a
    /// consult without it refuses rather than skipping.
    pub owner_pointer_seed: Option<&'a [u8; SECRET_LEN]>,
    /// The pointer-payload envelope version a consulted re-point is read under.
    pub payload_version: u64,
    /// The record a re-key is about to replace, handed from the resolve that
    /// gated it to the publish (see [`GatedRoots`]). One rotation pass per net.
    pub gated: GatedRoots,
    /// The scope the sweep is walking, held from the scope-root read that
    /// proved it (see [`SweptScopeState`]). One sweep pass per net.
    pub swept: SweptScopeState,
}

/// The one scope root this pass gated and has not yet republished.
///
/// A cascade resolves a descendant and then immediately publishes its re-key,
/// which would otherwise fetch and gate the same record twice — so the resolve
/// parks what the publish needs and the publish takes it. One slot, because
/// that hand-off is the only contract: a second park evicts the first rather
/// than retaining every descendant's record for the length of the walk.
#[derive(Default)]
pub struct GatedRoots {
    inner: RefCell<Option<(IpnsName, RepublishBase)>>,
}

impl GatedRoots {
    fn park(&self, name: IpnsName, base: RepublishBase) {
        *self.inner.borrow_mut() = Some((name, base));
    }

    /// The parked record for `name`, if that is the one parked. Matching on the
    /// name and not the scope keeps the caller-imposed label authoritative: a
    /// scope reached under a second `ipnsName` re-reads rather than aliasing
    /// onto the first record (the C2 conflict, `rotation/cascade.rs`).
    fn take(&self, name: &IpnsName) -> Option<RepublishBase> {
        let mut parked = self.inner.borrow_mut();
        match parked.as_ref() {
            Some((parked_name, _)) if parked_name == name => parked.take().map(|(_, base)| base),
            _ => None,
        }
    }
}

/// What republishing a scope root needs from the record it replaces: the body
/// carried forward, the envelope fields a republish preserves byte-stable
/// (#27 D10), and the write seed the record's name signs under.
struct RepublishBase {
    read_body: ReadBody,
    unknown: PreservedFields,
    epoch_tag_unknown: PreservedFields,
    /// `None` when the root is held keyless — no seed to sign a republish under.
    write_scope_seed: Option<Zeroizing<[u8; SECRET_LEN]>>,
}

impl From<GatedScopeRoot> for RepublishBase {
    fn from(root: GatedScopeRoot) -> Self {
        Self {
            read_body: root.read_body,
            unknown: root.envelope.unknown,
            epoch_tag_unknown: root.envelope.epoch_tag_unknown,
            write_scope_seed: root.write_scope_seed,
        }
    }
}

/// The `scope_id -> parent` edges and per-scope override seeds a walk needs to
/// derive each interior scope root's ancestor node seed.
///
/// Every interior scope root carries an ascent link, and the adoption gate
/// derives the expected ascent keypair from the **reader's** ancestor node seed
/// rather than from the record — no seed, no gate pass. Seeded at the rotating
/// root ([`Self::rooted_at`]) and extended as the walk gates each level: a
/// descendant's parent edge comes from the gated parent index that named it, and
/// the parent's override seed from that parent's own gate-passing owner blob, so
/// no network-supplied field ever chooses which seed a scope is read under.
#[derive(Default)]
pub struct RotationAncestry {
    inner: RefCell<Ancestry>,
}

#[derive(Default)]
struct Ancestry {
    /// The rotating root's own ancestor node seed, when it is itself an interior
    /// scope root ([`RotationAncestry::under_parent_node_seed`]).
    root: Option<([u8; 16], Zeroizing<[u8; SECRET_LEN]>)>,
    parents: BTreeMap<[u8; 16], [u8; 16]>,
    override_seeds: BTreeMap<[u8; 16], Zeroizing<[u8; SECRET_LEN]>>,
}

impl RotationAncestry {
    /// Seed the walk at the rotating root: the override seed its descendants'
    /// **published** records sealed their ascent links under, plus the parent
    /// edge for each entry of its caller-held direct-child-scope index.
    ///
    /// After the root's own cut has landed that is the root's **pre-cut** seed,
    /// not the plan's current one — a descendant that never republished still
    /// carries the previous derivation, and gating it under the post-cut seed
    /// fails closed at the ascent link.
    pub fn rooted_at(
        scope_id: [u8; 16],
        override_seed: &[u8; SECRET_LEN],
        child_index: &[ChildScopeRef],
    ) -> Self {
        let ancestry = Self::default();
        ancestry.record(scope_id, override_seed, child_index);
        ancestry
    }

    /// Supply the **rotating root's own** ancestor node seed. Required whenever
    /// the rotation is anchored at an interior scope root — a revoke or
    /// scope-exit on a shared folder — whose record carries an ascent link the
    /// gate verifies against a reader-derived keypair. `None` is the vault root,
    /// which carries no ascent link and needs none.
    ///
    /// The seed is also what [`OwnerRotationNet::resolve_anchored`] reads to pick
    /// the binding a gated root read runs under, so the two cannot disagree.
    pub fn under_parent_node_seed(
        self,
        scope_id: [u8; 16],
        parent_node_seed: Option<&[u8; SECRET_LEN]>,
    ) -> Self {
        if let Some(seed) = parent_node_seed {
            self.inner.borrow_mut().root = Some((scope_id, Zeroizing::new(*seed)));
        }
        self
    }

    fn record(
        &self,
        scope_id: [u8; 16],
        override_seed: &[u8; SECRET_LEN],
        child_index: &[ChildScopeRef],
    ) {
        let mut inner = self.inner.borrow_mut();
        inner
            .override_seeds
            .insert(scope_id, Zeroizing::new(*override_seed));
        for child in child_index {
            // A writer-authored index naming a scope this walk already gated —
            // its own, or an ancestor — would derive a parent seed for a root
            // from below it, minting an ascent link no reader's descent
            // reproduces (`rotation/eager_set.rs::bind_child_labels` skips the
            // walk root on the same rule). A gated scope already has whatever
            // parent edge it is entitled to, so nothing honest is dropped.
            if inner.override_seeds.contains_key(&child.scope_id) {
                continue;
            }
            // First-seen wins, matching the walk's own dedup: a scope listed by
            // two parents must gate under the same one whichever order the walk
            // reaches it in.
            inner.parents.entry(child.scope_id).or_insert(scope_id);
        }
    }

    /// `nodeSeed(parentOverrideSeed, scope_id)` — the caller-supplied seed at the
    /// rotating root, otherwise derived from the parent this walk already gated.
    fn parent_node_seed(&self, scope_id: &[u8; 16]) -> Option<Zeroizing<[u8; SECRET_LEN]>> {
        let inner = self.inner.borrow();
        if let Some((root, seed)) = &inner.root
            && root == scope_id
        {
            return Some(seed.clone());
        }
        let parent = inner.parents.get(scope_id)?;
        let parent_seed = inner.override_seeds.get(parent)?;
        Some(Zeroizing::new(
            *kdf::node_seed(parent_seed, scope_id).as_bytes(),
        ))
    }
}

/// Which root binding a gated read must prove.
///
/// A descendant's record is bound to its parent by an ascent link the gate
/// verifies ([`gated_child_root`]) — a `directChildScopeIndex` entry, or one
/// reparented into a grant's subtree. A vault root carries no ascent link, so
/// requiring one there would refuse every honest record.
enum RootAnchor {
    /// A claimed descendant scope root — proven a child, not merely a root.
    Descendant,
    /// The vault root.
    VaultRoot,
}

/// One scope root as the adoption gate authenticated it, plus the seeds the
/// owner recovered from its own blobs. Terminal owner of those seeds: they
/// zeroize when the value is dropped.
struct GatedScopeRoot {
    envelope: Envelope,
    section: GrantSection,
    read_body: ReadBody,
    /// The override seed recovered from this root's own owner blob — the
    /// ancestor seed its descendants' ascent links are derived from.
    read_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// `None` when the root is held keyless — no owner-write-blob, or no
    /// durable write-epoch floor to open it under.
    write_scope_seed: Option<Zeroizing<[u8; SECRET_LEN]>>,
}

/// One scope root as this pass gated it, plus the write plane read out of it:
/// the name it was gated at, the authenticated record, its unsealed write body,
/// and the write epoch that body opened under.
struct GatedWritePlane {
    name: IpnsName,
    root: GatedScopeRoot,
    write_body: WriteBody,
    write_epoch: u64,
}

/// Parse a `ChildScopeRef`'s opaque `ipnsName` bytes. A name that is not a
/// canonical IPNS name has no verifying key to gate against, so it is a
/// fail-closed rejection rather than an availability stall.
pub(crate) fn scope_name(ipns_name: &[u8]) -> Result<IpnsName, ResolveFailure> {
    core::str::from_utf8(ipns_name)
        .ok()
        .and_then(|text| IpnsName::parse(text).ok())
        .ok_or(ResolveFailure::Rejected)
}

/// Recover the freshly minted override seed from the re-sealed section's own
/// owner blob, under the AAD the envelope about to carry it will claim.
///
/// The rotation primitive is the terminal owner of the seed it minted and hands
/// the publisher none, so this is the only source of the seed the record must
/// seal under — and a section that will not reopen under the owner key the
/// adoption gate re-derives can therefore never be signed (release-active,
/// security rule 8). That failure is permanent for these bytes, so it is a
/// rejection rather than a retryable stall — the sweep must not re-run it.
fn new_override_seed(
    enc_secret: &X25519Secret,
    record: &ResealedScopeRoot,
) -> Result<Zeroizing<[u8; SECRET_LEN]>, RotationPublishError> {
    let owner_blob = &record.section.owner_blob;
    let aad = AadContext {
        v: ENVELOPE_V,
        id: record.scope_id,
        scope: record.scope_id,
        epoch: record.read_epoch,
        struct_tag: STRUCT_TAG_OWNER_BLOB,
    };
    let payload = open_owner_blob(enc_secret, &owner_blob.enc, &aad, &owner_blob.ciphertext)
        .map_err(|_| RotationPublishError::Rejected)?;
    Ok(Zeroizing::new(*payload.override_seed()))
}

/// Carry a resolve verdict into the publish arm without laundering a
/// fail-closed trust violation into a retryable transport failure (rule 6).
fn publish_verdict(failure: ResolveFailure) -> RotationPublishError {
    match failure {
        ResolveFailure::Unavailable => RotationPublishError::NotPublished,
        ResolveFailure::Rejected | ResolveFailure::ConflictingChildLabel => {
            RotationPublishError::Rejected
        }
    }
}

/// Carry an authoring refusal into the publish arm on the same rule-6 axis as
/// [`publish_verdict`]. A trust refusal is this build's own gate verdict on the
/// bytes it was about to sign, reached before the PUT: re-authoring the same
/// section reaches it again, so retrying it would launder a trust violation into
/// an availability stall. A codec or size refusal is a property of the body this
/// pass built, and stays retryable: it is reached from a record the next pass
/// re-resolves, and a permanent verdict on it would let anyone who can grow that
/// record block the owner's revocation for good.
fn author_verdict(refusal: AuthorError) -> RotationPublishError {
    if refusal.is_trust_refusal() {
        RotationPublishError::Rejected
    } else {
        RotationPublishError::NotPublished
    }
}

/// Carry a publish-pipeline failure onto rule 6's axis. An API that echoes back
/// an address other than the one we uploaded is not answering about our block,
/// and an empty head CID is this build's own release-active refusal to sign
/// `/ipfs/` ([`PublishError::EmptyHeadCid`]) — both deterministic on what this
/// pass authored, so a retry re-authors and re-charges a head block forever
/// without converging. Everything else, including a body this pass built too
/// large, stays retryable: those inputs are attacker-influenced, and a permanent
/// verdict on them would let anyone who can grow a record block the rotation.
fn record_publish_verdict(error: RecordPublishError) -> RotationPublishError {
    match error {
        RecordPublishError::HeadCidMismatch { .. }
        | RecordPublishError::Publish(PublishError::EmptyHeadCid) => RotationPublishError::Rejected,
        _ => RotationPublishError::NotPublished,
    }
}

/// A fresh per-seal nonce from the injected entropy seam.
fn nonce<E: Entropy>(entropy: &RefCell<E>) -> Result<[u8; 24], RotationPublishError> {
    let mut nonce = [0u8; 24];
    entropy
        .borrow_mut()
        .fill(&mut nonce)
        .map_err(|_| RotationPublishError::NotPublished)?;
    Ok(nonce)
}

/// A rotation root read's verdict, carrying ADR 0003 D2's below-floor split: a
/// scope root under its own read-epoch floor is a **superseded name**, not a
/// trust rejection — rotations publish before they raise the floor, so the
/// condition cannot mean the root lags. Only the sweep routes that verdict
/// (through the pointer consult); every other arm folds it back into a
/// fail-closed rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootGateVerdict {
    Rejected,
    Unavailable,
    Superseded,
}

impl From<RootGateVerdict> for ResolveFailure {
    fn from(verdict: RootGateVerdict) -> Self {
        match verdict {
            RootGateVerdict::Unavailable => Self::Unavailable,
            RootGateVerdict::Rejected | RootGateVerdict::Superseded => Self::Rejected,
        }
    }
}

impl From<RootGateVerdict> for SweepResolveFailure {
    fn from(verdict: RootGateVerdict) -> Self {
        match verdict {
            RootGateVerdict::Unavailable => Self::Unavailable,
            RootGateVerdict::Rejected => Self::Rejected,
            RootGateVerdict::Superseded => Self::Superseded,
        }
    }
}

/// The rejection arm of a rotation's gated read, recovered at the durable
/// sequence floor.
///
/// Adopting a scope root raises that name's sequence floor, so re-reading the
/// **unchanged** record rejects as not-newer — and a rotation reads in order to
/// re-key, so a pass that aborts before publishing must be able to read again or
/// the revoke can never complete. Only the exact floor recovers; a strictly
/// lower sequence is a replay, and every other rejection stays a fail-closed
/// trust violation (rule 6).
async fn reread_at_floor<H: Http, F: FloorStore>(
    adopter: &RootAdopter<'_, H, F>,
    name: &IpnsName,
    record_bytes: &[u8],
    reason: &RejectionReason,
) -> Result<GatedScopeRoot, RootGateVerdict> {
    if !matches!(
        reason,
        RejectionReason::SequenceNotNewer { floor, sequence } if sequence == floor
    ) {
        return Err(RootGateVerdict::Rejected);
    }
    let recovered = adopter
        .recover_own_scope_root(name, record_bytes)
        .await
        .map_err(|_| RootGateVerdict::Unavailable)?
        // The recovery is fail-open; the rotation keeps the gate's own verdict.
        .ok_or(RootGateVerdict::Rejected)?;
    Ok(GatedScopeRoot {
        envelope: recovered.envelope,
        section: recovered.grant_section,
        read_body: recovered.read_body,
        read_scope_seed: recovered.read_scope_seed,
        write_scope_seed: recovered.write_scope_seed,
    })
}

/// Gate `record_bytes` as a scope root under the label `adopter` carries,
/// recovering this reader's own already-adopted record through
/// [`reread_at_floor`]. The one ladder every rotation arm's root read runs.
async fn gated_scope_root<H: Http, F: FloorStore>(
    adopter: &RootAdopter<'_, H, F>,
    name: &IpnsName,
    record_bytes: &[u8],
) -> Result<GatedScopeRoot, RootGateVerdict> {
    match adopter.adopt_root(name, record_bytes).await {
        Ok((candidate, outcome)) => Ok(GatedScopeRoot {
            envelope: candidate.envelope,
            section: candidate.grant_section,
            read_body: outcome.adopted.read_body,
            read_scope_seed: outcome
                .read_scope_seed
                .ok_or(RootGateVerdict::Unavailable)?,
            write_scope_seed: outcome.write_scope_seed,
        }),
        Err(GateError::Seam(_)) => Err(RootGateVerdict::Unavailable),
        Err(GateError::Rejected(rejection))
            if matches!(rejection.reason, RejectionReason::EpochBelowFloor { .. }) =>
        {
            Err(RootGateVerdict::Superseded)
        }
        Err(GateError::Rejected(rejection)) => {
            reread_at_floor(adopter, name, record_bytes, &rejection.reason).await
        }
    }
}

/// Gate `record_bytes` as the scope root of `expected_id`, a claimed **child**
/// scope of the one `adopter` carries the parent node seed for.
///
/// Two bindings prove it, and the caller supplies neither: the owner-signed
/// commitment binds the name, and the **ascent link** — required here,
/// release-active — binds the record to `nodeSeed(parent read seed, child)`. The
/// gate verifies an ascent link only when the record carries one and the vault
/// root carries none, so without this requirement any owner-signed root planted
/// by a committed writer would gate cleanly as this scope's descendant.
async fn gated_child_root<H: Http, F: FloorStore>(
    adopter: &RootAdopter<'_, H, F>,
    name: &IpnsName,
    record_bytes: &[u8],
    expected_id: [u8; 16],
) -> Result<GatedScopeRoot, RootGateVerdict> {
    let gated = gated_scope_root(adopter, name, record_bytes).await?;
    if gated.envelope.id != expected_id || gated.section.ascent_link.is_none() {
        return Err(RootGateVerdict::Rejected);
    }
    Ok(gated)
}

/// Unseal a gated scope root's write-body under the write scope seed the reader
/// recovered, at the durable write-epoch floor, and report that floor — the AAD
/// epoch the seed's own recovery already bound, and the write epoch a re-seal of
/// this root must republish at. A root held keyless has no readable write-body —
/// availability, not a trust verdict.
async fn write_plane_of<F: FloorStore>(
    floors: &F,
    envelope: &Envelope,
    section: &GrantSection,
    write_scope_seed: &[u8; SECRET_LEN],
    scope_id: [u8; 16],
) -> Result<(WriteBody, u64), ResolveFailure> {
    let Some(write_epoch) = floor::write_epoch_floor(floors, &scope_id)
        .await
        .map_err(|_| ResolveFailure::Unavailable)?
    else {
        return Err(ResolveFailure::Unavailable);
    };
    let body = open_write_body(envelope, section, &scope_id, write_scope_seed, write_epoch)?;
    Ok((body, write_epoch))
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> OwnerRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport,
    F: FloorStore,
{
    /// The freshest verified record at `name` run through the adoption gate
    /// under `scope_id` — the caller's own trusted label, imposed on the gate so
    /// a record claiming another scope is a transplant it rejects
    /// ([`ChildIndexResolver::direct_child_index`]'s binding obligation).
    /// Idempotent: a record at this name's own sequence floor recovers through
    /// [`reread_at_floor`].
    async fn gated_root(
        &self,
        scope_id: [u8; 16],
        name: &IpnsName,
    ) -> Result<GatedScopeRoot, RootGateVerdict> {
        let Some((_, record_bytes)) = fanout_get_verify(self.transport, name).await else {
            return Err(RootGateVerdict::Unavailable);
        };
        gated_scope_root(&self.root_adopter(scope_id), name, &record_bytes).await
    }

    /// The adopter every root read of this arm runs under, carrying the ancestor
    /// seed this walk has already proved when it has one. Shared by both root
    /// edges so the label and the ascent authority cannot drift apart.
    fn root_adopter(&self, scope_id: [u8; 16]) -> RootAdopter<'_, H, F> {
        let adopter = RootAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            self.keys.enc_secret,
            self.keys.identity,
            scope_id,
        );
        match self.ancestry.parent_node_seed(&scope_id) {
            Some(seed) => adopter.under_parent_node_seed(seed),
            None => adopter,
        }
    }

    /// The prologue both read edges share: gate `scope`'s record under the
    /// caller's own label, unseal its write body, and extend the ancestry with
    /// the seed the pass just proved so the next level down can derive its own
    /// ascent authority. The seed recorded is the **published** one — the
    /// cascade re-keys top-down, so a descendant's record still carries the
    /// ascent link its parent's pre-cascade seed sealed.
    ///
    /// Which binding the gated read must prove is [`RootAnchor`]'s.
    async fn gated_write_plane(
        &self,
        scope: &ChildScopeRef,
        anchor: RootAnchor,
    ) -> Result<GatedWritePlane, ResolveFailure> {
        let name = scope_name(&scope.ipns_name)?;
        let adopter = self.root_adopter(scope.scope_id);
        let Some((_, record_bytes)) = fanout_get_verify(self.transport, &name).await else {
            return Err(ResolveFailure::Unavailable);
        };
        let root = match anchor {
            RootAnchor::Descendant => {
                gated_child_root(&adopter, &name, &record_bytes, scope.scope_id).await
            }
            RootAnchor::VaultRoot => gated_scope_root(&adopter, &name, &record_bytes).await,
        }
        .map_err(ResolveFailure::from)?;
        // A root held keyless has no readable write-body — availability, not a
        // trust verdict.
        let Some(write_scope_seed) = root.write_scope_seed.as_deref() else {
            return Err(ResolveFailure::Unavailable);
        };
        let (write_body, write_epoch) = write_plane_of(
            self.floors,
            &root.envelope,
            &root.section,
            write_scope_seed,
            scope.scope_id,
        )
        .await?;
        self.ancestry.record(
            scope.scope_id,
            &root.read_scope_seed,
            &write_body.direct_child_scope_index,
        );
        Ok(GatedWritePlane {
            name,
            root,
            write_body,
            write_epoch,
        })
    }

    /// [`CascadeResealResolver::resolve`] at [`RootAnchor::VaultRoot`]. Same
    /// gated read, same parked republish base; only the binding differs.
    pub async fn resolve_vault_root(
        &self,
        scope: &ChildScopeRef,
    ) -> Result<CascadeTarget, ResolveFailure> {
        self.resolve_at(scope, RootAnchor::VaultRoot).await
    }

    /// The same gated read under the binding this net's own ancestry implies: a
    /// root it holds an ancestor seed for is an interior one, which must prove
    /// its ascent link; a root it holds none for is the vault root, which carries
    /// none. Reading the anchor off the seed is what keeps the label and the
    /// ascent authority from drifting apart ([`Self::root_adopter`]).
    pub(crate) async fn resolve_anchored(
        &self,
        scope: &ChildScopeRef,
    ) -> Result<CascadeTarget, ResolveFailure> {
        match self.ancestry.parent_node_seed(&scope.scope_id) {
            Some(_) => self.resolve_at(scope, RootAnchor::Descendant).await,
            None => self.resolve_at(scope, RootAnchor::VaultRoot).await,
        }
    }

    async fn resolve_at(
        &self,
        scope: &ChildScopeRef,
        anchor: RootAnchor,
    ) -> Result<CascadeTarget, ResolveFailure> {
        let GatedWritePlane {
            name,
            root,
            write_body,
            write_epoch,
        } = self.gated_write_plane(scope, anchor).await?;
        let GatedScopeRoot {
            envelope,
            section,
            read_body,
            read_scope_seed,
            write_scope_seed,
        } = root;
        // This build authors exactly `ENVELOPE_V`, so re-sealing a newer
        // client's root under its own `v` would mint structures whose AAD this
        // build can never reproduce (`sync/drain.rs` guards the same downgrade).
        //
        // The root gate binds `envelope.scope` but not `envelope.id`, and every
        // AAD a re-seal of this target authors binds the id — so a root whose
        // record claims another node would be re-sealed under a key no reader
        // re-derives (the write wave imposes the same binding).
        if envelope.v != ENVELOPE_V || envelope.id != scope.scope_id {
            return Err(ResolveFailure::Rejected);
        }
        let Some(write_scope_seed) = write_scope_seed else {
            return Err(ResolveFailure::Unavailable);
        };

        let target = CascadeTarget {
            v: envelope.v,
            current_read_epoch: envelope.epoch,
            owner_enc_pub: self.keys.enc_secret.public(),
            pseudonym_signer: self.keys.scope_keys.writer_pseudonym(&scope.scope_id),
            override_seed: read_scope_seed,
            write_scope_seed: write_scope_seed.clone(),
            pointer_read_key: self.keys.scope_keys.pointer_read_key(&scope.scope_id),
            write_epoch,
            commitment: section.commitment,
            commitment_sig: section.commitment_sig,
            grant_ledger: write_body.grant_ledger,
            write_history_link: write_body.write_history_link,
            direct_child_scope_index: write_body.direct_child_scope_index,
            carried_history_links: section.history_links,
            carried_ascent_link: section.ascent_link.is_some(),
        };
        self.gated.park(
            name,
            RepublishBase {
                read_body,
                unknown: envelope.unknown,
                epoch_tag_unknown: envelope.epoch_tag_unknown,
                write_scope_seed: Some(write_scope_seed),
            },
        );
        Ok(target)
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> ChildIndexResolver
    for OwnerRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport,
    F: FloorStore,
{
    async fn direct_child_index(
        &self,
        child: &ChildScopeRef,
    ) -> Result<Vec<ChildScopeRef>, ResolveFailure> {
        let gated = self
            .gated_write_plane(child, RootAnchor::Descendant)
            .await?;
        Ok(gated.write_body.direct_child_scope_index)
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> CascadeResealResolver
    for OwnerRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport,
    F: FloorStore,
{
    async fn resolve(&self, scope: &ChildScopeRef) -> Result<CascadeTarget, ResolveFailure> {
        self.resolve_at(scope, RootAnchor::Descendant).await
    }
}

/// The seams a re-sealed scope root's publish runs on — the tail both rotation
/// arms share once each has recovered, from its own blob, the override seed the
/// fresh section wraps.
struct RootPublish<'a, T, H: Http, C: CredentialStore, F, Sch, E> {
    transport: &'a T,
    api: &'a ApiClient<H, C>,
    floors: &'a F,
    scheduler: &'a Sch,
    profile: &'a SyncTimingProfile,
    entropy: &'a RefCell<E>,
    /// The contact-anchored owner identity the authored root must verify under
    /// (`author_scope_root_with_section`'s pre-publish mirror of gate stage 2).
    owner_identity: &'a EcdsaVerifier,
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> RootPublish<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    /// The two durable-floor mirrors of gate rejects this build would itself make
    /// on the record about to be signed — release-active, because a signed record
    /// cannot be unpublished (security rule 8):
    ///
    /// - the read epoch must not sit below the durable revocation floor (stage 5);
    /// - the write epoch must not sit below the durable write floor, which the
    ///   owner-write-blob's AAD binds — below it the root publishes write-plane
    ///   dead, and floors are monotonic, so it can never be rotated back.
    ///
    /// Runs **after** this pass's gated read of the scope root, which may itself
    /// advance the read-epoch floor: measured before it, the floor comparison
    /// would miss a cut minted below the epoch that read just adopted.
    async fn check_publishable(
        &self,
        record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError> {
        let scope_id = &record.scope_id;
        let read_floor = floor::read_epoch_floor(self.floors, scope_id)
            .await
            .map_err(|_| RotationPublishError::NotPublished)?
            .unwrap_or(0);
        let write_floor = floor::write_epoch_floor(self.floors, scope_id)
            .await
            .map_err(|_| RotationPublishError::NotPublished)?
            .unwrap_or(0);
        if record.read_epoch < read_floor || record.write_epoch < write_floor {
            return Err(RotationPublishError::Rejected);
        }
        Ok(())
    }

    /// Author `record`'s envelope over `current` — the record it replaces — dry
    /// run it, and CAS-publish it register-first at `name`.
    async fn run(
        &self,
        name: &IpnsName,
        record: &ResealedScopeRoot,
        override_seed: &[u8; SECRET_LEN],
        current: RepublishBase,
    ) -> Result<(), RotationPublishError> {
        self.check_publishable(record).await?;

        let node_seed = kdf::node_seed(override_seed, &record.scope_id);
        let read_key = Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes());
        let nonce = nonce(self.entropy)?;
        let head = author_scope_root_with_section(
            EnvelopeAuthoring {
                node_id: record.scope_id,
                scope_id: record.scope_id,
                epoch: record.read_epoch,
                read_key: &read_key,
                nonce: &nonce,
                body: &current.read_body,
                carried_unknown: current.unknown,
                carried_epoch_tag_unknown: current.epoch_tag_unknown,
            },
            name,
            &record.section,
            self.owner_identity,
        )
        .map_err(author_verdict)?;

        let write_scope_seed = current
            .write_scope_seed
            .as_deref()
            .ok_or(RotationPublishError::NotPublished)?;

        let binding = HeadBinding {
            node_id: record.scope_id,
            scope_id: record.scope_id,
            epoch: record.read_epoch,
        };
        let preflighted = preflight(&binding, &read_key, &head)
            .map_err(|_| RotationPublishError::NotPublished)?;

        let signer = SessionIdentity::write_name_signer(write_scope_seed, &record.scope_id);
        let receipt = publish_record(
            self.transport,
            self.api,
            self.floors,
            self.scheduler,
            self.profile,
            &RecordPublishRequest {
                name,
                signer: &signer,
                head: &preflighted,
                content_cids: Vec::new(),
                min_current_sequence: None,
            },
        )
        .await
        .map_err(record_publish_verdict)?;

        match receipt.outcome {
            PublishOutcome::Published { .. } => Ok(()),
            PublishOutcome::LostRace { .. } => Err(RotationPublishError::LostRace),
            // Acked but not read back as ours: nothing is proven durable, and
            // re-publishing is idempotent-in-sequence.
            PublishOutcome::Unconfirmed { .. } => Err(RotationPublishError::NotPublished),
        }
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> OwnerRotationNet<'_, T, H, C, F, Sch, E>
where
    H: Http,
{
    fn root_publish(&self) -> RootPublish<'_, T, H, C, F, Sch, E> {
        RootPublish {
            transport: self.transport,
            api: self.api,
            floors: self.floors,
            scheduler: self.scheduler,
            profile: self.profile,
            entropy: self.entropy,
            owner_identity: self.keys.identity,
        }
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> ScopeRootPublisher
    for OwnerRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    async fn publish_scope_root(
        &self,
        record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError> {
        let name = scope_name(&record.ipns_name).map_err(publish_verdict)?;
        let override_seed = new_override_seed(self.keys.enc_secret, record)?;

        // The read body and the envelope fields a republish preserves come from
        // the node's own current record, gated — the rotation carries neither.
        // A resolve that already gated this exact name hands its read over here
        // rather than making the pass read the record twice ([`GatedRoots`]).
        let current = match self.gated.take(&name) {
            Some(parked) => parked,
            None => RepublishBase::from(
                self.gated_root(record.scope_id, &name)
                    .await
                    .map_err(|verdict| publish_verdict(verdict.into()))?,
            ),
        };
        self.root_publish()
            .run(&name, record, &override_seed, current)
            .await
    }
}

// ---------------------------------------------------------------------------
// The grantee arm: the flat scope-exit cut of one granted scope root
// (blueprint/engine.md "rotateScope" — grantee scope-exit rotations are flat,
// self-contained, offline; every old-seed holder is a live grantee that receives
// the new seed, so no cascade).
// ---------------------------------------------------------------------------

/// The grantee key material the scope-exit rotation runs under. The grantee is
/// the terminal owner of its own key material, so nothing here is zeroized.
pub struct GranteeRotationKeys<'a> {
    /// Opens this device's own grant blob — its seed source, and the key the
    /// re-sealed section must reopen under before it is signed.
    pub enc_secret: &'a X25519Secret,
    /// The **verified contact's** encryption subkey: the blinded-tag ECDH peer
    /// this device self-locates under, the pairwise input its writer pseudonym
    /// derives from, and the owner-blob recipient every re-seal wraps to. Never
    /// a key the record supplies (`grants/accept.rs`).
    pub owner_enc_pub: &'a X25519Public,
    /// The contact-anchored owner identity: the adoption gate's stage-2 anchor.
    pub owner_identity: &'a EcdsaVerifier,
}

/// One scope root this device holds a grant for.
///
/// A [`NodeId`] locates nothing on its own, and a grantee cannot derive a scope
/// root's name — that derivation runs off the write scope seed only the record
/// itself conveys — so the pairing is caller-held, from the accept flow that
/// adopted the share.
pub struct GrantedScopeRoot {
    /// The scope id, which is also its scope root's node id.
    pub scope_id: [u8; 16],
    /// The name the scope root's record lives at.
    pub ipns_name: IpnsName,
}

/// The grantee-arm rotation seams over the live net plane.
pub struct GranteeRotationNet<'a, T, H: Http, C: CredentialStore, F, Sch, E> {
    /// The record-plane transport: fan-out GET for the read, CAS PUT for the
    /// publish.
    pub transport: &'a T,
    /// The API client: register-first and the head-block upload.
    pub api: &'a ApiClient<H, C>,
    /// Content read sources for the head block.
    pub gateway: &'a Gateway,
    /// The HTTP seam the content fetch rides.
    pub http: &'a H,
    /// The durable floors the adoption gate reads and advances.
    pub floors: &'a F,
    /// The scheduler the publish pipeline's background re-PUT and the cut's
    /// lazy-wave sweep ride.
    pub scheduler: &'a Sch,
    /// The publish pipeline's timing policy.
    pub profile: &'a SyncTimingProfile,
    /// Injected entropy — the per-seal nonce source (determinism law).
    pub entropy: &'a RefCell<E>,
    /// The grantee material.
    pub keys: GranteeRotationKeys<'a>,
    /// The granted scope roots this device can rotate. A trigger naming a scope
    /// absent here is one this device holds no grant for.
    pub granted: &'a [GrantedScopeRoot],
    /// Builds the lazy-wave sweep task `rotate_scope` enqueues once the cut is
    /// durable ([`rotate_scope`]'s third effect).
    pub sweep: &'a dyn Fn([u8; 16]) -> BoxedTask,
    /// The record a cut is about to replace, handed from the read that gated it
    /// to the publish (see [`GatedRoots`]). One rotation pass per net.
    pub gated: GatedRoots,
}

/// One granted scope root as this device gated it, held so the
/// [`RotateScopePlan`](crate::rotation::RotateScopePlan) can borrow it. Terminal
/// owner of the seeds its own grant blob wrapped: they zeroize on drop.
struct GranteePlan {
    /// The ascent link's published public half — all a holder with no ancestor
    /// seed can re-seal to ([`AscentAuthority::CarriedPublic`]).
    ascent_public: [u8; 32],
    /// The read epoch the record publishes at; the cut publishes at `+ 1`.
    read_epoch: u64,
    section: GrantSection,
    write_body: WriteBody,
    write_epoch: u64,
    read_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    write_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    pointer_read_key: Zeroizing<[u8; SECRET_LEN]>,
    /// The writer pseudonym this device detach-signs every re-sealed structure
    /// under — the key its own committed entry names.
    pseudonym: Ed25519Signer,
}

/// The structured AAD a scope root's grant blob at `epoch` is sealed under
/// (`id == scope == scope_id`, as at every scope root).
fn grant_blob_aad(scope_id: [u8; 16], epoch: u64) -> AadContext {
    AadContext {
        v: ENVELOPE_V,
        id: scope_id,
        scope: scope_id,
        epoch,
        struct_tag: STRUCT_TAG_GRANT_BLOB,
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> GranteeRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport,
    F: FloorStore,
{
    /// The scope root `scope` names, from the caller-held inventory. A trigger
    /// naming a scope this device holds no grant for is refused rather than read
    /// under an unheld label.
    fn granted_root(&self, scope: NodeId) -> Result<&GrantedScopeRoot, ResolveFailure> {
        self.granted
            .iter()
            .find(|granted| granted.scope_id == scope.0)
            .ok_or(ResolveFailure::Rejected)
    }

    /// This device's pairwise ECDH with the verified contact and the blinded tag
    /// it derives at `name` — one shared secret for both, as `mint_grant_row`
    /// derives the owner's half of the same pair.
    fn self_location(&self, name: &IpnsName) -> Option<(SecretBytes, [u8; 32])> {
        recipient_self_location(
            self.keys.enc_secret,
            self.keys.owner_enc_pub,
            name.as_str().as_bytes(),
        )
    }

    /// This device's own grant blob in `section`, opened under `aad`. `None`
    /// when no blob is filed at `tag` — at a fresh owner-signed record that
    /// absence is the definitive revocation signal (`grants/revocation.rs`), and
    /// here a fail-closed refusal.
    fn open_own_grant(
        &self,
        section: &GrantSection,
        tag: &[u8; 32],
        aad: &AadContext,
    ) -> Option<GrantBlobPayload> {
        let blob = self_locate_signed(&section.grant_blobs, tag)?;
        open_grant_blob(self.keys.enc_secret, &blob.enc, aad, &blob.ciphertext).ok()
    }

    /// The freshest verified record at this scope root's name, gated under this
    /// device's own grant blob with the contact-anchored owner as the stage-2
    /// anchor. Idempotent: a record at this name's own sequence floor recovers
    /// through [`reread_at_floor`], so a pass that aborted before publishing can
    /// read again.
    async fn gated_root(
        &self,
        granted: &GrantedScopeRoot,
    ) -> Result<GatedScopeRoot, RootGateVerdict> {
        let name = &granted.ipns_name;
        let Some((_, record_bytes)) = fanout_get_verify(self.transport, name).await else {
            return Err(RootGateVerdict::Unavailable);
        };
        let adopter = RootAdopter::for_grantee(
            self.gateway,
            self.http,
            self.floors,
            self.keys.enc_secret,
            self.keys.owner_enc_pub,
            self.keys.owner_identity,
            granted.scope_id,
        );
        gated_scope_root(&adopter, name, &record_bytes).await
    }

    /// Gate the scope root and assemble everything its flat cut re-seals, parking
    /// the read the publish will need ([`GatedRoots`]).
    ///
    /// The committed set, the ledger and the direct-child-scope index are carried
    /// **verbatim**: a grantee re-wraps blobs for the committed tag set and can
    /// neither extend nor shrink it, and no descendant scope root is re-keyed
    /// (the eager-set law's grantee arm).
    async fn resolve_plan(
        &self,
        granted: &GrantedScopeRoot,
    ) -> Result<GranteePlan, ResolveFailure> {
        let gated = self
            .gated_root(granted)
            .await
            .map_err(ResolveFailure::from)?;
        let GatedScopeRoot {
            envelope,
            section,
            read_body,
            read_scope_seed,
            write_scope_seed,
        } = gated;
        // This build authors exactly `ENVELOPE_V`, so re-sealing a newer client's
        // root under its own `v` would mint structures whose AAD this build can
        // never reproduce (`sync/drain.rs` guards the same downgrade).
        if envelope.v != ENVELOPE_V {
            return Err(ResolveFailure::Rejected);
        }
        // A read-only grant conveys no write scope seed, so this device can sign
        // no record at this name — a permanent capability verdict, never a stall.
        let Some(write_scope_seed) = write_scope_seed else {
            return Err(ResolveFailure::Rejected);
        };
        let (write_body, write_epoch) = write_plane_of(
            self.floors,
            &envelope,
            &section,
            &write_scope_seed,
            granted.scope_id,
        )
        .await?;
        // A granted scope root is anchored under a parent scope, so it always
        // carries an ascent link; a record missing one has had it stripped, and
        // republishing without one severs every ancestor's descent for good.
        let ascent_public = section
            .ascent_link
            .as_ref()
            .map(|link| link.ascent_public)
            .ok_or(ResolveFailure::Rejected)?;
        let (pairwise, tag) = self
            .self_location(&granted.ipns_name)
            .ok_or(ResolveFailure::Rejected)?;
        // The owner-signed commitment, never the blob's contents, says what this
        // device may do here; publishing the root is a write.
        if section
            .commitment
            .entries
            .iter()
            .find(|entry| entry.tag == tag)
            .map(|entry| entry.permission)
            != Some(Permission::Write)
        {
            return Err(ResolveFailure::Rejected);
        }
        // The commitment binds `(tag, permission)` but never `recipientEncPk`,
        // and a committed co-writer authors the ledger — so a row swapped under
        // this device's own tag would re-wrap its next seed to a key it does not
        // hold. The rows this device cannot check are the residual
        // [`ResealError::TagNotBoundToRecipient`] names.
        let own_row = write_body
            .grant_ledger
            .iter()
            .find(|entry| entry.tag == tag)
            .ok_or(ResolveFailure::Rejected)?;
        if own_row.recipient_enc_pk != self.keys.enc_secret.public().to_bytes() {
            return Err(ResolveFailure::Rejected);
        }
        let grant = self
            .open_own_grant(
                &section,
                &tag,
                &grant_blob_aad(granted.scope_id, envelope.epoch),
            )
            .ok_or(ResolveFailure::Rejected)?;
        let pseudonym = SessionIdentity::grantee_writer_pseudonym_signer(
            pairwise.as_bytes(),
            &granted.scope_id,
        );

        let plan = GranteePlan {
            ascent_public,
            read_epoch: envelope.epoch,
            section,
            write_body,
            write_epoch,
            read_scope_seed,
            write_scope_seed: write_scope_seed.clone(),
            pointer_read_key: Zeroizing::new(*grant.pointer_read_key()),
            pseudonym,
        };
        self.gated.park(
            granted.ipns_name.clone(),
            RepublishBase {
                read_body,
                unknown: envelope.unknown,
                epoch_tag_unknown: envelope.epoch_tag_unknown,
                write_scope_seed: Some(write_scope_seed),
            },
        );
        Ok(plan)
    }

    fn root_publish(&self) -> RootPublish<'_, T, H, C, F, Sch, E> {
        RootPublish {
            transport: self.transport,
            api: self.api,
            floors: self.floors,
            scheduler: self.scheduler,
            profile: self.profile,
            entropy: self.entropy,
            owner_identity: self.keys.owner_identity,
        }
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> ScopeRootPublisher
    for GranteeRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    async fn publish_scope_root(
        &self,
        record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError> {
        let name = scope_name(&record.ipns_name).map_err(publish_verdict)?;
        // [`new_override_seed`]'s grantee mirror, on the same release-active
        // rule: a section this rotator can no longer reopen is never signed
        // (security rule 8), and that is permanent for these bytes.
        let (_, tag) = self
            .self_location(&name)
            .ok_or(RotationPublishError::Rejected)?;
        let grant = self
            .open_own_grant(
                &record.section,
                &tag,
                &grant_blob_aad(record.scope_id, record.read_epoch),
            )
            .ok_or(RotationPublishError::Rejected)?;
        let override_seed = Zeroizing::new(*grant.read_scope_seed());

        // The read [`Self::resolve_plan`] gated parks the body and the envelope
        // fields a republish preserves ([`GatedRoots`]).
        let current = self
            .gated
            .take(&name)
            .ok_or(RotationPublishError::NotPublished)?;
        self.root_publish()
            .run(&name, record, &override_seed, current)
            .await
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> ScopeExitRotator
    for GranteeRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    async fn rotate_on_scope_exit(
        &self,
        scope_root: NodeId,
    ) -> Result<RotationOutcome, RotateError> {
        let granted = self
            .granted_root(scope_root)
            .map_err(RotateError::Resolve)?;
        let source = self
            .resolve_plan(granted)
            .await
            .map_err(RotateError::Resolve)?;
        let plan = RotateScopePlan {
            identity: ScopeRootIdentity {
                v: ENVELOPE_V,
                scope_id: granted.scope_id,
                ipns_name: granted.ipns_name.as_str().as_bytes(),
                owner_enc_pub: self.keys.owner_enc_pub,
                owner_enc_secret: None,
                ascent: Some(AscentAuthority::CarriedPublic(&source.ascent_public)),
                // A granted scope root is anchored under a parent scope, so it
                // always owes one — evidence independent of the field that mints
                // it ([`ScopeRootIdentity::owes_ascent_link`]).
                owes_ascent_link: true,
                pseudonym_signer: &source.pseudonym,
            },
            committed: CommittedSet {
                owner_identity: self.keys.owner_identity,
                commitment: &source.section.commitment,
                commitment_sig: &source.section.commitment_sig,
                grant_ledger: &source.write_body.grant_ledger,
                direct_child_scope_index: &source.write_body.direct_child_scope_index,
            },
            current_override_seed: &source.read_scope_seed,
            current_read_epoch: source.read_epoch,
            write_scope_seed: &source.write_scope_seed,
            write_epoch: source.write_epoch,
            write_history_link: &source.write_body.write_history_link,
            pointer_read_key: &source.pointer_read_key,
            carried_history_links: &source.section.history_links,
        };
        rotate_scope(
            &mut SharedEntropy(self.entropy),
            self.floors,
            self.scheduler,
            self,
            &plan,
            || (self.sweep)(granted.scope_id),
        )
        .await
    }
}

/// The scope a sweep pass is walking, held from the scope-root read that proved
/// it to the node reads and publishes that ride on it.
///
/// An interior node carries no seed of its own: its read key derives from the
/// scope's, and the epoch its record was sealed at derives from the scope's
/// history-link ratchet. Pinning that one gated read is what lets the pass read
/// and re-seal every node under material a single adoption proved.
///
/// Keyed on the scope root's own name, as [`GatedRoots`] is: a caller asking
/// under a different label gets nothing rather than aliasing onto this scope's
/// keys.
#[derive(Default)]
pub struct SweptScopeState {
    inner: RefCell<Option<Rc<SweptScopeSource>>>,
}

/// Everything the sweep's node reads and publishes need from the scope root.
/// Shared behind an [`Rc`] rather than copied per node, so the two seeds have
/// one live copy that zeroizes when the state is replaced or dropped.
struct SweptScopeSource {
    scope_id: [u8; 16],
    name: IpnsName,
    read_epoch: u64,
    write_epoch: u64,
    read_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    write_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    parent_node_seed: Option<Zeroizing<[u8; SECRET_LEN]>>,
    /// Whether the gated record carried an ascent link, so the index repair's
    /// re-seal cannot silently publish this root without one.
    carried_ascent_link: bool,
    commitment: GrantSetCommitment,
    commitment_sig: [u8; ECDSA_SIG_LEN],
    history_links: Vec<SignedSealed>,
    grant_ledger: Vec<GrantLedgerEntry>,
    write_history_link: Vec<u8>,
}

impl SweptScopeState {
    fn park(&self, source: SweptScopeSource) {
        *self.inner.borrow_mut() = Some(Rc::new(source));
    }

    /// The parked scope when it is the one `scope` names. The `Rc` is cloned so
    /// no borrow is held across a suspend point.
    fn source(&self, scope: &ChildScopeRef) -> Option<Rc<SweptScopeSource>> {
        self.inner
            .borrow()
            .as_ref()
            .filter(|source| {
                source.scope_id == scope.scope_id
                    && source.name.as_str().as_bytes() == scope.ipns_name
            })
            .map(Rc::clone)
    }
}

/// Carry a gate error into the sweep's read arm on rule 6's axis: a rejection
/// is a fail-closed trust violation, a seam failure is availability.
fn read_verdict(error: GateError) -> SweepResolveFailure {
    match error {
        GateError::Seam(_) => SweepResolveFailure::Unavailable,
        GateError::Rejected(_) => SweepResolveFailure::Rejected,
    }
}

/// Carry a re-seal refusal into the sweep's publish arm on rule 6's axis: every
/// variant but entropy is this build's own fail-closed verdict on material the
/// pass already gated, so re-sealing the same inputs reaches it again.
fn reseal_publish_verdict(error: ResealError) -> RotationPublishError {
    match error {
        ResealError::Entropy(_) => RotationPublishError::NotPublished,
        _ => RotationPublishError::Rejected,
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> OwnerRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport,
    F: FloorStore,
{
    /// The scope `scope` names, as this pass gated it. A node read or publish
    /// issued for a scope this net never gated has no material to run under —
    /// fail-closed rather than a read under an unproven label.
    fn swept_scope(
        &self,
        scope: &ChildScopeRef,
    ) -> Result<Rc<SweptScopeSource>, SweepResolveFailure> {
        self.swept
            .source(scope)
            .ok_or(SweepResolveFailure::Rejected)
    }

    /// Prove a walked child really is a descendant scope root **of this scope**
    /// ([`gated_child_root`]), and report the name it gated current at.
    ///
    /// The read body is authored by any committed writer, so the `ChildRef` that
    /// led here proves nothing at all.
    async fn gated_child_scope_root(
        &self,
        source: &SweptScopeSource,
        child: &NodeRef,
        name: &IpnsName,
        record_bytes: &[u8],
        head: LocalHead,
    ) -> Result<SweptChild, SweepResolveFailure> {
        let parent_node_seed = kdf::node_seed(&source.read_scope_seed, &child.node_id);
        let adopter = RootAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            self.keys.enc_secret,
            self.keys.identity,
            child.node_id,
        )
        .under_parent_node_seed(Zeroizing::new(*parent_node_seed.as_bytes()));
        adopter.hold_local_head(head);
        gated_child_root(&adopter, name, record_bytes, child.node_id)
            .await
            .map_err(SweepResolveFailure::from)?;
        Ok(SweptChild::ScopeRoot(ChildScopeRef::new(
            child.node_id,
            name.as_str().as_bytes().to_vec(),
        )))
    }

    /// Open one interior node's record at the epoch it was sealed at.
    ///
    /// This is the one read that deliberately does **not** run the scope's
    /// read-epoch floor: a lagging interior node is below that floor by
    /// construction, and it is exactly the record the sweep exists to advance
    /// (ADR 0003 D1). It is safe where admitting a below-floor *scope root* is
    /// not, because an interior record carries no seed, no grant blob and no
    /// commitment — every key here comes from the scope root this pass already
    /// gated, so nothing the record claims hands a revoked reader anything.
    ///
    /// What the skipped stage did carry is **authorship**: an interior body is
    /// authenticated only by the AEAD under the epoch's read key, so a party who
    /// held that epoch's seed and still holds the node's write key can author a
    /// body this pass promotes to the current epoch. That is the write plane's
    /// residual forgery window (CONTEXT.md "Forgery window"), closed by
    /// `rotateScopeWrite`, not by this read. The per-name sequence floor is what
    /// bars a rolled-back record, and it advances here on every confirmed
    /// unseal so it stops being 0 for an unbrowsed node.
    async fn interior_node(
        &self,
        source: &SweptScopeSource,
        child: &NodeRef,
        name: &IpnsName,
        sequence: u64,
        envelope: Envelope,
    ) -> Result<SweptChild, SweepResolveFailure> {
        if envelope.v != ENVELOPE_V
            || envelope.id != child.node_id
            || envelope.scope != source.scope_id
        {
            return Err(SweepResolveFailure::Rejected);
        }
        floor::check_sequence(
            self.floors,
            name.as_str().as_bytes(),
            sequence,
            floor::Strictness::AtOrAboveFloor,
        )
        .await
        .map_err(|error| match error {
            GateError::Seam(_) => SweepResolveFailure::Unavailable,
            GateError::Rejected(_) => SweepResolveFailure::Rejected,
        })?;
        // A record above the scope root's epoch is not lagging, and this scope's
        // ratchet only walks backward, so there is no seed here that opens it —
        // an honest race with a fresher root, or an epoch label a committed
        // writer chose freely (the epoch is only AAD). Either way it is this
        // pass's read that fails, not the record's trust.
        if envelope.epoch > source.read_epoch {
            return Err(SweepResolveFailure::Unreadable);
        }
        let seed = seed_at_epoch(
            envelope.v,
            source.scope_id,
            &source.read_scope_seed,
            source.read_epoch,
            &source.history_links,
            envelope.epoch,
        )
        .ok_or(SweepResolveFailure::Unreadable)?;
        let read_key = read_key_for(&seed, &envelope.id);
        let read_body =
            open_read_body(&envelope, &read_key).map_err(|_| SweepResolveFailure::Rejected)?;
        // The floor law's child arm: the per-name sequence floor advances only
        // after an AAD-confirmed unseal (`net/child.rs`), and nothing else on
        // this path raises it — so without this a rolled-back record stays
        // admissible for as long as the node goes unbrowsed.
        floor::advance_sequence_on_unseal(self.floors, name.as_str().as_bytes(), sequence)
            .await
            .map_err(|_| SweepResolveFailure::Unavailable)?;
        Ok(SweptChild::Interior(SweptNode {
            current_read_epoch: envelope.epoch,
            sequence,
            read_body,
            carried_unknown: envelope.unknown,
            carried_epoch_tag_unknown: envelope.epoch_tag_unknown,
        }))
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> SweepResolver
    for OwnerRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport,
    F: FloorStore,
{
    async fn resolve_scope(
        &self,
        scope: &ChildScopeRef,
    ) -> Result<SweptScope, SweepResolveFailure> {
        let name = scope_name(&scope.ipns_name).map_err(SweepResolveFailure::from)?;
        let root = self
            .gated_root(scope.scope_id, &name)
            .await
            .map_err(SweepResolveFailure::from)?;
        if root.envelope.v != ENVELOPE_V {
            return Err(SweepResolveFailure::Rejected);
        }
        let GatedScopeRoot {
            envelope,
            section,
            read_body,
            read_scope_seed,
            write_scope_seed,
        } = root;
        // A root held keyless has no readable write-body — availability, not a
        // trust verdict.
        let write_scope_seed = write_scope_seed.ok_or(SweepResolveFailure::Unavailable)?;
        let (write_body, write_epoch) = write_plane_of(
            self.floors,
            &envelope,
            &section,
            &write_scope_seed,
            scope.scope_id,
        )
        .await
        .map_err(SweepResolveFailure::from)?;
        let children = body_children(&read_body);
        let read_epoch = envelope.epoch;
        self.swept.park(SweptScopeSource {
            scope_id: scope.scope_id,
            name: name.clone(),
            read_epoch,
            write_epoch,
            read_scope_seed,
            write_scope_seed: write_scope_seed.clone(),
            parent_node_seed: self.ancestry.parent_node_seed(&scope.scope_id),
            carried_ascent_link: section.ascent_link.is_some(),
            commitment: section.commitment,
            commitment_sig: section.commitment_sig,
            history_links: section.history_links,
            grant_ledger: write_body.grant_ledger,
            write_history_link: write_body.write_history_link,
        });
        // The index repair republishes this root, and runs off this read rather
        // than gating the same record twice ([`GatedRoots`]).
        self.gated.park(
            name,
            RepublishBase {
                read_body,
                unknown: envelope.unknown,
                epoch_tag_unknown: envelope.epoch_tag_unknown,
                write_scope_seed: Some(write_scope_seed),
            },
        );
        Ok(SweptScope {
            current_read_epoch: read_epoch,
            children,
            direct_child_scope_index: write_body.direct_child_scope_index,
        })
    }

    async fn consult_pointer(
        &self,
        scope_id: &[u8; 16],
    ) -> Result<Option<Vec<u8>>, SweepResolveFailure> {
        let seed = self
            .owner_pointer_seed
            .ok_or(SweepResolveFailure::Unavailable)?;
        let pointer = scope_pointer_name(seed, scope_id);
        let block = match RecordPointerFetch::new(self.transport)
            .fetch(&pointer)
            .await
        {
            Ok(Some(block)) => block,
            Ok(None) => return Ok(None),
            Err(_) => return Err(SweepResolveFailure::Unavailable),
        };
        let pointer_read_key = self.keys.scope_keys.pointer_read_key(scope_id);
        let repoint = open_repoint(
            &pointer_read_key,
            self.payload_version,
            scope_id,
            self.keys.identity,
            &block,
        )
        .map_err(|_| SweepResolveFailure::Rejected)?;
        Ok(Some(repoint.current_root.as_str().as_bytes().to_vec()))
    }

    async fn resolve_child(
        &self,
        scope: &ChildScopeRef,
        child: &NodeRef,
    ) -> Result<SweptChild, SweepResolveFailure> {
        let source = self.swept_scope(scope)?;
        let name = scope_name(&child.ipns_name).map_err(SweepResolveFailure::from)?;
        let Some((_, record_bytes)) = fanout_get_verify(self.transport, &name).await else {
            return Err(SweepResolveFailure::Unavailable);
        };
        let (sequence, block) =
            fetch_head_block(self.gateway, self.http, &name, &record_bytes, None)
                .await
                .map_err(read_verdict)?;
        let envelope = decode_envelope(&block).map_err(|_| SweepResolveFailure::Rejected)?;
        if has_grant_section(&envelope) {
            // The root gate re-assembles the head; hand it the block this read
            // already paid for.
            return self
                .gated_child_scope_root(
                    &source,
                    child,
                    &name,
                    &record_bytes,
                    LocalHead {
                        cid: root_block_cid(&block),
                        block,
                    },
                )
                .await;
        }
        self.interior_node(&source, child, &name, sequence, envelope)
            .await
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> SweepPublisher
    for OwnerRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    async fn publish_node(
        &self,
        scope: &ChildScopeRef,
        node: &LaggingNode<'_>,
    ) -> Result<(), RotationPublishError> {
        let source = self
            .swept_scope(scope)
            .map_err(|_| RotationPublishError::Rejected)?;
        let name = scope_name(node.ipns_name).map_err(publish_verdict)?;
        // Release-active (security rule 8), both halves. The seam's own
        // invariant: a node is only ever sealed at the epoch of the scope root
        // this pass gated, since any other value signs under a key no reader
        // re-derives. And the durable mirror: a concurrent cascade can raise the
        // read-epoch floor after that gated read, and a record cannot be
        // unpublished — so re-read the floor rather than trusting the snapshot.
        if node.read_epoch != source.read_epoch {
            return Err(RotationPublishError::Rejected);
        }
        let read_floor = floor::read_epoch_floor(self.floors, &source.scope_id)
            .await
            .map_err(|_| RotationPublishError::NotPublished)?
            .unwrap_or(0);
        if node.read_epoch < read_floor {
            return Err(RotationPublishError::Rejected);
        }
        let read_key = read_key_for(&source.read_scope_seed, &node.node_id);
        let nonce = nonce(self.entropy)?;
        let head = author_child_envelope(EnvelopeAuthoring {
            node_id: node.node_id,
            scope_id: source.scope_id,
            epoch: node.read_epoch,
            read_key: &read_key,
            nonce: &nonce,
            body: node.read_body,
            carried_unknown: node.carried_unknown.clone(),
            carried_epoch_tag_unknown: node.carried_epoch_tag_unknown.clone(),
        })
        .map_err(author_verdict)?;

        let binding = HeadBinding {
            node_id: node.node_id,
            scope_id: source.scope_id,
            epoch: node.read_epoch,
        };
        let preflighted = preflight(&binding, &read_key, &head)
            .map_err(|_| RotationPublishError::NotPublished)?;
        let signer = SessionIdentity::write_name_signer(&source.write_scope_seed, &node.node_id);
        let receipt = publish_record(
            self.transport,
            self.api,
            self.floors,
            self.scheduler,
            self.profile,
            &RecordPublishRequest {
                name: &name,
                signer: &signer,
                head: &preflighted,
                content_cids: Vec::new(),
                // Nothing on the sweep's read path adopts an interior record, so
                // no gate ever raises this name's durable sequence floor to what
                // the network already holds: the record the pass read is the CAS
                // lower bound, exactly as the pointer publish and revival treat
                // their own ungated names.
                min_current_sequence: Some(node.sequence),
            },
        )
        .await
        .map_err(|_| RotationPublishError::NotPublished)?;

        match receipt.outcome {
            PublishOutcome::Published { .. } => Ok(()),
            PublishOutcome::LostRace { .. } => Err(RotationPublishError::LostRace),
            PublishOutcome::Unconfirmed { .. } => Err(RotationPublishError::NotPublished),
        }
    }

    async fn repair_child_scope_index(
        &self,
        scope: &ChildScopeRef,
        index: &[ChildScopeRef],
    ) -> Result<(), RotationPublishError> {
        // Keyed on `scope`, so the repair can only ever republish the root this
        // pass gated, at the name it gated it under — never a name the walk did
        // not resolve current.
        let source = self
            .swept_scope(scope)
            .map_err(|_| RotationPublishError::Rejected)?;
        let owner_enc_pub = self.keys.enc_secret.public();
        let pseudonym_signer = self.keys.scope_keys.writer_pseudonym(&source.scope_id);
        let pointer_read_key = self.keys.scope_keys.pointer_read_key(&source.scope_id);
        let section = reseal_scope_root(
            &mut *self.entropy.borrow_mut(),
            &ScopeRootIdentity {
                v: ENVELOPE_V,
                scope_id: source.scope_id,
                ipns_name: &scope.ipns_name,
                owner_enc_pub: &owner_enc_pub,
                owner_enc_secret: Some(self.keys.enc_secret),
                ascent: source
                    .parent_node_seed
                    .as_deref()
                    .map(AscentAuthority::ParentSeed),
                owes_ascent_link: source.carried_ascent_link,
                pseudonym_signer: &pseudonym_signer,
            },
            &ResealSeeds {
                override_seed: &source.read_scope_seed,
                read_epoch: source.read_epoch,
                // Metadata only: the same seed at the same epoch mints no
                // history link.
                prev: None,
                write_scope_seed: &source.write_scope_seed,
                write_epoch: source.write_epoch,
                write_history: WriteHistory::Carried(&source.write_history_link),
                pointer_read_key: &pointer_read_key,
            },
            &CommittedSet {
                owner_identity: self.keys.identity,
                commitment: &source.commitment,
                commitment_sig: &source.commitment_sig,
                grant_ledger: &source.grant_ledger,
                direct_child_scope_index: index,
            },
            &source.history_links,
        )
        .map_err(reseal_publish_verdict)?;
        self.publish_scope_root(&ResealedScopeRoot {
            scope_id: source.scope_id,
            ipns_name: scope.ipns_name.clone(),
            read_epoch: source.read_epoch,
            write_epoch: source.write_epoch,
            section,
        })
        .await
    }
}

/// The write-plane name wave's transport edge (blueprint/engine.md
/// "rotateScopeWrite"): the owner arm of both [`WriteSubtreeResolver`] and
/// [`WriteWavePublisher`] over the same net plane the read-plane seams above run
/// on.
///
/// The wave hands this no authoring material — only routing identity and the one
/// write seed that signs at the new name ([`RepublishedNode`]) — so every
/// republish re-resolves the node at its current name through the adoption gate,
/// rewrites the child names the wave moved, and re-seals under the **unchanged**
/// read key at the **unchanged** read epoch. The read plane's clock never moves
/// here (#38 D1).
pub struct WriteWaveNet<'a, T, H: Http, C: CredentialStore, F, Sch, E> {
    /// The record-plane transport: fan-out GET for the re-resolve, CAS PUT for
    /// the republish.
    pub transport: &'a T,
    /// The API client: register-first, the head-block upload, and retirement.
    pub api: &'a ApiClient<H, C>,
    /// Content read sources for the head block.
    pub gateway: &'a Gateway,
    /// The HTTP seam the content fetch rides.
    pub http: &'a H,
    /// The durable floors the adoption gate reads and advances.
    pub floors: &'a F,
    /// The scheduler the publish pipeline's background re-PUT rides.
    pub scheduler: &'a Sch,
    /// The publish pipeline's timing policy.
    pub profile: &'a SyncTimingProfile,
    /// Injected entropy — the per-seal nonce source (determinism law).
    pub entropy: &'a RefCell<E>,
    /// The scope under rotation; every record the wave touches must claim it.
    pub scope_id: [u8; 16],
    /// The scope's read override seed. A write rotation cuts no read key, so the
    /// same seed derives every per-node read key on both sides of the wave.
    pub read_scope_seed: &'a [u8; SECRET_LEN],
    /// The rotating root's own ancestor node seed, required when it is itself an
    /// interior scope root (its record carries an ascent link the gate verifies
    /// against a reader-derived keypair).
    pub parent_node_seed: Option<&'a [u8; SECRET_LEN]>,
    /// The owner material: opens the root's owner blob, anchors the gate, and
    /// re-signs the grant-set commitment — which binds `ipnsName`, so a root that
    /// moves without a re-sign is a record this build's own gate rejects.
    pub owner: &'a EcdsaSigner,
    /// Opens each scope root's owner blob on the gated re-resolve, and the
    /// owner-blob recipient every re-seal wraps to.
    pub owner_enc_secret: &'a X25519Secret,
    /// The two per-scope derivations the root's re-seal needs, and no wider
    /// capability (the same narrowing [`OwnerRotationKeys`] makes).
    pub scope_keys: &'a dyn OwnerScopeKeys,
    /// The owner-signed committed set the rotation was authorized over
    /// (`RotateScopeWritePlan::commitment`) — what the root's re-seal binds to,
    /// never the set carried by the record the wave re-reads.
    ///
    /// A grant-set commitment is epoch-free, so an older owner-signed one still
    /// verifies: a write grantee inside the forgery window can republish the root
    /// carrying the **pre-revoke** set, and that record passes every gate stage.
    /// Minting the moved root's section from it would wrap the freshly minted
    /// `writeScopeSeed` to the revokee — a permanent write-revocation bypass.
    pub authorized_commitment: &'a GrantSetCommitment,
    /// Derives the scope pointer's name and its record signer (owner-only).
    pub owner_pointer_seed: &'a [u8; SECRET_LEN],
    /// The pointer-payload envelope version the scope pointer is read under
    /// (`RotateScopeWritePlan::payload_version`).
    pub payload_version: u64,
    /// The root name the wave is moving off. It lingers serving the tombstone, so
    /// [`WriteWaveNet::retire`] refuses a batch naming it.
    pub current_root_name: &'a IpnsName,
    /// The session's vault-anchor scope, which
    /// [`floor::repoint_regression`] needs to scope its read-epoch stage. Unlike
    /// the consume side, which derives it from the session it is booting, this
    /// is caller-supplied: wiring that fills it from anything but the session
    /// root silently mis-scopes that stage.
    pub session_root_scope_id: [u8; 16],
    /// The root read this pass gated and has not yet republished
    /// ([`GatedWaveRoot`]). One rotation pass per net.
    pub gated_root: GatedWaveRoot,
    /// The subtree index the enumeration builds as it descends
    /// ([`WaveSubtree`]). One rotation pass per net.
    pub subtree: WaveSubtree,
}

/// What this pass's own gated reads discovered: the write scope's node index —
/// a node id locates nothing on its own, only a gated parent's read body names
/// its children — and the lowest read epoch those reads carried.
#[derive(Default)]
pub struct WaveSubtree {
    inner: RefCell<Discovered>,
}

#[derive(Default)]
struct Discovered {
    names: BTreeMap<[u8; 16], IpnsName>,
    /// The directly-descendant scope roots the pass **proved**: each rotates
    /// under its own write scope seed, so the wave stops at them
    /// (`grants/child_index.rs`).
    child_scopes: BTreeSet<[u8; 16]>,
    /// The lowest envelope read epoch this pass gated. A name wave cuts no read
    /// key, so the wave's moved copies carry these same epochs.
    lowest_read_epoch: Option<u64>,
}

impl WaveSubtree {
    /// The name a gated parent gave `node_id`.
    fn name(&self, node_id: &[u8; 16]) -> Option<IpnsName> {
        self.inner.borrow().names.get(node_id).cloned()
    }

    /// Mark `scope_id` as the boundary of a proven descendant scope root
    /// ([`WriteWaveNet::record_scope_boundary`]).
    fn record_child_scope(&self, scope_id: [u8; 16]) {
        self.inner.borrow_mut().child_scopes.insert(scope_id);
    }

    /// Record the read epoch one gated node carried.
    fn record_read_epoch(&self, epoch: u64) {
        let mut inner = self.inner.borrow_mut();
        inner.lowest_read_epoch = Some(inner.lowest_read_epoch.map_or(epoch, |l| l.min(epoch)));
    }

    /// The lowest read epoch this pass gated.
    fn lowest_read_epoch(&self) -> Option<u64> {
        self.inner.borrow().lowest_read_epoch
    }

    /// Record `body`'s in-scope children at the names it gives them and return
    /// their ids for the walk to descend into.
    ///
    /// Two parents naming one id at **different** names is the read plane's C2
    /// conflict ([`ResolveFailure::ConflictingChildLabel`]): rotating the one
    /// picked would leave the other name live, so the walk aborts instead.
    fn record_children(&self, body: &ReadBody) -> Result<Vec<[u8; 16]>, ResolveFailure> {
        let ReadBody::Folder { children, .. } = body else {
            return Ok(Vec::new());
        };
        let mut inner = self.inner.borrow_mut();
        let mut ids = Vec::with_capacity(children.len());
        for child in children {
            if inner.child_scopes.contains(&child.id) {
                continue;
            }
            let name = scope_name(&child.ipns_name)?;
            match inner.names.entry(child.id) {
                Entry::Occupied(seen) if *seen.get() != name => {
                    return Err(ResolveFailure::ConflictingChildLabel);
                }
                Entry::Occupied(_) => {}
                Entry::Vacant(slot) => {
                    slot.insert(name);
                }
            }
            ids.push(child.id);
        }
        Ok(ids)
    }
}

/// The scope root's gated read, held from the enumeration that proved it to the
/// republish that moves it, and re-parked when that publish fails.
///
/// The root is the one record the wave both reads and re-signs, so a re-fetch
/// between those two points would let a still-committed writer interpose a
/// section of its own for the wave to carry forward. Pinning the read keeps the
/// section the wave re-seals the one it proved.
#[derive(Default)]
pub struct GatedWaveRoot {
    inner: RefCell<Option<(IpnsName, WaveSource)>>,
}

impl GatedWaveRoot {
    fn take(&self, name: &IpnsName) -> Option<WaveSource> {
        let mut parked = self.inner.borrow_mut();
        match parked.as_ref() {
            Some((parked_name, _)) if parked_name == name => {
                parked.take().map(|(_, source)| source)
            }
            _ => None,
        }
    }

    fn park(&self, name: &IpnsName, source: WaveSource) {
        *self.inner.borrow_mut() = Some((name.clone(), source));
    }
}

/// One node's current record as the gate authenticated it, plus what a republish
/// at the new name needs: the body to rewrite, the read epoch and key it re-seals
/// under, and the envelope fields carried forward byte-stable (#27 D10).
#[derive(Clone)]
struct WaveSource {
    read_body: ReadBody,
    read_epoch: u64,
    read_key: Zeroizing<[u8; SECRET_LEN]>,
    unknown: PreservedFields,
    epoch_tag_unknown: PreservedFields,
    /// `Some` only for the scope root — interior nodes carry no grant section.
    root: Option<RootPlane>,
}

/// The scope root's own plane as this pass read it: the section it carries, the
/// read seed its own owner blob yielded, and the write body the re-seal rebuilds
/// with the wave's fresh write scope seed.
#[derive(Clone)]
struct RootPlane {
    section: GrantSection,
    read_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    write_body: WriteBody,
    /// The write scope seed the root's own owner-write blob yielded — the one the
    /// wave retires, sealed into the moved root's fresh write-plane history link.
    write_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The write epoch the section was sealed at — the floor the wave advances
    /// past.
    write_epoch: u64,
}

/// Rewrite the in-scope child names the wave moved, or refuse.
///
/// Fail-closed both ways: a mapped child the body does not carry means the
/// subtree enumeration and the published body disagree, and publishing either
/// half of that disagreement strands a subtree behind a name nothing resolves.
/// Refs the map does not name — a descendant scope root, which rotates under its
/// own write scope seed — keep their names.
fn rewrite_child_names(
    body: &mut ReadBody,
    child_names: &BTreeMap<[u8; 16], IpnsName>,
) -> Result<(), WritePublishError> {
    let ReadBody::Folder { children, .. } = body else {
        return if child_names.is_empty() {
            Ok(())
        } else {
            Err(WritePublishError::Rejected)
        };
    };
    let mut rewritten = 0usize;
    for child in children.iter_mut() {
        if let Some(name) = child_names.get(&child.id) {
            child.ipns_name = name.as_str().as_bytes().to_vec();
            rewritten += 1;
        }
    }
    if rewritten != child_names.len() {
        return Err(WritePublishError::Rejected);
    }
    Ok(())
}

/// Carry a gate verdict into the wave on rule 6's axis: a rejection is a trust
/// violation no retry clears, a seam failure is availability.
fn wave_verdict(error: GateError) -> WritePublishError {
    match error {
        GateError::Rejected(_) => WritePublishError::Rejected,
        GateError::Seam(_) => WritePublishError::NotLanded,
    }
}

/// The same axis for a read the wave shares with the read-plane rotation edges.
///
/// [`ResolveFailure::ConflictingChildLabel`] is retryable to the cascade and the
/// sweep because the write-rotation re-point wave repairs both parent indexes.
/// This *is* that wave, so it has nothing left to wait for: retrying here spins
/// on a conflict only this run can clear.
fn wave_read_verdict(failure: ResolveFailure) -> WritePublishError {
    match failure {
        ResolveFailure::Unavailable => WritePublishError::NotLanded,
        ResolveFailure::Rejected | ResolveFailure::ConflictingChildLabel => {
            WritePublishError::Rejected
        }
    }
}

/// The same axis back out to the subtree enumeration: only a fail-closed refusal
/// is a rejection, so no trust verdict is laundered into a retryable stall.
fn subtree_verdict(error: WritePublishError) -> ResolveFailure {
    match error {
        WritePublishError::Rejected => ResolveFailure::Rejected,
        WritePublishError::NotLanded
        | WritePublishError::LostRace
        | WritePublishError::RegistryFull => ResolveFailure::Unavailable,
    }
}

/// The same axis for the re-seal that mints a moved root's section. Every
/// variant but one is this build's own fail-closed verdict on material the wave
/// already gated — the committed set, the ledger it must equal, the carried
/// links the decoder already bounded — so re-sealing the same inputs reaches it
/// again. Entropy is the injected seam failing, not a verdict on any of that.
/// Matched exhaustively: a new variant must be classified here, not defaulted.
fn reseal_verdict(error: ResealError) -> WritePublishError {
    match error {
        ResealError::Entropy(_) => WritePublishError::NotLanded,
        ResealError::LedgerDivergesFromCommitment
        | ResealError::SignerNotCommitted
        | ResealError::UnusableRecipientKey
        | ResealError::TagNotBoundToRecipient
        | ResealError::AscentLinkMismatch
        | ResealError::AscentLinkDropped
        | ResealError::AscentLinkNotOwed
        | ResealError::UnusableAscentPublic
        | ResealError::TooManyHistoryLinks
        | ResealError::TooManyCommittedGrants
        | ResealError::HistoryLinkNotDescending
        | ResealError::HistoryLinkNotContiguous
        | ResealError::OwnerKeyRequiredForWriteCut
        | ResealError::WriteBodyTooLarge
        | ResealError::Encode(_) => WritePublishError::Rejected,
    }
}

/// The same axis for the publish pipeline. A CID the API echoes back wrong, and
/// the pipeline's own release-active encode refusals, are deterministic on the
/// bytes this pass built — a retry re-uploads and re-charges a head block
/// forever without converging.
fn publish_record_verdict(error: RecordPublishError) -> WritePublishError {
    match error {
        RecordPublishError::HeadCidMismatch { .. } => WritePublishError::Rejected,
        RecordPublishError::Publish(PublishError::Register(_)) => WritePublishError::RegistryFull,
        RecordPublishError::Publish(
            PublishError::EmptyHeadCid | PublishError::RecordTooLarge { .. },
        ) => WritePublishError::Rejected,
        _ => WritePublishError::NotLanded,
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> WriteWaveNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport,
    F: FloorStore,
{
    /// Gate an interior node's current record and open it for re-authoring.
    ///
    /// The adopt advances the per-name sequence floor, so a wave that already
    /// gated these bytes lands on the at-floor re-open instead — which is also
    /// the only child path that keeps the envelope's preserved fields.
    async fn interior_source(
        &self,
        node_id: [u8; 16],
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<WaveSource, WritePublishError> {
        let adopter = ChildAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            self.scope_id,
            Zeroizing::new(*self.read_scope_seed),
            node_id,
        );
        match adopter.adopt(name, record_bytes).await {
            Ok(_) => {}
            // Our own current record at exactly the floor — the at-floor re-open
            // below is the path for it. A strictly older sequence is a replay and
            // stays a fail-closed violation (`net/resolve.rs` splits it the same
            // way).
            Err(GateError::Rejected(rejection))
                if matches!(
                    rejection.reason,
                    RejectionReason::SequenceNotNewer { floor, sequence } if sequence == floor
                ) => {}
            Err(error) => return Err(wave_verdict(error)),
        }
        let (adopted, envelope) = adopter
            .open_carried_at_floor(name, record_bytes)
            .await
            .map_err(wave_verdict)?;
        if envelope.v != ENVELOPE_V {
            return Err(WritePublishError::Rejected);
        }
        Ok(WaveSource {
            read_body: adopted.read_body,
            read_epoch: adopted.epoch,
            read_key: read_key_for(self.read_scope_seed, &node_id),
            unknown: envelope.unknown,
            epoch_tag_unknown: envelope.epoch_tag_unknown,
            root: None,
        })
    }

    /// Gate the scope root's current record and open it for re-authoring, plus
    /// the write plane the re-seal rebuilds. Both keys come from the seeds the
    /// root's own blobs carry, never the caller's copies — the record must reopen
    /// under the keys readers re-derive.
    async fn root_source(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<WaveSource, WritePublishError> {
        let identity = self.owner.verifying_key();
        let gated = gated_scope_root(&self.root_adopter(&identity), name, record_bytes)
            .await
            .map_err(|verdict| wave_read_verdict(verdict.into()))?;
        let envelope = gated.envelope;
        // The root gate binds `envelope.scope` but not `envelope.id`, and every
        // AAD this republish authors binds the id — so a root whose record claims
        // another node would be re-sealed under a key no reader re-derives.
        if envelope.v != ENVELOPE_V || envelope.id != self.scope_id {
            return Err(WritePublishError::Rejected);
        }
        let read_scope_seed = gated.read_scope_seed;
        let write_scope_seed = gated.write_scope_seed.ok_or(WritePublishError::NotLanded)?;
        let write_epoch = floor::write_epoch_floor(self.floors, &self.scope_id)
            .await
            .map_err(|_| WritePublishError::NotLanded)?
            .ok_or(WritePublishError::NotLanded)?;
        let write_body = open_write_body(
            &envelope,
            &gated.section,
            &self.scope_id,
            &write_scope_seed,
            write_epoch,
        )
        .map_err(wave_read_verdict)?;
        Ok(WaveSource {
            read_body: gated.read_body,
            read_epoch: envelope.epoch,
            read_key: read_key_for(&read_scope_seed, &envelope.id),
            unknown: envelope.unknown,
            epoch_tag_unknown: envelope.epoch_tag_unknown,
            root: Some(RootPlane {
                section: gated.section,
                read_scope_seed,
                write_body,
                write_scope_seed,
                write_epoch,
            }),
        })
    }

    /// Prove each claimed directly-descendant scope root before the enumeration
    /// stops at it, and record the proven boundary.
    ///
    /// `directChildScopeIndex` is authored by any committed writer — including
    /// the grantee this rotation is cutting — so an entry naming an ordinary
    /// in-scope node would carve that node out of the wave and leave it live at
    /// a name the revokee's retired write scope seed still derives.
    /// [`gated_child_root`] is the proof, over the seed the root's own owner
    /// blob yielded.
    async fn record_scope_boundary(
        &self,
        index: &[ChildScopeRef],
        read_scope_seed: &[u8; SECRET_LEN],
    ) -> Result<(), ResolveFailure> {
        let identity = self.owner.verifying_key();
        for child in index {
            let name = scope_name(&child.ipns_name)?;
            let Some((_, record_bytes)) = fanout_get_verify(self.transport, &name).await else {
                return Err(ResolveFailure::Unavailable);
            };
            let parent_node_seed = kdf::node_seed(read_scope_seed, &child.scope_id);
            let adopter = RootAdopter::new(
                self.gateway,
                self.http,
                self.floors,
                self.owner_enc_secret,
                &identity,
                child.scope_id,
            )
            .under_parent_node_seed(Zeroizing::new(*parent_node_seed.as_bytes()));
            gated_child_root(&adopter, &name, &record_bytes, child.scope_id)
                .await
                .map_err(ResolveFailure::from)?;
            self.subtree.record_child_scope(child.scope_id);
        }
        Ok(())
    }

    /// The adopter every root read of this scope runs through, under the
    /// rotating root's own ancestor seed when it has one.
    fn root_adopter<'i>(&'i self, identity: &'i EcdsaVerifier) -> RootAdopter<'i, H, F> {
        let adopter = RootAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            self.owner_enc_secret,
            identity,
            self.scope_id,
        );
        match self.parent_node_seed {
            Some(seed) => adopter.under_parent_node_seed(Zeroizing::new(*seed)),
            None => adopter,
        }
    }
}

/// `nodeSeed(scopeReadSeed, node) -> readKey` — the frozen edges every reader
/// re-derives for a node in the scope.
fn read_key_for(
    scope_read_seed: &[u8; SECRET_LEN],
    node_id: &[u8; 16],
) -> Zeroizing<[u8; SECRET_LEN]> {
    let node_seed = kdf::node_seed(scope_read_seed, node_id);
    Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes())
}

/// Unseal a gated scope root's write body under `write_scope_seed` at
/// `write_epoch` — the AAD epoch the owner-write-blob's own recovery bound. The
/// gate authenticated the structure's detached signature; the unseal is what
/// proves it is *this* scope's write body at *this* write epoch.
fn open_write_body(
    envelope: &Envelope,
    section: &GrantSection,
    scope_id: &[u8; 16],
    write_scope_seed: &[u8; SECRET_LEN],
    write_epoch: u64,
) -> Result<WriteBody, ResolveFailure> {
    let write_seed = kdf::write_seed(write_scope_seed, scope_id);
    let write_key = kdf::write_key(write_seed.as_bytes());
    let ctx = AadContext {
        v: envelope.v,
        id: envelope.id,
        scope: envelope.scope,
        epoch: write_epoch,
        struct_tag: STRUCT_TAG_WRITE_BODY,
    };
    let plaintext = Zeroizing::new(
        unseal(write_key.as_bytes(), &ctx, &section.write_body.sealed)
            .map_err(|_| ResolveFailure::Rejected)?,
    );
    decode_write_body(&plaintext).map_err(|_| ResolveFailure::Rejected)
}

/// A moved root's grant set, re-minted at its new name: the entries the owner
/// re-signs and the ledger rows the write body carries, built together so the
/// two cannot drift apart.
struct RemintedGrants {
    entries: Vec<GrantSetEntry>,
    ledger: Vec<GrantLedgerEntry>,
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> WriteWaveNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    /// Re-mint every committed grant at the moved root's new name.
    ///
    /// A blinded tag binds the scope root's `ipnsName` (`kdf::blinded_tag`) and a
    /// write rotation moves that name, so a grant set carried through as it
    /// stands republishes tags no grantee can re-derive — which
    /// [`classify`](crate::grants::classify) reads as the definitive revocation
    /// of the entire set. The rows are re-minted from the owner–recipient ECDH
    /// that filed them in the first place.
    ///
    /// This owner-re-signs the set it builds, so both carried halves are proven
    /// before a single row is re-minted, and every field a re-minted commitment
    /// entry carries is either derived here or copied from what the owner already
    /// signed. A ledger row additionally carries forward `expiresAt` and the
    /// preserved unknowns, which no owner signature covers. A row neither owner
    /// authority over `recipientEncPk` covers is dropped from the moved set
    /// rather than re-minted.
    fn remint_grants(
        &self,
        node: &RepublishedNode,
        plane: &RootPlane,
    ) -> Result<RemintedGrants, WritePublishError> {
        // Release-active (security rule 8). The gate owner-verifies the record's
        // own committed set and binds it to the name it was read at
        // (`gate/adoption.rs` stage 2), so equality with the authorized set is
        // what proves the mint runs off the owner's own attestation
        // ([`WriteWaveNet::authorized_commitment`]).
        if plane.section.commitment != *self.authorized_commitment {
            return Err(WritePublishError::Rejected);
        }
        let commitment = self.authorized_commitment;
        let ledger = &plane.write_body.grant_ledger;
        enforce_committed_ledger(commitment, ledger).map_err(|_| WritePublishError::Rejected)?;
        let old_name = commitment.ipns_name.as_slice();
        let new_name = node.new_name.as_str().as_bytes();
        let carried: BTreeMap<[u8; 32], &GrantSetEntry> =
            commitment.entries.iter().map(|e| (e.tag, e)).collect();

        let owner_identity = self.owner.verifying_key();

        let mut reminted = RemintedGrants {
            entries: Vec::with_capacity(ledger.len()),
            ledger: Vec::with_capacity(ledger.len()),
        };
        for entry in ledger {
            // The owner holds both authorities over the row here, and the
            // stronger one decides (`rotation::adopt_recipients`): re-deriving
            // the committed tag proves `recipientEncPk`, so a corrupted
            // `ownerSig` costs the row nothing. Only a key that derives no
            // committed tag AND carries no owner signature is dropped — there is
            // no honest key to re-mint it under, and refusing instead would let
            // the write grantee this wave is cutting veto its own revocation.
            let attested = row_is_owner_attested(&owner_identity, entry, old_name);
            let Some(recipient_enc) = bound_recipient(self.owner_enc_secret, entry, old_name)
            else {
                if attested {
                    return Err(WritePublishError::Rejected);
                }
                continue;
            };
            // `recipientIdentityPk` is the one recipient field the tag does not
            // prove, and the mint below owner-signs whatever it is handed. Where
            // the row carried no owner signature, the label is a write-grantee's
            // to choose, so it is dropped rather than laundered into the owner's.
            let recipient_identity_pk = if attested {
                entry.recipient_identity_pk
            } else {
                UNATTESTED_IDENTITY_PK
            };
            let row = mint_grant_row(
                self.owner,
                self.owner_enc_secret,
                recipient_identity_pk,
                &recipient_enc,
                &self.scope_id,
                new_name,
                entry.permission,
            )
            .ok_or(WritePublishError::Rejected)?;

            let committed = carried.get(&entry.tag).ok_or(WritePublishError::Rejected)?;
            // The pseudonym binds the scope, not the name, so the mint must
            // reproduce the committed key: it authorizes structure signing, and
            // re-signing a different one would hand that authority elsewhere.
            let mut commitment_entry = row.commitment_entry;
            if commitment_entry.pseudonym_pk != committed.pseudonym_pk {
                return Err(WritePublishError::Rejected);
            }
            commitment_entry.unknown = committed.unknown.clone();
            let mut ledger_entry = row.ledger_entry;
            // The deadline is the discovered-expiry trigger's input and the
            // invite claim path's restriction; dropping it at a re-mint erases
            // both, and dropping the unknown fields discards what another version
            // wrote.
            ledger_entry.expires_at = entry.expires_at;
            ledger_entry.unknown = entry.unknown.clone();

            reminted.entries.push(commitment_entry);
            reminted.ledger.push(ledger_entry);
        }
        // Tag order, never the ledger order a write-grantee authored: the owner
        // signs these entries (`reseal_scope_root` sorts its blobs on the same
        // rule).
        reminted.entries.sort_by(|a, b| a.tag.cmp(&b.tag));
        reminted.ledger.sort_by(|a, b| a.tag.cmp(&b.tag));
        Ok(reminted)
    }

    /// The moved root's grant section, re-minted for the wave.
    ///
    /// The root's section is the only channel that carries `writeScopeSeed` to
    /// anyone — the owner-write blob and every write grantee's blob — so a root
    /// republished with the section carried verbatim would move every name while
    /// handing out the seed that derives the retired ones, and its write body
    /// would stay sealed below the write-epoch floor the re-point is about to
    /// raise. Re-seal is the general mechanism
    /// ([`reseal_scope_root`](crate::rotation::reseal_scope_root)): same override
    /// seed and read epoch (a name wave cuts no read key, so `prev` mints no
    /// history link), fresh write scope seed, advanced write epoch, new name.
    fn reseal_root(
        &self,
        node: &RepublishedNode,
        plane: &RootPlane,
        fresh_write_scope_seed: &[u8; SECRET_LEN],
        read_epoch: u64,
    ) -> Result<GrantSection, WritePublishError> {
        let remint = self.remint_grants(node, plane)?;
        let mut commitment = self.authorized_commitment.clone();
        commitment.ipns_name = node.new_name.as_str().as_bytes().to_vec();
        commitment.entries = remint.entries;
        let commitment_sig = sign_grant_set(self.owner, &commitment)
            .map_err(|_| WritePublishError::Rejected)?
            .to_compact();
        let owner_enc_pub = self.owner_enc_secret.public();
        let pseudonym_signer = self.scope_keys.writer_pseudonym(&self.scope_id);
        let pointer_read_key = self.scope_keys.pointer_read_key(&self.scope_id);
        reseal_scope_root(
            &mut *self.entropy.borrow_mut(),
            &ScopeRootIdentity {
                v: ENVELOPE_V,
                scope_id: self.scope_id,
                ipns_name: node.new_name.as_str().as_bytes(),
                owner_enc_pub: &owner_enc_pub,
                owner_enc_secret: Some(self.owner_enc_secret),
                ascent: self.parent_node_seed.map(AscentAuthority::ParentSeed),
                owes_ascent_link: plane.section.ascent_link.is_some(),
                pseudonym_signer: &pseudonym_signer,
            },
            &ResealSeeds {
                override_seed: &plane.read_scope_seed,
                read_epoch,
                prev: None,
                write_scope_seed: fresh_write_scope_seed,
                write_epoch: node.write_epoch,
                write_history: WriteHistory::Cut(PrevEpochSeed {
                    seed: &plane.write_scope_seed,
                    epoch: plane.write_epoch,
                }),
                pointer_read_key: &pointer_read_key,
            },
            &CommittedSet {
                owner_identity: &self.owner.verifying_key(),
                commitment: &commitment,
                commitment_sig: &commitment_sig,
                grant_ledger: &remint.ledger,
                direct_child_scope_index: &plane.write_body.direct_child_scope_index,
            },
            &plane.section.history_links,
        )
        .map_err(reseal_verdict)
    }

    /// Author and CAS-publish `node`'s rewritten record at its new name, signing
    /// under the one narrow capability the wave handed for it.
    async fn publish_moved(
        &self,
        node: &RepublishedNode,
        source: WaveSource,
    ) -> Result<(), WritePublishError> {
        // The signer IS the name's key, so a record published at a name it does
        // not open would be one no resolver can verify (`IpnsRecord::verify`).
        // Release-active: this path owner-signs a commitment over `new_name` and
        // uploads the head block before it ever reaches the transport.
        if IpnsName::from_public_key(&node.signer.verifying_key()) != node.new_name {
            return Err(WritePublishError::Rejected);
        }
        let WaveSource {
            mut read_body,
            read_epoch,
            read_key,
            unknown,
            epoch_tag_unknown,
            root,
        } = source;
        rewrite_child_names(&mut read_body, &node.child_names)?;

        // `read_epoch` is the enumeration's envelope epoch, carried across the
        // whole subtree since a name wave cuts no read key — so a read rotation
        // adopted mid-wave leaves every record below the live floor. The
        // stage-5 mirror, strict `<` like `check_publishable`.
        let read_floor = floor::read_epoch_floor(self.floors, &self.scope_id)
            .await
            .map_err(|_| WritePublishError::NotLanded)?
            .unwrap_or(0);
        if read_epoch < read_floor {
            return Err(WritePublishError::Rejected);
        }

        let mut nonce = [0u8; 24];
        self.entropy
            .borrow_mut()
            .fill(&mut nonce)
            .map_err(|_| WritePublishError::NotLanded)?;
        let authoring = EnvelopeAuthoring {
            node_id: node.node_id,
            scope_id: self.scope_id,
            epoch: read_epoch,
            read_key: &read_key,
            nonce: &nonce,
            body: &read_body,
            carried_unknown: unknown,
            carried_epoch_tag_unknown: epoch_tag_unknown,
        };
        let head = match root {
            Some(plane) => {
                let fresh = node
                    .write_scope_seed
                    .as_ref()
                    .ok_or(WritePublishError::Rejected)?;
                if node.node_id != self.scope_id || node.write_epoch <= plane.write_epoch {
                    return Err(WritePublishError::Rejected);
                }
                // Every re-minted tag binds `new_name`, and a write grantee
                // derives that name from the seed this section hands it — so a
                // name the published seed does not derive mints a set no grantee
                // can ever self-locate.
                if node.new_name != derive_write_name(fresh.as_bytes(), &node.node_id) {
                    return Err(WritePublishError::Rejected);
                }
                // `plane.write_epoch` is the floor as the enumeration saw it, and
                // the whole interior wave has run since. The floor is monotonic
                // and rises on any pointer consult, so a floor above that
                // snapshot means another device's re-point superseded the record
                // this wave is carrying forward — and sealing against the
                // snapshot would publish a section at or below the live floor,
                // a write plane `open_write_body` could never reopen.
                let write_floor = floor::write_epoch_floor(self.floors, &self.scope_id)
                    .await
                    .map_err(|_| WritePublishError::NotLanded)?
                    .ok_or(WritePublishError::NotLanded)?;
                if write_floor > plane.write_epoch {
                    return Err(WritePublishError::Rejected);
                }
                let section = self.reseal_root(node, &plane, fresh.as_bytes(), read_epoch)?;
                author_scope_root_with_section(
                    authoring,
                    &node.new_name,
                    &section,
                    &self.owner.verifying_key(),
                )
            }
            None => author_child_envelope(authoring),
        }
        .map_err(|refusal| {
            if refusal.is_trust_refusal() {
                WritePublishError::Rejected
            } else {
                WritePublishError::NotLanded
            }
        })?;

        let binding = HeadBinding {
            node_id: node.node_id,
            scope_id: self.scope_id,
            epoch: read_epoch,
        };
        // A preflight refusal is this build's own verdict on the bytes it just
        // authored: re-authoring the same inputs reaches it again (rule 6).
        let preflighted =
            preflight(&binding, &read_key, &head).map_err(|_| WritePublishError::Rejected)?;
        let receipt = publish_record(
            self.transport,
            self.api,
            self.floors,
            self.scheduler,
            self.profile,
            &RecordPublishRequest {
                name: &node.new_name,
                signer: &node.signer,
                head: &preflighted,
                content_cids: Vec::new(),
                min_current_sequence: None,
            },
        )
        .await
        .map_err(publish_record_verdict)?;
        match receipt.outcome {
            PublishOutcome::Published { .. } => Ok(()),
            PublishOutcome::LostRace { .. } => Err(WritePublishError::LostRace),
            PublishOutcome::Unconfirmed { .. } => Err(WritePublishError::NotLanded),
        }
    }

    /// Flip the canonical scope pointer to the sealed re-point `block`.
    ///
    /// The record's `Value` is the block itself rather than an `/ipfs/` head
    /// ([`RecordPointerFetch`](super::pointer_fetch::RecordPointerFetch) reads it
    /// back that way), so this rides [`publish_inline`] and inherits every law of
    /// the pipeline. Nothing gates a pointer record, so no adopt ever raises its
    /// sequence floor: the freshest record on the network is the lower bound a
    /// second rotation must clear, and a confirmed flip raises the floor itself.
    async fn publish_scope_pointer(&self, block: &[u8]) -> Result<(), WritePublishError> {
        let name = scope_pointer_name(self.owner_pointer_seed, &self.scope_id);
        let signer = scope_pointer_signer(self.owner_pointer_seed, &self.scope_id);
        let observed = fanout_get_verify(self.transport, &name)
            .await
            .map_or(0, |(record, _)| record.sequence);
        let receipt = publish_inline(
            self.transport,
            self.api,
            self.floors,
            self.scheduler,
            self.profile,
            &InlineRecordRequest {
                name: &name,
                signer: &signer,
                value: block,
                min_current_sequence: Some(observed),
            },
        )
        .await
        .map_err(|error| match error {
            PublishError::Register(_) => WritePublishError::RegistryFull,
            PublishError::EmptyHeadCid | PublishError::RecordTooLarge { .. } => {
                WritePublishError::Rejected
            }
            _ => WritePublishError::NotLanded,
        })?;
        match receipt.outcome {
            PublishOutcome::Published { sequence } => {
                floor::advance_sequence_on_unseal(self.floors, name.as_str().as_bytes(), sequence)
                    .await
                    .map_err(|_| WritePublishError::NotLanded)
            }
            PublishOutcome::LostRace { .. } => Err(WritePublishError::LostRace),
            PublishOutcome::Unconfirmed { .. } => Err(WritePublishError::NotLanded),
        }
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> WriteSubtreeResolver
    for WriteWaveNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport,
    F: FloorStore,
{
    async fn resolve_node(&self, node_id: &[u8; 16]) -> Result<WriteScopeNode, ResolveFailure> {
        let is_root = *node_id == self.scope_id;
        let current_name = if is_root {
            self.current_root_name.clone()
        } else {
            self.subtree.name(node_id).ok_or(ResolveFailure::Rejected)?
        };
        let Some((_, record_bytes)) = fanout_get_verify(self.transport, &current_name).await else {
            return Err(ResolveFailure::Unavailable);
        };
        let source = if is_root {
            self.root_source(&current_name, &record_bytes).await
        } else {
            self.interior_source(*node_id, &current_name, &record_bytes)
                .await
        }
        .map_err(subtree_verdict)?;

        self.subtree.record_read_epoch(source.read_epoch);
        if let Some(plane) = &source.root {
            self.record_scope_boundary(
                &plane.write_body.direct_child_scope_index,
                &plane.read_scope_seed,
            )
            .await?;
        }
        let child_node_ids = self.subtree.record_children(&source.read_body)?;
        // The republish runs off this read ([`GatedWaveRoot`]).
        if is_root {
            self.gated_root.park(&current_name, source);
        }
        Ok(WriteScopeNode {
            node_id: *node_id,
            current_name,
            child_node_ids,
        })
    }

    /// Recover an in-flight wave from the canonical scope pointer.
    ///
    /// The moved root's name derives from the very seed a resume needs, so the
    /// owner-signed pointer is the one published anchor that breaks that circle;
    /// the seed itself still comes from the moved root's own blob through the
    /// gate, never from the pointer.
    async fn recover_wave(&self) -> Result<Option<ResumedWriteWave>, ResolveFailure> {
        let pointer = scope_pointer_name(self.owner_pointer_seed, &self.scope_id);
        let block = match RecordPointerFetch::new(self.transport)
            .fetch(&pointer)
            .await
        {
            Ok(Some(block)) => block,
            // No pointer record: this scope has never been re-pointed, so there is
            // no wave to pick up. A seam failure is not that answer — reporting it
            // as one mints a second seed for a wave already in flight and orphans
            // every name the first one registered.
            Ok(None) => return Ok(None),
            Err(_) => return Err(ResolveFailure::Unavailable),
        };
        let pointer_read_key = self.scope_keys.pointer_read_key(&self.scope_id);
        let repoint = open_repoint(
            &pointer_read_key,
            self.payload_version,
            &self.scope_id,
            &self.owner.verifying_key(),
            &block,
        )
        .map_err(|_| ResolveFailure::Rejected)?;
        if repoint.prev_root.as_ref() != Some(self.current_root_name) {
            return Ok(None);
        }
        let Some((_, record_bytes)) =
            fanout_get_verify(self.transport, &repoint.current_root).await
        else {
            return Err(ResolveFailure::Unavailable);
        };
        let identity = self.owner.verifying_key();
        let gated = gated_scope_root(
            &self.root_adopter(&identity),
            &repoint.current_root,
            &record_bytes,
        )
        .await
        .map_err(ResolveFailure::from)?;
        if gated.envelope.v != ENVELOPE_V || gated.envelope.id != self.scope_id {
            return Err(ResolveFailure::Rejected);
        }
        // The re-point object is the owner's own signed statement of the write
        // epoch, so the blob is opened there rather than at the durable floor —
        // which a resume must leave where the pre-wave root can still be read.
        let owb = gated
            .section
            .owner_write_blob
            .as_ref()
            .ok_or(ResolveFailure::Rejected)?;
        let seed = open_write_scope_seed_at(
            self.owner_enc_secret,
            &gated.envelope,
            owb,
            repoint.write_epoch,
        )
        .ok_or(ResolveFailure::Rejected)?;
        Ok(Some(ResumedWriteWave {
            write_scope_seed: SecretBytes::new(*seed),
            root_name: repoint.current_root,
            write_epoch: repoint.write_epoch,
        }))
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> WriteWavePublisher
    for WriteWaveNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    async fn is_republished(&self, new_name: &IpnsName) -> Result<bool, WritePublishError> {
        Ok(fanout_get_verify(self.transport, new_name).await.is_some())
    }

    async fn republish(&self, node: &RepublishedNode) -> Result<(), WritePublishError> {
        let source = match self.gated_root.take(&node.current_name) {
            Some(parked) => parked,
            None => {
                let record_bytes = fanout_get_verify(self.transport, &node.current_name)
                    .await
                    .map(|(_, bytes)| bytes)
                    .ok_or(WritePublishError::NotLanded)?;
                if node.is_root {
                    self.root_source(&node.current_name, &record_bytes).await?
                } else {
                    self.interior_source(node.node_id, &node.current_name, &record_bytes)
                        .await?
                }
            }
        };
        // The interior path re-opens its own record at the floor, so only the
        // root's read has to survive a failed publish.
        let held = node.is_root.then(|| source.clone());
        let published = self.publish_moved(node, source).await;
        if published.is_err()
            && let Some(source) = held
        {
            self.gated_root.park(&node.current_name, source);
        }
        published
    }

    async fn retire(&self, old_names: &[IpnsName]) -> Result<(), WritePublishError> {
        // Irreversible, and the old root serves the tombstone every lagging
        // reader chases (`net/retire.rs::root_retire_ready`).
        if !root_retire_ready() && old_names.iter().any(|name| name == self.current_root_name) {
            return Err(WritePublishError::Rejected);
        }
        // Re-read here, not at the enumeration: a rise since then leaves the
        // wave's moved copies below the live floor, and tombstoning the old
        // names would strand the subtree at both. Fail closed with nothing
        // gated — that epoch is the whole evidence this step rests on.
        let moved_read_epoch = self
            .subtree
            .lowest_read_epoch()
            .ok_or(WritePublishError::Rejected)?;
        let read_floor = floor::read_epoch_floor(self.floors, &self.scope_id)
            .await
            .map_err(|_| WritePublishError::NotLanded)?
            .unwrap_or(0);
        if moved_read_epoch < read_floor {
            return Err(WritePublishError::Rejected);
        }
        let targets: Vec<String> = old_names
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        retire(self.api, &targets)
            .await
            .map(drop)
            .map_err(|_| WritePublishError::NotLanded)
    }

    async fn check_repoint_publishable(
        &self,
        repoint: &RepointObject,
    ) -> Result<(), WritePublishError> {
        // The produce side of the gate's own rule, run against the same
        // predicate the cold seed consumes it with, so the two cannot drift.
        match floor::repoint_regression(self.floors, repoint, &self.session_root_scope_id)
            .await
            .map_err(|_| WritePublishError::NotLanded)?
        {
            Some(_) => Err(WritePublishError::Rejected),
            None => Ok(()),
        }
    }

    async fn publish_repoint(
        &self,
        channel: RepointChannel,
        block: &[u8],
    ) -> Result<(), WritePublishError> {
        match channel {
            RepointChannel::ScopePointer => self.publish_scope_pointer(block).await,
            // Neither accelerator has a wire shape yet — the mailbox re-point
            // payload is unspecified and no tombstone record exists — and this
            // build never signs bytes it cannot decode (security rule 8). Both
            // carry nothing load-bearing, so the wave completes without them.
            RepointChannel::Mailbox | RepointChannel::Tombstone => {
                Err(WritePublishError::NotLanded)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use core::num::NonZeroU64;

    use crate::content::dag::root_block_cid;
    use crate::entropy::EntropyError;
    use crate::grants::{
        GrantRow, PublishedGrantBlob, mint_grant_row, recipient_blinded_tag, self_locate,
    };
    use cipherbox_core::codec::Value;
    use cipherbox_core::error::{CodecError, Malformed};
    use cipherbox_core::ipns::{IpnsRecord, VerifiedRecord};
    use cipherbox_core::seal::{
        AscentLink, ChildRef, GrantBlobPayload, GrantSetCommitment, NodeKind, Permission,
        STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_HISTORY_LINK,
        STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_WRITE_HISTORY_LINK, StructureSigInput,
        decode_envelope, decode_grant_section, encode_envelope, encode_grant_section,
        encode_write_body, grant_section_bytes, open_ascent_link, open_grant_blob,
        open_history_link, open_owner_history_link, open_owner_write_blob, open_read_body, seal,
        seal_read_body, set_grant_section, sign_grant_set, sign_recipient_binding, sign_structure,
        verify_grant_set,
    };
    use cipherbox_core::suite::ecdsa::{EcdsaSignature, IDENTITY_PUBLIC_LEN};
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use cipherbox_core::suite::secret::{SecretBytes, ct_eq};

    use super::*;
    use crate::content::GatewaySource;
    use crate::rotation::sweep::sim;
    use crate::rotation::{
        CascadeError, CascadeOutcome, CommittedSet, EnumerationError, PrevEpochSeed, ResealSeeds,
        RotateScopePlan, RotateScopeWritePlan, ScopeRootIdentity, WriteRotateError,
        cascade_rotate_scope, derive_write_name, enumerate_eager_set, reseal_scope_root,
        rotate_scope, rotate_scope_write, sweep_pass,
    };
    use crate::seams::{EndpointId, HttpResponse, SeamError, SeamResult};
    use crate::sync::pointer::{SessionRole, open_repoint, seal_repoint};
    use crate::testkit::fakes::{
        InMemoryCredentialStore, InMemoryFloorStore, InMemoryRecordStore, ScriptedHttp,
        VirtualScheduler,
    };
    use crate::testkit::{
        FakeWorld, OWNER_ROOT_EPOCH, OWNER_ROOT_PSEUDONYM_SEED, OWNER_ROOT_SCOPE_SEED,
        OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootFixture, OwnerRootSpec, SeededEntropy, block_on,
        owner_root_fixture, requested_cid,
    };

    const SCOPE: [u8; 16] = [0x44; 16];
    const CHILD_SCOPE: [u8; 16] = [0xc1; 16];
    const OWNER_SCALAR: [u8; 32] = [0x11; 32];
    const OWNER_ENC_SCALAR: [u8; 32] = [0x33; 32];
    const POINTER_READ_KEY: [u8; 32] = [0x5a; 32];
    const OWNER_ROOT_SECRET: [u8; 32] = [0x6b; 32];
    const OWNER_POINTER_SEED: [u8; 32] = [0x7c; 32];
    /// The pointer-payload envelope version every re-point in this suite is
    /// sealed and read under.
    const PAYLOAD_VERSION: u64 = 1;

    /// The owner's derivation arm: the two per-scope edges the rotation needs,
    /// off this test owner's root secret and pointer seed.
    struct OwnerSeeds;

    impl OwnerScopeKeys for OwnerSeeds {
        fn writer_pseudonym(&self, scope_id: &[u8; 16]) -> Ed25519Signer {
            kdf::pseudonym_sign(&OWNER_ROOT_SECRET, scope_id)
        }

        fn pointer_read_key(&self, scope_id: &[u8; 16]) -> Zeroizing<[u8; SECRET_LEN]> {
            Zeroizing::new(*kdf::pointer_read_key(&OWNER_POINTER_SEED, scope_id).as_bytes())
        }
    }
    const FRESH_SEED: [u8; 32] = [0xf0; 32];
    const TTL_NANOS: u64 = 2_000_000_000;
    const EOL: &str = "2099-01-01T00:00:00Z";

    fn owner_identity() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&OWNER_SCALAR).expect("valid scalar")
    }

    fn owner_enc() -> X25519Secret {
        X25519Secret::from_scalar(OWNER_ENC_SCALAR)
    }

    /// A vault root: no ascent link, an owner-write-blob at the fixture's epoch
    /// so the owner recovers the write-scope seed its write body opens under.
    fn vault_root(scope_id: [u8; 16], child_scope_index: Vec<ChildScopeRef>) -> OwnerRootFixture {
        scope_root(scope_id, child_scope_index, None)
    }

    /// An interior scope root, whose ascent link seals under
    /// `nodeSeed(parentOverrideSeed, scope_id)` — what every descendant in a
    /// real eager set looks like.
    fn interior(
        scope_id: [u8; 16],
        parent_override_seed: &[u8; 32],
        child_scope_index: Vec<ChildScopeRef>,
    ) -> OwnerRootFixture {
        let parent_node_seed = *kdf::node_seed(parent_override_seed, &scope_id).as_bytes();
        scope_root(scope_id, child_scope_index, Some(parent_node_seed))
    }

    fn scope_root(
        scope_id: [u8; 16],
        child_scope_index: Vec<ChildScopeRef>,
        parent_node_seed: Option<[u8; 32]>,
    ) -> OwnerRootFixture {
        owner_root_fixture(OwnerRootSpec {
            owner_identity: &owner_identity(),
            owner_enc: &owner_enc().public(),
            scope_id,
            root_id: scope_id,
            children: Vec::new(),
            child_scope_index,
            parent_node_seed,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants: Vec::new(),
        })
    }

    fn child_ref(scope_id: [u8; 16], fixture: &OwnerRootFixture) -> ChildScopeRef {
        ChildScopeRef {
            scope_id,
            ipns_name: fixture.name.as_str().as_bytes().to_vec(),
            unknown: PreservedFields::new(),
        }
    }

    fn record_for(scope_id: &[u8; 16], head_cid_str: &str, sequence: u64) -> Vec<u8> {
        let write_seed = kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, scope_id);
        let signer = kdf::ipns_keypair(write_seed.as_bytes());
        IpnsRecord::create_v2(
            &signer,
            format!("/ipfs/{head_cid_str}").as_bytes(),
            sequence,
            TTL_NANOS,
            EOL,
        )
        .marshal()
    }

    /// The block store the content gateway and the API upload share, so a
    /// published head is readable by the very next gated resolve.
    type Blocks = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

    /// One HTTP fake standing in for the content gateway and the API: block GETs
    /// answer from `blocks`, `/content/upload` files the bytes under the CID the
    /// caller declared, and the registry acks.
    fn serve_plane(http: &ScriptedHttp, blocks: &Blocks) {
        for _ in 0..256 {
            let blocks = Arc::clone(blocks);
            http.enqueue_derived(move |request| {
                if request.url.contains("/content/upload") {
                    let cid = request
                        .headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("x-content-cid"))
                        .map(|(_, value)| value.clone())
                        .ok_or_else(|| SeamError::new("upload without a content CID"))?;
                    let body = request.body.clone().unwrap_or_default();
                    let size = body.len();
                    blocks.lock().expect("lock").insert(cid.clone(), body);
                    return Ok(HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: format!(r#"{{"cid":"{cid}","size":{size}}}"#).into_bytes(),
                    });
                }
                if request.url.ends_with("/registry/retire") {
                    return Ok(HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: br#"{"retired":1,"unpinned":0}"#.to_vec(),
                    });
                }
                if request.url.contains("/registry/") {
                    return Ok(HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: Vec::new(),
                    });
                }
                match blocks
                    .lock()
                    .expect("lock")
                    .get(&requested_cid(&request.url))
                {
                    Some(block) => Ok(HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: block.clone(),
                    }),
                    None => Err(SeamError::new("no such block")),
                }
            });
        }
    }

    /// The seams one owner device runs the rotation edges over.
    struct Harness<T> {
        transport: T,
        store: InMemoryRecordStore,
        world: FakeWorld,
        http: ScriptedHttp,
        api: ApiClient<ScriptedHttp, InMemoryCredentialStore>,
        floors: InMemoryFloorStore,
        gateway: Gateway,
        profile: SyncTimingProfile,
        entropy: RefCell<SeededEntropy>,
        enc_secret: X25519Secret,
        identity: EcdsaVerifier,
        blocks: Blocks,
    }

    impl<T: RecordTransport + Clone> Harness<T> {
        fn build(make: impl FnOnce(InMemoryRecordStore, ScriptedHttp) -> T) -> Self {
            let world = FakeWorld::new();
            let device = world.device(b"owner");
            let http = device.http.clone();
            let blocks: Blocks = Arc::new(Mutex::new(BTreeMap::new()));
            serve_plane(&http, &blocks);
            let api = ApiClient::new(
                http.clone(),
                device.credential_store.clone(),
                "http://api.test",
            );
            let store = device.record_store.clone();
            Self {
                transport: make(store.clone(), http.clone()),
                store,
                world,
                http,
                api,
                floors: device.floor_store.clone(),
                gateway: Gateway {
                    accelerator: Some(GatewaySource::public("https://gw.test")),
                    public_fallbacks: Vec::new(),
                },
                profile: SyncTimingProfile::CI,
                entropy: RefCell::new(SeededEntropy::new(7)),
                enc_secret: owner_enc(),
                identity: owner_identity().verifying_key(),
                blocks,
            }
        }

        /// Stage `fixture`'s head block and a signed record for it at `sequence`
        /// on every endpoint. `write_floor` seeds the scope's durable
        /// write-epoch floor; without one the owner-write-blob never opens.
        fn stage(&self, scope_id: [u8; 16], fixture: &OwnerRootFixture, write_floor: Option<u64>) {
            self.blocks
                .lock()
                .expect("lock")
                .insert(fixture.head_cid_str.clone(), fixture.head_block.clone());
            let record = record_for(&scope_id, &fixture.head_cid_str, 1);
            for endpoint in self.store.endpoints() {
                self.store
                    .seed_record(&endpoint, fixture.name.as_str(), record.clone());
            }
            if let Some(epoch) = write_floor {
                block_on(floor::advance_write_epoch_on_sight(
                    &self.floors,
                    &scope_id,
                    epoch,
                ))
                .expect("write floor");
            }
        }

        /// The wiring rooted at the vault root, whose own record carries no
        /// ascent link — the ancestry the walk extends from. `ascent_seed` is
        /// the seed the descendants' **published** records sealed their ascent
        /// links under ([`RotationAncestry::rooted_at`]).
        fn net_under(
            &self,
            ascent_seed: &[u8; 32],
            root_child_index: &[ChildScopeRef],
        ) -> Net<'_, T> {
            self.net_rooted(RotationAncestry::rooted_at(
                SCOPE,
                ascent_seed,
                root_child_index,
            ))
        }

        fn net(&self, root_child_index: &[ChildScopeRef]) -> Net<'_, T> {
            self.net_under(&OWNER_ROOT_SCOPE_SEED, root_child_index)
        }

        fn net_rooted(&self, ancestry: RotationAncestry) -> Net<'_, T> {
            OwnerRotationNet {
                transport: &self.transport,
                api: &self.api,
                gateway: &self.gateway,
                http: &self.http,
                floors: &self.floors,
                scheduler: &self.world.scheduler,
                profile: &self.profile,
                entropy: &self.entropy,
                keys: OwnerRotationKeys {
                    enc_secret: &self.enc_secret,
                    identity: &self.identity,
                    scope_keys: &OwnerSeeds,
                },
                ancestry,
                owner_pointer_seed: Some(&OWNER_POINTER_SEED),
                payload_version: PAYLOAD_VERSION,
                gated: GatedRoots::default(),
                swept: SweptScopeState::default(),
            }
        }
    }

    type Net<'a, T> = OwnerRotationNet<
        'a,
        T,
        ScriptedHttp,
        InMemoryCredentialStore,
        InMemoryFloorStore,
        VirtualScheduler,
        SeededEntropy,
    >;

    impl Harness<InMemoryRecordStore> {
        fn plain() -> Self {
            Self::build(|store, _| store)
        }
    }

    impl Harness<RacingTransport> {
        fn racing(key: &str, winner: Vec<u8>) -> Self {
            let key = key.to_owned();
            Self::build(move |store, _| RacingTransport {
                inner: store,
                winner: Arc::new(Mutex::new(Some((key, winner)))),
            })
        }
    }

    /// The concurrent writer's record, keyed by the name it lands at.
    type Winner = Arc<Mutex<Option<(String, Vec<u8>)>>>;

    /// A transport where a concurrent writer lands a strictly-newer record the
    /// instant our PUT goes out — the CAS race the publisher must report.
    #[derive(Clone)]
    struct RacingTransport {
        inner: InMemoryRecordStore,
        winner: Winner,
    }

    impl RecordTransport for RacingTransport {
        fn endpoints(&self) -> Vec<EndpointId> {
            self.inner.endpoints()
        }

        async fn get_record(
            &self,
            endpoint: &EndpointId,
            routing_key: &str,
            max_bytes: usize,
        ) -> SeamResult<Option<Vec<u8>>> {
            self.inner
                .get_record(endpoint, routing_key, max_bytes)
                .await
        }

        async fn put_record(
            &self,
            endpoint: &EndpointId,
            routing_key: &str,
            record: &[u8],
        ) -> SeamResult<()> {
            self.inner.put_record(endpoint, routing_key, record).await?;
            if let Some((key, winner)) = self.winner.lock().expect("lock").take() {
                for endpoint in self.inner.endpoints() {
                    self.inner.seed_record(&endpoint, &key, winner.clone());
                }
            }
            Ok(())
        }
    }

    /// A one-level tree: the vault root names `CHILD_SCOPE`, an interior scope
    /// root whose own write body names a grandchild.
    fn one_level() -> (OwnerRootFixture, ChildScopeRef, ChildScopeRef) {
        let grandchild_scope = [0xd2; 16];
        let child_seed = OWNER_ROOT_SCOPE_SEED;
        let leaf = interior(grandchild_scope, &child_seed, Vec::new());
        let grandchild = child_ref(grandchild_scope, &leaf);
        let child = interior(
            CHILD_SCOPE,
            &OWNER_ROOT_SCOPE_SEED,
            vec![grandchild.clone()],
        );
        let child_ref = child_ref(CHILD_SCOPE, &child);
        (child, child_ref, grandchild)
    }

    #[test]
    fn a_descendants_adjacency_comes_from_its_own_gated_write_body() {
        let (child, child_ref, grandchild) = one_level();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));

        let index = block_on(
            harness
                .net(core::slice::from_ref(&child_ref))
                .direct_child_index(&child_ref),
        )
        .expect("the descendant's own index");
        assert_eq!(index, vec![grandchild]);
    }

    /// The ascent link every interior scope root carries is verified against a
    /// keypair the **reader** derives from its ancestor seed, so a walk that
    /// cannot place a descendant under its parent proves nothing about it.
    #[test]
    fn a_descendant_off_the_ancestry_never_passes_the_gate() {
        let (child, child_ref, _) = one_level();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));

        assert_eq!(
            block_on(
                harness
                    .net_rooted(RotationAncestry::default())
                    .direct_child_index(&child_ref)
            ),
            Err(ResolveFailure::Rejected),
        );
    }

    #[test]
    fn a_record_claiming_another_scope_is_a_fail_closed_rejection() {
        let (child, child_ref, _) = one_level();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));

        let mislabelled = ChildScopeRef {
            scope_id: [0x9e; 16],
            ..child_ref.clone()
        };
        assert_eq!(
            block_on(
                harness
                    .net(core::slice::from_ref(&child_ref))
                    .direct_child_index(&mislabelled)
            ),
            Err(ResolveFailure::Rejected),
        );
    }

    #[test]
    fn a_descendant_no_endpoint_serves_is_availability_not_a_trust_verdict() {
        let (_, child_ref, _) = one_level();
        let harness = Harness::plain();
        assert_eq!(
            block_on(
                harness
                    .net(core::slice::from_ref(&child_ref))
                    .direct_child_index(&child_ref)
            ),
            Err(ResolveFailure::Unavailable),
        );
    }

    #[test]
    fn a_non_canonical_ipns_name_is_rejected_before_any_fetch() {
        let harness = Harness::plain();
        let malformed = ChildScopeRef {
            scope_id: CHILD_SCOPE,
            ipns_name: b"not-an-ipns-name".to_vec(),
            unknown: PreservedFields::new(),
        };
        assert_eq!(
            block_on(harness.net(&[]).direct_child_index(&malformed)),
            Err(ResolveFailure::Rejected),
        );
        assert!(
            harness.http.requests().is_empty(),
            "an unparseable name has no key to gate against, so nothing is fetched"
        );
    }

    /// No durable write-epoch floor means the owner-write-blob never opens, so
    /// the write body has no key — re-authorable, never a trust verdict.
    #[test]
    fn a_root_held_keyless_yields_no_index_and_no_rejection() {
        let (child, child_ref, _) = one_level();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, None);

        assert_eq!(
            block_on(
                harness
                    .net(core::slice::from_ref(&child_ref))
                    .direct_child_index(&child_ref)
            ),
            Err(ResolveFailure::Unavailable),
        );
    }

    /// The record `rotate_scope` hands the publisher: `fixture`'s scope root
    /// re-sealed at `read_epoch` under a fresh override seed. The history link
    /// descends from `read_epoch`, so a cut minted from a stale snapshot carries
    /// the link that snapshot would have.
    fn cut(fixture: &OwnerRootFixture, scope_id: [u8; 16], read_epoch: u64) -> ResealedScopeRoot {
        let pseudonym = Ed25519Signer::from_seed(OWNER_ROOT_PSEUDONYM_SEED);
        let owner_enc_pub = owner_enc().public();
        let mut entropy = SeededEntropy::new(11);
        let section = reseal_scope_root(
            &mut entropy,
            &ScopeRootIdentity {
                v: ENVELOPE_V,
                scope_id,
                ipns_name: fixture.name.as_str().as_bytes(),
                owner_enc_pub: &owner_enc_pub,
                owner_enc_secret: None,
                ascent: None,
                owes_ascent_link: false,
                pseudonym_signer: &pseudonym,
            },
            &ResealSeeds {
                override_seed: &FRESH_SEED,
                read_epoch,
                prev: read_epoch.checked_sub(1).map(|epoch| PrevEpochSeed {
                    seed: &OWNER_ROOT_SCOPE_SEED,
                    epoch,
                }),
                write_scope_seed: &OWNER_ROOT_WRITE_SCOPE_SEED,
                write_epoch: OWNER_ROOT_EPOCH,
                write_history: WriteHistory::Carried(&[]),
                pointer_read_key: &POINTER_READ_KEY,
            },
            &CommittedSet {
                owner_identity: &owner_identity().verifying_key(),
                commitment: &fixture.grant_section.commitment,
                commitment_sig: &fixture.grant_section.commitment_sig,
                grant_ledger: &[],
                direct_child_scope_index: &[],
            },
            &[],
        )
        .expect("re-seal");
        ResealedScopeRoot {
            scope_id,
            ipns_name: fixture.name.as_str().as_bytes().to_vec(),
            read_epoch,
            write_epoch: OWNER_ROOT_EPOCH,
            section,
        }
    }

    /// `SCOPE`'s root staged at the fixture epoch on a plain harness, plus the
    /// cut `rotate_scope` would hand the publisher for it.
    fn staged_cut() -> (
        Harness<InMemoryRecordStore>,
        OwnerRootFixture,
        ResealedScopeRoot,
    ) {
        let root = vault_root(SCOPE, Vec::new());
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        let cut = cut(&root, SCOPE, OWNER_ROOT_EPOCH + 1);
        (harness, root, cut)
    }

    #[test]
    fn a_resealed_root_lands_at_the_new_epoch_carrying_its_new_section() {
        let (harness, root, cut) = staged_cut();

        block_on(harness.net(&[]).publish_scope_root(&cut)).expect("the cut lands");

        let (verified, envelope) = published_head(&harness, &root.name);
        assert_eq!(
            verified.sequence, 2,
            "the CAS sequence advanced past the adopted floor"
        );
        assert_eq!(envelope.epoch, OWNER_ROOT_EPOCH + 1);
        assert_eq!(envelope.scope, SCOPE);
        let section = decode_grant_section(grant_section_bytes(&envelope).expect("the marker"))
            .expect("the section decodes");
        assert_eq!(
            section, cut.section,
            "the record carries the re-sealed section verbatim"
        );
        let node_seed = kdf::node_seed(&FRESH_SEED, &SCOPE);
        let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();
        open_read_body(&envelope, &read_key)
            .expect("the body reopens under the freshly minted override seed");
    }

    /// Rule 8 at the whole-record scale: a cut is published only if this build's
    /// own adoption gate re-adopts it. The cut's read epoch runs ahead of its
    /// write epoch, so every structure signature must be recomputable at the
    /// envelope's read epoch — the one the gate authenticates from.
    #[test]
    fn a_published_cut_re_adopts_through_this_builds_own_gate() {
        let (harness, root, cut) = staged_cut();
        assert_ne!(
            cut.read_epoch, cut.write_epoch,
            "a read rotation is exactly where the two epochs diverge"
        );

        block_on(harness.net(&[]).publish_scope_root(&cut)).expect("the cut lands");

        let regated = block_on(harness.net(&[]).gated_root(SCOPE, &root.name)).map(|_| ());
        assert_eq!(regated, Ok(()), "the cut we signed passes our own gate");
    }

    #[test]
    fn a_section_the_owner_cannot_reopen_is_never_signed() {
        let (harness, root, mut cut) = staged_cut();
        let last = cut.section.owner_blob.ciphertext.len() - 1;
        cut.section.owner_blob.ciphertext[last] ^= 0xff;

        let outcome = block_on(harness.net(&[]).publish_scope_root(&cut));
        assert_eq!(outcome, Err(RotationPublishError::Rejected));
        assert!(
            !outcome.unwrap_err().is_retryable(),
            "these bytes will never open — re-running the sweep cannot help",
        );
        let endpoint = &harness.store.endpoints()[0];
        assert_eq!(
            harness.store.record_at(endpoint, root.name.as_str()),
            Some(record_for(&SCOPE, &root.head_cid_str, 1)),
            "the pre-rotation record still stands — nothing was published",
        );
    }

    #[test]
    fn a_section_minted_for_another_epoch_is_never_signed() {
        let (harness, _root, mut cut) = staged_cut();
        cut.read_epoch = OWNER_ROOT_EPOCH + 2;

        assert_eq!(
            block_on(harness.net(&[]).publish_scope_root(&cut)),
            Err(RotationPublishError::Rejected),
        );
    }

    /// A revoke or scope-exit rotates an **interior** scope root, whose record
    /// carries an ascent link — the caller supplies that root's own ancestor
    /// node seed, and without it the gate cannot read the record to republish.
    #[test]
    fn an_interior_scope_root_rotates_under_its_supplied_ancestor_seed() {
        let root = interior(CHILD_SCOPE, &OWNER_ROOT_SCOPE_SEED, Vec::new());
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        let cut = cut(&root, CHILD_SCOPE, OWNER_ROOT_EPOCH + 1);
        let parent_node_seed = *kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &CHILD_SCOPE).as_bytes();

        assert_eq!(
            block_on(
                harness
                    .net_rooted(RotationAncestry::default())
                    .publish_scope_root(&cut)
            ),
            Err(RotationPublishError::Rejected),
            "no ancestor seed means the gate cannot verify the ascent link",
        );
        block_on(
            harness
                .net_rooted(
                    RotationAncestry::default()
                        .under_parent_node_seed(CHILD_SCOPE, Some(&parent_node_seed)),
                )
                .publish_scope_root(&cut),
        )
        .expect("the interior root's cut lands under its supplied ancestor seed");
    }

    /// The encode-side mirrors of gate stages 2 and 3, and the verdict they
    /// carry: a section this build's own gate would reject is refused before the
    /// record is signed, and fatally — re-authoring the same section reaches the
    /// same refusal, so retrying it would launder a trust violation into an
    /// availability stall (rule 6).
    #[test]
    fn a_section_the_gate_would_reject_is_a_verdict_not_a_stall() {
        for corrupt in [
            |cut: &mut ResealedScopeRoot| cut.section.commitment_sig[0] ^= 0xff,
            |cut: &mut ResealedScopeRoot| cut.section.owner_blob.signature[0] ^= 0xff,
        ] {
            let (harness, root, mut cut) = staged_cut();
            corrupt(&mut cut);

            let outcome = block_on(harness.net(&[]).publish_scope_root(&cut));
            assert_eq!(outcome, Err(RotationPublishError::Rejected));
            assert!(!outcome.unwrap_err().is_retryable());
            let endpoint = &harness.store.endpoints()[0];
            assert_eq!(
                harness.store.record_at(endpoint, root.name.as_str()),
                Some(record_for(&SCOPE, &root.head_cid_str, 1)),
                "the pre-rotation record still stands — nothing was published",
            );
        }
    }

    /// Gate stage 5's encode-side mirror: a plan built from a stale snapshot
    /// would publish a root below the durable revocation floor, which this
    /// build's own gate always rejects.
    #[test]
    fn a_cut_below_the_durable_revocation_floor_is_never_signed() {
        let (harness, _root, cut) = staged_cut();
        block_on(harness.floors.raise_epoch_floor(&SCOPE, cut.read_epoch + 1))
            .expect("raise the revocation floor");

        assert_eq!(
            block_on(harness.net(&[]).publish_scope_root(&cut)),
            Err(RotationPublishError::Rejected),
        );
    }

    /// The gated read the publish runs first advances the durable read-epoch
    /// floor to the record it adopts, so the stage-5 mirror must be measured
    /// against the floor as it stands *after* that read: a cut minted from a
    /// snapshot older than the published root would otherwise be signed below
    /// the floor its own gate then enforces, leaving the root unadoptable.
    #[test]
    fn a_cut_below_the_epoch_the_gated_read_adopts_is_never_signed() {
        let root = vault_root(SCOPE, Vec::new());
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        // Nothing has raised the read-epoch floor yet; the staged root sits at
        // OWNER_ROOT_EPOCH and this cut was minted from a snapshot below it.
        let stale = cut(&root, SCOPE, OWNER_ROOT_EPOCH - 1);

        assert_eq!(
            block_on(harness.net(&[]).publish_scope_root(&stale)),
            Err(RotationPublishError::Rejected),
        );
        let endpoint = &harness.store.endpoints()[0];
        assert_eq!(
            harness.store.record_at(endpoint, root.name.as_str()),
            Some(record_for(&SCOPE, &root.head_cid_str, 1)),
            "the pre-rotation record still stands — nothing was published",
        );
    }

    /// A gate rejection on the record the publish must read first is a
    /// fail-closed trust violation, never a retryable transport failure — a
    /// forged record must not be retried like a flaky endpoint (rule 6).
    #[test]
    fn a_gate_rejected_current_record_is_not_laundered_into_a_retry() {
        let (harness, root, _) = staged_cut();
        // The staged record sits at epoch 1; raising the floor above it makes the
        // gate reject it, while the cut itself still clears the floor.
        let floor = OWNER_ROOT_EPOCH + 4;
        block_on(harness.floors.raise_epoch_floor(&SCOPE, floor)).expect("raise the floor");
        let cut = cut(&root, SCOPE, floor);

        let outcome = block_on(harness.net(&[]).publish_scope_root(&cut));
        assert_eq!(outcome, Err(RotationPublishError::Rejected));
        assert!(
            !outcome.unwrap_err().is_retryable(),
            "a trust rejection is never retryable",
        );
    }

    /// The eager-set walk over the production resolver: two levels of real
    /// records, gated one by one, with completeness proved from published state
    /// alone.
    #[test]
    fn the_eager_set_walk_composes_over_the_production_resolver() {
        // The grandchild's ascent link seals under its own parent's seed —
        // every fixture shares OWNER_ROOT_SCOPE_SEED as its override seed, so
        // the walk's derived ancestry is what has to line up.
        let grandchild = interior([0xd2; 16], &OWNER_ROOT_SCOPE_SEED, Vec::new());
        let grandchild_ref = child_ref([0xd2; 16], &grandchild);
        let child = interior(
            CHILD_SCOPE,
            &OWNER_ROOT_SCOPE_SEED,
            vec![grandchild_ref.clone()],
        );
        let child_ref = child_ref(CHILD_SCOPE, &child);

        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        harness.stage([0xd2; 16], &grandchild, Some(OWNER_ROOT_EPOCH));

        let eager_set = block_on(enumerate_eager_set(
            SCOPE,
            core::slice::from_ref(&child_ref),
            &harness.net(core::slice::from_ref(&child_ref)),
        ))
        .expect("every reachable descendant resolved");
        assert_eq!(
            eager_set.into_descendants(),
            vec![child_ref, grandchild_ref],
            "the closure is both levels, ascending by scope id",
        );
    }

    /// The owner's own vault root, planted in a descendant's child-scope index
    /// by a committed writer of that scope. It is a real owner-signed record
    /// whose node id is its scope id, so every other gate stage passes; only the
    /// ascent-link requirement stops the cascade adopting it as an eager-set
    /// member and re-keying it under this scope's seed.
    #[test]
    fn a_vault_root_planted_in_a_descendants_index_never_enters_the_eager_set() {
        let planted_scope = [0x77; 16];
        let planted = vault_root(planted_scope, Vec::new());
        assert!(
            planted.grant_section.ascent_link.is_none(),
            "a vault root is exactly the record with nothing binding it to a parent",
        );
        let child = interior(
            CHILD_SCOPE,
            &OWNER_ROOT_SCOPE_SEED,
            vec![child_ref(planted_scope, &planted)],
        );
        let child_ref = child_ref(CHILD_SCOPE, &child);

        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        harness.stage(planted_scope, &planted, Some(OWNER_ROOT_EPOCH));

        assert_eq!(
            block_on(enumerate_eager_set(
                SCOPE,
                core::slice::from_ref(&child_ref),
                &harness.net(core::slice::from_ref(&child_ref)),
            ))
            .expect_err("the planted root is refused"),
            EnumerationError {
                scope_id: planted_scope,
                reason: ResolveFailure::Rejected,
            },
        );
    }

    /// A writer naming its own scope in its own index is the shape that would
    /// turn an ancestry-derived ascent rule into a revocation DoS: the entry
    /// makes a root look like its own child. The walk skips it before any
    /// resolve, so the enumeration completes and the rotation still cuts.
    #[test]
    fn a_scope_naming_itself_as_its_own_child_is_skipped_not_fatal() {
        let harness = Harness::plain();
        let root = vault_root(SCOPE, Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        let self_entry = child_ref(SCOPE, &root);

        let eager_set = block_on(enumerate_eager_set(
            SCOPE,
            core::slice::from_ref(&self_entry),
            &harness.net(core::slice::from_ref(&self_entry)),
        ))
        .expect("a self-entry terminates the walk rather than failing it");
        assert!(
            eager_set.into_descendants().is_empty(),
            "the root is not its own descendant",
        );
    }

    /// `rotate_scope` over the production publisher: the cut lands on the record
    /// plane and only then does the durable `minReadEpoch` floor move.
    #[test]
    fn the_root_cut_composes_over_the_production_publisher() {
        let root = vault_root(SCOPE, Vec::new());
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        let pseudonym = Ed25519Signer::from_seed(OWNER_ROOT_PSEUDONYM_SEED);
        let owner_enc_pub = owner_enc().public();
        let mut entropy = SeededEntropy::new(23);

        let outcome = block_on(rotate_scope(
            &mut entropy,
            &harness.floors,
            &harness.world.scheduler,
            &harness.net(&[]),
            &RotateScopePlan {
                identity: ScopeRootIdentity {
                    v: ENVELOPE_V,
                    scope_id: SCOPE,
                    ipns_name: root.name.as_str().as_bytes(),
                    owner_enc_pub: &owner_enc_pub,
                    owner_enc_secret: None,
                    ascent: None,
                    owes_ascent_link: false,
                    pseudonym_signer: &pseudonym,
                },
                committed: CommittedSet {
                    owner_identity: &owner_identity().verifying_key(),
                    commitment: &root.grant_section.commitment,
                    commitment_sig: &root.grant_section.commitment_sig,
                    grant_ledger: &[],
                    direct_child_scope_index: &[],
                },
                current_override_seed: &OWNER_ROOT_SCOPE_SEED,
                current_read_epoch: OWNER_ROOT_EPOCH,
                write_scope_seed: &OWNER_ROOT_WRITE_SCOPE_SEED,
                write_epoch: OWNER_ROOT_EPOCH,
                write_history_link: &[],
                pointer_read_key: &POINTER_READ_KEY,
                carried_history_links: &[],
            },
            || Box::pin(async {}),
        ))
        .expect("the root cut completes");

        assert_eq!(outcome.new_read_epoch, OWNER_ROOT_EPOCH + 1);
        assert_eq!(outcome.epoch_floor, OWNER_ROOT_EPOCH + 1);
        let endpoint = &harness.store.endpoints()[0];
        let published = harness
            .store
            .record_at(endpoint, root.name.as_str())
            .expect("a record at the scope root");
        assert_ne!(
            published,
            record_for(&SCOPE, &root.head_cid_str, 1),
            "the pre-rotation record was replaced by the cut",
        );
    }

    // --- The cascade's re-seal resolver ---

    /// Author a scope root exactly as the owner itself would — section re-sealed
    /// under the pseudonym `OWNER_ROOT_SECRET` derives for this scope, so a
    /// cascade re-key of it stays committed (where [`owner_root_fixture`] signs
    /// under a fixed seed). The read body is an empty folder; `children` is the
    /// direct-child-scope index the walk descends.
    fn owner_scope_root(
        scope_id: [u8; 16],
        override_seed: &[u8; 32],
        read_epoch: u64,
        parent_node_seed: Option<&[u8; 32]>,
        children: &[ChildScopeRef],
    ) -> OwnerRootFixture {
        owner_scope_root_at(
            ENVELOPE_V,
            scope_id,
            override_seed,
            read_epoch,
            parent_node_seed,
            children,
            Vec::new(),
            None,
        )
    }

    /// [`owner_scope_root`] at a chosen envelope version — every AAD in the
    /// record, section included, binds `v`.
    #[allow(clippy::too_many_arguments)]
    fn owner_scope_root_at(
        v: u64,
        scope_id: [u8; 16],
        override_seed: &[u8; 32],
        read_epoch: u64,
        parent_node_seed: Option<&[u8; 32]>,
        children: &[ChildScopeRef],
        body_children: Vec<ChildRef>,
        prev: Option<PrevEpochSeed<'_>>,
    ) -> OwnerRootFixture {
        let write_seed = kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &scope_id);
        let name =
            IpnsName::from_public_key(&kdf::ipns_keypair(write_seed.as_bytes()).verifying_key());
        let pseudonym = kdf::pseudonym_sign(&OWNER_ROOT_SECRET, &scope_id);
        let commitment = GrantSetCommitment {
            ipns_name: name.as_str().as_bytes().to_vec(),
            owner_pseudonym_pk: pseudonym.verifying_key().to_bytes(),
            entries: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let commitment_sig = sign_grant_set(&owner_identity(), &commitment)
            .expect("sign the commitment")
            .to_compact();
        let owner_enc_pub = owner_enc().public();
        let pointer_read_key = *kdf::pointer_read_key(&OWNER_POINTER_SEED, &scope_id).as_bytes();
        let mut entropy = SeededEntropy::new(31);
        let section = reseal_scope_root(
            &mut entropy,
            &ScopeRootIdentity {
                v,
                scope_id,
                ipns_name: name.as_str().as_bytes(),
                owner_enc_pub: &owner_enc_pub,
                owner_enc_secret: None,
                ascent: parent_node_seed.map(AscentAuthority::ParentSeed),
                owes_ascent_link: parent_node_seed.is_some(),
                pseudonym_signer: &pseudonym,
            },
            &ResealSeeds {
                override_seed,
                read_epoch,
                prev,
                write_scope_seed: &OWNER_ROOT_WRITE_SCOPE_SEED,
                write_epoch: OWNER_ROOT_EPOCH,
                write_history: WriteHistory::Carried(&[]),
                pointer_read_key: &pointer_read_key,
            },
            &CommittedSet {
                owner_identity: &owner_identity().verifying_key(),
                commitment: &commitment,
                commitment_sig: &commitment_sig,
                grant_ledger: &[],
                direct_child_scope_index: children,
            },
            &[],
        )
        .expect("re-seal the scope root");

        let node_seed = kdf::node_seed(override_seed, &scope_id);
        let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();
        let body = ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: body_children,
            unknown: PreservedFields::new(),
        };
        // Authored through the seal primitives rather than
        // `author_scope_root_with_section`, which pins `ENVELOPE_V`.
        let mut envelope = seal_read_body(
            &read_key,
            &[0x3c; 24],
            v,
            scope_id,
            scope_id,
            read_epoch,
            &body,
        )
        .expect("seal the read body");
        set_grant_section(
            &mut envelope,
            encode_grant_section(&section).expect("encode the section"),
        );
        let head_block = encode_envelope(&envelope).expect("encode the envelope");

        OwnerRootFixture {
            head_cid_str: root_block_cid(&head_block),
            name,
            grant_section: section,
            envelope,
            head_block,
        }
    }

    /// A vault root naming one interior descendant — the shape a read revoke
    /// cascades over.
    fn owner_tree() -> (OwnerRootFixture, OwnerRootFixture, ChildScopeRef) {
        let child_parent_seed = *kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &CHILD_SCOPE).as_bytes();
        let child = owner_scope_root(
            CHILD_SCOPE,
            &OWNER_ROOT_SCOPE_SEED,
            OWNER_ROOT_EPOCH,
            Some(&child_parent_seed),
            &[],
        );
        let child_ref = child_ref(CHILD_SCOPE, &child);
        let root = owner_scope_root(
            SCOPE,
            &OWNER_ROOT_SCOPE_SEED,
            OWNER_ROOT_EPOCH,
            None,
            core::slice::from_ref(&child_ref),
        );
        (root, child, child_ref)
    }

    /// The vault root carries no ascent link, so the descendant edge refuses
    /// it — nothing proves it a child of anything. Its own edge reads it, which
    /// is what a mint or a rotation anchored at the root needs.
    #[test]
    fn the_vault_root_resolves_only_through_its_own_edge() {
        let root = vault_root(SCOPE, Vec::new());
        let root_ref = child_ref(SCOPE, &root);
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        assert_eq!(
            block_on(harness.net(&[]).resolve(&root_ref)).err(),
            Some(ResolveFailure::Rejected),
            "an ascent link the vault root never carries is not evidence it lacks",
        );

        let target = block_on(harness.net(&[]).resolve_vault_root(&root_ref))
            .expect("the vault root's own re-seal material");
        assert_eq!(target.current_read_epoch, OWNER_ROOT_EPOCH);
        assert!(
            ct_eq(&target.override_seed, &OWNER_ROOT_SCOPE_SEED),
            "the seed comes from the gated record's own owner blob",
        );
        assert!(ct_eq(
            &target.write_scope_seed,
            &OWNER_ROOT_WRITE_SCOPE_SEED
        ));
    }

    /// The root gate binds the scope but not the node id, and every AAD a
    /// re-seal authors binds the id — so a record claiming another node yields
    /// no re-seal material rather than one re-sealed under a key no reader
    /// re-derives. Fail-closed on whichever ladder rung catches it first.
    #[test]
    fn a_vault_root_record_claiming_another_node_yields_no_reseal_material() {
        let planted = owner_root_fixture(OwnerRootSpec {
            owner_identity: &owner_identity(),
            owner_enc: &owner_enc().public(),
            scope_id: SCOPE,
            root_id: CHILD_SCOPE,
            children: Vec::new(),
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants: Vec::new(),
        });
        let harness = Harness::plain();
        harness.stage(SCOPE, &planted, Some(OWNER_ROOT_EPOCH));

        assert!(
            block_on(
                harness
                    .net(&[])
                    .resolve_vault_root(&child_ref(SCOPE, &planted))
            )
            .is_err(),
        );
    }

    #[test]
    fn a_descendants_reseal_material_comes_from_its_own_gated_record() {
        let (_, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));

        let target = block_on(
            harness
                .net(core::slice::from_ref(&child_ref))
                .resolve(&child_ref),
        )
        .expect("the descendant's own re-seal material");

        assert_eq!(target.current_read_epoch, OWNER_ROOT_EPOCH);
        assert_eq!(target.write_epoch, OWNER_ROOT_EPOCH);
        assert!(
            ct_eq(&target.override_seed, &OWNER_ROOT_SCOPE_SEED),
            "the seed comes from the gated record's own owner blob",
        );
        assert!(
            ct_eq(&target.write_scope_seed, &OWNER_ROOT_WRITE_SCOPE_SEED),
            "the write seed comes from the gated record's owner-write-blob",
        );
        assert_eq!(
            target.pseudonym_signer.verifying_key().to_bytes(),
            target.commitment.owner_pseudonym_pk,
            "the owner re-derives the pseudonym the record commits to",
        );
        assert_eq!(
            target.owner_enc_pub.to_bytes(),
            owner_enc().public().to_bytes(),
            "the owner-blob recipient is the owner's own key, not a record field",
        );
        assert!(
            ct_eq(
                &target.pointer_read_key,
                kdf::pointer_read_key(&OWNER_POINTER_SEED, &CHILD_SCOPE).as_bytes()
            ),
            "the pointer read key is owner-derived, never read off the network",
        );
    }

    /// The rotation's gated read is idempotent. Adopting the record raised this
    /// name's sequence floor, so without the equal-floor re-read a second pass
    /// over the unchanged record would reject it — and the scope could never be
    /// re-keyed again.
    #[test]
    fn a_scope_root_this_pass_already_adopted_re_reads_at_the_sequence_floor() {
        let (_, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        let net = harness.net(core::slice::from_ref(&child_ref));

        let first = block_on(net.resolve(&child_ref)).expect("the first read");
        net.gated
            .take(&child.name)
            .expect("the resolve parked its gated read for the publish");

        let again = block_on(net.resolve(&child_ref)).expect("the unchanged record re-reads");
        assert_eq!(again.current_read_epoch, first.current_read_epoch);
        assert!(
            ct_eq(&again.override_seed, &first.override_seed),
            "the re-read recovers the same read seed the adopt did",
        );
        assert!(ct_eq(&again.write_scope_seed, &first.write_scope_seed));
    }

    /// The equal-floor re-read is no way around the ascent link: a reader that
    /// cannot place the descendant under its parent stays rejected even once the
    /// record sits at its own sequence floor. The gate reaches the ascent link
    /// (stage 3) before the sequence floor (stage 4), so the re-read never sees
    /// a `SequenceNotNewer` verdict to recover from.
    #[test]
    fn a_scope_root_at_the_floor_off_the_ancestry_is_still_rejected() {
        let (_, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        let index = vec![child_ref.clone()];

        block_on(harness.net(&index).resolve(&child_ref)).expect("the first read raises the floor");
        assert_eq!(
            block_on(
                harness
                    .net_rooted(RotationAncestry::default())
                    .resolve(&child_ref)
            )
            .err(),
            Some(ResolveFailure::Rejected),
        );
    }

    /// The ancestry seed is what the descendants' **published** ascent links
    /// were sealed under, never the rotating root's post-cut seed — the trap a
    /// retry that reused the plan's own `current_override_seed` would fall into,
    /// which would fail closed at the gate and strand the descendant again.
    #[test]
    fn a_descendant_gated_under_the_post_cut_root_seed_is_rejected() {
        let (_, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        let index = vec![child_ref.clone()];

        assert_eq!(
            block_on(harness.net_under(&[0xab; 32], &index).resolve(&child_ref)).err(),
            Some(ResolveFailure::Rejected),
            "a post-cut root seed derives the wrong ascent authority",
        );
        assert!(
            block_on(
                harness
                    .net_under(&OWNER_ROOT_SCOPE_SEED, &index)
                    .resolve(&child_ref)
            )
            .is_ok(),
            "the seed its published ascent link was sealed under still gates it",
        );
    }

    /// A record strictly **below** the durable sequence floor is a replay, not
    /// our own current record: the equal-floor re-read must not launder it into
    /// a rotatable target.
    #[test]
    fn a_scope_root_below_the_sequence_floor_stays_a_fail_closed_rejection() {
        let (_, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        block_on(floor::advance_sequence_on_unseal(
            &harness.floors,
            child.name.as_str().as_bytes(),
            9,
        ))
        .expect("raise the sequence floor above the staged record");

        assert_eq!(
            block_on(
                harness
                    .net(core::slice::from_ref(&child_ref))
                    .resolve(&child_ref)
            )
            .err(),
            Some(ResolveFailure::Rejected),
        );
    }

    /// The parked read is bound to the name it was gated at, not to the scope:
    /// a scope reached under a second `ipnsName` must re-read rather than
    /// alias onto the first record.
    #[test]
    fn a_parked_read_never_satisfies_a_different_name() {
        let (root, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        let net = harness.net(core::slice::from_ref(&child_ref));

        block_on(net.resolve(&child_ref)).expect("the first read");
        assert!(
            net.gated.take(&root.name).is_none(),
            "another name does not collect this scope's parked read",
        );
        assert!(
            net.gated.take(&child.name).is_some(),
            "the name it was gated at still does",
        );
    }

    #[test]
    fn a_cascade_target_claiming_another_scope_is_a_fail_closed_rejection() {
        let (_, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));

        let mislabelled = ChildScopeRef {
            scope_id: [0x9e; 16],
            ..child_ref.clone()
        };
        assert_eq!(
            block_on(
                harness
                    .net(core::slice::from_ref(&child_ref))
                    .resolve(&mislabelled)
            )
            .err(),
            Some(ResolveFailure::Rejected),
        );
    }

    /// This build authors exactly `ENVELOPE_V`, so a root at another version is
    /// refused at the read — before any structure is re-sealed under an AAD
    /// this build could never rebuild. The record still passes the gate, so the
    /// rejection is this resolver's own, not the gate's.
    #[test]
    fn a_descendant_at_an_unsupported_envelope_version_is_rejected_at_resolve() {
        let parent_node_seed = *kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &CHILD_SCOPE).as_bytes();
        let child = owner_scope_root_at(
            ENVELOPE_V + 1,
            CHILD_SCOPE,
            &OWNER_ROOT_SCOPE_SEED,
            OWNER_ROOT_EPOCH,
            Some(&parent_node_seed),
            &[],
            Vec::new(),
            None,
        );
        let child_ref = child_ref(CHILD_SCOPE, &child);
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        let net = harness.net(core::slice::from_ref(&child_ref));

        assert!(
            block_on(net.gated_root(CHILD_SCOPE, &child.name)).is_ok(),
            "the record itself is gate-passing",
        );
        assert_eq!(
            block_on(net.resolve(&child_ref)).err(),
            Some(ResolveFailure::Rejected),
        );
    }

    #[test]
    fn a_cascade_resolve_of_an_unserved_descendant_is_availability() {
        let (_, _, child_ref) = owner_tree();
        let harness = Harness::plain();
        assert_eq!(
            block_on(
                harness
                    .net(core::slice::from_ref(&child_ref))
                    .resolve(&child_ref)
            )
            .err(),
            Some(ResolveFailure::Unavailable),
        );
    }

    /// One owner-revocation cascade pass over the production resolver and
    /// publisher, rooted at `SCOPE`. The plan re-seals the root the harness
    /// staged, so its committed set and signer come off that fixture rather than
    /// being rebuilt beside it.
    ///
    /// `override_seed` is the root's own current seed the plan re-keys from;
    /// `ascent_seed` is what the descendants' published ascent links were sealed
    /// under. They diverge on a retry after the root's cut already landed — see
    /// [`RotationAncestry::rooted_at`].
    fn cascade_pass<T>(
        harness: &Harness<T>,
        root: &OwnerRootFixture,
        override_seed: &[u8; 32],
        ascent_seed: &[u8; 32],
        read_epoch: u64,
        index: &[ChildScopeRef],
        entropy_seed: u64,
    ) -> Result<CascadeOutcome, CascadeError>
    where
        T: RecordTransport + Clone + 'static,
    {
        let pseudonym = OwnerSeeds.writer_pseudonym(&SCOPE);
        let owner_enc_pub = owner_enc().public();
        let pointer_read_key = OwnerSeeds.pointer_read_key(&SCOPE);
        let mut entropy = SeededEntropy::new(entropy_seed);
        let net = harness.net_under(ascent_seed, index);
        block_on(cascade_rotate_scope(
            &mut entropy,
            &harness.floors,
            &harness.world.scheduler,
            &net,
            &net,
            &RotateScopePlan {
                identity: ScopeRootIdentity {
                    v: ENVELOPE_V,
                    scope_id: SCOPE,
                    ipns_name: root.name.as_str().as_bytes(),
                    owner_enc_pub: &owner_enc_pub,
                    owner_enc_secret: None,
                    ascent: None,
                    owes_ascent_link: false,
                    pseudonym_signer: &pseudonym,
                },
                committed: CommittedSet {
                    owner_identity: &owner_identity().verifying_key(),
                    commitment: &root.grant_section.commitment,
                    commitment_sig: &root.grant_section.commitment_sig,
                    grant_ledger: &[],
                    direct_child_scope_index: index,
                },
                current_override_seed: override_seed,
                current_read_epoch: read_epoch,
                write_scope_seed: &OWNER_ROOT_WRITE_SCOPE_SEED,
                write_epoch: OWNER_ROOT_EPOCH,
                write_history_link: &[],
                pointer_read_key: &pointer_read_key,
                carried_history_links: &[],
            },
            || Box::pin(async {}),
        ))
    }

    /// The whole owner-revocation cascade over the production resolver and
    /// publisher: both levels re-keyed with **fresh** seeds, and the descendant's
    /// ascent link re-sealed under the root's newly minted derivation — the
    /// top-down thread that actually locks a revoked reader out.
    #[test]
    fn the_cascade_composes_over_the_production_resolver_and_publisher() {
        let (root, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        let index = vec![child_ref];

        let outcome = cascade_pass(
            &harness,
            &root,
            &OWNER_ROOT_SCOPE_SEED,
            &OWNER_ROOT_SCOPE_SEED,
            OWNER_ROOT_EPOCH,
            &index,
            41,
        )
        .expect("the cascade completes");

        assert_eq!(
            outcome
                .rekeyed
                .iter()
                .map(|scope| (scope.scope_id, scope.new_read_epoch))
                .collect::<Vec<_>>(),
            vec![
                (SCOPE, OWNER_ROOT_EPOCH + 1),
                (CHILD_SCOPE, OWNER_ROOT_EPOCH + 1)
            ],
            "root first, then its one descendant, both cut to the next epoch",
        );

        // The published root's own owner blob is the only source of the fresh
        // seed — recovering it here is what a later reader does too.
        let root_fresh = published_override_seed(&harness, &root.name, SCOPE, OWNER_ROOT_EPOCH + 1);
        assert!(
            !ct_eq(&root_fresh, &OWNER_ROOT_SCOPE_SEED),
            "the root was re-keyed to a fresh seed, not walked forward",
        );
        let child_fresh =
            published_override_seed(&harness, &child.name, CHILD_SCOPE, OWNER_ROOT_EPOCH + 1);
        assert!(
            !ct_eq(&child_fresh, &OWNER_ROOT_SCOPE_SEED),
            "the descendant was re-keyed too — the eager set, not a floor raise",
        );

        let published = published_section(&harness, &child.name);
        let ascent = published
            .ascent_link
            .expect("an interior root's ascent link");
        let link = AscentLink {
            ascent_public: ascent.ascent_public,
            enc: ascent.enc,
            ciphertext: ascent.ciphertext,
            unknown: PreservedFields::new(),
        };
        let ctx = AadContext {
            v: ENVELOPE_V,
            id: CHILD_SCOPE,
            scope: CHILD_SCOPE,
            epoch: OWNER_ROOT_EPOCH + 1,
            struct_tag: STRUCT_TAG_ASCENT_LINK,
        };
        let fresh_parent_seed = *kdf::node_seed(&root_fresh, &CHILD_SCOPE).as_bytes();
        assert!(
            open_ascent_link(&fresh_parent_seed, &ctx, &link).is_ok(),
            "the descendant's ascent link re-sealed under the root's new seed",
        );
        let stale_parent_seed = *kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &CHILD_SCOPE).as_bytes();
        assert!(
            open_ascent_link(&stale_parent_seed, &ctx, &link).is_err(),
            "the pre-cascade derivation no longer opens it — the revocation",
        );
    }

    /// The cascade's own retry contract, end to end: a descendant whose publish
    /// never lands leaves it resolved-but-unpublished, and the retry has to read
    /// it again. Without the equal-floor re-read the second pass rejected the
    /// unchanged record — a retryable abort that could never succeed, leaving
    /// the revoked reader in that subtree for good.
    #[test]
    fn a_cascade_that_aborts_after_resolving_a_descendant_completes_on_retry() {
        let (root, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.store.fail_put_for(child.name.as_str());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        let index = vec![child_ref];

        let aborted = cascade_pass(
            &harness,
            &root,
            &OWNER_ROOT_SCOPE_SEED,
            &OWNER_ROOT_SCOPE_SEED,
            OWNER_ROOT_EPOCH,
            &index,
            41,
        )
        .expect_err("the descendant's record never lands");
        assert_eq!(aborted.scope_id(), CHILD_SCOPE);
        assert!(
            aborted.is_retryable(),
            "a PUT no endpoint took is availability, not a trust verdict",
        );

        // The retry rebuilds the plan from current state, as the module contract
        // requires: the root already advanced to its own fresh seed and epoch.
        // The ancestry stays on the PRE-cut seed — the descendant never
        // republished, so its ascent link still carries that derivation.
        harness.store.heal_put_for(child.name.as_str());
        let root_fresh = published_override_seed(&harness, &root.name, SCOPE, OWNER_ROOT_EPOCH + 1);
        let outcome = cascade_pass(
            &harness,
            &root,
            &root_fresh,
            &OWNER_ROOT_SCOPE_SEED,
            OWNER_ROOT_EPOCH + 1,
            &index,
            43,
        )
        .expect("the retry completes");

        assert_eq!(outcome.descendant_count(), 1);
        let child_fresh =
            published_override_seed(&harness, &child.name, CHILD_SCOPE, OWNER_ROOT_EPOCH + 1);
        assert!(
            !ct_eq(&child_fresh, &OWNER_ROOT_SCOPE_SEED),
            "the descendant was re-keyed on the retry, not left on its cached seed",
        );
    }

    /// Enumerating the eager set adopts every descendant record and publishes
    /// none of them, so the cascade that follows re-reads each at its own
    /// sequence floor.
    #[test]
    fn a_cascade_after_an_eager_set_enumeration_still_completes() {
        let (root, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        let index = vec![child_ref];

        block_on(enumerate_eager_set(SCOPE, &index, &harness.net(&index)))
            .expect("every reachable descendant resolved");

        let outcome = cascade_pass(
            &harness,
            &root,
            &OWNER_ROOT_SCOPE_SEED,
            &OWNER_ROOT_SCOPE_SEED,
            OWNER_ROOT_EPOCH,
            &index,
            41,
        )
        .expect("the cascade still completes over already-adopted descendants");
        assert_eq!(outcome.descendant_count(), 1);
    }

    /// The verified record now standing at `name` and the head envelope it
    /// points at, read back off the same planes a resolver would.
    fn published_head<T: RecordTransport + Clone>(
        harness: &Harness<T>,
        name: &IpnsName,
    ) -> (VerifiedRecord, Envelope) {
        let endpoint = &harness.store.endpoints()[0];
        let record = harness
            .store
            .record_at(endpoint, name.as_str())
            .expect("a record at the scope root");
        let verified = IpnsRecord::unmarshal(&record)
            .and_then(|record| record.verify(name))
            .expect("the published record verifies under its own name");
        let value = String::from_utf8(verified.value.clone()).expect("a utf8 record value");
        let block = harness
            .blocks
            .lock()
            .expect("lock")
            .get(value.trim_start_matches("/ipfs/"))
            .cloned()
            .expect("the published head block reached the content plane");
        (verified, decode_envelope(&block).expect("the head decodes"))
    }

    /// The grant section of whatever record now stands at `name`.
    fn published_section<T: RecordTransport + Clone>(
        harness: &Harness<T>,
        name: &IpnsName,
    ) -> GrantSection {
        let (_, envelope) = published_head(harness, name);
        decode_grant_section(grant_section_bytes(&envelope).expect("the marker"))
            .expect("the section decodes")
    }

    /// The override seed the record now standing at `name` wraps to the owner.
    fn published_override_seed<T: RecordTransport + Clone>(
        harness: &Harness<T>,
        name: &IpnsName,
        scope_id: [u8; 16],
        epoch: u64,
    ) -> [u8; 32] {
        let section = published_section(harness, name);
        let ctx = AadContext {
            v: ENVELOPE_V,
            id: scope_id,
            scope: scope_id,
            epoch,
            struct_tag: STRUCT_TAG_OWNER_BLOB,
        };
        *open_owner_blob(
            &owner_enc(),
            &section.owner_blob.enc,
            &ctx,
            &section.owner_blob.ciphertext,
        )
        .expect("the owner blob reopens")
        .override_seed()
    }

    #[test]
    fn a_concurrent_writer_at_a_higher_sequence_is_a_retryable_lost_race() {
        let root = vault_root(SCOPE, Vec::new());
        let winner = record_for(&SCOPE, &root.head_cid_str, 9);
        let harness = Harness::racing(root.name.as_str(), winner);
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        let cut = cut(&root, SCOPE, OWNER_ROOT_EPOCH + 1);

        assert_eq!(
            block_on(harness.net(&[]).publish_scope_root(&cut)),
            Err(RotationPublishError::LostRace),
            "a lost CAS race is reported, never a silent drop",
        );
    }

    // --- The grantee arm: the flat scope-exit cut --------------------------

    /// The granted scope this device holds a write grant in — an **interior**
    /// scope root, so its record carries the ascent link a grantee can only
    /// re-seal to its published public half.
    const GRANTEE_SCOPE: [u8; 16] = [0x9c; 16];
    /// A device holding no grant in `GRANTEE_SCOPE` at all.
    const OUTSIDER_ENC_SCALAR: [u8; 32] = [0xa3; 32];

    fn grantee_enc() -> X25519Secret {
        X25519Secret::from_scalar([0xa1; 32])
    }

    /// The row the owner mints for this device at the granted root's own name —
    /// the tag it self-locates under and the pseudonym its re-seal signs with.
    fn grantee_row(name: &IpnsName, permission: Permission) -> GrantRow {
        let identity = EcdsaSigner::from_scalar(&[0xa2; 32]).expect("valid scalar");
        mint_grant_row(
            &owner_identity(),
            &owner_enc(),
            identity.verifying_key().to_sec1(),
            &grantee_enc().public(),
            &GRANTEE_SCOPE,
            name.as_str().as_bytes(),
            permission,
        )
        .expect("a contributory recipient key")
    }

    /// The ancestor seed the granted scope root's ascent link derives from.
    fn grantee_parent_node_seed() -> [u8; 32] {
        *kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &GRANTEE_SCOPE).as_bytes()
    }

    /// A staged, gate-passing granted scope root committing `grants` and naming
    /// `child_scope_index` as its descendant scope roots.
    fn granted_scope_root_with(
        grants: Vec<GrantRow>,
        child_scope_index: Vec<ChildScopeRef>,
    ) -> OwnerRootFixture {
        owner_root_fixture(OwnerRootSpec {
            owner_identity: &owner_identity(),
            owner_enc: &owner_enc().public(),
            scope_id: GRANTEE_SCOPE,
            root_id: GRANTEE_SCOPE,
            children: Vec::new(),
            child_scope_index,
            parent_node_seed: Some(grantee_parent_node_seed()),
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants,
        })
    }

    fn granted_scope_root(
        permission: Permission,
        child_scope_index: Vec<ChildScopeRef>,
    ) -> OwnerRootFixture {
        let name = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &GRANTEE_SCOPE);
        granted_scope_root_with(vec![grantee_row(&name, permission)], child_scope_index)
    }

    type GranteeNet<'a, T> = GranteeRotationNet<
        'a,
        T,
        ScriptedHttp,
        InMemoryCredentialStore,
        InMemoryFloorStore,
        VirtualScheduler,
        SeededEntropy,
    >;

    /// A staged granted scope root plus everything a grantee net borrows, owned
    /// together so one call sets a case up.
    struct GranteeWorld<T> {
        harness: Harness<T>,
        root: OwnerRootFixture,
        granted: Vec<GrantedScopeRoot>,
        enc_secret: X25519Secret,
        owner_enc_pub: X25519Public,
        /// The sweep `rotate_scope` enqueues; these cases assert the cut, not
        /// the lazy wave it hands the scheduler.
        sweep: Box<dyn Fn([u8; 16]) -> BoxedTask>,
    }

    impl<T: RecordTransport + Clone + 'static> GranteeWorld<T> {
        fn staged(harness: Harness<T>, root: OwnerRootFixture) -> Self {
            harness.stage(GRANTEE_SCOPE, &root, Some(OWNER_ROOT_EPOCH));
            Self {
                granted: vec![GrantedScopeRoot {
                    scope_id: GRANTEE_SCOPE,
                    ipns_name: root.name.clone(),
                }],
                harness,
                root,
                enc_secret: grantee_enc(),
                owner_enc_pub: owner_enc().public(),
                sweep: Box::new(|_| Box::pin(async {})),
            }
        }

        fn net(&self) -> GranteeNet<'_, T> {
            GranteeRotationNet {
                transport: &self.harness.transport,
                api: &self.harness.api,
                gateway: &self.harness.gateway,
                http: &self.harness.http,
                floors: &self.harness.floors,
                scheduler: &self.harness.world.scheduler,
                profile: &self.harness.profile,
                entropy: &self.harness.entropy,
                keys: GranteeRotationKeys {
                    enc_secret: &self.enc_secret,
                    owner_enc_pub: &self.owner_enc_pub,
                    owner_identity: &self.harness.identity,
                },
                granted: &self.granted,
                sweep: self.sweep.as_ref(),
                gated: GatedRoots::default(),
            }
        }

        fn cut(&self) -> Result<RotationOutcome, RotateError> {
            block_on(self.net().rotate_on_scope_exit(NodeId(GRANTEE_SCOPE)))
        }
    }

    /// Republish `root`'s record carrying `section` instead of its own, at the
    /// next sequence — what anyone holding the scope's write seed can put on the
    /// wire, since no structure signature covers the ascent link's public half
    /// or its presence.
    fn republish_section<T: RecordTransport + Clone>(
        harness: &Harness<T>,
        root: &OwnerRootFixture,
        scope_id: [u8; 16],
        section: GrantSection,
    ) {
        let mut envelope = root.envelope.clone();
        set_grant_section(
            &mut envelope,
            encode_grant_section(&section).expect("the section encodes"),
        );
        let block = encode_envelope(&envelope).expect("the envelope encodes");
        let cid = root_block_cid(&block);
        harness
            .blocks
            .lock()
            .expect("lock")
            .insert(cid.clone(), block);
        let record = record_for(&scope_id, &cid, 2);
        for endpoint in harness.store.endpoints() {
            harness
                .store
                .seed_record(&endpoint, root.name.as_str(), record.clone());
        }
    }

    /// Republish `root` with `ledger` in its write body, re-sealed under the
    /// scope write seed and re-signed under the pseudonym the commitment names —
    /// what a committed co-writer can put on the wire, since the commitment binds
    /// `(tag, permission)` and never `recipientEncPk`.
    fn republish_ledger<T: RecordTransport + Clone>(
        harness: &Harness<T>,
        root: &OwnerRootFixture,
        scope_id: [u8; 16],
        ledger: Vec<GrantLedgerEntry>,
    ) {
        let write_seed = kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &scope_id);
        let write_key = kdf::write_key(write_seed.as_bytes());
        let ctx = AadContext {
            v: ENVELOPE_V,
            id: scope_id,
            scope: scope_id,
            epoch: OWNER_ROOT_EPOCH,
            struct_tag: STRUCT_TAG_WRITE_BODY,
        };
        let body = WriteBody {
            grant_ledger: ledger,
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let sealed = seal(
            write_key.as_bytes(),
            &[0x5a; 24],
            &ctx,
            &encode_write_body(&body).expect("the write body encodes"),
        );
        let input = StructureSigInput::over_ciphertext(
            scope_id,
            OWNER_ROOT_EPOCH,
            STRUCT_TAG_WRITE_BODY,
            None,
            &sealed,
        );
        let mut section = root.grant_section.clone();
        section.write_body = SignedSealed {
            signature: sign_structure(&Ed25519Signer::from_seed(OWNER_ROOT_PSEUDONYM_SEED), &input)
                .to_bytes(),
            sealed,
            unknown: PreservedFields::new(),
        };
        republish_section(harness, root, scope_id, section);
    }

    fn plain_world(permission: Permission) -> GranteeWorld<InMemoryRecordStore> {
        GranteeWorld::staged(Harness::plain(), granted_scope_root(permission, Vec::new()))
    }

    #[test]
    fn a_grantee_cut_lands_and_re_adopts_through_this_builds_own_gate() {
        let world = plain_world(Permission::Write);

        let outcome = world
            .cut()
            .expect("the flat cut completes over the production seams");

        assert_eq!(outcome.new_read_epoch, OWNER_ROOT_EPOCH + 1);
        assert_eq!(outcome.epoch_floor, OWNER_ROOT_EPOCH + 1);
        let (_, envelope) = published_head(&world.harness, &world.root.name);
        assert_eq!(
            envelope.epoch,
            OWNER_ROOT_EPOCH + 1,
            "the record standing at the name is the cut"
        );
        assert_eq!(
            block_on(world.net().gated_root(&world.granted[0])).map(|_| ()),
            Ok(()),
            "the cut this grantee signed passes its own gate on read-back",
        );
    }

    #[test]
    fn a_grantee_cut_re_seals_the_ascent_link_the_owners_descent_still_opens() {
        // A grantee holds no ancestor seed, so it re-seals to the public half the
        // record carries; the owner's descent must recover the FRESH seed from it
        // or the cut orphans the scope from above.
        let world = plain_world(Permission::Write);
        world.cut().expect("the flat cut completes");

        let section = published_section(&world.harness, &world.root.name);
        let link = section
            .ascent_link
            .expect("an interior root keeps its ascent link");
        let ctx = AadContext {
            v: ENVELOPE_V,
            id: GRANTEE_SCOPE,
            scope: GRANTEE_SCOPE,
            epoch: OWNER_ROOT_EPOCH + 1,
            struct_tag: STRUCT_TAG_ASCENT_LINK,
        };
        let descended = open_ascent_link(
            &grantee_parent_node_seed(),
            &ctx,
            &AscentLink {
                ascent_public: link.ascent_public,
                enc: link.enc,
                ciphertext: link.ciphertext,
                unknown: PreservedFields::new(),
            },
        )
        .expect("the ancestor's own descent opens the re-sealed link");
        assert!(
            ct_eq(
                descended.override_seed(),
                &published_override_seed(
                    &world.harness,
                    &world.root.name,
                    GRANTEE_SCOPE,
                    OWNER_ROOT_EPOCH + 1,
                ),
            ),
            "the ascent link and the owner blob carry the one seed the cut minted",
        );
    }

    #[test]
    fn a_grantee_cut_is_flat_and_carries_the_committed_set_verbatim() {
        // The eager-set law's grantee arm: the single root republishes and no
        // descendant scope root is re-keyed, over a set the grantee can neither
        // extend nor shrink (#26 D5).
        let harness = Harness::plain();
        let descendant = interior(CHILD_SCOPE, &OWNER_ROOT_SCOPE_SEED, Vec::new());
        harness.stage(CHILD_SCOPE, &descendant, Some(OWNER_ROOT_EPOCH));
        let index = vec![child_ref(CHILD_SCOPE, &descendant)];
        let world = GranteeWorld::staged(
            harness,
            granted_scope_root(Permission::Write, index.clone()),
        );
        let endpoint = &world.harness.store.endpoints()[0];
        let descendant_before = world
            .harness
            .store
            .record_at(endpoint, descendant.name.as_str())
            .expect("the descendant is staged");

        world.cut().expect("the flat cut completes");

        assert_eq!(
            world
                .harness
                .store
                .record_at(endpoint, descendant.name.as_str()),
            Some(descendant_before),
            "no descendant scope root is re-keyed by a grantee rotation",
        );
        let section = published_section(&world.harness, &world.root.name);
        assert_eq!(
            section.commitment, world.root.grant_section.commitment,
            "the owner-signed committed set crosses the rotation byte-identical",
        );
        assert_eq!(
            section.commitment_sig, world.root.grant_section.commitment_sig,
            "and so does the owner signature over it",
        );
        let net = world.net();
        let (_, tag) = net
            .self_location(&world.root.name)
            .expect("a contributory contact key");
        let grant = net
            .open_own_grant(
                &section,
                &tag,
                &grant_blob_aad(GRANTEE_SCOPE, OWNER_ROOT_EPOCH + 1),
            )
            .expect("this device's blob is re-wrapped at the new epoch");
        let body = open_write_body(
            &published_head(&world.harness, &world.root.name).1,
            &section,
            &GRANTEE_SCOPE,
            grant.write_scope_seed().expect("a write grant"),
            OWNER_ROOT_EPOCH,
        )
        .expect("the write body opens under the unchanged write plane");
        assert_eq!(
            body.direct_child_scope_index, index,
            "the descendant scope index is carried forward, not walked",
        );
    }

    #[test]
    fn a_grantee_pass_that_already_adopted_the_root_can_read_it_again() {
        // A rotation reads in order to re-key, so a pass that aborted before
        // publishing must be able to read the unchanged record again — otherwise
        // its own sequence floor locks the cut out for good (`reread_at_floor`).
        let world = plain_world(Permission::Write);
        block_on(world.net().gated_root(&world.granted[0]))
            .expect("the first read adopts and raises the floor");

        assert!(
            world.cut().is_ok(),
            "the cut still completes over the record this net already adopted",
        );
    }

    #[test]
    fn a_device_holding_no_grant_blob_cannot_assemble_a_plan() {
        // The absence of a blob at our tag in a fresh owner-signed record is the
        // definitive revocation signal, so it is a trust verdict and never a
        // retryable stall (AGENTS.md rule 6).
        let mut world = plain_world(Permission::Write);
        world.enc_secret = X25519Secret::from_scalar(OUTSIDER_ENC_SCALAR);

        assert_eq!(
            world.cut(),
            Err(RotateError::Resolve(ResolveFailure::Rejected)),
        );
    }

    #[test]
    fn a_blob_under_a_tag_the_commitment_does_not_commit_is_refused() {
        // Any committed writer can mint a blob at a revoked reader's tag; only
        // the owner-signed commitment says who holds a grant (CONTEXT.md
        // "Grant blob").
        let name = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &GRANTEE_SCOPE);
        let mut row = grantee_row(&name, Permission::Write);
        // The blob and the ledger row stay; the owner's commitment drops the tag,
        // exactly as a revoke leaves it before the writer re-plants the blob.
        row.commitment_entry = GrantSetEntry::new([0xee; 32], Permission::Write, [0u8; 32]);
        let world = GranteeWorld::staged(
            Harness::plain(),
            granted_scope_root_with(vec![row], Vec::new()),
        );

        assert_eq!(
            block_on(world.net().gated_root(&world.granted[0])).map(|_| ()),
            Err(RootGateVerdict::Rejected),
            "the gated read refuses it, so no reader trusts the grant either",
        );
        assert_eq!(
            world.cut(),
            Err(RotateError::Resolve(ResolveFailure::Rejected)),
        );
    }

    #[test]
    fn a_trigger_naming_an_unheld_scope_is_refused_before_any_read() {
        let mut world = plain_world(Permission::Write);
        world.granted.clear();

        assert_eq!(
            world.cut(),
            Err(RotateError::Resolve(ResolveFailure::Rejected)),
        );
    }

    #[test]
    fn a_read_only_grantee_cuts_nothing() {
        // A read grant commits no write permission, so it can sign no record at
        // the scope root's name — permanent, never a stall.
        let world = plain_world(Permission::Read);

        assert_eq!(
            world.cut(),
            Err(RotateError::Resolve(ResolveFailure::Rejected)),
        );
    }

    #[test]
    fn a_grantee_cut_refuses_a_root_whose_ascent_link_was_stripped() {
        // The link's *presence* is covered by no structure signature, so anyone
        // holding the write scope seed can drop it. Re-publishing without one
        // would sever the owner's descent for good.
        let world = plain_world(Permission::Write);
        let mut stripped = world.root.grant_section.clone();
        stripped.ascent_link = None;
        republish_section(&world.harness, &world.root, GRANTEE_SCOPE, stripped);

        assert_eq!(
            world.cut(),
            Err(RotateError::Resolve(ResolveFailure::Rejected)),
        );
    }

    #[test]
    fn a_grantee_cut_refuses_a_ledger_row_that_swapped_its_own_recipient_key() {
        // The commitment binds `(tag, permission)` but not `recipientEncPk`, so a
        // co-writer could redirect this device's own next seed to a key it does
        // not hold — while its blob at the current epoch still opens.
        let world = plain_world(Permission::Write);
        let mut row = grantee_row(&world.root.name, Permission::Write).ledger_entry;
        row.recipient_enc_pk = X25519Secret::from_scalar([0x66; 32]).public().to_bytes();
        republish_ledger(&world.harness, &world.root, GRANTEE_SCOPE, vec![row]);

        assert_eq!(
            world.cut(),
            Err(RotateError::Resolve(ResolveFailure::Rejected)),
        );
    }

    #[test]
    fn a_grantee_cut_that_loses_the_cas_race_is_retryable() {
        let root = granted_scope_root(Permission::Write, Vec::new());
        let winner = record_for(&GRANTEE_SCOPE, &root.head_cid_str, 9);
        let world = GranteeWorld::staged(Harness::racing(root.name.as_str(), winner), root);

        let error = world
            .cut()
            .expect_err("the concurrent writer wins the race");
        assert_eq!(
            error,
            RotateError::Publish(RotationPublishError::LostRace),
            "a lost race is reported, never a silent drop",
        );
        assert!(
            matches!(&error, RotateError::Publish(publish) if publish.is_retryable()),
            "and it stays retryable",
        );
    }

    #[test]
    fn a_rotation_publish_refusal_this_pass_authored_is_never_retried() {
        // A mis-echoed CID and an empty head CID are verdicts on what this pass
        // authored, so a retry re-authors them and refuses again. A size refusal
        // is attacker-influenced and stays retryable (rule 6 axis).
        for deterministic in [
            RecordPublishError::HeadCidMismatch {
                expected: "bafy-ours".to_owned(),
                returned: "bafy-theirs".to_owned(),
            },
            RecordPublishError::Publish(PublishError::EmptyHeadCid),
        ] {
            assert_eq!(
                record_publish_verdict(deterministic),
                RotationPublishError::Rejected,
            );
        }
        assert!(
            record_publish_verdict(RecordPublishError::Publish(PublishError::RecordTooLarge {
                size: 1,
                limit: 0,
            }))
            .is_retryable(),
            "a size refusal on an attacker-influenced record stays retryable",
        );
    }

    /// A transport that snapshots the HTTP calls already made the first time a
    /// record reaches the record plane, so a test can prove the name was
    /// registered before anything was published under it.
    #[derive(Clone)]
    struct RegisterWatch {
        inner: InMemoryRecordStore,
        http: ScriptedHttp,
        before_first_put: Arc<Mutex<Option<Vec<String>>>>,
    }

    impl RecordTransport for RegisterWatch {
        fn endpoints(&self) -> Vec<EndpointId> {
            self.inner.endpoints()
        }

        async fn get_record(
            &self,
            endpoint: &EndpointId,
            routing_key: &str,
            max_bytes: usize,
        ) -> SeamResult<Option<Vec<u8>>> {
            self.inner
                .get_record(endpoint, routing_key, max_bytes)
                .await
        }

        async fn put_record(
            &self,
            endpoint: &EndpointId,
            routing_key: &str,
            record: &[u8],
        ) -> SeamResult<()> {
            {
                let mut seen = self.before_first_put.lock().expect("lock");
                if seen.is_none() {
                    *seen = Some(
                        self.http
                            .requests()
                            .into_iter()
                            .map(|request| request.url)
                            .collect(),
                    );
                }
            }
            self.inner.put_record(endpoint, routing_key, record).await
        }
    }

    #[test]
    fn a_grantee_cut_registers_its_name_before_it_publishes_under_it() {
        let watch = Arc::new(Mutex::new(None));
        let harness = Harness::build({
            let watch = Arc::clone(&watch);
            move |inner, http| RegisterWatch {
                inner,
                http,
                before_first_put: watch,
            }
        });
        let world =
            GranteeWorld::staged(harness, granted_scope_root(Permission::Write, Vec::new()));

        world.cut().expect("the flat cut completes");

        let before = watch
            .lock()
            .expect("lock")
            .clone()
            .expect("the cut reached the record plane");
        assert!(
            before.iter().any(|url| url.ends_with("/registry/register")),
            "the name is registered before any record is published under it",
        );
    }

    #[test]
    fn the_owner_and_grantee_arms_cut_the_same_scope_root_the_same_way() {
        // Both arms are legal on this root: the owner holds its owner blob, the
        // grantee holds a write grant in the same committed set. Whoever cuts, the
        // published record must be the same cut.
        let cut_by = |grantee: bool| {
            let world = plain_world(Permission::Write);
            let name = world.root.name.clone();
            if grantee {
                world.cut().expect("the grantee arm cuts");
            } else {
                let harness = &world.harness;
                let pseudonym = Ed25519Signer::from_seed(OWNER_ROOT_PSEUDONYM_SEED);
                let owner_enc_pub = owner_enc().public();
                let parent_node_seed = grantee_parent_node_seed();
                let net = harness.net_rooted(
                    RotationAncestry::default()
                        .under_parent_node_seed(GRANTEE_SCOPE, Some(&parent_node_seed)),
                );
                let mut entropy = SeededEntropy::new(31);
                block_on(rotate_scope(
                    &mut entropy,
                    &harness.floors,
                    &harness.world.scheduler,
                    &net,
                    &RotateScopePlan {
                        identity: ScopeRootIdentity {
                            v: ENVELOPE_V,
                            scope_id: GRANTEE_SCOPE,
                            ipns_name: name.as_str().as_bytes(),
                            owner_enc_pub: &owner_enc_pub,
                            owner_enc_secret: None,
                            ascent: Some(AscentAuthority::ParentSeed(&parent_node_seed)),
                            owes_ascent_link: true,
                            pseudonym_signer: &pseudonym,
                        },
                        committed: CommittedSet {
                            owner_identity: &owner_identity().verifying_key(),
                            commitment: &world.root.grant_section.commitment,
                            commitment_sig: &world.root.grant_section.commitment_sig,
                            grant_ledger: &[grantee_row(&name, Permission::Write).ledger_entry],
                            direct_child_scope_index: &[],
                        },
                        current_override_seed: &OWNER_ROOT_SCOPE_SEED,
                        current_read_epoch: OWNER_ROOT_EPOCH,
                        write_scope_seed: &OWNER_ROOT_WRITE_SCOPE_SEED,
                        write_epoch: OWNER_ROOT_EPOCH,
                        write_history_link: &[],
                        pointer_read_key: &POINTER_READ_KEY,
                        carried_history_links: &[],
                    },
                    || Box::pin(async {}),
                ))
                .expect("the owner arm cuts");
            }
            let (_, envelope) = published_head(&world.harness, &name);
            let section = published_section(&world.harness, &name);
            (
                envelope.epoch,
                section.commitment,
                section.grant_blobs.len(),
            )
        };

        let (owner_epoch, owner_commitment, owner_blobs) = cut_by(false);
        let (grantee_epoch, grantee_commitment, grantee_blobs) = cut_by(true);
        assert_eq!(
            owner_epoch, grantee_epoch,
            "both arms cut to the same epoch"
        );
        assert_eq!(
            owner_commitment, grantee_commitment,
            "neither arm may touch the owner-signed committed set",
        );
        assert_eq!(
            owner_blobs, grantee_blobs,
            "both re-wrap one blob per committed grant",
        );
    }

    // --- The write-plane name wave ([`WriteWaveNet`]) ---

    /// The write scope seed the wave moves TO — every new name derives from it.
    /// Used where a test hands the publisher its own orders; a test that runs
    /// `rotate_scope_write` takes the seed the wave mints
    /// ([`SeededEntropy::first_draw`]).
    const FRESH_WRITE_SCOPE_SEED: [u8; 32] = [0xa5; 32];

    /// The wave's owner arm. `writer_pseudonym` must be the signer the fixture's
    /// commitment names, or the re-seal refuses (`ResealError::SignerNotCommitted`).
    struct WaveSeeds;

    impl OwnerScopeKeys for WaveSeeds {
        fn writer_pseudonym(&self, _scope_id: &[u8; 16]) -> Ed25519Signer {
            Ed25519Signer::from_seed(OWNER_ROOT_PSEUDONYM_SEED)
        }

        fn pointer_read_key(&self, scope_id: &[u8; 16]) -> Zeroizing<[u8; SECRET_LEN]> {
            Zeroizing::new(*kdf::pointer_read_key(&OWNER_POINTER_SEED, scope_id).as_bytes())
        }
    }

    type Wave<'a, T> = WriteWaveNet<
        'a,
        T,
        ScriptedHttp,
        InMemoryCredentialStore,
        InMemoryFloorStore,
        VirtualScheduler,
        SeededEntropy,
    >;

    /// A stand-in authorized set for a wave whose test republishes no root: only
    /// the root re-seal reads it, and it matches no record, so a test that grows
    /// a root publish fails loudly rather than passing on a fabricated plan.
    fn no_root_plan() -> GrantSetCommitment {
        GrantSetCommitment {
            ipns_name: Vec::new(),
            owner_pseudonym_pk: [0u8; 32],
            entries: Vec::new(),
            unknown: PreservedFields::new(),
        }
    }

    fn wave<'a, T: RecordTransport + Clone>(
        harness: &'a Harness<T>,
        owner: &'a EcdsaSigner,
        current_root: &'a IpnsName,
        plan: &'a GrantSetCommitment,
    ) -> Wave<'a, T> {
        WriteWaveNet {
            transport: &harness.transport,
            api: &harness.api,
            gateway: &harness.gateway,
            http: &harness.http,
            floors: &harness.floors,
            scheduler: &harness.world.scheduler,
            profile: &harness.profile,
            entropy: &harness.entropy,
            scope_id: SCOPE,
            read_scope_seed: &OWNER_ROOT_SCOPE_SEED,
            parent_node_seed: None,
            owner,
            owner_enc_secret: &harness.enc_secret,
            scope_keys: &WaveSeeds,
            authorized_commitment: plan,
            gated_root: GatedWaveRoot::default(),
            subtree: WaveSubtree::default(),
            owner_pointer_seed: &OWNER_POINTER_SEED,
            payload_version: 1,
            current_root_name: current_root,
            // The fixtures rotate the vault anchor itself, so the re-point's
            // read-epoch gate is live in these tests.
            session_root_scope_id: SCOPE,
        }
    }

    /// The pre-wave root name: derived from the write scope seed the fixtures
    /// publish under.
    fn old_root_name() -> IpnsName {
        derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE)
    }

    fn folder(children: Vec<ChildRef>) -> ReadBody {
        ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children,
            unknown: PreservedFields::new(),
        }
    }

    fn ref_to(id: [u8; 16], name: &IpnsName) -> ChildRef {
        ChildRef {
            id,
            name: format!("node-{:02x}", id[0]),
            ipns_name: name.as_str().as_bytes().to_vec(),
            kind: NodeKind::Folder,
            link_counter: 1,
            unknown: PreservedFields::new(),
        }
    }

    /// Stage one **interior** node: its read body sealed under the scope's own
    /// per-node read key, the head block served, and the signed record seeded at
    /// its pre-wave write-plane name.
    fn stage_node<T: RecordTransport + Clone>(
        harness: &Harness<T>,
        node_id: [u8; 16],
        body: &ReadBody,
    ) -> IpnsName {
        let node_seed = kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &node_id);
        let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();
        let envelope = seal_read_body(
            &read_key,
            &[19u8; 24],
            ENVELOPE_V,
            node_id,
            SCOPE,
            OWNER_ROOT_EPOCH,
            body,
        )
        .expect("the interior body seals");
        let block = encode_envelope(&envelope).expect("the head encodes");
        let cid = root_block_cid(&block);
        harness
            .blocks
            .lock()
            .expect("lock")
            .insert(cid.clone(), block);
        let name = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &node_id);
        let record = record_for(&node_id, &cid, 1);
        for endpoint in harness.store.endpoints() {
            harness
                .store
                .seed_record(&endpoint, name.as_str(), record.clone());
        }
        name
    }

    /// The order the wave would issue for `node_id`.
    fn order(
        node_id: [u8; 16],
        current_name: &IpnsName,
        child_names: BTreeMap<[u8; 16], IpnsName>,
        is_root: bool,
    ) -> RepublishedNode {
        RepublishedNode {
            node_id,
            current_name: current_name.clone(),
            new_name: derive_write_name(&FRESH_WRITE_SCOPE_SEED, &node_id),
            child_names,
            signer: kdf::ipns_keypair(
                kdf::write_seed(&FRESH_WRITE_SCOPE_SEED, &node_id).as_bytes(),
            ),
            write_scope_seed: is_root.then(|| SecretBytes::new(FRESH_WRITE_SCOPE_SEED)),
            write_epoch: OWNER_ROOT_EPOCH + 1,
            is_root,
        }
    }

    fn one_child(id: [u8; 16], name: &IpnsName) -> BTreeMap<[u8; 16], IpnsName> {
        BTreeMap::from([(id, name.clone())])
    }

    /// The read body a **read-only** holder opens at `name`: it derives per-node
    /// read keys from the scope read seed alone — no write seed, so it can derive
    /// no name and must follow the child refs it is handed.
    fn read_only_open<T: RecordTransport + Clone>(
        harness: &Harness<T>,
        node_id: [u8; 16],
        name: &IpnsName,
    ) -> ReadBody {
        let (_, envelope) = published_head(harness, name);
        assert_eq!(envelope.id, node_id, "the record is the node it claims");
        assert_eq!(
            envelope.epoch, OWNER_ROOT_EPOCH,
            "the read epoch never moves"
        );
        let node_seed = kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &node_id);
        let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();
        open_read_body(&envelope, &read_key).expect("reopens under the unchanged read key")
    }

    fn child_names_of(body: &ReadBody) -> Vec<Vec<u8>> {
        match body {
            ReadBody::Folder { children, .. } => {
                children.iter().map(|c| c.ipns_name.clone()).collect()
            }
            ReadBody::File { .. } => Vec::new(),
        }
    }

    #[test]
    fn a_republished_folder_names_its_children_at_their_new_names() {
        let harness = Harness::plain();
        let leaf_id = [0x0a; 16];
        let leaf_old = stage_node(&harness, leaf_id, &folder(Vec::new()));
        let parent_id = [0x0b; 16];
        let parent_old = stage_node(
            &harness,
            parent_id,
            &folder(vec![ref_to(leaf_id, &leaf_old)]),
        );

        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = wave(&harness, &owner, &current_root, &plan);

        let leaf = order(leaf_id, &leaf_old, BTreeMap::new(), false);
        block_on(net.republish(&leaf)).expect("the leaf republishes");
        let parent = order(
            parent_id,
            &parent_old,
            one_child(leaf_id, &leaf.new_name),
            false,
        );
        block_on(net.republish(&parent)).expect("the parent republishes");

        let body = read_only_open(&harness, parent_id, &parent.new_name);
        assert_eq!(
            child_names_of(&body),
            vec![leaf.new_name.as_str().as_bytes().to_vec()],
            "the parent names its child at the name the wave moved it to"
        );
        assert_ne!(
            child_names_of(&body)[0],
            leaf_old.as_str().as_bytes().to_vec(),
            "no retired name survives in the republished body"
        );
    }

    #[test]
    fn a_read_only_holder_descends_the_whole_subtree_after_the_wave() {
        // Depth greater than one, so a root-only pass cannot satisfy it: a holder
        // with the scope READ seed and no write seed starts at the re-pointed root
        // and must reach every node by following rewritten child refs alone.
        let harness = Harness::plain();
        let leaf_id = [0x0c; 16];
        let leaf_old = stage_node(&harness, leaf_id, &folder(Vec::new()));
        let mid_id = [0x0d; 16];
        let mid_old = stage_node(&harness, mid_id, &folder(vec![ref_to(leaf_id, &leaf_old)]));
        let root = owner_root_fixture(OwnerRootSpec {
            owner_identity: &owner_identity(),
            owner_enc: &owner_enc().public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children: vec![ref_to(mid_id, &mid_old)],
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants: Vec::new(),
        });
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);

        // Child-first, root last — exactly the wave's own order.
        let leaf = order(leaf_id, &leaf_old, BTreeMap::new(), false);
        block_on(net.republish(&leaf)).expect("leaf");
        let mid = order(mid_id, &mid_old, one_child(leaf_id, &leaf.new_name), false);
        block_on(net.republish(&mid)).expect("mid");
        let new_root = order(SCOPE, &root.name, one_child(mid_id, &mid.new_name), true);
        block_on(net.republish(&new_root)).expect("root");

        // The read-only descent: root -> mid -> leaf, by child refs alone.
        let mut name = new_root.new_name.clone();
        let mut node_id = SCOPE;
        for expected in [mid_id, leaf_id] {
            let body = read_only_open(&harness, node_id, &name);
            let refs = child_names_of(&body);
            assert_eq!(refs.len(), 1, "one child at each level");
            name = IpnsName::parse(core::str::from_utf8(&refs[0]).expect("utf8 name"))
                .expect("a canonical child name");
            node_id = expected;
            assert_eq!(
                name,
                derive_write_name(&FRESH_WRITE_SCOPE_SEED, &expected),
                "the ref names the node's post-wave name"
            );
        }
        // The deepest node is reachable and carries no stale ref.
        assert!(child_names_of(&read_only_open(&harness, leaf_id, &name)).is_empty());
    }

    #[test]
    fn a_moved_root_re_signs_its_commitment_over_the_new_name() {
        // The grant-set commitment binds `ipnsName`, so a root that moves without
        // a re-sign is a record this build's own gate rejects at stage 2.
        let harness = Harness::plain();
        let leaf_id = [0x0e; 16];
        let leaf_old = stage_node(&harness, leaf_id, &folder(Vec::new()));
        let root = owner_root_fixture(OwnerRootSpec {
            owner_identity: &owner_identity(),
            owner_enc: &owner_enc().public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children: vec![ref_to(leaf_id, &leaf_old)],
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants: Vec::new(),
        });
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let leaf = order(leaf_id, &leaf_old, BTreeMap::new(), false);
        block_on(net.republish(&leaf)).expect("leaf");
        let moved = order(SCOPE, &root.name, one_child(leaf_id, &leaf.new_name), true);
        block_on(net.republish(&moved)).expect("the root moves");

        let section = published_section(&harness, &moved.new_name);
        assert_eq!(
            section.commitment.ipns_name,
            moved.new_name.as_str().as_bytes(),
            "the commitment names the record's new name"
        );
        assert_ne!(
            section.commitment.ipns_name,
            root.name.as_str().as_bytes(),
            "and no longer the name it moved off"
        );
        let sig = EcdsaSignature::from_compact(&section.commitment_sig).expect("a compact sig");
        verify_grant_set(&owner.verifying_key(), &section.commitment, &sig)
            .expect("the re-signed commitment verifies under the owner identity");
        // The root's section is the only channel that carries `writeScopeSeed`,
        // so the wave must re-mint the write plane under the fresh seed at the
        // advanced write epoch — otherwise every name moves while the published
        // seed still derives the retired ones.
        let owner_write_blob = section
            .owner_write_blob
            .as_ref()
            .expect("the moved root carries an owner-write blob");
        let aad = AadContext {
            v: ENVELOPE_V,
            id: SCOPE,
            scope: SCOPE,
            epoch: OWNER_ROOT_EPOCH + 1,
            struct_tag: STRUCT_TAG_OWNER_WRITE_BLOB,
        };
        let payload = open_owner_write_blob(
            &owner_enc(),
            &owner_write_blob.enc,
            &aad,
            &owner_write_blob.ciphertext,
        )
        .expect("the owner reopens its write blob at the NEW write epoch");
        assert_eq!(
            payload.write_scope_seed(),
            &FRESH_WRITE_SCOPE_SEED,
            "the published seed is the one the wave derived every new name from"
        );
        assert_eq!(payload.write_epoch, OWNER_ROOT_EPOCH + 1);

        // The read plane is untouched: the override seed the owner blob carries
        // is the pre-wave one, at the unchanged read epoch.
        assert_eq!(
            published_override_seed(&harness, &moved.new_name, SCOPE, OWNER_ROOT_EPOCH),
            OWNER_ROOT_SCOPE_SEED,
            "a name wave re-keys no read seed"
        );
    }

    // --- The wave's grant re-mint ---

    /// The deadline the write grant carries, so a re-mint that drops it is
    /// visible.
    const GRANT_DEADLINE: u64 = 1_800_000_000_000;

    fn read_grantee() -> X25519Secret {
        X25519Secret::from_scalar([0x91; 32])
    }

    fn write_grantee() -> X25519Secret {
        X25519Secret::from_scalar([0x92; 32])
    }

    /// The committed grant set the wave fixtures publish: a read grantee and a
    /// deadlined write grantee, minted at the **pre-wave** root name.
    fn granted_rows() -> Vec<GrantRow> {
        let name = old_root_name();
        let mint = |identity_scalar: [u8; 32], enc: &X25519Secret, permission| {
            let identity = EcdsaSigner::from_scalar(&identity_scalar).expect("valid scalar");
            mint_grant_row(
                &owner_identity(),
                &owner_enc(),
                identity.verifying_key().to_sec1(),
                &enc.public(),
                &SCOPE,
                name.as_str().as_bytes(),
                permission,
            )
            .expect("a contributory recipient key")
        };
        let read = mint([0x93; 32], &read_grantee(), Permission::Read);
        let mut write = mint([0x94; 32], &write_grantee(), Permission::Write);
        write.ledger_entry.expires_at = NonZeroU64::new(GRANT_DEADLINE);
        vec![read, write]
    }

    /// A vault root committing [`granted_rows`], with `children` in its folder.
    fn granted_root(children: Vec<ChildRef>) -> OwnerRootFixture {
        granted_root_with(granted_rows(), children)
    }

    fn granted_root_with(grants: Vec<GrantRow>, children: Vec<ChildRef>) -> OwnerRootFixture {
        owner_root_fixture(OwnerRootSpec {
            owner_identity: &owner_identity(),
            owner_enc: &owner_enc().public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children,
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants,
        })
    }

    /// The blob a grantee finds in `section` by re-deriving its own tag from the
    /// name the record asserts — the whole read-side self-location path.
    fn self_located(
        section: &GrantSection,
        grantee: &X25519Secret,
        name: &IpnsName,
    ) -> Option<PublishedGrantBlob> {
        let blobs: Vec<PublishedGrantBlob> = section
            .grant_blobs
            .iter()
            .map(|b| PublishedGrantBlob {
                tag: b.tag,
                enc: b.enc,
                ciphertext: b.ciphertext.clone(),
            })
            .collect();
        let tag = recipient_blinded_tag(grantee, &owner_enc().public(), name.as_str().as_bytes())
            .expect("a contributory sharer key");
        self_locate(&blobs, &tag).cloned()
    }

    fn open_blob(blob: &PublishedGrantBlob, grantee: &X25519Secret) -> GrantBlobPayload {
        let ctx = AadContext {
            v: ENVELOPE_V,
            id: SCOPE,
            scope: SCOPE,
            epoch: OWNER_ROOT_EPOCH,
            struct_tag: STRUCT_TAG_GRANT_BLOB,
        };
        open_grant_blob(grantee, &blob.enc, &ctx, &blob.ciphertext)
            .expect("the grantee opens its own blob")
    }

    #[test]
    fn a_surviving_grantee_self_locates_its_blob_after_the_name_wave() {
        // The blinded tag binds the scope root's `ipnsName` and the wave moves
        // that name, so a section republished under the retired tags reads to
        // every grantee as a definitive revocation (`grants/revocation.rs`).
        let harness = Harness::plain();
        let root = granted_root(Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        assert!(
            self_located(&root.grant_section, &read_grantee(), &root.name).is_some(),
            "the grantee locates its blob before the wave"
        );

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        block_on(net.republish(&moved)).expect("the root moves");

        let section = published_section(&harness, &moved.new_name);
        let blob = self_located(&section, &read_grantee(), &moved.new_name)
            .expect("the grantee locates its blob at the name the record asserts");
        let payload = open_blob(&blob, &read_grantee());
        assert_eq!(payload.read_scope_seed(), &OWNER_ROOT_SCOPE_SEED);
        assert!(
            payload.write_scope_seed().is_none(),
            "a read grant carries no write seed"
        );
        assert!(
            section.commitment.entries.iter().any(|e| e.tag == blob.tag),
            "the owner-signed commitment commits the re-minted tag"
        );
        assert!(
            self_located(&section, &read_grantee(), &root.name).is_none(),
            "no tag bound to the retired name survives the wave"
        );
    }

    #[test]
    fn a_read_and_a_write_grantee_both_survive_a_wave_over_a_deeper_subtree() {
        // Depth greater than one, and both permissions in the ledger: the write
        // grantee must come out of the wave holding the seed that derives the
        // post-wave names, the read grantee holding none.
        let harness = Harness::plain();
        let leaf_id = [0x1c; 16];
        let leaf_old = stage_node(&harness, leaf_id, &folder(Vec::new()));
        let mid_id = [0x1d; 16];
        let mid_old = stage_node(&harness, mid_id, &folder(vec![ref_to(leaf_id, &leaf_old)]));
        let root = granted_root(vec![ref_to(mid_id, &mid_old)]);
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let leaf = order(leaf_id, &leaf_old, BTreeMap::new(), false);
        block_on(net.republish(&leaf)).expect("leaf");
        let mid = order(mid_id, &mid_old, one_child(leaf_id, &leaf.new_name), false);
        block_on(net.republish(&mid)).expect("mid");
        let moved = order(SCOPE, &root.name, one_child(mid_id, &mid.new_name), true);
        block_on(net.republish(&moved)).expect("root");

        let section = published_section(&harness, &moved.new_name);
        let read_blob = self_located(&section, &read_grantee(), &moved.new_name)
            .expect("the read grantee self-locates at the new name");
        assert!(
            open_blob(&read_blob, &read_grantee())
                .write_scope_seed()
                .is_none()
        );
        let write_blob = self_located(&section, &write_grantee(), &moved.new_name)
            .expect("the write grantee self-locates at the new name");
        assert_eq!(
            open_blob(&write_blob, &write_grantee()).write_scope_seed(),
            Some(&FRESH_WRITE_SCOPE_SEED),
            "the write grantee is handed the seed the wave derived every new name from"
        );
        assert_ne!(read_blob.tag, write_blob.tag);
        assert_eq!(
            section.commitment.entries.len(),
            2,
            "the re-minted commitment commits the whole set, no more and no less"
        );
    }

    #[test]
    fn the_re_mint_carries_each_grants_deadline_forward() {
        let harness = Harness::plain();
        let root = granted_root(Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        block_on(net.republish(&moved)).expect("the root moves");

        let (_, envelope) = published_head(&harness, &moved.new_name);
        let section = published_section(&harness, &moved.new_name);
        let body = open_write_body(
            &envelope,
            &section,
            &SCOPE,
            &FRESH_WRITE_SCOPE_SEED,
            OWNER_ROOT_EPOCH + 1,
        )
        .expect("the owner reopens the re-minted write body");

        let row = |grantee: &X25519Secret| {
            let tag = recipient_blinded_tag(
                grantee,
                &owner_enc().public(),
                moved.new_name.as_str().as_bytes(),
            )
            .expect("a contributory sharer key");
            body.grant_ledger
                .iter()
                .find(|e| e.tag == tag)
                .expect("the grantee's re-minted ledger row")
                .clone()
        };
        let write_row = row(&write_grantee());
        assert_eq!(
            write_row.expires_at,
            NonZeroU64::new(GRANT_DEADLINE),
            "a deadline dropped by the re-mint silently un-expires the grant"
        );
        assert_eq!(write_row.permission, Permission::Write);
        assert_eq!(
            write_row.recipient_enc_pk,
            write_grantee().public().to_bytes()
        );
        assert_eq!(
            row(&read_grantee()).expires_at,
            None,
            "and a row that never expired stays that way"
        );
    }

    #[test]
    fn the_re_mint_carries_each_grants_preserved_unknown_fields_forward() {
        // The two halves come from different signed structures — the commitment
        // entry from the owner-signed set, the ledger row from the write body —
        // so each is asserted under its own key.
        let field = |key: &str, v: u64| -> PreservedFields {
            [(key.to_string(), Value::Unsigned(v))]
                .into_iter()
                .collect()
        };
        let mut rows = granted_rows();
        rows[0].commitment_entry.unknown = field("zc", 7);
        rows[0].ledger_entry.unknown = field("zl", 9);
        let root = granted_root_with(rows, Vec::new());
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        block_on(net.republish(&moved)).expect("the root moves");

        let (_, envelope) = published_head(&harness, &moved.new_name);
        let section = published_section(&harness, &moved.new_name);
        let body = open_write_body(
            &envelope,
            &section,
            &SCOPE,
            &FRESH_WRITE_SCOPE_SEED,
            OWNER_ROOT_EPOCH + 1,
        )
        .expect("the owner reopens the re-minted write body");

        let tag = recipient_blinded_tag(
            &read_grantee(),
            &owner_enc().public(),
            moved.new_name.as_str().as_bytes(),
        )
        .expect("a contributory sharer key");
        let entry = section
            .commitment
            .entries
            .iter()
            .find(|e| e.tag == tag)
            .expect("the grantee's re-minted commitment entry");
        assert_eq!(
            entry.unknown.get("zc"),
            Some(&Value::Unsigned(7)),
            "a dropped unknown discards what another version committed"
        );
        let row = body
            .grant_ledger
            .iter()
            .find(|e| e.tag == tag)
            .expect("the grantee's re-minted ledger row");
        assert_eq!(
            row.unknown.get("zl"),
            Some(&Value::Unsigned(9)),
            "and the ledger half is carried under no owner signature at all"
        );
    }

    #[test]
    fn the_re_mint_reproduces_the_committed_pseudonym_key() {
        // The pseudonym binds the scope and not the name, so the wave must
        // republish the key the owner already committed: it is what authorizes
        // structure signing.
        let harness = Harness::plain();
        let root = granted_root(Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        block_on(net.republish(&moved)).expect("the root moves");

        let published = published_section(&harness, &moved.new_name);
        let keys = |section: &GrantSection| -> BTreeSet<[u8; 32]> {
            section
                .commitment
                .entries
                .iter()
                .map(|e| e.pseudonym_pk)
                .collect()
        };
        let before = keys(&root.grant_section);
        assert_eq!(before.len(), 2);
        assert_eq!(keys(&published), before);
        assert!(
            published.commitment.entries.is_sorted_by_key(|e| e.tag),
            "the owner signs a tag order, never the one a write-grantee authored"
        );
    }

    #[test]
    fn the_wave_refuses_a_committed_pseudonym_key_the_mint_does_not_reproduce_release_active() {
        // The owner re-signs the entries the re-mint builds, so a committed
        // pseudonym key the pairwise mint does not reproduce would be re-signed
        // into structure-signing authority the owner never derived. The refusal is
        // a runtime `Err`, never a debug_assert. Active in release.
        let harness = Harness::plain();
        let mut rows = granted_rows();
        rows[0].commitment_entry.pseudonym_pk = [0xaa; 32];
        let root = granted_root_with(rows, Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        assert_eq!(
            block_on(net.republish(&moved)),
            Err(WritePublishError::Rejected)
        );
        assert!(!published_at(&harness, &moved.new_name));
    }

    #[test]
    fn a_new_name_the_fresh_write_scope_seed_does_not_derive_is_refused_release_active() {
        // Every re-minted tag binds the new name, and a write grantee derives
        // that name from the published seed — so the two diverging mints a set
        // no grantee can self-locate. The refusal is a runtime `Err`, never a
        // debug_assert. Active in release.
        let harness = Harness::plain();
        let root = granted_root(Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let mut moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        // The name and its record signer still agree; only the seed the section
        // hands out no longer derives them.
        moved.write_scope_seed = Some(SecretBytes::new([0xb7; 32]));
        assert_eq!(
            block_on(net.republish(&moved)),
            Err(WritePublishError::Rejected)
        );
        assert!(!published_at(&harness, &moved.new_name));
    }

    /// The moved root's re-minted ledger, opened under the fresh write seed.
    fn moved_ledger<T: RecordTransport + Clone>(
        harness: &Harness<T>,
        moved: &RepublishedNode,
    ) -> Vec<GrantLedgerEntry> {
        let (_, envelope) = published_head(harness, &moved.new_name);
        let section = published_section(harness, &moved.new_name);
        open_write_body(
            &envelope,
            &section,
            &SCOPE,
            &FRESH_WRITE_SCOPE_SEED,
            OWNER_ROOT_EPOCH + 1,
        )
        .expect("the owner reopens the re-minted write body")
        .grant_ledger
    }

    /// Stage the wave fixture, let a committed writer `edit` the read grantee's
    /// ledger row, and run the wave to completion.
    fn wave_over_an_edited_row(
        harness: &Harness<InMemoryRecordStore>,
        edit: impl FnOnce(&mut GrantLedgerEntry),
    ) -> (OwnerRootFixture, RepublishedNode) {
        let root = granted_root(Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        let mut ledger: Vec<GrantLedgerEntry> = granted_rows()
            .into_iter()
            .map(|row| row.ledger_entry)
            .collect();
        edit(&mut ledger[0]);
        republish_ledger(harness, &root, SCOPE, ledger);

        let owner = owner_identity();
        let net = wave(harness, &owner, &root.name, &root.grant_section.commitment);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        block_on(net.republish(&moved)).expect("the wave lands");
        (root, moved)
    }

    #[test]
    fn a_swapped_recipient_key_costs_its_own_row_and_nothing_else() {
        // A committed write-grantee re-authors the write body with a victim's
        // `recipientEncPk` replaced by a key of its own, under the victim's
        // owner-committed tag. Neither owner authority covers the result — the
        // key derives no committed tag and the row's owner signature no longer
        // verifies — so there is nothing honest to re-mint at the moved name.
        //
        // The row is dropped, not refused: the wave IS the write revocation, and
        // refusing would hand the grantee it cuts a veto over its own cut.
        let harness = Harness::plain();
        let survivor = granted_rows()[1].ledger_entry.recipient_identity_pk;
        let (_, moved) = wave_over_an_edited_row(&harness, |row| {
            row.recipient_enc_pk = X25519Secret::from_scalar([0x9f; 32]).public().to_bytes();
        });

        let section = published_section(&harness, &moved.new_name);
        assert_eq!(
            section.commitment.entries.len(),
            1,
            "the unprovable row is not re-minted into the moved set"
        );
        let victim_tag = recipient_blinded_tag(
            &read_grantee(),
            &owner_enc().public(),
            moved.new_name.as_str().as_bytes(),
        )
        .expect("a contributory sharer key");
        assert!(
            section.grant_blobs.iter().all(|b| b.tag != victim_tag),
            "and files no blob for it"
        );
        assert_eq!(
            moved_ledger(&harness, &moved)
                .iter()
                .map(|e| e.recipient_identity_pk)
                .collect::<Vec<_>>(),
            vec![survivor],
            "the surviving grantee crosses the wave intact"
        );
    }

    #[test]
    fn a_row_the_owner_can_still_prove_keeps_its_grant_release_active() {
        // The cheapest attack on a co-grantee is to corrupt the 64 signature
        // bytes and leave the key alone — no key material needed. The owner
        // re-derives the committed tag from `recipientEncPk` and proves the row
        // honest anyway, so the grant survives and the re-mint restores its
        // attestation. Dropping it here would be an owner-signed revocation of a
        // third party, triggered by one flipped bit. Active in release.
        let harness = Harness::plain();
        let (_, moved) = wave_over_an_edited_row(&harness, |row| row.owner_sig[0] ^= 0xff);

        let section = published_section(&harness, &moved.new_name);
        assert_eq!(section.commitment.entries.len(), 2, "both grants re-minted");
        let victim_tag = recipient_blinded_tag(
            &read_grantee(),
            &owner_enc().public(),
            moved.new_name.as_str().as_bytes(),
        )
        .expect("a contributory sharer key");
        assert!(
            section.grant_blobs.iter().any(|b| b.tag == victim_tag),
            "the victim keeps its blob"
        );
        let row = moved_ledger(&harness, &moved)
            .into_iter()
            .find(|e| e.tag == victim_tag)
            .expect("the victim's re-minted ledger row");
        assert!(
            row_is_owner_attested(
                &owner_identity().verifying_key(),
                &row,
                moved.new_name.as_str().as_bytes()
            ),
            "and the re-mint restores the attestation the writer broke"
        );
        assert_eq!(
            row.recipient_identity_pk, UNATTESTED_IDENTITY_PK,
            "the label goes, though: a corrupted signature and an edited label \
             are the same evidence, so the owner vouches for neither"
        );
    }

    #[test]
    fn an_unattested_recipient_identity_pk_is_never_laundered_release_active() {
        // `recipientIdentityPk` is the one recipient field the committed tag does
        // not prove, and the re-mint owner-signs whatever label it is handed. A
        // writer that sets it keeps the victim's grant — the key still derives
        // the committed tag — but must not get its own bytes into an owner
        // signature. Active in release.
        let harness = Harness::plain();
        let (_, moved) = wave_over_an_edited_row(&harness, |row| {
            row.recipient_identity_pk = [0xff; IDENTITY_PUBLIC_LEN];
        });

        let victim_tag = recipient_blinded_tag(
            &read_grantee(),
            &owner_enc().public(),
            moved.new_name.as_str().as_bytes(),
        )
        .expect("a contributory sharer key");
        let row = moved_ledger(&harness, &moved)
            .into_iter()
            .find(|e| e.tag == victim_tag)
            .expect("the victim keeps its re-minted ledger row");
        assert_eq!(
            row.recipient_identity_pk, UNATTESTED_IDENTITY_PK,
            "the writer's label is dropped, not signed"
        );
    }

    #[test]
    fn the_wave_refuses_an_attested_key_core_will_not_adopt_release_active() {
        // A cofactor twin and the key with bit 255 set both re-derive the
        // victim's own tag, so the re-mint's tag comparison cannot separate them
        // from the honest key — only core's adoption gate does. Reachable only
        // *under* the owner's own signature, since a planted row detaches its
        // attestation and is dropped first. Re-minting one would move the name
        // and file a row whose grant blob the victim can never open. The refusal
        // is a runtime `Err`, never a debug_assert. Active in release.
        let victim = read_grantee().public();
        let mut high_bit = victim.to_bytes();
        high_bit[31] |= 0x80;

        let unadoptable = cipherbox_core::suite::x25519::cofactor_twins(&victim)
            .into_iter()
            .chain([high_bit]);
        for enc_pk in unadoptable {
            let harness = Harness::plain();
            let root = granted_root(Vec::new());
            harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
            let mut ledger: Vec<GrantLedgerEntry> = granted_rows()
                .into_iter()
                .map(|row| row.ledger_entry)
                .collect();
            ledger[0].recipient_enc_pk = enc_pk;
            ledger[0].owner_sig = sign_recipient_binding(
                &owner_identity(),
                root.name.as_str().as_bytes(),
                &ledger[0],
            )
            .expect("the owner attests the row")
            .to_compact();
            republish_ledger(&harness, &root, SCOPE, ledger);

            let owner = owner_identity();
            let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
            let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
            assert_eq!(
                block_on(net.republish(&moved)),
                Err(WritePublishError::Rejected)
            );
            assert!(!published_at(&harness, &moved.new_name));
        }
    }

    #[test]
    fn the_wave_refuses_a_ledger_row_the_commitment_does_not_commit_release_active() {
        // A committed read-grantee re-authoring the write body upgrades its own
        // row to write. Re-minting off that ledger would put the upgrade in the
        // commitment the owner then signs, and hand it the write scope seed. The
        // refusal is a runtime `Err`, never a debug_assert. Active in release.
        let harness = Harness::plain();
        let mut rows = granted_rows();
        rows[0].ledger_entry.permission = Permission::Write;
        let root = granted_root_with(rows, Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        assert_eq!(
            block_on(net.republish(&moved)),
            Err(WritePublishError::Rejected)
        );
        assert!(!published_at(&harness, &moved.new_name));
    }

    #[test]
    fn the_wave_refuses_a_root_whose_committed_set_diverges_from_the_owner_plan_release_active() {
        // The staged record carries the PRE-REVOKE set, which the owner's plan
        // dropped the write grant from — the replay
        // [`WriteWaveNet::authorized_commitment`] exists to refuse. Release-active.
        let harness = Harness::plain();
        let root = granted_root(Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let revokee = recipient_blinded_tag(
            &write_grantee(),
            &owner_enc().public(),
            root.name.as_str().as_bytes(),
        )
        .expect("a contributory sharer key");
        let mut plan = root.grant_section.commitment.clone();
        plan.entries.retain(|e| e.tag != revokee);
        assert_ne!(
            plan.entries.len(),
            root.grant_section.commitment.entries.len(),
            "the record still carries the write grant this rotation is cutting",
        );

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &plan);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        assert_eq!(
            block_on(net.republish(&moved)),
            Err(WritePublishError::Rejected)
        );
        assert!(
            !published_at(&harness, &moved.new_name),
            "nothing is published, so the revokee never receives a re-minted blob",
        );
    }

    #[test]
    fn a_write_floor_rise_before_the_root_republish_refuses_the_seal() {
        // The enumeration reads the root first and parks it, so the whole
        // child-first wave runs before the root republishes — and a concurrent
        // focus-window tick observing another device's re-point raises the
        // monotonic write floor in between. Both sides of that rise are refused:
        // the one the wave's own epoch still clears, where the parked record has
        // silently been superseded, and the one that would seal the section at or
        // below the live floor, where `open_write_body` could never reopen it.
        let harness = Harness::plain();
        let root = staged_childless_root(&harness);
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        block_on(net.resolve_node(&SCOPE)).expect("the enumeration gates and parks the root");

        let mut ahead = order(SCOPE, &root.name, BTreeMap::new(), true);
        ahead.write_epoch = OWNER_ROOT_EPOCH + 2;
        block_on(floor::advance_write_epoch_on_sight(
            &harness.floors,
            &SCOPE,
            OWNER_ROOT_EPOCH + 1,
        ))
        .expect("the floor rise lands");
        assert_eq!(
            block_on(net.republish(&ahead)),
            Err(WritePublishError::Rejected),
            "a floor above the parked snapshot refuses even at an epoch it clears",
        );
        assert!(!published_at(&harness, &ahead.new_name));

        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        block_on(floor::advance_write_epoch_on_sight(
            &harness.floors,
            &SCOPE,
            moved.write_epoch,
        ))
        .expect("the floor rise lands");
        assert_eq!(
            block_on(net.republish(&moved)),
            Err(WritePublishError::Rejected),
            "the seal is refused against the live floor, not the parked snapshot",
        );
        assert!(!published_at(&harness, &moved.new_name));
    }

    /// A childless scope-root fixture, staged at the fixture epoch.
    fn staged_childless_root(harness: &Harness<InMemoryRecordStore>) -> OwnerRootFixture {
        let root = owner_root_fixture(OwnerRootSpec {
            owner_identity: &owner_identity(),
            owner_enc: &owner_enc().public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children: Vec::new(),
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants: Vec::new(),
        });
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        root
    }

    #[test]
    fn a_read_floor_rise_before_the_republish_refuses_the_record() {
        // The enumeration parks the root while the whole interior subtree runs,
        // so a concurrent read rotation in between leaves the wave's carried
        // epoch below the live floor.
        let harness = Harness::plain();
        let root = staged_childless_root(&harness);
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        block_on(net.resolve_node(&SCOPE)).expect("the enumeration gates and parks the root");

        block_on(
            harness
                .floors
                .raise_epoch_floor(&SCOPE, OWNER_ROOT_EPOCH + 1),
        )
        .expect("the floor rise lands");

        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        assert_eq!(
            block_on(net.republish(&moved)),
            Err(WritePublishError::Rejected),
        );
        assert!(!published_at(&harness, &moved.new_name));
    }

    #[test]
    fn a_republish_at_exactly_the_read_floor_still_lands() {
        // Strictly below, not at — the gated read the wave runs first leaves the
        // floor at exactly the epoch it then carries, so `<=` would stall every
        // ordinary wave.
        let harness = Harness::plain();
        let root = staged_childless_root(&harness);
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        block_on(net.resolve_node(&SCOPE)).expect("the enumeration gates and parks the root");
        assert_eq!(
            block_on(floor::read_epoch_floor(&harness.floors, &SCOPE)),
            Ok(Some(OWNER_ROOT_EPOCH)),
            "the gated read left the floor at exactly the epoch the wave carries",
        );

        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        block_on(net.republish(&moved)).expect("a republish at the floor lands");
        assert!(published_at(&harness, &moved.new_name));
    }

    #[test]
    fn a_failed_root_publish_leaves_the_root_republishable() {
        // A pass that gated the root and then failed to publish retries off the
        // read it already holds — otherwise a wave interrupted between the two
        // re-reads a record whose section a still-committed writer may have
        // replaced in the meantime.
        let harness = Harness::plain();
        let root = staged_childless_root(&harness);
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);

        // A root order the publisher refuses *after* the gated read: no fresh
        // write scope seed means the section cannot be re-minted.
        let mut seedless = order(SCOPE, &root.name, BTreeMap::new(), true);
        seedless.write_scope_seed = None;
        assert_eq!(
            block_on(net.republish(&seedless)),
            Err(WritePublishError::Rejected)
        );

        // The retry succeeds off the held read, where a second gated read would
        // reject as not-newer against the floor the first one advanced.
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        block_on(net.republish(&moved)).expect("the retried root republish");
        assert_eq!(
            published_section(&harness, &moved.new_name)
                .commitment
                .ipns_name,
            moved.new_name.as_str().as_bytes()
        );
    }

    #[test]
    fn a_child_name_the_body_does_not_carry_is_refused_fail_closed() {
        // The subtree enumeration and the published body disagreeing means one of
        // them is wrong; publishing either half strands a subtree behind a name
        // nothing resolves.
        let harness = Harness::plain();
        let node_id = [0x1a; 16];
        let current = stage_node(&harness, node_id, &folder(Vec::new()));
        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = wave(&harness, &owner, &current_root, &plan);

        let stray = derive_write_name(&FRESH_WRITE_SCOPE_SEED, &[0x1b; 16]);
        let bogus = order(node_id, &current, one_child([0x1b; 16], &stray), false);
        assert_eq!(
            block_on(net.republish(&bogus)),
            Err(WritePublishError::Rejected)
        );
    }

    #[test]
    fn the_read_epoch_floor_never_moves_across_a_republish() {
        // Each plane's clock is authored by its own authority (#38 D1): a name wave
        // advances the WRITE epoch, and a same-epoch metadata rewrite must raise no
        // read-epoch floor.
        let harness = Harness::plain();
        let node_id = [0x2a; 16];
        let current = stage_node(&harness, node_id, &folder(Vec::new()));
        let before =
            block_on(floor::read_epoch_floor(&harness.floors, &SCOPE)).expect("floor read");

        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = wave(&harness, &owner, &current_root, &plan);
        block_on(net.republish(&order(node_id, &current, BTreeMap::new(), false)))
            .expect("republish");

        assert_eq!(
            block_on(floor::read_epoch_floor(&harness.floors, &SCOPE)).expect("floor read"),
            before,
            "an interior name-wave republish moves no read-epoch floor"
        );
    }

    #[test]
    fn retire_refuses_a_batch_naming_the_lingering_root() {
        // Retirement is irreversible and the old root serves the tombstone every
        // lagging reader chases, so the guard is release-active, not a debug assert.
        let harness = Harness::plain();
        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = wave(&harness, &owner, &current_root, &plan);
        let interior = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &[0x3a; 16]);
        // Stands in for the enumeration's gated read of the subtree.
        net.subtree.record_read_epoch(OWNER_ROOT_EPOCH);

        assert_eq!(
            block_on(net.retire(&[interior.clone(), current_root.clone()])),
            Err(WritePublishError::Rejected)
        );
        block_on(net.retire(&[interior])).expect("an interior-only batch retires");
    }

    #[test]
    fn a_retire_behind_no_gated_read_is_refused() {
        // The moved copies' read epoch is the whole evidence the retire's floor
        // comparison rests on, and the tombstone cannot be taken back.
        let harness = Harness::plain();
        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = wave(&harness, &owner, &current_root, &plan);
        let interior = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &[0x3a; 16]);

        assert_eq!(
            block_on(net.retire(&[interior])),
            Err(WritePublishError::Rejected),
        );
    }

    #[test]
    fn a_read_floor_rise_before_the_retire_refuses_the_tombstones() {
        // Release-active: retirement is irreversible, and the moved copies the
        // tombstones hand the subtree to sit below the risen floor.
        let harness = Harness::plain();
        let root = staged_childless_root(&harness);
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        block_on(net.resolve_node(&SCOPE)).expect("the enumeration gates the subtree");
        let interior = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &[0x3a; 16]);

        block_on(
            harness
                .floors
                .raise_epoch_floor(&SCOPE, OWNER_ROOT_EPOCH + 1),
        )
        .expect("the floor rise lands");

        assert_eq!(
            block_on(net.retire(&[interior])),
            Err(WritePublishError::Rejected),
        );
    }

    #[test]
    fn a_retire_at_exactly_the_read_floor_still_runs() {
        // Strictly below, not at: the wave's own gated read leaves the floor at
        // the epoch its records carry, so the common case must not self-refuse.
        let harness = Harness::plain();
        let root = staged_childless_root(&harness);
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        block_on(net.resolve_node(&SCOPE)).expect("the enumeration gates the subtree");
        let interior = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &[0x3a; 16]);

        assert_eq!(
            block_on(floor::read_epoch_floor(&harness.floors, &SCOPE)).expect("floor read"),
            Some(OWNER_ROOT_EPOCH),
            "the gated read advanced the floor to the epoch it adopted",
        );
        block_on(net.retire(&[interior])).expect("the retire runs at its own epoch");
    }

    #[test]
    fn a_repoint_below_the_live_read_floor_is_refused_at_the_vault_anchor() {
        // Signing it would publish a re-point this build's own cold seed
        // permanently rejects (`gate/floor.rs`).
        let harness = Harness::plain();
        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = wave(&harness, &owner, &current_root, &plan);
        block_on(harness.floors.raise_epoch_floor(&SCOPE, OWNER_ROOT_EPOCH))
            .expect("the floor rise lands");

        assert_eq!(
            block_on(net.check_repoint_publishable(&anchor_repoint(SCOPE, OWNER_ROOT_EPOCH - 1))),
            Err(WritePublishError::Rejected),
        );
        block_on(net.check_repoint_publishable(&anchor_repoint(SCOPE, OWNER_ROOT_EPOCH)))
            .expect("at the floor is not below it");
    }

    #[test]
    fn a_repoint_below_the_live_write_epoch_floor_is_refused_at_every_scope() {
        // The gate's write-epoch stage is unconditional, so the produce side is
        // too: a shared scope carries no read-epoch comparison and still cannot
        // sign a rolled-back write clock.
        let harness = Harness::plain();
        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = Wave {
            session_root_scope_id: [0xa1; 16],
            ..wave(&harness, &owner, &current_root, &plan)
        };
        block_on(floor::advance_write_epoch_on_sight(
            &harness.floors,
            &SCOPE,
            4,
        ))
        .expect("the write floor rise lands");

        let mut repoint = anchor_repoint(SCOPE, 0);
        repoint.write_epoch = 3;
        assert_eq!(
            block_on(net.check_repoint_publishable(&repoint)),
            Err(WritePublishError::Rejected),
        );
        repoint.write_epoch = 4;
        block_on(net.check_repoint_publishable(&repoint)).expect("at the floor is not below it");
    }

    #[test]
    fn a_shared_scope_repoint_skips_the_read_epoch_comparison() {
        // The narrowing is load-bearing in both directions: comparing here would
        // refuse an honest re-point (`gate/floor.rs`).
        let harness = Harness::plain();
        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = Wave {
            session_root_scope_id: [0xa1; 16],
            ..wave(&harness, &owner, &current_root, &plan)
        };
        block_on(harness.floors.raise_epoch_floor(&SCOPE, OWNER_ROOT_EPOCH))
            .expect("the floor rise lands");

        block_on(net.check_repoint_publishable(&anchor_repoint(SCOPE, OWNER_ROOT_EPOCH - 1)))
            .expect("a shared scope carries no read-epoch comparison");
    }

    /// A re-point of `scope_id` vouching `min_read_epoch`, at the fixture's names.
    fn anchor_repoint(scope_id: [u8; 16], min_read_epoch: u64) -> RepointObject {
        RepointObject {
            scope_id,
            current_root: derive_write_name(&[0x5e; SECRET_LEN], &scope_id),
            write_epoch: 2,
            min_read_epoch,
            prev_root: Some(old_root_name()),
        }
    }

    #[test]
    fn the_canonical_repoint_lands_on_the_scope_pointer_record() {
        let harness = Harness::plain();
        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = wave(&harness, &owner, &current_root, &plan);
        let block = b"a-sealed-repoint-object".to_vec();

        block_on(net.publish_repoint(RepointChannel::ScopePointer, &block))
            .expect("the pointer flips");

        let name = scope_pointer_name(&OWNER_POINTER_SEED, &SCOPE);
        let record = harness
            .store
            .record_at(&harness.store.endpoints()[0], name.as_str())
            .expect("a record at the scope pointer");
        let verified = IpnsRecord::unmarshal(&record)
            .and_then(|record| record.verify(&name))
            .expect("the pointer record verifies under its own name");
        assert_eq!(
            verified.value, block,
            "the pointer's value IS the sealed re-point block, not an /ipfs/ head"
        );
        assert_eq!(verified.sequence, 1, "a first publish embeds sequence 1");

        // A second rotation must clear what is already at the name.
        block_on(net.publish_repoint(RepointChannel::ScopePointer, b"a-second-repoint"))
            .expect("the second flip");
        let record = harness
            .store
            .record_at(&harness.store.endpoints()[0], name.as_str())
            .expect("a record at the scope pointer");
        let verified = IpnsRecord::unmarshal(&record)
            .and_then(|record| record.verify(&name))
            .expect("verifies");
        assert_eq!(verified.sequence, 2);
    }

    #[test]
    fn the_accelerator_channels_report_that_they_did_not_land() {
        // No mailbox re-point payload and no tombstone record shape exist, and this
        // build never signs bytes it cannot decode — so both refuse rather than
        // claiming a delivery the wave would then report as complete.
        let harness = Harness::plain();
        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = wave(&harness, &owner, &current_root, &plan);
        for channel in [RepointChannel::Mailbox, RepointChannel::Tombstone] {
            assert_eq!(
                block_on(net.publish_repoint(channel, b"block")),
                Err(WritePublishError::NotLanded)
            );
        }
    }

    #[test]
    fn is_republished_answers_from_published_state_alone() {
        let harness = Harness::plain();
        let node_id = [0x4a; 16];
        let current = stage_node(&harness, node_id, &folder(Vec::new()));
        let owner = owner_identity();
        let current_root = old_root_name();
        let plan = no_root_plan();
        let net = wave(&harness, &owner, &current_root, &plan);
        let node = order(node_id, &current, BTreeMap::new(), false);

        assert!(!block_on(net.is_republished(&node.new_name)).expect("query"));
        block_on(net.republish(&node)).expect("republish");
        assert!(
            block_on(net.is_republished(&node.new_name)).expect("query"),
            "a resumed wave skips this node off published state, with no in-memory carry"
        );
    }

    #[test]
    fn a_reseal_seam_failure_stays_retryable_and_a_trust_failure_does_not() {
        // One sample per `ResealError` variant. The `match` below is the
        // enforcement: a variant added without a classification here stops this
        // test compiling, so none can be silently omitted from the axis.
        for sample in [
            ResealError::Entropy(EntropyError::new("seam down")),
            ResealError::LedgerDivergesFromCommitment,
            ResealError::SignerNotCommitted,
            ResealError::UnusableRecipientKey,
            ResealError::TagNotBoundToRecipient,
            ResealError::AscentLinkMismatch,
            ResealError::AscentLinkDropped,
            ResealError::AscentLinkNotOwed,
            ResealError::UnusableAscentPublic,
            ResealError::TooManyHistoryLinks,
            ResealError::TooManyCommittedGrants,
            ResealError::HistoryLinkNotDescending,
            ResealError::HistoryLinkNotContiguous,
            ResealError::OwnerKeyRequiredForWriteCut,
            ResealError::WriteBodyTooLarge,
            ResealError::Encode(CodecError::Malformed(Malformed::DepthExceeded {
                offset: 0,
            })),
        ] {
            let (expected, why) = match &sample {
                ResealError::Entropy(_) => (
                    WritePublishError::NotLanded,
                    "the entropy seam being down is availability, not a verdict on the section",
                ),
                ResealError::LedgerDivergesFromCommitment
                | ResealError::SignerNotCommitted
                | ResealError::UnusableRecipientKey
                | ResealError::TagNotBoundToRecipient
                | ResealError::AscentLinkMismatch
                | ResealError::AscentLinkDropped
                | ResealError::AscentLinkNotOwed
                | ResealError::UnusableAscentPublic
                | ResealError::TooManyHistoryLinks
                | ResealError::TooManyCommittedGrants
                | ResealError::HistoryLinkNotDescending
                | ResealError::HistoryLinkNotContiguous
                | ResealError::OwnerKeyRequiredForWriteCut
                | ResealError::WriteBodyTooLarge
                | ResealError::Encode(_) => (
                    WritePublishError::Rejected,
                    "deterministic on inputs the wave already gated; retrying never converges",
                ),
            };
            let check = sample.check();
            assert_eq!(reseal_verdict(sample), expected, "{check}: {why}");
        }
    }

    // --- the subtree enumeration: the wave's read edge ---------------------

    const MID: [u8; 16] = [0x60; 16];
    const LEAF: [u8; 16] = [0x61; 16];

    /// `MID` (naming `LEAF`) and a real descendant scope root, all staged and
    /// gate-passing, under a root carrying `index`.
    struct StagedScope {
        root: OwnerRootFixture,
        mid_name: IpnsName,
        descendant: OwnerRootFixture,
    }

    fn staged_scope_with_index(
        harness: &Harness<InMemoryRecordStore>,
        index: impl FnOnce(&OwnerRootFixture, &IpnsName) -> Vec<ChildScopeRef>,
    ) -> StagedScope {
        staged_scope_with(harness, index, Vec::new())
    }

    /// The same staging, with `write_history_link` planted in the root's write
    /// body — bytes any committed writer can author.
    fn staged_scope_with(
        harness: &Harness<InMemoryRecordStore>,
        index: impl FnOnce(&OwnerRootFixture, &IpnsName) -> Vec<ChildScopeRef>,
        write_history_link: Vec<u8>,
    ) -> StagedScope {
        let leaf_old = stage_node(harness, LEAF, &folder(Vec::new()));
        let mid_name = stage_node(harness, MID, &folder(vec![ref_to(LEAF, &leaf_old)]));
        let descendant = interior(CHILD_SCOPE, &OWNER_ROOT_SCOPE_SEED, Vec::new());
        harness.stage(CHILD_SCOPE, &descendant, Some(OWNER_ROOT_EPOCH));
        let root = staged_root(
            harness,
            vec![
                ref_to(MID, &mid_name),
                ref_to(CHILD_SCOPE, &descendant.name),
            ],
            index(&descendant, &mid_name),
            write_history_link,
        );
        StagedScope {
            root,
            mid_name,
            descendant,
        }
    }

    fn staged_scope(harness: &Harness<InMemoryRecordStore>) -> StagedScope {
        staged_scope_with_index(harness, |descendant, _| {
            vec![child_ref(CHILD_SCOPE, descendant)]
        })
    }

    /// A staged, gate-passing scope root naming `children`, committing
    /// `child_scope_index`, and publishing `write_history_link` in its write body.
    fn staged_root(
        harness: &Harness<InMemoryRecordStore>,
        children: Vec<ChildRef>,
        child_scope_index: Vec<ChildScopeRef>,
        write_history_link: Vec<u8>,
    ) -> OwnerRootFixture {
        let root = owner_root_fixture(OwnerRootSpec {
            owner_identity: &owner_identity(),
            owner_enc: &owner_enc().public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children,
            child_scope_index,
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link,
            grants: Vec::new(),
        });
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        root
    }

    /// Pinned to a known fresh seed so every derived name is computable.
    fn write_plan<'a>(
        root: &'a OwnerRootFixture,
        owner: &'a EcdsaSigner,
    ) -> RotateScopeWritePlan<'a> {
        RotateScopeWritePlan {
            scope_id: SCOPE,
            payload_version: 1,
            owner_pointer_seed: &OWNER_POINTER_SEED,
            commitment: &root.grant_section.commitment,
            commitment_sig: &root.grant_section.commitment_sig,
            owner_identity_signer: owner,
            current_write_epoch: OWNER_ROOT_EPOCH,
            min_read_epoch: OWNER_ROOT_EPOCH,
            current_root_name: &root.name,
        }
    }

    fn published_at<T: RecordTransport + Clone>(harness: &Harness<T>, name: &IpnsName) -> bool {
        harness
            .store
            .record_at(&harness.store.endpoints()[0], name.as_str())
            .is_some()
    }

    #[test]
    fn the_enumeration_descends_gated_records_and_stops_at_a_descendant_scope_root() {
        let harness = Harness::plain();
        let staged = staged_scope(&harness);
        let owner = owner_identity();
        let net = wave(
            &harness,
            &owner,
            &staged.root.name,
            &staged.root.grant_section.commitment,
        );

        let resolved = block_on(net.resolve_node(&SCOPE)).expect("the root resolves");
        assert_eq!(
            resolved,
            WriteScopeNode {
                node_id: SCOPE,
                current_name: staged.root.name.clone(),
                child_node_ids: vec![MID],
            },
            "the wave never descends into the descendant scope root"
        );

        let mid = block_on(net.resolve_node(&MID)).expect("the child resolves");
        assert_eq!(
            mid.current_name, staged.mid_name,
            "at the name its gated parent gave"
        );
        assert_eq!(mid.child_node_ids, vec![LEAF]);
        assert_eq!(
            block_on(net.resolve_node(&LEAF))
                .expect("the leaf resolves")
                .child_node_ids,
            Vec::<[u8; 16]>::new()
        );
    }

    #[test]
    fn a_planted_index_entry_never_exempts_an_ordinary_node_from_the_wave() {
        let harness = Harness::plain();
        let staged = staged_scope_with_index(&harness, |descendant, mid_name| {
            vec![
                child_ref(CHILD_SCOPE, descendant),
                // MID is an ordinary interior folder, named at its real name.
                ChildScopeRef {
                    scope_id: MID,
                    ipns_name: mid_name.as_str().as_bytes().to_vec(),
                    unknown: PreservedFields::new(),
                },
            ]
        });
        let owner = owner_identity();
        let net = wave(
            &harness,
            &owner,
            &staged.root.name,
            &staged.root.grant_section.commitment,
        );

        assert_eq!(
            block_on(net.resolve_node(&SCOPE)),
            Err(ResolveFailure::Rejected),
            "MID's record carries no owner-signed commitment naming it a scope \
             root, so the claimed boundary is refused rather than honoured"
        );
    }

    /// The owner's own vault root, named by the committed child-scope index as if
    /// it were a descendant scope root. Every gate stage passes on it — it is a
    /// real owner-signed record whose node id is its scope id — so only the
    /// ascent-link requirement stops the wave recording it as this scope's
    /// boundary and stopping the enumeration there.
    #[test]
    fn the_vault_root_named_by_the_child_scope_index_is_refused() {
        let harness = Harness::plain();
        let vault_scope = [0x77; 16];
        let planted = vault_root(vault_scope, Vec::new());
        assert!(
            planted.grant_section.ascent_link.is_none(),
            "a vault root is exactly the record with nothing binding it to us",
        );
        harness.stage(vault_scope, &planted, Some(OWNER_ROOT_EPOCH));
        let staged = staged_scope_with_index(&harness, |descendant, _| {
            vec![
                child_ref(CHILD_SCOPE, descendant),
                child_ref(vault_scope, &planted),
            ]
        });
        let owner = owner_identity();
        let net = wave(
            &harness,
            &owner,
            &staged.root.name,
            &staged.root.grant_section.commitment,
        );

        assert_eq!(
            block_on(net.resolve_node(&SCOPE)),
            Err(ResolveFailure::Rejected)
        );
    }

    #[test]
    fn a_node_no_gated_record_named_has_no_name_to_read_at() {
        let harness = Harness::plain();
        let staged = staged_scope(&harness);
        let owner = owner_identity();
        let net = wave(
            &harness,
            &owner,
            &staged.root.name,
            &staged.root.grant_section.commitment,
        );

        assert_eq!(
            block_on(net.resolve_node(&[0xee; 16])),
            Err(ResolveFailure::Rejected)
        );
    }

    #[test]
    fn one_id_named_at_two_names_aborts_rather_than_picking() {
        let harness = Harness::plain();
        let elsewhere = derive_write_name(&FRESH_WRITE_SCOPE_SEED, &LEAF);
        let leaf_old = stage_node(&harness, LEAF, &folder(Vec::new()));
        let mid_old = stage_node(&harness, MID, &folder(vec![ref_to(LEAF, &elsewhere)]));
        let root = staged_root(
            &harness,
            vec![ref_to(MID, &mid_old), ref_to(LEAF, &leaf_old)],
            Vec::new(),
            Vec::new(),
        );
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);

        block_on(net.resolve_node(&SCOPE)).expect("the root resolves");
        assert_eq!(
            block_on(net.resolve_node(&MID)),
            Err(ResolveFailure::ConflictingChildLabel)
        );
    }

    #[test]
    fn a_gate_rejected_node_aborts_the_wave_and_is_never_reported_as_staleness() {
        let harness = Harness::plain();
        let served = stage_node(&harness, LEAF, &folder(Vec::new()));
        // The root names a node id at a record that claims a different id — the
        // transplant the child gate refuses.
        let root = staged_root(&harness, vec![ref_to(MID, &served)], Vec::new(), Vec::new());
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let mut entropy = SeededEntropy::new(13);

        let error = block_on(rotate_scope_write(
            &mut entropy,
            &net,
            &net,
            &write_plan(&root, &owner),
        ))
        .expect_err("the wave aborts");
        assert_eq!(
            error,
            WriteRotateError::Resolve {
                node_id: MID,
                reason: ResolveFailure::Rejected,
            }
        );
        assert!(!error.is_retryable(), "a gate verdict no retry can clear");
        assert!(
            !published_at(&harness, &scope_pointer_name(&OWNER_POINTER_SEED, &SCOPE)),
            "the root is never re-pointed over a subtree the wave could not enumerate"
        );
        assert!(!published_at(
            &harness,
            &derive_write_name(&FRESH_WRITE_SCOPE_SEED, &SCOPE)
        ));
    }

    #[test]
    fn an_unresolvable_node_aborts_the_wave_rather_than_truncating_the_subtree() {
        let harness = Harness::plain();
        let unserved = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &LEAF);
        let root = staged_root(
            &harness,
            vec![ref_to(LEAF, &unserved)],
            Vec::new(),
            Vec::new(),
        );
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name, &root.grant_section.commitment);
        let mut entropy = SeededEntropy::new(13);

        let error = block_on(rotate_scope_write(
            &mut entropy,
            &net,
            &net,
            &write_plan(&root, &owner),
        ))
        .expect_err("the wave aborts");
        assert_eq!(
            error,
            WriteRotateError::Resolve {
                node_id: LEAF,
                reason: ResolveFailure::Unavailable,
            }
        );
        assert!(error.is_retryable(), "no host served it — availability");
        assert!(
            !published_at(&harness, &scope_pointer_name(&OWNER_POINTER_SEED, &SCOPE)),
            "an incomplete enumeration never reaches the re-point"
        );
    }

    #[test]
    fn the_production_edges_carry_the_whole_wave_from_enumeration_to_re_point() {
        let harness = Harness::plain();
        let staged = staged_scope(&harness);
        let owner = owner_identity();
        let net = wave(
            &harness,
            &owner,
            &staged.root.name,
            &staged.root.grant_section.commitment,
        );
        let mut entropy = SeededEntropy::new(13);

        // Each plane's clock is authored by its own authority (#38 D1), so the
        // read-epoch floors must sit exactly where an ordinary read of these
        // records leaves them once the whole wave has run — at the rotating
        // scope, and at every descendant scope root the enumeration adopts.
        let floors_before = [SCOPE, CHILD_SCOPE].map(|scope| {
            block_on(harness.floors.raise_epoch_floor(&scope, OWNER_ROOT_EPOCH))
                .expect("floor raise");
            block_on(floor::read_epoch_floor(&harness.floors, &scope)).expect("floor read")
        });

        let outcome = block_on(rotate_scope_write(
            &mut entropy,
            &net,
            &net,
            &write_plan(&staged.root, &owner),
        ))
        .expect("the wave completes over the production seams");

        let floors_after = [SCOPE, CHILD_SCOPE].map(|scope| {
            block_on(floor::read_epoch_floor(&harness.floors, &scope)).expect("floor read")
        });
        assert_eq!(
            floors_after, floors_before,
            "a write rotation advances the write epoch and moves no read-epoch floor",
        );

        let fresh = SeededEntropy::first_draw(13);
        assert_eq!(outcome.new_write_epoch, OWNER_ROOT_EPOCH + 1);
        assert_eq!(outcome.new_root_name, derive_write_name(&fresh, &SCOPE));
        assert_eq!(
            outcome.interior_node_count, 2,
            "MID and LEAF, and not the descendant scope root"
        );
        assert!(
            outcome.repoint_accelerators.is_empty(),
            "neither accelerator has a wire shape to publish on"
        );

        // The canonical flip carries the owner-signed re-point object.
        let pointer = scope_pointer_name(&OWNER_POINTER_SEED, &SCOPE);
        let block = harness
            .store
            .record_at(&harness.store.endpoints()[0], pointer.as_str())
            .and_then(|bytes| IpnsRecord::unmarshal(&bytes).ok()?.verify(&pointer).ok())
            .expect("the pointer record verifies under its own name")
            .value;
        let repoint = open_repoint(
            kdf::pointer_read_key(&OWNER_POINTER_SEED, &SCOPE).as_bytes(),
            1,
            &SCOPE,
            &owner.verifying_key(),
            &block,
        )
        .expect("the re-point object opens under the owner's pointer key");
        assert_eq!(repoint.current_root, outcome.new_root_name);
        assert_eq!(repoint.prev_root, Some(staged.root.name.clone()));

        // A read-only holder descends by child refs alone — the proof every
        // interior node moved and every parent was rewritten.
        let mut name = outcome.new_root_name.clone();
        let mut node_id = SCOPE;
        for expected in [MID, LEAF] {
            let refs = child_names_of(&read_only_open(&harness, node_id, &name));
            let next = refs
                .iter()
                .map(|bytes| core::str::from_utf8(bytes).expect("a utf8 name"))
                .find(|text| *text == derive_write_name(&fresh, &expected).as_str())
                .expect("the parent names the child at the name the wave moved it to");
            name = IpnsName::parse(next).expect("a canonical name");
            node_id = expected;
        }
        assert_ne!(
            name, staged.mid_name,
            "no retired name survives the descent"
        );

        assert!(
            child_names_of(&read_only_open(&harness, SCOPE, &outcome.new_root_name))
                .contains(&staged.descendant.name.as_str().as_bytes().to_vec()),
            "the descendant scope root keeps the name its own wave will move"
        );
    }

    #[test]
    fn a_planted_write_history_link_is_never_re_signed_into_the_moved_root() {
        // No owner signature covers `writeHistoryLink`, and the resume reads a
        // seed from exactly there (`WriteHistory`). The cut mints its own.
        const PLANTED: &[u8] = b"planted-by-a-write-grantee";
        let harness = Harness::plain();
        let staged = staged_scope_with(
            &harness,
            |descendant, _| vec![child_ref(CHILD_SCOPE, descendant)],
            PLANTED.to_vec(),
        );
        let owner = owner_identity();
        let net = wave(
            &harness,
            &owner,
            &staged.root.name,
            &staged.root.grant_section.commitment,
        );
        let mut entropy = SeededEntropy::new(61);

        let outcome = block_on(rotate_scope_write(
            &mut entropy,
            &net,
            &net,
            &write_plan(&staged.root, &owner),
        ))
        .expect("the wave completes");

        let fresh = SeededEntropy::first_draw(61);
        let new_epoch = OWNER_ROOT_EPOCH + 1;
        let (_, envelope) = published_head(&harness, &outcome.new_root_name);
        let section = published_section(&harness, &outcome.new_root_name);
        let body = open_write_body(&envelope, &section, &SCOPE, &fresh, new_epoch)
            .expect("the moved root's write body opens under the fresh write scope seed");

        assert_ne!(
            body.write_history_link.as_slice(),
            PLANTED,
            "the planted bytes are not what the owner re-signed"
        );
        let link_ctx = AadContext {
            v: ENVELOPE_V,
            id: SCOPE,
            scope: SCOPE,
            epoch: new_epoch,
            struct_tag: STRUCT_TAG_WRITE_HISTORY_LINK,
        };
        let payload = open_owner_history_link(&owner_enc(), &link_ctx, &body.write_history_link)
            .expect("the wave's own link opens for the owner");
        assert!(ct_eq(payload.prev_seed(), &OWNER_ROOT_WRITE_SCOPE_SEED));
        assert_eq!(payload.prev_epoch, OWNER_ROOT_EPOCH);

        assert!(
            open_history_link(
                kdf::structure_key(&fresh, STRUCT_TAG_HISTORY_LINK).as_bytes(),
                &link_ctx,
                &body.write_history_link,
            )
            .is_err(),
            "a write grantee holding the published seed opens nothing"
        );
    }

    #[test]
    fn the_recovery_seam_reads_the_fresh_seed_off_the_published_root() {
        // #26 D8: no checkpoints. A wave that flipped the pointer leaves its fresh
        // write scope seed reachable from published records alone — the pointer
        // names the moved root, the moved root's owner-write blob carries the seed
        // — so a brand-new orchestrator resumes on it.
        let harness = Harness::plain();
        let staged = staged_scope(&harness);
        let owner = owner_identity();
        let outcome = {
            let net = wave(
                &harness,
                &owner,
                &staged.root.name,
                &staged.root.grant_section.commitment,
            );
            let mut entropy = SeededEntropy::new(62);
            block_on(rotate_scope_write(
                &mut entropy,
                &net,
                &net,
                &write_plan(&staged.root, &owner),
            ))
            .expect("the wave completes")
        };

        // A fresh net: no gated root parked, no subtree index, nothing carried.
        let resumed = wave(
            &harness,
            &owner,
            &staged.root.name,
            &staged.root.grant_section.commitment,
        );
        let recovered = block_on(resumed.recover_wave())
            .expect("the recovery reads published state")
            .expect("a flipped pointer names an in-flight wave");
        assert_eq!(recovered.root_name, outcome.new_root_name);
        assert!(
            ct_eq(
                recovered.write_scope_seed.as_bytes(),
                &SeededEntropy::first_draw(62)
            ),
            "the seed comes back off the published root, not from memory"
        );
        assert_eq!(
            derive_write_name(recovered.write_scope_seed.as_bytes(), &SCOPE),
            recovered.root_name,
            "the recovered pair satisfies the check rotate_scope_write imposes"
        );
    }

    #[test]
    fn a_scope_pointer_naming_another_predecessor_is_not_this_waves_recovery() {
        // The pointer is scope-wide and outlives any one rotation: only a re-point
        // whose `prevRoot` is the root THIS wave is moving off describes this
        // wave. Anything else is an earlier rotation's, and resuming on its seed
        // would move the subtree to names the current root never had.
        let harness = Harness::plain();
        let staged = staged_scope(&harness);
        let owner = owner_identity();
        {
            let net = wave(
                &harness,
                &owner,
                &staged.root.name,
                &staged.root.grant_section.commitment,
            );
            let mut entropy = SeededEntropy::new(63);
            block_on(rotate_scope_write(
                &mut entropy,
                &net,
                &net,
                &write_plan(&staged.root, &owner),
            ))
            .expect("the wave completes");
        }

        let elsewhere = derive_write_name(&[0x3c; 32], &SCOPE);
        let other = wave(
            &harness,
            &owner,
            &elsewhere,
            &staged.root.grant_section.commitment,
        );
        assert!(
            block_on(other.recover_wave())
                .expect("the recovery reads published state")
                .is_none(),
            "a re-point off another predecessor is not this wave's to resume"
        );
    }

    #[test]
    fn a_resumed_wave_re_resolves_the_subtree_from_published_records_alone() {
        // A crash leaves the durable floors raised, so the resumed pass reads its
        // own un-re-pointed root back with no in-memory carry from the pass that
        // raised them.
        let harness = Harness::plain();
        let staged = staged_scope(&harness);
        let owner = owner_identity();

        let first = wave(
            &harness,
            &owner,
            &staged.root.name,
            &staged.root.grant_section.commitment,
        );
        let before: Vec<WriteScopeNode> = [SCOPE, MID, LEAF]
            .into_iter()
            .map(|id| block_on(first.resolve_node(&id)).expect("the first pass enumerates"))
            .collect();
        drop(first);

        let resumed = wave(
            &harness,
            &owner,
            &staged.root.name,
            &staged.root.grant_section.commitment,
        );
        let after: Vec<WriteScopeNode> = [SCOPE, MID, LEAF]
            .into_iter()
            .map(|id| block_on(resumed.resolve_node(&id)).expect("the resumed pass enumerates"))
            .collect();

        assert_eq!(before, after);
    }

    // --- The interior-node lazy wave ---

    /// The read epoch `SCOPE` sits at after one read rotation, and the seed that
    /// cut minted. Records authored before it carry `OWNER_ROOT_SCOPE_SEED`, so a
    /// node still at [`OWNER_ROOT_EPOCH`] only opens through the history link the
    /// cut left behind.
    const SWEPT_EPOCH: u64 = OWNER_ROOT_EPOCH + 1;
    const SWEPT_SEED: [u8; 32] = [0xa5; 32];

    /// The scope read seed records at `epoch` were sealed under.
    fn seed_at(epoch: u64) -> [u8; 32] {
        if epoch >= SWEPT_EPOCH {
            SWEPT_SEED
        } else {
            OWNER_ROOT_SCOPE_SEED
        }
    }

    /// One interior node's record: an ordinary child envelope sealed under the
    /// scope's `epoch`-era read key, at the write name its own write seed derives.
    fn interior_record(
        node_id: [u8; 16],
        epoch: u64,
        children: Vec<ChildRef>,
    ) -> (IpnsName, Vec<u8>) {
        let name = interior_name(node_id);
        let read_key = read_key_for(&seed_at(epoch), &node_id);
        let body = ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children,
            unknown: PreservedFields::new(),
        };
        let envelope = seal_read_body(
            &read_key,
            &[0x4d; 24],
            ENVELOPE_V,
            node_id,
            SCOPE,
            epoch,
            &body,
        )
        .expect("seal the interior body");
        (
            name,
            encode_envelope(&envelope).expect("encode the envelope"),
        )
    }

    /// The write name an interior node's own write seed derives. A pure function
    /// of the node id, so a parent body can cite a child staged after it.
    fn interior_name(node_id: [u8; 16]) -> IpnsName {
        let write_seed = kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &node_id);
        IpnsName::from_public_key(&kdf::ipns_keypair(write_seed.as_bytes()).verifying_key())
    }

    /// The parent ref a folder body carries for `node_id` at `name`.
    fn body_ref(node_id: [u8; 16], name: &IpnsName) -> ChildRef {
        ChildRef {
            id: node_id,
            name: format!("n{:02x}", node_id[0]),
            ipns_name: name.as_str().as_bytes().to_vec(),
            kind: NodeKind::Folder,
            link_counter: 1,
            unknown: PreservedFields::new(),
        }
    }

    /// `SCOPE`'s root as the sweep meets it: post-rotation at [`SWEPT_EPOCH`]
    /// under [`SWEPT_SEED`], carrying the one history link back to the
    /// pre-rotation seed, with `body_children` in its read body and
    /// `child_scope_index` as its committed boundary set.
    fn swept_root(
        body_children: Vec<ChildRef>,
        child_scope_index: &[ChildScopeRef],
    ) -> OwnerRootFixture {
        owner_scope_root_at(
            ENVELOPE_V,
            SCOPE,
            &SWEPT_SEED,
            SWEPT_EPOCH,
            None,
            child_scope_index,
            body_children,
            Some(PrevEpochSeed {
                seed: &OWNER_ROOT_SCOPE_SEED,
                epoch: OWNER_ROOT_EPOCH,
            }),
        )
    }

    impl<T: RecordTransport + Clone> Harness<T> {
        /// Stage a head block and a signed record for `node_id` at `name`.
        fn stage_node(&self, node_id: [u8; 16], name: &IpnsName, block: &[u8]) {
            self.stage_node_at(node_id, name, block, 1);
        }

        /// [`Self::stage_node`] at a chosen record sequence.
        fn stage_node_at(&self, node_id: [u8; 16], name: &IpnsName, block: &[u8], sequence: u64) {
            let cid = root_block_cid(block);
            self.blocks
                .lock()
                .expect("lock")
                .insert(cid.clone(), block.to_vec());
            let record = record_for(&node_id, &cid, sequence);
            for endpoint in self.store.endpoints() {
                self.store
                    .seed_record(&endpoint, name.as_str(), record.clone());
            }
        }
    }

    /// A staged one-node scope: `SCOPE`'s root at [`SWEPT_EPOCH`] naming one
    /// interior node published at `node_epoch`.
    fn staged_swept_scope(
        node_epoch: u64,
    ) -> (Harness<InMemoryRecordStore>, ChildScopeRef, [u8; 16]) {
        let node_id = [0x01; 16];
        let (node_name, node_block) = interior_record(node_id, node_epoch, Vec::new());
        let root = swept_root(vec![body_ref(node_id, &node_name)], &[]);
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage_node(node_id, &node_name, &node_block);
        (harness, child_ref(SCOPE, &root), node_id)
    }

    #[test]
    fn a_lagging_interior_node_opens_through_the_history_link_ratchet() {
        let (harness, scope, _) = staged_swept_scope(OWNER_ROOT_EPOCH);
        let net = harness.net(&[]);

        let swept = block_on(net.resolve_scope(&scope)).expect("the scope root gates");
        assert_eq!(swept.current_read_epoch, SWEPT_EPOCH);
        assert_eq!(swept.children.len(), 1, "the read body is the frontier");

        let found =
            block_on(net.resolve_child(&scope, &swept.children[0])).expect("the node opens");
        let SweptChild::Interior(node) = found else {
            panic!("an ordinary node is not a scope-root boundary");
        };
        assert_eq!(
            node.current_read_epoch, OWNER_ROOT_EPOCH,
            "the node is behind its scope, and read anyway",
        );
        assert_eq!(node.read_body, interior_body());
    }

    /// The body [`interior_record`] sealed for a childless node.
    fn interior_body() -> ReadBody {
        ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        }
    }

    #[test]
    fn a_node_whose_epoch_the_ratchet_cannot_reach_is_unreadable() {
        // A record claiming an epoch no history link walks back to opens under
        // no seed this scope can derive — unreadable to every reader, so the
        // pass isolates the node rather than calling the record forged.
        let node_id = [0x01; 16];
        let (node_name, node_block) = interior_record(node_id, OWNER_ROOT_EPOCH, Vec::new());
        // A root with no history links at all: nothing walks back from SWEPT_EPOCH.
        let root = owner_scope_root_at(
            ENVELOPE_V,
            SCOPE,
            &SWEPT_SEED,
            SWEPT_EPOCH,
            None,
            &[],
            vec![body_ref(node_id, &node_name)],
            None,
        );
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage_node(node_id, &node_name, &node_block);
        let net = harness.net(&[]);
        let scope = child_ref(SCOPE, &root);
        let swept = block_on(net.resolve_scope(&scope)).expect("gates");

        assert_eq!(
            block_on(net.resolve_child(&scope, &swept.children[0])),
            Err(SweepResolveFailure::Unreadable),
        );
    }

    #[test]
    fn a_node_read_under_a_scope_this_net_never_gated_is_refused() {
        // The parked read is keyed on the scope root's own name, so a caller
        // asking under another label gets nothing rather than this scope's keys.
        let (harness, scope, _) = staged_swept_scope(OWNER_ROOT_EPOCH);
        let net = harness.net(&[]);
        let swept = block_on(net.resolve_scope(&scope)).expect("gates");
        let foreign = ChildScopeRef::new([0x9e; 16], scope.ipns_name.clone());

        assert_eq!(
            block_on(net.resolve_child(&foreign, &swept.children[0])),
            Err(SweepResolveFailure::Rejected),
        );
    }

    #[test]
    fn an_interior_record_below_its_names_sequence_floor_is_refused() {
        // The sweep reads past the read-epoch floor by design, so the per-name
        // sequence floor is what stops a rolled-back record being carried
        // forward as the node's current body.
        let (harness, scope, node_id) = staged_swept_scope(OWNER_ROOT_EPOCH);
        let (node_name, _) = interior_record(node_id, OWNER_ROOT_EPOCH, Vec::new());
        block_on(
            harness
                .floors
                .raise_sequence_floor(node_name.as_str().as_bytes(), 5),
        )
        .expect("raise the sequence floor past the staged record");
        let net = harness.net(&[]);
        let swept = block_on(net.resolve_scope(&scope)).expect("gates");

        assert_eq!(
            block_on(net.resolve_child(&scope, &swept.children[0])),
            Err(SweepResolveFailure::Rejected),
        );
    }

    #[test]
    fn an_interior_record_claiming_another_node_is_refused() {
        let (harness, scope, _) = staged_swept_scope(OWNER_ROOT_EPOCH);
        let net = harness.net(&[]);
        let swept = block_on(net.resolve_scope(&scope)).expect("gates");
        let mislabelled = NodeRef {
            node_id: [0x9e; 16],
            ipns_name: swept.children[0].ipns_name.clone(),
        };
        assert_eq!(
            block_on(net.resolve_child(&scope, &mislabelled)),
            Err(SweepResolveFailure::Rejected),
        );
    }

    #[test]
    fn a_child_carrying_a_grant_section_is_a_scope_root_boundary() {
        let boundary = [0x0a; 16];
        let parent_node_seed = *kdf::node_seed(&SWEPT_SEED, &boundary).as_bytes();
        let descendant = owner_scope_root(
            boundary,
            &OWNER_ROOT_SCOPE_SEED,
            OWNER_ROOT_EPOCH,
            Some(&parent_node_seed),
            &[],
        );
        let root = swept_root(vec![body_ref(boundary, &descendant.name)], &[]);
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage(boundary, &descendant, Some(OWNER_ROOT_EPOCH));
        let net = harness.net(&[]);
        let scope = child_ref(SCOPE, &root);
        let swept = block_on(net.resolve_scope(&scope)).expect("gates");

        assert_eq!(
            block_on(net.resolve_child(&scope, &swept.children[0])),
            Ok(SweptChild::ScopeRoot(ChildScopeRef::new(
                boundary,
                descendant.name.as_str().as_bytes().to_vec(),
            ))),
            "a grant section makes it the cascade's, and names it for the index",
        );
    }

    #[test]
    fn a_swept_node_republishes_at_the_scopes_epoch_under_the_current_seed() {
        let (harness, scope, node_id) = staged_swept_scope(OWNER_ROOT_EPOCH);
        // One net per pass: the publisher runs off the resolve that gated it.
        let net = harness.net(&[]);
        let outcome = block_on(sweep_pass(&net, &net, &scope)).expect("the pass converges");
        assert_eq!(outcome.converged, vec![node_id]);
        drop(outcome);

        let (node_name, _) = interior_record(node_id, OWNER_ROOT_EPOCH, Vec::new());
        let (_, envelope) = published_head(&harness, &node_name);
        assert_eq!(envelope.epoch, SWEPT_EPOCH, "advanced to the scope's epoch");
        assert!(
            !has_grant_section(&envelope),
            "an interior node never gains a scope-root marker",
        );
        let read_key = read_key_for(&SWEPT_SEED, &node_id);
        assert_eq!(
            open_read_body(&envelope, &read_key).expect("reopens under the current seed"),
            interior_body(),
            "the body is carried forward verbatim",
        );
    }

    #[test]
    fn a_swept_node_lands_above_the_sequence_the_network_already_holds() {
        // Nothing on the sweep's read path adopts an interior record, so this
        // device's durable sequence floor for the node starts at 0 while the
        // network is at 7. Publishing at floor + 1 would lose the CAS forever.
        let node_id = [0x01; 16];
        let (node_name, node_block) = interior_record(node_id, OWNER_ROOT_EPOCH, Vec::new());
        let root = swept_root(vec![body_ref(node_id, &node_name)], &[]);
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage_node_at(node_id, &node_name, &node_block, 7);
        assert_eq!(
            block_on(floor::sequence_floor(
                &harness.floors,
                node_name.as_str().as_bytes()
            ))
            .expect("floor read"),
            None,
            "the node was never adopted on this device",
        );

        let net = harness.net(&[]);
        let outcome =
            block_on(sweep_pass(&net, &net, &child_ref(SCOPE, &root))).expect("the pass converges");
        assert_eq!(outcome.converged, vec![node_id]);
        let (published, _) = published_head(&harness, &node_name);
        assert_eq!(
            published.sequence, 8,
            "the CAS ran off the record the pass read, not the empty floor",
        );
    }

    #[test]
    fn an_interior_unseal_advances_the_names_sequence_floor() {
        // The floor law's child arm, so a rolled-back record stops being
        // admissible the moment the sweep has read the real one.
        let node_id = [0x01; 16];
        let (node_name, node_block) = interior_record(node_id, OWNER_ROOT_EPOCH, Vec::new());
        let root = swept_root(vec![body_ref(node_id, &node_name)], &[]);
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage_node_at(node_id, &node_name, &node_block, 7);
        let net = harness.net(&[]);
        let scope = child_ref(SCOPE, &root);
        let swept = block_on(net.resolve_scope(&scope)).expect("gates");
        block_on(net.resolve_child(&scope, &swept.children[0])).expect("opens");

        assert_eq!(
            block_on(floor::sequence_floor(
                &harness.floors,
                node_name.as_str().as_bytes()
            ))
            .expect("floor read"),
            Some(7),
        );
    }

    /// The owner's own vault root, planted in a swept node's read body as if it
    /// were a descendant scope root. Every gate stage passes on it — it is a
    /// real owner-signed record — and a vault root carries no ascent link, so
    /// only the sweep's own requirement for one stops it being repaired into
    /// this scope's committed index, where a later cascade would re-key it
    /// under this scope's seed.
    #[test]
    fn the_vault_root_planted_as_a_child_scope_root_is_refused() {
        let vault_scope = [0x77; 16];
        let planted = vault_root(vault_scope, Vec::new());
        assert!(
            planted.grant_section.ascent_link.is_none(),
            "a vault root is exactly the record with nothing binding it to us",
        );
        let root = swept_root(vec![body_ref(vault_scope, &planted.name)], &[]);
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage(vault_scope, &planted, Some(OWNER_ROOT_EPOCH));
        let net = harness.net(&[]);
        let scope = child_ref(SCOPE, &root);
        let swept = block_on(net.resolve_scope(&scope)).expect("gates");

        assert_eq!(
            block_on(net.resolve_child(&scope, &swept.children[0])),
            Err(SweepResolveFailure::Rejected),
        );

        // The pass isolates it under the verdict that condemned it, and the
        // index it commits to never names it.
        let net = harness.net(&[]);
        let outcome = block_on(sweep_pass(&net, &net, &scope)).expect("the pass completes");
        assert_eq!(
            outcome.unreachable,
            vec![(vault_scope, SweepResolveFailure::Rejected)]
        );
        assert!(outcome.flagged_indexes.is_empty());
        assert!(outcome.skipped_scope_roots.is_empty());
    }

    #[test]
    fn a_scope_root_below_its_own_floor_is_superseded_not_rejected() {
        let (harness, scope, _) = staged_swept_scope(OWNER_ROOT_EPOCH);
        block_on(harness.floors.raise_epoch_floor(&SCOPE, SWEPT_EPOCH + 3))
            .expect("raise the floor past the record");

        assert_eq!(
            block_on(harness.net(&[]).resolve_scope(&scope)),
            Err(SweepResolveFailure::Superseded),
            "a rotation publishes before it raises the floor, so this is a stale name",
        );
    }

    #[test]
    fn a_forged_below_floor_record_stays_a_trust_rejection() {
        // A record whose commitment another identity signed is refused at gate
        // stage 2, which runs before the floor stages — so a forgery is never
        // reclassified as a stale name and no consult path is offered one.
        let (harness, scope, _) = staged_swept_scope(OWNER_ROOT_EPOCH);
        let impostor = owner_root_fixture(OwnerRootSpec {
            owner_identity: &EcdsaSigner::from_scalar(&[0x4d; 32]).expect("valid scalar"),
            owner_enc: &owner_enc().public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children: Vec::new(),
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants: Vec::new(),
        });
        harness.stage(SCOPE, &impostor, Some(OWNER_ROOT_EPOCH));
        block_on(harness.floors.raise_epoch_floor(&SCOPE, SWEPT_EPOCH + 3))
            .expect("raise the floor past the forged record");

        assert_eq!(
            block_on(harness.net(&[]).resolve_scope(&scope)),
            Err(SweepResolveFailure::Rejected),
        );
    }

    #[test]
    fn the_consult_reports_the_owner_signed_current_root_name() {
        let (harness, _, _) = staged_swept_scope(OWNER_ROOT_EPOCH);
        let current_root = vault_root([0xb0; 16], Vec::new()).name;
        let repoint = RepointObject {
            scope_id: SCOPE,
            current_root: current_root.clone(),
            write_epoch: OWNER_ROOT_EPOCH,
            min_read_epoch: SWEPT_EPOCH,
            prev_root: None,
        };
        stage_scope_pointer(&harness, &owner_identity(), &repoint);

        assert_eq!(
            block_on(harness.net(&[]).consult_pointer(&SCOPE)),
            Ok(Some(current_root.as_str().as_bytes().to_vec())),
        );
    }

    #[test]
    fn a_scope_pointer_another_identity_signed_admits_nothing() {
        let (harness, _, _) = staged_swept_scope(OWNER_ROOT_EPOCH);
        let repoint = RepointObject {
            scope_id: SCOPE,
            current_root: vault_root([0xb0; 16], Vec::new()).name,
            write_epoch: OWNER_ROOT_EPOCH,
            min_read_epoch: SWEPT_EPOCH,
            prev_root: None,
        };
        let impostor = EcdsaSigner::from_scalar(&[0x4d; 32]).expect("valid scalar");
        stage_scope_pointer(&harness, &impostor, &repoint);

        assert_eq!(
            block_on(harness.net(&[]).consult_pointer(&SCOPE)),
            Err(SweepResolveFailure::Rejected),
        );
    }

    #[test]
    fn a_scope_that_was_never_re_pointed_has_no_fresher_name() {
        let (harness, _, _) = staged_swept_scope(OWNER_ROOT_EPOCH);
        assert_eq!(block_on(harness.net(&[]).consult_pointer(&SCOPE)), Ok(None));
    }

    /// Publish `repoint` at `SCOPE`'s scope-pointer name, sealed under the same
    /// pointer read key the net re-derives and signed by `owner`.
    fn stage_scope_pointer<T: RecordTransport + Clone>(
        harness: &Harness<T>,
        owner: &EcdsaSigner,
        repoint: &RepointObject,
    ) {
        let pointer = scope_pointer_name(&OWNER_POINTER_SEED, &SCOPE);
        let read_key = OwnerSeeds.pointer_read_key(&SCOPE);
        let mut entropy = SeededEntropy::new(5);
        let block = seal_repoint(
            SessionRole::Owner,
            &mut entropy,
            &read_key,
            PAYLOAD_VERSION,
            owner,
            repoint,
        )
        .expect("owner seals the re-point");
        let signer = scope_pointer_signer(&OWNER_POINTER_SEED, &SCOPE);
        let record = IpnsRecord::create_v2(&signer, &block, 1, TTL_NANOS, EOL).marshal();
        for endpoint in harness.store.endpoints() {
            harness
                .store
                .seed_record(&endpoint, pointer.as_str(), record.clone());
        }
    }

    #[test]
    fn an_omitted_scope_root_is_repaired_into_the_published_index() {
        let boundary = [0x0a; 16];
        let parent_node_seed = *kdf::node_seed(&SWEPT_SEED, &boundary).as_bytes();
        let descendant = owner_scope_root(
            boundary,
            &OWNER_ROOT_SCOPE_SEED,
            OWNER_ROOT_EPOCH,
            Some(&parent_node_seed),
            &[],
        );
        // The body names it; the committed index does not — the #38 D6 gap.
        let root = swept_root(vec![body_ref(boundary, &descendant.name)], &[]);
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage(boundary, &descendant, Some(OWNER_ROOT_EPOCH));
        let net = harness.net(&[]);

        let outcome =
            block_on(sweep_pass(&net, &net, &child_ref(SCOPE, &root))).expect("the pass runs");
        assert_eq!(outcome.flagged_indexes, vec![boundary]);
        assert!(
            outcome.converged.is_empty(),
            "the self-heal did not ride an epoch-lag re-seal",
        );

        // The republished root's own write body now names it.
        let regated = harness.net(&[]);
        let swept = block_on(regated.resolve_scope(&child_ref(SCOPE, &root)))
            .expect("the repaired root re-gates");
        assert_eq!(
            swept.direct_child_scope_index,
            vec![ChildScopeRef::new(
                boundary,
                descendant.name.as_str().as_bytes().to_vec(),
            )],
        );
    }

    #[test]
    fn a_planted_self_entry_gives_the_walk_root_no_parent_seed() {
        // `directChildScopeIndex` is writer-authored, so an entry naming the walk
        // root is a writer's claim to be its parent.
        let planted = RotationAncestry::rooted_at(
            SCOPE,
            &OWNER_ROOT_SCOPE_SEED,
            &[ChildScopeRef::new(SCOPE, b"self-entry".to_vec())],
        );
        assert!(planted.parent_node_seed(&SCOPE).is_none());

        // A genuine descendant still gates under its parent's derivation, and the
        // rotating root's caller-supplied ancestor seed is untouched — that is the
        // interior-root rotation, not a writer-authored claim.
        let child = [0x0a; 16];
        let honest = RotationAncestry::rooted_at(
            SCOPE,
            &OWNER_ROOT_SCOPE_SEED,
            &[ChildScopeRef::new(child, b"child".to_vec())],
        );
        assert!(honest.parent_node_seed(&child).is_some());
        assert!(
            planted
                .under_parent_node_seed(SCOPE, Some(&SWEPT_SEED))
                .parent_node_seed(&SCOPE)
                .is_some()
        );

        // Same claim one hop down: a descendant's own index naming the walk root
        // is the identical primitive, so the filter is keyed on "already gated",
        // not on the entry naming its own scope.
        let deep = RotationAncestry::rooted_at(
            SCOPE,
            &OWNER_ROOT_SCOPE_SEED,
            &[ChildScopeRef::new(child, b"child".to_vec())],
        );
        deep.record(
            child,
            &SWEPT_SEED,
            &[ChildScopeRef::new(SCOPE, b"back-edge".to_vec())],
        );
        assert!(deep.parent_node_seed(&SCOPE).is_none());
    }

    #[test]
    fn a_poisoned_ancestry_still_adopts_the_link_less_vault_root() {
        // The requirement is keyed on the record's own section, not on the
        // ancestry's answer, so the self-heal republishes the root link-less and
        // an ordinary read — which derives no parent seed — still adopts it.
        let boundary = [0x0a; 16];
        let parent_node_seed = *kdf::node_seed(&SWEPT_SEED, &boundary).as_bytes();
        let descendant = owner_scope_root(
            boundary,
            &OWNER_ROOT_SCOPE_SEED,
            OWNER_ROOT_EPOCH,
            Some(&parent_node_seed),
            &[],
        );
        let root = swept_root(vec![body_ref(boundary, &descendant.name)], &[]);
        assert!(
            root.grant_section.ascent_link.is_none(),
            "a vault root is exactly the record that owes no ascent link",
        );
        let harness = Harness::plain();
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        harness.stage(boundary, &descendant, Some(OWNER_ROOT_EPOCH));
        let planted = ChildScopeRef::new(SCOPE, root.name.as_str().as_bytes().to_vec());
        let net = harness.net(&[planted]);

        let outcome =
            block_on(sweep_pass(&net, &net, &child_ref(SCOPE, &root))).expect("the pass runs");
        assert_eq!(outcome.flagged_indexes, vec![boundary]);

        let regated = harness.net(&[]);
        block_on(regated.resolve_scope(&child_ref(SCOPE, &root)))
            .expect("the republished vault root still adopts on an ordinary read");
    }

    /// Stage `scenario`'s scope on the record plane and return the scope root's
    /// ref, so the same description drives both the simulation and the real
    /// seams.
    fn stage_scenario(
        harness: &Harness<InMemoryRecordStore>,
        scenario: &sim::Scenario,
    ) -> ChildScopeRef {
        let mut names: BTreeMap<[u8; 16], IpnsName> = BTreeMap::new();
        let mut index: Vec<ChildScopeRef> = Vec::new();
        for (byte, _, _) in scenario.nodes {
            let node_id = sim::id(*byte);
            names.insert(node_id, interior_name(node_id));
        }
        for (byte, indexed) in scenario.scope_roots {
            let scope_id = sim::id(*byte);
            let parent_node_seed = *kdf::node_seed(&SWEPT_SEED, &scope_id).as_bytes();
            let descendant = owner_scope_root(
                scope_id,
                &OWNER_ROOT_SCOPE_SEED,
                OWNER_ROOT_EPOCH,
                Some(&parent_node_seed),
                &[],
            );
            harness.stage(scope_id, &descendant, Some(OWNER_ROOT_EPOCH));
            if *indexed {
                index.push(child_ref(scope_id, &descendant));
            }
            names.insert(scope_id, descendant.name.clone());
        }
        // Every name is bound above, so a node's body can cite a child whose
        // own record is staged later in this loop.
        for (byte, epoch, children) in scenario.nodes {
            let node_id = sim::id(*byte);
            let body: Vec<ChildRef> = children
                .iter()
                .map(|child| {
                    let child_id = sim::id(*child);
                    body_ref(child_id, names.get(&child_id).expect("a staged child"))
                })
                .collect();
            let (name, block) = interior_record(node_id, *epoch, body);
            harness.stage_node(node_id, &name, &block);
        }
        let body: Vec<ChildRef> = scenario
            .children
            .iter()
            .map(|byte| {
                let node_id = sim::id(*byte);
                body_ref(node_id, names.get(&node_id).expect("a staged child"))
            })
            .collect();
        let root = swept_root(body, &index);
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));
        child_ref(SCOPE, &root)
    }

    /// The fake-vs-concrete equivalence check: every scenario runs the one pure
    /// [`sweep_pass`] over the simulation network and over the production seams,
    /// and the two outcomes must agree. A fake that drifts from its production
    /// counterpart is a suite proving nothing, so the divergence fails this gate
    /// rather than being found by reading.
    #[test]
    fn the_sweep_simulation_and_the_production_seams_agree() {
        for scenario in sim::SCENARIOS {
            let fake = scenario.fake();
            // Both must *complete*: two identical aborts would agree while
            // proving nothing about the population either side walked.
            let simulated = block_on(sweep_pass(&fake, &fake, &sim::scope_ref(0x00)))
                .unwrap_or_else(|e| panic!("simulated {:?}: {e}", scenario.label));

            let harness = Harness::plain();
            let scope = stage_scenario(&harness, scenario);
            let net = harness.net(&[]);
            let real = block_on(sweep_pass(&net, &net, &scope))
                .unwrap_or_else(|e| panic!("real {:?}: {e}", scenario.label));

            assert_eq!(simulated, real, "scenario {:?} diverged", scenario.label);

            // Both sides must have walked the whole subtree the scenario
            // describes, not just the root's own body: a scenario set that
            // flattened back to one level would otherwise agree trivially.
            let mut reached: Vec<[u8; 16]> = simulated
                .converged
                .iter()
                .chain(&simulated.already_converged)
                .chain(&simulated.skipped_scope_roots)
                .copied()
                .collect();
            reached.sort_unstable();
            let mut described: Vec<[u8; 16]> = scenario
                .nodes
                .iter()
                .map(|(byte, _, _)| sim::id(*byte))
                .chain(scenario.scope_roots.iter().map(|(byte, _)| sim::id(*byte)))
                .collect();
            described.sort_unstable();
            assert_eq!(
                reached, described,
                "scenario {:?} left part of its subtree unwalked",
                scenario.label
            );
        }
    }
}
