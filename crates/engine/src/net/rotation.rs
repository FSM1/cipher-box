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

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, ChildScopeRef, Envelope, GrantLedgerEntry, GrantSection, GrantSetEntry,
    PreservedFields, ReadBody, STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_WRITE_BODY, WriteBody,
    decode_write_body, open_owner_blob, sign_grant_set, unseal,
};
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use zeroize::Zeroizing;

use super::adopter::RootAdopter;
use super::author::{
    AuthorError, ENVELOPE_V, EnvelopeAuthoring, author_child_envelope,
    author_scope_root_with_section,
};
use super::child::ChildAdopter;
use super::publish::{InlineRecordRequest, PublishError, PublishOutcome, publish_inline};
use super::record_publish::{
    HeadBinding, RecordPublishError, RecordPublishRequest, preflight, publish_record,
};
use super::retire::{retire, root_retire_ready};
use crate::api::ApiClient;
use crate::content::Gateway;
use crate::entropy::Entropy;
use crate::gate::{GateError, RejectionReason, floor};
use crate::grants::{enforce_committed_ledger, entry_tag_is_bound, mint_grant_row};
use crate::net::fanout_get_verify;
use crate::net::resolve::Adopter;
use crate::profile::SyncTimingProfile;
use crate::rotation::{
    CascadeResealResolver, CascadeTarget, ChildIndexResolver, CommittedSet, RepointChannel,
    RepublishedNode, ResealError, ResealSeeds, ResealedScopeRoot, ResolveFailure,
    ScopeRootIdentity, ScopeRootPublishError, ScopeRootPublisher, WritePublishError,
    WriteScopeNode, WriteSubtreeResolver, WriteWavePublisher, derive_write_name, reseal_scope_root,
};
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};
use crate::session::SessionIdentity;
use crate::sync::pointer::{scope_pointer_name, scope_pointer_signer};

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
    /// The record a re-key is about to replace, handed from the resolve that
    /// gated it to the publish (see [`GatedRoots`]). One rotation pass per net.
    pub gated: GatedRoots,
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
    /// gate verifies against a reader-derived keypair. A vault root carries no
    /// ascent link and needs none.
    pub fn under_parent_node_seed(
        self,
        scope_id: [u8; 16],
        parent_node_seed: &[u8; SECRET_LEN],
    ) -> Self {
        self.inner.borrow_mut().root = Some((scope_id, Zeroizing::new(*parent_node_seed)));
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
fn scope_name(ipns_name: &[u8]) -> Result<IpnsName, ResolveFailure> {
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
) -> Result<Zeroizing<[u8; SECRET_LEN]>, ScopeRootPublishError> {
    let owner_blob = &record.section.owner_blob;
    let aad = AadContext {
        v: ENVELOPE_V,
        id: record.scope_id,
        scope: record.scope_id,
        epoch: record.read_epoch,
        struct_tag: STRUCT_TAG_OWNER_BLOB,
    };
    let payload = open_owner_blob(enc_secret, &owner_blob.enc, &aad, &owner_blob.ciphertext)
        .map_err(|_| ScopeRootPublishError::Rejected)?;
    Ok(Zeroizing::new(*payload.override_seed()))
}

/// Carry a resolve verdict into the publish arm without laundering a
/// fail-closed trust violation into a retryable transport failure (rule 6).
fn publish_verdict(failure: ResolveFailure) -> ScopeRootPublishError {
    match failure {
        ResolveFailure::Unavailable => ScopeRootPublishError::NotPublished,
        ResolveFailure::Rejected | ResolveFailure::ConflictingChildLabel => {
            ScopeRootPublishError::Rejected
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
fn author_verdict(refusal: AuthorError) -> ScopeRootPublishError {
    if refusal.is_trust_refusal() {
        ScopeRootPublishError::Rejected
    } else {
        ScopeRootPublishError::NotPublished
    }
}

/// A fresh per-seal nonce from the injected entropy seam.
fn nonce<E: Entropy>(entropy: &RefCell<E>) -> Result<[u8; 24], ScopeRootPublishError> {
    let mut nonce = [0u8; 24];
    entropy
        .borrow_mut()
        .fill(&mut nonce)
        .map_err(|_| ScopeRootPublishError::NotPublished)?;
    Ok(nonce)
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
) -> Result<GatedScopeRoot, ResolveFailure> {
    if !matches!(
        reason,
        RejectionReason::SequenceNotNewer { floor, sequence } if sequence == floor
    ) {
        return Err(ResolveFailure::Rejected);
    }
    let recovered = adopter
        .recover_own_scope_root(name, record_bytes)
        .await
        .map_err(|_| ResolveFailure::Unavailable)?
        // The recovery is fail-open; the rotation keeps the gate's own verdict.
        .ok_or(ResolveFailure::Rejected)?;
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
) -> Result<GatedScopeRoot, ResolveFailure> {
    match adopter.adopt_root(name, record_bytes).await {
        Ok((candidate, outcome)) => Ok(GatedScopeRoot {
            envelope: candidate.envelope,
            section: candidate.grant_section,
            read_body: outcome.adopted.read_body,
            read_scope_seed: outcome.read_scope_seed.ok_or(ResolveFailure::Unavailable)?,
            write_scope_seed: outcome.write_scope_seed,
        }),
        Err(GateError::Seam(_)) => Err(ResolveFailure::Unavailable),
        Err(GateError::Rejected(rejection)) => {
            reread_at_floor(adopter, name, record_bytes, &rejection.reason).await
        }
    }
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
    ) -> Result<GatedScopeRoot, ResolveFailure> {
        let Some((_, record_bytes)) = fanout_get_verify(self.transport, name).await else {
            return Err(ResolveFailure::Unavailable);
        };
        let mut adopter = RootAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            self.keys.enc_secret,
            self.keys.identity,
            scope_id,
        );
        if let Some(seed) = self.ancestry.parent_node_seed(&scope_id) {
            adopter = adopter.under_parent_node_seed(seed);
        }
        gated_scope_root(&adopter, name, &record_bytes).await
    }

    /// Unseal a gated scope root's write-body under the owner's recovered write
    /// scope seed at the durable write-epoch floor, and report that floor — the
    /// AAD epoch the owner-write-blob's own recovery already bound, and the
    /// write epoch a re-seal of this root must republish at. A root held keyless
    /// has no readable write-body — availability, not a trust verdict.
    async fn write_body(
        &self,
        root: &GatedScopeRoot,
        scope_id: [u8; 16],
    ) -> Result<(WriteBody, u64), ResolveFailure> {
        let (Some(write_scope_seed), Some(write_epoch)) = (
            root.write_scope_seed.as_deref(),
            floor::write_epoch_floor(self.floors, &scope_id)
                .await
                .map_err(|_| ResolveFailure::Unavailable)?,
        ) else {
            return Err(ResolveFailure::Unavailable);
        };
        let body = open_write_body(
            &root.envelope,
            &root.section,
            &scope_id,
            write_scope_seed,
            write_epoch,
        )?;
        Ok((body, write_epoch))
    }

    /// The prologue both read edges share: gate `scope`'s record under the
    /// caller's own label, unseal its write body, and extend the ancestry with
    /// the seed the pass just proved so the next level down can derive its own
    /// ascent authority. The seed recorded is the **published** one — the
    /// cascade re-keys top-down, so a descendant's record still carries the
    /// ascent link its parent's pre-cascade seed sealed.
    async fn gated_write_plane(
        &self,
        scope: &ChildScopeRef,
    ) -> Result<GatedWritePlane, ResolveFailure> {
        let name = scope_name(&scope.ipns_name)?;
        let root = self.gated_root(scope.scope_id, &name).await?;
        let (write_body, write_epoch) = self.write_body(&root, scope.scope_id).await?;
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
    ) -> Result<(), ScopeRootPublishError> {
        let floors = self.floors;
        let scope_id = &record.scope_id;
        let read_floor = floor::read_epoch_floor(floors, scope_id)
            .await
            .map_err(|_| ScopeRootPublishError::NotPublished)?
            .unwrap_or(0);
        let write_floor = floor::write_epoch_floor(floors, scope_id)
            .await
            .map_err(|_| ScopeRootPublishError::NotPublished)?
            .unwrap_or(0);
        if record.read_epoch < read_floor || record.write_epoch < write_floor {
            return Err(ScopeRootPublishError::Rejected);
        }
        Ok(())
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
        let gated = self.gated_write_plane(child).await?;
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
        let GatedWritePlane {
            name,
            root,
            write_body,
            write_epoch,
        } = self.gated_write_plane(scope).await?;
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
        if envelope.v != ENVELOPE_V {
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
    ) -> Result<(), ScopeRootPublishError> {
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
                    .map_err(publish_verdict)?,
            ),
        };
        self.check_publishable(record).await?;

        let node_seed = kdf::node_seed(&override_seed, &record.scope_id);
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
            &name,
            &record.section,
            self.keys.identity,
        )
        .map_err(author_verdict)?;

        let write_scope_seed = current
            .write_scope_seed
            .as_deref()
            .ok_or(ScopeRootPublishError::NotPublished)?;

        let binding = HeadBinding {
            node_id: record.scope_id,
            scope_id: record.scope_id,
            epoch: record.read_epoch,
        };
        let preflighted = preflight(&binding, &read_key, &head)
            .map_err(|_| ScopeRootPublishError::NotPublished)?;

        let signer = SessionIdentity::write_name_signer(write_scope_seed, &record.scope_id);
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
                min_current_sequence: None,
            },
        )
        .await
        .map_err(|_| ScopeRootPublishError::NotPublished)?;

        match receipt.outcome {
            PublishOutcome::Published { .. } => Ok(()),
            PublishOutcome::LostRace { .. } => Err(ScopeRootPublishError::LostRace),
            // Acked but not read back as ours: nothing is proven durable, and
            // re-publishing is idempotent-in-sequence.
            PublishOutcome::Unconfirmed { .. } => Err(ScopeRootPublishError::NotPublished),
        }
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
    /// Derives the scope pointer's name and its record signer (owner-only).
    pub owner_pointer_seed: &'a [u8; SECRET_LEN],
    /// The root name the wave is moving off. It lingers serving the tombstone, so
    /// [`WriteWaveNet::retire`] refuses a batch naming it.
    pub current_root_name: &'a IpnsName,
    /// The root read this pass gated and has not yet republished
    /// ([`GatedWaveRoot`]). One rotation pass per net.
    pub gated_root: GatedWaveRoot,
    /// The subtree index the enumeration builds as it descends
    /// ([`WaveSubtree`]). One rotation pass per net.
    pub subtree: WaveSubtree,
}

/// The write scope's node index, as this pass's own gated reads discovered it: a
/// node id locates nothing on its own — only a gated parent's read body names
/// its children.
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
        | ResealError::TooManyHistoryLinks
        | ResealError::TooManyCommittedGrants
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
        let mut adopter = RootAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            self.owner_enc_secret,
            &identity,
            self.scope_id,
        );
        if let Some(seed) = self.parent_node_seed {
            adopter = adopter.under_parent_node_seed(Zeroizing::new(*seed));
        }
        let gated = gated_scope_root(&adopter, name, record_bytes)
            .await
            .map_err(wave_read_verdict)?;
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
    /// a name the revokee's retired write scope seed still derives. Only the
    /// owner-signed commitment names a scope root's own `ipnsName`, so the root
    /// gate is the proof, over the seed the root's own owner blob yielded
    /// (`OwnerRotationNet::gated_write_plane` gates the same index).
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
            // The gate binds `envelope.scope` to the label above; a scope root's
            // node id is its scope id, and only this binds it.
            if gated_scope_root(&adopter, &name, &record_bytes)
                .await?
                .envelope
                .id
                != child.scope_id
            {
                return Err(ResolveFailure::Rejected);
            }
            self.subtree.record_child_scope(child.scope_id);
        }
        Ok(())
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
    /// signed. A ledger row additionally carries forward the fields no owner
    /// signature covers — `expiresAt`, `recipientIdentityPk`, and the preserved
    /// unknowns.
    fn remint_grants(
        &self,
        node: &RepublishedNode,
        plane: &RootPlane,
    ) -> Result<RemintedGrants, WritePublishError> {
        let ledger = &plane.write_body.grant_ledger;
        enforce_committed_ledger(&plane.section.commitment, ledger)
            .map_err(|_| WritePublishError::Rejected)?;
        let old_name = plane.section.commitment.ipns_name.as_slice();
        let new_name = node.new_name.as_str().as_bytes();
        let carried: BTreeMap<[u8; 32], &GrantSetEntry> = plane
            .section
            .commitment
            .entries
            .iter()
            .map(|e| (e.tag, e))
            .collect();

        let mut reminted = RemintedGrants {
            entries: Vec::with_capacity(ledger.len()),
            ledger: Vec::with_capacity(ledger.len()),
        };
        for entry in ledger {
            if !entry_tag_is_bound(self.owner_enc_secret, entry, old_name) {
                return Err(WritePublishError::Rejected);
            }
            let recipient_enc = X25519Public::from_bytes(entry.recipient_enc_pk)
                .ok_or(WritePublishError::Rejected)?;
            let row = mint_grant_row(
                self.owner_enc_secret,
                entry.recipient_identity_pk,
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
        let mut commitment = plane.section.commitment.clone();
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
                parent_node_seed: self.parent_node_seed,
                pseudonym_signer: &pseudonym_signer,
            },
            &ResealSeeds {
                override_seed: &plane.read_scope_seed,
                read_epoch,
                prev: None,
                write_scope_seed: fresh_write_scope_seed,
                write_epoch: node.write_epoch,
                pointer_read_key: &pointer_read_key,
            },
            &CommittedSet {
                commitment: &commitment,
                commitment_sig: &commitment_sig,
                grant_ledger: &remint.ledger,
                write_history_link: &plane.write_body.write_history_link,
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
                // The write floor is monotonic and the re-point raises it to
                // `node.write_epoch`; sealing the section at or below the floor
                // publishes a root whose write plane can never be reopened.
                if node.write_epoch <= plane.write_epoch || node.node_id != self.scope_id {
                    return Err(WritePublishError::Rejected);
                }
                // Every re-minted tag binds `new_name`, and a write grantee
                // derives that name from the seed this section hands it — so a
                // name the published seed does not derive mints a set no grantee
                // can ever self-locate.
                if node.new_name != derive_write_name(fresh.as_bytes(), &node.node_id) {
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
        let targets: Vec<String> = old_names
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        retire(self.api, &targets)
            .await
            .map_err(|_| WritePublishError::NotLanded)
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
        STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_OWNER_WRITE_BLOB,
        decode_envelope, decode_grant_section, encode_envelope, encode_grant_section,
        grant_section_bytes, open_ascent_link, open_grant_blob, open_owner_write_blob,
        open_read_body, seal_read_body, set_grant_section, sign_grant_set, verify_grant_set,
    };
    use cipherbox_core::suite::ecdsa::{EcdsaSignature, IDENTITY_PUBLIC_LEN};
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use cipherbox_core::suite::secret::{SecretBytes, ct_eq};

    use super::*;
    use crate::content::GatewaySource;
    use crate::rotation::{
        CascadeError, CascadeOutcome, CommittedSet, PrevEpochSeed, ResealSeeds, RotateScopePlan,
        RotateScopeWritePlan, ScopeRootIdentity, WriteRotateError, cascade_rotate_scope,
        derive_write_name, enumerate_eager_set, reseal_scope_root, rotate_scope,
        rotate_scope_write,
    };
    use crate::seams::{EndpointId, HttpResponse, SeamError, SeamResult};
    use crate::sync::pointer::open_repoint;
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
        fn build(make: impl FnOnce(InMemoryRecordStore) -> T) -> Self {
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
                transport: make(store.clone()),
                store,
                world,
                http,
                api,
                floors: device.floor_store.clone(),
                gateway: Gateway {
                    accelerator: Some(GatewaySource {
                        base_url: "https://gw.test".into(),
                        bearer: None,
                    }),
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
                gated: GatedRoots::default(),
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
            Self::build(|store| store)
        }
    }

    impl Harness<RacingTransport> {
        fn racing(key: &str, winner: Vec<u8>) -> Self {
            let key = key.to_owned();
            Self::build(move |store| RacingTransport {
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
    /// re-sealed at `read_epoch` under a fresh override seed.
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
                parent_node_seed: None,
                pseudonym_signer: &pseudonym,
            },
            &ResealSeeds {
                override_seed: &FRESH_SEED,
                read_epoch,
                prev: Some(PrevEpochSeed {
                    seed: &OWNER_ROOT_SCOPE_SEED,
                    epoch: OWNER_ROOT_EPOCH,
                }),
                write_scope_seed: &OWNER_ROOT_WRITE_SCOPE_SEED,
                write_epoch: OWNER_ROOT_EPOCH,
                pointer_read_key: &POINTER_READ_KEY,
            },
            &CommittedSet {
                commitment: &fixture.grant_section.commitment,
                commitment_sig: &fixture.grant_section.commitment_sig,
                grant_ledger: &[],
                write_history_link: &[],
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
        assert_eq!(outcome, Err(ScopeRootPublishError::Rejected));
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
            Err(ScopeRootPublishError::Rejected),
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
            Err(ScopeRootPublishError::Rejected),
            "no ancestor seed means the gate cannot verify the ascent link",
        );
        block_on(
            harness
                .net_rooted(
                    RotationAncestry::default()
                        .under_parent_node_seed(CHILD_SCOPE, &parent_node_seed),
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
            assert_eq!(outcome, Err(ScopeRootPublishError::Rejected));
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
            Err(ScopeRootPublishError::Rejected),
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
            Err(ScopeRootPublishError::Rejected),
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
        assert_eq!(outcome, Err(ScopeRootPublishError::Rejected));
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
                    parent_node_seed: None,
                    pseudonym_signer: &pseudonym,
                },
                committed: CommittedSet {
                    commitment: &root.grant_section.commitment,
                    commitment_sig: &root.grant_section.commitment_sig,
                    grant_ledger: &[],
                    write_history_link: &[],
                    direct_child_scope_index: &[],
                },
                current_override_seed: &OWNER_ROOT_SCOPE_SEED,
                current_read_epoch: OWNER_ROOT_EPOCH,
                write_scope_seed: &OWNER_ROOT_WRITE_SCOPE_SEED,
                write_epoch: OWNER_ROOT_EPOCH,
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
        )
    }

    /// [`owner_scope_root`] at a chosen envelope version — every AAD in the
    /// record, section included, binds `v`.
    fn owner_scope_root_at(
        v: u64,
        scope_id: [u8; 16],
        override_seed: &[u8; 32],
        read_epoch: u64,
        parent_node_seed: Option<&[u8; 32]>,
        children: &[ChildScopeRef],
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
                parent_node_seed,
                pseudonym_signer: &pseudonym,
            },
            &ResealSeeds {
                override_seed,
                read_epoch,
                prev: None,
                write_scope_seed: &OWNER_ROOT_WRITE_SCOPE_SEED,
                write_epoch: OWNER_ROOT_EPOCH,
                pointer_read_key: &pointer_read_key,
            },
            &CommittedSet {
                commitment: &commitment,
                commitment_sig: &commitment_sig,
                grant_ledger: &[],
                write_history_link: &[],
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
            children: Vec::new(),
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
                    parent_node_seed: None,
                    pseudonym_signer: &pseudonym,
                },
                committed: CommittedSet {
                    commitment: &root.grant_section.commitment,
                    commitment_sig: &root.grant_section.commitment_sig,
                    grant_ledger: &[],
                    write_history_link: &[],
                    direct_child_scope_index: index,
                },
                current_override_seed: override_seed,
                current_read_epoch: read_epoch,
                write_scope_seed: &OWNER_ROOT_WRITE_SCOPE_SEED,
                write_epoch: OWNER_ROOT_EPOCH,
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
            Err(ScopeRootPublishError::LostRace),
            "a lost CAS race is reported, never a silent drop",
        );
    }

    // --- The write-plane name wave ([`WriteWaveNet`]) ---

    /// The write scope seed the wave moves TO — every new name derives from it.
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

    fn wave<'a, T: RecordTransport + Clone>(
        harness: &'a Harness<T>,
        owner: &'a EcdsaSigner,
        current_root: &'a IpnsName,
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
            gated_root: GatedWaveRoot::default(),
            subtree: WaveSubtree::default(),
            owner_pointer_seed: &OWNER_POINTER_SEED,
            current_root_name: current_root,
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
        let net = wave(&harness, &owner, &current_root);

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
            grants: Vec::new(),
        });
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name);

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
            grants: Vec::new(),
        });
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name);
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
        let net = wave(&harness, &owner, &root.name);
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
        let net = wave(&harness, &owner, &root.name);
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
        let net = wave(&harness, &owner, &root.name);
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
        let net = wave(&harness, &owner, &root.name);
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
        let net = wave(&harness, &owner, &root.name);
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
        let net = wave(&harness, &owner, &root.name);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        assert_eq!(
            block_on(net.republish(&moved)),
            Err(WritePublishError::Rejected)
        );
        assert!(!published_at(&harness, &moved.new_name));
    }

    #[test]
    fn a_ledger_row_whose_identity_key_is_not_a_curve_point_does_not_stop_the_wave() {
        // `recipientIdentityPk` feeds no derivation and no owner signature covers
        // it, so a committed write-grantee can set a victim's to any 33 bytes.
        // Parsing it at the re-mint would hand that grantee a free veto over the
        // very wave that revokes them; the row carries the bytes forward instead.
        let harness = Harness::plain();
        let mut rows = granted_rows();
        rows[0].ledger_entry.recipient_identity_pk = [0xff; IDENTITY_PUBLIC_LEN];
        let root = granted_root_with(rows, Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name);
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
        assert_eq!(
            body.grant_ledger
                .iter()
                .find(|e| e.tag == tag)
                .expect("the grantee's re-minted ledger row")
                .recipient_identity_pk,
            [0xff; IDENTITY_PUBLIC_LEN],
            "carried verbatim, like every other field no owner signature covers"
        );
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
        let net = wave(&harness, &owner, &root.name);
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

    #[test]
    fn the_wave_refuses_a_swapped_recipient_key_release_active() {
        // The re-mint owner-re-signs the set it builds, so a `recipientEncPk` a
        // committed write-grantee swapped under an owner-committed tag would be
        // laundered into owner authority. The refusal is a runtime `Err`, never
        // a debug_assert. Active in release.
        let harness = Harness::plain();
        let mut rows = granted_rows();
        rows[0].ledger_entry.recipient_enc_pk =
            X25519Secret::from_scalar([0x9f; 32]).public().to_bytes();
        let root = granted_root_with(rows, Vec::new());
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        assert_eq!(
            block_on(net.republish(&moved)),
            Err(WritePublishError::Rejected)
        );
        assert!(!published_at(&harness, &moved.new_name));
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
        let net = wave(&harness, &owner, &root.name);
        let moved = order(SCOPE, &root.name, BTreeMap::new(), true);
        assert_eq!(
            block_on(net.republish(&moved)),
            Err(WritePublishError::Rejected)
        );
        assert!(!published_at(&harness, &moved.new_name));
    }

    #[test]
    fn a_failed_root_publish_leaves_the_root_republishable() {
        // A pass that gated the root and then failed to publish retries off the
        // read it already holds — otherwise a wave interrupted between the two
        // re-reads a record whose section a still-committed writer may have
        // replaced in the meantime.
        let harness = Harness::plain();
        let root = owner_root_fixture(OwnerRootSpec {
            owner_identity: &owner_identity(),
            owner_enc: &owner_enc().public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children: Vec::new(),
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            grants: Vec::new(),
        });
        harness.stage(SCOPE, &root, Some(OWNER_ROOT_EPOCH));

        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name);

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
        let net = wave(&harness, &owner, &current_root);

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
        let net = wave(&harness, &owner, &current_root);
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
        let net = wave(&harness, &owner, &current_root);
        let interior = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &[0x3a; 16]);

        assert_eq!(
            block_on(net.retire(&[interior.clone(), current_root.clone()])),
            Err(WritePublishError::Rejected)
        );
        block_on(net.retire(&[interior])).expect("an interior-only batch retires");
    }

    #[test]
    fn the_canonical_repoint_lands_on_the_scope_pointer_record() {
        let harness = Harness::plain();
        let owner = owner_identity();
        let current_root = old_root_name();
        let net = wave(&harness, &owner, &current_root);
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
        let net = wave(&harness, &owner, &current_root);
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
        let net = wave(&harness, &owner, &current_root);
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
        assert_eq!(
            reseal_verdict(ResealError::Entropy(EntropyError::new("seam down"))),
            WritePublishError::NotLanded,
            "the entropy seam being down is availability, not a verdict on the section"
        );

        for terminal in [
            ResealError::LedgerDivergesFromCommitment,
            ResealError::SignerNotCommitted,
            ResealError::UnusableRecipientKey,
            ResealError::AscentLinkMismatch,
            ResealError::TooManyHistoryLinks,
            ResealError::TooManyCommittedGrants,
            ResealError::Encode(CodecError::Malformed(Malformed::DepthExceeded {
                offset: 0,
            })),
        ] {
            let check = terminal.check();
            assert_eq!(
                reseal_verdict(terminal),
                WritePublishError::Rejected,
                "{check} is deterministic on inputs the wave already gated; retrying never converges"
            );
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

    /// A staged, gate-passing scope root naming `children` and committing
    /// `child_scope_index`.
    fn staged_root(
        harness: &Harness<InMemoryRecordStore>,
        children: Vec<ChildRef>,
        child_scope_index: Vec<ChildScopeRef>,
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
            resume_write_scope_seed: Some(&FRESH_WRITE_SCOPE_SEED),
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
        let net = wave(&harness, &owner, &staged.root.name);

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
        let net = wave(&harness, &owner, &staged.root.name);

        assert_eq!(
            block_on(net.resolve_node(&SCOPE)),
            Err(ResolveFailure::Rejected),
            "MID's record carries no owner-signed commitment naming it a scope \
             root, so the claimed boundary is refused rather than honoured"
        );
    }

    #[test]
    fn a_node_no_gated_record_named_has_no_name_to_read_at() {
        let harness = Harness::plain();
        let staged = staged_scope(&harness);
        let owner = owner_identity();
        let net = wave(&harness, &owner, &staged.root.name);

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
        );
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name);

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
        let root = staged_root(&harness, vec![ref_to(MID, &served)], Vec::new());
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name);
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
        let root = staged_root(&harness, vec![ref_to(LEAF, &unserved)], Vec::new());
        let owner = owner_identity();
        let net = wave(&harness, &owner, &root.name);
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
        let net = wave(&harness, &owner, &staged.root.name);
        let mut entropy = SeededEntropy::new(13);

        let outcome = block_on(rotate_scope_write(
            &mut entropy,
            &net,
            &net,
            &write_plan(&staged.root, &owner),
        ))
        .expect("the wave completes over the production seams");

        assert_eq!(outcome.new_write_epoch, OWNER_ROOT_EPOCH + 1);
        assert_eq!(
            outcome.new_root_name,
            derive_write_name(&FRESH_WRITE_SCOPE_SEED, &SCOPE)
        );
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
                .find(|text| {
                    *text == derive_write_name(&FRESH_WRITE_SCOPE_SEED, &expected).as_str()
                })
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
    fn a_resumed_wave_re_resolves_the_subtree_from_published_records_alone() {
        // A crash leaves the durable floors raised, so the resumed pass reads its
        // own un-re-pointed root back with no in-memory carry from the pass that
        // raised them.
        let harness = Harness::plain();
        let staged = staged_scope(&harness);
        let owner = owner_identity();

        let first = wave(&harness, &owner, &staged.root.name);
        let before: Vec<WriteScopeNode> = [SCOPE, MID, LEAF]
            .into_iter()
            .map(|id| block_on(first.resolve_node(&id)).expect("the first pass enumerates"))
            .collect();
        drop(first);

        let resumed = wave(&harness, &owner, &staged.root.name);
        let after: Vec<WriteScopeNode> = [SCOPE, MID, LEAF]
            .into_iter()
            .map(|id| block_on(resumed.resolve_node(&id)).expect("the resumed pass enumerates"))
            .collect();

        assert_eq!(before, after);
    }
}
