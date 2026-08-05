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
use std::collections::BTreeMap;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, ChildScopeRef, Envelope, GrantSection, PreservedFields, ReadBody,
    STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_WRITE_BODY, WriteBody, decode_write_body, open_owner_blob,
    unseal,
};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use super::adopter::RootAdopter;
use super::author::{AuthorError, ENVELOPE_V, EnvelopeAuthoring, author_scope_root_with_section};
use super::publish::PublishOutcome;
use super::record_publish::{HeadBinding, RecordPublishRequest, preflight, publish_record};
use crate::api::ApiClient;
use crate::content::Gateway;
use crate::entropy::Entropy;
use crate::gate::{GateError, floor};
use crate::net::fanout_get_verify;
use crate::profile::SyncTimingProfile;
use crate::rotation::{
    CascadeResealResolver, CascadeTarget, ChildIndexResolver, ResealedScopeRoot, ResolveFailure,
    ScopeRootPublishError, ScopeRootPublisher,
};
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};
use crate::session::SessionIdentity;

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
/// Adoption advances the durable **sequence** floor, so a second read of the
/// same record rejects as not-newer (`gate/adoption.rs` stage 4). A cascade
/// resolves a descendant and then immediately publishes its re-key, which would
/// be two reads of one record — so the resolve parks what the publish needs and
/// the publish takes it. One slot, because that hand-off is the only contract:
/// a second park evicts the first rather than retaining every descendant's
/// record for the length of the walk.
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
    /// Seed the walk at the rotating root: its own override seed, plus the
    /// parent edge for each entry of its caller-held direct-child-scope index.
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

/// Carry an authoring refusal into the publish arm on the same rule-6 axis. A
/// trust refusal is this build's own gate verdict on the bytes it was about to
/// sign, reached before the PUT: re-authoring the same section reaches it again.
/// A codec or size refusal is a property of the body this pass built from the
/// record it just resolved, and the next pass resolves that record again — so it
/// stays retryable rather than permanently blocking a revocation over bytes a
/// later read may not carry.
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

impl<T, H: Http, C: CredentialStore, F, Sch, E> OwnerRotationNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport,
    F: FloorStore,
{
    /// The root this pass already gated ([`GatedRoots`]), else the freshest
    /// verified record at `name` run through the adoption gate under
    /// `scope_id` — the caller's own trusted label, imposed
    /// on the gate so a record claiming another scope is a transplant it
    /// rejects ([`ChildIndexResolver::direct_child_index`]'s binding obligation).
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
        let (candidate, outcome) =
            adopter
                .adopt_root(name, &record_bytes)
                .await
                .map_err(|error| match error {
                    GateError::Rejected(_) => ResolveFailure::Rejected,
                    GateError::Seam(_) => ResolveFailure::Unavailable,
                })?;
        let read_scope_seed = outcome.read_scope_seed.ok_or(ResolveFailure::Unavailable)?;
        Ok(GatedScopeRoot {
            envelope: candidate.envelope,
            section: candidate.grant_section,
            read_body: outcome.adopted.read_body,
            read_scope_seed,
            write_scope_seed: outcome.write_scope_seed,
        })
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
        let write_seed = kdf::write_seed(write_scope_seed, &scope_id);
        let write_key = kdf::write_key(write_seed.as_bytes());
        let env = &root.envelope;
        let ctx = AadContext {
            v: env.v,
            id: env.id,
            scope: env.scope,
            epoch: write_epoch,
            struct_tag: STRUCT_TAG_WRITE_BODY,
        };
        // The gate authenticated this structure's detached signature; the unseal
        // is what proves it is *this* scope's write-body at *this* write epoch.
        let plaintext = Zeroizing::new(
            unseal(write_key.as_bytes(), &ctx, &root.section.write_body.sealed)
                .map_err(|_| ResolveFailure::Rejected)?,
        );
        let body = decode_write_body(&plaintext).map_err(|_| ResolveFailure::Rejected)?;
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
    /// Runs **after** this pass's gated read of the scope root, whose adoption
    /// advances the read-epoch floor: measured before it, the floor comparison
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use crate::content::dag::root_block_cid;
    use cipherbox_core::ipns::{IpnsRecord, VerifiedRecord};
    use cipherbox_core::seal::{
        AscentLink, GrantSetCommitment, STRUCT_TAG_ASCENT_LINK, decode_envelope,
        decode_grant_section, encode_envelope, encode_grant_section, grant_section_bytes,
        open_ascent_link, open_read_body, seal_read_body, set_grant_section, sign_grant_set,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use cipherbox_core::suite::secret::ct_eq;

    use super::*;
    use crate::content::GatewaySource;
    use crate::rotation::{
        CommittedSet, PrevEpochSeed, ResealSeeds, RotateScopePlan, ScopeRootIdentity,
        cascade_rotate_scope, enumerate_eager_set, reseal_scope_root, rotate_scope,
    };
    use crate::seams::{EndpointId, HttpResponse, SeamError, SeamResult};
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
        for _ in 0..64 {
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
        /// ascent link — the ancestry the walk extends from.
        fn net(&self, root_child_index: &[ChildScopeRef]) -> Net<'_, T> {
            self.net_rooted(RotationAncestry::rooted_at(
                SCOPE,
                &OWNER_ROOT_SCOPE_SEED,
                root_child_index,
            ))
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

    /// What [`GatedRoots`] exists for: discard the parked read and the record
    /// the pass already adopted is unreadable.
    #[test]
    fn a_scope_root_this_pass_already_adopted_cannot_be_read_again() {
        let (_, child, child_ref) = owner_tree();
        let harness = Harness::plain();
        harness.stage(CHILD_SCOPE, &child, Some(OWNER_ROOT_EPOCH));
        let net = harness.net(core::slice::from_ref(&child_ref));

        block_on(net.resolve(&child_ref)).expect("the first read");
        net.gated
            .take(&child.name)
            .expect("the resolve parked its gated read for the publish");
        assert_eq!(
            block_on(net.resolve(&child_ref)).err(),
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

        // The plan re-seals the root the harness staged, so its committed set and
        // signer come off that fixture rather than being rebuilt beside it.
        let pseudonym = OwnerSeeds.writer_pseudonym(&SCOPE);
        let owner_enc_pub = owner_enc().public();
        let pointer_read_key = OwnerSeeds.pointer_read_key(&SCOPE);
        let index = vec![child_ref.clone()];
        let mut entropy = SeededEntropy::new(41);
        let net = harness.net(&index);

        let outcome = block_on(cascade_rotate_scope(
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
                    parent_node_seed: None,
                    pseudonym_signer: &pseudonym,
                },
                committed: CommittedSet {
                    commitment: &root.grant_section.commitment,
                    commitment_sig: &root.grant_section.commitment_sig,
                    grant_ledger: &[],
                    write_history_link: &[],
                    direct_child_scope_index: &index,
                },
                current_override_seed: &OWNER_ROOT_SCOPE_SEED,
                current_read_epoch: OWNER_ROOT_EPOCH,
                write_scope_seed: &OWNER_ROOT_WRITE_SCOPE_SEED,
                write_epoch: OWNER_ROOT_EPOCH,
                pointer_read_key: &pointer_read_key,
                carried_history_links: &[],
            },
            || Box::pin(async {}),
        ))
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
}
