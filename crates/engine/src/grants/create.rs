//! Owner-side grant creation (blueprint/engine.md "Grants and ledger: Grant
//! creation").
//!
//! Mints the owner-only sharing path in the sequence the blueprint fixes:
//! converge the subtree, mint the grantee scope at read epoch 1, publish
//! grantee-first, re-seal the granted folder's interior nodes into that scope,
//! re-key the reparented descendants under the fresh derivation, update the
//! parent index, and — for a write grant, after the name wave — post the sealed
//! share pointer ([`post_share_pointer`]). Convergence is the load-bearing
//! correctness rule — a grant over a subtree that cannot be proven
//! epoch-converged is refused **fail-closed**, so a new grantee can never regress
//! through an ancestor scope's history (CONTEXT.md "Epoch-converged").
//!
//! A **write** grant owes one further step this module does not run: the name
//! wave that moves the minted scope off the names the scope it left derives.
//! [`GranteeScopePlan::write_cut`] carries the fresh seed the mint seals under;
//! the wave itself is
//! [`rotate_scope_write`](crate::rotation::rotate_scope_write), driven by the
//! caller over the minted root. The pointer post is split out of
//! [`create_grant`] so the caller runs it past that wave: a pointer naming the
//! scope root the wave moves off would send the grantee to a name their own
//! seed does not derive.
//!
//! # Simulation boundary
//!
//! Deterministic-simulation slice: entropy is the injected [`Entropy`] seam and
//! the read/floor/publish/mailbox effects are faked in tests. Every seam this
//! composes over has a production implementation in [`crate::net::rotation`].
//!
//! # Not implemented here
//!
//! - **Invites**: ephemeral-key blobs, bearer write-link flagging, claim
//!   conversion.
//!
//! This module composes existing machinery only and holds no crypto of its own.

use cipherbox_core::error::CodecError;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildScopeRef, GrantLedgerEntry, GrantSetCommitment, GrantSetEntry, Permission,
    PreservedFields, ReadBody, SignedSealed, sign_grant_set,
};
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier, SIGNATURE_LEN as ECDSA_SIG_LEN};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use core::fmt;
use zeroize::Zeroizing;

use crate::entropy::{Entropy, EntropyError, fresh_bytes, fresh_ephemeral, fresh_seed};
use crate::grants::SharePointer;
use cipherbox_core::payload::RepointObject;

use crate::grants::child_index::{canonicalize, insert_child, remove_child};
use crate::grants::contact::Contact;
use crate::grants::{GrantRow, mint_grant_row};
use crate::mailbox::post_sealed;
use crate::rotation::sweep::{body_children, canonicalize_frontier, resolve_scope_current};
use crate::rotation::{
    AscentAuthority, CascadeResealResolver, CommittedSet, NodeRef, ResealError, ResealSeeds,
    ResealedScopeRoot, ResolveFailure, RotationPublishError, ScopeRootIdentity, ScopeRootPublisher,
    SweepError, SweepPublisher, SweepResolveFailure, SweepResolver, SweptChild, WriteHistory,
    converge_subtree, derive_write_name, reseal_scope_root,
};
use crate::seams::{Mailbox, SeamError};
use cipherbox_core::hex::lower as hex_lower;
use cipherbox_core::ipns::IpnsName;
use std::collections::BTreeSet;

/// The fresh grantee scope minted at the granted folder. `scope_id` is the
/// folder's node id (a scope root's node id is its scope id). The mint anchors
/// the read plane at epoch 1.
///
/// The scope root's `ipnsName` is **derived** from `write_scope_seed` +
/// `scope_id`, never accepted as input: the blinded tag and the commitment both
/// bind that name, so binding them to anything but the folder's real resolvable
/// name (which the recipient re-derives from the record it resolves) would mint
/// a grant the recipient can never self-locate.
pub struct GranteeScopePlan<'a> {
    /// Payload/format version bound into every AAD context.
    pub v: u64,
    /// The granted folder's node id == the new scope id.
    pub scope_id: [u8; 16],
    /// `nodeSeed(folder)` derived in the **parent** scope — seals the ascent
    /// link so only ancestor-scope readers descend.
    pub parent_node_seed: &'a [u8; SECRET_LEN],
    /// The vault owner's encryption subkey public key — the owner-blob target.
    pub owner_enc_pub: &'a X25519Public,
    /// The folder's **current** write-scope seed — the scope it is leaving, and
    /// what its resolvable name derives from ([`Self::ipns_name`]).
    pub write_scope_seed: &'a [u8; SECRET_LEN],
    /// The freshly minted write-scope seed a **write** grant seals the new scope
    /// under, or `None` for a read grant (which cuts no write scope).
    ///
    /// A `Permission::Write` row's grant blob carries this value verbatim
    /// (`rotation/reseal.rs`), so a write grant that fell back to
    /// [`write_scope_seed`](Self::write_scope_seed) would hand the grantee every
    /// name in the scope the folder is leaving. The name wave that follows the
    /// mint is what moves the subtree onto names the granted scope's own seed
    /// derives (blueprint/engine.md "Grant creation").
    pub write_cut: Option<&'a [u8; SECRET_LEN]>,
    /// The scope's pointer read key.
    pub pointer_read_key: &'a [u8; SECRET_LEN],
    /// The descendant scope roots inside the folder: converged before minting,
    /// reparented into the new scope's direct-child-scope index, and re-keyed so
    /// each one's ascent link seals under `node_seed(fresh_override_seed,
    /// descendant.scope_id)` (blueprint/engine.md "subtree swept in").
    pub subtree_child_index: &'a [ChildScopeRef],
}

impl GranteeScopePlan<'_> {
    /// The scope root's `ipnsName`, derived rather than accepted — the sole
    /// gated identity edge (see the type's own rationale). Every mint over this
    /// plan binds the same bytes because they all read it here.
    pub fn ipns_name(&self) -> IpnsName {
        derive_write_name(self.write_scope_seed, &self.scope_id)
    }

    /// The permission this plan mints at, **derived** from
    /// [`write_cut`](Self::write_cut) rather than taken as its own parameter.
    ///
    /// A `Permission::Write` row's blob carries
    /// [`sealed_write_scope_seed`](Self::sealed_write_scope_seed) verbatim, so a
    /// write permission paired with no cut would seal the seed that derives
    /// every name in the scope the folder is leaving. Reading one off the other
    /// makes that pair unrepresentable instead of refusing it after the fact.
    pub fn permission(&self) -> Permission {
        match self.write_cut {
            Some(_) => Permission::Write,
            None => Permission::Read,
        }
    }

    /// The write-scope seed the minted scope's blobs and owner-write blob are
    /// sealed under — the cut for a write grant, the inherited seed otherwise.
    fn sealed_write_scope_seed(&self) -> &[u8; SECRET_LEN] {
        self.write_cut.unwrap_or(self.write_scope_seed)
    }
}

/// The recipient of the read grant.
pub struct GrantRecipient<'a> {
    /// The verified recipient. The identity key is the ledger entry and the
    /// mailbox routing address; the encryption subkey is the grant-blob and
    /// mailbox HPKE wrap target. A [`Contact`] is the pair as its holder signed
    /// it, so the two cannot be sourced apart — the key substitution the
    /// binding signature exists to deny is unrepresentable here.
    ///
    /// [`Contact`]: super::Contact
    pub contact: &'a Contact,
    /// Courtesy host label carried in the share pointer.
    pub display_name: String,
}

impl GrantRecipient<'_> {
    /// The recipient's identity key: the ledger entry and the mailbox address.
    fn identity_pk(&self) -> EcdsaVerifier {
        self.contact.identity_pk()
    }

    /// The recipient's bound encryption subkey: the HPKE wrap target.
    fn enc_pub(&self) -> X25519Public {
        self.contact.enc_subkey()
    }
}

/// Owner-held key material for the grant. `pseudonym_signer` must be the
/// owner's writer pseudonym for the new scope; its public key becomes the
/// commitment's `owner_pseudonym_pk` and reseal signs every structure with it.
pub struct OwnerGrantKeys<'a> {
    /// Owner encryption subkey secret — the pairwise ECDH half for the blinded
    /// tag and the recipient's writer pseudonym.
    pub enc_secret: &'a X25519Secret,
    /// Owner identity signer — signs the grant-set commitment; its
    /// verifying key is the sharer identity in the share pointer.
    pub identity_signer: &'a EcdsaSigner,
    /// Owner writer pseudonym for the new scope — reseals its structures.
    pub pseudonym_signer: &'a Ed25519Signer,
}

/// The parent scope root that gains the new child (and sheds any descendant
/// scope roots moved into the new scope). Its `seeds` are its **current**
/// read-plane seeds (`prev = None`): updating the index is a metadata-only
/// re-seal at the same epoch.
pub struct ParentScopePlan<'a> {
    /// The parent scope root's identity + signing capability.
    /// [`ScopeRootIdentity::owner_enc_secret`] is overridden with the owner's own
    /// subkey, so this plan cannot disable the parent's tag-binding check.
    ///
    /// [`ScopeRootIdentity::owes_ascent_link`] is **not** overridden and is the
    /// caller's to get right: granting inside an already-granted scope makes the
    /// parent itself a descendant, and its re-seal must keep its ascent link.
    pub identity: ScopeRootIdentity<'a>,
    /// The parent's current read-plane seeds (`prev = None`).
    pub seeds: ResealSeeds<'a>,
    /// The parent's owner-signed grant-set commitment.
    pub commitment: &'a GrantSetCommitment,
    /// The parent's commitment signature.
    pub commitment_sig: &'a [u8; ECDSA_SIG_LEN],
    /// The parent's grant ledger (unchanged by this op).
    pub grant_ledger: &'a [GrantLedgerEntry],
    /// The parent's current direct-child-scope index (before this grant).
    pub current_child_index: &'a [ChildScopeRef],
    /// The parent's carried read-plane history links.
    pub carried_history_links: &'a [SignedSealed],
}

/// The result of a successful read-grant creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateGrantOutcome {
    /// The new grantee scope id.
    pub scope_id: [u8; 16],
    /// The recipient's blinded tag committed at the new scope root.
    pub tag: [u8; 32],
    /// The parent's direct-child-scope index after the reparent + insert.
    pub parent_child_index: Vec<ChildScopeRef>,
}

/// A read-grant creation failure.
///
/// Failures **through the grantee scope-root publish** are truly
/// fail-closed — nothing is minted or shared. Failures **after** that publish
/// are NOT atomic: the grantee root is already committed to the network, so a
/// stale orphan can outlive the error. Each post-publish variant below documents
/// what it leaves behind; no reconciliation pass reclaims those orphans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateGrantError {
    /// The pre-grant convergence sweep aborted (enumeration/floor/publish/reseal).
    Converge(SweepError),
    /// The subtree could not be proven epoch-converged: convergence work was
    /// dropped on a lost CAS race, so the grant is refused rather than minted
    /// over a possibly-lagging subtree.
    SubtreeNotConverged {
        /// The interior nodes left unproven this pass — dropped on a lost CAS
        /// race, or unreadable at the epoch their record claims.
        unconverged: Vec<[u8; 16]>,
    },
    /// The convergence pass and the grant plan disagree about which descendant
    /// scope roots the granted folder holds. The pass reads the live tree and
    /// the plan filters a cached snapshot, so a committed writer of the scope
    /// the folder is leaving moves a descendant scope root across the folder
    /// boundary to drive them apart. Either direction is refused before the
    /// promotion publishes: a plan entry the pass did not meet re-keys a
    /// descendant the folder no longer holds under the grantee's derivation,
    /// and a scope root the pass met that the plan omits leaves the grantee a
    /// child ref no derivation of theirs follows.
    SubtreeBoundaryDiverged {
        /// Scope roots the plan names that the pass did not meet in the folder.
        planned_not_met: Vec<[u8; 16]>,
        /// Scope roots the pass met in the folder that the plan does not name.
        met_not_planned: Vec<[u8; 16]>,
    },
    /// The recipient encryption key is non-contributory (degenerate ECDH).
    UnusableRecipientKey,
    /// The recipient's encryption subkey is the vault owner's own: the owner
    /// already outranks every grantee, so the grant confers nothing while
    /// consuming a commitment slot and filing the owner's pseudonym as a third
    /// party's. The invite path's
    /// [`ClaimantIsTheOwner`](super::InviteError::ClaimantIsTheOwner) refuses
    /// the same input.
    RecipientIsTheOwner,
    /// Encoding/signing the grant-set commitment failed (fail-closed codec).
    CommitmentEncode(CodecError),
    /// Entropy acquisition failed (seed mint or mailbox ephemeral).
    Entropy(EntropyError),
    /// Assembling the grantee scope root failed (pre-publish: fail-closed).
    Mint(ResealError),
    /// Publishing the grantee scope root failed (register-first: nothing was
    /// pushed, so this is still fail-closed).
    Publish(RotationPublishError),
    /// Reading the scope root a previous attempt already promoted failed, so
    /// this call cannot tell a stalled grant from a fresh one. Pre-publish:
    /// fail-closed.
    Resume(ResolveFailure),
    /// The promoted root at the granted folder is not the one this plan minted:
    /// it commits no row for this recipient, or it reparented a different set of
    /// descendant scope roots. Refused rather than resumed, so a second
    /// recipient is never grafted onto a scope that commits nothing for them.
    ResumeNotThisGrant,
    /// The granted folder carries a read-epoch floor this device raised, and the
    /// resume probe found no promotion of it to resume: a live scope root this
    /// grant did not publish stands at the name a mint would publish at, and a
    /// fresh mint there would draw a second override seed over it.
    TargetAlreadyNamesAScope,
    /// Resolving a reparented descendant for its re-key failed. Post-publish: the
    /// grantee root and any earlier-re-keyed descendants are committed; this one
    /// keeps its old parent derivation (grantee cannot yet descend into it).
    DescendantResolve {
        /// The descendant that could not be resolved.
        scope_id: [u8; 16],
        /// The fail-closed resolve failure.
        reason: ResolveFailure,
    },
    /// Reading an interior node of the granted folder for its re-seal failed.
    /// Post-publish: the folder answers as a scope root of the new scope, so a
    /// node this leg did not move stays sealed under the scope the folder left,
    /// which readers of neither scope open. Re-driving the same grant resumes
    /// the move against the root already published and finishes it.
    InteriorResolve {
        /// The node that could not be read.
        node_id: [u8; 16],
        /// The fail-closed read failure.
        reason: SweepResolveFailure,
    },
    /// The walk met a node the convergence pass did not measure as interior: a
    /// body re-authored since that pass, or a node that now answers as a scope
    /// root. Either way the re-seal refuses rather than move a record the gate
    /// never proved into the grantee's scope. Only a committed writer of the
    /// scope the folder is leaving can author either.
    InteriorNotConverged {
        /// The node the walk met.
        node_id: [u8; 16],
    },
    /// The walk met an interior node whose record no longer carries the read
    /// epoch the convergence pass proved its scope at: the record regressed
    /// after the proof. The proof is what convergence rests on, so the walk
    /// refuses rather than seal a record it no longer covers into the grantee's
    /// scope.
    InteriorEpochRegressed {
        /// The node whose record left the proved epoch.
        node_id: [u8; 16],
    },
    /// Re-sealing an interior node of the granted folder under the fresh
    /// derivation failed, or its CAS publish lost the race. Post-publish: same
    /// partial-commit surface as `InteriorResolve`, re-drivable the same way,
    /// and a lost race is an error rather than a dropped node for the same
    /// reason.
    InteriorPublish {
        /// The node whose re-sealed record did not land.
        node_id: [u8; 16],
        /// The publish failure.
        error: RotationPublishError,
    },
    /// Re-sealing a reparented descendant's ascent link under the fresh grantee
    /// derivation failed. Post-publish: same partial-commit surface as
    /// `DescendantResolve`.
    DescendantMint {
        /// The descendant that could not be re-sealed.
        scope_id: [u8; 16],
        /// The underlying re-seal rejection.
        error: ResealError,
    },
    /// Publishing a re-keyed descendant failed. Post-publish: the grantee root and
    /// any earlier-re-keyed descendants are committed; this one keeps its old
    /// parent derivation.
    DescendantPublish {
        /// The descendant whose re-keyed record did not land.
        scope_id: [u8; 16],
        /// The publish failure.
        error: RotationPublishError,
    },
    /// Re-sealing the reparented parent scope root failed. Post-publish: the
    /// grantee root is already on the network with no parent reference.
    ParentMint(ResealError),
    /// Publishing the reparented parent scope root failed. Post-publish: the
    /// grantee root is already on the network with no parent reference.
    ParentPublish(RotationPublishError),
    /// Vouching for the scope on the owner's pointer plane failed
    /// ([`ScopePointerVoucher`]). Pre-publish: no scope root is promoted, so
    /// the cut refuses with no scope in existence that no plane speaks for.
    VouchScope(RotationPublishError),
    /// Posting the sealed share pointer to the recipient mailbox failed
    /// ([`post_share_pointer`]). Both scope roots are published, the parent
    /// index is updated and any write-scope cut has landed; only the share
    /// pointer is missing, so the grantee never learns of a scope that exists. A
    /// retry posts a fresh item — delivery is at-least-once, and the accept flow
    /// is the dedup point.
    Mailbox(SeamError),
}

impl CreateGrantError {
    /// A stable machine tag for assertions and host classification.
    pub fn check(&self) -> &'static str {
        match self {
            Self::Converge(_) => "converge-failed",
            Self::SubtreeNotConverged { .. } => "subtree-not-converged",
            Self::SubtreeBoundaryDiverged { .. } => "subtree-boundary-diverged",
            Self::UnusableRecipientKey => "unusable-recipient-key",
            Self::RecipientIsTheOwner => "recipient-is-the-owner",
            Self::CommitmentEncode(_) => "commitment-encode-failed",
            Self::Entropy(_) => "entropy-error",
            Self::Mint(_) => "mint-failed",
            Self::Publish(_) => "publish-failed",
            Self::Resume(_) => "resume-probe-failed",
            Self::ResumeNotThisGrant => "resume-not-this-grant",
            Self::TargetAlreadyNamesAScope => "target-already-names-a-scope",
            Self::InteriorResolve { .. } => "interior-resolve-failed",
            Self::InteriorNotConverged { .. } => "interior-not-converged",
            Self::InteriorEpochRegressed { .. } => "interior-epoch-regressed",
            Self::InteriorPublish { .. } => "interior-publish-failed",
            Self::DescendantResolve { .. } => "descendant-resolve-failed",
            Self::DescendantMint { .. } => "descendant-mint-failed",
            Self::DescendantPublish { .. } => "descendant-publish-failed",
            Self::ParentMint(_) => "parent-mint-failed",
            Self::ParentPublish(_) => "parent-publish-failed",
            Self::VouchScope(_) => "vouch-scope-failed",
            Self::Mailbox(_) => "mailbox-post-failed",
        }
    }
}

impl fmt::Display for CreateGrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "grant creation failed: {}", self.check())
    }
}

impl std::error::Error for CreateGrantError {}

/// Every network leg a grant mint reads and publishes through. One value
/// serves them all: the resolver and the publisher have never differed.
pub trait MintNet:
    SweepResolver
    + CascadeResealResolver
    + GrantResumeResolver
    + ScopeRootPublisher
    + SweepPublisher
    + ScopeRootPromoter
    + InteriorResealer
{
}

impl<N> MintNet for N where
    N: SweepResolver
        + CascadeResealResolver
        + GrantResumeResolver
        + ScopeRootPublisher
        + SweepPublisher
        + ScopeRootPromoter
        + InteriorResealer
{
}

/// Publish a node that is becoming a scope root for the **first time**.
///
/// Distinct from [`ScopeRootPublisher`], which CAS-publishes a re-sealed scope
/// root over the record it replaces: a promotion has no such record. Its base is
/// the granted node's own **child** record — the read body it already publishes,
/// plus the write scope seed it inherits from the scope it is leaving, since a
/// read grant cuts no write scope. Gating that record as a scope root, which it
/// is not yet, refuses every honest promotion.
pub trait ScopeRootPromoter {
    /// Publish `record` at the granted node's name, over the node's current
    /// gated child record inside `parent`. A node whose current record does not
    /// gate — or which already answers as a scope root — is a fail-closed
    /// refusal, never a publish under a fabricated body.
    ///
    /// Returns the children of the body it promoted. That body is the new scope
    /// root's, so its children are the interior the fresh scope now owns: taking
    /// them from the publish rather than from a read of the caller's own binds
    /// the re-seal to the record this call made current.
    async fn promote_scope_root(
        &self,
        parent: &ChildScopeRef,
        node: &NodeRef,
        record: &ResealedScopeRoot,
    ) -> Result<Vec<NodeRef>, RotationPublishError>;
}

/// The two reads a stalled grant's resume runs — the read-side counterpart of
/// [`ScopeRootPromoter`] and [`InteriorResealer`], on the rule
/// [`WriteSubtreeResolver::recover_wave`](crate::rotation::WriteSubtreeResolver)
/// already follows: crash recovery is a resolve, and nothing here publishes.
///
/// The mint and the interior move it owes are not atomic. Both methods exist so
/// a move that stalled part way finishes against the root the first attempt
/// published, rather than minting a second scope over the same folder — which
/// would draw a second override seed and strand every node already moved.
pub trait GrantResumeResolver {
    /// The scope root a previous attempt already promoted at `node`, or `None`
    /// when `node` is still an ordinary child of `parent`.
    ///
    /// Gated as a descendant scope root of `parent`: the record answers at the
    /// name the folder derives, carries `node`'s id, and binds an ascent link
    /// under `nodeSeed(parent read seed, node)`. `parent` must be the ref
    /// [`SweepResolver::resolve_scope`] proved current.
    async fn promoted_root(
        &self,
        parent: &ChildScopeRef,
        node: &NodeRef,
    ) -> Result<Option<PromotedScopeRoot>, ResolveFailure>;

    /// Read `node` as a record a stalled move already published into `root`, or
    /// `None` when the record at its name claims another scope.
    ///
    /// Authenticity comes from `root`'s own derivation — the override seed out
    /// of its section's owner blob, at the epoch the record claims — so `None`
    /// never widens what a walk admits.
    async fn moved_interior_node(
        &self,
        root: &ResealedScopeRoot,
        node: &NodeRef,
    ) -> Result<Option<ReadBody>, SweepResolveFailure>;

    /// Whether this device holds a read-epoch floor at `node`'s own scope id.
    ///
    /// Only a scope root adopted at that id raises one, so the floor tells a
    /// live scope from a name the gate merely rejects at. It is read **after**
    /// [`promoted_root`](Self::promoted_root) answers `None`: a promotion this
    /// grant may resume carries the same floor, and refusing ahead of the probe
    /// makes a grant that stalls twice unshareable for ever.
    async fn holds_a_scope_root_floor(&self, node: &NodeRef) -> Result<bool, ResolveFailure>;
}

/// The scope root a stalled grant already published over the granted folder, as
/// the gate authenticated it.
pub struct PromotedScopeRoot {
    /// The published root. Typed as a re-seal's output because that is what the
    /// interior move's publish arm reads its scope and epoch out of; nothing
    /// here is re-sealed.
    pub record: ResealedScopeRoot,
    /// The scope's override seed, recovered from `record`'s own owner blob —
    /// the ancestor seed each reparented descendant's ascent link derives from,
    /// as [`CascadeTarget`](crate::rotation::CascadeTarget) carries one.
    pub override_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The children of the published root's body — the interior frontier.
    pub children: Vec<NodeRef>,
    /// The root's own published direct-child-scope index: the descendant scope
    /// roots the move stops at.
    pub boundaries: Vec<ChildScopeRef>,
}

/// The scope root one grant's interior move and descendant re-key both run
/// against, whether this call minted it or picked up a stalled attempt's.
struct GrantedRoot {
    record: ResealedScopeRoot,
    override_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The children of the root's own body — the walk's first level.
    frontier: Vec<NodeRef>,
    bounds: InteriorBounds,
}

/// What the interior walk may move, and at what epoch.
struct InteriorBounds {
    /// The read epoch the scope the folder is leaving was gated at.
    source_read_epoch: u64,
    /// The descendant scope roots the walk stops at.
    stop_at: BTreeSet<[u8; 16]>,
    /// The interior the convergence pass measured, which bounds what the walk
    /// may move. `None` on a resume, which runs no pass and so admits every
    /// node the gate authenticates in one of the two scopes. That widens the
    /// splice window a committed writer of the leaving scope already holds,
    /// from "between the pass and the mint" to "between the two attempts"; the
    /// bound the resume owes is not landed.
    measured: Option<BTreeSet<[u8; 16]>>,
}

/// One interior node's record, as the read that hands it to a publish found it.
/// Carries no epoch: an interior record is sealed at the epoch of the scope root
/// it belongs to, and that scope is the publisher's to name.
pub struct InteriorRecord<'a> {
    /// The node id, as the gated parent body named it.
    pub node_id: [u8; 16],
    /// That ref's opaque `ipnsName` bytes — the publish destination.
    pub ipns_name: &'a [u8],
    /// The sequence of the record this body came from: the CAS basis the re-seal
    /// must land above.
    pub sequence: u64,
    /// The body carried forward verbatim.
    pub read_body: &'a ReadBody,
    /// Envelope fields a republish preserves byte-stable.
    pub carried_unknown: &'a PreservedFields,
    /// `epochTag` fields a republish preserves byte-stable.
    pub carried_epoch_tag_unknown: &'a PreservedFields,
}

/// Re-seal one interior node into the scope a grant just minted over it.
///
/// Distinct from [`SweepPublisher::publish_node`], which advances a node inside
/// the scope it already belongs to: here the node **changes scope**, so the AAD
/// scope binding and the read key both come from `root`, while the name and the
/// key that signs at it still come from `source` — the scope the folder left,
/// whose write seed derives that name until a write grant's name wave moves it.
pub trait InteriorResealer {
    /// Re-seal `node`'s carried body under `root`'s derivation at `root`'s read
    /// epoch and CAS-publish it at the name it answers today. `source` is the
    /// ref [`SweepResolver::resolve_scope`] proved current for the scope the
    /// node is leaving.
    async fn reseal_interior_node(
        &self,
        source: &ChildScopeRef,
        root: &ResealedScopeRoot,
        node: &InteriorRecord<'_>,
    ) -> Result<(), RotationPublishError>;
}

/// Vouch for a scope on the owner's pointer plane, before its root exists.
///
/// A promoted scope root is the one scope root no plane speaks for on its own:
/// the vault root has the vault pointer and a rotated scope has the re-point
/// its own flip published, while a scope a read grant has just cut has neither.
/// The mint states its epoch here so that every later reader has proof rather
/// than an inference (`crate::net::rotation`
/// `recover_write_plane_from_pointer`).
pub trait ScopePointerVoucher {
    /// Publish `repoint`, owner-signed, at its scope's pointer name.
    async fn vouch_scope(&self, repoint: &RepointObject) -> Result<(), RotationPublishError>;
}

/// The read and write epoch a grant cut mints a promoted scope root at.
pub(crate) const MINT_EPOCH: u64 = 1;

/// Mint a grant for one recipient over `grantee`'s folder at `permission`.
///
/// The recipient's row over [`mint_grantee_scope`]. Fail-closed **through the
/// grantee publish**; past that point the sequence is not atomic — see
/// [`CreateGrantError`] for what each post-publish variant leaves committed.
///
/// The permission comes from [`GranteeScopePlan::permission`], so a write grant
/// owes [`GranteeScopePlan::write_cut`] by construction. It additionally owes
/// the name wave over the minted scope, which the caller runs once this returns,
/// and then [`post_share_pointer`] (blueprint/engine.md "Grant creation").
pub async fn create_grant<E, N, V>(
    entropy: &mut E,
    net: &N,
    voucher: &V,
    grantee: &GranteeScopePlan<'_>,
    recipient: &GrantRecipient<'_>,
    owner: &OwnerGrantKeys<'_>,
    parent: &ParentScopePlan<'_>,
) -> Result<CreateGrantOutcome, CreateGrantError>
where
    E: Entropy,
    N: MintNet,
    V: ScopePointerVoucher,
{
    let recipient_enc_pub = recipient.enc_pub();
    // Refused ahead of the publishing sweep, so a self-grant costs no publish.
    if recipient_enc_pub == owner.enc_secret.public() {
        return Err(CreateGrantError::RecipientIsTheOwner);
    }
    let ipns_name = grantee.ipns_name();
    let name_bytes = ipns_name.as_str().as_bytes();
    let permission = grantee.permission();
    let row = mint_grant_row(
        owner.identity_signer,
        owner.enc_secret,
        grantee.pointer_read_key,
        recipient.identity_pk().to_sec1(),
        &recipient_enc_pub,
        &grantee.scope_id,
        name_bytes,
        permission,
    )
    .ok_or(CreateGrantError::UnusableRecipientKey)?;
    let converged = converge_grant_subtree(net, net, grantee, parent).await?;
    mint_grantee_scope(entropy, net, voucher, converged, &row, owner).await
}

/// Post the sealed share pointer that tells `recipient` where the scope they
/// were granted answers.
///
/// `scope_root_name` is the name the scope root answers at **now**: a write
/// grant's name wave runs between the mint and this post, and a pointer naming
/// the pre-wave root would send the grantee to a name their own seed does not
/// derive (blueprint/engine.md "Grant creation").
pub async fn post_share_pointer<E, M>(
    entropy: &mut E,
    mailbox: &M,
    owner: &OwnerGrantKeys<'_>,
    grantee: &GranteeScopePlan<'_>,
    recipient: &GrantRecipient<'_>,
    scope_root_name: &IpnsName,
) -> Result<(), CreateGrantError>
where
    E: Entropy,
    M: Mailbox,
{
    let recipient_enc_pub = recipient.enc_pub();
    let pointer = SharePointer {
        scope_root_name: scope_root_name.as_str().as_bytes().to_vec(),
        sharer_identity_pk: owner.identity_signer.verifying_key().to_sec1(),
        display_name: recipient.display_name.clone(),
        permission: grantee.permission(),
    };
    // Fresh HPKE ephemeral scalar, never a clock or a constant.
    let ephemeral = fresh_ephemeral(entropy).map_err(CreateGrantError::Entropy)?;
    // Fresh random, never derived: the API keeps only
    // sha256(senderPublicKey : idempotencyKey), so any key an observer can
    // recompute hands it back the sender→recipient edge. The blinded tag is
    // public (`kdf::blinded_tag`) and ships in the clear in every scope root's
    // grant section, so deriving from it would rebuild that edge — and the
    // granted folder — from a cached record.
    let idempotency_bytes: [u8; 16] =
        fresh_bytes(entropy, "grant idempotency key").map_err(CreateGrantError::Entropy)?;
    let idempotency_key = format!("grant-{}", hex_lower(&idempotency_bytes));
    post_sealed(
        mailbox,
        &recipient_enc_pub,
        &recipient.identity_pk(),
        &ephemeral,
        grantee.v,
        owner.identity_signer,
        &pointer.encode(),
        &idempotency_key,
    )
    .await
    .map_err(CreateGrantError::Mailbox)
}

/// A subtree [`converge_grant_subtree`] proved converged, carrying the two plans
/// it proved it for.
///
/// [`mint_grantee_scope`] reads both plans only out of this, so neither skipping
/// the pass nor minting against plans other than the ones it swept is
/// expressible.
pub struct ConvergedSubtree<'a> {
    grantee: &'a GranteeScopePlan<'a>,
    parent: &'a ParentScopePlan<'a>,
    /// The read epoch this pass gated the scope the folder is leaving at. The
    /// mint's interior walk re-asserts it on every node it seals, so the one
    /// resolve that proved the scope current is also the one the walk measures
    /// against.
    source_read_epoch: u64,
    root: SubtreeRoot,
}

impl ConvergedSubtree<'_> {
    /// Whether the folder already answers as a scope root a previous attempt
    /// promoted. A caller that cannot resume — one whose row is minted fresh
    /// per call — refuses on this rather than paying for a mint that
    /// [`CreateGrantError::ResumeNotThisGrant`] will refuse.
    pub(super) fn resumes_a_promotion(&self) -> bool {
        matches!(self.root, SubtreeRoot::Promoted(_))
    }
}

/// What [`mint_grantee_scope`] still owes the granted folder.
enum SubtreeRoot {
    /// The folder is an ordinary child, so the mint owes it a scope root.
    Measured {
        /// Every interior node the pass measured against the scope's epoch. The
        /// re-seal walks only these, so a body re-authored between the pass and
        /// the mint cannot hand the grantee's scope a node the gate never
        /// proved.
        interior: BTreeSet<[u8; 16]>,
        /// Every descendant scope root the pass stopped at. The re-seal stops
        /// at the same set: a scope root is re-keyed as one, and its own
        /// interior stays in the scope it already belongs to.
        boundaries: BTreeSet<[u8; 16]>,
    },
    /// A stalled attempt already promoted the folder, so only the interior move
    /// is owed ([`GrantResumeResolver`]). Boxed: it carries a whole published
    /// section, and the measured arm is the common one.
    Promoted(Box<PromotedScopeRoot>),
}

/// Prove the granted folder's subtree epoch-converged inside the scope it still
/// lives in, so no interior node the grantee will read lags that scope's epoch.
///
/// [`mint_grantee_scope`] publishes a scope its grantee reads from epoch 1, and
/// this is what has to hold before it does. Split from the mint so a caller can
/// put its own durable write between the two: a dropped lost race means
/// convergence is unproven, and refusing there should cost nothing that outlives
/// the refusal (CONTEXT.md "Epoch-converged").
///
/// A folder that already answers as a promoted scope root skips the pass: the
/// attempt that promoted it proved the subtree converged, and the move it
/// stalled in re-seals every node it walks at the promoted scope's own read
/// epoch, so nothing it moves lags the scope the grantee reads.
pub async fn converge_grant_subtree<'a, R, P>(
    resolver: &R,
    publisher: &P,
    grantee: &'a GranteeScopePlan<'a>,
    parent: &'a ParentScopePlan<'a>,
) -> Result<ConvergedSubtree<'a>, CreateGrantError>
where
    R: SweepResolver + GrantResumeResolver,
    P: SweepPublisher,
{
    let ipns_name = grantee.ipns_name();
    let folder = NodeRef {
        node_id: grantee.scope_id,
        ipns_name: ipns_name.as_str().as_bytes().to_vec(),
    };
    // The probe runs on the parent this resolve proved current, whose read seed
    // is what the promotion's ascent link derives from. It runs ahead of the
    // pass so a stalled move stays re-drivable: the pass would meet the promoted
    // folder as a scope root the parent's index omits and repair the index for
    // it, which is the mint's own last step to take.
    let (parent_ref, parent_scope) = resolve_scope_current(
        resolver,
        &ChildScopeRef::new(parent.identity.scope_id, parent.identity.ipns_name.to_vec()),
    )
    .await
    .map_err(|reason| {
        CreateGrantError::Converge(SweepError::Scope {
            scope_id: parent.identity.scope_id,
            reason,
        })
    })?;
    if let Some(promoted) = resolver
        .promoted_root(&parent_ref, &folder)
        .await
        .map_err(CreateGrantError::Resume)?
    {
        return Ok(ConvergedSubtree {
            grantee,
            parent,
            source_read_epoch: parent_scope.current_read_epoch,
            root: SubtreeRoot::Promoted(Box::new(promoted)),
        });
    }
    if resolver
        .holds_a_scope_root_floor(&folder)
        .await
        .map_err(CreateGrantError::Resume)?
    {
        return Err(CreateGrantError::TargetAlreadyNamesAScope);
    }
    let swept = converge_subtree(resolver, publisher, &parent_ref, &folder)
        .await
        .map_err(CreateGrantError::Converge)?;
    // A node the pass could not read is as unproven as one whose convergence
    // publish lost the race: either way the grantee could descend into a node
    // still sealed at an epoch its fresh seed does not reach.
    if !swept.dropped_lost_race.is_empty() || !swept.unreachable.is_empty() {
        let mut unconverged = swept.dropped_lost_race.clone();
        unconverged.extend(swept.unreachable_nodes());
        unconverged.sort_unstable();
        return Err(CreateGrantError::SubtreeNotConverged { unconverged });
    }
    let interior = swept
        .converged
        .iter()
        .chain(swept.already_converged.iter())
        .copied()
        .collect();
    let boundaries: BTreeSet<[u8; 16]> = swept.skipped_scope_roots.iter().copied().collect();
    // One source of truth for the granted folder's descendant scope roots. The
    // pass reads the live tree; the plan's index filters a cached snapshot, and
    // the two are derived at different times. A divergence either way is a
    // fail-closed refusal, ahead of every publish the mint makes.
    let planned: BTreeSet<[u8; 16]> = grantee
        .subtree_child_index
        .iter()
        .map(|child| child.scope_id)
        .collect();
    if boundaries != planned {
        return Err(CreateGrantError::SubtreeBoundaryDiverged {
            planned_not_met: planned.difference(&boundaries).copied().collect(),
            met_not_planned: boundaries.difference(&planned).copied().collect(),
        });
    }
    Ok(ConvergedSubtree {
        grantee,
        parent,
        source_read_epoch: swept.scope_read_epoch,
        root: SubtreeRoot::Measured {
            interior,
            boundaries,
        },
    })
}

/// Mint the grantee scope `row` is committed at, and hand the granted folder to
/// it: mint (epoch 1) → publish (grantee first) → re-seal the folder's interior
/// nodes into the new scope → re-key the reparented descendants under the fresh
/// grantee derivation → parent index update.
///
/// The scope it mints commits exactly `row` and carries no history links, so
/// whoever holds that row's grant blob reaches this scope's first epoch and
/// nothing before it — the property that separates a scope mint from a row
/// appended to a scope the owner has already been rotating (#25 D6). `row` must
/// be minted at [`GranteeScopePlan::ipns_name`]; the mint binds the same bytes.
///
/// A [`ConvergedSubtree`] that carries a promoted root skips the mint and
/// finishes that root's owed interior move instead
/// ([`GrantResumeResolver`]).
///
/// Fail-closed **through the grantee publish**.
pub async fn mint_grantee_scope<E, N, V>(
    entropy: &mut E,
    net: &N,
    voucher: &V,
    converged: ConvergedSubtree<'_>,
    row: &GrantRow,
    owner: &OwnerGrantKeys<'_>,
) -> Result<CreateGrantOutcome, CreateGrantError>
where
    E: Entropy,
    N: MintNet,
    V: ScopePointerVoucher,
{
    let (resolver, publisher) = (net, net);
    let ConvergedSubtree {
        grantee,
        parent,
        source_read_epoch,
        root: subtree_root,
    } = converged;
    // 1) The scope root's ipnsName, derived from the folder's write material.
    let ipns_name = grantee.ipns_name();
    let name_bytes = ipns_name.as_str().as_bytes();

    let tag = row.tag;
    let parent_ref =
        ChildScopeRef::new(parent.identity.scope_id, parent.identity.ipns_name.to_vec());
    let folder = NodeRef {
        node_id: grantee.scope_id,
        ipns_name: name_bytes.to_vec(),
    };

    // The index the mint commits the granted scope to, and the one a resume
    // proves the published root already committed.
    let planned_index = canonicalize(grantee.subtree_child_index);
    // The scope root the interior move runs against, and the two bounds the
    // walk runs under: a stalled attempt's own published root when there is
    // one, a fresh mint otherwise.
    let root = match subtree_root {
        SubtreeRoot::Promoted(promoted) => {
            // Release-active, both halves. A root that commits a different row,
            // or that reparented a different set of descendant scope roots, is
            // not the one this plan minted: moving this folder's interior into
            // it would seal the subtree under a scope whose published authority
            // is not the one this call reports.
            //
            // The whole entry, never the tag alone: a blinded tag binds the
            // recipient and the scope root's name, and neither moves with the
            // permission (`kdf::blinded_tag`). Matching on it would let a
            // stalled write grant finish as a read grant over a root that still
            // commits write.
            let commits_row = promoted
                .record
                .section
                .commitment
                .entries
                .iter()
                .any(|entry| committed_as(entry, &row.commitment_entry));
            if !commits_row || canonicalize(&promoted.boundaries) != planned_index {
                return Err(CreateGrantError::ResumeNotThisGrant);
            }
            GrantedRoot {
                record: promoted.record,
                override_seed: promoted.override_seed,
                frontier: promoted.children,
                bounds: InteriorBounds {
                    source_read_epoch,
                    stop_at: promoted
                        .boundaries
                        .into_iter()
                        .map(|child| child.scope_id)
                        .collect(),
                    measured: None,
                },
            }
        }
        SubtreeRoot::Measured {
            interior,
            boundaries,
        } => {
            // 2) Build the committed set around the row — one entry, so the
            // scope's whole grant set is the one this mint authorises.
            let commitment = GrantSetCommitment {
                ipns_name: name_bytes.to_vec(),
                owner_pseudonym_pk: owner.pseudonym_signer.verifying_key().to_bytes(),
                cut_epoch: 0,
                entries: vec![row.commitment_entry.clone()],
                unknown: PreservedFields::new(),
            };
            let commitment_sig = sign_grant_set(owner.identity_signer, &commitment)
                .map_err(CreateGrantError::CommitmentEncode)?
                .to_compact();
            let ledger = vec![row.ledger_entry.clone()];

            // 3) Mint at read and write epoch 1 with a FRESH RANDOM override
            // seed (never KDF-derived). Both planes start with the mint: an
            // empty `writeHistoryLink` is exactly write epoch 1
            // (`cipherbox_core::seal::write_body`), so the parent's epoch here
            // would advertise a walk-back this root holds no link for. The new
            // scope adopts the folder's descendant scope roots as its
            // direct-child-scope index (they now live inside the granted scope).
            let override_seed = fresh_seed(entropy).map_err(CreateGrantError::Entropy)?;
            let grantee_section = {
                let identity = ScopeRootIdentity {
                    v: grantee.v,
                    scope_id: grantee.scope_id,
                    ipns_name: name_bytes,
                    owner_enc_pub: grantee.owner_enc_pub,
                    owner_enc_secret: Some(owner.enc_secret),
                    ascent: Some(AscentAuthority::ParentSeed(grantee.parent_node_seed)),
                    // A grant on an interior folder anchors a scope under its
                    // parent.
                    owes_ascent_link: true,
                    pseudonym_signer: owner.pseudonym_signer,
                };
                let seeds = ResealSeeds {
                    override_seed: &override_seed,
                    read_epoch: MINT_EPOCH,
                    prev: None,
                    write_scope_seed: grantee.sealed_write_scope_seed(),
                    write_epoch: MINT_EPOCH,
                    write_history: WriteHistory::Genesis,
                    pointer_read_key: grantee.pointer_read_key,
                };
                // Mint-canonical: the adopted index carries the same
                // canonicalization the sweep's self-heal enforces (sweep.rs), so
                // the grantee root never lands a shape the convergence pass
                // would later have to repair.
                let committed = CommittedSet {
                    commitment: &commitment,
                    commitment_sig: &commitment_sig,
                    grant_ledger: &ledger,
                    direct_child_scope_index: &planned_index,
                    revoked_recipients: &[],
                };
                reseal_scope_root(entropy, &identity, &seeds, &committed, &[])
                    .map_err(CreateGrantError::Mint)?
            };
            let grantee_record = ResealedScopeRoot {
                scope_id: grantee.scope_id,
                ipns_name: name_bytes.to_vec(),
                read_epoch: MINT_EPOCH,
                write_epoch: MINT_EPOCH,
                section: grantee_section,
            };

            // 4) Vouch for the scope on the pointer plane before the root
            // exists.
            //
            // It leads the publishes because a signed record cannot be
            // unpublished (AGENTS.md rule 8), which is what
            // [`CreateGrantError::VouchScope`] rests on. A re-point naming a
            // root not yet on the network costs a reader one waited pass, and a
            // retry re-publishes at the same scope id, so nothing is orphaned
            // either way. A resume enters through `SubtreeRoot::Promoted`
            // instead, where the vouch that led that promotion already stands.
            voucher
                .vouch_scope(&RepointObject {
                    scope_id: grantee.scope_id,
                    current_root: ipns_name.clone(),
                    write_epoch: MINT_EPOCH,
                    min_read_epoch: MINT_EPOCH,
                    prev_root: None,
                })
                .await
                .map_err(CreateGrantError::VouchScope)?;

            // 5) Publish the grantee scope root FIRST: it exists before the
            // parent references it (register-first / never-orphan), and its
            // index carries the reparented descendants before they are removed
            // from the parent (dest-first). A folder becoming a scope root is a
            // promotion, not a republish ([`ScopeRootPromoter`]).
            let promoted_children = publisher
                .promote_scope_root(&parent_ref, &folder, &grantee_record)
                .await
                .map_err(CreateGrantError::Publish)?;
            GrantedRoot {
                record: grantee_record,
                override_seed,
                frontier: promoted_children,
                bounds: InteriorBounds {
                    source_read_epoch,
                    stop_at: boundaries,
                    measured: Some(interior),
                },
            }
        }
    };

    // 5b) Re-seal the folder's interior nodes into the scope that now owns them.
    // Their records still seal under the read key of the scope the folder left,
    // which no reader of the fresh scope derives and no epoch-1 history link
    // walks back to (blueprint/engine.md "subtree swept in").
    let GrantedRoot {
        record: grantee_record,
        override_seed,
        frontier,
        bounds,
    } = root;
    reseal_granted_interior(
        resolver,
        publisher,
        &parent_ref,
        &grantee_record,
        frontier,
        &bounds,
    )
    .await?;

    // 5c) Re-key the reparented direct children so each ascent link re-seals under
    // the fresh grantee derivation (see `GranteeScopePlan::subtree_child_index`;
    // blueprint/engine.md "subtree swept in"). Metadata-only (existing seed,
    // current epoch, `prev = None`), threaded top-down as the eager cascade does
    // (rotation/cascade.rs). Register-first: the grantee root published above
    // already lists these descendants, so each points back at a parent that exists.
    for descendant in grantee.subtree_child_index {
        let target = resolver.resolve(descendant).await.map_err(|reason| {
            CreateGrantError::DescendantResolve {
                scope_id: descendant.scope_id,
                reason,
            }
        })?;
        let parent_node_seed =
            Zeroizing::new(*kdf::node_seed(&override_seed, &descendant.scope_id).as_bytes());
        let identity = ScopeRootIdentity {
            v: target.v,
            scope_id: descendant.scope_id,
            ipns_name: &descendant.ipns_name,
            owner_enc_pub: &target.owner_enc_pub,
            owner_enc_secret: Some(owner.enc_secret),
            ascent: Some(AscentAuthority::ParentSeed(&parent_node_seed)),
            owes_ascent_link: true,
            pseudonym_signer: &target.pseudonym_signer,
        };
        let seeds = ResealSeeds {
            override_seed: &target.override_seed,
            read_epoch: target.current_read_epoch,
            prev: None,
            write_scope_seed: &target.write_scope_seed,
            write_epoch: target.write_epoch,
            write_history: WriteHistory::Carried(&target.write_history_link),
            pointer_read_key: &target.pointer_read_key,
        };
        let canonical_index = canonicalize(&target.direct_child_scope_index);
        let committed = CommittedSet {
            commitment: &target.commitment,
            commitment_sig: &target.commitment_sig,
            grant_ledger: &target.grant_ledger,
            direct_child_scope_index: &canonical_index,
            revoked_recipients: &[],
        };
        let section = reseal_scope_root(
            entropy,
            &identity,
            &seeds,
            &committed,
            &target.carried_history_links,
        )
        .map_err(|error| CreateGrantError::DescendantMint {
            scope_id: descendant.scope_id,
            error,
        })?;
        let record = ResealedScopeRoot {
            scope_id: descendant.scope_id,
            ipns_name: descendant.ipns_name.clone(),
            read_epoch: target.current_read_epoch,
            write_epoch: target.write_epoch,
            section,
        };
        publisher
            .publish_scope_root(&record)
            .await
            .map_err(|error| CreateGrantError::DescendantPublish {
                scope_id: descendant.scope_id,
                error,
            })?;
    }

    // 6) Parent index update — a metadata-only re-seal at the same epoch.
    let mut parent_index = parent.current_child_index.to_vec();
    for descendant in grantee.subtree_child_index {
        parent_index = remove_child(&parent_index, &descendant.scope_id);
    }
    parent_index = insert_child(
        &parent_index,
        ChildScopeRef::new(grantee.scope_id, name_bytes.to_vec()),
    );

    let parent_section = {
        let committed = CommittedSet {
            commitment: parent.commitment,
            commitment_sig: parent.commitment_sig,
            grant_ledger: parent.grant_ledger,
            direct_child_scope_index: &parent_index,
            revoked_recipients: &[],
        };
        // The owner runs this leg, so the tag binding is not the caller's to
        // disable: the same subkey that re-wraps the parent's grant blobs decides
        // which rows are still filed under a tag they derive.
        let identity = ScopeRootIdentity {
            owner_enc_secret: Some(owner.enc_secret),
            ..parent.identity
        };
        reseal_scope_root(
            entropy,
            &identity,
            &parent.seeds,
            &committed,
            parent.carried_history_links,
        )
        .map_err(CreateGrantError::ParentMint)?
    };
    let parent_record = ResealedScopeRoot {
        scope_id: parent.identity.scope_id,
        ipns_name: parent.identity.ipns_name.to_vec(),
        read_epoch: parent.seeds.read_epoch,
        write_epoch: parent.seeds.write_epoch,
        section: parent_section,
    };
    publisher
        .publish_scope_root(&parent_record)
        .await
        .map_err(CreateGrantError::ParentPublish)?;

    Ok(CreateGrantOutcome {
        scope_id: grantee.scope_id,
        tag,
        parent_child_index: parent_index,
    })
}

/// Whether `published` commits exactly the row `minted` mints: the recipient,
/// the permission, the masked key and the writer pseudonym, not the blinded tag
/// alone. Preserved unknown fields are ignored — a published entry may carry
/// fields a later build wrote, and refusing those would wedge the resume.
fn committed_as(published: &GrantSetEntry, minted: &GrantSetEntry) -> bool {
    published.tag == minted.tag
        && published.permission == minted.permission
        && published.pseudonym_pk == minted.pseudonym_pk
        && published.masked_recipient_enc_pk() == minted.masked_recipient_enc_pk()
}

/// Re-seal every interior node under the granted folder into `root`, the scope
/// published over that folder.
///
/// The walk descends from `frontier` — `root`'s own body — reading each node in
/// `source`, the scope it is leaving, and falling through to `root` for a node a
/// stalled attempt already moved there. Admitting either scope id for the
/// duration of the move is what makes the leg re-drivable ([`GrantResumeResolver`]).
///
/// [`InteriorBounds::stop_at`] is skipped, because a scope root is re-keyed as
/// one and its own interior stays in the scope it already belongs to. A node
/// outside [`InteriorBounds::measured`] is refused, so a body re-authored
/// between the convergence pass and the mint cannot move a record the gate
/// never proved into the grantee's scope. The walk also re-asserts the
/// convergence proof itself at every level it seals: the pass is stale by the
/// time the walk consumes it, and only the epoch each record carries now says
/// whether it still holds.
///
/// Runs after the promotion, so each re-sealed node points back at a root that
/// exists. Each level goes through [`canonicalize_frontier`] and each node is
/// visited once by id.
async fn reseal_granted_interior<R, P>(
    resolver: &R,
    publisher: &P,
    source: &ChildScopeRef,
    root: &ResealedScopeRoot,
    frontier: Vec<NodeRef>,
    bounds: &InteriorBounds,
) -> Result<(), CreateGrantError>
where
    R: SweepResolver + GrantResumeResolver,
    P: InteriorResealer,
{
    let mut visited = BTreeSet::from([root.scope_id]);
    let mut frontier = canonicalize_frontier(frontier);
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for child in &frontier {
            if !visited.insert(child.node_id) || bounds.stop_at.contains(&child.node_id) {
                continue;
            }
            if bounds
                .measured
                .as_ref()
                .is_some_and(|measured| !measured.contains(&child.node_id))
            {
                return Err(CreateGrantError::InteriorNotConverged {
                    node_id: child.node_id,
                });
            }
            match resolver.resolve_child(source, child).await {
                Ok(SweptChild::Interior(node)) => {
                    // Release-active (security rule 8). The read admits any
                    // record at or below the scope's epoch, so a record that
                    // regressed since the pass would travel into the grantee's
                    // scope with no proof behind it.
                    if node.current_read_epoch < bounds.source_read_epoch {
                        return Err(CreateGrantError::InteriorEpochRegressed {
                            node_id: child.node_id,
                        });
                    }
                    next.extend(body_children(&node.read_body));
                    publisher
                        .reseal_interior_node(
                            source,
                            root,
                            &InteriorRecord {
                                node_id: child.node_id,
                                ipns_name: &child.ipns_name,
                                sequence: node.sequence,
                                read_body: &node.read_body,
                                carried_unknown: &node.carried_unknown,
                                carried_epoch_tag_unknown: &node.carried_epoch_tag_unknown,
                            },
                        )
                        .await
                        .map_err(|error| CreateGrantError::InteriorPublish {
                            node_id: child.node_id,
                            error,
                        })?;
                }
                Ok(SweptChild::ScopeRoot(_)) => {
                    return Err(CreateGrantError::InteriorNotConverged {
                        node_id: child.node_id,
                    });
                }
                // The scope the folder is leaving does not authenticate the
                // record, so either this move already published it into `root`
                // or nothing here opens it.
                Err(SweepResolveFailure::Rejected) => {
                    let moved = resolver
                        .moved_interior_node(root, child)
                        .await
                        .map_err(|reason| CreateGrantError::InteriorResolve {
                            node_id: child.node_id,
                            reason,
                        })?
                        .ok_or(CreateGrantError::InteriorResolve {
                            node_id: child.node_id,
                            reason: SweepResolveFailure::Rejected,
                        })?;
                    next.extend(body_children(&moved));
                }
                Err(reason) => {
                    return Err(CreateGrantError::InteriorResolve {
                        node_id: child.node_id,
                        reason,
                    });
                }
            }
        }
        frontier = canonicalize_frontier(next);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records what the mint vouched for, and can be told to refuse — the
    /// pointer plane's half of the mint, without a network.
    #[derive(Default)]
    struct RecordingVoucher {
        vouched: RefCell<Vec<RepointObject>>,
        refuse: bool,
    }

    impl RecordingVoucher {
        fn refusing() -> Self {
            Self {
                refuse: true,
                ..Self::default()
            }
        }
    }

    impl ScopePointerVoucher for RecordingVoucher {
        async fn vouch_scope(&self, repoint: &RepointObject) -> Result<(), RotationPublishError> {
            if self.refuse {
                return Err(RotationPublishError::NotPublished);
            }
            self.vouched.borrow_mut().push(repoint.clone());
            Ok(())
        }
    }

    use crate::grants::contact::import_contact;
    use crate::grants::ledger::self_locate;
    use crate::grants::recipient_blinded_tag;
    use crate::grants::{GrantRow, PublishedGrantBlob};
    use crate::mailbox::poll_verified;
    use crate::rotation::{
        CascadeTarget, LaggingNode, NodeRef, PrevEpochSeed, ResolveFailure, SweepResolveFailure,
        SweptChild, SweptNode, SweptScope,
    };
    use crate::testkit::fakes::InMemoryMailboxHub;
    use crate::testkit::{
        CARRIED_WRITE_HISTORY_LINK, SeededEntropy, SilentAtWidth, SilentEntropy, block_on,
    };
    use cipherbox_core::seal::{
        AadContext, AscentLink, ChildRef, NodeKind, ReadBody, STRUCT_TAG_ASCENT_LINK,
        STRUCT_TAG_GRANT_BLOB, open_ascent_link, open_grant_blob, sign_recipient_binding,
    };
    use cipherbox_core::suite::contact::ContactCode;
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use cipherbox_core::suite::secret::ct_eq;
    use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
    use std::cell::RefCell;
    use std::rc::Rc;
    use zeroize::Zeroizing;

    const V: u64 = 1;
    const GRANTEE_SCOPE: [u8; 16] = [0x5c; 16];
    const GRANTEE_WRITE_SCOPE_SEED: [u8; SECRET_LEN] = [0x55; SECRET_LEN];
    const GRANTEE_POINTER_READ_KEY: [u8; SECRET_LEN] = [0x66; SECRET_LEN];
    const PARENT_SCOPE: [u8; 16] = [0x0e; 16];
    const PARENT_POINTER_READ_KEY: [u8; SECRET_LEN] = [0x0c; SECRET_LEN];
    const PARENT_NAME: &[u8] = b"parent-scope-root-name";
    const DESCENDANT_SCOPE: [u8; 16] = [0xdd; 16];
    /// A second descendant scope root, so a test can reorder an index of two.
    const SECOND_DESCENDANT_SCOPE: [u8; 16] = [0xde; 16];
    const DESCENDANT_NAME: &[u8] = b"descendant-scope-root-name";
    /// The read epoch every `ParentScopePlan` below re-seals at — the epoch the
    /// convergence sweep measures the parent scope's interior nodes against.
    const PARENT_EPOCH: u64 = 3;
    /// An interior node of the parent scope, inside the granted folder.
    const INTERIOR_NODE: [u8; 16] = [0xa1; 16];

    /// The descendant scope root inside the granted folder, as both the plan
    /// and the live tree name it.
    fn descendant_ref() -> ChildScopeRef {
        ChildScopeRef::new(DESCENDANT_SCOPE, DESCENDANT_NAME.to_vec())
    }

    /// One interior node's simulated name inside the parent scope.
    fn interior_name(node_id: [u8; 16]) -> Vec<u8> {
        format!("interior-{:02x}", node_id[0]).into_bytes()
    }

    /// The child refs a simulated folder body names for `nodes`.
    fn child_refs(nodes: impl Iterator<Item = [u8; 16]>) -> Vec<ChildRef> {
        nodes
            .map(|node_id| ChildRef {
                id: node_id,
                name: "n".into(),
                ipns_name: interior_name(node_id),
                kind: NodeKind::Folder,
                link_counter: 1,
                unknown: PreservedFields::new(),
            })
            .collect()
    }

    /// One interior node as the mint re-sealed it into the granted scope.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ResealedInterior {
        node_id: [u8; 16],
        /// The scope the record was re-sealed under.
        scope_id: [u8; 16],
        /// The read epoch it was re-sealed at.
        read_epoch: u64,
        /// The name it was published at.
        ipns_name: Vec<u8>,
    }

    /// One interior node of the parent scope: its id and its published epoch.
    type InteriorNodeState = ([u8; 16], u64);

    /// One interior node deeper than the granted folder's own children: its
    /// parent's id, its own id, and its published epoch.
    type NestedNodeState = ([u8; 16], [u8; 16], u64);

    /// The grantee scope root's ipnsName, derived exactly as the primitive does
    /// (from the folder's write material) so assertions bind the real name.
    fn grantee_name() -> Vec<u8> {
        derive_write_name(&GRANTEE_WRITE_SCOPE_SEED, &GRANTEE_SCOPE)
            .as_str()
            .as_bytes()
            .to_vec()
    }

    fn owner_pseudonym() -> Ed25519Signer {
        Ed25519Signer::from_seed([0x22; 32])
    }
    fn owner_identity() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x33; 32]).unwrap()
    }
    fn owner_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x11; 32])
    }
    fn recipient_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x44; 32])
    }
    fn recipient_signer() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x45; 32]).expect("valid scalar")
    }
    fn recipient_identity() -> EcdsaVerifier {
        recipient_signer().verifying_key()
    }
    /// The recipient as the grant path takes them. `enc_pub` is a parameter so a
    /// test can vary the encryption subkey and still hand over a pair whose
    /// binding signature verifies.
    fn contact_for(enc_pub: X25519Public) -> Contact {
        import_contact(&ContactCode::create(&recipient_signer(), enc_pub).encode())
            .expect("a freshly created code verifies")
    }

    /// The whole net arm the primitive composes over: the convergence sweep's
    /// two seams, the cascade re-seal resolve the re-key step runs, and the scope-root
    /// publisher. It records every committed publish and can force a lost race
    /// to model an unconvergeable subtree.
    ///
    /// The parent scope sits at [`PARENT_EPOCH`] and carries whatever interior
    /// nodes `interior` lists, so a test decides whether the granted subtree
    /// holds a lagging node. `resolve` builds a valid descendant `CascadeTarget`
    /// for `DESCENDANT_SCOPE`.
    ///
    /// `fail_after` fails the Nth+ `publish_scope_root` call so a test can let
    /// the grantee publish succeed and then fail the parent publish — the
    /// post-publish partial-commit path a single `publish_result` flag cannot
    /// express.
    #[derive(Clone)]
    struct FakeNet {
        published: Rc<RefCell<Vec<ResealedScopeRoot>>>,
        publish_result: Result<(), RotationPublishError>,
        publish_calls: Rc<RefCell<usize>>,
        /// Every read-seam entry: the sweep's three resolver calls and the
        /// cascade re-seal resolve. A refusal that must land before the
        /// convergence gate leaves this at zero.
        resolve_calls: Rc<RefCell<usize>>,
        fail_after: Option<(usize, RotationPublishError)>,
        /// Interior nodes **inside** the granted folder: id → published epoch.
        interior: Rc<RefCell<Vec<InteriorNodeState>>>,
        /// Interior nodes of the same scope but **outside** the granted folder.
        outside: Rc<RefCell<Vec<InteriorNodeState>>>,
        /// What an interior-node re-seal publish returns.
        node_publish_result: Result<(), RotationPublishError>,
        node_publishes: Rc<RefCell<Vec<[u8; 16]>>>,
        /// Every interior node the mint re-sealed into the granted scope.
        resealed: Rc<RefCell<Vec<ResealedInterior>>>,
        /// What an interior re-seal into the granted scope returns.
        reseal_result: Result<(), RotationPublishError>,
        /// Interior nodes deeper than the folder's own children: parent id, node
        /// id, published epoch.
        nested: Rc<RefCell<Vec<NestedNodeState>>>,
        /// The descendant scope roots the granted folder holds: named by the
        /// folder's body and by the parent scope's committed index, which is
        /// what a plan built off a fresh snapshot names too.
        descendants: Vec<ChildScopeRef>,
        /// A child of the granted folder that answers as a descendant scope
        /// root — a boundary the interior walk must stop at.
        boundary: Option<[u8; 16]>,
        /// A node that answers at an older epoch once the promotion stands: a
        /// record re-authored back down the ratchet after the pass proved it.
        regresses_after_promotion: Option<([u8; 16], u64)>,
        /// A node the promoted body names that the convergence pass never saw:
        /// a body re-authored between the pass and the mint.
        promoted_extra: Option<[u8; 16]>,
        /// A node the pass measured as interior that answers as a scope root by
        /// the time the walk reaches it.
        turns_scope_root: Option<[u8; 16]>,
        /// A node the pass read that the walk can no longer read.
        stalls_after_promotion: Option<[u8; 16]>,
        /// A node the sweep cannot resolve at all.
        unresolvable: Option<[u8; 16]>,
        /// A node the scope's ratchet cannot open.
        unreadable: Option<[u8; 16]>,
        /// The scope root a promotion published — what a re-drive of the same
        /// grant resumes against.
        promotion: Rc<RefCell<Option<ResealedScopeRoot>>>,
        /// The direct-child-scope index that root reparented.
        promoted_boundaries: Vec<ChildScopeRef>,
        /// Interior nodes already re-sealed into the granted scope. The scope
        /// the folder left no longer authenticates them, so `resolve_child`
        /// refuses them and `moved_interior_node` answers instead.
        moved: Rc<RefCell<BTreeSet<[u8; 16]>>>,
        /// One node whose re-seal publish stalls, so a test can strand the tail
        /// of a subtree and then let it through.
        reseal_stall: Rc<RefCell<Option<[u8; 16]>>>,
        /// Nodes this device holds a read-epoch floor at.
        floored: Rc<RefCell<BTreeSet<[u8; 16]>>>,
    }

    impl FakeNet {
        fn new(publish_result: Result<(), RotationPublishError>) -> Self {
            Self {
                published: Rc::new(RefCell::new(Vec::new())),
                publish_result,
                publish_calls: Rc::new(RefCell::new(0)),
                resolve_calls: Rc::new(RefCell::new(0)),
                fail_after: None,
                interior: Rc::new(RefCell::new(Vec::new())),
                outside: Rc::new(RefCell::new(Vec::new())),
                node_publish_result: Ok(()),
                node_publishes: Rc::new(RefCell::new(Vec::new())),
                resealed: Rc::new(RefCell::new(Vec::new())),
                reseal_result: Ok(()),
                nested: Rc::new(RefCell::new(Vec::new())),
                descendants: Vec::new(),
                boundary: None,
                regresses_after_promotion: None,
                promoted_extra: None,
                turns_scope_root: None,
                stalls_after_promotion: None,
                unresolvable: None,
                unreadable: None,
                promotion: Rc::new(RefCell::new(None)),
                promoted_boundaries: Vec::new(),
                moved: Rc::new(RefCell::new(BTreeSet::new())),
                reseal_stall: Rc::new(RefCell::new(None)),
                floored: Rc::new(RefCell::new(BTreeSet::new())),
            }
        }

        /// Stall the re-seal publish of `node_id` until
        /// [`heal_reseal`](Self::heal_reseal) clears it.
        fn stalling_reseal_at(self, node_id: [u8; 16]) -> Self {
            *self.reseal_stall.borrow_mut() = Some(node_id);
            self
        }

        /// Let the stalled re-seal publish through.
        fn heal_reseal(&self) {
            *self.reseal_stall.borrow_mut() = None;
        }

        /// The children of the promoted folder's body — the interior frontier
        /// both promotion arms report.
        fn promoted_children(&self) -> Vec<NodeRef> {
            self.interior
                .borrow()
                .iter()
                .map(|(node_id, _)| *node_id)
                .chain(self.promoted_extra)
                .map(|node_id| NodeRef {
                    node_id,
                    ipns_name: interior_name(node_id),
                })
                .chain(self.descendants.iter().map(|child| NodeRef {
                    node_id: child.scope_id,
                    ipns_name: child.ipns_name.clone(),
                }))
                .collect()
        }

        /// Succeed every publish up to (excluding) the `n`th, then fail with
        /// `err` — models a grantee publish that lands and a later parent
        /// publish that loses the race.
        fn new_fail_after(n: usize, err: RotationPublishError) -> Self {
            Self {
                fail_after: Some((n, err)),
                ..Self::new(Ok(()))
            }
        }

        /// Put one interior node inside the granted folder at `epoch`.
        fn with_interior(self, node_id: [u8; 16], epoch: u64) -> Self {
            self.interior.borrow_mut().push((node_id, epoch));
            self
        }

        /// Put one interior node in the same scope but outside the granted
        /// folder, at `epoch`.
        fn with_outside(self, node_id: [u8; 16], epoch: u64) -> Self {
            self.outside.borrow_mut().push((node_id, epoch));
            self
        }

        fn node_publish(mut self, result: Result<(), RotationPublishError>) -> Self {
            self.node_publish_result = result;
            self
        }

        /// Put one interior node under `parent`, deeper than the folder's own
        /// children, at `epoch`.
        fn with_nested(self, parent: [u8; 16], node_id: [u8; 16], epoch: u64) -> Self {
            self.nested.borrow_mut().push((parent, node_id, epoch));
            self
        }

        /// Make `node_id` — a child of the granted folder — answer as a
        /// descendant scope root the parent scope's index does not name.
        fn with_boundary(mut self, node_id: [u8; 16]) -> Self {
            self.boundary = Some(node_id);
            self
        }

        /// Have this device hold a read-epoch floor at `node_id`.
        fn floored_at(self, node_id: [u8; 16]) -> Self {
            self.floored.borrow_mut().insert(node_id);
            self
        }

        /// Put a descendant scope root inside the granted folder, named by both
        /// the folder's body and the parent scope's committed index.
        fn with_descendant_scope(mut self, child: ChildScopeRef) -> Self {
            self.descendants.push(child);
            self
        }

        /// Have `node_id` answer at `epoch` once the promotion stands, as a
        /// record re-authored at an older epoch after the pass would.
        fn regressing_after_promotion(mut self, node_id: [u8; 16], epoch: u64) -> Self {
            self.regresses_after_promotion = Some((node_id, epoch));
            self
        }

        /// Have the promoted body name `node_id` on top of the folder's own
        /// children, as a body re-authored after the convergence pass would.
        fn promoting_also(mut self, node_id: [u8; 16]) -> Self {
            self.promoted_extra = Some(node_id);
            self
        }

        /// Have `node_id` answer as a scope root only after the promotion, as a
        /// concurrent grant over that node would leave it.
        fn turning_scope_root(mut self, node_id: [u8; 16]) -> Self {
            self.turns_scope_root = Some(node_id);
            self
        }

        /// Have `node_id` stop resolving after the promotion, as a node whose
        /// record the mint can no longer read.
        fn stalling_after_promotion(mut self, node_id: [u8; 16]) -> Self {
            self.stalls_after_promotion = Some(node_id);
            self
        }

        /// The direct-child-scope index the promoted root reparented, which a
        /// resume must find equal to the plan's own.
        fn reparenting(mut self, index: Vec<ChildScopeRef>) -> Self {
            self.promoted_boundaries = index;
            self
        }

        fn reseal(mut self, result: Result<(), RotationPublishError>) -> Self {
            self.reseal_result = result;
            self
        }

        fn unresolvable(mut self, node_id: [u8; 16]) -> Self {
            self.unresolvable = Some(node_id);
            self
        }

        /// A node whose body no seed on the scope's ratchet opens.
        fn unreadable(mut self, node_id: [u8; 16]) -> Self {
            self.unreadable = Some(node_id);
            self
        }

        fn count_resolve(&self) {
            *self.resolve_calls.borrow_mut() += 1;
        }

        fn resolve_calls(&self) -> usize {
            *self.resolve_calls.borrow()
        }
    }

    impl SweepResolver for FakeNet {
        async fn resolve_scope(
            &self,
            scope: &ChildScopeRef,
        ) -> Result<SweptScope, SweepResolveFailure> {
            self.count_resolve();
            if scope.scope_id != PARENT_SCOPE {
                return Err(SweepResolveFailure::Rejected);
            }
            let mut children = vec![NodeRef {
                node_id: GRANTEE_SCOPE,
                ipns_name: grantee_name(),
            }];
            children.extend(self.outside.borrow().iter().map(|(node_id, _)| NodeRef {
                node_id: *node_id,
                ipns_name: interior_name(*node_id),
            }));
            Ok(SweptScope {
                current_read_epoch: PARENT_EPOCH,
                children,
                direct_child_scope_index: self.descendants.clone(),
            })
        }

        async fn consult_pointer(
            &self,
            _scope_id: &[u8; 16],
        ) -> Result<Option<Vec<u8>>, SweepResolveFailure> {
            self.count_resolve();
            Ok(None)
        }

        async fn resolve_child(
            &self,
            _scope: &ChildScopeRef,
            child: &NodeRef,
        ) -> Result<SweptChild, SweepResolveFailure> {
            self.count_resolve();
            if self.unresolvable == Some(child.node_id) {
                return Err(SweepResolveFailure::Unavailable);
            }
            if self.unreadable == Some(child.node_id) {
                return Err(SweepResolveFailure::Unreadable);
            }
            let promoted = self.promotion.borrow().is_some();
            if promoted && self.stalls_after_promotion == Some(child.node_id) {
                return Err(SweepResolveFailure::Unavailable);
            }
            if self.moved.borrow().contains(&child.node_id) {
                return Err(SweepResolveFailure::Rejected);
            }
            if self.boundary == Some(child.node_id)
                || (promoted && self.turns_scope_root == Some(child.node_id))
            {
                return Ok(SweptChild::ScopeRoot(ChildScopeRef::new(
                    child.node_id,
                    child.ipns_name.clone(),
                )));
            }
            // The granted folder is itself an interior node of the parent scope
            // until the mint publishes its scope root; its body names the nodes
            // the convergence gate must reach.
            let (epoch, children) = if child.node_id == GRANTEE_SCOPE {
                let mut children =
                    child_refs(self.interior.borrow().iter().map(|(node_id, _)| *node_id));
                children.extend(self.descendants.iter().map(|descendant| ChildRef {
                    id: descendant.scope_id,
                    name: "n".into(),
                    ipns_name: descendant.ipns_name.clone(),
                    kind: NodeKind::Folder,
                    link_counter: 1,
                    unknown: PreservedFields::new(),
                }));
                (PARENT_EPOCH, children)
            } else {
                let epoch = self
                    .interior
                    .borrow()
                    .iter()
                    .chain(self.outside.borrow().iter())
                    .map(|(node_id, epoch)| (*node_id, *epoch))
                    .chain(
                        self.nested
                            .borrow()
                            .iter()
                            .map(|(_, node_id, epoch)| (*node_id, *epoch)),
                    )
                    .find(|(node_id, _)| *node_id == child.node_id)
                    .map(|(_, epoch)| epoch)
                    .ok_or(SweepResolveFailure::Unavailable)?;
                let children = child_refs(
                    self.nested
                        .borrow()
                        .iter()
                        .filter(|(parent, _, _)| *parent == child.node_id)
                        .map(|(_, node_id, _)| *node_id),
                );
                (epoch, children)
            };
            let epoch = match self.regresses_after_promotion {
                Some((node_id, regressed)) if promoted && node_id == child.node_id => regressed,
                _ => epoch,
            };
            Ok(SweptChild::Interior(SweptNode {
                current_read_epoch: epoch,
                sequence: 1,
                read_body: ReadBody::Folder {
                    created_at: 0,
                    modified_at: 0,
                    children,
                    unknown: PreservedFields::new(),
                },
                carried_unknown: PreservedFields::new(),
                carried_epoch_tag_unknown: PreservedFields::new(),
            }))
        }
    }

    impl SweepPublisher for FakeNet {
        async fn publish_node(
            &self,
            _scope: &ChildScopeRef,
            node: &LaggingNode<'_>,
        ) -> Result<(), RotationPublishError> {
            self.node_publishes.borrow_mut().push(node.node_id);
            self.node_publish_result.clone()?;
            for (node_id, epoch) in self
                .interior
                .borrow_mut()
                .iter_mut()
                .chain(self.outside.borrow_mut().iter_mut())
            {
                if *node_id == node.node_id {
                    *epoch = node.read_epoch;
                }
            }
            Ok(())
        }

        async fn repair_child_scope_index(
            &self,
            _scope: &ChildScopeRef,
            _index: &[ChildScopeRef],
        ) -> Result<(), RotationPublishError> {
            Ok(())
        }
    }

    impl CascadeResealResolver for FakeNet {
        async fn resolve(&self, scope: &ChildScopeRef) -> Result<CascadeTarget, ResolveFailure> {
            self.count_resolve();
            if scope.scope_id != DESCENDANT_SCOPE && scope.scope_id != SECOND_DESCENDANT_SCOPE {
                return Err(ResolveFailure::Rejected);
            }
            let pseudonym = owner_pseudonym();
            let commitment = GrantSetCommitment {
                ipns_name: scope.ipns_name.clone(),
                owner_pseudonym_pk: pseudonym.verifying_key().to_bytes(),
                cut_epoch: 0,
                entries: Vec::new(),
                unknown: PreservedFields::new(),
            };
            let commitment_sig = sign_grant_set(&owner_identity(), &commitment)
                .unwrap()
                .to_compact();
            Ok(CascadeTarget {
                v: V,
                current_read_epoch: 1,
                owner_enc_pub: owner_enc().public(),
                pseudonym_signer: pseudonym,
                override_seed: Zeroizing::new([0x71; SECRET_LEN]),
                write_epoch: 1,
                write_scope_seed: Zeroizing::new([0x72; SECRET_LEN]),
                pointer_read_key: Zeroizing::new([0x73; SECRET_LEN]),
                commitment,
                commitment_sig,
                grant_ledger: Vec::new(),
                write_history_link: Vec::new(),
                direct_child_scope_index: Vec::new(),
                carried_history_links: Vec::new(),
                // Every scope this resolver reaches is a descendant.
                carried_ascent_link: true,
            })
        }
    }

    impl InteriorResealer for FakeNet {
        async fn reseal_interior_node(
            &self,
            _source: &ChildScopeRef,
            root: &ResealedScopeRoot,
            node: &InteriorRecord<'_>,
        ) -> Result<(), RotationPublishError> {
            self.reseal_result.clone()?;
            if *self.reseal_stall.borrow() == Some(node.node_id) {
                return Err(RotationPublishError::NotPublished);
            }
            self.moved.borrow_mut().insert(node.node_id);
            self.resealed.borrow_mut().push(ResealedInterior {
                node_id: node.node_id,
                scope_id: root.scope_id,
                read_epoch: root.read_epoch,
                ipns_name: node.ipns_name.to_vec(),
            });
            Ok(())
        }
    }

    impl GrantResumeResolver for FakeNet {
        async fn promoted_root(
            &self,
            _parent: &ChildScopeRef,
            _node: &NodeRef,
        ) -> Result<Option<PromotedScopeRoot>, ResolveFailure> {
            let Some(record) = self.promotion.borrow().clone() else {
                return Ok(None);
            };
            Ok(Some(PromotedScopeRoot {
                record,
                // The real arm recovers this from the root's own owner blob; the
                // simulated one carries no record plane to recover it from.
                override_seed: Zeroizing::new([0x5e; SECRET_LEN]),
                children: self.promoted_children(),
                boundaries: self.promoted_boundaries.clone(),
            }))
        }

        async fn holds_a_scope_root_floor(&self, node: &NodeRef) -> Result<bool, ResolveFailure> {
            Ok(self.floored.borrow().contains(&node.node_id))
        }

        async fn moved_interior_node(
            &self,
            _root: &ResealedScopeRoot,
            node: &NodeRef,
        ) -> Result<Option<ReadBody>, SweepResolveFailure> {
            if !self.moved.borrow().contains(&node.node_id) {
                return Ok(None);
            }
            Ok(Some(ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children: child_refs(
                    self.nested
                        .borrow()
                        .iter()
                        .filter(|(parent, _, _)| *parent == node.node_id)
                        .map(|(_, node_id, _)| *node_id),
                ),
                unknown: PreservedFields::new(),
            }))
        }
    }

    /// The promotion seam over the same recording publisher; the base's real
    /// provenance is pinned against the production net
    /// (`crates/engine/tests/owner_actions.rs`).
    impl ScopeRootPromoter for FakeNet {
        async fn promote_scope_root(
            &self,
            _parent: &ChildScopeRef,
            _node: &NodeRef,
            record: &ResealedScopeRoot,
        ) -> Result<Vec<NodeRef>, RotationPublishError> {
            self.publish_scope_root(record).await?;
            *self.promotion.borrow_mut() = Some(record.clone());
            // The promoted body is the granted folder's, so its children are
            // the nodes inside the folder.
            Ok(self.promoted_children())
        }
    }

    impl ScopeRootPublisher for FakeNet {
        async fn publish_scope_root(
            &self,
            record: &ResealedScopeRoot,
        ) -> Result<(), RotationPublishError> {
            let call = {
                let mut c = self.publish_calls.borrow_mut();
                let call = *c;
                *c += 1;
                call
            };
            if let Some((n, err)) = &self.fail_after {
                if call >= *n {
                    return Err(err.clone());
                }
            }
            match &self.publish_result {
                Ok(()) => {
                    self.published.borrow_mut().push(record.clone());
                    Ok(())
                }
                Err(e) => Err(e.clone()),
            }
        }
    }

    /// What the grant path actually put on the wire for one post.
    #[derive(Clone)]
    struct PostedDelivery {
        address: Vec<u8>,
        idempotency_key: String,
    }

    /// A `Mailbox` fake that records every post, so a test can assert the
    /// delivery values the grant path chose.
    #[derive(Clone, Default)]
    struct RecordingMailbox {
        posts: Rc<RefCell<Vec<PostedDelivery>>>,
    }

    impl Mailbox for RecordingMailbox {
        async fn post(
            &self,
            recipient_public_key: &[u8],
            _sealed_payload: &[u8],
            idempotency_key: &str,
        ) -> crate::seams::SeamResult<()> {
            self.posts.borrow_mut().push(PostedDelivery {
                address: recipient_public_key.to_vec(),
                idempotency_key: idempotency_key.to_owned(),
            });
            Ok(())
        }
        async fn poll(&self) -> crate::seams::SeamResult<Vec<crate::seams::MailboxItem>> {
            Ok(Vec::new())
        }
        async fn ack(&self, _item_id: &str) -> crate::seams::SeamResult<()> {
            Ok(())
        }
    }

    /// The delivery the primitive posts for `recipient_enc` over the fixed
    /// grantee folder (empty subtree, converged, publishing OK), with the
    /// grant's blinded tag alongside it.
    fn delivery_for(entropy_seed: u64, recipient_enc: &X25519Secret) -> (PostedDelivery, [u8; 32]) {
        let net = FakeNet::new(Ok(()));
        let recorder = RecordingMailbox::default();

        let owner_enc = owner_enc();
        let owner_enc_pub = owner_enc.public();
        let owner_identity = owner_identity();
        let owner_pseudonym = owner_pseudonym();
        let recipient_pub = recipient_enc.public();

        let parent_node_seed = [0x44; SECRET_LEN];
        let grantee_write_scope_seed = GRANTEE_WRITE_SCOPE_SEED;
        let parent_override_seed = [0x0a; SECRET_LEN];
        let parent_write_scope_seed = [0x0b; SECRET_LEN];
        let parent_commitment = GrantSetCommitment {
            ipns_name: PARENT_NAME.to_vec(),
            owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
            cut_epoch: 0,
            entries: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let parent_commitment_sig = sign_grant_set(&owner_identity, &parent_commitment)
            .unwrap()
            .to_compact();

        let mut entropy = SeededEntropy::new(entropy_seed);
        let grantee = GranteeScopePlan {
            v: V,
            scope_id: GRANTEE_SCOPE,
            parent_node_seed: &parent_node_seed,
            owner_enc_pub: &owner_enc_pub,
            write_scope_seed: &grantee_write_scope_seed,
            write_cut: None,
            pointer_read_key: &GRANTEE_POINTER_READ_KEY,
            subtree_child_index: &[],
        };
        let recipient_contact = contact_for(recipient_pub);

        let recipient = GrantRecipient {
            contact: &recipient_contact,
            display_name: "Shared Folder".to_string(),
        };
        let owner = OwnerGrantKeys {
            enc_secret: &owner_enc,
            identity_signer: &owner_identity,
            pseudonym_signer: &owner_pseudonym,
        };
        let parent = ParentScopePlan {
            identity: ScopeRootIdentity {
                v: V,
                scope_id: PARENT_SCOPE,
                ipns_name: PARENT_NAME,
                owner_enc_pub: &owner_enc_pub,
                owner_enc_secret: None,
                ascent: None,
                owes_ascent_link: false,
                pseudonym_signer: &owner_pseudonym,
            },
            seeds: ResealSeeds {
                override_seed: &parent_override_seed,
                read_epoch: 3,
                prev: None::<PrevEpochSeed<'_>>,
                write_history: WriteHistory::Carried(CARRIED_WRITE_HISTORY_LINK),
                write_scope_seed: &parent_write_scope_seed,
                write_epoch: 2,
                pointer_read_key: &PARENT_POINTER_READ_KEY,
            },
            commitment: &parent_commitment,
            commitment_sig: &parent_commitment_sig,
            grant_ledger: &[],
            current_child_index: &[],
            carried_history_links: &[],
        };
        let voucher = RecordingVoucher::default();
        let outcome = block_on(async {
            let outcome = create_grant(
                &mut entropy,
                &net,
                &voucher,
                &grantee,
                &recipient,
                &owner,
                &parent,
            )
            .await?;
            post_share_pointer(
                &mut entropy,
                &recorder,
                &owner,
                &grantee,
                &recipient,
                &grantee.ipns_name(),
            )
            .await
            .map(|()| outcome)
        })
        .expect("grant creation succeeds");

        let posts = recorder.posts.borrow();
        assert_eq!(posts.len(), 1, "exactly one mailbox post per grant");
        (posts[0].clone(), outcome.tag)
    }

    /// A read grant with the given subtree, run against fresh fakes on seed
    /// `entropy_seed`. Returns the outcome, the published records, and the mailbox
    /// hub so the caller can assert on delivery.
    /// What every runner returns: the call's own result, the records the fake
    /// net published in order, and the mailbox the share pointer reached.
    type GrantRun = (
        Result<CreateGrantOutcome, CreateGrantError>,
        Vec<ResealedScopeRoot>,
        InMemoryMailboxHub,
    );

    fn assert_nothing_delivered(hub: &InMemoryMailboxHub) {
        let recip_box = hub.mailbox_for(&recipient_identity().to_sec1());
        assert!(
            block_on(poll_verified(&recip_box, &recipient_enc(), V))
                .unwrap()
                .is_empty(),
            "and nothing is delivered",
        );
    }

    fn run(
        entropy_seed: u64,
        subtree: &[ChildScopeRef],
        net: FakeNet,
        parent_grants: &[GrantRow],
    ) -> GrantRun {
        run_for(
            SeededEntropy::new(entropy_seed),
            subtree,
            net,
            parent_grants,
            &recipient_enc(),
            &RecordingVoucher::default(),
        )
    }

    fn run_for<E: Entropy>(
        entropy: E,
        subtree: &[ChildScopeRef],
        net: FakeNet,
        parent_grants: &[GrantRow],
        recipient_enc: &X25519Secret,
        voucher: &RecordingVoucher,
    ) -> GrantRun {
        run_full(
            entropy,
            subtree,
            net,
            parent_grants,
            recipient_enc,
            voucher,
            None,
        )
    }

    fn run_full<E: Entropy>(
        mut entropy: E,
        subtree: &[ChildScopeRef],
        net: FakeNet,
        parent_grants: &[GrantRow],
        recipient_enc: &X25519Secret,
        voucher: &RecordingVoucher,
        write_cut: Option<&[u8; SECRET_LEN]>,
    ) -> GrantRun {
        let hub = InMemoryMailboxHub::default();
        let mailbox = hub.mailbox_for(&recipient_identity().to_sec1());

        let owner_enc = owner_enc();
        let owner_enc_pub = owner_enc.public();
        let owner_identity = owner_identity();
        let owner_pseudonym = owner_pseudonym();
        let recipient_pub = recipient_enc.public();

        let parent_node_seed = [0x44; SECRET_LEN];
        let grantee_write_scope_seed = GRANTEE_WRITE_SCOPE_SEED;

        let parent_override_seed = [0x0a; SECRET_LEN];
        let parent_write_scope_seed = [0x0b; SECRET_LEN];
        let parent_commitment = GrantSetCommitment {
            ipns_name: PARENT_NAME.to_vec(),
            owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
            cut_epoch: 0,
            entries: parent_grants
                .iter()
                .map(|g| g.commitment_entry.clone())
                .collect(),
            unknown: PreservedFields::new(),
        };
        let parent_commitment_sig = sign_grant_set(&owner_identity, &parent_commitment)
            .unwrap()
            .to_compact();
        let parent_ledger: Vec<GrantLedgerEntry> = parent_grants
            .iter()
            .map(|g| g.ledger_entry.clone())
            .collect();

        let outcome = {
            let grantee = GranteeScopePlan {
                v: V,
                scope_id: GRANTEE_SCOPE,
                parent_node_seed: &parent_node_seed,
                owner_enc_pub: &owner_enc_pub,
                write_scope_seed: &grantee_write_scope_seed,
                write_cut,
                pointer_read_key: &GRANTEE_POINTER_READ_KEY,
                subtree_child_index: subtree,
            };
            let recipient_contact = contact_for(recipient_pub);

            let recipient = GrantRecipient {
                contact: &recipient_contact,
                display_name: "Shared Folder".to_string(),
            };
            let owner = OwnerGrantKeys {
                enc_secret: &owner_enc,
                identity_signer: &owner_identity,
                pseudonym_signer: &owner_pseudonym,
            };
            let parent = ParentScopePlan {
                identity: ScopeRootIdentity {
                    v: V,
                    scope_id: PARENT_SCOPE,
                    ipns_name: PARENT_NAME,
                    owner_enc_pub: &owner_enc_pub,
                    owner_enc_secret: None,
                    ascent: None,
                    owes_ascent_link: false,
                    pseudonym_signer: &owner_pseudonym,
                },
                seeds: ResealSeeds {
                    override_seed: &parent_override_seed,
                    read_epoch: 3,
                    prev: None::<PrevEpochSeed<'_>>,
                    write_history: WriteHistory::Carried(CARRIED_WRITE_HISTORY_LINK),
                    write_scope_seed: &parent_write_scope_seed,
                    write_epoch: 2,
                    pointer_read_key: &PARENT_POINTER_READ_KEY,
                },
                commitment: &parent_commitment,
                commitment_sig: &parent_commitment_sig,
                grant_ledger: &parent_ledger,
                current_child_index: &[],
                carried_history_links: &[],
            };
            block_on(async {
                let outcome = create_grant(
                    &mut entropy,
                    &net,
                    voucher,
                    &grantee,
                    &recipient,
                    &owner,
                    &parent,
                )
                .await?;
                post_share_pointer(
                    &mut entropy,
                    &mailbox,
                    &owner,
                    &grantee,
                    &recipient,
                    &grantee.ipns_name(),
                )
                .await
                .map(|()| outcome)
            })
        };
        let published = net.published.borrow().clone();
        (outcome, published, hub)
    }

    /// The API keeps `sha256(senderPublicKey : idempotencyKey)`, so an
    /// idempotency key an observer can recompute hands it back the sender to
    /// recipient edge. A seam that writes nothing makes every key that constant.
    #[test]
    fn a_silent_seam_delivers_no_grant_pointer() {
        // The idempotency key is the only 16-byte draw on this path, so
        // silencing that width reaches it past the guarded draws before it.
        let (outcome, _published, hub) = run_for(
            SilentAtWidth::new(9, 16),
            &[],
            FakeNet::new(Ok(())),
            &[],
            &recipient_enc(),
            &RecordingVoucher::default(),
        );

        // Name the draw: without it the assertion holds for a refusal from any
        // earlier draw on the same path.
        let refused = outcome.expect_err("the zero draw is refused");
        assert!(
            matches!(&refused, CreateGrantError::Entropy(e)
                if e.message().contains("grant idempotency key")),
            "the refusal is the idempotency draw, not an earlier one: {refused:?}"
        );
        let recip_box = hub.mailbox_for(&recipient_identity().to_sec1());
        assert!(
            block_on(poll_verified(&recip_box, &recipient_enc(), V))
                .unwrap()
                .is_empty(),
            "nothing is posted under a key the API could recompute",
        );
    }

    #[test]
    fn a_silent_entropy_seam_cuts_no_grant_scope() {
        // The grant scope is minted at read epoch 1 under a fresh random override
        // seed. An all-zero one hands every reader of the shared folder its
        // structure keys, so the draw is refused before anything is published.
        let (outcome, published, hub) = run_for(
            SilentEntropy,
            &[],
            FakeNet::new(Ok(())),
            &[],
            &recipient_enc(),
            &RecordingVoucher::default(),
        );

        assert!(matches!(
            outcome.expect_err("the zero draw is refused"),
            CreateGrantError::Entropy(_),
        ));
        assert!(published.is_empty(), "no scope root is minted");
        assert_nothing_delivered(&hub);
    }

    /// The pointer plane vouches for the scope before the scope exists, so a
    /// pointer publish that does not land refuses the whole cut. Publishing the
    /// roots anyway would leave a scope in existence that no plane speaks for,
    /// and a signed record cannot be unpublished.
    #[test]
    fn a_refused_pointer_publish_mints_no_scope_root() {
        let voucher = RecordingVoucher::refusing();
        let (outcome, published, hub) = run_for(
            SeededEntropy::new(7),
            &[],
            FakeNet::new(Ok(())),
            &[],
            &recipient_enc(),
            &voucher,
        );

        assert_eq!(
            outcome.expect_err("the cut refuses").check(),
            "vouch-scope-failed",
        );
        assert!(published.is_empty(), "no scope root is promoted");
        assert_nothing_delivered(&hub);
    }

    /// The epoch the mint vouches for is the epoch it seals the root at, or a
    /// reader is handed a clock that opens nothing.
    #[test]
    fn the_mint_vouches_for_the_epoch_it_seals_the_root_at() {
        let voucher = RecordingVoucher::default();
        let (outcome, published, _hub) = run_for(
            SeededEntropy::new(7),
            &[],
            FakeNet::new(Ok(())),
            &[],
            &recipient_enc(),
            &voucher,
        );
        outcome.expect("grant creation succeeds over a converged subtree");

        let vouched = voucher.vouched.borrow();
        let [repoint] = vouched.as_slice() else {
            panic!("one scope, one re-point");
        };
        assert_eq!(repoint.scope_id, published[0].scope_id);
        assert_eq!(repoint.write_epoch, published[0].write_epoch);
        assert_eq!(repoint.min_read_epoch, published[0].read_epoch);
        assert_eq!(
            repoint.current_root.as_str().as_bytes(),
            published[0].ipns_name.as_slice(),
            "and it names the root the mint is about to publish",
        );
        assert_eq!(repoint.prev_root, None, "a mint supersedes no earlier root");
    }

    #[test]
    fn a_granted_scope_mints_at_write_epoch_one_however_far_the_parent_has_rotated() {
        let (outcome, published, _hub) = run(7, &[], FakeNet::new(Ok(())), &[]);
        outcome.expect("grant creation succeeds over a converged subtree");

        assert_eq!(
            published[1].write_epoch, 2,
            "the parent scope has already rotated its write plane"
        );
        assert_eq!(
            published[0].write_epoch, 1,
            "and the scope minted inside it starts a write plane of its own"
        );
    }

    #[test]
    fn converged_subtree_mints_publishes_and_posts_the_share_pointer() {
        let (outcome, published, hub) = run(7, &[], FakeNet::new(Ok(())), &[]);
        let outcome = outcome.expect("grant creation succeeds over a converged subtree");

        // Two records, grantee first (register-first / never-orphan / dest-first).
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].scope_id, GRANTEE_SCOPE);
        assert_eq!(
            published[0].read_epoch, 1,
            "grantee scope minted at epoch 1"
        );
        assert_eq!(
            published[0].ipns_name,
            grantee_name(),
            "published at the folder's derived resolvable name"
        );
        assert_eq!(published[1].scope_id, PARENT_SCOPE);

        // The recipient's blob is filed under, and committed at, the blinded tag
        // bound to the derived scope-root name (which the recipient re-derives).
        let expected_tag =
            recipient_blinded_tag(&recipient_enc(), &owner_enc().public(), &grantee_name())
                .unwrap();
        assert_eq!(outcome.tag, expected_tag);
        let blobs: Vec<PublishedGrantBlob> = published[0]
            .section
            .grant_blobs
            .iter()
            .map(|b| PublishedGrantBlob {
                tag: b.tag,
                enc: b.enc,
                ciphertext: b.ciphertext.clone(),
            })
            .collect();
        assert!(self_locate(&blobs, &expected_tag).is_some());
        assert_eq!(published[0].section.commitment.entries.len(), 1);
        assert_eq!(published[0].section.commitment.entries[0].tag, expected_tag);
        assert_eq!(
            published[0].section.commitment.entries[0].permission,
            Permission::Read
        );

        // The parent index now lists the new grantee scope root.
        assert!(
            outcome
                .parent_child_index
                .iter()
                .any(|c| c.scope_id == GRANTEE_SCOPE)
        );

        // The recipient receives the sealed share pointer.
        let recip_box = hub.mailbox_for(&recipient_identity().to_sec1());
        let items = block_on(poll_verified(&recip_box, &recipient_enc(), V)).unwrap();
        assert_eq!(items.len(), 1);
        let pointer = SharePointer::decode(&items[0].payload).unwrap();
        assert_eq!(pointer.scope_root_name, grantee_name());
        assert_eq!(pointer.permission, Permission::Read);
        assert_eq!(
            pointer.sharer_identity_pk,
            owner_identity().verifying_key().to_sec1()
        );
    }

    #[test]
    fn a_lagging_interior_node_that_cannot_converge_refuses_the_grant() {
        // An interior node of the parent scope lags (epoch 1 < PARENT_EPOCH) and
        // its convergence publish loses the CAS race, so the subtree cannot be
        // proven epoch-converged: the grant is refused — nothing minted, nothing
        // posted.
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, 1)
            .node_publish(Err(RotationPublishError::LostRace));
        let (outcome, published, hub) = run(7, &[], net, &[]);

        match outcome {
            Err(CreateGrantError::SubtreeNotConverged { unconverged }) => {
                assert_eq!(unconverged, vec![INTERIOR_NODE]);
            }
            other => panic!("expected SubtreeNotConverged, got {other:?}"),
        }
        // Fail-closed: no grantee/parent record published, no share pointer.
        assert!(published.is_empty(), "nothing published on a refused grant");
        let recip_box = hub.mailbox_for(&recipient_identity().to_sec1());
        let items = block_on(poll_verified(&recip_box, &recipient_enc(), V)).unwrap();
        assert!(items.is_empty(), "no share pointer on a refused grant");
    }

    #[test]
    fn the_same_lagging_node_lets_the_grant_through_once_it_converges() {
        // The passing direction of the same gate: identical subtree, and the
        // node's convergence publish now lands, so the grant proceeds.
        let net = FakeNet::new(Ok(())).with_interior(INTERIOR_NODE, 1);
        let publishes = Rc::clone(&net.node_publishes);
        let (outcome, published, _hub) = run(7, &[], net, &[]);

        outcome.expect("a converged subtree grants");
        assert_eq!(
            *publishes.borrow(),
            vec![INTERIOR_NODE],
            "the lagging node was advanced before the mint"
        );
        assert_eq!(published.len(), 2, "grantee root and parent index");
    }

    #[test]
    fn an_already_converged_subtree_needs_no_convergence_publish() {
        let net = FakeNet::new(Ok(())).with_interior(INTERIOR_NODE, PARENT_EPOCH);
        let publishes = Rc::clone(&net.node_publishes);
        let (outcome, _published, _hub) = run(7, &[], net, &[]);
        outcome.expect("grant creation succeeds");
        assert!(publishes.borrow().is_empty(), "nothing lagged");
    }

    #[test]
    fn a_node_lagging_outside_the_granted_folder_does_not_block_the_grant() {
        // The gate owes the epoch-converged guarantee over the folder being
        // shared, not over every sibling in the scope it happens to sit in.
        const OUTSIDE_NODE: [u8; 16] = [0xb2; 16];
        let net = FakeNet::new(Ok(())).with_outside(OUTSIDE_NODE, 1);
        let publishes = Rc::clone(&net.node_publishes);
        let (outcome, _published, _hub) = run(7, &[], net, &[]);

        outcome.expect("a lagging sibling is none of this grant's business");
        assert!(
            publishes.borrow().is_empty(),
            "the sibling subtree was never walked, let alone re-sealed"
        );
    }

    /// A node this device cannot read is as unproven as one whose publish lost
    /// the race: the grantee could descend into it.
    #[test]
    fn an_unreachable_node_in_the_granted_folder_refuses_the_grant() {
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, 1)
            .unreadable(INTERIOR_NODE);
        refuses_as_unconverged(net);
    }

    /// The pass isolates an unresolvable node rather than aborting, so this
    /// refusal — not the abort — is what keeps the grant fail-closed.
    #[test]
    fn an_unresolvable_interior_node_is_rejected_fail_closed() {
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, 1)
            .unresolvable(INTERIOR_NODE);
        refuses_as_unconverged(net);
    }

    fn refuses_as_unconverged(net: FakeNet) {
        let (outcome, published, _hub) = run(7, &[], net, &[]);
        match outcome {
            Err(CreateGrantError::SubtreeNotConverged { unconverged }) => {
                assert_eq!(unconverged, vec![INTERIOR_NODE]);
            }
            other => panic!("expected SubtreeNotConverged, got {other:?}"),
        }
        assert!(published.is_empty());
    }

    /// A second interior node inside the granted folder.
    const SECOND_NODE: [u8; 16] = [0xa2; 16];
    /// An interior node one level under [`INTERIOR_NODE`].
    const DEEP_NODE: [u8; 16] = [0xa3; 16];

    #[test]
    fn every_interior_node_of_the_granted_folder_re_seals_into_the_new_scope() {
        // Without this the grantee holds a scope root whose whole interior is
        // still sealed under the scope the folder left, and epoch 1 carries no
        // history link to walk back through.
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .with_interior(SECOND_NODE, PARENT_EPOCH)
            .with_nested(INTERIOR_NODE, DEEP_NODE, PARENT_EPOCH);
        let resealed = Rc::clone(&net.resealed);
        let (outcome, _published, _hub) = run(7, &[], net, &[]);
        outcome.expect("grant creation succeeds");

        let mut nodes: Vec<[u8; 16]> = resealed
            .borrow()
            .iter()
            .map(|record| record.node_id)
            .collect();
        nodes.sort_unstable();
        assert_eq!(
            nodes,
            vec![INTERIOR_NODE, SECOND_NODE, DEEP_NODE],
            "the walk descends past the folder's own children",
        );
        for record in resealed.borrow().iter() {
            assert_eq!(
                record.scope_id, GRANTEE_SCOPE,
                "re-sealed under the scope the mint published, not the one it left",
            );
            assert_eq!(record.read_epoch, 1, "at that scope's first epoch");
            assert_eq!(
                record.ipns_name,
                interior_name(record.node_id),
                "at the name the folder's body already names it by",
            );
        }
    }

    /// One grant at the permission `write_cut` implies, over an existing fake.
    fn run_write(
        entropy_seed: u64,
        net: &FakeNet,
        write_cut: Option<&[u8; SECRET_LEN]>,
    ) -> GrantRun {
        run_full(
            SeededEntropy::new(entropy_seed),
            &[],
            net.clone(),
            &[],
            &recipient_enc(),
            &RecordingVoucher::default(),
            write_cut,
        )
    }

    /// Drive a grant that stalls on its interior move, and leave the fake
    /// holding the promoted root a re-drive resumes against.
    fn stall_grant(net: &FakeNet) {
        let (stalled, _published, _hub) = run(7, &[], net.clone(), &[]);
        assert_eq!(
            stalled
                .expect_err("the stalled publish fails the grant")
                .check(),
            "interior-publish-failed",
        );
        net.heal_reseal();
    }

    #[test]
    fn a_stalled_interior_move_finishes_on_the_root_the_first_attempt_promoted() {
        // The mint is not atomic with the move it owes. A re-drive that minted a
        // second scope would draw a second override seed and strand every node
        // the first attempt already moved.
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .with_interior(SECOND_NODE, PARENT_EPOCH)
            .stalling_reseal_at(SECOND_NODE);
        let resealed = Rc::clone(&net.resealed);
        stall_grant(&net);

        let (resumed, published, _hub) = run(8, &[], net, &[]);
        resumed.expect("the re-drive finishes the owed move");

        let mut moved: Vec<[u8; 16]> = resealed.borrow().iter().map(|r| r.node_id).collect();
        moved.sort_unstable();
        assert_eq!(
            moved,
            vec![INTERIOR_NODE, SECOND_NODE],
            "each node is moved once: the first attempt's is skipped, the tail is finished",
        );
        assert_eq!(
            published
                .iter()
                .filter(|record| record.scope_id == GRANTEE_SCOPE)
                .count(),
            1,
            "one scope root over the folder, so one override seed",
        );
    }

    #[test]
    fn a_promoted_root_that_commits_no_row_for_this_recipient_is_not_resumed() {
        // Resuming grafts no second recipient onto a scope: their blob is not in
        // its committed set, so the move would seal the subtree under a scope
        // they cannot open.
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .stalling_reseal_at(INTERIOR_NODE);
        stall_grant(&net);

        let other_recipient = X25519Secret::from_scalar([0x4b; 32]);
        let (refused, _published, _hub) = run_for(
            SeededEntropy::new(8),
            &[],
            net,
            &[],
            &other_recipient,
            &RecordingVoucher::default(),
        );
        assert_eq!(
            refused
                .expect_err("a second recipient does not resume the first one's grant")
                .check(),
            "resume-not-this-grant",
        );
    }

    /// A live scope root the resume probe does not claim still stands at the
    /// name this mint would publish at, and only the floor answers for it.
    #[test]
    fn a_floored_target_the_probe_does_not_resume_refuses_the_mint() {
        let net = FakeNet::new(Ok(())).floored_at(GRANTEE_SCOPE);
        let (refused, published, hub) = run(7, &[], net, &[]);
        assert_eq!(
            refused
                .expect_err("a mint over a floored target is refused")
                .check(),
            "target-already-names-a-scope",
        );
        assert!(published.is_empty(), "and nothing is published");
        assert_nothing_delivered(&hub);
    }

    #[test]
    fn a_promoted_root_at_another_permission_is_not_resumed() {
        // A blinded tag binds the recipient and the scope root's name, and
        // neither moves with the permission. Matching on the tag alone would
        // let a stalled write grant finish as a read grant over a root whose
        // published authority still says write.
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .stalling_reseal_at(INTERIOR_NODE);
        let write_cut = [0x77; SECRET_LEN];
        let (stalled, _published, _hub) = run_write(7, &net, Some(&write_cut));
        assert_eq!(
            stalled
                .expect_err("the stalled publish fails the grant")
                .check(),
            "interior-publish-failed",
        );
        net.heal_reseal();

        let (refused, _published, _hub) = run_write(8, &net, None);
        assert_eq!(
            refused
                .expect_err("a read grant does not finish a stalled write grant")
                .check(),
            "resume-not-this-grant",
        );
    }

    #[test]
    fn a_reordered_reparented_index_still_resumes() {
        // The index is read off a write body any committed writer of the
        // leaving scope authors, so the comparison is over the canonical form
        // rather than the bytes it happened to land in.
        let first = descendant_ref();
        let second =
            ChildScopeRef::new(SECOND_DESCENDANT_SCOPE, b"second-descendant-name".to_vec());
        let subtree = vec![first.clone(), second.clone()];
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .with_descendant_scope(first.clone())
            .with_descendant_scope(second.clone())
            .stalling_reseal_at(INTERIOR_NODE)
            .reparenting(vec![second, first]);
        let (stalled, _published, _hub) = run(7, &subtree, net.clone(), &[]);
        assert_eq!(
            stalled
                .expect_err("the stalled publish fails the grant")
                .check(),
            "interior-publish-failed",
        );
        net.heal_reseal();

        let (resumed, _published, _hub) = run(8, &subtree, net, &[]);
        resumed.expect("the same members in another order are the same index");
    }

    #[test]
    fn a_promoted_root_that_reparented_another_index_is_not_resumed() {
        // The reparented index is what the mint committed the granted scope to.
        // One that is not this plan's names a scope this plan did not mint.
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .stalling_reseal_at(INTERIOR_NODE)
            .reparenting(vec![descendant_ref()]);
        stall_grant(&net);

        let (refused, _published, _hub) = run(8, &[], net, &[]);
        assert_eq!(
            refused
                .expect_err("the plan reparents nothing, so this root is not its own")
                .check(),
            "resume-not-this-grant",
        );
    }

    #[test]
    fn the_interior_re_seal_stops_at_a_descendant_scope_root() {
        // A descendant scope root is re-keyed as a scope root, and its own
        // interior stays in the scope it already belongs to.
        let net = FakeNet::new(Ok(())).with_descendant_scope(descendant_ref());
        let resealed = Rc::clone(&net.resealed);
        let (outcome, _published, _hub) = run(7, &[descendant_ref()], net, &[]);
        outcome.expect("grant creation succeeds");
        assert!(resealed.borrow().is_empty());
    }

    /// The plan's index filters a cached snapshot. A committed writer of the
    /// scope the folder is leaving moves a descendant scope root out of the
    /// folder after that snapshot, and the re-key would seal the descendant's
    /// ascent link under the grantee's derivation — a scope the live tree no
    /// longer places inside the granted folder.
    #[test]
    fn a_planned_child_scope_the_pass_did_not_meet_refuses_the_grant() {
        let net = FakeNet::new(Ok(()));
        let (outcome, published, hub) = run(7, &[descendant_ref()], net, &[]);

        match outcome {
            Err(CreateGrantError::SubtreeBoundaryDiverged {
                planned_not_met,
                met_not_planned,
            }) => {
                assert_eq!(planned_not_met, vec![DESCENDANT_SCOPE]);
                assert!(met_not_planned.is_empty());
            }
            other => panic!("expected SubtreeBoundaryDiverged, got {other:?}"),
        }
        assert!(published.is_empty(), "refused before the promotion publish");
        assert_nothing_delivered(&hub);
    }

    /// The other direction costs availability rather than exposure: the walk
    /// stops at the observed scope root and the re-key never reparents it, so
    /// the grantee holds a child ref no derivation of theirs follows.
    #[test]
    fn a_scope_root_the_pass_met_that_the_plan_omits_refuses_the_grant() {
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .with_boundary(INTERIOR_NODE);
        let (outcome, published, hub) = run(7, &[], net, &[]);

        match outcome {
            Err(CreateGrantError::SubtreeBoundaryDiverged {
                planned_not_met,
                met_not_planned,
            }) => {
                assert!(planned_not_met.is_empty());
                assert_eq!(met_not_planned, vec![INTERIOR_NODE]);
            }
            other => panic!("expected SubtreeBoundaryDiverged, got {other:?}"),
        }
        assert!(published.is_empty(), "refused before the promotion publish");
        assert_nothing_delivered(&hub);
    }

    /// The convergence proof is stale by the time the walk consumes it. A
    /// record re-authored back down the ratchet after the pass would travel
    /// into the grantee's scope at read epoch 1 with nothing behind it.
    #[test]
    fn an_interior_node_that_regressed_after_the_pass_refuses_the_grant() {
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .regressing_after_promotion(INTERIOR_NODE, PARENT_EPOCH - 1);
        let resealed = Rc::clone(&net.resealed);
        let (outcome, _published, hub) = run(7, &[], net, &[]);

        match outcome {
            Err(CreateGrantError::InteriorEpochRegressed { node_id }) => {
                assert_eq!(node_id, INTERIOR_NODE);
            }
            other => panic!("expected InteriorEpochRegressed, got {other:?}"),
        }
        assert!(
            resealed.borrow().is_empty(),
            "no partial seal: the refusal lands before the node moves scope",
        );
        assert_nothing_delivered(&hub);
    }

    /// The walk re-asserts the proof at every level it seals, not only at the
    /// folder's own children.
    #[test]
    fn a_regression_below_the_folders_own_children_refuses_the_grant() {
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .with_nested(INTERIOR_NODE, DEEP_NODE, PARENT_EPOCH)
            .regressing_after_promotion(DEEP_NODE, PARENT_EPOCH - 1);
        let resealed = Rc::clone(&net.resealed);
        let (outcome, _published, hub) = run(7, &[], net, &[]);

        match outcome {
            Err(CreateGrantError::InteriorEpochRegressed { node_id }) => {
                assert_eq!(node_id, DEEP_NODE);
            }
            other => panic!("expected InteriorEpochRegressed, got {other:?}"),
        }
        assert!(
            !resealed
                .borrow()
                .iter()
                .any(|record| record.node_id == DEEP_NODE),
            "the regressed node never reaches the grantee's scope",
        );
        assert_nothing_delivered(&hub);
    }

    /// A node the pass measured as interior can answer as a scope root by the
    /// time the walk reaches it. A scope root is re-keyed as one, so re-sealing
    /// its record as an interior body would publish over the record that carries
    /// its own seeds.
    #[test]
    fn a_node_that_becomes_a_scope_root_after_the_pass_is_not_moved_into_the_new_scope() {
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .turning_scope_root(INTERIOR_NODE);
        let resealed = Rc::clone(&net.resealed);
        let (outcome, _published, _hub) = run(7, &[], net, &[]);

        match outcome {
            Err(CreateGrantError::InteriorNotConverged { node_id }) => {
                assert_eq!(node_id, INTERIOR_NODE);
            }
            other => panic!("expected InteriorNotConverged, got {other:?}"),
        }
        assert!(resealed.borrow().is_empty());
    }

    /// A read the walk cannot make leaves the node sealed under the scope the
    /// folder left, so the grant reports the partial commit rather than posting
    /// a pointer to a scope the grantee opens only the root of.
    #[test]
    fn an_interior_node_the_mint_cannot_read_fails_the_grant() {
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .stalling_after_promotion(INTERIOR_NODE);
        let resealed = Rc::clone(&net.resealed);
        let (outcome, _published, _hub) = run(7, &[], net, &[]);

        match outcome {
            Err(CreateGrantError::InteriorResolve { node_id, reason }) => {
                assert_eq!(node_id, INTERIOR_NODE);
                assert_eq!(reason, SweepResolveFailure::Unavailable);
            }
            other => panic!("expected InteriorResolve, got {other:?}"),
        }
        assert!(resealed.borrow().is_empty());
    }

    #[test]
    fn a_node_the_convergence_pass_never_measured_is_not_moved_into_the_new_scope() {
        // Only a committed writer of the scope the folder is leaving can author
        // the folder's body. One that names a node from elsewhere in that scope
        // would have the mint re-seal it into the grantee's scope, where the
        // owner's own readers no longer open it.
        const FOREIGN_NODE: [u8; 16] = [0xb7; 16];
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .promoting_also(FOREIGN_NODE);
        let resealed = Rc::clone(&net.resealed);
        let (outcome, _published, _hub) = run(7, &[], net, &[]);

        match outcome {
            Err(CreateGrantError::InteriorNotConverged { node_id }) => {
                assert_eq!(node_id, FOREIGN_NODE);
            }
            other => panic!("expected InteriorNotConverged, got {other:?}"),
        }
        assert!(
            !resealed
                .borrow()
                .iter()
                .any(|record| record.node_id == FOREIGN_NODE),
            "the node the pass never measured was never re-sealed",
        );
    }

    #[test]
    fn an_interior_node_that_does_not_re_seal_fails_the_grant() {
        // Post-publish: the grantee root is committed, and the grant reports the
        // node the grantee cannot open rather than posting a pointer to a scope
        // whose interior is unreadable.
        let net = FakeNet::new(Ok(()))
            .with_interior(INTERIOR_NODE, PARENT_EPOCH)
            .reseal(Err(RotationPublishError::LostRace));
        let (outcome, published, hub) = run(7, &[], net, &[]);

        match outcome {
            Err(CreateGrantError::InteriorPublish { node_id, error }) => {
                assert_eq!(node_id, INTERIOR_NODE);
                assert_eq!(error, RotationPublishError::LostRace);
            }
            other => panic!("expected InteriorPublish, got {other:?}"),
        }
        assert_eq!(
            published.len(),
            1,
            "the grantee root published before the re-seal ran"
        );
        assert_eq!(published[0].scope_id, GRANTEE_SCOPE);
        let recip_box = hub.mailbox_for(&recipient_identity().to_sec1());
        assert!(
            block_on(poll_verified(&recip_box, &recipient_enc(), V))
                .unwrap()
                .is_empty(),
            "and no share pointer names it",
        );
    }

    #[test]
    fn parent_publish_failure_leaves_the_grantee_root_committed_and_no_share() {
        // Post-publish partial commit: the grantee root publishes (call 0), then
        // the parent publish (call 1) loses the CAS race. The primitive is NOT
        // atomic past the grantee publish — the root is already on the network and NO
        // share pointer is posted. This pins the doc comment's post-publish caveat
        // to behavior.
        let (outcome, published, hub) = run(
            7,
            &[],
            FakeNet::new_fail_after(1, RotationPublishError::LostRace),
            &[],
        );

        assert_eq!(
            outcome.unwrap_err().check(),
            "parent-publish-failed",
            "the parent publish is the failing step"
        );
        // The grantee root is already committed — the partial-commit the doc warns
        // about, not a fail-closed rollback.
        assert_eq!(published.len(), 1, "grantee root committed, parent not");
        assert_eq!(published[0].scope_id, GRANTEE_SCOPE);
        // No share pointer is posted when publishing aborts before the mailbox step.
        let recip_box = hub.mailbox_for(&recipient_identity().to_sec1());
        let items = block_on(poll_verified(&recip_box, &recipient_enc(), V)).unwrap();
        assert!(items.is_empty(), "no share pointer when publish aborts");
    }

    #[test]
    fn descendant_publish_failure_leaves_the_grantee_root_committed_and_no_share() {
        // Post-publish partial commit on the re-key step (5b): the grantee root
        // publishes (call 0), then the reparented descendant's re-keyed record
        // (call 1) loses the CAS race. Fail-safe under-share — the grantee root is
        // committed but NO share pointer is posted, so the recipient never learns
        // where to look and sees zero exposure.
        let subtree = vec![descendant_ref()];
        let (outcome, published, hub) = run(
            7,
            &subtree,
            FakeNet::new_fail_after(1, RotationPublishError::LostRace)
                .with_descendant_scope(descendant_ref()),
            &[],
        );

        assert_eq!(
            outcome.unwrap_err().check(),
            "descendant-publish-failed",
            "the reparented descendant's re-key publish is the failing step"
        );
        // Only the grantee root landed (call 0); the descendant (call 1) failed and
        // the parent index (call 2) was never attempted.
        assert_eq!(published.len(), 1, "grantee root committed, descendant not");
        assert_eq!(published[0].scope_id, GRANTEE_SCOPE);
        // Fail-safe: with no share pointer the recipient cannot locate the grantee
        // root, so the partial commit exposes nothing.
        let recip_box = hub.mailbox_for(&recipient_identity().to_sec1());
        let items = block_on(poll_verified(&recip_box, &recipient_enc(), V)).unwrap();
        assert!(
            items.is_empty(),
            "no share pointer on a failed descendant re-key"
        );
    }

    #[test]
    fn creation_is_deterministic_under_a_fixed_entropy_seed() {
        // A non-empty subtree drives the re-key's entropy draws (HPKE ephemerals,
        // seal nonces in the descendant re-key), proving they too are byte-identical
        // under a fixed seed.
        let subtree = vec![descendant_ref()];
        let net = || FakeNet::new(Ok(())).with_descendant_scope(descendant_ref());
        let (a_outcome, a_pub, _) = run(42, &subtree, net(), &[]);
        let (b_outcome, b_pub, _) = run(42, &subtree, net(), &[]);
        assert_eq!(a_outcome.unwrap(), b_outcome.unwrap());
        assert_eq!(a_pub, b_pub, "same seed → byte-identical published records");
    }

    #[test]
    fn the_idempotency_key_is_entropy_drawn_and_carries_no_public_material() {
        // The API keeps only sha256(sender : key), so a key an observer can
        // recompute hands back the sharing edge. The blinded tag is public and
        // ships in the clear in the grant section, so it must not appear here.
        let (a, tag) = delivery_for(7, &recipient_enc());
        let (b, _) = delivery_for(9, &recipient_enc());

        assert_ne!(
            a.idempotency_key, b.idempotency_key,
            "the key follows the entropy seam, not the grant's own material"
        );
        assert!(
            !a.idempotency_key.contains(&hex_lower(&tag)),
            "the public blinded tag never reaches the wire as the key"
        );
    }

    #[test]
    fn delivery_is_addressed_and_keyed_in_the_shape_the_transport_accepts() {
        // Posting the X25519 subkey as the routing address, or a `grant:`-prefixed
        // idempotency key, is a `PostMessageDto` refusal.
        let (delivery, _) = delivery_for(7, &recipient_enc());

        assert_eq!(
            delivery.address,
            recipient_identity().to_sec1(),
            "routing address is the recipient's compressed SEC1 identity key"
        );
        assert!(
            crate::mailbox::idempotency_key_is_legal(&delivery.idempotency_key),
            "idempotency key {:?} leaves the transport alphabet",
            delivery.idempotency_key
        );
    }

    #[test]
    fn the_wrap_target_and_the_routing_address_are_one_bound_pair() {
        // The grant blob conveys the read scope seed and the pointer routes the
        // grantee to it. Sourcing the two keys apart seals the seed to one party
        // and tells another to look, which the contact-code binding signature
        // exists to deny, so both must read off one verified contact.
        let contact = contact_for(recipient_enc().public());
        let (delivery, tag) = delivery_for(7, &recipient_enc());

        assert_eq!(
            delivery.address,
            contact.identity_pk().to_sec1(),
            "the pointer is addressed to the contact's identity key"
        );
        assert_eq!(
            Some(tag),
            recipient_blinded_tag(&owner_enc(), &contact.enc_subkey(), &grantee_name()),
            "the committed tag is the ECDH with the subkey that identity key bound"
        );
    }

    #[test]
    fn grantee_can_descend_into_a_reparented_descendant() {
        // A reparented descendant re-keys under the fresh grantee derivation (see
        // `GranteeScopePlan::subtree_child_index`) so the grantee, holding only its
        // grant-blob seed, can descend the shared subtree. No floor is raised, so
        // the pre-mint sweep publishes nothing (the descendant is already
        // converged); the descendant record below is published solely by the re-key
        // step, and the lookup finds nothing without it.
        let subtree = vec![descendant_ref()];
        let (outcome, published, _hub) = run(
            7,
            &subtree,
            FakeNet::new(Ok(())).with_descendant_scope(descendant_ref()),
            &[],
        );
        outcome.expect("grant creation succeeds over a converged subtree");

        // The grantee opens its grant blob to recover the fresh override seed.
        let grantee_record = published
            .iter()
            .find(|r| r.scope_id == GRANTEE_SCOPE)
            .expect("grantee root published");
        let grantee_tag =
            recipient_blinded_tag(&recipient_enc(), &owner_enc().public(), &grantee_name())
                .unwrap();
        let grant_blob = grantee_record
            .section
            .grant_blobs
            .iter()
            .find(|b| b.tag == grantee_tag)
            .expect("grantee grant blob present");
        let grant_ctx = AadContext {
            v: V,
            id: GRANTEE_SCOPE,
            scope: GRANTEE_SCOPE,
            epoch: 1,
            struct_tag: STRUCT_TAG_GRANT_BLOB,
        };
        let grant_payload = open_grant_blob(
            &recipient_enc(),
            &grant_blob.enc,
            &grant_ctx,
            &grant_blob.ciphertext,
        )
        .expect("grantee opens its grant blob");
        let grantee_seed = *grant_payload.read_scope_seed();

        // The descendant was re-keyed and published; its ascent link opens under
        // the grantee's derivation and yields the descendant's own override seed
        // ([0x71; _] from the resolver) — proving the grantee can descend.
        let descendant_record = published
            .iter()
            .find(|r| r.scope_id == DESCENDANT_SCOPE)
            .expect("descendant re-keyed and published");
        assert_eq!(
            descendant_record.read_epoch, 1,
            "metadata-only re-key: no epoch bump"
        );
        let ascent = descendant_record
            .section
            .ascent_link
            .as_ref()
            .expect("reparented descendant carries an ascent link");
        let parent_node_seed = *kdf::node_seed(&grantee_seed, &DESCENDANT_SCOPE).as_bytes();
        let ascent_ctx = AadContext {
            v: V,
            id: DESCENDANT_SCOPE,
            scope: DESCENDANT_SCOPE,
            epoch: 1,
            struct_tag: STRUCT_TAG_ASCENT_LINK,
        };
        let link = AscentLink {
            ascent_public: ascent.ascent_public,
            enc: ascent.enc,
            ciphertext: ascent.ciphertext.clone(),
            unknown: PreservedFields::new(),
        };
        let descend = open_ascent_link(&parent_node_seed, &ascent_ctx, &link)
            .expect("grantee derivation opens the descendant ascent link");
        assert!(
            ct_eq(descend.override_seed(), &[0x71; SECRET_LEN]),
            "ascent link yields the descendant override seed under the grantee derivation"
        );
    }

    #[test]
    fn descendant_scope_root_publishes_under_the_enumerated_ref_name() {
        // The re-key must publish/reseal the reparented descendant under
        // the name from the enumerated `ChildScopeRef` (`descendant.ipns_name`),
        // not the resolved target's — the scope-root publication binding enforced
        // in sweep.rs. A regression to any other name (e.g. the parent's) is
        // caught here.
        let subtree = vec![descendant_ref()];
        let (outcome, published, _hub) = run(
            7,
            &subtree,
            FakeNet::new(Ok(())).with_descendant_scope(descendant_ref()),
            &[],
        );
        outcome.expect("grant creation succeeds over a converged subtree");

        let descendant_record = published
            .iter()
            .find(|r| r.scope_id == DESCENDANT_SCOPE)
            .expect("descendant re-keyed and published");
        assert_eq!(
            descendant_record.ipns_name,
            DESCENDANT_NAME.to_vec(),
            "published under the enumerated ChildScopeRef name"
        );
        assert_ne!(
            descendant_record.ipns_name,
            PARENT_NAME.to_vec(),
            "never republished under the parent scope-root name"
        );
    }

    #[test]
    fn a_self_grant_is_refused_before_any_network_effect() {
        let net = FakeNet::new(Ok(()));
        let (outcome, published, hub) = run_for(
            SeededEntropy::new(7),
            &[],
            net.clone(),
            &[],
            &owner_enc(),
            &RecordingVoucher::default(),
        );

        let err = outcome.expect_err("a self-grant is refused");
        assert_eq!(err, CreateGrantError::RecipientIsTheOwner);
        assert_eq!(err.check(), "recipient-is-the-owner");
        // The sweep's first act is a `resolve_scope`, so a zero read count is
        // what pins the refusal ahead of the convergence gate; `published` alone
        // cannot, since a sweep over an empty subtree publishes nothing.
        assert_eq!(net.resolve_calls(), 0, "no read seam is consulted");
        assert!(published.is_empty(), "nothing reaches the network");
        // Raw `poll`, not `poll_verified`: an unopenable blob must count as a
        // post, not be filtered away into a false pass.
        let recip_box = hub.mailbox_for(&recipient_identity().to_sec1());
        let items = block_on(recip_box.poll()).unwrap();
        assert!(items.is_empty(), "no share pointer is posted");
    }

    #[test]
    fn a_swapped_recipient_key_in_the_parent_ledger_costs_only_its_own_row() {
        // A committed write-grantee of the PARENT scope swaps a victim's
        // `recipientEncPk` under the victim's owner-committed tag. Tag and
        // permission still match, so owner authority over the set passes — but
        // the row's own owner signature covers the key, so the swap detaches the
        // row. The parent re-seal wraps no seed to the attacker's key and still
        // completes: refusing would let any co-writer block every share the owner
        // makes from that scope.
        let victim = X25519Secret::from_scalar([0x51; SECRET_LEN]);
        let attacker = X25519Secret::from_scalar([0x52; SECRET_LEN]);
        let bystander = X25519Secret::from_scalar([0x53; SECRET_LEN]);
        let mut row = parent_row(&victim.public());
        row.ledger_entry.recipient_enc_pk = attacker.public().to_bytes();
        let untouched = parent_row(&bystander.public());
        let bystander_tag = untouched.tag;

        let (outcome, published, _hub) = run(7, &[], FakeNet::new(Ok(())), &[row, untouched]);

        outcome.expect("the share the swapped row was meant to block still lands");
        let parent = published
            .iter()
            .find(|r| r.scope_id == PARENT_SCOPE)
            .expect("the parent record reaches the network");
        let ctx = AadContext {
            v: V,
            id: PARENT_SCOPE,
            scope: PARENT_SCOPE,
            epoch: parent.read_epoch,
            struct_tag: STRUCT_TAG_GRANT_BLOB,
        };
        assert!(
            parent.section.grant_blobs.iter().all(|b| open_grant_blob(
                &attacker,
                &b.enc,
                &ctx,
                &b.ciphertext
            )
            .is_err()),
            "no blob in the parent section opens under the swapped key"
        );
        let blob = parent
            .section
            .grant_blobs
            .iter()
            .find(|b| b.tag == bystander_tag)
            .expect("the untouched co-grantee still gets its blob");
        assert!(
            open_grant_blob(&bystander, &blob.enc, &ctx, &blob.ciphertext).is_ok(),
            "and it opens, so the swept-past section is real"
        );
    }

    #[test]
    fn a_relabelled_parent_row_cannot_redirect_the_parent_blob() {
        // A committed write grantee authors the ledger row, so it can relabel
        // `recipientEncPk` there and re-file it. The re-seal takes the recipient
        // off the owner-signed commitment entry instead, so the relabel is inert:
        // the blob still opens for the committed party and never for the
        // attacker.
        let victim = X25519Secret::from_scalar([0x51; SECRET_LEN]);
        let attacker = X25519Secret::from_scalar([0x52; SECRET_LEN]);
        let mut row = parent_row(&victim.public());
        row.ledger_entry.recipient_enc_pk = attacker.public().to_bytes();
        row.ledger_entry.owner_sig =
            sign_recipient_binding(&owner_identity(), PARENT_NAME, &row.ledger_entry)
                .expect("the owner attests the row")
                .to_compact();
        let tag = row.tag;

        let (outcome, published, _hub) = run(7, &[], FakeNet::new(Ok(())), &[row]);
        outcome.expect("the parent re-seal ignores the row's recipient field");

        let parent = published
            .iter()
            .find(|r| r.scope_id == PARENT_SCOPE)
            .expect("the parent record publishes");
        let ctx = AadContext {
            v: V,
            id: PARENT_SCOPE,
            scope: PARENT_SCOPE,
            epoch: parent.read_epoch,
            struct_tag: STRUCT_TAG_GRANT_BLOB,
        };
        let blob = parent
            .section
            .grant_blobs
            .iter()
            .find(|b| b.tag == tag)
            .expect("the committed grantee still gets its blob");
        assert!(
            open_grant_blob(&victim, &blob.enc, &ctx, &blob.ciphertext).is_ok(),
            "the blob opens for the party the owner committed"
        );
        assert!(
            open_grant_blob(&attacker, &blob.enc, &ctx, &blob.ciphertext).is_err(),
            "and never for the key the row was relabelled to"
        );
    }

    /// One honestly minted parent-scope row for `recipient`.
    fn parent_row(recipient: &X25519Public) -> GrantRow {
        mint_grant_row(
            &owner_identity(),
            &owner_enc(),
            &PARENT_POINTER_READ_KEY,
            recipient_identity().to_sec1(),
            recipient,
            &PARENT_SCOPE,
            PARENT_NAME,
            Permission::Read,
        )
        .expect("a contributory recipient key")
    }
}
