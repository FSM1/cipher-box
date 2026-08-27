//! Owner-side read-grant creation (blueprint/engine.md "Grants and ledger:
//! Grant creation").
//!
//! Mints the owner-only **read** sharing path in the sequence the blueprint
//! fixes: converge the subtree, mint the grantee scope at read epoch 1, publish
//! grantee-first, re-key the reparented descendants under the fresh derivation,
//! then post the sealed share pointer. Convergence is the load-bearing
//! correctness rule — a grant over a subtree that cannot be proven
//! epoch-converged is refused **fail-closed**, so a new grantee can never regress
//! through an ancestor scope's history (CONTEXT.md "Epoch-converged").
//!
//! # Simulation boundary
//!
//! Deterministic-simulation slice: entropy is the injected [`Entropy`] seam and
//! the read/floor/publish/mailbox effects are faked in tests. Every seam this
//! composes over has a production implementation in [`crate::net::rotation`].
//!
//! # Not implemented here
//!
//! - **Write grants**: the write-scope cut via [`rotate_scope_write`](super::
//!   super::rotation::rotate_scope_write) plus the both-seeds grant blob, layered
//!   on this identical skeleton.
//! - **Invites**: ephemeral-key blobs, bearer write-link flagging, claim
//!   conversion.
//!
//! This module composes existing machinery only and holds no crypto of its own.

use cipherbox_core::error::CodecError;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildScopeRef, GrantLedgerEntry, GrantSetCommitment, Permission, PreservedFields, SignedSealed,
    sign_grant_set,
};
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier, SIGNATURE_LEN as ECDSA_SIG_LEN};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use core::fmt;
use zeroize::Zeroizing;

use crate::entropy::{Entropy, EntropyError, fresh_bytes, fresh_ephemeral, fresh_seed};
use crate::grants::SharePointer;
use crate::grants::child_index::{canonicalize, insert_child, remove_child};
use crate::grants::{GrantRow, mint_grant_row};
use crate::mailbox::post_sealed;
use crate::rotation::{
    AscentAuthority, CascadeResealResolver, CommittedSet, NodeRef, ResealError, ResealSeeds,
    ResealedScopeRoot, ResolveFailure, RotationPublishError, ScopeRootIdentity, ScopeRootPublisher,
    SweepError, SweepPublisher, SweepResolver, WriteHistory, converge_subtree, derive_write_name,
    reseal_scope_root,
};
use crate::seams::{Mailbox, SeamError};
use cipherbox_core::hex::lower as hex_lower;
use cipherbox_core::ipns::IpnsName;

/// The fresh grantee scope minted at the granted folder. `scope_id` is the
/// folder's node id (a scope root's node id is its scope id). The read grant
/// anchors only the read plane at epoch 1; the write plane stays the folder's
/// inherited one (flat derivation), so `write_scope_seed`/`write_epoch` are the
/// folder's current write-scope material — no write-scope cut (that is the
/// write-grant follow-on).
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
    /// The folder's inherited write-scope seed (read grants cut no write scope).
    pub write_scope_seed: &'a [u8; SECRET_LEN],
    /// The folder's current write epoch.
    pub write_epoch: u64,
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
}

/// The recipient of the read grant.
pub struct GrantRecipient<'a> {
    /// secp256k1 identity key — the ledger entry and the mailbox routing
    /// address. Source it from the imported [`Contact`], whose binding
    /// signature is what ties it to `enc_pub`.
    ///
    /// [`Contact`]: super::Contact
    pub identity_pk: EcdsaVerifier,
    /// X25519 encryption subkey public key: the grant-blob and mailbox HPKE
    /// wrap target.
    pub enc_pub: &'a X25519Public,
    /// Courtesy host label carried in the share pointer.
    pub display_name: String,
}

/// Owner-held key material for the grant. `pseudonym_signer` must be the
/// owner's writer pseudonym for the new scope; its public key becomes the
/// commitment's `owner_pseudonym_pk` and reseal signs every structure with it.
pub struct OwnerGrantKeys<'a> {
    /// Owner encryption subkey secret — the pairwise ECDH half for the blinded
    /// tag and the recipient's writer pseudonym.
    pub enc_secret: &'a X25519Secret,
    /// Owner identity signer — signs the epoch-free grant-set commitment; its
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
    /// Resolving a reparented descendant for its re-key failed. Post-publish: the
    /// grantee root and any earlier-re-keyed descendants are committed; this one
    /// keeps its old parent derivation (grantee cannot yet descend into it).
    DescendantResolve {
        /// The descendant that could not be resolved.
        scope_id: [u8; 16],
        /// The fail-closed resolve failure.
        reason: ResolveFailure,
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
    /// Posting the sealed share pointer to the recipient mailbox failed.
    /// Post-publish: both scope roots are published and the parent index is
    /// updated; only the share pointer is missing. A retry posts a fresh item —
    /// delivery is at-least-once, and the accept flow is the dedup point.
    Mailbox(SeamError),
}

impl CreateGrantError {
    /// A stable machine tag for assertions and host classification.
    pub fn check(&self) -> &'static str {
        match self {
            Self::Converge(_) => "converge-failed",
            Self::SubtreeNotConverged { .. } => "subtree-not-converged",
            Self::UnusableRecipientKey => "unusable-recipient-key",
            Self::RecipientIsTheOwner => "recipient-is-the-owner",
            Self::CommitmentEncode(_) => "commitment-encode-failed",
            Self::Entropy(_) => "entropy-error",
            Self::Mint(_) => "mint-failed",
            Self::Publish(_) => "publish-failed",
            Self::DescendantResolve { .. } => "descendant-resolve-failed",
            Self::DescendantMint { .. } => "descendant-mint-failed",
            Self::DescendantPublish { .. } => "descendant-publish-failed",
            Self::ParentMint(_) => "parent-mint-failed",
            Self::ParentPublish(_) => "parent-publish-failed",
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
    async fn promote_scope_root(
        &self,
        parent: &ChildScopeRef,
        node: &NodeRef,
        record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError>;
}

/// Mint a read grant for one recipient over `grantee`'s folder.
///
/// The recipient's row over [`mint_grantee_scope`], then the mailbox share
/// pointer that tells them where to look. Fail-closed **through the grantee
/// publish**; past that point the sequence is not atomic — see
/// [`CreateGrantError`] for what each post-publish variant leaves committed.
#[allow(clippy::too_many_arguments)]
pub async fn create_read_grant<E, R, P, M>(
    entropy: &mut E,
    resolver: &R,
    publisher: &P,
    mailbox: &M,
    grantee: &GranteeScopePlan<'_>,
    recipient: &GrantRecipient<'_>,
    owner: &OwnerGrantKeys<'_>,
    parent: &ParentScopePlan<'_>,
) -> Result<CreateGrantOutcome, CreateGrantError>
where
    E: Entropy,
    R: SweepResolver + CascadeResealResolver,
    P: ScopeRootPublisher + SweepPublisher + ScopeRootPromoter,
    M: Mailbox,
{
    // Refused ahead of the publishing sweep, so a self-grant costs no publish.
    if *recipient.enc_pub == owner.enc_secret.public() {
        return Err(CreateGrantError::RecipientIsTheOwner);
    }
    let ipns_name = grantee.ipns_name();
    let name_bytes = ipns_name.as_str().as_bytes();
    let row = mint_grant_row(
        owner.identity_signer,
        owner.enc_secret,
        recipient.identity_pk.to_sec1(),
        recipient.enc_pub,
        &grantee.scope_id,
        name_bytes,
        Permission::Read,
    )
    .ok_or(CreateGrantError::UnusableRecipientKey)?;
    let converged = converge_grant_subtree(resolver, publisher, grantee, parent).await?;
    let outcome = mint_grantee_scope(entropy, resolver, publisher, &converged, &row, owner).await?;

    // Post the sealed share pointer to the recipient's mailbox with a fresh
    // HPKE ephemeral scalar (never a clock or a constant).
    let pointer = SharePointer {
        scope_root_name: name_bytes.to_vec(),
        sharer_identity_pk: owner.identity_signer.verifying_key().to_sec1(),
        display_name: recipient.display_name.clone(),
        permission: Permission::Read,
    };
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
        recipient.enc_pub,
        &recipient.identity_pk,
        &ephemeral,
        grantee.v,
        owner.identity_signer,
        &pointer.encode(),
        &idempotency_key,
    )
    .await
    .map_err(CreateGrantError::Mailbox)?;

    Ok(outcome)
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
}

/// Prove the granted folder's subtree epoch-converged inside the scope it still
/// lives in, so no interior node the grantee will read lags that scope's epoch.
///
/// [`mint_grantee_scope`] publishes a scope its grantee reads from epoch 1, and
/// this is what has to hold before it does. Split from the mint so a caller can
/// put its own durable write between the two: a dropped lost race means
/// convergence is unproven, and refusing there should cost nothing that outlives
/// the refusal (CONTEXT.md "Epoch-converged").
pub async fn converge_grant_subtree<'a, R, P>(
    resolver: &R,
    publisher: &P,
    grantee: &'a GranteeScopePlan<'a>,
    parent: &'a ParentScopePlan<'a>,
) -> Result<ConvergedSubtree<'a>, CreateGrantError>
where
    R: SweepResolver,
    P: SweepPublisher,
{
    let ipns_name = grantee.ipns_name();
    let swept = converge_subtree(
        resolver,
        publisher,
        &ChildScopeRef::new(parent.identity.scope_id, parent.identity.ipns_name.to_vec()),
        &NodeRef {
            node_id: grantee.scope_id,
            ipns_name: ipns_name.as_str().as_bytes().to_vec(),
        },
    )
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
    Ok(ConvergedSubtree { grantee, parent })
}

/// Mint the grantee scope `row` is committed at, and hand the granted folder to
/// it: mint (epoch 1) → publish (grantee first) → re-key the reparented
/// descendants under the fresh grantee derivation → parent index update.
///
/// The scope it mints commits exactly `row` and carries no history links, so
/// whoever holds that row's grant blob reaches this scope's first epoch and
/// nothing before it — the property that separates a scope mint from a row
/// appended to a scope the owner has already been rotating (#25 D6). `row` must
/// be minted at [`GranteeScopePlan::ipns_name`]; the mint binds the same bytes.
///
/// Fail-closed **through the grantee publish**.
pub async fn mint_grantee_scope<E, R, P>(
    entropy: &mut E,
    resolver: &R,
    publisher: &P,
    converged: &ConvergedSubtree<'_>,
    row: &GrantRow,
    owner: &OwnerGrantKeys<'_>,
) -> Result<CreateGrantOutcome, CreateGrantError>
where
    E: Entropy,
    R: SweepResolver + CascadeResealResolver,
    P: ScopeRootPublisher + SweepPublisher + ScopeRootPromoter,
{
    let ConvergedSubtree { grantee, parent } = converged;
    // 1) The scope root's ipnsName, derived from the folder's write material.
    let ipns_name = grantee.ipns_name();
    let name_bytes = ipns_name.as_str().as_bytes();

    // 2) Build the committed set around the row — one entry, so the scope's
    // whole grant set is the one this mint authorises.
    let owner_identity = owner.identity_signer.verifying_key();
    let tag = row.tag;
    let commitment = GrantSetCommitment {
        ipns_name: name_bytes.to_vec(),
        owner_pseudonym_pk: owner.pseudonym_signer.verifying_key().to_bytes(),
        entries: vec![row.commitment_entry.clone()],
        unknown: PreservedFields::new(),
    };
    let commitment_sig = sign_grant_set(owner.identity_signer, &commitment)
        .map_err(CreateGrantError::CommitmentEncode)?
        .to_compact();
    let ledger = vec![row.ledger_entry.clone()];

    // 3) Mint at read epoch 1 with a FRESH RANDOM override seed (never
    // KDF-derived). The new scope adopts the folder's descendant scope roots as
    // its direct-child-scope index (they now live inside the granted scope).
    let override_seed = fresh_seed(entropy).map_err(CreateGrantError::Entropy)?;

    let grantee_section = {
        let identity = ScopeRootIdentity {
            v: grantee.v,
            scope_id: grantee.scope_id,
            ipns_name: name_bytes,
            owner_enc_pub: grantee.owner_enc_pub,
            owner_enc_secret: Some(owner.enc_secret),
            ascent: Some(AscentAuthority::ParentSeed(grantee.parent_node_seed)),
            // A grant on an interior folder anchors a scope under its parent.
            owes_ascent_link: true,
            pseudonym_signer: owner.pseudonym_signer,
        };
        let seeds = ResealSeeds {
            override_seed: &override_seed,
            read_epoch: 1,
            prev: None,
            write_scope_seed: grantee.write_scope_seed,
            write_epoch: grantee.write_epoch,
            write_history: WriteHistory::Carried(&[]),
            pointer_read_key: grantee.pointer_read_key,
        };
        // Mint-canonical: the adopted index carries the same canonicalization the
        // sweep's self-heal enforces (sweep.rs), so the grantee root never lands a
        // shape the convergence pass would later have to repair.
        let grantee_child_index = canonicalize(grantee.subtree_child_index);
        let committed = CommittedSet {
            owner_identity: &owner_identity,
            commitment: &commitment,
            commitment_sig: &commitment_sig,
            grant_ledger: &ledger,
            direct_child_scope_index: &grantee_child_index,
            revoked_recipients: &[],
        };
        reseal_scope_root(entropy, &identity, &seeds, &committed, &[])
            .map_err(CreateGrantError::Mint)?
    };
    let grantee_record = ResealedScopeRoot {
        scope_id: grantee.scope_id,
        ipns_name: name_bytes.to_vec(),
        read_epoch: 1,
        write_epoch: grantee.write_epoch,
        section: grantee_section,
    };

    // 4) Publish the grantee scope root FIRST: it exists before the parent
    // references it (register-first / never-orphan), and its index carries the
    // reparented descendants before they are removed from the parent
    // (dest-first). A folder becoming a scope root is a promotion, not a
    // republish ([`ScopeRootPromoter`]).
    publisher
        .promote_scope_root(
            &ChildScopeRef::new(parent.identity.scope_id, parent.identity.ipns_name.to_vec()),
            &NodeRef {
                node_id: grantee.scope_id,
                ipns_name: name_bytes.to_vec(),
            },
            &grantee_record,
        )
        .await
        .map_err(CreateGrantError::Publish)?;

    // 4b) Re-key the reparented direct children so each ascent link re-seals under
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
            owner_identity: &owner_identity,
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

    // 5) Parent index update — a metadata-only re-seal at the same epoch.
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
            owner_identity: &owner_identity,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::ledger::self_locate;
    use crate::grants::recipient_blinded_tag;
    use crate::grants::{GrantRow, PublishedGrantBlob};
    use crate::mailbox::poll_verified;
    use crate::rotation::{
        CascadeTarget, LaggingNode, NodeRef, PrevEpochSeed, ResolveFailure, SweepResolveFailure,
        SweptChild, SweptNode, SweptScope,
    };
    use crate::testkit::fakes::InMemoryMailboxHub;
    use crate::testkit::{SeededEntropy, SilentAtWidth, SilentEntropy, block_on};
    use cipherbox_core::seal::{
        AadContext, AscentLink, ChildRef, NodeKind, ReadBody, STRUCT_TAG_ASCENT_LINK,
        STRUCT_TAG_GRANT_BLOB, open_ascent_link, open_grant_blob, sign_recipient_binding,
    };
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
    const PARENT_SCOPE: [u8; 16] = [0x0e; 16];
    const PARENT_NAME: &[u8] = b"parent-scope-root-name";
    const DESCENDANT_SCOPE: [u8; 16] = [0xdd; 16];
    const DESCENDANT_NAME: &[u8] = b"descendant-scope-root-name";
    /// The read epoch every `ParentScopePlan` below re-seals at — the epoch the
    /// convergence sweep measures the parent scope's interior nodes against.
    const PARENT_EPOCH: u64 = 3;
    /// An interior node of the parent scope, inside the granted folder.
    const INTERIOR_NODE: [u8; 16] = [0xa1; 16];

    /// One interior node's simulated name inside the parent scope.
    fn interior_name(node_id: [u8; 16]) -> Vec<u8> {
        format!("interior-{:02x}", node_id[0]).into_bytes()
    }

    /// One interior node of the parent scope: its id and its published epoch.
    type InteriorNodeState = ([u8; 16], u64);

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
    fn recipient_identity() -> EcdsaVerifier {
        EcdsaSigner::from_scalar(&[0x45; 32])
            .expect("valid scalar")
            .verifying_key()
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
        /// A node the sweep cannot resolve at all.
        unresolvable: Option<[u8; 16]>,
        /// A node the scope's ratchet cannot open.
        unreadable: Option<[u8; 16]>,
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
                unresolvable: None,
                unreadable: None,
            }
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
                direct_child_scope_index: Vec::new(),
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
            // The granted folder is itself an interior node of the parent scope
            // until the mint publishes its scope root; its body names the nodes
            // the convergence gate must reach.
            let (epoch, children) = if child.node_id == GRANTEE_SCOPE {
                (
                    PARENT_EPOCH,
                    self.interior
                        .borrow()
                        .iter()
                        .map(|(node_id, _)| ChildRef {
                            id: *node_id,
                            name: "n".into(),
                            ipns_name: interior_name(*node_id),
                            kind: NodeKind::Folder,
                            link_counter: 1,
                            unknown: PreservedFields::new(),
                        })
                        .collect(),
                )
            } else {
                let epoch = self
                    .interior
                    .borrow()
                    .iter()
                    .chain(self.outside.borrow().iter())
                    .find(|(node_id, _)| *node_id == child.node_id)
                    .map(|(_, epoch)| *epoch)
                    .ok_or(SweepResolveFailure::Unavailable)?;
                (epoch, Vec::new())
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
            if scope.scope_id != DESCENDANT_SCOPE {
                return Err(ResolveFailure::Rejected);
            }
            let pseudonym = owner_pseudonym();
            let commitment = GrantSetCommitment {
                ipns_name: DESCENDANT_NAME.to_vec(),
                owner_pseudonym_pk: pseudonym.verifying_key().to_bytes(),
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
                write_scope_seed: Zeroizing::new([0x72; SECRET_LEN]),
                pointer_read_key: Zeroizing::new([0x73; SECRET_LEN]),
                write_epoch: 1,
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

    /// The promotion seam over the same recording publisher; the base's real
    /// provenance is pinned against the production net
    /// (`crates/engine/tests/owner_actions.rs`).
    impl ScopeRootPromoter for FakeNet {
        async fn promote_scope_root(
            &self,
            _parent: &ChildScopeRef,
            _node: &NodeRef,
            record: &ResealedScopeRoot,
        ) -> Result<(), RotationPublishError> {
            self.publish_scope_root(record).await
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
        let grantee_pointer_read_key = [0x66; SECRET_LEN];
        let parent_override_seed = [0x0a; SECRET_LEN];
        let parent_write_scope_seed = [0x0b; SECRET_LEN];
        let parent_pointer_read_key = [0x0c; SECRET_LEN];
        let parent_commitment = GrantSetCommitment {
            ipns_name: PARENT_NAME.to_vec(),
            owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
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
            write_epoch: 1,
            pointer_read_key: &grantee_pointer_read_key,
            subtree_child_index: &[],
        };
        let recipient = GrantRecipient {
            identity_pk: recipient_identity(),
            enc_pub: &recipient_pub,
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
                write_history: WriteHistory::Carried(&[]),
                write_scope_seed: &parent_write_scope_seed,
                write_epoch: 2,
                pointer_read_key: &parent_pointer_read_key,
            },
            commitment: &parent_commitment,
            commitment_sig: &parent_commitment_sig,
            grant_ledger: &[],
            current_child_index: &[],
            carried_history_links: &[],
        };
        let outcome = block_on(create_read_grant(
            &mut entropy,
            &net,
            &net,
            &recorder,
            &grantee,
            &recipient,
            &owner,
            &parent,
        ))
        .expect("grant creation succeeds");

        let posts = recorder.posts.borrow();
        assert_eq!(posts.len(), 1, "exactly one mailbox post per grant");
        (posts[0].clone(), outcome.tag)
    }

    /// A read grant with the given subtree, run against fresh fakes on seed
    /// `entropy_seed`. Returns the outcome, the published records, and the mailbox
    /// hub so the caller can assert on delivery.
    #[allow(clippy::type_complexity)]
    fn run(
        entropy_seed: u64,
        subtree: &[ChildScopeRef],
        net: FakeNet,
        parent_grants: &[GrantRow],
    ) -> (
        Result<CreateGrantOutcome, CreateGrantError>,
        Vec<ResealedScopeRoot>,
        InMemoryMailboxHub,
    ) {
        run_for(
            SeededEntropy::new(entropy_seed),
            subtree,
            net,
            parent_grants,
            &recipient_enc(),
        )
    }

    fn run_for<E: Entropy>(
        mut entropy: E,
        subtree: &[ChildScopeRef],
        net: FakeNet,
        parent_grants: &[GrantRow],
        recipient_enc: &X25519Secret,
    ) -> (
        Result<CreateGrantOutcome, CreateGrantError>,
        Vec<ResealedScopeRoot>,
        InMemoryMailboxHub,
    ) {
        let hub = InMemoryMailboxHub::default();
        let mailbox = hub.mailbox_for(&recipient_identity().to_sec1());

        let owner_enc = owner_enc();
        let owner_enc_pub = owner_enc.public();
        let owner_identity = owner_identity();
        let owner_pseudonym = owner_pseudonym();
        let recipient_pub = recipient_enc.public();

        let parent_node_seed = [0x44; SECRET_LEN];
        let grantee_write_scope_seed = GRANTEE_WRITE_SCOPE_SEED;
        let grantee_pointer_read_key = [0x66; SECRET_LEN];

        let parent_override_seed = [0x0a; SECRET_LEN];
        let parent_write_scope_seed = [0x0b; SECRET_LEN];
        let parent_pointer_read_key = [0x0c; SECRET_LEN];
        let parent_commitment = GrantSetCommitment {
            ipns_name: PARENT_NAME.to_vec(),
            owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
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
                write_epoch: 1,
                pointer_read_key: &grantee_pointer_read_key,
                subtree_child_index: subtree,
            };
            let recipient = GrantRecipient {
                identity_pk: recipient_identity(),
                enc_pub: &recipient_pub,
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
                    write_history: WriteHistory::Carried(&[]),
                    write_scope_seed: &parent_write_scope_seed,
                    write_epoch: 2,
                    pointer_read_key: &parent_pointer_read_key,
                },
                commitment: &parent_commitment,
                commitment_sig: &parent_commitment_sig,
                grant_ledger: &parent_ledger,
                current_child_index: &[],
                carried_history_links: &[],
            };
            block_on(create_read_grant(
                &mut entropy,
                &net,
                &net,
                &mailbox,
                &grantee,
                &recipient,
                &owner,
                &parent,
            ))
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
        );

        assert!(matches!(
            outcome.expect_err("the zero draw is refused"),
            CreateGrantError::Entropy(_),
        ));
        assert!(published.is_empty(), "no scope root is minted");
        let recip_box = hub.mailbox_for(&recipient_identity().to_sec1());
        assert!(
            block_on(poll_verified(&recip_box, &recipient_enc(), V))
                .unwrap()
                .is_empty(),
            "and nothing is delivered",
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
        let subtree = vec![ChildScopeRef::new(
            DESCENDANT_SCOPE,
            DESCENDANT_NAME.to_vec(),
        )];
        let (outcome, published, hub) = run(
            7,
            &subtree,
            FakeNet::new_fail_after(1, RotationPublishError::LostRace),
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
        let subtree = vec![ChildScopeRef::new(
            DESCENDANT_SCOPE,
            DESCENDANT_NAME.to_vec(),
        )];
        let (a_outcome, a_pub, _) = run(42, &subtree, FakeNet::new(Ok(())), &[]);
        let (b_outcome, b_pub, _) = run(42, &subtree, FakeNet::new(Ok(())), &[]);
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
    fn grantee_can_descend_into_a_reparented_descendant() {
        // A reparented descendant re-keys under the fresh grantee derivation (see
        // `GranteeScopePlan::subtree_child_index`) so the grantee, holding only its
        // grant-blob seed, can descend the shared subtree. No floor is raised, so
        // the pre-mint sweep publishes nothing (the descendant is already
        // converged); the descendant record below is published solely by the re-key
        // step, and the lookup finds nothing without it.
        let subtree = vec![ChildScopeRef::new(
            DESCENDANT_SCOPE,
            DESCENDANT_NAME.to_vec(),
        )];
        let (outcome, published, _hub) = run(7, &subtree, FakeNet::new(Ok(())), &[]);
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
        let subtree = vec![ChildScopeRef::new(
            DESCENDANT_SCOPE,
            DESCENDANT_NAME.to_vec(),
        )];
        let (outcome, published, _hub) = run(7, &subtree, FakeNet::new(Ok(())), &[]);
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
        let (outcome, published, hub) =
            run_for(SeededEntropy::new(7), &[], net.clone(), &[], &owner_enc());

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
    fn an_attested_parent_row_the_owner_cannot_re_derive_fails_closed_release_active() {
        // The owner's two authorities over one row disagree: its signature binds
        // a `recipientEncPk` its own encryption subkey cannot re-derive the tag
        // from. Wrapping the parent's override seed and pointer read key under
        // that disagreement is what the refusal prevents. Runtime `Err`, never a
        // debug_assert. Active in release.
        let victim = X25519Secret::from_scalar([0x51; SECRET_LEN]);
        let attacker = X25519Secret::from_scalar([0x52; SECRET_LEN]);
        let mut row = parent_row(&victim.public());
        row.ledger_entry.recipient_enc_pk = attacker.public().to_bytes();
        row.ledger_entry.owner_sig =
            sign_recipient_binding(&owner_identity(), PARENT_NAME, &row.ledger_entry)
                .expect("the owner attests the row")
                .to_compact();

        let (outcome, published, _hub) = run(7, &[], FakeNet::new(Ok(())), &[row]);

        assert_eq!(
            outcome.expect_err("the parent re-seal refuses the row"),
            CreateGrantError::ParentMint(ResealError::TagNotBoundToRecipient)
        );
        assert!(
            published.iter().all(|r| r.scope_id != PARENT_SCOPE),
            "no parent record reaches the network"
        );
    }

    /// One honestly minted parent-scope row for `recipient`.
    fn parent_row(recipient: &X25519Public) -> GrantRow {
        mint_grant_row(
            &owner_identity(),
            &owner_enc(),
            recipient_identity().to_sec1(),
            recipient,
            &PARENT_SCOPE,
            PARENT_NAME,
            Permission::Read,
        )
        .expect("a contributory recipient key")
    }
}
