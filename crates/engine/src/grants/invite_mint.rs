//! The owner-side mint of an invite link, end to end (blueprint/engine.md
//! "Grants and ledger: Invites", ADR 0023 D2, ADR 0024 D4).
//!
//! An invite link mints the same fresh scope
//! ([`mint_grantee_scope`](super::mint_grantee_scope)) a personal grant does,
//! with a link entry at `read` as its committed set. The bearer starts at that
//! scope's first epoch and walks back through no history the owner cut before
//! the link existed.
//!
//! The fragment is sealed and its bound checked before anything publishes, and
//! the owner device records nothing: the link lives in the record alone.

use core::fmt;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::SIGNATURE_LEN as ECDSA_SIG_LEN;
use cipherbox_core::suite::secret::SecretBytes;
use zeroize::Zeroizing;

use crate::entropy::Entropy;
#[cfg(test)]
use crate::grants::ScopeRootPromoter;
use crate::grants::create::{MintNet, ScopePointerVoucher};
#[cfg(test)]
use crate::rotation::{CascadeResealResolver, ScopeRootPublisher, SweepPublisher, SweepResolver};

use super::create::{
    CreateGrantError, GrantSubtree, GrantedReadScope, GranteeScopePlan, OwnerGrantKeys,
    ParentScopePlan, converge_grant_subtree, promote_grantee_scope, resume_grantee_scope,
};
use super::invite::{EphemeralInvitee, InviteError, InviteFragment, LinkTerms, mint_invite_grant};

/// What one mint needs beyond the owner's own key material: the scope the link
/// grants, the parent that gains it, the link's terms, and what its fragment
/// names.
pub struct InviteMintPlan<'a> {
    /// The fresh scope the link's row is committed at — the invited folder's
    /// own, minted at read epoch 1. It carries no write cut.
    pub grantee: &'a GranteeScopePlan<'a>,
    /// The scope root the invited folder currently lives in, which gains the
    /// new scope in its direct-child-scope index.
    pub parent: &'a ParentScopePlan<'a>,
    /// The terms the link entry carries.
    pub terms: LinkTerms,
    /// The fresh scope's pointer name, which the fragment carries.
    pub scope_pointer_name: &'a IpnsName,
    /// The owner's name, as the owner gave it. May be empty.
    pub owner_name: &'a str,
    /// The folder's name.
    pub folder_name: &'a str,
}

/// A minted link as the host must present it: one opaque URL fragment
/// ([`InviteFragment`]) and nothing else. Assembling the URL around it is the
/// host's, since the engine knows no origin.
#[derive(Clone, PartialEq, Eq)]
pub struct MintedInviteLink {
    /// The link's URL fragment — **the whole bearer capability**. A host puts it
    /// in a URL and nowhere durable.
    pub fragment: Zeroizing<String>,
}

impl fmt::Debug for MintedInviteLink {
    /// Hand-written like [`Command`](crate::facade::Command)'s: the fragment is
    /// the capability, and a derived `{:?}` would put it in host logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MintedInviteLink(..)")
    }
}

/// A fail-closed mint failure. On every variant the host is handed no
/// capability.
#[derive(Debug)]
pub enum InviteMintError {
    /// Minting the link's row or sealing its fragment failed. Nothing
    /// published.
    Mint(InviteError),
    /// Minting the scope the row is committed at failed. Fail-closed through
    /// the scope-root publish; past it [`CreateGrantError`] states what stayed
    /// behind.
    Create(CreateGrantError),
}

impl fmt::Display for InviteMintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InviteMintError::Mint(e) => write!(f, "{e}"),
            InviteMintError::Create(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InviteMintError {}

/// Mint one invite link over the invited folder: seal its fragment, converge
/// the subtree, and mint and publish the fresh scope its link entry is the
/// whole committed set of.
///
/// The fragment is the only copy of the invite secret, so once the scope root
/// that commits the link has landed the fragment is returned whatever the
/// handover after it does. The handover's result rides alongside: the minted
/// scope's read material, or the post-publish failure. A later mint over the
/// same folder finishes that handover against the promoted root and refuses a
/// second link.
///
/// Owner-only by construction, exactly as [`create_grant`](super::create_grant)
/// is: the scope this publishes is signed under the owner's writer pseudonym and
/// its commitment under the owner identity, so no other session can author it.
pub async fn mint_invite_link<E, N, V>(
    entropy: &mut E,
    net: &N,
    voucher: &V,
    owner: &OwnerGrantKeys<'_>,
    plan: &InviteMintPlan<'_>,
) -> Result<(MintedInviteLink, Result<GrantedReadScope, CreateGrantError>), InviteMintError>
where
    E: Entropy,
    N: MintNet,
    V: ScopePointerVoucher,
{
    let invitee = EphemeralInvitee::mint(entropy).map_err(InviteMintError::Mint)?;
    let row = mint_invite_grant(
        owner.identity_signer,
        owner.enc_secret,
        plan.grantee.pointer_read_key,
        &invitee,
        &plan.grantee.scope_id,
        plan.grantee.write_scope_seed,
        &plan.terms,
    )
    .map_err(InviteMintError::Mint)?;

    let mut fragment = InviteFragment {
        invite_secret: invitee.secret().clone(),
        owner_contact_code: ContactCode::create(owner.identity_signer, owner.enc_secret.public())
            .encode(),
        scope_id: plan.grantee.scope_id,
        scope_pointer_name: plan.scope_pointer_name.clone(),
        pointer_read_key: SecretBytes::new(*plan.grantee.pointer_read_key),
        owner_name: plan.owner_name.to_owned(),
        folder_name: plan.folder_name.to_owned(),
        names_sig: [0u8; ECDSA_SIG_LEN],
    };
    fragment.sign_names(owner.identity_signer);
    // Ahead of every publish, so a fragment past its bound leaves no live link
    // that nobody holds.
    let fragment = fragment.encode().map_err(InviteMintError::Mint)?;

    let subtree = converge_grant_subtree(net, net, plan.grantee, plan.parent)
        .await
        .map_err(InviteMintError::Create)?;
    let converged = match subtree {
        GrantSubtree::Converged(converged) => converged,
        // The link a stalled mint committed is still the one its fragment
        // holder reads, so the handover finishes and no second link mints.
        GrantSubtree::Promoted(promoted) => {
            let Some(link) = promoted.sole_link_entry() else {
                return Err(InviteMintError::Create(
                    CreateGrantError::ResumeNotThisGrant,
                ));
            };
            resume_grantee_scope(entropy, net, promoted, &link, owner)
                .await
                .map_err(InviteMintError::Create)?;
            return Err(InviteMintError::Create(
                CreateGrantError::TargetAlreadyNamesAScope,
            ));
        }
    };
    let handover = promote_grantee_scope(entropy, net, voucher, converged, &row, owner)
        .await
        .map_err(InviteMintError::Create)?;

    Ok((
        MintedInviteLink { fragment },
        handover.map(|outcome| outcome.read_scope),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::create::{
        GrantResumeResolver, InteriorRecord, InteriorResealer, MovingChild, PromotedScopeRoot,
    };
    use super::*;
    use crate::rotation::published_override_seed;
    use crate::seams::UnixMillis;

    /// Always accepts.
    struct AcceptingVoucher;

    impl ScopePointerVoucher for AcceptingVoucher {
        async fn vouch_scope(
            &self,
            _repoint: &cipherbox_core::payload::RepointObject,
        ) -> Result<(), crate::rotation::RotationPublishError> {
            Ok(())
        }
    }

    use core::cell::RefCell;
    use std::rc::Rc;

    use cipherbox_core::kdf;
    use cipherbox_core::seal::{
        ChildRef, ChildScopeRef, GrantSetCommitment, NodeKind, PreservedFields, ReadBody,
        SignedSealed, sign_grant_set,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use cipherbox_core::suite::secret::SECRET_LEN;
    use cipherbox_core::suite::x25519::X25519Secret;
    use zeroize::Zeroizing;

    use cipherbox_core::seal::{
        AadContext, GrantSetEntryKind, Permission, STRUCT_TAG_GRANT_BLOB, open_grant_blob,
    };
    use cipherbox_core::suite::secret::ct_eq;

    use crate::grants::invite::MAX_INVITE_NAME_BYTES;
    use crate::grants::{recipient_blinded_tag, self_locate_signed};
    use crate::rotation::{
        CascadeTarget, LaggingNode, NodeRef, ResealSeeds, ResealedScopeRoot, ResolveFailure,
        RotationPublishError, ScopeRootIdentity, SweepResolveFailure, SweptChild, SweptNode,
        SweptScope, WriteHistory, derive_write_name,
    };
    use crate::testkit::{SeededEntropy, block_on};

    const V: u64 = 1;
    const OWNER_SECRET: [u8; SECRET_LEN] = [0x21; SECRET_LEN];
    const PARENT_SCOPE: [u8; 16] = [0x0e; 16];
    const PARENT_NAME: &[u8] = b"parent-scope-root-name";
    const PARENT_EPOCH: u64 = 3;
    const FOLDER: [u8; 16] = [0x5c; 16];
    const WRITE_SCOPE_SEED: [u8; SECRET_LEN] = [0x44; SECRET_LEN];
    const OVERRIDE_SEED: [u8; SECRET_LEN] = [0x55; SECRET_LEN];
    const POINTER_READ_KEY: [u8; SECRET_LEN] = [0x66; SECRET_LEN];
    const PARENT_NODE_SEED: [u8; SECRET_LEN] = [0x88; SECRET_LEN];
    const DEADLINE: UnixMillis = UnixMillis(1_700_000_000_000);
    const SEED: u64 = 9;

    fn owner_identity() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&OWNER_SECRET).expect("valid scalar")
    }

    fn owner_pseudonym() -> Ed25519Signer {
        Ed25519Signer::from_seed([0x22; 32])
    }

    /// The parent scope's retained read-plane history — every epoch its owner
    /// has cut. A carried link passes through a re-seal verbatim, so opaque
    /// bytes are enough to prove the invite's own scope inherits none of it.
    fn parent_history() -> Vec<SignedSealed> {
        vec![SignedSealed {
            sealed: vec![0xa5; 48],
            signature: [0xb6; 64],
            unknown: PreservedFields::new(),
        }]
    }

    /// The invite scope's ipnsName, derived exactly as the mint does.
    fn folder_name() -> Vec<u8> {
        derive_write_name(&WRITE_SCOPE_SEED, &FOLDER)
            .as_str()
            .as_bytes()
            .to_vec()
    }

    /// The net arm the mint composes over: the convergence sweep's seams and
    /// the scope-root publisher, over a parent scope holding the invited folder
    /// and nothing else.
    #[derive(Clone)]
    struct FakeNet {
        published: Rc<RefCell<Vec<ResealedScopeRoot>>>,
        refuse_publish: bool,
        /// Refuse every publish once this many have landed.
        publishes_before_refusal: Option<usize>,
        /// One interior node inside the invited folder, when a test wants the
        /// mint to own a subtree rather than a bare folder.
        interior: Option<[u8; 16]>,
        /// The interior nodes the mint re-sealed into the invite's scope.
        resealed: Rc<RefCell<Vec<[u8; 16]>>>,
        /// Answer `promoted_root` from what a previous mint published, as a
        /// folder an earlier attempt already promoted answers.
        promotion_stands: bool,
    }

    impl FakeNet {
        fn new() -> Self {
            Self {
                published: Rc::new(RefCell::new(Vec::new())),
                refuse_publish: false,
                publishes_before_refusal: None,
                interior: None,
                resealed: Rc::new(RefCell::new(Vec::new())),
                promotion_stands: false,
            }
        }

        fn with_interior(mut self, node_id: [u8; 16]) -> Self {
            self.interior = Some(node_id);
            self
        }
    }

    impl SweepResolver for FakeNet {
        async fn resolve_scope(
            &self,
            scope: &ChildScopeRef,
        ) -> Result<SweptScope, SweepResolveFailure> {
            if scope.scope_id != PARENT_SCOPE {
                return Err(SweepResolveFailure::Rejected);
            }
            Ok(SweptScope {
                current_read_epoch: PARENT_EPOCH,
                children: vec![NodeRef {
                    node_id: FOLDER,
                    ipns_name: folder_name(),
                }],
                direct_child_scope_index: Vec::new(),
            })
        }

        async fn consult_pointer(
            &self,
            _scope_id: &[u8; 16],
        ) -> Result<Option<Vec<u8>>, SweepResolveFailure> {
            Ok(None)
        }

        async fn resolve_child(
            &self,
            _scope: &ChildScopeRef,
            child: &NodeRef,
        ) -> Result<SweptChild, SweepResolveFailure> {
            let children = if child.node_id == FOLDER {
                self.interior
                    .iter()
                    .map(|node_id| ChildRef {
                        id: *node_id,
                        name: "n".into(),
                        ipns_name: b"invited-folder-interior".to_vec(),
                        kind: NodeKind::Folder,
                        link_counter: 1,
                        unknown: PreservedFields::new(),
                    })
                    .collect()
            } else if self.interior == Some(child.node_id) {
                Vec::new()
            } else {
                return Err(SweepResolveFailure::Unavailable);
            };
            Ok(SweptChild::Interior(SweptNode {
                current_read_epoch: PARENT_EPOCH,
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
            _node: &LaggingNode<'_>,
        ) -> Result<(), RotationPublishError> {
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
        async fn resolve(&self, _scope: &ChildScopeRef) -> Result<CascadeTarget, ResolveFailure> {
            Err(ResolveFailure::Rejected)
        }
    }

    impl InteriorResealer for FakeNet {
        async fn reseal_interior_node(
            &self,
            _source: &ChildScopeRef,
            _root: &ResealedScopeRoot,
            node: &InteriorRecord<'_>,
        ) -> Result<(), RotationPublishError> {
            self.resealed.borrow_mut().push(node.node_id);
            Ok(())
        }
    }

    impl GrantResumeResolver for FakeNet {
        async fn promoted_root(
            &self,
            _parent: &ChildScopeRef,
            node: &NodeRef,
        ) -> Result<Option<PromotedScopeRoot>, ResolveFailure> {
            if !self.promotion_stands {
                return Ok(None);
            }
            let record = self
                .published
                .borrow()
                .iter()
                .find(|published| published.scope_id == node.node_id)
                .cloned()
                .ok_or(ResolveFailure::Rejected)?;
            let override_seed = published_override_seed(
                &kdf::enc_subkey(&OWNER_SECRET),
                V,
                node.node_id,
                1,
                &record.section,
            )
            .ok_or(ResolveFailure::Rejected)?;
            Ok(Some(PromotedScopeRoot {
                record,
                override_seed,
                children: Vec::new(),
                boundaries: Vec::new(),
            }))
        }

        async fn holds_a_scope_root_floor(&self, _node: &NodeRef) -> Result<bool, ResolveFailure> {
            Ok(false)
        }

        async fn resolve_moving_child(
            &self,
            source: &ChildScopeRef,
            _root: &ResealedScopeRoot,
            node: &NodeRef,
        ) -> Result<MovingChild, SweepResolveFailure> {
            match self.resolve_child(source, node).await? {
                SweptChild::Interior(swept) => Ok(MovingChild::Pending(swept)),
                SweptChild::ScopeRoot(_) => Ok(MovingChild::ScopeRoot),
            }
        }
    }

    /// The promotion seam over the same recording publisher; an invite mints a
    /// scope at a folder exactly as a direct grant does.
    impl ScopeRootPromoter for FakeNet {
        async fn promote_scope_root(
            &self,
            _parent: &ChildScopeRef,
            _node: &NodeRef,
            record: &ResealedScopeRoot,
        ) -> Result<Vec<NodeRef>, RotationPublishError> {
            self.publish_scope_root(record).await?;
            Ok(self
                .interior
                .iter()
                .map(|node_id| NodeRef {
                    node_id: *node_id,
                    ipns_name: b"invited-folder-interior".to_vec(),
                })
                .collect())
        }
    }

    impl ScopeRootPublisher for FakeNet {
        async fn publish_scope_root(
            &self,
            record: &ResealedScopeRoot,
        ) -> Result<(), RotationPublishError> {
            if self.refuse_publish
                || self
                    .publishes_before_refusal
                    .is_some_and(|landed| self.published.borrow().len() >= landed)
            {
                return Err(RotationPublishError::NotPublished);
            }
            self.published.borrow_mut().push(record.clone());
            Ok(())
        }
    }

    /// One owner and one folder to invite to.
    struct Fixture {
        owner: EcdsaSigner,
        enc: X25519Secret,
        pseudonym: Ed25519Signer,
        parent_commitment: GrantSetCommitment,
        parent_commitment_sig: [u8; 64],
        entropy: RefCell<SeededEntropy>,
        net: FakeNet,
    }

    impl Fixture {
        fn new() -> Self {
            let owner = owner_identity();
            let enc = kdf::enc_subkey(&OWNER_SECRET);
            let parent_commitment = GrantSetCommitment {
                ipns_name: PARENT_NAME.to_vec(),
                owner_pseudonym_pk: owner_pseudonym().verifying_key().to_bytes(),
                cut_epoch: 0,
                entries: Vec::new(),
                unknown: PreservedFields::default(),
            };
            let parent_commitment_sig = sign_grant_set(&owner, &parent_commitment)
                .expect("signs")
                .to_compact();
            Self {
                owner,
                enc,
                pseudonym: owner_pseudonym(),
                parent_commitment,
                parent_commitment_sig,
                entropy: RefCell::new(SeededEntropy::new(SEED)),
                net: FakeNet::new(),
            }
        }

        /// The same fixture over a folder that holds one interior node.
        fn with_interior(mut self, node_id: [u8; 16]) -> Self {
            self.net = self.net.with_interior(node_id);
            self
        }

        fn keys(&self) -> OwnerGrantKeys<'_> {
            OwnerGrantKeys {
                enc_secret: &self.enc,
                identity_signer: &self.owner,
                pseudonym_signer: &self.pseudonym,
            }
        }

        fn mint(&self, terms: LinkTerms) -> Result<MintedInviteLink, InviteMintError> {
            self.mint_named(terms, "Photos")
        }

        /// A mint whose handover landed whole.
        fn mint_named(
            &self,
            terms: LinkTerms,
            folder_name: &str,
        ) -> Result<MintedInviteLink, InviteMintError> {
            self.mint_with_handover(terms, folder_name)
                .map(|(minted, handover)| {
                    handover.expect("the handover lands");
                    minted
                })
        }

        fn mint_with_handover(
            &self,
            terms: LinkTerms,
            folder_name: &str,
        ) -> Result<(MintedInviteLink, Result<GrantedReadScope, CreateGrantError>), InviteMintError>
        {
            let owner_enc_pub = self.enc.public();
            let grantee = GranteeScopePlan {
                v: V,
                scope_id: FOLDER,
                parent_node_seed: &PARENT_NODE_SEED,
                owner_enc_pub: &owner_enc_pub,
                write_scope_seed: &WRITE_SCOPE_SEED,
                write_cut: None,
                pointer_read_key: &POINTER_READ_KEY,
                subtree_child_index: &[],
            };
            let history = parent_history();
            let override_seed = Zeroizing::new(OVERRIDE_SEED);
            let pointer_read_key = Zeroizing::new(POINTER_READ_KEY);
            let write_scope_seed = Zeroizing::new(WRITE_SCOPE_SEED);
            let parent = ParentScopePlan {
                identity: ScopeRootIdentity {
                    v: V,
                    scope_id: PARENT_SCOPE,
                    ipns_name: PARENT_NAME,
                    owner_enc_pub: &owner_enc_pub,
                    owner_enc_secret: Some(&self.enc),
                    ascent: None,
                    owes_ascent_link: false,
                    pseudonym_signer: &self.pseudonym,
                },
                seeds: ResealSeeds {
                    override_seed: &override_seed,
                    read_epoch: PARENT_EPOCH,
                    prev: None,
                    write_scope_seed: &write_scope_seed,
                    write_epoch: 1,
                    write_history: WriteHistory::Genesis,
                    pointer_read_key: &pointer_read_key,
                },
                commitment: &self.parent_commitment,
                commitment_sig: &self.parent_commitment_sig,
                grant_ledger: &[],
                current_child_index: &[],
                carried_history_links: &history,
            };
            block_on(mint_invite_link(
                &mut crate::entropy::SharedEntropy(&self.entropy),
                &self.net,
                &AcceptingVoucher,
                &self.keys(),
                &InviteMintPlan {
                    grantee: &grantee,
                    parent: &parent,
                    terms,
                    scope_pointer_name: &pointer_name(),
                    owner_name: "Ada",
                    folder_name,
                },
            ))
        }

        /// The invite scope root the mint published.
        fn scope_root(&self) -> ResealedScopeRoot {
            self.net
                .published
                .borrow()
                .iter()
                .find(|r| r.scope_id == FOLDER)
                .cloned()
                .expect("the invite scope was published")
        }
    }

    fn pointer_name() -> IpnsName {
        IpnsName::from_public_key(&Ed25519Signer::from_seed([0x77; 32]).verifying_key())
    }

    fn read_link() -> LinkTerms {
        LinkTerms {
            deadline: DEADLINE,
            conversion_permission: Permission::Read,
            admission_cap: 3,
        }
    }

    fn write_link() -> LinkTerms {
        LinkTerms {
            deadline: DEADLINE,
            conversion_permission: Permission::Write,
            admission_cap: 3,
        }
    }

    /// The fragment names the minted scope's pointer and read key, and the
    /// scope commits the link entry the fragment's secret derives.
    #[test]
    fn a_minted_link_commits_a_link_entry_the_fragment_answers_to() {
        let f = Fixture::new();

        let link = f.mint(write_link()).expect("the mint lands");

        let fragment = InviteFragment::decode(&link.fragment).expect("the mint's own fragment");
        assert_eq!(fragment.scope_id, FOLDER);
        assert_eq!(fragment.scope_pointer_name, pointer_name());
        assert!(ct_eq(
            fragment.pointer_read_key.as_bytes(),
            &POINTER_READ_KEY
        ));
        assert_eq!(
            fragment.verified_names(&f.owner.verifying_key()),
            Some(("Ada", "Photos")),
        );
        let invitee =
            EphemeralInvitee::from_secret(fragment.invite_secret.as_bytes()).expect("valid secret");
        let tag = recipient_blinded_tag(invitee.enc_secret(), &f.enc.public(), &folder_name())
            .expect("contributory");

        let scope_root = f.scope_root();
        let [entry] = &scope_root.section.commitment.entries[..] else {
            panic!("the link is the scope's whole grant set");
        };
        assert_eq!(entry.tag, tag);
        assert_eq!(entry.kind, GrantSetEntryKind::Link);
        assert_eq!(entry.permission, Permission::Read);
        assert_eq!(entry.conversion_permission, Some(Permission::Write));
        assert_eq!(entry.deadline.map(|d| d.get()), Some(DEADLINE.0));
        assert_eq!(entry.admission_cap, Some(3));
    }

    /// ADR 0024 D4: the blob of a write link carries read material only, so a
    /// holder of the fragment gets no write seed.
    #[test]
    fn the_blob_of_a_write_link_opens_no_write_seed() {
        let f = Fixture::new();

        let link = f.mint(write_link()).expect("the mint lands");

        let fragment = InviteFragment::decode(&link.fragment).expect("the mint's own fragment");
        let invitee =
            EphemeralInvitee::from_secret(fragment.invite_secret.as_bytes()).expect("valid secret");
        let tag = recipient_blinded_tag(invitee.enc_secret(), &f.enc.public(), &folder_name())
            .expect("contributory");
        let scope_root = f.scope_root();
        let blob = self_locate_signed(&scope_root.section.grant_blobs, &tag)
            .expect("a blob at the link tag");
        let grant = open_grant_blob(
            invitee.enc_secret(),
            &blob.enc,
            &AadContext {
                v: V,
                id: FOLDER,
                scope: FOLDER,
                epoch: scope_root.read_epoch,
                struct_tag: STRUCT_TAG_GRANT_BLOB,
            },
            &blob.ciphertext,
        )
        .expect("the holder opens the link blob");
        assert!(grant.write_scope_seed().is_none());
    }

    /// The mint runs no write-scope cut and no name wave: the scope root stays
    /// at the name the parent's write seed derives, at its first write epoch.
    #[test]
    fn a_write_link_mint_runs_no_rotation() {
        let f = Fixture::new();

        f.mint(write_link()).expect("the mint lands");

        let published = f.net.published.borrow();
        let invite_roots: Vec<_> = published.iter().filter(|r| r.scope_id == FOLDER).collect();
        let [scope_root] = invite_roots[..] else {
            panic!("the mint publishes the scope root once");
        };
        assert_eq!(scope_root.ipns_name.as_slice(), folder_name().as_slice());
        assert_eq!(scope_root.read_epoch, 1);
        assert_eq!(scope_root.write_epoch, 1);
        assert!(scope_root.section.history_links.is_empty());
    }

    /// A bearer reads the folder's interior under the scope the link mints, so
    /// the mint owes that interior the same re-seal a personal grant owes it.
    #[test]
    fn a_minted_link_re_seals_the_invited_folders_interior() {
        const INTERIOR_NODE: [u8; 16] = [0xa1; 16];
        let f = Fixture::new().with_interior(INTERIOR_NODE);

        f.mint(read_link()).expect("the mint lands");

        assert_eq!(*f.net.resealed.borrow(), vec![INTERIOR_NODE]);
    }

    /// A fragment its own claim path would refuse is refused before anything
    /// publishes, so no live link stands that nobody holds.
    #[test]
    fn a_mint_whose_fragment_is_refused_publishes_nothing() {
        let f = Fixture::new();

        let refused = f
            .mint_named(read_link(), &"n".repeat(MAX_INVITE_NAME_BYTES + 1))
            .expect_err("a name past the bound is refused");

        assert!(matches!(
            refused,
            InviteMintError::Mint(InviteError::NameTooLong)
        ));
        assert!(f.net.published.borrow().is_empty());
    }

    /// A zero deadline is refused at the mint, before any publish.
    #[test]
    fn a_zero_deadline_is_refused_before_any_publish() {
        let f = Fixture::new();

        let refused = f
            .mint(LinkTerms {
                deadline: UnixMillis(0),
                ..read_link()
            })
            .expect_err("a zero deadline is refused");

        assert!(matches!(
            refused,
            InviteMintError::Mint(InviteError::InvalidExpiry)
        ));
        assert!(f.net.published.borrow().is_empty());
    }

    /// A publish that fails hands out no capability.
    #[test]
    fn a_publish_that_fails_hands_out_no_capability() {
        let mut f = Fixture::new();
        f.net.refuse_publish = true;

        let refused = f
            .mint(read_link())
            .expect_err("an unpublished link is refused");

        assert!(matches!(refused, InviteMintError::Create(_)));
    }

    /// A folder a link already promoted takes no second link. The mint
    /// finishes the promoted root's handover and refuses.
    #[test]
    fn a_link_over_an_already_promoted_folder_is_refused() {
        let mut f = Fixture::new();
        f.mint(read_link()).expect("the first mint lands");
        f.net.promotion_stands = true;

        let refused = f
            .mint(read_link())
            .expect_err("a promoted folder takes no second mint");

        assert!(matches!(
            refused,
            InviteMintError::Create(CreateGrantError::TargetAlreadyNamesAScope)
        ));
        let links = f
            .net
            .published
            .borrow()
            .iter()
            .filter(|r| r.scope_id == FOLDER)
            .flat_map(|r| r.section.commitment.entries.clone())
            .map(|entry| entry.tag)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(links.len(), 1, "no second link is committed");
    }

    /// The fragment is the only copy of the invite secret, so a handover that
    /// fails after the scope root landed still returns it, and the link it
    /// names is the one committed. A later mint finishes the handover.
    #[test]
    fn a_parent_publish_failure_after_the_root_still_returns_the_fragment() {
        let mut f = Fixture::new();
        f.net.publishes_before_refusal = Some(1);

        let (link, handover) = f
            .mint_with_handover(read_link(), "Photos")
            .expect("the root that commits the link landed");

        assert!(matches!(handover, Err(CreateGrantError::ParentPublish(_))));
        let fragment = InviteFragment::decode(&link.fragment).expect("the mint's own fragment");
        let invitee =
            EphemeralInvitee::from_secret(fragment.invite_secret.as_bytes()).expect("valid secret");
        let tag = recipient_blinded_tag(invitee.enc_secret(), &f.enc.public(), &folder_name())
            .expect("contributory");
        let scope_root = f.scope_root();
        assert!(
            self_locate_signed(&scope_root.section.grant_blobs, &tag).is_some(),
            "the holder self-locates its blob at the committed root"
        );

        f.net.publishes_before_refusal = None;
        f.net.promotion_stands = true;
        assert!(matches!(
            f.mint(read_link()),
            Err(InviteMintError::Create(
                CreateGrantError::TargetAlreadyNamesAScope
            ))
        ));
        assert!(
            f.net
                .published
                .borrow()
                .iter()
                .any(|r| r.scope_id == PARENT_SCOPE),
            "the retry publishes the parent the first mint owed"
        );
    }
}
