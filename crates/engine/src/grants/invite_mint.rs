//! The owner-side mint of an invite link, end to end (blueprint/engine.md
//! "Grants and ledger: Invites").
//!
//! An invite link is a read grant whose recipient is a throwaway keypair rather
//! than a contact, so it mints the same fresh scope
//! ([`mint_grantee_scope`](super::mint_grantee_scope)) a personal grant does:
//! the bearer starts at that scope's first epoch and walks back through no
//! history the owner cut before the link existed.
//!
//! Recording before publishing is the ack-after-durable rule the accept flow
//! already follows ([`ConvertedClaim::record`](super::ConvertedClaim::record)):
//! a committed entry no record names is authority no
//! [`locate_invite_link`](super::locate_invite_link) call can name
//! (`invite_store.rs` header), while a record whose row never published is
//! inert — conversion refuses it as uncommitted.

use core::fmt;

use cipherbox_core::seal::Permission;
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::secret::SecretBytes;

use crate::entropy::Entropy;
use crate::grants::ScopeRootPromoter;
use crate::rotation::{CascadeResealResolver, ScopeRootPublisher, SweepPublisher, SweepResolver};
use crate::seams::UnixMillis;

use super::create::{
    CreateGrantError, GranteeScopePlan, OwnerGrantKeys, ParentScopePlan, converge_grant_subtree,
    mint_grantee_scope,
};
use super::invite::{EphemeralInvitee, InviteError, mint_invite_grant};
use super::invite_store::{InviteStore, InviteStoreError};

/// What one mint needs beyond the owner's own key material: the scope the link
/// grants, the parent that gains it, and the link's terms.
pub struct InviteMintPlan<'a> {
    /// The fresh scope the link's row is committed at — the invited folder's
    /// own, minted at read epoch 1.
    pub grantee: &'a GranteeScopePlan<'a>,
    /// The scope root the invited folder currently lives in, which gains the
    /// new scope in its direct-child-scope index.
    pub parent: &'a ParentScopePlan<'a>,
    /// The link's deadline, or `None` for a link that never expires. The
    /// recorded copy is the authority for it
    /// ([`RecordedInvite::expires_at`](super::RecordedInvite::expires_at)).
    pub expires_at: Option<UnixMillis>,
}

/// A minted link as the host must present it: the bearer capability, the owner
/// bundle a claimant seals its claim to, and what the link hands out.
///
/// The URL fragment carries the invite secret and the owner's contact bundle
/// (blueprint/engine.md "Invites"); assembling the URL is the host's, since the
/// engine knows no origin.
#[derive(Clone, PartialEq, Eq)]
pub struct MintedInviteLink {
    /// The invite secret the fragment carries — **the whole capability**.
    pub invite_secret: SecretBytes,
    /// The owner's contact code, which a claimant seals its claim to.
    pub owner_contact_code: Vec<u8>,
    /// The scope root's opaque `ipnsName`, which a claim names.
    pub scope_root_name: Vec<u8>,
}

impl fmt::Debug for MintedInviteLink {
    /// Hand-written like [`Command`](crate::facade::Command)'s: the secret is
    /// the capability, and a derived `{:?}` would put it in host logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MintedInviteLink(..)")
    }
}

/// A fail-closed mint failure. On every variant the host is handed no
/// capability.
#[derive(Debug)]
pub enum InviteMintError {
    /// Minting the link's row failed.
    Mint(InviteError),
    /// The link could not be recorded durably. The row is unpublished, so the
    /// link exists nowhere.
    Store(InviteStoreError),
    /// Minting the scope the row is committed at failed. Fail-closed through
    /// the scope-root publish; past it the record is live and
    /// [`CreateGrantError`] states what stayed behind.
    Create(CreateGrantError),
}

impl fmt::Display for InviteMintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InviteMintError::Mint(e) => write!(f, "{e}"),
            InviteMintError::Store(e) => write!(f, "{e}"),
            InviteMintError::Create(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InviteMintError {}

/// Mint one invite link over the invited folder: converge the subtree, record
/// the link, mint and publish the fresh scope its row is the whole committed set
/// of, and hand back the bearer capability.
///
/// Owner-only by construction and read-only, exactly as
/// [`create_read_grant`](super::create_read_grant) is: the scope this publishes
/// is signed under the owner's writer pseudonym and its commitment under the
/// owner identity, and it inherits the parent's write plane — so a write row's
/// blob would hand the bearer the seed every name in that scope derives from.
pub async fn mint_invite_link<E, R, P, S>(
    entropy: &mut E,
    resolver: &R,
    publisher: &P,
    store: &S,
    owner: &OwnerGrantKeys<'_>,
    plan: &InviteMintPlan<'_>,
) -> Result<MintedInviteLink, InviteMintError>
where
    E: Entropy,
    R: SweepResolver + CascadeResealResolver,
    P: ScopeRootPublisher + SweepPublisher + ScopeRootPromoter,
    S: InviteStore,
{
    let invitee = EphemeralInvitee::mint(entropy).map_err(InviteMintError::Mint)?;
    let minted = mint_invite_grant(
        owner.identity_signer,
        owner.enc_secret,
        &invitee,
        &plan.grantee.scope_id,
        plan.grantee.write_scope_seed,
        Permission::Read,
        plan.expires_at,
    )
    .map_err(InviteMintError::Mint)?;

    // Ahead of the record, so a subtree the gate cannot prove converged costs no
    // durable slot.
    let converged = converge_grant_subtree(resolver, publisher, plan.grantee, plan.parent)
        .await
        .map_err(InviteMintError::Create)?;

    // Whole-set replacement, so the load is what keeps the links already
    // recorded.
    let mut records = store.load().await.map_err(InviteMintError::Store)?;
    records.links.push(minted.link);
    store
        .persist(&records)
        .await
        .map_err(InviteMintError::Store)?;

    mint_grantee_scope(entropy, resolver, publisher, &converged, &minted.row, owner)
        .await
        .map_err(InviteMintError::Create)?;

    Ok(MintedInviteLink {
        invite_secret: invitee.secret().clone(),
        owner_contact_code: ContactCode::create(owner.identity_signer, owner.enc_secret.public())
            .encode(),
        scope_root_name: plan.grantee.ipns_name().as_str().as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use std::rc::Rc;

    use cipherbox_core::kdf;
    use cipherbox_core::seal::{
        ChildScopeRef, GrantSetCommitment, PreservedFields, ReadBody, SignedSealed, sign_grant_set,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use cipherbox_core::suite::secret::SECRET_LEN;
    use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
    use zeroize::Zeroizing;

    use crate::grants::{RecordedInvite, StagingInviteStore, recipient_blinded_tag};
    use crate::rotation::{
        CascadeTarget, LaggingNode, NodeRef, ResealSeeds, ResealedScopeRoot, ResolveFailure,
        RotationPublishError, ScopeRootIdentity, SweepResolveFailure, SweptChild, SweptNode,
        SweptScope, WriteHistory, derive_write_name,
    };
    use crate::testkit::fakes::InMemoryStagingStore;
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
    }

    impl FakeNet {
        fn new() -> Self {
            Self {
                published: Rc::new(RefCell::new(Vec::new())),
                refuse_publish: false,
            }
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
            if child.node_id != FOLDER {
                return Err(SweepResolveFailure::Unavailable);
            }
            Ok(SweptChild::Interior(SweptNode {
                current_read_epoch: PARENT_EPOCH,
                sequence: 1,
                read_body: ReadBody::Folder {
                    created_at: 0,
                    modified_at: 0,
                    children: Vec::new(),
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

    /// The promotion seam over the same recording publisher; an invite mints a
    /// scope at a folder exactly as a direct grant does.
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
            if self.refuse_publish {
                return Err(RotationPublishError::NotPublished);
            }
            self.published.borrow_mut().push(record.clone());
            Ok(())
        }
    }

    /// One owner, one folder to invite to, and the durable backing its records
    /// land in.
    struct Fixture {
        owner: EcdsaSigner,
        enc: X25519Secret,
        pseudonym: Ed25519Signer,
        parent_commitment: GrantSetCommitment,
        parent_commitment_sig: [u8; 64],
        staging: InMemoryStagingStore,
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
                staging: InMemoryStagingStore::default(),
                entropy: RefCell::new(SeededEntropy::new(SEED)),
                net: FakeNet::new(),
            }
        }

        fn store(&self) -> StagingInviteStore<'_, InMemoryStagingStore, SeededEntropy> {
            StagingInviteStore::new(&self.staging, &self.enc, &self.entropy)
        }

        fn keys(&self) -> OwnerGrantKeys<'_> {
            OwnerGrantKeys {
                enc_secret: &self.enc,
                identity_signer: &self.owner,
                pseudonym_signer: &self.pseudonym,
            }
        }

        fn mint(
            &self,
            expires_at: Option<UnixMillis>,
        ) -> Result<MintedInviteLink, InviteMintError> {
            let owner_enc_pub = self.enc.public();
            let grantee = GranteeScopePlan {
                v: V,
                scope_id: FOLDER,
                parent_node_seed: &PARENT_NODE_SEED,
                owner_enc_pub: &owner_enc_pub,
                write_scope_seed: &WRITE_SCOPE_SEED,
                write_epoch: 1,
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
                    write_history: WriteHistory::Carried(&[]),
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
                &self.net,
                &self.store(),
                &self.keys(),
                &InviteMintPlan {
                    grantee: &grantee,
                    parent: &parent,
                    expires_at,
                },
            ))
        }

        /// The links a later session recovers: a fresh handle over the same
        /// durable backing.
        fn recovered(&self) -> Vec<RecordedInvite> {
            block_on(self.store().load())
                .expect("the records load")
                .links
        }
    }

    /// The whole point of the slice: what the mint hands out is claimable
    /// against a scope minted for this link alone, and what a later session
    /// recovers is the record the mint made.
    #[test]
    fn a_minted_link_is_recorded_and_its_scope_published() {
        let f = Fixture::new();

        let link = f.mint(None).expect("the mint lands");

        let [record] = f.recovered()[..] else {
            panic!("one link was minted");
        };
        let invitee =
            EphemeralInvitee::from_secret(link.invite_secret.as_bytes()).expect("valid secret");
        assert_eq!(
            record.ephemeral_identity_pk,
            invitee.identity_pk().to_sec1(),
            "the recovered record answers to the fragment holder's identity",
        );
        assert_eq!(record.expires_at, None);
        assert_eq!(link.scope_root_name, folder_name());

        let published = f.net.published.borrow();
        let scope_root = published
            .iter()
            .find(|r| r.scope_id == FOLDER)
            .expect("the invite scope was published");
        // The tag conversion re-derives from the record it recovered
        // (`convert_invite_claim`), so this is the entry a claim reads its
        // permission out of.
        assert_eq!(
            recipient_blinded_tag(
                &f.enc,
                &X25519Public::from_bytes(record.ephemeral_enc_pk).expect("valid key"),
                &folder_name(),
            ),
            Some(record.tag),
        );
        let [entry] = &scope_root.section.commitment.entries[..] else {
            panic!("the link is the scope's whole grant set");
        };
        assert_eq!(entry.tag, record.tag);
        assert_eq!(entry.permission, Permission::Read);
    }

    /// The narrowing this slice exists for: a bearer's history walk has nowhere
    /// to go, because the scope it is granted starts at the link.
    #[test]
    fn a_minted_links_scope_starts_at_epoch_one_with_no_history() {
        let f = Fixture::new();

        f.mint(None).expect("the mint lands");

        let published = f.net.published.borrow();
        let scope_root = published
            .iter()
            .find(|r| r.scope_id == FOLDER)
            .expect("the invite scope was published");
        assert_eq!(scope_root.read_epoch, 1);
        assert!(
            scope_root.section.history_links.is_empty(),
            "no epoch predates the link, so the parent's retained history stays behind",
        );
    }

    /// The recorded deadline is the authority for expiry, so the mint's term
    /// must survive into the record a later session converts against.
    #[test]
    fn a_links_deadline_is_recorded_as_minted() {
        let f = Fixture::new();

        f.mint(Some(DEADLINE)).expect("the mint lands");

        let [record] = f.recovered()[..] else {
            panic!("one link was minted");
        };
        assert_eq!(record.expires_at, Some(DEADLINE));
    }

    /// An unclaimable link is worse than a refused mint: a record that did not
    /// land refuses the whole mint, and nothing is published.
    #[test]
    fn a_mint_whose_record_does_not_land_publishes_nothing() {
        let f = Fixture::new();
        f.staging
            .interrupt_staged_write_after(f.store().staging_key(), 0);

        let refused = f.mint(None).expect_err("an unrecorded link is refused");

        assert!(matches!(
            refused,
            InviteMintError::Store(InviteStoreError::Seam(_))
        ));
        assert!(
            f.net.published.borrow().is_empty(),
            "nothing is published for a link the owner cannot revoke",
        );
    }

    /// The record lands first, so a publish that fails leaves an inert record
    /// rather than a committed entry no `locate_invite_link` call can name.
    #[test]
    fn a_publish_that_fails_hands_out_no_capability() {
        let mut f = Fixture::new();
        f.net.refuse_publish = true;

        let refused = f.mint(None).expect_err("an unpublished link is refused");

        assert!(matches!(refused, InviteMintError::Create(_)));
        assert_eq!(
            f.recovered().len(),
            1,
            "the record landed before the publish",
        );
    }
}
