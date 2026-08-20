//! The owner-side mint of an invite link, end to end (blueprint/engine.md
//! "Grants and ledger: Invites").
//!
//! [`mint_invite_grant`] produces a row and a record; neither is worth anything
//! alone, so this composes the three effects one mint needs and hands the
//! bearer capability back only after all three land.
//!
//! Recording before publishing is the ack-after-durable rule the accept flow
//! already follows ([`ConvertedClaim::record`](super::ConvertedClaim::record)):
//! a committed entry no record names is authority no
//! [`revoke_invite_link`](super::revoke_invite_link) call can cut
//! (`invite_store.rs` header), while a record whose row never published is
//! inert — conversion refuses it as uncommitted.

use core::cell::RefCell;
use core::fmt;

use cipherbox_core::error::CodecError;
use cipherbox_core::seal::{
    ChildScopeRef, GrantLedgerEntry, GrantSetCommitment, Permission, sign_grant_set,
};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::EcdsaSignature;
use cipherbox_core::suite::secret::SecretBytes;

use crate::entropy::Entropy;
use crate::rotation::{
    CascadeTarget, CommittedSet, ResealError, ResealSeeds, ResealedScopeRoot, ScopeRootIdentity,
    ScopeRootPublishError, ScopeRootPublisher, WriteHistory, reseal_scope_root,
};
use crate::seams::UnixMillis;

use super::invite::{
    CommittedScope, EphemeralInvitee, InviteError, LinkCapability, check_publishable,
    mint_invite_grant,
};
use super::invite_store::{InviteStore, InviteStoreError};
use super::{GrantRow, OwnerAuthority};

/// What one mint needs beyond the owner's own key material: which scope root
/// the link grants on, that root's current gate-passing state, and the terms.
pub struct InviteMintPlan<'a> {
    /// The scope root's id and opaque `ipnsName`.
    pub scope: &'a ChildScopeRef,
    /// The scope root's current re-seal material, from a gated read that has
    /// parked its republish base with the publisher. A root carrying an ascent
    /// link is refused ([`InviteMintError::NotAVaultRoot`]).
    pub current: &'a CascadeTarget,
    /// Read or write. A write link hands out an extractable subtree signing key
    /// ([`LinkCapability::BearerWrite`]).
    pub permission: Permission,
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
    /// What the link hands out.
    pub capability: LinkCapability,
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
    /// The scope root carries an ascent link, so it is a descendant of some
    /// parent scope. Re-sealing it here would drop that link and orphan the
    /// subtree from every later gated descent, so it is refused rather than
    /// re-sealed without one.
    NotAVaultRoot,
    /// The committed set names a different scope root than the one this mint
    /// publishes at. The blinded tag binds the publish name and the commitment
    /// binds its own, so re-signing across the two would commit rows no reader
    /// re-derives at the name it resolved. The gate pins them equal on a read;
    /// this refuses release-active rather than trusting that it ran
    /// (AGENTS.md rule 8).
    ScopeNameMismatch,
    /// Minting the row failed, or the extended set is not one this build may
    /// publish (grant-set ceiling, duplicate tag, divergent ledger).
    Mint(InviteError),
    /// The extended commitment could not be encoded for signing.
    Sign(CodecError),
    /// Re-sealing the scope root failed — nothing was recorded or published.
    Reseal(ResealError),
    /// The link could not be recorded durably. The row is unpublished, so the
    /// link exists nowhere.
    Store(InviteStoreError),
    /// The re-sealed scope root did not land. The link is recorded and inert —
    /// no commitment carries its tag, so no claim converts against it — and
    /// stays recorded: dropping it would risk forgetting a row that landed
    /// after all, which is the one state nothing can revoke. Until a prune
    /// path exists, each failed publish spends a slot toward
    /// [`MAX_INVITE_RECORDS`](super::MAX_INVITE_RECORDS).
    Publish(ScopeRootPublishError),
}

impl fmt::Display for InviteMintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InviteMintError::NotAVaultRoot => f.write_str("the scope root carries an ascent link"),
            InviteMintError::ScopeNameMismatch => {
                f.write_str("the committed set names another scope root")
            }
            InviteMintError::Sign(e) => write!(f, "commitment encode failed: {}", e.check()),
            InviteMintError::Reseal(e) => write!(f, "scope root re-seal failed: {e}"),
            InviteMintError::Mint(e) => write!(f, "{e}"),
            InviteMintError::Store(e) => write!(f, "{e}"),
            InviteMintError::Publish(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InviteMintError {}

/// Mint one invite link on the vault root: record it, publish its row, and hand
/// back the bearer capability.
///
/// Owner-only, on the same rule as
/// [`revoke_invite_link`](super::revoke_invite_link): the caller's identity key
/// must have signed the set it is about to extend, or nothing is minted.
pub async fn mint_invite_link<P: ScopeRootPublisher, S: InviteStore, E: Entropy>(
    owner: &OwnerAuthority<'_>,
    publisher: &P,
    store: &S,
    entropy: &RefCell<E>,
    plan: &InviteMintPlan<'_>,
) -> Result<MintedInviteLink, InviteMintError> {
    let current = plan.current;
    if current.carried_ascent_link {
        return Err(InviteMintError::NotAVaultRoot);
    }
    if current.commitment.ipns_name != plan.scope.ipns_name {
        return Err(InviteMintError::ScopeNameMismatch);
    }
    let commitment_sig = EcdsaSignature::from_compact(&current.commitment_sig)
        .ok_or(InviteMintError::Mint(InviteError::NotOwner))?;
    owner
        .authorise(&CommittedScope {
            scope_id: &plan.scope.scope_id,
            commitment: &current.commitment,
            commitment_sig: &commitment_sig,
            ledger: &current.grant_ledger,
        })
        .map_err(InviteMintError::Mint)?;

    let invitee =
        EphemeralInvitee::mint(&mut *entropy.borrow_mut()).map_err(InviteMintError::Mint)?;
    let minted = mint_invite_grant(
        owner.enc_secret,
        &invitee,
        &plan.scope.scope_id,
        &current.write_scope_seed,
        plan.permission,
        plan.expires_at,
    )
    .map_err(InviteMintError::Mint)?;

    let (commitment, ledger) = extend(current, &minted.row)?;
    let extended_sig =
        sign_grant_set(owner.identity_signer, &commitment).map_err(InviteMintError::Sign)?;
    let section = reseal_scope_root(
        &mut *entropy.borrow_mut(),
        &ScopeRootIdentity {
            v: current.v,
            scope_id: plan.scope.scope_id,
            ipns_name: &plan.scope.ipns_name,
            owner_enc_pub: &current.owner_enc_pub,
            owner_enc_secret: Some(owner.enc_secret),
            parent_node_seed: None,
            owes_ascent_link: current.carried_ascent_link,
            pseudonym_signer: &current.pseudonym_signer,
        },
        &ResealSeeds {
            override_seed: &current.override_seed,
            read_epoch: current.current_read_epoch,
            prev: None,
            write_scope_seed: &current.write_scope_seed,
            write_epoch: current.write_epoch,
            write_history: WriteHistory::Carried(&current.write_history_link),
            pointer_read_key: &current.pointer_read_key,
        },
        &CommittedSet {
            commitment: &commitment,
            commitment_sig: &extended_sig.to_compact(),
            grant_ledger: &ledger,
            direct_child_scope_index: &current.direct_child_scope_index,
        },
        &current.carried_history_links,
    )
    .map_err(InviteMintError::Reseal)?;

    let resealed = ResealedScopeRoot {
        scope_id: plan.scope.scope_id,
        ipns_name: plan.scope.ipns_name.clone(),
        read_epoch: current.current_read_epoch,
        write_epoch: current.write_epoch,
        section,
    };

    // Whole-set replacement, so the load is what keeps the links already
    // recorded.
    let mut records = store.load().await.map_err(InviteMintError::Store)?;
    records.links.push(minted.link);
    store
        .persist(&records)
        .await
        .map_err(InviteMintError::Store)?;

    publisher
        .publish_scope_root(&resealed)
        .await
        .map_err(InviteMintError::Publish)?;

    Ok(MintedInviteLink {
        invite_secret: invitee.secret().clone(),
        owner_contact_code: ContactCode::create(owner.identity_signer, owner.enc_secret.public())
            .encode(),
        scope_root_name: resealed.ipns_name,
        capability: minted.capability,
    })
}

/// The committed set with the link's row in it, refused release-active on every
/// invariant a resolver hard-rejects (AGENTS.md rule 8).
fn extend(
    current: &CascadeTarget,
    row: &GrantRow,
) -> Result<(GrantSetCommitment, Vec<GrantLedgerEntry>), InviteMintError> {
    let mut commitment = current.commitment.clone();
    commitment.entries.push(row.commitment_entry.clone());
    let mut ledger = current.grant_ledger.clone();
    ledger.push(row.ledger_entry.clone());
    check_publishable(&commitment, &ledger).map_err(InviteMintError::Mint)?;
    Ok((commitment, ledger))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::kdf;
    use cipherbox_core::seal::PreservedFields;
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::secret::SECRET_LEN;
    use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
    use zeroize::Zeroizing;

    use crate::grants::{
        RecordedInvite, StagingInviteStore, mint_grant_row, recipient_blinded_tag,
    };
    use crate::rotation::derive_write_name;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{SeededEntropy, block_on};

    const OWNER_SECRET: [u8; SECRET_LEN] = [0x21; SECRET_LEN];
    const IMPOSTOR_SECRET: [u8; SECRET_LEN] = [0x31; SECRET_LEN];
    const GRANTEE_SECRET: [u8; SECRET_LEN] = [0x41; SECRET_LEN];
    const SCOPE_ID: [u8; 16] = [0x33; 16];
    const WRITE_SCOPE_SEED: [u8; SECRET_LEN] = [0x44; SECRET_LEN];
    const OVERRIDE_SEED: [u8; SECRET_LEN] = [0x55; SECRET_LEN];
    const POINTER_READ_KEY: [u8; SECRET_LEN] = [0x66; SECRET_LEN];
    const PSEUDONYM_SEED: [u8; SECRET_LEN] = [0x77; SECRET_LEN];
    const SEED: u64 = 9;

    fn signer(secret: &[u8; SECRET_LEN]) -> EcdsaSigner {
        EcdsaSigner::from_scalar(secret).expect("valid scalar")
    }

    #[derive(Default)]
    struct FakePublisher {
        published: RefCell<Vec<ResealedScopeRoot>>,
        refuse: bool,
    }

    impl ScopeRootPublisher for FakePublisher {
        async fn publish_scope_root(
            &self,
            record: &ResealedScopeRoot,
        ) -> Result<(), ScopeRootPublishError> {
            if self.refuse {
                return Err(ScopeRootPublishError::NotPublished);
            }
            self.published.borrow_mut().push(record.clone());
            Ok(())
        }
    }

    /// One owner, one vault root as a gated read would hand it over, and the
    /// durable backing its records land in.
    struct Fixture {
        owner: EcdsaSigner,
        enc: X25519Secret,
        scope: ChildScopeRef,
        current: CascadeTarget,
        staging: InMemoryStagingStore,
        entropy: RefCell<SeededEntropy>,
        publisher: FakePublisher,
    }

    impl Fixture {
        /// A vault root with one grantee already committed — the shape that
        /// makes the re-seal's per-row checks non-vacuous.
        fn with_a_grantee() -> (Self, [u8; 32]) {
            let mut f = Self::new();
            let grantee = signer(&GRANTEE_SECRET);
            let row = mint_grant_row(
                &f.enc,
                grantee.verifying_key().to_sec1(),
                &kdf::enc_subkey(&GRANTEE_SECRET).public(),
                &SCOPE_ID,
                &f.scope.ipns_name,
                Permission::Read,
            )
            .expect("usable grantee key");
            let tag = row.tag;
            f.current.commitment.entries.push(row.commitment_entry);
            f.current.grant_ledger.push(row.ledger_entry);
            f.current.commitment_sig = sign_grant_set(&f.owner, &f.current.commitment)
                .expect("signs")
                .to_compact();
            (f, tag)
        }

        fn new() -> Self {
            let owner = signer(&OWNER_SECRET);
            let scope = ChildScopeRef::new(
                SCOPE_ID,
                derive_write_name(&WRITE_SCOPE_SEED, &SCOPE_ID)
                    .as_str()
                    .as_bytes()
                    .to_vec(),
            );
            let pseudonym_signer = kdf::pseudonym_sign(&PSEUDONYM_SEED, &SCOPE_ID);
            let enc = kdf::enc_subkey(&OWNER_SECRET);
            let commitment = GrantSetCommitment {
                ipns_name: scope.ipns_name.clone(),
                owner_pseudonym_pk: pseudonym_signer.verifying_key().to_bytes(),
                entries: Vec::new(),
                unknown: PreservedFields::default(),
            };
            let commitment_sig = sign_grant_set(&owner, &commitment).expect("signs");
            Self {
                enc: enc.clone(),
                current: CascadeTarget {
                    v: 1,
                    current_read_epoch: 1,
                    owner_enc_pub: enc.public(),
                    pseudonym_signer,
                    override_seed: Zeroizing::new(OVERRIDE_SEED),
                    write_scope_seed: Zeroizing::new(WRITE_SCOPE_SEED),
                    pointer_read_key: Zeroizing::new(POINTER_READ_KEY),
                    write_epoch: 1,
                    commitment,
                    commitment_sig: commitment_sig.to_compact(),
                    grant_ledger: Vec::new(),
                    write_history_link: Vec::new(),
                    direct_child_scope_index: Vec::new(),
                    carried_history_links: Vec::new(),
                    carried_ascent_link: false,
                },
                owner,
                scope,
                staging: InMemoryStagingStore::default(),
                entropy: RefCell::new(SeededEntropy::new(SEED)),
                publisher: FakePublisher::default(),
            }
        }

        fn store(&self) -> StagingInviteStore<'_, InMemoryStagingStore, SeededEntropy> {
            StagingInviteStore::new(&self.staging, &self.enc, &self.entropy)
        }

        fn authority(&self) -> OwnerAuthority<'_> {
            OwnerAuthority {
                identity_signer: &self.owner,
                enc_secret: &self.enc,
            }
        }

        fn plan(&self, permission: Permission) -> InviteMintPlan<'_> {
            InviteMintPlan {
                scope: &self.scope,
                current: &self.current,
                permission,
                expires_at: None,
            }
        }

        fn mint(&self, permission: Permission) -> Result<MintedInviteLink, InviteMintError> {
            self.mint_as(&self.authority(), permission)
        }

        fn mint_as(
            &self,
            owner: &OwnerAuthority<'_>,
            permission: Permission,
        ) -> Result<MintedInviteLink, InviteMintError> {
            block_on(mint_invite_link(
                owner,
                &self.publisher,
                &self.store(),
                &self.entropy,
                &self.plan(permission),
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

    /// The whole point of the slice: what the mint hands out is claimable, and
    /// what a later session recovers is the record the mint made.
    #[test]
    fn a_minted_link_is_recorded_and_its_row_published() {
        let f = Fixture::new();

        let link = f.mint(Permission::Read).expect("the mint lands");

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
        assert_eq!(link.capability, LinkCapability::Read);
        assert_eq!(link.scope_root_name, f.scope.ipns_name);

        let published = f.publisher.published.borrow();
        let [root] = &published[..] else {
            panic!("one scope root was published");
        };
        // The tag conversion re-derives from the record it recovered
        // (`convert_invite_claim`), so this is the entry a claim reads its
        // permission out of.
        assert_eq!(
            recipient_blinded_tag(
                &f.enc,
                &X25519Public::from_bytes(record.ephemeral_enc_pk).expect("valid key"),
                &f.scope.ipns_name,
            ),
            Some(record.tag),
        );
        let [entry] = &root.section.commitment.entries[..] else {
            panic!("one grant was committed");
        };
        assert_eq!(entry.tag, record.tag);
        assert_eq!(entry.permission, Permission::Read);
        assert_eq!(
            root.read_epoch, f.current.current_read_epoch,
            "a mint cuts no read plane",
        );
    }

    /// A write link hands out an extractable subtree signing key, and a host
    /// must be able to say so.
    #[test]
    fn a_write_link_reports_itself_bearer_write() {
        let f = Fixture::new();

        let link = f.mint(Permission::Write).expect("the mint lands");

        assert!(link.capability.is_bearer_write());
    }

    /// An unclaimable link is worse than a refused mint: a record that did not
    /// land refuses the whole mint, and nothing is published.
    #[test]
    fn a_mint_whose_record_does_not_land_publishes_nothing() {
        let f = Fixture::new();
        f.staging
            .interrupt_staged_write_after(f.store().staging_key(), 0);

        let refused = f
            .mint(Permission::Read)
            .expect_err("an unrecorded link is refused");

        assert!(matches!(
            refused,
            InviteMintError::Store(InviteStoreError::Seam(_))
        ));
        assert!(
            f.publisher.published.borrow().is_empty(),
            "nothing is published for a link the owner cannot revoke",
        );
    }

    /// The record lands first, so a publish that fails leaves an inert record
    /// rather than a committed entry no `revoke_invite_link` call can name.
    #[test]
    fn a_publish_that_fails_hands_out_no_capability() {
        let mut f = Fixture::new();
        f.publisher.refuse = true;

        let refused = f
            .mint(Permission::Read)
            .expect_err("an unpublished link is refused");

        assert!(matches!(refused, InviteMintError::Publish(_)));
        assert_eq!(
            f.recovered().len(),
            1,
            "the record landed before the publish",
        );
    }

    /// Owner-only: a caller whose identity key did not sign the set it is
    /// extending mints nothing, on the same rule `revoke_invite_link` enforces.
    #[test]
    fn a_caller_who_did_not_sign_the_set_mints_nothing() {
        let f = Fixture::new();
        let impostor = signer(&IMPOSTOR_SECRET);

        let refused = f
            .mint_as(
                &OwnerAuthority {
                    identity_signer: &impostor,
                    enc_secret: &f.enc,
                },
                Permission::Read,
            )
            .expect_err("a non-owner is refused");

        assert!(matches!(
            refused,
            InviteMintError::Mint(InviteError::NotOwner)
        ));
        assert!(f.publisher.published.borrow().is_empty());
        assert!(f.recovered().is_empty(), "a refused mint records nothing");
    }

    /// Revocation completeness cuts both ways: a re-seal wraps a blob for
    /// exactly the committed set, so a mint must leave every grantee already in
    /// it able to open the scope.
    #[test]
    fn a_mint_leaves_an_existing_grantees_grant_intact() {
        let (f, grantee_tag) = Fixture::with_a_grantee();

        let link = f.mint(Permission::Read).expect("the mint lands");

        let published = f.publisher.published.borrow();
        let [root] = &published[..] else {
            panic!("one scope root was published");
        };
        let tags: Vec<[u8; 32]> = root
            .section
            .commitment
            .entries
            .iter()
            .map(|entry| entry.tag)
            .collect();
        assert!(tags.contains(&grantee_tag), "the grantee stays committed");
        assert_eq!(tags.len(), 2, "the mint adds exactly the link's own row");
        assert_eq!(
            root.section.grant_blobs.len(),
            2,
            "one blob per committed row, so the grantee can still open the scope",
        );
        assert_eq!(link.capability, LinkCapability::Read);
    }

    /// The publish name is derived, the commitment carries its own copy, and
    /// every blinded tag binds one of them — so a set naming another root is
    /// refused before anything is signed, recorded or published.
    #[test]
    fn a_committed_set_naming_another_scope_root_is_refused() {
        let (mut f, _) = Fixture::with_a_grantee();
        f.current.commitment.ipns_name = b"k51qzi5uqu5dianothername".to_vec();
        f.current.commitment_sig = sign_grant_set(&f.owner, &f.current.commitment)
            .expect("signs")
            .to_compact();

        let refused = f
            .mint(Permission::Read)
            .expect_err("a set naming another root is refused");

        assert!(matches!(refused, InviteMintError::ScopeNameMismatch));
        assert!(f.publisher.published.borrow().is_empty());
        assert!(f.recovered().is_empty(), "nothing is recorded either");
    }

    /// A root carrying an ascent link is a descendant of some parent scope, and
    /// this re-seal has no parent node seed to author one from — so it refuses
    /// rather than publish a root orphaned from every later gated descent.
    #[test]
    fn a_root_carrying_an_ascent_link_is_refused() {
        let mut f = Fixture::new();
        f.current.carried_ascent_link = true;

        let refused = f
            .mint(Permission::Read)
            .expect_err("a descendant scope root is refused");

        assert!(matches!(refused, InviteMintError::NotAVaultRoot));
        assert!(f.publisher.published.borrow().is_empty());
        assert!(f.recovered().is_empty());
    }
}
