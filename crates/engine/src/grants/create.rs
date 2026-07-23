//! Owner-side read-grant creation (blueprint/engine.md "Grants and ledger:
//! Grant creation"; #635).
//!
//! Minting the owner-only sharing path for a **read** grant, as the exact
//! sequence the blueprint fixes:
//!
//! 1. **Converge** the subtree — run the [`sweep_pass`] over the granted
//!    folder's descendant scope roots. A grant over a subtree that cannot be
//!    proven epoch-converged is rejected **fail-closed** ([`CreateGrantError::
//!    SubtreeNotConverged`] / [`CreateGrantError::Converge`]); a new grantee must
//!    never be able to regress through an ancestor scope's history (CONTEXT.md
//!    "Epoch-converged"). This is the load-bearing correctness rule.
//! 2. **Mint the scope at read epoch 1** — a fresh **random** override seed (via
//!    the injected [`Entropy`] seam, never KDF-derived), assembled into the
//!    grantee scope root by [`reseal_scope_root`] with `prev = None` (the new
//!    grantee needs no history).
//! 3. **Parent index update** — move the folder's descendant scope roots into the
//!    new scope's direct-child-scope index and insert the new scope root into the
//!    parent's, under the dest-first / never-orphan discipline of
//!    [`child_index`](super::child_index).
//! 4. **Publish** — the grantee scope root first (register-first: it exists
//!    before anything references it), then the reparented parent.
//! 5. **Mailbox share pointer** — the sealed [`SharePointer`] posted to the
//!    recipient's mailbox (sender signature inside the seal), with a fresh
//!    HPKE ephemeral scalar drawn from entropy.
//!
//! # Simulation boundary
//!
//! This is a deterministic-simulation slice: entropy is the injected
//! [`Entropy`] seam and the read/floor/publish/mailbox effects are the faked
//! seams (`SweepResolver`, `FloorStore`, `ScopeRootPublisher`, `Mailbox`). No
//! clock or RNG is read. Production resolver/publisher wiring is deferred to
//! #745/#746, mirroring the rotation primitives (#744/#747/#749/#760).
//!
//! # Deferred (follow-on slices of #635)
//!
//! - **Write grants**: the write-scope cut via [`rotate_scope_write`](super::
//!   super::rotation::rotate_scope_write) plus the both-seeds grant blob. Read
//!   grant creation is the clean cut point; write grants layer the write-scope
//!   cut on top of this identical skeleton.
//! - **Invites**: ephemeral-key blobs, bearer write-link flagging, claim
//!   conversion.
//!
//! This module composes existing machinery only and holds no crypto of its own.

use cipherbox_core::error::CodecError;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildScopeRef, GrantLedgerEntry, GrantSetCommitment, GrantSetEntry, Permission, SignedSealed,
    sign_grant_set,
};
use cipherbox_core::suite::ecdsa::{
    EcdsaSigner, IDENTITY_PUBLIC_LEN, SIGNATURE_LEN as ECDSA_SIG_LEN,
};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use core::fmt;
use zeroize::Zeroizing;

use crate::entropy::{Entropy, EntropyError};
use crate::grants::SharePointer;
use crate::grants::child_index::{canonicalize, insert_child, remove_child};
use crate::hex::hex_lower;
use crate::mailbox::post_sealed;
use crate::rotation::{
    CommittedSet, ResealError, ResealSeeds, ResealedScopeRoot, ScopeRootIdentity,
    ScopeRootPublishError, ScopeRootPublisher, SweepError, SweepResolver, derive_write_name,
    reseal_scope_root, sweep_pass,
};
use crate::seams::{FloorStore, Mailbox, SeamError};

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
    /// The descendant scope roots inside the folder: converged before minting
    /// and reparented into the new scope's direct-child-scope index.
    ///
    /// Descent re-key of these descendants under the fresh grantee override seed
    /// is deferred (fail-safe under-share) pending blueprint confirmation —
    /// tracked in #770.
    pub subtree_child_index: &'a [ChildScopeRef],
}

/// The recipient of the read grant.
pub struct GrantRecipient<'a> {
    /// Compressed secp256k1 SEC1 identity key (for the ledger + share pointer).
    pub identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    /// X25519 encryption subkey public key: the grant-blob HPKE wrap target and
    /// the mailbox routing address.
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
    pub identity: ScopeRootIdentity<'a>,
    /// The parent's current read-plane seeds (`prev = None`).
    pub seeds: ResealSeeds<'a>,
    /// The parent's owner-signed grant-set commitment.
    pub commitment: &'a GrantSetCommitment,
    /// The parent's commitment signature.
    pub commitment_sig: &'a [u8; ECDSA_SIG_LEN],
    /// The parent's grant ledger (unchanged by this op).
    pub grant_ledger: &'a [GrantLedgerEntry],
    /// The parent's write-plane history link (unchanged by this op).
    pub write_history_link: &'a [u8],
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
/// Failures **through the grantee scope-root publish (step 5)** are truly
/// fail-closed — nothing is minted or shared: `Converge`,
/// `SubtreeNotConverged`, `UnusableRecipientKey`, `CommitmentEncode`,
/// `Entropy`, `Mint`, and `Publish` (register-first: a failed grantee publish
/// pushes nothing to the network). Failures **after** that publish are NOT
/// atomic: the grantee root — and, for `Mailbox`, the reparented parent — is
/// already committed to the network, so a stale orphan can outlive the error.
/// Orphan reconciliation belongs to the deferred resume machinery (#745/#746);
/// each post-publish variant documents what it leaves behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateGrantError {
    /// The pre-grant convergence sweep aborted (enumeration/floor/publish/reseal).
    Converge(SweepError),
    /// The subtree could not be proven epoch-converged: convergence work was
    /// dropped on a lost CAS race, so the grant is refused rather than minted
    /// over a possibly-lagging subtree.
    SubtreeNotConverged {
        /// Scope roots left unproven this pass.
        unconverged: Vec<[u8; 16]>,
    },
    /// The recipient encryption key is non-contributory (degenerate ECDH).
    UnusableRecipientKey,
    /// Encoding/signing the grant-set commitment failed (fail-closed codec).
    CommitmentEncode(CodecError),
    /// Entropy acquisition failed (seed mint or mailbox ephemeral).
    Entropy(EntropyError),
    /// Assembling the grantee scope root failed (pre-publish: fail-closed).
    Mint(ResealError),
    /// Publishing the grantee scope root failed (register-first: nothing was
    /// pushed, so this is still fail-closed).
    Publish(ScopeRootPublishError),
    /// Re-sealing the reparented parent scope root failed. Post-publish: the
    /// grantee root is already on the network with no parent reference — an
    /// orphan reconciled by #745/#746.
    ParentMint(ResealError),
    /// Publishing the reparented parent scope root failed. Post-publish: the
    /// grantee root is already on the network with no parent reference — an
    /// orphan reconciled by #745/#746.
    ParentPublish(ScopeRootPublishError),
    /// Posting the sealed share pointer to the recipient mailbox failed.
    /// Post-publish: both scope roots are published and the parent index is
    /// updated; only the share pointer is missing. Retry re-posts under the
    /// same idempotency key.
    Mailbox(SeamError),
}

impl CreateGrantError {
    /// A stable machine tag for assertions and host classification.
    pub fn check(&self) -> &'static str {
        match self {
            Self::Converge(_) => "converge-failed",
            Self::SubtreeNotConverged { .. } => "subtree-not-converged",
            Self::UnusableRecipientKey => "unusable-recipient-key",
            Self::CommitmentEncode(_) => "commitment-encode-failed",
            Self::Entropy(_) => "entropy-error",
            Self::Mint(_) => "mint-failed",
            Self::Publish(_) => "publish-failed",
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

/// Mint a read grant for one recipient over `grantee`'s folder.
///
/// Converge → mint (epoch 1) → reparent + parent index update → publish
/// (grantee first) → post the mailbox share pointer. Fail-closed **through the
/// grantee publish** (step 5): any earlier error mints and shares nothing. Past
/// that point the sequence is not atomic — see [`CreateGrantError`] for what
/// each post-publish variant leaves committed (orphan cleanup is deferred to
/// #745/#746). See the module docs for the full sequence and the deferred
/// write-grant / invite slices.
#[allow(clippy::too_many_arguments)]
pub async fn create_read_grant<E, F, R, P, M>(
    entropy: &mut E,
    floors: &F,
    sweep_resolver: &R,
    publisher: &P,
    mailbox: &M,
    grantee: &GranteeScopePlan<'_>,
    recipient: &GrantRecipient<'_>,
    owner: &OwnerGrantKeys<'_>,
    parent: &ParentScopePlan<'_>,
) -> Result<CreateGrantOutcome, CreateGrantError>
where
    E: Entropy,
    F: FloorStore,
    R: SweepResolver,
    P: ScopeRootPublisher,
    M: Mailbox,
{
    // 1) Convergence gate — run the sweep over the granted subtree. A dropped
    // lost race means convergence is unproven: refuse rather than share a
    // possibly-lagging subtree (the grant-creation convergence requirement).
    let swept = sweep_pass(
        entropy,
        floors,
        sweep_resolver,
        publisher,
        grantee.scope_id,
        grantee.subtree_child_index,
    )
    .await
    .map_err(CreateGrantError::Converge)?;
    if !swept.dropped_lost_race.is_empty() {
        return Err(CreateGrantError::SubtreeNotConverged {
            unconverged: swept.dropped_lost_race,
        });
    }

    // 2) Derive the scope root's ipnsName from the folder's write material — the
    // sole gated identity edge (blueprint/engine.md: the name binds the record
    // via the Ed25519 key it encodes). The tag and commitment below bind this
    // name, and the recipient re-derives the same name from the record it
    // resolves; deriving here (never trusting a passed name) keeps that binding
    // fail-closed at the mint.
    let ipns_name = derive_write_name(grantee.write_scope_seed, &grantee.scope_id);
    let name_bytes = ipns_name.as_str().as_bytes();

    // 3) Build the committed set for the recipient. The blinded tag and the
    // recipient's writer pseudonym both key off the same owner-recipient ECDH
    // (contributory-checked by the x25519 seam); a read entry's pseudonym never
    // authorizes a structure but is derived honestly so a later write upgrade
    // stays consistent.
    let shared = owner
        .enc_secret
        .diffie_hellman(recipient.enc_pub)
        .ok_or(CreateGrantError::UnusableRecipientKey)?;
    let tag = kdf::blinded_tag(shared.as_bytes(), name_bytes);
    let recipient_pseudonym_pk = kdf::pseudonym_sign(shared.as_bytes(), &grantee.scope_id)
        .verifying_key()
        .to_bytes();
    let commitment = GrantSetCommitment {
        ipns_name: name_bytes.to_vec(),
        owner_pseudonym_pk: owner.pseudonym_signer.verifying_key().to_bytes(),
        entries: vec![GrantSetEntry::new(
            tag,
            Permission::Read,
            recipient_pseudonym_pk,
        )],
        unknown: Vec::new(),
    };
    let commitment_sig = sign_grant_set(owner.identity_signer, &commitment)
        .map_err(CreateGrantError::CommitmentEncode)?
        .to_compact();
    let ledger = vec![GrantLedgerEntry::new(
        recipient.identity_pk,
        recipient.enc_pub.to_bytes(),
        Permission::Read,
        tag,
    )];

    // 4) Mint at read epoch 1 with a FRESH RANDOM override seed (never
    // KDF-derived). The new scope adopts the folder's descendant scope roots as
    // its direct-child-scope index (they now live inside the granted scope).
    let mut override_seed = Zeroizing::new([0u8; SECRET_LEN]);
    entropy
        .fill(override_seed.as_mut_slice())
        .map_err(CreateGrantError::Entropy)?;

    let grantee_section = {
        let identity = ScopeRootIdentity {
            v: grantee.v,
            scope_id: grantee.scope_id,
            ipns_name: name_bytes,
            owner_enc_pub: grantee.owner_enc_pub,
            parent_node_seed: Some(grantee.parent_node_seed),
            pseudonym_signer: owner.pseudonym_signer,
        };
        let seeds = ResealSeeds {
            override_seed: &override_seed,
            read_epoch: 1,
            prev: None,
            write_scope_seed: grantee.write_scope_seed,
            write_epoch: grantee.write_epoch,
            pointer_read_key: grantee.pointer_read_key,
        };
        // Mint-canonical: the adopted index carries the same canonicalization the
        // sweep's self-heal enforces (sweep.rs), so the grantee root never lands a
        // shape the convergence pass would later have to repair.
        let grantee_child_index = canonicalize(grantee.subtree_child_index);
        let committed = CommittedSet {
            commitment: &commitment,
            commitment_sig: &commitment_sig,
            grant_ledger: &ledger,
            write_history_link: &[],
            direct_child_scope_index: &grantee_child_index,
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

    // 5) Publish the grantee scope root FIRST: it exists before the parent
    // references it (register-first / never-orphan), and its index carries the
    // reparented descendants before they are removed from the parent
    // (dest-first).
    publisher
        .publish_scope_root(&grantee_record)
        .await
        .map_err(CreateGrantError::Publish)?;

    // 6) Parent index update: remove the reparented descendants, insert the new
    // scope root, then re-seal + publish the parent (metadata-only, same epoch).
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
            write_history_link: parent.write_history_link,
            direct_child_scope_index: &parent_index,
        };
        reseal_scope_root(
            entropy,
            &parent.identity,
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

    // 7) Post the sealed share pointer to the recipient's mailbox with a fresh
    // HPKE ephemeral scalar (never a clock or a constant).
    let pointer = SharePointer {
        scope_root_name: name_bytes.to_vec(),
        sharer_identity_pk: owner.identity_signer.verifying_key().to_sec1(),
        display_name: recipient.display_name.clone(),
        permission: Permission::Read,
    };
    let mut ephemeral = Zeroizing::new([0u8; 32]);
    entropy
        .fill(&mut *ephemeral)
        .map_err(CreateGrantError::Entropy)?;
    let recipient_address = recipient.enc_pub.to_bytes();
    // Key off the per-recipient blinded tag, not the shared scope_id: the API
    // stores sha256(senderPublicKey : idempotencyKey) per recipient, so a
    // scope-derived key would be identical across two recipients of the same
    // folder and let the server correlate the sharing edge. The tag is
    // deterministic (retry-safe), 32-byte high-entropy, and differs per recipient.
    let idempotency_key = format!("grant:{}", hex_lower(&tag));
    post_sealed(
        mailbox,
        recipient.enc_pub,
        &recipient_address,
        &ephemeral,
        grantee.v,
        owner.identity_signer,
        &pointer.encode(),
        &idempotency_key,
    )
    .await
    .map_err(CreateGrantError::Mailbox)?;

    Ok(CreateGrantOutcome {
        scope_id: grantee.scope_id,
        tag,
        parent_child_index: parent_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::PublishedGrantBlob;
    use crate::grants::ledger::self_locate;
    use crate::grants::recipient_blinded_tag;
    use crate::mailbox::poll_verified;
    use crate::rotation::{PrevEpochSeed, ResolveFailure, SweepTarget};
    use crate::testkit::fakes::{InMemoryFloorStore, InMemoryMailboxHub};
    use crate::testkit::{SeededEntropy, block_on};
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use cipherbox_core::suite::x25519::X25519Secret;
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

    /// A combined `SweepResolver` + `ScopeRootPublisher` fake: it records every
    /// committed publish and can force a lost race to model an unconvergeable
    /// subtree. `resolve` builds a valid, lagging descendant `SweepTarget` for
    /// `DESCENDANT_SCOPE` (whose re-seal succeeds, so the convergence outcome is
    /// decided by the publish result).
    ///
    /// `fail_after` fails the Nth+ `publish_scope_root` call so a test can let
    /// the grantee publish succeed and then fail the parent publish — the
    /// post-publish partial-commit path a single `publish_result` flag cannot
    /// express.
    #[derive(Clone)]
    struct FakeNet {
        published: Rc<RefCell<Vec<ResealedScopeRoot>>>,
        publish_result: Result<(), ScopeRootPublishError>,
        publish_calls: Rc<RefCell<usize>>,
        fail_after: Option<(usize, ScopeRootPublishError)>,
    }

    impl FakeNet {
        fn new(publish_result: Result<(), ScopeRootPublishError>) -> Self {
            Self {
                published: Rc::new(RefCell::new(Vec::new())),
                publish_result,
                publish_calls: Rc::new(RefCell::new(0)),
                fail_after: None,
            }
        }

        /// Succeed every publish up to (excluding) the `n`th, then fail with
        /// `err` — models a grantee publish that lands and a later parent
        /// publish that loses the race.
        fn new_fail_after(n: usize, err: ScopeRootPublishError) -> Self {
            Self {
                fail_after: Some((n, err)),
                ..Self::new(Ok(()))
            }
        }
    }

    impl SweepResolver for FakeNet {
        async fn resolve(&self, scope: &ChildScopeRef) -> Result<SweepTarget, ResolveFailure> {
            if scope.scope_id != DESCENDANT_SCOPE {
                return Err(ResolveFailure::Rejected);
            }
            let pseudonym = owner_pseudonym();
            let commitment = GrantSetCommitment {
                ipns_name: DESCENDANT_NAME.to_vec(),
                owner_pseudonym_pk: pseudonym.verifying_key().to_bytes(),
                entries: Vec::new(),
                unknown: Vec::new(),
            };
            let commitment_sig = sign_grant_set(&owner_identity(), &commitment)
                .unwrap()
                .to_compact();
            Ok(SweepTarget {
                v: V,
                scope_id: DESCENDANT_SCOPE,
                ipns_name: DESCENDANT_NAME.to_vec(),
                current_read_epoch: 1,
                owner_enc_pub: owner_enc().public(),
                parent_node_seed: None,
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
            })
        }
    }

    impl ScopeRootPublisher for FakeNet {
        async fn publish_scope_root(
            &self,
            record: &ResealedScopeRoot,
        ) -> Result<(), ScopeRootPublishError> {
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

    /// A `Mailbox` fake that records the idempotency key of every post, so a test
    /// can assert two recipients of the same folder get distinct keys.
    #[derive(Clone, Default)]
    struct RecordingMailbox {
        idempotency_keys: Rc<RefCell<Vec<String>>>,
    }

    impl Mailbox for RecordingMailbox {
        async fn post(
            &self,
            _recipient_public_key: &[u8],
            _sealed_payload: &[u8],
            idempotency_key: &str,
        ) -> crate::seams::SeamResult<()> {
            self.idempotency_keys
                .borrow_mut()
                .push(idempotency_key.to_owned());
            Ok(())
        }
        async fn poll(&self) -> crate::seams::SeamResult<Vec<crate::seams::MailboxItem>> {
            Ok(Vec::new())
        }
        async fn ack(&self, _item_id: &str) -> crate::seams::SeamResult<()> {
            Ok(())
        }
    }

    /// The mailbox idempotency key the primitive posts for `recipient_enc` over
    /// the fixed grantee folder (empty subtree, converged, publishing OK).
    fn idempotency_key_for(recipient_enc: &X25519Secret) -> String {
        let floors = InMemoryFloorStore::default();
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
            unknown: Vec::new(),
        };
        let parent_commitment_sig = sign_grant_set(&owner_identity, &parent_commitment)
            .unwrap()
            .to_compact();

        let mut entropy = SeededEntropy::new(7);
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
            identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
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
                parent_node_seed: None,
                pseudonym_signer: &owner_pseudonym,
            },
            seeds: ResealSeeds {
                override_seed: &parent_override_seed,
                read_epoch: 3,
                prev: None::<PrevEpochSeed<'_>>,
                write_scope_seed: &parent_write_scope_seed,
                write_epoch: 2,
                pointer_read_key: &parent_pointer_read_key,
            },
            commitment: &parent_commitment,
            commitment_sig: &parent_commitment_sig,
            grant_ledger: &[],
            write_history_link: &[],
            current_child_index: &[],
            carried_history_links: &[],
        };
        block_on(create_read_grant(
            &mut entropy,
            &floors,
            &net,
            &net,
            &recorder,
            &grantee,
            &recipient,
            &owner,
            &parent,
        ))
        .expect("grant creation succeeds");

        let keys = recorder.idempotency_keys.borrow();
        assert_eq!(keys.len(), 1, "exactly one mailbox post per grant");
        keys[0].clone()
    }

    /// A read grant with the given subtree, run against fresh fakes on seed
    /// `entropy_seed`. Returns the outcome, the published records, and the mailbox
    /// hub so the caller can assert on delivery.
    #[allow(clippy::type_complexity)]
    fn run(
        entropy_seed: u64,
        subtree: &[ChildScopeRef],
        floor: Option<([u8; 16], u64)>,
        net: FakeNet,
    ) -> (
        Result<CreateGrantOutcome, CreateGrantError>,
        Vec<ResealedScopeRoot>,
        InMemoryMailboxHub,
    ) {
        let floors = InMemoryFloorStore::default();
        if let Some((scope, epoch)) = floor {
            block_on(floors.raise_epoch_floor(&scope, epoch)).unwrap();
        }
        let hub = InMemoryMailboxHub::default();
        let mailbox = hub.mailbox_for(&recipient_enc().public().to_bytes());

        let owner_enc = owner_enc();
        let owner_enc_pub = owner_enc.public();
        let owner_identity = owner_identity();
        let owner_pseudonym = owner_pseudonym();
        let recipient_enc = recipient_enc();
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
            unknown: Vec::new(),
        };
        let parent_commitment_sig = sign_grant_set(&owner_identity, &parent_commitment)
            .unwrap()
            .to_compact();

        let outcome = {
            let mut entropy = SeededEntropy::new(entropy_seed);
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
                identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
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
                    parent_node_seed: None,
                    pseudonym_signer: &owner_pseudonym,
                },
                seeds: ResealSeeds {
                    override_seed: &parent_override_seed,
                    read_epoch: 3,
                    prev: None::<PrevEpochSeed<'_>>,
                    write_scope_seed: &parent_write_scope_seed,
                    write_epoch: 2,
                    pointer_read_key: &parent_pointer_read_key,
                },
                commitment: &parent_commitment,
                commitment_sig: &parent_commitment_sig,
                grant_ledger: &[],
                write_history_link: &[],
                current_child_index: &[],
                carried_history_links: &[],
            };
            block_on(create_read_grant(
                &mut entropy,
                &floors,
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

    #[test]
    fn converged_subtree_mints_publishes_and_posts_the_share_pointer() {
        let (outcome, published, hub) = run(7, &[], None, FakeNet::new(Ok(())));
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
        let recip_box = hub.mailbox_for(&recipient_enc().public().to_bytes());
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
    fn non_converged_subtree_is_rejected_fail_closed() {
        // A descendant that lags (floor 2 > epoch 1) whose convergence publish
        // loses the CAS race: the subtree cannot be proven converged, so the
        // grant is refused — nothing minted, nothing posted.
        let subtree = vec![ChildScopeRef::new(
            DESCENDANT_SCOPE,
            DESCENDANT_NAME.to_vec(),
        )];
        let (outcome, published, hub) = run(
            7,
            &subtree,
            Some((DESCENDANT_SCOPE, 2)),
            FakeNet::new(Err(ScopeRootPublishError::LostRace)),
        );

        match outcome {
            Err(CreateGrantError::SubtreeNotConverged { unconverged }) => {
                assert_eq!(unconverged, vec![DESCENDANT_SCOPE]);
            }
            other => panic!("expected SubtreeNotConverged, got {other:?}"),
        }
        // Fail-closed: no grantee/parent record published, no share pointer.
        assert!(published.is_empty(), "nothing published on a refused grant");
        let recip_box = hub.mailbox_for(&recipient_enc().public().to_bytes());
        let items = block_on(poll_verified(&recip_box, &recipient_enc(), V)).unwrap();
        assert!(items.is_empty(), "no share pointer on a refused grant");
    }

    #[test]
    fn unresolvable_subtree_is_rejected_fail_closed() {
        // A subtree scope root that will not resolve is a fail-closed convergence
        // abort, never a silent partial share.
        let subtree = vec![ChildScopeRef::new([0x99; 16], b"unresolvable".to_vec())];
        let (outcome, published, _hub) = run(7, &subtree, None, FakeNet::new(Ok(())));
        assert_eq!(outcome.unwrap_err().check(), "converge-failed");
        assert!(published.is_empty());
    }

    #[test]
    fn parent_publish_failure_leaves_the_grantee_root_committed_and_no_share() {
        // Post-publish partial commit: the grantee root publishes (call 0), then
        // the parent publish (call 1) loses the CAS race. The primitive is NOT
        // atomic past step 5 — the grantee root is already on the network (orphan
        // cleanup belongs to #745/#746) and NO share pointer is posted. This pins
        // the doc comment's post-publish caveat to behavior.
        let (outcome, published, hub) = run(
            7,
            &[],
            None,
            FakeNet::new_fail_after(1, ScopeRootPublishError::LostRace),
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
        let recip_box = hub.mailbox_for(&recipient_enc().public().to_bytes());
        let items = block_on(poll_verified(&recip_box, &recipient_enc(), V)).unwrap();
        assert!(items.is_empty(), "no share pointer when publish aborts");
    }

    #[test]
    fn creation_is_deterministic_under_a_fixed_entropy_seed() {
        let (a_outcome, a_pub, _) = run(42, &[], None, FakeNet::new(Ok(())));
        let (b_outcome, b_pub, _) = run(42, &[], None, FakeNet::new(Ok(())));
        assert_eq!(a_outcome.unwrap(), b_outcome.unwrap());
        assert_eq!(a_pub, b_pub, "same seed → byte-identical published records");
    }

    #[test]
    fn idempotency_key_differs_per_recipient_for_the_same_folder() {
        // The mailbox idempotency key binds the per-recipient blinded tag, not the
        // shared scope_id: two recipients of the SAME folder must post distinct
        // keys so the server can't correlate the sharing edge via
        // sha256(sender : key).
        let key_a = idempotency_key_for(&recipient_enc());
        let key_b = idempotency_key_for(&X25519Secret::from_scalar([0x77; 32]));
        assert!(key_a.starts_with("grant:"));
        assert_ne!(
            key_a, key_b,
            "same folder, different recipients → different idempotency keys"
        );
    }
}
