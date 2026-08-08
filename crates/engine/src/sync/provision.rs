//! First-run vault provisioning — the one path that mints an account's genesis
//! scope root and the vault pointer naming it (blueprint/api.md: "bootstrap is
//! the derived vault pointer"; CONTEXT.md "Vault pointer", "Re-point object").
//!
//! [`cold_start`](super::boot::cold_start) reads the vault pointer and derives
//! everything below it; this is the other end of that chain, and like it a
//! **pure composition over injected seams** — no crypto of its own, no clock, no
//! RNG. Entropy arrives through [`Entropy`], the owner's per-scope derivations
//! through [`OwnerScopeKeys`], and both publish edges through
//! [`VaultProvisionPublisher`].
//!
//! # Straight-line, and what a failure leaves behind
//!
//! There is no resume and no cross-device coordination: every failure returns
//! `Err`, and the caller must not deposit seeds or spawn the tick loop on one.
//! What a failure can leave on the network, by stage:
//!
//! - before the root publish — nothing;
//! - at the root publish — a registered name and a pinned head block, and
//!   possibly a root record, none of which any pointer names. Unreachable, never
//!   authoritative; the next boot provisions afresh under new seeds and the
//!   orphan is a pin leak, not a fork;
//! - at the pointer publish — the same, plus a pointer that may be durable: an
//!   `Unconfirmed` verdict means an endpoint acked. The next boot resolves it and
//!   cold-starts normally, recovering the write scope seed from the root's
//!   owner-write blob.
//!
//! The floor cold-seed is the one durable local effect, and it runs **before**
//! any publish: an account whose floors already exceed the genesis epoch is
//! refused rather than pointed at a root its own floor law rejects. Re-running
//! seeds the same epochs, so a failed attempt costs nothing.

use core::cell::RefCell;

use zeroize::Zeroizing;

use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::seal::{GrantSetCommitment, PreservedFields, ReadBody, sign_grant_set};
use cipherbox_core::suite::aead::NONCE_LEN;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::X25519Secret;

use crate::entropy::{Entropy, EntropyError};
use crate::gate::floor::{self, ColdSeedError, FloorRegression};
use crate::net::author::{
    AuthorError, ENVELOPE_V, EnvelopeAuthoring, author_scope_root_with_section,
};
use crate::net::record_publish::{HeadBinding, PreflightError, PreflightedHead, preflight};
use crate::net::rotation::OwnerScopeKeys;
use crate::rotation::reseal::{
    CommittedSet, ResealError, ResealSeeds, ScopeRootIdentity, WriteHistory, reseal_scope_root,
};
use crate::rotation::rotate_write::{WritePublishError, derive_write_name};
use crate::seams::{FloorStore, SeamError};
use crate::session::SessionIdentity;
use crate::sync::pointer::{PointerError, SessionRole, seal_repoint};

/// The read and write epoch a genesis root publishes at. Both planes start at
/// the first epoch rather than zero: a rotation advances past its predecessor
/// ([`build_repoint_object`](crate::rotation::build_repoint_object)), and the
/// floor law reserves nothing below it.
pub const GENESIS_EPOCH: u64 = 1;

/// The vault-pointer chain index a first run publishes at. Higher indices exist
/// only as the owner-side pointer-key-compromise recovery (CONTEXT.md "Vault
/// pointer").
pub const GENESIS_VAULT_POINTER_INDEX: u64 = 0;

/// Why a first-run mint was refused before it began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPointerProbe {
    /// A record already exists at the vault-pointer name, so this account has
    /// published before. Minting would put a second genesis vault at the one
    /// name that names the first, and the first carries the only copy of a
    /// write scope seed nobody can re-derive.
    AlreadyPublished,
    /// Some authority that must answer did not — any endpoint that failed, or an
    /// API that would not say. Never evidence that an account is new: one silent
    /// endpoint is exactly how a partial outage impersonates a vacant name.
    Indeterminate,
}

impl core::fmt::Display for VaultPointerProbe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyPublished => {
                f.write_str("a record already exists at the vault-pointer name")
            }
            Self::Indeterminate => {
                f.write_str("no authority could say whether the vault-pointer name is vacant")
            }
        }
    }
}

/// The network effects provisioning makes, behind one seam so a deterministic
/// simulation can drive the whole composition without a transport (the shape
/// [`WriteWavePublisher`](crate::rotation::WriteWavePublisher) has for the same
/// reason).
///
/// Both publish implementations MUST register the name they publish, first and
/// fail-closed — the never-orphan ordering law (`net/publish.rs`, #28 D5).
pub trait VaultProvisionPublisher {
    /// Fail-closed proof that `name` has never carried a vault pointer — the
    /// mint's one precondition.
    ///
    /// A failed read is not that proof. The pointer walk yields nothing for an
    /// outage exactly as it does for a new account, because the fan-out GET
    /// tolerates a per-endpoint failure as staleness (`net/fanout.rs`), so the
    /// mint asks positively here instead — and **unanimously**: every authority
    /// must answer, and none may hold a record. One tolerated silence is one
    /// partial outage away from overwriting a live account's only vault.
    async fn require_vacant_vault_pointer(&self, name: &IpnsName) -> Result<(), VaultPointerProbe>;

    /// Upload the head block, then register-first CAS-publish the genesis root
    /// record at `name` under its narrow per-name `signer`.
    async fn publish_root_record(
        &self,
        name: &IpnsName,
        signer: &Ed25519Signer,
        head: &PreflightedHead,
    ) -> Result<(), WritePublishError>;

    /// Publish `block` as the raw record `Value` at the vault-pointer `name`.
    async fn publish_vault_pointer(
        &self,
        name: &IpnsName,
        signer: &Ed25519Signer,
        block: &[u8],
    ) -> Result<(), WritePublishError>;
}

/// The owner material one provisioning run needs, all read from the live
/// [`SessionIdentity`](crate::session::SessionIdentity) — never re-derived here.
pub struct ProvisionPlan<'a> {
    /// The vault's root scope id, which is also its root node id.
    pub scope_id: [u8; 16],
    /// The re-point payload wire version the pointer is sealed at.
    pub payload_version: u64,
    /// The owner identity: signs the grant-set commitment and the re-point
    /// object, and anchors the authored root's own produce-side gate check.
    pub owner_identity: &'a EcdsaSigner,
    /// The owner's encryption subkey — the owner blob and owner-write-blob
    /// recipient, and the tag-binding proof `reseal_scope_root` runs.
    pub owner_enc_secret: &'a X25519Secret,
    /// The signer for [`GENESIS_VAULT_POINTER_INDEX`] (`vault-pointer-index`
    /// edge). Its verifying key is the pointer name, so the name cannot be
    /// mis-paired with the key that signs at it.
    pub vault_pointer_signer: &'a Ed25519Signer,
    /// The journaled creation time of the root folder's read body (injected;
    /// this module reads no clock).
    pub created_at: u64,
}

/// A provisioned vault: what the account now has published, and the two scope
/// seeds only this run holds.
///
/// `Debug` is hand-written: both seeds are key material and must never reach a
/// log site (security rule 2).
pub struct ProvisionedVault {
    /// The genesis scope root's write-plane `ipnsName`.
    pub root_name: IpnsName,
    /// The owner-signed re-point object the vault pointer now carries — the same
    /// value a later boot's pointer walk hands back.
    pub repoint: RepointObject,
    /// The root scope's read (override) seed.
    pub read_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The root scope's write seed — the one the owner cannot re-derive, and
    /// which every later session recovers from the owner-write blob.
    pub write_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
}

impl core::fmt::Debug for ProvisionedVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProvisionedVault")
            .field("root_name", &self.root_name)
            .field("repoint", &self.repoint)
            .field("read_scope_seed", &"<redacted>")
            .field("write_scope_seed", &"<redacted>")
            .finish()
    }
}

/// A fail-closed provisioning failure. Nothing is deposited and no loop spawns
/// on any of these (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionError {
    /// The vault-pointer name is not provably vacant, so nothing was minted and
    /// nothing was drawn (see [`VaultPointerProbe`]).
    NotAFirstRun(VaultPointerProbe),
    /// The entropy seam could not supply a scope seed or a seal nonce.
    Entropy(EntropyError),
    /// The grant-set commitment could not be encoded for signing.
    Commitment(CodecError),
    /// The genesis grant section could not be assembled.
    Reseal(ResealError),
    /// The root envelope was refused by the produce-side gate mirror.
    Author(AuthorError),
    /// The authored head did not survive its own dry run.
    Preflight(PreflightError),
    /// The re-point object could not be sealed.
    Repoint(PointerError),
    /// A publish did not durably land. Names the stage, since the two differ in
    /// what they leave behind (module docs).
    Publish {
        /// `root-record` or `vault-pointer`.
        stage: &'static str,
        /// The underlying transport verdict.
        error: WritePublishError,
    },
    /// The durable floors already sit above the genesis epoch: this account has
    /// published a higher epoch than a first run can mint, so the root just
    /// published is below its own floor. Fail-closed — the floor law.
    FloorRegression(FloorRegression),
    /// The floor store could not be read or written.
    Seam(SeamError),
}

impl core::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAFirstRun(probe) => write!(f, "not a first run: {probe}"),
            Self::Entropy(e) => write!(f, "provisioning entropy error: {e}"),
            Self::Commitment(e) => write!(f, "grant-set commitment encode failed: {}", e.check()),
            Self::Reseal(e) => write!(f, "genesis grant section: {e}"),
            Self::Author(e) => write!(f, "genesis root envelope: {e}"),
            Self::Preflight(e) => write!(f, "genesis root dry run: {e}"),
            Self::Repoint(e) => write!(f, "genesis re-point seal failed: {e:?}"),
            Self::Publish { stage, error } => write!(f, "{stage} publish failed: {error}"),
            Self::FloorRegression(r) => write!(f, "{r}"),
            Self::Seam(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProvisionError {}

impl ProvisionError {
    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            Self::NotAFirstRun(VaultPointerProbe::AlreadyPublished) => "vault-already-published",
            Self::NotAFirstRun(VaultPointerProbe::Indeterminate) => "vault-pointer-indeterminate",
            Self::Entropy(_) => "entropy-error",
            Self::Commitment(_) => "commitment-encode-failed",
            Self::Reseal(e) => e.check(),
            Self::Author(e) => e.check(),
            Self::Preflight(_) => "preflight-failed",
            Self::Repoint(_) => "repoint-seal-failed",
            Self::Publish { .. } => "publish-failed",
            Self::FloorRegression(_) => "floor-regression",
            Self::Seam(_) => "seam-error",
        }
    }

    /// Whether a fresh `start` could clear this — an availability stall — versus
    /// this build's own fail-closed verdict on the vault it was about to mint,
    /// which a retry reaches again. Rule 6: a refusal is never laundered into a
    /// retryable stall, and a stall is never reported as a refusal.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::NotAFirstRun(probe) => *probe == VaultPointerProbe::Indeterminate,
            Self::Entropy(_) | Self::Seam(_) => true,
            Self::Publish { error, .. } => *error != WritePublishError::Rejected,
            Self::Commitment(_)
            | Self::Reseal(_)
            | Self::Author(_)
            | Self::Preflight(_)
            | Self::Repoint(_)
            | Self::FloorRegression(_) => false,
        }
    }
}

/// Provision an account's first vault: mint both scope seeds, seed the floors
/// the genesis re-point vouches, then author and publish the scope root and the
/// vault pointer naming it.
///
/// Ordering is the safety property: the floor law refuses before anything is
/// published, and the root is published **before** the pointer, so the pointer
/// never names a record that is not there. Everything the caller needs to run a
/// live session comes back in [`ProvisionedVault`]; nothing is deposited here.
pub async fn provision_vault<E, K, P, Fl>(
    entropy: &RefCell<E>,
    scope_keys: &K,
    publisher: &P,
    floors: &Fl,
    plan: &ProvisionPlan<'_>,
) -> Result<ProvisionedVault, ProvisionError>
where
    E: Entropy,
    K: OwnerScopeKeys,
    P: VaultProvisionPublisher,
    Fl: FloorStore,
{
    let scope_id = plan.scope_id;
    let pointer_name = IpnsName::from_public_key(&plan.vault_pointer_signer.verifying_key());

    // 1) The precondition, before a byte of key material is drawn: this account
    //    has provably never published a vault pointer. `Engine::start` reaches
    //    provisioning on any pointer walk that yielded nothing, and an outage
    //    yields nothing too — so the mint asks positively rather than inferring
    //    a new account from a failed read.
    publisher
        .require_vacant_vault_pointer(&pointer_name)
        .await
        .map_err(ProvisionError::NotAFirstRun)?;

    // 2-3) Both scope seeds are RANDOM, never KDF-derived: the write scope seed
    //      is the one input the owner cannot re-derive, and the read seed is an
    //      override seed a rotation replaces in kind.
    let read_scope_seed = draw_seed(entropy)?;
    let write_scope_seed = draw_seed(entropy)?;

    // 4) The root's write-plane name — a pure function of the write scope seed,
    //    so every later write grantee re-derives it with no discovery.
    let root_name = derive_write_name(&write_scope_seed, &scope_id);

    // 5) The re-point object the vault pointer will carry, and the floors it
    //    vouches — seeded BEFORE anything is published, so a durable floor
    //    already above the genesis epoch stops the run rather than signing a
    //    pointer at a root its own floor law rejects. Later sessions reach this
    //    same state through `cold_start`'s cold-seed.
    let repoint = RepointObject {
        scope_id,
        current_root: root_name.clone(),
        write_epoch: GENESIS_EPOCH,
        min_read_epoch: GENESIS_EPOCH,
        prev_root: None,
    };
    floor::cold_seed_checked(floors, &repoint, &scope_id)
        .await
        .map_err(|e| match e {
            ColdSeedError::Seam(seam) => ProvisionError::Seam(seam),
            ColdSeedError::Regression(reg) => ProvisionError::FloorRegression(reg),
        })?;

    // 6) The grant-set commitment: no grantees yet, this name, and the owner's
    //    writer pseudonym. The commitment is owner-signed and carries no epoch,
    //    so it is never revised — a pseudonym that is not the one
    //    `OwnerScopeKeys` derives fails `SignerNotCommitted` on every later
    //    rotation, permanently. Deriving it here through the same trait the
    //    re-seal path uses is what keeps the two sides one value.
    let pseudonym_signer = scope_keys.writer_pseudonym(&scope_id);
    let commitment = GrantSetCommitment {
        ipns_name: root_name.as_str().as_bytes().to_vec(),
        owner_pseudonym_pk: pseudonym_signer.verifying_key().to_bytes(),
        entries: Vec::new(),
        unknown: PreservedFields::new(),
    };
    let commitment_sig = sign_grant_set(plan.owner_identity, &commitment)
        .map_err(ProvisionError::Commitment)?
        .to_compact();

    // 7) The grant section. A vault root's shape: no parent node seed (so no
    //    ascent link), no predecessor epoch (so no history link), and a write
    //    plane that has nothing to carry.
    let pointer_read_key = scope_keys.pointer_read_key(&scope_id);
    let owner_enc_pub = plan.owner_enc_secret.public();
    let section = reseal_scope_root(
        &mut *entropy.borrow_mut(),
        &ScopeRootIdentity {
            v: ENVELOPE_V,
            scope_id,
            ipns_name: root_name.as_str().as_bytes(),
            owner_enc_pub: &owner_enc_pub,
            owner_enc_secret: Some(plan.owner_enc_secret),
            parent_node_seed: None,
            pseudonym_signer: &pseudonym_signer,
        },
        &ResealSeeds {
            override_seed: &read_scope_seed,
            read_epoch: GENESIS_EPOCH,
            prev: None,
            write_scope_seed: &write_scope_seed,
            write_epoch: GENESIS_EPOCH,
            write_history: WriteHistory::Carried(b""),
            pointer_read_key: &pointer_read_key,
        },
        &CommittedSet {
            commitment: &commitment,
            commitment_sig: &commitment_sig,
            grant_ledger: &[],
            direct_child_scope_index: &[],
        },
        &[],
    )
    .map_err(ProvisionError::Reseal)?;

    // 8) The root envelope: an empty folder at the anchored root node, carrying
    //    the section as its scope-root marker.
    let read_key = kdf::read_key(kdf::node_seed(&read_scope_seed, &scope_id).as_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    entropy
        .borrow_mut()
        .fill(&mut nonce)
        .map_err(ProvisionError::Entropy)?;
    let body = ReadBody::Folder {
        created_at: plan.created_at,
        modified_at: plan.created_at,
        children: Vec::new(),
        unknown: PreservedFields::new(),
    };
    let head = author_scope_root_with_section(
        EnvelopeAuthoring {
            node_id: scope_id,
            scope_id,
            epoch: GENESIS_EPOCH,
            read_key: read_key.as_bytes(),
            nonce: &nonce,
            body: &body,
            carried_unknown: PreservedFields::new(),
            carried_epoch_tag_unknown: PreservedFields::new(),
        },
        &root_name,
        &section,
        &plan.owner_identity.verifying_key(),
    )
    .map_err(ProvisionError::Author)?;

    // 9) Register-first, upload, CAS publish. The name has no durable sequence
    //    floor, so the pipeline embeds sequence 1.
    let binding = HeadBinding {
        node_id: scope_id,
        scope_id,
        epoch: GENESIS_EPOCH,
    };
    let preflighted =
        preflight(&binding, read_key.as_bytes(), &head).map_err(ProvisionError::Preflight)?;
    let root_signer = SessionIdentity::write_name_signer(&write_scope_seed, &scope_id);
    publisher
        .publish_root_record(&root_name, &root_signer, &preflighted)
        .await
        .map_err(|error| ProvisionError::Publish {
            stage: "root-record",
            error,
        })?;

    // 10) Seal the re-point. `build_repoint_object` cannot mint this one: it takes
    //    a predecessor name by value and enforces that the new one differs, which
    //    is the invariant of an advance, not of a first publication.
    let block = seal_repoint(
        SessionRole::Owner,
        &mut *entropy.borrow_mut(),
        &pointer_read_key,
        plan.payload_version,
        plan.owner_identity,
        &repoint,
    )
    .map_err(ProvisionError::Repoint)?;

    // 11) The pointer LAST — the act that makes everything above reachable.
    publisher
        .publish_vault_pointer(&pointer_name, plan.vault_pointer_signer, &block)
        .await
        .map_err(|error| ProvisionError::Publish {
            stage: "vault-pointer",
            error,
        })?;

    Ok(ProvisionedVault {
        root_name,
        repoint,
        read_scope_seed,
        write_scope_seed,
    })
}

/// Draw one 32-byte scope seed from the entropy seam, fail-closed.
///
/// An all-zero draw is refused for the reason
/// [`fresh_ephemeral`](crate::entropy::fresh_ephemeral) refuses one: a seam that
/// reports success having written nothing would hand this account's whole vault
/// a world-known root secret, and it would be published before anything read it
/// back.
fn draw_seed<E: Entropy>(
    entropy: &RefCell<E>,
) -> Result<Zeroizing<[u8; SECRET_LEN]>, ProvisionError> {
    let mut seed = Zeroizing::new([0u8; SECRET_LEN]);
    entropy
        .borrow_mut()
        .fill(seed.as_mut())
        .map_err(ProvisionError::Entropy)?;
    if seed.iter().all(|byte| *byte == 0) {
        return Err(ProvisionError::Entropy(EntropyError::new(
            "entropy seam produced an all-zero scope seed",
        )));
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    use cipherbox_core::hex::lower as hex_lower;
    use cipherbox_core::seal::{decode_grant_section, grant_section_bytes, verify_grant_set};
    use cipherbox_core::suite::ecdsa::EcdsaSignature;

    use crate::facade::LoginSecret;
    use crate::owner_keys::OwnerSessionKeys;
    use crate::sync::pointer::open_repoint;
    use crate::testkit::fakes::InMemoryFloorStore;
    use crate::testkit::{SeededEntropy, block_on};

    const SECRET: [u8; 32] = [0x11; 32];
    /// The all-zero bootstrap anchor `Engine::start` binds its cold-start scope to.
    const SCOPE: [u8; 16] = [0u8; 16];
    const VERSION: u64 = 1;

    fn session() -> SessionIdentity {
        SessionIdentity::derive(&LoginSecret::new(SECRET.to_vec())).expect("valid identity")
    }

    /// One recorded publish, in call order — the tape the ordering invariant is
    /// asserted over.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Effect {
        Root(String),
        Pointer(String),
    }

    /// A publisher over in-memory state, optionally scripted to refuse one leg.
    #[derive(Default)]
    struct FakePublisher {
        effects: RefCell<Vec<Effect>>,
        head_block: RefCell<Option<Vec<u8>>>,
        pointer_block: RefCell<Option<Vec<u8>>>,
        probe: Option<VaultPointerProbe>,
        refuse_root: Cell<bool>,
        refuse_pointer: Option<WritePublishError>,
    }

    impl FakePublisher {
        fn refusing_root() -> Self {
            Self {
                refuse_root: Cell::new(true),
                ..Self::default()
            }
        }

        fn refusing_pointer(error: WritePublishError) -> Self {
            Self {
                refuse_pointer: Some(error),
                ..Self::default()
            }
        }

        fn probing(probe: VaultPointerProbe) -> Self {
            Self {
                probe: Some(probe),
                ..Self::default()
            }
        }
    }

    impl VaultProvisionPublisher for FakePublisher {
        async fn require_vacant_vault_pointer(
            &self,
            _name: &IpnsName,
        ) -> Result<(), VaultPointerProbe> {
            self.probe.map_or(Ok(()), Err)
        }

        async fn publish_root_record(
            &self,
            name: &IpnsName,
            signer: &Ed25519Signer,
            head: &PreflightedHead,
        ) -> Result<(), WritePublishError> {
            // The signer IS the name's key, or no resolver could verify the
            // record: the production arm signs whatever it is handed, so the
            // pairing is provisioning's to get right.
            assert_eq!(
                IpnsName::from_public_key(&signer.verifying_key()),
                *name,
                "the root signer must be the root name's key"
            );
            if self.refuse_root.get() {
                return Err(WritePublishError::NotLanded);
            }
            self.effects
                .borrow_mut()
                .push(Effect::Root(name.as_str().to_owned()));
            *self.head_block.borrow_mut() = Some(head.block().to_vec());
            Ok(())
        }

        async fn publish_vault_pointer(
            &self,
            name: &IpnsName,
            signer: &Ed25519Signer,
            block: &[u8],
        ) -> Result<(), WritePublishError> {
            assert_eq!(
                IpnsName::from_public_key(&signer.verifying_key()),
                *name,
                "the pointer signer must be the pointer name's key"
            );
            if let Some(error) = self.refuse_pointer.clone() {
                return Err(error);
            }
            self.effects
                .borrow_mut()
                .push(Effect::Pointer(name.as_str().to_owned()));
            *self.pointer_block.borrow_mut() = Some(block.to_vec());
            Ok(())
        }
    }

    /// Run `provision_vault` for `session` over `publisher` and `floors`.
    fn run(
        session: &SessionIdentity,
        publisher: &FakePublisher,
        floors: &InMemoryFloorStore,
        entropy_seed: u64,
    ) -> Result<ProvisionedVault, ProvisionError> {
        let entropy = RefCell::new(SeededEntropy::new(entropy_seed));
        let pointer_signer = session.vault_pointer_signer(GENESIS_VAULT_POINTER_INDEX);
        block_on(provision_vault(
            &entropy,
            &OwnerSessionKeys::new(session),
            publisher,
            floors,
            &ProvisionPlan {
                scope_id: SCOPE,
                payload_version: VERSION,
                owner_identity: session.identity(),
                owner_enc_secret: session.enc_subkey(),
                vault_pointer_signer: &pointer_signer,
                created_at: 1_700_000_000_000,
            },
        ))
    }

    /// The grant-set commitment as it was published, read back out of the head
    /// block the publisher captured.
    fn published_commitment(publisher: &FakePublisher) -> cipherbox_core::seal::GrantSection {
        let block = publisher
            .head_block
            .borrow()
            .clone()
            .expect("a root record was published");
        let envelope = cipherbox_core::seal::decode_envelope(&block).expect("a decodable head");
        decode_grant_section(grant_section_bytes(&envelope).expect("a scope-root marker"))
            .expect("a decodable grant section")
    }

    /// **The join.** The pseudonym provisioning commits, epoch-free and for ever,
    /// must be the one the production `OwnerScopeKeys` arm derives — the key every
    /// later re-seal detach-signs under and the gate checks against the
    /// commitment. The two halves are written in different modules and nothing
    /// else compares them; a mismatch is a permanent `SignerNotCommitted` on every
    /// rotation, surfacing only at the first one.
    #[test]
    fn the_committed_pseudonym_is_the_one_the_owner_arm_derives() {
        let session = session();
        let publisher = FakePublisher::default();
        run(&session, &publisher, &InMemoryFloorStore::default(), 1)
            .expect("provisioning succeeds");

        let committed = published_commitment(&publisher)
            .commitment
            .owner_pseudonym_pk;
        assert_eq!(
            committed,
            OwnerSessionKeys::new(&session)
                .writer_pseudonym(&SCOPE)
                .verifying_key()
                .to_bytes(),
            "a later re-seal signs under this key and must stay committed",
        );
    }

    /// The same join, from the other side: none of the three owner secrets
    /// FSM1/cipher-box-next ADR 0005 rejected may stand in for the pseudonym seed,
    /// so swapping the derivation is caught here rather than at a first rotation.
    #[test]
    fn the_committed_pseudonym_is_none_of_the_rejected_owner_inputs() {
        let session = session();
        let publisher = FakePublisher::default();
        run(&session, &publisher, &InMemoryFloorStore::default(), 2)
            .expect("provisioning succeeds");
        let committed = published_commitment(&publisher)
            .commitment
            .owner_pseudonym_pk;

        let enc = kdf::enc_subkey(&SECRET);
        let self_ecdh = enc
            .diffie_hellman(&enc.public())
            .expect("self-ECDH is contributory");
        for (name, seed) in [
            ("the login secret", SECRET),
            (
                "the owner pointer seed",
                *kdf::owner_pointer_seed(&SECRET).as_bytes(),
            ),
            ("self-ECDH over the enc subkey", *self_ecdh.as_bytes()),
        ] {
            assert_ne!(
                committed,
                kdf::pseudonym_sign(&seed, &SCOPE)
                    .verifying_key()
                    .to_bytes(),
                "{name} stood in for the owner pseudonym seed",
            );
        }
    }

    /// The commitment is the owner-trust anchor every resolve checks, so it must
    /// be signed by the session's own identity and name the record's own name.
    #[test]
    fn the_commitment_is_owner_signed_over_the_published_root_name() {
        let session = session();
        let publisher = FakePublisher::default();
        let out = run(&session, &publisher, &InMemoryFloorStore::default(), 3)
            .expect("provisioning succeeds");

        let section = published_commitment(&publisher);
        assert_eq!(
            section.commitment.ipns_name,
            out.root_name.as_str().as_bytes(),
            "the commitment anchors the name the record is published under",
        );
        let sig = EcdsaSignature::from_compact(&section.commitment_sig).expect("a compact sig");
        assert!(
            verify_grant_set(&session.owner_identity(), &section.commitment, &sig).is_ok(),
            "the owner identity attests the committed set",
        );
        assert!(
            section.commitment.entries.is_empty(),
            "a first-run vault has no grantees",
        );
    }

    /// The pointer must resolve back to the root that was just published, under
    /// the owner's own pointer read key and at the genesis epochs — the loop
    /// `cold_start` closes on the next boot.
    #[test]
    fn the_published_pointer_names_the_published_root() {
        let session = session();
        let publisher = FakePublisher::default();
        let out = run(&session, &publisher, &InMemoryFloorStore::default(), 4)
            .expect("provisioning succeeds");

        let block = publisher
            .pointer_block
            .borrow()
            .clone()
            .expect("a pointer was published");
        let repoint = open_repoint(
            session.pointer_read_key(&SCOPE).as_bytes(),
            VERSION,
            &SCOPE,
            &session.owner_identity(),
            &block,
        )
        .expect("the owner's own pointer read key opens it");
        assert_eq!(repoint.current_root, out.root_name);
        assert_eq!(
            repoint.prev_root, None,
            "a genesis re-point has no predecessor"
        );
        assert_eq!(repoint.write_epoch, GENESIS_EPOCH);
        assert_eq!(repoint.min_read_epoch, GENESIS_EPOCH);
        // The name the pointer carries is the one the returned write seed derives,
        // or the drain would publish every node under keys nothing can verify.
        assert_eq!(
            derive_write_name(&out.write_scope_seed, &SCOPE),
            out.root_name,
        );
    }

    /// The pointer is the only entry point, so it must never land before the
    /// record it names.
    #[test]
    fn the_root_record_is_published_before_the_pointer() {
        let session = session();
        let publisher = FakePublisher::default();
        let out = run(&session, &publisher, &InMemoryFloorStore::default(), 5)
            .expect("provisioning succeeds");
        assert_eq!(
            *publisher.effects.borrow(),
            vec![
                Effect::Root(out.root_name.as_str().to_owned()),
                Effect::Pointer(
                    IpnsName::from_public_key(
                        &session
                            .vault_pointer_signer(GENESIS_VAULT_POINTER_INDEX)
                            .verifying_key()
                    )
                    .as_str()
                    .to_owned()
                ),
            ],
        );
    }

    /// A root publish that did not land aborts before the pointer, so no boot can
    /// ever reach a pointer naming a record that is not there.
    #[test]
    fn a_failed_root_publish_leaves_no_pointer() {
        let session = session();
        let publisher = FakePublisher::refusing_root();
        let err = run(&session, &publisher, &InMemoryFloorStore::default(), 6)
            .expect_err("a root that did not land is not a provisioned vault");
        assert_eq!(err.check(), "publish-failed");
        assert!(
            publisher.effects.borrow().is_empty(),
            "nothing is published once the root refused",
        );
    }

    /// Two devices provisioning at once: whatever verdict the loser's pointer PUT
    /// comes back with, it is a failure and never a silent success — the loser's
    /// root is orphaned and the winner's pointer is the account's. `LostRace` is
    /// the verdict when a strictly higher sequence is observed; `Unconfirmed`
    /// (surfaced as `NotLanded`) is the one a same-sequence fork reaches, which is
    /// what two genesis pointers at sequence 1 actually produce.
    #[test]
    fn a_pointer_publish_that_is_not_published_is_fail_closed() {
        for error in [WritePublishError::LostRace, WritePublishError::NotLanded] {
            let session = session();
            let publisher = FakePublisher::refusing_pointer(error.clone());
            let err = run(&session, &publisher, &InMemoryFloorStore::default(), 7)
                .expect_err("only a confirmed publish is a provisioned vault");
            assert_eq!(
                err,
                ProvisionError::Publish {
                    stage: "vault-pointer",
                    error,
                },
            );
        }
    }

    /// The mint's precondition. `Engine::start` reaches provisioning on any
    /// pointer walk that yielded nothing, and an unreachable record plane yields
    /// nothing too — so an indeterminate probe must refuse rather than mint a
    /// second genesis vault over a live account's one pointer name.
    #[test]
    fn an_indeterminate_pointer_probe_mints_nothing() {
        let session = session();
        let floors = InMemoryFloorStore::default();
        let publisher = FakePublisher::probing(VaultPointerProbe::Indeterminate);
        let err = run(&session, &publisher, &floors, 20)
            .expect_err("a failed read is not evidence of a new account");
        assert_eq!(
            err,
            ProvisionError::NotAFirstRun(VaultPointerProbe::Indeterminate)
        );
        assert!(
            err.is_retryable(),
            "an outage is availability, not a verdict"
        );
        assert!(publisher.effects.borrow().is_empty(), "nothing published");
        assert_eq!(
            block_on(floor::write_epoch_floor(&floors, &SCOPE)).unwrap(),
            None,
            "and no durable local state was written either",
        );
    }

    /// A record already at the pointer name means the account has published, so
    /// the refusal is permanent for this run rather than a stall a retry clears.
    #[test]
    fn an_already_published_vault_is_never_re_minted() {
        let session = session();
        let publisher = FakePublisher::probing(VaultPointerProbe::AlreadyPublished);
        let err = run(&session, &publisher, &InMemoryFloorStore::default(), 21)
            .expect_err("a published vault is not a first run");
        assert_eq!(
            err,
            ProvisionError::NotAFirstRun(VaultPointerProbe::AlreadyPublished)
        );
        assert!(!err.is_retryable(), "re-running reaches the same refusal");
        assert!(publisher.effects.borrow().is_empty(), "nothing published");
    }

    /// A seam that reports success having written nothing would hand this account
    /// a world-known root secret, published before anything read it back.
    #[test]
    fn a_silent_entropy_seam_mints_nothing() {
        struct Silent;
        impl Entropy for Silent {
            fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
                Ok(())
            }
        }
        let session = session();
        let publisher = FakePublisher::default();
        let pointer_signer = session.vault_pointer_signer(GENESIS_VAULT_POINTER_INDEX);
        let err = block_on(provision_vault(
            &RefCell::new(Silent),
            &OwnerSessionKeys::new(&session),
            &publisher,
            &InMemoryFloorStore::default(),
            &ProvisionPlan {
                scope_id: SCOPE,
                payload_version: VERSION,
                owner_identity: session.identity(),
                owner_enc_secret: session.enc_subkey(),
                vault_pointer_signer: &pointer_signer,
                created_at: 0,
            },
        ))
        .expect_err("an all-zero scope seed is never published");
        assert_eq!(err.check(), "entropy-error");
        assert!(publisher.effects.borrow().is_empty(), "nothing published");
    }

    /// The floors the genesis re-point vouches are durable before anything is
    /// published: the session's own adopts open the owner-write blob at the write
    /// floor, and without it the root is held keyless.
    #[test]
    fn the_genesis_floors_are_seeded() {
        let session = session();
        let floors = InMemoryFloorStore::default();
        let publisher = FakePublisher::default();
        run(&session, &publisher, &floors, 8).expect("provisioning succeeds");
        assert_eq!(
            block_on(floor::read_epoch_floor(&floors, &SCOPE)).unwrap(),
            Some(GENESIS_EPOCH),
        );
        assert_eq!(
            block_on(floor::write_epoch_floor(&floors, &SCOPE)).unwrap(),
            Some(GENESIS_EPOCH),
        );
    }

    /// An account whose durable floors already sit above the genesis epoch has
    /// published past what a first run can mint. Provisioning it would sign a
    /// pointer at a root the floor law rejects, so it refuses before publishing
    /// anything.
    #[test]
    fn floors_above_the_genesis_epoch_refuse_before_any_publish() {
        let session = session();
        let floors = InMemoryFloorStore::default();
        block_on(floor::advance_write_epoch_on_sight(&floors, &SCOPE, 9)).expect("floor raise");
        let publisher = FakePublisher::default();
        let err = run(&session, &publisher, &floors, 9).expect_err("not a first run");
        assert_eq!(
            err,
            ProvisionError::FloorRegression(FloorRegression::WriteEpoch {
                floor: 9,
                vouched: GENESIS_EPOCH,
            }),
        );
        assert!(publisher.effects.borrow().is_empty(), "nothing published");
    }

    /// Both seeds are drawn from the entropy seam, never derived from the login
    /// secret: a seed a second party could re-derive is not a scope secret.
    #[test]
    fn both_scope_seeds_are_drawn_not_derived() {
        let session = session();
        let out = run(
            &session,
            &FakePublisher::default(),
            &InMemoryFloorStore::default(),
            10,
        )
        .expect("provisioning succeeds");
        assert_ne!(*out.read_scope_seed, *out.write_scope_seed);
        assert_ne!(*out.read_scope_seed, SECRET);
        assert_ne!(*out.write_scope_seed, SECRET);
        // A different entropy stream mints a different vault for the same secret.
        let other = run(
            &session,
            &FakePublisher::default(),
            &InMemoryFloorStore::default(),
            11,
        )
        .expect("provisioning succeeds");
        assert_ne!(out.root_name, other.root_name);
    }

    /// Key material never reaches a log site, including a test-assertion `{:?}`.
    #[test]
    fn debug_redacts_both_seeds() {
        let session = session();
        let out = run(
            &session,
            &FakePublisher::default(),
            &InMemoryFloorStore::default(),
            12,
        )
        .expect("provisioning succeeds");
        let rendered = format!("{out:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&hex_lower(out.write_scope_seed.as_slice())));
        assert!(!rendered.contains(&hex_lower(out.read_scope_seed.as_slice())));
    }
}
