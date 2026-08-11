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
//! # Idempotent, and stateless about it (ADR 0007)
//!
//! Both genesis scope seeds are **derived from the login secret**, so every
//! attempt by one account reproduces one root name, one set of keys and one
//! re-point object. Resume needs no journal and no checkpoint: a retry re-derives
//! what a crashed attempt held, adopts the record that attempt published, and
//! publishes no second one.
//!
//! Two consequences shape the sequence below:
//!
//! - **the root step confirms by adopt** — a record at the derived name that
//!   this session's read key opens and the adoption gate admits completes the
//!   step, whoever published it (D3);
//! - **the mint's success condition is a re-openable re-point, not a landed
//!   PUT** — after the pointer publish the pointer is resolved and opened under
//!   the owner's own pointer read key, and that answer decides (D2). No server
//!   answer authorises any branch: a withheld or lying one can only reach the
//!   indeterminate branch, which refuses.
//!
//! The floor cold-seed is the one durable local effect, and it runs **before**
//! any publish: an account whose floors already exceed the genesis epoch is
//! refused rather than pointed at a root its own floor law rejects. Re-running
//! seeds the same epochs, so a failed attempt costs nothing.
//!
//! The residual a crash can still leave is one unreferenced pinned head block,
//! between the head upload and the record PUT — the shape every publish has,
//! and no new mechanism here (D4).

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
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
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
use crate::sync::pointer::{PointerError, SessionRole, open_repoint, seal_repoint};

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

/// Whether the genesis root record already stands at its derived name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootStep {
    /// A record there passed this session's adoption gate: the root step is
    /// complete, whether this run published it or a crashed earlier attempt did
    /// (D3). Nothing further is authored, published or uploaded.
    AlreadyAdopted,
    /// Nothing adoptable answers — author and publish. Bytes that are there but
    /// fail the gate reach this arm too: at a name only this account's derived
    /// seed can sign for, the recovery is to publish, and CAS decides.
    MustPublish,
}

/// The network effects provisioning makes, behind one seam so a deterministic
/// simulation can drive the whole composition without a transport (the shape
/// [`WriteWavePublisher`](crate::rotation::WriteWavePublisher) has for the same
/// reason).
///
/// Both publish implementations MUST register the name they publish, first and
/// fail-closed — the never-orphan ordering law (`net/publish.rs`, #28 D5).
pub trait VaultProvisionPublisher {
    /// Whether a record at the derived root `name` passes this session's
    /// adoption gate — the root step's confirm-by-adopt (D3).
    async fn genesis_root_step(&self, name: &IpnsName) -> RootStep;

    /// The sealed re-point block the vault pointer at `name` carries, or `None`
    /// when nothing resolvable answers. An outage and a vacant name are one
    /// answer here: neither completes a mint, and the caller refuses on both.
    async fn fetch_vault_pointer(&self, name: &IpnsName) -> Option<Vec<u8>>;

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
    /// The genesis read (override) seed — the `genesis-read-scope-seed` edge,
    /// read from the live session like every other owner derivation here.
    pub genesis_read_scope_seed: &'a SecretBytes,
    /// The genesis `writeScopeSeed` (`genesis-write-scope-seed` edge). Deriving
    /// it is what makes this mint idempotent: a retry re-derives the same root
    /// name and the same keys, so a crashed attempt's record is this account's
    /// own genesis root rather than an orphan (D1).
    pub genesis_write_scope_seed: &'a SecretBytes,
    /// The journaled creation time of the root folder's read body (injected;
    /// this module reads no clock).
    pub created_at: u64,
}

/// What a provisioning run settled on, decided by the re-point the pointer name
/// serves once the mint has published (D2).
#[derive(Debug)]
pub enum ProvisionOutcome {
    /// The pointer names this run's derived root: the vault is live and the
    /// caller may deposit its seeds. Boxed, so passing the outcome around moves
    /// a pointer rather than copying both seeds.
    Minted(Box<ProvisionedVault>),
    /// The pointer names a root this mint did not derive — the account has
    /// published and moved on since the vacancy probe. The mint publishes
    /// nothing further; the caller cold-starts from the account's own re-point
    /// instead, resolving it through the same authenticated walk as any boot.
    MovedOn,
}

/// A provisioned vault: what the account now has published, and the two scope
/// seeds this run derived.
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
    /// The root scope's write seed. Derived at genesis and recovered from the
    /// owner-write blob at every later session; the first rotation replaces it
    /// with a drawn one and the login secret stops being a route to it.
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
    /// Nothing resolvable answers at the vault-pointer name once the mint has
    /// published, so no branch of the success condition is decidable (D2).
    /// Indeterminate, never a verdict: nothing was deposited.
    PointerUnresolved,
    /// A block at this account's own pointer name that this account's own
    /// pointer read key and owner identity will not open — tamper or a wrong
    /// owner, fail-closed (surfaced from the walk verbatim).
    RepointUnopenable(PointerError),
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
            Self::PointerUnresolved => {
                f.write_str("the vault-pointer name served no re-point after the mint published")
            }
            Self::RepointUnopenable(e) => {
                write!(f, "the vault pointer's re-point will not open: {e:?}")
            }
            Self::Publish { stage, error } => write!(f, "{stage} publish failed: {error}"),
            Self::FloorRegression(r) => write!(f, "{r}"),
            Self::Seam(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProvisionError {}

impl ProvisionError {
    /// Whether a fresh `start` could clear this — an availability stall — versus
    /// this build's own fail-closed verdict on the vault it was about to mint,
    /// which a retry reaches again. Rule 6: a refusal is never laundered into a
    /// retryable stall, and a stall is never reported as a refusal.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::NotAFirstRun(probe) => *probe == VaultPointerProbe::Indeterminate,
            Self::Entropy(_) | Self::Seam(_) | Self::PointerUnresolved => true,
            Self::Publish { error, .. } => *error != WritePublishError::Rejected,
            Self::Commitment(_)
            | Self::Reseal(_)
            | Self::Author(_)
            | Self::Preflight(_)
            | Self::Repoint(_)
            | Self::RepointUnopenable(_)
            | Self::FloorRegression(_) => false,
        }
    }
}

/// Provision an account's first vault: re-derive both scope seeds, seed the
/// floors the genesis re-point vouches, then bring the scope root and the vault
/// pointer naming it to their published state.
///
/// Ordering is the safety property: the floor law refuses before anything is
/// published, and the root is published **before** the pointer, so the pointer
/// never names a record that is not there. Idempotence is the other: each step
/// is skipped when what it would publish already stands. Everything the caller
/// needs to run a live session comes back in [`ProvisionOutcome`]; nothing is
/// deposited here.
pub async fn provision_vault<E, K, P, Fl>(
    entropy: &RefCell<E>,
    scope_keys: &K,
    publisher: &P,
    floors: &Fl,
    plan: &ProvisionPlan<'_>,
) -> Result<ProvisionOutcome, ProvisionError>
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

    // 2-3) Both genesis scope seeds are DERIVED (D1), so a retry reproduces this
    //      run's vault rather than forking a second one. The rotation and
    //      grant-cut seeds they neighbour stay drawn.
    let read_scope_seed = Zeroizing::new(*plan.genesis_read_scope_seed.as_bytes());
    let write_scope_seed = Zeroizing::new(*plan.genesis_write_scope_seed.as_bytes());

    // 4) The root's write-plane name — a pure function of the write scope seed,
    //    so every later write grantee re-derives it with no discovery, and so
    //    every attempt by this account names the same root.
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

    // 6) The stable per-scope pointer read key: the grant section carries it to
    //    every grantee, and the re-point below is sealed under it.
    let pointer_read_key = scope_keys.pointer_read_key(&scope_id);

    // 7) The root step, by adopt (D3). A record already at the derived name — a
    //    crashed attempt's, or a concurrent device's — completes it, and this
    //    run authors nothing, uploads no head block and publishes no record.
    let material = GenesisRoot {
        name: &root_name,
        read_scope_seed: &read_scope_seed,
        write_scope_seed: &write_scope_seed,
        pointer_read_key: &pointer_read_key,
    };
    if publisher.genesis_root_step(&root_name).await == RootStep::MustPublish {
        match publish_genesis_root(entropy, scope_keys, publisher, plan, &material).await {
            Ok(()) => {}
            // A PUT that did not land still completes the step if a concurrent
            // device's record is adoptable now: both derived the same root, so
            // there is no fork of identity to adjudicate — only bytes at one
            // name. Every other failure is this build's own refusal.
            Err(ProvisionError::Publish { stage, error }) => {
                if publisher.genesis_root_step(&root_name).await == RootStep::MustPublish {
                    return Err(ProvisionError::Publish { stage, error });
                }
            }
            Err(other) => return Err(other),
        }
    }

    // 8) Seal the re-point. `build_repoint_object` cannot mint this one: it takes
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

    // 9) The pointer — the act that makes everything above reachable. Its own
    //    verdict does not decide the mint (D2), so it is held only to report if
    //    step 10 then finds nothing to decide over.
    let publish_refusal = publisher
        .publish_vault_pointer(&pointer_name, plan.vault_pointer_signer, &block)
        .await
        .err();

    // 10) The success condition: the pointer name serves a re-point this owner's
    //     own read key opens. Nothing here is authorised by a server answer — a
    //     withheld or lying one reaches the indeterminate arm, which refuses.
    let Some(served) = publisher.fetch_vault_pointer(&pointer_name).await else {
        return Err(match publish_refusal {
            Some(error) => ProvisionError::Publish {
                stage: "vault-pointer",
                error,
            },
            None => ProvisionError::PointerUnresolved,
        });
    };
    let served = open_repoint(
        &pointer_read_key,
        plan.payload_version,
        &scope_id,
        &plan.owner_identity.verifying_key(),
        &served,
    )
    .map_err(ProvisionError::RepointUnopenable)?;
    if served.current_root != root_name {
        return Ok(ProvisionOutcome::MovedOn);
    }

    Ok(ProvisionOutcome::Minted(Box::new(ProvisionedVault {
        root_name,
        repoint,
        read_scope_seed,
        write_scope_seed,
    })))
}

/// The derived genesis material one root publish is authored under — the values
/// [`provision_vault`] computed before the root step, threaded to the publish
/// arm rather than re-derived there.
struct GenesisRoot<'a> {
    name: &'a IpnsName,
    read_scope_seed: &'a [u8; SECRET_LEN],
    write_scope_seed: &'a [u8; SECRET_LEN],
    pointer_read_key: &'a [u8; SECRET_LEN],
}

/// Author the genesis scope root and publish it register-first: the grant-set
/// commitment, the grant section, the empty-folder envelope, and the CAS PUT.
///
/// Reached only when nothing adoptable stands at the derived name, so a retry
/// that finds its predecessor's record never runs this and never uploads a
/// second head block (D3).
async fn publish_genesis_root<E, K, P>(
    entropy: &RefCell<E>,
    scope_keys: &K,
    publisher: &P,
    plan: &ProvisionPlan<'_>,
    root: &GenesisRoot<'_>,
) -> Result<(), ProvisionError>
where
    E: Entropy,
    K: OwnerScopeKeys,
    P: VaultProvisionPublisher,
{
    let scope_id = plan.scope_id;
    let root_name = root.name;

    // The grant-set commitment: no grantees yet, this name, and the owner's
    // writer pseudonym. The commitment is owner-signed and carries no epoch,
    // so it is never revised — a pseudonym that is not the one
    // `OwnerScopeKeys` derives fails `SignerNotCommitted` on every later
    // rotation, permanently. Deriving it here through the same trait the
    // re-seal path uses is what keeps the two sides one value.
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

    // The grant section. A vault root's shape: no parent node seed (so no
    // ascent link), no predecessor epoch (so no history link), and a write
    // plane that has nothing to carry.
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
            owes_ascent_link: false,
            pseudonym_signer: &pseudonym_signer,
        },
        &ResealSeeds {
            override_seed: root.read_scope_seed,
            read_epoch: GENESIS_EPOCH,
            prev: None,
            write_scope_seed: root.write_scope_seed,
            write_epoch: GENESIS_EPOCH,
            write_history: WriteHistory::Carried(b""),
            pointer_read_key: root.pointer_read_key,
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

    // The root envelope: an empty folder at the anchored root node, carrying
    // the section as its scope-root marker.
    let read_key = kdf::read_key(kdf::node_seed(root.read_scope_seed, &scope_id).as_bytes());
    let nonce = fresh_nonce(entropy)?;
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
        root_name,
        &section,
        &plan.owner_identity.verifying_key(),
    )
    .map_err(ProvisionError::Author)?;

    // Register-first, upload, CAS publish. The name has no durable sequence
    // floor, so the pipeline embeds sequence 1.
    let binding = HeadBinding {
        node_id: scope_id,
        scope_id,
        epoch: GENESIS_EPOCH,
    };
    let preflighted =
        preflight(&binding, read_key.as_bytes(), &head).map_err(ProvisionError::Preflight)?;
    let root_signer = SessionIdentity::write_name_signer(root.write_scope_seed, &scope_id);
    publisher
        .publish_root_record(root_name, &root_signer, &preflighted)
        .await
        .map_err(|error| ProvisionError::Publish {
            stage: "root-record",
            error,
        })
}

/// Draw the envelope's AEAD nonce, fail-closed.
///
/// An all-zero draw is refused for the reason
/// [`fresh_ephemeral`](crate::entropy::fresh_ephemeral) refuses one: a seam that
/// reports success having written nothing would seal this account's genesis root
/// under a fixed nonce, and it would be published before anything read it back.
fn fresh_nonce<E: Entropy>(entropy: &RefCell<E>) -> Result<[u8; NONCE_LEN], ProvisionError> {
    let mut nonce = [0u8; NONCE_LEN];
    entropy
        .borrow_mut()
        .fill(&mut nonce)
        .map_err(ProvisionError::Entropy)?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(ProvisionError::Entropy(EntropyError::new(
            "entropy seam produced an all-zero envelope nonce",
        )));
    }
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    use cipherbox_core::hex::lower as hex_lower;
    use cipherbox_core::seal::{
        decode_envelope, decode_grant_section, grant_section_bytes, open_read_body,
        verify_grant_set,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSignature;

    use crate::facade::LoginSecret;
    use crate::owner_keys::OwnerSessionKeys;
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

    /// The published state runs share: the record plane as far as this module
    /// can see it. A retry and a concurrent device both read one of these, which
    /// is what makes idempotence testable at all.
    #[derive(Default)]
    struct Network {
        /// Every root record published at the derived name, in order. More than
        /// one is the concurrent-mint case, not an error.
        root_records: RefCell<Vec<Vec<u8>>>,
        pointer_block: RefCell<Option<Vec<u8>>>,
        effects: RefCell<Vec<Effect>>,
    }

    impl Network {
        /// The head block of the first root record published here.
        fn first_root(&self) -> Vec<u8> {
            self.root_records
                .borrow()
                .first()
                .cloned()
                .expect("a root record was published")
        }

        fn root_effects(&self) -> usize {
            self.effects
                .borrow()
                .iter()
                .filter(|e| matches!(e, Effect::Root(_)))
                .count()
        }
    }

    /// What the pointer PUT does. `Unconfirmed` is the shape a same-sequence
    /// genesis race produces: an endpoint acked, the confirm did not — which no
    /// longer decides the mint.
    #[derive(Default, Clone)]
    enum PointerPublish {
        #[default]
        Lands,
        Refused(WritePublishError),
        UnconfirmedButLands(WritePublishError),
        /// Reports success, and the bytes are nowhere to be found afterwards.
        Swallowed,
    }

    /// A publisher over a shared [`Network`], optionally scripted to refuse a leg.
    struct FakePublisher<'a> {
        net: &'a Network,
        probe: Option<VaultPointerProbe>,
        refuse_root: Option<WritePublishError>,
        pointer: PointerPublish,
        /// The root probe answers from before this run's peer published —
        /// the interleaving where two devices both see a vacant name.
        blind_to_root: bool,
    }

    impl<'a> FakePublisher<'a> {
        fn new(net: &'a Network) -> Self {
            Self {
                net,
                probe: None,
                refuse_root: None,
                pointer: PointerPublish::Lands,
                blind_to_root: false,
            }
        }

        fn refusing_root(net: &'a Network, error: WritePublishError) -> Self {
            Self {
                refuse_root: Some(error),
                ..Self::new(net)
            }
        }

        fn publishing_pointer(net: &'a Network, pointer: PointerPublish) -> Self {
            Self {
                pointer,
                ..Self::new(net)
            }
        }

        fn probing(net: &'a Network, probe: VaultPointerProbe) -> Self {
            Self {
                probe: Some(probe),
                ..Self::new(net)
            }
        }

        fn blind_to_root(net: &'a Network) -> Self {
            Self {
                blind_to_root: true,
                ..Self::new(net)
            }
        }
    }

    impl VaultProvisionPublisher for FakePublisher<'_> {
        async fn genesis_root_step(&self, _name: &IpnsName) -> RootStep {
            if self.blind_to_root || self.net.root_records.borrow().is_empty() {
                RootStep::MustPublish
            } else {
                RootStep::AlreadyAdopted
            }
        }

        async fn fetch_vault_pointer(&self, _name: &IpnsName) -> Option<Vec<u8>> {
            self.net.pointer_block.borrow().clone()
        }

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
            if let Some(error) = self.refuse_root.clone() {
                return Err(error);
            }
            self.net
                .effects
                .borrow_mut()
                .push(Effect::Root(name.as_str().to_owned()));
            self.net
                .root_records
                .borrow_mut()
                .push(head.block().to_vec());
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
            let (verdict, lands) = match &self.pointer {
                PointerPublish::Lands => (Ok(()), true),
                PointerPublish::Refused(error) => (Err(error.clone()), false),
                PointerPublish::UnconfirmedButLands(error) => (Err(error.clone()), true),
                PointerPublish::Swallowed => (Ok(()), false),
            };
            if lands {
                self.net
                    .effects
                    .borrow_mut()
                    .push(Effect::Pointer(name.as_str().to_owned()));
                *self.net.pointer_block.borrow_mut() = Some(block.to_vec());
            }
            verdict
        }
    }

    /// Run `provision_vault` for `session` over `publisher` and `floors`.
    fn run(
        session: &SessionIdentity,
        publisher: &FakePublisher<'_>,
        floors: &InMemoryFloorStore,
        entropy_seed: u64,
    ) -> Result<ProvisionOutcome, ProvisionError> {
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
                genesis_read_scope_seed: &session.genesis_read_scope_seed(),
                genesis_write_scope_seed: &session.genesis_write_scope_seed(),
                created_at: 1_700_000_000_000,
            },
        ))
    }

    /// Run and take the minted vault, failing the test on any other outcome.
    fn mint(
        session: &SessionIdentity,
        publisher: &FakePublisher<'_>,
        floors: &InMemoryFloorStore,
        entropy_seed: u64,
    ) -> ProvisionedVault {
        match run(session, publisher, floors, entropy_seed).expect("provisioning succeeds") {
            ProvisionOutcome::Minted(vault) => *vault,
            ProvisionOutcome::MovedOn => panic!("expected a minted vault"),
        }
    }

    /// Mint over a fresh network, the common case.
    fn mint_fresh(session: &SessionIdentity, net: &Network, entropy_seed: u64) -> ProvisionedVault {
        mint(
            session,
            &FakePublisher::new(net),
            &InMemoryFloorStore::default(),
            entropy_seed,
        )
    }

    /// The grant-set commitment as it was published, read back out of the head
    /// block the network captured.
    fn published_commitment(net: &Network) -> cipherbox_core::seal::GrantSection {
        let envelope = decode_envelope(&net.first_root()).expect("a decodable head");
        decode_grant_section(grant_section_bytes(&envelope).expect("a scope-root marker"))
            .expect("a decodable grant section")
    }

    /// Open a published root record's read body under `read_scope_seed` — what a
    /// session holding that seed can do with the bytes, and nothing else can.
    fn open_root_body(head_block: &[u8], read_scope_seed: &[u8; SECRET_LEN]) -> ReadBody {
        let envelope = decode_envelope(head_block).expect("a decodable head");
        let read_key = kdf::read_key(kdf::node_seed(read_scope_seed, &SCOPE).as_bytes());
        open_read_body(&envelope, read_key.as_bytes()).expect("the derived read key opens it")
    }

    /// The one root name this account's derived write seed can name.
    fn derived_root_name(session: &SessionIdentity) -> IpnsName {
        derive_write_name(session.genesis_write_scope_seed().as_bytes(), &SCOPE)
    }

    /// Seal a re-point naming `current_root` under this owner's pointer read key
    /// — an authentic owner-signed pointer value, for the moved-on cases.
    fn foreign_repoint(session: &SessionIdentity, current_root: IpnsName) -> Vec<u8> {
        let mut entropy = SeededEntropy::new(99);
        seal_repoint(
            SessionRole::Owner,
            &mut entropy,
            &OwnerSessionKeys::new(session).pointer_read_key(&SCOPE),
            VERSION,
            session.identity(),
            &RepointObject {
                scope_id: SCOPE,
                current_root,
                write_epoch: 4,
                min_read_epoch: 4,
                prev_root: None,
            },
        )
        .expect("the owner seals its own re-point")
    }

    // -----------------------------------------------------------------------
    // ADR 0007's gate.
    // -----------------------------------------------------------------------

    /// **Gate item 1.** Two runs for one login secret, over independent entropy
    /// streams, produce the same root name and the same re-point — and each
    /// opens the record the other published. Asserted on the values, not on the
    /// derivation code.
    #[test]
    fn two_runs_over_independent_entropy_mint_one_vault() {
        let session = session();
        let (first_net, second_net) = (Network::default(), Network::default());
        let first = mint_fresh(&session, &first_net, 1);
        let second = mint_fresh(&session, &second_net, 999);

        assert_eq!(first.root_name, second.root_name, "one account, one root");
        assert_eq!(first.repoint, second.repoint, "and one re-point object");
        assert_eq!(*first.read_scope_seed, *second.read_scope_seed);
        assert_eq!(*first.write_scope_seed, *second.write_scope_seed);
        // The property that makes a crashed attempt's record recoverable rather
        // than orphaned: the other run's keys open it.
        assert_eq!(
            open_root_body(&second_net.first_root(), &first.read_scope_seed),
            open_root_body(&first_net.first_root(), &second.read_scope_seed),
            "each run's read key opens the other's published root",
        );
    }

    /// **Gate item 2.** A run interrupted after its root record lands, re-run:
    /// it publishes no second root record, uploads no second head block, and
    /// completes. Exactly one root name is registered for the account.
    #[test]
    fn a_retry_adopts_the_crashed_attempts_root_and_publishes_no_second_one() {
        let session = session();
        let net = Network::default();
        let floors = InMemoryFloorStore::default();

        // The crash: the root record lands, the pointer never does.
        let crashed = run(
            &session,
            &FakePublisher::publishing_pointer(
                &net,
                PointerPublish::Refused(WritePublishError::NotLanded),
            ),
            &floors,
            1,
        )
        .expect_err("a mint whose pointer never landed is not a provisioned vault");
        assert!(crashed.is_retryable(), "{crashed}");
        assert_eq!(net.root_effects(), 1, "the root record did land");

        let retried = mint(&session, &FakePublisher::new(&net), &floors, 2);
        assert_eq!(
            net.root_effects(),
            1,
            "the retry adopts the crashed attempt's root instead of publishing a second",
        );
        assert_eq!(
            net.root_records.borrow().len(),
            1,
            "and uploads no second head block",
        );
        assert_eq!(
            retried.root_name,
            derived_root_name(&session),
            "at the one derived name",
        );
    }

    /// **Gate item 3.** Two concurrent runs against one account both complete.
    /// One root name and one pointer name exist, and each device's session opens
    /// the record the other published — the both-`Published` interleaving, where
    /// no device is told anything went wrong, not only the `Unconfirmed` one.
    #[test]
    fn two_concurrent_runs_converge_on_one_vault() {
        let session = session();
        let net = Network::default();
        let first = mint(
            &session,
            &FakePublisher::new(&net),
            &InMemoryFloorStore::default(),
            1,
        );
        // The peer's root probe ran before the first device's record landed, so
        // it publishes too: two records, one name, both openable by both.
        let second = mint(
            &session,
            &FakePublisher::blind_to_root(&net),
            &InMemoryFloorStore::default(),
            2,
        );

        assert_eq!(first.root_name, second.root_name);
        assert_eq!(first.repoint, second.repoint);
        let records = net.root_records.borrow().clone();
        assert_eq!(records.len(), 2, "the interleaving under test");
        for record in &records {
            assert_eq!(
                open_root_body(record, &first.read_scope_seed),
                open_root_body(record, &second.read_scope_seed),
                "both devices open both records",
            );
        }
        let pointers: Vec<_> = net
            .effects
            .borrow()
            .iter()
            .filter_map(|e| match e {
                Effect::Pointer(name) => Some(name.clone()),
                Effect::Root(_) => None,
            })
            .collect();
        assert_eq!(
            pointers
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            1,
            "one pointer name",
        );
    }

    /// **Gate item 4, first half.** A pointer publish that comes back
    /// unconfirmed, at a name that nonetheless serves a re-point naming the
    /// derived root, completes the mint — the verdict does not decide it, the
    /// re-point does.
    #[test]
    fn an_unconfirmed_pointer_publish_that_serves_its_repoint_completes_the_mint() {
        for error in [WritePublishError::NotLanded, WritePublishError::LostRace] {
            let session = session();
            let net = Network::default();
            let vault = mint(
                &session,
                &FakePublisher::publishing_pointer(
                    &net,
                    PointerPublish::UnconfirmedButLands(error.clone()),
                ),
                &InMemoryFloorStore::default(),
                3,
            );
            assert_eq!(vault.root_name, derived_root_name(&session), "{error:?}");
        }
    }

    /// **Gate item 4, second half.** One that serves nothing resolvable fails
    /// retryable and deposits nothing — distinct, asserted outcomes.
    #[test]
    fn a_pointer_that_serves_nothing_is_indeterminate_and_retryable() {
        let session = session();
        let net = Network::default();
        let err = run(
            &session,
            &FakePublisher::publishing_pointer(&net, PointerPublish::Swallowed),
            &InMemoryFloorStore::default(),
            4,
        )
        .expect_err("an unresolvable pointer is not a provisioned vault");
        assert_eq!(err, ProvisionError::PointerUnresolved);
        assert!(
            err.is_retryable(),
            "indeterminate is availability, not a verdict"
        );
    }

    /// **Gate item 5.** A re-point naming a root this mint did not derive stops
    /// the mint and hands the caller back to cold start, with no record
    /// published after the point of discovery.
    #[test]
    fn a_foreign_repoint_stops_the_mint() {
        let session = session();
        let net = Network::default();
        let moved_on = foreign_repoint(&session, derive_write_name(&[9u8; 32], &SCOPE));
        *net.pointer_block.borrow_mut() = Some(moved_on.clone());

        let outcome = run(
            &session,
            &FakePublisher::publishing_pointer(
                &net,
                PointerPublish::Refused(WritePublishError::LostRace),
            ),
            &InMemoryFloorStore::default(),
            5,
        )
        .expect("a moved-on account is not a mint failure");
        assert!(matches!(outcome, ProvisionOutcome::MovedOn), "{outcome:?}");
        assert_eq!(
            *net.pointer_block.borrow(),
            Some(moved_on),
            "nothing of this run's was published over the account's own pointer",
        );
    }

    /// The other end of gate item 5: a block at this account's own pointer name
    /// that its own key will not open is a trust violation, fail-closed and
    /// never retried into a second mint.
    #[test]
    fn a_repoint_this_owner_cannot_open_is_fail_closed() {
        let session = session();
        let net = Network::default();
        *net.pointer_block.borrow_mut() = Some(b"not a sealed re-point".to_vec());

        let err = run(
            &session,
            &FakePublisher::publishing_pointer(
                &net,
                PointerPublish::Refused(WritePublishError::LostRace),
            ),
            &InMemoryFloorStore::default(),
            6,
        )
        .expect_err("unopenable bytes at our own pointer name are never a mint");
        assert!(matches!(err, ProvisionError::RepointUnopenable(_)), "{err}");
        assert!(!err.is_retryable(), "a retry reaches the same bytes");
    }

    /// **Gate item 6, engine side.** Both genesis seeds are the catalog
    /// derivation over this account's login secret, not a draw — asserted on the
    /// values, so swapping the edge or reinstating the draw fails here.
    #[test]
    fn both_genesis_seeds_are_the_catalog_derivation() {
        let session = session();
        let vault = mint_fresh(&session, &Network::default(), 10);
        assert_eq!(
            vault.read_scope_seed.as_slice(),
            kdf::genesis_read_scope_seed(&SECRET).as_bytes(),
        );
        assert_eq!(
            vault.write_scope_seed.as_slice(),
            kdf::genesis_write_scope_seed(&SECRET).as_bytes(),
        );
        assert_ne!(*vault.read_scope_seed, *vault.write_scope_seed);
        assert_ne!(*vault.write_scope_seed, SECRET);
    }

    // -----------------------------------------------------------------------
    // The invariants the provisioning slice already carried.
    // -----------------------------------------------------------------------

    /// **The join.** The pseudonym provisioning commits, epoch-free and for ever,
    /// must be the one the production `OwnerScopeKeys` arm derives — the key every
    /// later re-seal detach-signs under and the gate checks against the
    /// commitment. The two halves are written in different modules and nothing
    /// else compares them; a mismatch is a permanent `SignerNotCommitted` on every
    /// rotation, surfacing only at the first one.
    #[test]
    fn the_committed_pseudonym_is_the_one_the_owner_arm_derives() {
        let session = session();
        let net = Network::default();
        mint_fresh(&session, &net, 1);

        let committed = published_commitment(&net).commitment.owner_pseudonym_pk;
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
        let net = Network::default();
        mint_fresh(&session, &net, 2);
        let committed = published_commitment(&net).commitment.owner_pseudonym_pk;

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
        let net = Network::default();
        let vault = mint_fresh(&session, &net, 3);

        let section = published_commitment(&net);
        assert_eq!(
            section.commitment.ipns_name,
            vault.root_name.as_str().as_bytes(),
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
        let net = Network::default();
        let vault = mint_fresh(&session, &net, 4);

        let block = net
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
        assert_eq!(repoint.current_root, vault.root_name);
        assert_eq!(
            repoint.prev_root, None,
            "a genesis re-point has no predecessor"
        );
        assert_eq!(repoint.write_epoch, GENESIS_EPOCH);
        assert_eq!(repoint.min_read_epoch, GENESIS_EPOCH);
        // The name the pointer carries is the one the returned write seed derives,
        // or the drain would publish every node under keys nothing can verify.
        assert_eq!(
            derive_write_name(&vault.write_scope_seed, &SCOPE),
            vault.root_name,
        );
    }

    /// The pointer is the only entry point, so it must never land before the
    /// record it names.
    #[test]
    fn the_root_record_is_published_before_the_pointer() {
        let session = session();
        let net = Network::default();
        let vault = mint_fresh(&session, &net, 5);
        assert_eq!(
            *net.effects.borrow(),
            vec![
                Effect::Root(vault.root_name.as_str().to_owned()),
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
        let net = Network::default();
        let err = run(
            &session,
            &FakePublisher::refusing_root(&net, WritePublishError::NotLanded),
            &InMemoryFloorStore::default(),
            6,
        )
        .expect_err("a root that did not land is not a provisioned vault");
        assert!(matches!(err, ProvisionError::Publish { .. }), "{err}");
        assert!(
            net.effects.borrow().is_empty(),
            "nothing is published once the root refused",
        );
    }

    /// The mint's precondition. `Engine::start` reaches provisioning on any
    /// pointer walk that yielded nothing, and an unreachable record plane yields
    /// nothing too — so an indeterminate probe must refuse rather than mint a
    /// second genesis vault over a live account's one pointer name.
    #[test]
    fn an_indeterminate_pointer_probe_mints_nothing() {
        let session = session();
        let floors = InMemoryFloorStore::default();
        let net = Network::default();
        let err = run(
            &session,
            &FakePublisher::probing(&net, VaultPointerProbe::Indeterminate),
            &floors,
            20,
        )
        .expect_err("a failed read is not evidence of a new account");
        assert_eq!(
            err,
            ProvisionError::NotAFirstRun(VaultPointerProbe::Indeterminate)
        );
        assert!(
            err.is_retryable(),
            "an outage is availability, not a verdict"
        );
        assert!(net.effects.borrow().is_empty(), "nothing published");
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
        let net = Network::default();
        let err = run(
            &session,
            &FakePublisher::probing(&net, VaultPointerProbe::AlreadyPublished),
            &InMemoryFloorStore::default(),
            21,
        )
        .expect_err("a published vault is not a first run");
        assert_eq!(
            err,
            ProvisionError::NotAFirstRun(VaultPointerProbe::AlreadyPublished)
        );
        assert!(!err.is_retryable(), "re-running reaches the same refusal");
        assert!(net.effects.borrow().is_empty(), "nothing published");
    }

    /// Rule 6 on the axis the host sees: `Event::VaultUnprovisioned` carries this
    /// flag, and it is the only thing telling a host whether trying again can
    /// help. A refusal reported as retryable spins forever; a stall reported as
    /// a refusal strands an account that one reconnect would have provisioned.
    #[test]
    fn only_stalls_are_reported_retryable() {
        for refusal in [
            ProvisionError::NotAFirstRun(VaultPointerProbe::AlreadyPublished),
            ProvisionError::FloorRegression(FloorRegression::WriteEpoch {
                floor: 9,
                vouched: GENESIS_EPOCH,
            }),
            ProvisionError::Publish {
                stage: "root-record",
                error: WritePublishError::Rejected,
            },
            ProvisionError::RepointUnopenable(PointerError::NotOwnerSession),
        ] {
            assert!(
                !refusal.is_retryable(),
                "{refusal} is reached again by a retry"
            );
        }
        for stall in [
            ProvisionError::NotAFirstRun(VaultPointerProbe::Indeterminate),
            ProvisionError::Publish {
                stage: "vault-pointer",
                error: WritePublishError::NotLanded,
            },
            ProvisionError::Entropy(EntropyError::new("seam down")),
            ProvisionError::PointerUnresolved,
        ] {
            assert!(stall.is_retryable(), "{stall} is an outage, not a verdict");
        }
    }

    /// A seam that reports success having written nothing would seal the genesis
    /// root under a fixed nonce, published before anything read it back.
    #[test]
    fn a_silent_entropy_seam_mints_nothing() {
        struct Silent;
        impl Entropy for Silent {
            fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
                Ok(())
            }
        }
        let session = session();
        let net = Network::default();
        let publisher = FakePublisher::new(&net);
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
                genesis_read_scope_seed: &session.genesis_read_scope_seed(),
                genesis_write_scope_seed: &session.genesis_write_scope_seed(),
                created_at: 0,
            },
        ))
        .expect_err("a fixed-nonce genesis root is never published");
        assert!(
            matches!(err, ProvisionError::Entropy(_) | ProvisionError::Reseal(_)),
            "{err}"
        );
        assert!(net.effects.borrow().is_empty(), "nothing published");
    }

    /// The floors the genesis re-point vouches are durable before anything is
    /// published: the session's own adopts open the owner-write blob at the write
    /// floor, and without it the root is held keyless.
    #[test]
    fn the_genesis_floors_are_seeded() {
        let session = session();
        let floors = InMemoryFloorStore::default();
        let net = Network::default();
        mint(&session, &FakePublisher::new(&net), &floors, 8);
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
        let net = Network::default();
        let err =
            run(&session, &FakePublisher::new(&net), &floors, 9).expect_err("not a first run");
        assert_eq!(
            err,
            ProvisionError::FloorRegression(FloorRegression::WriteEpoch {
                floor: 9,
                vouched: GENESIS_EPOCH,
            }),
        );
        assert!(net.effects.borrow().is_empty(), "nothing published");
    }

    /// Key material never reaches a log site, including a test-assertion `{:?}`.
    #[test]
    fn debug_redacts_both_seeds() {
        let session = session();
        let vault = mint_fresh(&session, &Network::default(), 12);
        let rendered = format!("{vault:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&hex_lower(vault.write_scope_seed.as_slice())));
        assert!(!rendered.contains(&hex_lower(vault.read_scope_seed.as_slice())));
    }
}
