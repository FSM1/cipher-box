//! `rotateScopeWrite` — the owner-only write-plane rotation (blueprint/engine.md
//! "Rotation primitives: rotateScopeWrite", #26 D3, #38 D3, #34 D4).
//!
//! The third rotation primitive: where [`rotate_scope`](super::rotate::rotate_scope)
//! cuts the read plane and [`cascade`](super::cascade) re-keys descendant read
//! scopes, this cuts the **write** plane — a fresh write override seed, a bumped
//! `writeEpoch`, and a background child-first name wave.
//!
//! # What changes (and what does not)
//!
//! `ipnsName`, the IPNS signing keypair, and `writeKey` all derive from
//! `writeSeed(node) = KDF(writeScopeSeed, node.id)` (CONTEXT.md "Write seed"), so a
//! fresh write scope seed moves every node to a fresh name under a fresh signing
//! key. The read plane is untouched — override seeds, read keys, and `minReadEpoch`
//! carry verbatim, and no rotation path re-encrypts content bytes (#26 D6).
//!
//! # Ordering is the safety property (#34 D4)
//!
//! A new name is **registered before** its predecessor is retired, old names stay
//! live until the pointer flips, and the pointer flips last — so at every instant
//! a resolver reaches every node by at least one live name. Interior old names
//! batch-retire only **after** the root re-point; the old root name lingers past
//! the migration window.
//!
//! # Three-channel re-point (#38 D3)
//!
//! The owner-identity-signed re-point object publishes to the scope pointer record
//! (canonical), the mailbox, and the old root name's tombstone (feeding the
//! depth-guarded `movedTo` chase). `writeEpoch` advances here; `minReadEpoch` is
//! carried unchanged, so each plane's clock stays authored by its owning authority
//! (#38 D1).
//!
//! # Crash recovery from published records only (#26 D8)
//!
//! No cross-crash state: a resumed wave re-derives each node's deterministic new
//! name and skips already-republished nodes via
//! [`WriteWavePublisher::is_republished`]; every effect is idempotent, so it
//! converges to the same terminal state. The fresh write scope seed is recovered
//! from the published root — deferred #745/#746 wiring, faked here via
//! [`RotateScopeWritePlan::resume_write_scope_seed`]. Accepted limitation: a crash
//! after the pointer flip but before interior retirement orphans the prior run's
//! interior old names — the fail-safe direction (leaking a registration beats
//! retiring a live name); reclaim is tracked in #764.
//!
//! # Owner-only, fail-closed, deterministic
//!
//! The caller must present the owner identity signer that authored the current
//! grant-set commitment, and that commitment must name this scope's current root
//! ([`WriteRotateError::NotOwner`], [`WriteRotateError::CommitmentScopeMismatch`]).
//! [`build_repoint_object`]'s two encode-side invariants are release-active, never
//! a `debug_assert!` (AGENTS.md rule 8). Entropy enters only through the
//! [`Entropy`] seam; the impure edges are the injected [`WriteSubtreeResolver`] and
//! [`WriteWavePublisher`] (network wiring is #745/#746, faked in this slice).

use std::collections::{BTreeSet, VecDeque};

use zeroize::Zeroizing;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::seal::{GrantSetCommitment, verify_grant_set};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaSigner, SIGNATURE_LEN as ECDSA_SIG_LEN};
use cipherbox_core::suite::secret::SECRET_LEN;

use super::eager_set::ResolveFailure;
use crate::entropy::{Entropy, EntropyError};
use crate::hex::hex_lower;
use crate::sync::pointer::{PointerError, SessionRole, seal_repoint};

/// One node of the write scope's subtree, resolved from its **current** published
/// record — its id, the name it currently sits at, and its child node ids. The
/// wave descends `child_node_ids` to enumerate the subtree and re-points each node
/// to a freshly derived name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteScopeNode {
    /// The node id (16-byte UUID). The root node's id equals the scope id.
    pub node_id: [u8; 16],
    /// The node's current (old-epoch) `ipnsName` — retired at completion (an
    /// interior node) or left to linger (the root).
    pub current_name: IpnsName,
    /// The node's direct children within this write scope.
    pub child_node_ids: Vec<[u8; 16]>,
}

/// The three re-point channels the wave publishes to (#38 D3). The scope pointer
/// is canonical; the mailbox and the old-root tombstone are verifiable
/// accelerators — nothing on them is load-bearing for safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepointChannel {
    /// The stable scope pointer record — the canonical re-point.
    ScopePointer,
    /// The recipient mailbox — an accelerator for surviving grantees.
    Mailbox,
    /// The old root name's final tombstone — an accelerator for the `movedTo`
    /// chase.
    Tombstone,
}

/// The three channels in canonical publish order: pointer first (the authoritative
/// switch), then the two accelerators.
const REPOINT_CHANNELS: [RepointChannel; 3] = [
    RepointChannel::ScopePointer,
    RepointChannel::Mailbox,
    RepointChannel::Tombstone,
];

/// One node re-published at its freshly derived name — the record the publisher
/// CAS-installs. Assembling the record bytes (read-body carried verbatim, write-
/// body re-sealed at the new write epoch for the root) and IPNS-signing them under
/// the node's fresh write keypair is the deferred #745/#746 wiring; this slice
/// fakes the publish and carries only the routing identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepublishedNode {
    /// The node id being republished.
    pub node_id: [u8; 16],
    /// The freshly derived `ipnsName` the record is published at.
    pub new_name: IpnsName,
    /// The write epoch the record publishes at (bumped for the whole scope).
    pub write_epoch: u64,
    /// Whether this is the scope root (re-pointed last, old name lingers).
    pub is_root: bool,
}

/// Resolve the write scope's subtree from published records — the read edge, the
/// analogue of the cascade's `CascadeResealResolver`. Resolve + adoption-gate +
/// unseal live behind this trait; the real network/gate wiring is #745/#746 and
/// tests fake it. A resolve either yields the node or a fail-closed
/// [`ResolveFailure`].
pub trait WriteSubtreeResolver {
    /// Resolve `node_id`'s current write-plane node (its name + children), or a
    /// fail-closed [`ResolveFailure`] if its record cannot be authoritatively
    /// obtained.
    async fn resolve_node(&self, node_id: &[u8; 16]) -> Result<WriteScopeNode, ResolveFailure>;
}

/// The write edge of the name wave: register-first name enrollment, CAS republish,
/// batch retire, and the three-channel re-point — the analogue of the cascade's
/// `ScopeRootPublisher`, mapping to the API pin/name registry and `/routing/v1`
/// transport. Real wiring is #745/#746; tests fake it.
///
/// Contract the orchestrator relies on and the fake honours:
///
/// - **register / retire are idempotent** — a resumed wave re-registers and
///   re-retires the same names harmlessly.
/// - **`is_republished` reads published state only** — it is how a resumed wave
///   skips already-done nodes without any in-memory checkpoint.
pub trait WriteWavePublisher {
    /// Register-first: enroll `new_name` in the name registry (idempotent). MUST
    /// precede retiring the predecessor it replaces — never orphan a name.
    async fn register(&self, new_name: &IpnsName) -> Result<(), WritePublishError>;

    /// Whether a record is already published at `new_name` — the resume query,
    /// answered from published state only (no in-memory carry across a crash).
    async fn is_republished(&self, new_name: &IpnsName) -> Result<bool, WritePublishError>;

    /// CAS-publish `node`'s record at its freshly derived name.
    async fn republish(&self, node: &RepublishedNode) -> Result<(), WritePublishError>;

    /// Batch-retire interior old names at wave completion. MUST run only **after**
    /// the root re-point, and MUST NOT include the old root name (it lingers).
    async fn retire(&self, old_names: &[IpnsName]) -> Result<(), WritePublishError>;

    /// Publish the owner-signed re-point `block` on one of the three channels.
    async fn publish_repoint(
        &self,
        channel: RepointChannel,
        block: &[u8],
    ) -> Result<(), WritePublishError>;
}

/// Why one write-plane transport op did not durably land. All variants mean the
/// wave must abort — it never claims completion on a dropped effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WritePublishError {
    /// The register / PUT did not land; nothing durable. Retryable.
    NotLanded,
    /// A concurrent writer won the CAS race at this name. The wave re-resolves and
    /// retries.
    LostRace,
    /// Register-first was rejected by the name registry (quota). Retryable once
    /// capacity frees.
    RegistryFull,
}

impl core::fmt::Display for WritePublishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WritePublishError::NotLanded => f.write_str("write-plane record did not land"),
            WritePublishError::LostRace => f.write_str("write-plane publish lost the CAS race"),
            WritePublishError::RegistryFull => f.write_str("name registry rejected register-first"),
        }
    }
}

impl std::error::Error for WritePublishError {}

/// The inputs to one write scope's rotation.
pub struct RotateScopeWritePlan<'a> {
    /// The scope id (== the write scope root's node id).
    pub scope_id: [u8; 16],
    /// The pointer-payload envelope version.
    pub payload_version: u64,
    /// The owner's stable pointer seed — derives the scope's `pointerReadKey` the
    /// re-point object seals under.
    pub owner_pointer_seed: &'a [u8; SECRET_LEN],
    /// The owner-signed, epoch-free grant-set commitment — the owner-only anchor.
    pub commitment: &'a GrantSetCommitment,
    /// The current 64-byte compact ECDSA owner signature over `commitment`.
    pub commitment_sig: &'a [u8; ECDSA_SIG_LEN],
    /// The owner identity signer — MUST be the identity that signed `commitment`
    /// (owner-only gate), and signs the re-point object.
    pub owner_identity_signer: &'a EcdsaSigner,
    /// The scope's current write epoch — the rotation publishes at `+ 1`.
    pub current_write_epoch: u64,
    /// The owner-vouched `minReadEpoch`, carried unchanged (read plane untouched).
    pub min_read_epoch: u64,
    /// The scope root's current `ipnsName` — becomes `prevRootName` and lingers.
    pub current_root_name: &'a IpnsName,
    /// On a **resumed** wave, the fresh write scope seed recovered from the
    /// published root (the write-plane history link); `None` on a fresh rotation,
    /// which mints one via the entropy seam. Recovery wiring is deferred to
    /// #745/#746 (faked in tests); the seam boundary is
    /// [`Entropy`]-vs-published-record, never in-memory carry.
    pub resume_write_scope_seed: Option<&'a [u8; SECRET_LEN]>,
}

/// A completed write rotation. Holding one is proof the whole subtree was
/// republished, the root re-pointed on all three channels, and interior old names
/// retired — an incomplete wave returns [`WriteRotateError`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRotationOutcome {
    /// The new write epoch the scope was cut to (`current_write_epoch + 1`).
    pub new_write_epoch: u64,
    /// The scope root's new `ipnsName` (`currentRootName` in the re-point object).
    pub new_root_name: IpnsName,
    /// The number of interior (non-root) nodes in the scope's subtree — the wave
    /// covers all of them, though a resumed wave may have republished some in a
    /// prior run (skipped via `is_republished`), and a post-flip-crash resume
    /// retires none of them (see the crash-recovery module docs).
    pub interior_node_count: usize,
}

/// A fail-closed write-rotation failure. Every variant leaves the rotation
/// resumable: the wave is idempotent and re-runs converge (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteRotateError {
    /// The presented owner signer did not author the current commitment — not the
    /// owner. Owner-only, fail-closed before anything is minted or published.
    NotOwner,
    /// The owner-authentic commitment names a different scope than the one under
    /// rotation (`commitment.ipns_name != current_root_name`). Binds the owner-auth
    /// token to the exact rotated scope, the same binding the adoption gate enforces
    /// (`gate/adoption.rs`) — so a valid owner signature over another scope's
    /// commitment cannot authorize this rotation. Fail-closed before any mint.
    CommitmentScopeMismatch,
    /// The write epoch is exhausted (`current_write_epoch == u64::MAX`). Rotating
    /// would reuse the epoch with fresh key material (a key-regression violation),
    /// so nothing is minted. Unreachable in practice; release-active.
    EpochExhausted,
    /// The re-point object does not advance the write epoch past its predecessor —
    /// the encode-side mirror of the floor law's monotonic write-epoch reject.
    /// Release-active (never a `debug_assert!`), so a release build never publishes
    /// a re-point the adoption floor rejects as non-advancing.
    WriteEpochNotAdvancing,
    /// The re-point object re-points the scope to its own predecessor name (a no-op
    /// the consult would adopt as "no progress", masking the rotation). Rejected
    /// release-active before publish.
    IdentityRepoint,
    /// Minting the fresh write scope seed failed (entropy seam). Retryable.
    Entropy(EntropyError),
    /// A subtree node could not be authoritatively resolved (gate rejection or host
    /// unavailability), so the wave is not provably complete.
    Resolve {
        /// The node that could not be resolved.
        node_id: [u8; 16],
        /// Why the resolve failed.
        reason: ResolveFailure,
    },
    /// A write-plane transport op did not land. Names the stage so a retry knows
    /// where the wave stopped (it re-derives and resumes from published state).
    Publish {
        /// The wave stage that failed (`register` / `republish` / `retire` /
        /// `repoint-<channel>`).
        stage: &'static str,
        /// The offending node id, or the scope id for the retire/re-point stages.
        node_id: [u8; 16],
        /// The underlying transport failure.
        error: WritePublishError,
    },
    /// Sealing the owner-signed re-point object failed (entropy or the owner-plane
    /// write gate). Surfaced verbatim from the pointer path.
    Repoint(PointerError),
}

impl core::fmt::Display for WriteRotateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WriteRotateError::NotOwner => {
                f.write_str("presented signer did not author the current commitment (not owner)")
            }
            WriteRotateError::CommitmentScopeMismatch => {
                f.write_str("commitment names a different scope than the one under rotation")
            }
            WriteRotateError::EpochExhausted => f.write_str("write epoch exhausted (u64::MAX)"),
            WriteRotateError::WriteEpochNotAdvancing => {
                f.write_str("re-point write epoch does not advance past its predecessor")
            }
            WriteRotateError::IdentityRepoint => {
                f.write_str("re-point points the scope to its own predecessor name")
            }
            WriteRotateError::Entropy(e) => write!(f, "write-seed entropy error: {e}"),
            WriteRotateError::Resolve { node_id, reason } => write!(
                f,
                "subtree resolve of node [{}] failed: {reason}",
                hex_lower(node_id)
            ),
            WriteRotateError::Publish {
                stage,
                node_id,
                error,
            } => write!(
                f,
                "{stage} of node [{}] failed: {error}",
                hex_lower(node_id)
            ),
            WriteRotateError::Repoint(e) => write!(f, "re-point seal failed: {e:?}"),
        }
    }
}

impl std::error::Error for WriteRotateError {}

impl WriteRotateError {
    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            WriteRotateError::NotOwner => "not-owner",
            WriteRotateError::CommitmentScopeMismatch => "commitment-scope-mismatch",
            WriteRotateError::EpochExhausted => "epoch-exhausted",
            WriteRotateError::WriteEpochNotAdvancing => "write-epoch-not-advancing",
            WriteRotateError::IdentityRepoint => "identity-repoint",
            WriteRotateError::Entropy(_) => "entropy-error",
            WriteRotateError::Resolve { .. } => "resolve-failed",
            WriteRotateError::Publish { .. } => "publish-failed",
            WriteRotateError::Repoint(_) => "repoint-seal-failed",
        }
    }

    /// Whether re-running the wave could clear this failure — an availability
    /// stall — versus an owner/trust violation no retry can fix.
    pub fn is_retryable(&self) -> bool {
        match self {
            WriteRotateError::NotOwner
            | WriteRotateError::CommitmentScopeMismatch
            | WriteRotateError::EpochExhausted
            | WriteRotateError::WriteEpochNotAdvancing
            | WriteRotateError::IdentityRepoint => false,
            WriteRotateError::Entropy(_) | WriteRotateError::Publish { .. } => true,
            WriteRotateError::Resolve { reason, .. } => *reason == ResolveFailure::Unavailable,
            WriteRotateError::Repoint(e) => matches!(e, PointerError::Entropy(_)),
        }
    }
}

/// A node's freshly derived write-plane `ipnsName` under `write_scope_seed`:
/// `ipnsName = IpnsName(ipnsKeypair(writeSeed(write_scope_seed, node_id)))`
/// (CONTEXT.md "Write seed"). Pure and deterministic — the reason a surviving
/// write-grantee derives every new name locally with zero re-discovery.
pub fn derive_write_name(write_scope_seed: &[u8; SECRET_LEN], node_id: &[u8; 16]) -> IpnsName {
    let write_seed = kdf::write_seed(write_scope_seed, node_id);
    IpnsName::from_public_key(&kdf::ipns_keypair(write_seed.as_bytes()).verifying_key())
}

/// Assemble the re-point object, enforcing release-active (never a
/// `debug_assert!`, AGENTS.md rule 8) that `new_write_epoch` advances past
/// `prev_write_epoch` ([`WriteRotateError::WriteEpochNotAdvancing`]) and that
/// `new_root` differs from `prev_root` ([`WriteRotateError::IdentityRepoint`]).
/// The read plane is untouched, so `min_read_epoch` is carried verbatim.
pub fn build_repoint_object(
    scope_id: [u8; 16],
    new_root: IpnsName,
    prev_root: IpnsName,
    new_write_epoch: u64,
    prev_write_epoch: u64,
    min_read_epoch: u64,
) -> Result<RepointObject, WriteRotateError> {
    if new_write_epoch <= prev_write_epoch {
        return Err(WriteRotateError::WriteEpochNotAdvancing);
    }
    if new_root == prev_root {
        return Err(WriteRotateError::IdentityRepoint);
    }
    Ok(RepointObject {
        scope_id,
        current_root: new_root,
        write_epoch: new_write_epoch,
        min_read_epoch,
        prev_root: Some(prev_root),
    })
}

/// Perform the owner-only write-plane rotation for the scope in `plan`.
///
/// Owner-checks the caller, mints (or resumes with) the fresh write scope seed,
/// bumps `writeEpoch`, then runs the child-first name wave: descendants
/// register-first + republish at their freshly derived names, the root **last**,
/// then the owner-signed re-point publishes to all three channels, and finally the
/// interior old names batch-retire (the old root lingers). Every effect is
/// idempotent, so a crashed wave re-runs to the same terminal state (module docs).
pub async fn rotate_scope_write<E, R, P>(
    entropy: &mut E,
    resolver: &R,
    publisher: &P,
    plan: &RotateScopeWritePlan<'_>,
) -> Result<WriteRotationOutcome, WriteRotateError>
where
    E: Entropy,
    R: WriteSubtreeResolver,
    P: WriteWavePublisher,
{
    let scope_id = plan.scope_id;

    // 1) Owner-only, fail-closed BEFORE anything is minted or published. The
    //    current commitment is owner-authentic (it passed the gate to resolve), so
    //    binding the presented signer to it anchors the rotation to the owner
    //    identity — the same gate the read-revoke trigger enforces.
    let current_sig =
        EcdsaSignature::from_compact(plan.commitment_sig).ok_or(WriteRotateError::NotOwner)?;
    verify_grant_set(
        &plan.owner_identity_signer.verifying_key(),
        plan.commitment,
        &current_sig,
    )
    .map_err(|_| WriteRotateError::NotOwner)?;

    // 1a) bind commitment to the rotated scope — see CommitmentScopeMismatch
    if plan.commitment.ipns_name != plan.current_root_name.as_str().as_bytes() {
        return Err(WriteRotateError::CommitmentScopeMismatch);
    }

    // 2) Fail-closed BEFORE minting: a saturating bump at u64::MAX would republish
    //    fresh key material under the same write epoch (a key-regression violation),
    //    so an exhausted epoch is rejected. Release-active per AGENTS.md rule 8.
    let new_write_epoch = plan
        .current_write_epoch
        .checked_add(1)
        .ok_or(WriteRotateError::EpochExhausted)?;

    // 3) The fresh write override seed — RANDOM via the entropy seam (never KDF-
    //    derived), or the seed a resumed wave recovered from the published root.
    //    `Zeroizing` wipes it on every return path, including a panic unwind; this
    //    orchestrator is its terminal owner.
    let write_scope_seed: Zeroizing<[u8; SECRET_LEN]> = match plan.resume_write_scope_seed {
        Some(seed) => Zeroizing::new(*seed),
        None => {
            let mut seed = Zeroizing::new([0u8; SECRET_LEN]);
            entropy
                .fill(seed.as_mut())
                .map_err(WriteRotateError::Entropy)?;
            seed
        }
    };

    // 4) Enumerate the subtree from published records. BFS yields the root first,
    //    then level order; the wave processes descendants child-first (reversed) and
    //    the root last.
    let bfs = collect_subtree(resolver, scope_id).await?;
    let (root, descendants) = bfs
        .split_first()
        .expect("collect_subtree always yields at least the root");

    // 5) Child-first wave over the descendants (deepest first): register-first, then
    //    republish unless already done (resume skips it via published state).
    let mut interior_old_names: Vec<IpnsName> = Vec::with_capacity(descendants.len());
    for node in descendants.iter().rev() {
        let new_name = derive_write_name(&write_scope_seed, &node.node_id);
        republish_node(publisher, node.node_id, &new_name, new_write_epoch, false).await?;
        // Retire only a superseded name, never one a node still lives at: on a
        // post-flip resume the resolver reports the already-migrated (new) name as
        // current, and retiring it would orphan a live descendant (never orphan).
        if node.current_name != new_name {
            interior_old_names.push(node.current_name.clone());
        }
    }

    // 6) Root LAST: republish the root at its new name. The old root name is NOT
    //    retired — it lingers past the migration window (#34 D4).
    let new_root_name = derive_write_name(&write_scope_seed, &root.node_id);
    republish_node(
        publisher,
        root.node_id,
        &new_root_name,
        new_write_epoch,
        true,
    )
    .await?;

    // 7) Three-channel re-point: seal the owner-signed re-point object and publish
    //    it in `REPOINT_CHANNELS` order.
    let repoint = build_repoint_object(
        scope_id,
        new_root_name.clone(),
        plan.current_root_name.clone(),
        new_write_epoch,
        plan.current_write_epoch,
        plan.min_read_epoch,
    )?;
    let pointer_read_key = kdf::pointer_read_key(plan.owner_pointer_seed, &scope_id);
    let block = seal_repoint(
        SessionRole::Owner,
        entropy,
        pointer_read_key.as_bytes(),
        plan.payload_version,
        plan.owner_identity_signer,
        &repoint,
    )
    .map_err(WriteRotateError::Repoint)?;
    for channel in REPOINT_CHANNELS {
        publisher
            .publish_repoint(channel, &block)
            .await
            .map_err(|error| WriteRotateError::Publish {
                stage: repoint_stage(channel),
                node_id: scope_id,
                error,
            })?;
    }

    // 8) Batch-retire the interior old names — only now, after the re-point flipped
    //    the pointer. The old root name is absent (it lingers).
    if !interior_old_names.is_empty() {
        publisher
            .retire(&interior_old_names)
            .await
            .map_err(|error| WriteRotateError::Publish {
                stage: "retire",
                node_id: scope_id,
                error,
            })?;
    }

    Ok(WriteRotationOutcome {
        new_write_epoch,
        new_root_name,
        interior_node_count: descendants.len(),
    })
}

/// Register-first then CAS-republish one node at `new_name`, skipping the
/// republish when published state already carries it (the resume idempotence).
async fn republish_node<P: WriteWavePublisher>(
    publisher: &P,
    node_id: [u8; 16],
    new_name: &IpnsName,
    write_epoch: u64,
    is_root: bool,
) -> Result<(), WriteRotateError> {
    // Register-first: enroll the new name BEFORE its predecessor is ever retired.
    publisher
        .register(new_name)
        .await
        .map_err(|error| WriteRotateError::Publish {
            stage: "register",
            node_id,
            error,
        })?;

    // Resume: skip a node whose new-name record already landed on a prior run.
    let already =
        publisher
            .is_republished(new_name)
            .await
            .map_err(|error| WriteRotateError::Publish {
                stage: "republish",
                node_id,
                error,
            })?;
    if already {
        return Ok(());
    }

    publisher
        .republish(&RepublishedNode {
            node_id,
            new_name: new_name.clone(),
            write_epoch,
            is_root,
        })
        .await
        .map_err(|error| WriteRotateError::Publish {
            stage: "republish",
            node_id,
            error,
        })
}

/// The `repoint-<channel>` publish-stage label for an error.
fn repoint_stage(channel: RepointChannel) -> &'static str {
    match channel {
        RepointChannel::ScopePointer => "repoint-scope-pointer",
        RepointChannel::Mailbox => "repoint-mailbox",
        RepointChannel::Tombstone => "repoint-tombstone",
    }
}

/// BFS the write scope's subtree from `root_id` via the resolver: root first, then
/// level order. A `node_id`-keyed visited set terminates diamonds/cycles fail-
/// closed (a tree has none, but the walk never loops). An unresolvable node aborts
/// — a partial subtree is never a complete wave.
async fn collect_subtree<R: WriteSubtreeResolver>(
    resolver: &R,
    root_id: [u8; 16],
) -> Result<Vec<WriteScopeNode>, WriteRotateError> {
    let mut visited: BTreeSet<[u8; 16]> = BTreeSet::new();
    let mut order: Vec<WriteScopeNode> = Vec::new();
    let mut queue: VecDeque<[u8; 16]> = VecDeque::new();

    visited.insert(root_id);
    queue.push_back(root_id);

    while let Some(id) = queue.pop_front() {
        let node =
            resolver
                .resolve_node(&id)
                .await
                .map_err(|reason| WriteRotateError::Resolve {
                    node_id: id,
                    reason,
                })?;
        for child in &node.child_node_ids {
            if visited.insert(*child) {
                queue.push_back(*child);
            }
        }
        order.push(node);
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{SeededEntropy, block_on};
    use cipherbox_core::seal::sign_grant_set;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::rc::Rc;

    const SCOPE: [u8; 16] = [0x5c; 16];
    const OLD_WRITE_SCOPE_SEED: [u8; 32] = [0x0d; 32];
    const OWNER_POINTER_SEED: [u8; 32] = [0x0e; 32];

    fn nid(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn owner() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x33; 32]).unwrap()
    }

    /// An owner-signed commitment naming `name` as the scope root. The signature
    /// binds `name` only; callers pass a mismatched name to exercise the reject path.
    fn commitment_for(
        owner: &EcdsaSigner,
        name: &IpnsName,
    ) -> (GrantSetCommitment, [u8; ECDSA_SIG_LEN]) {
        let c = GrantSetCommitment {
            ipns_name: name.as_str().as_bytes().to_vec(),
            owner_pseudonym_pk: [0x22; 32],
            entries: Vec::new(),
            unknown: Vec::new(),
        };
        let sig = sign_grant_set(owner, &c).unwrap().to_compact();
        (c, sig)
    }

    /// The default commitment: bound to the scope root every test rotates
    /// (`old_name_of(SCOPE)`, each test's `current_root`).
    fn commitment(owner: &EcdsaSigner) -> (GrantSetCommitment, [u8; ECDSA_SIG_LEN]) {
        commitment_for(owner, &old_name_of(&SCOPE))
    }

    /// A node's old (pre-rotation) name — derived from the OLD write scope seed, so
    /// the wave's freshly derived names provably differ.
    fn old_name_of(node_id: &[u8; 16]) -> IpnsName {
        derive_write_name(&OLD_WRITE_SCOPE_SEED, node_id)
    }

    /// One recorded wave effect, in call order — the tape the ordering invariants
    /// are asserted over.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Register(String),
        Republish { node_id: [u8; 16], is_root: bool },
        Retire(Vec<String>),
        Repoint(RepointChannel),
    }

    /// A fake subtree resolver over a fixed `node_id -> children` map.
    struct FakeResolver {
        nodes: HashMap<[u8; 16], Vec<[u8; 16]>>,
    }

    impl WriteSubtreeResolver for FakeResolver {
        async fn resolve_node(&self, node_id: &[u8; 16]) -> Result<WriteScopeNode, ResolveFailure> {
            let children = self
                .nodes
                .get(node_id)
                .ok_or(ResolveFailure::Unavailable)?
                .clone();
            Ok(WriteScopeNode {
                node_id: *node_id,
                current_name: old_name_of(node_id),
                child_node_ids: children,
            })
        }
    }

    /// A resolver modelling a resume AFTER the pointer already flipped: every node
    /// reports its NEW (post-rotation) name as current, as a resolver walking the
    /// flipped pointer would. Retiring any of these would orphan a live descendant.
    struct PostFlipResolver {
        nodes: HashMap<[u8; 16], Vec<[u8; 16]>>,
        seed: [u8; 32],
    }

    impl WriteSubtreeResolver for PostFlipResolver {
        async fn resolve_node(&self, node_id: &[u8; 16]) -> Result<WriteScopeNode, ResolveFailure> {
            let children = self
                .nodes
                .get(node_id)
                .ok_or(ResolveFailure::Unavailable)?
                .clone();
            Ok(WriteScopeNode {
                node_id: *node_id,
                current_name: derive_write_name(&self.seed, node_id),
                child_node_ids: children,
            })
        }
    }

    /// A resolver that fails on one node id — drives the resolve-abort path.
    struct FailingResolver {
        inner: FakeResolver,
        fail_on: [u8; 16],
    }

    impl WriteSubtreeResolver for FailingResolver {
        async fn resolve_node(&self, node_id: &[u8; 16]) -> Result<WriteScopeNode, ResolveFailure> {
            if *node_id == self.fail_on {
                return Err(ResolveFailure::Rejected);
            }
            self.inner.resolve_node(node_id).await
        }
    }

    /// Shared, "durable" published state plus the effect tape. Cloning the handle
    /// models reopening the same backing across a crash (a fresh orchestrator, the
    /// same published records).
    #[derive(Clone, Default)]
    struct WaveState {
        published: Rc<RefCell<HashSet<String>>>,
        registered: Rc<RefCell<HashSet<String>>>,
        retired: Rc<RefCell<HashSet<String>>>,
        events: Rc<RefCell<Vec<Event>>>,
        republish_calls: Rc<RefCell<HashMap<String, usize>>>,
        repoint_channels: Rc<RefCell<Vec<RepointChannel>>>,
    }

    /// A fake publisher over shared [`WaveState`], optionally scripted to fail once
    /// a given number of republish calls have landed (to crash a wave mid-flight).
    struct FakePublisher {
        state: WaveState,
        fail_republish_after: Option<usize>,
    }

    impl FakePublisher {
        fn new(state: WaveState) -> Self {
            Self {
                state,
                fail_republish_after: None,
            }
        }
        fn failing_after(state: WaveState, n: usize) -> Self {
            Self {
                state,
                fail_republish_after: Some(n),
            }
        }
    }

    impl WriteWavePublisher for FakePublisher {
        async fn register(&self, new_name: &IpnsName) -> Result<(), WritePublishError> {
            self.state
                .registered
                .borrow_mut()
                .insert(new_name.as_str().to_owned());
            self.state
                .events
                .borrow_mut()
                .push(Event::Register(new_name.as_str().to_owned()));
            Ok(())
        }

        async fn is_republished(&self, new_name: &IpnsName) -> Result<bool, WritePublishError> {
            Ok(self.state.published.borrow().contains(new_name.as_str()))
        }

        async fn republish(&self, node: &RepublishedNode) -> Result<(), WritePublishError> {
            let key = node.new_name.as_str().to_owned();
            {
                let calls = self.state.republish_calls.borrow();
                let landed: usize = calls.values().sum();
                if let Some(limit) = self.fail_republish_after {
                    if landed >= limit {
                        return Err(WritePublishError::NotLanded);
                    }
                }
            }
            // Register-first invariant: a name is registered before it is published.
            assert!(
                self.state.registered.borrow().contains(&key),
                "republish before register — orphaned name"
            );
            *self
                .state
                .republish_calls
                .borrow_mut()
                .entry(key.clone())
                .or_insert(0) += 1;
            self.state.published.borrow_mut().insert(key);
            self.state.events.borrow_mut().push(Event::Republish {
                node_id: node.node_id,
                is_root: node.is_root,
            });
            Ok(())
        }

        async fn retire(&self, old_names: &[IpnsName]) -> Result<(), WritePublishError> {
            let names: Vec<String> = old_names.iter().map(|n| n.as_str().to_owned()).collect();
            for n in &names {
                self.state.retired.borrow_mut().insert(n.clone());
            }
            self.state.events.borrow_mut().push(Event::Retire(names));
            Ok(())
        }

        async fn publish_repoint(
            &self,
            channel: RepointChannel,
            _block: &[u8],
        ) -> Result<(), WritePublishError> {
            self.state.repoint_channels.borrow_mut().push(channel);
            self.state.events.borrow_mut().push(Event::Repoint(channel));
            Ok(())
        }
    }

    /// A three-level tree: root(0x5c) → {0x02, 0x03}; 0x02 → {0x04, 0x05}.
    fn tree() -> FakeResolver {
        let mut nodes = HashMap::new();
        nodes.insert(SCOPE, vec![nid(0x02), nid(0x03)]);
        nodes.insert(nid(0x02), vec![nid(0x04), nid(0x05)]);
        nodes.insert(nid(0x03), Vec::new());
        nodes.insert(nid(0x04), Vec::new());
        nodes.insert(nid(0x05), Vec::new());
        FakeResolver { nodes }
    }

    fn plan<'a>(
        owner: &'a EcdsaSigner,
        commitment: &'a GrantSetCommitment,
        sig: &'a [u8; ECDSA_SIG_LEN],
        current_root: &'a IpnsName,
        resume: Option<&'a [u8; 32]>,
    ) -> RotateScopeWritePlan<'a> {
        RotateScopeWritePlan {
            scope_id: SCOPE,
            payload_version: 2,
            owner_pointer_seed: &OWNER_POINTER_SEED,
            commitment,
            commitment_sig: sig,
            owner_identity_signer: owner,
            current_write_epoch: 4,
            min_read_epoch: 7,
            current_root_name: current_root,
            resume_write_scope_seed: resume,
        }
    }

    #[test]
    fn happy_path_child_first_root_last_repoint_then_retire() {
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let resolver = tree();
        let state = WaveState::default();
        let publisher = FakePublisher::new(state.clone());
        let current_root = old_name_of(&SCOPE);

        let outcome = block_on(async {
            let mut e = SeededEntropy::new(1);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root, None),
            )
            .await
        })
        .expect("rotation succeeds");

        assert_eq!(outcome.new_write_epoch, 5, "write epoch bumped 4 -> 5");
        assert_eq!(outcome.interior_node_count, 4, "four interior nodes");

        let events = state.events.borrow();

        // The root republish is the LAST republish, and every republish precedes it.
        let republish_positions: Vec<(usize, bool)> = events
            .iter()
            .enumerate()
            .filter_map(|(i, ev)| match ev {
                Event::Republish { is_root, .. } => Some((i, *is_root)),
                _ => None,
            })
            .collect();
        assert_eq!(republish_positions.len(), 5, "root + four interior");
        let root_pos = republish_positions.last().unwrap();
        assert!(
            root_pos.1,
            "the LAST republish is the root (root re-pointed last)"
        );
        assert!(
            republish_positions[..4].iter().all(|(_, is_root)| !is_root),
            "every non-final republish is an interior node (child-first)"
        );

        // Child-first: a child publishes before its parent. 0x04/0x05 before 0x02.
        let order_of = |target: [u8; 16]| {
            events
                .iter()
                .position(|ev| matches!(ev, Event::Republish { node_id, .. } if *node_id == target))
                .unwrap()
        };
        assert!(
            order_of(nid(0x04)) < order_of(nid(0x02)),
            "grandchild before its parent"
        );
        assert!(
            order_of(nid(0x05)) < order_of(nid(0x02)),
            "grandchild before its parent"
        );

        // Three-channel re-point, in canonical order, AFTER every republish.
        let first_repoint = events
            .iter()
            .position(|ev| matches!(ev, Event::Repoint(_)))
            .unwrap();
        let last_republish = events
            .iter()
            .rposition(|ev| matches!(ev, Event::Republish { .. }))
            .unwrap();
        assert!(
            last_republish < first_repoint,
            "root re-point follows every republish"
        );
        assert_eq!(
            *state.repoint_channels.borrow(),
            vec![
                RepointChannel::ScopePointer,
                RepointChannel::Mailbox,
                RepointChannel::Tombstone
            ],
            "all three channels, pointer first"
        );

        // Retire is LAST, after the re-point, and the old ROOT name is never retired.
        let retire_pos = events
            .iter()
            .position(|ev| matches!(ev, Event::Retire(_)))
            .unwrap();
        assert!(retire_pos > first_repoint, "retire follows the re-point");
        assert!(
            !state.retired.borrow().contains(current_root.as_str()),
            "the old root name lingers — never retired"
        );
        assert_eq!(
            state.retired.borrow().len(),
            4,
            "exactly the four interior names retired"
        );
    }

    #[test]
    fn register_first_never_orphans_a_name() {
        // No interior name is retired before the pointer flips, and every republished
        // node was registered first (the publisher's own assert also enforces the
        // per-node ordering).
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let resolver = tree();
        let state = WaveState::default();
        let publisher = FakePublisher::new(state.clone());
        let current_root = old_name_of(&SCOPE);

        block_on(async {
            let mut e = SeededEntropy::new(2);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root, None),
            )
            .await
        })
        .expect("rotation succeeds");

        let events = state.events.borrow();
        let first_retire = events.iter().position(|ev| matches!(ev, Event::Retire(_)));
        let first_repoint = events
            .iter()
            .position(|ev| matches!(ev, Event::Repoint(_)))
            .unwrap();
        assert!(
            first_retire.map(|r| r > first_repoint).unwrap_or(true),
            "no interior name is retired before the pointer flips (never orphan)"
        );
        let registers = events
            .iter()
            .filter(|ev| matches!(ev, Event::Register(_)))
            .count();
        let republishes = events
            .iter()
            .filter(|ev| matches!(ev, Event::Republish { .. }))
            .count();
        assert_eq!(registers, 5);
        assert_eq!(republishes, 5);
    }

    #[test]
    fn mid_wave_crash_resumes_from_published_records_only() {
        // Crash the wave after two republishes, then resume with a FRESH orchestrator
        // over the SAME published state (no in-memory carry) and the recovered seed.
        // The resumed wave completes, republishes each remaining node exactly once
        // (already-done nodes skipped via published state), and re-points last.
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let resolver = tree();
        let state = WaveState::default();
        let current_root = old_name_of(&SCOPE);

        // The seed a fresh wave WOULD mint — captured so the resume threads it back
        // in, standing in for recovery from the published root (#745/#746).
        let recovered_seed = {
            let mut e = SeededEntropy::new(9);
            let mut seed = [0u8; 32];
            e.fill(&mut seed).unwrap();
            seed
        };

        // First attempt crashes after two republishes.
        let crashing = FakePublisher::failing_after(state.clone(), 2);
        let err = block_on(async {
            let mut e = SeededEntropy::new(9);
            rotate_scope_write(
                &mut e,
                &resolver,
                &crashing,
                &plan(&owner, &c, &sig, &current_root, None),
            )
            .await
        })
        .expect_err("the wave crashes mid-flight");
        assert_eq!(err.check(), "publish-failed");
        let published_after_crash = state.published.borrow().len();
        assert!(
            (1..5).contains(&published_after_crash),
            "a strict, non-empty subset republished before the crash (got {published_after_crash})"
        );
        assert!(
            state.repoint_channels.borrow().is_empty(),
            "no re-point before the wave completed"
        );

        // Resume: a brand-new orchestrator + publisher over the same durable state.
        let resume_pub = FakePublisher::new(state.clone());
        let outcome = block_on(async {
            let mut e = SeededEntropy::new(123); // a DIFFERENT stream — no fresh mint on resume
            rotate_scope_write(
                &mut e,
                &resolver,
                &resume_pub,
                &plan(&owner, &c, &sig, &current_root, Some(&recovered_seed)),
            )
            .await
        })
        .expect("the resumed wave completes");

        assert_eq!(outcome.new_write_epoch, 5);
        assert_eq!(
            outcome.new_root_name,
            derive_write_name(&recovered_seed, &SCOPE)
        );

        // Every node republished exactly once across BOTH runs — the resume skipped
        // the already-published nodes (proof it read published state, not memory).
        let calls = state.republish_calls.borrow();
        assert_eq!(calls.len(), 5, "all five nodes republished");
        assert!(
            calls.values().all(|&n| n == 1),
            "no node republished twice — resume is idempotent off published records"
        );
        // The wave completed: pointer flipped on all three channels, interior retired.
        assert_eq!(state.repoint_channels.borrow().len(), 3);
        assert_eq!(state.retired.borrow().len(), 4);
        assert!(
            !state.retired.borrow().contains(current_root.as_str()),
            "root lingers"
        );
    }

    #[test]
    fn resume_after_flip_never_retires_a_live_name() {
        // A resume AFTER the pointer already flipped: the resolver reports every
        // node's NEW name as current (the migrated records the flipped pointer now
        // reaches). The wave must retire NONE of them — retiring a name a node still
        // lives at would orphan a live descendant. Without the orphan guard this
        // batch-retires the four live interior names.
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let recovered_seed = [0x77u8; 32];
        let mut nodes = HashMap::new();
        nodes.insert(SCOPE, vec![nid(0x02), nid(0x03)]);
        nodes.insert(nid(0x02), vec![nid(0x04), nid(0x05)]);
        nodes.insert(nid(0x03), Vec::new());
        nodes.insert(nid(0x04), Vec::new());
        nodes.insert(nid(0x05), Vec::new());
        let resolver = PostFlipResolver {
            nodes,
            seed: recovered_seed,
        };
        let state = WaveState::default();
        // The fully-migrated published state: every new name already landed.
        for id in [SCOPE, nid(0x02), nid(0x03), nid(0x04), nid(0x05)] {
            let name = derive_write_name(&recovered_seed, &id);
            state
                .published
                .borrow_mut()
                .insert(name.as_str().to_owned());
        }
        let publisher = FakePublisher::new(state.clone());
        let current_root = old_name_of(&SCOPE);

        block_on(async {
            let mut e = SeededEntropy::new(50);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root, Some(&recovered_seed)),
            )
            .await
        })
        .expect("the resumed wave completes");

        assert!(
            state.retired.borrow().is_empty(),
            "no live (already-migrated) name is retired on a post-flip resume"
        );
    }

    #[test]
    fn non_owner_signer_is_rejected_fail_closed() {
        // A real, valid signer that did NOT author the commitment cannot rotate.
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let resolver = tree();
        let state = WaveState::default();
        let publisher = FakePublisher::new(state.clone());
        let current_root = old_name_of(&SCOPE);
        let impostor = EcdsaSigner::from_scalar(&[0x44; 32]).unwrap();

        let err = block_on(async {
            let mut e = SeededEntropy::new(3);
            let mut p = plan(&owner, &c, &sig, &current_root, None);
            p.owner_identity_signer = &impostor;
            rotate_scope_write(&mut e, &resolver, &publisher, &p).await
        })
        .expect_err("a non-owner is rejected");
        assert_eq!(err.check(), "not-owner");
        assert!(
            !err.is_retryable(),
            "owner-only is not an availability stall"
        );
        assert!(
            state.published.borrow().is_empty(),
            "nothing published on an owner-only rejection"
        );
    }

    #[test]
    fn commitment_naming_a_different_scope_is_rejected_fail_closed() {
        // The owner correctly signs the commitment, but it names a DIFFERENT scope
        // root than the one under rotation. The owner-gate binds the auth token to
        // the exact rotated scope (the adoption gate's `commitment.ipns_name`
        // binding), so a valid-but-wrong-scope commitment fails closed before any
        // mint or publish — an owner cannot rotate scope B with scope A's token.
        let owner = owner();
        let other_root = old_name_of(&nid(0xaa));
        let (c, sig) = commitment_for(&owner, &other_root);
        let resolver = tree();
        let state = WaveState::default();
        let publisher = FakePublisher::new(state.clone());
        let current_root = old_name_of(&SCOPE);

        let err = block_on(async {
            let mut e = SeededEntropy::new(7);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root, None),
            )
            .await
        })
        .expect_err("a commitment naming another scope is rejected");
        assert_eq!(err.check(), "commitment-scope-mismatch");
        assert!(
            !err.is_retryable(),
            "a scope-binding violation is not an availability stall"
        );
        assert!(
            state.published.borrow().is_empty(),
            "nothing published on a scope-mismatch rejection"
        );
    }

    #[test]
    fn resolve_failure_aborts_without_publishing() {
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let resolver = FailingResolver {
            inner: tree(),
            fail_on: nid(0x04),
        };
        let state = WaveState::default();
        let publisher = FakePublisher::new(state.clone());
        let current_root = old_name_of(&SCOPE);

        let err = block_on(async {
            let mut e = SeededEntropy::new(4);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root, None),
            )
            .await
        })
        .expect_err("an unresolvable node aborts the wave");
        assert_eq!(err.check(), "resolve-failed");
        assert!(
            state.published.borrow().is_empty(),
            "nothing republished when enumeration fails"
        );
    }

    #[test]
    fn exhausted_write_epoch_fails_closed() {
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let resolver = tree();
        let publisher = FakePublisher::new(WaveState::default());
        let current_root = old_name_of(&SCOPE);

        let err = block_on(async {
            let mut e = SeededEntropy::new(5);
            let mut p = plan(&owner, &c, &sig, &current_root, None);
            p.current_write_epoch = u64::MAX;
            rotate_scope_write(&mut e, &resolver, &publisher, &p).await
        })
        .expect_err("an exhausted epoch fails closed");
        assert_eq!(err.check(), "epoch-exhausted");
    }

    #[test]
    fn derive_write_name_is_deterministic_and_moves_the_name() {
        // A surviving write-grantee derives the same new name locally; the new name
        // differs from the old (a fresh write scope seed moved it).
        let fresh = [0xef; 32];
        let a = derive_write_name(&fresh, &SCOPE);
        let b = derive_write_name(&fresh, &SCOPE);
        assert_eq!(a, b, "same seed + node id -> same name (local derivation)");
        assert_ne!(a, old_name_of(&SCOPE), "the fresh seed moved the name");
    }

    // --- Encode-side fail-closed guards (release-active, AGENTS.md rule 8) ---

    #[test]
    fn build_repoint_rejects_non_advancing_write_epoch_release_active() {
        // The encode-side mirror of the floor law's monotonic write-epoch reject: a
        // re-point that does not advance the write epoch is a runtime `Err`, never a
        // debug_assert. Active in release builds.
        let new_root = derive_write_name(&[0x01; 32], &SCOPE);
        let prev_root = old_name_of(&SCOPE);
        for (new_epoch, prev_epoch) in [(5u64, 5u64), (4, 5)] {
            let err = build_repoint_object(
                SCOPE,
                new_root.clone(),
                prev_root.clone(),
                new_epoch,
                prev_epoch,
                7,
            )
            .expect_err("non-advancing write epoch");
            assert_eq!(err.check(), "write-epoch-not-advancing");
        }
    }

    #[test]
    fn build_repoint_rejects_identity_repoint_release_active() {
        // Re-pointing a scope to its own predecessor name is not progress: rejected
        // release-active before publish.
        let same = old_name_of(&SCOPE);
        let err = build_repoint_object(SCOPE, same.clone(), same, 6, 5, 7)
            .expect_err("identity re-point");
        assert_eq!(err.check(), "identity-repoint");
    }

    #[test]
    fn build_repoint_accepts_a_valid_advance() {
        let new_root = derive_write_name(&[0x01; 32], &SCOPE);
        let prev_root = old_name_of(&SCOPE);
        let obj =
            build_repoint_object(SCOPE, new_root.clone(), prev_root.clone(), 6, 5, 7).unwrap();
        assert_eq!(obj.current_root, new_root);
        assert_eq!(obj.prev_root, Some(prev_root));
        assert_eq!(obj.write_epoch, 6);
        assert_eq!(obj.min_read_epoch, 7, "read plane carried unchanged");
    }
}
