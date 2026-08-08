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
//! key. The read plane's **keys** are untouched — override seeds, read keys, and
//! `minReadEpoch` carry verbatim, and no rotation path re-encrypts content bytes
//! (#26 D6). Read-body *metadata* is not: see [`RepublishedNode::child_names`].
//!
//! # Ordering is the safety property (#34 D4)
//!
//! A new name is **registered before** its predecessor is retired, old names stay
//! live until the pointer flips, and the pointer flips last — so at every instant
//! a resolver reaches every node by at least one live name. Interior old names
//! batch-retire only **after** the root re-point; the old root name lingers past
//! the migration window.
//!
//! # Re-point channels (#38 D3)
//!
//! The owner-identity-signed re-point object flips the canonical scope pointer
//! record, then goes out on the two accelerator channels (see [`RepointChannel`]).
//! `writeEpoch` advances here; `minReadEpoch` is carried unchanged, so each plane's
//! clock stays authored by its owning authority (#38 D1).
//!
//! # Crash recovery from published records only (#26 D8)
//!
//! No cross-crash state: a resumed wave re-derives each node's deterministic new
//! name and skips already-republished nodes via
//! [`WriteWavePublisher::is_republished`]; every effect is idempotent, so it
//! converges to the same terminal state. The fresh write scope seed comes from
//! the published moved root through [`WriteSubtreeResolver::recover_wave`], and
//! is refused unless it derives that root's own name
//! ([`WriteRotateError::ResumedSeedNotAtItsRoot`]). Accepted limitation: a crash
//! after the pointer flip but before interior retirement orphans the prior run's
//! interior old names — the fail-safe direction (leaking a registration beats
//! retiring a live name); reclaiming those orphaned names from the moved root's
//! write-plane history link is not landed.
//!
//! # Owner-only, fail-closed, deterministic
//!
//! The caller must present the owner identity signer that authored the current
//! grant-set commitment, and that commitment must name this scope's current root
//! ([`WriteRotateError::NotOwner`], [`WriteRotateError::CommitmentScopeMismatch`]).
//! [`build_repoint_object`]'s two encode-side invariants are release-active, never
//! a `debug_assert!` (AGENTS.md rule 8). Entropy enters only through the
//! [`Entropy`] seam; the impure edges are the injected [`WriteSubtreeResolver`] and
//! [`WriteWavePublisher`] (`net/rotation.rs` holds both production arms).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use zeroize::Zeroizing;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::seal::{GrantSetCommitment, verify_grant_set};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaSigner, SIGNATURE_LEN as ECDSA_SIG_LEN};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};

use super::eager_set::ResolveFailure;
use crate::entropy::{Entropy, EntropyError};
use crate::sync::pointer::{PointerError, SessionRole, seal_repoint};
use cipherbox_core::hex::lower as hex_lower;

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

/// The two accelerator channels, published after the canonical
/// [`RepointChannel::ScopePointer`] flip.
const REPOINT_ACCELERATORS: [RepointChannel; 2] =
    [RepointChannel::Mailbox, RepointChannel::Tombstone];

/// The order to republish one node at its freshly derived name. It carries
/// routing identity and the narrowest key material the publish needs — never the
/// record's authoring material: the publisher re-resolves the node at
/// [`Self::current_name`] and rewrites what moved, so the wave drags neither
/// O(subtree) bodies nor per-node read keys through this primitive
/// (blueprint/engine.md "rotateScopeWrite").
#[derive(Debug, Clone)]
pub struct RepublishedNode {
    /// The node id being republished.
    pub node_id: [u8; 16],
    /// The node's current (pre-wave) `ipnsName` — where the publisher does its
    /// gated read of the record it is about to succeed.
    pub current_name: IpnsName,
    /// The freshly derived `ipnsName` the record is published at.
    pub new_name: IpnsName,
    /// Each in-scope direct child's freshly derived name, keyed by child node id.
    ///
    /// A read-only survivor holds no `writeScopeSeed` and can derive no name, so
    /// the wave rewrites the matching `ChildRef.ipnsName` and re-seals the parent's
    /// read body under its unchanged read key at its unchanged read epoch — without
    /// it a read-only holder reaches the new root and cannot descend. Empty for a
    /// leaf; child-first ordering makes every entry known before the parent
    /// publishes.
    pub child_names: BTreeMap<[u8; 16], IpnsName>,
    /// Signs the record at [`Self::new_name`] — the narrow per-name capability
    /// (the shape `net/liveness.rs` holds for the same reason), never the seed it
    /// derives from, so the publisher can derive no other node's name.
    pub signer: Ed25519Signer,
    /// The wave's fresh write scope seed, carried **only** for the scope root:
    /// the root's grant section is the sole channel that distributes it (the
    /// owner-write blob and every write grantee's blob), and a root republished
    /// without it strands the whole write plane on the retired names.
    pub write_scope_seed: Option<SecretBytes>,
    /// The write epoch the record publishes at (bumped for the whole scope).
    pub write_epoch: u64,
    /// Whether this is the scope root (re-pointed last, old name lingers).
    pub is_root: bool,
}

/// A prior wave over this scope, read back from published records: the fresh
/// write scope seed it minted and the `ipnsName` its moved root was published at.
/// The pair travels together because the name is what makes the seed checkable —
/// see [`rotate_scope_write`].
pub struct ResumedWriteWave {
    /// The fresh write scope seed the crashed wave minted.
    pub write_scope_seed: SecretBytes,
    /// The `ipnsName` the moved root was published at.
    pub root_name: IpnsName,
    /// The write epoch the moved root was published at, as the owner signed it.
    pub write_epoch: u64,
}

/// Resolve the write scope's subtree from published records — the read edge, the
/// analogue of the cascade's `CascadeResealResolver`. Resolve + adoption-gate +
/// unseal live behind this trait (`net/rotation.rs::WriteWaveNet`). A resolve
/// either yields the node or a fail-closed [`ResolveFailure`].
pub trait WriteSubtreeResolver {
    /// Resolve `node_id`'s current write-plane node (its name + children), or a
    /// fail-closed [`ResolveFailure`] if its record cannot be authoritatively
    /// obtained.
    async fn resolve_node(&self, node_id: &[u8; 16]) -> Result<WriteScopeNode, ResolveFailure>;

    /// The in-flight wave to pick up, read from published records; `None` when
    /// no moved root of this scope is published, which is a fresh rotation.
    /// The whole of the crash-recovery seam (#26 D8): entropy versus a published
    /// record, never an in-memory checkpoint a crash would have taken with it.
    async fn recover_wave(&self) -> Result<Option<ResumedWriteWave>, ResolveFailure>;
}

/// The write edge of the name wave: CAS republish, batch retire, and the
/// three-channel re-point — the analogue of the cascade's `ScopeRootPublisher`,
/// mapping to the API pin/name registry and `/routing/v1` transport
/// (`net/rotation.rs::WriteWaveNet`).
///
/// Contract the orchestrator relies on and the fake honours:
///
/// - **republish / retire are idempotent** — a resumed wave re-publishes and
///   re-retires the same names harmlessly.
/// - **`is_republished` reads published state only** — it is how a resumed wave
///   skips already-done nodes without any in-memory checkpoint.
/// - **`republish` registers the name it PUTs**, first and fail-closed
///   (`net/publish.rs`, #28 D5) — the never-orphan ordering law.
pub trait WriteWavePublisher {
    /// Whether a record is already published at `new_name` — the resume query,
    /// answered from published state only (no in-memory carry across a crash).
    async fn is_republished(&self, new_name: &IpnsName) -> Result<bool, WritePublishError>;

    /// Register-first then CAS-publish `node`'s record at its freshly derived
    /// name, rewriting [`RepublishedNode::child_names`] into its read body.
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

/// Why one write-plane op did not durably land. Only [`Self::Rejected`] is a
/// trust verdict a retry cannot clear (rule 6: a fail-closed rejection is never
/// laundered into an availability stall), and it aborts the wave on every
/// channel; the rest abort every stage except an accelerator re-point.
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
    /// The publisher's own fail-closed verdict on the bytes it was about to sign
    /// or the effect it was about to make irreversible — a gate rejection on the
    /// re-resolve, a read body whose children disagree with the wave, or a retire
    /// batch naming the lingering root. Re-running reaches the same verdict.
    Rejected,
}

impl core::fmt::Display for WritePublishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WritePublishError::NotLanded => f.write_str("write-plane record did not land"),
            WritePublishError::LostRace => f.write_str("write-plane publish lost the CAS race"),
            WritePublishError::RegistryFull => f.write_str("name registry rejected register-first"),
            WritePublishError::Rejected => f.write_str("write-plane publish refused fail-closed"),
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
}

/// A completed write rotation. Holding one is proof the whole subtree was
/// republished, the **canonical** re-point landed, and interior old names retired
/// — an incomplete wave returns [`WriteRotateError`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRotationOutcome {
    /// The new write epoch the scope was cut to (`current_write_epoch + 1`).
    pub new_write_epoch: u64,
    /// The scope root's new `ipnsName` (`currentRootName` in the re-point object).
    pub new_root_name: IpnsName,
    /// Which accelerator channels the re-point actually reached, in publish
    /// order. Nothing on them is load-bearing (see [`RepointChannel`]), so a
    /// refused accelerator leaves the wave complete and is reported rather than
    /// aborting a rotation whose canonical re-point already flipped the pointer.
    pub repoint_accelerators: Vec<RepointChannel>,
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
    /// The write scope seed recovered from a published moved root does not derive
    /// that root's own `ipnsName` — the reverse of the check the republish makes
    /// forward. Resuming on it would move the whole subtree to names derived from
    /// a seed nothing owner-authentic ties to this scope, so the wave refuses
    /// before a single republish. Release-active.
    ResumedSeedNotAtItsRoot,
    /// The recovered wave targets a different write epoch than this run does.
    /// The pointer plane carries no adoption gate, so an older owner-signed
    /// re-point stays replayable at the scope's one stable pointer name for ever;
    /// requiring the recovered epoch to be the one this run publishes at is what
    /// makes a resume pick up **this** wave rather than a superseded one.
    /// Release-active.
    ResumedWaveAtAnotherEpoch,
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
        /// The wave stage that failed (`republish` / `retire` /
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
            WriteRotateError::ResumedSeedNotAtItsRoot => f.write_str(
                "recovered write scope seed does not derive the root it was published at",
            ),
            WriteRotateError::ResumedWaveAtAnotherEpoch => {
                f.write_str("recovered wave targets a different write epoch than this rotation")
            }
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
            WriteRotateError::ResumedSeedNotAtItsRoot => "resumed-seed-not-at-its-root",
            WriteRotateError::ResumedWaveAtAnotherEpoch => "resumed-wave-at-another-epoch",
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
            | WriteRotateError::IdentityRepoint
            | WriteRotateError::ResumedSeedNotAtItsRoot
            | WriteRotateError::ResumedWaveAtAnotherEpoch => false,
            WriteRotateError::Entropy(_) => true,
            WriteRotateError::Publish { error, .. } => *error != WritePublishError::Rejected,
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
/// Owner-checks the caller, recovers or mints the fresh write scope seed,
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

    // 3) The fresh write override seed — the seed a crashed wave already published
    //    at its moved root, or RANDOM via the entropy seam (never KDF-derived).
    //    `Zeroizing` wipes it on every return path, including a panic unwind; this
    //    orchestrator is its terminal owner.
    let resumed = resolver
        .recover_wave()
        .await
        .map_err(|reason| WriteRotateError::Resolve {
            node_id: scope_id,
            reason,
        })?;
    let write_scope_seed: Zeroizing<[u8; SECRET_LEN]> = match resumed {
        Some(wave) => {
            if wave.write_epoch != new_write_epoch {
                return Err(WriteRotateError::ResumedWaveAtAnotherEpoch);
            }
            let seed = Zeroizing::new(*wave.write_scope_seed.as_bytes());
            if derive_write_name(&seed, &scope_id) != wave.root_name {
                return Err(WriteRotateError::ResumedSeedNotAtItsRoot);
            }
            seed
        }
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

    // 5) Child-first wave over the descendants (deepest first): republish unless
    //    already done (resume skips it via published state).
    let mut interior_old_names: Vec<IpnsName> = Vec::with_capacity(descendants.len());
    for node in descendants.iter().rev() {
        let new_name = derive_write_name(&write_scope_seed, &node.node_id);
        republish_node(
            publisher,
            &write_scope_seed,
            node,
            &new_name,
            new_write_epoch,
            false,
        )
        .await?;
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
        &write_scope_seed,
        root,
        &new_root_name,
        new_write_epoch,
        true,
    )
    .await?;

    // 7) Seal the owner-signed re-point object; flip the canonical pointer, then
    //    the accelerators.
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
    publisher
        .publish_repoint(RepointChannel::ScopePointer, &block)
        .await
        .map_err(|error| WriteRotateError::Publish {
            stage: repoint_stage(RepointChannel::ScopePointer),
            node_id: scope_id,
            error,
        })?;
    let mut repoint_accelerators = Vec::with_capacity(REPOINT_ACCELERATORS.len());
    for channel in REPOINT_ACCELERATORS {
        match publisher.publish_repoint(channel, &block).await {
            Ok(()) => repoint_accelerators.push(channel),
            // An accelerator carries nothing load-bearing, so an availability
            // failure is reported, not fatal. A `Rejected` is not availability:
            // the publisher refused to sign, and rule 6 forbids absorbing that.
            Err(WritePublishError::Rejected) => {
                return Err(WriteRotateError::Publish {
                    stage: repoint_stage(channel),
                    node_id: scope_id,
                    error: WritePublishError::Rejected,
                });
            }
            Err(_) => {}
        }
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
        repoint_accelerators,
        interior_node_count: descendants.len(),
    })
}

/// CAS-republish one node at `new_name`, skipping the republish when published
/// state already carries it (the resume idempotence).
async fn republish_node<P: WriteWavePublisher>(
    publisher: &P,
    write_scope_seed: &[u8; SECRET_LEN],
    node: &WriteScopeNode,
    new_name: &IpnsName,
    write_epoch: u64,
    is_root: bool,
) -> Result<(), WriteRotateError> {
    let node_id = node.node_id;
    let publish_error = |error| WriteRotateError::Publish {
        stage: "republish",
        node_id,
        error,
    };

    // Resume: skip a node whose new-name record already landed on a prior run.
    if publisher
        .is_republished(new_name)
        .await
        .map_err(publish_error)?
    {
        return Ok(());
    }

    let child_names = node
        .child_node_ids
        .iter()
        .map(|child| (*child, derive_write_name(write_scope_seed, child)))
        .collect();

    publisher
        .republish(&RepublishedNode {
            node_id,
            current_name: node.current_name.clone(),
            new_name: new_name.clone(),
            child_names,
            signer: kdf::ipns_keypair(kdf::write_seed(write_scope_seed, &node_id).as_bytes()),
            write_scope_seed: is_root.then(|| SecretBytes::new(*write_scope_seed)),
            write_epoch,
            is_root,
        })
        .await
        .map_err(publish_error)
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
    use cipherbox_core::seal::{PreservedFields, sign_grant_set};
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::rc::Rc;

    const SCOPE: [u8; 16] = [0x5c; 16];
    /// The write epoch every test's [`plan`] publishes at (`current_write_epoch + 1`).
    const ROTATED_WRITE_EPOCH: u64 = 5;
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
            unknown: PreservedFields::new(),
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

    /// The moved root as published state holds it: where it landed, the seed its
    /// grant section publishes, and the write epoch it published at.
    type PublishedRoot = (IpnsName, [u8; SECRET_LEN], u64);

    /// One recorded wave effect, in call order — the tape the ordering invariants
    /// are asserted over.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Republish { node_id: [u8; 16], is_root: bool },
        Retire(Vec<String>),
        Repoint(RepointChannel),
    }

    /// The recovery a resolver reads back out of published state: the moved root
    /// the publisher landed, and the write scope seed its grant section carries.
    /// Nothing else crosses a crash, so a resume that works here works off
    /// published records alone.
    fn recover_from(state: &WaveState) -> Result<Option<ResumedWriteWave>, ResolveFailure> {
        Ok(state.published_root.borrow().as_ref().map(resumed))
    }

    fn resumed((name, seed, write_epoch): &PublishedRoot) -> ResumedWriteWave {
        ResumedWriteWave {
            write_scope_seed: SecretBytes::new(*seed),
            root_name: name.clone(),
            write_epoch: *write_epoch,
        }
    }

    /// A fake subtree resolver over a fixed `node_id -> children` map.
    struct FakeResolver {
        nodes: HashMap<[u8; 16], Vec<[u8; 16]>>,
        state: WaveState,
        /// Overrides the published-state recovery, so a test can hand back a pair
        /// whose seed and root name disagree.
        recovery: Option<PublishedRoot>,
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

        async fn recover_wave(&self) -> Result<Option<ResumedWriteWave>, ResolveFailure> {
            match &self.recovery {
                Some(pair) => Ok(Some(resumed(pair))),
                None => recover_from(&self.state),
            }
        }
    }

    /// A resolver modelling a resume AFTER the pointer already flipped: every node
    /// reports its NEW (post-rotation) name as current, as a resolver walking the
    /// flipped pointer would. Retiring any of these would orphan a live descendant.
    struct PostFlipResolver {
        nodes: HashMap<[u8; 16], Vec<[u8; 16]>>,
        seed: [u8; 32],
        state: WaveState,
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

        async fn recover_wave(&self) -> Result<Option<ResumedWriteWave>, ResolveFailure> {
            recover_from(&self.state)
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

        async fn recover_wave(&self) -> Result<Option<ResumedWriteWave>, ResolveFailure> {
            self.inner.recover_wave().await
        }
    }

    /// Shared, "durable" published state plus the effect tape. Cloning the handle
    /// models reopening the same backing across a crash (a fresh orchestrator, the
    /// same published records).
    #[derive(Clone, Default)]
    struct WaveState {
        published: Rc<RefCell<HashSet<String>>>,
        /// The moved root as published state holds it: the name it landed at and
        /// the write scope seed its grant section publishes. The one thing a
        /// resumed wave reads back — the recovery seam's whole source.
        published_root: Rc<RefCell<Option<PublishedRoot>>>,
        retired: Rc<RefCell<HashSet<String>>>,
        events: Rc<RefCell<Vec<Event>>>,
        republish_calls: Rc<RefCell<HashMap<String, usize>>>,
        repoint_channels: Rc<RefCell<Vec<RepointChannel>>>,
        /// Every order the wave issued, in call order — the rewrite material the
        /// concrete publisher acts on.
        orders: Rc<RefCell<Vec<RepublishedNode>>>,
    }

    /// A fake publisher over shared [`WaveState`], optionally scripted to fail once
    /// a given number of republish calls have landed (to crash a wave mid-flight),
    /// or to refuse a given re-point channel.
    struct FakePublisher {
        state: WaveState,
        fail_republish_after: Option<usize>,
        refuse_channel: Option<RepointChannel>,
    }

    impl FakePublisher {
        fn new(state: WaveState) -> Self {
            Self {
                state,
                fail_republish_after: None,
                refuse_channel: None,
            }
        }
        fn failing_after(state: WaveState, n: usize) -> Self {
            Self {
                fail_republish_after: Some(n),
                ..Self::new(state)
            }
        }
        fn refusing(state: WaveState, channel: RepointChannel) -> Self {
            Self {
                refuse_channel: Some(channel),
                ..Self::new(state)
            }
        }
    }

    impl WriteWavePublisher for FakePublisher {
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
            *self
                .state
                .republish_calls
                .borrow_mut()
                .entry(key.clone())
                .or_insert(0) += 1;
            self.state.published.borrow_mut().insert(key);
            if let Some(seed) = node
                .is_root
                .then_some(node.write_scope_seed.as_ref())
                .flatten()
            {
                *self.state.published_root.borrow_mut() =
                    Some((node.new_name.clone(), *seed.as_bytes(), node.write_epoch));
            }
            self.state.orders.borrow_mut().push(node.clone());
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
            if self.refuse_channel == Some(channel) {
                return Err(WritePublishError::NotLanded);
            }
            self.state.repoint_channels.borrow_mut().push(channel);
            self.state.events.borrow_mut().push(Event::Repoint(channel));
            Ok(())
        }
    }

    /// A three-level tree: root(0x5c) → {0x02, 0x03}; 0x02 → {0x04, 0x05}.
    fn tree() -> FakeResolver {
        tree_on(WaveState::default())
    }

    /// The same tree, reading its recovery out of `state` — the shared published
    /// backing a resumed wave picks up from.
    fn tree_on(state: WaveState) -> FakeResolver {
        let mut nodes = HashMap::new();
        nodes.insert(SCOPE, vec![nid(0x02), nid(0x03)]);
        nodes.insert(nid(0x02), vec![nid(0x04), nid(0x05)]);
        nodes.insert(nid(0x03), Vec::new());
        nodes.insert(nid(0x04), Vec::new());
        nodes.insert(nid(0x05), Vec::new());
        FakeResolver {
            nodes,
            state,
            recovery: None,
        }
    }

    fn plan<'a>(
        owner: &'a EcdsaSigner,
        commitment: &'a GrantSetCommitment,
        sig: &'a [u8; ECDSA_SIG_LEN],
        current_root: &'a IpnsName,
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
                &plan(&owner, &c, &sig, &current_root),
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
        assert_eq!(
            outcome.repoint_accelerators,
            vec![RepointChannel::Mailbox, RepointChannel::Tombstone]
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
    fn no_interior_name_retires_before_the_pointer_flips() {
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
                &plan(&owner, &c, &sig, &current_root),
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
        assert_eq!(
            events
                .iter()
                .filter(|ev| matches!(ev, Event::Republish { .. }))
                .count(),
            5
        );
    }

    #[test]
    fn every_order_carries_the_derived_names_of_its_in_scope_children() {
        // ADR 0004: a read-only survivor derives no write name, so the wave must
        // hand each parent its children's freshly derived names for the read-body
        // rewrite. Child-first ordering makes them known before the parent's turn.
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let resolver = tree();
        let state = WaveState::default();
        let publisher = FakePublisher::new(state.clone());
        let current_root = old_name_of(&SCOPE);
        let seed = SeededEntropy::first_draw(11);

        block_on(async {
            let mut e = SeededEntropy::new(11);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root),
            )
            .await
        })
        .expect("rotation succeeds");

        let orders = state.orders.borrow();
        let by_id: HashMap<[u8; 16], &RepublishedNode> =
            orders.iter().map(|o| (o.node_id, o)).collect();
        let expected_children: HashMap<[u8; 16], Vec<[u8; 16]>> = resolver
            .nodes
            .iter()
            .map(|(id, kids)| (*id, kids.clone()))
            .collect();

        for order in orders.iter() {
            let kids = &expected_children[&order.node_id];
            assert_eq!(
                order.child_names.len(),
                kids.len(),
                "one rewrite entry per in-scope child"
            );
            for kid in kids {
                let mapped = &order.child_names[kid];
                // The name the parent will write is exactly the name the child was
                // republished at — the whole point of the child-first ordering.
                assert_eq!(mapped, &by_id[kid].new_name);
                assert_eq!(mapped, &derive_write_name(&seed, kid));
            }
            // The capability is the node's own, and nothing wider: it signs at
            // the new name and derives no other node's.
            assert_eq!(
                IpnsName::from_public_key(&order.signer.verifying_key()),
                order.new_name,
                "the handed signer is the new name's key"
            );
            assert_eq!(
                order.write_scope_seed.is_some(),
                order.is_root,
                "only the root carries the scope seed its section distributes"
            );
            assert_eq!(order.current_name, old_name_of(&order.node_id));
        }
    }

    #[test]
    fn a_refused_accelerator_leaves_the_wave_complete() {
        // The mailbox and the tombstone carry nothing load-bearing, so a wave whose
        // canonical pointer flip landed must not be re-run for them — it reports
        // which accelerators it reached instead.
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let resolver = tree();
        let state = WaveState::default();
        let publisher = FakePublisher::refusing(state.clone(), RepointChannel::Mailbox);
        let current_root = old_name_of(&SCOPE);

        let outcome = block_on(async {
            let mut e = SeededEntropy::new(21);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root),
            )
            .await
        })
        .expect("a refused accelerator does not abort the wave");

        assert_eq!(
            outcome.repoint_accelerators,
            vec![RepointChannel::Tombstone]
        );
        assert_eq!(
            *state.repoint_channels.borrow(),
            vec![RepointChannel::ScopePointer, RepointChannel::Tombstone]
        );
        assert_eq!(
            state.retired.borrow().len(),
            4,
            "the wave still completes its retirement"
        );
    }

    #[test]
    fn a_refused_canonical_repoint_aborts_before_any_retire() {
        // The scope pointer is the authoritative switch: without it the old names
        // are still the live ones, so retiring them would orphan the subtree.
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let resolver = tree();
        let state = WaveState::default();
        let publisher = FakePublisher::refusing(state.clone(), RepointChannel::ScopePointer);
        let current_root = old_name_of(&SCOPE);

        let err = block_on(async {
            let mut e = SeededEntropy::new(22);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root),
            )
            .await
        })
        .expect_err("the canonical channel is not optional");
        assert_eq!(err.check(), "publish-failed");
        assert!(
            state.retired.borrow().is_empty(),
            "nothing retires while the old names are still the live ones"
        );
    }

    #[test]
    fn a_fail_closed_publish_refusal_is_not_retryable() {
        // Rule 6: a publisher's own trust verdict must not be laundered into an
        // availability stall a retry loop keeps charging.
        for (error, retryable) in [
            (WritePublishError::NotLanded, true),
            (WritePublishError::LostRace, true),
            (WritePublishError::RegistryFull, true),
            (WritePublishError::Rejected, false),
        ] {
            let err = WriteRotateError::Publish {
                stage: "republish",
                node_id: SCOPE,
                error,
            };
            assert_eq!(err.is_retryable(), retryable);
        }
    }

    #[test]
    fn mid_wave_crash_resumes_from_published_records_only() {
        // Crash the wave at the canonical re-point — past the root republish, so
        // published state holds the moved root — then resume with a FRESH
        // orchestrator, a fresh publisher, and an entropy stream that would mint a
        // DIFFERENT seed. Nothing is handed in: the resume converges on the first
        // run's names or not at all.
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let state = WaveState::default();
        let resolver = tree_on(state.clone());
        let current_root = old_name_of(&SCOPE);
        let minted = SeededEntropy::first_draw(9);

        // First attempt lands every republish, then dies on the pointer flip.
        let crashing = FakePublisher::refusing(state.clone(), RepointChannel::ScopePointer);
        let err = block_on(async {
            let mut e = SeededEntropy::new(9);
            rotate_scope_write(
                &mut e,
                &resolver,
                &crashing,
                &plan(&owner, &c, &sig, &current_root),
            )
            .await
        })
        .expect_err("the wave crashes mid-flight");
        assert_eq!(err.check(), "publish-failed");
        assert_eq!(
            state.published.borrow().len(),
            5,
            "the whole subtree republished before the flip failed"
        );
        assert!(
            state.repoint_channels.borrow().is_empty(),
            "no re-point before the wave completed"
        );

        // Resume: a brand-new orchestrator + publisher over the same durable state.
        let resume_pub = FakePublisher::new(state.clone());
        let outcome = block_on(async {
            let mut e = SeededEntropy::new(123); // a DIFFERENT stream — a fresh mint would diverge
            rotate_scope_write(
                &mut e,
                &resolver,
                &resume_pub,
                &plan(&owner, &c, &sig, &current_root),
            )
            .await
        })
        .expect("the resumed wave completes");

        assert_eq!(outcome.new_write_epoch, 5);
        assert_eq!(
            outcome.new_root_name,
            derive_write_name(&minted, &SCOPE),
            "the resume ran on the first run's published seed, not a fresh mint"
        );
        assert_ne!(
            minted,
            SeededEntropy::first_draw(123),
            "the resume's own stream would have minted a different seed"
        );

        // Every node republished exactly once across BOTH runs — the resume skipped
        // the already-published nodes (proof it read published state, not memory).
        let calls = state.republish_calls.borrow();
        assert_eq!(calls.len(), 5, "all five nodes republished");
        assert!(
            calls.values().all(|&n| n == 1),
            "no node republished twice — resume is idempotent off published records"
        );
        // Across both runs every node was ordered with its children's post-wave
        // names, so a resume leaves no stale child name behind.
        let orders = state.orders.borrow();
        let published: HashMap<[u8; 16], IpnsName> = orders
            .iter()
            .map(|o| (o.node_id, o.new_name.clone()))
            .collect();
        for order in orders.iter() {
            for (child, name) in &order.child_names {
                assert_eq!(name, &published[child]);
            }
        }
        drop(orders);

        // The wave completed: pointer flipped on all three channels, interior retired.
        assert_eq!(state.repoint_channels.borrow().len(), 3);
        assert_eq!(state.retired.borrow().len(), 4);
        assert!(
            !state.retired.borrow().contains(current_root.as_str()),
            "root lingers"
        );
    }

    #[test]
    fn a_recovered_wave_at_another_write_epoch_is_refused_before_any_publish() {
        // Nothing gates the scope pointer, and every re-point this scope ever
        // published lives at the same stable name — so an older owner-signed
        // re-point stays replayable for ever. Requiring the recovered epoch to be
        // the one this run publishes at is what pins a resume to THIS wave.
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let state = WaveState::default();
        let stale_seed = [0x93; SECRET_LEN];
        let resolver = FakeResolver {
            recovery: Some((
                derive_write_name(&stale_seed, &SCOPE),
                stale_seed,
                ROTATED_WRITE_EPOCH - 1,
            )),
            ..tree_on(state.clone())
        };
        let publisher = FakePublisher::new(state.clone());
        let current_root = old_name_of(&SCOPE);

        let err = block_on(async {
            let mut e = SeededEntropy::new(32);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root),
            )
            .await
        })
        .expect_err("a wave at another write epoch is not this run's to resume");
        assert_eq!(err.check(), "resumed-wave-at-another-epoch");
        assert!(!err.is_retryable(), "a replayed re-point is not a stall");
        assert!(
            state.published.borrow().is_empty(),
            "nothing published on a refused recovery"
        );
    }

    #[test]
    fn a_recovered_seed_that_does_not_derive_its_root_name_is_refused() {
        // The recovery's two halves must agree: a seed that derives some other
        // name is what a forged write-plane history link, or a root published
        // under a seed nothing ties to it, would hand back. Resuming on it would
        // republish the whole subtree under attacker-chosen names, so the wave
        // refuses before it touches the publisher.
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let state = WaveState::default();
        let resolver = FakeResolver {
            // A real published root name, but not the one that seed derives.
            recovery: Some((
                derive_write_name(&[0x92; SECRET_LEN], &SCOPE),
                [0x91; SECRET_LEN],
                ROTATED_WRITE_EPOCH,
            )),
            ..tree_on(state.clone())
        };
        let publisher = FakePublisher::new(state.clone());
        let current_root = old_name_of(&SCOPE);

        let err = block_on(async {
            let mut e = SeededEntropy::new(31);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root),
            )
            .await
        })
        .expect_err("a seed that does not derive its own root name is refused");
        assert_eq!(err.check(), "resumed-seed-not-at-its-root");
        assert!(!err.is_retryable(), "no retry reconciles the two halves");
        assert!(
            state.published.borrow().is_empty(),
            "nothing published on a refused recovery"
        );
    }

    #[test]
    fn a_crash_before_the_root_publishes_has_no_seed_to_recover() {
        // The moved root is the only published carrier of the fresh seed, so a
        // crash before it lands leaves nothing to recover: the retry mints its own
        // and the first run's interior names are orphaned — the fail-safe
        // direction the module documents.
        let owner = owner();
        let (c, sig) = commitment(&owner);
        let state = WaveState::default();
        let resolver = tree_on(state.clone());
        let current_root = old_name_of(&SCOPE);

        let crashing = FakePublisher::failing_after(state.clone(), 2);
        block_on(async {
            let mut e = SeededEntropy::new(41);
            rotate_scope_write(
                &mut e,
                &resolver,
                &crashing,
                &plan(&owner, &c, &sig, &current_root),
            )
            .await
        })
        .expect_err("the wave crashes before the root republish");
        assert!(
            state.published_root.borrow().is_none(),
            "no moved root published, so nothing carries the seed"
        );
        let orphaned: Vec<String> = state.published.borrow().iter().cloned().collect();
        assert_eq!(orphaned.len(), 2, "two interior names landed");

        let resume_pub = FakePublisher::new(state.clone());
        let outcome = block_on(async {
            let mut e = SeededEntropy::new(42);
            rotate_scope_write(
                &mut e,
                &resolver,
                &resume_pub,
                &plan(&owner, &c, &sig, &current_root),
            )
            .await
        })
        .expect("the retry completes on a freshly minted seed");

        assert_eq!(
            outcome.new_root_name,
            derive_write_name(&SeededEntropy::first_draw(42), &SCOPE),
            "the retry minted its own seed"
        );
        for name in &orphaned {
            assert!(
                !state.retired.borrow().contains(name),
                "the first run's names are orphaned, never retired"
            );
        }
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
        let state = WaveState::default();
        let resolver = PostFlipResolver {
            nodes,
            seed: recovered_seed,
            state: state.clone(),
        };
        // The fully-migrated published state: every new name already landed, and
        // the moved root carries the seed the resume recovers.
        for id in [SCOPE, nid(0x02), nid(0x03), nid(0x04), nid(0x05)] {
            let name = derive_write_name(&recovered_seed, &id);
            state
                .published
                .borrow_mut()
                .insert(name.as_str().to_owned());
        }
        *state.published_root.borrow_mut() = Some((
            derive_write_name(&recovered_seed, &SCOPE),
            recovered_seed,
            ROTATED_WRITE_EPOCH,
        ));
        let publisher = FakePublisher::new(state.clone());
        let current_root = old_name_of(&SCOPE);

        block_on(async {
            let mut e = SeededEntropy::new(50);
            rotate_scope_write(
                &mut e,
                &resolver,
                &publisher,
                &plan(&owner, &c, &sig, &current_root),
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
            let mut p = plan(&owner, &c, &sig, &current_root);
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
                &plan(&owner, &c, &sig, &current_root),
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
                &plan(&owner, &c, &sig, &current_root),
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
            let mut p = plan(&owner, &c, &sig, &current_root);
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
