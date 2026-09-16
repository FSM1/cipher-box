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
//! The one owner-identity-signed re-point object flips the scope pointer record,
//! and at the vault anchor the indexed vault pointer too (see [`RepointChannel`]).
//! One gated object, sealed once per channel, and neither channel is
//! best-effort: an outcome is proof every channel this rotation owed landed.
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
//! ([`WriteRotateError::ResumedSeedNotAtItsRoot`]).
//!
//! A resumed wave walks its own moved copies ([`ResumedRoot`]), and a resume and
//! a fresh start alike re-derive what the epoch below them superseded from
//! [`RecoveredWave::superseded_write_scope_seed`] — published state again, no
//! checkpoint. A wave that crashed past its pointer flip has nothing to resume,
//! because the flip made its moved copies the live ones, so the next fresh
//! rotation is what reclaims the interior names it left registered.
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
use cipherbox_core::seal::{GrantSetBindingError, GrantSetCommitment, verify_grant_set_bound};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaSigner, SIGNATURE_LEN as ECDSA_SIG_LEN};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};

use super::eager_set::ResolveFailure;
use crate::entropy::{Entropy, EntropyError, fresh_seed};
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

/// The two re-point channels the wave publishes to (blueprint/engine.md
/// "rotateScopeWrite"). Each names one pointer plane, and both are canonical for
/// the plane they name — there is no best-effort channel. The gate runs on the
/// re-point object, so every channel carries the same vouched fact under its own
/// seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepointChannel {
    /// The scope's stable pointer record — the re-point every rotation flips.
    ScopePointer,
    /// The vault anchor's indexed vault pointer — the cold-start anchor, flipped
    /// only when the rotated scope is the one that pointer names
    /// ([`RotateScopeWritePlan::is_vault_anchor`]).
    VaultPointer,
}

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

/// What [`WriteSubtreeResolver::recover_wave`] read out of published state: the
/// wave still in flight if there is one, and the seed whose interior names this
/// rotation supersedes either way.
pub struct RecoveredWave {
    /// The wave to pick up, or `None` on a fresh rotation, which mints its own
    /// seed instead.
    pub in_flight: Option<ResumedWriteWave>,
    /// The write scope seed one epoch below the wave this rotation publishes,
    /// read off a published root's owner-sealed write history link and accepted
    /// only when it derives the name that root succeeded — which is what proves
    /// it is this scope's own predecessor and not a seed someone else sealed to
    /// the owner's public half.
    ///
    /// It is the only way to name that epoch's interior names: they derive from
    /// it alone, and no live record carries a trace of them. A wave that crashed
    /// after its pointer flipped left them registered and cannot be resumed,
    /// because the flip made its moved copies the live ones, so the next fresh
    /// rotation is where they are reclaimed. `None` leaves them to their EOL,
    /// the fail-safe direction.
    pub superseded_write_scope_seed: Option<SecretBytes>,
}

impl RecoveredWave {
    /// No wave in flight and nothing to reclaim — a scope with no published
    /// predecessor, or one whose evidence did not check out.
    #[must_use]
    pub fn nothing() -> Self {
        Self {
            in_flight: None,
            superseded_write_scope_seed: None,
        }
    }
}

/// The moved root a resumed wave enumerates from: the name
/// [`WriteSubtreeResolver::recover_wave`] handed back, once the recovered seed
/// was proved to derive it, and the owner-vouched write epoch it publishes at.
///
/// A resumed pass must read its own moved copies. The pre-wave root lingers
/// serving the pre-rotation read epoch, so a read rotation adopted mid-wave
/// leaves that record below the live floor while the moved copies its sweep
/// re-keyed sit above it — enumerating the lingering name re-derives exactly the
/// evidence [`WriteWavePublisher::retire`] already refused on, for ever.
///
/// The write epoch travels with the name because a resume leaves the durable
/// write-epoch floor where the pre-wave root can still be read
/// ([`WriteSubtreeResolver::recover_wave`]), so that floor opens nothing at the
/// moved root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumedRoot {
    /// The moved root's `ipnsName`.
    pub name: IpnsName,
    /// The owner-vouched write epoch its write plane is sealed at.
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
    ///
    /// `resumed` anchors the scope root, and only it: `Some` on a resumed pass
    /// ([`ResumedRoot`]), `None` on a fresh one, where the root sits at the name
    /// the plan carries.
    async fn resolve_node(
        &self,
        node_id: &[u8; 16],
        resumed: Option<&ResumedRoot>,
    ) -> Result<WriteScopeNode, ResolveFailure>;

    /// What published records say about this scope's write plane
    /// ([`RecoveredWave`]). The whole of the crash-recovery seam (#26 D8):
    /// entropy versus a published record, never an in-memory checkpoint a crash
    /// would have taken with it.
    async fn recover_wave(&self) -> Result<RecoveredWave, ResolveFailure>;
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
/// - **the root republish runs off the enumeration's own read** — the moved root
///   is owner-signed over a `directChildScopeIndex` only
///   [`WriteSubtreeResolver::resolve_node`] proves the boundaries of, so an
///   implementor MUST refuse a root it never enumerated, not re-read one.
pub trait WriteWavePublisher {
    /// Whether a record is already published at `new_name` — the resume query,
    /// answered from published state only (no in-memory carry across a crash).
    async fn is_republished(&self, new_name: &IpnsName) -> Result<bool, WritePublishError>;

    /// Register-first then CAS-publish `node`'s record at its freshly derived
    /// name, rewriting [`RepublishedNode::child_names`] into its read body.
    async fn republish(&self, node: &RepublishedNode) -> Result<(), WritePublishError>;

    /// Batch-retire interior old names at wave completion. MUST run only **after**
    /// the root re-point, and MUST NOT include the old root name (it lingers).
    /// The wave's one irreversible step, so an implementor MUST re-read the
    /// read-epoch floor here and refuse on a rise — its evidence being the epochs
    /// its own [`WriteSubtreeResolver::resolve_node`] reads gated, which is why
    /// the resolver and the publisher must be one value.
    async fn retire(&self, old_names: &[IpnsName]) -> Result<(), WritePublishError>;

    /// Refuse a re-point this build's own gate would reject
    /// ([`floor::repoint_regression`](crate::gate::floor::repoint_regression)),
    /// **before** the owner signs it.
    async fn check_repoint_publishable(
        &self,
        repoint: &RepointObject,
    ) -> Result<(), WritePublishError>;

    /// Publish the owner-signed re-point `block` on one [`RepointChannel`].
    async fn publish_repoint(
        &self,
        channel: RepointChannel,
        block: &[u8],
    ) -> Result<(), WritePublishError>;
}

/// Why one write-plane op did not durably land. Only [`Self::Rejected`] is a
/// trust verdict a retry cannot clear (rule 6: a fail-closed rejection is never
/// laundered into an availability stall).
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
    /// re-resolve, a read body whose children disagree with the wave, a retire
    /// batch naming the lingering root, or a re-point channel the caller asked
    /// for and gave no capability to publish on. Re-running reaches the same
    /// verdict.
    Rejected,
}

/// The class label a re-point seal failure carries. `PointerError` serves the
/// pointer plane too, so its rotation reading lives here.
fn pointer_error_class(error: &PointerError) -> &'static str {
    match error {
        PointerError::NotOwnerSession => "capability",
        PointerError::Entropy(_) | PointerError::Seam(_) | PointerError::Unavailable => {
            "availability"
        }
        PointerError::Open(error) => error.class(),
        PointerError::IndexRegression { .. } => "trust",
    }
}

impl WritePublishError {
    /// The class label a reject vector carries for this failure.
    pub fn class(&self) -> &'static str {
        match self {
            Self::NotLanded | Self::LostRace | Self::RegistryFull => "availability",
            Self::Rejected => "trust",
        }
    }
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
    /// The owner-signed grant-set commitment — the owner-only anchor.
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
    /// Whether this scope is the vault anchor — the scope the session's indexed
    /// vault pointer names ([`RepointChannel::VaultPointer`]).
    pub is_vault_anchor: bool,
}

/// A completed write rotation. Holding one is proof the whole subtree was
/// republished, every re-point channel this rotation owed landed, and interior
/// old names retired — an incomplete wave returns [`WriteRotateError`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRotationOutcome {
    /// The new write epoch the scope was cut to (`current_write_epoch + 1`).
    pub new_write_epoch: u64,
    /// The scope root's new `ipnsName` (`currentRootName` in the re-point object).
    pub new_root_name: IpnsName,
    /// The number of interior (non-root) nodes in the scope's subtree — the wave
    /// covers all of them, though a resumed wave may have republished some in a
    /// prior run (skipped via `is_republished`).
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
        /// `repoint-precheck` / `repoint-<channel>`).
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
    /// Every write-plane rotation check, in declaration order — the surface
    /// `crates/engine/tests/kat_rotation.rs` pins (see the module header for the
    /// prefix rule).
    pub const CHECKS: &'static [&'static str] = &[
        "rot-write-not-owner",
        "rot-write-commitment-scope-mismatch",
        "rot-write-epoch-exhausted",
        "rot-write-write-epoch-not-advancing",
        "rot-write-identity-repoint",
        "rot-write-entropy-error",
        "rot-write-resumed-seed-not-at-its-root",
        "rot-write-resumed-wave-at-another-epoch",
        "rot-write-resolve-failed",
        "rot-write-publish-failed",
        "rot-write-repoint-seal-failed",
    ];

    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            WriteRotateError::NotOwner => "rot-write-not-owner",
            WriteRotateError::CommitmentScopeMismatch => "rot-write-commitment-scope-mismatch",
            WriteRotateError::EpochExhausted => "rot-write-epoch-exhausted",
            WriteRotateError::WriteEpochNotAdvancing => "rot-write-write-epoch-not-advancing",
            WriteRotateError::IdentityRepoint => "rot-write-identity-repoint",
            WriteRotateError::Entropy(_) => "rot-write-entropy-error",
            WriteRotateError::ResumedSeedNotAtItsRoot => "rot-write-resumed-seed-not-at-its-root",
            WriteRotateError::ResumedWaveAtAnotherEpoch => {
                "rot-write-resumed-wave-at-another-epoch"
            }
            WriteRotateError::Resolve { .. } => "rot-write-resolve-failed",
            WriteRotateError::Publish { .. } => "rot-write-publish-failed",
            WriteRotateError::Repoint(_) => "rot-write-repoint-seal-failed",
        }
    }

    /// The class label used in reject vectors. Exhaustive, so a new variant must
    /// state its class rather than inherit `"trust"`.
    pub fn class(&self) -> &'static str {
        match self {
            WriteRotateError::NotOwner
            | WriteRotateError::CommitmentScopeMismatch
            | WriteRotateError::WriteEpochNotAdvancing
            | WriteRotateError::IdentityRepoint
            | WriteRotateError::ResumedSeedNotAtItsRoot
            | WriteRotateError::ResumedWaveAtAnotherEpoch => "trust",
            WriteRotateError::EpochExhausted => "over-cap",
            WriteRotateError::Entropy(_) => "availability",
            WriteRotateError::Resolve { reason, .. } => reason.class(),
            WriteRotateError::Publish { error, .. } => error.class(),
            WriteRotateError::Repoint(error) => pointer_error_class(error),
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
/// then the owner-signed re-point publishes to every channel this rotation owes
/// ([`RepointChannel`]), and finally the interior old names batch-retire (the old
/// root lingers). Every effect is idempotent, so a crashed wave re-runs to the
/// same terminal state (module docs).
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
    verify_grant_set_bound(
        &plan.owner_identity_signer.verifying_key(),
        plan.commitment,
        &current_sig,
        plan.current_root_name.as_str().as_bytes(),
    )
    .map_err(|e| match e {
        GrantSetBindingError::Verify(_) => WriteRotateError::NotOwner,
        GrantSetBindingError::ScopeMismatch => WriteRotateError::CommitmentScopeMismatch,
    })?;

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
    let superseded_seed: Option<Zeroizing<[u8; SECRET_LEN]>> = resumed
        .superseded_write_scope_seed
        .map(|prev| Zeroizing::new(*prev.as_bytes()));
    let mut resumed_root: Option<ResumedRoot> = None;
    let write_scope_seed: Zeroizing<[u8; SECRET_LEN]> = match resumed.in_flight {
        Some(wave) => {
            if wave.write_epoch != new_write_epoch {
                return Err(WriteRotateError::ResumedWaveAtAnotherEpoch);
            }
            let seed = Zeroizing::new(*wave.write_scope_seed.as_bytes());
            if derive_write_name(&seed, &scope_id) != wave.root_name {
                return Err(WriteRotateError::ResumedSeedNotAtItsRoot);
            }
            resumed_root = Some(ResumedRoot {
                name: wave.root_name,
                write_epoch: wave.write_epoch,
            });
            seed
        }
        None => fresh_seed(entropy).map_err(WriteRotateError::Entropy)?,
    };

    // 4) Enumerate the subtree from published records. BFS yields the root first,
    //    then level order; the wave processes descendants child-first (reversed) and
    //    the root last.
    let bfs = collect_subtree(resolver, scope_id, resumed_root.as_ref()).await?;
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
        // Retire only a superseded name, never one a node still lives at
        // (never orphan).
        if node.current_name != new_name {
            interior_old_names.push(node.current_name.clone());
        }
        // The names the epoch below the live one sat at derive from its own
        // seed, and a crashed wave may have left them registered.
        if let Some(prev) = superseded_seed.as_ref() {
            let old_name = derive_write_name(prev, &node.node_id);
            if old_name != new_name && old_name != node.current_name {
                interior_old_names.push(old_name);
            }
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

    // 7) Seal the owner-signed re-point object and flip every plane this
    //    rotation owes.
    let repoint = build_repoint_object(
        scope_id,
        new_root_name.clone(),
        plan.current_root_name.clone(),
        new_write_epoch,
        plan.current_write_epoch,
        plan.min_read_epoch,
    )?;
    publisher
        .check_repoint_publishable(&repoint)
        .await
        .map_err(|error| WriteRotateError::Publish {
            stage: "repoint-precheck",
            node_id: scope_id,
            error,
        })?;
    let pointer_read_key = kdf::pointer_read_key(plan.owner_pointer_seed, &scope_id);
    for channel in repoint_channels(plan.is_vault_anchor) {
        // Sealed per channel, not once and copied. A fresh nonce makes each block
        // globally unique, so identical bytes at two names would be a
        // zero-false-positive join between the account-level vault-pointer name
        // and a scope-pointer name every grantee of that scope holds.
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
            .publish_repoint(*channel, &block)
            .await
            .map_err(|error| WriteRotateError::Publish {
                stage: repoint_stage(*channel),
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

/// The channels one rotation owes, in publish order: the scope pointer first,
/// because a lag there costs a live reader a poll interval and a lag at the
/// anchor costs a cold start its whole boot.
fn repoint_channels(is_vault_anchor: bool) -> &'static [RepointChannel] {
    if is_vault_anchor {
        &[RepointChannel::ScopePointer, RepointChannel::VaultPointer]
    } else {
        &[RepointChannel::ScopePointer]
    }
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

    // The resolver gated this node at the very name the wave moves it to, so a
    // prior run already moved it and there is nothing to publish. Checked before
    // `is_republished`, whose fan-out can transiently miss a live record: the root
    // arm's re-seal would then refuse the epoch that record already carries, and
    // rule 6 forbids burning the wave on an availability blip.
    if node.current_name == *new_name {
        return Ok(());
    }

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
        RepointChannel::VaultPointer => "repoint-vault-pointer",
    }
}

/// BFS the write scope's subtree from `root_id` via the resolver: root first, then
/// level order. A `node_id`-keyed visited set terminates diamonds/cycles fail-
/// closed (a tree has none, but the walk never loops). An unresolvable node aborts
/// — a partial subtree is never a complete wave.
async fn collect_subtree<R: WriteSubtreeResolver>(
    resolver: &R,
    root_id: [u8; 16],
    resumed: Option<&ResumedRoot>,
) -> Result<Vec<WriteScopeNode>, WriteRotateError> {
    let mut visited: BTreeSet<[u8; 16]> = BTreeSet::new();
    let mut order: Vec<WriteScopeNode> = Vec::new();
    let mut queue: VecDeque<[u8; 16]> = VecDeque::new();

    visited.insert(root_id);
    queue.push_back(root_id);

    while let Some(id) = queue.pop_front() {
        let node = resolver
            .resolve_node(&id, resumed)
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
mod tests;
