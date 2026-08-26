//! The facade — the engine's single async command-and-event surface
//! (blueprint/engine.md "Facade").
//!
//! Designed to be wrapped, not extended: desktop calls it directly in the
//! Tauri process; web wraps it via `crates/wasm` inside a dedicated worker,
//! with the RPC layer and tab leadership owned by `packages/client`
//! (#28 D3/D4). The engine's contract is only this: one live instance is
//! the single writer, and every trust decision already happened below the
//! facade — hosts render, they never decide.
//!
//! The surface shape (constructor over the whole seam set, `start(secret)`,
//! the [`Command`] enum, the [`Event`] stream) is frozen. Metadata intent ops
//! stage through the durable op queue, reads render the gate-passing base
//! snapshot ⊕ pending-op overlay (blueprint/engine.md "Sync core: State law"),
//! and every successful stage emits [`Event::SnapshotUpdated`]. A command whose
//! slice has not landed returns [`EngineError::Unimplemented`].

use core::cell::{Cell, RefCell};
use core::fmt;
use core::pin::Pin;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use cipherbox_core::codec::RedactedBytes;
use cipherbox_core::content::encode_content_cid_str;
use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildScopeRef, GrantLedgerEntry, GrantSection, GrantSetCommitment, ReadBody, Version,
    seal_content_key, sign_grant_set,
};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::x25519::X25519Secret;
use futures_channel::mpsc;
use futures_core::Stream;
use zeroize::Zeroizing;

use crate::api::{ApiClient, ApiError, IdentityChallengeSigner};
use crate::content::budget::{Refusal, ReservationId};
use crate::content::{
    ContentKey, ContentProfile, ContentWriter, Gateway, GatewayConfig, OpenError, Refused,
    RootManifest, SealError, SessionBearer, StagingLedger, open_content_range, open_content_root,
    pre_flight_quota_check, read_pinned_range, sealed_total_bytes,
};
use crate::entropy::{Entropy, SharedEntropy, fresh_bytes, fresh_ephemeral};
use crate::gate::{GateError, floor};
use crate::grants::received_status::{ReceivedShareStatus, ReceivedVerdicts};
use crate::grants::{
    AcceptError, AcceptOutcome, ClaimOutcome, CommittedScope, Contact, ContactStore,
    ContactStoreError, ConvertedClaim, CreateGrantError, EphemeralInvitee, GrantRecipient,
    GranteeScopePlan, InviteClaim, InviteError, InviteFragment, InviteMintError, InviteMintPlan,
    InviteStore, InviteStoreError, MAX_DISPLAY_NAME_BYTES, MintedInviteLink, OwnerAuthority,
    OwnerGrantKeys, ParentScopePlan, PublishedGrantBlob, ReceivedShareStore,
    ReceivedShareStoreError, ResolutionClass, SharePointer, StagingContactStore,
    StagingInviteStore, StagingReceivedShareStore, UNATTESTED_IDENTITY_PK, accept_share,
    convert_invite_claim, create_read_grant, enforce_committed_ledger, import_contact,
    locate_invite_link, mint_invite_link, partition_scope_links, post_invite_claim,
    recipient_blinded_tag, resolve_recipient, row_is_owner_attested,
};
use crate::mailbox::{locate_verified, poll_verified, post_sealed};
use crate::net::author::ENVELOPE_V;
use crate::net::cut::OwnerCutNet;
use crate::net::record_publish::RecordPublishError;
use crate::net::retire::{OrphanHeads, retire};
use crate::net::rotation::scope_name;
use crate::net::rotation::{GatedRoots, RotationAncestry, SweptScopeState};
use crate::net::{
    Adopter, ChildAdopter, ChildResolveError, EolRenewResult, FolderRefresh, HeldMaterial,
    HeldRecord, HeldRecords, LivenessControl, OwnerRotationKeys, OwnerRotationNet, PointerConsult,
    PointerConsultArm, PointerConsultError, PublishError, PublishOutcome, RE_PUT_INTERVAL,
    RecordPointerFetch, ResolveOutcome, RootAdopter, VaultProvisionNet, assemble_candidate,
    eol_renew_pass, fanout_get_verify, keyless_re_put, refresh_base_from_outcome, resolve_and_hold,
    resolve_child, run_liveness_loop,
};
use crate::owner_keys::{OwnerSeedKeys, OwnerSessionKeys};
use crate::profile::SyncTimingProfile;
use crate::rotation::{
    AscentAuthority, CascadeTarget, CommittedSet, GrantCutPlan, MAX_ROTATION_ATTEMPTS, ResealError,
    ResealSeeds, ResealedScopeRoot, ResolveFailure, Retryable, RevokeError, RotateError,
    RotateScopePlan, ScopeRootIdentity, ScopeRootPublisher, WriteHistory, WriteRevokeKind, bounded,
    derive_write_name, reseal_scope_root, revoke_read_grant, revoke_write_grant, rotate_on_cut,
    rotate_scope, run_sweep,
};
use crate::seams::{
    BoxedTask, CredentialStore, FloorStore, LiveSeam, Mailbox, OpId, RecordTransport, Scheduler,
    SeamError, SeamResult, SeamSet, SeamTypes, SnapshotCache, StagingStore, UnixMillis,
};
use crate::session::SessionIdentity;
use crate::settings::{
    PlacementRefusal, PlacementSource, SessionPlacement, SettingsPublishError, VaultSettings,
    decide_placement, load_settings, placement_of, publish_settings,
};
use crate::storage_policy::StoragePolicy;
use crate::sync::boot::{ColdStartError, ColdStartOutcome, ColdStartParams, cold_start};
use crate::sync::cancel::UploadCancels;
use crate::sync::drain::{Drain, DrainReport, DrainScope, published_op_mark};
use crate::sync::model::{NodeMeta, Snapshot, collation_key};
use crate::sync::op::{NewNode, Op, OpKind, Replaced, ScopeCrossing, StagedContent};
use crate::sync::overlay::apply_overlay;
use crate::sync::pointer::PointerFetch;
use crate::sync::project::project_child_version;
use crate::sync::provision::{
    GENESIS_VAULT_POINTER_INDEX, ProvisionError, ProvisionOutcome, ProvisionPlan, ProvisionedVault,
    VaultPointerProbe, provision_vault,
};
use crate::sync::rebase::{QueueScan, QueueScanMemo, decode_queue};
use cipherbox_core::hex::lower as hex_lower;

pub use crate::sync::drain::{BlockedOp, SettingsHold};
pub use crate::sync::rebase::DeadLetterReason;
use crate::sync::record::{RecordReader, RecordSeal};
pub use crate::sync::refresh::ForcedPass;
use crate::sync::refresh::{ManualRefresh, RefreshVerdict};
use crate::sync::staging::{LiveBlocks, collect_orphans, release_version_blocks, stage_op};
use crate::sync::staleness::{Connectivity, classify};
use crate::sync::tick::{
    FocusWindow, ResolveMode, TickControl, consult_scopes, consult_scopes_due, focus_folders,
    focus_folders_due, focus_window_expired, on_access_refresh_due, resolve_mode, run_tick_loop,
};

/// The stable 16-byte node identifier (`id16`, blueprint/core.md). Public,
/// non-secret, and location-independent — routes and commands key on it,
/// never on rotating `ipnsName`s.
///
/// `Ord` orders by the raw id bytes: a non-secret, location-independent total
/// order that keeps the sync core's snapshot maps and dead-letter reporting
/// deterministic across platforms.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct NodeId(pub [u8; 16]);

/// A live write handle, minted by [`Engine::begin_write`].
///
/// Content never crosses the facade as one buffer: the client slices the file
/// and feeds chunks through [`Engine::push_chunk`], the engine seals and stages
/// each, and the op is journaled once at [`Engine::commit_write`] — so peak heap
/// is one chunk however large the file (blueprint/engine.md "Content plane").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WriteHandle(pub u64);

/// A live ranged-read stream, minted by [`Engine::open_content_stream`].
///
/// The head version and its verified DAG root manifest are pinned when the
/// stream opens, so every window [`Engine::read_stream`] serves is a slice of
/// that one authenticated object. Re-resolving per window would let a head
/// change mid-stream splice two versions into one response body, which no
/// downstream check can detect — every byte is still CID-verified and unsealed
/// under its own version's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamHandle(pub u64);

/// What a write handle is writing to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteTarget {
    /// A new file under `parent`, created by the same commit.
    NewFile {
        /// Parent folder.
        parent: NodeId,
        /// Name as entered (uniqueness uses the strict comparator).
        name: String,
    },
    /// A new version of a file that already exists.
    Version {
        /// Target file node.
        node: NodeId,
    },
}

/// What a created node is. Kind is sealed inside the read-body on the wire;
/// at the facade it is plain intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NodeKind {
    /// A file node.
    File,
    /// A folder node.
    Folder,
}

/// What the op queue holds for a node, strongest class first: a queued content
/// write outranks a queued metadata mutation. The variant order **is** the rank
/// (a node with both queued reports `Content`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum PendingClass {
    /// No queued op targets the node.
    #[default]
    None,
    /// A queued op mutates only the node's metadata (create without content,
    /// rename, relink, delete).
    Metadata,
    /// A queued op writes new content bytes for the node.
    Content,
}

/// A node's host-facing attributes, projected from the rendered view for a
/// FUSE getattr/readdir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAttrs {
    /// Stable node id.
    pub id: NodeId,
    /// Display name, as entered.
    pub name: String,
    /// File or folder.
    pub kind: NodeKind,
    /// Plaintext content size in bytes, once the content plane projects it.
    pub size: Option<u64>,
    /// Modification time (Unix millis), once projected.
    pub mtime: Option<u64>,
    /// Retained version count, `None` until projected.
    pub content_version: Option<u64>,
}

/// Minimal filesystem-level counters for a FUSE statfs. Node count only:
/// quota and byte accounting live on the API client and are not wired at the
/// facade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatFs {
    /// Nodes reachable from the root in the rendered view.
    pub nodes: u64,
}

/// One ancestor step in a [`SnapshotView`]'s breadcrumb trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breadcrumb {
    /// Stable node id.
    pub id: NodeId,
    /// Display name, as entered (empty for the root).
    pub name: String,
}

/// One direct child in a [`SnapshotView`], projected key-free from the
/// rendered view plus the op-queue/dead-letter bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotChild {
    /// Stable node id.
    pub id: NodeId,
    /// Display name, as entered.
    pub name: String,
    /// File or folder.
    pub kind: NodeKind,
    /// Plaintext content size in bytes, once the content plane projects it.
    pub size: Option<u64>,
    /// Modification time (Unix millis), once projected.
    pub mtime: Option<u64>,
    /// What the op queue holds for this node.
    pub pending: PendingClass,
    /// Whether a retained dead-lettered op maps to this node.
    pub dead_letter: bool,
    /// Retained version count, `None` until projected.
    pub content_version: Option<u64>,
}

/// Which budget refused a write, and what a user can do about it. A full device
/// is not a full account (different errnos on desktop — `ENOSPC` vs `EDQUOT`,
/// blueprint/desktop.md), and the three device-side refusals call for three
/// different actions: nothing helps here, free some space, or wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverBudgetCause {
    /// The write is larger than the most this platform will ever stage, so no
    /// amount of free space or drain progress admits it.
    StagingLimit,
    /// This device's measured storage headroom cut the staging budget below the
    /// platform cap, and the write does not fit what is left.
    DeviceFull,
    /// The write fits the budget, but bytes already staged and reserved by other
    /// writes leave too little right now — the drain frees room as it uploads.
    StagingBacklog,
    /// Too many uploads are already open; one must finish or be cancelled first.
    TooManyWrites,
    /// The host could not measure storage headroom, so nothing can be admitted.
    /// Distinct from a measured zero, which is a device known to be full.
    StorageUnmeasured,
    /// The account's hosted storage quota refused the bytes.
    AccountQuota,
}

/// Whose budget refused, which is the axis a POSIX host adapter needs and the
/// only one it may decide from: `ENOSPC` for [`Device`](RefusedBudget::Device),
/// `EDQUOT` for [`Account`](RefusedBudget::Account) (blueprint/desktop.md
/// "Reads, writes, and the never-block law").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedBudget {
    /// This device's staging budget, in every form it can run out.
    Device,
    /// The account's hosted storage quota.
    Account,
}

impl OverBudgetCause {
    /// Whose budget this cause names.
    pub fn budget(self) -> RefusedBudget {
        match self {
            OverBudgetCause::StagingLimit
            | OverBudgetCause::DeviceFull
            | OverBudgetCause::StagingBacklog
            | OverBudgetCause::TooManyWrites
            | OverBudgetCause::StorageUnmeasured => RefusedBudget::Device,
            OverBudgetCause::AccountQuota => RefusedBudget::Account,
        }
    }
}

/// One imported contact, projected key-free for a sharing UI. The engine
/// re-verifies the stored contact code before a row appears here, so a row is
/// proof the binding held ([`Contact`](crate::grants::Contact)).
///
/// The identity key alone: a grant names its recipient by it, and the engine
/// re-resolves the matching encryption subkey from the binding-verified book
/// rather than from anything a host hands back
/// ([`recipient_contact`](Engine::recipient_contact)).
#[derive(Clone, PartialEq, Eq)]
pub struct SharingContact {
    /// The peer's secp256k1 identity key, compressed SEC1 — the grant ledger's
    /// recipient label and the address their mailbox answers at.
    pub identity_public_key: Vec<u8>,
}

/// A peer's identity key is a stable cross-service identifier for a third party,
/// so a derived `{:?}` would file the owner's whole contact book in host logs
/// (the [`Command`] impl below withholds the same bytes for the same reason).
impl fmt::Debug for SharingContact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharingContact")
            .field(
                "identity_public_key",
                &RedactedBytes::of(&self.identity_public_key),
            )
            .finish()
    }
}

/// One grant standing on a rendered scope, projected from the scope root's own
/// owner-signed grant ledger — the engine's truth, not a record of what this
/// session happened to issue.
#[derive(Clone, PartialEq, Eq)]
pub struct SharingGrant {
    /// The recipient's secp256k1 identity key, which joins the row to a
    /// [`SharingContact`]. All-zero for a row whose recipient the owner's own
    /// binding signature does not vouch for, which joins to no contact.
    pub recipient_identity_public_key: Vec<u8>,
    /// The permission the scope root commits for this recipient.
    pub permission: Permission,
}

impl fmt::Debug for SharingGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharingGrant")
            .field(
                "recipient_identity_public_key",
                &RedactedBytes::of(&self.recipient_identity_public_key),
            )
            .field("permission", &self.permission)
            .finish()
    }
}

/// The invite-link standing this owner has at one scope, as a host renders the
/// link half of a share dialog. Nothing here is key material: the link's own
/// bytes stay in the owner's records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharingInviteLinks {
    /// The scope carries exactly one link the owner recorded **and** its own
    /// owner-signed commitment still carries — the link
    /// [`Command::RevokeInviteLink`] cuts and [`Command::ConvertInviteClaims`]
    /// converts against.
    pub live: bool,
    /// The live link's deadline in Unix millis, or `None` where it does not
    /// expire or where there is no live link.
    pub expires_at: Option<UnixMillis>,
    /// The recorded deadline has passed, read against the engine's clock rather
    /// than a host's. A conversion also honours the published row's deadline,
    /// which a write-grantee can shorten, so a link this reports claimable may
    /// still be refused — never the reverse.
    pub expired: bool,
    /// This owner's records at the scope that its commitment no longer carries —
    /// what [`Command::PruneInviteLinks`] drops.
    pub spent: u32,
}

/// What one scope's own record says about sharing, when this read reached it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSharing {
    /// The grants the scope root's ledger commits, ordered as it commits them.
    /// Empty for a node that is not a scope root: nothing is granted there.
    pub grants: Vec<SharingGrant>,
    /// Whether a further share of the scope — a grant or an invite link — would
    /// be accepted: a share mints a fresh scope at the node, which `share_scope`
    /// refuses where one already stands.
    pub can_mint_share: bool,
    /// This owner's invite links there, absent where those records would not
    /// open — never an empty standing a host would draw as "no link here".
    pub invite_links: Option<SharingInviteLinks>,
}

/// A key-free read of the sharing state a host renders for one scope: this
/// vault's whole verified contact book, and the grants the scope's own record
/// commits — the same altitude as [`SnapshotView`], and the read that lets a UI
/// stop mirroring its own command outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingView {
    /// The scope root this read is for.
    pub scope: NodeId,
    /// Every contact this vault has imported, ordered as the book stores them.
    pub contacts: Vec<SharingContact>,
    /// `None` where this read could not reach the scope root — absence a host
    /// must not paint as "shared with nobody".
    pub state: Option<ScopeSharing>,
}

/// One share this vault accepted, as a host renders it at `/shared`
/// (blueprint/web-client.md): the bookmark's key-free discovery fields plus the
/// engine's own resolution verdict.
///
/// The label and the permission are the ones the accept committed; the scope
/// root is the authority on both, so [`resolution`](Self::resolution) is what
/// says whether the share still stands.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedShareRow {
    /// The shared scope's id — this row's stable identity, and the handle a
    /// browse opens it under. The scope root's `ipnsName` is deliberately not
    /// projected: a write rotation moves it, and the durable list seals it.
    pub scope: NodeId,
    /// The sharer's identity key as the accepted bookmark holds it, which the
    /// accept flow bound to a verified contact before writing.
    pub sharer_identity_public_key: Vec<u8>,
    /// The display label the share was accepted under.
    pub display_name: String,
    /// The permission the owner-signed commitment granted at accept.
    pub permission: Permission,
    /// The engine's classification of this share's latest resolve, or `None`
    /// when no pass has resolved it yet (`crate::grants::revocation`).
    pub resolution: Option<ResolutionClass>,
}

impl fmt::Debug for ReceivedShareRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedShareRow")
            .field("scope", &self.scope)
            .field(
                "sharer_identity_public_key",
                &RedactedBytes::of(&self.sharer_identity_public_key),
            )
            .field("display_name", &self.display_name)
            .field("permission", &self.permission)
            .field("resolution", &self.resolution)
            .finish()
    }
}

/// One retained dead-lettered op and why it will never publish. The reason is
/// the whole surface: "the folder this was going into no longer exists" and
/// "this queued change is corrupt" call for different user actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadLetter {
    /// The dead-lettered op.
    pub op_id: OpId,
    /// Why it dead-lettered.
    pub reason: DeadLetterReason,
}

/// What a session owes the user outside any one folder — the compensation
/// channel for work already acked at journal time, which is why none of it may
/// retro-fail an operation that already returned success (blueprint/desktop.md
/// "Conflicts, dead letters, and rotation").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    /// Every retained dead-lettered op, with its reason.
    pub dead_letters: Vec<DeadLetter>,
    /// The over-quota hold, if the drain has one. Read rather than evented:
    /// this is a state that *clears*, and a lost "resumed" would strand a host
    /// on a blockage that is gone.
    pub blocked: Option<BlockedOp>,
    /// The settings-refused hold, if the drain has one. Read for the same
    /// reason as `blocked`, and it names the rule so a host can tell the member
    /// which part of their own provider config to fix.
    pub settings_hold: Option<SettingsHold>,
    /// How many durable queue entries this session holds but cannot read
    /// (CONTEXT.md "Retained record"). Deliberately unattributed — it says the
    /// device is not empty, never whose work it holds — and it exists so an
    /// over-budget rejection on an apparently empty vault has an explanation.
    pub retained_records: usize,
    /// The staleness rung at read time.
    pub staleness: Staleness,
}

/// A key-free snapshot of one folder for a host UI paint: its children, its
/// breadcrumb trail, the retained dead letters, and the staleness rung — one
/// internally-consistent read of the rendered view (state law).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotView {
    /// The rendered root node id.
    pub root: NodeId,
    /// The folder this view lists.
    pub folder: NodeId,
    /// That folder's own name, empty at the root. A host cannot recover it from
    /// `ancestors` (which starts at the parent) and must not cache a name across
    /// a navigation, so the view carries it.
    pub folder_name: String,
    /// Direct children, deterministically ordered by node id.
    pub children: Vec<SnapshotChild>,
    /// Ancestor trail from the folder's parent up to and including the root,
    /// nearest first.
    pub ancestors: Vec<Breadcrumb>,
    /// See [`SessionStatus::dead_letters`].
    pub dead_letters: Vec<DeadLetter>,
    /// See [`SessionStatus::blocked`].
    pub blocked: Option<BlockedOp>,
    /// See [`SessionStatus::settings_hold`].
    pub settings_hold: Option<SettingsHold>,
    /// See [`SessionStatus::retained_records`].
    pub retained_records: usize,
    /// See [`SessionStatus::staleness`].
    pub staleness: Staleness,
}

/// Grant permission level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read grant: read seed only.
    Read,
    /// Write grant: read and write seeds.
    Write,
}

impl From<Permission> for cipherbox_core::seal::Permission {
    fn from(permission: Permission) -> Self {
        match permission {
            Permission::Read => Self::Read,
            Permission::Write => Self::Write,
        }
    }
}

impl From<cipherbox_core::seal::Permission> for Permission {
    fn from(permission: cipherbox_core::seal::Permission) -> Self {
        match permission {
            cipherbox_core::seal::Permission::Read => Self::Read,
            cipherbox_core::seal::Permission::Write => Self::Write,
        }
    }
}

/// The staleness ladder (#33 D4): fresh → reconciling → stale → offline.
/// Availability staleness keeps cached views usable indefinitely; trust
/// violations are never staleness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staleness {
    /// View is within the freshness window.
    Fresh,
    /// A background reconcile is in flight (quiet indicator).
    Reconciling,
    /// Past the profile threshold: stale badge, "last synced X ago".
    Stale,
    /// Offline banner.
    Offline,
}

/// The login secret handed to [`Engine::start`], and nowhere else.
///
/// Zeroized on drop. The engine derives everything else in-crate via core's
/// KDF catalog; the secret never leaves engine memory, is never logged, and
/// has no `Clone`.
pub struct LoginSecret(Zeroizing<Vec<u8>>);

impl LoginSecret {
    /// Wraps the raw login secret bytes. The caller should not retain a
    /// copy (web transfers the buffer and zeroes its own).
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Whether the secret is empty (always a caller bug).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the raw secret bytes for in-crate cold-start derivation only.
    /// `pub(crate)` so the secret never leaves engine memory.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for LoginSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginSecret(redacted)")
    }
}

/// Where [`Engine::start`] authenticates and the liveness loop registers
/// renewals — a non-blank API origin, or the named harness mode that has no API.
///
/// [`parse`](Self::parse) is the only way to build a configured base and
/// [`offline`](Self::offline) exists only under `test-kit`, so a shipped host
/// cannot bring up an engine that never authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiBaseUrl(Option<String>);

impl ApiBaseUrl {
    /// The API origin, trimmed of surrounding whitespace. Blank or
    /// whitespace-only is refused.
    pub fn parse(base_url: &str) -> Result<Self, BlankApiBaseUrl> {
        let trimmed = base_url.trim();
        if trimmed.is_empty() {
            return Err(BlankApiBaseUrl);
        }
        Ok(Self(Some(trimmed.to_owned())))
    }

    /// The harness's no-API mode: [`Engine::start`] skips login and the engine
    /// never authenticates.
    #[cfg(feature = "test-kit")]
    pub fn offline() -> Self {
        Self(None)
    }

    /// The configured origin, or `None` in offline mode.
    fn configured(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

/// [`ApiBaseUrl::parse`] refused a blank or whitespace-only base URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlankApiBaseUrl;

impl fmt::Display for BlankApiBaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("apiBaseUrl is required: the engine must authenticate to the API")
    }
}

impl std::error::Error for BlankApiBaseUrl {}

/// Every command a host can issue — the intent ops, grant/rotation/share
/// actions, auth, and manual refresh (blueprint/engine.md "Facade").
///
/// Payloads are scaffold-minimal and harden with the pipeline slices; the
/// variant set is the surface hosts build against.
///
/// `Debug` is hand-written and prints only the variant name: payloads
/// carry private user data (plaintext content, names, contact bundles),
/// and a derived `{:?}` at any diagnostic site would leak it into logs.
#[derive(Clone, PartialEq, Eq)]
pub enum Command {
    // --- intent ops (#33 D6: every mutation rides the durable op queue) ---
    /// Create an empty node under a parent. A file created **with** content is
    /// a write handle, not a command ([`Engine::begin_write`]).
    Create {
        /// Parent folder.
        parent: NodeId,
        /// Name as entered (uniqueness uses the strict comparator).
        name: String,
        /// File or folder.
        kind: NodeKind,
    },
    /// Delete a node (conditional delete semantics on rebase).
    Delete {
        /// Target node.
        node: NodeId,
    },
    /// Rename a node in place.
    Rename {
        /// Target node.
        node: NodeId,
        /// New name as entered.
        new_name: String,
    },
    /// Move a node to a new parent. Intra-scope this is a pure relink;
    /// cross-scope it re-seals the subtree and may trigger a scope-exit
    /// rotation for the source (#26 D1/D7).
    Relink {
        /// Node being moved.
        node: NodeId,
        /// Destination parent.
        new_parent: NodeId,
    },
    /// Relink and rename a node in one intent op, conditionally replacing the
    /// node at the destination name — a concurrent edit to it wins and the move
    /// auto-suffixes instead ([`OpKind::Move`](crate::OpKind::Move)).
    Move {
        /// Node being moved.
        node: NodeId,
        /// Destination parent (the current parent for a pure rename).
        new_parent: NodeId,
        /// Name at the destination, as entered.
        new_name: String,
        /// The node the destination name currently holds, if any.
        replacing: Option<NodeId>,
    },
    /// Cancel a queued upload, releasing its staged blocks and retiring
    /// whatever of it already reached the network.
    ///
    /// Content-only: for a metadata op a compensating mutation is already
    /// equivalent, while for an upload it is not — a compensating delete still
    /// pushes the whole file through the network and never returns the staging
    /// budget. Guaranteed until the version's last block confirms and refused
    /// after with [`EngineError::TooLateToCancel`], so a cancel never mutates
    /// published state.
    CancelUpload {
        /// The queue id [`Engine::commit_write`] returned.
        op_id: OpId,
    },

    // --- focus and refresh ---
    /// Set the open folder driving the focus window; `None` when no folder
    /// is open.
    SetFocus {
        /// The open folder, if any.
        node: Option<NodeId>,
    },
    /// Manual refresh with nocache semantics everywhere (#33 D4).
    ManualRefresh,

    // --- grants, shares, rotation (owner/grant actions per engine.md) ---
    /// Import a contact code; binding-signature verification is mandatory
    /// and fail-closed (#34 D6).
    ImportContact {
        /// The self-authenticating contact bundle bytes.
        contact_code: Vec<u8>,
    },
    /// Grant a node to an imported contact (owner-only).
    Grant {
        /// Node to grant (folder or file — files are first-class targets).
        node: NodeId,
        /// Recipient's identity public key, as imported.
        recipient_identity_public_key: Vec<u8>,
        /// Read or write.
        permission: Permission,
    },
    /// Revoke a grant (owner-only; read revoke = immediate cut).
    Revoke {
        /// Granted node.
        node: NodeId,
        /// Recipient's identity public key.
        recipient_identity_public_key: Vec<u8>,
    },
    /// Downgrade a write grant to read (owner-only; triggers write
    /// rotation).
    Downgrade {
        /// Granted node.
        node: NodeId,
        /// Recipient's identity public key.
        recipient_identity_public_key: Vec<u8>,
    },
    /// Mint an invite link for a node (#25 D6). The returned URL fragment
    /// carries the ephemeral secret. `node` is a folder inside the vault root's
    /// scope: the link mints that folder's scope, so its bearer starts at the
    /// scope's first epoch and reaches nothing the owner sealed before the link
    /// existed.
    CreateInviteLink {
        /// Node to invite to.
        node: NodeId,
        /// Read or write.
        permission: Permission,
        /// The link's deadline, or `None` for a link that never expires. A
        /// claim past it is refused without owner action; the published copy is
        /// a hint, and this recorded one is the authority.
        expires_at: Option<UnixMillis>,
    },
    /// Revoke an invite link the owner minted at `node` (owner-only). The cut
    /// rotates the read plane, and the grants claims already converted from the
    /// link keep standing — ending a link ends future claims, not the personal
    /// grants it produced.
    RevokeInviteLink {
        /// The node the link was minted at.
        node: NodeId,
    },
    /// Drop the invite records at `node` whose row the scope's own owner-signed
    /// commitment does not carry — the slots a mint spent on a publish that
    /// never landed, and the links a revoke has already cut.
    ///
    /// Fail-closed: it proves a row dead against a gate-passing record before
    /// dropping anything, so a scope that will not resolve prunes nothing.
    PruneInviteLinks {
        /// The node whose links are being pruned.
        node: NodeId,
    },
    /// Claim an invite link from the fragment its URL carries ([`InviteFragment`]).
    ClaimInviteLink {
        /// The link's URL fragment, verbatim.
        fragment: Zeroizing<String>,
    },
    /// Convert the invite claims waiting on this owner's inbox for the link
    /// minted at `node` (owner-only).
    ConvertInviteClaims {
        /// The node the link was minted at.
        node: NodeId,
    },
    /// Accept a share from a polled mailbox pointer or claimed invite.
    AcceptShare {
        /// The sealed share pointer payload.
        sealed_share_pointer: Vec<u8>,
    },
    /// Manual hygiene rotate-now for a scope (same primitives as every
    /// rotation trigger).
    RotateNow {
        /// The scope root to rotate.
        node: NodeId,
    },

    // --- vault settings ---
    /// Publish the account's vault settings record — the member's placement,
    /// provider and retention choice. A confirmed publish binds this session
    /// and enrols the name for renewal.
    SaveVaultSettings {
        /// The settings to seal and publish.
        settings: VaultSettings,
    },

    // --- auth ---
    /// Exchange a host-collected SIWE wallet signature (secondary method;
    /// the engine performs the exchange through its API client).
    SiweLogin {
        /// The signed SIWE message.
        message: String,
        /// The wallet signature bytes.
        signature: Vec<u8>,
    },
    /// Log out: zeroize engine state; durable seams survive by design.
    Logout,
    /// Forget this device: end the session and erase every durable seam —
    /// floors, the op queue, staged bytes, the snapshot cache, and any
    /// persisted refresh token (blueprint/web-client.md "Logout").
    ///
    /// Device-scoped, never account-scoped: the seams never interpret their
    /// contents, so no filter could make a per-account erase complete.
    ForgetDevice,
}

impl Command {
    /// Stable command name for diagnostics and typed unimplemented errors.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Create { .. } => "create",
            Command::Delete { .. } => "delete",
            Command::Rename { .. } => "rename",
            Command::Relink { .. } => "relink",
            Command::Move { .. } => "move",
            Command::CancelUpload { .. } => "cancelUpload",
            Command::SetFocus { .. } => "setFocus",
            Command::ManualRefresh => "manualRefresh",
            Command::ImportContact { .. } => "importContact",
            Command::Grant { .. } => "grant",
            Command::Revoke { .. } => "revoke",
            Command::Downgrade { .. } => "downgrade",
            Command::CreateInviteLink { .. } => "createInviteLink",
            Command::RevokeInviteLink { .. } => "revokeInviteLink",
            Command::PruneInviteLinks { .. } => "pruneInviteLinks",
            Command::ClaimInviteLink { .. } => "claimInviteLink",
            Command::ConvertInviteClaims { .. } => "convertInviteClaims",
            Command::AcceptShare { .. } => "acceptShare",
            Command::RotateNow { .. } => "rotateNow",
            Command::SaveVaultSettings { .. } => "saveVaultSettings",
            Command::SiweLogin { .. } => "siweLogin",
            Command::Logout => "logout",
            Command::ForgetDevice => "forgetDevice",
        }
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Command({})", self.name())
    }
}

/// What a command hands back to its caller.
///
/// `Debug` is hand-written like [`Command`]'s: a peer's identity key is a
/// stable cross-service identifier for a third party, and a derived `{:?}`
/// would put it in host logs.
#[derive(Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    /// The command completed and queued nothing; any further effect arrives on
    /// the event stream.
    Done,
    /// An intent op reached the durable queue under this id — the same id a
    /// later [`Event::OpProgress`] or [`Event::DeadLetter`] carries, so a host
    /// can correlate them back to the call that made it.
    Queued {
        /// The durable queue id.
        op_id: OpId,
    },
    /// [`Command::ImportContact`] verified a contact code. Holding the
    /// [`Contact`] is itself the proof its binding signature verified.
    ContactImported(Contact),
    /// [`Command::CreateInviteLink`] minted a link: recorded, published, and
    /// only then handed out. The payload is the bearer capability itself
    /// ([`MintedInviteLink`]) — a host puts it in a URL fragment and nowhere
    /// durable.
    InviteLinkMinted(MintedInviteLink),
    /// [`Command::AcceptShare`] adopted a share: the gate passed, the seeds
    /// opened, and the entry is durable in this vault's received-shares list.
    /// Carries no key material — the permission is the owner-committed one, not
    /// the pointer's claim.
    ShareAccepted(AcceptOutcome),
}

impl fmt::Debug for CommandOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandOutcome::Done => f.write_str("CommandOutcome(done)"),
            CommandOutcome::Queued { op_id } => write!(f, "CommandOutcome(queued {})", op_id.0),
            CommandOutcome::ContactImported(_) => f.write_str("CommandOutcome(contactImported)"),
            CommandOutcome::InviteLinkMinted(_) => f.write_str("CommandOutcome(inviteLinkMinted)"),
            CommandOutcome::ShareAccepted(_) => f.write_str("CommandOutcome(shareAccepted)"),
        }
    }
}

impl CommandOutcome {
    /// The staged op's durable queue id, for a command that queued one.
    pub fn op_id(&self) -> Option<OpId> {
        match self {
            CommandOutcome::Queued { op_id } => Some(*op_id),
            _ => None,
        }
    }
}

/// Events the engine emits on the one-way stream out
/// (blueprint/engine.md "Facade"). Payloads are scaffold-minimal and harden
/// with the pipeline slices; the variant set is the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A new gate-passing snapshot (with pending-op overlay applied) is
    /// available.
    SnapshotUpdated,
    /// Staleness-ladder transition.
    StalenessChanged {
        /// The new level.
        level: Staleness,
    },
    /// Withheld-update escalation on a shared scope (#33 D7).
    WithheldUpdateEscalation {
        /// The pinned name, as opaque bytes.
        ipns_name: Vec<u8>,
    },
    /// A queued op terminally failed; staged bytes are preserved unless the
    /// abandonment released them (#33 D6).
    DeadLetter {
        /// The dead-lettered op.
        op_id: OpId,
        /// Why it dead-lettered — the four reasons need four different messages.
        reason: DeadLetterReason,
    },
    /// Attributable abuse: a fail-closed adoption-gate rejection, or an
    /// owner-blob / ascent-link / unseal cross-check disagreement (#39 D6) —
    /// never a silent failure.
    AttributableAbuse {
        /// Human-readable classification (no key material).
        description: String,
    },
    /// A held record's sub-EOL renewal did not land — a lost CAS race or a
    /// fail-closed publish failure. Surfaced, never silent (blueprint/engine.md
    /// "never a silent failure"); a later rebase/retry slice acts on it.
    RenewalFailed {
        /// The record's routing key (`ipnsName`); non-secret.
        routing_key: String,
        /// Human-readable classification (no key material).
        detail: String,
    },
    /// This account has no vault yet and minting one did not land, so the write
    /// path stays dark until a mint lands — a forced refresh retries one.
    /// Surfaced, never silent (blueprint/engine.md "never a silent failure"):
    /// reads still paint and ops still queue, but nothing will publish.
    VaultUnprovisioned {
        /// Whether a retry could clear this — an availability stall — versus a
        /// fail-closed refusal to mint, which a retry reaches again.
        retryable: bool,
        /// Key-material-free classification of what stopped the mint.
        detail: String,
    },
    /// Progress of a content-plane transfer for one node: the driving op (if
    /// any), the phase reached, how far the transfer has got, and the failure
    /// classification on a failed phase.
    OpProgress {
        /// The queued op driving the transfer, if any. A read of published
        /// content is driven by no op; an upload always carries the id
        /// [`Engine::commit_write`] returned, so a host keys progress per op.
        op_id: Option<OpId>,
        /// The node the transfer is for.
        node: NodeId,
        /// The phase reached.
        phase: OpPhase,
        /// How far the transfer has got, on the phases that count blocks.
        progress: Option<BlockProgress>,
        /// Failure classification for a failed phase (no key material).
        error: Option<String>,
    },
}

/// How far a content transfer has got, in whole blocks of the version's DAG
/// (its leaves plus the root manifest). Blocks, not bytes: a resumed upload's
/// confirmed prefix is no longer on this device to measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockProgress {
    /// Blocks confirmed so far, counting a previous pass's durable progress.
    pub confirmed: u32,
    /// Blocks the version has in total; never zero.
    pub total: u32,
}

/// The phase an [`Event::OpProgress`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpPhase {
    /// A content download started.
    DownloadStarted,
    /// A content download completed.
    DownloadCompleted,
    /// A content download failed.
    DownloadFailed,
    /// The drain began uploading a queued op's content version.
    UploadStarted,
    /// One more of the version's blocks is confirmed on the network.
    UploadProgress,
    /// Every block of the version is on the network; its record publishes next.
    UploadCompleted,
    /// One attempt at sending the version's blocks stopped, classified in
    /// `error`. Not itself terminal: an [`Event::DeadLetter`] in the same pass
    /// is what says the op will never publish.
    UploadFailed,
    /// The user cancelled the upload and its staged blocks were released
    /// (`Command::CancelUpload`).
    UploadCancelled,
    /// A dual write's hosted leg landed but the member's own provider did not
    /// take the version. The op published and the content is retrievable; it is
    /// simply not on their node, and no retry is queued.
    ExternalPinFailed,
}

/// Errors returned by facade calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// A command was issued before [`Engine::start`].
    NotStarted,
    /// [`Engine::start`] was called on an already-started engine (one live
    /// instance is the single writer).
    AlreadyStarted,
    /// [`Command::ForgetDevice`] swept this instance's seams. Terminal: the
    /// loops are stopped and the bearers sealed, so nothing here can be served
    /// or restarted — the host builds a fresh engine.
    Forgotten,
    /// The login secret was empty or not a valid 32-byte identity scalar.
    InvalidSecret,
    /// A read named a node absent from the rendered view.
    UnknownNode,
    /// A folder read named a file node.
    NotAFolder,
    /// A content read named a folder node.
    NotAFile,
    /// The content plane could not serve the read — an unpublished pending
    /// node, no reachable source, or an over-cap block. Availability,
    /// retryable; never a trust verdict.
    ContentUnavailable {
        /// Diagnostic message; never carries key material.
        message: String,
    },
    /// A fail-closed trust violation on the read path — a rejected child
    /// record, or a CID/manifest/unseal disagreement. Never retried, never
    /// rendered (rule 6).
    TrustViolation {
        /// The verdict classification; never carries key material.
        message: String,
    },
    /// Host-supplied bytes this build could not decode — a truncated paste, a
    /// mis-scanned code, an over-cap payload. A refusal of the input, never a
    /// trust verdict about the peer who authored it: collapsing the two would
    /// tell a host a garbled scan came from a forger.
    MalformedInput {
        /// The check that fired; never key material and never input bytes.
        check: &'static str,
    },
    /// The content's DAG root declared a format version this build cannot
    /// read; see [`DagError::UnsupportedFormat`](crate::DagError).
    UnsupportedContentFormat {
        /// The version the root declared.
        version: u64,
    },
    /// No byte destination could be decided, so the write is refused rather
    /// than placed on a store the member did not choose (blueprint/engine.md
    /// "Settings-load policy"). Recoverable: republishing or re-resolving the
    /// vault settings record clears it.
    NoPlacement {
        /// Which rule refused, so a host can say what to fix.
        refusal: PlacementRefusal,
    },
    /// The command's pipeline slice has not landed yet (scaffold state).
    Unimplemented {
        /// [`Command::name`] of the rejected command.
        command: &'static str,
    },
    /// A write was refused for want of room. The cause names which budget and
    /// which user action, and `available` is the room left — never the whole
    /// budget, which a caller cannot act on when other writes already hold most
    /// of it.
    OverBudget {
        /// Which budget refused it, and what a user can do about it.
        cause: OverBudgetCause,
        /// The version's exact sealed byte total.
        requested: u64,
        /// The room a caller may quote: `budget - (staged + reserved)` for a
        /// backlog, and the applicable ceiling for the other causes.
        available: u64,
    },
    /// The bytes fed to a write handle did not add up to the size declared at
    /// [`begin_write`](Engine::begin_write). The reachable cause is a backing
    /// file truncated mid-upload; committing it would publish a short version as
    /// a success.
    ContentSizeMismatch {
        /// The size declared at `beginWrite`.
        declared: u64,
        /// The total the pushes actually carried.
        observed: u64,
    },
    /// A write-handle call named a handle this engine does not hold — never
    /// minted, or already committed, failed, or aborted.
    UnknownWriteHandle,
    /// A read named a stream handle this engine does not hold — never minted,
    /// or already closed.
    UnknownStreamHandle,
    /// The open-stream table is already at [`MAX_OPEN_STREAMS`]; close one first.
    TooManyStreams,
    /// [`Command::CancelUpload`] named an op that is no longer cancellable: its
    /// version's last block confirmed and its record is publishing, or it has
    /// already left the durable queue. Never converted into a compensating
    /// delete, which would substitute an irreversible published mutation.
    TooLateToCancel {
        /// The op the cancel named.
        op_id: OpId,
    },
    /// [`Command::CancelUpload`] named a queued op that carries no upload. A
    /// metadata op is undone by a compensating mutation, not a cancel.
    NotAnUpload {
        /// The op the cancel named.
        op_id: OpId,
    },
    /// The file is past the flat-DAG ceiling: its root would inline more leaf
    /// links than a readable block can hold, so no device could ever serve it
    /// back. A format limit, not a budget verdict
    /// ([`DagError::RootTooLarge`](crate::DagError)).
    ContentTooLarge {
        /// The assembly check that fired; never key material.
        check: &'static str,
    },
    /// The version's content key could not be sealed to the owner's enc subkey,
    /// so the commit authors no op. Deterministic and fail-closed — never
    /// retryable availability, unlike [`Seam`](EngineError::Seam).
    ContentKeySealFailed {
        /// The seal check that fired; never key material.
        check: &'static str,
    },
    /// A forced refresh ([`Command::ManualRefresh`]) could not land: no
    /// endpoint served a record the pass could adopt, or no sync loop is
    /// running to force a pass at all. Availability, retryable — a rejected
    /// record is [`TrustViolation`](EngineError::TrustViolation) instead. The
    /// rendered view is unchanged last-known-good, so a host reports the
    /// refresh as failed rather than repainting as though it had landed.
    RefreshFailed {
        /// Diagnostic message; never carries key material.
        message: String,
    },
    /// A host seam failed (durable op-queue I/O). Availability, never a trust
    /// decision — trust classification happens below the facade.
    Seam {
        /// Diagnostic message; never carries key material.
        message: String,
    },
    /// Entropy acquisition failed while minting a node id (fail closed — never
    /// a predictable id).
    Entropy {
        /// Diagnostic message; never carries key material.
        message: String,
    },
    /// An authenticated API call failed (cold-start login or SIWE): a rejected
    /// credential or an unreachable API. Fail-closed — `start` propagates it
    /// rather than running unauthenticated. The message is the API's own
    /// diagnostic, never key material.
    Auth {
        /// Diagnostic message; never carries key material.
        message: String,
    },
    /// The cold-start data path hit a fail-closed trust violation — a forged
    /// vault pointer, a regressed floor, or a root record the adoption gate
    /// rejected. `start` returns before spawning any background loop; the engine
    /// renders nothing past an unadopted root (rules 4/6). Distinct from
    /// [`Seam`](EngineError::Seam): never retryable availability. The message
    /// carries the verdict classification, never key material.
    ColdStart {
        /// Diagnostic message; never carries key material.
        message: String,
    },
    /// A relocation whose scope crossing this engine cannot settle, refused
    /// before it is journaled (blueprint/desktop.md "Conflicts, dead letters,
    /// and rotation"). Fail-closed: a crossing the engine cannot rule out may
    /// owe a scope-exit rotation, and an op the kernel was already acked for
    /// can never be retro-failed, so the refusal has to precede the ack.
    ScopeExitRefused {
        /// Diagnostic message; never carries key material.
        message: String,
    },
    /// A command named a node this build cannot act on. Neither a refusal of
    /// the bytes that named it ([`MalformedInput`](EngineError::MalformedInput))
    /// nor of the whole command ([`Unimplemented`](EngineError::Unimplemented)):
    /// the command is wired and the node is well-formed, but the rule named
    /// here rules that node out as its target.
    UnsupportedTarget {
        /// The rule that refused; never key material.
        check: &'static str,
    },
}

impl EngineError {
    fn from_seam(err: SeamError) -> Self {
        EngineError::Seam {
            message: err.message().to_owned(),
        }
    }

    fn from_api(err: ApiError) -> Self {
        EngineError::Auth {
            message: err.to_string(),
        }
    }

    /// Entropy acquisition failed — fail closed, never a predictable substitute.
    fn from_entropy(err: crate::entropy::EntropyError) -> Self {
        EngineError::Entropy {
            message: err.message().to_owned(),
        }
    }

    /// Map an invite-mint failure on the classes a host acts on: availability
    /// it may retry, an input or a bound it can change, and a fail-closed
    /// refusal it must never retry (rule 6).
    fn from_invite_mint(err: InviteMintError) -> Self {
        match err {
            InviteMintError::Mint(e) => EngineError::from_invite(e),
            InviteMintError::Store(e) => EngineError::from_invite_store(e),
            InviteMintError::Create(e) => EngineError::from_create_grant(e),
        }
    }

    /// Map an invite-record store failure. A stored set that will not open is a
    /// report that the owner's own authority was tampered with, never a
    /// retryable outage (`invite_store.rs` header).
    fn from_invite_store(err: InviteStoreError) -> Self {
        match err {
            InviteStoreError::Entropy(e) => EngineError::from_entropy(e),
            // Only the offered set can overflow, and the host acts on it by
            // revoking a live link or pruning the dead ones.
            InviteStoreError::Full { .. } => EngineError::MalformedInput {
                check: "invite-records-full",
            },
            InviteStoreError::Encode(_) => EngineError::MalformedInput {
                check: "invite-records-unstorable",
            },
            InviteStoreError::Seal(e) => EngineError::MalformedInput { check: e.check() },
            InviteStoreError::Seam(e) => EngineError::Seam {
                message: e.message().to_owned(),
            },
            e @ InviteStoreError::Unreadable(_) => EngineError::TrustViolation {
                message: e.to_string(),
            },
        }
    }

    /// Map a link-selection failure: every arm is a verdict on the owner's own
    /// records against the owner-signed set, never availability.
    fn from_invite(err: InviteError) -> Self {
        match err {
            InviteError::Entropy(e) => EngineError::from_entropy(e),
            e @ (InviteError::NotOwner | InviteError::Authority(_)) => {
                EngineError::TrustViolation {
                    message: e.to_string(),
                }
            }
            e => EngineError::MalformedInput { check: e.check() },
        }
    }

    /// Map the gated read a mint runs first: a rejection is a fail-closed trust
    /// verdict, and every other verdict is availability.
    fn from_resolve_failure(err: ResolveFailure) -> Self {
        match err {
            ResolveFailure::Rejected => EngineError::TrustViolation {
                message: err.to_string(),
            },
            _ => EngineError::Seam {
                message: err.to_string(),
            },
        }
    }

    /// Map a child-pipeline gate error: a rejection is a fail-closed trust
    /// verdict; a seam failure is availability.
    fn from_gate(err: GateError) -> Self {
        match err {
            GateError::Rejected(rejection) => EngineError::TrustViolation {
                message: rejection.to_string(),
            },
            GateError::Seam(seam) => EngineError::ContentUnavailable {
                message: seam.message().to_owned(),
            },
        }
    }

    /// Map a settings-publish failure. The split is retryability: a refusal
    /// that is deterministic in the settings offered is an input the host must
    /// change, and reporting it as availability would leave a host retrying a
    /// save that can never land.
    fn from_settings_publish(err: SettingsPublishError) -> Self {
        match err {
            SettingsPublishError::Placement(refusal) => EngineError::NoPlacement { refusal },
            SettingsPublishError::Byo(e) => EngineError::MalformedInput { check: e.check() },
            SettingsPublishError::Codec(e) => EngineError::MalformedInput { check: e.check() },
            // The sealed record does not reopen under the key its own reader
            // re-derives, or is past the block ceiling: an encoder verdict on
            // these bytes, not an outage (security rule 8).
            SettingsPublishError::Preflight(_) => EngineError::MalformedInput {
                check: "settings-record-preflight",
            },
            SettingsPublishError::Entropy(e) => EngineError::from_entropy(e),
            // The API answered about a block other than the one uploaded, so
            // publishing on its answer would sign a pointer to bytes nothing
            // confirmed — a fail-closed verdict, never an outage to retry.
            SettingsPublishError::Publish(RecordPublishError::HeadCidMismatch { .. }) => {
                EngineError::TrustViolation {
                    message: "the API echoed a different address for the settings head block"
                        .to_owned(),
                }
            }
            SettingsPublishError::Publish(_) => EngineError::Seam {
                message: "the settings record did not reach the record plane".to_owned(),
            },
            SettingsPublishError::Unconfirmed => EngineError::Seam {
                message: "the settings publish was not confirmed on re-resolve".to_owned(),
            },
            SettingsPublishError::Floor(e) => EngineError::from_seam(e),
            SettingsPublishError::Revision => EngineError::Seam {
                message: "the durable settings revision counter did not advance".to_owned(),
            },
        }
    }

    /// Map a rotation failure on the axis its own classifier already answers: an
    /// availability stall or a C2 label conflict the re-point wave repairs is
    /// [`Seam`](EngineError::Seam); a gate-rejected record, a re-seal this build
    /// refuses to sign, a refused publish and an exhausted epoch are fail-closed
    /// verdicts on the owner's own state, never retried (rule 6). A terminal
    /// failure on a cut means it is not a revocation yet, so the caller reports
    /// it rather than treating the re-signed set as done.
    fn from_rotation<E: Retryable + fmt::Display>(err: E) -> Self {
        match err.is_retryable() {
            true => EngineError::Seam {
                message: err.to_string(),
            },
            false => EngineError::TrustViolation {
                message: err.to_string(),
            },
        }
    }

    /// [`from_rotation`](EngineError::from_rotation), with the one arm a read
    /// rotation raises that is neither: a failed entropy draw.
    fn from_rotate(err: RotateError) -> Self {
        match err {
            RotateError::Reseal(ResealError::Entropy(e)) => EngineError::from_entropy(e),
            other => EngineError::from_rotation(other),
        }
    }

    /// Map a committed-set cut refusal. The authority arms are verdicts on the
    /// owner's own published record; the rest refuse the request against the
    /// committed set, which is an input the host can change.
    fn from_revoke(err: RevokeError) -> Self {
        match err {
            RevokeError::UnauthorizedSigner
            | RevokeError::CommitmentScopeMismatch
            | RevokeError::LedgerDiverges(_) => EngineError::TrustViolation {
                message: err.to_string(),
            },
            refused => EngineError::MalformedInput {
                check: refused.check(),
            },
        }
    }

    /// Map a read-grant creation failure on the classes a host acts on:
    /// availability it may retry, an input or a bound it can change, and a
    /// fail-closed refusal it must never retry.
    fn from_create_grant(err: CreateGrantError) -> Self {
        match err {
            CreateGrantError::Entropy(e) => EngineError::from_entropy(e),
            CreateGrantError::Mailbox(e) => EngineError::from_seam(e),
            CreateGrantError::Converge(e) if e.is_retryable() => EngineError::Seam {
                message: e.to_string(),
            },
            CreateGrantError::Publish(e)
            | CreateGrantError::DescendantPublish { error: e, .. }
            | CreateGrantError::ParentPublish(e)
                if e.is_retryable() =>
            {
                EngineError::Seam {
                    message: e.to_string(),
                }
            }
            CreateGrantError::DescendantResolve { reason, .. }
                if reason != ResolveFailure::Rejected =>
            {
                EngineError::Seam {
                    message: reason.to_string(),
                }
            }
            // The recipient's own key, and a subtree the converge could not
            // bring current: both are the request's inputs, not verdicts on a
            // peer's record.
            e @ (CreateGrantError::UnusableRecipientKey
            | CreateGrantError::RecipientIsTheOwner
            | CreateGrantError::SubtreeNotConverged { .. }) => {
                EngineError::MalformedInput { check: e.check() }
            }
            terminal => EngineError::TrustViolation {
                message: terminal.to_string(),
            },
        }
    }

    /// Map an accept-flow failure. Every binding arm is a fail-closed trust
    /// verdict on the pointer or the record it named — never degraded to
    /// staleness, which would tell a host to keep retrying a forgery.
    fn from_accept(err: AcceptError) -> Self {
        match err {
            AcceptError::MalformedPointer(e) => EngineError::MalformedInput { check: e.check() },
            AcceptError::Gate(e) => EngineError::from_gate(e),
            AcceptError::Ack(e) => EngineError::from_seam(e),
            AcceptError::Persist(e) => EngineError::from_received_share_store(e),
            // No blob at your tag on an owner-signed record is the definitive
            // "you were removed" (`grants/revocation.rs`), never a claim that the
            // record is forged — a host that could not tell them apart would
            // report a revocation as an attack.
            AcceptError::NoBlobAtTag => EngineError::MalformedInput {
                check: "no-grant-at-your-tag",
            },
            trust => EngineError::TrustViolation {
                message: trust.to_string(),
            },
        }
    }

    /// Map a contact-book failure. The book is this vault's own state, so a
    /// stored book that will not open is a fail-closed verdict; everything a
    /// host can act on — a code it must re-scan, a book it must prune, a seam it
    /// may retry — keeps its own class.
    fn from_contact_store(err: ContactStoreError) -> Self {
        match err {
            ContactStoreError::Import(e @ CodecError::Malformed(_)) => {
                EngineError::MalformedInput { check: e.check() }
            }
            ContactStoreError::RecipientNotImported => EngineError::MalformedInput {
                check: "recipient-not-imported",
            },
            ContactStoreError::Full => EngineError::MalformedInput {
                check: "contact-book-full",
            },
            ContactStoreError::Encode(_) => EngineError::MalformedInput {
                check: "contact-book-unstorable",
            },
            ContactStoreError::Seam(e) => EngineError::from_seam(e),
            ContactStoreError::Entropy(e) => EngineError::from_entropy(e),
            // A seal refusal is deterministic in the book it was handed, so it
            // joins `Encode` as an input the host must change — never `Seam`,
            // whose retry would never converge.
            ContactStoreError::Seal(e) => EngineError::MalformedInput { check: e.check() },
            // A rejected binding, and a stored book this build cannot read: both
            // are fail-closed trust verdicts, not outages a host should retry.
            other => EngineError::TrustViolation {
                message: other.to_string(),
            },
        }
    }

    /// Map a received-shares store failure: a host seam is availability, and a
    /// stored list this build cannot open or re-seal is an input the host must
    /// resolve, never an outage a retry converges on.
    fn from_received_share_store(err: ReceivedShareStoreError) -> Self {
        match err {
            ReceivedShareStoreError::Seam(e) => EngineError::from_seam(e),
            ReceivedShareStoreError::Entropy(e) => EngineError::from_entropy(e),
            ReceivedShareStoreError::Full => EngineError::MalformedInput {
                check: "received-shares-full",
            },
            ReceivedShareStoreError::Seal(e) => EngineError::MalformedInput { check: e.check() },
            ReceivedShareStoreError::Encode(_) => EngineError::MalformedInput {
                check: "received-shares-unstorable",
            },
            ReceivedShareStoreError::Unreadable(e) => EngineError::TrustViolation {
                message: e.to_string(),
            },
        }
    }

    /// Map a cold-start failure onto the facade error: every trust arm (forged
    /// pointer, regressed floor, rejected root) collapses to the single
    /// fail-closed [`ColdStart`](EngineError::ColdStart) — never retryable
    /// availability.
    fn from_cold_start(err: ColdStartError) -> Self {
        match err {
            ColdStartError::Seam(seam) => EngineError::from_seam(seam),
            ColdStartError::NotStarted => EngineError::NotStarted,
            trust => EngineError::ColdStart {
                message: trust.to_string(),
            },
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::NotStarted => f.write_str("engine not started"),
            EngineError::Forgotten => f.write_str("this device was forgotten"),
            EngineError::AlreadyStarted => f.write_str("engine already started"),
            EngineError::InvalidSecret => {
                f.write_str("login secret is not a valid identity scalar")
            }
            EngineError::UnknownNode => f.write_str("unknown node"),
            EngineError::NotAFolder => f.write_str("not a folder"),
            EngineError::NotAFile => f.write_str("not a file"),
            EngineError::ContentUnavailable { message } => {
                write!(f, "content unavailable: {message}")
            }
            EngineError::TrustViolation { message } => write!(f, "trust violation: {message}"),
            EngineError::MalformedInput { check } => write!(f, "malformed input: {check}"),
            EngineError::UnsupportedContentFormat { version } => write!(
                f,
                "content format version {version} is not supported by this client"
            ),
            EngineError::Unimplemented { command } => {
                write!(f, "command not implemented yet: {command}")
            }
            EngineError::OverBudget {
                cause,
                requested,
                available,
            } => match cause {
                OverBudgetCause::StagingLimit => write!(
                    f,
                    "this write is {requested} bytes, past the {available}-byte maximum this device can stage"
                ),
                OverBudgetCause::DeviceFull => write!(
                    f,
                    "this write needs {requested} bytes but this device's free space allows only {available}"
                ),
                OverBudgetCause::StagingBacklog => write!(
                    f,
                    "this write needs {requested} bytes but only {available} are free until queued uploads finish"
                ),
                OverBudgetCause::TooManyWrites => f.write_str(
                    "too many uploads are already in progress; finish or cancel one first",
                ),
                OverBudgetCause::StorageUnmeasured => write!(
                    f,
                    "this device's available storage could not be measured, so the {requested}-byte write cannot be admitted"
                ),
                OverBudgetCause::AccountQuota => write!(
                    f,
                    "this write needs {requested} bytes but the account's storage quota leaves {available}"
                ),
            },
            EngineError::NoPlacement { refusal } => match refusal {
                PlacementRefusal::SettingsUnavailable(_) => f.write_str(
                    "your vault settings are unavailable, so this device cannot tell where your files should be stored; reconnect or save your settings again",
                ),
                PlacementRefusal::NoProvider => f.write_str(
                    "your vault settings choose your own IPFS provider but name none; add one in settings",
                ),
                PlacementRefusal::NoExternalIngress(_) => f.write_str(
                    "a pinning service cannot be your only storage — it fetches content from the network rather than receiving it; add your own IPFS node, or store on CipherBox as well",
                ),
            },
            EngineError::ContentSizeMismatch { declared, observed } => write!(
                f,
                "the file changed while it was being read: {declared} bytes were declared and {observed} arrived"
            ),
            EngineError::UnknownWriteHandle => f.write_str("unknown write handle"),
            EngineError::UnknownStreamHandle => f.write_str("unknown stream handle"),
            EngineError::TooManyStreams => write!(
                f,
                "too many read streams are already open; at most {MAX_OPEN_STREAMS} may be open at once, so close one first"
            ),
            EngineError::TooLateToCancel { op_id } => write!(
                f,
                "upload {} is already publishing and can no longer be cancelled",
                op_id.0
            ),
            EngineError::NotAnUpload { op_id } => write!(
                f,
                "queued op {} carries no upload to cancel; undo it with a compensating change",
                op_id.0
            ),
            EngineError::ContentTooLarge { check } => write!(
                f,
                "this file is too large to store as a single version: [{check}]"
            ),
            EngineError::ContentKeySealFailed { check } => {
                write!(f, "content key seal failed: [{check}]")
            }
            EngineError::RefreshFailed { message } => write!(f, "refresh failed: {message}"),
            EngineError::UnsupportedTarget { check } => {
                write!(f, "unsupported target: {check}")
            }
            EngineError::Seam { message } => write!(f, "seam error: {message}"),
            EngineError::Entropy { message } => write!(f, "entropy error: {message}"),
            EngineError::Auth { message } => write!(f, "auth error: {message}"),
            EngineError::ColdStart { message } => write!(f, "cold-start failed: {message}"),
            EngineError::ScopeExitRefused { message } => {
                write!(f, "this move was refused before it was queued: {message}")
            }
        }
    }
}

impl std::error::Error for EngineError {}

/// The receiving side of the engine's one-way event stream.
///
/// Runtime-agnostic: an unbounded in-process channel, awaitable on any
/// executor, native or WASM. Ends (`None`) when the engine is dropped.
pub struct EventStream {
    receiver: mpsc::UnboundedReceiver<Event>,
}

impl EventStream {
    /// Waits for the next event; `None` once the engine is gone.
    pub async fn next(&mut self) -> Option<Event> {
        core::future::poll_fn(|cx| Pin::new(&mut self.receiver).poll_next(cx)).await
    }

    /// The next buffered event without waiting; `None` when none is ready.
    pub fn try_next(&mut self) -> Option<Event> {
        self.receiver.try_recv().ok()
    }

    /// A stream fed by hand, for a host driving its own session loop
    /// (`test-kit`).
    #[cfg(any(test, feature = "test-kit"))]
    pub fn piped() -> (EventSink, Self) {
        let (sender, receiver) = mpsc::unbounded();
        (EventSink(sender), Self { receiver })
    }
}

/// The sending half of a hand-fed [`EventStream::piped`]. Closing it ends the
/// stream, as dropping the engine ends a real one.
#[cfg(any(test, feature = "test-kit"))]
pub struct EventSink(mpsc::UnboundedSender<Event>);

#[cfg(any(test, feature = "test-kit"))]
impl EventSink {
    /// Emits one event.
    pub fn send(&self, event: Event) {
        let _ = self.0.unbounded_send(event);
    }
}

/// A rendered read of the engine's state: the gate-passing base snapshot with
/// the pending-op overlay applied (state law, blueprint/engine.md "Sync core:
/// State law"). Reads project off this — never off raw or ungated records.
/// One render backs a whole FUSE readdir+getattr batch, so the view is
/// internally consistent.
pub struct EngineView {
    rendered: Snapshot,
}

impl EngineView {
    /// The rendered root node id — the FUSE mount anchor.
    pub fn root(&self) -> NodeId {
        self.rendered.root
    }

    /// The children under `parent`, deterministically ordered by node id.
    pub fn children(&self, parent: NodeId) -> Vec<NodeAttrs> {
        self.rendered
            .children(parent)
            .into_iter()
            .map(node_attrs)
            .collect()
    }

    /// The child of `parent` whose name folds equal to `name` under the strict
    /// comparator, if any (FUSE lookup).
    pub fn lookup(&self, parent: NodeId, name: &str) -> Option<NodeAttrs> {
        let key = collation_key(name);
        self.rendered
            .children(parent)
            .into_iter()
            .find(|child| collation_key(child.name()) == key)
            .map(node_attrs)
    }

    /// The child of `parent` stored under exactly `name`, if any — what a host
    /// presenting names case-sensitively resolves through. Collisions stay
    /// [`lookup`](Self::lookup)'s: this decides what a name refers to, never
    /// whether two names are one.
    pub fn lookup_exact(&self, parent: NodeId, name: &str) -> Option<NodeAttrs> {
        self.rendered
            .children(parent)
            .into_iter()
            .find(|child| child.name() == name)
            .map(node_attrs)
    }

    /// The node's attributes, if present in the rendered view (FUSE getattr).
    pub fn attrs(&self, node: NodeId) -> Option<NodeAttrs> {
        self.rendered.node(node).map(node_attrs)
    }

    /// Minimal statfs: the node count reachable from the root. Byte/quota
    /// accounting is API-client-side and not wired here.
    pub fn statfs(&self) -> StatFs {
        StatFs {
            nodes: count_nodes(&self.rendered),
        }
    }
}

/// Prove at journal time that a relocation stays inside this session's one
/// scope, so the op reaching [`stage_op`] is the [`ScopeCrossing::Intra`] its
/// callers record.
///
/// A destination the render does not hold is [`EngineError::UnknownNode`] — the
/// same verdict [`Engine::snapshot`] gives it, so a host reads one answer for a
/// node that is gone. A destination it holds but cannot walk to the root is
/// refused instead: the rotation such a relocation may owe cannot be settled
/// here, and refusing before the journal entry is spent is the only order that
/// works, because an op the caller was already told succeeded can never be
/// retro-failed (blueprint/desktop.md "Conflicts, dead letters, and rotation").
///
/// Only the destination is checked: the source parent comes from
/// [`Engine::relocation_anchors`], which reads it off the render or falls back
/// to the root.
fn refuse_scope_exit(rendered: &Snapshot, new_parent: NodeId) -> Result<(), EngineError> {
    if !rendered.contains(new_parent) {
        return Err(EngineError::UnknownNode);
    }
    if new_parent != rendered.root && !rendered.ancestors(new_parent).contains(&rendered.root) {
        return Err(EngineError::ScopeExitRefused {
            message: "its destination folder is not in this session's scope".to_owned(),
        });
    }
    Ok(())
}

/// The owner rotation arm over one engine's seam family.
type OwnerNet<'a, T> = OwnerRotationNet<
    'a,
    <T as SeamTypes>::RecordTransport,
    <T as SeamTypes>::Http,
    <T as SeamTypes>::CredentialStore,
    <T as SeamTypes>::FloorStore,
    <T as SeamTypes>::Scheduler,
    Box<dyn Entropy>,
>;

/// The label a share pointer carries for `node`.
///
/// The recipient's received-shares codec hard-rejects a longer one, so it is
/// refused where the name is still the owner's to change (AGENTS.md rule 8).
fn share_display_name(rendered: &Snapshot, node: NodeId) -> Result<String, EngineError> {
    let name = rendered
        .node(node)
        .ok_or(EngineError::UnknownNode)?
        .name()
        .to_owned();
    if name.len() > MAX_DISPLAY_NAME_BYTES {
        return Err(EngineError::MalformedInput {
            check: "grant-display-name-too-long",
        });
    }
    Ok(name)
}

/// A resolved scope root's owner signature, parsed. Unparseable is a verdict on
/// the record, never on the caller.
fn parsed_commitment_sig(compact: &[u8; 64]) -> Result<EcdsaSignature, EngineError> {
    EcdsaSignature::from_compact(compact).ok_or_else(|| EngineError::TrustViolation {
        message: "the scope root's commitment signature is unparseable".to_owned(),
    })
}

/// A scope root's opaque `ipnsName` bytes as a parsed name, on the resolve
/// path's own definition of parseable. An address this build cannot read is a
/// refusal of the bytes that carried it, never a verdict on their author.
fn parsed_scope_name(ipns_name: &[u8]) -> Result<IpnsName, EngineError> {
    scope_name(ipns_name).map_err(|_| EngineError::MalformedInput {
        check: "scope-root-name-is-unparseable",
    })
}

/// A scope root this session acts on as its owner, and the ancestor node seed a
/// gated read of an interior one needs. `None` at the vault root, which carries
/// no ascent link to prove.
struct OwnerScope {
    scope: ChildScopeRef,
    parent_node_seed: Option<Zeroizing<[u8; 32]>>,
    /// Whether the parent's owner-signed index names this scope root at this
    /// name — see [`OwnerScope::resolve_error`].
    vouched: bool,
}

/// What an action does when the parent's owner-signed index does not vouch for
/// the node's scope root.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UnindexedScope {
    /// Refuse: the node names no scope root this action can reach.
    Refuse,
    /// Read it at the name its write material derives. A mint publishes the
    /// scope root before it updates the parent's index, so a link committed by a
    /// mint that stopped in between is live at that name and reachable nowhere
    /// else — and an owner that cannot reach it cannot revoke it.
    Derive,
}

impl OwnerScope {
    /// The ancestry a gated read of this scope root runs under: seeded with its
    /// own ancestor seed when it is anchored below the vault root, which is also
    /// what tells [`OwnerRotationNet::resolve_anchored`] which binding to prove.
    fn ancestry(&self) -> RotationAncestry {
        RotationAncestry::default()
            .under_parent_node_seed(self.scope.scope_id, self.parent_node_seed.as_deref())
    }

    /// How a failed resolve of this scope root classifies.
    ///
    /// A rejection at a name nothing vouched for is the caller's target error,
    /// not an abuse event: every node of a scope publishes at a derived name, so
    /// a node that is no scope root answers there with an ordinary record the
    /// gate rightly refuses. Reporting that as a trust violation would put a
    /// plain input mistake on the channel a host must treat as attributable
    /// (AGENTS.md rule 6).
    fn resolve_error(&self, check: &'static str, failure: ResolveFailure) -> EngineError {
        match failure {
            ResolveFailure::Rejected if !self.vouched => EngineError::UnsupportedTarget { check },
            other => EngineError::from_resolve_failure(other),
        }
    }
}

/// Who a freshly minted scope is shared with.
enum ScopeShare<'a> {
    /// An imported contact, whose verified binding signature is what ties the
    /// key the grant wraps to the identity the pointer is addressed to.
    Contact(&'a Contact),
    /// A bearer link: the recipient is a throwaway keypair the engine draws,
    /// and its secret is the whole capability.
    InviteLink {
        /// The link's deadline, or `None` for a link that never expires.
        expires_at: Option<UnixMillis>,
    },
}

/// The host-facing names a scope mint's refusals carry. One rule, one name per
/// command: a grant and an invite link are different actions to a user, so they
/// do not report each other's.
struct ShareChecks {
    /// The vault root is refused as a target.
    vault_root: &'static str,
    /// The node already names a scope, so a mint would replace it.
    already_a_scope: &'static str,
    /// The parent scope root's envelope version is not the one this build
    /// authors.
    envelope_version: &'static str,
}

impl ScopeShare<'_> {
    fn checks(&self) -> ShareChecks {
        match self {
            ScopeShare::Contact(_) => ShareChecks {
                vault_root: "grant-target-is-the-vault-root",
                already_a_scope: "grant-target-already-names-a-scope",
                envelope_version: "grant-parent-envelope-version-unsupported",
            },
            ScopeShare::InviteLink { .. } => ShareChecks {
                vault_root: "invite-target-is-the-vault-root",
                already_a_scope: "invite-target-already-names-a-scope",
                envelope_version: "invite-parent-envelope-version-unsupported",
            },
        }
    }
}

/// The entries of `index` whose scope roots sit inside `node`'s subtree — the
/// descendant scopes a grant at `node` reparents into the fresh scope.
///
/// Fail-closed on an entry the rendered view cannot place: leaving a live scope
/// root indexed under a scope that no longer contains it is a descendant the
/// eager cascade never reaches, which is a silent revocation hole rather than a
/// stale bookmark.
fn subtree_child_scopes(
    rendered: &Snapshot,
    node: NodeId,
    index: &[ChildScopeRef],
) -> Result<Vec<ChildScopeRef>, EngineError> {
    let mut inside = Vec::new();
    for child in index {
        let scope_root = NodeId(child.scope_id);
        if !rendered.contains(scope_root) {
            return Err(EngineError::UnsupportedTarget {
                check: "grant-cannot-place-a-child-scope",
            });
        }
        if rendered.is_descendant_of(scope_root, node) {
            inside.push(child.clone());
        }
    }
    Ok(inside)
}

/// The published grant blobs of a gated scope root, as the accept flow's
/// self-location reads them. The structure signature is the gate's to verify;
/// self-location keys on the tag alone.
fn published_grant_blobs(section: &GrantSection) -> Vec<PublishedGrantBlob> {
    section
        .grant_blobs
        .iter()
        .map(|blob| PublishedGrantBlob {
            tag: blob.tag,
            enc: blob.enc,
            ciphertext: blob.ciphertext.clone(),
        })
        .collect()
}

fn node_attrs(meta: &NodeMeta) -> NodeAttrs {
    NodeAttrs {
        id: meta.id,
        name: meta.name().to_owned(),
        kind: meta.kind,
        size: meta.size,
        mtime: meta.mtime,
        content_version: meta.content_version,
    }
}

/// Stamp every folder a focus pass attempted against the caller's clock
/// reading. Attempts, not merges: an unresolvable folder must not turn every
/// navigation into a fresh endpoint fan-out, and the poll leg refreshes the
/// window regardless, so recovery stays automatic.
fn stamp_focus_refreshed(
    stamps: &RefCell<BTreeMap<NodeId, UnixMillis>>,
    folders: &[NodeId],
    now: UnixMillis,
) {
    let mut stamps = stamps.borrow_mut();
    for folder in folders {
        stamps.insert(*folder, now);
    }
}

/// Emit an [`Event::RenewalFailed`] for every sub-EOL renewal that did not land
/// (a lost CAS race or a fail-closed publish failure). A comfortably-ahead or
/// republished record emits nothing. Best-effort over the in-process channel: a
/// dropped receiver (host torn down) is fine.
fn emit_renewal_failures(events: &mpsc::UnboundedSender<Event>, results: &[EolRenewResult]) {
    for result in results {
        let detail = match &result.outcome {
            Ok(Some(PublishOutcome::LostRace {
                published_sequence,
                observed_sequence,
            })) => {
                format!(
                    "lost CAS race: published {published_sequence}, observed {observed_sequence}"
                )
            }
            Ok(Some(PublishOutcome::Unconfirmed { sequence })) => {
                format!("published sequence {sequence} but it did not resolve back")
            }
            Err(PublishError::Register(_)) => "register-first publish failed".to_owned(),
            Err(PublishError::AllEndpointsFailed) => "all record endpoints failed".to_owned(),
            Err(PublishError::FloorRead(_)) => "sequence floor read failed".to_owned(),
            Err(PublishError::EmptyHeadCid) => "empty head CID (never published)".to_owned(),
            Err(PublishError::RecordTooLarge { size, limit }) => {
                format!("record of {size} bytes over the {limit}-byte cap (never published)")
            }
            // A no-renewal (comfortably ahead) or a clean republish is not a
            // failure — nothing to surface.
            Ok(Some(PublishOutcome::Published { .. })) | Ok(None) => continue,
        };
        let _ = events.unbounded_send(Event::RenewalFailed {
            routing_key: result.routing_key.clone(),
            detail,
        });
    }
}

/// Surface a fail-closed resolve rejection as [`Event::AttributableAbuse`]: a
/// trust violation is never mere staleness (AGENTS.md rule 6), so it must not
/// poll silently. `routing_key` is the record's `ipnsName` and `detail` a
/// classification; neither carries key material.
pub(crate) fn emit_trust_violation(
    events: &mpsc::UnboundedSender<Event>,
    routing_key: &str,
    detail: impl fmt::Display,
) {
    let _ = events.unbounded_send(Event::AttributableAbuse {
        description: format!("{routing_key}: {detail}"),
    });
}

/// What [`Engine::sharing`] calls a node the vault root's committed child-scope
/// index does not name — not an error to the caller, which reads it as "no scope
/// root here, so nothing is granted".
const NOT_A_SCOPE_ROOT: &str = "sharing-target-is-not-a-scope-root";

/// One tick's pointer-consult window: the scopes due this pass
/// ([`consult_scopes_due`]), which of them is the vault anchor, and the clock
/// the stamps are taken from.
struct ConsultWindow {
    scopes: Vec<NodeId>,
    anchor: NodeId,
    now: UnixMillis,
}

/// The focus tick's polled scope-pointer consults (`crate::sync::pointer`:
/// "Consult discipline: polled, not fallback").
///
/// Each consult advances the scope's write-epoch floor on sight, which is what
/// evicts the `writeScopeSeed` a write-only rotation retired — that rotation
/// leaves the read epoch untouched, so the sweep's event-driven consult never
/// fires for it. An unavailable pointer leaves the stamp unset, so the next tick
/// retries rather than waiting out the interval.
///
/// Returns the vault anchor's owner-vouched current root when this pass
/// consulted one (see [`consult_scopes`]).
async fn consult_pointers<T: RecordTransport, F: FloorStore>(
    transport: &T,
    floors: &F,
    keys: &RefCell<Option<Rc<SweepKeys>>>,
    events: &mpsc::UnboundedSender<Event>,
    consulted: &RefCell<BTreeMap<NodeId, UnixMillis>>,
    window: ConsultWindow,
) -> Option<IpnsName> {
    // The pass owns a copy for exactly its own duration, on the same terms as
    // the tick's enc subkey: teardown empties the cell.
    let keys = keys.borrow().clone()?;
    let mut anchor_root = None;
    for scope in window.scopes {
        let consult = PointerConsult {
            scope_keys: &keys.scope_keys,
            owner_identity: &keys.owner_identity,
            payload_version: POINTER_PAYLOAD_VERSION,
        };
        match consult.run(transport, floors, &scope.0).await {
            Err(PointerConsultError::Unavailable) => continue,
            // A verdict is stable, so a refusal is stamped like a clean
            // consult: re-polling a rolled-back pointer every tick would
            // repeat its abuse event forever without changing it.
            Err(PointerConsultError::Rejected) => {
                consulted.borrow_mut().insert(scope, window.now);
                emit_trust_violation(
                    events,
                    &hex_lower(&scope.0),
                    "scope pointer unauthenticated, or vouched below the write-epoch floor",
                );
            }
            Ok(current_root) => {
                consulted.borrow_mut().insert(scope, window.now);
                if scope == window.anchor {
                    anchor_root = current_root;
                }
            }
        }
    }
    anchor_root
}

/// Project a scope root's grant ledger for a host: the recipient label and the
/// committed permission, and nothing the ledger's sealed half carries.
///
/// Any committed **writer** authors the write body this ledger rides in
/// (`cipherbox_core::seal::write_body`), so neither the row count nor the
/// recipient bytes are owner truth on their own. The caller has already held the
/// ledger to the owner-signed commitment; this holds each row's recipient label
/// to the owner's own binding signature, filing one it cannot vouch for under
/// [`UNATTESTED_IDENTITY_PK`] rather than naming a party the owner never signed.
fn project_grant_ledger<'a>(
    owner_identity: &EcdsaVerifier,
    scope_root_ipns_name: &[u8],
    ledger: impl IntoIterator<Item = &'a GrantLedgerEntry>,
) -> Vec<SharingGrant> {
    ledger
        .into_iter()
        .map(|entry| SharingGrant {
            recipient_identity_public_key: if row_is_owner_attested(
                owner_identity,
                entry,
                scope_root_ipns_name,
            ) {
                entry.recipient_identity_pk.to_vec()
            } else {
                UNATTESTED_IDENTITY_PK.to_vec()
            },
            permission: entry.permission.into(),
        })
        .collect()
}

/// The record bytes already held for `name` under `node`, when the scope seeds
/// recovered alongside them are still in hand — the precondition for
/// [`RootAdopter::holding`]'s steady-state skip.
fn steady_state_hold(
    held: &RefCell<HeldRecords>,
    scope_root: [u8; 16],
    name: &IpnsName,
    read_seeds: &RefCell<ScopeSeeds>,
    write_seeds: &RefCell<ScopeSeeds>,
) -> Option<Vec<u8>> {
    if !read_seeds.borrow().contains_key(&scope_root)
        || !write_seeds.borrow().contains_key(&scope_root)
    {
        return None;
    }
    let held = held.borrow();
    let record = held.get(&scope_root)?;
    (record.routing_key == name.as_str()).then(|| record.record_bytes.clone())
}

/// Fold one drain pass's report into the host-visible surface: retain and emit
/// every dead letter, and emit one [`Event::SnapshotUpdated`] if the pass moved
/// anything off the queue (the overlay the host renders just shrank). Both sends
/// are best-effort over the in-process channel — a dropped receiver is fine.
fn surface_drain_report(
    events: &mpsc::UnboundedSender<Event>,
    dead_letters: &RefCell<RetainedDeadLetters>,
    report: &DrainReport,
) {
    for (op_id, target, reason) in &report.dead_letters {
        dead_letters
            .borrow_mut()
            .insert(*op_id, (Some(*target), *reason));
        let _ = events.unbounded_send(Event::DeadLetter {
            op_id: *op_id,
            reason: *reason,
        });
    }
    if !report.is_empty() {
        let _ = events.unbounded_send(Event::SnapshotUpdated);
    }
}

/// Deposit a recovered scope write seed, but only if it derives the very name
/// the scope root publishes under. A write-capable grantee can commit an
/// owner-write-blob wrapping a seed of its choosing; holding it would make the
/// drain mint every new node's `ipnsName` and signer from a key that party also
/// holds. A seed that cannot name our own root is not our scope's — held
/// keyless, never a trust verdict.
fn deposit_write_seed(
    cell: &RefCell<ScopeSeeds>,
    scope_id: [u8; 16],
    seed: Zeroizing<[u8; 32]>,
    root_name: Option<&IpnsName>,
    floor: Option<u64>,
) {
    if root_name.is_some_and(|name| derive_write_name(&seed, &scope_id) == *name) {
        deposit_seed(cell, scope_id, seed, floor);
    }
}

/// Count nodes reachable from the root via the link graph, cycle-guarded (a
/// malformed link cycle terminates rather than looping).
fn count_nodes(snapshot: &Snapshot) -> u64 {
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![snapshot.root];
    seen.insert(snapshot.root);
    while let Some(id) = stack.pop() {
        for child in snapshot.children(id) {
            if seen.insert(child.id) {
                stack.push(child.id);
            }
        }
    }
    seen.len() as u64
}

/// Staleness-ladder inputs (#33 D4): the last successful reconcile, whether one
/// is in flight, and the last rung reported — [`Event::StalenessChanged`] fires
/// only on a rung change.
#[derive(Default)]
struct SyncStatus {
    last_success: Option<UnixMillis>,
    reconcile_in_flight: bool,
    reported: Option<Staleness>,
}

/// A recovered scope seed and a lower bound on the epoch it belongs to (see
/// [`deposit_seed`]).
///
/// The bound is the seed's expiry: a rotation that raises the scope's durable
/// floor past it revokes that epoch, so the seed is evicted rather than left
/// resident for the rest of the session. Least privilege is a retention rule,
/// not only an install rule.
struct CachedSeed {
    seed: Zeroizing<[u8; 32]>,
    floor: u64,
}

/// One of the engine's in-memory per-scope seed cells: scope id → the recovered
/// seed (zeroized on removal/drop).
type ScopeSeeds = BTreeMap<[u8; 16], CachedSeed>;

/// Which of a scope's two independent durable floors bounds a cached seed
/// (`gate::floor`: the read-epoch floor is the revocation boundary, the
/// write-epoch floor an owner-only clock).
#[derive(Clone, Copy)]
enum SeedFloor {
    Read,
    Write,
}

impl SeedFloor {
    async fn durable<F: FloorStore>(
        self,
        floors: &F,
        scope_id: &[u8; 16],
    ) -> SeamResult<Option<u64>> {
        match self {
            Self::Read => floor::read_epoch_floor(floors, scope_id).await,
            Self::Write => floor::write_epoch_floor(floors, scope_id).await,
        }
    }
}

/// Read `scope_id`'s durable floor for `which`, evicting a cached seed stamped
/// below it, and hand the floor back for the pass's own deposits.
///
/// `None` on a floor-store failure, which also evicts: a seed whose currency
/// cannot be established is not held, and nothing may be stamped against a floor
/// that was never read.
async fn refresh_seed_floor<F: FloorStore>(
    floors: &F,
    cell: &RefCell<ScopeSeeds>,
    scope_id: &[u8; 16],
    which: SeedFloor,
) -> Option<u64> {
    let durable = which
        .durable(floors, scope_id)
        .await
        .ok()
        .map(|floor| floor.unwrap_or(0));
    let mut seeds = cell.borrow_mut();
    if durable.is_none_or(|floor| seeds.get(scope_id).is_some_and(|c| c.floor < floor)) {
        seeds.remove(scope_id);
    }
    durable
}

/// Deposit a recovered scope seed under `stamp`, which must be **at or below the
/// epoch the seed belongs to** — the seed's own epoch where the recovery names it
/// (an adopted record's `epoch`, a re-point's vouched floors), else the durable
/// floor read *before* the resolve.
///
/// A pre-resolve floor is a valid stamp because floors are monotonic and every
/// recovery arm refuses an envelope below the floor it read (`gate::adoption`
/// stage 5, `RootAdopter::recover_own_scope_material`). What is *not* valid is a
/// floor re-read after the resolve: a rise that landed mid-pass would be absorbed
/// into the stamp and keep a revoked-epoch seed resident.
///
/// `None` skips the deposit — the floor could not be read, so nothing can be
/// stamped and the eviction pass has already cleared the cell.
fn deposit_seed(
    cell: &RefCell<ScopeSeeds>,
    scope_id: [u8; 16],
    seed: Zeroizing<[u8; 32]>,
    stamp: Option<u64>,
) {
    if let Some(floor) = stamp {
        cell.borrow_mut()
            .insert(scope_id, CachedSeed { seed, floor });
    }
}

/// A scope's two durable epoch floors as one resolve pass observed them, before
/// the resolve moved either. `None` on a floor-store failure (see
/// [`refresh_seed_floor`]).
struct SeedFloors {
    read: Option<u64>,
    write: Option<u64>,
}

/// Evict both of `scope_id`'s cached seeds against their durable floors and
/// report those floors, the stamps this pass's deposits carry.
async fn refresh_seed_floors<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    read_seeds: &RefCell<ScopeSeeds>,
    write_seeds: &RefCell<ScopeSeeds>,
) -> SeedFloors {
    SeedFloors {
        read: refresh_seed_floor(floors, read_seeds, scope_id, SeedFloor::Read).await,
        write: refresh_seed_floor(floors, write_seeds, scope_id, SeedFloor::Write).await,
    }
}

/// The scope's cached seed, without an eviction pass.
fn cached_seed(cell: &RefCell<ScopeSeeds>, scope_id: &[u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
    cell.borrow()
        .get(scope_id)
        .map(|cached| cached.seed.clone())
}

/// Retained dead letters: op id → its target node when known (`None` for an
/// undecodable queue entry, which never decoded far enough to name one) and why
/// it dead-lettered.
type RetainedDeadLetters = BTreeMap<OpId, (Option<NodeId>, DeadLetterReason)>;

impl From<Refused> for EngineError {
    fn from(
        Refused {
            refusal,
            requested,
            available,
        }: Refused,
    ) -> Self {
        EngineError::OverBudget {
            cause: match refusal {
                Refusal::OverLimit => OverBudgetCause::StagingLimit,
                Refusal::DeviceFull => OverBudgetCause::DeviceFull,
                Refusal::Backlog => OverBudgetCause::StagingBacklog,
                Refusal::TooManyWrites => OverBudgetCause::TooManyWrites,
                Refusal::Unmeasured => OverBudgetCause::StorageUnmeasured,
            },
            requested,
            available,
        }
    }
}

/// Map a content-sealing failure onto the facade error: entropy is fail-closed
/// availability, and an assembly refusal is a version this build's own reader
/// would reject.
/// The settings record this session published, unless the record plane now
/// serves a different one.
///
/// The resolve tick replaces each held record in place, so nothing in that map
/// can go stale under the renewal; the settings slot has no such refresher. A
/// second device that saved after this session did leaves this record
/// superseded, and a sub-EOL renewal would re-sign it at `floor + 1` with a
/// fresh validity — which wins record selection and rolls the account back to
/// the body this session published, credentials and placement included.
///
/// Only a positively observed *different* record supersedes: a plane this pass
/// cannot read is availability, and the renewal itself refuses to renew what it
/// cannot resolve.
async fn live_settings_record<R: RecordTransport>(
    transport: &R,
    slot: &RefCell<Option<HeldRecord>>,
) -> Option<HeldRecord> {
    let held = slot.borrow().clone()?;
    let Ok(name) = IpnsName::parse(&held.routing_key) else {
        return None;
    };
    match fanout_get_verify(transport, &name).await {
        Some((live, _)) if live.value != format!("/ipfs/{}", held.head_cid).into_bytes() => {
            // The verdict names the record this pass read, not whatever the slot
            // holds now: a save that landed across the resolve installed its own
            // confirmed record, and clearing that one drops it from the renewal.
            let mut slot = slot.borrow_mut();
            if slot
                .as_ref()
                .is_some_and(|current| current.record_bytes == held.record_bytes)
            {
                *slot = None;
            }
            None
        }
        _ => Some(held),
    }
}

fn seal_error(error: SealError) -> EngineError {
    match error {
        SealError::Entropy(error) => EngineError::from_entropy(error),
        SealError::Dag(error) => EngineError::ContentTooLarge {
            check: error.check(),
        },
    }
}

/// One write handle in flight between `beginWrite` and its commit.
struct LiveWrite {
    /// The node the commit's op targets — minted here for a new file.
    node: NodeId,
    /// What the commit journals.
    target: WriteTarget,
    /// The size declared at `beginWrite`, which the reservation was sized from
    /// and the commit cross-checks the pushes against.
    declared_size: u64,
    /// The version this write replaces ([`Engine::write_anchor`]), taken at the
    /// open rather than the commit: the whole upload sits between the two, and
    /// an anchor minted after it would call a version that landed mid-upload
    /// the one the caller wrote against.
    base_version_cid: Option<Vec<u8>>,
    /// The staging reservation held for this handle's whole life.
    reservation: ReservationId,
    /// The streaming framer, holding the version's content key.
    writer: ContentWriter,
}

/// The engine's live write handles and the budget they hold.
#[derive(Default)]
struct LiveWrites {
    ledger: StagingLedger,
    open: BTreeMap<WriteHandle, LiveWrite>,
    next: u64,
}

/// What one [`StreamHandle`] pins: the head version resolved at open (holding
/// its content key) and the root manifest its leaves are read against.
struct LiveStream {
    version: Version,
    manifest: RootManifest,
    /// Released when the last [`Rc`] drops, which an in-flight
    /// [`read_stream`](Engine::read_stream) can outlive the map entry by.
    _slot: StreamSlot,
}

/// One of the [`MAX_OPEN_STREAMS`] slots, reserved before
/// [`open_content_stream`](Engine::open_content_stream) spends any network and
/// released when the [`LiveStream`] it lives in drops.
///
/// The ceiling bounds *live pinned versions*, not map entries: reserving across
/// the open's awaits means a doomed open pays no resolve, and releasing on the
/// last `Rc` means an in-flight read that outlives `close_stream` still counts.
struct StreamSlot {
    live: Rc<Cell<usize>>,
}

impl StreamSlot {
    /// `None` once the ceiling is met.
    fn acquire(live: &Rc<Cell<usize>>) -> Option<Self> {
        let count = live.get();
        if count >= MAX_OPEN_STREAMS {
            return None;
        }
        live.set(count + 1);
        Some(Self {
            live: Rc::clone(live),
        })
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.live.set(self.live.get() - 1);
    }
}

/// How many read streams may be open at once.
///
/// A host holds one stream per open media element, so a real UI is two orders
/// below this; the ceiling exists because each entry pins a content key and a
/// root manifest carrying a CID per MiB of file, which an unbounded table turns
/// into a memory and key-pinning DoS ([`EngineError::TooManyStreams`]).
pub const MAX_OPEN_STREAMS: usize = 256;

/// The most file nodes an on-access refresh queue holds between ticks.
///
/// Each queued file costs the next tick one record resolve, and a host that
/// stats a large listing puts every entry in view: the ceiling bounds the pass
/// to the window rather than to the listing.
pub const MAX_FOCUS_FILES: usize = 64;

pub use crate::grants::MAX_CONTACT_CODE_BYTES;

/// The engine's live read streams, bounded by [`MAX_OPEN_STREAMS`].
#[derive(Default)]
struct LiveStreams {
    open: BTreeMap<StreamHandle, Rc<LiveStream>>,
    /// Slots reserved, counted outside `open` so a [`StreamSlot`] can release
    /// itself without re-entering the [`RefCell`] this lives behind.
    live: Rc<Cell<usize>>,
    next: u64,
}

/// The re-point pointer-payload wire version the owner's own vault seals under
/// and the cold-start walk verifies against (`crates/core` pointer payload) — the
/// sole v2 version (CONTEXT.md "Vault pointer").
const POINTER_PAYLOAD_VERSION: u64 = 1;

/// The resolve-tick task, spawned once a root name exists to poll.
type TickLoopSpawner = Box<dyn FnOnce(IpnsName)>;

/// Builds the lazy-wave sweep task a rotation enqueues once its cut is durable
/// ([`rotate_scope`]'s third effect), over the scope root the rotation read and
/// the ancestor seed it read it under.
type SweepTaskFactory = Rc<dyn Fn(ChildScopeRef, Option<Zeroizing<[u8; 32]>>) -> BoxedTask>;

/// The session material a spawned sweep opens and re-seals under, held in a cell
/// the engine empties on drop so teardown revokes it rather than waiting out the
/// task ([`Engine::tick_enc_subkey`] carries the tick loop's on the same terms).
struct SweepKeys {
    enc_secret: X25519Secret,
    owner_identity: EcdsaVerifier,
    scope_keys: OwnerSeedKeys,
}

/// How many sweep passes one enqueued task runs before it gives up and leaves
/// the remainder to the next rotation or ordinary write. The idle sweep cadence
/// is an open edge (blueprint/engine.md "Open edges"), so the task rides
/// [`SyncTimingProfile::poll_cadence`] until it lands in the profile.
const SWEEP_MAX_PASSES: u32 = 3;

/// The engine — the single stateful brain behind the facade.
///
/// Constructed over the whole seam set (missing seam = compile error), an
/// injected entropy source, and an explicit sync timing profile. Generic
/// over the host's [`SeamTypes`] family: fully statically dispatched, no
/// `Send` requirement, so one implementation links natively on desktop and
/// compiles to worker-hosted WASM on web.
pub struct Engine<T: SeamTypes> {
    seams: SeamSet<T>,
    /// Seeds, nonces, and command-path node-id minting. Shared with the
    /// spawned drain, which needs a fresh seal nonce per authored record.
    entropy: Rc<RefCell<Box<dyn Entropy>>>,
    profile: SyncTimingProfile,
    /// The measured storage split this device runs under, injected whole at
    /// construction so no staging read-modify-write queries the host mid-flight.
    storage_policy: StoragePolicy,
    /// The frozen content-framing profile every write handle frames under.
    content_profile: ContentProfile,
    /// Live write handles and the staging bytes each has reserved. In memory
    /// only: a restart drops every reservation, and the blocks a dropped handle
    /// staged are unreferenced and collectible as orphans.
    writes: RefCell<LiveWrites>,
    /// Live read streams and the content version each pins. In memory only: a
    /// restart drops them, and a host reopens.
    streams: RefCell<LiveStreams>,
    /// The staging keys those handles hold — orphan GC's live set, shared with
    /// the tick loop that sweeps after each drain pass.
    live_blocks: Rc<RefCell<LiveBlocks>>,
    /// The upload-cancel interlock, shared with the drain the tick loop runs.
    cancels: Rc<RefCell<UploadCancels>>,
    /// The API base URL cold start logs in against and the liveness loop
    /// registers renewals against.
    api_base_url: ApiBaseUrl,
    /// The resolved content read-source set, built once from the injected
    /// [`GatewayConfig`] at construction. Empty (dormant) until the host supplies
    /// endpoints; reads then fail closed as [`ReadError`](crate::ReadError)`::Unavailable`.
    /// Read by the cold-start [`RootAdopter`] and the resolve-tick driver's
    /// per-pass adopter.
    gateway: Gateway,
    /// The session access token, shared with the API client
    /// [`start`](Self::start) builds so teardown here reaches it.
    session_bearer: SessionBearer,
    /// The read accelerator's opaque pseudonym (CONTEXT.md, Accelerator token),
    /// shared by that same client and the gateway leg.
    accelerator_bearer: SessionBearer,
    events: mpsc::UnboundedSender<Event>,
    /// The last-known-good gate-passing base snapshot (state law's left
    /// operand). Seeded at the anchored root; cold-start/resolve replace it
    /// with the resolved remote state. Reads render this ⊕ the pending-op
    /// overlay; commands never mutate it — only the op queue diverges locally.
    /// Behind an [`Rc`]`<`[`RefCell`]`>` so the resolve-tick loop shares the one
    /// cell and repaints it in place from a gate-passing live resolve.
    snapshot: Rc<RefCell<Snapshot>>,
    /// The session's live held-record set, keyed by node id: the resolve path
    /// ([`resolve_and_hold`](crate::net::resolve_and_hold)) inserts each
    /// gate-passing record here, and the cold-start liveness loop keyless
    /// re-PUTs the map's values on the hourly cadence.
    held_records: Rc<RefCell<HeldRecords>>,
    /// The vault settings record this session published, in its own slot rather
    /// than in [`held_records`](Self::held_records): that map is keyed by node
    /// id and the settings record has none, so a synthetic id would put it in a
    /// slot a resolved record could claim and evict its renewal.
    settings_record: Rc<RefCell<Option<HeldRecord>>>,
    /// Staleness bookkeeping shared with the resolve-tick loop: it stamps
    /// successes and reports rung changes; [`snapshot`](Self::snapshot)
    /// classifies at read time off the same cell.
    sync_status: Rc<RefCell<SyncStatus>>,
    /// Per-scope read seeds recovered by gate-passing adopts (the owner-blob
    /// override seed), keyed by scope id. In-memory only — never persisted,
    /// never crossing the facade (security rules 1/3); the child read pipeline
    /// derives per-node read keys from them (`node-seed` → `read-key`).
    scope_read_seeds: Rc<RefCell<ScopeSeeds>>,
    /// Per-scope write seeds recovered by gate-passing adopts (the
    /// owner-write-blob seed), keyed by scope id. In-memory only, exactly like
    /// [`scope_read_seeds`](Self::scope_read_seeds); the drain derives each new
    /// node's `ipnsName` and its narrow per-name signer from them.
    scope_write_seeds: Rc<RefCell<ScopeSeeds>>,
    /// The open focus window ([`Command::SetFocus`]): the folder the host has
    /// open, whose record and whole ancestor chain every resolve tick refreshes.
    /// Shared with the tick loop, which reads it on each pass.
    focus: Rc<RefCell<FocusWindow>>,
    /// When each focus folder was last refreshed, so a navigation inside the
    /// staleness threshold renders state already held instead of re-probing the
    /// record plane (blueprint/engine.md: refresh on access past the threshold).
    focus_refreshed: Rc<RefCell<BTreeMap<NodeId, UnixMillis>>>,
    /// When each scope's pointer was last consulted, so the polled consult runs
    /// at [`SyncTimingProfile::pointer_consult_interval`] rather than at the
    /// poll cadence. In-memory: a floor only ever moves up, so a restart's first
    /// tick re-consults and re-derives it.
    pointer_consulted: Rc<RefCell<BTreeMap<NodeId, UnixMillis>>>,
    /// The verdict the tick's last pass reached for each bookmarked shared
    /// scope. In-memory: a verdict is what a live resolve found, so a restart
    /// re-earns it rather than rendering one nothing observed this session.
    received_verdicts: Rc<RefCell<ReceivedVerdicts>>,
    /// When a host operation last put the focus window's folder in view
    /// ([`note_focus_access`](Self::note_focus_access)). Shared with the tick
    /// loop, which is what closes a window the operation stream stopped
    /// feeding. `None` when no window is open.
    focus_touched: Rc<Cell<Option<UnixMillis>>>,
    /// The folder the FUSE-op TTL check last fired a hint for, and when. One
    /// slot: the check only ever asks about the folder in view, and a hint is
    /// not the refresh stamp a completed pass earns
    /// ([`focus_refreshed`](Self::focus_refreshed)).
    focus_hinted: Cell<Option<(NodeId, UnixMillis)>>,
    /// File nodes a host operation put in view past the staleness threshold,
    /// awaiting the tick's file leg ([`FolderRefresh::run_files`]). Most recent
    /// last, capped at [`MAX_FOCUS_FILES`]: a focus window is about what is in
    /// view now, so a full queue drops its oldest entry rather than refusing the
    /// file the host just looked at. Shared with the tick loop, which drains it
    /// each pass.
    focus_files: Rc<RefCell<Vec<NodeId>>>,
    /// Retained dead-lettered ops. Feeds [`SnapshotView`]'s dead-letter surface
    /// (#33 D6: dead letters are retained, never silent).
    dead_letters: Rc<RefCell<RetainedDeadLetters>>,
    /// Memo of the durable queue scan every read renders through
    /// ([`scan_queue`](Self::scan_queue)).
    queue_scan: RefCell<QueueScanMemo>,
    /// The drain's over-quota hold, written by the drain tick and read by
    /// [`snapshot`](Self::snapshot). In-memory: a restart re-derives it from the
    /// next drain attempt's own 413 rather than trusting a stale verdict.
    blocked: Rc<RefCell<Option<BlockedOp>>>,
    /// The drain's settings-refused hold, on the same in-memory terms as
    /// [`blocked`](Self::blocked): a restart re-derives it from the next drain
    /// attempt's own verdict.
    settings_hold: Rc<RefCell<Option<SettingsHold>>>,
    /// Pinned bytes a published prune still owes the registry, written by the
    /// drain tick and read by [`pending_reclaim_bytes`](Self::pending_reclaim_bytes).
    /// In-memory: the durable record is the retire ledger, which every pass re-reads.
    pending_reclaim: Rc<Cell<u64>>,
    /// Head blocks the drain uploaded for a publish that never reached the
    /// record transport, pending retirement. Session-lived so a retire the
    /// registry refused goes out again on a later pass.
    orphan_heads: Rc<OrphanHeads>,
    /// Session-alive latch: cleared on drop so the spawned liveness loop
    /// stops at its next wake instead of re-PUTting after the engine is gone.
    alive: Rc<Cell<bool>>,
    /// The resolve tick's second wake source, shared with the spawned loop:
    /// [`Command::ManualRefresh`] files a request here and awaits its verdict.
    manual_refresh: ManualRefresh,
    /// The cold-start session identity, derived from the login secret at
    /// [`start`](Self::start). `None` until then; the single place derived key
    /// material lives once the engine is live. The resolve/publish/rotation
    /// slices read every signer from here. Owned outright, never shared, so the
    /// retained login secret drops with the engine.
    session: Option<SessionIdentity>,
    /// The one piece of session secret the resolve-tick loop needs — the
    /// encryption subkey it opens owner blobs and op records with — in a cell
    /// the engine empties on drop. A parked task is not polled until its next
    /// scheduler wake, so anything the loop captured outright would stay
    /// resident for up to that wake past the engine (security rules 1/7); every
    /// shared cell below carrying key material is cleared the same way.
    tick_enc_subkey: Rc<RefCell<Option<X25519Secret>>>,
    /// Built at [`start`](Self::start), where the seam bounds its task needs
    /// hold, and waiting for a root name to poll.
    tick_loop_spawner: RefCell<Option<TickLoopSpawner>>,
    /// Builds the sweep task every rotation arm enqueues. Built at
    /// [`start`](Self::start) for the same reason the tick loop is: a spawned
    /// task is `'static`, and the command path's seam bounds are narrower.
    sweep_tasks: RefCell<Option<SweepTaskFactory>>,
    /// What a spawned sweep opens and signs with, shared with every task it
    /// produces and emptied on drop — the tasks read through this cell, so
    /// teardown revokes the material instead of waiting out the last pass. The
    /// tick's polled pointer consult reads the same cell rather than holding a
    /// second copy of the two owner seeds.
    sweep_keys: Rc<RefCell<Option<Rc<SweepKeys>>>>,
    /// Where this session's bytes go, decided at [`start`](Self::start) from the
    /// vault settings load and re-decided by a settings save, and shared with
    /// the drain. Carries its own provenance, because an assumed placement must
    /// never latch account-scoped state. `None` until start, and emptied on drop
    /// like [`tick_enc_subkey`](Self::tick_enc_subkey) — the config it holds
    /// carries the member's provider bearer.
    placement: Rc<RefCell<Option<SessionPlacement>>>,
    /// Whether this session has already held the account's `byo` flag to the
    /// vaulted mode. Latched per placement decision, not per write: the flag is
    /// account-wide, so re-deriving it on every write would let two devices flap
    /// it — a saved settings change is the one event that re-arms it.
    byo_reconciled: Cell<bool>,
    /// The one shared API client, built and logged in at [`start`](Self::start)
    /// and handed to the liveness loop so the access JWT is shared across
    /// publish/renew (no redundant 401→refresh). `None` until then.
    api: Option<Rc<ApiClient<T::Http, T::CredentialStore>>>,
    started: bool,
    /// Terminal: [`Command::ForgetDevice`] swept the seams, so this instance
    /// serves nothing further. Separate from `started`, which stays write-once.
    forgotten: bool,
}

impl<T: SeamTypes> Engine<T> {
    /// Builds an engine over the whole seam set and hands back the paired
    /// event stream.
    pub fn new(
        seams: SeamSet<T>,
        entropy: Box<dyn Entropy>,
        profile: SyncTimingProfile,
        content_profile: ContentProfile,
        storage_policy: StoragePolicy,
        api_base_url: ApiBaseUrl,
        gateway: GatewayConfig,
    ) -> (Self, EventStream) {
        let (events, receiver) = mpsc::unbounded();
        let session_bearer = SessionBearer::default();
        let accelerator_bearer = SessionBearer::default();
        (
            Self {
                seams,
                entropy: Rc::new(RefCell::new(entropy)),
                profile,
                storage_policy,
                content_profile,
                writes: RefCell::new(LiveWrites::default()),
                streams: RefCell::new(LiveStreams::default()),
                live_blocks: Rc::new(RefCell::new(LiveBlocks::default())),
                cancels: Rc::new(RefCell::new(UploadCancels::default())),
                api_base_url,
                gateway: gateway.into_gateway(accelerator_bearer.clone()),
                session_bearer,
                accelerator_bearer,
                events,
                // The anchored all-zero root until cold-start/resolve replaces
                // the base snapshot; children come from the pending-op overlay.
                snapshot: Rc::new(RefCell::new(Snapshot::new(NodeId([0u8; 16])))),
                held_records: Rc::new(RefCell::new(HeldRecords::new())),
                settings_record: Rc::new(RefCell::new(None)),
                sync_status: Rc::new(RefCell::new(SyncStatus::default())),
                scope_read_seeds: Rc::new(RefCell::new(BTreeMap::new())),
                scope_write_seeds: Rc::new(RefCell::new(BTreeMap::new())),
                focus: Rc::new(RefCell::new(FocusWindow::default())),
                focus_refreshed: Rc::new(RefCell::new(BTreeMap::new())),
                pointer_consulted: Rc::new(RefCell::new(BTreeMap::new())),
                received_verdicts: Rc::new(RefCell::new(ReceivedVerdicts::new())),
                focus_touched: Rc::new(Cell::new(None)),
                focus_hinted: Cell::new(None),
                focus_files: Rc::new(RefCell::new(Vec::new())),
                dead_letters: Rc::new(RefCell::new(BTreeMap::new())),
                queue_scan: RefCell::new(QueueScanMemo::default()),
                blocked: Rc::new(RefCell::new(None)),
                settings_hold: Rc::new(RefCell::new(None)),
                pending_reclaim: Rc::new(Cell::new(0)),
                orphan_heads: Rc::new(OrphanHeads::default()),
                alive: Rc::new(Cell::new(true)),
                manual_refresh: ManualRefresh::default(),
                session: None,
                tick_enc_subkey: Rc::new(RefCell::new(None)),
                tick_loop_spawner: RefCell::new(None),
                sweep_tasks: RefCell::new(None),
                sweep_keys: Rc::new(RefCell::new(None)),
                placement: Rc::new(RefCell::new(None)),
                byo_reconciled: Cell::new(false),
                api: None,
                started: false,
                forgotten: false,
            },
            EventStream { receiver },
        )
    }

    /// Start of secret: consumes the login secret and brings the engine up.
    ///
    /// Derives the cold-start [`SessionIdentity`] from the secret — the
    /// owner-plane identity that needs no network (enc subkey, owner pointer
    /// seed, vault-pointer signer chain), plus the per-scope/per-name signer
    /// factories the pipeline layers scope material onto — then runs the
    /// cold-start data path off it ([`cold_start_data_path`](Self::cold_start_data_path)).
    ///
    /// The lifecycle contract holds: exactly one successful `start` per
    /// instance, and the secret is zeroized on consumption — derivation is the
    /// only reader, and the secret is dropped at its terminal owner the moment
    /// the identity is built.
    pub async fn start(&mut self, secret: LoginSecret) -> Result<(), EngineError>
    where
        T::Http: Clone + 'static,
        T::CredentialStore: Clone + 'static,
        T::FloorStore: Clone + 'static,
        T::SnapshotCache: Clone + 'static,
        T::StagingStore: Clone + 'static,
    {
        if self.forgotten {
            return Err(EngineError::Forgotten);
        }
        if self.started {
            return Err(EngineError::AlreadyStarted);
        }
        if secret.is_empty() {
            return Err(EngineError::InvalidSecret);
        }
        // Pure derivation from the injected secret — no clock, no RNG.
        let session = SessionIdentity::derive(&secret)?;

        // The one shared client for login, publish, and renewal. Login is
        // fail-closed: a rejected login returns before the session is committed
        // or any loop spawns, so the loop never runs unauthenticated (rules 3/6).
        let base_url = self.api_base_url.configured();
        let api = Rc::new(
            ApiClient::new(
                self.seams.http.clone(),
                self.seams.credential_store.clone(),
                base_url.unwrap_or_default().to_owned(),
            )
            .with_session_bearers(self.session_bearer.clone(), self.accelerator_bearer.clone()),
        );
        if base_url.is_some() {
            let signer = IdentityChallengeSigner::from_signer(session.identity().clone());
            api.login_identity(&signer)
                .await
                .map_err(EngineError::from_api)?;
        }

        // Where this session's bytes go. Server-free and ahead of any vault
        // resolve, so a self-hosting owner never needs CipherBox to tell them
        // where their own node is (blueprint/engine.md "Vault settings record").
        let settings = load_settings(
            &self.seams.record_transport,
            &self.gateway,
            &self.seams.http,
            &self.seams.floor_store,
            &self.seams.snapshot_cache,
            &self.seams.scheduler,
            &self.profile,
            secret.expose(),
        )
        .await;
        *self.placement.borrow_mut() = Some(decide_placement(&settings));
        // The secret zeroizes on drop here, at its terminal owner.
        drop(secret);

        self.session = Some(session);

        // Cold-start data path (E4/E7): resolve the owner vault pointer, cold-seed
        // the floors, adopt the current root through the gate, and project its base
        // snapshot — all off the production `RecordPointerFetch`/`RootAdopter` over
        // the engine's own gateway/seams. Fail-closed: a trust violation clears the
        // just-derived session and returns before either background loop spawns, so
        // no derived key material stays resident and nothing runs past an unadopted
        // root (rules 4/6). An empty chain (a first-run vault with no pointer yet)
        // degrades to the anchored root with no error.
        let root = self.snapshot.borrow().root;
        let root_scope_id = root.0;
        let mut outcome = self.cold_start_or_clear(root).await?;
        // An empty chain is an account that has never published: mint its genesis
        // vault before anything reads one (`sync/provision.rs`). Register-first
        // has no offline form, so the harness's no-API mode skips provisioning
        // for the same reason it skips login ([`ApiBaseUrl::offline`]).
        let provisioned =
            if outcome.vault_pointer.is_none() && self.api_base_url.configured().is_some() {
                match self.provision_first_run_vault(&api, root_scope_id).await {
                    Ok(ProvisionOutcome::Minted(vault)) => Some(*vault),
                    Ok(ProvisionOutcome::MovedOn) => {
                        outcome = self.cold_start_or_clear(root).await?;
                        None
                    }
                    // Non-fatal, on the same terms as the empty chain this ran
                    // for: cold start already paints an unprovisioned vault and
                    // queues ops against it, so a mint that did not land leaves
                    // the engine exactly where `main` left it — minus the
                    // silence.
                    Err(err) => {
                        let _ = self.events.unbounded_send(Event::VaultUnprovisioned {
                            retryable: err.is_retryable(),
                            detail: err.to_string(),
                        });
                        None
                    }
                }
            } else {
                None
            };
        let mut root_name = self.install_cold_start(outcome, root_scope_id);
        if let Some(provisioned) = provisioned {
            root_name = Some(self.install_mint(provisioned));
        }
        // A successful cold start is a successful reconcile: stamp it so the
        // ladder starts Fresh rather than Reconciling.
        self.sync_status.borrow_mut().last_success = Some(self.seams.scheduler.now());

        // A crash between staging a version's blocks and journaling its op
        // leaves them referenced by nothing, so cold start is the first place
        // that residue can be reclaimed.
        collect_orphans(&self.seams.staging_store, &self.live_blocks).await;

        self.spawn_liveness_loop(api.clone());
        *self.sweep_tasks.borrow_mut() = self.build_sweep_task_factory(api.clone());
        *self.tick_loop_spawner.borrow_mut() = self.build_tick_loop_spawner(api.clone());
        if let Some(root_name) = root_name {
            self.open_tick_loop(root_name);
        }
        self.api = Some(api);
        self.started = true;
        Ok(())
    }

    /// Bring a cold-start outcome up as this session's data path: deposit both
    /// scope seeds, install the gate-passing base as the state law's left
    /// operand, and answer the resolved root name (the vault pointer's
    /// `currentRoot`) the tick loop polls — `None` on an empty chain.
    ///
    /// Both seeds are stamped from the owner-vouched re-point the cold-seed
    /// installed the floors from, and which the adopt and the owner-write-blob
    /// AAD then bound to — the epochs they belong to, not a later floor read
    /// (see `deposit_seed`).
    fn install_cold_start(
        &self,
        mut outcome: ColdStartOutcome,
        root_scope_id: [u8; 16],
    ) -> Option<IpnsName> {
        let vouched = outcome.vault_pointer.as_ref().map(|vp| &vp.repoint);
        // A gate-passing root adopt surfaced the scope read seed: deposit it in
        // the in-memory per-scope cell the child read pipeline derives from.
        if let Some(seed) = outcome.read_scope_seed.take() {
            deposit_seed(
                &self.scope_read_seeds,
                root_scope_id,
                seed,
                vouched.map(|repoint| repoint.min_read_epoch),
            );
        }
        let root_name = outcome
            .vault_pointer
            .as_ref()
            .map(|vp| vp.repoint.current_root.clone());
        // The same adopt recovered the scope write seed: the drain derives every
        // new node's `ipnsName` and its narrow per-name signer from it.
        if let Some((scope_id, seed)) = outcome.write_scope_seed.take() {
            deposit_write_seed(
                &self.scope_write_seeds,
                scope_id,
                seed,
                root_name.as_ref(),
                vouched.map(|repoint| repoint.write_epoch),
            );
        }
        *self.snapshot.borrow_mut() = outcome.base;
        root_name
    }

    /// Deposit a fresh mint's seeds and answer the root name it published. A
    /// just-provisioned vault has no adopt to surface them — this run minted
    /// them — so they are stamped at the epochs its own re-point vouches and
    /// the floors it seeded from them.
    fn install_mint(&self, vault: ProvisionedVault) -> IpnsName {
        deposit_seed(
            &self.scope_read_seeds,
            vault.repoint.scope_id,
            vault.read_scope_seed,
            Some(vault.repoint.min_read_epoch),
        );
        deposit_write_seed(
            &self.scope_write_seeds,
            vault.repoint.scope_id,
            vault.write_scope_seed,
            Some(&vault.root_name),
            Some(vault.repoint.write_epoch),
        );
        vault.root_name
    }

    /// Whether this session holds the root scope's write seed — the material a
    /// publish needs. `false` means the vault is unprovisioned (or held
    /// keyless): reads paint and ops queue, but nothing will publish until a
    /// mint lands, which a forced refresh retries. The event stream announces it
    /// ([`Event::VaultUnprovisioned`]); this answers a host that attached after.
    pub fn is_provisioned(&self) -> bool {
        let root = self.snapshot.borrow().root.0;
        self.scope_write_seeds.borrow().contains_key(&root)
    }

    /// The live session identity, once [`start`](Self::start) has derived it.
    /// `pub(crate)`: the in-crate pipeline (resolve, publish, rotation, the
    /// liveness loop) reads its signers here; hosts wrap the facade and never
    /// hold key material.
    #[allow(dead_code)]
    pub(crate) fn session(&self) -> Option<&SessionIdentity> {
        self.session.as_ref()
    }

    /// Stop the spawned loops at their next wake and drop the key material they
    /// share with the engine here and now, at the terminal owner (security rule
    /// 7) — see [`tick_enc_subkey`](Self::tick_enc_subkey). `try_borrow_mut`
    /// because a panic while dropping aborts the process.
    fn shut_down(&self) {
        self.alive.set(false);
        // Sealed, not cleared: the gateway clone a parked tick holds shares this
        // cell, and a refresh still on the wire would re-arm a plain clear
        // (security rule 7).
        self.session_bearer.seal();
        self.accelerator_bearer.seal();
        // Every parked manual refresh fails now: no pass is left to answer it.
        self.manual_refresh.close();
        if let Ok(mut enc_subkey) = self.tick_enc_subkey.try_borrow_mut() {
            *enc_subkey = None;
        }
        if let Ok(mut spawner) = self.tick_loop_spawner.try_borrow_mut() {
            *spawner = None;
        }
        if let Ok(mut sweep_tasks) = self.sweep_tasks.try_borrow_mut() {
            *sweep_tasks = None;
        }
        if let Ok(mut keys) = self.sweep_keys.try_borrow_mut() {
            *keys = None;
        }
        if let Ok(mut placement) = self.placement.try_borrow_mut() {
            *placement = None;
        }
        if let Ok(mut held) = self.held_records.try_borrow_mut() {
            held.clear();
        }
        if let Ok(mut settings) = self.settings_record.try_borrow_mut() {
            *settings = None;
        }
        // Each open stream pins a version's content key; releasing the table's
        // `Rc`s here is what makes this the terminal owner (security rule 7).
        if let Ok(mut streams) = self.streams.try_borrow_mut() {
            streams.open.clear();
        }
        for seeds in [&self.scope_read_seeds, &self.scope_write_seeds] {
            if let Ok(mut seeds) = seeds.try_borrow_mut() {
                seeds.clear();
            }
        }
        if let Ok(mut consulted) = self.pointer_consulted.try_borrow_mut() {
            consulted.clear();
        }
        if let Ok(mut verdicts) = self.received_verdicts.try_borrow_mut() {
            verdicts.clear();
        }
    }

    /// The gate every entry point shares: a forget latches the instance
    /// terminal, and an engine that never started has nothing to serve.
    fn live_session(&self) -> Result<(), EngineError> {
        match (self.forgotten, self.started) {
            (true, _) => Err(EngineError::Forgotten),
            (_, false) => Err(EngineError::NotStarted),
            _ => Ok(()),
        }
    }

    /// [`Command::ForgetDevice`]: stop the session, then erase every durable
    /// seam.
    ///
    /// The sweep is last, and `shut_down` drops the session-alive latch before
    /// it: a floor raise or cache put from a pass still in flight would
    /// otherwise land behind the erase and re-seed the device with state it just
    /// disowned. Those passes hold [`LiveSeam`] handles, which is what makes the
    /// latch bind them ([`Scheduler::spawn`] cannot cancel or join).
    ///
    /// Every seam is swept even after one refuses, and the first refusal is what
    /// the caller sees.
    async fn forget_device(&mut self) -> Result<(), EngineError> {
        self.forgotten = true;
        let api = self.api.take();

        // Best-effort, before the seams and outside the verdict: this is the
        // one leg that needs the network, and the erase must land offline. On
        // web the refresh credential is an HTTP-only cookie no seam can reach,
        // so a server-side revoke is the only thing that ends it. It runs
        // *before* `shut_down`, which seals the bearer the endpoint
        // authenticates with — an unauthenticated revoke leaves the cookie live.
        if let Some(api) = &api {
            let _ = api.logout().await;
        }

        self.shut_down();
        // Dropped here, at the terminal owner: `shut_down` seals what the loops
        // share, and these are the engine's own copies (security rule 7). The
        // render goes with them — it is plaintext metadata about the vault this
        // device is disowning.
        drop(api);
        self.session = None;
        let root = self.snapshot.borrow().root;
        *self.snapshot.borrow_mut() = Snapshot::new(root);

        [
            self.seams.credential_store.clear_refresh_token().await,
            self.seams.staging_store.clear().await,
            self.seams.snapshot_cache.clear().await,
            self.seams.floor_store.clear().await,
        ]
        .into_iter()
        .find(Result::is_err)
        .unwrap_or(Ok(()))
        .map_err(EngineError::from_seam)
    }

    /// Run the cold-start live-session data path — the ordered chain composed on
    /// top of the derived [`SessionIdentity`] (blueprint/engine.md cold-start
    /// sequence): vault-pointer resolve → floor cold-seed (fail-closed on
    /// regression) → current root name adoption through the gate → first
    /// [`Event::SnapshotUpdated`] with the pending-op overlay, cache-first from
    /// the snapshot cache. Any queue entry that fails to decode is surfaced as
    /// an [`Event::DeadLetter`] and dropped from the durable queue before the
    /// chain runs, so a corrupt entry is not re-emitted on the next boot.
    ///
    /// Emits no clock/RNG-derived value, so the whole chain is deterministic off
    /// the injected seams; the record plane enters through the [`PointerFetch`]
    /// and [`Adopter`] seam traits.
    ///
    /// `owner_identity` is the auth-provided contact-code-anchored identity that
    /// signs the re-point object — the vault-pointer walk's fail-closed anchor.
    pub(crate) async fn cold_start_data_path<Pf, Ad>(
        &self,
        pointer_fetch: &Pf,
        adopter: &Ad,
        owner_identity: &EcdsaVerifier,
        root_scope_id: [u8; 16],
        payload_version: u64,
        root: NodeId,
    ) -> Result<ColdStartOutcome, ColdStartError>
    where
        Pf: PointerFetch,
        Ad: Adopter,
    {
        // Precondition guard fails fast before any seam I/O, so an unstarted
        // engine returns `NotStarted` rather than misclassifying a staging-store
        // failure as retryable `Seam`.
        let session = self.session.as_ref().ok_or(ColdStartError::NotStarted)?;
        let raw = self
            .seams
            .staging_store
            .queued_ops()
            .await
            .map_err(ColdStartError::Seam)?;
        let scan = decode_queue(&RecordReader::new(session.enc_subkey()), &raw);
        let pending: Vec<_> = scan.mine.into_iter().map(|(_id, op)| op).collect();

        // Surface every undecodable queue entry as `Event::DeadLetter` and drop
        // its op record from the durable queue so a corrupt entry is not
        // re-decoded and re-emitted on every boot.
        //
        // `DeadLetter` delivery is best-effort over a non-durable in-process
        // channel, so hosts MUST dedup by `op_id`. Gate the durable removal on a
        // successful send: a receiver dropped mid-teardown must not silently
        // purge an unsurfaced entry — preserved, the next boot re-surfaces it.
        for (op_id, reason) in &scan.undecodable {
            // Retain the dead letter (target unknown for an undecodable entry)
            // so the read surface keeps reporting it.
            self.dead_letters
                .borrow_mut()
                .insert(*op_id, (None, *reason));
            if self
                .events
                .unbounded_send(Event::DeadLetter {
                    op_id: *op_id,
                    reason: *reason,
                })
                .is_ok()
            {
                self.seams
                    .staging_store
                    .remove_op(*op_id)
                    .await
                    .map_err(ColdStartError::Seam)?;
            }
        }

        let params = ColdStartParams {
            login_secret: session.login_secret(),
            owner_identity,
            root_scope_id,
            payload_version,
            root,
            pending_ops: &pending,
        };
        let events = self.events.clone();
        cold_start(
            pointer_fetch,
            adopter,
            &self.seams.floor_store,
            &self.seams.record_transport,
            &self.seams.snapshot_cache,
            &params,
            &mut |event: Event| {
                let _ = events.unbounded_send(event);
            },
        )
        .await
    }

    /// Run [`cold_start_data_path`](Self::cold_start_data_path) over the live
    /// record plane, clearing the session fail-closed on a trust violation
    /// ([`Self::clear_failed_start`]) so no key material stays resident.
    async fn cold_start_or_clear(&mut self, root: NodeId) -> Result<ColdStartOutcome, EngineError> {
        match self.run_cold_start(root).await {
            Ok(outcome) => Ok(outcome),
            Err(err) => {
                self.clear_failed_start();
                Err(EngineError::from_cold_start(err))
            }
        }
    }

    /// Run [`cold_start_data_path`](Self::cold_start_data_path) over the live
    /// record plane, off the session `start` has already derived.
    async fn run_cold_start(&self, root: NodeId) -> Result<ColdStartOutcome, ColdStartError> {
        let session = self.session.as_ref().ok_or(ColdStartError::NotStarted)?;
        let owner_identity = session.owner_identity();
        let pointer_fetch = RecordPointerFetch::new(&self.seams.record_transport);
        let adopter = self.root_adopter(session, &owner_identity, root.0);
        self.cold_start_data_path(
            &pointer_fetch,
            &adopter,
            &owner_identity,
            root.0,
            POINTER_PAYLOAD_VERSION,
            root,
        )
        .await
    }

    /// The owner-root adopter both the cold-start chain and the mint's root step
    /// run under. One construction, because D3 rests on them being the same gate:
    /// a mint that confirmed against a laxer adopter than cold start adopts
    /// through would skip publishing a record the next boot then rejects.
    fn root_adopter<'a>(
        &'a self,
        session: &'a SessionIdentity,
        owner_identity: &'a EcdsaVerifier,
        scope_id: [u8; 16],
    ) -> RootAdopter<'a, T::Http, T::FloorStore> {
        RootAdopter::new(
            &self.gateway,
            &self.seams.http,
            &self.seams.floor_store,
            session.enc_subkey(),
            owner_identity,
            scope_id,
        )
    }

    /// Fail-closed symmetry with the login path: clear the derived session and
    /// the placement decision beside it, so the engine reports unstarted. The
    /// access token login already stored outlives the dropped client in the
    /// shared bearer cell, so it is dropped here by name.
    fn clear_failed_start(&mut self) {
        self.session = None;
        *self.tick_loop_spawner.borrow_mut() = None;
        *self.placement.borrow_mut() = None;
        self.session_bearer.clear();
        self.accelerator_bearer.clear();
    }

    /// Mint this account's first vault: the genesis scope root and the vault
    /// pointer naming it ([`provision_vault`]). Called from
    /// [`start`](Self::start) on an empty pointer chain only, before the seed
    /// deposits and before any loop spawns.
    ///
    /// The owner's per-scope derivations go in as [`OwnerSessionKeys`], the same
    /// arm every re-seal resolves them through — so the writer pseudonym the
    /// commitment names is by construction the one a later rotation signs under.
    async fn provision_first_run_vault(
        &self,
        api: &Rc<ApiClient<T::Http, T::CredentialStore>>,
        root_scope_id: [u8; 16],
    ) -> Result<ProvisionOutcome, ProvisionError>
where {
        let session = self.session.as_ref().expect("session set by start");
        let owner_identity = session.owner_identity();
        let publisher = VaultProvisionNet {
            transport: &self.seams.record_transport,
            adopter: &self.root_adopter(session, &owner_identity, root_scope_id),
            api,
            floors: &self.seams.floor_store,
            scheduler: &self.seams.scheduler,
            profile: &self.profile,
        };
        provision_vault(
            &self.entropy,
            &OwnerSessionKeys::new(session),
            &publisher,
            &RecordPointerFetch::new(&self.seams.record_transport),
            &self.seams.floor_store,
            &ProvisionPlan {
                scope_id: root_scope_id,
                payload_version: POINTER_PAYLOAD_VERSION,
                owner_identity: session.identity(),
                owner_enc_secret: session.enc_subkey(),
                vault_pointer_signer: &session.vault_pointer_signer(GENESIS_VAULT_POINTER_INDEX),
                genesis_read_scope_seed: &session.genesis_read_scope_seed(),
                genesis_write_scope_seed: &session.genesis_write_scope_seed(),
                created_at: self.seams.scheduler.now().0,
            },
        )
        .await
    }

    /// Build the factory for the lazy-wave sweep task every rotation enqueues
    /// once its cut is durable (blueprint/engine.md "Rotation primitives:
    /// sweep").
    ///
    /// Built here for the reason
    /// [`build_tick_loop_spawner`](Self::build_tick_loop_spawner) is. `None`
    /// when there is no session to derive the owner's two rotation seeds from.
    fn build_sweep_task_factory(
        &self,
        api: Rc<ApiClient<T::Http, T::CredentialStore>>,
    ) -> Option<SweepTaskFactory>
    where
        T::Http: Clone + 'static,
        T::CredentialStore: Clone + 'static,
        T::FloorStore: Clone + 'static,
    {
        let session = self.session.as_ref()?;
        *self.sweep_keys.borrow_mut() = Some(Rc::new(SweepKeys {
            enc_secret: session.enc_subkey().clone(),
            owner_identity: session.owner_identity(),
            scope_keys: OwnerSeedKeys::of(session),
        }));
        let held = self.sweep_keys.clone();
        let transport = self.seams.record_transport.clone();
        let floors = LiveSeam::new(self.seams.floor_store.clone(), self.alive.clone());
        let scheduler = self.seams.scheduler.clone();
        let http = self.seams.http.clone();
        let gateway = self.gateway.clone();
        let entropy = self.entropy.clone();
        let alive = self.alive.clone();
        let profile = self.profile;

        Some(Rc::new(
            move |scope: ChildScopeRef, parent_node_seed: Option<Zeroizing<[u8; 32]>>| {
                let held = held.clone();
                let api = api.clone();
                let transport = transport.clone();
                let floors = floors.clone();
                let scheduler = scheduler.clone();
                let http = http.clone();
                let gateway = gateway.clone();
                let entropy = entropy.clone();
                let alive = alive.clone();
                Box::pin(async move {
                    // The pass owns a copy for exactly its own duration; the
                    // engine emptied the cell if the session is already gone.
                    let Some(keys) = held.borrow().clone() else {
                        return;
                    };
                    let net = OwnerRotationNet {
                        transport: &transport,
                        api: api.as_ref(),
                        gateway: &gateway,
                        http: &http,
                        floors: &floors,
                        scheduler: &scheduler,
                        profile: &profile,
                        entropy: &entropy,
                        keys: OwnerRotationKeys {
                            enc_secret: &keys.enc_secret,
                            identity: &keys.owner_identity,
                            scope_keys: &keys.scope_keys,
                        },
                        // An interior scope root's every gated read must prove
                        // its ascent link, so the walk carries the ancestor seed
                        // the rotation read it under.
                        ancestry: RotationAncestry::default()
                            .under_parent_node_seed(scope.scope_id, parent_node_seed.as_deref()),
                        pointer_consult: PointerConsultArm::Permitted,
                        payload_version: POINTER_PAYLOAD_VERSION,
                        gated: GatedRoots::default(),
                        swept: SweptScopeState::default(),
                    };
                    // The wave is idempotent and every later write advances it,
                    // so a pass that does not converge is left to the next one.
                    let _ = run_sweep(
                        &scheduler,
                        &net,
                        &net,
                        &scope,
                        profile.poll_cadence,
                        SWEEP_MAX_PASSES,
                        &|| alive.get() && held.borrow().is_some(),
                    )
                    .await;
                }) as BoxedTask
            },
        ))
    }

    /// Spawn the ~hourly liveness loop (blueprint/engine.md "Liveness"):
    /// actively-used vaults keep their own records alive off the injected
    /// scheduler, so no client depends on the API republisher. Each pass runs
    /// the keyless re-PUT (every held record, byte-for-byte) and then the
    /// sub-EOL seq+1 renewal (any name inside the 30-day EOL window). The task
    /// holds only `Rc`/seam-handle clones, so the engine may drop while it is
    /// parked; the alive latch then stops it.
    fn spawn_liveness_loop(&self, api: Rc<ApiClient<T::Http, T::CredentialStore>>)
    where
        T::Http: Clone + 'static,
        T::CredentialStore: Clone + 'static,
        T::FloorStore: Clone + 'static,
    {
        let scheduler = self.seams.scheduler.clone();
        let transport = self.seams.record_transport.clone();
        let floors = LiveSeam::new(self.seams.floor_store.clone(), self.alive.clone());
        let profile = self.profile;
        let held = self.held_records.clone();
        let settings_record = self.settings_record.clone();
        let alive = self.alive.clone();
        let events = self.events.clone();
        self.seams.scheduler.spawn(Box::pin(async move {
            run_liveness_loop(&scheduler, RE_PUT_INTERVAL, || async {
                if !alive.get() {
                    return LivenessControl::Stop;
                }
                let settings = live_settings_record(&transport, &settings_record).await;
                let records: Vec<HeldRecord> =
                    held.borrow().values().cloned().chain(settings).collect();
                keyless_re_put(&transport, &records).await;
                // Surface every renewal that did not land (LostRace/PublishError)
                // as an Event — never a silent failure (blueprint/engine.md).
                let renewals =
                    eol_renew_pass(&transport, &api, &floors, &scheduler, &profile, &records).await;
                emit_renewal_failures(&events, &renewals);
                LivenessControl::Continue
            })
            .await;
        }));
    }

    /// Spawn the fixed-cadence resolve-tick driver (blueprint/engine.md
    /// "Resolve/publish pipeline", "Liveness"): each pass re-resolves the owner
    /// root through the adoption gate and inserts the gate-passing record into the
    /// held set the liveness loop keeps alive. Fixed cadence off the injected
    /// scheduler's focus-window `poll_cadence` — the determinism law's only time
    /// source is `scheduler.sleep`, so it holds under virtual time. The task holds
    /// only `Rc`/seam-handle clones and the alive latch, so it stops once the
    /// engine drops.
    ///
    /// The task is built here rather than spawned, so the root name it polls may
    /// arrive later: an account whose first-run mint did not land has no root at
    /// `start` and gets one from [`provision_in_session`](Self::provision_in_session),
    /// which runs off the narrow `command` path where these seam bounds do not
    /// hold. `None` when there is no session to build one from.
    fn build_tick_loop_spawner(
        &self,
        api: Rc<ApiClient<T::Http, T::CredentialStore>>,
    ) -> Option<TickLoopSpawner>
    where
        T::Http: Clone + 'static,
        T::CredentialStore: Clone + 'static,
        T::FloorStore: Clone + 'static,
        T::SnapshotCache: Clone + 'static,
        T::StagingStore: Clone + 'static,
    {
        let session = self.session.as_ref()?;
        let tick_enc_subkey = self.tick_enc_subkey.clone();
        let scheduler = self.seams.scheduler.clone();
        let staging = LiveSeam::new(self.seams.staging_store.clone(), self.alive.clone());
        let entropy = self.entropy.clone();
        let scope_write_seeds = self.scope_write_seeds.clone();
        let dead_letters = self.dead_letters.clone();
        let blocked = self.blocked.clone();
        let settings_hold = self.settings_hold.clone();
        let pending_reclaim = self.pending_reclaim.clone();
        let content_profile = self.content_profile;
        let storage_policy = self.storage_policy;
        let orphan_heads = self.orphan_heads.clone();
        let cancels = self.cancels.clone();
        let live_blocks = self.live_blocks.clone();
        let transport = self.seams.record_transport.clone();
        let snapshot_cache = LiveSeam::new(self.seams.snapshot_cache.clone(), self.alive.clone());
        let floors = LiveSeam::new(self.seams.floor_store.clone(), self.alive.clone());
        let http = self.seams.http.clone();
        let gateway = self.gateway.clone();
        let placement = self.placement.clone();
        let held = self.held_records.clone();
        let base = self.snapshot.clone();
        let events = self.events.clone();
        let alive = self.alive.clone();
        let sync_status = self.sync_status.clone();
        let scope_read_seeds = self.scope_read_seeds.clone();
        let focus = self.focus.clone();
        let focus_touched = self.focus_touched.clone();
        let focus_refreshed = self.focus_refreshed.clone();
        let focus_files = self.focus_files.clone();
        let pointer_consulted = self.pointer_consulted.clone();
        let received_verdicts = self.received_verdicts.clone();
        let consult_keys = self.sweep_keys.clone();
        let profile = self.profile;
        let interval = self.profile.poll_cadence;
        let owner_identity = session.owner_identity();
        // The vault's own root scope and root node are the anchored all-zero id16
        // (the cold-start bootstrap anchor): the adopter's scope binding and the
        // held-set fallback key.
        let root_id = self.snapshot.borrow().root.0;

        let manual = self.manual_refresh.clone();

        Some(Box::new(move |mut root_name: IpnsName| {
            manual.arm();
            let spawn_on = scheduler.clone();
            spawn_on.spawn(Box::pin(async move {
                run_tick_loop(&scheduler, &manual, interval, async |cause| {
                    if !alive.get() {
                        return TickControl::Stop;
                    }
                    let mode = resolve_mode(cause);
                    // The pass owns a copy for exactly its own duration; the engine
                    // emptied the cell if it is already gone.
                    let enc_subkey = tick_enc_subkey.borrow().clone();
                    let Some(enc_subkey) = enc_subkey else {
                        return TickControl::Stop;
                    };
                    // Carries the member's BYO bearer, so the pass owns a copy on the
                    // same terms as the enc subkey above.
                    let Some(SessionPlacement { decision, .. }) = placement.borrow().clone() else {
                        return TickControl::Stop;
                    };
                    // The polled pointer consult (#38 D4), ahead of the floor
                    // refresh below so a write epoch this pass sights evicts the
                    // seed it retired in the same pass.
                    let now = scheduler.now();
                    // A manual refresh resolves nocache everywhere, so it
                    // consults every scope in the window rather than waiting out
                    // the interval the poll leg is paced by.
                    let consult_targets = match mode {
                        ResolveMode::NoCache => consult_scopes(&base.borrow(), &focus.borrow()),
                        ResolveMode::CacheFirst => consult_scopes_due(
                            &base.borrow(),
                            &focus.borrow(),
                            &pointer_consulted.borrow(),
                            now,
                            &profile,
                        ),
                    };
                    if let Some(current_root) = consult_pointers(
                        &transport,
                        &floors,
                        &consult_keys,
                        &events,
                        &pointer_consulted,
                        ConsultWindow {
                            scopes: consult_targets,
                            anchor: NodeId(root_id),
                            now,
                        },
                    )
                    .await
                    {
                        root_name = current_root;
                    }
                    // Before the steady-state hold consults them: a floor raised
                    // since the last pass revokes the seeds this pass would
                    // otherwise read and seal under. The floors it reports stamp
                    // whatever this pass's own resolve recovers.
                    let floors_before = refresh_seed_floors(
                        &floors,
                        &root_id,
                        &scope_read_seeds,
                        &scope_write_seeds,
                    )
                    .await;
                    let adopter = RootAdopter::new(
                        &gateway,
                        &http,
                        &floors,
                        &enc_subkey,
                        &owner_identity,
                        root_id,
                    )
                    .holding(steady_state_hold(
                        &held,
                        root_id,
                        &root_name,
                        &scope_read_seeds,
                        &scope_write_seeds,
                    ));
                    // Own-root material: the write-scope seed the owner cannot
                    // re-derive rides the adopt (recovered from the owner-write-blob),
                    // so the caller-side seed is `None` and the gate's authenticated
                    // node id keys the hold. A resolve/gate failure is availability —
                    // it never stops the loop (blueprint/engine.md "Liveness").
                    let material = HeldMaterial {
                        node_id: root_id,
                        write_scope_seed: None,
                    };
                    // A gate-passing `Adopted` repaints the shared base cell and emits
                    // `SnapshotUpdated`; `Current`/`NoUpdate`/`TrustViolation` leave
                    // last-known-good intact (fail-closed for data).
                    sync_status.borrow_mut().reconcile_in_flight = true;
                    let mut held_resolve = resolve_and_hold(
                        &transport,
                        &snapshot_cache,
                        &adopter,
                        &root_name,
                        &held,
                        &material,
                        mode,
                    )
                    .await;
                    // A gate-passing adopt re-surfaces the scope seeds: refresh the
                    // in-memory per-scope cells the child read pipeline and the
                    // drain derive from.
                    if let Ok(surfaced) = &mut held_resolve {
                        if let Some(seed) = surfaced.read_scope_seed.take() {
                            // An adopt names the epoch its own owner blob's seed
                            // belongs to; an equal-floor `Current` recovery does not,
                            // and takes the pre-resolve floor (see `deposit_seed`).
                            let stamp = match &surfaced.resolved.outcome {
                                ResolveOutcome::Adopted(adopted) => Some(adopted.epoch),
                                _ => floors_before.read,
                            };
                            deposit_seed(&scope_read_seeds, root_id, seed, stamp);
                        }
                        if let Some((node_id, seed)) = surfaced.write_scope_seed.take() {
                            deposit_write_seed(
                                &scope_write_seeds,
                                node_id,
                                seed,
                                Some(&root_name),
                                floors_before.write,
                            );
                        }
                    }
                    let resolved = held_resolve.map(|surfaced| surfaced.resolved);
                    if let Ok(resolved) = &resolved {
                        if let ResolveOutcome::TrustViolation(rejection) = &resolved.outcome {
                            emit_trust_violation(&events, root_name.as_str(), rejection);
                        }
                        if refresh_base_from_outcome(&base, NodeId(root_id), &resolved.outcome) {
                            let _ = events.unbounded_send(Event::SnapshotUpdated);
                        }
                    }
                    let read_seed = cached_seed(&scope_read_seeds, &root_id);
                    // A host that derives focus from an operation stream cannot
                    // close its own window: a stream that stops arriving produces
                    // no call to close it with. The tick has the timer, so the
                    // tick closes it.
                    if focus_window_expired(scheduler.now(), focus_touched.get(), &profile) {
                        focus.borrow_mut().open_folder = None;
                        focus_touched.set(None);
                    }
                    // The focus window's folders below the root — the read leg for a
                    // subtree this device did not author. It runs before the drain,
                    // so the queue rebases onto the deepest state this pass
                    // reconciled, not just the root's.
                    let open = focus_folders(&base.borrow(), &focus.borrow());
                    let mut folder_verdict = RefreshVerdict::Reconciled;
                    if let Some(read_seed) = &read_seed {
                        let refresh = FolderRefresh {
                            transport: &transport,
                            snapshot_cache: &snapshot_cache,
                            http: &http,
                            floors: &floors,
                            gateway: &gateway,
                            base: &base,
                            events: &events,
                            scope_id: root_id,
                            scope_read_seed: read_seed,
                            mode,
                        };
                        // This leg holds one scope's read material, so a file
                        // sealed under another would fail its AAD-bound unseal
                        // and be reported as abuse by an honest writer. Files
                        // outside it stay queued for the leg that can serve them.
                        let due_files = {
                            let base = base.borrow();
                            let mut queued = focus_files.borrow_mut();
                            let (mine, theirs) = queued.iter().partition(|file| {
                                base.ancestors(**file).last() == Some(&NodeId(root_id))
                            });
                            *queued = theirs;
                            mine
                        };
                        for (nodes, report) in [
                            (&open, refresh.run(&open).await),
                            (&due_files, refresh.run_files(&due_files).await),
                        ] {
                            if nodes.is_empty() {
                                continue;
                            }
                            stamp_focus_refreshed(&focus_refreshed, nodes, scheduler.now());
                            if report.changed {
                                let _ = events.unbounded_send(Event::SnapshotUpdated);
                            }
                            folder_verdict = folder_verdict.worst(report.verdict);
                        }
                    }
                    // `Adopted`/`Current` are the reconciled outcomes: both prove the
                    // record plane answered with gate-passing state, so both stamp
                    // the ladder's `last_success` (#33 D4). A gate rejection is a
                    // trust verdict, never the staleness the other failures are.
                    let root_verdict = match &resolved {
                        Ok(r) => match &r.outcome {
                            ResolveOutcome::Adopted(_) | ResolveOutcome::Current { .. } => {
                                RefreshVerdict::Reconciled
                            }
                            ResolveOutcome::TrustViolation(_) => RefreshVerdict::Rejected,
                            ResolveOutcome::NoUpdate => RefreshVerdict::Unreachable,
                        },
                        Err(_) => RefreshVerdict::Unreachable,
                    };
                    // The ladder measures the record plane, which the root leg alone
                    // proves answered: one focused folder that did not is staleness
                    // on that folder, not a plane-wide outage.
                    let reconciled = root_verdict == RefreshVerdict::Reconciled;
                    // Answer the manual requests on every read leg the pass forced,
                    // the focus window included — a refresh that left the folder in
                    // view unresolved has not landed. The drain below reports its own
                    // progress through the op events.
                    manual.settle(root_verdict.worst(folder_verdict));
                    // The drain rides the same tick: it publishes onto exactly the
                    // gate-passing state this pass just reconciled. Both scope seeds
                    // are required — without them there is no name to publish under
                    // and no key to seal with, so the queue simply waits.
                    let write_seed = cached_seed(&scope_write_seeds, &root_id);
                    if let (Some(read_seed), Some(write_seed)) = (read_seed, write_seed) {
                        let report = Drain {
                            transport: &transport,
                            api: &api,
                            floors: &floors,
                            snapshot_cache: &snapshot_cache,
                            staging: &staging,
                            scheduler: &scheduler,
                            http: &http,
                            gateway: &gateway,
                            placement: &decision,
                            profile: &profile,
                            preserved_budget_bytes: storage_policy.preserved_budget_bytes(),
                            content_profile: &content_profile,
                            entropy: &entropy,
                            base: &base,
                            held: &held,
                            blocked: &blocked,
                            settings_hold: &settings_hold,
                            pending_reclaim: &pending_reclaim,
                            orphan_heads: &orphan_heads,
                            cancels: &cancels,
                            events: &events,
                        }
                        .run(&DrainScope {
                            root: NodeId(root_id),
                            root_name: &root_name,
                            read_scope_seed: &read_seed,
                            write_scope_seed: &write_seed,
                            enc_secret: &enc_subkey,
                            owner_identity: &owner_identity,
                        })
                        .await;
                        surface_drain_report(&events, &dead_letters, &report);
                    }
                    // After the drain, so the pass's own removals are swept in the
                    // same tick rather than a cadence later.
                    collect_orphans(&staging, &live_blocks).await;
                    // Last, and after the settle above: the grantee's own read
                    // leg is the slowest in the pass, and a host refresh waits
                    // on nothing it reports.
                    ReceivedShareStatus {
                        transport: &transport,
                        gateway: &gateway,
                        http: &http,
                        floors: &floors,
                        enc_secret: &enc_subkey,
                    }
                    .refresh(&staging, &entropy, &received_verdicts, now, &profile)
                    .await;
                    let mut status = sync_status.borrow_mut();
                    status.reconcile_in_flight = false;
                    if reconciled {
                        status.last_success = Some(scheduler.now());
                    }
                    let rung = classify(
                        scheduler.now(),
                        status.last_success,
                        status.reconcile_in_flight,
                        Connectivity::Online,
                        &profile,
                    );
                    if status.reported != Some(rung) {
                        status.reported = Some(rung);
                        let _ = events.unbounded_send(Event::StalenessChanged { level: rung });
                    }
                    drop(status);
                    TickControl::Continue
                })
                .await;
            }));
        }))
    }

    /// Start polling `root_name`, consuming the spawner
    /// [`start`](Self::start) built. One session runs one tick loop, so a
    /// second call spawns nothing.
    fn open_tick_loop(&self, root_name: IpnsName) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let Some(spawn) = self.tick_loop_spawner.borrow_mut().take() else {
            return;
        };
        // Least privilege, drawn no earlier than the loop that reads it: the
        // pass needs the enc subkey and the (public) owner verifier, never the
        // login secret or the pointer seeds beside them.
        *self.tick_enc_subkey.borrow_mut() = Some(session.enc_subkey().clone());
        spawn(root_name);
    }

    /// Executes one command. The single write entry point: every mutation,
    /// share action, auth call, and manual refresh comes through here.
    ///
    /// The metadata intent ops (create/delete/rename/relink) stage onto the
    /// durable op queue via [`stage_op`] and emit [`Event::SnapshotUpdated`];
    /// the base sequence each op carries is read from the rendered view (state
    /// law), so an op rebases against the state the host saw. The grant,
    /// share, and rotation arms whose slices have not landed stay
    /// [`EngineError::Unimplemented`].
    ///
    pub async fn command(&mut self, command: Command) -> Result<CommandOutcome, EngineError> {
        // Ahead of the session gate: an engine whose `start` failed closed — a
        // regressed floor, an unreadable cache — is exactly the device whose
        // only recovery is to be forgotten, and it never reached a session.
        if matches!(command, Command::ForgetDevice) {
            return self.forget_device().await.map(|()| CommandOutcome::Done);
        }
        self.live_session()?;
        // One clock read per command, journaled on the op: a retried publish
        // re-mints the same sequence, so authoring time must not be re-read.
        let authored_at = self.seams.scheduler.now();
        match command {
            Command::Create { parent, name, kind } => {
                let target = self.mint_node_id()?;
                let base_sequence = self.base_sequence_for(parent).await?;
                let node = match kind {
                    NodeKind::Folder => NewNode::Folder,
                    NodeKind::File => NewNode::File { content: None },
                };
                let op = Op::create(target, parent, name, node, base_sequence, authored_at);
                self.stage_and_notify(&op).await
            }
            Command::Delete { node } => {
                // Both anchors snapshot the target's own sequence for the
                // conditional-delete rebase rule.
                let seq = self.base_sequence_for(node).await?;
                self.stage_and_notify(&Op::delete(node, seq, authored_at, seq))
                    .await
            }
            Command::Rename { node, new_name } => {
                let seq = self.base_sequence_for(node).await?;
                self.stage_and_notify(&Op::rename(node, new_name, seq, authored_at))
                    .await
            }
            Command::Relink { node, new_parent } => {
                let rendered = self.render().await?;
                let (from_parent, base_sequence) = self.relocation_anchors(&rendered, node);
                refuse_scope_exit(&rendered, new_parent)?;
                let op = Op::relink(
                    node,
                    from_parent,
                    new_parent,
                    base_sequence,
                    authored_at,
                    ScopeCrossing::Intra,
                );
                self.stage_and_notify(&op).await
            }
            Command::Move {
                node,
                new_parent,
                new_name,
                replacing,
            } => {
                let rendered = self.render().await?;
                let (from_parent, base_sequence) = self.relocation_anchors(&rendered, node);
                refuse_scope_exit(&rendered, new_parent)?;
                let replacing = replacing.map(|replaced| Replaced {
                    node: replaced,
                    // The conditional-delete anchor: a concurrent edit that
                    // advances the replaced node past this keeps it, and the
                    // move auto-suffixes off the name it could not free.
                    sequence: rendered.record_sequence(replaced).unwrap_or(1),
                });
                let op = Op::move_node(
                    node,
                    from_parent,
                    new_parent,
                    new_name,
                    replacing,
                    base_sequence,
                    authored_at,
                    ScopeCrossing::Intra,
                );
                self.stage_and_notify(&op).await
            }
            Command::CancelUpload { op_id } => self
                .cancel_upload(op_id)
                .await
                .map(|()| CommandOutcome::Done),
            Command::SetFocus { node } => {
                self.focus.borrow_mut().open_folder = node;
                // Navigation is the tick model's second trigger source (#33 D2):
                // refresh the newly-focused chain now rather than waiting out a
                // poll cadence, and only past the staleness threshold — a repeat
                // visit renders the state already held.
                if self.refresh_focus_on_access(authored_at).await {
                    let _ = self.events.unbounded_send(Event::SnapshotUpdated);
                }
                Ok(CommandOutcome::Done)
            }
            Command::ImportContact { contact_code } => {
                if contact_code.len() > MAX_CONTACT_CODE_BYTES {
                    return Err(EngineError::MalformedInput {
                        check: "contact-code-too-large",
                    });
                }
                let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
                StagingContactStore::new(
                    &self.seams.staging_store,
                    session.enc_subkey(),
                    &self.entropy,
                )
                .record(&contact_code)
                .await
                .map(CommandOutcome::ContactImported)
                .map_err(EngineError::from_contact_store)
            }
            Command::CreateInviteLink {
                node,
                permission,
                expires_at,
            } => self.create_invite_link(node, permission, expires_at).await,
            Command::RevokeInviteLink { node } => self
                .revoke_invite_link(node)
                .await
                .map(|()| CommandOutcome::Done),
            Command::PruneInviteLinks { node } => self
                .prune_invite_links(node)
                .await
                .map(|()| CommandOutcome::Done),
            Command::ClaimInviteLink { fragment } => self
                .claim_invite_link(&fragment)
                .await
                .map(|()| CommandOutcome::Done),
            Command::ConvertInviteClaims { node } => self
                .convert_invite_claims(node)
                .await
                .map(|()| CommandOutcome::Done),
            Command::Grant {
                node,
                recipient_identity_public_key,
                permission,
            } => {
                self.grant(node, &recipient_identity_public_key, permission)
                    .await
            }
            Command::Revoke {
                node,
                recipient_identity_public_key,
            } => self
                .revoke_grant(node, &recipient_identity_public_key)
                .await
                .map(|()| CommandOutcome::Done),
            // A downgrade cuts the write plane only, and the wave re-mints the
            // grant set from a record still carrying the pre-cut commitment. The
            // pre-wave re-seal that would publish the demoted set is not
            // implemented.
            Command::Downgrade { .. } => Err(EngineError::UnsupportedTarget {
                check: "downgrade-needs-a-pre-wave-reseal",
            }),
            Command::AcceptShare {
                sealed_share_pointer,
            } => self
                .accept_share(&sealed_share_pointer)
                .await
                .map(CommandOutcome::ShareAccepted),
            Command::RotateNow { node } => {
                self.rotate_now(node).await.map(|()| CommandOutcome::Done)
            }
            Command::ManualRefresh => self.manual_refresh().await.map(|()| CommandOutcome::Done),
            Command::SaveVaultSettings { settings } => {
                self.save_vault_settings(&settings).await?;
                Ok(CommandOutcome::Done)
            }
            Command::SiweLogin { message, signature } => {
                let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
                api.siwe_login(&message, &hex_lower(&signature))
                    .await
                    .map_err(EngineError::from_api)?;
                Ok(CommandOutcome::Done)
            }
            other => Err(EngineError::Unimplemented {
                command: other.name(),
            }),
        }
    }

    /// The vault root's scope reference: its scope id and the `ipnsName` the
    /// session's write scope seed derives it at.
    fn vault_root_scope(&self) -> Result<ChildScopeRef, EngineError> {
        let scope_id = self.snapshot.borrow().root.0;
        let write_scope_seed = cached_seed(&self.scope_write_seeds, &scope_id).ok_or(
            EngineError::ContentUnavailable {
                message: "no write scope seed is held for the vault root".to_owned(),
            },
        )?;
        Ok(ChildScopeRef::new(
            scope_id,
            derive_write_name(&write_scope_seed, &scope_id)
                .as_str()
                .as_bytes()
                .to_vec(),
        ))
    }

    /// The scope root `node` names, and the ancestor node seed a gated read of an
    /// interior one needs.
    ///
    /// The authority for what is a scope root is the vault root's owner-signed
    /// direct-child-scope index, so an interior root's `ipnsName` is taken from
    /// that index rather than re-derived: a scope a write rotation has moved is
    /// then read at the name its parent vouches for. A node the base snapshot
    /// does not hold is refused before any resolve.
    ///
    /// `unindexed` decides what an index miss means — see [`UnindexedScope`].
    /// Either way the read is gated and its ascent link is proved under the
    /// parent node seed, so a record planted at a derived name is refused.
    async fn owner_scope(
        &self,
        node: NodeId,
        api: &Rc<ApiClient<T::Http, T::CredentialStore>>,
        keys: OwnerRotationKeys<'_>,
        check: &'static str,
        unindexed: UnindexedScope,
    ) -> Result<OwnerScope, EngineError> {
        let root = self.snapshot.borrow().root;
        if node == root {
            return Ok(OwnerScope {
                scope: self.vault_root_scope()?,
                parent_node_seed: None,
                vouched: true,
            });
        }
        if !self.snapshot.borrow().contains(node) {
            return Err(EngineError::UnsupportedTarget { check });
        }
        let parent = self.vault_root_scope()?;
        let current = self
            .owner_rotation_net(
                api,
                keys,
                RotationAncestry::default(),
                PointerConsultArm::Refused,
            )
            .resolve_vault_root(&parent)
            .await
            .map_err(EngineError::from_resolve_failure)?;
        let indexed = current
            .direct_child_scope_index
            .iter()
            .find(|child| child.scope_id == node.0)
            .cloned();
        let vouched = indexed.is_some();
        let scope = match (indexed, unindexed) {
            (Some(child), _) => child,
            (None, UnindexedScope::Refuse) => {
                return Err(EngineError::UnsupportedTarget { check });
            }
            (None, UnindexedScope::Derive) => ChildScopeRef::new(
                node.0,
                derive_write_name(&current.write_scope_seed, &node.0)
                    .as_str()
                    .as_bytes()
                    .to_vec(),
            ),
        };
        Ok(OwnerScope {
            parent_node_seed: Some(Zeroizing::new(
                *kdf::node_seed(&current.override_seed, &node.0).as_bytes(),
            )),
            scope,
            vouched,
        })
    }

    /// The owner rotation arm over this session's seams.
    #[allow(clippy::type_complexity)]
    fn owner_rotation_net<'a>(
        &'a self,
        api: &'a Rc<ApiClient<T::Http, T::CredentialStore>>,
        keys: OwnerRotationKeys<'a>,
        ancestry: RotationAncestry,
        pointer_consult: PointerConsultArm,
    ) -> OwnerNet<'a, T> {
        OwnerRotationNet {
            transport: &self.seams.record_transport,
            api: api.as_ref(),
            gateway: &self.gateway,
            http: &self.seams.http,
            floors: &self.seams.floor_store,
            scheduler: &self.seams.scheduler,
            profile: &self.profile,
            entropy: &self.entropy,
            keys,
            ancestry,
            pointer_consult,
            payload_version: POINTER_PAYLOAD_VERSION,
            gated: GatedRoots::default(),
            swept: SweptScopeState::default(),
        }
    }

    /// The sweep-task factory [`start`](Self::start) built, absent once the
    /// engine has torn its session material down.
    fn sweep_factory(&self) -> Result<SweepTaskFactory, EngineError> {
        self.sweep_tasks
            .borrow()
            .clone()
            .ok_or(EngineError::NotStarted)
    }

    /// This session's contact book over the staging store — the one place the
    /// three-seam construction lives.
    fn contact_store<'a>(
        &'a self,
        session: &'a SessionIdentity,
    ) -> StagingContactStore<'a, T::StagingStore, Box<dyn Entropy>> {
        StagingContactStore::new(
            &self.seams.staging_store,
            session.enc_subkey(),
            &self.entropy,
        )
    }

    /// The imported contact a grant or revoke names, or a fail-closed refusal.
    ///
    /// The recipient's encryption subkey is only usable because a verified
    /// binding signature tied it to this identity key at import — a key taken
    /// from the command instead would let a host wrap a grant to anyone.
    async fn recipient_contact(
        &self,
        session: &SessionIdentity,
        identity_public_key: &[u8],
    ) -> Result<Contact, EngineError> {
        let identity_pk: [u8; IDENTITY_PUBLIC_LEN] =
            identity_public_key
                .try_into()
                .map_err(|_| EngineError::MalformedInput {
                    check: "recipient-identity-key-length",
                })?;
        resolve_recipient(&self.contact_store(session), &identity_pk)
            .await
            .map_err(EngineError::from_contact_store)
    }

    /// Re-drive `attempt` under the rotation caller contract's bound
    /// ([`bounded`]), spaced on this session's poll cadence.
    async fn bounded_rotation<V, E, A>(&self, attempt: A) -> Result<V, E>
    where
        A: AsyncFnMut() -> Result<V, E>,
        E: Retryable,
    {
        bounded(
            &self.seams.scheduler,
            self.profile.poll_cadence,
            MAX_ROTATION_ATTEMPTS,
            attempt,
        )
        .await
    }

    /// Manual hygiene rotate-now over the vault root's scope
    /// (blueprint/engine.md "Triggers": manual rotations re-seal the
    /// **unchanged** committed set, so this is the flat root cut, not the
    /// revocation cascade).
    async fn rotate_now(&self, node: NodeId) -> Result<(), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let sweep = self.sweep_factory()?;
        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let owner_keys = || OwnerRotationKeys {
            enc_secret: session.enc_subkey(),
            identity: &owner_identity,
            scope_keys: &scope_keys,
        };
        let target = self
            .owner_scope(
                node,
                api,
                owner_keys(),
                "rotate-target-is-not-a-scope-root",
                UnindexedScope::Refuse,
            )
            .await?;

        self.bounded_rotation(async || {
            let net = self.owner_rotation_net(
                api,
                owner_keys(),
                target.ancestry(),
                PointerConsultArm::Refused,
            );
            let current = net
                .resolve_anchored(&target.scope)
                .await
                .map_err(RotateError::Resolve)?;
            rotate_scope(
                &mut SharedEntropy(&self.entropy),
                &self.seams.floor_store,
                &self.seams.scheduler,
                &net,
                &RotateScopePlan {
                    identity: ScopeRootIdentity {
                        v: current.v,
                        scope_id: target.scope.scope_id,
                        ipns_name: &target.scope.ipns_name,
                        owner_enc_pub: &current.owner_enc_pub,
                        owner_enc_secret: Some(session.enc_subkey()),
                        ascent: target
                            .parent_node_seed
                            .as_deref()
                            .map(AscentAuthority::ParentSeed),
                        owes_ascent_link: current.carried_ascent_link,
                        pseudonym_signer: &current.pseudonym_signer,
                    },
                    committed: CommittedSet {
                        owner_identity: &owner_identity,
                        commitment: &current.commitment,
                        commitment_sig: &current.commitment_sig,
                        grant_ledger: &current.grant_ledger,
                        direct_child_scope_index: &current.direct_child_scope_index,
                    },
                    current_override_seed: &current.override_seed,
                    current_read_epoch: current.current_read_epoch,
                    write_scope_seed: &current.write_scope_seed,
                    write_epoch: current.write_epoch,
                    write_history_link: &current.write_history_link,
                    pointer_read_key: &current.pointer_read_key,
                    carried_history_links: &current.carried_history_links,
                },
                || sweep(target.scope.clone(), target.parent_node_seed.clone()),
            )
            .await
        })
        .await
        .map(|_| ())
        .map_err(EngineError::from_rotate)
    }

    /// Revoke a recipient's grant on the vault root's scope.
    ///
    /// The owner's half of the same pairwise ECDH the recipient self-locates
    /// under names the tag, so it is derived here and never taken from a caller.
    async fn revoke_grant(
        &self,
        node: NodeId,
        recipient_identity_public_key: &[u8],
    ) -> Result<(), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let contact = self
            .recipient_contact(session, recipient_identity_public_key)
            .await?;
        self.cut_and_rotate(
            node,
            "revoke-target-is-not-a-scope-root",
            UnindexedScope::Refuse,
            async |target: &OwnerScope, _current: &CascadeTarget| {
                recipient_blinded_tag(
                    session.enc_subkey(),
                    &contact.enc_subkey(),
                    &target.scope.ipns_name,
                )
                .ok_or(EngineError::MalformedInput {
                    check: "unusable-recipient-key",
                })
            },
        )
        .await
        .map(|_| ())
    }

    /// Cut the tag `select` names out of the owner-signed committed set at
    /// `node`'s scope root, then drive the cut through the planes it demands
    /// (blueprint/engine.md "Triggers"). Returns the tag it cut.
    ///
    /// The cut alone revokes nothing — only the fresh-seed cascade completes a
    /// read revoke, and only the name wave ends a write grant — so a failure to
    /// rotate is reported rather than swallowed. `select` runs over the resolved
    /// set: what makes a revoke owner-only is where that tag comes from, and it
    /// is never the command.
    async fn cut_and_rotate<S>(
        &self,
        node: NodeId,
        check: &'static str,
        unindexed: UnindexedScope,
        select: S,
    ) -> Result<[u8; 32], EngineError>
    where
        S: AsyncFnOnce(&OwnerScope, &CascadeTarget) -> Result<[u8; 32], EngineError>,
    {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let sweep = self.sweep_factory()?;
        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let owner_keys = || OwnerRotationKeys {
            enc_secret: session.enc_subkey(),
            identity: &owner_identity,
            scope_keys: &scope_keys,
        };
        let owner_pointer_seed = session.owner_pointer_seed();
        let target = self
            .owner_scope(node, api, owner_keys(), check, unindexed)
            .await?;
        let scope_root_name = parsed_scope_name(&target.scope.ipns_name)?;
        let current = self
            .owner_rotation_net(
                api,
                owner_keys(),
                target.ancestry(),
                PointerConsultArm::Refused,
            )
            .resolve_anchored(&target.scope)
            .await
            .map_err(|e| target.resolve_error(check, e))?;
        let tag = select(&target, &current).await?;

        let plan = GrantCutPlan {
            commitment: &current.commitment,
            commitment_sig: &current.commitment_sig,
            grant_ledger: &current.grant_ledger,
            scope_root_name: &scope_root_name,
            owner_signer: session.identity(),
        };
        // A write grant is cut by `revoke_write_grant`, never by a read revoke —
        // the read cut refuses it by name, which is what selects the arm.
        let cut = match revoke_read_grant(&plan, &tag) {
            Err(RevokeError::WriteGranted) => {
                revoke_write_grant(&plan, &tag, WriteRevokeKind::Full)
            }
            read_cut => read_cut,
        }
        .map_err(EngineError::from_revoke)?;

        let rotator = OwnerCutNet {
            transport: &self.seams.record_transport,
            api: api.as_ref(),
            gateway: &self.gateway,
            http: &self.seams.http,
            floors: &self.seams.floor_store,
            scheduler: &self.seams.scheduler,
            profile: &self.profile,
            entropy: &self.entropy,
            keys: owner_keys(),
            owner_signer: session.identity(),
            owner_pointer_seed: owner_pointer_seed.as_bytes(),
            payload_version: POINTER_PAYLOAD_VERSION,
            scope_root_name: &scope_root_name,
            scope_id: target.scope.scope_id,
            parent_node_seed: target.parent_node_seed.as_deref(),
            session_root_scope_id: self.snapshot.borrow().root.0,
            sweep: &|| sweep(target.scope.clone(), target.parent_node_seed.clone()),
        };
        rotate_on_cut(&rotator, node, &cut)
            .await
            .map_err(EngineError::from_rotation)?;
        Ok(tag)
    }

    /// Grant a node inside the vault root's scope to an imported contact
    /// (blueprint/engine.md "Grant creation").
    async fn grant(
        &self,
        node: NodeId,
        recipient_identity_public_key: &[u8],
        permission: Permission,
    ) -> Result<CommandOutcome, EngineError> {
        // A write grant owes a write-scope cut — a fresh write scope seed and a
        // name wave over the granted subtree — which the read-grant mint does
        // not author.
        if permission == Permission::Write {
            return Err(EngineError::UnsupportedTarget {
                check: "write-grants-need-a-write-scope-cut",
            });
        }
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let contact = self
            .recipient_contact(session, recipient_identity_public_key)
            .await?;
        self.share_scope(node, ScopeShare::Contact(&contact)).await
    }

    /// Mint an invite link over a node inside the vault root's scope: the same
    /// fresh scope a grant mints, committed to a throwaway keypair whose secret
    /// is the link's whole capability ([`mint_invite_link`]).
    async fn create_invite_link(
        &self,
        node: NodeId,
        permission: Permission,
        expires_at: Option<UnixMillis>,
    ) -> Result<CommandOutcome, EngineError> {
        // The minted scope inherits the parent's write plane, so a write link
        // would hand the bearer the seed every name in that scope derives from.
        if permission == Permission::Write {
            return Err(EngineError::UnsupportedTarget {
                check: "write-links-need-a-write-scope-cut",
            });
        }
        self.share_scope(node, ScopeShare::InviteLink { expires_at })
            .await
    }

    /// Mint the fresh scope a share of `node` is granted at: converge the
    /// subtree, mint the scope at epoch 1, reparent whatever descendant scope
    /// roots the node carries, republish the parent's direct-child-scope index,
    /// and deliver what `share` owes its recipient
    /// (blueprint/engine.md "Grant creation").
    ///
    /// Owner-only by construction: the parent's re-seal is signed under the
    /// owner's writer pseudonym and its commitment under the owner identity, so
    /// no other session can author it.
    async fn share_scope(
        &self,
        node: NodeId,
        share: ScopeShare<'_>,
    ) -> Result<CommandOutcome, EngineError> {
        let checks = share.checks();
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        // The vault root's own scope is the session's; minting one at it would
        // replace the scope every record this vault publishes lives in.
        if node.0 == self.snapshot.borrow().root.0 {
            return Err(EngineError::UnsupportedTarget {
                check: checks.vault_root,
            });
        }
        let parent = self.vault_root_scope()?;
        let rendered = self.render().await?;
        // A link owes the bound too: the pointer its conversion posts carries
        // this label, so a link minted past it would be one nobody can claim.
        let display_name = share_display_name(&rendered, node)?;

        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let net = self.owner_rotation_net(
            api,
            OwnerRotationKeys {
                enc_secret: session.enc_subkey(),
                identity: &owner_identity,
                scope_keys: &scope_keys,
            },
            RotationAncestry::default(),
            // The converge pass consults the scope pointer.
            PointerConsultArm::Permitted,
        );
        let current = net
            .resolve_vault_root(&parent)
            .await
            .map_err(EngineError::from_resolve_failure)?;

        // The minted scope root and any share pointer naming it are authored at
        // the parent record's envelope version and opened under the one this
        // build authors, so a divergence would mint a grant nothing can open.
        if current.v != ENVELOPE_V {
            return Err(EngineError::UnsupportedTarget {
                check: checks.envelope_version,
            });
        }

        // A second share of the same folder would mint another scope at epoch 1,
        // replacing the seed every existing grantee of it holds — a silent
        // revocation dressed as a share. Adding a recipient to a scope that
        // already exists is a row on its committed set, not a fresh mint.
        if current
            .direct_child_scope_index
            .iter()
            .any(|child| child.scope_id == node.0)
        {
            return Err(EngineError::UnsupportedTarget {
                check: checks.already_a_scope,
            });
        }

        let subtree = subtree_child_scopes(&rendered, node, &current.direct_child_scope_index)?;

        let parent_node_seed = kdf::node_seed(&current.override_seed, &node.0);
        let pointer_read_key = session.pointer_read_key(&node.0);
        let pseudonym_signer = session.owner_writer_pseudonym_signer(&node.0);
        let grantee = GranteeScopePlan {
            v: current.v,
            scope_id: node.0,
            parent_node_seed: parent_node_seed.as_bytes(),
            owner_enc_pub: &current.owner_enc_pub,
            // A read grant cuts no write scope: the granted node keeps the
            // write-plane material it already publishes under.
            write_scope_seed: &current.write_scope_seed,
            write_epoch: current.write_epoch,
            pointer_read_key: pointer_read_key.as_bytes(),
            subtree_child_index: &subtree,
        };
        let owner = OwnerGrantKeys {
            enc_secret: session.enc_subkey(),
            identity_signer: session.identity(),
            pseudonym_signer: &pseudonym_signer,
        };
        let parent_plan = ParentScopePlan {
            identity: ScopeRootIdentity {
                v: current.v,
                scope_id: parent.scope_id,
                ipns_name: &parent.ipns_name,
                owner_enc_pub: &current.owner_enc_pub,
                owner_enc_secret: Some(session.enc_subkey()),
                ascent: None,
                owes_ascent_link: current.carried_ascent_link,
                pseudonym_signer: &current.pseudonym_signer,
            },
            seeds: ResealSeeds {
                override_seed: &current.override_seed,
                read_epoch: current.current_read_epoch,
                // Updating the index is a metadata-only re-seal at the same
                // epoch, so it cuts no read plane and mints no history link.
                prev: None,
                write_scope_seed: &current.write_scope_seed,
                write_epoch: current.write_epoch,
                write_history: WriteHistory::Carried(&current.write_history_link),
                pointer_read_key: &current.pointer_read_key,
            },
            commitment: &current.commitment,
            commitment_sig: &current.commitment_sig,
            grant_ledger: &current.grant_ledger,
            current_child_index: &current.direct_child_scope_index,
            carried_history_links: &current.carried_history_links,
        };

        match share {
            ScopeShare::Contact(contact) => create_read_grant(
                &mut SharedEntropy(&self.entropy),
                &net,
                &net,
                api.as_ref(),
                &grantee,
                &GrantRecipient {
                    identity_pk: contact.identity_pk(),
                    enc_pub: &contact.enc_subkey(),
                    display_name,
                },
                &owner,
                &parent_plan,
            )
            .await
            .map(|_| CommandOutcome::Done)
            .map_err(EngineError::from_create_grant),
            ScopeShare::InviteLink { expires_at } => mint_invite_link(
                &mut SharedEntropy(&self.entropy),
                &net,
                &net,
                &StagingInviteStore::new(
                    &self.seams.staging_store,
                    session.enc_subkey(),
                    &self.entropy,
                ),
                &owner,
                &InviteMintPlan {
                    grantee: &grantee,
                    parent: &parent_plan,
                    expires_at,
                },
            )
            .await
            .map(CommandOutcome::InviteLinkMinted)
            .map_err(EngineError::from_invite_mint),
        }
    }

    /// Revoke the invite link the owner minted at `node`: cut its row from the
    /// owner-signed committed set, drive the cut through the planes it demands,
    /// and only then forget the record.
    ///
    /// The record outlives a failed rotation, so the next attempt can still name
    /// the link; it is spent only once the cut has landed.
    async fn revoke_invite_link(&self, node: NodeId) -> Result<(), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let store = self.invite_store(session);
        let mut records = store.load().await.map_err(EngineError::from_invite_store)?;
        if records.links.is_empty() {
            return Err(EngineError::from_invite(InviteError::LinkNotCommitted));
        }
        let links = records.links.clone();

        // Owner-only, and derived from the owner's own records: the tag comes
        // from a record this session's encryption subkey re-derives, never from
        // the command.
        let tag = self
            .cut_and_rotate(
                node,
                "revoke-link-target-is-not-a-scope-root",
                UnindexedScope::Derive,
                async |target: &OwnerScope, current: &CascadeTarget| {
                    let commitment_sig = parsed_commitment_sig(&current.commitment_sig)?;
                    locate_invite_link(
                        &OwnerAuthority {
                            identity_signer: session.identity(),
                            enc_secret: session.enc_subkey(),
                        },
                        &CommittedScope {
                            scope_id: &target.scope.scope_id,
                            commitment: &current.commitment,
                            commitment_sig: &commitment_sig,
                            ledger: &current.grant_ledger,
                        },
                        &links,
                    )
                    .map(|link| link.tag)
                    .map_err(EngineError::from_invite)
                },
            )
            .await?;

        records.forget_links(&BTreeSet::from([tag]));
        store
            .persist(&records)
            .await
            .map_err(EngineError::from_invite_store)
    }

    /// Drop the invite records at `node` the scope's own owner-signed commitment
    /// no longer carries — a link a revoke has cut, and one a later mint at the
    /// same node superseded.
    ///
    /// Fail-closed: a record is dropped only against a gate-passing commitment
    /// that does not carry its tag. An unresolvable scope root is staleness, not
    /// a revocation signal (blueprint/engine.md "Revocation is discovered"), so
    /// it prunes nothing rather than forgetting a row that may be live.
    async fn prune_invite_links(&self, node: NodeId) -> Result<(), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let store = self.invite_store(session);
        let mut records = store.load().await.map_err(EngineError::from_invite_store)?;
        // The records are local and decide the whole outcome, so an owner with
        // none spends no resolve on a pass that can drop nothing.
        if records.links.is_empty() {
            return Ok(());
        }
        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let owner_keys = || OwnerRotationKeys {
            enc_secret: session.enc_subkey(),
            identity: &owner_identity,
            scope_keys: &scope_keys,
        };
        let check = "prune-target-is-not-a-scope-root";
        let target = self
            .owner_scope(node, api, owner_keys(), check, UnindexedScope::Derive)
            .await?;
        let current = self
            .owner_rotation_net(
                api,
                owner_keys(),
                target.ancestry(),
                PointerConsultArm::Refused,
            )
            .resolve_anchored(&target.scope)
            .await
            .map_err(|e| target.resolve_error(check, e))?;

        let dead = partition_scope_links(
            session.enc_subkey(),
            &records.links,
            &current.commitment,
            &target.scope.scope_id,
        )
        .spent;
        if dead.is_empty() {
            return Ok(());
        }
        records.forget_links(&dead);
        store
            .persist(&records)
            .await
            .map_err(EngineError::from_invite_store)
    }

    /// Claim an invite link from the fragment its URL carries: reconstruct the
    /// ephemeral identity the link committed, post a sealed claim to the owner
    /// the fragment names, and record that owner as a contact
    /// (blueprint/engine.md "Grants and ledger: Invites").
    ///
    /// The engine does the parsing so the host never has to ([`InviteFragment`]).
    ///
    /// Residual: a fragment is unsigned and its fields are independent, so its
    /// `ownerContactCode` names whoever minted the *link*, not provably whoever
    /// owns the scope root beside it. Recording that bundle is what lets the
    /// accept flow anchor the grant this claim produces — the contact book is
    /// its only authority — so it waits on a post the transport accepted, and a
    /// fragment that reaches no inbox spends no durable slot.
    async fn claim_invite_link(&self, fragment: &str) -> Result<(), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let fragment = InviteFragment::decode(fragment).map_err(EngineError::from_invite)?;
        let invitee = EphemeralInvitee::from_secret(fragment.invite_secret.as_bytes())
            .map_err(EngineError::from_invite)?;
        let owner = import_contact(&fragment.owner_contact_code)
            .map_err(|e| EngineError::MalformedInput { check: e.check() })?;

        let mut entropy = SharedEntropy(&self.entropy);
        let claim = InviteClaim::mint(
            &mut entropy,
            fragment.scope_root_name.clone(),
            ContactCode::create(session.identity(), session.enc_subkey().public()).encode(),
        )
        .map_err(EngineError::from_invite)?;
        let ephemeral = fresh_ephemeral(&mut entropy).map_err(EngineError::from_entropy)?;
        // Fresh random and unlabelled: the API keeps only sha256(senderPublicKey
        // : idempotencyKey) but sees the key itself, so a derivable one hands
        // back the sender edge and a named one hands back the message class.
        let idempotency: [u8; 16] = fresh_bytes(&mut entropy, "claim idempotency key")
            .map_err(EngineError::from_entropy)?;
        post_invite_claim(
            api.as_ref(),
            &owner,
            &invitee,
            &ephemeral,
            ENVELOPE_V,
            &claim,
            &hex_lower(&idempotency),
        )
        .await
        .map_err(EngineError::from_seam)?;

        self.contact_store(session)
            .record(&fragment.owner_contact_code)
            .await
            .map(|_| ())
            .map_err(EngineError::from_contact_store)
    }

    /// Convert the invite claims this session's inbox holds for the link minted
    /// at `node`.
    ///
    /// Owner-only twice over: conversion authorises against the owner's own
    /// signature over the set it is changing, and the links it converts against
    /// come from the owner's durable records, never from an item.
    ///
    /// Per item, in order — convert, publish, post the claimant their pointer,
    /// record the spent claim, ack. A seam failure anywhere in that sequence
    /// leaves the item unacked and unrecorded, so the pass moves on and reports
    /// the failure at the end rather than letting one undeliverable claim block
    /// every later one. The publish is deliberately outside
    /// [`Self::bounded_rotation`]: a lost race is re-driven by the next pass
    /// against a re-resolved set, never retried against a stale one.
    async fn convert_invite_claims(&self, node: NodeId) -> Result<(), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let store = self.invite_store(session);
        let mut records = store.load().await.map_err(EngineError::from_invite_store)?;
        if records.links.is_empty() {
            return Ok(());
        }
        // Ahead of the render and both resolves, so the steady state — an inbox
        // with nothing on it — spends neither.
        let items = poll_verified(api.as_ref(), session.enc_subkey(), ENVELOPE_V)
            .await
            .map_err(EngineError::from_seam)?;
        if items.is_empty() {
            return Ok(());
        }
        let display_name = share_display_name(&self.render().await?, node)?;

        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let owner_keys = || OwnerRotationKeys {
            enc_secret: session.enc_subkey(),
            identity: &owner_identity,
            scope_keys: &scope_keys,
        };
        let check = "convert-target-is-not-a-scope-root";
        let target = self
            .owner_scope(node, api, owner_keys(), check, UnindexedScope::Derive)
            .await?;
        let net = self.owner_rotation_net(
            api,
            owner_keys(),
            target.ancestry(),
            PointerConsultArm::Refused,
        );
        let mut current = net
            .resolve_anchored(&target.scope)
            .await
            .map_err(|e| target.resolve_error(check, e))?;
        let mut commitment_sig = parsed_commitment_sig(&current.commitment_sig)?;

        let authority = OwnerAuthority {
            identity_signer: session.identity(),
            enc_secret: session.enc_subkey(),
        };
        // Both are verdicts on the record this pass resolved rather than on any
        // one item, so they fail the pass closed instead of reading as every
        // item merely skipped (AGENTS.md rule 6).
        authority
            .authorise(&CommittedScope {
                scope_id: &target.scope.scope_id,
                commitment: &current.commitment,
                commitment_sig: &commitment_sig,
                ledger: &current.grant_ledger,
            })
            .map_err(EngineError::from_invite)?;
        enforce_committed_ledger(&current.commitment, &current.grant_ledger)
            .map_err(|v| EngineError::from_invite(InviteError::Authority(v)))?;

        let mut failure: Option<EngineError> = None;
        for item in &items {
            let converted = convert_invite_claim(
                &authority,
                &CommittedScope {
                    scope_id: &target.scope.scope_id,
                    commitment: &current.commitment,
                    commitment_sig: &commitment_sig,
                    ledger: &current.grant_ledger,
                },
                &records.links,
                &records.claims,
                item,
                self.seams.scheduler.now(),
            );
            let ConvertedClaim {
                row,
                commitment,
                ledger,
                claimant,
                outcome,
                record,
            } = match converted {
                Ok(converted) => converted,
                // Terminal on a link this owner records: spent, or a claim that
                // can never become convertible. Acking ends its life rather than
                // holding an inbox slot to its TTL.
                Err(
                    InviteError::ClaimAlreadyConverted
                    | InviteError::ClaimIdIsZero
                    | InviteError::ClaimantIsTheEphemeralHalf
                    | InviteError::ClaimantIsTheOwner
                    | InviteError::ClaimantContact(_)
                    | InviteError::UnusableClaimantKey
                    | InviteError::GrantWasCut,
                ) => {
                    if let Err(e) = api.ack(&item.item_id).await {
                        failure.get_or_insert(EngineError::from_seam(e));
                    }
                    continue;
                }
                // Another consumer's item, or a link a ledger repair may revive.
                Err(
                    InviteError::MalformedClaim(_)
                    | InviteError::ScopeMismatch
                    | InviteError::LinkNotCommitted
                    | InviteError::LinkExpired,
                ) => continue,
                // The set cannot take another grant, or would not publish.
                Err(e) => return Err(EngineError::from_invite(e)),
            };

            if outcome != ClaimOutcome::Unchanged {
                match self
                    .publish_converted_claim(session, &net, &target, &current, &commitment, &ledger)
                    .await
                {
                    Ok(signed) => {
                        current.commitment_sig = signed.to_compact();
                        commitment_sig = signed;
                        current.commitment = commitment;
                        current.grant_ledger = ledger;
                    }
                    Err(e) => {
                        failure.get_or_insert(e);
                        continue;
                    }
                }
            }

            // Ahead of the spent record: a post that fails leaves the claim
            // unrecorded, so the next pass re-runs it rather than acking a
            // claimant who was never told where to look.
            let mut entropy = SharedEntropy(&self.entropy);
            let ephemeral = fresh_ephemeral(&mut entropy).map_err(EngineError::from_entropy)?;
            let idempotency: [u8; 16] = fresh_bytes(&mut entropy, "claim grant idempotency key")
                .map_err(EngineError::from_entropy)?;
            let pointer = SharePointer {
                scope_root_name: current.commitment.ipns_name.clone(),
                sharer_identity_pk: owner_identity.to_sec1(),
                display_name: display_name.clone(),
                permission: row.commitment_entry.permission,
            };
            if let Err(e) = post_sealed(
                api.as_ref(),
                &claimant.enc_subkey(),
                &claimant.identity_pk(),
                &ephemeral,
                ENVELOPE_V,
                session.identity(),
                &pointer.encode(),
                &hex_lower(&idempotency),
            )
            .await
            {
                failure.get_or_insert(EngineError::from_seam(e));
                continue;
            }

            if let Some(record) = record {
                records.claims.push(record);
                if let Err(e) = store.persist(&records).await {
                    // The held set is what the next item converts against, so it
                    // must not carry a record the durable one does not.
                    records.claims.pop();
                    failure.get_or_insert(EngineError::from_invite_store(e));
                    continue;
                }
            }

            if let Err(e) = api.ack(&item.item_id).await {
                failure.get_or_insert(EngineError::from_seam(e));
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Publish the set one converted claim produced at the scope root it belongs
    /// to: owner-re-sign, re-seal at the **same** read epoch (a claim cuts no
    /// key, so it mints no history link), publish, and hand back the signature
    /// the published set now carries.
    async fn publish_converted_claim(
        &self,
        session: &SessionIdentity,
        net: &OwnerNet<'_, T>,
        target: &OwnerScope,
        current: &CascadeTarget,
        commitment: &GrantSetCommitment,
        ledger: &[GrantLedgerEntry],
    ) -> Result<EcdsaSignature, EngineError> {
        let signature = sign_grant_set(session.identity(), commitment).map_err(|_| {
            EngineError::MalformedInput {
                check: "converted-commitment-unsignable",
            }
        })?;
        let section = reseal_scope_root(
            &mut SharedEntropy(&self.entropy),
            &ScopeRootIdentity {
                v: current.v,
                scope_id: target.scope.scope_id,
                ipns_name: &target.scope.ipns_name,
                owner_enc_pub: &current.owner_enc_pub,
                owner_enc_secret: Some(session.enc_subkey()),
                ascent: target
                    .parent_node_seed
                    .as_deref()
                    .map(AscentAuthority::ParentSeed),
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
                owner_identity: &session.owner_identity(),
                commitment,
                commitment_sig: &signature.to_compact(),
                grant_ledger: ledger,
                direct_child_scope_index: &current.direct_child_scope_index,
            },
            &current.carried_history_links,
        )
        .map_err(|e| EngineError::MalformedInput { check: e.check() })?;
        net.publish_scope_root(&ResealedScopeRoot {
            scope_id: target.scope.scope_id,
            ipns_name: target.scope.ipns_name.clone(),
            read_epoch: current.current_read_epoch,
            write_epoch: current.write_epoch,
            section,
        })
        .await
        .map_err(|e| {
            let message = e.to_string();
            match e.is_retryable() {
                true => EngineError::Seam { message },
                false => EngineError::TrustViolation { message },
            }
        })?;
        Ok(signature)
    }

    /// This session's durable received-share bookmarks.
    fn received_share_store<'a>(
        &'a self,
        session: &'a SessionIdentity,
    ) -> StagingReceivedShareStore<'a, T::StagingStore, Box<dyn Entropy>> {
        StagingReceivedShareStore::new(
            &self.seams.staging_store,
            session.enc_subkey(),
            &self.entropy,
        )
    }

    /// This session's durable invite records.
    fn invite_store<'a>(
        &'a self,
        session: &'a SessionIdentity,
    ) -> StagingInviteStore<'a, T::StagingStore, Box<dyn Entropy>> {
        StagingInviteStore::new(
            &self.seams.staging_store,
            session.enc_subkey(),
            &self.entropy,
        )
    }

    /// Accept a share the mailbox delivered: bind the pointer to the imported
    /// contact, resolve and gate the scope root it names, self-locate the grant
    /// blob by blinded tag, unseal the seeds, and append the entry to this
    /// vault's sealed received-shares list before acking
    /// (blueprint/engine.md "Accept flow").
    ///
    /// Fail-closed throughout: an unverifiable sender, an uncommitted tag, or a
    /// gate rejection is a trust verdict, never staleness.
    async fn accept_share(
        &self,
        sealed_share_pointer: &[u8],
    ) -> Result<AcceptOutcome, EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        // The version the sender sealed under is the envelope version its scope
        // root was minted at, which is the one this build authors; a payload from
        // any other is an item that does not open, and is dropped.
        let item = locate_verified(
            api.as_ref(),
            session.enc_subkey(),
            ENVELOPE_V,
            sealed_share_pointer,
        )
        .await
        .map_err(EngineError::from_seam)?
        .ok_or(EngineError::MalformedInput {
            check: "share-pointer-is-not-on-this-inbox",
        })?;

        let contact = self
            .recipient_contact(session, &item.sender_identity.to_sec1())
            .await?;
        let pointer = SharePointer::decode(&item.payload)
            .map_err(|e| EngineError::MalformedInput { check: e.check() })?;
        // Bind the pointer to the contact before it names anything to fetch, so
        // one imported peer cannot steer a resolve at a scope root of their
        // choosing. The accept flow re-checks it against the same contact.
        if pointer.sharer_identity_pk != contact.identity_pk().to_sec1() {
            return Err(EngineError::TrustViolation {
                message: AcceptError::SharerMismatch.to_string(),
            });
        }
        let name = parsed_scope_name(&pointer.scope_root_name)?;
        let (_, record_bytes) = fanout_get_verify(&self.seams.record_transport, &name)
            .await
            .ok_or(EngineError::ContentUnavailable {
                message: "the shared scope root did not resolve".to_owned(),
            })?;
        let candidate =
            assemble_candidate(&self.gateway, &self.seams.http, &name, &record_bytes, None)
                .await
                .map_err(EngineError::from_gate)?;

        let store = self.received_share_store(session);
        let mut received = store
            .load()
            .await
            .map_err(EngineError::from_received_share_store)?;
        let blobs = published_grant_blobs(&candidate.grant_section);
        accept_share(
            &self.seams.floor_store,
            api.as_ref(),
            &store,
            &item,
            &contact,
            session.enc_subkey(),
            &candidate,
            &blobs,
            &mut received,
        )
        .await
        .map_err(EngineError::from_accept)
    }

    /// Seal and publish the vault settings record, then adopt what it
    /// published: the renewal enrolment [`publish_settings`] states the need
    /// for, and the placement this session writes under.
    async fn save_vault_settings(&self, settings: &VaultSettings) -> Result<(), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let held = publish_settings(
            &self.seams.record_transport,
            api,
            &self.seams.floor_store,
            &self.seams.snapshot_cache,
            &self.seams.scheduler,
            &self.profile,
            &mut SharedEntropy(&self.entropy),
            &self.orphan_heads,
            session.login_secret(),
            settings,
        )
        .await
        .map_err(EngineError::from_settings_publish)?;
        *self.settings_record.borrow_mut() = Some(held);
        // The confirm re-resolve read back our own bytes, so this device has
        // adopted what it published: the session's byte destinations follow, or
        // an `External` save keeps feeding the hosted leg until the next start.
        *self.placement.borrow_mut() = Some(SessionPlacement::member(placement_of(settings)));
        self.byo_reconciled.set(false);
        Ok(())
    }

    /// The scope's cached read seed, evicted first if the durable read-epoch
    /// floor has risen past the one it was recovered under. Every on-demand
    /// read goes through here; the resolve tick evicts once per pass.
    async fn scope_read_seed(&self, scope_id: &[u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
        refresh_seed_floor(
            &self.seams.floor_store,
            &self.scope_read_seeds,
            scope_id,
            SeedFloor::Read,
        )
        .await;
        cached_seed(&self.scope_read_seeds, scope_id)
    }

    /// Mint this account's first vault inside a live session, for a `start`
    /// whose own mint did not land.
    ///
    /// Fail-closed: an availability stall is [`EngineError::RefreshFailed`] and
    /// stays retryable; a refusal — to mint, or to adopt what another device
    /// published — is a verdict a retry reaches identically.
    async fn provision_in_session(&self) -> Result<(), EngineError> {
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?.clone();
        let root = self.snapshot.borrow().root;
        let root_name = match self.provision_first_run_vault(&api, root.0).await {
            Ok(ProvisionOutcome::Minted(vault)) => self.install_mint(*vault),
            // The account published from another device between this session's
            // failed mint and this retry — caught by the vacancy probe before
            // minting, or by the pointer walk after. Its root is the one to
            // adopt, never a second mint over it, and never a dark session: this
            // device authenticated nothing wrong, it simply lost the race.
            Ok(ProvisionOutcome::MovedOn)
            | Err(ProvisionError::NotAFirstRun(VaultPointerProbe::AlreadyPublished)) => {
                let outcome = self
                    .run_cold_start(root)
                    .await
                    .map_err(EngineError::from_cold_start)?;
                self.install_cold_start(outcome, root.0).ok_or_else(|| {
                    EngineError::RefreshFailed {
                        message: "the vault pointer served no root to adopt".to_owned(),
                    }
                })?
            }
            Err(err) if err.is_retryable() => {
                return Err(EngineError::RefreshFailed {
                    message: err.to_string(),
                });
            }
            Err(err) => {
                return Err(EngineError::TrustViolation {
                    message: err.to_string(),
                });
            }
        };
        self.open_tick_loop(root_name);
        self.sync_status.borrow_mut().last_success = Some(self.seams.scheduler.now());
        let _ = self.events.unbounded_send(Event::SnapshotUpdated);
        Ok(())
    }

    /// Force a resolve-and-drain pass now and report what its read legs
    /// reconciled — the nocache forcing path (#33 D4): the pass it brings
    /// forward skips the snapshot cache, so only what the record plane serves
    /// counts, and an unreachable plane is a failure rather than a silent
    /// repaint off last-known-good.
    ///
    /// Requests coalesce onto one pass, which the tick loop runs
    /// ([`ManualRefresh`]). The drain rides that pass but reports through its
    /// own op events; this returns on the read legs.
    async fn manual_refresh(&self) -> Result<(), EngineError> {
        match self.file_forced_pass()? {
            Some(pass) => pass.landed().await,
            None => match self.api_base_url.configured() {
                Some(_) => self.provision_in_session().await,
                None => Err(EngineError::RefreshFailed {
                    message: "this account has no vault yet".to_owned(),
                }),
            },
        }
    }

    /// File a forced pass and hand back where its verdict lands, so a host
    /// that also serves a kernel awaits the network legs off the loop it filed
    /// them from (blueprint/desktop.md "the never-block law"). Requests
    /// coalesce onto one pass ([`ForcedPass`]).
    ///
    /// `None` when an unconsumed tick-loop spawner says the start found no root
    /// to poll: what answers a refresh then is the mint, not a pass, and
    /// [`Command::ManualRefresh`] is what runs it.
    pub fn file_forced_pass(&self) -> Result<Option<ForcedPass>, EngineError> {
        // The same gate [`command`](Self::command) files every other request
        // behind: a host reaching this directly is not a weaker caller.
        self.live_session()?;
        if self.tick_loop_spawner.borrow().is_some() {
            return Ok(None);
        }
        self.manual_refresh
            .filed()
            .map(Some)
            .ok_or_else(|| EngineError::RefreshFailed {
                message: "no sync loop is running to force a pass".to_owned(),
            })
    }

    /// Refresh the focus window's folders that are past the on-access staleness
    /// threshold, returning whether the base changed.
    async fn refresh_focus_on_access(&self, now: UnixMillis) -> bool {
        let due = focus_folders_due(
            &self.snapshot.borrow(),
            &self.focus.borrow(),
            &self.focus_refreshed.borrow(),
            now,
            &self.profile,
        );
        if due.is_empty() {
            return false;
        }
        let scope_id = self.snapshot.borrow().root.0;
        let Some(scope_read_seed) = self.scope_read_seed(&scope_id).await else {
            return false;
        };
        let report = FolderRefresh {
            transport: &self.seams.record_transport,
            snapshot_cache: &self.seams.snapshot_cache,
            http: &self.seams.http,
            floors: &self.seams.floor_store,
            gateway: &self.gateway,
            base: &self.snapshot,
            events: &self.events,
            scope_id,
            scope_read_seed: &scope_read_seed,
            mode: ResolveMode::CacheFirst,
        }
        .run(&due)
        .await;
        stamp_focus_refreshed(&self.focus_refreshed, &due, now);
        report.changed
    }

    // -----------------------------------------------------------------------
    // Write handles: the content path across the facade.
    // -----------------------------------------------------------------------

    /// Open a write handle for `size` plaintext bytes, reserving the exact
    /// sealed total it will occupy against this device's staging budget.
    ///
    /// The reservation is held for the handle's whole life, so two handles
    /// opened before either stages a byte contend for the budget rather than
    /// both being admitted against room only one can have. It is released when
    /// the write commits, fails, or is aborted.
    pub async fn begin_write(
        &mut self,
        target: WriteTarget,
        size: u64,
    ) -> Result<WriteHandle, EngineError> {
        self.live_session()?;
        // Checked before anything is spent: a version of a node this device has
        // no file for would journal an `updateContent` the drain can only halt
        // on, after a whole upload's worth of staging, entropy and budget.
        let base_version_cid = match &target {
            WriteTarget::NewFile { .. } => None,
            WriteTarget::Version { node } => {
                match self.render().await?.node(*node).map(|meta| meta.kind) {
                    Some(NodeKind::Folder) => return Err(EngineError::NotAFile),
                    Some(_) => self.write_anchor(*node).await?,
                    None => return Err(EngineError::UnknownNode),
                }
            }
        };
        let requested = sealed_total_bytes(size, &self.content_profile).map_err(|error| {
            EngineError::ContentTooLarge {
                check: error.check(),
            }
        })?;
        // Sized in sealed bytes, which is what the hosted ingress counts.
        self.hosted_quota_pre_flight(requested).await?;
        let staged = self
            .seams
            .staging_store
            .staged_bytes_total()
            .await
            .map_err(EngineError::from_seam)?;
        // Admitted before anything is spent, so a refused write burns no node id
        // and no entropy; a failure past this point hands the reservation back.
        let mut writes = self.writes.borrow_mut();
        let reservation = writes
            .ledger
            .admit(requested, staged, &self.storage_policy)?;
        let opened = (|| {
            let node = match &target {
                WriteTarget::NewFile { .. } => self.mint_node_id()?,
                WriteTarget::Version { node } => *node,
            };
            let key = ContentKey::generate(&mut *self.entropy.borrow_mut())
                .map_err(EngineError::from_entropy)?;
            Ok((node, ContentWriter::new(key, self.content_profile, size)))
        })();
        let (node, writer) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                writes.ledger.release(reservation);
                return Err(error);
            }
        };

        writes.next += 1;
        let handle = WriteHandle(writes.next);
        self.live_blocks.borrow_mut().open(handle);
        writes.open.insert(
            handle,
            LiveWrite {
                node,
                target,
                declared_size: size,
                base_version_cid,
                reservation,
                writer,
            },
        );
        Ok(handle)
    }

    /// Refuse a write whose hosted leg the account quota cannot admit, before
    /// the version is sealed and staged rather than at the drain.
    ///
    /// Two directions, deliberately different: the placement decision is
    /// fail-closed, while the quota probe is not — the API upload endpoint is
    /// the authoritative gate, so an unreachable one leaves the write to queue
    /// offline like any other.
    async fn hosted_quota_pre_flight(&self, requested: u64) -> Result<(), EngineError> {
        // Only the predicate and the provenance leave the borrow: cloning the
        // placement would copy the member's provider bearer on every write.
        let (hosted_leg, source) = match self.placement.borrow().as_ref() {
            None => return Err(EngineError::NotStarted),
            Some(SessionPlacement {
                decision: Err(refusal),
                ..
            }) => return Err(EngineError::NoPlacement { refusal: *refusal }),
            Some(SessionPlacement {
                decision: Ok(placement),
                source,
            }) => (placement.has_hosted_leg(), *source),
        };
        let Some(api) = self.api.as_ref() else {
            return Ok(());
        };
        let Ok(quota) = api.quota().await else {
            return Ok(());
        };
        match source {
            // A set flag contradicts the default this session assumed, so refuse;
            // a clear one is a server signal that must not widen an
            // unauthenticated default, and latches nothing either way.
            PlacementSource::Assumed(reason) => {
                if quota.advisory {
                    return Err(EngineError::NoPlacement {
                        refusal: PlacementRefusal::SettingsUnavailable(reason),
                    });
                }
            }
            // The account's flag is two-state where the mode is three and dual
            // has no server representation, so `byo=true` is exactly `External`.
            // The vaulted mode is the source of truth; the flag is latched only
            // once the PATCH lands, so two devices still cannot flap it per file
            // while a transient failure stays retryable — the hosted ingress
            // rejects a BYO account, so an unreconciled flag fails every hosted
            // upload the session makes.
            PlacementSource::Member => {
                if !self.byo_reconciled.get()
                    && quota.advisory == hosted_leg
                    && api.set_byo(!hosted_leg).await.is_ok()
                {
                    self.byo_reconciled.set(true);
                }
            }
        }
        pre_flight_quota_check(requested, &quota, hosted_leg).map_err(|refused| {
            EngineError::OverBudget {
                cause: OverBudgetCause::AccountQuota,
                requested,
                available: refused.limit_bytes.saturating_sub(refused.used_bytes),
            }
        })
    }

    /// Feed the next slice of the file. Seals and stages every whole chunk it
    /// completes; the budget is not re-checked, since `beginWrite` reserved the
    /// whole version. Pushing past the declared size fails closed and drops the
    /// handle — the declaration is what the reservation was sized from.
    pub async fn push_chunk(
        &mut self,
        handle: WriteHandle,
        bytes: &[u8],
    ) -> Result<(), EngineError> {
        self.live_session()?;
        match self.push_chunk_inner(handle, bytes).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.abort_write(handle).await;
                Err(error)
            }
        }
    }

    async fn push_chunk_inner(&self, handle: WriteHandle, bytes: &[u8]) -> Result<(), EngineError> {
        let mut rest = bytes;
        loop {
            let leaf = {
                let mut writes = self.writes.borrow_mut();
                let write = writes
                    .open
                    .get_mut(&handle)
                    .ok_or(EngineError::UnknownWriteHandle)?;
                if write.writer.observed_size() + rest.len() as u64 > write.declared_size {
                    return Err(EngineError::ContentSizeMismatch {
                        declared: write.declared_size,
                        observed: write.writer.observed_size() + rest.len() as u64,
                    });
                }
                let (remaining, leaf) = write
                    .writer
                    .push(rest, &mut *self.entropy.borrow_mut())
                    .map_err(|e| EngineError::Entropy {
                        message: e.message().to_owned(),
                    })?;
                // The borrow must not span the staging await; carry the offset
                // out rather than the slice.
                let consumed = rest.len() - remaining.len();
                rest = &rest[consumed..];
                leaf
            };
            if let Some(leaf) = leaf {
                self.stage_handle_block(handle, &leaf.cid, &leaf.sealed)
                    .await?;
            }
            if rest.is_empty() {
                return Ok(());
            }
        }
    }

    /// Close the handle: seal the tail, assemble and stage the root, seal the
    /// per-version content key, and journal one op.
    ///
    /// Fails closed when the pushes did not add up to the declared size — the
    /// reachable cause is a backing file truncated mid-read, and committing it
    /// would publish a short version as a success.
    pub async fn commit_write(&mut self, handle: WriteHandle) -> Result<OpId, EngineError> {
        self.live_session()?;
        // Taken out of the ledger up front: from here the handle is spent
        // whatever happens, and its reservation must not outlive it.
        let write = self.take_write(handle)?;
        match self.commit_write_inner(handle, write).await {
            Ok(op_id) => {
                // The journaled op now references the blocks, so GC no longer
                // needs the handle to vouch for them.
                self.live_blocks.borrow_mut().close(handle);
                let _ = self.events.unbounded_send(Event::SnapshotUpdated);
                Ok(op_id)
            }
            Err(error) => {
                self.release_handle_blocks(handle).await;
                Err(error)
            }
        }
    }

    /// Abandon a write handle: release its reservation and the blocks it staged.
    /// Idempotent — an unknown handle is already gone.
    pub async fn abort_write(&mut self, handle: WriteHandle) {
        if self.take_write(handle).is_err() {
            return;
        }
        self.release_handle_blocks(handle).await;
    }

    /// Remove a handle from the ledger, releasing its budget reservation.
    fn take_write(&self, handle: WriteHandle) -> Result<LiveWrite, EngineError> {
        let mut writes = self.writes.borrow_mut();
        let write = writes
            .open
            .remove(&handle)
            .ok_or(EngineError::UnknownWriteHandle)?;
        writes.ledger.release(write.reservation);
        Ok(write)
    }

    /// Stage one of a handle's blocks, recording its key as live **before** the
    /// bytes land so an orphan-GC pass in the same turn cannot collect it.
    async fn stage_handle_block(
        &self,
        handle: WriteHandle,
        cid: &[u8],
        sealed: &[u8],
    ) -> Result<(), EngineError> {
        self.live_blocks.borrow_mut().record(handle, cid);
        self.seams
            .staging_store
            .put_staged_bytes(cid, sealed)
            .await
            .map_err(EngineError::from_seam)
    }

    /// Drop every block a handle staged — no op will ever reference them.
    /// Best-effort: a failed removal is orphan residue a later GC pass collects.
    async fn release_handle_blocks(&self, handle: WriteHandle) {
        let keys = self.live_blocks.borrow_mut().close(handle);
        for key in keys {
            let _ = self.seams.staging_store.remove_staged_bytes(&key).await;
        }
    }

    async fn commit_write_inner(
        &self,
        handle: WriteHandle,
        write: LiveWrite,
    ) -> Result<OpId, EngineError> {
        let LiveWrite {
            node,
            target,
            declared_size,
            base_version_cid,
            writer,
            ..
        } = write;
        let observed = writer.observed_size();
        if observed != declared_size {
            return Err(EngineError::ContentSizeMismatch {
                declared: declared_size,
                observed,
            });
        }
        let finished = writer
            .finish(&mut *self.entropy.borrow_mut())
            .map_err(seal_error)?;

        if let Some(tail) = &finished.tail {
            self.stage_handle_block(handle, &tail.cid, &tail.sealed)
                .await?;
        }
        let root_cid = finished.content.content_cid().to_vec();
        self.stage_handle_block(handle, &root_cid, &finished.root_block)
            .await?;

        // The `{scope, epoch}` the key blob's AAD binds — see `seal_content_key`
        // for why they are values and not key inputs.
        let scope = self.snapshot.borrow().root;
        let epoch = floor::read_epoch_floor(&self.seams.floor_store, &scope.0)
            .await
            .map_err(EngineError::from_seam)?
            .unwrap_or(0);
        // Its own ephemeral, independent of the op record's: two seals to one
        // recipient key must never share one.
        let key_seal = self.record_seal()?;
        let sealed_content_key = seal_content_key(
            key_seal.owner_enc_secret,
            &key_seal.ephemeral_scalar,
            &scope.0,
            epoch,
            &root_cid,
            finished.key.as_bytes(),
        )
        .map_err(|e| EngineError::ContentKeySealFailed { check: e.check() })?;

        let content = StagedContent {
            root_cid,
            plaintext_size: declared_size,
            sealed_content_key,
            epoch,
        };
        let authored_at = self.seams.scheduler.now();
        let op = match target {
            WriteTarget::NewFile { parent, name } => {
                let base_sequence = self.base_sequence_for(parent).await?;
                Op::create(
                    node,
                    parent,
                    name,
                    NewNode::File {
                        content: Some(content),
                    },
                    base_sequence,
                    authored_at,
                )
            }
            WriteTarget::Version { node } => {
                let base_sequence = self.base_sequence_for(node).await?;
                Op::update_content(node, content, base_version_cid, base_sequence, authored_at)
            }
        };
        let seal = self.record_seal()?;
        stage_op(&self.seams.staging_store, seal, &op)
            .await
            .map_err(EngineError::from_seam)
    }

    /// Issues the single-use nonce an EIP-4361 message must embed, so the host
    /// collects a wallet signature without reaching the API itself
    /// (blueprint/web-client.md: `apps/web` holds no seam of its own). Fails
    /// `NotStarted` before [`start`](Self::start), like the
    /// [`Command::SiweLogin`] that spends the nonce — SIWE is a secondary
    /// method (blueprint/engine.md "API client").
    pub async fn siwe_challenge(&self) -> Result<String, EngineError> {
        self.live_session()?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let nonce = api.siwe_challenge().await.map_err(EngineError::from_api)?;
        Ok(nonce.nonce)
    }

    /// Cancel one queued upload ([`Command::CancelUpload`]).
    ///
    /// Staged bytes are **released**, not preserved: the rule that splits the
    /// two is whether the engine gave up on the op or the user did.
    async fn cancel_upload(&self, op_id: OpId) -> Result<(), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let queued = self.scan_queue().await?.mine;
        let Some((_, op)) = queued.iter().find(|(id, _)| *id == op_id) else {
            return Err(EngineError::TooLateToCancel { op_id });
        };
        let Some(root_cid) = op.content_root_cid().map(<[u8]>::to_vec) else {
            return Err(EngineError::NotAnUpload { op_id });
        };
        // The durable half of the publish-entry interlock: a reboot clears the
        // session-scoped one, and a version whose record publish was confirmed
        // must stay uncancellable across it. Read under this session's own
        // identity, the same one the mark was written under.
        if published_op_mark(&self.seams.staging_store, session.enc_subkey())
            .await
            .map_err(EngineError::from_seam)?
            .is_some_and(|mark| op_id.0 <= mark)
        {
            return Err(EngineError::TooLateToCancel { op_id });
        }
        // Claimed before anything is undone, and refused once the drain holds
        // the op for publish — cancel never mutates published state.
        if !self.cancels.borrow_mut().request(op_id) {
            return Err(EngineError::TooLateToCancel { op_id });
        }
        let node = op.target;
        // A cancelled create takes every later queued op on the node it will
        // never bring into being; a cancelled version takes nothing, since
        // versions are independent full writes.
        let cascade: Vec<(OpId, Op)> = match op.kind {
            OpKind::Create { .. } => queued
                .iter()
                .filter(|(id, later)| *id > op_id && later.target == node)
                .cloned()
                .collect(),
            _ => Vec::new(),
        };

        if let Err(error) = self.discard_upload(op_id, node, &root_cid).await {
            self.cancels.borrow_mut().withdraw(op_id);
            return Err(error);
        }
        // The primary op is already gone, so the overlay is stale either way:
        // the host is told even when a cascade step fails part way.
        let mut cascaded = Ok(());
        for (later_id, later) in cascade {
            cascaded = match later.content_root_cid() {
                Some(root_cid) => self.discard_upload(later_id, later.target, root_cid).await,
                None => self.dequeue_op(later_id).await,
            };
            if cascaded.is_err() {
                break;
            }
        }
        let _ = self.events.unbounded_send(Event::SnapshotUpdated);
        cascaded
    }

    /// Undo one queued upload: drop the op, retire what of it reached the
    /// network ([`UploadCancels`]), release its blocks, and tell the host.
    ///
    /// The dequeue goes first and is the only step allowed to fail the cancel:
    /// an op that is still queued is still publishable, and unpinning its blocks
    /// before it has left would publish a version whose leading leaves are gone.
    /// The retire is then best-effort — a refused batch leaves pin rows charged,
    /// which is a leak, where refusing the cancel over it would break the
    /// guarantee the user was given.
    async fn discard_upload(
        &self,
        op_id: OpId,
        node: NodeId,
        root_cid: &[u8],
    ) -> Result<(), EngineError> {
        self.dequeue_op(op_id).await?;
        let uploaded: Vec<String> = self
            .cancels
            .borrow()
            .uploaded_by(op_id)
            .iter()
            .map(|cid| encode_content_cid_str(cid))
            .collect();
        if let Some(api) = &self.api
            && !uploaded.is_empty()
        {
            let _ = retire(api, &uploaded).await;
        }
        release_version_blocks(&self.seams.staging_store, root_cid).await;
        let _ = self.events.unbounded_send(Event::OpProgress {
            op_id: Some(op_id),
            node,
            phase: OpPhase::UploadCancelled,
            progress: None,
            error: None,
        });
        Ok(())
    }

    async fn dequeue_op(&self, op_id: OpId) -> Result<(), EngineError> {
        self.seams
            .staging_store
            .remove_op(op_id)
            .await
            .map_err(EngineError::from_seam)
    }

    /// A rendered read of the current state — the gate-passing base snapshot ⊕
    /// the pending-op overlay — for FUSE-shaped reads (children/lookup/attrs/
    /// statfs). Fails `NotStarted` before [`start`](Self::start).
    pub async fn view(&self) -> Result<EngineView, EngineError> {
        self.live_session()?;
        Ok(EngineView {
            rendered: self.render().await?,
        })
    }

    /// What this session owes the user outside any one folder: the retained
    /// dead letters, the drain's hold, the unreadable queue entries, and the
    /// staleness rung. Off the durable queue and the engine's own state, never
    /// off a render — a mount reads this for its tray without paying for the
    /// snapshot overlay on the kernel path.
    pub async fn status(&self) -> Result<SessionStatus, EngineError> {
        self.live_session()?;
        // Every `RefCell` read happens after the await, so no borrow spans it.
        let retained_records = self.scan_queue().await?.retained;
        Ok(SessionStatus {
            dead_letters: self.retained_dead_letters(),
            blocked: *self.blocked.borrow(),
            settings_hold: *self.settings_hold.borrow(),
            retained_records,
            staleness: self.staleness_now(),
        })
    }

    /// Vault-level pinned bytes a published prune still owes the registry — the
    /// figure a host shows beside the quota, because the quota does not fall by
    /// them until the retire ledger drains. Zero once it has.
    ///
    /// A vault-wide state that *clears*, so it is read rather than evented: a
    /// lost "reclaimed" would strand a host on a debt that is already paid.
    #[must_use]
    pub fn pending_reclaim_bytes(&self) -> u64 {
        self.pending_reclaim.get()
    }

    /// A key-free [`SnapshotView`] of `folder` — its children (with pending/
    /// dead-letter flags), breadcrumb trail, retained dead letters, and the
    /// staleness rung. A pure read over the same rendered view [`view`](Self::view)
    /// serves (state law): one pending-ops read feeds both the overlay and the
    /// pending flags, so the flags and the rendered children never disagree.
    pub async fn snapshot(&self, folder: NodeId) -> Result<SnapshotView, EngineError> {
        self.live_session()?;
        let scan = self.scan_queue().await?;
        let ops: Vec<Op> = scan.mine.into_iter().map(|(_id, op)| op).collect();
        let rendered = {
            let base = self.snapshot.borrow();
            apply_overlay(&base, &ops)
        };
        let meta = rendered.node(folder).ok_or(EngineError::UnknownNode)?;
        if meta.kind != NodeKind::Folder {
            return Err(EngineError::NotAFolder);
        }
        let mut pending: BTreeMap<NodeId, PendingClass> = BTreeMap::new();
        for op in &ops {
            let slot = pending.entry(op.target).or_default();
            *slot = (*slot).max(op.pending_class());
        }
        let dead = self.dead_letters.borrow();
        let dead_nodes: BTreeSet<NodeId> = dead.values().filter_map(|(node, _)| *node).collect();
        let children = rendered
            .children(folder)
            .into_iter()
            .map(|child| SnapshotChild {
                id: child.id,
                name: child.name().to_owned(),
                kind: child.kind,
                size: child.size,
                mtime: child.mtime,
                pending: pending.get(&child.id).copied().unwrap_or_default(),
                dead_letter: dead_nodes.contains(&child.id),
                content_version: child.content_version,
            })
            .collect();
        let ancestors = rendered
            .ancestors(folder)
            .into_iter()
            .map(|id| Breadcrumb {
                id,
                name: rendered
                    .node(id)
                    .map(|meta| meta.name().to_owned())
                    .unwrap_or_default(),
            })
            .collect();
        let folder_name = rendered
            .node(folder)
            .map(|meta| meta.name().to_owned())
            .unwrap_or_default();
        Ok(SnapshotView {
            root: rendered.root,
            folder,
            folder_name,
            children,
            ancestors,
            dead_letters: self.retained_dead_letters(),
            blocked: *self.blocked.borrow(),
            settings_hold: *self.settings_hold.borrow(),
            retained_records: scan.retained,
            staleness: self.staleness_now(),
        })
    }

    /// The shares this vault has accepted, key-free, each carrying the engine's
    /// own resolution verdict (blueprint/web-client.md "/shared").
    ///
    /// The rows come from the durable received-shares list, so they survive a
    /// reload; the verdict comes from the focus tick's last resolve of that
    /// scope root, so a revocation the owner published is *discovered* here
    /// rather than delivered.
    pub async fn received_shares(&self) -> Result<Vec<ReceivedShareRow>, EngineError> {
        self.live_session()?;
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let received = self
            .received_share_store(session)
            .load()
            .await
            .map_err(EngineError::from_received_share_store)?;

        let verdicts = self.received_verdicts.borrow();
        Ok(received
            .iter()
            .map(|share| ReceivedShareRow {
                scope: NodeId(share.scope_id),
                sharer_identity_public_key: share.sharer_identity_pk.to_vec(),
                display_name: share.display_name.clone(),
                permission: share.permission.into(),
                resolution: verdicts.get(&share.scope_id).map(|v| v.class),
            })
            .collect())
    }

    /// The sharing state standing on `scope_root`, key-free: this vault's whole
    /// verified contact book, and the grants the scope root's own owner-signed
    /// ledger commits.
    ///
    /// The contact book is durable, so a contact imported in an earlier session
    /// is offered without a re-import. The grant half is read from the record
    /// plane rather than remembered, so a reload — or a grant another device
    /// issued — renders the same list.
    ///
    /// A node the vault root's committed child-scope index does not name is not
    /// a scope root, and nothing is granted at it: the grant list is empty, and
    /// that emptiness is the answer. A node this vault does not hold at all is
    /// [`EngineError::UnknownNode`], and a scope root this read could not reach
    /// leaves [`SharingView::state`] absent rather than empty.
    pub async fn sharing(&self, scope_root: NodeId) -> Result<SharingView, EngineError> {
        self.live_session()?;
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        // A node this vault does not hold is a caller error, and must not read
        // back as the empty grant list a node that is simply not a scope root
        // answers with.
        {
            let base = self.snapshot.borrow();
            if scope_root != base.root && !base.contains(scope_root) {
                return Err(EngineError::UnknownNode);
            }
        }
        let contacts = self
            .contact_store(session)
            .contacts()
            .await
            .map_err(EngineError::from_contact_store)?
            .into_iter()
            .map(|contact| SharingContact {
                identity_public_key: contact.identity_pk().to_sec1().to_vec(),
            })
            .collect();
        Ok(SharingView {
            scope: scope_root,
            contacts,
            state: self.scope_sharing(session, scope_root).await,
        })
    }

    /// Everything one resolve of `scope_root` settles for [`Self::sharing`]: the
    /// grant ledger its record commits projected key-free, this owner's invite
    /// links there, and whether a further share would be accepted.
    ///
    /// The authority for what is a scope root is the vault root's owner-signed
    /// direct-child-scope index, which [`owner_scope`](Self::owner_scope) owns —
    /// so a node it does not name has an empty grant list and a mint on offer. A
    /// read reports, it does not repair, so an index miss refuses rather than
    /// reaching for a derived name ([`UnindexedScope`]).
    /// A resolve that failed answers `None`, so a host cannot paint "shared with
    /// nobody" over a subtree it simply could not read, nor offer a mint the
    /// engine would refuse.
    async fn scope_sharing(
        &self,
        session: &SessionIdentity,
        scope_root: NodeId,
    ) -> Option<ScopeSharing> {
        let api = self.api.as_ref()?;
        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let keys = || OwnerRotationKeys {
            enc_secret: session.enc_subkey(),
            identity: &owner_identity,
            scope_keys: &scope_keys,
        };
        let target = match self
            .owner_scope(
                scope_root,
                api,
                keys(),
                NOT_A_SCOPE_ROOT,
                UnindexedScope::Refuse,
            )
            .await
        {
            Ok(target) => target,
            Err(EngineError::UnsupportedTarget {
                check: NOT_A_SCOPE_ROOT,
            }) => {
                return Some(ScopeSharing {
                    grants: Vec::new(),
                    can_mint_share: true,
                    invite_links: Some(SharingInviteLinks::default()),
                });
            }
            Err(_) => return None,
        };
        let current = self
            .owner_rotation_net(api, keys(), target.ancestry(), PointerConsultArm::Refused)
            .resolve_anchored(&target.scope)
            .await
            .ok()?;
        // Fail closed on a ledger the owner's commitment does not commit: the
        // write body it rides in is authored by any committed writer, so the row
        // set is only as trustworthy as the epoch-free commitment over it.
        if enforce_committed_ledger(&current.commitment, &current.grant_ledger).is_err() {
            return None;
        }
        // Attributing a record to this owner rests on the owner's own signature
        // over the set it is read against, so an unheld commitment reads as
        // unreachable rather than as a scope with no links.
        let commitment_sig = parsed_commitment_sig(&current.commitment_sig).ok()?;
        OwnerAuthority {
            identity_signer: session.identity(),
            enc_secret: session.enc_subkey(),
        }
        .authorise(&CommittedScope {
            scope_id: &target.scope.scope_id,
            commitment: &current.commitment,
            commitment_sig: &commitment_sig,
            ledger: &current.grant_ledger,
        })
        .ok()?;

        // A link store this could not open is absence, not "no links": the grant
        // half of the read still stands.
        let split = self.invite_store(session).load().await.ok().map(|records| {
            partition_scope_links(
                session.enc_subkey(),
                &records.links,
                &current.commitment,
                &target.scope.scope_id,
            )
        });
        // One committed record is the live link; two have no defined cut, so the
        // read reports none — the same rule `locate_invite_link` revokes under.
        let live = split
            .as_ref()
            .and_then(|split| match split.committed.as_slice() {
                [link] => Some(link),
                _ => None,
            });
        let now = self.seams.scheduler.now();
        let invite_links = split.as_ref().map(|split| SharingInviteLinks {
            live: live.is_some(),
            expires_at: live.and_then(|link| link.expires_at),
            expired: live
                .and_then(|link| link.expires_at)
                .is_some_and(|deadline| now.0 >= deadline.0),
            spent: u32::try_from(split.spent.len()).unwrap_or(u32::MAX),
        });

        Some(ScopeSharing {
            // A link renders as a link, never as a grant row keyed by the
            // ephemeral identity only the fragment holder answers for.
            grants: project_grant_ledger(
                &owner_identity,
                &target.scope.ipns_name,
                current.grant_ledger.iter().filter(|entry| {
                    split.as_ref().is_none_or(|split| {
                        !split.committed.iter().any(|link| link.tag == entry.tag)
                    })
                }),
            ),
            // A share mints a fresh scope at the node, so one that already is a
            // scope root refuses it.
            can_mint_share: false,
            invite_links,
        })
    }

    /// Read one file node's full plaintext content (blueprint/engine.md
    /// "Content plane": verified reads). Resolves the child record cache-first
    /// through the [`ChildAdopter`] pipeline, fetches the head version's DAG
    /// (root manifest + leaves) CID-verified fail-closed, unseals each leaf
    /// under the version content key, and reassembles the plaintext with
    /// length cross-checks. Emits [`Event::OpProgress`] on entry, success, and
    /// failure; on success folds the head version's size/mtime into the base
    /// snapshot, emitting [`Event::SnapshotUpdated`] only when they changed.
    pub async fn read_content(&self, node: NodeId) -> Result<Vec<u8>, EngineError> {
        self.live_session()?;
        self.emit_op_progress(node, OpPhase::DownloadStarted, None);
        match self.read_whole(node).await {
            Ok(plaintext) => {
                self.emit_op_progress(node, OpPhase::DownloadCompleted, None);
                Ok(plaintext)
            }
            Err(err) => {
                self.emit_op_progress(node, OpPhase::DownloadFailed, Some(err.to_string()));
                Err(err)
            }
        }
    }

    /// [`read_content`](Engine::read_content) without its progress phases.
    async fn read_whole(&self, node: NodeId) -> Result<Vec<u8>, EngineError> {
        let (version, version_count) = self.head_version(node).await?;
        self.refuse_unpaired_version(node, &version).await?;
        // The range clamps to the version's size, so the whole file is the
        // unbounded window.
        let bytes = open_content_range(&self.gateway, &self.seams.http, &version, 0, u64::MAX)
            .await
            .map_err(open_engine_error)?;
        self.project_head(node, &version, version_count);
        Ok(bytes)
    }

    /// Open a ranged-read stream over a file node, pinning the head version and
    /// its verified root manifest for the handle's whole life ([`StreamHandle`]).
    ///
    /// This is where a media read pays its resolve, its adoption gate, and its
    /// root-manifest fetch — once, not once per window. Closed with
    /// [`close_stream`](Engine::close_stream).
    pub async fn open_content_stream(&self, node: NodeId) -> Result<StreamHandle, EngineError> {
        self.live_session()?;
        // Reserved before the resolve, so an open past the ceiling spends no
        // network and no open that reaches the insert can be refused there.
        let slot =
            StreamSlot::acquire(&self.streams.borrow().live).ok_or(EngineError::TooManyStreams)?;
        let (version, version_count) = self.head_version(node).await?;
        self.refuse_unpaired_version(node, &version).await?;
        let manifest = open_content_root(&self.gateway, &self.seams.http, &version)
            .await
            .map_err(open_engine_error)?;
        self.project_head(node, &version, version_count);
        let mut streams = self.streams.borrow_mut();
        streams.next += 1;
        let handle = StreamHandle(streams.next);
        streams.open.insert(
            handle,
            Rc::new(LiveStream {
                version,
                manifest,
                _slot: slot,
            }),
        );
        Ok(handle)
    }

    /// Read one byte window of an open stream's pinned version, fetching only
    /// the leaves the window covers. Clamped to the pinned version, so an offset
    /// at or past its end yields no bytes. Emits no [`Event::OpProgress`]: a
    /// media element pulls a window per seek and per buffer refill, and a phase
    /// pair each would drown the stream.
    pub async fn read_stream(
        &self,
        handle: StreamHandle,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, EngineError> {
        self.live_session()?;
        // Lifted out of the map so the borrow does not span the awaits below;
        // the pinned content key zeroizes when the last `Rc` drops.
        let stream = self
            .streams
            .borrow()
            .open
            .get(&handle)
            .map(Rc::clone)
            .ok_or(EngineError::UnknownStreamHandle)?;
        read_pinned_range(
            &self.gateway,
            &self.seams.http,
            &stream.version,
            &stream.manifest,
            offset,
            length,
        )
        .await
        .map_err(open_engine_error)
    }

    /// The `contentCid` of the version a live stream pinned: the identity of
    /// the plaintext every window off it serves. `None` for a handle the
    /// engine does not hold.
    pub fn stream_version_cid(&self, handle: StreamHandle) -> Option<Vec<u8>> {
        self.streams
            .borrow()
            .open
            .get(&handle)
            .map(|stream| stream.version.content_cid.clone())
    }

    /// Release a read stream. Idempotent — an unknown handle is already gone.
    pub fn close_stream(&self, handle: StreamHandle) {
        self.streams.borrow_mut().open.remove(&handle);
    }

    /// Repaint the base node from a head version a read has just verified.
    ///
    /// The verified head is gate-passing state, so it may legally touch the base
    /// node's projected size/mtime. Repaint only on a real change — a repeat read
    /// must not cascade.
    fn project_head(&self, node: NodeId, version: &Version, version_count: u64) {
        if project_child_version(
            &mut self.snapshot.borrow_mut(),
            node,
            version.size,
            version.modified_at,
            version_count,
            Some(&version.content_cid),
        ) {
            let _ = self.events.unbounded_send(Event::SnapshotUpdated);
        }
    }

    /// [`Self::resolve_head`] for a read, which needs bytes: a file with no
    /// published version is unavailable rather than empty.
    async fn head_version(&self, node: NodeId) -> Result<(Version, u64), EngineError> {
        match self.resolve_head(node).await? {
            (Some(version), count) => Ok((version, count)),
            (None, _) => Err(EngineError::ContentUnavailable {
                message: "file has no published content version".to_owned(),
            }),
        }
    }

    /// Resolve one file node's head content version: base-snapshot lookup →
    /// gated child resolve → head of the sealed body's version list. Returns
    /// the head version (`None` for a file that has published none) and the
    /// body's version count.
    async fn resolve_head(&self, node: NodeId) -> Result<(Option<Version>, u64), EngineError> {
        // The base snapshot alone answers the lookup (kind and ipnsName never
        // come from the overlay) — no full render for a single node. The borrow
        // never spans an await.
        let base_meta = {
            let base = self.snapshot.borrow();
            base.node(node)
                .map(|meta| (meta.kind, meta.ipns_name.clone()))
        };
        let (kind, ipns_name) = match base_meta {
            Some(meta) => meta,
            None => {
                // Absent from gate-passing state: a queued op targeting the node
                // means a pending (unpublished) create; anything else is unknown.
                let pending = self.pending_ops().await?;
                return Err(if pending.iter().any(|op| op.target == node) {
                    EngineError::ContentUnavailable {
                        message: "content not yet published".to_owned(),
                    }
                } else {
                    EngineError::UnknownNode
                });
            }
        };
        if kind == NodeKind::Folder {
            return Err(EngineError::NotAFile);
        }
        let name_bytes = ipns_name.ok_or_else(|| EngineError::ContentUnavailable {
            message: "content not yet published".to_owned(),
        })?;
        // The bytes are the UTF-8 of the canonical base36 name; anything
        // else is a malformed child ref, fail-closed.
        let name = core::str::from_utf8(&name_bytes)
            .ok()
            .and_then(|s| IpnsName::parse(s).ok())
            .ok_or_else(|| EngineError::TrustViolation {
                message: "child ipnsName is not a canonical IPNS name".to_owned(),
            })?;
        // The node's scope is the vault root scope (subscope reads are a later
        // slice). A clone of the seed keeps the cell borrow from spanning the
        // awaits below; the clone zeroizes when the adopter drops.
        let scope_id = self.snapshot.borrow().root.0;
        // No untrusted input was judged here — a missing seed is missing held
        // material (availability), never a trust verdict.
        let scope_read_seed = self.scope_read_seed(&scope_id).await.ok_or_else(|| {
            EngineError::ContentUnavailable {
                message: "no read seed held for the node's scope".to_owned(),
            }
        })?;
        let adopter = ChildAdopter::new(
            &self.gateway,
            &self.seams.http,
            &self.seams.floor_store,
            scope_id,
            scope_read_seed,
            node.0,
        );
        let adopted = resolve_child(
            &self.seams.record_transport,
            &self.seams.snapshot_cache,
            &adopter,
            &name,
            ResolveMode::CacheFirst,
        )
        .await
        .map_err(|e| match e {
            ChildResolveError::Unavailable(message) => EngineError::ContentUnavailable { message },
            ChildResolveError::Gate(gate) => EngineError::from_gate(gate),
        })?;

        let ReadBody::File { versions, .. } = adopted.read_body else {
            // The parent's child ref said file: a sealed folder body is a kind
            // transplant, fail-closed.
            return Err(EngineError::TrustViolation {
                message: "sealed body kind disagrees with the child ref".to_owned(),
            });
        };
        // Newest-first; head is current (crates/core/src/seal/body.rs). Clone the
        // head rather than moving it out: `into_iter().next()` bitwise-moves slot
        // 0, so its content key would reach the allocator unzeroized.
        Ok((versions.first().cloned(), versions.len() as u64))
    }

    /// Best-effort [`Event::OpProgress`] emission for a full content read (a
    /// dropped receiver is fine).
    fn emit_op_progress(&self, node: NodeId, phase: OpPhase, error: Option<String>) {
        let _ = self.events.unbounded_send(Event::OpProgress {
            op_id: None,
            node,
            phase,
            progress: None,
            error,
        });
    }

    /// The current base snapshot's root node id — the FUSE mount anchor. The
    /// seeded all-zero root until cold-start/resolve replaces the base snapshot.
    pub fn root(&self) -> NodeId {
        self.snapshot.borrow().root
    }

    /// Render the base snapshot with the pending-op overlay applied.
    async fn render(&self) -> Result<Snapshot, EngineError> {
        // Take the base borrow only after the await, and drop it at the end of
        // this sync call — a `RefCell` borrow must never span an `.await`.
        let ops = self.pending_ops().await?;
        let base = self.snapshot.borrow();
        Ok(apply_overlay(&base, &ops))
    }

    /// Every retained dead-lettered op, with its reason.
    fn retained_dead_letters(&self) -> Vec<DeadLetter> {
        self.dead_letters
            .borrow()
            .iter()
            .map(|(op_id, (_, reason))| DeadLetter {
                op_id: *op_id,
                reason: *reason,
            })
            .collect()
    }

    /// The staleness rung at this instant, off the injected clock.
    fn staleness_now(&self) -> Staleness {
        let status = self.sync_status.borrow();
        classify(
            self.seams.scheduler.now(),
            status.last_success,
            status.reconcile_in_flight,
            Connectivity::Online,
            &self.profile,
        )
    }

    /// Scan the durable staging store's queue for this session. Undecodable
    /// entries are dropped from the render here; the cold-start path
    /// dead-letters and removes them from the durable queue.
    ///
    /// Memoized on the queue's own shape ([`QueueScanMemo`]), so reads pay the
    /// HPKE open per owned record once per queue mutation, not once per render.
    async fn scan_queue(&self) -> Result<QueueScan, EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let raw = self
            .seams
            .staging_store
            .queued_ops()
            .await
            .map_err(EngineError::from_seam)?;
        let reader = RecordReader::new(session.enc_subkey());
        let mut memo = self.queue_scan.borrow_mut();
        Ok(memo.scan(&reader, &raw, decode_queue).clone())
    }

    /// This session's pending ops, FIFO.
    async fn pending_ops(&self) -> Result<Vec<Op>, EngineError> {
        Ok(self
            .scan_queue()
            .await?
            .mine
            .into_iter()
            .map(|(_id, op)| op)
            .collect())
    }

    /// What a relocation op anchors on: the parent the move was formed against
    /// (the scope root for an unlinked node) and the target's base sequence.
    fn relocation_anchors(&self, rendered: &Snapshot, node: NodeId) -> (NodeId, u64) {
        let from_parent = rendered
            .parent_of(node)
            .unwrap_or(self.snapshot.borrow().root);
        (from_parent, rendered.record_sequence(node).unwrap_or(1))
    }

    /// The version a new write of `node` follows — the conditional-edit anchor
    /// ([`OpKind::UpdateContent`](crate::sync::op::OpKind::UpdateContent)): the
    /// last queued op that authors one, else the published head.
    ///
    /// A head this device has never projected is resolved here, before anything
    /// is spent, rather than left unanchored — an unanchored write is one the
    /// drain can only refuse, after a whole upload. Fails closed: a head that
    /// will not resolve is a write that cannot prove what it replaces.
    async fn write_anchor(&self, node: NodeId) -> Result<Option<Vec<u8>>, EngineError> {
        let authored = self.staged_version_cid(node).await?;
        if authored.is_some() {
            return Ok(authored);
        }
        let projected = {
            let base = self.snapshot.borrow();
            base.node(node)
                .map(|meta| (meta.content_version, meta.head_content_cid.clone()))
        };
        match projected {
            // Absent from gate-passing state: a pending create, whose versions
            // are exactly what its own queue authors.
            None => Ok(None),
            Some((Some(_), head)) => Ok(head),
            Some((None, _)) => match self.resolve_head(node).await? {
                (Some(version), count) => {
                    let cid = version.content_cid.clone();
                    self.project_head(node, &version, count);
                    Ok(Some(cid))
                }
                (None, _) => Ok(None),
            },
        }
    }

    /// Refuse to serve `version` when the queue has staged a different one: the
    /// read-side half of the pairing rule
    /// [`rendered_version_cid`](Self::rendered_version_cid) states.
    ///
    /// Availability, not trust — the drain publishes the staged version and the
    /// read lands. Judged on the staged cid alone, so a refusal costs no
    /// resolve.
    async fn refuse_unpaired_version(
        &self,
        node: NodeId,
        version: &Version,
    ) -> Result<(), EngineError> {
        match self
            .staged_version_cid(node)
            .await?
            .is_some_and(|staged| staged != version.content_cid)
        {
            true => Err(EngineError::ContentUnavailable {
                message: "a newer content version is staged and not yet published".to_owned(),
            }),
            false => Ok(()),
        }
    }

    /// The `contentCid` of the newest version a queued op has staged for `node`,
    /// `None` when the queue authors none.
    async fn staged_version_cid(&self, node: NodeId) -> Result<Option<Vec<u8>>, EngineError> {
        Ok(self.pending_ops().await?.iter().rev().find_map(|op| {
            (op.target == node)
                .then(|| op.content_root_cid())
                .flatten()
                .map(<[u8]>::to_vec)
        }))
    }

    /// The `contentCid` of the version the rendered view's size and mtime
    /// describe for `node`: the staged version when the queue authors one, else
    /// the head this device has projected. `None` for a node no version has
    /// ever been published or staged for.
    ///
    /// A consumer that samples the rendered length and composes over bytes it
    /// pinned separately must pair the two against this: composing over any
    /// other version seals that version's bytes under this one's length —
    /// `published ++ zero-hole ++ tail`, with no error.
    pub async fn rendered_version_cid(&self, node: NodeId) -> Result<Option<Vec<u8>>, EngineError> {
        self.live_session()?;
        if let Some(staged) = self.staged_version_cid(node).await? {
            return Ok(Some(staged));
        }
        Ok(self
            .snapshot
            .borrow()
            .node(node)
            .and_then(|meta| meta.head_content_cid.clone()))
    }

    /// The base sequence to anchor an op at: the target's own record sequence in
    /// the rendered view, defaulting to 1 for a node not yet in gate-passing
    /// state (a pending create).
    async fn base_sequence_for(&self, node: NodeId) -> Result<u64, EngineError> {
        Ok(self.render().await?.record_sequence(node).unwrap_or(1))
    }

    /// Mint a fresh random 16-byte node id from the injected entropy seam
    /// (id16, non-secret; blueprint/core.md). Fails closed on entropy failure —
    /// never a predictable id.
    fn mint_node_id(&self) -> Result<NodeId, EngineError> {
        let id = fresh_bytes(&mut *self.entropy.borrow_mut(), "node id")
            .map_err(EngineError::from_entropy)?;
        Ok(NodeId(id))
    }

    /// Stage a metadata op and emit [`Event::SnapshotUpdated`] on success,
    /// returning the durable queue id the drain will report the op under.
    async fn stage_and_notify(&mut self, op: &Op) -> Result<CommandOutcome, EngineError> {
        let seal = self.record_seal()?;
        let op_id = stage_op(&self.seams.staging_store, seal, op)
            .await
            .map_err(EngineError::from_seam)?;
        // Best-effort push-invalidation trigger; a dropped receiver (host torn
        // down) is fine.
        let _ = self.events.unbounded_send(Event::SnapshotUpdated);
        Ok(CommandOutcome::Queued { op_id })
    }

    /// Sealing inputs for one durable op record: the session's enc-subkey plus
    /// a fresh ephemeral scalar. Fails closed on entropy failure — a reused
    /// HPKE ephemeral is a confidentiality break, never a degraded mode.
    fn record_seal(&self) -> Result<RecordSeal<'_>, EngineError> {
        let owner_enc_secret = self
            .session
            .as_ref()
            .ok_or(EngineError::NotStarted)?
            .enc_subkey();
        let ephemeral_scalar =
            fresh_ephemeral(&mut *self.entropy.borrow_mut()).map_err(EngineError::from_entropy)?;
        Ok(RecordSeal {
            owner_enc_secret,
            ephemeral_scalar,
        })
    }

    /// Note that a host filesystem operation put `node` in view, and report
    /// whether its state is past the staleness threshold — the desktop
    /// **FUSE-op TTL check** (blueprint/desktop.md "Freshness"). `None` is an
    /// operation with no node in view.
    ///
    /// A folder becomes the focus window; a file joins the queue the tick's file
    /// leg drains ([`focus_files`](Self::focus_files)). Only a node this
    /// device's own gate-passing state calls a file takes the file path, so a
    /// node it has not resolved yet keeps the window behaviour it had before it
    /// was projected.
    ///
    /// Nothing resolves here: a kernel callback never waits on the record plane
    /// (blueprint/desktop.md "the never-block law"). A `true` answer is the
    /// refresh hint, and the tick is what acts on it, over the window this call
    /// set. The hint is recorded so a burst of callbacks over one node costs one
    /// hint rather than one per callback.
    pub fn note_focus_access(&self, node: Option<NodeId>) -> bool {
        let Some(node) = node else {
            return false;
        };
        let now = self.seams.scheduler.now();
        let is_file = self
            .snapshot
            .borrow()
            .node(node)
            .is_some_and(|meta| meta.kind == NodeKind::File);
        if !is_file {
            self.focus.borrow_mut().open_folder = Some(node);
            self.focus_touched.set(Some(now));
        }
        // A pass that resolved the node and a hint already filed for it both
        // answer this access; the later of the two is what it is measured from.
        let hinted = self
            .focus_hinted
            .get()
            .filter(|(hinted, _)| *hinted == node)
            .map(|(_, at)| at);
        let last = self
            .focus_refreshed
            .borrow()
            .get(&node)
            .copied()
            .max(hinted);
        let stale = last.is_none_or(|last| on_access_refresh_due(now, last, &self.profile));
        if stale {
            self.focus_hinted.set(Some((node, now)));
            if is_file {
                let mut queued = self.focus_files.borrow_mut();
                queued.retain(|held| *held != node);
                queued.push(node);
                if queued.len() > MAX_FOCUS_FILES {
                    queued.remove(0);
                }
            }
        }
        stale
    }

    /// The folder the focus window currently holds open.
    pub fn focus_folder(&self) -> Option<NodeId> {
        self.focus.borrow().open_folder
    }

    /// The sync timing profile this engine runs under.
    pub fn profile(&self) -> &SyncTimingProfile {
        &self.profile
    }

    /// The measured storage split this engine runs under.
    pub fn storage_policy(&self) -> &StoragePolicy {
        &self.storage_policy
    }
}

/// Map a verified-read failure onto the facade error surface.
fn open_engine_error(error: OpenError) -> EngineError {
    match error {
        OpenError::Trust(message) => EngineError::TrustViolation { message },
        OpenError::Unavailable(message) => EngineError::ContentUnavailable { message },
        OpenError::UnsupportedFormat { version } => {
            EngineError::UnsupportedContentFormat { version }
        }
    }
}

impl<T: SeamTypes> Drop for Engine<T> {
    fn drop(&mut self) {
        // The spawned loops hold only `Rc` clones, so they outlive the engine
        // unless it tears them down here.
        self.shut_down();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::{Value, json};

    use cipherbox_core::ipns::IpnsRecord;
    use cipherbox_core::kdf;

    use crate::seams::{CredentialStore, EndpointId, HttpResponse, UnixMillis};
    use crate::settings::settings_name;
    use crate::testkit::fakes::InMemoryRecordStore;
    use crate::testkit::{FakeDevice, FakeSeamTypes, FakeWorld, SeededEntropy, block_on};

    /// A destination the render cannot walk to the root is refused, and one it
    /// does not hold at all is the same "gone" verdict every other read gives —
    /// a host that could not tell them apart would show a scope-exit
    /// explanation for a folder someone simply deleted.
    #[test]
    fn a_relocation_is_proven_in_scope_before_it_can_be_journaled() {
        let root = NodeId([1; 16]);
        let inside = NodeId([2; 16]);
        let orphan = NodeId([3; 16]);
        let mut rendered = Snapshot::new(root);
        rendered.upsert_node(NodeMeta::new(inside, "box", NodeKind::Folder));
        rendered.link_next(root, inside);
        rendered.upsert_node(NodeMeta::new(orphan, "adrift", NodeKind::Folder));

        assert!(refuse_scope_exit(&rendered, root).is_ok());
        assert!(refuse_scope_exit(&rendered, inside).is_ok());
        assert!(matches!(
            refuse_scope_exit(&rendered, NodeId([9; 16])),
            Err(EngineError::UnknownNode)
        ));
        assert!(matches!(
            refuse_scope_exit(&rendered, orphan),
            Err(EngineError::ScopeExitRefused { .. })
        ));
    }

    /// A transport that lands a settings save into `slot` before the resolve it
    /// wraps can answer — the interleaving a single-threaded executor allows at
    /// any `.await`.
    struct SavesAcrossTheResolve {
        inner: InMemoryRecordStore,
        slot: Rc<RefCell<Option<HeldRecord>>>,
        saved: HeldRecord,
    }

    impl RecordTransport for SavesAcrossTheResolve {
        fn endpoints(&self) -> Vec<EndpointId> {
            self.inner.endpoints()
        }

        async fn get_record(
            &self,
            endpoint: &EndpointId,
            routing_key: &str,
            max_bytes: usize,
        ) -> SeamResult<Option<Vec<u8>>> {
            *self.slot.borrow_mut() = Some(self.saved.clone());
            self.inner
                .get_record(endpoint, routing_key, max_bytes)
                .await
        }

        async fn put_record(
            &self,
            endpoint: &EndpointId,
            routing_key: &str,
            record: &[u8],
        ) -> SeamResult<()> {
            self.inner.put_record(endpoint, routing_key, record).await
        }
    }

    const SETTINGS_SECRET: [u8; 32] = [7u8; 32];

    /// A held settings record at `head` and `sequence`, signed by the name's
    /// own keypair so the resolve verifies it.
    fn settings_held(head: &str, sequence: u64) -> HeldRecord {
        const TTL_NANOS: u64 = 2_000_000_000;
        const EOL: &str = "2099-01-01T00:00:00Z";
        HeldRecord {
            routing_key: settings_name(&SETTINGS_SECRET).as_str().to_owned(),
            record_bytes: IpnsRecord::create_v2(
                &kdf::settings_ipns_keypair(&SETTINGS_SECRET),
                format!("/ipfs/{head}").as_bytes(),
                sequence,
                TTL_NANOS,
                EOL,
            )
            .marshal(),
            signer: kdf::settings_ipns_keypair(&SETTINGS_SECRET),
            head_cid: head.to_owned(),
            content_cids: Vec::new(),
        }
    }

    /// Resolve `superseded` against a plane a second device published over,
    /// with `saved` landing in the slot across the resolve. Answers what the
    /// slot holds afterwards.
    fn resolve_with_a_save_across_it(
        superseded: HeldRecord,
        saved: HeldRecord,
    ) -> Option<HeldRecord> {
        let name = settings_name(&SETTINGS_SECRET);
        let inner = InMemoryRecordStore::new(vec![EndpointId::new("fake:someguy")]);
        let live = settings_held("bafyseconddevicehead", 2).record_bytes;
        for endpoint in inner.endpoints() {
            inner.seed_record(&endpoint, name.as_str(), live.clone());
        }

        let slot = Rc::new(RefCell::new(Some(superseded)));
        let transport = SavesAcrossTheResolve {
            inner,
            slot: Rc::clone(&slot),
            saved,
        };
        assert!(block_on(live_settings_record(&transport, &slot)).is_none());
        slot.borrow().clone()
    }

    /// The superseded verdict names the record that pass read. A save that
    /// landed across the resolve installed its own confirmed record, and
    /// clearing that one would drop the live settings from the keyless re-PUT
    /// and the EOL renewal for the rest of the session.
    #[test]
    fn a_save_that_lands_across_the_resolve_keeps_its_record_in_the_renewal() {
        let saved = settings_held("bafysavedhead", 3);
        assert_eq!(
            resolve_with_a_save_across_it(settings_held("bafysupersededhead", 1), saved.clone())
                .map(|held| held.record_bytes),
            Some(saved.record_bytes),
            "the superseded record was cleared, not the save that replaced it"
        );
    }

    /// A head CID does not name a record: the same head re-signed at a higher
    /// sequence is a different record, and the renewal has to keep it.
    #[test]
    fn a_save_across_the_resolve_survives_even_at_the_head_it_replaces() {
        const HEAD: &str = "bafysupersededhead";
        let saved = settings_held(HEAD, 3);
        assert_eq!(
            resolve_with_a_save_across_it(settings_held(HEAD, 1), saved.clone())
                .map(|held| held.record_bytes),
            Some(saved.record_bytes),
            "a save sharing the inspected head CID is still a different record"
        );
    }

    /// Shaped as the API issues one; the engine signs nothing else.
    const LOGIN_CHALLENGE_FIXTURE: &str =
        "cipherbox-login:v2:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A JSON HTTP response the scripted client decodes as a Nest body.
    fn json_response(status: u16, body: Value) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    /// Script the API calls first-run provisioning makes on a configured base
    /// URL: the vacancy probe against the recovery cache, the head-block upload
    /// answered at the block's own address, then register-first for the root
    /// name and for the vault pointer.
    fn serve_provisioning(device: &FakeDevice) {
        // The vacancy probe: the API's record cache has never seen this name.
        device
            .http
            .enqueue_derived(|_| Ok(json_response(404, json!({ "statusCode": 404 }))));
        device.http.enqueue_derived(|request| {
            let block = request.body.clone().unwrap_or_default();
            Ok(json_response(
                200,
                json!({ "cid": crate::content::root_block_cid(&block), "size": block.len() }),
            ))
        });
        for _ in 0..2 {
            device
                .http
                .enqueue_derived(|_| Ok(json_response(200, json!([]))));
        }
    }

    /// An engine over a retained device (so the test scripts HTTP and inspects
    /// the credential store), against `base_url`.
    fn engine_over(base_url: ApiBaseUrl) -> (Engine<FakeSeamTypes>, EventStream, FakeDevice) {
        let device = FakeWorld::new().device(b"alice-pk");
        let (engine, events) = Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
            ContentProfile::CI,
            StoragePolicy::CI,
            base_url,
            GatewayConfig::disabled(),
        );
        (engine, events, device)
    }

    fn new_engine() -> (Engine<FakeSeamTypes>, EventStream) {
        let device = FakeWorld::new().device(b"alice-pk");
        Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
            ContentProfile::CI,
            StoragePolicy::CI,
            ApiBaseUrl::offline(),
            GatewayConfig::disabled(),
        )
    }

    /// Starts an engine whose virtual clock sits at `clock` before `start`, so
    /// tests can prove derivation is independent of the wall time at boot.
    fn started_engine_at(secret_byte: u8, clock: UnixMillis) -> Engine<FakeSeamTypes> {
        let world = FakeWorld::new();
        world.scheduler.advance_to(clock);
        let device = world.device(b"alice-pk");
        let (mut engine, _events) = Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
            ContentProfile::CI,
            StoragePolicy::CI,
            ApiBaseUrl::offline(),
            GatewayConfig::disabled(),
        );
        block_on(engine.start(LoginSecret::new(vec![secret_byte; 32]))).unwrap();
        engine
    }

    /// A mint that did not land must not cost the host its engine. Cold start
    /// already paints an unprovisioned vault and queues ops against it, so a
    /// failed provision leaves exactly that state — a fresh account on a flaky
    /// network still opens the app, still reads, still queues — and says so
    /// rather than failing silently.
    #[test]
    fn a_failed_provision_still_starts_the_engine_and_reports_itself() {
        let (mut engine, mut events, device) =
            engine_over(ApiBaseUrl::parse("http://api.test").expect("a configured base"));
        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": LOGIN_CHALLENGE_FIXTURE, "expiresAt": "2099-01-01T00:00:00Z" }),
        ));
        device.http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "gatewayToken": "gw-a", "isNewUser": true }),
        ));
        // The vacancy probe answers, so the mint proceeds — and then the
        // head-block upload has no route, exactly as an unreachable API leaves it.
        device
            .http
            .enqueue_derived(|_| Ok(json_response(404, json!({ "statusCode": 404 }))));

        block_on(engine.start(LoginSecret::new(vec![7u8; 32])))
            .expect("a mint that did not land is not a failed start");
        assert!(
            !engine.is_provisioned(),
            "the write path is dark until a later start mints one"
        );

        let reported: Vec<Event> = core::iter::from_fn(|| events.try_next())
            .filter(|event| matches!(event, Event::VaultUnprovisioned { .. }))
            .collect();
        assert!(
            matches!(
                reported.as_slice(),
                [Event::VaultUnprovisioned {
                    retryable: true,
                    ..
                }]
            ),
            "an unreachable API is a stall the host may retry, announced once: {reported:?}"
        );
    }

    /// The late mint spawns the resolve-tick loop for the root it just
    /// published.
    #[test]
    fn a_refresh_retries_a_first_run_mint_that_did_not_land() {
        let (mut engine, mut events, device) =
            engine_over(ApiBaseUrl::parse("http://api.test").expect("a configured base"));
        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": LOGIN_CHALLENGE_FIXTURE, "expiresAt": "2099-01-01T00:00:00Z" }),
        ));
        device.http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "gatewayToken": "gw-a", "isNewUser": true }),
        ));
        // The vacancy probe answers, then the head-block upload has no route.
        device
            .http
            .enqueue_derived(|_| Ok(json_response(404, json!({ "statusCode": 404 }))));
        block_on(engine.start(LoginSecret::new(vec![7u8; 32])))
            .expect("a mint that did not land is not a failed start");
        assert!(!engine.is_provisioned(), "the write path starts dark");
        let _ = device.scheduler.take_spawned_tasks();
        while events.try_next().is_some() {}

        // The network is back: the same refresh a host drives for anything else
        // now mints.
        serve_provisioning(&device);
        block_on(engine.command(Command::ManualRefresh)).expect("the retry mints");

        assert!(
            engine.is_provisioned(),
            "the write path opens in the session that failed to mint",
        );
        assert_eq!(
            device.scheduler.take_spawned_tasks().len(),
            1,
            "the late mint spawns the resolve-tick loop its root can now be polled by",
        );
    }

    /// Fail-closed but never fail-dark: a retry that does not land reports as
    /// the retryable stall it is, so the next one still reaches the mint.
    #[test]
    fn a_retry_that_does_not_land_stays_retryable() {
        let (mut engine, _events, device) =
            engine_over(ApiBaseUrl::parse("http://api.test").expect("a configured base"));
        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": LOGIN_CHALLENGE_FIXTURE, "expiresAt": "2099-01-01T00:00:00Z" }),
        ));
        device.http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "gatewayToken": "gw-a", "isNewUser": true }),
        ));
        device
            .http
            .enqueue_derived(|_| Ok(json_response(404, json!({ "statusCode": 404 }))));
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).expect("start survives the mint");

        device
            .http
            .enqueue_derived(|_| Ok(json_response(404, json!({ "statusCode": 404 }))));
        let refused = block_on(engine.command(Command::ManualRefresh));
        assert!(
            matches!(refused, Err(EngineError::RefreshFailed { .. })),
            "an unreachable API is a stall, not a verdict: {refused:?}",
        );
        assert!(!engine.is_provisioned());

        serve_provisioning(&device);
        block_on(engine.command(Command::ManualRefresh)).expect("the next retry mints");
        assert!(
            engine.is_provisioned(),
            "the session never went permanently dark"
        );
    }

    #[test]
    fn login_secret_debug_is_redacted() {
        let secret = LoginSecret::new(vec![0xAA; 32]);
        assert_eq!(format!("{secret:?}"), "LoginSecret(redacted)");
    }

    #[test]
    fn cold_start_derives_and_wires_the_session_identity() {
        let (mut engine, _events) = new_engine();
        assert!(engine.session().is_none(), "no identity before start");

        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        let session = engine
            .session()
            .expect("start derives the session identity");

        // Start derives the same identity as the pure derivation from the same
        // secret — it invents no key material.
        let expected =
            SessionIdentity::derive(&LoginSecret::new(vec![7u8; 32])).expect("valid identity");
        assert_eq!(
            session.vault_pointer_signer(0).verifying_key().to_bytes(),
            expected.vault_pointer_signer(0).verifying_key().to_bytes(),
        );
    }

    #[test]
    fn cold_start_derivation_is_deterministic_and_clock_independent() {
        // Two engines whose virtual clocks sit at different instants derive the
        // same identity from the same secret: `start` reads no clock or RNG,
        // only the seed.
        let a = started_engine_at(7, UnixMillis(0));
        let b = started_engine_at(7, UnixMillis(1_000_000));
        assert_eq!(
            a.session().unwrap().enc_subkey_public().to_bytes(),
            b.session().unwrap().enc_subkey_public().to_bytes(),
        );
        let c = started_engine_at(8, UnixMillis(2_000_000));
        assert_ne!(
            a.session().unwrap().enc_subkey_public().to_bytes(),
            c.session().unwrap().enc_subkey_public().to_bytes(),
            "a different secret is a different identity",
        );
    }

    #[test]
    fn start_performs_identity_login_and_persists_a_refresh_token() {
        /// Shaped as the API issues one; the engine signs nothing else.
        const LOGIN_CHALLENGE: &str =
            "cipherbox-login:v2:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let (mut engine, _events, device) =
            engine_over(ApiBaseUrl::parse("http://api.test").expect("a configured base"));
        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": LOGIN_CHALLENGE, "expiresAt": "2099-01-01T00:00:00Z" }),
        ));
        device.http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "gatewayToken": "gw-a", "isNewUser": true }),
        ));
        // A configured base URL means the empty pointer chain provisions.
        serve_provisioning(&device);

        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).expect("start logs in");

        // The refresh token from the token response persisted via CredentialStore.
        let stored = block_on(device.credential_store.load_refresh_token())
            .unwrap()
            .unwrap();
        assert_eq!(stored, "a".repeat(64).as_bytes());

        // The login signed the server challenge with the session identity signer:
        // the wire signature equals the identity's own deterministic signature.
        let requests = device.http.requests();
        assert_eq!(requests[1].url, "http://api.test/auth/login");
        let login_body: Value = serde_json::from_slice(requests[1].body.as_ref().unwrap()).unwrap();
        let identity = engine.session().unwrap().identity();
        let expected = hex_lower(
            &identity
                .sign_detcbor(LOGIN_CHALLENGE.as_bytes())
                .to_compact(),
        );
        assert_eq!(login_body["signature"], expected);
    }

    /// What gates the accelerator is the login-minted pseudonym, never the
    /// access JWT. Both are bound by login rather than configured, and both are
    /// gone with the engine.
    #[test]
    fn login_binds_the_pseudonym_to_the_accelerator_and_shutdown_drops_both() {
        let device = FakeWorld::new().device(b"alice-pk");
        let (mut engine, _events) = Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
            ContentProfile::CI,
            StoragePolicy::CI,
            ApiBaseUrl::parse("http://api.test").expect("a configured base"),
            GatewayConfig {
                accelerator: Some("https://gw.test".into()),
                public_fallbacks: Vec::new(),
            },
        );
        let accelerator_bearer = engine.accelerator_bearer.clone();
        let session_bearer = engine.session_bearer.clone();
        assert!(!accelerator_bearer.is_held(), "no credential before login");

        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": LOGIN_CHALLENGE_FIXTURE, "expiresAt": "2099-01-01T00:00:00Z" }),
        ));
        device.http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "gatewayToken": "gw-a", "isNewUser": true }),
        ));
        serve_provisioning(&device);
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).expect("start logs in");

        let held = engine
            .gateway
            .accelerator
            .as_ref()
            .expect("accelerator")
            .bearer
            .peek();
        assert_eq!(
            held.as_deref().map(String::as_str),
            Some("gw-a"),
            "the accelerator leg presents the read-scoped pseudonym"
        );
        assert_eq!(
            session_bearer.peek().as_deref().map(String::as_str),
            Some("jwt-1"),
            "the API leg keeps the access JWT, which the gateway tier never sees"
        );

        drop(engine);
        assert!(
            !accelerator_bearer.is_held(),
            "a parked tick's gateway clone outlives the engine; the token must not"
        );
        assert!(!session_bearer.is_held(), "the access JWT goes with it");
    }

    #[test]
    fn start_login_failure_is_fail_closed() {
        let (mut engine, _events, device) =
            engine_over(ApiBaseUrl::parse("http://api.test").expect("a configured base"));
        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": "c", "expiresAt": "2099-01-01T00:00:00Z" }),
        ));
        device.http.enqueue_response(json_response(
            401,
            json!({ "message": "Invalid challenge signature" }),
        ));
        // Clear any pre-start bookkeeping so the spawn assertion is unambiguous.
        let _ = device.scheduler.take_spawned_tasks();

        let out = block_on(engine.start(LoginSecret::new(vec![7u8; 32])));

        assert!(
            matches!(out, Err(EngineError::Auth { .. })),
            "a rejected login is a hard error, not a start"
        );
        assert!(
            engine.session().is_none(),
            "session not left half-initialized on login failure"
        );
        assert!(
            device.scheduler.take_spawned_tasks().is_empty(),
            "no liveness loop spawned before authentication succeeds"
        );
        assert_eq!(
            block_on(engine.command(Command::ManualRefresh)),
            Err(EngineError::NotStarted),
            "the engine stays unstarted after a failed login"
        );
    }

    #[test]
    fn siwe_login_command_forwards_message_and_hex_signature() {
        // Offline: `start` skips cold-start login, so only the SIWE exchange is
        // scripted here.
        let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        device.http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-siwe", "refreshToken": "b".repeat(64), "gatewayToken": "gw-b" }),
        ));

        let signature = vec![0xDE, 0xAD, 0xBE, 0xEF];
        block_on(engine.command(Command::SiweLogin {
            message: "siwe-message".to_owned(),
            signature: signature.clone(),
        }))
        .expect("siwe login");

        let request = device
            .http
            .requests()
            .pop()
            .expect("a SIWE request was sent");
        assert_eq!(request.url, "/auth/siwe/login");
        let body: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
        assert_eq!(body["message"], "siwe-message");
        assert_eq!(
            body["signature"],
            hex_lower(&signature),
            "the wallet signature crosses the wire hex-encoded"
        );
    }

    #[test]
    fn renewal_lost_race_surfaces_an_event_not_silence() {
        use crate::net::EolRenewResult;

        let (events, mut receiver) = mpsc::unbounded();
        let results = vec![
            // A lost CAS race: surfaced.
            EolRenewResult {
                routing_key: "k12D-lost".to_owned(),
                outcome: Ok(Some(PublishOutcome::LostRace {
                    published_sequence: 2,
                    observed_sequence: 3,
                })),
            },
            // A fail-closed publish failure: surfaced.
            EolRenewResult {
                routing_key: "k12D-failed".to_owned(),
                outcome: Err(PublishError::AllEndpointsFailed),
            },
            // A clean republish and a comfortably-ahead no-renewal: silent.
            EolRenewResult {
                routing_key: "k12D-ok".to_owned(),
                outcome: Ok(Some(PublishOutcome::Published { sequence: 2 })),
            },
            EolRenewResult {
                routing_key: "k12D-ahead".to_owned(),
                outcome: Ok(None),
            },
        ];

        emit_renewal_failures(&events, &results);
        drop(events);

        let mut emitted = Vec::new();
        while let Some(event) = block_on(async {
            core::future::poll_fn(|cx| Pin::new(&mut receiver).poll_next(cx)).await
        }) {
            emitted.push(event);
        }
        assert_eq!(
            emitted,
            vec![
                Event::RenewalFailed {
                    routing_key: "k12D-lost".to_owned(),
                    detail: "lost CAS race: published 2, observed 3".to_owned(),
                },
                Event::RenewalFailed {
                    routing_key: "k12D-failed".to_owned(),
                    detail: "all record endpoints failed".to_owned(),
                },
            ],
            "only the lost race and the publish failure surface; success is silent",
        );
    }

    #[test]
    fn command_names_are_stable() {
        assert_eq!(Command::ManualRefresh.name(), "manualRefresh");
        assert_eq!(Command::Logout.name(), "logout");
        assert_eq!(
            Command::Delete {
                node: NodeId([0; 16])
            }
            .name(),
            "delete"
        );
    }

    #[test]
    fn command_debug_prints_only_the_variant_name() {
        let command = Command::Create {
            parent: NodeId([0; 16]),
            name: "vacation-plans.txt".into(),
            kind: NodeKind::File,
        };
        let debug = format!("{command:?}");
        assert_eq!(debug, "Command(create)", "payloads must never leak");
    }

    #[test]
    fn engine_error_displays() {
        assert_eq!(
            EngineError::Unimplemented { command: "create" }.to_string(),
            "command not implemented yet: create"
        );
        assert_eq!(EngineError::NotStarted.to_string(), "engine not started");
        assert_eq!(
            EngineError::UnsupportedContentFormat { version: 2 }.to_string(),
            "content format version 2 is not supported by this client"
        );
    }

    /// The three device-side refusals are three different user actions, and each
    /// quotes the room left rather than the whole budget.
    #[test]
    fn over_budget_messages_name_the_action_and_quote_the_room_left() {
        let message = |cause| {
            EngineError::OverBudget {
                cause,
                requested: 900,
                available: 100,
            }
            .to_string()
        };
        let limit = message(OverBudgetCause::StagingLimit);
        let full = message(OverBudgetCause::DeviceFull);
        let backlog = message(OverBudgetCause::StagingBacklog);
        for text in [&limit, &full, &backlog] {
            assert!(text.contains("100"), "the refusal quotes the room left");
            assert!(!text.contains("256"), "never the whole budget");
        }
        assert_ne!(limit, full);
        assert_ne!(full, backlog);
        assert_ne!(limit, backlog);
        assert_ne!(
            message(OverBudgetCause::StorageUnmeasured),
            message(OverBudgetCause::AccountQuota),
            "an unmeasurable device is not a full account"
        );
    }

    // --- facade wiring: reads, command execution, event emission ---

    fn started() -> (Engine<FakeSeamTypes>, EventStream) {
        let (mut engine, events) = new_engine();
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        (engine, events)
    }

    /// Every event currently buffered on the stream, without blocking.
    fn drain(events: &mut EventStream) -> Vec<Event> {
        let mut out = Vec::new();
        while let Some(event) = events.try_next() {
            out.push(event);
        }
        out
    }

    fn create(engine: &mut Engine<FakeSeamTypes>, parent: NodeId, name: &str, kind: NodeKind) {
        block_on(engine.command(Command::Create {
            parent,
            name: name.into(),
            kind,
        }))
        .unwrap();
    }

    /// Feed `plaintext` through a write handle and commit it, the way a host
    /// slices a file.
    fn write_file(
        engine: &mut Engine<FakeSeamTypes>,
        target: WriteTarget,
        plaintext: &[u8],
    ) -> Result<OpId, EngineError> {
        let handle = block_on(engine.begin_write(target, plaintext.len() as u64))?;
        for piece in plaintext
            .chunks(7)
            .chain(plaintext.is_empty().then_some(&[][..]))
        {
            block_on(engine.push_chunk(handle, piece))?;
        }
        block_on(engine.commit_write(handle))
    }

    #[test]
    fn command_before_start_returns_not_started() {
        let (mut engine, _events) = new_engine();
        let out = block_on(engine.command(Command::Delete {
            node: NodeId([1; 16]),
        }));
        assert_eq!(out, Err(EngineError::NotStarted));
    }

    #[test]
    fn view_before_start_returns_not_started() {
        let (engine, _events) = new_engine();
        assert!(matches!(
            block_on(engine.view()),
            Err(EngineError::NotStarted)
        ));
    }

    #[test]
    fn create_is_visible_through_the_read_surface_and_emits() {
        let (mut engine, mut events) = started();
        let root = engine.root();
        create(&mut engine, root, "notes.txt", NodeKind::File);

        let view = block_on(engine.view()).unwrap();
        let children = view.children(root);
        assert_eq!(children.len(), 1, "the pending create renders");
        assert_eq!(children[0].name, "notes.txt");
        assert_eq!(children[0].kind, NodeKind::File);

        let found = view.lookup(root, "notes.txt").expect("lookup finds it");
        assert_eq!(found.id, children[0].id);
        assert_eq!(view.attrs(found.id).unwrap().name, "notes.txt");

        assert_eq!(
            block_on(events.next()),
            Some(Event::SnapshotUpdated),
            "a successful stage emits SnapshotUpdated"
        );
    }

    #[test]
    fn a_committed_write_renders_its_declared_size_before_it_publishes() {
        let (mut engine, mut events) = started();
        let root = engine.root();
        let plaintext = b"forty bytes of content ------------------";
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: root,
                name: "notes.txt".into(),
            },
            plaintext,
        )
        .expect("the write commits");

        let children = block_on(engine.view()).unwrap().children(root);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].kind, NodeKind::File);
        assert_eq!(
            children[0].size,
            Some(plaintext.len() as u64),
            "the overlay renders the committed size"
        );
        assert!(drain(&mut events).contains(&Event::SnapshotUpdated));
    }

    /// The acceptance case: a backing file that shrinks mid-read must fail the
    /// commit, never publish a short version as a success.
    #[test]
    fn a_write_whose_bytes_fall_short_of_the_declaration_fails_the_commit() {
        let (mut engine, _events) = started();
        let root = engine.root();
        let handle = block_on(engine.begin_write(
            WriteTarget::NewFile {
                parent: root,
                name: "truncated.txt".into(),
            },
            64,
        ))
        .unwrap();
        block_on(engine.push_chunk(handle, b"only twenty bytes...")).unwrap();

        assert_eq!(
            block_on(engine.commit_write(handle)),
            Err(EngineError::ContentSizeMismatch {
                declared: 64,
                observed: 20
            })
        );
        assert!(
            block_on(engine.view()).unwrap().children(root).is_empty(),
            "nothing is journaled, so nothing renders"
        );
        assert_eq!(
            block_on(engine.seams.staging_store.staged_bytes_total()).unwrap(),
            0,
            "the failed write releases the blocks it staged"
        );
    }

    /// A file that grows past its declaration is the same class of hazard, and
    /// is refused at the push rather than absorbed silently.
    #[test]
    fn a_push_past_the_declared_size_fails_closed_and_drops_the_handle() {
        let (mut engine, _events) = started();
        let root = engine.root();
        let handle = block_on(engine.begin_write(
            WriteTarget::NewFile {
                parent: root,
                name: "grew.txt".into(),
            },
            8,
        ))
        .unwrap();
        assert!(matches!(
            block_on(engine.push_chunk(handle, b"nine bytes")),
            Err(EngineError::ContentSizeMismatch { declared: 8, .. })
        ));
        assert_eq!(
            block_on(engine.commit_write(handle)),
            Err(EngineError::UnknownWriteHandle),
            "the handle is spent"
        );
    }

    /// The ledger's whole point: two handles opened before either stages a byte
    /// must contend for the budget, not both be admitted against it.
    #[test]
    fn concurrent_write_handles_cannot_over_admit_the_staging_budget() {
        let (mut engine, _events) = started();
        // Room for one 200-byte version's sealed total, not two.
        engine.storage_policy = StoragePolicy {
            staging_budget_bytes: 2000,
            staging_cap_bytes: 2000,
            ..StoragePolicy::CI
        };
        let root = engine.root();
        let target = |name: &str| WriteTarget::NewFile {
            parent: root,
            name: name.into(),
        };
        let first = block_on(engine.begin_write(target("a"), 200)).expect("the first fits");
        let refused = block_on(engine.begin_write(target("b"), 200)).unwrap_err();
        assert!(
            matches!(
                refused,
                EngineError::OverBudget {
                    cause: OverBudgetCause::StagingBacklog,
                    ..
                }
            ),
            "got {refused:?}"
        );

        block_on(engine.abort_write(first));
        assert!(
            block_on(engine.begin_write(target("b"), 200)).is_ok(),
            "releasing the first reservation frees the room"
        );
    }

    #[test]
    fn a_write_past_the_platform_cap_is_refused_before_a_byte_is_pushed() {
        let (mut engine, _events) = started();
        let root = engine.root();
        let refused = block_on(engine.begin_write(
            WriteTarget::NewFile {
                parent: root,
                name: "huge.bin".into(),
            },
            StoragePolicy::CI.staging_cap_bytes + 1,
        ))
        .unwrap_err();
        assert!(
            matches!(
                refused,
                EngineError::OverBudget {
                    cause: OverBudgetCause::StagingLimit,
                    ..
                }
            ),
            "got {refused:?}"
        );
    }

    /// The flat-DAG ceiling is a format limit, not a budget verdict: no device
    /// can serve such a version back, so freeing space would not help and the
    /// refusal must not quote a byte figure as though it would.
    #[test]
    fn a_file_past_the_flat_dag_ceiling_is_refused_as_a_format_limit() {
        let (mut engine, _events) = started();
        let root = engine.root();
        assert_eq!(
            block_on(engine.begin_write(
                WriteTarget::NewFile {
                    parent: root,
                    name: "colossal.bin".into(),
                },
                u64::MAX,
            )),
            Err(EngineError::ContentTooLarge {
                check: "dag-root-too-large"
            })
        );
    }

    /// A hold is a state that *clears*, so it is read off both surfaces rather
    /// than evented: a lost "released" would strand a host on a refusal the
    /// member has already fixed in their settings.
    #[test]
    fn a_settings_refused_hold_reaches_both_read_surfaces() {
        let (engine, _events) = started();
        let root = engine.root();
        let hold = SettingsHold {
            op_id: OpId(1),
            node: root,
            refusal: crate::settings::SettingsRefusal::Byo(
                crate::content::ProviderError::InsecureTransport,
            ),
        };
        *engine.settings_hold.borrow_mut() = Some(hold);

        assert_eq!(
            block_on(engine.snapshot(root)).unwrap().settings_hold,
            Some(hold)
        );
        assert_eq!(block_on(engine.status()).unwrap().settings_hold, Some(hold));
    }

    #[test]
    fn delete_removes_the_node_from_the_view() {
        let (mut engine, _events) = started();
        let root = engine.root();
        create(&mut engine, root, "f", NodeKind::File);
        let id = block_on(engine.view()).unwrap().children(root)[0].id;

        block_on(engine.command(Command::Delete { node: id })).unwrap();
        assert!(
            block_on(engine.view()).unwrap().children(root).is_empty(),
            "the pending delete renders"
        );
    }

    #[test]
    fn rename_updates_the_name_in_the_view() {
        let (mut engine, _events) = started();
        let root = engine.root();
        create(&mut engine, root, "old.txt", NodeKind::File);
        let id = block_on(engine.view()).unwrap().children(root)[0].id;

        block_on(engine.command(Command::Rename {
            node: id,
            new_name: "new.txt".into(),
        }))
        .unwrap();

        let view = block_on(engine.view()).unwrap();
        assert!(view.lookup(root, "old.txt").is_none());
        assert_eq!(view.lookup(root, "new.txt").unwrap().id, id);
    }

    #[test]
    fn relink_moves_the_node_between_folders_in_the_view() {
        let (mut engine, _events) = started();
        let root = engine.root();
        create(&mut engine, root, "dir", NodeKind::Folder);
        let dir = block_on(engine.view())
            .unwrap()
            .lookup(root, "dir")
            .unwrap()
            .id;
        create(&mut engine, dir, "f", NodeKind::File);
        let file = block_on(engine.view())
            .unwrap()
            .lookup(dir, "f")
            .unwrap()
            .id;

        block_on(engine.command(Command::Relink {
            node: file,
            new_parent: root,
        }))
        .unwrap();

        let view = block_on(engine.view()).unwrap();
        assert!(view.children(dir).is_empty(), "moved out of dir");
        assert_eq!(
            view.lookup(root, "f").unwrap().id,
            file,
            "now linked under root"
        );
    }

    #[test]
    fn statfs_counts_reachable_nodes() {
        let (mut engine, _events) = started();
        let root = engine.root();
        assert_eq!(
            block_on(engine.view()).unwrap().statfs().nodes,
            1,
            "root only"
        );
        create(&mut engine, root, "a", NodeKind::Folder);
        create(&mut engine, root, "b", NodeKind::File);
        assert_eq!(block_on(engine.view()).unwrap().statfs().nodes, 3);
    }

    /// The catch-all's remaining coverage, asserted rather than inferred: every
    /// grant, share and rotation arm is wired, so a command that still reports
    /// `Unimplemented` names a slice that genuinely has not landed.
    #[test]
    fn logout_is_the_only_command_left_unimplemented() {
        let (mut engine, _events) = started();
        assert_eq!(
            block_on(engine.command(Command::Logout)),
            Err(EngineError::Unimplemented { command: "logout" }),
        );
    }

    /// "Forget this device": the erase a logout deliberately does not do
    /// (blueprint/web-client.md "Logout").
    mod forget_device {
        use super::*;

        use crate::seams::AUTHORIZATION;

        /// An engine with something durable in every seam the erase covers, and
        /// the device handles to read them back through. Unstarted, so a test
        /// that needs a session says so.
        fn loaded() -> (Engine<FakeSeamTypes>, FakeDevice, EventStream) {
            let (engine, events, device) = engine_over(ApiBaseUrl::offline());
            block_on(async {
                let floors = &device.floor_store;
                floors.raise_epoch_floor(b"scope", 4).await.unwrap();
                floors.raise_sequence_floor(b"name", 9).await.unwrap();
                let staging = &device.staging_store;
                staging.enqueue_op(b"queued-op").await.unwrap();
                staging.put_staged_bytes(b"key", b"staged").await.unwrap();
                device.snapshot_cache.put(b"key", b"sealed").await.unwrap();
                device
                    .credential_store
                    .store_refresh_token(b"refresh")
                    .await
                    .unwrap();
            });
            (engine, device, events)
        }

        /// The same, with a live session over it.
        fn started_and_loaded() -> (Engine<FakeSeamTypes>, FakeDevice, EventStream) {
            let (mut engine, device, events) = loaded();
            block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
            (engine, device, events)
        }

        #[test]
        fn forgetting_erases_every_durable_seam() {
            let (mut engine, device, _events) = started_and_loaded();

            assert_eq!(
                block_on(engine.command(Command::ForgetDevice)),
                Ok(CommandOutcome::Done)
            );

            block_on(async {
                assert_eq!(
                    device.floor_store.epoch_floor(b"scope").await.unwrap(),
                    None
                );
                assert_eq!(
                    device.floor_store.sequence_floor(b"name").await.unwrap(),
                    None
                );
                assert!(device.staging_store.queued_ops().await.unwrap().is_empty());
                assert!(device.staging_store.staged_keys().await.unwrap().is_empty());
                assert_eq!(device.snapshot_cache.get(b"key").await.unwrap(), None);
                assert_eq!(
                    device.credential_store.load_refresh_token().await.unwrap(),
                    None
                );
            });
        }

        /// A forget latches the instance terminal, so no later caller can
        /// re-seed the stores it emptied; a fresh engine is the only way back.
        /// The passes it still has in flight are bound by the same latch
        /// through [`LiveSeam`].
        #[test]
        fn a_forgotten_engine_serves_nothing_and_cannot_be_restarted() {
            let (mut engine, _device, _events) = started_and_loaded();
            let root = engine.root();

            block_on(engine.command(Command::ForgetDevice)).unwrap();

            assert_eq!(
                block_on(engine.command(Command::ManualRefresh)),
                Err(EngineError::Forgotten)
            );
            // Every public read, not just the gated ones: `shut_down` leaves the
            // render and the session standing, so a reader that consults its own
            // field instead of the shared gate keeps answering after the sweep.
            assert!(matches!(
                block_on(engine.view()),
                Err(EngineError::Forgotten)
            ));
            assert!(matches!(
                block_on(engine.snapshot(root)),
                Err(EngineError::Forgotten)
            ));
            assert!(matches!(
                block_on(engine.sharing(root)),
                Err(EngineError::Forgotten)
            ));
            assert!(matches!(
                block_on(engine.received_shares()),
                Err(EngineError::Forgotten)
            ));
            assert!(matches!(
                block_on(engine.rendered_version_cid(root)),
                Err(EngineError::Forgotten)
            ));
            assert!(matches!(
                block_on(engine.siwe_challenge()),
                Err(EngineError::Forgotten)
            ));
            assert_eq!(
                block_on(engine.start(LoginSecret::new(vec![7u8; 32]))),
                Err(EngineError::Forgotten)
            );
        }

        /// The recovery case the affordance exists for: a device whose cold
        /// start fails closed never reaches a session, so a forget gated on one
        /// would leave clearing the browser's site data as the only way out.
        #[test]
        fn an_engine_that_never_started_can_still_be_forgotten() {
            let (mut engine, device, _events) = loaded();

            assert_eq!(
                block_on(engine.command(Command::ForgetDevice)),
                Ok(CommandOutcome::Done)
            );

            block_on(async {
                assert_eq!(
                    device.floor_store.epoch_floor(b"scope").await.unwrap(),
                    None
                );
                assert!(device.staging_store.queued_ops().await.unwrap().is_empty());
                assert_eq!(device.snapshot_cache.get(b"key").await.unwrap(), None);
            });
        }

        /// The revoke is the only leg that needs the network, and on web the
        /// refresh credential is an HTTP-only cookie no seam can reach — so an
        /// unauthenticated `/auth/logout` the API rejects would leave the
        /// device's server session live after it reported itself forgotten.
        #[test]
        fn the_revoke_presents_the_session_bearer_the_erase_then_seals() {
            let (mut engine, _events, device) =
                engine_over(ApiBaseUrl::parse("http://api.test").expect("a configured base"));
            device.http.enqueue_response(json_response(
                200,
                json!({ "challenge": LOGIN_CHALLENGE_FIXTURE, "expiresAt": "2099-01-01T00:00:00Z" }),
            ));
            device.http.enqueue_response(json_response(
                200,
                json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "gatewayToken": "gw-a", "isNewUser": true }),
            ));
            serve_provisioning(&device);
            block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).expect("start logs in");
            let session_bearer = engine.session_bearer.clone();

            block_on(engine.command(Command::ForgetDevice)).unwrap();

            let revoke = device
                .http
                .requests()
                .into_iter()
                .rfind(|request| request.url.ends_with("/auth/logout"))
                .expect("the erase revokes the server session");
            assert!(
                revoke
                    .headers
                    .iter()
                    .any(|(name, value)| name.eq_ignore_ascii_case(AUTHORIZATION)
                        && value == "Bearer jwt-1"),
                "{revoke:?}"
            );
            assert!(
                !session_bearer.is_held(),
                "the bearer the revoke presented is sealed behind it"
            );
        }

        /// A refusing seam must not spare the rest, and must still reach the
        /// caller: the erase is security-relevant, so a silent partial is the
        /// one outcome neither half may produce.
        #[test]
        fn a_seam_that_refuses_the_erase_does_not_spare_the_others() {
            let (mut engine, device, _events) = started_and_loaded();
            device.floor_store.fail_clear();

            assert!(matches!(
                block_on(engine.command(Command::ForgetDevice)),
                Err(EngineError::Seam { .. })
            ));

            block_on(async {
                assert!(device.staging_store.queued_ops().await.unwrap().is_empty());
                assert_eq!(device.snapshot_cache.get(b"key").await.unwrap(), None);
                assert_eq!(
                    device.credential_store.load_refresh_token().await.unwrap(),
                    None,
                    "a seam past the refusal is erased too"
                );
                assert_eq!(
                    device.floor_store.epoch_floor(b"scope").await.unwrap(),
                    Some(4),
                    "only the seam that refused is left standing"
                );
            });
        }
    }

    /// A wired arm refuses with its own typed verdict, never by falling through
    /// the catch-all, and refuses before it reaches any key material.
    #[test]
    fn a_rotation_arm_refuses_a_node_that_names_no_scope_root() {
        let (mut engine, _events) = started();
        let node = NodeId([1; 16]);
        for (command, check) in [
            (
                Command::RotateNow { node },
                "rotate-target-is-not-a-scope-root",
            ),
            (
                Command::Downgrade {
                    node,
                    recipient_identity_public_key: vec![2u8; 33],
                },
                "downgrade-needs-a-pre-wave-reseal",
            ),
        ] {
            let name = command.name();
            assert_eq!(
                block_on(engine.command(command)),
                Err(EngineError::UnsupportedTarget { check }),
                "`{name}` must refuse with its own typed verdict",
            );
        }
    }

    /// A revoke names a recipient before it names a scope: the contact book is
    /// local, so a recipient this vault never imported is refused without a
    /// resolve — and without deriving a blinded tag against an unverified key.
    #[test]
    fn a_revoke_refuses_an_unimported_recipient_before_it_resolves_anything() {
        let (mut engine, _events) = started();
        assert_eq!(
            block_on(engine.command(Command::Revoke {
                node: NodeId([1; 16]),
                recipient_identity_public_key: vec![2u8; 33],
            })),
            Err(EngineError::MalformedInput {
                check: "recipient-not-imported"
            }),
        );
    }

    /// A read grant mints a fresh scope at the granted folder; a write grant
    /// additionally owes a write-scope cut this build does not author, so it is
    /// a typed refusal rather than a half-done grant.
    #[test]
    fn a_write_grant_is_refused_before_anything_is_minted() {
        let (mut engine, _events) = started();
        assert_eq!(
            block_on(engine.command(Command::Grant {
                node: NodeId([1; 16]),
                recipient_identity_public_key: vec![2u8; 33],
                permission: Permission::Write,
            })),
            Err(EngineError::UnsupportedTarget {
                check: "write-grants-need-a-write-scope-cut"
            }),
        );
    }

    /// A share pointer the inbox does not hold cannot be accepted: the accept
    /// acks by transport id, so there would be nothing to ack and the item would
    /// redeliver forever.
    #[test]
    fn a_share_pointer_off_the_inbox_is_refused() {
        let (mut engine, _events) = started();
        assert_eq!(
            block_on(engine.command(Command::AcceptShare {
                sealed_share_pointer: b"not-a-sealed-item".to_vec(),
            })),
            Err(EngineError::MalformedInput {
                check: "share-pointer-is-not-on-this-inbox"
            }),
        );
    }

    #[test]
    fn a_blank_api_base_url_is_unrepresentable() {
        for blank in ["", "   ", "\t\n"] {
            assert_eq!(
                ApiBaseUrl::parse(blank),
                Err(BlankApiBaseUrl),
                "a blank base is refused: {blank:?}"
            );
        }
        assert_eq!(
            ApiBaseUrl::parse("  http://api.test  ")
                .expect("a configured base")
                .configured(),
            Some("http://api.test"),
            "surrounding whitespace is trimmed, not carried into request URLs"
        );
    }

    /// The stream ceiling bounds live pinned versions, and an in-flight
    /// `read_stream` holds its `Rc` past the map removal `close_stream` does —
    /// so the slot must ride the pin, not the table entry.
    #[test]
    fn a_pinned_stream_holds_its_slot_past_the_map_removal() {
        let mut streams = LiveStreams::default();
        let handle = StreamHandle(1);
        streams.open.insert(
            handle,
            Rc::new(LiveStream {
                version: Version::new(vec![0u8; 36], [0u8; 32], 0, 0),
                manifest: RootManifest {
                    chunk_size: 16,
                    size: 0,
                    leaf_cids: Vec::new().into_boxed_slice(),
                },
                _slot: StreamSlot::acquire(&streams.live).expect("a free slot"),
            }),
        );

        let in_flight = streams.open.get(&handle).map(Rc::clone).expect("open");
        streams.open.remove(&handle);
        assert_eq!(
            streams.live.get(),
            1,
            "the in-flight read still pins a version and its content key"
        );
        drop(in_flight);
        assert_eq!(streams.live.get(), 0, "the last holder released the slot");
    }

    /// The cache's retention rule, at the mechanism: a seed lives exactly as
    /// long as the durable floor stays at or below its stamp, and an unreadable
    /// floor holds nothing.
    #[test]
    fn a_cached_seed_lives_only_while_the_floor_stays_at_its_stamp() {
        use crate::testkit::fakes::InMemoryFloorStore;

        const SCOPE: [u8; 16] = [4u8; 16];
        let floors = InMemoryFloorStore::default();
        let cell = RefCell::new(ScopeSeeds::new());
        block_on(async {
            floors.raise_epoch_floor(&SCOPE, 5).await.unwrap();
            let stamp = refresh_seed_floor(&floors, &cell, &SCOPE, SeedFloor::Read).await;
            assert_eq!(stamp, Some(5));
            deposit_seed(&cell, SCOPE, Zeroizing::new([3u8; 32]), stamp);

            refresh_seed_floor(&floors, &cell, &SCOPE, SeedFloor::Read).await;
            assert!(
                cell.borrow().contains_key(&SCOPE),
                "an unmoved floor keeps the seed"
            );

            floors.raise_epoch_floor(&SCOPE, 6).await.unwrap();
            refresh_seed_floor(&floors, &cell, &SCOPE, SeedFloor::Read).await;
            assert!(
                !cell.borrow().contains_key(&SCOPE),
                "the rise past the stamp revokes it"
            );

            // A stamp the caller could not read holds nothing, so a floor-store
            // failure never leaves an unprovable seed resident.
            deposit_seed(&cell, SCOPE, Zeroizing::new([3u8; 32]), None);
            assert!(!cell.borrow().contains_key(&SCOPE));
        });
    }

    /// A floor store whose reads fail — the seam-outage arm of
    /// [`refresh_seed_floor`], which no in-memory fake exercises.
    struct UnreadableFloors;

    impl FloorStore for UnreadableFloors {
        async fn epoch_floor(&self, _scope_id: &[u8]) -> SeamResult<Option<u64>> {
            Err(SeamError::new("floor store unavailable"))
        }

        async fn raise_epoch_floor(&self, _scope_id: &[u8], _epoch: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store unavailable"))
        }

        async fn sequence_floor(&self, _ipns_name: &[u8]) -> SeamResult<Option<u64>> {
            Err(SeamError::new("floor store unavailable"))
        }

        async fn raise_sequence_floor(&self, _ipns_name: &[u8], _sequence: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store unavailable"))
        }

        async fn clear(&self) -> SeamResult<()> {
            Err(SeamError::new("floor store unavailable"))
        }
    }

    /// A floor that cannot be read evicts: a seed whose currency cannot be
    /// established is dropped, not trusted for the rest of the session.
    /// Stamped far above any floor either arm could return, so only the read
    /// failure can account for the eviction.
    #[test]
    fn an_unreadable_floor_evicts_the_cached_seed() {
        const SCOPE: [u8; 16] = [5u8; 16];
        let cell = RefCell::new(ScopeSeeds::new());
        block_on(async {
            for which in [SeedFloor::Read, SeedFloor::Write] {
                cell.borrow_mut().insert(
                    SCOPE,
                    CachedSeed {
                        seed: Zeroizing::new([3u8; 32]),
                        floor: u64::MAX,
                    },
                );
                let stamp = refresh_seed_floor(&UnreadableFloors, &cell, &SCOPE, which).await;
                assert_eq!(stamp, None, "an unread floor stamps nothing");
                assert!(
                    !cell.borrow().contains_key(&SCOPE),
                    "the seed goes with the floor that could not vouch for it"
                );
            }
        });
    }

    #[test]
    fn stream_slots_are_bounded_and_reusable() {
        let live = Rc::new(Cell::new(0usize));
        let held: Vec<StreamSlot> = (0..MAX_OPEN_STREAMS)
            .map(|open| StreamSlot::acquire(&live).unwrap_or_else(|| panic!("slot {open}")))
            .collect();
        assert!(StreamSlot::acquire(&live).is_none(), "the ceiling is met");
        drop(held);
        assert!(
            StreamSlot::acquire(&live).is_some(),
            "released slots are reusable"
        );
    }

    // --- snapshot read surface ---

    mod snapshot_read {
        use super::*;

        use cipherbox_core::seal::{ChildRef, NodeKind as CoreNodeKind, PreservedFields, ReadBody};

        use crate::gate::Adopted;
        use crate::net::{ResolveOutcome, refresh_base_from_outcome};

        /// A gate-passing adopted root folder with the given children, mirroring
        /// what a live resolve repaints the base with.
        fn adopted_folder(children: Vec<ChildRef>) -> Adopted {
            Adopted {
                read_body: ReadBody::Folder {
                    created_at: 0,
                    modified_at: 456,
                    children,
                    unknown: PreservedFields::new(),
                },
                sequence: 2,
                epoch: 1,
            }
        }

        fn child_ref(id: u8, name: &str, kind: CoreNodeKind) -> ChildRef {
            ChildRef {
                id: [id; 16],
                name: name.to_string(),
                ipns_name: vec![id],
                kind,
                link_counter: 1,
                unknown: PreservedFields::new(),
            }
        }

        #[test]
        fn snapshot_lists_base_children_with_no_pending_flags() {
            let (engine, _events) = started();
            let root = engine.root();
            refresh_base_from_outcome(
                &engine.snapshot,
                root,
                &ResolveOutcome::Adopted(adopted_folder(vec![
                    child_ref(1, "a", CoreNodeKind::Folder),
                    child_ref(2, "b.txt", CoreNodeKind::File),
                ])),
            );

            let view = block_on(engine.snapshot(root)).unwrap();
            assert_eq!(view.root, root);
            assert_eq!(view.folder, root);
            let by: Vec<(NodeId, &str, NodeKind, PendingClass, Option<u64>)> = view
                .children
                .iter()
                .map(|c| (c.id, c.name.as_str(), c.kind, c.pending, c.content_version))
                .collect();
            assert_eq!(
                by,
                vec![
                    (
                        NodeId([1; 16]),
                        "a",
                        NodeKind::Folder,
                        PendingClass::None,
                        None
                    ),
                    (
                        NodeId([2; 16]),
                        "b.txt",
                        NodeKind::File,
                        PendingClass::None,
                        None
                    ),
                ],
                "base children render id-sorted, none pending, no version count"
            );
            assert!(view.children.iter().all(|c| !c.dead_letter));
            assert!(view.dead_letters.is_empty());
            assert_eq!(view.retained_records, 0);
            assert!(view.ancestors.is_empty(), "the root has no ancestors");
            assert!(view.folder_name.is_empty(), "the root has no name");
        }

        #[test]
        fn staged_create_appears_pending_as_a_metadata_op() {
            let (mut engine, _events) = started();
            let root = engine.root();
            create(&mut engine, root, "notes.txt", NodeKind::File);

            let view = block_on(engine.snapshot(root)).unwrap();
            assert_eq!(view.children.len(), 1);
            assert_eq!(view.children[0].name, "notes.txt");
            assert_eq!(
                view.children[0].pending,
                PendingClass::Metadata,
                "a contentless create queues a metadata mutation"
            );
            assert!(!view.children[0].dead_letter);
        }

        #[test]
        fn a_queued_content_write_outranks_a_queued_metadata_op() {
            let (mut engine, _events) = started();
            let root = engine.root();
            create(&mut engine, root, "notes.txt", NodeKind::File);
            let node = block_on(engine.snapshot(root)).unwrap().children[0].id;

            write_file(&mut engine, WriteTarget::Version { node }, b"bytes").unwrap();

            let view = block_on(engine.snapshot(root)).unwrap();
            assert_eq!(view.children[0].pending, PendingClass::Content);
        }

        #[test]
        fn a_foreign_queue_entry_is_invisible_but_counted() {
            let (engine, _events) = started();
            let root = engine.root();
            let stranger = cipherbox_core::suite::x25519::X25519Secret::from_scalar([9; 32]);
            let theirs = crate::sync::record::encode_op_record(
                RecordSeal {
                    owner_enc_secret: &stranger,
                    ephemeral_scalar: Zeroizing::new([3; 32]),
                },
                &Op::create(
                    NodeId([7; 16]),
                    root,
                    "theirs.txt",
                    NewNode::File { content: None },
                    1,
                    crate::seams::UnixMillis(1),
                ),
            )
            .unwrap();
            block_on(engine.seams.staging_store.enqueue_op(&theirs)).unwrap();

            let view = block_on(engine.snapshot(root)).unwrap();
            assert!(
                view.children.is_empty(),
                "another account's op never renders"
            );
            assert!(view.dead_letters.is_empty(), "and never dead-letters");
            assert_eq!(
                view.retained_records, 1,
                "but the count says the device is not empty"
            );
        }

        /// Ops enqueue and drain through the staging seam, not through the
        /// engine's command path, so the memoized queue scan has to key on the
        /// durable queue itself.
        #[test]
        fn a_record_enqueued_behind_the_engines_back_renders_on_the_next_read() {
            let (mut engine, _events) = started();
            let root = engine.root();
            create(&mut engine, root, "mine.txt", NodeKind::File);
            // Prime the memo with a scan that predates the enqueue below.
            assert_eq!(block_on(engine.snapshot(root)).unwrap().children.len(), 1);

            let ours = crate::sync::record::encode_op_record(
                RecordSeal {
                    owner_enc_secret: engine.session.as_ref().expect("started").enc_subkey(),
                    ephemeral_scalar: Zeroizing::new([0x2B; 32]),
                },
                &Op::create(
                    NodeId([8; 16]),
                    root,
                    "out-of-band.txt",
                    NewNode::File { content: None },
                    1,
                    crate::seams::UnixMillis(1),
                ),
            )
            .unwrap();
            block_on(engine.seams.staging_store.enqueue_op(&ours)).unwrap();

            let names: Vec<String> = block_on(engine.snapshot(root))
                .unwrap()
                .children
                .into_iter()
                .map(|child| child.name)
                .collect();
            assert_eq!(names, vec!["out-of-band.txt", "mine.txt"]);
        }

        #[test]
        fn breadcrumbs_walk_nearest_first_to_the_root() {
            let (mut engine, _events) = started();
            let root = engine.root();
            create(&mut engine, root, "dir", NodeKind::Folder);
            let dir = block_on(engine.view())
                .unwrap()
                .lookup(root, "dir")
                .unwrap()
                .id;
            create(&mut engine, dir, "sub", NodeKind::Folder);
            let sub = block_on(engine.view())
                .unwrap()
                .lookup(dir, "sub")
                .unwrap()
                .id;

            let view = block_on(engine.snapshot(sub)).unwrap();
            assert_eq!(
                view.ancestors,
                vec![
                    Breadcrumb {
                        id: dir,
                        name: "dir".to_owned(),
                    },
                    Breadcrumb {
                        id: root,
                        name: String::new(),
                    },
                ],
                "nearest first, ending at the root"
            );
            assert_eq!(
                view.folder_name, "sub",
                "the listed folder names itself; the trail starts at its parent"
            );
        }

        #[test]
        fn unknown_folder_is_unknown_node() {
            let (engine, _events) = started();
            assert_eq!(
                block_on(engine.snapshot(NodeId([9; 16]))),
                Err(EngineError::UnknownNode)
            );
        }

        #[test]
        fn file_node_is_not_a_folder() {
            let (mut engine, _events) = started();
            let root = engine.root();
            create(&mut engine, root, "f.txt", NodeKind::File);
            let file = block_on(engine.view())
                .unwrap()
                .lookup(root, "f.txt")
                .unwrap()
                .id;
            assert_eq!(
                block_on(engine.snapshot(file)),
                Err(EngineError::NotAFolder)
            );
        }

        #[test]
        fn snapshot_before_start_returns_not_started() {
            let (engine, _events) = new_engine();
            assert_eq!(
                block_on(engine.snapshot(NodeId([0; 16]))),
                Err(EngineError::NotStarted)
            );
        }
    }

    // --- cold-start data path composition ---

    mod cold_start {
        use super::*;

        use std::sync::{Arc, Mutex};

        use cipherbox_core::ipns::{IpnsName, IpnsRecord};
        use cipherbox_core::kdf;
        use cipherbox_core::payload::RepointObject;
        use cipherbox_core::seal::{PreservedFields, ReadBody};
        use cipherbox_core::suite::ecdsa::EcdsaSigner;
        use cipherbox_core::suite::ed25519::Ed25519Signer;

        use crate::gate::Adopted;
        use crate::seams::{EndpointId, OpId, SeamResult, StagingStore};
        use crate::sync::boot::RootResolve;
        use crate::sync::pointer::{SessionRole, seal_repoint, vault_pointer_name};
        use crate::testkit::FakeDevice;

        const SECRET: &[u8] = b"facade-cold-start-secret-fixture";
        const ROOT_SCOPE: [u8; 16] = [0u8; 16];
        const VERSION: u64 = 1;

        fn owner() -> EcdsaSigner {
            EcdsaSigner::from_scalar(&[3u8; 32]).expect("valid scalar")
        }

        fn root_signer() -> Ed25519Signer {
            kdf::ipns_keypair(&[9u8; 32])
        }

        fn root_name() -> IpnsName {
            IpnsName::from_public_key(&root_signer().verifying_key())
        }

        /// A scripted vault-pointer network keyed by the login secret's indexed
        /// names.
        #[derive(Clone, Default)]
        struct ScriptedPointers {
            blocks: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>>,
        }

        impl ScriptedPointers {
            fn seal_index(&self, index: u64, min_read_epoch: u64, write_epoch: u64) {
                let read_key =
                    kdf::pointer_read_key(kdf::owner_pointer_seed(SECRET).as_bytes(), &ROOT_SCOPE);
                let object = RepointObject {
                    scope_id: ROOT_SCOPE,
                    current_root: root_name(),
                    write_epoch,
                    min_read_epoch,
                    prev_root: None,
                };
                let mut entropy = SeededEntropy::new(index);
                let block = seal_repoint(
                    SessionRole::Owner,
                    &mut entropy,
                    read_key.as_bytes(),
                    VERSION,
                    &owner(),
                    &object,
                )
                .unwrap();
                self.blocks
                    .lock()
                    .unwrap()
                    .insert(vault_pointer_name(SECRET, index).as_str().to_owned(), block);
            }
        }

        impl PointerFetch for ScriptedPointers {
            async fn fetch(&self, name: &IpnsName) -> SeamResult<Option<Vec<u8>>> {
                Ok(self.blocks.lock().unwrap().get(name.as_str()).cloned())
            }
        }

        #[derive(Clone)]
        struct AdoptingAdopter;

        impl Adopter for AdoptingAdopter {
            async fn adopt(
                &self,
                _name: &IpnsName,
                _record_bytes: &[u8],
            ) -> Result<crate::net::AdoptOutcome, crate::gate::GateError> {
                Ok(crate::net::AdoptOutcome {
                    adopted: Adopted {
                        read_body: ReadBody::Folder {
                            created_at: 0,
                            modified_at: 0,
                            children: Vec::new(),
                            unknown: PreservedFields::new(),
                        },
                        sequence: 1,
                        epoch: 1,
                    },
                    write_scope_seed: None,
                    node_id: [0u8; 16],
                    read_scope_seed: None,
                })
            }
        }

        /// Seed a valid signed IPNS record at the root name across the device's
        /// endpoints so the gated resolve fetches a record to adopt.
        fn seed_root_record(device: &FakeDevice) {
            let record = IpnsRecord::create_v2(
                &root_signer(),
                b"/ipfs/bafyrootmeta",
                1,
                0,
                "2099-01-01T00:00:00Z",
            )
            .marshal();
            for endpoint in [
                EndpointId::new("fake:someguy"),
                EndpointId::new("fake:public-routing"),
            ] {
                device
                    .record_store
                    .seed_record(&endpoint, root_name().as_str(), record.clone());
            }
        }

        /// A started engine on a world whose clock sits at `clock`, with a valid
        /// vault pointer and root record already published.
        fn started_at(clock: UnixMillis) -> (Engine<FakeSeamTypes>, EventStream, ScriptedPointers) {
            let world = FakeWorld::new();
            world.scheduler.advance_to(clock);
            let device = world.device(b"alice-pk");
            seed_root_record(&device);
            let (mut engine, mut events) = Engine::new(
                device.seam_set(),
                Box::new(SeededEntropy::new(42)),
                SyncTimingProfile::CI,
                ContentProfile::CI,
                StoragePolicy::CI,
                ApiBaseUrl::offline(),
                GatewayConfig::disabled(),
            );
            block_on(engine.start(LoginSecret::new(SECRET.to_vec()))).unwrap();
            // `start` runs its own cold start over the (unseeded) record store: an
            // empty vault-pointer chain paints once. These tests then drive
            // `cold_start_data_path` directly against the scripted pointers, so
            // drain that incidental first paint to isolate the driven stream.
            assert_eq!(block_on(events.next()), Some(Event::SnapshotUpdated));
            let pointers = ScriptedPointers::default();
            pointers.seal_index(0, 1, 1);
            pointers.seal_index(1, 3, 2);
            (engine, events, pointers)
        }

        fn drive(
            engine: &mut Engine<FakeSeamTypes>,
            pointers: &ScriptedPointers,
        ) -> ColdStartOutcome {
            block_on(engine.cold_start_data_path(
                pointers,
                &AdoptingAdopter,
                &owner().verifying_key(),
                ROOT_SCOPE,
                VERSION,
                NodeId([0xAB; 16]),
            ))
            .unwrap()
        }

        #[test]
        fn runs_the_full_sequence_and_emits_on_the_event_stream() {
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
            let outcome = drive(&mut engine, &pointers);

            assert_eq!(
                outcome.vault_pointer.unwrap().index,
                1,
                "highest valid index"
            );
            assert_eq!(outcome.root_resolve, Some(RootResolve::Adopted));
            // Floors seeded from the owner-vouched re-point.
            assert_eq!(
                block_on(crate::gate::floor::read_epoch_floor(
                    &engine.seams.floor_store,
                    &ROOT_SCOPE
                ))
                .unwrap(),
                Some(3)
            );
            // The first snapshot event reached the host's stream.
            assert_eq!(block_on(events.next()), Some(Event::SnapshotUpdated));
        }

        #[test]
        fn reads_no_clock_two_engines_on_independent_clocks_agree() {
            let (mut a, _ea, pa) = started_at(UnixMillis(0));
            let (mut b, _eb, pb) = started_at(UnixMillis(5_000_000));
            // The data path is a pure function of the seams + session: the two
            // outcomes match despite the engines' clocks sitting far apart.
            assert_eq!(drive(&mut a, &pa), drive(&mut b, &pb));
        }

        /// A gate-passing `Adopted` folder carrying one child — the projected
        /// material a newer live resolve folds into the shared base cell.
        fn adopted_with_child(child_id: [u8; 16], name: &str) -> Adopted {
            use cipherbox_core::seal::{ChildRef, NodeKind as CoreNodeKind, PreservedFields};
            Adopted {
                read_body: ReadBody::Folder {
                    created_at: 0,
                    modified_at: 0,
                    children: vec![ChildRef {
                        id: child_id,
                        name: name.to_string(),
                        ipns_name: vec![1],
                        kind: CoreNodeKind::File,
                        link_counter: 1,
                        unknown: PreservedFields::new(),
                    }],
                    unknown: PreservedFields::new(),
                },
                sequence: 2,
                epoch: 1,
            }
        }

        #[test]
        fn a_newer_adopted_tick_repaints_the_view_and_emits() {
            use crate::net::{ResolveOutcome, refresh_base_from_outcome};

            let (engine, mut events, _pointers) = started_at(UnixMillis(123_456));
            let root = engine.root();

            // One resolve-tick pass over a gate-passing newer `Adopted`: fold it
            // into the shared base cell and emit, exactly as the tick loop does.
            assert!(refresh_base_from_outcome(
                &engine.snapshot,
                root,
                &ResolveOutcome::Adopted(adopted_with_child([0xC1; 16], "live.txt")),
            ));
            let _ = engine.events.unbounded_send(Event::SnapshotUpdated);

            let view = block_on(engine.view()).unwrap();
            assert!(
                view.lookup(root, "live.txt").is_some(),
                "the view reflects the newly adopted child"
            );
            assert_eq!(view.children(root).len(), 1);
            assert_eq!(block_on(events.next()), Some(Event::SnapshotUpdated));
        }

        #[test]
        fn tick_repaint_is_clock_independent() {
            use crate::net::{ResolveOutcome, refresh_base_from_outcome};

            let (a, _ea, _pa) = started_at(UnixMillis(0));
            let (b, _eb, _pb) = started_at(UnixMillis(5_000_000));
            let root = a.root();
            assert_eq!(root, b.root());

            refresh_base_from_outcome(
                &a.snapshot,
                root,
                &ResolveOutcome::Adopted(adopted_with_child([0xD2; 16], "clk.txt")),
            );
            refresh_base_from_outcome(
                &b.snapshot,
                root,
                &ResolveOutcome::Adopted(adopted_with_child([0xD2; 16], "clk.txt")),
            );

            // Clock-independent: the two repainted bases are byte-identical, and
            // both render the same post-pass view.
            assert_eq!(*a.snapshot.borrow(), *b.snapshot.borrow());
            let va = block_on(a.view()).unwrap();
            let vb = block_on(b.view()).unwrap();
            assert!(va.lookup(root, "clk.txt").is_some());
            assert_eq!(va.children(root).len(), vb.children(root).len());
        }

        #[test]
        fn before_start_returns_not_started_not_panic() {
            let (engine, _events) = new_engine();
            assert!(engine.session().is_none(), "no identity before start");
            let out = block_on(engine.cold_start_data_path(
                &ScriptedPointers::default(),
                &AdoptingAdopter,
                &owner().verifying_key(),
                ROOT_SCOPE,
                VERSION,
                NodeId([0xAB; 16]),
            ));
            assert_eq!(out, Err(ColdStartError::NotStarted));
        }

        #[test]
        fn unstarted_engine_reports_not_started_even_when_staging_store_fails() {
            // Precondition guard must run before the staging read, so a failing
            // seam on an unstarted engine still classifies as `NotStarted`, not
            // a retryable `Seam`.
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            device.staging_store.fail_queued_ops();
            let (engine, _events) = Engine::new(
                device.seam_set(),
                Box::new(SeededEntropy::new(42)),
                SyncTimingProfile::CI,
                ContentProfile::CI,
                StoragePolicy::CI,
                ApiBaseUrl::offline(),
                GatewayConfig::disabled(),
            );
            assert!(engine.session().is_none(), "no identity before start");
            let out = block_on(engine.cold_start_data_path(
                &ScriptedPointers::default(),
                &AdoptingAdopter,
                &owner().verifying_key(),
                ROOT_SCOPE,
                VERSION,
                NodeId([0xAB; 16]),
            ));
            assert_eq!(out, Err(ColdStartError::NotStarted));
        }

        #[test]
        fn undecodable_queue_entry_surfaces_as_dead_letter_on_cold_start() {
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
            // A corrupt op record whose header does not even read.
            let op_id = block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op"))
                .expect("enqueue");
            assert_eq!(op_id, OpId(1));

            drive(&mut engine, &pointers);

            // The dead-letter surfaces on the host stream ahead of the first paint.
            assert_eq!(
                block_on(events.next()),
                Some(Event::DeadLetter {
                    op_id: OpId(1),
                    reason: DeadLetterReason::Undecodable
                })
            );
            assert_eq!(block_on(events.next()), Some(Event::SnapshotUpdated));
            // The op record was dropped from the durable queue.
            assert!(
                block_on(engine.seams.staging_store.queued_ops())
                    .unwrap()
                    .is_empty(),
                "the dead-lettered op is removed from the durable queue"
            );
        }

        #[test]
        fn another_accounts_queued_record_is_invisible_and_survives_cold_start() {
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
            // A well-formed record sealed by a different identity — the shape a
            // second account meets on a shared browser profile.
            let stranger = cipherbox_core::suite::x25519::X25519Secret::from_scalar([0xC7; 32]);
            let theirs = crate::sync::record::encode_op_record(
                RecordSeal {
                    owner_enc_secret: &stranger,
                    ephemeral_scalar: Zeroizing::new([0x5A; 32]),
                },
                &Op::rename(NodeId([9; 16]), "theirs.txt", 1, UnixMillis(1)),
            )
            .expect("seal");
            block_on(engine.seams.staging_store.enqueue_op(&theirs)).expect("enqueue");

            drive(&mut engine, &pointers);

            assert_eq!(
                block_on(events.next()),
                Some(Event::SnapshotUpdated),
                "no dead letter is raised for a record this account cannot see"
            );
            let view = block_on(engine.snapshot(engine.root())).unwrap();
            assert!(view.dead_letters.is_empty(), "never surfaced");
            assert!(
                view.children.iter().all(|c| c.name != "theirs.txt"),
                "never replayed into the render"
            );
            assert_eq!(
                block_on(engine.seams.staging_store.queued_ops()).unwrap(),
                vec![(OpId(1), theirs)],
                "never removed — deleting it would destroy that account's offline work"
            );
        }

        #[test]
        fn retained_dead_letter_surfaces_in_the_snapshot_view() {
            let (mut engine, _events, pointers) = started_at(UnixMillis(123_456));
            block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op")).expect("enqueue");

            drive(&mut engine, &pointers);

            let view = block_on(engine.snapshot(engine.root())).unwrap();
            assert_eq!(
                view.dead_letters,
                vec![DeadLetter {
                    op_id: OpId(1),
                    reason: DeadLetterReason::Undecodable
                }],
                "the retained dead letter stays on the read surface after removal \
                 from the durable queue"
            );
            assert!(
                view.children.iter().all(|c| !c.dead_letter),
                "an undecodable entry maps to no node"
            );
        }

        #[test]
        fn dead_lettered_entry_is_not_re_emitted_on_a_second_boot() {
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
            block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op")).expect("enqueue");

            // First boot: surfaces the dead-letter, then paints.
            drive(&mut engine, &pointers);
            assert_eq!(
                block_on(events.next()),
                Some(Event::DeadLetter {
                    op_id: OpId(1),
                    reason: DeadLetterReason::Undecodable
                })
            );
            assert_eq!(block_on(events.next()), Some(Event::SnapshotUpdated));

            // Second boot over the same durable store: the corrupt entry is gone,
            // so only the paint event fires — no re-emitted dead-letter.
            drive(&mut engine, &pointers);
            assert_eq!(block_on(events.next()), Some(Event::SnapshotUpdated));
        }

        #[test]
        fn dropped_receiver_preserves_unsurfaced_dead_letter_across_a_boot() {
            let (mut engine, events, pointers) = started_at(UnixMillis(123_456));
            block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op")).expect("enqueue");
            // Receiver gone mid-teardown: the `DeadLetter` send fails, so the
            // durable removal is gated off and the entry survives for next boot.
            drop(events);

            drive(&mut engine, &pointers);

            assert_eq!(
                block_on(engine.seams.staging_store.queued_ops())
                    .unwrap()
                    .len(),
                1,
                "an unsurfaced dead-letter is retained when the send fails"
            );
        }

        #[test]
        fn remove_op_failure_after_send_re_surfaces_the_dead_letter_next_boot() {
            let (engine, mut events, pointers) = started_at(UnixMillis(123_456));
            block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op")).expect("enqueue");
            // Send lands in the buffer but the durable removal fails: the gated
            // `?` aborts cold-start with `Seam` before the paint, leaving the op
            // queued. The receiver stays alive, so the `DeadLetter` is observable.
            engine.seams.staging_store.fail_remove_op();

            let first = block_on(engine.cold_start_data_path(
                &pointers,
                &AdoptingAdopter,
                &owner().verifying_key(),
                ROOT_SCOPE,
                VERSION,
                NodeId([0xAB; 16]),
            ));
            assert!(
                matches!(first, Err(ColdStartError::Seam(_))),
                "a failed durable removal aborts cold-start as a retryable Seam error"
            );
            assert_eq!(
                block_on(events.next()),
                Some(Event::DeadLetter {
                    op_id: OpId(1),
                    reason: DeadLetterReason::Undecodable
                })
            );
            assert_eq!(
                block_on(engine.seams.staging_store.queued_ops())
                    .unwrap()
                    .len(),
                1,
                "a removal failure after a successful send retains the op"
            );

            // Next boot re-surfaces the same op_id — hosts dedup by it — proving
            // the best-effort contract holds under a partial seam failure.
            let second = block_on(engine.cold_start_data_path(
                &pointers,
                &AdoptingAdopter,
                &owner().verifying_key(),
                ROOT_SCOPE,
                VERSION,
                NodeId([0xAB; 16]),
            ));
            assert!(matches!(second, Err(ColdStartError::Seam(_))));
            assert_eq!(
                block_on(events.next()),
                Some(Event::DeadLetter {
                    op_id: OpId(1),
                    reason: DeadLetterReason::Undecodable
                })
            );
        }
    }

    // --- capstone: start() cold-start orchestration + resolve-tick driver ---

    mod capstone {
        use super::*;

        use core::task::{Context, Poll, Waker};

        use cipherbox_core::content::{compute_cid, encode_content_cid_str};
        use cipherbox_core::ipns::{IpnsName, IpnsRecord};
        use cipherbox_core::kdf;
        use cipherbox_core::payload::RepointObject;
        use cipherbox_core::seal::{
            ChildRef, NodeKind as CoreNodeKind, PreservedFields, ReadBody, encode_envelope,
            seal_read_body, set_grant_section,
        };
        use cipherbox_core::suite::ecdsa::EcdsaSigner;

        use crate::content::DAG_ROOT_CODEC;
        use crate::net::RE_PUT_INTERVAL;
        use crate::seams::{BoxedTask, EndpointId, RecordTransport};
        use crate::sync::pointer::{
            SessionRole, scope_pointer_name, scope_pointer_signer, seal_repoint, vault_pointer_name,
        };
        use crate::testkit::{
            FakeDevice, OWNER_ROOT_EPOCH as EPOCH, OWNER_ROOT_SCOPE_SEED as SCOPE_SEED,
            OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED, OwnerRootSpec, owner_root_fixture,
            poll_tasks_once,
        };

        const CAP_SECRET: [u8; 32] = [7u8; 32];
        const SCOPE: [u8; 16] = [0u8; 16];
        const ROOT: NodeId = NodeId([0u8; 16]);
        const CHILD_ID: [u8; 16] = [0x2C; 16];
        const CHILD_NAME: &str = "hello.txt";
        const TTL_NANOS: u64 = 2_000_000_000;
        const EOL: &str = "2099-01-01T00:00:00Z";

        fn owner_identity() -> EcdsaSigner {
            EcdsaSigner::from_scalar(&CAP_SECRET).expect("valid scalar")
        }

        /// The child's write-plane IPNS name (`write-seed` → `ipns-keypair`).
        fn child_name() -> IpnsName {
            let write_seed = kdf::write_seed(&WRITE_SCOPE_SEED, &CHILD_ID);
            IpnsName::from_public_key(&kdf::ipns_keypair(write_seed.as_bytes()).verifying_key())
        }

        /// The owner-root head block (one child) and its content-CID string, plus
        /// the root record's write-plane IPNS name. Keyed off `CAP_SECRET` so the
        /// engine's session-derived owner identity + enc subkey open it, and scoped
        /// to the all-zero bootstrap anchor (`SCOPE`/`ROOT`) so `start`'s cold-start
        /// scope binding matches.
        fn owner_root() -> (Vec<u8>, String, IpnsName) {
            let fx = owner_root_fixture(OwnerRootSpec {
                owner_identity: &owner_identity(),
                owner_enc: &kdf::enc_subkey(&CAP_SECRET).public(),
                scope_id: SCOPE,
                root_id: ROOT.0,
                children: vec![ChildRef {
                    id: CHILD_ID,
                    name: CHILD_NAME.into(),
                    ipns_name: child_name().as_str().as_bytes().to_vec(),
                    kind: CoreNodeKind::File,
                    link_counter: 1,
                    unknown: PreservedFields::new(),
                }],
                child_scope_index: Vec::new(),
                parent_node_seed: None,
                // At the read epoch (write plane == read plane here), so the
                // cold-seeded write floor opens it and the owner recovers its
                // write-scope seed for the held-set renewal signer.
                owner_write_blob_epoch: Some(EPOCH),
                write_history_link: Vec::new(),
                grants: Vec::new(),
            });
            (fx.head_block, fx.head_cid_str, fx.name)
        }

        /// A root record published at `node_id`'s derived write name, signed by
        /// that name's own key — the shape a write rotation moves a root into.
        fn root_record_at_node(node_id: [u8; 16], head_cid_str: &str, sequence: u64) -> Vec<u8> {
            let write_seed = kdf::write_seed(&WRITE_SCOPE_SEED, &node_id);
            let signer = kdf::ipns_keypair(write_seed.as_bytes());
            let value = format!("/ipfs/{head_cid_str}");
            IpnsRecord::create_v2(&signer, value.as_bytes(), sequence, TTL_NANOS, EOL).marshal()
        }

        fn root_record(head_cid_str: &str, sequence: u64) -> Vec<u8> {
            let write_seed = kdf::write_seed(&WRITE_SCOPE_SEED, &ROOT.0);
            let signer = kdf::ipns_keypair(write_seed.as_bytes());
            let value = format!("/ipfs/{head_cid_str}");
            IpnsRecord::create_v2(&signer, value.as_bytes(), sequence, TTL_NANOS, EOL).marshal()
        }

        /// Seal + publish the owner vault pointer at index 0, its re-point naming
        /// `root_name` and vouching the read/write floors the cold-seed adopts.
        fn seed_vault_pointer(device: &FakeDevice, root_name: &IpnsName) {
            let read_key =
                kdf::pointer_read_key(kdf::owner_pointer_seed(&CAP_SECRET).as_bytes(), &SCOPE);
            let mut entropy = SeededEntropy::new(0);
            let block = seal_repoint(
                SessionRole::Owner,
                &mut entropy,
                read_key.as_bytes(),
                POINTER_PAYLOAD_VERSION,
                &owner_identity(),
                &RepointObject {
                    scope_id: SCOPE,
                    current_root: root_name.clone(),
                    write_epoch: EPOCH,
                    min_read_epoch: EPOCH,
                    prev_root: None,
                },
            )
            .unwrap();
            let record = IpnsRecord::create_v2(
                &kdf::vault_pointer_index(&CAP_SECRET, 0),
                &block,
                1,
                TTL_NANOS,
                EOL,
            )
            .marshal();
            let pointer_name = vault_pointer_name(&CAP_SECRET, 0);
            for endpoint in device.record_store.endpoints() {
                device
                    .record_store
                    .seed_record(&endpoint, pointer_name.as_str(), record.clone());
            }
        }

        fn seed_root_record_at(
            device: &FakeDevice,
            endpoint: &EndpointId,
            name: &IpnsName,
            head_cid_str: &str,
        ) {
            device
                .record_store
                .seed_record(endpoint, name.as_str(), root_record(head_cid_str, 1));
        }

        fn gateway_config() -> GatewayConfig {
            GatewayConfig {
                accelerator: Some("https://gw.test".into()),
                public_fallbacks: Vec::new(),
            }
        }

        fn head_response(head_block: &[u8]) -> HttpResponse {
            HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: head_block.to_vec(),
            }
        }

        fn engine_on(device: &FakeDevice) -> (Engine<FakeSeamTypes>, EventStream) {
            Engine::new(
                device.seam_set(),
                Box::new(SeededEntropy::new(42)),
                SyncTimingProfile::CI,
                ContentProfile::CI,
                StoragePolicy::CI,
                ApiBaseUrl::offline(),
                gateway_config(),
            )
        }

        #[test]
        fn start_with_empty_seams_is_a_graceful_noop() {
            // The regression guard: empty seams (no vault pointer, no record) leave
            // cold start an anchored-root no-op — start succeeds, no error, and the
            // base is the all-zero root with no children.
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (mut engine, _events) = engine_on(&device);
            block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec())))
                .expect("empty seams start cleanly");
            assert_eq!(engine.root(), ROOT);
            assert!(
                block_on(engine.view()).unwrap().children(ROOT).is_empty(),
                "an empty chain projects no children"
            );
        }

        #[test]
        fn start_assigns_the_projected_base_snapshot() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (head_block, head_cid, root_name) = owner_root();
            seed_vault_pointer(&device, &root_name);
            for endpoint in device.record_store.endpoints() {
                seed_root_record_at(&device, &endpoint, &root_name, &head_cid);
            }
            // The cold-start adopt fetches the head block once over the gateway.
            device.http.enqueue_response(head_response(&head_block));

            let (mut engine, _events) = engine_on(&device);
            block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec())))
                .expect("cold start adopts the owner root");

            let view = block_on(engine.view()).unwrap();
            let children = view.children(ROOT);
            assert_eq!(
                children.len(),
                1,
                "the projected base carries the root's child"
            );
            assert_eq!(children[0].id, NodeId(CHILD_ID));
            assert_eq!(children[0].name, CHILD_NAME);
            assert_eq!(children[0].kind, NodeKind::File);
        }

        #[test]
        fn start_cold_start_trust_failure_is_fail_closed() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (_head_block, head_cid, root_name) = owner_root();
            seed_vault_pointer(&device, &root_name);
            for endpoint in device.record_store.endpoints() {
                seed_root_record_at(&device, &endpoint, &root_name, &head_cid);
            }
            // The adopt fetches the head block over the gateway, but the returned
            // bytes do not hash to the record's head CID: a fail-closed trust
            // violation surfaces as `ColdStart`.
            device
                .http
                .enqueue_response(head_response(b"forged head block"));

            let (mut engine, _events) = engine_on(&device);
            let out = block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec())));

            assert!(
                matches!(out, Err(EngineError::ColdStart { .. })),
                "a forged cold-start root is a hard trust failure, not a start: {out:?}"
            );
            // Mirrors `start_login_failure_is_fail_closed`: the derived session is
            // cleared, so no key material stays resident and the engine reports
            // unstarted.
            assert!(
                engine.session().is_none(),
                "a fail-closed cold start leaves no derived session resident"
            );
            assert_eq!(
                block_on(engine.command(Command::ManualRefresh)),
                Err(EngineError::NotStarted),
                "the engine stays unstarted after a cold-start trust failure"
            );
        }

        #[test]
        fn start_is_clock_independent() {
            fn base_children(clock: UnixMillis) -> Vec<NodeAttrs> {
                let world = FakeWorld::new();
                world.scheduler.advance_to(clock);
                let device = world.device(b"alice-pk");
                let (head_block, head_cid, root_name) = owner_root();
                seed_vault_pointer(&device, &root_name);
                for endpoint in device.record_store.endpoints() {
                    seed_root_record_at(&device, &endpoint, &root_name, &head_cid);
                }
                device.http.enqueue_response(head_response(&head_block));
                let (mut engine, _events) = engine_on(&device);
                block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec()))).unwrap();
                block_on(engine.view()).unwrap().children(ROOT)
            }
            // Two engines whose virtual clocks sit far apart reach the identical
            // projected base: cold start reads no clock.
            assert_eq!(
                base_children(UnixMillis(0)),
                base_children(UnixMillis(5_000_000))
            );
        }

        #[test]
        fn resolve_tick_loop_populates_the_held_set() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (head_block, head_cid, root_name) = owner_root();
            // Vault pointer present (the root name is known and floors cold-seed),
            // but no root record at boot: cold start resolves NoUpdate, so the
            // sequence floor stays unset and the tick's later resolve is a fresh,
            // gate-passing Adopt that surfaces the owner write seed.
            seed_vault_pointer(&device, &root_name);
            let (mut engine, _events) = engine_on(&device);
            block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec()))).unwrap();
            assert!(
                engine.held_records.borrow().is_empty(),
                "nothing held until the record appears"
            );

            // The record appears; drive one resolve-tick interval.
            for endpoint in device.record_store.endpoints() {
                seed_root_record_at(&device, &endpoint, &root_name, &head_cid);
            }
            device.http.enqueue_response(head_response(&head_block));

            let mut tasks = world.scheduler.take_spawned_tasks();
            poll_tasks_once(&mut tasks); // park each loop at its first sleep
            world.scheduler.advance(engine.profile().poll_cadence);
            poll_tasks_once(&mut tasks); // the resolve tick runs one pass

            let held = engine.held_records.borrow();
            assert_eq!(held.len(), 1, "the resolve tick held the owner root");
            let record = held.get(&ROOT.0).expect("held under the root node id");
            assert_eq!(record.routing_key, root_name.as_str());
            assert_eq!(
                engine
                    .scope_read_seeds
                    .borrow()
                    .get(&SCOPE)
                    .map(|s| *s.seed),
                Some(SCOPE_SEED),
                "the tick adopt deposited the recovered scope read seed"
            );
        }

        /// A started engine over the full cold-start fixture, with its spawned
        /// loops taken and parked at their first sleep. The cold-start adopt
        /// raises the sequence floor to the record's own sequence, so every
        /// later poll of the same record is an equal-floor `Current`.
        fn started_and_parked(
            world: &FakeWorld,
            device: &FakeDevice,
        ) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
            let (head_block, head_cid, root_name) = owner_root();
            seed_vault_pointer(device, &root_name);
            for endpoint in device.record_store.endpoints() {
                seed_root_record_at(device, &endpoint, &root_name, &head_cid);
            }
            device.http.enqueue_response(head_response(&head_block));
            let (mut engine, events) = engine_on(device);
            block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec()))).unwrap();
            let mut tasks = world.scheduler.take_spawned_tasks();
            poll_tasks_once(&mut tasks);
            (engine, events, tasks)
        }

        /// Advance one poll cadence and run one pass of each loop, serving the
        /// head block the root record anchors.
        fn tick(world: &FakeWorld, device: &FakeDevice, tasks: &mut [BoxedTask]) {
            let (head_block, _, _) = owner_root();
            device.http.enqueue_response(head_response(&head_block));
            world.scheduler.advance(SyncTimingProfile::CI.poll_cadence);
            poll_tasks_once(tasks);
        }

        /// Nothing the spawned loops share may outlive the engine: a parked task
        /// is not polled again until its next scheduler wake, so `Drop` — not the
        /// next pass — has to clear the key material.
        #[test]
        fn engine_drop_clears_the_key_material_the_spawned_loops_share() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (engine, _events, mut tasks) = started_and_parked(&world, &device);
            tick(&world, &device, &mut tasks);

            let held = engine.held_records.clone();
            let read_seeds = engine.scope_read_seeds.clone();
            let write_seeds = engine.scope_write_seeds.clone();
            let enc_subkey = engine.tick_enc_subkey.clone();
            assert!(
                !held.borrow().is_empty(),
                "the tick holds the root under a per-name renewal signer"
            );
            assert!(!read_seeds.borrow().is_empty());
            assert!(!write_seeds.borrow().is_empty());
            assert!(enc_subkey.borrow().is_some());

            // The tasks stay parked across the drop — only `Drop` can clear this.
            drop(engine);
            assert!(
                held.borrow().is_empty(),
                "the per-name renewal signers go with the engine"
            );
            assert!(read_seeds.borrow().is_empty(), "and the scope read seed");
            assert!(write_seeds.borrow().is_empty(), "and the scope write seed");
            assert!(
                enc_subkey.borrow().is_none(),
                "and the session secret the tick borrowed"
            );
        }

        /// A forged owner-root record is fail-closed either way; without an event
        /// a persistent forgery is indistinguishable from an idle vault.
        #[test]
        fn a_persistently_forged_steady_state_record_raises_an_abuse_event() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (_, head_cid, root_name) = owner_root();
            let (engine, mut events, mut tasks) = started_and_parked(&world, &device);
            let adopted = block_on(engine.view()).unwrap().children(ROOT);
            let _ = drain(&mut events);

            // A strictly newer record whose signed head anchor the served block
            // does not address: fail-closed at assembly, on every poll.
            for endpoint in device.record_store.endpoints() {
                device.record_store.seed_record(
                    &endpoint,
                    root_name.as_str(),
                    root_record(&head_cid, 2),
                );
            }
            for _ in 0..2 {
                device
                    .http
                    .enqueue_response(head_response(b"forged head block"));
                world.scheduler.advance(SyncTimingProfile::CI.poll_cadence);
                poll_tasks_once(&mut tasks);

                let abuse: Vec<String> = drain(&mut events)
                    .into_iter()
                    .filter_map(|event| match event {
                        Event::AttributableAbuse { description } => Some(description),
                        _ => None,
                    })
                    .collect();
                assert_eq!(abuse.len(), 1, "every forged poll raises one abuse event");
                assert!(
                    abuse[0].contains(root_name.as_str())
                        && abuse[0].contains("content-cid-mismatch"),
                    "the event names the record and the check that rejected it: {}",
                    abuse[0]
                );
            }
            assert_eq!(
                block_on(engine.view()).unwrap().children(ROOT),
                adopted,
                "and the forgery still never renders"
            );
        }

        /// An idle vault re-fetching its own unchanged record must not re-open
        /// the owner blobs and re-insert the hold on every poll.
        #[test]
        fn a_steady_state_poll_neither_re_recovers_nor_re_holds() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (engine, _events, mut tasks) = started_and_parked(&world, &device);

            tick(&world, &device, &mut tasks);
            assert_eq!(
                engine.held_records.borrow().len(),
                1,
                "the first steady-state poll recovers the write seed and holds"
            );
            // Stamp the entry: a re-hold rebuilds it wholesale, so the stamp
            // surviving is the observable proof that no re-hold ran.
            engine
                .held_records
                .borrow_mut()
                .get_mut(&ROOT.0)
                .expect("held under the root node id")
                .content_cids = vec!["bafystamp".to_owned()];

            tick(&world, &device, &mut tasks);
            assert_eq!(
                engine.held_records.borrow()[&ROOT.0].content_cids,
                vec!["bafystamp".to_owned()],
                "the next poll left the hold alone"
            );
            assert_eq!(
                engine
                    .scope_write_seeds
                    .borrow()
                    .get(&SCOPE)
                    .map(|s| *s.seed),
                Some(WRITE_SCOPE_SEED),
                "and the material recovered once stays in hand"
            );
        }

        /// The drain is the only source of a head's content CIDs, so a re-hold
        /// that carries none must keep the set the publish registered.
        #[test]
        fn a_re_hold_keeps_the_content_cids_the_publish_registered() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (_, head_cid, root_name) = owner_root();
            let (engine, _events, mut tasks) = started_and_parked(&world, &device);
            tick(&world, &device, &mut tasks);

            let published = vec!["bafypublished".to_owned()];
            let before = {
                let mut held = engine.held_records.borrow_mut();
                let record = held.get_mut(&ROOT.0).expect("held under the root node id");
                record.content_cids.clone_from(&published);
                record.record_bytes.clone()
            };

            // A strictly newer record over the same head: an `Adopted` poll,
            // which rebuilds the hold wholesale rather than skipping it.
            let reseed = |sequence| {
                for endpoint in device.record_store.endpoints() {
                    device.record_store.seed_record(
                        &endpoint,
                        root_name.as_str(),
                        root_record(&head_cid, sequence),
                    );
                }
            };
            reseed(2);
            tick(&world, &device, &mut tasks);
            let held = engine.held_records.borrow();
            assert_ne!(
                held[&ROOT.0].record_bytes, before,
                "the poll really did re-hold, so the assertion below is not vacuous"
            );
            assert_eq!(
                held[&ROOT.0].content_cids, published,
                "the re-hold carried the published set forward"
            );
            drop(held);

            // Stamped against a head this device did not author: that block set
            // is superseded, so it must not ride the new head's renewal.
            engine
                .held_records
                .borrow_mut()
                .get_mut(&ROOT.0)
                .expect("held under the root node id")
                .head_cid = "bafyotherhead".to_owned();
            reseed(3);
            tick(&world, &device, &mut tasks);
            assert!(
                engine.held_records.borrow()[&ROOT.0]
                    .content_cids
                    .is_empty(),
                "CIDs held for a different head are dropped, not carried over"
            );
        }

        /// A rotation that raises the scope's durable read-epoch floor revokes
        /// the epoch the cached seed was recovered under, so the seed goes —
        /// least privilege binds retention, not only install.
        #[test]
        fn a_read_epoch_floor_rise_evicts_the_cached_scope_read_seed() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (engine, _events, mut tasks) = started_and_parked(&world, &device);
            tick(&world, &device, &mut tasks);
            assert!(engine.scope_read_seeds.borrow().contains_key(&SCOPE));

            block_on(device.floor_store.raise_epoch_floor(&SCOPE, EPOCH + 1)).unwrap();
            tick(&world, &device, &mut tasks);

            assert!(
                !engine.scope_read_seeds.borrow().contains_key(&SCOPE),
                "the seed recovered below the new floor is evicted"
            );
            assert!(
                engine.scope_write_seeds.borrow().contains_key(&SCOPE),
                "the write-epoch floor is a separate clock and did not move"
            );
        }

        /// Publish an owner-signed re-point at `SCOPE`'s **scope**-pointer name
        /// vouching `write_epoch` — the plane a write-only rotation re-points,
        /// and the one the polled consult reads.
        use cipherbox_core::seal::Permission as CorePermission;
        use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
        use cipherbox_core::suite::secret::SecretBytes;

        use crate::grants::ReceivedSharesList;

        /// A shared scope this session has accepted, whose scope root nothing on
        /// the record plane answers for.
        const SHARED_SCOPE: [u8; 16] = [0x7d; 16];

        /// Persist one received-share bookmark into this device's durable list,
        /// the state an accept leaves behind.
        fn bookmark_a_received_share(device: &FakeDevice) {
            let enc_secret = kdf::enc_subkey(&CAP_SECRET);
            let entropy = RefCell::new(SeededEntropy::new(11));
            let store =
                StagingReceivedShareStore::new(&device.staging_store, &enc_secret, &entropy);
            let mut list = ReceivedSharesList::new();
            list.reconcile(crate::grants::ReceivedShare {
                scope_root_name: child_name().as_str().as_bytes().to_vec(),
                scope_id: SHARED_SCOPE,
                sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
                display_name: "shared-folder".to_owned(),
                permission: CorePermission::Read,
                pointer_read_key: SecretBytes::new([0x9a; 32]),
            });
            block_on(store.persist(&list)).expect("the list persists");
        }

        fn seed_scope_pointer(device: &FakeDevice, root_name: &IpnsName, write_epoch: u64) {
            let owner_seed = kdf::owner_pointer_seed(&CAP_SECRET);
            let read_key = kdf::pointer_read_key(owner_seed.as_bytes(), &SCOPE);
            let mut entropy = SeededEntropy::new(3);
            let block = seal_repoint(
                SessionRole::Owner,
                &mut entropy,
                read_key.as_bytes(),
                POINTER_PAYLOAD_VERSION,
                &owner_identity(),
                &RepointObject {
                    scope_id: SCOPE,
                    current_root: root_name.clone(),
                    write_epoch,
                    min_read_epoch: EPOCH,
                    prev_root: None,
                },
            )
            .unwrap();
            let record = IpnsRecord::create_v2(
                &scope_pointer_signer(owner_seed.as_bytes(), &SCOPE),
                &block,
                1,
                TTL_NANOS,
                EOL,
            )
            .marshal();
            let pointer_name = scope_pointer_name(owner_seed.as_bytes(), &SCOPE);
            for endpoint in device.record_store.endpoints() {
                device
                    .record_store
                    .seed_record(&endpoint, pointer_name.as_str(), record.clone());
            }
        }

        /// The residual a write-only rotation leaves: it raises no read epoch, so
        /// it mints no superseded scope root for the sweep's event-driven consult
        /// — the polled tick leg is what advances the write-epoch floor, and with
        /// it evicts the `writeScopeSeed` that rotation retired.
        #[test]
        fn the_focus_tick_consults_the_scope_pointer_and_advances_the_write_epoch_floor() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (engine, _events, mut tasks) = started_and_parked(&world, &device);
            tick(&world, &device, &mut tasks);
            assert!(engine.scope_write_seeds.borrow().contains_key(&SCOPE));

            let (_, _, root_name) = owner_root();
            seed_scope_pointer(&device, &root_name, EPOCH + 1);
            tick(&world, &device, &mut tasks);

            assert_eq!(
                block_on(floor::write_epoch_floor(&device.floor_store, &SCOPE)).unwrap(),
                Some(EPOCH + 1),
                "the polled consult advanced the write-epoch floor on sight",
            );
            assert!(
                !engine.scope_write_seeds.borrow().contains_key(&SCOPE),
                "and the seed the rotation retired is evicted in the same pass",
            );
            assert!(
                engine.pointer_consulted.borrow().contains_key(&ROOT),
                "the pass stamped the consult, so the interval damper can pace it",
            );
        }

        /// The anchor's scope pointer is the only owner-vouched plane naming the
        /// vault's current root. A pass that sights a re-point reports the moved
        /// root, so the rest of the pass reads and publishes there rather than at
        /// the name cold start opened with.
        #[test]
        fn the_anchor_consult_reports_the_root_its_pointer_vouches() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (engine, _events, mut tasks) = started_and_parked(&world, &device);
            tick(&world, &device, &mut tasks);

            let moved = child_name();
            seed_scope_pointer(&device, &moved, EPOCH + 1);
            let (events, _rx) = mpsc::unbounded();
            let consult = |anchor| {
                block_on(consult_pointers(
                    &device.record_store,
                    &device.floor_store,
                    &engine.sweep_keys,
                    &events,
                    &RefCell::new(BTreeMap::new()),
                    ConsultWindow {
                        scopes: vec![ROOT],
                        anchor,
                        now: UnixMillis(0),
                    },
                ))
            };

            assert_eq!(
                consult(ROOT),
                Some(moved),
                "the anchor's re-point names the root the pass must poll"
            );
            assert_eq!(
                consult(NodeId([0x9e; 16])),
                None,
                "a shared scope's root is its own, and never the vault's"
            );
        }

        /// And the pass acts on it: every later leg — the gated resolve, the
        /// held set the liveness loop renews, the drain — addresses the moved
        /// root, not the name cold start opened with.
        #[test]
        fn a_tick_that_sights_a_repoint_resolves_the_moved_root() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (_, head_cid, root_name) = owner_root();
            let (engine, mut events, mut tasks) = started_and_parked(&world, &device);
            tick(&world, &device, &mut tasks);
            assert_eq!(
                engine.held_records.borrow()[&ROOT.0].routing_key,
                root_name.as_str(),
                "cold start opened at the name the vault pointer gave it"
            );

            // The anchor's pointer names a moved root, and a record answers there.
            let moved = child_name();
            seed_scope_pointer(&device, &moved, EPOCH + 1);
            for endpoint in device.record_store.endpoints() {
                device.record_store.seed_record(
                    &endpoint,
                    moved.as_str(),
                    root_record_at_node(CHILD_ID, &head_cid, 1),
                );
            }
            let _ = drain(&mut events);
            tick(&world, &device, &mut tasks);

            // The record answering there is bound to the name it moved off, so
            // the gate refuses it — and names what this pass resolved.
            let abuse: Vec<String> = drain(&mut events)
                .into_iter()
                .filter_map(|event| match event {
                    Event::AttributableAbuse { description } => Some(description),
                    _ => None,
                })
                .collect();
            assert_eq!(abuse.len(), 1, "one verdict on the one root resolved");
            assert!(
                abuse[0].contains(moved.as_str()),
                "the pass resolved the root its anchor pointer named: {}",
                abuse[0]
            );
            assert_ne!(
                engine.held_records.borrow()[&ROOT.0].routing_key,
                moved.as_str(),
                "and a gate refusal holds nothing (fail-closed)"
            );
        }

        /// The `/shared` read: the durable bookmark's key-free fields, and the
        /// verdict only a pass that actually resolved the scope root can supply.
        /// A share nothing has resolved yet reports no verdict at all — a host
        /// must not paint that as "still granted".
        #[test]
        fn received_shares_carry_no_verdict_until_a_pass_reaches_one() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (engine, _events, mut tasks) = started_and_parked(&world, &device);
            bookmark_a_received_share(&device);

            let before = block_on(engine.received_shares()).expect("the list reads");
            assert_eq!(before.len(), 1);
            assert_eq!(before[0].display_name, "shared-folder");
            assert_eq!(before[0].scope, NodeId(SHARED_SCOPE));
            assert_eq!(before[0].permission, Permission::Read);
            assert_eq!(
                before[0].resolution, None,
                "no pass has resolved this scope root yet"
            );

            tick(&world, &device, &mut tasks);

            let after = block_on(engine.received_shares()).expect("the list reads");
            assert_eq!(
                after[0].resolution,
                Some(ResolutionClass::Unresolvable),
                "a scope root nothing answers at is unresolvable, never a revocation",
            );
        }

        /// The write-epoch floor is the same rule on the seed the drain mints
        /// every new node's name and signer from.
        #[test]
        fn a_write_epoch_floor_rise_evicts_the_cached_scope_write_seed() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (engine, _events, mut tasks) = started_and_parked(&world, &device);
            tick(&world, &device, &mut tasks);
            assert!(engine.scope_write_seeds.borrow().contains_key(&SCOPE));

            block_on(floor::advance_write_epoch_on_sight(
                &device.floor_store,
                &SCOPE,
                EPOCH + 1,
            ))
            .unwrap();
            tick(&world, &device, &mut tasks);

            assert!(
                !engine.scope_write_seeds.borrow().contains_key(&SCOPE),
                "the seed recovered below the new write floor is evicted"
            );
            assert!(
                engine.scope_read_seeds.borrow().contains_key(&SCOPE),
                "and the read seed, whose floor did not move, stays"
            );
        }

        #[test]
        fn staleness_rungs_transition_and_emit_once_per_change() {
            use core::time::Duration;

            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (head_block, head_cid, root_name) = owner_root();
            seed_vault_pointer(&device, &root_name);
            for endpoint in device.record_store.endpoints() {
                seed_root_record_at(&device, &endpoint, &root_name, &head_cid);
            }
            device.http.enqueue_response(head_response(&head_block));
            let (mut engine, mut events) = engine_on(&device);
            block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec()))).unwrap();
            assert_eq!(
                drain(&mut events),
                vec![Event::SnapshotUpdated],
                "cold start paints once and stamps last_success"
            );

            let mut tasks = world.scheduler.take_spawned_tasks();
            poll_tasks_once(&mut tasks); // park each loop at its first sleep

            // CI profile: 1 s poll, 3 s stale_after. With no reachable head
            // block, each tick fails to reconcile and last_success stays at 0.
            world.scheduler.advance(Duration::from_secs(1));
            poll_tasks_once(&mut tasks);
            assert_eq!(
                drain(&mut events),
                vec![Event::StalenessChanged {
                    level: Staleness::Fresh
                }],
                "the first classified rung is reported"
            );
            world.scheduler.advance(Duration::from_secs(1));
            poll_tasks_once(&mut tasks);
            assert_eq!(drain(&mut events), vec![], "no re-emit within a rung");
            world.scheduler.advance(Duration::from_secs(1)); // t=3 s ≥ stale_after
            poll_tasks_once(&mut tasks);
            assert_eq!(
                drain(&mut events),
                vec![Event::StalenessChanged {
                    level: Staleness::Stale
                }]
            );
            world.scheduler.advance(Duration::from_secs(1));
            poll_tasks_once(&mut tasks);
            assert_eq!(drain(&mut events), vec![], "stale reported exactly once");

            // The record plane recovers with a newer root: the adopt stamps
            // last_success and the rung steps back to Fresh.
            for endpoint in device.record_store.endpoints() {
                device.record_store.seed_record(
                    &endpoint,
                    root_name.as_str(),
                    root_record(&head_cid, 2),
                );
            }
            device.http.enqueue_response(head_response(&head_block));
            world.scheduler.advance(Duration::from_secs(1));
            poll_tasks_once(&mut tasks);
            assert_eq!(
                drain(&mut events),
                vec![
                    Event::SnapshotUpdated,
                    Event::StalenessChanged {
                        level: Staleness::Fresh
                    },
                ],
                "a reconciled tick repaints and steps the ladder back to Fresh"
            );

            // The read surface classifies off the same state.
            let view = block_on(engine.snapshot(ROOT)).unwrap();
            assert_eq!(view.staleness, Staleness::Fresh);
        }

        #[test]
        fn two_loops_coexist_and_stop_on_drop() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (head_block, head_cid, root_name) = owner_root();
            seed_vault_pointer(&device, &root_name);
            let (mut engine, _events) = engine_on(&device);
            block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec()))).unwrap();

            let mut tasks = world.scheduler.take_spawned_tasks();
            assert_eq!(
                tasks.len(),
                2,
                "start spawns the liveness loop and the resolve-tick loop"
            );

            // Seed the record at only the first endpoint so the keyless re-PUT is
            // observable when it propagates to the second.
            let endpoints = device.record_store.endpoints();
            seed_root_record_at(&device, &endpoints[0], &root_name, &head_cid);
            device.http.enqueue_response(head_response(&head_block));

            let mut cx = Context::from_waker(Waker::noop());
            poll_tasks_once(&mut tasks); // park both at their first sleep
            // One hourly interval wakes both the 1 s tick and the 1 h re-PUT. Drive
            // the tick first (it holds the root), then the keyless re-PUT.
            world.scheduler.advance(RE_PUT_INTERVAL);
            let _ = tasks[1].as_mut().poll(&mut cx); // resolve tick
            let _ = tasks[0].as_mut().poll(&mut cx); // keyless re-PUT

            assert!(
                !engine.held_records.borrow().is_empty(),
                "the resolve tick populated the held set"
            );
            assert!(
                device
                    .record_store
                    .record_at(&endpoints[1], root_name.as_str())
                    .is_some(),
                "the keyless re-PUT propagated the held record to the second endpoint"
            );

            // Drop clears the alive latch; both loops stop at their next wake.
            drop(engine);
            world.scheduler.advance(RE_PUT_INTERVAL);
            let after = poll_tasks_once(&mut tasks);
            assert!(
                after.iter().all(Poll::is_ready),
                "both loops stop after the engine drops"
            );
        }

        // --- Engine::read_content over the ChildAdopter pipeline ---

        mod read_content {
            use super::*;

            use cipherbox_core::seal::Version;

            use crate::content::{
                ContentDag, ContentKey, ContentProfile, SealedChunk, assemble, frame_and_seal,
            };
            use crate::gate::floor;
            use crate::seams::SnapshotCache;

            const CONTENT_KEY: [u8; 32] = [0x99; 32];
            const CHILD_MTIME: u64 = 777;
            /// 24 bytes → two leaves at the CI profile's 16-byte chunk size.
            const PLAINTEXT: &[u8] = b"two-leaf plaintext bytes";

            /// The child's sealed content DAG: leaves + root manifest block.
            fn content_dag(plaintext: &[u8]) -> (Vec<SealedChunk>, ContentDag) {
                let key = ContentKey::from_bytes(CONTENT_KEY);
                let leaves = frame_and_seal(
                    plaintext,
                    &key,
                    &mut SeededEntropy::new(5),
                    &ContentProfile::CI,
                )
                .unwrap();
                let cids: Vec<Vec<u8>> = leaves.iter().map(|leaf| leaf.cid.clone()).collect();
                let dag = assemble(&cids, plaintext.len() as u64, &ContentProfile::CI).unwrap();
                (leaves, dag)
            }

            fn head_version(dag: &ContentDag, size: u64) -> Version {
                Version::new(dag.content_cid.clone(), CONTENT_KEY, size, CHILD_MTIME)
            }

            fn file_body(versions: Vec<Version>) -> ReadBody {
                ReadBody::File {
                    created_at: 0,
                    modified_at: CHILD_MTIME,
                    versions,
                    unknown: PreservedFields::new(),
                }
            }

            /// A child head block sealed under the node's derived read key. The
            /// knobs drive the fail-closed tests: the envelope id/scope/epoch
            /// (transplants, epoch inflation), the body (kind transplant, empty
            /// / size-lying version list), and a bolted-on grant section.
            fn sealed_child_head(
                envelope_id: [u8; 16],
                scope: [u8; 16],
                epoch: u64,
                body: &ReadBody,
                with_grant_section: bool,
            ) -> (Vec<u8>, String) {
                let node_seed = kdf::node_seed(&SCOPE_SEED, &envelope_id);
                let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();
                let mut envelope =
                    seal_read_body(&read_key, &[13u8; 24], 1, envelope_id, scope, epoch, body)
                        .unwrap();
                if with_grant_section {
                    set_grant_section(&mut envelope, vec![1, 2, 3]);
                }
                let head_block = encode_envelope(&envelope).unwrap();
                let cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head_block));
                (head_block, cid)
            }

            /// A child file head block at the fixture scope/epoch.
            fn child_head(
                envelope_id: [u8; 16],
                versions: Vec<Version>,
                with_grant_section: bool,
            ) -> (Vec<u8>, String) {
                sealed_child_head(
                    envelope_id,
                    SCOPE,
                    EPOCH,
                    &file_body(versions),
                    with_grant_section,
                )
            }

            /// The child record, signed by the child's own write-plane signer.
            fn child_record(head_cid_str: &str, sequence: u64) -> Vec<u8> {
                let write_seed = kdf::write_seed(&WRITE_SCOPE_SEED, &CHILD_ID);
                let signer = kdf::ipns_keypair(write_seed.as_bytes());
                let value = format!("/ipfs/{head_cid_str}");
                IpnsRecord::create_v2(&signer, value.as_bytes(), sequence, TTL_NANOS, EOL).marshal()
            }

            /// Seed the child record at every endpoint.
            fn seed_child_record(device: &FakeDevice, head_cid_str: &str, sequence: u64) {
                let record = child_record(head_cid_str, sequence);
                for endpoint in device.record_store.endpoints() {
                    device.record_store.seed_record(
                        &endpoint,
                        child_name().as_str(),
                        record.clone(),
                    );
                }
            }

            /// A started engine over the full cold-start fixture (pointer +
            /// root record + root head block), drained past the first paint.
            fn started(device: &FakeDevice) -> (Engine<FakeSeamTypes>, EventStream) {
                let (head_block, head_cid, root_name) = owner_root();
                seed_vault_pointer(device, &root_name);
                for endpoint in device.record_store.endpoints() {
                    seed_root_record_at(device, &endpoint, &root_name, &head_cid);
                }
                device.http.enqueue_response(head_response(&head_block));
                let (mut engine, mut events) = engine_on(device);
                block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec()))).unwrap();
                assert_eq!(drain(&mut events), vec![Event::SnapshotUpdated]);
                (engine, events)
            }

            fn progress(node: NodeId, phase: OpPhase) -> Event {
                Event::OpProgress {
                    op_id: None,
                    node,
                    phase,
                    progress: None,
                    error: None,
                }
            }

            /// Script the full download fetch order: child head, DAG root, then
            /// each leaf.
            fn enqueue_download(
                device: &FakeDevice,
                head_block: &[u8],
                dag: &ContentDag,
                leaves: &[SealedChunk],
            ) {
                device.http.enqueue_response(head_response(head_block));
                device.http.enqueue_response(head_response(&dag.root_block));
                for leaf in leaves {
                    device.http.enqueue_response(head_response(&leaf.sealed));
                }
            }

            #[test]
            fn happy_path_reads_the_exact_plaintext_and_folds_metadata() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, mut events) = started(&device);

                let (leaves, dag) = content_dag(PLAINTEXT);
                assert_eq!(leaves.len(), 2, "the fixture spans two leaves");
                let (head_block, head_cid) = child_head(
                    CHILD_ID,
                    vec![head_version(&dag, PLAINTEXT.len() as u64)],
                    false,
                );
                seed_child_record(&device, &head_cid, 1);
                enqueue_download(&device, &head_block, &dag, &leaves);

                let node = NodeId(CHILD_ID);
                let bytes = block_on(engine.read_content(node)).expect("read succeeds");
                assert_eq!(bytes, PLAINTEXT, "the exact plaintext round-trips");
                assert_eq!(
                    drain(&mut events),
                    vec![
                        progress(node, OpPhase::DownloadStarted),
                        Event::SnapshotUpdated,
                        progress(node, OpPhase::DownloadCompleted),
                    ],
                );
                let view = block_on(engine.snapshot(ROOT)).unwrap();
                let child = view
                    .children
                    .iter()
                    .find(|c| c.id == node)
                    .expect("child listed");
                assert_eq!(child.size, Some(PLAINTEXT.len() as u64));
                assert_eq!(child.mtime, Some(CHILD_MTIME));

                // A second read re-serves the same record, now at the durable
                // floor: the at-floor re-open yields the identical plaintext,
                // and the unchanged size/mtime fold repaints nothing.
                enqueue_download(&device, &head_block, &dag, &leaves);
                assert_eq!(block_on(engine.read_content(node)).unwrap(), PLAINTEXT);
                assert_eq!(
                    drain(&mut events),
                    vec![
                        progress(node, OpPhase::DownloadStarted),
                        progress(node, OpPhase::DownloadCompleted),
                    ],
                    "an identical second read emits no SnapshotUpdated"
                );
            }

            #[test]
            fn a_tampered_leaf_fails_closed_with_no_partial_bytes() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, mut events) = started(&device);

                let (leaves, dag) = content_dag(PLAINTEXT);
                let (head_block, head_cid) = child_head(
                    CHILD_ID,
                    vec![head_version(&dag, PLAINTEXT.len() as u64)],
                    false,
                );
                seed_child_record(&device, &head_cid, 1);
                device.http.enqueue_response(head_response(&head_block));
                device.http.enqueue_response(head_response(&dag.root_block));
                // The first leaf does not content-address to its CID.
                let mut tampered = leaves[0].sealed.clone();
                *tampered.last_mut().unwrap() ^= 0x01;
                device.http.enqueue_response(head_response(&tampered));

                let node = NodeId(CHILD_ID);
                let err = block_on(engine.read_content(node)).unwrap_err();
                assert!(
                    matches!(err, EngineError::TrustViolation { .. }),
                    "a leaf CID mismatch is a fail-closed trust violation: {err:?}"
                );
                assert_eq!(
                    drain(&mut events),
                    vec![
                        progress(node, OpPhase::DownloadStarted),
                        Event::OpProgress {
                            op_id: None,
                            node,
                            phase: OpPhase::DownloadFailed,
                            progress: None,
                            error: Some(err.to_string()),
                        },
                    ],
                    "started then failed; no snapshot fold"
                );
                let view = block_on(engine.snapshot(ROOT)).unwrap();
                let child = view.children.iter().find(|c| c.id == node).unwrap();
                assert_eq!(child.size, None, "no partial state reaches the view");
            }

            #[test]
            fn a_transplanted_child_envelope_rejects_fail_closed() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                // The envelope names a DIFFERENT node id, served under the
                // child's name: an id transplant.
                let (_leaves, dag) = content_dag(PLAINTEXT);
                let (head_block, head_cid) = child_head(
                    [0xEE; 16],
                    vec![head_version(&dag, PLAINTEXT.len() as u64)],
                    false,
                );
                seed_child_record(&device, &head_cid, 1);
                device.http.enqueue_response(head_response(&head_block));

                let err = block_on(engine.read_content(NodeId(CHILD_ID))).unwrap_err();
                assert!(
                    matches!(err, EngineError::TrustViolation { .. }),
                    "an id transplant rejects fail-closed: {err:?}"
                );
            }

            #[test]
            fn a_child_envelope_bearing_a_grant_section_rejects() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                let (_leaves, dag) = content_dag(PLAINTEXT);
                let (head_block, head_cid) = child_head(
                    CHILD_ID,
                    vec![head_version(&dag, PLAINTEXT.len() as u64)],
                    true,
                );
                seed_child_record(&device, &head_cid, 1);
                device.http.enqueue_response(head_response(&head_block));

                let err = block_on(engine.read_content(NodeId(CHILD_ID))).unwrap_err();
                assert!(
                    matches!(err, EngineError::TrustViolation { .. }),
                    "a grant-section-bearing child rejects fail-closed: {err:?}"
                );
            }

            #[test]
            fn folder_unknown_and_pending_nodes_map_to_their_errors() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (mut engine, _events) = started(&device);

                assert_eq!(
                    block_on(engine.read_content(ROOT)),
                    Err(EngineError::NotAFile),
                    "a folder node is not readable content"
                );
                assert_eq!(
                    block_on(engine.read_content(NodeId([0x5A; 16]))),
                    Err(EngineError::UnknownNode)
                );

                // A staged (pending-only) create has no ipnsName yet:
                // availability, not trust — content is simply not published.
                block_on(engine.command(Command::Create {
                    parent: ROOT,
                    name: "pending.txt".into(),
                    kind: NodeKind::File,
                }))
                .unwrap();
                let pending = block_on(engine.view())
                    .unwrap()
                    .lookup(ROOT, "pending.txt")
                    .unwrap()
                    .id;
                assert!(
                    matches!(
                        block_on(engine.read_content(pending)),
                        Err(EngineError::ContentUnavailable { .. })
                    ),
                    "a pending-only node is availability, not trust"
                );
            }

            #[test]
            fn an_empty_version_list_is_an_error() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                let (head_block, head_cid) = child_head(CHILD_ID, Vec::new(), false);
                seed_child_record(&device, &head_cid, 1);
                device.http.enqueue_response(head_response(&head_block));

                assert!(
                    matches!(
                        block_on(engine.read_content(NodeId(CHILD_ID))),
                        Err(EngineError::ContentUnavailable { .. })
                    ),
                    "no published version yields no content"
                );
            }

            #[test]
            fn a_manifest_size_disagreement_fails_closed() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                // The version lies about its size relative to the manifest.
                let (_leaves, dag) = content_dag(PLAINTEXT);
                let (head_block, head_cid) = child_head(
                    CHILD_ID,
                    vec![head_version(&dag, PLAINTEXT.len() as u64 + 1)],
                    false,
                );
                seed_child_record(&device, &head_cid, 1);
                device.http.enqueue_response(head_response(&head_block));
                device.http.enqueue_response(head_response(&dag.root_block));

                let err = block_on(engine.read_content(NodeId(CHILD_ID))).unwrap_err();
                assert!(
                    matches!(err, EngineError::TrustViolation { .. }),
                    "a size disagreement is fail-closed: {err:?}"
                );
            }

            #[test]
            fn a_replayed_lower_sequence_rejects_after_adoption() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                let (leaves, dag) = content_dag(PLAINTEXT);
                let (head_block, head_cid) = child_head(
                    CHILD_ID,
                    vec![head_version(&dag, PLAINTEXT.len() as u64)],
                    false,
                );
                seed_child_record(&device, &head_cid, 2);
                enqueue_download(&device, &head_block, &dag, &leaves);
                block_on(engine.read_content(NodeId(CHILD_ID))).expect("adopts at sequence 2");

                // Replay: re-serve sequence 1 for the same child. The per-name
                // floor advanced to 2, so the replay rejects fail-closed.
                seed_child_record(&device, &head_cid, 1);
                device.http.enqueue_response(head_response(&head_block));
                let err = block_on(engine.read_content(NodeId(CHILD_ID))).unwrap_err();
                match &err {
                    EngineError::TrustViolation { message } => assert!(
                        message.contains("sequence-not-newer"),
                        "the replay names the sequence floor: {message}"
                    ),
                    other => panic!("a replay must reject fail-closed, got {other:?}"),
                }
            }

            #[test]
            fn an_unreachable_content_plane_is_availability_not_trust() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                // No child record anywhere and a cold cache: nothing resolvable.
                let err = block_on(engine.read_content(NodeId(CHILD_ID))).unwrap_err();
                assert!(
                    matches!(err, EngineError::ContentUnavailable { .. }),
                    "an unpublished child is availability: {err:?}"
                );

                // The record appears but no gateway response is scripted: every
                // source transport-fails, which stays availability, never trust.
                let (_leaves, dag) = content_dag(PLAINTEXT);
                let (_head_block, head_cid) = child_head(
                    CHILD_ID,
                    vec![head_version(&dag, PLAINTEXT.len() as u64)],
                    false,
                );
                seed_child_record(&device, &head_cid, 1);
                let err = block_on(engine.read_content(NodeId(CHILD_ID))).unwrap_err();
                assert!(
                    matches!(err, EngineError::ContentUnavailable { .. }),
                    "an unreachable gateway is availability: {err:?}"
                );
            }

            #[test]
            fn an_inflated_child_epoch_cannot_poison_the_scope_epoch_floor() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                // A write-capable party seals the child claiming a far-future
                // epoch (the read key does not bind epoch, so it unseals fine).
                let (leaves, dag) = content_dag(PLAINTEXT);
                let (head_block, head_cid) = sealed_child_head(
                    CHILD_ID,
                    SCOPE,
                    EPOCH + 1000,
                    &file_body(vec![head_version(&dag, PLAINTEXT.len() as u64)]),
                    false,
                );
                seed_child_record(&device, &head_cid, 1);
                enqueue_download(&device, &head_block, &dag, &leaves);
                assert_eq!(
                    block_on(engine.read_content(NodeId(CHILD_ID))).unwrap(),
                    PLAINTEXT,
                    "the inflated-epoch child still reads"
                );

                // The child's sequence floor advanced...
                assert_eq!(
                    block_on(floor::sequence_floor(
                        &device.floor_store,
                        child_name().as_str().as_bytes(),
                    ))
                    .unwrap(),
                    Some(1),
                );
                // ...but the scope read-epoch floor did not move: it advances
                // only from gate-adopted roots.
                assert_eq!(
                    block_on(floor::read_epoch_floor(&device.floor_store, &SCOPE)).unwrap(),
                    Some(EPOCH),
                    "a child unseal must not raise the scope read-epoch floor"
                );

                // A subsequent honest root at the real epoch still adopts — the
                // child could not poison the root path into EpochBelowFloor.
                let (root_head_block, root_head_cid, root_name) = owner_root();
                for endpoint in device.record_store.endpoints() {
                    device.record_store.seed_record(
                        &endpoint,
                        root_name.as_str(),
                        root_record(&root_head_cid, 2),
                    );
                }
                device
                    .http
                    .enqueue_response(head_response(&root_head_block));
                let mut tasks = world.scheduler.take_spawned_tasks();
                poll_tasks_once(&mut tasks); // park each loop at its first sleep
                world.scheduler.advance(engine.profile().poll_cadence);
                poll_tasks_once(&mut tasks); // the resolve tick runs one pass
                assert_eq!(
                    block_on(floor::sequence_floor(
                        &device.floor_store,
                        root_name.as_str().as_bytes(),
                    ))
                    .unwrap(),
                    Some(2),
                    "the honest root adopted at the real epoch"
                );
            }

            #[test]
            fn at_floor_reopen_rejects_a_cached_record_above_the_floor() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                // A cached child record at sequence 2 while this device's
                // per-name floor never advanced (no prior adopt): the at-floor
                // re-open admits only the exact floor.
                let (_leaves, dag) = content_dag(PLAINTEXT);
                let (head_block, head_cid) = child_head(
                    CHILD_ID,
                    vec![head_version(&dag, PLAINTEXT.len() as u64)],
                    false,
                );
                block_on(device.snapshot_cache.put(
                    child_name().as_str().as_bytes(),
                    &child_record(&head_cid, 2),
                ))
                .unwrap();
                for endpoint in device.record_store.endpoints() {
                    device.record_store.fail_endpoint(&endpoint);
                }
                device.http.enqueue_response(head_response(&head_block));

                let err = block_on(engine.read_content(NodeId(CHILD_ID))).unwrap_err();
                match &err {
                    EngineError::TrustViolation { message } => assert!(
                        message.contains("sequence-not-newer"),
                        "an above-floor re-open is a sequence rejection: {message}"
                    ),
                    other => panic!("an above-floor re-open must reject fail-closed: {other:?}"),
                }
            }

            #[test]
            fn a_scope_transplanted_child_envelope_rejects_fail_closed() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                // The envelope carries the expected node id but a FOREIGN scope,
                // sealed consistently (AAD scope == envelope scope, and the read
                // key binds no scope) — only the explicit scope check can fire.
                let (_leaves, dag) = content_dag(PLAINTEXT);
                let (head_block, head_cid) = sealed_child_head(
                    CHILD_ID,
                    [0xAB; 16],
                    EPOCH,
                    &file_body(vec![head_version(&dag, PLAINTEXT.len() as u64)]),
                    false,
                );
                seed_child_record(&device, &head_cid, 1);
                device.http.enqueue_response(head_response(&head_block));

                let err = block_on(engine.read_content(NodeId(CHILD_ID))).unwrap_err();
                assert!(
                    matches!(err, EngineError::TrustViolation { .. }),
                    "a scope transplant rejects fail-closed: {err:?}"
                );
            }

            #[test]
            fn a_kind_transplanted_child_body_rejects_fail_closed() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                // A sealed FOLDER body at a node the parent lists as a file.
                let folder_body = ReadBody::Folder {
                    created_at: 0,
                    modified_at: 0,
                    children: Vec::new(),
                    unknown: PreservedFields::new(),
                };
                let (head_block, head_cid) =
                    sealed_child_head(CHILD_ID, SCOPE, EPOCH, &folder_body, false);
                seed_child_record(&device, &head_cid, 1);
                device.http.enqueue_response(head_response(&head_block));

                let err = block_on(engine.read_content(NodeId(CHILD_ID))).unwrap_err();
                match &err {
                    EngineError::TrustViolation { message } => assert!(
                        message.contains("kind disagrees"),
                        "the rejection names the kind transplant: {message}"
                    ),
                    other => panic!("a kind transplant must reject fail-closed: {other:?}"),
                }
            }

            #[test]
            fn no_update_serves_the_cached_record_without_moving_floors() {
                let world = FakeWorld::new();
                let device = world.device(b"alice-pk");
                let (engine, _events) = started(&device);

                let (leaves, dag) = content_dag(PLAINTEXT);
                let (head_block, head_cid) = child_head(
                    CHILD_ID,
                    vec![head_version(&dag, PLAINTEXT.len() as u64)],
                    false,
                );
                seed_child_record(&device, &head_cid, 1);
                enqueue_download(&device, &head_block, &dag, &leaves);
                assert_eq!(
                    block_on(engine.read_content(NodeId(CHILD_ID))).unwrap(),
                    PLAINTEXT,
                    "the adopt seeds the cache and floors"
                );

                // Every record source unreachable: NoUpdate falls back to the
                // cached last-known-good, re-opened at the floor.
                for endpoint in device.record_store.endpoints() {
                    device.record_store.fail_endpoint(&endpoint);
                }
                enqueue_download(&device, &head_block, &dag, &leaves);
                assert_eq!(
                    block_on(engine.read_content(NodeId(CHILD_ID))).unwrap(),
                    PLAINTEXT,
                    "the cached record serves the exact plaintext"
                );
                assert_eq!(
                    block_on(floor::sequence_floor(
                        &device.floor_store,
                        child_name().as_str().as_bytes(),
                    ))
                    .unwrap(),
                    Some(1),
                    "the at-floor re-open advanced no sequence floor"
                );
                assert_eq!(
                    block_on(floor::read_epoch_floor(&device.floor_store, &SCOPE)).unwrap(),
                    Some(EPOCH),
                    "the at-floor re-open advanced no epoch floor"
                );
            }
        }
    }
}

/// The FUSE-op TTL check and the operation-stream focus window
/// (blueprint/desktop.md "Freshness"). Driven at the facade because the focus
/// window and its refresh stamps are engine state; `fuse-op-core` covers what
/// the mount does with the answer.
#[cfg(test)]
mod focus_access_tests {
    use super::*;
    use crate::testkit::fakes::VirtualScheduler;
    use crate::testkit::{FakeSeamTypes, FakeWorld, SeededEntropy};

    const FOLDER: NodeId = NodeId([3; 16]);
    const OTHER: NodeId = NodeId([4; 16]);

    fn engine() -> (Engine<FakeSeamTypes>, VirtualScheduler) {
        let world = FakeWorld::new();
        let device = world.device(b"alice-pk");
        let scheduler = world.scheduler.clone();
        let (engine, _events) = Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
            ContentProfile::CI,
            StoragePolicy::CI,
            ApiBaseUrl::offline(),
            GatewayConfig::disabled(),
        );
        (engine, scheduler)
    }

    #[test]
    fn a_folder_this_device_has_never_refreshed_is_stale() {
        let (engine, _clock) = engine();
        assert!(engine.note_focus_access(Some(FOLDER)));
    }

    #[test]
    fn a_second_access_inside_the_threshold_fires_no_second_hint() {
        let (engine, clock) = engine();
        assert!(engine.note_focus_access(Some(FOLDER)));

        clock.advance(SyncTimingProfile::CI.stale_after / 2);
        assert!(
            !engine.note_focus_access(Some(FOLDER)),
            "the hint already filed covers this access"
        );

        clock.advance(SyncTimingProfile::CI.stale_after);
        assert!(
            engine.note_focus_access(Some(FOLDER)),
            "past the threshold the folder is stale again"
        );
    }

    #[test]
    fn the_folder_in_view_becomes_the_open_folder() {
        let (engine, _clock) = engine();
        assert_eq!(engine.focus_folder(), None);

        engine.note_focus_access(Some(FOLDER));
        assert_eq!(engine.focus_folder(), Some(FOLDER));

        engine.note_focus_access(Some(OTHER));
        assert_eq!(engine.focus_folder(), Some(OTHER));
    }

    #[test]
    fn an_operation_with_no_folder_in_view_neither_hints_nor_moves_the_window() {
        let (engine, clock) = engine();
        engine.note_focus_access(Some(FOLDER));

        clock.advance(SyncTimingProfile::CI.focus_horizon * 2);
        assert!(!engine.note_focus_access(None));
        assert_eq!(
            engine.focus_folder(),
            Some(FOLDER),
            "closing a quiet window is the tick's job, not an operation's"
        );
    }

    /// The hint damper is the FUSE-op check's own; it must not stand in for the
    /// stamp a completed refresh pass earns, which the on-access navigation leg
    /// reads to decide whether to resolve.
    #[test]
    fn a_hint_never_stamps_a_refresh_no_pass_ran() {
        let (engine, _clock) = engine();
        assert!(engine.note_focus_access(Some(FOLDER)));

        assert!(
            engine.focus_refreshed.borrow().is_empty(),
            "a hint is a request for a pass, never the record of one"
        );
    }
}
