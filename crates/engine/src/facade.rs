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

use cipherbox_core::content::encode_content_cid_str;
use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{ReadBody, Version, seal_content_key};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
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
use crate::entropy::Entropy;
use crate::gate::{GateError, floor};
use crate::grants::{Contact, ContactStore, ContactStoreError, StagingContactStore};
use crate::net::retire::{OrphanHeads, retire};
use crate::net::{
    Adopter, ChildAdopter, ChildResolveError, EolRenewResult, FolderRefresh, HeldMaterial,
    HeldRecord, HeldRecords, LivenessControl, PublishError, PublishOutcome, RE_PUT_INTERVAL,
    RecordPointerFetch, ResolveOutcome, RootAdopter, VaultProvisionNet, eol_renew_pass,
    keyless_re_put, refresh_base_from_outcome, resolve_and_hold, resolve_child, run_liveness_loop,
};
use crate::owner_keys::OwnerSessionKeys;
use crate::profile::SyncTimingProfile;
use crate::rotation::derive_write_name;
use crate::seams::{
    FloorStore, OpId, Scheduler, SeamError, SeamResult, SeamSet, SeamTypes, StagingStore,
    UnixMillis,
};
use crate::session::SessionIdentity;
use crate::settings::{PlacementDecision, PlacementRefusal, decide_placement, load_settings};
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
    GENESIS_VAULT_POINTER_INDEX, ProvisionError, ProvisionOutcome, ProvisionPlan, provision_vault,
};
use crate::sync::rebase::{QueueScan, QueueScanMemo, decode_queue};
use cipherbox_core::hex::lower as hex_lower;

pub use crate::sync::drain::BlockedOp;
pub use crate::sync::rebase::DeadLetterReason;
use crate::sync::record::{RecordReader, RecordSeal};
use crate::sync::refresh::{ManualRefresh, RefreshVerdict};
use crate::sync::staging::{LiveBlocks, collect_orphans, release_version_blocks, stage_op};
use crate::sync::staleness::{Connectivity, classify};
use crate::sync::tick::{
    FocusWindow, ResolveMode, TickControl, focus_folders, focus_folders_due, resolve_mode,
    run_tick_loop,
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
    /// Every retained dead-lettered op, with its reason.
    pub dead_letters: Vec<DeadLetter>,
    /// The over-quota hold, if the drain has one. Read here and never as an
    /// event: this is a state that *clears*, and a lost "resumed" would strand
    /// the UI on a blockage that is gone.
    pub blocked: Option<BlockedOp>,
    /// How many durable queue entries this session holds but cannot read
    /// (CONTEXT.md "Retained record"). Deliberately unattributed — it says the
    /// device is not empty, never whose work it holds — and it exists so an
    /// over-budget rejection on an apparently empty vault has an explanation.
    pub retained_records: usize,
    /// The staleness rung at read time.
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
    /// carries the ephemeral secret; response payloads land with the grants
    /// slice.
    CreateInviteLink {
        /// Node to invite to.
        node: NodeId,
        /// Read or write.
        permission: Permission,
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
            Command::AcceptShare { .. } => "acceptShare",
            Command::RotateNow { .. } => "rotateNow",
            Command::SiweLogin { .. } => "siweLogin",
            Command::Logout => "logout",
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
}

impl fmt::Debug for CommandOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandOutcome::Done => f.write_str("CommandOutcome(done)"),
            CommandOutcome::Queued { op_id } => write!(f, "CommandOutcome(queued {})", op_id.0),
            CommandOutcome::ContactImported(_) => f.write_str("CommandOutcome(contactImported)"),
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
    /// path stays dark until a later `start` provisions it. Surfaced, never
    /// silent (blueprint/engine.md "never a silent failure"): reads still paint
    /// and ops still queue, but nothing will publish.
    VaultUnprovisioned {
        /// Whether a fresh `start` could clear this — an availability stall —
        /// versus a fail-closed refusal to mint, which a retry reaches again.
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
            EngineError::Seam { message } => write!(f, "seam error: {message}"),
            EngineError::Entropy { message } => write!(f, "entropy error: {message}"),
            EngineError::Auth { message } => write!(f, "auth error: {message}"),
            EngineError::ColdStart { message } => write!(f, "cold-start failed: {message}"),
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
            .find(|child| collation_key(&child.name) == key)
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

fn node_attrs(meta: &NodeMeta) -> NodeAttrs {
    NodeAttrs {
        id: meta.id,
        name: meta.name.clone(),
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
    /// The session access token, shared by the API client [`start`](Self::start)
    /// builds and the read accelerator's gateway leg — the accelerator is
    /// CipherBox's own token-authed gateway, so the session is what gates it.
    /// One cell for both: clearing it de-authenticates the API client too.
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
    /// Where this session's bytes go, decided once at [`start`](Self::start)
    /// from the vault settings load and shared with the drain. `None` until
    /// then, and emptied on drop like [`tick_enc_subkey`](Self::tick_enc_subkey)
    /// — the config it holds carries the member's provider bearer.
    placement: Rc<RefCell<Option<PlacementDecision>>>,
    /// Whether this session has already held the account's `byo` flag to the
    /// vaulted mode. Once a session: the flag is account-wide and the mode is
    /// fixed at [`start`](Self::start), so re-deriving it per write would only
    /// let two devices flap it.
    byo_reconciled: Cell<bool>,
    /// The one shared API client, built and logged in at [`start`](Self::start)
    /// and handed to the liveness loop so the access JWT is shared across
    /// publish/renew (no redundant 401→refresh). `None` until then.
    api: Option<Rc<ApiClient<T::Http, T::CredentialStore>>>,
    started: bool,
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
                accelerator_bearer,
                events,
                // The anchored all-zero root until cold-start/resolve replaces
                // the base snapshot; children come from the pending-op overlay.
                snapshot: Rc::new(RefCell::new(Snapshot::new(NodeId([0u8; 16])))),
                held_records: Rc::new(RefCell::new(HeldRecords::new())),
                sync_status: Rc::new(RefCell::new(SyncStatus::default())),
                scope_read_seeds: Rc::new(RefCell::new(BTreeMap::new())),
                scope_write_seeds: Rc::new(RefCell::new(BTreeMap::new())),
                focus: Rc::new(RefCell::new(FocusWindow::default())),
                focus_refreshed: Rc::new(RefCell::new(BTreeMap::new())),
                dead_letters: Rc::new(RefCell::new(BTreeMap::new())),
                queue_scan: RefCell::new(QueueScanMemo::default()),
                blocked: Rc::new(RefCell::new(None)),
                pending_reclaim: Rc::new(Cell::new(0)),
                orphan_heads: Rc::new(OrphanHeads::default()),
                alive: Rc::new(Cell::new(true)),
                manual_refresh: ManualRefresh::default(),
                session: None,
                tick_enc_subkey: Rc::new(RefCell::new(None)),
                placement: Rc::new(RefCell::new(None)),
                byo_reconciled: Cell::new(false),
                api: None,
                started: false,
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
        T::Scheduler: Clone + 'static,
        T::RecordTransport: Clone + 'static,
        T::Http: Clone + 'static,
        T::CredentialStore: Clone + 'static,
        T::FloorStore: Clone + 'static,
        T::SnapshotCache: Clone + 'static,
        T::StagingStore: Clone + 'static,
    {
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
            .with_session_bearer(self.accelerator_bearer.clone()),
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
        let mut outcome = match self.run_cold_start(root).await {
            Ok(outcome) => outcome,
            Err(err) => {
                self.clear_failed_start();
                return Err(EngineError::from_cold_start(err));
            }
        };
        // An empty chain is an account that has never published: mint its genesis
        // vault before anything reads one (`sync/provision.rs`). Register-first
        // has no offline form, so the harness's no-API mode skips provisioning
        // for the same reason it skips login ([`ApiBaseUrl::offline`]).
        let provisioned =
            if outcome.vault_pointer.is_none() && self.api_base_url.configured().is_some() {
                match self.provision_first_run_vault(&api, root_scope_id).await {
                    Ok(ProvisionOutcome::Minted(vault)) => Some(*vault),
                    // The account published between this run's pointer walk and
                    // its mint. Nothing of this run's is live, so the whole
                    // cold-start chain re-runs against the re-point that is —
                    // floors, gate and seeds all from the account's own record.
                    Ok(ProvisionOutcome::MovedOn) => {
                        match self.run_cold_start(root).await {
                            Ok(rerun) => outcome = rerun,
                            Err(err) => {
                                self.clear_failed_start();
                                return Err(EngineError::from_cold_start(err));
                            }
                        }
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
        // Both seeds are stamped from the owner-vouched re-point the cold-seed
        // installed the floors from, and which the adopt and the owner-write-blob
        // AAD then bound to — the epochs they belong to, not a later floor read
        // (see `deposit_seed`).
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
        // The gate-passing base becomes the state law's left operand (reads render
        // this ⊕ the pending-op overlay). The resolved root name — the vault
        // pointer's `currentRoot` — drives the resolve-tick loop; `None` on an
        // empty chain, where the tick loop stays a dormant no-op.
        let mut root_name = outcome
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
        // A just-provisioned vault has no adopt to surface its seeds — this run
        // minted them — so they deposit here, stamped at the epochs its own
        // re-point vouches and the floors it seeded from them.
        if let Some(provisioned) = provisioned {
            deposit_seed(
                &self.scope_read_seeds,
                root_scope_id,
                provisioned.read_scope_seed,
                Some(provisioned.repoint.min_read_epoch),
            );
            deposit_write_seed(
                &self.scope_write_seeds,
                root_scope_id,
                provisioned.write_scope_seed,
                Some(&provisioned.root_name),
                Some(provisioned.repoint.write_epoch),
            );
            root_name = Some(provisioned.root_name);
        }
        *self.snapshot.borrow_mut() = outcome.base;
        // A successful cold start is a successful reconcile: stamp it so the
        // ladder starts Fresh rather than Reconciling.
        self.sync_status.borrow_mut().last_success = Some(self.seams.scheduler.now());

        // A crash between staging a version's blocks and journaling its op
        // leaves them referenced by nothing, so cold start is the first place
        // that residue can be reclaimed.
        collect_orphans(&self.seams.staging_store, &self.live_blocks).await;

        self.spawn_liveness_loop(api.clone());
        self.spawn_resolve_tick_loop(root_name, api.clone());
        self.api = Some(api);
        self.started = true;
        Ok(())
    }

    /// Whether this session holds the root scope's write seed — the material a
    /// publish needs. `false` means the vault is unprovisioned (or held
    /// keyless): reads paint and ops queue, but nothing will publish until a
    /// later `start` mints it. The event stream announces the transition
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
        self.accelerator_bearer.seal();
        // Every parked manual refresh fails now: no pass is left to answer it.
        self.manual_refresh.close();
        if let Ok(mut enc_subkey) = self.tick_enc_subkey.try_borrow_mut() {
            *enc_subkey = None;
        }
        if let Ok(mut placement) = self.placement.try_borrow_mut() {
            *placement = None;
        }
        if let Ok(mut held) = self.held_records.try_borrow_mut() {
            held.clear();
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
    /// record plane, off the session `start` has already derived. Called a
    /// second time when a mint discovers the account moved on, so the chain that
    /// reaches a live vault is one chain rather than two spellings of it.
    async fn run_cold_start(&self, root: NodeId) -> Result<ColdStartOutcome, ColdStartError> {
        let session = self.session.as_ref().ok_or(ColdStartError::NotStarted)?;
        let owner_identity = session.owner_identity();
        let pointer_fetch = RecordPointerFetch::new(&self.seams.record_transport);
        let adopter = RootAdopter::new(
            &self.gateway,
            &self.seams.http,
            &self.seams.floor_store,
            session.enc_subkey(),
            &owner_identity,
            root.0,
        );
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

    /// Fail-closed symmetry with the login path: clear the derived session and
    /// the placement decision beside it, so no key material stays resident and
    /// the engine reports unstarted. The access token login already stored
    /// outlives the dropped client in the shared bearer cell, so it is dropped
    /// here by name.
    fn clear_failed_start(&mut self) {
        self.session = None;
        *self.placement.borrow_mut() = None;
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
    where
        T::RecordTransport: Clone + 'static,
        T::Scheduler: Clone + 'static,
    {
        let session = self.session.as_ref().expect("session set by start");
        let owner_identity = session.owner_identity();
        let publisher = VaultProvisionNet {
            transport: &self.seams.record_transport,
            adopter: &RootAdopter::new(
                &self.gateway,
                &self.seams.http,
                &self.seams.floor_store,
                session.enc_subkey(),
                &owner_identity,
                root_scope_id,
            ),
            api,
            floors: &self.seams.floor_store,
            scheduler: &self.seams.scheduler,
            profile: &self.profile,
        };
        provision_vault(
            &self.entropy,
            &OwnerSessionKeys::new(session),
            &publisher,
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

    /// Spawn the ~hourly liveness loop (blueprint/engine.md "Liveness"):
    /// actively-used vaults keep their own records alive off the injected
    /// scheduler, so no client depends on the API republisher. Each pass runs
    /// the keyless re-PUT (every held record, byte-for-byte) and then the
    /// sub-EOL seq+1 renewal (any name inside the 30-day EOL window). The task
    /// holds only `Rc`/seam-handle clones, so the engine may drop while it is
    /// parked; the alive latch then stops it.
    fn spawn_liveness_loop(&self, api: Rc<ApiClient<T::Http, T::CredentialStore>>)
    where
        T::Scheduler: Clone + 'static,
        T::RecordTransport: Clone + 'static,
        T::Http: Clone + 'static,
        T::CredentialStore: Clone + 'static,
        T::FloorStore: Clone + 'static,
    {
        let scheduler = self.seams.scheduler.clone();
        let transport = self.seams.record_transport.clone();
        let floors = self.seams.floor_store.clone();
        let profile = self.profile;
        let held = self.held_records.clone();
        let alive = self.alive.clone();
        let events = self.events.clone();
        self.seams.scheduler.spawn(Box::pin(async move {
            run_liveness_loop(&scheduler, RE_PUT_INTERVAL, || async {
                if !alive.get() {
                    return LivenessControl::Stop;
                }
                let records: Vec<HeldRecord> = held.borrow().values().cloned().collect();
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
    /// `root_name` is the vault pointer's resolved `currentRoot`; `None` (an empty
    /// chain) spawns nothing — there is no root to poll until a later start
    /// rediscovers one.
    fn spawn_resolve_tick_loop(
        &self,
        root_name: Option<IpnsName>,
        api: Rc<ApiClient<T::Http, T::CredentialStore>>,
    ) where
        T::Scheduler: Clone + 'static,
        T::RecordTransport: Clone + 'static,
        T::Http: Clone + 'static,
        T::CredentialStore: Clone + 'static,
        T::FloorStore: Clone + 'static,
        T::SnapshotCache: Clone + 'static,
        T::StagingStore: Clone + 'static,
    {
        let (Some(root_name), Some(session)) = (root_name, self.session.as_ref()) else {
            return;
        };
        // Least privilege: the pass needs the enc subkey and the (public) owner
        // verifier, never the login secret or the pointer seeds beside them.
        *self.tick_enc_subkey.borrow_mut() = Some(session.enc_subkey().clone());
        let tick_enc_subkey = self.tick_enc_subkey.clone();
        let scheduler = self.seams.scheduler.clone();
        let staging = self.seams.staging_store.clone();
        let entropy = self.entropy.clone();
        let scope_write_seeds = self.scope_write_seeds.clone();
        let dead_letters = self.dead_letters.clone();
        let blocked = self.blocked.clone();
        let pending_reclaim = self.pending_reclaim.clone();
        let content_profile = self.content_profile;
        let orphan_heads = self.orphan_heads.clone();
        let cancels = self.cancels.clone();
        let live_blocks = self.live_blocks.clone();
        let transport = self.seams.record_transport.clone();
        let snapshot_cache = self.seams.snapshot_cache.clone();
        let floors = self.seams.floor_store.clone();
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
        let focus_refreshed = self.focus_refreshed.clone();
        let profile = self.profile;
        let interval = self.profile.poll_cadence;
        let owner_identity = session.owner_identity();
        // The vault's own root scope and root node are the anchored all-zero id16
        // (the cold-start bootstrap anchor): the adopter's scope binding and the
        // held-set fallback key.
        let root_id = self.snapshot.borrow().root.0;

        let manual = self.manual_refresh.clone();
        manual.arm();

        self.seams.scheduler.spawn(Box::pin(async move {
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
                let decision = placement.borrow().clone();
                let Some(decision) = decision else {
                    return TickControl::Stop;
                };
                // Before the steady-state hold consults them: a floor raised
                // since the last pass revokes the seeds this pass would
                // otherwise read and seal under. The floors it reports stamp
                // whatever this pass's own resolve recovers.
                let floors_before =
                    refresh_seed_floors(&floors, &root_id, &scope_read_seeds, &scope_write_seeds)
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
                // The focus window's folders below the root — the read leg for a
                // subtree this device did not author. It runs before the drain,
                // so the queue rebases onto the deepest state this pass
                // reconciled, not just the root's.
                let open = focus_folders(&base.borrow(), &focus.borrow());
                let mut folder_verdict = RefreshVerdict::Reconciled;
                if let Some(read_seed) = &read_seed
                    && !open.is_empty()
                {
                    let report = FolderRefresh {
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
                    }
                    .run(&open)
                    .await;
                    stamp_focus_refreshed(&focus_refreshed, &open, scheduler.now());
                    if report.changed {
                        let _ = events.unbounded_send(Event::SnapshotUpdated);
                    }
                    folder_verdict = report.verdict;
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
                        content_profile: &content_profile,
                        entropy: &entropy,
                        base: &base,
                        held: &held,
                        blocked: &blocked,
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
        if !self.started {
            return Err(EngineError::NotStarted);
        }
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
                // This session holds one scope, so every relocation it can form
                // stays inside it.
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
                .map_err(|err| match err {
                    ContactStoreError::Import(e @ CodecError::Malformed(_)) => {
                        EngineError::MalformedInput { check: e.check() }
                    }
                    ContactStoreError::Full => EngineError::MalformedInput {
                        check: "contact-book-full",
                    },
                    ContactStoreError::Encode(_) => EngineError::MalformedInput {
                        check: "contact-book-unstorable",
                    },
                    ContactStoreError::Seam(e) => EngineError::Seam {
                        message: e.message().to_owned(),
                    },
                    ContactStoreError::Entropy(e) => EngineError::from_entropy(e),
                    // A seal refusal is deterministic in the book it was handed,
                    // so it joins `Encode` as an input the host must change —
                    // never `Seam`, whose retry would never converge.
                    ContactStoreError::Seal(e) => EngineError::MalformedInput { check: e.check() },
                    // A rejected binding, and a stored book this build
                    // cannot read: both are fail-closed trust verdicts, not
                    // outages a host should retry.
                    other => EngineError::TrustViolation {
                        message: other.to_string(),
                    },
                })
            }
            Command::ManualRefresh => self.manual_refresh().await.map(|()| CommandOutcome::Done),
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
        let failed = |message: &str| EngineError::RefreshFailed {
            message: message.to_owned(),
        };
        let verdict = self.manual_refresh.request().ok_or_else(|| {
            // The loop does not spawn without a root name, and an unprovisioned
            // vault has none — so say that, rather than reporting the missing
            // loop and leaving the host to guess why its refresh does nothing.
            failed(if self.is_provisioned() {
                "no sync loop is running to force a pass"
            } else {
                "this account has no vault yet: a later start mints one"
            })
        })?;
        match verdict.await {
            Ok(RefreshVerdict::Reconciled) => Ok(()),
            Ok(RefreshVerdict::Unreachable) => {
                Err(failed("no endpoint served a record this pass could adopt"))
            }
            // Fail-closed, and reported as the verdict it is: a host retries
            // availability and must never retry a rejection (rule 6).
            Ok(RefreshVerdict::Rejected) => Err(EngineError::TrustViolation {
                message: "the record plane served a record the adoption gate rejected".to_owned(),
            }),
            Err(_) => Err(failed("the sync loop stopped before the pass ran")),
        }
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
        if !self.started {
            return Err(EngineError::NotStarted);
        }
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
        // Only the predicate leaves the borrow: cloning the placement would copy
        // the member's provider bearer on every write.
        let hosted_leg = match self.placement.borrow().as_ref() {
            None => return Err(EngineError::NotStarted),
            Some(Err(refusal)) => return Err(EngineError::NoPlacement { refusal: *refusal }),
            Some(Ok(placement)) => placement.has_hosted_leg(),
        };
        let Some(api) = self.api.as_ref() else {
            return Ok(());
        };
        let Ok(quota) = api.quota().await else {
            return Ok(());
        };
        // The account's flag is two-state where the mode is three and dual has
        // no server representation, so `byo=true` is exactly `External`. The
        // vaulted mode is the source of truth; the flag is latched only once the
        // PATCH lands, so two devices still cannot flap it per file while a
        // transient failure stays retryable — the hosted ingress rejects a BYO
        // account, so an unreconciled flag fails every hosted upload the session
        // makes.
        if !self.byo_reconciled.get()
            && quota.advisory == hosted_leg
            && api.set_byo(!hosted_leg).await.is_ok()
        {
            self.byo_reconciled.set(true);
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
        if !self.started {
            return Err(EngineError::NotStarted);
        }
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
        if !self.started {
            return Err(EngineError::NotStarted);
        }
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
        if !self.started {
            return Err(EngineError::NotStarted);
        }
        Ok(EngineView {
            rendered: self.render().await?,
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
        if !self.started {
            return Err(EngineError::NotStarted);
        }
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
                name: child.name.clone(),
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
                    .map(|meta| meta.name.clone())
                    .unwrap_or_default(),
            })
            .collect();
        let folder_name = rendered
            .node(folder)
            .map(|meta| meta.name.clone())
            .unwrap_or_default();
        let dead_letters = dead
            .iter()
            .map(|(op_id, (_, reason))| DeadLetter {
                op_id: *op_id,
                reason: *reason,
            })
            .collect();
        let status = self.sync_status.borrow();
        let staleness = classify(
            self.seams.scheduler.now(),
            status.last_success,
            status.reconcile_in_flight,
            Connectivity::Online,
            &self.profile,
        );
        Ok(SnapshotView {
            root: rendered.root,
            folder,
            folder_name,
            children,
            ancestors,
            dead_letters,
            blocked: *self.blocked.borrow(),
            retained_records: scan.retained,
            staleness,
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
        if !self.started {
            return Err(EngineError::NotStarted);
        }
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
        if !self.started {
            return Err(EngineError::NotStarted);
        }
        // Reserved before the resolve, so an open past the ceiling spends no
        // network and no open that reaches the insert can be refused there.
        let slot =
            StreamSlot::acquire(&self.streams.borrow().live).ok_or(EngineError::TooManyStreams)?;
        let (version, version_count) = self.head_version(node).await?;
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
        if !self.started {
            return Err(EngineError::NotStarted);
        }
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
        let queued = self.pending_ops().await?;
        let authored = queued.iter().rev().find_map(|op| {
            (op.target == node)
                .then(|| op.staged_content())
                .flatten()
                .map(|content| content.root_cid.clone())
        });
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
        let mut id = [0u8; 16];
        self.entropy
            .borrow_mut()
            .fill(&mut id)
            .map_err(|e| EngineError::Entropy {
                message: e.message().to_owned(),
            })?;
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
        let mut ephemeral_scalar = Zeroizing::new([0u8; 32]);
        self.entropy
            .borrow_mut()
            .fill(ephemeral_scalar.as_mut())
            .map_err(|e| EngineError::Entropy {
                message: e.message().to_owned(),
            })?;
        Ok(RecordSeal {
            owner_enc_secret,
            ephemeral_scalar,
        })
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

    use crate::seams::{CredentialStore, HttpResponse, UnixMillis};
    use crate::testkit::{FakeDevice, FakeSeamTypes, FakeWorld, SeededEntropy, block_on};

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
            json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "isNewUser": true }),
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
            json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "isNewUser": true }),
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

    /// The read accelerator is CipherBox's own token-authed gateway, so the
    /// credential it presents is the session's — bound by login rather than
    /// configured, and gone with the engine.
    #[test]
    fn login_binds_the_session_token_to_the_accelerator_and_shutdown_drops_it() {
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
        assert!(!accelerator_bearer.is_held(), "no credential before login");

        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": LOGIN_CHALLENGE_FIXTURE, "expiresAt": "2099-01-01T00:00:00Z" }),
        ));
        device.http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "isNewUser": true }),
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
            Some("jwt-1"),
            "the accelerator leg presents the session access token"
        );

        drop(engine);
        assert!(
            !accelerator_bearer.is_held(),
            "a parked tick's gateway clone outlives the engine; the token must not"
        );
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
            json!({ "accessToken": "jwt-siwe", "refreshToken": "b".repeat(64) }),
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

    #[test]
    fn non_metadata_commands_stay_unimplemented() {
        let (mut engine, _events) = started();
        let out = block_on(engine.command(Command::RotateNow {
            node: NodeId([1; 16]),
        }));
        assert_eq!(
            out,
            Err(EngineError::Unimplemented {
                command: "rotateNow"
            })
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
        use crate::sync::pointer::{SessionRole, seal_repoint, vault_pointer_name};
        use crate::testkit::{
            FakeDevice, OWNER_ROOT_EPOCH as EPOCH, OWNER_ROOT_SCOPE_SEED as SCOPE_SEED,
            OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED, OwnerRootSpec, owner_root_fixture,
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

        /// Poll every spawned loop task once with a no-op waker. Manual re-polls
        /// drive the virtual clock's parked sleeps (the loops never yield inside a
        /// pass over the synchronous fakes), so this is the sound driver for the
        /// fire-and-forget loops — auto-advance would spin an infinite pass loop.
        fn poll_each(tasks: &mut [BoxedTask]) -> Vec<Poll<()>> {
            let mut cx = Context::from_waker(Waker::noop());
            tasks.iter_mut().map(|t| t.as_mut().poll(&mut cx)).collect()
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
            poll_each(&mut tasks); // park each loop at its first sleep
            world.scheduler.advance(engine.profile().poll_cadence);
            poll_each(&mut tasks); // the resolve tick runs one pass

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
            poll_each(&mut tasks);
            (engine, events, tasks)
        }

        /// Advance one poll cadence and run one pass of each loop, serving the
        /// head block the root record anchors.
        fn tick(world: &FakeWorld, device: &FakeDevice, tasks: &mut [BoxedTask]) {
            let (head_block, _, _) = owner_root();
            device.http.enqueue_response(head_response(&head_block));
            world.scheduler.advance(SyncTimingProfile::CI.poll_cadence);
            poll_each(tasks);
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
                poll_each(&mut tasks);

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
            poll_each(&mut tasks); // park each loop at its first sleep

            // CI profile: 1 s poll, 3 s stale_after. With no reachable head
            // block, each tick fails to reconcile and last_success stays at 0.
            world.scheduler.advance(Duration::from_secs(1));
            poll_each(&mut tasks);
            assert_eq!(
                drain(&mut events),
                vec![Event::StalenessChanged {
                    level: Staleness::Fresh
                }],
                "the first classified rung is reported"
            );
            world.scheduler.advance(Duration::from_secs(1));
            poll_each(&mut tasks);
            assert_eq!(drain(&mut events), vec![], "no re-emit within a rung");
            world.scheduler.advance(Duration::from_secs(1)); // t=3 s ≥ stale_after
            poll_each(&mut tasks);
            assert_eq!(
                drain(&mut events),
                vec![Event::StalenessChanged {
                    level: Staleness::Stale
                }]
            );
            world.scheduler.advance(Duration::from_secs(1));
            poll_each(&mut tasks);
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
            poll_each(&mut tasks);
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
            for task in &mut tasks {
                let _ = task.as_mut().poll(&mut cx); // park both at their first sleep
            }
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
            let after = poll_each(&mut tasks);
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
                poll_each(&mut tasks); // park each loop at its first sleep
                world.scheduler.advance(engine.profile().poll_cadence);
                poll_each(&mut tasks); // the resolve tick runs one pass
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
