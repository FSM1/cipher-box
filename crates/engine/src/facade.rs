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

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{ReadBody, seal_content_key};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use futures_channel::mpsc;
use futures_core::Stream;
use zeroize::Zeroizing;

use crate::api::{ApiClient, ApiError, IdentityChallengeSigner};
use crate::content::budget::{Refusal, ReservationId};
use crate::content::{
    ContentKey, ContentProfile, ContentWriter, Gateway, GatewayConfig, OpenError, Refused,
    SealError, StagingLedger, open_content, sealed_total_bytes,
};
use crate::entropy::Entropy;
use crate::gate::{GateError, floor};
use crate::hex::hex_lower;
use crate::net::{
    Adopter, ChildAdopter, EolRenewResult, FolderRefresh, FolderRefreshReport, HeldMaterial,
    HeldRecord, HeldRecords, LivenessControl, PublishError, PublishOutcome, RE_PUT_INTERVAL,
    RecordPointerFetch, ResolveOutcome, RootAdopter, eol_renew_pass, keyless_re_put,
    refresh_base_from_outcome, resolve, resolve_and_hold, run_liveness_loop,
};
use crate::profile::SyncTimingProfile;
use crate::rotation::derive_write_name;
use crate::seams::{OpId, Scheduler, SeamError, SeamSet, SeamTypes, StagingStore, UnixMillis};
use crate::session::SessionIdentity;
use crate::storage_policy::StoragePolicy;
use crate::sync::boot::{ColdStartError, ColdStartOutcome, ColdStartParams, cold_start};
use crate::sync::drain::{Drain, DrainReport, DrainScope};
use crate::sync::model::{NodeMeta, Snapshot, collation_key};
use crate::sync::op::{NewNode, Op, Replaced, StagedContent};
use crate::sync::overlay::apply_overlay;
use crate::sync::pointer::PointerFetch;
use crate::sync::project::project_child_version;
use crate::sync::rebase::{QueueScan, QueueScanMemo, decode_queue};

pub use crate::sync::drain::BlockedOp;
pub use crate::sync::rebase::DeadLetterReason;
use crate::sync::record::{RecordReader, RecordSeal};
use crate::sync::staging::stage_op;
use crate::sync::staleness::{Connectivity, classify};
use crate::sync::tick::{FocusWindow, focus_folders, on_access_refresh_due};

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
/// is one chunk however large the file (blueprint/engine.md "Content plane";
/// #815).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WriteHandle(pub u64);

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
/// "this queued change is corrupt" call for different user actions (#859).
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
    /// Direct children, deterministically ordered by node id.
    pub children: Vec<SnapshotChild>,
    /// Ancestor trail from the folder's parent up to and including the root,
    /// nearest first.
    pub ancestors: Vec<Breadcrumb>,
    /// Every retained dead-lettered op, with its reason.
    pub dead_letters: Vec<DeadLetter>,
    /// The over-quota hold, if the drain has one. Read here and never as an
    /// event: this is a state that *clears*, and a lost "resumed" would strand
    /// the UI on a blockage that is gone (#841).
    pub blocked: Option<BlockedOp>,
    /// How many durable queue entries this session holds but cannot read
    /// (CONTEXT.md "Retained record"). Deliberately unattributed — it says the
    /// device is not empty, never whose work it holds — and it exists so an
    /// over-budget rejection on an apparently empty vault has an explanation
    /// (#832 §6 residual).
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
    /// `pub(crate)` so the secret never leaves engine memory; the only caller
    /// is [`SessionIdentity::derive`](crate::session::SessionIdentity::derive).
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for LoginSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginSecret(redacted)")
    }
}

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
        /// Why it dead-lettered — the four reasons need four different messages
        /// (#859).
        reason: DeadLetterReason,
    },
    /// Attributable abuse: owner-blob / ascent-link / unseal cross-check
    /// disagreement (#39 D6) — never a silent failure.
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
    /// (`Command::CancelUpload`, #869).
    UploadCancelled,
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
    /// The content's DAG root declared a format version this build cannot
    /// read; see [`DagError::UnsupportedFormat`](crate::DagError).
    UnsupportedContentFormat {
        /// The version the root declared.
        version: u64,
    },
    /// The command's pipeline slice has not landed yet (scaffold state).
    Unimplemented {
        /// [`Command::name`] of the rejected command.
        command: &'static str,
    },
    /// A write was refused for want of room. The cause names which budget and
    /// which user action, and `available` is the room left — never the whole
    /// budget, which a caller cannot act on when other writes already hold most
    /// of it (#829).
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
    /// a success (#830).
    ContentSizeMismatch {
        /// The size declared at `beginWrite`.
        declared: u64,
        /// The total the pushes actually carried.
        observed: u64,
    },
    /// A write-handle call named a handle this engine does not hold — never
    /// minted, or already committed, failed, or aborted.
    UnknownWriteHandle,
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
            EngineError::ContentSizeMismatch { declared, observed } => write!(
                f,
                "the file changed while it was being read: {declared} bytes were declared and {observed} arrived"
            ),
            EngineError::UnknownWriteHandle => f.write_str("unknown write handle"),
            EngineError::ContentTooLarge { check } => write!(
                f,
                "this file is too large to store as a single version: [{check}]"
            ),
            EngineError::ContentKeySealFailed { check } => {
                write!(f, "content key seal failed: [{check}]")
            }
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

/// Stamp every folder a focus pass merged with the caller's clock reading, so
/// the on-access threshold measures from the last gate-passing merge. A folder
/// the pass could not merge keeps its old stamp and stays due.
fn stamp_focus_refreshed(
    stamps: &RefCell<BTreeMap<NodeId, UnixMillis>>,
    report: &FolderRefreshReport,
    now: UnixMillis,
) {
    let mut stamps = stamps.borrow_mut();
    for folder in &report.refreshed {
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
    cell: &RefCell<ScopeWriteSeeds>,
    scope_id: [u8; 16],
    seed: Zeroizing<[u8; 32]>,
    root_name: Option<&IpnsName>,
) {
    if root_name.is_some_and(|name| derive_write_name(&seed, &scope_id) == *name) {
        cell.borrow_mut().insert(scope_id, seed);
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

/// The engine's in-memory per-scope read-seed cell: scope id → the recovered
/// scope read seed (zeroized on removal/drop).
type ScopeReadSeeds = BTreeMap<[u8; 16], Zeroizing<[u8; 32]>>;

/// The engine's in-memory per-scope write-seed cell: scope id → the recovered
/// scope write seed (zeroized on removal/drop).
type ScopeWriteSeeds = BTreeMap<[u8; 16], Zeroizing<[u8; 32]>>;

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
    /// Seeds, nonces, jitter, and command-path node-id minting. Shared with the
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
    /// The API base URL the liveness loop's [`ApiClient`] registers renewals
    /// against. Empty until the auth/config slice supplies it; the register-first
    /// renewal is a no-op against an empty base until then.
    api_base_url: String,
    /// The resolved content read-source set, built once from the injected
    /// [`GatewayConfig`] at construction. Empty (dormant) until the host supplies
    /// endpoints; reads then fail closed as [`ReadError`](crate::ReadError)`::Unavailable`.
    /// Read by the cold-start [`RootAdopter`] and the resolve-tick driver's
    /// per-pass adopter.
    gateway: Gateway,
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
    scope_read_seeds: Rc<RefCell<ScopeReadSeeds>>,
    /// Per-scope write seeds recovered by gate-passing adopts (the
    /// owner-write-blob seed), keyed by scope id. In-memory only, exactly like
    /// [`scope_read_seeds`](Self::scope_read_seeds); the drain derives each new
    /// node's `ipnsName` and its narrow per-name signer from them.
    scope_write_seeds: Rc<RefCell<ScopeWriteSeeds>>,
    /// The open focus window ([`Command::SetFocus`]): the folder the host has
    /// open, whose record and whole ancestor chain every resolve tick refreshes.
    /// Shared with the tick loop, which reads it on each pass.
    focus: Rc<RefCell<FocusWindow>>,
    /// When each focus folder last merged a gate-passing body, so a navigation
    /// inside the staleness threshold renders state already held instead of
    /// re-resolving (blueprint/engine.md: refresh on access past the threshold).
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
    /// Session-alive latch: cleared on drop so the spawned liveness loop
    /// stops at its next wake instead of re-PUTting after the engine is gone.
    alive: Rc<Cell<bool>>,
    /// The cold-start session identity, derived from the login secret at
    /// [`start`](Self::start). `None` until then; the single place derived key
    /// material lives once the engine is live. The resolve/publish/rotation
    /// slices read every signer from here. Behind an [`Rc`] so the spawned
    /// liveness loop shares it for the sub-EOL renewal's per-name signers.
    session: Option<Rc<SessionIdentity>>,
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
        api_base_url: String,
        gateway: GatewayConfig,
    ) -> (Self, EventStream) {
        let (events, receiver) = mpsc::unbounded();
        (
            Self {
                seams,
                entropy: Rc::new(RefCell::new(entropy)),
                profile,
                storage_policy,
                content_profile,
                writes: RefCell::new(LiveWrites::default()),
                api_base_url,
                gateway: gateway.into_gateway(),
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
                alive: Rc::new(Cell::new(true)),
                session: None,
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
        // Pure derivation from the injected secret — no clock, no RNG — then
        // the secret zeroizes on drop here, at its terminal owner.
        let session = Rc::new(SessionIdentity::derive(&secret)?);
        drop(secret);

        // The one shared client for login, publish, and renewal. Login is
        // fail-closed: a rejected login returns before the session is committed
        // or any loop spawns, so the loop never runs unauthenticated (rules 3/6).
        // An empty base URL is the pre-integration dormant state (field doc) — no
        // API to authenticate against, so login is skipped.
        let api = Rc::new(ApiClient::new(
            self.seams.http.clone(),
            self.seams.credential_store.clone(),
            self.api_base_url.clone(),
        ));
        if !self.api_base_url.is_empty() {
            let signer = IdentityChallengeSigner::from_signer(session.identity().clone());
            api.login_identity(&signer)
                .await
                .map_err(EngineError::from_api)?;
        }

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
        let cold_start = {
            let session = self.session.as_ref().expect("session set above");
            let owner_identity = session.owner_identity();
            let pointer_fetch = RecordPointerFetch::new(&self.seams.record_transport);
            let adopter = RootAdopter::new(
                &self.gateway,
                &self.seams.http,
                &self.seams.floor_store,
                session.enc_subkey(),
                &owner_identity,
                root_scope_id,
            );
            self.cold_start_data_path(
                &pointer_fetch,
                &adopter,
                &owner_identity,
                root_scope_id,
                POINTER_PAYLOAD_VERSION,
                root,
            )
            .await
        };
        let mut outcome = match cold_start {
            Ok(outcome) => outcome,
            Err(err) => {
                // Fail-closed symmetry with the login path: clear the derived
                // session so no key material stays resident and the engine reports
                // unstarted.
                self.session = None;
                return Err(EngineError::from_cold_start(err));
            }
        };
        // A gate-passing root adopt surfaced the scope read seed: deposit it in
        // the in-memory per-scope cell the child read pipeline derives from.
        if let Some(seed) = outcome.read_scope_seed.take() {
            self.scope_read_seeds
                .borrow_mut()
                .insert(root_scope_id, seed);
        }
        // The gate-passing base becomes the state law's left operand (reads render
        // this ⊕ the pending-op overlay). The resolved root name — the vault
        // pointer's `currentRoot` — drives the resolve-tick loop; `None` on an
        // empty chain, where the tick loop stays a dormant no-op.
        let root_name = outcome
            .vault_pointer
            .as_ref()
            .map(|vp| vp.repoint.current_root.clone());
        // The same adopt recovered the scope write seed: the drain derives every
        // new node's `ipnsName` and its narrow per-name signer from it.
        if let Some((scope_id, seed)) = outcome.write_scope_seed.take() {
            deposit_write_seed(&self.scope_write_seeds, scope_id, seed, root_name.as_ref());
        }
        *self.snapshot.borrow_mut() = outcome.base;
        // A successful cold start is a successful reconcile: stamp it so the
        // ladder starts Fresh rather than Reconciling.
        self.sync_status.borrow_mut().last_success = Some(self.seams.scheduler.now());

        self.spawn_liveness_loop(api.clone());
        self.spawn_resolve_tick_loop(root_name, api.clone());
        self.api = Some(api);
        self.started = true;
        Ok(())
    }

    /// The live session identity, once [`start`](Self::start) has derived it.
    /// `pub(crate)`: the in-crate pipeline (resolve, publish, rotation, the
    /// liveness loop) reads its signers here; hosts wrap the facade and never
    /// hold key material.
    #[allow(dead_code)]
    pub(crate) fn session(&self) -> Option<&SessionIdentity> {
        self.session.as_deref()
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
        // re-decoded and re-emitted on every boot (#768).
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
        let (Some(root_name), Some(session)) = (root_name, self.session.clone()) else {
            return;
        };
        let scheduler = self.seams.scheduler.clone();
        let staging = self.seams.staging_store.clone();
        let entropy = self.entropy.clone();
        let scope_write_seeds = self.scope_write_seeds.clone();
        let dead_letters = self.dead_letters.clone();
        let blocked = self.blocked.clone();
        let transport = self.seams.record_transport.clone();
        let snapshot_cache = self.seams.snapshot_cache.clone();
        let floors = self.seams.floor_store.clone();
        let http = self.seams.http.clone();
        let gateway = self.gateway.clone();
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

        self.seams.scheduler.spawn(Box::pin(async move {
            run_liveness_loop(&scheduler, interval, || async {
                if !alive.get() {
                    return LivenessControl::Stop;
                }
                let adopter = RootAdopter::new(
                    &gateway,
                    &http,
                    &floors,
                    session.enc_subkey(),
                    &owner_identity,
                    root_id,
                );
                // Own-root material: the write-scope seed the owner cannot
                // re-derive rides the adopt (recovered from the owner-write-blob),
                // so the caller-side seed is `None` and the gate's authenticated
                // node id keys the hold. A resolve/gate failure is availability —
                // it never stops the loop (blueprint/engine.md "Liveness").
                let material = HeldMaterial {
                    node_id: root_id,
                    write_scope_seed: None,
                    content_cids: Vec::new(),
                };
                // A gate-passing `Adopted` repaints the shared base cell and emits
                // `SnapshotUpdated`; `Current`/`NoUpdate`/`TrustViolation` leave
                // last-known-good intact (fail-closed for data). (surfacing: #796)
                sync_status.borrow_mut().reconcile_in_flight = true;
                let resolved = resolve_and_hold(
                    &transport,
                    &snapshot_cache,
                    &adopter,
                    &root_name,
                    &held,
                    &material,
                )
                .await
                .map(|held_resolve| {
                    // A gate-passing adopt re-surfaces the scope seeds: refresh
                    // the in-memory per-scope cells the child read pipeline and
                    // the drain derive from.
                    if let Some(seed) = held_resolve.read_scope_seed {
                        scope_read_seeds.borrow_mut().insert(root_id, seed);
                    }
                    if let Some((node_id, seed)) = held_resolve.write_scope_seed {
                        deposit_write_seed(&scope_write_seeds, node_id, seed, Some(&root_name));
                    }
                    held_resolve.resolved
                });
                if let Ok(resolved) = &resolved {
                    if refresh_base_from_outcome(&base, NodeId(root_id), &resolved.outcome) {
                        let _ = events.unbounded_send(Event::SnapshotUpdated);
                    }
                }
                let read_seed = scope_read_seeds.borrow().get(&root_id).cloned();
                // The focus window's folders below the root — the read leg for a
                // subtree this device did not author. It runs before the drain,
                // so the queue rebases onto the deepest state this pass
                // reconciled, not just the root's.
                let open = focus_folders(&base.borrow(), &focus.borrow());
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
                        scope_id: root_id,
                        scope_read_seed: read_seed,
                    }
                    .run(&open)
                    .await;
                    stamp_focus_refreshed(&focus_refreshed, &report, scheduler.now());
                    if report.changed {
                        let _ = events.unbounded_send(Event::SnapshotUpdated);
                    }
                }
                // The drain rides the same tick: it publishes onto exactly the
                // gate-passing state this pass just reconciled. Both scope seeds
                // are required — without them there is no name to publish under
                // and no key to seal with, so the queue simply waits.
                let write_seed = scope_write_seeds.borrow().get(&root_id).cloned();
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
                        profile: &profile,
                        entropy: &entropy,
                        base: &base,
                        held: &held,
                        blocked: &blocked,
                        events: &events,
                    }
                    .run(&DrainScope {
                        root: NodeId(root_id),
                        root_name: &root_name,
                        read_scope_seed: &read_seed,
                        write_scope_seed: &write_seed,
                        enc_secret: session.enc_subkey(),
                        owner_identity: &owner_identity,
                    })
                    .await;
                    surface_drain_report(&events, &dead_letters, &report);
                }
                // `Adopted`/`Current` are the reconciled outcomes: both prove the
                // record plane answered with gate-passing state, so both stamp
                // the ladder's `last_success` (#33 D4).
                let reconciled = matches!(
                    &resolved,
                    Ok(r) if matches!(
                        r.outcome,
                        ResolveOutcome::Adopted(_) | ResolveOutcome::Current { .. }
                    )
                );
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
                LivenessControl::Continue
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
    /// law), so an op rebases against the state the host saw. Content sealing,
    /// grants, rotation, and auth land with their own slices and stay
    /// [`EngineError::Unimplemented`].
    ///
    /// Returns the durable queue id of the staged op, so a host can correlate a
    /// later [`Event::DeadLetter`] or [`Event::OpProgress`] back to the call
    /// that made it; `None` for a command that queues nothing.
    pub async fn command(&mut self, command: Command) -> Result<Option<OpId>, EngineError> {
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
                // trailing bools: cross_scope=false, exits_granted_source=false — intra-scope pure relink
                let op = Op::relink(
                    node,
                    from_parent,
                    new_parent,
                    base_sequence,
                    authored_at,
                    false,
                    false,
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
                );
                self.stage_and_notify(&op).await
            }
            Command::SetFocus { node } => {
                self.focus.borrow_mut().open_folder = node;
                // Navigation is the tick model's second trigger source (#33 D2):
                // refresh the newly-focused chain now rather than waiting out a
                // poll cadence, and only past the staleness threshold — a repeat
                // visit renders the state already held.
                if self.refresh_focus_on_access(authored_at).await {
                    let _ = self.events.unbounded_send(Event::SnapshotUpdated);
                }
                Ok(None)
            }
            Command::SiweLogin { message, signature } => {
                let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
                api.siwe_login(&message, &hex_lower(&signature))
                    .await
                    .map_err(EngineError::from_api)?;
                Ok(None)
            }
            other => Err(EngineError::Unimplemented {
                command: other.name(),
            }),
        }
    }

    /// Refresh the focus window's folders that are past the on-access staleness
    /// threshold, returning whether the base changed. A folder refreshed inside
    /// the threshold is left alone — the window still rides every resolve tick.
    async fn refresh_focus_on_access(&self, now: UnixMillis) -> bool {
        let due: Vec<NodeId> = {
            let refreshed = self.focus_refreshed.borrow();
            focus_folders(&self.snapshot.borrow(), &self.focus.borrow())
                .into_iter()
                .filter(|folder| {
                    refreshed
                        .get(folder)
                        .is_none_or(|last| on_access_refresh_due(now, *last, &self.profile))
                })
                .collect()
        };
        if due.is_empty() {
            return false;
        }
        // The vault root scope: granted-subscope focus is a later slice. A
        // missing read seed is missing held material (availability), never a
        // trust verdict — the window simply does not refresh this pass.
        let scope_id = self.snapshot.borrow().root.0;
        let Some(scope_read_seed) = self.scope_read_seeds.borrow().get(&scope_id).cloned() else {
            return false;
        };
        let report = FolderRefresh {
            transport: &self.seams.record_transport,
            snapshot_cache: &self.seams.snapshot_cache,
            http: &self.seams.http,
            floors: &self.seams.floor_store,
            gateway: &self.gateway,
            base: &self.snapshot,
            scope_id,
            scope_read_seed: &scope_read_seed,
        }
        .run(&due)
        .await;
        stamp_focus_refreshed(&self.focus_refreshed, &report, now);
        report.changed
    }

    // -----------------------------------------------------------------------
    // Write handles: the content path across the facade (#815).
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
        if let WriteTarget::Version { node } = &target {
            match self.render().await?.node(*node).map(|meta| meta.kind) {
                Some(NodeKind::Folder) => return Err(EngineError::NotAFile),
                Some(_) => {}
                None => return Err(EngineError::UnknownNode),
            }
        }
        let requested = sealed_total_bytes(size, &self.content_profile).map_err(|error| {
            EngineError::ContentTooLarge {
                check: error.check(),
            }
        })?;
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
        writes.open.insert(
            handle,
            LiveWrite {
                node,
                target,
                declared_size: size,
                reservation,
                writer,
            },
        );
        Ok(handle)
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
                self.seams
                    .staging_store
                    .put_staged_bytes(&leaf.cid, &leaf.sealed)
                    .await
                    .map_err(EngineError::from_seam)?;
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
    /// would publish a short version as a success (#830).
    pub async fn commit_write(&mut self, handle: WriteHandle) -> Result<OpId, EngineError> {
        if !self.started {
            return Err(EngineError::NotStarted);
        }
        // Taken out of the ledger up front: from here the handle is spent
        // whatever happens, and its reservation must not outlive it.
        let write = self.take_write(handle)?;
        let mut staged = write.writer.staged_leaf_cids().to_vec();
        match self.commit_write_inner(write, &mut staged).await {
            Ok(op_id) => {
                let _ = self.events.unbounded_send(Event::SnapshotUpdated);
                Ok(op_id)
            }
            Err(error) => {
                self.release_blocks(&staged).await;
                Err(error)
            }
        }
    }

    /// Abandon a write handle: release its reservation and the blocks it staged.
    /// Idempotent — an unknown handle is already gone.
    pub async fn abort_write(&mut self, handle: WriteHandle) {
        let Ok(write) = self.take_write(handle) else {
            return;
        };
        self.release_blocks(write.writer.staged_leaf_cids()).await;
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

    /// Drop staged blocks no op will ever reference. Best-effort: a failed
    /// removal is orphan residue a later GC pass collects.
    async fn release_blocks(&self, keys: &[Vec<u8>]) {
        for key in keys {
            let _ = self.seams.staging_store.remove_staged_bytes(key).await;
        }
    }

    /// `staged` accumulates every block this commit puts into the store, so a
    /// failure after the tail or the root landed still releases them.
    async fn commit_write_inner(
        &self,
        write: LiveWrite,
        staged: &mut Vec<Vec<u8>>,
    ) -> Result<OpId, EngineError> {
        let LiveWrite {
            node,
            target,
            declared_size,
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
            staged.push(tail.cid.clone());
            self.seams
                .staging_store
                .put_staged_bytes(&tail.cid, &tail.sealed)
                .await
                .map_err(EngineError::from_seam)?;
        }
        let root_cid = finished.content.content_cid().to_vec();
        staged.push(root_cid.clone());
        self.seams
            .staging_store
            .put_staged_bytes(&root_cid, &finished.root_block)
            .await
            .map_err(EngineError::from_seam)?;

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
                Op::update_content(node, content, base_sequence, authored_at)
            }
        };
        let seal = self.record_seal()?;
        stage_op(&self.seams.staging_store, seal, &op)
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
        match self.read_content_inner(node).await {
            Ok((plaintext, size, modified_at, version_count)) => {
                // The verified head version is gate-passing state, so it may
                // legally touch the base node's projected size/mtime. Repaint
                // only on a real change — a repeat read must not cascade.
                if project_child_version(
                    &mut self.snapshot.borrow_mut(),
                    node,
                    size,
                    modified_at,
                    version_count,
                ) {
                    let _ = self.events.unbounded_send(Event::SnapshotUpdated);
                }
                self.emit_op_progress(node, OpPhase::DownloadCompleted, None);
                Ok(plaintext)
            }
            Err(err) => {
                self.emit_op_progress(node, OpPhase::DownloadFailed, Some(err.to_string()));
                Err(err)
            }
        }
    }

    /// The verified read pipeline behind [`read_content`](Self::read_content):
    /// base-snapshot lookup → gated child resolve →
    /// [`open_content`] (version-DAG fetch, per-leaf unseal, length
    /// cross-checks). Returns the plaintext plus the head version's
    /// `(size, modifiedAt)` and the body's version count.
    async fn read_content_inner(
        &self,
        node: NodeId,
    ) -> Result<(Vec<u8>, u64, u64, u64), EngineError> {
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
        let scope_read_seed = self
            .scope_read_seeds
            .borrow()
            .get(&scope_id)
            .cloned()
            .ok_or_else(|| EngineError::ContentUnavailable {
                message: "no read seed held for the node's scope".to_owned(),
            })?;
        let adopter = ChildAdopter::new(
            &self.gateway,
            &self.seams.http,
            &self.seams.floor_store,
            scope_id,
            scope_read_seed,
            node.0,
        );
        let resolved = resolve(
            &self.seams.record_transport,
            &self.seams.snapshot_cache,
            &adopter,
            &name,
        )
        .await
        .map_err(|e| EngineError::ContentUnavailable {
            message: e.message().to_owned(),
        })?;
        // One at-floor re-open serves both non-adopt outcomes: `Current` carries
        // the re-fetched bytes, `NoUpdate` falls back to the cached
        // last-known-good; neither advances a floor.
        let adopted = 'adopted: {
            let record_bytes = match resolved.outcome {
                ResolveOutcome::Adopted(adopted) => break 'adopted adopted,
                ResolveOutcome::TrustViolation(rejection) => {
                    return Err(EngineError::from_gate(GateError::Rejected(rejection)));
                }
                ResolveOutcome::Current { record_bytes } => record_bytes,
                ResolveOutcome::NoUpdate => {
                    resolved
                        .last_known_good
                        .ok_or_else(|| EngineError::ContentUnavailable {
                            message: "no record source reachable and no cached record".to_owned(),
                        })?
                }
            };
            adopter
                .open_at_floor(&name, &record_bytes)
                .await
                .map_err(EngineError::from_gate)?
        };

        let ReadBody::File { versions, .. } = adopted.read_body else {
            // The parent's child ref said file: a sealed folder body is a kind
            // transplant, fail-closed.
            return Err(EngineError::TrustViolation {
                message: "sealed body kind disagrees with the child ref".to_owned(),
            });
        };
        // Newest-first; head is current (crates/core/src/seal/body.rs).
        let Some(version) = versions.first() else {
            return Err(EngineError::ContentUnavailable {
                message: "file has no published content version".to_owned(),
            });
        };

        let plaintext = open_content(&self.gateway, &self.seams.http, version)
            .await
            .map_err(|e| match e {
                OpenError::Trust(message) => EngineError::TrustViolation { message },
                OpenError::Unavailable(message) => EngineError::ContentUnavailable { message },
                OpenError::UnsupportedFormat { version } => {
                    EngineError::UnsupportedContentFormat { version }
                }
            })?;
        Ok((
            plaintext,
            version.size,
            version.modified_at,
            versions.len() as u64,
        ))
    }

    /// Best-effort [`Event::OpProgress`] emission for a content read (a dropped
    /// receiver is fine).
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
    async fn stage_and_notify(&mut self, op: &Op) -> Result<Option<OpId>, EngineError> {
        let seal = self.record_seal()?;
        let op_id = stage_op(&self.seams.staging_store, seal, op)
            .await
            .map_err(EngineError::from_seam)?;
        // Best-effort push-invalidation trigger; a dropped receiver (host torn
        // down) is fine.
        let _ = self.events.unbounded_send(Event::SnapshotUpdated);
        Ok(Some(op_id))
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

impl<T: SeamTypes> Drop for Engine<T> {
    fn drop(&mut self) {
        // Signal the spawned liveness loop to stop; it holds only `Rc` clones,
        // so it outlives the engine unless the latch is cleared here.
        self.alive.set(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::{Value, json};

    use crate::seams::{CredentialStore, HttpResponse, UnixMillis};
    use crate::testkit::{FakeDevice, FakeSeamTypes, FakeWorld, SeededEntropy, block_on};

    /// A JSON HTTP response the scripted client decodes as a Nest body.
    fn json_response(status: u16, body: Value) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    /// An engine over a retained device (so the test scripts HTTP and inspects
    /// the credential store), against `base_url`.
    fn engine_over(base_url: &str) -> (Engine<FakeSeamTypes>, EventStream, FakeDevice) {
        let device = FakeWorld::new().device(b"alice-pk");
        let (engine, events) = Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
            ContentProfile::CI,
            StoragePolicy::CI,
            base_url.to_owned(),
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
            String::new(),
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
            String::new(),
            GatewayConfig::disabled(),
        );
        block_on(engine.start(LoginSecret::new(vec![secret_byte; 32]))).unwrap();
        engine
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
        let (mut engine, _events, device) = engine_over("http://api.test");
        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": "cipherbox-login:v2:abc", "expiresAt": "2099-01-01T00:00:00Z" }),
        ));
        device.http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "isNewUser": true }),
        ));

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
                .sign_detcbor(b"cipherbox-login:v2:abc")
                .to_compact(),
        );
        assert_eq!(login_body["signature"], expected);
    }

    #[test]
    fn start_login_failure_is_fail_closed() {
        let (mut engine, _events, device) = engine_over("http://api.test");
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
        // Empty base: `start` skips cold-start login, so only the SIWE exchange
        // is scripted here.
        let (mut engine, _events, device) = engine_over("");
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
    /// quotes the room left rather than the whole budget (#829).
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
            "the overlay renders the committed size (#830)"
        );
        assert!(drain(&mut events).contains(&Event::SnapshotUpdated));
    }

    /// The acceptance case: a backing file that shrinks mid-read must fail the
    /// commit, never publish a short version as a success (#830).
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

    // --- snapshot read surface ---

    mod snapshot_read {
        use super::*;

        use cipherbox_core::seal::{ChildRef, NodeKind as CoreNodeKind, ReadBody};

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
                    unknown: Vec::new(),
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
                unknown: Vec::new(),
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
        /// engine's command path, so the memoized queue scan (#880) has to key
        /// on the durable queue itself.
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
        use cipherbox_core::seal::ReadBody;
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
                            unknown: Vec::new(),
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
                String::new(),
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
            use cipherbox_core::seal::{ChildRef, NodeKind as CoreNodeKind};
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
                        unknown: Vec::new(),
                    }],
                    unknown: Vec::new(),
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
                String::new(),
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

        use cipherbox_core::codec::Value;
        use cipherbox_core::content::{compute_cid, encode_content_cid_str};
        use cipherbox_core::ipns::{IpnsName, IpnsRecord};
        use cipherbox_core::kdf;
        use cipherbox_core::payload::RepointObject;
        use cipherbox_core::seal::{
            ChildRef, NodeKind as CoreNodeKind, ReadBody, encode_envelope, seal_read_body,
        };
        use cipherbox_core::suite::ecdsa::EcdsaSigner;

        use crate::content::{DAG_ROOT_CODEC, GatewaySource};
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
                    unknown: Vec::new(),
                }],
                // At the read epoch (write plane == read plane here), so the
                // cold-seeded write floor opens it and the owner recovers its
                // write-scope seed for the held-set renewal signer.
                owner_write_blob_epoch: Some(EPOCH),
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
                accelerator: Some(GatewaySource {
                    base_url: "https://gw.test".into(),
                    bearer: None,
                }),
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
                String::new(),
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
                engine.scope_read_seeds.borrow().get(&SCOPE).map(|s| **s),
                Some(SCOPE_SEED),
                "the tick adopt deposited the recovered scope read seed"
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
                    unknown: Vec::new(),
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
                    envelope
                        .unknown
                        .push(("grantSection".to_string(), Value::Bytes(vec![1, 2, 3])));
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
                    unknown: Vec::new(),
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
