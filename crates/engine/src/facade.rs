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
//! and every successful stage emits [`Event::SnapshotUpdated`]. A [`Command`]
//! variant with no arm of its own returns [`EngineError::Unimplemented`].

use core::cell::{Cell, RefCell};
use core::fmt;
use core::pin::Pin;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use cipherbox_core::codec::{RedactedBytes, RedactedText};
use cipherbox_core::content::{CONTENT_CID_LEN, encode_content_cid_str};
use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildScopeRef, GrantLedgerEntry, GrantSection, GrantSetCommitment, MAX_READ_SEALED_BYTES,
    ReadBody, Version, open_content_key, seal_content_key, sign_grant_set,
};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::X25519Secret;
use futures_channel::mpsc;
use futures_core::Stream;
use zeroize::Zeroizing;

use crate::api::{ApiClient, ApiError, AuthMethod, IdentityChallengeSigner, RegisteredDevice};
use crate::bin_index::{BinIndexKeys, BinIndexLoad, BinnedNode, load_bin_index};
use crate::content::budget::{Refusal, ReservationId};
use crate::content::{
    ContentKey, ContentProfile, ContentWriter, Gateway, GatewayConfig, OpenError, PinMode, Refused,
    RootManifest, SealError, SessionBearer, StagingLedger, open_content_range, open_content_root,
    pre_flight_quota_check, read_pinned_range, sealed_total_bytes,
};
use crate::devices::{self, ApprovalDecision, MalformedDeviceField, PendingApprovalView};
use crate::entropy::{Entropy, SharedEntropy, fresh_bytes, fresh_ephemeral, fresh_seed};
use crate::gate::{GateError, floor, record_cut_epoch_floor};
use crate::grants::grafted::{
    BookmarkedScopeRoots, GraftedSharers, NamedNodes, evict_grafted_read_seeds, floor_view,
};
use crate::grants::inbox::ShareInbox;
use crate::grants::received_status::{
    ReceivedShareStatus, ReceivedVerdicts, ScopeRender, grafted_root_name,
};
use crate::grants::{
    ClaimOutcome, CommittedScope, Contact, ContactStore, ContactStoreError, ConvertedClaim,
    CreateGrantError, EphemeralInvitee, GrantRecipient, GranteeScopePlan, InviteClaim, InviteError,
    InviteFragment, InviteMintError, InviteMintPlan, InviteStore, InviteStoreError,
    MintedInviteLink, OwnerAuthority, OwnerGrantKeys, ParentScopePlan, PendingInviteLink,
    PublishedGrantBlob, ReceivedShareStore, ReceivedShareStoreError, ResolutionClass, SharePointer,
    StagingContactStore, StagingInviteStore, StagingReceivedShareStore, UNATTESTED_IDENTITY_PK,
    convert_invite_claim, create_grant, enforce_committed_ledger, import_contact, insert_child,
    link_budget_full, locate_invite_link, mint_invite_link, partition_scope_links,
    post_invite_claim, post_share_pointer, recipient_blinded_tag, resolve_recipient,
    row_is_owner_attested,
};
use crate::mailbox::{poll_verified, post_sealed};
use crate::name::{NameError, is_emittable, validate_name};
use crate::net::author::ENVELOPE_V;
use crate::net::cut::OwnerCutNet;
use crate::net::record_publish::RecordPublishError;
use crate::net::retire::{OrphanHeads, ReclaimStall, retire};
use crate::net::rotation::scope_name;
use crate::net::rotation::{GatedRoots, RotationAncestry, SweptScopeState};
use crate::net::{
    Adopter, ChildAdopter, ChildResolveError, EolRenewResult, FolderRefresh, GraftedLeg, HeldKey,
    HeldMaterial, HeldRecord, HeldRecords, LivenessControl, OwnerRotationKeys, OwnerRotationNet,
    PointerConsult, PointerConsultArm, PointerConsultError, PublishError, PublishOutcome,
    RE_PUT_INTERVAL, RecordPlane, RecordPointerFetch, ResolveOutcome, RootAdopter,
    ScopePointerEnrolment, VaultProvisionNet, enrol_owned_scope_pointers, eol_renew_pass,
    fanout_get_verify, keyless_re_put, refresh_base_from_resolved, resolve_and_hold, resolve_child,
    run_liveness_loop,
};
use crate::owner_keys::{OwnerSeedKeys, OwnerSessionKeys};
use crate::profile::SyncTimingProfile;
use crate::rotation::{
    AscentAuthority, CascadeTarget, CommittedSet, CutRotationReport, GrantCutPlan,
    MAX_ROTATION_ATTEMPTS, ResealError, ResealSeeds, ResealedScopeRoot, ResolveFailure, Retryable,
    RevokeError, RevokedCommittedSet, RotateError, RotateScopePlan, ScopeRootIdentity,
    ScopeRootPublisher, WriteHistory, WriteRevokeKind, bounded, cut_for_write_grant,
    derive_write_name, record_grant_floor, reseal_scope_root, revoke_read_grant,
    revoke_write_grant, rotate_on_cut, rotate_scope, run_sweep,
};
use crate::seams::{
    BoxedTask, CredentialStore, FloorStore, LiveSeam, Mailbox, OpId, OwnerScopedFloorStore,
    RecordTransport, Scheduler, SeamError, SeamResult, SeamSet, SeamTypes, SnapshotCache,
    StagingStore, UnixMillis,
};
use crate::session::SessionIdentity;
use crate::settings::{
    DEFAULT_BIN_RETENTION_DAYS, PlacementRefusal, PlacementSource, SessionPlacement,
    SettingsOrigin, SettingsPublishError, VaultSettings, VaultSettingsSummary, decide_placement,
    load_settings, load_settings_at, placement_of, publish_settings, redecide_placement,
    settings_name, summarize_settings,
};
use crate::storage_policy::StoragePolicy;
use crate::sync::boot::{ColdStartError, ColdStartOutcome, ColdStartParams, cold_start};
use crate::sync::cancel::UploadCancels;
use crate::sync::drain::{
    Drain, DrainReport, DrainScope, bin_load_is_a_verdict, hold_captures, published_op_mark,
};
use crate::sync::model::{NodeMeta, RenderedChild, Snapshot, collation_key, rendered_children};
use crate::sync::op::{NewNode, Op, OpKind, Replaced, ScopeCrossing, StagedContent};
use crate::sync::overlay::apply_overlay;
use crate::sync::pointer::PointerFetch;
use crate::sync::project::{UnlinkedChild, map_kind, project_child_version};
use crate::sync::provision::{
    GENESIS_VAULT_POINTER_INDEX, ProvisionError, ProvisionOutcome, ProvisionPlan, ProvisionedVault,
    VaultPointerProbe, provision_vault,
};
use crate::sync::rebase::{QueueScan, QueueScanMemo, decode_queue};
use crate::sync::record::{RecordClass, record_content_root_cid};
use cipherbox_core::hex::lower as hex_lower;

pub use crate::sync::drain::{BlockedOp, SettingsHold};
pub use crate::sync::rebase::DeadLetterReason;
use crate::sync::record::{RecordReader, RecordSeal};
pub use crate::sync::refresh::ForcedPass;
use crate::sync::refresh::{ManualRefresh, RefreshVerdict};
use crate::sync::staging::{
    LiveBlocks, PreservedBounds, PreservedDeadLetter, StagedBlocks, read_preserved_dead_letters,
    reconcile_staging, release_version_blocks, stage_op, take_preserved_dead_letter,
};
use crate::sync::staleness::{Connectivity, classify};
use crate::sync::tick::{
    FocusWindow, ResolveMode, TickControl, consult_scopes, consult_scopes_due, elapsed_at_least,
    focus_by_scope, focus_folders_due, focus_window_expired, on_access_refresh_due, resolve_mode,
    run_tick_loop, scope_root_of,
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
#[derive(Clone, PartialEq, Eq)]
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
        /// The version the caller's bytes were derived from, when the caller
        /// read one. The conditional-edit anchor is otherwise derived from this
        /// device's own rendered view, which a refresh between the read and the
        /// open can advance past what the caller actually holds.
        expected_version: Option<Vec<u8>>,
    },
}

impl fmt::Debug for WriteTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NewFile { parent, name } => f
                .debug_struct("NewFile")
                .field("parent", parent)
                .field("name", &RedactedText::of(name))
                .finish(),
            Self::Version {
                node,
                expected_version,
            } => f
                .debug_struct("Version")
                .field("node", node)
                .field("expectedVersion", &expected_version.is_some())
                .finish(),
        }
    }
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

/// Which SIWE surface a nonce is minted for. The API keeps one pool per intent
/// and refuses a cross-intent spend, so a signature the host collects under one
/// prompt can never serve the other operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiweIntent {
    /// A wallet sign-in.
    Login,
    /// Linking a wallet to the signed-in account.
    Link,
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
#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for NodeAttrs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeAttrs")
            .field("id", &self.id)
            .field("name", &RedactedText::of(&self.name))
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("mtime", &self.mtime)
            .field("content_version", &self.content_version)
            .finish()
    }
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
#[derive(Clone, PartialEq, Eq)]
pub struct Breadcrumb {
    /// Stable node id.
    pub id: NodeId,
    /// Display name, as entered (empty for the root).
    pub name: String,
}

impl fmt::Debug for Breadcrumb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Breadcrumb")
            .field("id", &self.id)
            .field("name", &RedactedText::of(&self.name))
            .finish()
    }
}

/// One direct child in a [`SnapshotView`], projected key-free from the
/// rendered view plus the op-queue/dead-letter bookkeeping.
#[derive(Clone, PartialEq, Eq)]
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
    /// The head version's content root CID, `None` until projected — what a
    /// caller hands back on [`WriteTarget::Version::expected_version`].
    pub content_cid: Option<Vec<u8>>,
}

impl fmt::Debug for SnapshotChild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotChild")
            .field("id", &self.id)
            .field("name", &RedactedText::of(&self.name))
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("mtime", &self.mtime)
            .field("pending", &self.pending)
            .field("dead_letter", &self.dead_letter)
            .field("content_version", &self.content_version)
            .field("content_cid", &self.content_cid)
            .finish()
    }
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
    /// The refusal a contact grant at this scope would report, or `None` where
    /// none of the grounds this read consults stands in its way — `share_scope`
    /// refuses on others it does not reach here, so this narrows what a host
    /// offers rather than promising acceptance. Carries the same `ShareChecks`
    /// name the command itself would return.
    pub grant_refusal: Option<&'static str>,
    /// The refusal an invite-link mint at this scope would report, or `None`.
    pub invite_link_refusal: Option<&'static str>,
    /// This owner's invite links there, absent where those records would not
    /// open — never an empty standing a host would draw as "no link here".
    pub invite_links: Option<SharingInviteLinks>,
}

/// A key-free read of the sharing state a host renders for one scope: this
/// vault's whole verified contact book, this member's own contact code, and the
/// grants the scope's own record commits — the same altitude as
/// [`SnapshotView`], and the read that lets a UI stop mirroring its own command
/// outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingView {
    /// The scope root this read is for.
    pub scope: NodeId,
    /// Every contact this vault has imported, ordered as the book stores them.
    pub contacts: Vec<SharingContact>,
    /// This member's own contact code: the self-authenticating
    /// `{identityPk, encSubkey, bindingSig}` bundle a peer imports to complete
    /// the exchange the other direction already serves
    /// ([`Command::ImportContact`]). Public material, signed under the
    /// session's own identity key — it derives nothing and unwraps nothing.
    pub own_contact_code: Vec<u8>,
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
    /// The shared scope's id. The sharer authors it, so it identifies this row
    /// only together with [`sharer_identity_public_key`](Self::sharer_identity_public_key):
    /// two sharers may each grant one id, and a host must key a row on the pair.
    /// The scope root's `ipnsName` is deliberately not projected: a write
    /// rotation moves it, and the durable list seals it.
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
            .field("display_name", &RedactedText::of(&self.display_name))
            .field("permission", &self.permission)
            .field("resolution", &self.resolution)
            .finish()
    }
}

/// The `/bin` route's whole read: the owner's soft-deleted nodes, and where
/// the index they came from stands on the load ladder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinView {
    /// One row per soft-deleted node.
    pub entries: Vec<BinRow>,
    /// Which rung the bin index load reached.
    /// [`SettingsOrigin::Defaults`] means this device established no index at
    /// all, so the empty `entries` is the documented fallback and not a claim
    /// that the owner has deleted nothing. A host must render that apart from a
    /// bin it read.
    pub origin: SettingsOrigin,
}

/// One soft-deleted node, as the `/bin` route renders it.
///
/// The bin entry's `ipnsName` and its bin-held key are deliberately not
/// projected: the name is the record route a restore or a purge resolves inside
/// the engine, and the key is the access the entry holds on the owner's behalf.
/// Neither is a host's to hold (CONTEXT.md "Bin entry").
#[derive(Clone, PartialEq, Eq)]
pub struct BinRow {
    /// The soft-deleted node. A restore and a purge both name it.
    pub node: NodeId,
    /// The node's immutable kind.
    pub kind: NodeKind,
    /// The folder the node was unlinked from — a restore's default destination.
    pub origin_parent: NodeId,
    /// The name the node carried in that folder.
    pub origin_name: String,
    /// Where [`origin_parent`](Self::origin_parent) stands in the rendered
    /// vault, so a host can name the place a restore puts the node back.
    pub origin_folder: BinOrigin,
    /// The injected deletion time, in milliseconds. A host renders expiry from
    /// this and the owner's `bin_retention_days`.
    pub deleted_at: u64,
    /// The scope the node belonged to at the delete.
    pub scope: NodeId,
}

impl fmt::Debug for BinRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinRow")
            .field("node", &self.node)
            .field("kind", &self.kind)
            .field("origin_parent", &self.origin_parent)
            .field("origin_name", &RedactedText::of(&self.origin_name))
            .field("origin_folder", &self.origin_folder)
            .field("deleted_at", &self.deleted_at)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Where a bin row's origin folder stands in the rendered vault.
#[derive(Clone, PartialEq, Eq)]
pub enum BinOrigin {
    /// The vault root, which carries no name of its own.
    Root,
    /// A folder the vault still holds, under the name it carries there.
    Folder(String),
    /// No folder of that id stands in the vault, so a default restore refuses
    /// with [`EngineError::RestoreTargetGone`].
    Gone,
}

impl fmt::Debug for BinOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => f.write_str("Root"),
            Self::Folder(name) => f
                .debug_tuple("Folder")
                .field(&RedactedText::of(name))
                .finish(),
            Self::Gone => f.write_str("Gone"),
        }
    }
}

/// The storage pane's whole read: the member's own settings minus the provider
/// credential, the account quota, and what a published prune still owes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStorageView {
    /// The settings this session loaded, redacted.
    pub settings: VaultSettingsSummary,
    /// `None` when the quota probe did not answer — a settings read is never
    /// blocked by one (blueprint/engine.md "defaults, never blocked").
    pub quota: Option<QuotaView>,
    /// Vault-level pinned bytes a published prune still owes the registry.
    pub pending_reclaim_bytes: u64,
    /// Debts the last reclaim pass could not settle, and why.
    pub reclaim_stalls: Vec<ReclaimStall>,
}

/// The account quota as the storage pane renders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaView {
    /// Bytes counted against the account.
    pub used_bytes: u64,
    /// The account's limit.
    pub limit_bytes: u64,
    /// Whether the figure is a hint rather than a ceiling. Derived from the
    /// vaulted mode, never from the account flag, for the reason
    /// [`pre_flight_quota_check`](crate::content::pre_flight_quota_check)
    /// gives.
    pub advisory: bool,
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
#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for SnapshotView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotView")
            .field("root", &self.root)
            .field("folder", &self.folder)
            .field("folder_name", &RedactedText::of(&self.folder_name))
            .field("children", &self.children)
            .field("ancestors", &self.ancestors)
            .field("dead_letters", &self.dead_letters)
            .field("blocked", &self.blocked)
            .field("settings_hold", &self.settings_hold)
            .field("retained_records", &self.retained_records)
            .field("staleness", &self.staleness)
            .finish()
    }
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

pub use crate::name::MAX_NODE_NAME_BYTES;

/// The det-CBOR cost of one `ChildRef` beyond its `name` and its `ipnsName`:
/// the five known keys, the map and byte-string heads, the kind, and a
/// `linkCounter` at `u64::MAX`. Pinned by
/// `a_full_folder_of_worst_case_children_still_seals`.
const CHILD_REF_FIXED_BYTES: usize = 128;

/// The cost of one `ChildRef` this device authors, at worst — a name at
/// [`MAX_NODE_NAME_BYTES`] and a base36 `ipnsName`.
const MAX_AUTHORED_CHILD_REF_BYTES: usize =
    CHILD_REF_FIXED_BYTES + MAX_NODE_NAME_BYTES + MAX_IPNS_NAME_BYTES;

/// The base36 CIDv1 text of an Ed25519 key, which is what the author path
/// writes into a `ChildRef`.
const MAX_IPNS_NAME_BYTES: usize = 64;

/// The most children a command may leave a folder holding.
///
/// The cheap half of the bound. A folder's read-body seals into one block, so
/// the ceiling is derived from `MAX_READ_SEALED_BYTES` rather than picked, and
/// it holds where every child is one this device authored. A peer sizes its own
/// children, so [`refuse_full_parent`] charges the listing's real bytes as well
/// — a count alone would admit a further child into a folder of 1000 names of
/// 2 KiB that no re-author can publish.
pub const MAX_FOLDER_CHILDREN: usize = MAX_READ_SEALED_BYTES / MAX_AUTHORED_CHILD_REF_BYTES;

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
    /// Put a soft-deleted node back into the tree (ADR 0010 item 4). The
    /// destination re-seals the node at its own scope's current epoch, so the
    /// bin-held key stops opening it and the destination's grantees read it
    /// again by scope membership.
    Restore {
        /// The binned node, as the bin index names it.
        node: NodeId,
        /// Where to put it back, or `None` for the folder its bin entry names.
        /// A destination the vault no longer holds is
        /// [`EngineError::RestoreTargetGone`], so a host can offer another.
        into: Option<NodeId>,
    },
    /// Destroy a soft-deleted node: reclaim what its subtree owes and drop its
    /// bin entry (ADR 0010 item 7). Irreversible.
    Purge {
        /// The binned node, as the bin index names it.
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
    /// Drop one parked write: the preserved entry goes, and its staged version
    /// is released. Irreversible, so a host asks first.
    DiscardDeadLetter {
        /// The op id the dead letter was announced under, and the identity the
        /// preserved entry carries.
        op_id: OpId,
    },
    /// Re-queue one parked write's staged version as a **fresh** op, anchored on
    /// the head this device renders now.
    ///
    /// Never a resumed op: the parked one lost its anchor, and re-queueing it as
    /// authored would replay exactly the conditional-edit refusal that parked
    /// it. The fresh anchor is the member saying the bytes they parked are the
    /// ones they want, so the write is theirs to lose, not one this device loses
    /// for them.
    RecoverDeadLetter {
        /// The op id the dead letter was announced under.
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
    /// Link a host-collected SIWE wallet signature to the signed-in account.
    SiweLink {
        /// The signed SIWE message.
        message: String,
        /// The wallet signature bytes.
        signature: Vec<u8>,
    },
    /// Unlink one login method. Re-proves the account identity key server-side.
    UnlinkAuthMethod {
        /// The row `/auth/methods` served.
        method_id: String,
    },
    /// Register this device's identity key on the account (ADR 0009 D4).
    RegisterDevice {
        /// The raw Ed25519 device identity public key, lowercase hex.
        public_key: String,
        /// The device's own signature over
        /// [`Engine::device_registration_challenge`]; made in browser custody,
        /// so it crosses as bytes the engine never produced.
        signature: String,
        /// The CipherBox identity token this device signed in with.
        identity_token: String,
        /// A display label for the approval prompt: context, never evidence.
        label: Option<String>,
    },
    /// Revoke a registered device key. It stops that device approving from now
    /// on and un-shares nothing it already holds (ADR 0009 D5).
    RevokeDevice {
        /// The row `/devices` served.
        device_id: String,
    },
    /// Answer one rendezvous (ADR 0009 D3/D5), after the member confirmed the
    /// comparison value and a fresh factor was sealed to the requester.
    RespondToApproval {
        /// The rendezvous being answered.
        request_id: String,
        /// Approve or deny.
        decision: ApprovalDecision,
        /// The approving device's registered identity public key.
        device_public_key: String,
        /// The rendezvous key the response was signed over, so the engine can
        /// rebuild exactly the payload the API will verify.
        ephemeral_public_key: String,
        /// The device's own signature over the response payload.
        signature: String,
        /// The sealed fresh factor; `None` on a denial.
        sealed_factor: Option<String>,
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
            Command::Restore { .. } => "restore",
            Command::Purge { .. } => "purge",
            Command::Rename { .. } => "rename",
            Command::Relink { .. } => "relink",
            Command::Move { .. } => "move",
            Command::CancelUpload { .. } => "cancelUpload",
            Command::DiscardDeadLetter { .. } => "discardDeadLetter",
            Command::RecoverDeadLetter { .. } => "recoverDeadLetter",
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
            Command::RotateNow { .. } => "rotateNow",
            Command::SaveVaultSettings { .. } => "saveVaultSettings",
            Command::SiweLink { .. } => "siweLink",
            Command::UnlinkAuthMethod { .. } => "unlinkAuthMethod",
            Command::RegisterDevice { .. } => "registerDevice",
            Command::RevokeDevice { .. } => "revokeDevice",
            Command::RespondToApproval { .. } => "respondToApproval",
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
}

impl fmt::Debug for CommandOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandOutcome::Done => f.write_str("CommandOutcome(done)"),
            CommandOutcome::Queued { op_id } => write!(f, "CommandOutcome(queued {})", op_id.0),
            CommandOutcome::ContactImported(_) => f.write_str("CommandOutcome(contactImported)"),
            CommandOutcome::InviteLinkMinted(_) => f.write_str("CommandOutcome(inviteLinkMinted)"),
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
///
/// `Debug` is hand-written for the same reason [`Command`]'s is: this is the
/// stream a host logs, and two variants name a record.
#[derive(Clone, PartialEq, Eq)]
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
    /// This device holds a preserved dead-letter record another build wrote.
    /// Nothing may overwrite it, so the parked writes it holds can be neither
    /// listed nor released, and no later dead letter may join them. Terminal:
    /// no pass changes it, and the member is the only one who can.
    ParkedWritesUnreadable,
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
        /// The record's routing key (`ipnsName`).
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

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SnapshotUpdated => f.write_str("SnapshotUpdated"),
            Self::StalenessChanged { level } => f
                .debug_struct("StalenessChanged")
                .field("level", level)
                .finish(),
            Self::WithheldUpdateEscalation { ipns_name } => f
                .debug_struct("WithheldUpdateEscalation")
                .field("ipns_name", &RedactedBytes::of(ipns_name))
                .finish(),
            Self::DeadLetter { op_id, reason } => f
                .debug_struct("DeadLetter")
                .field("op_id", op_id)
                .field("reason", reason)
                .finish(),
            Self::ParkedWritesUnreadable => f.write_str("ParkedWritesUnreadable"),
            Self::AttributableAbuse { description } => f
                .debug_struct("AttributableAbuse")
                .field("description", description)
                .finish(),
            Self::RenewalFailed {
                routing_key,
                detail,
            } => f
                .debug_struct("RenewalFailed")
                .field("routing_key", &RedactedText::of(routing_key))
                .field("detail", detail)
                .finish(),
            Self::VaultUnprovisioned { retryable, detail } => f
                .debug_struct("VaultUnprovisioned")
                .field("retryable", retryable)
                .field("detail", detail)
                .finish(),
            Self::OpProgress {
                op_id,
                node,
                phase,
                progress,
                error,
            } => f
                .debug_struct("OpProgress")
                .field("op_id", op_id)
                .field("node", node)
                .field("phase", phase)
                .field("progress", progress)
                .field("error", error)
                .finish(),
        }
    }
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
    /// A fail-closed verdict no retry can clear: a rejected child record, a
    /// CID/manifest/unseal disagreement, or a local rotation refusal on this
    /// vault's own material ([`from_rotation`](EngineError::from_rotation)).
    /// Never retried, never rendered (rule 6), and never an accusation against
    /// a peer — a host cannot tell the two sources apart.
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
    /// [`Command::DiscardDeadLetter`] or [`Command::RecoverDeadLetter`] named an
    /// op this device holds no parked write for — one already discarded, one
    /// already recovered, or one the age or byte bound evicted.
    UnknownDeadLetter {
        /// The op the command named.
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
    /// Retry later: a host seam failed (durable op-queue I/O), or a rotation
    /// stalled on something a later pass repairs
    /// ([`from_rotation`](EngineError::from_rotation), the cross-parent
    /// child-label conflict included). Never a trust decision — trust
    /// classification happens below the facade.
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
    /// [`Command::Restore`] named a destination the vault no longer holds, or
    /// resolved one from a bin entry whose `originParent` is gone. Reported
    /// apart from every other refusal so a host can offer another folder rather
    /// than say the restore failed.
    RestoreTargetGone,
    /// [`Command::Restore`] or [`Command::Purge`] named a node the owner's bin
    /// index holds no entry for. Neither node nor bin is at fault: the entry
    /// left, most often because another device already acted on it.
    NotBinned,
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

/// A device-surface field refusal, as the host sees it: a refusal of the input,
/// never an auth verdict, so a caller can tell a bad field from a dead session.
fn malformed<T>(checked: Result<T, MalformedDeviceField>) -> Result<T, EngineError> {
    checked.map_err(|refusal| EngineError::MalformedInput {
        check: refusal.check(),
    })
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
            InviteMintError::Fragment(e) => EngineError::from_invite(e),
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
            e @ (InviteError::NotOwner | InviteError::Authority(_) | InviteError::ScopeUnbound) => {
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
            SettingsPublishError::BinRetention => EngineError::MalformedInput {
                check: "bin-retention-too-long",
            },
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
            // The scope's own sharing read names the link this refuses for
            // ([`ScopeSharing::invite_link_refusal`]), which is where the owner
            // revokes it.
            ContactStoreError::LinkBookFull { .. } => EngineError::MalformedInput {
                check: LINK_CONTACT_BUDGET_FULL,
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
            EngineError::RestoreTargetGone => {
                f.write_str("the folder this item came from is gone; choose another")
            }
            EngineError::NotBinned => f.write_str("this item is not in the bin"),
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
            EngineError::UnknownDeadLetter { op_id } => write!(
                f,
                "no parked write is held for op {}",
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

    /// The children under `parent`, deterministically ordered by node id and
    /// rendered under names unique to the folder ([`rendered_children`]).
    pub fn children(&self, parent: NodeId) -> Vec<NodeAttrs> {
        rendered_children(&self.rendered, parent)
            .iter()
            .map(rendered_attrs)
            .collect()
    }

    /// The child of `parent` a case-insensitive host resolves `name` to: the
    /// one rendered under exactly `name` when it exists, and otherwise the one
    /// whose rendered name folds equal under the strict comparator (FUSE
    /// lookup).
    ///
    /// The exact match wins whatever the id order, so a grantee that plants a
    /// folding twin cannot shadow an owner's file
    /// ([`rendered_children`](crate::sync::model::rendered_children)).
    pub fn lookup(&self, parent: NodeId, name: &str) -> Option<NodeAttrs> {
        let children = rendered_children(&self.rendered, parent);
        find_rendered(&children, name)
            .or_else(|| {
                let key = collation_key(name);
                children
                    .iter()
                    .find(|child| collation_key(child.name()) == key)
            })
            .map(rendered_attrs)
    }

    /// The child of `parent` rendered under exactly `name`, if any — what a host
    /// presenting names case-sensitively resolves through. Folding twins stay
    /// [`lookup`](Self::lookup)'s: this decides what a name refers to, never
    /// whether two names are one.
    pub fn lookup_exact(&self, parent: NodeId, name: &str) -> Option<NodeAttrs> {
        let children = rendered_children(&self.rendered, parent);
        find_rendered(&children, name).map(rendered_attrs)
    }

    /// The node's attributes, if present in the rendered view (FUSE getattr),
    /// under the name its own folder renders it with — the name
    /// [`children`](Self::children) and [`lookup`](Self::lookup) gave it, so a
    /// duplicate is not re-ambiguated one accessor after the listing.
    pub fn attrs(&self, node: NodeId) -> Option<NodeAttrs> {
        self.rendered
            .node(node)
            .map(|meta| node_attrs(meta, &rendered_name(&self.rendered, node)))
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

/// Refuse a journal target the write plane cannot author under.
///
/// An accepted shared scope is grafted into the render tree with no parent link
/// (`grants::received_status`), so a browse reaches it but the drain cannot:
/// an op there names a chain that walks to no root this session publishes under.
/// Refusing at journal time is the only order that works, on the same grounds as
/// [`refuse_scope_exit`].
///
/// A node the render does not hold at all keeps its existing verdict — the
/// rebase decides what a stale target means, and that is not this check's call.
fn refuse_outside_vault(rendered: &Snapshot, node: NodeId) -> Result<(), EngineError> {
    if rendered.contains(node)
        && node != rendered.root
        && !rendered.ancestors(node).contains(&rendered.root)
    {
        return Err(EngineError::ScopeExitRefused {
            message: "that item is not in this session's scope".to_owned(),
        });
    }
    Ok(())
}

/// Where a bin row's origin folder stands in `rendered`.
fn origin_folder(rendered: &Snapshot, parent: NodeId) -> BinOrigin {
    if parent == rendered.root {
        return BinOrigin::Root;
    }
    match rendered.node(parent) {
        // The rendered name, not the stored one: a bin row must name the origin
        // folder the way a host navigating there would read it.
        Some(_) => BinOrigin::Folder(rendered_name(rendered, parent)),
        None => BinOrigin::Gone,
    }
}

/// The owner rotation arm over one engine's seam family.
type OwnerNet<'a, T> = OwnerRotationNet<
    'a,
    <T as SeamTypes>::RecordTransport,
    <T as SeamTypes>::Http,
    <T as SeamTypes>::CredentialStore,
    OwnerScopedFloorStore<<T as SeamTypes>::FloorStore>,
    <T as SeamTypes>::Scheduler,
    Box<dyn Entropy>,
>;

/// A name a command authors, held to the one name law ([`crate::name`]) — the
/// facade is the only boundary every client crosses, so a web caller meets the
/// same rules a mount enforces.
fn refuse_unlawful_name(name: &str) -> Result<(), EngineError> {
    validate_name(name).map_err(|reason| EngineError::MalformedInput {
        check: reason.check(),
    })
}

/// A name a command carries over from the vault, held to the narrow tier only
/// ([`crate::name`]): the wider law would strand a node a peer named, and a name
/// no kernel can carry strands it just as surely — restored into a live folder,
/// it is invisible and unremovable through every projection.
fn refuse_unemittable_name(name: &str) -> Result<(), EngineError> {
    if name.len() > MAX_NODE_NAME_BYTES {
        return Err(EngineError::MalformedInput {
            check: NameError::TooLong.check(),
        });
    }
    if !is_emittable(name) {
        return Err(EngineError::MalformedInput {
            check: "node-name-unemittable",
        });
    }
    Ok(())
}

/// A folder gaining a child, held to [`MAX_FOLDER_CHILDREN`].
///
/// Refused before the op is queued: a queued op the drain can only halt on costs
/// a staging reservation and surfaces as a dead letter, where the ceiling reads
/// as a failure rather than as a limit the caller can act on. `arriving` names
/// the node being placed, so a relink inside its own parent is not refused for a
/// child the folder already holds, and `replacing` names the child a move frees.
fn refuse_full_parent(
    rendered: &Snapshot,
    parent: NodeId,
    arriving: Option<NodeId>,
    replacing: Option<NodeId>,
) -> Result<(), EngineError> {
    let children = rendered.children(parent);
    if arriving.is_some_and(|node| children.iter().any(|child| child.id == node)) {
        return Ok(());
    }
    let retained = children.iter().filter(|child| Some(child.id) != replacing);
    let (count, listing) = retained.fold((0usize, 0usize), |(count, bytes), child| {
        (
            count + 1,
            bytes.saturating_add(child_ref_bytes(child.name(), child.ipns_name.as_deref())),
        )
    });
    let admits = count < MAX_FOLDER_CHILDREN
        && listing.saturating_add(MAX_AUTHORED_CHILD_REF_BYTES) <= MAX_READ_SEALED_BYTES;
    if admits {
        return Ok(());
    }
    Err(EngineError::MalformedInput {
        check: "folder-child-ceiling",
    })
}

/// A rename leaves the child count alone and moves the listing's bytes, so the
/// count arm of [`refuse_full_parent`] never fires for one. Refused here, where
/// the caller learns it, rather than at the drain's oversized re-seal.
///
/// Only a name that grows is held to the budget, so a peer-overfilled folder
/// still lets a shorter name out of it.
fn refuse_over_budget_rename(
    rendered: &Snapshot,
    node: NodeId,
    new_name: &str,
) -> Result<(), EngineError> {
    let Some(parent) = rendered.parent_of(node) else {
        return Ok(());
    };
    let (before, after) =
        rendered
            .children(parent)
            .iter()
            .fold((0usize, 0usize), |(before, after), child| {
                let ipns = child.ipns_name.as_deref();
                let renamed = if child.id == node {
                    new_name
                } else {
                    child.name()
                };
                (
                    before.saturating_add(child_ref_bytes(child.name(), ipns)),
                    after.saturating_add(child_ref_bytes(renamed, ipns)),
                )
            });
    if after > before && after > MAX_READ_SEALED_BYTES {
        return Err(EngineError::MalformedInput {
            check: "folder-child-ceiling",
        });
    }
    Ok(())
}

/// What one child costs the folder body it sits in. The two attacker-sized
/// fields are charged as they stand; the rest is [`CHILD_REF_FIXED_BYTES`].
///
/// A child's carried unknown fields are not charged: the rendered view does not
/// carry them, while the drain re-emits them. That gap is what leaves the seal
/// bound the backstop it is.
fn child_ref_bytes(name: &str, ipns_name: Option<&[u8]>) -> usize {
    CHILD_REF_FIXED_BYTES + name.len() + ipns_name.map_or(0, <[u8]>::len)
}

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
    if name.len() > MAX_NODE_NAME_BYTES {
        return Err(EngineError::MalformedInput {
            check: "grant-display-name-too-long",
        });
    }
    Ok(name)
}

/// A host-collected wallet signature in the one encoding the API's SIWE DTO
/// accepts: `0x` + lowercase hex. Applied here rather than in [`ApiClient`],
/// whose SIWE calls take an already-formatted string.
fn eth_signature_hex(signature: &[u8]) -> String {
    format!("0x{}", hex_lower(signature))
}

/// A resolved scope root's owner signature, parsed. Unparseable is a verdict on
/// the record, never on the caller.
fn parsed_commitment_sig(compact: &[u8; 64]) -> Result<EcdsaSignature, EngineError> {
    EcdsaSignature::from_compact(compact).ok_or_else(|| EngineError::TrustViolation {
        message: "the scope root's commitment signature is unparseable".to_owned(),
    })
}

/// The resolved set at `target` with its scope id bound to the commitment
/// ([`CommittedScope::bind`]).
fn bound_scope<'a>(
    target: &'a OwnerScope,
    current: &'a CascadeTarget,
    commitment_sig: &'a EcdsaSignature,
) -> Result<CommittedScope<'a>, EngineError> {
    CommittedScope::bind(
        &target.scope,
        &current.commitment,
        commitment_sig,
        &current.grant_ledger,
    )
    .map_err(EngineError::from_invite)
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

/// The name a claim conversion reports once the links this owner records hold
/// the whole link-sourced share of the contact book
/// ([`MAX_LINK_CONTACTS`](crate::grants::MAX_LINK_CONTACTS)).
///
/// The sharing read reports it as the scope's `invite_link_refusal` while the
/// live link there holds part of that share. One scope carries at most one live
/// link, so reporting it there is what names the link the owner revokes.
const LINK_CONTACT_BUDGET_FULL: &str = "invite-link-contact-budget-full";

/// The name [`Engine::enclosing_scope`] reports when an ancestor of the target
/// is a live scope root its parent's index does not name. Anchoring above it
/// would hand the writer that dropped the entry the derivation of every scope
/// minted below, so the walk refuses instead.
const ENCLOSING_INDEX_LOST_A_ROOT: &str = "enclosing-scope-index-lost-a-root";

/// How far a committed-set cut goes at the tag it names.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CutKind {
    /// Remove the row: a read revoke, or a full write revoke.
    Revoke,
    /// Demote a write row to read, keeping the recipient committed
    /// ([`WriteRevokeKind::DowngradeToRead`]).
    Downgrade,
}

impl CutKind {
    /// The name this cut reports for a target that names no scope root. One
    /// rule, one name per command, as [`ShareChecks`] does for share actions.
    fn target_check(self) -> &'static str {
        match self {
            CutKind::Revoke => "revoke-target-is-not-a-scope-root",
            CutKind::Downgrade => "downgrade-target-is-not-a-scope-root",
        }
    }
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

/// What a share still owes its recipient once the mint has published and any
/// write-scope cut has moved the scope root.
///
/// Both halves name that root, so neither can be produced before the wave that
/// moves it (blueprint/engine.md "Grant creation").
enum PendingShare<'a> {
    /// The sealed mailbox pointer a personal grant's recipient reads.
    SharePointer(GrantRecipient<'a>),
    /// The bearer capability an invite link hands its host, still to be sealed.
    Fragment(PendingInviteLink),
}

/// The host-facing names a scope mint's refusals carry. One rule, one name per
/// command: a grant and an invite link are different actions to a user, so they
/// do not report each other's.
#[derive(Clone, Copy)]
struct ShareChecks {
    /// The vault root is refused as a target.
    vault_root: &'static str,
    /// The node already names a scope, so a mint would replace it.
    already_a_scope: &'static str,
    /// The parent scope root's envelope version is not the one this build
    /// authors.
    envelope_version: &'static str,
}

/// The [`ShareChecks`] ground on which a further share of a scope is refused, or
/// that one would be accepted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ShareStanding {
    Accepted,
    VaultRoot,
    AlreadyAScope,
    EnvelopeVersion,
}

impl ShareChecks {
    /// The names a contact grant reports.
    const GRANT: Self = Self {
        vault_root: "grant-target-is-the-vault-root",
        already_a_scope: "grant-target-already-names-a-scope",
        envelope_version: "grant-parent-envelope-version-unsupported",
    };
    /// The names an invite-link mint reports.
    const INVITE_LINK: Self = Self {
        vault_root: "invite-target-is-the-vault-root",
        already_a_scope: "invite-target-already-names-a-scope",
        envelope_version: "invite-parent-envelope-version-unsupported",
    };

    /// The name this command reports for `standing`, or `None` where nothing
    /// refuses.
    fn refusal(self, standing: ShareStanding) -> Option<&'static str> {
        match standing {
            ShareStanding::Accepted => None,
            ShareStanding::VaultRoot => Some(self.vault_root),
            ShareStanding::AlreadyAScope => Some(self.already_a_scope),
            ShareStanding::EnvelopeVersion => Some(self.envelope_version),
        }
    }
}

impl ScopeShare<'_> {
    fn checks(&self) -> ShareChecks {
        match self {
            ScopeShare::Contact(_) => ShareChecks::GRANT,
            ScopeShare::InviteLink { .. } => ShareChecks::INVITE_LINK,
        }
    }
}

/// The grounds a parent scope root's resolved record refuses a further share of
/// `node` on. `share_scope` and the `sharing` read take both from here, so
/// neither reports one the other would not; the vault-root ground is settled
/// before any resolve, in `share_scope`'s guard and `owner_scope_standing`.
///
/// A second share of the same folder would mint another scope at epoch 1,
/// replacing the seed every existing grantee holds — a silent revocation dressed
/// as a share; adding a recipient to a scope that already exists is a row on its
/// committed set, not a fresh mint. And a mint authors the fresh scope root at
/// the parent record's envelope version while opening it under the one this
/// build authors, so a divergence would mint a grant nothing can open.
fn record_share_standing(
    node: NodeId,
    envelope_version: u64,
    direct_child_scopes: &[ChildScopeRef],
) -> ShareStanding {
    if envelope_version != ENVELOPE_V {
        ShareStanding::EnvelopeVersion
    } else if direct_child_scopes
        .iter()
        .any(|child| child.scope_id == node.0)
    {
        ShareStanding::AlreadyAScope
    } else {
        ShareStanding::Accepted
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
pub(crate) fn published_grant_blobs(section: &GrantSection) -> Vec<PublishedGrantBlob> {
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

fn node_attrs(meta: &NodeMeta, name: &str) -> NodeAttrs {
    NodeAttrs {
        id: meta.id,
        name: name.to_owned(),
        kind: meta.kind,
        size: meta.size,
        mtime: meta.mtime,
        content_version: meta.content_version,
    }
}

/// A child under the name its folder renders it with, not its stored one.
fn rendered_attrs(child: &RenderedChild<'_>) -> NodeAttrs {
    node_attrs(child.meta, child.name())
}

/// The first child rendered under exactly `name`.
fn find_rendered<'a, 'b>(
    children: &'a [RenderedChild<'b>],
    name: &str,
) -> Option<&'a RenderedChild<'b>> {
    children.iter().find(|child| child.name() == name)
}

/// The name `node`'s own parent renders it under — what a breadcrumb and a
/// folder title must show, so a duplicate is not re-ambiguated one surface after
/// the listing told the two apart.
fn rendered_name(rendered: &Snapshot, node: NodeId) -> String {
    let Some(parent) = rendered.parent_of(node) else {
        return rendered
            .node(node)
            .map(|meta| meta.name().to_owned())
            .unwrap_or_default();
    };
    rendered_children(rendered, parent)
        .iter()
        .find(|child| child.meta.id == node)
        .map(|child| child.name().to_owned())
        .unwrap_or_default()
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
            Err(PublishError::EmptyInlineValue) => {
                "empty inline value (never published)".to_owned()
            }
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
/// poll silently.
///
/// `routing_key` is the record's `ipnsName`, and this description crosses to a
/// host verbatim rather than through a rendering policy — so the name renders as
/// its shape here, the way its own type does. `detail` is a classification and
/// carries no key material.
pub(crate) fn emit_trust_violation(
    events: &mpsc::UnboundedSender<Event>,
    routing_key: &str,
    detail: impl fmt::Display,
) {
    let _ = events.unbounded_send(Event::AttributableAbuse {
        description: format!("{:?}: {detail}", RedactedText::of(routing_key)),
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
            Ok(consult) => {
                consulted.borrow_mut().insert(scope, window.now);
                if scope == window.anchor {
                    anchor_root = consult.map(|consult| consult.current_root);
                }
            }
        }
    }
    anchor_root
}

/// The bin retention the owner actually chose, or `None` when this device's
/// settings load carried no member choice.
///
/// The delete branch takes the documented default because binning is the
/// reversible error ([`bin_retention_days`]); expiry destroys, so it acts only
/// on a retention this device can show is the owner's.
fn owner_bin_retention_days(summary: &RefCell<Option<VaultSettingsSummary>>) -> Option<u32> {
    let summary = summary.borrow();
    summary
        .as_ref()
        .filter(|summary| summary.origin != SettingsOrigin::Defaults)
        .map(|summary| summary.bin_retention_days)
}

/// The bin retention a session loaded, which decides whether a delete is soft
/// and whether the poll leg's observed unlinks are captured
/// (blueprint/engine.md "Delete branch"). A session with no settings summary
/// yet takes the documented default, and so does one whose load degraded.
fn bin_retention_days(summary: &RefCell<Option<VaultSettingsSummary>>) -> u32 {
    summary
        .borrow()
        .as_ref()
        .map_or(DEFAULT_BIN_RETENTION_DAYS, |summary| {
            summary.bin_retention_days
        })
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
    let record = held.get(&HeldKey::node(scope_root))?;
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

/// [`Engine::vault_root_scope`]'s refusal name.
const HELD_SEED_NOT_AT_CURRENT_ROOT: &str = "held-write-seed-does-not-name-the-current-root";

/// Whether `seed` derives the scope root's own `ipnsName` — the one proof both
/// the deposit ([`deposit_write_seed`]) and the read
/// ([`Engine::vault_root_scope`]) hold a write scope seed to, stated once so
/// the two cannot drift apart.
fn seed_names(seed: &[u8; 32], scope_id: &[u8; 16], root_name: Option<&IpnsName>) -> bool {
    root_name.is_some_and(|name| derive_write_name(seed, scope_id) == *name)
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
    if seed_names(&seed, &scope_id, root_name) {
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
pub(crate) struct CachedSeed {
    seed: Zeroizing<[u8; 32]>,
    floor: u64,
}

/// One of the engine's in-memory per-scope seed cells: scope id → the recovered
/// seed (zeroized on removal/drop).
pub(crate) type ScopeSeeds = BTreeMap<[u8; 16], CachedSeed>;

/// Which of a scope's two independent durable floors bounds a cached seed
/// (`gate::floor`: the read-epoch floor is the revocation boundary, the
/// write-epoch floor an owner-only clock).
#[derive(Clone, Copy)]
pub(crate) enum SeedFloor {
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
pub(crate) async fn refresh_seed_floor<F: FloorStore>(
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
pub(crate) fn deposit_seed(
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
pub(crate) type RetainedDeadLetters = BTreeMap<OpId, (Option<NodeId>, DeadLetterReason)>;

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
/// The account-level record in `slot` — the vault settings or the bin index —
/// unless the record plane now serves a different one.
///
/// The resolve tick replaces each held record in place, so nothing in that map
/// can go stale under the renewal; these slots have no such refresher. A
/// second device that published after this session did leaves this record
/// superseded, and a sub-EOL renewal would re-sign it at `floor + 1` with a
/// fresh validity — which wins record selection and rolls the account back to
/// the body this session published.
///
/// Only a positively observed *different* record supersedes: a plane this pass
/// cannot read is availability, and the renewal itself refuses to renew what it
/// cannot resolve.
async fn live_account_record<R: RecordTransport>(
    transport: &R,
    slot: &RefCell<Option<HeldRecord>>,
) -> Option<HeldRecord> {
    let held = slot.borrow().clone()?;
    let Ok(name) = IpnsName::parse(&held.routing_key) else {
        return None;
    };
    match fanout_get_verify(transport, &name).await {
        Some((live, _)) if live.value != held.value.record_value() => {
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

/// Drop every held scope pointer the record plane no longer serves.
///
/// The resolve tick replaces each node-plane record in place; the pointer plane
/// has no such refresher, and only a local rotation ever writes it. So a
/// re-point another device landed leaves this session's entry stale, and both
/// liveness layers would keep it alive: the keyless re-PUT would re-seed a
/// retired re-point block hourly, and a sub-EOL renewal would re-sign it at a
/// higher sequence and roll the scope back to a root name that no longer holds.
///
/// Only a positively observed *different* record supersedes, on the same terms
/// as [`live_account_record`]: a plane this pass cannot read is availability.
async fn drop_superseded_pointers<R: RecordTransport>(transport: &R, held: &RefCell<HeldRecords>) {
    let pointers: Vec<(HeldKey, HeldRecord)> = held
        .borrow()
        .iter()
        .filter(|(key, _)| key.plane == RecordPlane::ScopePointer)
        .map(|(key, record)| (*key, record.clone()))
        .collect();
    for (key, record) in pointers {
        let Ok(name) = IpnsName::parse(&record.routing_key) else {
            continue;
        };
        let Some((live, _)) = fanout_get_verify(transport, &name).await else {
            continue;
        };
        if live.value == record.value.record_value() {
            continue;
        }
        // The verdict names the record this pass read: a flip that landed across
        // the fetch installed its own confirmed entry, and dropping that one
        // would take the fresh pointer out of the renewal.
        let mut held = held.borrow_mut();
        if held
            .get(&key)
            .is_some_and(|current| current.record_bytes == record.record_bytes)
        {
            held.remove(&key);
        }
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
    /// The queued op that staged this version ([`staged_open_error`]).
    staged_op: Option<OpId>,
    /// Released when the last [`Rc`] drops, which an in-flight
    /// [`read_stream`](Engine::read_stream) can outlive the map entry by.
    _slot: StreamSlot,
}

/// The version one read pins, and where it came from.
struct PinnedVersion {
    /// The version every block of the read is verified and unsealed under.
    version: Version,
    /// The queued op that staged it, for a version this device has authored and
    /// not yet published. `None` for a published head.
    staged_op: Option<OpId>,
    /// The retained version count to repaint the base node with. `None` for a
    /// staged version: it is not gate-passing state, so pinning one repaints
    /// nothing.
    version_count: Option<u64>,
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

/// The resolve-tick task, spawned once a root name exists to poll. It reads
/// that name from [`Engine::current_root_name`] on every pass.
type TickLoopSpawner = Box<dyn FnOnce()>;

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
    /// The bin index record this session published, in its own slot for the
    /// same reason the settings record has one, and shared with the drain,
    /// which is what writes a bin entry.
    bin_index_record: Rc<RefCell<Option<HeldRecord>>>,
    /// Staleness bookkeeping shared with the resolve-tick loop: it stamps
    /// successes and reports rung changes; [`snapshot`](Self::snapshot)
    /// classifies at read time off the same cell.
    sync_status: Rc<RefCell<SyncStatus>>,
    /// Per-scope read seeds recovered by gate-passing adopts (the owner-blob
    /// override seed), keyed by scope id. In-memory only — never persisted,
    /// never crossing the facade (security rules 1/3); the child read pipeline
    /// derives per-node read keys from them (`node-seed` → `read-key`).
    ///
    /// Every key is the vault root scope id or a grafted scope id. The eviction
    /// pass reads that as an invariant: it drops a seed under any other key,
    /// because no floor namespace answers for one
    /// ([`evict_grafted_read_seeds`](crate::grants::grafted::evict_grafted_read_seeds)).
    scope_read_seeds: Rc<RefCell<ScopeSeeds>>,
    /// Per-scope write seeds recovered by gate-passing adopts (the
    /// owner-write-blob seed), keyed by scope id. In-memory only, exactly like
    /// [`scope_read_seeds`](Self::scope_read_seeds); the drain derives each new
    /// node's `ipnsName` and its narrow per-name signer from them.
    scope_write_seeds: Rc<RefCell<ScopeSeeds>>,
    /// The `ipnsName` the vault root scope currently publishes under: adopted at
    /// cold start, minted by a first run, moved by a write wave this session
    /// drove, and re-read from the vault pointer on every consult. `None` until
    /// one of those lands.
    ///
    /// A write wave moves the root and leaves the predecessor name **dead to
    /// survivors but live to the revokee**, who still holds its write-name key
    /// (blueprint/engine.md "Residuals"). The cached write scope seed lags the
    /// wave until an adopt re-deposits it, so an owner action that re-derived
    /// its target would name the dead root. This cell is what the derivation is
    /// proved against ([`vault_root_scope`](Self::vault_root_scope)).
    current_root_name: Rc<RefCell<Option<IpnsName>>>,
    /// The vault-pointer index this session adopted at cold start, or minted —
    /// the index a root write rotation must re-point
    /// ([`resolve_vault_pointer`](crate::sync::pointer::resolve_vault_pointer)
    /// adopts the highest valid one). `None` on a vault with neither.
    vault_pointer_index: Cell<Option<u64>>,
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
    /// Rebuilt by the received-share pass, like
    /// [`received_verdicts`](Self::received_verdicts).
    grafted_sharers: Rc<RefCell<GraftedSharers>>,
    /// Rebuilt by the same pass: the cross-plane rule the focus window's folder
    /// leg applies below a grafted root
    /// ([`GraftedPlane`](crate::grants::grafted::GraftedPlane)).
    bookmarked_scope_roots: Rc<RefCell<BookmarkedScopeRoots>>,
    /// Rebuilt by the same pass: what each renderable grafted scope's body
    /// named, which decides the ids no plane may render.
    grafted_named_nodes: Rc<RefCell<NamedNodes>>,
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
    /// Why the debts the last reclaim pass could not settle did not settle,
    /// written by the drain tick and read by
    /// [`reclaim_stalls`](Self::reclaim_stalls). In-memory for the same reason
    /// [`pending_reclaim`](Self::pending_reclaim) is: every pass re-derives it
    /// from the retire ledger.
    reclaim_stalls: Rc<RefCell<Vec<ReclaimStall>>>,
    /// Head blocks the drain uploaded for a publish that never reached the
    /// record transport, pending retirement. Session-lived so a retire the
    /// registry refused goes out again on a later pass.
    orphan_heads: Rc<OrphanHeads>,
    /// Whether a poll tick has reconciled the record plane since this session
    /// started. The drain holds a replayed quarantine until it is set
    /// (blueprint/engine.md "Retirement").
    converged_tick: Rc<Cell<bool>>,
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
    /// The bin index's own signer and seal key, derived at
    /// [`start`](Self::start) and shared with the drain on the same terms as
    /// [`tick_enc_subkey`](Self::tick_enc_subkey): a spawned task holds the two
    /// edges the bin index needs, never the login secret they came from.
    tick_bin_keys: Rc<RefCell<Option<Rc<BinIndexKeys>>>>,
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
    /// The host-visible summary of the settings this session loaded, refreshed
    /// by a confirmed save and by the tick's re-decide. Redacted at construction
    /// ([`VaultSettings::summary`]), so the provider bearer never enters it.
    /// Shared with the tick loop, which must never move the placement without
    /// moving what the host is told the session writes under.
    settings_summary: Rc<RefCell<Option<VaultSettingsSummary>>>,
    /// Unlinks a read leg observed and this device did not author. The drain
    /// adopts them into the bin and clears only what it settles, so a capture
    /// the merge already dropped from the base is not lost on a failed pass
    /// (ADR 0010 item 5).
    observed_unlinks: Rc<RefCell<Vec<UnlinkedChild>>>,
    /// Whether this session has already held the account's `byo` flag to the
    /// vaulted mode. Latched per placement decision, not per write: the flag is
    /// account-wide, so re-deriving it on every write would let two devices flap
    /// it — a settings change this session adopts is the one event that re-arms
    /// it, whether the member saved it here or on another device.
    byo_reconciled: Rc<Cell<bool>>,
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
                // Shared by every account on purpose: a well-known anchor, never
                // an account discriminator — separation lives in the KDFs and in
                // the per-identity seam views that consume it.
                snapshot: Rc::new(RefCell::new(Snapshot::new(NodeId([0u8; 16])))),
                held_records: Rc::new(RefCell::new(HeldRecords::new())),
                settings_record: Rc::new(RefCell::new(None)),
                bin_index_record: Rc::new(RefCell::new(None)),
                sync_status: Rc::new(RefCell::new(SyncStatus::default())),
                scope_read_seeds: Rc::new(RefCell::new(BTreeMap::new())),
                scope_write_seeds: Rc::new(RefCell::new(BTreeMap::new())),
                current_root_name: Rc::new(RefCell::new(None)),
                vault_pointer_index: Cell::new(None),
                focus: Rc::new(RefCell::new(FocusWindow::default())),
                focus_refreshed: Rc::new(RefCell::new(BTreeMap::new())),
                pointer_consulted: Rc::new(RefCell::new(BTreeMap::new())),
                received_verdicts: Rc::new(RefCell::new(ReceivedVerdicts::new())),
                grafted_sharers: Rc::new(RefCell::new(GraftedSharers::new())),
                bookmarked_scope_roots: Rc::new(RefCell::new(BookmarkedScopeRoots::new())),
                grafted_named_nodes: Rc::new(RefCell::new(NamedNodes::new())),
                focus_touched: Rc::new(Cell::new(None)),
                focus_hinted: Cell::new(None),
                dead_letters: Rc::new(RefCell::new(BTreeMap::new())),
                queue_scan: RefCell::new(QueueScanMemo::default()),
                blocked: Rc::new(RefCell::new(None)),
                settings_hold: Rc::new(RefCell::new(None)),
                pending_reclaim: Rc::new(Cell::new(0)),
                reclaim_stalls: Rc::new(RefCell::new(Vec::new())),
                orphan_heads: Rc::new(OrphanHeads::default()),
                converged_tick: Rc::new(Cell::new(false)),
                alive: Rc::new(Cell::new(true)),
                manual_refresh: ManualRefresh::default(),
                session: None,
                tick_enc_subkey: Rc::new(RefCell::new(None)),
                tick_bin_keys: Rc::new(RefCell::new(None)),
                tick_loop_spawner: RefCell::new(None),
                sweep_tasks: RefCell::new(None),
                sweep_keys: Rc::new(RefCell::new(None)),
                placement: Rc::new(RefCell::new(None)),
                settings_summary: Rc::new(RefCell::new(None)),
                observed_unlinks: Rc::new(RefCell::new(Vec::new())),
                byo_reconciled: Rc::new(Cell::new(false)),
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
        // Before the first floor read: an unbound view refuses every one.
        self.seams.floor_store.bind(session.enc_subkey());

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
        *self.settings_summary.borrow_mut() = Some(summarize_settings(&settings));
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
        self.install_cold_start(outcome, root_scope_id);
        if let Some(provisioned) = provisioned {
            self.install_mint(provisioned);
        }
        // A successful cold start is a successful reconcile: stamp it so the
        // ladder starts Fresh rather than Reconciling.
        self.sync_status.borrow_mut().last_success = Some(self.seams.scheduler.now());

        // A crash between staging a version's blocks and journaling its op
        // leaves them referenced by nothing, so cold start is the first place
        // that residue can be reclaimed — and the first place a preserved set
        // that was already over its bounds when this store opened is cut back to
        // them, before a single tick runs.
        reconcile_staging(
            &self.seams.staging_store,
            &self.live_blocks,
            PreservedBounds::at(
                self.seams.scheduler.now(),
                &self.storage_policy,
                &self.profile,
            ),
        )
        .await;

        self.spawn_liveness_loop(api.clone());
        *self.sweep_tasks.borrow_mut() = self.build_sweep_task_factory(api.clone());
        *self.tick_loop_spawner.borrow_mut() = self.build_tick_loop_spawner(api.clone());
        self.open_tick_loop();
        self.api = Some(api);
        self.started = true;
        Ok(())
    }

    /// Bring a cold-start outcome up as this session's data path: deposit both
    /// scope seeds, install the gate-passing base as the state law's left
    /// operand, and hold the resolved root name (the vault pointer's
    /// `currentRoot`) the tick loop polls. An empty chain holds none, and
    /// answers `false`.
    ///
    /// Both seeds are stamped from the owner-vouched re-point the cold-seed
    /// installed the floors from, and which the adopt and the owner-write-blob
    /// AAD then bound to — the epochs they belong to, not a later floor read
    /// (see `deposit_seed`).
    fn install_cold_start(&self, mut outcome: ColdStartOutcome, root_scope_id: [u8; 16]) -> bool {
        let anchor = outcome.vault_pointer.as_ref();
        let vouched = anchor.map(|vp| &vp.repoint);
        self.vault_pointer_index.set(anchor.map(|vp| vp.index));
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
        *self.current_root_name.borrow_mut() = root_name.clone();
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
        root_name.is_some()
    }

    /// Deposit a fresh mint's seeds and hold the root name it published. A
    /// just-provisioned vault has no adopt to surface them — this run minted
    /// them — so they are stamped at the epochs its own re-point vouches and
    /// the floors it seeded from them.
    fn install_mint(&self, vault: ProvisionedVault) {
        self.vault_pointer_index
            .set(Some(GENESIS_VAULT_POINTER_INDEX));
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
        *self.current_root_name.borrow_mut() = Some(vault.root_name);
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
        if let Ok(mut bin_keys) = self.tick_bin_keys.try_borrow_mut() {
            *bin_keys = None;
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
        if let Ok(mut summary) = self.settings_summary.try_borrow_mut() {
            *summary = None;
        }
        if let Ok(mut held) = self.held_records.try_borrow_mut() {
            held.clear();
        }
        if let Ok(mut settings) = self.settings_record.try_borrow_mut() {
            *settings = None;
        }
        if let Ok(mut bin_index) = self.bin_index_record.try_borrow_mut() {
            *bin_index = None;
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
        // Session-scoped, and a failed start would otherwise leave the prior
        // account's index resident.
        self.vault_pointer_index.set(None);
        if let Ok(mut consulted) = self.pointer_consulted.try_borrow_mut() {
            consulted.clear();
        }
        if let Ok(mut verdicts) = self.received_verdicts.try_borrow_mut() {
            verdicts.clear();
        }
        if let Ok(mut sharers) = self.grafted_sharers.try_borrow_mut() {
            sharers.clear();
        }
        if let Ok(mut roots) = self.bookmarked_scope_roots.try_borrow_mut() {
            roots.clear();
        }
        if let Ok(mut named) = self.grafted_named_nodes.try_borrow_mut() {
            named.clear();
        }
    }

    /// A forget latches the instance terminal, and an engine that never started
    /// has nothing to end. The gate [`Command::Logout`] passes, since it is
    /// idempotent and must stay retryable after it has cleared the session.
    fn started_session(&self) -> Result<(), EngineError> {
        match (self.forgotten, self.started) {
            (true, _) => Err(EngineError::Forgotten),
            (_, false) => Err(EngineError::NotStarted),
            _ => Ok(()),
        }
    }

    /// The gate every other entry point shares: [`started_session`](Self::started_session),
    /// and a session a logout has not already ended.
    fn live_session(&self) -> Result<(), EngineError> {
        self.started_session()?;
        if self.session.is_none() {
            return Err(EngineError::NotStarted);
        }
        Ok(())
    }

    /// [`Command::Logout`]: end the session and revoke the credential it
    /// authenticated with. The durable seams survive by design
    /// (blueprint/web-client.md "Logout") — [`forget_device`](Self::forget_device)
    /// is this and their erase.
    ///
    /// The revoke is best-effort and outside any verdict: it is the one leg that
    /// needs the network, and an offline logout must still end the local
    /// session. On web the refresh credential is an HTTP-only cookie no seam can
    /// reach, so a server-side revoke is the only thing that ends it, and it
    /// runs *before* `shut_down` seals the bearer the endpoint authenticates
    /// with — an unauthenticated revoke leaves the cookie live.
    ///
    /// `session = None` is what [`live_session`](Self::live_session) reads: the
    /// instance serves nothing afterwards, and the alive latch `shut_down` drops
    /// is never re-armed, so a logged-out engine is replaced rather than reused.
    ///
    /// Returns the persisted credential's drop, which is a verdict rather than
    /// best-effort: a refresh token the store still holds outlives the session
    /// it belongs to. `ApiClient::logout` drops it too, but only on the path
    /// where the server answered.
    async fn log_out(&mut self) -> SeamResult<()> {
        let api = self.api.take();
        if let Some(api) = &api {
            let _ = api.logout().await;
        }

        self.shut_down();
        // Dropped here, at the terminal owner: `shut_down` seals what the loops
        // share, and these are the engine's own copies (security rule 7). The
        // render goes with them — it is plaintext metadata about the vault this
        // session is leaving.
        drop(api);
        self.session = None;
        let root = self.snapshot.borrow().root;
        *self.snapshot.borrow_mut() = Snapshot::new(root);

        self.seams.credential_store.clear_refresh_token().await
    }

    /// [`Command::ForgetDevice`]: a [`log_out`](Self::log_out), then the erase
    /// of every durable seam that a logout deliberately leaves standing.
    ///
    /// The sweep is last, and `log_out` drops the session-alive latch before it:
    /// a floor raise or cache put from a pass still in flight would otherwise
    /// land behind the erase and re-seed the device with state it just
    /// disowned. Those passes hold [`LiveSeam`] handles, which is what makes the
    /// latch bind them ([`Scheduler::spawn`] cannot cancel or join).
    ///
    /// Every seam is swept even after one refuses, and the first refusal is what
    /// the caller sees.
    async fn forget_device(&mut self) -> Result<(), EngineError> {
        self.forgotten = true;

        [
            self.log_out().await,
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

        // The preserved set outlives the process and the notice map does not, so
        // a parked write is only nameable again once the set is read back. A set
        // this build cannot read holds parked writes it can neither list nor
        // release, which is the one state a host has to be told about outright.
        match read_preserved_dead_letters(&self.seams.staging_store)
            .await
            .map_err(ColdStartError::Seam)?
        {
            Some(parked) => {
                let reader = RecordReader::new(session.enc_subkey());
                let mut notices = self.dead_letters.borrow_mut();
                for entry in parked {
                    // The same two conditions [`Self::parked_write`] states: one
                    // account's session lists no other's entries, and an op the
                    // queue still holds is pending rather than parked.
                    let mine = matches!(reader.classify(&entry.record), RecordClass::Mine(_));
                    let queued = raw.iter().any(|(id, _)| *id == entry.op_id);
                    if mine && !queued {
                        notices.insert(entry.op_id, (None, entry.reason));
                    }
                }
            }
            None => {
                let _ = self.events.unbounded_send(Event::ParkedWritesUnreadable);
            }
        }

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
    ) -> RootAdopter<'a, T::Http, OwnerScopedFloorStore<T::FloorStore>> {
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
        *self.settings_summary.borrow_mut() = None;
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
        let bin_index_record = self.bin_index_record.clone();
        let alive = self.alive.clone();
        let events = self.events.clone();
        let gateway = self.gateway.clone();
        let http = self.seams.http.clone();
        let entropy = self.entropy.clone();
        let pointer_keys = self.sweep_keys.clone();
        let root_id = self.snapshot.borrow().root.0;
        self.seams.scheduler.spawn(Box::pin(async move {
            run_liveness_loop(&scheduler, RE_PUT_INTERVAL, || async {
                if !alive.get() {
                    return LivenessControl::Stop;
                }
                let settings = live_account_record(&transport, &settings_record).await;
                let bin_index = live_account_record(&transport, &bin_index_record).await;
                drop_superseded_pointers(&transport, &held).await;
                // The flip is the only other producer of a held scope pointer,
                // so a session that runs no rotation must re-enrol what it owns
                // or the pointer lapses at its EOL.
                let session_keys = pointer_keys.borrow().clone();
                if let Some(keys) = session_keys {
                    enrol_owned_scope_pointers(ScopePointerEnrolment {
                        api: &api,
                        transport: &transport,
                        gateway: &gateway,
                        http: &http,
                        floors: &floors,
                        scheduler: &scheduler,
                        profile: &profile,
                        entropy: &entropy,
                        enc_secret: &keys.enc_secret,
                        identity: &keys.owner_identity,
                        keys: &keys.scope_keys,
                        held: &held,
                        root_id,
                        payload_version: POINTER_PAYLOAD_VERSION,
                    })
                    .await;
                }
                let records: Vec<HeldRecord> = held
                    .borrow()
                    .values()
                    .cloned()
                    .chain(settings)
                    .chain(bin_index)
                    .collect();
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
        let tick_bin_keys = self.tick_bin_keys.clone();
        let tick_settings = self.settings_summary.clone();
        let observed_unlinks = self.observed_unlinks.clone();
        let bin_index_record = self.bin_index_record.clone();
        let scheduler = self.seams.scheduler.clone();
        let staging = LiveSeam::new(self.seams.staging_store.clone(), self.alive.clone());
        let entropy = self.entropy.clone();
        let scope_write_seeds = self.scope_write_seeds.clone();
        let dead_letters = self.dead_letters.clone();
        let blocked = self.blocked.clone();
        let settings_hold = self.settings_hold.clone();
        let pending_reclaim = self.pending_reclaim.clone();
        let reclaim_stalls = self.reclaim_stalls.clone();
        let content_profile = self.content_profile;
        let storage_policy = self.storage_policy;
        let orphan_heads = self.orphan_heads.clone();
        let converged_tick = self.converged_tick.clone();
        let cancels = self.cancels.clone();
        let live_blocks = self.live_blocks.clone();
        let transport = self.seams.record_transport.clone();
        let snapshot_cache = LiveSeam::new(self.seams.snapshot_cache.clone(), self.alive.clone());
        let floors = LiveSeam::new(self.seams.floor_store.clone(), self.alive.clone());
        let http = self.seams.http.clone();
        let gateway = self.gateway.clone();
        let placement = self.placement.clone();
        let settings_summary = self.settings_summary.clone();
        let byo_reconciled = self.byo_reconciled.clone();
        // Non-secret: the published name, not the seed that derives it. Paired
        // with the tick's own enc-subkey copy, this reaches the settings record
        // without a second copy of the login secret in a `'static` task.
        let settings_name = settings_name(session.login_secret());
        // Start has just decided, so the first re-decide comes one interval on.
        let settings_rechecked = Cell::new(self.seams.scheduler.now());
        let held = self.held_records.clone();
        let base = self.snapshot.clone();
        let events = self.events.clone();
        let alive = self.alive.clone();
        let sync_status = self.sync_status.clone();
        let scope_read_seeds = self.scope_read_seeds.clone();
        let current_root_name = self.current_root_name.clone();
        let focus = self.focus.clone();
        let focus_touched = self.focus_touched.clone();
        let focus_refreshed = self.focus_refreshed.clone();
        let pointer_consulted = self.pointer_consulted.clone();
        let received_verdicts = self.received_verdicts.clone();
        let grafted_sharers = self.grafted_sharers.clone();
        let bookmarked_scope_roots = self.bookmarked_scope_roots.clone();
        let grafted_named_nodes = self.grafted_named_nodes.clone();
        let consult_keys = self.sweep_keys.clone();
        let profile = self.profile;
        let interval = self.profile.poll_cadence;
        let owner_identity = session.owner_identity();
        // The vault's own root scope and root node are the anchored all-zero id16
        // (the cold-start bootstrap anchor): the adopter's scope binding and the
        // held-set fallback key.
        let root_id = self.snapshot.borrow().root.0;

        let manual = self.manual_refresh.clone();

        Some(Box::new(move || {
            manual.arm();
            let spawn_on = scheduler.clone();
            spawn_on.spawn(Box::pin(async move {
                run_tick_loop(&scheduler, &manual, interval, async |cause| {
                    if !alive.get() {
                        return TickControl::Stop;
                    }
                    let mode = resolve_mode(cause);
                    // The session cell is the root's only current name: a wave
                    // this session drove between passes has already moved it.
                    let Some(mut root_name) = current_root_name.borrow().clone() else {
                        return TickControl::Stop;
                    };
                    // The pass owns a copy for exactly its own duration; the engine
                    // emptied the cell if it is already gone.
                    let enc_subkey = tick_enc_subkey.borrow().clone();
                    let Some(enc_subkey) = enc_subkey else {
                        return TickControl::Stop;
                    };
                    let bin_keys = tick_bin_keys.borrow().clone();
                    let Some(bin_keys) = bin_keys else {
                        return TickControl::Stop;
                    };
                    let now = scheduler.now();
                    // What this paces is a revocation window
                    // ([`redecide_placement`]), so a backward clock step must
                    // not park the next check on a future stamp.
                    let last_checked = settings_rechecked.get();
                    if now.0 < last_checked.0
                        || elapsed_at_least(now, last_checked, profile.settings_recheck_interval)
                    {
                        settings_rechecked.set(now);
                        let load = load_settings_at(
                            &transport,
                            &gateway,
                            &http,
                            &floors,
                            &snapshot_cache,
                            &scheduler,
                            &profile,
                            &enc_subkey,
                            &settings_name,
                        )
                        .await;
                        // A teardown that landed inside the load already
                        // cleared the placement cell, which holds the member's
                        // provider bearer. Writing the re-decide over that
                        // would make it resident again and re-arm the pass the
                        // cleared cell stops below (security rules 1 and 7).
                        if !alive.get() {
                            return TickControl::Stop;
                        }
                        if let Some(decided) = redecide_placement(&load) {
                            *placement.borrow_mut() = Some(decided);
                            *settings_summary.borrow_mut() = Some(summarize_settings(&load));
                            byo_reconciled.set(false);
                        }
                    }
                    // Carries the member's BYO bearer, so the pass owns a copy on the
                    // same terms as the enc subkey above.
                    let Some(SessionPlacement { decision, .. }) = placement.borrow().clone() else {
                        return TickControl::Stop;
                    };
                    // The polled pointer consult (#38 D4), ahead of the floor
                    // refresh below so a write epoch this pass sights evicts the
                    // seed it retired in the same pass.
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
                        *current_root_name.borrow_mut() = Some(current_root.clone());
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
                    let grafted = grafted_sharers.borrow().clone();
                    evict_grafted_read_seeds(&floors, &grafted, &root_id, &scope_read_seeds).await;
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
                        let merged = refresh_base_from_resolved(&base, NodeId(root_id), resolved);
                        if merged.changed {
                            let _ = events.unbounded_send(Event::SnapshotUpdated);
                        }
                        hold_captures(
                            &observed_unlinks,
                            merged.observed_unlinks(root_id, NodeId(root_id), now.0),
                        );
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
                    // The focus window's folders below each scope root — the read
                    // leg for a subtree this device did not author. It runs before
                    // the drain, so the queue rebases onto the deepest state this
                    // pass reconciled, not just the root's.
                    //
                    // Grouped by scope: a leg holds one scope's read material, so a
                    // record sealed under another would fail its AAD-bound unseal
                    // and be reported as abuse by an honest writer. A scope whose
                    // seed this device has not recovered serves nothing, and its
                    // files stay queued for the pass that can.
                    let mut folder_verdict = RefreshVerdict::Reconciled;
                    let mut attempted_files: Vec<NodeId> = Vec::new();
                    let by_scope = focus_by_scope(&base.borrow(), &focus.borrow());
                    let scope_roots = bookmarked_scope_roots.borrow().clone();
                    for (scope_root, targets) in by_scope {
                        let Some(scope_read_seed) = cached_seed(&scope_read_seeds, &scope_root.0)
                        else {
                            continue;
                        };
                        let Some(scope_floors) =
                            floor_view(&floors, &grafted, &root_id, &scope_root.0)
                        else {
                            continue;
                        };
                        attempted_files.extend(targets.files.iter().copied());
                        let refresh = FolderRefresh {
                            transport: &transport,
                            snapshot_cache: &snapshot_cache,
                            http: &http,
                            floors: &scope_floors,
                            gateway: &gateway,
                            base: &base,
                            events: &events,
                            scope_id: scope_root.0,
                            scope_read_seed: &scope_read_seed,
                            plane: (scope_root.0 != root_id).then_some(GraftedLeg {
                                scope_roots: &scope_roots,
                                named_nodes: &grafted_named_nodes,
                            }),
                            mode,
                            observed_at: now.0,
                        };
                        for (nodes, report) in [
                            (&targets.folders, refresh.run(&targets.folders).await),
                            (&targets.files, refresh.run_files(&targets.files).await),
                        ] {
                            if nodes.is_empty() {
                                continue;
                            }
                            stamp_focus_refreshed(&focus_refreshed, nodes, scheduler.now());
                            if report.changed {
                                let _ = events.unbounded_send(Event::SnapshotUpdated);
                            }
                            hold_captures(&observed_unlinks, report.departed);
                            folder_verdict = folder_verdict.worst(report.verdict);
                        }
                    }
                    // Take only what this pass attempted. A lookup queues a file
                    // while the refreshes above are awaited, and a wholesale
                    // replacement would drop what arrived after the snapshot.
                    focus
                        .borrow_mut()
                        .open_files
                        .retain(|node| !attempted_files.contains(node));
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
                    // A vault that keeps no bin captures no unlink either: the
                    // owner turned the bin off, and an adoption carries no owner
                    // command that could overrule that.
                    if bin_retention_days(&tick_settings) == 0 {
                        observed_unlinks.borrow_mut().clear();
                    }
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
                            storage_policy: &storage_policy,
                            live_blocks: &live_blocks,
                            content_profile: &content_profile,
                            entropy: &entropy,
                            base: &base,
                            held: &held,
                            blocked: &blocked,
                            settings_hold: &settings_hold,
                            pending_reclaim: &pending_reclaim,
                            reclaim_stalls: &reclaim_stalls,
                            orphan_heads: &orphan_heads,
                            converged_tick: &converged_tick,
                            cancels: &cancels,
                            events: &events,
                            bin_keys: &bin_keys,
                            bin_retention_days: owner_bin_retention_days(&tick_settings),
                            dead_letters: &dead_letters,
                            bin_index_record: &bin_index_record,
                            observed_unlinks: &observed_unlinks,
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
                    } else {
                        // The drain sweeps staging on the listing it already
                        // took; without one, an abandoned write handle's residue
                        // still has to be reclaimed at the poll cadence.
                        reconcile_staging(
                            &staging,
                            &live_blocks,
                            PreservedBounds::at(scheduler.now(), &storage_policy, &profile),
                        )
                        .await;
                    }
                    // Last, and after the settle above: the grantee's own read
                    // leg is the slowest in the pass, and a host refresh waits
                    // on nothing it reports.
                    //
                    // The mailbox pull leads it, so a share this pass accepts is
                    // classified by the refresh below rather than a pass later.
                    ShareInbox {
                        mailbox: api.as_ref(),
                        transport: &transport,
                        gateway: &gateway,
                        http: &http,
                        floors: &floors,
                        enc_secret: &enc_subkey,
                        vault_root_scope: root_id,
                    }
                    .pull(&staging, &entropy, ENVELOPE_V, &events)
                    .await;
                    ReceivedShareStatus {
                        transport: &transport,
                        gateway: &gateway,
                        http: &http,
                        floors: &floors,
                        enc_secret: &enc_subkey,
                    }
                    .refresh(
                        &staging,
                        &entropy,
                        &received_verdicts,
                        &ScopeRender {
                            base: &base,
                            read_seeds: &scope_read_seeds,
                            grafted_sharers: &grafted_sharers,
                            scope_roots: &bookmarked_scope_roots,
                            named_nodes: &grafted_named_nodes,
                            events: &events,
                        },
                        now,
                        &profile,
                    )
                    .await;
                    let mut status = sync_status.borrow_mut();
                    status.reconcile_in_flight = false;
                    if reconciled {
                        status.last_success = Some(scheduler.now());
                        // Set after the drain above, so the pass that converges
                        // the base is never the pass that decides against it.
                        converged_tick.set(true);
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

    /// Start polling the root this session holds, consuming the spawner
    /// [`start`](Self::start) built. One session runs one tick loop, so a
    /// second call spawns nothing, and a session with no root yet spawns
    /// nothing until one lands.
    fn open_tick_loop(&self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        if self.current_root_name.borrow().is_none() {
            return;
        }
        let Some(spawn) = self.tick_loop_spawner.borrow_mut().take() else {
            return;
        };
        // Least privilege, drawn no earlier than the loop that reads it: the
        // pass needs the enc subkey, the bin index's own two edges, and the
        // (public) owner verifier, never the login secret or the pointer seeds
        // beside them.
        *self.tick_enc_subkey.borrow_mut() = Some(session.enc_subkey().clone());
        *self.tick_bin_keys.borrow_mut() =
            Some(Rc::new(BinIndexKeys::derive(session.login_secret())));
        spawn();
    }

    /// Executes one command. The single write entry point: every mutation,
    /// share action, auth call, and manual refresh comes through here.
    ///
    /// The metadata intent ops (create/delete/rename/relink) stage onto the
    /// durable op queue via [`stage_op`] and emit [`Event::SnapshotUpdated`];
    /// the base sequence each op carries is read from the rendered view (state
    /// law), so an op rebases against the state the host saw.
    ///
    pub async fn command(&mut self, command: Command) -> Result<CommandOutcome, EngineError> {
        // Ahead of the session gate: an engine whose `start` failed closed — a
        // regressed floor, an unreadable cache — is exactly the device whose
        // only recovery is to be forgotten, and it never reached a session.
        if matches!(command, Command::ForgetDevice) {
            return self.forget_device().await.map(|()| CommandOutcome::Done);
        }
        // Ahead of it too, and for the same shape of reason: the session a
        // logout ends is gone by the time its credential drop can refuse, so
        // gating on a live session would make that refusal unretryable.
        if matches!(command, Command::Logout) {
            self.started_session()?;
            return self
                .log_out()
                .await
                .map(|()| CommandOutcome::Done)
                .map_err(EngineError::from_seam);
        }
        self.live_session()?;
        // One clock read per command, journaled on the op: a retried publish
        // re-mints the same sequence, so authoring time must not be re-read.
        let authored_at = self.seams.scheduler.now();
        match command {
            Command::Create { parent, name, kind } => {
                refuse_unlawful_name(&name)?;
                let rendered = self.render().await?;
                refuse_outside_vault(&rendered, parent)?;
                refuse_full_parent(&rendered, parent, None, None)?;
                let target = self.mint_node_id()?;
                let base_sequence = rendered.record_sequence(parent).unwrap_or(1);
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
                let to_bin = self.bin_retention_days() > 0;
                self.stage_and_notify(&Op::delete(node, seq, authored_at, seq, to_bin))
                    .await
            }
            Command::Restore { node, into } => {
                let entry = self.binned_node(node).await?;
                refuse_unemittable_name(&entry.origin_name)?;
                let into = into.unwrap_or(NodeId(entry.origin_parent));
                let rendered = self.render().await?;
                if !rendered.contains(into) {
                    return Err(EngineError::RestoreTargetGone);
                }
                refuse_outside_vault(&rendered, into)?;
                refuse_full_parent(&rendered, into, None, None)?;
                let base_sequence = rendered.record_sequence(into).unwrap_or(1);
                let op = Op::restore(
                    node,
                    into,
                    entry.origin_name.clone(),
                    map_kind(entry.kind),
                    base_sequence,
                    authored_at,
                );
                self.stage_and_notify(&op).await
            }
            Command::Purge { node } => {
                let entry = self.binned_node(node).await?;
                // A node the rendered view still holds is one the user still
                // sees in its folder: the entry alone never licenses a purge.
                if self.render().await?.contains(node) {
                    return Err(EngineError::UnsupportedTarget {
                        check: "purge-target-still-linked",
                    });
                }
                let op = Op::purge(node, entry.deleted_at, 1, authored_at);
                self.stage_and_notify(&op).await
            }
            Command::Rename { node, new_name } => {
                refuse_unlawful_name(&new_name)?;
                let rendered = self.render().await?;
                refuse_outside_vault(&rendered, node)?;
                refuse_over_budget_rename(&rendered, node, &new_name)?;
                let seq = rendered.record_sequence(node).unwrap_or(1);
                self.stage_and_notify(&Op::rename(node, new_name, seq, authored_at))
                    .await
            }
            Command::Relink { node, new_parent } => {
                let rendered = self.render().await?;
                refuse_outside_vault(&rendered, node)?;
                let (from_parent, base_sequence) = self.relocation_anchors(&rendered, node);
                refuse_scope_exit(&rendered, new_parent)?;
                refuse_full_parent(&rendered, new_parent, Some(node), None)?;
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
                refuse_unlawful_name(&new_name)?;
                let rendered = self.render().await?;
                refuse_outside_vault(&rendered, node)?;
                let (from_parent, base_sequence) = self.relocation_anchors(&rendered, node);
                refuse_scope_exit(&rendered, new_parent)?;
                refuse_full_parent(&rendered, new_parent, Some(node), replacing)?;
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
            Command::DiscardDeadLetter { op_id } => self
                .discard_dead_letter(op_id)
                .await
                .map(|()| CommandOutcome::Done),
            Command::RecoverDeadLetter { op_id } => self.recover_dead_letter(op_id).await,
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
            Command::Downgrade {
                node,
                recipient_identity_public_key,
            } => self
                .downgrade_grant(node, &recipient_identity_public_key)
                .await
                .map(|()| CommandOutcome::Done),
            Command::RotateNow { node } => {
                self.rotate_now(node).await.map(|()| CommandOutcome::Done)
            }
            Command::ManualRefresh => self.manual_refresh().await.map(|()| CommandOutcome::Done),
            Command::SaveVaultSettings { settings } => {
                self.save_vault_settings(&settings).await?;
                Ok(CommandOutcome::Done)
            }
            Command::SiweLink { message, signature } => {
                let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
                let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
                let signer = IdentityChallengeSigner::from_signer(session.identity().clone());
                api.siwe_link(&message, &eth_signature_hex(&signature), &signer)
                    .await
                    .map_err(EngineError::from_api)?;
                Ok(CommandOutcome::Done)
            }
            Command::UnlinkAuthMethod { method_id } => {
                let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
                let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
                let signer = IdentityChallengeSigner::from_signer(session.identity().clone());
                api.unlink_auth_method(&method_id, &signer)
                    .await
                    .map_err(EngineError::from_api)?;
                Ok(CommandOutcome::Done)
            }
            Command::RegisterDevice {
                public_key,
                signature,
                identity_token,
                label,
            } => {
                let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
                let account_id = api.account_id().map_err(EngineError::from_api)?;
                malformed(devices::check_registration(
                    &account_id,
                    &public_key,
                    &signature,
                    &identity_token,
                    label.as_deref(),
                ))?;
                api.register_device(&public_key, &signature, &identity_token, label.as_deref())
                    .await
                    .map_err(EngineError::from_api)?;
                Ok(CommandOutcome::Done)
            }
            Command::RevokeDevice { device_id } => {
                let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
                malformed(devices::check_registry_id(&device_id))?;
                api.revoke_device(&device_id)
                    .await
                    .map_err(EngineError::from_api)?;
                Ok(CommandOutcome::Done)
            }
            Command::RespondToApproval {
                request_id,
                decision,
                device_public_key,
                ephemeral_public_key,
                signature,
                sealed_factor,
            } => {
                let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
                malformed(devices::check_response(
                    &device_public_key,
                    &request_id,
                    decision,
                    &ephemeral_public_key,
                    &signature,
                    sealed_factor.as_deref(),
                ))?;
                api.respond_to_approval(
                    &request_id,
                    decision.as_str(),
                    &device_public_key,
                    &signature,
                    sealed_factor.as_deref(),
                )
                .await
                .map_err(EngineError::from_api)?;
                Ok(CommandOutcome::Done)
            }
            // The two commands hoisted above the session gate are the only ones
            // this arm can name, so it is the completeness backstop rather than
            // a live verdict: a variant added without an arm reports itself.
            other => Err(EngineError::Unimplemented {
                command: other.name(),
            }),
        }
    }

    /// The vault root's scope reference: its scope id and the `ipnsName` the
    /// root currently publishes under.
    ///
    /// Every owner action anchors here, so the derivation is proved against the
    /// name this session holds rather than trusted — the read-side twin of
    /// [`deposit_write_seed`]'s deposit-time proof. A seed that does not name
    /// the current root is the post-wave lag, and the action it would target is
    /// the superseded root the revokee still authors at: refuse until an adopt
    /// re-deposits. The lag is session-local staleness, not host-supplied bytes,
    /// so the verdict is the retryable [`EngineError::ContentUnavailable`] the
    /// absent-seed refusal above already answers.
    fn vault_root_scope(&self) -> Result<ChildScopeRef, EngineError> {
        let scope_id = self.snapshot.borrow().root.0;
        let write_scope_seed = cached_seed(&self.scope_write_seeds, &scope_id).ok_or(
            EngineError::ContentUnavailable {
                message: "no write scope seed is held for the vault root".to_owned(),
            },
        )?;
        let held = self.current_root_name.borrow();
        if !seed_names(&write_scope_seed, &scope_id, held.as_ref()) {
            return Err(EngineError::ContentUnavailable {
                message: HELD_SEED_NOT_AT_CURRENT_ROOT.to_owned(),
            });
        }
        let root_name = held.as_ref().expect("seed_names refuses an absent name");
        Ok(ChildScopeRef::new(
            scope_id,
            root_name.as_str().as_bytes().to_vec(),
        ))
    }

    /// The scope root that encloses `node`, the gated record it resolves to, and
    /// the net that gated it — the vault root when no scope this vault granted
    /// contains `node`.
    ///
    /// Each hop reads the next level's `ipnsName` out of the level above's
    /// direct-child-scope index. That index carries no signature of its own; it
    /// rides the sealed write body, which any committed writer of that scope may
    /// author. What holds the walk together is the target: the adoption gate
    /// binds each name to a commitment the owner signed, and proves the ascent
    /// link under the ancestor seed the level above derives. So a substituted
    /// name cannot pass — but a **removed** entry would silently move the anchor
    /// up a level, and hand the writer that removed it the seeds a later mint
    /// below would derive. An ancestor the index does not name is therefore
    /// probed the way [`refuse_an_unindexed_scope`](Self::refuse_an_unindexed_scope)
    /// probes the leaf, and a live scope root there fails the walk closed.
    ///
    /// The returned net is the one that gated the final level, so the caller
    /// republishes that scope from the record this pass parked rather than from
    /// a second read taken later (`GatedRoots`).
    ///
    /// The walk follows the base snapshot's ancestor chain downward and visits
    /// each level at most once.
    async fn enclosing_scope<'a>(
        &'a self,
        node: NodeId,
        api: &'a Rc<ApiClient<T::Http, T::CredentialStore>>,
        keys: OwnerRotationKeys<'a>,
        pointer_consult: PointerConsultArm,
    ) -> Result<(OwnerScope, CascadeTarget, OwnerNet<'a, T>), EngineError> {
        let OwnerRotationKeys {
            enc_secret,
            identity,
            scope_keys,
        } = keys;
        let owner_keys = || OwnerRotationKeys {
            enc_secret,
            identity,
            scope_keys,
        };
        let mut scope = OwnerScope {
            scope: self.vault_root_scope()?,
            parent_node_seed: None,
            vouched: true,
        };
        let mut net = self.owner_rotation_net(api, owner_keys(), scope.ancestry(), pointer_consult);
        let mut current = net
            .resolve_vault_root(&scope.scope)
            .await
            .map_err(EngineError::from_resolve_failure)?;
        // Root-first, so each step descends into the index the step above rode.
        // The vault root is the walk's own anchor rather than a step in it, and
        // no index names it.
        let (mut chain, root) = {
            let base = self.snapshot.borrow();
            (base.ancestors(node), base.root)
        };
        chain.reverse();
        chain.retain(|ancestor| *ancestor != root);
        for ancestor in chain {
            let Some(child) = current
                .direct_child_scope_index
                .iter()
                .find(|child| child.scope_id == ancestor.0)
                .cloned()
            else {
                self.refuse_an_unindexed_scope(
                    ancestor,
                    &current,
                    api,
                    owner_keys(),
                    ENCLOSING_INDEX_LOST_A_ROOT,
                )
                .await?;
                continue;
            };
            let parent_node_seed = kdf::node_seed(&current.override_seed, &child.scope_id);
            scope = OwnerScope {
                scope: child,
                parent_node_seed: Some(Zeroizing::new(*parent_node_seed.as_bytes())),
                vouched: true,
            };
            net = self.owner_rotation_net(api, owner_keys(), scope.ancestry(), pointer_consult);
            current = net
                .resolve_anchored(&scope.scope)
                .await
                .map_err(EngineError::from_resolve_failure)?;
        }
        Ok((scope, current, net))
    }

    /// The scope root `node` names, and the ancestor node seed a gated read of an
    /// interior one needs.
    ///
    /// The authority for what is a scope root is the direct-child-scope index of
    /// the scope that encloses it ([`enclosing_scope`](Self::enclosing_scope)),
    /// so an interior root's `ipnsName` is taken from that index rather than
    /// re-derived: a scope a write rotation has moved is then read at the name
    /// its parent vouches for. A node the base snapshot does not hold is refused
    /// before any resolve.
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
        self.owner_scope_standing(node, api, keys, check, unindexed)
            .await?
            .0
            .ok_or(EngineError::UnsupportedTarget { check })
    }

    /// [`owner_scope`](Self::owner_scope) together with the standing a further
    /// share of `node` would carry, so a caller that reports both reads the
    /// parent once.
    ///
    /// The scope is `None` for a node the index does not name under
    /// [`UnindexedScope::Refuse`] — a miss whose refusal shape is the caller's.
    async fn owner_scope_standing(
        &self,
        node: NodeId,
        api: &Rc<ApiClient<T::Http, T::CredentialStore>>,
        keys: OwnerRotationKeys<'_>,
        check: &'static str,
        unindexed: UnindexedScope,
    ) -> Result<(Option<OwnerScope>, ShareStanding), EngineError> {
        let root = self.snapshot.borrow().root;
        if node == root {
            return Ok((
                Some(OwnerScope {
                    scope: self.vault_root_scope()?,
                    parent_node_seed: None,
                    vouched: true,
                }),
                ShareStanding::VaultRoot,
            ));
        }
        if !self.snapshot.borrow().contains(node) {
            return Err(EngineError::UnsupportedTarget { check });
        }
        let (_, current, _) = self
            .enclosing_scope(node, api, keys, PointerConsultArm::Refused)
            .await?;
        let standing = record_share_standing(node, current.v, &current.direct_child_scope_index);
        let indexed = current
            .direct_child_scope_index
            .iter()
            .find(|child| child.scope_id == node.0)
            .cloned();
        let vouched = indexed.is_some();
        let scope = match (indexed, unindexed) {
            (Some(child), _) => child,
            (None, UnindexedScope::Refuse) => return Ok((None, standing)),
            (None, UnindexedScope::Derive) => ChildScopeRef::new(
                node.0,
                derive_write_name(&current.write_scope_seed, &node.0)
                    .as_str()
                    .as_bytes()
                    .to_vec(),
            ),
        };
        Ok((
            Some(OwnerScope {
                parent_node_seed: Some(Zeroizing::new(
                    *kdf::node_seed(&current.override_seed, &node.0).as_bytes(),
                )),
                scope,
                vouched,
            }),
            standing,
        ))
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
                        commitment: &current.commitment,
                        commitment_sig: &current.commitment_sig,
                        grant_ledger: &current.grant_ledger,
                        direct_child_scope_index: &current.direct_child_scope_index,
                        revoked_recipients: &[],
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

    /// Revoke a recipient's grant at `node`'s scope root.
    ///
    /// The owner's half of the same pairwise ECDH the recipient self-locates
    /// under names the tag, so it is derived here and never taken from a caller.
    async fn revoke_grant(
        &self,
        node: NodeId,
        recipient_identity_public_key: &[u8],
    ) -> Result<(), EngineError> {
        self.cut_recipient(node, recipient_identity_public_key, CutKind::Revoke)
            .await
    }

    /// Demote a recipient's write grant at `node`'s scope root to read
    /// (blueprint/engine.md "Triggers": write revoke / downgrade).
    ///
    /// The read plane is untouched — the recipient keeps the grant they hold —
    /// so the cut is driven through the write plane alone, behind the pre-wave
    /// publish of the demoted set that [`rotate_on_cut`] owes it.
    async fn downgrade_grant(
        &self,
        node: NodeId,
        recipient_identity_public_key: &[u8],
    ) -> Result<(), EngineError> {
        self.cut_recipient(node, recipient_identity_public_key, CutKind::Downgrade)
            .await
    }

    /// The shared spine of [`revoke_grant`](Self::revoke_grant) and
    /// [`downgrade_grant`](Self::downgrade_grant).
    ///
    /// The owner's half of the same pairwise ECDH the recipient self-locates
    /// under names the tag, so it is derived here and never taken from a caller.
    async fn cut_recipient(
        &self,
        node: NodeId,
        recipient_identity_public_key: &[u8],
        kind: CutKind,
    ) -> Result<(), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let contact = self
            .recipient_contact(session, recipient_identity_public_key)
            .await?;
        let cut = self
            .cut_and_rotate(
                node,
                kind.target_check(),
                UnindexedScope::Refuse,
                kind,
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
            .await;
        // A claim conversion records its claimant only so a cut can resolve
        // them; the grant is gone, so the entry returns the room it took. The
        // book keeps a contact that still holds a converted grant elsewhere, and
        // never drops one the owner imported or granted directly.
        //
        // Also on the already-cut verdict: a book write that failed behind a cut
        // that landed leaves a retry facing a set the tag has already left, and
        // without this the room the claim took would never come back.
        let cut_reached_the_set = match &cut {
            Ok(_) => true,
            Err(EngineError::MalformedInput { check }) => *check == RevokeError::NotGranted.check(),
            Err(_) => false,
        };
        if kind == CutKind::Revoke && cut_reached_the_set {
            self.contact_store(session)
                .forget_link_grant(&contact.identity_pk().to_sec1(), &node.0)
                .await
                .map_err(EngineError::from_contact_store)?;
        }
        cut.map(|_| ())
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
        kind: CutKind,
        select: S,
    ) -> Result<[u8; 32], EngineError>
    where
        S: AsyncFnOnce(&OwnerScope, &CascadeTarget) -> Result<[u8; 32], EngineError>,
    {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let owner_keys = || OwnerRotationKeys {
            enc_secret: session.enc_subkey(),
            identity: &owner_identity,
            scope_keys: &scope_keys,
        };
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
            pointer_read_key: &current.pointer_read_key,
        };
        let cut = match kind {
            // A write grant is cut by `revoke_write_grant`, never by a read
            // revoke — the read cut refuses it by name, which is what selects
            // the arm.
            CutKind::Revoke => match revoke_read_grant(&plan, &tag) {
                Err(RevokeError::WriteGranted) => {
                    revoke_write_grant(&plan, &tag, WriteRevokeKind::Full)
                }
                read_cut => read_cut,
            },
            CutKind::Downgrade => revoke_write_grant(&plan, &tag, WriteRevokeKind::DowngradeToRead),
        }
        .map_err(EngineError::from_revoke)?;

        self.drive_cut(node, &target, &scope_root_name, &cut)
            .await?;
        Ok(tag)
    }

    /// Drive an authorized cut at `target` through the planes it demands
    /// ([`rotate_on_cut`] over the production [`OwnerCutNet`]).
    async fn drive_cut(
        &self,
        node: NodeId,
        target: &OwnerScope,
        scope_root_name: &IpnsName,
        cut: &RevokedCommittedSet,
    ) -> Result<CutRotationReport, EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let sweep = self.sweep_factory()?;
        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let owner_pointer_seed = session.owner_pointer_seed();
        let vault_pointer_signer = self
            .vault_pointer_index
            .get()
            .map(|index| session.vault_pointer_signer(index));
        let rotator = OwnerCutNet {
            transport: &self.seams.record_transport,
            api: api.as_ref(),
            gateway: &self.gateway,
            http: &self.seams.http,
            floors: &self.seams.floor_store,
            scheduler: &self.seams.scheduler,
            profile: &self.profile,
            entropy: &self.entropy,
            keys: OwnerRotationKeys {
                enc_secret: session.enc_subkey(),
                identity: &owner_identity,
                scope_keys: &scope_keys,
            },
            owner_signer: session.identity(),
            owner_pointer_seed: owner_pointer_seed.as_bytes(),
            vault_pointer_signer: vault_pointer_signer.as_ref(),
            held: &self.held_records,
            payload_version: POINTER_PAYLOAD_VERSION,
            scope_root_name,
            scope_id: target.scope.scope_id,
            parent_node_seed: target.parent_node_seed.as_deref(),
            session_root_scope_id: self.snapshot.borrow().root.0,
            sweep: &|| sweep(target.scope.clone(), target.parent_node_seed.clone()),
        };
        let report = rotate_on_cut(&rotator, node, cut)
            .await
            .map_err(EngineError::from_rotation)?;
        // The planes have published the cut set, so this device now refuses the
        // set it just cut. The gate raises the same floor from any adopted
        // record; without this raise the owner keeps accepting the pre-cut root
        // a surviving write grantee republishes, until its next resolve here.
        record_cut_epoch_floor(
            &self.seams.floor_store,
            &target.scope.scope_id,
            cut.commitment.cut_epoch,
        )
        .await
        .map_err(EngineError::from_seam)?;
        if let Some(write) = report.write.as_ref() {
            // First, and before anything fallible: the wave already published,
            // so every later step in this method can fail without leaving the
            // session anchored on the root the wave moved off. No index carries
            // the vault root's name, so this cell is its only record.
            if node.0 == self.snapshot.borrow().root.0 {
                *self.current_root_name.borrow_mut() = Some(write.new_root_name.clone());
            }
            // The wave publishes the re-point but never pre-advances the floor
            // (`WriteEpochLease`): a failed publish must not brick the plane.
            // Once it has landed, this session authored that owner-vouched
            // `writeEpoch`, and the root it signed binds the same value as its
            // owner-write blob's AAD — so the floor follows it here, exactly as
            // a later consult of the pointer this wave just wrote would move it.
            // Monotonic-max, so it can never roll one back. The wave holds no
            // lease by the time it returns, so the raise is never deferred.
            floor::advance_write_epoch_on_sight(
                &self.seams.floor_store,
                &target.scope.scope_id,
                write.new_write_epoch,
            )
            .await
            .map_err(EngineError::from_seam)?;
            // Every wave moves the root, so every wave owes the index the same
            // repoint — the vault root excepted, handled above.
            if node.0 != self.snapshot.borrow().root.0 {
                self.repoint_child_scope_index(node, &write.new_root_name)
                    .await?;
            }
        }
        Ok(report)
    }

    /// Grant a node to an imported contact
    /// (blueprint/engine.md "Grant creation").
    async fn grant(
        &self,
        node: NodeId,
        recipient_identity_public_key: &[u8],
        permission: Permission,
    ) -> Result<CommandOutcome, EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let contact = self
            .recipient_contact(session, recipient_identity_public_key)
            .await?;
        self.share_scope(node, ScopeShare::Contact(&contact), permission)
            .await
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
        self.share_scope(node, ScopeShare::InviteLink { expires_at }, permission)
            .await
    }

    /// Mint the fresh scope a share of `node` is granted at: converge the
    /// subtree, mint the scope at epoch 1, reparent whatever descendant scope
    /// roots the node carries, republish the parent's direct-child-scope index,
    /// and deliver what `share` owes its recipient
    /// (blueprint/engine.md "Grant creation").
    ///
    /// A `Permission::Write` share adds the write-scope cut between the mint and
    /// the delivery: the mint seals a freshly drawn `writeScopeSeed`, and the
    /// name wave then moves the subtree onto the names that seed's successor
    /// derives ([`Self::cut_granted_write_scope`]).
    ///
    /// Owner-only by construction: the parent's re-seal is signed under the
    /// owner's writer pseudonym and its commitment under the owner identity, so
    /// no other session can author it.
    async fn share_scope(
        &self,
        node: NodeId,
        share: ScopeShare<'_>,
        permission: Permission,
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
        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let owner_keys = || OwnerRotationKeys {
            enc_secret: session.enc_subkey(),
            identity: &owner_identity,
            scope_keys: &scope_keys,
        };
        // The parent is the scope that already holds the folder, which is the
        // vault root only when no scope this vault granted encloses it. Its
        // commitment, ledger, seeds and index are the ones the mint re-seals,
        // and the converge pass that follows consults the scope pointer.
        let (parent_scope, current, net) = self
            .enclosing_scope(node, api, owner_keys(), PointerConsultArm::Permitted)
            .await?;
        let parent = &parent_scope.scope;

        if let Some(check) = checks.refusal(record_share_standing(
            node,
            current.v,
            &current.direct_child_scope_index,
        )) {
            return Err(EngineError::UnsupportedTarget { check });
        }

        self.refuse_an_unindexed_scope(node, &current, api, owner_keys(), checks.already_a_scope)
            .await?;
        let parent_node_seed = kdf::node_seed(&current.override_seed, &node.0);

        let rendered = self.render().await?;
        // A link owes the bound too: the pointer its conversion posts carries
        // this label, so a link minted past it would be one nobody can claim.
        let display_name = share_display_name(&rendered, node)?;
        let subtree = subtree_child_scopes(&rendered, node, &current.direct_child_scope_index)?;

        let pointer_read_key = session.pointer_read_key(&node.0);
        let pseudonym_signer = session.owner_writer_pseudonym_signer(&node.0);
        // A read grant cuts no write scope: the granted node keeps the
        // write-plane material it already publishes under. A write grant draws
        // its own, because the mint seals this value into the grantee's blob and
        // the inherited seed derives every name in the scope the node is
        // leaving.
        let granted_write_scope_seed = match permission {
            Permission::Read => None,
            Permission::Write => Some(
                fresh_seed(&mut SharedEntropy(&self.entropy)).map_err(EngineError::from_entropy)?,
            ),
        };
        let grantee = GranteeScopePlan {
            v: current.v,
            scope_id: node.0,
            parent_node_seed: parent_node_seed.as_bytes(),
            owner_enc_pub: &current.owner_enc_pub,
            write_scope_seed: &current.write_scope_seed,
            write_cut: granted_write_scope_seed.as_deref(),
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
                // An interior parent is itself a descendant, so its re-seal owes
                // the ascent link it already carries.
                ascent: parent_scope
                    .parent_node_seed
                    .as_deref()
                    .map(AscentAuthority::ParentSeed),
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

        let scope_root_name = grantee.ipns_name();
        let pending = match &share {
            ScopeShare::Contact(contact) => {
                let recipient = GrantRecipient {
                    contact,
                    display_name,
                };
                create_grant(
                    &mut SharedEntropy(&self.entropy),
                    &net,
                    &net,
                    &grantee,
                    &recipient,
                    &owner,
                    &parent_plan,
                )
                .await
                .map_err(EngineError::from_create_grant)?;
                PendingShare::SharePointer(recipient)
            }
            ScopeShare::InviteLink { expires_at } => PendingShare::Fragment(
                mint_invite_link(
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
                        expires_at: *expires_at,
                    },
                )
                .await
                .map_err(EngineError::from_invite_mint)?,
            ),
        };

        if let ScopeShare::Contact(contact) = &share {
            // The grant this mint published is one no claim conversion recorded,
            // so a later cut must not collect the recipient's book entry and
            // leave that grant with no resolvable recipient. An owner grant is a
            // vouch, and it outranks whatever a claim wrote.
            self.contact_store(session)
                .vouch(&contact.identity_pk().to_sec1())
                .await
                .map_err(EngineError::from_contact_store)?;
        }
        let scope_root_name = match permission {
            Permission::Read => scope_root_name,
            Permission::Write => {
                self.cut_granted_write_scope(node, &scope_root_name, parent_node_seed.as_bytes())
                    .await?
            }
        };
        match pending {
            PendingShare::SharePointer(recipient) => post_share_pointer(
                &mut SharedEntropy(&self.entropy),
                api.as_ref(),
                &owner,
                &grantee,
                &recipient,
                &scope_root_name,
            )
            .await
            .map(|()| CommandOutcome::Done)
            .map_err(EngineError::from_create_grant),
            PendingShare::Fragment(link) => link
                .seal(&scope_root_name)
                .map(CommandOutcome::InviteLinkMinted)
                .map_err(EngineError::from_invite_mint),
        }
    }

    /// Refuse when a live scope root already answers at the name a mint would
    /// publish `node`'s under.
    ///
    /// [`record_share_standing`] decides from the parent's index, which
    /// `mint_grantee_scope` writes last: a mint that published the grantee scope
    /// root and then failed leaves a live scope the index does not name. A mint
    /// over it would republish at that same derived name under a fresh override
    /// seed and cut the first grantee off a scope they still hold — a revocation
    /// the owner never asked for.
    ///
    /// Two answers refuse, and both are needed.
    ///
    /// A read-epoch floor at `node`'s own scope id is the first: only a scope
    /// root adopted at that id ever raises one, and it is what answers when the
    /// record there sits below the floor this device already holds — a state the
    /// gate reports as a plain rejection rather than as the live scope it is.
    ///
    /// The gated read is the second, under the ascent authority a real scope
    /// root there must answer to.
    ///
    /// Past both, `node`'s own record is what answers at that name until a mint
    /// promotes it, so a rejection is the ordinary "no scope here" and the share
    /// proceeds. A name this pass could not read leaves the question open, and
    /// the answer that costs nothing is to retry.
    async fn refuse_an_unindexed_scope(
        &self,
        node: NodeId,
        parent: &CascadeTarget,
        api: &Rc<ApiClient<T::Http, T::CredentialStore>>,
        keys: OwnerRotationKeys<'_>,
        check: &'static str,
    ) -> Result<(), EngineError> {
        if floor::read_epoch_floor(&self.seams.floor_store, &node.0)
            .await
            .map_err(EngineError::from_seam)?
            .is_some()
        {
            return Err(EngineError::UnsupportedTarget { check });
        }
        let probe = OwnerScope {
            scope: ChildScopeRef::new(
                node.0,
                derive_write_name(&parent.write_scope_seed, &node.0)
                    .as_str()
                    .as_bytes()
                    .to_vec(),
            ),
            parent_node_seed: Some(Zeroizing::new(
                *kdf::node_seed(&parent.override_seed, &node.0).as_bytes(),
            )),
            vouched: false,
        };
        match self
            .owner_rotation_net(api, keys, probe.ancestry(), PointerConsultArm::Refused)
            .resolve_anchored(&probe.scope)
            .await
        {
            Ok(_) => Err(EngineError::UnsupportedTarget { check }),
            Err(ResolveFailure::Rejected) => Ok(()),
            Err(other) => Err(EngineError::from_resolve_failure(other)),
        }
    }

    /// The write-scope cut a write grant owes, over the scope the mint just
    /// published (blueprint/engine.md "Grant creation").
    ///
    /// Until this lands the granted subtree still sits at names the scope it
    /// left derives, so the seed in the grantee's blob derives nothing they can
    /// resolve and the owner alone authors there. The wave moves the subtree
    /// onto names only the granted scope's `writeScopeSeed` derives, which is
    /// what lets a later cut of this grantee re-key one scope instead of the
    /// vault.
    ///
    /// The set driven is the one the mint published, read back off the record
    /// and proven owner-signed by [`cut_for_write_grant`] — the same authority a
    /// revoke's cut runs under, never a set this session merely believes it
    /// wrote.
    ///
    /// Returns the name the wave moved the scope root to, which is the name the
    /// share owes its recipient.
    ///
    /// This runs inside the non-atomic tail
    /// [`CreateGrantError`](crate::grants::CreateGrantError) documents, but ahead
    /// of the delivery: the grantee root is published and the parent index names
    /// it. A failure therefore leaves a scope the recipient was never told
    /// about, and no command re-drives the owed wave — the owner revokes the
    /// grantee and grants again.
    async fn cut_granted_write_scope(
        &self,
        node: NodeId,
        scope_root_name: &IpnsName,
        parent_node_seed: &[u8; SECRET_LEN],
    ) -> Result<IpnsName, EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let target = OwnerScope {
            scope: ChildScopeRef::new(node.0, scope_root_name.as_str().as_bytes().to_vec()),
            parent_node_seed: Some(Zeroizing::new(*parent_node_seed)),
            vouched: true,
        };
        let current = self
            .owner_rotation_net(
                api,
                OwnerRotationKeys {
                    enc_secret: session.enc_subkey(),
                    identity: &owner_identity,
                    scope_keys: &scope_keys,
                },
                target.ancestry(),
                PointerConsultArm::Refused,
            )
            .resolve_anchored(&target.scope)
            .await
            // The mint published this root and the parent's index names it, so
            // a gate rejection here is a trust violation, never a bad target.
            .map_err(EngineError::from_resolve_failure)?;
        let cut = cut_for_write_grant(&GrantCutPlan {
            commitment: &current.commitment,
            commitment_sig: &current.commitment_sig,
            grant_ledger: &current.grant_ledger,
            scope_root_name,
            owner_signer: session.identity(),
            pointer_read_key: &current.pointer_read_key,
        })
        .map_err(EngineError::from_revoke)?;
        // `cut_for_write_grant` sets the write plane, so the wave ran and its
        // outcome names the root the grantee resolves.
        self.drive_cut(node, &target, scope_root_name, &cut)
            .await?
            .write
            .map(|write| write.new_root_name)
            .ok_or(EngineError::TrustViolation {
                message: "the write-scope cut reported no name wave".to_owned(),
            })
    }

    /// Point the enclosing scope's direct-child-scope index at the name a
    /// write-scope cut moved `node`'s scope root to.
    ///
    /// The index is the owner's own authority for where an interior scope root
    /// lives ([`Self::owner_scope_standing`]), and a later owner action reads it
    /// before it consults any pointer. Left naming the pre-wave root, the next
    /// revoke or downgrade of this grantee would resolve a name the scope has
    /// moved off. A metadata-only re-seal at the parent's current epoch, so it
    /// cuts no plane.
    async fn repoint_child_scope_index(
        &self,
        node: NodeId,
        moved: &IpnsName,
    ) -> Result<(), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let owner_keys = || OwnerRotationKeys {
            enc_secret: session.enc_subkey(),
            identity: &owner_identity,
            scope_keys: &scope_keys,
        };
        let (parent_scope, current, net) = self
            .enclosing_scope(node, api, owner_keys(), PointerConsultArm::Permitted)
            .await?;
        let parent = &parent_scope.scope;
        let index = insert_child(
            &current.direct_child_scope_index,
            ChildScopeRef::new(node.0, moved.as_str().as_bytes().to_vec()),
        );
        let section = reseal_scope_root(
            &mut SharedEntropy(&self.entropy),
            &ScopeRootIdentity {
                v: current.v,
                scope_id: parent.scope_id,
                ipns_name: &parent.ipns_name,
                owner_enc_pub: &current.owner_enc_pub,
                owner_enc_secret: Some(session.enc_subkey()),
                ascent: parent_scope
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
                commitment: &current.commitment,
                commitment_sig: &current.commitment_sig,
                grant_ledger: &current.grant_ledger,
                direct_child_scope_index: &index,
                revoked_recipients: &[],
            },
            &current.carried_history_links,
        )
        .map_err(|e| EngineError::from_rotate(RotateError::Reseal(e)))?;
        net.publish_scope_root(&ResealedScopeRoot {
            scope_id: parent.scope_id,
            ipns_name: parent.ipns_name.clone(),
            read_epoch: current.current_read_epoch,
            write_epoch: current.write_epoch,
            section,
        })
        .await
        .map_err(|e| EngineError::from_rotate(RotateError::Publish(e)))
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

        // The cut names the tag the set carries now; the record set files the
        // link under the tag it was minted at, and a write wave between the two
        // moves them apart ([`CommittedLink`]).
        let mut recorded_tag = None;
        // Owner-only, and derived from the owner's own records: the tag comes
        // from a record this session's encryption subkey re-derives, never from
        // the command.
        self.cut_and_rotate(
            node,
            "revoke-link-target-is-not-a-scope-root",
            UnindexedScope::Derive,
            CutKind::Revoke,
            async |target: &OwnerScope, current: &CascadeTarget| {
                let commitment_sig = parsed_commitment_sig(&current.commitment_sig)?;
                let scope = bound_scope(target, current, &commitment_sig)?;
                let link = locate_invite_link(
                    &OwnerAuthority {
                        identity_signer: session.identity(),
                        enc_secret: session.enc_subkey(),
                    },
                    &scope,
                    &links,
                )
                .map_err(EngineError::from_invite)?;
                recorded_tag = Some(link.record.tag);
                Ok(link.tag)
            },
        )
        .await?;

        records.forget_links(&BTreeSet::from_iter(recorded_tag));
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

        // Bound like every other invite read: a record set is destroyed against
        // the commitment this scope's own gated reference names, never a pair a
        // caller assembled.
        let commitment_sig = parsed_commitment_sig(&current.commitment_sig)?;
        let dead = partition_scope_links(
            session.enc_subkey(),
            &records.links,
            &bound_scope(&target, &current, &commitment_sig)?,
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
            session.contact_code(),
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
            .authorise(&bound_scope(&target, &current, &commitment_sig)?)
            .map_err(EngineError::from_invite)?;
        enforce_committed_ledger(&current.commitment, &current.grant_ledger)
            .map_err(|v| EngineError::from_invite(InviteError::Authority(v)))?;

        let mut failure: Option<EngineError> = None;
        for item in &items {
            let converted = convert_invite_claim(
                &authority,
                &bound_scope(&target, &current, &commitment_sig)?,
                &current.pointer_read_key,
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
                link_tag,
                claimant_code,
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

            // Ahead of the publish: `revoke`/`downgrade` resolve their recipient
            // in the contact book alone, so a grant this owner cannot later cut
            // must never reach the record plane. A book with no room refuses the
            // conversion and the item stays un-acked. The write is charged to
            // the link that drove it, so bearer traffic cannot crowd out the
            // contacts the owner imported by hand.
            if let Err(e) = self
                .contact_store(session)
                .record_from_link(&claimant_code, &link_tag, &target.scope.scope_id)
                .await
            {
                failure.get_or_insert(EngineError::from_contact_store(e));
                continue;
            }

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
                        // The owner's own grant decision, and the only evidence
                        // of one this pass holds: the conversion **minted** this
                        // row, and the set carrying it landed. `Upgraded` and
                        // `Unchanged` both turn on a row the resolved record
                        // already carried, which a committed write grantee
                        // authors, so neither may lift a cut
                        // (`rotation::record_grant_floor`).
                        if outcome == ClaimOutcome::Granted {
                            if let Err(e) = record_grant_floor(
                                &self.seams.floor_store,
                                &target.scope.scope_id,
                                &claimant.enc_subkey(),
                                current.current_read_epoch,
                            )
                            .await
                            {
                                failure.get_or_insert(EngineError::from_seam(e));
                                continue;
                            }
                        }
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
                commitment,
                commitment_sig: &signature.to_compact(),
                grant_ledger: ledger,
                direct_child_scope_index: &current.direct_child_scope_index,
                revoked_recipients: &[],
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
        *self.settings_summary.borrow_mut() = Some(settings.summary(SettingsOrigin::Resolved));
        self.byo_reconciled.set(false);
        Ok(())
    }

    /// The scope's cached read seed, evicted first if the durable read-epoch
    /// floor has risen past the one it was recovered under. Every on-demand
    /// read goes through here; the resolve tick evicts once per pass.
    async fn scope_read_seed(&self, scope_id: &[u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
        let own_root = self.snapshot.borrow().root.0;
        let sharers = self.grafted_sharers.borrow().clone();
        let Some(floors) = floor_view(&self.seams.floor_store, &sharers, &own_root, scope_id)
        else {
            self.scope_read_seeds.borrow_mut().remove(scope_id);
            return None;
        };
        refresh_seed_floor(&floors, &self.scope_read_seeds, scope_id, SeedFloor::Read).await;
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
        match self.provision_first_run_vault(&api, root.0).await {
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
                if !self.install_cold_start(outcome, root.0) {
                    return Err(EngineError::RefreshFailed {
                        message: "the vault pointer served no root to adopt".to_owned(),
                    });
                }
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
        }
        self.open_tick_loop();
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
        // One leg holds one scope's read material, so a folder in a shared scope
        // this vault accepted refreshes on the tick's own leg for that scope,
        // never here under the vault's seed.
        let (scope_id, due) = {
            let base = self.snapshot.borrow();
            let mine = due
                .into_iter()
                .filter(|node| scope_root_of(&base, *node) == base.root)
                .collect::<Vec<_>>();
            (base.root.0, mine)
        };
        if due.is_empty() {
            return false;
        }
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
            plane: None,
            mode: ResolveMode::CacheFirst,
            observed_at: now.0,
        }
        .run(&due)
        .await;
        hold_captures(&self.observed_unlinks, report.departed);
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
            WriteTarget::NewFile { parent, name } => {
                refuse_unlawful_name(name)?;
                let rendered = self.render().await?;
                refuse_outside_vault(&rendered, *parent)?;
                refuse_full_parent(&rendered, *parent, None, None)?;
                None
            }
            WriteTarget::Version {
                node,
                expected_version,
            } => {
                let rendered = self.render().await?;
                refuse_outside_vault(&rendered, *node)?;
                match rendered.node(*node).map(|meta| meta.kind) {
                    Some(NodeKind::Folder) => return Err(EngineError::NotAFile),
                    Some(_) => match expected_version {
                        // Shape-checked at the boundary rather than left to fail
                        // closed on the drain: an anchor that is not a content
                        // CID can only ever park the write, and a parked write
                        // spends a slot in a set that evicts oldest-first.
                        Some(expected) if expected.len() != CONTENT_CID_LEN => {
                            return Err(EngineError::MalformedInput {
                                check: "expected-version-is-not-a-content-cid",
                            });
                        }
                        Some(expected) => Some(expected.clone()),
                        None => self.write_anchor(*node).await?,
                    },
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
                WriteTarget::Version { node, .. } => *node,
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
        // Re-checked here, not only at `begin_write`: a `NewFile` handle takes no
        // place in the folder until it commits, so handles opened together all
        // see the same free one.
        if let WriteTarget::NewFile { parent, .. } = &target {
            refuse_full_parent(&self.render().await?, *parent, None, None)?;
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
            WriteTarget::Version { node, .. } => {
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
    /// `NotStarted` before [`start`](Self::start), like the exchange that spends
    /// the nonce — SIWE is a secondary method (blueprint/engine.md
    /// "API client").
    ///
    /// The intent picks the pool ([`SiweIntent`]).
    pub async fn siwe_challenge(&self, intent: SiweIntent) -> Result<String, EngineError> {
        self.live_session()?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let nonce = match intent {
            SiweIntent::Login => api.siwe_challenge().await,
            SiweIntent::Link => api.siwe_link_challenge().await,
        }
        .map_err(EngineError::from_api)?;
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

    /// Why the debts the last reclaim pass could not settle did not settle.
    ///
    /// Reclaim has no attempt budget and no dead-letter class, so a debt that
    /// never settles is otherwise invisible: the pending figure counts only what
    /// a pass could price, and a stalled debt prices at nothing. Empty once the
    /// ledger drains, and re-derived on every pass, so a cleared stall clears
    /// here too (blueprint/engine.md "never a silent failure").
    #[must_use]
    pub fn reclaim_stalls(&self) -> Vec<ReclaimStall> {
        self.reclaim_stalls.borrow().clone()
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
        let children = rendered_children(&rendered, folder)
            .iter()
            .map(|child| SnapshotChild {
                id: child.meta.id,
                name: child.name().to_owned(),
                kind: child.meta.kind,
                size: child.meta.size,
                mtime: child.meta.mtime,
                pending: pending.get(&child.meta.id).copied().unwrap_or_default(),
                dead_letter: dead_nodes.contains(&child.meta.id),
                content_version: child.meta.content_version,
                content_cid: child.meta.head_content_cid.clone(),
            })
            .collect();
        let ancestors = rendered
            .ancestors(folder)
            .into_iter()
            .map(|id| Breadcrumb {
                id,
                name: rendered_name(&rendered, id),
            })
            .collect();
        let folder_name = rendered_name(&rendered, folder);
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

    /// The storage pane's whole read ([`VaultStorageView`]).
    pub async fn vault_storage(&self) -> Result<VaultStorageView, EngineError> {
        self.live_session()?;
        let settings = self
            .settings_summary
            .borrow()
            .clone()
            .ok_or(EngineError::NotStarted)?;
        let quota = match &self.api {
            Some(api) => api.quota().await.ok(),
            None => None,
        };
        Ok(VaultStorageView {
            quota: quota.map(|quota| QuotaView {
                used_bytes: quota.used_bytes,
                limit_bytes: quota.limit_bytes,
                // The vaulted mode is authoritative for this device; the account
                // flag adds what a sibling device placed externally, which this
                // device's settings cannot show.
                advisory: settings.pin_mode != PinMode::Hosted || quota.advisory,
            }),
            settings,
            pending_reclaim_bytes: self.pending_reclaim_bytes(),
            reclaim_stalls: self.reclaim_stalls(),
        })
    }

    /// The login methods on this account, for the account settings pane.
    pub async fn auth_methods(&self) -> Result<Vec<AuthMethod>, EngineError> {
        self.live_session()?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        api.auth_methods().await.map_err(EngineError::from_api)
    }

    /// The device identity keys registered to this account (ADR 0009 D4).
    pub async fn devices(&self) -> Result<Vec<RegisteredDevice>, EngineError> {
        self.live_session()?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        api.devices().await.map_err(EngineError::from_api)
    }

    /// The bytes a device signs to join this account's registry.
    ///
    /// The account id is read from the engine's own session rather than named
    /// by the host, so a host cannot ask for a payload naming another account.
    pub async fn device_registration_challenge(
        &self,
        device_public_key: &str,
    ) -> Result<Vec<u8>, EngineError> {
        self.live_session()?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let account_id = api.account_id().map_err(EngineError::from_api)?;
        malformed(devices::registration_payload(
            &account_id,
            device_public_key,
        ))
    }

    /// What this account is asked to approve, each row carrying the comparison
    /// value its screen must show (ADR 0009 D3).
    ///
    /// A row whose request binding does not verify, or whose relayed fields
    /// cannot produce a comparison value, is dropped rather than offered: it
    /// could never be approved safely, and rendering it would ask a member to
    /// authorise something the requester never signed.
    pub async fn pending_approvals(&self) -> Result<Vec<PendingApprovalView>, EngineError> {
        self.live_session()?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let rows = api
            .pending_approvals()
            .await
            .map_err(EngineError::from_api)?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        // A device already on the registry has a factor of its own and needs no
        // approval, so a row naming one is a relay's invention rather than a
        // member's device. The read runs only when a row arrived.
        let registered = api.devices().await.map_err(EngineError::from_api)?;
        Ok(rows
            .into_iter()
            .filter(|row| {
                devices::request_binding_holds(
                    &row.requester_device_public_key,
                    &row.ephemeral_public_key,
                    &row.request_signature,
                ) && !registered
                    .iter()
                    .any(|device| device.public_key == row.requester_device_public_key)
            })
            .filter_map(|row| {
                // A row this engine could never answer is never offered: the id
                // has to survive the same path check the response takes.
                devices::check_registry_id(&row.request_id).ok()?;
                let comparison_value = devices::comparison_value(
                    &row.requester_device_public_key,
                    &row.ephemeral_public_key,
                )
                .ok()?;
                Some(PendingApprovalView {
                    request_id: row.request_id,
                    requester_device_public_key: row.requester_device_public_key,
                    ephemeral_public_key: row.ephemeral_public_key,
                    comparison_value,
                    created_at: row.created_at,
                    expires_at: row.expires_at,
                })
            })
            // The cap is spent on rows that survived verification, so a relay
            // cannot bury the member's row behind rows it invented. Lazy, so a
            // list that yields a full screen stops being read here.
            .take(devices::MAX_PENDING_APPROVALS)
            .collect())
    }

    /// The shares this vault has accepted, key-free, each carrying the engine's
    /// own resolution verdict (blueprint/web-client.md "/shared").
    ///
    /// The rows come from the durable received-shares list, so they survive a
    /// reload; the verdict comes from the focus tick's last resolve of that
    /// scope root, so a revocation the owner published is *discovered* here
    /// rather than delivered.
    ///
    /// The label is the one the graft renders under ([`grafted_root_name`]), so
    /// this row and the folder it opens name the same thing.
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
                display_name: grafted_root_name(&share.display_name, NodeId(share.scope_id))
                    .to_string(),
                permission: share.permission.into(),
                resolution: verdicts.get(&share.key()).map(|v| v.class),
            })
            .collect())
    }

    /// The owner's bin, one row per soft-deleted node, for the `/bin` route.
    ///
    /// Owner-only by construction: a grantee's session holds no bin index key,
    /// so this read answers for the owner alone (CONTEXT.md "Bin index").
    pub async fn bin(&self) -> Result<BinView, EngineError> {
        self.live_session()?;
        let (index, origin) = match self.owner_bin_load().await? {
            BinIndexLoad::Resolved(index) => (index, SettingsOrigin::Resolved),
            BinIndexLoad::Stale { index, .. } => (index, SettingsOrigin::Stale),
            BinIndexLoad::Empty(_) => {
                return Ok(BinView {
                    entries: Vec::new(),
                    origin: SettingsOrigin::Defaults,
                });
            }
        };
        // The same rendered view a default restore resolves its destination
        // against, so the two never disagree on what the vault still holds.
        let rendered = self.render().await?;
        Ok(BinView {
            entries: index
                .entries
                .iter()
                .map(|entry| BinRow {
                    node: NodeId(entry.node_id),
                    kind: map_kind(entry.kind),
                    origin_parent: NodeId(entry.origin_parent),
                    origin_name: entry.origin_name().to_owned(),
                    origin_folder: origin_folder(&rendered, NodeId(entry.origin_parent)),
                    deleted_at: entry.deleted_at,
                    scope: NodeId(entry.scope_id),
                })
                .collect(),
            origin,
        })
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
    /// A node the enclosing scope's committed child-scope index does not name is
    /// not a scope root, and nothing is granted at it: the grant list is empty, and
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
        // One decode: a load re-verifies one binding signature per stored code,
        // so the sharing read must not open the book twice.
        let book = self
            .contact_store(session)
            .contacts_with_sources()
            .await
            .map_err(EngineError::from_contact_store)?;
        let sources: Vec<Option<[u8; 32]>> = book.iter().map(|(_, source)| *source).collect();
        let contacts = book
            .into_iter()
            .map(|(contact, _)| SharingContact {
                identity_public_key: contact.identity_pk().to_sec1().to_vec(),
            })
            .collect();
        Ok(SharingView {
            scope: scope_root,
            contacts,
            own_contact_code: session.contact_code(),
            state: self.scope_sharing(session, scope_root, &sources).await,
        })
    }

    /// Everything one resolve of `scope_root` settles for [`Self::sharing`]: the
    /// grant ledger its record commits projected key-free, this owner's invite
    /// links there, and the refusal a further share of it would report.
    ///
    /// The authority for what is a scope root is the enclosing scope's
    /// direct-child-scope index, which
    /// [`owner_scope_standing`](Self::owner_scope_standing) owns — so a node it
    /// does not name has an empty grant list, and only the parent record's own
    /// grounds stand in a mint's way.
    /// A read reports, it does not repair, so an index miss refuses rather
    /// than reaching for a derived name ([`UnindexedScope`]).
    /// A resolve that failed answers `None`, so a host cannot paint "shared with
    /// nobody" over a subtree it simply could not read, nor offer a mint the
    /// engine would refuse.
    async fn scope_sharing(
        &self,
        session: &SessionIdentity,
        scope_root: NodeId,
        sources: &[Option<[u8; 32]>],
    ) -> Option<ScopeSharing> {
        let api = self.api.as_ref()?;
        let owner_identity = session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(session);
        let keys = || OwnerRotationKeys {
            enc_secret: session.enc_subkey(),
            identity: &owner_identity,
            scope_keys: &scope_keys,
        };
        let (target, standing) = self
            .owner_scope_standing(
                scope_root,
                api,
                keys(),
                NOT_A_SCOPE_ROOT,
                UnindexedScope::Refuse,
            )
            .await
            .ok()?;
        let grant_refusal = ShareChecks::GRANT.refusal(standing);
        let invite_link_refusal = ShareChecks::INVITE_LINK.refusal(standing);
        let Some(target) = target else {
            return Some(ScopeSharing {
                grants: Vec::new(),
                grant_refusal,
                invite_link_refusal,
                invite_links: Some(SharingInviteLinks::default()),
            });
        };
        let current = self
            .owner_rotation_net(api, keys(), target.ancestry(), PointerConsultArm::Refused)
            .resolve_anchored(&target.scope)
            .await
            .ok()?;
        // Fail closed on a ledger the owner's commitment does not commit: the
        // write body it rides in is authored by any committed writer, so the row
        // set is only as trustworthy as the owner's commitment over it.
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
        .authorise(&bound_scope(&target, &current, &commitment_sig).ok()?)
        .ok()?;

        // A link store this could not open is absence, not "no links": the grant
        // half of the read still stands.
        let records = self.invite_store(session).load().await.ok();
        let scope = bound_scope(&target, &current, &commitment_sig).ok()?;
        let split = records
            .as_ref()
            .map(|records| partition_scope_links(session.enc_subkey(), &records.links, &scope));
        // One committed record is the live link; two have no defined cut, so the
        // read reports none — the same rule `locate_invite_link` revokes under.
        let live = split
            .as_ref()
            .and_then(|split| match split.committed.as_slice() {
                [link] => Some(link),
                _ => None,
            });
        // Reported at the scope whose link took the headroom, which is what
        // names the link: one scope carries at most one live link, and revoking
        // it is the remedy. It outranks the standing ground because that one is
        // permanent and needs no action, while this one does — and while it
        // stands, a link minted here would only mint claims that cannot convert.
        let invite_link_refusal = match live {
            Some(link) if link_budget_full(sources, &link.record.tag) => {
                Some(LINK_CONTACT_BUDGET_FULL)
            }
            _ => invite_link_refusal,
        };
        let now = self.seams.scheduler.now();
        let invite_links = split.as_ref().map(|split| SharingInviteLinks {
            live: live.is_some(),
            expires_at: live.and_then(|link| link.record.expires_at),
            expired: live
                .and_then(|link| link.record.expires_at)
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
            grant_refusal,
            invite_link_refusal,
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
        let PinnedVersion {
            version,
            staged_op,
            version_count,
        } = self.pinned_version(node).await?;
        // The range clamps to the version's size, so the whole file is the
        // unbounded window.
        let bytes = open_content_range(
            &self.staged_blocks(),
            &self.gateway,
            &self.seams.http,
            &version,
            0,
            u64::MAX,
        )
        .await
        .map_err(|error| staged_open_error(staged_op, error))?;
        self.project_pinned_head(node, &version, version_count);
        Ok(bytes)
    }

    /// The block sources a content read runs over: this device's staging store,
    /// then the gateway.
    ///
    /// One set for every read, because the staging key **is** the block's
    /// `contentCid` — a local hit is byte-identical to what a gateway would
    /// serve for that address, so a half-uploaded version reads across the two
    /// legs (blueprint/engine.md "Content plane").
    fn staged_blocks(&self) -> StagedBlocks<'_, T::StagingStore> {
        StagedBlocks(&self.seams.staging_store)
    }

    /// Repaint the base node from a read that pinned a published head.
    /// A staged version carries no count and repaints nothing: it is this
    /// device's own and not gate-passing state.
    fn project_pinned_head(&self, node: NodeId, version: &Version, version_count: Option<u64>) {
        if let Some(version_count) = version_count {
            self.project_head(node, version, version_count);
        }
    }

    /// The version a read of `node` pins: the one a queued op staged when there
    /// is one, else the published head.
    ///
    /// Serving the staged version is what pairs the length the rendered view
    /// reports with the bytes a partial write composes over
    /// ([`rendered_version_cid`](Self::rendered_version_cid)).
    async fn pinned_version(&self, node: NodeId) -> Result<PinnedVersion, EngineError> {
        match self.staged_version(node).await? {
            Some((op_id, version)) => Ok(PinnedVersion {
                version,
                staged_op: Some(op_id),
                version_count: None,
            }),
            None => {
                let (version, count) = self.head_version(node).await?;
                Ok(PinnedVersion {
                    version,
                    staged_op: None,
                    version_count: Some(count),
                })
            }
        }
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
        let PinnedVersion {
            version,
            staged_op,
            version_count,
        } = self.pinned_version(node).await?;
        let manifest = open_content_root(
            &self.staged_blocks(),
            &self.gateway,
            &self.seams.http,
            &version,
        )
        .await
        .map_err(|error| staged_open_error(staged_op, error))?;
        self.project_pinned_head(node, &version, version_count);
        let mut streams = self.streams.borrow_mut();
        streams.next += 1;
        let handle = StreamHandle(streams.next);
        streams.open.insert(
            handle,
            Rc::new(LiveStream {
                version,
                manifest,
                staged_op,
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
            &self.staged_blocks(),
            &self.gateway,
            &self.seams.http,
            &stream.version,
            &stream.manifest,
            offset,
            length,
        )
        .await
        .map_err(|error| staged_open_error(stream.staged_op, error))
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

    /// The plaintext size of the version a live stream pinned: the exact length
    /// every window off it can serve, so a ranged reader frames a response head
    /// against the bytes it will get rather than a size read before the pin.
    /// `None` for a handle the engine does not hold.
    pub fn stream_size(&self, handle: StreamHandle) -> Option<u64> {
        self.streams
            .borrow()
            .open
            .get(&handle)
            .map(|stream| stream.version.size)
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
                let pending = self.scan_queue().await?;
                let owed = pending.mine.iter().find(|(_, op)| op.target == node);
                return Err(match owed {
                    Some((op_id, _)) => EngineError::ContentUnavailable {
                        message: format!("content not yet published by queued op {}", op_id.0),
                    },
                    None => EngineError::UnknownNode,
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

    /// Plant a child into the base snapshot the way a peer's committed record
    /// does: the command boundary's name law never sees it, so a host suite can
    /// drive names and duplicates this device would refuse to author.
    #[cfg(any(test, feature = "test-kit"))]
    pub fn plant_committed_child(&self, parent: NodeId, child: NodeId, name: &str, kind: NodeKind) {
        let mut base = self.snapshot.borrow_mut();
        base.upsert_node(NodeMeta::new(child, name, kind));
        base.link_next(parent, child);
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

    /// The version the read plane pins for `node` when the queue has staged one,
    /// with the durable id of the op that owes it.
    ///
    /// This is the read half of the pairing rule
    /// [`rendered_version_cid`](Self::rendered_version_cid) states: the reader
    /// serves the very version the rendered length describes, so a partial write
    /// composes its tail over the bytes it measured against.
    async fn staged_version(&self, node: NodeId) -> Result<Option<(OpId, Version)>, EngineError> {
        let Some((op_id, staged, authored_at)) = self.staged_content(node).await? else {
            return Ok(None);
        };
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let scope = self.snapshot.borrow().root;
        let key = open_content_key(
            session.enc_subkey(),
            &scope.0,
            staged.epoch,
            &staged.root_cid,
            &staged.sealed_content_key,
        )
        .map_err(|error| EngineError::ContentUnavailable {
            message: format!(
                "the staged content key of queued op {} did not open: [{}]",
                op_id.0,
                error.check()
            ),
        })?;
        Ok(Some((
            op_id,
            Version::new(staged.root_cid, *key, staged.plaintext_size, authored_at.0),
        )))
    }

    /// The newest queued op that stages content for `node`: its durable id, what
    /// it staged, and the time it was authored — the `modifiedAt` the drain will
    /// publish the version under, so the reader and the publisher agree.
    async fn staged_content(
        &self,
        node: NodeId,
    ) -> Result<Option<(OpId, StagedContent, UnixMillis)>, EngineError> {
        Ok(self
            .scan_queue()
            .await?
            .mine
            .into_iter()
            .rev()
            .find_map(|(op_id, op)| {
                (op.target == node)
                    .then(|| op.staged_content().cloned())
                    .flatten()
                    .map(|staged| (op_id, staged, op.authored_at))
            }))
    }

    /// The `contentCid` of the newest version a queued op has staged for `node`,
    /// `None` when the queue authors none.
    async fn staged_version_cid(&self, node: NodeId) -> Result<Option<Vec<u8>>, EngineError> {
        Ok(self
            .staged_content(node)
            .await?
            .map(|(_, staged, _)| staged.root_cid))
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
        let rendered = self.render().await?;
        refuse_outside_vault(&rendered, node)?;
        Ok(rendered.record_sequence(node).unwrap_or(1))
    }

    fn bin_retention_days(&self) -> u32 {
        bin_retention_days(&self.settings_summary)
    }

    /// Mint a fresh random 16-byte node id from the injected entropy seam
    /// (id16, non-secret; blueprint/core.md). Fails closed on entropy failure —
    /// never a predictable id.
    fn mint_node_id(&self) -> Result<NodeId, EngineError> {
        let id = fresh_bytes(&mut *self.entropy.borrow_mut(), "node id")
            .map_err(EngineError::from_entropy)?;
        Ok(NodeId(id))
    }

    /// Drop one parked write ([`Command::DiscardDeadLetter`]).
    ///
    /// The parked write `op_id` names, with the op it holds.
    ///
    /// Two conditions, both fail-closed, and both because the set is a durable
    /// surface of a store one account shares with another
    /// (`crate::sync::drain` owner scoping). The record must open under **this**
    /// session's own custody, so no session acts on an entry another identity
    /// parked; and the op must have left the durable queue, because the drain
    /// writes the preserved entry before it dequeues, so a crash in that gap
    /// leaves one version named by a live queue entry and by this set at once.
    /// Releasing it then would drop bytes an op is still going to publish.
    async fn parked_write(&self, op_id: OpId) -> Result<(PreservedDeadLetter, Op), EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let queued = self
            .seams
            .staging_store
            .queued_ops()
            .await
            .map_err(EngineError::from_seam)?;
        if queued.iter().any(|(id, _)| *id == op_id) {
            return Err(EngineError::UnknownDeadLetter { op_id });
        }
        let parked = read_preserved_dead_letters(&self.seams.staging_store)
            .await
            .map_err(EngineError::from_seam)?
            .unwrap_or_default()
            .into_iter()
            .find(|entry| entry.op_id == op_id)
            .ok_or(EngineError::UnknownDeadLetter { op_id })?;
        match RecordReader::new(session.enc_subkey()).classify(&parked.record) {
            RecordClass::Mine(op) => Ok((parked, op)),
            _ => Err(EngineError::UnknownDeadLetter { op_id }),
        }
    }

    /// The shortened set is durable before a byte is released, so a failed write
    /// leaves a list that still names the version rather than one naming blocks
    /// that are already gone.
    async fn discard_dead_letter(&self, op_id: OpId) -> Result<(), EngineError> {
        self.live_session()?;
        let (parked, _) = self.parked_write(op_id).await?;
        take_preserved_dead_letter(&self.seams.staging_store, op_id)
            .await
            .map_err(EngineError::from_seam)?;
        // A record whose clear root will not read names no blocks to release;
        // orphan GC reclaims them once this list no longer holds it.
        if let Some(root) = record_content_root_cid(&parked.record).ok().flatten() {
            release_version_blocks(&self.seams.staging_store, root.as_slice()).await;
        }
        self.dead_letters.borrow_mut().remove(&op_id);
        let _ = self.events.unbounded_send(Event::SnapshotUpdated);
        Ok(())
    }

    /// Re-queue one parked write ([`Command::RecoverDeadLetter`]).
    ///
    /// A create mints a fresh node id, so a version the plane already carries is
    /// never re-authored at its own name. Both arms reuse the parked version's
    /// staged blocks, which the new queue entry references from the moment it
    /// lands.
    async fn recover_dead_letter(&mut self, op_id: OpId) -> Result<CommandOutcome, EngineError> {
        self.live_session()?;
        let authored_at = self.seams.scheduler.now();
        let (_, op) = self.parked_write(op_id).await?;

        // A recover re-stages the parked intent, so it owes the caller the
        // refusals `begin_write` gives the same intent: a target that went
        // away while the write was parked, and a parent with no room left.
        let rendered = self.render().await?;
        let fresh = match &op.kind {
            OpKind::UpdateContent { content, .. } => {
                if !rendered.contains(op.target) {
                    return Err(EngineError::UnknownNode);
                }
                Op::update_content(
                    op.target,
                    content.clone(),
                    self.write_anchor(op.target).await?,
                    self.base_sequence_for(op.target).await?,
                    authored_at,
                )
            }
            OpKind::Create { parent, name, node } => {
                refuse_full_parent(&rendered, *parent, None, None)?;
                Op::create(
                    self.mint_node_id()?,
                    *parent,
                    name.clone(),
                    node.clone(),
                    self.base_sequence_for(*parent).await?,
                    authored_at,
                )
            }
            // Every other intent is metadata, which a compensating command
            // expresses directly and which stages no version to recover.
            _ => {
                return Err(EngineError::MalformedInput {
                    check: "parked-write-carries-no-version",
                });
            }
        };

        let outcome = self.stage_and_notify(&fresh).await?;
        // Only after the queue entry references the blocks: a failure here costs
        // a second reference to a version nothing released.
        take_preserved_dead_letter(&self.seams.staging_store, op_id)
            .await
            .map_err(EngineError::from_seam)?;
        self.dead_letters.borrow_mut().remove(&op_id);
        Ok(outcome)
    }

    /// What the owner's bin index says about `node`, for the command that acts
    /// on it.
    async fn binned_node(&self, node: NodeId) -> Result<BinnedNode, EngineError> {
        // A command acts on an established index only: a load this device could
        // not resolve proves nothing about the entry it is about to act on.
        let index = match self.owner_bin_load().await? {
            BinIndexLoad::Resolved(index) | BinIndexLoad::Stale { index, .. } => index,
            BinIndexLoad::Empty(reason) => {
                return Err(EngineError::Seam {
                    message: format!("bin index unresolved: {reason:?}"),
                });
            }
        };
        BinnedNode::of(&index, &node.0).ok_or(EngineError::NotBinned)
    }

    /// The owner's bin index load. A refusal of bytes the plane actually served
    /// is a trust verdict at whichever rung it lands on, never the availability
    /// a caller retries on (AGENTS.md rule 6), so both rungs are charged here.
    ///
    /// A cached index answers as readily as a resolved one: the drain re-reads
    /// the entry before it publishes anything, and a purge is conditional on the
    /// `deletedAt` that read produced.
    async fn owner_bin_load(&self) -> Result<BinIndexLoad, EngineError> {
        let keys = self
            .tick_bin_keys
            .borrow()
            .clone()
            .ok_or(EngineError::NotStarted)?;
        let load = load_bin_index(
            &self.seams.record_transport,
            &self.gateway,
            &self.seams.http,
            &self.seams.floor_store,
            &self.seams.snapshot_cache,
            &self.seams.scheduler,
            &self.profile,
            &keys,
        )
        .await;
        let reason = match load {
            BinIndexLoad::Resolved(_) => return Ok(load),
            BinIndexLoad::Stale { reason, .. } | BinIndexLoad::Empty(reason) => reason,
        };
        if bin_load_is_a_verdict(reason) {
            let message = format!("bin index refused: {reason:?}");
            emit_trust_violation(&self.events, keys.name().as_str(), message.clone());
            return Err(EngineError::TrustViolation { message });
        }
        Ok(load)
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
    /// A folder becomes the focus window; a file joins
    /// [`FocusWindow::open_files`], the queue the tick's file leg drains. Only a
    /// node this device's own gate-passing state calls a file takes the file
    /// path, so a node it has not resolved yet keeps the window behaviour it had
    /// before it was projected.
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
                self.note_focus_file(node);
            }
        }
        stale
    }

    /// Put `node` on the on-access file queue, newest last and bounded by
    /// [`MAX_FOCUS_FILES`]. The focus window and the refresh hint do not move.
    ///
    /// Damped by the same staleness threshold every other on-access refresh
    /// runs against. A file that has published no version projects no size
    /// however often a pass resolves it, so an undamped caller keyed on the
    /// absent size would spend a resolve on that node every tick, forever.
    pub fn note_focus_file(&self, node: NodeId) {
        let now = self.seams.scheduler.now();
        let resolved = self.focus_refreshed.borrow().get(&node).copied();
        if resolved.is_some_and(|last| !on_access_refresh_due(now, last, &self.profile)) {
            return;
        }
        let mut focus = self.focus.borrow_mut();
        focus.open_files.retain(|held| *held != node);
        focus.open_files.push(node);
        if focus.open_files.len() > MAX_FOCUS_FILES {
            focus.open_files.remove(0);
        }
    }

    /// The files the tick's file leg will resolve next, oldest first.
    pub fn queued_focus_files(&self) -> Vec<NodeId> {
        self.focus.borrow().open_files.clone()
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

/// [`open_engine_error`], with the queued op named: every byte and every length
/// a staged read judges came from that one op, so the host has an op to route
/// on rather than a bare verdict.
fn staged_open_error(staged_op: Option<OpId>, error: OpenError) -> EngineError {
    let Some(op_id) = staged_op else {
        return open_engine_error(error);
    };
    let naming = |message: String| format!("{message}; staged by queued op {}", op_id.0);
    match open_engine_error(error) {
        EngineError::ContentUnavailable { message } => EngineError::ContentUnavailable {
            message: naming(message),
        },
        EngineError::TrustViolation { message } => EngineError::TrustViolation {
            message: naming(message),
        },
        verdict => verdict,
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

    #[test]
    fn lookup_prefers_the_exact_name_over_a_folding_twin_that_sorts_first() {
        let root = NodeId([0; 16]);
        let mut rendered = Snapshot::new(root);
        // The ligature U+FB01 folds to "fi", so both names key the same.
        let twin = NodeId([1; 16]);
        let owned = NodeId([2; 16]);
        rendered.upsert_node(NodeMeta::new(twin, "\u{fb01}le.txt", NodeKind::File));
        rendered.link(root, twin, 1);
        rendered.upsert_node(NodeMeta::new(owned, "file.txt", NodeKind::File));
        rendered.link(root, owned, 2);
        let view = EngineView { rendered };

        assert_eq!(
            view.lookup(root, "file.txt").expect("resolves").id,
            owned,
            "the exact name wins the lower-sorting folding twin"
        );
        assert_eq!(
            view.lookup(root, "\u{fb01}le.txt").expect("resolves").id,
            twin,
            "each name still resolves to itself"
        );
    }

    /// `assert_children_unique` binds a folder's children on `id` and on
    /// `ipnsName`, never on `name`, so a grantee that mints a low-sorting id can
    /// commit a child under an owner's exact name. Both must stay reachable, and
    /// under names a host can tell apart.
    #[test]
    fn an_exact_duplicate_renders_under_a_suffix_and_both_children_open() {
        let root = NodeId([0; 16]);
        let mut rendered = Snapshot::new(root);
        let planted = NodeId([1; 16]);
        let owned = NodeId([2; 16]);
        rendered.upsert_node(NodeMeta::new(planted, "q3.pdf", NodeKind::File));
        rendered.link(root, planted, 1);
        rendered.upsert_node(NodeMeta::new(owned, "q3.pdf", NodeKind::File));
        rendered.link(root, owned, 2);
        let view = EngineView { rendered };

        let names: Vec<String> = view.children(root).into_iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            ["q3.pdf", "q3 (1).pdf"],
            "the listing tells them apart"
        );
        assert_eq!(view.lookup(root, "q3.pdf").expect("resolves").id, planted);
        assert_eq!(
            view.lookup(root, "q3 (1).pdf").expect("resolves").id,
            owned,
            "the shadowed child opens under its rendered name"
        );
        assert_eq!(
            view.lookup_exact(root, "q3 (1).pdf").expect("resolves").id,
            owned
        );
    }

    /// The fold is what makes a name the host cannot spell exactly reachable, so
    /// it stays the fallback rather than being dropped for the exact match.
    #[test]
    fn lookup_still_folds_when_no_child_carries_the_exact_name() {
        let root = NodeId([0; 16]);
        let mut rendered = Snapshot::new(root);
        let junk = NodeId([1; 16]);
        rendered.upsert_node(NodeMeta::new(junk, ".Ds_StOrE", NodeKind::File));
        rendered.link(root, junk, 1);
        let view = EngineView { rendered };

        assert_eq!(view.lookup(root, ".DS_Store").expect("folds").id, junk);
        assert!(view.lookup_exact(root, ".DS_Store").is_none());
    }

    /// Every host-facing projection carries a plaintext name, and a wasm build
    /// links `console_error_panic_hook`, so a panic that formats one would put
    /// that name in the browser console. The rendering keeps the shape and the
    /// ids and withholds the name (crates/core/src/codec/redact.rs).
    #[test]
    fn a_host_facing_projection_debug_withholds_the_plaintext_name() {
        const NAME: &str = "quarterly-results.txt";
        const FOLDER: &str = "board-papers";

        let attrs = NodeAttrs {
            id: NodeId([1; 16]),
            name: NAME.to_string(),
            kind: NodeKind::File,
            size: Some(9),
            mtime: Some(7),
            content_version: Some(2),
        };
        let view = SnapshotView {
            root: NodeId([0; 16]),
            folder: NodeId([2; 16]),
            folder_name: FOLDER.to_string(),
            children: vec![SnapshotChild {
                id: NodeId([3; 16]),
                name: NAME.to_string(),
                kind: NodeKind::File,
                size: None,
                mtime: None,
                pending: PendingClass::None,
                dead_letter: false,
                content_version: None,
                content_cid: None,
            }],
            ancestors: vec![Breadcrumb {
                id: NodeId([4; 16]),
                name: FOLDER.to_string(),
            }],
            dead_letters: Vec::new(),
            blocked: None,
            settings_hold: None,
            retained_records: 0,
            staleness: Staleness::Fresh,
        };
        let target = WriteTarget::NewFile {
            parent: NodeId([2; 16]),
            name: NAME.to_string(),
        };

        for (shape, rendered) in [
            ("NodeAttrs", format!("{attrs:?}")),
            ("SnapshotChild", format!("{:?}", view.children[0])),
            ("Breadcrumb", format!("{:?}", view.ancestors[0])),
            ("NewFile", format!("{target:?}")),
            ("SnapshotView", format!("{view:?}")),
        ] {
            assert!(
                !rendered.contains(NAME) && !rendered.contains(FOLDER),
                "a name never renders: {rendered}"
            );
            assert!(rendered.contains(shape), "the shape survives: {rendered}");
            assert!(rendered.contains("redacted"), "{rendered}");
        }
    }

    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use crate::net::HeldValue;
    use serde_json::{Value, json};

    use cipherbox_core::ipns::IpnsRecord;
    use cipherbox_core::kdf;

    use core::num::NonZeroU64;

    use crate::api::{ChallengeSigner, new_user_login_response};
    use crate::content::{ByoIpfsConfig, ByoKind, RetentionPolicy};
    use crate::net::retire::ReclaimStallReason;
    use crate::seams::{CredentialStore, EndpointId, HttpMethod, HttpResponse, UnixMillis};
    use crate::settings::{cached_settings_block, settings_name};
    use crate::testkit::fakes::InMemoryRecordStore;
    use crate::testkit::{FakeDevice, FakeSeamTypes, FakeWorld, SeededEntropy, block_on};

    /// One rule set decides both the refusal `share_scope` returns and the
    /// standing the `sharing` read reports, and a grant and a link name every
    /// ground apart — including the envelope-version one, which only a parent
    /// record this build cannot author reaches.
    #[test]
    fn a_share_standing_names_each_ground_apart_for_a_grant_and_a_link() {
        let node = NodeId([7; 16]);
        let indexed = [ChildScopeRef::new(node.0, b"name".to_vec())];

        for (standing, grant, link) in [
            (record_share_standing(node, ENVELOPE_V, &[]), None, None),
            (
                record_share_standing(node, ENVELOPE_V, &indexed),
                Some("grant-target-already-names-a-scope"),
                Some("invite-target-already-names-a-scope"),
            ),
            (
                record_share_standing(node, ENVELOPE_V + 1, &indexed),
                Some("grant-parent-envelope-version-unsupported"),
                Some("invite-parent-envelope-version-unsupported"),
            ),
            (
                ShareStanding::VaultRoot,
                Some("grant-target-is-the-vault-root"),
                Some("invite-target-is-the-vault-root"),
            ),
        ] {
            assert_eq!(ShareChecks::GRANT.refusal(standing), grant);
            assert_eq!(ShareChecks::INVITE_LINK.refusal(standing), link);
        }
    }

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

    /// An accepted shared scope is grafted in parentless, so a browse reaches it
    /// but the write plane cannot author under it. A mutation there must be
    /// refused where the caller can still be told, not journaled into a queue
    /// whose drain can never walk its chain to a root.
    #[test]
    fn a_journal_target_outside_this_vaults_tree_is_refused() {
        let root = NodeId([1; 16]);
        let inside = NodeId([2; 16]);
        let shared_root = NodeId([3; 16]);
        let shared_child = NodeId([4; 16]);
        let mut rendered = Snapshot::new(root);
        rendered.upsert_node(NodeMeta::new(inside, "mine", NodeKind::Folder));
        rendered.link_next(root, inside);
        rendered.upsert_node(NodeMeta::new(shared_root, "theirs", NodeKind::Folder));
        rendered.upsert_node(NodeMeta::new(shared_child, "theirs/sub", NodeKind::Folder));
        rendered.link_next(shared_root, shared_child);

        assert!(refuse_outside_vault(&rendered, root).is_ok());
        assert!(refuse_outside_vault(&rendered, inside).is_ok());
        assert!(
            refuse_outside_vault(&rendered, NodeId([9; 16])).is_ok(),
            "a node the render never held keeps the verdict the rebase gives it"
        );
        for node in [shared_root, shared_child] {
            assert!(matches!(
                refuse_outside_vault(&rendered, node),
                Err(EngineError::ScopeExitRefused { .. })
            ));
        }
    }

    /// The relocation arms read their source off the render, so a destination
    /// check alone still admits a move *out* of a grafted shared scope. Its op
    /// names a chain that walks to no root this session publishes, so the drain
    /// halts on it instead of the caller hearing a refusal.
    #[test]
    fn a_relocation_whose_source_is_outside_this_vault_is_refused() {
        let (mut engine, _events) = started();
        let root = engine.snapshot.borrow().root;
        let shared_root = NodeId([0xf1; 16]);
        let shared_child = NodeId([0xf2; 16]);
        {
            let mut base = engine.snapshot.borrow_mut();
            base.upsert_node(NodeMeta::new(shared_root, "theirs", NodeKind::Folder));
            base.upsert_node(NodeMeta::new(shared_child, "doc", NodeKind::File));
            base.link_next(shared_root, shared_child);
        }

        for command in [
            Command::Relink {
                node: shared_child,
                new_parent: root,
            },
            Command::Move {
                node: shared_child,
                new_parent: root,
                new_name: "doc".to_owned(),
                replacing: None,
            },
        ] {
            let label = command.name();
            assert!(
                matches!(
                    block_on(engine.command(command)),
                    Err(EngineError::ScopeExitRefused { .. })
                ),
                "{label} out of a grafted scope must refuse where the caller hears it"
            );
        }
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
            value: HeldValue::Head(head.to_owned()),
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
        assert!(block_on(live_account_record(&transport, &slot)).is_none());
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

    const POINTER_SCOPE: [u8; 16] = [0x77; 16];

    /// A held scope pointer whose record serves `served` at `sequence`, while
    /// the held entry renews `ours`.
    fn pointer_held(
        ours: &[u8],
        served: &[u8],
        sequence: u64,
    ) -> (InMemoryRecordStore, HeldRecord) {
        const TTL_NANOS: u64 = 2_000_000_000;
        const EOL: &str = "2099-01-01T00:00:00Z";
        let signer = Ed25519Signer::from_seed([0x21; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let store = InMemoryRecordStore::new(vec![EndpointId::new("fake:someguy")]);
        let live = IpnsRecord::create_v2(&signer, served, sequence, TTL_NANOS, EOL).marshal();
        for endpoint in store.endpoints() {
            store.seed_record(&endpoint, name.as_str(), live.clone());
        }
        let held = HeldRecord {
            routing_key: name.as_str().to_owned(),
            record_bytes: IpnsRecord::create_v2(&signer, ours, 1, TTL_NANOS, EOL).marshal(),
            signer,
            value: HeldValue::Inline(ours.to_vec()),
            content_cids: Vec::new(),
        };
        (store, held)
    }

    fn after_the_pointer_sweep(store: InMemoryRecordStore, held: HeldRecord) -> usize {
        let map = RefCell::new(HeldRecords::new());
        map.borrow_mut()
            .insert(HeldKey::scope_pointer(POINTER_SCOPE), held);
        block_on(drop_superseded_pointers(&store, &map));
        map.borrow().len()
    }

    #[test]
    fn a_scope_pointer_the_plane_superseded_leaves_the_held_set() {
        // Only a local rotation writes this plane, so a re-point from another
        // device leaves this session re-PUTting a retired block hourly.
        let (store, held) = pointer_held(b"our-repoint", b"a-newer-repoint", 2);
        assert_eq!(after_the_pointer_sweep(store, held), 0);
    }

    #[test]
    fn a_scope_pointer_the_plane_still_serves_stays_in_the_renewal() {
        let (store, held) = pointer_held(b"our-repoint", b"our-repoint", 1);
        assert_eq!(after_the_pointer_sweep(store, held), 1);
    }

    #[test]
    fn a_scope_pointer_no_endpoint_serves_stays_in_the_renewal() {
        // A plane this pass cannot read is availability, never supersession.
        let (_store, held) = pointer_held(b"our-repoint", b"our-repoint", 1);
        let empty = InMemoryRecordStore::new(vec![EndpointId::new("fake:someguy")]);
        assert_eq!(after_the_pointer_sweep(empty, held), 1);
    }

    /// Shaped as the API issues one; the engine signs nothing else.
    const LOGIN_CHALLENGE_FIXTURE: &str =
        "cipherbox-login:v2:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// The two step-up tags, each admitted only by the operation that names it.
    const LINK_CHALLENGE_FIXTURE: &str =
        "cipherbox-link:v2:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const UNLINK_CHALLENGE_FIXTURE: &str =
        "cipherbox-unlink:v2:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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
            new_user_login_response("jwt-1", &"a".repeat(64), "gw-a"),
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
            new_user_login_response("jwt-1", &"a".repeat(64), "gw-a"),
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
            new_user_login_response("jwt-1", &"a".repeat(64), "gw-a"),
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
            new_user_login_response("jwt-1", &"a".repeat(64), "gw-a"),
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
            new_user_login_response("jwt-1", &"a".repeat(64), "gw-a"),
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

    /// An EIP-191 signature is 65 bytes; anything shorter would pass a test
    /// that only checks the encoding while the API refuses the length.
    const WALLET_SIGNATURE_FIXTURE: [u8; 65] = [0xAB; 65];

    /// The API refuses a `signature` outside `HEX_ETH_SIGNATURE`
    /// (`/^0x[0-9a-fA-F]{130}$/`, apps/api/src/auth/dto/auth.dto.ts) with a 400
    /// before the SIWE service ever sees it, so asserting the encoding alone
    /// pins a body the server cannot accept.
    fn assert_eth_signature_wire_shape(sent: &Value) {
        let signature = sent.as_str().expect("the signature crosses as a string");
        assert!(
            signature.len() == 132
                && signature.starts_with("0x")
                && signature[2..].bytes().all(|byte| byte.is_ascii_hexdigit()),
            "the API's wallet DTO refuses this signature: {signature:?}"
        );
    }

    #[test]
    fn siwe_link_command_forwards_message_and_hex_signature() {
        let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        let before = device.http.requests().len();
        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": LINK_CHALLENGE_FIXTURE }),
        ));
        device
            .http
            .enqueue_response(json_response(200, json!({ "success": true })));

        let signature = WALLET_SIGNATURE_FIXTURE.to_vec();
        block_on(engine.command(Command::SiweLink {
            message: "siwe-link-message".to_owned(),
            signature: signature.clone(),
        }))
        .expect("siwe link");

        let requests = device.http.requests();
        let request = requests[before..].last().expect("a link request was sent");
        assert_eq!(request.url, "/auth/siwe/link");
        let body: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
        assert_eq!(body["message"], "siwe-link-message");
        assert_eth_signature_wire_shape(&body["signature"]);
        assert_eq!(
            body["signature"],
            format!("0x{}", hex_lower(&signature)),
            "the wallet signature crosses the wire 0x-prefixed hex"
        );
    }

    /// A link changes which keys open the account, so it carries the same
    /// live-possession proof [`Command::UnlinkAuthMethod`] does.
    #[test]
    fn siwe_link_command_reproves_the_identity_key() {
        let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        let before = device.http.requests().len();
        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": LINK_CHALLENGE_FIXTURE }),
        ));
        device
            .http
            .enqueue_response(json_response(200, json!({ "success": true })));

        block_on(engine.command(Command::SiweLink {
            message: "siwe-link-message".to_owned(),
            signature: WALLET_SIGNATURE_FIXTURE.to_vec(),
        }))
        .expect("siwe link");

        let signer = IdentityChallengeSigner::from_signer(
            engine.session().expect("live").identity().clone(),
        );
        let requests = device.http.requests();
        let sent = &requests[before..];
        assert_eq!(sent.len(), 2, "one challenge, then one link");
        assert_eq!(sent[0].url, "/auth/challenge/step-up");
        let mint: Value = serde_json::from_slice(sent[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(mint["operation"], "link");
        assert_eq!(sent[1].url, "/auth/siwe/link");
        let body: Value = serde_json::from_slice(sent[1].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["challenge"], LINK_CHALLENGE_FIXTURE);
        assert_eq!(
            body["challengeSignature"],
            signer.sign_challenge(LINK_CHALLENGE_FIXTURE),
            "the account identity key signed the challenge the server issued"
        );
    }

    #[test]
    fn unlink_auth_method_command_reproves_the_identity_key() {
        let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        let before = device.http.requests().len();
        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": UNLINK_CHALLENGE_FIXTURE }),
        ));
        device
            .http
            .enqueue_response(json_response(200, json!({ "success": true })));

        block_on(engine.command(Command::UnlinkAuthMethod {
            method_id: "method-1".to_owned(),
        }))
        .expect("unlink");

        let signer = IdentityChallengeSigner::from_signer(
            engine.session().expect("live").identity().clone(),
        );
        let requests = device.http.requests();
        let sent = &requests[before..];
        assert_eq!(sent.len(), 2, "one challenge, then one unlink");
        assert_eq!(sent[0].url, "/auth/challenge/step-up");
        let challenge_body: Value = serde_json::from_slice(sent[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(challenge_body["operation"], "unlink");
        assert_eq!(challenge_body["methodId"], "method-1");
        assert!(
            challenge_body.get("publicKey").is_none(),
            "the mint reads the key off the token, never the body"
        );
        assert_eq!(sent[1].url, "/auth/unlink");
        let body: Value = serde_json::from_slice(sent[1].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["methodId"], "method-1");
        assert_eq!(body["challenge"], UNLINK_CHALLENGE_FIXTURE);
        assert_eq!(
            body["signature"],
            signer.sign_challenge(UNLINK_CHALLENGE_FIXTURE),
            "the account identity key signed the challenge the server issued"
        );
    }

    /// The engine holds each operation to its own tag, so a challenge minted
    /// for a different operation never reaches the identity key at all.
    #[test]
    fn a_step_up_challenge_for_another_operation_is_never_signed() {
        for (command, wrong) in [
            (
                Command::UnlinkAuthMethod {
                    method_id: "method-1".to_owned(),
                },
                LINK_CHALLENGE_FIXTURE,
            ),
            (
                Command::SiweLink {
                    message: "siwe-link-message".to_owned(),
                    signature: WALLET_SIGNATURE_FIXTURE.to_vec(),
                },
                UNLINK_CHALLENGE_FIXTURE,
            ),
        ] {
            let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
            block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
            let before = device.http.requests().len();
            device
                .http
                .enqueue_response(json_response(200, json!({ "challenge": wrong })));

            let error = block_on(engine.command(command)).unwrap_err();
            assert!(
                matches!(&error, EngineError::Auth { message } if message.contains("step-up")),
                "{error:?} for {wrong}"
            );
            let requests = device.http.requests();
            assert_eq!(
                requests[before..].len(),
                1,
                "the mint was the only request for {wrong}"
            );
        }
    }

    /// The two nonce pools reach two routes, and the link pool is
    /// owner-authenticated.
    #[test]
    fn a_siwe_challenge_reaches_the_route_its_intent_names() {
        for (intent, path) in [
            (SiweIntent::Login, "/auth/siwe/challenge"),
            (SiweIntent::Link, "/auth/siwe/link-challenge"),
        ] {
            let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
            block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
            let before = device.http.requests().len();
            device.http.enqueue_response(json_response(
                200,
                json!({ "nonce": "a1b2c3d4e5f60718", "expiresAt": "2099-01-01T00:00:00Z" }),
            ));

            assert_eq!(
                block_on(engine.siwe_challenge(intent)),
                Ok("a1b2c3d4e5f60718".to_owned())
            );
            let requests = device.http.requests();
            assert_eq!(requests[before..].last().expect("a mint").url, path);
        }
    }

    /// The bearer the member typed is in the record this device read back, and
    /// still must not reach the host: the summary is redacted at construction.
    #[test]
    fn vault_storage_reports_the_saved_provider_without_its_bearer() {
        const BEARER: &str = "provider-bearer-do-not-leak";
        let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
        let settings = VaultSettings {
            pin_mode: PinMode::Dual,
            byo: Some(ByoIpfsConfig {
                endpoint: "https://node.example".to_owned(),
                kind: ByoKind::Kubo,
                access_token: Some(Zeroizing::new(BEARER.to_owned())),
            }),
            retention: RetentionPolicy::KeepLatest(NonZeroU64::new(3).expect("nonzero")),
            bin_retention_days: DEFAULT_BIN_RETENTION_DAYS,
        };
        let (key, block) = cached_settings_block(&[7u8; 32], &settings, &mut SeededEntropy::new(9));
        block_on(device.snapshot_cache.put(&key, &block)).expect("seed last-known-good");
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        // The account flag lags the vaulted mode, so the server says the rows
        // are authoritative while this vault already places bytes off them.
        device.http.enqueue_response(json_response(
            200,
            json!({ "usedBytes": 10, "limitBytes": 100, "advisory": false }),
        ));

        let view = block_on(engine.vault_storage()).expect("storage view");

        assert_eq!(
            view.settings,
            VaultSettingsSummary {
                pin_mode: PinMode::Dual,
                byo_endpoint: Some("https://node.example".to_owned()),
                byo_kind: Some(ByoKind::Kubo),
                byo_credential_stored: true,
                retention: RetentionPolicy::KeepLatest(NonZeroU64::new(3).expect("nonzero")),
                bin_retention_days: DEFAULT_BIN_RETENTION_DAYS,
                origin: SettingsOrigin::Stale,
            },
        );
        assert!(
            !format!("{view:?}").contains(BEARER),
            "the provider bearer must not survive into the host-visible view"
        );
        assert_eq!(
            view.quota,
            Some(QuotaView {
                used_bytes: 10,
                limit_bytes: 100,
                advisory: true,
            }),
            "a vault placing bytes off the hosted store reads its quota as a hint, \
             whatever the account flag says"
        );
    }

    /// A sibling device placing bytes externally sets the account flag while
    /// this device still reads `Hosted`, so deriving the hint from the vaulted
    /// mode alone renders a ceiling that does not bind.
    #[test]
    fn vault_storage_keeps_an_advisory_flag_a_hosted_vault_cannot_see() {
        let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        device.http.enqueue_response(json_response(
            200,
            json!({ "usedBytes": 10, "limitBytes": 100, "advisory": true }),
        ));

        let view = block_on(engine.vault_storage()).expect("storage view");

        assert_eq!(
            view.settings.pin_mode,
            PinMode::Hosted,
            "this device's own settings place every byte on the hosted store"
        );
        assert_eq!(
            view.quota,
            Some(QuotaView {
                used_bytes: 10,
                limit_bytes: 100,
                advisory: true,
            }),
            "the account flag survives a vaulted mode that cannot account for it"
        );
    }

    /// A debt the pass could not settle prices at nothing, so the byte figure
    /// alone reads as a drained ledger. The stall list is what tells them apart.
    #[test]
    fn vault_storage_prices_a_stalled_reclaim_above_zero() {
        let (mut engine, _events, _device) = engine_over(ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        let stall = ReclaimStall {
            node: [3u8; 16],
            target: "bafystalledroot".to_owned(),
            reason: ReclaimStallReason::TargetStillLive,
        };
        engine.pending_reclaim.set(0);
        engine.reclaim_stalls.borrow_mut().push(stall.clone());

        let view = block_on(engine.vault_storage()).expect("storage view");

        assert_eq!(view.pending_reclaim_bytes, 0);
        assert_eq!(view.reclaim_stalls, vec![stall]);
    }

    /// blueprint/engine.md "defaults, never blocked": the member's own settings
    /// are readable whether or not the account quota answered.
    #[test]
    fn vault_storage_degrades_when_the_quota_probe_fails() {
        let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        let before = device.http.requests().len();

        // Nothing is scripted, so the quota probe fails at the seam.
        let view = block_on(engine.vault_storage()).expect("a failed probe is not an error");

        assert!(view.quota.is_none());
        assert_eq!(view.settings.origin, SettingsOrigin::Defaults);
        assert!(
            device.http.requests().len() > before,
            "the probe was attempted, not skipped"
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

    /// The bound is release-active and it sits at the facade, because the
    /// projection's own name check runs above it and a web caller reaches the
    /// commands with nothing in front of them.
    #[test]
    fn an_over_bound_name_is_refused_at_every_command_that_carries_one() {
        let (mut engine, _events) = started();
        let root = engine.root();
        let too_long = "n".repeat(MAX_NODE_NAME_BYTES + 1);
        let refusal = Err(EngineError::MalformedInput {
            check: "node-name-too-long",
        });

        assert_eq!(
            block_on(engine.command(Command::Create {
                parent: root,
                name: too_long.clone(),
                kind: NodeKind::File,
            })),
            refusal
        );
        assert_eq!(
            block_on(engine.command(Command::Rename {
                node: root,
                new_name: too_long.clone(),
            })),
            refusal
        );
        assert_eq!(
            block_on(engine.command(Command::Move {
                node: root,
                new_parent: root,
                new_name: too_long.clone(),
                replacing: None,
            })),
            refusal
        );
        assert_eq!(
            block_on(engine.begin_write(
                WriteTarget::NewFile {
                    parent: root,
                    name: too_long,
                },
                4,
            ))
            .err(),
            refusal.err()
        );

        // The bound itself is admitted: an off-by-one here would refuse a name
        // the mount advertises as creatable.
        create(
            &mut engine,
            root,
            &"n".repeat(MAX_NODE_NAME_BYTES),
            NodeKind::File,
        );
    }

    /// The whole law, not only the length cap: the facade is the one boundary
    /// every client crosses, so a web caller cannot author a name a mount could
    /// never carry.
    #[test]
    fn a_name_the_law_refuses_is_refused_at_create_and_at_rename() {
        let (mut engine, _events) = started();
        let root = engine.root();
        create(&mut engine, root, "keeper.txt", NodeKind::File);
        let node = block_on(engine.view())
            .expect("view")
            .lookup(root, "keeper.txt")
            .expect("the seeded child")
            .id;

        for (name, check) in [
            ("CON", "node-name-reserved-device"),
            ("a\u{7}b", "node-name-control"),
            ("a/b", "node-name-separator"),
            ("re:port", "node-name-reserved-character"),
            ("report.", "node-name-trailing-dot-or-space"),
            ("", "node-name-empty"),
        ] {
            let refusal = Err(EngineError::MalformedInput { check });
            assert_eq!(
                block_on(engine.command(Command::Create {
                    parent: root,
                    name: name.to_owned(),
                    kind: NodeKind::File,
                })),
                refusal,
                "create {name:?}"
            );
            assert_eq!(
                block_on(engine.command(Command::Rename {
                    node,
                    new_name: name.to_owned(),
                })),
                refusal,
                "rename to {name:?}"
            );
        }
    }

    /// A listing that told two folders apart must not re-ambiguate them one
    /// surface later, in the trail the user navigates by.
    #[test]
    fn a_duplicate_folder_keeps_its_rendered_name_in_the_breadcrumb() {
        let (engine, _events) = started();
        let root = engine.root();
        let planted = NodeId([0xa1; 16]);
        let shadowed = NodeId([0xa2; 16]);
        engine.plant_committed_child(root, planted, "reports", NodeKind::Folder);
        engine.plant_committed_child(root, shadowed, "reports", NodeKind::Folder);
        let leaf = NodeId([0xa3; 16]);
        engine.plant_committed_child(shadowed, leaf, "q3", NodeKind::Folder);

        let view = block_on(engine.snapshot(leaf)).expect("snapshot");
        assert_eq!(view.folder_name, "q3");
        let trail: Vec<&str> = view
            .ancestors
            .iter()
            .map(|step| step.name.as_str())
            .collect();
        assert_eq!(
            trail.first().copied(),
            Some("reports (1)"),
            "the trail names the folder the listing named"
        );
    }

    /// A bin row names the origin folder the way the listing names it. Two
    /// origin folders that share a stored name would otherwise report one name
    /// for both rows, which is the telling-apart the bin row exists to give.
    #[test]
    fn a_bin_rows_origin_folder_reads_under_its_rendered_name() {
        let (engine, _events) = started();
        let root = engine.root();
        let planted = NodeId([0xb1; 16]);
        let shadowed = NodeId([0xb2; 16]);
        engine.plant_committed_child(root, planted, "reports", NodeKind::Folder);
        engine.plant_committed_child(root, shadowed, "reports", NodeKind::Folder);

        let rendered = block_on(engine.render()).expect("render");
        assert_eq!(origin_folder(&rendered, root), BinOrigin::Root);
        assert_eq!(
            origin_folder(&rendered, planted),
            BinOrigin::Folder("reports".to_owned())
        );
        assert_eq!(
            origin_folder(&rendered, shadowed),
            BinOrigin::Folder("reports (1)".to_owned()),
            "the row names the folder the listing named"
        );
        assert_eq!(
            origin_folder(&rendered, NodeId([0xbf; 16])),
            BinOrigin::Gone
        );
    }

    /// Every read accessor names one node the same. A caller that lists a
    /// duplicate and then asks for its attributes by id must not be handed the
    /// stored name back, or the two children collapse under one name again on
    /// the surface after the listing.
    #[test]
    fn attrs_names_a_duplicate_the_way_the_listing_does() {
        let (engine, _events) = started();
        let root = engine.root();
        let plain = NodeId([0xb1; 16]);
        let twin = NodeId([0xb2; 16]);
        engine.plant_committed_child(root, plain, "q3.pdf", NodeKind::File);
        engine.plant_committed_child(root, twin, "q3.pdf", NodeKind::File);

        let view = block_on(engine.view()).expect("view");
        for listed in view.children(root) {
            assert_eq!(
                view.attrs(listed.id).expect("attrs").name,
                listed.name,
                "{:?} must be named alike by every accessor",
                listed.id
            );
        }
        assert_eq!(view.attrs(twin).expect("attrs").name, "q3 (1).pdf");
    }

    #[test]
    fn a_restore_is_held_to_the_length_bound_alone() {
        // A peer named it, so the wider law must not strand it.
        assert!(refuse_unemittable_name("CON").is_ok());
        assert!(refuse_unlawful_name("CON").is_err());
        assert_eq!(
            refuse_unemittable_name(&"n".repeat(MAX_NODE_NAME_BYTES + 1)),
            Err(EngineError::MalformedInput {
                check: "node-name-too-long",
            })
        );
        // The narrow tier still holds: restored into a live folder, a name no
        // kernel can carry is invisible and unremovable through the mount.
        for name in ["", "a/b", "a\0b", "..", "a\nb"] {
            assert_eq!(
                refuse_unemittable_name(name),
                Err(EngineError::MalformedInput {
                    check: "node-name-unemittable",
                }),
                "{name:?} must not be restored into a listing"
            );
        }
    }

    /// The ceiling is derived from the seal budget, so the derivation has to
    /// hold against a real encode rather than against arithmetic on paper: a
    /// full folder of the worst names this device admits must still seal.
    #[test]
    fn a_full_folder_of_worst_case_children_still_seals() {
        use cipherbox_core::seal::{ChildRef, PreservedFields, encode_read_body};
        use cipherbox_core::suite::aead::{NONCE_LEN, TAG_LEN};

        let children: Vec<ChildRef> = (0..MAX_FOLDER_CHILDREN)
            .map(|i| ChildRef {
                id: (i as u128).to_be_bytes(),
                name: format!("{i:0>MAX_NODE_NAME_BYTES$}"),
                // Distinct per child, because the encoder refuses a duplicate.
                ipns_name: {
                    let mut name = vec![b'k'; MAX_IPNS_NAME_BYTES];
                    name[..16].copy_from_slice(&(i as u128).to_be_bytes());
                    name
                },
                kind: cipherbox_core::seal::NodeKind::File,
                link_counter: u64::MAX,
                unknown: PreservedFields::new(),
            })
            .collect();
        let body = ReadBody::Folder {
            created_at: u64::MAX,
            modified_at: u64::MAX,
            children,
            unknown: PreservedFields::new(),
        };

        let encoded = encode_read_body(&body).expect("a full folder encodes");
        let sealed = encoded.len() + NONCE_LEN + TAG_LEN;
        assert!(
            sealed <= MAX_READ_SEALED_BYTES,
            "{MAX_FOLDER_CHILDREN} worst-case children seal to {sealed}, over {MAX_READ_SEALED_BYTES}"
        );
    }

    /// A node the folder already holds is not a new child, so a relink inside
    /// its own parent is not refused by a count it does not change, and neither
    /// is a move that frees the name it replaces.
    #[test]
    fn a_folder_at_its_ceiling_refuses_a_new_child_but_not_one_it_holds() {
        let root = NodeId([0; 16]);
        let mut rendered = Snapshot::new(root);
        for i in 0..MAX_FOLDER_CHILDREN {
            let child = NodeId((i as u128 + 1).to_be_bytes());
            rendered.upsert_node(NodeMeta::new(child, "n", NodeKind::File));
            rendered.link(root, child, 1);
        }
        let held = NodeId(1u128.to_be_bytes());
        let full = Err(EngineError::MalformedInput {
            check: "folder-child-ceiling",
        });

        assert_eq!(refuse_full_parent(&rendered, root, None, None), full);
        assert_eq!(
            refuse_full_parent(&rendered, root, Some(held), None),
            Ok(()),
            "a relink inside its own parent adds nothing"
        );
        assert_eq!(
            refuse_full_parent(&rendered, root, None, Some(held)),
            Ok(()),
            "a move frees the place it replaces"
        );

        rendered.unlink(root, held);
        assert_eq!(
            refuse_full_parent(&rendered, root, None, None),
            Ok(()),
            "one place freed admits one new child"
        );
    }

    /// A peer sizes its own children, so a count far below the ceiling can still
    /// name a listing no re-author can publish. The byte charge is what refuses
    /// it — the count alone would admit one more.
    #[test]
    fn a_folder_of_peer_sized_names_refuses_on_bytes_far_below_the_count() {
        let root = NodeId([0; 16]);
        let mut rendered = Snapshot::new(root);
        let name = "n".repeat(2048);
        let children = MAX_READ_SEALED_BYTES / (CHILD_REF_FIXED_BYTES + name.len()) + 1;
        for i in 0..children {
            let child = NodeId((i as u128 + 1).to_be_bytes());
            rendered.upsert_node(NodeMeta::new(child, name.clone(), NodeKind::File));
            rendered.link(root, child, 1);
        }

        assert!(
            children < MAX_FOLDER_CHILDREN,
            "the count ceiling alone would admit this listing"
        );
        assert_eq!(
            refuse_full_parent(&rendered, root, None, None),
            Err(EngineError::MalformedInput {
                check: "folder-child-ceiling",
            })
        );
    }

    /// A rename adds no child, so only the byte charge can refuse one. The
    /// drain would otherwise halt on the oversized re-seal and dead-letter the
    /// op after its retry budget, long after the caller could act.
    #[test]
    fn a_rename_that_grows_a_listing_past_the_seal_budget_is_refused() {
        let root = NodeId([0; 16]);
        let mut rendered = Snapshot::new(root);
        let target = NodeId(1u128.to_be_bytes());
        let ballast = NodeId(2u128.to_be_bytes());
        // A peer sizes its own child, so the listing sits exactly at the budget
        // and one more byte of name is over it.
        let ballast_name = "n".repeat(MAX_READ_SEALED_BYTES - 2 * CHILD_REF_FIXED_BYTES - 1);
        rendered.upsert_node(NodeMeta::new(target, "n", NodeKind::File));
        rendered.link(root, target, 1);
        rendered.upsert_node(NodeMeta::new(ballast, ballast_name, NodeKind::File));
        rendered.link(root, ballast, 1);

        assert_eq!(
            refuse_over_budget_rename(&rendered, target, "n"),
            Ok(()),
            "a listing that seals stays renamable"
        );
        assert_eq!(
            refuse_over_budget_rename(&rendered, target, "nn"),
            Err(EngineError::MalformedInput {
                check: "folder-child-ceiling",
            }),
            "the one byte that pushes it over is refused at the boundary"
        );
    }

    /// A peer overfills a folder this vault must still let a member out of, so
    /// the budget holds a growing name only.
    #[test]
    fn a_rename_that_shrinks_a_listing_is_never_refused() {
        let root = NodeId([0; 16]);
        let mut rendered = Snapshot::new(root);
        let name = "n".repeat(MAX_NODE_NAME_BYTES);
        let children = MAX_READ_SEALED_BYTES / (CHILD_REF_FIXED_BYTES + name.len()) + 1;
        for i in 0..children {
            let child = NodeId((i as u128 + 1).to_be_bytes());
            rendered.upsert_node(NodeMeta::new(child, name.clone(), NodeKind::File));
            rendered.link(root, child, 1);
        }
        let target = NodeId(1u128.to_be_bytes());

        assert_eq!(
            refuse_over_budget_rename(&rendered, target, "n"),
            Ok(()),
            "a shorter name is the way out of an overfilled folder"
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

    /// Two accounts on one browser profile or one desktop share a floor store,
    /// and the vault root scope id is the anchored all-zero id16 for both — so
    /// the engine keys its floors by identity, or the second account provisions
    /// against a ratchet it cannot lower (blueprint/engine.md "Floor law").
    #[test]
    fn a_second_identity_on_one_device_inherits_no_floor_from_the_first() {
        const ROOT_SCOPE: [u8; 16] = [0u8; 16];
        let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        block_on(engine.seams.floor_store.raise_epoch_floor(&ROOT_SCOPE, 9)).unwrap();

        assert_eq!(
            block_on(device.floors(&[9u8; 32]).epoch_floor(&ROOT_SCOPE)).unwrap(),
            None,
            "the second identity mints against no floor of the first's"
        );
        assert_eq!(
            block_on(device.floors(&[7u8; 32]).epoch_floor(&ROOT_SCOPE)).unwrap(),
            Some(9),
            "and start bound the store to the identity that raised it"
        );
    }

    /// Ending a session: the logout every forget composes, and the erase only a
    /// forget does (blueprint/web-client.md "Logout").
    mod session_end {
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

        /// Forget is logout plus the erase, structurally rather than by
        /// documentation: the same teardown runs for both, and only forget
        /// follows it with the seam sweep.
        #[test]
        fn logout_ends_the_session_and_leaves_every_durable_seam() {
            let (mut engine, device, _events) = started_and_loaded();
            // Staged after the start: cold start collects what the seeded queue
            // no longer references, and a logout must spare what is still live.
            block_on(device.staging_store.put_staged_bytes(b"live", b"staged")).unwrap();

            assert_eq!(
                block_on(engine.command(Command::Logout)),
                Ok(CommandOutcome::Done)
            );

            block_on(async {
                assert_eq!(
                    device.floor_store.epoch_floor(b"scope").await.unwrap(),
                    Some(4),
                    "floors survive a logout by design — they are this device's replay bar"
                );
                assert_eq!(
                    device.floor_store.sequence_floor(b"name").await.unwrap(),
                    Some(9)
                );
                assert_eq!(
                    device.staging_store.staged_bytes(b"live").await.unwrap(),
                    Some(b"staged".to_vec())
                );
                assert!(device.snapshot_cache.get(b"key").await.unwrap().is_some());
                assert_eq!(
                    device.credential_store.load_refresh_token().await.unwrap(),
                    None,
                    "the credential the session authenticated with does not outlive it"
                );
            });
        }

        /// The credential drop is a verdict, and the session it belonged to is
        /// gone by the time the store can refuse — so the command stays
        /// reachable, or a refused drop would have no retry but a full erase.
        #[test]
        fn a_logout_can_be_issued_again_after_it_cleared_the_session() {
            let (mut engine, device, _events) = started_and_loaded();
            block_on(engine.command(Command::Logout)).unwrap();
            block_on(device.credential_store.store_refresh_token(b"late")).unwrap();

            assert_eq!(
                block_on(engine.command(Command::Logout)),
                Ok(CommandOutcome::Done)
            );
            assert_eq!(
                block_on(device.credential_store.load_refresh_token()).unwrap(),
                None,
                "the retry reaches the store the first attempt left holding a token"
            );
        }

        /// The session is over, not merely idle: an engine a logout ended has
        /// nothing left to authenticate a command with.
        #[test]
        fn a_logged_out_engine_serves_nothing_and_cannot_be_restarted() {
            let (mut engine, _device, _events) = started_and_loaded();
            block_on(engine.command(Command::Logout)).unwrap();

            assert_eq!(
                block_on(engine.command(Command::ManualRefresh)),
                Err(EngineError::NotStarted)
            );
            assert_eq!(
                block_on(engine.start(LoginSecret::new(vec![7u8; 32]))),
                Err(EngineError::AlreadyStarted),
                "the alive latch is never re-armed, so a host builds a new engine"
            );
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
                block_on(engine.siwe_challenge(SiweIntent::Login)),
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
                new_user_login_response("jwt-1", &"a".repeat(64), "gw-a"),
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
        let name = Command::RotateNow { node }.name();
        assert_eq!(
            block_on(engine.command(Command::RotateNow { node })),
            Err(EngineError::UnsupportedTarget {
                check: "rotate-target-is-not-a-scope-root"
            }),
            "`{name}` must refuse with its own typed verdict",
        );
    }

    /// A downgrade names a recipient before it names a scope, exactly as a
    /// revoke does: both run the same cut spine.
    #[test]
    fn a_downgrade_refuses_an_unimported_recipient_before_it_resolves_anything() {
        let (mut engine, _events) = started();
        assert_eq!(
            block_on(engine.command(Command::Downgrade {
                node: NodeId([1; 16]),
                recipient_identity_public_key: vec![2u8; 33],
            })),
            Err(EngineError::MalformedInput {
                check: "recipient-not-imported"
            }),
        );
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

    /// A write grant names its recipient before it mints anything, so an
    /// unimported one costs no publish — the same refusal a read grant gives.
    #[test]
    fn a_write_grant_refuses_an_unimported_recipient_before_anything_is_minted() {
        let (mut engine, _events) = started();
        assert_eq!(
            block_on(engine.command(Command::Grant {
                node: NodeId([1; 16]),
                recipient_identity_public_key: vec![2u8; 33],
                permission: Permission::Write,
            })),
            Err(EngineError::MalformedInput {
                check: "recipient-not-imported"
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
                staged_op: None,
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
        use crate::net::{ResolveOutcome, Resolved, refresh_base_from_resolved};

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
            refresh_base_from_resolved(
                &engine.snapshot,
                root,
                &Resolved::just(ResolveOutcome::Adopted(adopted_folder(vec![
                    child_ref(1, "a", CoreNodeKind::Folder),
                    child_ref(2, "b.txt", CoreNodeKind::File),
                ]))),
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

            write_file(
                &mut engine,
                WriteTarget::Version {
                    node,
                    expected_version: None,
                },
                b"bytes",
            )
            .unwrap();

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

        use crate::sync::staging::PRESERVED_DEAD_LETTERS_KEY;

        use cipherbox_core::ipns::{IpnsName, IpnsRecord};
        use cipherbox_core::kdf;
        use cipherbox_core::payload::RepointObject;
        use cipherbox_core::seal::{PreservedFields, ReadBody};
        use cipherbox_core::suite::ecdsa::EcdsaSigner;
        use cipherbox_core::suite::ed25519::Ed25519Signer;

        use crate::gate::Adopted;
        use crate::seams::{EndpointId, OpId, SeamResult, StagingStore};
        use crate::sync::boot::RootResolve;
        use crate::sync::pointer::{PointerRecord, SessionRole, seal_repoint, vault_pointer_name};
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
            async fn fetch(&self, name: &IpnsName) -> SeamResult<PointerRecord> {
                Ok(match self.blocks.lock().unwrap().get(name.as_str()) {
                    Some(block) => PointerRecord::Found(block.clone()),
                    None => PointerRecord::Absent,
                })
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
            use crate::net::{ResolveOutcome, Resolved, refresh_base_from_resolved};

            let (engine, mut events, _pointers) = started_at(UnixMillis(123_456));
            let root = engine.root();

            // One resolve-tick pass over a gate-passing newer `Adopted`: fold it
            // into the shared base cell and emit, exactly as the tick loop does.
            assert!(
                refresh_base_from_resolved(
                    &engine.snapshot,
                    root,
                    &Resolved::just(ResolveOutcome::Adopted(adopted_with_child(
                        [0xC1; 16], "live.txt"
                    ))),
                )
                .changed
            );
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
            use crate::net::{ResolveOutcome, Resolved, refresh_base_from_resolved};

            let (a, _ea, _pa) = started_at(UnixMillis(0));
            let (b, _eb, _pb) = started_at(UnixMillis(5_000_000));
            let root = a.root();
            assert_eq!(root, b.root());

            refresh_base_from_resolved(
                &a.snapshot,
                root,
                &Resolved::just(ResolveOutcome::Adopted(adopted_with_child(
                    [0xD2; 16], "clk.txt",
                ))),
            );
            refresh_base_from_resolved(
                &b.snapshot,
                root,
                &Resolved::just(ResolveOutcome::Adopted(adopted_with_child(
                    [0xD2; 16], "clk.txt",
                ))),
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

        /// A preserved set this build cannot read holds parked writes it can
        /// neither list nor release, and no later dead letter may join them.
        /// Standing down silently would leave the member with a vault that has
        /// quietly stopped keeping their parked work.
        #[test]
        fn an_unreadable_preserved_set_surfaces_on_cold_start() {
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
            block_on(
                engine
                    .seams
                    .staging_store
                    .put_staged_bytes(PRESERVED_DEAD_LETTERS_KEY, b"another build wrote this"),
            )
            .expect("the store holds it");

            drive(&mut engine, &pointers);

            assert_eq!(block_on(events.next()), Some(Event::ParkedWritesUnreadable));
            assert_eq!(
                block_on(
                    engine
                        .seams
                        .staging_store
                        .staged_bytes(PRESERVED_DEAD_LETTERS_KEY)
                )
                .unwrap()
                .as_deref(),
                Some(b"another build wrote this".as_slice()),
                "and nothing overwrites what it already holds"
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

        /// The anchor name is what the cold start measures a recovered write
        /// scope seed against, so a vault pointer left at the pre-rotation root
        /// declines the seed the same boot just recovered. The write wave's
        /// vault-pointer channel is what keeps the two in step.
        #[test]
        fn a_recovered_write_seed_is_kept_only_at_the_root_the_anchor_names() {
            let seed = Zeroizing::new([0x4d; 32]);
            let moved = derive_write_name(&seed, &ROOT_SCOPE);
            let stale = derive_write_name(&[0x9e; 32], &ROOT_SCOPE);

            let kept = RefCell::new(ScopeSeeds::new());
            deposit_write_seed(&kept, ROOT_SCOPE, seed.clone(), Some(&moved), Some(3));
            assert!(
                kept.borrow().contains_key(&ROOT_SCOPE),
                "the anchor names the root this seed derives"
            );

            let dropped = RefCell::new(ScopeSeeds::new());
            deposit_write_seed(&dropped, ROOT_SCOPE, seed, Some(&stale), Some(3));
            assert!(
                !dropped.borrow().contains_key(&ROOT_SCOPE),
                "an anchor left at the pre-rotation root declines the seed"
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
            let record = held
                .get(&HeldKey::node(ROOT.0))
                .expect("held under the root node id");
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
                    abuse[0].contains("content-cid-mismatch"),
                    "the event names the check that rejected it: {}",
                    abuse[0]
                );
                assert!(
                    !abuse[0].contains(root_name.as_str()),
                    "and withholds the live handle it rejected: {}",
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
                .get_mut(&HeldKey::node(ROOT.0))
                .expect("held under the root node id")
                .content_cids = vec!["bafystamp".to_owned()];

            tick(&world, &device, &mut tasks);
            assert_eq!(
                engine.held_records.borrow()[&HeldKey::node(ROOT.0)].content_cids,
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
                let record = held
                    .get_mut(&HeldKey::node(ROOT.0))
                    .expect("held under the root node id");
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
                held[&HeldKey::node(ROOT.0)].record_bytes,
                before,
                "the poll really did re-hold, so the assertion below is not vacuous"
            );
            assert_eq!(
                held[&HeldKey::node(ROOT.0)].content_cids,
                published,
                "the re-hold carried the published set forward"
            );
            drop(held);

            // Stamped against a head this device did not author: that block set
            // is superseded, so it must not ride the new head's renewal.
            engine
                .held_records
                .borrow_mut()
                .get_mut(&HeldKey::node(ROOT.0))
                .expect("held under the root node id")
                .value = HeldValue::Head("bafyotherhead".to_owned());
            reseed(3);
            tick(&world, &device, &mut tasks);
            assert!(
                engine.held_records.borrow()[&HeldKey::node(ROOT.0)]
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

            block_on(
                device
                    .floors(&CAP_SECRET)
                    .raise_epoch_floor(&SCOPE, EPOCH + 1),
            )
            .unwrap();
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
            bookmark_a_received_share_labelled(device, "shared-folder");
        }

        fn bookmark_a_received_share_labelled(device: &FakeDevice, display_name: &str) {
            let enc_secret = kdf::enc_subkey(&CAP_SECRET);
            let entropy = RefCell::new(SeededEntropy::new(11));
            let store =
                StagingReceivedShareStore::new(&device.staging_store, &enc_secret, &entropy);
            let mut list = ReceivedSharesList::new();
            list.reconcile(crate::grants::ReceivedShare {
                scope_root_name: child_name().as_str().as_bytes().to_vec(),
                scope_id: SHARED_SCOPE,
                sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
                display_name: display_name.to_owned(),
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
                block_on(floor::write_epoch_floor(
                    &device.floors(&CAP_SECRET),
                    &SCOPE
                ))
                .unwrap(),
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
                    &device.floors(&CAP_SECRET),
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
                engine.held_records.borrow()[&HeldKey::node(ROOT.0)].routing_key,
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
            // the gate refuses it. Only the moved record trips that check, and
            // the name cold start opened with resolves clean — so one refusal
            // naming it is what proves where this pass went.
            let abuse: Vec<String> = drain(&mut events)
                .into_iter()
                .filter_map(|event| match event {
                    Event::AttributableAbuse { description } => Some(description),
                    _ => None,
                })
                .collect();
            assert_eq!(abuse.len(), 1, "one verdict on the one root resolved");
            assert!(
                abuse[0].contains("commitment-invalid"),
                "the pass resolved the root its anchor pointer named: {}",
                abuse[0]
            );
            assert_ne!(
                engine.held_records.borrow()[&HeldKey::node(ROOT.0)].routing_key,
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

        /// The `/shared` row and the graft it opens must name the same thing.
        /// A sharer-authored label the name law refuses reaches the row too, and
        /// a row that showed the raw label would tell the user one name while
        /// the folder carried another.
        #[test]
        fn a_shared_row_carries_the_label_the_graft_renders_under() {
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            let (engine, _events, _tasks) = started_and_parked(&world, &device);
            bookmark_a_received_share_labelled(&device, "a\u{202E}gnp.exe");

            let rows = block_on(engine.received_shares()).expect("the list reads");

            assert_eq!(
                rows[0].display_name,
                crate::sync::model::node_id_label(NodeId(SHARED_SCOPE)),
                "the row shows the name the law admits, not the sharer's"
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
                &device.floors(&CAP_SECRET),
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
                        &device.floors(&CAP_SECRET),
                        child_name().as_str().as_bytes(),
                    ))
                    .unwrap(),
                    Some(1),
                );
                // ...but the scope read-epoch floor did not move: it advances
                // only from gate-adopted roots.
                assert_eq!(
                    block_on(floor::read_epoch_floor(&device.floors(&CAP_SECRET), &SCOPE)).unwrap(),
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
                        &device.floors(&CAP_SECRET),
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
                        &device.floors(&CAP_SECRET),
                        child_name().as_str().as_bytes(),
                    ))
                    .unwrap(),
                    Some(1),
                    "the at-floor re-open advanced no sequence floor"
                );
                assert_eq!(
                    block_on(floor::read_epoch_floor(&device.floors(&CAP_SECRET), &SCOPE)).unwrap(),
                    Some(EPOCH),
                    "the at-floor re-open advanced no epoch floor"
                );
            }
        }
    }

    // --- device registry and approval rendezvous (ADR 0009) ---

    /// A raw Ed25519 device identity public key, as the registry spells one.
    const DEVICE_KEY: &str = "cd11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
    /// Opaque ciphertext to the engine, which never opens it. It is still a
    /// whole envelope by length: the produce side refuses anything the
    /// requester's own opener could not read.
    const SEALED_FACTOR: &str =
        "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWg==";

    /// A device signature, in the width the registry's DTOs fix.
    fn device_signature() -> String {
        "ab".repeat(64)
    }

    /// One registry row, as `GET /devices` serves one.
    fn registry_row(id: &str) -> Value {
        json!({
            "id": id,
            "publicKey": DEVICE_KEY,
            "label": "Laptop",
            "createdAt": "2026-08-27T10:00:00.000Z",
            "lastSeenAt": "2026-08-27T11:00:00.000Z",
        })
    }

    /// An engine with a live session, so a device command clears the gate that
    /// every one of them runs behind.
    fn started_device_engine() -> (Engine<FakeSeamTypes>, FakeDevice) {
        let (mut engine, _events, device) = engine_over(ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).expect("start");
        (engine, device)
    }

    /// [`started_device_engine`] against a configured base, logged in with an
    /// access token whose subject is `account_id`.
    fn engine_for_account(account_id: &str) -> (Engine<FakeSeamTypes>, FakeDevice) {
        use base64::Engine as _;

        let (mut engine, _events, device) =
            engine_over(ApiBaseUrl::parse("http://api.test").expect("a configured base"));
        device.http.enqueue_response(json_response(
            200,
            json!({ "challenge": LOGIN_CHALLENGE_FIXTURE, "expiresAt": "2099-01-01T00:00:00Z" }),
        ));
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({ "sub": account_id }).to_string());
        device.http.enqueue_response(json_response(
            200,
            new_user_login_response(
                &format!("header.{claims}.signature"),
                &"a".repeat(64),
                "gw-a",
            ),
        ));
        serve_provisioning(&device);
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).expect("start logs in");
        (engine, device)
    }

    #[test]
    fn the_register_device_command_posts_the_key_and_signature_it_was_given() {
        let (mut engine, device) = engine_for_account("account-7");
        let before = device.http.requests().len();
        device
            .http
            .enqueue_response(json_response(200, registry_row("device-1")));

        block_on(engine.command(Command::RegisterDevice {
            public_key: DEVICE_KEY.to_owned(),
            signature: device_signature(),
            identity_token: "identity-token".to_owned(),
            label: Some("Laptop".to_owned()),
        }))
        .expect("the registry accepted the key");

        let requests = device.http.requests();
        let sent = &requests[before..];
        assert_eq!(sent.len(), 1, "one registration and nothing else");
        assert_eq!(sent[0].method, HttpMethod::Post);
        assert_eq!(sent[0].url, "http://api.test/devices");
        let body: Value = serde_json::from_slice(sent[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["publicKey"], DEVICE_KEY);
        assert_eq!(body["signature"], device_signature());
        assert_eq!(body["identityToken"], "identity-token");
        assert_eq!(body["label"], "Laptop");
    }

    #[test]
    fn the_revoke_device_command_deletes_the_row_the_host_named() {
        let (mut engine, device) = started_device_engine();
        let before = device.http.requests().len();
        device
            .http
            .enqueue_response(json_response(200, json!({ "success": true })));

        block_on(engine.command(Command::RevokeDevice {
            device_id: "device-1".to_owned(),
        }))
        .expect("the row is gone");

        let requests = device.http.requests();
        let sent = &requests[before..];
        assert_eq!(sent.len(), 1, "one delete and nothing else");
        assert_eq!(sent[0].method, HttpMethod::Delete);
        assert_eq!(sent[0].url, "/devices/device-1");
    }

    #[test]
    fn the_respond_to_approval_command_answers_the_rendezvous_it_names() {
        let (mut engine, device) = started_device_engine();
        let ephemeral = devices::rendezvous_public_key(&[3u8; 32]).expect("a rendezvous key");
        let before = device.http.requests().len();
        device
            .http
            .enqueue_response(json_response(200, json!({ "success": true })));

        block_on(engine.command(Command::RespondToApproval {
            request_id: "request-1".to_owned(),
            decision: ApprovalDecision::Approve,
            device_public_key: DEVICE_KEY.to_owned(),
            ephemeral_public_key: ephemeral,
            signature: device_signature(),
            sealed_factor: Some(SEALED_FACTOR.to_owned()),
        }))
        .expect("the rendezvous is answered");

        let requests = device.http.requests();
        let sent = &requests[before..];
        assert_eq!(sent.len(), 1, "one response and nothing else");
        assert_eq!(sent[0].method, HttpMethod::Post);
        assert_eq!(sent[0].url, "/device-approval/requests/request-1/respond");
        let body: Value = serde_json::from_slice(sent[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["decision"], "approve");
        assert_eq!(body["devicePublicKey"], DEVICE_KEY);
        assert_eq!(body["sealedFactor"], SEALED_FACTOR);
    }

    /// The engine rebuilds the payload the API verifies, so a response the API
    /// would refuse is refused here — before it can be sent at all.
    #[test]
    fn a_response_the_api_would_refuse_never_leaves_the_device() {
        let (mut engine, device) = started_device_engine();
        let ephemeral = devices::rendezvous_public_key(&[3u8; 32]).expect("a rendezvous key");
        let response =
            |decision, ephemeral_public_key: String, sealed_factor| Command::RespondToApproval {
                request_id: "request-1".to_owned(),
                decision,
                device_public_key: DEVICE_KEY.to_owned(),
                ephemeral_public_key,
                signature: device_signature(),
                sealed_factor,
            };

        for (command, check) in [
            (
                response(
                    ApprovalDecision::Deny,
                    ephemeral.clone(),
                    Some(SEALED_FACTOR.to_owned()),
                ),
                "denial-seals-nothing",
            ),
            (
                response(
                    ApprovalDecision::Approve,
                    format!("04{}", "11".repeat(32)),
                    Some(SEALED_FACTOR.to_owned()),
                ),
                "ephemeral-key-not-a-point",
            ),
        ] {
            let before = device.http.requests().len();
            assert_eq!(
                block_on(engine.command(command)),
                Err(EngineError::MalformedInput { check }),
            );
            assert_eq!(
                device.http.requests().len(),
                before,
                "{check} built no request"
            );
        }
    }

    /// The account a device registers against is the one the session already
    /// authenticated as, so a host cannot ask for a payload that names another.
    #[test]
    fn the_registration_challenge_names_the_account_the_session_holds() {
        let (engine, _device) = engine_for_account("account-7");

        let challenge = block_on(engine.device_registration_challenge(DEVICE_KEY))
            .expect("a registration challenge");

        assert_eq!(
            String::from_utf8(challenge).expect("the payload is text"),
            format!("cipherbox/device-registration/v1\naccount-7\n{DEVICE_KEY}"),
        );
        assert_eq!(
            block_on(engine.device_registration_challenge(&DEVICE_KEY.to_uppercase())),
            Err(EngineError::MalformedInput {
                check: "device-public-key-not-lowercase-hex",
            }),
            "a key outside the registry alphabet is never signed",
        );
    }

    /// The bulletin board relays every field of a rendezvous, so a row it
    /// could have substituted is dropped rather than offered for approval.
    #[test]
    fn pending_approvals_drops_a_row_the_requester_did_not_sign() {
        let (engine, device) = started_device_engine();
        let signer = Ed25519Signer::from_seed([13u8; 32]);
        let requester = hex_lower(&signer.verifying_key().to_bytes());
        let ephemeral = devices::rendezvous_public_key(&[3u8; 32]).expect("a rendezvous key");
        let payload =
            devices::approval_request_payload(&requester, &ephemeral).expect("a request payload");
        let signature = hex_lower(&signer.sign(&payload).to_bytes());
        let row = |request_id: &str, request_signature: &str| {
            json!({
                "requestId": request_id,
                "requesterDevicePublicKey": requester,
                "ephemeralPublicKey": ephemeral,
                "requestSignature": request_signature,
                "createdAt": "2026-08-27T10:00:00.000Z",
                "expiresAt": "2026-08-27T10:05:00.000Z",
            })
        };
        device.http.enqueue_response(json_response(
            200,
            json!({ "requests": [
                row("request-1", &signature),
                row("request-2", &"11".repeat(64)),
                row("../account", &signature),
            ]}),
        ));
        device
            .http
            .enqueue_response(json_response(200, json!({ "devices": [] })));

        let rows = block_on(engine.pending_approvals()).expect("the board answered");

        assert_eq!(rows.len(), 1, "an unsigned rendezvous is never offered");
        assert_eq!(rows[0].request_id, "request-1");
        assert_eq!(
            rows[0].comparison_value,
            devices::comparison_value(&requester, &ephemeral).expect("a comparison value"),
            "the kept row carries the digits its own fields produce",
        );
    }

    /// A device on the registry already holds a factor, so a row naming one is
    /// the relay's invention rather than a member's device.
    #[test]
    fn pending_approvals_drops_a_row_naming_a_key_already_on_the_registry() {
        let (engine, device) = started_device_engine();
        let signer = Ed25519Signer::from_seed([13u8; 32]);
        let requester = hex_lower(&signer.verifying_key().to_bytes());
        let ephemeral = devices::rendezvous_public_key(&[3u8; 32]).expect("a rendezvous key");
        let payload =
            devices::approval_request_payload(&requester, &ephemeral).expect("a request payload");
        let signature = hex_lower(&signer.sign(&payload).to_bytes());
        device.http.enqueue_response(json_response(
            200,
            json!({ "requests": [{
                "requestId": "request-1",
                "requesterDevicePublicKey": requester,
                "ephemeralPublicKey": ephemeral,
                "requestSignature": signature,
                "createdAt": "2026-08-27T10:00:00.000Z",
                "expiresAt": "2026-08-27T10:05:00.000Z",
            }]}),
        ));
        device.http.enqueue_response(json_response(
            200,
            json!({ "devices": [{
                "id": "device-1",
                "publicKey": requester,
                "label": null,
                "createdAt": "2026-08-01T09:00:00.000Z",
                "lastSeenAt": "2026-08-20T09:00:00.000Z",
            }]}),
        ));

        let rows = block_on(engine.pending_approvals()).expect("the board answered");

        assert!(rows.is_empty(), "a registered key needs no approval");
    }

    /// The registry read costs a round trip, so an empty board never pays it.
    #[test]
    fn pending_approvals_reads_no_registry_when_the_board_is_empty() {
        let (engine, device) = started_device_engine();
        let before = device.http.requests().len();
        device
            .http
            .enqueue_response(json_response(200, json!({ "requests": [] })));

        assert!(
            block_on(engine.pending_approvals())
                .expect("the board answered")
                .is_empty()
        );

        assert_eq!(device.http.requests().len() - before, 1);
    }

    #[test]
    fn the_device_list_returns_the_rows_the_registry_served() {
        let (engine, device) = started_device_engine();
        device.http.enqueue_response(json_response(
            200,
            json!({ "devices": [registry_row("device-1")] }),
        ));

        let rows = block_on(engine.devices()).expect("the registry answered");

        assert_eq!(
            rows,
            vec![RegisteredDevice {
                id: "device-1".to_owned(),
                public_key: DEVICE_KEY.to_owned(),
                label: Some("Laptop".to_owned()),
                created_at: "2026-08-27T10:00:00.000Z".to_owned(),
                last_seen_at: "2026-08-27T11:00:00.000Z".to_owned(),
            }]
        );
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
