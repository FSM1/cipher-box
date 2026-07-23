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
//! the [`Command`] enum, the [`Event`] stream) is frozen. This slice wires the
//! facade onto the sync core: the metadata intent ops (create/delete/rename/
//! relink) stage through the durable op queue, reads render the gate-passing
//! base snapshot ⊕ pending-op overlay (blueprint/engine.md "Sync core: State
//! law"), and every successful stage emits [`Event::SnapshotUpdated`]. The
//! non-metadata commands (grants, rotation, auth, content seal) stay
//! [`EngineError::Unimplemented`] until their slices land.

use core::cell::{Cell, RefCell};
use core::fmt;
use core::pin::Pin;
use std::rc::Rc;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use futures_channel::mpsc;
use futures_core::Stream;
use zeroize::Zeroizing;

use crate::api::{ApiClient, ApiError, IdentityChallengeSigner};
use crate::content::{Gateway, GatewayConfig};
use crate::entropy::Entropy;
use crate::hex::hex_lower;
use crate::net::{
    Adopter, EolRenewResult, HeldMaterial, HeldRecord, HeldRecords, LivenessControl, PublishError,
    PublishOutcome, RE_PUT_INTERVAL, RecordPointerFetch, RootAdopter, eol_renew_pass,
    keyless_re_put, resolve_and_hold, run_liveness_loop,
};
use crate::profile::SyncTimingProfile;
use crate::seams::{OpId, Scheduler, SeamError, SeamSet, SeamTypes, StagingStore};
use crate::session::SessionIdentity;
use crate::sync::boot::{ColdStartError, ColdStartOutcome, ColdStartParams, cold_start};
use crate::sync::model::{NodeMeta, Snapshot, collation_key};
use crate::sync::op::Op;
use crate::sync::overlay::apply_overlay;
use crate::sync::pointer::PointerFetch;
use crate::sync::rebase::decode_queue;
use crate::sync::staging::{StageOutcome, stage_op};

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

/// Plaintext file content crossing the facade.
///
/// A newtype rather than bare `Vec<u8>` so `Debug` is structurally
/// redacted: plaintext user bytes must never reach a log site (security
/// rule 2), including through a derived `{:?}` on a containing [`Command`].
#[derive(Clone, PartialEq, Eq)]
pub struct PlaintextContent(pub Vec<u8>);

impl fmt::Debug for PlaintextContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlaintextContent(<{} bytes>)", self.0.len())
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

/// A node's host-facing attributes, projected from the rendered view for a
/// FUSE getattr/readdir. Kind-uniform metadata only — content size and
/// timestamps land with the content-plane slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAttrs {
    /// Stable node id.
    pub id: NodeId,
    /// Display name, as entered.
    pub name: String,
    /// File or folder.
    pub kind: NodeKind,
    /// Current content version (bumped per `updateContent`).
    pub content_version: u64,
}

/// Minimal filesystem-level counters for a FUSE statfs. Node count only:
/// quota and byte accounting live on the API client and are not wired at the
/// facade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatFs {
    /// Nodes reachable from the root in the rendered view.
    pub nodes: u64,
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
    /// Create a node under a parent.
    Create {
        /// Parent folder.
        parent: NodeId,
        /// Name as entered (uniqueness uses the strict comparator).
        name: String,
        /// File or folder.
        kind: NodeKind,
        /// Initial content for file creates.
        content: Option<PlaintextContent>,
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
    /// Write new content to a file node (fresh per-version content key).
    UpdateContent {
        /// Target file node.
        node: NodeId,
        /// New content bytes.
        content: PlaintextContent,
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
            Command::UpdateContent { .. } => "updateContent",
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
    /// A queued op terminally failed rebase; staged bytes are preserved
    /// (#33 D6).
    DeadLetter {
        /// The dead-lettered op.
        op_id: OpId,
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
    /// The command's pipeline slice has not landed yet (scaffold state).
    Unimplemented {
        /// [`Command::name`] of the rejected command.
        command: &'static str,
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
            EngineError::Unimplemented { command } => {
                write!(f, "command not implemented yet: {command}")
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
        content_version: meta.content_version,
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
    /// Seeds, nonces, jitter, and command-path node-id minting.
    entropy: Box<dyn Entropy>,
    profile: SyncTimingProfile,
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
    snapshot: Snapshot,
    /// The session's live held-record set, keyed by node id: the resolve path
    /// ([`resolve_and_hold`](crate::net::resolve_and_hold)) inserts each
    /// gate-passing record here, and the cold-start liveness loop keyless
    /// re-PUTs the map's values on the hourly cadence. Empty until the resolve
    /// tick driver (next slice) wires it in.
    held_records: Rc<RefCell<HeldRecords>>,
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
        api_base_url: String,
        gateway: GatewayConfig,
    ) -> (Self, EventStream) {
        let (events, receiver) = mpsc::unbounded();
        (
            Self {
                seams,
                entropy,
                profile,
                api_base_url,
                gateway: gateway.into_gateway(),
                events,
                // The anchored all-zero root until cold-start/resolve replaces
                // the base snapshot; children come from the pending-op overlay.
                snapshot: Snapshot::new(NodeId([0u8; 16])),
                held_records: Rc::new(RefCell::new(HeldRecords::new())),
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
    /// factories the pipeline layers scope material onto. The remaining
    /// cold-start steps (vault-pointer resolve, floor cold-seed, root
    /// adoption, first snapshot event) land with the resolve/gate slices,
    /// which read their key material from the session assembled here.
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
        let cold_start = {
            let session = self.session.as_ref().expect("session set above");
            let owner_identity = session.owner_identity();
            let root = self.snapshot.root;
            let root_scope_id = root.0;
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
        let outcome = match cold_start {
            Ok(outcome) => outcome,
            Err(err) => {
                // Fail-closed symmetry with the login path: clear the derived
                // session so no key material stays resident and the engine reports
                // unstarted.
                self.session = None;
                return Err(EngineError::from_cold_start(err));
            }
        };

        // The gate-passing base becomes the state law's left operand (reads render
        // this ⊕ the pending-op overlay). The resolved root name — the vault
        // pointer's `currentRoot` — drives the resolve-tick loop; `None` on an
        // empty chain, where the tick loop stays a dormant no-op.
        let root_name = outcome
            .vault_pointer
            .as_ref()
            .map(|vp| vp.repoint.current_root.clone());
        self.snapshot = outcome.base;

        self.spawn_liveness_loop(api.clone());
        self.spawn_resolve_tick_loop(root_name);
        self.api = Some(api);
        self.started = true;
        Ok(())
    }

    /// The live session identity, once [`start`](Self::start) has derived it.
    /// `pub(crate)`: the in-crate pipeline (resolve, publish, rotation, the
    /// liveness loop) reads its signers here; hosts wrap the facade and never
    /// hold key material.
    // Read by the pipeline slices that consume the session (resolve #745/#746);
    // the liveness loop (#750) shares the `Rc` directly.
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
    /// Reads every seam from the engine, the login secret from
    /// [`session`](Self::session), and the pending ops from the durable staging
    /// store; emits no clock/RNG-derived value, so the whole chain is
    /// deterministic off the injected seams. The record-plane fetchers enter as
    /// the two seam traits the resolver slices (#745/#746) implement:
    /// [`PointerFetch`] for the pointer block and [`Adopter`] for the root record.
    ///
    /// `owner_identity` is the auth-provided contact-code-anchored identity that
    /// signs the re-point object — the vault-pointer walk's fail-closed anchor.
    // Takes `&self`: `start` runs the production `RootAdopter`/`RecordPointerFetch`
    // through it while they borrow the engine's own gateway/seams — a `&mut self`
    // receiver would alias those shared borrows.
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
        let (decoded, undecodable) = decode_queue(&raw);
        let pending: Vec<_> = decoded.into_iter().map(|(_id, op)| op).collect();

        // Surface every undecodable queue entry as `Event::DeadLetter` and drop
        // its op record from the durable queue so a corrupt/forward-version
        // entry is not re-decoded and re-emitted on every boot (#768). Staged
        // upload bytes live in a separate plane keyed by staging keys — never
        // touched here, so they are retained per the dead-letter contract
        // (blueprint/engine.md #33 D6).
        //
        // `DeadLetter` delivery is best-effort over a non-durable in-process
        // channel, so hosts MUST dedup by `op_id`. Gate the durable removal on a
        // successful send: a receiver dropped mid-teardown must not silently
        // purge an unsurfaced entry — preserved, the next boot re-surfaces it.
        for (op_id, _reason) in &undecodable {
            if self
                .events
                .unbounded_send(Event::DeadLetter { op_id: *op_id })
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
        let mut emit = |event: Event| {
            let _ = events.unbounded_send(event);
        };
        cold_start(
            pointer_fetch,
            adopter,
            &self.seams.floor_store,
            &self.seams.record_transport,
            &self.seams.snapshot_cache,
            &params,
            &mut emit,
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
        // The shared client from `start` (see the `api` field): the renewal pass
        // only fires once the resolve-tick driver populates the held set.
        self.seams.scheduler.spawn(Box::pin(async move {
            run_liveness_loop(&scheduler, RE_PUT_INTERVAL, || async {
                if !alive.get() {
                    return LivenessControl::Stop;
                }
                let records: Vec<HeldRecord> = held.borrow().values().cloned().collect();
                keyless_re_put(&transport, &records).await;
                // Surface every renewal that did not land (LostRace/PublishError)
                // as an Event — never a silent failure (blueprint/engine.md). The
                // held set is empty until the resolve-tick driver populates it.
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
    fn spawn_resolve_tick_loop(&self, root_name: Option<IpnsName>)
    where
        T::Scheduler: Clone + 'static,
        T::RecordTransport: Clone + 'static,
        T::Http: Clone + 'static,
        T::FloorStore: Clone + 'static,
        T::SnapshotCache: Clone + 'static,
    {
        let (Some(root_name), Some(session)) = (root_name, self.session.clone()) else {
            return;
        };
        let scheduler = self.seams.scheduler.clone();
        let transport = self.seams.record_transport.clone();
        let snapshot_cache = self.seams.snapshot_cache.clone();
        let floors = self.seams.floor_store.clone();
        let http = self.seams.http.clone();
        let gateway = self.gateway.clone();
        let held = self.held_records.clone();
        let alive = self.alive.clone();
        let interval = self.profile.poll_cadence;
        let owner_identity = session.owner_identity();
        // The vault's own root scope and root node are the anchored all-zero id16
        // (the cold-start bootstrap anchor): the adopter's scope binding and the
        // held-set fallback key.
        let root_id = self.snapshot.root.0;

        self.seams.scheduler.spawn(Box::pin(async move {
            run_liveness_loop(&scheduler, interval, || async {
                if !alive.get() {
                    return LivenessControl::Stop;
                }
                // Rebuild the owner-root adopter from the Rc'd session + task-owned
                // seams each pass (the adopter borrows; the task owns the clones).
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
                // The resolve outcome (incl. a steady-state `TrustViolation`) is
                // dropped: fail-closed for data (a forged record is never held or
                // rendered), but surfacing it as a staleness-ladder /
                // `AttributableAbuse` event is a later slice.
                let _ = resolve_and_hold(
                    &transport,
                    &snapshot_cache,
                    &adopter,
                    &root_name,
                    &held,
                    &material,
                )
                .await;
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
    pub async fn command(&mut self, command: Command) -> Result<(), EngineError> {
        if !self.started {
            return Err(EngineError::NotStarted);
        }
        let command_name = command.name();
        match command {
            Command::Create {
                parent,
                name,
                kind,
                content,
            } => {
                // A content-bearing create needs the content plane (sealing +
                // staged bytes), a later slice; only metadata creates (folders
                // and empty files) stage here.
                if content.is_some() {
                    return Err(EngineError::Unimplemented {
                        command: command_name,
                    });
                }
                let target = self.mint_node_id()?;
                let base_sequence = self.base_sequence_for(parent).await?;
                let op = Op::create(target, parent, name, kind, base_sequence, None);
                self.stage_and_notify(&op).await
            }
            Command::Delete { node } => {
                // Both anchors snapshot the target's own sequence for the
                // conditional-delete rebase rule.
                let seq = self.base_sequence_for(node).await?;
                self.stage_and_notify(&Op::delete(node, seq, seq)).await
            }
            Command::Rename { node, new_name } => {
                let seq = self.base_sequence_for(node).await?;
                self.stage_and_notify(&Op::rename(node, new_name, seq))
                    .await
            }
            Command::Relink { node, new_parent } => {
                let rendered = self.render().await?;
                let from_parent = rendered.parent_of(node).unwrap_or(self.snapshot.root);
                let base_sequence = rendered.record_sequence(node).unwrap_or(1);
                // trailing bools: cross_scope=false, exits_granted_source=false — intra-scope pure relink
                let op = Op::relink(node, from_parent, new_parent, base_sequence, false, false);
                self.stage_and_notify(&op).await
            }
            Command::SiweLogin { message, signature } => {
                let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
                api.siwe_login(&message, &hex_lower(&signature))
                    .await
                    .map_err(EngineError::from_api)?;
                Ok(())
            }
            other => Err(EngineError::Unimplemented {
                command: other.name(),
            }),
        }
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

    /// The current base snapshot's root node id — the FUSE mount anchor. The
    /// seeded all-zero root until cold-start/resolve replaces the base snapshot.
    pub fn root(&self) -> NodeId {
        self.snapshot.root
    }

    /// Render the base snapshot with the pending-op overlay applied.
    async fn render(&self) -> Result<Snapshot, EngineError> {
        let ops = self.pending_ops().await?;
        Ok(apply_overlay(&self.snapshot, &ops))
    }

    /// The pending ops from the durable staging store, decoded FIFO. Undecodable
    /// entries are dropped from the render here; the cold-start path dead-letters
    /// and removes them from the durable queue.
    async fn pending_ops(&self) -> Result<Vec<Op>, EngineError> {
        let raw = self
            .seams
            .staging_store
            .queued_ops()
            .await
            .map_err(EngineError::from_seam)?;
        let (decoded, _undecodable) = decode_queue(&raw);
        Ok(decoded.into_iter().map(|(_id, op)| op).collect())
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
    fn mint_node_id(&mut self) -> Result<NodeId, EngineError> {
        let mut id = [0u8; 16];
        self.entropy
            .fill(&mut id)
            .map_err(|e| EngineError::Entropy {
                message: e.message().to_owned(),
            })?;
        Ok(NodeId(id))
    }

    /// Stage a metadata op and emit [`Event::SnapshotUpdated`] on success.
    async fn stage_and_notify(&mut self, op: &Op) -> Result<(), EngineError> {
        // metadata ops never budget-reject; a rejection means a content op reached this path — fail closed
        match stage_op(&self.seams.staging_store, &self.profile, op, None)
            .await
            .map_err(EngineError::from_seam)?
        {
            StageOutcome::Queued { .. } => {
                // Best-effort push-invalidation trigger; a dropped receiver
                // (host torn down) is fine.
                let _ = self.events.unbounded_send(Event::SnapshotUpdated);
                Ok(())
            }
            StageOutcome::RejectedOverBudget { .. } => Err(EngineError::Seam {
                message: "metadata op unexpectedly rejected over budget".to_owned(),
            }),
        }
    }

    /// The sync timing profile this engine runs under.
    pub fn profile(&self) -> &SyncTimingProfile {
        &self.profile
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
            content: Some(PlaintextContent(b"top-secret-plaintext".to_vec())),
        };
        let debug = format!("{command:?}");
        assert_eq!(debug, "Command(create)", "payloads must never leak");
    }

    #[test]
    fn plaintext_content_debug_is_redacted() {
        let content = PlaintextContent(b"top-secret-plaintext".to_vec());
        assert_eq!(format!("{content:?}"), "PlaintextContent(<20 bytes>)");
    }

    #[test]
    fn engine_error_displays() {
        assert_eq!(
            EngineError::Unimplemented { command: "create" }.to_string(),
            "command not implemented yet: create"
        );
        assert_eq!(EngineError::NotStarted.to_string(), "engine not started");
    }

    // --- facade wiring: reads, command execution, event emission ---

    fn started() -> (Engine<FakeSeamTypes>, EventStream) {
        let (mut engine, events) = new_engine();
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        (engine, events)
    }

    fn create(engine: &mut Engine<FakeSeamTypes>, parent: NodeId, name: &str, kind: NodeKind) {
        block_on(engine.command(Command::Create {
            parent,
            name: name.into(),
            kind,
            content: None,
        }))
        .unwrap();
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
    fn content_bearing_create_is_unimplemented_pending_the_content_plane() {
        let (mut engine, _events) = started();
        let root = engine.root();
        let out = block_on(engine.command(Command::Create {
            parent: root,
            name: "f".into(),
            kind: NodeKind::File,
            content: Some(PlaintextContent(b"x".to_vec())),
        }));
        assert_eq!(out, Err(EngineError::Unimplemented { command: "create" }));
        // Nothing staged: the read surface stays empty.
        assert!(block_on(engine.view()).unwrap().children(root).is_empty());
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
            // A corrupt op record that `Op::decode` rejects.
            let op_id = block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op"))
                .expect("enqueue");
            assert_eq!(op_id, OpId(1));

            drive(&mut engine, &pointers);

            // The dead-letter surfaces on the host stream ahead of the first paint.
            assert_eq!(
                block_on(events.next()),
                Some(Event::DeadLetter { op_id: OpId(1) })
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
        fn dead_lettered_entry_is_not_re_emitted_on_a_second_boot() {
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
            block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op")).expect("enqueue");

            // First boot: surfaces the dead-letter, then paints.
            drive(&mut engine, &pointers);
            assert_eq!(
                block_on(events.next()),
                Some(Event::DeadLetter { op_id: OpId(1) })
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
                Some(Event::DeadLetter { op_id: OpId(1) })
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
                Some(Event::DeadLetter { op_id: OpId(1) })
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
            AadContext, ChildRef, GrantSection, GrantSetCommitment, NodeKind as CoreNodeKind,
            OverrideSeedPayload, OwnerWriteBlobPayload, ReadBody, STRUCT_TAG_OWNER_BLOB,
            STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_WRITE_BODY, SignedOwnerBlob,
            SignedOwnerWriteBlob, SignedSealed, StructureSigInput, WriteBody, encode_envelope,
            encode_grant_section, encode_write_body, seal, seal_owner_blob, seal_owner_write_blob,
            seal_read_body, sign_grant_set, sign_structure,
        };
        use cipherbox_core::suite::ecdsa::EcdsaSigner;
        use cipherbox_core::suite::ed25519::Ed25519Signer;

        use crate::content::{DAG_ROOT_CODEC, GatewaySource};
        use crate::net::RE_PUT_INTERVAL;
        use crate::seams::{BoxedTask, EndpointId, RecordTransport};
        use crate::sync::pointer::{SessionRole, seal_repoint, vault_pointer_name};
        use crate::testkit::FakeDevice;

        const CAP_SECRET: [u8; 32] = [7u8; 32];
        const SCOPE: [u8; 16] = [0u8; 16];
        const ROOT: NodeId = NodeId([0u8; 16]);
        const CHILD_ID: [u8; 16] = [0x2C; 16];
        const CHILD_NAME: &str = "hello.txt";
        const SCOPE_SEED: [u8; 32] = [0x66; 32];
        const WRITE_SCOPE_SEED: [u8; 32] = [0x77; 32];
        const EPOCH: u64 = 1;
        const TTL_NANOS: u64 = 2_000_000_000;
        const EOL: &str = "2099-01-01T00:00:00Z";

        fn owner_identity() -> EcdsaSigner {
            EcdsaSigner::from_scalar(&CAP_SECRET).expect("valid scalar")
        }

        /// The owner-root head block (one child) and its content-CID string, plus
        /// the root record's write-plane IPNS name. Keyed off `CAP_SECRET` so the
        /// engine's session-derived owner identity + enc subkey open it, and scoped
        /// to the all-zero bootstrap anchor (`SCOPE`/`ROOT`) so `start`'s cold-start
        /// scope binding matches. Mirrors the E2 `RootAdopter` head-block fixture.
        fn owner_root() -> (Vec<u8>, String, IpnsName) {
            let owner_identity = owner_identity();
            let owner_pseudonym = Ed25519Signer::from_seed([0x22; 32]);
            let owner_enc = kdf::enc_subkey(&CAP_SECRET);

            let node_seed = kdf::node_seed(&SCOPE_SEED, &ROOT.0);
            let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();
            let write_seed = kdf::write_seed(&WRITE_SCOPE_SEED, &ROOT.0);
            let name = IpnsName::from_public_key(
                &kdf::ipns_keypair(write_seed.as_bytes()).verifying_key(),
            );
            let write_key = kdf::write_key(write_seed.as_bytes());

            let sign = |tag: u8, ct: &[u8]| -> [u8; 64] {
                let input = StructureSigInput::over_ciphertext(SCOPE, EPOCH, tag, None, ct);
                sign_structure(&owner_pseudonym, &input).to_bytes()
            };

            let owner_blob_aad = AadContext {
                v: 1,
                id: ROOT.0,
                scope: SCOPE,
                epoch: EPOCH,
                struct_tag: STRUCT_TAG_OWNER_BLOB,
            };
            let sealed_owner = seal_owner_blob(
                &owner_enc.public(),
                &[3u8; 32],
                &owner_blob_aad,
                &OverrideSeedPayload::new(SCOPE_SEED, EPOCH),
            );
            let owner_blob = SignedOwnerBlob {
                signature: sign(STRUCT_TAG_OWNER_BLOB, &sealed_owner.ciphertext),
                enc: sealed_owner.enc,
                ciphertext: sealed_owner.ciphertext.clone(),
                unknown: Vec::new(),
            };

            let write_body_aad = AadContext {
                v: 1,
                id: ROOT.0,
                scope: SCOPE,
                epoch: EPOCH,
                struct_tag: STRUCT_TAG_WRITE_BODY,
            };
            let write_body_sealed = seal(
                write_key.as_bytes(),
                &[22u8; 24],
                &write_body_aad,
                &encode_write_body(&WriteBody {
                    grant_ledger: Vec::new(),
                    write_history_link: Vec::new(),
                    direct_child_scope_index: Vec::new(),
                    unknown: Vec::new(),
                })
                .unwrap(),
            );
            let write_body = SignedSealed {
                signature: sign(STRUCT_TAG_WRITE_BODY, &write_body_sealed),
                sealed: write_body_sealed,
                unknown: Vec::new(),
            };

            // Owner-write-blob at the read epoch (write plane == read plane here), so
            // the cold-seeded write floor opens it and the owner recovers its
            // write-scope seed for the held-set renewal signer.
            let owb_aad = AadContext {
                v: 1,
                id: ROOT.0,
                scope: SCOPE,
                epoch: EPOCH,
                struct_tag: STRUCT_TAG_OWNER_WRITE_BLOB,
            };
            let sealed_owb = seal_owner_write_blob(
                &owner_enc.public(),
                &[4u8; 32],
                &owb_aad,
                &OwnerWriteBlobPayload::new(WRITE_SCOPE_SEED, EPOCH),
            );
            let owner_write_blob = Some(SignedOwnerWriteBlob {
                signature: sign(STRUCT_TAG_OWNER_WRITE_BLOB, &sealed_owb.ciphertext),
                enc: sealed_owb.enc,
                ciphertext: sealed_owb.ciphertext,
                unknown: Vec::new(),
            });

            let commitment = GrantSetCommitment {
                ipns_name: name.as_str().as_bytes().to_vec(),
                owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
                entries: Vec::new(),
                unknown: Vec::new(),
            };
            let commitment_sig = sign_grant_set(&owner_identity, &commitment)
                .unwrap()
                .to_compact();
            let grant_section = GrantSection {
                commitment,
                commitment_sig,
                grant_blobs: Vec::new(),
                owner_blob,
                owner_write_blob,
                ascent_link: None,
                history_links: Vec::new(),
                write_body,
                unknown: Vec::new(),
            };

            let folder = ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children: vec![ChildRef {
                    id: CHILD_ID,
                    name: CHILD_NAME.into(),
                    ipns_name: vec![0x2C],
                    kind: CoreNodeKind::File,
                    link_counter: 1,
                    unknown: Vec::new(),
                }],
                unknown: Vec::new(),
            };
            let mut envelope =
                seal_read_body(&read_key, &[11u8; 24], 1, ROOT.0, SCOPE, EPOCH, &folder).unwrap();
            envelope.unknown.push((
                "grantSection".to_string(),
                Value::Bytes(encode_grant_section(&grant_section).unwrap()),
            ));

            let head_block = encode_envelope(&envelope);
            let head_cid_str = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head_block));
            (head_block, head_cid_str, name)
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
    }
}
