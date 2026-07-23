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

use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use futures_channel::mpsc;
use futures_core::Stream;
use zeroize::Zeroizing;

use crate::entropy::Entropy;
use crate::net::{
    Adopter, HeldRecord, LivenessControl, RE_PUT_INTERVAL, keyless_re_put, run_liveness_loop,
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
}

/// Errors returned by facade calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// A command was issued before [`Engine::start`].
    NotStarted,
    /// [`Engine::start`] was called on an already-started engine (one live
    /// instance is the single writer).
    AlreadyStarted,
    /// The login secret was empty.
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
}

impl EngineError {
    fn from_seam(err: SeamError) -> Self {
        EngineError::Seam {
            message: err.message().to_owned(),
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::NotStarted => f.write_str("engine not started"),
            EngineError::AlreadyStarted => f.write_str("engine already started"),
            EngineError::InvalidSecret => f.write_str("login secret must not be empty"),
            EngineError::Unimplemented { command } => {
                write!(f, "command not implemented yet: {command}")
            }
            EngineError::Seam { message } => write!(f, "seam error: {message}"),
            EngineError::Entropy { message } => write!(f, "entropy error: {message}"),
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
    events: mpsc::UnboundedSender<Event>,
    /// The last-known-good gate-passing base snapshot (state law's left
    /// operand). Seeded at the anchored root; cold-start/resolve replace it
    /// with the resolved remote state. Reads render this ⊕ the pending-op
    /// overlay; commands never mutate it — only the op queue diverges locally.
    snapshot: Snapshot,
    /// The session's live held-record set: the resolve slice pushes each
    /// gate-passing record here, and the cold-start liveness loop keyless
    /// re-PUTs the set on the hourly cadence. Empty until resolve lands.
    held_records: Rc<RefCell<Vec<HeldRecord>>>,
    /// Session-alive latch: cleared on drop so the spawned liveness loop
    /// stops at its next wake instead of re-PUTting after the engine is gone.
    alive: Rc<Cell<bool>>,
    /// The cold-start session identity, derived from the login secret at
    /// [`start`](Self::start). `None` until then; the single place derived key
    /// material lives once the engine is live. The resolve/publish/rotation
    /// slices and the liveness loop read every signer from here.
    session: Option<SessionIdentity>,
    started: bool,
}

impl<T: SeamTypes> Engine<T> {
    /// Builds an engine over the whole seam set and hands back the paired
    /// event stream.
    pub fn new(
        seams: SeamSet<T>,
        entropy: Box<dyn Entropy>,
        profile: SyncTimingProfile,
    ) -> (Self, EventStream) {
        let (events, receiver) = mpsc::unbounded();
        (
            Self {
                seams,
                entropy,
                profile,
                events,
                // The anchored all-zero root until cold-start/resolve replaces
                // the base snapshot; children come from the pending-op overlay.
                snapshot: Snapshot::new(NodeId([0u8; 16])),
                held_records: Rc::new(RefCell::new(Vec::new())),
                alive: Rc::new(Cell::new(true)),
                session: None,
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
    {
        if self.started {
            return Err(EngineError::AlreadyStarted);
        }
        if secret.is_empty() {
            return Err(EngineError::InvalidSecret);
        }
        // Pure derivation from the injected secret — no clock, no RNG — then
        // the secret zeroizes on drop here, at its terminal owner.
        self.session = Some(SessionIdentity::derive(&secret));
        drop(secret);
        self.spawn_liveness_loop();
        self.started = true;
        Ok(())
    }

    /// The live session identity, once [`start`](Self::start) has derived it.
    /// `pub(crate)`: the in-crate pipeline (resolve, publish, rotation, the
    /// liveness loop) reads its signers here; hosts wrap the facade and never
    /// hold key material.
    // Read by the pipeline slices that consume the session (resolve #745/#746,
    // liveness composition #750/#751); the hook is live now, its callers land next.
    #[allow(dead_code)]
    pub(crate) fn session(&self) -> Option<&SessionIdentity> {
        self.session.as_ref()
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
    // Live composition consumed by the facade cold-start test; the resolver slice
    // (#745/#746) supplies the concrete `PointerFetch`/`Adopter` at the `start`
    // call site.
    #[allow(dead_code)]
    pub(crate) async fn cold_start_data_path<Pf, Ad>(
        &mut self,
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

    /// Spawn the ~hourly keyless re-PUT loop (blueprint/engine.md "Liveness"):
    /// actively-used vaults keep their own records alive off the injected
    /// scheduler, so no client depends on the API republisher. The task holds
    /// only `Rc`/seam-handle clones, so the engine may drop while it is parked;
    /// the alive latch then stops it. The sub-EOL seq+1 renewal joins this same
    /// loop once cold-start derives the per-name signers it needs.
    fn spawn_liveness_loop(&self)
    where
        T::Scheduler: Clone + 'static,
        T::RecordTransport: Clone + 'static,
    {
        let scheduler = self.seams.scheduler.clone();
        let transport = self.seams.record_transport.clone();
        let held = self.held_records.clone();
        let alive = self.alive.clone();
        self.seams.scheduler.spawn(Box::pin(async move {
            run_liveness_loop(&scheduler, RE_PUT_INTERVAL, || async {
                if !alive.get() {
                    return LivenessControl::Stop;
                }
                let records = held.borrow().clone();
                keyless_re_put(&transport, &records).await;
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

    use crate::seams::UnixMillis;
    use crate::testkit::{FakeSeamTypes, FakeWorld, SeededEntropy, block_on};

    fn new_engine() -> (Engine<FakeSeamTypes>, EventStream) {
        let device = FakeWorld::new().device(b"alice-pk");
        Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
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

        // The per-name signers #750/#751 need are reachable and match the pure
        // derivation from the same secret — start invents no key material.
        let expected = SessionIdentity::derive(&LoginSecret::new(vec![7u8; 32]));
        assert_eq!(
            session.vault_pointer_signer(0).verifying_key().to_bytes(),
            expected.vault_pointer_signer(0).verifying_key().to_bytes(),
        );
        assert_eq!(
            session
                .write_name_signer(&[5u8; 32], &[4u8; 16])
                .verifying_key()
                .to_bytes(),
            expected
                .write_name_signer(&[5u8; 32], &[4u8; 16])
                .verifying_key()
                .to_bytes(),
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
            ) -> Result<Adopted, crate::gate::GateError> {
                Ok(Adopted {
                    read_body: ReadBody::Folder {
                        created_at: 0,
                        modified_at: 0,
                        children: Vec::new(),
                        unknown: Vec::new(),
                    },
                    sequence: 1,
                    epoch: 1,
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
            let (mut engine, events) = Engine::new(
                device.seam_set(),
                Box::new(SeededEntropy::new(42)),
                SyncTimingProfile::CI,
            );
            block_on(engine.start(LoginSecret::new(SECRET.to_vec()))).unwrap();
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
            let (mut engine, _events) = new_engine();
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
            let (mut engine, _events) = Engine::new(
                device.seam_set(),
                Box::new(SeededEntropy::new(42)),
                SyncTimingProfile::CI,
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
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
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
}
