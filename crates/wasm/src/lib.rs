//! CipherBox wasm — wasm-bindgen bindings over the engine facade
//! (`cipherbox-engine`, which links `cipherbox-core`), loaded as one ES module
//! inside the engine worker by `packages/client`.
//!
//! Normative design: blueprint/web-client.md ("WASM packaging and the type
//! boundary"). This crate is bindings only — it holds no vault logic, no
//! crypto, and no codec of its own; every trust decision already happened
//! below the facade (blueprint/engine.md). Core is linked *inside*: nothing
//! from `cipherbox-core` is exported directly to JS.
//!
//! The wasm-bindgen-generated `.d.ts` is the single boundary contract that
//! `packages/client` re-exports — there is no hand-maintained TS mirror of
//! engine structures. Boundary hygiene is structural: `u64`s (op ids, sizes,
//! IPNS sequence numbers) cross as `bigint`, binary payloads as `Uint8Array`,
//! and no secret key material crosses at all — the command surface exposes
//! only intent (a grant carries the recipient's *public* identity key, never
//! a secret), and the event and read surfaces only key-free view state and
//! decrypted user content (snapshot views, downloaded plaintext bytes).

// wasm-bindgen's macro-generated glue is unsafe by nature and exempt; this
// forbids only unsafe we would hand-write (there is none).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use cipherbox_engine::facade;
use wasm_bindgen::prelude::*;

// Shared JS-seam → engine-seam adapters (browser wasm target only): both the
// production engine host and the test-only conformance bridge build on them.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod seams_bridge;

// The production engine host: constructs the one engine instance over the
// browser seams and exposes `start`/`command`/`snapshot`/`download`/`nextEvent`
// to the worker.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod host;

// Test-only browser seam conformance bridge. Compiled only for the browser
// suite's WASM build (`--features conformance` on the wasm target); the
// production artifact never pulls the engine test kit or these bindings.
#[cfg(all(feature = "conformance", target_family = "wasm", target_os = "unknown"))]
mod conformance;

// ---------------------------------------------------------------------------
// Boundary value types.
// ---------------------------------------------------------------------------

/// The stable 16-byte node identifier (`id16`). Routes and commands key on it,
/// never on rotating `ipnsName`s.
#[wasm_bindgen]
pub struct NodeId {
    inner: facade::NodeId,
}

#[wasm_bindgen]
impl NodeId {
    /// Builds a node id from its 16 raw bytes; throws if the length is wrong.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<NodeId, JsError> {
        let inner: [u8; 16] = bytes
            .try_into()
            .map_err(|_| JsError::new("nodeId must be exactly 16 bytes"))?;
        Ok(Self {
            inner: facade::NodeId(inner),
        })
    }

    /// The 16 raw bytes of this node id.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.0.to_vec()
    }
}

impl NodeId {
    fn facade(&self) -> facade::NodeId {
        self.inner
    }
}

/// What a created node is (sealed inside the read-body on the wire; plain
/// intent at the facade).
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A file node.
    File,
    /// A folder node.
    Folder,
}

impl From<NodeKind> for facade::NodeKind {
    fn from(kind: NodeKind) -> Self {
        match kind {
            NodeKind::File => facade::NodeKind::File,
            NodeKind::Folder => facade::NodeKind::Folder,
        }
    }
}

impl From<facade::NodeKind> for NodeKind {
    fn from(kind: facade::NodeKind) -> Self {
        match kind {
            facade::NodeKind::File => NodeKind::File,
            facade::NodeKind::Folder => NodeKind::Folder,
        }
    }
}

/// What the op queue holds for a node (a queued content write outranks a queued
/// metadata mutation).
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingClass {
    /// No queued op targets the node.
    None,
    /// A queued op mutates only the node's metadata.
    Metadata,
    /// A queued op writes new content bytes for the node.
    Content,
}

impl From<facade::PendingClass> for PendingClass {
    fn from(class: facade::PendingClass) -> Self {
        match class {
            facade::PendingClass::None => PendingClass::None,
            facade::PendingClass::Metadata => PendingClass::Metadata,
            facade::PendingClass::Content => PendingClass::Content,
        }
    }
}

/// Grant permission level.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read grant: read seed only.
    Read,
    /// Write grant: read and write seeds.
    Write,
}

impl From<Permission> for facade::Permission {
    fn from(permission: Permission) -> Self {
        match permission {
            Permission::Read => facade::Permission::Read,
            Permission::Write => facade::Permission::Write,
        }
    }
}

/// The staleness ladder (#33 D4): a view is `Fresh`, quietly `Reconciling`,
/// `Stale` past the profile threshold, or `Offline`. Availability staleness,
/// never a trust violation.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staleness {
    /// View is within the freshness window.
    Fresh,
    /// A background reconcile is in flight.
    Reconciling,
    /// Past the profile threshold: "last synced X ago".
    Stale,
    /// Offline banner.
    Offline,
}

impl From<facade::Staleness> for Staleness {
    fn from(level: facade::Staleness) -> Self {
        match level {
            facade::Staleness::Fresh => Staleness::Fresh,
            facade::Staleness::Reconciling => Staleness::Reconciling,
            facade::Staleness::Stale => Staleness::Stale,
            facade::Staleness::Offline => Staleness::Offline,
        }
    }
}

/// The phase an `opProgress` event reports.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpPhase {
    /// A content download started.
    DownloadStarted,
    /// A content download completed.
    DownloadCompleted,
    /// A content download failed.
    DownloadFailed,
}

impl From<facade::OpPhase> for OpPhase {
    fn from(phase: facade::OpPhase) -> Self {
        match phase {
            facade::OpPhase::DownloadStarted => OpPhase::DownloadStarted,
            facade::OpPhase::DownloadCompleted => OpPhase::DownloadCompleted,
            facade::OpPhase::DownloadFailed => OpPhase::DownloadFailed,
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot read surface — key-free view state projected by the engine. Ids
// cross as raw 16-byte `Uint8Array`s (the `NodeId.bytes` shape), `u64`s as
// `bigint`, absent projections as `undefined`.
// ---------------------------------------------------------------------------

/// One ancestor step in a [`SnapshotView`]'s breadcrumb trail.
#[wasm_bindgen]
pub struct Breadcrumb {
    inner: facade::Breadcrumb,
}

#[wasm_bindgen]
impl Breadcrumb {
    /// The 16 raw bytes of the ancestor's node id.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Vec<u8> {
        self.inner.id.0.to_vec()
    }

    /// Display name, as entered (empty for the root).
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.inner.name.clone()
    }
}

impl Breadcrumb {
    /// Wraps an engine breadcrumb. Never exported to JS.
    pub fn from_facade(inner: facade::Breadcrumb) -> Self {
        Self { inner }
    }
}

/// One direct child in a [`SnapshotView`].
#[wasm_bindgen]
pub struct SnapshotChild {
    inner: facade::SnapshotChild,
}

#[wasm_bindgen]
impl SnapshotChild {
    /// The 16 raw bytes of the child's node id.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Vec<u8> {
        self.inner.id.0.to_vec()
    }

    /// Display name, as entered.
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    /// File or folder.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> NodeKind {
        self.inner.kind.into()
    }

    /// Plaintext content size in bytes (a `bigint`), or `undefined` until the
    /// content plane projects it.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> Option<u64> {
        self.inner.size
    }

    /// Modification time in Unix millis (a `bigint`), or `undefined` until
    /// projected.
    #[wasm_bindgen(getter)]
    pub fn mtime(&self) -> Option<u64> {
        self.inner.mtime
    }

    /// What the op queue holds for this node.
    #[wasm_bindgen(getter)]
    pub fn pending(&self) -> PendingClass {
        self.inner.pending.into()
    }

    /// Whether a retained dead-lettered op maps to this node.
    #[wasm_bindgen(getter, js_name = deadLetter)]
    pub fn dead_letter(&self) -> bool {
        self.inner.dead_letter
    }

    /// Retained version count (a `bigint`), or `undefined` until projected.
    #[wasm_bindgen(getter, js_name = contentVersion)]
    pub fn content_version(&self) -> Option<u64> {
        self.inner.content_version
    }
}

impl SnapshotChild {
    /// Wraps an engine snapshot child. Never exported to JS.
    pub fn from_facade(inner: facade::SnapshotChild) -> Self {
        Self { inner }
    }
}

/// A key-free snapshot of one folder for a host UI paint: children, breadcrumb
/// trail, retained dead letters, and the staleness rung.
#[wasm_bindgen]
pub struct SnapshotView {
    inner: facade::SnapshotView,
}

#[wasm_bindgen]
impl SnapshotView {
    /// The 16 raw bytes of the rendered root node id.
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> {
        self.inner.root.0.to_vec()
    }

    /// The 16 raw bytes of the folder this view lists.
    #[wasm_bindgen(getter)]
    pub fn folder(&self) -> Vec<u8> {
        self.inner.folder.0.to_vec()
    }

    /// Direct children, deterministically ordered by node id.
    #[wasm_bindgen(getter)]
    pub fn children(&self) -> Vec<SnapshotChild> {
        self.inner
            .children
            .iter()
            .cloned()
            .map(SnapshotChild::from_facade)
            .collect()
    }

    /// Ancestor trail from the folder's parent up to and including the root,
    /// nearest first.
    #[wasm_bindgen(getter)]
    pub fn ancestors(&self) -> Vec<Breadcrumb> {
        self.inner
            .ancestors
            .iter()
            .cloned()
            .map(Breadcrumb::from_facade)
            .collect()
    }

    /// Every retained dead-lettered op id (`u64`s, crossing as `bigint`s).
    #[wasm_bindgen(getter, js_name = deadLetters)]
    pub fn dead_letters(&self) -> Vec<u64> {
        self.inner.dead_letters.iter().map(|op| op.0).collect()
    }

    /// Durable queue entries this session holds but cannot read — another
    /// identity's, or written by a newer build. A host reports these instead of
    /// leaving an over-budget rejection unexplained on a vault that looks empty.
    #[wasm_bindgen(getter, js_name = retainedRecords)]
    pub fn retained_records(&self) -> usize {
        self.inner.retained_records
    }

    /// The staleness rung at read time.
    #[wasm_bindgen(getter)]
    pub fn staleness(&self) -> Staleness {
        self.inner.staleness.into()
    }
}

impl SnapshotView {
    /// Wraps an engine snapshot view for the boundary. For the engine handle
    /// and the boundary tests; never exported to JS.
    pub fn from_facade(inner: facade::SnapshotView) -> Self {
        Self { inner }
    }
}

// ---------------------------------------------------------------------------
// Commands — the write-intent surface. Built by the host, consumed (later) by
// the engine handle; payload readback is deliberately absent so no user data or
// key material can be read back out through the boundary. Only the stable
// variant `name` is exposed.
// ---------------------------------------------------------------------------

/// One command a host issues to the engine (blueprint/engine.md "Facade").
/// Opaque to JS: constructed through the static builders, then handed to the
/// engine — never destructured.
#[wasm_bindgen]
pub struct Command {
    inner: facade::Command,
}

#[wasm_bindgen]
impl Command {
    /// Create a node under a parent (`content` only for file creates).
    pub fn create(
        parent: &NodeId,
        name: String,
        kind: NodeKind,
        content: Option<Vec<u8>>,
    ) -> Command {
        Self::wrap(facade::Command::Create {
            parent: parent.facade(),
            name,
            kind: kind.into(),
            content: content.map(facade::PlaintextContent),
        })
    }

    /// Delete a node (conditional-delete semantics on rebase).
    pub fn delete(node: &NodeId) -> Command {
        Self::wrap(facade::Command::Delete {
            node: node.facade(),
        })
    }

    /// Rename a node in place.
    pub fn rename(node: &NodeId, new_name: String) -> Command {
        Self::wrap(facade::Command::Rename {
            node: node.facade(),
            new_name,
        })
    }

    /// Move a node to a new parent.
    pub fn relink(node: &NodeId, new_parent: &NodeId) -> Command {
        Self::wrap(facade::Command::Relink {
            node: node.facade(),
            new_parent: new_parent.facade(),
        })
    }

    /// Write new content to a file node.
    #[wasm_bindgen(js_name = updateContent)]
    pub fn update_content(node: &NodeId, content: Vec<u8>) -> Command {
        Self::wrap(facade::Command::UpdateContent {
            node: node.facade(),
            content: facade::PlaintextContent(content),
        })
    }

    /// Set the open folder driving the focus window (`undefined` clears it).
    #[wasm_bindgen(js_name = setFocus)]
    pub fn set_focus(node: Option<NodeId>) -> Command {
        Self::wrap(facade::Command::SetFocus {
            node: node.map(|n| n.facade()),
        })
    }

    /// Manual refresh with nocache semantics everywhere.
    #[wasm_bindgen(js_name = manualRefresh)]
    pub fn manual_refresh() -> Command {
        Self::wrap(facade::Command::ManualRefresh)
    }

    /// Import a self-authenticating contact code (binding-signature verified
    /// in the engine).
    #[wasm_bindgen(js_name = importContact)]
    pub fn import_contact(contact_code: Vec<u8>) -> Command {
        Self::wrap(facade::Command::ImportContact { contact_code })
    }

    /// Grant a node to an imported contact (owner-only).
    pub fn grant(
        node: &NodeId,
        recipient_identity_public_key: Vec<u8>,
        permission: Permission,
    ) -> Command {
        Self::wrap(facade::Command::Grant {
            node: node.facade(),
            recipient_identity_public_key,
            permission: permission.into(),
        })
    }

    /// Revoke a grant (owner-only; read revoke = immediate cut).
    pub fn revoke(node: &NodeId, recipient_identity_public_key: Vec<u8>) -> Command {
        Self::wrap(facade::Command::Revoke {
            node: node.facade(),
            recipient_identity_public_key,
        })
    }

    /// Downgrade a write grant to read (owner-only; triggers write rotation).
    pub fn downgrade(node: &NodeId, recipient_identity_public_key: Vec<u8>) -> Command {
        Self::wrap(facade::Command::Downgrade {
            node: node.facade(),
            recipient_identity_public_key,
        })
    }

    /// Mint an invite link for a node.
    #[wasm_bindgen(js_name = createInviteLink)]
    pub fn create_invite_link(node: &NodeId, permission: Permission) -> Command {
        Self::wrap(facade::Command::CreateInviteLink {
            node: node.facade(),
            permission: permission.into(),
        })
    }

    /// Accept a share from a polled mailbox pointer or claimed invite.
    #[wasm_bindgen(js_name = acceptShare)]
    pub fn accept_share(sealed_share_pointer: Vec<u8>) -> Command {
        Self::wrap(facade::Command::AcceptShare {
            sealed_share_pointer,
        })
    }

    /// Manual hygiene rotate-now for a scope.
    #[wasm_bindgen(js_name = rotateNow)]
    pub fn rotate_now(node: &NodeId) -> Command {
        Self::wrap(facade::Command::RotateNow {
            node: node.facade(),
        })
    }

    /// Exchange a host-collected SIWE wallet signature (secondary method).
    #[wasm_bindgen(js_name = siweLogin)]
    pub fn siwe_login(message: String, signature: Vec<u8>) -> Command {
        Self::wrap(facade::Command::SiweLogin { message, signature })
    }

    /// Log out: zeroize engine state; durable seams survive by design.
    pub fn logout() -> Command {
        Self::wrap(facade::Command::Logout)
    }

    /// The stable command name (matches the builder's JS name), for
    /// diagnostics. Carries no payload.
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }
}

impl Command {
    fn wrap(inner: facade::Command) -> Self {
        Self { inner }
    }

    /// Unwraps to the engine command. For the engine-handle slice and the
    /// boundary tests; never exported to JS.
    pub fn into_facade(self) -> facade::Command {
        self.inner
    }
}

// ---------------------------------------------------------------------------
// Events — the read surface of the one-way event stream. Every getter returns
// key-free view state; a getter is `undefined` for a non-matching variant.
// ---------------------------------------------------------------------------

/// One event the engine emits on the outbound stream (blueprint/engine.md
/// "Facade"). Read `kind`, then the matching payload getter.
#[wasm_bindgen]
pub struct Event {
    inner: facade::Event,
}

#[wasm_bindgen]
impl Event {
    /// The event discriminant, as a stable string literal.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        match self.inner {
            facade::Event::SnapshotUpdated => "snapshotUpdated",
            facade::Event::StalenessChanged { .. } => "stalenessChanged",
            facade::Event::WithheldUpdateEscalation { .. } => "withheldUpdateEscalation",
            facade::Event::DeadLetter { .. } => "deadLetter",
            facade::Event::AttributableAbuse { .. } => "attributableAbuse",
            facade::Event::RenewalFailed { .. } => "renewalFailed",
            facade::Event::OpProgress { .. } => "opProgress",
        }
        .to_string()
    }

    /// `stalenessChanged`: the new level; otherwise `undefined`.
    #[wasm_bindgen(getter)]
    pub fn staleness(&self) -> Option<Staleness> {
        match self.inner {
            facade::Event::StalenessChanged { level } => Some(level.into()),
            _ => None,
        }
    }

    /// `withheldUpdateEscalation`: the pinned IPNS name bytes; otherwise
    /// `undefined`.
    #[wasm_bindgen(getter, js_name = ipnsName)]
    pub fn ipns_name(&self) -> Option<Vec<u8>> {
        match &self.inner {
            facade::Event::WithheldUpdateEscalation { ipns_name } => Some(ipns_name.clone()),
            _ => None,
        }
    }

    /// `deadLetter` or `opProgress`: the op id (a `u64`, crossing as
    /// `bigint`); otherwise (or for an op-less transfer) `undefined`.
    #[wasm_bindgen(getter, js_name = opId)]
    pub fn op_id(&self) -> Option<u64> {
        match self.inner {
            facade::Event::DeadLetter { op_id } => Some(op_id.0),
            facade::Event::OpProgress { op_id, .. } => op_id.map(|op| op.0),
            _ => None,
        }
    }

    /// `opProgress`: the 16 raw bytes of the transferring node's id; otherwise
    /// `undefined`.
    #[wasm_bindgen(getter)]
    pub fn node(&self) -> Option<Vec<u8>> {
        match self.inner {
            facade::Event::OpProgress { node, .. } => Some(node.0.to_vec()),
            _ => None,
        }
    }

    /// `opProgress`: the phase reached; otherwise `undefined`.
    #[wasm_bindgen(getter)]
    pub fn phase(&self) -> Option<OpPhase> {
        match self.inner {
            facade::Event::OpProgress { phase, .. } => Some(phase.into()),
            _ => None,
        }
    }

    /// `opProgress`: the key-free failure classification for a failed phase;
    /// otherwise `undefined`.
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        match &self.inner {
            facade::Event::OpProgress { error, .. } => error.clone(),
            _ => None,
        }
    }

    /// `attributableAbuse`: the key-free classification; otherwise `undefined`.
    #[wasm_bindgen(getter)]
    pub fn description(&self) -> Option<String> {
        match &self.inner {
            facade::Event::AttributableAbuse { description } => Some(description.clone()),
            _ => None,
        }
    }

    /// `renewalFailed`: the failed record's routing key (`ipnsName`); otherwise
    /// `undefined`.
    #[wasm_bindgen(getter, js_name = routingKey)]
    pub fn routing_key(&self) -> Option<String> {
        match &self.inner {
            facade::Event::RenewalFailed { routing_key, .. } => Some(routing_key.clone()),
            _ => None,
        }
    }

    /// `renewalFailed`: the key-free failure classification; otherwise
    /// `undefined`.
    #[wasm_bindgen(getter)]
    pub fn detail(&self) -> Option<String> {
        match &self.inner {
            facade::Event::RenewalFailed { detail, .. } => Some(detail.clone()),
            _ => None,
        }
    }
}

impl Event {
    /// Wraps an engine event for the boundary. For the event-stream reader
    /// slice and the boundary tests; never exported to JS.
    pub fn from_facade(inner: facade::Event) -> Self {
        Self { inner }
    }
}

// ---------------------------------------------------------------------------
// Native-only conversion tests. The browser-shaped boundary behaviour lives in
// `tests/boundary.rs` under wasm-bindgen-test; these host tests guard the
// facade<->binding mapping (a new engine variant breaks an exhaustive match).
//
// Gated off wasm32-unknown-unknown (the exact complement of `boundary.rs`):
// that target has no libtest harness, so a plain `#[test]` there compiles to a
// silent no-op. Native and wasm32-wasip1 run these unchanged.
// ---------------------------------------------------------------------------

#[cfg(all(test, not(all(target_family = "wasm", target_os = "unknown"))))]
mod tests {
    use super::*;
    use cipherbox_engine::seams::OpId;

    // The wrong-length rejection path builds a `JsError`, which only runs on
    // wasm; it is asserted in `tests/boundary.rs`. Here we cover the accepted
    // path and the byte round-trip.
    #[test]
    fn node_id_accepts_16_bytes_and_round_trips() {
        assert!(NodeId::from_bytes(&[0u8; 16]).is_ok());
        assert_eq!(
            NodeId::from_bytes(&[7u8; 16]).unwrap().bytes(),
            vec![7u8; 16]
        );
    }

    #[test]
    fn command_builders_carry_the_stable_name() {
        let node = NodeId::from_bytes(&[0u8; 16]).unwrap();
        assert_eq!(Command::manual_refresh().name(), "manualRefresh");
        assert_eq!(Command::logout().name(), "logout");
        assert_eq!(
            Command::update_content(&node, b"bytes".to_vec()).name(),
            "updateContent"
        );
        assert_eq!(Command::set_focus(None).name(), "setFocus");
        assert_eq!(
            Command::create(&node, "f".into(), NodeKind::Folder, None).name(),
            "create"
        );
    }

    #[test]
    fn command_unwraps_to_the_engine_variant() {
        let node = NodeId::from_bytes(&[1u8; 16]).unwrap();
        let cmd = Command::grant(&node, vec![9, 9, 9], Permission::Write);
        match cmd.into_facade() {
            facade::Command::Grant {
                permission,
                recipient_identity_public_key,
                ..
            } => {
                assert_eq!(permission, facade::Permission::Write);
                assert_eq!(recipient_identity_public_key, vec![9, 9, 9]);
            }
            other => panic!("expected Grant, got {other:?}"),
        }
    }

    #[test]
    fn event_kind_and_payload_getters_map_variants() {
        let snapshot = Event::from_facade(facade::Event::SnapshotUpdated);
        assert_eq!(snapshot.kind(), "snapshotUpdated");
        assert!(snapshot.op_id().is_none());

        let dead = Event::from_facade(facade::Event::DeadLetter { op_id: OpId(42) });
        assert_eq!(dead.kind(), "deadLetter");
        assert_eq!(dead.op_id(), Some(42));

        let stale = Event::from_facade(facade::Event::StalenessChanged {
            level: facade::Staleness::Offline,
        });
        assert_eq!(stale.kind(), "stalenessChanged");
        assert_eq!(stale.staleness(), Some(Staleness::Offline));

        let withheld = Event::from_facade(facade::Event::WithheldUpdateEscalation {
            ipns_name: vec![1, 2, 3],
        });
        assert_eq!(withheld.ipns_name(), Some(vec![1, 2, 3]));

        let progress = Event::from_facade(facade::Event::OpProgress {
            op_id: None,
            node: facade::NodeId([0u8; 16]),
            phase: facade::OpPhase::DownloadStarted,
            error: None,
        });
        assert_eq!(progress.kind(), "opProgress");
    }

    #[test]
    fn op_progress_getters_map_the_payload_and_stay_undefined_off_variant() {
        let progress = Event::from_facade(facade::Event::OpProgress {
            op_id: Some(OpId(7)),
            node: facade::NodeId([3u8; 16]),
            phase: facade::OpPhase::DownloadFailed,
            error: Some("unavailable".into()),
        });
        assert_eq!(progress.op_id(), Some(7));
        assert_eq!(progress.node(), Some(vec![3u8; 16]));
        assert_eq!(progress.phase(), Some(OpPhase::DownloadFailed));
        assert_eq!(progress.error(), Some("unavailable".into()));

        let op_less = Event::from_facade(facade::Event::OpProgress {
            op_id: None,
            node: facade::NodeId([0u8; 16]),
            phase: facade::OpPhase::DownloadStarted,
            error: None,
        });
        assert!(op_less.op_id().is_none());
        assert_eq!(op_less.phase(), Some(OpPhase::DownloadStarted));
        assert!(op_less.error().is_none());

        let other = Event::from_facade(facade::Event::SnapshotUpdated);
        assert!(other.node().is_none());
        assert!(other.phase().is_none());
        assert!(other.error().is_none());
    }

    // Constructs the facade structs literally so a new engine field breaks this
    // test at compile time, mirroring the exhaustive-match guard for enums.
    #[test]
    fn snapshot_view_getters_map_every_field() {
        let view = SnapshotView::from_facade(facade::SnapshotView {
            root: facade::NodeId([1u8; 16]),
            folder: facade::NodeId([2u8; 16]),
            children: vec![
                facade::SnapshotChild {
                    id: facade::NodeId([3u8; 16]),
                    name: "photo.jpg".into(),
                    kind: facade::NodeKind::File,
                    size: Some(1024),
                    mtime: Some(1_700_000_000_000),
                    pending: facade::PendingClass::Content,
                    dead_letter: false,
                    content_version: Some(2),
                },
                facade::SnapshotChild {
                    id: facade::NodeId([4u8; 16]),
                    name: "docs".into(),
                    kind: facade::NodeKind::Folder,
                    size: None,
                    mtime: None,
                    pending: facade::PendingClass::None,
                    dead_letter: true,
                    content_version: None,
                },
            ],
            ancestors: vec![facade::Breadcrumb {
                id: facade::NodeId([1u8; 16]),
                name: String::new(),
            }],
            dead_letters: vec![OpId(9), OpId(11)],
            retained_records: 3,
            staleness: facade::Staleness::Reconciling,
        });

        assert_eq!(view.root(), vec![1u8; 16]);
        assert_eq!(view.folder(), vec![2u8; 16]);
        assert_eq!(view.dead_letters(), vec![9, 11]);
        assert_eq!(view.retained_records(), 3);
        assert_eq!(view.staleness(), Staleness::Reconciling);

        let children = view.children();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].id(), vec![3u8; 16]);
        assert_eq!(children[0].name(), "photo.jpg");
        assert_eq!(children[0].kind(), NodeKind::File);
        assert_eq!(children[0].size(), Some(1024));
        assert_eq!(children[0].mtime(), Some(1_700_000_000_000));
        assert_eq!(children[0].pending(), PendingClass::Content);
        assert!(!children[0].dead_letter());
        assert_eq!(children[0].content_version(), Some(2));
        assert_eq!(children[1].kind(), NodeKind::Folder);
        assert_eq!(children[1].pending(), PendingClass::None);
        assert!(children[1].content_version().is_none());
        assert!(children[1].size().is_none());
        assert!(children[1].mtime().is_none());
        assert!(children[1].dead_letter());

        let ancestors = view.ancestors();
        assert_eq!(ancestors.len(), 1);
        assert_eq!(ancestors[0].id(), vec![1u8; 16]);
        assert_eq!(ancestors[0].name(), "");
    }
}
