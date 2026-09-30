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
//! engine structures. The facade commands, their outcomes and the events cross
//! as the engine's own types, typed by tsify ([`boundary`]). Boundary hygiene is
//! structural: `u64`s cross as `bigint`, binary payloads as `Uint8Array`, and
//! the command surface exposes only intent while the event and read surfaces
//! carry key-free view state and decrypted user content.
//!
//! One secret crosses out, and only because handing it over *is* the feature:
//! an invite link's bearer capability (the `inviteLinkMinted` outcome), which
//! the host puts in a URL fragment and reads nothing out of. It crosses as the
//! fragment text rather than as bytes so the host composes and parses no link
//! material. Residual: a JS string is immutable, so the host cannot scrub the
//! copy it holds — inherent to a capability that has to reach a URL.

// wasm-bindgen's macro-generated glue is unsafe by nature and exempt; this
// forbids only unsafe we would hand-write (there is none).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use cipherbox_engine::content::ByoKind as EngineByoKind;
use cipherbox_engine::facade;
use cipherbox_engine::{PinMode as EnginePinMode, RetentionPolicy};
use wasm_bindgen::prelude::*;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod seams_bridge;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod host;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub mod boundary;

// Test-only: the production artifact never pulls the engine test kit or these
// bindings.
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

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
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
/// A view reads it as this ordinal; a command names it as the string the
/// engine type `Permission` spells, hence the JS name.
#[wasm_bindgen(js_name = ViewPermission)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read grant: read seed only.
    Read,
    /// Write grant: read and write seeds.
    Write,
}

impl From<facade::Permission> for Permission {
    fn from(permission: facade::Permission) -> Self {
        match permission {
            facade::Permission::Read => Permission::Read,
            facade::Permission::Write => Permission::Write,
        }
    }
}

// ---------------------------------------------------------------------------
// Vault settings — the member's placement, provider and retention choice, as
// `EngineHandle.vaultStorage` reads it back. The *credential* is write-only
// across the boundary: [`VaultSettingsSummary`] reports only that one is
// stored, so the provider bearer never crosses back into JS.
// ---------------------------------------------------------------------------

/// Where a version's bytes are pinned. The JS name is as for [`Permission`].
#[wasm_bindgen(js_name = ViewPinMode)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// CipherBox's hosted pin store (the cold-start default).
    Hosted,
    /// The member's own provider only.
    External,
    /// Both legs.
    Dual,
}

impl From<EnginePinMode> for PinMode {
    fn from(mode: EnginePinMode) -> Self {
        match mode {
            EnginePinMode::Hosted => PinMode::Hosted,
            EnginePinMode::External => PinMode::External,
            EnginePinMode::Dual => PinMode::Dual,
        }
    }
}

/// The kind of member-supplied IPFS provider, which fixes the reachability
/// probe. The JS name is as for [`Permission`].
#[wasm_bindgen(js_name = ViewByoKind)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByoKind {
    /// A Kubo RPC endpoint.
    Kubo,
    /// An IPFS Pinning Service API endpoint.
    Psa,
    /// A Pinata endpoint.
    Pinata,
}

impl From<EngineByoKind> for ByoKind {
    fn from(kind: EngineByoKind) -> Self {
        match kind {
            EngineByoKind::Kubo => ByoKind::Kubo,
            EngineByoKind::Psa => ByoKind::Psa,
            EngineByoKind::Pinata => ByoKind::Pinata,
        }
    }
}

/// The staleness ladder (#33 D4): a view is `Fresh`, quietly `Reconciling`,
/// `Stale` past the profile threshold, or `Offline`. Availability staleness,
/// never a trust violation. The JS name is as for [`Permission`].
#[wasm_bindgen(js_name = ViewStaleness)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staleness {
    /// View is within the freshness window.
    Fresh,
    /// A background reconcile is in flight, for at most one refresh deadline.
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

/// Why a queued op dead-lettered. Each reason calls for a different message
/// and a different user action, so the classification crosses with the op
/// rather than being reduced to a flag. The JS name is as for [`Permission`].
#[wasm_bindgen(js_name = ViewDeadLetterReason)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadLetterReason {
    /// The op's target or parent is gone from gate-passing state.
    TargetGone,
    /// A relink destination is gone from gate-passing state.
    DestinationGone,
    /// A relink destination lies inside the moved subtree.
    DestinationInsideTarget,
    /// The folder is saturated with colliding names.
    SuffixExhausted,
    /// The durable op record is corrupt.
    Undecodable,
    /// The network permanently refused the op's own bytes.
    PayloadRefused,
    /// The op's drain attempt budget ran out.
    AttemptsExhausted,
    /// The op's staged content can never publish, and its blocks were released.
    ContentUnrecoverable,
    /// Another writer published a version this edit was not formed against; the
    /// edit's own version stays staged rather than superseding it.
    BaseSuperseded,
    /// Every attempt authored a record over the block ceiling, so the node's
    /// listing has to be split rather than retried.
    HeadTooLarge,
    /// The op was abandoned and its staged version could not be kept: this
    /// device holds a preserved dead-letter record another build wrote.
    PreservationRefused,
    /// The record plane already carries the node this create mints, while
    /// nothing durable on this device remembers publishing it.
    AlreadyPublished,
    /// A purge named a node gate-passing state still reaches through a live
    /// parent, so the bin entry alone did not prove it unlinked.
    TargetStillLinked,
    /// Every attempt authored a shared folder's root record that leaves no room
    /// for the re-key a revoke needs.
    ScopeRootNotResealable,
    /// The owner's bin index holds every entry one record can carry, so the
    /// soft delete could not be recorded.
    BinIndexFull,
    /// An op that would move a node into a scope no pass can seal it into: a
    /// move between two shared folders, or a restore into a folder in a
    /// different shared folder than the one the node was deleted from.
    CrossingUnauthorable,
    /// This device cannot read the account's bin, and its own first attempt to
    /// write one did not finish, so it may not write over it either. Another
    /// device of the account clears this; until one does, a delete here must be
    /// permanent.
    BinIndexStrandedMint,
    /// A delete whose target is also in a folder of a shared folder this
    /// device cannot write in the same pass.
    TargetLinkedAcrossScopes,
    /// An op inside a folder somebody shared with write access needed the
    /// account's own bin or its own reclaim bookkeeping, which the share does
    /// not reach.
    GraftedScopeVaultSurface,
}

impl From<facade::DeadLetterReason> for DeadLetterReason {
    fn from(reason: facade::DeadLetterReason) -> Self {
        match reason {
            facade::DeadLetterReason::TargetGone => DeadLetterReason::TargetGone,
            facade::DeadLetterReason::DestinationGone => DeadLetterReason::DestinationGone,
            facade::DeadLetterReason::DestinationInsideTarget => {
                DeadLetterReason::DestinationInsideTarget
            }
            facade::DeadLetterReason::SuffixExhausted => DeadLetterReason::SuffixExhausted,
            facade::DeadLetterReason::Undecodable => DeadLetterReason::Undecodable,
            facade::DeadLetterReason::PayloadRefused => DeadLetterReason::PayloadRefused,
            facade::DeadLetterReason::AttemptsExhausted => DeadLetterReason::AttemptsExhausted,
            facade::DeadLetterReason::ContentUnrecoverable => {
                DeadLetterReason::ContentUnrecoverable
            }
            facade::DeadLetterReason::BaseSuperseded => DeadLetterReason::BaseSuperseded,
            facade::DeadLetterReason::HeadTooLarge => DeadLetterReason::HeadTooLarge,
            facade::DeadLetterReason::PreservationRefused => DeadLetterReason::PreservationRefused,
            facade::DeadLetterReason::AlreadyPublished => DeadLetterReason::AlreadyPublished,
            facade::DeadLetterReason::TargetStillLinked => DeadLetterReason::TargetStillLinked,
            facade::DeadLetterReason::ScopeRootNotResealable => {
                DeadLetterReason::ScopeRootNotResealable
            }
            facade::DeadLetterReason::BinIndexFull => DeadLetterReason::BinIndexFull,
            facade::DeadLetterReason::CrossingUnauthorable => {
                DeadLetterReason::CrossingUnauthorable
            }
            facade::DeadLetterReason::BinIndexStrandedMint => {
                DeadLetterReason::BinIndexStrandedMint
            }
            facade::DeadLetterReason::TargetLinkedAcrossScopes => {
                DeadLetterReason::TargetLinkedAcrossScopes
            }
            facade::DeadLetterReason::GraftedScopeVaultSurface => {
                DeadLetterReason::GraftedScopeVaultSurface
            }
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

    /// The head version's content root CID, or `undefined` until projected.
    /// A caller hands it back on `beginWrite` to anchor a write where it read.
    #[wasm_bindgen(getter, js_name = contentCid)]
    pub fn content_cid(&self) -> Option<Vec<u8>> {
        self.inner.content_cid.clone()
    }

    /// Invite claims that wait for a conversion at this scope root.
    #[wasm_bindgen(getter, js_name = pendingInviteClaims)]
    pub fn pending_invite_claims(&self) -> u32 {
        self.inner.pending_invite_claims
    }

    /// The node's `ipnsName`, or `undefined` until a read projects one.
    #[wasm_bindgen(getter, js_name = ipnsName)]
    pub fn ipns_name(&self) -> Option<String> {
        self.inner.ipns_name.clone()
    }
}

impl SnapshotChild {
    /// Wraps an engine snapshot child. Never exported to JS.
    pub fn from_facade(inner: facade::SnapshotChild) -> Self {
        Self { inner }
    }
}

/// One prior version of a file, as `fileVersions` lists it.
#[wasm_bindgen]
pub struct VersionEntry {
    inner: facade::VersionEntry,
}

#[wasm_bindgen]
impl VersionEntry {
    /// The version's content root CID — the name every version call takes.
    #[wasm_bindgen(getter, js_name = contentCid)]
    pub fn content_cid(&self) -> Vec<u8> {
        self.inner.content_cid.clone()
    }

    /// The version's plaintext size in bytes, as a `bigint`.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> u64 {
        self.inner.size
    }

    /// When the version was written, Unix millis as a `bigint`.
    #[wasm_bindgen(getter, js_name = modifiedAt)]
    pub fn modified_at(&self) -> u64 {
        self.inner.modified_at
    }
}

impl VersionEntry {
    /// Wraps an engine version entry. Never exported to JS.
    pub fn from_facade(inner: facade::VersionEntry) -> Self {
        Self { inner }
    }
}

/// One retained dead-lettered op and why it dead-lettered.
#[wasm_bindgen]
pub struct DeadLetter {
    inner: facade::DeadLetter,
}

#[wasm_bindgen]
impl DeadLetter {
    /// The dead-lettered op id (a `u64`, crossing as a `bigint`).
    #[wasm_bindgen(getter, js_name = opId)]
    pub fn op_id(&self) -> u64 {
        self.inner.op_id.0
    }

    /// Why it dead-lettered.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> DeadLetterReason {
        self.inner.reason.into()
    }
}

/// The queue head held over rather than failed, keeping its place and its
/// staging reservation until its reason's own exit comes.
#[wasm_bindgen]
pub struct QueueHold {
    inner: facade::QueueHold,
}

#[wasm_bindgen]
impl QueueHold {
    /// The held op id (a `u64`, crossing as a `bigint`).
    #[wasm_bindgen(getter, js_name = opId)]
    pub fn op_id(&self) -> u64 {
        self.inner.op_id.0
    }

    /// The 16 raw bytes of the node the held op targets.
    #[wasm_bindgen(getter)]
    pub fn node(&self) -> Vec<u8> {
        self.inner.node.0.to_vec()
    }

    /// What the hold waits on: `quota`, `settings` or `bin-index`.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> String {
        self.inner.reason.name().to_owned()
    }

    /// The byte count the resume probe must find room for, on a quota hold and
    /// nowhere else.
    #[wasm_bindgen(getter, js_name = neededBytes)]
    pub fn needed_bytes(&self) -> Option<u64> {
        match self.inner.reason {
            facade::QueueHoldReason::Quota { needed_bytes } => Some(needed_bytes),
            _ => None,
        }
    }

    /// The stable check name of what refused, on a settings or a bin index hold.
    /// Never the endpoint or the bearer the settings carry.
    #[wasm_bindgen(getter)]
    pub fn check(&self) -> Option<String> {
        match self.inner.reason {
            facade::QueueHoldReason::Quota { .. } => None,
            facade::QueueHoldReason::Settings(refusal) => Some(refusal.check().to_owned()),
            facade::QueueHoldReason::BinIndex(reason) => Some(reason.check().to_owned()),
        }
    }
}

/// A freshly opened read stream and the plaintext size of the version it
/// pinned (`Engine::stream_size`).
#[wasm_bindgen]
pub struct OpenedStream {
    handle: u64,
    size: f64,
}

#[wasm_bindgen]
impl OpenedStream {
    /// The handle every window of this stream is read against.
    #[wasm_bindgen(getter)]
    pub fn handle(&self) -> u64 {
        self.handle
    }

    /// The pinned version's plaintext size in bytes. A JS number, not a
    /// `bigint`, so it pairs with the whole-number offsets `readStream` takes.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> f64 {
        self.size
    }
}

impl OpenedStream {
    /// Pairs a minted handle with its pinned version's size.
    pub fn new(handle: u64, size: f64) -> Self {
        Self { handle, size }
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

    /// The listed folder's own name, empty at the root.
    #[wasm_bindgen(getter, js_name = folderName)]
    pub fn folder_name(&self) -> String {
        self.inner.folder_name.clone()
    }

    /// What this vault may do now in the scope the listed folder belongs to.
    #[wasm_bindgen(getter)]
    pub fn permission(&self) -> Permission {
        self.inner.permission.into()
    }

    /// Whether the listed folder stands in a scope another vault granted this
    /// one. A write there stays inside that scope.
    #[wasm_bindgen(getter, js_name = receivedShare)]
    pub fn received_share(&self) -> bool {
        self.inner.received_share
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

    /// Every retained dead-lettered op, with the reason it will never publish.
    #[wasm_bindgen(getter, js_name = deadLetters)]
    pub fn dead_letters(&self) -> Vec<DeadLetter> {
        self.inner
            .dead_letters
            .iter()
            .map(|dead| DeadLetter { inner: *dead })
            .collect()
    }

    /// The drain's held queue head, or `undefined`.
    #[wasm_bindgen(getter, js_name = queueHold)]
    pub fn queue_hold(&self) -> Option<QueueHold> {
        self.inner.queue_hold.map(|inner| QueueHold { inner })
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

/// One imported contact in a [`SharingView`].
#[wasm_bindgen]
pub struct SharingContact {
    inner: facade::SharingContact,
}

#[wasm_bindgen]
impl SharingContact {
    /// The peer's secp256k1 identity key, compressed SEC1 — the grant ledger's
    /// recipient label.
    #[wasm_bindgen(getter, js_name = identityPublicKey)]
    pub fn identity_public_key(&self) -> Vec<u8> {
        self.inner.identity_public_key.clone()
    }

    /// The last grantee name this device saw for the peer; a pre-fill, not an
    /// authority.
    #[wasm_bindgen(getter, js_name = cachedName)]
    pub fn cached_name(&self) -> Option<String> {
        self.inner.cached_name.clone()
    }
}

impl SharingContact {
    /// Wraps an engine sharing contact. Never exported to JS.
    pub fn from_facade(inner: facade::SharingContact) -> Self {
        Self { inner }
    }
}

/// One grant standing on the scope a [`SharingView`] reads.
#[wasm_bindgen]
pub struct SharingGrant {
    inner: facade::SharingGrant,
}

#[wasm_bindgen]
impl SharingGrant {
    /// The recipient's secp256k1 identity key, which joins the row to a
    /// [`SharingContact`].
    #[wasm_bindgen(getter, js_name = recipientIdentityPublicKey)]
    pub fn recipient_identity_public_key(&self) -> Vec<u8> {
        self.inner.recipient_identity_public_key.clone()
    }

    /// The permission the scope root commits for this recipient.
    #[wasm_bindgen(getter)]
    pub fn permission(&self) -> Permission {
        self.inner.permission.into()
    }

    /// The grantee name on the owner-attested row.
    #[wasm_bindgen(getter, js_name = granteeName)]
    pub fn grantee_name(&self) -> Option<GranteeName> {
        self.inner
            .grantee_name
            .as_ref()
            .map(|(name, source)| GranteeName {
                name: name.clone(),
                source: source.as_wire(),
            })
    }

    /// The tag of the link that admitted this grantee, which matches a
    /// [`SharingInviteLink`]'s `tag`.
    #[wasm_bindgen(getter, js_name = viaLink)]
    pub fn via_link(&self) -> Option<Vec<u8>> {
        self.inner.via_link.clone()
    }
}

/// A grantee name and who chose it, which cross as one value so neither
/// reaches JS without the other.
#[wasm_bindgen]
pub struct GranteeName {
    name: String,
    source: &'static str,
}

#[wasm_bindgen]
impl GranteeName {
    /// The name.
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// Who chose the name: `"owner"` or `"claimant"`.
    #[wasm_bindgen(getter)]
    pub fn source(&self) -> String {
        self.source.to_owned()
    }
}

impl SharingGrant {
    /// Wraps an engine sharing grant. Never exported to JS.
    pub fn from_facade(inner: facade::SharingGrant) -> Self {
        Self { inner }
    }
}

/// One invite link this owner's commitment carries on the scope a
/// [`SharingView`] reads.
#[wasm_bindgen]
pub struct SharingInviteLink {
    inner: facade::SharingInviteLink,
}

#[wasm_bindgen]
impl SharingInviteLink {
    /// The link entry's blinded tag, which a revoke names to cut this link.
    #[wasm_bindgen(getter)]
    pub fn tag(&self) -> Vec<u8> {
        self.inner.tag.clone()
    }

    /// The permission conversion grants a claimant of this link.
    #[wasm_bindgen(getter)]
    pub fn permission(&self) -> Permission {
        self.inner.permission.into()
    }

    /// The link's deadline in Unix millis (a `u64`, crossing as a `bigint`).
    #[wasm_bindgen(getter, js_name = expiresAt)]
    pub fn expires_at(&self) -> u64 {
        self.inner.expires_at.0
    }

    /// Whether the deadline has passed, decided on the engine's clock so a
    /// host never compares the deadline against its own.
    #[wasm_bindgen(getter)]
    pub fn expired(&self) -> bool {
        self.inner.expired
    }

    /// The link's owner-signed admission cap (a `u64`, crossing as a `bigint`).
    #[wasm_bindgen(getter, js_name = admissionCap)]
    pub fn admission_cap(&self) -> u64 {
        self.inner.admission_cap
    }

    /// Invite claims this link signed that wait for a conversion.
    #[wasm_bindgen(getter, js_name = pendingClaims)]
    pub fn pending_claims(&self) -> u32 {
        self.inner.pending_claims
    }

    /// The contacts this link sourced hold its whole share of the contact
    /// book, so its claims do not convert until the owner revokes it.
    #[wasm_bindgen(getter, js_name = contactBudgetFull)]
    pub fn contact_budget_full(&self) -> bool {
        self.inner.contact_budget_full
    }

    /// Invite claims this link refused at a cap: its admission cap or the
    /// grant set was full.
    #[wasm_bindgen(getter, js_name = refusedClaims)]
    pub fn refused_claims(&self) -> u32 {
        self.inner.refused_claims
    }
}

impl SharingInviteLink {
    /// Wraps an engine invite link. Never exported to JS.
    pub fn from_facade(inner: facade::SharingInviteLink) -> Self {
        Self { inner }
    }
}

/// What one scope's own record says about sharing, when the read reached it.
#[wasm_bindgen]
pub struct ScopeSharing {
    inner: facade::ScopeSharing,
}

#[wasm_bindgen]
impl ScopeSharing {
    /// The grants the scope root's ledger commits, ordered as it commits them.
    #[wasm_bindgen(getter)]
    pub fn grants(&self) -> Vec<SharingGrant> {
        self.inner
            .grants
            .iter()
            .cloned()
            .map(SharingGrant::from_facade)
            .collect()
    }

    /// The refusal a contact grant at this scope would report, or `undefined`
    /// where one would be accepted.
    #[wasm_bindgen(getter, js_name = grantRefusal)]
    pub fn grant_refusal(&self) -> Option<String> {
        self.inner.grant_refusal.map(str::to_owned)
    }

    /// The refusal an invite-link mint at this scope would report, or
    /// `undefined` where one would be accepted.
    #[wasm_bindgen(getter, js_name = inviteLinkRefusal)]
    pub fn invite_link_refusal(&self) -> Option<String> {
        self.inner.invite_link_refusal.map(str::to_owned)
    }

    /// Every invite link this owner's commitment carries at the scope, in
    /// commitment order and expired ones included.
    #[wasm_bindgen(getter, js_name = inviteLinks)]
    pub fn invite_links(&self) -> Vec<SharingInviteLink> {
        self.inner
            .invite_links
            .iter()
            .cloned()
            .map(SharingInviteLink::from_facade)
            .collect()
    }

    /// The read epoch of the scope root's published record, or `undefined` for
    /// a node that is not a scope root.
    #[wasm_bindgen(getter, js_name = readEpoch)]
    pub fn read_epoch(&self) -> Option<u64> {
        self.inner.epochs.map(|epochs| epochs.read_epoch)
    }

    /// The write epoch of the scope root's published record, or `undefined`
    /// for a node that is not a scope root.
    #[wasm_bindgen(getter, js_name = writeEpoch)]
    pub fn write_epoch(&self) -> Option<u64> {
        self.inner.epochs.map(|epochs| epochs.write_epoch)
    }
}

impl ScopeSharing {
    /// Wraps an engine scope sharing state. Never exported to JS.
    pub fn from_facade(inner: facade::ScopeSharing) -> Self {
        Self { inner }
    }
}

/// A key-free read of one scope's sharing state: this vault's whole verified
/// contact book, this member's own contact code, and the grants the scope's own
/// record commits.
#[wasm_bindgen]
pub struct SharingView {
    inner: facade::SharingView,
}

#[wasm_bindgen]
impl SharingView {
    /// The 16 raw bytes of the scope root this read is for.
    #[wasm_bindgen(getter)]
    pub fn scope(&self) -> Vec<u8> {
        self.inner.scope.0.to_vec()
    }

    /// Every contact this vault has imported, ordered as the book stores them.
    #[wasm_bindgen(getter)]
    pub fn contacts(&self) -> Vec<SharingContact> {
        self.inner
            .contacts
            .iter()
            .cloned()
            .map(SharingContact::from_facade)
            .collect()
    }

    /// This member's own contact code, for a peer to import. Public material
    /// only.
    #[wasm_bindgen(getter, js_name = ownContactCode)]
    pub fn own_contact_code(&self) -> Vec<u8> {
        self.inner.own_contact_code.clone()
    }

    /// What the scope's own record says about sharing, or `undefined` when the
    /// read could not reach the scope root — the distinction the facade
    /// `SharingView` draws.
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Option<ScopeSharing> {
        self.inner.state.clone().map(ScopeSharing::from_facade)
    }
}

impl SharingView {
    /// Wraps an engine sharing view for the boundary. For the engine handle and
    /// the boundary tests; never exported to JS.
    pub fn from_facade(inner: facade::SharingView) -> Self {
        Self { inner }
    }
}

/// One share this vault accepted, as `/shared` renders it: the accepted
/// bookmark's key-free fields plus the engine's own resolution verdict.
#[wasm_bindgen]
pub struct ReceivedShareRow {
    inner: facade::ReceivedShareRow,
}

#[wasm_bindgen]
impl ReceivedShareRow {
    /// The 16 raw bytes of the shared scope — this row's stable identity, and
    /// the handle a browse opens it under.
    #[wasm_bindgen(getter)]
    pub fn scope(&self) -> Vec<u8> {
        self.inner.scope.0.to_vec()
    }

    /// The sharer's secp256k1 identity key, which joins the row to a
    /// [`SharingContact`].
    #[wasm_bindgen(getter, js_name = sharerIdentityPublicKey)]
    pub fn sharer_identity_public_key(&self) -> Vec<u8> {
        self.inner.sharer_identity_public_key.clone()
    }

    /// The display label the share was accepted under.
    #[wasm_bindgen(getter, js_name = displayName)]
    pub fn display_name(&self) -> String {
        self.inner.display_name.clone()
    }

    /// The permission the owner-signed commitment granted at accept.
    #[wasm_bindgen(getter)]
    pub fn permission(&self) -> Permission {
        self.inner.permission.into()
    }

    /// The engine's classification of this share's latest resolve — one of
    /// `granted`, `revocation-signal`, `expired`, `unresolvable`, `epoch-lag` —
    /// or `undefined` when no pass has resolved it yet. A host renders the
    /// engine's verdict; it never computes one.
    #[wasm_bindgen(getter)]
    pub fn resolution(&self) -> Option<String> {
        self.inner.resolution.map(|class| class.name().to_owned())
    }

    /// Whether the share still reads through the link it was joined by.
    #[wasm_bindgen(getter, js_name = viaLink)]
    pub fn via_link(&self) -> bool {
        self.inner.via_link
    }
}

impl ReceivedShareRow {
    /// Wraps an engine received-share row. Never exported to JS.
    pub fn from_facade(inner: facade::ReceivedShareRow) -> Self {
        Self { inner }
    }
}

/// One direct child of a previewed folder: a name and a kind.
#[wasm_bindgen]
pub struct PreviewEntry {
    inner: facade::PreviewEntry,
}

#[wasm_bindgen]
impl PreviewEntry {
    /// The child's name.
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    /// The child's kind.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> NodeKind {
        self.inner.kind.into()
    }
}

/// What the invite page shows before the join (ADR 0028 D2, D5).
#[wasm_bindgen]
pub struct InvitePreview {
    inner: facade::InvitePreview,
}

#[wasm_bindgen]
impl InvitePreview {
    /// The 16 raw bytes of the folder the join bookmarks.
    #[wasm_bindgen(getter)]
    pub fn scope(&self) -> Vec<u8> {
        self.inner.scope.0.to_vec()
    }

    /// The owner's name, or `undefined` when the owner signature over the
    /// names does not verify.
    #[wasm_bindgen(getter, js_name = ownerName)]
    pub fn owner_name(&self) -> Option<String> {
        self.inner.names.as_ref().map(|n| n.owner_name.clone())
    }

    /// The folder's name, present exactly when [`Self::owner_name`] is.
    #[wasm_bindgen(getter, js_name = folderName)]
    pub fn folder_name(&self) -> Option<String> {
        self.inner.names.as_ref().map(|n| n.folder_name.clone())
    }

    /// The permission conversion grants, or `undefined` when the preview read
    /// no link entry.
    #[wasm_bindgen(getter)]
    pub fn permission(&self) -> Option<Permission> {
        self.inner.permission.map(Permission::from)
    }

    /// One of `live`, `expired`, `revoked`, `unresolvable`.
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> String {
        self.inner.state.name().to_owned()
    }

    /// Whether this account already joined the folder.
    #[wasm_bindgen(getter)]
    pub fn joined(&self) -> bool {
        self.inner.joined
    }

    /// The scope root's direct children, in the order its body holds them.
    #[wasm_bindgen(getter)]
    pub fn listing(&self) -> Vec<PreviewEntry> {
        self.inner
            .listing
            .iter()
            .cloned()
            .map(|inner| PreviewEntry { inner })
            .collect()
    }
}

impl InvitePreview {
    /// Wraps an engine invite preview. Never exported to JS.
    pub fn from_facade(inner: facade::InvitePreview) -> Self {
        Self { inner }
    }
}

/// The `/bin` route's whole read: the owner's soft-deleted nodes, and which
/// rung the bin index load reached.
#[wasm_bindgen]
pub struct BinView {
    inner: facade::BinView,
}

#[wasm_bindgen]
impl BinView {
    /// One row per soft-deleted node.
    #[wasm_bindgen(getter)]
    pub fn entries(&self) -> Vec<BinRow> {
        self.inner
            .entries
            .iter()
            .cloned()
            .map(BinRow::from_facade)
            .collect()
    }

    /// Which rung the bin index load reached.
    #[wasm_bindgen(getter)]
    pub fn origin(&self) -> SettingsOrigin {
        self.inner.origin.into()
    }
}

impl BinView {
    /// Wraps an engine bin view. Never exported to JS.
    pub fn from_facade(inner: facade::BinView) -> Self {
        Self { inner }
    }
}

/// Where a bin row's origin folder stands in the vault (mirrors the facade
/// `BinOrigin`).
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOriginKind {
    /// The vault root, which carries no name of its own.
    Root,
    /// A folder the vault still holds.
    Folder,
    /// No folder of that id stands in the vault, so a default restore refuses.
    Gone,
}

/// One soft-deleted node, as the `/bin` route renders it. Key-free by
/// construction: the entry's bin-held key and its `ipnsName` have no getter.
#[wasm_bindgen]
pub struct BinRow {
    inner: facade::BinRow,
}

#[wasm_bindgen]
impl BinRow {
    /// The 16 raw bytes of the soft-deleted node, which a `restore` or a
    /// `purge` command names.
    #[wasm_bindgen(getter)]
    pub fn node(&self) -> Vec<u8> {
        self.inner.node.0.to_vec()
    }

    /// The node's immutable kind.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> NodeKind {
        self.inner.kind.into()
    }

    /// The 16 raw bytes of the folder the node was unlinked from — where a
    /// restore puts it back when the host names no other destination.
    #[wasm_bindgen(getter, js_name = originParent)]
    pub fn origin_parent(&self) -> Vec<u8> {
        self.inner.origin_parent.0.to_vec()
    }

    /// The name the node carried in that folder.
    #[wasm_bindgen(getter, js_name = originName)]
    pub fn origin_name(&self) -> String {
        self.inner.origin_name.clone()
    }

    /// Where the origin folder stands in the vault this session renders.
    #[wasm_bindgen(getter, js_name = originFolderKind)]
    pub fn origin_folder_kind(&self) -> BinOriginKind {
        match self.inner.origin_folder {
            facade::BinOrigin::Root => BinOriginKind::Root,
            facade::BinOrigin::Folder(_) => BinOriginKind::Folder,
            facade::BinOrigin::Gone => BinOriginKind::Gone,
        }
    }

    /// The origin folder's own name, empty for every kind but
    /// [`BinOriginKind::Folder`] — the root carries none and a gone folder
    /// leaves none to read.
    #[wasm_bindgen(getter, js_name = originFolderName)]
    pub fn origin_folder_name(&self) -> String {
        match &self.inner.origin_folder {
            facade::BinOrigin::Folder(name) => name.clone(),
            _ => String::new(),
        }
    }

    /// The deletion time in milliseconds, a `u64` crossing as a `bigint`. A
    /// host renders expiry from this and `binRetentionDays`.
    #[wasm_bindgen(getter, js_name = deletedAt)]
    pub fn deleted_at(&self) -> u64 {
        self.inner.deleted_at
    }

    /// The 16 raw bytes of the scope the node belonged to at the delete.
    #[wasm_bindgen(getter)]
    pub fn scope(&self) -> Vec<u8> {
        self.inner.scope.0.to_vec()
    }
}

impl BinRow {
    /// Wraps an engine bin row. Never exported to JS.
    pub fn from_facade(inner: facade::BinRow) -> Self {
        Self { inner }
    }
}

// ---------------------------------------------------------------------------
// The storage pane's read surface, and the account's login methods.
// ---------------------------------------------------------------------------

/// Whose choice a [`VaultSettingsSummary`] reports.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsOrigin {
    /// The published record opened and validated.
    Resolved,
    /// This device's last-known-good copy: still the member's choice.
    Stale,
    /// Nothing here is the member's choice, only the documented defaults.
    Defaults,
}

impl From<cipherbox_engine::SettingsOrigin> for SettingsOrigin {
    fn from(origin: cipherbox_engine::SettingsOrigin) -> Self {
        match origin {
            cipherbox_engine::SettingsOrigin::Resolved => SettingsOrigin::Resolved,
            cipherbox_engine::SettingsOrigin::Stale => SettingsOrigin::Stale,
            cipherbox_engine::SettingsOrigin::Defaults => SettingsOrigin::Defaults,
        }
    }
}

/// The member's settings as a host may see them. The provider bearer is absent
/// by construction, not withheld by these getters.
#[wasm_bindgen]
pub struct VaultSettingsSummary {
    inner: cipherbox_engine::VaultSettingsSummary,
}

#[wasm_bindgen]
impl VaultSettingsSummary {
    /// Where a version's bytes are pinned.
    #[wasm_bindgen(getter, js_name = pinMode)]
    pub fn pin_mode(&self) -> PinMode {
        self.inner.pin_mode.into()
    }

    /// The member's own provider endpoint, or `undefined`.
    #[wasm_bindgen(getter, js_name = byoEndpoint)]
    pub fn byo_endpoint(&self) -> Option<String> {
        self.inner.byo_endpoint.clone()
    }

    /// That provider's kind, or `undefined`.
    #[wasm_bindgen(getter, js_name = byoKind)]
    pub fn byo_kind(&self) -> Option<ByoKind> {
        self.inner.byo_kind.map(ByoKind::from)
    }

    /// Whether a provider bearer is stored. The bearer itself never crosses.
    #[wasm_bindgen(getter, js_name = byoCredentialStored)]
    pub fn byo_credential_stored(&self) -> bool {
        self.inner.byo_credential_stored
    }

    /// How many versions are kept, or `undefined` to keep every version.
    ///
    /// A bound wider than this host can represent saturates rather than
    /// reading as `undefined`: a bound must never widen to no bound at all.
    #[wasm_bindgen(getter, js_name = keepLatestVersions)]
    pub fn keep_latest_versions(&self) -> Option<u32> {
        match self.inner.retention {
            RetentionPolicy::KeepAll => None,
            RetentionPolicy::KeepLatest(n) => Some(u32::try_from(n.get()).unwrap_or(u32::MAX)),
        }
    }

    /// How long a soft-deleted node stays in the bin. `0` keeps the hard delete.
    #[wasm_bindgen(getter, js_name = binRetentionDays)]
    pub fn bin_retention_days(&self) -> u32 {
        self.inner.bin_retention_days
    }

    /// Whose choice this summary reports.
    #[wasm_bindgen(getter)]
    pub fn origin(&self) -> SettingsOrigin {
        self.inner.origin.into()
    }
}

impl VaultSettingsSummary {
    /// Wraps an engine settings summary. Never exported to JS.
    pub fn from_facade(inner: cipherbox_engine::VaultSettingsSummary) -> Self {
        Self { inner }
    }
}

/// The account quota as the storage pane renders it.
#[wasm_bindgen]
pub struct QuotaView {
    inner: facade::QuotaView,
}

#[wasm_bindgen]
impl QuotaView {
    /// Bytes counted against the account (a `u64`, crossing as a `bigint`).
    #[wasm_bindgen(getter, js_name = usedBytes)]
    pub fn used_bytes(&self) -> u64 {
        self.inner.used_bytes
    }

    /// The account's limit (a `u64`, crossing as a `bigint`).
    #[wasm_bindgen(getter, js_name = limitBytes)]
    pub fn limit_bytes(&self) -> u64 {
        self.inner.limit_bytes
    }

    /// Whether the figure is a hint rather than a ceiling.
    #[wasm_bindgen(getter)]
    pub fn advisory(&self) -> bool {
        self.inner.advisory
    }
}

/// Why a reclaim debt did not settle.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimStallReason {
    /// The owing node's published record, or a version it names, could not be
    /// established this pass.
    NodeUnreadable,
    /// The node's published record still names this doomed root.
    TargetStillLive,
    /// The doomed root itself could not be expanded.
    TargetUnexpandable,
}

impl From<cipherbox_engine::ReclaimStallReason> for ReclaimStallReason {
    fn from(reason: cipherbox_engine::ReclaimStallReason) -> Self {
        match reason {
            cipherbox_engine::ReclaimStallReason::NodeUnreadable => {
                ReclaimStallReason::NodeUnreadable
            }
            cipherbox_engine::ReclaimStallReason::TargetStillLive => {
                ReclaimStallReason::TargetStillLive
            }
            cipherbox_engine::ReclaimStallReason::TargetUnexpandable => {
                ReclaimStallReason::TargetUnexpandable
            }
        }
    }
}

/// A debt the reclaim pass left owed, and why. A stalled debt prices at
/// nothing, so the byte figure alone cannot tell one from a drained ledger.
#[wasm_bindgen]
pub struct ReclaimStall {
    inner: cipherbox_engine::ReclaimStall,
}

#[wasm_bindgen]
impl ReclaimStall {
    /// The 16 raw bytes of the node owing the debt.
    #[wasm_bindgen(getter)]
    pub fn node(&self) -> Vec<u8> {
        self.inner.node.to_vec()
    }

    /// The doomed version's root `contentCid`.
    #[wasm_bindgen(getter)]
    pub fn target(&self) -> String {
        self.inner.target.clone()
    }

    /// What stopped it.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> ReclaimStallReason {
        self.inner.reason.into()
    }
}

/// The storage pane's whole read (`facade::VaultStorageView`).
#[wasm_bindgen]
pub struct VaultStorageView {
    inner: facade::VaultStorageView,
}

#[wasm_bindgen]
impl VaultStorageView {
    /// The settings this session loaded, redacted.
    #[wasm_bindgen(getter)]
    pub fn settings(&self) -> VaultSettingsSummary {
        VaultSettingsSummary::from_facade(self.inner.settings.clone())
    }

    /// The account quota, or `undefined` when the probe did not answer.
    #[wasm_bindgen(getter)]
    pub fn quota(&self) -> Option<QuotaView> {
        self.inner.quota.map(|inner| QuotaView { inner })
    }

    /// Pinned bytes a published prune still owes the registry (a `u64`,
    /// crossing as a `bigint`).
    #[wasm_bindgen(getter, js_name = pendingReclaimBytes)]
    pub fn pending_reclaim_bytes(&self) -> u64 {
        self.inner.pending_reclaim_bytes
    }

    /// Whether that figure is a floor on the debt rather than its total: the
    /// last reclaim pass read a bounded window of the retire ledger.
    #[wasm_bindgen(getter, js_name = pendingReclaimIsPartial)]
    pub fn pending_reclaim_is_partial(&self) -> bool {
        self.inner.pending_reclaim_is_partial
    }

    /// Debts the last reclaim pass could not settle.
    #[wasm_bindgen(getter, js_name = reclaimStalls)]
    pub fn reclaim_stalls(&self) -> Vec<ReclaimStall> {
        self.inner
            .reclaim_stalls
            .iter()
            .cloned()
            .map(|inner| ReclaimStall { inner })
            .collect()
    }
}

impl VaultStorageView {
    /// Wraps an engine storage view. Never exported to JS.
    pub fn from_facade(inner: facade::VaultStorageView) -> Self {
        Self { inner }
    }
}

/// Which login surface an [`AuthMethod`] admits.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethodKind {
    /// The account identity key.
    Identity,
    /// A linked SIWE wallet.
    Wallet,
    /// The staging-gated test login.
    Test,
    /// A kind this build does not know, rendered as-is.
    Unknown,
}

impl From<cipherbox_engine::AuthMethodKind> for AuthMethodKind {
    fn from(kind: cipherbox_engine::AuthMethodKind) -> Self {
        match kind {
            cipherbox_engine::AuthMethodKind::Identity => AuthMethodKind::Identity,
            cipherbox_engine::AuthMethodKind::Wallet => AuthMethodKind::Wallet,
            cipherbox_engine::AuthMethodKind::Test => AuthMethodKind::Test,
            cipherbox_engine::AuthMethodKind::Unknown => AuthMethodKind::Unknown,
        }
    }
}
/// One login method on the account. Display form only: the identifier hash
/// never crosses.
#[wasm_bindgen]
pub struct AuthMethod {
    inner: cipherbox_engine::AuthMethod,
}

#[wasm_bindgen]
impl AuthMethod {
    /// The row id an `unlinkAuthMethod` command names.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    /// Which login surface this row admits.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> AuthMethodKind {
        self.inner.kind.into()
    }

    /// A truncated, human-readable form of the identifier, or `undefined`.
    #[wasm_bindgen(getter, js_name = identifierDisplay)]
    pub fn identifier_display(&self) -> Option<String> {
        self.inner.identifier_display.clone()
    }

    /// When the row was created, ISO 8601.
    #[wasm_bindgen(getter, js_name = createdAt)]
    pub fn created_at(&self) -> String {
        self.inner.created_at.clone()
    }

    /// When the row last logged in, ISO 8601, or `undefined`.
    #[wasm_bindgen(getter, js_name = lastUsedAt)]
    pub fn last_used_at(&self) -> Option<String> {
        self.inner.last_used_at.clone()
    }
}

impl AuthMethod {
    /// Wraps an engine login-method row. Never exported to JS.
    pub fn from_facade(inner: cipherbox_engine::AuthMethod) -> Self {
        Self { inner }
    }
}

/// One device identity key on the account registry (ADR 0009 D4). The label is
/// context the device chose, never evidence: only the key is proved.
#[wasm_bindgen]
pub struct RegisteredDevice {
    inner: cipherbox_engine::RegisteredDevice,
}

#[wasm_bindgen]
impl RegisteredDevice {
    /// The row id a `revokeDevice` command names.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    /// The raw Ed25519 device identity public key, lowercase hex.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> String {
        self.inner.public_key.clone()
    }

    /// The display label the device offered, or `undefined`.
    #[wasm_bindgen(getter)]
    pub fn label(&self) -> Option<String> {
        self.inner.label.clone()
    }

    /// When the key was registered, ISO 8601.
    #[wasm_bindgen(getter, js_name = createdAt)]
    pub fn created_at(&self) -> String {
        self.inner.created_at.clone()
    }

    /// When the key was last seen, ISO 8601.
    #[wasm_bindgen(getter, js_name = lastSeenAt)]
    pub fn last_seen_at(&self) -> String {
        self.inner.last_seen_at.clone()
    }
}

impl RegisteredDevice {
    /// Wraps an engine device-registry row. Never exported to JS.
    pub fn from_facade(inner: cipherbox_engine::RegisteredDevice) -> Self {
        Self { inner }
    }
}

/// One rendezvous this account is asked to approve; see
/// [`cipherbox_engine::PendingApprovalView`] for what a row here guarantees.
#[wasm_bindgen]
pub struct PendingApproval {
    inner: cipherbox_engine::PendingApprovalView,
}

#[wasm_bindgen]
impl PendingApproval {
    /// The rendezvous id.
    #[wasm_bindgen(getter, js_name = requestId)]
    pub fn request_id(&self) -> String {
        self.inner.request_id.clone()
    }

    /// The requesting device identity public key, lowercase hex.
    #[wasm_bindgen(getter, js_name = requesterDevicePublicKey)]
    pub fn requester_device_public_key(&self) -> String {
        self.inner.requester_device_public_key.clone()
    }

    /// The compressed secp256k1 key a factor must be sealed to.
    #[wasm_bindgen(getter, js_name = ephemeralPublicKey)]
    pub fn ephemeral_public_key(&self) -> String {
        self.inner.ephemeral_public_key.clone()
    }

    /// The digits both screens must show before an approval is possible.
    #[wasm_bindgen(getter, js_name = comparisonValue)]
    pub fn comparison_value(&self) -> String {
        self.inner.comparison_value.clone()
    }

    /// When the rendezvous opened, ISO 8601.
    #[wasm_bindgen(getter, js_name = createdAt)]
    pub fn created_at(&self) -> String {
        self.inner.created_at.clone()
    }

    /// When the row is gone, ISO 8601.
    #[wasm_bindgen(getter, js_name = expiresAt)]
    pub fn expires_at(&self) -> String {
        self.inner.expires_at.clone()
    }
}

impl PendingApproval {
    /// Wraps an engine pending-approval row. Never exported to JS.
    pub fn from_facade(inner: cipherbox_engine::PendingApprovalView) -> Self {
        Self { inner }
    }
}

/// The short fingerprint of a 33-byte compressed identity key, the value both
/// hosts show beside a grantee name (ADR 0027 D7). Throws on bytes that are
/// not an identity key.
#[wasm_bindgen(js_name = identityFingerprint)]
pub fn identity_fingerprint(identity_public_key: &[u8]) -> Result<String, JsError> {
    cipherbox_engine::fingerprint_identity_key(identity_public_key)
        .ok_or_else(|| JsError::new("invalid identity public key"))
}

/// A signed IPNS record's sequence and EOL, verified under the name it was
/// fetched for.
#[cfg(feature = "observer")]
#[wasm_bindgen]
pub struct IpnsRecordReading {
    inner: cipherbox_engine::net::eol::RecordReading,
}

#[cfg(feature = "observer")]
#[wasm_bindgen]
impl IpnsRecordReading {
    /// The record sequence number.
    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> u64 {
        self.inner.sequence
    }

    /// The signed RFC3339 EOL text.
    #[wasm_bindgen(getter)]
    pub fn validity(&self) -> String {
        self.inner.validity.clone()
    }

    /// The EOL as Unix millis, or `undefined` where the text does not parse.
    #[wasm_bindgen(getter, js_name = validUntil)]
    pub fn valid_until(&self) -> Option<u64> {
        self.inner.valid_until
    }
}

/// Reads the sequence and EOL of the signed `record` a routing endpoint
/// returned for `ipnsName`. Throws the check name of a record that is
/// malformed or that the name's key did not sign.
#[cfg(feature = "observer")]
#[wasm_bindgen(js_name = readIpnsRecord)]
pub fn read_ipns_record(ipns_name: &str, record: &[u8]) -> Result<IpnsRecordReading, JsError> {
    cipherbox_engine::net::eol::verify_record_outside_session(ipns_name, record)
        .map(|inner| IpnsRecordReading { inner })
        .map_err(|error| JsError::new(error.check()))
}

// ---------------------------------------------------------------------------
// The device-approval rendezvous (ADR 0009). Pure functions of the exchange
// transcript, exported free rather than as engine commands: a device that asks
// to be approved has no session to issue a command through.
// ---------------------------------------------------------------------------

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod rendezvous {
    use super::*;
    use zeroize::Zeroizing;

    /// What a requester needs to open a rendezvous: the key it offers, the bytes it
    /// must sign over that key, and the digits its screen shows.
    #[wasm_bindgen]
    pub struct DeviceRendezvous {
        ephemeral_public_key: String,
        request_payload: Vec<u8>,
        comparison_value: String,
    }

    #[wasm_bindgen]
    impl DeviceRendezvous {
        /// The compressed secp256k1 key a factor must be sealed to.
        #[wasm_bindgen(getter, js_name = ephemeralPublicKey)]
        pub fn ephemeral_public_key(&self) -> String {
            self.ephemeral_public_key.clone()
        }

        /// The bytes the requesting device signs.
        #[wasm_bindgen(getter, js_name = requestPayload)]
        pub fn request_payload(&self) -> Vec<u8> {
            self.request_payload.clone()
        }

        /// The digits this screen shows, for the member to compare with the
        /// approver's. Both sides derive them from the same two requester fields.
        #[wasm_bindgen(getter, js_name = comparisonValue)]
        pub fn comparison_value(&self) -> String {
            self.comparison_value.clone()
        }
    }

    /// What an approver sends: the sealed factor, if it approved, and the bytes it
    /// must sign over its whole answer.
    #[wasm_bindgen]
    pub struct DeviceApprovalResponse {
        sealed_factor: Option<String>,
        payload: Vec<u8>,
    }

    #[wasm_bindgen]
    impl DeviceApprovalResponse {
        /// The sealed fresh factor, base64; absent on a denial.
        #[wasm_bindgen(getter, js_name = sealedFactor)]
        pub fn sealed_factor(&self) -> Option<String> {
            self.sealed_factor.clone()
        }

        /// The bytes the approving device signs.
        #[wasm_bindgen(getter)]
        pub fn payload(&self) -> Vec<u8> {
            self.payload.clone()
        }
    }

    /// Open a rendezvous from 32 fresh random bytes. The scalar stays with the
    /// caller: it is what opens the factor an approver seals back.
    #[wasm_bindgen(js_name = openDeviceRendezvous)]
    pub fn open_device_rendezvous(
        device_public_key: &str,
        rendezvous_scalar: Vec<u8>,
    ) -> Result<DeviceRendezvous, JsError> {
        let ephemeral_public_key =
            cipherbox_engine::rendezvous_public_key(&*scalar32(rendezvous_scalar)?)
                .map_err(malformed_device_field)?;
        let request_payload =
            cipherbox_engine::approval_request_payload(device_public_key, &ephemeral_public_key)
                .map_err(malformed_device_field)?;
        let comparison_value =
            cipherbox_engine::comparison_value(device_public_key, &ephemeral_public_key)
                .map_err(malformed_device_field)?;
        Ok(DeviceRendezvous {
            ephemeral_public_key,
            request_payload,
            comparison_value,
        })
    }

    /// Seal a fresh factor to the requester and build the answer to sign.
    /// `seal_scalar` must be 32 fresh random bytes on every call.
    #[wasm_bindgen(js_name = approveDeviceRendezvous)]
    pub fn approve_device_rendezvous(
        device_public_key: &str,
        request_id: &str,
        requester_device_public_key: &str,
        ephemeral_public_key: &str,
        seal_scalar: Vec<u8>,
        factor_key: Vec<u8>,
    ) -> Result<DeviceApprovalResponse, JsError> {
        let factor_key = Zeroizing::new(factor_key);
        let sealed_factor = cipherbox_engine::seal_factor(
            ephemeral_public_key,
            request_id,
            requester_device_public_key,
            &*scalar32(seal_scalar)?,
            &factor_key,
        )
        .map_err(malformed_device_field)?;
        let payload = cipherbox_engine::approval_response_payload(
            device_public_key,
            request_id,
            cipherbox_engine::ApprovalDecision::Approve,
            ephemeral_public_key,
            &sealed_factor,
        )
        .map_err(malformed_device_field)?;
        Ok(DeviceApprovalResponse {
            sealed_factor: Some(sealed_factor),
            payload,
        })
    }

    /// Build the denial to sign. A denial seals nothing.
    #[wasm_bindgen(js_name = denyDeviceRendezvous)]
    pub fn deny_device_rendezvous(
        device_public_key: &str,
        request_id: &str,
        ephemeral_public_key: &str,
    ) -> Result<DeviceApprovalResponse, JsError> {
        let payload = cipherbox_engine::approval_response_payload(
            device_public_key,
            request_id,
            cipherbox_engine::ApprovalDecision::Deny,
            ephemeral_public_key,
            "",
        )
        .map_err(malformed_device_field)?;
        Ok(DeviceApprovalResponse {
            sealed_factor: None,
            payload,
        })
    }

    /// Adopt the factor an approver sealed, with the scalar that opened the
    /// rendezvous. The approver's signature over the answer is verified first,
    /// so a relayed envelope nobody signed for is never opened (D4).
    ///
    /// The plaintext crosses into JS from the borrowed slice while its zeroizing
    /// owner is still alive: a `Vec` return would hand wasm-bindgen a buffer it
    /// frees without clearing, leaving the factor in linear memory for the life of
    /// the tab.
    #[wasm_bindgen(js_name = openDeviceFactor)]
    pub fn open_device_factor(
        sealed_factor: &str,
        request_id: &str,
        requester_device_public_key: &str,
        responder_device_public_key: &str,
        response_signature: &str,
        rendezvous_scalar: Vec<u8>,
    ) -> Result<js_sys::Uint8Array, JsError> {
        let opened = cipherbox_engine::adopt_factor(
            sealed_factor,
            request_id,
            requester_device_public_key,
            responder_device_public_key,
            response_signature,
            &*scalar32(rendezvous_scalar)?,
        )
        .map_err(|refusal| JsError::new(refusal.check()))?;
        Ok(js_sys::Uint8Array::from(opened.as_slice()))
    }

    /// Adopt a scalar the host handed in. Taken by value and held zeroizing, so the
    /// copy wasm-bindgen makes in linear memory does not outlive the call.
    fn scalar32(bytes: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, JsError> {
        let bytes = Zeroizing::new(bytes);
        <[u8; 32]>::try_from(bytes.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| JsError::new("a rendezvous scalar is 32 bytes"))
    }

    fn malformed_device_field(refusal: cipherbox_engine::MalformedDeviceField) -> JsError {
        JsError::new(refusal.check())
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

    const IPNS_NAME: &str = "k51qzi5uqu5djmw2yvf8kk5cdjc1ddc00o4d5sjwi6f79xzcay9j3gkddw5uu4";

    // The wrong-length rejection builds a `JsError` (wasm-only) — see
    // `tests/boundary.rs`.
    #[test]
    fn node_id_accepts_16_bytes_and_round_trips() {
        assert!(NodeId::from_bytes(&[0u8; 16]).is_ok());
        assert_eq!(
            NodeId::from_bytes(&[7u8; 16]).unwrap().bytes(),
            vec![7u8; 16]
        );
    }

    #[test]
    fn sharing_rows_expose_the_grantee_name_and_its_source() {
        let named = SharingGrant::from_facade(facade::SharingGrant {
            recipient_identity_public_key: vec![2; 33],
            permission: facade::Permission::Write,
            grantee_name: Some(("Ada".into(), cipherbox_core::seal::NameSource::Claimant)),
            via_link: Some(vec![0x44; 32]),
        });
        let name = named.grantee_name().expect("a named row");
        assert_eq!(name.name(), "Ada");
        assert_eq!(name.source(), "claimant");
        assert_eq!(named.via_link(), Some(vec![0x44; 32]));

        let unnamed = SharingGrant::from_facade(facade::SharingGrant {
            recipient_identity_public_key: vec![2; 33],
            permission: facade::Permission::Read,
            grantee_name: None,
            via_link: None,
        });
        assert!(unnamed.grantee_name().is_none());
        assert!(unnamed.via_link().is_none());

        let contact = SharingContact::from_facade(facade::SharingContact {
            identity_public_key: vec![2; 33],
            cached_name: Some("Ada".into()),
        });
        assert_eq!(contact.cached_name().as_deref(), Some("Ada"));
    }

    // Constructs the facade structs literally so a new engine field breaks this
    // test at compile time, mirroring the exhaustive-match guard for enums.
    #[test]
    fn snapshot_view_getters_map_every_field() {
        let view = SnapshotView::from_facade(facade::SnapshotView {
            root: facade::NodeId([1u8; 16]),
            folder: facade::NodeId([2u8; 16]),
            folder_name: "holiday".into(),
            permission: facade::Permission::Read,
            received_share: false,
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
                    content_cid: Some(vec![0xC1, 0xD0]),
                    pending_invite_claims: 0,
                    ipns_name: Some(IPNS_NAME.into()),
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
                    content_cid: None,
                    pending_invite_claims: 2,
                    ipns_name: None,
                },
            ],
            ancestors: vec![facade::Breadcrumb {
                id: facade::NodeId([1u8; 16]),
                name: String::new(),
            }],
            dead_letters: vec![
                facade::DeadLetter {
                    op_id: OpId(9),
                    reason: facade::DeadLetterReason::Undecodable,
                },
                facade::DeadLetter {
                    op_id: OpId(11),
                    reason: facade::DeadLetterReason::AttemptsExhausted,
                },
            ],
            queue_hold: Some(facade::QueueHold {
                op_id: OpId(12),
                node: facade::NodeId([5u8; 16]),
                reason: facade::QueueHoldReason::Quota { needed_bytes: 4096 },
            }),
            retained_records: 3,
            staleness: facade::Staleness::Reconciling,
        });

        assert_eq!(view.root(), vec![1u8; 16]);
        assert_eq!(view.folder(), vec![2u8; 16]);
        assert_eq!(view.folder_name(), "holiday");
        assert_eq!(view.permission(), Permission::Read);
        assert!(!view.received_share());
        let dead_letters = view.dead_letters();
        assert_eq!(
            dead_letters
                .iter()
                .map(|dead| (dead.op_id(), dead.reason()))
                .collect::<Vec<_>>(),
            vec![
                (9, DeadLetterReason::Undecodable),
                (11, DeadLetterReason::AttemptsExhausted),
            ]
        );
        let hold = view.queue_hold().expect("the view carries the hold");
        assert_eq!(hold.op_id(), 12);
        assert_eq!(hold.node(), vec![5u8; 16]);
        assert_eq!(hold.reason(), "quota");
        assert_eq!(hold.needed_bytes(), Some(4096));
        assert_eq!(hold.check(), None);
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
        assert_eq!(children[0].pending_invite_claims(), 0);
        assert_eq!(children[1].pending_invite_claims(), 2);
        assert_eq!(children[0].ipns_name().as_deref(), Some(IPNS_NAME));
        assert!(children[1].ipns_name().is_none());

        let ancestors = view.ancestors();
        assert_eq!(ancestors.len(), 1);
        assert_eq!(ancestors[0].id(), vec![1u8; 16]);
        assert_eq!(ancestors[0].name(), "");
    }

    /// A host dispatches on the reason, and each one carries exactly the figure
    /// its own notice renders.
    #[test]
    fn a_queue_hold_names_its_reason_and_carries_only_that_reasons_figure() {
        let settings = QueueHold {
            inner: facade::QueueHold {
                op_id: OpId(13),
                node: facade::NodeId([6u8; 16]),
                reason: facade::QueueHoldReason::Settings(cipherbox_engine::SettingsRefusal::Byo(
                    cipherbox_engine::ProviderError::InsecureTransport,
                )),
            },
        };
        assert_eq!(settings.reason(), "settings");
        assert_eq!(settings.check().as_deref(), Some("byo-endpoint-insecure"));
        assert_eq!(settings.needed_bytes(), None);

        let bin_index = QueueHold {
            inner: facade::QueueHold {
                op_id: OpId(14),
                node: facade::NodeId([7u8; 16]),
                reason: facade::QueueHoldReason::BinIndex(
                    cipherbox_engine::DefaultsReason::Suppressed,
                ),
            },
        };
        assert_eq!(bin_index.reason(), "bin-index");
        assert_eq!(bin_index.check().as_deref(), Some("suppressed"));
        assert_eq!(bin_index.needed_bytes(), None);
    }
}
