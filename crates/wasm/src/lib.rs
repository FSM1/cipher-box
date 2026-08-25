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
//! engine structures. Boundary hygiene is structural: `u64`s cross as `bigint`,
//! binary payloads as `Uint8Array`, and the command surface exposes only
//! intent while the event and read surfaces carry key-free view state and
//! decrypted user content.
//!
//! One secret crosses, and only because handing it over *is* the feature: an
//! invite link's bearer capability ([`CommandOutcome::fragment`]), which the
//! host puts in a URL fragment and reads nothing out of. It crosses as the
//! fragment text rather than as bytes so the host composes and parses no link
//! material. Residual: a JS string is immutable, so the host cannot scrub the
//! copy it holds — inherent to a capability that has to reach a URL — and
//! wasm-bindgen frees the linear-memory copy unwiped.

// wasm-bindgen's macro-generated glue is unsafe by nature and exempt; this
// forbids only unsafe we would hand-write (there is none).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use cipherbox_engine::content::{ByoIpfsConfig as EngineByo, ByoKind as EngineByoKind};
use cipherbox_engine::facade;
use cipherbox_engine::seams::{UnixMillis, check_bearer};
use cipherbox_engine::{
    AcceptOutcome, Contact, MintedInviteLink, PinMode as EnginePinMode, RetentionPolicy,
};
use core::num::NonZeroU64;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod seams_bridge;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod host;

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

impl From<facade::Permission> for Permission {
    fn from(permission: facade::Permission) -> Self {
        match permission {
            facade::Permission::Read => Permission::Read,
            facade::Permission::Write => Permission::Write,
        }
    }
}

// ---------------------------------------------------------------------------
// Vault settings — the member's placement, provider and retention choice, as a
// host builds it for `Command.saveVaultSettings`. Write-only across the
// boundary: no getter reads a config back out, so a stored provider credential
// never crosses back into JS.
// ---------------------------------------------------------------------------

/// Where a version's bytes are pinned.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// CipherBox's hosted pin store (the cold-start default).
    Hosted,
    /// The member's own provider only.
    External,
    /// Both legs.
    Dual,
}

impl From<PinMode> for EnginePinMode {
    fn from(mode: PinMode) -> Self {
        match mode {
            PinMode::Hosted => EnginePinMode::Hosted,
            PinMode::External => EnginePinMode::External,
            PinMode::Dual => EnginePinMode::Dual,
        }
    }
}

/// The kind of member-supplied IPFS provider, which fixes the reachability
/// probe.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByoKind {
    /// A Kubo RPC endpoint.
    Kubo,
    /// An IPFS Pinning Service API endpoint.
    Psa,
    /// A Pinata endpoint.
    Pinata,
}

impl From<ByoKind> for EngineByoKind {
    fn from(kind: ByoKind) -> Self {
        match kind {
            ByoKind::Kubo => EngineByoKind::Kubo,
            ByoKind::Psa => EngineByoKind::Psa,
            ByoKind::Pinata => EngineByoKind::Pinata,
        }
    }
}

/// A member's own IPFS provider. The engine validates the endpoint and the
/// credential before either reaches a request.
#[wasm_bindgen]
pub struct ByoIpfsConfig {
    inner: EngineByo,
}

/// The bearer a host sent as bytes, as the zeroizing text a request splices.
/// `String::from_utf8` reuses the incoming allocation, so the credential is
/// never copied; the rejected bytes are wiped before the refusal returns.
fn decode_bearer(bytes: Vec<u8>) -> Result<Zeroizing<String>, JsError> {
    let refused = || JsError::new("accessToken must be a sendable bearer");
    let token = Zeroizing::new(String::from_utf8(bytes).map_err(|error| {
        error.into_bytes().zeroize();
        refused()
    })?);
    check_bearer(&token).map_err(|_| refused())?;
    Ok(token)
}

#[wasm_bindgen]
impl ByoIpfsConfig {
    /// Builds a provider config. `accessToken` is `undefined` for a provider
    /// that needs none; when present it arrives as bytes and lands in a
    /// zeroizing buffer.
    ///
    /// Bytes rather than a `String` so the host holds the credential in
    /// something it can scrub: a JS string cannot be overwritten.
    ///
    /// The bytes are decoded and checked against [`check_bearer`] here rather
    /// than at save time, so a credential the engine will refuse never reaches
    /// a wasm object whose JS handle a later refusal could abandon. The
    /// refusals carry no part of the value.
    #[wasm_bindgen(constructor)]
    pub fn new(
        endpoint: String,
        kind: ByoKind,
        access_token: Option<Vec<u8>>,
    ) -> Result<ByoIpfsConfig, JsError> {
        let access_token = access_token.map(decode_bearer).transpose()?;
        Ok(Self {
            inner: EngineByo {
                endpoint,
                kind: kind.into(),
                access_token,
            },
        })
    }
}

/// The owner's client configuration, as `Command.saveVaultSettings` seals it
/// into the vault settings record.
#[wasm_bindgen]
pub struct VaultSettings {
    inner: cipherbox_engine::VaultSettings,
}

#[wasm_bindgen]
impl VaultSettings {
    /// Builds the settings to publish. `byo` is `undefined` when the member
    /// runs no provider of their own; `keepLatestVersions` is `undefined` to
    /// keep every version, and `0` is refused rather than read as "keep none",
    /// which would retire the live version of every file.
    #[wasm_bindgen(constructor)]
    pub fn new(
        pin_mode: PinMode,
        byo: Option<ByoIpfsConfig>,
        keep_latest_versions: Option<u32>,
    ) -> Result<VaultSettings, JsError> {
        let retention = match keep_latest_versions {
            None => RetentionPolicy::KeepAll,
            Some(n) => RetentionPolicy::KeepLatest(
                NonZeroU64::new(u64::from(n))
                    .ok_or_else(|| JsError::new("keepLatestVersions must be > 0"))?,
            ),
        };
        Ok(Self {
            inner: cipherbox_engine::VaultSettings {
                pin_mode: pin_mode.into(),
                byo: byo.map(|config| config.inner),
                retention,
            },
        })
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

/// Why a queued op dead-lettered. Each reason calls for a different message
/// and a different user action, so the classification crosses with the op
/// rather than being reduced to a flag.
#[wasm_bindgen]
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
    /// The drain began uploading a queued op's content version.
    UploadStarted,
    /// One more of the version's blocks is confirmed on the network.
    UploadProgress,
    /// Every block of the version is on the network.
    UploadCompleted,
    /// One upload attempt stopped; the op retries on the next drain tick.
    UploadFailed,
    /// The user cancelled the upload.
    UploadCancelled,
    /// The version published, but the member's own IPFS provider did not take
    /// it. No retry is queued.
    ExternalPinFailed,
}

impl From<facade::OpPhase> for OpPhase {
    fn from(phase: facade::OpPhase) -> Self {
        match phase {
            facade::OpPhase::DownloadStarted => OpPhase::DownloadStarted,
            facade::OpPhase::DownloadCompleted => OpPhase::DownloadCompleted,
            facade::OpPhase::DownloadFailed => OpPhase::DownloadFailed,
            facade::OpPhase::UploadStarted => OpPhase::UploadStarted,
            facade::OpPhase::UploadProgress => OpPhase::UploadProgress,
            facade::OpPhase::UploadCompleted => OpPhase::UploadCompleted,
            facade::OpPhase::UploadFailed => OpPhase::UploadFailed,
            facade::OpPhase::UploadCancelled => OpPhase::UploadCancelled,
            facade::OpPhase::ExternalPinFailed => OpPhase::ExternalPinFailed,
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot read surface — key-free view state projected by the engine. Ids
// cross as raw 16-byte `Uint8Array`s (the `NodeId.bytes` shape), `u64`s as
// `bigint`, absent projections as `undefined`.
// ---------------------------------------------------------------------------

/// The result of one `Engine::command` call. Read `kind`, then the matching
/// payload getter.
#[wasm_bindgen]
pub struct CommandOutcome {
    inner: facade::CommandOutcome,
}

#[wasm_bindgen]
impl CommandOutcome {
    /// The outcome discriminant, as a stable string literal.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        match self.inner {
            facade::CommandOutcome::Done => "done",
            facade::CommandOutcome::Queued { .. } => "queued",
            facade::CommandOutcome::ContactImported(_) => "contactImported",
            facade::CommandOutcome::InviteLinkMinted(_) => "inviteLinkMinted",
            facade::CommandOutcome::ShareAccepted(_) => "shareAccepted",
        }
        .to_owned()
    }

    /// `queued`: the staged op's durable queue id, as the same `bigint` an
    /// `opProgress`/`deadLetter` event carries, so the two compare equal and
    /// an id past 2^53 survives; otherwise `undefined`.
    #[wasm_bindgen(getter, js_name = opId)]
    pub fn op_id(&self) -> Option<u64> {
        self.inner.op_id().map(|op_id| op_id.0)
    }

    /// `contactImported`: the compressed SEC1 identity public key a grant
    /// command names as its recipient; otherwise `undefined`.
    #[wasm_bindgen(getter, js_name = identityPublicKey)]
    pub fn identity_public_key(&self) -> Option<Vec<u8>> {
        self.contact()
            .map(|contact| contact.identity_pk().to_sec1().to_vec())
    }

    /// `contactImported`: the X25519 encryption subkey the verified binding
    /// signature tied to that identity key; otherwise `undefined`.
    #[wasm_bindgen(getter, js_name = encPublicKey)]
    pub fn enc_public_key(&self) -> Option<Vec<u8>> {
        self.contact()
            .map(|contact| contact.enc_subkey().to_bytes().to_vec())
    }

    /// `inviteLinkMinted`: the link's whole URL fragment — the bearer
    /// capability, handed back verbatim to `claimInviteLink`; otherwise
    /// `undefined`.
    #[wasm_bindgen(getter)]
    pub fn fragment(&self) -> Option<String> {
        self.link().map(|link| link.fragment.to_string())
    }

    /// `shareAccepted`: the accepted scope's raw 16-byte id, the same
    /// `NodeId.bytes` shape a command names it by; otherwise `undefined`.
    #[wasm_bindgen(getter, js_name = scopeId)]
    pub fn scope_id(&self) -> Option<Vec<u8>> {
        self.share().map(|share| share.scope_id.to_vec())
    }

    /// `shareAccepted`: the record sequence the accept adopted, which the
    /// strict-sequence floor now holds; otherwise `undefined`.
    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> Option<u64> {
        self.share().map(|share| share.sequence)
    }

    /// `shareAccepted`: the **owner-committed** permission, never the share
    /// pointer's claim; otherwise `undefined`.
    #[wasm_bindgen(getter)]
    pub fn permission(&self) -> Option<Permission> {
        self.share()
            .map(|share| facade::Permission::from(share.permission).into())
    }

    /// `shareAccepted`: whether this accept added a new bookmark rather than
    /// refreshing one the vault already held; otherwise `undefined`.
    #[wasm_bindgen(getter, js_name = newlyAdded)]
    pub fn newly_added(&self) -> Option<bool> {
        self.share().map(|share| share.newly_added)
    }
}

impl CommandOutcome {
    /// Wraps an engine command outcome. Never exported to JS.
    pub fn from_facade(inner: facade::CommandOutcome) -> Self {
        Self { inner }
    }

    fn link(&self) -> Option<&MintedInviteLink> {
        match &self.inner {
            facade::CommandOutcome::InviteLinkMinted(link) => Some(link),
            _ => None,
        }
    }

    fn contact(&self) -> Option<&Contact> {
        match &self.inner {
            facade::CommandOutcome::ContactImported(contact) => Some(contact),
            _ => None,
        }
    }

    fn share(&self) -> Option<&AcceptOutcome> {
        match &self.inner {
            facade::CommandOutcome::ShareAccepted(share) => Some(share),
            _ => None,
        }
    }
}

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

/// The queue head held over the account quota, keeping its place and its
/// staging reservation until a quota probe reports room.
#[wasm_bindgen]
pub struct BlockedOp {
    inner: facade::BlockedOp,
}

#[wasm_bindgen]
impl BlockedOp {
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

    /// The byte count the resume probe must find room for.
    #[wasm_bindgen(getter, js_name = neededBytes)]
    pub fn needed_bytes(&self) -> u64 {
        self.inner.needed_bytes
    }
}

/// The queue head held over the member's own settings, keeping its place and
/// its staging reservation until those settings change.
#[wasm_bindgen]
pub struct SettingsHold {
    inner: facade::SettingsHold,
}

#[wasm_bindgen]
impl SettingsHold {
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

    /// The stable check name of the rule that refused. Never the endpoint or
    /// the bearer those settings carry.
    #[wasm_bindgen(getter)]
    pub fn check(&self) -> String {
        self.inner.refusal.check().to_owned()
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

    /// The drain's over-quota hold, or `undefined`.
    #[wasm_bindgen(getter)]
    pub fn blocked(&self) -> Option<BlockedOp> {
        self.inner.blocked.map(|inner| BlockedOp { inner })
    }

    /// The drain's settings-refused hold, or `undefined`.
    #[wasm_bindgen(getter, js_name = settingsHold)]
    pub fn settings_hold(&self) -> Option<SettingsHold> {
        self.inner.settings_hold.map(|inner| SettingsHold { inner })
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
}

impl SharingGrant {
    /// Wraps an engine sharing grant. Never exported to JS.
    pub fn from_facade(inner: facade::SharingGrant) -> Self {
        Self { inner }
    }
}

/// The invite-link standing this owner has on the scope a [`SharingView`] reads.
#[wasm_bindgen]
pub struct SharingInviteLinks {
    inner: facade::SharingInviteLinks,
}

#[wasm_bindgen]
impl SharingInviteLinks {
    /// Whether the scope carries one live link — the link a revoke cuts and a
    /// conversion converts against.
    #[wasm_bindgen(getter)]
    pub fn live(&self) -> bool {
        self.inner.live
    }

    /// The live link's deadline in Unix millis (a `u64`, crossing as a
    /// `bigint`), absent where it does not expire or where no link is live.
    #[wasm_bindgen(getter, js_name = expiresAt)]
    pub fn expires_at(&self) -> Option<u64> {
        self.inner.expires_at.map(|deadline| deadline.0)
    }

    /// Whether the live link's deadline has passed, decided on the engine's
    /// clock so a host never compares the deadline against its own.
    #[wasm_bindgen(getter)]
    pub fn expired(&self) -> bool {
        self.inner.expired
    }

    /// The records at this scope its commitment no longer carries — what a prune
    /// drops.
    #[wasm_bindgen(getter)]
    pub fn spent(&self) -> u32 {
        self.inner.spent
    }
}

impl SharingInviteLinks {
    /// Wraps an engine invite-link standing. Never exported to JS.
    pub fn from_facade(inner: facade::SharingInviteLinks) -> Self {
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

    /// Whether a further share of this scope would be accepted.
    #[wasm_bindgen(getter, js_name = canMintShare)]
    pub fn can_mint_share(&self) -> bool {
        self.inner.can_mint_share
    }

    /// This owner's invite links at the scope, or `undefined` when the read could
    /// not open those records.
    #[wasm_bindgen(getter, js_name = inviteLinks)]
    pub fn invite_links(&self) -> Option<SharingInviteLinks> {
        self.inner
            .invite_links
            .clone()
            .map(SharingInviteLinks::from_facade)
    }
}

impl ScopeSharing {
    /// Wraps an engine scope sharing state. Never exported to JS.
    pub fn from_facade(inner: facade::ScopeSharing) -> Self {
        Self { inner }
    }
}

/// A key-free read of one scope's sharing state: this vault's whole verified
/// contact book, and the grants the scope's own record commits.
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
    /// `granted`, `revocation-signal`, `unresolvable`, `epoch-lag` — or
    /// `undefined` when no pass has resolved it yet. A host renders the
    /// engine's verdict; it never computes one.
    #[wasm_bindgen(getter)]
    pub fn resolution(&self) -> Option<String> {
        self.inner.resolution.map(|class| class.name().to_owned())
    }
}

impl ReceivedShareRow {
    /// Wraps an engine received-share row. Never exported to JS.
    pub fn from_facade(inner: facade::ReceivedShareRow) -> Self {
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
    /// Create an empty node under a parent. A file created **with** content is
    /// a write handle, not a command (`beginWrite` on the engine handle).
    pub fn create(parent: &NodeId, name: String, kind: NodeKind) -> Command {
        Self::wrap(facade::Command::Create {
            parent: parent.facade(),
            name,
            kind: kind.into(),
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

    /// Cancel a queued upload by the op id `commitWrite` returned. Rejects with
    /// `notAnUpload` when the op carries no content, and with
    /// `tooLateToCancel` once the version's record is publishing.
    #[wasm_bindgen(js_name = cancelUpload)]
    pub fn cancel_upload(op_id: u64) -> Command {
        Self::wrap(facade::Command::CancelUpload {
            op_id: cipherbox_engine::seams::OpId(op_id),
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

    /// Mint an invite link for a node. `expires_at` is the link's deadline in
    /// Unix milliseconds, or `undefined` for a link that never expires.
    #[wasm_bindgen(js_name = createInviteLink)]
    pub fn create_invite_link(
        node: &NodeId,
        permission: Permission,
        expires_at: Option<u64>,
    ) -> Command {
        Self::wrap(facade::Command::CreateInviteLink {
            node: node.facade(),
            permission: permission.into(),
            expires_at: expires_at.map(UnixMillis),
        })
    }

    /// Revoke the invite link minted at a node (owner-only).
    #[wasm_bindgen(js_name = revokeInviteLink)]
    pub fn revoke_invite_link(node: &NodeId) -> Command {
        Self::wrap(facade::Command::RevokeInviteLink {
            node: node.facade(),
        })
    }

    /// Drop the invite records at a node whose row the scope's own owner-signed
    /// commitment no longer carries.
    #[wasm_bindgen(js_name = pruneInviteLinks)]
    pub fn prune_invite_links(node: &NodeId) -> Command {
        Self::wrap(facade::Command::PruneInviteLinks {
            node: node.facade(),
        })
    }

    /// Claim an invite link from the fragment its URL carries, verbatim.
    #[wasm_bindgen(js_name = claimInviteLink)]
    pub fn claim_invite_link(fragment: String) -> Command {
        Self::wrap(facade::Command::ClaimInviteLink {
            fragment: Zeroizing::new(fragment),
        })
    }

    /// Convert the invite claims waiting for the link minted at a node
    /// (owner-only).
    #[wasm_bindgen(js_name = convertInviteClaims)]
    pub fn convert_invite_claims(node: &NodeId) -> Command {
        Self::wrap(facade::Command::ConvertInviteClaims {
            node: node.facade(),
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

    /// Publish the account's vault settings record.
    #[wasm_bindgen(js_name = saveVaultSettings)]
    pub fn save_vault_settings(settings: VaultSettings) -> Command {
        Self::wrap(facade::Command::SaveVaultSettings {
            settings: settings.inner,
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
            facade::Event::VaultUnprovisioned { .. } => "vaultUnprovisioned",
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
            facade::Event::DeadLetter { op_id, .. } => Some(op_id.0),
            facade::Event::OpProgress { op_id, .. } => op_id.map(|op| op.0),
            _ => None,
        }
    }

    /// `deadLetter`: why the op will never publish; otherwise `undefined`.
    #[wasm_bindgen(getter, js_name = deadLetterReason)]
    pub fn dead_letter_reason(&self) -> Option<DeadLetterReason> {
        match self.inner {
            facade::Event::DeadLetter { reason, .. } => Some(reason.into()),
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

    /// `opProgress`: blocks of the version confirmed so far, on the phases that
    /// count them; otherwise `undefined`.
    #[wasm_bindgen(getter, js_name = blocksConfirmed)]
    pub fn blocks_confirmed(&self) -> Option<u32> {
        match self.inner {
            facade::Event::OpProgress { progress, .. } => progress.map(|p| p.confirmed),
            _ => None,
        }
    }

    /// `opProgress`: the version's whole block count, on the phases that count
    /// them; otherwise `undefined`.
    #[wasm_bindgen(getter, js_name = blocksTotal)]
    pub fn blocks_total(&self) -> Option<u32> {
        match self.inner {
            facade::Event::OpProgress { progress, .. } => progress.map(|p| p.total),
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

    /// `renewalFailed` / `vaultUnprovisioned`: the key-free failure
    /// classification; otherwise `undefined`.
    #[wasm_bindgen(getter)]
    pub fn detail(&self) -> Option<String> {
        match &self.inner {
            facade::Event::RenewalFailed { detail, .. }
            | facade::Event::VaultUnprovisioned { detail, .. } => Some(detail.clone()),
            _ => None,
        }
    }

    /// `vaultUnprovisioned`: whether a fresh `start` could clear it; otherwise
    /// `undefined`.
    #[wasm_bindgen(getter)]
    pub fn retryable(&self) -> Option<bool> {
        match &self.inner {
            facade::Event::VaultUnprovisioned { retryable, .. } => Some(*retryable),
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
    fn command_builders_carry_the_stable_name() {
        let node = NodeId::from_bytes(&[0u8; 16]).unwrap();
        assert_eq!(Command::manual_refresh().name(), "manualRefresh");
        assert_eq!(Command::logout().name(), "logout");
        assert_eq!(Command::set_focus(None).name(), "setFocus");
        assert_eq!(
            Command::create(&node, "f".into(), NodeKind::Folder).name(),
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

        let dead = Event::from_facade(facade::Event::DeadLetter {
            op_id: OpId(42),
            reason: facade::DeadLetterReason::TargetGone,
        });
        assert_eq!(dead.kind(), "deadLetter");
        assert_eq!(dead.op_id(), Some(42));
        assert_eq!(
            dead.dead_letter_reason(),
            Some(DeadLetterReason::TargetGone)
        );
        assert!(
            snapshot.dead_letter_reason().is_none(),
            "the reason is undefined off-variant"
        );

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
            progress: None,
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
            progress: None,
            error: Some("unavailable".into()),
        });
        assert_eq!(progress.op_id(), Some(7));
        assert_eq!(progress.node(), Some(vec![3u8; 16]));
        assert_eq!(progress.phase(), Some(OpPhase::DownloadFailed));
        assert_eq!(progress.error(), Some("unavailable".into()));
        assert!(progress.blocks_confirmed().is_none());

        let upload = Event::from_facade(facade::Event::OpProgress {
            op_id: Some(OpId(9)),
            node: facade::NodeId([4u8; 16]),
            phase: facade::OpPhase::UploadProgress,
            progress: Some(facade::BlockProgress {
                confirmed: 3,
                total: 8,
            }),
            error: None,
        });
        assert_eq!(upload.op_id(), Some(9));
        assert_eq!(upload.phase(), Some(OpPhase::UploadProgress));
        assert_eq!(upload.blocks_confirmed(), Some(3));
        assert_eq!(upload.blocks_total(), Some(8));

        let op_less = Event::from_facade(facade::Event::OpProgress {
            op_id: None,
            node: facade::NodeId([0u8; 16]),
            phase: facade::OpPhase::DownloadStarted,
            progress: None,
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
            folder_name: "holiday".into(),
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
            blocked: Some(facade::BlockedOp {
                op_id: OpId(12),
                node: facade::NodeId([5u8; 16]),
                needed_bytes: 4096,
            }),
            settings_hold: Some(facade::SettingsHold {
                op_id: OpId(13),
                node: facade::NodeId([6u8; 16]),
                refusal: cipherbox_engine::SettingsRefusal::Byo(
                    cipherbox_engine::ProviderError::InsecureTransport,
                ),
            }),
            retained_records: 3,
            staleness: facade::Staleness::Reconciling,
        });

        assert_eq!(view.root(), vec![1u8; 16]);
        assert_eq!(view.folder(), vec![2u8; 16]);
        assert_eq!(view.folder_name(), "holiday");
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
        let blocked = view.blocked().expect("the view carries the hold");
        assert_eq!(blocked.op_id(), 12);
        assert_eq!(blocked.node(), vec![5u8; 16]);
        assert_eq!(blocked.needed_bytes(), 4096);
        let held = view.settings_hold().expect("the view carries the hold");
        assert_eq!(held.op_id(), 13);
        assert_eq!(held.node(), vec![6u8; 16]);
        assert_eq!(held.check(), "byo-endpoint-insecure");
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
