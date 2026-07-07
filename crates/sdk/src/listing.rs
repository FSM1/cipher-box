//! Resolved child-listing API — the SC#6 / 68.2-parity gated read chain.
//!
//! Rust twin of the (68.2-02-planned) `packages/sdk/src/folder-listing.ts`
//! `listFolder`/`listSharedFolder` API: an imperative-pull `ResolvedChild[]`
//! carrier resolved once per folder load, plus a `folder:updated`-analog
//! event/callback (D-01/D-02).
//!
//! GATE-FIRST (T-69-06-01): every IPNS resolve on this path is routed through
//! `RotationHighWater::enforce_resolved` (69-02) BEFORE its bytes are decoded
//! or unsealed. A regressed generation/seq fails closed (`Err`) — no
//! `ResolvedChild` is ever returned for a rejected resolve.
//!
//! CRITICAL (Pitfall 4 / M1 integrity): for a COLD child reached during the
//! folder-listing walk, the `generation`/`version_floor` passed to the gate
//! are the PARENT's `SealedChildRef.generation`/`.version_floor` mirror —
//! NEVER the child's own envelope generation (`PublishedNode.generation`).
//! This mirrors TS `dfsFindFolder`'s documented generation-source rule
//! exactly (see `packages/sdk/src/client.ts`, 68.2-01 gate wiring).
//!
//! SINGLE GATED ENTRYPOINT (D-05/SC#6, T-69-06-02): the raw resolve+fetch
//! primitive (`resolve_published_node`) is `pub(crate)` — visible only inside
//! this crate. `list_folder`/`list_shared_folder` are the ONLY `pub` read
//! entrypoints; FUSE/WinFsp must never call a raw resolve directly.
//!
//! Zeroization (D-09, terminal-owner-only): `parent_read_key`/
//! `folder_read_key` are caller-supplied borrows and are NEVER zeroed here.
//! The per-child `read_key_sealed` unwrap mints a NEW key this module is the
//! terminal owner of — that buffer IS zeroed (via `Zeroizing`) once its
//! single use (unsealing the child's own node body) is done.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::{Zeroize, Zeroizing};

use cipherbox_core::node::seal;
use cipherbox_core::node::{
    decode_node, decode_published_node, decode_write_body, Node, NodeError, NodeKind,
    PublishedNode, SealedChildRef, WriteChildRef,
};

use crate::rotation::{EnforceResolvedParams, HighWaterStore, RotationError, RotationHighWater};

// ---------------------------------------------------------------------------
// Fetch seam — injected so unit tests can drive the gate logic without a
// live API/IPFS round trip (project memory: GSD subagents must not run live
// integration tests).
// ---------------------------------------------------------------------------

/// A durable resolve+fetch seam for a single IPNS name.
///
/// The real implementation composes `cipherbox_api_client::ipns::resolve_ipns_verified`
/// (the D-08 verified chokepoint) + `cipherbox_api_client::ipfs::fetch_content`; unit
/// tests inject a fake in-memory fetcher instead.
///
/// `#[allow(async_fn_in_trait)]`: only ever used generically
/// (`list_folder<F: NodeFetcher, ..>`), never as `dyn NodeFetcher`, so the
/// missing auto-trait bound on the generated future is not a concern within
/// this crate (mirrors `HighWaterStore`'s identical allow).
#[allow(async_fn_in_trait)]
pub trait NodeFetcher {
    /// Resolve `ipns_name` and fetch its published-node bytes (still
    /// AEAD-sealed — no decode/unseal happens here).
    async fn fetch(&self, ipns_name: &str) -> Result<FetchedRecord, ListingError>;
}

/// One fetched-but-not-yet-gated record: the verified IPNS sequence number
/// alongside the raw (still-sealed) `PublishedNode` envelope bytes.
#[derive(Debug, Clone)]
pub struct FetchedRecord {
    pub sequence_number: u64,
    pub bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors surfaced by the gated listing API.
#[derive(Debug, thiserror::Error)]
pub enum ListingError {
    #[error("resolve/fetch failed for {ipns_name}: {message}")]
    FetchFailed { ipns_name: String, message: String },
    /// The ROT-07 anti-rollback gate rejected a resolve BEFORE its bytes
    /// were trusted (decoded/unsealed) — fail-closed, no partial listing
    /// is ever returned for the rejected node.
    #[error("gate rejected resolve for {0}: {1}")]
    Gated(String, RotationError),
    /// Node codec/crypto failure (malformed JSON, AEAD auth-tag mismatch,
    /// wrong key, etc.) surfaced AFTER the gate has already passed.
    #[error("node codec/crypto error: {0}")]
    Node(#[from] NodeError),
    #[error("unknown node kind on wire: {0}")]
    InvalidKind(String),
    #[error("{0} is a file node -- cannot list children of a file")]
    NotAFolder(String),
}

// ---------------------------------------------------------------------------
// ResolvedChild + folder:updated-analog event
// ---------------------------------------------------------------------------

/// The Rust twin of 68.2's `ResolvedChild` — the single per-child metadata
/// carrier (D-01/D-02, SC#6), resolved once per folder load.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedChild {
    pub ipns_name: String,
    pub name: String,
    pub kind: NodeKind,
    /// Plaintext byte size (file children only; `None` for folder/root).
    pub size: Option<u64>,
    pub modified_at: u64,
    pub sequence: u64,
}

/// The owned-materialization twin of [`ResolvedChild`]: the resolved child
/// metadata PLUS its recovered owned write material. Returned by
/// [`resolve_owned_child`]/[`list_folder_owned`] to the terminal-owner caller
/// (the FUSE mount, P1b) which builds `InodeKind` from it.
///
/// D-09 terminal owner: `read_key`/`write_key`/`ipns_private_key` are the RAW
/// recovered key material wrapped in `Zeroizing` — the SDK does NOT zero
/// them; the caller owns their lifecycle. `Debug` REDACTS every key field so
/// the material can never leak into a log line (mirrors `emit::FolderEmission`).
pub struct ResolvedOwnedChild {
    pub child: ResolvedChild,
    /// The child node's STABLE own id (`PublishedNode.id`), recovered from the
    /// resolved child envelope. This — NOT any client-local inode number — is
    /// the D-07 write-plane pairing key (`WriteChildRef.child_id`) and the seal
    /// AAD. The FUSE mount MUST persist this on the inode so a later parent
    /// re-publish keys the child's `WriteChildRef` by the child's real id even
    /// after the child was re-materialized under a fresh local inode number.
    pub node_id: String,
    /// Raw 32-byte readKey recovered under the parent readKey (D-09 —
    /// caller-owned from here).
    pub read_key: Zeroizing<[u8; 32]>,
    /// Raw 32-byte writeKey recovered under the parent writeKey — the
    /// write-plane half `resolve_child`/`list_folder` discard (D-09).
    pub write_key: Zeroizing<[u8; 32]>,
    /// Raw Ed25519 signing seed recovered from the child's OWN sealed
    /// write-body (D-09 — caller-owned from here).
    pub ipns_private_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for ResolvedOwnedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedOwnedChild")
            .field("child", &self.child)
            .field("node_id", &self.node_id)
            .field("read_key", &"[REDACTED]")
            .field("write_key", &"[REDACTED]")
            .field("ipns_private_key", &"[REDACTED]")
            .finish()
    }
}

/// A `folder:updated`-analog notification, fired whenever a listing is
/// (re)computed, so the FUSE/WinFsp layer can refresh a projection (68.2
/// imperative-pull + event-push mirror).
#[derive(Debug, Clone, PartialEq)]
pub struct FolderUpdatedEvent {
    pub ipns_name: String,
    pub children: Vec<ResolvedChild>,
}

/// Callback type for the `folder:updated`-analog notification. Mirrors the
/// existing `Arc<dyn Fn(SyncStatus) + Send + Sync>` callback convention used
/// by `crate::sync::SyncDaemon`, but taken as a plain reference here since
/// listing has no persistent daemon/registration lifecycle in this plan.
pub type FolderUpdatedCallback<'a> = &'a (dyn Fn(&FolderUpdatedEvent) + Send + Sync);

// ---------------------------------------------------------------------------
// Raw gate-first resolve — crate-private (D-05/SC#6 single gated entrypoint)
// ---------------------------------------------------------------------------

/// Gate-first resolve: fetches `ipns_name` via the injected `fetcher`, then
/// gates the result through `enforce_resolved` BEFORE the fetched bytes are
/// decoded. Only on a passing gate does this function decode the
/// `PublishedNode` envelope and return it (alongside its verified sequence
/// number).
///
/// `expected_generation`/`expected_version_floor` are the values presented
/// to the gate. For a COLD child reached during a folder-listing walk,
/// callers MUST source these from the PARENT's `SealedChildRef.generation`/
/// `.version_floor` mirror — NEVER the child's own envelope generation
/// (Pitfall 4 / M1 integrity, T-69-06-01).
///
/// NOT `pub` beyond the crate (D-05/SC#6, T-69-06-02): raw resolve is
/// `crates/sdk`-internal only. `list_folder`/`list_shared_folder` are the
/// single gated read entrypoints FUSE/WinFsp may call.
pub(crate) async fn resolve_published_node<F, S>(
    fetcher: &F,
    high_water: &RotationHighWater<S>,
    ipns_name: &str,
    expected_generation: i64,
    expected_version_floor: i64,
) -> Result<(PublishedNode, u64), ListingError>
where
    F: NodeFetcher,
    S: HighWaterStore,
{
    let fetched = fetcher.fetch(ipns_name).await?;

    // GATE FIRST: enforce_resolved runs BEFORE fetched.bytes is trusted
    // (decoded). A regressed generation/seq fails closed here -- decode_published_node
    // below is never reached for a rejected resolve.
    high_water
        .enforce_resolved(EnforceResolvedParams {
            node_id: ipns_name.to_string(),
            seq: fetched.sequence_number as i64,
            generation: expected_generation,
            version_floor: expected_version_floor,
        })
        .await
        .map_err(|e| ListingError::Gated(ipns_name.to_string(), e))?;

    let published = decode_published_node(&fetched.bytes)?;
    Ok((published, fetched.sequence_number))
}

// ---------------------------------------------------------------------------
// list_folder / list_shared_folder — the single gated read entrypoint
// ---------------------------------------------------------------------------

/// Resolves the folder Node at `ipns_name` (gated), unseals it with
/// `folder_read_key`, and returns one `ResolvedChild` per child.
///
/// The folder's OWN resolve is gated using the generation floor
/// `high_water` already tracks for `ipns_name` (defaulting to 0 on first
/// contact) — mirroring the TS `ensureRootFolderState` gate: there is no
/// parent mirror for the folder being listed directly, only for ITS
/// CHILDREN (handled below).
///
/// Each child hop is gated using the PARENT's `SealedChildRef.generation`/
/// `.version_floor` mirror (Pitfall 4 / M1) — never the child's own
/// envelope generation. A regressed child fails the WHOLE listing closed
/// (`Err`, no partial `Vec` returned).
///
/// On success, invokes `on_updated` (if provided) with a `folder:updated`-analog
/// event carrying the resolved children, so FUSE/WinFsp can refresh a
/// projection (68.2 imperative-pull + event-push mirror).
pub async fn list_folder<F, S>(
    fetcher: &F,
    high_water: &RotationHighWater<S>,
    ipns_name: &str,
    folder_read_key: &[u8; 32],
    on_updated: Option<FolderUpdatedCallback<'_>>,
) -> Result<Vec<ResolvedChild>, ListingError>
where
    F: NodeFetcher,
    S: HighWaterStore,
{
    let own_generation = high_water
        .get_generation_floor(ipns_name)
        .await
        .unwrap_or(0) as i64;

    let (published, _own_sequence) =
        resolve_published_node(fetcher, high_water, ipns_name, own_generation, 0).await?;

    let kind = node_kind_from_str(&published.kind)?;
    let read_sealed_bytes = decode_b64(&published.read_sealed)?;
    let body = seal::unseal_node(
        &read_sealed_bytes,
        folder_read_key,
        &published.id,
        kind,
        published.generation,
    )?;
    let node = decode_node(&body)?;

    let children: &Vec<SealedChildRef> = match &node {
        Node::Folder { children, .. } | Node::Root { children, .. } => children,
        Node::File { .. } => return Err(ListingError::NotAFolder(ipns_name.to_string())),
    };

    let mut resolved = Vec::with_capacity(children.len());
    for child_ref in children {
        resolved.push(resolve_child(fetcher, high_water, folder_read_key, child_ref).await?);
    }

    if let Some(cb) = on_updated {
        cb(&FolderUpdatedEvent {
            ipns_name: ipns_name.to_string(),
            children: resolved.clone(),
        });
    }

    Ok(resolved)
}

/// Lists a grantee scope root the same way `list_folder` lists an owned
/// folder. One ECIES root unwrap has already happened upstream (share-grant
/// acceptance) to recover `grant_root_read_key`; from here on the walk is
/// symmetric hops through the identical gated resolve chain -- there is a
/// single internal resolver for both owned and shared listings (Claude's
/// Discretion, 69-CONTEXT.md).
pub async fn list_shared_folder<F, S>(
    fetcher: &F,
    high_water: &RotationHighWater<S>,
    grant_root_ipns_name: &str,
    grant_root_read_key: &[u8; 32],
    on_updated: Option<FolderUpdatedCallback<'_>>,
) -> Result<Vec<ResolvedChild>, ListingError>
where
    F: NodeFetcher,
    S: HighWaterStore,
{
    list_folder(
        fetcher,
        high_water,
        grant_root_ipns_name,
        grant_root_read_key,
        on_updated,
    )
    .await
}

/// Resolves one child hop: gate-first resolve (parent-mirror generation),
/// recover the child's readKey from the parent's `SealedChildRef.read_key_sealed`,
/// unseal the child's own node body, and assemble the `ResolvedChild`.
async fn resolve_child<F, S>(
    fetcher: &F,
    high_water: &RotationHighWater<S>,
    parent_read_key: &[u8; 32],
    child_ref: &SealedChildRef,
) -> Result<ResolvedChild, ListingError>
where
    F: NodeFetcher,
    S: HighWaterStore,
{
    // Pitfall 4 / M1: generation/version_floor sourced from the PARENT's
    // SealedChildRef mirror -- NEVER the child's own envelope generation
    // (which resolve_published_node has not even decoded yet at this point).
    let (published, sequence) = resolve_published_node(
        fetcher,
        high_water,
        &child_ref.ipns_name,
        child_ref.generation as i64,
        child_ref.version_floor as i64,
    )
    .await?;

    let kind = node_kind_from_str(&published.kind)?;

    // Generation-source rule (mirrors TS dfsFindFolder's unsealChildReadKey
    // call exactly): childRef.generation (parent mirror) is the AAD input,
    // NOT published.generation (child's own envelope generation).
    let sealed_read_key_bytes = decode_b64(&child_ref.read_key_sealed)?;
    let mut child_read_key_raw = seal::unseal_child_read_key(
        &sealed_read_key_bytes,
        parent_read_key,
        &published.id,
        kind,
        child_ref.generation,
    )?;
    if child_read_key_raw.len() != 32 {
        child_read_key_raw.zeroize();
        return Err(ListingError::Node(NodeError::InvalidFormat(
            "unsealed child read key is not 32 bytes".to_string(),
        )));
    }
    // We are the terminal owner of this minted key (D-09) -- copy into a
    // Zeroizing fixed buffer and wipe the intermediate Vec immediately.
    let mut child_read_key = Zeroizing::new([0u8; 32]);
    child_read_key.copy_from_slice(&child_read_key_raw);
    child_read_key_raw.zeroize();

    // The child's own body is sealed under its OWN envelope generation
    // (published.generation) -- distinct from the parent-mirror generation
    // used for the readKey unwrap AAD above (both roles are frozen, ADR 0003;
    // only the enforce_resolved gate input is parent-mirror-exclusive).
    let read_sealed_bytes = decode_b64(&published.read_sealed)?;
    let body = seal::unseal_node(
        &read_sealed_bytes,
        &child_read_key,
        &published.id,
        kind,
        published.generation,
    )?;
    let node = decode_node(&body)?;

    let (size, modified_at) = match &node {
        Node::File {
            content,
            modified_at,
            ..
        } => (Some(content.size), *modified_at),
        Node::Folder { modified_at, .. } | Node::Root { modified_at, .. } => (None, *modified_at),
    };

    Ok(ResolvedChild {
        ipns_name: child_ref.ipns_name.clone(),
        name: child_ref.name.clone(),
        kind,
        size,
        modified_at,
        sequence,
    })
}

// ---------------------------------------------------------------------------
// Owned materialization — resolve_owned_child / list_folder_owned
// ---------------------------------------------------------------------------

/// Owned twin of [`resolve_child`]: resolves one child hop through the SAME
/// gated `resolve_published_node` chain, then recovers the FULL owned write
/// material for the child — its `read_key` (under `parent_read_key`), its
/// `write_key` (under `parent_write_key`, the half `resolve_child` discards),
/// and its own `ipns_private_key` (from the child's sealed write-body). This
/// is the per-child materialization the P1b FUSE `populate_folder` consumes
/// to build `InodeKind`.
///
/// D-07 dual-keying: the read-plane `SealedChildRef` (keyed by `ipns_name`)
/// is paired with the write-plane `WriteChildRef` (keyed by `child_id`, a
/// UUID) by the CHILD NODE IDENTITY — `published.id == WriteChildRef.child_id`
/// — NEVER by treating `ipns_name` as the pairing key. No matching
/// `WriteChildRef` fails the child closed (`Err`).
///
/// Fail-closed: any unseal auth-tag failure, a non-32-byte unsealed key, a
/// missing D-07 pair, or an absent `write_sealed` returns `Err` (never a
/// panic/unwrap).
///
/// Terminal owner (D-09): `parent_read_key`/`parent_write_key` are borrowed
/// and NEVER zeroed here. The recovered keys are returned RAW (in `Zeroizing`)
/// to the caller which is their terminal owner. Only this module's own scratch
/// intermediates are zeroed (mirroring `resolve_child`).
pub(crate) async fn resolve_owned_child<F, S>(
    fetcher: &F,
    high_water: &RotationHighWater<S>,
    parent_read_key: &[u8; 32],
    parent_write_key: &[u8; 32],
    child_ref: &SealedChildRef,
    parent_write_children: &[WriteChildRef],
) -> Result<ResolvedOwnedChild, ListingError>
where
    F: NodeFetcher,
    S: HighWaterStore,
{
    // Pitfall 4 / M1: gate generation/version_floor are the PARENT's
    // SealedChildRef mirror -- NEVER the child's own envelope generation.
    let (published, sequence) = resolve_published_node(
        fetcher,
        high_water,
        &child_ref.ipns_name,
        child_ref.generation as i64,
        child_ref.version_floor as i64,
    )
    .await?;

    let kind = node_kind_from_str(&published.kind)?;

    // D-07 pairing: read plane (SealedChildRef, by ipns_name) <-> write plane
    // (WriteChildRef, by child_id UUID), matched by the CHILD NODE IDENTITY
    // (published.id == child_id). ipns_name is NEVER the pairing key. No match
    // fails the child closed.
    let write_child_ref = parent_write_children
        .iter()
        .find(|w| w.child_id == published.id)
        .ok_or_else(|| {
            ListingError::Node(NodeError::InvalidFormat(format!(
                "no WriteChildRef paired with child node id {} (D-07 read/write pairing failed)",
                published.id
            )))
        })?;

    // Recover the child read_key (parent-mirror generation AAD), copy into a
    // Zeroizing fixed buffer, wipe the intermediate immediately (terminal
    // owner of this minted scratch, mirroring resolve_child at :314-324).
    let sealed_read_key_bytes = decode_b64(&child_ref.read_key_sealed)?;
    let mut child_read_key_raw = seal::unseal_child_read_key(
        &sealed_read_key_bytes,
        parent_read_key,
        &published.id,
        kind,
        child_ref.generation,
    )?;
    if child_read_key_raw.len() != 32 {
        child_read_key_raw.zeroize();
        return Err(ListingError::Node(NodeError::InvalidFormat(
            "unsealed child read key is not 32 bytes".to_string(),
        )));
    }
    let mut read_key = Zeroizing::new([0u8; 32]);
    read_key.copy_from_slice(&child_read_key_raw);
    child_read_key_raw.zeroize();

    // Recover the child write_key (the half list_folder discards) under the
    // parent WRITE key, same parent-mirror generation AAD, same copy+wipe.
    let sealed_write_key_bytes = decode_b64(&write_child_ref.write_key_sealed)?;
    let mut child_write_key_raw = seal::unseal_child_write_key(
        &sealed_write_key_bytes,
        parent_write_key,
        &published.id,
        kind,
        child_ref.generation,
    )?;
    if child_write_key_raw.len() != 32 {
        child_write_key_raw.zeroize();
        return Err(ListingError::Node(NodeError::InvalidFormat(
            "unsealed child write key is not 32 bytes".to_string(),
        )));
    }
    let mut write_key = Zeroizing::new([0u8; 32]);
    write_key.copy_from_slice(&child_write_key_raw);
    child_write_key_raw.zeroize();

    // Unseal the read-body (child's OWN envelope generation) for size/modified_at.
    let read_sealed_bytes = decode_b64(&published.read_sealed)?;
    let body = seal::unseal_node(
        &read_sealed_bytes,
        &read_key,
        &published.id,
        kind,
        published.generation,
    )?;
    let node = decode_node(&body)?;
    let (size, modified_at) = match &node {
        Node::File {
            content,
            modified_at,
            ..
        } => (Some(content.size), *modified_at),
        Node::Folder { modified_at, .. } | Node::Root { modified_at, .. } => (None, *modified_at),
    };

    // An owned walk REQUIRES the write-body -- fail closed if absent.
    let write_sealed = published.write_sealed.as_ref().ok_or_else(|| {
        ListingError::Node(NodeError::InvalidFormat(format!(
            "owned child {} has no write_sealed body (owned walk requires the write body)",
            published.id
        )))
    })?;
    let write_sealed_bytes = decode_b64(write_sealed)?;
    // The write-body plaintext carries the ipns_private_key -- own it in a
    // Zeroizing scratch so it is wiped once we move the key out.
    let write_body_bytes = Zeroizing::new(seal::unseal_node(
        &write_sealed_bytes,
        &write_key,
        &published.id,
        kind,
        published.generation,
    )?);
    let write_body = decode_write_body(&write_body_bytes)?;
    let ipns_private_key = Zeroizing::new(write_body.ipns_private_key);

    Ok(ResolvedOwnedChild {
        child: ResolvedChild {
            ipns_name: child_ref.ipns_name.clone(),
            name: child_ref.name.clone(),
            kind,
            size,
            modified_at,
            sequence,
        },
        // D-07: the child's own STABLE id (already used as the pairing key above).
        // This is what the caller must persist so a re-published parent keys the
        // child's WriteChildRef by the real node id, not a local inode number.
        node_id: published.id.clone(),
        read_key,
        write_key,
        ipns_private_key,
    })
}

/// Owned twin of [`list_folder`]: materializes an EXISTING tree's per-child
/// owned `{read_key, write_key, ipns_private_key}` through the SAME
/// `NodeFetcher` + `RotationHighWater::enforce_resolved` gate (SC#6 — no raw
/// resolve; `resolve_published_node` stays `pub(crate)`).
///
/// Unlike `list_folder` (read-only, unseals only the parent READ-body), this
/// ALSO unseals the parent WRITE-body (`folder_write_key`) to recover
/// `write_children: Vec<WriteChildRef>` so the D-07 read/write pairing is
/// possible. An owned walk REQUIRES the write body — a folder with no
/// `write_sealed` fails closed.
///
/// No `on_updated` callback: key material must NEVER fan out to a callback/
/// event/log — this is the mount's internal materialization, not a projection
/// push. The parent `folder_read_key`/`folder_write_key` are borrowed and
/// never zeroed (terminal owner, D-09).
pub async fn list_folder_owned<F, S>(
    fetcher: &F,
    high_water: &RotationHighWater<S>,
    ipns_name: &str,
    folder_read_key: &[u8; 32],
    folder_write_key: &[u8; 32],
) -> Result<Vec<ResolvedOwnedChild>, ListingError>
where
    F: NodeFetcher,
    S: HighWaterStore,
{
    let own_generation = high_water
        .get_generation_floor(ipns_name)
        .await
        .unwrap_or(0) as i64;

    let (published, _own_sequence) =
        resolve_published_node(fetcher, high_water, ipns_name, own_generation, 0).await?;

    let kind = node_kind_from_str(&published.kind)?;

    // Parent READ-body -> children (SealedChildRef, read plane).
    let read_sealed_bytes = decode_b64(&published.read_sealed)?;
    let read_body = seal::unseal_node(
        &read_sealed_bytes,
        folder_read_key,
        &published.id,
        kind,
        published.generation,
    )?;
    let node = decode_node(&read_body)?;
    let children: &Vec<SealedChildRef> = match &node {
        Node::Folder { children, .. } | Node::Root { children, .. } => children,
        Node::File { .. } => return Err(ListingError::NotAFolder(ipns_name.to_string())),
    };

    // Parent WRITE-body -> write_children (WriteChildRef, write plane) for the
    // D-07 pairing. An owned walk REQUIRES the write body -- fail closed.
    let write_sealed = published.write_sealed.as_ref().ok_or_else(|| {
        ListingError::Node(NodeError::InvalidFormat(format!(
            "owned folder {} has no write_sealed body (owned walk requires the write body)",
            published.id
        )))
    })?;
    let write_sealed_bytes = decode_b64(write_sealed)?;
    let write_body_bytes = Zeroizing::new(seal::unseal_node(
        &write_sealed_bytes,
        folder_write_key,
        &published.id,
        kind,
        published.generation,
    )?);
    let write_children = decode_write_body(&write_body_bytes)?.write_children;

    let mut resolved = Vec::with_capacity(children.len());
    for child_ref in children {
        resolved.push(
            resolve_owned_child(
                fetcher,
                high_water,
                folder_read_key,
                folder_write_key,
                child_ref,
                &write_children,
            )
            .await?,
        );
    }

    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Single-node gated fetch — the sanctioned single-node read entrypoint (SC#6)
// ---------------------------------------------------------------------------

/// Resolves a SINGLE node envelope at `ipns_name` through the SAME gate-first
/// chain as `list_folder`/`list_folder_owned` (SC#6 — no raw resolve leaks to
/// consumers; the raw resolve primitive stays `pub(crate)`).
///
/// This is the ONLY sanctioned way for a consumer (the FUSE mount's file
/// CONTENT read + journal replay) to obtain a node's own [`PublishedNode`]
/// envelope: `list_folder`/`list_folder_owned` reject a file node (they list
/// CHILDREN of a folder), but the content-decrypt path needs the file node's
/// own envelope. This wrapper gates the node's OWN resolve exactly as
/// `list_folder` gates the folder it lists — using the generation floor the
/// `high_water` already tracks for `ipns_name` (defaulting to 0 on first
/// contact) — and returns the decoded envelope only on a passing gate.
///
/// GATE-FIRST (T-69-06-01): `enforce_resolved` runs BEFORE the fetched bytes
/// are decoded (inside `resolve_published_node`); a regressed generation/seq
/// fails closed (`Err`). No new raw-resolve public surface is added — this is
/// the single additional gated entrypoint beyond `list_folder`/
/// `list_shared_folder`/`list_folder_owned`.
pub async fn fetch_node_gated<F, S>(
    fetcher: &F,
    high_water: &RotationHighWater<S>,
    ipns_name: &str,
) -> Result<PublishedNode, ListingError>
where
    F: NodeFetcher,
    S: HighWaterStore,
{
    let own_generation = high_water
        .get_generation_floor(ipns_name)
        .await
        .unwrap_or(0) as i64;

    let (published, _own_sequence) =
        resolve_published_node(fetcher, high_water, ipns_name, own_generation, 0).await?;

    Ok(published)
}

// ---------------------------------------------------------------------------
// Wire-format helpers
// ---------------------------------------------------------------------------

fn decode_b64(s: &str) -> Result<Vec<u8>, ListingError> {
    STANDARD.decode(s).map_err(|e| {
        ListingError::Node(NodeError::DeserializationFailed(format!(
            "base64 decode failed: {e}"
        )))
    })
}

fn node_kind_from_str(kind: &str) -> Result<NodeKind, ListingError> {
    match kind {
        "folder" => Ok(NodeKind::Folder),
        "file" => Ok(NodeKind::File),
        "root" => Ok(NodeKind::Root),
        other => Err(ListingError::InvalidKind(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::{
        build_child_refs, build_file_emission, build_folder_emission, FolderEmission,
    };
    use cipherbox_core::node::{
        encode_node, encode_published_node, NodeContent, NodeWriteBody, VersionEntry,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory HashMap-backed high-water store (mirrors `high_water.rs`'s
    /// own `MemStore` test fixture -- not exported, so redefined locally).
    #[derive(Default)]
    struct MemStore(Mutex<HashMap<String, u64>>);

    impl HighWaterStore for MemStore {
        async fn get(&self, node_id: &str) -> Option<u64> {
            self.0.lock().unwrap().get(node_id).copied()
        }

        async fn put(&self, node_id: &str, value: u64) {
            self.0.lock().unwrap().insert(node_id.to_string(), value);
        }
    }

    fn rhw() -> RotationHighWater<MemStore> {
        RotationHighWater::new(MemStore::default(), MemStore::default())
    }

    /// In-memory fetcher fixture: a fixed map of ipns_name -> FetchedRecord.
    #[derive(Default)]
    struct FakeFetcher(HashMap<String, FetchedRecord>);

    impl NodeFetcher for FakeFetcher {
        async fn fetch(&self, ipns_name: &str) -> Result<FetchedRecord, ListingError> {
            self.0
                .get(ipns_name)
                .cloned()
                .ok_or_else(|| ListingError::FetchFailed {
                    ipns_name: ipns_name.to_string(),
                    message: "not found in fixture".to_string(),
                })
        }
    }

    /// Builds a sealed, base64-encoded read-body for `node` under `read_key`.
    fn seal_body_b64(node: &Node, read_key: &[u8; 32]) -> String {
        let body = encode_node(node).unwrap();
        let sealed =
            seal::seal_node(&body, read_key, node.id(), node.kind(), node.generation()).unwrap();
        STANDARD.encode(sealed)
    }

    /// Builds a `PublishedNode` envelope + its serialized bytes for a FetchedRecord.
    fn published_bytes(node: &Node, read_key: &[u8; 32]) -> Vec<u8> {
        let published = PublishedNode {
            schema: "node/v3".to_string(),
            kind: node.kind().as_str().to_string(),
            id: node.id().to_string(),
            generation: node.generation(),
            aead_version: 1,
            read_sealed: seal_body_b64(node, read_key),
            write_sealed: None,
        };
        encode_published_node(&published).unwrap()
    }

    /// Builds a base64 `read_key_sealed` for a `SealedChildRef`, using
    /// `mirror_generation` as the AAD input (the PARENT mirror value --
    /// tests exercise mismatches against the child's own envelope generation).
    fn seal_child_key_b64(
        child_read_key: &[u8; 32],
        parent_read_key: &[u8; 32],
        child_id: &str,
        child_kind: NodeKind,
        mirror_generation: u32,
    ) -> String {
        let sealed = seal::seal_child_read_key(
            child_read_key,
            parent_read_key,
            child_id,
            child_kind,
            mirror_generation,
        )
        .unwrap();
        STANDARD.encode(sealed)
    }

    fn file_node(id: &str, generation: u32, modified_at: u64, size: u64) -> Node {
        Node::File {
            id: id.to_string(),
            generation,
            created_at: 1_000,
            modified_at,
            content: NodeContent {
                cid: "cid-1".to_string(),
                file_iv: "iv-1".to_string(),
                size,
                mime_type: "text/plain".to_string(),
                encryption_mode: "GCM".to_string(),
                file_key: vec![1u8; 32],
                versions: Vec::<VersionEntry>::new(),
            },
        }
    }

    fn folder_node(
        id: &str,
        generation: u32,
        modified_at: u64,
        children: Vec<SealedChildRef>,
    ) -> Node {
        Node::Folder {
            id: id.to_string(),
            generation,
            created_at: 1_000,
            modified_at,
            children,
        }
    }

    // -----------------------------------------------------------------
    // Happy path: list_folder resolves a file child and a folder child.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn list_folder_returns_resolved_children_for_file_and_folder() {
        let parent_read_key = [7u8; 32];
        let file_read_key = [9u8; 32];
        let folder_read_key = [11u8; 32];

        let file = file_node("7a6af220-e1ee-5448-8be8-009e69732449", 3, 2_000, 555);
        let subfolder = folder_node("64673756-1ce5-572b-abd8-02eb6707b1da", 0, 3_000, vec![]);

        let child_file_ref = SealedChildRef {
            name: "hello.txt".to_string(),
            ipns_name: "ipns-file-1".to_string(),
            generation: 3,
            version_floor: 0,
            read_key_sealed: seal_child_key_b64(
                &file_read_key,
                &parent_read_key,
                "7a6af220-e1ee-5448-8be8-009e69732449",
                NodeKind::File,
                3,
            ),
        };
        let child_folder_ref = SealedChildRef {
            name: "subdir".to_string(),
            ipns_name: "ipns-folder-2".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: seal_child_key_b64(
                &folder_read_key,
                &parent_read_key,
                "64673756-1ce5-572b-abd8-02eb6707b1da",
                NodeKind::Folder,
                0,
            ),
        };

        let parent = folder_node(
            "56147b38-f729-5672-82b9-2eb3f985e284",
            0,
            5_000,
            vec![child_file_ref, child_folder_ref],
        );

        let fetcher = FakeFetcher(HashMap::from([
            (
                "ipns-parent".to_string(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: published_bytes(&parent, &parent_read_key),
                },
            ),
            (
                "ipns-file-1".to_string(),
                FetchedRecord {
                    sequence_number: 10,
                    bytes: published_bytes(&file, &file_read_key),
                },
            ),
            (
                "ipns-folder-2".to_string(),
                FetchedRecord {
                    sequence_number: 4,
                    bytes: published_bytes(&subfolder, &folder_read_key),
                },
            ),
        ]));

        let high_water = rhw();

        let children = list_folder(&fetcher, &high_water, "ipns-parent", &parent_read_key, None)
            .await
            .expect("list_folder should succeed");

        assert_eq!(children.len(), 2);

        assert_eq!(children[0].ipns_name, "ipns-file-1");
        assert_eq!(children[0].name, "hello.txt");
        assert_eq!(children[0].kind, NodeKind::File);
        assert_eq!(children[0].size, Some(555));
        assert_eq!(children[0].modified_at, 2_000);
        assert_eq!(children[0].sequence, 10);

        assert_eq!(children[1].ipns_name, "ipns-folder-2");
        assert_eq!(children[1].name, "subdir");
        assert_eq!(children[1].kind, NodeKind::Folder);
        assert_eq!(children[1].size, None);
        assert_eq!(children[1].modified_at, 3_000);
        assert_eq!(children[1].sequence, 4);
    }

    // -----------------------------------------------------------------
    // Pitfall 4 / M1: cold-child generation sourced from the PARENT
    // SealedChildRef mirror, never the child's own envelope generation.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn cold_child_generation_sourced_from_parent_mirror_not_child_envelope() {
        let parent_read_key = [3u8; 32];
        let child_read_key = [5u8; 32];

        // Child's OWN envelope generation is 2 -- but the PARENT mirror
        // (SealedChildRef.generation) says 5. Pre-seed the high-water floor
        // for this child's node_id at exactly 5: a correct implementation
        // (sourcing `generation` from the parent mirror = 5) passes the
        // gate (5 is not < floor 5); a buggy implementation that used the
        // child's own envelope generation (2) would be rejected as a
        // regression against the floor (2 < 5).
        let child = file_node("54d1eca0-c5c4-5d58-8b42-4d3ea13070dd", 2, 9_000, 42);
        let child_ref = SealedChildRef {
            name: "cold.bin".to_string(),
            ipns_name: "ipns-child-x".to_string(),
            generation: 5,
            version_floor: 0,
            // AAD-bound at generation=5 (parent mirror) -- matches what
            // dfsFindFolder's unsealChildReadKey call uses (childRef.generation).
            read_key_sealed: seal_child_key_b64(
                &child_read_key,
                &parent_read_key,
                "54d1eca0-c5c4-5d58-8b42-4d3ea13070dd",
                NodeKind::File,
                5,
            ),
        };
        let parent = folder_node(
            "56147b38-f729-5672-82b9-2eb3f985e284",
            0,
            5_000,
            vec![child_ref],
        );

        let fetcher = FakeFetcher(HashMap::from([
            (
                "ipns-parent".to_string(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: published_bytes(&parent, &parent_read_key),
                },
            ),
            (
                "ipns-child-x".to_string(),
                FetchedRecord {
                    sequence_number: 20,
                    bytes: published_bytes(&child, &child_read_key),
                },
            ),
        ]));

        let high_water = rhw();
        high_water.bump_generation("ipns-child-x", 5).await;

        let result =
            list_folder(&fetcher, &high_water, "ipns-parent", &parent_read_key, None).await;

        assert!(
            result.is_ok(),
            "expected Ok when generation is correctly sourced from the parent \
             SealedChildRef mirror (5); a bug sourcing it from the child's own \
             envelope generation (2) would reject this as a regression against \
             the pre-seeded floor of 5. Got: {:?}",
            result
        );
        let children = result.unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].ipns_name, "ipns-child-x");
        assert_eq!(children[0].sequence, 20);
    }

    // -----------------------------------------------------------------
    // Gate-first + fail-closed: a regressed child rejects the WHOLE
    // listing, and the gate runs BEFORE the (undecodable) bytes are ever
    // touched.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn gate_rejects_regression_before_touching_undecodable_bytes() {
        let parent_read_key = [13u8; 32];

        // The parent mirror claims generation=2 for this child, but the
        // high-water floor already sits at 10 (established by an earlier,
        // more-advanced resolve). This must be rejected BEFORE
        // decode_published_node ever runs -- proven by giving the fetcher
        // garbage (non-JSON) bytes for this child: if decode ran first we'd
        // see a `ListingError::Node` decode failure instead of `Gated`.
        let child_ref = SealedChildRef {
            name: "regressed.bin".to_string(),
            ipns_name: "ipns-child-y".to_string(),
            generation: 2,
            version_floor: 0,
            read_key_sealed: STANDARD.encode(b"not-a-real-sealed-key"),
        };
        let parent = folder_node(
            "56147b38-f729-5672-82b9-2eb3f985e284",
            0,
            5_000,
            vec![child_ref],
        );

        let fetcher = FakeFetcher(HashMap::from([
            (
                "ipns-parent".to_string(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: published_bytes(&parent, &parent_read_key),
                },
            ),
            (
                "ipns-child-y".to_string(),
                FetchedRecord {
                    sequence_number: 99,
                    bytes: b"this is not valid PublishedNode JSON".to_vec(),
                },
            ),
        ]));

        let high_water = rhw();
        high_water.bump_generation("ipns-child-y", 10).await;

        let result =
            list_folder(&fetcher, &high_water, "ipns-parent", &parent_read_key, None).await;

        match result {
            Err(ListingError::Gated(ipns_name, RotationError::GenerationRegression { .. })) => {
                assert_eq!(ipns_name, "ipns-child-y");
            }
            other => panic!(
                "expected ListingError::Gated(.., GenerationRegression) proving the \
                 gate ran BEFORE decode_published_node touched the undecodable bytes; \
                 got: {:?}",
                other
            ),
        }
    }

    // -----------------------------------------------------------------
    // folder:updated-analog event fires on a successful listing.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn folder_updated_event_fires_with_resolved_children() {
        let parent_read_key = [21u8; 32];
        let file_read_key = [22u8; 32];

        let file = file_node("7a6af220-e1ee-5448-8be8-009e69732449", 0, 2_000, 100);
        let child_ref = SealedChildRef {
            name: "hello.txt".to_string(),
            ipns_name: "ipns-file-1".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: seal_child_key_b64(
                &file_read_key,
                &parent_read_key,
                "7a6af220-e1ee-5448-8be8-009e69732449",
                NodeKind::File,
                0,
            ),
        };
        let parent = folder_node(
            "56147b38-f729-5672-82b9-2eb3f985e284",
            0,
            5_000,
            vec![child_ref],
        );

        let fetcher = FakeFetcher(HashMap::from([
            (
                "ipns-parent".to_string(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: published_bytes(&parent, &parent_read_key),
                },
            ),
            (
                "ipns-file-1".to_string(),
                FetchedRecord {
                    sequence_number: 7,
                    bytes: published_bytes(&file, &file_read_key),
                },
            ),
        ]));

        let high_water = rhw();
        let captured: Mutex<Vec<FolderUpdatedEvent>> = Mutex::new(Vec::new());
        let callback = |event: &FolderUpdatedEvent| {
            captured.lock().unwrap().push(event.clone());
        };

        let children = list_folder(
            &fetcher,
            &high_water,
            "ipns-parent",
            &parent_read_key,
            Some(&callback),
        )
        .await
        .expect("list_folder should succeed");

        let events = captured.into_inner().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ipns_name, "ipns-parent");
        assert_eq!(events[0].children, children);
    }

    // -----------------------------------------------------------------
    // list_shared_folder routes through the identical gated chain.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn list_shared_folder_uses_the_same_gated_chain_as_list_folder() {
        let grant_root_read_key = [31u8; 32];
        let file_read_key = [32u8; 32];

        let file = file_node("c201acee-b81f-5491-b584-a163ae01ec4a", 0, 2_500, 900);
        let child_ref = SealedChildRef {
            name: "shared.txt".to_string(),
            ipns_name: "ipns-shared-file-1".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: seal_child_key_b64(
                &file_read_key,
                &grant_root_read_key,
                "c201acee-b81f-5491-b584-a163ae01ec4a",
                NodeKind::File,
                0,
            ),
        };
        let grant_root = folder_node(
            "c1e6dd05-3d05-54cd-b7ad-864e44d62279",
            0,
            6_000,
            vec![child_ref],
        );

        let fetcher = FakeFetcher(HashMap::from([
            (
                "ipns-grant-root".to_string(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: published_bytes(&grant_root, &grant_root_read_key),
                },
            ),
            (
                "ipns-shared-file-1".to_string(),
                FetchedRecord {
                    sequence_number: 3,
                    bytes: published_bytes(&file, &file_read_key),
                },
            ),
        ]));

        let high_water = rhw();

        let children = list_shared_folder(
            &fetcher,
            &high_water,
            "ipns-grant-root",
            &grant_root_read_key,
            None,
        )
        .await
        .expect("list_shared_folder should succeed");

        assert_eq!(children.len(), 1);
        assert_eq!(children[0].ipns_name, "ipns-shared-file-1");
        assert_eq!(children[0].name, "shared.txt");
        assert_eq!(children[0].size, Some(900));
    }

    // -----------------------------------------------------------------
    // A file node is not listable (list_folder called on a leaf).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn listing_a_file_node_fails_with_not_a_folder() {
        let read_key = [41u8; 32];
        let file = file_node("a24526f8-50e9-5b44-8fbe-4b0afbbc0665", 0, 1_000, 10);

        let fetcher = FakeFetcher(HashMap::from([(
            "ipns-leaf".to_string(),
            FetchedRecord {
                sequence_number: 1,
                bytes: published_bytes(&file, &read_key),
            },
        )]));

        let high_water = rhw();
        let result = list_folder(&fetcher, &high_water, "ipns-leaf", &read_key, None).await;

        match result {
            Err(ListingError::NotAFolder(ipns_name)) => assert_eq!(ipns_name, "ipns-leaf"),
            other => panic!("expected NotAFolder, got: {:?}", other),
        }
    }

    // =================================================================
    // Owned materialization: resolve_owned_child / list_folder_owned
    // (69-17 — the write-plane recovery list_folder omits).
    // =================================================================

    /// A NodeContent builder for the owned-emission round-trip tests.
    fn owned_content(size: u64) -> NodeContent {
        NodeContent {
            cid: "cid-owned".to_string(),
            file_iv: "iv-owned".to_string(),
            size,
            mime_type: "text/plain".to_string(),
            encryption_mode: "GCM".to_string(),
            file_key: vec![9u8; 32],
            versions: Vec::<VersionEntry>::new(),
        }
    }

    /// Base64 `write_key_sealed` for a `WriteChildRef`, sealing `child_write_key`
    /// under `parent_write_key` at `mirror_generation` (the parent-mirror AAD).
    fn seal_child_write_key_b64(
        child_write_key: &[u8; 32],
        parent_write_key: &[u8; 32],
        child_id: &str,
        child_kind: NodeKind,
        mirror_generation: u32,
    ) -> String {
        let sealed = seal::seal_child_write_key(
            child_write_key,
            parent_write_key,
            child_id,
            child_kind,
            mirror_generation,
        )
        .unwrap();
        STANDARD.encode(sealed)
    }

    /// Re-seals a parent folder identity (from `parent_stub`) carrying exactly
    /// the given read/write child refs -- returns the encoded PublishedNode
    /// bytes (the "add children to an existing folder" step, mirroring the
    /// emit.rs round-trip fixture idiom).
    fn parent_published_with_children(
        parent_stub: &FolderEmission,
        parent_read_key: &[u8; 32],
        parent_write_key: &[u8; 32],
        children: Vec<SealedChildRef>,
        write_children: Vec<WriteChildRef>,
    ) -> Vec<u8> {
        let parent_node = Node::Folder {
            id: parent_stub.id.clone(),
            generation: 0,
            created_at: 1_000,
            modified_at: 5_000,
            children,
        };
        let write_body = NodeWriteBody {
            ipns_private_key: parent_stub.ipns_private_key.clone(),
            write_children,
        };
        let published = seal::seal_published_node(
            &parent_node,
            parent_read_key,
            parent_write_key,
            Some(&write_body),
        )
        .expect("re-seal parent ok");
        encode_published_node(&published).expect("encode ok")
    }

    // -----------------------------------------------------------------
    // Single-child owned recovery: recovered read/write/ipns keys equal
    // exactly what emit.rs minted.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn resolve_owned_child_recovers_minted_read_write_ipns_keys() {
        let child = build_file_emission(owned_content(777)).unwrap();
        let parent_read_key = [61u8; 32];
        let parent_write_key = [62u8; 32];
        let child_read_key: [u8; 32] = child.read_key.clone().try_into().unwrap();
        let child_write_key: [u8; 32] = child.write_key.clone().try_into().unwrap();

        let (sealed_ref, write_ref) = build_child_refs(
            &child_read_key,
            &child_write_key,
            &parent_read_key,
            &parent_write_key,
            &child.id,
            &child.ipns_name,
            "hello.txt",
            NodeKind::File,
            0,
            0,
        )
        .unwrap();

        let fetcher = FakeFetcher(HashMap::from([(
            child.ipns_name.clone(),
            FetchedRecord {
                sequence_number: 5,
                bytes: child.published_node.clone(),
            },
        )]));
        let high_water = rhw();

        let resolved = resolve_owned_child(
            &fetcher,
            &high_water,
            &parent_read_key,
            &parent_write_key,
            &sealed_ref,
            std::slice::from_ref(&write_ref),
        )
        .await
        .expect("resolve_owned_child should succeed");

        assert_eq!(&resolved.read_key[..], child.read_key.as_slice());
        assert_eq!(&resolved.write_key[..], child.write_key.as_slice());
        assert_eq!(
            resolved.ipns_private_key.as_slice(),
            child.ipns_private_key.as_slice()
        );
        assert_eq!(resolved.child.ipns_name, child.ipns_name);
        assert_eq!(resolved.child.name, "hello.txt");
        assert_eq!(resolved.child.kind, NodeKind::File);
        assert_eq!(resolved.child.size, Some(777));
        assert_eq!(resolved.child.sequence, 5);
    }

    // -----------------------------------------------------------------
    // D-07: pairing is by the child node identity (published.id ==
    // WriteChildRef.child_id) -- an ipns_name-keyed WriteChildRef fails
    // closed; the UUID-keyed one pairs.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn resolve_owned_child_pairs_by_published_id_never_by_ipns_name() {
        let child = build_file_emission(owned_content(10)).unwrap();
        let parent_read_key = [71u8; 32];
        let parent_write_key = [72u8; 32];
        let child_read_key: [u8; 32] = child.read_key.clone().try_into().unwrap();
        let child_write_key: [u8; 32] = child.write_key.clone().try_into().unwrap();

        let (sealed_ref, correct_write_ref) = build_child_refs(
            &child_read_key,
            &child_write_key,
            &parent_read_key,
            &parent_write_key,
            &child.id,
            &child.ipns_name,
            "file.bin",
            NodeKind::File,
            0,
            0,
        )
        .unwrap();

        let fetcher = FakeFetcher(HashMap::from([(
            child.ipns_name.clone(),
            FetchedRecord {
                sequence_number: 1,
                bytes: child.published_node.clone(),
            },
        )]));

        // A WriteChildRef keyed by the child's IPNS name (a k51) instead of
        // its UUID must NOT pair -- pairing is by published.id, never ipns_name.
        let mis_keyed = WriteChildRef {
            child_id: child.ipns_name.clone(),
            write_key_sealed: correct_write_ref.write_key_sealed.clone(),
        };
        let high_water = rhw();
        let err = resolve_owned_child(
            &fetcher,
            &high_water,
            &parent_read_key,
            &parent_write_key,
            &sealed_ref,
            std::slice::from_ref(&mis_keyed),
        )
        .await;
        assert!(
            matches!(err, Err(ListingError::Node(_))),
            "an ipns_name-keyed WriteChildRef must fail the pairing closed; got {:?}",
            err
        );

        // The correctly UUID-keyed WriteChildRef pairs and recovers.
        let high_water2 = rhw();
        let ok = resolve_owned_child(
            &fetcher,
            &high_water2,
            &parent_read_key,
            &parent_write_key,
            &sealed_ref,
            std::slice::from_ref(&correct_write_ref),
        )
        .await;
        assert!(
            ok.is_ok(),
            "UUID-keyed pairing should succeed; got {:?}",
            ok
        );
    }

    // -----------------------------------------------------------------
    // D-07 missing pair: no WriteChildRef for the child fails closed.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn resolve_owned_child_missing_write_pair_fails_closed() {
        let child = build_file_emission(owned_content(3)).unwrap();
        let parent_read_key = [73u8; 32];
        let parent_write_key = [74u8; 32];
        let child_read_key: [u8; 32] = child.read_key.clone().try_into().unwrap();
        let child_write_key: [u8; 32] = child.write_key.clone().try_into().unwrap();

        let (sealed_ref, _write_ref) = build_child_refs(
            &child_read_key,
            &child_write_key,
            &parent_read_key,
            &parent_write_key,
            &child.id,
            &child.ipns_name,
            "orphan.bin",
            NodeKind::File,
            0,
            0,
        )
        .unwrap();

        let fetcher = FakeFetcher(HashMap::from([(
            child.ipns_name.clone(),
            FetchedRecord {
                sequence_number: 1,
                bytes: child.published_node.clone(),
            },
        )]));
        let high_water = rhw();

        // Empty write-children slice -> no D-07 pair -> fail closed.
        let result = resolve_owned_child(
            &fetcher,
            &high_water,
            &parent_read_key,
            &parent_write_key,
            &sealed_ref,
            &[],
        )
        .await;
        assert!(
            matches!(result, Err(ListingError::Node(_))),
            "a missing D-07 write pair must fail closed; got {:?}",
            result
        );
    }

    // -----------------------------------------------------------------
    // write_sealed = None fails closed (an owned walk needs the write body).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn resolve_owned_child_write_sealed_none_fails_closed() {
        let parent_read_key = [50u8; 32];
        let parent_write_key = [51u8; 32];
        let child_read_key = [52u8; 32];
        let child_write_key = [53u8; 32];
        let child_id = "54d1eca0-c5c4-5d58-8b42-4d3ea13070dd";

        // published_bytes builds a PublishedNode with write_sealed = None.
        let child = file_node(child_id, 0, 1_000, 10);
        let child_ref = SealedChildRef {
            name: "leaf.bin".to_string(),
            ipns_name: "ipns-no-write".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: seal_child_key_b64(
                &child_read_key,
                &parent_read_key,
                child_id,
                NodeKind::File,
                0,
            ),
        };
        let write_ref = WriteChildRef {
            child_id: child_id.to_string(),
            write_key_sealed: seal_child_write_key_b64(
                &child_write_key,
                &parent_write_key,
                child_id,
                NodeKind::File,
                0,
            ),
        };

        let fetcher = FakeFetcher(HashMap::from([(
            "ipns-no-write".to_string(),
            FetchedRecord {
                sequence_number: 1,
                bytes: published_bytes(&child, &child_read_key),
            },
        )]));
        let high_water = rhw();

        let result = resolve_owned_child(
            &fetcher,
            &high_water,
            &parent_read_key,
            &parent_write_key,
            &child_ref,
            std::slice::from_ref(&write_ref),
        )
        .await;
        assert!(
            matches!(result, Err(ListingError::Node(_))),
            "an absent write_sealed must fail closed; got {:?}",
            result
        );
    }

    // -----------------------------------------------------------------
    // Terminal owner (D-09): the caller-supplied parent read+write key
    // buffers are byte-unchanged after resolve_owned_child.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn resolve_owned_child_leaves_parent_key_buffers_unchanged() {
        let child = build_file_emission(owned_content(1)).unwrap();
        let parent_read_key = [81u8; 32];
        let parent_write_key = [82u8; 32];
        let parent_read_key_before = parent_read_key;
        let parent_write_key_before = parent_write_key;
        let child_read_key: [u8; 32] = child.read_key.clone().try_into().unwrap();
        let child_write_key: [u8; 32] = child.write_key.clone().try_into().unwrap();

        let (sealed_ref, write_ref) = build_child_refs(
            &child_read_key,
            &child_write_key,
            &parent_read_key,
            &parent_write_key,
            &child.id,
            &child.ipns_name,
            "file.bin",
            NodeKind::File,
            0,
            0,
        )
        .unwrap();

        let fetcher = FakeFetcher(HashMap::from([(
            child.ipns_name.clone(),
            FetchedRecord {
                sequence_number: 1,
                bytes: child.published_node.clone(),
            },
        )]));
        let high_water = rhw();

        let _ = resolve_owned_child(
            &fetcher,
            &high_water,
            &parent_read_key,
            &parent_write_key,
            &sealed_ref,
            std::slice::from_ref(&write_ref),
        )
        .await
        .expect("resolve_owned_child should succeed");

        assert_eq!(
            parent_read_key, parent_read_key_before,
            "resolve_owned_child must never mutate/zero the caller's parent_read_key"
        );
        assert_eq!(
            parent_write_key, parent_write_key_before,
            "resolve_owned_child must never mutate/zero the caller's parent_write_key"
        );
    }

    // -----------------------------------------------------------------
    // 2-level emit -> owned round-trip: list_folder_owned recovers each
    // child's read/write/ipns keys byte-equal to what emit.rs minted.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn list_folder_owned_two_level_round_trip_recovers_minted_keys() {
        let file_emission = build_file_emission(owned_content(777)).unwrap();
        let subfolder_emission = build_folder_emission(vec![], vec![], false).unwrap();
        let parent_stub = build_folder_emission(vec![], vec![], false).unwrap();

        let parent_read_key: [u8; 32] = parent_stub.read_key.clone().try_into().unwrap();
        let parent_write_key: [u8; 32] = parent_stub.write_key.clone().try_into().unwrap();
        let file_read_key: [u8; 32] = file_emission.read_key.clone().try_into().unwrap();
        let file_write_key: [u8; 32] = file_emission.write_key.clone().try_into().unwrap();
        let folder_read_key: [u8; 32] = subfolder_emission.read_key.clone().try_into().unwrap();
        let folder_write_key: [u8; 32] = subfolder_emission.write_key.clone().try_into().unwrap();

        let (file_sealed_ref, file_write_ref) = build_child_refs(
            &file_read_key,
            &file_write_key,
            &parent_read_key,
            &parent_write_key,
            &file_emission.id,
            &file_emission.ipns_name,
            "hello.txt",
            NodeKind::File,
            0,
            0,
        )
        .unwrap();
        let (folder_sealed_ref, folder_write_ref) = build_child_refs(
            &folder_read_key,
            &folder_write_key,
            &parent_read_key,
            &parent_write_key,
            &subfolder_emission.id,
            &subfolder_emission.ipns_name,
            "subdir",
            NodeKind::Folder,
            0,
            0,
        )
        .unwrap();

        let parent_bytes = parent_published_with_children(
            &parent_stub,
            &parent_read_key,
            &parent_write_key,
            vec![file_sealed_ref, folder_sealed_ref],
            vec![file_write_ref, folder_write_ref],
        );

        let fetcher = FakeFetcher(HashMap::from([
            (
                parent_stub.ipns_name.clone(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: parent_bytes,
                },
            ),
            (
                file_emission.ipns_name.clone(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: file_emission.published_node.clone(),
                },
            ),
            (
                subfolder_emission.ipns_name.clone(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: subfolder_emission.published_node.clone(),
                },
            ),
        ]));
        let high_water = rhw();

        let children = list_folder_owned(
            &fetcher,
            &high_water,
            &parent_stub.ipns_name,
            &parent_read_key,
            &parent_write_key,
        )
        .await
        .expect("list_folder_owned should succeed");

        assert_eq!(children.len(), 2);

        let f = children
            .iter()
            .find(|c| c.child.ipns_name == file_emission.ipns_name)
            .expect("file child resolved");
        assert_eq!(f.child.name, "hello.txt");
        assert_eq!(f.child.kind, NodeKind::File);
        assert_eq!(f.child.size, Some(777));
        assert_eq!(&f.read_key[..], file_emission.read_key.as_slice());
        assert_eq!(&f.write_key[..], file_emission.write_key.as_slice());
        assert_eq!(
            f.ipns_private_key.as_slice(),
            file_emission.ipns_private_key.as_slice()
        );

        let d = children
            .iter()
            .find(|c| c.child.ipns_name == subfolder_emission.ipns_name)
            .expect("folder child resolved");
        assert_eq!(d.child.name, "subdir");
        assert_eq!(d.child.kind, NodeKind::Folder);
        assert_eq!(d.child.size, None);
        assert_eq!(&d.read_key[..], subfolder_emission.read_key.as_slice());
        assert_eq!(&d.write_key[..], subfolder_emission.write_key.as_slice());
        assert_eq!(
            d.ipns_private_key.as_slice(),
            subfolder_emission.ipns_private_key.as_slice()
        );
    }

    // -----------------------------------------------------------------
    // High-water floor gate: a child whose parent-mirror generation is
    // below a pre-seeded floor fails the WHOLE owned listing closed.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn list_folder_owned_high_water_floor_gate_rejects_regressed_child() {
        let file_emission = build_file_emission(owned_content(42)).unwrap();
        let parent_stub = build_folder_emission(vec![], vec![], false).unwrap();

        let parent_read_key: [u8; 32] = parent_stub.read_key.clone().try_into().unwrap();
        let parent_write_key: [u8; 32] = parent_stub.write_key.clone().try_into().unwrap();
        let file_read_key: [u8; 32] = file_emission.read_key.clone().try_into().unwrap();
        let file_write_key: [u8; 32] = file_emission.write_key.clone().try_into().unwrap();

        let (file_sealed_ref, file_write_ref) = build_child_refs(
            &file_read_key,
            &file_write_key,
            &parent_read_key,
            &parent_write_key,
            &file_emission.id,
            &file_emission.ipns_name,
            "regressed.bin",
            NodeKind::File,
            0,
            0,
        )
        .unwrap();

        let parent_bytes = parent_published_with_children(
            &parent_stub,
            &parent_read_key,
            &parent_write_key,
            vec![file_sealed_ref],
            vec![file_write_ref],
        );

        let fetcher = FakeFetcher(HashMap::from([
            (
                parent_stub.ipns_name.clone(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: parent_bytes,
                },
            ),
            (
                file_emission.ipns_name.clone(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: file_emission.published_node.clone(),
                },
            ),
        ]));

        // Seed the child's floor at 5; its parent-mirror generation is 0 -> the
        // gate rejects it (0 < 5) BEFORE any owned unseal.
        let high_water = rhw();
        high_water
            .bump_generation(&file_emission.ipns_name, 5)
            .await;

        let result = list_folder_owned(
            &fetcher,
            &high_water,
            &parent_stub.ipns_name,
            &parent_read_key,
            &parent_write_key,
        )
        .await;

        match result {
            Err(ListingError::Gated(name, RotationError::GenerationRegression { .. })) => {
                assert_eq!(name, file_emission.ipns_name);
            }
            other => panic!(
                "expected ListingError::Gated(.., GenerationRegression) for the regressed \
                 owned child; got: {:?}",
                other
            ),
        }
    }

    // -----------------------------------------------------------------
    // Terminal owner (D-09): parent read+write key buffers are unchanged
    // after list_folder_owned.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn list_folder_owned_leaves_parent_key_buffers_unchanged() {
        let file_emission = build_file_emission(owned_content(9)).unwrap();
        let parent_stub = build_folder_emission(vec![], vec![], false).unwrap();

        let parent_read_key: [u8; 32] = parent_stub.read_key.clone().try_into().unwrap();
        let parent_write_key: [u8; 32] = parent_stub.write_key.clone().try_into().unwrap();
        let parent_read_key_before = parent_read_key;
        let parent_write_key_before = parent_write_key;
        let file_read_key: [u8; 32] = file_emission.read_key.clone().try_into().unwrap();
        let file_write_key: [u8; 32] = file_emission.write_key.clone().try_into().unwrap();

        let (file_sealed_ref, file_write_ref) = build_child_refs(
            &file_read_key,
            &file_write_key,
            &parent_read_key,
            &parent_write_key,
            &file_emission.id,
            &file_emission.ipns_name,
            "keep.bin",
            NodeKind::File,
            0,
            0,
        )
        .unwrap();

        let parent_bytes = parent_published_with_children(
            &parent_stub,
            &parent_read_key,
            &parent_write_key,
            vec![file_sealed_ref],
            vec![file_write_ref],
        );

        let fetcher = FakeFetcher(HashMap::from([
            (
                parent_stub.ipns_name.clone(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: parent_bytes,
                },
            ),
            (
                file_emission.ipns_name.clone(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: file_emission.published_node.clone(),
                },
            ),
        ]));
        let high_water = rhw();

        let _ = list_folder_owned(
            &fetcher,
            &high_water,
            &parent_stub.ipns_name,
            &parent_read_key,
            &parent_write_key,
        )
        .await
        .expect("list_folder_owned should succeed");

        assert_eq!(
            parent_read_key, parent_read_key_before,
            "list_folder_owned must never mutate/zero the caller's folder_read_key"
        );
        assert_eq!(
            parent_write_key, parent_write_key_before,
            "list_folder_owned must never mutate/zero the caller's folder_write_key"
        );
    }

    // =================================================================
    // fetch_node_gated: the sanctioned single-node read entrypoint
    // (SC#6) — file CONTENT read + journal replay consume it.
    // =================================================================

    // -----------------------------------------------------------------
    // Happy path: round-trip an emitted file node's own PublishedNode
    // envelope through the gate.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn fetch_node_gated_round_trips_an_emitted_file_node() {
        let file_emission = build_file_emission(owned_content(321)).unwrap();

        let fetcher = FakeFetcher(HashMap::from([(
            file_emission.ipns_name.clone(),
            FetchedRecord {
                sequence_number: 7,
                bytes: file_emission.published_node.clone(),
            },
        )]));
        let high_water = rhw();

        let published = fetch_node_gated(&fetcher, &high_water, &file_emission.ipns_name)
            .await
            .expect("fetch_node_gated should return the file node's own envelope");

        // The returned envelope is the file node's OWN PublishedNode -- its id
        // matches the emitted node identity and its kind is "file" (which
        // list_folder/list_folder_owned would REJECT via NotAFolder).
        assert_eq!(published.id, file_emission.id);
        assert_eq!(published.kind, "file");
        assert_eq!(published.schema, "node/v3");

        // The gate ran and bumped the seq floor for this node_id (proving it is
        // gated by high_water, not a raw resolve).
        assert_eq!(
            high_water.get_seq_floor(&file_emission.ipns_name).await,
            Some(7)
        );
    }

    // -----------------------------------------------------------------
    // Gate-first fail-closed: a sequence regression against the floor
    // the gate already tracks rejects the fetch (proves fetch_node_gated
    // routes through enforce_resolved, not a raw resolve).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn fetch_node_gated_rejects_a_sequence_regression() {
        let file_emission = build_file_emission(owned_content(1)).unwrap();
        let high_water = rhw();

        // First contact at seq=20 succeeds and seeds the seq floor at 20.
        let fetcher_hi = FakeFetcher(HashMap::from([(
            file_emission.ipns_name.clone(),
            FetchedRecord {
                sequence_number: 20,
                bytes: file_emission.published_node.clone(),
            },
        )]));
        fetch_node_gated(&fetcher_hi, &high_water, &file_emission.ipns_name)
            .await
            .expect("first contact at seq=20 should pass");

        // A later resolve reporting seq=3 is a rollback -- the gate rejects it
        // BEFORE the (identical) bytes are trusted.
        let fetcher_lo = FakeFetcher(HashMap::from([(
            file_emission.ipns_name.clone(),
            FetchedRecord {
                sequence_number: 3,
                bytes: file_emission.published_node.clone(),
            },
        )]));
        let result = fetch_node_gated(&fetcher_lo, &high_water, &file_emission.ipns_name).await;

        match result {
            Err(ListingError::Gated(name, RotationError::SequenceRegression { .. })) => {
                assert_eq!(name, file_emission.ipns_name);
            }
            other => panic!(
                "expected ListingError::Gated(.., SequenceRegression) proving fetch_node_gated \
                 is gate-first; got: {:?}",
                other
            ),
        }
    }
}
