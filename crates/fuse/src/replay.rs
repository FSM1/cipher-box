//! Journal replay on mount (node/v3).
//!
//! Replays pending write-queue entries on mount so in-flight writes survive
//! crashes. 69-09 Slice 4: the journal now carries reshaped node/v3 ops — a
//! sealed child `PublishedNode` (base64) plus the D-07 dual parent splices
//! (`SealedChildRef` read plane / `WriteChildRef` write plane). There are NO
//! hex-ECIES-under-user-key node-to-node key fields any more.
//!
//! Replay therefore:
//!   1. recovers the parent folder's read/write keys by walking the owned read
//!      chain from root via `cipherbox_sdk::list_folder_owned` (69-17) — the
//!      parent's signing seed is NOT carried in the journal (69-18 design), it
//!      is recovered from the parent node's own sealed write-body at replay;
//!   2. re-uploads the file sidecar ciphertext to obtain the REAL content CID
//!      (the journal sealed the file node with `NodeContent.cid = ""`), unseals
//!      the placeholder child node, patches the CID, and RE-SEALS it;
//!   3. publishes the child node's own IPNS record (idempotent first-publish);
//!   4. splices BOTH parent planes (the journaled `SealedChildRef` /
//!      `WriteChildRef`) into the parent's CURRENT resolved node and re-publishes
//!      the parent record with CAS;
//!   5. fail-closed: any stale/legacy entry that fails serde/decode/resolution is
//!      `log::warn!` + retained (never `unwrap`/`panic`), mirroring queue.rs.
//!
//! All items carry the same cfg gate as lib.rs.

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::sync::Arc;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use zeroize::Zeroizing;

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use cipherbox_api_client::ApiClient;

// Bring NETWORK_TIMEOUT into scope from the runtime module.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::runtime::NETWORK_TIMEOUT;

// Bring PublishCoordinator + the replay-resolve classifier into scope.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::publish::{resolve_ipns_for_replay, PublishCoordinator};

// node/v3 core primitives.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use cipherbox_core::node::{
    decode_node, decode_published_node, decode_write_body, encode_published_node,
    seal::{seal_published_node, unseal_child_read_key, unseal_child_write_key, unseal_node},
    Node, NodeKind, NodeWriteBody, PublishedNode, SealedChildRef, WriteChildRef,
};

// node-visit cap for the owned-chain BFS: bounds total network round trips and
// prevents cycles (mirrors the legacy `resolve_folder_key` MAX_RESOLVE_NODES).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
const MAX_RESOLVE_NODES: usize = 32;

/// Recovered parent read + write symmetric keys (D-09 caller-owned Zeroizing).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
type ParentKeys = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

// ---------------------------------------------------------------------------
// Small decode helpers (fail-closed, never panic)
// ---------------------------------------------------------------------------

#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn decode_b64(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode failed: {} — retaining entry", e))
}

/// Copy a slice into a `Zeroizing<[u8; 32]>` without leaving an un-zeroed
/// temporary on the stack (preallocate-then-copy; a `try_into` would).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn to_key32(bytes: &[u8], what: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    if bytes.len() != 32 {
        return Err(format!(
            "{} has wrong length (got {}, expected 32) — retaining entry",
            what,
            bytes.len()
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Map a `PublishedNode.kind` wire string to a `NodeKind` (fail-closed).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn node_kind_from_str(kind: &str) -> Result<NodeKind, String> {
    match kind {
        "folder" => Ok(NodeKind::Folder),
        "file" => Ok(NodeKind::File),
        "root" => Ok(NodeKind::Root),
        other => Err(format!("unknown node kind '{}' — retaining entry", other)),
    }
}

// ---------------------------------------------------------------------------
// Owned-chain recovery of parent read/write keys
// ---------------------------------------------------------------------------

/// Recover the read + write keys for `target_ipns_name` by walking the OWNED
/// read chain from root via `cipherbox_sdk::list_folder_owned` (69-17), the
/// node/v3 analog of the legacy hex-ECIES `resolve_folder_key` BFS.
///
/// `list_folder_owned` returns each child's recovered `read_key`/`write_key`
/// (unsealed under the parent's keys) — so descending the folder tree yields
/// the target folder's owned key material without any user-ECIES unwrap. If
/// `target_ipns_name == root_ipns_name`, the root keys are returned directly.
///
/// The signing seed is intentionally NOT recovered here — the caller recovers
/// it from the parent node's own sealed write-body inside
/// [`fetch_splice_publish_parent`] (69-18: the seed is never journaled).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
async fn resolve_owned_parent<F, S>(
    fetcher: &F,
    high_water: &cipherbox_sdk::RotationHighWater<S>,
    root_read_key: &[u8; 32],
    root_write_key: &[u8; 32],
    root_ipns_name: &str,
    target_ipns_name: &str,
) -> Result<ParentKeys, String>
where
    F: cipherbox_sdk::NodeFetcher,
    S: cipherbox_sdk::HighWaterStore,
{
    if target_ipns_name == root_ipns_name {
        return Ok((
            Zeroizing::new(*root_read_key),
            Zeroizing::new(*root_write_key),
        ));
    }

    // BFS queue: (ipns_name, read_key, write_key) of each folder to expand.
    let mut queue: std::collections::VecDeque<(String, Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> =
        std::collections::VecDeque::new();
    queue.push_back((
        root_ipns_name.to_string(),
        Zeroizing::new(*root_read_key),
        Zeroizing::new(*root_write_key),
    ));
    let mut nodes_visited = 0usize;

    while let Some((cur_ipns, cur_read, cur_write)) = queue.pop_front() {
        if nodes_visited >= MAX_RESOLVE_NODES {
            return Err(format!(
                "resolve_owned_parent: node cap ({}) exceeded looking for {} — retaining entry",
                MAX_RESOLVE_NODES, target_ipns_name
            ));
        }
        nodes_visited += 1;

        // SC#6: the ONLY sanctioned resolve is list_folder_owned (gate-first,
        // owned walk). NEVER a raw resolve_published_node in fuse.
        let children =
            cipherbox_sdk::list_folder_owned(fetcher, high_water, &cur_ipns, &cur_read, &cur_write)
                .await
                .map_err(|e| {
                    format!(
                        "list_folder_owned {} failed: {} — retaining entry",
                        cur_ipns, e
                    )
                })?;

        for child in children {
            // Only folders can be parents; skip file children.
            if child.child.kind != NodeKind::Folder {
                continue;
            }
            if child.child.ipns_name == target_ipns_name {
                // Found the target folder — move its owned keys out.
                return Ok((child.read_key, child.write_key));
            }
            queue.push_back((child.child.ipns_name, child.read_key, child.write_key));
        }
    }

    Err(format!(
        "parent folder {} not found in vault tree ({} nodes searched) — retaining entry",
        target_ipns_name, nodes_visited
    ))
}

/// Memoizing wrapper around [`resolve_owned_parent`] for one `replay_for_vault`
/// call. Never persisted; dropped (and its Zeroizing keys wiped) at call end.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
async fn resolve_owned_parent_cached<F, S>(
    cache: &mut std::collections::HashMap<String, ParentKeys>,
    fetcher: &F,
    high_water: &cipherbox_sdk::RotationHighWater<S>,
    root_read_key: &[u8; 32],
    root_write_key: &[u8; 32],
    root_ipns_name: &str,
    target_ipns_name: &str,
) -> Result<ParentKeys, String>
where
    F: cipherbox_sdk::NodeFetcher,
    S: cipherbox_sdk::HighWaterStore,
{
    if let Some((r, w)) = cache.get(target_ipns_name) {
        return Ok((r.clone(), w.clone()));
    }
    let keys = resolve_owned_parent(
        fetcher,
        high_water,
        root_read_key,
        root_write_key,
        root_ipns_name,
        target_ipns_name,
    )
    .await?;
    cache.insert(
        target_ipns_name.to_string(),
        (keys.0.clone(), keys.1.clone()),
    );
    Ok(keys)
}

// ---------------------------------------------------------------------------
// Child-key recovery from the D-07 parent splices
// ---------------------------------------------------------------------------

/// Recover a child node's read + write keys by symmetric-unsealing the
/// journaled parent splices: `SealedChildRef.read_key_sealed` under the parent
/// readKey, `WriteChildRef.write_key_sealed` under the parent writeKey (D-07).
///
/// The child id + generation are taken from the splices themselves (`child_id`
/// = `WriteChildRef.child_id` = `uuid_from_ino`; generation from the read
/// splice), so the AAD round-trips exactly what the write path sealed.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn recover_child_read_write(
    parent_read_key: &[u8; 32],
    parent_write_key: &[u8; 32],
    child_ref: &SealedChildRef,
    write_child_ref: &WriteChildRef,
    kind: NodeKind,
) -> Result<ParentKeys, String> {
    let child_id = &write_child_ref.child_id;
    let generation = child_ref.generation;

    let read_sealed = decode_b64(&child_ref.read_key_sealed)?;
    let read_key_vec =
        unseal_child_read_key(&read_sealed, parent_read_key, child_id, kind, generation)
            .map_err(|e| format!("unseal child readKey: {} — retaining entry", e))?;

    let write_sealed = decode_b64(&write_child_ref.write_key_sealed)?;
    let write_key_vec =
        unseal_child_write_key(&write_sealed, parent_write_key, child_id, kind, generation)
            .map_err(|e| format!("unseal child writeKey: {} — retaining entry", e))?;

    let read_key = to_key32(&read_key_vec, "child readKey")?;
    let write_key = to_key32(&write_key_vec, "child writeKey")?;
    Ok((read_key, write_key))
}

/// Recover a node's Ed25519 signing seed from its OWN sealed write-body, given
/// that node's write key. Used to re-publish the child's / parent's IPNS record
/// (the seed is never carried in the journal — 69-18).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn recover_signing_seed(
    published: &PublishedNode,
    write_key: &[u8; 32],
    kind: NodeKind,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let write_sealed = published.write_sealed.as_ref().ok_or_else(|| {
        format!(
            "node {} has no write_sealed body — cannot recover signing seed — retaining entry",
            published.id
        )
    })?;
    let write_body_bytes = Zeroizing::new(
        unseal_node(
            &decode_b64(write_sealed)?,
            write_key,
            &published.id,
            kind,
            published.generation,
        )
        .map_err(|e| {
            format!(
                "unseal write-body for {}: {} — retaining entry",
                published.id, e
            )
        })?,
    );
    let write_body = decode_write_body(&write_body_bytes).map_err(|e| {
        format!(
            "decode write-body for {}: {} — retaining entry",
            published.id, e
        )
    })?;
    Ok(Zeroizing::new(write_body.ipns_private_key))
}

// ---------------------------------------------------------------------------
// Child IPNS publish (idempotent first-publish, seq 1, TEE enrollment)
// ---------------------------------------------------------------------------

/// Publish a freshly-emitted child node's OWN IPNS record at seq 1.
///
/// `node_bytes` are the `encode_published_node` bytes uploaded verbatim to IPFS
/// (already sealed). Idempotent: if the record already resolves (publish
/// completed pre-crash) the publish is skipped; a transient resolve error
/// retains the entry. On a genuine first publish the child key is TEE-enrolled
/// (crypto rule #7 keeper — the ONLY ECIES on this path).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
async fn publish_child_node(
    api: &ApiClient,
    coordinator: &PublishCoordinator,
    child_ipns_name: &str,
    node_bytes: &[u8],
    child_ipns_private_key: &Zeroizing<Vec<u8>>,
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
) -> Result<(), String> {
    use crate::error::IpnsResolveOutcome;
    use base64::Engine;

    match resolve_ipns_for_replay(coordinator, api, child_ipns_name).await {
        IpnsResolveOutcome::Found(_) => {
            log::info!(
                "replay: child node IPNS '{}' already published — skipping first-publish",
                child_ipns_name
            );
            return Ok(());
        }
        IpnsResolveOutcome::NotFound => {}
        IpnsResolveOutcome::Error(e) => {
            return Err(format!(
                "resolve child node IPNS {}: {} — retaining entry",
                child_ipns_name, e
            ));
        }
    }

    let ipns_key_arr = to_key32(child_ipns_private_key.as_slice(), "child IPNS signing seed")?;

    let cid = cipherbox_api_client::ipfs::upload_content(api, node_bytes)
        .await
        .map_err(|e| format!("upload child node: {}", e))?;
    let value = format!("/ipfs/{}", cid);
    let record = cipherbox_core::ipns::create_ipns_record(&ipns_key_arr, &value, 1, 86_400_000)
        .map_err(|e| format!("child IPNS record creation failed: {}", e))?;
    let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
        .map_err(|e| format!("child IPNS marshal failed: {}", e))?;
    let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

    // TEE enrollment on first publish (crypto rule #7 keeper ECIES wrap).
    let (encrypted_ipns_for_tee, tee_epoch) = match (tee_public_key, tee_key_epoch) {
        (Some(tee_key), Some(epoch)) => {
            let wrapped = cipherbox_crypto::wrap_key(child_ipns_private_key.as_slice(), tee_key)
                .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
            (Some(hex::encode(&wrapped)), Some(epoch))
        }
        (Some(_), None) => return Err("TEE public key present but key_epoch missing".to_string()),
        _ => (None, None),
    };

    let req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: child_ipns_name.to_string(),
        record: record_b64,
        metadata_cid: cid,
        encrypted_ipns_private_key: encrypted_ipns_for_tee,
        key_epoch: tee_epoch,
        expected_sequence_number: None,
    };
    match cipherbox_api_client::ipns::publish_ipns(api, &req)
        .await
        .map_err(|e| format!("publish child node IPNS: {}", e))?
    {
        cipherbox_api_client::PublishResult::Success => {}
        cipherbox_api_client::PublishResult::Conflict { .. } => {
            // A brand-new child IPNS should not conflict on first publish; a race
            // means another client created it — treat as already-published.
            log::warn!(
                "replay: unexpected conflict on child node first-publish for {}",
                child_ipns_name
            );
        }
    }
    coordinator.record_publish(child_ipns_name, 1);
    log::info!(
        "replay: child node IPNS published (seq 1) for {}",
        child_ipns_name
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Parent re-splice + re-publish (both planes, D-07)
// ---------------------------------------------------------------------------

/// Fetch the parent's CURRENT node, splice the journaled read/write child refs
/// into BOTH planes, re-seal, and CAS-publish the parent record.
///
/// D-06: operates on the parent's CURRENT remote node (never the stale
/// journaled snapshot). Idempotent — if the child is already spliced into the
/// read plane the publish is skipped. The parent signing seed is recovered from
/// the parent node's OWN write-body (69-18: never journaled).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
async fn fetch_splice_publish_parent<F, S>(
    fetcher: &F,
    high_water: &cipherbox_sdk::RotationHighWater<S>,
    api: &ApiClient,
    coordinator: Arc<PublishCoordinator>,
    parent_ipns_name: &str,
    parent_read_key: &[u8; 32],
    parent_write_key: &[u8; 32],
    new_child_ref: SealedChildRef,
    new_write_child_ref: WriteChildRef,
) -> Result<(), String>
where
    F: cipherbox_sdk::NodeFetcher,
    S: cipherbox_sdk::HighWaterStore,
{
    let lock = coordinator.get_lock(parent_ipns_name);
    let _guard = lock.lock().await;

    // SLICE-5 DEPENDENCY (69-09 Slice 2 FLAG / TASK 0): `cipherbox_sdk::fetch_node_gated`
    // is the sanctioned SC#6 single-node gated resolve, added in Slice 5. Replay
    // needs the parent's CURRENT PublishedNode to splice into and MUST NOT call the
    // crate-private `resolve_published_node` directly. Until Slice 5 lands this is
    // the ONE unresolved symbol in replay.rs (documented residual `cargo check` error).
    let published: PublishedNode =
        cipherbox_sdk::fetch_node_gated(fetcher, high_water, parent_ipns_name)
            .await
            .map_err(|e| {
                format!(
                    "fetch parent node {}: {} — retaining entry",
                    parent_ipns_name, e
                )
            })?;

    let kind = node_kind_from_str(&published.kind)?;
    if kind == NodeKind::File {
        return Err(format!(
            "parent {} resolved to a file node — retaining entry",
            parent_ipns_name
        ));
    }

    // Recover the parent's signing seed from its OWN write-body (69-18).
    let parent_signing_seed = recover_signing_seed(&published, parent_write_key, kind)?;

    // Read-body -> children (SealedChildRef).
    let read_body_bytes = unseal_node(
        &decode_b64(&published.read_sealed)?,
        parent_read_key,
        &published.id,
        kind,
        published.generation,
    )
    .map_err(|e| {
        format!(
            "unseal parent read-body {}: {} — retaining entry",
            parent_ipns_name, e
        )
    })?;
    let node = decode_node(&read_body_bytes).map_err(|e| {
        format!(
            "decode parent node {}: {} — retaining entry",
            parent_ipns_name, e
        )
    })?;

    // Write-body -> write_children (WriteChildRef).
    let write_sealed = published.write_sealed.as_ref().ok_or_else(|| {
        format!(
            "parent {} has no write_sealed body — retaining entry",
            parent_ipns_name
        )
    })?;
    let write_body_bytes = Zeroizing::new(
        unseal_node(
            &decode_b64(write_sealed)?,
            parent_write_key,
            &published.id,
            kind,
            published.generation,
        )
        .map_err(|e| {
            format!(
                "unseal parent write-body {}: {} — retaining entry",
                parent_ipns_name, e
            )
        })?,
    );
    let mut write_children = decode_write_body(&write_body_bytes)
        .map_err(|e| {
            format!(
                "decode parent write-body {}: {} — retaining entry",
                parent_ipns_name, e
            )
        })?
        .write_children;

    // Extract read-plane children + node identity, preserving the variant.
    let (id, generation, created_at, modified_at, mut children, is_root) = match node {
        Node::Folder {
            id,
            generation,
            created_at,
            modified_at,
            children,
        } => (id, generation, created_at, modified_at, children, false),
        Node::Root {
            id,
            generation,
            created_at,
            modified_at,
            children,
        } => (id, generation, created_at, modified_at, children, true),
        Node::File { .. } => {
            return Err(format!(
                "parent {} decoded as a file node — retaining entry",
                parent_ipns_name
            ))
        }
    };

    // D-06 idempotency: child already present in the read plane -> nothing to do.
    if children
        .iter()
        .any(|c| c.ipns_name == new_child_ref.ipns_name)
    {
        log::info!(
            "replay: child {} already spliced into parent {} — skipping (idempotent)",
            new_child_ref.ipns_name,
            parent_ipns_name
        );
        return Ok(());
    }

    // Splice BOTH planes (dedup by key, then push).
    children.retain(|c| c.ipns_name != new_child_ref.ipns_name);
    children.push(new_child_ref);
    write_children.retain(|w| w.child_id != new_write_child_ref.child_id);
    write_children.push(new_write_child_ref);

    // Rebuild the parent node preserving id/generation/timestamps.
    let new_node = if is_root {
        Node::Root {
            id,
            generation,
            created_at,
            modified_at,
            children,
        }
    } else {
        Node::Folder {
            id,
            generation,
            created_at,
            modified_at,
            children,
        }
    };
    let new_write_body = NodeWriteBody {
        ipns_private_key: parent_signing_seed.to_vec(),
        write_children,
    };
    let new_published = seal_published_node(
        &new_node,
        parent_read_key,
        parent_write_key,
        Some(&new_write_body),
    )
    .map_err(|e| {
        format!(
            "re-seal parent {}: {} — retaining entry",
            parent_ipns_name, e
        )
    })?;
    let new_bytes = encode_published_node(&new_published).map_err(|e| {
        format!(
            "encode parent {}: {} — retaining entry",
            parent_ipns_name, e
        )
    })?;

    // Upload the re-sealed parent envelope, then CAS-publish it.
    let parent_signing_arr = to_key32(parent_signing_seed.as_slice(), "parent IPNS signing seed")?;
    let new_cid = cipherbox_api_client::ipfs::upload_content(api, &new_bytes)
        .await
        .map_err(|e| format!("upload parent node {}: {}", parent_ipns_name, e))?;

    let seq = coordinator.resolve_sequence(api, parent_ipns_name).await?;
    let new_seq = seq
        .checked_add(1)
        .ok_or_else(|| "IPNS sequence number overflow".to_string())?;
    let value = format!("/ipfs/{}", new_cid);
    let record =
        cipherbox_core::create_ipns_record(&parent_signing_arr, &value, new_seq, 86_400_000)
            .map_err(|e| format!("create parent IPNS record: {}", e))?;
    let marshaled = cipherbox_core::marshal_ipns_record(&record)
        .map_err(|e| format!("marshal parent IPNS record: {}", e))?;
    use base64::Engine;
    let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

    let req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: parent_ipns_name.to_string(),
        record: record_b64,
        metadata_cid: new_cid.clone(),
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: Some(seq.to_string()),
    };
    match cipherbox_api_client::ipns::publish_ipns(api, &req)
        .await
        .map_err(|e| format!("publish parent IPNS {}: {}", parent_ipns_name, e))?
    {
        cipherbox_api_client::PublishResult::Success => {
            coordinator.record_publish(parent_ipns_name, new_seq);
            log::info!(
                "replay: parent node/v3 published for {} (new_seq={}, new_cid={})",
                parent_ipns_name,
                new_seq,
                new_cid
            );
            Ok(())
        }
        cipherbox_api_client::PublishResult::Conflict {
            current_sequence_number,
        } => {
            // CAS conflict — retain the entry for the next mount. The uploaded CID
            // is still pinned (safe; just not yet referenced).
            log::warn!(
                "replay: CAS conflict on parent {} (expected {}, server has {}) — retaining entry",
                parent_ipns_name,
                seq,
                current_sequence_number
            );
            Err(format!(
                "IPNS conflict on parent {} (server seq {}) — will retry on next mount",
                parent_ipns_name, current_sequence_number
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// replay_for_vault — vault-scoped entry loop
// ---------------------------------------------------------------------------

/// Replay all pending journal entries for the given vault on mount.
///
/// node/v3 (69-09 Slice 4): loads all entries for `root_ipns_name`, orders them
/// MkdirPublish-before-UploadFile (D-08), then for each entry re-publishes the
/// child node and re-splices the D-07 parent planes into the parent's CURRENT
/// node (never the stale snapshot). A stale/legacy entry that fails serde is
/// dropped by the loader itself (queue.rs D-04 fail-closed); an entry that fails
/// decode/resolve at replay is `log::warn!` + retained via `record_failure`.
///
/// Errors are logged but never fail the mount — a partially-replayed journal is
/// better than a failed mount.
///
/// SLICE-5 CALLER NOTE (69-09): the signature changed from the legacy
/// `(private_key, public_key, root_folder_key)` to node/v3 root material
/// `(journal_dir, root_read_key, root_write_key)`. The desktop mount site
/// (`apps/desktop/src-tauri/src/fuse/mod.rs`) + windows mirror are updated in
/// Slice 5 to pass the root node's read/write keys (available from root
/// population) and the journal dir (already computed at the mount site).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
pub async fn replay_for_vault(
    journal: &cipherbox_sdk::WriteQueue,
    api: Arc<ApiClient>,
    // Journal dir: used to build the anti-rollback high-water gate (sidecars live
    // adjacent to the journal, matching the fs.rs mount wiring).
    journal_dir: std::path::PathBuf,
    // node/v3 root material (replaces private_key/public_key/root_folder_key).
    root_read_key: &[u8; 32],
    root_write_key: &[u8; 32],
    root_ipns_name: &str,
    coordinator: Arc<PublishCoordinator>,
    // TEE key/epoch so a first-publish replay (per-node IPNS never created in the
    // original failed session) can enroll the record for TEE republishing.
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
) {
    let entries = match journal.load_all_for_vault(root_ipns_name) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("replay_for_vault: failed to load journal entries: {}", e);
            return;
        }
    };

    if entries.is_empty() {
        return;
    }

    log::info!(
        "replay_for_vault: replaying {} journal entry(s) for vault {}",
        entries.len(),
        root_ipns_name
    );

    // D-08: MkdirPublish entries process before UploadFile entries.
    let ordered = cipherbox_sdk::WriteQueue::ordered_for_replay(entries);

    // node/v3 gate + fetcher, built once per replay call (matching fs.rs mount
    // wiring). The high-water sidecars live adjacent to the journal dir.
    let high_water = cipherbox_sdk::new_journal_high_water(&journal_dir);
    let fetcher = cipherbox_sdk::ApiNodeFetcher { api: api.as_ref() };

    // Per-replay parent-key cache (never persisted; wiped at end of call).
    let mut parent_cache: std::collections::HashMap<String, ParentKeys> =
        std::collections::HashMap::new();

    for entry in &ordered {
        // Skip already-failed entries (user must manually intervene for those).
        if matches!(
            entry.status,
            cipherbox_sdk::JournalEntryStatus::Failed { .. }
        ) {
            log::info!(
                "replay_for_vault: skipping failed entry {} (status=Failed)",
                entry.id
            );
            continue;
        }

        let result = match &entry.op {
            cipherbox_sdk::JournalOp::MkdirPublish {
                child_ipns_name,
                child_published_node,
                parent_child_ref,
                parent_write_child_ref,
                parent_folder_ipns_name,
                created_at_ms: _,
            } => {
                // mkdir is metadata-only → 3× the base network timeout (D-03/WR-07).
                tokio::time::timeout(
                    NETWORK_TIMEOUT * 3,
                    replay_mkdir_entry(
                        &fetcher,
                        &high_water,
                        &api,
                        coordinator.clone(),
                        root_read_key,
                        root_write_key,
                        root_ipns_name,
                        &mut parent_cache,
                        child_ipns_name,
                        child_published_node,
                        parent_child_ref,
                        parent_write_child_ref,
                        parent_folder_ipns_name,
                        tee_public_key,
                        tee_key_epoch,
                    ),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(format!(
                        "replay_mkdir_entry timed out after {}s",
                        (NETWORK_TIMEOUT * 3).as_secs()
                    ))
                })
            }
            cipherbox_sdk::JournalOp::UploadFile {
                sidecar_path,
                sidecar_sha256,
                legacy_ciphertext_b64,
                child_published_node,
                parent_child_ref,
                parent_write_child_ref,
                file_meta_ipns_name,
                parent_folder_ipns_name,
                size: _,
                created_at_ms: _,
            } => {
                // D-02: never trust the persisted `sidecar_path` for a non-legacy
                // entry — re-derive <journal_dir>/<id>.bin from the journal id so an
                // out-of-band-edited path cannot make replay read an attacker-chosen
                // file. The empty-path branch (legacy inline ciphertext) is preserved.
                let derived_sidecar_path: std::path::PathBuf;
                let replay_sidecar_path: &std::path::Path = if sidecar_path.as_os_str().is_empty() {
                    sidecar_path
                } else {
                    derived_sidecar_path = journal.sidecar_path_for(&entry.id);
                    &derived_sidecar_path
                };
                // upload may re-stream a multi-GB sidecar → 18× (~180s).
                tokio::time::timeout(
                    NETWORK_TIMEOUT * 18,
                    replay_upload_entry(
                        &fetcher,
                        &high_water,
                        &api,
                        coordinator.clone(),
                        root_read_key,
                        root_write_key,
                        root_ipns_name,
                        &mut parent_cache,
                        replay_sidecar_path,
                        sidecar_sha256,
                        legacy_ciphertext_b64,
                        child_published_node,
                        parent_child_ref,
                        parent_write_child_ref,
                        file_meta_ipns_name.as_deref(),
                        parent_folder_ipns_name,
                        tee_public_key,
                        tee_key_epoch,
                    ),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(format!(
                        "replay_upload_entry timed out after {}s",
                        (NETWORK_TIMEOUT * 18).as_secs()
                    ))
                })
            }
        };

        let kind_label = match &entry.op {
            cipherbox_sdk::JournalOp::MkdirPublish { .. } => "MkdirPublish",
            cipherbox_sdk::JournalOp::UploadFile { .. } => "UploadFile",
        };

        match result {
            Ok(()) => {
                log::info!(
                    "replay_for_vault: {} {} replayed successfully",
                    kind_label,
                    entry.id
                );
                if let Err(e) = journal.remove(&entry.id) {
                    log::warn!(
                        "replay_for_vault: {} {} failed to remove journal entry after success: {}; entry may replay again on next mount",
                        kind_label, entry.id, e
                    );
                }
            }
            Err(e) => {
                // F2: record the failure so retries accumulate across mounts and the
                // entry parks as Failed at max_retries (D-09), making WriteParked
                // reachable at runtime instead of retrying forever. Fail-closed: a
                // stale/undecodable entry is retained + warned, never replayed as garbage.
                match journal.record_failure(entry, &e) {
                    Ok(cipherbox_sdk::JournalEntryStatus::Failed { .. }) => log::error!(
                        "replay_for_vault: {} {} parked as Failed after {} retries: {}",
                        kind_label, entry.id, journal.max_retries, e
                    ),
                    Ok(_) => log::warn!(
                        "replay_for_vault: {} {} failed: {} (retry {}/{}, will retry on next mount)",
                        kind_label, entry.id, e, entry.retries + 1, journal.max_retries
                    ),
                    Err(re) => log::warn!(
                        "replay_for_vault: {} {} failed: {}; record_failure also errored: {}",
                        kind_label, entry.id, e, re
                    ),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-op replay
// ---------------------------------------------------------------------------

/// Replay a single `MkdirPublish` entry: publish the child folder's own node
/// (idempotent seq 1), then splice both parent planes into the parent's current
/// node and re-publish it.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
async fn replay_mkdir_entry<F, S>(
    fetcher: &F,
    high_water: &cipherbox_sdk::RotationHighWater<S>,
    api: &ApiClient,
    coordinator: Arc<PublishCoordinator>,
    root_read_key: &[u8; 32],
    root_write_key: &[u8; 32],
    root_ipns_name: &str,
    parent_cache: &mut std::collections::HashMap<String, ParentKeys>,
    child_ipns_name: &str,
    child_published_node_b64: &str,
    parent_child_ref: &SealedChildRef,
    parent_write_child_ref: &WriteChildRef,
    parent_folder_ipns_name: &str,
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
) -> Result<(), String>
where
    F: cipherbox_sdk::NodeFetcher,
    S: cipherbox_sdk::HighWaterStore,
{
    // Recover the parent folder's owned read/write keys (owned read chain).
    let (parent_read_key, parent_write_key) = resolve_owned_parent_cached(
        parent_cache,
        fetcher,
        high_water,
        root_read_key,
        root_write_key,
        root_ipns_name,
        parent_folder_ipns_name,
    )
    .await?;

    // Decode the sealed child folder node bytes (uploaded verbatim — folder nodes
    // carry no content CID to fill).
    let child_node_bytes = decode_b64(child_published_node_b64)?;

    // Recover the child folder's own keys from the D-07 parent splices so we can
    // unseal its write-body and recover its signing seed for the seq-1 publish.
    let (child_read_key, child_write_key) = recover_child_read_write(
        &parent_read_key,
        &parent_write_key,
        parent_child_ref,
        parent_write_child_ref,
        NodeKind::Folder,
    )?;
    // child_read_key is not needed further for a folder (no content to re-seal),
    // but recovering it validates the read splice fail-closed.
    let _ = child_read_key;

    let published = decode_published_node(&child_node_bytes)
        .map_err(|e| format!("decode child folder node: {} — retaining entry", e))?;
    let child_signing_seed = recover_signing_seed(&published, &child_write_key, NodeKind::Folder)?;

    // Publish the child folder's own IPNS record (idempotent first-publish).
    publish_child_node(
        api,
        coordinator.as_ref(),
        child_ipns_name,
        &child_node_bytes,
        &child_signing_seed,
        tee_public_key,
        tee_key_epoch,
    )
    .await?;

    // Splice both planes into the parent and re-publish it.
    fetch_splice_publish_parent(
        fetcher,
        high_water,
        api,
        coordinator,
        parent_folder_ipns_name,
        &parent_read_key,
        &parent_write_key,
        parent_child_ref.clone(),
        parent_write_child_ref.clone(),
    )
    .await
}

/// Replay a single `UploadFile` entry: re-upload the sidecar ciphertext for the
/// REAL content CID, patch + re-seal the placeholder file node, publish the
/// file node's own IPNS record, then splice both parent planes and re-publish
/// the parent.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
async fn replay_upload_entry<F, S>(
    fetcher: &F,
    high_water: &cipherbox_sdk::RotationHighWater<S>,
    api: &ApiClient,
    coordinator: Arc<PublishCoordinator>,
    root_read_key: &[u8; 32],
    root_write_key: &[u8; 32],
    root_ipns_name: &str,
    parent_cache: &mut std::collections::HashMap<String, ParentKeys>,
    sidecar_path: &std::path::Path,
    sidecar_sha256: &str,
    legacy_ciphertext_b64: &str,
    child_published_node_b64: &str,
    parent_child_ref: &SealedChildRef,
    parent_write_child_ref: &WriteChildRef,
    file_meta_ipns_name: Option<&str>,
    parent_folder_ipns_name: &str,
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
) -> Result<(), String>
where
    F: cipherbox_sdk::NodeFetcher,
    S: cipherbox_sdk::HighWaterStore,
{
    // REQ-4: an entry with no per-file IPNS name cannot publish a resolvable file
    // node — park it (retain), never publish an unresolvable pointer. Placed above
    // the ciphertext upload so such entries don't re-pin content on every mount.
    let file_ipns_name = match file_meta_ipns_name {
        Some(name) if !name.is_empty() => name,
        _ => {
            return Err(
                "UploadFile entry has no per-file IPNS name — parking (no unresolvable node)"
                    .to_string(),
            )
        }
    };

    // Step 1: re-upload ciphertext (idempotent CID). Read from the sidecar .bin and
    // verify SHA-256 before re-upload; a missing/mismatched sidecar retains the entry.
    let ciphertext = if sidecar_path.as_os_str().is_empty() {
        // Legacy pre-Phase-52 entry: no sidecar, inline base64 ciphertext. One-time
        // passthrough replay so the pending upload is not lost at upgrade.
        if legacy_ciphertext_b64.is_empty() {
            return Err(
                "UploadFile entry has no sidecar and no legacy inline ciphertext — retaining entry"
                    .to_string(),
            );
        }
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(legacy_ciphertext_b64)
            .map_err(|e| format!("decode legacy inline ciphertext: {} — retaining entry", e))?
    } else {
        let ciphertext = std::fs::read(sidecar_path)
            .map_err(|e| format!("read ciphertext sidecar: {} — retaining entry", e))?;
        let actual_sha256 = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&ciphertext);
            hex::encode(hasher.finalize())
        };
        if actual_sha256 != sidecar_sha256 {
            return Err(format!(
                "sidecar hash mismatch (expected {}, got {}) — retaining entry",
                sidecar_sha256, actual_sha256
            ));
        }
        ciphertext
    };
    let file_cid = cipherbox_api_client::ipfs::upload_content(api, &ciphertext)
        .await
        .map_err(|e| format!("upload ciphertext: {}", e))?;
    log::info!("replay: re-uploaded ciphertext -> CID {}", file_cid);

    // Step 2: recover the parent folder's owned read/write keys.
    let (parent_read_key, parent_write_key) = resolve_owned_parent_cached(
        parent_cache,
        fetcher,
        high_water,
        root_read_key,
        root_write_key,
        root_ipns_name,
        parent_folder_ipns_name,
    )
    .await?;

    // Step 3: recover the file node's own keys from the D-07 parent splices.
    let (file_read_key, file_write_key) = recover_child_read_write(
        &parent_read_key,
        &parent_write_key,
        parent_child_ref,
        parent_write_child_ref,
        NodeKind::File,
    )?;

    // Step 4: decode the placeholder file node (NodeContent.cid == ""), patch in
    // the REAL content CID, and RE-SEAL under the file's own read/write keys.
    let placeholder_bytes = decode_b64(child_published_node_b64)?;
    let published = decode_published_node(&placeholder_bytes)
        .map_err(|e| format!("decode placeholder file node: {} — retaining entry", e))?;
    let file_signing_seed = recover_signing_seed(&published, &file_write_key, NodeKind::File)?;

    let read_body_bytes = unseal_node(
        &decode_b64(&published.read_sealed)?,
        &file_read_key,
        &published.id,
        NodeKind::File,
        published.generation,
    )
    .map_err(|e| format!("unseal placeholder file read-body: {} — retaining entry", e))?;
    let file_node = decode_node(&read_body_bytes)
        .map_err(|e| format!("decode placeholder file node body: {} — retaining entry", e))?;

    let (id, generation, created_at, modified_at, mut content) = match file_node {
        Node::File {
            id,
            generation,
            created_at,
            modified_at,
            content,
        } => (id, generation, created_at, modified_at, content),
        _ => return Err("placeholder child node is not a file node — retaining entry".to_string()),
    };
    // Patch the placeholder CID with the freshly-uploaded content CID.
    content.cid = file_cid.clone();
    let resealed_node = Node::File {
        id,
        generation,
        created_at,
        modified_at,
        content,
    };
    let write_body = NodeWriteBody {
        ipns_private_key: file_signing_seed.to_vec(),
        write_children: Vec::new(),
    };
    let resealed_published = seal_published_node(
        &resealed_node,
        &file_read_key,
        &file_write_key,
        Some(&write_body),
    )
    .map_err(|e| format!("re-seal file node: {} — retaining entry", e))?;
    let resealed_bytes = encode_published_node(&resealed_published)
        .map_err(|e| format!("encode re-sealed file node: {} — retaining entry", e))?;

    // Step 5: publish the file node's own IPNS record (idempotent first-publish).
    publish_child_node(
        api,
        coordinator.as_ref(),
        file_ipns_name,
        &resealed_bytes,
        &file_signing_seed,
        tee_public_key,
        tee_key_epoch,
    )
    .await?;
    log::info!("replay: file node IPNS published for '{}'", file_ipns_name);

    // Step 6: splice both planes into the parent and re-publish it.
    fetch_splice_publish_parent(
        fetcher,
        high_water,
        api,
        coordinator,
        parent_folder_ipns_name,
        &parent_read_key,
        &parent_write_key,
        parent_child_ref.clone(),
        parent_write_child_ref.clone(),
    )
    .await
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    use cipherbox_core::node::{SealedChildRef, WriteChildRef};

    // Build a syntactically-valid (but crypto-garbage) pair of D-07 parent splices
    // for entries that never reach the crypto path (skip-Failed / park cases).
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    fn dummy_refs() -> (SealedChildRef, WriteChildRef) {
        (
            SealedChildRef {
                name: "child".to_string(),
                ipns_name: "k51childtest".to_string(),
                generation: 0,
                version_floor: 0,
                read_key_sealed: String::new(),
            },
            WriteChildRef {
                child_id: "00000000-0000-4000-8000-000000000000".to_string(),
                write_key_sealed: String::new(),
            },
        )
    }

    // replay_for_vault must skip Failed entries entirely (not re-attempt, not
    // remove). Pins the D-09 skip-failed path under the node/v3 reshape.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn replay_for_vault_does_not_touch_failed_entries() {
        use cipherbox_sdk::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
        use std::sync::Arc;

        let dir = std::env::temp_dir()
            .join("cb-s4-replay-skip-failed")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = WriteQueue::new(dir.clone(), 5);
        let vault = "k51vaults4skip";

        let (parent_child_ref, parent_write_child_ref) = dummy_refs();
        let entry = JournalEntry {
            id: "failed-s4".to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                sidecar_path: std::path::PathBuf::from("/tmp/failed-s4.bin"),
                sidecar_sha256: hex::encode([0u8; 32]),
                legacy_ciphertext_b64: String::new(),
                child_published_node: String::new(),
                parent_child_ref,
                parent_write_child_ref,
                file_meta_ipns_name: Some("k51filemetas4".to_string()),
                parent_folder_ipns_name: vault.to_string(),
                size: 1,
                created_at_ms: 1_700_000_000_000,
            },
            retries: 5,
            status: JournalEntryStatus::Failed {
                last_error: "simulated prior failure".to_string(),
            },
        };
        journal.put(&entry).unwrap();

        let api = Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
        let coordinator = Arc::new(super::PublishCoordinator::new());

        super::replay_for_vault(
            &journal,
            api,
            dir.clone(),
            &[0u8; 32],
            &[0u8; 32],
            vault,
            coordinator,
            None,
            None,
        )
        .await;

        let after = journal.load_all_for_vault(vault).unwrap();
        assert_eq!(
            after.len(),
            1,
            "Failed entry must not be removed by replay (D-09 / skip-failed path)"
        );
        assert!(
            matches!(after[0].status, JournalEntryStatus::Failed { .. }),
            "status must remain Failed after replay"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // An UploadFile entry with no per-file IPNS name is parked (retained), never
    // published as an unresolvable node. The early Err in replay_upload_entry
    // routes through record_failure, so after replay the entry count stays at 1.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn upload_without_ipns_name_parks() {
        use cipherbox_sdk::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
        use std::sync::Arc;

        let dir = std::env::temp_dir()
            .join("cb-s4-upload-no-name-parks")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = WriteQueue::new(dir.clone(), 5);
        let vault = "k51vaults4noname";

        let (parent_child_ref, parent_write_child_ref) = dummy_refs();
        let entry = JournalEntry {
            id: "none-name-s4".to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                sidecar_path: std::path::PathBuf::from("/tmp/none-name-s4.bin"),
                sidecar_sha256: hex::encode([0u8; 32]),
                legacy_ciphertext_b64: String::new(),
                child_published_node: String::new(),
                parent_child_ref,
                parent_write_child_ref,
                file_meta_ipns_name: None,
                parent_folder_ipns_name: vault.to_string(),
                size: 1,
                created_at_ms: 1_700_000_000_000,
            },
            retries: 0,
            status: JournalEntryStatus::Pending,
        };
        journal.put(&entry).unwrap();

        let api = Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
        let coordinator = Arc::new(super::PublishCoordinator::new());

        super::replay_for_vault(
            &journal,
            api,
            dir.clone(),
            &[0u8; 32],
            &[0u8; 32],
            vault,
            coordinator,
            None,
            None,
        )
        .await;

        let after = journal.load_all_for_vault(vault).unwrap();
        assert_eq!(
            after.len(),
            1,
            "no-name entry must be retained (parked), not removed as replayed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // resolve_sequence_strict returns Err on ANY resolve failure, NEVER falling
    // back to the cache. (Coordinator-level; unaffected by the node/v3 reshape.)
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn strict_resolve_bypasses_cache() {
        let api = cipherbox_api_client::ApiClient::new("http://127.0.0.1:1");
        let coordinator = super::PublishCoordinator::new();
        let ipns_name = "k51strictbypass";

        coordinator.record_publish(ipns_name, 42);

        let result = coordinator.resolve_sequence_strict(&api, ipns_name).await;
        assert!(
            result.is_err(),
            "strict resolve must err on resolve failure even with a populated cache (got {:?})",
            result
        );
    }

    // Non-strict resolve_sequence cache-fallback contract (mirror of strict path).
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn resolve_sequence_falls_back_to_cache_on_resolve_failure() {
        let api = cipherbox_api_client::ApiClient::new("http://127.0.0.1:1");
        let coordinator = super::PublishCoordinator::new();
        let ipns_name = "k51softfallback";

        coordinator.record_publish(ipns_name, 42);

        let result = coordinator.resolve_sequence(&api, ipns_name).await;
        assert_eq!(
            result,
            Ok(42),
            "non-strict resolve must fall back to the cached sequence on resolve failure (got {:?})",
            result
        );
    }

    // Non-strict resolve_sequence with NO cached sequence must return Err on a
    // resolve failure — it must NOT fabricate a base sequence.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn resolve_sequence_errs_on_resolve_failure_without_cache() {
        let api = cipherbox_api_client::ApiClient::new("http://127.0.0.1:1");
        let coordinator = super::PublishCoordinator::new();
        let ipns_name = "k51softnocache";

        let result = coordinator.resolve_sequence(&api, ipns_name).await;
        assert!(
            result.is_err(),
            "non-strict resolve must err on resolve failure when no cached sequence exists (got {:?})",
            result
        );
    }

    // replay_for_vault must record each failed replay so retries accumulate across
    // mounts and the entry parks as Failed at max_retries (D-09). An UploadFile
    // entry with file_meta_ipns_name == None returns Err immediately (no network),
    // exercising the failure path deterministically.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn replay_records_failure_and_parks_at_max_retries() {
        use cipherbox_sdk::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
        use std::sync::Arc;

        let dir = std::env::temp_dir()
            .join("cb-s4-replay-park-test")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = WriteQueue::new(dir.clone(), 5);
        let vault = "k51vaults4park";

        let (parent_child_ref, parent_write_child_ref) = dummy_refs();
        let entry = JournalEntry {
            id: "s4park".to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                sidecar_path: std::path::PathBuf::from("/tmp/s4park.bin"),
                sidecar_sha256: hex::encode([0u8; 32]),
                legacy_ciphertext_b64: String::new(),
                child_published_node: String::new(),
                parent_child_ref,
                parent_write_child_ref,
                file_meta_ipns_name: None, // None -> immediate Err in replay
                parent_folder_ipns_name: vault.to_string(),
                size: 2,
                created_at_ms: 1_700_000_000_000,
            },
            retries: 4, // one below max_retries
            status: JournalEntryStatus::Pending,
        };
        journal.put(&entry).unwrap();

        let api = Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
        let coordinator = Arc::new(super::PublishCoordinator::new());

        // First replay: failure increments retries 4 -> 5, stays Pending.
        super::replay_for_vault(
            &journal,
            api.clone(),
            dir.clone(),
            &[0u8; 32],
            &[0u8; 32],
            vault,
            coordinator.clone(),
            None,
            None,
        )
        .await;
        let after1 = journal.load_all_for_vault(vault).unwrap();
        let e1 = after1
            .iter()
            .find(|e| e.id == "s4park")
            .expect("entry retained after failure");
        assert_eq!(
            e1.retries, 5,
            "retries must increment on a failed replay (F2)"
        );
        assert!(
            matches!(e1.status, JournalEntryStatus::Pending),
            "still Pending below max"
        );

        // Second replay: retries already at max -> parks as Failed (kept on disk).
        super::replay_for_vault(
            &journal,
            api,
            dir.clone(),
            &[0u8; 32],
            &[0u8; 32],
            vault,
            coordinator,
            None,
            None,
        )
        .await;
        let after2 = journal.load_all_for_vault(vault).unwrap();
        let e2 = after2
            .iter()
            .find(|e| e.id == "s4park")
            .expect("parked entry kept on disk");
        assert!(
            matches!(e2.status, JournalEntryStatus::Failed { .. }),
            "entry must park as Failed at max_retries so WriteParked becomes reachable (F2)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
