//! Journal replay on mount.
//!
//! Replays pending write-queue entries on mount so in-flight writes
//! survive crashes. All items carry the same cfg gate as lib.rs.

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::sync::Arc;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use zeroize::Zeroizing;

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use cipherbox_api_client::ApiClient;

// Bring NETWORK_TIMEOUT into scope from the runtime module.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::runtime::NETWORK_TIMEOUT;

// Bring resolve_ipns_for_replay into scope from the publish module (pub(crate) — not re-exported).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::publish::resolve_ipns_for_replay;

// Bring metadata helpers into scope.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::metadata::{encrypt_metadata_to_json, merge_folder_children};

// Bring PublishCoordinator into scope.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::publish::PublishCoordinator;

/// Platform-unified `publish_file_metadata` for replay.
///
/// Under the `fuse` feature, delegates to `crate::operations::implementation`.
/// Under the `winfsp` feature (without `fuse`), delegates to
/// `crate::platform::windows::operations::implementation`.
/// Identical signatures on both sides (same function, duplicated per platform).
#[cfg(feature = "fuse")]
use crate::operations::implementation::publish_file_metadata;
#[cfg(all(feature = "winfsp", not(feature = "fuse")))]
use crate::platform::windows::operations::implementation::publish_file_metadata;

/// Replay all pending journal entries for the given vault on mount.
///
/// Loads all entries for `root_ipns_name` (D-07 vault-scoping), orders them
/// MkdirPublish-before-UploadFile (D-08), then for each entry fetches the parent
/// folder's CURRENT remote metadata, merges the journaled child entry via
/// `merge_folder_children`, and CAS-publishes with retry (D-06 — never re-publishes
/// the stale journaled snapshot).
///
/// Errors are logged but never fail the mount — a partially-replayed journal is
/// better than a failed mount.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn replay_for_vault(
    journal: &cipherbox_sdk::WriteQueue,
    api: Arc<ApiClient>,
    private_key: &[u8],
    public_key: &[u8],
    root_folder_key: &[u8],
    root_ipns_name: &str,
    coordinator: Arc<PublishCoordinator>,
    // F3: TEE key/epoch so a first-publish replay (per-file IPNS never created in the
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

    // #15: local to one replay_for_vault call; never persisted.
    // Seeded with the root key so that root-shortcut lookups (folder_ipns_name == root)
    // are served directly from the cache without entering resolve_folder_key at all.
    let mut folder_key_cache: std::collections::HashMap<String, Zeroizing<Vec<u8>>> =
        std::collections::HashMap::new();
    folder_key_cache.insert(
        root_ipns_name.to_string(),
        Zeroizing::new(root_folder_key.to_vec()),
    );

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

        match &entry.op {
            cipherbox_sdk::JournalOp::MkdirPublish {
                child_ipns_name,
                child_folder_key_hex,
                child_ipns_key_hex,
                parent_folder_ipns_name,
                parent_ipns_key_hex,
                name_encrypted_hex,
                created_at_ms,
            } => {
                // D-03 (WR-07): bound the replay network ops so a hung IPNS/upload call can
                // neither stall the mount nor spin forever. mkdir is metadata-only → 3×.
                // A timeout becomes an Err routed through record_failure (park/retry), exactly
                // like a network error.
                let result = tokio::time::timeout(
                    NETWORK_TIMEOUT * 3,
                    replay_mkdir_entry(
                        &api,
                        private_key,
                        root_folder_key,
                        root_ipns_name,
                        &mut folder_key_cache,
                        coordinator.clone(),
                        child_ipns_name,
                        child_folder_key_hex,
                        child_ipns_key_hex,
                        parent_folder_ipns_name,
                        parent_ipns_key_hex,
                        name_encrypted_hex,
                        *created_at_ms,
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
                });
                match result {
                    Ok(()) => {
                        log::info!(
                            "replay_for_vault: MkdirPublish {} replayed successfully",
                            entry.id
                        );
                        if let Err(e) = journal.remove(&entry.id) {
                            log::warn!(
                                "replay_for_vault: MkdirPublish {} failed to remove journal entry after success: {}; entry may replay again on next mount",
                                entry.id, e
                            );
                        }
                    }
                    Err(e) => {
                        // F2: record the failure so retries accumulate across mounts and the
                        // entry parks as Failed at max_retries (D-09), making the WriteParked
                        // notification reachable at runtime instead of retrying forever.
                        match journal.record_failure(entry, &e) {
                            Ok(cipherbox_sdk::JournalEntryStatus::Failed { .. }) => log::error!(
                                "replay_for_vault: MkdirPublish {} parked as Failed after {} retries: {}",
                                entry.id, journal.max_retries, e
                            ),
                            Ok(_) => log::warn!(
                                "replay_for_vault: MkdirPublish {} failed: {} (retry {}/{}, will retry on next mount)",
                                entry.id, e, entry.retries + 1, journal.max_retries
                            ),
                            Err(re) => log::warn!(
                                "replay_for_vault: MkdirPublish {} failed: {}; record_failure also errored: {}",
                                entry.id, e, re
                            ),
                        }
                    }
                }
            }
            cipherbox_sdk::JournalOp::UploadFile {
                sidecar_path,
                sidecar_sha256,
                legacy_ciphertext_b64,
                wrapped_key_hex,
                iv_hex,
                file_meta_ipns_name,
                file_ipns_key_hex,
                parent_folder_ipns_name,
                parent_ipns_key_hex,
                filename_encrypted_hex,
                size,
                created_at_ms,
            } => {
                // D-02: never trust the persisted JSON `sidecar_path` for a non-legacy entry —
                // re-derive the canonical <journal_dir>/<id>.bin from the journal id so an
                // out-of-band-edited/redirected path cannot make replay read an attacker-chosen
                // file. The empty-path branch (legacy/inline ciphertext) is preserved verbatim.
                // `derived_sidecar_path` is bound here so the derived owned PathBuf outlives the
                // borrow passed into the (awaited) replay call below.
                let derived_sidecar_path: std::path::PathBuf;
                let replay_sidecar_path: &std::path::Path = if sidecar_path.as_os_str().is_empty() {
                    sidecar_path
                } else {
                    derived_sidecar_path = journal.sidecar_path_for(&entry.id);
                    &derived_sidecar_path
                };
                // D-03 (WR-07): bound the replay network ops. upload may re-stream a multi-GB
                // sidecar → 18× (~180s). Idempotent re-upload means a timeout safely retains
                // the entry via record_failure.
                let result = tokio::time::timeout(
                    NETWORK_TIMEOUT * 18,
                    replay_upload_entry(
                        &api,
                        private_key,
                        public_key,
                        root_folder_key,
                        root_ipns_name,
                        &mut folder_key_cache,
                        coordinator.clone(),
                        replay_sidecar_path,
                        sidecar_sha256,
                        legacy_ciphertext_b64,
                        wrapped_key_hex,
                        iv_hex,
                        file_meta_ipns_name.as_deref(),
                        file_ipns_key_hex.as_deref(),
                        parent_folder_ipns_name,
                        parent_ipns_key_hex,
                        filename_encrypted_hex,
                        *size,
                        *created_at_ms,
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
                });
                match result {
                    Ok(()) => {
                        log::info!(
                            "replay_for_vault: UploadFile {} replayed successfully",
                            entry.id
                        );
                        if let Err(e) = journal.remove(&entry.id) {
                            log::warn!(
                                "replay_for_vault: UploadFile {} failed to remove journal entry after success: {}; entry may replay again on next mount",
                                entry.id, e
                            );
                        }
                    }
                    Err(e) => {
                        // F2: record the failure so retries accumulate across mounts and the
                        // entry parks as Failed at max_retries (D-09), making the WriteParked
                        // notification reachable at runtime instead of retrying forever.
                        // Note: the plaintext filename is not logged here — it is ECIES-encrypted
                        // at rest (D-04) and only decrypted transiently inside replay_upload_entry.
                        match journal.record_failure(entry, &e) {
                            Ok(cipherbox_sdk::JournalEntryStatus::Failed { .. }) => log::error!(
                                "replay_for_vault: UploadFile {} parked as Failed after {} retries: {}",
                                entry.id, journal.max_retries, e
                            ),
                            Ok(_) => log::warn!(
                                "replay_for_vault: UploadFile {} failed: {} (retry {}/{}, will retry on next mount)",
                                entry.id, e, entry.retries + 1, journal.max_retries
                            ),
                            Err(re) => log::warn!(
                                "replay_for_vault: UploadFile {} failed: {}; record_failure also errored: {}",
                                entry.id, e, re
                            ),
                        }
                    }
                }
            }
        }
    }
}

/// Look up the folder key for `folder_ipns_name` via a bounded breadth-first descent.
///
/// WR-02: resolves parent folders nested two or more levels below root, not just
/// direct children of root. The BFS is capped at `MAX_RESOLVE_NODES` to bound network
/// round trips and prevent cycles.
///
/// If `folder_ipns_name == root_ipns_name`, returns `root_folder_key` directly.
/// Otherwise starts from root and iterates through the folder tree level by level,
/// decrypting each layer's metadata with the just-unwrapped folder key from the layer above.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
async fn resolve_folder_key(
    api: &ApiClient,
    private_key: &[u8],
    root_folder_key: &[u8],
    root_ipns_name: &str,
    folder_ipns_name: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    // Node-visit cap: bounds total network round trips and prevents infinite loops
    // (WR-02). This counts nodes visited across the BFS, not tree depth.
    const MAX_RESOLVE_NODES: usize = 32;

    if folder_ipns_name == root_ipns_name {
        return Ok(Zeroizing::new(root_folder_key.to_vec()));
    }

    // BFS queue: (ipns_name_of_this_folder, unwrapped_folder_key_for_this_folder).
    // Starts at root; each step expands to all subfolder children of the current node.
    // Keys are Zeroizing so they are wiped from memory on drop.
    let mut queue: std::collections::VecDeque<(String, Zeroizing<Vec<u8>>)> =
        std::collections::VecDeque::new();
    queue.push_back((
        root_ipns_name.to_string(),
        Zeroizing::new(root_folder_key.to_vec()),
    ));
    let mut nodes_visited = 0usize;

    while let Some((current_ipns, current_folder_key)) = queue.pop_front() {
        if nodes_visited >= MAX_RESOLVE_NODES {
            return Err(format!(
                "resolve_folder_key: node cap ({}) exceeded looking for {} — aborting",
                MAX_RESOLVE_NODES, folder_ipns_name
            ));
        }
        nodes_visited += 1;

        // Fetch and decrypt this folder's metadata.
        // D-01: route through the verified chokepoint.
        // D-03 (security boundary): hard fail-closed on Invalid/Api; Legacy is warn+continue.
        let resolved_cid =
            match crate::verify::resolve_ipns_verified(api, &current_ipns).await {
                Ok(verified) => verified.cid,
                Err(crate::verify::VerifyError::Legacy { cid, .. }) => {
                    // D-03: all-absent legacy record — use the carried cid (no second resolve_ipns).
                    // T-59-04: eliminates the TOCTOU race window.
                    // DB CID authoritative; backward-compatible with pre-signing records.
                    log::warn!(
                        "resolve_folder_key: IPNS {} resolved without signature fields — \
                         proceeding (D-03, DB CID authoritative)",
                        current_ipns
                    );
                    cid
                }
                Err(crate::verify::VerifyError::Invalid(msg)) => {
                    // D-03 hard fail-closed: invalid/partial signature → refuse CID.
                    return Err(format!(
                        "IPNS {} signature verification failed — refusing to use CID (D-02): {}",
                        current_ipns, msg
                    ));
                }
                Err(crate::verify::VerifyError::Api(e)) => {
                    return Err(format!("resolve IPNS {}: {}", current_ipns, e));
                }
            };

        let enc_bytes = cipherbox_api_client::ipfs::fetch_content(api, &resolved_cid)
            .await
            .map_err(|e| format!("fetch metadata for {}: {}", current_ipns, e))?;
        let meta =
            cipherbox_core::decrypt_metadata_from_ipfs_public(&enc_bytes, &current_folder_key)
                .map_err(|e| format!("decrypt metadata for {}: {}", current_ipns, e))?;

        for child in &meta.children {
            if let cipherbox_core::folder::FolderChild::Folder(f) = child {
                let enc_key_bytes = hex::decode(&f.folder_key_encrypted).map_err(|e| {
                    format!("hex decode folder_key_encrypted for {}: {}", f.ipns_name, e)
                })?;
                // unwrap_key now returns Zeroizing<Vec<u8>> — key is wiped on drop.
                let child_folder_key =
                    cipherbox_crypto::ecies::unwrap_key(&enc_key_bytes, private_key)
                        .map_err(|e| format!("unwrap folder key for {}: {}", f.ipns_name, e))?;

                if f.ipns_name == folder_ipns_name {
                    // Found the target folder.
                    return Ok(child_folder_key);
                }

                // Enqueue for further descent.
                queue.push_back((f.ipns_name.clone(), child_folder_key));
            }
        }
    }

    Err(format!(
        "folder IPNS {} not found in vault tree (searched {} nodes)",
        folder_ipns_name, nodes_visited
    ))
}

/// Memoizing wrapper around `resolve_folder_key` for use within a single `replay_for_vault` call.
///
/// #15: on cache hit returns the clone immediately without entering the BFS; on miss runs
/// `resolve_folder_key` (BFS unchanged — `MAX_RESOLVE_NODES` cap and root-shortcut intact),
/// inserts the result into the cache, and returns it.
///
/// The cache is declared inside `replay_for_vault` and dropped at the end of that call —
/// it is never persisted and never shared with the running filesystem.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
async fn resolve_folder_key_cached(
    cache: &mut std::collections::HashMap<String, Zeroizing<Vec<u8>>>,
    api: &ApiClient,
    private_key: &[u8],
    root_folder_key: &[u8],
    root_ipns_name: &str,
    folder_ipns_name: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if let Some(key) = cache.get(folder_ipns_name) {
        return Ok(key.clone());
    }
    let key = resolve_folder_key(
        api,
        private_key,
        root_folder_key,
        root_ipns_name,
        folder_ipns_name,
    )
    .await?;
    // Store the key wrapped in `Zeroizing` so it is wiped from memory when the cache
    // is dropped at the end of `replay_for_vault`. `resolve_folder_key` already returns
    // `Zeroizing<Vec<u8>>`, so this is a single clone into the cache.
    let cached = cache
        .entry(folder_ipns_name.to_string())
        .or_insert_with(|| key.clone());
    Ok(cached.clone())
}

/// Fetch, decrypt, merge, and CAS-publish a parent folder update.
///
/// Core CR-01 / D-06 implementation: fetches CURRENT remote metadata, merges, then
/// signs and publishes an IPNS record with the provided unwrapped parent IPNS private key.
/// Returns `Err` if the publish did not succeed (Conflict or key absent) so the caller
/// retains the journal entry for the next mount.
///
/// IMPORTANT: `unpin_content` is NOT called on the pre-merge CID here. The old CID is
/// unpinned only after a confirmed `PublishResult::Success` (T-43-19 — never unpin a CID
/// that the live IPNS record still references).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
// `parent_ipns_private_key_raw`: unwrapped (raw 32-byte) Ed25519 parent IPNS key for signing.
// Must be obtained via ecies::unwrap_key(parent_ipns_key_hex). If empty, returns Err (CR-01).
async fn fetch_merge_publish_parent(
    api: &ApiClient,
    folder_key: &[u8],
    parent_ipns_name: &str,
    parent_ipns_private_key_raw: &[u8],
    coordinator: Arc<PublishCoordinator>,
    local_child: cipherbox_core::folder::FolderChild,
) -> Result<(), String> {
    use base64::Engine;

    // CR-01: if the caller could not unwrap the parent IPNS key, retain the entry.
    if parent_ipns_private_key_raw.is_empty() {
        return Err("parent IPNS private key unavailable — retaining journal entry".to_string());
    }

    let lock = coordinator.get_lock(parent_ipns_name);
    let _guard = lock.lock().await;

    // D-06: fetch CURRENT remote metadata (not the stale journaled snapshot).
    // D-01: route through the verified chokepoint.
    let parent_cid = match crate::verify::resolve_ipns_verified(api, parent_ipns_name).await {
        Ok(verified) => verified.cid,
        Err(crate::verify::VerifyError::Legacy { cid, .. }) => {
            // D-04: legacy record — use the carried cid (no second resolve_ipns).
            // T-59-04: eliminates the TOCTOU race window.
            log::warn!(
                "fetch_merge_publish_parent: IPNS {} resolved without signature fields \
                 — using DB CID (D-04)",
                parent_ipns_name
            );
            cid
        }
        Err(crate::verify::VerifyError::Invalid(msg)) => {
            // Journal entry retained — return Err so the replay loop keeps the entry.
            return Err(format!(
                "parent IPNS {} verify failed — retaining journal entry: {}",
                parent_ipns_name, msg
            ));
        }
        Err(crate::verify::VerifyError::Api(e)) => {
            return Err(format!("resolve parent IPNS {}: {}", parent_ipns_name, e));
        }
    };
    let remote_bytes = cipherbox_api_client::ipfs::fetch_content(api, &parent_cid)
        .await
        .map_err(|e| format!("fetch parent metadata: {}", e))?;
    let remote_meta = cipherbox_core::decrypt_metadata_from_ipfs_public(&remote_bytes, folder_key)
        .map_err(|e| format!("decrypt parent metadata: {}", e))?;

    // D-06 idempotency: check if the child is already present in the remote.
    let child_ipns_key = match &local_child {
        cipherbox_core::folder::FolderChild::Folder(f) => f.ipns_name.clone(),
        cipherbox_core::folder::FolderChild::File(f) => f.file_meta_ipns_name.clone(),
    };
    let already_present = remote_meta.children.iter().any(|c| {
        let ipns = match c {
            cipherbox_core::folder::FolderChild::Folder(f) => &f.ipns_name,
            cipherbox_core::folder::FolderChild::File(f) => &f.file_meta_ipns_name,
        };
        ipns == &child_ipns_key
    });
    if already_present {
        log::info!(
            "replay: child {} already present in parent {} — skipping merge (idempotent, Pitfall 5)",
            child_ipns_key,
            parent_ipns_name
        );
        return Ok(());
    }

    // Merge local child into remote (union merge).
    let local_meta = cipherbox_core::folder::FolderMetadata {
        version: "v2".to_string(),
        children: vec![local_child],
    };
    let merged = merge_folder_children(&local_meta, remote_meta);

    // Encrypt and upload the merged metadata.
    let json_bytes = encrypt_metadata_to_json(&merged, folder_key)?;
    let seq = coordinator.resolve_sequence(api, parent_ipns_name).await?;
    let new_cid = cipherbox_api_client::ipfs::upload_content(api, &json_bytes)
        .await
        .map_err(|e| format!("upload merged metadata: {}", e))?;

    // CR-01: sign and publish the parent IPNS record with the unwrapped key.
    // Mirror the live mkdir parent-publish flow from write_ops.rs:596-641.
    let parent_key_arr: [u8; 32] = parent_ipns_private_key_raw.try_into().map_err(|_| {
        format!(
            "parent IPNS key has wrong length (got {}, expected 32) — retaining journal entry",
            parent_ipns_private_key_raw.len()
        )
    })?;
    let new_seq = seq
        .checked_add(1)
        .ok_or_else(|| "IPNS sequence number overflow".to_string())?;
    let parent_value = format!("/ipfs/{}", new_cid);
    let parent_record =
        cipherbox_core::create_ipns_record(&parent_key_arr, &parent_value, new_seq, 86_400_000)
            .map_err(|e| format!("create parent IPNS record: {}", e))?;
    let parent_marshaled = cipherbox_core::marshal_ipns_record(&parent_record)
        .map_err(|e| format!("marshal parent IPNS record: {}", e))?;
    let parent_record_b64 = base64::engine::general_purpose::STANDARD.encode(&parent_marshaled);

    let parent_req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: parent_ipns_name.to_string(),
        record: parent_record_b64,
        metadata_cid: new_cid.clone(),
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: Some(seq.to_string()),
    };

    match cipherbox_api_client::ipns::publish_ipns(api, &parent_req)
        .await
        .map_err(|e| format!("publish parent IPNS: {}", e))?
    {
        cipherbox_api_client::PublishResult::Success => {
            // CR-01 / T-43-21: only advance the sequence cache on confirmed Success (IN-06 fix).
            coordinator.record_publish(parent_ipns_name, new_seq);
            // T-43-19: unpin the OLD CID (the one the live IPNS record no longer references)
            // only AFTER the new record is confirmed live.
            let _ = cipherbox_api_client::ipfs::unpin_content(api, &parent_cid).await;
            log::info!(
                "replay: parent IPNS published for {} (new_seq={}, new_cid={})",
                parent_ipns_name,
                new_seq,
                new_cid
            );
            Ok(())
        }
        cipherbox_api_client::PublishResult::Conflict {
            current_sequence_number,
        } => {
            // T-43-18: CAS conflict — do NOT remove the journal entry; retain for next mount.
            // The new_cid is still pinned on IPFS which is safe (it just won't be referenced yet).
            log::warn!(
                "replay: CAS conflict on parent {} (expected seq {}, server has {:?}) — retaining entry",
                parent_ipns_name, seq, current_sequence_number
            );
            Err(format!(
                "IPNS conflict on parent {} (server seq {:?}) — will retry on next mount",
                parent_ipns_name, current_sequence_number
            ))
        }
    }
}

/// Publish a child folder's initial empty `FolderMetadata` (seq 0) during replay.
///
/// Mirrors the live mkdir background publish (`write_ops.rs`) and
/// [`publish_file_metadata`]: encrypt the empty `{ version: "v2", children: [] }`
/// metadata with the child folder key, upload, create a seq-0 IPNS record signed by the
/// child IPNS key, enroll the child key with the TEE on first publish, then publish.
/// Closes the crash window where `MkdirPublish` was fsynced but the child's own IPNS
/// record was never created — which would otherwise leave the merged parent pointing at
/// an unresolvable child IPNS name.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
async fn publish_child_folder_metadata(
    api: &ApiClient,
    child_folder_key: &[u8],
    child_ipns_private_key: &zeroize::Zeroizing<Vec<u8>>,
    child_ipns_name: &str,
    coordinator: &PublishCoordinator,
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
) -> Result<(), String> {
    use base64::Engine;

    let metadata = cipherbox_core::folder::FolderMetadata {
        version: "v2".to_string(),
        children: vec![],
    };
    let json_bytes = encrypt_metadata_to_json(&metadata, child_folder_key)?;
    let initial_cid = cipherbox_api_client::ipfs::upload_content(api, &json_bytes)
        .await
        .map_err(|e| format!("upload child folder metadata: {}", e))?;

    let ipns_key_arr: [u8; 32] = child_ipns_private_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid child IPNS key length".to_string())?;
    let value = format!("/ipfs/{}", initial_cid);
    let record = cipherbox_core::ipns::create_ipns_record(&ipns_key_arr, &value, 0, 86_400_000)
        .map_err(|e| format!("child IPNS record creation failed: {}", e))?;
    let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
        .map_err(|e| format!("child IPNS marshal failed: {}", e))?;
    let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

    // TEE enrollment on first publish (same pattern as publish_file_metadata).
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
        metadata_cid: initial_cid,
        encrypted_ipns_private_key: encrypted_ipns_for_tee,
        key_epoch: tee_epoch,
        expected_sequence_number: None,
    };
    match cipherbox_api_client::ipns::publish_ipns(api, &req)
        .await
        .map_err(|e| format!("{}", e))?
    {
        cipherbox_api_client::PublishResult::Success => {}
        cipherbox_api_client::PublishResult::Conflict { .. } => {
            // Seq 0 should never conflict — log and continue (matches the live mkdir path).
            log::warn!(
                "replay: unexpected conflict on child folder IPNS publish for {}",
                child_ipns_name
            );
        }
    }
    coordinator.record_publish(child_ipns_name, 0);
    log::info!(
        "replay: child folder IPNS published (seq 0) for {}",
        child_ipns_name
    );
    Ok(())
}

/// Replay a single `MkdirPublish` journal entry.
/// Re-publishes the child folder's seq-0 IPNS record (idempotent), then fetches current
/// parent metadata, merges the child folder entry, and CAS-publishes the parent.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
async fn replay_mkdir_entry(
    api: &ApiClient,
    private_key: &[u8],
    root_folder_key: &[u8],
    root_ipns_name: &str,
    // #15: per-replay folder-key cache; seeded with root key in replay_for_vault.
    folder_key_cache: &mut std::collections::HashMap<String, Zeroizing<Vec<u8>>>,
    coordinator: Arc<PublishCoordinator>,
    child_ipns_name: &str,
    child_folder_key_hex: &str,
    // child_ipns_key_hex: user-ECIES-wrapped child IPNS key; written as-is (CR-03, no re-wrap).
    child_ipns_key_hex: &str,
    parent_folder_ipns_name: &str,
    // parent_ipns_key_hex: user-ECIES-wrapped parent IPNS key from journal (CR-01).
    parent_ipns_key_hex: &str,
    // D-04: ECIES-encrypted directory name hex; decrypted transiently via decrypt_journal_name.
    name_encrypted_hex: &str,
    created_at_ms: u64,
    // TEE key/epoch for child-folder first-publish enrollment when the child's seq-0 IPNS
    // record was never created in the original (failed) session.
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
) -> Result<(), String> {
    // D-04: decrypt the directory name transiently (legacy plaintext passes through; a
    // corrupt ECIES name returns Err so the entry is retained, never replayed as garbage).
    let name = decrypt_journal_name(name_encrypted_hex, private_key)?;

    let parent_folder_key = resolve_folder_key_cached(
        folder_key_cache,
        api,
        private_key,
        root_folder_key,
        root_ipns_name,
        parent_folder_ipns_name,
    )
    .await?;

    // CR-01: hex-decode and ecies-unwrap the journaled parent IPNS key.
    // Returns Err if the key is absent/malformed so the entry is retained (T-43-20).
    let parent_ipns_key_raw = if parent_ipns_key_hex.is_empty() {
        return Err(
            "parent_ipns_key_hex is empty in MkdirPublish entry — retaining for retry".to_string(),
        );
    } else {
        let wrapped_bytes = hex::decode(parent_ipns_key_hex)
            .map_err(|e| format!("hex decode parent_ipns_key_hex: {} — retaining entry", e))?;
        cipherbox_crypto::ecies::unwrap_key(&wrapped_bytes, private_key)
            .map_err(|e| format!("ecies unwrap parent IPNS key: {} — retaining entry", e))?
    };

    // CR-491: re-publish the child folder's own initial (empty) FolderMetadata before
    // merging it into the parent. A crash after the MkdirPublish journal fsync but before
    // the live background thread created the child's seq-0 IPNS record would otherwise leave
    // the parent pointing at a child IPNS name that resolves to nothing. Idempotent: if the
    // child record already exists (publish completed pre-crash), skip; a transient resolve
    // error retains the entry for retry.
    if child_ipns_key_hex.is_empty() {
        return Err(
            "child_ipns_key_hex is empty in MkdirPublish entry — retaining for retry".to_string(),
        );
    }
    {
        use crate::error::IpnsResolveOutcome;
        match resolve_ipns_for_replay(coordinator.as_ref(), api, child_ipns_name).await {
            IpnsResolveOutcome::Found(_) => {
                log::info!(
                    "replay: child folder IPNS '{}' already published — skipping seq-0 publish",
                    child_ipns_name
                );
            }
            IpnsResolveOutcome::NotFound => {
                // Unwrap the user-ECIES-wrapped child IPNS key and folder key to sign and
                // encrypt the child's own metadata record. Both are zeroized on drop.
                let child_ipns_key_wrapped = hex::decode(child_ipns_key_hex).map_err(|e| {
                    format!("hex decode child_ipns_key_hex: {} — retaining entry", e)
                })?;
                // unwrap_key returns Zeroizing<Vec<u8>> directly (S3/D-05).
                let child_ipns_key_raw =
                    cipherbox_crypto::ecies::unwrap_key(&child_ipns_key_wrapped, private_key)
                        .map_err(|e| {
                            format!("ecies unwrap child IPNS key: {} — retaining entry", e)
                        })?;
                let child_folder_key_wrapped = hex::decode(child_folder_key_hex).map_err(|e| {
                    format!("hex decode child_folder_key_hex: {} — retaining entry", e)
                })?;
                // unwrap_key returns Zeroizing<Vec<u8>> directly (S3/D-05).
                let child_folder_key_raw =
                    cipherbox_crypto::ecies::unwrap_key(&child_folder_key_wrapped, private_key)
                        .map_err(|e| {
                            format!("ecies unwrap child folder key: {} — retaining entry", e)
                        })?;
                publish_child_folder_metadata(
                    api,
                    &child_folder_key_raw,
                    &child_ipns_key_raw,
                    child_ipns_name,
                    coordinator.as_ref(),
                    tee_public_key,
                    tee_key_epoch,
                )
                .await?;
            }
            IpnsResolveOutcome::Error(e) => {
                return Err(format!(
                    "resolve child folder IPNS sequence: {} — retaining entry",
                    e
                ));
            }
        }
    }

    // CR-03: write the user-ECIES-wrapped child IPNS key as-is into FolderEntry.
    // The journal already stores the user-wrapped form (populated by 43-06 write side fix).
    // No re-wrap here — that would produce a doubly-wrapped key.
    let child_entry =
        cipherbox_core::folder::FolderChild::Folder(cipherbox_core::folder::FolderEntry {
            id: format!("replay-{}", child_ipns_name),
            name: name.to_string(),
            ipns_name: child_ipns_name.to_string(),
            folder_key_encrypted: child_folder_key_hex.to_string(),
            // CR-03: user-ECIES-wrapped child IPNS key, matching build_folder_metadata convention.
            ipns_private_key_encrypted: child_ipns_key_hex.to_string(),
            created_at: created_at_ms,
            modified_at: created_at_ms,
        });

    fetch_merge_publish_parent(
        api,
        &parent_folder_key,
        parent_folder_ipns_name,
        &parent_ipns_key_raw,
        coordinator,
        child_entry,
    )
    .await
}

/// Decrypt a journaled name field (D-04, IN-03) with passthrough-once legacy compat.
///
/// `encrypted_hex` is normally a hex-encoded ECIES ciphertext of the name, produced
/// write-side by `cipherbox_crypto::ecies::wrap_key`. This helper hex-decodes then
/// `ecies::unwrap_key`s it with the user private key and returns the plaintext name.
///
/// Failure handling distinguishes the legacy signal from genuine corruption:
///
/// * **Not valid hex** → treated as a pre-Phase-52 legacy plaintext name: a `log::warn!`
///   is emitted once and the input is returned verbatim (`Ok`) for this single replay.
/// * **Valid hex but too short to be an ECIES ciphertext** (fewer than
///   `ECIES_MIN_CIPHERTEXT_SIZE` decoded bytes) → also a legacy plaintext name. Hex-validity
///   alone does NOT prove a Phase-52 name: a pre-Phase-52 filename can itself be pure
///   even-length hex (a hyphen-less UUID, a SHA-1/SHA-256 digest, a git object id, …). A
///   genuine ECIES name is always `ephemeral_pubkey(65) || nonce(16) || tag(16) ||
///   ciphertext`, and bit-rot flips bytes in place without shrinking it, so anything below
///   the unwrap floor cannot be one. Pass it through verbatim rather than parking it for a
///   retry it can never pass — a parked entry is age-purged by `gc_failed_entries` (sidecar
///   `.bin` and all), which would destroy the captured write.
/// * **Valid hex, long enough, but ECIES-unwrap fails or unwraps to non-UTF-8** → the
///   at-rest ciphertext is corrupt (e.g. bit-rot). Returning the raw hex as a filename would
///   publish a garbage name AND discard the original write (a successful replay removes
///   the entry). Instead return `Err` so the caller retains/parks the entry for retry.
///   The error message deliberately leaks neither the name nor any host path (D-04).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) fn decrypt_journal_name(encrypted_hex: &str, private_key: &[u8]) -> Result<String, String> {
    // Legacy passthrough applies to any value that cannot be a Phase-52 ECIES name: a
    // non-hex value, OR hex that decodes to fewer bytes than the minimum ECIES ciphertext
    // (a hex-shaped legacy plaintext filename — UUID, SHA digest, etc.).
    let decoded = match hex::decode(encrypted_hex) {
        Ok(bytes) if bytes.len() >= cipherbox_crypto::ecies::ECIES_MIN_CIPHERTEXT_SIZE => bytes,
        _ => {
            log::warn!(
                "replay: legacy plaintext journal name — replaying once, not re-persisting"
            );
            return Ok(encrypted_hex.to_string());
        }
    };
    // Long enough to be an ECIES ciphertext: it must decrypt. A failure here is corruption,
    // not a legacy name — do NOT pass the raw hex through as a filename; retain the entry.
    let plaintext = cipherbox_crypto::ecies::unwrap_key(&decoded, private_key)
        .map_err(|_| "corrupt encrypted journal name — retaining entry".to_string())?;
    String::from_utf8(plaintext.to_vec())
        .map_err(|_| "corrupt encrypted journal name — retaining entry".to_string())
}

/// Replay a single `UploadFile` journal entry.
/// Re-uploads ciphertext (idempotent CID), re-publishes file IPNS, merges file pointer
/// into current parent metadata.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
async fn replay_upload_entry(
    api: &ApiClient,
    private_key: &[u8],
    _public_key: &[u8],
    root_folder_key: &[u8],
    root_ipns_name: &str,
    // #15: per-replay folder-key cache; seeded with root key in replay_for_vault.
    folder_key_cache: &mut std::collections::HashMap<String, Zeroizing<Vec<u8>>>,
    coordinator: Arc<PublishCoordinator>,
    // D-01: ciphertext is read from the sidecar .bin (path + sha256), not an inline blob.
    sidecar_path: &std::path::Path,
    sidecar_sha256: &str,
    // Compat-only: pre-Phase-52 inline base64 ciphertext, present only on legacy entries that
    // have no sidecar. Used for a one-time passthrough replay so the upload is not lost.
    legacy_ciphertext_b64: &str,
    wrapped_key_hex: &str,
    iv_hex: &str,
    file_meta_ipns_name: Option<&str>,
    file_ipns_key_hex: Option<&str>,
    parent_folder_ipns_name: &str,
    // parent_ipns_key_hex: user-ECIES-wrapped parent IPNS private key from journal (CR-01).
    parent_ipns_key_hex: &str,
    // D-04: ECIES-encrypted filename hex; decrypted transiently via decrypt_journal_name.
    filename_encrypted_hex: &str,
    size: u64,
    created_at_ms: u64,
    // F3: TEE key/epoch for first-publish enrollment when the per-file IPNS record
    // was never created in the original (failed) session.
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
) -> Result<(), String> {
    // D-04: decrypt the filename transiently (legacy plaintext passes through; a corrupt
    // ECIES name returns Err so the entry is retained, never replayed as garbage).
    let filename = decrypt_journal_name(filename_encrypted_hex, private_key)?;

    // REQ-4: park legacy entries with no per-file IPNS name rather than publishing an
    // empty, unresolvable FilePointer (id "replay-", file_meta_ipns_name ""). Returning
    // Err routes through record_failure → retained on disk; never marks the entry replayed.
    // No fresh-IPNS minting — lowest risk, no new key material. Placed above Step 1 (the
    // ciphertext upload/pin) so legacy entries don't re-pin content on every mount.
    if file_meta_ipns_name.is_none() {
        return Err(
            "legacy UploadFile entry has no per-file IPNS name -- parking (no empty FilePointer)"
                .to_string(),
        );
    }

    // CR-01: hex-decode and ecies-unwrap the journaled parent IPNS key.
    // Returns Err if the key is absent/malformed so the entry is retained (T-43-20).
    let parent_ipns_key_raw = if parent_ipns_key_hex.is_empty() {
        return Err(
            "parent_ipns_key_hex is empty in UploadFile entry — retaining for retry".to_string(),
        );
    } else {
        let wrapped_bytes = hex::decode(parent_ipns_key_hex)
            .map_err(|e| format!("hex decode parent_ipns_key_hex: {} — retaining entry", e))?;
        cipherbox_crypto::ecies::unwrap_key(&wrapped_bytes, private_key)
            .map_err(|e| format!("ecies unwrap parent IPNS key: {} — retaining entry", e))?
    };

    // Step 1: re-upload ciphertext (idempotent — same plaintext → same ciphertext → same CID).
    // D-01: read the ciphertext from the sidecar .bin and verify its SHA-256 before re-upload.
    // A missing sidecar (legacy in-flight entry, or an already-cleaned happy-path entry) or a
    // hash mismatch returns Err so the entry is RETAINED (record_failure) — never re-upload
    // corrupted or absent ciphertext, and never publish a bad CID.
    let ciphertext = if sidecar_path.as_os_str().is_empty() {
        // Legacy pre-Phase-52 entry: no sidecar, ciphertext stored inline as base64. Honor it
        // for a one-time passthrough replay so the pending upload is not lost at upgrade. The
        // entry is removed (not re-persisted) once replay succeeds, so this only runs once.
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
        // D-01: read the ciphertext from the sidecar .bin and verify its SHA-256 before re-upload.
        // The sidecar path is NOT included in the error (it can leak host directories through
        // logs / record_failure — the scrubbing this phase adds, D-05).
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

    log::info!(
        "replay: re-uploaded ciphertext for '{}' -> CID {}",
        filename,
        file_cid
    );

    // Step 2: resolve parent folder key for subsequent steps.
    // #15: uses the memoizing wrapper — on cache hit (same parent seen earlier in this replay)
    // returns immediately without BFS; on miss runs resolve_folder_key unchanged.
    let parent_folder_key = resolve_folder_key_cached(
        folder_key_cache,
        api,
        private_key,
        root_folder_key,
        root_ipns_name,
        parent_folder_ipns_name,
    )
    .await?;

    // Step 3: re-publish file IPNS metadata if both the IPNS key AND the IPNS name are
    // available. The name guard (Option<&str>) replaces the old empty-string sentinel (#18):
    // None means "no per-file IPNS record" and the publish block is skipped, preserving
    // the existing behavior where an absent name → no per-file publish (T-45-03-DUR).
    if let Some(file_ipns_key_hex_str) = file_ipns_key_hex {
        if !file_ipns_key_hex_str.is_empty() {
            if let Some(file_meta_ipns_name) = file_meta_ipns_name {
                // CR-02: ecies-unwrap the ECIES-wrapped file IPNS key before casting to [u8;32].
                // The journaled key is user-ECIES-wrapped (~117 bytes), NOT a raw 32-byte key.
                // Directly casting the wrapped bytes always fails (they're ~117 bytes, not 32).
                let file_ipns_key_wrapped = hex::decode(file_ipns_key_hex_str)
                    .map_err(|e| format!("hex decode file_ipns_key: {}", e))?;
                // unwrap_key returns Zeroizing<Vec<u8>> directly (S3/D-05).
                // CR-02: the raw key is zeroized on drop; no cast to [u8;32] needed here
                // because publish_file_metadata accepts &Zeroizing<Vec<u8>> and casts internally.
                let file_ipns_key =
                    cipherbox_crypto::ecies::unwrap_key(&file_ipns_key_wrapped, private_key)
                        .map_err(|e| format!("ecies unwrap file IPNS key: {}", e))?;

                let file_meta = cipherbox_core::folder::FileMetadata {
                    version: "v1".to_string(),
                    cid: file_cid.clone(),
                    file_key_encrypted: wrapped_key_hex.to_string(),
                    file_iv: iv_hex.to_string(),
                    size,
                    mime_type: String::new(),
                    encryption_mode: "GCM".to_string(),
                    created_at: created_at_ms,
                    modified_at: created_at_ms,
                    versions: None,
                };

                // F3: determine whether the per-file IPNS record already exists. If the original
                // upload failed before ever creating it, resolve returns not-found and this is a
                // FIRST publish (seq 0 + TEE enrollment), mirroring the live path
                // (operations.rs::publish_file_metadata). Otherwise it is an update (seq + 1).
                // A transient resolve error (not "not found") is propagated so the entry is
                // retained for retry rather than creating a duplicate record at seq 0.
                // #19: classification is centralised in resolve_ipns_for_replay; the typed
                // IpnsResolveOutcome replaces the brittle .contains("not found") inline match.
                let is_first_publish = {
                    use crate::error::IpnsResolveOutcome;
                    match resolve_ipns_for_replay(coordinator.as_ref(), api, file_meta_ipns_name)
                        .await
                    {
                        IpnsResolveOutcome::Found(_) => false,
                        IpnsResolveOutcome::NotFound => {
                            log::info!(
                                "replay: per-file IPNS '{}' not found — creating as first publish (seq 0)",
                                file_meta_ipns_name
                            );
                            true
                        }
                        IpnsResolveOutcome::Error(e) => {
                            return Err(format!(
                                "resolve file IPNS sequence: {} — retaining entry",
                                e
                            ))
                        }
                    }
                };

                // #20: delegate encrypt→upload→IPNS-record→TEE-wrap→publish to the shared
                // `publish_file_metadata` (operations.rs / platform/windows/operations.rs).
                // Only ECIES-unwrap (Step 1, above) and `is_first_publish` (Step F3, above) stay
                // local — publish_file_metadata handles all remaining publish steps including
                // TEE enrollment on first publish and `record_publish` for sequence tracking.
                publish_file_metadata(
                    api,
                    &file_meta,
                    &parent_folder_key,
                    &file_ipns_key,
                    file_meta_ipns_name,
                    coordinator.as_ref(),
                    tee_public_key,
                    tee_key_epoch,
                    is_first_publish,
                )
                .await
                .map_err(|e| format!("replay file IPNS publish: {}", e))?;

                log::info!(
                    "replay: file IPNS published for '{}' (first_publish={})",
                    filename,
                    is_first_publish
                );
            }
        }
    }

    // Step 4: merge file pointer into parent folder metadata (D-06 fetch-and-merge).
    // Use unwrap_or_default() for the IPNS name in the FilePointer: when None (no per-file
    // IPNS record), an empty string preserves the pre-Phase-45 behavior where files without
    // a per-file IPNS name are still merged into the parent via their FilePointer entry.
    let file_meta_ipns_name_str = file_meta_ipns_name.unwrap_or_default();
    let file_pointer =
        cipherbox_core::folder::FolderChild::File(cipherbox_core::folder::FilePointer {
            id: format!("replay-{}", file_meta_ipns_name_str),
            name: filename.to_string(),
            file_meta_ipns_name: file_meta_ipns_name_str.to_string(),
            // CR-02: store the journaled file_ipns_key_hex AS-IS — it is already user-ECIES-wrapped.
            // Do NOT re-wrap: that would produce a doubly-wrapped key in the stored FilePointer.
            ipns_private_key_encrypted: file_ipns_key_hex.map(|k| k.to_string()),
            created_at: created_at_ms,
            modified_at: created_at_ms,
        });

    fetch_merge_publish_parent(
        api,
        &parent_folder_key,
        parent_folder_ipns_name,
        &parent_ipns_key_raw,
        coordinator,
        file_pointer,
    )
    .await
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    use zeroize::Zeroizing;

    // T-45-06: replay_for_vault must skip Failed entries entirely (not re-attempt, not
    // remove). Pins the current behavior so refactors (#11/#15/#20) cannot regress it.
    // An entry with status=Failed and a non-routable API host demonstrates that the
    // entry count stays at 1 after replay — i.e., it was neither removed nor re-queued.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn replay_for_vault_does_not_touch_failed_entries() {
        use cipherbox_sdk::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
        use std::sync::Arc; // noqa: already in scope via the test module's outer `use`

        let dir = std::env::temp_dir()
            .join("cb-t45-06-replay-skip-failed")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = WriteQueue::new(dir.clone(), 5);
        let vault = "k51vault45t06";

        // Build an entry that is already Failed before replay starts.
        let entry = JournalEntry {
            id: "failed-t4506".to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                sidecar_path: std::path::PathBuf::from("/tmp/failed-t4506.bin"),
                sidecar_sha256: hex::encode([0u8; 32]),
                legacy_ciphertext_b64: String::new(),
                wrapped_key_hex: hex::encode(b"wk"),
                iv_hex: hex::encode(b"iv"),
                file_meta_ipns_name: Some("k51filemeta45t06".to_string()),
                file_ipns_key_hex: None,
                parent_folder_ipns_name: vault.to_string(),
                parent_ipns_key_hex: hex::encode(b"ecies-parent-key"),
                filename_encrypted_hex: hex::encode("t4506.txt".as_bytes()),
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
            &[0u8; 32],
            &[0u8; 33],
            &[0u8; 32],
            vault,
            coordinator,
            None,
            None,
        )
        .await;

        // After replay, the Failed entry must still be present (not removed, not retried).
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

    // T-45-07: Two calls to `resolve_folder_key_cached` with the same folder_ipns_name
    // (the root IPNS, using the root-shortcut path so no network is needed) hit the cache
    // on the second call. Assertions:
    //   1. Both calls return identical key bytes.
    //   2. The cache contains exactly one entry for the queried name after both calls.
    //   3. The returned key equals root_folder_key (root-shortcut invariant preserved).
    //
    // The cache is pre-seeded with the root key (mirroring replay_for_vault), so the FIRST
    // call also hits the cache — zero BFS traversals for root lookups.
    // Extends the Plan-01 placeholder which only tested resolve_folder_key equality.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn resolve_folder_key_cache_resolves_shared_parent_once() {
        use std::sync::Arc;

        let root_folder_key = [0u8; 32];
        let root_ipns_name = "k51rootipns45t07";

        let api = Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));

        // Seed the cache exactly as replay_for_vault does (#15).
        let mut cache: std::collections::HashMap<String, Zeroizing<Vec<u8>>> =
            std::collections::HashMap::new();
        cache.insert(
            root_ipns_name.to_string(),
            Zeroizing::new(root_folder_key.to_vec()),
        );

        // First lookup: cache hit (seeded above) — no BFS, no network.
        let key1 = super::resolve_folder_key_cached(
            &mut cache,
            &api,
            &[0u8; 32], // private_key (unused on cache-hit path)
            &root_folder_key,
            root_ipns_name,
            root_ipns_name, // folder_ipns_name == root
        )
        .await
        .expect("first cached resolve must succeed");

        // Cache must hold exactly one entry after the first lookup.
        assert_eq!(
            cache.len(),
            1,
            "cache must have exactly one entry after first lookup (root key was pre-seeded)"
        );

        // Second lookup: another cache hit for the same name — no new entry.
        let key2 = super::resolve_folder_key_cached(
            &mut cache,
            &api,
            &[0u8; 32],
            &root_folder_key,
            root_ipns_name,
            root_ipns_name,
        )
        .await
        .expect("second cached resolve must succeed");

        // Cache still has exactly one entry — the second lookup did NOT insert a duplicate.
        assert_eq!(
            cache.len(),
            1,
            "cache must still have one entry after second lookup (same key — not duplicated)"
        );

        // Both calls returned identical bytes.
        assert_eq!(
            key1, key2,
            "two resolve_folder_key_cached calls with the same parent must return identical key bytes"
        );
        // The returned value is the root folder key (root-shortcut / cache-seeded invariant).
        assert_eq!(
            key1.as_slice(),
            root_folder_key.as_slice(),
            "cached resolve must return root_folder_key unchanged"
        );
    }

    // REQ-4: a legacy UploadFile journal entry with file_meta_ipns_name == None is parked
    // (retained), never published as an empty FilePointer. The early Err in
    // replay_upload_entry routes through record_failure, so after replay against an
    // unroutable API the entry count stays at 1. Mirrors
    // replay_for_vault_does_not_touch_failed_entries harness.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn legacy_empty_name_parks() {
        use cipherbox_sdk::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
        use std::sync::Arc;

        let dir = std::env::temp_dir()
            .join("cb-req4-legacy-empty-name-parks")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = WriteQueue::new(dir.clone(), 5);
        let vault = "k51vaultreq4";

        // Legacy entry: per-file IPNS name is None → must be parked, not published.
        let entry = JournalEntry {
            id: "legacy-none-name".to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                sidecar_path: std::path::PathBuf::from("/tmp/legacy-none-name.bin"),
                sidecar_sha256: hex::encode([0u8; 32]),
                legacy_ciphertext_b64: String::new(),
                wrapped_key_hex: hex::encode(b"wk"),
                iv_hex: hex::encode(b"iv"),
                file_meta_ipns_name: None,
                file_ipns_key_hex: None,
                parent_folder_ipns_name: vault.to_string(),
                parent_ipns_key_hex: hex::encode(b"ecies-parent-key"),
                filename_encrypted_hex: hex::encode("legacy.txt".as_bytes()),
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
            &[0u8; 32],
            &[0u8; 33],
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
            "legacy None-name entry must be retained (parked), not removed as replayed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // REQ-5: resolve_sequence_strict returns Err on ANY resolve failure, NEVER falling
    // back to the cache. Here the cache is seeded via record_publish(N) but the API is
    // unroutable, so strict resolve must err (unlike resolve_sequence which would return
    // Ok(cached)).
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn strict_resolve_bypasses_cache() {
        let api = cipherbox_api_client::ApiClient::new("http://127.0.0.1:1");
        let coordinator = super::PublishCoordinator::new();
        let ipns_name = "k51strictbypass";

        // Seed the cache: resolve_sequence would now return Ok(42) on failure.
        coordinator.record_publish(ipns_name, 42);

        let result = coordinator.resolve_sequence_strict(&api, ipns_name).await;
        assert!(
            result.is_err(),
            "strict resolve must err on resolve failure even with a populated cache (got {:?})",
            result
        );
    }

    // REQ-5: a transient (non-404) resolve failure during replay retains the entry rather
    // than advancing IPNS off a stale cached sequence. The IPNS name has a cached sequence
    // seeded, but because resolve_ipns_for_replay now uses the strict resolve, the failure
    // is classified as Error(_) → entry retained (len stays 1). Mirrors the replay-retain
    // harness.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn transient_failure_retains_entry() {
        use cipherbox_sdk::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
        use std::sync::Arc;

        let dir = std::env::temp_dir()
            .join("cb-req5-transient-failure-retains")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = WriteQueue::new(dir.clone(), 5);
        let vault = "k51vaultreq5";
        let file_meta = "k51filemetareq5";

        // Entry has a per-file IPNS name AND key, so replay reaches the resolve step.
        let entry = JournalEntry {
            id: "transient-retain".to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                sidecar_path: std::path::PathBuf::from("/tmp/transient-retain.bin"),
                sidecar_sha256: hex::encode([0u8; 32]),
                legacy_ciphertext_b64: String::new(),
                wrapped_key_hex: hex::encode(b"wk"),
                iv_hex: hex::encode(b"iv"),
                file_meta_ipns_name: Some(file_meta.to_string()),
                file_ipns_key_hex: Some(hex::encode(b"ecies-file-key")),
                parent_folder_ipns_name: vault.to_string(),
                parent_ipns_key_hex: hex::encode(b"ecies-parent-key"),
                filename_encrypted_hex: hex::encode("transient.txt".as_bytes()),
                size: 1,
                created_at_ms: 1_700_000_000_000,
            },
            retries: 0,
            status: JournalEntryStatus::Pending,
        };
        journal.put(&entry).unwrap();

        let api = Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
        let coordinator = Arc::new(super::PublishCoordinator::new());
        // Seed a cached sequence for the per-file IPNS name. With the OLD cache-fallback
        // resolve this would let replay advance off the cache; strict resolve must err.
        coordinator.record_publish(file_meta, 7);

        super::replay_for_vault(
            &journal,
            api,
            &[0u8; 32],
            &[0u8; 33],
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
            "transient resolve failure must retain the entry (strict resolve, no cache fallback)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // T-45-05: not_found_outcome_drives_first_publish
    //
    // Pins the #19 branch contract: given each IpnsResolveOutcome variant, the replay
    // sequencing decision must produce the correct (is_first_publish, new_seq) pair
    // without any network access. This test exercises the classification → sequence
    // computation directly, mirroring the branch logic inside replay_upload_entry.
    //
    // NotFound  -> is_first_publish=true,  new_seq=0  (next_file_publish_sequence(true, None))
    // Found(7)  -> is_first_publish=false, new_seq=8  (current_seq + 1)
    // Error(_)  -> Err propagated (entry retained, no sequence produced)
    #[test]
    fn not_found_outcome_drives_first_publish() {
        use super::super::next_file_publish_sequence;
        use crate::error::IpnsResolveOutcome;

        // NotFound -> first publish at seq 0
        let outcome_not_found = IpnsResolveOutcome::NotFound;
        let (is_first, new_seq) = match outcome_not_found {
            IpnsResolveOutcome::Found(seq) => {
                (false, next_file_publish_sequence(false, Some(seq)).unwrap())
            }
            IpnsResolveOutcome::NotFound => (true, next_file_publish_sequence(true, None).unwrap()),
            IpnsResolveOutcome::Error(e) => panic!("unexpected Error variant: {}", e),
        };
        assert!(is_first, "NotFound must set is_first_publish=true");
        assert_eq!(new_seq, 0, "NotFound must produce seq 0");

        // Found(7) -> update at seq 8
        let outcome_found = IpnsResolveOutcome::Found(7);
        let (is_first, new_seq) = match outcome_found {
            IpnsResolveOutcome::Found(seq) => {
                (false, next_file_publish_sequence(false, Some(seq)).unwrap())
            }
            IpnsResolveOutcome::NotFound => (true, next_file_publish_sequence(true, None).unwrap()),
            IpnsResolveOutcome::Error(e) => panic!("unexpected Error variant: {}", e),
        };
        assert!(!is_first, "Found must set is_first_publish=false");
        assert_eq!(new_seq, 8, "Found(7) must produce seq 8");

        // Error(_) -> propagated as Err (entry retained)
        let outcome_err = IpnsResolveOutcome::Error("transient failure".to_string());
        let result: Result<(bool, u64), String> = match outcome_err {
            IpnsResolveOutcome::Found(seq) => {
                Ok((false, next_file_publish_sequence(false, Some(seq)).unwrap()))
            }
            IpnsResolveOutcome::NotFound => {
                Ok((true, next_file_publish_sequence(true, None).unwrap()))
            }
            IpnsResolveOutcome::Error(e) => Err(format!(
                "resolve file IPNS sequence: {} — retaining entry",
                e
            )),
        };
        assert!(
            result.is_err(),
            "Error variant must propagate as Err (entry retained)"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("retaining entry"),
            "error message must mention retaining entry"
        );
    }

    // F2: replay_for_vault must record each failed replay so retries accumulate across
    // mounts and the entry parks as Failed at max_retries (D-09). Before the fix the
    // failure arm only logged "will retry on next mount", so retries never advanced and
    // the WriteParked notification was unreachable. An UploadFile entry with an empty
    // parent_ipns_key_hex makes replay_upload_entry return Err immediately (no network),
    // so this exercises the failure path deterministically.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn replay_records_failure_and_parks_at_max_retries() {
        use cipherbox_sdk::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
        use std::sync::Arc;

        let dir = std::env::temp_dir()
            .join("cb-f2-replay-park-test")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = WriteQueue::new(dir.clone(), 5);
        let vault = "k51vaultf2park";

        let entry = JournalEntry {
            id: "f2entry".to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                sidecar_path: std::path::PathBuf::from("/tmp/f2entry.bin"),
                sidecar_sha256: hex::encode([0u8; 32]),
                legacy_ciphertext_b64: String::new(),
                wrapped_key_hex: hex::encode(b"wk"),
                iv_hex: hex::encode(b"iv"),
                file_meta_ipns_name: Some("k51filemeta".to_string()),
                file_ipns_key_hex: None,
                parent_folder_ipns_name: vault.to_string(),
                parent_ipns_key_hex: String::new(), // empty -> immediate Err in replay
                filename_encrypted_hex: hex::encode("f2.txt".as_bytes()),
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
            &[0u8; 32],
            &[0u8; 33],
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
            .find(|e| e.id == "f2entry")
            .expect("entry retained after failure");
        assert_eq!(
            e1.retries, 5,
            "retries must increment on a failed replay (F2)"
        );
        assert!(
            matches!(e1.status, JournalEntryStatus::Pending),
            "still Pending below max"
        );

        // Second replay: retries already at max -> parks as Failed (kept on disk, D-09).
        super::replay_for_vault(
            &journal,
            api,
            &[0u8; 32],
            &[0u8; 33],
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
            .find(|e| e.id == "f2entry")
            .expect("parked entry kept on disk");
        assert!(
            matches!(e2.status, JournalEntryStatus::Failed { .. }),
            "entry must park as Failed at max_retries so WriteParked becomes reachable (F2)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
