//! Metadata encryption, merge, and background publish helpers.

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::sync::Arc;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use zeroize::Zeroizing;

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use cipherbox_api_client::ApiClient;

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::publish::PublishCoordinator;

/// Encrypt a FolderMetadata struct and package as JSON bytes ready for IPFS upload.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn encrypt_metadata_to_json(
    metadata: &cipherbox_core::folder::FolderMetadata,
    folder_key: &[u8],
) -> Result<Vec<u8>, String> {
    let folder_key_arr: [u8; 32] = folder_key
        .try_into()
        .map_err(|_| "Invalid folder key length".to_string())?;
    let sealed = cipherbox_core::folder::encrypt_folder_metadata(metadata, &folder_key_arr)
        .map_err(|e| format!("Metadata encryption failed: {}", e))?;
    let iv_hex = hex::encode(&sealed[..12]);
    use base64::Engine;
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
    let json = serde_json::json!({ "iv": iv_hex, "data": data_base64 });
    serde_json::to_vec(&json).map_err(|e| format!("JSON serialization failed: {}", e))
}

/// Merge local children onto remote children to resolve a concurrent-edit conflict.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn merge_folder_children(
    local: &cipherbox_core::folder::FolderMetadata,
    remote: cipherbox_core::folder::FolderMetadata,
) -> cipherbox_core::folder::FolderMetadata {
    use cipherbox_core::folder::FolderChild;

    fn child_ipns_key(child: &FolderChild) -> &str {
        match child {
            FolderChild::Folder(f) => f.ipns_name.as_str(),
            FolderChild::File(f) => f.file_meta_ipns_name.as_str(),
        }
    }

    let local_by_ipns: std::collections::HashMap<String, &FolderChild> = local
        .children
        .iter()
        .map(|c| (child_ipns_key(c).to_string(), c))
        .collect();

    let mut merged: Vec<FolderChild> = Vec::new();
    let mut seen_ipns: std::collections::HashSet<String> = std::collections::HashSet::new();

    for remote_child in &remote.children {
        let ipns = child_ipns_key(remote_child).to_string();
        if let Some(local_child) = local_by_ipns.get(&ipns) {
            merged.push((*local_child).clone());
        } else {
            merged.push(remote_child.clone());
        }
        seen_ipns.insert(ipns);
    }

    for local_child in &local.children {
        let ipns = child_ipns_key(local_child).to_string();
        if !seen_ipns.contains(&ipns) {
            merged.push(local_child.clone());
        }
    }

    cipherbox_core::folder::FolderMetadata {
        version: "v2".to_string(),
        children: merged,
    }
}

/// Spawn a background OS thread to upload encrypted metadata and publish via IPNS.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn spawn_metadata_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    metadata: cipherbox_core::folder::FolderMetadata,
    folder_key: Vec<u8>,
    ipns_private_key: Vec<u8>,
    ipns_name: String,
    old_metadata_cid: Option<String>,
    coordinator: Arc<PublishCoordinator>,
) {
    std::thread::spawn(move || {
        let result = rt.block_on(async {
            let lock = coordinator.get_lock(&ipns_name);
            let _guard = lock.lock().await;

            let json_bytes = encrypt_metadata_to_json(&metadata, &folder_key)?;
            let seq = coordinator.resolve_sequence(&api, &ipns_name).await?;
            let new_cid = cipherbox_api_client::ipfs::upload_content(&api, &json_bytes)
                .await
                .map_err(|e| format!("{}", e))?;

            let ipns_key_arr: [u8; 32] = ipns_private_key
                .try_into()
                .map_err(|_| "Invalid IPNS private key length".to_string())?;
            let new_seq = seq + 1;
            let value = format!("/ipfs/{}", new_cid);
            let record =
                cipherbox_core::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)
                    .map_err(|e| format!("IPNS record creation failed: {}", e))?;
            let marshaled = cipherbox_core::marshal_ipns_record(&record)
                .map_err(|e| format!("IPNS record marshal failed: {}", e))?;

            use base64::Engine;
            let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

            let req = cipherbox_api_client::IpnsPublishRequest {
                ipns_name: ipns_name.clone(),
                record: record_b64,
                metadata_cid: new_cid.clone(),
                encrypted_ipns_private_key: None,
                key_epoch: None,
                expected_sequence_number: Some(seq.to_string()),
            };

            match cipherbox_api_client::ipns::publish_ipns(&api, &req)
                .await
                .map_err(|e| format!("{}", e))?
            {
                cipherbox_api_client::PublishResult::Success => {
                    coordinator.record_publish(&ipns_name, new_seq);
                    if let Some(old) = old_metadata_cid {
                        let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                    }
                    log::info!("Background metadata publish succeeded for {}", ipns_name);
                }
                cipherbox_api_client::PublishResult::Conflict {
                    current_sequence_number,
                } => {
                    log::warn!(
                        "Conflict for {}: expected seq {}, server has {}",
                        ipns_name,
                        seq,
                        current_sequence_number
                    );

                    let fresh_seq = coordinator.resolve_sequence(&api, &ipns_name).await?;
                    let remote_resolve = cipherbox_api_client::ipns::resolve_ipns(&api, &ipns_name)
                        .await
                        .map_err(|e| format!("{}", e))?;
                    let remote_bytes =
                        cipherbox_api_client::ipfs::fetch_content(&api, &remote_resolve.cid)
                            .await
                            .map_err(|e| format!("{}", e))?;
                    let remote_metadata = cipherbox_core::decrypt_metadata_from_ipfs_public(
                        &remote_bytes,
                        &folder_key,
                    )?;

                    let merged_metadata = merge_folder_children(&metadata, remote_metadata);

                    let jitter_ms = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos()
                        % 400) as u64
                        + 100;
                    tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;

                    let retry_json = encrypt_metadata_to_json(&merged_metadata, &folder_key)?;
                    let retry_cid = cipherbox_api_client::ipfs::upload_content(&api, &retry_json)
                        .await
                        .map_err(|e| format!("{}", e))?;

                    let retry_seq = fresh_seq + 1;
                    let retry_value = format!("/ipfs/{}", retry_cid);
                    let retry_record = cipherbox_core::create_ipns_record(
                        &ipns_key_arr,
                        &retry_value,
                        retry_seq,
                        86_400_000,
                    )
                    .map_err(|e| format!("IPNS retry record failed: {}", e))?;
                    let retry_marshaled = cipherbox_core::marshal_ipns_record(&retry_record)
                        .map_err(|e| format!("IPNS retry marshal failed: {}", e))?;
                    let retry_b64 =
                        base64::engine::general_purpose::STANDARD.encode(&retry_marshaled);

                    let retry_cid_for_cleanup = retry_cid.clone();
                    let retry_req = cipherbox_api_client::IpnsPublishRequest {
                        ipns_name: ipns_name.clone(),
                        record: retry_b64,
                        metadata_cid: retry_cid,
                        encrypted_ipns_private_key: None,
                        key_epoch: None,
                        expected_sequence_number: Some(fresh_seq.to_string()),
                    };

                    match cipherbox_api_client::ipns::publish_ipns(&api, &retry_req)
                        .await
                        .map_err(|e| format!("{}", e))?
                    {
                        cipherbox_api_client::PublishResult::Success => {
                            coordinator.record_publish(&ipns_name, retry_seq);
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &new_cid).await;
                            if let Some(old) = old_metadata_cid {
                                let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                            }
                            log::info!(
                                "Conflict resolved for {} after retry (seq {})",
                                ipns_name,
                                retry_seq
                            );
                        }
                        cipherbox_api_client::PublishResult::Conflict { .. } => {
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &new_cid).await;
                            let _ = cipherbox_api_client::ipfs::unpin_content(
                                &api,
                                &retry_cid_for_cleanup,
                            )
                            .await;
                            return Err(format!("Persistent conflict for {}", ipns_name));
                        }
                    }
                }
            }
            Ok::<(), String>(())
        });
        if let Err(e) = result {
            log::error!("Background metadata publish failed: {}", e);
        }
    });
}

/// Add a BinEntry to the user's encrypted recycle bin IPNS record.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn spawn_bin_entry_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    entry: cipherbox_core::bin::BinEntry,
    user_private_key: Zeroizing<Vec<u8>>,
    user_public_key: Vec<u8>,
    coordinator: Arc<PublishCoordinator>,
) {
    std::thread::spawn(move || {
        let result = rt.block_on(async {
            let pk_arr: [u8; 32] = user_private_key
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid private key length for bin derivation".to_string())?;
            let (bin_ipns_private_key, _bin_ipns_public_key, bin_ipns_name) =
                cipherbox_crypto::derive_bin_ipns_keypair(&pk_arr)
                    .map_err(|e| format!("Bin IPNS derivation failed: {}", e))?;

            let lock = coordinator.get_lock(&bin_ipns_name);
            let _guard = lock.lock().await;

            let (mut bin_metadata, existing_cid) =
                match cipherbox_api_client::ipns::resolve_ipns(&api, &bin_ipns_name).await {
                    Ok(resp) => {
                        match cipherbox_api_client::ipfs::fetch_content(&api, &resp.cid).await {
                            Ok(bytes) => {
                                match cipherbox_core::decrypt_bin_metadata(
                                    &bytes,
                                    &user_private_key,
                                ) {
                                    Ok(meta) => (meta, Some(resp.cid)),
                                    Err(e) => {
                                        log::warn!("Failed to decrypt bin metadata: {}", e);
                                        return Err(format!("Bin decrypt failed: {}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("Failed to fetch bin metadata blob: {}", e);
                                return Err(format!("Bin fetch failed: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        let e_str = format!("{}", e);
                        if e_str.to_lowercase().contains("not found") {
                            (cipherbox_core::empty_bin_metadata(), None)
                        } else {
                            log::warn!("Failed to resolve bin IPNS: {}", e);
                            return Err(format!("Bin resolve failed: {}", e));
                        }
                    }
                };

            bin_metadata.sequence_number += 1;
            bin_metadata.entries.push(entry);

            let encrypted = cipherbox_core::encrypt_bin_metadata(&bin_metadata, &user_public_key)
                .map_err(|e| format!("Bin metadata encryption failed: {}", e))?;

            let new_cid = cipherbox_api_client::ipfs::upload_content(&api, &encrypted)
                .await
                .map_err(|e| format!("{}", e))?;

            let seq = coordinator
                .resolve_sequence(&api, &bin_ipns_name)
                .await
                .unwrap_or(0);
            let new_seq = seq + 1;

            let bin_ipns_key_arr: [u8; 32] = bin_ipns_private_key
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid bin IPNS key length".to_string())?;
            let value = format!("/ipfs/{}", new_cid);
            let record =
                cipherbox_core::create_ipns_record(&bin_ipns_key_arr, &value, new_seq, 86_400_000)
                    .map_err(|e| format!("Bin IPNS record creation failed: {}", e))?;
            let marshaled = cipherbox_core::marshal_ipns_record(&record)
                .map_err(|e| format!("Bin IPNS marshal failed: {}", e))?;

            use base64::Engine;
            let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

            let req = cipherbox_api_client::IpnsPublishRequest {
                ipns_name: bin_ipns_name.clone(),
                record: record_b64,
                metadata_cid: new_cid,
                encrypted_ipns_private_key: None,
                key_epoch: None,
                expected_sequence_number: Some(seq.to_string()),
            };

            match cipherbox_api_client::ipns::publish_ipns(&api, &req)
                .await
                .map_err(|e| format!("{}", e))?
            {
                cipherbox_api_client::PublishResult::Success => {
                    coordinator.record_publish(&bin_ipns_name, new_seq);
                    if let Some(old) = existing_cid {
                        let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                    }
                    log::info!("Bin entry published");
                }
                cipherbox_api_client::PublishResult::Conflict {
                    current_sequence_number,
                } => {
                    log::warn!(
                        "Bin IPNS publish conflict (expected {}, server {})",
                        seq,
                        current_sequence_number
                    );
                }
            }

            Ok::<(), String>(())
        });
        if let Err(e) = result {
            log::error!("Background bin entry publish failed: {}", e);
        }
    });
}

/// Bounded retry budget for the fire-and-forget re-encrypt on cross-folder move.
/// Mirrors the durable journal's bounded-retry-then-park bound (D-09).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
const REENCRYPT_MAX_ATTEMPTS: u32 = 5;

/// Outcome of a single re-encrypt attempt, used to decide whether to retry.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
enum ReencryptOutcome {
    /// Re-keyed to the destination on this attempt.
    Done,
    /// A prior attempt already re-keyed the record; nothing left to do.
    AlreadyDone,
    /// Transient failure (resolve/fetch/publish) — worth retrying.
    Retry(String),
    /// Deterministic failure (undecryptable under BOTH keys) — retrying can't help.
    Terminal(String),
}

/// Resolve a file's IPNS record and fetch its current encrypted metadata bytes.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
async fn resolve_and_fetch_file_meta(
    api: &ApiClient,
    file_meta_ipns_name: &str,
) -> Result<Vec<u8>, String> {
    let resp = cipherbox_api_client::ipns::resolve_ipns(api, file_meta_ipns_name)
        .await
        .map_err(|e| format!("resolve file IPNS: {}", e))?;
    let enc_bytes = cipherbox_api_client::ipfs::fetch_content(api, &resp.cid)
        .await
        .map_err(|e| format!("fetch file metadata: {}", e))?;
    Ok(enc_bytes)
}

/// Re-encrypt a file's `FileMetadata` IPNS record from `source_folder_key` to
/// `dest_folder_key` after a cross-folder move (fire-and-forget).
///
/// A file's `FileMetadata` is sealed with its PARENT folder's AES key. The rename
/// handlers only republish the old/new *folder* metadata; the per-file record
/// stays sealed under the source key. Without this, any fresh resolve under the
/// destination folder's key — a remount, another device, or the web client —
/// fails with a decryption error. This resolves the current record under the
/// source key and republishes the SAME metadata sealed under the destination key
/// (no version bump). Mirrors the SDK `moveItem` re-encrypt step.
///
/// Bounded in-memory retry: a transient resolve/fetch/publish failure is retried
/// with exponential backoff up to `REENCRYPT_MAX_ATTEMPTS`. Idempotent — if a
/// prior attempt already re-keyed the record (it decrypts under the destination
/// but not the source key), the work is treated as complete. A record that
/// decrypts under NEITHER key is a terminal failure and is not retried.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
pub fn spawn_file_meta_reencrypt(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    file_meta_ipns_name: String,
    file_ipns_private_key: Zeroizing<Vec<u8>>,
    source_folder_key: Zeroizing<Vec<u8>>,
    dest_folder_key: Zeroizing<Vec<u8>>,
    coordinator: Arc<PublishCoordinator>,
    tee_public_key: Option<Vec<u8>>,
    tee_key_epoch: Option<u32>,
) {
    // Distinct folders always carry distinct keys; this guard is purely defensive
    // and skips a needless resolve+publish (and sequence bump) if they ever match.
    if source_folder_key == dest_folder_key {
        return;
    }
    std::thread::spawn(move || {
        // Fixed-size keys; a bad length is a terminal misconfiguration, not retryable.
        // Wrap the copies in `Zeroizing` so the fixed-size key bytes are wiped on drop.
        let source_key_arr: Zeroizing<[u8; 32]> =
            match source_folder_key.as_slice().try_into() {
                Ok(arr) => Zeroizing::new(arr),
                Err(_) => {
                    log::error!(
                        "File metadata re-encrypt on move failed: invalid source folder key length"
                    );
                    return;
                }
            };
        let dest_key_arr: Zeroizing<[u8; 32]> = match dest_folder_key.as_slice().try_into() {
            Ok(arr) => Zeroizing::new(arr),
            Err(_) => {
                log::error!(
                    "File metadata re-encrypt on move failed: invalid destination folder key length"
                );
                return;
            }
        };

        let result: Result<(), String> = rt.block_on(async {
            let mut last_error = String::new();
            for attempt in 1..=REENCRYPT_MAX_ATTEMPTS {
                // Serialize against concurrent publishes to the same file IPNS record.
                // Re-acquired each attempt so backoff sleeps never hold the lock.
                let outcome = {
                    let lock = coordinator.get_lock(&file_meta_ipns_name);
                    let _guard = lock.lock().await;

                    match resolve_and_fetch_file_meta(&api, &file_meta_ipns_name).await {
                        Err(e) => ReencryptOutcome::Retry(e),
                        Ok(enc_bytes) => {
                            // Decrypt the CURRENT record under the SOURCE folder key.
                            match cipherbox_core::decrypt_file_metadata_from_ipfs_public(
                                &enc_bytes,
                                &source_key_arr,
                            ) {
                                Ok(file_meta) => {
                                    // Republish the SAME metadata sealed under the
                                    // DESTINATION key. The record already exists, so this
                                    // is an update (seq + 1), no TEE enroll.
                                    match publish_file_metadata(
                                        &api,
                                        &file_meta,
                                        &dest_folder_key,
                                        &file_ipns_private_key,
                                        &file_meta_ipns_name,
                                        coordinator.as_ref(),
                                        tee_public_key.as_deref(),
                                        tee_key_epoch,
                                        false,
                                    )
                                    .await
                                    {
                                        Ok(()) => ReencryptOutcome::Done,
                                        Err(e) => ReencryptOutcome::Retry(format!(
                                            "re-publish file metadata under dest key: {}",
                                            e
                                        )),
                                    }
                                }
                                Err(source_err) => {
                                    // Source-key decrypt failed. A prior attempt may have
                                    // already re-keyed the record to the destination —
                                    // confirm under the dest key (idempotent). If THAT also
                                    // fails the record is genuinely undecryptable: terminal,
                                    // retrying can't recover it.
                                    if cipherbox_core::decrypt_file_metadata_from_ipfs_public(
                                        &enc_bytes,
                                        &dest_key_arr,
                                    )
                                    .is_ok()
                                    {
                                        ReencryptOutcome::AlreadyDone
                                    } else {
                                        ReencryptOutcome::Terminal(format!(
                                            "decrypt file metadata under source key: {}",
                                            source_err
                                        ))
                                    }
                                }
                            }
                        }
                    }
                }; // lock released here, before any backoff sleep

                match outcome {
                    ReencryptOutcome::Done => {
                        log::info!(
                            "Re-encrypted file metadata for {} after cross-folder move",
                            file_meta_ipns_name
                        );
                        return Ok(());
                    }
                    ReencryptOutcome::AlreadyDone => {
                        log::info!(
                            "File metadata for {} already re-encrypted to destination key",
                            file_meta_ipns_name
                        );
                        return Ok(());
                    }
                    ReencryptOutcome::Terminal(e) => return Err(e),
                    ReencryptOutcome::Retry(e) => {
                        last_error = e;
                        if attempt < REENCRYPT_MAX_ATTEMPTS {
                            // Exponential backoff (0.5s, 1s, 2s, 4s) + jitter, matching the
                            // publish-conflict backoff idiom elsewhere in this file.
                            let base_ms = 500u64 << (attempt - 1);
                            let jitter_ms = (std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .subsec_nanos()
                                % 400) as u64;
                            tokio::time::sleep(std::time::Duration::from_millis(
                                base_ms + jitter_ms,
                            ))
                            .await;
                        }
                    }
                }
            }
            Err(format!(
                "exhausted {} attempts: {}",
                REENCRYPT_MAX_ATTEMPTS, last_error
            ))
        });
        if let Err(e) = result {
            log::error!("File metadata re-encrypt on move failed: {}", e);
        }
    });
}

/// Platform-unified `publish_file_metadata` used by `spawn_file_meta_reencrypt`.
///
/// Under the `fuse` feature, delegates to `crate::operations::implementation`.
/// Under the `winfsp` feature (without `fuse`), delegates to
/// `crate::platform::windows::operations::implementation`.
#[cfg(feature = "fuse")]
use crate::operations::implementation::publish_file_metadata;
#[cfg(all(feature = "winfsp", not(feature = "fuse")))]
use crate::platform::windows::operations::implementation::publish_file_metadata;

#[cfg(test)]
mod tests {
    // T-45-08: merge_folder_children with one new child and one existing child (shared
    // file_meta_ipns_name) yields a merged result with both children, and the LOCAL
    // version of the existing child wins. Characterizes the merge semantics that
    // fetch_merge_publish_parent relies on during replay.
    #[test]
    fn merge_folder_children_unions_new_and_existing() {
        use cipherbox_core::folder::{FilePointer, FolderChild, FolderMetadata};

        // Shared IPNS name — identifies the "existing" file on both local and remote.
        let existing_ipns = "k51existing45t08";

        let local_existing = FolderChild::File(FilePointer {
            id: "local-existing-id".to_string(),
            name: "existing_local.txt".to_string(), // local version name — must win
            file_meta_ipns_name: existing_ipns.to_string(),
            ipns_private_key_encrypted: None,
            created_at: 1000,
            modified_at: 2000,
        });
        let local_new = FolderChild::File(FilePointer {
            id: "local-new-id".to_string(),
            name: "new_file.txt".to_string(), // only on local side
            file_meta_ipns_name: "k51new45t08".to_string(),
            ipns_private_key_encrypted: None,
            created_at: 1001,
            modified_at: 2001,
        });
        let remote_existing = FolderChild::File(FilePointer {
            id: "remote-existing-id".to_string(),
            name: "existing_remote.txt".to_string(), // remote version — must lose
            file_meta_ipns_name: existing_ipns.to_string(),
            ipns_private_key_encrypted: None,
            created_at: 999,
            modified_at: 1999,
        });

        let local_meta = FolderMetadata {
            version: "v2".to_string(),
            children: vec![local_existing, local_new],
        };
        let remote_meta = FolderMetadata {
            version: "v2".to_string(),
            children: vec![remote_existing],
        };

        let merged = super::merge_folder_children(&local_meta, remote_meta);

        // Union: both the existing child and the new child must be present.
        assert_eq!(
            merged.children.len(),
            2,
            "merged result must contain both children"
        );

        // Local version wins for the existing child.
        let merged_existing = merged.children.iter().find(|c| {
            if let FolderChild::File(f) = c {
                f.file_meta_ipns_name == existing_ipns
            } else {
                false
            }
        });
        let merged_existing = merged_existing.expect("existing child must be in merged result");
        if let FolderChild::File(f) = merged_existing {
            assert_eq!(
                f.name, "existing_local.txt",
                "local version must win for existing child (same IPNS key)"
            );
        }

        // New child must also be present.
        let has_new = merged.children.iter().any(|c| {
            if let FolderChild::File(f) = c {
                f.file_meta_ipns_name == "k51new45t08"
            } else {
                false
            }
        });
        assert!(
            has_new,
            "new child (local-only) must be included in merged result"
        );
    }

    // REQ-4 motivation: two distinct FilePointers that both carry an EMPTY
    // file_meta_ipns_name collapse to a single entry under merge_folder_children
    // (they key on the empty string ""). This pins WHY legacy None-name replay
    // entries must be parked rather than published as empty FilePointers — an
    // empty locator is not a unique key and silently clobbers siblings. Pure, no network.
    #[test]
    fn empty_name_merge_collision() {
        use cipherbox_core::folder::{FilePointer, FolderChild, FolderMetadata};

        let empty_a = FolderChild::File(FilePointer {
            id: "replay-".to_string(),
            name: "file_a.txt".to_string(),
            file_meta_ipns_name: String::new(), // empty locator
            ipns_private_key_encrypted: None,
            created_at: 1000,
            modified_at: 2000,
        });
        let empty_b = FolderChild::File(FilePointer {
            id: "replay-".to_string(),
            name: "file_b.txt".to_string(), // distinct name/timestamps...
            file_meta_ipns_name: String::new(), // ...but the SAME empty locator
            ipns_private_key_encrypted: None,
            created_at: 1001,
            modified_at: 2001,
        });

        // One empty-name pointer is local, the other remote. They are distinct files but
        // share the "" locator key, so merge cannot keep both: the remote loop looks up
        // local_by_ipns[""], finds the local version, pushes it, and marks "" seen; the
        // local loop then skips it. Two distinct empty-name files collapse to one.
        let local_meta = FolderMetadata {
            version: "v2".to_string(),
            children: vec![empty_a],
        };
        let remote_meta = FolderMetadata {
            version: "v2".to_string(),
            children: vec![empty_b],
        };

        let merged = super::merge_folder_children(&local_meta, remote_meta);

        assert_eq!(
            merged.children.len(),
            1,
            "two distinct empty-name FilePointers collapse to one (they collide on the \"\" key)"
        );
    }
}
