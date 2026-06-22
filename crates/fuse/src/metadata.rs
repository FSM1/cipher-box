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

/// Shared one-retry CAS publish helper (D-03).
///
/// Resolves the current IPNS sequence, calls `make_record(new_seq)` to produce
/// `(record_b64, metadata_cid)`, publishes with `expected_sequence_number:
/// Some(seq.to_string())`, and on `Conflict` re-resolves + retries once with a
/// jitter back-off.
///
/// On persistent `Conflict`:
/// - If `journal_entry: Some((queue, entry))` — enqueue via `WriteQueue::put` and
///   return `Ok(())` (durable ack). **No call site supplies `Some` this phase** — see
///   D-01a: there is no `JournalOp::FilePublish`/`BinPublish` variant in
///   `crates/sdk/src/queue.rs`, so journaling per-file/bin publishes is a deferred
///   cross-crate change (CONTEXT Deferred Ideas).
/// - If `journal_entry: None` — return `Err` (the fire-and-forget caller logs at
///   `log::error!` and the blocking/sync path returns `EIO`).
///
/// Hard failures (record creation, marshal, upload, resolve) propagate `Err`
/// immediately — no retry.
///
/// The `old_cids_to_unpin` parameter carries CIDs to unpin only on success; on the
/// retry path additional intermediate CIDs are also cleaned up. Pass `vec![]` when
/// there is nothing to unpin.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) async fn publish_with_cas_retry<F>(
    api: &ApiClient,
    coordinator: &PublishCoordinator,
    ipns_name: &str,
    make_record: F,
    old_cids_to_unpin: &[String],
    journal_entry: Option<()>, // placeholder for future (queue, entry) — always None this phase
) -> Result<(), String>
where
    F: Fn(u64) -> Result<(String, String), String>, // make_record(new_seq) -> (record_b64, cid)
{
    let seq = coordinator.resolve_sequence(api, ipns_name).await?;
    let new_seq = seq
        .checked_add(1)
        .ok_or_else(|| "IPNS sequence number overflow".to_string())?;

    let (record_b64, metadata_cid) = make_record(new_seq)?;

    let req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: ipns_name.to_string(),
        record: record_b64,
        metadata_cid: metadata_cid.clone(),
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: Some(seq.to_string()),
    };

    match cipherbox_api_client::ipns::publish_ipns(api, &req)
        .await
        .map_err(|e| format!("{}", e))?
    {
        cipherbox_api_client::PublishResult::Success => {
            coordinator.record_publish(ipns_name, new_seq);
            for cid in old_cids_to_unpin {
                let _ = cipherbox_api_client::ipfs::unpin_content(api, cid).await;
            }
            return Ok(());
        }
        cipherbox_api_client::PublishResult::Conflict {
            current_sequence_number,
        } => {
            log::warn!(
                "Conflict for {}: expected seq {}, server has {}. Re-resolving for retry.",
                ipns_name,
                seq,
                current_sequence_number
            );

            let jitter_ms = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
                % 400) as u64
                + 100;
            tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;

            let fresh_seq = coordinator.resolve_sequence(api, ipns_name).await?;
            let retry_seq = fresh_seq
                .checked_add(1)
                .ok_or_else(|| "IPNS sequence number overflow on retry".to_string())?;

            let (retry_b64, retry_cid) = make_record(retry_seq)?;

            let retry_req = cipherbox_api_client::IpnsPublishRequest {
                ipns_name: ipns_name.to_string(),
                record: retry_b64,
                metadata_cid: retry_cid.clone(),
                encrypted_ipns_private_key: None,
                key_epoch: None,
                expected_sequence_number: Some(fresh_seq.to_string()),
            };

            match cipherbox_api_client::ipns::publish_ipns(api, &retry_req)
                .await
                .map_err(|e| format!("{}", e))?
            {
                cipherbox_api_client::PublishResult::Success => {
                    coordinator.record_publish(ipns_name, retry_seq);
                    // Unpin the initial (now-superseded) CID and the old ones
                    let _ = cipherbox_api_client::ipfs::unpin_content(api, &metadata_cid).await;
                    for cid in old_cids_to_unpin {
                        let _ = cipherbox_api_client::ipfs::unpin_content(api, cid).await;
                    }
                    log::info!(
                        "Conflict resolved for {} after retry (seq {})",
                        ipns_name,
                        retry_seq
                    );
                    Ok(())
                }
                cipherbox_api_client::PublishResult::Conflict { .. } => {
                    // Clean up both intermediate CIDs
                    let _ = cipherbox_api_client::ipfs::unpin_content(api, &metadata_cid).await;
                    let _ = cipherbox_api_client::ipfs::unpin_content(api, &retry_cid).await;

                    if journal_entry.is_some() {
                        // D-01a: future path — journal enqueue (no call site supplies Some this phase)
                        // queue.put(&entry).map_err(|e| format!("journal enqueue failed: {}", e))?;
                        // return Ok(());
                        // For now return Err (journal_entry is always None this phase)
                        Err(format!("persistent conflict for {}", ipns_name))
                    } else {
                        // D-01a: per-file/bin path — no JournalOp::FilePublish/BinPublish variant;
                        // journaling deferred (CONTEXT Deferred Ideas). On exhaustion: Err → EIO.
                        Err(format!("persistent conflict for {}", ipns_name))
                    }
                }
            }
        }
    }
}

/// Classify an IPNS resolve error string as "record does not exist yet" (so the caller
/// can treat it as an empty/first-publish case) vs a genuine failure to surface.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn is_ipns_not_found(error_message: &str) -> bool {
    error_message.to_lowercase().contains("not found")
}

/// Spawn a background OS thread to upload encrypted metadata and publish via IPNS.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn spawn_metadata_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    metadata: cipherbox_core::folder::FolderMetadata,
    folder_key: Zeroizing<Vec<u8>>, // D-12: Zeroizing to match spawn_bin_entry_publish pattern
    ipns_private_key: Zeroizing<Vec<u8>>, // D-12: Zeroizing to match spawn_bin_entry_publish pattern
    ipns_name: String,
    old_metadata_cid: Option<String>,
    coordinator: Arc<PublishCoordinator>,
) {
    std::thread::spawn(move || {
        let result = rt.block_on(async {
            let lock = coordinator.get_lock(&ipns_name);
            let _guard = lock.lock().await;

            // Pre-validate IPNS key length so make_record can use it without fallible conversion.
            // Using a Zeroizing wrapper so the fixed-size bytes are zeroed on drop.
            let ipns_key_arr: Zeroizing<[u8; 32]> = {
                let arr: [u8; 32] = ipns_private_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid IPNS private key length".to_string())?;
                Zeroizing::new(arr)
            };

            // Pre-upload: build the initial encrypted metadata blob before entering the
            // CAS loop so make_record only re-encrypts on the conflict retry path.
            let json_bytes = encrypt_metadata_to_json(&metadata, &folder_key)?;
            let initial_cid = cipherbox_api_client::ipfs::upload_content(&api, &json_bytes)
                .await
                .map_err(|e| format!("{}", e))?;

            // old_cids_to_unpin: the previous metadata CID (if any) — unpinned on success.
            let old_cids: Vec<String> = old_metadata_cid.into_iter().collect();

            // make_record: builds the signed IPNS record for the initial (non-conflict)
            // publish, reusing the pre-uploaded blob CID. It is sync, so it cannot perform
            // the async merge-on-conflict the folder path needs — hence the folder site does
            // NOT route through publish_with_cas_retry; it runs its own inline CAS loop below
            // (D-03). Cloned because the closure captures the CID by value.
            let initial_cid_for_closure = initial_cid.clone();
            let make_record = |new_seq: u64| -> Result<(String, String), String> {
                use base64::Engine;
                let value = format!("/ipfs/{}", initial_cid_for_closure);
                let record = cipherbox_core::create_ipns_record(
                    &ipns_key_arr,
                    &value,
                    new_seq,
                    86_400_000,
                )
                .map_err(|e| format!("IPNS record creation failed: {}", e))?;
                let marshaled = cipherbox_core::marshal_ipns_record(&record)
                    .map_err(|e| format!("IPNS record marshal failed: {}", e))?;
                let record_b64 =
                    base64::engine::general_purpose::STANDARD.encode(&marshaled);
                Ok((record_b64, initial_cid_for_closure.clone()))
            };

            // Folder CAS loop: own retry path (NOT publish_with_cas_retry) because the
            // conflict arm must async-fetch + merge_folder_children + re-encrypt remote
            // metadata before retrying, which the sync make_record closure can't express.
            // publish_with_cas_retry covers the per-file/bin sites; this loop is the
            // reference implementation it was extracted from and shares the same decision
            // policy (D-03). On persistent conflict it returns Err (D-01a: no
            // JournalOp variant for standalone folder re-publish; surfaced as Err).

            // --- Folder CAS loop ---
            let seq = coordinator.resolve_sequence(&api, &ipns_name).await?;
            let new_seq = seq
                .checked_add(1)
                .ok_or_else(|| "IPNS sequence number overflow".to_string())?;

            // Build record using the initial CID
            let (record_b64, new_cid) = make_record(new_seq)?;

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
                    for cid in &old_cids {
                        let _ = cipherbox_api_client::ipfs::unpin_content(&api, cid).await;
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
                    // D-01/D-02: route through verified chokepoint; fail only this merge operation.
                    let remote_cid = match crate::verify::resolve_ipns_verified(&api, &ipns_name).await {
                        Ok(v) => v.cid,
                        Err(crate::verify::VerifyError::Legacy) => {
                            log::warn!(
                                "remote_merge: IPNS {} resolved without signature fields \
                                 — using DB CID for merge (D-04)",
                                ipns_name
                            );
                            cipherbox_api_client::ipns::resolve_ipns(&api, &ipns_name)
                                .await
                                .map_err(|e| format!("{}", e))?.cid
                        }
                        Err(crate::verify::VerifyError::Invalid(msg)) => {
                            return Err(format!("IPNS {} verify failed on merge: {}", ipns_name, msg));
                        }
                        Err(crate::verify::VerifyError::Api(e)) => {
                            return Err(format!("{}", e));
                        }
                    };
                    let remote_bytes =
                        cipherbox_api_client::ipfs::fetch_content(&api, &remote_cid)
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

                    let retry_seq = fresh_seq
                        .checked_add(1)
                        .ok_or_else(|| "IPNS sequence number overflow on retry".to_string())?;
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
                    use base64::Engine;
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
                            for cid in &old_cids {
                                let _ =
                                    cipherbox_api_client::ipfs::unpin_content(&api, cid).await;
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

            // D-01: route bin IPNS resolve through the verified chokepoint.
            let (mut bin_metadata, existing_cid) =
                match crate::verify::resolve_ipns_verified(&api, &bin_ipns_name).await {
                    Ok(verified) => {
                        match cipherbox_api_client::ipfs::fetch_content(&api, &verified.cid).await {
                            Ok(bytes) => {
                                match cipherbox_core::decrypt_bin_metadata(
                                    &bytes,
                                    &user_private_key,
                                ) {
                                    Ok(meta) => (meta, Some(verified.cid)),
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
                    Err(crate::verify::VerifyError::Legacy) => {
                        // D-04: legacy record — re-resolve and proceed with DB CID.
                        log::warn!(
                            "spawn_bin_entry_publish: IPNS {} resolved without signature fields \
                             — using DB CID (D-04)",
                            bin_ipns_name
                        );
                        match cipherbox_api_client::ipns::resolve_ipns(&api, &bin_ipns_name).await {
                            Ok(resp) => {
                                match cipherbox_api_client::ipfs::fetch_content(&api, &resp.cid).await {
                                    Ok(bytes) => {
                                        match cipherbox_core::decrypt_bin_metadata(&bytes, &user_private_key) {
                                            Ok(meta) => (meta, Some(resp.cid)),
                                            Err(e) => return Err(format!("Bin decrypt failed: {}", e)),
                                        }
                                    }
                                    Err(e) => return Err(format!("Bin fetch failed: {}", e)),
                                }
                            }
                            Err(e) => {
                                let e_str = format!("{}", e);
                                if is_ipns_not_found(&e_str) {
                                    (cipherbox_core::empty_bin_metadata(), None)
                                } else {
                                    return Err(format!("Bin resolve failed: {}", e));
                                }
                            }
                        }
                    }
                    Err(crate::verify::VerifyError::Invalid(msg)) => {
                        // D-02: fail only this operation.
                        log::warn!("spawn_bin_entry_publish: IPNS {} verify failed: {}", bin_ipns_name, msg);
                        return Err(format!("Bin IPNS verify failed: {}", msg));
                    }
                    Err(crate::verify::VerifyError::Api(e)) => {
                        let e_str = format!("{}", e);
                        if is_ipns_not_found(&e_str) {
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

            // Validate bin IPNS key length before entering the CAS loop.
            let bin_ipns_key_arr: Zeroizing<[u8; 32]> = {
                let arr: [u8; 32] = bin_ipns_private_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid bin IPNS key length".to_string())?;
                Zeroizing::new(arr)
            };

            // `existing_cid` is None when the bin IPNS record does not exist yet (first
            // publish for this vault's bin). The CAS helper's resolve_sequence would treat
            // that not-found as a fatal error, so the first publish must NOT go through the
            // CAS helper — it publishes directly at seq 0 with expected_sequence_number: None
            // (no prior record to compare against), mirroring the per-file first-publish path.
            let is_first_bin_publish = existing_cid.is_none();
            let new_cid_for_record = new_cid.clone();
            let old_cids: Vec<String> = existing_cid.into_iter().collect();
            use base64::Engine;

            let make_bin_record = |seq_for_record: u64| -> Result<(String, String), String> {
                let value = format!("/ipfs/{}", new_cid_for_record);
                let record = cipherbox_core::create_ipns_record(
                    &bin_ipns_key_arr,
                    &value,
                    seq_for_record,
                    86_400_000,
                )
                .map_err(|e| format!("Bin IPNS record creation failed: {}", e))?;
                let marshaled = cipherbox_core::marshal_ipns_record(&record)
                    .map_err(|e| format!("Bin IPNS marshal failed: {}", e))?;
                let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
                Ok((record_b64, new_cid_for_record.clone()))
            };

            if is_first_bin_publish {
                // First publish: no prior record, so no CAS. Publish at seq 0.
                let (record_b64, _cid) = make_bin_record(0)?;
                let req = cipherbox_api_client::IpnsPublishRequest {
                    ipns_name: bin_ipns_name.clone(),
                    record: record_b64,
                    metadata_cid: new_cid.clone(),
                    encrypted_ipns_private_key: None,
                    key_epoch: None,
                    expected_sequence_number: None,
                };
                match cipherbox_api_client::ipns::publish_ipns(&api, &req)
                    .await
                    .map_err(|e| format!("{}", e))?
                {
                    cipherbox_api_client::PublishResult::Success => {
                        coordinator.record_publish(&bin_ipns_name, 0);
                        log::info!("Bin entry published (first publish)");
                    }
                    cipherbox_api_client::PublishResult::Conflict { .. } => {
                        // Another client raced to create the bin record. D-01a: no
                        // JournalOp::BinPublish variant — surface as Err → EIO.
                        return Err(format!(
                            "Conflict on first bin IPNS publish for {} — another client raced",
                            bin_ipns_name
                        ));
                    }
                }
            } else {
                // Update publish: route through the shared CAS helper (D-03 / D-02).
                // D-01a: no JournalOp::BinPublish variant exists in crates/sdk/src/queue.rs
                // (only UploadFile/MkdirPublish); journaling bin publish is deferred (CONTEXT
                // Deferred Ideas). On retry exhaustion: return Err → log::error! → EIO.
                publish_with_cas_retry(
                    &api,
                    &coordinator,
                    &bin_ipns_name,
                    make_bin_record,
                    &old_cids,
                    None, // D-01a: no JournalOp::BinPublish variant; exhaustion → Err → EIO
                )
                .await
                .inspect(|_| log::info!("Bin entry published"))?;
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

/// Base exponential-backoff delay (in ms, pre-jitter) before re-encrypt attempt `attempt`.
/// `attempt` is 1-based; the delay applies before the *next* attempt. Yields 0.5s, 1s,
/// 2s, 4s for attempts 1..4. Saturates instead of overflowing the shift for large inputs.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn reencrypt_backoff_base_ms(attempt: u32) -> u64 {
    500u64
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(u64::MAX)
}

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
    // D-01: route through the verified chokepoint.
    let cid = match crate::verify::resolve_ipns_verified(api, file_meta_ipns_name).await {
        Ok(v) => v.cid,
        Err(crate::verify::VerifyError::Legacy) => {
            // D-04: legacy record — re-resolve and proceed with DB CID.
            log::warn!(
                "resolve_and_fetch_file_meta: IPNS {} resolved without signature fields \
                 — using DB CID (D-04)",
                file_meta_ipns_name
            );
            cipherbox_api_client::ipns::resolve_ipns(api, file_meta_ipns_name)
                .await
                .map_err(|e| format!("resolve file IPNS: {}", e))?.cid
        }
        Err(crate::verify::VerifyError::Invalid(msg)) => {
            // D-02: fail only this operation.
            return Err(format!(
                "file IPNS {} verify failed: {}",
                file_meta_ipns_name, msg
            ));
        }
        Err(crate::verify::VerifyError::Api(e)) => {
            return Err(format!("resolve file IPNS: {}", e));
        }
    };
    let enc_bytes = cipherbox_api_client::ipfs::fetch_content(api, &cid)
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
                            let base_ms = reencrypt_backoff_base_ms(attempt);
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
    // --- publish_with_cas_retry tests (D-03 / D-01a / D-02) ---
    //
    // These tests exercise the helper logic via a closure-driven seam. Since the
    // actual IPNS publish and coordinator calls are network-bound, we verify the
    // branching that does not require a live network by testing the logic paths
    // directly through mock PublishResult variants.

    /// Enum mirroring PublishResult for test seam
    #[derive(Debug)]
    enum MockPublishResult {
        Success,
        Conflict { current_sequence_number: u64 },
        Err(String),
    }

    /// Minimal seam for publish_with_cas_retry logic, exercisable without network.
    /// Returns (result, make_record_call_count, record_publish_called).
    fn run_publish_retry_seam(
        first_publish: MockPublishResult,
        retry_publish: Option<MockPublishResult>,
        journal_entry_is_some: bool,
    ) -> (Result<(), String>, usize, bool) {
        let mut make_record_call_count = 0usize;
        let mut record_publish_called = false;

        // Simulate the publish_with_cas_retry decision tree
        let result: Result<(), String> = (|| {
            let seq: u64 = 0; // simulated resolved sequence
            let new_seq = seq.checked_add(1).ok_or_else(|| "overflow".to_string())?;

            make_record_call_count += 1;
            let _record = format!("record-seq-{}", new_seq); // simulates make_record(new_seq)

            match first_publish {
                MockPublishResult::Err(e) => return Err(e),
                MockPublishResult::Success => {
                    record_publish_called = true;
                    return Ok(());
                }
                MockPublishResult::Conflict { .. } => {
                    // Re-resolve + re-make-record (the retry path)
                    let fresh_seq: u64 = 1; // simulated re-resolved sequence
                    let retry_seq =
                        fresh_seq.checked_add(1).ok_or_else(|| "overflow".to_string())?;
                    make_record_call_count += 1;
                    let _retry_record = format!("record-seq-{}", retry_seq);

                    match retry_publish.unwrap_or(MockPublishResult::Err(
                        "no retry configured".to_string(),
                    )) {
                        MockPublishResult::Success => {
                            record_publish_called = true;
                            return Ok(());
                        }
                        MockPublishResult::Conflict { .. } => {
                            // persistent conflict: if journal_entry is Some, enqueue
                            // (journal path not wired this phase — no call site supplies Some)
                            // Per D-01a: return Err (fire-and-forget → EIO)
                            if journal_entry_is_some {
                                // Future: queue.put(&entry); return Ok
                                return Err("persistent conflict — journal path placeholder".to_string());
                            } else {
                                return Err(format!("persistent conflict for test-ipns-name"));
                            }
                        }
                        MockPublishResult::Err(e) => return Err(e),
                    }
                }
            }
        })();

        (result, make_record_call_count, record_publish_called)
    }

    // Test 1: success on first attempt — make_record called once, record_publish called.
    #[test]
    fn publish_with_cas_retry_success_first_attempt() {
        let (result, call_count, record_publish) =
            run_publish_retry_seam(MockPublishResult::Success, None, false);
        assert!(result.is_ok(), "expected Ok on first-attempt success");
        assert_eq!(call_count, 1, "make_record must be called once on success");
        assert!(record_publish, "record_publish must be called on success");
    }

    // Test 2: conflict then retry success — make_record called twice, record_publish called.
    #[test]
    fn publish_with_cas_retry_conflict_then_success() {
        let (result, call_count, record_publish) = run_publish_retry_seam(
            MockPublishResult::Conflict {
                current_sequence_number: 5,
            },
            Some(MockPublishResult::Success),
            false,
        );
        assert!(result.is_ok(), "expected Ok after conflict+retry success");
        assert_eq!(
            call_count, 2,
            "make_record must be called twice (initial + retry)"
        );
        assert!(record_publish, "record_publish must be called on retry success");
    }

    // Test 3: persistent conflict with journal_entry: None (the per-file/bin path per D-01a).
    // Must return Err containing "conflict" — NEVER record_publish with stale seq, NEVER warn-and-ack.
    #[test]
    fn publish_with_cas_retry_persistent_conflict_journal_none_returns_err() {
        let (result, _call_count, record_publish) = run_publish_retry_seam(
            MockPublishResult::Conflict {
                current_sequence_number: 5,
            },
            Some(MockPublishResult::Conflict {
                current_sequence_number: 6,
            }),
            false, // journal_entry: None — the per-file/bin path per D-01a
        );
        assert!(result.is_err(), "persistent conflict with journal:None must return Err");
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.to_lowercase().contains("conflict"),
            "error message must mention 'conflict', got: {}",
            err_msg
        );
        assert!(
            !record_publish,
            "record_publish must NOT be called on persistent conflict (would ack stale seq)"
        );
    }

    // Test 4: make_record returns Err (e.g. wrap_key failure) — propagates Err, no publish, no record_publish.
    #[test]
    fn publish_with_cas_retry_make_record_error_propagates() {
        let (result, _call_count, record_publish) = run_publish_retry_seam(
            MockPublishResult::Err("wrap_key failed: invalid key".to_string()),
            None,
            false,
        );
        assert!(result.is_err(), "make_record Err must propagate");
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("wrap_key"),
            "error must propagate make_record message, got: {}",
            err_msg
        );
        assert!(
            !record_publish,
            "record_publish must NOT be called when make_record errors"
        );
    }

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

    #[test]
    fn reencrypt_backoff_base_ms_doubles_per_attempt() {
        // 1-based attempt index: 0.5s, 1s, 2s, 4s, 8s ...
        assert_eq!(super::reencrypt_backoff_base_ms(1), 500);
        assert_eq!(super::reencrypt_backoff_base_ms(2), 1000);
        assert_eq!(super::reencrypt_backoff_base_ms(3), 2000);
        assert_eq!(super::reencrypt_backoff_base_ms(4), 4000);
    }

    #[test]
    fn reencrypt_backoff_base_ms_saturates_on_huge_attempt() {
        // A pathological attempt value must not overflow the left shift.
        assert_eq!(super::reencrypt_backoff_base_ms(u32::MAX), u64::MAX);
    }

    #[test]
    fn is_ipns_not_found_matches_case_insensitively() {
        assert!(super::is_ipns_not_found("IPNS record Not Found"));
        assert!(super::is_ipns_not_found("404 not found"));
    }

    #[test]
    fn is_ipns_not_found_rejects_other_errors() {
        assert!(!super::is_ipns_not_found("connection refused"));
        assert!(!super::is_ipns_not_found("500 internal server error"));
        assert!(!super::is_ipns_not_found(""));
    }
}
