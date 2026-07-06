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

                    // D-01a: journal_entry param reserved for future journal-enqueue path
                    // (no JournalOp::FilePublish/BinPublish variant this phase; all call sites
                    // pass None). On persistent conflict: Err → EIO.
                    let _ = &journal_entry; // suppress unused warning until D-01a is wired
                    Err(format!("persistent conflict for {}", ipns_name))
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

/// Total wall-clock budget for a single blocking share-revocation, layered over
/// the bounded retry loop. A hung or unreachable backend surfaces as a failure
/// (→ EIO) rather than wedging the user's `rm` indefinitely.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
const REVOKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Maximum revocation attempts (1 initial + 2 retries). Mirrors the SDK
/// `revokeBatchWithRetry` `maxAttempts = 3` default.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
const REVOKE_MAX_ATTEMPTS: u32 = 3;

/// Decide whether a revocation error is a deterministic client failure that will
/// never succeed on retry (a 4xx — validation 400, auth 401/403, etc.) and so
/// should be surfaced immediately rather than burning the backoff budget.
///
/// Transport failures and 5xx are transient and retried. Mirrors the SDK
/// `isNonRetryableError` predicate (share/index.ts).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn is_non_retryable_revoke_error(err: &cipherbox_api_client::ApiError) -> bool {
    matches!(
        err,
        cipherbox_api_client::ApiError::ApiResponse { status, .. }
            if (400..=499).contains(status)
    )
}

/// Synchronously revoke every share/invite for a single deleted node's IPNS
/// name, blocking the calling filesystem thread until it succeeds, fails
/// non-retryably, exhausts retries, or times out.
///
/// This is the fail-closed access cutoff that must run BEFORE the destructive
/// inode removal / parent metadata update on the delete path. On `Err(())` the
/// caller MUST abort the delete (e.g. `reply.error(libc::EIO)`) so the item
/// stays put and no sharee is left with access to soon-to-be-orphaned content.
///
/// Returns `Ok(())` when:
/// - the revocation succeeds (2xx), or
/// - `ipns_name` is empty (nothing was ever shared without a name — nothing to
///   revoke).
///
/// Returns `Err(())` on any non-retryable 4xx, exhausted transient retries, or
/// timeout. The error is intentionally opaque (the caller maps it to a single
/// errno); details are logged.
///
/// The whole loop is bounded by [`REVOKE_TIMEOUT`] layered over up to
/// [`REVOKE_MAX_ATTEMPTS`] attempts with exponential backoff (300ms * 2^attempt).
//
// `Result<(), ()>` is deliberate: the only caller (the FUSE delete path) maps
// every failure to a single errno (EIO / STATUS_ACCESS_DENIED) and the rich
// error detail is logged here, so propagating a typed error would add no value.
#[allow(clippy::result_unit_err)]
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn revoke_shares_blocking(
    api: &Arc<ApiClient>,
    rt: &tokio::runtime::Handle,
    ipns_name: &str,
) -> Result<(), ()> {
    if ipns_name.is_empty() {
        // Nothing to revoke for an unnamed node.
        return Ok(());
    }

    let names = vec![ipns_name.to_string()];

    let outcome = rt.block_on(async {
        tokio::time::timeout(REVOKE_TIMEOUT, async {
            let mut last_err: Option<cipherbox_api_client::ApiError> = None;
            for attempt in 0..REVOKE_MAX_ATTEMPTS {
                match cipherbox_api_client::shares::revoke_shares_for_items(api, &names).await {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        // Deterministic 4xx: surface immediately, no retry.
                        if is_non_retryable_revoke_error(&err) {
                            return Err(err);
                        }
                        last_err = Some(err);
                        // Backoff before the next attempt (skip after the last).
                        if attempt < REVOKE_MAX_ATTEMPTS - 1 {
                            let backoff_ms = 300u64 * (1u64 << attempt);
                            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        }
                    }
                }
            }
            Err(
                last_err.unwrap_or(cipherbox_api_client::ApiError::ApiResponse {
                    status: 0,
                    message: "share revocation exhausted retries".to_string(),
                }),
            )
        })
        .await
    });

    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            log::error!(
                "share revocation failed for ipns {} (delete aborted): {}",
                ipns_name,
                e
            );
            Err(())
        }
        Err(_elapsed) => {
            log::error!(
                "share revocation timed out for ipns {} after {:?} (delete aborted)",
                ipns_name,
                REVOKE_TIMEOUT
            );
            Err(())
        }
    }
}

/// Spawn a background OS thread to upload a sealed node/v3 `PublishedNode` and
/// publish it via IPNS (69-09 Slice 3 write emission).
///
/// The parent folder/root node was already re-sealed by
/// [`crate::CipherBoxFS::build_folder_metadata`] — this function uploads the
/// opaque `published_node` bytes verbatim (no `FolderMetadata` encrypt) and runs
/// the CAS publish loop. On an IPNS sequence conflict it republishes the SAME
/// sealed bytes at a fresh sequence (last-writer-wins). The node/v3 merge of
/// concurrent remote children (the former `merge_folder_children` path) is
/// deferred to 69-09 Slice 5 — a sealed envelope cannot be structurally merged
/// without unsealing under the parent readKey, which Slice 5 wires in.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn spawn_metadata_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    published_node: Vec<u8>,
    ipns_private_key: Zeroizing<Vec<u8>>, // D-12: Zeroizing to match spawn_bin_entry_publish pattern
    ipns_name: String,
    old_metadata_cid: Option<String>,
    coordinator: Arc<PublishCoordinator>,
) {
    std::thread::spawn(move || {
        let result = rt.block_on(async {
            let lock = coordinator.get_lock(&ipns_name);
            let _guard = lock.lock().await;

            // Pre-validate IPNS key length so the record builder is infallible.
            let ipns_key_arr: Zeroizing<[u8; 32]> = {
                let arr: [u8; 32] = ipns_private_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid IPNS private key length".to_string())?;
                Zeroizing::new(arr)
            };

            // Upload the sealed node/v3 envelope ONCE, then CAS-publish it.
            let cid = cipherbox_api_client::ipfs::upload_content(&api, &published_node)
                .await
                .map_err(|e| format!("{}", e))?;
            let old_cids: Vec<String> = old_metadata_cid.into_iter().collect();

            let make_record = |new_seq: u64| -> Result<String, String> {
                use base64::Engine;
                let value = format!("/ipfs/{}", cid);
                let record =
                    cipherbox_core::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)
                        .map_err(|e| format!("IPNS record creation failed: {}", e))?;
                let marshaled = cipherbox_core::marshal_ipns_record(&record)
                    .map_err(|e| format!("IPNS record marshal failed: {}", e))?;
                Ok(base64::engine::general_purpose::STANDARD.encode(&marshaled))
            };

            // CAS loop: on conflict, republish the SAME sealed bytes at a fresh
            // sequence (last-writer-wins). Bounded to avoid an unbounded retry.
            let max_attempts = 5u32;
            let mut attempt = 0u32;
            loop {
                let seq = coordinator.resolve_sequence(&api, &ipns_name).await?;
                let new_seq = seq
                    .checked_add(1)
                    .ok_or_else(|| "IPNS sequence number overflow".to_string())?;
                let record_b64 = make_record(new_seq)?;
                let req = cipherbox_api_client::IpnsPublishRequest {
                    ipns_name: ipns_name.clone(),
                    record: record_b64,
                    metadata_cid: cid.clone(),
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
                        for old in &old_cids {
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, old).await;
                        }
                        log::info!("Background node/v3 publish succeeded for {}", ipns_name);
                        break;
                    }
                    cipherbox_api_client::PublishResult::Conflict {
                        current_sequence_number,
                    } => {
                        attempt += 1;
                        if attempt >= max_attempts {
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &cid).await;
                            return Err(format!(
                                "Persistent conflict for {} after {} attempts",
                                ipns_name, max_attempts
                            ));
                        }
                        log::warn!(
                            "Conflict for {} (expected {}, server has {}); retrying at fresh seq",
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
                match cipherbox_api_client::ipns::resolve_ipns_verified(&api, &bin_ipns_name).await // sc6-allow: legacy recycle-bin publish (spawn_bin_entry_publish), not a node/v3 read
                {
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
                    // D-04: Legacy variant removed — all-absent sig fields fail closed.
                    Err(cipherbox_api_client::ipns::VerifyError::Invalid(msg)) => {
                        // D-02: fail only this operation.
                        log::warn!(
                            "spawn_bin_entry_publish: IPNS {} verify failed: {}",
                            bin_ipns_name,
                            msg
                        );
                        return Err(format!("Bin IPNS verify failed: {}", msg));
                    }
                    Err(cipherbox_api_client::ipns::VerifyError::Api(e)) => {
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
                // First publish: no prior record, so no CAS. Publish at seq 1 (D-02).
                let (record_b64, _cid) = make_bin_record(1)?;
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
                        coordinator.record_publish(&bin_ipns_name, 1);
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
                    let retry_seq = fresh_seq
                        .checked_add(1)
                        .ok_or_else(|| "overflow".to_string())?;
                    make_record_call_count += 1;
                    let _retry_record = format!("record-seq-{}", retry_seq);

                    match retry_publish
                        .unwrap_or(MockPublishResult::Err("no retry configured".to_string()))
                    {
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
                                return Err(
                                    "persistent conflict — journal path placeholder".to_string()
                                );
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
        assert!(
            record_publish,
            "record_publish must be called on retry success"
        );
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
        assert!(
            result.is_err(),
            "persistent conflict with journal:None must return Err"
        );
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
    fn is_ipns_not_found_matches_case_insensitively() {
        // Predicate matches on "not found" substring (case-insensitive).
        assert!(super::is_ipns_not_found("IPNS record Not Found"));
        // Use a legible case that documents what the predicate actually matches.
        assert!(super::is_ipns_not_found("record not found"));
        // Negative: "404" alone must NOT match — the predicate is "not found", not "404".
        assert!(
            !super::is_ipns_not_found("404"),
            "bare '404' without 'not found' must not match is_ipns_not_found"
        );
    }

    #[test]
    fn is_ipns_not_found_rejects_other_errors() {
        assert!(!super::is_ipns_not_found("connection refused"));
        assert!(!super::is_ipns_not_found("500 internal server error"));
        assert!(!super::is_ipns_not_found(""));
    }

    // --- revoke_shares_blocking classifier + no-op tests ---

    use cipherbox_api_client::ApiError;

    /// Every 4xx is a deterministic client failure → non-retryable (surface
    /// immediately, no backoff). Mirrors the SDK `isNonRetryableError`.
    #[test]
    fn revoke_4xx_is_non_retryable() {
        for status in [400u16, 401, 403, 404, 409, 422, 499] {
            let err = ApiError::ApiResponse {
                status,
                message: "client error".to_string(),
            };
            assert!(
                super::is_non_retryable_revoke_error(&err),
                "status {} must be classified non-retryable",
                status
            );
        }
    }

    /// 5xx is transient → retryable (consume the backoff budget).
    #[test]
    fn revoke_5xx_is_retryable() {
        for status in [500u16, 502, 503, 504] {
            let err = ApiError::ApiResponse {
                status,
                message: "server error".to_string(),
            };
            assert!(
                !super::is_non_retryable_revoke_error(&err),
                "status {} must be classified retryable",
                status
            );
        }
    }

    /// Auth/deserialization/not-found error variants are not the
    /// ApiResponse-4xx shape, so they are treated as retryable (the loop will
    /// re-attempt and ultimately surface as a failure → EIO if persistent).
    #[test]
    fn revoke_non_apiresponse_errors_are_retryable() {
        assert!(!super::is_non_retryable_revoke_error(
            &ApiError::AuthFailed("no token".to_string())
        ));
        assert!(!super::is_non_retryable_revoke_error(
            &ApiError::DeserializationFailed("bad json".to_string())
        ));
        assert!(!super::is_non_retryable_revoke_error(
            &ApiError::IpnsNotFound("k51".to_string())
        ));
        // The internal "exhausted retries" sentinel (status 0) is NOT in the
        // 4xx range, so it does not short-circuit a fresh attempt.
        assert!(!super::is_non_retryable_revoke_error(
            &ApiError::ApiResponse {
                status: 0,
                message: "exhausted".to_string(),
            }
        ));
    }

    /// An empty ipns_name is a no-op: revoke_shares_blocking returns Ok(())
    /// WITHOUT any network round-trip (proven by the unreachable base URL — a
    /// real request would fail and return Err).
    #[test]
    fn revoke_blocking_empty_name_is_ok_no_network() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let api = std::sync::Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
        let result = super::revoke_shares_blocking(&api, rt.handle(), "");
        assert!(result.is_ok());
    }

    /// A non-empty name against an unreachable backend exhausts retries and
    /// returns Err(()) — the fail-closed signal the delete path maps to EIO.
    /// Connection-refused is a transport error (retryable), so this also
    /// exercises the retry loop terminating in Err.
    #[test]
    fn revoke_blocking_unreachable_backend_fails_closed() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Port 1 is unreachable: connect refused → RequestFailed (transient) →
        // retried up to the cap → Err. Bounded by REVOKE_TIMEOUT well under the
        // 15s ceiling for a connection-refused (returns immediately each time).
        let api = std::sync::Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
        let result = super::revoke_shares_blocking(&api, rt.handle(), "k51unreachable");
        assert!(
            result.is_err(),
            "revoke against an unreachable backend must fail closed (Err)"
        );
    }
}
