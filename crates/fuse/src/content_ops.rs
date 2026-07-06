//! Shared crypto/IPNS helpers for macOS FUSE and Windows WinFsp.
//!
//! This module holds the truly-identical async helpers extracted from
//! `operations.rs` (macOS) and `platform/windows/operations.rs` (Windows).
//!
//! # A2 Scope Note
//!
//! `fetch_and_decrypt_file_content` (the SYNCHRONOUS wrapper) is NOT included
//! here because the macOS FUSE path (operations.rs) uses a private
//! `block_with_timeout` with `NETWORK_TIMEOUT = 3s`, while the Windows path
//! uses `crate::block_with_timeout` (10s from runtime.rs). The different
//! timeouts are intentional: the macOS sync FUSE callback thread must not
//! block for too long. Keeping the sync wrapper in each operations.rs preserves
//! this invariant. Both files continue to re-export from this module only the
//! async helpers that are truly identical.

/// Build a `Zeroizing<[u8; 32]>` from a slice without ever materializing a
/// plain `[u8; 32]` temporary (preallocate-then-copy). A `try_into()` would
/// briefly leave an un-zeroed copy of sensitive key material on the stack.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn zeroizing_32_from_slice(
    bytes: &[u8],
    message: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    if bytes.len() != 32 {
        return Err(message.to_string());
    }
    let mut out = zeroize::Zeroizing::new([0_u8; 32]);
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Symmetrically unseal a file node's OWN read-body (node/v3, SC#1) and return
/// its [`NodeContent`] descriptor. Never ECIES — the read-body is sealed under
/// the file node's `read_key`. `read_key` is a caller-owned borrow (D-09).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn unseal_file_content(
    published: &cipherbox_core::node::PublishedNode,
    read_key: &[u8; 32],
) -> Result<cipherbox_core::node::NodeContent, String> {
    use base64::Engine as _;
    let read_sealed_bytes = base64::engine::general_purpose::STANDARD
        .decode(&published.read_sealed)
        .map_err(|e| format!("Invalid file node read_sealed base64: {}", e))?;
    let body = cipherbox_core::node::seal::unseal_node(
        &read_sealed_bytes,
        read_key,
        &published.id,
        cipherbox_core::node::NodeKind::File,
        published.generation,
    )
    .map_err(|e| format!("File node read-body unseal failed: {}", e))?;
    let node = cipherbox_core::node::decode_node(&body)
        .map_err(|e| format!("File node decode failed: {}", e))?;
    match node {
        cipherbox_core::node::Node::File { content, .. } => Ok(content),
        _ => Err("Expected a file node, got folder/root".to_string()),
    }
}

/// Gated single-node fetch (SC#6) + symmetric content download + decrypt.
///
/// node/v3: resolves the file node at `ipns_name` through the sanctioned
/// [`cipherbox_sdk::fetch_node_gated`] wrapper (anti-rollback gate first), then
/// unseals its read-body under `read_key` and downloads+decrypts the content.
/// This is the owned-prefetch entrypoint used by the read/open/readdir paths —
/// each takes an OWNED `high_water` clone into the spawned task. `read_key` is a
/// caller-owned borrow (D-09).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn fetch_node_and_decrypt_content(
    api: &cipherbox_api_client::ApiClient,
    high_water: &cipherbox_sdk::RotationHighWater<cipherbox_sdk::JsonSidecarFloorStore>,
    ipns_name: &str,
    read_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let fetcher = cipherbox_sdk::ApiNodeFetcher { api };
    let published = cipherbox_sdk::fetch_node_gated(&fetcher, high_water, ipns_name)
        .await
        .map_err(|e| format!("fetch_node_gated failed for {}: {}", ipns_name, e))?;
    fetch_and_decrypt_content_async(api, &published, read_key).await
}

/// Gated single-node fetch (SC#6) that recovers a file's content DESCRIPTORS
/// (CID, IV hex, size, encryption mode) WITHOUT downloading the content.
///
/// Used by the FilePointer-resolution path: an unresolved File inode (empty CID)
/// is resolved by fetching its own node and unsealing the read-body. Returns
/// `(cid, iv_hex, size, encryption_mode)`.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn resolve_file_descriptors(
    api: &cipherbox_api_client::ApiClient,
    high_water: &cipherbox_sdk::RotationHighWater<cipherbox_sdk::JsonSidecarFloorStore>,
    ipns_name: &str,
    read_key: &[u8; 32],
) -> Result<(String, String, u64, String), String> {
    let fetcher = cipherbox_sdk::ApiNodeFetcher { api };
    let published = cipherbox_sdk::fetch_node_gated(&fetcher, high_water, ipns_name)
        .await
        .map_err(|e| format!("fetch_node_gated failed for {}: {}", ipns_name, e))?;
    let content = unseal_file_content(&published, read_key)?;
    Ok((
        content.cid,
        content.file_iv,
        content.size,
        content.encryption_mode,
    ))
}

/// Async version of content download + decrypt for background prefetch tasks.
///
/// node/v3 (69-09 Slice 2): the file content-key is recovered by SYMMETRIC
/// unseal of the file node's OWN sealed read-body — NOT ECIES. The `published`
/// envelope's `read_sealed` body is unsealed under the file node's `read_key`
/// (from `InodeKind::File.read_key`) via `cipherbox_core::node::seal::unseal_node`,
/// yielding a `NodeContent { cid, file_iv, encryption_mode, file_key, .. }`.
/// The content is then fetched by that CID and decrypted with the recovered
/// `file_key`.
///
/// D-09 terminal owner: `read_key` is a caller-owned borrow, never zeroed here.
/// The recovered `file_key`/`NodeContent` scratch is owned locally and dropped
/// (the fixed-key buffer via `Zeroizing`).
///
/// SIGNATURE CHANGE (69-09 Slice 5 caller note): the former
/// `(cid, encrypted_file_key_hex, iv_hex, encryption_mode, private_key)` params
/// are replaced by the file node's fetched `PublishedNode` + its `read_key`
/// (the descriptors now live authoritatively inside the sealed body). The
/// caller (read_ops/dir_ops) must obtain the file node's `PublishedNode` via
/// the sanctioned resolve path and pass the inode's `read_key`.
///
/// Uses fully-qualified submodule paths for `cipherbox_crypto` so this compiles
/// under both `fuse` and `winfsp` feature sets.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn fetch_and_decrypt_content_async(
    api: &cipherbox_api_client::ApiClient,
    published: &cipherbox_core::node::PublishedNode,
    read_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    // Recover the file node's content descriptor by SYMMETRIC unseal of its own
    // read-body (node/v3, SC#1) — never ECIES.
    let content = unseal_file_content(published, read_key)?;

    let encrypted_bytes = cipherbox_api_client::ipfs::fetch_content(api, &content.cid)
        .await
        .map_err(|e| e.to_string())?;
    let file_key_arr = zeroizing_32_from_slice(&content.file_key, "Invalid file key length")?;

    let plaintext = if content.encryption_mode == "CTR" {
        let iv = hex::decode(&content.file_iv).map_err(|_| "Invalid file IV hex".to_string())?;
        let iv_arr: [u8; 16] = iv
            .try_into()
            .map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
        cipherbox_crypto::aes_ctr::decrypt_aes_ctr(&encrypted_bytes, &file_key_arr, &iv_arr)
            .map_err(|e| format!("CTR decryption failed: {}", e))?
    } else {
        let iv = hex::decode(&content.file_iv).map_err(|_| "Invalid file IV hex".to_string())?;
        let iv_arr: [u8; 12] = iv
            .try_into()
            .map_err(|_| "Invalid GCM IV length (expected 12)".to_string())?;
        cipherbox_crypto::aes::decrypt_aes_gcm(&encrypted_bytes, &file_key_arr, &iv_arr)
            .map_err(|e| format!("GCM decryption failed: {}", e))?
    };
    Ok(plaintext)
}

/// Encrypt and publish per-file FileMetadata to the file's own IPNS record.
///
/// Shared between macOS FUSE (operations.rs re-exports this) and Windows WinFsp
/// (platform/windows/operations.rs re-exports this). Uses fully-qualified
/// submodule paths for `cipherbox_crypto` and `cipherbox_core::ipns` so this
/// compiles under both feature sets.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn publish_file_metadata(
    api: &cipherbox_api_client::ApiClient,
    file_meta: &cipherbox_core::folder::FileMetadata,
    folder_key: &[u8],
    file_ipns_private_key: &zeroize::Zeroizing<Vec<u8>>,
    file_ipns_name: &str,
    coordinator: &crate::PublishCoordinator,
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
    is_first_publish: bool,
) -> Result<(), String> {
    let folder_key_arr = zeroizing_32_from_slice(
        folder_key,
        "Invalid folder key length for FileMetadata encryption",
    )?;

    // Encrypt FileMetadata with parent folder key
    let sealed = cipherbox_core::folder::encrypt_file_metadata(file_meta, &folder_key_arr)
        .map_err(|e| format!("FileMetadata encryption failed: {}", e))?;

    // Package as JSON envelope: { "iv": hex, "data": base64 }
    let iv_hex = hex::encode(&sealed[..12]);
    use base64::Engine;
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
    let json = serde_json::json!({ "iv": iv_hex, "data": data_base64 });
    let json_bytes = serde_json::to_vec(&json)
        .map_err(|e| format!("FileMetadata JSON serialization failed: {}", e))?;

    // Upload encrypted file metadata to IPFS
    let file_meta_cid = cipherbox_api_client::ipfs::upload_content(api, &json_bytes)
        .await
        .map_err(|e| e.to_string())?;

    // Resolve current IPNS sequence number
    let current_seq = if is_first_publish {
        None
    } else {
        Some(coordinator.resolve_sequence(api, file_ipns_name).await?)
    };

    // Create IPNS key material shared by both branches (D.2: only signing steps move inside is_first_publish).
    let ipns_key_arr = zeroizing_32_from_slice(
        file_ipns_private_key.as_slice(),
        "Invalid file IPNS private key length",
    )?;
    let new_seq = crate::next_file_publish_sequence(is_first_publish, current_seq)?;
    let value = format!("/ipfs/{}", file_meta_cid);

    // TEE enrollment on first publish only (same pattern as folder creation in write_ops.rs)
    let (encrypted_ipns_for_tee, tee_epoch) =
        match (is_first_publish, tee_public_key, tee_key_epoch) {
            (true, Some(tee_key), Some(epoch)) => {
                let wrapped =
                    cipherbox_crypto::ecies::wrap_key(file_ipns_private_key.as_slice(), tee_key)
                        .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
                (Some(hex::encode(&wrapped)), Some(epoch))
            }
            (true, Some(_), None) => {
                return Err("TEE public key present but key_epoch missing".to_string());
            }
            _ => (None, None),
        };

    // Route through the shared CAS publish helper (D-02 / D-03).
    // Per-file IPNS publishes now use expected_sequence_number: Some(seq) via the helper —
    // the previous None was the D-01/D-02 bug (Conflict fell through to record_publish).
    //
    // D-01a: no JournalOp::FilePublish variant exists in crates/sdk/src/queue.rs
    // (only UploadFile/MkdirPublish); journaling per-file publish is deferred (CONTEXT
    // Deferred Ideas). On retry exhaustion: return Err, which the fire-and-forget caller
    // (spawn_file_meta_reencrypt) or the blocking/sync path logs at log::error! → EIO.
    //
    // TEE enrollment fields (encrypted_ipns_for_tee, tee_epoch) are used ONLY on the
    // is_first_publish branch below, which builds its own IpnsPublishRequest and does NOT
    // route through publish_with_cas_retry. The update path (the CAS helper) never carries
    // TEE fields — the helper always sets encrypted_ipns_private_key/key_epoch to None, and
    // updates need no re-enrollment. The make_record closure only re-signs (record, cid).
    let file_meta_cid_for_closure = file_meta_cid.clone();

    // For is_first_publish, there is no prior sequence to CAS against. The helper
    // calls coordinator.resolve_sequence first; for a first publish the server returns
    // sequence 0 or "not found" which is handled by next_file_publish_sequence above.
    // On a genuine first publish the expected_sequence_number should be None (no prior
    // sequence). We only apply CAS for update publishes (not is_first_publish).
    if is_first_publish {
        // First publish: no CAS expected_sequence_number (no prior record exists).
        // D.2: record/marshaled/record_b64 only needed here; build inside the branch.
        let record =
            cipherbox_core::ipns::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)
                .map_err(|e| format!("File IPNS record creation failed: {}", e))?;
        let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
            .map_err(|e| format!("File IPNS record marshal failed: {}", e))?;
        let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
        let req = cipherbox_api_client::IpnsPublishRequest {
            ipns_name: file_ipns_name.to_string(),
            record: record_b64,
            metadata_cid: file_meta_cid.clone(),
            encrypted_ipns_private_key: encrypted_ipns_for_tee,
            key_epoch: tee_epoch,
            expected_sequence_number: None,
        };
        match cipherbox_api_client::ipns::publish_ipns(api, &req)
            .await
            .map_err(|e| e.to_string())?
        {
            cipherbox_api_client::PublishResult::Success => {}
            cipherbox_api_client::PublishResult::Conflict { .. } => {
                // On first publish, a conflict means another client raced to create.
                // D-01a: no JournalOp::FilePublish variant — return Err → EIO.
                return Err(format!(
                    "Conflict on first per-file IPNS publish for {} — another client raced",
                    file_ipns_name
                ));
            }
        }
        coordinator.record_publish(file_ipns_name, new_seq);
    } else {
        // Update publish: use CAS via the shared helper (D-02 / D-03).
        // current_seq is always Some here (is_first_publish == false) and is consumed only by
        // next_file_publish_sequence above; the helper re-resolves the sequence internally, so
        // no local unwrap/guard is needed.
        crate::metadata::publish_with_cas_retry(
            api,
            coordinator,
            file_ipns_name,
            |new_seq_for_record: u64| {
                // Re-sign the SAME metadata blob with the new sequence number.
                // The CID (file_meta_cid_for_closure) does not change on retry — only the
                // sequence embedded in the IPNS record signature changes.
                let value = format!("/ipfs/{}", file_meta_cid_for_closure);
                let record = cipherbox_core::ipns::create_ipns_record(
                    &ipns_key_arr,
                    &value,
                    new_seq_for_record,
                    86_400_000,
                )
                .map_err(|e| format!("File IPNS record creation failed on retry: {}", e))?;
                let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
                    .map_err(|e| format!("File IPNS record marshal failed on retry: {}", e))?;
                use base64::Engine;
                let retry_record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
                Ok((retry_record_b64, file_meta_cid_for_closure.clone()))
            },
            &[],  // no old CIDs to unpin on per-file publish (caller handles pruned_cids)
            None, // D-01a: no JournalOp::FilePublish variant; exhaustion → Err → EIO
        )
        .await?;
        // publish_with_cas_retry calls coordinator.record_publish on success.
        // The closure re-signs with the sequence number the helper computes on each attempt.
    }

    log::info!("Per-file IPNS publish succeeded for {}", file_ipns_name);

    Ok(())
}
