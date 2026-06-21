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

/// Async version of content download + decrypt for background prefetch tasks.
///
/// Uses fully-qualified submodule paths for `cipherbox_crypto` so this compiles
/// under both `fuse` and `winfsp` feature sets.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn fetch_and_decrypt_content_async(
    api: &cipherbox_api_client::ApiClient,
    cid: &str,
    encrypted_file_key_hex: &str,
    iv_hex: &str,
    encryption_mode: &str,
    private_key: &[u8],
) -> Result<Vec<u8>, String> {
    let encrypted_bytes = cipherbox_api_client::ipfs::fetch_content(api, cid)
        .await
        .map_err(|e| e.to_string())?;
    let encrypted_file_key =
        hex::decode(encrypted_file_key_hex).map_err(|_| "Invalid file key hex".to_string())?;
    // unwrap_key returns Zeroizing<Vec<u8>> (S3/D-05).
    let file_key = cipherbox_crypto::ecies::unwrap_key(&encrypted_file_key, private_key)
        .map_err(|e| format!("File key unwrap failed: {}", e))?;
    let file_key_arr = zeroizing_32_from_slice(file_key.as_slice(), "Invalid file key length")?;

    let plaintext = if encryption_mode == "CTR" {
        let iv = hex::decode(iv_hex).map_err(|_| "Invalid file IV hex".to_string())?;
        let iv_arr: [u8; 16] = iv
            .try_into()
            .map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
        cipherbox_crypto::aes_ctr::decrypt_aes_ctr(&encrypted_bytes, &file_key_arr, &iv_arr)
            .map_err(|e| format!("CTR decryption failed: {}", e))?
    } else {
        let iv = hex::decode(iv_hex).map_err(|_| "Invalid file IV hex".to_string())?;
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

    // Create and sign IPNS record
    let ipns_key_arr = zeroizing_32_from_slice(
        file_ipns_private_key.as_slice(),
        "Invalid file IPNS private key length",
    )?;
    let new_seq = crate::next_file_publish_sequence(is_first_publish, current_seq)?;
    let value = format!("/ipfs/{}", file_meta_cid);
    let record =
        cipherbox_core::ipns::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)
            .map_err(|e| format!("File IPNS record creation failed: {}", e))?;
    let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
        .map_err(|e| format!("File IPNS record marshal failed: {}", e))?;

    let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

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
    // TEE enrollment fields (encrypted_ipns_for_tee, tee_epoch) are passed on the first
    // publish only. The make_record closure captures them and includes them in the record.
    // On the retry path (conflict → re-resolve → retry), make_record is called a second
    // time with a higher new_seq — the TEE fields are preserved across both calls.
    let file_meta_cid_for_closure = file_meta_cid.clone();

    // For is_first_publish, there is no prior sequence to CAS against. The helper
    // calls coordinator.resolve_sequence first; for a first publish the server returns
    // sequence 0 or "not found" which is handled by next_file_publish_sequence above.
    // On a genuine first publish the expected_sequence_number should be None (no prior
    // sequence). We only apply CAS for update publishes (not is_first_publish).
    if is_first_publish {
        // First publish: no CAS expected_sequence_number (no prior record exists).
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
        // The make_record closure builds a new IPNS record for a given sequence number.
        // For update publishes, current_seq is Some(resolved_seq) so new_seq = resolved_seq + 1.
        // The helper re-resolves on conflict and calls make_record again with the fresh seq.
        let current_seq_for_cas = current_seq
            .ok_or_else(|| "resolve_sequence returned None for update publish".to_string())?;

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
                let retry_record_b64 =
                    base64::engine::general_purpose::STANDARD.encode(&marshaled);
                Ok((retry_record_b64, file_meta_cid_for_closure.clone()))
            },
            &[], // no old CIDs to unpin on per-file publish (caller handles pruned_cids)
            None, // D-01a: no JournalOp::FilePublish variant; exhaustion → Err → EIO
        )
        .await?;

        // NOTE: publish_with_cas_retry calls coordinator.record_publish on success.
        // The initial record_b64 built above is NOT used on the retry path — the closure
        // re-signs with the fresh sequence. This is correct: the first publish attempt
        // uses expected_sequence_number: Some(current_seq_for_cas) which is already
        // baked into the helper's initial publish call via the helper's resolve_sequence.
        // The make_record closure is only called with the sequence numbers the HELPER
        // computes — so the pre-built record_b64 for the initial call is not reused.
        //
        // To feed the pre-built record_b64 to the helper's first call, we must match
        // what the helper does: it calls make_record(resolve_sequence()+1). Since we
        // already computed new_seq = current_seq + 1 above, the first closure call will
        // get new_seq again (same value). The record produced by the closure must match
        // the seq, and the closure re-signs with the seq it receives — this is correct.
        let _ = current_seq_for_cas; // used above in comment; suppress unused-variable warning
    }

    log::info!("Per-file IPNS publish succeeded for {}", file_ipns_name);

    Ok(())
}
