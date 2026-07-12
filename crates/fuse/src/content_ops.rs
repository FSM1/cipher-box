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
/// (CID, IV, size, encryption mode) WITHOUT downloading the content.
///
/// Used by the FilePointer-resolution path: an unresolved File inode (empty CID)
/// is resolved by fetching its own node and unsealing the read-body. Returns
/// `(cid, file_iv, size, encryption_mode)` where `file_iv` is the wire value
/// (BASE64) stored into the inode's display-only `iv` field (never decoded for
/// crypto — content decrypt re-reads `content.file_iv` from the fresh node).
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
    use base64::Engine as _;
    // Recover the file node's content descriptor by SYMMETRIC unseal of its own
    // read-body (node/v3, SC#1) — never ECIES.
    let mut content = unseal_file_content(published, read_key)?;

    // SC2 item 4: `content.file_key` is a locally-owned plaintext copy from the
    // unseal. Narrow it into the Zeroizing working buffer, then scrub the copy
    // inside `content` so no later path (fetch/decrypt errors included) holds an
    // un-zeroed key. On a length error, scrub before surfacing the error too.
    let file_key_arr = match zeroizing_32_from_slice(&content.file_key, "Invalid file key length") {
        Ok(k) => k,
        Err(e) => {
            cipherbox_crypto::utils::clear_bytes(&mut content.file_key);
            return Err(e);
        }
    };
    cipherbox_crypto::utils::clear_bytes(&mut content.file_key);

    let encrypted_bytes = cipherbox_api_client::ipfs::fetch_content(api, &content.cid)
        .await
        .map_err(|e| e.to_string())?;

    // NodeContent.file_iv is BASE64 on the wire (the shipped TS/web read chain —
    // sdk-core downloadFileContent — does base64ToBytes(fileIv)). Decode as base64,
    // never hex: a hex-decoded IV would yield the wrong bytes and fail the GCM tag.
    let plaintext = if content.encryption_mode == "CTR" {
        let iv = base64::engine::general_purpose::STANDARD
            .decode(&content.file_iv)
            .map_err(|_| "Invalid file IV base64".to_string())?;
        let iv_arr: [u8; 16] = iv
            .try_into()
            .map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
        cipherbox_crypto::aes_ctr::decrypt_aes_ctr(&encrypted_bytes, &file_key_arr, &iv_arr)
            .map_err(|e| format!("CTR decryption failed: {}", e))?
    } else {
        let iv = base64::engine::general_purpose::STANDARD
            .decode(&content.file_iv)
            .map_err(|_| "Invalid file IV base64".to_string())?;
        let iv_arr: [u8; 12] = iv
            .try_into()
            .map_err(|_| "Invalid GCM IV length (expected 12)".to_string())?;
        cipherbox_crypto::aes::decrypt_aes_gcm(&encrypted_bytes, &file_key_arr, &iv_arr)
            .map_err(|e| format!("GCM decryption failed: {}", e))?
    };
    Ok(plaintext)
}

/// Live per-file node/v3 publish (69-09 Slice 5b(c)).
///
/// The single per-file publish path on the node model: re-seals the file's OWN
/// `PublishedNode` with the now-known content `cid` (the journal-time seal used
/// an empty-CID placeholder), uploads the sealed envelope to IPFS, and publishes
/// the file's per-file IPNS record pointing at the envelope CID.
///
/// Two publish tails:
/// - `is_first_publish` (fresh file): publish at sequence 1 with
///   `expected_sequence_number: None` and TEE enrollment (the pre-wrapped
///   `encrypted_ipns_for_tee`, rule #7). A `Conflict` means another client raced
///   → `Err` → EIO.
/// - update (overwrite): route through the shared CAS helper
///   [`crate::metadata::publish_with_cas_retry`] (no TEE re-enroll).
///
/// This is the only per-file publish path in the default build; the legacy
/// per-file metadata publish was removed in the D-04 core cutover. D-09:
/// `read_key`/`write_key` are caller-owned borrows; the raw `file_key` is moved
/// into `NodeContent.file_key` (sealed inside the read-body, never ECIES).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
pub async fn publish_file_node(
    api: &cipherbox_api_client::ApiClient,
    file_ipns_name: &str,
    child_id: &str,
    cid: &str,
    file_key: &[u8],
    iv_hex: &str,
    size: u64,
    mime_type: &str,
    encryption_mode: &str,
    read_key: &[u8; 32],
    write_key: &[u8; 32],
    ipns_private_key: &zeroize::Zeroizing<Vec<u8>>,
    coordinator: &crate::PublishCoordinator,
    encrypted_ipns_for_tee: Option<&str>,
    tee_key_epoch: Option<u32>,
    is_first_publish: bool,
) -> Result<(), String> {
    use base64::Engine as _;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // 1. Re-seal the file node with the real content CID.
    // NodeContent.file_iv is BASE64 on the wire — the shipped TS/web read chain
    // (sdk-core downloadFileContent) does base64ToBytes(fileIv). The mount threads
    // the IV as hex internally (`iv_hex`); convert to base64 at this wire boundary
    // so a cross-client TS reader recovers the correct 12-byte IV. (Publishing hex
    // here makes the reader decode 24 hex chars as base64 -> 18 wrong bytes ->
    // AES-GCM "Decryption failed" — the D-07 desktop-e2e cross-client failure.)
    let file_iv_b64 = base64::engine::general_purpose::STANDARD
        .encode(hex::decode(iv_hex).map_err(|_| "Invalid file IV hex".to_string())?);
    let node_content = cipherbox_core::node::NodeContent {
        cid: cid.to_string(),
        file_iv: file_iv_b64,
        size,
        mime_type: mime_type.to_string(),
        encryption_mode: encryption_mode.to_string(),
        file_key: file_key.to_vec(),
        versions: Vec::new(),
    };
    // D-09: `file_key`/`ipns_private_key` are caller-owned borrows and are NEVER
    // zeroed here. `node_content.file_key` (via `.to_vec()`) and
    // `write_body.ipns_private_key` (via `.to_vec()`) are LOCALLY-owned plaintext
    // copies — those are the buffers scrubbed after sealing (SC2 item 4).
    let mut file_node = cipherbox_core::node::Node::File {
        id: child_id.to_string(),
        generation: 0,
        created_at: now_ms,
        modified_at: now_ms,
        content: node_content,
    };
    let mut write_body = cipherbox_core::node::NodeWriteBody {
        ipns_private_key: ipns_private_key.to_vec(),
        write_children: Vec::new(),
        recipient_pins: Vec::new(),
    };
    let seal_result = cipherbox_core::node::seal::seal_published_node(
        &file_node,
        read_key,
        write_key,
        Some(&write_body),
    );
    // Sealing has consumed the borrows — scrub the locally-owned plaintext key
    // copies now, so success AND every error path below drops zeroed buffers.
    if let cipherbox_core::node::Node::File { content, .. } = &mut file_node {
        cipherbox_crypto::utils::clear_bytes(&mut content.file_key);
    }
    cipherbox_crypto::utils::clear_bytes(&mut write_body.ipns_private_key);
    let published = seal_result.map_err(|e| format!("File node seal failed: {}", e))?;
    let published_bytes = cipherbox_core::node::encode_published_node(&published)
        .map_err(|e| format!("File node encode failed: {}", e))?;

    // 2. Upload the sealed node envelope to IPFS.
    let node_cid = cipherbox_api_client::ipfs::upload_content(api, &published_bytes)
        .await
        .map_err(|e| e.to_string())?;

    // 3. Publish the per-file IPNS record → /ipfs/<node envelope CID>.
    let ipns_key_arr = zeroizing_32_from_slice(
        ipns_private_key.as_slice(),
        "Invalid file IPNS private key length",
    )?;
    let value = format!("/ipfs/{}", node_cid);

    // `is_first_publish` is the caller's release-time HINT (the file inode had an
    // empty CID; see read_ops.rs). A dropped UploadComplete (write_generation
    // mismatch, fs.rs) or a duplicated/deferred FUSE-T release can leave that hint
    // set AFTER the per-file record already exists at seq 1. Re-running the seq-1
    // tail re-seals a FRESH node envelope (created_at/modified_at = now_ms changes
    // each call → a new envelope CID), and the API anti-equivocation gate
    // (Phase 71 D-05) rejects a same-sequence republish with a different CID (400).
    // Confirm the record is genuinely absent before taking the first-publish
    // (seq 1 + TEE enroll) tail; if it already resolves, the content still needs
    // to be published, so fall through to the sequence-bumping CAS branch instead
    // (cf. replay.rs::publish_child_node's resolve-first guard, which skips because
    // replay has nothing new to publish — here we do).
    // On the `Found` path we keep the resolved sequence so the CAS branch below can
    // reuse it instead of resolving the same name a second time.
    let (do_first_publish, resolved_seq) = if is_first_publish {
        match crate::publish::resolve_ipns_for_replay(coordinator, api, file_ipns_name).await {
            crate::error::IpnsResolveOutcome::NotFound => (true, None),
            crate::error::IpnsResolveOutcome::Found(seq) => (false, Some(seq)),
            crate::error::IpnsResolveOutcome::Error(e) => {
                return Err(format!(
                    "resolve before per-file first-publish for {}: {} \
                     — refusing to risk a seq-1 equivocation",
                    file_ipns_name, e
                ));
            }
        }
    } else {
        (false, None)
    };

    if do_first_publish {
        // First publish: no prior record → seq 1, expected None, TEE enroll.
        let (enc_tee, epoch) = match (encrypted_ipns_for_tee, tee_key_epoch) {
            (Some(h), Some(e)) => (Some(h.to_string()), Some(e)),
            (Some(_), None) => {
                return Err("TEE wrap present but key_epoch missing".to_string());
            }
            (None, Some(_)) => {
                return Err("TEE key_epoch present but wrap missing".to_string());
            }
            (None, None) => (None, None),
        };
        let record = cipherbox_core::ipns::create_ipns_record(&ipns_key_arr, &value, 1, 86_400_000)
            .map_err(|e| format!("File node IPNS record creation failed: {}", e))?;
        let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
            .map_err(|e| format!("File node IPNS record marshal failed: {}", e))?;
        let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
        let req = cipherbox_api_client::IpnsPublishRequest {
            ipns_name: file_ipns_name.to_string(),
            record: record_b64,
            metadata_cid: node_cid.clone(),
            encrypted_ipns_private_key: enc_tee,
            key_epoch: epoch,
            expected_sequence_number: None,
        };
        match cipherbox_api_client::ipns::publish_ipns(api, &req)
            .await
            .map_err(|e| e.to_string())?
        {
            cipherbox_api_client::PublishResult::Success => {}
            cipherbox_api_client::PublishResult::Conflict { .. } => {
                return Err(format!(
                    "Conflict on first per-file node publish for {} — another client raced",
                    file_ipns_name
                ));
            }
        }
        coordinator.record_publish(file_ipns_name, 1);
    } else {
        // Update publish: CAS via the shared helper (D-02 / D-03). Re-sign the
        // SAME node envelope CID at each attempted sequence.
        let node_cid_for_closure = node_cid.clone();
        let ipns_key_ref = &ipns_key_arr;
        crate::metadata::publish_with_cas_retry(
            api,
            coordinator,
            file_ipns_name,
            resolved_seq,
            |new_seq_for_record: u64| {
                let value = format!("/ipfs/{}", node_cid_for_closure);
                let record = cipherbox_core::ipns::create_ipns_record(
                    ipns_key_ref,
                    &value,
                    new_seq_for_record,
                    86_400_000,
                )
                .map_err(|e| format!("File node IPNS record creation failed on retry: {}", e))?;
                let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
                    .map_err(|e| format!("File node IPNS record marshal failed on retry: {}", e))?;
                let retry_record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
                Ok((retry_record_b64, node_cid_for_closure.clone()))
            },
            &[],
            None, // D-01a: no JournalOp::FilePublish variant; exhaustion → Err → EIO
            2,    // preserve today's single-retry (2-attempt) per-file behavior
        )
        .await?;
    }

    log::info!("Per-file node/v3 publish succeeded for {}", file_ipns_name);

    Ok(())
}
