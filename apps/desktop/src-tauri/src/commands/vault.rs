//! Vault initialization and decryption commands.

use crate::state::AppState;
use zeroize::Zeroizing;

/// Derive the node/v3 root read/write keys from the legacy `root_folder_key`,
/// byte-matching the desktop mount bridge in
/// `apps/desktop/src-tauri/src/fuse/mod.rs:192-205` so a freshly-created vault
/// is readable/writable at first mount.
///
/// PHASE-63 COUPLING (temporary placeholder): the real node/v3 root read/write
/// keys are minted server-side at registration (sdk-core `registration.ts`
/// `rootReadKey`/`rootWriteKey`) and recovered into the client key state at
/// login. Until that recovery is wired into the desktop runtime (phase 63),
/// BOTH create (here) and mount (mod.rs:192-205) bridge from `root_folder_key`:
/// `read_key` = the first 32 bytes; `write_key` = `read_key` with every byte
/// XOR 0xA5. These two derivations MUST stay byte-identical — changing one
/// without the other silently breaks create/mount consistency.
fn derive_root_node_keys(
    root_folder_key: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    // read_key: reuse the 32-byte root folder key (mount bridge mod.rs:192-198).
    let read_key: Zeroizing<[u8; 32]> = {
        let mut k = [0u8; 32];
        let src = root_folder_key;
        let n = src.len().min(32);
        k[..n].copy_from_slice(&src[..n]);
        Zeroizing::new(k)
    };
    // write_key: domain-separated placeholder transform (mount bridge mod.rs:199-205).
    let write_key: Zeroizing<[u8; 32]> = {
        let mut k = *read_key;
        for b in k.iter_mut() {
            *b ^= 0xA5;
        }
        Zeroizing::new(k)
    };
    Ok((read_key, write_key))
}

/// Build an empty node/v3 ROOT node (no children) sealed under the given root
/// read/write keys, returning the `encode_published_node` envelope bytes.
///
/// Pure / no-IO. Mirrors the `crates/sdk::build_folder_emission` seal path
/// (`seal_published_node(.., Some(&write_body))` → `encode_published_node`) but
/// with DETERMINISTIC keys — the HKDF-derived root IPNS signing seed and the
/// mount-bridge root read/write keys — instead of the minted random keys
/// `build_folder_emission` uses, so create and mount agree on the root keys.
///
/// Terminal-owner (D-09): the caller owns the key buffers; this helper only
/// borrows them into the seal and never zeroes caller-owned material.
fn build_empty_root_published_node(
    root_read_key: &[u8; 32],
    root_write_key: &[u8; 32],
    root_ipns_private_key: &[u8],
) -> Result<Vec<u8>, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let root_node = cipherbox_core::node::Node::Root {
        id: cipherbox_crypto::utils::generate_uuid_v4(),
        generation: 0,
        created_at: now,
        modified_at: now,
        children: Vec::new(),
    };
    let write_body = cipherbox_core::node::NodeWriteBody {
        ipns_private_key: root_ipns_private_key.to_vec(),
        write_children: Vec::new(),
    };
    let published = cipherbox_core::node::seal::seal_published_node(
        &root_node,
        root_read_key,
        root_write_key,
        Some(&write_body),
    )
    .map_err(|e| format!("root node seal failed: {}", e))?;
    cipherbox_core::node::encode_published_node(&published)
        .map_err(|e| format!("root node encode failed: {}", e))
}

/// Load user-configurable vault settings from encrypted IPNS entry.
///
/// Pattern: derive IPNS keypair -> resolve IPNS -> fetch IPFS -> ECIES unwrap -> parse JSON -> validate.
/// Returns default settings on any failure (IPNS not found, decrypt error, parse error).
/// Per D-03 and D-05: graceful fallback, desktop is read-only for settings.
pub(crate) async fn load_vault_settings(
    api: &std::sync::Arc<cipherbox_api_client::ApiClient>,
    private_key: &[u8; 32],
) -> cipherbox_core::VaultSettings {
    let result: Result<cipherbox_core::VaultSettings, String> =
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (_priv_key, _pub_key, ipns_name) =
                cipherbox_crypto::hkdf::derive_vault_settings_ipns_keypair(private_key)
                    .map_err(|e| format!("HKDF derivation failed: {:?}", e))?;

            // D-09: route through verified chokepoint — fail-closed on tampered settings.
            let resolved =
                match cipherbox_api_client::ipns::resolve_ipns_verified(api, &ipns_name).await {
                    Ok(v) => v,
                    Err(cipherbox_api_client::ipns::VerifyError::Api(e)) => {
                        return Err(format!("IPNS resolve failed: {}", e));
                    }
                    Err(cipherbox_api_client::ipns::VerifyError::Invalid(msg)) => {
                        log::error!(
                            "Vault settings IPNS {} verify failed (D-09): {}",
                            ipns_name,
                            msg
                        );
                        return Err(format!("IPNS verification failed: {}", msg));
                    }
                };

            let encrypted = cipherbox_api_client::ipfs::fetch_content(api, &resolved.cid)
                .await
                .map_err(|e| format!("IPFS fetch failed: {}", e))?;

            // NOT AES-GCM — vault settings use ECIES wrapKey
            let plaintext = cipherbox_crypto::ecies::unwrap_key(&encrypted, private_key)
                .map_err(|e| format!("ECIES unwrap failed: {:?}", e))?;

            let parsed: serde_json::Value = serde_json::from_slice(&plaintext)
                .map_err(|e| format!("JSON parse failed: {}", e))?;

            Ok(cipherbox_core::validate_vault_settings(&parsed))
        })
        .await
        .unwrap_or_else(|_| Err("vault settings load timed out after 10s".to_string()));

    match result {
        Ok(settings) => {
            log::info!(
                "Vault settings loaded: maxVersions={}, cooldown={}min, retention={}d, delete={:?}",
                settings.max_versions_per_file,
                settings.version_cooldown_minutes,
                settings.recycle_bin_retention_days,
                settings.delete_behavior
            );
            settings
        }
        Err(e) => {
            log::warn!("Vault settings load failed (using defaults): {}", e);
            cipherbox_core::default_vault_settings()
        }
    }
}

/// Initialize a new vault for a first-time user.
///
/// Generates a root folder AES-256 key and derives a deterministic Ed25519 IPNS
/// keypair via HKDF from the user's private key. ECIES-wraps them with the
/// user's secp256k1 public key, and POSTs everything to `/vault/init`.
pub(crate) async fn initialize_vault(state: &AppState, public_key: &[u8]) -> Result<(), String> {
    // Generate root folder AES-256 key (32 random bytes)
    let root_folder_key = cipherbox_crypto::utils::generate_random_bytes(32);

    // Derive IPNS keypairs from user's private key
    let private_key = state
        .sdk
        .private_key
        .read()
        .await
        .as_ref()
        .ok_or("Private key not available for vault IPNS derivation")?
        .clone();
    let private_key_arr: [u8; 32] = private_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid private key length")?;

    // Root folder IPNS keypair (for folder metadata)
    let (root_ipns_private_key, _root_ipns_public_key, root_ipns_name) =
        cipherbox_crypto::hkdf::derive_vault_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault IPNS derivation failed: {:?}", e))?;

    // Vault key IPNS keypair (for rootFolderKey blob — separate IPNS name)
    let (vault_key_ipns_private, _vault_key_ipns_public, vault_key_ipns_name) =
        cipherbox_crypto::hkdf::derive_vault_key_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault key IPNS derivation failed: {:?}", e))?;

    // ECIES-wrap rootFolderKey for v2 blob header
    let encrypted_root_folder_key = cipherbox_crypto::ecies::wrap_key(&root_folder_key, public_key)
        .map_err(|e| format!("Failed to wrap root folder key: {}", e))?;

    log::info!("Publishing vault key blob and root folder metadata");

    use base64::Engine;

    // 1. Publish v2 key blob to vault key IPNS (key only, no metadata)
    let blob_bytes =
        cipherbox_core::vault_blob::serialize_vault_blob_v2(&encrypted_root_folder_key)?;
    let key_blob_cid = cipherbox_api_client::ipfs::upload_content(&state.sdk.api, &blob_bytes)
        .await
        .map_err(|e| e.to_string())?;

    let vault_key_ipns_arr: [u8; 32] = vault_key_ipns_private
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid vault key IPNS private key length".to_string())?;
    let key_value = format!("/ipfs/{}", key_blob_cid);
    let key_record =
        cipherbox_core::ipns::create_ipns_record(&vault_key_ipns_arr, &key_value, 1, 86_400_000)
            .map_err(|e| format!("IPNS record creation failed: {}", e))?;
    let key_marshaled = cipherbox_core::ipns::marshal_ipns_record(&key_record)
        .map_err(|e| format!("IPNS record marshaling failed: {}", e))?;
    let key_record_base64 = base64::engine::general_purpose::STANDARD.encode(&key_marshaled);

    let key_publish_req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: vault_key_ipns_name,
        record: key_record_base64,
        metadata_cid: key_blob_cid,
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: None,
    };
    match cipherbox_api_client::ipns::publish_ipns(&state.sdk.api, &key_publish_req)
        .await
        .map_err(|e| e.to_string())?
    {
        cipherbox_api_client::PublishResult::Success => {}
        cipherbox_api_client::PublishResult::Conflict { .. } => {
            log::warn!("Unexpected conflict on vault key blob publish (sequence 1); aborting vault initialization to avoid mismatched root_folder_key");
            return Err(
                "Vault initialization aborted due to existing vault key IPNS record".to_string(),
            );
        }
    }

    // 2. Publish folder metadata using v1 encrypted envelope format on IPFS ({iv, data});
    //    FolderMetadata.version remains "v2" (metadata schema version).
    let empty_metadata = cipherbox_core::folder::FolderMetadata {
        version: "v2".to_string(),
        children: vec![],
    };
    let folder_key_arr: [u8; 32] = root_folder_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid root folder key length".to_string())?;
    let sealed = cipherbox_core::folder::encrypt_folder_metadata(&empty_metadata, &folder_key_arr)
        .map_err(|e| format!("Metadata encryption failed: {}", e))?;
    let iv_hex = hex::encode(&sealed[..12]);
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
    let json_metadata = serde_json::json!({ "iv": iv_hex, "data": data_base64 });
    let json_bytes = serde_json::to_vec(&json_metadata)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;
    let folder_cid = cipherbox_api_client::ipfs::upload_content(&state.sdk.api, &json_bytes)
        .await
        .map_err(|e| e.to_string())?;

    let root_ipns_arr: [u8; 32] = root_ipns_private_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid root IPNS private key length".to_string())?;
    let folder_value = format!("/ipfs/{}", folder_cid);
    let folder_record =
        cipherbox_core::ipns::create_ipns_record(&root_ipns_arr, &folder_value, 1, 86_400_000)
            .map_err(|e| format!("IPNS record creation failed: {}", e))?;
    let folder_marshaled = cipherbox_core::ipns::marshal_ipns_record(&folder_record)
        .map_err(|e| format!("IPNS record marshaling failed: {}", e))?;
    let folder_record_base64 = base64::engine::general_purpose::STANDARD.encode(&folder_marshaled);

    let folder_publish_req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: root_ipns_name.clone(),
        record: folder_record_base64,
        metadata_cid: folder_cid,
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: None,
    };
    match cipherbox_api_client::ipns::publish_ipns(&state.sdk.api, &folder_publish_req)
        .await
        .map_err(|e| e.to_string())?
    {
        cipherbox_api_client::PublishResult::Success => {}
        cipherbox_api_client::PublishResult::Conflict { .. } => {
            log::warn!("Unexpected conflict on root folder publish (sequence 1); aborting vault initialization to avoid inconsistent state");
            return Err(
                "Vault initialization aborted due to existing root folder IPNS record".to_string(),
            );
        }
    }

    // 3. Register vault with backend AFTER both IPNS records are durable
    let init_req = cipherbox_api_client::InitVaultRequest {
        owner_public_key: hex::encode(public_key),
        root_ipns_name: root_ipns_name.clone(),
    };

    let resp = state
        .sdk
        .api
        .authenticated_post("/vault/init", &init_req)
        .await
        .map_err(|e| format!("Vault init request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Vault init failed ({}): {}", status, body));
    }

    log::info!("Vault initialized: key blob + root metadata published for new user");
    Ok(())
}

/// Fetch vault from backend and decrypt rootFolderKey from IPFS v2 blob.
///
/// All users read rootFolderKey from the IPFS vault blob v2 header.
/// The IPNS keypair is always HKDF-derived from the user's private key.
/// Stores all keys in AppState (memory only).
pub(crate) async fn fetch_and_decrypt_vault(state: &AppState) -> Result<(), String> {
    log::info!("Fetching and decrypting vault keys");

    // GET /vault
    let resp = state
        .sdk
        .api
        .authenticated_get("/vault")
        .await
        .map_err(|e| format!("Vault fetch failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Vault fetch failed ({}): {}", status, body));
    }

    let vault: cipherbox_api_client::VaultResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse vault response: {}", e))?;

    // Get private key
    let private_key = state
        .sdk
        .private_key
        .read()
        .await
        .as_ref()
        .ok_or("Private key not available for vault decryption")?
        .clone();
    let private_key_arr: [u8; 32] = private_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid private key length")?;

    // Derive root folder IPNS keypair (for folder operations)
    let (root_ipns_priv, _root_ipns_pub, _root_ipns_name) =
        cipherbox_crypto::hkdf::derive_vault_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("HKDF derivation failed: {:?}", e))?;

    // Derive vault key IPNS keypair (for rootFolderKey blob)
    let (_vault_key_priv, _vault_key_pub, vault_key_ipns_name) =
        cipherbox_crypto::hkdf::derive_vault_key_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault key HKDF derivation failed: {:?}", e))?;

    // D-09: route vault key IPNS through verified chokepoint — tampered blob rejected.
    let resolved = match cipherbox_api_client::ipns::resolve_ipns_verified(
        &state.sdk.api,
        &vault_key_ipns_name,
    )
    .await
    {
        Ok(v) => v,
        Err(cipherbox_api_client::ipns::VerifyError::Api(e)) => {
            return Err(format!("Vault key IPNS resolve failed: {}", e));
        }
        Err(cipherbox_api_client::ipns::VerifyError::Invalid(msg)) => {
            log::error!(
                "Vault key IPNS {} verify failed (D-09): {}",
                vault_key_ipns_name,
                msg
            );
            return Err(format!("Vault key IPNS verification failed: {}", msg));
        }
    };
    let blob_bytes = cipherbox_api_client::ipfs::fetch_content(&state.sdk.api, &resolved.cid)
        .await
        .map_err(|e| format!("IPFS fetch failed for vault key blob: {}", e))?;

    if cipherbox_core::vault_blob::detect_blob_version(&blob_bytes) != 2 {
        return Err("Vault key blob is not v2 format".into());
    }
    let enc_key = cipherbox_core::vault_blob::deserialize_vault_blob_v2(&blob_bytes)
        .map_err(|e| format!("v2 blob parse failed: {}", e))?;
    let root_folder_key = cipherbox_crypto::ecies::unwrap_key(enc_key, &private_key)
        .map_err(|e| format!("Failed to decrypt rootFolderKey from v2 blob: {}", e))?;

    // `unwrap_key` returns `Zeroizing<Vec<u8>>` (Phase 51 S3); the SDK-state field is
    // also `Zeroizing<Vec<u8>>`, so store it directly and keep the key wiped on drop.
    *state.sdk.root_folder_key.write().await = Some(root_folder_key);

    // Root folder IPNS key is HKDF-derived
    *state.sdk.root_ipns_private_key.write().await = Some(root_ipns_priv.to_vec());

    // Store IPNS name and TEE keys
    *state.sdk.root_ipns_name.write().await = Some(vault.root_ipns_name);
    *state.sdk.tee_keys.write().await = vault.tee_keys;

    log::info!("Vault keys decrypted and stored in memory");
    Ok(())
}

#[cfg(test)]
mod root_emit_tests {
    use super::*;
    use base64::Engine as _;

    /// KAT-consistent round-trip for the empty node/v3 root emit helper:
    /// seal+encode → decode envelope → unseal both bodies under the bridge
    /// keys, asserting AAD key separation (read key cannot open the write body).
    #[test]
    fn build_empty_root_published_node_round_trips() {
        let root_folder_key = [0x42u8; 32];
        let root_ipns_seed = [0x11u8; 32];

        let (read_key, write_key) =
            derive_root_node_keys(&root_folder_key).expect("derive root node keys");

        // Bridge byte-match (mod.rs:192-205): read = first 32 bytes; write = read ^ 0xA5.
        assert_eq!(*read_key, root_folder_key);
        let mut expected_write = root_folder_key;
        for b in expected_write.iter_mut() {
            *b ^= 0xA5;
        }
        assert_eq!(*write_key, expected_write);

        let bytes = build_empty_root_published_node(&read_key, &write_key, &root_ipns_seed)
            .expect("build empty root published node");

        // Envelope shape: schema node/v3, kind root, generation 0, both bodies sealed.
        let published =
            cipherbox_core::node::decode_published_node(&bytes).expect("decode published node");
        assert_eq!(published.schema, "node/v3");
        assert_eq!(published.kind, "root");
        assert_eq!(published.generation, 0);
        assert!(
            published.write_sealed.is_some(),
            "write body must be sealed"
        );

        // Read-body unseals under the root read key → empty-children Root.
        let read_sealed = base64::engine::general_purpose::STANDARD
            .decode(&published.read_sealed)
            .expect("valid base64 read_sealed");
        let read_body = cipherbox_core::node::seal::unseal_node(
            &read_sealed,
            &read_key,
            &published.id,
            cipherbox_core::node::NodeKind::Root,
            0,
        )
        .expect("unseal read body under read key");
        match cipherbox_core::node::decode_node(&read_body).expect("decode read-body node") {
            cipherbox_core::node::Node::Root {
                children,
                generation,
                ..
            } => {
                assert!(children.is_empty(), "root has no children");
                assert_eq!(generation, 0);
            }
            other => panic!("expected Node::Root, got {:?}", other),
        }

        // Write-body unseals under the root write key → empty write_children + the ipns seed.
        let write_sealed = base64::engine::general_purpose::STANDARD
            .decode(published.write_sealed.as_ref().unwrap())
            .expect("valid base64 write_sealed");
        let write_body_bytes = cipherbox_core::node::seal::unseal_node(
            &write_sealed,
            &write_key,
            &published.id,
            cipherbox_core::node::NodeKind::Root,
            0,
        )
        .expect("unseal write body under write key");
        let write_body =
            cipherbox_core::node::decode_write_body(&write_body_bytes).expect("decode write body");
        assert!(write_body.write_children.is_empty(), "no write children");
        assert_eq!(write_body.ipns_private_key, root_ipns_seed.to_vec());

        // AAD key separation: the read key must NOT open the write-body seal.
        let opened_with_read = cipherbox_core::node::seal::unseal_node(
            &write_sealed,
            &read_key,
            &published.id,
            cipherbox_core::node::NodeKind::Root,
            0,
        );
        assert!(
            opened_with_read.is_err(),
            "the write-body must not open under the read key (AAD/key separation)"
        );
    }
}
