//! Vault initialization and decryption commands.

use crate::api::types;
use crate::crypto;
use crate::state::AppState;

/// Initialize a new vault for a first-time user.
///
/// Generates a root folder AES-256 key and derives a deterministic Ed25519 IPNS
/// keypair via HKDF from the user's private key. ECIES-wraps them with the
/// user's secp256k1 public key, and POSTs everything to `/vault/init`.
pub(crate) async fn initialize_vault(state: &AppState, public_key: &[u8]) -> Result<(), String> {
    // Generate root folder AES-256 key (32 random bytes)
    let root_folder_key = crypto::utils::generate_random_bytes(32);

    // Derive IPNS keypairs from user's private key
    let private_key = state
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
        crypto::hkdf::derive_vault_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault IPNS derivation failed: {:?}", e))?;

    // Vault key IPNS keypair (for rootFolderKey blob — separate IPNS name)
    let (vault_key_ipns_private, _vault_key_ipns_public, vault_key_ipns_name) =
        crypto::hkdf::derive_vault_key_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault key IPNS derivation failed: {:?}", e))?;

    // ECIES-wrap rootFolderKey for v2 blob header
    let encrypted_root_folder_key = crypto::ecies::wrap_key(&root_folder_key, public_key)
        .map_err(|e| format!("Failed to wrap root folder key: {}", e))?;

    log::info!("Publishing vault key blob and root folder metadata");

    let empty_metadata = crypto::folder::FolderMetadata {
        version: "v2".to_string(),
        children: vec![],
    };

    let folder_key_arr: [u8; 32] = root_folder_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid root folder key length".to_string())?;
    let sealed = crypto::folder::encrypt_folder_metadata(&empty_metadata, &folder_key_arr)
        .map_err(|e| format!("Metadata encryption failed: {}", e))?;

    use base64::Engine;
    let iv_hex = hex::encode(&sealed[..12]);
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
    let json_metadata = serde_json::json!({
        "iv": iv_hex,
        "data": data_base64,
    });
    let json_bytes = serde_json::to_vec(&json_metadata)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;

    // 1. Publish v2 key blob to vault key IPNS (rootFolderKey storage)
    let blob_bytes =
        crypto::vault_blob::serialize_vault_blob_v2(&encrypted_root_folder_key, &json_bytes)?;
    let key_blob_cid = crate::api::ipfs::upload_content(&state.api, &blob_bytes).await?;

    let vault_key_ipns_arr: [u8; 32] = vault_key_ipns_private.as_slice()
        .try_into()
        .map_err(|_| "Invalid vault key IPNS private key length".to_string())?;
    let key_value = format!("/ipfs/{}", key_blob_cid);
    let key_record = crypto::ipns::create_ipns_record(&vault_key_ipns_arr, &key_value, 0, 86_400_000)
        .map_err(|e| format!("IPNS record creation failed: {}", e))?;
    let key_marshaled = crypto::ipns::marshal_ipns_record(&key_record)
        .map_err(|e| format!("IPNS record marshaling failed: {}", e))?;
    let key_record_base64 = base64::engine::general_purpose::STANDARD.encode(&key_marshaled);

    let key_publish_req = crate::api::ipns::IpnsPublishRequest {
        ipns_name: vault_key_ipns_name,
        record: key_record_base64,
        metadata_cid: key_blob_cid,
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: None,
    };
    match crate::api::ipns::publish_ipns(&state.api, &key_publish_req).await? {
        crate::api::ipns::PublishResult::Success => {}
        crate::api::ipns::PublishResult::Conflict { .. } => {
            log::warn!("Unexpected conflict on vault key blob publish (sequence 0)");
        }
    }

    // 2. Publish v1 folder metadata to root folder IPNS (standard folder format)
    let folder_cid = crate::api::ipfs::upload_content(&state.api, &json_bytes).await?;

    let root_ipns_arr: [u8; 32] = root_ipns_private_key.as_slice()
        .try_into()
        .map_err(|_| "Invalid root IPNS private key length".to_string())?;
    let folder_value = format!("/ipfs/{}", folder_cid);
    let folder_record = crypto::ipns::create_ipns_record(&root_ipns_arr, &folder_value, 0, 86_400_000)
        .map_err(|e| format!("IPNS record creation failed: {}", e))?;
    let folder_marshaled = crypto::ipns::marshal_ipns_record(&folder_record)
        .map_err(|e| format!("IPNS record marshaling failed: {}", e))?;
    let folder_record_base64 = base64::engine::general_purpose::STANDARD.encode(&folder_marshaled);

    let folder_publish_req = crate::api::ipns::IpnsPublishRequest {
        ipns_name: root_ipns_name.clone(),
        record: folder_record_base64,
        metadata_cid: folder_cid,
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: None,
    };
    match crate::api::ipns::publish_ipns(&state.api, &folder_publish_req).await? {
        crate::api::ipns::PublishResult::Success => {}
        crate::api::ipns::PublishResult::Conflict { .. } => {
            log::warn!("Unexpected conflict on root folder publish (sequence 0)");
        }
    }

    // 3. Register vault with backend AFTER both IPNS records are durable
    let init_req = types::InitVaultRequest {
        owner_public_key: hex::encode(public_key),
        root_ipns_name: root_ipns_name.clone(),
    };

    let resp = state
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
        .api
        .authenticated_get("/vault")
        .await
        .map_err(|e| format!("Vault fetch failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Vault fetch failed ({}): {}", status, body));
    }

    let vault: types::VaultResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse vault response: {}", e))?;

    // Get private key
    let private_key = state
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
        crypto::hkdf::derive_vault_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("HKDF derivation failed: {:?}", e))?;

    // Derive vault key IPNS keypair (for rootFolderKey blob)
    let (_vault_key_priv, _vault_key_pub, vault_key_ipns_name) =
        crypto::hkdf::derive_vault_key_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault key HKDF derivation failed: {:?}", e))?;

    // Resolve vault key IPNS, fetch v2 blob, extract rootFolderKey
    let resolved = crate::api::ipns::resolve_ipns(&state.api, &vault_key_ipns_name)
        .await
        .map_err(|e| format!("Vault key IPNS resolve failed: {}", e))?;
    let blob_bytes = crate::api::ipfs::fetch_content(&state.api, &resolved.cid)
        .await
        .map_err(|e| format!("IPFS fetch failed for vault key blob: {}", e))?;

    if crypto::vault_blob::detect_blob_version(&blob_bytes) != 2 {
        return Err("Vault key blob is not v2 format".into());
    }
    let (enc_key, _meta) = crypto::vault_blob::deserialize_vault_blob_v2(&blob_bytes)
        .map_err(|e| format!("v2 blob parse failed: {}", e))?;
    let root_folder_key = crypto::ecies::unwrap_key(enc_key, &private_key)
        .map_err(|e| format!("Failed to decrypt rootFolderKey from v2 blob: {}", e))?;

    *state.root_folder_key.write().await = Some(root_folder_key);

    // Root folder IPNS key is HKDF-derived
    *state.root_ipns_private_key.write().await = Some(root_ipns_priv.to_vec());

    // Store IPNS name and TEE keys
    *state.root_ipns_name.write().await = Some(vault.root_ipns_name);
    *state.tee_keys.write().await = vault.tee_keys;

    log::info!("Vault keys decrypted and stored in memory");
    Ok(())
}
