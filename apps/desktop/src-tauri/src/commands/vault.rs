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

    // Derive IPNS keypair deterministically via HKDF from user's private key
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
    let (ipns_private_key, _ipns_public_key, root_ipns_name) =
        crypto::hkdf::derive_vault_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault IPNS derivation failed: {:?}", e))?;

    // ECIES-wrap keys with user's uncompressed secp256k1 public key
    let encrypted_root_folder_key = crypto::ecies::wrap_key(&root_folder_key, public_key)
        .map_err(|e| format!("Failed to wrap root folder key: {}", e))?;
    let encrypted_ipns_private_key = crypto::ecies::wrap_key(&ipns_private_key, public_key)
        .map_err(|e| format!("Failed to wrap IPNS private key: {}", e))?;

    // 1. Register vault with backend
    let init_req = types::InitVaultRequest {
        owner_public_key: hex::encode(public_key),
        encrypted_root_folder_key: hex::encode(&encrypted_root_folder_key),
        encrypted_root_ipns_private_key: hex::encode(&encrypted_ipns_private_key),
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

    // 2. Create and publish initial empty folder metadata
    //    Without this, FUSE init() can't resolve the root IPNS name.
    log::info!("Publishing initial empty root folder metadata");

    let empty_metadata = crypto::folder::FolderMetadata {
        version: "v2".to_string(),
        children: vec![],
    };

    // Encrypt metadata with root folder key
    let folder_key_arr: [u8; 32] = root_folder_key
        .try_into()
        .map_err(|_| "Invalid root folder key length".to_string())?;
    let sealed = crypto::folder::encrypt_folder_metadata(&empty_metadata, &folder_key_arr)
        .map_err(|e| format!("Metadata encryption failed: {}", e))?;

    // Format as JSON { "iv": "<hex>", "data": "<base64>" }
    let iv_hex = hex::encode(&sealed[..12]);
    use base64::Engine;
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
    let json_metadata = serde_json::json!({
        "iv": iv_hex,
        "data": data_base64,
    });
    let json_bytes = serde_json::to_vec(&json_metadata)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;

    // Upload encrypted metadata to IPFS
    let initial_cid = crate::api::ipfs::upload_content(&state.api, &json_bytes).await?;

    // Create and sign IPNS record (sequence 0, 24h lifetime)
    let ipns_key_arr: [u8; 32] = ipns_private_key.as_slice()
        .try_into()
        .map_err(|_| "Invalid IPNS private key length".to_string())?;
    let value = format!("/ipfs/{}", initial_cid);
    let record = crypto::ipns::create_ipns_record(&ipns_key_arr, &value, 0, 86_400_000)
        .map_err(|e| format!("IPNS record creation failed: {}", e))?;
    let marshaled = crypto::ipns::marshal_ipns_record(&record)
        .map_err(|e| format!("IPNS record marshaling failed: {}", e))?;
    let record_base64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

    // Publish IPNS record via backend (sequence 0 - first ever publish, no conflict check needed)
    let publish_req = crate::api::ipns::IpnsPublishRequest {
        ipns_name: root_ipns_name.clone(),
        record: record_base64,
        metadata_cid: initial_cid,
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: None,
    };
    match crate::api::ipns::publish_ipns(&state.api, &publish_req).await? {
        crate::api::ipns::PublishResult::Success => {}
        crate::api::ipns::PublishResult::Conflict { .. } => {
            // Sequence 0 should never conflict on vault init -- log and continue
            log::warn!("Unexpected conflict on vault init publish (sequence 0)");
        }
    }

    log::info!("Vault initialized and root metadata published for new user");
    Ok(())
}

/// Fetch vault keys from backend and decrypt them using the user's private key.
///
/// Decrypts:
/// - Root folder AES-256 key (32 bytes) from ECIES-wrapped hex
/// - Root IPNS Ed25519 private key (32 bytes) from ECIES-wrapped hex
///
/// The IPNS public key is derivable from the private key if ever needed.
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

    // Get private key for decryption
    let private_key = state
        .private_key
        .read()
        .await
        .as_ref()
        .ok_or("Private key not available for vault decryption")?
        .clone();

    // Decrypt root folder key
    let encrypted_root_folder_key = hex::decode(&vault.encrypted_root_folder_key)
        .map_err(|_| "Invalid encryptedRootFolderKey hex")?;
    let root_folder_key = crypto::ecies::unwrap_key(&encrypted_root_folder_key, &private_key)
        .map_err(|e| format!("Failed to decrypt root folder key: {}", e))?;
    *state.root_folder_key.write().await = Some(root_folder_key);

    // Decrypt root IPNS private key
    let encrypted_root_ipns_private_key = hex::decode(&vault.encrypted_root_ipns_private_key)
        .map_err(|_| "Invalid encryptedRootIpnsPrivateKey hex")?;
    let root_ipns_private_key =
        crypto::ecies::unwrap_key(&encrypted_root_ipns_private_key, &private_key)
            .map_err(|e| format!("Failed to decrypt root IPNS private key: {}", e))?;

    // Verify stored IPNS key matches HKDF derivation (consistency check)
    let private_key_arr: [u8; 32] = private_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid private key length for HKDF check")?;
    if let Ok((expected_ipns_key, _, _)) = crypto::hkdf::derive_vault_ipns_keypair(&private_key_arr) {
        if root_ipns_private_key != *expected_ipns_key {
            log::warn!("Vault IPNS key mismatch: stored key differs from HKDF derivation");
            // Don't block - proceed with stored key for backward compatibility
        }
    }

    *state.root_ipns_private_key.write().await = Some(root_ipns_private_key);

    // Store IPNS name and TEE keys
    *state.root_ipns_name.write().await = Some(vault.root_ipns_name);
    *state.tee_keys.write().await = vault.tee_keys;

    log::info!("Vault keys decrypted and stored in memory");
    Ok(())
}
