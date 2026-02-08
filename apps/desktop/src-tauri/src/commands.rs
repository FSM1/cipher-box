//! Tauri IPC commands for the desktop auth flow.
//!
//! These commands are invoked from the webview (TypeScript) via Tauri's
//! `invoke()` API. They handle authentication, vault key decryption,
//! Keychain storage, and logout.

use std::sync::Arc;
use tauri::{Manager, State};

use crate::api::{auth, types};
use crate::crypto;
use crate::state::AppState;

/// Handle completed Web3Auth authentication from the webview.
///
/// Called after the webview has completed the Web3Auth SDK flow and obtained
/// an idToken and the user's secp256k1 private key. This command:
/// 1. Sends idToken to backend to get access + refresh tokens
/// 2. Stores refresh token in macOS Keychain
/// 3. Stores private key and derived public key in AppState (memory only)
/// 4. Fetches and decrypts vault keys (including root IPNS keypair)
#[tauri::command]
pub async fn handle_auth_complete(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id_token: String,
    private_key: String,
) -> Result<(), String> {
    log::info!("Handling auth completion from webview");

    // Update tray status: Mounting (auth in progress, about to mount)
    let _ = crate::tray::update_tray_status(&app, &crate::tray::TrayStatus::Mounting);

    // 1. Convert private key from hex to bytes and derive public key
    //    (needed for the login request)
    let private_key_hex = if private_key.starts_with("0x") {
        &private_key[2..]
    } else {
        &private_key
    };
    let private_key_bytes =
        hex::decode(private_key_hex).map_err(|_| "Invalid private key hex".to_string())?;
    if private_key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }

    // Derive uncompressed public key (65 bytes, 0x04 prefix) from private key
    let public_key_bytes = derive_public_key(&private_key_bytes)?;
    let public_key_hex = hex::encode(&public_key_bytes);

    // 2. Login with backend (requires publicKey and loginType)
    let login_req = types::LoginRequest {
        id_token: id_token.clone(),
        public_key: public_key_hex,
        login_type: "social".to_string(),
    };

    let resp = state
        .api
        .post("/auth/login", &login_req)
        .await
        .map_err(|e| format!("Login request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Login failed ({}): {}", status, body));
    }

    let login_resp: types::LoginResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse login response: {}", e))?;

    // 3. Store access token in API client
    state.api.set_access_token(login_resp.access_token.clone()).await;

    // 4. Extract user ID from JWT claims (decode payload, read `sub`)
    let user_id = extract_user_id_from_jwt(&login_resp.access_token)?;
    *state.user_id.write().await = Some(user_id.clone());

    // 5. Store refresh token in Keychain
    auth::store_refresh_token(&user_id, &login_resp.refresh_token)
        .map_err(|e| format!("Keychain store failed: {}", e))?;
    auth::store_user_id(&user_id)
        .map_err(|e| format!("Keychain store user ID failed: {}", e))?;

    // 6. Store keys in AppState
    *state.private_key.write().await = Some(private_key_bytes);
    *state.public_key.write().await = Some(public_key_bytes);

    // 7. Fetch and decrypt vault keys (including root IPNS keypair)
    fetch_and_decrypt_vault(&state).await?;

    // 8. Mark as authenticated
    *state.is_authenticated.write().await = true;

    // 9. Mount FUSE filesystem
    #[cfg(feature = "fuse")]
    {
        *state.mount_status.write().await = crate::state::MountStatus::Mounting;
        let private_key = state
            .private_key
            .read()
            .await
            .as_ref()
            .ok_or("Private key not available for FUSE mount")?
            .clone();
        let public_key = state
            .public_key
            .read()
            .await
            .as_ref()
            .ok_or("Public key not available for FUSE mount")?
            .clone();
        let root_folder_key = state
            .root_folder_key
            .read()
            .await
            .as_ref()
            .ok_or("Root folder key not available for FUSE mount")?
            .clone();
        let root_ipns_name = state
            .root_ipns_name
            .read()
            .await
            .as_ref()
            .ok_or("Root IPNS name not available for FUSE mount")?
            .clone();
        let root_ipns_private_key = state.root_ipns_private_key.read().await.clone();

        // Extract TEE keys for new folder creation
        let tee_keys = state.tee_keys.read().await;
        let tee_public_key = tee_keys.as_ref().and_then(|tk| {
            hex::decode(&tk.current_public_key).ok()
        });
        let tee_key_epoch = tee_keys.as_ref().map(|tk| tk.current_epoch);
        drop(tee_keys);

        let rt = tokio::runtime::Handle::current();
        match crate::fuse::mount_filesystem(
            &state,
            rt,
            private_key,
            public_key,
            root_folder_key,
            root_ipns_name,
            root_ipns_private_key,
            tee_public_key,
            tee_key_epoch,
        ) {
            Ok(_handle) => {
                *state.mount_status.write().await = crate::state::MountStatus::Mounted;
                let _ = crate::tray::update_tray_status(&app, &crate::tray::TrayStatus::Synced);
                log::info!("FUSE filesystem mounted at ~/CipherVault");
            }
            Err(e) => {
                let err_msg = format!("FUSE mount failed: {}", e);
                *state.mount_status.write().await =
                    crate::state::MountStatus::Error(err_msg.clone());
                let _ = crate::tray::update_tray_status(
                    &app,
                    &crate::tray::TrayStatus::Error(err_msg.clone()),
                );
                log::error!("{}", err_msg);
                // Don't fail auth -- user is authenticated but mount failed
            }
        }
    }

    log::info!("Authentication complete for user {}", user_id);
    Ok(())
}

/// Try to silently refresh the session from a Keychain-stored refresh token.
///
/// On cold start, the private key is NOT available (it requires Web3Auth login).
/// This command refreshes the API session tokens only. The webview still needs
/// to complete Web3Auth login to obtain the private key for vault decryption.
///
/// Returns `true` if the API session was refreshed successfully.
/// Returns `false` if no stored session exists or refresh failed.
#[tauri::command]
pub async fn try_silent_refresh(state: State<'_, AppState>) -> Result<bool, String> {
    log::info!("Attempting silent refresh from Keychain");

    // Check for stored user ID
    let user_id = match auth::get_last_user_id() {
        Ok(Some(id)) => id,
        Ok(None) => {
            log::info!("No stored user ID, silent refresh skipped");
            return Ok(false);
        }
        Err(e) => {
            log::warn!("Failed to read user ID from Keychain: {}", e);
            return Ok(false);
        }
    };

    // Get refresh token from Keychain
    let refresh_token = match auth::get_refresh_token(&user_id) {
        Ok(Some(token)) => token,
        Ok(None) => {
            log::info!("No stored refresh token for user {}", user_id);
            return Ok(false);
        }
        Err(e) => {
            log::warn!("Failed to read refresh token from Keychain: {}", e);
            return Ok(false);
        }
    };

    // POST /auth/refresh with the stored refresh token
    let refresh_req = types::RefreshRequest {
        refresh_token: refresh_token.clone(),
    };

    let resp = match state.api.post("/auth/refresh", &refresh_req).await {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Refresh request failed (network error): {}", e);
            return Ok(false);
        }
    };

    if resp.status().as_u16() == 401 {
        // Stale token -- delete from Keychain
        log::info!("Refresh token expired, clearing Keychain");
        let _ = auth::delete_refresh_token(&user_id);
        return Ok(false);
    }

    if !resp.status().is_success() {
        log::warn!("Refresh failed with status {}", resp.status());
        return Ok(false);
    }

    let refresh_resp: types::RefreshResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse refresh response: {}", e))?;

    // Store new tokens
    state.api.set_access_token(refresh_resp.access_token).await;
    auth::store_refresh_token(&user_id, &refresh_resp.refresh_token)
        .map_err(|e| format!("Keychain store failed: {}", e))?;
    *state.user_id.write().await = Some(user_id.clone());

    log::info!("Silent refresh successful for user {}", user_id);

    // NOTE: Private key is NOT restored by silent refresh.
    // The webview must complete Web3Auth login to get the private key.
    // is_authenticated remains false until handle_auth_complete is called.
    Ok(true)
}

/// Start the background sync daemon.
///
/// Called from the webview after successful auth + mount. Creates the sync channel,
/// stores the sender in AppState for the tray menu, and spawns the daemon.
#[tauri::command]
pub async fn start_sync_daemon(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    log::info!("Starting background sync daemon");

    let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);

    // Store the sender in AppState so the tray "Sync Now" button can trigger syncs
    if let Ok(mut guard) = state.sync_trigger.write() {
        *guard = Some(tx);
    }

    // Extract shared references the daemon needs from AppState.
    // AppState fields are RwLock which we wrap in Arc for shared ownership
    // between the daemon task and the Tauri-managed state.
    //
    // We use the AppHandle to get the managed state which is already Arc-wrapped by Tauri.
    // The daemon reads root_ipns_name and is_authenticated via the app handle's state.
    let api = state.api.clone();
    let app_handle = app.clone();

    // Get the root IPNS name -- daemon needs to read it periodically
    let root_ipns_name = state.root_ipns_name.read().await.clone();

    // Clone values for the daemon's owned copies
    let root_ipns_name_lock = Arc::new(tokio::sync::RwLock::new(root_ipns_name));
    let is_authenticated_lock = Arc::new(tokio::sync::RwLock::new(
        *state.is_authenticated.read().await,
    ));

    // Spawn sync state bridge: periodically sync auth/ipns state from AppState to daemon
    let bridge_app = app.clone();
    let bridge_root = root_ipns_name_lock.clone();
    let bridge_auth = is_authenticated_lock.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let state = bridge_app.state::<AppState>();
            *bridge_root.write().await = state.root_ipns_name.read().await.clone();
            *bridge_auth.write().await = *state.is_authenticated.read().await;
        }
    });

    tokio::spawn(async move {
        let mut daemon = crate::sync::SyncDaemon::new(
            api,
            root_ipns_name_lock,
            is_authenticated_lock,
            rx,
            app_handle,
        );
        daemon.run().await;
    });

    log::info!("Sync daemon spawned");
    Ok(())
}

/// Logout: invalidate session, clear Keychain, zero all sensitive keys.
#[tauri::command]
pub async fn logout(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    log::info!("Logging out");

    // Unmount FUSE filesystem before clearing keys
    #[cfg(feature = "fuse")]
    {
        if let Err(e) = crate::fuse::unmount_filesystem() {
            log::warn!("FUSE unmount failed (will continue logout): {}", e);
        }
        *state.mount_status.write().await = crate::state::MountStatus::Unmounted;
    }

    // POST /auth/logout (best-effort, don't fail logout if server unreachable)
    let resp = state.api.authenticated_post("/auth/logout", &()).await;
    if let Err(e) = resp {
        log::warn!("Logout request failed (will continue local cleanup): {}", e);
    }

    // Delete refresh token from Keychain
    if let Some(ref user_id) = *state.user_id.read().await {
        let _ = auth::delete_refresh_token(user_id);
    }

    // Zero all sensitive keys in memory
    state.clear_keys().await;

    // Update tray status
    let _ = crate::tray::update_tray_status(&app, &crate::tray::TrayStatus::NotConnected);

    log::info!("Logout complete");
    Ok(())
}

/// Fetch vault keys from backend and decrypt them using the user's private key.
///
/// Decrypts:
/// - Root folder AES-256 key (32 bytes) from ECIES-wrapped hex
/// - Root IPNS Ed25519 private key (32 bytes) from ECIES-wrapped hex
/// - Root IPNS Ed25519 public key (32 bytes) from hex
///
/// Stores all keys in AppState (memory only).
async fn fetch_and_decrypt_vault(state: &AppState) -> Result<(), String> {
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
    *state.root_ipns_private_key.write().await = Some(root_ipns_private_key);

    // Decode root IPNS public key (not encrypted, just hex-encoded)
    let root_ipns_public_key = hex::decode(&vault.root_ipns_public_key)
        .map_err(|_| "Invalid rootIpnsPublicKey hex")?;
    *state.root_ipns_public_key.write().await = Some(root_ipns_public_key);

    // Store IPNS name and TEE keys
    *state.root_ipns_name.write().await = Some(vault.root_ipns_name);
    *state.tee_keys.write().await = vault.tee_keys;

    log::info!("Vault keys decrypted and stored in memory");
    Ok(())
}

/// Extract the user ID (`sub` claim) from a JWT access token.
///
/// Decodes the JWT payload (base64url) without verification -- the server
/// already verified the token, we just need the `sub` field for Keychain lookup.
fn extract_user_id_from_jwt(token: &str) -> Result<String, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    // Decode the payload (second part) -- base64url encoding
    let payload = parts[1];
    // base64url: replace - with + and _ with /, then add padding
    let padded = match payload.len() % 4 {
        2 => format!("{}==", payload),
        3 => format!("{}=", payload),
        _ => payload.to_string(),
    };
    let standard = padded.replace('-', "+").replace('_', "/");

    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &standard)
        .map_err(|e| format!("Failed to decode JWT payload: {}", e))?;

    let json: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|e| format!("Failed to parse JWT payload: {}", e))?;

    json["sub"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "JWT payload missing 'sub' claim".to_string())
}

/// Derive an uncompressed secp256k1 public key (65 bytes, 0x04 prefix) from a 32-byte private key.
///
/// Uses the `ecies` crate's re-exported `SecretKey` and `PublicKey` from libsecp256k1.
fn derive_public_key(private_key: &[u8]) -> Result<Vec<u8>, String> {
    let sk = ecies::SecretKey::parse_slice(private_key)
        .map_err(|e| format!("Invalid secp256k1 private key: {:?}", e))?;
    let pk = ecies::PublicKey::from_secret_key(&sk);
    Ok(pk.serialize().to_vec()) // 65-byte uncompressed format
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_user_id_from_jwt() {
        // Create a mock JWT with a known sub claim
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"user-123-abc","iat":1700000000}
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
        );
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"sub\":\"user-123-abc\",\"iat\":1700000000}",
        );
        let token = format!("{}.{}.fake-signature", header, payload);

        let user_id = extract_user_id_from_jwt(&token).unwrap();
        assert_eq!(user_id, "user-123-abc");
    }

    #[test]
    fn test_extract_user_id_invalid_jwt() {
        let result = extract_user_id_from_jwt("not-a-jwt");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_user_id_missing_sub() {
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
        );
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"iat\":1700000000}",
        );
        let token = format!("{}.{}.fake-signature", header, payload);

        let result = extract_user_id_from_jwt(&token);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sub"));
    }

    #[test]
    fn test_derive_public_key() {
        // Use a known private key and verify the public key is 65 bytes with 0x04 prefix
        let private_key = hex::decode(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();

        let public_key = derive_public_key(&private_key).unwrap();
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04); // Uncompressed prefix
    }

    #[test]
    fn test_derive_public_key_invalid_size() {
        let result = derive_public_key(&[0u8; 16]); // Too short
        assert!(result.is_err());
    }
}
