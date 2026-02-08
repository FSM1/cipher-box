//! Tauri IPC commands for the desktop auth flow.
//!
//! These commands are invoked from the webview (TypeScript) via Tauri's
//! `invoke()` API. They handle authentication, vault key decryption,
//! Keychain storage, and logout.

use tauri::State;

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
    state: State<'_, AppState>,
    id_token: String,
    private_key: String,
) -> Result<(), String> {
    log::info!("Handling auth completion from webview");

    // 1. Login with backend
    let login_req = types::LoginRequest {
        id_token: id_token.clone(),
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

    // 2. Store access token in API client
    state.api.set_access_token(login_resp.access_token.clone()).await;

    // 3. Extract user ID from JWT claims (decode payload, read `sub`)
    let user_id = extract_user_id_from_jwt(&login_resp.access_token)?;
    *state.user_id.write().await = Some(user_id.clone());

    // 4. Store refresh token in Keychain
    auth::store_refresh_token(&user_id, &login_resp.refresh_token)
        .map_err(|e| format!("Keychain store failed: {}", e))?;
    auth::store_user_id(&user_id)
        .map_err(|e| format!("Keychain store user ID failed: {}", e))?;

    // 5. Convert private key from hex to bytes and store in AppState
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

    // 6. Derive uncompressed public key from private key using ecies crate
    let public_key_bytes = derive_public_key(&private_key_bytes)?;

    *state.private_key.write().await = Some(private_key_bytes);
    *state.public_key.write().await = Some(public_key_bytes);

    // 7. Fetch and decrypt vault keys (including root IPNS keypair)
    fetch_and_decrypt_vault(&state).await?;

    // 8. Mark as authenticated
    *state.is_authenticated.write().await = true;

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

/// Logout: invalidate session, clear Keychain, zero all sensitive keys.
#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    log::info!("Logging out");

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
