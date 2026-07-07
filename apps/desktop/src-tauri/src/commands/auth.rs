//! Authentication commands: login, session restore, silent refresh, logout.

use tauri::{Manager, State};
use zeroize::Zeroizing;

use crate::keychain;
use crate::state::AppState;
use cipherbox_api_client;

use super::util::{derive_public_key, extract_user_id_from_jwt};
use super::vault::{fetch_and_decrypt_vault, initialize_vault};

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

    // Derive uncompressed public key from private key (65 bytes, 0x04 prefix)
    // Used for both ECIES operations and backend auth (backend expects uncompressed)
    let public_key_bytes = derive_public_key(&private_key_bytes)?;
    let public_key_hex = hex::encode(&public_key_bytes); // 130 hex chars

    // 2. Login with backend (requires uncompressed publicKey, 130 hex chars)
    let login_req = cipherbox_api_client::LoginRequest {
        id_token: id_token.clone(),
        public_key: public_key_hex,
        login_type: "corekit".to_string(),
    };

    let resp = state
        .sdk
        .api
        .post("/auth/login", &login_req)
        .await
        .map_err(|e| format!("Login request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Login failed ({}): {}", status, body));
    }

    let login_resp: cipherbox_api_client::LoginResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse login response: {}", e))?;

    // Delegate to shared post-auth setup
    complete_auth_setup(
        &app,
        &state,
        login_resp.access_token,
        login_resp.refresh_token,
        Zeroizing::new(private_key_bytes),
        public_key_bytes,
        login_resp.is_new_user,
        false,
    )
    .await
}

/// Shared post-auth setup used by both `handle_auth_complete` and `handle_test_login_complete`.
///
/// Stores tokens and keys, initializes/fetches vault, registers device, mounts FUSE,
/// and hides the login window.
pub(crate) async fn complete_auth_setup(
    app: &tauri::AppHandle,
    state: &AppState,
    access_token: String,
    refresh_token: String,
    private_key_bytes: Zeroizing<Vec<u8>>,
    public_key_bytes: Vec<u8>,
    is_new_user: bool,
    skip_keychain: bool,
) -> Result<(), String> {
    // 1. Store access token in API client
    state.sdk.api.set_access_token(access_token.clone()).await;

    // 2. Extract user ID from JWT claims (decode payload, read `sub`)
    let user_id = extract_user_id_from_jwt(&access_token)?;
    *state.sdk.user_id.write().await = Some(user_id.clone());

    // 3. Store refresh token in Keychain (skip in test-login mode to avoid popups)
    if !skip_keychain {
        keychain::store_refresh_token(&user_id, &refresh_token)
            .map_err(|e| format!("Keychain store failed: {}", e))?;
        keychain::store_user_id(&user_id)
            .map_err(|e| format!("Keychain store user ID failed: {}", e))?;
    } else {
        log::info!("Skipping Keychain storage (test-login mode)");
    }

    // 4. Store keys in SDK state
    *state.sdk.private_key.write().await = Some(private_key_bytes.to_vec());
    *state.sdk.public_key.write().await = Some(public_key_bytes.clone());

    // 5. Initialize vault for new users, or fetch existing vault
    //    Also handle the edge case where user exists but vault was deleted.
    if is_new_user {
        log::info!("New user detected, initializing vault");
        initialize_vault(state, &public_key_bytes).await?;
    }
    match fetch_and_decrypt_vault(state).await {
        Ok(()) => {}
        Err(e) if e.contains("404") && !is_new_user => {
            log::warn!("Vault not found for existing user, re-initializing");
            initialize_vault(state, &public_key_bytes).await?;
            fetch_and_decrypt_vault(state).await?;
        }
        Err(e) => return Err(e),
    }

    // 5b. Load vault settings (graceful fallback to defaults)
    if let Ok(pk_arr) = <[u8; 32]>::try_from(private_key_bytes.as_slice()) {
        let settings = super::vault::load_vault_settings(&state.sdk.api, &pk_arr).await;
        *state.sdk.vault_settings.write().await = settings;
    } else {
        log::warn!("Private key not 32 bytes, using default vault settings");
    }

    // 6. Mark as authenticated
    *state.sdk.is_authenticated.write().await = true;

    // 7–9. Mount filesystem, register device, tear down login windows.
    post_auth_finalize(app, state, &private_key_bytes, &public_key_bytes, &user_id).await?;

    log::info!("Authentication complete for user {}", user_id);
    Ok(())
}

/// Factor of `complete_auth_setup`'s mount/sync/device/teardown tail.
///
/// Mounts the filesystem (or marks synced when no FS feature is enabled), registers
/// the device in the encrypted registry, and destroys OAuth popup windows / hides
/// the main login webview.  Called only after vault keys are in state and
/// `is_authenticated` is set to `true`.
async fn post_auth_finalize(
    app: &tauri::AppHandle,
    state: &AppState,
    private_key_bytes: &Zeroizing<Vec<u8>>,
    public_key_bytes: &[u8],
    user_id: &str,
) -> Result<(), String> {
    // 7. Mount filesystem (or just mark as synced if no filesystem feature enabled)
    // NOTE: Device registry spawn moved AFTER mount to avoid concurrent HTTP
    //       requests that cause reqwest connection pool starvation during pre-populate.
    #[cfg(not(any(feature = "fuse", feature = "winfsp")))]
    {
        let _ = crate::tray::update_tray_status(app, &crate::tray::TrayStatus::Synced);
    }
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    {
        *state.mount_status.write().await = crate::state::MountStatus::Mounting;
        let private_key = state
            .sdk
            .private_key
            .read()
            .await
            .as_ref()
            .ok_or("Private key not available for filesystem mount")?
            .clone();
        let public_key = state
            .sdk
            .public_key
            .read()
            .await
            .as_ref()
            .ok_or("Public key not available for filesystem mount")?
            .clone();
        let root_folder_key = state
            .sdk
            .root_folder_key
            .read()
            .await
            .as_ref()
            .ok_or("Root folder key not available for filesystem mount")?
            .clone();
        // node/v3 root read/write keys recovered into KeyState at login
        // (69-22 fields, populated by 69-23 vault init/recovery). These are the
        // REAL persisted keys — the mount consumes them directly (the legacy
        // root_folder_key placeholder bridge is retired in fuse/mod.rs).
        let root_read_key = state
            .sdk
            .root_read_key
            .read()
            .await
            .as_ref()
            .ok_or("Root read key not available for filesystem mount")?
            .clone();
        let root_write_key = state
            .sdk
            .root_write_key
            .read()
            .await
            .as_ref()
            .ok_or("Root write key not available for filesystem mount")?
            .clone();
        let root_ipns_name = state
            .sdk
            .root_ipns_name
            .read()
            .await
            .as_ref()
            .ok_or("Root IPNS name not available for filesystem mount")?
            .clone();
        let root_ipns_private_key = state.sdk.root_ipns_private_key.read().await.clone();

        // Extract TEE keys for new folder creation
        let tee_keys = state.sdk.tee_keys.read().await;
        let tee_public_key = tee_keys
            .as_ref()
            .and_then(|tk| hex::decode(&tk.current_public_key).ok());
        let tee_key_epoch = tee_keys.as_ref().map(|tk| tk.current_epoch);
        drop(tee_keys);

        // Read vault settings for FUSE versioning parameters
        let vault_settings = state.sdk.vault_settings.read().await;
        let max_versions = vault_settings.max_versions_per_file as usize;
        // CRITICAL: Convert minutes to milliseconds (per Pitfall 4 in RESEARCH.md)
        let cooldown_ms = vault_settings.version_cooldown_minutes as u64 * 60 * 1000;
        drop(vault_settings);

        let rt = tokio::runtime::Handle::current();
        match crate::fuse::mount_filesystem(
            state,
            rt,
            private_key,
            public_key,
            root_folder_key,
            root_read_key,
            root_write_key,
            root_ipns_name,
            root_ipns_private_key,
            tee_public_key,
            tee_key_epoch,
            max_versions,
            cooldown_ms,
        )
        .await
        {
            Ok(_handle) => {
                *state.mount_status.write().await = crate::state::MountStatus::Mounted;
                let _ = crate::tray::update_tray_status(app, &crate::tray::TrayStatus::Synced);
                log::info!(
                    "Filesystem mounted at {}",
                    crate::fuse::mount_point().display()
                );

                // Start the background sync daemon now that the vault is mounted.
                // Every auth flow (OAuth, email, session-restore, dev-key test-login)
                // funnels through complete_auth_setup, so this is the single point that
                // guarantees the daemon runs — without it, parked writes never surface
                // via WriteParked notifications (G-43-UAT-01).
                if let Err(e) = super::sync::spawn_sync_daemon(app.clone(), state) {
                    log::warn!("Failed to start sync daemon (non-fatal): {}", e);
                }
            }
            Err(e) => {
                let err_msg = format!("Filesystem mount failed: {}", e);
                *state.mount_status.write().await =
                    crate::state::MountStatus::Error(err_msg.clone());
                let _ = crate::tray::update_tray_status(
                    app,
                    &crate::tray::TrayStatus::Error(err_msg.clone()),
                );
                log::error!("{}", err_msg);
                // Don't fail auth -- user is authenticated but mount failed
            }
        }
    }

    // 8. Register device in encrypted registry (non-blocking, after mount)
    {
        let reg_api = state.sdk.api.clone();
        let reg_private_key = Zeroizing::new(private_key_bytes.to_vec());
        let reg_public_key = public_key_bytes.to_vec();
        let reg_user_id = user_id.to_string();
        tokio::spawn(async move {
            let pk_arr: [u8; 32] = match reg_private_key.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    log::warn!("Device registry: invalid private key length");
                    return;
                }
            };
            match crate::registry::register_device(&reg_api, &pk_arr, &reg_public_key, &reg_user_id)
                .await
            {
                Ok(()) => log::info!("Device registry updated"),
                Err(e) => log::warn!("Device registry update failed (non-blocking): {}", e),
            }
        });
    }

    // Close OAuth popup windows and hide the login webview
    for (label, window) in app.webview_windows() {
        if label.starts_with("oauth-popup-") {
            let _ = window.destroy();
        } else if label == "main" {
            let _ = window.hide();
        }
    }

    Ok(())
}

/// Handle session restore when Core Kit has a restored LOGGED_IN session.
///
/// Called when Core Kit's init() restores a previous session from localStorage
/// and the Rust side already has a valid access token from silent refresh.
/// Unlike `handle_auth_complete`, this skips the `/auth/login` POST since
/// tokens are already valid.
#[tauri::command]
pub async fn handle_session_restore(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    private_key: String,
) -> Result<(), String> {
    log::info!("Handling session restore from Core Kit");

    let _ = crate::tray::update_tray_status(&app, &crate::tray::TrayStatus::Mounting);

    // Convert private key from hex to bytes
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

    let public_key_bytes = derive_public_key(&private_key_bytes)?;

    // Get the existing access token (set by try_silent_refresh)
    let access_token = state
        .sdk
        .api
        .get_access_token()
        .await
        .ok_or("No access token available - silent refresh may not have succeeded")?;

    // Extract user_id from the existing access token to look up the refresh token
    let user_id = extract_user_id_from_jwt(&access_token)?;
    let refresh_token = keychain::get_refresh_token(&user_id)
        .map_err(|e| format!("Keychain read failed: {}", e))?
        .ok_or("No refresh token in Keychain")?;

    complete_auth_setup(
        &app,
        &state,
        access_token,
        refresh_token,
        Zeroizing::new(private_key_bytes),
        public_key_bytes,
        false, // not a new user
        true,  // skip Keychain writes (already stored)
    )
    .await
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
    let user_id = match keychain::get_last_user_id() {
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
    let refresh_token = match keychain::get_refresh_token(&user_id) {
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
    let refresh_req = cipherbox_api_client::RefreshRequest {
        refresh_token: refresh_token.clone(),
    };

    let resp = match state.sdk.api.post("/auth/refresh", &refresh_req).await {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Refresh request failed (network error): {}", e);
            return Ok(false);
        }
    };

    if resp.status().as_u16() == 401 {
        // Stale token -- delete from Keychain
        log::info!("Refresh token expired, clearing Keychain");
        let _ = keychain::delete_refresh_token(&user_id);
        return Ok(false);
    }

    if !resp.status().is_success() {
        log::warn!("Refresh failed with status {}", resp.status());
        return Ok(false);
    }

    let refresh_resp: cipherbox_api_client::RefreshResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse refresh response: {}", e))?;

    // Store new tokens
    state
        .sdk
        .api
        .set_access_token(refresh_resp.access_token)
        .await;
    keychain::store_refresh_token(&user_id, &refresh_resp.refresh_token)
        .map_err(|e| format!("Keychain store failed: {}", e))?;
    *state.sdk.user_id.write().await = Some(user_id.clone());

    log::info!("Silent refresh successful for user {}", user_id);

    // NOTE: Private key is NOT restored by silent refresh.
    // The webview must complete Web3Auth login to get the private key.
    // is_authenticated remains false until handle_auth_complete is called.
    Ok(true)
}

/// Logout: invalidate session, clear Keychain, zero all sensitive keys.
#[tauri::command]
pub async fn logout(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    log::info!("Logging out");

    // Unmount filesystem before clearing keys
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    {
        if let Err(e) = crate::fuse::unmount_filesystem() {
            log::warn!("Filesystem unmount failed (will continue logout): {}", e);
        }
        *state.mount_status.write().await = crate::state::MountStatus::Unmounted;
    }

    // POST /auth/logout (best-effort, don't fail logout if server unreachable)
    let resp = state.sdk.api.authenticated_post("/auth/logout", &()).await;
    if let Err(e) = resp {
        log::warn!("Logout request failed (will continue local cleanup): {}", e);
    }

    // Delete refresh token from Keychain
    if let Some(ref user_id) = *state.sdk.user_id.read().await {
        let _ = keychain::delete_refresh_token(user_id);
    }

    // D-02: purge this vault's journal entries (.json + .bin) so they do not persist past
    // the session into another login. The shared journal dir is only filtered at read time,
    // so without this the departing vault's entries (incl. ciphertext sidecars) would leak
    // across sessions (T-52-15, Information Disclosure). Must run BEFORE clear_keys() because
    // it reads the current vault IPNS from sdk state, which clear_keys() zeroes to None.
    //
    // FUTURE: a `switch_account` / `delete_account` command (none exists today — RESEARCH
    // Open Q2) must likewise call `WriteQueue::purge_vault` for the departing vault.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    {
        if let Some(ipns) = state.sdk.root_ipns_name.read().await.clone() {
            let journal = cipherbox_sdk::WriteQueue::new(
                crate::fuse::default_journal_dir(),
                crate::fuse::JOURNAL_MAX_RETRIES,
            );
            match journal.purge_vault(&ipns) {
                Ok(n) => log::info!(
                    "Logout: purged {} journal entr{} for vault",
                    n,
                    if n == 1 { "y" } else { "ies" }
                ),
                Err(e) => log::warn!("Logout: journal purge failed (will continue logout): {}", e),
            }
        }
    }

    // Zero all sensitive keys in memory
    state.clear_keys().await;

    // Update tray status
    let _ = crate::tray::update_tray_status(&app, &crate::tray::TrayStatus::NotConnected);

    log::info!("Logout complete");
    Ok(())
}
