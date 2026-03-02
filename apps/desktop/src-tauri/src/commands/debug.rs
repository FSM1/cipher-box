//! Debug-only commands (compiled only in debug builds).
//!
//! All functions in this module are gated behind `#[cfg(debug_assertions)]`
//! at the module level via `mod.rs`.

use tauri::State;
use zeroize::Zeroizing;

use crate::state::AppState;

use super::auth::complete_auth_setup;
use super::util::derive_public_key;

/// Get the dev-key if one was provided via CLI (debug builds only).
///
/// Returns `Some(hex_string)` if `--dev-key` was passed at startup, `None` otherwise.
/// The webview can use this to skip Web3Auth login and call `handle_auth_complete`
/// directly with a synthetic identity token or via the test-login endpoint.
#[tauri::command]
pub async fn get_dev_key(state: State<'_, AppState>) -> Result<Option<String>, String> {
    log::info!("get_dev_key invoked by webview");
    let key = state.dev_key.read().await.clone();
    log::info!("get_dev_key returning: has_key={}", key.is_some());
    Ok(key)
}

/// Log a JS error from the webview to the Rust logger.
/// Used in CI to surface webview errors that would otherwise be invisible.
#[tauri::command]
pub fn log_js_error(context: String, message: String) {
    log::error!("[webview-js] {}: {}", context, message);
}

/// Handle test-login authentication (debug builds only).
///
/// Called from the webview after a successful `POST /auth/test-login` response.
/// Unlike `handle_auth_complete`, this skips the `/auth/login` POST because
/// test-login already returns access + refresh tokens directly.
///
/// The private key comes from the test-login response (server-generated
/// deterministic keypair), NOT from the CLI `--dev-key` argument.
#[tauri::command]
pub async fn handle_test_login_complete(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    access_token: String,
    refresh_token: String,
    private_key_hex: String,
    is_new_user: bool,
) -> Result<(), String> {
    log::info!("Handling test-login auth completion (debug mode)");

    // Update tray status: Mounting
    let _ = crate::tray::update_tray_status(&app, &crate::tray::TrayStatus::Mounting);

    // Convert private key hex to bytes
    let pk_hex = if private_key_hex.starts_with("0x") {
        &private_key_hex[2..]
    } else {
        &private_key_hex
    };
    let private_key_bytes =
        hex::decode(pk_hex).map_err(|_| "Invalid private key hex from test-login".to_string())?;
    if private_key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }

    // Derive public key from the test-login private key
    let public_key_bytes = derive_public_key(&private_key_bytes)?;

    // Delegate to shared post-auth setup (skips /auth/login POST and Keychain)
    complete_auth_setup(
        &app,
        &state,
        access_token,
        refresh_token,
        Zeroizing::new(private_key_bytes),
        public_key_bytes,
        is_new_user,
        true, // skip Keychain -- test-login re-authenticates each time
    )
    .await
}
