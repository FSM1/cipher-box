//! OAuth popup window command.

use std::sync::atomic::{AtomicU32, Ordering};

/// Counter for unique OAuth popup window labels (shared with tray handler).
static POPUP_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Open an OAuth popup window directly from Rust.
///
/// Bypasses `window.open()` which is unreliable on Windows WebView2 (the
/// `NewWindowRequested` event / `on_new_window` handler may silently fail).
/// Instead, the webview calls this command via `invoke()` to create a new
/// Tauri webview window pointing directly at the OAuth URL.
#[tauri::command]
pub async fn open_oauth_popup(app: tauri::AppHandle, url: String) -> Result<(), String> {
    let n = POPUP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let label = format!("oauth-popup-{}", n);

    let parsed_url: tauri::Url = url
        .parse()
        .map_err(|e| format!("Invalid OAuth URL: {}", e))?;

    // Allowlist: only HTTPS requests to known OAuth providers are permitted.
    const ALLOWED_HOSTS: &[&str] = &["accounts.google.com"];
    if parsed_url.scheme() != "https" {
        return Err("OAuth URL must use HTTPS".to_string());
    }
    let host = parsed_url.host_str().unwrap_or("");
    if !ALLOWED_HOSTS.contains(&host) {
        return Err(format!("OAuth URL host '{}' is not allowed", host));
    }

    log::info!("Creating OAuth popup window: {} -> {}", label, host);

    tauri::WebviewWindowBuilder::new(
        &app,
        &label,
        tauri::WebviewUrl::External(parsed_url),
    )
    .title("Sign in with Google")
    .inner_size(500.0, 700.0)
    .center()
    .build()
    .map_err(|e| format!("Failed to create OAuth popup: {}", e))?;

    Ok(())
}
