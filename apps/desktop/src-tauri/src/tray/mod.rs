//! System tray (menu bar) icon and menu for CipherBox Desktop.
//!
//! Creates a macOS menu bar icon with status display and actions:
//! Open CipherVault, Sync Now, Login/Logout, Quit.
//!
//! The app runs as a pure background utility (no Dock icon).

pub mod status;

pub use status::TrayStatus;

use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager};

/// ID used to look up the single tray icon instance.
const TRAY_ID: &str = "cipherbox-tray";

/// Build and register the system tray icon with an initial NotConnected menu.
///
/// Menu items:
/// - `status`: Disabled informational line showing current status
/// - `open`: Open ~/CipherVault in Finder (enabled when mounted)
/// - `sync`: Trigger immediate sync (enabled when connected)
/// - separator
/// - `login`: Show Web3Auth webview (when not connected)
/// - `logout`: Unmount + clear keys (when connected)
/// - separator
/// - `quit`: Unmount if mounted, then exit
pub fn build_tray(app: &AppHandle) -> Result<(), String> {
    let menu = build_menu(app, &TrayStatus::NotConnected)?;

    let _tray = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .show_menu_on_left_click(true)
        .tooltip("CipherBox")
        .icon(
            app.default_window_icon()
                .cloned()
                .unwrap_or_else(|| tauri::image::Image::new(&[], 0, 0)),
        )
        .on_menu_event(move |app, event| {
            handle_menu_event(app, event.id().as_ref());
        })
        .build(app)
        .map_err(|e| format!("Failed to build tray icon: {}", e))?;

    log::info!("System tray icon created");
    Ok(())
}

/// Build the tray menu with item states matching the given status.
fn build_menu(
    app: &AppHandle,
    status: &TrayStatus,
) -> Result<tauri::menu::Menu<tauri::Wry>, String> {
    let status_text = format!("Status: {}", status.label());
    let is_mounted = matches!(status, TrayStatus::Syncing | TrayStatus::Synced);
    let is_syncable = matches!(status, TrayStatus::Synced | TrayStatus::Error(_));
    let is_disconnected = matches!(status, TrayStatus::NotConnected);
    let is_connected = status.is_connected();

    let status_item = MenuItemBuilder::with_id("status", &status_text)
        .enabled(false)
        .build(app)
        .map_err(|e| format!("Failed to build status item: {}", e))?;

    let open_item = MenuItemBuilder::with_id("open", "Open CipherVault")
        .enabled(is_mounted)
        .build(app)
        .map_err(|e| format!("Failed to build open item: {}", e))?;

    let sync_item = MenuItemBuilder::with_id("sync", "Sync Now")
        .enabled(is_syncable)
        .build(app)
        .map_err(|e| format!("Failed to build sync item: {}", e))?;

    let login_item = MenuItemBuilder::with_id("login", "Login...")
        .enabled(is_disconnected)
        .build(app)
        .map_err(|e| format!("Failed to build login item: {}", e))?;

    let logout_item = MenuItemBuilder::with_id("logout", "Logout")
        .enabled(is_connected)
        .build(app)
        .map_err(|e| format!("Failed to build logout item: {}", e))?;

    let quit_item = MenuItemBuilder::with_id("quit", "Quit CipherBox")
        .build(app)
        .map_err(|e| format!("Failed to build quit item: {}", e))?;

    let sep1 = PredefinedMenuItem::separator(app)
        .map_err(|e| format!("Failed to build separator: {}", e))?;
    let sep2 = PredefinedMenuItem::separator(app)
        .map_err(|e| format!("Failed to build separator: {}", e))?;

    MenuBuilder::new(app)
        .item(&status_item)
        .item(&open_item)
        .item(&sync_item)
        .item(&sep1)
        .item(&login_item)
        .item(&logout_item)
        .item(&sep2)
        .item(&quit_item)
        .build()
        .map_err(|e| format!("Failed to build menu: {}", e))
}

/// Handle a menu item click by ID.
fn handle_menu_event(app: &AppHandle, id: &str) {
    match id {
        "open" => {
            // Open ~/CipherVault in Finder
            let mount_point = dirs::home_dir()
                .map(|h| h.join("CipherVault"))
                .unwrap_or_default();
            if let Err(e) = std::process::Command::new("open")
                .arg(mount_point.to_str().unwrap_or("~/CipherVault"))
                .spawn()
            {
                log::error!("Failed to open CipherVault in Finder: {}", e);
            }
        }
        "sync" => {
            // Trigger immediate sync via the SyncDaemon channel stored in AppState
            let state = app.state::<crate::state::AppState>();
            if let Some(tx) = state.sync_trigger.read().ok().and_then(|g| g.clone()) {
                let _ = tx.try_send(());
                log::info!("Manual sync triggered");
            } else {
                log::warn!("Sync trigger channel not available");
            }
        }
        "login" => {
            // Show or create the webview window for Web3Auth login
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            } else {
                // No window exists yet (headless start) — create one
                log::info!("Creating login webview window");
                match tauri::WebviewWindowBuilder::new(
                    app,
                    "main",
                    tauri::WebviewUrl::App("index.html".into()),
                )
                .title("CipherBox")
                .inner_size(480.0, 600.0)
                .center()
                .resizable(false)
                .on_new_window(|_url, _features| {
                    // Allow Web3Auth OAuth popups (Google, etc.)
                    tauri::webview::NewWindowResponse::Allow
                })
                .build()
                {
                    Ok(window) => {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                    Err(e) => {
                        log::error!("Failed to create login window: {}", e);
                    }
                }
            }
        }
        "logout" => {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let state = app_handle.state::<crate::state::AppState>();

                // Unmount FUSE filesystem
                #[cfg(feature = "fuse")]
                {
                    if let Err(e) = crate::fuse::unmount_filesystem() {
                        log::warn!("FUSE unmount during logout failed: {}", e);
                    }
                    *state.mount_status.write().await = crate::state::MountStatus::Unmounted;
                }

                // POST /auth/logout (best-effort)
                let _ = state.api.authenticated_post("/auth/logout", &()).await;

                // Delete refresh token from Keychain
                if let Some(ref user_id) = *state.user_id.read().await {
                    let _ = crate::api::auth::delete_refresh_token(user_id);
                }

                // Zero all sensitive keys
                state.clear_keys().await;

                // Update tray status
                if let Err(e) = update_tray_status(&app_handle, &TrayStatus::NotConnected) {
                    log::warn!("Failed to update tray status after logout: {}", e);
                }

                log::info!("Logout complete (via tray menu)");
            });
        }
        "quit" => {
            // Unmount FUSE if mounted, then exit
            #[cfg(feature = "fuse")]
            {
                let _ = crate::fuse::unmount_filesystem();
            }
            app.exit(0);
        }
        _ => {
            log::debug!("Unknown tray menu event: {}", id);
        }
    }
}

/// Update the tray menu to reflect the new status.
///
/// Rebuilds the entire menu with updated item states and sets it on the tray icon.
/// On Error status, sends a system notification.
pub fn update_tray_status(app: &AppHandle, status: &TrayStatus) -> Result<(), String> {
    let tray = app
        .tray_by_id(TRAY_ID)
        .ok_or_else(|| "Tray icon not found".to_string())?;

    // Rebuild the menu with updated states
    let menu = build_menu(app, status)?;
    tray.set_menu(Some(menu))
        .map_err(|e| format!("Failed to set tray menu: {}", e))?;

    // Send notification on Error status
    if let TrayStatus::Error(ref msg) = status {
        if let Err(e) = send_error_notification(app, msg) {
            log::warn!("Failed to send error notification: {}", e);
        }
    }

    log::debug!("Tray status updated to: {}", status.label());
    Ok(())
}

/// Send a system notification for error states.
fn send_error_notification(app: &AppHandle, message: &str) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;
    app.notification()
        .builder()
        .title("CipherBox Error")
        .body(message)
        .show()
        .map_err(|e| format!("Notification failed: {}", e))?;
    Ok(())
}
