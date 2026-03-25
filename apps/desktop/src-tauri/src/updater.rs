//! Auto-update integration using tauri-plugin-updater.
//!
//! Checks for updates on launch (with 5-second delay), downloads in background,
//! and notifies via system notification. Manual check available from tray menu.

use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;

/// Check for updates on app launch. Spawns async task with 5s delay.
pub fn check_on_launch(app: &AppHandle) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        // Small delay to avoid competing with login/mount startup
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        if let Err(e) = do_update_check(&handle).await {
            log::warn!("Update check failed: {}", e);
        }
    });
}

/// Manual check triggered from tray "Check for Updates..." menu item.
pub fn manual_check(app: &AppHandle) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        match do_update_check(&handle).await {
            Ok(found) => {
                if !found {
                    // No update available -- notify user since they asked explicitly
                    use tauri_plugin_notification::NotificationExt;
                    let _ = handle
                        .notification()
                        .builder()
                        .title("CipherBox")
                        .body("You are running the latest version.")
                        .show();
                }
            }
            Err(e) => {
                use tauri_plugin_notification::NotificationExt;
                let _ = handle
                    .notification()
                    .builder()
                    .title("CipherBox")
                    .body("Update check failed. Please try again later.")
                    .show();
                log::warn!("Manual update check failed: {}", e);
            }
        }
    });
}

/// Perform the actual update check, download, and notification.
/// Returns Ok(true) if an update was found and downloaded, Ok(false) if no update.
async fn do_update_check(app: &AppHandle) -> Result<bool, Box<dyn std::error::Error>> {
    let updater = app.updater()?;
    let update = updater.check().await?;

    if let Some(update) = update {
        log::info!("Update available: v{}", update.version);

        // Download and install (stages for next restart on macOS/Linux)
        let version = update.version.clone();
        update
            .download_and_install(
                |chunk_length, content_length| {
                    log::debug!(
                        "Downloading update: {} / {:?} bytes",
                        chunk_length,
                        content_length
                    );
                },
                || {
                    log::info!("Update downloaded, pending install on restart");
                },
            )
            .await?;

        // Notify user via system notification
        use tauri_plugin_notification::NotificationExt;
        let _ = app
            .notification()
            .builder()
            .title("CipherBox Update Ready")
            .body(&format!(
                "CipherBox v{} is ready. It will be installed on next restart.",
                version
            ))
            .show();

        Ok(true)
    } else {
        log::info!("No update available (current version is latest)");
        Ok(false)
    }
}
