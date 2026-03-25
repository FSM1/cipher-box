//! Background sync daemon command.

use tauri::State;

use crate::state::AppState;

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

    let sdk_state = state.sdk.clone();
    let app_handle = app.clone();

    tokio::spawn(async move {
        let mut daemon = crate::sync::create_sync_daemon(
            sdk_state,
            app_handle,
            crate::sync::SYNC_INTERVAL,
            rx,
        );
        daemon.run().await;
    });

    log::info!("Sync daemon spawned");
    Ok(())
}
