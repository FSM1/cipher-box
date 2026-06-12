//! Background sync daemon command.

use tauri::State;

use crate::state::AppState;

/// Start the background sync daemon.
///
/// Called from the webview after successful auth + mount. Creates the sync channel,
/// stores the sender in AppState for the tray menu, and spawns the daemon.
///
/// Constructs a `WriteQueue` pointing at `<data_local_dir>/cipherbox/cb-journal` —
/// the same path the FUSE mount uses — so the daemon observes the same on-disk
/// entries the FUSE layer writes (CR-07).
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

    // Build the journal directory using the same resolution as the FUSE mount
    // (apps/desktop/src-tauri/src/fuse/mod.rs) so daemon and FUSE share the
    // same on-disk journal (CR-07).
    let journal_dir = dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("cipherbox")
        .join("cb-journal");
    std::fs::create_dir_all(&journal_dir)
        .map_err(|e| format!("Failed to create journal directory: {}", e))?;
    let write_queue = cipherbox_sdk::WriteQueue::new(journal_dir, 5);

    let sdk_state = state.sdk.clone();
    let app_handle = app.clone();

    tokio::spawn(async move {
        let mut daemon = crate::sync::create_sync_daemon(
            sdk_state,
            app_handle,
            crate::sync::SYNC_INTERVAL,
            rx,
            write_queue,
        );
        daemon.run().await;
    });

    log::info!("Sync daemon spawned");
    Ok(())
}
