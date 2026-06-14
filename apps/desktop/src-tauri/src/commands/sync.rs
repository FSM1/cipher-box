//! Background sync daemon command.

use tauri::State;

use crate::state::AppState;

/// Start the background sync daemon.
///
/// Exposed as an IPC command for completeness, but the daemon is normally started
/// automatically from the post-mount auth path (`complete_auth_setup`) so every
/// login flow gets a running daemon. Delegates to [`spawn_sync_daemon`].
#[tauri::command]
pub async fn start_sync_daemon(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    spawn_sync_daemon(app, state.inner())
}

/// Create the sync channel, store its sender in AppState for the tray menu, and
/// spawn the background sync daemon.
///
/// Constructs a `WriteQueue` pointing at `<data_local_dir>/cipherbox/cb-journal` —
/// the same path the FUSE mount uses — so the daemon observes the same on-disk
/// entries the FUSE layer writes (CR-07). The daemon is what surfaces parked
/// writes via `WriteParked` notifications, so it MUST be started once the vault
/// is mounted; otherwise failed uploads never reach the user (G-43-UAT-01).
pub fn spawn_sync_daemon(app: tauri::AppHandle, state: &AppState) -> Result<(), String> {
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

    tokio::spawn(async move {
        let mut daemon = crate::sync::create_sync_daemon(
            sdk_state,
            app,
            crate::sync::SYNC_INTERVAL,
            rx,
            write_queue,
        );
        daemon.run().await;
    });

    log::info!("Sync daemon spawned");
    Ok(())
}
