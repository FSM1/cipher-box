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
    // Idempotent singleton: if a daemon is already running, keep it. The daemon reads
    // auth/vault state from the shared KeyState each poll, so it adapts across re-auth
    // without a restart — spawning a second loop would leave two daemons polling and
    // double every status update and WriteParked notification (the D-10 spam this phase
    // prevents).
    let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);

    // Check-and-set the trigger sender under a single write lock so two concurrent
    // callers can't both pass the "already running?" check and each spawn a daemon. A
    // poisoned lock is surfaced as an error rather than silently ignored — ignoring it
    // would spawn a daemon whose sender the tray "Sync Now" button could never reach.
    {
        let mut guard = state
            .sync_trigger
            .write()
            .map_err(|_| "sync_trigger lock poisoned".to_string())?;
        if guard.is_some() {
            log::debug!("Sync daemon already running; skipping spawn");
            return Ok(());
        }
        *guard = Some(tx);
    }

    log::info!("Starting background sync daemon");

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
