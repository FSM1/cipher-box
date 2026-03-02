//! Background sync daemon command.

use std::sync::Arc;

use tauri::{Manager, State};

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

    // Extract shared references the daemon needs from AppState.
    // AppState fields are RwLock which we wrap in Arc for shared ownership
    // between the daemon task and the Tauri-managed state.
    //
    // We use the AppHandle to get the managed state which is already Arc-wrapped by Tauri.
    // The daemon reads root_ipns_name and is_authenticated via the app handle's state.
    let api = state.api.clone();
    let app_handle = app.clone();

    // Get the root IPNS name -- daemon needs to read it periodically
    let root_ipns_name = state.root_ipns_name.read().await.clone();

    // Clone values for the daemon's owned copies
    let root_ipns_name_lock = Arc::new(tokio::sync::RwLock::new(root_ipns_name));
    let is_authenticated_lock = Arc::new(tokio::sync::RwLock::new(
        *state.is_authenticated.read().await,
    ));

    // Spawn sync state bridge: periodically sync auth/ipns state from AppState to daemon
    let bridge_app = app.clone();
    let bridge_root = root_ipns_name_lock.clone();
    let bridge_auth = is_authenticated_lock.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let state = bridge_app.state::<AppState>();
            *bridge_root.write().await = state.root_ipns_name.read().await.clone();
            *bridge_auth.write().await = *state.is_authenticated.read().await;
        }
    });

    tokio::spawn(async move {
        let mut daemon = crate::sync::SyncDaemon::new(
            api,
            root_ipns_name_lock,
            is_authenticated_lock,
            rx,
            app_handle,
        );
        daemon.run().await;
    });

    log::info!("Sync daemon spawned");
    Ok(())
}
