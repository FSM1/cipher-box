//! Sync daemon bridge for desktop app.
//!
//! Creates `cipherbox_sdk::SyncDaemon` with Tauri tray status callback.
//! The sync daemon itself lives in the SDK crate -- this module provides
//! the bridge that converts SDK `SyncStatus` to Tauri `TrayStatus`.

// Re-export SDK types that the desktop app uses directly
pub use cipherbox_sdk::queue::{QueuedWrite, UploadHandler, WriteQueue};
pub use cipherbox_sdk::sync::SYNC_INTERVAL;
pub use cipherbox_sdk::SyncDaemon;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use cipherbox_sdk::SyncStatus;

/// Start the SDK sync daemon with a Tauri tray status bridge.
///
/// The `sync_now_rx` channel receives manual sync triggers from the tray menu.
/// Returns a `SyncDaemon` that should be run in a spawned tokio task.
pub fn create_sync_daemon(
    state: Arc<cipherbox_sdk::KeyState>,
    app_handle: tauri::AppHandle,
    poll_interval: Duration,
    sync_now_rx: mpsc::Receiver<()>,
) -> SyncDaemon {
    let app = app_handle;
    let status_callback = Arc::new(move |status: SyncStatus| {
        // Bridge SDK sync status to Tauri tray status update
        let tray_status = match status {
            SyncStatus::Idle => crate::tray::TrayStatus::Synced,
            SyncStatus::Syncing => crate::tray::TrayStatus::Syncing,
            SyncStatus::Error(ref e) if e == "Offline" => crate::tray::TrayStatus::Offline,
            SyncStatus::Error(e) => crate::tray::TrayStatus::Error(e),
        };
        let _ = crate::tray::update_tray_status(&app, &tray_status);
    });

    SyncDaemon::new(state, status_callback, poll_interval, sync_now_rx)
}
