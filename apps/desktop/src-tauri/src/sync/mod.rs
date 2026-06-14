//! Sync daemon bridge for desktop app.
//!
//! Creates `cipherbox_sdk::SyncDaemon` with Tauri tray status callback.
//! The sync daemon itself lives in the SDK crate -- this module provides
//! the bridge that converts SDK `SyncStatus` to Tauri `TrayStatus`.

// Re-export SDK types that the desktop app uses directly
pub use cipherbox_sdk::sync::SYNC_INTERVAL;
pub use cipherbox_sdk::SyncDaemon;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use cipherbox_sdk::SyncStatus;

/// Start the SDK sync daemon with a Tauri tray status bridge.
///
/// The `sync_now_rx` channel receives manual sync triggers from the tray menu.
/// The `write_queue` must point at the same cb-journal directory the FUSE layer writes
/// so the daemon can observe `Failed` entries and surface them via `WriteParked` (CR-07).
/// Returns a `SyncDaemon` that should be run in a spawned tokio task.
pub fn create_sync_daemon(
    state: Arc<cipherbox_sdk::KeyState>,
    app_handle: tauri::AppHandle,
    poll_interval: Duration,
    sync_now_rx: mpsc::Receiver<()>,
    write_queue: cipherbox_sdk::WriteQueue,
) -> SyncDaemon {
    let app = app_handle;
    // Edge-trigger the park notification. The SDK daemon emits a level-triggered
    // WriteParked status on every poll cycle while any entry stays Failed, but the
    // OS toast must fire only when the parked-failure count *increases* (a newly
    // parked write) — otherwise it re-notifies every ~30s poll (D-10: must not spam
    // the user). The tray status itself stays level-triggered (steady-state indicator);
    // only the notification is gated. The watermark resets to 0 when the journal clears
    // (Idle / failed == 0) so a future failure notifies again. It is intentionally NOT
    // reset on Syncing — the daemon emits Syncing at the start of every cycle, so
    // resetting there would re-arm the toast each poll and reintroduce the spam.
    let last_notified_failed = Arc::new(AtomicU32::new(0));
    let status_callback = Arc::new(move |status: SyncStatus| {
        // Bridge SDK sync status to Tauri tray status update.
        let tray_status = match status {
            SyncStatus::Idle => {
                last_notified_failed.store(0, Ordering::Relaxed);
                crate::tray::TrayStatus::Synced
            }
            SyncStatus::Syncing => crate::tray::TrayStatus::Syncing,
            SyncStatus::Error(ref e) if e == "Offline" => crate::tray::TrayStatus::Offline,
            SyncStatus::Error(e) => crate::tray::TrayStatus::Error(e),
            SyncStatus::WriteParked { failed, .. } if failed > 0 => {
                // Notify only when the parked-failure count rises above the last
                // value we notified on, so the toast fires once per newly parked
                // write rather than on every poll. ZK-safe neutral copy — no file
                // names or paths that could leak vault contents into OS logs.
                let prev = last_notified_failed.swap(failed, Ordering::Relaxed);
                if failed > prev {
                    let msg = format!("{} pending upload(s) failed and require attention.", failed);
                    if let Err(e) = crate::tray::send_write_parked_notification(&app, &msg) {
                        log::warn!("Failed to send write-parked notification: {}", e);
                    }
                }
                crate::tray::TrayStatus::WriteParked
            }
            SyncStatus::WriteParked { .. } => {
                // failed == 0: pending-only state — transient retries are silent (D-10).
                last_notified_failed.store(0, Ordering::Relaxed);
                crate::tray::TrayStatus::Syncing
            }
        };
        let _ = crate::tray::update_tray_status(&app, &tray_status);
    });

    SyncDaemon::new(state, status_callback, poll_interval, sync_now_rx, write_queue)
}
