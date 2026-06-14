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

use crate::tray::TrayStatus;

/// Pure outcome of bridging one `SyncStatus` to the tray, computed without touching
/// the OS — so the edge-trigger notification logic (D-10) is unit-testable.
#[derive(Debug, PartialEq)]
struct TrayBridgeOutcome {
    /// Tray status to display (level-triggered steady-state indicator).
    tray: TrayStatus,
    /// New value for the "last notified failed count" watermark.
    watermark: u32,
    /// `Some(failed)` => fire a park notification for `failed` failures; `None` => stay silent.
    notify_failed: Option<u32>,
}

/// Decide the tray status, notification watermark, and whether to fire an OS toast for a
/// given `SyncStatus`, given the last failed count we already notified on (`prev_watermark`).
///
/// Edge-trigger rule (D-10): the park toast fires only when the parked-failure count
/// *rises* above the last value we notified on, so a steady stream of poll cycles at the
/// same failure level notifies once, not every ~30s poll. The watermark resets to 0 when
/// the journal clears (Idle, or `WriteParked` with `failed == 0`) so a later failure
/// notifies again. It is intentionally preserved (not reset) on Syncing — the daemon emits
/// Syncing at the start of every cycle, and resetting there would re-arm the toast each
/// poll and reintroduce the spam.
fn bridge_status(status: &SyncStatus, prev_watermark: u32) -> TrayBridgeOutcome {
    match status {
        SyncStatus::Idle => TrayBridgeOutcome {
            tray: TrayStatus::Synced,
            watermark: 0,
            notify_failed: None,
        },
        SyncStatus::Syncing => TrayBridgeOutcome {
            tray: TrayStatus::Syncing,
            watermark: prev_watermark, // preserved on purpose — see doc comment
            notify_failed: None,
        },
        SyncStatus::Error(e) if e == "Offline" => TrayBridgeOutcome {
            tray: TrayStatus::Offline,
            watermark: prev_watermark,
            notify_failed: None,
        },
        SyncStatus::Error(e) => TrayBridgeOutcome {
            tray: TrayStatus::Error(e.clone()),
            watermark: prev_watermark,
            notify_failed: None,
        },
        SyncStatus::WriteParked { failed, .. } if *failed > 0 => TrayBridgeOutcome {
            tray: TrayStatus::WriteParked,
            watermark: *failed,
            notify_failed: if *failed > prev_watermark {
                Some(*failed)
            } else {
                None
            },
        },
        // failed == 0: pending-only state — transient retries are silent (D-10).
        SyncStatus::WriteParked { .. } => TrayBridgeOutcome {
            tray: TrayStatus::Syncing,
            watermark: 0,
            notify_failed: None,
        },
    }
}

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
    // Watermark of the last parked-failure count we fired an OS toast for (D-10). The
    // pure decision lives in `bridge_status`; this callback applies it and performs the
    // OS side effects (notification + tray update).
    let last_notified_failed = Arc::new(AtomicU32::new(0));
    let status_callback = Arc::new(move |status: SyncStatus| {
        // The daemon invokes this serially per poll cycle, so load+store is equivalent
        // to a swap of the watermark.
        let prev = last_notified_failed.load(Ordering::Relaxed);
        let outcome = bridge_status(&status, prev);
        last_notified_failed.store(outcome.watermark, Ordering::Relaxed);

        if let Some(failed) = outcome.notify_failed {
            // ZK-safe neutral copy — no file names or paths that could leak vault
            // contents into OS notification logs.
            let msg = format!("{} pending upload(s) failed and require attention.", failed);
            if let Err(e) = crate::tray::send_write_parked_notification(&app, &msg) {
                log::warn!("Failed to send write-parked notification: {}", e);
            }
        }
        let _ = crate::tray::update_tray_status(&app, &outcome.tray);
    });

    SyncDaemon::new(state, status_callback, poll_interval, sync_now_rx, write_queue)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parked(pending: u32, failed: u32) -> SyncStatus {
        SyncStatus::WriteParked { pending, failed }
    }

    #[test]
    fn idle_marks_synced_and_clears_watermark() {
        let out = bridge_status(&SyncStatus::Idle, 3);
        assert_eq!(out.tray, TrayStatus::Synced);
        assert_eq!(out.watermark, 0);
        assert_eq!(out.notify_failed, None);
    }

    #[test]
    fn syncing_preserves_watermark_and_is_silent() {
        // Critical: Syncing must NOT reset the watermark, or the daemon's per-cycle
        // Syncing emit would re-arm the toast every poll (D-10 spam regression).
        let out = bridge_status(&SyncStatus::Syncing, 2);
        assert_eq!(out.tray, TrayStatus::Syncing);
        assert_eq!(out.watermark, 2);
        assert_eq!(out.notify_failed, None);
    }

    #[test]
    fn offline_and_error_preserve_watermark_silently() {
        let off = bridge_status(&SyncStatus::Error("Offline".to_string()), 5);
        assert_eq!(off.tray, TrayStatus::Offline);
        assert_eq!(off.watermark, 5);
        assert_eq!(off.notify_failed, None);

        let err = bridge_status(&SyncStatus::Error("boom".to_string()), 5);
        assert_eq!(err.tray, TrayStatus::Error("boom".to_string()));
        assert_eq!(err.watermark, 5);
        assert_eq!(err.notify_failed, None);
    }

    #[test]
    fn first_parked_failure_notifies() {
        let out = bridge_status(&parked(0, 2), 0);
        assert_eq!(out.tray, TrayStatus::WriteParked);
        assert_eq!(out.watermark, 2);
        assert_eq!(out.notify_failed, Some(2));
    }

    #[test]
    fn same_failure_level_does_not_renotify() {
        let out = bridge_status(&parked(0, 2), 2);
        assert_eq!(out.tray, TrayStatus::WriteParked);
        assert_eq!(out.watermark, 2);
        assert_eq!(out.notify_failed, None);
    }

    #[test]
    fn rising_failure_count_renotifies() {
        let out = bridge_status(&parked(1, 3), 2);
        assert_eq!(out.tray, TrayStatus::WriteParked);
        assert_eq!(out.watermark, 3);
        assert_eq!(out.notify_failed, Some(3));
    }

    #[test]
    fn pending_only_is_silent_and_clears_watermark() {
        let out = bridge_status(&parked(4, 0), 2);
        assert_eq!(out.tray, TrayStatus::Syncing);
        assert_eq!(out.watermark, 0);
        assert_eq!(out.notify_failed, None);
    }

    /// End-to-end edge-trigger trace: notify once on a new failure, stay silent while it
    /// persists (including across the per-poll Syncing emit), re-notify only when it
    /// rises, and re-arm after the journal clears.
    #[test]
    fn edge_trigger_sequence_notifies_once_per_new_failure() {
        let mut wm = 0u32;
        let mut step = |s: SyncStatus| {
            let o = bridge_status(&s, wm);
            wm = o.watermark;
            o.notify_failed
        };
        assert_eq!(step(parked(0, 1)), Some(1)); // new failure -> notify
        assert_eq!(step(SyncStatus::Syncing), None); // poll cycle -> silent, watermark kept
        assert_eq!(step(parked(0, 1)), None); // same level -> silent
        assert_eq!(step(parked(0, 2)), Some(2)); // rose -> notify
        assert_eq!(step(SyncStatus::Idle), None); // journal cleared -> reset
        assert_eq!(step(parked(0, 1)), Some(1)); // re-armed -> notify again
    }
}
