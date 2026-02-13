//! Background sync daemon for CipherBox Desktop.
//!
//! Polls IPNS every 30 seconds for metadata changes, refreshes the inode table
//! when changes are detected, and processes queued offline writes.
//!
//! Uses sequence number comparison (not CID) per project decision from Phase 7.

pub mod queue;
#[cfg(test)]
mod tests;

pub use queue::{QueuedWrite, UploadHandler, WriteQueue};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::RwLock;

/// Default polling interval for IPNS sync (30 seconds).
pub const SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// The background sync daemon.
///
/// Runs in a tokio task, polling IPNS for metadata changes at a regular interval.
/// Can be triggered manually via the `sync_now_tx` channel from the tray menu.
pub struct SyncDaemon {
    /// API client for IPFS/IPNS operations.
    api: Arc<crate::api::client::ApiClient>,
    /// Root folder IPNS name (shared reference, updated on auth).
    root_ipns_name: Arc<RwLock<Option<String>>>,
    /// Whether the user is fully authenticated (shared reference).
    is_authenticated: Arc<RwLock<bool>>,
    /// Poll interval (default 30s).
    poll_interval: Duration,
    /// Cached IPNS sequence numbers: ipns_name -> last known sequence_number.
    cached_sequence_numbers: HashMap<String, u64>,
    /// Channel receiver for manual sync triggers (from tray "Sync Now" button).
    sync_now_rx: mpsc::Receiver<()>,
    /// Offline write queue for deferred uploads.
    write_queue: WriteQueue,
    /// AppHandle for updating tray status.
    app_handle: tauri::AppHandle,
    /// Whether the last poll attempt detected offline state.
    was_offline: bool,
}

impl SyncDaemon {
    /// Create a new sync daemon.
    ///
    /// The `sync_now_rx` channel receives manual sync triggers from the tray menu.
    /// Shared references to `root_ipns_name` and `is_authenticated` are read from
    /// AppState fields (they are `tokio::sync::RwLock` wrapped in Arc by the caller).
    pub fn new(
        api: Arc<crate::api::client::ApiClient>,
        root_ipns_name: Arc<RwLock<Option<String>>>,
        is_authenticated: Arc<RwLock<bool>>,
        sync_now_rx: mpsc::Receiver<()>,
        app_handle: tauri::AppHandle,
    ) -> Self {
        Self {
            api,
            root_ipns_name,
            is_authenticated,
            poll_interval: SYNC_INTERVAL,
            cached_sequence_numbers: HashMap::new(),
            sync_now_rx,
            write_queue: WriteQueue::default(),
            app_handle,
            was_offline: false,
        }
    }

    /// Main run loop. Call from a spawned tokio task.
    ///
    /// Uses `tokio::select!` to wait on either the periodic tick or a manual trigger.
    /// On each tick: poll IPNS for changes, process write queue.
    pub async fn run(&mut self) {
        let mut ticker = tokio::time::interval(self.poll_interval);
        // The first tick fires immediately; skip it to let the app finish mounting.
        ticker.tick().await;

        log::info!(
            "Sync daemon started (interval: {}s)",
            self.poll_interval.as_secs()
        );

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.sync_cycle().await;
                }
                Some(()) = self.sync_now_rx.recv() => {
                    log::info!("Manual sync triggered");
                    self.sync_cycle().await;
                }
            }
        }
    }

    /// Execute one full sync cycle: poll + process write queue.
    async fn sync_cycle(&mut self) {
        // Check if authenticated
        if !*self.is_authenticated.read().await {
            return;
        }

        // Update tray to Syncing
        let _ = crate::tray::update_tray_status(
            &self.app_handle,
            &crate::tray::TrayStatus::Syncing,
        );

        match self.poll().await {
            Ok(()) => {
                // Transitioned from offline to online
                if self.was_offline {
                    log::info!("Connectivity restored, resuming sync");
                    self.was_offline = false;
                }

                // Process queued writes (best-effort)
                if !self.write_queue.is_empty() {
                    log::info!(
                        "Processing {} queued writes",
                        self.write_queue.len()
                    );
                    // Write queue processing requires an UploadHandler implementation
                    // which would use self.api. For v1, log pending items.
                    // Full write queue processing with FUSE integration is deferred
                    // to after the UploadHandler trait is wired to the ApiClient+FUSE layer.
                    log::debug!(
                        "Write queue has {} pending items",
                        self.write_queue.len()
                    );
                }

                let _ = crate::tray::update_tray_status(
                    &self.app_handle,
                    &crate::tray::TrayStatus::Synced,
                );
            }
            Err(e) => {
                log::warn!("Sync poll failed: {}", e);

                // Determine if this is a network error (offline) or API error
                if is_network_error(&e) {
                    if !self.was_offline {
                        log::info!("Network appears offline, pausing active sync");
                        self.was_offline = true;
                    }
                    let _ = crate::tray::update_tray_status(
                        &self.app_handle,
                        &crate::tray::TrayStatus::Offline,
                    );
                } else {
                    let _ = crate::tray::update_tray_status(
                        &self.app_handle,
                        &crate::tray::TrayStatus::Error(e),
                    );
                }
            }
        }
    }

    /// Poll IPNS for all known folders and detect changes via sequence number comparison.
    ///
    /// For each folder:
    /// 1. Resolve IPNS name to get current sequence number
    /// 2. Compare with cached sequence number
    /// 3. If changed: log the change (metadata cache TTL handles refresh on next FUSE access)
    /// 4. Update cached sequence numbers
    async fn poll(&mut self) -> Result<(), String> {
        // Get root IPNS name
        let root_ipns_name = self
            .root_ipns_name
            .read()
            .await
            .clone()
            .ok_or_else(|| "Root IPNS name not available".to_string())?;

        // Resolve root folder IPNS
        let resolve_result =
            crate::api::ipns::resolve_ipns(&self.api, &root_ipns_name).await?;

        let new_seq = resolve_result
            .sequence_number
            .parse::<u64>()
            .unwrap_or(0);

        let cached_seq = self
            .cached_sequence_numbers
            .get(&root_ipns_name)
            .copied()
            .unwrap_or(0);

        if new_seq != cached_seq {
            log::info!(
                "IPNS change detected for root folder: seq {} -> {}",
                cached_seq,
                new_seq
            );
            self.cached_sequence_numbers
                .insert(root_ipns_name.clone(), new_seq);

            // The metadata cache has a 30s TTL, so the next FUSE readdir/lookup
            // will fetch and decrypt fresh metadata automatically.
            log::info!(
                "Root folder metadata changed (CID: {}). Cache will refresh on next access.",
                resolve_result.cid
            );
        }

        Ok(())
    }

    /// Access the write queue for enqueuing offline writes.
    pub fn write_queue_mut(&mut self) -> &mut WriteQueue {
        &mut self.write_queue
    }
}

/// Heuristic check for network-level errors vs application errors.
fn is_network_error(error: &str) -> bool {
    let network_patterns = [
        "dns error",
        "connect error",
        "connection refused",
        "network unreachable",
        "timed out",
        "timeout",
        "no route to host",
        "network is down",
        "couldn't resolve host",
    ];
    let lower = error.to_lowercase();
    network_patterns.iter().any(|p| lower.contains(p))
}
