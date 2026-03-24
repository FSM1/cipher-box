//! Top-level SDK client that ties state, sync, and registry together.
//!
//! The `CipherBoxSdkClient` owns the shared `KeyState` and provides
//! methods to start/stop sync and clear key material. The desktop app
//! creates one instance at startup and shares the `state` Arc with
//! FUSE and Tauri command handlers.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::state::{KeyState, SyncStatus};
use crate::sync::SyncDaemon;

/// Top-level SDK client.
///
/// Owns the shared `KeyState` and optionally runs a `SyncDaemon`.
/// The desktop app creates one of these, shares `state` with FUSE
/// and commands, and bridges sync status updates to the tray icon.
pub struct CipherBoxSdkClient {
    /// Shared key material state. Passed to SyncDaemon, FUSE, commands.
    pub state: Arc<KeyState>,
    /// Handle to abort the sync task when stopping.
    sync_handle: Option<tokio::task::JoinHandle<()>>,
    /// Channel sender to trigger manual sync.
    sync_trigger_tx: Option<mpsc::Sender<()>>,
}

impl CipherBoxSdkClient {
    /// Create a new SDK client with the given API base URL.
    pub fn new(api_base_url: &str) -> Self {
        Self {
            state: Arc::new(KeyState::from_url(api_base_url)),
            sync_handle: None,
            sync_trigger_tx: None,
        }
    }

    /// Create a new SDK client wrapping an existing KeyState.
    pub fn from_state(state: Arc<KeyState>) -> Self {
        Self {
            state,
            sync_handle: None,
            sync_trigger_tx: None,
        }
    }

    /// Start the background sync daemon.
    ///
    /// The `status_callback` is invoked on every status change (Idle, Syncing, Error).
    /// Returns a `mpsc::Sender<()>` that can be used to trigger manual sync cycles
    /// (e.g., from a "Sync Now" tray menu item).
    ///
    /// If sync is already running, this is a no-op.
    pub fn start_sync(
        &mut self,
        status_callback: Arc<dyn Fn(SyncStatus) + Send + Sync>,
        poll_interval: Duration,
    ) -> mpsc::Sender<()> {
        if self.sync_handle.is_some() {
            // Already running -- return existing trigger
            return self
                .sync_trigger_tx
                .clone()
                .expect("sync_trigger_tx should exist when sync_handle exists");
        }

        let (sync_now_tx, sync_now_rx) = mpsc::channel(1);
        let state = self.state.clone();

        let handle = tokio::spawn(async move {
            let mut daemon = SyncDaemon::new(state, status_callback, poll_interval, sync_now_rx);
            daemon.run().await;
        });

        self.sync_handle = Some(handle);
        self.sync_trigger_tx = Some(sync_now_tx.clone());
        sync_now_tx
    }

    /// Stop the background sync daemon.
    pub fn stop_sync(&mut self) {
        if let Some(handle) = self.sync_handle.take() {
            handle.abort();
        }
        self.sync_trigger_tx = None;
    }

    /// Zero all key material and stop sync.
    pub async fn clear(&mut self) {
        self.stop_sync();
        self.state.clear().await;
    }
}
