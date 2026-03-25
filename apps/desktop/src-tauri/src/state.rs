//! Application state for CipherBox Desktop.
//!
//! Thread-safe state holding decrypted keys in memory, API client,
//! and mount status. Delegates key material management to `cipherbox_sdk::KeyState`.
//! Sensitive keys are zeroed on logout via `clear_keys()`.

use std::sync::Arc;
use tokio::sync::RwLock;

use cipherbox_sdk::KeyState;

/// Channel sender type for triggering manual sync from the tray menu.
pub type SyncTrigger = tokio::sync::mpsc::Sender<()>;

/// FUSE mount status for the system tray indicator.
#[derive(Debug, Clone, PartialEq)]
pub enum MountStatus {
    Unmounted,
    Mounting,
    Mounted,
    Error(String),
}

/// Thread-safe application state shared across Tauri commands.
///
/// Key material is managed by `cipherbox_sdk::KeyState` (the `sdk` field).
/// Tauri-specific fields (mount status, sync trigger, dev key) stay here.
pub struct AppState {
    /// SDK key state (shared with sync daemon and FUSE).
    pub sdk: Arc<KeyState>,

    /// Current FUSE mount status (Tauri-specific).
    pub mount_status: RwLock<MountStatus>,

    /// Channel sender to trigger an immediate sync cycle from the tray "Sync Now" button.
    /// Set once the SyncDaemon is spawned. Uses std::sync::RwLock because the tray
    /// menu event handler is synchronous.
    pub sync_trigger: std::sync::RwLock<Option<SyncTrigger>>,

    /// Hex-encoded secp256k1 private key for headless auth (debug builds only).
    /// Set via `--dev-key <hex>` CLI argument. Compiled out in release builds.
    pub dev_key: RwLock<Option<String>>,
}

impl AppState {
    /// Create a new AppState with the given API base URL and optional dev key.
    pub fn new(api_base_url: &str, dev_key: Option<String>) -> Self {
        Self {
            sdk: Arc::new(KeyState::from_url(api_base_url)),
            mount_status: RwLock::new(MountStatus::Unmounted),
            sync_trigger: std::sync::RwLock::new(None),
            dev_key: RwLock::new(dev_key),
        }
    }

    /// Zero all sensitive key material and reset authentication state.
    ///
    /// Delegates to `KeyState::clear()` for key zeroization, then clears
    /// Tauri-specific fields (dev_key).
    pub async fn clear_keys(&self) {
        // Delegate key material clearing to SDK
        self.sdk.clear().await;

        // Clear Tauri-specific sensitive fields
        {
            use zeroize::Zeroize;
            let mut key = self.dev_key.write().await;
            if let Some(ref mut k) = *key {
                k.zeroize();
            }
            *key = None;
        }
    }
}
