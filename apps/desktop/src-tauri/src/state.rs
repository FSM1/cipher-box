//! Application state for CipherBox Desktop.
//!
//! Thread-safe state holding decrypted keys in memory, API client,
//! and mount status. Sensitive keys are zeroed on logout via `clear_keys()`.

use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroize;

use crate::api::client::ApiClient;
use crate::api::types::TeeKeysResponse;

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
/// All sensitive key material is stored in memory only and zeroed on logout.
/// The `ApiClient` is shared via `Arc` for concurrent access from async commands.
pub struct AppState {
    /// HTTP client for CipherBox API communication.
    pub api: Arc<ApiClient>,

    /// 32-byte secp256k1 private key (memory only, never persisted).
    pub private_key: RwLock<Option<Vec<u8>>>,

    /// 65-byte uncompressed secp256k1 public key (0x04 prefix).
    pub public_key: RwLock<Option<Vec<u8>>>,

    /// 32-byte AES-256 root folder encryption key.
    pub root_folder_key: RwLock<Option<Vec<u8>>>,

    /// Root folder IPNS name (base36 CIDv1 string, e.g., k51...).
    pub root_ipns_name: RwLock<Option<String>>,

    /// Decrypted 32-byte Ed25519 IPNS private key for signing root folder metadata updates.
    /// Memory only, never persisted to disk.
    pub root_ipns_private_key: RwLock<Option<Vec<u8>>>,

    /// Authenticated user ID (JWT `sub` claim).
    pub user_id: RwLock<Option<String>>,

    /// Current and previous TEE public keys for IPNS key encryption.
    pub tee_keys: RwLock<Option<TeeKeysResponse>>,

    /// Whether the user is fully authenticated with vault keys decrypted.
    pub is_authenticated: RwLock<bool>,

    /// Current FUSE mount status.
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
            api: Arc::new(ApiClient::new(api_base_url)),
            private_key: RwLock::new(None),
            public_key: RwLock::new(None),
            root_folder_key: RwLock::new(None),
            root_ipns_name: RwLock::new(None),
            root_ipns_private_key: RwLock::new(None),
            user_id: RwLock::new(None),
            tee_keys: RwLock::new(None),
            is_authenticated: RwLock::new(false),
            mount_status: RwLock::new(MountStatus::Unmounted),
            sync_trigger: std::sync::RwLock::new(None),
            dev_key: RwLock::new(dev_key),
        }
    }

    /// Zero all sensitive key material and reset authentication state.
    ///
    /// Uses `zeroize` to securely wipe sensitive bytes from memory.
    /// Called on logout and before app exit.
    pub async fn clear_keys(&self) {
        // Each field uses a single lock acquisition to zeroize and clear.
        {
            let mut key = self.private_key.write().await;
            if let Some(ref mut k) = *key { k.zeroize(); }
            *key = None;
        }
        {
            let mut key = self.public_key.write().await;
            if let Some(ref mut k) = *key { k.zeroize(); }
            *key = None;
        }
        {
            let mut key = self.root_folder_key.write().await;
            if let Some(ref mut k) = *key { k.zeroize(); }
            *key = None;
        }
        {
            let mut key = self.root_ipns_private_key.write().await;
            if let Some(ref mut k) = *key { k.zeroize(); }
            *key = None;
        }

        // Clear dev key (sensitive: contains private key hex)
        {
            let mut key = self.dev_key.write().await;
            if let Some(ref mut k) = *key { k.zeroize(); }
            *key = None;
        }

        // Clear non-sensitive fields
        *self.root_ipns_name.write().await = None;
        *self.user_id.write().await = None;
        *self.tee_keys.write().await = None;
        *self.is_authenticated.write().await = false;

        // Clear access token from API client
        self.api.clear_access_token().await;
    }
}
