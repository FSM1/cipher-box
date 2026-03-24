//! Key material state management for the CipherBox SDK.
//!
//! Holds decrypted key material in memory. All sensitive keys are zeroed
//! on clear() via the `zeroize` crate. No Tauri or OS-specific dependencies.

use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroize;

use cipherbox_api_client::ApiClient;
use cipherbox_api_client::TeeKeysResponse;

/// Sync status for external notification via generic callback.
#[derive(Debug, Clone, PartialEq)]
pub enum SyncStatus {
    Idle,
    Syncing,
    Error(String),
}

/// Key material state shared across SDK components.
///
/// All sensitive keys are zeroed on `clear()`. This struct holds ONLY
/// key material and authentication state -- no Tauri-specific fields
/// (mount_status, sync_trigger, dev_key stay in the desktop app).
pub struct KeyState {
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
}

impl KeyState {
    /// Create a new KeyState with the given API client.
    pub fn new(api: Arc<ApiClient>) -> Self {
        Self {
            api,
            private_key: RwLock::new(None),
            public_key: RwLock::new(None),
            root_folder_key: RwLock::new(None),
            root_ipns_name: RwLock::new(None),
            root_ipns_private_key: RwLock::new(None),
            user_id: RwLock::new(None),
            tee_keys: RwLock::new(None),
            is_authenticated: RwLock::new(false),
        }
    }

    /// Create a new KeyState from an API base URL.
    pub fn from_url(api_base_url: &str) -> Self {
        Self::new(Arc::new(ApiClient::new(api_base_url)))
    }

    /// Zero all sensitive key material and reset authentication state.
    ///
    /// Uses `zeroize` to securely wipe sensitive bytes from memory.
    /// Called on logout and before app exit.
    pub async fn clear(&self) {
        // Zeroize sensitive key fields
        {
            let mut key = self.private_key.write().await;
            if let Some(ref mut k) = *key {
                k.zeroize();
            }
            *key = None;
        }
        {
            let mut key = self.public_key.write().await;
            if let Some(ref mut k) = *key {
                k.zeroize();
            }
            *key = None;
        }
        {
            let mut key = self.root_folder_key.write().await;
            if let Some(ref mut k) = *key {
                k.zeroize();
            }
            *key = None;
        }
        {
            let mut key = self.root_ipns_private_key.write().await;
            if let Some(ref mut k) = *key {
                k.zeroize();
            }
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
