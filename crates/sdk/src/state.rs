//! Key material state management for the CipherBox SDK.
//!
//! Holds decrypted key material in memory. All sensitive keys are zeroed
//! on clear() via the `zeroize` crate. No Tauri or OS-specific dependencies.

use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroize;

use cipherbox_api_client::ApiClient;
use cipherbox_api_client::TeeKeysResponse;
use cipherbox_core::VaultSettings;

/// Sync status for external notification via generic callback.
#[derive(Debug, Clone, PartialEq)]
pub enum SyncStatus {
    Idle,
    Syncing,
    Error(String),
    /// One or more journal entries could not be uploaded after max retries (D-10).
    ///
    /// `pending` is the count of entries still awaiting a first successful attempt;
    /// `failed` is the count of entries parked with `JournalEntryStatus::Failed`.
    WriteParked {
        /// Number of pending journal entries not yet attempted.
        pending: u32,
        /// Number of entries that exhausted retries and are parked on disk.
        failed: u32,
    },
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
    pub root_folder_key: RwLock<Option<zeroize::Zeroizing<Vec<u8>>>>,

    /// 32-byte AES-256 node/v3 root READ key (seals the root read body).
    ///
    /// One of the two independent random root keys of the node/v3 model
    /// (research §Q1): never derived from `root_write_key` or `root_folder_key`.
    /// Landing slot filled by the desktop recovery (69-23) and read by the
    /// mount (69-24). Zeroed on `clear()`.
    pub root_read_key: RwLock<Option<zeroize::Zeroizing<Vec<u8>>>>,

    /// 32-byte AES-256 node/v3 root WRITE key (seals the root write body).
    ///
    /// The second independent random root key of the node/v3 model
    /// (research §Q1): never derived from `root_read_key` or `root_folder_key`.
    /// Landing slot filled by the desktop recovery (69-23) and read by the
    /// mount (69-24). Zeroed on `clear()`.
    pub root_write_key: RwLock<Option<zeroize::Zeroizing<Vec<u8>>>>,

    /// Root folder IPNS name (base36 CIDv1 string, e.g., k51...).
    pub root_ipns_name: RwLock<Option<String>>,

    /// Decrypted 32-byte Ed25519 IPNS private key for signing root folder metadata updates.
    /// Memory only, never persisted to disk.
    pub root_ipns_private_key: RwLock<Option<Vec<u8>>>,

    /// Authenticated user ID (JWT `sub` claim).
    pub user_id: RwLock<Option<String>>,

    /// Current and previous TEE public keys for IPNS key encryption.
    pub tee_keys: RwLock<Option<TeeKeysResponse>>,

    /// User-configurable vault settings (retention, versioning, delete behavior).
    /// Non-optional: defaults to default_vault_settings() when not loaded from IPNS.
    pub vault_settings: RwLock<VaultSettings>,

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
            root_read_key: RwLock::new(None),
            root_write_key: RwLock::new(None),
            root_ipns_name: RwLock::new(None),
            root_ipns_private_key: RwLock::new(None),
            user_id: RwLock::new(None),
            tee_keys: RwLock::new(None),
            vault_settings: RwLock::new(cipherbox_core::default_vault_settings()),
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
            let mut key = self.root_read_key.write().await;
            if let Some(ref mut k) = *key {
                k.zeroize();
            }
            *key = None;
        }
        {
            let mut key = self.root_write_key.write().await;
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
        *self.vault_settings.write().await = cipherbox_core::default_vault_settings();
        *self.is_authenticated.write().await = false;

        // Clear access token from API client
        self.api.clear_access_token().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> KeyState {
        KeyState::from_url("http://localhost:9999")
    }

    #[tokio::test]
    async fn new_creates_state_with_none_fields() {
        let state = make_state();

        assert!(state.private_key.read().await.is_none());
        assert!(state.public_key.read().await.is_none());
        assert!(state.root_folder_key.read().await.is_none());
        assert!(state.root_read_key.read().await.is_none());
        assert!(state.root_write_key.read().await.is_none());
        assert!(state.root_ipns_name.read().await.is_none());
        assert!(state.root_ipns_private_key.read().await.is_none());
        assert!(state.user_id.read().await.is_none());
        assert!(state.tee_keys.read().await.is_none());
        assert_eq!(*state.vault_settings.read().await, cipherbox_core::default_vault_settings());
        assert!(!*state.is_authenticated.read().await);
    }

    #[tokio::test]
    async fn fields_are_writable_and_readable() {
        let state = make_state();

        *state.private_key.write().await = Some(vec![1, 2, 3]);
        *state.public_key.write().await = Some(vec![4, 5, 6]);
        *state.root_folder_key.write().await = Some(zeroize::Zeroizing::new(vec![7, 8, 9]));
        *state.root_read_key.write().await = Some(zeroize::Zeroizing::new(vec![13, 14, 15]));
        *state.root_write_key.write().await = Some(zeroize::Zeroizing::new(vec![16, 17, 18]));
        *state.root_ipns_name.write().await = Some("k51test".to_string());
        *state.root_ipns_private_key.write().await = Some(vec![10, 11, 12]);
        *state.user_id.write().await = Some("user-123".to_string());
        *state.is_authenticated.write().await = true;

        assert_eq!(*state.private_key.read().await, Some(vec![1, 2, 3]));
        assert_eq!(*state.public_key.read().await, Some(vec![4, 5, 6]));
        assert_eq!(
            *state.root_folder_key.read().await,
            Some(zeroize::Zeroizing::new(vec![7, 8, 9]))
        );
        assert_eq!(
            *state.root_read_key.read().await,
            Some(zeroize::Zeroizing::new(vec![13, 14, 15]))
        );
        assert_eq!(
            *state.root_write_key.read().await,
            Some(zeroize::Zeroizing::new(vec![16, 17, 18]))
        );
        assert_eq!(*state.root_ipns_name.read().await, Some("k51test".to_string()));
        assert_eq!(*state.root_ipns_private_key.read().await, Some(vec![10, 11, 12]));
        assert_eq!(*state.user_id.read().await, Some("user-123".to_string()));
        assert!(*state.is_authenticated.read().await);
    }

    #[tokio::test]
    async fn clear_zeros_all_sensitive_byte_fields() {
        let state = make_state();

        // Populate sensitive fields with non-zero bytes.
        *state.private_key.write().await = Some(vec![0xFF; 32]);
        *state.public_key.write().await = Some(vec![0xAA; 65]);
        *state.root_folder_key.write().await = Some(zeroize::Zeroizing::new(vec![0xBB; 32]));
        *state.root_read_key.write().await = Some(zeroize::Zeroizing::new(vec![0xDD; 32]));
        *state.root_write_key.write().await = Some(zeroize::Zeroizing::new(vec![0xEE; 32]));
        *state.root_ipns_private_key.write().await = Some(vec![0xCC; 32]);
        *state.root_ipns_name.write().await = Some("k51name".to_string());
        *state.user_id.write().await = Some("user-abc".to_string());
        *state.is_authenticated.write().await = true;

        // Set vault settings to non-default values
        *state.vault_settings.write().await = cipherbox_core::VaultSettings {
            version: "v1".to_string(),
            recycle_bin_retention_days: 60,
            delete_behavior: cipherbox_core::DeleteBehavior::Permanent,
            max_versions_per_file: 50,
            version_cooldown_minutes: 30,
        };

        state.clear().await;

        // All fields should be None / false / defaults after clear.
        assert!(state.private_key.read().await.is_none());
        assert!(state.public_key.read().await.is_none());
        assert!(state.root_folder_key.read().await.is_none());
        assert!(state.root_read_key.read().await.is_none());
        assert!(state.root_write_key.read().await.is_none());
        assert!(state.root_ipns_private_key.read().await.is_none());
        assert!(state.root_ipns_name.read().await.is_none());
        assert!(state.user_id.read().await.is_none());
        assert!(state.tee_keys.read().await.is_none());
        assert_eq!(*state.vault_settings.read().await, cipherbox_core::default_vault_settings());
        assert!(!*state.is_authenticated.read().await);
    }

    #[test]
    fn sync_status_variants() {
        let idle = SyncStatus::Idle;
        let syncing = SyncStatus::Syncing;
        let error = SyncStatus::Error("timeout".to_string());

        assert_eq!(idle, SyncStatus::Idle);
        assert_eq!(syncing, SyncStatus::Syncing);
        assert_eq!(error, SyncStatus::Error("timeout".to_string()));
        assert_ne!(idle, syncing);
    }

    #[test]
    fn sync_status_write_parked_variant() {
        let parked = SyncStatus::WriteParked {
            pending: 2,
            failed: 1,
        };

        assert_eq!(
            parked,
            SyncStatus::WriteParked {
                pending: 2,
                failed: 1,
            }
        );
        assert_ne!(parked, SyncStatus::Idle);
        assert_ne!(
            parked,
            SyncStatus::WriteParked {
                pending: 0,
                failed: 1,
            }
        );
    }
}
