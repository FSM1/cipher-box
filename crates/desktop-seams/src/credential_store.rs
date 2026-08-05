//! Desktop [`CredentialStore`]: the OS keyring, plus a feature-gated
//! file-backed test double.

use cipherbox_engine::seams::{CredentialStore, SeamError, SeamResult};

/// Keyring account label for the rotating refresh token.
const REFRESH_TOKEN_ACCOUNT: &str = "refresh-token";
/// Keyring account label for the last-account id.
const LAST_ACCOUNT_ID_ACCOUNT: &str = "last-account-id";

/// Refresh-token persistence in the OS keyring (Apple Keychain, Windows
/// Credential Manager, or the Secret Service on Linux) —
/// blueprint/engine.md "CredentialStore", desktop column;
/// blueprint/desktop.md "OS keychain".
///
/// Holds **only** the rotating refresh token and the last-account id, under
/// one service name, two accounts — never key material, never a seed, never
/// the short-lived access JWT (which lives in engine memory only). Both
/// values are stored as opaque secret bytes.
///
/// `Debug` is derived and safe: the struct carries only the service name, a
/// non-secret; no token is ever held in memory by this handle.
#[derive(Debug, Clone)]
pub struct KeyringCredentialStore {
    service: String,
}

impl KeyringCredentialStore {
    /// A credential store under one keyring service name (e.g.
    /// `"com.cipherbox.desktop"`). One store per running app.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, account: &str) -> SeamResult<keyring::Entry> {
        keyring::Entry::new(&self.service, account)
            .map_err(|err| SeamError::new(format!("keyring entry: {err}")))
    }

    /// Stores an opaque secret under one account, replacing any previous
    /// value.
    fn store_secret(&self, account: &str, secret: &[u8]) -> SeamResult<()> {
        self.entry(account)?
            .set_secret(secret)
            .map_err(|err| SeamError::new(format!("keyring set: {err}")))
    }

    /// Loads an opaque secret, mapping a missing entry to `None`.
    fn load_secret(&self, account: &str) -> SeamResult<Option<Vec<u8>>> {
        match self.entry(account)?.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(SeamError::new(format!("keyring get: {err}"))),
        }
    }

    /// Deletes an account's secret. Idempotent (a missing entry is success).
    fn clear_secret(&self, account: &str) -> SeamResult<()> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(SeamError::new(format!("keyring delete: {err}"))),
        }
    }

    /// Persists the last-account id — the only extra datum this store holds
    /// beyond the refresh token, used by the shell to pick the account
    /// directory on next launch (blueprint/desktop.md "last-account id").
    pub async fn store_last_account_id(&self, account_id: &[u8]) -> SeamResult<()> {
        self.store_secret(LAST_ACCOUNT_ID_ACCOUNT, account_id)
    }

    /// The persisted last-account id, if any.
    pub async fn load_last_account_id(&self) -> SeamResult<Option<Vec<u8>>> {
        self.load_secret(LAST_ACCOUNT_ID_ACCOUNT)
    }

    /// Deletes the persisted last-account id. Idempotent.
    pub async fn clear_last_account_id(&self) -> SeamResult<()> {
        self.clear_secret(LAST_ACCOUNT_ID_ACCOUNT)
    }
}

impl CredentialStore for KeyringCredentialStore {
    async fn store_refresh_token(&self, refresh_token: &[u8]) -> SeamResult<()> {
        self.store_secret(REFRESH_TOKEN_ACCOUNT, refresh_token)
    }

    async fn load_refresh_token(&self) -> SeamResult<Option<Vec<u8>>> {
        self.load_secret(REFRESH_TOKEN_ACCOUNT)
    }

    async fn clear_refresh_token(&self) -> SeamResult<()> {
        self.clear_secret(REFRESH_TOKEN_ACCOUNT)
    }
}

/// A file-backed [`CredentialStore`] **test double** for headless CI, where
/// no OS keyring is available.
///
/// Gated behind the `test-support` feature and never compiled into a
/// production build. It writes its values to plaintext files, so it must
/// never hold a real token — only the conformance kit's fixture tokens. The
/// real credential path is always [`KeyringCredentialStore`].
#[cfg(feature = "test-support")]
pub use file_double::FileCredentialStore;

#[cfg(feature = "test-support")]
mod file_double {
    use std::path::{Path, PathBuf};

    use cipherbox_engine::seams::{CredentialStore, SeamResult};

    use crate::fs_util::{atomic_write, ensure_dir, read_file_opt, remove_file_durable, seam_err};

    /// File-backed credential store — TEST DOUBLE ONLY. Values are written
    /// in plaintext; never use it for a real token. See the module note.
    pub struct FileCredentialStore {
        refresh_token_path: PathBuf,
        last_account_id_path: PathBuf,
    }

    impl FileCredentialStore {
        /// Opens (creating if absent) a file-backed store rooted at `dir`.
        pub fn open(dir: impl AsRef<Path>) -> SeamResult<Self> {
            let dir = dir.as_ref();
            ensure_dir(dir).map_err(|err| seam_err("file_credential_store open", &err))?;
            Ok(Self {
                refresh_token_path: dir.join("refresh_token"),
                last_account_id_path: dir.join("last_account_id"),
            })
        }

        /// Persists the last-account id (mirrors the keyring store's inherent
        /// method so tests exercise the same surface).
        pub async fn store_last_account_id(&self, account_id: &[u8]) -> SeamResult<()> {
            atomic_write(&self.last_account_id_path, account_id)
                .map_err(|err| seam_err("file_credential_store store_last_account_id", &err))
        }

        /// The persisted last-account id, if any.
        pub async fn load_last_account_id(&self) -> SeamResult<Option<Vec<u8>>> {
            read_file_opt(&self.last_account_id_path)
                .map_err(|err| seam_err("file_credential_store load_last_account_id", &err))
        }

        /// Deletes the persisted last-account id. Idempotent.
        pub async fn clear_last_account_id(&self) -> SeamResult<()> {
            remove_file_durable(&self.last_account_id_path)
                .map_err(|err| seam_err("file_credential_store clear_last_account_id", &err))
        }
    }

    impl CredentialStore for FileCredentialStore {
        async fn store_refresh_token(&self, refresh_token: &[u8]) -> SeamResult<()> {
            atomic_write(&self.refresh_token_path, refresh_token)
                .map_err(|err| seam_err("file_credential_store store_refresh_token", &err))
        }

        async fn load_refresh_token(&self) -> SeamResult<Option<Vec<u8>>> {
            read_file_opt(&self.refresh_token_path)
                .map_err(|err| seam_err("file_credential_store load_refresh_token", &err))
        }

        async fn clear_refresh_token(&self) -> SeamResult<()> {
            remove_file_durable(&self.refresh_token_path)
                .map_err(|err| seam_err("file_credential_store clear_refresh_token", &err))
        }
    }
}
