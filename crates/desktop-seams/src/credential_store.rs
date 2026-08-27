//! Desktop [`CredentialStore`]: the OS keyring, plus a feature-gated
//! file-backed test double.

use std::sync::Arc;

use cipherbox_engine::seams::{CredentialStore, SeamError, SeamResult};
use zeroize::Zeroizing;

use crate::offload::Offload;

/// Keyring account label for the rotating refresh token.
const REFRESH_TOKEN_ACCOUNT: &str = "refresh-token";
/// Keyring account label for the last-account id.
const LAST_ACCOUNT_ID_ACCOUNT: &str = "last-account-id";
/// Keyring account label for the Core Kit store's wrapping key.
const CORE_KIT_WRAPPING_KEY_ACCOUNT: &str = "core-kit-wrapping-key";

/// Custody of the key that seals the Core Kit store
/// ([`SealedCoreKitStore`](crate::SealedCoreKitStore)).
///
/// A trait rather than an inherent method, because the store is written against
/// whichever credential store the host built: the keyring in production, the
/// file double on a headless runner.
pub trait CoreKitWrappingKey {
    /// Persists the wrapping key, replacing any previous one.
    fn store_core_kit_wrapping_key(&self, key: &[u8]) -> impl Future<Output = SeamResult<()>>;
    /// The persisted wrapping key, if this device holds one.
    fn load_core_kit_wrapping_key(
        &self,
    ) -> impl Future<Output = SeamResult<Option<Zeroizing<Vec<u8>>>>>;
    /// Deletes the wrapping key. Idempotent.
    fn clear_core_kit_wrapping_key(&self) -> impl Future<Output = SeamResult<()>>;
}

fn entry(service: &str, account: &str) -> SeamResult<keyring::Entry> {
    keyring::Entry::new(service, account)
        .map_err(|err| SeamError::new(format!("keyring entry: {err}")))
}

/// Refresh-token persistence in the OS keyring (Apple Keychain, Windows
/// Credential Manager, or the Secret Service on Linux) —
/// blueprint/engine.md "CredentialStore", desktop column;
/// blueprint/desktop.md "OS keychain".
///
/// Holds the rotating refresh token, the last-account id, and the Core Kit
/// store's wrapping key, under one service name, one account each — never a
/// seed, and never the short-lived access JWT (which lives in engine memory
/// only). Every value is stored as opaque secret bytes.
///
/// The wrapping key is the one key this store holds, and it is the reason it
/// holds it: what it seals is local state only, it derives nothing in the KDF
/// catalog, and it never leaves this device (blueprint/desktop.md "OS
/// keychain").
///
/// `Debug` is derived and safe: the struct carries only the service name and a
/// queue handle, both non-secret; no token is ever held in memory by this
/// handle.
///
/// No method on this path is an `async fn`: each hands back the worker-queue
/// future, so the queue slot is taken when the method is called rather than
/// when its future is first polled. One `async fn` anywhere between the caller
/// and the worker queue would restore the ordering hazard the queue exists to
/// remove — a write landing after the logout delete that was issued later.
#[derive(Debug, Clone)]
pub struct KeyringCredentialStore {
    service: String,
    offload: Arc<Offload>,
}

impl KeyringCredentialStore {
    /// A credential store under one keyring service name (e.g.
    /// `"com.cipherbox.desktop"`). One store per running app: clones share the
    /// one worker queue, which is what keeps a logout delete ordered behind a
    /// write the keyring is still prompting for.
    pub fn new(service: impl Into<String>) -> SeamResult<Self> {
        Ok(Self {
            service: service.into(),
            offload: Arc::new(Offload::start("keyring")?),
        })
    }

    /// Stores an opaque secret under one account, replacing any previous
    /// value.
    fn store_secret(
        &self,
        account: &'static str,
        secret: &[u8],
    ) -> impl Future<Output = SeamResult<()>> + use<> {
        let service = self.service.clone();
        // The worker owns this copy outright, so it is wiped where it dies.
        let secret = Zeroizing::new(secret.to_vec());
        self.offload.run("keyring set", move || {
            entry(&service, account)?
                .set_secret(&secret)
                .map_err(|err| SeamError::new(format!("keyring set: {err}")))
        })
    }

    /// Loads an opaque secret, mapping a missing entry to `None`.
    fn load_secret(
        &self,
        account: &'static str,
    ) -> impl Future<Output = SeamResult<Option<Vec<u8>>>> + use<> {
        let service = self.service.clone();
        self.offload.run("keyring get", move || {
            match entry(&service, account)?.get_secret() {
                Ok(secret) => Ok(Some(secret)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(err) => Err(SeamError::new(format!("keyring get: {err}"))),
            }
        })
    }

    /// Deletes an account's secret. Idempotent (a missing entry is success).
    fn clear_secret(&self, account: &'static str) -> impl Future<Output = SeamResult<()>> + use<> {
        let service = self.service.clone();
        self.offload.run("keyring delete", move || {
            match entry(&service, account)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(err) => Err(SeamError::new(format!("keyring delete: {err}"))),
            }
        })
    }

    /// Persists the last-account id — the only extra datum this store holds
    /// beyond the refresh token, used by the shell to pick the account
    /// directory on next launch (blueprint/desktop.md "last-account id").
    pub fn store_last_account_id(
        &self,
        account_id: &[u8],
    ) -> impl Future<Output = SeamResult<()>> + use<> {
        self.store_secret(LAST_ACCOUNT_ID_ACCOUNT, account_id)
    }

    /// The persisted last-account id, if any.
    pub fn load_last_account_id(
        &self,
    ) -> impl Future<Output = SeamResult<Option<Vec<u8>>>> + use<> {
        self.load_secret(LAST_ACCOUNT_ID_ACCOUNT)
    }

    /// Deletes the persisted last-account id. Idempotent.
    pub fn clear_last_account_id(&self) -> impl Future<Output = SeamResult<()>> + use<> {
        self.clear_secret(LAST_ACCOUNT_ID_ACCOUNT)
    }
}

impl CoreKitWrappingKey for KeyringCredentialStore {
    fn store_core_kit_wrapping_key(&self, key: &[u8]) -> impl Future<Output = SeamResult<()>> {
        self.store_secret(CORE_KIT_WRAPPING_KEY_ACCOUNT, key)
    }

    fn load_core_kit_wrapping_key(
        &self,
    ) -> impl Future<Output = SeamResult<Option<Zeroizing<Vec<u8>>>>> {
        // The queue slot is taken here, before the wrapper future is built, so
        // the ordering the worker queue exists to give is not lost to it.
        let loading = self.load_secret(CORE_KIT_WRAPPING_KEY_ACCOUNT);
        async move { loading.await.map(|held| held.map(Zeroizing::new)) }
    }

    fn clear_core_kit_wrapping_key(&self) -> impl Future<Output = SeamResult<()>> {
        self.clear_secret(CORE_KIT_WRAPPING_KEY_ACCOUNT)
    }
}

impl CredentialStore for KeyringCredentialStore {
    fn store_refresh_token(&self, refresh_token: &[u8]) -> impl Future<Output = SeamResult<()>> {
        self.store_secret(REFRESH_TOKEN_ACCOUNT, refresh_token)
    }

    fn load_refresh_token(&self) -> impl Future<Output = SeamResult<Option<Vec<u8>>>> {
        self.load_secret(REFRESH_TOKEN_ACCOUNT)
    }

    fn clear_refresh_token(&self) -> impl Future<Output = SeamResult<()>> {
        self.clear_secret(REFRESH_TOKEN_ACCOUNT)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyringCredentialStore;
    use std::sync::Arc;

    #[test]
    fn a_cloned_store_shares_one_ordering_queue() {
        let store =
            KeyringCredentialStore::new("com.cipherbox.desktop.test").expect("worker started");
        let handed_to_the_shell = store.clone();
        assert!(Arc::ptr_eq(&store.offload, &handed_to_the_shell.offload));
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
    use zeroize::Zeroizing;

    use crate::credential_store::CoreKitWrappingKey;
    use crate::fs_util::{atomic_write, ensure_dir, read_file_opt, remove_file_durable, seam_err};

    /// File-backed credential store — TEST DOUBLE ONLY. Values are written
    /// in plaintext; never use it for a real token. See the module note.
    pub struct FileCredentialStore {
        refresh_token_path: PathBuf,
        last_account_id_path: PathBuf,
        core_kit_wrapping_key_path: PathBuf,
    }

    impl FileCredentialStore {
        /// Opens (creating if absent) a file-backed store rooted at `dir`.
        pub fn open(dir: impl AsRef<Path>) -> SeamResult<Self> {
            let dir = dir.as_ref();
            ensure_dir(dir).map_err(|err| seam_err("file_credential_store open", &err))?;
            Ok(Self {
                refresh_token_path: dir.join("refresh_token"),
                last_account_id_path: dir.join("last_account_id"),
                core_kit_wrapping_key_path: dir.join("core_kit_wrapping_key"),
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

    impl CoreKitWrappingKey for FileCredentialStore {
        async fn store_core_kit_wrapping_key(&self, key: &[u8]) -> SeamResult<()> {
            atomic_write(&self.core_kit_wrapping_key_path, key)
                .map_err(|err| seam_err("file_credential_store store_core_kit_wrapping_key", &err))
        }

        async fn load_core_kit_wrapping_key(&self) -> SeamResult<Option<Zeroizing<Vec<u8>>>> {
            read_file_opt(&self.core_kit_wrapping_key_path)
                .map(|held| held.map(Zeroizing::new))
                .map_err(|err| seam_err("file_credential_store load_core_kit_wrapping_key", &err))
        }

        async fn clear_core_kit_wrapping_key(&self) -> SeamResult<()> {
            remove_file_durable(&self.core_kit_wrapping_key_path)
                .map_err(|err| seam_err("file_credential_store clear_core_kit_wrapping_key", &err))
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
