//! The session credential store the `e2e-hook` build runs on.

use std::sync::{Arc, Mutex};

use cipherbox_engine::seams::{CredentialStore, SeamError, SeamResult};
use zeroize::Zeroizing;

/// A session-lifetime [`CredentialStore`]. Nothing at rest: a headless runner
/// has no OS keyring, and this build always starts from a supplied login
/// secret. Clones share the one held value, and that value is zeroized when the
/// last clone drops.
#[derive(Clone, Default)]
pub struct MemoryCredentialStore {
    held: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
}

impl MemoryCredentialStore {
    /// The keyring store's own method, which the session teardown calls. This
    /// store keeps nothing past its process, so the clear has nothing to drop.
    pub async fn clear_last_account_id(&self) -> SeamResult<()> {
        Ok(())
    }
}

impl CredentialStore for MemoryCredentialStore {
    async fn store_refresh_token(&self, refresh_token: &[u8]) -> SeamResult<()> {
        *self.held.lock().map_err(|_| unreadable())? = Some(Zeroizing::new(refresh_token.to_vec()));
        Ok(())
    }

    async fn load_refresh_token(&self) -> SeamResult<Option<Vec<u8>>> {
        let held = self.held.lock().map_err(|_| unreadable())?;
        Ok(held.as_ref().map(|token| token.as_slice().to_vec()))
    }

    async fn clear_refresh_token(&self) -> SeamResult<()> {
        *self.held.lock().map_err(|_| unreadable())? = None;
        Ok(())
    }
}

fn unreadable() -> SeamError {
    SeamError::new("memory_credential_store: the held value is unreadable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reports_none_before_anything_is_stored() {
        let store = MemoryCredentialStore::default();
        assert_eq!(store.load_refresh_token().await, Ok(None));
    }

    #[tokio::test]
    async fn round_trips_one_stored_value() {
        let store = MemoryCredentialStore::default();
        store.store_refresh_token(b"a-token").await.expect("stored");
        assert_eq!(
            store.load_refresh_token().await,
            Ok(Some(b"a-token".to_vec()))
        );
    }

    #[tokio::test]
    async fn a_clear_leaves_nothing_to_load() {
        let store = MemoryCredentialStore::default();
        store.store_refresh_token(b"a-token").await.expect("stored");
        store.clear_refresh_token().await.expect("cleared");
        assert_eq!(store.load_refresh_token().await, Ok(None));
    }

    /// The engine holds one clone and the seam set holds another, so a write
    /// through either must be the one value.
    #[tokio::test]
    async fn clones_share_the_one_held_value() {
        let store = MemoryCredentialStore::default();
        let cloned = store.clone();
        store.store_refresh_token(b"a-token").await.expect("stored");
        assert_eq!(
            cloned.load_refresh_token().await,
            Ok(Some(b"a-token".to_vec()))
        );
    }
}
