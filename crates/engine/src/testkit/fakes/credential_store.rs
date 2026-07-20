//! In-memory [`CredentialStore`] fake.

use std::sync::{Arc, Mutex};

use crate::seams::{CredentialStore, SeamResult};

/// In-memory refresh-token store (models the desktop keychain shape).
/// Clones share state ("reopen").
#[derive(Clone, Default)]
pub struct InMemoryCredentialStore {
    inner: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CredentialStore for InMemoryCredentialStore {
    async fn store_refresh_token(&self, refresh_token: &[u8]) -> SeamResult<()> {
        *self.inner.lock().expect("lock") = Some(refresh_token.to_vec());
        Ok(())
    }

    async fn load_refresh_token(&self) -> SeamResult<Option<Vec<u8>>> {
        Ok(self.inner.lock().expect("lock").clone())
    }

    async fn clear_refresh_token(&self) -> SeamResult<()> {
        *self.inner.lock().expect("lock") = None;
        Ok(())
    }
}
