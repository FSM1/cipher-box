//! The seams the harness drives the engine's API client over.
//!
//! The transport is the desktop production seam, not a harness-local one, so a
//! run exercises the same byte mover the shipping client uses.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use cipherbox_desktop_seams::ReqwestHttp;
use cipherbox_engine::seams::{CredentialStore, SeamResult};

/// Build the one transport every virtual client clones. Clones share the
/// connection pool, so the harness measures the API rather than repeated TLS
/// handshakes.
pub(crate) fn build_http() -> Result<ReqwestHttp, String> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|error| format!("build reqwest client: {error}"))?;
    Ok(ReqwestHttp::with_client(client))
}

/// An in-memory refresh-token store, one per virtual client so their sessions
/// stay independent. The engine's in-memory fake lives behind its `test-kit`
/// feature, which a normal dependency must not enable.
#[derive(Clone, Default)]
pub(crate) struct MemoryCredentialStore {
    inner: Rc<RefCell<Option<Vec<u8>>>>,
}

impl CredentialStore for MemoryCredentialStore {
    async fn store_refresh_token(&self, refresh_token: &[u8]) -> SeamResult<()> {
        *self.inner.borrow_mut() = Some(refresh_token.to_vec());
        Ok(())
    }

    async fn load_refresh_token(&self) -> SeamResult<Option<Vec<u8>>> {
        Ok(self.inner.borrow().clone())
    }

    async fn clear_refresh_token(&self) -> SeamResult<()> {
        *self.inner.borrow_mut() = None;
        Ok(())
    }
}
