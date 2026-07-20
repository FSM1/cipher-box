//! Production-shaped seam implementations and helpers for the live contract
//! suite (blueprint/testing.md).
//!
//! The tests in `tests/contract.rs` build the engine's real [`ApiClient`] over
//! [`ReqwestHttp`] (a real HTTP client, the desktop `Http` seam's shape) and
//! [`MemoryCredentialStore`] (models the OS keychain), point it at the CI
//! stack, and assert API-side effects. No mocks: contract drift between server
//! behavior and the hand-written client fails a test run, not a grep.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use cipherbox_engine::api::IdentityChallengeSigner;
use cipherbox_engine::seams::{
    CredentialStore, Http, HttpMethod, HttpRequest, HttpResponse, SeamError, SeamResult,
};

/// The desktop-shaped `Http` seam: a real reqwest client. Featureless reqwest
/// (no TLS backend) is enough — the CI stack is reached over plain http.
#[derive(Clone, Default)]
pub struct ReqwestHttp {
    client: reqwest::Client,
}

impl ReqwestHttp {
    /// Builds a client with reqwest defaults.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Http for ReqwestHttp {
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse> {
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Head => reqwest::Method::HEAD,
        };
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let response = builder
            .send()
            .await
            .map_err(|error| SeamError::new(format!("reqwest send: {error}")))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|error| SeamError::new(format!("reqwest body: {error}")))?
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// An in-memory refresh-token store modelling the desktop OS keychain: a token
/// stored here survives across `ApiClient` calls within one test.
#[derive(Clone, Default)]
pub struct MemoryCredentialStore {
    inner: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CredentialStore for MemoryCredentialStore {
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

/// A fresh random secp256k1 identity signer (crypto lives in core; this loops
/// over the OS RNG until it draws a valid scalar).
pub fn random_identity_signer() -> IdentityChallengeSigner {
    loop {
        let mut scalar = [0u8; 32];
        getrandom::getrandom(&mut scalar).expect("os rng");
        if let Some(signer) = IdentityChallengeSigner::from_scalar(&scalar) {
            return signer;
        }
    }
}

/// Decode a 64-char hex string into a 32-byte scalar. `None` on any malformed
/// input.
pub fn hex_to_scalar(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = (hex.as_bytes()[index * 2] as char).to_digit(16)?;
        let low = (hex.as_bytes()[index * 2 + 1] as char).to_digit(16)?;
        *byte = ((high << 4) | low) as u8;
    }
    Some(out)
}

/// The API base URL for the live stack, from `CONTRACT_API_URL`. When unset the
/// suite skips (there is no stack to hit); the merge-blocking CI job always
/// sets it, so the assertions always run there.
pub fn api_url() -> Option<String> {
    non_empty("CONTRACT_API_URL")
}

/// The base URL of a second API instance booted in production mode, from
/// `CONTRACT_API_PROD_URL`, used to assert test-login is hard-blocked in
/// production. Optional locally; set by the CI job.
pub fn prod_api_url() -> Option<String> {
    non_empty("CONTRACT_API_PROD_URL")
}

/// The shared test-login secret; must equal the API's `TEST_LOGIN_SECRET`.
pub fn test_login_secret() -> String {
    std::env::var("CONTRACT_TEST_LOGIN_SECRET").unwrap_or_else(|_| "contract-suite-secret".into())
}

fn non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}
