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
use std::time::Duration;

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
    /// Builds a client with a finite total request timeout so a hung CI stack
    /// fails the suite instead of blocking it forever.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("build reqwest client"),
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
        // The per-request deadline the engine asked for, narrower than the
        // client-wide ceiling `new` sets; dropping it would leave a call the
        // engine bounded running to the 30s budget.
        if let Some(timeout_ms) = request.timeout_ms {
            builder = builder.timeout(Duration::from_millis(timeout_ms));
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

/// A fresh random secp256k1 identity scalar (crypto lives in core; this loops
/// over the OS RNG until it draws a valid one). Held by the caller where a test
/// needs the identity key itself and not only a login.
pub fn random_identity_scalar() -> [u8; 32] {
    loop {
        let mut scalar = [0u8; 32];
        getrandom::getrandom(&mut scalar).expect("os rng");
        if IdentityChallengeSigner::from_scalar(&scalar).is_some() {
            return scalar;
        }
    }
}

/// A fresh random secp256k1 identity signer.
pub fn random_identity_signer() -> IdentityChallengeSigner {
    IdentityChallengeSigner::from_scalar(&random_identity_scalar()).expect("a validated scalar")
}

/// Decode a 64-char hex string into a 32-byte scalar. `None` on any malformed
/// input.
pub fn hex_to_scalar(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    hex_to_bytes(hex_str)?.try_into().ok()
}

/// Decode an even-length hex string into bytes. `None` on any malformed input.
pub fn hex_to_bytes(hex_str: &str) -> Option<Vec<u8>> {
    hex::decode(hex_str).ok()
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

/// The base URL of the stack's IPFS gateway, from `CONTRACT_GATEWAY_URL` — how
/// a read path fetches a block the ingress pinned. Set by the CI job alongside
/// [`api_url`]; a suite that has an API but no gateway is a misconfiguration,
/// so the leg that needs it fails loudly rather than skipping.
pub fn gateway_url() -> Option<String> {
    non_empty("CONTRACT_GATEWAY_URL")
}

/// The shared test-login secret; must equal the API's `TEST_LOGIN_SECRET`.
pub fn test_login_secret() -> String {
    std::env::var("CONTRACT_TEST_LOGIN_SECRET").unwrap_or_else(|_| "contract-suite-secret".into())
}

fn non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}
