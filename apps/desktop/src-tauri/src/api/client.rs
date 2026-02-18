//! HTTP client with auth header injection and desktop client type header.
//!
//! All requests include `X-Client-Type: desktop` header so the backend
//! returns refresh tokens in the response body instead of cookies.

use reqwest::{Client, Response};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

/// HTTP client wrapper for CipherBox API communication.
///
/// Manages base URL, access token, and ensures all requests
/// include the `X-Client-Type: desktop` header.
pub struct ApiClient {
    client: Client,
    base_url: String,
    access_token: Arc<RwLock<Option<String>>>,
}

impl ApiClient {
    /// Create a new API client with the given base URL.
    pub fn new(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: Arc::new(RwLock::new(None)),
        }
    }

    /// Store the access token for authenticated requests.
    pub async fn set_access_token(&self, token: String) {
        let mut guard = self.access_token.write().await;
        *guard = Some(token);
    }

    /// Clear the access token (used on logout).
    pub async fn clear_access_token(&self) {
        let mut guard = self.access_token.write().await;
        *guard = None;
    }

    /// Send an authenticated GET request to a relative API path.
    pub async fn authenticated_get(&self, path: &str) -> Result<Response, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        eprintln!(">>> authenticated_get: acquiring token lock for {}", path);
        let token = self.access_token.read().await;
        eprintln!(">>> authenticated_get: token lock acquired, sending {}", path);

        let mut builder = self
            .client
            .get(&url)
            .header("X-Client-Type", "desktop");

        if let Some(ref t) = *token {
            builder = builder.bearer_auth(t);
        }

        let result = builder.send().await;
        eprintln!(">>> authenticated_get: send complete for {}", path);
        result
    }

    /// Send an authenticated POST request with a JSON body to a relative API path.
    pub async fn authenticated_post<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<Response, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.access_token.read().await;

        let mut builder = self
            .client
            .post(&url)
            .header("X-Client-Type", "desktop")
            .json(body);

        if let Some(ref t) = *token {
            builder = builder.bearer_auth(t);
        }

        builder.send().await
    }

    /// Send an unauthenticated POST request with a JSON body to a relative API path.
    /// Used for login and refresh where no access token is available yet.
    pub async fn post<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<Response, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .post(&url)
            .header("X-Client-Type", "desktop")
            .json(body)
            .send()
            .await
    }

    /// Fetch raw bytes from an absolute URL (used for IPFS content fetching).
    pub async fn get_bytes(&self, url: &str) -> Result<Vec<u8>, reqwest::Error> {
        let resp = self.client.get(url).send().await?;
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }

    /// Send an authenticated multipart POST request (used for IPFS file uploads).
    pub async fn authenticated_multipart_post(
        &self,
        path: &str,
        form: reqwest::multipart::Form,
    ) -> Result<Response, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.access_token.read().await;

        let mut builder = self
            .client
            .post(&url)
            .header("X-Client-Type", "desktop")
            .multipart(form);

        if let Some(ref t) = *token {
            builder = builder.bearer_auth(t);
        }

        builder.send().await
    }
}
