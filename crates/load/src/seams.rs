//! The production-shaped seams the harness drives the engine's API client over.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use cipherbox_engine::seams::{
    CredentialStore, Http, HttpMethod, HttpRequest, HttpResponse, SeamError, SeamResult,
};

/// A real reqwest client. Clones share one connection pool, so every virtual
/// client should be built from a clone rather than its own [`LoadHttp::new`] —
/// otherwise the harness measures TCP and TLS handshakes instead of the API.
#[derive(Clone)]
pub struct LoadHttp {
    client: reqwest::Client,
}

impl LoadHttp {
    pub fn new() -> Result<Self, String> {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map(|client| Self { client })
            .map_err(|error| format!("build reqwest client: {error}"))
    }

    /// A direct request, for the read accelerator and other surfaces that are
    /// not part of the API client.
    pub async fn get(&self, url: &str, bearer: Option<&str>) -> Result<(u16, Vec<u8>), String> {
        let mut builder = self.client.get(url);
        if let Some(token) = bearer {
            builder = builder.bearer_auth(token);
        }
        let response = builder
            .send()
            .await
            .map_err(|error| format!("gateway send: {error}"))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|error| format!("gateway body: {error}"))?
            .to_vec();
        Ok((status, body))
    }
}

impl Http for LoadHttp {
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

/// An in-memory refresh-token store: one per virtual client, so their sessions
/// stay independent.
#[derive(Clone, Default)]
pub struct MemoryCredentialStore {
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
