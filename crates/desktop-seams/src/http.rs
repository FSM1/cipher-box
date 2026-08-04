//! Desktop [`Http`]: a `reqwest` byte mover.

use core::time::Duration;

use cipherbox_engine::seams::{
    CappedFetchError, Http, HttpMethod, HttpRequest, HttpResponse, SeamError, SeamResult,
};

/// Plain HTTP for the hand-written API client, the trustless gateway read
/// path, and BYO providers (blueprint/engine.md "Http", desktop column).
///
/// A pure byte mover over `reqwest` with rustls: it sends exactly the
/// request the engine describes — no headers the engine did not ask for —
/// and returns the response verbatim. Non-2xx statuses are responses, not
/// errors; a seam `Err` is reserved for transport-level failure (unreachable,
/// aborted). The rotating refresh token is injected by the engine as an
/// `Authorization`/cookie header here; this seam never persists it. The client
/// [`new`](Self::new) builds keeps no cookie jar, so desktop has no ambient
/// credentials for [`cipherbox_engine::seams::HttpCredentials`] to scope;
/// a [`with_client`](Self::with_client) caller owns that policy.
#[derive(Debug, Clone)]
pub struct ReqwestHttp {
    client: reqwest::Client,
}

impl ReqwestHttp {
    /// Builds an HTTP seam over a fresh `reqwest` client.
    ///
    /// A connect timeout bounds the handshake, so a dead or black-hole host
    /// fails fast instead of hanging the engine task forever. The whole-request
    /// bound is per request class and rides [`HttpRequest::timeout_ms`], so a
    /// nonce fetch and a content-chunk upload do not share one client-wide
    /// deadline (#939).
    pub fn new() -> SeamResult<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                // The engine decides over which transport a request carrying an
                // `Authorization` header may go (blueprint/engine.md "Content
                // plane"). A redirect that downgrades to plaintext would carry
                // the credential onto the clear network past that decision, so
                // it is surfaced as the 3xx it is rather than followed.
                let downgrade = attempt.url().scheme() == "http"
                    && attempt
                        .previous()
                        .last()
                        .is_some_and(|previous| previous.scheme() == "https");
                if downgrade {
                    attempt.stop()
                } else if attempt.previous().len() > 10 {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .map_err(|err| SeamError::new(format!("http client build: {err}")))?;
        Ok(Self { client })
    }

    /// Builds an HTTP seam over a caller-supplied `reqwest` client (shared
    /// connection pool, custom timeouts).
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl ReqwestHttp {
    /// Send the request and return the status, headers, and the not-yet-read
    /// `reqwest` response — the shared prelude for buffered and capped reads.
    async fn dispatch(
        &self,
        request: HttpRequest,
    ) -> SeamResult<(u16, Vec<(String, String)>, reqwest::Response)> {
        let mut builder = self
            .client
            .request(map_method(request.method), &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        if let Some(timeout_ms) = request.timeout_ms {
            builder = builder.timeout(Duration::from_millis(timeout_ms));
        }

        let response = builder
            .send()
            .await
            .map_err(|err| SeamError::new(format!("http send: {err}")))?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    // Header values can be non-UTF-8; keep them lossless-ish
                    // without failing the whole response on an odd byte.
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        Ok((status, headers, response))
    }
}

impl Http for ReqwestHttp {
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse> {
        let (status, headers, response) = self.dispatch(request).await?;
        let body = response
            .bytes()
            .await
            .map_err(|err| SeamError::new(format!("http body: {err}")))?
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    async fn send_capped(
        &self,
        request: HttpRequest,
        max_bytes: usize,
    ) -> Result<HttpResponse, CappedFetchError> {
        let (status, headers, mut response) = self
            .dispatch(request)
            .await
            .map_err(CappedFetchError::Transport)?;

        // Reject a body that declares itself over the cap before reading a byte;
        // a missing or lying Content-Length is still bounded by the streaming
        // drain below (#787).
        if let Some(declared) = response.content_length() {
            if declared > max_bytes as u64 {
                return Err(CappedFetchError::BodyTooLarge {
                    observed: usize::try_from(declared).unwrap_or(usize::MAX),
                    limit: max_bytes,
                });
            }
        }

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|err| {
            CappedFetchError::Transport(SeamError::new(format!("http body: {err}")))
        })? {
            if body.len() + chunk.len() > max_bytes {
                return Err(CappedFetchError::BodyTooLarge {
                    observed: body.len() + chunk.len(),
                    limit: max_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

fn map_method(method: HttpMethod) -> reqwest::Method {
    match method {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Put => reqwest::Method::PUT,
        HttpMethod::Patch => reqwest::Method::PATCH,
        HttpMethod::Delete => reqwest::Method::DELETE,
        HttpMethod::Head => reqwest::Method::HEAD,
    }
}
