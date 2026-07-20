//! Desktop [`Http`]: a `reqwest` byte mover.

use cipherbox_engine::seams::{Http, HttpMethod, HttpRequest, HttpResponse, SeamError, SeamResult};

/// Plain HTTP for the hand-written API client, the trustless gateway read
/// path, and BYO providers (blueprint/engine.md "Http", desktop column).
///
/// A pure byte mover over `reqwest` with rustls: it sends exactly the
/// request the engine describes — no headers the engine did not ask for —
/// and returns the response verbatim. Non-2xx statuses are responses, not
/// errors; a seam `Err` is reserved for transport-level failure (unreachable,
/// aborted). The rotating refresh token is injected by the engine as an
/// `Authorization`/cookie header here; this seam never persists it.
#[derive(Debug, Clone)]
pub struct ReqwestHttp {
    client: reqwest::Client,
}

impl ReqwestHttp {
    /// Builds an HTTP seam over a fresh `reqwest` client.
    pub fn new() -> SeamResult<Self> {
        let client = reqwest::Client::builder()
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

impl Http for ReqwestHttp {
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse> {
        let mut builder = self
            .client
            .request(map_method(request.method), &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
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
