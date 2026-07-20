//! `Http` — plain HTTP transport (blueprint/engine.md).

use core::fmt;

use super::SeamResult;

/// Formats headers as their names only. Header values ride this seam
/// carrying live credentials (`Authorization` bearer JWTs, refresh
/// cookies) and must never reach logs.
struct HeaderNames<'a>(&'a [(String, String)]);

impl fmt::Debug for HeaderNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| name))
            .finish()
    }
}

/// Formats a body as its byte length only.
struct BodyLen(usize);

impl fmt::Debug for BodyLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

/// HTTP method of a [`HttpRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// GET
    Get,
    /// POST
    Post,
    /// PUT
    Put,
    /// PATCH
    Patch,
    /// DELETE
    Delete,
    /// HEAD
    Head,
}

/// One HTTP request, fully described by the engine.
///
/// `Debug` is hand-written: header values and bodies carry credentials and
/// are redacted to names and byte lengths (security rule 2 — never log
/// sensitive material).
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Request method.
    pub method: HttpMethod,
    /// Absolute URL.
    pub url: String,
    /// Header name/value pairs, in send order.
    pub headers: Vec<(String, String)>,
    /// Request body bytes, if any.
    pub body: Option<Vec<u8>>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &HeaderNames(&self.headers))
            .field("body", &self.body.as_ref().map(|body| BodyLen(body.len())))
            .finish()
    }
}

/// One HTTP response, returned verbatim to the engine.
///
/// `Debug` is hand-written: header values (`Set-Cookie`) and bodies are
/// redacted to names and byte lengths, like [`HttpRequest`].
#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Header name/value pairs as received.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &HeaderNames(&self.headers))
            .field("body", &BodyLen(self.body.len()))
            .finish()
    }
}

/// Plain HTTP for the hand-written API client, the trustless gateway read
/// path, and BYO pin providers.
///
/// A pure byte mover: the transport adds no headers the engine did not ask
/// for, follows the host's cookie policy (web rides the HTTP-only refresh
/// cookie here via `credentials: 'include'`, which is why web's
/// [`super::CredentialStore`] is a no-op), and never interprets bodies.
/// Non-2xx statuses are responses, not errors — a seam `Err` is reserved
/// for transport-level failure (unreachable, aborted).
///
/// No conformance kit ships for this seam: it has no seam-local durable
/// semantics; its behavior is exercised end-to-end by the live contract
/// suite (blueprint/testing.md).
pub trait Http {
    /// Sends one request and resolves with the complete response.
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_debug_redacts_header_values_and_body() {
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: "https://api.example/auth/refresh".into(),
            headers: vec![("Authorization".into(), "Bearer secret-jwt".into())],
            body: Some(b"refresh-token-bytes".to_vec()),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-jwt"), "header values must not leak");
        assert!(!debug.contains("refresh-token-bytes"), "body must not leak");
        assert!(debug.contains("Authorization"), "header names stay visible");
        assert!(debug.contains("<19 bytes>"), "body renders as a length");
    }

    #[test]
    fn response_debug_redacts_header_values_and_body() {
        let response = HttpResponse {
            status: 200,
            headers: vec![("Set-Cookie".into(), "refresh=secret-cookie".into())],
            body: b"account-payload".to_vec(),
        };
        let debug = format!("{response:?}");
        assert!(!debug.contains("secret-cookie"), "cookie must not leak");
        assert!(!debug.contains("account-payload"), "body must not leak");
        assert!(debug.contains("Set-Cookie") && debug.contains("200"));
    }
}
