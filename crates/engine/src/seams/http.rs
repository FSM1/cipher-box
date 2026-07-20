//! `Http` — plain HTTP transport (blueprint/engine.md).

use super::SeamResult;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// One HTTP response, returned verbatim to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Header name/value pairs as received.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
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
