//! `Http` — plain HTTP transport (blueprint/engine.md).

use core::fmt;

use super::{SeamError, SeamResult};

/// The `Content-Length` response header, consulted by [`Http::send_capped`] for
/// an up-front reject before any body bytes are read.
pub const CONTENT_LENGTH: &str = "content-length";

/// Why a size-capped fetch ([`Http::send_capped`]) did not return a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CappedFetchError {
    /// Transport-level failure (unreachable, aborted) — the seam's reserved
    /// `Err`, an availability signal, not a trust or size decision.
    Transport(SeamError),
    /// The response body would exceed `max_bytes`, rejected at the transport
    /// before the whole body is buffered so a lying/huge gateway cannot force an
    /// unbounded allocation (the peak-memory bound of #787). Fail-closed and
    /// terminal: an over-cap block is never adoptable from any source.
    BodyTooLarge {
        /// The observed lower bound on the body size — the declared
        /// `Content-Length` if that alone exceeded the cap, else the bytes
        /// accumulated when the streaming read passed the cap.
        observed: usize,
        /// The enforced ceiling (`max_bytes`).
        limit: usize,
    },
}

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

    /// Like [`send`](Self::send), but fails closed if the response body would
    /// exceed `max_bytes`, so a lying/huge gateway cannot force an over-cap
    /// adoption. The strength of the bound differs by transport:
    ///
    /// - Desktop (`reqwest`) enforces it *while* reading the body — a
    ///   `Content-Length` pre-check plus a capped streaming read that aborts
    ///   past the cap — the true peak-memory bound at the content fetch
    ///   boundary (#787).
    /// - WASM (the JS fetch bridge) applies a `Content-Length` pre-check plus a
    ///   post-buffer size check: it fails closed on size but is *not* a
    ///   peak-memory bound, because the JS seam buffers the whole body before it
    ///   reaches Rust. The streaming bound is tracked in #641.
    ///
    /// The default implementation only backstops: it buffers the whole body via
    /// [`send`](Self::send) and then checks the length, which bounds nothing. It
    /// is for seams that never carry untrusted content bodies (the fakes, the
    /// API-only contract transport).
    async fn send_capped(
        &self,
        request: HttpRequest,
        max_bytes: usize,
    ) -> Result<HttpResponse, CappedFetchError> {
        let response = self
            .send(request)
            .await
            .map_err(CappedFetchError::Transport)?;
        if response.body.len() > max_bytes {
            return Err(CappedFetchError::BodyTooLarge {
                observed: response.body.len(),
                limit: max_bytes,
            });
        }
        Ok(response)
    }
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
