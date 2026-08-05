//! `Http` — plain HTTP transport (blueprint/engine.md).

use core::fmt;

use super::{SeamError, SeamResult};

/// Why a size-capped fetch ([`Http::send_capped`]) did not return a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CappedFetchError {
    /// Transport-level failure (unreachable, aborted) — the seam's reserved
    /// `Err`, an availability signal, not a trust or size decision.
    Transport(SeamError),
    /// The response body would exceed `max_bytes`, rejected at the transport
    /// before the whole body is buffered so a lying/huge gateway cannot force an
    /// unbounded allocation. Fail-closed and terminal: an over-cap block is
    /// never adoptable from any source.
    BodyTooLarge {
        /// The observed lower bound on the body size — the declared
        /// `Content-Length` if that alone exceeded the cap, else the bytes
        /// drained so far including the chunk that passed it.
        observed: usize,
        /// The enforced ceiling (`max_bytes`).
        limit: usize,
    },
}

/// The `Authorization` header name — one spelling for every splice site.
pub const AUTHORIZATION: &str = "Authorization";

/// A bearer credential refused before it became a header value. Carries
/// nothing: the token itself must never reach an error string or a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBearer;

/// Builds the `Authorization: Bearer …` pair for `token`, refusing an empty one
/// or one carrying a byte outside visible ASCII (`0x21..=0x7e`).
///
/// A header value is the host transport's input, and a control character or
/// space in one splits or injects a header — which of the two happens depends
/// on the transport, so the decision does not belong to the seam. The engine's
/// three bearer sources differ in trust class (a member's BYO config token, an
/// access token decoded out of an `/auth/*` body, a gateway source's token) but
/// not in this obligation, so it lives once, here, beside the request type that
/// carries it.
pub fn bearer_header(token: &str) -> Result<(String, String), InvalidBearer> {
    if token.is_empty() || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(InvalidBearer);
    }
    Ok((AUTHORIZATION.to_owned(), format!("Bearer {token}")))
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

/// Whether the transport may attach the host's *ambient* credentials — the
/// browser's HTTP-only refresh cookie — to a request.
///
/// Defaults to [`Omit`](Self::Omit): ambient authority is scoped to the API
/// origin, so the per-leaf gateway and BYO-provider fetches carry none. Those
/// reads need no authority (`content::read` attaches an explicit
/// `Authorization` bearer where one is configured), and sending credentials to
/// an arbitrary gateway lets it set a `SameSite=None` cookie and correlate
/// every subsequent leaf fetch (blueprint/web-client.md seam table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpCredentials {
    /// Send no ambient credentials.
    #[default]
    Omit,
    /// Send the host's ambient credentials — the API origin only.
    Include,
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
    /// Ambient-credential scope for this request.
    pub credentials: HttpCredentials,
    /// Wall-clock ceiling for the whole request, in milliseconds.
    ///
    /// Per request class, not global: a nonce fetch and a 1 MiB block read do
    /// not share a deadline. `None` leaves the bound to the host transport's
    /// own policy — a request that must never hang a UI flow sets one.
    pub timeout_ms: Option<u64>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &HeaderNames(&self.headers))
            .field("body", &self.body.as_ref().map(|body| BodyLen(body.len())))
            .field("credentials", &self.credentials)
            .field("timeout_ms", &self.timeout_ms)
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
/// for, attaches ambient credentials only where the request asks for them via
/// [`HttpCredentials`] (web rides the HTTP-only refresh cookie on the API
/// origin, which is why web's [`super::CredentialStore`] is a no-op), honours
/// [`HttpRequest::timeout_ms`], and never interprets bodies. Non-2xx statuses
/// are responses, not errors — a seam `Err` is reserved for transport-level
/// failure (unreachable, aborted, deadline elapsed).
///
/// One obligation the transport owns: it must not follow a redirect. Every
/// target on this seam — the API, a gateway, a BYO provider — is directly
/// addressed and gated on the URL the engine supplied, so a hop the engine did
/// not choose can only escape that gate: it replays the request past
/// [`crate::content::validate_byo_config`]'s endpoint rules, and a downgrade to
/// `http` would carry an `Authorization` header onto the clear network
/// (blueprint/engine.md "Content plane"). A 3xx is surfaced as the response it
/// is, and the engine treats it as the non-2xx it is.
///
/// No conformance kit ships for this seam: it has no seam-local durable
/// semantics; its behavior is exercised end-to-end by the live contract
/// suite (blueprint/testing.md).
pub trait Http {
    /// Sends one request and resolves with the complete response.
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse>;

    /// Like [`send`](Self::send), but fails closed if the response body would
    /// exceed `max_bytes`, so a lying/huge gateway cannot force an over-cap
    /// adoption. Both real transports — desktop (`reqwest`) and WASM (the JS
    /// fetch bridge) — enforce one bound the same way: a `Content-Length`
    /// pre-check, then a streaming drain that aborts as soon as the accumulated
    /// body would pass the cap. The body is never accumulated past `max_bytes`;
    /// the transport hands over whole chunks, so peak memory is `max_bytes` —
    /// twice that on the arm that concatenates the chunks at the end — plus at
    /// most the one chunk that tripped the cap.
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
            credentials: HttpCredentials::Include,
            timeout_ms: Some(10_000),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-jwt"), "header values must not leak");
        assert!(!debug.contains("refresh-token-bytes"), "body must not leak");
        assert!(debug.contains("Authorization"), "header names stay visible");
        assert!(debug.contains("<19 bytes>"), "body renders as a length");
    }

    #[test]
    fn a_usable_bearer_becomes_the_authorization_pair() {
        assert_eq!(
            bearer_header("eyJhbGciOi.J9-_~+/=").unwrap(),
            (
                AUTHORIZATION.to_owned(),
                "Bearer eyJhbGciOi.J9-_~+/=".to_owned()
            )
        );
    }

    #[test]
    fn a_bearer_that_could_reshape_the_request_is_refused() {
        for token in [
            "",                     // an `Authorization: Bearer ` no server accepts
            "jwt\r\nX-Injected: 1", // header injection
            "jwt\nX-Injected: 1",   // bare LF
            "jwt\r",                // bare CR
            "jwt token",            // a space splits the credential
            "jwt\ttoken",           // tab
            "jwt\0",                // NUL
            "jwt\u{7f}",            // DEL
            "jwt\u{80}",            // non-ASCII
            "jwt\u{2028}",          // line separator
        ] {
            assert_eq!(bearer_header(token), Err(InvalidBearer), "token {token:?}");
        }
    }

    #[test]
    fn the_bearer_refusal_carries_no_credential() {
        let refusal = bearer_header("super-secret-jwt token").unwrap_err();
        assert!(!format!("{refusal:?}").contains("super-secret-jwt"));
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
