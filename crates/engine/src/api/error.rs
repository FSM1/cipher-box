//! Errors surfaced by the [`super::ApiClient`].

use core::fmt;

use crate::seams::SeamError;

/// The 413 `code` for the account-quota gate. Transient: it clears when the
/// account frees space (blueprint/api.md).
pub const QUOTA_EXCEEDED: &str = "QUOTA_EXCEEDED";

/// The 413 `code` for the transport cap, which shares the status. Permanent for
/// the request: the same bytes are refused on every retry.
pub const UPLOAD_TOO_LARGE: &str = "UPLOAD_TOO_LARGE";

/// The 400 `code` the registry's batch gate stamps: an over-cap or malformed
/// batch, refused identically on every retry (blueprint/api.md "Batch bounds").
/// A 400 without it never reached that gate.
pub const REGISTRY_BATCH_REFUSED: &str = "REGISTRY_BATCH_REFUSED";

/// A failure of an API call.
///
/// Diagnostic strings carried here are the API's own error messages, never key
/// material: the client extracts only the server's `message` field and never
/// echoes request bodies, tokens, or signatures (security rule 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// Transport-level failure from the [`crate::seams::Http`] seam
    /// (unreachable host, aborted request). Distinct from an HTTP error
    /// status, which is a well-formed response.
    Transport(SeamError),
    /// The request needed authentication the client does not hold — no access
    /// token in memory and no refresh token to mint one (e.g. a call before
    /// any login).
    NotAuthenticated,
    /// The API answered 401 and a single refresh-then-retry did not recover
    /// it: the session is dead and the caller must re-login.
    Unauthorized,
    /// The API answered 403 — e.g. the staging test-login endpoint is disabled
    /// or hard-blocked in production.
    Forbidden,
    /// A non-2xx status the client does not special-case. `message` is the
    /// server's diagnostic string when the body parsed as a Nest error
    /// envelope; `code` is its stable machine discriminator, which is what a
    /// caller may branch on — prose is diagnostic only.
    Status {
        /// The HTTP status code.
        status: u16,
        /// The server's `message` field, if the error body carried one.
        message: Option<String>,
        /// The server's `code` field, if the error body carried one.
        code: Option<String>,
    },
    /// A 2xx body did not match the expected shape. Carries a short reason,
    /// never the body bytes.
    Decode(String),
    /// A caller-supplied content address was not core's canonical CIDv1 base32
    /// string under a content-plane codec, so no request was sent. Refused
    /// here because the address is what the ingress pins under — a
    /// non-canonical one must never reach the wire.
    MalformedContentCid,
}

impl From<SeamError> for ApiError {
    fn from(error: SeamError) -> Self {
        ApiError::Transport(error)
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Transport(error) => write!(f, "api transport error: {error}"),
            ApiError::NotAuthenticated => f.write_str("api call requires authentication"),
            ApiError::Unauthorized => f.write_str("api rejected the request as unauthorized"),
            ApiError::Forbidden => f.write_str("api refused the request as forbidden"),
            ApiError::Status {
                status,
                message: Some(message),
                ..
            } => write!(f, "api returned status {status}: {message}"),
            ApiError::Status {
                status,
                message: None,
                ..
            } => write!(f, "api returned status {status}"),
            ApiError::Decode(reason) => write!(f, "api response decode error: {reason}"),
            ApiError::MalformedContentCid => {
                f.write_str("api call carried a non-canonical content CID")
            }
        }
    }
}

impl std::error::Error for ApiError {}
