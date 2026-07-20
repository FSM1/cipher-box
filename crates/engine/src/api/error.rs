//! Errors surfaced by the [`super::ApiClient`].

use core::fmt;

use crate::seams::SeamError;

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
    /// envelope.
    Status {
        /// The HTTP status code.
        status: u16,
        /// The server's `message` field, if the error body carried one.
        message: Option<String>,
    },
    /// A 2xx body did not match the expected shape. Carries a short reason,
    /// never the body bytes.
    Decode(String),
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
            } => write!(f, "api returned status {status}: {message}"),
            ApiError::Status {
                status,
                message: None,
            } => write!(f, "api returned status {status}"),
            ApiError::Decode(reason) => write!(f, "api response decode error: {reason}"),
        }
    }
}

impl std::error::Error for ApiError {}
