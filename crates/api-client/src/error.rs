//! Error types for the CipherBox API client.

use thiserror::Error;

/// Errors that can occur when communicating with the CipherBox API.
#[derive(Debug, Error)]
pub enum ApiError {
    /// HTTP request failed at the transport level.
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    /// API returned a non-success status code.
    #[error("API returned error {status}: {message}")]
    ApiResponse {
        /// HTTP status code.
        status: u16,
        /// Error message from the response body.
        message: String,
    },

    /// Authentication failed (401 or token refresh failure).
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// Response body could not be deserialized.
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),

    /// IPNS name was not found (404 on resolve).
    #[error("IPNS name not found: {0}")]
    IpnsNotFound(String),
}
