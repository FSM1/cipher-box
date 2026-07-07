//! Error types for the CipherBox SDK.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] cipherbox_crypto::CryptoError),
    #[error("Core error: {0}")]
    Core(#[from] cipherbox_core::CoreError),
    #[error("IPNS error: {0}")]
    Ipns(#[from] cipherbox_core::ipns::IpnsError),
    #[error("API error: {0}")]
    Api(#[from] cipherbox_api_client::ApiError),
    /// Node (`node/v3`) codec/seal failure — surfaced by `crate::emit`'s
    /// `seal_published_node`/`encode_published_node`/`seal_child_*_key` calls.
    #[error("Node error: {0}")]
    Node(#[from] cipherbox_core::node::NodeError),
    #[error("Sync error: {0}")]
    SyncError(String),
    #[error("Queue error: {0}")]
    QueueError(String),
    #[error("Registry error: {0}")]
    RegistryError(String),
    #[error("Key state error: {0}")]
    KeyStateError(String),
    /// A `crate::emit` invariant violation (e.g. a minted key/id whose byte
    /// length does not match its expected fixed size).
    #[error("Emit error: {0}")]
    Emit(String),
    #[error("Not authenticated")]
    NotAuthenticated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_sync_error() {
        let err = SdkError::SyncError("connection lost".to_string());
        assert_eq!(err.to_string(), "Sync error: connection lost");
    }

    #[test]
    fn display_queue_error() {
        let err = SdkError::QueueError("full".to_string());
        assert_eq!(err.to_string(), "Queue error: full");
    }

    #[test]
    fn display_registry_error() {
        let err = SdkError::RegistryError("parse failed".to_string());
        assert_eq!(err.to_string(), "Registry error: parse failed");
    }

    #[test]
    fn display_key_state_error() {
        let err = SdkError::KeyStateError("missing key".to_string());
        assert_eq!(err.to_string(), "Key state error: missing key");
    }

    #[test]
    fn display_not_authenticated() {
        let err = SdkError::NotAuthenticated;
        assert_eq!(err.to_string(), "Not authenticated");
    }

    #[test]
    fn error_variants_are_constructible() {
        // Verify each string-carrying variant can be constructed.
        let _ = SdkError::SyncError("a".to_string());
        let _ = SdkError::QueueError("b".to_string());
        let _ = SdkError::RegistryError("c".to_string());
        let _ = SdkError::KeyStateError("d".to_string());
        let _ = SdkError::NotAuthenticated;
    }

    #[test]
    fn error_is_debug_printable() {
        let err = SdkError::NotAuthenticated;
        let debug = format!("{:?}", err);
        assert!(debug.contains("NotAuthenticated"));
    }

    #[test]
    fn error_implements_std_error() {
        // Verify SdkError implements std::error::Error via thiserror.
        let err: Box<dyn std::error::Error> = Box::new(SdkError::SyncError("test".to_string()));
        assert_eq!(err.to_string(), "Sync error: test");
    }
}
