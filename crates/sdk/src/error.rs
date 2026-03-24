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
    #[error("Sync error: {0}")]
    SyncError(String),
    #[error("Queue error: {0}")]
    QueueError(String),
    #[error("Registry error: {0}")]
    RegistryError(String),
    #[error("Key state error: {0}")]
    KeyStateError(String),
    #[error("Not authenticated")]
    NotAuthenticated,
}
