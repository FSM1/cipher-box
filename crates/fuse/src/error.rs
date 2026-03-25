use thiserror::Error;

#[derive(Debug, Error)]
pub enum FuseError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] cipherbox_crypto::CryptoError),
    #[error("Core error: {0}")]
    Core(#[from] cipherbox_core::CoreError),
    #[error("API error: {0}")]
    Api(#[from] cipherbox_api_client::ApiError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Mount failed: {0}")]
    MountFailed(String),
    #[error("Unmount failed: {0}")]
    UnmountFailed(String),
    #[error("Inode not found: {0}")]
    InodeNotFound(u64),
    #[error("File handle not found: {0}")]
    FileHandleNotFound(u64),
    #[error("Permission denied")]
    PermissionDenied,
}
