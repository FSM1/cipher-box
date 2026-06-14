use thiserror::Error;

/// Typed outcome for IPNS sequence resolution.
///
/// Replaces stringly-typed `.contains("not found")` matches in the replay path.
/// Defined as a plain outcome enum — `#[derive(Debug)]` only, NOT `thiserror::Error`.
#[derive(Debug)]
pub enum IpnsResolveOutcome {
    /// IPNS record exists; contains the current sequence number.
    Found(u64),
    /// IPNS record does not exist (404 / "not found").
    NotFound,
    /// Resolution failed for a non-404 reason.
    Error(String),
}

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
