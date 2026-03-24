use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Crypto operation failed: {0}")]
    Crypto(#[from] cipherbox_crypto::CryptoError),
    #[error("Metadata serialization failed: {0}")]
    SerializationFailed(String),
    #[error("Metadata deserialization failed: {0}")]
    DeserializationFailed(String),
    #[error("IPNS record creation failed: {0}")]
    IpnsCreationFailed(String),
    #[error("IPNS record marshaling failed")]
    IpnsMarshalingFailed,
    #[error("Vault blob format error: {0}")]
    VaultBlobError(String),
    #[error("Invalid folder metadata: {0}")]
    InvalidFolderMetadata(String),
    #[error("Invalid bin metadata: {0}")]
    InvalidBinMetadata(String),
    #[error("Hex decode error: {0}")]
    HexDecodeError(String),
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),
    #[error("JSON parse error: {0}")]
    JsonError(String),
}
