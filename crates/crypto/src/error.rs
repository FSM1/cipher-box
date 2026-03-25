//! Unified error type for all cipherbox-crypto operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AES-GCM encryption failed")]
    AesEncryptionFailed,
    #[error("AES-GCM decryption failed")]
    AesDecryptionFailed,
    #[error("AES-CTR encryption failed")]
    AesCtrEncryptionFailed,
    #[error("AES-CTR decryption failed")]
    AesCtrDecryptionFailed,
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },
    #[error("Invalid IV size: expected {expected}, got {actual}")]
    InvalidIvSize { expected: usize, actual: usize },
    #[error("ECIES wrapping failed")]
    EciesWrappingFailed,
    #[error("ECIES unwrapping failed")]
    EciesUnwrappingFailed,
    #[error("Ed25519 key generation failed")]
    Ed25519KeyGenFailed,
    #[error("Ed25519 signing failed")]
    Ed25519SigningFailed,
    #[error("Ed25519 verification failed")]
    Ed25519VerificationFailed,
    #[error("HKDF derivation failed")]
    HkdfDerivationFailed,
    #[error("IPNS name derivation failed")]
    IpnsNameDerivationFailed,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid range")]
    InvalidRange,
    #[error("Invalid file ID: must be at least 10 characters")]
    InvalidFileId,
}
