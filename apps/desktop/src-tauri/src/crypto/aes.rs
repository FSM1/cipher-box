//! AES-256-GCM encryption/decryption.
//!
//! Sealed format: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
//! This matches the TypeScript `sealAesGcm` output exactly.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use thiserror::Error;

use super::utils::generate_iv;

/// AES-256-GCM key size in bytes (256 bits).
pub const AES_KEY_SIZE: usize = 32;

/// AES-GCM IV size in bytes (96 bits).
pub const AES_IV_SIZE: usize = 12;

/// AES-GCM authentication tag size in bytes (128 bits).
pub const AES_TAG_SIZE: usize = 16;

/// Minimum sealed data size: IV + auth tag (empty plaintext).
const MIN_SEALED_SIZE: usize = AES_IV_SIZE + AES_TAG_SIZE;

#[derive(Debug, Error)]
pub enum AesError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid key size")]
    InvalidKeySize,
    #[error("Invalid IV size")]
    InvalidIvSize,
}

/// Encrypt data using AES-256-GCM.
///
/// Returns ciphertext with 16-byte auth tag appended (same as Web Crypto API).
pub fn encrypt_aes_gcm(
    plaintext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
) -> Result<Vec<u8>, AesError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AesError::EncryptionFailed)?;
    let nonce = Nonce::from_slice(iv);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| AesError::EncryptionFailed)
}

/// Decrypt data using AES-256-GCM.
///
/// Expects ciphertext with 16-byte auth tag appended.
pub fn decrypt_aes_gcm(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
) -> Result<Vec<u8>, AesError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AesError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AesError::DecryptionFailed)
}

/// Seal data using AES-256-GCM with automatic IV generation.
///
/// Returns: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
/// This format matches the TypeScript `sealAesGcm` exactly.
pub fn seal_aes_gcm(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, AesError> {
    let iv = generate_iv();
    let ciphertext = encrypt_aes_gcm(plaintext, key, &iv)?;

    // IV || ciphertext (which already includes the tag)
    let mut sealed = Vec::with_capacity(AES_IV_SIZE + ciphertext.len());
    sealed.extend_from_slice(&iv);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Unseal data encrypted with `seal_aes_gcm`.
///
/// Extracts IV from first 12 bytes, decrypts remainder.
pub fn unseal_aes_gcm(sealed: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, AesError> {
    if sealed.len() < MIN_SEALED_SIZE {
        return Err(AesError::DecryptionFailed);
    }

    let iv: [u8; 12] = sealed[..AES_IV_SIZE]
        .try_into()
        .map_err(|_| AesError::DecryptionFailed)?;
    let ciphertext = &sealed[AES_IV_SIZE..];

    decrypt_aes_gcm(ciphertext, key, &iv)
}
