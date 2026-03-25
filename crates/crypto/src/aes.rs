//! AES-256-GCM encryption/decryption.
//!
//! Sealed format: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
//! This matches the TypeScript `sealAesGcm` output exactly.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use crate::error::CryptoError;
use crate::utils::generate_iv;

/// AES-256-GCM key size in bytes (256 bits).
pub const AES_KEY_SIZE: usize = 32;

/// AES-GCM IV size in bytes (96 bits).
pub const AES_IV_SIZE: usize = 12;

/// AES-GCM authentication tag size in bytes (128 bits).
pub const AES_TAG_SIZE: usize = 16;

/// Minimum sealed data size: IV + auth tag (empty plaintext).
const MIN_SEALED_SIZE: usize = AES_IV_SIZE + AES_TAG_SIZE;

/// Encrypt data using AES-256-GCM.
///
/// Returns ciphertext with 16-byte auth tag appended (same as Web Crypto API).
pub fn encrypt_aes_gcm(
    plaintext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AesEncryptionFailed)?;
    let nonce = Nonce::from_slice(iv);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::AesEncryptionFailed)
}

/// Decrypt data using AES-256-GCM.
///
/// Expects ciphertext with 16-byte auth tag appended.
pub fn decrypt_aes_gcm(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AesDecryptionFailed)?;
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::AesDecryptionFailed)
}

/// Seal data using AES-256-GCM with automatic IV generation.
///
/// Returns: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
/// This format matches the TypeScript `sealAesGcm` exactly.
pub fn seal_aes_gcm(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
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
pub fn unseal_aes_gcm(sealed: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < MIN_SEALED_SIZE {
        return Err(CryptoError::AesDecryptionFailed);
    }

    let iv: [u8; 12] = sealed[..AES_IV_SIZE]
        .try_into()
        .map_err(|_| CryptoError::AesDecryptionFailed)?;
    let ciphertext = &sealed[AES_IV_SIZE..];

    decrypt_aes_gcm(ciphertext, key, &iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [0xABu8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"hello cipherbox";

        let ciphertext = encrypt_aes_gcm(plaintext, &key, &iv).unwrap();
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn seal_unseal_round_trip() {
        let key = [0x42u8; 32];
        let plaintext = b"sealed round trip data";

        let sealed = seal_aes_gcm(plaintext, &key).unwrap();
        assert!(sealed.len() >= AES_IV_SIZE + AES_TAG_SIZE + plaintext.len());

        let decrypted = unseal_aes_gcm(&sealed, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = [0xAAu8; 32];
        let wrong_key = [0xBBu8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"secret";

        let ciphertext = encrypt_aes_gcm(plaintext, &key, &iv).unwrap();
        let result = decrypt_aes_gcm(&ciphertext, &wrong_key, &iv);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_corrupted_ciphertext_fails() {
        let key = [0xAAu8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"secret";

        let mut ciphertext = encrypt_aes_gcm(plaintext, &key, &iv).unwrap();
        ciphertext[0] ^= 0xFF;

        let result = decrypt_aes_gcm(&ciphertext, &key, &iv);
        assert!(result.is_err());
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let key = [0xCCu8; 32];
        let iv = [0x02u8; 12];
        let plaintext = b"";

        let ciphertext = encrypt_aes_gcm(plaintext, &key, &iv).unwrap();
        assert_eq!(ciphertext.len(), AES_TAG_SIZE);

        let decrypted = decrypt_aes_gcm(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn unseal_too_short_data_fails() {
        let key = [0xAAu8; 32];
        let short = vec![0u8; AES_IV_SIZE + AES_TAG_SIZE - 1];
        assert!(unseal_aes_gcm(&short, &key).is_err());
    }

    #[test]
    fn unseal_with_wrong_key_fails() {
        let key = [0xAAu8; 32];
        let wrong_key = [0xBBu8; 32];
        let sealed = seal_aes_gcm(b"data", &key).unwrap();
        assert!(unseal_aes_gcm(&sealed, &wrong_key).is_err());
    }
}
