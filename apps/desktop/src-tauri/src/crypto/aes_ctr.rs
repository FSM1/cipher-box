//! AES-256-CTR encryption/decryption.
//!
//! Symmetric encryption for media file content using CTR mode.
//! CTR mode enables random-access decryption (any byte range without
//! processing preceding bytes), required for streaming media playback.
//!
//! Uses Ctr64BE (big-endian 64-bit counter) to match Web Crypto API's
//! `AES-CTR` with `length: 64`.
//!
//! SECURITY NOTE: AES-CTR does NOT provide authentication (unlike GCM).
//! Integrity is provided by IPFS content addressing.

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use thiserror::Error;

/// AES-CTR IV size in bytes (128-bit counter block).
pub const AES_CTR_IV_SIZE: usize = 16;

/// AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;

/// Type alias for AES-256-CTR with 64-bit big-endian counter.
/// Matches Web Crypto API's `AES-CTR` with `length: 64`.
type Aes256Ctr64BE = ctr::Ctr64BE<Aes256>;

#[derive(Debug, Error)]
pub enum AesCtrError {
    #[error("Invalid key size")]
    InvalidKeySize,
    #[error("Invalid IV size")]
    InvalidIvSize,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid range")]
    InvalidRange,
}

/// Encrypt data using AES-256-CTR.
///
/// Each encryption MUST use a unique IV (nonce + counter) with the same key.
/// Reusing nonce+key pairs is catastrophic for AES-CTR security.
///
/// CTR output is the same size as the input (no authentication tag).
pub fn encrypt_aes_ctr(
    plaintext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, AesCtrError> {
    let mut cipher =
        Aes256Ctr64BE::new(key.into(), iv.into());

    let mut output = plaintext.to_vec();
    cipher.apply_keystream(&mut output);

    Ok(output)
}

/// Decrypt data encrypted with AES-256-CTR.
///
/// CTR encrypt == decrypt (XOR is symmetric), but provided as a separate
/// function for API clarity.
pub fn decrypt_aes_ctr(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, AesCtrError> {
    // CTR mode: decrypt is identical to encrypt
    encrypt_aes_ctr(ciphertext, key, iv)
}

/// Decrypt an arbitrary byte range from AES-256-CTR encrypted data.
///
/// Computes the correct counter value for any byte offset and decrypts
/// only the required blocks, avoiding the need to process the entire file.
///
/// The counter is computed as: baseCounter + floor(startByte / 16)
/// where baseCounter is the initial counter value from the IV (bytes 8-15).
///
/// `ciphertext` must contain at least the block-aligned range covering
/// `[start_byte, end_byte]` (inclusive).
pub fn decrypt_aes_ctr_range(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
    start_byte: usize,
    end_byte: usize,
) -> Result<Vec<u8>, AesCtrError> {
    if start_byte > end_byte {
        return Err(AesCtrError::InvalidRange);
    }

    if ciphertext.is_empty() || start_byte >= ciphertext.len() {
        return Ok(Vec::new());
    }

    // Clamp end_byte to actual data
    let clamped_end = end_byte.min(ciphertext.len().saturating_sub(1));
    if clamped_end < start_byte {
        // Range is entirely beyond available data
        return Ok(Vec::new());
    }

    // Compute block-aligned range
    let start_block = start_byte / AES_BLOCK_SIZE;
    let end_block = clamped_end / AES_BLOCK_SIZE;
    let block_aligned_start = start_block * AES_BLOCK_SIZE;
    let block_aligned_end = ((end_block + 1) * AES_BLOCK_SIZE).min(ciphertext.len());

    // Build counter for starting block:
    // Copy nonce (first 8 bytes of IV), compute counter = baseCounter + startBlock
    let mut counter = [0u8; 16];
    counter[..8].copy_from_slice(&iv[..8]);

    let base_counter = u64::from_be_bytes(iv[8..16].try_into().unwrap());
    let new_counter = base_counter.wrapping_add(start_block as u64);
    counter[8..16].copy_from_slice(&new_counter.to_be_bytes());

    // Create cipher with adjusted counter
    let mut cipher = Aes256Ctr64BE::new(key.into(), &counter.into());

    // Decrypt the block-aligned range
    let mut decrypted = ciphertext[block_aligned_start..block_aligned_end].to_vec();
    cipher.apply_keystream(&mut decrypted);

    // Extract exact requested bytes from decrypted block-aligned data
    let offset_in_first_block = start_byte - block_aligned_start;
    let requested_length = clamped_end - start_byte + 1;
    let result = decrypted[offset_in_first_block..offset_in_first_block + requested_length].to_vec();

    Ok(result)
}
