//! Utility functions for cryptographic operations.

use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroize;

use super::aes::{AES_IV_SIZE, AES_KEY_SIZE};

#[derive(Debug, Error)]
pub enum UtilError {
    #[error("Invalid hex string")]
    InvalidHex,
}

/// Generate cryptographically secure random bytes.
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Generate a random 32-byte AES key.
pub fn generate_file_key() -> [u8; AES_KEY_SIZE] {
    let mut key = [0u8; AES_KEY_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Generate a random 12-byte IV.
pub fn generate_iv() -> [u8; AES_IV_SIZE] {
    let mut iv = [0u8; AES_IV_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    iv
}

/// Convert a hex string to bytes.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, UtilError> {
    hex::decode(hex).map_err(|_| UtilError::InvalidHex)
}

/// Convert bytes to a hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Zeroize sensitive data in a byte slice.
pub fn clear_bytes(buf: &mut [u8]) {
    buf.zeroize();
}
