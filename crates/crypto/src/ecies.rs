//! ECIES key wrapping using secp256k1.
//!
//! Uses the `ecies` Rust crate which is cross-compatible with the `eciesjs` npm package
//! (same author: ecies/rs and ecies/js). Format: ephemeral_pubkey(65) || nonce(16) || tag(16) || ciphertext.

use crate::error::CryptoError;

/// secp256k1 uncompressed public key size in bytes (04 prefix + x + y coordinates).
pub const SECP256K1_PUBLIC_KEY_SIZE: usize = 65;

/// secp256k1 private key size in bytes.
pub const SECP256K1_PRIVATE_KEY_SIZE: usize = 32;

/// ECIES minimum ciphertext size: ephemeral pubkey (65) + auth tag (16).
pub const ECIES_MIN_CIPHERTEXT_SIZE: usize = SECP256K1_PUBLIC_KEY_SIZE + 16;

/// Wrap (encrypt) data using ECIES with secp256k1.
///
/// The `ecies` Rust crate and `eciesjs` npm package produce compatible output.
pub fn wrap_key(data: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Validate public key size (uncompressed secp256k1)
    if recipient_public_key.len() != SECP256K1_PUBLIC_KEY_SIZE {
        return Err(CryptoError::InvalidPublicKey);
    }

    // Validate uncompressed public key prefix (0x04)
    if recipient_public_key[0] != 0x04 {
        return Err(CryptoError::InvalidPublicKey);
    }

    ecies::encrypt(recipient_public_key, data).map_err(|_| CryptoError::EciesWrappingFailed)
}

/// Unwrap (decrypt) data using ECIES with secp256k1.
pub fn unwrap_key(wrapped: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Validate private key size
    if private_key.len() != SECP256K1_PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidPrivateKey);
    }

    // Validate minimum ciphertext size
    if wrapped.len() < ECIES_MIN_CIPHERTEXT_SIZE {
        return Err(CryptoError::EciesUnwrappingFailed);
    }

    ecies::decrypt(private_key, wrapped).map_err(|_| CryptoError::EciesUnwrappingFailed)
}
