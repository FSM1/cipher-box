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

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_secp256k1_keypair() -> (Vec<u8>, Vec<u8>) {
        let (sk, pk) = ecies::utils::generate_keypair();
        let sk_bytes = sk.serialize().to_vec();
        let pk_bytes = pk.serialize().to_vec();
        (sk_bytes, pk_bytes)
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let (sk, pk) = generate_secp256k1_keypair();
        let data = b"secret key material";

        let wrapped = wrap_key(data, &pk).unwrap();
        let unwrapped = unwrap_key(&wrapped, &sk).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn unwrap_with_wrong_private_key_fails() {
        let (_sk, pk) = generate_secp256k1_keypair();
        let (wrong_sk, _) = generate_secp256k1_keypair();
        let data = b"secret";

        let wrapped = wrap_key(data, &pk).unwrap();
        let result = unwrap_key(&wrapped, &wrong_sk);
        assert!(result.is_err());
    }

    #[test]
    fn wrap_with_invalid_public_key_fails() {
        let result = wrap_key(b"data", &[0u8; 65]);
        assert!(result.is_err());
    }

    #[test]
    fn wrap_with_wrong_size_public_key_fails() {
        let result = wrap_key(b"data", &[0x04; 33]);
        assert!(result.is_err());
    }

    #[test]
    fn unwrap_truncated_ciphertext_fails() {
        let (sk, _) = generate_secp256k1_keypair();
        let short = vec![0u8; ECIES_MIN_CIPHERTEXT_SIZE - 1];
        let result = unwrap_key(&short, &sk);
        assert!(result.is_err());
    }

    #[test]
    fn unwrap_with_invalid_private_key_size_fails() {
        let result = unwrap_key(&[0u8; 100], &[0u8; 16]);
        assert!(result.is_err());
    }
}
