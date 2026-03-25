//! Ed25519 key generation, signing, and verification.
//!
//! Used for IPNS record signing. Deterministic signatures are critical
//! for cross-language test vector verification.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

/// Ed25519 public key size in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 private key size in bytes.
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Generate a new Ed25519 keypair.
///
/// Returns (public_key_32bytes, private_key_32bytes).
/// The private key is wrapped in `Zeroizing` to ensure it is zeroed on drop.
pub fn generate_ed25519_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    (
        verifying_key.to_bytes().to_vec(),
        Zeroizing::new(signing_key.to_bytes().to_vec()),
    )
}

/// Sign a message with an Ed25519 private key.
///
/// Returns 64-byte deterministic signature.
pub fn sign_ed25519(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if private_key.len() != ED25519_PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidPrivateKey);
    }

    let mut key_bytes: [u8; 32] = private_key
        .try_into()
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    key_bytes.zeroize();
    let signature = signing_key.sign(message);

    Ok(signature.to_bytes().to_vec())
}

/// Verify an Ed25519 signature.
///
/// Returns true if valid, false otherwise. Never throws.
pub fn verify_ed25519(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if signature.len() != ED25519_SIGNATURE_SIZE || public_key.len() != ED25519_PUBLIC_KEY_SIZE {
        return false;
    }

    let Ok(sig_bytes) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(key_bytes) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };

    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };

    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key.verify(message, &sig).is_ok()
}

/// Derive the 32-byte public key from a 32-byte Ed25519 private key.
pub fn get_public_key(private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if private_key.len() != ED25519_PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidPrivateKey);
    }

    let mut key_bytes: [u8; 32] = private_key
        .try_into()
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    key_bytes.zeroize();
    let verifying_key = signing_key.verifying_key();

    Ok(verifying_key.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_sizes() {
        let (public_key, private_key) = generate_ed25519_keypair();
        assert_eq!(public_key.len(), ED25519_PUBLIC_KEY_SIZE);
        assert_eq!(private_key.len(), ED25519_PRIVATE_KEY_SIZE);
    }

    #[test]
    fn sign_verify_round_trip() {
        let (public_key, private_key) = generate_ed25519_keypair();
        let message = b"test message for signing";

        let signature = sign_ed25519(message, &private_key).unwrap();
        assert_eq!(signature.len(), ED25519_SIGNATURE_SIZE);
        assert!(verify_ed25519(message, &signature, &public_key));
    }

    #[test]
    fn verify_wrong_message_returns_false() {
        let (public_key, private_key) = generate_ed25519_keypair();
        let signature = sign_ed25519(b"original", &private_key).unwrap();
        assert!(!verify_ed25519(b"tampered", &signature, &public_key));
    }

    #[test]
    fn verify_wrong_key_returns_false() {
        let (_, private_key) = generate_ed25519_keypair();
        let (other_public_key, _) = generate_ed25519_keypair();
        let message = b"test";

        let signature = sign_ed25519(message, &private_key).unwrap();
        assert!(!verify_ed25519(message, &signature, &other_public_key));
    }

    #[test]
    fn sign_with_invalid_key_size_fails() {
        let result = sign_ed25519(b"msg", &[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn verify_with_bad_signature_size_returns_false() {
        let (public_key, _) = generate_ed25519_keypair();
        assert!(!verify_ed25519(b"msg", &[0u8; 32], &public_key));
    }

    #[test]
    fn verify_with_bad_public_key_size_returns_false() {
        assert!(!verify_ed25519(b"msg", &[0u8; 64], &[0u8; 16]));
    }

    #[test]
    fn get_public_key_determinism() {
        let (_, private_key) = generate_ed25519_keypair();
        let pk1 = get_public_key(&private_key).unwrap();
        let pk2 = get_public_key(&private_key).unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn get_public_key_matches_generated() {
        let (public_key, private_key) = generate_ed25519_keypair();
        let derived = get_public_key(&private_key).unwrap();
        assert_eq!(derived, public_key);
    }

    #[test]
    fn get_public_key_invalid_size_fails() {
        let result = get_public_key(&[0u8; 16]);
        assert!(result.is_err());
    }
}
