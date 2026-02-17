//! Ed25519 key generation, signing, and verification.
//!
//! Used for IPNS record signing. Deterministic signatures are critical
//! for cross-language test vector verification.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::Zeroize;

/// Ed25519 public key size in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 private key size in bytes.
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

#[derive(Debug, Error)]
pub enum Ed25519Error {
    #[error("Signing failed")]
    SigningFailed,
    #[error("Invalid private key size")]
    InvalidPrivateKeySize,
    #[error("Invalid public key")]
    InvalidPublicKey,
}

/// Generate a new Ed25519 keypair.
///
/// Returns (public_key_32bytes, private_key_32bytes).
pub fn generate_ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    (
        verifying_key.to_bytes().to_vec(),
        signing_key.to_bytes().to_vec(),
    )
}

/// Sign a message with an Ed25519 private key.
///
/// Returns 64-byte deterministic signature.
pub fn sign_ed25519(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, Ed25519Error> {
    if private_key.len() != ED25519_PRIVATE_KEY_SIZE {
        return Err(Ed25519Error::InvalidPrivateKeySize);
    }

    let mut key_bytes: [u8; 32] = private_key
        .try_into()
        .map_err(|_| Ed25519Error::InvalidPrivateKeySize)?;
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
pub fn get_public_key(private_key: &[u8]) -> Result<Vec<u8>, Ed25519Error> {
    if private_key.len() != ED25519_PRIVATE_KEY_SIZE {
        return Err(Ed25519Error::InvalidPrivateKeySize);
    }

    let key_bytes: [u8; 32] = private_key
        .try_into()
        .map_err(|_| Ed25519Error::InvalidPrivateKeySize)?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    Ok(verifying_key.to_bytes().to_vec())
}
