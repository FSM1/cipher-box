//! CipherBox cryptographic primitives and key derivation.
//!
//! Pure crypto operations with no CipherBox domain knowledge.
//! Mirrors @cipherbox/crypto TypeScript package.

pub mod aes;
pub mod aes_ctr;
pub mod ecies;
pub mod ed25519;
pub mod error;
pub mod hkdf;
pub mod ipns_name;
pub mod utils;

// Re-export primary functions
pub use aes::{
    build_node_aad, decrypt_aes_gcm, decrypt_aes_gcm_aad, encrypt_aes_gcm, encrypt_aes_gcm_aad,
    seal_aes_gcm, seal_aes_gcm_aad, unseal_aes_gcm, unseal_aes_gcm_aad,
};
pub use aes_ctr::{decrypt_aes_ctr, encrypt_aes_ctr};
pub use ecies::{unwrap_key, wrap_key};
pub use ed25519::{generate_ed25519_keypair, get_public_key, sign_ed25519, verify_ed25519};
pub use error::CryptoError;
pub use hkdf::{
    derive_bin_ipns_keypair, derive_file_ipns_keypair, derive_registry_ipns_keypair,
    derive_vault_ipns_keypair, derive_vault_key_ipns_keypair,
    derive_vault_settings_ipns_keypair,
};
pub use ipns_name::derive_ipns_name;
pub use utils::{clear_bytes, generate_file_key, generate_iv, generate_random_bytes};
