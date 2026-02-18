//! CipherBox Rust Crypto Module
//!
//! Mirrors the @cipherbox/crypto TypeScript module for cross-language compatibility.
//! All operations produce byte-identical output to the TypeScript implementation.

pub mod aes;
pub mod aes_ctr;
pub mod ecies;
pub mod ed25519;
pub mod folder;
pub mod hkdf;
pub mod ipns;
pub mod utils;

#[cfg(test)]
mod tests;

// Re-export primary functions for convenience
pub use aes::{decrypt_aes_gcm, encrypt_aes_gcm, seal_aes_gcm, unseal_aes_gcm};
pub use ecies::{unwrap_key, wrap_key};
pub use ed25519::{generate_ed25519_keypair, get_public_key, sign_ed25519, verify_ed25519};
pub use folder::{decrypt_folder_metadata, encrypt_folder_metadata, FolderMetadata};
pub use ipns::{create_ipns_record, derive_ipns_name, marshal_ipns_record, IpnsRecord};
pub use utils::{clear_bytes, generate_file_key, generate_iv, generate_random_bytes};
