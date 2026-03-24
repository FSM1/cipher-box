//! CipherBox Rust Crypto Module
//!
//! Pure crypto primitives now come from the cipherbox-crypto crate.
//! Domain-specific modules (folder, bin, vault_blob, ipns) remain local
//! until extraction to cipherbox-core in a later plan.

// Domain modules (staying local until cipherbox-core extraction)
pub mod bin;
pub mod folder;
pub mod ipns;
pub mod vault_blob;

#[cfg(test)]
mod tests;

// Re-export cipherbox-crypto sub-modules for backward compatibility
// so existing `crate::crypto::aes::*` paths keep working.
pub use cipherbox_crypto::aes;
pub use cipherbox_crypto::aes_ctr;
pub use cipherbox_crypto::ecies;
pub use cipherbox_crypto::ed25519;
pub use cipherbox_crypto::hkdf;
pub use cipherbox_crypto::ipns_name;
pub use cipherbox_crypto::utils;

// Re-export primary functions from cipherbox-crypto
pub use cipherbox_crypto::aes::{decrypt_aes_gcm, encrypt_aes_gcm, seal_aes_gcm, unseal_aes_gcm};
pub use cipherbox_crypto::aes_ctr::{decrypt_aes_ctr, encrypt_aes_ctr};
pub use cipherbox_crypto::ecies::{unwrap_key, wrap_key};
pub use cipherbox_crypto::ed25519::{
    generate_ed25519_keypair, get_public_key, sign_ed25519, verify_ed25519,
};
pub use cipherbox_crypto::hkdf::{
    derive_bin_ipns_keypair, derive_file_ipns_keypair, derive_registry_ipns_keypair,
    derive_vault_ipns_keypair, derive_vault_key_ipns_keypair,
};
pub use cipherbox_crypto::ipns_name::derive_ipns_name;
pub use cipherbox_crypto::utils::{clear_bytes, generate_file_key, generate_iv, generate_random_bytes};
pub use cipherbox_crypto::CryptoError;

// Re-export domain types (these stay until cipherbox-core extraction)
pub use bin::{
    decrypt_bin_metadata, empty_bin_metadata, encrypt_bin_metadata, BinEntry, BinItemType,
    RecycleBinMetadata,
};
pub use folder::{decrypt_folder_metadata, encrypt_folder_metadata, FolderMetadata};
pub use ipns::{create_ipns_record, marshal_ipns_record, IpnsRecord};
pub use vault_blob::{deserialize_vault_blob_v2, detect_blob_version, serialize_vault_blob_v2};
