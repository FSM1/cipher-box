//! CipherBox Rust Crypto Module
//!
//! All crypto and domain logic now comes from cipherbox-crypto
//! and cipherbox-core crates. This module provides backward-compatible
//! re-exports so existing `crate::crypto::*` paths keep working.

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

// Re-export cipherbox-core sub-modules for backward compatibility
// so existing `crate::crypto::folder::*`, `crate::crypto::bin::*`,
// `crate::crypto::ipns::*`, `crate::crypto::vault_blob::*` paths keep working.
pub use cipherbox_core::folder;
pub use cipherbox_core::bin;
pub use cipherbox_core::ipns;
pub use cipherbox_core::vault_blob;
pub use cipherbox_core::decrypt;

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

// Re-export primary types from cipherbox-core
pub use cipherbox_core::folder::{
    decrypt_folder_metadata, encrypt_folder_metadata, FolderMetadata, FolderChild, FolderEntry,
    FilePointer, FileMetadata, VersionEntry, encrypt_file_metadata, decrypt_file_metadata,
};
pub use cipherbox_core::bin::{
    encrypt_bin_metadata, decrypt_bin_metadata, empty_bin_metadata, RecycleBinMetadata, BinEntry,
    BinItemType, VersionCidEntry,
};
pub use cipherbox_core::ipns::{create_ipns_record, marshal_ipns_record, IpnsRecord};
pub use cipherbox_core::vault_blob::{serialize_vault_blob_v2, deserialize_vault_blob_v2, detect_blob_version};
pub use cipherbox_core::decrypt::{decrypt_metadata_from_ipfs_public, decrypt_file_metadata_from_ipfs_public};
