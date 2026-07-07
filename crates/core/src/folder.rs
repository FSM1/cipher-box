//! Folder version-history types.
//!
//! The legacy folder-model metadata types (`FolderMetadata`/`FolderChild`/
//! `FolderEntry`/`FilePointer`/`FileMetadata` + their encrypt/decrypt helpers)
//! were removed in the D-04 clean cutover to the single Node model
//! (`crate::node`). This module now holds only `VersionEntry` — the file
//! version-history row consumed by `crates/fuse/src/helpers.rs`
//! (`apply_versioning`/`versions_to_bin_entries`).

use serde::{Deserialize, Serialize};

/// A single past version of a file.
/// Stores full crypto context for independent decryption.
/// Matches TypeScript `VersionEntry` from `@cipherbox/crypto/file/types.ts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionEntry {
    /// IPFS CID of the encrypted file content for this version.
    pub cid: String,
    /// Hex-encoded ECIES-wrapped AES-256 key for decrypting this version.
    pub file_key_encrypted: String,
    /// Hex-encoded IV used for this version's encryption.
    pub file_iv: String,
    /// Original file size in bytes (before encryption).
    pub size: u64,
    /// When this version was created (Unix ms).
    pub timestamp: u64,
    /// Encryption mode used for this version.
    pub encryption_mode: String,
}
