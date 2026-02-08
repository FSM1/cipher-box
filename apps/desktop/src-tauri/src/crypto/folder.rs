//! Folder metadata types and encryption.
//!
//! Matches the TypeScript `FolderMetadata` type exactly.
//! Uses Serde `rename_all = "camelCase"` to produce JSON field names
//! identical to the TypeScript format.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use super::aes::{self, AesError};

#[derive(Debug, Error)]
pub enum FolderError {
    #[error("Encryption failed")]
    EncryptionFailed(#[from] AesError),
    #[error("Serialization failed")]
    SerializationFailed,
    #[error("Deserialization failed")]
    DeserializationFailed,
}

/// Decrypted folder metadata structure.
/// The entire FolderMetadata object is encrypted as a single blob with AES-256-GCM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderMetadata {
    /// Schema version for future migrations.
    pub version: String,
    /// Files and subfolders in this folder.
    pub children: Vec<FolderChild>,
}

/// A child entry can be either a folder or a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum FolderChild {
    /// A subfolder entry.
    Folder(FolderEntry),
    /// A file entry.
    File(FileEntry),
}

/// Subfolder entry within folder metadata.
/// Contains ECIES-wrapped keys for accessing the subfolder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderEntry {
    /// UUID for internal reference.
    pub id: String,
    /// Folder name (plaintext, since whole metadata is encrypted).
    pub name: String,
    /// IPNS name for this subfolder (k51... format).
    pub ipns_name: String,
    /// Hex-encoded ECIES-wrapped AES-256 key for decrypting subfolder metadata.
    pub folder_key_encrypted: String,
    /// Hex-encoded ECIES-wrapped Ed25519 private key for IPNS signing.
    pub ipns_private_key_encrypted: String,
    /// Creation timestamp (Unix ms).
    pub created_at: u64,
    /// Last modification timestamp (Unix ms).
    pub modified_at: u64,
}

/// File entry within folder metadata.
/// Contains reference to encrypted file on IPFS and ECIES-wrapped decryption key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    /// UUID for internal reference.
    pub id: String,
    /// File name (plaintext, since whole metadata is encrypted).
    pub name: String,
    /// IPFS CID of the encrypted file content.
    pub cid: String,
    /// Hex-encoded ECIES-wrapped AES-256 key for decrypting file.
    pub file_key_encrypted: String,
    /// Hex-encoded IV used for file encryption.
    pub file_iv: String,
    /// Original file size in bytes (before encryption).
    pub size: u64,
    /// Creation timestamp (Unix ms).
    pub created_at: u64,
    /// Last modification timestamp (Unix ms).
    pub modified_at: u64,
    /// Encryption mode (always "GCM" for v1.0).
    pub encryption_mode: String,
}

/// Encrypt folder metadata with AES-256-GCM.
///
/// JSON serializes the metadata, then seals with AES-GCM.
/// Returns the sealed bytes: IV (12) || ciphertext || tag (16).
pub fn encrypt_folder_metadata(
    metadata: &FolderMetadata,
    folder_key: &[u8; 32],
) -> Result<Vec<u8>, FolderError> {
    let mut json = serde_json::to_vec(metadata).map_err(|_| FolderError::SerializationFailed)?;
    let result = aes::seal_aes_gcm(&json, folder_key).map_err(FolderError::EncryptionFailed);
    json.zeroize();
    result
}

/// Decrypt folder metadata from AES-256-GCM sealed bytes.
///
/// Unseals, then JSON deserializes to FolderMetadata.
pub fn decrypt_folder_metadata(
    sealed: &[u8],
    folder_key: &[u8; 32],
) -> Result<FolderMetadata, FolderError> {
    let mut json = aes::unseal_aes_gcm(sealed, folder_key).map_err(FolderError::EncryptionFailed)?;
    let result = serde_json::from_slice(&json).map_err(|_| FolderError::DeserializationFailed);
    json.zeroize();
    result
}
