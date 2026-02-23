//! Folder metadata types and encryption.
//!
//! Matches the TypeScript `FolderMetadata` type exactly.
//! Uses Serde `rename_all = "camelCase"` to produce JSON field names
//! identical to the TypeScript format.
//!
//! Only v2 schema (per-file IPNS pointers via FilePointer) is supported.
//! v1 (inline file data) has been removed.

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

/// Slim file reference stored in folder metadata.
/// Points to a file's own IPNS record instead of embedding all file data inline.
/// Matches TypeScript `FilePointer` from `@cipherbox/crypto/file/types.ts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilePointer {
    /// UUID for internal reference.
    pub id: String,
    /// File name (plaintext, since folder metadata is encrypted).
    pub name: String,
    /// IPNS name of the file's own metadata record.
    pub file_meta_ipns_name: String,
    /// Hex-encoded ECIES-wrapped Ed25519 private key for signing this file's IPNS record.
    /// Present for files created after the random-key migration. Absent for legacy files
    /// whose IPNS key is derived deterministically via HKDF.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ipns_private_key_encrypted: Option<String>,
    /// Creation timestamp (Unix ms).
    pub created_at: u64,
    /// Last modification timestamp (Unix ms).
    pub modified_at: u64,
}

/// A child entry can be either a folder or a file pointer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum FolderChild {
    /// A subfolder entry.
    Folder(FolderEntry),
    /// A file pointer referencing a per-file IPNS record.
    File(FilePointer),
}

/// Decrypted folder metadata structure (v2 schema with per-file IPNS pointers).
/// The entire FolderMetadata object is encrypted as a single blob with AES-256-GCM.
/// Children can be FolderEntry (subfolder) or FilePointer (slim IPNS reference).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderMetadata {
    /// Schema version (always "v2").
    pub version: String,
    /// Folders and file pointers in this folder.
    pub children: Vec<FolderChild>,
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
/// Rejects metadata with version other than "v2".
pub fn decrypt_folder_metadata(
    sealed: &[u8],
    folder_key: &[u8; 32],
) -> Result<FolderMetadata, FolderError> {
    let mut json = aes::unseal_aes_gcm(sealed, folder_key).map_err(FolderError::EncryptionFailed)?;

    // Parse as generic JSON to check version field
    let value: serde_json::Value =
        serde_json::from_slice(&json).map_err(|e| {
            log::error!("JSON parse failed: {}", e);
            json.zeroize();
            FolderError::DeserializationFailed
        })?;

    let version = value.get("version").and_then(|v| v.as_str());
    if version != Some("v2") {
        log::error!(
            "Unsupported folder metadata version: {:?} (only v2 is supported)",
            version
        );
        json.zeroize();
        return Err(FolderError::DeserializationFailed);
    }

    let result: Result<FolderMetadata, _> = serde_json::from_value(value).map_err(|e| {
        log::error!("V2 metadata deserialization failed: {}", e);
        FolderError::DeserializationFailed
    });

    json.zeroize();
    result
}

/// Default encryption mode for FileMetadata: "GCM".
fn default_encryption_mode() -> String {
    "GCM".to_string()
}

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

/// Decrypted per-file metadata structure.
/// Stored as an encrypted blob in the file's own IPNS record.
/// Encrypted with the parent folder's folderKey (NOT the file's own key).
/// Matches TypeScript `FileMetadata` from `@cipherbox/crypto/file/types.ts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadata {
    /// Schema version.
    pub version: String,
    /// IPFS CID of the encrypted file content.
    pub cid: String,
    /// Hex-encoded ECIES-wrapped AES-256 key for decrypting file.
    pub file_key_encrypted: String,
    /// Hex-encoded IV used for file encryption.
    pub file_iv: String,
    /// Original file size in bytes (before encryption).
    pub size: u64,
    /// MIME type of the original file.
    pub mime_type: String,
    /// Encryption mode (optional for backward compat; defaults to "GCM").
    #[serde(default = "default_encryption_mode")]
    pub encryption_mode: String,
    /// Creation timestamp (Unix ms).
    pub created_at: u64,
    /// Last modification timestamp (Unix ms).
    pub modified_at: u64,
    /// Past versions of this file (newest first). None if no versions exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub versions: Option<Vec<VersionEntry>>,
}

/// Encrypt file metadata with AES-256-GCM.
///
/// JSON serializes the metadata, then seals with AES-GCM.
/// Uses the parent folder's folderKey for encryption.
/// Returns the sealed bytes: IV (12) || ciphertext || tag (16).
pub fn encrypt_file_metadata(
    metadata: &FileMetadata,
    folder_key: &[u8; 32],
) -> Result<Vec<u8>, FolderError> {
    let mut json = serde_json::to_vec(metadata).map_err(|_| FolderError::SerializationFailed)?;
    let result = aes::seal_aes_gcm(&json, folder_key).map_err(FolderError::EncryptionFailed);
    json.zeroize();
    result
}

/// Decrypt file metadata from AES-256-GCM sealed bytes.
///
/// Uses the parent folder's folderKey for decryption.
/// Unseals, then JSON deserializes to FileMetadata.
pub fn decrypt_file_metadata(
    sealed: &[u8],
    folder_key: &[u8; 32],
) -> Result<FileMetadata, FolderError> {
    let mut json = aes::unseal_aes_gcm(sealed, folder_key).map_err(FolderError::EncryptionFailed)?;
    let result = serde_json::from_slice(&json).map_err(|_| FolderError::DeserializationFailed);
    json.zeroize();
    result
}
