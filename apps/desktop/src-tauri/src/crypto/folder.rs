//! Folder metadata types and encryption.
//!
//! Matches the TypeScript `FolderMetadata` and `FolderMetadataV2` types exactly.
//! Uses Serde `rename_all = "camelCase"` to produce JSON field names
//! identical to the TypeScript format.
//!
//! Supports both v1 (inline file data) and v2 (per-file IPNS pointer) schemas.

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

// ============================================================
// v2 Folder Metadata Types (per-file IPNS pointers)
// ============================================================

/// Slim file reference stored in v2 folder metadata.
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
    /// Creation timestamp (Unix ms).
    pub created_at: u64,
    /// Last modification timestamp (Unix ms).
    pub modified_at: u64,
}

/// A v2 child entry can be either a folder or a file pointer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum FolderChildV2 {
    /// A subfolder entry (same structure as v1).
    Folder(FolderEntry),
    /// A file pointer referencing a per-file IPNS record.
    File(FilePointer),
}

/// v2 folder metadata with per-file IPNS pointers instead of inline file data.
/// Children can be FolderEntry (unchanged) or FilePointer (slim IPNS reference).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderMetadataV2 {
    /// Schema version for v2 format.
    pub version: String,
    /// Folders and file pointers in this folder.
    pub children: Vec<FolderChildV2>,
}

/// Union type for version-dispatched folder metadata parsing.
/// Accepts both v1 and v2 folder metadata.
#[derive(Debug, Clone)]
pub enum AnyFolderMetadata {
    V1(FolderMetadata),
    V2(FolderMetadataV2),
}

impl AnyFolderMetadata {
    /// Convert to v1 FolderMetadata for FUSE layer compatibility.
    ///
    /// V1 is returned as-is. V2 is converted by mapping FilePointers to
    /// placeholder FileEntries (the FUSE layer resolves actual file metadata
    /// via per-file IPNS lookups).
    pub fn to_v1(&self) -> FolderMetadata {
        match self {
            AnyFolderMetadata::V1(v1) => v1.clone(),
            AnyFolderMetadata::V2(v2) => {
                let children = v2.children.iter().map(|child| match child {
                    FolderChildV2::Folder(entry) => FolderChild::Folder(entry.clone()),
                    FolderChildV2::File(ptr) => FolderChild::File(FileEntry {
                        id: ptr.id.clone(),
                        name: ptr.name.clone(),
                        cid: String::new(), // Resolved via per-file IPNS
                        file_key_encrypted: String::new(), // Resolved via per-file IPNS
                        file_iv: String::new(), // Resolved via per-file IPNS
                        size: 0, // Unknown until file metadata resolved
                        created_at: ptr.created_at,
                        modified_at: ptr.modified_at,
                        encryption_mode: "GCM".to_string(),
                    }),
                }).collect();
                FolderMetadata {
                    version: "v1".to_string(),
                    children,
                }
            }
        }
    }

    /// Get the number of children in this folder metadata.
    pub fn children_len(&self) -> usize {
        match self {
            AnyFolderMetadata::V1(v1) => v1.children.len(),
            AnyFolderMetadata::V2(v2) => v2.children.len(),
        }
    }
}

/// Default encryption mode for FileMetadata: "GCM".
fn default_encryption_mode() -> String {
    "GCM".to_string()
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
}

/// Decrypt folder metadata from AES-256-GCM sealed bytes, dispatching to v1 or v2.
///
/// Decrypts the sealed blob, then checks the `version` field to determine format.
pub fn decrypt_any_folder_metadata(
    sealed: &[u8],
    folder_key: &[u8; 32],
) -> Result<AnyFolderMetadata, FolderError> {
    let mut json = aes::unseal_aes_gcm(sealed, folder_key).map_err(FolderError::EncryptionFailed)?;

    // Debug: log the decrypted JSON to diagnose deserialization failures
    if let Ok(s) = std::str::from_utf8(&json) {
        let preview = if s.len() > 4000 { &s[..4000] } else { s };
        log::debug!("Decrypted folder metadata JSON: {}", preview);
    }

    // Parse as generic JSON to check version field
    let value: serde_json::Value =
        serde_json::from_slice(&json).map_err(|e| {
            log::error!("JSON parse failed: {}", e);
            FolderError::DeserializationFailed
        })?;

    let result = match value.get("version").and_then(|v| v.as_str()) {
        Some("v2") => {
            // Try strict v2 first (FilePointer children with fileMetaIpnsName).
            // Fall back to v1 parsing if the web app wrote v2-tagged metadata
            // with v1-style inline file entries (cid, fileKeyEncrypted, etc.).
            match serde_json::from_value::<FolderMetadataV2>(value.clone()) {
                Ok(v2) => Ok(AnyFolderMetadata::V2(v2)),
                Err(v2_err) => {
                    log::debug!("V2 parse failed ({}), trying v1 fallback", v2_err);
                    let v1: FolderMetadata =
                        serde_json::from_value(value).map_err(|e| {
                            log::error!("V1 fallback also failed: {}", e);
                            FolderError::DeserializationFailed
                        })?;
                    Ok(AnyFolderMetadata::V1(v1))
                }
            }
        }
        _ => {
            // Default to v1 for backward compatibility
            let v1: FolderMetadata =
                serde_json::from_value(value).map_err(|e| {
                    log::error!("V1 metadata deserialization failed: {}", e);
                    FolderError::DeserializationFailed
                })?;
            Ok(AnyFolderMetadata::V1(v1))
        }
    };

    json.zeroize();
    result
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
