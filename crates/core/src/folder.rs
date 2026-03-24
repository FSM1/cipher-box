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

use cipherbox_crypto::aes;
use cipherbox_crypto::error::CryptoError;

#[derive(Debug, Error)]
pub enum FolderError {
    #[error("Crypto operation failed")]
    EncryptionFailed(#[from] CryptoError),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    fn sample_folder_metadata_empty() -> FolderMetadata {
        FolderMetadata {
            version: "v2".to_string(),
            children: vec![],
        }
    }

    fn sample_folder_metadata_with_children() -> FolderMetadata {
        FolderMetadata {
            version: "v2".to_string(),
            children: vec![
                FolderChild::Folder(FolderEntry {
                    id: "folder-1".to_string(),
                    name: "Documents".to_string(),
                    ipns_name: "k51abc".to_string(),
                    folder_key_encrypted: "deadbeef".to_string(),
                    ipns_private_key_encrypted: "cafebabe".to_string(),
                    created_at: 1700000000000,
                    modified_at: 1700000001000,
                }),
                FolderChild::File(FilePointer {
                    id: "file-1".to_string(),
                    name: "photo.jpg".to_string(),
                    file_meta_ipns_name: "k51def".to_string(),
                    ipns_private_key_encrypted: Some("aabbccdd".to_string()),
                    created_at: 1700000002000,
                    modified_at: 1700000003000,
                }),
            ],
        }
    }

    fn sample_file_metadata() -> FileMetadata {
        FileMetadata {
            version: "v1".to_string(),
            cid: "bafy123".to_string(),
            file_key_encrypted: "encrypted-key-hex".to_string(),
            file_iv: "aabbccdd".to_string(),
            size: 4096,
            mime_type: "image/jpeg".to_string(),
            encryption_mode: "GCM".to_string(),
            created_at: 1700000000000,
            modified_at: 1700000001000,
            versions: None,
        }
    }

    #[test]
    fn encrypt_decrypt_folder_metadata_empty_children() {
        let key = test_key();
        let metadata = sample_folder_metadata_empty();
        let sealed = encrypt_folder_metadata(&metadata, &key).unwrap();
        let decrypted = decrypt_folder_metadata(&sealed, &key).unwrap();
        assert_eq!(decrypted.version, "v2");
        assert!(decrypted.children.is_empty());
    }

    #[test]
    fn encrypt_decrypt_folder_metadata_with_children() {
        let key = test_key();
        let metadata = sample_folder_metadata_with_children();
        let sealed = encrypt_folder_metadata(&metadata, &key).unwrap();
        let decrypted = decrypt_folder_metadata(&sealed, &key).unwrap();
        assert_eq!(decrypted.version, "v2");
        assert_eq!(decrypted.children.len(), 2);

        // Verify folder child
        match &decrypted.children[0] {
            FolderChild::Folder(f) => {
                assert_eq!(f.id, "folder-1");
                assert_eq!(f.name, "Documents");
                assert_eq!(f.ipns_name, "k51abc");
            }
            _ => panic!("Expected FolderChild::Folder"),
        }

        // Verify file child
        match &decrypted.children[1] {
            FolderChild::File(f) => {
                assert_eq!(f.id, "file-1");
                assert_eq!(f.name, "photo.jpg");
                assert_eq!(f.file_meta_ipns_name, "k51def");
                assert_eq!(f.ipns_private_key_encrypted, Some("aabbccdd".to_string()));
            }
            _ => panic!("Expected FolderChild::File"),
        }
    }

    #[test]
    fn decrypt_folder_metadata_wrong_key_returns_error() {
        let key = test_key();
        let wrong_key = [0xCD; 32];
        let metadata = sample_folder_metadata_empty();
        let sealed = encrypt_folder_metadata(&metadata, &key).unwrap();
        let result = decrypt_folder_metadata(&sealed, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_file_metadata_round_trip() {
        let key = test_key();
        let metadata = sample_file_metadata();
        let sealed = encrypt_file_metadata(&metadata, &key).unwrap();
        let decrypted = decrypt_file_metadata(&sealed, &key).unwrap();
        assert_eq!(decrypted.version, "v1");
        assert_eq!(decrypted.cid, "bafy123");
        assert_eq!(decrypted.file_key_encrypted, "encrypted-key-hex");
        assert_eq!(decrypted.file_iv, "aabbccdd");
        assert_eq!(decrypted.size, 4096);
        assert_eq!(decrypted.mime_type, "image/jpeg");
        assert_eq!(decrypted.encryption_mode, "GCM");
        assert_eq!(decrypted.created_at, 1700000000000);
        assert_eq!(decrypted.modified_at, 1700000001000);
        assert!(decrypted.versions.is_none());
    }

    #[test]
    fn version_field_preserved_in_folder_metadata() {
        let key = test_key();
        let metadata = FolderMetadata {
            version: "v2".to_string(),
            children: vec![],
        };
        let sealed = encrypt_folder_metadata(&metadata, &key).unwrap();
        let decrypted = decrypt_folder_metadata(&sealed, &key).unwrap();
        assert_eq!(decrypted.version, "v2");
    }

    #[test]
    fn decrypt_folder_metadata_rejects_non_v2() {
        let key = test_key();
        // Manually create v1 metadata JSON, encrypt it, and try to decrypt
        let v1_json = serde_json::json!({
            "version": "v1",
            "children": []
        });
        let json_bytes = serde_json::to_vec(&v1_json).unwrap();
        let sealed = aes::seal_aes_gcm(&json_bytes, &key).unwrap();
        let result = decrypt_folder_metadata(&sealed, &key);
        assert!(result.is_err());
    }

    #[test]
    fn file_metadata_default_encryption_mode() {
        // JSON without encryptionMode should default to "GCM"
        let json = r#"{
            "version": "v1",
            "cid": "bafy",
            "fileKeyEncrypted": "aabb",
            "fileIv": "ccdd",
            "size": 100,
            "mimeType": "text/plain",
            "createdAt": 0,
            "modifiedAt": 0
        }"#;
        let metadata: FileMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.encryption_mode, "GCM");
    }

    #[test]
    fn file_metadata_with_versions_round_trip() {
        let key = test_key();
        let metadata = FileMetadata {
            version: "v1".to_string(),
            cid: "bafy-current".to_string(),
            file_key_encrypted: "key-hex".to_string(),
            file_iv: "iv-hex".to_string(),
            size: 2048,
            mime_type: "application/pdf".to_string(),
            encryption_mode: "GCM".to_string(),
            created_at: 1000,
            modified_at: 2000,
            versions: Some(vec![VersionEntry {
                cid: "bafy-old".to_string(),
                file_key_encrypted: "old-key".to_string(),
                file_iv: "old-iv".to_string(),
                size: 1024,
                timestamp: 500,
                encryption_mode: "GCM".to_string(),
            }]),
        };
        let sealed = encrypt_file_metadata(&metadata, &key).unwrap();
        let decrypted = decrypt_file_metadata(&sealed, &key).unwrap();
        let versions = decrypted.versions.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].cid, "bafy-old");
        assert_eq!(versions[0].size, 1024);
    }
}
