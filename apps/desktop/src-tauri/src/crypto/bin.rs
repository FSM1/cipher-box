//! Recycle bin metadata types and encryption.
//!
//! Mirrors the TypeScript `RecycleBinMetadata` and `BinEntry` types from
//! `@cipherbox/crypto` for cross-platform compatibility. Uses ECIES
//! (same as DeviceRegistry) for encryption -- the user's secp256k1
//! publicKey encrypts, privateKey decrypts.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::folder::{FilePointer, FolderEntry};

#[derive(Debug, Error)]
pub enum BinError {
    #[error("Bin metadata encryption failed")]
    EncryptionFailed,
    #[error("Bin metadata decryption failed")]
    DecryptionFailed,
    #[error("Bin metadata serialization failed")]
    SerializationFailed,
    #[error("Bin metadata deserialization failed")]
    DeserializationFailed,
    #[error("Bin metadata validation failed: {0}")]
    ValidationFailed(String),
}

/// Top-level recycle bin metadata structure.
/// Encrypted as a whole blob via ECIES with the user's secp256k1 publicKey.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecycleBinMetadata {
    pub version: String,
    pub sequence_number: u64,
    pub entries: Vec<BinEntry>,
}

/// A single item in the recycle bin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BinEntry {
    pub id: String,
    pub item_type: BinItemType,
    pub name: String,
    pub original_parent_ipns_name: String,
    pub original_path: String,
    pub deleted_at: u64,
    pub size: u64,
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub file_pointer: Option<FilePointer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub folder_entry: Option<FolderEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BinItemType {
    File,
    Folder,
}

/// Encrypt bin metadata with ECIES using user's secp256k1 public key.
///
/// JSON-serializes the metadata, then encrypts the entire blob with ECIES.
/// Cross-compatible with TypeScript `encryptBinMetadata` from @cipherbox/crypto.
pub fn encrypt_bin_metadata(
    metadata: &RecycleBinMetadata,
    user_public_key: &[u8],
) -> Result<Vec<u8>, BinError> {
    let json = serde_json::to_vec(metadata)
        .map_err(|_| BinError::SerializationFailed)?;
    crate::crypto::ecies::wrap_key(&json, user_public_key)
        .map_err(|_| BinError::EncryptionFailed)
}

/// Decrypt bin metadata with ECIES using user's secp256k1 private key.
pub fn decrypt_bin_metadata(
    ciphertext: &[u8],
    user_private_key: &[u8],
) -> Result<RecycleBinMetadata, BinError> {
    let plaintext = crate::crypto::ecies::unwrap_key(ciphertext, user_private_key)
        .map_err(|_| BinError::DecryptionFailed)?;
    let metadata: RecycleBinMetadata = serde_json::from_slice(&plaintext)
        .map_err(|_| BinError::DeserializationFailed)?;
    if metadata.version != "v1" {
        return Err(BinError::ValidationFailed(
            format!("Unsupported bin metadata version: {}", metadata.version),
        ));
    }
    Ok(metadata)
}

/// Create a new empty RecycleBinMetadata.
pub fn empty_bin_metadata() -> RecycleBinMetadata {
    RecycleBinMetadata {
        version: "v1".to_string(),
        sequence_number: 0,
        entries: vec![],
    }
}

// generate_uuid_v4 and mime_from_extension are in crate::crypto::utils
