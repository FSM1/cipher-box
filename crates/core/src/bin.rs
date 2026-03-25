//! Recycle bin metadata types and encryption.
//!
//! Mirrors the TypeScript `RecycleBinMetadata` and `BinEntry` types from
//! `@cipherbox/core` for cross-platform compatibility. Uses ECIES
//! (same as DeviceRegistry) for encryption -- the user's secp256k1
//! publicKey encrypts, privateKey decrypts.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::folder::{FilePointer, FolderEntry};

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
    pub content_cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub content_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub version_cids: Option<Vec<VersionCidEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub file_pointer: Option<FilePointer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub folder_entry: Option<FolderEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionCidEntry {
    pub cid: String,
    pub size: u64,
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
    cipherbox_crypto::ecies::wrap_key(&json, user_public_key)
        .map_err(|_| BinError::EncryptionFailed)
}

/// Decrypt bin metadata with ECIES using user's secp256k1 private key.
pub fn decrypt_bin_metadata(
    ciphertext: &[u8],
    user_private_key: &[u8],
) -> Result<RecycleBinMetadata, BinError> {
    let plaintext = cipherbox_crypto::ecies::unwrap_key(ciphertext, user_private_key)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a secp256k1 keypair for ECIES tests.
    /// Returns (private_key_32bytes, public_key_65bytes_uncompressed).
    fn generate_secp256k1_keypair() -> (Vec<u8>, Vec<u8>) {
        let (sk, pk) = ecies::utils::generate_keypair();
        (sk.serialize().to_vec(), pk.serialize().to_vec())
    }

    fn sample_bin_entry() -> BinEntry {
        BinEntry {
            id: "entry-1".to_string(),
            item_type: BinItemType::File,
            name: "deleted-photo.jpg".to_string(),
            original_parent_ipns_name: "k51parent".to_string(),
            original_path: "/Documents/deleted-photo.jpg".to_string(),
            deleted_at: 1700000000000,
            size: 4096,
            mime_type: "image/jpeg".to_string(),
            content_cid: Some("bafyfile123".to_string()),
            content_size: Some(4096),
            version_cids: None,
            file_pointer: None,
            folder_entry: None,
        }
    }

    #[test]
    fn empty_bin_metadata_returns_v1_with_empty_entries() {
        let meta = empty_bin_metadata();
        assert_eq!(meta.version, "v1");
        assert_eq!(meta.sequence_number, 0);
        assert!(meta.entries.is_empty());
    }

    #[test]
    fn encrypt_decrypt_bin_metadata_round_trip() {
        let (sk, pk) = generate_secp256k1_keypair();
        let metadata = empty_bin_metadata();

        let encrypted = encrypt_bin_metadata(&metadata, &pk).unwrap();
        let decrypted = decrypt_bin_metadata(&encrypted, &sk).unwrap();

        assert_eq!(decrypted.version, "v1");
        assert_eq!(decrypted.sequence_number, 0);
        assert!(decrypted.entries.is_empty());
    }

    #[test]
    fn encrypt_decrypt_bin_metadata_with_entries() {
        let (sk, pk) = generate_secp256k1_keypair();
        let metadata = RecycleBinMetadata {
            version: "v1".to_string(),
            sequence_number: 5,
            entries: vec![
                sample_bin_entry(),
                BinEntry {
                    id: "entry-2".to_string(),
                    item_type: BinItemType::Folder,
                    name: "old-folder".to_string(),
                    original_parent_ipns_name: "k51root".to_string(),
                    original_path: "/old-folder".to_string(),
                    deleted_at: 1700000001000,
                    size: 0,
                    mime_type: "".to_string(),
                    content_cid: None,
                    content_size: None,
                    version_cids: None,
                    file_pointer: None,
                    folder_entry: Some(FolderEntry {
                        id: "folder-id".to_string(),
                        name: "old-folder".to_string(),
                        ipns_name: "k51folder".to_string(),
                        folder_key_encrypted: "aabb".to_string(),
                        ipns_private_key_encrypted: "ccdd".to_string(),
                        created_at: 1000,
                        modified_at: 2000,
                    }),
                },
            ],
        };

        let encrypted = encrypt_bin_metadata(&metadata, &pk).unwrap();
        let decrypted = decrypt_bin_metadata(&encrypted, &sk).unwrap();

        assert_eq!(decrypted.version, "v1");
        assert_eq!(decrypted.sequence_number, 5);
        assert_eq!(decrypted.entries.len(), 2);
        assert_eq!(decrypted.entries[0].id, "entry-1");
        assert_eq!(decrypted.entries[0].name, "deleted-photo.jpg");
        assert_eq!(decrypted.entries[1].id, "entry-2");
        assert!(decrypted.entries[1].folder_entry.is_some());
    }

    #[test]
    fn decrypt_bin_metadata_wrong_key_returns_error() {
        let (_, pk) = generate_secp256k1_keypair();
        let (wrong_sk, _) = generate_secp256k1_keypair();
        let metadata = empty_bin_metadata();

        let encrypted = encrypt_bin_metadata(&metadata, &pk).unwrap();
        let result = decrypt_bin_metadata(&encrypted, &wrong_sk);
        assert!(result.is_err());
    }

    #[test]
    fn bin_item_type_serializes_lowercase() {
        let file_json = serde_json::to_string(&BinItemType::File).unwrap();
        assert_eq!(file_json, r#""file""#);
        let folder_json = serde_json::to_string(&BinItemType::Folder).unwrap();
        assert_eq!(folder_json, r#""folder""#);
    }

    #[test]
    fn bin_metadata_camel_case_fields() {
        let metadata = RecycleBinMetadata {
            version: "v1".to_string(),
            sequence_number: 3,
            entries: vec![],
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("\"sequenceNumber\""));
        assert!(!json.contains("\"sequence_number\""));
    }
}
