//! Recycle bin metadata types and encryption.
//!
//! Mirrors the TypeScript `RecycleBinMetadata` and `BinEntry` types from
//! `@cipherbox/core` for cross-platform compatibility. Uses ECIES
//! (same as DeviceRegistry) for encryption -- the user's secp256k1
//! publicKey encrypts, privateKey decrypts.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::node::{SealedChildRef, WriteChildRef};

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
    /// node/v3 restore keeper: base64 of the deleted node's
    /// `encode_published_node` (a re-upload blob so a later restore can
    /// re-publish the child node). Best-effort at delete time — may be an
    /// empty string when the sealed envelope is not available without I/O.
    /// Serialized as `childPublishedNode`.
    pub child_published_node: String,
    /// node/v3 READ-plane link (keyed by ipnsName): the child's readKey sealed
    /// under the ORIGINAL parent's readKey. Re-spliced into a target parent's
    /// read-body on restore. Distinct from `write_child_ref` (D-07) — never
    /// conflate `child_ref.ipns_name` (a k51) with `write_child_ref.child_id`
    /// (a UUID). Serialized as `childRef`.
    pub child_ref: SealedChildRef,
    /// node/v3 WRITE-plane link (keyed by childId UUID, D-07): the child's
    /// writeKey sealed under the ORIGINAL parent's writeKey. Re-spliced into a
    /// target parent's write-body on restore. Serialized as `writeChildRef`.
    pub write_child_ref: WriteChildRef,
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
    let json = serde_json::to_vec(metadata).map_err(|_| BinError::SerializationFailed)?;
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
    let metadata: RecycleBinMetadata =
        serde_json::from_slice(&plaintext).map_err(|_| BinError::DeserializationFailed)?;
    if metadata.version != "v1" {
        return Err(BinError::ValidationFailed(format!(
            "Unsupported bin metadata version: {}",
            metadata.version
        )));
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

    /// A sample READ-plane child ref keyed by ipnsName (a k51 identity).
    fn sample_child_ref(ipns_name: &str) -> SealedChildRef {
        SealedChildRef {
            name: "deleted-photo.jpg".to_string(),
            ipns_name: ipns_name.to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: "cmVhZC1rZXktc2VhbGVk".to_string(),
        }
    }

    /// A sample WRITE-plane child ref keyed by childId (a UUID) — D-07 distinct
    /// from the read plane's `ipns_name`.
    fn sample_write_child_ref(child_id: &str) -> WriteChildRef {
        WriteChildRef {
            child_id: child_id.to_string(),
            write_key_sealed: "d3JpdGUta2V5LXNlYWxlZA==".to_string(),
        }
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
            child_published_node: "cHVibGlzaGVkLW5vZGU=".to_string(),
            child_ref: sample_child_ref("k51file-abc"),
            write_child_ref: sample_write_child_ref("550e8400-e29b-41d4-a716-446655440000"),
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
                    child_published_node: String::new(),
                    child_ref: SealedChildRef {
                        name: "old-folder".to_string(),
                        ipns_name: "k51folder".to_string(),
                        generation: 0,
                        version_floor: 0,
                        read_key_sealed: "Zm9sZGVyLXJlYWQ=".to_string(),
                    },
                    write_child_ref: sample_write_child_ref("660e8400-e29b-41d4-a716-446655440001"),
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
        assert_eq!(
            decrypted.entries[0].child_ref.ipns_name, "k51file-abc",
            "the node/v3 read-plane child ref must survive the encrypt/decrypt round trip"
        );
        assert_eq!(
            decrypted.entries[0].write_child_ref.child_id, "550e8400-e29b-41d4-a716-446655440000",
            "the node/v3 write-plane child ref must survive the encrypt/decrypt round trip"
        );
        assert_eq!(decrypted.entries[1].id, "entry-2");
        assert_eq!(decrypted.entries[1].child_ref.ipns_name, "k51folder");
    }

    /// D-07 non-conflation: the write plane is keyed by a UUID `child_id` and
    /// the read plane by a k51 `ipns_name` — the two key spaces must never be
    /// equal. Guards the invariant at the type level (project memory
    /// "write plane keyed by UUID, read plane by ipnsName").
    #[test]
    fn child_ref_ipns_name_never_equals_write_child_ref_child_id() {
        let entry = sample_bin_entry();
        assert_ne!(
            entry.write_child_ref.child_id, entry.child_ref.ipns_name,
            "D-07: WriteChildRef.child_id (a UUID) must never equal SealedChildRef.ipns_name (a k51)"
        );
    }

    #[test]
    fn node_v3_restore_fields_serialize_camel_case() {
        let json = serde_json::to_string(&sample_bin_entry()).unwrap();
        assert!(json.contains("\"childPublishedNode\""));
        assert!(json.contains("\"childRef\""));
        assert!(json.contains("\"writeChildRef\""));
        // The legacy fields are gone — never emitted on the wire.
        assert!(!json.contains("originalFolderKeyEncrypted"));
        assert!(!json.contains("filePointer"));
        assert!(!json.contains("folderEntry"));
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
