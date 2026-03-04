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

/// Generate a random UUID v4 string.
/// Uses the same pattern as `registry/mod.rs::generate_uuid_v4`.
pub fn generate_uuid_v4() -> String {
    let bytes = crate::crypto::utils::generate_random_bytes(16);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6] & 0x0f, bytes[7],
        (bytes[8] & 0x3f) | 0x80, bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Guess MIME type from file extension.
/// Simple inline mapping to avoid adding `mime_guess` dependency.
pub fn guess_mime_type(filename: &str) -> &'static str {
    let ext = filename
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/x-rar-compressed",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "tiff" | "tif" => "image/tiff",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "csv" => "text/csv",
        "md" => "text/markdown",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}
