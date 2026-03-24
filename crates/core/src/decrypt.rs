//! Shared decrypt functions for folder and file metadata.
//! Used by CipherBoxFS::drain_refresh_completions() which is platform-agnostic.

use crate::folder::{FolderMetadata, FileMetadata};

/// Decrypt folder metadata from IPFS encrypted format.
///
/// All folder metadata (including root) uses v1 JSON `{"iv":"...","data":"..."}`.
/// The v2 blob format is only used for the vault key blob (separate IPNS name).
pub fn decrypt_metadata_from_ipfs_public(
    encrypted_bytes: &[u8],
    folder_key: &[u8],
) -> Result<FolderMetadata, String> {
    let json_portion = encrypted_bytes;

    #[derive(serde::Deserialize)]
    struct EncryptedFolderMetadata {
        iv: String,
        data: String,
    }

    let encrypted: EncryptedFolderMetadata = serde_json::from_slice(json_portion)
        .map_err(|e| format!("Failed to parse encrypted metadata JSON: {}", e))?;

    let iv_bytes =
        hex::decode(&encrypted.iv).map_err(|_| "Invalid metadata IV hex".to_string())?;
    if iv_bytes.len() != 12 {
        return Err(format!(
            "Invalid IV length: {} (expected 12)",
            iv_bytes.len()
        ));
    }
    let iv: [u8; 12] = iv_bytes.try_into().unwrap();

    use base64::Engine;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&encrypted.data)
        .map_err(|e| format!("Invalid metadata base64: {}", e))?;

    let folder_key_arr: [u8; 32] = folder_key
        .try_into()
        .map_err(|_| "Invalid folder key length".to_string())?;

    // Reconstruct sealed format: IV || ciphertext (includes tag)
    let mut sealed = Vec::with_capacity(12 + ciphertext.len());
    sealed.extend_from_slice(&iv);
    sealed.extend_from_slice(&ciphertext);

    crate::folder::decrypt_folder_metadata(&sealed, &folder_key_arr)
        .map_err(|e| format!("Metadata decryption failed: {}", e))
}

/// Decrypt file metadata from IPFS encrypted JSON format.
pub fn decrypt_file_metadata_from_ipfs_public(
    encrypted_bytes: &[u8],
    folder_key: &[u8; 32],
) -> Result<FileMetadata, String> {
    #[derive(serde::Deserialize)]
    struct EncryptedFolderMetadata {
        iv: String,
        data: String,
    }

    let encrypted: EncryptedFolderMetadata = serde_json::from_slice(encrypted_bytes)
        .map_err(|e| format!("Failed to parse encrypted file metadata JSON: {}", e))?;

    let iv_bytes = hex::decode(&encrypted.iv)
        .map_err(|_| "Invalid file metadata IV hex".to_string())?;
    if iv_bytes.len() != 12 {
        return Err(format!(
            "Invalid IV length: {} (expected 12)",
            iv_bytes.len()
        ));
    }
    let iv: [u8; 12] = iv_bytes.try_into().unwrap();

    use base64::Engine;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&encrypted.data)
        .map_err(|e| format!("Invalid file metadata base64: {}", e))?;

    // Reconstruct sealed format: IV || ciphertext (includes tag)
    let mut sealed = Vec::with_capacity(12 + ciphertext.len());
    sealed.extend_from_slice(&iv);
    sealed.extend_from_slice(&ciphertext);

    crate::folder::decrypt_file_metadata(&sealed, folder_key)
        .map_err(|e| format!("File metadata decryption failed: {}", e))
}
