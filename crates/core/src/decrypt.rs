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

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_crypto::aes;

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    /// Helper: encrypt metadata with seal_aes_gcm, split into IV + ciphertext,
    /// then wrap in the JSON `{"iv":"hex","data":"base64"}` format that IPFS uses.
    fn encrypt_to_ipfs_json(plaintext_json: &[u8], key: &[u8; 32]) -> Vec<u8> {
        use base64::Engine;
        let sealed = aes::seal_aes_gcm(plaintext_json, key).unwrap();
        let iv_hex = hex::encode(&sealed[..12]);
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
        let json = serde_json::json!({
            "iv": iv_hex,
            "data": ciphertext_b64
        });
        serde_json::to_vec(&json).unwrap()
    }

    #[test]
    fn decrypt_metadata_from_ipfs_public_round_trip() {
        let key = test_key();
        let folder_meta = crate::folder::FolderMetadata {
            version: "v2".to_string(),
            children: vec![],
        };
        let plaintext = serde_json::to_vec(&folder_meta).unwrap();
        let encrypted_json = encrypt_to_ipfs_json(&plaintext, &key);

        let decrypted = decrypt_metadata_from_ipfs_public(&encrypted_json, &key).unwrap();
        assert_eq!(decrypted.version, "v2");
        assert!(decrypted.children.is_empty());
    }

    #[test]
    fn decrypt_file_metadata_from_ipfs_public_round_trip() {
        let key = test_key();
        let file_meta = crate::folder::FileMetadata {
            version: "v1".to_string(),
            cid: "bafytest".to_string(),
            file_key_encrypted: "aabb".to_string(),
            file_iv: "ccdd".to_string(),
            size: 1024,
            mime_type: "text/plain".to_string(),
            encryption_mode: "GCM".to_string(),
            created_at: 1000,
            modified_at: 2000,
            versions: None,
        };
        let plaintext = serde_json::to_vec(&file_meta).unwrap();
        let encrypted_json = encrypt_to_ipfs_json(&plaintext, &key);

        let decrypted = decrypt_file_metadata_from_ipfs_public(&encrypted_json, &key).unwrap();
        assert_eq!(decrypted.version, "v1");
        assert_eq!(decrypted.cid, "bafytest");
        assert_eq!(decrypted.size, 1024);
    }

    #[test]
    fn invalid_json_input_returns_error() {
        let key = test_key();
        let result = decrypt_metadata_from_ipfs_public(b"not json at all", &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse"));
    }

    #[test]
    fn invalid_base64_in_data_field_returns_error() {
        let key = test_key();
        let bad_json = serde_json::json!({
            "iv": "000000000000000000000000",  // 12 bytes in hex
            "data": "!!!not-base64!!!"
        });
        let bytes = serde_json::to_vec(&bad_json).unwrap();
        let result = decrypt_metadata_from_ipfs_public(&bytes, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("base64"));
    }

    #[test]
    fn invalid_iv_hex_returns_error() {
        let key = test_key();
        let bad_json = serde_json::json!({
            "iv": "zzzz",
            "data": "AAAA"
        });
        let bytes = serde_json::to_vec(&bad_json).unwrap();
        let result = decrypt_metadata_from_ipfs_public(&bytes, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("IV"));
    }

    #[test]
    fn wrong_key_returns_decryption_error() {
        let key = test_key();
        let wrong_key = [0xCD; 32];
        let folder_meta = crate::folder::FolderMetadata {
            version: "v2".to_string(),
            children: vec![],
        };
        let plaintext = serde_json::to_vec(&folder_meta).unwrap();
        let encrypted_json = encrypt_to_ipfs_json(&plaintext, &key);

        let result = decrypt_metadata_from_ipfs_public(&encrypted_json, &wrong_key);
        assert!(result.is_err());
    }
}
