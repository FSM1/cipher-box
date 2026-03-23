//! Vault blob v2 format: binary envelope for root folder IPFS blobs.
//!
//! Format: 0x02 | uint16_BE(key_len) | ECIES_encrypted_key | AES_GCM_metadata_json
//!
//! v1 blobs are plain JSON: {"iv":"...","data":"..."}
//! v2 blobs prepend the ECIES-wrapped rootFolderKey before the metadata JSON.

/// Version byte for v2 format.
pub const BLOB_V2_VERSION: u8 = 0x02;

/// Detect whether a vault blob is v1 (JSON) or v2 (binary envelope).
///
/// v1 blobs start with 0x7B ('{' -- JSON). v2 blobs start with 0x02.
pub fn detect_blob_version(blob: &[u8]) -> u8 {
    if !blob.is_empty() && blob[0] == BLOB_V2_VERSION {
        2
    } else {
        1
    }
}

/// Serialize a vault blob v2.
///
/// Produces: `0x02 | uint16_BE(key_len) | encrypted_root_folder_key | encrypted_metadata_json`
pub fn serialize_vault_blob_v2(
    encrypted_root_folder_key: &[u8],
    encrypted_metadata_json: &[u8],
) -> Result<Vec<u8>, String> {
    if encrypted_root_folder_key.len() > u16::MAX as usize {
        return Err(format!(
            "Encrypted key too long for v2 blob ({} bytes, max {})",
            encrypted_root_folder_key.len(),
            u16::MAX
        ));
    }
    let key_len = encrypted_root_folder_key.len() as u16;
    let mut result =
        Vec::with_capacity(3 + encrypted_root_folder_key.len() + encrypted_metadata_json.len());
    result.push(BLOB_V2_VERSION);
    result.push((key_len >> 8) as u8);
    result.push((key_len & 0xff) as u8);
    result.extend_from_slice(encrypted_root_folder_key);
    result.extend_from_slice(encrypted_metadata_json);
    Ok(result)
}

/// Deserialize a vault blob v2 into (encrypted_key, encrypted_metadata_json).
///
/// Returns borrowed slices into the original blob for zero-copy parsing.
pub fn deserialize_vault_blob_v2(blob: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if blob.len() < 3 {
        return Err(format!(
            "Vault blob too short for v2 header (need at least 3 bytes, have {})",
            blob.len()
        ));
    }
    if blob[0] != BLOB_V2_VERSION {
        return Err("Not a v2 vault blob".into());
    }
    let key_len = ((blob[1] as usize) << 8) | (blob[2] as usize);
    if blob.len() < 3 + key_len {
        return Err(format!(
            "Vault blob too short for key (expected {} bytes, have {})",
            key_len,
            blob.len() - 3
        ));
    }
    Ok((&blob[3..3 + key_len], &blob[3 + key_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let key = vec![0xAA; 129];
        let metadata = b"{\"iv\":\"abc\",\"data\":\"def\"}";
        let blob = serialize_vault_blob_v2(&key, metadata).unwrap();
        let (decoded_key, decoded_meta) = deserialize_vault_blob_v2(&blob).unwrap();
        assert_eq!(decoded_key, key.as_slice());
        assert_eq!(decoded_meta, metadata);
    }

    #[test]
    fn test_detect_v2() {
        let blob = serialize_vault_blob_v2(&[0; 129], b"test").unwrap();
        assert_eq!(detect_blob_version(&blob), 2);
    }

    #[test]
    fn test_detect_v1() {
        let v1 = b"{\"iv\":\"abc\",\"data\":\"def\"}";
        assert_eq!(detect_blob_version(v1), 1);
    }

    #[test]
    fn test_deserialize_v1_blob_errors() {
        let v1 = b"{\"iv\":\"abc\"}";
        assert!(deserialize_vault_blob_v2(v1).is_err());
    }

    #[test]
    fn test_deserialize_empty_blob_errors() {
        assert!(deserialize_vault_blob_v2(&[]).is_err());
    }

    #[test]
    fn test_deserialize_short_blob_errors() {
        assert!(deserialize_vault_blob_v2(&[0x02, 0x00]).is_err());
    }

    #[test]
    fn test_key_len_overflow_errors() {
        // Claim key is 1000 bytes but only provide 5
        let blob = vec![0x02, 0x03, 0xE8, 0, 0, 0, 0, 0];
        assert!(deserialize_vault_blob_v2(&blob).is_err());
    }

    #[test]
    fn test_header_format() {
        let key = vec![0xBB; 129];
        let meta = b"meta";
        let blob = serialize_vault_blob_v2(&key, meta).unwrap();
        assert_eq!(blob[0], 0x02);
        assert_eq!(blob[1], 0x00); // 129 >> 8 = 0
        assert_eq!(blob[2], 0x81); // 129 & 0xFF = 0x81
        assert_eq!(&blob[3..132], key.as_slice());
        assert_eq!(&blob[132..], b"meta");
    }

    // Cross-platform test vector: MUST match TypeScript vault-blob-vectors.test.ts
    // Key (129 bytes): 0xAA followed by 128 bytes incrementing 0x00..0x7F
    // Metadata: UTF-8 of '{"iv":"abc","data":"def"}'
    // Expected hex: 02 0081 aa 0001...7f 7b226976...7d
    #[test]
    fn test_cross_platform_vector() {
        // Build the same 129-byte key as TypeScript test vector
        let mut key = vec![0xAA];
        for i in 0u8..128 {
            key.push(i);
        }
        assert_eq!(key.len(), 129);

        let metadata = b"{\"iv\":\"abc\",\"data\":\"def\"}";
        let blob = serialize_vault_blob_v2(&key, metadata).unwrap();

        // Verify structure
        assert_eq!(blob[0], 0x02);
        assert_eq!(blob[1], 0x00);
        assert_eq!(blob[2], 0x81); // 129
        assert_eq!(blob.len(), 3 + 129 + metadata.len());

        // Verify exact hex matches TypeScript EXPECTED_HEX
        let blob_hex = hex::encode(&blob);
        let expected_hex = concat!(
            "02",   // version byte
            "0081", // key_len = 129
            "aa",   // key[0]
            "000102030405060708090a0b0c0d0e0f", // key[1..16]
            "101112131415161718191a1b1c1d1e1f", // key[17..32]
            "202122232425262728292a2b2c2d2e2f", // key[33..48]
            "303132333435363738393a3b3c3d3e3f", // key[49..64]
            "404142434445464748494a4b4c4d4e4f", // key[65..80]
            "505152535455565758595a5b5c5d5e5f", // key[81..96]
            "606162636465666768696a6b6c6d6e6f", // key[97..112]
            "707172737475767778797a7b7c7d7e7f", // key[113..128]
            "7b226976223a22616263222c2264617461223a22646566227d", // metadata JSON
        );
        assert_eq!(blob_hex, expected_hex);

        // Round-trip
        let (dk, dm) = deserialize_vault_blob_v2(&blob).unwrap();
        assert_eq!(dk, key.as_slice());
        assert_eq!(dm, metadata);
    }

    // Cross-platform test vector 2: minimal blob (1-byte key, 1-byte metadata)
    // Must match TypeScript Vector 2
    #[test]
    fn test_cross_platform_minimal_vector() {
        let key = vec![0xFF];
        let meta = vec![0x42];
        let blob = serialize_vault_blob_v2(&key, &meta).unwrap();
        let expected_hex = "020001ff42";
        assert_eq!(hex::encode(&blob), expected_hex);

        let (dk, dm) = deserialize_vault_blob_v2(&blob).unwrap();
        assert_eq!(dk, &[0xFF]);
        assert_eq!(dm, &[0x42]);
    }
}
