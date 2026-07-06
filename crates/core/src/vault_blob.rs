//! Vault key blob v2 format: binary envelope for ECIES-wrapped rootFolderKey.
//!
//! Format: 0x02 | uint16_BE(key_len) | ECIES_encrypted_key
//!
//! This is a key-only blob -- folder metadata is stored separately at
//! the root folder's own IPNS name using standard v1 JSON format.

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

/// Serialize a vault key blob v2.
///
/// Produces: `0x02 | uint16_BE(key_len) | encrypted_root_folder_key`
pub fn serialize_vault_blob_v2(encrypted_root_folder_key: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted_root_folder_key.is_empty() {
        return Err("Encrypted key must not be empty for v2 blob".into());
    }
    if encrypted_root_folder_key.len() > u16::MAX as usize {
        return Err(format!(
            "Encrypted key too long for v2 blob ({} bytes, max {})",
            encrypted_root_folder_key.len(),
            u16::MAX
        ));
    }
    let key_len = encrypted_root_folder_key.len() as u16;
    let mut result = Vec::with_capacity(3 + encrypted_root_folder_key.len());
    result.push(BLOB_V2_VERSION);
    result.push((key_len >> 8) as u8);
    result.push((key_len & 0xff) as u8);
    result.extend_from_slice(encrypted_root_folder_key);
    Ok(result)
}

/// Deserialize a vault key blob v2 to extract the encrypted rootFolderKey.
///
/// Returns borrowed slice into the original blob for zero-copy parsing.
pub fn deserialize_vault_blob_v2(blob: &[u8]) -> Result<&[u8], String> {
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
    if key_len == 0 {
        return Err("Invalid v2 blob: encrypted key length must be > 0".into());
    }
    if blob.len() < 3 + key_len {
        return Err(format!(
            "Vault blob too short for key (expected {} bytes, have {})",
            key_len,
            blob.len() - 3
        ));
    }
    Ok(&blob[3..3 + key_len])
}

// ---------------------------------------------------------------------------
// Vault key blob v3 format (ADDITIVE — v2 above is untouched).
//
// Format: 0x03 | u16_BE(readLen) | ECIES(rootReadKey) | u16_BE(writeLen) | ECIES(rootWriteKey)
//
// Carries BOTH ECIES-wrapped root keys (rootReadKey + rootWriteKey) in one
// blob (NODE-06, D-05). This codec is pure envelope byte-manipulation — it
// performs NO crypto; the caller (69-23) supplies the already-ECIES-wrapped
// key bytes. Mirrors packages/core/src/vault/blob.ts field-for-field so a
// v3 vault minted on either client opens on the other (D-04).
// ---------------------------------------------------------------------------

/// Version byte for v3 format.
pub const BLOB_V3_VERSION: u8 = 0x03;

/// Serialize a vault key blob v3.
///
/// Produces: `0x03 | u16_BE(read_len) | enc_read | u16_BE(write_len) | enc_write`
///
/// Both segments must be non-empty and <= u16::MAX bytes. Envelope-only: the
/// caller supplies the already-ECIES-wrapped key bytes.
pub fn serialize_vault_blob_v3(
    encrypted_root_read_key: &[u8],
    encrypted_root_write_key: &[u8],
) -> Result<Vec<u8>, String> {
    if encrypted_root_read_key.is_empty() {
        return Err("Encrypted read key must not be empty for v3 blob".into());
    }
    if encrypted_root_read_key.len() > u16::MAX as usize {
        return Err(format!(
            "Encrypted read key too long for v3 blob ({} bytes, max {})",
            encrypted_root_read_key.len(),
            u16::MAX
        ));
    }
    if encrypted_root_write_key.is_empty() {
        return Err("Encrypted write key must not be empty for v3 blob".into());
    }
    if encrypted_root_write_key.len() > u16::MAX as usize {
        return Err(format!(
            "Encrypted write key too long for v3 blob ({} bytes, max {})",
            encrypted_root_write_key.len(),
            u16::MAX
        ));
    }

    let read_len = encrypted_root_read_key.len() as u16;
    let write_len = encrypted_root_write_key.len() as u16;

    // Layout: 0x03 | u16_BE(read_len) | enc_read | u16_BE(write_len) | enc_write
    let mut result = Vec::with_capacity(
        1 + 2 + encrypted_root_read_key.len() + 2 + encrypted_root_write_key.len(),
    );
    result.push(BLOB_V3_VERSION);
    result.push((read_len >> 8) as u8);
    result.push((read_len & 0xff) as u8);
    result.extend_from_slice(encrypted_root_read_key);
    result.push((write_len >> 8) as u8);
    result.push((write_len & 0xff) as u8);
    result.extend_from_slice(encrypted_root_write_key);
    Ok(result)
}

/// Deserialize a vault key blob v3 into OWNED (read_key, write_key) copies.
///
/// Returns owned `Vec<u8>` copies (not borrowed views) so a later zeroization
/// of the source blob cannot corrupt the recovered keys (D-09, mirrors
/// blob.ts `.slice()`). Fail-closed: wrong version / truncated / zero-length
/// segments return `Err` (never panics).
pub fn deserialize_vault_blob_v3(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if blob.len() < 5 {
        return Err(format!(
            "Vault blob too short for v3 header (need at least 5 bytes, have {})",
            blob.len()
        ));
    }
    if blob[0] != BLOB_V3_VERSION {
        return Err("Not a v3 vault blob".into());
    }

    let read_len = ((blob[1] as usize) << 8) | (blob[2] as usize);
    if read_len == 0 {
        return Err("Invalid v3 blob: read key length must be > 0".into());
    }
    if blob.len() < 3 + read_len + 2 {
        return Err("Vault blob truncated (missing write key header)".into());
    }

    // OWNED copy (not a borrowed view) so a later zeroization of the source
    // blob cannot corrupt the recovered key (D-09, mirrors blob.ts `.slice()`).
    let read_key = blob[3..3 + read_len].to_vec();

    let write_offset = 3 + read_len;
    let write_len = ((blob[write_offset] as usize) << 8) | (blob[write_offset + 1] as usize);
    if write_len == 0 {
        return Err("Invalid v3 blob: write key length must be > 0".into());
    }
    if blob.len() < write_offset + 2 + write_len {
        return Err("Vault blob truncated (write key)".into());
    }

    let write_key = blob[write_offset + 2..write_offset + 2 + write_len].to_vec();

    Ok((read_key, write_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let key = vec![0xAA; 129];
        let blob = serialize_vault_blob_v2(&key).unwrap();
        let decoded_key = deserialize_vault_blob_v2(&blob).unwrap();
        assert_eq!(decoded_key, key.as_slice());
    }

    #[test]
    fn test_detect_v2() {
        let blob = serialize_vault_blob_v2(&[0; 129]).unwrap();
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
        let blob = vec![0x02, 0x03, 0xE8, 0, 0, 0, 0, 0];
        assert!(deserialize_vault_blob_v2(&blob).is_err());
    }

    #[test]
    fn test_header_format() {
        let key = vec![0xBB; 129];
        let blob = serialize_vault_blob_v2(&key).unwrap();
        assert_eq!(blob[0], 0x02);
        assert_eq!(blob[1], 0x00); // 129 >> 8 = 0
        assert_eq!(blob[2], 0x81); // 129 & 0xFF = 0x81
        assert_eq!(&blob[3..], key.as_slice());
        assert_eq!(blob.len(), 3 + 129);
    }

    // Cross-platform test vector: MUST match TypeScript vault-blob-vectors.test.ts
    #[test]
    fn test_cross_platform_vector() {
        let mut key = vec![0xAA];
        for i in 0u8..128 {
            key.push(i);
        }
        assert_eq!(key.len(), 129);

        let blob = serialize_vault_blob_v2(&key).unwrap();

        assert_eq!(blob[0], 0x02);
        assert_eq!(blob[1], 0x00);
        assert_eq!(blob[2], 0x81); // 129
        assert_eq!(blob.len(), 3 + 129);

        let blob_hex = hex::encode(&blob);
        let expected_hex = concat!(
            "02",                               // version byte
            "0081",                             // key_len = 129
            "aa",                               // key[0]
            "000102030405060708090a0b0c0d0e0f", // key[1..16]
            "101112131415161718191a1b1c1d1e1f", // key[17..32]
            "202122232425262728292a2b2c2d2e2f", // key[33..48]
            "303132333435363738393a3b3c3d3e3f", // key[49..64]
            "404142434445464748494a4b4c4d4e4f", // key[65..80]
            "505152535455565758595a5b5c5d5e5f", // key[81..96]
            "606162636465666768696a6b6c6d6e6f", // key[97..112]
            "707172737475767778797a7b7c7d7e7f", // key[113..128]
        );
        assert_eq!(blob_hex, expected_hex);

        let dk = deserialize_vault_blob_v2(&blob).unwrap();
        assert_eq!(dk, key.as_slice());
    }

    #[test]
    fn test_cross_platform_minimal_vector() {
        let key = vec![0xFF];
        let blob = serialize_vault_blob_v2(&key).unwrap();
        let expected_hex = "020001ff";
        assert_eq!(hex::encode(&blob), expected_hex);

        let dk = deserialize_vault_blob_v2(&blob).unwrap();
        assert_eq!(dk, &[0xFF]);
    }

    #[test]
    fn test_key_too_long_for_u16() {
        let key = vec![0xAA; 65536];
        let result = serialize_vault_blob_v2(&key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_zero_length_key_rejected() {
        let result = serialize_vault_blob_v2(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must not be empty"));

        let blob = vec![0x02, 0x00, 0x00];
        assert!(deserialize_vault_blob_v2(&blob).is_err());
    }

    #[test]
    fn test_detect_empty_blob_defaults_to_v1() {
        assert_eq!(detect_blob_version(&[]), 1);
    }

    #[test]
    fn test_large_key_round_trip() {
        // Just under the u16 max
        let key = vec![0x42; 65535];
        let blob = serialize_vault_blob_v2(&key).unwrap();
        let decoded = deserialize_vault_blob_v2(&blob).unwrap();
        assert_eq!(decoded.len(), 65535);
        assert_eq!(decoded, key.as_slice());
    }

    // -- v3 codec tests ----------------------------------------------------

    /// Cross-language KAT: loads the FROZEN vector tests/vectors/vault-v3-blob.json
    /// at runtime (mirroring crates/core/tests/node_codec_vectors.rs) and asserts
    /// serialize output is byte-identical to expected_blob_hex + a full round-trip.
    /// The vector — not a hardcoded copy — drives the gate, so a future layout
    /// drift on either the Rust or TS side fails here (T-69-21-01, D-04).
    #[test]
    fn test_cross_platform_v3_vector() {
        use std::path::PathBuf;

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/vectors/vault-v3-blob.json");
        let data = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
        let vector: serde_json::Value = serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));

        let read_key_hex = vector["read_key_hex"].as_str().expect("read_key_hex");
        let write_key_hex = vector["write_key_hex"].as_str().expect("write_key_hex");
        let expected_blob_hex = vector["expected_blob_hex"]
            .as_str()
            .expect("expected_blob_hex");

        let read_key = hex::decode(read_key_hex).expect("decode read_key_hex");
        let write_key = hex::decode(write_key_hex).expect("decode write_key_hex");
        assert_eq!(read_key.len(), 129);
        assert_eq!(write_key.len(), 129);

        // serialize == expected_blob_hex, byte-for-byte
        let blob = serialize_vault_blob_v3(&read_key, &write_key).unwrap();
        assert_eq!(hex::encode(&blob), expected_blob_hex);

        // round-trip: deserialize back to the two input keys (OWNED copies)
        let (r, w) = deserialize_vault_blob_v3(&blob).unwrap();
        assert_eq!(r, read_key);
        assert_eq!(w, write_key);
    }

    #[test]
    fn test_v3_serialize_rejects_empty_read() {
        let err = serialize_vault_blob_v3(&[], &[0xBB]).unwrap_err();
        assert!(err.contains("read key must not be empty"));
    }

    #[test]
    fn test_v3_serialize_rejects_empty_write() {
        let err = serialize_vault_blob_v3(&[0xAA], &[]).unwrap_err();
        assert!(err.contains("write key must not be empty"));
    }

    #[test]
    fn test_v3_serialize_rejects_read_too_long() {
        let read = vec![0xAA; 65536];
        let err = serialize_vault_blob_v3(&read, &[0xBB]).unwrap_err();
        assert!(err.contains("read key too long"));
    }

    #[test]
    fn test_v3_serialize_rejects_write_too_long() {
        let write = vec![0xBB; 65536];
        let err = serialize_vault_blob_v3(&[0xAA], &write).unwrap_err();
        assert!(err.contains("write key too long"));
    }

    #[test]
    fn test_v3_deserialize_rejects_short_blob() {
        // 4 bytes < 5-byte minimum header
        assert!(deserialize_vault_blob_v3(&[0x03, 0x00, 0x01, 0xAA]).is_err());
        assert!(deserialize_vault_blob_v3(&[]).is_err());
    }

    #[test]
    fn test_v3_deserialize_rejects_wrong_version() {
        // Well-formed length fields but a v2 version byte, and a JSON ('{') byte.
        let blob = vec![0x02, 0x00, 0x01, 0xAA, 0x00, 0x01, 0xBB];
        assert!(deserialize_vault_blob_v3(&blob).is_err());
        let blob = vec![0x7B, 0x00, 0x01, 0xAA, 0x00, 0x01, 0xBB];
        assert!(deserialize_vault_blob_v3(&blob).is_err());
    }

    #[test]
    fn test_v3_deserialize_rejects_zero_read_length() {
        let blob = vec![0x03, 0x00, 0x00, 0x00, 0x01, 0xBB];
        let err = deserialize_vault_blob_v3(&blob).unwrap_err();
        assert!(err.contains("read key length must be > 0"));
    }

    #[test]
    fn test_v3_deserialize_rejects_zero_write_length() {
        // read_len=1 present, write header declares 0
        let blob = vec![0x03, 0x00, 0x01, 0xAA, 0x00, 0x00];
        let err = deserialize_vault_blob_v3(&blob).unwrap_err();
        assert!(err.contains("write key length must be > 0"));
    }

    #[test]
    fn test_v3_deserialize_rejects_truncated_write_header() {
        // Header promises read_len=5 but only ~2 bytes follow, so the write
        // key header would run off the end.
        let blob = vec![0x03, 0x00, 0x05, 0xAA, 0xBB];
        let err = deserialize_vault_blob_v3(&blob).unwrap_err();
        assert!(err.contains("missing write key header"));
    }

    #[test]
    fn test_v3_deserialize_rejects_truncated_write_body() {
        // read_len=1, write_len declared 4 but only 1 byte present
        let blob = vec![0x03, 0x00, 0x01, 0xAA, 0x00, 0x04, 0xBB];
        let err = deserialize_vault_blob_v3(&blob).unwrap_err();
        assert!(err.contains("truncated (write key)"));
    }

    #[test]
    fn test_v3_minimal_round_trip() {
        let blob = serialize_vault_blob_v3(&[0xAA], &[0xBB]).unwrap();
        assert_eq!(hex::encode(&blob), "030001aa0001bb");
        let (r, w) = deserialize_vault_blob_v3(&blob).unwrap();
        assert_eq!(r, vec![0xAA]);
        assert_eq!(w, vec![0xBB]);
    }

    #[test]
    fn test_v3_near_u16_round_trip() {
        let read = vec![0x11; 65535];
        let write = vec![0x22; 65535];
        let blob = serialize_vault_blob_v3(&read, &write).unwrap();
        assert_eq!(blob.len(), 1 + 2 + 65535 + 2 + 65535);
        let (r, w) = deserialize_vault_blob_v3(&blob).unwrap();
        assert_eq!(r, read);
        assert_eq!(w, write);
    }

    #[test]
    fn test_v3_deserialize_returns_owned_copies() {
        // Mutating the source blob after deserialize must NOT affect the
        // returned keys (owned copies, D-09).
        let mut blob = serialize_vault_blob_v3(&[0xAA], &[0xBB]).unwrap();
        let (r, w) = deserialize_vault_blob_v3(&blob).unwrap();
        for b in blob.iter_mut() {
            *b = 0;
        }
        assert_eq!(r, vec![0xAA]);
        assert_eq!(w, vec![0xBB]);
    }
}
