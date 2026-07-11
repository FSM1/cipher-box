//! AES-256-GCM encryption/decryption.
//!
//! Sealed format: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
//! This matches the TypeScript `sealAesGcm` output exactly.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use uuid::Uuid;

use crate::error::CryptoError;
use crate::utils::generate_iv;

/// Frozen domain separator for node AAD (D-00, mirrors hkdf.rs precedent).
const NODE_SEAL_DOMAIN: &[u8] = b"cipherbox/node-seal/v1";

/// AES-256-GCM key size in bytes (256 bits).
pub const AES_KEY_SIZE: usize = 32;

/// AES-GCM IV size in bytes (96 bits).
pub const AES_IV_SIZE: usize = 12;

/// AES-GCM authentication tag size in bytes (128 bits).
pub const AES_TAG_SIZE: usize = 16;

/// Minimum sealed data size: IV + auth tag (empty plaintext).
const MIN_SEALED_SIZE: usize = AES_IV_SIZE + AES_TAG_SIZE;

/// Encrypt data using AES-256-GCM.
///
/// Returns ciphertext with 16-byte auth tag appended (same as Web Crypto API).
pub fn encrypt_aes_gcm(
    plaintext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AesEncryptionFailed)?;
    let nonce = Nonce::from_slice(iv);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::AesEncryptionFailed)
}

/// Decrypt data using AES-256-GCM.
///
/// Expects ciphertext with 16-byte auth tag appended.
pub fn decrypt_aes_gcm(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AesDecryptionFailed)?;
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::AesDecryptionFailed)
}

/// Seal data using AES-256-GCM with automatic IV generation.
///
/// Returns: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
/// This format matches the TypeScript `sealAesGcm` exactly.
pub fn seal_aes_gcm(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let iv = generate_iv();
    let ciphertext = encrypt_aes_gcm(plaintext, key, &iv)?;

    // IV || ciphertext (which already includes the tag)
    let mut sealed = Vec::with_capacity(AES_IV_SIZE + ciphertext.len());
    sealed.extend_from_slice(&iv);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Unseal data encrypted with `seal_aes_gcm`.
///
/// Extracts IV from first 12 bytes, decrypts remainder.
pub fn unseal_aes_gcm(sealed: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < MIN_SEALED_SIZE {
        return Err(CryptoError::AesDecryptionFailed);
    }

    let iv: [u8; 12] = sealed[..AES_IV_SIZE]
        .try_into()
        .map_err(|_| CryptoError::AesDecryptionFailed)?;
    let ciphertext = &sealed[AES_IV_SIZE..];

    decrypt_aes_gcm(ciphertext, key, &iv)
}

/// Encrypt data using AES-256-GCM with Additional Authenticated Data (AAD).
///
/// Returns ciphertext with 16-byte auth tag appended.
pub fn encrypt_aes_gcm_aad(
    plaintext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AesEncryptionFailed)?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::AesEncryptionFailed)
}

/// Decrypt data using AES-256-GCM with Additional Authenticated Data (AAD).
///
/// Expects ciphertext with 16-byte auth tag appended.
pub fn decrypt_aes_gcm_aad(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AesDecryptionFailed)?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::AesDecryptionFailed)
}

/// Seal data using AES-256-GCM with AAD and automatic IV generation.
///
/// Returns: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
pub fn seal_aes_gcm_aad(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let iv = generate_iv();
    let ciphertext = encrypt_aes_gcm_aad(plaintext, key, &iv, aad)?;
    let mut sealed = Vec::with_capacity(AES_IV_SIZE + ciphertext.len());
    sealed.extend_from_slice(&iv);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Unseal data encrypted with `seal_aes_gcm_aad`.
///
/// Extracts IV from first 12 bytes, decrypts remainder using the provided AAD.
pub fn unseal_aes_gcm_aad(sealed: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < MIN_SEALED_SIZE {
        return Err(CryptoError::AesDecryptionFailed);
    }
    let iv: [u8; 12] = sealed[..AES_IV_SIZE]
        .try_into()
        .map_err(|_| CryptoError::AesDecryptionFailed)?;
    let ciphertext = &sealed[AES_IV_SIZE..];
    decrypt_aes_gcm_aad(ciphertext, key, &iv, aad)
}

/// Returns true iff `s` is exactly the canonical 8-4-4-4-12 hyphenated UUID shape
/// (hex digits case-insensitive, hyphens only at byte indices 8, 13, 18, 23).
/// Dependency-free byte-position check — does NOT delegate to `Uuid::parse_str`,
/// which also accepts simple-32-hex, braced `{...}`, and `urn:uuid:...` forms.
/// Applied BEFORE `Uuid::parse_str` in `build_node_aad` to narrow the acceptance
/// domain to canonical-only (SC3, Option A), matching TS `uuidToBytes`.
fn is_canonical_uuid_form(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        let is_hyphen_pos = matches!(i, 8 | 13 | 18 | 23);
        if is_hyphen_pos {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Build the canonical 45-byte AAD for a node seal operation.
///
/// Encoding (D-00, frozen — never re-litigated):
///   "cipherbox/node-seal/v1" (22B UTF-8) ‖ 0x00 ‖ nodeId (16B raw UUID RFC-4122) ‖ kind (1B) ‖ generation (4B BE u32) ‖ role (1B)
///
/// Fail-closed (D-03): returns `Err(CryptoError::InvalidAadInput)` for:
/// - malformed / non-16-byte UUID
/// - non-canonical UUID form (simple-32-hex, braced, urn:uuid:, loose-hyphen — SC3, Option A)
/// - kind ∉ {0x01, 0x02, 0x03}
/// - role ∉ {0x01, 0x02, 0x03, 0x04}
pub fn build_node_aad(
    node_id: &str,
    kind: u8,
    generation: u32,
    role: u8,
) -> Result<Vec<u8>, CryptoError> {
    if !matches!(kind, 0x01..=0x03) {
        return Err(CryptoError::InvalidAadInput);
    }
    if !matches!(role, 0x01..=0x04) {
        return Err(CryptoError::InvalidAadInput);
    }
    if !is_canonical_uuid_form(node_id) {
        return Err(CryptoError::InvalidAadInput);
    }
    let uuid = Uuid::parse_str(node_id).map_err(|_| CryptoError::InvalidAadInput)?;
    let id_bytes = uuid.as_bytes(); // &[u8; 16] RFC-4122 field order (D-04)
    let mut aad = Vec::with_capacity(NODE_SEAL_DOMAIN.len() + 1 + 16 + 1 + 4 + 1);
    aad.extend_from_slice(NODE_SEAL_DOMAIN);
    aad.push(0x00);
    aad.extend_from_slice(id_bytes);
    aad.push(kind);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.push(role);
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [0xABu8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"hello cipherbox";

        let ciphertext = encrypt_aes_gcm(plaintext, &key, &iv).unwrap();
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn seal_unseal_round_trip() {
        let key = [0x42u8; 32];
        let plaintext = b"sealed round trip data";

        let sealed = seal_aes_gcm(plaintext, &key).unwrap();
        assert!(sealed.len() >= AES_IV_SIZE + AES_TAG_SIZE + plaintext.len());

        let decrypted = unseal_aes_gcm(&sealed, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = [0xAAu8; 32];
        let wrong_key = [0xBBu8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"secret";

        let ciphertext = encrypt_aes_gcm(plaintext, &key, &iv).unwrap();
        let result = decrypt_aes_gcm(&ciphertext, &wrong_key, &iv);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_corrupted_ciphertext_fails() {
        let key = [0xAAu8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"secret";

        let mut ciphertext = encrypt_aes_gcm(plaintext, &key, &iv).unwrap();
        ciphertext[0] ^= 0xFF;

        let result = decrypt_aes_gcm(&ciphertext, &key, &iv);
        assert!(result.is_err());
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let key = [0xCCu8; 32];
        let iv = [0x02u8; 12];
        let plaintext = b"";

        let ciphertext = encrypt_aes_gcm(plaintext, &key, &iv).unwrap();
        assert_eq!(ciphertext.len(), AES_TAG_SIZE);

        let decrypted = decrypt_aes_gcm(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn unseal_too_short_data_fails() {
        let key = [0xAAu8; 32];
        let short = vec![0u8; AES_IV_SIZE + AES_TAG_SIZE - 1];
        assert!(unseal_aes_gcm(&short, &key).is_err());
    }

    #[test]
    fn unseal_with_wrong_key_fails() {
        let key = [0xAAu8; 32];
        let wrong_key = [0xBBu8; 32];
        let sealed = seal_aes_gcm(b"data", &key).unwrap();
        assert!(unseal_aes_gcm(&sealed, &wrong_key).is_err());
    }

    // ── build_node_aad tests ─────────────────────────────────────────────────

    #[test]
    fn build_node_aad_canonical_layout() {
        // Canonical input: kind=folder(0x01), generation=42, role=body(0x01)
        let aad = build_node_aad(
            "550e8400-e29b-41d4-a716-446655440000",
            0x01,
            42,
            0x01,
        )
        .unwrap();
        assert_eq!(aad.len(), 45, "AAD must be exactly 45 bytes");

        // Bytes 0..22: domain "cipherbox/node-seal/v1"
        assert_eq!(&aad[..22], b"cipherbox/node-seal/v1");
        // Byte 22: null separator
        assert_eq!(aad[22], 0x00);
        // Bytes 23..39: raw UUID bytes RFC-4122 field order
        assert_eq!(
            &aad[23..39],
            &[0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
              0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00]
        );
        // Byte 39: kind
        assert_eq!(aad[39], 0x01);
        // Bytes 40..44: generation 42 big-endian
        assert_eq!(&aad[40..44], &[0x00, 0x00, 0x00, 0x2a]);
        // Byte 44: role
        assert_eq!(aad[44], 0x01);
    }

    #[test]
    fn build_node_aad_generation_zero() {
        let aad = build_node_aad(
            "550e8400-e29b-41d4-a716-446655440000",
            0x01,
            0,
            0x01,
        )
        .unwrap();
        assert_eq!(&aad[40..44], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn build_node_aad_generation_max() {
        let aad = build_node_aad(
            "550e8400-e29b-41d4-a716-446655440000",
            0x01,
            u32::MAX,
            0x01,
        )
        .unwrap();
        assert_eq!(&aad[40..44], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn build_node_aad_invalid_kind_returns_err() {
        // kind 0x04 is out of range (only 0x01..=0x03)
        assert!(matches!(
            build_node_aad("550e8400-e29b-41d4-a716-446655440000", 0x04, 0, 0x01),
            Err(CryptoError::InvalidAadInput)
        ));
        // kind 0x00 also invalid
        assert!(matches!(
            build_node_aad("550e8400-e29b-41d4-a716-446655440000", 0x00, 0, 0x01),
            Err(CryptoError::InvalidAadInput)
        ));
    }

    #[test]
    fn build_node_aad_invalid_role_returns_err() {
        // role 0x05 is out of range (only 0x01..=0x04)
        assert!(matches!(
            build_node_aad("550e8400-e29b-41d4-a716-446655440000", 0x01, 0, 0x05),
            Err(CryptoError::InvalidAadInput)
        ));
        // role 0x00 also invalid
        assert!(matches!(
            build_node_aad("550e8400-e29b-41d4-a716-446655440000", 0x01, 0, 0x00),
            Err(CryptoError::InvalidAadInput)
        ));
    }

    #[test]
    fn build_node_aad_malformed_uuid_returns_err() {
        assert!(matches!(
            build_node_aad("not-a-uuid", 0x01, 0, 0x01),
            Err(CryptoError::InvalidAadInput)
        ));
        assert!(matches!(
            build_node_aad("", 0x01, 0, 0x01),
            Err(CryptoError::InvalidAadInput)
        ));
        assert!(matches!(
            build_node_aad("550e8400-e29b-41d4-a716", 0x01, 0, 0x01),
            Err(CryptoError::InvalidAadInput)
        ));
    }

    // ── encrypt/decrypt_aes_gcm_aad tests ───────────────────────────────────

    #[test]
    fn encrypt_decrypt_aad_round_trip() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 12];
        let plaintext = b"aad round trip test";
        let aad = b"node-seal-context";

        let ciphertext = encrypt_aes_gcm_aad(plaintext, &key, &iv, aad).unwrap();
        let decrypted = decrypt_aes_gcm_aad(&ciphertext, &key, &iv, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_aad_wrong_aad_fails() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 12];
        let plaintext = b"secret payload";
        let aad = b"correct-aad";
        let wrong_aad = b"wrong-aad";

        let ciphertext = encrypt_aes_gcm_aad(plaintext, &key, &iv, aad).unwrap();
        let result = decrypt_aes_gcm_aad(&ciphertext, &key, &iv, wrong_aad);
        assert!(result.is_err(), "Expected Err when decrypting with wrong AAD");
    }

    // ── seal/unseal_aes_gcm_aad tests ────────────────────────────────────────

    #[test]
    fn seal_unseal_aad_round_trip() {
        let key = [0x33u8; 32];
        let aad = b"cipherbox-node-aad";
        let plaintext = b"sealed aad round trip";

        let sealed = seal_aes_gcm_aad(plaintext, &key, aad).unwrap();
        // Output length: IV (12) + plaintext.len() + tag (16)
        assert_eq!(
            sealed.len(),
            AES_IV_SIZE + plaintext.len() + AES_TAG_SIZE,
            "sealed length must be IV + plaintext + tag"
        );

        let decrypted = unseal_aes_gcm_aad(&sealed, &key, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn seal_aad_two_calls_differ() {
        // Fresh IV each call — identical inputs must produce different blobs.
        let key = [0x44u8; 32];
        let aad = b"same-aad";
        let plaintext = b"same plaintext";

        let sealed1 = seal_aes_gcm_aad(plaintext, &key, aad).unwrap();
        let sealed2 = seal_aes_gcm_aad(plaintext, &key, aad).unwrap();
        assert_ne!(sealed1, sealed2, "Two seals of the same input must differ (fresh IV)");
    }

    #[test]
    fn unseal_aad_transplant_fails() {
        // A blob sealed under aad_a must be rejected when unseal is given aad_b (CRYPTO-03).
        let key = [0x55u8; 32];
        let aad_a = b"original-aad";
        let aad_b = b"transplanted-aad";
        let plaintext = b"transplant test";

        let sealed = seal_aes_gcm_aad(plaintext, &key, aad_a).unwrap();
        let result = unseal_aes_gcm_aad(&sealed, &key, aad_b);
        assert!(result.is_err(), "Expected Err when unsealing with wrong AAD (transplant)");
    }

    #[test]
    fn unseal_aad_truncated_blob_fails() {
        // A blob shorter than MIN_SEALED_SIZE must be rejected before decryption (CRYPTO-03).
        let key = [0x66u8; 32];
        let aad = b"any-aad";
        let short = vec![0u8; AES_IV_SIZE + AES_TAG_SIZE - 1];
        assert!(
            unseal_aes_gcm_aad(&short, &key, aad).is_err(),
            "Expected Err for truncated blob below MIN_SEALED_SIZE"
        );
    }

    #[test]
    fn build_node_aad_matches_committed_vectors() {
        // Verify all four role bytes against the committed node-aad.json expected_aad values.
        let node_id = "550e8400-e29b-41d4-a716-446655440000";
        let cases: &[(&str, u8, u32, u8, &str)] = &[
            (
                "role=body(0x01)",
                1, 42, 1,
                "636970686572626f782f6e6f64652d7365616c2f763100550e8400e29b41d4a716446655440000010000002a01",
            ),
            (
                "role=child-readkey(0x02)",
                1, 42, 2,
                "636970686572626f782f6e6f64652d7365616c2f763100550e8400e29b41d4a716446655440000010000002a02",
            ),
            (
                "role=content(0x03)",
                1, 42, 3,
                "636970686572626f782f6e6f64652d7365616c2f763100550e8400e29b41d4a716446655440000010000002a03",
            ),
            (
                "role=child-writekey(0x04)",
                1, 42, 4,
                "636970686572626f782f6e6f64652d7365616c2f763100550e8400e29b41d4a716446655440000010000002a04",
            ),
        ];
        for (desc, kind, gen, role, expected_hex) in cases {
            let aad = build_node_aad(node_id, *kind, *gen, *role).unwrap();
            assert_eq!(
                hex::encode(&aad),
                *expected_hex,
                "AAD mismatch for: {}",
                desc
            );
        }
    }
}
