//! Cross-language parity tests for cipherbox-crypto.
//!
//! Loads shared test vectors from tests/vectors/crypto/*.json
//! and verifies Rust produces identical output to TypeScript.
//! Both Rust and TypeScript test suites load the same vector files,
//! ensuring byte-level parity across implementations.

use serde::Deserialize;
use std::path::PathBuf;

/// Resolve path to shared test vectors directory relative to workspace root.
fn vectors_path(subpath: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/vectors");
    p.push(subpath);
    p
}

/// Load and deserialize a JSON test vector file.
fn load_vectors<T: serde::de::DeserializeOwned>(filename: &str) -> Vec<T> {
    let path = vectors_path(filename);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    serde_json::from_str(&data).unwrap()
}

// ============================================================
// AES-256-GCM Cross-Language Vectors
// ============================================================

#[derive(Deserialize)]
struct AesGcmVector {
    #[allow(dead_code)]
    description: String,
    key: String,
    iv: String,
    plaintext: String,
    ciphertext: String,
}

#[test]
fn aes_gcm_cross_language() {
    let vectors: Vec<AesGcmVector> = load_vectors("crypto/aes-gcm.json");
    assert!(!vectors.is_empty(), "No AES-GCM vectors loaded");

    for v in &vectors {
        let key = hex::decode(&v.key).unwrap();
        let iv = hex::decode(&v.iv).unwrap();
        let plaintext = hex::decode(&v.plaintext).unwrap();
        let expected = hex::decode(&v.ciphertext).unwrap();

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let iv_arr: [u8; 12] = iv.try_into().unwrap();

        // Encrypt and verify
        let encrypted = cipherbox_crypto::encrypt_aes_gcm(&plaintext, &key_arr, &iv_arr).unwrap();
        assert_eq!(
            hex::encode(&encrypted),
            v.ciphertext,
            "AES-GCM encrypt mismatch for: {}",
            v.description
        );

        // Decrypt and verify
        let decrypted = cipherbox_crypto::decrypt_aes_gcm(&expected, &key_arr, &iv_arr).unwrap();
        assert_eq!(
            hex::encode(&decrypted),
            v.plaintext,
            "AES-GCM decrypt mismatch for: {}",
            v.description
        );
    }
}

// ============================================================
// Ed25519 Cross-Language Vectors
// ============================================================

#[derive(Deserialize)]
struct Ed25519Vector {
    #[allow(dead_code)]
    description: String,
    private_key: String,
    public_key: String,
    message: String,
    signature: String,
}

#[test]
fn ed25519_cross_language() {
    let vectors: Vec<Ed25519Vector> = load_vectors("crypto/ed25519.json");
    assert!(!vectors.is_empty(), "No Ed25519 vectors loaded");

    for v in &vectors {
        let private_key = hex::decode(&v.private_key).unwrap();
        let expected_public = hex::decode(&v.public_key).unwrap();
        let message = hex::decode(&v.message).unwrap();

        // Verify public key derivation
        let public_key = cipherbox_crypto::get_public_key(&private_key).unwrap();
        assert_eq!(
            hex::encode(&public_key),
            v.public_key,
            "Ed25519 public key mismatch for: {}",
            v.description
        );

        // Verify deterministic signature
        let signature = cipherbox_crypto::sign_ed25519(&message, &private_key).unwrap();
        assert_eq!(
            hex::encode(&signature),
            v.signature,
            "Ed25519 signature mismatch for: {}",
            v.description
        );

        // Verify signature
        let sig_bytes = hex::decode(&v.signature).unwrap();
        assert!(
            cipherbox_crypto::verify_ed25519(&message, &sig_bytes, &expected_public),
            "Ed25519 signature verification failed for: {}",
            v.description
        );
    }
}

// ============================================================
// ECIES Cross-Language Vectors
// ============================================================

#[derive(Deserialize)]
struct EciesVector {
    #[allow(dead_code)]
    description: String,
    private_key: String,
    public_key: String,
    plaintext: String,
    /// TypeScript-wrapped ciphertext for Rust to unwrap.
    /// ECIES is non-deterministic (ephemeral key), so we test
    /// unwrap of known ciphertext + round-trip, not exact output match.
    wrapped: String,
}

#[test]
fn ecies_cross_language() {
    let vectors: Vec<EciesVector> = load_vectors("crypto/ecies.json");
    assert!(!vectors.is_empty(), "No ECIES vectors loaded");

    for v in &vectors {
        let private_key = hex::decode(&v.private_key).unwrap();
        let public_key = hex::decode(&v.public_key).unwrap();
        let plaintext = hex::decode(&v.plaintext).unwrap();
        let wrapped = hex::decode(&v.wrapped).unwrap();

        // Unwrap TypeScript-wrapped ciphertext
        let unwrapped = cipherbox_crypto::unwrap_key(&wrapped, &private_key).unwrap();
        assert_eq!(
            hex::encode(&unwrapped),
            v.plaintext,
            "ECIES unwrap mismatch for: {}",
            v.description
        );

        // Round-trip: wrap with public key, unwrap with private key
        let re_wrapped = cipherbox_crypto::wrap_key(&plaintext, &public_key).unwrap();
        let re_unwrapped = cipherbox_crypto::unwrap_key(&re_wrapped, &private_key).unwrap();
        assert_eq!(
            re_unwrapped, plaintext,
            "ECIES round-trip failed for: {}",
            v.description
        );
    }
}

// ============================================================
// HKDF Derivation Cross-Language Vectors
// ============================================================

#[derive(Deserialize)]
struct HkdfVector {
    #[allow(dead_code)]
    description: String,
    private_key: String,
    info: String,
    expected_ed25519_private_key: String,
    expected_ed25519_public_key: String,
    expected_ipns_name: String,
}

#[test]
fn hkdf_cross_language() {
    let vectors: Vec<HkdfVector> = load_vectors("crypto/hkdf.json");
    assert!(!vectors.is_empty(), "No HKDF vectors loaded");

    for v in &vectors {
        let private_key_bytes = hex::decode(&v.private_key).unwrap();
        let pk: [u8; 32] = private_key_bytes.try_into().unwrap();

        // Route to the correct derivation function based on info string
        let (derived_priv, derived_pub, ipns_name) = match v.info.as_str() {
            "cipherbox-vault-ipns-v1" => {
                cipherbox_crypto::derive_vault_ipns_keypair(&pk).unwrap()
            }
            "cipherbox-vault-key-ipns-v1" => {
                cipherbox_crypto::derive_vault_key_ipns_keypair(&pk).unwrap()
            }
            "cipherbox-device-registry-ipns-v1" => {
                cipherbox_crypto::derive_registry_ipns_keypair(&pk).unwrap()
            }
            "cipherbox-recycle-bin-ipns-v1" => {
                cipherbox_crypto::derive_bin_ipns_keypair(&pk).unwrap()
            }
            info if info.starts_with("cipherbox-file-ipns-v1:") => {
                let file_id = &info["cipherbox-file-ipns-v1:".len()..];
                cipherbox_crypto::derive_file_ipns_keypair(&pk, file_id).unwrap()
            }
            other => panic!("Unknown HKDF info string: {}", other),
        };

        assert_eq!(
            hex::encode(derived_priv.as_slice()),
            v.expected_ed25519_private_key,
            "HKDF private key mismatch for: {}",
            v.description
        );
        assert_eq!(
            hex::encode(&derived_pub),
            v.expected_ed25519_public_key,
            "HKDF public key mismatch for: {}",
            v.description
        );
        assert_eq!(
            ipns_name, v.expected_ipns_name,
            "HKDF IPNS name mismatch for: {}",
            v.description
        );
    }
}

// ============================================================
// IPNS Name Derivation Cross-Language Vectors
// ============================================================

#[derive(Deserialize)]
struct IpnsNameVector {
    #[allow(dead_code)]
    description: String,
    public_key: String,
    expected_name: String,
}

#[test]
fn ipns_name_cross_language() {
    let vectors: Vec<IpnsNameVector> = load_vectors("crypto/ipns-name.json");
    assert!(!vectors.is_empty(), "No IPNS name vectors loaded");

    for v in &vectors {
        let public_key = hex::decode(&v.public_key).unwrap();
        let pk: [u8; 32] = public_key.try_into().unwrap();

        let name = cipherbox_crypto::derive_ipns_name(&pk).unwrap();
        assert_eq!(
            name, v.expected_name,
            "IPNS name mismatch for: {}",
            v.description
        );
    }
}
