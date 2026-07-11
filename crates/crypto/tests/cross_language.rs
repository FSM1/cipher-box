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
            hex::encode(unwrapped.as_slice()),
            v.plaintext,
            "ECIES unwrap mismatch for: {}",
            v.description
        );

        // Round-trip: wrap with public key, unwrap with private key
        let re_wrapped = cipherbox_crypto::wrap_key(&plaintext, &public_key).unwrap();
        let re_unwrapped = cipherbox_crypto::unwrap_key(&re_wrapped, &private_key).unwrap();
        assert_eq!(
            re_unwrapped.as_slice(),
            plaintext.as_slice(),
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
            "cipherbox-vault-ipns-v1" => cipherbox_crypto::derive_vault_ipns_keypair(&pk).unwrap(),
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
            "cipherbox-vault-settings-v1" => {
                cipherbox_crypto::derive_vault_settings_ipns_keypair(&pk).unwrap()
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
// Node AAD Cross-Language Vectors
// ============================================================

#[derive(Deserialize)]
struct NodeAadVector {
    #[allow(dead_code)]
    description: String,
    node_id: String,
    kind: u8,
    generation: u32,
    role: u8,
    expected_aad: String,
}

/// Full-seal KAT vector: fixed key/iv/plaintext/aad committed by the TS side.
/// Rust must reproduce the exact ciphertext byte-for-byte (T-61-11).
#[derive(Deserialize)]
struct NodeSealVector {
    description: String,
    node_id: String,
    kind: u8,
    generation: u32,
    role: u8,
    key: String,
    iv: String,
    plaintext: String,
    ciphertext: String,
}

#[test]
fn node_aad_cross_language() {
    // node-aad.json is a top-level object (not a flat array), so parse via
    // serde_json::Value and pull the aad_vectors array — not load_vectors().
    let path = vectors_path("crypto/node-aad.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    let root: serde_json::Value = serde_json::from_str(&data).unwrap();

    // ── aad_vectors: pin AAD construction byte-for-byte ──────────────────────
    let aad_vectors: Vec<NodeAadVector> =
        serde_json::from_value(root["aad_vectors"].clone()).unwrap();

    // Guard: exactly 4 entries covering all role bytes 0x01..0x04.
    // Mirrors the TS length guard so coverage cannot silently erode.
    assert_eq!(aad_vectors.len(), 4, "Expected exactly 4 aad_vectors (one per role byte)");
    let mut roles: Vec<u8> = aad_vectors.iter().map(|v| v.role).collect();
    roles.sort_unstable();
    assert_eq!(roles, vec![1, 2, 3, 4], "aad_vectors must cover role bytes 0x01..0x04 exactly once");

    for v in &aad_vectors {
        let aad = cipherbox_crypto::build_node_aad(&v.node_id, v.kind, v.generation, v.role)
            .unwrap_or_else(|e| panic!("build_node_aad failed for {}: {:?}", v.description, e));
        assert_eq!(
            hex::encode(&aad),
            v.expected_aad,
            "AAD mismatch for: {}",
            v.description
        );
    }

    // ── seal_vectors: pin the full AEAD-with-AAD path TS↔Rust ───────────────
    // encrypt_aes_gcm_aad must reproduce the exact ciphertext the TS side committed
    // for the same fixed key/iv/plaintext/AAD (proves Web Crypto additionalData ≡
    // aes-gcm Payload { msg, aad } byte-for-byte; T-61-11, CRYPTO-02, TEST-02).
    let seal_vectors: Vec<NodeSealVector> =
        serde_json::from_value(root["seal_vectors"].clone()).unwrap();

    assert_eq!(seal_vectors.len(), 1, "Expected exactly 1 committed seal_vector");

    for v in &seal_vectors {
        let key_bytes = hex::decode(&v.key)
            .unwrap_or_else(|_| panic!("Bad hex key in: {}", v.description));
        let iv_bytes = hex::decode(&v.iv)
            .unwrap_or_else(|_| panic!("Bad hex iv in: {}", v.description));
        let plaintext = hex::decode(&v.plaintext)
            .unwrap_or_else(|_| panic!("Bad hex plaintext in: {}", v.description));

        let key_arr: [u8; 32] = key_bytes
            .try_into()
            .unwrap_or_else(|_| panic!("Key must be 32 bytes in: {}", v.description));
        let iv_arr: [u8; 12] = iv_bytes
            .try_into()
            .unwrap_or_else(|_| panic!("IV must be 12 bytes in: {}", v.description));

        let aad = cipherbox_crypto::build_node_aad(&v.node_id, v.kind, v.generation, v.role)
            .unwrap_or_else(|e| panic!("build_node_aad failed for {}: {:?}", v.description, e));

        let ciphertext = cipherbox_crypto::encrypt_aes_gcm_aad(&plaintext, &key_arr, &iv_arr, &aad)
            .unwrap_or_else(|e| panic!("encrypt_aes_gcm_aad failed for {}: {:?}", v.description, e));

        assert_eq!(
            hex::encode(&ciphertext),
            v.ciphertext,
            "Full-seal KAT ciphertext mismatch for: {}",
            v.description
        );

        // Pin the frozen sealed-blob envelope order [IV(12)][ct+tag] (D-00a). The ciphertext
        // assertion above only pins the AEAD output; this asserts the high-level seal envelope
        // is IV-FIRST and identical to the TS side: a seal/unseal pair that silently switched to
        // `ct||iv` would pass round-trip + ciphertext checks but fail to open this IV-first blob.
        let mut sealed_envelope = iv_arr.to_vec();
        sealed_envelope.extend_from_slice(&ciphertext);
        let opened = cipherbox_crypto::unseal_aes_gcm_aad(&sealed_envelope, &key_arr, &aad)
            .unwrap_or_else(|e| panic!("unseal_aes_gcm_aad failed for {}: {:?}", v.description, e));
        assert_eq!(
            hex::encode(&opened),
            v.plaintext,
            "Sealed-envelope [IV][ct+tag] order mismatch for: {}",
            v.description
        );
    }
}

// ============================================================
// UUID Acceptance-Domain Cross-Language Oracle (SC3)
// ============================================================

#[derive(Deserialize)]
struct UuidAcceptanceFixedParams {
    kind: u8,
    generation: u32,
    role: u8,
}

#[derive(Deserialize)]
struct UuidAcceptanceCase {
    description: String,
    node_id: String,
    expected: String,
}

#[derive(Deserialize)]
struct UuidAcceptanceOracle {
    #[allow(dead_code)]
    description: String,
    fixed_params: UuidAcceptanceFixedParams,
    cases: Vec<UuidAcceptanceCase>,
}

/// Drives build_node_aad over every case in uuid-acceptance.json and asserts Rust
/// agrees with the shared accept/reject verdict. The TS side
/// (packages/crypto/src/__tests__/build-node-aad.test.ts) drives the identical
/// oracle so a divergent UUID acceptance domain between languages fails on both
/// sides (SC3, Option A: canonical-only).
#[test]
fn uuid_acceptance_cross_language() {
    let path = vectors_path("crypto/uuid-acceptance.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    let oracle: UuidAcceptanceOracle = serde_json::from_str(&data).unwrap();

    // Non-vacuous guard: at least 2 accept and 6 reject cases must be present.
    assert!(
        oracle.cases.len() >= 8,
        "Expected at least 8 uuid-acceptance.json cases"
    );
    let accept_count = oracle.cases.iter().filter(|c| c.expected == "accept").count();
    let reject_count = oracle.cases.iter().filter(|c| c.expected == "reject").count();
    assert!(accept_count >= 2, "Expected at least 2 accept cases");
    assert!(reject_count >= 6, "Expected at least 6 reject cases");

    let params = &oracle.fixed_params;
    for c in &oracle.cases {
        let result = cipherbox_crypto::build_node_aad(&c.node_id, params.kind, params.generation, params.role);
        match c.expected.as_str() {
            "accept" => assert!(
                result.is_ok(),
                "expected accept for: {} ({:?}), got {:?}",
                c.description,
                c.node_id,
                result
            ),
            "reject" => assert!(
                result.is_err(),
                "expected reject for: {} ({:?}), got Ok",
                c.description,
                c.node_id
            ),
            other => panic!("unknown expected value '{}' in case: {}", other, c.description),
        }
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
