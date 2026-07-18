//! Cross-language write-body seal KAT — asserts `seal_published_node`'s
//! write-body arm reproduces `tests/vectors/node-codec.json`
//! `seal_vectors[0].expected_published_node.writeSealed` byte-for-byte
//! (fixed key + fixed IV, D-04/D-07, 69-15 Task 2, A2 RESOLVED).
//!
//! Mirrors the fixed-IV low-level seal path used by
//! `crates/crypto/tests/cross_language.rs` (`seal_vectors`): rebuild the AAD,
//! encrypt with `encrypt_aes_gcm_aad` under the FIXED iv, and compare the
//! IV||ciphertext blob (base64) to the committed oracle — proving Rust
//! `encode_write_body` + the role-0x01/writeKey seal matches the TS oracle.

use cipherbox_core::node::{encode_write_body, NodeWriteBody, WriteChildRef};
use serde::Deserialize;
use std::path::PathBuf;

/// Resolve path to the shared cross-language test vector relative to workspace root.
fn vectors_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/vectors/node-codec.json");
    p
}

#[derive(Deserialize)]
struct ExpectedPublishedNode {
    #[allow(dead_code)]
    schema: String,
    #[allow(dead_code)]
    kind: String,
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    generation: u32,
    #[allow(dead_code)]
    #[serde(rename = "aeadVersion")]
    aead_version: u8,
    #[allow(dead_code)]
    #[serde(rename = "readSealed")]
    read_sealed: String,
    #[serde(rename = "writeSealed")]
    write_sealed: String,
}

#[derive(Deserialize)]
struct SealVector {
    description: String,
    node_id: String,
    kind: u8,
    generation: u32,
    #[allow(dead_code)]
    read_key: String,
    write_key: String,
    ipns_private_key_hex: String,
    fixed_iv: String,
    /// Recipient-pubkey pins (raw compressed secp256k1, base64) sealed inside
    /// the write-body (D-03b). Absent (defaults to empty) for the frozen
    /// seal_vectors[0] empty-pin KAT.
    #[serde(default)]
    recipient_pins: Vec<String>,
    expected_published_node: ExpectedPublishedNode,
}

#[derive(Deserialize)]
struct NodeCodecSealVectors {
    seal_vectors: Vec<SealVector>,
}

fn load_vectors() -> NodeCodecSealVectors {
    let path = vectors_path();
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e))
}

/// Reproduces `writeSealed` byte-for-byte via the fixed-IV low-level seal
/// path (mirrors `crates/crypto/tests/cross_language.rs` `seal_vectors`).
#[test]
fn write_body_seal_matches_kat() {
    let vectors = load_vectors();
    // Non-vacuous vector-count guard (no vacuous pass).
    assert!(
        !vectors.seal_vectors.is_empty(),
        "node-codec.json seal_vectors must not be empty"
    );

    for v in &vectors.seal_vectors {
        let write_key_bytes = hex::decode(&v.write_key)
            .unwrap_or_else(|_| panic!("Bad hex write_key in: {}", v.description));
        let write_key: [u8; 32] = write_key_bytes
            .try_into()
            .unwrap_or_else(|_| panic!("write_key must be 32 bytes in: {}", v.description));

        let iv_bytes = hex::decode(&v.fixed_iv)
            .unwrap_or_else(|_| panic!("Bad hex fixed_iv in: {}", v.description));
        let iv: [u8; 12] = iv_bytes
            .try_into()
            .unwrap_or_else(|_| panic!("fixed_iv must be 12 bytes in: {}", v.description));

        let ipns_private_key = hex::decode(&v.ipns_private_key_hex)
            .unwrap_or_else(|_| panic!("Bad hex ipns_private_key_hex in: {}", v.description));

        // Decode the recipient pins (base64 → raw compressed pubkey bytes).
        // Empty for seal_vectors[0]; non-empty for seal_vectors[1].
        let recipient_pins: Vec<Vec<u8>> = v
            .recipient_pins
            .iter()
            .map(|p| {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, p)
                    .unwrap_or_else(|_| panic!("Bad base64 recipient_pin in: {}", v.description))
            })
            .collect();

        let wb = NodeWriteBody {
            ipns_private_key,
            write_children: Vec::<WriteChildRef>::new(),
            recipient_pins,
        };
        let wb_bytes = encode_write_body(&wb)
            .unwrap_or_else(|e| panic!("encode_write_body failed for {}: {:?}", v.description, e));

        let aad = cipherbox_crypto::build_node_aad(&v.node_id, v.kind, v.generation, 0x01)
            .unwrap_or_else(|e| panic!("build_node_aad failed for {}: {:?}", v.description, e));

        let ciphertext = cipherbox_crypto::encrypt_aes_gcm_aad(&wb_bytes, &write_key, &iv, &aad)
            .unwrap_or_else(|e| {
                panic!("encrypt_aes_gcm_aad failed for {}: {:?}", v.description, e)
            });

        let mut sealed = iv.to_vec();
        sealed.extend_from_slice(&ciphertext);
        let sealed_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sealed);

        assert_eq!(
            sealed_b64, v.expected_published_node.write_sealed,
            "writeSealed KAT mismatch for: {}",
            v.description
        );
    }
}
