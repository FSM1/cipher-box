//! Cross-language Node codec KAT — asserts cipherbox-core's Node JSON codec
//! produces byte-identical output to `tests/vectors/node-codec.json`
//! (the frozen cross-language oracle, D-04, SC#4).
//!
//! Mirrors the vector-loading pattern from `crates/crypto/tests/cross_language.rs`.
//! This plan (69-01) is scoped to the plaintext JSON codec only (`body_vectors`);
//! the `seal_vectors` (full AEAD seal) are exercised once a later Phase-69 plan
//! wires `cipherbox_core::node` to `cipherbox-crypto`'s seal primitives.

use cipherbox_core::node::{decode_node, encode_node, Node, SealedChildRef};
use serde::Deserialize;
use std::path::PathBuf;

/// Resolve path to the shared cross-language test vector relative to workspace root.
fn vectors_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/vectors/node-codec.json");
    p
}

#[derive(Deserialize)]
struct BodyVector {
    description: String,
    node: serde_json::Value,
    expected_read_body_hex: String,
}

#[derive(Deserialize)]
struct NodeCodecVectors {
    body_vectors: Vec<BodyVector>,
}

fn load_vectors() -> NodeCodecVectors {
    let path = vectors_path();
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e))
}

#[test]
fn node_codec_round_trips_and_byte_matches_kat() {
    let vectors = load_vectors();
    // Non-vacuous vector-count guard (no vacuous pass, T-69-01-02).
    assert!(
        !vectors.body_vectors.is_empty(),
        "node-codec.json body_vectors must not be empty"
    );

    for v in &vectors.body_vectors {
        let expected_bytes = hex::decode(&v.expected_read_body_hex)
            .unwrap_or_else(|e| panic!("bad hex in {}: {}", v.description, e));

        // decode(vector.encodedJson) yields the expected Node variant.
        let decoded = decode_node(&expected_bytes)
            .unwrap_or_else(|e| panic!("decode_node failed for {}: {:?}", v.description, e));

        let expected_kind = v
            .node
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or_else(|| panic!("vector {} missing node.kind", v.description));
        let actual_kind = match &decoded {
            Node::Folder { .. } => "folder",
            Node::File { .. } => "file",
            Node::Root { .. } => "root",
        };
        assert_eq!(
            actual_kind, expected_kind,
            "kind mismatch for: {}",
            v.description
        );

        // re-encode(decoded) is byte-identical to the vector's canonical JSON.
        let re_encoded = encode_node(&decoded)
            .unwrap_or_else(|e| panic!("encode_node failed for {}: {:?}", v.description, e));
        assert_eq!(
            hex::encode(&re_encoded),
            v.expected_read_body_hex,
            "re-encode byte mismatch for: {}",
            v.description
        );
    }
}

#[test]
fn sealed_child_ref_has_exactly_five_fields() {
    let json = r#"{
        "name": "docs",
        "ipnsName": "k51abc",
        "generation": 0,
        "versionFloor": "0",
        "readKeySealed": "AAAA"
    }"#;
    let parsed: SealedChildRef =
        serde_json::from_str(json).expect("valid five-field SealedChildRef must decode");
    assert_eq!(parsed.name, "docs");
    assert_eq!(parsed.ipns_name, "k51abc");
    assert_eq!(parsed.generation, 0);
    assert_eq!(parsed.version_floor, 0);
    assert_eq!(parsed.read_key_sealed, "AAAA");
}

#[test]
fn sealed_child_ref_rejects_unknown_fields() {
    // NODE-03: SealedChildRef is the frozen five-field set with no write field.
    // An extra/unknown field (e.g. a smuggled writeKeySealed) must be rejected.
    let json = r#"{
        "name": "docs",
        "ipnsName": "k51abc",
        "generation": 0,
        "versionFloor": "0",
        "readKeySealed": "AAAA",
        "writeKeySealed": "smuggled"
    }"#;
    let result: Result<SealedChildRef, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "SealedChildRef must reject unknown fields (NODE-03)"
    );
}
