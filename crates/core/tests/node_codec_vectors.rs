//! Cross-language Node codec KAT — asserts cipherbox-core's Node JSON codec
//! produces byte-identical output to `tests/vectors/node-codec.json`
//! (the frozen cross-language oracle, D-04, SC#4).
//!
//! Mirrors the vector-loading pattern from `crates/crypto/tests/cross_language.rs`.
//! This plan (69-01) is scoped to the plaintext JSON codec only (`body_vectors`);
//! the `seal_vectors` (full AEAD seal) are exercised once a later Phase-69 plan
//! wires `cipherbox_core::node` to `cipherbox-crypto`'s seal primitives.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
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
    // Only present on file-kind body vectors (folder/root nodes carry no
    // content.fileIv at all) — see Task 1's SC2 sample-value rework.
    #[serde(default)]
    expected_file_iv_len_bytes: Option<usize>,
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

/// SC2 (T-75-09/T-75-10): NodeContent.file_iv is base64 on the wire, never hex
/// (Phase 69 desktop-e2e "Decryption failed" root cause). The PRIMARY LOCK test
/// above only round-trips fileIv as an opaque string — it never decodes it, so a
/// hex-vs-base64 implementation divergence would still pass silently. This test
/// closes that gap: for every body vector carrying `expected_file_iv_len_bytes`
/// (file-kind vectors only — folder/root nodes have no content.fileIv), base64-
/// decode content.fileIv and each versions[].fileIv, and assert the decoded
/// length matches the pinned expectation. A hex decode substituted here would
/// either fail outright (the samples contain non-hex characters / '=' padding)
/// or, if it happened to parse, silently disagree with the pinned byte length.
#[test]
fn node_codec_kat_file_iv_is_base64_not_hex() {
    let vectors = load_vectors();
    assert!(
        !vectors.body_vectors.is_empty(),
        "node-codec.json body_vectors must not be empty"
    );

    let mut file_iv_vectors_checked = 0usize;

    for v in &vectors.body_vectors {
        let Some(expected_len) = v.expected_file_iv_len_bytes else {
            // folder/root vectors carry no content.fileIv — nothing to decode.
            continue;
        };
        file_iv_vectors_checked += 1;

        let content = v
            .node
            .get("content")
            .unwrap_or_else(|| panic!("vector {} missing node.content", v.description));

        let file_iv_b64 = content
            .get("fileIv")
            .and_then(|f| f.as_str())
            .unwrap_or_else(|| panic!("vector {} missing content.fileIv", v.description));
        let file_iv_bytes = STANDARD.decode(file_iv_b64).unwrap_or_else(|e| {
            panic!(
                "fileIv base64 decode failed for {}: {}",
                v.description, e
            )
        });
        assert_eq!(
            file_iv_bytes.len(),
            expected_len,
            "content.fileIv byte length mismatch for {}",
            v.description
        );

        let versions = content
            .get("versions")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("vector {} missing content.versions array", v.description));
        for version in versions {
            let version_file_iv_b64 = version
                .get("fileIv")
                .and_then(|f| f.as_str())
                .unwrap_or_else(|| {
                    panic!("vector {} has a version missing fileIv", v.description)
                });
            let version_file_iv_bytes = STANDARD.decode(version_file_iv_b64).unwrap_or_else(|e| {
                panic!(
                    "versions[].fileIv base64 decode failed for {}: {}",
                    v.description, e
                )
            });
            assert_eq!(
                version_file_iv_bytes.len(),
                expected_len,
                "versions[].fileIv byte length mismatch for {}",
                v.description
            );
        }
    }

    // Non-vacuous guard: at least the GCM and CTR file vectors must have been
    // exercised, or this test would trivially pass on an all-folder/root fixture.
    assert!(
        file_iv_vectors_checked >= 2,
        "expected at least 2 body vectors carrying expected_file_iv_len_bytes, found {}",
        file_iv_vectors_checked
    );
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
