//! AAD-bound Node seal/unseal KAT + transplant-resistance test —
//! `crates/core/src/node/seal.rs` (69-04).
//!
//! Loads the frozen AAD oracle `tests/vectors/crypto/node-aad.json` and
//! exercises the wrapper via round-trip decryption success (a mismatched
//! AAD would otherwise fail the GCM auth-tag check), so a passing test here
//! proves `seal.rs`'s internal `build_node_aad` calls byte-match the KAT.
//!
//! This is RED until `cipherbox_core::node::seal` exists (69-04 Task 2).

use cipherbox_core::node::seal::{seal_child_read_key, seal_node, unseal_child_read_key, unseal_node};
use cipherbox_core::node::NodeKind;
use serde::Deserialize;
use std::path::PathBuf;

/// Resolve path to the shared cross-language AAD test vector relative to workspace root.
fn vectors_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/vectors/crypto/node-aad.json");
    p
}

#[derive(Deserialize)]
struct SealVector {
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

#[derive(Deserialize)]
struct AadVector {
    description: String,
    node_id: String,
    kind: u8,
    generation: u32,
    role: u8,
    expected_aad: String,
}

#[derive(Deserialize)]
struct NodeAadVectors {
    seal_vectors: Vec<SealVector>,
    aad_vectors: Vec<AadVector>,
}

fn load_vectors() -> NodeAadVectors {
    let path = vectors_path();
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e))
}

fn kind_from_u8(kind: u8) -> NodeKind {
    match kind {
        1 => NodeKind::Folder,
        2 => NodeKind::File,
        3 => NodeKind::Root,
        other => panic!("unexpected kind byte in vector: {other}"),
    }
}

fn key32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("valid hex key");
    bytes.try_into().expect("32-byte key")
}

/// D-01b full-seal KAT: a fixed key/iv/ciphertext role-0x01 (body) vector
/// must unseal (via `unseal_node`) to the exact expected plaintext.
#[test]
fn seal_vectors_full_seal_kat_role_body() {
    let vectors = load_vectors();
    assert!(
        !vectors.seal_vectors.is_empty(),
        "node-aad.json seal_vectors must not be empty"
    );

    for v in &vectors.seal_vectors {
        assert_eq!(v.role, 1, "unexpected role in seal_vectors: {}", v.description);

        let key = key32(&v.key);
        let iv = hex::decode(&v.iv).expect("valid hex iv");
        let ciphertext = hex::decode(&v.ciphertext).expect("valid hex ciphertext");
        let plaintext = hex::decode(&v.plaintext).expect("valid hex plaintext");

        let mut sealed = iv.clone();
        sealed.extend_from_slice(&ciphertext);

        let kind = kind_from_u8(v.kind);
        let recovered = unseal_node(&sealed, &key, &v.node_id, kind, v.generation)
            .unwrap_or_else(|e| panic!("unseal_node failed for {}: {:?}", v.description, e));
        assert_eq!(recovered, plaintext, "plaintext mismatch for: {}", v.description);
    }
}

/// AAD KAT: for role 0x01 (body) and role 0x02 (child-readkey) vectors, a
/// blob manually sealed under `expected_aad` must be unsealable by our
/// wrapper — this only succeeds if the wrapper's internal `build_node_aad`
/// call byte-matches `expected_aad`.
#[test]
fn aad_vectors_role_body_and_child_readkey_conform() {
    let vectors = load_vectors();
    assert!(
        !vectors.aad_vectors.is_empty(),
        "node-aad.json aad_vectors must not be empty"
    );

    let mut checked = 0;
    for v in &vectors.aad_vectors {
        if v.role != 1 && v.role != 2 {
            // role 0x03 (content) and 0x04 (write-key) are outside this
            // plan's read-chain scope check; exercised elsewhere.
            continue;
        }
        checked += 1;

        let expected_aad = hex::decode(&v.expected_aad).expect("valid hex aad");
        let key = [0x11u8; 32];
        let kind = kind_from_u8(v.kind);
        let plaintext = b"probe-plaintext-for-aad-check";

        let manual_sealed = cipherbox_crypto::aes::seal_aes_gcm_aad(plaintext, &key, &expected_aad)
            .expect("manual seal must succeed");

        let recovered = if v.role == 1 {
            unseal_node(&manual_sealed, &key, &v.node_id, kind, v.generation)
        } else {
            unseal_child_read_key(&manual_sealed, &key, &v.node_id, kind, v.generation)
        }
        .unwrap_or_else(|e| panic!("unseal via wrapper failed for {}: {:?}", v.description, e));

        assert_eq!(&recovered[..], plaintext, "AAD mismatch for: {}", v.description);
    }
    assert!(checked > 0, "expected at least one role 0x01/0x02 aad_vector");
}

#[test]
fn seal_node_round_trip() {
    let key = [0x22u8; 32];
    let node_id = "550e8400-e29b-41d4-a716-446655440000";
    let body = b"round-trip read-body bytes";

    let sealed = seal_node(body, &key, node_id, NodeKind::Folder, 7).expect("seal_node ok");
    let recovered =
        unseal_node(&sealed, &key, node_id, NodeKind::Folder, 7).expect("unseal_node ok");
    assert_eq!(recovered, body);
}

#[test]
fn seal_child_read_key_round_trip() {
    let parent_key = [0x33u8; 32];
    let child_key = [0x44u8; 32];
    let child_id = "660e8400-e29b-41d4-a716-446655440001";

    let sealed = seal_child_read_key(&child_key, &parent_key, child_id, NodeKind::File, 3)
        .expect("seal_child_read_key ok");
    let recovered = unseal_child_read_key(&sealed, &parent_key, child_id, NodeKind::File, 3)
        .expect("unseal_child_read_key ok");
    assert_eq!(recovered, child_key.to_vec());
}

/// Transplant resistance (T-69-04-01): a blob sealed at (childId=A, role=0x02,
/// generation=5) must fail to unseal when replayed under a different
/// childId, role, or generation.
#[test]
fn transplant_resistance_child_id_role_and_generation() {
    let parent_key = [0x55u8; 32];
    let child_key = [0x66u8; 32];
    let child_id_a = "770e8400-e29b-41d4-a716-446655440002";
    let child_id_b = "880e8400-e29b-41d4-a716-446655440003";

    let sealed = seal_child_read_key(&child_key, &parent_key, child_id_a, NodeKind::Folder, 5)
        .expect("seal ok");

    assert!(
        unseal_child_read_key(&sealed, &parent_key, child_id_b, NodeKind::Folder, 5).is_err(),
        "transplant to a different childId must fail"
    );

    assert!(
        unseal_node(&sealed, &parent_key, child_id_a, NodeKind::Folder, 5).is_err(),
        "transplant to a different role must fail"
    );

    assert!(
        unseal_child_read_key(&sealed, &parent_key, child_id_a, NodeKind::Folder, 6).is_err(),
        "transplant to a different generation must fail"
    );

    assert!(
        unseal_child_read_key(&sealed, &parent_key, child_id_a, NodeKind::Folder, 5).is_ok(),
        "correct parameters must still unseal (sanity)"
    );
}

/// D-03 fail-closed: `build_node_aad` (and thus `seal_node`) must reject a
/// malformed node_id rather than silently succeeding.
#[test]
fn build_node_aad_fail_closed_on_malformed_node_id() {
    let key = [0x77u8; 32];
    let body = b"whatever";
    let result = seal_node(body, &key, "not-a-uuid", NodeKind::Folder, 1);
    assert!(result.is_err(), "malformed node_id must fail closed");
}

#[test]
fn seal_produces_fresh_random_iv_each_call() {
    let key = [0x88u8; 32];
    let node_id = "990e8400-e29b-41d4-a716-446655440004";
    let body = b"same body sealed twice";

    let sealed1 = seal_node(body, &key, node_id, NodeKind::Folder, 1).expect("seal ok");
    let sealed2 = seal_node(body, &key, node_id, NodeKind::Folder, 1).expect("seal ok");
    assert_ne!(sealed1, sealed2, "two seals of the same body must differ (fresh IV)");
}
