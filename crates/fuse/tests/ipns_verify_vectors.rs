//! Cross-language IPNS verify test vectors.
//!
//! Loads the shared fixture from tests/vectors/ipns/verify.json and validates
//! each case against the real, production `cipherbox_api_client::ipns::bind_verified`
//! (which itself calls `verify_ipns_resolve_signature` and `cipherbox-core`'s CBOR
//! decoders) — no binding logic is re-implemented here (Phase 75 dedup, gap #9).
//!
//! Located in `crates/fuse` to avoid a dependency cycle: both
//! `cipherbox-api-client` and `cipherbox-core` depend on `cipherbox-crypto`, so
//! `cipherbox-crypto` cannot dev-depend on either without a cycle. `cipherbox-fuse`
//! already depends on both, making it the cycle-free home for this test (D-12).
//!
//! See: tests/vectors/ipns/verify.json for the 12 cases (D-11, extended Phase 75).

use serde::Deserialize;
use std::path::PathBuf;

// ============================================================
// Vector loading helpers (mirrors cross_language.rs convention)
// ============================================================

/// Resolve the path to the shared test vectors directory from CARGO_MANIFEST_DIR.
/// crates/fuse is two levels below the repo root, so we go ../../tests/vectors.
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
// IPNS Verify Vectors
// ============================================================

/// Deserializes one entry from tests/vectors/ipns/verify.json.
///
/// Field names match the fixture schema exactly (snake_case JSON).
#[derive(Deserialize)]
struct IpnsVerifyVector {
    description: String,
    ipns_name: String,
    cid: String,
    sequence_number: String,
    signature_v2: Option<String>,
    data: Option<String>,
    pub_key: Option<String>,
    expected_result: String, // "valid" | "invalid"
}

/// Classify a vector using the real, production binding logic — no hand-spelled
/// cid/sequence/ValidityType logic here (Phase 75 dedup, gap #9).
///
/// 1. Call `verify_ipns_resolve_signature` → `Option<bool>` signature verdict.
/// 2. Call the now-`pub` `cipherbox_api_client::ipns::bind_verified` with that verdict,
///    which owns ALL binding: base64 decode, CBOR cid/sequence binding (D-07/D-08), and
///    the ValidityType == 0 EOL gate + expiry check (Phase 75 gap #7).
/// 3. Map `Ok` → "valid", `Err` → "invalid".
fn classify_vector(v: &IpnsVerifyVector) -> String {
    let resp = cipherbox_api_client::types::IpnsResolveResponse {
        success: true,
        cid: v.cid.clone(),
        sequence_number: v.sequence_number.clone(),
        signature_v2: v.signature_v2.clone(),
        data: v.data.clone(),
        pub_key: v.pub_key.clone(),
    };

    let verdict =
        match cipherbox_api_client::ipns::verify_ipns_resolve_signature(&resp, &v.ipns_name) {
            Err(e) => {
                eprintln!("[{}] verify error: {}", v.description, e);
                return "invalid".to_string();
            }
            Ok(v) => v,
        };

    match cipherbox_api_client::ipns::bind_verified(&resp, verdict) {
        Ok(_) => "valid".to_string(),
        Err(e) => {
            eprintln!("[{}] bind_verified rejected: {}", v.description, e);
            "invalid".to_string()
        }
    }
}

/// Cross-language IPNS verify parity test.
///
/// Loads the 12-case shared fixture and asserts that Rust produces the same
/// verdict as the expected_result field. This pins:
///
/// - `cipherbox_api_client::ipns::verify_ipns_resolve_signature` (the signed-bytes
///   construction: "ipns-signature:" prefix || CBOR data)
/// - `cipherbox_api_client::ipns::bind_verified` (CBOR cid/sequence binding, D-07/D-08,
///   and the Phase 75 ValidityType == 0 EOL gate + expiry check)
///
/// Both are exercised against vectors whose bytes were produced by the JS
/// generator (`scripts/gen-ipns-verify-vectors.ts`), so any Rust↔JS drift
/// in byte-construction fails this test — satisfying D-12.
#[test]
fn ipns_verify_cross_language() {
    let vectors: Vec<IpnsVerifyVector> = load_vectors("ipns/verify.json");
    assert!(!vectors.is_empty(), "No IPNS verify vectors loaded");
    assert_eq!(vectors.len(), 12, "Expected exactly 12 IPNS verify vectors");

    for v in &vectors {
        let actual = classify_vector(v);
        assert_eq!(
            actual, v.expected_result,
            "IPNS verify vector mismatch for: {}",
            v.description
        );
    }
}
