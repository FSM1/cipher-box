//! Cross-language IPNS verify test vectors.
//!
//! Loads the shared fixture from tests/vectors/ipns/verify.json and validates
//! each case against the real `verify_ipns_resolve_signature` (from
//! `cipherbox-api-client`) and `decode_ipns_cbor_data` (from `cipherbox-core`),
//! matching the binding logic in `crates/fuse/src/verify.rs` `bind_verified`.
//!
//! Located in `crates/fuse` to avoid a dependency cycle: both
//! `cipherbox-api-client` and `cipherbox-core` depend on `cipherbox-crypto`, so
//! `cipherbox-crypto` cannot dev-depend on either without a cycle. `cipherbox-fuse`
//! already depends on both, making it the cycle-free home for this test (D-12).
//!
//! See: tests/vectors/ipns/verify.json for the 7 cases (D-11).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
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
    expected_result: String, // "valid" | "invalid" | "legacy"
}

/// Run the same two-step binding logic as `crates/fuse/src/verify.rs` `bind_verified`:
///
/// 1. Call `verify_ipns_resolve_signature` → `Option<bool>`.
/// 2. For `Some(true)`: base64-decode `data`, call `decode_ipns_cbor_data`, compare
///    embedded value to `/ipfs/{resp.cid}` and embedded seq to `resp.sequence_number`.
/// 3. Map to "valid" | "invalid" | "legacy".
///
/// This is equivalent to `bind_verified(&resp, verdict)` but spelled out explicitly so
/// the test pins both the api-client signature check and the core CBOR decode path.
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

    match verdict {
        None => "legacy".to_string(),
        Some(false) => "invalid".to_string(),
        Some(true) => {
            // Signature is valid. Perform the CBOR binding check (D-07/D-08).
            // This is the same path as bind_verified in fuse/src/verify.rs.
            let data_b64 = match resp.data.as_deref() {
                Some(s) => s,
                None => return "invalid".to_string(),
            };
            let data_bytes = match STANDARD.decode(data_b64) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[{}] base64 decode failed: {}", v.description, e);
                    return "invalid".to_string();
                }
            };

            let (embedded_value, embedded_seq) =
                match cipherbox_core::ipns::decode_ipns_cbor_data(&data_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[{}] CBOR decode failed: {}", v.description, e);
                        return "invalid".to_string();
                    }
                };

            // D-08: embedded CBOR value must be "/ipfs/<response.cid>"
            let expected_value = format!("/ipfs/{}", resp.cid);
            if embedded_value != expected_value {
                eprintln!(
                    "[{}] cid binding mismatch: embedded={}, response={}",
                    v.description, embedded_value, resp.cid
                );
                return "invalid".to_string();
            }

            // D-07: embedded seq must match response sequence_number
            let resp_seq = match resp.sequence_number.parse::<u64>() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[{}] parse sequence_number failed: {}", v.description, e);
                    return "invalid".to_string();
                }
            };
            if embedded_seq != resp_seq {
                eprintln!(
                    "[{}] seq binding mismatch: embedded={}, response={}",
                    v.description, embedded_seq, resp_seq
                );
                return "invalid".to_string();
            }

            "valid".to_string()
        }
    }
}

/// Cross-language IPNS verify parity test.
///
/// Loads the 7-case shared fixture and asserts that Rust produces the same
/// verdict as the expected_result field. This pins:
///
/// - `cipherbox_api_client::ipns::verify_ipns_resolve_signature` (the signed-bytes
///   construction: "ipns-signature:" prefix || CBOR data)
/// - `cipherbox_core::ipns::decode_ipns_cbor_data` (the CBOR field extraction)
///
/// Both are exercised against vectors whose bytes were produced by the JS
/// generator (`scripts/gen-ipns-verify-vectors.ts`), so any Rust↔JS drift
/// in byte-construction fails this test — satisfying D-12.
#[test]
fn ipns_verify_cross_language() {
    let vectors: Vec<IpnsVerifyVector> = load_vectors("ipns/verify.json");
    assert!(!vectors.is_empty(), "No IPNS verify vectors loaded");
    assert_eq!(vectors.len(), 7, "Expected exactly 7 IPNS verify vectors");

    for v in &vectors {
        let actual = classify_vector(v);
        assert_eq!(
            actual, v.expected_result,
            "IPNS verify vector mismatch for: {}",
            v.description
        );
    }
}
