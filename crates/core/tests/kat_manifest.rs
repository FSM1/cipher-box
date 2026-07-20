//! The KAT manifest job (blueprint/core.md "KAT regime", blueprint/testing.md
//! "crates/core — KATs and property tests"): merge-blocking, machine-checked.
//!
//! Fixtures are embedded with `include_str!` — never loaded from the
//! filesystem at runtime — so the same suite runs natively and under
//! wasm32-wasip1 (the residual parity surface). Vectors regenerate only
//! through the committed generator (`examples/kat_gen.rs`); the exact counts
//! and coverage lists here are the anti-vacuity backstop.

use std::collections::BTreeSet;

// On wasm32-unknown-unknown (the browser-shaped KAT leg) there is no libtest
// harness; wasm-bindgen-test provides one. Shadowing `test` with its attribute
// runs every `#[test]` below under wasm-bindgen-test-runner unchanged, while
// native and wasm32-wasip1 keep the built-in `#[test]`.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use cipherbox_core::codec::{decode, decode_map_partial, encode, encode_map_partial};
use cipherbox_core::error::{Malformed, TrustViolation};
use serde::Deserialize;

const MANIFEST: &str = include_str!("../kat/manifest.json");

/// Every vector file the manifest may reference, embedded at compile time.
/// Path keys are manifest-relative (relative to `kat/`).
const FIXTURES: &[(&str, &str)] = &[
    (
        "vectors/codec/accept.json",
        include_str!("../kat/vectors/codec/accept.json"),
    ),
    (
        "vectors/codec/reject.json",
        include_str!("../kat/vectors/codec/reject.json"),
    ),
    (
        "vectors/codec/unknown_fields.json",
        include_str!("../kat/vectors/codec/unknown_fields.json"),
    ),
];

// ---------------------------------------------------------------------------
// Manifest + vector file shapes. deny_unknown_fields: a field the schema does
// not know is a manifest drift, not a tolerance.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    manifest_version: u64,
    profile: String,
    codecs: Codecs,
    structure_tags: serde_json::Map<String, serde_json::Value>,
    kdf_edges: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Codecs {
    #[serde(rename = "det-cbor")]
    det_cbor: DetCbor,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DetCbor {
    accept: AcceptSection,
    reject: RejectSection,
    unknown_fields: UnknownFieldsSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptSection {
    file: String,
    count: usize,
    required_kinds: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectSection {
    file: String,
    count: usize,
    checks: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnknownFieldsSection {
    file: String,
    count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptVector {
    name: String,
    hex: String,
    diag: String,
    kinds: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectVector {
    name: String,
    hex: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnknownVector {
    name: String,
    hex: String,
    known_keys: Vec<String>,
    expect_unknown_count: usize,
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn manifest() -> Manifest {
    serde_json::from_str(MANIFEST).expect("kat/manifest.json must match the manifest schema")
}

fn fixture(path: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(p, _)| *p == path)
        .unwrap_or_else(|| panic!("manifest references {path}, which is not include_str!-embedded"))
        .1
}

fn accept_vectors(m: &Manifest) -> Vec<AcceptVector> {
    serde_json::from_str(fixture(&m.codecs.det_cbor.accept.file)).expect("accept.json shape")
}

fn reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.codecs.det_cbor.reject.file)).expect("reject.json shape")
}

fn unknown_vectors(m: &Manifest) -> Vec<UnknownVector> {
    serde_json::from_str(fixture(&m.codecs.det_cbor.unknown_fields.file))
        .expect("unknown_fields.json shape")
}

fn unhex(name: &str, hex: &str) -> Vec<u8> {
    let bytes = hex::decode(hex).unwrap_or_else(|e| panic!("vector {name}: bad hex: {e}"));
    // Lowercase hex is part of the fixture contract.
    assert_eq!(
        hex::encode(&bytes),
        hex,
        "vector {name}: hex must be lowercase"
    );
    bytes
}

// ---------------------------------------------------------------------------
// Assertions.
// ---------------------------------------------------------------------------

#[test]
fn manifest_header_is_pinned() {
    let m = manifest();
    assert_eq!(m.manifest_version, 1);
    assert_eq!(m.profile, "cipherbox/v2 det-cbor");
}

#[test]
fn fixture_table_matches_manifest_files() {
    let m = manifest();
    let referenced = [
        m.codecs.det_cbor.accept.file.as_str(),
        m.codecs.det_cbor.reject.file.as_str(),
        m.codecs.det_cbor.unknown_fields.file.as_str(),
    ];
    let referenced_set: BTreeSet<&str> = referenced.iter().copied().collect();
    assert_eq!(
        referenced_set.len(),
        referenced.len(),
        "manifest must not reference the same file twice"
    );
    let embedded: BTreeSet<&str> = FIXTURES.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        referenced_set, embedded,
        "manifest files and include_str!-embedded fixtures must match 1:1"
    );
}

#[test]
fn vector_counts_are_exact() {
    let m = manifest();
    assert_eq!(
        accept_vectors(&m).len(),
        m.codecs.det_cbor.accept.count,
        "accept.json count drift"
    );
    assert_eq!(
        reject_vectors(&m).len(),
        m.codecs.det_cbor.reject.count,
        "reject.json count drift"
    );
    assert_eq!(
        unknown_vectors(&m).len(),
        m.codecs.det_cbor.unknown_fields.count,
        "unknown_fields.json count drift"
    );
}

#[test]
fn vector_names_are_unique_within_each_file() {
    let m = manifest();
    let mut seen = BTreeSet::new();
    for v in accept_vectors(&m) {
        assert!(
            seen.insert(v.name.clone()),
            "duplicate accept vector name {}",
            v.name
        );
    }
    seen.clear();
    for v in reject_vectors(&m) {
        assert!(
            seen.insert(v.name.clone()),
            "duplicate reject vector name {}",
            v.name
        );
    }
    seen.clear();
    for v in unknown_vectors(&m) {
        assert!(
            seen.insert(v.name.clone()),
            "duplicate unknown-field vector name {}",
            v.name
        );
    }
}

#[test]
fn reject_checks_list_matches_vectors_and_error_surface() {
    let m = manifest();
    let listed: BTreeSet<&str> = m
        .codecs
        .det_cbor
        .reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        listed.len(),
        m.codecs.det_cbor.reject.checks.len(),
        "manifest checks list must not contain duplicates"
    );

    let vectors = reject_vectors(&m);
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks must be exactly the distinct checks in reject.json"
    );

    let all: BTreeSet<&str> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .copied()
        .collect();
    assert!(
        listed.is_subset(&all),
        "every manifest check must exist on the error surface"
    );
    for check in TrustViolation::CHECKS {
        assert!(
            listed.contains(check),
            "all trust-violation checks are decode-reachable; missing {check}"
        );
    }

    // The only checks without reject vectors are the two that `decode` can
    // never emit: unexpected-type (schema-layer accessor failure) and
    // unknown-field-collision (encode_map_partial caller bug). Both are
    // unit-test-pinned in src/codec/fields.rs.
    let absent: BTreeSet<&str> = all.difference(&listed).copied().collect();
    let expected_absent: BTreeSet<&str> = ["unexpected-type", "unknown-field-collision"]
        .into_iter()
        .collect();
    assert_eq!(
        absent, expected_absent,
        "reject vectors must cover every decode-reachable check"
    );
}

#[test]
fn accept_kinds_cover_required_kinds_exactly() {
    let m = manifest();
    let required: BTreeSet<&str> = m
        .codecs
        .det_cbor
        .accept
        .required_kinds
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        required.len(),
        m.codecs.det_cbor.accept.required_kinds.len(),
        "requiredKinds must not contain duplicates"
    );

    // The canonical kind list is fixed HERE, independent of the generator —
    // the accept-side anchor mirroring how reject checks anchor to the error
    // surface. Dropping an accept vector (and its kind) from kat_gen must
    // fail this test, never silently shrink coverage.
    const ALL_KINDS: &[&str] = &[
        "uint",
        "negint",
        "bytes",
        "text",
        "array",
        "map",
        "bool",
        "null",
        "depth-limit",
    ];
    let canonical: BTreeSet<&str> = ALL_KINDS.iter().copied().collect();
    assert_eq!(
        required, canonical,
        "requiredKinds must be exactly the canonical kind list"
    );

    let vectors = accept_vectors(&m);
    for kind in &required {
        assert!(
            vectors.iter().any(|v| v.kinds.iter().any(|k| k == kind)),
            "required kind {kind} has no accept vector"
        );
    }
    for v in &vectors {
        assert!(!v.kinds.is_empty(), "accept vector {} has no kinds", v.name);
        for k in &v.kinds {
            assert!(
                required.contains(k.as_str()),
                "accept vector {} has kind {k} outside requiredKinds",
                v.name
            );
        }
    }
}

#[test]
fn accept_vectors_decode_reencode_and_render_diag() {
    let m = manifest();
    for v in accept_vectors(&m) {
        let bytes = unhex(&v.name, &v.hex);
        let value = decode(&bytes)
            .unwrap_or_else(|e| panic!("accept vector {}: decoder rejected it: {e}", v.name));
        assert_eq!(
            hex::encode(encode(&value)),
            v.hex,
            "accept vector {}: re-encode must be byte-identical",
            v.name
        );
        assert_eq!(
            value.to_string(),
            v.diag,
            "accept vector {}: diagnostic-notation drift",
            v.name
        );
    }
}

#[test]
fn reject_vectors_fire_the_named_check() {
    let m = manifest();
    for v in reject_vectors(&m) {
        let bytes = unhex(&v.name, &v.hex);
        let err = match decode(&bytes) {
            Err(e) => e,
            Ok(value) => panic!("reject vector {}: decoder accepted it as {value}", v.name),
        };
        assert_eq!(
            err.check(),
            v.check,
            "reject vector {}: wrong check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "reject vector {}: wrong class ({err})",
            v.name
        );
    }
}

#[test]
fn reject_vector_class_matches_the_check_lists() {
    let m = manifest();
    for v in reject_vectors(&m) {
        let expected = if TrustViolation::CHECKS.contains(&v.check.as_str()) {
            "trust"
        } else if Malformed::CHECKS.contains(&v.check.as_str()) {
            "malformed"
        } else {
            panic!(
                "reject vector {}: check {} is on neither list",
                v.name, v.check
            )
        };
        assert_eq!(
            v.class, expected,
            "reject vector {}: class must match the list its check lives in",
            v.name
        );
    }
}

#[test]
fn unknown_field_vectors_round_trip_byte_stable() {
    let m = manifest();
    for v in unknown_vectors(&m) {
        let bytes = unhex(&v.name, &v.hex);
        let (known, unknown) =
            decode_map_partial(&bytes, |k| v.known_keys.iter().any(|kk| kk == k)).unwrap_or_else(
                |e| {
                    panic!(
                        "unknown-field vector {}: decode_map_partial failed: {e}",
                        v.name
                    )
                },
            );
        assert_eq!(
            unknown.len(),
            v.expect_unknown_count,
            "unknown-field vector {}: unknown count",
            v.name
        );
        // The known/unknown split must be exhaustive over the map.
        let full = decode(&bytes).expect("vector decodes as a full strict item");
        assert_eq!(
            known.len() + unknown.len(),
            full.as_map().expect("top-level map").len(),
            "unknown-field vector {}: split must cover every entry",
            v.name
        );
        let reencoded = encode_map_partial(&known, &unknown).unwrap_or_else(|e| {
            panic!(
                "unknown-field vector {}: encode_map_partial failed: {e}",
                v.name
            )
        });
        assert_eq!(
            hex::encode(reencoded),
            v.hex,
            "unknown-field vector {}: rewrite must be byte-stable",
            v.name
        );
    }
}

#[test]
fn structure_tags_and_kdf_edges_sections_exist_and_are_empty() {
    // Present-and-empty by design: later spine slices land the structure-tag
    // registry and the KDF edge catalog here, replacing this assertion with
    // their completeness checks.
    let m = manifest();
    assert!(
        m.structure_tags.is_empty(),
        "structureTags gains entries only with its completeness machinery"
    );
    assert!(
        m.kdf_edges.is_empty(),
        "kdfEdges gains entries only with its completeness machinery"
    );
}
