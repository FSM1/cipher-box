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
use cipherbox_core::kdf::{self, EDGES, EdgeProbe};
use cipherbox_core::suite::contact::import_contact_code;
use cipherbox_core::suite::hpke::{hpke_open, hpke_seal};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
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
    (
        "vectors/kdf/edges.json",
        include_str!("../kat/vectors/kdf/edges.json"),
    ),
    (
        "vectors/hpke/seal.json",
        include_str!("../kat/vectors/hpke/seal.json"),
    ),
    (
        "vectors/hpke/open_reject.json",
        include_str!("../kat/vectors/hpke/open_reject.json"),
    ),
    (
        "vectors/contact/accept.json",
        include_str!("../kat/vectors/contact/accept.json"),
    ),
    (
        "vectors/contact/reject.json",
        include_str!("../kat/vectors/contact/reject.json"),
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
    kdf: KdfSection,
    suite: SuiteSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KdfSection {
    file: String,
    count: usize,
    edges: Vec<EdgeRow>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EdgeRow {
    name: String,
    context: String,
    input_layout: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuiteSection {
    hpke: HpkeMeta,
    contact: ContactMeta,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HpkeMeta {
    kem_id: String,
    kdf_id: String,
    aead_id: String,
    seal_file: String,
    seal_count: usize,
    open_reject_file: String,
    open_reject_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactMeta {
    accept: FileCount,
    reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCount {
    file: String,
    count: usize,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KdfEdgesFile {
    probe: ProbeJson,
    edges: Vec<EdgeVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeJson {
    seed: String,
    id: String,
    struct_tag: u8,
    index: u64,
    ipns_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EdgeVector {
    name: String,
    context: String,
    input_layout: String,
    output: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HpkeSealVector {
    name: String,
    recipient_secret: String,
    recipient_public: String,
    ephemeral_scalar: String,
    info: String,
    aad: String,
    plaintext: String,
    enc: String,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HpkeOpenRejectVector {
    name: String,
    recipient_secret: String,
    enc: String,
    info: String,
    aad: String,
    ciphertext: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContactAcceptVector {
    name: String,
    hex: String,
    identity_pk: String,
    enc_subkey: String,
    binding_sig: String,
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

fn kdf_edges_file(m: &Manifest) -> KdfEdgesFile {
    serde_json::from_str(fixture(&m.kdf.file)).expect("kdf edges.json shape")
}

fn hpke_seal_vectors(m: &Manifest) -> Vec<HpkeSealVector> {
    serde_json::from_str(fixture(&m.suite.hpke.seal_file)).expect("hpke seal.json shape")
}

fn hpke_open_reject_vectors(m: &Manifest) -> Vec<HpkeOpenRejectVector> {
    serde_json::from_str(fixture(&m.suite.hpke.open_reject_file))
        .expect("hpke open_reject.json shape")
}

fn contact_accept_vectors(m: &Manifest) -> Vec<ContactAcceptVector> {
    serde_json::from_str(fixture(&m.suite.contact.accept.file)).expect("contact accept.json shape")
}

fn contact_reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.suite.contact.reject.file)).expect("contact reject.json shape")
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

fn unhex32(name: &str, hex: &str) -> [u8; 32] {
    unhex(name, hex)
        .try_into()
        .unwrap_or_else(|_| panic!("vector {name}: expected 32 bytes"))
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
        m.kdf.file.as_str(),
        m.suite.hpke.seal_file.as_str(),
        m.suite.hpke.open_reject_file.as_str(),
        m.suite.contact.accept.file.as_str(),
        m.suite.contact.reject.file.as_str(),
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

/// The codec's decode-reachable checks, fixed HERE as the anti-vacuity anchor
/// (mirrors kat_gen.rs). The suite/kdf checks live on the same error surface
/// but are pinned by the contact and hpke families, not the codec reject file.
const CODEC_DECODE_REACHABLE_CHECKS: &[&str] = &[
    "non-canonical-uint",
    "non-canonical-length",
    "indefinite-length",
    "unsorted-map-keys",
    "duplicate-map-key",
    "truncated",
    "trailing-bytes",
    "invalid-utf8",
    "invalid-map-key-type",
    "tag-forbidden",
    "float-forbidden",
    "simple-value-forbidden",
    "reserved-additional-info",
    "unexpected-break",
    "depth-exceeded",
];

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

    // The codec reject family covers exactly the decode-reachable codec checks
    // — fixed above, independent of the generator.
    let canonical: BTreeSet<&str> = CODEC_DECODE_REACHABLE_CHECKS.iter().copied().collect();
    assert_eq!(
        listed, canonical,
        "codec reject vectors must cover exactly the decode-reachable codec checks"
    );

    let surface: BTreeSet<&str> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .copied()
        .collect();
    assert!(
        listed.is_subset(&surface),
        "every codec reject check must exist on the error surface"
    );
    // Every codec trust check is decode-reachable, hence vector-covered here.
    for check in [
        "non-canonical-uint",
        "non-canonical-length",
        "indefinite-length",
        "unsorted-map-keys",
        "duplicate-map-key",
    ] {
        assert!(listed.contains(check), "missing codec trust check {check}");
    }
}

/// The whole error surface is vector-pinned save the one check `decode` and the
/// suite decoders can never emit: `unknown-field-collision` (an
/// `encode_map_partial` caller bug), which stays unit-test-pinned in
/// src/codec/fields.rs. This is the crate-wide extension of the reject-coverage
/// law across the codec, contact, and hpke families.
#[test]
fn every_crate_check_is_pinned_by_a_vector_family() {
    let m = manifest();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    covered.extend(reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(contact_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(hpke_open_reject_vectors(&m).into_iter().map(|v| v.check));

    let surface: BTreeSet<String> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .map(|s| s.to_string())
        .collect();
    let uncovered: Vec<&String> = surface.difference(&covered).collect();
    let expected_uncovered = "unknown-field-collision".to_string();
    assert_eq!(
        uncovered,
        vec![&expected_uncovered],
        "every crate check but the one unit-pinned collision check must have a reject vector"
    );
    assert!(
        covered.is_subset(&surface),
        "every reject-vector check must exist on the error surface"
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
fn structure_tags_section_exists_and_is_empty() {
    // Present-and-empty by design: the structure-tag registry lands with the
    // seal/structure-signature slice, replacing this with its completeness
    // check. (The KDF catalog is no longer empty — see the kdf_* tests.)
    let m = manifest();
    assert!(
        m.structure_tags.is_empty(),
        "structureTags gains entries only with its completeness machinery"
    );
}

// ---------------------------------------------------------------------------
// KDF edge catalog: the fourteen frozen edges, their contexts + layouts, the
// per-edge output freeze, and the mechanical separation KAT.
// ---------------------------------------------------------------------------

/// The canonical edge-name list, fixed HERE independent of the crate's `EDGES`
/// const and the generator — the anti-vacuity anchor for the catalog (mirrors
/// how ALL_KINDS anchors the accept side). Dropping or renaming an edge must
/// fail a test, never silently shrink the catalog.
const ALL_EDGE_NAMES: &[&str] = &[
    "node-seed",
    "read-key",
    "structure-key",
    "write-seed",
    "write-key",
    "ipns-keypair",
    "ascent-keypair",
    "enc-subkey",
    "blinded-tag",
    "pseudonym-sign",
    "owner-pointer-seed",
    "scope-pointer",
    "pointer-read-key",
    "vault-pointer-index",
];

#[test]
fn kdf_catalog_freezes_names_contexts_and_layouts() {
    let m = manifest();
    assert_eq!(m.kdf.count, ALL_EDGE_NAMES.len(), "kdf edge count drift");
    assert_eq!(m.kdf.edges.len(), m.kdf.count, "kdf edges list vs count");
    assert_eq!(EDGES.len(), ALL_EDGE_NAMES.len(), "crate EDGES count drift");

    let file = kdf_edges_file(&m);
    assert_eq!(file.edges.len(), m.kdf.count, "edges.json count drift");

    // Manifest rows, the crate EDGES const, the fixture rows, and the canonical
    // name list must all agree, edge by edge and in order.
    for (i, name) in ALL_EDGE_NAMES.iter().enumerate() {
        let expected_ctx = format!("cipherbox/v2/{name}");
        let man = &m.kdf.edges[i];
        let crate_edge = &EDGES[i];
        let fix = &file.edges[i];

        assert_eq!(man.name, *name, "manifest edge {i} name");
        assert_eq!(man.context, expected_ctx, "manifest edge {name} context");
        assert_eq!(crate_edge.name, *name, "crate EDGES {i} name");
        assert_eq!(
            crate_edge.context, expected_ctx,
            "crate EDGES {name} context"
        );
        assert_eq!(
            crate_edge.input_layout, man.input_layout,
            "layout drift {name}"
        );
        assert_eq!(fix.name, *name, "fixture edge {i} name");
        assert_eq!(fix.context, expected_ctx, "fixture edge {name} context");
        assert_eq!(
            fix.input_layout, man.input_layout,
            "fixture layout drift {name}"
        );
    }
}

#[test]
fn kdf_edge_outputs_are_frozen_and_pairwise_separated() {
    let m = manifest();
    let file = kdf_edges_file(&m);

    // Recompute every edge under the fixture's own probe inputs and check the
    // frozen output byte-for-byte — a BLAKE3 or dependency change moves these.
    let seed = unhex32("probe.seed", &file.probe.seed);
    let id: [u8; 16] = unhex("probe.id", &file.probe.id)
        .try_into()
        .expect("probe id is 16 bytes");
    let ipns_name = unhex("probe.ipnsName", &file.probe.ipns_name);
    let probe = EdgeProbe {
        seed: &seed,
        id: &id,
        struct_tag: file.probe.struct_tag,
        index: file.probe.index,
        ipns_name: &ipns_name,
    };
    let computed = kdf::edge_probe_outputs(&probe);
    assert_eq!(computed.len(), file.edges.len());
    for (c, f) in computed.iter().zip(&file.edges) {
        assert_eq!(c.name, f.name, "probe/fixture order mismatch");
        assert_eq!(
            hex::encode(c.output),
            f.output,
            "kdf edge {} output drift",
            f.name
        );
    }

    // Mechanical separation KAT over the whole table: no two edges share an
    // output for equal inputs.
    let outputs: BTreeSet<&str> = file.edges.iter().map(|e| e.output.as_str()).collect();
    assert_eq!(
        outputs.len(),
        file.edges.len(),
        "two KDF edges froze to the same output"
    );
}

// ---------------------------------------------------------------------------
// HPKE: the fixed-ephemeral full-envelope KAT and the fail-closed open rejects.
// ---------------------------------------------------------------------------

#[test]
fn hpke_suite_ids_are_frozen() {
    let m = manifest();
    assert_eq!(
        m.suite.hpke.kem_id, "0x0020",
        "KEM = DHKEM(X25519, HKDF-SHA256)"
    );
    assert_eq!(m.suite.hpke.kdf_id, "0x0001", "KDF = HKDF-SHA256");
    assert_eq!(
        m.suite.hpke.aead_id, "0x8000",
        "AEAD = XChaCha20-Poly1305, CipherBox private-use id"
    );
}

#[test]
fn hpke_seal_vectors_are_frozen_and_open() {
    let m = manifest();
    let vectors = hpke_seal_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.suite.hpke.seal_count,
        "hpke seal count drift"
    );
    assert!(!vectors.is_empty(), "hpke seal family must not be empty");

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate hpke seal {}",
            v.name
        );
        let recipient_public = X25519Public::from_bytes(unhex32(&v.name, &v.recipient_public));
        let eph = unhex32(&v.name, &v.ephemeral_scalar);
        let info = unhex(&v.name, &v.info);
        let aad = unhex(&v.name, &v.aad);
        let plaintext = unhex(&v.name, &v.plaintext);

        // Fixed-ephemeral seal must reproduce the frozen enc + ciphertext.
        let sealed = hpke_seal(&recipient_public, &eph, &info, &aad, &plaintext);
        assert_eq!(
            hex::encode(sealed.enc),
            v.enc,
            "hpke seal {}: enc drift",
            v.name
        );
        assert_eq!(
            hex::encode(&sealed.ciphertext),
            v.ciphertext,
            "hpke seal {}: ciphertext drift",
            v.name
        );

        // And the recipient must recover the plaintext.
        let recipient = X25519Secret::from_scalar(unhex32(&v.name, &v.recipient_secret));
        let enc = unhex32(&v.name, &v.enc);
        let opened = hpke_open(
            &recipient,
            &enc,
            &info,
            &aad,
            &unhex(&v.name, &v.ciphertext),
        )
        .unwrap_or_else(|_| panic!("hpke seal {}: open must recover plaintext", v.name));
        assert_eq!(
            &opened[..],
            &plaintext[..],
            "hpke seal {}: plaintext",
            v.name
        );
    }
}

#[test]
fn hpke_open_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = hpke_open_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.suite.hpke.open_reject_count,
        "hpke open-reject count drift"
    );
    assert!(
        !vectors.is_empty(),
        "hpke open-reject family must not be empty"
    );

    for v in &vectors {
        assert_eq!(v.check, "hpke-open-failed", "open-reject {}: check", v.name);
        assert_eq!(v.class, "trust", "open-reject {}: class", v.name);
        let recipient = X25519Secret::from_scalar(unhex32(&v.name, &v.recipient_secret));
        let enc = unhex32(&v.name, &v.enc);
        let err = hpke_open(
            &recipient,
            &enc,
            &unhex(&v.name, &v.info),
            &unhex(&v.name, &v.aad),
            &unhex(&v.name, &v.ciphertext),
        )
        .expect_err("open-reject vector must fail closed");
        assert_eq!(err.check(), "hpke-open-failed", "open-reject {}", v.name);
    }
}

// ---------------------------------------------------------------------------
// Contact codes: accept vectors import + round-trip; reject vectors pin the
// structural checks and the mandatory fail-closed binding verify.
// ---------------------------------------------------------------------------

#[test]
fn contact_accept_vectors_import_and_round_trip() {
    let m = manifest();
    let vectors = contact_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.suite.contact.accept.count,
        "contact accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "contact accept family must not be empty"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate contact accept {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.hex);
        let code = import_contact_code(&bytes)
            .unwrap_or_else(|e| panic!("contact accept {}: must import: {e}", v.name));
        // Re-encode is byte-stable, and the components match the vector.
        assert_eq!(
            hex::encode(code.encode()),
            v.hex,
            "contact accept {}: rewrite",
            v.name
        );
        assert_eq!(
            hex::encode(code.identity_pk.to_sec1()),
            v.identity_pk,
            "contact accept {}: identityPk",
            v.name
        );
        assert_eq!(
            hex::encode(code.enc_subkey.to_bytes()),
            v.enc_subkey,
            "contact accept {}: encSubkey",
            v.name
        );
        assert_eq!(
            hex::encode(code.binding_sig.to_compact()),
            v.binding_sig,
            "contact accept {}: bindingSig",
            v.name
        );
    }
}

#[test]
fn contact_reject_vectors_fire_the_named_check_and_class() {
    let m = manifest();
    let vectors = contact_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.suite.contact.reject.count,
        "contact reject count drift"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate contact reject {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.hex);
        let err = match import_contact_code(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("contact reject {}: import accepted it", v.name),
        };
        assert_eq!(err.check(), v.check, "contact reject {}: check", v.name);
        assert_eq!(err.class(), v.class, "contact reject {}: class", v.name);
    }
}

#[test]
fn contact_reject_family_covers_the_binding_checks() {
    let m = manifest();
    // The manifest checks list is exactly the distinct checks in the file...
    let listed: BTreeSet<&str> = m
        .suite
        .contact
        .reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        listed.len(),
        m.suite.contact.reject.checks.len(),
        "contact reject checks list must not contain duplicates"
    );
    let vectors = contact_reject_vectors(&m);
    let vector_checks: BTreeSet<String> = vectors.iter().map(|v| v.check.clone()).collect();
    let vector_checks_ref: BTreeSet<&str> = vector_checks.iter().map(String::as_str).collect();
    assert_eq!(
        listed, vector_checks_ref,
        "manifest checks vs contact reject.json"
    );

    // ...and it must include the mandatory binding-verify check plus every
    // structural contact check (anti-vacuity: fixed HERE).
    for required in [
        "subkey-binding-invalid",
        "missing-field",
        "invalid-identity-key",
        "invalid-enc-subkey",
        "invalid-binding-sig-encoding",
    ] {
        assert!(
            listed.contains(required),
            "contact rejects must cover {required}"
        );
    }
}
