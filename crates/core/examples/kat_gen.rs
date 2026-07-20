//! The committed KAT generator for the det-CBOR codec fixtures
//! (blueprint/core.md "KAT regime": vectors regenerate only through committed
//! generators, never hand-edits).
//!
//! Run from any cwd:
//!
//! ```text
//! cargo run -p cipherbox-core --example kat_gen
//! ```
//!
//! Accept and unknown-field vectors are built from [`Value`] constructors and
//! the live encoder. Reject vectors are explicit hand-crafted byte literals —
//! deriving them from the encoder would be vacuous, since the deterministic
//! encoder cannot emit any of them. Every vector is asserted against the live
//! codec before anything is written, so a generator run is itself a
//! self-check. Output is deterministic: re-running is byte-identical.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use cipherbox_core::codec::{
    MAX_DEPTH, Map, Value, decode, decode_map_partial, encode, encode_map_partial,
};
use cipherbox_core::error::{Malformed, TrustViolation};
use cipherbox_core::kdf::{self, EDGES, EdgeProbe};
use cipherbox_core::suite::contact::{ContactCode, import_contact_code};
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::hpke::{self, hpke_open, hpke_seal};
use cipherbox_core::suite::x25519::X25519Secret;
use serde::Serialize;
use serde_json::json;

const PROFILE: &str = "cipherbox/v2 det-cbor";

fn hexstr(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[derive(Serialize)]
struct AcceptVector {
    name: String,
    hex: String,
    diag: String,
    kinds: Vec<String>,
}

#[derive(Serialize)]
struct RejectVector {
    name: String,
    hex: String,
    check: String,
    class: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnknownVector {
    name: String,
    hex: String,
    known_keys: Vec<String>,
    expect_unknown_count: usize,
}

// --- KDF edge vectors -------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfEdgesFile {
    probe: ProbeJson,
    edges: Vec<EdgeVector>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeJson {
    seed: String,
    id: String,
    struct_tag: u8,
    index: u64,
    ipns_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EdgeVector {
    name: String,
    context: String,
    input_layout: String,
    output: String,
}

// --- HPKE vectors -----------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

// --- Contact code vectors ---------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContactAcceptVector {
    name: String,
    hex: String,
    identity_pk: String,
    enc_subkey: String,
    binding_sig: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    manifest_version: u64,
    profile: String,
    codecs: Codecs,
    structure_tags: serde_json::Value,
    kdf: KdfSection,
    suite: SuiteSection,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfSection {
    file: String,
    count: usize,
    edges: Vec<EdgeRow>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EdgeRow {
    name: String,
    context: String,
    input_layout: String,
}

#[derive(Serialize)]
struct SuiteSection {
    hpke: HpkeMeta,
    contact: ContactMeta,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HpkeMeta {
    kem_id: String,
    kdf_id: String,
    aead_id: String,
    seal_file: String,
    seal_count: usize,
    open_reject_file: String,
    open_reject_count: usize,
}

#[derive(Serialize)]
struct ContactMeta {
    accept: FileCount,
    reject: RejectSection,
}

#[derive(Serialize)]
struct FileCount {
    file: String,
    count: usize,
}

#[derive(Serialize)]
struct Codecs {
    #[serde(rename = "det-cbor")]
    det_cbor: DetCbor,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DetCbor {
    accept: AcceptSection,
    reject: RejectSection,
    unknown_fields: UnknownFieldsSection,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptSection {
    file: String,
    count: usize,
    required_kinds: Vec<String>,
}

#[derive(Serialize)]
struct RejectSection {
    file: String,
    count: usize,
    checks: Vec<String>,
}

#[derive(Serialize)]
struct UnknownFieldsSection {
    file: String,
    count: usize,
}

fn main() {
    let kat_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("kat");
    let vectors_dir = kat_dir.join("vectors");
    let codec_dir = vectors_dir.join("codec");
    let kdf_dir = vectors_dir.join("kdf");
    let hpke_dir = vectors_dir.join("hpke");
    let contact_dir = vectors_dir.join("contact");
    for dir in [&codec_dir, &kdf_dir, &hpke_dir, &contact_dir] {
        fs::create_dir_all(dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    }

    let accept = build_accept_vectors();
    let reject = build_reject_vectors();
    let unknown = build_unknown_field_vectors();

    write_pretty(&codec_dir.join("accept.json"), &accept);
    write_pretty(&codec_dir.join("reject.json"), &reject);
    write_pretty(&codec_dir.join("unknown_fields.json"), &unknown);

    let kdf_edges = build_kdf_edges();
    let hpke_seal = build_hpke_seal();
    let hpke_open_reject = build_hpke_open_reject();
    let contact_accept = build_contact_accept();
    let contact_reject = build_contact_reject();

    write_pretty(&kdf_dir.join("edges.json"), &kdf_edges);
    write_pretty(&hpke_dir.join("seal.json"), &hpke_seal);
    write_pretty(&hpke_dir.join("open_reject.json"), &hpke_open_reject);
    write_pretty(&contact_dir.join("accept.json"), &contact_accept);
    write_pretty(&contact_dir.join("reject.json"), &contact_reject);

    let manifest = build_manifest(
        &accept,
        &reject,
        &unknown,
        &kdf_edges,
        &hpke_seal,
        &hpke_open_reject,
        &contact_accept,
        &contact_reject,
    );
    write_pretty(&kat_dir.join("manifest.json"), &manifest);

    println!(
        "kat_gen: wrote {} accept, {} reject, {} unknown-field, {} kdf-edge, {} hpke-seal, \
         {} hpke-open-reject, {} contact-accept, {} contact-reject vectors + manifest.json",
        accept.len(),
        reject.len(),
        unknown.len(),
        kdf_edges.edges.len(),
        hpke_seal.len(),
        hpke_open_reject.len(),
        contact_accept.len(),
        contact_reject.len(),
    );
}

fn write_pretty<T: Serialize>(path: &Path, value: &T) {
    let mut text = serde_json::to_string_pretty(value).expect("serialize JSON");
    text.push('\n');
    fs::write(path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

// ---------------------------------------------------------------------------
// Accept vectors: built from Value constructors + the live encoder.
// ---------------------------------------------------------------------------

/// `levels` nested arrays, innermost empty: `nested_arrays(1)` is `[]`.
fn nested_arrays(levels: usize) -> Value {
    let mut v = Value::Array(Vec::new());
    for _ in 1..levels {
        v = Value::Array(vec![v]);
    }
    v
}

fn map_of(entries: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in entries {
        m.insert(k, v);
    }
    Value::Map(m)
}

fn accept_specs() -> Vec<(&'static str, Value, Vec<&'static str>)> {
    vec![
        // Unsigned boundaries: every argument-width class edge, both sides.
        ("uint-0", Value::Unsigned(0), vec!["uint"]),
        ("uint-23-max-immediate", Value::Unsigned(23), vec!["uint"]),
        ("uint-24-min-8bit", Value::Unsigned(24), vec!["uint"]),
        ("uint-255-max-8bit", Value::Unsigned(255), vec!["uint"]),
        ("uint-256-min-16bit", Value::Unsigned(256), vec!["uint"]),
        ("uint-65535-max-16bit", Value::Unsigned(65535), vec!["uint"]),
        ("uint-65536-min-32bit", Value::Unsigned(65536), vec!["uint"]),
        (
            "uint-4294967295-max-32bit",
            Value::Unsigned(4_294_967_295),
            vec!["uint"],
        ),
        (
            "uint-4294967296-min-64bit",
            Value::Unsigned(4_294_967_296),
            vec!["uint"],
        ),
        ("uint-u64-max", Value::Unsigned(u64::MAX), vec!["uint"]),
        // Negatives: Value::Negative(n) is -1 - n.
        ("negint-minus-1", Value::Negative(0), vec!["negint"]),
        (
            "negint-minus-24-max-immediate",
            Value::Negative(23),
            vec!["negint"],
        ),
        (
            "negint-minus-25-min-8bit",
            Value::Negative(24),
            vec!["negint"],
        ),
        // -2^64: below i64/i128::from(u64) territory on the wire, the full
        // major-1 range. Diag pins the arbitrary-precision rendering.
        (
            "negint-minus-2-pow-64",
            Value::Negative(u64::MAX),
            vec!["negint"],
        ),
        // Bytes: the 24-length one crosses into the 8-bit length header.
        ("bytes-empty", Value::Bytes(Vec::new()), vec!["bytes"]),
        (
            "bytes-short",
            Value::Bytes(vec![0x01, 0x02, 0x03]),
            vec!["bytes"],
        ),
        (
            "bytes-len-24-8bit-length-header",
            Value::Bytes((0u8..24).collect()),
            vec!["bytes"],
        ),
        // Text: empty, ascii, multibyte (UTF-8 length != char count), 24+.
        ("text-empty", Value::Text(String::new()), vec!["text"]),
        ("text-ascii", Value::Text("hello".into()), vec!["text"]),
        (
            "text-multibyte-unicode",
            Value::Text("héllo wörld — ✓🚀".into()),
            vec!["text"],
        ),
        (
            "text-len-26-8bit-length-header",
            Value::Text("abcdefghijklmnopqrstuvwxyz".into()),
            vec!["text"],
        ),
        // Arrays.
        ("array-empty", Value::Array(Vec::new()), vec!["array"]),
        (
            "array-nested",
            Value::Array(vec![
                Value::Unsigned(1),
                Value::Array(vec![
                    Value::Unsigned(2),
                    Value::Array(vec![Value::Unsigned(3)]),
                ]),
            ]),
            vec!["array"],
        ),
        (
            "array-heterogeneous",
            Value::Array(vec![
                Value::Unsigned(1),
                Value::Negative(1),
                Value::Bytes(vec![0xff]),
                Value::Text("mixed".into()),
                Value::Bool(true),
                Value::Null,
                Value::Array(Vec::new()),
                Value::Map(Map::new()),
            ]),
            vec!["array"],
        ),
        // Maps: canonical order is length-first, then bytewise — "a" and "b"
        // sort before "aa".
        ("map-empty", Value::Map(Map::new()), vec!["map"]),
        (
            "map-canonical-key-order-length-first",
            map_of(vec![
                ("aa", Value::Unsigned(3)),
                ("b", Value::Unsigned(2)),
                ("a", Value::Unsigned(1)),
            ]),
            vec!["map"],
        ),
        (
            "map-nested",
            map_of(vec![
                ("k", map_of(vec![("nested", Value::Bool(true))])),
                ("z", Value::Array(vec![Value::Null])),
            ]),
            vec!["map"],
        ),
        // Keys straddling the 23/24 length-header class boundary, in
        // canonical order (length-first: the 23-char key sorts before the
        // 24-char one whose header grows to 78 18). The reversed order is a
        // reject vector.
        (
            "map-keys-length-class-boundary",
            {
                let mut m = Map::new();
                m.insert("a".repeat(23), Value::Unsigned(0));
                m.insert("b".repeat(24), Value::Unsigned(1));
                Value::Map(m)
            },
            vec!["map"],
        ),
        // Simple values.
        ("bool-true", Value::Bool(true), vec!["bool"]),
        ("bool-false", Value::Bool(false), vec!["bool"]),
        ("null", Value::Null, vec!["null"]),
        // Exactly at the depth limit: the innermost (128th) array is read at
        // depth 127 < MAX_DEPTH. One level deeper is the depth-exceeded
        // reject vector.
        (
            "array-nested-at-depth-limit-128",
            nested_arrays(MAX_DEPTH),
            vec!["array", "depth-limit"],
        ),
    ]
}

fn build_accept_vectors() -> Vec<AcceptVector> {
    let specs = accept_specs();
    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(specs.len());
    for (name, value, kinds) in specs {
        assert!(names.insert(name), "duplicate accept vector name {name}");
        let bytes = encode(&value);
        let decoded = decode(&bytes)
            .unwrap_or_else(|e| panic!("accept vector {name}: live decoder rejected it: {e}"));
        assert_eq!(
            decoded, value,
            "accept vector {name}: decode != source value"
        );
        assert_eq!(
            encode(&decoded),
            bytes,
            "accept vector {name}: re-encode not byte-stable"
        );
        out.push(AcceptVector {
            name: name.to_string(),
            hex: hex::encode(&bytes),
            diag: value.to_string(),
            kinds: kinds.into_iter().map(str::to_string).collect(),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Reject vectors: explicit hand-crafted byte literals, one per decode-
// reachable check (several for the load-bearing ones), each asserted against
// the live decoder for the exact check + class.
// ---------------------------------------------------------------------------

fn reject_specs() -> Vec<(&'static str, String, &'static str, &'static str)> {
    let h = |s: &str| s.to_string();
    // MAX_DEPTH (128) array heads then an empty array: the 129th nesting
    // level would be read at depth 128, one past the limit.
    let depth_129 = "81".repeat(MAX_DEPTH) + "80";
    vec![
        // --- trust: non-canonical-uint ---------------------------------
        // 18 17 — uint 23 in 8-bit form; shortest form is the immediate 17.
        (
            "uint-23-in-8bit-form",
            h("1817"),
            "non-canonical-uint",
            "trust",
        ),
        // 19 00ff — uint 255 in 16-bit form; shortest is 18 ff.
        (
            "uint-255-in-16bit-form",
            h("1900ff"),
            "non-canonical-uint",
            "trust",
        ),
        // 1a 0000ffff — uint 65535 in 32-bit form; shortest is 19 ffff.
        (
            "uint-65535-in-32bit-form",
            h("1a0000ffff"),
            "non-canonical-uint",
            "trust",
        ),
        // 1b 00000000ffffffff — uint 4294967295 in 64-bit form.
        (
            "uint-4294967295-in-64bit-form",
            h("1b00000000ffffffff"),
            "non-canonical-uint",
            "trust",
        ),
        // 38 17 — negative -24 (major 1, arg 23) in 8-bit form; shortest is 37.
        (
            "negint-minus-24-in-8bit-form",
            h("3817"),
            "non-canonical-uint",
            "trust",
        ),
        // --- trust: non-canonical-length -------------------------------
        // 58 03 aa bb cc — 3-byte string with an 8-bit length header;
        // shortest is 43.
        (
            "bytes-len-3-in-8bit-form",
            h("5803aabbcc"),
            "non-canonical-length",
            "trust",
        ),
        // 78 01 61 — 1-char text with an 8-bit length header; shortest is 61.
        (
            "text-len-1-in-8bit-form",
            h("780161"),
            "non-canonical-length",
            "trust",
        ),
        // 98 03 01 02 03 — 3-element array with an 8-bit length header.
        (
            "array-len-3-in-8bit-form",
            h("9803010203"),
            "non-canonical-length",
            "trust",
        ),
        // b8 01 61 61 01 — 1-entry map {"a": 1} with an 8-bit length header.
        (
            "map-len-1-in-8bit-form",
            h("b801616101"),
            "non-canonical-length",
            "trust",
        ),
        // --- trust: indefinite-length -----------------------------------
        // 5f 41 aa ff — indefinite bytes, one 1-byte chunk, break.
        (
            "indefinite-bytes",
            h("5f41aaff"),
            "indefinite-length",
            "trust",
        ),
        // 7f 61 61 ff — indefinite text, one chunk "a", break.
        (
            "indefinite-text",
            h("7f6161ff"),
            "indefinite-length",
            "trust",
        ),
        // 9f 01 ff — indefinite array [1], break.
        (
            "indefinite-array",
            h("9f01ff"),
            "indefinite-length",
            "trust",
        ),
        // bf 61 61 01 ff — indefinite map {"a": 1}, break.
        (
            "indefinite-map",
            h("bf616101ff"),
            "indefinite-length",
            "trust",
        ),
        // --- trust: unsorted-map-keys -----------------------------------
        // a2 6162 01 6161 02 — {"b": 1, "a": 2}: bytewise order violation.
        (
            "map-keys-bytewise-out-of-order",
            h("a2616201616102"),
            "unsorted-map-keys",
            "trust",
        ),
        // a2 626161 01 6162 02 — {"aa": 1, "b": 2}: canonical text-key order
        // is length-first, so "b" must sort before "aa".
        (
            "map-keys-length-order-violation",
            h("a262616101616202"),
            "unsorted-map-keys",
            "trust",
        ),
        // --- trust: duplicate-map-key -----------------------------------
        // a2 6161 01 6161 02 — {"a": 1, "a": 2}.
        (
            "map-duplicate-key",
            h("a2616101616102"),
            "duplicate-map-key",
            "trust",
        ),
        // --- malformed: truncated ---------------------------------------
        // Zero bytes: no item at all.
        ("empty-input", h(""), "truncated", "malformed"),
        // 18 — uint head promising an 8-bit argument that never comes.
        (
            "uint-head-missing-argument",
            h("18"),
            "truncated",
            "malformed",
        ),
        // 44 aa bb — bytes head claiming 4 bytes, only 2 present.
        (
            "bytes-shorter-than-length",
            h("44aabb"),
            "truncated",
            "malformed",
        ),
        // 82 01 — array of 2 with only 1 element present.
        ("array-missing-element", h("8201"), "truncated", "malformed"),
        // --- malformed: trailing-bytes ----------------------------------
        // 01 00 — a complete item (1) followed by a stray byte.
        (
            "trailing-byte-after-item",
            h("0100"),
            "trailing-bytes",
            "malformed",
        ),
        // --- malformed: invalid-utf8 ------------------------------------
        // 62 ff fe — 2-byte text whose payload is not UTF-8.
        (
            "text-invalid-utf8",
            h("62fffe"),
            "invalid-utf8",
            "malformed",
        ),
        // --- malformed: invalid-map-key-type ----------------------------
        // a1 01 02 — {1: 2}: integer map key; the profile admits text only.
        (
            "map-key-unsigned",
            h("a10102"),
            "invalid-map-key-type",
            "malformed",
        ),
        // --- malformed: tag-forbidden -----------------------------------
        // d8 2a 45 0001020300… — tag 42 (a DAG-CBOR CID link) around bytes.
        // CID links are outside this profile; every tag rejects.
        (
            "tag-42-dag-cbor-cid-link",
            h("d82a4500010203aa"),
            "tag-forbidden",
            "malformed",
        ),
        // c0 00 — tag 0 (datetime) in immediate form.
        ("tag-0-datetime", h("c000"), "tag-forbidden", "malformed"),
        // --- malformed: float-forbidden ---------------------------------
        // f9 0014 — half-float whose bit pattern (0x0014) aliases simple
        // value 20 (false). A decoder dispatching on the decoded argument
        // instead of the additional info accepts this as `false` — a real
        // bug class in this decoder's history; must reject as a float.
        (
            "half-float-aliasing-simple-false",
            h("f90014"),
            "float-forbidden",
            "malformed",
        ),
        // fa 47c35000 — float32 100000.0.
        ("float32", h("fa47c35000"), "float-forbidden", "malformed"),
        // fb 3ff199999999999a — float64 1.1.
        (
            "float64",
            h("fb3ff199999999999a"),
            "float-forbidden",
            "malformed",
        ),
        // --- malformed: simple-value-forbidden --------------------------
        // f8 14 — simple value 20 in two-byte form. Must NOT alias `false`
        // (f4): only the immediate forms of false/true/null are admitted.
        (
            "two-byte-simple-20-not-false",
            h("f814"),
            "simple-value-forbidden",
            "malformed",
        ),
        // f7 — simple value 23 (undefined).
        (
            "simple-undefined",
            h("f7"),
            "simple-value-forbidden",
            "malformed",
        ),
        // f0 — simple value 16 (unassigned).
        (
            "simple-16-unassigned",
            h("f0"),
            "simple-value-forbidden",
            "malformed",
        ),
        // --- malformed: reserved-additional-info ------------------------
        // 1c — major 0 with additional info 28 (reserved everywhere).
        (
            "uint-ai-28-reserved",
            h("1c"),
            "reserved-additional-info",
            "malformed",
        ),
        // 1f — major 0 with additional info 31: indefinite length is not
        // defined for integers, so this is reserved, not indefinite-length.
        (
            "uint-ai-31-reserved",
            h("1f"),
            "reserved-additional-info",
            "malformed",
        ),
        // --- malformed: unexpected-break --------------------------------
        // ff — a break stop code with no indefinite-length item open.
        ("bare-break", h("ff"), "unexpected-break", "malformed"),
        // --- malformed: depth-exceeded ----------------------------------
        // 129 nested arrays: one past MAX_DEPTH (the 128-deep accept vector
        // is the other side of this edge).
        (
            "array-nesting-129-levels",
            depth_129,
            "depth-exceeded",
            "malformed",
        ),
        // --- crypto-review additions (PR #659 security review) ----------
        // f8 ff — two-byte simple value 255: well-formed CBOR (arg >= 32,
        // unassigned) yet profile-forbidden; f8 14 pins the ill-formed half.
        (
            "two-byte-simple-255",
            h("f8ff"),
            "simple-value-forbidden",
            "malformed",
        ),
        // a2 60 00 60 f4 — {"": 0, "": false}: duplicate empty-string key.
        (
            "map-duplicate-empty-key",
            h("a2600060f4"),
            "duplicate-map-key",
            "trust",
        ),
        // a3 6161 00 6162 01 6161 02 — {"a": 0, "b": 1, "a": 2}: a duplicate
        // separated by a middle key surfaces as an ordering violation, never
        // silently — pins the check-precedence choice.
        (
            "map-gap-duplicate-fires-unsorted",
            h("a3616100616201616102"),
            "unsorted-map-keys",
            "trust",
        ),
        // 5f ff / 7f ff — *empty* indefinite bytes/text (the other
        // indefinite vectors carry chunks).
        (
            "indefinite-bytes-empty",
            h("5fff"),
            "indefinite-length",
            "trust",
        ),
        (
            "indefinite-text-empty",
            h("7fff"),
            "indefinite-length",
            "trust",
        ),
        // dc — a tag head with reserved additional info 28: tag rejection
        // fires on the initial byte, before ai validation.
        (
            "tag-head-reserved-ai-precedence",
            h("dc"),
            "tag-forbidden",
            "malformed",
        ),
        // a1 78 01 61 f6 — {"a"(8-bit len): null}: non-shortest length on
        // the *key* path.
        (
            "map-key-len-1-in-8bit-form",
            h("a1780161f6"),
            "non-canonical-length",
            "trust",
        ),
        // The reversed order of the map-keys-length-class-boundary accept
        // vector: the 24-char key (header 78 18) before the 23-char key
        // (header 77) violates length-first order.
        (
            "map-keys-length-class-boundary-out-of-order",
            format!("a27818{}0177{}00", "62".repeat(24), "61".repeat(23)),
            "unsorted-map-keys",
            "trust",
        ),
    ]
}

fn build_reject_vectors() -> Vec<RejectVector> {
    let specs = reject_specs();
    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(specs.len());
    for (name, hex, check, class) in specs {
        assert!(names.insert(name), "duplicate reject vector name {name}");
        assert_eq!(
            hex,
            hex.to_lowercase(),
            "reject vector {name}: hex must be lowercase"
        );
        let bytes =
            hex::decode(&hex).unwrap_or_else(|e| panic!("reject vector {name}: bad hex: {e}"));
        let err = match decode(&bytes) {
            Err(e) => e,
            Ok(v) => panic!("reject vector {name}: decoder accepted it as {v}"),
        };
        assert_eq!(
            err.check(),
            check,
            "reject vector {name}: wrong check ({err})"
        );
        assert_eq!(
            err.class(),
            class,
            "reject vector {name}: wrong class ({err})"
        );
        out.push(RejectVector {
            name: name.to_string(),
            hex,
            check: check.to_string(),
            class: class.to_string(),
        });
    }

    // Self-check the codec coverage law before writing anything: these vectors
    // cover exactly the codec's decode-reachable checks. The codec's two
    // encode-/schema-side checks (unexpected-type, unknown-field-collision) are
    // unit-test-pinned in src/codec/fields.rs; the suite/kdf checks live in the
    // contact and hpke families, not here.
    let present: BTreeSet<&str> = out.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        present,
        codec_decode_reachable_checks(),
        "codec reject vectors must cover exactly the decode-reachable codec checks"
    );
    let surface: BTreeSet<&str> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .copied()
        .collect();
    assert!(
        present.is_subset(&surface),
        "every codec reject check must exist on the error surface"
    );
    out
}

/// The codec's decode-reachable checks, fixed here as the anti-vacuity anchor
/// for the codec reject family (mirrors kat_manifest.rs). Adding a codec check
/// without a vector, or a vector for a check outside this set, fails the
/// generator self-check.
fn codec_decode_reachable_checks() -> BTreeSet<&'static str> {
    [
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
    ]
    .into_iter()
    .collect()
}

// ---------------------------------------------------------------------------
// Unknown-field vectors: the single decode tolerance, byte-stable on rewrite.
// ---------------------------------------------------------------------------

fn unknown_field_specs() -> Vec<(&'static str, Value, Vec<&'static str>, usize)> {
    vec![
        (
            "all-known",
            map_of(vec![("a", Value::Unsigned(1)), ("b", Value::Unsigned(2))]),
            vec!["a", "b"],
            0,
        ),
        (
            "none-known",
            map_of(vec![("a", Value::Unsigned(1)), ("b", Value::Unsigned(2))]),
            vec![],
            2,
        ),
        // Canonical key order a, b, aa, zz — known and unknown interleave.
        (
            "interleaved-known-unknown",
            map_of(vec![
                ("a", Value::Unsigned(1)),
                ("b", Value::Bytes(vec![0xff])),
                ("aa", Value::Text("x".into())),
                ("zz", Value::Null),
            ]),
            vec!["a", "aa"],
            2,
        ),
        // The preserved unknown value is itself a nested map.
        (
            "unknown-value-nested-map",
            map_of(vec![
                ("id", Value::Unsigned(7)),
                (
                    "meta",
                    map_of(vec![
                        (
                            "x",
                            Value::Array(vec![Value::Unsigned(1), Value::Unsigned(2)]),
                        ),
                        ("y", Value::Text("z".into())),
                    ]),
                ),
            ]),
            vec!["id"],
            1,
        ),
        // The preserved unknown value is itself a nested array.
        (
            "unknown-value-nested-array",
            map_of(vec![
                ("k", Value::Bool(true)),
                (
                    "list",
                    Value::Array(vec![
                        Value::Unsigned(1),
                        Value::Array(vec![Value::Unsigned(2)]),
                        Value::Null,
                    ]),
                ),
            ]),
            vec!["k"],
            1,
        ),
        ("empty-map", Value::Map(Map::new()), vec![], 0),
    ]
}

fn build_unknown_field_vectors() -> Vec<UnknownVector> {
    let specs = unknown_field_specs();
    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(specs.len());
    for (name, value, known_keys, expect_unknown) in specs {
        assert!(
            names.insert(name),
            "duplicate unknown-field vector name {name}"
        );
        let bytes = encode(&value);
        let known_set: BTreeSet<&str> = known_keys.iter().copied().collect();
        let (known, unknown) = decode_map_partial(&bytes, |k| known_set.contains(k))
            .unwrap_or_else(|e| panic!("unknown-field vector {name}: decode failed: {e}"));
        assert_eq!(
            unknown.len(),
            expect_unknown,
            "unknown-field vector {name}: unknown count"
        );
        let total = value.as_map().expect("spec value is a map").len();
        assert_eq!(
            known.len() + unknown.len(),
            total,
            "unknown-field vector {name}: split must be exhaustive"
        );
        let reencoded = encode_map_partial(&known, &unknown)
            .unwrap_or_else(|e| panic!("unknown-field vector {name}: rewrite failed: {e}"));
        assert_eq!(
            reencoded, bytes,
            "unknown-field vector {name}: rewrite not byte-stable"
        );
        out.push(UnknownVector {
            name: name.to_string(),
            hex: hex::encode(&bytes),
            known_keys: known_keys.into_iter().map(str::to_string).collect(),
            expect_unknown_count: expect_unknown,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Manifest: every byte comes from this generator — header constants and
// counts/checks/requiredKinds from the generated data. The empty
// structureTags/kdfEdges sections are extended by extending this generator
// when those spine slices land, never by hand-editing the JSON.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_manifest(
    accept: &[AcceptVector],
    reject: &[RejectVector],
    unknown: &[UnknownVector],
    kdf_edges: &KdfEdgesFile,
    hpke_seal: &[HpkeSealVector],
    hpke_open_reject: &[HpkeOpenRejectVector],
    contact_accept: &[ContactAcceptVector],
    contact_reject: &[RejectVector],
) -> Manifest {
    // requiredKinds: distinct kinds in first-appearance order (deterministic).
    let mut required_kinds: Vec<String> = Vec::new();
    for v in accept {
        for k in &v.kinds {
            if !required_kinds.contains(k) {
                required_kinds.push(k.clone());
            }
        }
    }

    // The KDF catalog table is frozen from EDGES itself (single source).
    let edges: Vec<EdgeRow> = EDGES
        .iter()
        .map(|e| EdgeRow {
            name: e.name.to_string(),
            context: e.context.to_string(),
            input_layout: e.input_layout.to_string(),
        })
        .collect();

    Manifest {
        manifest_version: 1,
        profile: PROFILE.to_string(),
        codecs: Codecs {
            det_cbor: DetCbor {
                accept: AcceptSection {
                    file: "vectors/codec/accept.json".to_string(),
                    count: accept.len(),
                    required_kinds,
                },
                reject: RejectSection {
                    file: "vectors/codec/reject.json".to_string(),
                    count: reject.len(),
                    checks: checks_in_surface_order(reject),
                },
                unknown_fields: UnknownFieldsSection {
                    file: "vectors/codec/unknown_fields.json".to_string(),
                    count: unknown.len(),
                },
            },
        },
        structure_tags: json!({}),
        kdf: KdfSection {
            file: "vectors/kdf/edges.json".to_string(),
            count: kdf_edges.edges.len(),
            edges,
        },
        suite: SuiteSection {
            hpke: HpkeMeta {
                kem_id: "0x0020".to_string(),
                kdf_id: "0x0001".to_string(),
                aead_id: format!("0x{:04x}", hpke::AEAD_ID_XCHACHA),
                seal_file: "vectors/hpke/seal.json".to_string(),
                seal_count: hpke_seal.len(),
                open_reject_file: "vectors/hpke/open_reject.json".to_string(),
                open_reject_count: hpke_open_reject.len(),
            },
            contact: ContactMeta {
                accept: FileCount {
                    file: "vectors/contact/accept.json".to_string(),
                    count: contact_accept.len(),
                },
                reject: RejectSection {
                    file: "vectors/contact/reject.json".to_string(),
                    count: contact_reject.len(),
                    checks: checks_in_surface_order(contact_reject),
                },
            },
        },
    }
}

/// The distinct reject-vector checks, ordered trust-first then malformed to
/// match the error-surface declaration order. Asserts every check comes from
/// the surface.
fn checks_in_surface_order(vectors: &[RejectVector]) -> Vec<String> {
    let present: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    let checks: Vec<String> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .copied()
        .filter(|c| present.contains(c))
        .map(str::to_string)
        .collect();
    assert_eq!(
        checks.len(),
        present.len(),
        "every reject-vector check must come from the error surface"
    );
    checks
}

// ---------------------------------------------------------------------------
// KDF edge vectors: the whole catalog under one fixed probe. Frozen outputs
// pin every edge byte-for-byte (a BLAKE3 or dependency change would move them),
// and the separation self-check asserts no two edges collide.
// ---------------------------------------------------------------------------

fn build_kdf_edges() -> KdfEdgesFile {
    // Fixed probe inputs, frozen alongside the outputs.
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let id: [u8; 16] = std::array::from_fn(|i| (0x40 + i) as u8);
    let struct_tag = 0x01u8;
    let index = 0u64;
    let ipns_name = b"cipherbox/v2/scope-root".to_vec();

    let probe = EdgeProbe {
        seed: &seed,
        id: &id,
        struct_tag,
        index,
        ipns_name: &ipns_name,
    };
    let outputs = kdf::edge_probe_outputs(&probe);
    assert_eq!(outputs.len(), EDGES.len(), "probe must cover every edge");

    // Mechanical separation KAT: no two edges share an output for equal inputs.
    let distinct: BTreeSet<[u8; 32]> = outputs.iter().map(|o| o.output).collect();
    assert_eq!(
        distinct.len(),
        EDGES.len(),
        "two KDF edges produced equal output under uniform inputs"
    );

    let edges: Vec<EdgeVector> = outputs
        .iter()
        .zip(EDGES)
        .map(|(o, e)| {
            assert_eq!(o.name, e.name, "probe order must track EDGES order");
            EdgeVector {
                name: e.name.to_string(),
                context: e.context.to_string(),
                input_layout: e.input_layout.to_string(),
                output: hexstr(&o.output),
            }
        })
        .collect();

    KdfEdgesFile {
        probe: ProbeJson {
            seed: hexstr(&seed),
            id: hexstr(&id),
            struct_tag,
            index,
            ipns_name: hexstr(&ipns_name),
        },
        edges,
    }
}

// ---------------------------------------------------------------------------
// HPKE vectors: fixed-ephemeral seals (the eciesjs lesson — freeze enc + the
// whole ciphertext) plus open-reject cases pinning the fail-closed check.
// ---------------------------------------------------------------------------

/// A fixed HPKE seal case: name, ephemeral scalar, info, aad, plaintext.
type SealCase = (
    &'static str,
    [u8; 32],
    &'static [u8],
    &'static [u8],
    &'static [u8],
);

fn build_hpke_seal() -> Vec<HpkeSealVector> {
    let recipient_scalar: [u8; 32] = std::array::from_fn(|i| (0x10 + i) as u8);
    let recipient = X25519Secret::from_scalar(recipient_scalar);
    let recipient_public = recipient.public();

    let cases: Vec<SealCase> = vec![
        (
            "empty-info-empty-aad",
            std::array::from_fn(|i| (0x20 + i) as u8),
            b"",
            b"",
            b"grant blob payload",
        ),
        (
            "with-info-and-aad",
            std::array::from_fn(|i| (0x30 + i) as u8),
            b"cipherbox/v2 grant",
            b"scope-aad",
            b"read scope seed",
        ),
        (
            "empty-plaintext",
            std::array::from_fn(|i| (0x50 + i) as u8),
            b"info",
            b"aad",
            b"",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, eph, info, aad, pt) in cases {
        assert!(names.insert(name), "duplicate hpke seal vector {name}");
        let sealed = hpke_seal(&recipient_public, &eph, info, aad, pt);
        // Determinism under a fixed ephemeral scalar.
        assert_eq!(
            hpke_seal(&recipient_public, &eph, info, aad, pt),
            sealed,
            "hpke seal {name}: not deterministic"
        );
        // Round-trips.
        let opened = hpke_open(&recipient, &sealed.enc, info, aad, &sealed.ciphertext)
            .unwrap_or_else(|_| panic!("hpke seal {name}: open must recover plaintext"));
        assert_eq!(&opened[..], pt, "hpke seal {name}: plaintext mismatch");
        out.push(HpkeSealVector {
            name: name.to_string(),
            recipient_secret: hexstr(&recipient_scalar),
            recipient_public: hexstr(&recipient_public.to_bytes()),
            ephemeral_scalar: hexstr(&eph),
            info: hexstr(info),
            aad: hexstr(aad),
            plaintext: hexstr(pt),
            enc: hexstr(&sealed.enc),
            ciphertext: hexstr(&sealed.ciphertext),
        });
    }
    out
}

fn build_hpke_open_reject() -> Vec<HpkeOpenRejectVector> {
    let recipient_scalar: [u8; 32] = std::array::from_fn(|i| (0x10 + i) as u8);
    let recipient = X25519Secret::from_scalar(recipient_scalar);
    let eph: [u8; 32] = std::array::from_fn(|i| (0x60 + i) as u8);
    let info: &[u8] = b"info";
    let aad: &[u8] = b"aad";
    let sealed = hpke_seal(&recipient.public(), &eph, info, aad, b"open-me");
    assert!(
        hpke_open(&recipient, &sealed.enc, info, aad, &sealed.ciphertext).is_ok(),
        "baseline seal must open"
    );

    let mut tampered = sealed.ciphertext.clone();
    tampered[0] ^= 0x01;
    let cases: Vec<(&str, Vec<u8>, &[u8])> = vec![
        ("tampered-ciphertext", tampered, aad),
        ("wrong-aad", sealed.ciphertext.clone(), b"other-aad"),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, ct, open_aad) in cases {
        assert!(
            names.insert(name),
            "duplicate hpke open-reject vector {name}"
        );
        let err = hpke_open(&recipient, &sealed.enc, info, open_aad, &ct)
            .expect_err("open must fail closed");
        assert_eq!(err.check(), "hpke-open-failed", "hpke open-reject {name}");
        out.push(HpkeOpenRejectVector {
            name: name.to_string(),
            recipient_secret: hexstr(&recipient_scalar),
            enc: hexstr(&sealed.enc),
            info: hexstr(info),
            aad: hexstr(open_aad),
            ciphertext: hexstr(&ct),
            check: "hpke-open-failed".to_string(),
            class: "trust".to_string(),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Contact code vectors: valid codes that import, and every fail-closed reject —
// structural (malformed) and the mandatory binding verify (trust).
// ---------------------------------------------------------------------------

fn build_contact_accept() -> Vec<ContactAcceptVector> {
    let cases: Vec<(&str, [u8; 32], [u8; 32])> = vec![
        ("primary", [0x22; 32], [0x33; 32]),
        (
            "alt-keys",
            std::array::from_fn(|i| (i + 1) as u8),
            std::array::from_fn(|i| (0x80 + i) as u8),
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, id_scalar, enc_scalar) in cases {
        assert!(names.insert(name), "duplicate contact accept vector {name}");
        let signer = EcdsaSigner::from_scalar(&id_scalar).expect("valid identity scalar");
        let enc_public = X25519Secret::from_scalar(enc_scalar).public();
        let code = ContactCode::create(&signer, enc_public);
        let bytes = code.encode();
        // Self-check: imports, and re-encode is byte-stable.
        let imported = import_contact_code(&bytes).expect("accept vector must import");
        assert_eq!(
            imported.encode(),
            bytes,
            "contact accept {name}: not byte-stable"
        );
        out.push(ContactAcceptVector {
            name: name.to_string(),
            hex: hexstr(&bytes),
            identity_pk: hexstr(&code.identity_pk.to_sec1()),
            enc_subkey: hexstr(&code.enc_subkey.to_bytes()),
            binding_sig: hexstr(&code.binding_sig.to_compact()),
        });
    }
    out
}

fn build_contact_reject() -> Vec<RejectVector> {
    let signer = EcdsaSigner::from_scalar(&[0x22; 32]).expect("valid scalar");
    let good_id = signer.verifying_key().to_sec1().to_vec();
    let enc_public = X25519Secret::from_scalar([0x33; 32]).public();
    let good_enc = enc_public.to_bytes().to_vec();
    let good_sig = ContactCode::create(&signer, enc_public)
        .binding_sig
        .to_compact()
        .to_vec();

    // A structurally valid code whose enc subkey has been flipped: every field
    // parses, but the binding no longer matches.
    let mut tampered_enc = good_enc.clone();
    tampered_enc[0] ^= 0x01;

    let bytes_of = |identity: Option<Value>, enc: Option<Value>, sig: Option<Value>| -> Vec<u8> {
        let mut m = Map::new();
        if let Some(v) = sig {
            m.insert("bindingSig", v);
        }
        if let Some(v) = enc {
            m.insert("encSubkey", v);
        }
        if let Some(v) = identity {
            m.insert("identityPk", v);
        }
        encode(&Value::Map(m))
    };
    let b = |v: &[u8]| Value::Bytes(v.to_vec());

    let cases: Vec<(&str, Vec<u8>, &str, &str)> = vec![
        (
            "missing-binding-sig",
            bytes_of(Some(b(&good_id)), Some(b(&good_enc)), None),
            "missing-field",
            "malformed",
        ),
        (
            "identity-pk-wrong-type",
            bytes_of(
                Some(Value::Unsigned(1)),
                Some(b(&good_enc)),
                Some(b(&good_sig)),
            ),
            "unexpected-type",
            "malformed",
        ),
        (
            "identity-pk-not-on-curve",
            bytes_of(Some(b(&[0xff; 33])), Some(b(&good_enc)), Some(b(&good_sig))),
            "invalid-identity-key",
            "malformed",
        ),
        (
            "enc-subkey-wrong-length",
            bytes_of(Some(b(&good_id)), Some(b(&[0u8; 31])), Some(b(&good_sig))),
            "invalid-enc-subkey",
            "malformed",
        ),
        (
            "binding-sig-wrong-length",
            bytes_of(Some(b(&good_id)), Some(b(&good_enc)), Some(b(&[0u8; 63]))),
            "invalid-binding-sig-encoding",
            "malformed",
        ),
        (
            "binding-sig-all-zero",
            bytes_of(Some(b(&good_id)), Some(b(&good_enc)), Some(b(&[0u8; 64]))),
            "invalid-binding-sig-encoding",
            "malformed",
        ),
        (
            "binding-does-not-verify",
            bytes_of(
                Some(b(&good_id)),
                Some(b(&tampered_enc)),
                Some(b(&good_sig)),
            ),
            "subkey-binding-invalid",
            "trust",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, bytes, check, class) in cases {
        assert!(names.insert(name), "duplicate contact reject vector {name}");
        let err = match import_contact_code(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("contact reject {name}: import accepted it"),
        };
        assert_eq!(
            err.check(),
            check,
            "contact reject {name}: wrong check ({err})"
        );
        assert_eq!(
            err.class(),
            class,
            "contact reject {name}: wrong class ({err})"
        );
        out.push(RejectVector {
            name: name.to_string(),
            hex: hexstr(&bytes),
            check: check.to_string(),
            class: class.to_string(),
        });
    }
    out
}
