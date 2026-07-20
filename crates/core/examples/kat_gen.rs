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
use serde::Serialize;
use serde_json::json;

const PROFILE: &str = "cipherbox/v2 det-cbor";

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    manifest_version: u64,
    profile: String,
    codecs: Codecs,
    structure_tags: serde_json::Value,
    kdf_edges: serde_json::Value,
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
    let codec_dir = kat_dir.join("vectors").join("codec");
    fs::create_dir_all(&codec_dir).expect("create kat/vectors/codec");

    let accept = build_accept_vectors();
    let reject = build_reject_vectors();
    let unknown = build_unknown_field_vectors();

    write_pretty(&codec_dir.join("accept.json"), &accept);
    write_pretty(&codec_dir.join("reject.json"), &reject);
    write_pretty(&codec_dir.join("unknown_fields.json"), &unknown);

    let manifest = build_manifest(&accept, &reject, &unknown);
    write_pretty(&kat_dir.join("manifest.json"), &manifest);

    println!(
        "kat_gen: wrote {} accept, {} reject, {} unknown-field vectors + manifest.json",
        accept.len(),
        reject.len(),
        unknown.len(),
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

    // Self-check the coverage law before writing anything: every decode-
    // reachable check is present; the only absentees are the two encode-/
    // schema-side checks pinned by unit tests in src/codec/fields.rs.
    let present: BTreeSet<&str> = out.iter().map(|v| v.check.as_str()).collect();
    let absent: Vec<&str> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .copied()
        .filter(|c| !present.contains(c))
        .collect();
    assert_eq!(
        absent,
        ["unexpected-type", "unknown-field-collision"],
        "reject vectors must cover every decode-reachable check"
    );
    out
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

fn build_manifest(
    accept: &[AcceptVector],
    reject: &[RejectVector],
    unknown: &[UnknownVector],
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

    // checks: the decode-reachable subset, in error-surface declaration order
    // (trust first, then malformed).
    let present: BTreeSet<&str> = reject.iter().map(|v| v.check.as_str()).collect();
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
                    checks,
                },
                unknown_fields: UnknownFieldsSection {
                    file: "vectors/codec/unknown_fields.json".to_string(),
                    count: unknown.len(),
                },
            },
        },
        structure_tags: json!({}),
        kdf_edges: json!({}),
    }
}
