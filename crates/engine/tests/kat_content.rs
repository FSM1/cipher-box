//! The engine's content-DAG KAT suite — the sibling of core's manifest sweep
//! (#820 §5). Core's sweep is core-scoped by construction: it enumerates core's
//! error surface and cannot regenerate engine-produced bytes.
//!
//! Fixtures are embedded at compile time, so the suite never depends on the
//! working directory. `crates/engine/kat` is written only by
//! `cargo run -p cipherbox-engine --example kat_gen`; CI diffs the regenerated
//! tree, so a format change that is not a deliberate re-freeze fails there.

use std::collections::BTreeSet;

use cipherbox_core::codec::{Value, decode};
use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str, verify_cid};
use cipherbox_engine::content::{
    ContentProfile, DAG_ROOT_CODEC, DagError, ROOT_FORMAT_VERSION, assemble, decode_root,
};
use serde::Deserialize;

const MANIFEST: &str = include_str!("../kat/manifest.json");

/// Every vector file the manifest may reference. Path keys are
/// manifest-relative (relative to `kat/`).
const FIXTURES: &[(&str, &str)] = &[
    (
        "vectors/content/dag_root_accept.json",
        include_str!("../kat/vectors/content/dag_root_accept.json"),
    ),
    (
        "vectors/content/dag_root_reject.json",
        include_str!("../kat/vectors/content/dag_root_reject.json"),
    ),
    (
        "vectors/content/dag_capacity_accept.json",
        include_str!("../kat/vectors/content/dag_capacity_accept.json"),
    ),
    (
        "vectors/content/dag_capacity_reject.json",
        include_str!("../kat/vectors/content/dag_capacity_reject.json"),
    ),
];

// deny_unknown_fields: a field the schema does not know is a manifest drift,
// not a tolerance.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    manifest_version: u64,
    profile: String,
    content: ContentSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentSection {
    root_format_version: u64,
    root_cid_codec: u8,
    production_chunk_size: u64,
    dag_root_accept: FileCount,
    dag_root_reject: RejectSection,
    dag_capacity_accept: FileCount,
    dag_capacity_reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileCount {
    file: String,
    count: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RejectSection {
    file: String,
    count: usize,
    checks: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DagRootAcceptVector {
    name: String,
    chunk_size: u64,
    size: u64,
    leaf_cids: Vec<String>,
    root_block: String,
    content_cid: String,
    content_cid_str: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DagRootRejectVector {
    name: String,
    root_block: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DagCapacityAcceptVector {
    name: String,
    chunk_size: u64,
    leaf_count: u64,
    size: u64,
    root_block_len: usize,
    content_cid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DagCapacityRejectVector {
    name: String,
    chunk_size: u64,
    leaf_count: u64,
    size: u64,
    check: String,
    class: String,
}

/// The DAG check surface, restated independently of the code under test —
/// core's manifest sweep uses the same kind of anchor. Without it, dropping a
/// variant, its `check()` arm, its `CHECKS` entry and its vector in one commit
/// would leave every gate green.
const DAG_CHECKS: &[&str] = &[
    "dag-unsupported-format",
    "dag-zero-chunk-size",
    "dag-malformed-leaf-cid",
    "dag-link-count-mismatch",
    "dag-root-too-large",
];

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

fn root_accept_vectors(m: &Manifest) -> Vec<DagRootAcceptVector> {
    serde_json::from_str(fixture(&m.content.dag_root_accept.file)).expect("accept vector shape")
}

fn root_reject_vectors(m: &Manifest) -> Vec<DagRootRejectVector> {
    serde_json::from_str(fixture(&m.content.dag_root_reject.file)).expect("reject vector shape")
}

fn capacity_accept_vectors(m: &Manifest) -> Vec<DagCapacityAcceptVector> {
    serde_json::from_str(fixture(&m.content.dag_capacity_accept.file)).expect("capacity accept")
}

fn capacity_reject_vectors(m: &Manifest) -> Vec<DagCapacityRejectVector> {
    serde_json::from_str(fixture(&m.content.dag_capacity_reject.file)).expect("capacity reject")
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("vector bytes are lowercase hex")
}

fn profile_of(chunk_size: u64) -> ContentProfile {
    ContentProfile::new(chunk_size as usize).expect("a vector's chunk size is nonzero")
}

/// A capacity vector's synthetic links: the `raw` content CID of the big-endian
/// link index, the rule the generator froze the root CID under.
fn capacity_leaves(count: u64) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| compute_cid(CONTENT_CID_CODEC, &i.to_be_bytes()))
        .collect()
}

#[test]
fn manifest_header_pins_the_frozen_content_format() {
    let m = manifest();
    assert_eq!(m.manifest_version, 1);
    assert_eq!(m.profile, "cipherbox/v2 engine content-dag");
    assert_eq!(m.content.root_format_version, ROOT_FORMAT_VERSION);
    assert_eq!(m.content.root_cid_codec, DAG_ROOT_CODEC);
    assert_eq!(
        m.content.production_chunk_size,
        ContentProfile::PRODUCTION.chunk_size() as u64,
        "the manifest and the shipped profile freeze the same chunk size"
    );
}

#[test]
fn fixture_table_matches_manifest_files() {
    let m = manifest();
    let referenced: BTreeSet<&str> = [
        m.content.dag_root_accept.file.as_str(),
        m.content.dag_root_reject.file.as_str(),
        m.content.dag_capacity_accept.file.as_str(),
        m.content.dag_capacity_reject.file.as_str(),
    ]
    .into_iter()
    .collect();
    let embedded: BTreeSet<&str> = FIXTURES.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        referenced, embedded,
        "every embedded fixture is referenced and every reference is embedded"
    );
}

#[test]
fn vector_counts_are_exact() {
    let m = manifest();
    assert_eq!(
        root_accept_vectors(&m).len(),
        m.content.dag_root_accept.count
    );
    assert_eq!(
        root_reject_vectors(&m).len(),
        m.content.dag_root_reject.count
    );
    assert_eq!(
        capacity_accept_vectors(&m).len(),
        m.content.dag_capacity_accept.count
    );
    assert_eq!(
        capacity_reject_vectors(&m).len(),
        m.content.dag_capacity_reject.count
    );
}

#[test]
fn vector_names_are_unique_within_each_file() {
    let m = manifest();
    let mut names = BTreeSet::new();
    for name in root_accept_vectors(&m).iter().map(|v| v.name.clone()) {
        assert!(names.insert(name.clone()), "duplicate accept vector {name}");
    }
    names.clear();
    for name in root_reject_vectors(&m).iter().map(|v| v.name.clone()) {
        assert!(names.insert(name.clone()), "duplicate reject vector {name}");
    }
    names.clear();
    for name in capacity_accept_vectors(&m).iter().map(|v| v.name.clone()) {
        assert!(
            names.insert(name.clone()),
            "duplicate capacity-accept vector {name}"
        );
    }
    names.clear();
    for name in capacity_reject_vectors(&m).iter().map(|v| v.name.clone()) {
        assert!(
            names.insert(name.clone()),
            "duplicate capacity-reject vector {name}"
        );
    }
}

#[test]
fn accept_vectors_reproduce_the_frozen_root_bytes() {
    let m = manifest();
    for v in root_accept_vectors(&m) {
        let leaf_cids: Vec<Vec<u8>> = v.leaf_cids.iter().map(|c| unhex(c)).collect();
        let dag = assemble(&leaf_cids, v.size, &profile_of(v.chunk_size))
            .unwrap_or_else(|e| panic!("{}: accept vector must assemble, got {e:?}", v.name));

        assert_eq!(
            dag.root_block,
            unhex(&v.root_block),
            "{}: root bytes",
            v.name
        );
        assert_eq!(dag.content_cid, unhex(&v.content_cid), "{}: cid", v.name);
        assert_eq!(
            encode_content_cid_str(&dag.content_cid),
            v.content_cid_str,
            "{}: cid string",
            v.name
        );
        assert!(
            verify_cid(&dag.content_cid, &dag.root_block).is_ok(),
            "{}: the root addresses its own bytes",
            v.name
        );

        let decoded = decode_root(&dag.root_block)
            .unwrap_or_else(|e| panic!("{}: own root must decode, got {e:?}", v.name));
        assert_eq!(decoded.chunk_size, v.chunk_size, "{}: chunk size", v.name);
        assert_eq!(decoded.size, v.size, "{}: size", v.name);
        let links: Vec<Vec<u8>> = decoded.leaf_cids.iter().map(|cid| cid.to_vec()).collect();
        assert_eq!(links, leaf_cids, "{}: link order", v.name);
    }
}

#[test]
fn every_accept_vector_carries_the_frozen_format_version() {
    let m = manifest();
    for v in root_accept_vectors(&m) {
        let root = decode(&unhex(&v.root_block)).expect("a frozen root is valid det-CBOR");
        assert_eq!(
            root.as_map().expect("root is a map").get("v"),
            Some(&Value::Unsigned(ROOT_FORMAT_VERSION)),
            "{}: the discriminator is in the published bytes",
            v.name
        );
    }
}

#[test]
fn every_accept_vector_frames_at_the_production_chunk_size() {
    let m = manifest();
    let production = ContentProfile::PRODUCTION.chunk_size() as u64;
    for v in root_accept_vectors(&m) {
        assert_eq!(
            v.chunk_size, production,
            "{}: the freeze is only real at production framing",
            v.name
        );
    }
}

#[test]
fn reject_vectors_fail_closed_with_the_named_verdict() {
    let m = manifest();
    for v in root_reject_vectors(&m) {
        let error = decode_root(&unhex(&v.root_block))
            .map(|ok| panic!("{}: reject vector decoded to {ok:?}", v.name))
            .unwrap_err();
        assert_eq!(error.check(), v.check, "{}: check", v.name);
        assert_eq!(error.class(), v.class, "{}: class", v.name);
    }
}

#[test]
fn an_unreadable_format_version_is_never_a_trust_verdict() {
    let m = manifest();
    let unsupported: Vec<DagRootRejectVector> = root_reject_vectors(&m)
        .into_iter()
        .filter(|v| v.check == "dag-unsupported-format")
        .collect();
    assert!(
        !unsupported.is_empty(),
        "the format discriminator must be reject-pinned"
    );
    for v in unsupported {
        let error = decode_root(&unhex(&v.root_block)).expect_err("must fail closed");
        assert_eq!(
            error.class(),
            "unsupported",
            "{}: an out-of-date client is not a forged record (#820)",
            v.name
        );
    }
}

#[test]
fn the_flat_dag_ceiling_assembles_and_stays_readable() {
    let m = manifest();
    for v in capacity_accept_vectors(&m) {
        let leaves = capacity_leaves(v.leaf_count);
        let dag = assemble(&leaves, v.size, &profile_of(v.chunk_size))
            .unwrap_or_else(|e| panic!("{}: the ceiling must assemble, got {e:?}", v.name));
        assert_eq!(dag.root_block.len(), v.root_block_len, "{}: size", v.name);
        assert_eq!(dag.content_cid, unhex(&v.content_cid), "{}: cid", v.name);
        assert_eq!(
            decode_root(&dag.root_block)
                .unwrap_or_else(|e| panic!("{}: ceiling root must decode, got {e:?}", v.name))
                .leaf_cids
                .len() as u64,
            v.leaf_count,
            "{}: every link survives the round trip",
            v.name
        );
    }
}

#[test]
fn one_link_past_the_ceiling_fails_closed_at_assemble() {
    let m = manifest();
    for v in capacity_reject_vectors(&m) {
        let leaves = capacity_leaves(v.leaf_count);
        let error = assemble(&leaves, v.size, &profile_of(v.chunk_size))
            .map(|ok| panic!("{}: over-ceiling assembled to {ok:?}", v.name))
            .unwrap_err();
        assert_eq!(error.check(), v.check, "{}: check", v.name);
        assert_eq!(error.class(), v.class, "{}: class", v.name);
    }
}

#[test]
fn reject_checks_lists_match_their_vectors_and_the_error_surface() {
    let m = manifest();
    for (listed, present) in [
        (
            &m.content.dag_root_reject.checks,
            root_reject_vectors(&m)
                .into_iter()
                .map(|v| v.check)
                .collect::<BTreeSet<_>>(),
        ),
        (
            &m.content.dag_capacity_reject.checks,
            capacity_reject_vectors(&m)
                .into_iter()
                .map(|v| v.check)
                .collect::<BTreeSet<_>>(),
        ),
    ] {
        let expected: Vec<String> = DagError::CHECKS
            .iter()
            .filter(|c| present.contains(**c))
            .map(|c| (*c).to_string())
            .collect();
        assert_eq!(
            *listed, expected,
            "a manifest checks list is the vectors' distinct checks in surface order"
        );
    }
}

/// The engine sweep: no DAG fail-closed check ships unpinned.
#[test]
fn every_dag_check_is_pinned_by_a_vector_family() {
    let m = manifest();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    covered.extend(root_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(capacity_reject_vectors(&m).into_iter().map(|v| v.check));

    assert_eq!(
        DagError::CHECKS,
        DAG_CHECKS,
        "the shipped surface must match this suite's independent anchor"
    );
    let surface: BTreeSet<String> = DAG_CHECKS.iter().map(|c| (*c).to_string()).collect();
    assert_eq!(
        surface.difference(&covered).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "every DAG check must have a reject vector"
    );
    assert!(
        covered.is_subset(&surface),
        "every reject-vector check must exist on the error surface"
    );
}
