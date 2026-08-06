//! The adoption gate's frozen stage-3 vectors: **one section, one signer**
//! (blueprint/engine.md "Adoption gate and floors").
//!
//! Sibling of the content-DAG suite and self-contained — its own manifest under
//! `kat/gate/`, since the gate freezes a trust predicate over whole scope-root
//! head blocks rather than a content format. `crates/engine/kat` is written only
//! by `cargo run -p cipherbox-engine --example kat_gen`; CI diffs the
//! regenerated tree, so a verdict change that is not a deliberate re-freeze
//! fails there.

use std::collections::BTreeSet;

use cipherbox_core::error::TrustViolation;
use cipherbox_core::seal::{decode_envelope, decode_grant_section, grant_section_bytes};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier};
use cipherbox_engine::gate::authenticate_section_structures;
use serde::Deserialize;

const MANIFEST: &str = include_str!("../kat/gate/manifest.json");

/// Every vector file the gate manifest may reference, keyed manifest-relative.
const FIXTURES: &[(&str, &str)] = &[
    (
        "vectors/section_signer_accept.json",
        include_str!("../kat/gate/vectors/section_signer_accept.json"),
    ),
    (
        "vectors/section_signer_reject.json",
        include_str!("../kat/gate/vectors/section_signer_reject.json"),
    ),
];

// deny_unknown_fields: a field the schema does not know is a manifest drift,
// not a tolerance.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    manifest_version: u64,
    profile: String,
    section_signer_accept: FileCount,
    section_signer_reject: RejectSection,
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
struct SectionSignerVector {
    name: String,
    head_block: String,
    owner_identity_pk: String,
    check: Option<String>,
    class: Option<String>,
}

fn manifest() -> Manifest {
    serde_json::from_str(MANIFEST).expect("gate manifest parses")
}

fn vectors(file: &str) -> Vec<SectionSignerVector> {
    let text = FIXTURES
        .iter()
        .find(|(p, _)| *p == file)
        .unwrap_or_else(|| panic!("no embedded fixture for {file}"))
        .1;
    serde_json::from_str(text).expect("vector file parses")
}

fn bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("vector hex decodes")
}

/// Run the vector's head block through the gate's stage 2 and stage 3, in the
/// gate's own order. Stage 2 must pass on every vector — otherwise a stage-3
/// vector would be proving nothing but a bad commitment signature.
fn authenticate(v: &SectionSignerVector) -> Result<(), cipherbox_core::error::CodecError> {
    let envelope = decode_envelope(&bytes(&v.head_block)).expect("head block decodes");
    let section = decode_grant_section(
        grant_section_bytes(&envelope).expect("a scope root carries its grant section"),
    )
    .expect("grant section decodes");

    let owner = EcdsaVerifier::from_sec1(&bytes(&v.owner_identity_pk)).expect("owner identity");
    let sig = EcdsaSignature::from_compact(&section.commitment_sig).expect("commitment signature");
    cipherbox_core::seal::verify_grant_set(&owner, &section.commitment, &sig)
        .expect("every vector passes stage 2, so stage 3 owns the verdict");

    authenticate_section_structures(&section, &envelope)
}

#[test]
fn manifest_header_and_counts_are_exact() {
    let m = manifest();
    assert_eq!(m.manifest_version, 1);
    assert_eq!(m.profile, "cipherbox/v2 engine adoption-gate");
    assert_eq!(
        vectors(&m.section_signer_accept.file).len(),
        m.section_signer_accept.count
    );
    assert_eq!(
        vectors(&m.section_signer_reject.file).len(),
        m.section_signer_reject.count
    );
    assert!(
        m.section_signer_reject.count > 0,
        "the reject family must not be empty"
    );

    let referenced: BTreeSet<&str> = [
        m.section_signer_accept.file.as_str(),
        m.section_signer_reject.file.as_str(),
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
fn accept_vectors_authenticate_under_one_committed_signer() {
    let m = manifest();
    let vs = vectors(&m.section_signer_accept.file);
    let mut names = BTreeSet::new();
    for v in &vs {
        assert!(names.insert(v.name.clone()), "duplicate vector {}", v.name);
        assert!(v.check.is_none() && v.class.is_none(), "{}", v.name);
        authenticate(v).unwrap_or_else(|e| panic!("{}: {e}", v.name));
    }
}

#[test]
fn a_section_signed_by_two_committed_pseudonyms_fails_closed() {
    let m = manifest();
    let vs = vectors(&m.section_signer_reject.file);
    let mut names = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for v in &vs {
        assert!(names.insert(v.name.clone()), "duplicate vector {}", v.name);
        let error = authenticate(v).expect_err(&format!("{} must fail closed", v.name));
        assert_eq!(Some(error.check()), v.check.as_deref(), "{}", v.name);
        assert_eq!(Some(error.class()), v.class.as_deref(), "{}", v.name);
        seen.insert(error.check().to_string());
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        {
            let mut c = m.section_signer_reject.checks.clone();
            c.sort();
            c
        },
        "the manifest's check list is exactly what the vectors fire"
    );
    assert!(
        vs.iter().any(|v| v.name == "two-committed-signers"),
        "the mixed-signer vector is the whole point of this family"
    );
}

#[test]
fn every_gate_check_comes_from_cores_trust_surface() {
    // The gate composes core's verify functions and invents no cryptographic
    // error code of its own (blueprint/engine.md).
    let m = manifest();
    for check in &m.section_signer_reject.checks {
        assert!(
            TrustViolation::CHECKS.contains(&check.as_str()),
            "{check} is not a core trust verdict"
        );
    }
}
