//! The adoption gate's frozen stage-3 vectors: **one section, one signer**
//! (blueprint/engine.md "Adoption gate and floors"). Sibling of the content-DAG
//! suite, with its own manifest under `kat/gate/` because it freezes a trust
//! predicate over whole scope-root head blocks rather than a content format.

use std::collections::BTreeSet;
use std::convert::Infallible;

use cipherbox_core::error::TrustViolation;
use cipherbox_core::seal::{
    Envelope, GrantSection, Permission, StructureSigInput, decode_envelope, decode_grant_section,
    grant_section_bytes, verify_grant_set, verify_structure,
};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier};
use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Verifier};
use cipherbox_engine::gate::{
    authenticate_section_structures, committed_write_pseudonyms, for_each_structure,
};
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

/// The vector's decoded head block, after asserting the gate's **stage 2**
/// passes: a stage-3 vector whose commitment signature is bad would prove
/// nothing about stage 3.
fn stage_two(v: &SectionSignerVector) -> (Envelope, GrantSection) {
    let envelope = decode_envelope(&bytes(&v.head_block)).expect("head block decodes");
    let section = decode_grant_section(
        grant_section_bytes(&envelope).expect("a scope root carries its grant section"),
    )
    .expect("grant section decodes");

    let owner = EcdsaVerifier::from_sec1(&bytes(&v.owner_identity_pk)).expect("owner identity");
    let sig = EcdsaSignature::from_compact(&section.commitment_sig).expect("commitment signature");
    verify_grant_set(&owner, &section.commitment, &sig)
        .expect("every vector passes stage 2, so stage 3 owns the verdict");
    (envelope, section)
}

/// Stage 3's **pre-pin** predicate: for each seed-bearing structure, every
/// committed write-capable pseudonym whose key verifies it. Driven off the
/// gate's own [`for_each_structure`] and [`committed_write_pseudonyms`], so a
/// new structure kind or a change to the committed set cannot leave this
/// harness describing a section the gate no longer reads the same way.
///
/// The pin makes stage 3 stop at the first signer, so only this wider view can
/// show that a reject vector's every signature is individually valid — that the
/// pin, and nothing else, is what refuses it.
fn signers_per_structure(section: &GrantSection, envelope: &Envelope) -> Vec<BTreeSet<[u8; 32]>> {
    let committed = committed_write_pseudonyms(&section.commitment);
    let mut out = Vec::new();
    let walked: Result<(), Infallible> =
        for_each_structure(section, |tag, recipient, ct, signature| {
            let input = StructureSigInput::over_ciphertext(
                envelope.scope,
                envelope.epoch,
                tag,
                recipient,
                ct,
            );
            let sig = Ed25519Signature::from_bytes(*signature);
            out.push(
                committed
                    .iter()
                    .filter(|pk| {
                        Ed25519Verifier::from_bytes(**pk)
                            .is_some_and(|v| verify_structure(&v, &input, &sig).is_ok())
                    })
                    .copied()
                    .collect(),
            );
            Ok(())
        });
    walked.expect("the walk never fails");
    out
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
    let mut signed_by_a_non_owner = false;
    for v in &vs {
        assert!(names.insert(v.name.clone()), "duplicate vector {}", v.name);
        assert!(v.check.is_none() && v.class.is_none(), "{}", v.name);
        let (envelope, section) = stage_two(v);
        authenticate_section_structures(&section, &envelope)
            .unwrap_or_else(|e| panic!("{}: {e}", v.name));

        // Non-vacuous: more than one committed write-capable pseudonym is on
        // offer, and exactly one of them signed the whole section.
        assert!(
            section
                .commitment
                .entries
                .iter()
                .any(|e| e.permission == Permission::Write),
            "{}: a one-pseudonym commitment pins vacuously",
            v.name
        );
        let signers: BTreeSet<[u8; 32]> = signers_per_structure(&section, &envelope)
            .into_iter()
            .flatten()
            .collect();
        let [signer] = signers.into_iter().collect::<Vec<_>>()[..] else {
            panic!("{}: one section, one signer", v.name);
        };
        signed_by_a_non_owner |= signer != section.commitment.owner_pseudonym_pk;
    }
    assert!(
        signed_by_a_non_owner,
        "pinning must not narrow *who* may sign: one accept vector is signed \
         throughout by a committed pseudonym that is not the owner's"
    );
}

#[test]
fn a_section_signed_by_two_committed_pseudonyms_fails_closed() {
    let m = manifest();
    let vs = vectors(&m.section_signer_reject.file);
    let mut names = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for v in &vs {
        assert!(names.insert(v.name.clone()), "duplicate vector {}", v.name);
        let (envelope, section) = stage_two(v);
        let error = authenticate_section_structures(&section, &envelope)
            .expect_err(&format!("{} must fail closed", v.name));
        assert_eq!(Some(error.check()), v.check.as_deref(), "{}", v.name);
        assert_eq!(Some(error.class()), v.class.as_deref(), "{}", v.name);
        seen.insert(error.check().to_string());

        // The pin, and nothing else, is what refuses these: every structure
        // signature is individually valid under some committed pseudonym, and
        // together they name more than one.
        let per_structure = signers_per_structure(&section, &envelope);
        for (i, signers) in per_structure.iter().enumerate() {
            assert_eq!(
                signers.len(),
                1,
                "{}: structure {i} must verify under exactly one committed pseudonym",
                v.name
            );
        }
        let distinct: BTreeSet<[u8; 32]> = per_structure.into_iter().flatten().collect();
        assert_eq!(
            distinct.len(),
            2,
            "{}: a pin vector must carry exactly two committed signers",
            v.name
        );
    }
    assert_eq!(
        seen,
        m.section_signer_reject.checks.iter().cloned().collect(),
        "the manifest's check list is exactly what the vectors fire"
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
