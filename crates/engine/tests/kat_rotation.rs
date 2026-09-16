//! The rotation reject KAT suite: the frozen verdict of every fail-closed
//! check the rotation planes publish.
//!
//! The suite re-drives the live entry points and diffs the result against the
//! committed vectors, so reclassifying a trust rejection as an availability
//! stall — or moving a check between planes — is a red test rather than a
//! silent change of what a host retries forever.
//!
//! Fixtures are embedded at compile time, so the suite never depends on the
//! working directory. `crates/engine/kat` is written only by
//! `cargo run -p cipherbox-engine --example kat_gen`.

use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::error::{Malformed, TrustViolation};
use cipherbox_engine::content::DagError;
use cipherbox_engine::rotation::{
    CascadeError, ResealError, RevokeError, RotateError, RotateOnCutError, SweepError,
    WriteRotateError,
};
use cipherbox_engine::testkit::rotation::{RotationRejectFamily, reject_families};
use serde::Deserialize;

const MANIFEST: &str = include_str!("../kat/rotation/manifest.json");

/// Every vector file the manifest may reference, keyed manifest-relative
/// (relative to `kat/rotation/`).
const FIXTURES: &[(&str, &str)] = &[
    (
        "vectors/cascade_reject.json",
        include_str!("../kat/rotation/vectors/cascade_reject.json"),
    ),
    (
        "vectors/cut_reject.json",
        include_str!("../kat/rotation/vectors/cut_reject.json"),
    ),
    (
        "vectors/read_rotate_reject.json",
        include_str!("../kat/rotation/vectors/read_rotate_reject.json"),
    ),
    (
        "vectors/reseal_reject.json",
        include_str!("../kat/rotation/vectors/reseal_reject.json"),
    ),
    (
        "vectors/revoke_reject.json",
        include_str!("../kat/rotation/vectors/revoke_reject.json"),
    ),
    (
        "vectors/sweep_reject.json",
        include_str!("../kat/rotation/vectors/sweep_reject.json"),
    ),
    (
        "vectors/write_rotate_reject.json",
        include_str!("../kat/rotation/vectors/write_rotate_reject.json"),
    ),
];

// deny_unknown_fields: a field the schema does not know is a manifest drift,
// not a tolerance.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    manifest_version: u64,
    profile: String,
    families: BTreeMap<String, FamilySection>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FamilySection {
    file: String,
    count: usize,
    checks: Vec<String>,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RejectVector {
    name: String,
    check: String,
    class: String,
}

/// The four axes a rotation caller acts on. A delegated variant surfaces the
/// wrapped type's own label instead, so core's labels are admitted too.
const ROTATION_CLASSES: &[&str] = &["trust", "availability", "over-cap", "capability"];
const DELEGATED_CLASSES: &[&str] = &["malformed", "unsupported"];

fn manifest() -> Manifest {
    serde_json::from_str(MANIFEST).expect("kat/rotation/manifest.json must match the schema")
}

fn fixture(path: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(p, _)| *p == path)
        .unwrap_or_else(|| panic!("manifest references {path}, which is not include_str!-embedded"))
        .1
}

fn vectors(section: &FamilySection) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&section.file)).expect("reject vector shape")
}

fn section<'a>(m: &'a Manifest, plane: &str) -> &'a FamilySection {
    m.families
        .get(plane)
        .unwrap_or_else(|| panic!("the manifest names no family for plane {plane}"))
}

/// The live families, as the generator drives them.
fn driven() -> Vec<RotationRejectFamily> {
    reject_families()
}

#[test]
fn manifest_header_names_the_rotation_profile() {
    let m = manifest();
    assert_eq!(m.manifest_version, 1);
    assert_eq!(m.profile, "cipherbox/v2 engine rotation plane");
}

#[test]
fn every_embedded_fixture_is_referenced_and_every_reference_embedded() {
    let m = manifest();
    let referenced: BTreeSet<&str> = m.families.values().map(|f| f.file.as_str()).collect();
    let embedded: BTreeSet<&str> = FIXTURES.iter().map(|(p, _)| *p).collect();
    assert_eq!(referenced, embedded);
}

#[test]
fn the_committed_families_are_exactly_the_driven_ones() {
    let m = manifest();
    let committed: BTreeSet<&str> = m.families.keys().map(String::as_str).collect();
    let live: BTreeSet<&str> = driven().iter().map(|f| f.plane).collect();
    assert_eq!(
        committed, live,
        "a plane the generator builds must have a committed family, and no other"
    );
}

/// The freeze: re-driving the live rotation code reproduces every committed
/// verdict, in order.
#[test]
fn re_driving_the_planes_reproduces_the_committed_vectors() {
    let m = manifest();
    for family in driven() {
        let committed = vectors(section(&m, family.plane));
        let live: Vec<RejectVector> = family
            .vectors
            .iter()
            .map(|v| RejectVector {
                name: v.name.to_string(),
                check: v.check.to_string(),
                class: v.class.to_string(),
            })
            .collect();
        assert_eq!(
            live, committed,
            "{}: the live refusals must equal the committed vectors",
            family.plane
        );
    }
}

#[test]
fn manifest_counts_and_checks_agree_with_the_vector_files() {
    let m = manifest();
    for family in driven() {
        let listed = section(&m, family.plane);
        let committed = vectors(listed);
        assert_eq!(
            committed.len(),
            listed.count,
            "{}: vector count",
            family.plane
        );

        let present: BTreeSet<&str> = committed.iter().map(|v| v.check.as_str()).collect();
        let expected: Vec<String> = family
            .surface
            .iter()
            .filter(|c| present.contains(**c))
            .map(|c| (*c).to_string())
            .collect();
        assert_eq!(
            listed.checks, expected,
            "{}: a manifest checks list is the vectors' distinct checks in surface order",
            family.plane
        );
    }
}

#[test]
fn every_committed_check_sits_on_its_own_surface() {
    let m = manifest();
    for family in driven() {
        let surface: BTreeSet<&str> = family.surface.iter().copied().collect();
        for vector in vectors(section(&m, family.plane)) {
            assert!(
                surface.contains(vector.check.as_str()),
                "{}: {} names off-surface check {}",
                family.plane,
                vector.name,
                vector.check
            );
        }
    }
}

#[test]
fn vector_names_are_unique_within_each_family() {
    let m = manifest();
    for family in driven() {
        let mut names = BTreeSet::new();
        for vector in vectors(section(&m, family.plane)) {
            assert!(
                names.insert(vector.name.clone()),
                "{}: duplicate vector name {}",
                family.plane,
                vector.name
            );
        }
    }
}

#[test]
fn every_class_is_a_rotation_axis_or_a_delegated_label() {
    let m = manifest();
    for family in driven() {
        for vector in vectors(section(&m, family.plane)) {
            assert!(
                ROTATION_CLASSES.contains(&vector.class.as_str())
                    || DELEGATED_CLASSES.contains(&vector.class.as_str()),
                "{}: {} carries unknown class {}",
                family.plane,
                vector.name,
                vector.class
            );
        }
    }
}

/// The `rot-<plane>-` prefix rule made executable: no check name is shared by
/// two rotation surfaces, and none collides with a surface outside rotation.
#[test]
fn no_check_name_is_shared_across_surfaces() {
    let mut owner: BTreeMap<&str, &str> = BTreeMap::new();
    let surfaces: [(&str, &[&str]); 10] = [
        ("core-trust", TrustViolation::CHECKS),
        ("core-malformed", Malformed::CHECKS),
        ("content-dag", DagError::CHECKS),
        ("reseal", ResealError::CHECKS),
        ("revoke", RevokeError::CHECKS),
        ("read_rotate", RotateError::CHECKS),
        ("cascade", CascadeError::CHECKS),
        ("write_rotate", WriteRotateError::CHECKS),
        ("sweep", SweepError::CHECKS),
        ("cut", RotateOnCutError::CHECKS),
    ];
    for (name, checks) in surfaces {
        for check in checks {
            if let Some(previous) = owner.insert(check, name) {
                panic!("{check} is published by both {previous} and {name}");
            }
        }
    }

    for family in driven() {
        assert!(
            surfaces.iter().any(|(name, _)| *name == family.plane),
            "{}: the collision table must cover every driven plane",
            family.plane
        );
    }
}
