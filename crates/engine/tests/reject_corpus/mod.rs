//! The freeze harness a committed reject corpus is read through: the manifest
//! schema, the embedded vector files, and the invariants every corpus holds.
//!
//! One home for both corpora under `crates/engine/kat`, so a new plane in
//! either adds a family builder and a fixture line and nothing else.

use std::collections::{BTreeMap, BTreeSet};

use cipherbox_engine::testkit::reject::RejectFamily;
use serde::Deserialize;

// deny_unknown_fields: a field the schema does not know is a manifest drift,
// not a tolerance.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
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

/// The four axes an engine caller acts on. A variant that surfaces another
/// type's verdict keeps that type's label, so core's are admitted too.
const CLASSES: &[&str] = &["trust", "availability", "over-cap", "capability"];
const DELEGATED_CLASSES: &[&str] = &["malformed", "unsupported"];

/// One committed corpus and the live families that must reproduce it.
pub struct Corpus {
    manifest: Manifest,
    fixtures: &'static [(&'static str, &'static str)],
    driven: Vec<RejectFamily>,
}

impl Corpus {
    /// `manifest` and `fixtures` are `include_str!`-embedded, so a suite never
    /// depends on the working directory.
    pub fn new(
        manifest: &str,
        fixtures: &'static [(&'static str, &'static str)],
        driven: Vec<RejectFamily>,
    ) -> Self {
        Self {
            manifest: serde_json::from_str(manifest).expect("a manifest must match the schema"),
            fixtures,
            driven,
        }
    }

    pub fn header_names(&self, profile: &str) {
        assert_eq!(self.manifest.manifest_version, 1);
        assert_eq!(self.manifest.profile, profile);
    }

    pub fn every_fixture_is_referenced_and_every_reference_embedded(&self) {
        let referenced: BTreeSet<&str> = self
            .manifest
            .families
            .values()
            .map(|f| f.file.as_str())
            .collect();
        let embedded: BTreeSet<&str> = self.fixtures.iter().map(|(p, _)| *p).collect();
        assert_eq!(referenced, embedded);
    }

    pub fn the_committed_families_are_exactly_the_driven_ones(&self) {
        let committed: BTreeSet<&str> = self.manifest.families.keys().map(String::as_str).collect();
        let live: BTreeSet<&str> = self.driven.iter().map(|f| f.plane).collect();
        assert_eq!(
            committed, live,
            "a plane the generator builds must have a committed family, and no other"
        );
    }

    /// The freeze: re-driving the live code reproduces every committed verdict,
    /// in order.
    pub fn re_driving_reproduces_the_committed_vectors(&self) {
        for family in &self.driven {
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
                live,
                self.vectors(family.plane),
                "{}: the live refusals must equal the committed vectors",
                family.plane
            );
        }
    }

    pub fn counts_and_checks_agree_with_the_vector_files(&self) {
        for family in &self.driven {
            let listed = self.section(family.plane);
            let committed = self.vectors(family.plane);
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

    pub fn every_committed_check_sits_on_its_own_surface(&self) {
        for family in &self.driven {
            let surface: BTreeSet<&str> = family.surface.iter().copied().collect();
            for vector in self.vectors(family.plane) {
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

    pub fn vector_names_are_unique_within_each_family(&self) {
        for family in &self.driven {
            let mut names = BTreeSet::new();
            for vector in self.vectors(family.plane) {
                assert!(
                    names.insert(vector.name.clone()),
                    "{}: duplicate vector name {}",
                    family.plane,
                    vector.name
                );
            }
        }
    }

    pub fn every_class_is_an_axis_or_a_delegated_label(&self) {
        for family in &self.driven {
            for vector in self.vectors(family.plane) {
                assert!(
                    CLASSES.contains(&vector.class.as_str())
                        || DELEGATED_CLASSES.contains(&vector.class.as_str()),
                    "{}: {} carries unknown class {}",
                    family.plane,
                    vector.name,
                    vector.class
                );
            }
        }
    }

    fn section(&self, plane: &str) -> &FamilySection {
        self.manifest
            .families
            .get(plane)
            .unwrap_or_else(|| panic!("the manifest names no family for plane {plane}"))
    }

    fn vectors(&self, plane: &str) -> Vec<RejectVector> {
        let path = &self.section(plane).file;
        let text = self
            .fixtures
            .iter()
            .find(|(p, _)| p == path)
            .unwrap_or_else(|| {
                panic!("manifest references {path}, which is not include_str!-embedded")
            })
            .1;
        serde_json::from_str(text).expect("reject vector shape")
    }
}
