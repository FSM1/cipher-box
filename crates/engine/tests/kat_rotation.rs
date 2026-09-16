//! The rotation reject KAT suite: the frozen verdict of every fail-closed
//! check the rotation planes publish.
//!
//! The suite re-drives the live entry points and diffs the result against the
//! committed vectors, so reclassifying a trust rejection as an availability
//! stall — or moving a check between planes — is a red test rather than a
//! silent change of what a host retries forever.
//!
//! `crates/engine/kat` is written only by
//! `cargo run -p cipherbox-engine --example kat_gen`.

mod reject_corpus;

use cipherbox_engine::testkit::rotation::reject_families;
use reject_corpus::Corpus;

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

fn corpus() -> Corpus {
    Corpus::new(MANIFEST, FIXTURES, reject_families())
}

#[test]
fn manifest_header_names_the_rotation_profile() {
    corpus().header_names("cipherbox/v2 engine rotation plane");
}

#[test]
fn every_embedded_fixture_is_referenced_and_every_reference_embedded() {
    corpus().every_fixture_is_referenced_and_every_reference_embedded();
}

#[test]
fn the_committed_families_are_exactly_the_driven_ones() {
    corpus().the_committed_families_are_exactly_the_driven_ones();
}

#[test]
fn re_driving_the_planes_reproduces_the_committed_vectors() {
    corpus().re_driving_reproduces_the_committed_vectors();
}

#[test]
fn manifest_counts_and_checks_agree_with_the_vector_files() {
    corpus().counts_and_checks_agree_with_the_vector_files();
}

#[test]
fn every_committed_check_sits_on_its_own_surface() {
    corpus().every_committed_check_sits_on_its_own_surface();
}

#[test]
fn vector_names_are_unique_within_each_family() {
    corpus().vector_names_are_unique_within_each_family();
}

#[test]
fn every_class_is_a_rotation_axis_or_a_delegated_label() {
    corpus().every_class_is_an_axis_or_a_delegated_label();
}
