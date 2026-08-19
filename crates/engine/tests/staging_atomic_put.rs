//! The negative controls for the staging-store kit's failure-atomicity phases:
//! each pairs the kit with the fault a host that is not failure-atomic would
//! show (the previous bytes destroyed; a partial record stranded where the key
//! held none), and proves the kit refuses to pass it. The positive leg — the
//! in-memory fake passing the whole kit — lives in `conformance_fakes.rs`.

use cipherbox_engine::testkit::conformance::staging_store::FAILED_PUT_KEY;
use cipherbox_engine::testkit::fakes::{InMemoryStagingBackings, InMemoryStagingStore};
use cipherbox_engine::testkit::{block_on, conformance};

/// Runs the whole kit against the in-memory fake, with `arm` as its lever.
fn run_kit(arm: fn(&InMemoryStagingStore)) {
    let backings = InMemoryStagingBackings::default();
    block_on(conformance::staging_store::check(
        async |backing| backings.open(backing),
        async |backing| arm(&backings.open(backing)),
    ));
}

#[test]
#[should_panic(expected = "must leave the previous bytes readable and unchanged")]
fn the_kit_catches_a_host_that_destroys_the_previous_bytes() {
    run_kit(|store| store.destroy_staged_write_after(FAILED_PUT_KEY, 0));
}

#[test]
#[should_panic(expected = "must leave no record at the key")]
fn the_kit_catches_a_host_that_strands_a_partial_record() {
    run_kit(|store| store.strand_staged_write_after(FAILED_PUT_KEY, 0));
}
