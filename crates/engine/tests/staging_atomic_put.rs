//! The failed-put kit cases run against the in-memory fake — the replacement
//! case and the fresh-backing case, each paired with the fault a host that is
//! not failure-atomic would show (the previous bytes destroyed; a partial
//! record stranded where the key held none). The paired `should_panic` tests
//! are the negative controls that prove each case actually holds a host to
//! `put_staged_bytes`'s failure-atomicity.

use cipherbox_engine::testkit::conformance::staging_store::FAILED_PUT_KEY;
use cipherbox_engine::testkit::fakes::InMemoryStagingStore;
use cipherbox_engine::testkit::{block_on, conformance};

#[test]
fn the_in_memory_staging_store_passes_the_failed_put_kit() {
    let store = InMemoryStagingStore::default();
    block_on(conformance::staging_store::check_failed_put(
        async || store.clone(),
        async || store.interrupt_staged_write_after(FAILED_PUT_KEY, 0),
    ));
}

#[test]
#[should_panic(expected = "must leave the previous bytes readable and unchanged")]
fn the_failed_put_kit_catches_a_host_that_destroys_the_previous_bytes() {
    let store = InMemoryStagingStore::default();
    block_on(conformance::staging_store::check_failed_put(
        async || store.clone(),
        async || store.destroy_staged_write_after(FAILED_PUT_KEY, 0),
    ));
}

#[test]
fn the_in_memory_staging_store_passes_the_failed_first_put_kit() {
    let store = InMemoryStagingStore::default();
    block_on(conformance::staging_store::check_failed_first_put(
        async || store.clone(),
        async || store.interrupt_staged_write_after(FAILED_PUT_KEY, 0),
    ));
}

#[test]
#[should_panic(expected = "must leave no record at the key")]
fn the_failed_first_put_kit_catches_a_host_that_strands_a_partial_record() {
    let store = InMemoryStagingStore::default();
    block_on(conformance::staging_store::check_failed_first_put(
        async || store.clone(),
        async || store.strand_staged_write_after(FAILED_PUT_KEY, 0),
    ));
}
