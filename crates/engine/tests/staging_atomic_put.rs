//! The failed-put kit case run against the in-memory fake, both ways: with a
//! write fault that leaves the stored value alone, and with one that destroys
//! it first — the negative control that proves the kit actually holds a host to
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
