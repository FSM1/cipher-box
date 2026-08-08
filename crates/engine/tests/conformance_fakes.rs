//! Every seam conformance kit executed against its in-memory fake — the
//! kits are proven by the fakes passing them, and the fakes are proven honest
//! by the kits.

use cipherbox_engine::seams::EndpointId;
use cipherbox_engine::testkit::fakes::{
    InMemoryCredentialStore, InMemoryFloorStore, InMemoryMailboxHub, InMemoryReceivedShareStore,
    InMemoryRecordStore, InMemorySnapshotCache, InMemoryStagingStore, VirtualScheduler,
};
use cipherbox_engine::testkit::{block_on, conformance};

#[test]
fn in_memory_floor_store_passes_the_floor_store_kit() {
    let store = InMemoryFloorStore::default();
    block_on(conformance::floor_store::check(async || store.clone()));
}

#[test]
fn in_memory_staging_store_passes_the_staging_store_kit() {
    let store = InMemoryStagingStore::default();
    block_on(conformance::staging_store::check(async || store.clone()));
}

#[test]
fn in_memory_snapshot_cache_passes_the_snapshot_cache_kit() {
    let cache = InMemorySnapshotCache::default();
    block_on(conformance::snapshot_cache::check(async || cache.clone()));
}

#[test]
fn in_memory_received_share_store_passes_the_received_share_store_kit() {
    let store = InMemoryReceivedShareStore::default();
    block_on(conformance::received_share_store::check(async || {
        store.clone()
    }));
}

#[test]
fn in_memory_credential_store_passes_the_credential_store_kit() {
    let store = InMemoryCredentialStore::default();
    block_on(conformance::credential_store::check(async || store.clone()));
}

#[test]
fn in_memory_record_store_passes_the_record_transport_kit() {
    let transport = InMemoryRecordStore::new(vec![
        EndpointId::new("fake:someguy"),
        EndpointId::new("fake:public-routing"),
    ]);
    block_on(conformance::record_transport::check(
        &transport,
        "k51-fresh-routing-key",
        b"opaque-signed-record-bytes",
    ));
}

#[test]
fn in_memory_mailbox_passes_the_mailbox_kit() {
    let hub = InMemoryMailboxHub::default();
    let mailbox = hub.mailbox_for(b"self-pk");
    block_on(conformance::mailbox::check(&mailbox, b"self-pk"));
}

#[test]
fn virtual_scheduler_passes_the_scheduler_kit() {
    let scheduler = VirtualScheduler::new().with_auto_advance();
    block_on(conformance::scheduler::check(&scheduler));
}
