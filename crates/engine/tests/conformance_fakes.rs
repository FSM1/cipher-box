//! Every seam conformance kit executed against its in-memory fake — the
//! kits are proven by the fakes passing them, and the fakes are proven honest
//! by the kits.

use cipherbox_engine::api::ApiClient;
use cipherbox_engine::seams::EndpointId;
use cipherbox_engine::testkit::conformance::staging_store::FAILED_PUT_KEY;
use cipherbox_engine::testkit::fakes::{
    InMemoryCredentialStore, InMemoryFloorStore, InMemoryMailboxHub, InMemoryReceivedShareStore,
    InMemoryRecordStore, InMemorySnapshotCache, InMemoryStagingBackings, ScriptedHttp,
    VirtualScheduler,
};
use cipherbox_engine::testkit::{block_on, conformance};

#[test]
fn in_memory_floor_store_passes_the_floor_store_kit() {
    let store = InMemoryFloorStore::default();
    block_on(conformance::floor_store::check(async || store.clone()));
}

#[test]
fn in_memory_staging_store_passes_the_staging_store_kit() {
    let backings = InMemoryStagingBackings::default();
    block_on(conformance::staging_store::check(
        async |backing| backings.open(backing),
        async |backing| {
            backings
                .open(backing)
                .interrupt_staged_write_after(FAILED_PUT_KEY, 0)
        },
    ));
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

/// The `Mailbox` implementation v2.0 actually ships is the engine's own API
/// client, so the kit runs against it too — over the fake API's mailbox routes,
/// which is the only place the wire shape and the trait contract meet.
#[test]
fn the_api_client_passes_the_mailbox_kit() {
    let address = [0x02u8; 33];
    let hub = InMemoryMailboxHub::default();
    let client = ApiClient::new(
        ScriptedHttp::with_mailbox(hub.mailbox_for(&address)),
        InMemoryCredentialStore::default(),
        "http://api.test",
    );
    block_on(conformance::mailbox::check(&client, &address));
}

#[test]
fn virtual_scheduler_passes_the_scheduler_kit() {
    let scheduler = VirtualScheduler::new().with_auto_advance();
    block_on(conformance::scheduler::check(&scheduler));
}
