//! The fake world — shared network state plus per-device seam sets, the
//! seed of the simulation harness (blueprint/testing.md).

use cipherbox_core::kdf;

use crate::seams::{EndpointId, OwnerScopedFloorStore, SeamSet, SeamTypes};
use crate::testkit::fakes::{
    InMemoryCredentialStore, InMemoryFloorStore, InMemoryMailbox, InMemoryMailboxHub,
    InMemoryReceivedShareStore, InMemoryRecordStore, InMemorySnapshotCache, InMemoryStagingStore,
    ScriptedHttp, VirtualScheduler,
};

/// The [`SeamTypes`] family binding every fake — the test kit's host.
pub struct FakeSeamTypes;

impl SeamTypes for FakeSeamTypes {
    type FloorStore = InMemoryFloorStore;
    type RecordTransport = InMemoryRecordStore;
    type Http = ScriptedHttp;
    type Scheduler = VirtualScheduler;
    type StagingStore = InMemoryStagingStore;
    type SnapshotCache = InMemorySnapshotCache;
    type CredentialStore = InMemoryCredentialStore;
}

/// State shared by every device in a scenario: one virtual clock, one fake
/// `/routing/v1` record store, one mailbox hub. N engine instances (owner,
/// write-grantee, read-grantee, revokee, adversary) built over one world
/// interact exactly the way real clients do — through published records
/// and sealed mailbox traffic — stepped deterministically on virtual time.
pub struct FakeWorld {
    /// The shared virtual clock.
    pub scheduler: VirtualScheduler,
    /// The shared fake record store ("the network").
    pub record_store: InMemoryRecordStore,
    /// The shared mailbox hub ("the API mailbox").
    pub mailbox_hub: InMemoryMailboxHub,
}

impl FakeWorld {
    /// A fresh world with the default two-endpoint set (mirroring
    /// production shape: someguy plus one independent endpoint).
    pub fn new() -> Self {
        Self {
            scheduler: VirtualScheduler::new(),
            record_store: InMemoryRecordStore::new(vec![
                EndpointId::new("fake:someguy"),
                EndpointId::new("fake:public-routing"),
            ]),
            mailbox_hub: InMemoryMailboxHub::default(),
        }
    }

    /// A new device (one account session) on this world: fresh device-local
    /// stores, shared network and clock. `recipient_public_key` binds the
    /// device's mailbox inbox.
    pub fn device(&self, recipient_public_key: &[u8]) -> FakeDevice {
        let mailbox = self.mailbox_hub.mailbox_for(recipient_public_key);
        FakeDevice {
            floor_store: InMemoryFloorStore::default(),
            staging_store: InMemoryStagingStore::default(),
            snapshot_cache: InMemorySnapshotCache::default(),
            credential_store: InMemoryCredentialStore::default(),
            http: ScriptedHttp::with_route(mailbox.http_route()),
            mailbox,
            received_share_store: InMemoryReceivedShareStore::default(),
            scheduler: self.scheduler.clone(),
            record_store: self.record_store.clone(),
        }
    }
}

impl Default for FakeWorld {
    fn default() -> Self {
        Self::new()
    }
}

/// One device's seam handles. Every field is a cheap `Clone` handle, so the
/// test retains inspection/driving access to state it moves into an engine
/// via [`FakeDevice::seam_set`].
pub struct FakeDevice {
    /// Device-local durable floors.
    pub floor_store: InMemoryFloorStore,
    /// Device-local op queue + staged bytes.
    pub staging_store: InMemoryStagingStore,
    /// Device-local ciphertext cache.
    pub snapshot_cache: InMemorySnapshotCache,
    /// Device-local refresh-token store.
    pub credential_store: InMemoryCredentialStore,
    /// Device-local scripted HTTP. It also answers the API's mailbox routes
    /// from [`Self::mailbox`], which is how an engine reaches its inbox.
    pub http: ScriptedHttp,
    /// This device's inbox on the shared hub.
    pub mailbox: InMemoryMailbox,
    /// Device-local durable received-shares bookmark (the grants accept flow's
    /// [`ReceivedShareStore`](crate::grants::ReceivedShareStore)).
    pub received_share_store: InMemoryReceivedShareStore,
    /// The shared virtual clock.
    pub scheduler: VirtualScheduler,
    /// The shared record store.
    pub record_store: InMemoryRecordStore,
}

impl FakeDevice {
    /// This device's floors as the engine keys them for the session `secret`
    /// starts: [`OwnerScopedFloorStore`] namespaces every key by identity, so a
    /// raw read of the shared store finds none of the engine's own floors.
    pub fn floors(&self, secret: &[u8]) -> OwnerScopedFloorStore<InMemoryFloorStore> {
        let floors = OwnerScopedFloorStore::new(self.floor_store.clone());
        floors.bind(&kdf::enc_subkey(secret), &kdf::contact_label_seed(secret));
        floors
    }

    /// The complete seam set for this device, ready for
    /// [`crate::facade::Engine::new`].
    pub fn seam_set(&self) -> SeamSet<FakeSeamTypes> {
        SeamSet {
            floor_store: OwnerScopedFloorStore::new(self.floor_store.clone()),
            record_transport: self.record_store.clone(),
            http: self.http.clone(),
            scheduler: self.scheduler.clone(),
            staging_store: self.staging_store.clone(),
            snapshot_cache: self.snapshot_cache.clone(),
            credential_store: self.credential_store.clone(),
        }
    }
}
