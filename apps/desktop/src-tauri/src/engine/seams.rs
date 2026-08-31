//! The seam set the native host injects (blueprint/desktop.md "Engine
//! wiring"): `crates/desktop-seams` for the seven durable/transport seams, and
//! the OS CSPRNG for entropy.

use std::path::Path;

use cipherbox_desktop_seams::{
    FileFloorStore, FileSnapshotCache, FileStagingStore, ReqwestHttp, ReqwestRecordTransport,
    TokioScheduler,
};
use cipherbox_engine::seams::SeamResult;
use cipherbox_engine::{Entropy, EntropyError, OwnerScopedFloorStore, SeamSet, SeamTypes};

use super::config::EngineConfig;

/// Where a session's refresh token lives on this host.
#[cfg(not(feature = "e2e-hook"))]
pub type HostCredentialStore = cipherbox_desktop_seams::KeyringCredentialStore;

/// Where a session's refresh token lives on this host.
#[cfg(feature = "e2e-hook")]
pub type HostCredentialStore = crate::e2e::MemoryCredentialStore;

/// The desktop host's concrete seam family.
pub struct DesktopSeamTypes;

impl SeamTypes for DesktopSeamTypes {
    type FloorStore = FileFloorStore;
    type RecordTransport = ReqwestRecordTransport;
    type Http = ReqwestHttp;
    type Scheduler = TokioScheduler;
    type StagingStore = FileStagingStore;
    type SnapshotCache = FileSnapshotCache;
    type CredentialStore = HostCredentialStore;
}

/// Production entropy: the OS CSPRNG. Fail-closed — never substitutes
/// predictable bytes.
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(dest).map_err(|error| EntropyError::new(error.to_string()))
    }
}

/// Opens every durable store under `account_dir` and builds the whole seam set.
/// `credentials` is the store the host already holds rather than a service
/// name: the keyring build's worker queue is what orders a credential write
/// against the logout delete issued after it.
pub fn seam_set(
    config: &EngineConfig,
    account_dir: &Path,
    credentials: HostCredentialStore,
) -> SeamResult<SeamSet<DesktopSeamTypes>> {
    Ok(SeamSet::<DesktopSeamTypes> {
        floor_store: OwnerScopedFloorStore::new(FileFloorStore::open(account_dir.join("floors"))?),
        record_transport: ReqwestRecordTransport::new(config.record_endpoints.clone())?,
        http: ReqwestHttp::new()?,
        scheduler: TokioScheduler::new(),
        staging_store: FileStagingStore::open(account_dir.join("staging"))?,
        snapshot_cache: FileSnapshotCache::open(account_dir.join("cache"))?,
        credential_store: credentials,
    })
}

/// The credential store this crate's tests hand a session.
#[cfg(all(test, not(feature = "e2e-hook")))]
pub fn test_credentials() -> HostCredentialStore {
    HostCredentialStore::new("com.cipherbox.desktop.test").expect("a credential store")
}

#[cfg(all(test, feature = "e2e-hook"))]
pub fn test_credentials() -> HostCredentialStore {
    HostCredentialStore::default()
}
