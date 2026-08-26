//! The seam set the native host injects (blueprint/desktop.md "Engine
//! wiring"): `crates/desktop-seams` for the seven durable/transport seams, and
//! the OS CSPRNG for entropy.

use std::path::Path;

use cipherbox_desktop_seams::{
    FileFloorStore, FileSnapshotCache, FileStagingStore, KeyringCredentialStore, ReqwestHttp,
    ReqwestRecordTransport, TokioScheduler,
};
use cipherbox_engine::seams::SeamResult;
use cipherbox_engine::{Entropy, EntropyError, SeamSet, SeamTypes};

use super::config::EngineConfig;

/// The desktop host's concrete seam family.
pub struct DesktopSeamTypes;

impl SeamTypes for DesktopSeamTypes {
    type FloorStore = FileFloorStore;
    type RecordTransport = ReqwestRecordTransport;
    type Http = ReqwestHttp;
    type Scheduler = TokioScheduler;
    type StagingStore = FileStagingStore;
    type SnapshotCache = FileSnapshotCache;
    type CredentialStore = KeyringCredentialStore;
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
pub fn seam_set(
    config: &EngineConfig,
    account_dir: &Path,
    keyring_service: &str,
) -> SeamResult<SeamSet<DesktopSeamTypes>> {
    Ok(SeamSet::<DesktopSeamTypes> {
        floor_store: FileFloorStore::open(account_dir.join("floors"))?,
        record_transport: ReqwestRecordTransport::new(config.record_endpoints.clone())?,
        http: ReqwestHttp::new()?,
        scheduler: TokioScheduler::new(),
        staging_store: FileStagingStore::open(account_dir.join("staging"))?,
        snapshot_cache: FileSnapshotCache::open(account_dir.join("cache"))?,
        credential_store: KeyringCredentialStore::new(keyring_service)?,
    })
}
