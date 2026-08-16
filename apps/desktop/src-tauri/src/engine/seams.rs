//! The seam set the native host injects (blueprint/desktop.md "Engine
//! wiring"): `crates/desktop-seams` for the seven durable/transport seams, the
//! host's own [`HttpMailbox`] for the eighth, and the OS CSPRNG for entropy.

use std::path::Path;

use cipherbox_desktop_seams::{
    FileFloorStore, FileSnapshotCache, FileStagingStore, KeyringCredentialStore, ReqwestHttp,
    ReqwestRecordTransport, TokioScheduler,
};
use cipherbox_engine::{Entropy, EntropyError, SeamSet, SeamTypes};

use super::config::EngineConfig;
use super::mailbox::HttpMailbox;

/// The desktop host's concrete seam family.
pub struct DesktopSeamTypes;

impl SeamTypes for DesktopSeamTypes {
    type FloorStore = FileFloorStore;
    type RecordTransport = ReqwestRecordTransport;
    type Http = ReqwestHttp;
    type Mailbox = HttpMailbox;
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
///
/// One `reqwest` client backs both HTTP seams, so the API and the gateway share
/// a connection pool.
pub fn seam_set(
    config: &EngineConfig,
    account_dir: &Path,
    keyring_service: &str,
) -> Result<SeamSet<DesktopSeamTypes>, String> {
    let http = ReqwestHttp::new().map_err(|error| error.to_string())?;
    Ok(SeamSet::<DesktopSeamTypes> {
        floor_store: FileFloorStore::open(account_dir.join("floors"))
            .map_err(|error| error.to_string())?,
        record_transport: ReqwestRecordTransport::new(config.record_endpoints.clone())
            .map_err(|error| error.to_string())?,
        mailbox: HttpMailbox::new(http.clone(), &config.api_base_url),
        http,
        scheduler: TokioScheduler::new(),
        staging_store: FileStagingStore::open(account_dir.join("staging"))
            .map_err(|error| error.to_string())?,
        snapshot_cache: FileSnapshotCache::open(account_dir.join("cache"))
            .map_err(|error| error.to_string())?,
        credential_store: KeyringCredentialStore::new(keyring_service),
    })
}
