//! The seam set the native host injects (blueprint/desktop.md "Engine
//! wiring"): `crates/desktop-seams` for the seven durable/transport seams.
//! Entropy is not a seam — the engine owns its one production source.

use std::path::Path;

use cipherbox_desktop_seams::{
    FileFloorStore, FileSnapshotCache, FileStagingStore, ReqwestHttp, ReqwestRecordTransport,
    TokioScheduler,
};
use cipherbox_engine::seams::SeamResult;
use cipherbox_engine::{OwnerScopedFloorStore, QueueGenerationStore, SeamSet, SeamTypes};

use super::config::EngineConfig;

/// Where a session's refresh token lives on this host.
#[cfg(not(feature = "e2e-hook"))]
pub type HostCredentialStore = cipherbox_desktop_seams::KeyringCredentialStore;

/// Where a session's refresh token lives on this host.
#[cfg(feature = "e2e-hook")]
pub type HostCredentialStore = crate::e2e::MemoryCredentialStore;

/// The record transport and HTTP seams this host injects.
#[cfg(not(feature = "e2e-hook"))]
type HostTransport<S> = S;

/// The record transport and HTTP seams this host injects, each slow request
/// reported (`crate::e2e::diagnostics`).
#[cfg(feature = "e2e-hook")]
type HostTransport<S> = cipherbox_desktop_seams::Timed<S>;

#[cfg(not(feature = "e2e-hook"))]
fn host_transport<S>(seam: S) -> HostTransport<S> {
    seam
}

#[cfg(feature = "e2e-hook")]
fn host_transport<S>(seam: S) -> HostTransport<S> {
    use crate::e2e::diagnostics;
    cipherbox_desktop_seams::Timed::new(
        seam,
        diagnostics::SLOW_REQUEST,
        diagnostics::slow_requests(),
    )
}

/// The desktop host's concrete seam family.
pub struct DesktopSeamTypes;

impl SeamTypes for DesktopSeamTypes {
    type FloorStore = FileFloorStore;
    type RecordTransport = HostTransport<ReqwestRecordTransport>;
    type Http = HostTransport<ReqwestHttp>;
    type Scheduler = TokioScheduler;
    type StagingStore = FileStagingStore;
    type SnapshotCache = FileSnapshotCache;
    type CredentialStore = HostCredentialStore;
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
        record_transport: host_transport(ReqwestRecordTransport::new(
            config.record_endpoints.clone(),
            config.record_accelerator_url.clone(),
        )?),
        http: host_transport(ReqwestHttp::new()?),
        scheduler: TokioScheduler::new(),
        staging_store: QueueGenerationStore::new(FileStagingStore::open(
            account_dir.join("staging"),
        )?),
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
