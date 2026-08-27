//! CipherBox desktop seam set: the concrete host-seam implementations the
//! desktop native host injects into the engine constructor
//! (blueprint/engine.md "Host seams", desktop column; blueprint/desktop.md
//! "Engine wiring").
//!
//! Every durable store here writes **ciphertext-only at rest** under
//! `<data_local_dir>/cipherbox/<accountId>/` — the same law as web's
//! IndexedDB stores; a stolen disk yields sealed bytes only. Plaintext and
//! key material never touch these stores: [`FileSnapshotCache`] holds sealed
//! record/metadata bytes the engine unseals on read, [`SealedCoreKitStore`]
//! holds the login SDK's session state sealed under a keyring-held wrapping
//! key, and [`KeyringCredentialStore`] keeps the rotating refresh token, the
//! last-account id, and that wrapping key in the OS keyring — never a seed.
//!
//! The seven seams split by concern:
//!
//! - [`FileFloorStore`], [`FileStagingStore`], [`FileSnapshotCache`] —
//!   fsync-barriered files (the v1 high-water / write-journal discipline
//!   generalized).
//! - [`KeyringCredentialStore`] — the OS keyring.
//! - [`ReqwestHttp`], [`ReqwestRecordTransport`] — `reqwest` over rustls.
//! - [`TokioScheduler`] — timers, background tasks, wall clock on Tokio.
//!
//! Two exports are not seam traits: [`SealedCoreKitStore`], the login SDK's own
//! store, and [`measured_storage_policy`], the desktop leg of the
//! host-to-engine storage measurement — a construction-time figure the shell
//! hands [`cipherbox_engine::Engine::new`].
//!
//! This crate constructs no engine and touches no webview — the desktop shell
//! does both.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// The seam traits use native `async fn` (blueprint: single-writer engine
// pinned to one execution context, `!Send` futures). Implementing them is
// unremarkable; this mirrors the engine crate's own allowance.
#![allow(async_fn_in_trait)]

mod core_kit_store;
mod credential_store;
mod floor_store;
mod fs_util;
mod http;
mod offload;
mod paths;
mod record_transport;
mod scheduler;
mod snapshot_cache;
mod staging_store;
mod storage_policy;

pub use core_kit_store::SealedCoreKitStore;
pub use credential_store::{CoreKitWrappingKey, KeyringCredentialStore};
pub use floor_store::FileFloorStore;
pub use http::ReqwestHttp;
pub use paths::{account_data_dir, core_kit_store_dir};
pub use record_transport::ReqwestRecordTransport;
pub use scheduler::TokioScheduler;
pub use snapshot_cache::FileSnapshotCache;
pub use staging_store::FileStagingStore;
pub use storage_policy::measured_storage_policy;

#[cfg(feature = "test-support")]
pub use credential_store::FileCredentialStore;
