//! CipherBox desktop seam set: the concrete host-seam implementations the
//! desktop native host injects into the engine constructor
//! (blueprint/engine.md "Host seams", desktop column; blueprint/desktop.md
//! "Engine wiring").
//!
//! Every durable store here writes **ciphertext-only at rest** under
//! `<data_local_dir>/cipherbox/<accountId>/` — the same law as web's
//! IndexedDB stores; a stolen disk yields sealed bytes only. Plaintext and
//! key material never touch these stores: [`FileSnapshotCache`] holds sealed
//! record/metadata bytes the engine unseals on read, and
//! [`KeyringCredentialStore`] keeps only the rotating refresh token and the
//! last-account id in the OS keyring — never a seed or an unwrapped key.
//!
//! The nine seams split by concern:
//!
//! - [`FileFloorStore`], [`FileStagingStore`], [`FileSnapshotCache`] —
//!   fsync-barriered files (the v1 high-water / write-journal discipline
//!   generalized).
//! - [`KeyringCredentialStore`] — the OS keyring.
//! - [`ReqwestHttp`], [`ReqwestRecordTransport`] — `reqwest` over rustls.
//! - [`TokioScheduler`] — timers, background tasks, wall clock on Tokio.
//!
//! `Mailbox` and `RefreshHintSource` are not implemented here: the mailbox
//! is the engine's own API client over the [`ReqwestHttp`] seam (nothing
//! desktop-specific), and refresh hints are produced by the `crates/fuse`
//! operation core from FUSE-op TTL checks. This crate constructs no engine
//! and touches no webview — the desktop shell wires those in a later slice.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// The seam traits use native `async fn` (blueprint: single-writer engine
// pinned to one execution context, `!Send` futures). Implementing them is
// unremarkable; this mirrors the engine crate's own allowance.
#![allow(async_fn_in_trait)]

mod credential_store;
mod floor_store;
mod fs_util;
mod http;
mod paths;
mod record_transport;
mod scheduler;
mod snapshot_cache;
mod staging_store;

pub use credential_store::KeyringCredentialStore;
pub use floor_store::FileFloorStore;
pub use http::ReqwestHttp;
pub use paths::account_data_dir;
pub use record_transport::ReqwestRecordTransport;
pub use scheduler::TokioScheduler;
pub use snapshot_cache::FileSnapshotCache;
pub use staging_store::FileStagingStore;

#[cfg(feature = "test-support")]
pub use credential_store::FileCredentialStore;
