//! In-memory fakes, one per seam trait.
//!
//! Every fake is a cheap `Clone` handle over shared state: cloning models
//! "reopening" the same durable backing (the conformance kits' factory
//! contract) and lets a test keep an inspection handle to state it moved
//! into an engine.

mod credential_store;
mod floor_store;
mod http;
mod mailbox;
mod received_share_store;
mod record_store;
mod scheduler;
mod snapshot_cache;
mod staging_store;

pub use credential_store::InMemoryCredentialStore;
pub use floor_store::InMemoryFloorStore;
pub use http::ScriptedHttp;
pub use mailbox::{InMemoryMailbox, InMemoryMailboxHub};
pub use received_share_store::InMemoryReceivedShareStore;
pub use record_store::InMemoryRecordStore;
pub use scheduler::VirtualScheduler;
pub use snapshot_cache::InMemorySnapshotCache;
pub use staging_store::InMemoryStagingStore;
