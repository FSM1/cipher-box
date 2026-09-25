//! In-memory fakes, one per seam trait.
//!
//! Every fake is a cheap `Clone` handle over shared state: cloning models
//! "reopening" the same durable backing (the conformance kits' factory
//! contract) and lets a test keep an inspection handle to state it moved
//! into an engine.

mod adopter;
mod credential_store;
mod floor_store;
mod http;
mod mailbox;
mod name_registry;
mod received_share_store;
mod record_store;
mod scheduler;
mod snapshot_cache;
mod staging_store;

pub use adopter::{AdoptVerdict, ScriptedAdopter};
pub use credential_store::InMemoryCredentialStore;
pub use floor_store::{InMemoryFloorStore, SplitWriteFloorStore};
pub use http::ScriptedHttp;
pub use mailbox::{InMemoryMailbox, InMemoryMailboxHub};
pub use name_registry::InMemoryNameRegistry;
pub use received_share_store::InMemoryReceivedShareStore;
pub use record_store::{InMemoryRecordStore, SlotFillingRecordStore};
pub use scheduler::VirtualScheduler;
pub use snapshot_cache::InMemorySnapshotCache;
pub(crate) use staging_store::StagingContents;
pub use staging_store::{InMemoryStagingBackings, InMemoryStagingStore};
