//! CipherBox stateful SDK.
//!
//! Provides stateful orchestration: sync daemon, write queue,
//! key material management, and device registry operations.
//! Mirrors @cipherbox/sdk TypeScript package.

pub mod client;
pub mod error;
pub mod floor_store;
pub mod listing;
pub mod queue;
pub mod registry;
pub mod rotation;
pub mod state;
pub mod sync;

pub use client::CipherBoxSdkClient;
pub use error::SdkError;
pub use floor_store::JsonSidecarFloorStore;
pub use listing::{
    list_folder, list_shared_folder, FetchedRecord, FolderUpdatedCallback, FolderUpdatedEvent,
    ListingError, NodeFetcher, ResolvedChild,
};
pub use queue::{
    JournalEntry, JournalEntryStatus, JournalOp, WriteQueue, JOURNAL_GC_MAX_AGE_DAYS,
    JOURNAL_GC_MAX_SIZE_BYTES, MAX_JOURNAL_PAYLOAD_BYTES,
};
pub use rotation::{
    has_covering_grant, maybe_rotate_on_scope_exit, CoverageParams, EnforceResolvedParams,
    HighWaterStore, LocalGrantRecord, RotationError, RotationHighWater, ScopeExitResult,
};
pub use state::{KeyState, SyncStatus};
pub use sync::SyncDaemon;
