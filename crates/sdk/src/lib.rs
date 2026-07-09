//! CipherBox stateful SDK.
//!
//! Provides stateful orchestration: sync daemon, write queue,
//! key material management, and device registry operations.
//! Mirrors @cipherbox/sdk TypeScript package.

pub mod adapter;
pub mod client;
pub mod emit;
pub mod error;
pub mod floor_store;
pub mod listing;
pub mod queue;
pub mod registry;
pub mod rotation;
pub mod state;
pub mod sync;

pub use adapter::{new_journal_high_water, ApiNodeFetcher};
pub use client::CipherBoxSdkClient;
pub use emit::{
    build_child_refs, build_file_emission, build_folder_emission, create_file_node,
    create_folder_node, FileEmission, FolderEmission, TeeEnrollment,
};
pub use error::SdkError;
pub use floor_store::{CombinedFloorRecord, JsonSidecarFloorStore};
pub use listing::{
    fetch_node_gated, list_folder, list_folder_owned, list_shared_folder, FetchedRecord,
    FolderUpdatedCallback, FolderUpdatedEvent, ListingError, NodeFetcher, ResolvedChild,
    ResolvedOwnedChild,
};
pub use queue::{
    JournalEntry, JournalEntryStatus, JournalOp, WriteQueue, JOURNAL_GC_MAX_AGE_DAYS,
    JOURNAL_GC_MAX_SIZE_BYTES, MAX_JOURNAL_PAYLOAD_BYTES,
};
pub use rotation::{
    has_covering_grant, maybe_rotate_on_scope_exit, rotate_one, rotate_read_from_node,
    rotate_read_from_node_with_root_children, CommittedRotation, CoverageParams,
    EnforceResolvedParams, HighWaterStore, LocalGrantRecord, PublishOutcome, ResolvedRecord,
    RotateOneOutcome, RotateReadResult, RotationDeps, RotationError, RotationHighWater,
    RotationJobRecord, RotationStatus, ScopeExitResult,
};
pub use state::{KeyState, SyncStatus};
pub use sync::SyncDaemon;
