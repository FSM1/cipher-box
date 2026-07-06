//! CipherBox stateful SDK.
//!
//! Provides stateful orchestration: sync daemon, write queue,
//! key material management, and device registry operations.
//! Mirrors @cipherbox/sdk TypeScript package.

pub mod client;
pub mod error;
pub mod queue;
pub mod registry;
pub mod rotation;
pub mod state;
pub mod sync;

pub use client::CipherBoxSdkClient;
pub use error::SdkError;
pub use queue::{
    JournalEntry, JournalEntryStatus, JournalOp, WriteQueue, JOURNAL_GC_MAX_AGE_DAYS,
    JOURNAL_GC_MAX_SIZE_BYTES, MAX_JOURNAL_PAYLOAD_BYTES,
};
pub use rotation::{EnforceResolvedParams, HighWaterStore, RotationError, RotationHighWater};
pub use state::{KeyState, SyncStatus};
pub use sync::SyncDaemon;
