//! CipherBox stateful SDK.
//!
//! Provides stateful orchestration: sync daemon, write queue,
//! key material management, and device registry operations.
//! Mirrors @cipherbox/sdk TypeScript package.

pub mod client;
pub mod error;
pub mod queue;
pub mod registry;
pub mod state;
pub mod sync;

pub use client::CipherBoxSdkClient;
pub use error::SdkError;
pub use queue::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
pub use state::{KeyState, SyncStatus};
pub use sync::SyncDaemon;
