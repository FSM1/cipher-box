//! Shared constants for the CipherBox FUSE filesystem.
//!
//! These constants are used by both macOS (fuser) and Windows (WinFsp)
//! filesystem implementations.

use std::time::Duration;

/// Total storage quota in bytes (500 MiB).
pub const QUOTA_BYTES: u64 = 500 * 1024 * 1024;

/// Maximum number of past versions to keep per file.
pub const MAX_VERSIONS_PER_FILE: usize = 10;

/// Cooldown period for desktop FUSE version creation (15 minutes in milliseconds).
/// Only creates a new version entry if the most recent version is older than this.
pub const VERSION_COOLDOWN_MS: u64 = 15 * 60 * 1000;

/// Maximum time for file content download in open().
/// Large files (e.g., 64MB) can take 30-60s from staging IPFS.
/// This blocks the NFS thread, but since the content is cached after
/// open(), all subsequent reads are instant.
pub const CONTENT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
