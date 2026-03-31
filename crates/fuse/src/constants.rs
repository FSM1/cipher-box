//! Shared constants for the CipherBox FUSE filesystem.
//!
//! These constants are used by both macOS (fuser) and Windows (WinFsp)
//! filesystem implementations.

use std::time::Duration;

/// Total storage quota in bytes (500 MiB).
pub const QUOTA_BYTES: u64 = 500 * 1024 * 1024;

/// Default maximum versions per file (used as fallback if settings not loaded).
/// User-configurable value is stored in CipherBoxFS.max_versions_per_file.
pub const DEFAULT_MAX_VERSIONS_PER_FILE: usize = 10;

/// Default version cooldown in milliseconds (used as fallback if settings not loaded).
/// User-configurable value is stored in CipherBoxFS.version_cooldown_ms.
pub const DEFAULT_VERSION_COOLDOWN_MS: u64 = 15 * 60 * 1000;

/// Maximum time for file content download in open().
/// Large files (e.g., 64MB) can take 30-60s from staging IPFS.
/// This blocks the NFS thread, but since the content is cached after
/// open(), all subsequent reads are instant.
pub const CONTENT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
