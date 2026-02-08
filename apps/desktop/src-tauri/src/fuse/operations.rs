//! FUSE filesystem trait implementation for CipherVaultFS.
//!
//! Implements read operations: init, lookup, getattr, readdir, open, read, release, statfs, access.
//! Write operations are deferred to plan 09-06.
//!
//! IMPORTANT: All async operations spawn tasks on the tokio runtime and never block the FUSE thread.
//! This prevents Finder from hanging during network operations (RESEARCH.md pitfall 3).

#[cfg(feature = "fuse")]
use fuser::Filesystem;

// Filesystem trait implementation is added in Task 2.
// This file is created now to satisfy the module declaration.
