//! The macOS mount table, read without a call into any mounted filesystem.
//!
//! `crates/fuse` is `#![forbid(unsafe_code)]`, and no safe wrapper of
//! `getfsstat` exists, so the one FFI call the FUSE-T unmount watch needs is
//! here instead. A read through the mount point is not a substitute: a hung
//! FUSE-T volume blocks it.

#![warn(missing_docs)]

use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
mod apple;

#[cfg(target_os = "macos")]
pub use apple::mounts;

/// One filesystem the kernel has mounted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mounted {
    /// Where it is mounted.
    pub on: PathBuf,
    /// Which mount it is.
    pub identity: Identity,
}

/// What tells one mount from another mount at the same path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The kernel's id for the mounted filesystem.
    pub fsid: [i32; 2],
    /// The filesystem type, such as `smbfs`.
    pub fs_type: OsString,
    /// What is mounted, such as the SMB share.
    pub from: OsString,
}
