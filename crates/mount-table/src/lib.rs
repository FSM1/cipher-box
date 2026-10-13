//! The macOS mount table, read without a call into any mounted filesystem.
//!
//! `crates/fuse` is `#![forbid(unsafe_code)]`, and no safe wrapper of
//! `getfsstat` exists, so the one FFI call the FUSE-T unmount watch needs is
//! here instead. A read through the mount point is not a substitute: a hung
//! FUSE-T volume blocks it.

#![warn(missing_docs)]

#[cfg(target_os = "macos")]
mod apple;

#[cfg(target_os = "macos")]
pub use apple::mount_points;
