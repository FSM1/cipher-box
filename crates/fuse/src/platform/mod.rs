//! Platform-specific mount/unmount implementations.
//!
//! Each platform module provides mount and unmount functions gated behind
//! the appropriate feature flag.

#[cfg(all(feature = "fuse", target_os = "macos"))]
pub mod macos;

#[cfg(all(feature = "fuse", target_os = "linux"))]
pub mod linux;

#[cfg(feature = "winfsp")]
pub mod windows;
