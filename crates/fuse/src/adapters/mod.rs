//! One adapter per mount technology, each a thin decoder over the shared
//! operation core.

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod fuse;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod stale;
