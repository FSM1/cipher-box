//! The vault's mount across the session lifecycle (blueprint/desktop.md
//! "Lifecycle").
//!
//! [`Projection`] owns the session's engine: mounted, it holds the operation
//! core the engine lives inside; unmounted, it holds the engine directly. A
//! platform `crates/fuse` has no host adapter for takes the second shape.

use serde::Serialize;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod projected;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use projected::{KernelOp, Projection};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod detached;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use detached::{KernelOp, Projection};

/// Whether this session projects the vault as a filesystem, and where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MountStatus {
    /// The mount point, once a mount is live.
    pub path: Option<String>,
    /// Why this session has no mount. A mount failure never fails the session,
    /// so this is the only place it is ever said.
    pub refusal: Option<String>,
}

impl MountStatus {
    /// The vault is not projected, and `refusal` is why. A status with neither
    /// a path nor a reason is the silent failure this line exists to prevent.
    fn refused(refusal: &str) -> Self {
        Self {
            path: None,
            refusal: Some(refusal.to_owned()),
        }
    }
}
