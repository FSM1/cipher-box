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
pub use projected::{KernelOp, Mounted, Projection};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod detached;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use detached::{KernelOp, Mounted, Projection};

/// What the mount woke the session with. Making the mount and serving it are
/// the two states of one thing, so they reach the session loop as one wake
/// source rather than contending for the projection.
pub enum FromMount {
    /// The kernel asked the mount for something.
    Op(KernelOp),
    /// The kernel session ended under a live app — an unmount from outside
    /// CipherBox. The mount status moved with no engine event behind it.
    Ended,
    /// The mounting thread reached its verdict.
    Landed(Mounted),
}

/// Whether this session projects the vault as a filesystem, and where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum MountStatus {
    /// The mount is still being made. The session serves reads throughout, so
    /// this is a state a status read lands in rather than waits out.
    Opening,
    /// The vault is projected, at this mount point.
    Mounted {
        /// The mount point.
        path: String,
    },
    /// The vault is not projected, and this is why. A mount failure never fails
    /// the session, so this is the only place it is ever said.
    Refused {
        /// Why there is no mount.
        reason: String,
    },
}

impl MountStatus {
    fn refused(reason: &str) -> Self {
        Self::Refused {
            reason: reason.to_owned(),
        }
    }
}
