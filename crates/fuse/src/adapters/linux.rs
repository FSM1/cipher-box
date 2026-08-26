//! The Linux backend: kernel FUSE through the vendored `fuser`
//! (blueprint/desktop.md "Backends"). The wire and every mount's floor are
//! [`crate::adapters::fuse`]; what is Linux's is what it adds to them.

use std::io;
use std::path::Path;

use fuser::MountOption;

use crate::adapter::HostCapabilities;
use crate::adapters::fuse::{FuseMount, MountProfile};

/// Mount at `mountpoint`, which is prepared first.
pub fn mount(mountpoint: &Path) -> io::Result<FuseMount> {
    FuseMount::at(mountpoint, profile())
}

/// The kernel caches attributes and honours reply TTLs, and `inval_inode` /
/// `inval_entry` correct it, so this backend keeps every cache the shared
/// [`crate::CacheTtls`] rule is willing to time.
fn profile() -> MountProfile {
    MountProfile {
        options: vec![MountOption::NoAtime],
        capabilities: HostCapabilities {
            push_invalidation: true,
            attribute_cache: true,
            case_insensitive_lookup: false,
        },
    }
}
