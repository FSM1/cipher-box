//! The Linux backend: kernel FUSE through the vendored `fuser`
//! (blueprint/desktop.md "Backends"). The wire itself is
//! [`crate::adapters::fuse`]; what is Linux's is the option set the mount is
//! made with and what the kernel does with the replies.

use std::io;
use std::path::Path;

use fuser::MountOption;

use crate::adapter::HostCapabilities;
use crate::adapters::fuse::{FuseMount, MountProfile};

/// Mount at `mountpoint`, which must already exist.
pub fn mount(mountpoint: &Path) -> io::Result<FuseMount> {
    FuseMount::at(mountpoint, profile())
}

/// The kernel caches attributes and honours reply TTLs, and `inval_inode` /
/// `inval_entry` correct it, so this backend keeps every cache the shared
/// [`crate::CacheTtls`] rule is willing to time.
fn profile() -> MountProfile {
    MountProfile {
        options: vec![
            MountOption::FSName("cipherbox".to_owned()),
            MountOption::DefaultPermissions,
            MountOption::NoSuid,
            MountOption::NoExec,
            MountOption::NoDev,
            MountOption::NoAtime,
        ],
        capabilities: HostCapabilities {
            push_invalidation: true,
            attribute_cache: true,
            // Case-sensitive presentation is the platform convention; the
            // engine's one strict comparator still decides collisions
            // (blueprint/desktop.md "Names and attributes").
            case_insensitive_lookup: false,
        },
        resumable_readdir: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vault the whole machine can read is not a trade for tidier teardown,
    /// so the mount admits its maker only — and carries nothing executable or
    /// setuid whatever a stored name suggests.
    #[test]
    fn the_mount_is_owner_only_and_carries_no_privileged_bits() {
        let options = profile().options;
        for refused in [
            MountOption::AllowOther,
            MountOption::AllowRoot,
            MountOption::AutoUnmount,
        ] {
            assert!(!options.contains(&refused), "{refused:?}");
        }
        for required in [
            MountOption::NoSuid,
            MountOption::NoExec,
            MountOption::NoDev,
            MountOption::DefaultPermissions,
        ] {
            assert!(options.contains(&required), "{required:?}");
        }
    }
}
