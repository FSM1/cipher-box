//! The macOS backend: FUSE-T's SMB backend, reached through the vendored
//! `fuser` against FUSE-T's libfuse2 shim (blueprint/desktop.md "Backends" —
//! macFUSE stays rejected, the NFS backend abandoned unconditionally).
//!
//! The wire itself is [`crate::adapters::fuse`]; what is macOS's is the option
//! set, the freshness contract that option set buys, and the single-pass
//! `readdir` the smbfs client performs.

use std::io;
use std::path::Path;

use fuser::MountOption;

use crate::adapter::HostCapabilities;
use crate::adapters::fuse::{FuseMount, MountProfile};

/// FUSE-T defaults to its NFS backend, which is abandoned unconditionally
/// (FSM1/cipher-box-next#32) — and which serves no notifications at all, so a
/// mount that silently landed on it would cache a revoked vault forever.
const SMB_BACKEND: &str = "backend=smb";

/// The one option the SMB backend cannot be mounted without: smbfs otherwise
/// imposes a 3 s attribute floor and keeps cached data indefinitely
/// (blueprint/desktop.md "Freshness").
const NO_ATTR_CACHE: &str = "noattrcache";

/// Names cross the smbfs client in the encoding the client chose, and the
/// engine stores them as entered. Without this, a name typed on macOS would be
/// stored decomposed and the same name typed anywhere else composed — two
/// stored spellings the engine's comparator does not fold together
/// (blueprint/desktop.md "Names and attributes").
const NFC_NAMES: &str = "nfc";

/// Mount at `mountpoint`, which must already exist.
pub fn mount(mountpoint: &Path) -> io::Result<FuseMount> {
    FuseMount::at(mountpoint, profile())
}

/// `noattrcache` leaves the smbfs client with no attribute cache to time, and
/// the client ignores FUSE reply TTLs on this backend regardless — so there is
/// no attribute lifetime to freeze here, only push invalidation
/// (blueprint/desktop.md "Freshness"; FSM1/cipher-box-next#32).
fn profile() -> MountProfile {
    MountProfile {
        options: vec![
            MountOption::FSName("cipherbox".to_owned()),
            MountOption::CUSTOM(SMB_BACKEND.to_owned()),
            MountOption::CUSTOM(NO_ATTR_CACHE.to_owned()),
            MountOption::CUSTOM(NFC_NAMES.to_owned()),
            MountOption::DefaultPermissions,
            MountOption::NoSuid,
            MountOption::NoExec,
            MountOption::NoDev,
        ],
        capabilities: HostCapabilities {
            push_invalidation: true,
            attribute_cache: false,
            // Case-sensitive presentation is the platform convention; the
            // engine's one strict comparator still decides collisions
            // (blueprint/desktop.md "Names and attributes").
            case_insensitive_lookup: false,
        },
        resumable_readdir: false,
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use cipherbox_engine::SyncTimingProfile;

    use super::*;
    use crate::adapter::CacheTtls;

    /// Without it the smbfs client imposes a 3 s attribute floor and serves
    /// cached data that nothing revalidates — the hard requirement this backend
    /// ships under.
    #[test]
    fn the_mount_sets_noattrcache() {
        assert!(
            profile()
                .options
                .contains(&MountOption::CUSTOM(NO_ATTR_CACHE.to_owned()))
        );
    }

    /// The suppressed cache has to reach the operation core, or it would go on
    /// handing this backend attribute lifetimes the client already ignores.
    #[test]
    fn a_suppressed_attribute_cache_is_given_no_lifetime() {
        let capabilities = profile().capabilities;
        assert!(!capabilities.attribute_cache);
        for timing in [SyncTimingProfile::PRODUCTION, SyncTimingProfile::CI] {
            let ttls = CacheTtls::for_host(&capabilities, &timing);
            assert_eq!(ttls.attr, Duration::ZERO);
            assert!(!ttls.entry.is_zero(), "name lookups are still cached");
        }
    }

    /// Uninvalidated cached data on this backend never revalidates, so a mount
    /// that could not push would be serving a stale vault forever — and FUSE-T
    /// serves notifications on the SMB backend only, so the declared capability
    /// and the selected backend are one claim, not two.
    #[test]
    fn the_backend_pushes_invalidation_and_is_the_one_that_can() {
        let profile = profile();
        assert!(profile.capabilities.push_invalidation);
        assert!(
            profile
                .options
                .contains(&MountOption::CUSTOM(SMB_BACKEND.to_owned())),
            "FUSE-T mounts its notification-less NFS backend unless told otherwise"
        );
    }

    /// One spelling of a name reaches the engine from every platform, or the
    /// strict comparator sees two names where a user sees one.
    #[test]
    fn names_arrive_composed() {
        assert!(
            profile()
                .options
                .contains(&MountOption::CUSTOM(NFC_NAMES.to_owned()))
        );
    }

    /// The smbfs client walks a directory in one pass and never resumes at a
    /// cookie, so a listing kept for it could only answer a request that never
    /// comes.
    #[test]
    fn a_directory_walk_is_single_pass() {
        assert!(!profile().resumable_readdir);
    }

    /// Same owner-only posture as every other backend: no `allow_other`, and
    /// nothing executable or setuid whatever a stored name suggests.
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
        for required in [MountOption::NoSuid, MountOption::NoExec, MountOption::NoDev] {
            assert!(options.contains(&required), "{required:?}");
        }
    }
}
