//! The macOS backend: FUSE-T's SMB backend, reached through the vendored
//! `fuser` against FUSE-T's libfuse2 shim (blueprint/desktop.md "Backends" —
//! macFUSE stays rejected, the NFS backend abandoned unconditionally).
//!
//! The wire and every mount's floor are [`crate::adapters::fuse`]; what is
//! macOS's is the backend it selects and the freshness contract that selection
//! buys.

use std::io;
use std::path::Path;

use cipherbox_engine::entropy::{Entropy, EntropyError, OsEntropy, fresh_bytes};
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

/// Each mount's FUSE-T `location`, which names its Bonjour service and host
/// (blueprint/desktop.md "FUSE-T mount name").
pub(crate) const LOCATION_PREFIX: &str = "CipherBox-";

/// Random bytes in a location: 8 hex characters, far inside a DNS label's 63.
pub(crate) const LOCATION_BYTES: usize = 4;

/// Mount at `mountpoint`, which is prepared first.
pub fn mount(mountpoint: &Path) -> io::Result<FuseMount> {
    let profile = member_profile(&mut OsEntropy).map_err(io::Error::other)?;
    FuseMount::at(mountpoint, profile)
}

/// The profile a member's mount is made under, with a location of its own.
fn member_profile(entropy: &mut dyn Entropy) -> Result<MountProfile, EntropyError> {
    Ok(profile(Some(&location(entropy)?)))
}

/// Mount under FUSE-T's default, shared name: the comparison leg of the
/// mount-cadence probe, never a member's mount.
#[cfg(feature = "e2e-hook")]
pub fn mount_under_the_shared_name(mountpoint: &Path) -> io::Result<FuseMount> {
    FuseMount::at(mountpoint, profile(None))
}

/// A location this machine's earlier mounts did not use.
pub(crate) fn location(entropy: &mut dyn Entropy) -> Result<String, EntropyError> {
    let drawn: [u8; LOCATION_BYTES] = fresh_bytes(entropy, "the mount's location")?;
    let suffix: String = drawn.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("{LOCATION_PREFIX}{suffix}"))
}

fn profile(location: Option<&str>) -> MountProfile {
    let mut options = vec![
        MountOption::CUSTOM(SMB_BACKEND.to_owned()),
        MountOption::CUSTOM(NO_ATTR_CACHE.to_owned()),
        MountOption::CUSTOM(NFC_NAMES.to_owned()),
    ];
    if let Some(location) = location {
        options.push(MountOption::CUSTOM(format!("location={location}")));
    }
    MountProfile {
        options,
        capabilities: HostCapabilities {
            push_invalidation: true,
            attribute_cache: false,
            case_insensitive_lookup: false,
        },
    }
}

/// An entropy source that draws the same bytes every time, so a test knows the
/// location it expects.
#[cfg(test)]
pub(crate) struct FixedEntropy(pub [u8; LOCATION_BYTES]);

#[cfg(test)]
impl Entropy for FixedEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        dest.copy_from_slice(&self.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use cipherbox_engine::SyncTimingProfile;

    use super::*;
    use crate::adapter::CacheTtls;

    const PROBE: &str = "CipherBox-00c0ffee";

    /// Two mounts draw two locations, so neither resolves through records
    /// macOS cached for the other.
    #[test]
    fn each_mount_gets_a_location_of_its_own() {
        let first = location(&mut OsEntropy).expect("entropy");
        let second = location(&mut OsEntropy).expect("entropy");
        assert_ne!(first, second);
        for drawn in [&first, &second] {
            let suffix = drawn.strip_prefix(LOCATION_PREFIX).expect("the prefix");
            assert_eq!(suffix.len(), 2 * LOCATION_BYTES);
            assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
            // One DNS label, with room left for FUSE-T's collision suffix.
            assert!(drawn.len() + "-99".len() <= 63);
        }
    }

    /// The profile a member's mount is made under carries the drawn location.
    #[test]
    fn a_member_mount_passes_its_location() {
        let profile = member_profile(&mut FixedEntropy([0x00, 0xc0, 0xff, 0xee])).expect("entropy");
        assert!(
            profile
                .options
                .contains(&MountOption::CUSTOM(format!("location={PROBE}")))
        );
    }

    /// Without it the smbfs client imposes a 3 s attribute floor and serves
    /// cached data that nothing revalidates — the hard requirement this backend
    /// ships under.
    #[test]
    fn the_mount_sets_noattrcache() {
        assert!(
            profile(Some(PROBE))
                .options
                .contains(&MountOption::CUSTOM(NO_ATTR_CACHE.to_owned()))
        );
    }

    /// The suppressed cache has to reach the operation core, or it would go on
    /// handing this backend attribute lifetimes the client already ignores.
    #[test]
    fn a_suppressed_attribute_cache_is_given_no_lifetime() {
        let capabilities = profile(Some(PROBE)).capabilities;
        assert!(!capabilities.attribute_cache);
        let ttls = CacheTtls::for_host(&capabilities, &SyncTimingProfile::PRODUCTION);
        assert_eq!(ttls.attr, Duration::ZERO);
    }

    /// Uninvalidated cached data on this backend never revalidates, so a mount
    /// that could not push would be serving a stale vault forever — and FUSE-T
    /// serves notifications on the SMB backend only, so the declared capability
    /// and the selected backend are one claim, not two.
    #[test]
    fn the_backend_pushes_invalidation_and_is_the_one_that_can() {
        let profile = profile(Some(PROBE));
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
            profile(Some(PROBE))
                .options
                .contains(&MountOption::CUSTOM(NFC_NAMES.to_owned()))
        );
    }
}
