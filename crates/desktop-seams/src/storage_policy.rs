//! The desktop leg of the measured storage policy (CONTEXT.md "Storage
//! policy"): the free bytes a non-privileged user has on the volume the engine
//! data dir sits on. The split itself is [`StoragePolicy::measured`]'s.

use std::io::{self, ErrorKind};
use std::path::Path;

use cipherbox_engine::{StoragePlatform, StoragePolicy};

/// The storage split for a device whose engine data lives under `data_dir`.
///
/// A volume this host cannot measure yields [`StoragePolicy::UNMEASURED`] —
/// never a fabricated figure, so a refused write says "unknown" rather than
/// "full".
pub fn measured_storage_policy(data_dir: &Path) -> StoragePolicy {
    match volume_free_bytes(data_dir) {
        Some(free_bytes) => StoragePolicy::measured(StoragePlatform::DESKTOP, free_bytes),
        None => StoragePolicy::UNMEASURED,
    }
}

/// Free bytes on the volume holding `path`, climbing past a path that does not
/// exist yet — a directory is created inside its nearest existing ancestor, so
/// that ancestor names the volume the split applies to.
fn volume_free_bytes(path: &Path) -> Option<u64> {
    for ancestor in path.ancestors() {
        match fs4::available_space(ancestor) {
            Ok(free_bytes) => return Some(free_bytes),
            Err(error) if climbs_past(&error) => continue,
            Err(_) => return None,
        }
    }
    None
}

/// Whether a failed measurement means "nothing is there yet", the one refusal a
/// climb to the parent answers. Any other refusal is a volume this host cannot
/// measure, and climbing past it would answer with a different volume's free
/// space — the fabricated figure the policy refuses to invent.
fn climbs_past(error: &io::Error) -> bool {
    error.kind() == ErrorKind::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_engine::Headroom;

    #[test]
    fn a_real_volume_yields_a_measured_desktop_split() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let policy = measured_storage_policy(dir.path());

        assert_eq!(policy.headroom, Headroom::Measured);
        assert_eq!(
            policy.staging_cap_bytes,
            StoragePlatform::DESKTOP.staging_cap_bytes,
            "a refusal must be able to name the desktop platform cap"
        );
    }

    #[test]
    fn a_data_dir_that_does_not_exist_yet_still_measures() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let unborn = dir.path().join("cipherbox").join("acct-42");
        assert!(!unborn.exists());

        assert_eq!(
            measured_storage_policy(&unborn).headroom,
            Headroom::Measured,
            "without the climb a dir that is not there yet would measure nothing"
        );
    }

    #[test]
    fn a_path_naming_no_volume_is_unmeasured_rather_than_full() {
        let policy = measured_storage_policy(Path::new(""));

        assert_eq!(policy, StoragePolicy::UNMEASURED);
        assert_eq!(
            policy.headroom,
            Headroom::Unmeasured,
            "an unmeasurable volume must stay distinguishable from a full one"
        );
    }

    /// The climb exists for a directory that is not there yet. Every other
    /// refusal stops it: answering with the parent volume's free space would be
    /// the fabricated figure the policy refuses to invent.
    ///
    /// Driven off the classification rather than a contrived path, because
    /// which errno a host raises for an unmeasurable volume is the host's
    /// business and differs across the three desktop targets.
    #[test]
    fn only_a_path_that_is_not_there_yet_climbs_to_its_parent() {
        assert!(climbs_past(&io::Error::from(ErrorKind::NotFound)));

        for refusal in [
            ErrorKind::PermissionDenied,
            ErrorKind::NotADirectory,
            ErrorKind::InvalidInput,
            ErrorKind::Other,
        ] {
            assert!(
                !climbs_past(&io::Error::from(refusal)),
                "{refusal:?} is a volume that will not measure, not a missing one"
            );
        }
    }
}
