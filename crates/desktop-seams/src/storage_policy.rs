//! The desktop leg of the measured storage policy (CONTEXT.md "Storage
//! policy"): the free bytes a non-privileged user has on the volume the engine
//! data dir sits on. The split itself is [`StoragePolicy::measured`]'s.

use std::io::ErrorKind;
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
///
/// Only a not-found climbs. A path that exists but will not measure is
/// unmeasured, never its parent's volume: reporting the root filesystem's free
/// space for an unreadable mount is exactly the fabricated figure the policy
/// refuses to invent.
fn volume_free_bytes(path: &Path) -> Option<u64> {
    for ancestor in path.ancestors() {
        match fs4::available_space(ancestor) {
            Ok(free_bytes) => return Some(free_bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return None,
        }
    }
    None
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
        let free = volume_free_bytes(dir.path()).expect("the temp volume measures");
        assert_eq!(
            policy,
            StoragePolicy::measured(StoragePlatform::DESKTOP, free),
            "the seam contributes the measurement only; the split is the engine's"
        );
    }

    #[test]
    fn a_data_dir_that_does_not_exist_yet_measures_the_volume_it_will_land_on() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let unborn = dir.path().join("cipherbox").join("acct-42");
        assert!(!unborn.exists());

        assert_eq!(
            measured_storage_policy(&unborn),
            measured_storage_policy(dir.path()),
            "the nearest existing ancestor is the volume the dir will be created on"
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

    /// The climb is for a directory that does not exist yet. A path that does
    /// exist and still will not measure must not be answered with some other
    /// volume's free space — that is the fabricated figure the policy refuses.
    #[test]
    fn a_path_that_exists_but_will_not_measure_never_reports_another_volume() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let file = dir.path().join("not-a-directory");
        std::fs::write(&file, b"x").expect("the file writes");
        // A component under a regular file exists on no volume, and statvfs
        // answers ENOTDIR rather than ENOENT.
        let under_a_file = file.join("child");

        assert_eq!(
            volume_free_bytes(&under_a_file),
            None,
            "a refusal that is not a missing directory stops the climb"
        );
    }
}
