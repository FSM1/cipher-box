//! The desktop leg of the measured storage policy (CONTEXT.md "Storage
//! policy"; blueprint/engine.md "Host seams").
//!
//! Web measures origin headroom through `navigator.storage.estimate()`;
//! desktop measures the free bytes a non-privileged user has on the volume its
//! engine data dir sits on. Both hand one figure to
//! [`StoragePolicy::measured`], which owns the split.

use std::path::Path;

use cipherbox_engine::{StoragePlatform, StoragePolicy};

/// The storage split for a device whose engine data lives under `data_dir`.
///
/// A volume this host cannot measure yields [`StoragePolicy::UNMEASURED`] —
/// never a fabricated figure, so a refused write says "unknown" rather than
/// "full". The split never floors up.
///
/// `data_dir` need not exist yet: a directory is created inside its nearest
/// existing ancestor, so that ancestor's volume is the one the split applies
/// to.
pub fn measured_storage_policy(data_dir: &Path) -> StoragePolicy {
    match volume_free_bytes(data_dir) {
        Some(free_bytes) => StoragePolicy::measured(StoragePlatform::DESKTOP, free_bytes),
        None => StoragePolicy::UNMEASURED,
    }
}

/// Free bytes on the volume holding the nearest ancestor of `path` that exists.
fn volume_free_bytes(path: &Path) -> Option<u64> {
    path.ancestors()
        .find_map(|ancestor| fs4::available_space(ancestor).ok())
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
}
