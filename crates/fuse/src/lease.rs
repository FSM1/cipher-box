//! The exclusive claim one process holds on one spill directory.
//!
//! A directory whose lease can be taken is one no live process holds. The OS
//! releases the lock however the process ends, which is what makes a crashed
//! instance's directory reclaimable and a live one's untouchable.
//!
//! The lock file sits beside the directory it guards, not inside it: a claim
//! taken before the directory exists leaves no window in which a sibling sees
//! an unclaimed directory to sweep.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use fs4::{FileExt, TryLockError};

/// A held claim, released when it drops.
pub(crate) struct Lease {
    _lock: File,
}

/// Claim the lock file at `lock`, or `None` when a live process holds it.
pub(crate) fn claim(lock: &Path) -> io::Result<Option<Lease>> {
    let file = open_private(lock)?;
    match FileExt::try_lock(&file) {
        Ok(()) => Ok(Some(Lease { _lock: file })),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

#[cfg(unix)]
fn open_private(lock: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock)
}

/// Off unix the lock file inherits the parent's ACL. It holds no content —
/// only the lock the OS keeps against the open handle.
#[cfg(not(unix))]
fn open_private(lock: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_lease_refuses_a_second_claim_and_releases_on_drop() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let lock = dir.path().join("area.0.lock");

        let held = claim(&lock).expect("the lock file opens");
        assert!(held.is_some());
        assert!(
            claim(&lock)
                .expect("a second open is not an error")
                .is_none(),
            "a live claim is what stops a sweep",
        );
        drop(held);
        assert!(
            claim(&lock).expect("the lock file opens").is_some(),
            "a released claim leaves the directory reclaimable",
        );
    }
}
