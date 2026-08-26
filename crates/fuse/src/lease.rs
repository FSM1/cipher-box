//! The exclusive claim one process holds on one spill directory.
//!
//! Opening a spill area sweeps what is in it, so the sweep needs an ownership
//! check or two instances over one account delete each other's live spill
//! files. A directory whose lease can be taken is one no live process holds,
//! and that is the only kind a sweep ever touches.

use std::fs::OpenOptions;
use std::io;
use std::path::Path;

/// The lock file inside a spill directory. Holding it open under an exclusive
/// OS lock is the lease; the kernel releases it however the process ends, which
/// is what makes a crashed instance's directory reclaimable.
const LOCK_FILE: &str = "lock";

/// Whether `name` is the lease itself rather than a spill file, so a sweep of
/// this process's own directory leaves its claim standing.
pub(crate) fn is_lock_file(name: &std::ffi::OsStr) -> bool {
    name == LOCK_FILE
}

#[cfg(unix)]
mod imp {
    use super::*;
    use nix::errno::Errno;
    use nix::fcntl::{Flock, FlockArg};
    use std::fs::File;
    use std::os::unix::fs::OpenOptionsExt;

    /// A held claim. The lock goes when this drops, whether that is a release
    /// or a crash.
    pub(crate) struct Lease(#[allow(dead_code)] Flock<File>);

    pub(crate) fn claim(dir: &Path) -> io::Result<Option<Lease>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join(LOCK_FILE))?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(held) => Ok(Some(Lease(held))),
            Err((_, Errno::EWOULDBLOCK | Errno::EACCES)) => Ok(None),
            Err((_, errno)) => Err(io::Error::from(errno)),
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::fs::File;
    use std::os::windows::fs::OpenOptionsExt;

    /// Opened denying every share mode, so a second opener is refused for as
    /// long as this handle lives.
    const SHARE_NOTHING: u32 = 0;
    const ERROR_SHARING_VIOLATION: i32 = 32;

    pub(crate) struct Lease(#[allow(dead_code)] File);

    pub(crate) fn claim(dir: &Path) -> io::Result<Option<Lease>> {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(SHARE_NOTHING)
            .open(dir.join(LOCK_FILE))
        {
            Ok(file) => Ok(Some(Lease(file))),
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

pub(crate) use imp::{Lease, claim};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_lease_refuses_a_second_claim_and_releases_on_drop() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let held = claim(dir.path()).expect("the lock file opens");
        assert!(held.is_some());
        assert!(
            claim(dir.path())
                .expect("a second open is not an error")
                .is_none(),
            "a live claim is what stops a sweep",
        );
        drop(held);
        assert!(
            claim(dir.path()).expect("the lock file opens").is_some(),
            "a released claim leaves the directory reclaimable",
        );
    }
}
