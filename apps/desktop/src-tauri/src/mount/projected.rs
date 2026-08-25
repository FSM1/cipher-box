//! The vault projected as a filesystem, on the platforms `crates/fuse` has a
//! host adapter for.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cipherbox_engine::{Engine, Event};
use cipherbox_fuse::{CacheBudget, FuseInvalidator, FuseMount, OperationCore, SpillArea};

use super::MountStatus;
use crate::engine::DesktopSeamTypes;

pub use cipherbox_fuse::KernelOp;

/// Shown once the kernel session has ended under a live app — an unmount from
/// a terminal or Finder. The inode map is per mount session, so the vault is
/// projected again by signing in again, not by re-mounting under it.
const ENDED: &str = "the vault was unmounted outside CipherBox; sign out and back in to mount it";

/// The vault's mount point: `~/CipherBox`, the name v1 taught members to look
/// for.
fn mount_point(home_dir: &Path) -> PathBuf {
    home_dir.join("CipherBox")
}

/// The session's engine, and the filesystem it is projected through.
pub enum Projection {
    /// No mount: the engine stands alone, and `refusal` is why the vault is not
    /// also a filesystem.
    Detached {
        engine: Box<Engine<DesktopSeamTypes>>,
        refusal: String,
    },
    /// The vault is projected through `core`. `mount` empties when the kernel
    /// session ends; the engine goes on running inside the core either way.
    Projected {
        core: Box<OperationCore<DesktopSeamTypes, FuseInvalidator>>,
        mount: Option<FuseMount>,
        at: PathBuf,
    },
}

impl Projection {
    /// Mounts the vault for a session that has already started, or hands back
    /// an engine that stands alone and the reason it does.
    pub fn open(engine: Engine<DesktopSeamTypes>, home_dir: &Path, account_dir: &Path) -> Self {
        let at = mount_point(home_dir);
        match mount(&at, account_dir) {
            Ok((mount, spill)) => Self::Projected {
                core: Box::new(OperationCore::new(
                    engine,
                    mount.invalidator(),
                    CacheBudget::PRODUCTION,
                    spill,
                )),
                mount: Some(mount),
                at,
            },
            Err(refusal) => Self::Detached {
                engine: Box::new(engine),
                refusal,
            },
        }
    }

    /// The session's one engine, wherever it is being held.
    pub fn engine_mut(&mut self) -> &mut Engine<DesktopSeamTypes> {
        match self {
            Self::Detached { engine, .. } => engine,
            Self::Projected { core, .. } => core.engine_mut(),
        }
    }

    pub fn status(&self) -> MountStatus {
        match self {
            Self::Detached { refusal, .. } => MountStatus::refused(refusal),
            Self::Projected { mount: None, .. } => MountStatus::refused(ENDED),
            Self::Projected { at, .. } => MountStatus {
                path: Some(at.display().to_string()),
                refusal: None,
            },
        }
    }

    /// The next kernel operation. Never resolves without a live mount, so a
    /// host may wait on it beside its other wake sources whether or not this
    /// session projects anything.
    pub async fn next_op(&mut self) -> KernelOp {
        loop {
            let Self::Projected { core, mount, .. } = self else {
                return core::future::pending().await;
            };
            let Some(live) = mount.as_mut() else {
                return core::future::pending().await;
            };
            match live.next_op().await {
                Some(op) => return op,
                // The kernel session is over: the handles and cached plaintext
                // it held go, and this session projects nothing from here.
                None => {
                    core.unmount();
                    *mount = None;
                }
            }
        }
    }

    /// Answer one operation from the operation core.
    pub async fn answer(&mut self, op: KernelOp) {
        if let Self::Projected {
            core,
            mount: Some(mount),
            ..
        } = self
        {
            mount.answer(core, op).await;
        }
    }

    /// Fold one engine event into the kernel's caches — the push invalidation a
    /// background reconcile has no callback path to announce itself on
    /// (blueprint/desktop.md "Freshness").
    pub async fn absorb(&mut self, event: &Event) {
        if let Self::Projected { core, .. } = self {
            // A render that refused leaves the kernel holding what it has until
            // its TTLs expire; the next snapshot event renders again.
            let _ = core.absorb_event(event).await;
        }
    }

    /// Ends the session's projection: quiesce the adapter, unmount, then let
    /// the engine stop (blueprint/desktop.md "Lifecycle").
    pub fn tear_down(self) {
        let Self::Projected {
            mut core,
            mut mount,
            ..
        } = self
        else {
            return;
        };
        if let Some(mount) = mount.as_mut() {
            mount.quiesce();
        }
        drop(mount);
        core.unmount();
    }
}

/// Prepare the mount point, open the spill area, and mount. The spill area
/// comes first: a mount with nowhere to spill would have to be torn down again.
fn mount(at: &Path, account_dir: &Path) -> Result<(FuseMount, SpillArea), String> {
    prepare(at)
        .map_err(|error| format!("{} cannot be mounted on: {error}", at.display()))
        .and_then(|()| {
            SpillArea::production(account_dir)
                .map_err(|error| format!("the mount has nowhere to spill writes: {error}"))
        })
        .and_then(|spill| {
            platform_mount(at)
                .map(|mount| (mount, spill))
                .map_err(|error| format!("the vault could not be mounted: {error}"))
        })
}

/// Make `at` fit to mount on: a private, empty directory.
///
/// v1 emptied whatever it found here. Deleting a member's files is not a trade
/// for a tidier mount, so anything already in the way is refused instead — and
/// a mount refusal costs the session nothing.
fn prepare(at: &Path) -> io::Result<()> {
    match fs::symlink_metadata(at) {
        Ok(found) => {
            // Resolved by the mount, not by this check: a link here would
            // project the vault somewhere the member never chose.
            if found.file_type().is_symlink() {
                return Err(io::Error::other("it is a symbolic link"));
            }
            if !found.is_dir() {
                return Err(io::Error::other("it is not a directory"));
            }
            if fs::read_dir(at)?.next().is_some() {
                return Err(io::Error::other("it is not empty"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(at)?,
        Err(error) => return Err(error),
    }
    restrict(at)
}

/// Owner-only, matching what the mount itself admits: the directory is visible
/// before and after the mount, and a wider one invites company to the vault's
/// front door.
fn restrict(at: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(at, fs::Permissions::from_mode(0o700))
}

#[cfg(target_os = "linux")]
fn platform_mount(at: &Path) -> io::Result<FuseMount> {
    cipherbox_fuse::linux::mount(at)
}

#[cfg(target_os = "macos")]
fn platform_mount(at: &Path) -> io::Result<FuseMount> {
    cipherbox_fuse::macos::mount(at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(at: &Path) -> u32 {
        fs::metadata(at)
            .expect("a prepared directory")
            .permissions()
            .mode()
            & 0o777
    }

    /// The mount point is made on demand, and made private: a member who has
    /// never mounted before has no `~/CipherBox` for this to find.
    #[test]
    fn a_missing_mount_point_is_created_owner_only() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = mount_point(home.path());

        prepare(&at).expect("a missing mount point is made");
        assert!(at.is_dir());
        assert_eq!(mode(&at), 0o700);
    }

    /// A mount point left over from a previous session is reused, and its
    /// permissions are brought back to owner-only rather than trusted.
    #[test]
    fn an_empty_mount_point_is_reused_and_re_restricted() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = mount_point(home.path());
        fs::create_dir(&at).expect("a leftover mount point");
        fs::set_permissions(&at, fs::Permissions::from_mode(0o777)).expect("a widened directory");

        prepare(&at).expect("an empty mount point is reused");
        assert_eq!(mode(&at), 0o700);
    }

    /// v1 emptied the mount point. A member who put files here loses them that
    /// way, and a mount is never worth that: the mount is refused instead, and
    /// the session carries on without one.
    #[test]
    fn a_mount_point_with_anything_in_it_is_refused_rather_than_emptied() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = mount_point(home.path());
        fs::create_dir(&at).expect("a mount point");
        let theirs = at.join("their-file.txt");
        fs::write(&theirs, b"not the mount's to delete").expect("a member's file");

        assert!(prepare(&at).is_err());
        assert!(theirs.exists(), "nothing under the mount point is deleted");
    }

    /// A symlink at the mount point projects the vault wherever it points, so
    /// it is refused before the mount resolves it.
    #[test]
    fn a_symlinked_mount_point_is_refused() {
        let home = tempfile::tempdir().expect("a temp dir");
        let elsewhere = home.path().join("elsewhere");
        fs::create_dir(&elsewhere).expect("a target directory");
        let at = mount_point(home.path());
        std::os::unix::fs::symlink(&elsewhere, &at).expect("a symlinked mount point");

        assert!(prepare(&at).is_err());
    }

    #[test]
    fn a_mount_point_that_is_a_file_is_refused() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = mount_point(home.path());
        fs::write(&at, b"not a directory").expect("a file in the way");

        assert!(prepare(&at).is_err());
    }

    /// Every refusal names the mount point, because the member's next move is
    /// to go and look at it.
    #[test]
    fn a_refusal_names_the_mount_point() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = mount_point(home.path());
        fs::write(&at, b"not a directory").expect("a file in the way");

        let refusal = mount(&at, &home.path().join("account"))
            .err()
            .expect("a file in the way is not mountable");
        assert!(refusal.contains(&at.display().to_string()), "{refusal}");
    }
}
