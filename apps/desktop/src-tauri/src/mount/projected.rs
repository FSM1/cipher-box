//! The vault projected as a filesystem, on the platforms `crates/fuse` has a
//! host adapter for.

use std::path::{Path, PathBuf};

use cipherbox_engine::{Engine, Event};
use cipherbox_fuse::{CacheBudget, FuseInvalidator, FuseMount, OperationCore, SpillArea};

use super::MountStatus;
use crate::engine::DesktopSeamTypes;

pub use cipherbox_fuse::KernelOp;

/// Shown once the kernel session has ended under a live app — an unmount from a
/// terminal or Finder. The inode map is per mount session, so the vault is
/// projected again by signing in again, not by re-mounting under it.
const ENDED: &str = "the vault was unmounted outside CipherBox; sign out and back in to mount it";

/// Shown when the device reports no home directory, so no mount point can be
/// composed. A mount refusal, not a reason to refuse the session.
const NO_HOME: &str = "this device has no home directory to mount the vault under";

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
    /// Mounts the vault for a session that has already started, or hands back an
    /// engine that stands alone and the reason it does.
    pub fn open(
        engine: Engine<DesktopSeamTypes>,
        home_dir: Option<&Path>,
        account_dir: &Path,
    ) -> Self {
        let Some(home_dir) = home_dir else {
            return Self::Detached {
                engine: Box::new(engine),
                refusal: NO_HOME.to_owned(),
            };
        };
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

    /// The next kernel operation, or `None` the one time the kernel session
    /// ends under a live app: the mount status has moved, and a host that only
    /// re-reads on a wake would go on showing the mount point otherwise.
    ///
    /// Never resolves without a live mount, so a host may wait on it beside its
    /// other wake sources whether or not this session projects anything.
    pub async fn next_op(&mut self) -> Option<KernelOp> {
        let Self::Projected {
            mount: Some(live), ..
        } = self
        else {
            return core::future::pending().await;
        };
        match live.next_op().await {
            Some(op) => Some(op),
            None => {
                self.detach();
                None
            }
        }
    }

    /// The kernel session has ended — an unmount from outside the app. The
    /// handles and cached plaintext this mount held go with it; the engine goes
    /// on running.
    fn detach(&mut self) {
        if let Self::Projected { core, mount, .. } = self {
            core.unmount();
            *mount = None;
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

    /// Ends the session's projection: quiesce the adapter, unmount, then let the
    /// engine stop (blueprint/desktop.md "Lifecycle").
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

/// Mount, and open the spill area the mount's writes land in. The spill area
/// comes first: a mount with nowhere to spill would have to be torn down again.
fn mount(at: &Path, account_dir: &Path) -> Result<(FuseMount, SpillArea), String> {
    let spill = SpillArea::production(account_dir)
        .map_err(|error| format!("the mount has nowhere to spill writes: {error}"))?;
    let mount = cipherbox_fuse::mount(at)
        .map_err(|error| format!("{} could not be mounted: {error}", at.display()))?;
    Ok((mount, spill))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every refusal names the mount point, because the member's next move is to
    /// go and look at it.
    #[test]
    fn a_refusal_names_the_mount_point() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = mount_point(home.path());
        std::fs::write(&at, b"not a directory").expect("a file in the way");

        let refusal = mount(&at, &home.path().join("account"))
            .err()
            .expect("a file in the way is not mountable");
        assert!(refusal.contains(&at.display().to_string()), "{refusal}");
    }
}
