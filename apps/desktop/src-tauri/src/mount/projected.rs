//! The vault projected as a filesystem. One projection over all three host
//! adapters: which one a build links is the only thing that differs.

use std::path::{Path, PathBuf};
use std::time::Duration;

use cipherbox_engine::{Engine, Event};
use cipherbox_fuse::{CacheBudget, Invalidator, Mount, OperationCore, Publication, SpillArea};
use tokio::task::JoinHandle;

use super::{FromMount, MountStatus};
use crate::engine::DesktopSeamTypes;

pub use cipherbox_fuse::KernelOp;

/// What the mounting thread hands back: the mount it made, or why it made none.
pub type Landing = Result<Mount, String>;

/// Shown once the kernel session has ended under a live app — an unmount from a
/// terminal or Finder. The inode map is per mount session, so the vault is
/// projected again by signing in again, not by re-mounting under it.
const ENDED: &str = "the vault was unmounted outside CipherBox; sign out and back in to mount it";

/// Shown when the device reports no home directory, so no mount point can be
/// composed. A mount refusal, not a reason to refuse the session.
const NO_HOME: &str = "this device has no home directory to mount the vault under";

/// Shown when the mounting thread ended without a verdict.
const NO_VERDICT: &str = "the mount stopped before it said whether it had been made";

/// Shown when the backend never published the mount at the mount point. Until
/// it does, that path is the directory under the mount, and a write there
/// reaches no engine — so the session says the vault is not projected rather
/// than name a mount point that takes writes and loses them.
const NOT_PUBLISHED: &str = "the mount was made but the backend never published it";

/// How long a session that is ending waits for a mount still being made. The
/// mount unmounts itself when the handle it lands in is dropped, so the wait
/// bounds an orderly shutdown rather than gating one.
const SHUTDOWN_WITHIN: Duration = Duration::from_secs(5);

/// The vault's mount point: `~/CipherBox`, the name v1 taught members to look
/// for. WinFsp makes that directory itself and removes it at unmount; the unix
/// backends mount over one the adapter prepares.
fn mount_point(home_dir: &Path) -> PathBuf {
    home_dir.join("CipherBox")
}

/// The session's engine, and the filesystem it is projected through.
pub enum Projection {
    /// The mount is being made off this thread, and its verdict will arrive on
    /// `landing`.
    Opening {
        engine: Box<Engine<DesktopSeamTypes>>,
        spill: SpillArea,
        at: PathBuf,
        landing: JoinHandle<Landing>,
    },
    /// No mount: the engine stands alone, and `refusal` is why the vault is not
    /// also a filesystem.
    Detached {
        engine: Box<Engine<DesktopSeamTypes>>,
        refusal: String,
    },
    /// The vault is projected through `core`. `mount` empties when the kernel
    /// session ends; the engine goes on running inside the core either way.
    Projected {
        core: Box<OperationCore<DesktopSeamTypes, Invalidator>>,
        mount: Option<Mount>,
        at: PathBuf,
    },
}

impl Projection {
    /// Starts the mount for a session that has already started, or hands back an
    /// engine that stands alone and the reason it does.
    ///
    /// Returns without waiting on the mount: the spill area opens here because
    /// a mount with nowhere to spill would have to be torn down again, and the
    /// mount itself lands through [`next`](Self::next).
    ///
    /// Must be called on a runtime: the blocking mount is dispatched onto its
    /// own thread rather than run here.
    pub fn open(
        engine: Engine<DesktopSeamTypes>,
        home_dir: Option<&Path>,
        account_dir: &Path,
    ) -> Self {
        let engine = Box::new(engine);
        let Some(home_dir) = home_dir else {
            return Self::Detached {
                engine,
                refusal: NO_HOME.to_owned(),
            };
        };
        let at = mount_point(home_dir);
        let spill = match SpillArea::production(account_dir) {
            Ok(spill) => spill,
            Err(error) => {
                return Self::Detached {
                    engine,
                    refusal: format!("the mount has nowhere to spill writes: {error}"),
                };
            }
        };

        let mounting = at.clone();
        Self::Opening {
            engine,
            spill,
            at,
            landing: tokio::task::spawn_blocking(move || mount(&mounting)),
        }
    }

    /// The session's one engine, wherever it is being held.
    pub fn engine_mut(&mut self) -> &mut Engine<DesktopSeamTypes> {
        match self {
            Self::Opening { engine, .. } | Self::Detached { engine, .. } => engine,
            Self::Projected { core, .. } => core.engine_mut(),
        }
    }

    pub fn status(&self) -> MountStatus {
        match self {
            Self::Opening { .. } => MountStatus::Opening,
            Self::Detached { refusal, .. } => MountStatus::refused(refusal),
            Self::Projected { mount: None, .. } => MountStatus::refused(ENDED),
            Self::Projected {
                mount: Some(mount),
                at,
                ..
            } => match mount.publication() {
                Publication::Live => MountStatus::Mounted {
                    path: at.display().to_string(),
                },
                Publication::Pending => MountStatus::Opening,
                Publication::Refused => MountStatus::refused(NOT_PUBLISHED),
            },
        }
    }

    /// Folds the mounting thread's verdict in: the engine moves into the
    /// operation core the mount feeds, or stands alone with the refusal.
    pub fn settled(self, landed: Landing) -> Self {
        let Self::Opening {
            engine, spill, at, ..
        } = self
        else {
            return self;
        };
        match landed {
            Ok(mount) => Self::Projected {
                core: Box::new(OperationCore::new(
                    *engine,
                    mount.invalidator(),
                    CacheBudget::PRODUCTION,
                    spill,
                )),
                mount: Some(mount),
                at,
            },
            Err(refusal) => Self::Detached { engine, refusal },
        }
    }

    /// The next thing the mount wakes the session with.
    ///
    /// Cancel-safe, and never resolves while there is nothing to wake for, so a
    /// host waits on it beside its other wake sources whether or not this
    /// session projects anything.
    pub async fn next(&mut self) -> FromMount {
        match self {
            Self::Opening { landing, .. } => FromMount::Landed(
                (&mut *landing)
                    .await
                    .unwrap_or_else(|_| Err(NO_VERDICT.to_owned())),
            ),
            Self::Projected {
                mount: Some(live), ..
            } => match live.next_op().await {
                Some(op) => FromMount::Op(op),
                None => {
                    self.detach();
                    FromMount::Ended
                }
            },
            _ => core::future::pending().await,
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
    ///
    /// A mount still being made is waited out rather than abandoned, so a
    /// session that has ended leaves no mount work behind it to land on the
    /// mount point the next sign-in wants.
    pub async fn tear_down(self) {
        match self {
            Self::Opening { landing, .. } => {
                // Whatever it lands is dropped, and dropping a mount is
                // the unmount.
                let _ = tokio::time::timeout(SHUTDOWN_WITHIN, landing).await;
            }
            Self::Projected {
                mut core,
                mut mount,
                ..
            } => {
                if let Some(mount) = mount.as_mut() {
                    mount.quiesce();
                }
                drop(mount);
                core.unmount();
            }
            Self::Detached { .. } => {}
        }
    }
}

/// Mount at `at`, naming the mount point in whatever refused it — the member's
/// next move is to go and look at it.
fn mount(at: &Path) -> Landing {
    cipherbox_fuse::mount(at)
        .map_err(|error| format!("{} could not be mounted: {error}", at.display()))
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

        let Err(refusal) = mount(&at) else {
            panic!("a file in the way is not mountable");
        };
        assert!(refusal.contains(&at.display().to_string()), "{refusal}");
    }
}
