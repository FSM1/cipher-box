//! The FUSE wire, shared by both backends that speak it: kernel FUSE on Linux
//! and FUSE-T's SMB backend on macOS, through the one vendored `fuser`
//! (blueprint/desktop.md "Backends"). What differs between them is a
//! [`MountProfile`], not a second operation tree — v1's per-host trees produced
//! a revocation bypass that existed in exactly one of them.
//!
//! Two directions, two objects. Inbound, [`FuseSession`] decodes the wire on
//! fuser's session thread and hands each operation — with the reply it is owed
//! — to the engine task, the only thread that may touch the operation core.
//! Outbound, [`FuseInvalidator`] turns the core's invalidations into
//! `inval_inode`/`inval_entry`.
//!
//! The reply object crosses the channel with the request, so the session thread
//! never waits on the engine and the kernel is answered wherever the operation
//! finishes. The queue between them is unbounded, which the never-block law
//! makes unavoidable: a queued write holds its plaintext until the pump reaches
//! it, so the mount caps the kernel's write width rather than the queue.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cipherbox_engine::seams::SeamTypes;
use cipherbox_engine::{NodeKind, StatFs};
use fuser::{
    BackgroundSession, FileAttr, FileType, Filesystem, KernelConfig, MountOption, Notifier,
    ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen,
    ReplyStatfs, ReplyWrite, Request, Session, TimeOrNow,
};
use futures_channel::mpsc;
use futures_core::Stream;
use zeroize::Zeroizing;

use crate::adapter::{CacheTtls, HostAdapter, HostCapabilities, Invalidation, Publication};
use crate::adapters::{ADVISORY_CAPACITY_BYTES, Listed, cursor_of, stale};
use crate::errno::errno_of;
use crate::error::VfsError;
use crate::handle::{Access, HandleId};
use crate::name::MAX_NAME_BYTES;
use crate::ops::{Attributes, DirEntry, DirHandleId, OperationCore};
use crate::spill::restrict_dir;

/// Inodes are per mount session and never reused, so there is no generation
/// axis for the kernel to disambiguate along.
const GENERATION: u64 = 0;

/// `st_blocks` counts 512-byte units by POSIX definition, whatever `st_blksize`
/// says.
const STAT_BLOCK_BYTES: u64 = 512;

/// The I/O size the mount advertises. One page: the projection's own framing is
/// the chunk cache's, and nothing here is served better by a larger hint.
const PREFERRED_IO_BYTES: u32 = 4096;

/// The node-count counterpart of [`ADVISORY_CAPACITY_BYTES`]: the nodes in use
/// are truthful, the headroom above them is not.
const ADVISORY_FREE_NODES: u64 = 1 << 20;

/// The widest single write the kernel may hand over. fuser's default is 16 MiB,
/// and every write in flight holds that much plaintext in the op queue until
/// the pump reaches it.
const MAX_WRITE_BYTES: u32 = 1 << 20;

/// How long a mount is given to reach [`Publication::Live`] before a host
/// reports it [`Publication::Refused`]. Wide enough for a loaded runner.
const PUBLISHED_WITHIN: Duration = Duration::from_secs(30);

/// How often the publication watch re-reads the mount point.
const PUBLISH_POLL: Duration = Duration::from_millis(25);

/// [`Publication`] as the watch stores it.
const PENDING: u8 = 0;
const LIVE: u8 = 1;
const REFUSED: u8 = 2;

/// Owner-only, and no execute bit: the projection carries no POSIX mode of its
/// own, and a vault is not a place to hand out an executable.
const FILE_MODE: u16 = 0o600;
/// The directory counterpart of [`FILE_MODE`] — traversal needs the execute
/// bit.
const DIRECTORY_MODE: u16 = 0o700;

/// A request the projection cannot even name. Answered through the shared table
/// rather than beside it, so no adapter drifts from another.
fn malformed() -> i32 {
    errno_of(&VfsError::Invalid)
}

/// What one mount technology asks of the shared FUSE wire, on top of
/// [`floor_options`].
pub(crate) struct MountProfile {
    /// The options this backend adds. The floor is not among them.
    pub(crate) options: Vec<MountOption>,
    /// What the backend can do for the operation core.
    pub(crate) capabilities: HostCapabilities,
}

/// Every CipherBox mount's floor, whatever backend it is made on. Held here
/// rather than in each profile so a backend cannot ship without it.
fn floor_options() -> Vec<MountOption> {
    vec![
        MountOption::FSName("cipherbox".to_owned()),
        MountOption::DefaultPermissions,
        MountOption::NoSuid,
        MountOption::NoExec,
        MountOption::NoDev,
    ]
}

/// Option tokens a backend may not carry. Each either admits someone other
/// than the mount's maker — a vault the whole machine can read is not a trade
/// for tidier teardown, and `auto_unmount` is here because fuser adds
/// `allow_other` to get it — or is the antonym of a floor option, and vault
/// content is bytes another client committed.
const WIDENING_TOKENS: &[&str] = &[
    "allow_other",
    "allow_root",
    "auto_unmount",
    "suid",
    "exec",
    "dev",
];

/// Whether `option` carries one of [`WIDENING_TOKENS`].
///
/// Decided on the string the mount program receives, not on the enum: a
/// `CUSTOM` renders verbatim, so `CUSTOM("allow_other")` is `allow_other` to
/// the mount and a variant comparison would wave it through. A custom string
/// is several options when it holds commas, and `nosuid` must not read as
/// `suid`, so each token is compared whole.
fn widens_access(option: &MountOption) -> bool {
    fuser::option_to_string(option).split(',').any(|token| {
        let key = token.split('=').next().unwrap_or(token);
        WIDENING_TOKENS.contains(&key)
    })
}

/// The floor plus what `profile` adds, or an error if the backend asked for an
/// option that widens who may read the vault or what it may be trusted to hold.
fn mount_options(profile_options: Vec<MountOption>) -> io::Result<Vec<MountOption>> {
    if let Some(refused) = profile_options.iter().find(|option| widens_access(option)) {
        return Err(io::Error::other(format!(
            "a mount option would widen the vault's floor: {refused:?}"
        )));
    }
    let mut options = floor_options();
    options.extend(profile_options);
    Ok(options)
}

/// Pushes the operation core's invalidations at the backend.
#[derive(Clone)]
pub struct FuseInvalidator {
    notifier: Notifier,
    capabilities: HostCapabilities,
}

impl HostAdapter for FuseInvalidator {
    fn capabilities(&self) -> HostCapabilities {
        self.capabilities
    }

    fn invalidate(&self, invalidation: Invalidation) {
        // An inode the kernel never cached answers `ENOENT`, which the notifier
        // already absorbs; what is left is a channel on its way down, and the
        // trait's contract is that the adapter absorbs that too.
        let _ = match invalidation {
            // Offset zero, length zero: the attributes and every cached page.
            Invalidation::Data { ino } => self.notifier.inval_inode(ino, 0, 0),
            // A negative offset is the kernel's "attributes only".
            Invalidation::Attributes { ino } => self.notifier.inval_inode(ino, -1, 0),
            Invalidation::Entry { parent, name } => {
                self.notifier.inval_entry(parent, OsStr::new(&name))
            }
        };
    }
}

/// The identity the mount presents. The projection stores no POSIX ownership,
/// and the mount admits only the user who made it, so every node belongs to the
/// caller by construction.
#[derive(Clone, Copy)]
struct Ownership {
    uid: u32,
    gid: u32,
}

/// One decoded kernel request and the reply it is owed.
enum FuseOp {
    Lookup {
        parent: u64,
        name: String,
        reply: ReplyEntry,
    },
    GetAttr {
        ino: u64,
        reply: ReplyAttr,
    },
    SetSize {
        ino: u64,
        size: u64,
        handle: Option<HandleId>,
        reply: ReplyAttr,
    },
    OpenDir {
        ino: u64,
        reply: ReplyOpen,
    },
    ReadDir {
        ino: u64,
        walk: DirHandleId,
        offset: usize,
        reply: ReplyDirectory,
    },
    ReleaseDir {
        walk: DirHandleId,
        reply: ReplyEmpty,
    },
    /// The kernel giving back references it took on entry replies. It expects
    /// no answer, which is why this carries no reply.
    Forget {
        ino: u64,
        count: u64,
    },
    Create {
        parent: u64,
        name: String,
        access: Access,
        reply: ReplyCreate,
    },
    MkDir {
        parent: u64,
        name: String,
        reply: ReplyEntry,
    },
    Unlink {
        parent: u64,
        name: String,
        reply: ReplyEmpty,
    },
    RmDir {
        parent: u64,
        name: String,
        reply: ReplyEmpty,
    },
    Rename {
        parent: u64,
        name: String,
        new_parent: u64,
        new_name: String,
        reply: ReplyEmpty,
    },
    Open {
        ino: u64,
        access: Access,
        truncate: bool,
        reply: ReplyOpen,
    },
    Read {
        handle: HandleId,
        offset: u64,
        size: u32,
        reply: ReplyData,
    },
    Write {
        handle: HandleId,
        offset: u64,
        data: Zeroizing<Vec<u8>>,
        reply: ReplyWrite,
    },
    Flush {
        handle: HandleId,
        reply: ReplyEmpty,
    },
    FSync {
        handle: HandleId,
        reply: ReplyEmpty,
    },
    Release {
        handle: HandleId,
        reply: ReplyEmpty,
    },
    StatFs {
        reply: ReplyStatfs,
    },
}

impl FuseOp {
    /// Answer with `errno` instead of running — the only thing to do with a
    /// request the engine task will never see. A FUSE request nobody answers
    /// hangs its caller for the life of the mount.
    fn refuse(self, errno: i32) {
        match self {
            FuseOp::Lookup { reply, .. } | FuseOp::MkDir { reply, .. } => reply.error(errno),
            FuseOp::GetAttr { reply, .. } | FuseOp::SetSize { reply, .. } => reply.error(errno),
            FuseOp::Unlink { reply, .. }
            | FuseOp::RmDir { reply, .. }
            | FuseOp::Rename { reply, .. }
            | FuseOp::ReleaseDir { reply, .. }
            | FuseOp::Flush { reply, .. }
            | FuseOp::FSync { reply, .. }
            | FuseOp::Release { reply, .. } => reply.error(errno),
            FuseOp::ReadDir { reply, .. } => reply.error(errno),
            FuseOp::Create { reply, .. } => reply.error(errno),
            FuseOp::Open { reply, .. } | FuseOp::OpenDir { reply, .. } => reply.error(errno),
            FuseOp::Read { reply, .. } => reply.error(errno),
            FuseOp::Write { reply, .. } => reply.error(errno),
            FuseOp::StatFs { reply, .. } => reply.error(errno),
            FuseOp::Forget { .. } => {}
        }
    }
}

/// The `fuser::Filesystem` this mount registers: a decoder, and nothing else.
struct FuseSession {
    ops: mpsc::UnboundedSender<FuseOp>,
}

impl FuseSession {
    fn dispatch(&self, op: FuseOp) {
        if let Err(refused) = self.ops.unbounded_send(op) {
            // The engine task is gone; the mount is on its way down.
            refused.into_inner().refuse(libc::ENOTCONN);
        }
    }
}

/// One decoded kernel request, waiting for an operation core to answer it.
///
/// Opaque, and answered exactly once: a host takes it from
/// [`FuseMount::next_op`] and hands it back to [`FuseMount::answer`].
pub struct KernelOp(Option<FuseOp>);

impl Drop for KernelOp {
    /// A FUSE request nobody answers hangs its caller for the life of the
    /// mount, so an operation dropped unanswered is refused instead.
    fn drop(&mut self) {
        if let Some(op) = self.0.take() {
            op.refuse(libc::ENOTCONN);
        }
    }
}

/// A live mount. Dropping it unmounts and ends the session thread; the
/// operation core it fed is torn down separately, by its own `unmount`.
pub struct FuseMount {
    /// Held for its `Drop`, which is the unmount.
    _session: BackgroundSession,
    invalidator: FuseInvalidator,
    ops: mpsc::UnboundedReceiver<FuseOp>,
    owner: Ownership,
    published: Arc<AtomicU8>,
}

/// Watch `at` from a thread of its own until the mount serves it rather than
/// the directory it covers, or until `within` runs out.
///
/// Off the pump, and it has to be: once the mount is published, reading the
/// mount point is a kernel operation this session owes the answer to, so a pump
/// that read it would wait on itself. FUSE-T's SMB backend also asks for the
/// root while it publishes, which is the same knot from the other side.
///
/// Until the mount point moves off the filesystem it covers, a write there
/// reaches the directory under the mount and no engine — silent loss, which is
/// what [`Publication`] exists to keep a host from reporting as a mount.
fn watch_publication(at: PathBuf, covered: u64, within: Duration) -> Arc<AtomicU8> {
    let verdict = Arc::new(AtomicU8::new(PENDING));
    let watch = verdict.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + within;
        loop {
            if let Some(settled) = settle(&at, covered, deadline) {
                watch.store(settled, Ordering::Release);
                return;
            }
            thread::sleep(PUBLISH_POLL);
        }
    });
    verdict
}

/// One read of the mount point: its verdict, or nothing while the answer is
/// still to come.
fn settle(at: &Path, covered: u64, deadline: Instant) -> Option<u8> {
    // A read that fails while the mount lands is not a verdict; the deadline is.
    if device_of(at).is_ok_and(|serving| serving != covered) {
        return Some(LIVE);
    }
    (Instant::now() >= deadline).then_some(REFUSED)
}

impl FuseMount {
    /// Mount at `mountpoint`, cleared ([`stale::clear`]) and prepared
    /// ([`prepare`]) first, under one backend's [`MountProfile`].
    pub(crate) fn at(mountpoint: &Path, profile: MountProfile) -> io::Result<Self> {
        let options = mount_options(profile.options)?;
        stale::clear(mountpoint)?;
        prepare(mountpoint)?;
        let covered = device_of(mountpoint)?;
        let (sender, ops) = mpsc::unbounded();
        let session = Session::new(FuseSession { ops: sender }, mountpoint, &options)?;
        let invalidator = FuseInvalidator {
            notifier: session.notifier(),
            capabilities: profile.capabilities,
        };
        Ok(Self {
            _session: session.spawn()?,
            invalidator,
            ops,
            owner: Ownership {
                uid: nix::unistd::Uid::effective().as_raw(),
                gid: nix::unistd::Gid::effective().as_raw(),
            },
            published: watch_publication(mountpoint.to_path_buf(), covered, PUBLISHED_WITHIN),
        })
    }

    /// Whether the backend has published this mount at its mount point yet.
    pub fn publication(&self) -> Publication {
        match self.published.load(Ordering::Acquire) {
            LIVE => Publication::Live,
            REFUSED => Publication::Refused,
            _ => Publication::Pending,
        }
    }

    /// The invalidator to mount the operation core behind.
    pub fn invalidator(&self) -> FuseInvalidator {
        self.invalidator.clone()
    }

    /// The next kernel operation, or `None` once the session has ended.
    ///
    /// Cancel-safe: an operation is taken off the queue or it is not, so a host
    /// may wait on this beside its other wake sources.
    pub async fn next_op(&mut self) -> Option<KernelOp> {
        core::future::poll_fn(|cx| Pin::new(&mut self.ops).poll_next(cx))
            .await
            .map(|op| KernelOp(Some(op)))
    }

    /// Answer one operation from `core`.
    ///
    /// Serial by construction — one operation core is one stateful projection —
    /// and the never-block law is what keeps a serial pump responsive: no
    /// operation here awaits IPNS resolution, publish, or API bookkeeping.
    pub async fn answer<T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, FuseInvalidator>,
        mut op: KernelOp,
    ) {
        if let Some(op) = op.0.take() {
            answer(core, op, self.owner).await;
        }
    }

    /// Stop accepting kernel operations, ahead of the unmount
    /// (blueprint/desktop.md "Lifecycle" — quiesce, unmount, stop the engine).
    /// Everything queued and everything the session dispatches from here is
    /// refused rather than left for a pump that has stopped running.
    pub fn quiesce(&mut self) {
        self.ops.close();
        // Each refuses itself on the way out — [`KernelOp`] owns that policy, so
        // there is one refusal path rather than one per shutdown route.
        while let Ok(op) = self.ops.try_recv() {
            drop(KernelOp(Some(op)));
        }
    }
}

/// The filesystem serving `path`. A mount moves its mount point onto another
/// one, which is the signal both backends share that the mount is live.
fn device_of(path: &Path) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;

    fs::metadata(path).map(|found| found.dev())
}

/// Make `mountpoint` fit to mount on: a private, empty directory, created if it
/// is not there.
///
/// v1 emptied whatever it found. Deleting a member's files is not a trade for a
/// tidier mount, so anything already in the way refuses the mount instead — and
/// a refusal costs the session nothing (blueprint/desktop.md "Lifecycle": mount
/// failure never fails login).
fn prepare(mountpoint: &Path) -> io::Result<()> {
    match fs::symlink_metadata(mountpoint) {
        Ok(found) => {
            // Refused before the mount resolves it: a link here would project
            // the vault somewhere the member never chose.
            if found.file_type().is_symlink() {
                return Err(io::Error::other("the mount point is a symbolic link"));
            }
            if !found.is_dir() {
                return Err(io::Error::other("the mount point is not a directory"));
            }
            if fs::read_dir(mountpoint)?.next().is_some() {
                return Err(io::Error::other("the mount point is not empty"));
            }
        }
        // Owner-only from the moment it exists, not narrowed after: a
        // `create_dir_all` takes the umask first, and the floor the mount
        // carries has to hold over the directory fronting it the whole time.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;

            return fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(mountpoint);
        }
        Err(error) => return Err(error),
    }
    // One found is brought back to the same floor.
    restrict_dir(mountpoint)
}

impl Filesystem for FuseSession {
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), libc::c_int> {
        // A refusal hands back the nearest width the kernel will take, which is
        // still narrower than the default this exists to cut.
        if let Err(nearest) = config.set_max_write(MAX_WRITE_BYTES) {
            let _ = config.set_max_write(nearest);
        }
        Ok(())
    }

    fn destroy(&mut self) {
        // Ends the pump: the session is over, so no further operation can be
        // answered.
        self.ops.close_channel();
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(name) = as_utf8(name) else {
            // A name the projection cannot hold provably does not exist, and
            // absence is what `stat` and `test -e` are asking about.
            reply.error(errno_of(&VfsError::NotFound));
            return;
        };
        self.dispatch(FuseOp::Lookup {
            parent,
            name,
            reply,
        });
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        self.dispatch(FuseOp::GetAttr { ino, reply });
    }

    /// The projection carries no POSIX mode, ownership, or timestamps, so the
    /// only field here it can act on is the size — a bare `truncate(2)`, and
    /// the `O_TRUNC` a kernel that did not negotiate `atomic_o_trunc` sends as
    /// its own request. The rest is accepted and ignored rather than refused:
    /// an `ENOSYS` here fails `cp -p` and `touch` outright.
    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        self.dispatch(match size {
            Some(size) => FuseOp::SetSize {
                ino,
                size,
                handle: fh.map(HandleId),
                reply,
            },
            None => FuseOp::GetAttr { ino, reply },
        });
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(name) = as_utf8(name) else {
            reply.error(malformed());
            return;
        };
        self.dispatch(FuseOp::MkDir {
            parent,
            name,
            reply,
        });
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(name) = as_utf8(name) else {
            reply.error(malformed());
            return;
        };
        self.dispatch(FuseOp::Unlink {
            parent,
            name,
            reply,
        });
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(name) = as_utf8(name) else {
            reply.error(malformed());
            return;
        };
        self.dispatch(FuseOp::RmDir {
            parent,
            name,
            reply,
        });
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let (Some(name), Some(new_name)) = (as_utf8(name), as_utf8(new_name)) else {
            reply.error(malformed());
            return;
        };
        self.dispatch(FuseOp::Rename {
            parent,
            name,
            new_parent,
            new_name,
            reply,
        });
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let (Some(name), Some(access)) = (as_utf8(name), Access::from_open_flags(flags)) else {
            reply.error(malformed());
            return;
        };
        self.dispatch(FuseOp::Create {
            parent,
            name,
            access,
            reply,
        });
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(access) = Access::from_open_flags(flags) else {
            reply.error(malformed());
            return;
        };
        self.dispatch(FuseOp::Open {
            ino,
            access,
            truncate: flags & libc::O_TRUNC != 0,
            reply,
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Ok(offset) = u64::try_from(offset) else {
            reply.error(malformed());
            return;
        };
        self.dispatch(FuseOp::Read {
            handle: HandleId(fh),
            offset,
            size,
            reply,
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let Ok(offset) = u64::try_from(offset) else {
            reply.error(malformed());
            return;
        };
        // The borrow is fuser's receive buffer, reused for the next request, so
        // the payload has to be copied to outlive this callback.
        self.dispatch(FuseOp::Write {
            handle: HandleId(fh),
            offset,
            data: Zeroizing::new(data.to_vec()),
            reply,
        });
    }

    /// The directory handle minted here is what pins one walk's listing, so a
    /// second walk over the same directory gets its own.
    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        self.dispatch(FuseOp::OpenDir { ino, reply });
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        reply: ReplyDirectory,
    ) {
        let Ok(offset) = usize::try_from(offset) else {
            reply.error(malformed());
            return;
        };
        self.dispatch(FuseOp::ReadDir {
            ino,
            walk: DirHandleId(fh),
            offset,
            reply,
        });
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        self.dispatch(FuseOp::ReleaseDir {
            walk: DirHandleId(fh),
            reply,
        });
    }

    fn forget(&mut self, _req: &Request<'_>, ino: u64, nlookup: u64) {
        self.dispatch(FuseOp::Forget {
            ino,
            count: nlookup,
        });
    }

    /// `close(2)` returns what this returns — the no-false-ack discipline's
    /// last mile (blueprint/desktop.md "release").
    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        self.dispatch(FuseOp::Flush {
            handle: HandleId(fh),
            reply,
        });
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.dispatch(FuseOp::FSync {
            handle: HandleId(fh),
            reply,
        });
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.dispatch(FuseOp::Release {
            handle: HandleId(fh),
            reply,
        });
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        self.dispatch(FuseOp::StatFs { reply });
    }
}

/// The engine stores names as UTF-8 text, so bytes that are not are a name no
/// client could have committed. Admission proper is the core's.
fn as_utf8(name: &OsStr) -> Option<String> {
    name.to_str().map(str::to_owned)
}

/// Run one operation and answer its reply.
async fn answer<T: SeamTypes>(
    core: &mut OperationCore<T, FuseInvalidator>,
    op: FuseOp,
    owner: Ownership,
) {
    match op {
        FuseOp::Lookup {
            parent,
            name,
            reply,
        } => {
            let outcome = core.lookup(parent, &name).await;
            entry(reply, owner, core.cache_ttls(), outcome);
        }
        FuseOp::GetAttr { ino, reply } => {
            let outcome = core.getattr(ino).await;
            attr(reply, owner, core.cache_ttls(), outcome);
        }
        FuseOp::SetSize {
            ino,
            size,
            handle,
            reply,
        } => {
            let outcome = match core.truncate(ino, size, handle).await {
                Ok(()) => core.getattr(ino).await,
                Err(refusal) => Err(refusal),
            };
            attr(reply, owner, core.cache_ttls(), outcome);
        }
        FuseOp::OpenDir { ino, reply } => match core.opendir(ino).await {
            Ok(walk) => reply.opened(walk.0, 0),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        FuseOp::ReadDir {
            ino,
            walk,
            offset,
            mut reply,
        } => match core.readdir(walk, cursor_of(offset)).await {
            Ok(entries) => {
                emit_listing(&mut reply, ino, offset, entries);
                reply.ok();
            }
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        FuseOp::ReleaseDir { walk, reply } => {
            core.releasedir(walk);
            reply.ok();
        }
        FuseOp::Forget { ino, count } => core.forget(ino, count),
        FuseOp::Create {
            parent,
            name,
            access,
            reply,
        } => {
            let outcome = core.create(parent, &name, access).await;
            let ttls = core.cache_ttls();
            match outcome {
                Ok((attrs, handle)) => {
                    let (size, entry_ttl, attr_ttl) = ttls.projected_entry(&attrs);
                    reply.created(
                        &entry_ttl,
                        &attr_ttl,
                        &file_attr(&attrs, size, owner),
                        GENERATION,
                        handle.0,
                        0,
                    );
                }
                Err(refusal) => reply.error(errno_of(&refusal)),
            }
        }
        FuseOp::MkDir {
            parent,
            name,
            reply,
        } => {
            let outcome = core.mkdir(parent, &name).await;
            entry(reply, owner, core.cache_ttls(), outcome);
        }
        FuseOp::Unlink {
            parent,
            name,
            reply,
        } => empty(reply, core.unlink(parent, &name).await),
        FuseOp::RmDir {
            parent,
            name,
            reply,
        } => empty(reply, core.rmdir(parent, &name).await),
        FuseOp::Rename {
            parent,
            name,
            new_parent,
            new_name,
            reply,
        } => empty(
            reply,
            core.rename(parent, &name, new_parent, &new_name).await,
        ),
        FuseOp::Open {
            ino,
            access,
            truncate,
            reply,
        } => match open_handle(core, ino, access, truncate).await {
            Ok(handle) => reply.opened(handle.0, 0),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        FuseOp::Read {
            handle,
            offset,
            size,
            reply,
        } => match core.read(handle, offset, size).await {
            // Terminal owner of the plaintext: wiped the moment the kernel has
            // it.
            Ok(plaintext) => reply.data(&Zeroizing::new(plaintext)),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        FuseOp::Write {
            handle,
            offset,
            data,
            reply,
        } => match core.write(handle, offset, &data).await {
            Ok(taken) => reply.written(taken),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        FuseOp::Flush { handle, reply } => empty(reply, core.flush(handle).await),
        FuseOp::FSync { handle, reply } => empty(reply, core.fsync(handle).await),
        FuseOp::Release { handle, reply } => empty(reply, core.release(handle).await),
        FuseOp::StatFs { reply } => match core.statfs().await {
            Ok(stats) => reply_statfs(reply, stats),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
    }
}

/// `O_TRUNC` is open-then-truncate: the new length rides into the one
/// `updateContent` op this handle's release journals, so the opening truncate
/// and the writes after it become a single version.
async fn open_handle<T: SeamTypes>(
    core: &mut OperationCore<T, FuseInvalidator>,
    ino: u64,
    access: Access,
    truncate: bool,
) -> Result<HandleId, VfsError> {
    let handle = core.open(ino, access).await?;
    if truncate && let Err(refusal) = core.truncate(ino, 0, Some(handle)).await {
        // The kernel never learns this handle's number, so nothing will ever
        // release it; the failed open has to give back what it took.
        let _ = core.release(handle).await;
        return Err(refusal);
    }
    Ok(handle)
}

fn empty(reply: ReplyEmpty, outcome: Result<(), VfsError>) {
    match outcome {
        Ok(()) => reply.ok(),
        Err(refusal) => reply.error(errno_of(&refusal)),
    }
}

/// The name binding and the attributes carry their own lifetimes, decided by
/// [`CacheTtls::projected_entry`].
fn entry(
    reply: ReplyEntry,
    owner: Ownership,
    ttls: CacheTtls,
    outcome: Result<Attributes, VfsError>,
) {
    match outcome {
        Ok(attrs) => {
            let (size, entry_ttl, attr_ttl) = ttls.projected_entry(&attrs);
            reply.entry(
                &entry_ttl,
                &attr_ttl,
                &file_attr(&attrs, size, owner),
                GENERATION,
            );
        }
        Err(refusal) => reply.error(errno_of(&refusal)),
    }
}

fn attr(
    reply: ReplyAttr,
    owner: Ownership,
    ttls: CacheTtls,
    outcome: Result<Attributes, VfsError>,
) {
    match outcome {
        Ok(attrs) => {
            let (size, ttl) = ttls.projected_size(&attrs);
            reply.attr(&ttl, &file_attr(&attrs, size, owner));
        }
        Err(refusal) => reply.error(errno_of(&refusal)),
    }
}

/// The counts `statfs` answers with: total blocks, total nodes, free nodes.
fn statfs_counts(stats: StatFs) -> (u64, u64, u64) {
    (
        ADVISORY_CAPACITY_BYTES / u64::from(PREFERRED_IO_BYTES),
        stats.nodes.saturating_add(ADVISORY_FREE_NODES),
        ADVISORY_FREE_NODES,
    )
}

fn reply_statfs(reply: ReplyStatfs, stats: StatFs) {
    let (blocks, files, free_nodes) = statfs_counts(stats);
    reply.statfs(
        blocks,
        blocks,
        blocks,
        files,
        free_nodes,
        PREFERRED_IO_BYTES,
        MAX_NAME_BYTES as u32,
        PREFERRED_IO_BYTES,
    );
}

/// One [`crate::adapters::page`] as the FUSE wire spells it: a dot entry names
/// the directory itself, and the resume position is the kernel's cookie.
fn page(
    ino: u64,
    offset: usize,
    entries: &[DirEntry],
) -> impl Iterator<Item = (u64, NodeKind, &str, i64)> {
    crate::adapters::page(offset, entries).map(move |(listed, resume_at)| match listed {
        Listed::Dot(name) => (ino, NodeKind::Folder, name, resume_at as i64),
        Listed::Child(child) => (child.ino, child.kind, child.name.as_str(), resume_at as i64),
    })
}

/// Pack one [`page`] into the reply buffer, stopping where it fills.
fn emit_listing(reply: &mut ReplyDirectory, ino: u64, offset: usize, entries: &[DirEntry]) {
    for (child, kind, name, resume_at) in page(ino, offset, entries) {
        if reply.add(child, resume_at, file_type(kind), OsStr::new(name)) {
            break;
        }
    }
}

fn file_type(kind: NodeKind) -> FileType {
    match kind {
        NodeKind::Folder => FileType::Directory,
        NodeKind::File => FileType::RegularFile,
    }
}

/// The projection's attributes as the kernel's `stat`, at the `size`
/// [`CacheTtls::projected_size`] decided to report.
fn file_attr(attrs: &Attributes, size: u64, owner: Ownership) -> FileAttr {
    let time = attrs
        .mtime_millis
        .and_then(|millis| UNIX_EPOCH.checked_add(Duration::from_millis(millis)))
        .unwrap_or(UNIX_EPOCH);
    FileAttr {
        ino: attrs.ino,
        size,
        blocks: size.div_ceil(STAT_BLOCK_BYTES),
        atime: time,
        mtime: time,
        ctime: time,
        crtime: time,
        kind: file_type(attrs.kind),
        perm: match attrs.kind {
            NodeKind::Folder => DIRECTORY_MODE,
            NodeKind::File => FILE_MODE,
        },
        // Hard links do not exist in the projection; a directory's own `.` is
        // the second link POSIX tools expect to count.
        nlink: match attrs.kind {
            NodeKind::Folder => 2,
            NodeKind::File => 1,
        },
        uid: owner.uid,
        gid: owner.gid,
        rdev: 0,
        blksize: PREFERRED_IO_BYTES,
        flags: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use cipherbox_engine::NodeId;

    use super::*;
    use crate::adapters::DOT_ENTRIES;

    fn owner() -> Ownership {
        Ownership { uid: 501, gid: 20 }
    }

    fn mode(at: &Path) -> u32 {
        fs::metadata(at)
            .expect("a prepared directory")
            .permissions()
            .mode()
            & 0o777
    }

    /// A write to a mount point the backend has not published yet reaches the
    /// directory under the mount and no engine, so a host must not call that
    /// mount made.
    #[test]
    fn a_mount_point_still_serving_the_directory_under_it_is_not_settled() {
        let home = tempfile::tempdir().expect("a temp dir");
        let covered = device_of(home.path()).expect("a stat");

        assert_eq!(
            settle(
                home.path(),
                covered,
                Instant::now() + Duration::from_secs(30)
            ),
            None
        );
    }

    /// The mount moves the mount point onto its own filesystem, which is what
    /// the watch waits for.
    #[test]
    fn a_mount_point_served_by_another_filesystem_is_published() {
        let home = tempfile::tempdir().expect("a temp dir");
        let covered = device_of(home.path()).expect("a stat").wrapping_add(1);

        assert_eq!(
            settle(
                home.path(),
                covered,
                Instant::now() + Duration::from_secs(30)
            ),
            Some(LIVE)
        );
    }

    /// A backend that never publishes must reach a verdict rather than leave a
    /// host waiting out a mount that will not arrive.
    #[test]
    fn a_mount_point_that_has_not_moved_by_the_deadline_is_refused() {
        let home = tempfile::tempdir().expect("a temp dir");
        let covered = device_of(home.path()).expect("a stat");

        assert_eq!(settle(home.path(), covered, Instant::now()), Some(REFUSED));
    }

    /// The watch runs to a verdict without a mount to read, which is the path a
    /// backend that never publishes takes.
    #[test]
    fn the_watch_reaches_a_verdict_off_the_pump() {
        let home = tempfile::tempdir().expect("a temp dir");
        let covered = device_of(home.path()).expect("a stat");

        let verdict = watch_publication(home.path().to_path_buf(), covered, Duration::ZERO);
        while verdict.load(Ordering::Acquire) == PENDING {
            thread::yield_now();
        }
        assert_eq!(verdict.load(Ordering::Acquire), REFUSED);
    }

    /// The mount point is made on demand and made private: a member who has
    /// never mounted before has none for this to find.
    #[test]
    fn a_missing_mount_point_is_created_owner_only() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = home.path().join("CipherBox");

        prepare(&at).expect("a missing mount point is made");
        assert!(at.is_dir());
        assert_eq!(mode(&at), 0o700);
    }

    /// One left over from a previous session is reused, and its permissions are
    /// brought back to owner-only rather than trusted.
    #[test]
    fn an_empty_mount_point_is_reused_and_re_restricted() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = home.path().join("CipherBox");
        fs::create_dir(&at).expect("a leftover mount point");
        fs::set_permissions(&at, fs::Permissions::from_mode(0o777)).expect("a widened directory");

        prepare(&at).expect("an empty mount point is reused");
        assert_eq!(mode(&at), 0o700);
    }

    /// v1 emptied the mount point, and a member who put files there lost them.
    /// A mount is never worth that, and a refusal costs the session nothing.
    #[test]
    fn a_mount_point_with_anything_in_it_is_refused_rather_than_emptied() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = home.path().join("CipherBox");
        fs::create_dir(&at).expect("a mount point");
        let theirs = at.join("their-file.txt");
        fs::write(&theirs, b"not the mount's to delete").expect("a member's file");

        assert!(prepare(&at).is_err());
        assert!(theirs.exists(), "nothing under the mount point is deleted");
    }

    /// A symlink at the mount point projects the vault wherever it points.
    #[test]
    fn a_symlinked_mount_point_is_refused() {
        let home = tempfile::tempdir().expect("a temp dir");
        let elsewhere = home.path().join("elsewhere");
        fs::create_dir(&elsewhere).expect("a target directory");
        let at = home.path().join("CipherBox");
        std::os::unix::fs::symlink(&elsewhere, &at).expect("a symlinked mount point");

        assert!(prepare(&at).is_err());
    }

    #[test]
    fn a_mount_point_that_is_a_file_is_refused() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = home.path().join("CipherBox");
        fs::write(&at, b"not a directory").expect("a file in the way");

        assert!(prepare(&at).is_err());
    }

    fn node(kind: NodeKind, size: Option<u64>) -> Attributes {
        Attributes {
            ino: 42,
            node: NodeId([3; 16]),
            kind,
            size,
            mtime_millis: Some(1_700_000_000_123),
        }
    }

    /// The mount presents no executable and nothing group- or world-readable:
    /// the projection has no POSIX mode of its own, so what it shows is policy.
    #[test]
    fn the_mount_presents_owner_only_modes_and_no_execute_bit_on_files() {
        let file = file_attr(&node(NodeKind::File, Some(1)), 1, owner());
        assert_eq!(file.perm, 0o600);
        assert_eq!(file.perm & 0o077, 0, "nothing for group or other");
        assert_eq!(file.perm & 0o111, 0, "no execute bit anywhere");

        let folder = file_attr(&node(NodeKind::Folder, None), 0, owner());
        assert_eq!(folder.perm, 0o700);
        assert_eq!(folder.perm & 0o077, 0, "nothing for group or other");
    }

    #[test]
    fn a_node_belongs_to_the_user_who_mounted_it() {
        let attrs = file_attr(&node(NodeKind::File, Some(1)), 1, owner());
        assert_eq!((attrs.uid, attrs.gid), (501, 20));
    }

    /// `st_blocks` is in 512-byte units whatever `st_blksize` advertises, and it
    /// rounds up: a kernel told zero blocks for a non-empty file reports a file
    /// that occupies nothing.
    #[test]
    fn block_counts_are_512_byte_units_rounded_up() {
        for (size, blocks) in [(0, 0), (1, 1), (512, 1), (513, 2), (4096, 8)] {
            let attrs = file_attr(&node(NodeKind::File, Some(size)), size, owner());
            assert_eq!(attrs.blocks, blocks, "{size} bytes");
        }
    }

    #[test]
    fn kinds_and_link_counts_follow_the_projection() {
        let file = file_attr(&node(NodeKind::File, Some(0)), 0, owner());
        assert_eq!(file.kind, FileType::RegularFile);
        assert_eq!(file.nlink, 1);

        let folder = file_attr(&node(NodeKind::Folder, None), 0, owner());
        assert_eq!(folder.kind, FileType::Directory);
        assert_eq!(folder.nlink, 2, "a directory's own `.` is the second link");
    }

    /// An mtime the content plane never projected is the epoch, not a clock
    /// read: the projection has no clock of its own.
    #[test]
    fn an_unprojected_mtime_is_the_epoch() {
        let mut attrs = node(NodeKind::File, Some(0));
        attrs.mtime_millis = None;
        assert_eq!(file_attr(&attrs, 0, owner()).mtime, UNIX_EPOCH);

        attrs.mtime_millis = Some(1_500);
        assert_eq!(
            file_attr(&attrs, 0, owner()).mtime,
            UNIX_EPOCH + Duration::from_millis(1_500)
        );
    }

    fn child(ino: u64, name: &str) -> DirEntry {
        DirEntry {
            ino,
            name: name.to_owned(),
            kind: NodeKind::File,
            size: Some(0),
            mtime_millis: None,
        }
    }

    /// One walk's worth of entries as the kernel sees them, resumed at
    /// `offset` — the core hands back the children from that offset's cursor,
    /// and this is what the adapter packs.
    fn walk(ino: u64, offset: usize, children: &[DirEntry]) -> Vec<(u64, String, i64)> {
        let tail = children.get(cursor_of(offset)..).unwrap_or_default();
        page(ino, offset, tail)
            .map(|(child, _, name, resume_at)| (child, name.to_owned(), resume_at))
            .collect()
    }

    fn children() -> Vec<DirEntry> {
        vec![child(2, "alpha"), child(3, "beta"), child(4, "gamma")]
    }

    /// A listing leads with `.` and `..`, both naming the directory itself.
    #[test]
    fn a_listing_leads_with_the_dot_entries() {
        let listed: Vec<_> = page(1, 0, &children())
            .take(DOT_ENTRIES)
            .map(|(ino, kind, name, _)| (ino, kind, name.to_owned()))
            .collect();
        assert_eq!(
            listed,
            vec![
                (1, NodeKind::Folder, ".".to_owned()),
                (1, NodeKind::Folder, "..".to_owned()),
            ]
        );
    }

    /// The cookie the kernel resumes at is the offset *after* the entry it
    /// took, so resuming there must land on the next entry — never repeat or
    /// skip one, and never re-emit a dot entry the walk has passed.
    #[test]
    fn a_continuation_resumes_on_the_entry_after_the_last_one_taken() {
        let children = children();
        let whole = walk(1, 0, &children);

        for taken in 0..whole.len() {
            let resume_at = whole[taken].2 as usize;
            assert_eq!(
                walk(1, resume_at, &children),
                whole[taken + 1..],
                "resuming at {resume_at}"
            );
        }
    }

    #[test]
    fn a_cookie_past_the_end_emits_nothing() {
        let children = children();
        assert!(walk(1, DOT_ENTRIES + children.len(), &children).is_empty());
        assert!(walk(1, usize::MAX, &children).is_empty());
    }

    /// The floor is the shared wire's, not each backend's, so a new backend
    /// cannot ship without it — and cannot widen who reads the vault either.
    #[test]
    fn every_mount_carries_the_floor_and_no_option_that_widens_it() {
        let options = mount_options(vec![MountOption::CUSTOM("backend=smb".to_owned())])
            .expect("a backend option is added on top of the floor");
        for required in [
            MountOption::FSName("cipherbox".to_owned()),
            MountOption::DefaultPermissions,
            MountOption::NoSuid,
            MountOption::NoExec,
            MountOption::NoDev,
        ] {
            assert!(options.contains(&required), "{required:?}");
        }
        assert!(options.contains(&MountOption::CUSTOM("backend=smb".to_owned())));

        for refused in [
            MountOption::AllowOther,
            MountOption::AllowRoot,
            MountOption::AutoUnmount,
            MountOption::Suid,
            MountOption::Exec,
            MountOption::Dev,
            // A backend that speaks only in custom strings — which is what the
            // FUSE-T profile is — reaches the same options this way.
            MountOption::CUSTOM("allow_other".to_owned()),
            MountOption::CUSTOM("noattrcache,suid".to_owned()),
        ] {
            assert!(
                mount_options(vec![refused.clone()]).is_err(),
                "{refused:?} must be refused, not merely absent"
            );
        }

        for allowed in [
            MountOption::NoAtime,
            MountOption::CUSTOM("noattrcache".to_owned()),
            MountOption::CUSTOM("backend=smb".to_owned()),
            MountOption::CUSTOM("nfc".to_owned()),
        ] {
            assert!(
                mount_options(vec![allowed.clone()]).is_ok(),
                "{allowed:?} narrows nothing and must pass"
            );
        }
    }

    /// Everything the decoder refuses before the core sees it comes from the
    /// one table, so a second unix adapter cannot answer these differently.
    #[test]
    fn a_pre_core_refusal_comes_from_the_shared_table() {
        assert_eq!(malformed(), errno_of(&VfsError::Invalid));
        assert_eq!(malformed(), libc::EINVAL);
    }

    #[test]
    fn a_name_the_projection_cannot_hold_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt;

        assert_eq!(as_utf8(OsStr::new("alpha")).as_deref(), Some("alpha"));
        assert_eq!(as_utf8(OsStr::from_bytes(&[0xff, 0xfe])), None);
    }

    /// The default width is 16 MiB, and every write in flight holds that much
    /// plaintext in the op queue.
    #[test]
    fn the_mount_narrows_the_kernels_write_width() {
        assert!(MAX_WRITE_BYTES < fuser::MAX_WRITE_SIZE as u32);
    }

    /// A client that reads `statfs` before writing refuses the write on a zero,
    /// so the mount advertises the headroom the facade cannot measure.
    #[test]
    fn the_mount_advertises_room_it_cannot_measure() {
        let (blocks, files, free_nodes) = statfs_counts(StatFs { nodes: 7 });

        assert!(blocks > 0, "bavail is what a client checks before writing");
        assert!(free_nodes > 0, "a zero ffree refuses file creation");
        assert_eq!(files, 7 + free_nodes, "the nodes in use stay truthful");
    }
}
