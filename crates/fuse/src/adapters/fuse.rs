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
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

use crate::adapter::{CacheTtls, HostAdapter, HostCapabilities, Invalidation};
use crate::errno::errno_of;
use crate::error::VfsError;
use crate::handle::{Access, HandleId};
use crate::name::MAX_NAME_BYTES;
use crate::ops::{Attributes, DirEntry, OperationCore};

/// Inodes are per mount session and never reused, so there is no generation
/// axis for the kernel to disambiguate along.
const GENERATION: u64 = 0;

/// `st_blocks` counts 512-byte units by POSIX definition, whatever `st_blksize`
/// says.
const STAT_BLOCK_BYTES: u64 = 512;

/// The I/O size the mount advertises. One page: the projection's own framing is
/// the chunk cache's, and nothing here is served better by a larger hint.
const PREFERRED_IO_BYTES: u32 = 4096;

/// The capacity `statfs` advertises. Byte accounting does not reach the facade,
/// and a mount that answers zero free space is refused *before* the write by
/// clients that read `statfs` first; a write over a real budget is still refused
/// where it belongs, by the engine's `ENOSPC`/`EDQUOT`.
const ADVISORY_CAPACITY_BYTES: u64 = 1 << 40;

/// The node-count counterpart of [`ADVISORY_CAPACITY_BYTES`]: the nodes in use
/// are truthful, the headroom above them is not.
const ADVISORY_FREE_NODES: u64 = 1 << 20;

/// The widest single write the kernel may hand over. fuser's default is 16 MiB,
/// and every write in flight holds that much plaintext in the op queue until
/// the pump reaches it.
const MAX_WRITE_BYTES: u32 = 1 << 20;

/// Owner-only, and no execute bit: the projection carries no POSIX mode of its
/// own, and a vault is not a place to hand out an executable.
const FILE_MODE: u16 = 0o600;
/// The directory counterpart of [`FILE_MODE`] — traversal needs the execute
/// bit.
const DIRECTORY_MODE: u16 = 0o700;

/// `.` and `..`, which a listing synthesizes ahead of the real children.
const DOT_ENTRIES: usize = 2;

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
    /// Whether a `readdir` sequence resumes at the cookie the previous reply
    /// ended on. FUSE-T's smbfs client walks a directory in a single pass and
    /// never returns for the rest, so a listing kept for it could only answer a
    /// request that never comes (blueprint/desktop.md "The FS core and host
    /// adapters" — readdir single-pass).
    pub(crate) resumable_readdir: bool,
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
    ReadDir {
        ino: u64,
        offset: usize,
        reply: ReplyDirectory,
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
            | FuseOp::Flush { reply, .. }
            | FuseOp::FSync { reply, .. }
            | FuseOp::Release { reply, .. } => reply.error(errno),
            FuseOp::ReadDir { reply, .. } => reply.error(errno),
            FuseOp::Create { reply, .. } => reply.error(errno),
            FuseOp::Open { reply, .. } => reply.error(errno),
            FuseOp::Read { reply, .. } => reply.error(errno),
            FuseOp::Write { reply, .. } => reply.error(errno),
            FuseOp::StatFs { reply, .. } => reply.error(errno),
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

/// The listing the kernel is currently walking.
///
/// On a backend that resumes at the cookie the previous reply ended on,
/// rendering the directory again per continuation makes one listing cost a
/// render per reply buffer. One slot is enough — the kernel walks one stream at
/// a time — and a miss simply renders.
struct DirStream {
    resumable: bool,
    dir: Option<u64>,
    entries: Vec<DirEntry>,
}

impl DirStream {
    fn new(resumable: bool) -> Self {
        Self {
            resumable,
            dir: None,
            entries: Vec::new(),
        }
    }

    /// Whether the listing in hand answers this request, or the directory has
    /// to be rendered again. A fresh walk always renders, so a directory is
    /// never served from a listing older than the walk asking for it.
    fn serves(&self, ino: u64, offset: usize) -> bool {
        self.resumable && offset != 0 && self.dir == Some(ino)
    }

    fn hold(&mut self, ino: u64, entries: Vec<DirEntry>) {
        self.dir = Some(ino);
        self.entries = entries;
    }

    fn forget(&mut self) {
        self.dir = None;
        self.entries = Vec::new();
    }

    /// Drop the listing a backend will not come back for — on a single-pass
    /// mount that is every listing, and each one is a directory's worth of
    /// filenames held for the life of the mount otherwise.
    fn release(&mut self) {
        if !self.resumable {
            self.forget();
        }
    }

    /// The entry a listing emits at `index`: the two dot entries, then the
    /// children. Both dot entries name the directory itself — the kernel
    /// resolves `..` through lookup and its own dcache, never through the inode
    /// a listing reports.
    fn at(&self, index: usize, ino: u64) -> Option<(u64, NodeKind, &OsStr)> {
        match index {
            0 => Some((ino, NodeKind::Folder, OsStr::new("."))),
            1 => Some((ino, NodeKind::Folder, OsStr::new(".."))),
            _ => self
                .entries
                .get(index - DOT_ENTRIES)
                .map(|child| (child.ino, child.kind, OsStr::new(&child.name))),
        }
    }

    fn len(&self) -> usize {
        DOT_ENTRIES + self.entries.len()
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
    listing: DirStream,
}

impl FuseMount {
    /// Mount at `mountpoint`, which must already exist, under one backend's
    /// [`MountProfile`] and the shared [`floor_options`].
    pub(crate) fn at(mountpoint: &Path, profile: MountProfile) -> io::Result<Self> {
        let options = mount_options(profile.options)?;
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
            listing: DirStream::new(profile.resumable_readdir),
        })
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
            answer(core, op, self.owner, &mut self.listing).await;
        }
    }

    /// Stop accepting kernel operations, ahead of the unmount
    /// (blueprint/desktop.md "Lifecycle" — quiesce, unmount, stop the engine).
    /// Everything queued and everything the session dispatches from here is
    /// refused rather than left for a pump that has stopped running.
    pub fn quiesce(&mut self) {
        self.ops.close();
        while let Ok(op) = self.ops.try_recv() {
            op.refuse(libc::ENOTCONN);
        }
    }
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

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        reply: ReplyDirectory,
    ) {
        let Ok(offset) = usize::try_from(offset) else {
            reply.error(malformed());
            return;
        };
        self.dispatch(FuseOp::ReadDir { ino, offset, reply });
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
    listing: &mut DirStream,
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
        FuseOp::ReadDir {
            ino,
            offset,
            mut reply,
        } => {
            if !listing.serves(ino, offset) {
                match core.readdir(ino).await {
                    Ok(entries) => listing.hold(ino, entries),
                    Err(refusal) => {
                        listing.forget();
                        reply.error(errno_of(&refusal));
                        return;
                    }
                }
            }
            emit_listing(&mut reply, ino, offset, listing);
            reply.ok();
            listing.release();
        }
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
                    let (size, ttl) = ttls.projected_size(&attrs);
                    reply.created(
                        &ttl,
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

/// One lifetime covers the name binding and the attributes both, so a
/// provisional size holds the whole reply down to zero.
fn entry(
    reply: ReplyEntry,
    owner: Ownership,
    ttls: CacheTtls,
    outcome: Result<Attributes, VfsError>,
) {
    match outcome {
        Ok(attrs) => {
            let (size, ttl) = ttls.projected_size(&attrs);
            reply.entry(&ttl, &file_attr(&attrs, size, owner), GENERATION);
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

/// Pack `listing` into the reply buffer, resuming at `offset`.
fn emit_listing(reply: &mut ReplyDirectory, ino: u64, offset: usize, listing: &DirStream) {
    for index in offset..listing.len() {
        let Some((child, kind, name)) = listing.at(index, ino) else {
            break;
        };
        // The offset the kernel resumes at is the one *after* this entry.
        if reply.add(child, index as i64 + 1, file_type(kind), name) {
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
    use cipherbox_engine::NodeId;

    use super::*;

    fn owner() -> Ownership {
        Ownership { uid: 501, gid: 20 }
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
        }
    }

    fn stream() -> DirStream {
        streaming(true)
    }

    fn streaming(resumable: bool) -> DirStream {
        let mut listing = DirStream::new(resumable);
        listing.hold(1, vec![child(2, "alpha"), child(3, "beta")]);
        listing
    }

    /// A listing leads with `.` and `..`, both naming the directory itself.
    #[test]
    fn a_listing_leads_with_the_dot_entries() {
        let listing = stream();
        assert_eq!(listing.len(), 4);
        for index in [0, 1] {
            let (ino, kind, name) = listing.at(index, 1).expect("a dot entry");
            assert_eq!(ino, 1);
            assert_eq!(kind, NodeKind::Folder);
            assert_eq!(name, if index == 0 { "." } else { ".." });
        }
    }

    /// The cookie the kernel resumes at is the index *after* the entry it took,
    /// so resuming there must land on the next child, never repeat or skip one.
    #[test]
    fn a_continuation_resumes_on_the_entry_after_the_last_one_taken() {
        let listing = stream();
        let emitted: Vec<_> = (0..listing.len())
            .filter_map(|index| listing.at(index, 1))
            .map(|(ino, _, name)| (ino, name.to_owned()))
            .collect();

        for resumed in 0..listing.len() {
            let rest: Vec<_> = (resumed..listing.len())
                .filter_map(|index| listing.at(index, 1))
                .map(|(ino, _, name)| (ino, name.to_owned()))
                .collect();
            assert_eq!(rest, emitted[resumed..], "resuming at {resumed}");
        }
    }

    /// A walk that starts over must see the directory as it is now, or a mount
    /// would serve a listing older than the `readdir` asking for it.
    #[test]
    fn a_fresh_walk_always_renders() {
        for resumable in [true, false] {
            assert!(!streaming(resumable).serves(1, 0));
        }
    }

    #[test]
    fn a_resumable_backend_continues_the_listing_in_hand() {
        let listing = stream();
        assert!(listing.serves(1, 1));
        assert!(!listing.serves(2, 1), "another directory renders its own");
        assert!(!DirStream::new(true).serves(1, 1), "an empty slot renders");
    }

    #[test]
    fn a_single_pass_backend_is_never_served_from_a_previous_reply() {
        let listing = streaming(false);
        for offset in [0, 1, 2, usize::MAX] {
            assert!(!listing.serves(1, offset), "at {offset}");
        }
    }

    /// A listing a backend will not come back for is a directory's worth of
    /// filenames held for the life of the mount.
    #[test]
    fn a_single_pass_backend_keeps_no_listing_after_its_reply() {
        let mut kept = streaming(true);
        kept.release();
        assert!(
            kept.serves(1, 1),
            "a resumable backend keeps what it may ask for"
        );

        let mut dropped = streaming(false);
        dropped.release();
        assert_eq!(
            dropped.len(),
            DOT_ENTRIES,
            "nothing but the dot entries left"
        );
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

    #[test]
    fn a_cookie_past_the_end_emits_nothing() {
        let listing = stream();
        assert!(listing.at(listing.len(), 1).is_none());
        assert!(listing.at(usize::MAX, 1).is_none());
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
