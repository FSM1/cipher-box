//! The Linux host adapter: kernel FUSE through the vendored `fuser`
//! (blueprint/desktop.md "Backends").
//!
//! Two directions, two objects. Inbound, [`KernelSession`] decodes the wire on
//! fuser's session thread and hands each operation — with the reply it is owed
//! — to the engine task, the only thread that may touch the operation core.
//! Outbound, [`KernelInvalidator`] turns the core's invalidations into
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

/// Pushes the operation core's invalidations at the kernel.
#[derive(Clone)]
pub struct KernelInvalidator(Notifier);

impl HostAdapter for KernelInvalidator {
    fn capabilities(&self) -> HostCapabilities {
        HostCapabilities {
            push_invalidation: true,
            attribute_cache: true,
        }
    }

    fn invalidate(&self, invalidation: Invalidation) {
        // An inode the kernel never cached answers `ENOENT`, which the notifier
        // already absorbs; what is left is a channel on its way down, and the
        // trait's contract is that the adapter absorbs that too.
        let _ = match invalidation {
            // Offset zero, length zero: the attributes and every cached page.
            Invalidation::Data { ino } => self.0.inval_inode(ino, 0, 0),
            // A negative offset is the kernel's "attributes only".
            Invalidation::Attributes { ino } => self.0.inval_inode(ino, -1, 0),
            Invalidation::Entry { parent, name } => self.0.inval_entry(parent, OsStr::new(&name)),
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
enum KernelOp {
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

impl KernelOp {
    /// Answer with `errno` instead of running — the only thing to do with a
    /// request the engine task will never see. A FUSE request nobody answers
    /// hangs its caller for the life of the mount.
    fn refuse(self, errno: i32) {
        match self {
            KernelOp::Lookup { reply, .. } | KernelOp::MkDir { reply, .. } => reply.error(errno),
            KernelOp::GetAttr { reply, .. } | KernelOp::SetSize { reply, .. } => reply.error(errno),
            KernelOp::Unlink { reply, .. }
            | KernelOp::RmDir { reply, .. }
            | KernelOp::Rename { reply, .. }
            | KernelOp::Flush { reply, .. }
            | KernelOp::FSync { reply, .. }
            | KernelOp::Release { reply, .. } => reply.error(errno),
            KernelOp::ReadDir { reply, .. } => reply.error(errno),
            KernelOp::Create { reply, .. } => reply.error(errno),
            KernelOp::Open { reply, .. } => reply.error(errno),
            KernelOp::Read { reply, .. } => reply.error(errno),
            KernelOp::Write { reply, .. } => reply.error(errno),
            KernelOp::StatFs { reply, .. } => reply.error(errno),
        }
    }
}

/// The `fuser::Filesystem` this mount registers: a decoder, and nothing else.
struct KernelSession {
    ops: mpsc::UnboundedSender<KernelOp>,
}

impl KernelSession {
    fn dispatch(&self, op: KernelOp) {
        if let Err(refused) = self.ops.unbounded_send(op) {
            // The engine task is gone; the mount is on its way down.
            refused.into_inner().refuse(libc::ENOTCONN);
        }
    }
}

/// The listing the kernel is currently walking.
///
/// A `readdir` sequence resumes at the cookie the previous reply ended on, so
/// rendering the directory again per continuation makes one listing cost a
/// render per reply buffer. One slot is enough — the kernel walks one stream at
/// a time — and a miss simply renders.
#[derive(Default)]
struct DirStream {
    dir: Option<u64>,
    entries: Vec<DirEntry>,
}

impl DirStream {
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

/// A live kernel mount. Dropping it unmounts and ends the session thread; the
/// operation core it fed is torn down separately, by its own `unmount`.
pub struct KernelMount {
    /// Held for its `Drop`, which is the unmount.
    _session: BackgroundSession,
    invalidator: KernelInvalidator,
    ops: mpsc::UnboundedReceiver<KernelOp>,
    owner: Ownership,
}

impl KernelMount {
    /// Mount at `mountpoint`, which must already exist.
    ///
    /// Owner-only by construction: no `allow_other`, and therefore no
    /// `auto_unmount` either, since fuser must add `allow_other` to get it — a
    /// vault the whole machine can read is not a trade for tidier teardown.
    pub fn at(mountpoint: &Path) -> io::Result<Self> {
        let (sender, ops) = mpsc::unbounded();
        let session = Session::new(
            KernelSession { ops: sender },
            mountpoint,
            &[
                MountOption::FSName("cipherbox".to_owned()),
                MountOption::DefaultPermissions,
                MountOption::NoSuid,
                MountOption::NoExec,
                MountOption::NoDev,
                MountOption::NoAtime,
            ],
        )?;
        let invalidator = KernelInvalidator(session.notifier());
        Ok(Self {
            _session: session.spawn()?,
            invalidator,
            ops,
            owner: Ownership {
                uid: nix::unistd::Uid::effective().as_raw(),
                gid: nix::unistd::Gid::effective().as_raw(),
            },
        })
    }

    /// The invalidator to mount the operation core behind.
    pub fn invalidator(&self) -> KernelInvalidator {
        self.invalidator.clone()
    }

    /// Answer kernel operations from `core` until the session ends.
    ///
    /// Serial by construction — one operation core is one stateful projection —
    /// and the never-block law is what keeps a serial pump responsive: no
    /// operation here awaits IPNS resolution, publish, or API bookkeeping.
    pub async fn serve<T: SeamTypes>(&mut self, core: &mut OperationCore<T, KernelInvalidator>) {
        let owner = self.owner;
        let mut listing = DirStream::default();
        loop {
            let next = core::future::poll_fn(|cx| Pin::new(&mut self.ops).poll_next(cx)).await;
            let Some(op) = next else { break };
            answer(core, op, owner, &mut listing).await;
        }
    }
}

impl Filesystem for KernelSession {
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
        self.dispatch(KernelOp::Lookup {
            parent,
            name,
            reply,
        });
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        self.dispatch(KernelOp::GetAttr { ino, reply });
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
            Some(size) => KernelOp::SetSize {
                ino,
                size,
                handle: fh.map(HandleId),
                reply,
            },
            None => KernelOp::GetAttr { ino, reply },
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
        self.dispatch(KernelOp::MkDir {
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
        self.dispatch(KernelOp::Unlink {
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
        self.dispatch(KernelOp::RmDir {
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
        self.dispatch(KernelOp::Rename {
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
        self.dispatch(KernelOp::Create {
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
        self.dispatch(KernelOp::Open {
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
        self.dispatch(KernelOp::Read {
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
        self.dispatch(KernelOp::Write {
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
        self.dispatch(KernelOp::ReadDir { ino, offset, reply });
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
        self.dispatch(KernelOp::Flush {
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
        self.dispatch(KernelOp::FSync {
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
        self.dispatch(KernelOp::Release {
            handle: HandleId(fh),
            reply,
        });
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        self.dispatch(KernelOp::StatFs { reply });
    }
}

/// The engine stores names as UTF-8 text, so bytes that are not are a name no
/// client could have committed. Admission proper is the core's.
fn as_utf8(name: &OsStr) -> Option<String> {
    name.to_str().map(str::to_owned)
}

/// Run one operation and answer its reply.
async fn answer<T: SeamTypes>(
    core: &mut OperationCore<T, KernelInvalidator>,
    op: KernelOp,
    owner: Ownership,
    listing: &mut DirStream,
) {
    match op {
        KernelOp::Lookup {
            parent,
            name,
            reply,
        } => {
            let outcome = core.lookup(parent, &name).await;
            entry(reply, owner, core.cache_ttls(), outcome);
        }
        KernelOp::GetAttr { ino, reply } => {
            let outcome = core.getattr(ino).await;
            attr(reply, owner, core.cache_ttls(), outcome);
        }
        KernelOp::SetSize {
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
        KernelOp::ReadDir {
            ino,
            offset,
            mut reply,
        } => {
            // A fresh stream always renders; only a continuation of the one in
            // hand is served from it.
            if offset == 0 || listing.dir != Some(ino) {
                match core.readdir(ino).await {
                    Ok(entries) => {
                        *listing = DirStream {
                            dir: Some(ino),
                            entries,
                        }
                    }
                    Err(refusal) => {
                        *listing = DirStream::default();
                        reply.error(errno_of(&refusal));
                        return;
                    }
                }
            }
            emit_listing(&mut reply, ino, offset, listing);
            reply.ok();
        }
        KernelOp::Create {
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
        KernelOp::MkDir {
            parent,
            name,
            reply,
        } => {
            let outcome = core.mkdir(parent, &name).await;
            entry(reply, owner, core.cache_ttls(), outcome);
        }
        KernelOp::Unlink {
            parent,
            name,
            reply,
        } => empty(reply, core.unlink(parent, &name).await),
        KernelOp::RmDir {
            parent,
            name,
            reply,
        } => empty(reply, core.rmdir(parent, &name).await),
        KernelOp::Rename {
            parent,
            name,
            new_parent,
            new_name,
            reply,
        } => empty(
            reply,
            core.rename(parent, &name, new_parent, &new_name).await,
        ),
        KernelOp::Open {
            ino,
            access,
            truncate,
            reply,
        } => match open_handle(core, ino, access, truncate).await {
            Ok(handle) => reply.opened(handle.0, 0),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        KernelOp::Read {
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
        KernelOp::Write {
            handle,
            offset,
            data,
            reply,
        } => match core.write(handle, offset, &data).await {
            Ok(taken) => reply.written(taken),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        KernelOp::Flush { handle, reply } => empty(reply, core.flush(handle).await),
        KernelOp::FSync { handle, reply } => empty(reply, core.fsync(handle).await),
        KernelOp::Release { handle, reply } => empty(reply, core.release(handle).await),
        KernelOp::StatFs { reply } => match core.statfs().await {
            Ok(stats) => reply_statfs(reply, stats),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
    }
}

/// `O_TRUNC` is open-then-truncate: the new length rides into the one
/// `updateContent` op this handle's release journals, so the opening truncate
/// and the writes after it become a single version.
async fn open_handle<T: SeamTypes>(
    core: &mut OperationCore<T, KernelInvalidator>,
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

fn reply_statfs(reply: ReplyStatfs, stats: StatFs) {
    // Byte accounting does not reach the facade; the node count and the
    // advertised name length are what this mount can answer truthfully.
    reply.statfs(
        0,
        0,
        0,
        stats.nodes,
        0,
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
        DirStream {
            dir: Some(1),
            entries: vec![child(2, "alpha"), child(3, "beta")],
        }
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
}
