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
//! finishes.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cipherbox_engine::seams::SeamTypes;
use cipherbox_engine::{NodeKind, StatFs};
use fuser::{
    BackgroundSession, FileAttr, FileType, Filesystem, MountOption, Notifier, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, Request, Session, TimeOrNow,
};
use futures_channel::mpsc;
use futures_core::Stream;
use zeroize::Zeroizing;

use crate::adapter::{HostAdapter, HostCapabilities, Invalidation};
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

/// Owner-only, and no execute bit: the projection carries no POSIX mode of its
/// own, and a vault is not a place to hand out an executable.
const FILE_MODE: u16 = 0o600;
/// The directory counterpart of [`FILE_MODE`] — traversal needs the execute
/// bit.
const DIRECTORY_MODE: u16 = 0o700;

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
        // Absorbed, per the trait's contract: the mutation is already durable,
        // and a channel that will not take the notification is the session
        // ending, with no surface left to tell.
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
        size: Option<u64>,
        handle: Option<HandleId>,
        reply: ReplyAttr,
    },
    ReadDir {
        ino: u64,
        offset: i64,
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
    /// request the engine task will never see.
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
        while let Some(op) = core::future::poll_fn(|cx| Pin::new(&mut self.ops).poll_next(cx)).await
        {
            answer(core, op, self.owner).await;
        }
    }
}

impl Filesystem for KernelSession {
    fn destroy(&mut self) {
        // Ends the pump: the session is over, so no further operation can be
        // answered.
        self.ops.close_channel();
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match admissible(name) {
            Some(name) => self.dispatch(KernelOp::Lookup {
                parent,
                name,
                reply,
            }),
            None => reply.error(libc::EINVAL),
        }
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
        self.dispatch(KernelOp::SetSize {
            ino,
            size,
            handle: fh.map(HandleId),
            reply,
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
        match admissible(name) {
            Some(name) => self.dispatch(KernelOp::MkDir {
                parent,
                name,
                reply,
            }),
            None => reply.error(libc::EINVAL),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match admissible(name) {
            Some(name) => self.dispatch(KernelOp::Unlink {
                parent,
                name,
                reply,
            }),
            None => reply.error(libc::EINVAL),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match admissible(name) {
            Some(name) => self.dispatch(KernelOp::RmDir {
                parent,
                name,
                reply,
            }),
            None => reply.error(libc::EINVAL),
        }
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
        match (admissible(name), admissible(new_name)) {
            (Some(name), Some(new_name)) => self.dispatch(KernelOp::Rename {
                parent,
                name,
                new_parent,
                new_name,
                reply,
            }),
            _ => reply.error(libc::EINVAL),
        }
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
        let (Some(name), Some(access)) = (admissible(name), Access::from_open_flags(flags)) else {
            reply.error(libc::EINVAL);
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
            reply.error(libc::EINVAL);
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
            reply.error(libc::EINVAL);
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
            reply.error(libc::EINVAL);
            return;
        };
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
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
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

/// A name the wire can carry into the projection. The engine stores names as
/// UTF-8 text; bytes that are not are a name no client could have committed.
fn admissible(name: &OsStr) -> Option<String> {
    name.to_str().map(str::to_owned)
}

/// Run one operation and answer its reply.
async fn answer<T: SeamTypes>(
    core: &mut OperationCore<T, KernelInvalidator>,
    op: KernelOp,
    owner: Ownership,
) {
    let ttls = core.cache_ttls();
    match op {
        KernelOp::Lookup {
            parent,
            name,
            reply,
        } => match core.lookup(parent, &name).await {
            // One lifetime covers the name binding and the attributes both, so
            // a provisional size holds the whole reply down to zero.
            Ok(attrs) => reply.entry(
                &ttls.attr_for(attrs.kind, attrs.size),
                &file_attr(&attrs, owner),
                GENERATION,
            ),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        KernelOp::GetAttr { ino, reply } => match core.getattr(ino).await {
            Ok(attrs) => reply.attr(
                &ttls.attr_for(attrs.kind, attrs.size),
                &file_attr(&attrs, owner),
            ),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        KernelOp::SetSize {
            ino,
            size,
            handle,
            reply,
        } => {
            if let Some(size) = size
                && let Err(refusal) = core.truncate(ino, size, handle).await
            {
                reply.error(errno_of(&refusal));
                return;
            }
            match core.getattr(ino).await {
                Ok(attrs) => reply.attr(
                    &ttls.attr_for(attrs.kind, attrs.size),
                    &file_attr(&attrs, owner),
                ),
                Err(refusal) => reply.error(errno_of(&refusal)),
            }
        }
        KernelOp::ReadDir {
            ino,
            offset,
            mut reply,
        } => match core.readdir(ino).await {
            Ok(entries) => {
                emit_listing(&mut reply, ino, offset, entries);
                reply.ok();
            }
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        KernelOp::Create {
            parent,
            name,
            access,
            reply,
        } => match core.create(parent, &name, access).await {
            Ok((attrs, handle)) => reply.created(
                &ttls.attr_for(attrs.kind, attrs.size),
                &file_attr(&attrs, owner),
                GENERATION,
                handle.0,
                0,
            ),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
        KernelOp::MkDir {
            parent,
            name,
            reply,
        } => match core.mkdir(parent, &name).await {
            Ok(attrs) => reply.entry(
                &ttls.attr_for(attrs.kind, attrs.size),
                &file_attr(&attrs, owner),
                GENERATION,
            ),
            Err(refusal) => reply.error(errno_of(&refusal)),
        },
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

/// Emit `.` and `..` and then the directory's children, resuming at `offset`.
///
/// Both dot entries name this directory: the kernel resolves `..` through
/// lookup and its own dcache, never through the inode a listing reports.
fn emit_listing(reply: &mut ReplyDirectory, ino: u64, offset: i64, entries: Vec<DirEntry>) {
    let dots = [
        (ino, NodeKind::Folder, OsString::from(".")),
        (ino, NodeKind::Folder, OsString::from("..")),
    ];
    let children = entries
        .into_iter()
        .map(|entry| (entry.ino, entry.kind, OsString::from(entry.name)));
    let taken = usize::try_from(offset).unwrap_or(usize::MAX);
    for (index, (child, kind, name)) in dots.into_iter().chain(children).enumerate().skip(taken) {
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

/// The projection's attributes as the kernel's `stat`.
///
/// An unprojected size has to become *some* number here; `attribute_ttl` is
/// what keeps the kernel from caching that number.
fn file_attr(attrs: &Attributes, owner: Ownership) -> FileAttr {
    let size = attrs.size.unwrap_or(0);
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
