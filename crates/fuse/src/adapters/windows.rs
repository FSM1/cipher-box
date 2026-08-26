//! The Windows backend: WinFsp's user-mode filesystem host, reached through the
//! `winfsp` crate (blueprint/desktop.md "Backends").
//!
//! WinFsp is GPLv3 and so is winfsp-rs; the combined work ships under GPLv3,
//! with WinFsp's commercial licence as the escape hatch. Its licence asks that
//! the notice be shown, and it is — `docs/ATTRIBUTION.md` and the desktop app's
//! about surface both carry it.
//!
//! Two directions, two objects, exactly as the FUSE wire has them
//! ([`crate::adapters::fuse`]). Inbound, [`VaultFs`] decodes WinFsp's callbacks
//! on a dispatcher thread and hands each operation to the engine task, the only
//! thread that may touch the operation core. Outbound, [`WinFspInvalidator`]
//! turns the core's invalidations into `FspFileSystemNotify`.
//!
//! What differs from the FUSE wire is where the answer is written. A FUSE reply
//! object can be carried across a thread and answered wherever the operation
//! finishes, so its session thread never waits. A WinFsp callback *returns* its
//! NTSTATUS, so the dispatcher thread that decoded the request is the one that
//! has to answer it: every operation here crosses to the engine task with a
//! one-shot channel and the dispatcher blocks on it. WinFsp runs a pool of
//! dispatcher threads, so several may wait at once while the pump stays serial.
//!
//! Two more consequences of the protocol, both stated here rather than
//! discovered later:
//!
//! * **Names are paths, not `(parent, name)` pairs.** Every path-bearing
//!   callback is resolved a component at a time through the core's `lookup`,
//!   which is also what makes [`HostCapabilities::case_insensitive_lookup`]
//!   load-bearing on this backend: Windows resolves `REPORT.TXT` onto a stored
//!   `Report.txt`, while the engine's strict comparator still decides every
//!   collision.
//! * **There is no FORGET.** Nothing ever hands an inode reference back, so
//!   this adapter takes none it would have to. The inode table already mints a
//!   binding for every child a listing names and keeps it for the session; what
//!   is bounded — the operation core's served/listed shadow maps, and this
//!   adapter's [`PathBook`] — stays bounded and corrects the kernel on
//!   eviction.

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::fs;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};

use cipherbox_engine::seams::SeamTypes;
use cipherbox_engine::{NodeKind, StatFs, SyncTimingProfile};
use futures_channel::mpsc;
use futures_core::Stream;
use widestring::U16CStr;
use winfsp::FspError;
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo,
    WideNameInfo,
};
use winfsp::host::{FileSystemHost, FileSystemParams, VolumeParams};
use winfsp::notify::{Notifier, NotifyInfo, NotifyingFileSystemContext};
use zeroize::Zeroizing;

use crate::adapter::{CacheTtls, HostAdapter, HostCapabilities, Invalidation};
use crate::error::VfsError;
use crate::handle::{Access, HandleId};
use crate::inode::ROOT_INO;
use crate::name::MAX_NAME_BYTES;
use crate::ntstatus::{NtStatus, ntstatus_of};
use crate::ops::{Attributes, DirEntry, DirHandleId, OperationCore};

/// What a WinFsp mount can do for the operation core.
///
/// `case_insensitive_lookup` is the Windows convention and the only place the
/// three profiles differ: a name the caller types resolves onto the spelling
/// the vault stores. Presentation only — collisions are decided by the engine's
/// one strict comparator on every platform, so a folder committed anywhere
/// mounts everywhere (blueprint/desktop.md "Names and attributes").
///
/// Public because it is the profile the portable vfs suite drives the core
/// with on this leg; the FUSE profiles are reachable from their own modules'
/// tests and never leave the crate.
pub const CAPABILITIES: HostCapabilities = HostCapabilities {
    push_invalidation: true,
    attribute_cache: true,
    case_insensitive_lookup: true,
};

/// How often the notify timer drains what the core asked to invalidate.
///
/// WinFsp serves notifications from a timer rather than a call the filesystem
/// makes: `FspFileSystemNotifyBegin` has to bracket them, and only the timer
/// callback holds that bracket. One second is the ceiling on how late a repaint
/// can be, which is well inside every cache lifetime [`CacheTtls`] hands out.
const NOTIFY_INTERVAL_MILLIS: u32 = 1_000;

/// The volume label and filesystem name the mount presents. `CIPHERBOX` is what
/// Explorer's address bar shows.
const FILESYSTEM_NAME: &str = "CipherBox";

/// The sector size the volume advertises, and the allocation unit with it. One
/// page: the projection's own framing is the chunk cache's, and nothing here is
/// served better by a larger hint.
const SECTOR_BYTES: u16 = 4096;

/// The capacity the volume advertises. Byte accounting does not reach the
/// facade, and a client that reads free space before writing refuses the write
/// on a zero; a write over a real budget is still refused where it belongs, by
/// the engine's `ENOSPC`/`EDQUOT` equivalents.
const ADVISORY_CAPACITY_BYTES: u64 = 1 << 40;

/// How many inode→path bindings this adapter remembers so it can name them to
/// `FspFileSystemNotify`. Finite whatever a peer commits, on the same grounds
/// as the operation core's shadow maps: a path evicted here is a notification
/// dropped, never a wrong one sent.
const NOTIFIABLE_PATHS: usize = 4096;

/// How many notifications may queue between two timer ticks. A queue that
/// overflows drops its oldest: a mount cannot make the kernel wait, and the
/// cache lifetimes are the backstop.
const NOTIFY_QUEUE_DEPTH: usize = 4096;

/// `.` and `..`, which a listing synthesizes ahead of the children the core
/// hands back. Both name the directory itself — Windows resolves `..` by
/// opening the parent path, never through the entry a listing reports.
const DOT_NAMES: [&str; 2] = [".", ".."];

const DOT_ENTRIES: usize = DOT_NAMES.len();

/// The widest name a `DirInfo` or `NotifyInfo` buffer has to hold, in UTF-16
/// units: [`MAX_NAME_BYTES`] of UTF-8 is at most that many UTF-16 units, plus
/// the NUL `set_name` appends.
const NAME_UNITS: usize = MAX_NAME_BYTES + 1;

// The NT status space, for the three refusals this adapter decides on its own
// rather than reading out of the shared `VfsError` table. Named here for the
// same reason the FUSE wire names `libc::ENOTCONN` inline: they answer states
// the operation core never sees.
//
/// The mount is on its way down and no operation will be answered again.
const STATUS_VOLUME_DISMOUNTED: NtStatus = 0xC000_026E_u32 as i32;
/// A read that started at or past the end of the file.
const STATUS_END_OF_FILE: NtStatus = 0xC000_0011_u32 as i32;
/// A request naming something this projection cannot even spell.
const STATUS_OBJECT_NAME_INVALID: NtStatus = 0xC000_0033_u32 as i32;

// Win32 constants, stated rather than pulled from a binding, exactly as
// `crate::ntstatus` states the NT ones: they are numbers in a wire protocol,
// not an API call.
/// `FILE_ATTRIBUTE_DIRECTORY`.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// `FILE_ATTRIBUTE_NORMAL`.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// `FILE_DIRECTORY_FILE`, a create option asking for a directory.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
/// `FILE_READ_DATA`.
const FILE_READ_DATA: u32 = 0x0000_0001;
/// `FILE_WRITE_DATA`.
const FILE_WRITE_DATA: u32 = 0x0000_0002;
/// `FILE_APPEND_DATA`.
const FILE_APPEND_DATA: u32 = 0x0000_0004;
/// `FspCleanupDelete`, the cleanup flag that carries out a delete.
const FSP_CLEANUP_DELETE: u32 = 0x01;

/// `FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME`: a directory
/// entry appeared, vanished, or moved.
const NOTIFY_FILTER_NAME: u32 = 0x0000_0001 | 0x0000_0002;
/// `FILE_NOTIFY_CHANGE_ATTRIBUTES | _SIZE | _LAST_WRITE`: a node's own state
/// moved.
const NOTIFY_FILTER_NODE: u32 = 0x0000_0004 | 0x0000_0008 | 0x0000_0010;
/// `FILE_ACTION_MODIFIED`. The core reports that something stopped being the
/// truth, not which way it moved, and "re-read this" is what that means to a
/// watcher.
const NOTIFY_ACTION_MODIFIED: u32 = 0x0000_0003;

/// The 100-nanosecond ticks between the NT epoch (1601-01-01) and the Unix one.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// The path components a WinFsp request names, from the mount root down. Empty
/// is the root itself.
type VaultPath = Vec<String>;

/// Split a WinFsp path into the components the operation core addresses nodes
/// by, or `None` for text the projection could not have stored: the engine
/// holds names as UTF-8, so unpaired surrogates name nothing.
fn components(path: &U16CStr) -> Option<VaultPath> {
    Some(
        path.to_string()
            .ok()?
            .split('\\')
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// The path as WinFsp spells one: `\` for the root, `\a\b` below it.
fn rendered(path: &[String]) -> String {
    let mut out = String::new();
    for part in path {
        out.push('\\');
        out.push_str(part);
    }
    if out.is_empty() {
        out.push('\\');
    }
    out
}

/// The access mode a `GrantedAccess` word asks for, or `None` for a handle that
/// asked for neither — an open taken only to delete, rename, or stat, which
/// owes the core no file handle at all.
fn access_of(granted: u32) -> Option<Access> {
    let read = granted & FILE_READ_DATA != 0;
    let write = granted & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0;
    match (read, write) {
        (true, true) => Some(Access::ReadWrite),
        (true, false) => Some(Access::Read),
        (false, true) => Some(Access::Write),
        (false, false) => None,
    }
}

/// A Unix-millis timestamp as an NT `FILETIME`. An mtime the content plane
/// never projected is the epoch, not a clock read: the projection has no clock
/// of its own.
fn filetime(millis: Option<u64>) -> u64 {
    millis
        .and_then(|millis| millis.checked_mul(10_000))
        .and_then(|ticks| FILETIME_UNIX_EPOCH.checked_add(ticks))
        .unwrap_or(FILETIME_UNIX_EPOCH)
}

/// One node as WinFsp's `FSP_FSCTL_FILE_INFO`.
///
/// A size the content plane has not projected yet is reported as zero, because
/// the reply has to carry some number. On the FUSE wire that number comes with
/// a lifetime of zero; WinFsp times file information per volume rather than per
/// reply, so what corrects it here is the projection's own push invalidation —
/// which is why this backend must never ship with `push_invalidation` false.
fn file_info(kind: NodeKind, size: Option<u64>, mtime_millis: Option<u64>) -> FileInfo {
    let size = size.unwrap_or(0);
    let time = filetime(mtime_millis);
    FileInfo {
        file_attributes: match kind {
            NodeKind::Folder => FILE_ATTRIBUTE_DIRECTORY,
            NodeKind::File => FILE_ATTRIBUTE_NORMAL,
        },
        reparse_tag: 0,
        // Rounded up to the sector the volume advertises, the way a real
        // allocation is.
        allocation_size: size.next_multiple_of(u64::from(SECTOR_BYTES)),
        file_size: match kind {
            NodeKind::Folder => 0,
            NodeKind::File => size,
        },
        creation_time: time,
        last_access_time: time,
        last_write_time: time,
        change_time: time,
        index_number: 0,
        hard_links: 0,
        ea_size: 0,
    }
}

fn info_of(attrs: &Attributes) -> FileInfo {
    file_info(attrs.kind, attrs.size, attrs.mtime_millis)
}

/// The file attributes `get_security_by_name` answers with.
fn security_of(attrs: &Attributes) -> FileSecurity {
    FileSecurity {
        reparse: false,
        // No security descriptor: this projection enforces no ACLs, and WinFsp
        // grants a caller exactly the access it asked for when a file system
        // reports none (`FspAccessCheckEx`). The mount admits only the user who
        // made it, which is the access control there is.
        sz_security_descriptor: 0,
        attributes: match attrs.kind {
            NodeKind::Folder => FILE_ATTRIBUTE_DIRECTORY,
            NodeKind::File => FILE_ATTRIBUTE_NORMAL,
        },
    }
}

/// Where a directory enumeration resumes.
enum Marker {
    /// From the top.
    Start,
    /// After `.`.
    Current,
    /// After `..`.
    Parent,
    /// After the named child.
    After(String),
}

impl Marker {
    fn of(marker: &DirMarker<'_>) -> Self {
        if marker.is_none() {
            Self::Start
        } else if marker.is_current() {
            Self::Current
        } else if marker.is_parent() {
            Self::Parent
        } else {
            match marker
                .inner_as_cstr()
                .and_then(|name| name.to_string().ok())
            {
                Some(name) => Self::After(name),
                // A marker this mount could not have emitted resumes at the
                // top: a repeated entry is a client's problem, a skipped one is
                // a missing file.
                None => Self::Start,
            }
        }
    }
}

/// One page of a directory walk, as the core answered it.
struct Listing {
    /// The directory's own attributes, which both dot entries carry.
    dir: Attributes,
    /// How many of the two dot entries this page has already passed.
    passed_dots: usize,
    /// The kernel-offset space position this page's first child sits at.
    base: usize,
    /// The children from that position on.
    entries: Vec<DirEntry>,
}

impl Listing {
    /// The page as `(name, info, resume_at)` triples: the dot entries this
    /// marker has not passed, then the children. Each carries the offset a
    /// continuation resumes at, which is the one *after* it.
    fn page(&self) -> impl Iterator<Item = (&str, FileInfo, usize)> {
        let dir = info_of(&self.dir);
        let dots = DOT_NAMES
            .iter()
            .enumerate()
            .skip(self.passed_dots.min(DOT_ENTRIES))
            .map(move |(index, name)| (*name, dir.clone(), index + 1));
        let children = self.entries.iter().enumerate().map(|(step, child)| {
            (
                child.name.as_str(),
                file_info(child.kind, child.size, child.mtime_millis),
                self.base + step + 1,
            )
        });
        dots.chain(children)
    }
}

/// What an open WinFsp file context holds and gives back at `close`.
#[derive(Clone, Copy)]
struct Held {
    handle: Option<HandleId>,
    walk: Option<DirHandleId>,
}

/// What an open or create landed.
struct Opened {
    attrs: Attributes,
    held: Held,
}

/// The answer channel one operation is owed. Dropping it unanswered is what
/// wakes the dispatcher thread waiting on it — a WinFsp request nobody answers
/// blocks its caller for the life of the mount.
struct Answer<T>(SyncSender<Result<T, VfsError>>);

impl<T> Answer<T> {
    fn give(self, outcome: Result<T, VfsError>) {
        let _ = self.0.send(outcome);
    }
}

/// One decoded WinFsp request, waiting for an operation core to answer it.
enum WinFspOp {
    /// Attributes for a path — `get_security_by_name`, which is also how
    /// WinFsp asks whether a path exists.
    Stat {
        path: VaultPath,
        reply: Answer<Attributes>,
    },
    Open {
        path: VaultPath,
        access: Option<Access>,
        reply: Answer<Opened>,
    },
    Create {
        path: VaultPath,
        kind: NodeKind,
        access: Option<Access>,
        reply: Answer<Opened>,
    },
    Close {
        held: Held,
        reply: Answer<()>,
    },
    GetAttr {
        ino: u64,
        reply: Answer<Attributes>,
    },
    SetSize {
        ino: u64,
        size: u64,
        handle: Option<HandleId>,
        reply: Answer<Attributes>,
    },
    Read {
        handle: HandleId,
        offset: u64,
        size: u32,
        reply: Answer<Zeroizing<Vec<u8>>>,
    },
    Write {
        ino: u64,
        handle: HandleId,
        offset: u64,
        data: Zeroizing<Vec<u8>>,
        at_end: bool,
        constrained: bool,
        reply: Answer<(u32, Attributes)>,
    },
    Flush {
        handle: HandleId,
        reply: Answer<()>,
    },
    ReadDir {
        ino: u64,
        walk: DirHandleId,
        marker: Marker,
        reply: Answer<Listing>,
    },
    /// Whether the node may be deleted at all — WinFsp decides the disposition
    /// before `cleanup` carries it out, and a `rmdir` that only failed at
    /// cleanup would look like it worked.
    Removable {
        ino: u64,
        kind: NodeKind,
        reply: Answer<()>,
    },
    Delete {
        path: VaultPath,
        kind: NodeKind,
        reply: Answer<()>,
    },
    Rename {
        from: VaultPath,
        to: VaultPath,
        replace: bool,
        reply: Answer<()>,
    },
    StatFs {
        reply: Answer<StatFs>,
    },
}

/// One decoded WinFsp request, waiting for an operation core to answer it.
///
/// Opaque, and answered exactly once: a host takes it from
/// [`WinFspMount::next_op`] and hands it back to [`WinFspMount::answer`].
/// Dropping it instead refuses it, because dropping it drops the answer channel
/// the dispatcher thread is waiting on.
pub struct KernelOp(WinFspOp);

/// One notification waiting for the next timer tick.
struct Notification {
    path: String,
    filter: u32,
    action: u32,
}

/// The inode→path bindings this mount can still name to WinFsp, newest last.
///
/// The core reports invalidations by inode; `FspFileSystemNotify` names a path.
/// Nothing else in the projection holds paths — the inode map is keyed on the
/// engine's node id precisely so a rename costs it nothing — so the translation
/// lives here, filled by the path walks the adapter is doing anyway.
#[derive(Default)]
struct PathBook {
    by_ino: HashMap<u64, String>,
    order: VecDeque<u64>,
}

impl PathBook {
    fn remember(&mut self, ino: u64, path: &[String]) {
        let rendered = rendered(path);
        if self.by_ino.insert(ino, rendered).is_none() {
            self.order.push_back(ino);
        }
        while self.order.len() > NOTIFIABLE_PATHS {
            if let Some(evicted) = self.order.pop_front() {
                self.by_ino.remove(&evicted);
            }
        }
    }

    fn path(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(String::as_str)
    }
}

/// What the invalidator and the notify timer share: the paths one can name and
/// the queue the other drains.
#[derive(Default)]
struct NotifyPlane {
    book: Mutex<PathBook>,
    queue: Mutex<VecDeque<Notification>>,
}

impl NotifyPlane {
    fn push(&self, notification: Notification) {
        let Ok(mut queue) = self.queue.lock() else {
            return;
        };
        if queue.len() >= NOTIFY_QUEUE_DEPTH {
            queue.pop_front();
        }
        queue.push_back(notification);
    }

    /// The path for `ino`, or `None` for a node this mount never named to
    /// Windows — which is a node Windows cannot be holding state for.
    fn path(&self, ino: u64) -> Option<String> {
        self.book.lock().ok()?.path(ino).map(str::to_owned)
    }
}

/// Pushes the operation core's invalidations at WinFsp.
#[derive(Clone)]
pub struct WinFspInvalidator {
    plane: Arc<NotifyPlane>,
}

impl HostAdapter for WinFspInvalidator {
    fn capabilities(&self) -> HostCapabilities {
        CAPABILITIES
    }

    fn invalidate(&self, invalidation: Invalidation) {
        // A node this mount never named to Windows is one Windows holds nothing
        // for, and a queue at its ceiling is the mount absorbing what it cannot
        // make the kernel wait for — both are the adapter's to swallow, which
        // is the trait's contract.
        let notification = match invalidation {
            Invalidation::Data { ino } | Invalidation::Attributes { ino } => {
                self.plane.path(ino).map(|path| Notification {
                    path,
                    filter: NOTIFY_FILTER_NODE,
                    action: NOTIFY_ACTION_MODIFIED,
                })
            }
            Invalidation::Entry { parent, name } => {
                self.plane.path(parent).map(|parent| Notification {
                    // The root renders as `\`, and `\` + `\name` would name
                    // nothing.
                    path: format!("{}\\{name}", parent.trim_end_matches('\\')),
                    filter: NOTIFY_FILTER_NAME,
                    action: NOTIFY_ACTION_MODIFIED,
                })
            }
        };
        if let Some(notification) = notification {
            self.plane.push(notification);
        }
    }
}

/// The `winfsp::FileSystemContext` this mount registers: a decoder, and nothing
/// else.
struct VaultFs {
    ops: mpsc::UnboundedSender<WinFspOp>,
    plane: Arc<NotifyPlane>,
}

/// What one open WinFsp handle addresses. WinFsp hands it back by shared
/// reference from any thread, so what has to change under it — the path a
/// rename moves — is behind a lock.
pub struct OpenNode {
    ino: u64,
    kind: NodeKind,
    held: Held,
    path: Mutex<VaultPath>,
}

/// The mount is on its way down; nothing more will be answered.
fn dismounted() -> FspError {
    FspError::NTSTATUS(STATUS_VOLUME_DISMOUNTED)
}

/// A request naming text the projection could not have stored.
fn unnameable() -> FspError {
    FspError::NTSTATUS(STATUS_OBJECT_NAME_INVALID)
}

impl VaultFs {
    /// Hand one operation to the engine task and wait for its answer.
    ///
    /// The wait is the protocol's, not a choice: this call *is* the callback
    /// WinFsp expects an NTSTATUS back from.
    fn ask<T>(&self, op: impl FnOnce(Answer<T>) -> WinFspOp) -> winfsp::Result<T> {
        let (sender, answers) = sync_channel(1);
        self.ops
            .unbounded_send(op(Answer(sender)))
            .map_err(|_| dismounted())?;
        match answers.recv() {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(refusal)) => Err(FspError::NTSTATUS(ntstatus_of(&refusal))),
            // The operation was dropped unanswered, which is how the pump
            // refuses everything queued when the session ends.
            Err(_) => Err(dismounted()),
        }
    }

    fn path_of(&self, name: &U16CStr) -> winfsp::Result<VaultPath> {
        components(name).ok_or_else(unnameable)
    }
}

impl FileSystemContext for VaultFs {
    type FileContext = OpenNode;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        // No reparse points in the projection, so the resolver is never called:
        // a path is a path all the way down.
        let path = self.path_of(file_name)?;
        let attrs = self.ask(|reply| WinFspOp::Stat { path, reply })?;
        Ok(security_of(&attrs))
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = self.path_of(file_name)?;
        let access = access_of(granted_access);
        let opened = self.ask(|reply| WinFspOp::Open {
            path: path.clone(),
            access,
            reply,
        })?;
        *file_info.as_mut() = info_of(&opened.attrs);
        Ok(OpenNode {
            ino: opened.attrs.ino,
            kind: opened.attrs.kind,
            held: opened.held,
            path: Mutex::new(path),
        })
    }

    fn close(&self, context: Self::FileContext) {
        // Waited on rather than fired and forgotten: the handle's last writes
        // become one op inside `release`, and a later open of the same file
        // must not race it.
        let _ = self.ask(|reply| WinFspOp::Close {
            held: context.held,
            reply,
        });
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = self.path_of(file_name)?;
        let kind = if create_options & FILE_DIRECTORY_FILE != 0 {
            NodeKind::Folder
        } else {
            NodeKind::File
        };
        let access = access_of(granted_access);
        let opened = self.ask(|reply| WinFspOp::Create {
            path: path.clone(),
            kind,
            access,
            reply,
        })?;
        *file_info.as_mut() = info_of(&opened.attrs);
        Ok(OpenNode {
            ino: opened.attrs.ino,
            kind: opened.attrs.kind,
            held: opened.held,
            path: Mutex::new(path),
        })
    }

    /// The last user-mode handle on the file has closed. A delete disposition
    /// set by [`set_delete`](Self::set_delete) is carried out here, which is
    /// WinFsp's contract: nothing may be deleted while a handle can still
    /// reach it.
    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
        if flags & FSP_CLEANUP_DELETE == 0 {
            return;
        }
        let Ok(path) = context.path.lock().map(|path| path.clone()) else {
            return;
        };
        let kind = context.kind;
        // Nothing to answer: `cleanup` returns no status, and the removability
        // check already ran at `set_delete`.
        let _ = self.ask(|reply| WinFspOp::Delete { path, kind, reply });
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // `None` is a whole-volume flush. Every handle's writes are already
        // journaled at its own flush or release, and the durable op queue is
        // the mount's only durability layer, so there is nothing left to push.
        let Some(context) = context else {
            return Ok(());
        };
        let Some(handle) = context.held.handle else {
            return Ok(());
        };
        self.ask(|reply| WinFspOp::Flush { handle, reply })?;
        let ino = context.ino;
        let attrs = self.ask(|reply| WinFspOp::GetAttr { ino, reply })?;
        *file_info = info_of(&attrs);
        Ok(())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let ino = context.ino;
        let attrs = self.ask(|reply| WinFspOp::GetAttr { ino, reply })?;
        *file_info = info_of(&attrs);
        Ok(())
    }

    /// The projection enforces no ACLs, so there is no descriptor to hand back
    /// — see [`security_of`].
    fn get_security(
        &self,
        _context: &Self::FileContext,
        _security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        Ok(0)
    }

    /// Accepted and ignored, the way the FUSE wire accepts a `chmod` it cannot
    /// act on: the projection carries no ACL of its own, and refusing here
    /// fails an ordinary copy outright.
    fn set_security(
        &self,
        _context: &Self::FileContext,
        _security_information: u32,
        _modification_descriptor: winfsp::filesystem::ModificationDescriptor,
    ) -> winfsp::Result<()> {
        Ok(())
    }

    /// `CREATE_ALWAYS` / `TRUNCATE_EXISTING` on a file that already exists. The
    /// new length rides into the one `updateContent` op this handle's release
    /// journals, so the truncate and the writes after it become one version.
    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let (ino, handle) = (context.ino, context.held.handle);
        let attrs = self.ask(|reply| WinFspOp::SetSize {
            ino,
            size: 0,
            handle,
            reply,
        })?;
        *file_info = info_of(&attrs);
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        let walk = context
            .held
            .walk
            .ok_or(FspError::NTSTATUS(ntstatus_of(&VfsError::NotADirectory)))?;
        let ino = context.ino;
        let marker = Marker::of(&marker);
        let listing = self.ask(|reply| WinFspOp::ReadDir {
            ino,
            walk,
            marker,
            reply,
        })?;

        let mut cursor = 0u32;
        let mut whole = true;
        for (name, info, _) in listing.page() {
            let mut entry = DirInfo::<NAME_UNITS>::new();
            *entry.file_info_mut() = info;
            // A name no `DirInfo` buffer could hold is one the projection could
            // not have stored either; skipping it is the same refusal the core
            // makes, one layer out.
            if entry.set_name(name).is_err() {
                continue;
            }
            if !entry.append_to_buffer(buffer, &mut cursor) {
                whole = false;
                break;
            }
        }
        if whole {
            // Only a page that emitted everything it was given is the end of
            // the enumeration; finalizing a full buffer would end it early.
            DirInfo::<NAME_UNITS>::finalize_buffer(buffer, &mut cursor);
        }
        Ok(cursor)
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let to = self.path_of(new_file_name)?;
        // The context's own path, not the one in the request: WinFsp spells the
        // request the caller's way, and a case-insensitive resolve means that
        // spelling need not be the stored one.
        let from = context
            .path
            .lock()
            .map(|path| path.clone())
            .map_err(|_| dismounted())?;
        self.ask(|reply| WinFspOp::Rename {
            from,
            to: to.clone(),
            replace: replace_if_exists,
            reply,
        })?;
        if let Ok(mut path) = context.path.lock() {
            *path = to;
        }
        Ok(())
    }

    /// Times and attributes are accepted and ignored: the projection stores
    /// none of them, and an outright refusal fails `copy` and `touch`.
    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        _creation_time: u64,
        _last_access_time: u64,
        _last_write_time: u64,
        _last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        self.get_file_info(context, file_info)
    }

    /// WinFsp's contract: decide here, delete in
    /// [`cleanup`](Self::cleanup). A non-empty directory is refused now, so
    /// Explorer reports the refusal instead of appearing to succeed.
    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        if !delete_file {
            return Ok(());
        }
        let (ino, kind) = (context.ino, context.kind);
        self.ask(|reply| WinFspOp::Removable { ino, kind, reply })
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let (ino, handle) = (context.ino, context.held.handle);
        // An allocation-size change reserves space; the projection has no
        // allocation to reserve, and truncating to it would lose bytes.
        if set_allocation_size {
            return self.get_file_info(context, file_info);
        }
        let attrs = self.ask(|reply| WinFspOp::SetSize {
            ino,
            size: new_size,
            handle,
            reply,
        })?;
        *file_info = info_of(&attrs);
        Ok(())
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        let handle = context
            .held
            .handle
            .ok_or(FspError::NTSTATUS(ntstatus_of(&VfsError::BadHandle)))?;
        let size = u32::try_from(buffer.len())
            .map_err(|_| FspError::NTSTATUS(ntstatus_of(&VfsError::Invalid)))?;
        let plaintext = self.ask(|reply| WinFspOp::Read {
            handle,
            offset,
            size,
            reply,
        })?;
        if plaintext.is_empty() && size > 0 {
            return Err(FspError::NTSTATUS(STATUS_END_OF_FILE));
        }
        let taken = plaintext.len();
        buffer[..taken].copy_from_slice(&plaintext);
        // Terminal owner of the plaintext until here; the `Zeroizing` wipes it
        // now that WinFsp's buffer holds the bytes.
        drop(plaintext);
        Ok(taken as u32)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let handle = context
            .held
            .handle
            .ok_or(FspError::NTSTATUS(ntstatus_of(&VfsError::BadHandle)))?;
        let ino = context.ino;
        let (taken, attrs) = self.ask(|reply| WinFspOp::Write {
            ino,
            handle,
            offset,
            // The borrow is WinFsp's transfer buffer, reused for the next
            // request, so the payload has to be copied to cross the channel.
            data: Zeroizing::new(buffer.to_vec()),
            at_end: write_to_eof,
            constrained: constrained_io,
            reply,
        })?;
        *file_info = info_of(&attrs);
        Ok(taken)
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        let stats = self.ask(|reply| WinFspOp::StatFs { reply })?;
        let _ = stats;
        out_volume_info.total_size = ADVISORY_CAPACITY_BYTES;
        out_volume_info.free_size = ADVISORY_CAPACITY_BYTES;
        out_volume_info.set_volume_label(FILESYSTEM_NAME);
        Ok(())
    }

    /// The volume's label is the product's, not a member's to rename.
    fn set_volume_label(
        &self,
        _volume_label: &U16CStr,
        volume_info: &mut VolumeInfo,
    ) -> winfsp::Result<()> {
        self.get_volume_info(volume_info)
    }

    fn dispatcher_stopped(&self, _normally: bool) {
        // Ends the pump: the session is over, so no further operation can be
        // answered.
        self.ops.close_channel();
    }
}

impl NotifyingFileSystemContext<()> for VaultFs {
    fn should_notify(&self) -> Option<()> {
        let queue = self.plane.queue.lock().ok()?;
        (!queue.is_empty()).then_some(())
    }

    fn notify(&self, _context: (), notifier: &Notifier) {
        let Ok(mut queue) = self.plane.queue.lock() else {
            return;
        };
        let pending: Vec<Notification> = queue.drain(..).collect();
        drop(queue);
        for notification in pending {
            let mut info = NotifyInfo::<NAME_UNITS>::new();
            if info.set_name(&notification.path).is_err() {
                continue;
            }
            info.filter = notification.filter;
            info.action = notification.action;
            notifier.notify(&info);
        }
    }
}

/// A live mount. Dropping it unmounts and stops the dispatcher; the operation
/// core it fed is torn down separately, by its own `unmount`.
///
/// [`quiesce`](Self::quiesce) before dropping, from anywhere other than the
/// pump: a dispatcher thread blocked on an answer the pump will never give is
/// one the unmount would wait on forever.
pub struct WinFspMount {
    /// Held for its `Drop`, which unmounts and stops the dispatcher.
    _host: FileSystemHost<VaultFs>,
    invalidator: WinFspInvalidator,
    plane: Arc<NotifyPlane>,
    ops: mpsc::UnboundedReceiver<WinFspOp>,
    /// Per open directory, the offset each name it emitted resumes at — the
    /// translation between WinFsp's name markers and the core's cursor.
    resumes: HashMap<DirHandleId, HashMap<String, usize>>,
}

/// Mount the vault at `mountpoint`, which is prepared first.
pub fn mount(mountpoint: &Path) -> io::Result<WinFspMount> {
    WinFspMount::at(mountpoint)
}

impl WinFspMount {
    fn at(mountpoint: &Path) -> io::Result<Self> {
        prepare(mountpoint)?;
        // Loads the WinFsp DLL the installed driver ships, through the registry
        // — the delay-load this crate links means nothing resolves until now.
        winfsp::winfsp_init().map_err(|error| {
            io::Error::other(format!("WinFsp is not installed on this device: {error:?}"))
        })?;

        let (sender, ops) = mpsc::unbounded();
        let plane = Arc::new(NotifyPlane::default());
        let context = VaultFs {
            ops: sender,
            plane: Arc::clone(&plane),
        };
        let params = FileSystemParams::default_params(volume_params());
        let mut host =
            FileSystemHost::new_with_timer::<(), NOTIFY_INTERVAL_MILLIS>(params, context)
                .map_err(|error| io::Error::other(format!("the WinFsp host: {error}")))?;
        host.mount(mountpoint)
            .map_err(|error| io::Error::other(format!("the WinFsp mount point: {error}")))?;
        host.start()
            .map_err(|error| io::Error::other(format!("the WinFsp dispatcher: {error}")))?;

        Ok(Self {
            _host: host,
            invalidator: WinFspInvalidator {
                plane: Arc::clone(&plane),
            },
            plane,
            ops,
            resumes: HashMap::new(),
        })
    }

    /// The invalidator to mount the operation core behind.
    pub fn invalidator(&self) -> WinFspInvalidator {
        self.invalidator.clone()
    }

    /// The next WinFsp operation, or `None` once the dispatcher has stopped.
    ///
    /// Cancel-safe: an operation is taken off the queue or it is not, so a host
    /// may wait on this beside its other wake sources.
    pub async fn next_op(&mut self) -> Option<KernelOp> {
        core::future::poll_fn(|cx| Pin::new(&mut self.ops).poll_next(cx))
            .await
            .map(KernelOp)
    }

    /// Stop accepting operations, ahead of the unmount (blueprint/desktop.md
    /// "Lifecycle" — quiesce, unmount, stop the engine). Everything queued and
    /// everything a dispatcher thread hands over from here is refused rather
    /// than left for a pump that has stopped running.
    pub fn quiesce(&mut self) {
        self.ops.close();
        // Each refuses itself on the way out: dropping an operation drops the
        // answer channel its dispatcher thread is waiting on.
        while let Ok(op) = self.ops.try_recv() {
            drop(KernelOp(op));
        }
    }

    /// Answer one operation from `core`.
    ///
    /// Serial by construction — one operation core is one stateful projection —
    /// and the never-block law is what keeps a serial pump responsive against a
    /// pool of dispatcher threads waiting on it.
    pub async fn answer<T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, WinFspInvalidator>,
        op: KernelOp,
    ) {
        match op.0 {
            WinFspOp::Stat { path, reply } => {
                reply.give(self.resolve(core, &path).await);
            }
            WinFspOp::Open {
                path,
                access,
                reply,
            } => {
                reply.give(self.open(core, &path, access).await);
            }
            WinFspOp::Create {
                path,
                kind,
                access,
                reply,
            } => {
                reply.give(self.create(core, &path, kind, access).await);
            }
            WinFspOp::Close { held, reply } => {
                if let Some(walk) = held.walk {
                    core.releasedir(walk);
                    self.resumes.remove(&walk);
                }
                let released = match held.handle {
                    Some(handle) => core.release(handle).await,
                    None => Ok(()),
                };
                reply.give(released);
            }
            WinFspOp::GetAttr { ino, reply } => reply.give(core.getattr(ino).await),
            WinFspOp::SetSize {
                ino,
                size,
                handle,
                reply,
            } => {
                let outcome = match core.truncate(ino, size, handle).await {
                    Ok(()) => core.getattr(ino).await,
                    Err(refusal) => Err(refusal),
                };
                reply.give(outcome);
            }
            WinFspOp::Read {
                handle,
                offset,
                size,
                reply,
            } => {
                reply.give(core.read(handle, offset, size).await.map(Zeroizing::new));
            }
            WinFspOp::Write {
                ino,
                handle,
                offset,
                data,
                at_end,
                constrained,
                reply,
            } => {
                reply.give(write(core, ino, handle, offset, &data, at_end, constrained).await);
            }
            WinFspOp::Flush { handle, reply } => reply.give(core.flush(handle).await),
            WinFspOp::ReadDir {
                ino,
                walk,
                marker,
                reply,
            } => {
                reply.give(self.read_dir(core, ino, walk, marker).await);
            }
            WinFspOp::Removable { ino, kind, reply } => {
                reply.give(removable(core, ino, kind).await);
            }
            WinFspOp::Delete { path, kind, reply } => {
                reply.give(self.delete(core, &path, kind).await);
            }
            WinFspOp::Rename {
                from,
                to,
                replace,
                reply,
            } => {
                reply.give(self.rename(core, &from, &to, replace).await);
            }
            WinFspOp::StatFs { reply } => reply.give(core.statfs().await),
        }
    }

    /// Resolve a path from the mount root, one component at a time, recording
    /// each inode's path so an invalidation for it can be named to WinFsp.
    ///
    /// No reference is taken and none is given back: WinFsp has no FORGET, and
    /// the inode table already binds every name a listing minted for the life
    /// of the session.
    async fn resolve<T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, WinFspInvalidator>,
        path: &[String],
    ) -> Result<Attributes, VfsError> {
        let mut here = core.getattr(ROOT_INO).await?;
        self.remember(here.ino, &[]);
        for (depth, name) in path.iter().enumerate() {
            here = core.lookup(here.ino, name).await?;
            self.remember(here.ino, &path[..=depth]);
        }
        Ok(here)
    }

    /// Resolve everything but the last component, handing back the parent and
    /// the child's name — what every operation that names a child needs.
    async fn parent_of<'a, T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, WinFspInvalidator>,
        path: &'a [String],
    ) -> Result<(Attributes, &'a str), VfsError> {
        let (name, ancestors) = path.split_last().ok_or(VfsError::Invalid)?;
        let parent = self.resolve(core, ancestors).await?;
        Ok((parent, name.as_str()))
    }

    fn remember(&mut self, ino: u64, path: &[String]) {
        if let Ok(mut book) = self.plane.book.lock() {
            book.remember(ino, path);
        }
    }

    async fn open<T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, WinFspInvalidator>,
        path: &[String],
        access: Option<Access>,
    ) -> Result<Opened, VfsError> {
        let attrs = self.resolve(core, path).await?;
        let held = match attrs.kind {
            NodeKind::Folder => Held {
                handle: None,
                walk: Some(core.opendir(attrs.ino).await?),
            },
            // An open that asked for neither read nor write — a delete, a
            // rename, a bare stat — owes the core no file handle, and a handle
            // nothing would ever read or write is a stream slot spent for
            // nothing.
            NodeKind::File => Held {
                handle: match access {
                    Some(access) => Some(core.open(attrs.ino, access).await?),
                    None => None,
                },
                walk: None,
            },
        };
        Ok(Opened { attrs, held })
    }

    async fn create<T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, WinFspInvalidator>,
        path: &[String],
        kind: NodeKind,
        access: Option<Access>,
    ) -> Result<Opened, VfsError> {
        let (parent, name) = self.parent_of(core, path).await?;
        let (attrs, held) = match kind {
            NodeKind::Folder => {
                let attrs = core.mkdir(parent.ino, name).await?;
                let walk = core.opendir(attrs.ino).await?;
                (
                    attrs,
                    Held {
                        handle: None,
                        walk: Some(walk),
                    },
                )
            }
            NodeKind::File => {
                // A create that asked for no write access still needs one to
                // exist afterwards; the handle it opens is released at once.
                let (attrs, handle) = core
                    .create(parent.ino, name, access.unwrap_or(Access::ReadWrite))
                    .await?;
                let handle = match access {
                    Some(_) => Some(handle),
                    None => {
                        core.release(handle).await?;
                        None
                    }
                };
                (attrs, Held { handle, walk: None })
            }
        };
        self.remember(attrs.ino, path);
        Ok(Opened { attrs, held })
    }

    async fn read_dir<T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, WinFspInvalidator>,
        ino: u64,
        walk: DirHandleId,
        marker: Marker,
    ) -> Result<Listing, VfsError> {
        let offset = match marker {
            Marker::Start => 0,
            Marker::Current => 1,
            Marker::Parent => DOT_ENTRIES,
            Marker::After(name) => self
                .resumes
                .get(&walk)
                .and_then(|emitted| emitted.get(&name))
                .copied()
                // A marker this walk never emitted restarts the enumeration
                // rather than skipping to a guess.
                .unwrap_or(0),
        };
        let dir = core.getattr(ino).await?;
        let entries = core
            .readdir(walk, offset.saturating_sub(DOT_ENTRIES))
            .await?;
        let listing = Listing {
            dir,
            passed_dots: offset.min(DOT_ENTRIES),
            base: offset.max(DOT_ENTRIES),
            entries: entries.to_vec(),
        };
        let emitted = self.resumes.entry(walk).or_default();
        for (name, _, resume_at) in listing.page() {
            emitted.insert(name.to_owned(), resume_at);
        }
        Ok(listing)
    }

    async fn delete<T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, WinFspInvalidator>,
        path: &[String],
        kind: NodeKind,
    ) -> Result<(), VfsError> {
        let (parent, name) = self.parent_of(core, path).await?;
        match kind {
            NodeKind::Folder => core.rmdir(parent.ino, name).await,
            NodeKind::File => core.unlink(parent.ino, name).await,
        }
    }

    async fn rename<T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, WinFspInvalidator>,
        from: &[String],
        to: &[String],
        replace: bool,
    ) -> Result<(), VfsError> {
        let (source, name) = self.parent_of(core, from).await?;
        let (destination, new_name) = self.parent_of(core, to).await?;
        // POSIX rename replaces unconditionally; Windows asks first, and a
        // caller that did not ask must get the collision rather than a silent
        // replacement.
        if !replace
            && core
                .lookup(destination.ino, new_name)
                .await
                .is_ok_and(|found| found.node != source.node)
        {
            return Err(VfsError::AlreadyExists);
        }
        core.rename(source.ino, name, destination.ino, new_name)
            .await
    }
}

impl Drop for WinFspMount {
    fn drop(&mut self) {
        // The host's own `Drop` unmounts and stops the dispatcher, which waits
        // for every in-flight callback. One blocked on an answer this pump will
        // never give would wait forever, so the queue is emptied first.
        self.quiesce();
    }
}

/// One write, against the length WinFsp's own flags are relative to.
async fn write<T: SeamTypes>(
    core: &mut OperationCore<T, WinFspInvalidator>,
    ino: u64,
    handle: HandleId,
    offset: u64,
    data: &[u8],
    at_end: bool,
    constrained: bool,
) -> Result<(u32, Attributes), VfsError> {
    let len = core.getattr(ino).await?.size.unwrap_or(0);
    let offset = if at_end { len } else { offset };
    // Constrained I/O is the cache manager writing back pages it already owns:
    // it must never extend the file, and a window wholly past the end writes
    // nothing at all.
    let data = if constrained {
        let room = len.saturating_sub(offset);
        &data[..(data.len() as u64).min(room) as usize]
    } else {
        data
    };
    if data.is_empty() {
        return Ok((0, core.getattr(ino).await?));
    }
    let taken = core.write(handle, offset, data).await?;
    Ok((taken, core.getattr(ino).await?))
}

/// Whether the node may be deleted, without deleting it.
///
/// A directory is removable when it is empty, which the core answers by walking
/// it — the same emptiness `rmdir` itself enforces, asked one step earlier so
/// WinFsp can refuse the disposition rather than fail silently at cleanup.
async fn removable<T: SeamTypes>(
    core: &mut OperationCore<T, WinFspInvalidator>,
    ino: u64,
    kind: NodeKind,
) -> Result<(), VfsError> {
    if kind != NodeKind::Folder {
        return Ok(());
    }
    let walk = core.opendir(ino).await?;
    let empty = core.readdir(walk, 0).await.map(<[_]>::is_empty);
    core.releasedir(walk);
    match empty? {
        true => Ok(()),
        false => Err(VfsError::NotEmpty),
    }
}

/// The volume WinFsp mounts, timed by the shared [`CacheTtls`] rule from what
/// [`CAPABILITIES`] declared.
fn volume_params() -> VolumeParams {
    let ttls = CacheTtls::for_host(&CAPABILITIES, &SyncTimingProfile::PRODUCTION);
    let mut params = VolumeParams::new();
    params
        .filesystem_name(FILESYSTEM_NAME)
        .sector_size(SECTOR_BYTES)
        .sectors_per_allocation_unit(1)
        .max_component_length(MAX_NAME_BYTES as u16)
        // The Windows convention, and the one this backend's
        // `case_insensitive_lookup` is the other half of: names resolve folded
        // and are stored as entered.
        .case_sensitive_search(false)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        // The projection enforces no ACLs — see `security_of`.
        .persistent_acls(false)
        .reparse_points(false)
        .named_streams(false)
        .extended_attributes(false)
        .read_only_volume(false)
        // The vault's bytes are whatever another client last committed, so the
        // cache manager is told to let them go the moment a handle closes
        // rather than serve a version this device has replaced.
        .flush_and_purge_on_cleanup(true)
        .file_info_timeout(millis_of(ttls.attr))
        .dir_info_timeout(millis_of(ttls.entry));
    params
}

/// A cache lifetime as the millisecond count WinFsp times its own caches by.
fn millis_of(ttl: core::time::Duration) -> u32 {
    u32::try_from(ttl.as_millis()).unwrap_or(u32::MAX)
}

/// Make `mountpoint` fit for WinFsp to mount on.
///
/// Unlike the unix backends, WinFsp *creates* the directory mount point itself
/// and removes it at unmount, so the job here is to leave the path clear rather
/// than to prepare a directory. Nothing of the member's is deleted: anything in
/// the way is refused, and a refusal costs the session nothing
/// (blueprint/desktop.md "Lifecycle": mount failure never fails login).
fn prepare(mountpoint: &Path) -> io::Result<()> {
    if let Some(parent) = mountpoint.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::symlink_metadata(mountpoint) {
        Ok(found) => {
            // A reparse point here is either a member's junction — which would
            // project the vault somewhere they never chose — or a mount point a
            // crashed session left behind. Neither is this mount's to resolve.
            if found.file_type().is_symlink() {
                return Err(io::Error::other(
                    "the mount point is a link or a leftover mount point",
                ));
            }
            if !found.is_dir() {
                return Err(io::Error::other("the mount point is not a directory"));
            }
            if fs::read_dir(mountpoint)?.next().is_some() {
                return Err(io::Error::other("the mount point is not empty"));
            }
            // An empty leftover directory holds nothing and is in WinFsp's way.
            fs::remove_dir(mountpoint)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use cipherbox_engine::NodeId;

    use super::*;

    fn node(kind: NodeKind, size: Option<u64>) -> Attributes {
        Attributes {
            ino: 42,
            node: NodeId([3; 16]),
            kind,
            size,
            mtime_millis: Some(1_700_000_000_123),
        }
    }

    /// The profile as the operation core reads it — off the adapter it is
    /// mounted behind, which is the only copy that decides anything.
    fn declared() -> HostCapabilities {
        WinFspInvalidator {
            plane: Arc::new(NotifyPlane::default()),
        }
        .capabilities()
    }

    /// Windows resolves a name folded and stores it as entered, and the
    /// operation core reads that off the profile — the volume's own
    /// `CaseSensitiveSearch`/`CasePreservedNames` and the declared capability
    /// are one claim, not two.
    #[test]
    fn the_mount_presents_names_the_windows_way() {
        assert!(declared().case_insensitive_lookup);
        assert_eq!(declared(), CAPABILITIES);
    }

    /// An unprojected size is corrected by push, and this backend has no
    /// per-reply lifetime to fall back on: a mount that could not push would
    /// serve a zero-length copy of a real file for a whole `FileInfoTimeout`.
    #[test]
    fn the_backend_pushes_invalidation() {
        assert!(declared().push_invalidation);
        let ttls = CacheTtls::for_host(&declared(), &SyncTimingProfile::PRODUCTION);
        assert!(!ttls.attr.is_zero());
        assert!(!ttls.entry.is_zero());
        assert!(
            u128::from(NOTIFY_INTERVAL_MILLIS) < ttls.attr.as_millis(),
            "a repaint later than the cache it corrects would never be seen"
        );
    }

    /// The volume's timeouts come from the one shared rule, so this backend
    /// cannot drift from what the operation core believes it may cache.
    #[test]
    fn the_volume_is_timed_by_the_shared_cache_rule() {
        let ttls = CacheTtls::for_host(&CAPABILITIES, &SyncTimingProfile::PRODUCTION);
        assert_eq!(millis_of(ttls.attr), ttls.attr.as_millis() as u32);
        assert_eq!(millis_of(core::time::Duration::MAX), u32::MAX);
    }

    #[test]
    fn a_path_splits_into_the_components_the_core_names_nodes_by() {
        let path = widestring::u16cstr!("\\folder\\report.txt");
        assert_eq!(
            components(path),
            Some(vec!["folder".to_owned(), "report.txt".to_owned()])
        );
        assert_eq!(components(widestring::u16cstr!("\\")), Some(Vec::new()));
        assert_eq!(components(widestring::u16cstr!("")), Some(Vec::new()));
    }

    /// The path a notification names is the one Windows opened, and the root's
    /// is a lone separator — `\` joined with a child must not double it.
    #[test]
    fn a_rendered_path_never_doubles_the_root_separator() {
        assert_eq!(rendered(&[]), "\\");
        assert_eq!(rendered(&["folder".to_owned()]), "\\folder");
        let root = rendered(&[]);
        assert_eq!(
            format!("{}\\report.txt", root.trim_end_matches('\\')),
            "\\report.txt"
        );
    }

    #[test]
    fn an_access_word_decodes_to_the_mode_it_asked_for() {
        assert_eq!(access_of(FILE_READ_DATA), Some(Access::Read));
        assert_eq!(access_of(FILE_WRITE_DATA), Some(Access::Write));
        assert_eq!(access_of(FILE_APPEND_DATA), Some(Access::Write));
        assert_eq!(
            access_of(FILE_READ_DATA | FILE_WRITE_DATA),
            Some(Access::ReadWrite)
        );
        assert_eq!(
            access_of(0x0001_0000),
            None,
            "an open taken only to delete owes the core no handle"
        );
    }

    /// A kernel that believes a directory has a size, or a file none, is a
    /// kernel that stops reading at byte zero.
    #[test]
    fn file_information_follows_the_projection() {
        let file = info_of(&node(NodeKind::File, Some(4097)));
        assert_eq!(file.file_attributes, FILE_ATTRIBUTE_NORMAL);
        assert_eq!(file.file_size, 4097);
        assert_eq!(
            file.allocation_size,
            2 * u64::from(SECTOR_BYTES),
            "allocation rounds up to the advertised sector"
        );

        let folder = info_of(&node(NodeKind::Folder, None));
        assert_eq!(folder.file_attributes, FILE_ATTRIBUTE_DIRECTORY);
        assert_eq!(folder.file_size, 0);
    }

    /// An mtime the content plane never projected is the NT epoch, not a clock
    /// read: the projection has no clock of its own.
    #[test]
    fn an_unprojected_mtime_is_the_epoch() {
        assert_eq!(filetime(None), FILETIME_UNIX_EPOCH);
        assert_eq!(filetime(Some(0)), FILETIME_UNIX_EPOCH);
        assert_eq!(filetime(Some(1)), FILETIME_UNIX_EPOCH + 10_000);
        assert_eq!(
            filetime(Some(u64::MAX)),
            FILETIME_UNIX_EPOCH,
            "an overflowing timestamp is no timestamp"
        );
    }

    fn child(name: &str) -> DirEntry {
        DirEntry {
            ino: 7,
            name: name.to_owned(),
            kind: NodeKind::File,
            size: Some(1),
            mtime_millis: None,
        }
    }

    fn walk(offset: usize, children: &[DirEntry]) -> Vec<(String, usize)> {
        let listing = Listing {
            dir: node(NodeKind::Folder, None),
            passed_dots: offset.min(DOT_ENTRIES),
            base: offset.max(DOT_ENTRIES),
            entries: children
                .get(offset.saturating_sub(DOT_ENTRIES)..)
                .unwrap_or_default()
                .to_vec(),
        };
        listing
            .page()
            .map(|(name, _, resume_at)| (name.to_owned(), resume_at))
            .collect()
    }

    fn children() -> Vec<DirEntry> {
        vec![child("alpha"), child("beta"), child("gamma")]
    }

    /// A listing leads with `.` and `..`, both naming the directory itself.
    #[test]
    fn a_listing_leads_with_the_dot_entries() {
        let listed = walk(0, &children());
        assert_eq!(listed[0], (".".to_owned(), 1));
        assert_eq!(listed[1], ("..".to_owned(), 2));
        assert_eq!(listed[2], ("alpha".to_owned(), 3));
    }

    /// The marker WinFsp resumes at is the name after which enumeration
    /// continues, so resuming there must land on the next entry — never repeat
    /// or skip one, and never re-emit a dot entry the walk has passed.
    #[test]
    fn a_continuation_resumes_on_the_entry_after_the_last_one_taken() {
        let children = children();
        let whole = walk(0, &children);

        for taken in 0..whole.len() {
            let resume_at = whole[taken].1;
            assert_eq!(
                walk(resume_at, &children),
                whole[taken + 1..],
                "at {resume_at}"
            );
        }
    }

    #[test]
    fn a_marker_past_the_end_emits_nothing() {
        let children = children();
        assert!(walk(DOT_ENTRIES + children.len(), &children).is_empty());
        assert!(walk(usize::MAX, &children).is_empty());
    }

    /// A node this mount never named to Windows is one Windows holds nothing
    /// for; a node it did is one an invalidation has to be able to name.
    #[test]
    fn only_a_remembered_inode_can_be_notified() {
        let plane = Arc::new(NotifyPlane::default());
        let invalidator = WinFspInvalidator {
            plane: Arc::clone(&plane),
        };

        invalidator.invalidate(Invalidation::Attributes { ino: 9 });
        assert!(
            plane.queue.lock().expect("the queue").is_empty(),
            "a path the mount cannot spell is not a notification it can send"
        );

        plane
            .book
            .lock()
            .expect("the book")
            .remember(9, &["folder".to_owned()]);
        invalidator.invalidate(Invalidation::Data { ino: 9 });
        invalidator.invalidate(Invalidation::Entry {
            parent: 9,
            name: "report.txt".to_owned(),
        });

        let queue = plane.queue.lock().expect("the queue");
        assert_eq!(queue[0].path, "\\folder");
        assert_eq!(queue[0].filter, NOTIFY_FILTER_NODE);
        assert_eq!(queue[1].path, "\\folder\\report.txt");
        assert_eq!(queue[1].filter, NOTIFY_FILTER_NAME);
    }

    /// An entry under the root is `\name`, not `\\name`.
    #[test]
    fn an_entry_under_the_root_is_named_from_the_root_separator() {
        let plane = Arc::new(NotifyPlane::default());
        let invalidator = WinFspInvalidator {
            plane: Arc::clone(&plane),
        };
        plane.book.lock().expect("the book").remember(ROOT_INO, &[]);

        invalidator.invalidate(Invalidation::Entry {
            parent: ROOT_INO,
            name: "report.txt".to_owned(),
        });
        assert_eq!(
            plane.queue.lock().expect("the queue")[0].path,
            "\\report.txt"
        );
    }

    /// What a peer commits decides how many paths this map is asked to hold, so
    /// it holds a bounded number of them — a dropped notification is corrected
    /// by the cache lifetime, an unbounded map is not corrected at all.
    #[test]
    fn the_notifiable_paths_are_bounded() {
        let mut book = PathBook::default();
        for ino in 0..(NOTIFIABLE_PATHS as u64 + 10) {
            book.remember(ino, &[format!("node-{ino}")]);
        }
        assert_eq!(book.by_ino.len(), NOTIFIABLE_PATHS);
        assert_eq!(book.path(0), None, "the oldest binding is the one evicted");
        assert_eq!(book.path(NOTIFIABLE_PATHS as u64 + 9), Some("\\node-4105"));
    }

    #[test]
    fn the_notify_queue_is_bounded() {
        let plane = NotifyPlane::default();
        for step in 0..(NOTIFY_QUEUE_DEPTH + 5) {
            plane.push(Notification {
                path: format!("\\{step}"),
                filter: NOTIFY_FILTER_NODE,
                action: NOTIFY_ACTION_MODIFIED,
            });
        }
        let queue = plane.queue.lock().expect("the queue");
        assert_eq!(queue.len(), NOTIFY_QUEUE_DEPTH);
        assert_eq!(queue[0].path, "\\5", "the oldest is the one dropped");
    }

    /// v1 emptied the mount point, and a member who put files there lost them.
    /// A mount is never worth that.
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

    /// WinFsp makes the mount point itself, so an empty leftover is cleared out
    /// of its way rather than reused.
    #[test]
    fn an_empty_mount_point_is_cleared_for_winfsp_to_make_its_own() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = home.path().join("CipherBox");
        fs::create_dir(&at).expect("a leftover mount point");

        prepare(&at).expect("an empty leftover is cleared");
        assert!(!at.exists());
    }

    #[test]
    fn a_missing_mount_point_is_left_for_winfsp_to_make() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = home.path().join("CipherBox");

        prepare(&at).expect("a missing mount point needs no clearing");
        assert!(!at.exists());
        assert!(home.path().is_dir(), "the parent is made if it is missing");
    }

    #[test]
    fn a_mount_point_that_is_a_file_is_refused() {
        let home = tempfile::tempdir().expect("a temp dir");
        let at = home.path().join("CipherBox");
        fs::write(&at, b"not a directory").expect("a file in the way");

        assert!(prepare(&at).is_err());
    }

    /// Everything the decoder refuses before the core sees it is an error
    /// severity status, or WinFsp takes the operation for one that worked.
    #[test]
    fn every_pre_core_refusal_is_an_error_severity_status() {
        for status in [
            STATUS_VOLUME_DISMOUNTED,
            STATUS_END_OF_FILE,
            STATUS_OBJECT_NAME_INVALID,
        ] {
            assert_eq!((status as u32) >> 30, 0b11, "{status:#x} must refuse");
        }
    }
}
