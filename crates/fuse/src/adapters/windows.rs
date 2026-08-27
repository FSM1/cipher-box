//! The Windows backend: WinFsp's user-mode filesystem host, reached through the
//! `winfsp` crate (blueprint/desktop.md "Backends"; licence notice in
//! `docs/ATTRIBUTION.md`).
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
//! Access control is this backend's own, which is the one thing the FUSE wire
//! gets from the kernel for free: see [`crate::adapters::descriptor`].

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::fs;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};

use cipherbox_engine::seams::SeamTypes;
use cipherbox_engine::{NodeId, NodeKind, SyncTimingProfile};
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
use crate::adapters::descriptor::OwnerOnlyDescriptor;
use crate::adapters::{ADVISORY_CAPACITY_BYTES, DOT_ENTRIES, Listed, cursor_of};
use crate::error::VfsError;
use crate::handle::{Access, HandleId};
use crate::inode::ROOT_INO;
use crate::name::MAX_NAME_BYTES;
use crate::ntstatus::{NtStatus, STATUS_OBJECT_NAME_INVALID, ntstatus_of};
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

/// How many inode→path bindings this adapter remembers so it can name them to
/// `FspFileSystemNotify`. Finite whatever a peer commits, on the same grounds
/// as the operation core's shadow maps: a path evicted here is a notification
/// dropped, never a wrong one sent.
const NOTIFIABLE_PATHS: usize = 4096;

/// How many notifications may queue between two timer ticks. A queue that
/// overflows drops its oldest: a mount cannot make the kernel wait, and the
/// cache lifetimes are the backstop.
const NOTIFY_QUEUE_DEPTH: usize = 4096;

/// The widest name a `DirInfo` buffer has to hold, in UTF-16 units:
/// [`MAX_NAME_BYTES`] of UTF-8 is at most that many UTF-16 units, plus the NUL
/// `set_name` appends. One entry is one path component.
const NAME_UNITS: usize = MAX_NAME_BYTES + 1;

/// The widest path a `NotifyInfo` buffer has to hold. A notification names a
/// whole path, not a component, so sizing it like a name would silence
/// invalidation for anything nested. WinFsp's own ceiling for a path in a
/// transaction is `FSP_FSCTL_TRANSACT_PATH_SIZEMAX`, 1024 UTF-16 units.
const NOTIFY_PATH_UNITS: usize = 1024;

// The two NT statuses this adapter decides on its own, for states the operation
// core never sees; every other refusal comes from `crate::ntstatus`.
/// The mount is on its way down and no operation will be answered again.
const STATUS_VOLUME_DISMOUNTED: NtStatus = 0xC000_026E_u32 as i32;
/// A read that started at or past the end of the file.
const STATUS_END_OF_FILE: NtStatus = 0xC000_0011_u32 as i32;

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

/// The `FILE_ATTRIBUTE_*` word a node presents. The projection carries no
/// read-only or hidden bit of its own.
fn file_attributes(kind: NodeKind) -> u32 {
    match kind {
        NodeKind::Folder => FILE_ATTRIBUTE_DIRECTORY,
        NodeKind::File => FILE_ATTRIBUTE_NORMAL,
    }
}

/// One node as WinFsp's `FSP_FSCTL_FILE_INFO`.
///
/// A size the content plane has not projected yet is reported as zero, because
/// the reply has to carry some number. On the FUSE wire that number comes with
/// a lifetime of zero; WinFsp times file information per volume rather than per
/// reply, so what corrects it here is push invalidation, which is why this
/// backend must never ship with `push_invalidation` false.
fn file_info(kind: NodeKind, size: Option<u64>, mtime_millis: Option<u64>) -> FileInfo {
    let size = size.unwrap_or(0);
    let time = filetime(mtime_millis);
    FileInfo {
        file_attributes: file_attributes(kind),
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

/// The attributes and descriptor size `get_security_by_name` answers with. The
/// size is never zero — see [`crate::adapters::descriptor`].
fn security_of(attrs: &Attributes, descriptor: &OwnerOnlyDescriptor) -> FileSecurity {
    FileSecurity {
        reparse: false,
        sz_security_descriptor: descriptor.len(),
        attributes: file_attributes(attrs.kind),
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
    /// Where this page starts in WinFsp's offset space.
    offset: usize,
    /// The children the core resumed at [`cursor_of(offset)`](cursor_of).
    entries: Vec<DirEntry>,
}

impl Listing {
    /// One [`crate::adapters::page`] as WinFsp's `DirInfo` wants it: a dot
    /// entry carries the directory's own information.
    fn page(&self) -> impl Iterator<Item = (&str, FileInfo, usize)> {
        let dir = info_of(&self.dir);
        crate::adapters::page(self.offset, &self.entries).map(move |(listed, resume_at)| {
            match listed {
                Listed::Dot(name) => (name, dir.clone(), resume_at),
                Listed::Child(child) => (
                    child.name.as_str(),
                    file_info(child.kind, child.size, child.mtime_millis),
                    resume_at,
                ),
            }
        })
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
        ino: u64,
        handle: HandleId,
        reply: Answer<Attributes>,
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
    /// Remove the node the closing handle was opened on, named by the path
    /// WinFsp gave and checked against the identity the handle holds.
    Delete {
        path: VaultPath,
        node: NodeId,
        reply: Answer<()>,
    },
    Rename {
        from: VaultPath,
        to: VaultPath,
        replace: bool,
        reply: Answer<()>,
    },
}

/// A [`WinFspOp`] as a host sees it: opaque, and answered exactly once. A host
/// takes it from [`WinFspMount::next_op`] and hands it back to
/// [`WinFspMount::answer`]. Dropping it instead refuses it, because dropping it
/// drops the answer channel the dispatcher thread is waiting on.
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

    /// Drop every binding at or under `prefix` — what a rename or a delete
    /// makes wrong. A binding kept past its path would name a node that has
    /// moved, and, once something new is created there, notify about the wrong
    /// one.
    fn forget_subtree(&mut self, prefix: &str) {
        let under = format!("{}\\", prefix.trim_end_matches('\\'));
        self.by_ino
            .retain(|_, path| path != prefix && !path.starts_with(&under));
        self.order.retain(|ino| self.by_ino.contains_key(ino));
    }
}

/// What the invalidator and the notify timer share: the paths one can name and
/// the queue the other drains.
#[derive(Default)]
struct NotifyPlane {
    book: Mutex<PathBook>,
    queue: Mutex<VecDeque<Notification>>,
    /// Invalidations this mount could not turn into a notification. Counted
    /// rather than swallowed: push is the only thing that corrects this
    /// backend's caches, so a drop is a node stale until its lifetime expires,
    /// and a mount that drops them silently looks exactly like one that has
    /// nothing to say.
    dropped: AtomicU64,
}

impl NotifyPlane {
    fn push(&self, notification: Notification) {
        // A path WinFsp's own transaction cannot carry would be refused by
        // `set_name` on the timer thread, where there is nothing left to
        // report; it is counted here, where there still is.
        if notification.path.encode_utf16().count() >= NOTIFY_PATH_UNITS {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(mut queue) = self.queue.lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if queue.len() >= NOTIFY_QUEUE_DEPTH {
            queue.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(notification);
    }

    fn drop_one(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
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
        match notification {
            Some(notification) => self.plane.push(notification),
            None => self.plane.drop_one(),
        }
    }
}

/// The `winfsp::FileSystemContext` this mount registers: a decoder, and nothing
/// else.
struct VaultFs {
    ops: mpsc::UnboundedSender<WinFspOp>,
    plane: Arc<NotifyPlane>,
    /// The volume's owner-only descriptor, built once at mount: every node
    /// reports the same one, because the projection stores no per-node
    /// ownership.
    descriptor: OwnerOnlyDescriptor,
    resumes: Resumes,
}

/// What one open WinFsp handle addresses. WinFsp hands it back by shared
/// reference from any thread, so what has to change under it — the path a
/// rename moves — is behind a lock.
pub struct OpenNode {
    ino: u64,
    /// The engine's stable node id, which a rename anywhere above this node
    /// cannot change. What a delete is checked against — see
    /// [`WinFspMount::delete`].
    node: NodeId,
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

/// A refusal the decoder makes before the core sees the request, answered
/// through the shared table rather than beside it so no adapter drifts from
/// another.
fn refuse(error: &VfsError) -> FspError {
    FspError::NTSTATUS(ntstatus_of(error))
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
        // A quiesce that landed between the send and here has already drained
        // what it could see, so this operation may be sitting in a queue
        // nothing will read again. Refusing now is what keeps a dispatcher
        // thread out of a wait that cannot end.
        if self.ops.is_closed() {
            return Err(dismounted());
        }
        match answers.recv() {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(refusal)) => Err(refuse(&refusal)),
            // The operation was dropped unanswered, which is how the pump
            // refuses everything queued when the session ends.
            Err(_) => Err(dismounted()),
        }
    }

    fn path_of(&self, name: &U16CStr) -> winfsp::Result<VaultPath> {
        components(name).ok_or_else(unnameable)
    }

    /// The context an `open` or a `create` landed, with the reply it fills.
    fn landed(&self, path: VaultPath, opened: Opened, file_info: &mut OpenFileInfo) -> OpenNode {
        *file_info.as_mut() = info_of(&opened.attrs);
        OpenNode {
            ino: opened.attrs.ino,
            node: opened.attrs.node,
            kind: opened.attrs.kind,
            held: opened.held,
            path: Mutex::new(path),
        }
    }
}

impl FileSystemContext for VaultFs {
    type FileContext = OpenNode;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let path = self.path_of(file_name)?;
        let attrs = self.ask(|reply| WinFspOp::Stat { path, reply })?;
        cipherbox_win_security::write_descriptor(security_descriptor, self.descriptor.as_bytes());
        Ok(security_of(&attrs, &self.descriptor))
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
        Ok(self.landed(path, opened, file_info))
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
        Ok(self.landed(path, opened, file_info))
    }

    /// The last user-mode handle on the file has closed. A delete disposition
    /// set by [`set_delete`](Self::set_delete) is carried out here, which is
    /// WinFsp's contract: nothing may be deleted while a handle can still
    /// reach it.
    fn cleanup(&self, context: &Self::FileContext, file_name: Option<&U16CStr>, flags: u32) {
        if flags & FSP_CLEANUP_DELETE == 0 {
            return;
        }
        // WinFsp's own name for the node, which is current as of this request;
        // the one captured at open is stale the moment anything above the node
        // is renamed. The captured path is only the fallback for a request that
        // carried none.
        let path = match file_name.and_then(components) {
            Some(path) => path,
            None => match context.path.lock() {
                Ok(path) => path.clone(),
                Err(_) => return,
            },
        };
        let node = context.node;
        // Nothing to answer: `cleanup` returns no status, and the removability
        // check already ran at `set_delete`.
        let _ = self.ask(|reply| WinFspOp::Delete { path, node, reply });
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // A whole-volume flush (`None`) has nothing to push: the durable op
        // queue is this mount's only durability layer, and every handle's
        // writes reach it at that handle's own flush or release.
        let Some(context) = context else {
            return Ok(());
        };
        let Some(handle) = context.held.handle else {
            return Ok(());
        };
        let ino = context.ino;
        let attrs = self.ask(|reply| WinFspOp::Flush { ino, handle, reply })?;
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

    /// The volume's one descriptor, on the same terms as
    /// [`get_security_by_name`](Self::get_security_by_name): the projection
    /// stores no per-node ownership, and the mount belongs to one account.
    fn get_security(
        &self,
        _context: &Self::FileContext,
        security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        Ok(cipherbox_win_security::write_descriptor(
            security_descriptor,
            self.descriptor.as_bytes(),
        ))
    }

    // `set_security` is left to the trait's default refusal: the vault stores
    // no ACL, and accepting a descriptor to discard it would acknowledge a
    // permission change that never happened.

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
            .ok_or_else(|| refuse(&VfsError::NotADirectory))?;
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
        let mut emitted: Option<Resume> = None;
        for (name, info, resume_at) in listing.page() {
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
            emitted = Some(Resume {
                last: name.to_owned(),
                offset: resume_at,
            });
        }
        // Recorded here rather than by the pump: only the dispatcher knows how
        // much of the page fitted, and a marker for an entry the client never
        // saw restarts the enumeration on every continuation.
        if let (Ok(mut resumes), Some(emitted)) = (self.resumes.lock(), emitted) {
            resumes.insert(walk, emitted);
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
            .ok_or_else(|| refuse(&VfsError::BadHandle))?;
        let size = u32::try_from(buffer.len()).map_err(|_| refuse(&VfsError::Invalid))?;
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
            .ok_or_else(|| refuse(&VfsError::BadHandle))?;
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

    /// [`ADVISORY_CAPACITY_BYTES`], without asking the engine anything: the
    /// facade counts nodes, and a Windows volume has nowhere to report a node
    /// count.
    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
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
            let mut info = NotifyInfo::<NOTIFY_PATH_UNITS>::new();
            if info.set_name(&notification.path).is_err() {
                self.plane.drop_one();
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
    ops: mpsc::UnboundedReceiver<WinFspOp>,
    pump: Pump,
}

/// The mount's answering half: everything [`WinFspMount::answer`] needs that is
/// not the WinFsp host itself.
///
/// Held apart from the host so the operation logic — path resolution, the
/// identity a delete is checked against, the collision a rename refuses — can
/// be driven without a live volume, which is the only way any of it is testable
/// off a mounted machine.
struct Pump {
    plane: Arc<NotifyPlane>,
    resumes: Resumes,
    /// Close-time commits that did not land. `close` returns no status to
    /// WinFsp, so this counter is the only place a host could ever learn that a
    /// handle's last writes were never journaled.
    close_failures: u64,
}

/// Where one open directory's enumeration continues.
///
/// The last name *emitted*, and nothing else. WinFsp's marker is defined as the
/// last name the filesystem transferred, so one entry answers every
/// continuation — and one entry per open directory is what keeps this bounded.
/// A whole page's worth would be sized by what a peer committed, which is the
/// same unbounded growth the operation core's shadow maps exist to refuse.
struct Resume {
    last: String,
    offset: usize,
}

/// The open directories' resume markers, shared between the dispatcher that
/// writes them and the pump that reads and retires them.
type Resumes = Arc<Mutex<HashMap<DirHandleId, Resume>>>;

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
        // Built before the volume exists: a mount that cannot name the account
        // it belongs to must not serve a node (`crate::adapters::descriptor`).
        let descriptor = OwnerOnlyDescriptor::for_this_user()?;

        let (sender, ops) = mpsc::unbounded();
        let plane = Arc::new(NotifyPlane::default());
        let resumes: Resumes = Arc::new(Mutex::new(HashMap::new()));
        let context = VaultFs {
            ops: sender,
            plane: Arc::clone(&plane),
            descriptor,
            resumes: Arc::clone(&resumes),
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
            ops,
            pump: Pump {
                plane,
                resumes,
                close_failures: 0,
            },
        })
    }

    /// The invalidator to mount the operation core behind.
    pub fn invalidator(&self) -> WinFspInvalidator {
        self.invalidator.clone()
    }

    /// Handles this mount closed while they still owed an `updateContent` op
    /// that would not journal.
    ///
    /// `close` returns no status on this protocol, so nothing else in the
    /// session ever learns of one — the FUSE backends answer the same failure
    /// out of `close(2)`.
    pub fn close_failures(&self) -> u64 {
        self.pump.close_failures
    }

    /// Invalidations this mount could not push at the kernel: a node it could
    /// not name a path for, a path WinFsp's own transaction could not carry, or
    /// a notify queue at its ceiling. See [`NotifyPlane::dropped`].
    pub fn dropped_notifications(&self) -> u64 {
        self.pump.plane.dropped.load(Ordering::Relaxed)
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
        self.pump.answer(core, op).await;
    }
}

impl Pump {
    /// Answer one operation from `core`.
    async fn answer<T: SeamTypes>(
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
                    if let Ok(mut resumes) = self.resumes.lock() {
                        resumes.remove(&walk);
                    }
                }
                let released = match held.handle {
                    Some(handle) => core.release(handle).await,
                    None => Ok(()),
                };
                // WinFsp's `Close` returns no status, so a commit that failed
                // here reaches nobody through the kernel. Counted so the host
                // can see that this mount closed a handle owing writes it never
                // journaled — the no-false-ack discipline's last mile is a
                // refusal `close(2)` carries on the FUSE backends and this one
                // cannot.
                if released.is_err() {
                    self.close_failures += 1;
                }
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
            WinFspOp::Flush { ino, handle, reply } => {
                let outcome = match core.flush(handle).await {
                    Ok(()) => core.getattr(ino).await,
                    Err(refusal) => Err(refusal),
                };
                reply.give(outcome);
            }
            WinFspOp::ReadDir {
                ino,
                walk,
                marker,
                reply,
            } => {
                reply.give(self.read_dir(core, ino, walk, marker).await);
            }
            WinFspOp::Removable { ino, kind, reply } => {
                reply.give(core.removable(ino, kind).await);
            }
            WinFspOp::Delete { path, node, reply } => {
                reply.give(self.delete(core, &path, node).await);
            }
            WinFspOp::Rename {
                from,
                to,
                replace,
                reply,
            } => {
                reply.give(self.rename(core, &from, &to, replace).await);
            }
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
        self.remember(ROOT_INO, &[]);
        let mut here = None;
        let mut parent = ROOT_INO;
        for (depth, name) in path.iter().enumerate() {
            let found = core.lookup(parent, name).await?;
            self.remember(found.ino, &path[..=depth]);
            parent = found.ino;
            here = Some(found);
        }
        match here {
            Some(found) => Ok(found),
            None => core.getattr(ROOT_INO).await,
        }
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
            // A marker that is not the last name this walk emitted restarts
            // rather than skipping to a guess, on [`Marker::of`]'s terms.
            Marker::After(name) => self.resumes.lock().ok().map_or(0, |resumes| {
                resumes
                    .get(&walk)
                    .filter(|resume| resume.last == name)
                    .map_or(0, |resume| resume.offset)
            }),
        };
        let dir = core.getattr(ino).await?;
        let entries = core.readdir(walk, cursor_of(offset)).await?;
        Ok(Listing {
            dir,
            offset,
            entries: entries.to_vec(),
        })
    }

    /// Remove `node`, which must still be what `path` names.
    ///
    /// The identity check is the whole point. A delete disposition is set when
    /// a handle is opened and carried out when it closes, and in between an
    /// ancestor can move — locally, or absorbed from a peer, which fires no
    /// callback at all. Removing whatever the path names by then would remove
    /// a node this handle was never opened on.
    async fn delete<T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, WinFspInvalidator>,
        path: &[String],
        node: NodeId,
    ) -> Result<(), VfsError> {
        let (parent, name) = self.parent_of(core, path).await?;
        let found = core.lookup(parent.ino, name).await?;
        if found.node != node {
            return Err(VfsError::NotFound);
        }
        let removed = match found.kind {
            NodeKind::Folder => core.rmdir(parent.ino, name).await,
            NodeKind::File => core.unlink(parent.ino, name).await,
        };
        if removed.is_ok() {
            self.forget_paths(path);
        }
        removed
    }

    async fn rename<T: SeamTypes>(
        &mut self,
        core: &mut OperationCore<T, WinFspInvalidator>,
        from: &[String],
        to: &[String],
        replace: bool,
    ) -> Result<(), VfsError> {
        let (parent, name) = self.parent_of(core, from).await?;
        let source = core.lookup(parent.ino, name).await?;
        let (destination, new_name) = self.parent_of(core, to).await?;
        // POSIX rename replaces unconditionally; Windows asks first, and a
        // caller that did not ask must get the collision rather than a silent
        // replacement. Compared against the node being moved, not its parent:
        // a case-only respell folds onto the source itself and is a rename, not
        // a collision.
        if !replace {
            match core.lookup(destination.ino, new_name).await {
                Ok(found) if found.node != source.node => return Err(VfsError::AlreadyExists),
                Ok(_) => {}
                // Only absence is "nothing in the way". Every other refusal
                // means the destination could not be read, and a rename that
                // replaced on an unread destination would destroy it.
                Err(VfsError::NotFound) => {}
                Err(refusal) => return Err(refusal),
            }
        }
        core.rename(parent.ino, name, destination.ino, new_name)
            .await?;
        self.forget_paths(from);
        self.remember(source.ino, to);
        Ok(())
    }

    /// Drop the bindings for `path` and everything under it, so no later
    /// notification names a path the vault no longer has.
    fn forget_paths(&mut self, path: &[String]) {
        if let Ok(mut book) = self.plane.book.lock() {
            book.forget_subtree(&rendered(path));
        }
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
///
/// That length is [`OperationCore::append_offset`]'s, never `getattr`'s: a file
/// whose content plane has not projected a size yet reports `None`, and reading
/// that as zero would land an append on the head of the file and a constrained
/// write nowhere at all. Both are silent — the version still publishes the
/// right total length.
async fn write<T: SeamTypes>(
    core: &mut OperationCore<T, WinFspInvalidator>,
    ino: u64,
    handle: HandleId,
    offset: u64,
    data: &[u8],
    at_end: bool,
    constrained: bool,
) -> Result<(u32, Attributes), VfsError> {
    let (offset, data) = if at_end || constrained {
        let len = core.append_offset(handle).await?;
        let offset = if at_end { len } else { offset };
        // Constrained I/O is the cache manager writing back pages it already
        // owns: it must never extend the file, and a window wholly past the end
        // writes nothing at all.
        let room = match constrained {
            true => usize::try_from(len.saturating_sub(offset)).unwrap_or(usize::MAX),
            false => data.len(),
        };
        (offset, &data[..room.min(data.len())])
    } else {
        (offset, data)
    };
    if data.is_empty() {
        return Ok((0, core.getattr(ino).await?));
    }
    let taken = core.write(handle, offset, data).await?;
    Ok((taken, core.getattr(ino).await?))
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
        // The volume enforces one owner-only ACL on every node, which is what
        // this advertises; it is not settable, and `set_security` refuses.
        .persistent_acls(true)
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
            offset,
            entries: children
                .get(cursor_of(offset)..)
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

    /// A node deep enough to outgrow a *name* buffer must still be notifiable:
    /// a notification names a whole path, not a component.
    #[test]
    fn a_deeply_nested_node_is_still_notified() {
        let plane = Arc::new(NotifyPlane::default());
        let invalidator = WinFspInvalidator {
            plane: Arc::clone(&plane),
        };
        // Well past the 255-unit ceiling a single name is held to, and well
        // inside WinFsp's own ceiling for a path.
        let deep: VaultPath = (0..40).map(|step| format!("folder-{step:04}")).collect();
        assert!(rendered(&deep).len() > MAX_NAME_BYTES);
        plane.book.lock().expect("the book").remember(9, &deep);

        invalidator.invalidate(Invalidation::Data { ino: 9 });
        assert_eq!(
            plane.queue.lock().expect("the queue")[0].path,
            rendered(&deep)
        );
        assert_eq!(plane.dropped.load(Ordering::Relaxed), 0);
    }

    /// The two shapes of drop [`NotifyPlane::dropped`] has to count.
    #[test]
    fn an_unnameable_invalidation_is_counted_rather_than_swallowed() {
        let plane = Arc::new(NotifyPlane::default());
        let invalidator = WinFspInvalidator {
            plane: Arc::clone(&plane),
        };

        invalidator.invalidate(Invalidation::Data { ino: 9 });
        assert_eq!(
            plane.dropped.load(Ordering::Relaxed),
            1,
            "a node this mount cannot name"
        );

        let sprawling: VaultPath = (0..NOTIFY_PATH_UNITS).map(|_| "x".to_owned()).collect();
        plane.book.lock().expect("the book").remember(9, &sprawling);
        invalidator.invalidate(Invalidation::Data { ino: 9 });
        assert!(plane.queue.lock().expect("the queue").is_empty());
        assert_eq!(
            plane.dropped.load(Ordering::Relaxed),
            2,
            "a path WinFsp's transaction could not carry"
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

    /// A rename moves a whole subtree's paths, and a path is what a
    /// notification names. A binding kept past its path names a node that has
    /// moved — and notifies about the wrong one once something is created
    /// where it used to be.
    #[test]
    fn a_rename_rebinds_the_moved_path_and_drops_what_moved_under_it() {
        let mut book = PathBook::default();
        book.remember(2, &["Archive".to_owned()]);
        book.remember(3, &["Archive".to_owned(), "report.txt".to_owned()]);
        book.remember(4, &["Elsewhere".to_owned()]);

        book.forget_subtree(&rendered(&["Archive".to_owned()]));
        assert_eq!(book.path(2), None, "the moved node's old path is gone");
        assert_eq!(book.path(3), None, "and so is everything under it");
        assert_eq!(
            book.path(4),
            Some("\\Elsewhere"),
            "a sibling that only shares a prefix's first letters is untouched"
        );

        book.remember(2, &["Moved".to_owned()]);
        assert_eq!(book.path(2), Some("\\Moved"));
    }

    /// A prefix match on the rendered string alone would take `\Archived` for a
    /// child of `\Archive`.
    #[test]
    fn forgetting_a_subtree_stops_at_the_path_separator() {
        let mut book = PathBook::default();
        book.remember(2, &["Archive".to_owned()]);
        book.remember(3, &["Archived".to_owned()]);

        book.forget_subtree("\\Archive");
        assert_eq!(book.path(2), None);
        assert_eq!(book.path(3), Some("\\Archived"));
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

    /// The one thing standing between a second local account and the vault's
    /// plaintext — see [`crate::adapters::descriptor`].
    #[test]
    fn every_node_reports_a_descriptor_scoped_to_the_mounting_user() {
        let descriptor = OwnerOnlyDescriptor::for_this_user().expect("this process has a user");
        assert!(descriptor.len() > 0, "a zero-length descriptor is no check");

        for kind in [NodeKind::File, NodeKind::Folder] {
            let reported = security_of(&node(kind, None), &descriptor);
            assert_eq!(reported.sz_security_descriptor, descriptor.len());
            assert!(!reported.reparse);
        }
    }

    // --- the pump, driven over a real engine on the in-memory seams ---

    use cipherbox_engine::testkit::{FakeSeamTypes, FakeWorld, SeededEntropy, block_on};
    use cipherbox_engine::{
        ApiBaseUrl, Command, ContentProfile, Engine, GatewayConfig, LoginSecret, StoragePolicy,
    };

    use crate::cache::CacheBudget;
    use crate::spill::SpillArea;

    type TestCore = OperationCore<FakeSeamTypes, WinFspInvalidator>;

    fn pumped() -> (Pump, TestCore) {
        let plane = Arc::new(NotifyPlane::default());
        let world = FakeWorld::new();
        let device = world.device(b"alice-pk");
        let (mut engine, _events) = Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
            ContentProfile::CI,
            StoragePolicy::CI,
            ApiBaseUrl::offline(),
            GatewayConfig::disabled(),
        );
        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).expect("the engine starts");
        let spill = SpillArea::seeded(
            tempfile::tempdir().expect("a spill dir").keep(),
            Box::new(SeededEntropy::new(11)),
        )
        .expect("the spill area opens");
        let core = OperationCore::new(
            engine,
            WinFspInvalidator {
                plane: Arc::clone(&plane),
            },
            CacheBudget::CI,
            spill,
        );
        let pump = Pump {
            plane,
            resumes: Arc::new(Mutex::new(HashMap::new())),
            close_failures: 0,
        };
        (pump, core)
    }

    fn path(parts: &[&str]) -> VaultPath {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    /// Seed a child the way another client would commit one, straight through
    /// the facade.
    fn seed(core: &mut TestCore, parent: &[&str], name: &str, kind: NodeKind) {
        let parent = if parent.is_empty() {
            block_on(core.getattr(ROOT_INO)).expect("the root").node
        } else {
            let mut here = block_on(core.getattr(ROOT_INO)).expect("the root");
            for step in parent {
                here = block_on(core.lookup(here.ino, step)).expect("an ancestor");
            }
            here.node
        };
        block_on(core.engine_mut().command(Command::Create {
            parent,
            name: name.to_owned(),
            kind,
        }))
        .expect("the seeded create");
    }

    fn names_under(core: &mut TestCore, parent: &[&str]) -> Vec<String> {
        let mut here = block_on(core.getattr(ROOT_INO)).expect("the root");
        for step in parent {
            here = block_on(core.lookup(here.ino, step)).expect("an ancestor");
        }
        let walk = block_on(core.opendir(here.ino)).expect("opendir");
        let listed = block_on(core.readdir(walk, 0))
            .expect("readdir")
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        core.releasedir(walk);
        listed
    }

    /// The one respelling Windows resolves and POSIX does not: a rename onto a
    /// fold of the source's own name. Comparing the destination against the
    /// source's *parent* would call that a collision and refuse every attempt
    /// to fix a file's capitalisation.
    #[test]
    fn a_case_only_rename_is_a_rename_and_not_a_collision() {
        let (mut pump, mut core) = pumped();
        seed(&mut core, &[], "Report.txt", NodeKind::File);

        block_on(pump.rename(
            &mut core,
            &path(&["Report.txt"]),
            &path(&["REPORT.TXT"]),
            false,
        ))
        .expect("a respell of a node's own name is a rename");
        assert_eq!(names_under(&mut core, &[]), vec!["REPORT.TXT".to_owned()]);
    }

    /// A destination that genuinely holds another node is still a collision,
    /// and a caller that did not ask to replace must get one.
    #[test]
    fn a_rename_onto_another_node_is_refused_unless_replacement_was_asked_for() {
        let (mut pump, mut core) = pumped();
        seed(&mut core, &[], "draft.txt", NodeKind::File);
        seed(&mut core, &[], "report.txt", NodeKind::File);

        assert_eq!(
            block_on(pump.rename(
                &mut core,
                &path(&["draft.txt"]),
                &path(&["report.txt"]),
                false,
            )),
            Err(VfsError::AlreadyExists)
        );
        assert_eq!(names_under(&mut core, &[]).len(), 2, "nothing was replaced");

        block_on(pump.rename(
            &mut core,
            &path(&["draft.txt"]),
            &path(&["report.txt"]),
            true,
        ))
        .expect("a caller that asked to replace, replaces");
        assert_eq!(names_under(&mut core, &[]), vec!["report.txt".to_owned()]);
    }

    /// A destination the mount could not read is not a destination it may
    /// overwrite. Only absence means "nothing in the way": collapsing every
    /// refusal into that would let one transient failure destroy a file the
    /// caller never asked to replace.
    #[test]
    fn a_rename_that_could_not_probe_the_destination_refuses_rather_than_replacing() {
        let (mut pump, mut core) = pumped();
        seed(&mut core, &[], "draft.txt", NodeKind::File);
        seed(&mut core, &[], "Archive", NodeKind::Folder);

        // A destination *inside a file* is the probe refusing for a reason
        // that is not absence — the parent cannot be walked at all.
        assert_eq!(
            block_on(pump.rename(
                &mut core,
                &path(&["Archive"]),
                &path(&["draft.txt", "moved"]),
                false,
            )),
            Err(VfsError::NotADirectory),
            "the probe's own refusal is the rename's"
        );
        assert_eq!(
            names_under(&mut core, &[]).len(),
            2,
            "and nothing moved or was replaced"
        );
    }

    /// A rename moves the paths a notification names, and [`PathBook`] is the
    /// only thing in the projection that tracks them.
    #[test]
    fn a_rename_rebinds_the_paths_a_notification_would_name() {
        let (mut pump, mut core) = pumped();
        seed(&mut core, &[], "Archive", NodeKind::Folder);
        seed(&mut core, &["Archive"], "report.txt", NodeKind::File);

        let moved = block_on(pump.resolve(&mut core, &path(&["Archive"]))).expect("the folder");
        let child = block_on(pump.resolve(&mut core, &path(&["Archive", "report.txt"])))
            .expect("the child");
        assert_eq!(pump.plane.path(moved.ino).as_deref(), Some("\\Archive"));

        block_on(pump.rename(&mut core, &path(&["Archive"]), &path(&["Boxes"]), false))
            .expect("the rename");

        assert_eq!(
            pump.plane.path(moved.ino).as_deref(),
            Some("\\Boxes"),
            "the moved node answers to its new path"
        );
        assert_eq!(
            pump.plane.path(child.ino),
            None,
            "and nothing under it still answers to the old one"
        );
    }

    /// A delete disposition is set when a handle opens and carried out when it
    /// closes. In between an ancestor can move — locally, or absorbed from a
    /// peer, which fires no callback at all — and something else can be created
    /// at the path the handle remembers. Removing that would remove a node this
    /// handle was never opened on.
    #[test]
    fn a_delete_never_removes_a_node_recreated_at_the_old_path() {
        let (mut pump, mut core) = pumped();
        seed(&mut core, &[], "Archive", NodeKind::Folder);
        seed(&mut core, &["Archive"], "report.txt", NodeKind::File);
        let doomed = block_on(pump.resolve(&mut core, &path(&["Archive", "report.txt"])))
            .expect("the node the handle was opened on");

        // The ancestor moves, and a peer's `Archive` takes its place with a
        // `report.txt` of its own.
        block_on(pump.rename(&mut core, &path(&["Archive"]), &path(&["Boxes"]), false))
            .expect("the ancestor moves");
        seed(&mut core, &[], "Archive", NodeKind::Folder);
        seed(&mut core, &["Archive"], "report.txt", NodeKind::File);

        assert_eq!(
            block_on(pump.delete(&mut core, &path(&["Archive", "report.txt"]), doomed.node)),
            Err(VfsError::NotFound),
            "the name binds a different node now"
        );
        assert_eq!(
            names_under(&mut core, &["Archive"]),
            vec!["report.txt".to_owned()],
            "the impostor survives"
        );

        // The node the handle was actually opened on is still removable, under
        // the path it moved to.
        block_on(pump.delete(&mut core, &path(&["Boxes", "report.txt"]), doomed.node))
            .expect("the node this handle owned");
        assert!(names_under(&mut core, &["Boxes"]).is_empty());
    }

    /// A removed node's path must stop being notifiable, or a node later
    /// created there inherits its invalidations.
    #[test]
    fn a_delete_drops_the_path_it_removed() {
        let (mut pump, mut core) = pumped();
        seed(&mut core, &[], "report.txt", NodeKind::File);
        let doomed = block_on(pump.resolve(&mut core, &path(&["report.txt"]))).expect("the file");
        assert_eq!(pump.plane.path(doomed.ino).as_deref(), Some("\\report.txt"));

        block_on(pump.delete(&mut core, &path(&["report.txt"]), doomed.node)).expect("the delete");
        assert_eq!(pump.plane.path(doomed.ino), None);
    }

    /// One marker per open directory, whatever a peer committed inside it: the
    /// map the enumeration resumes through is the one structure this adapter
    /// adds, and it is sized by the kernel's open handles, never by a listing.
    #[test]
    fn the_directory_resume_map_holds_one_marker_per_open_directory() {
        let (mut pump, mut core) = pumped();
        seed(&mut core, &[], "Archive", NodeKind::Folder);
        for step in 0..64 {
            seed(
                &mut core,
                &["Archive"],
                &format!("file-{step:03}.txt"),
                NodeKind::File,
            );
        }
        let dir = block_on(pump.resolve(&mut core, &path(&["Archive"]))).expect("the folder");
        let walk = block_on(core.opendir(dir.ino)).expect("opendir");

        // Page the whole listing the way WinFsp does: emit, record the last
        // name emitted (the dispatcher's job), resume from it.
        let mut marker = Marker::Start;
        let mut seen = 0;
        loop {
            let listing =
                block_on(pump.read_dir(&mut core, dir.ino, walk, marker)).expect("a page");
            let Some((last, _, resume_at)) = listing.page().last() else {
                break;
            };
            seen += listing.entries.len();
            let last = last.to_owned();
            pump.resumes.lock().expect("the map").insert(
                walk,
                Resume {
                    last: last.clone(),
                    offset: resume_at,
                },
            );
            if listing.entries.is_empty() {
                break;
            }
            marker = Marker::After(last);
        }

        assert_eq!(seen, 64, "the whole listing was walked");
        assert_eq!(
            pump.resumes.lock().expect("the map").len(),
            1,
            "one open directory is one marker, however long its listing"
        );
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
