//! Hardware verification gates 1–3 for issue #644 (FSM1/cipher-box-next#32
//! pre-build checks), run by hand against FUSE-T >= 1.2.7 with the SMB backend.
//!
//! Gate 1: SMB invalidation round-trip latency (data / attr / entry), plus a
//!         no-invalidation control that measures natural SMB cache staleness.
//!         These numbers feed the kernel entry/attr TTL constants in the sync
//!         timing profile (blueprint/desktop.md, Freshness).
//! Gate 2: replay of the v1 macOS cross-client flake scenario, plus the
//!         attribute-churn/atomic-rename workload from fuse-t issue 109.
//! Gate 3: overwrite-rename atomicity under the SMB backend.
//!
//! Usage: hw-gates <gate1|gate2|gate3|all> [--iters N] [--ttl SECS] [--mnt PATH]

use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, Notifier, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
};

const ROOT_INO: u64 = 1;
const BLOCK: u32 = 4096;

// ---------------------------------------------------------------------------
// In-memory store: plays the role of the remote/canonical state. "Remote
// client" mutations edit it directly; the mount only sees them through FUSE.
// ---------------------------------------------------------------------------

enum NodeKind {
    File(Vec<u8>),
    Dir(BTreeMap<OsString, u64>),
}

struct Node {
    kind: NodeKind,
    mtime: SystemTime,
    crtime: SystemTime,
}

impl Node {
    fn new_file(data: Vec<u8>) -> Self {
        let now = SystemTime::now();
        Node {
            kind: NodeKind::File(data),
            mtime: now,
            crtime: now,
        }
    }
    fn new_dir() -> Self {
        let now = SystemTime::now();
        Node {
            kind: NodeKind::Dir(BTreeMap::new()),
            mtime: now,
            crtime: now,
        }
    }
    fn size(&self) -> u64 {
        match &self.kind {
            NodeKind::File(d) => d.len() as u64,
            NodeKind::Dir(_) => 0,
        }
    }
}

#[derive(Default)]
struct OpLog {
    renames: Vec<String>,
    rename_name_fallbacks: u64,
    creates: u64,
    unlinks: u64,
    setattrs: u64,
}

struct Store {
    nodes: HashMap<u64, Node>,
    next_ino: u64,
    ops: OpLog,
}

impl Store {
    fn new() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(ROOT_INO, Node::new_dir());
        Store {
            nodes,
            next_ino: 2,
            ops: OpLog::default(),
        }
    }

    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    fn insert_file(&mut self, parent: u64, name: &OsStr, data: Vec<u8>) -> u64 {
        let ino = self.alloc_ino();
        self.nodes.insert(ino, Node::new_file(data));
        if let Some(Node {
            kind: NodeKind::Dir(children),
            ..
        }) = self.nodes.get_mut(&parent)
        {
            children.insert(name.to_owned(), ino);
        }
        ino
    }

    fn insert_dir(&mut self, parent: u64, name: &OsStr) -> u64 {
        let ino = self.alloc_ino();
        self.nodes.insert(ino, Node::new_dir());
        if let Some(Node {
            kind: NodeKind::Dir(children),
            ..
        }) = self.nodes.get_mut(&parent)
        {
            children.insert(name.to_owned(), ino);
        }
        ino
    }

    fn child(&self, parent: u64, name: &OsStr) -> Option<u64> {
        match &self.nodes.get(&parent)?.kind {
            NodeKind::Dir(children) => children.get(name).copied(),
            _ => None,
        }
    }

    /// Exact lookup, falling back to a unique prefix match. FUSE-T has been
    /// observed truncating names in the rename callback (v1 finding); the
    /// fallback both keeps the harness working and counts occurrences so the
    /// gate can report whether 1.2.7 still does it.
    fn child_for_rename(&mut self, parent: u64, name: &OsStr) -> Option<(OsString, u64)> {
        if let Some(ino) = self.child(parent, name) {
            return Some((name.to_owned(), ino));
        }
        let matches: Vec<(OsString, u64)> = match &self.nodes.get(&parent)?.kind {
            NodeKind::Dir(children) => children
                .iter()
                .filter(|(n, _)| n.as_encoded_bytes().starts_with(name.as_encoded_bytes()))
                .map(|(n, i)| (n.clone(), *i))
                .collect(),
            _ => return None,
        };
        if matches.len() == 1 {
            self.ops.rename_name_fallbacks += 1;
            return Some(matches.into_iter().next().unwrap());
        }
        None
    }
}

// ---------------------------------------------------------------------------
// FUSE filesystem over the store
// ---------------------------------------------------------------------------

struct HwFs {
    store: Arc<Mutex<Store>>,
    ttl: Duration,
    // SMB backend treats fh=0 as an invalid handle (v1 finding) — never hand
    // out zero.
    next_fh: AtomicU64,
    uid: u32,
    gid: u32,
}

impl HwFs {
    fn attr(&self, ino: u64, node: &Node) -> FileAttr {
        let kind = match node.kind {
            NodeKind::File(_) => FileType::RegularFile,
            NodeKind::Dir(_) => FileType::Directory,
        };
        FileAttr {
            ino,
            size: node.size(),
            blocks: node.size().div_ceil(u64::from(BLOCK)),
            atime: node.mtime,
            mtime: node.mtime,
            ctime: node.mtime,
            crtime: node.crtime,
            kind,
            perm: if matches!(kind, FileType::Directory) {
                0o755
            } else {
                0o644
            },
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK,
            flags: 0,
        }
    }

    fn fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::Relaxed)
    }
}

impl Filesystem for HwFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let store = self.store.lock().unwrap();
        match store.child(parent, name) {
            Some(ino) => {
                let attr = self.attr(ino, &store.nodes[&ino]);
                reply.entry(&self.ttl, &attr, 0);
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let store = self.store.lock().unwrap();
        match store.nodes.get(&ino) {
            Some(node) => reply.attr(&self.ttl, &self.attr(ino, node)),
            None => reply.error(libc::ENOENT),
        }
    }

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
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let mut store = self.store.lock().unwrap();
        store.ops.setattrs += 1;
        let Some(node) = store.nodes.get_mut(&ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        if let Some(sz) = size {
            if let NodeKind::File(data) = &mut node.kind {
                data.resize(sz as usize, 0);
            }
        }
        node.mtime = match mtime {
            Some(TimeOrNow::SpecificTime(t)) => t,
            Some(TimeOrNow::Now) | None => SystemTime::now(),
        };
        let attr = self.attr(ino, node);
        reply.attr(&self.ttl, &attr);
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
        let mut store = self.store.lock().unwrap();
        if store.child(parent, name).is_some() {
            reply.error(libc::EEXIST);
            return;
        }
        let ino = store.insert_dir(parent, name);
        let attr = self.attr(ino, &store.nodes[&ino]);
        reply.entry(&self.ttl, &attr, 0);
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let mut store = self.store.lock().unwrap();
        store.ops.unlinks += 1;
        let Some(ino) = store.child(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };
        if let Some(Node {
            kind: NodeKind::Dir(children),
            ..
        }) = store.nodes.get_mut(&parent)
        {
            children.retain(|_, i| *i != ino);
        }
        store.nodes.remove(&ino);
        reply.ok();
    }

    fn rmdir(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.unlink(req, parent, name, reply);
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let mut store = self.store.lock().unwrap();
        store.ops.renames.push(format!(
            "{} -> {}",
            name.to_string_lossy(),
            newname.to_string_lossy()
        ));
        let Some((actual_name, ino)) = store.child_for_rename(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };
        // Overwrite semantics: dropping any existing target atomically under
        // the store lock — the whole point of gate 3 is whether the kernel
        // side preserves this atomicity for readers.
        let displaced = store.child(newparent, newname);
        if let Some(Node {
            kind: NodeKind::Dir(children),
            ..
        }) = store.nodes.get_mut(&parent)
        {
            children.remove(&actual_name);
        }
        if let Some(Node {
            kind: NodeKind::Dir(children),
            ..
        }) = store.nodes.get_mut(&newparent)
        {
            children.insert(newname.to_owned(), ino);
        }
        if let Some(old) = displaced {
            store.nodes.remove(&old);
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(self.fh(), 0);
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let store = self.store.lock().unwrap();
        match store.nodes.get(&ino) {
            Some(Node {
                kind: NodeKind::File(data),
                ..
            }) => {
                let start = (offset as usize).min(data.len());
                let end = (start + size as usize).min(data.len());
                reply.data(&data[start..end]);
            }
            _ => reply.error(libc::ENOENT),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let mut store = self.store.lock().unwrap();
        match store.nodes.get_mut(&ino) {
            Some(node) => {
                if let NodeKind::File(buf) = &mut node.kind {
                    let off = offset as usize;
                    if buf.len() < off + data.len() {
                        buf.resize(off + data.len(), 0);
                    }
                    buf[off..off + data.len()].copy_from_slice(data);
                    node.mtime = SystemTime::now();
                    reply.written(data.len() as u32);
                } else {
                    reply.error(libc::EISDIR);
                }
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn flush(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _lock: u64, reply: ReplyEmpty) {
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _ds: bool, reply: ReplyEmpty) {
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(self.fh(), 0);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let store = self.store.lock().unwrap();
        let Some(Node {
            kind: NodeKind::Dir(children),
            ..
        }) = store.nodes.get(&ino)
        else {
            reply.error(libc::ENOTDIR);
            return;
        };
        let mut entries: Vec<(u64, FileType, OsString)> = vec![
            (ino, FileType::Directory, OsString::from(".")),
            (ROOT_INO, FileType::Directory, OsString::from("..")),
        ];
        for (name, child_ino) in children {
            let kind = match store.nodes[child_ino].kind {
                NodeKind::File(_) => FileType::RegularFile,
                NodeKind::Dir(_) => FileType::Directory,
            };
            entries.push((*child_ino, kind, name.clone()));
        }
        for (i, (e_ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(e_ino, (i + 1) as i64, kind, &name) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _fl: i32, reply: ReplyEmpty) {
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        reply.statfs(
            1 << 30,
            1 << 29,
            1 << 29,
            1 << 20,
            1 << 20,
            BLOCK,
            255,
            BLOCK,
        );
    }

    // Encryption is the access control (v1 finding: SMB backend runs requests
    // under a different uid, so uid checks here break rename/open).
    fn access(&mut self, _req: &Request<'_>, _ino: u64, _mask: i32, reply: ReplyEmpty) {
        reply.ok();
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let mut store = self.store.lock().unwrap();
        store.ops.creates += 1;
        let ino = match store.child(parent, name) {
            Some(existing) => existing,
            None => store.insert_file(parent, name, Vec::new()),
        };
        let attr = self.attr(ino, &store.nodes[&ino]);
        reply.created(&self.ttl, &attr, 0, self.fh(), 0);
    }
}

// ---------------------------------------------------------------------------
// Mount plumbing
// ---------------------------------------------------------------------------

struct Mounted {
    session: Option<fuser::BackgroundSession>,
    notifier: Notifier,
    store: Arc<Mutex<Store>>,
    mnt: PathBuf,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        drop(self.session.take());
        // Finder or a stuck handle can wedge the plain unmount (v1 finding).
        let _ = std::process::Command::new("diskutil")
            .args(["unmount", "force"])
            .arg(&self.mnt)
            .output();
    }
}

impl Mounted {
    /// A "remote client" mutation: edit a file's bytes directly in the store
    /// (bypassing the mount) and bump its mtime.
    fn edit(&self, ino: u64, f: impl FnOnce(&mut Vec<u8>)) {
        let mut s = self.store.lock().unwrap();
        let node = s.nodes.get_mut(&ino).unwrap();
        if let NodeKind::File(d) = &mut node.kind {
            f(d);
        }
        node.mtime = SystemTime::now();
    }
}

/// `init` populates the store before the mount comes up: the SMB client
/// caches the first root listing, so anything a gate expects to be visible
/// without an invalidation must exist before the first read.
fn mount_opts(mnt: &Path, ttl: Duration, extra: &[&str], init: impl FnOnce(&mut Store)) -> Mounted {
    let _ = std::process::Command::new("umount").arg(mnt).output();
    std::fs::create_dir_all(mnt).expect("create mountpoint");

    let store = Arc::new(Mutex::new(Store::new()));
    init(&mut store.lock().unwrap());
    let fs = HwFs {
        store: store.clone(),
        ttl,
        next_fh: AtomicU64::new(1),
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let mut options = vec![
        MountOption::FSName("hwgates".to_string()),
        MountOption::CUSTOM("volname=HWGates".to_string()),
        MountOption::CUSTOM("noappledouble".to_string()),
        MountOption::CUSTOM("noapplexattr".to_string()),
        MountOption::CUSTOM("backend=smb".to_string()),
        MountOption::RW,
    ];
    options.extend(extra.iter().map(|o| MountOption::CUSTOM(o.to_string())));
    let session = fuser::spawn_mount2(fs, mnt, &options).expect("mount failed");
    let notifier = session.notifier();

    // The SMB mount comes up asynchronously, and read_dir on the not-yet
    // covered mountpoint happily lists the local (empty) directory — wait
    // until statfs reports smbfs at the mountpoint.
    let deadline = Instant::now() + Duration::from_secs(20);
    let c_mnt = std::ffi::CString::new(mnt.as_os_str().as_encoded_bytes()).unwrap();
    loop {
        let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c_mnt.as_ptr(), &mut sfs) } == 0 {
            let ty = unsafe { std::ffi::CStr::from_ptr(sfs.f_fstypename.as_ptr()) };
            if ty.to_bytes() == b"smbfs" {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "smbfs mount did not appear in 20s"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Mounted {
        session: Some(session),
        notifier,
        store,
        mnt: mnt.to_path_buf(),
    }
}

// ---------------------------------------------------------------------------
// Measurement helpers
// ---------------------------------------------------------------------------

fn stats_line(label: &str, samples: &mut [Duration], timeouts: usize) -> String {
    if samples.is_empty() {
        return format!("{label}: NO SAMPLES ({timeouts} timeouts)");
    }
    samples.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let p = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
    format!(
        "{label}: n={} min={:.1}ms p50={:.1}ms p95={:.1}ms max={:.1}ms timeouts={}",
        samples.len(),
        ms(samples[0]),
        ms(p(0.5)),
        ms(p(0.95)),
        ms(samples[samples.len() - 1]),
        timeouts
    )
}

fn poll_until(deadline: Duration, mut check: impl FnMut() -> bool) -> Option<Duration> {
    let start = Instant::now();
    loop {
        if check() {
            return Some(start.elapsed());
        }
        if start.elapsed() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Run `round` n times, collecting latencies and counting timeouts.
fn measure(n: usize, mut round: impl FnMut(usize) -> Option<Duration>) -> (Vec<Duration>, usize) {
    let mut lat = Vec::new();
    let mut timeouts = 0;
    for i in 0..n {
        match round(i) {
            Some(d) => lat.push(d),
            None => timeouts += 1,
        }
    }
    (lat, timeouts)
}

fn read_first(f: &std::fs::File) -> Option<u8> {
    use std::os::unix::fs::FileExt as _;
    let mut b = [0u8; 1];
    f.read_at(&mut b, 0).ok().map(|_| b[0])
}

// ---------------------------------------------------------------------------
// Gate 1 — invalidation round-trip latency
// ---------------------------------------------------------------------------

fn gate1(mnt: &Path, iters: usize, ttl: Duration) {
    println!(
        "\n=== Gate 1: SMB invalidation round-trip (ttl={}s) ===",
        ttl.as_secs()
    );
    let mut probe_ino = 0;
    let m = mount_opts(mnt, ttl, &[], |s| {
        probe_ino = s.insert_file(ROOT_INO, OsStr::new("probe.dat"), vec![0u8; 4096]);
    });
    let probe = m.mnt.join("probe.dat");
    std::fs::read(&probe).expect("warm read");

    // Data invalidation: same-size content change, so only the data cache can
    // reveal it.
    let (mut lat, to) = measure(iters, |i| {
        let pattern = ((i + 1) % 251 + 1) as u8;
        m.edit(probe_ino, |d| d.fill(pattern));
        m.notifier
            .inval_inode(probe_ino, 0, -1)
            .expect("inval_inode failed — SMB invalidation unsupported?");
        poll_until(Duration::from_secs(10), || {
            std::fs::read(&probe)
                .map(|d| d.first() == Some(&pattern))
                .unwrap_or(false)
        })
    });
    println!("{}", stats_line("data-inval ", &mut lat, to));

    // Attr invalidation: size grows by one byte per round.
    let mut expect_len = 4096u64;
    let (mut lat, to) = measure(iters, |_| {
        expect_len += 1;
        m.edit(probe_ino, |d| d.push(0xAB));
        m.notifier
            .inval_inode(probe_ino, 0, -1)
            .expect("inval_inode");
        poll_until(Duration::from_secs(10), || {
            std::fs::metadata(&probe)
                .map(|md| md.len() == expect_len)
                .unwrap_or(false)
        })
    });
    println!("{}", stats_line("attr-inval ", &mut lat, to));

    // Attr control: same size-growth change with NO invalidation, to tell
    // whether inval_inode moves attr visibility at all or the smbfs client
    // attr-cache TTL is the floor either way.
    let (mut lat, to) = measure(5, |_| {
        expect_len += 1;
        m.edit(probe_ino, |d| d.push(0xAB));
        poll_until(Duration::from_secs(30), || {
            std::fs::metadata(&probe)
                .map(|md| md.len() == expect_len)
                .unwrap_or(false)
        })
    });
    println!("{}", stats_line("attr-noinval", &mut lat, to));

    // Data visibility for a HELD-OPEN descriptor — the realistic desktop
    // case (apps keep files open; open-per-read polling defeats the SMB
    // client cache and hides staleness).
    let held = std::fs::File::open(&probe).expect("open probe");
    let (mut lat, to) = measure(iters, |i| {
        let pattern = (100 + i % 100) as u8;
        m.edit(probe_ino, |d| d.fill(pattern));
        m.notifier
            .inval_inode(probe_ino, 0, -1)
            .expect("inval_inode");
        poll_until(Duration::from_secs(10), || {
            read_first(&held) == Some(pattern)
        })
    });
    println!("{}", stats_line("open-fd data-inval  ", &mut lat, to));

    let (mut lat, to) = measure(5, |i| {
        let pattern = (210 + i) as u8;
        m.edit(probe_ino, |d| d.fill(pattern));
        let r = poll_until(Duration::from_secs(30), || {
            read_first(&held) == Some(pattern)
        });
        // Resync before the next control round.
        let _ = m.notifier.inval_inode(probe_ino, 0, -1);
        std::thread::sleep(Duration::from_millis(200));
        r
    });
    println!("{}", stats_line("open-fd data-noinval", &mut lat, to));
    drop(held);

    // Entry invalidation: new child appears remotely.
    let (mut lat, to) = measure(iters, |i| {
        let name = format!("entry_{i}.dat");
        m.store
            .lock()
            .unwrap()
            .insert_file(ROOT_INO, OsStr::new(&name), vec![1u8; 128]);
        m.notifier
            .inval_entry(ROOT_INO, OsStr::new(&name))
            .expect("inval_entry");
        let path = m.mnt.join(&name);
        poll_until(Duration::from_secs(10), || std::fs::metadata(&path).is_ok())
    });
    println!("{}", stats_line("entry-inval", &mut lat, to));

    // Control: how stale does the mount stay with NO invalidation? This is
    // the natural SMB cache horizon the TTL constants must otherwise absorb.
    let (mut lat, to) = measure(5, |i| {
        let pattern = (200 + i) as u8;
        m.edit(probe_ino, |d| d.fill(pattern));
        let r = poll_until(Duration::from_secs(30), || {
            std::fs::read(&probe)
                .map(|d| d.first() == Some(&pattern))
                .unwrap_or(false)
        });
        // Resync before the next control round.
        let _ = m.notifier.inval_inode(probe_ino, 0, -1);
        std::thread::sleep(Duration::from_millis(200));
        r
    });
    println!("{}", stats_line("no-inval   ", &mut lat, to));
}

/// Gate 1 follow-ups: (a) does `-o noattrcache` remove the smbfs 3s attr
/// floor, and (b) what is the real staleness horizon for data the client has
/// already cached, with and without invalidation.
fn gate1b(mnt: &Path, ttl: Duration) {
    println!("\n=== Gate 1b: noattrcache + cached-data staleness horizon ===");
    let mut probe_ino = 0;
    let m = mount_opts(mnt, ttl, &["noattrcache"], |s| {
        probe_ino = s.insert_file(ROOT_INO, OsStr::new("probe.dat"), vec![0u8; 4096]);
    });
    let probe = m.mnt.join("probe.dat");
    std::fs::read(&probe).expect("warm read");

    // Attr latency with noattrcache, invalidation fired.
    let mut expect_len = 4096u64;
    let (mut lat, to) = measure(10, |_| {
        expect_len += 1;
        m.edit(probe_ino, |d| d.push(0xAB));
        m.notifier
            .inval_inode(probe_ino, 0, -1)
            .expect("inval_inode");
        poll_until(Duration::from_secs(10), || {
            std::fs::metadata(&probe)
                .map(|md| md.len() == expect_len)
                .unwrap_or(false)
        })
    });
    println!("{}", stats_line("noattrcache attr-inval  ", &mut lat, to));

    let (mut lat, to) = measure(5, |_| {
        expect_len += 1;
        m.edit(probe_ino, |d| d.push(0xAB));
        poll_until(Duration::from_secs(15), || {
            std::fs::metadata(&probe)
                .map(|md| md.len() == expect_len)
                .unwrap_or(false)
        })
    });
    println!("{}", stats_line("noattrcache attr-noinval", &mut lat, to));

    // Staleness horizon for already-cached data: hold the file open and read
    // it so the client caches pages, then change it remotely and see how long
    // until the change lands — once with a single invalidation, once without.
    let held = std::fs::File::open(&probe).expect("open probe");
    for (label, fire_inval) in [("with-inval", true), ("no-inval", false)] {
        let _ = read_first(&held);
        std::thread::sleep(Duration::from_millis(500));
        let pattern = if fire_inval { 0x51 } else { 0x52 };
        m.edit(probe_ino, |d| d.fill(pattern));
        if fire_inval {
            m.notifier
                .inval_inode(probe_ino, 0, -1)
                .expect("inval_inode");
        }
        match poll_until(Duration::from_secs(300), || {
            read_first(&held) == Some(pattern)
        }) {
            Some(d) => println!("cached-data horizon {label}: {:.1}s", d.as_secs_f64()),
            None => println!("cached-data horizon {label}: >300s (never converged)"),
        }
    }
}

/// Sequential-read throughput with and without `noattrcache`, to price the
/// coherence-vs-cache trade-off gate 1b exposes.
fn gate1c(mnt: &Path, ttl: Duration) {
    println!("\n=== Gate 1c: read throughput, default vs noattrcache ===");
    const SIZE: usize = 256 * 1024 * 1024;
    for opts in [&[][..], &["noattrcache"][..]] {
        let m = mount_opts(mnt, ttl, opts, |s| {
            s.insert_file(ROOT_INO, OsStr::new("big.dat"), vec![0x5Au8; SIZE]);
        });
        let big = m.mnt.join("big.dat");
        let label = if opts.is_empty() {
            "default    "
        } else {
            "noattrcache"
        };
        for pass in ["cold", "warm"] {
            let t0 = Instant::now();
            let data = std::fs::read(&big).expect("read big");
            let dt = t0.elapsed();
            assert_eq!(data.len(), SIZE);
            println!(
                "{label} {pass}: {:.0} MB/s ({:.2}s for 256 MiB)",
                256.0 / dt.as_secs_f64(),
                dt.as_secs_f64()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Gate 2 — v1 cross-client flake replay + issue-109 churn workload
// ---------------------------------------------------------------------------

fn gate2(mnt: &Path, iters: usize, ttl: Duration) {
    println!("\n=== Gate 2: v1 cross-client flake replay ({iters} rounds, 2s deadline) ===");
    let mut shared_ino = 0;
    let m = mount_opts(mnt, ttl, &[], |s| {
        shared_ino = s.insert_file(ROOT_INO, OsStr::new("shared.dat"), vec![0u8; 1024]);
    });
    let shared = m.mnt.join("shared.dat");
    std::fs::read(&shared).expect("warm read");

    // The v1 scenario: client A creates a file and updates a shared one;
    // client B (this mount) must observe both promptly once the engine fires
    // invalidation. v1/NFS flaked ~15% because inval_inode was ignored.
    let mut flakes = 0;
    for i in 0..iters {
        let name = format!("cc_{i}.dat");
        let pattern = (i % 251 + 1) as u8;
        m.store
            .lock()
            .unwrap()
            .insert_file(ROOT_INO, OsStr::new(&name), vec![pattern; 256]);
        m.edit(shared_ino, |d| d.fill(pattern));
        m.notifier
            .inval_entry(ROOT_INO, OsStr::new(&name))
            .expect("inval_entry");
        m.notifier
            .inval_inode(shared_ino, 0, -1)
            .expect("inval_inode");
        let path = m.mnt.join(&name);
        let ok = poll_until(Duration::from_secs(2), || {
            std::fs::metadata(&path).is_ok()
                && std::fs::read(&shared)
                    .map(|d| d.first() == Some(&pattern))
                    .unwrap_or(false)
        })
        .is_some();
        if !ok {
            flakes += 1;
        }
    }
    println!(
        "cross-client visibility: {}/{iters} ok, flake rate {:.1}% (v1/NFS baseline ~15%)",
        iters - flakes,
        flakes as f64 * 100.0 / iters as f64
    );

    // Issue-109 replay: attribute churn + atomic renames through the mount.
    // On the NFS backend this class of workload could panic Apple's kext; the
    // gate is that SMB survives it with no I/O errors and a live mount.
    println!("--- churn workload (30s, 2 writers + 1 reader) ---");
    let stop = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(AtomicU64::new(0));
    let ops = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for w in 0..2u32 {
        let dir = m.mnt.join(format!("churn{w}"));
        std::fs::create_dir_all(&dir).expect("mkdir churn");
        let (stop, errors, ops) = (stop.clone(), errors.clone(), ops.clone());
        handles.push(std::thread::spawn(move || {
            let target = dir.join("t.dat");
            let tmp = dir.join("t.tmp");
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) {
                i += 1;
                let mut fail = false;
                fail |= std::fs::write(&tmp, i.to_le_bytes()).is_err();
                fail |= std::fs::rename(&tmp, &target).is_err();
                // utimes-style attribute churn
                fail |= std::process::Command::new("touch")
                    .arg("-t")
                    .arg("202601010101")
                    .arg(&target)
                    .status()
                    .map(|s| !s.success())
                    .unwrap_or(true);
                if fail {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
                ops.fetch_add(3, Ordering::Relaxed);
            }
        }));
    }
    {
        let (stop, errors, ops) = (stop.clone(), errors.clone(), ops.clone());
        let root = m.mnt.clone();
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                for w in 0..2u32 {
                    let t = root.join(format!("churn{w}/t.dat"));
                    match std::fs::metadata(&t) {
                        Ok(_) => {
                            let _ = std::fs::read(&t);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    ops.fetch_add(2, Ordering::Relaxed);
                }
            }
        }));
    }
    std::thread::sleep(Duration::from_secs(30));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    let mount_alive = std::fs::read_dir(&m.mnt).is_ok();
    println!(
        "churn: {} ops, {} errors, mount alive after: {}",
        ops.load(Ordering::Relaxed),
        errors.load(Ordering::Relaxed),
        mount_alive
    );
}

// ---------------------------------------------------------------------------
// Gate 3 — overwrite-rename atomicity
// ---------------------------------------------------------------------------

fn gate3(mnt: &Path, iters: usize, ttl: Duration) {
    println!("\n=== Gate 3: overwrite-rename atomicity ({iters} renames, 64KiB target) ===");
    const SIZE: usize = 64 * 1024;
    let m = mount_opts(mnt, ttl, &[], |s| {
        s.insert_file(ROOT_INO, OsStr::new("target.dat"), vec![0u8; SIZE]);
    });
    let target = m.mnt.join("target.dat");
    let tmp = m.mnt.join("target.tmp");

    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let (target, stop) = (target.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut reads = 0u64;
            let mut torn = 0u64;
            let mut missing = 0u64;
            let mut short = 0u64;
            let mut errors = 0u64;
            let mut examples: Vec<String> = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                reads += 1;
                match std::fs::read(&target) {
                    Ok(d) if d.len() != SIZE => {
                        short += 1;
                        if examples.len() < 5 {
                            examples.push(format!("short read: {} bytes", d.len()));
                        }
                    }
                    Ok(d) => {
                        let v = d[0];
                        if d.iter().any(|b| *b != v) {
                            torn += 1;
                            if examples.len() < 5 {
                                let other = d.iter().find(|b| **b != v).unwrap();
                                examples.push(format!("torn read: mixed {v} and {other}"));
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing += 1,
                    Err(e) => {
                        errors += 1;
                        if examples.len() < 5 {
                            examples.push(format!("io error: {e}"));
                        }
                    }
                }
            }
            (reads, torn, missing, short, errors, examples)
        })
    };

    let mut write_errs = 0u64;
    for i in 1..=iters {
        let pattern = (i % 251 + 1) as u8;
        let res = (|| -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&vec![pattern; SIZE])?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &target)
        })();
        if res.is_err() {
            write_errs += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let (reads, torn, missing, short, errors, examples) = reader.join().unwrap();
    println!(
        "reads={reads} torn={torn} missing(ENOENT)={missing} short={short} io-errors={errors} write-errors={write_errs}"
    );
    for e in &examples {
        println!("  example anomaly: {e}");
    }

    let s = m.store.lock().unwrap();
    println!(
        "fs-side ops: {} renames, {} creates, {} unlinks, {} setattrs, {} rename-name fallbacks",
        s.ops.renames.len(),
        s.ops.creates,
        s.ops.unlinks,
        s.ops.setattrs,
        s.ops.rename_name_fallbacks
    );
    if let Some(sample) = s.ops.renames.first() {
        println!("first rename callback: {sample}");
    }
    // A rename-name fallback hit means the harness had to guess the source of
    // a rename — a resurrected truncation bug must fail the gate, not pass
    // silently under the guessed name.
    let verdict_ok = torn == 0
        && missing == 0
        && short == 0
        && errors == 0
        && write_errs == 0
        && s.ops.rename_name_fallbacks == 0;
    println!(
        "atomicity verdict: {}",
        if verdict_ok { "PASS" } else { "FAIL" }
    );
}

// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("all");
    let flag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let iters: usize = flag("--iters").and_then(|v| v.parse().ok()).unwrap_or(0);
    let ttl = Duration::from_secs(flag("--ttl").and_then(|v| v.parse().ok()).unwrap_or(3600));
    let mnt = flag("--mnt")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("hwgates-mnt"));

    println!(
        "FUSE-T hardware gates (issue #644) — mount at {}",
        mnt.display()
    );
    match cmd {
        "gate1" => gate1(&mnt, if iters == 0 { 30 } else { iters }, ttl),
        "gate1b" => gate1b(&mnt, ttl),
        "gate1c" => gate1c(&mnt, ttl),
        "gate2" => gate2(&mnt, if iters == 0 { 100 } else { iters }, ttl),
        "gate3" => gate3(&mnt, if iters == 0 { 300 } else { iters }, ttl),
        // Debug aid: mount with a probe file and hold the mount open.
        "serve" => {
            let m = mount_opts(&mnt, ttl, &[], |s| {
                s.insert_file(ROOT_INO, OsStr::new("probe.dat"), vec![7u8; 4096]);
            });
            println!("serving {} — ctrl-c to stop", m.mnt.display());
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
        "all" => {
            gate1(&mnt, 30, ttl);
            gate2(&mnt, 100, ttl);
            gate3(&mnt, 300, ttl);
        }
        other => {
            eprintln!("unknown gate '{other}'; use gate1|gate2|gate3|all");
            std::process::exit(2);
        }
    }
}
