//! The platform-neutral vfs operation core: one implementation of every
//! filesystem operation, over the engine facade and nothing else
//! (blueprint/desktop.md "The FS core and host adapters").
//!
//! It is a projection, not a second brain. Reads render the facade's snapshot
//! (with the pending-op overlay already applied) and never wait on the
//! network; mutations become facade intent ops. No keys, no publish
//! machinery, and no freshness policy of its own — the staleness threshold and
//! the focus window live below the facade, and the projection only reports
//! which node an operation had in view.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use cipherbox_core::codec::RedactedText;
use cipherbox_engine::seams::SeamTypes;
use cipherbox_engine::{
    Command, Engine, EngineView, Event, NodeAttrs, NodeId, NodeKind, SessionStatus, StatFs,
    StreamHandle, WriteHandle, WriteTarget,
};

use zeroize::Zeroizing;

use crate::adapter::{CacheTtls, HostAdapter, Invalidation};
use crate::cache::{CacheBudget, ChunkCache, grow_wiping};
use crate::error::VfsError;
use crate::handle::{Access, FIRST_HANDLE, HandleId, HandleTable, OpenFile};
use crate::inode::{InodeTable, ROOT_INO};
use crate::name::{is_emittable, is_platform_junk, validate_name};
use crate::spill::{SpillArea, SpillFile};

/// A node as the kernel sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attributes {
    /// The session's inode number for the node.
    pub ino: u64,
    /// The engine's stable node id.
    pub node: NodeId,
    /// File or folder.
    pub kind: NodeKind,
    /// Plaintext size in bytes, `None` until the content plane projects one.
    /// Never collapsed to zero: a kernel that believes `st_size == 0` stops
    /// reading at byte zero, and `cp` writes an empty copy of a real file.
    pub size: Option<u64>,
    /// Modification time in Unix millis, once projected.
    pub mtime_millis: Option<u64>,
}

/// One entry in a directory listing.
///
/// Carries the attributes an enumeration has to report, not just the name: a
/// FUSE `readdir` needs the name and kind alone, but a WinFsp one answers with
/// a whole `FSP_FSCTL_DIR_INFO`, and re-`getattr`-ing every child to fill it
/// would put a whole directory into the engine's focus window. Both come out of
/// the one render the listing already made.
#[derive(Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The session's inode number for the child.
    pub ino: u64,
    /// The child's name, as entered.
    pub name: String,
    /// File or folder.
    pub kind: NodeKind,
    /// Plaintext size in bytes, `None` until the content plane projects one —
    /// the same provisional number [`Attributes::size`] carries, on the same
    /// terms.
    pub size: Option<u64>,
    /// Modification time in Unix millis, once projected.
    pub mtime_millis: Option<u64>,
}

impl fmt::Debug for DirEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirEntry")
            .field("ino", &self.ino)
            .field("name", &RedactedText::of(&self.name))
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("mtime_millis", &self.mtime_millis)
            .finish()
    }
}

/// One writable handle's uncommitted content: the sealed spill its writes
/// landed in, and the file they leave behind.
struct Pending {
    /// Minted on the first write — a handle that only creates or truncates
    /// spills no bytes and pays for no file.
    spill: Option<SpillFile>,
    /// Plaintext length of the version release will journal.
    len: u64,
    /// How far into the file the base version may still contribute bytes.
    /// Clamped by every truncate: bytes a shrink removed must read as the zeros
    /// of a hole if the file grows again, never as the version's own plaintext.
    base_len: u64,
    /// Whether an `updateContent` op is still owed for what the spill holds.
    dirty: bool,
}

impl Pending {
    /// A handle's write state over a file of `len` bytes, all of which the base
    /// version still holds.
    fn over(len: u64) -> Self {
        Self {
            spill: None,
            len,
            base_len: len,
            dirty: false,
        }
    }
}

/// The attributes this mount last handed the kernel for one node — the state
/// the kernel's cache holds, and so the only state a repaint has to correct.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Served {
    size: Option<u64>,
    mtime_millis: Option<u64>,
    content_version: Option<u64>,
}

impl Served {
    /// `meta` as the kernel sees it, at the size the pending-op overlay
    /// projects.
    fn of(meta: &NodeAttrs, size: Option<u64>) -> Self {
        Self {
            size,
            mtime_millis: meta.mtime,
            content_version: meta.content_version,
        }
    }
}

/// How a block-fetching path uses the chunk cache: a path that will come back
/// to these bytes retains and promotes them; a one-shot pass reads through,
/// leaving neither the budget nor the recency order spent on blocks it will
/// never ask for again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retain {
    Hot,
    Scan,
}

/// A bounded map that evicts its least-recently-written entry — the ceiling
/// every kernel-cache shadow map is kept under.
///
/// What these maps hold is sized from outside this device: a peer sharing a
/// scope decides how many nodes and how long a name, and Finder or Spotlight
/// walks a mount unprompted.
///
/// Writing is the access: every entry is rewritten by the operation that hands
/// the kernel the state it records, so recency of write is recency of use.
///
/// Eviction is reported rather than silent, and the caller must correct the
/// kernel for what it drops. These maps are the only thing a repaint measures
/// a change against, so an entry dropped quietly is kernel state nothing would
/// ever correct again — and uninvalidated cached data never revalidates on a
/// client that ignores reply lifetimes (blueprint/desktop.md "Freshness").
struct Shadow<V> {
    limit: usize,
    entries: HashMap<NodeId, (u64, V)>,
    recency: BTreeMap<u64, NodeId>,
    next_tick: u64,
}

impl<V> Shadow<V> {
    /// A map holding at most `limit` entries — at least one, so a ceiling the
    /// map could never hold anything under is not representable.
    fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            entries: HashMap::new(),
            recency: BTreeMap::new(),
            next_tick: 0,
        }
    }

    /// Take `node`'s slot, reporting everything that displaced.
    fn insert(&mut self, node: NodeId, value: V) -> Displaced<V> {
        let tick = self.next_tick;
        self.next_tick += 1;
        let replaced = self
            .entries
            .insert(node, (tick, value))
            .map(|(used, held)| {
                self.recency.remove(&used);
                held
            });
        self.recency.insert(tick, node);
        let mut evicted = None;
        // One insert adds at most one entry, so at most one is ever displaced.
        if self.entries.len() > self.limit
            && let Some((_, node)) = self.recency.pop_first()
            && let Some((_, held)) = self.entries.remove(&node)
        {
            evicted = Some((node, held));
        }
        Displaced { replaced, evicted }
    }

    fn remove(&mut self, node: NodeId) {
        if let Some((used, _)) = self.entries.remove(&node) {
            self.recency.remove(&used);
        }
    }

    /// Every entry, in no particular order and without renewing any of them —
    /// a repaint is the mount reading its own bookkeeping, not a kernel access.
    fn iter(&self) -> impl Iterator<Item = (NodeId, &V)> {
        self.entries.iter().map(|(node, (_, value))| (*node, value))
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.recency.clear();
    }
}

/// What an [`insert`](Shadow::insert) displaced: the value the same node held,
/// and the entry the ceiling evicted to make room for this one.
struct Displaced<V> {
    replaced: Option<V>,
    evicted: Option<(NodeId, V)>,
}

/// A directory walk's token, minted per `opendir` and handed to the kernel as
/// its directory file handle. Distinct from [`HandleId`] because the two name
/// different things and the kernel keeps their number spaces apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DirHandleId(pub u64);

/// One open directory: the node it walks, and the listing it pages through once
/// the walk has started.
struct Walk {
    dir: NodeId,
    listing: Vec<DirEntry>,
}

/// The operation core for one mount session: the engine it projects, the host
/// adapter it pushes invalidation to, and the session's inode and handle maps.
pub struct OperationCore<T: SeamTypes, A: HostAdapter> {
    engine: Engine<T>,
    adapter: A,
    inodes: InodeTable,
    handles: HandleTable,
    cache: ChunkCache,
    spill: SpillArea,
    /// Per writable handle, the writes it has taken but not yet journaled.
    pending: HashMap<HandleId, Pending>,
    /// Per node, the `contentCid` of the newest version this mount has bound a
    /// read stream to. The kernel's page cache for that node's inode can only
    /// hold bytes this mount served, so a bind at a different version is
    /// exactly the condition under which those pages went stale.
    streamed: HashMap<NodeId, Vec<u8>>,
    /// Per node, the attributes this mount last served. Only nodes the kernel
    /// actually asked about are here, and a repaint drops each one it
    /// invalidates — the map tracks what the kernel is believed to hold, not
    /// the tree.
    served: Shadow<Served>,
    /// Per directory, the entries this mount last listed, on the same terms.
    listed: Shadow<BTreeMap<String, NodeId>>,
    /// Per open directory, the walk it is paging through — see
    /// [`readdir`](Self::readdir). An entry lives from `opendir` to
    /// `releasedir`, so the kernel's own open-directory count bounds it.
    walks: HashMap<DirHandleId, Walk>,
    /// The next [`DirHandleId`]: monotonic and never reused, so a released
    /// handle can never address a later walk.
    next_walk: u64,
    /// The node the last read-path operation found past the staleness
    /// threshold, if any.
    refresh_hint: Option<NodeId>,
}

impl<T: SeamTypes, A: HostAdapter> OperationCore<T, A> {
    /// Mount `engine` behind `adapter`, holding at most `cache`'s worth of
    /// plaintext and spilling writes into `spill`. The engine must already be
    /// started.
    pub fn new(engine: Engine<T>, adapter: A, cache: CacheBudget, spill: SpillArea) -> Self {
        Self {
            engine,
            adapter,
            inodes: InodeTable::new(),
            handles: HandleTable::new(),
            cache: ChunkCache::new(cache),
            spill,
            pending: HashMap::new(),
            streamed: HashMap::new(),
            served: Shadow::new(cache.shadowed_nodes()),
            listed: Shadow::new(cache.shadowed_directories()),
            walks: HashMap::new(),
            next_walk: FIRST_HANDLE,
            refresh_hint: None,
        }
    }

    /// Plaintext this mount is holding right now — never above the budget it
    /// was mounted with.
    pub fn cached_plaintext_bytes(&self) -> usize {
        self.cache.retained_bytes()
    }

    /// How many directories the kernel has open on this mount — back to zero
    /// once it has released each one.
    pub fn open_directories(&self) -> usize {
        self.walks.len()
    }

    /// The engine this mount projects. A session runs exactly one brain, so a
    /// host that also serves reads of its own drives it through here rather
    /// than standing up a second engine over the same account.
    pub fn engine_mut(&mut self) -> &mut Engine<T> {
        &mut self.engine
    }

    /// The kernel cache lifetimes this mount's adapter earned.
    pub fn cache_ttls(&self) -> CacheTtls {
        CacheTtls::for_host(&self.adapter.capabilities(), self.engine.profile())
    }

    /// The node the most recent read-path operation found past the staleness
    /// threshold, if any — the refresh hint that operation's TTL check fired.
    /// The engine's next tick is what acts on it; a host surfaces it as the
    /// "checking for updates" state.
    pub fn last_refresh_hint(&self) -> Option<NodeId> {
        self.refresh_hint
    }

    /// Fold one engine event into the kernel's caches.
    ///
    /// A background reconcile lands a new snapshot without any operation of the
    /// kernel's having asked for one, so nothing on the callback path would ever
    /// tell it that the entries and pages it holds stopped being the truth — the
    /// event stream is what does (blueprint/desktop.md "Freshness").
    pub async fn absorb_event(&mut self, event: &Event) -> Result<(), VfsError> {
        if *event != Event::SnapshotUpdated || (self.served.is_empty() && self.listed.is_empty()) {
            return Ok(());
        }
        self.repaint().await
    }

    /// Invalidate everything the new render moved out from under what this
    /// mount last served, and take the new state as the baseline.
    ///
    /// Replaced rather than dropped: an invalidation does not oblige the kernel
    /// to come back — a `read` on an open fd is answered from its page cache —
    /// so a mount that forgot the node it just invalidated would measure the
    /// *next* change against nothing and push nothing for it.
    async fn repaint(&mut self) -> Result<(), VfsError> {
        let view = self.render().await?;

        let mut moved = Vec::new();
        for (node, served) in self.served.iter() {
            let Some(meta) = view.attrs(node) else {
                continue;
            };
            let fresh = Served::of(&meta, self.pending_len(node).or(meta.size));
            if fresh != *served {
                moved.push((node, fresh));
            }
        }
        for (node, fresh) in moved {
            let content_moved = self
                .track_served(node, fresh.clone())
                .is_some_and(|last| last.content_version != fresh.content_version);
            let ino = self.inodes.ino_for(node);
            if content_moved {
                self.content_changed(ino);
            } else {
                self.adapter.invalidate(Invalidation::Attributes { ino });
            }
        }

        let mut relisted = Vec::new();
        for (dir, listed) in self.listed.iter() {
            let fresh = listing_of(&emittable_children(&view, dir));
            if fresh != *listed {
                relisted.push((dir, rebound_names(listed, &fresh), fresh));
            }
        }
        for (dir, names, fresh) in relisted {
            self.track_listed(dir, fresh);
            let parent = self.inodes.ino_for(dir);
            for name in names {
                self.entry_changed(parent, &name);
            }
        }
        Ok(())
    }

    /// The **FUSE-op TTL check**: put the node this operation has in view into
    /// the engine's focus window, and record the hint a node past the staleness
    /// threshold fires (blueprint/desktop.md "Freshness"). The thresholds and
    /// the window are the engine's; this only reports which node the operation
    /// was about, and answers from the render it already has (the never-block
    /// law).
    fn ttl_check(&mut self, node: Option<NodeId>) {
        let stale = self.engine.note_focus_access(node);
        self.refresh_hint = node.filter(|_| stale);
    }

    /// Resolve a name under a directory.
    pub async fn lookup(&mut self, parent: u64, name: &str) -> Result<Attributes, VfsError> {
        if !is_emittable(name) {
            return Err(VfsError::NotFound);
        }
        let view = self.render().await?;
        let parent_node = self.directory(&view, parent)?;
        self.ttl_check(Some(parent_node));
        let meta = self
            .resolve(&view, parent_node, name)
            .ok_or(VfsError::NotFound)?;
        // A child ref mirrors no size, so only the child's own record projects
        // one. A host that decides a read from these attributes never opens a
        // file the reply reports as empty, so the length has to reach it with no
        // open of its own.
        let attrs = self.entry_attributes(&meta);
        if attrs.kind == NodeKind::File && attrs.size.is_none() {
            self.engine.note_focus_file(meta.id);
        }
        Ok(attrs)
    }

    /// Find `name` under `parent` as the host presents names — the one rule
    /// every operation that names an existing node resolves through.
    ///
    /// Which engine rule the host presents — see
    /// [`HostCapabilities::case_insensitive_lookup`]. Collisions are not on
    /// this axis: `create`, `mkdir`, and a rename's destination stay with the
    /// strict comparator.
    ///
    /// Junk is the one class an exact host still resolves by folding, because
    /// the mount hides it: a peer's `.Ds_StOrE` never appears in a listing, so
    /// the canonical spelling is the only one a user can type, and without the
    /// fold it could never be unlinked ([`is_platform_junk`]).
    fn resolve(&self, view: &EngineView, parent: NodeId, name: &str) -> Option<NodeAttrs> {
        if self.adapter.capabilities().case_insensitive_lookup {
            return view.lookup(parent, name);
        }
        view.lookup_exact(parent, name)
            .or_else(|| is_platform_junk(name).then(|| view.lookup(parent, name))?)
    }

    /// Read one node's attributes.
    pub async fn getattr(&mut self, ino: u64) -> Result<Attributes, VfsError> {
        let view = self.render().await?;
        let node = self.node_of(ino)?;
        let meta = view.attrs(node).ok_or(VfsError::NotFound)?;
        // A file goes in as itself: its size and mtime live in its own record,
        // and its parent's listing mirrors neither, so putting the parent in
        // view would refresh everything about it except what `getattr` returns.
        self.ttl_check(Some(node));
        Ok(self.attributes(&meta))
    }

    /// Open a directory for walking, minting the handle the kernel carries on
    /// every [`readdir`](Self::readdir) and gives back at
    /// [`releasedir`](Self::releasedir).
    pub async fn opendir(&mut self, ino: u64) -> Result<DirHandleId, VfsError> {
        let view = self.render().await?;
        let dir = self.directory(&view, ino)?;
        let walk = DirHandleId(self.next_walk);
        self.next_walk += 1;
        self.walks.insert(
            walk,
            Walk {
                dir,
                listing: Vec::new(),
            },
        );
        Ok(walk)
    }

    /// One page of a directory walk: the children from `cursor` onward, in the
    /// engine's deterministic order, with platform junk and names no kernel
    /// could carry hidden — both classes arrive from other clients, which
    /// validate nothing. `.` and `..` are the adapter's to synthesize, along
    /// with the offset cookies it hands the kernel.
    ///
    /// A walk renders its directory once, at `cursor` zero, and answers every
    /// continuation from that listing. The cursor the kernel resumes at only
    /// means anything against the listing that produced it: a re-render between
    /// two pages would shift positions under it, and the walk would skip or
    /// duplicate an entry that never moved. `cursor` zero is also `rewinddir`,
    /// which is why it renders again rather than replaying.
    pub async fn readdir(
        &mut self,
        walk: DirHandleId,
        cursor: usize,
    ) -> Result<&[DirEntry], VfsError> {
        let dir = self.walks.get(&walk).ok_or(VfsError::BadHandle)?.dir;
        self.ttl_check(Some(dir));
        if cursor > 0 {
            return Ok(self.walks[&walk].listing.get(cursor..).unwrap_or_default());
        }
        let view = self.render().await?;
        let children = emittable_children(&view, dir);
        self.track_listed(dir, listing_of(&children));
        let listing: Vec<DirEntry> = children
            .into_iter()
            .map(|child| DirEntry {
                ino: self.inodes.ino_for(child.id),
                // A child a handle is still writing is as long as that handle
                // has made it, exactly as `attributes` reports it — a listing
                // that disagreed with the `getattr` beside it would show a
                // stale length for a file this mount is holding open.
                size: self.pending_len(child.id).or(child.size),
                mtime_millis: child.mtime,
                name: child.name,
                kind: child.kind,
            })
            .collect();
        let held = self.walks.get_mut(&walk).ok_or(VfsError::BadHandle)?;
        held.listing = listing;
        Ok(&held.listing)
    }

    /// Close a directory the kernel has finished walking, dropping the listing
    /// it was paging through.
    pub fn releasedir(&mut self, walk: DirHandleId) {
        self.walks.remove(&walk);
    }

    /// Give back `count` of the kernel's references to `ino`, dropping
    /// everything this mount held on that inode's behalf once the last one is
    /// gone — the FUSE FORGET contract. Nothing the kernel no longer addresses
    /// needs correcting, and the shadow maps grow with what it asked about.
    pub fn forget(&mut self, ino: u64, count: u64) {
        let Some(node) = self.inodes.forget(ino, count) else {
            return;
        };
        self.served.remove(node);
        self.listed.remove(node);
        self.streamed.remove(&node);
    }

    /// Create an empty file and open a handle on it.
    pub async fn create(
        &mut self,
        parent: u64,
        name: &str,
        access: Access,
    ) -> Result<(Attributes, HandleId), VfsError> {
        let attrs = self.make(parent, name, NodeKind::File).await?;
        let handle = self.handles.open(attrs.node, access);
        if access.writable() {
            self.pending.insert(handle, Pending::over(0));
        }
        Ok((attrs, handle))
    }

    /// Create a directory.
    pub async fn mkdir(&mut self, parent: u64, name: &str) -> Result<Attributes, VfsError> {
        self.make(parent, name, NodeKind::Folder).await
    }

    /// Remove a file.
    pub async fn unlink(&mut self, parent: u64, name: &str) -> Result<(), VfsError> {
        self.remove(parent, name, NodeKind::File).await
    }

    /// Remove an empty directory.
    pub async fn rmdir(&mut self, parent: u64, name: &str) -> Result<(), VfsError> {
        self.remove(parent, name, NodeKind::Folder).await
    }

    /// Whether [`unlink`](Self::unlink) or [`rmdir`](Self::rmdir) would be
    /// allowed to make `ino` vanish, without making it vanish.
    ///
    /// For a host that decides a delete's disposition one call before it
    /// carries the delete out: the same predicate the removal itself gates on,
    /// so an approved disposition cannot fail at a step that has no status to
    /// report.
    pub async fn removable(&mut self, ino: u64, kind: NodeKind) -> Result<(), VfsError> {
        let view = self.render().await?;
        let node = self.node_of(ino)?;
        let meta = view.attrs(node).ok_or(VfsError::NotFound)?;
        removable(&view, &meta, kind)
    }

    /// Move and/or rename a node, replacing an existing destination the way
    /// POSIX rename does.
    pub async fn rename(
        &mut self,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
    ) -> Result<(), VfsError> {
        validate_name(new_name)?;
        let view = self.render().await?;
        let parent_node = self.directory(&view, parent)?;
        let new_parent_node = self.directory(&view, new_parent)?;
        let source = self
            .resolve(&view, parent_node, name)
            .ok_or(VfsError::NotFound)?;
        if contains(&view, source.id, new_parent_node) {
            return Err(VfsError::Invalid);
        }
        // A case- or normalization-only respell folds onto the source itself
        // under the engine's strict comparator; it is a rename, not a replace.
        let replaced = view
            .lookup(new_parent_node, new_name)
            .filter(|dest| dest.id != source.id);
        if let Some(dest) = &replaced {
            removable(&view, dest, source.kind)?;
            // The replaced node's own unlink rides the move op; only the hidden
            // junk it may still hold needs deletes of its own.
            self.delete_descendants(&view, dest.id).await?;
        }
        // POSIX renaming a node onto itself changes nothing, so it journals
        // nothing.
        if replaced.is_none() && new_parent_node == parent_node && source.name == new_name {
            return Ok(());
        }
        self.command(Command::Move {
            node: source.id,
            new_parent: new_parent_node,
            new_name: new_name.to_owned(),
            replacing: replaced.as_ref().map(|dest| dest.id),
        })
        .await?;

        let ino = self.inodes.ino_for(source.id);
        self.entry_refolded(parent, &source.name, name);
        // A replaced destination was itself resolved by the folding
        // comparator, so the kernel may hold it under a spelling that is
        // neither the stored source name nor the one this rename installs.
        let displaced = replaced.map(|dest| dest.name);
        self.entry_refolded(
            new_parent,
            displaced.as_deref().unwrap_or(new_name),
            new_name,
        );
        self.adapter.invalidate(Invalidation::Attributes { ino });
        Ok(())
    }

    /// Open a file handle.
    pub async fn open(&mut self, ino: u64, access: Access) -> Result<HandleId, VfsError> {
        let view = self.render().await?;
        let node = self.node_of(ino)?;
        let meta = view.attrs(node).ok_or(VfsError::NotFound)?;
        if meta.kind != NodeKind::File {
            return Err(VfsError::IsADirectory);
        }
        Ok(self.handles.open(node, access))
    }

    /// What an open handle addresses.
    pub fn handle(&self, handle: HandleId) -> Result<OpenFile, VfsError> {
        self.handles.get(handle).ok_or(VfsError::BadHandle)
    }

    /// Read up to `size` bytes at `offset`.
    ///
    /// The engine would serve any window in one call; the loop exists to frame
    /// the window into cache-aligned blocks, so a cached block answers from
    /// memory and a missed one costs exactly the sealed chunks it covers — the
    /// first byte never waits for the last (blueprint/desktop.md "Reads,
    /// writes, and the never-block law"). A short answer is end-of-file, the
    /// way `pread` is.
    ///
    /// The caller takes terminal ownership of the plaintext it hands back; the
    /// window it was assembled in is wiped, including on the failure path.
    pub async fn read(
        &mut self,
        handle: HandleId,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, VfsError> {
        let open = self.handles.get(handle).ok_or(VfsError::BadHandle)?;
        if !matches!(open.access, Access::Read | Access::ReadWrite) {
            return Err(VfsError::BadHandle);
        }
        // A handle holding writes reads what it wrote, not what the network
        // still serves — the op carrying those bytes may not even be journaled.
        if self.pending.contains_key(&handle) {
            return self.read_pending(handle, offset, size).await;
        }
        let stream = self.stream_for(handle).await?;
        let block_bytes = self.cache.block_bytes();
        let end = offset.saturating_add(u64::from(size));
        let mut out = Zeroizing::new(Vec::new());
        let mut cursor = offset;
        while cursor < end {
            let index = cursor / block_bytes;
            let within = (cursor - index * block_bytes) as usize;
            let want = (end - cursor) as usize;
            let (taken, whole) = match self.cache.get((stream, index)) {
                Some(block) => (
                    take_from(&mut out, block, within, want),
                    block.len() as u64 == block_bytes,
                ),
                None => {
                    let block = self
                        .engine
                        .read_stream(stream, index * block_bytes, block_bytes)
                        .await?;
                    let taken = take_from(&mut out, &block, within, want);
                    let whole = block.len() as u64 == block_bytes;
                    self.cache.insert((stream, index), block);
                    (taken, whole)
                }
            };
            // A block short of the framing width is the file's last one, so the
            // window ends here however much of it the caller asked for.
            if taken == 0 || !whole {
                break;
            }
            cursor += taken as u64;
        }
        Ok(core::mem::take(&mut *out))
    }

    /// Land `data` at `offset` in the handle's sealed spill file, reporting how
    /// many bytes it took.
    ///
    /// Nothing crosses the facade here: the bytes sit under a per-handle key
    /// this process holds only in memory until [`flush`](Self::flush) or
    /// [`release`](Self::release) turns them into one `updateContent` op
    /// (blueprint/desktop.md "Reads, writes, and the never-block law").
    pub async fn write(
        &mut self,
        handle: HandleId,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, VfsError> {
        let open = self.handles.get(handle).ok_or(VfsError::BadHandle)?;
        if !open.access.writable() {
            return Err(VfsError::BadHandle);
        }
        let took = u32::try_from(data.len()).map_err(|_| VfsError::Invalid)?;
        // POSIX: a zero-length write changes nothing, not even the length.
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(VfsError::Invalid)?;
        self.begin_pending(handle, open.node).await?;

        let block_bytes = self.cache.block_bytes();
        let mut cursor = offset;
        let mut rest = data;
        while !rest.is_empty() {
            let index = cursor / block_bytes;
            let within = (cursor - index * block_bytes) as usize;
            let take = (block_bytes as usize - within).min(rest.len());
            // A block the write replaces whole owes the base version nothing.
            if within == 0 && take as u64 == block_bytes {
                self.spill_mut(handle)?.put(index, &rest[..take])?;
            } else {
                let mut block = self.version_block(handle, index, Retain::Scan).await?;
                block[within..within + take].copy_from_slice(&rest[..take]);
                self.spill_mut(handle)?.put(index, &block)?;
            }
            cursor += take as u64;
            rest = &rest[take..];
        }

        let pending = self.pending.get_mut(&handle).ok_or(VfsError::BadHandle)?;
        pending.len = pending.len.max(end);
        pending.dirty = true;
        Ok(took)
    }

    /// The length an append on `handle` lands at.
    ///
    /// Not [`getattr`](Self::getattr)'s size, which is provisional until the
    /// content plane projects one: a host that took an unprojected `None` for
    /// the end of the file would append at offset zero and overwrite its head,
    /// silently, because the length the version publishes would still be right.
    /// Resolving the head is what projects the length, and this is the call
    /// that forces it.
    pub async fn append_offset(&mut self, handle: HandleId) -> Result<u64, VfsError> {
        let open = self.handles.get(handle).ok_or(VfsError::BadHandle)?;
        if !open.access.writable() {
            return Err(VfsError::BadHandle);
        }
        self.begin_pending(handle, open.node).await?;
        Ok(self.pending.get(&handle).ok_or(VfsError::BadHandle)?.len)
    }

    /// Set a file's length.
    ///
    /// On an open writable handle this is a spill-file operation: the new
    /// length rides into the one `updateContent` op that handle's release
    /// journals, which is also how an adapter carries `O_TRUNC`. With no handle
    /// it becomes its own op, so a bare `truncate(2)` is never silently lost.
    pub async fn truncate(
        &mut self,
        ino: u64,
        size: u64,
        handle: Option<HandleId>,
    ) -> Result<(), VfsError> {
        let view = self.render().await?;
        let node = self.node_of(ino)?;
        if view.attrs(node).ok_or(VfsError::NotFound)?.kind != NodeKind::File {
            return Err(VfsError::IsADirectory);
        }
        let Some(handle) = handle else {
            let handle = self.handles.open(node, Access::Write);
            let truncated = self.truncate_handle(handle, size).await;
            let released = self.release(handle).await;
            return truncated.and(released);
        };
        if self.handle(handle)?.node != node {
            return Err(VfsError::BadHandle);
        }
        self.truncate_handle(handle, size).await
    }

    /// Journal what a handle has written as one `updateContent` op.
    ///
    /// The kernel is acked only once that op is durable in the staging store,
    /// so a failing queue refuses the write instead of losing it — the v1 INV-1
    /// no-false-ack discipline (blueprint/desktop.md "release"). `close(2)`
    /// returns what this returns.
    pub async fn flush(&mut self, handle: HandleId) -> Result<(), VfsError> {
        self.commit(handle).await
    }

    /// `fsync` means what [`flush`](Self::flush) means here: one op carries the
    /// whole file, and the durable op queue is the mount's only durability
    /// layer.
    pub async fn fsync(&mut self, handle: HandleId) -> Result<(), VfsError> {
        self.commit(handle).await
    }

    /// Close a file handle: journal anything it still owes, then release the
    /// stream it pinned, the plaintext that stream cached, and its spill.
    pub async fn release(&mut self, handle: HandleId) -> Result<(), VfsError> {
        let committed = self.commit(handle).await;
        let open = self.handles.close(handle).ok_or(VfsError::BadHandle)?;
        self.pending.remove(&handle);
        self.release_stream(open.stream);
        committed
    }

    /// Tear the mount down: every pinned stream released and every cached
    /// plaintext block zeroized. Writes a handle never flushed die with their
    /// spill — unopenable ciphertext and no half-formed op.
    pub fn unmount(&mut self) {
        for open in self.handles.drain() {
            self.release_stream(open.stream);
        }
        self.pending.clear();
        self.cache.clear();
        self.streamed.clear();
        self.served.clear();
        self.listed.clear();
        self.walks.clear();
        self.refresh_hint = None;
    }

    /// Give `handle` a write state if it has none, sized to the file it is
    /// about to modify.
    async fn begin_pending(&mut self, handle: HandleId, node: NodeId) -> Result<(), VfsError> {
        if self.pending.contains_key(&handle) {
            return Ok(());
        }
        self.repin_stream(handle, node).await?;
        let len = self.base_len(handle, node).await?;
        self.pending.insert(handle, Pending::over(len));
        Ok(())
    }

    /// Re-bind a handle whose pinned stream is not the version the rendered
    /// length describes ([`Engine::rendered_version_cid`]) — a stream is bound
    /// once and never re-opened, so a version the queue staged or another device
    /// published moves the length out from under it.
    ///
    /// Re-opening is what pairs them again: it resolves the newer head, or
    /// refuses while the queue still owes the version the length came from —
    /// availability, so the next drain admits the write.
    async fn repin_stream(&mut self, handle: HandleId, node: NodeId) -> Result<(), VfsError> {
        let Some(pinned) = self.handles.get(handle).ok_or(VfsError::BadHandle)?.stream else {
            return Ok(());
        };
        let Some(rendered) = self.engine.rendered_version_cid(node).await? else {
            return Ok(());
        };
        if self.engine.stream_version_cid(pinned) == Some(rendered) {
            return Ok(());
        }
        self.handles.detach_stream(handle);
        self.release_stream(Some(pinned));
        self.stream_for(handle).await?;
        Ok(())
    }

    /// The plaintext length of the version a handle's writes start from.
    ///
    /// An unprojected size is unknown, never zero: resolving the head is what
    /// projects it, and reading it as zero would drop the file's untouched tail
    /// on the first partial write.
    async fn base_len(&mut self, handle: HandleId, node: NodeId) -> Result<u64, VfsError> {
        if let Some(size) = self.render().await?.attrs(node).and_then(|meta| meta.size) {
            return Ok(size);
        }
        self.stream_for(handle).await?;
        self.render()
            .await?
            .attrs(node)
            .and_then(|meta| meta.size)
            .ok_or_else(|| VfsError::Unavailable {
                message: "content size is not projected".to_owned(),
            })
    }

    async fn truncate_handle(&mut self, handle: HandleId, size: u64) -> Result<(), VfsError> {
        let open = self.handles.get(handle).ok_or(VfsError::BadHandle)?;
        if !open.access.writable() {
            return Err(VfsError::BadHandle);
        }
        if size == 0 {
            // Truncating everything away resolves nothing: no byte of the
            // version being replaced can survive it.
            self.pending
                .entry(handle)
                .or_insert_with(|| Pending::over(0));
        } else {
            self.begin_pending(handle, open.node).await?;
        }
        let pending = self.pending.get_mut(&handle).ok_or(VfsError::BadHandle)?;
        if let Some(spill) = pending.spill.as_mut() {
            spill.truncate(size)?;
        }
        pending.len = size;
        pending.base_len = pending.base_len.min(size);
        pending.dirty = true;
        Ok(())
    }

    /// Turn what a handle holds into exactly one `updateContent` op. A handle
    /// that owes nothing journals nothing.
    async fn commit(&mut self, handle: HandleId) -> Result<(), VfsError> {
        let open = self.handles.get(handle).ok_or(VfsError::BadHandle)?;
        let Some(pending) = self.pending.get(&handle) else {
            return Ok(());
        };
        if !pending.dirty {
            return Ok(());
        }
        let len = pending.len;
        let write = self
            .engine
            .begin_write(
                WriteTarget::Version {
                    node: open.node,
                    expected_version: None,
                },
                len,
            )
            .await?;
        if let Err(error) = self.push_version(handle, write, len).await {
            self.engine.abort_write(write).await;
            return Err(error);
        }
        self.engine.commit_write(write).await?;
        if let Some(pending) = self.pending.get_mut(&handle) {
            pending.dirty = false;
        }
        let ino = self.inodes.ino_for(open.node);
        // Nothing re-binds this inode, so the pages this commit replaced would
        // stay live.
        self.content_changed(ino);
        Ok(())
    }

    /// Feed the whole version through the open write handle, one block at a
    /// time, so peak plaintext is one block however large the file.
    async fn push_version(
        &mut self,
        handle: HandleId,
        write: WriteHandle,
        len: u64,
    ) -> Result<(), VfsError> {
        let block_bytes = self.cache.block_bytes();
        let mut offset = 0;
        while offset < len {
            let index = offset / block_bytes;
            let take = block_bytes.min(len - offset) as usize;
            let block = self.version_block(handle, index, Retain::Scan).await?;
            self.engine.push_chunk(write, &block[..take]).await?;
            offset += take as u64;
        }
        Ok(())
    }

    /// Read a range of the file a handle's writes are building.
    async fn read_pending(
        &mut self,
        handle: HandleId,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, VfsError> {
        let len = self.pending.get(&handle).ok_or(VfsError::BadHandle)?.len;
        let block_bytes = self.cache.block_bytes();
        let end = offset.saturating_add(u64::from(size)).min(len);
        let mut out = Zeroizing::new(Vec::new());
        let mut cursor = offset;
        while cursor < end {
            let index = cursor / block_bytes;
            let within = (cursor - index * block_bytes) as usize;
            let want = (end - cursor) as usize;
            let block = self.version_block(handle, index, Retain::Hot).await?;
            cursor += take_from(&mut out, &block, within, want) as u64;
        }
        Ok(core::mem::take(&mut *out))
    }

    /// Block `index` of the version a handle's writes are building: its spill
    /// block if it took one, else the base version's bytes, else the zeros a
    /// hole reads as. Always a whole block wide.
    ///
    /// The base block is cached whole and clamped at use: the truncate floor is
    /// per-handle `Pending` state, not a property of the stream every handle on
    /// the file shares.
    async fn version_block(
        &mut self,
        handle: HandleId,
        index: u64,
        retain: Retain,
    ) -> Result<Zeroizing<Vec<u8>>, VfsError> {
        let block_bytes = self.cache.block_bytes();
        let pending = self.pending.get_mut(&handle).ok_or(VfsError::BadHandle)?;
        let base_len = pending.base_len;
        if let Some(spill) = pending.spill.as_mut()
            && let Some(block) = spill.block(index)?
        {
            return Ok(block);
        }
        let mut out = Zeroizing::new(vec![0u8; block_bytes as usize]);
        let at = index.checked_mul(block_bytes).ok_or(VfsError::Invalid)?;
        if at >= base_len {
            return Ok(out);
        }
        // Clamped to the floor a truncate left: past it the version's own bytes
        // are gone, and the file reads as the hole they left.
        let want = block_bytes.min(base_len - at) as usize;
        let stream = self.stream_for(handle).await?;
        let held = match retain {
            Retain::Hot => self.cache.get((stream, index)),
            Retain::Scan => self.cache.peek((stream, index)),
        };
        if let Some(block) = held {
            clamp_into(&mut out, block, want);
            return Ok(out);
        }
        let mut base = Zeroizing::new(self.engine.read_stream(stream, at, block_bytes).await?);
        clamp_into(&mut out, &base, want);
        if retain == Retain::Hot {
            self.cache
                .insert((stream, index), core::mem::take(&mut *base));
        }
        Ok(out)
    }

    /// The handle's spill file, minted on first use.
    fn spill_mut(&mut self, handle: HandleId) -> Result<&mut SpillFile, VfsError> {
        let block_bytes = self.cache.block_bytes();
        let pending = self.pending.get_mut(&handle).ok_or(VfsError::BadHandle)?;
        if pending.spill.is_none() {
            pending.spill = Some(self.spill.create(block_bytes)?);
        }
        pending.spill.as_mut().ok_or(VfsError::BadHandle)
    }

    /// The length a handle with unjournaled writes will publish for `node` —
    /// the file's real length until its op reaches the queue.
    fn pending_len(&self, node: NodeId) -> Option<u64> {
        self.pending
            .iter()
            .filter(|(handle, pending)| {
                pending.dirty
                    && self
                        .handles
                        .get(**handle)
                        .is_some_and(|open| open.node == node)
            })
            .map(|(_, pending)| pending.len)
            .max()
    }

    /// The read stream pinning `handle`'s content version, opened on first use:
    /// a handle on a file whose bytes are never read pays neither the resolve
    /// nor a slot against the engine's stream ceiling. A writer earns that only
    /// over an already-projected size whose blocks its writes replace whole — an
    /// unprojected size resolves regardless, because only the resolve yields the
    /// base length.
    async fn stream_for(&mut self, handle: HandleId) -> Result<StreamHandle, VfsError> {
        let open = self.handles.get(handle).ok_or(VfsError::BadHandle)?;
        if let Some(stream) = open.stream {
            return Ok(stream);
        }
        let stream = self.engine.open_content_stream(open.node).await?;
        if !self.handles.attach_stream(handle, stream) {
            self.engine.close_stream(stream);
            return Err(VfsError::BadHandle);
        }
        // The kernel's pages for this inode came from the version this mount
        // last bound; binding a different one is what makes them stale. A first
        // bind repaints nothing — the kernel holds no bytes the mount never
        // served.
        if let Some(pinned) = self.engine.stream_version_cid(stream) {
            let superseded = self
                .streamed
                .insert(open.node, pinned.clone())
                .is_some_and(|last| last != pinned);
            if superseded {
                let ino = self.inodes.ino_for(open.node);
                self.adapter.invalidate(Invalidation::Data { ino });
            }
        }
        Ok(stream)
    }

    /// Release a stream a handle held, wiping the plaintext it cached.
    fn release_stream(&mut self, stream: Option<StreamHandle>) {
        if let Some(stream) = stream {
            self.engine.close_stream(stream);
            self.cache.forget_stream(stream);
        }
    }

    /// Filesystem counters. The longest admissible name is
    /// [`MAX_NAME_BYTES`](crate::MAX_NAME_BYTES), the same limit create
    /// enforces.
    pub async fn statfs(&mut self) -> Result<StatFs, VfsError> {
        Ok(self.render().await?.statfs())
    }

    /// What the mount owes the user outside the kernel path. Never reached from
    /// a vfs operation: the tray reads it, and the kernel is never failed for
    /// anything it reports.
    pub async fn status(&self) -> Result<SessionStatus, VfsError> {
        Ok(self.engine.status().await?)
    }

    /// One internally-consistent read of the facade's rendered state, with the
    /// mount root bound to its inode.
    async fn render(&mut self) -> Result<EngineView, VfsError> {
        let view = self.engine.view().await?;
        if self.inodes.bind_root(view.root()) {
            self.adapter
                .invalidate(Invalidation::Attributes { ino: ROOT_INO });
        }
        Ok(view)
    }

    /// Stage an intent op; the projection needs only the outcome, not the staged OpId.
    async fn command(&mut self, command: Command) -> Result<(), VfsError> {
        self.engine.command(command).await?;
        Ok(())
    }

    /// Record what this mount just served for `node`, reporting what it served
    /// before, and correct the kernel for whatever the ceiling evicted.
    ///
    /// The correction has to go out at eviction: an evicted node is one no
    /// later repaint can measure a change against, so this is the last moment
    /// anything knows the kernel holds state for it at all.
    fn track_served(&mut self, node: NodeId, served: Served) -> Option<Served> {
        let displaced = self.served.insert(node, served);
        if let Some((evicted, _)) = displaced.evicted {
            let ino = self.inodes.ino_for(evicted);
            self.content_changed(ino);
        }
        displaced.replaced
    }

    /// The listing counterpart of [`track_served`](Self::track_served). An
    /// evicted directory is dropped one spelling at a time, because one
    /// spelling is all an entry invalidation matches.
    fn track_listed(&mut self, dir: NodeId, listing: BTreeMap<String, NodeId>) {
        let Some((evicted, names)) = self.listed.insert(dir, listing).evicted else {
            return;
        };
        let parent = self.inodes.ino_for(evicted);
        for name in names.keys() {
            self.entry_changed(parent, name);
        }
    }

    /// Report a node whose bytes and attributes both moved. Data first: a
    /// kernel that learned the new size first would serve the pages it still
    /// holds as the new version.
    fn content_changed(&self, ino: u64) {
        self.adapter.invalidate(Invalidation::Data { ino });
        self.adapter.invalidate(Invalidation::Attributes { ino });
    }

    /// Invalidate one name binding, under exactly the spelling given —
    /// `notify_inval_entry` matches one name and no fold of it.
    fn entry_changed(&self, parent: u64, name: &str) {
        self.adapter.invalidate(Invalidation::Entry {
            parent,
            name: name.to_owned(),
        });
    }

    /// Invalidate a binding a fold reached, under both spellings the kernel may
    /// hold it under: the stored one a listing gave it, and the one the caller
    /// typed and had an entry minted for. Clearing only one leaves the other
    /// serving a node that has moved for its whole TTL.
    fn entry_refolded(&self, parent: u64, stored: &str, requested: &str) {
        self.entry_changed(parent, stored);
        if requested != stored {
            self.entry_changed(parent, requested);
        }
    }

    fn node_of(&self, ino: u64) -> Result<NodeId, VfsError> {
        self.inodes.node(ino).ok_or(VfsError::NotFound)
    }

    /// Resolve an inode that must be a directory.
    fn directory(&self, view: &EngineView, ino: u64) -> Result<NodeId, VfsError> {
        let node = self.node_of(ino)?;
        let meta = view.attrs(node).ok_or(VfsError::NotFound)?;
        if meta.kind != NodeKind::Folder {
            return Err(VfsError::NotADirectory);
        }
        Ok(node)
    }

    /// [`attributes`](Self::attributes) for a reply that hands the kernel an
    /// entry, taking the reference such a reply owes. The kernel gives it back
    /// in [`forget`](Self::forget).
    fn entry_attributes(&mut self, meta: &NodeAttrs) -> Attributes {
        self.inodes.looked_up(meta.id);
        self.attributes(meta)
    }

    fn attributes(&mut self, meta: &NodeAttrs) -> Attributes {
        let size = self.pending_len(meta.id).or(meta.size);
        self.track_served(meta.id, Served::of(meta, size));
        Attributes {
            ino: self.inodes.ino_for(meta.id),
            node: meta.id,
            kind: meta.kind,
            size,
            mtime_millis: meta.mtime,
        }
    }

    async fn make(
        &mut self,
        parent: u64,
        name: &str,
        kind: NodeKind,
    ) -> Result<Attributes, VfsError> {
        validate_name(name)?;
        let view = self.render().await?;
        let parent_node = self.directory(&view, parent)?;
        if view.lookup(parent_node, name).is_some() {
            return Err(VfsError::AlreadyExists);
        }
        self.command(Command::Create {
            parent: parent_node,
            name: name.to_owned(),
            kind,
        })
        .await?;

        let view = self.render().await?;
        let meta = view
            .lookup(parent_node, name)
            .ok_or_else(|| VfsError::Internal {
                message: "a staged create is missing from the rendered view".to_owned(),
            })?;
        let attrs = self.entry_attributes(&meta);
        self.entry_changed(parent, name);
        Ok(attrs)
    }

    async fn remove(
        &mut self,
        parent: u64,
        name: &str,
        expected: NodeKind,
    ) -> Result<(), VfsError> {
        let view = self.render().await?;
        let parent_node = self.directory(&view, parent)?;
        let meta = self
            .resolve(&view, parent_node, name)
            .ok_or(VfsError::NotFound)?;
        removable(&view, &meta, expected)?;
        let gone = meta.name.clone();
        self.delete(&view, meta.id).await?;
        self.entry_refolded(parent, &gone, name);
        Ok(())
    }

    /// Delete a node that has already passed [`removable`], sweeping the whole
    /// subtree it still holds — only junk can survive that check, and junk the
    /// mount hides is junk the user could never clear by hand. A junk folder
    /// can hold real descendants, and `Command::Delete` unlinks exactly one
    /// node, so the sweep has to reach them or they outlive the mount point
    /// they hung from.
    async fn delete(&mut self, view: &EngineView, victim: NodeId) -> Result<(), VfsError> {
        self.delete_descendants(view, victim).await?;
        self.command(Command::Delete { node: victim }).await
    }

    /// The [`delete`](Self::delete) sweep without the node itself, for a caller
    /// that unlinks the root of the subtree by other means.
    async fn delete_descendants(
        &mut self,
        view: &EngineView,
        root: NodeId,
    ) -> Result<(), VfsError> {
        let mut order = subtree(view, root);
        // `subtree` is deepest-first, so the root is the last entry.
        order.pop();
        for node in order {
            self.command(Command::Delete { node }).await?;
        }
        Ok(())
    }
}

/// The children of `dir` a listing emits — the one place that rule is written,
/// so what `readdir` hands the kernel and what a repaint compares against
/// cannot drift apart. A directory the render no longer holds emits nothing,
/// which is itself the change.
fn emittable_children(view: &EngineView, dir: NodeId) -> Vec<NodeAttrs> {
    view.children(dir)
        .into_iter()
        .filter(|child| !is_platform_junk(&child.name) && is_emittable(&child.name))
        .collect()
}

/// A listing keyed by the name the kernel caches it under.
fn listing_of(children: &[NodeAttrs]) -> BTreeMap<String, NodeId> {
    children
        .iter()
        .map(|child| (child.name.clone(), child.id))
        .collect()
}

/// The names whose binding moved between two listings: added, removed, or the
/// same name over a different node. Each name appears once however it moved —
/// one entry invalidation is all the kernel needs.
fn rebound_names(
    before: &BTreeMap<String, NodeId>,
    after: &BTreeMap<String, NodeId>,
) -> Vec<String> {
    before
        .iter()
        .filter(|(name, node)| after.get(*name) != Some(node))
        .map(|(name, _)| name.clone())
        .chain(
            after
                .iter()
                .filter(|(name, _)| !before.contains_key(*name))
                .map(|(name, _)| name.clone()),
        )
        .collect()
}

/// Copy the first `want` bytes of `block` over the head of `out`, leaving the
/// rest of `out` as the zeros a truncate's floor reads as.
fn clamp_into(out: &mut [u8], block: &[u8], want: usize) {
    let take = want.min(block.len());
    out[..take].copy_from_slice(&block[..take]);
}

/// Append at most `want` bytes of `block` from `within` onto `out`, reporting
/// how many the block actually held.
fn take_from(out: &mut Zeroizing<Vec<u8>>, block: &[u8], within: usize, want: usize) -> usize {
    // An offset past a short block's end takes nothing rather than indexing
    // outside it.
    let start = within.min(block.len());
    let take = (block.len() - start).min(want);
    grow_wiping(out, take);
    out.extend_from_slice(&block[start..start + take]);
    take
}

/// Whether `candidate` is `node` or lives somewhere beneath it. Relinking a
/// folder into its own subtree would detach that subtree from the root for
/// good; POSIX rename answers `EINVAL` and so does the projection.
fn contains(view: &EngineView, node: NodeId, candidate: NodeId) -> bool {
    subtree(view, node).contains(&candidate)
}

/// `root` and everything beneath it, deepest first — the order deletes must
/// run in, since each one unlinks a single node. Visit-tracked like the
/// engine snapshot's own `ancestors` walk: a malformed cycle has to terminate
/// rather than hang the mount.
fn subtree(view: &EngineView, root: NodeId) -> Vec<NodeId> {
    let mut order = Vec::new();
    let mut seen = BTreeSet::from([root]);
    let mut frontier = vec![root];
    while let Some(next) = frontier.pop() {
        order.push(next);
        for child in view.children(next) {
            if seen.insert(child.id) {
                frontier.push(child.id);
            }
        }
    }
    // Preorder puts every node before its descendants; reversed, after them.
    order.reverse();
    order
}

/// The POSIX preconditions for making a node vanish: it must be the kind the
/// caller expects, and a folder must be empty.
fn removable(view: &EngineView, victim: &NodeAttrs, expected: NodeKind) -> Result<(), VfsError> {
    if victim.kind != expected {
        return Err(match expected {
            NodeKind::File => VfsError::IsADirectory,
            NodeKind::Folder => VfsError::NotADirectory,
        });
    }
    // Junk does not count: it is hidden from listings, so a folder holding
    // nothing else reads as empty through the mount and must behave that way.
    if expected == NodeKind::Folder
        && view
            .children(victim.id)
            .iter()
            .any(|child| !is_platform_junk(&child.name))
    {
        return Err(VfsError::NotEmpty);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId([byte; 16])
    }

    /// A listing entry is the projection a host receives per child, so its
    /// rendering withholds the name for the same reason the engine's do
    /// (crates/core/src/codec/redact.rs).
    #[test]
    fn dir_entry_debug_withholds_the_plaintext_name() {
        const NAME: &str = "payroll.csv";
        let entry = DirEntry {
            ino: 42,
            name: NAME.to_string(),
            kind: NodeKind::File,
            size: Some(11),
            mtime_millis: Some(3),
        };
        let rendered = format!("{entry:?}");

        assert!(!rendered.contains(NAME), "a name never renders: {rendered}");
        assert!(rendered.contains("DirEntry"), "the shape survives");
        assert!(rendered.contains("42"), "the inode survives: {rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    fn evicted<V>(displaced: Displaced<V>) -> Option<NodeId> {
        displaced.evicted.map(|(node, _)| node)
    }

    fn held<V: Copy>(shadow: &Shadow<V>, node: NodeId) -> Option<V> {
        shadow
            .iter()
            .find(|(slot, _)| *slot == node)
            .map(|(_, value)| *value)
    }

    /// The ceiling is the whole point: what these maps hold is decided by a
    /// peer's tree and by whatever walks the mount, not by this device.
    #[test]
    fn a_shadow_map_never_grows_past_its_ceiling() {
        let mut shadow = Shadow::new(3);
        for byte in 0..32u8 {
            shadow.insert(node(byte), byte);
        }
        assert_eq!(shadow.iter().count(), 3);
    }

    /// These maps are the only thing a repaint measures a change against, so an
    /// entry dropped quietly is kernel state nothing would correct again — the
    /// caller has to be told what went, and told exactly once.
    #[test]
    fn every_eviction_is_reported_to_the_caller() {
        let mut shadow = Shadow::new(2);
        assert_eq!(evicted(shadow.insert(node(1), "first")), None);
        assert_eq!(evicted(shadow.insert(node(2), "second")), None);
        assert_eq!(
            evicted(shadow.insert(node(1), "first again")),
            None,
            "a rewrite displaces nothing but itself"
        );

        assert_eq!(evicted(shadow.insert(node(3), "third")), Some(node(2)));
        assert_eq!(evicted(shadow.insert(node(4), "fourth")), Some(node(1)));
    }

    /// A ceiling nothing could ever be held under would evict every entry as it
    /// landed, and push a correction for state the kernel just received.
    #[test]
    fn a_map_always_holds_at_least_one_entry() {
        let mut shadow = Shadow::new(0);
        assert_eq!(evicted(shadow.insert(node(1), "first")), None);
        assert_eq!(held(&shadow, node(1)), Some("first"));
    }

    /// Rewriting an entry is the mount re-serving that state to the kernel, so
    /// it renews the entry against the ceiling — a working set the kernel keeps
    /// asking about must outlive one pass over a tree it never revisits.
    #[test]
    fn the_least_recently_written_entry_is_the_one_evicted() {
        let mut shadow = Shadow::new(2);
        shadow.insert(node(1), "first");
        shadow.insert(node(2), "second");
        shadow.insert(node(1), "first again");
        shadow.insert(node(3), "third");

        assert_eq!(held(&shadow, node(2)), None, "untouched since it landed");
        assert_eq!(held(&shadow, node(1)), Some("first again"));
        assert_eq!(held(&shadow, node(3)), Some("third"));
    }

    /// A repaint walks every entry to diff it; counting that as a kernel access
    /// would make the ceiling evict by nothing but first-insertion order.
    #[test]
    fn walking_the_map_renews_nothing() {
        let mut shadow = Shadow::new(2);
        shadow.insert(node(1), "first");
        shadow.insert(node(2), "second");

        assert_eq!(shadow.iter().count(), 2);

        shadow.insert(node(3), "third");
        assert_eq!(held(&shadow, node(1)), None, "the walk renewed nothing");
    }

    #[test]
    fn replacing_an_entry_keeps_the_map_at_one_slot_for_it() {
        let mut shadow = Shadow::new(2);
        assert_eq!(shadow.insert(node(1), "first").replaced, None);
        assert_eq!(shadow.insert(node(1), "again").replaced, Some("first"));

        assert_eq!(shadow.iter().count(), 1);
        assert_eq!(held(&shadow, node(1)), Some("again"));
    }

    #[test]
    fn a_removed_entry_frees_its_slot() {
        let mut shadow = Shadow::new(2);
        shadow.insert(node(1), "first");
        shadow.remove(node(1));

        assert!(shadow.is_empty());

        shadow.insert(node(2), "second");
        shadow.insert(node(3), "third");
        assert_eq!(
            held(&shadow, node(2)),
            Some("second"),
            "the slot really freed"
        );
    }
}
