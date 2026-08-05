//! The platform-neutral vfs operation core: one implementation of every
//! filesystem operation, over the engine facade and nothing else
//! (blueprint/desktop.md "The FS core and host adapters").
//!
//! It is a projection, not a second brain. Reads render the facade's snapshot
//! (with the pending-op overlay already applied) and never wait on the
//! network; mutations become facade intent ops. No keys, no publish
//! machinery, no freshness policy — those decisions all happened below the
//! facade.

use std::collections::BTreeSet;

use cipherbox_engine::seams::SeamTypes;
use cipherbox_engine::{Command, Engine, EngineView, NodeAttrs, NodeId, NodeKind, StatFs};

use crate::adapter::{CacheTtls, HostAdapter, Invalidation};
use crate::error::VfsError;
use crate::handle::{Access, HandleId, HandleTable, OpenFile};
use crate::inode::{InodeTable, ROOT_INO};
use crate::name::{is_emittable, is_platform_junk, validate_name};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The session's inode number for the child.
    pub ino: u64,
    /// The child's name, as entered.
    pub name: String,
    /// File or folder.
    pub kind: NodeKind,
}

/// The operation core for one mount session: the engine it projects, the host
/// adapter it pushes invalidation to, and the session's inode and handle maps.
pub struct OperationCore<T: SeamTypes, A: HostAdapter> {
    engine: Engine<T>,
    adapter: A,
    inodes: InodeTable,
    handles: HandleTable,
}

impl<T: SeamTypes, A: HostAdapter> OperationCore<T, A> {
    /// Mount `engine` behind `adapter`. The engine must already be started.
    pub fn new(engine: Engine<T>, adapter: A) -> Self {
        Self {
            engine,
            adapter,
            inodes: InodeTable::new(),
            handles: HandleTable::new(),
        }
    }

    /// The kernel cache lifetimes this mount's adapter earned.
    pub fn cache_ttls(&self) -> CacheTtls {
        CacheTtls::for_host(&self.adapter.capabilities(), self.engine.profile())
    }

    /// Resolve a name under a directory.
    pub async fn lookup(&mut self, parent: u64, name: &str) -> Result<Attributes, VfsError> {
        if !is_emittable(name) {
            return Err(VfsError::NotFound);
        }
        let view = self.render().await?;
        let parent_node = self.directory(&view, parent)?;
        let meta = view.lookup(parent_node, name).ok_or(VfsError::NotFound)?;
        Ok(self.attributes(&meta))
    }

    /// Read one node's attributes.
    pub async fn getattr(&mut self, ino: u64) -> Result<Attributes, VfsError> {
        let view = self.render().await?;
        let node = self.node_of(ino)?;
        let meta = view.attrs(node).ok_or(VfsError::NotFound)?;
        Ok(self.attributes(&meta))
    }

    /// List a directory's children in the engine's deterministic order,
    /// hiding platform junk and names no kernel could carry — both classes
    /// arrive from other clients, which validate nothing. `.` and `..` are the
    /// adapter's to synthesize, along with any offset cookies.
    pub async fn readdir(&mut self, ino: u64) -> Result<Vec<DirEntry>, VfsError> {
        let view = self.render().await?;
        let node = self.directory(&view, ino)?;
        let children = view.children(node);
        let mut entries = Vec::with_capacity(children.len());
        for child in children {
            if is_platform_junk(&child.name) || !is_emittable(&child.name) {
                continue;
            }
            entries.push(DirEntry {
                ino: self.inodes.ino_for(child.id),
                name: child.name,
                kind: child.kind,
            });
        }
        Ok(entries)
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
        let source = view.lookup(parent_node, name).ok_or(VfsError::NotFound)?;
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
            replacing: replaced.map(|dest| dest.id),
        })
        .await?;

        let ino = self.inodes.ino_for(source.id);
        self.entry_changed(parent, name);
        self.entry_changed(new_parent, new_name);
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

    /// Close a file handle.
    pub fn release(&mut self, handle: HandleId) -> Result<(), VfsError> {
        self.handles.close(handle).ok_or(VfsError::BadHandle)?;
        Ok(())
    }

    /// Filesystem counters. The longest admissible name is
    /// [`MAX_NAME_BYTES`](crate::MAX_NAME_BYTES), the same limit create
    /// enforces.
    pub async fn statfs(&mut self) -> Result<StatFs, VfsError> {
        Ok(self.render().await?.statfs())
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

    fn entry_changed(&self, parent: u64, name: &str) {
        self.adapter.invalidate(Invalidation::Entry {
            parent,
            name: name.to_owned(),
        });
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

    fn attributes(&mut self, meta: &NodeAttrs) -> Attributes {
        Attributes {
            ino: self.inodes.ino_for(meta.id),
            node: meta.id,
            kind: meta.kind,
            size: meta.size,
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
        let attrs = self.attributes(&meta);
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
        let meta = view.lookup(parent_node, name).ok_or(VfsError::NotFound)?;
        removable(&view, &meta, expected)?;
        self.delete(&view, meta.id).await?;
        self.entry_changed(parent, name);
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
