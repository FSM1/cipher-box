//! The platform-neutral vfs operation core: one implementation of every
//! filesystem operation, over the engine facade and nothing else
//! (blueprint/desktop.md "The FS core and host adapters").
//!
//! It is a projection, not a second brain. Reads render the facade's snapshot
//! (with the pending-op overlay already applied) and never wait on the
//! network; mutations become facade intent ops. No keys, no publish
//! machinery, no freshness policy — those decisions all happened below the
//! facade.

use cipherbox_engine::seams::SeamTypes;
use cipherbox_engine::{Command, Engine, EngineView, NodeAttrs, NodeId, NodeKind};

use crate::adapter::{CacheTtls, HostAdapter, Invalidation};
use crate::error::VfsError;
use crate::handle::{Access, HandleId, HandleTable, OpenFile};
use crate::inode::InodeTable;
use crate::name::{MAX_NAME_BYTES, is_platform_junk, validate_name};

/// A node as the kernel sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attributes {
    /// The session's inode number for the node.
    pub ino: u64,
    /// The engine's stable node id.
    pub node: NodeId,
    /// File or folder.
    pub kind: NodeKind,
    /// Plaintext size in bytes; zero until the content plane projects one.
    pub size: u64,
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

/// Filesystem-level counters for statfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsStats {
    /// Nodes reachable from the mount root.
    pub nodes: u64,
    /// The longest admissible name, in bytes — the same limit create
    /// enforces, so the advertised value is never a fiction.
    pub name_max: u32,
}

/// The operation core for one mount session: the engine it projects, the host
/// adapter it pushes invalidation to, and the session's inode and handle maps.
pub struct OperationCore<T: SeamTypes, A: HostAdapter> {
    engine: Engine<T>,
    adapter: A,
    inodes: InodeTable,
    handles: HandleTable,
    ttls: CacheTtls,
}

impl<T: SeamTypes, A: HostAdapter> OperationCore<T, A> {
    /// Mount `engine` behind `adapter`. The engine must already be started.
    pub fn new(engine: Engine<T>, adapter: A) -> Self {
        let ttls = CacheTtls::for_host(&adapter.capabilities(), engine.profile());
        Self {
            engine,
            adapter,
            inodes: InodeTable::new(),
            handles: HandleTable::new(),
            ttls,
        }
    }

    /// The kernel cache lifetimes this mount's adapter earned.
    pub fn cache_ttls(&self) -> CacheTtls {
        self.ttls
    }

    /// Resolve a name under a directory.
    pub async fn lookup(&mut self, parent: u64, name: &str) -> Result<Attributes, VfsError> {
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
    /// hiding platform junk that arrived from another client. `.` and `..`
    /// are the adapter's to synthesize, along with any offset cookies.
    pub async fn readdir(&mut self, ino: u64) -> Result<Vec<DirEntry>, VfsError> {
        let view = self.render().await?;
        let node = self.directory(&view, ino)?;
        let mut entries = Vec::new();
        for child in view.children(node) {
            if is_platform_junk(&child.name) {
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
        // A case- or normalization-only respell folds onto the source itself
        // under the engine's strict comparator; it is a rename, not a replace.
        let replaced = view
            .lookup(new_parent_node, new_name)
            .filter(|dest| dest.id != source.id);
        if let Some(dest) = &replaced {
            match (source.kind, dest.kind) {
                (NodeKind::File, NodeKind::Folder) => return Err(VfsError::IsADirectory),
                (NodeKind::Folder, NodeKind::File) => return Err(VfsError::NotADirectory),
                (NodeKind::Folder, NodeKind::Folder) if !view.children(dest.id).is_empty() => {
                    return Err(VfsError::NotEmpty);
                }
                _ => {}
            }
        }

        // The facade has no combined move-and-rename op, so the projection
        // spells the request as the minimal ordered intent-op sequence:
        // vacate the destination, relink, then respell.
        if let Some(dest) = replaced {
            self.command(Command::Delete { node: dest.id }).await?;
        }
        if new_parent_node != parent_node {
            self.command(Command::Relink {
                node: source.id,
                new_parent: new_parent_node,
            })
            .await?;
        }
        if source.name != new_name {
            self.command(Command::Rename {
                node: source.id,
                new_name: new_name.to_owned(),
            })
            .await?;
        }

        let ino = self.inodes.ino_for(source.id);
        self.adapter.invalidate(Invalidation::Entry {
            parent,
            name: name.to_owned(),
        });
        self.adapter.invalidate(Invalidation::Entry {
            parent: new_parent,
            name: new_name.to_owned(),
        });
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

    /// Filesystem counters.
    pub async fn statfs(&mut self) -> Result<FsStats, VfsError> {
        let view = self.render().await?;
        Ok(FsStats {
            nodes: view.statfs().nodes,
            name_max: MAX_NAME_BYTES as u32,
        })
    }

    /// One internally-consistent read of the facade's rendered state, with the
    /// mount root bound to its inode.
    async fn render(&mut self) -> Result<EngineView, VfsError> {
        let view = self.engine.view().await.map_err(VfsError::from_engine)?;
        self.inodes.bind_root(view.root());
        Ok(view)
    }

    async fn command(&mut self, command: Command) -> Result<(), VfsError> {
        self.engine
            .command(command)
            .await
            .map_err(VfsError::from_engine)
    }

    fn node_of(&self, ino: u64) -> Result<NodeId, VfsError> {
        self.inodes.node(ino).ok_or(VfsError::NotFound)
    }

    /// Resolve an inode that must be a directory.
    fn directory(&self, view: &EngineView, ino: u64) -> Result<NodeId, VfsError> {
        let node = self.node_of(ino)?;
        match view.attrs(node) {
            None => Err(VfsError::NotFound),
            Some(meta) if meta.kind != NodeKind::Folder => Err(VfsError::NotADirectory),
            Some(_) => Ok(node),
        }
    }

    fn attributes(&mut self, meta: &NodeAttrs) -> Attributes {
        Attributes {
            ino: self.inodes.ino_for(meta.id),
            node: meta.id,
            kind: meta.kind,
            size: meta.size.unwrap_or(0),
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
            content: None,
        })
        .await?;

        let view = self.render().await?;
        let meta = view
            .lookup(parent_node, name)
            .ok_or_else(|| VfsError::Internal {
                message: "a staged create is missing from the rendered view".to_owned(),
            })?;
        let attrs = self.attributes(&meta);
        self.adapter.invalidate(Invalidation::Entry {
            parent,
            name: name.to_owned(),
        });
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
        // No junk filtering here: junk hidden from listings must still be
        // removable through the mount, or a name another client committed is
        // stranded forever.
        let meta = view.lookup(parent_node, name).ok_or(VfsError::NotFound)?;
        if meta.kind != expected {
            return Err(match expected {
                NodeKind::File => VfsError::IsADirectory,
                NodeKind::Folder => VfsError::NotADirectory,
            });
        }
        if expected == NodeKind::Folder && !view.children(meta.id).is_empty() {
            return Err(VfsError::NotEmpty);
        }
        self.command(Command::Delete { node: meta.id }).await?;
        self.adapter.invalidate(Invalidation::Entry {
            parent,
            name: name.to_owned(),
        });
        Ok(())
    }
}
