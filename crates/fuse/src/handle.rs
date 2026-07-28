//! Open-file handles for one mount session. Key-free like the inode map: a
//! handle records which node it addresses and how it was opened, never
//! anything derived from a key.

use std::collections::HashMap;

use cipherbox_engine::NodeId;

/// A kernel file-handle token, unique for the mount session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HandleId(pub u64);

/// How a handle was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Reads only.
    Read,
    /// Writes only.
    Write,
    /// Reads and writes.
    ReadWrite,
}

impl Access {
    /// Whether this handle may write.
    pub fn writable(self) -> bool {
        matches!(self, Access::Write | Access::ReadWrite)
    }
}

/// What one open handle addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFile {
    /// The node the handle is open on.
    pub node: NodeId,
    /// How it was opened.
    pub access: Access,
}

/// The session's open handles.
#[derive(Debug, Default)]
pub struct HandleTable {
    open: HashMap<HandleId, OpenFile>,
    next: u64,
}

impl HandleTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a handle on `node`. Ids are monotonic and never reused, so a
    /// release cannot be raced onto a later open.
    pub fn open(&mut self, node: NodeId, access: Access) -> HandleId {
        let id = HandleId(self.next);
        self.next += 1;
        self.open.insert(id, OpenFile { node, access });
        id
    }

    /// The handle's target, if it is still open.
    pub fn get(&self, id: HandleId) -> Option<OpenFile> {
        self.open.get(&id).copied()
    }

    /// Close a handle, reporting whether it was open.
    pub fn close(&mut self, id: HandleId) -> Option<OpenFile> {
        self.open.remove(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId([byte; 16])
    }

    #[test]
    fn an_open_handle_resolves_to_its_node() {
        let mut table = HandleTable::new();
        let id = table.open(node(1), Access::Read);
        assert_eq!(
            table.get(id),
            Some(OpenFile {
                node: node(1),
                access: Access::Read
            })
        );
    }

    #[test]
    fn closing_releases_the_handle_exactly_once() {
        let mut table = HandleTable::new();
        let id = table.open(node(1), Access::ReadWrite);
        assert!(table.close(id).is_some());
        assert_eq!(table.get(id), None);
        assert!(table.close(id).is_none(), "a second close is not an open");
    }

    #[test]
    fn ids_are_never_reused_after_a_close() {
        let mut table = HandleTable::new();
        let first = table.open(node(1), Access::Read);
        table.close(first);
        let second = table.open(node(1), Access::Read);
        assert_ne!(first, second);
    }

    #[test]
    fn two_opens_on_one_node_are_independent() {
        let mut table = HandleTable::new();
        let reader = table.open(node(1), Access::Read);
        let writer = table.open(node(1), Access::Write);
        assert_ne!(reader, writer);
        table.close(reader);
        assert_eq!(table.get(reader), None);
        assert_eq!(table.get(writer).map(|h| h.access), Some(Access::Write));
    }

    #[test]
    fn write_access_is_reported_for_writable_opens_only() {
        assert!(!Access::Read.writable());
        assert!(Access::Write.writable());
        assert!(Access::ReadWrite.writable());
    }
}
