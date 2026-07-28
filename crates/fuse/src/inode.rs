//! The key-free inode map: kernel inode numbers ↔ engine node ids, allocated
//! per mount session (blueprint/desktop.md "Names and attributes").
//!
//! Keying on the engine's stable node id — never on `(parent, name)` — is what
//! makes an inode survive a rename for free, and keeps the map free of any key
//! material: it holds two integers' worth of identity and nothing else.

use std::collections::HashMap;

use cipherbox_engine::NodeId;

/// The mount root's inode number, fixed by every FUSE-family protocol.
pub const ROOT_INO: u64 = 1;

/// Kernel inode numbers for one mount session.
///
/// Numbers are allocated monotonically and never reused, so a node the kernel
/// still remembers can never collide with a later one — v1 reallocated and
/// paid for it in stale-handle disconnects. Bindings live for the session; a
/// remount renumbers from scratch.
#[derive(Debug)]
pub struct InodeTable {
    by_ino: HashMap<u64, NodeId>,
    by_node: HashMap<NodeId, u64>,
    root: Option<NodeId>,
    next: u64,
}

impl InodeTable {
    /// An empty table; [`ROOT_INO`] binds on the first [`bind_root`](Self::bind_root).
    pub fn new() -> Self {
        Self {
            by_ino: HashMap::new(),
            by_node: HashMap::new(),
            root: None,
            next: ROOT_INO + 1,
        }
    }

    /// Bind the rendered root to [`ROOT_INO`]. Idempotent, and re-points the
    /// root inode if cold start replaces the anchored root the session opened
    /// on.
    pub fn bind_root(&mut self, root: NodeId) {
        if self.root == Some(root) {
            return;
        }
        if let Some(previous) = self.root.replace(root) {
            self.by_node.remove(&previous);
        }
        self.by_ino.insert(ROOT_INO, root);
        self.by_node.insert(root, ROOT_INO);
    }

    /// The node bound to `ino`, if the session has seen it.
    pub fn node(&self, ino: u64) -> Option<NodeId> {
        self.by_ino.get(&ino).copied()
    }

    /// The inode number for `node`, allocating one on first sight.
    pub fn ino_for(&mut self, node: NodeId) -> u64 {
        if let Some(ino) = self.by_node.get(&node) {
            return *ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_ino.insert(ino, node);
        self.by_node.insert(node, ino);
        ino
    }
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId([byte; 16])
    }

    #[test]
    fn the_root_binds_to_ino_one() {
        let mut table = InodeTable::new();
        table.bind_root(node(0));
        assert_eq!(table.node(ROOT_INO), Some(node(0)));
        assert_eq!(table.ino_for(node(0)), ROOT_INO);
    }

    #[test]
    fn a_node_keeps_its_inode_across_repeated_lookups() {
        let mut table = InodeTable::new();
        table.bind_root(node(0));
        let first = table.ino_for(node(7));
        assert_eq!(table.ino_for(node(7)), first);
        assert_eq!(table.node(first), Some(node(7)));
    }

    #[test]
    fn distinct_nodes_never_share_an_inode() {
        let mut table = InodeTable::new();
        table.bind_root(node(0));
        let a = table.ino_for(node(1));
        let b = table.ino_for(node(2));
        assert_ne!(a, b);
        assert_ne!(a, ROOT_INO);
        assert_ne!(b, ROOT_INO);
    }

    #[test]
    fn cold_start_repointing_the_root_moves_the_root_inode() {
        let mut table = InodeTable::new();
        table.bind_root(node(0));
        let child = table.ino_for(node(9));

        table.bind_root(node(3));

        assert_eq!(table.node(ROOT_INO), Some(node(3)));
        assert_eq!(table.ino_for(node(3)), ROOT_INO);
        assert_eq!(table.ino_for(node(9)), child, "other bindings survive");
    }

    #[test]
    fn unknown_inodes_resolve_to_nothing() {
        let table = InodeTable::new();
        assert_eq!(table.node(ROOT_INO), None);
        assert_eq!(table.node(4242), None);
    }
}
