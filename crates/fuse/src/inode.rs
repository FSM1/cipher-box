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
    /// Per inode, its node and how many references the kernel is holding — one
    /// per entry reply it took, given back in FORGET. A binding dropped while
    /// the kernel still holds one would answer `ENOENT` for a node that exists.
    by_ino: HashMap<u64, (NodeId, u64)>,
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

    /// Bind the rendered root to [`ROOT_INO`], reporting whether it *moved* —
    /// a cold start can replace the anchored root the session opened on, and
    /// then [`ROOT_INO`] addresses a different node than the kernel has
    /// cached, so the caller must push an invalidation. The first bind of a
    /// session moves nothing.
    pub fn bind_root(&mut self, root: NodeId) -> bool {
        if self.root == Some(root) {
            return false;
        }
        let previous = self.root.replace(root);
        if let Some(previous) = previous {
            self.by_node.remove(&previous);
        }
        // The incoming root may already hold an ordinary number from an
        // earlier listing; drop it, or the node answers to two inodes.
        if let Some(stale) = self.by_node.insert(root, ROOT_INO) {
            self.by_ino.remove(&stale);
        }
        self.by_ino.insert(ROOT_INO, (root, 0));
        previous.is_some()
    }

    /// Take one kernel reference on `node`, minting its inode number on first
    /// sight — what every reply that hands the kernel an entry owes, and the
    /// count [`forget`](Self::forget) draws down.
    pub fn looked_up(&mut self, node: NodeId) -> u64 {
        let ino = self.ino_for(node);
        if let Some((_, held)) = self.by_ino.get_mut(&ino) {
            *held += 1;
        }
        ino
    }

    /// Give back `count` of the kernel's references to `ino`, reporting the
    /// node whose binding that dropped — nothing while references remain, and
    /// nothing for an inode the kernel never took one on.
    ///
    /// Dropping is safe because numbers are never reused: a later
    /// [`ino_for`](Self::ino_for) mints a fresh one rather than resurrecting
    /// this. The root is never forgotten — the mount would lose its anchor.
    pub fn forget(&mut self, ino: u64, count: u64) -> Option<NodeId> {
        if ino == ROOT_INO {
            return None;
        }
        let (_, held) = self.by_ino.get_mut(&ino)?;
        if *held == 0 {
            return None;
        }
        *held = held.saturating_sub(count);
        if *held > 0 {
            return None;
        }
        let (node, _) = self.by_ino.remove(&ino)?;
        self.by_node.remove(&node);
        Some(node)
    }

    /// The node bound to `ino`, if the session has seen it.
    pub fn node(&self, ino: u64) -> Option<NodeId> {
        self.by_ino.get(&ino).map(|(node, _)| *node)
    }

    /// The inode number for `node`, allocating one on first sight.
    pub fn ino_for(&mut self, node: NodeId) -> u64 {
        if let Some(ino) = self.by_node.get(&node) {
            return *ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_ino.insert(ino, (node, 0));
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
        assert!(!table.bind_root(node(0)), "the first bind moves nothing");
        let child = table.ino_for(node(9));
        let promoted = table.ino_for(node(3));

        assert!(table.bind_root(node(3)), "a re-anchor must be reported");
        assert!(
            !table.bind_root(node(3)),
            "rebinding the same root does not"
        );

        assert_eq!(table.node(ROOT_INO), Some(node(3)));
        assert_eq!(table.ino_for(node(3)), ROOT_INO);
        assert_eq!(
            table.node(promoted),
            None,
            "the promoted node must not answer to two inodes"
        );
        assert_eq!(table.ino_for(node(9)), child, "other bindings survive");
    }

    #[test]
    fn a_forgotten_inode_is_dropped_and_never_resurrected() {
        let mut table = InodeTable::new();
        table.bind_root(node(0));
        let ino = table.looked_up(node(7));

        assert_eq!(table.forget(ino, 1), Some(node(7)));

        assert_eq!(table.node(ino), None);
        assert_ne!(table.ino_for(node(7)), ino, "numbers are never reused");
    }

    /// The kernel counts every entry reply it took and gives them back in one
    /// or several FORGETs; a binding dropped before the last of them would
    /// answer `ENOENT` for a node the kernel is still addressing.
    #[test]
    fn a_binding_survives_until_the_last_reference_is_given_back() {
        let mut table = InodeTable::new();
        table.bind_root(node(0));
        let ino = table.looked_up(node(7));
        assert_eq!(table.looked_up(node(7)), ino, "one binding, two references");

        assert_eq!(table.forget(ino, 1), None, "one reference is still held");
        assert_eq!(table.node(ino), Some(node(7)));

        assert_eq!(table.forget(ino, 1), Some(node(7)));
        assert_eq!(table.node(ino), None);
    }

    /// A FORGET carrying more than the mount believes it handed out is the
    /// kernel's count, not a reason to leave the binding pinned forever.
    #[test]
    fn an_oversized_forget_drops_the_binding_rather_than_wrapping() {
        let mut table = InodeTable::new();
        table.bind_root(node(0));
        let ino = table.looked_up(node(7));

        assert_eq!(table.forget(ino, u64::MAX), Some(node(7)));
        assert_eq!(table.node(ino), None);
    }

    /// A listing mints inode numbers without the kernel taking a reference on
    /// any of them, so a FORGET can name one it never looked up.
    #[test]
    fn an_inode_the_kernel_never_referenced_is_not_dropped_by_a_forget() {
        let mut table = InodeTable::new();
        table.bind_root(node(0));
        let ino = table.ino_for(node(7));

        assert_eq!(table.forget(ino, 1), None);
        assert_eq!(table.node(ino), Some(node(7)));
    }

    #[test]
    fn the_root_is_never_forgotten() {
        let mut table = InodeTable::new();
        table.bind_root(node(0));
        assert_eq!(table.forget(ROOT_INO, u64::MAX), None);
        assert_eq!(table.node(ROOT_INO), Some(node(0)));
    }

    #[test]
    fn unknown_inodes_resolve_to_nothing() {
        let table = InodeTable::new();
        assert_eq!(table.node(ROOT_INO), None);
        assert_eq!(table.node(4242), None);
    }
}
