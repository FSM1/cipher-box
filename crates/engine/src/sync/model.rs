//! The working tree model — the state law's left operand (blueprint/engine.md
//! "Sync core", CONTEXT.md "Pending-op overlay").
//!
//! The [`Snapshot`] is the last-known-good **gate-passing** remote state, a
//! single-owner projection of the resolved read-bodies (the content-plane
//! assembly from `Adopted` read-bodies lands with a later slice; the sync core
//! is written against this engine-domain projection). Rendered state is this
//! snapshot with the pending-op overlay applied on top — the op queue is the
//! only local divergence.
//!
//! A node's parent is expressed as a [`Link`] carrying the monotonic
//! `link_counter` (mirrors core's `ChildRef.linkCounter`, #33 D5). A
//! well-formed snapshot holds at most one link per child; a dual-link crash
//! residue holds two, resolved by [`crate::sync::rebase::observed_repair`].

use std::collections::BTreeMap;

use crate::facade::{NodeId, NodeKind};

/// One node's metadata in the working tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeMeta {
    /// Location-independent node id.
    pub id: NodeId,
    /// The display name, stored **as entered** (uniqueness folds via
    /// [`collation_key`]; the stored name is never mutated for comparison).
    pub name: String,
    /// File or folder.
    pub kind: NodeKind,
    /// The node's own IPNS record sequence — the conditional-delete snapshot
    /// (a delete op drops on rebase if this advanced past the op's snapshot).
    pub record_sequence: u64,
    /// Bumped on every `updateContent` (a fresh per-version content key seals
    /// each version, CONTEXT.md "Content key").
    pub content_version: u64,
    /// Plaintext content size in bytes; `None` until the content plane
    /// projects it.
    pub size: Option<u64>,
    /// Modification time (Unix millis) from the sealed read-body; `None`
    /// until projected.
    pub mtime: Option<u64>,
    /// The node's opaque `ipnsName` bytes as carried by its parent's
    /// `ChildRef`; `None` for nodes not yet in gate-passing state.
    pub ipns_name: Option<Vec<u8>>,
}

impl NodeMeta {
    /// A node at record sequence 1, content version 0, no projected
    /// size/mtime/ipnsName.
    pub fn new(id: NodeId, name: impl Into<String>, kind: NodeKind) -> Self {
        Self {
            id,
            name: name.into(),
            kind,
            record_sequence: 1,
            content_version: 0,
            size: None,
            mtime: None,
            ipns_name: None,
        }
    }
}

/// A parent→child link with the monotonic dual-link tiebreak counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// The parent folder.
    pub parent: NodeId,
    /// The child node.
    pub child: NodeId,
    /// Monotonic counter; on a dual-link the higher counter is the winner
    /// (ties broken by parent id for a total, cross-platform-stable order).
    pub link_counter: u64,
}

/// The last-known-good remote snapshot: gate-passing state, single owner
/// (the state law's left operand, #33 D6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The vault root node id.
    pub root: NodeId,
    nodes: BTreeMap<NodeId, NodeMeta>,
    links: Vec<Link>,
}

impl Snapshot {
    /// An empty snapshot anchored at `root` (the root node itself is present
    /// as a folder with no parent link).
    pub fn new(root: NodeId) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(root, NodeMeta::new(root, "", NodeKind::Folder));
        Self {
            root,
            nodes,
            links: Vec::new(),
        }
    }

    /// Inserts or replaces a node's metadata.
    pub fn upsert_node(&mut self, meta: NodeMeta) {
        self.nodes.insert(meta.id, meta);
    }

    /// The node's metadata, if present.
    pub fn node(&self, id: NodeId) -> Option<&NodeMeta> {
        self.nodes.get(&id)
    }

    /// Mutable access to a node's metadata.
    pub fn node_mut(&mut self, id: NodeId) -> Option<&mut NodeMeta> {
        self.nodes.get_mut(&id)
    }

    /// Whether the node is present in gate-passing state.
    pub fn contains(&self, id: NodeId) -> bool {
        self.nodes.contains_key(&id)
    }

    /// The node's own record sequence, if present.
    pub fn record_sequence(&self, id: NodeId) -> Option<u64> {
        self.nodes.get(&id).map(|n| n.record_sequence)
    }

    /// Adds a parent→child link. Idempotent on `(parent, child)`: a repeat
    /// keeps the higher `link_counter` (a re-link never lowers it).
    pub fn link(&mut self, parent: NodeId, child: NodeId, link_counter: u64) {
        if let Some(existing) = self
            .links
            .iter_mut()
            .find(|l| l.parent == parent && l.child == child)
        {
            existing.link_counter = existing.link_counter.max(link_counter);
            return;
        }
        self.links.push(Link {
            parent,
            child,
            link_counter,
        });
    }

    /// Links `child` under `parent` with a **fresh winning counter** — one
    /// above every existing link to the child — in a single pass. The model
    /// owns the "a newly-established link supersedes prior links" invariant so
    /// callers (create, relink, resurrect) never hand-roll counter allocation.
    pub fn link_next(&mut self, parent: NodeId, child: NodeId) {
        let mut max_counter = 0u64;
        let mut existing: Option<usize> = None;
        for (i, l) in self.links.iter().enumerate() {
            if l.child == child {
                max_counter = max_counter.max(l.link_counter);
                if l.parent == parent {
                    existing = Some(i);
                }
            }
        }
        let next = max_counter + 1;
        match existing {
            Some(i) => self.links[i].link_counter = self.links[i].link_counter.max(next),
            None => self.links.push(Link {
                parent,
                child,
                link_counter: next,
            }),
        }
    }

    /// Removes the link between `parent` and `child`, if any.
    pub fn unlink(&mut self, parent: NodeId, child: NodeId) {
        self.links
            .retain(|l| !(l.parent == parent && l.child == child));
    }

    /// Removes a node and every link that references it (as parent or child).
    pub fn remove_node(&mut self, id: NodeId) {
        self.nodes.remove(&id);
        self.links.retain(|l| l.parent != id && l.child != id);
    }

    /// Every link naming `child` as the child. One entry in a well-formed
    /// snapshot; two on a dual-link crash residue.
    pub fn links_to(&self, child: NodeId) -> Vec<Link> {
        self.links
            .iter()
            .copied()
            .filter(|l| l.child == child)
            .collect()
    }

    /// The child's effective parent: the winning link's parent on a dual-link
    /// (highest counter, then lowest parent id). `None` for the root or an
    /// unlinked node.
    pub fn parent_of(&self, child: NodeId) -> Option<NodeId> {
        self.winning_link(child).map(|l| l.parent)
    }

    /// The winning link for a child under the dual-link tiebreak.
    pub fn winning_link(&self, child: NodeId) -> Option<Link> {
        self.links
            .iter()
            .filter(|l| l.child == child)
            .copied()
            .max_by(|a, b| {
                a.link_counter
                    .cmp(&b.link_counter)
                    .then(b.parent.cmp(&a.parent))
            })
    }

    /// The children linked under `parent`, deterministically ordered by child
    /// id. Dual-linked children appear under every parent that links them
    /// (the residue [`observed_repair`](crate::sync::rebase::observed_repair)
    /// heals).
    pub fn children(&self, parent: NodeId) -> Vec<&NodeMeta> {
        let mut ids: Vec<NodeId> = self
            .links
            .iter()
            .filter(|l| l.parent == parent)
            .map(|l| l.child)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids.into_iter()
            .filter_map(|id| self.nodes.get(&id))
            .collect()
    }

    /// The ancestor chain from `node`'s parent up to and including the root,
    /// nearest first. Empty for the root. Cycle-guarded (a malformed cycle
    /// terminates rather than looping).
    pub fn ancestors(&self, node: NodeId) -> Vec<NodeId> {
        let mut chain = Vec::new();
        let mut seen = vec![node];
        let mut current = node;
        while let Some(parent) = self.parent_of(current) {
            if seen.contains(&parent) {
                break;
            }
            chain.push(parent);
            seen.push(parent);
            current = parent;
        }
        chain
    }

    /// Whether `parent` already links a child (other than `exclude`) whose name
    /// folds equal to `name` under the strict comparator — the add/add and
    /// rename collision predicate.
    pub fn name_taken(&self, parent: NodeId, name: &str, exclude: Option<NodeId>) -> bool {
        let key = collation_key(name);
        self.children(parent)
            .into_iter()
            .any(|child| Some(child.id) != exclude && collation_key(&child.name) == key)
    }

    /// The highest `link_counter` currently linking `child` anywhere, or 0.
    pub fn max_link_counter(&self, child: NodeId) -> u64 {
        self.links
            .iter()
            .filter(|l| l.child == child)
            .map(|l| l.link_counter)
            .max()
            .unwrap_or(0)
    }

    /// Every link, for inspection (repair, tests).
    pub fn links(&self) -> &[Link] {
        &self.links
    }
}

/// The single strict name comparator (blueprint/engine.md rebase table:
/// "one strict comparator everywhere … identical at create and merge on all
/// platforms, names stored as-entered"). Case-folded so `Report.txt` and
/// `report.txt` collide; the stored name is never mutated.
///
/// Canonical Unicode NFC normalization is the cross-language KAT'd surface
/// core owns (its `name_cmp` is the wire-order sibling); this engine-side key
/// folds case with the platform-stable Unicode default mapping and is applied
/// identically at create and at merge.
pub fn collation_key(name: &str) -> String {
    name.to_lowercase()
}

/// The auto-suffix for an add/add collision loser: ` (n)` inserted before the
/// extension (`report.txt` → `report (2).txt`; `folder` → `folder (2)`;
/// `.bashrc` → `.bashrc (2)`).
pub fn suffix_name(name: &str, n: u32) -> String {
    match split_extension(name) {
        Some((stem, ext)) => format!("{stem} ({n}).{ext}"),
        None => format!("{name} ({n})"),
    }
}

/// Split a trailing extension: `("report", "txt")` for `report.txt`. `None`
/// when there is no interior dot with a non-empty stem (a dotfile like
/// `.bashrc` has no extension to preserve).
fn split_extension(name: &str) -> Option<(&str, &str)> {
    let dot = name.rfind('.')?;
    let (stem, dot_ext) = name.split_at(dot);
    let ext = &dot_ext[1..];
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some((stem, ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    #[test]
    fn collation_key_folds_case() {
        assert_eq!(collation_key("Report.TXT"), collation_key("report.txt"));
        assert_ne!(collation_key("a"), collation_key("b"));
    }

    #[test]
    fn suffix_preserves_extension() {
        assert_eq!(suffix_name("report.txt", 2), "report (2).txt");
        assert_eq!(suffix_name("folder", 2), "folder (2)");
        assert_eq!(suffix_name(".bashrc", 2), ".bashrc (2)");
        assert_eq!(suffix_name("a.b.c", 3), "a.b (3).c");
    }

    #[test]
    fn parent_and_children_track_links() {
        let mut snap = Snapshot::new(id(0));
        snap.upsert_node(NodeMeta::new(id(1), "a", NodeKind::Folder));
        snap.upsert_node(NodeMeta::new(id(2), "b", NodeKind::File));
        snap.link(id(0), id(1), 1);
        snap.link(id(1), id(2), 1);

        assert_eq!(snap.parent_of(id(2)), Some(id(1)));
        assert_eq!(snap.parent_of(id(1)), Some(id(0)));
        assert_eq!(snap.parent_of(id(0)), None);
        let names: Vec<&str> = snap
            .children(id(1))
            .iter()
            .map(|n| n.name.as_str())
            .collect();
        assert_eq!(names, vec!["b"]);
    }

    #[test]
    fn ancestors_walk_to_root() {
        let mut snap = Snapshot::new(id(0));
        snap.upsert_node(NodeMeta::new(id(1), "a", NodeKind::Folder));
        snap.upsert_node(NodeMeta::new(id(2), "b", NodeKind::Folder));
        snap.link(id(0), id(1), 1);
        snap.link(id(1), id(2), 1);
        assert_eq!(snap.ancestors(id(2)), vec![id(1), id(0)]);
        assert_eq!(snap.ancestors(id(0)), Vec::<NodeId>::new());
    }

    #[test]
    fn dual_link_winner_is_highest_counter() {
        let mut snap = Snapshot::new(id(0));
        snap.upsert_node(NodeMeta::new(id(1), "p1", NodeKind::Folder));
        snap.upsert_node(NodeMeta::new(id(2), "p2", NodeKind::Folder));
        snap.upsert_node(NodeMeta::new(id(3), "c", NodeKind::File));
        snap.link(id(1), id(3), 1);
        snap.link(id(2), id(3), 2);
        assert_eq!(snap.links_to(id(3)).len(), 2, "residue holds two links");
        assert_eq!(snap.parent_of(id(3)), Some(id(2)), "higher counter wins");
    }

    #[test]
    fn name_taken_folds_and_excludes_self() {
        let mut snap = Snapshot::new(id(0));
        snap.upsert_node(NodeMeta::new(id(1), "Report.txt", NodeKind::File));
        snap.link(id(0), id(1), 1);
        assert!(snap.name_taken(id(0), "report.txt", None));
        assert!(!snap.name_taken(id(0), "report.txt", Some(id(1))));
        assert!(!snap.name_taken(id(0), "other.txt", None));
    }
}
