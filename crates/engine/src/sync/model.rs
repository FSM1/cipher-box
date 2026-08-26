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

use core::fmt;
use std::collections::BTreeMap;

use cipherbox_core::codec::{RedactedBytes, RedactedText};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::facade::{NodeId, NodeKind};

/// One node's metadata in the working tree.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct NodeMeta {
    /// Location-independent node id.
    #[zeroize(skip)]
    pub id: NodeId,
    /// The display name, stored **as entered** (uniqueness folds via
    /// [`collation_key`]; the stored name is never mutated for comparison).
    ///
    /// Private so [`Self::rename`] is the only way to replace it: a field
    /// assignment would drop the superseded `String` intact.
    name: String,
    /// File or folder.
    #[zeroize(skip)]
    pub kind: NodeKind,
    /// The node's own IPNS record sequence — the conditional-delete snapshot
    /// (a delete op drops on rebase if this advanced past the op's snapshot).
    pub record_sequence: u64,
    /// The node's retained version count, projected from the file read-body's
    /// `versions` list and bumped on every queued `updateContent` (a fresh
    /// per-version content key seals each version, CONTEXT.md "Content key").
    /// `None` until projected — unprojected is not zero.
    pub content_version: Option<u64>,
    /// The `contentCid` of the head version, projected with the count — the
    /// conditional-edit anchor an `updateContent` is formed against. `None`
    /// while unprojected **and** for a file with no published version, which
    /// the count tells apart.
    #[zeroize(skip)]
    pub head_content_cid: Option<Vec<u8>>,
    /// Plaintext content size in bytes; `None` until the content plane
    /// projects it.
    pub size: Option<u64>,
    /// Modification time (Unix millis) from the sealed read-body; `None`
    /// until projected.
    pub mtime: Option<u64>,
    /// The node's opaque `ipnsName` bytes as carried by its parent's
    /// `ChildRef`; `None` for nodes not yet in gate-passing state.
    #[zeroize(skip)]
    pub ipns_name: Option<Vec<u8>>,
}

impl fmt::Debug for NodeMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeMeta")
            .field("id", &self.id)
            .field("name", &RedactedText::of(&self.name))
            .field("kind", &self.kind)
            .field("record_sequence", &self.record_sequence)
            .field("content_version", &self.content_version)
            .field("head_content_cid", &self.head_content_cid)
            .field("size", &self.size)
            .field("mtime", &self.mtime)
            .field(
                "ipns_name",
                &self.ipns_name.as_deref().map(RedactedBytes::of),
            )
            .finish()
    }
}

impl NodeMeta {
    /// A node at record sequence 1, with no projected content
    /// version/size/mtime/ipnsName.
    pub fn new(id: NodeId, name: impl Into<String>, kind: NodeKind) -> Self {
        Self {
            id,
            name: name.into(),
            kind,
            record_sequence: 1,
            content_version: None,
            head_content_cid: None,
            size: None,
            mtime: None,
            ipns_name: None,
        }
    }

    /// The display name, as entered.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Replace the display name, wiping the one it supersedes.
    pub fn rename(&mut self, name: impl Into<String>) {
        self.name.zeroize();
        self.name = name.into();
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

    /// Adds a parent→child link, reporting whether the link was established or
    /// its counter raised. Idempotent on `(parent, child)`: a repeat keeps the
    /// higher `link_counter` (a re-link never lowers it).
    pub fn link(&mut self, parent: NodeId, child: NodeId, link_counter: u64) -> bool {
        if let Some(existing) = self
            .links
            .iter_mut()
            .find(|l| l.parent == parent && l.child == child)
        {
            let raised = existing.link_counter < link_counter;
            existing.link_counter = existing.link_counter.max(link_counter);
            return raised;
        }
        self.links.push(Link {
            parent,
            child,
            link_counter,
        });
        true
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

    /// Removes `id` and every node that only `id` reached — the cascade an
    /// unlink owes, so a detached subtree does not survive as parentless nodes
    /// no walk can reach. A node another link still names is kept, and so is
    /// everything under it.
    ///
    /// Call it where the node is already unlinked.
    pub fn remove_unreachable(&mut self, id: NodeId) {
        let mut pending = vec![id];
        while let Some(node) = pending.pop() {
            if node == self.root || self.links.iter().any(|l| l.child == node) {
                continue;
            }
            let orphaned: Vec<NodeId> = self
                .links
                .iter()
                .filter(|l| l.parent == node)
                .map(|l| l.child)
                .collect();
            self.remove_node(node);
            pending.extend(orphaned);
        }
    }

    /// Removes `id` as a **delete** does: detached from every parent that names
    /// it, and taking with it every node only `id` reached.
    ///
    /// The same cascade the observed-remote direction reaches through
    /// [`unlink`](Self::unlink) then [`remove_unreachable`](Self::remove_unreachable),
    /// where only the shortened parent's ref departed. Here the node itself is
    /// going, so a dual-link residue must not keep it — or its subtree — alive.
    pub fn remove_deleted(&mut self, id: NodeId) {
        self.links.retain(|l| l.child != id);
        self.remove_unreachable(id);
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

    /// Whether `node` sits anywhere under `ancestor`, walking parent links up
    /// from `node`. A node is not its own ancestor.
    ///
    /// Cheaper than scanning [`ancestors`](Self::ancestors), which allocates the
    /// whole chain, and it stops at the first match.
    pub fn is_descendant_of(&self, node: NodeId, ancestor: NodeId) -> bool {
        let mut seen = vec![node];
        let mut current = node;
        while let Some(parent) = self.parent_of(current) {
            // The cycle guard runs first: a link cycle that walks back to `node`
            // must not answer that it is its own ancestor.
            if seen.contains(&parent) {
                return false;
            }
            if parent == ancestor {
                return true;
            }
            seen.push(parent);
            current = parent;
        }
        false
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
/// "one strict comparator everywhere — NFC-normalized + case-folded, identical
/// at create and merge on all platforms, names stored as-entered").
///
/// Canonical composition runs before the fold, so `café` composed and
/// decomposed key the same, and **again after** it, because the case map is not
/// closed under canonical equivalence: `J` + U+030C folds to a decomposed `ǰ`
/// whose precomposed twin U+01F0 folds to itself, and the two would key apart
/// while rendering identically. Compatibility equivalence is deliberately not
/// folded — `ﬁle` and `file` are names a user can tell apart. The stored name
/// is never mutated.
///
/// Zeroizing because the key is a near-verbatim copy of the name, built per
/// sibling on every lookup. Sized exactly: a growth realloc would free an
/// intermediate holding the name that zeroizing the result cannot reach
/// ([`suffix_name`] pre-sizes for the same reason).
pub fn collation_key(name: &str) -> Zeroizing<String> {
    let folded = || name.nfc().flat_map(char::to_lowercase).nfc();
    let mut key = Zeroizing::new(String::with_capacity(folded().map(char::len_utf8).sum()));
    key.extend(folded());
    key
}

/// The auto-suffix for an add/add collision loser: ` (n)` inserted before the
/// extension (`report.txt` → `report (2).txt`; `folder` → `folder (2)`;
/// `.bashrc` → `.bashrc (2)`).
/// Zeroizing for the same reason as [`collation_key`]: the candidate embeds
/// the name verbatim, and a saturated folder builds thousands of them.
///
/// Built into a buffer sized for the whole candidate up front. `format!` grows
/// its own, and the reallocation frees an intermediate holding the name — which
/// zeroizing the returned value cannot reach.
pub fn suffix_name(name: &str, n: u32) -> Zeroizing<String> {
    let suffix = format!(" ({n})");
    let mut out = Zeroizing::new(String::with_capacity(name.len() + suffix.len()));
    match split_extension(name) {
        Some((stem, ext)) => {
            out.push_str(stem);
            out.push_str(&suffix);
            out.push('.');
            out.push_str(ext);
        }
        None => {
            out.push_str(name);
            out.push_str(&suffix);
        }
    }
    out
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

    fn folder(snapshot: &mut Snapshot, parent: NodeId, child: NodeId) {
        snapshot.upsert_node(NodeMeta::new(child, "n", NodeKind::Folder));
        snapshot.link(parent, child, 1);
    }

    #[test]
    fn remove_unreachable_takes_the_cascade_and_stops_at_a_live_edge() {
        let mut snap = Snapshot::new(id(0));
        folder(&mut snap, id(0), id(1));
        folder(&mut snap, id(1), id(2));
        folder(&mut snap, id(2), id(3));
        folder(&mut snap, id(0), id(4));
        // A node under the doomed subtree that another live parent also links.
        snap.link(id(4), id(3), 2);

        snap.unlink(id(0), id(1));
        snap.remove_unreachable(id(1));

        assert!(!snap.contains(id(1)));
        assert!(!snap.contains(id(2)));
        assert!(
            snap.contains(id(3)),
            "still linked from the surviving parent"
        );
        assert_eq!(snap.parent_of(id(3)), Some(id(4)));
    }

    #[test]
    fn remove_unreachable_is_a_no_op_on_a_node_a_parent_still_links() {
        let mut snap = Snapshot::new(id(0));
        folder(&mut snap, id(0), id(1));
        folder(&mut snap, id(1), id(2));

        snap.remove_unreachable(id(1));

        assert!(snap.contains(id(1)), "the root still links it");
        assert!(snap.contains(id(2)));
    }

    /// Child refs are wire data, so a link cycle is reachable; the walk must
    /// terminate rather than chase it.
    #[test]
    fn remove_unreachable_terminates_over_a_detached_cycle() {
        let mut snap = Snapshot::new(id(0));
        folder(&mut snap, id(0), id(1));
        folder(&mut snap, id(1), id(2));
        snap.link(id(2), id(1), 3);

        snap.unlink(id(0), id(1));
        snap.remove_unreachable(id(1));

        assert!(snap.contains(id(1)), "the cycle's own edge still names it");
        assert!(snap.contains(id(0)));
    }

    /// The delete direction takes the node itself, so no surviving link to it
    /// may keep the subtree alive — unlike the observed direction, where a
    /// second parent naming the child is exactly what licenses keeping it.
    #[test]
    fn remove_deleted_detaches_from_every_parent_before_cascading() {
        let mut snap = Snapshot::new(id(0));
        folder(&mut snap, id(0), id(1));
        folder(&mut snap, id(0), id(4));
        folder(&mut snap, id(1), id(2));
        folder(&mut snap, id(2), id(3));
        // A dual-link residue on the delete target itself.
        snap.link(id(4), id(1), 2);

        snap.remove_deleted(id(1));

        assert!(!snap.contains(id(1)), "the residual link does not save it");
        assert!(!snap.contains(id(2)), "nor its descendants");
        assert!(!snap.contains(id(3)));
        assert!(snap.contains(id(4)), "a bystander parent survives");
    }

    #[test]
    fn remove_deleted_keeps_a_descendant_another_parent_still_names() {
        let mut snap = Snapshot::new(id(0));
        folder(&mut snap, id(0), id(1));
        folder(&mut snap, id(1), id(2));
        folder(&mut snap, id(0), id(4));
        snap.link(id(4), id(2), 2);

        snap.remove_deleted(id(1));

        assert!(!snap.contains(id(1)));
        assert_eq!(
            snap.parent_of(id(2)),
            Some(id(4)),
            "still linked from the surviving parent"
        );
    }

    #[test]
    fn remove_unreachable_never_removes_the_root() {
        let mut snap = Snapshot::new(id(0));
        folder(&mut snap, id(0), id(1));

        snap.remove_unreachable(id(0));

        assert!(snap.contains(id(0)));
        assert!(snap.contains(id(1)));
    }

    /// A node's name and its live `ipnsName` are decoded user content; the
    /// rendering keeps the shape and withholds both.
    #[test]
    fn debug_renders_no_name_and_no_ipns_name() {
        let mut meta = NodeMeta::new(id(1), "secret-name.txt", NodeKind::File);
        meta.ipns_name = Some(b"k51qzi5uqu5dksecretname".to_vec());
        let rendered = format!("{meta:?}");

        assert!(
            !rendered.contains("secret-name.txt"),
            "a filename never renders: {rendered}"
        );
        let unredacted = format!("{:?}", meta.ipns_name.as_ref().expect("set above"));
        assert!(
            !rendered.contains(&unredacted),
            "the ipnsName bytes never render: {rendered}"
        );
        assert!(rendered.contains("NodeMeta"), "the shape survives");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn collation_key_folds_case() {
        assert_eq!(collation_key("Report.TXT"), collation_key("report.txt"));
        assert_ne!(collation_key("a"), collation_key("b"));
    }

    /// The comparator's frozen vectors: each pair is one name typed two ways,
    /// and the vault holds one entry for both however a client composed them
    /// (blueprint/engine.md rebase table, blueprint/desktop.md "Names and
    /// attributes"). Written as escapes rather than literals so the file's own
    /// encoding cannot silently normalize a case away.
    #[test]
    fn collation_key_normalizes_to_nfc() {
        for (case, composed, decomposed) in [
            ("latin e-acute", "caf\u{e9}", "cafe\u{301}"),
            ("latin o-diaeresis", "\u{d6}sterreich", "O\u{308}sterreich"),
            (
                "vietnamese e-circumflex-acute",
                "b\u{1ebf}",
                "be\u{302}\u{301}",
            ),
            (
                "hangul syllable gag",
                "\u{ac01}",
                "\u{1100}\u{1161}\u{11a8}",
            ),
            ("hiragana voiced ga", "\u{304c}", "\u{304b}\u{3099}"),
            // The fold's own output must be re-composed: this pair keys apart
            // under an NFC-then-fold that stops there.
            ("j-caron under an uppercase base", "J\u{30c}", "\u{1f0}"),
        ] {
            assert_ne!(composed, decomposed, "{case}: the inputs differ as bytes");
            assert_eq!(
                collation_key(composed),
                collation_key(decomposed),
                "{case}: one name, however it was typed"
            );
        }

        // Compatibility equivalence is *not* folded: NFKC would collapse these,
        // and a comparator that did would refuse names users can tell apart.
        assert_ne!(collation_key("\u{fb01}le"), collation_key("file"));
        assert_ne!(collation_key("\u{2460}"), collation_key("1"));
    }

    /// Normalization runs before the fold, so a decomposed name still collides
    /// with a differently-cased composed sibling.
    #[test]
    fn name_taken_folds_case_across_a_decomposition_boundary() {
        let mut snap = Snapshot::new(id(0));
        snap.upsert_node(NodeMeta::new(id(1), "Cafe\u{301}.txt", NodeKind::File));
        snap.link(id(0), id(1), 1);
        assert!(snap.name_taken(id(0), "caf\u{e9}.txt", None));
        assert!(!snap.name_taken(id(0), "caf\u{e9}.txt", Some(id(1))));
    }

    #[test]
    fn suffix_preserves_extension() {
        assert_eq!(*suffix_name("report.txt", 2), *"report (2).txt");
        assert_eq!(*suffix_name("folder", 2), *"folder (2)");
        assert_eq!(*suffix_name(".bashrc", 2), *".bashrc (2)");
        assert_eq!(*suffix_name("a.b.c", 3), *"a.b (3).c");
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
    /// The predicate the grant path splits a parent's child-scope index on: a
    /// node is not its own ancestor, and a cycle in the links terminates the
    /// walk rather than hanging it.
    #[test]
    fn descent_is_strict_and_cycle_safe() {
        let root = NodeId([0; 16]);
        let mid = NodeId([1; 16]);
        let leaf = NodeId([2; 16]);
        let mut snapshot = Snapshot::new(root);
        snapshot.upsert_node(NodeMeta::new(mid, "mid", NodeKind::Folder));
        snapshot.upsert_node(NodeMeta::new(leaf, "leaf", NodeKind::Folder));
        snapshot.link(root, mid, 1);
        snapshot.link(mid, leaf, 1);

        assert!(snapshot.is_descendant_of(leaf, root));
        assert!(snapshot.is_descendant_of(leaf, mid));
        assert!(!snapshot.is_descendant_of(mid, leaf));
        assert!(
            !snapshot.is_descendant_of(root, root),
            "a node is not its own ancestor"
        );

        // Close a cycle: `mid`'s winning link now comes from its own descendant.
        snapshot.link(leaf, mid, 2);
        assert_eq!(snapshot.parent_of(mid), Some(leaf), "the cycle is linked");
        assert!(
            !snapshot.is_descendant_of(mid, mid),
            "a cycle does not make a node its own ancestor"
        );
        assert!(
            !snapshot.is_descendant_of(mid, root),
            "and the walk terminates rather than looping"
        );
    }
}
