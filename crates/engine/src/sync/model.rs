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
use std::collections::{BTreeMap, HashSet};

use caseless::Caseless;
use cipherbox_core::codec::{RedactedBytes, RedactedText};
use cipherbox_core::hex::lower as hex_lower;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::facade::{NodeId, NodeKind};
use crate::name::{MAX_NODE_NAME_BYTES, is_emittable, strip_deceptive};

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

    /// Removes a node and every link that references it (as parent or child),
    /// reporting whether the node was there to remove.
    ///
    /// Shallow, and private for it: a node going away for good wants
    /// [`remove_deleted`](Self::remove_deleted) or
    /// [`remove_unreachable`](Self::remove_unreachable), which take the subtree
    /// too. Neither leaves a node behind that no walk reaches.
    fn remove_node(&mut self, id: NodeId) -> bool {
        let present = self.nodes.remove(&id).is_some();
        self.links.retain(|l| l.parent != id && l.child != id);
        present
    }

    /// Removes `id` and every node that only `id` reached — the cascade an
    /// unlink owes, so a detached subtree does not survive as parentless nodes
    /// no walk can reach. A node another link still names is kept, and so is
    /// everything under it.
    ///
    /// Reports the ids that actually left, in removal order: the cascade keeps
    /// nodes the caller named, and takes nodes it did not.
    ///
    /// Call it where the node is already unlinked.
    pub fn remove_unreachable(&mut self, id: NodeId) -> Vec<NodeId> {
        let mut removed = Vec::new();
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
            if self.remove_node(node) {
                removed.push(node);
            }
            pending.extend(orphaned);
        }
        removed
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

    /// Moves `target` under `new_parent` and vacates the node it replaces, in
    /// the one order both are safe in. The model owns the order so no caller
    /// can get it wrong: a vacate is a delete
    /// ([`remove_deleted`](Self::remove_deleted)), and the replaced node may be
    /// the target's own ancestor, so a cascade taken first would sweep the
    /// target out with it.
    ///
    /// The dest link is established before the source link departs, which is
    /// what [`link_next`](Self::link_next) needs to see the counter it must
    /// beat — a source-remove that has not published yet then loses the
    /// dual-link tiebreak instead of drawing with the winner.
    ///
    /// `vacating` must already be a child of `new_parent`; the callers prove it
    /// (`crate::sync::rebase::rebase_move`).
    pub fn relocate(&mut self, target: NodeId, new_parent: NodeId, vacating: Option<NodeId>) {
        let current = self.parent_of(target);
        if current != Some(new_parent) {
            self.link_next(new_parent, target);
            if let Some(current) = current {
                self.unlink(current, target);
            }
        }
        if let Some(replaced) = vacating {
            self.remove_deleted(replaced);
        }
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
        self.links_ranked(child).into_iter().next()
    }

    /// Every link to `child`, winner first, under the one dual-link tiebreak
    /// (highest counter, then lowest parent id).
    ///
    /// A caller that acts on the whole set — a delete unlinks from every parent
    /// — orders it here rather than spelling the comparator again, or the head
    /// of its list stops being the parent readers resolve the child under.
    pub fn links_ranked(&self, child: NodeId) -> Vec<Link> {
        let mut links = self.links_to(child);
        links.sort_by(|a, b| {
            b.link_counter
                .cmp(&a.link_counter)
                .then(a.parent.cmp(&b.parent))
        });
        links
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
/// while rendering identically. NFKC is deliberately not applied — `①` and `1`
/// are names a user can tell apart. The stored name is never mutated.
///
/// Zeroizing because the key is a near-verbatim copy of the name, built per
/// sibling on every lookup. Sized exactly: a growth realloc would free an
/// intermediate holding the name that zeroizing the result cannot reach
/// ([`suffix_name`] pre-sizes for the same reason).
pub fn collation_key(name: &str) -> Zeroizing<String> {
    let folded = || case_fold(name.nfc()).nfc();
    let mut key = Zeroizing::new(String::with_capacity(folded().map(char::len_utf8).sum()));
    key.extend(folded());
    key
}

/// The comparator's fold alone, without either normalization pass — Unicode
/// *full* case folding (`CaseFolding.txt` status `C` and `F`), not a lowercase
/// mapping. The two differ on names users really type: `Σ`, `σ` and final `ς`
/// are one letter to a fold and up to three to a lowercase mapping, and `ſ`
/// folds to `s` where lowercasing leaves it alone.
///
/// Public so `crates/fuse`'s junk filter folds by calling the comparator rather
/// than by re-deriving it — a table revision then moves both at once.
pub fn case_fold<I: Iterator<Item = char>>(chars: I) -> impl Iterator<Item = char> {
    chars.default_case_fold()
}

/// The auto-suffix for a collision loser: ` (n)` inserted before the
/// extension (`report.txt` → `report (2).txt`; `folder` → `folder (2)`;
/// `.bashrc` → `.bashrc (2)`).
///
/// The result always fits [`MAX_NODE_NAME_BYTES`]: the stem is cut on a
/// character boundary first, so a loser at the bound is re-authored under a
/// name the projection can still emit rather than one it drops from every
/// listing.
///
/// Zeroizing for the same reason as [`collation_key`]: the candidate embeds
/// the name verbatim, and a saturated folder builds thousands of them. Built
/// into a buffer sized for the whole candidate up front — `format!` grows its
/// own, and the reallocation frees an intermediate holding the name, which
/// zeroizing the returned value cannot reach.
pub fn suffix_name(name: &str, n: u32) -> Zeroizing<String> {
    insert_before_extension(name, &format!(" ({n})"))
}

/// `suffix` inserted ahead of the extension, inside [`MAX_NODE_NAME_BYTES`].
fn insert_before_extension(name: &str, suffix: &str) -> Zeroizing<String> {
    // The extension is kept only while a byte of stem can survive beside it.
    let (stem, ext) = match split_extension(name)
        .filter(|(_, ext)| suffix.len() + ext.len() + 1 < MAX_NODE_NAME_BYTES)
    {
        Some((stem, ext)) => (stem, Some(ext)),
        None => (name, None),
    };
    let ext_bytes = ext.map_or(0, |ext| ext.len() + 1);
    let room = MAX_NODE_NAME_BYTES.saturating_sub(suffix.len() + ext_bytes);
    let stem = truncate_on_char_boundary(stem, room);
    let mut out = Zeroizing::new(String::with_capacity(stem.len() + suffix.len() + ext_bytes));
    out.push_str(stem);
    out.push_str(suffix);
    if let Some(ext) = ext {
        out.push('.');
        out.push_str(ext);
    }
    out
}

/// The longest prefix of `text` within `max` bytes that is still valid UTF-8.
fn truncate_on_char_boundary(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The highest auto-suffix a collision loser probes — a folder jammed with
/// this many colliding siblings is pathological, not a routine merge.
pub(crate) const MAX_SUFFIX_PROBE: u32 = 10_000;

/// Sibling name material claimed inside one folder — a verbatim copy of every
/// name it holds, so the set wipes what it held rather than freeing it intact.
/// A `HashSet<Zeroizing<String>>` cannot stand in: `Zeroizing` is not `Hash`.
#[derive(Default)]
pub(crate) struct TakenNames(HashSet<String>);

impl TakenNames {
    /// Claims `key`, reporting whether it was still free. The copy is made only
    /// on a real insert: `HashSet::insert` drops the argument when the key is
    /// already held, which would free a verbatim name this set cannot reach.
    pub(crate) fn claim(&mut self, key: &str) -> bool {
        if self.holds(key) {
            return false;
        }
        self.0.insert(key.to_owned())
    }

    /// Whether the key is already claimed.
    pub(crate) fn holds(&self, key: &str) -> bool {
        self.0.contains(key)
    }
}

impl FromIterator<String> for TakenNames {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl Drop for TakenNames {
    fn drop(&mut self) {
        for mut key in self.0.drain() {
            key.zeroize();
        }
    }
}

/// One child as a read plane shows it.
pub(crate) struct RenderedChild<'a> {
    /// The child's stored metadata — never rewritten by the render.
    pub(crate) meta: &'a NodeMeta,
    rendered: Option<Zeroizing<String>>,
}

impl RenderedChild<'_> {
    /// The name this child is shown and resolved under.
    pub(crate) fn name(&self) -> &str {
        shown(self.meta, &self.rendered)
    }
}

/// The name a child is shown under, given whatever the render made of it.
fn shown<'a>(meta: &'a NodeMeta, rendered: &'a Option<Zeroizing<String>>) -> &'a str {
    rendered
        .as_ref()
        .map_or_else(|| meta.name(), |name| name.as_str())
}

/// The name a child enters the render under: its stored name, or a neutralised
/// spelling when the stored name holds a character the law refuses as deceptive
/// ([`crate::name::strip_deceptive`]).
///
/// The strip can leave a name no kernel carries — one built of nothing else —
/// and a listing drops such a name, so that child falls back to its node id and
/// stays removable, the way a share label the law refuses does
/// ([`crate::grants::received_status::grafted_root_name`]).
fn neutralised(meta: &NodeMeta) -> Option<Zeroizing<String>> {
    let stripped = strip_deceptive(meta.name())?;
    Some(if is_emittable(&stripped) {
        stripped
    } else {
        Zeroizing::new(node_id_label(meta.id))
    })
}

/// The children of `parent` as a read plane shows them, ordered by node id: a
/// child an earlier sibling already stores the same **exact** name as renders
/// under the lowest free `name (n)` instead.
///
/// A folder's children are bound on `id` and `ipnsName` and never on `name`
/// (`crates/core/src/seal/body.rs`), so a peer can commit a child under the
/// exact name an owner's child holds. Rendering the later id under its own name
/// keeps both children reachable and tells them apart, with a tiebreak
/// identical on every device. It does not decide *whose* the plain name is: a
/// grantee mints its own ids, so it can sort first and keep it. The stored name
/// is untouched, and a member who renames the loser persists the fix through
/// the normal op path.
///
/// Two spellings that only *fold* equal keep both names, because they are
/// different names to a host that spells one exactly
/// ([`crate::EngineView::lookup`]). Spellings a person cannot tell apart —
/// composed against decomposed, a homoglyph — are that case, so the pass does
/// not separate them. The strict comparator still decides which suffix is free.
pub(crate) fn rendered_children(snapshot: &Snapshot, parent: NodeId) -> Vec<RenderedChild<'_>> {
    let children = snapshot.children(parent);
    let neutral: Vec<Option<Zeroizing<String>>> =
        children.iter().map(|meta| neutralised(meta)).collect();
    // The ordinary folder holds no two children under one name, and this runs
    // on the kernel's readdir and lookup path: borrowed names, no fold, no copy.
    let unique = {
        let mut names: HashSet<&str> = HashSet::with_capacity(children.len());
        children
            .iter()
            .zip(&neutral)
            .all(|(meta, name)| names.insert(shown(meta, name)))
    };
    if unique {
        return children
            .into_iter()
            .zip(neutral)
            .map(|(meta, rendered)| RenderedChild { meta, rendered })
            .collect();
    }
    disambiguate(children, neutral)
}

/// The suffixing pass, over a folder that really holds a duplicate — of a
/// stored name, or of the neutralised spelling a stored name renders under.
fn disambiguate(
    children: Vec<&NodeMeta>,
    neutral: Vec<Option<Zeroizing<String>>>,
) -> Vec<RenderedChild<'_>> {
    let mut folded: TakenNames = children
        .iter()
        .zip(&neutral)
        .map(|(meta, name)| collation_key(shown(meta, name)).to_string())
        .collect();
    let mut floors = SuffixFloors::default();
    children
        .into_iter()
        .zip(neutral)
        .map(|(meta, neutral)| {
            let suffixed = {
                let name = shown(meta, &neutral);
                floors.floor_for(name).map(|from| {
                    match lowest_free_suffix(name, from, &mut folded) {
                        Some((candidate, n)) => {
                            floors.advance(name, n);
                            candidate
                        }
                        None => node_id_name(name, meta.id, &mut folded),
                    }
                })
            };
            RenderedChild {
                meta,
                rendered: suffixed.or(neutral),
            }
        })
        .collect()
}

/// The last-resort rendered name for a twin the numeric probe cannot serve: the
/// child's own node id, which a folder binds unique
/// (`crates/core/src/seal/body.rs`). Leaving such a twin under its stored name
/// instead would put two children back under one name, and the first by id — a
/// grantee's, since it mints them — would take every lookup of it.
fn node_id_name(name: &str, id: NodeId, folded: &mut TakenNames) -> Zeroizing<String> {
    let tagged = insert_before_extension(name, &format!(" {}", node_id_label(id)));
    // A sibling that stored this very spelling still gives way; the id is
    // unique, so numbering off it terminates.
    if folded.claim(&collation_key(&tagged)) {
        return tagged;
    }
    lowest_free_suffix(&tagged, 1, folded).map_or(tagged, |(candidate, _)| candidate)
}

/// The one fallback label for a node no carried name can serve: its own id in
/// brackets. A folder binds `id` unique (`crates/core/src/seal/body.rs`) and the
/// name law admits every spelling of it, so it is safe wherever a name must
/// exist and cannot come from a peer.
pub(crate) fn node_id_label(id: NodeId) -> String {
    format!("[{}]", hex_lower(&id.0))
}

/// The lowest `name (n)`, at or above `from`, that `taken` does not already
/// hold under the strict comparator — claimed, and reported with the index it
/// took. `None` iff the probe is exhausted, which a pathological folder can do;
/// the caller decides what an unresolvable collision means.
///
/// One probe rule for both collision paths: the rebase decides the name a
/// losing op publishes under, and the read plane decides the name a duplicate
/// already in the vault shows under.
pub(crate) fn lowest_free_suffix(
    name: &str,
    from: u32,
    taken: &mut TakenNames,
) -> Option<(Zeroizing<String>, u32)> {
    (from..=MAX_SUFFIX_PROBE).find_map(|n| {
        let candidate = suffix_name(name, n);
        taken
            .claim(&collation_key(&candidate))
            .then_some((candidate, n))
    })
}

/// Where each stored name's next twin starts probing. A folder a peer filled
/// with one name repeated costs O(children) probes this way; probing from 1
/// every time would cost the square of it, on the kernel's own path.
///
/// A verbatim copy of every duplicated name, so it wipes what it held rather
/// than freeing it intact.
#[derive(Default)]
struct SuffixFloors(BTreeMap<String, u32>);

impl SuffixFloors {
    /// Registers `name`. `None` for the first child to store it — that child
    /// keeps the name — and otherwise the suffix index to probe from.
    fn floor_for(&mut self, name: &str) -> Option<u32> {
        match self.0.get(name) {
            Some(floor) => Some(*floor),
            None => {
                self.0.insert(name.to_owned(), 1);
                None
            }
        }
    }

    /// Records the index a twin took, so the next twin starts past it. Every
    /// index below it is claimed, so none of them can come free again.
    fn advance(&mut self, name: &str, taken: u32) {
        if let Some(floor) = self.0.get_mut(name) {
            *floor = taken.saturating_add(1);
        }
    }
}

impl Drop for SuffixFloors {
    fn drop(&mut self) {
        for (mut name, _) in core::mem::take(&mut self.0) {
            name.zeroize();
        }
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

    /// The report is what a caller prunes node-keyed state from, so it must be
    /// the snapshot's own answer: everything the cascade took, nothing it kept,
    /// and no id twice however often the caller names one.
    #[test]
    fn remove_unreachable_reports_the_ids_it_removed() {
        let mut snap = Snapshot::new(id(0));
        folder(&mut snap, id(0), id(1));
        folder(&mut snap, id(1), id(2));
        folder(&mut snap, id(2), id(3));
        folder(&mut snap, id(0), id(4));
        snap.link(id(4), id(3), 2);

        snap.unlink(id(0), id(1));
        let mut removed = snap.remove_unreachable(id(1));
        removed.sort_unstable();
        assert_eq!(
            removed,
            vec![id(1), id(2)],
            "the cascade, less the node the surviving parent keeps"
        );

        assert!(
            snap.remove_unreachable(id(1)).is_empty(),
            "a node already gone was not removed by this call"
        );
        assert!(
            snap.remove_unreachable(id(3)).is_empty(),
            "nor is a node a live link keeps"
        );
    }

    /// The reclamation loop walks a wire-ordered doomed set, and a preorder walk
    /// puts a diamond's child ahead of one of its parents. The child is kept
    /// while that parent stands, so the parent's own removal is the call that
    /// owes the cascade — otherwise the child stays in the snapshot with no link
    /// at all, present and unreachable.
    #[test]
    fn removing_a_diamonds_second_parent_takes_the_child_it_orphans() {
        let mut snap = Snapshot::new(id(0));
        folder(&mut snap, id(0), id(1));
        folder(&mut snap, id(1), id(2));
        folder(&mut snap, id(1), id(3));
        // The diamond: both doomed folders name the same child.
        snap.link(id(3), id(2), 2);

        snap.unlink(id(0), id(1));
        // Wire order: the child first, then the parent that still names it.
        assert!(
            snap.remove_unreachable(id(2)).is_empty(),
            "a parent inside the doomed set still names it"
        );
        let mut removed = snap.remove_unreachable(id(1));
        removed.sort_unstable();

        assert_eq!(removed, vec![id(1), id(2), id(3)]);
        assert!(
            !snap.contains(id(2)),
            "the child does not survive the parent that orphaned it"
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

        // NFKC is *not* applied: a comparator that folded compatibility
        // equivalence would refuse names users can tell apart.
        assert_ne!(collation_key("\u{2460}"), collation_key("1"));
        assert_ne!(collation_key("\u{ff41}"), collation_key("a"));
    }

    /// The comparator's frozen case-fold vectors, beside the NFC ones above:
    /// each family is one name a user can type several ways, and the vault
    /// holds one entry for all of them. A lowercase mapping splits every family
    /// here (blueprint/engine.md rebase table: "NFC-normalized + case-folded").
    #[test]
    fn collation_key_applies_full_case_folding() {
        for (case, family) in [
            // Capital, medial and final sigma are one letter to a fold. A
            // lowercased Greek word ends in the final form, so this is the pair
            // real names hit.
            (
                "greek sigma",
                &["\u{39f}\u{3a3}", "\u{3bf}\u{3c2}", "\u{3bf}\u{3c3}"][..],
            ),
            ("latin long s", &[".d\u{17f}_store", ".ds_store"][..]),
            // Folds that expand one character into two, the `F` mappings a
            // lowercase table has no room to express.
            (
                "latin sharp s",
                &["stra\u{df}e", "STRA\u{1e9e}E", "strasse"][..],
            ),
            // A ligature's case mapping is its two letters, so the case law
            // reaches it. NFKC plays no part: `①` has no case mapping at all,
            // which is what keeps it apart from `1` above.
            ("latin fi ligature", &["\u{fb01}le", "file"][..]),
        ] {
            for pair in family.windows(2) {
                assert_ne!(pair[0], pair[1], "{case}: the inputs differ as bytes");
                assert_eq!(
                    collation_key(pair[0]),
                    collation_key(pair[1]),
                    "{case}: one name, however it was typed"
                );
            }
        }
    }

    /// The exact pre-size is a zeroization invariant, not a micro-optimization:
    /// a growth realloc frees an intermediate holding the name that zeroizing
    /// the returned key cannot reach. The property rests on `String::extend`
    /// reserving the iterator's *lower* size hint, which no test would
    /// otherwise catch changing under a toolchain or table bump.
    #[test]
    fn collation_key_sizes_its_buffer_exactly() {
        for name in [
            "",
            "report.txt",
            "STRA\u{1e9e}E",
            "spi\u{fb03}est",
            "\u{390}",
            "des\u{212a}top.ini",
            "J\u{30c}",
            "\u{3bf}\u{3c2}",
            &"\u{1e9e}".repeat(500),
        ] {
            let key = collation_key(name);
            assert_eq!(
                key.capacity(),
                key.len(),
                "{name:?}: extend grew the buffer past its pre-size"
            );
        }
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

    /// A suffix that pushed the name past the bound would be dropped from every
    /// listing and every lookup by the projection's narrow tier, which loses the
    /// member its own file.
    #[test]
    fn a_suffixed_name_at_the_bound_stays_within_it() {
        for name in [
            "a".repeat(MAX_NODE_NAME_BYTES),
            format!("{}.txt", "a".repeat(MAX_NODE_NAME_BYTES - 4)),
            format!("{}.txt", "é".repeat((MAX_NODE_NAME_BYTES - 4) / 2)),
            format!("a.{}", "e".repeat(MAX_NODE_NAME_BYTES - 2)),
        ] {
            assert!(
                (MAX_NODE_NAME_BYTES - 1..=MAX_NODE_NAME_BYTES).contains(&name.len()),
                "{} does not set up the bound",
                name.len()
            );
            for n in [1, 2, 99, 10_000] {
                let suffixed = suffix_name(&name, n);
                assert!(
                    suffixed.len() <= MAX_NODE_NAME_BYTES,
                    "{n}: {} bytes",
                    suffixed.len()
                );
                assert!(suffixed.contains(&format!(" ({n})")), "the suffix survives");
                assert!(crate::name::is_emittable(&suffixed), "must stay emittable");
            }
        }
    }

    /// The stem is cut on a character boundary, so the result is still UTF-8 —
    /// a name is a CBOR text string and a mid-character cut cannot be encoded.
    #[test]
    fn truncation_cuts_the_stem_on_a_character_boundary() {
        let name = format!("{}.txt", "é".repeat(125));
        let suffixed = suffix_name(&name, 1);
        assert_eq!(*suffixed, format!("{} (1).txt", "é".repeat(123)));
    }

    fn child(snap: &mut Snapshot, parent: NodeId, index: u8, name: &str) {
        snap.upsert_node(NodeMeta::new(id(index), name, NodeKind::File));
        snap.link(parent, id(index), 1);
    }

    fn rendered_names(snap: &Snapshot, parent: NodeId) -> Vec<String> {
        rendered_children(snap, parent)
            .iter()
            .map(|child| child.name().to_owned())
            .collect()
    }

    /// A peer commits any text string, and a host draws a listing as it is
    /// given: one override reorders every name drawn around it.
    #[test]
    fn a_deceptive_stored_name_renders_stripped() {
        let mut snap = Snapshot::new(id(0));
        child(&mut snap, id(0), 1, "invoice\u{202E}cod.exe");

        assert_eq!(rendered_names(&snap, id(0)), ["invoicecod.exe"]);
    }

    /// The strip can leave nothing a kernel carries, and a listing drops such a
    /// name — the child would be unreachable, not merely misdrawn.
    #[test]
    fn a_name_of_nothing_but_deceptive_characters_renders_under_its_node_id() {
        let mut snap = Snapshot::new(id(0));
        child(&mut snap, id(0), 1, "\u{200B}\u{FEFF}");

        assert_eq!(rendered_names(&snap, id(0)), [node_id_label(id(1))]);
    }

    /// The author-time law admits the joiner and the non-joiner, so the render
    /// carries them. Stripping here would deny the same scripts a name again,
    /// one tier down.
    #[test]
    fn the_render_keeps_the_joiner_and_the_non_joiner() {
        let mut snap = Snapshot::new(id(0));
        child(
            &mut snap,
            id(0),
            1,
            "\u{645}\u{6CC}\u{200C}\u{631}\u{648}\u{62F}.txt",
        );
        child(&mut snap, id(0), 2, "crew \u{1F468}\u{200D}\u{1F4BB}");

        assert_eq!(
            rendered_names(&snap, id(0)),
            [
                "\u{645}\u{6CC}\u{200C}\u{631}\u{648}\u{62F}.txt",
                "crew \u{1F468}\u{200D}\u{1F4BB}"
            ]
        );
    }

    /// The two spellings render differently, so a host that spells either one
    /// exactly reaches its own child. Suffixing one would let a grantee who
    /// plants a twin rename its victim's entry.
    #[test]
    fn a_folding_twin_keeps_both_stored_names() {
        let mut snap = Snapshot::new(id(0));
        child(&mut snap, id(0), 1, "\u{fb01}le.txt");
        child(&mut snap, id(0), 2, "file.txt");

        assert_eq!(rendered_names(&snap, id(0)), ["\u{fb01}le.txt", "file.txt"]);
    }

    /// The probe skips a suffix a sibling already holds, however that sibling
    /// spells it — the strict comparator, not byte equality, decides free.
    #[test]
    fn the_probe_steps_over_a_suffix_a_folding_sibling_holds() {
        let mut snap = Snapshot::new(id(0));
        child(&mut snap, id(0), 1, "a.txt");
        child(&mut snap, id(0), 2, "A (1).TXT");
        child(&mut snap, id(0), 3, "a.txt");

        assert_eq!(
            rendered_names(&snap, id(0)),
            ["a.txt", "A (1).TXT", "a (2).txt"]
        );
    }

    /// A peer sizes a folder, so a listing of one name repeated must cost the
    /// read plane a walk, not its square: each twin probes on from where the
    /// last one landed.
    #[test]
    fn a_folder_of_one_repeated_name_renders_in_order() {
        let mut snap = Snapshot::new(id(0));
        for index in 1..=50 {
            child(&mut snap, id(0), index, "a.txt");
        }

        let rendered = rendered_names(&snap, id(0));
        assert_eq!(rendered[0], "a.txt");
        assert_eq!(rendered[49], "a (49).txt");
        assert_eq!(
            rendered
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            50,
            "every twin renders under a name of its own"
        );
    }

    /// A peer sizes the listing, so it can hold more twins than the probe
    /// serves. Falling back to the stored name would put two children under one
    /// name again, and the first by id — the grantee's — would take every
    /// lookup of it.
    #[test]
    fn a_twin_past_the_probe_renders_under_its_node_id() {
        let mut snap = Snapshot::new(id(0));
        // Every numbered candidate the probe would reach is a sibling's own
        // name. These ids all lead with a zero byte, so they sort first.
        for n in 1..=MAX_SUFFIX_PROBE {
            let sibling = NodeId(u128::from(n).to_be_bytes());
            snap.upsert_node(NodeMeta::new(
                sibling,
                suffix_name("a.txt", n).to_string(),
                NodeKind::File,
            ));
            snap.link(id(0), sibling, 1);
        }
        child(&mut snap, id(0), 1, "a.txt");
        child(&mut snap, id(0), 2, "a.txt");

        let rendered = rendered_names(&snap, id(0));
        let twin = rendered.last().expect("the twin");
        assert!(
            twin.contains(&hex_lower(&id(2).0)),
            "{twin:?} must carry the node id"
        );
        assert!(crate::name::is_emittable(twin));
        assert_eq!(
            rendered
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            rendered.len(),
            "no two children render under one name"
        );
    }

    #[test]
    fn the_frozen_collision_vectors_are_the_render() {
        for row in &crate::testkit::name_law::name_law_vectors().collisions {
            let mut snap = Snapshot::new(id(0));
            for (index, name) in row.names.iter().enumerate() {
                let index = u8::try_from(index + 1).expect("a vector row is short");
                child(&mut snap, id(0), index, name);
            }
            assert_eq!(
                rendered_names(&snap, id(0)),
                row.rendered,
                "stored {:?}",
                row.names
            );
            for name in rendered_names(&snap, id(0)) {
                assert!(
                    crate::name::is_emittable(&name),
                    "{name:?} must stay emittable"
                );
            }
        }
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

    /// A delete acts on every link the base holds, so the set is ranked once
    /// here — winner first, so the head is the parent readers resolve the child
    /// under, and so the folder a restore returns it to.
    #[test]
    fn ranked_links_put_the_winner_first() {
        let mut snap = Snapshot::new(id(0));
        for node in [1u8, 2, 3, 4] {
            snap.upsert_node(NodeMeta::new(id(node), "n", NodeKind::Folder));
        }
        snap.upsert_node(NodeMeta::new(id(9), "c", NodeKind::File));
        // scope 1 holds folders 2 and 3; folder 4 hangs off the vault root.
        snap.link(id(0), id(1), 1);
        snap.link(id(1), id(2), 1);
        snap.link(id(1), id(3), 1);
        snap.link(id(0), id(4), 1);
        snap.link(id(2), id(9), 1);
        snap.link(id(3), id(9), 2);
        snap.link(id(4), id(9), 3);

        assert_eq!(
            snap.links_ranked(id(9))
                .into_iter()
                .map(|link| link.parent)
                .collect::<Vec<_>>(),
            vec![id(4), id(3), id(2)],
            "highest counter first",
        );
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
