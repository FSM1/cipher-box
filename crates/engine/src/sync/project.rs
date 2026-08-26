//! Projection of a gate-passing adopted read-body into a facade [`Snapshot`] —
//! one folder's direct children at a time, no recursion, no network, no seams
//! (blueprint/engine.md "Sync core").
//!
//! [`project_folder`] is the single merge model. A snapshot is only ever
//! *merged into*, never rebuilt: the write plane authors below the scope root,
//! and a re-projection of the root that installed a fresh snapshot would delete
//! the deeper tree the drain just published — and with it every queued op that
//! rebases onto a node below depth 1.

use cipherbox_core::seal::{ChildRef, NodeKind as CoreNodeKind, ReadBody};

use crate::facade::{NodeId, NodeKind};
use crate::gate::Adopted;
use crate::sync::model::{NodeMeta, Snapshot};

/// Merge a gate-passing adopted **scope root** body into `snapshot`, reporting
/// whether anything changed. A body that is not a folder leaves the snapshot
/// untouched.
pub(crate) fn project_root(snapshot: &mut Snapshot, root: NodeId, adopted: &Adopted) -> bool {
    match &adopted.read_body {
        ReadBody::Folder {
            modified_at,
            children,
            ..
        } => project_folder(snapshot, root, children, adopted.sequence, *modified_at),
        ReadBody::File { .. } => false,
    }
}

/// Merge one folder's gate-passing children into `snapshot` **in place**,
/// reporting whether the merge changed anything. Children the folder no longer
/// names are unlinked, and dropped with their whole detached subtree once no
/// parent links them ([`Snapshot::remove_unreachable`]) — this is where a delete
/// another device published arrives.
///
/// The change report is what keeps a repeated projection of the same body from
/// repainting the host: the focus-window refresh re-merges a folder every tick.
///
/// Only a gate-passing body reaches here — the gate already enforced child
/// id/ipnsName uniqueness at unseal — so child uniqueness is trusted and not
/// re-validated. `link_counter` merges monotonically per link ([`Snapshot::link`]
/// keeps the higher of the two) and feeds the dual-link tiebreak in
/// [`Snapshot::winning_link`].
///
/// `size`, `mtime`, the content-version count and the child's own record
/// sequence have no `ChildRef` to come from (`crates/core/src/seal/body.rs`: no
/// size/mtime mirrors), so they survive from whatever the snapshot already held;
/// every other field is rebuilt from the body.
pub(crate) fn project_folder(
    snapshot: &mut Snapshot,
    folder: NodeId,
    children: &[ChildRef],
    sequence: u64,
    modified_at: u64,
) -> bool {
    let mut changed = false;
    if let Some(node) = snapshot.node_mut(folder) {
        changed |= node.record_sequence != sequence || node.mtime != Some(modified_at);
        node.record_sequence = sequence;
        node.mtime = Some(modified_at);
    }

    let departed: Vec<NodeId> = snapshot
        .children(folder)
        .into_iter()
        .map(|node| node.id)
        .filter(|id| !children.iter().any(|child| child.id == id.0))
        .collect();
    changed |= !departed.is_empty();
    for id in departed {
        snapshot.unlink(folder, id);
        snapshot.remove_unreachable(id);
    }

    for child in children {
        let id = NodeId(child.id);
        let mut meta = NodeMeta::new(id, child.name.clone(), map_kind(child.kind));
        meta.ipns_name = Some(child.ipns_name.clone());
        if let Some(prior) = snapshot.node(id) {
            meta.size = prior.size;
            meta.mtime = prior.mtime;
            meta.content_version = prior.content_version;
            meta.head_content_cid = prior.head_content_cid.clone();
            meta.record_sequence = prior.record_sequence;
        }
        changed |= snapshot.node(id) != Some(&meta);
        snapshot.upsert_node(meta);
        changed |= snapshot.link(folder, id, child.link_counter);
    }
    changed
}

/// Fold a verified file read-body's plaintext `(size, mtime)`, version count and
/// head `contentCid` into the base node. Returns whether any value actually
/// changed, so the caller repaints only on a real change (a repeat read of the
/// same version is a no-op).
///
/// `head_content_cid` is `None` only for a file with no published version.
pub(crate) fn project_child_version(
    snapshot: &mut Snapshot,
    node: NodeId,
    size: u64,
    mtime: u64,
    version_count: u64,
    head_content_cid: Option<&[u8]>,
) -> bool {
    let Some(meta) = snapshot.node_mut(node) else {
        return false;
    };
    let head = head_content_cid.map(<[u8]>::to_vec);
    let changed = meta.size != Some(size)
        || meta.mtime != Some(mtime)
        || meta.content_version != Some(version_count)
        || meta.head_content_cid != head;
    meta.size = Some(size);
    meta.mtime = Some(mtime);
    meta.content_version = Some(version_count);
    meta.head_content_cid = head;
    changed
}

/// Map the core wire node kind onto the structurally-identical facade kind.
fn map_kind(kind: CoreNodeKind) -> NodeKind {
    match kind {
        CoreNodeKind::Folder => NodeKind::Folder,
        CoreNodeKind::File => NodeKind::File,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::seal::{ChildRef, PreservedFields};

    fn node_id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    fn child(id: u8, name: &str, kind: CoreNodeKind, link_counter: u64) -> ChildRef {
        ChildRef {
            id: [id; 16],
            name: name.to_string(),
            ipns_name: vec![id],
            kind,
            link_counter,
            unknown: PreservedFields::new(),
        }
    }

    /// Project with nothing to merge over — the cold-start shape.
    fn project_fresh(root: NodeId, adopted: &Adopted) -> Snapshot {
        let mut snapshot = Snapshot::new(root);
        project_root(&mut snapshot, root, adopted);
        snapshot
    }

    fn adopted_folder(children: Vec<ChildRef>, sequence: u64) -> Adopted {
        Adopted {
            read_body: ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children,
                unknown: PreservedFields::new(),
            },
            sequence,
            epoch: 0,
        }
    }

    #[test]
    fn project_root_lifts_direct_children_only() {
        let root = node_id(0);
        let adopted = adopted_folder(
            vec![
                child(1, "a", CoreNodeKind::Folder, 1),
                child(2, "b.txt", CoreNodeKind::File, 1),
            ],
            5,
        );

        let snap = project_fresh(root, &adopted);

        let kids = snap.children(root);
        let by: Vec<(NodeId, &str, NodeKind)> =
            kids.iter().map(|n| (n.id, n.name(), n.kind)).collect();
        assert_eq!(
            by,
            vec![
                (node_id(1), "a", NodeKind::Folder),
                (node_id(2), "b.txt", NodeKind::File),
            ]
        );
        assert_eq!(snap.parent_of(node_id(1)), Some(root));
        assert_eq!(snap.parent_of(node_id(2)), Some(root));
    }

    #[test]
    fn project_root_reports_a_change_only_when_the_body_moves_the_base() {
        let root = node_id(0);
        let first = adopted_folder(vec![child(1, "a", CoreNodeKind::Folder, 1)], 5);
        let mut snap = Snapshot::new(root);

        assert!(
            project_root(&mut snap, root, &first),
            "the first projection"
        );
        assert!(
            !project_root(&mut snap, root, &first),
            "the identical body repaints nothing"
        );
        assert!(
            !project_root(
                &mut snap,
                root,
                &adopted_folder(vec![child(1, "a", CoreNodeKind::Folder, 0)], 5),
            ),
            "a lower link counter is a monotonic no-op, not a change"
        );
        assert!(
            project_root(
                &mut snap,
                root,
                &adopted_folder(vec![child(1, "renamed", CoreNodeKind::Folder, 1)], 5),
            ),
            "a renamed child is a change"
        );
        assert!(
            project_root(&mut snap, root, &adopted_folder(vec![], 5)),
            "a departed child is a change"
        );
        assert!(
            !project_root(
                &mut snap,
                root,
                &Adopted {
                    read_body: ReadBody::File {
                        created_at: 0,
                        modified_at: 0,
                        versions: Vec::new(),
                        unknown: PreservedFields::new(),
                    },
                    sequence: 9,
                    epoch: 0,
                },
            ),
            "a non-folder body leaves the snapshot untouched"
        );
    }

    #[test]
    fn project_root_carries_link_counter_for_dual_link_tiebreak() {
        let root = node_id(0);
        let adopted = adopted_folder(
            vec![
                child(1, "a", CoreNodeKind::Folder, 7),
                child(2, "b", CoreNodeKind::File, 3),
            ],
            1,
        );

        let snap = project_fresh(root, &adopted);

        assert_eq!(snap.max_link_counter(node_id(1)), 7);
        assert_eq!(snap.max_link_counter(node_id(2)), 3);
    }

    #[test]
    fn project_root_sets_root_sequence() {
        let root = node_id(0);
        let adopted = adopted_folder(vec![], 42);

        let snap = project_fresh(root, &adopted);

        assert_eq!(snap.record_sequence(root), Some(42));
    }

    #[test]
    fn project_root_carries_child_ipns_name_verbatim() {
        let root = node_id(0);
        let adopted = adopted_folder(vec![child(1, "a", CoreNodeKind::File, 1)], 1);

        let snap = project_fresh(root, &adopted);

        assert_eq!(
            snap.node(node_id(1)).unwrap().ipns_name,
            Some(vec![1]),
            "the ChildRef ipnsName rides into the projected meta"
        );
    }

    #[test]
    fn project_child_version_reports_change_once() {
        let root = node_id(0);
        let adopted = adopted_folder(vec![child(1, "a", CoreNodeKind::File, 1)], 1);
        let mut snap = project_fresh(root, &adopted);

        assert!(project_child_version(
            &mut snap,
            node_id(1),
            10,
            99,
            3,
            Some(b"cid")
        ));
        assert_eq!(snap.node(node_id(1)).unwrap().size, Some(10));
        assert_eq!(snap.node(node_id(1)).unwrap().mtime, Some(99));
        assert_eq!(snap.node(node_id(1)).unwrap().content_version, Some(3));
        // The identical fold changes nothing; a differing one does.
        assert!(!project_child_version(
            &mut snap,
            node_id(1),
            10,
            99,
            3,
            Some(b"cid")
        ));
        assert!(project_child_version(
            &mut snap,
            node_id(1),
            11,
            99,
            3,
            Some(b"cid")
        ));
        // A new version alone is a change.
        assert!(project_child_version(
            &mut snap,
            node_id(1),
            11,
            99,
            4,
            Some(b"cid")
        ));
        // An absent node folds nothing.
        assert!(!project_child_version(
            &mut snap,
            node_id(7),
            1,
            1,
            1,
            Some(b"cid")
        ));
    }

    #[test]
    fn re_projection_carries_forward_only_what_the_root_body_cannot_express() {
        let root = node_id(0);
        let first = adopted_folder(vec![child(1, "a.txt", CoreNodeKind::File, 1)], 1);
        let mut previous = project_fresh(root, &first);
        assert!(project_child_version(
            &mut previous,
            node_id(1),
            2_048,
            500,
            2,
            Some(b"cid")
        ));

        // The same child renamed, re-linked and re-kinded by the newer body.
        let next = adopted_folder(vec![child(1, "renamed.txt", CoreNodeKind::Folder, 9)], 2);
        let mut snap = previous;
        project_root(&mut snap, root, &next);

        let meta = snap.node(node_id(1)).unwrap();
        assert_eq!(meta.size, Some(2_048), "size has no ChildRef to come from");
        assert_eq!(meta.mtime, Some(500), "mtime has no ChildRef to come from");
        assert_eq!(meta.content_version, Some(2), "the version count carries");
        assert_eq!(meta.name(), "renamed.txt", "the body owns the name");
        assert_eq!(meta.kind, NodeKind::Folder, "the body owns the kind");
        assert_eq!(snap.max_link_counter(node_id(1)), 9, "the body owns links");
        assert_eq!(
            snap.record_sequence(root),
            Some(2),
            "the body owns sequence"
        );
    }

    #[test]
    fn re_projection_drops_the_carried_values_of_a_departed_node() {
        let root = node_id(0);
        let first = adopted_folder(vec![child(1, "a.txt", CoreNodeKind::File, 1)], 1);
        let mut previous = project_fresh(root, &first);
        assert!(project_child_version(
            &mut previous,
            node_id(1),
            2_048,
            500,
            2,
            Some(b"cid")
        ));

        // The child left the root body; it takes its projected values with it.
        let mut snap = previous;
        project_root(&mut snap, root, &adopted_folder(vec![], 2));

        assert!(!snap.contains(node_id(1)));

        // And a re-appearance is a fresh projection, not a resurrection.
        let back = adopted_folder(vec![child(1, "a.txt", CoreNodeKind::File, 1)], 3);
        project_root(&mut snap, root, &back);
        let meta = snap.node(node_id(1)).unwrap();
        assert_eq!(meta.size, None);
        assert_eq!(meta.mtime, None);
        assert_eq!(meta.content_version, None);
    }

    /// A delete another device published arrives as a departed child. The
    /// subtree under it goes with it, or the snapshot keeps nodes no walk from
    /// the root can reach.
    #[test]
    fn a_departed_folder_takes_its_whole_subtree() {
        let root = node_id(0);
        let mut snap = project_fresh(
            root,
            &adopted_folder(vec![child(1, "dir", CoreNodeKind::Folder, 1)], 1),
        );
        project_folder(
            &mut snap,
            node_id(1),
            &[child(2, "sub", CoreNodeKind::Folder, 1)],
            1,
            0,
        );
        project_folder(
            &mut snap,
            node_id(2),
            &[child(3, "deep.txt", CoreNodeKind::File, 1)],
            1,
            0,
        );

        assert!(project_root(&mut snap, root, &adopted_folder(vec![], 2)));

        assert!(!snap.contains(node_id(1)));
        assert!(!snap.contains(node_id(2)), "the descendant folder");
        assert!(!snap.contains(node_id(3)), "the descendant file");
        assert!(snap.links().is_empty(), "and every link under them");
    }

    #[test]
    fn a_departed_folder_leaves_what_another_parent_still_links() {
        let root = node_id(0);
        let mut snap = project_fresh(
            root,
            &adopted_folder(
                vec![
                    child(1, "dir", CoreNodeKind::Folder, 1),
                    child(4, "keeper", CoreNodeKind::Folder, 1),
                ],
                1,
            ),
        );
        project_folder(
            &mut snap,
            node_id(1),
            &[child(2, "shared.txt", CoreNodeKind::File, 1)],
            1,
            0,
        );
        project_folder(
            &mut snap,
            node_id(4),
            &[child(2, "shared.txt", CoreNodeKind::File, 2)],
            1,
            0,
        );

        project_root(
            &mut snap,
            root,
            &adopted_folder(vec![child(4, "keeper", CoreNodeKind::Folder, 1)], 2),
        );

        assert!(!snap.contains(node_id(1)));
        assert!(
            snap.contains(node_id(2)),
            "a node the surviving parent still links is live"
        );
        assert_eq!(snap.parent_of(node_id(2)), Some(node_id(4)));
    }

    #[test]
    fn project_root_sets_root_mtime_from_modified_at() {
        let root = node_id(0);
        let adopted = Adopted {
            read_body: ReadBody::Folder {
                created_at: 5,
                modified_at: 777,
                children: Vec::new(),
                unknown: PreservedFields::new(),
            },
            sequence: 1,
            epoch: 0,
        };

        let snap = project_fresh(root, &adopted);

        assert_eq!(snap.node(root).unwrap().mtime, Some(777));
        assert_eq!(snap.node(root).unwrap().size, None);
    }
}
