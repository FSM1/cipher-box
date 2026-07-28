//! Projection of a gate-passing adopted root read-body into a facade
//! [`Snapshot`] — direct children only, no recursion, no network, no seams
//! (blueprint/engine.md "Sync core"; the deeper content-plane assembly is a
//! later slice).

use cipherbox_core::seal::{NodeKind as CoreNodeKind, ReadBody};

use crate::facade::{NodeId, NodeKind};
use crate::gate::Adopted;
use crate::sync::model::{NodeMeta, Snapshot};

/// Project a gate-passing adopted root read-body into a [`Snapshot`] holding
/// the root and its **direct** children, merged over `previous`. Pure: the
/// child read-bodies (and thus the deeper tree) are not fetched here.
///
/// Only a gate-passing [`Adopted`] reaches this fn — the gate already enforced
/// child id/ipnsName uniqueness at unseal — so child uniqueness is trusted and
/// not re-validated. `link_counter` is carried verbatim (feeds the dual-link
/// tiebreak in [`Snapshot::winning_link`]).
///
/// `size`, `mtime` and the content-version count have no `ChildRef` to come
/// from (`crates/core/src/seal/body.rs`: no size/mtime mirrors), so they carry
/// forward from `previous`; every other field is rebuilt from the adopted body.
pub(crate) fn project_root(root: NodeId, adopted: &Adopted, previous: &Snapshot) -> Snapshot {
    let mut snapshot = Snapshot::new(root);
    if let Some(node) = snapshot.node_mut(root) {
        node.record_sequence = adopted.sequence;
    }

    if let ReadBody::Folder {
        modified_at,
        children,
        ..
    } = &adopted.read_body
    {
        if let Some(node) = snapshot.node_mut(root) {
            node.mtime = Some(*modified_at);
        }
        for child in children {
            let id = NodeId(child.id);
            let mut meta = NodeMeta::new(id, child.name.clone(), map_kind(child.kind));
            meta.ipns_name = Some(child.ipns_name.clone());
            if let Some(prior) = previous.node(id) {
                meta.size = prior.size;
                meta.mtime = prior.mtime;
                meta.content_version = prior.content_version;
            }
            snapshot.upsert_node(meta);
            snapshot.link(root, id, child.link_counter);
        }
    }

    snapshot
}

/// Fold a verified file read-body's plaintext `(size, mtime)` and version count
/// into the base node. Returns whether any value actually changed, so the caller
/// repaints only on a real change (a repeat read of the same version is a no-op).
pub(crate) fn project_child_version(
    snapshot: &mut Snapshot,
    node: NodeId,
    size: u64,
    mtime: u64,
    version_count: u64,
) -> bool {
    let Some(meta) = snapshot.node_mut(node) else {
        return false;
    };
    let changed = meta.size != Some(size)
        || meta.mtime != Some(mtime)
        || meta.content_version != Some(version_count);
    meta.size = Some(size);
    meta.mtime = Some(mtime);
    meta.content_version = Some(version_count);
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
    use cipherbox_core::seal::ChildRef;

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
            unknown: Vec::new(),
        }
    }

    /// Project with nothing to merge over — the cold-start shape.
    fn project_fresh(root: NodeId, adopted: &Adopted) -> Snapshot {
        project_root(root, adopted, &Snapshot::new(root))
    }

    fn adopted_folder(children: Vec<ChildRef>, sequence: u64) -> Adopted {
        Adopted {
            read_body: ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children,
                unknown: Vec::new(),
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
        let by: Vec<(NodeId, &str, NodeKind)> = kids
            .iter()
            .map(|n| (n.id, n.name.as_str(), n.kind))
            .collect();
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

        assert!(project_child_version(&mut snap, node_id(1), 10, 99, 3));
        assert_eq!(snap.node(node_id(1)).unwrap().size, Some(10));
        assert_eq!(snap.node(node_id(1)).unwrap().mtime, Some(99));
        assert_eq!(snap.node(node_id(1)).unwrap().content_version, Some(3));
        // The identical fold changes nothing; a differing one does.
        assert!(!project_child_version(&mut snap, node_id(1), 10, 99, 3));
        assert!(project_child_version(&mut snap, node_id(1), 11, 99, 3));
        // A new version alone is a change.
        assert!(project_child_version(&mut snap, node_id(1), 11, 99, 4));
        // An absent node folds nothing.
        assert!(!project_child_version(&mut snap, node_id(7), 1, 1, 1));
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
            2
        ));

        // The same child renamed, re-linked and re-kinded by the newer body.
        let next = adopted_folder(vec![child(1, "renamed.txt", CoreNodeKind::Folder, 9)], 2);
        let snap = project_root(root, &next, &previous);

        let meta = snap.node(node_id(1)).unwrap();
        assert_eq!(meta.size, Some(2_048), "size has no ChildRef to come from");
        assert_eq!(meta.mtime, Some(500), "mtime has no ChildRef to come from");
        assert_eq!(meta.content_version, Some(2), "the version count carries");
        assert_eq!(meta.name, "renamed.txt", "the body owns the name");
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
            2
        ));

        // The child left the root body; it takes its projected values with it.
        let snap = project_root(root, &adopted_folder(vec![], 2), &previous);

        assert!(!snap.contains(node_id(1)));

        // And a re-appearance is a fresh projection, not a resurrection.
        let back = adopted_folder(vec![child(1, "a.txt", CoreNodeKind::File, 1)], 3);
        let snap = project_root(root, &back, &snap);
        let meta = snap.node(node_id(1)).unwrap();
        assert_eq!(meta.size, None);
        assert_eq!(meta.mtime, None);
        assert_eq!(meta.content_version, None);
    }

    #[test]
    fn project_root_sets_root_mtime_from_modified_at() {
        let root = node_id(0);
        let adopted = Adopted {
            read_body: ReadBody::Folder {
                created_at: 5,
                modified_at: 777,
                children: Vec::new(),
                unknown: Vec::new(),
            },
            sequence: 1,
            epoch: 0,
        };

        let snap = project_fresh(root, &adopted);

        assert_eq!(snap.node(root).unwrap().mtime, Some(777));
        assert_eq!(snap.node(root).unwrap().size, None);
    }
}
