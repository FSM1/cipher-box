//! The state law — rendered state = last-known-good snapshot ⊕ pending-op
//! overlay, single owner (blueprint/engine.md "Sync core: State law",
//! CONTEXT.md "Pending-op overlay").
//!
//! The overlay is the **optimistic local view**: the queued ops are applied on
//! top of the gate-passing snapshot in FIFO order so the UI reflects the user's
//! own pending mutations immediately, before the network confirms them. It is
//! deliberately *not* the rebase ([`crate::sync::rebase`]): it never drops,
//! suffixes, or dead-letters — it renders intent. The op queue is the only
//! local divergence from the remote snapshot.

use crate::sync::model::{NodeMeta, Snapshot};
use crate::sync::op::{Op, OpKind};

/// Apply the pending op queue onto `base` in FIFO order, returning the rendered
/// view. Pure: `base` is untouched.
pub fn apply_overlay(base: &Snapshot, ops: &[Op]) -> Snapshot {
    let mut view = base.clone();
    for op in ops {
        apply_one(&mut view, op);
    }
    view
}

/// Apply one op to the working view optimistically (intent, not rebase).
///
/// Every op but a delete authors its target's next record, so each stamps
/// [`Op::stamp_authored`].
fn apply_one(view: &mut Snapshot, op: &Op) {
    match &op.kind {
        OpKind::Create {
            parent,
            name,
            kind,
            content,
        } => {
            let mut meta = NodeMeta::new(op.target, name.clone(), *kind);
            // A create carrying content authors exactly one version.
            if content.is_some() {
                meta.content_version = Some(1);
            }
            op.stamp_authored(&mut meta);
            view.upsert_node(meta);
            view.link_next(*parent, op.target);
        }
        OpKind::Delete { .. } => {
            view.remove_node(op.target);
        }
        OpKind::Rename { new_name } => {
            if let Some(node) = view.node_mut(op.target) {
                node.name = new_name.clone();
                op.stamp_authored(node);
            }
        }
        OpKind::Relink { new_parent, .. } => {
            if let Some(old_parent) = view.parent_of(op.target) {
                view.unlink(old_parent, op.target);
            }
            view.link_next(*new_parent, op.target);
            if let Some(node) = view.node_mut(op.target) {
                op.stamp_authored(node);
            }
        }
        OpKind::UpdateContent { .. } => {
            if let Some(node) = view.node_mut(op.target) {
                node.content_version = node.content_version.map(|count| count + 1);
                op.stamp_authored(node);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade::{NodeId, NodeKind};
    use crate::sync::op::StagedContent;

    /// Journal time for ops whose narrative does not turn on it.
    const AT: crate::seams::UnixMillis = crate::seams::UnixMillis(0);

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    fn base() -> Snapshot {
        Snapshot::new(id(0))
    }

    fn staged() -> StagedContent {
        StagedContent {
            root_cid: b"k".to_vec(),
            plaintext_size: 7,
        }
    }

    #[test]
    fn overlay_renders_a_pending_create_over_the_snapshot() {
        let base = base();
        let ops = vec![Op::create(
            id(1),
            id(0),
            "a.txt",
            NodeKind::File,
            1,
            AT,
            None,
        )];
        let view = apply_overlay(&base, &ops);

        assert!(view.contains(id(1)), "pending create is rendered");
        assert_eq!(view.parent_of(id(1)), Some(id(0)));
        assert!(!base.contains(id(1)), "the base snapshot is untouched");
    }

    #[test]
    fn overlay_applies_ops_in_fifo_order() {
        let mut base = base();
        base.upsert_node(NodeMeta::new(id(1), "old.txt", NodeKind::File));
        base.link(id(0), id(1), 1);

        let ops = vec![
            Op::rename(id(1), "mid.txt", 1, AT),
            Op::rename(id(1), "new.txt", 1, AT),
        ];
        let view = apply_overlay(&base, &ops);
        assert_eq!(
            view.node(id(1)).unwrap().name,
            "new.txt",
            "last write in FIFO order wins"
        );
    }

    #[test]
    fn overlay_relink_moves_the_node_in_the_view() {
        let mut base = base();
        base.upsert_node(NodeMeta::new(id(1), "dir", NodeKind::Folder));
        base.upsert_node(NodeMeta::new(id(2), "f", NodeKind::File));
        base.link(id(0), id(1), 1);
        base.link(id(0), id(2), 1);

        let ops = vec![Op::relink(id(2), id(0), id(1), 1, AT, false, false)];
        let view = apply_overlay(&base, &ops);
        assert_eq!(view.parent_of(id(2)), Some(id(1)));
        assert_eq!(view.children(id(0)).len(), 1, "moved out of root");
    }

    #[test]
    fn overlay_delete_removes_from_the_view_only() {
        let mut base = base();
        base.upsert_node(NodeMeta::new(id(1), "f", NodeKind::File));
        base.link(id(0), id(1), 1);
        let view = apply_overlay(&base, &[Op::delete(id(1), 1, AT, 1)]);
        assert!(!view.contains(id(1)));
        assert!(base.contains(id(1)));
    }

    #[test]
    fn overlay_update_content_bumps_a_projected_content_version() {
        let mut base = base();
        let mut meta = NodeMeta::new(id(1), "f.txt", NodeKind::File);
        meta.content_version = Some(4);
        base.upsert_node(meta);
        base.link(id(0), id(1), 1);
        let view = apply_overlay(&base, &[Op::update_content(id(1), staged(), 1, AT)]);
        assert_eq!(
            view.node(id(1)).unwrap().content_version,
            Some(5),
            "new version rendered"
        );
        assert_eq!(
            base.node(id(1)).unwrap().content_version,
            Some(4),
            "base untouched"
        );
    }

    #[test]
    fn overlay_update_content_leaves_an_unprojected_count_unknown() {
        let mut base = base();
        base.upsert_node(NodeMeta::new(id(1), "f.txt", NodeKind::File));
        base.link(id(0), id(1), 1);
        let view = apply_overlay(
            &base,
            &[Op::update_content(
                id(1),
                StagedContent {
                    root_cid: b"k".to_vec(),
                    plaintext_size: 7,
                },
                1,
                AT,
            )],
        );
        assert_eq!(
            view.node(id(1)).unwrap().content_version,
            None,
            "one more than unknown is still unknown"
        );
    }

    #[test]
    fn overlay_renders_the_one_version_a_content_bearing_create_authors() {
        let base = base();
        let with_content = Op::create(id(1), id(0), "a.txt", NodeKind::File, 1, AT, Some(staged()));
        let bare = Op::create(id(2), id(0), "dir", NodeKind::Folder, 1, AT, None);

        let view = apply_overlay(&base, &[with_content, bare]);

        assert_eq!(view.node(id(1)).unwrap().content_version, Some(1));
        assert_eq!(view.node(id(2)).unwrap().content_version, None);
    }
}
