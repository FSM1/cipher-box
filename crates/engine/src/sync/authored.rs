//! The authored facts an op writes onto the node it targets — the one place
//! the pending-op overlay and the drain's publish plan both read from, so a
//! rendered node and the record that will publish it never disagree (#863).

use crate::sync::model::NodeMeta;
use crate::sync::op::Op;

/// Stamp `op`'s authored facts onto the node it targets.
///
/// `mtime` is the op's `authored_at`, **overwriting** rather than filling: the
/// op authors the node's next record, so the projected remote time is stale the
/// moment it is queued. A content op also carries the version's plaintext size,
/// which is not derivable from the sealed staged blocks.
pub fn stamp_authored(meta: &mut NodeMeta, op: &Op) {
    meta.mtime = Some(op.authored_at.0);
    if let Some(content) = op.staged_content() {
        meta.size = Some(content.plaintext_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade::{NodeId, NodeKind};
    use crate::seams::UnixMillis;
    use crate::sync::op::StagedContent;

    fn meta() -> NodeMeta {
        NodeMeta::new(NodeId([1; 16]), "f.txt", NodeKind::File)
    }

    fn staged(size: u64) -> StagedContent {
        StagedContent {
            root_cid: b"root".to_vec(),
            plaintext_size: size,
        }
    }

    #[test]
    fn a_metadata_op_stamps_its_authored_time_and_leaves_size_alone() {
        let mut node = meta();
        node.size = Some(42);
        let op = Op::rename(node.id, "g.txt", 1, UnixMillis(1_700));
        stamp_authored(&mut node, &op);
        assert_eq!(node.mtime, Some(1_700));
        assert_eq!(node.size, Some(42));
    }

    #[test]
    fn a_content_op_stamps_the_plaintext_size_not_the_sealed_length() {
        let mut node = meta();
        let op = Op::update_content(node.id, staged(9), 1, UnixMillis(5));
        stamp_authored(&mut node, &op);
        assert_eq!(node.mtime, Some(5));
        assert_eq!(node.size, Some(9));
    }

    #[test]
    fn a_projected_mtime_is_overwritten_never_merely_filled() {
        let mut node = meta();
        node.mtime = Some(999);
        let op = Op::rename(node.id, "g", 1, UnixMillis(1));
        stamp_authored(&mut node, &op);
        assert_eq!(
            node.mtime,
            Some(1),
            "the op authors the node's next record, so the projected time is stale"
        );
    }
}
