//! Intent ops — the durable FIFO journal every mutation rides (CONTEXT.md "Op
//! queue"; blueprint/engine.md "Sync core: Ops").
//!
//! Every mutation is an intent op carrying its **base sequence** — the record
//! sequence of the state it was formed against — journaled FIFO in the durable
//! op queue on both platforms. This module owns the intent grammar;
//! [`crate::sync::record`] owns the durable record that seals it, and
//! [`crate::sync::rebase`] owns its replay.
//!
//! Content bytes never live in an op: `create`/`updateContent` reference their
//! staged upload by its DAG root CID and carry its plaintext length
//! ([`StagedContent`]), while the sealed blocks sit in the staging store behind
//! the storage policy's budget ([`crate::sync::staging`]).

use serde::{Deserialize, Serialize};

use crate::facade::{NodeId, NodeKind, PendingClass};
use crate::seams::UnixMillis;
use crate::sync::model::NodeMeta;

/// One intent op: the target node, the base sequence it was formed against,
/// when it was authored, and the mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Op {
    /// The node this op acts on. For [`OpKind::Create`] it is the id minted
    /// for the new node.
    pub target: NodeId,
    /// The record sequence of the base state this op was formed against — the
    /// rebase anchor (#33 D5).
    pub base_sequence: u64,
    /// When the intent was formed, from the [`Scheduler`] clock at journal
    /// time. Authored rather than read at publish: a retried publish re-mints
    /// the same sequence, so a clock read there would author divergent bytes
    /// at one sequence.
    ///
    /// [`Scheduler`]: crate::seams::Scheduler
    pub authored_at: UnixMillis,
    /// The mutation.
    pub kind: OpKind,
}

/// The staged content one op authors: the DAG root it references and the
/// plaintext length that root reassembles to.
///
/// One value because the two must not drift: the root names sealed blocks whose
/// byte count is not the plaintext's, so the size a node renders and the size
/// the published version carries both come from here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedContent {
    /// DAG root CID of the staged content — simultaneously the root block's
    /// staging key and the published version's `contentCid`.
    pub root_cid: Vec<u8>,
    /// Plaintext byte length of the content this root reassembles to.
    pub plaintext_size: u64,
}

/// The five intent-op mutations (#33 D6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpKind {
    /// Create a node under a parent.
    Create {
        /// The parent folder.
        parent: NodeId,
        /// The name as entered.
        name: String,
        /// File or folder.
        kind: NodeKind,
        /// The initial file content, if any (folders and empty files carry
        /// none).
        content: Option<StagedContent>,
    },
    /// Delete a node. `target_sequence` snapshots the target's own record
    /// sequence for the conditional-delete rebase rule.
    Delete {
        /// The target's record sequence at the time the delete was formed.
        target_sequence: u64,
    },
    /// Rename a node in place.
    Rename {
        /// The new name as entered.
        new_name: String,
    },
    /// Move a node to a new parent. Intra-scope this is a pure relink;
    /// cross-scope it re-seals the subtree at the destination epoch and, when
    /// it leaves a granted source scope, **queues a scope-exit rotation
    /// trigger** — this slice queues the trigger only, it does not rotate
    /// (CONTEXT.md #632 scope: "does NOT land: scope-exit rotation
    /// triggering").
    Relink {
        /// The source parent the move was formed against — the presence
        /// condition for the source-remove and the move-race detector
        /// (a concurrent move away from it makes this op the race loser).
        from_parent: NodeId,
        /// The destination parent.
        new_parent: NodeId,
        /// Whether the move crosses a scope boundary.
        cross_scope: bool,
        /// Whether the move leaves a granted source scope (a scope-exit
        /// rotation trigger for the source).
        exits_granted_source: bool,
    },
    /// Write a new file version (fresh per-version content key).
    UpdateContent {
        /// The new version's staged content.
        content: StagedContent,
    },
}

impl Op {
    /// A `create` op.
    pub fn create(
        new_node: NodeId,
        parent: NodeId,
        name: impl Into<String>,
        kind: NodeKind,
        base_sequence: u64,
        authored_at: UnixMillis,
        content: Option<StagedContent>,
    ) -> Self {
        Self {
            target: new_node,
            base_sequence,
            authored_at,
            kind: OpKind::Create {
                parent,
                name: name.into(),
                kind,
                content,
            },
        }
    }

    /// A conditional-`delete` op snapshotting the target's own sequence.
    pub fn delete(
        target: NodeId,
        base_sequence: u64,
        authored_at: UnixMillis,
        target_sequence: u64,
    ) -> Self {
        Self {
            target,
            base_sequence,
            authored_at,
            kind: OpKind::Delete { target_sequence },
        }
    }

    /// A `rename` op.
    pub fn rename(
        target: NodeId,
        new_name: impl Into<String>,
        base_sequence: u64,
        authored_at: UnixMillis,
    ) -> Self {
        Self {
            target,
            base_sequence,
            authored_at,
            kind: OpKind::Rename {
                new_name: new_name.into(),
            },
        }
    }

    /// A `relink` (move) op from `from_parent` to `new_parent`.
    pub fn relink(
        target: NodeId,
        from_parent: NodeId,
        new_parent: NodeId,
        base_sequence: u64,
        authored_at: UnixMillis,
        cross_scope: bool,
        exits_granted_source: bool,
    ) -> Self {
        Self {
            target,
            base_sequence,
            authored_at,
            kind: OpKind::Relink {
                from_parent,
                new_parent,
                cross_scope,
                exits_granted_source,
            },
        }
    }

    /// An `updateContent` op.
    pub fn update_content(
        target: NodeId,
        content: StagedContent,
        base_sequence: u64,
        authored_at: UnixMillis,
    ) -> Self {
        Self {
            target,
            base_sequence,
            authored_at,
            kind: OpKind::UpdateContent { content },
        }
    }

    /// The staged content this op authors, if any.
    pub fn staged_content(&self) -> Option<&StagedContent> {
        match &self.kind {
            OpKind::Create {
                content: Some(content),
                ..
            }
            | OpKind::UpdateContent { content } => Some(content),
            _ => None,
        }
    }

    /// The pending class this op puts its target in — a staged content write
    /// outranks a metadata-only mutation.
    pub fn pending_class(&self) -> PendingClass {
        match self.content_root_cid() {
            Some(_) => PendingClass::Content,
            None => PendingClass::Metadata,
        }
    }

    /// The staged content DAG root this op references, if any. One value with
    /// three roles — the root block's staging key, the root's content address,
    /// and the `contentCid` the published version carries — which is what lets
    /// the drain compare rather than recompute.
    pub fn content_root_cid(&self) -> Option<&[u8]> {
        self.staged_content().map(|c| &c.root_cid[..])
    }

    /// Stamp this op's authored facts onto the node it targets — `mtime`
    /// **overwriting** the projected time, and a content op's plaintext size.
    /// The one function the pending-op overlay and the drain's publish plan
    /// share, so a rendered node and the record that will publish it agree
    /// (blueprint/engine.md "State law").
    pub fn stamp_authored(&self, meta: &mut NodeMeta) {
        meta.mtime = Some(self.authored_at.0);
        if let Some(content) = self.staged_content() {
            meta.size = Some(content.plaintext_size);
        }
    }

    /// Encode the intent body — the plaintext a durable record seals
    /// ([`crate::sync::record`]).
    pub fn encode_body(&self) -> Vec<u8> {
        // Infallible: `Op` has no non-serializable field (a map key type, a
        // non-finite float); serde_json only errors on those.
        serde_json::to_vec(self).expect("Op serializes")
    }

    /// Decode an intent body opened from a durable record.
    pub fn decode_body(bytes: &[u8]) -> Result<Self, OpDecodeError> {
        serde_json::from_slice(bytes).map_err(|_| OpDecodeError)
    }
}

/// An intent body did not satisfy this build's op grammar.
///
/// Carries no detail by construction: the body is sealed *because* it holds
/// user plaintext — `Create { name }` and `Rename { new_name }` are filenames —
/// and a serde message echoes the offending value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpDecodeError;

impl core::fmt::Display for OpDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("op body did not match this build's grammar")
    }
}

impl std::error::Error for OpDecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    fn at(ms: u64) -> UnixMillis {
        UnixMillis(ms)
    }

    fn staged(root: &[u8], plaintext_size: u64) -> StagedContent {
        StagedContent {
            root_cid: root.to_vec(),
            plaintext_size,
        }
    }

    #[test]
    fn every_op_round_trips_through_the_body_encoding() {
        let ops = vec![
            Op::create(
                id(1),
                id(0),
                "a.txt",
                NodeKind::File,
                3,
                at(1_000),
                Some(staged(b"stage", 11)),
            ),
            Op::delete(id(2), 4, at(1_001), 7),
            Op::rename(id(3), "b.txt", 5, at(1_002)),
            Op::relink(id(4), id(0), id(9), 6, at(1_003), true, true),
            Op::update_content(id(5), staged(b"stage2", 12), 8, at(1_004)),
        ];
        for op in ops {
            assert_eq!(Op::decode_body(&op.encode_body()).unwrap(), op);
        }
    }

    #[test]
    fn authored_at_survives_the_round_trip_verbatim() {
        let op = Op::rename(id(1), "b", 1, at(1_700_000_000_123));
        assert_eq!(
            Op::decode_body(&op.encode_body()).unwrap().authored_at,
            at(1_700_000_000_123),
            "the journaled time is the authored one, never re-read"
        );
    }

    #[test]
    fn content_root_cid_exposed_only_for_content_ops() {
        assert_eq!(
            Op::create(
                id(1),
                id(0),
                "a",
                NodeKind::File,
                1,
                at(1),
                Some(staged(b"k", 1))
            )
            .content_root_cid(),
            Some(&b"k"[..])
        );
        assert_eq!(
            Op::update_content(id(1), staged(b"k", 1), 1, at(1)).content_root_cid(),
            Some(&b"k"[..])
        );
        assert_eq!(Op::rename(id(1), "b", 1, at(1)).content_root_cid(), None);
        assert_eq!(
            Op::create(id(1), id(0), "d", NodeKind::Folder, 1, at(1), None).content_root_cid(),
            None
        );
    }

    #[test]
    fn pending_class_is_content_for_exactly_the_content_bearing_kinds() {
        let classes = [
            Op::create(
                id(1),
                id(0),
                "a",
                NodeKind::File,
                1,
                at(1),
                Some(staged(b"k", 1)),
            )
            .pending_class(),
            Op::create(id(1), id(0), "a", NodeKind::File, 1, at(1), None).pending_class(),
            Op::create(id(1), id(0), "d", NodeKind::Folder, 1, at(1), None).pending_class(),
            Op::delete(id(2), 1, at(1), 1).pending_class(),
            Op::rename(id(3), "b", 1, at(1)).pending_class(),
            Op::relink(id(4), id(0), id(9), 1, at(1), false, false).pending_class(),
            Op::update_content(id(5), staged(b"k", 1), 1, at(1)).pending_class(),
        ];
        assert_eq!(
            classes,
            [
                PendingClass::Content,
                PendingClass::Metadata,
                PendingClass::Metadata,
                PendingClass::Metadata,
                PendingClass::Metadata,
                PendingClass::Metadata,
                PendingClass::Content,
            ]
        );
        assert!(PendingClass::Content > PendingClass::Metadata);
        assert!(PendingClass::Metadata > PendingClass::None);
    }

    #[test]
    fn a_content_op_stamps_its_authored_time_and_plaintext_size() {
        let mut node = NodeMeta::new(id(1), "f.txt", NodeKind::File);
        Op::update_content(id(1), staged(b"root", 9), 1, at(5)).stamp_authored(&mut node);
        assert_eq!(node.mtime, Some(5));
        assert_eq!(node.size, Some(9));
    }

    #[test]
    fn a_metadata_op_stamps_time_over_a_projection_and_leaves_size_alone() {
        let mut node = NodeMeta::new(id(1), "f.txt", NodeKind::File);
        node.mtime = Some(999);
        node.size = Some(42);
        Op::rename(id(1), "g.txt", 1, at(1)).stamp_authored(&mut node);
        assert_eq!(
            node.mtime,
            Some(1),
            "the op authors the node's next record, so the projected time is stale"
        );
        assert_eq!(node.size, Some(42), "a metadata op carries no size");
    }

    #[test]
    fn corrupt_bytes_decode_to_a_typed_error_not_a_panic() {
        assert!(Op::decode_body(b"not json").is_err());
    }
}
