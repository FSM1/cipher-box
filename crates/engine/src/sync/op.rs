//! Intent ops — the durable FIFO journal every mutation rides (CONTEXT.md "Op
//! queue"; blueprint/engine.md "Sync core: Ops").
//!
//! Every mutation is an intent op carrying its **base sequence** — the record
//! sequence of the state it was formed against — journaled FIFO in the durable
//! op queue on both platforms. Ops are the engine's own opaque encoded records
//! (the [`StagingStore`](crate::seams::StagingStore) never interprets them);
//! this module owns their encoding, and [`crate::sync::rebase`] owns their
//! replay.
//!
//! Content bytes never live in an op: `create`/`updateContent` reference their
//! staged upload by an opaque staging key, and the bytes sit in the staging
//! store behind the profile budget ([`crate::sync::staging`]).

use serde::{Deserialize, Serialize};

use crate::facade::{NodeId, NodeKind};

/// One intent op: the target node, the base sequence it was formed against,
/// and the mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Op {
    /// The node this op acts on. For [`OpKind::Create`] it is the id minted
    /// for the new node.
    pub target: NodeId,
    /// The record sequence of the base state this op was formed against — the
    /// rebase anchor (#33 D5).
    pub base_sequence: u64,
    /// The mutation.
    pub kind: OpKind,
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
        /// Staging key of the initial file content, if any (folders and empty
        /// files carry none).
        content_staging_key: Option<Vec<u8>>,
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
        /// Staging key of the new content bytes.
        content_staging_key: Vec<u8>,
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
        content_staging_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            target: new_node,
            base_sequence,
            kind: OpKind::Create {
                parent,
                name: name.into(),
                kind,
                content_staging_key,
            },
        }
    }

    /// A conditional-`delete` op snapshotting the target's own sequence.
    pub fn delete(target: NodeId, base_sequence: u64, target_sequence: u64) -> Self {
        Self {
            target,
            base_sequence,
            kind: OpKind::Delete { target_sequence },
        }
    }

    /// A `rename` op.
    pub fn rename(target: NodeId, new_name: impl Into<String>, base_sequence: u64) -> Self {
        Self {
            target,
            base_sequence,
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
        cross_scope: bool,
        exits_granted_source: bool,
    ) -> Self {
        Self {
            target,
            base_sequence,
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
        content_staging_key: Vec<u8>,
        base_sequence: u64,
    ) -> Self {
        Self {
            target,
            base_sequence,
            kind: OpKind::UpdateContent {
                content_staging_key,
            },
        }
    }

    /// The staging key this op references, if any (orphan-GC input).
    pub fn staging_key(&self) -> Option<&[u8]> {
        match &self.kind {
            OpKind::Create {
                content_staging_key: Some(key),
                ..
            }
            | OpKind::UpdateContent {
                content_staging_key: key,
            } => Some(key),
            _ => None,
        }
    }

    /// Encode to the opaque bytes the durable op queue stores.
    pub fn encode(&self) -> Vec<u8> {
        // Infallible: `Op` has no non-serializable field (a map key type, a
        // non-finite float); serde_json only errors on those.
        serde_json::to_vec(self).expect("Op serializes")
    }

    /// Decode from the durable op queue's opaque bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, OpDecodeError> {
        serde_json::from_slice(bytes).map_err(|e| OpDecodeError(e.to_string()))
    }
}

/// A durable op-queue record failed to decode — a corrupt or forward-version
/// journal entry. The engine dead-letters it rather than crash the replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpDecodeError(String);

impl OpDecodeError {
    /// The diagnostic message (no key material — ops carry no plaintext).
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for OpDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "op decode failed: {}", self.0)
    }
}

impl std::error::Error for OpDecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    #[test]
    fn every_op_round_trips_through_the_durable_encoding() {
        let ops = vec![
            Op::create(
                id(1),
                id(0),
                "a.txt",
                NodeKind::File,
                3,
                Some(b"stage".to_vec()),
            ),
            Op::delete(id(2), 4, 7),
            Op::rename(id(3), "b.txt", 5),
            Op::relink(id(4), id(0), id(9), 6, true, true),
            Op::update_content(id(5), b"stage2".to_vec(), 8),
        ];
        for op in ops {
            assert_eq!(Op::decode(&op.encode()).unwrap(), op);
        }
    }

    #[test]
    fn staging_key_exposed_only_for_content_ops() {
        assert_eq!(
            Op::create(id(1), id(0), "a", NodeKind::File, 1, Some(b"k".to_vec())).staging_key(),
            Some(&b"k"[..])
        );
        assert_eq!(
            Op::update_content(id(1), b"k".to_vec(), 1).staging_key(),
            Some(&b"k"[..])
        );
        assert_eq!(Op::rename(id(1), "b", 1).staging_key(), None);
        assert_eq!(
            Op::create(id(1), id(0), "d", NodeKind::Folder, 1, None).staging_key(),
            None
        );
    }

    #[test]
    fn corrupt_bytes_decode_to_a_typed_error_not_a_panic() {
        assert!(Op::decode(b"not json").is_err());
    }
}
