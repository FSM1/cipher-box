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

use core::fmt;
use core::num::NonZeroU64;

use cipherbox_core::codec::{RedactedBytes, RedactedText};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::facade::{NodeId, NodeKind, PendingClass};
use crate::seams::UnixMillis;
use crate::sync::model::NodeMeta;

/// One intent op: the target node, the base sequence it was formed against,
/// when it was authored, and the mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Op {
    /// The node this op acts on. For [`OpKind::Create`] it is the id minted
    /// for the new node.
    #[zeroize(skip)]
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

/// The staged content one op authors: the DAG root it references, the plaintext
/// length that root reassembles to, and the sealed key that opens it.
///
/// One value because the parts must not drift: the root names sealed blocks
/// whose byte count is not the plaintext's, and the key is a KDF non-edge that
/// nothing can re-derive if it is separated from the version it opens.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedContent {
    /// DAG root CID of the staged content — simultaneously the root block's
    /// staging key and the published version's `contentCid`.
    pub root_cid: Vec<u8>,
    /// Plaintext byte length of the content this root reassembles to, as the
    /// commit observed it. The overlay renders it; the drain cross-checks it
    /// against the staged root's own manifest before publishing.
    pub plaintext_size: u64,
    /// The per-version content key, HPKE-to-self sealed under the owner's enc
    /// subkey ([`cipherbox_core::seal::seal_content_key`]). The subkey comes
    /// from the login secret, so it is epoch-independent and available on
    /// exactly the sessions that can run a drain.
    pub sealed_content_key: Vec<u8>,
    /// The scope epoch bound into the key blob's AAD. Carried because the blob
    /// is opened at drain time, when the live scope epoch may have moved on.
    pub epoch: u64,
}

impl fmt::Debug for StagedContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedContent")
            .field("root_cid", &self.root_cid)
            .field("plaintext_size", &self.plaintext_size)
            .field(
                "sealed_content_key",
                &RedactedBytes::of(&self.sealed_content_key),
            )
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// The destination node a [`OpKind::Move`] replaces, with the sequence
/// snapshot the conditional-delete rule compares against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replaced {
    /// The node being replaced at the destination.
    pub node: NodeId,
    /// Its record sequence at the time the move was formed.
    pub sequence: u64,
}

/// What a `create` op brings into being. One value feeds the node's kind and
/// its initial content, so a folder carrying file content is unrepresentable
/// rather than refused at publish — the op-queue end of the same structural
/// guard [`new_child`](crate::net::author::new_child) makes on the wire
/// (AGENTS.md rule 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NewNode {
    /// A folder, always created empty.
    Folder,
    /// A file, with its first version's staged content when it has one.
    File {
        /// The initial content; `None` for an empty file.
        content: Option<StagedContent>,
    },
}

impl NewNode {
    /// The kind this node is created as.
    pub fn kind(&self) -> NodeKind {
        match self {
            Self::Folder => NodeKind::Folder,
            Self::File { .. } => NodeKind::File,
        }
    }
}

/// Where a relocation lands relative to the source scope — the one field both
/// relocation ops carry (blueprint/engine.md "Sync core: Ops", #26 D1/D7).
///
/// One value rather than a `cross_scope`/`exits_granted_source` pair: an exit
/// from a granted source is cross-scope by definition, so the pair could encode
/// an incoherent op the decoder would have to reject. Here it is unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeCrossing {
    /// Stays inside one scope: a pure relink, no re-seal, no trigger.
    Intra,
    /// Leaves a scope that grants nobody: the moved subtree re-seals at the
    /// destination epoch, and nothing rotates.
    Cross,
    /// Leaves a **granted** source scope: the destination re-seal plus a
    /// scope-exit rotation trigger for the source scope root.
    ExitsGrantedSource,
}

/// The intent-op mutations (#33 D6).
///
/// Wipes on drop, but only over the names: a content address rides the op
/// record's own clear header and a sealed content key is already ciphertext,
/// so wiping either would cost a pass over every render's copy to hide nothing.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub enum OpKind {
    /// Create a node under a parent.
    Create {
        /// The parent folder.
        #[zeroize(skip)]
        parent: NodeId,
        /// The name as entered.
        name: String,
        /// What is being created, carrying exactly the content its kind can
        /// hold.
        #[zeroize(skip)]
        node: NewNode,
    },
    /// Delete a node. `target_sequence` snapshots the target's own record
    /// sequence for the conditional-delete rebase rule.
    Delete {
        /// The target's record sequence at the time the delete was formed.
        target_sequence: u64,
        /// Whether this delete is soft: unlink the node and write a bin entry
        /// instead of retiring the record (CONTEXT.md "Soft delete"). Journaled
        /// on the op rather than read at publish, so a settings save between
        /// the two does not change what an already-queued delete does.
        to_bin: bool,
    },
    /// Rename a node in place.
    Rename {
        /// The new name as entered.
        new_name: String,
    },
    /// Move a node to a new parent.
    Relink {
        /// The source parent the move was formed against — the presence
        /// condition for the source-remove and the move-race detector
        /// (a concurrent move away from it makes this op the race loser).
        #[zeroize(skip)]
        from_parent: NodeId,
        /// The destination parent.
        #[zeroize(skip)]
        new_parent: NodeId,
        /// Where the destination sits relative to the source scope.
        #[zeroize(skip)]
        crossing: ScopeCrossing,
    },
    /// Relink **and** rename a node in one entry, optionally replacing the node
    /// already at the destination name. One kernel rename is one of these, so
    /// the whole POSIX-atomic operation is journaled or none of it is
    /// (blueprint/desktop.md "Reads, writes, and the never-block law").
    Move {
        /// The source parent the move was formed against — the presence
        /// condition for the source-remove and the move-race detector.
        #[zeroize(skip)]
        from_parent: NodeId,
        /// The destination parent (the source parent for a pure rename).
        #[zeroize(skip)]
        new_parent: NodeId,
        /// The name at the destination, as entered.
        new_name: String,
        /// The destination node this move vacates, if any.
        #[zeroize(skip)]
        replacing: Option<Replaced>,
        /// Where the destination sits relative to the source scope. A kernel
        /// rename is the desktop's whole move surface, so a scope exit reaches
        /// the engine through this op as readily as through [`Self::Relink`].
        #[zeroize(skip)]
        crossing: ScopeCrossing,
    },
    /// Write a new file version (fresh per-version content key).
    UpdateContent {
        /// The new version's staged content.
        #[zeroize(skip)]
        content: StagedContent,
        /// The `contentCid` of the version this edit was formed against — the
        /// conditional-edit anchor (blueprint/engine.md "Per-op rebase rules").
        /// A head that is not this one by rebase or publish time is a version
        /// this edit never saw, and the edit refuses rather than superseding
        /// it. `None` only for a file with no version yet.
        ///
        /// An identity, not a count: a queued predecessor and a concurrent
        /// writer advance a count identically, and a retention prune moves it
        /// backwards.
        base_version_cid: Option<Vec<u8>>,
    },
    /// Drop a file's older versions, keeping the newest `keep_latest`.
    ///
    /// A write-plane mutation like any other — it re-seals and publishes a
    /// shortened history — and it **ends at publish**. Reclaiming the dropped
    /// versions' bytes is journaled to the retire ledger
    /// ([`RetireLedger`](crate::seams::RetireLedger)) and drained off this
    /// queue, so garbage collection never holds the FIFO head behind user work.
    Prune {
        /// How many of the newest versions survive. [`NonZeroU64`] because
        /// keeping zero would retire the live version along with its history —
        /// unrepresentable rather than guarded, matching
        /// [`RetentionPolicy::KeepLatest`](crate::content::RetentionPolicy).
        #[zeroize(skip)]
        keep_latest: NonZeroU64,
    },
}

impl fmt::Debug for OpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create { parent, name, node } => f
                .debug_struct("Create")
                .field("parent", parent)
                .field("name", &RedactedText::of(name))
                .field("node", node)
                .finish(),
            Self::Delete {
                target_sequence,
                to_bin,
            } => f
                .debug_struct("Delete")
                .field("target_sequence", target_sequence)
                .field("to_bin", to_bin)
                .finish(),
            Self::Rename { new_name } => f
                .debug_struct("Rename")
                .field("new_name", &RedactedText::of(new_name))
                .finish(),
            Self::Relink {
                from_parent,
                new_parent,
                crossing,
            } => f
                .debug_struct("Relink")
                .field("from_parent", from_parent)
                .field("new_parent", new_parent)
                .field("crossing", crossing)
                .finish(),
            Self::Move {
                from_parent,
                new_parent,
                new_name,
                replacing,
                crossing,
            } => f
                .debug_struct("Move")
                .field("from_parent", from_parent)
                .field("new_parent", new_parent)
                .field("new_name", &RedactedText::of(new_name))
                .field("replacing", replacing)
                .field("crossing", crossing)
                .finish(),
            Self::UpdateContent {
                content,
                base_version_cid,
            } => f
                .debug_struct("UpdateContent")
                .field("content", content)
                .field("base_version_cid", base_version_cid)
                .finish(),
            Self::Prune { keep_latest } => f
                .debug_struct("Prune")
                .field("keep_latest", keep_latest)
                .finish(),
        }
    }
}

impl Op {
    /// A `create` op.
    pub fn create(
        new_node: NodeId,
        parent: NodeId,
        name: impl Into<String>,
        node: NewNode,
        base_sequence: u64,
        authored_at: UnixMillis,
    ) -> Self {
        Self {
            target: new_node,
            base_sequence,
            authored_at,
            kind: OpKind::Create {
                parent,
                name: name.into(),
                node,
            },
        }
    }

    /// A conditional-`delete` op snapshotting the target's own sequence.
    pub fn delete(
        target: NodeId,
        base_sequence: u64,
        authored_at: UnixMillis,
        target_sequence: u64,
        to_bin: bool,
    ) -> Self {
        Self {
            target,
            base_sequence,
            authored_at,
            kind: OpKind::Delete {
                target_sequence,
                to_bin,
            },
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
        crossing: ScopeCrossing,
    ) -> Self {
        Self {
            target,
            base_sequence,
            authored_at,
            kind: OpKind::Relink {
                from_parent,
                new_parent,
                crossing,
            },
        }
    }

    /// A combined `move` op.
    #[allow(clippy::too_many_arguments)]
    pub fn move_node(
        target: NodeId,
        from_parent: NodeId,
        new_parent: NodeId,
        new_name: impl Into<String>,
        replacing: Option<Replaced>,
        base_sequence: u64,
        authored_at: UnixMillis,
        crossing: ScopeCrossing,
    ) -> Self {
        Self {
            target,
            base_sequence,
            authored_at,
            kind: OpKind::Move {
                from_parent,
                new_parent,
                new_name: new_name.into(),
                replacing,
                crossing,
            },
        }
    }

    /// An `updateContent` op anchored on the version it was formed against.
    pub fn update_content(
        target: NodeId,
        content: StagedContent,
        base_version_cid: Option<Vec<u8>>,
        base_sequence: u64,
        authored_at: UnixMillis,
    ) -> Self {
        Self {
            target,
            base_sequence,
            authored_at,
            kind: OpKind::UpdateContent {
                content,
                base_version_cid,
            },
        }
    }

    /// A `prune` op keeping the newest `keep_latest` versions of a file.
    pub fn prune(
        target: NodeId,
        keep_latest: NonZeroU64,
        base_sequence: u64,
        authored_at: UnixMillis,
    ) -> Self {
        Self {
            target,
            base_sequence,
            authored_at,
            kind: OpKind::Prune { keep_latest },
        }
    }

    /// The staged content this op authors, if any.
    pub fn staged_content(&self) -> Option<&StagedContent> {
        match &self.kind {
            OpKind::Create {
                node: NewNode::File {
                    content: Some(content),
                },
                ..
            }
            | OpKind::UpdateContent { content, .. } => Some(content),
            _ => None,
        }
    }

    /// The parent this op moved its target out of when the move left a granted
    /// source scope — the node the full-depth scope-root walk starts from
    /// ([`crate::sync::rebase`]). `None` for every other op.
    pub fn scope_exit_source(&self) -> Option<NodeId> {
        let (from_parent, crossing) = match &self.kind {
            OpKind::Relink {
                from_parent,
                crossing,
                ..
            }
            | OpKind::Move {
                from_parent,
                crossing,
                ..
            } => (from_parent, crossing),
            _ => return None,
        };
        matches!(crossing, ScopeCrossing::ExitsGrantedSource).then_some(*from_parent)
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

    /// These are public engine types and a wasm panic format reaches the
    /// browser console, so every name and the sealed key render as a length.
    #[test]
    fn debug_renders_no_name_and_no_sealed_key() {
        let content = staged(b"root-cid", 9);
        let unredacted_key = format!("{:?}", content.sealed_content_key);
        let ops = [
            Op::create(
                id(1),
                id(0),
                "secret-name.txt",
                NewNode::File {
                    content: Some(content.clone()),
                },
                1,
                at(0),
            ),
            Op::rename(id(1), "secret-name.txt", 1, at(0)),
            Op::move_node(
                id(1),
                id(0),
                id(2),
                "secret-name.txt",
                None,
                1,
                at(0),
                ScopeCrossing::Intra,
            ),
            Op::update_content(id(1), content, None, 1, at(0)),
        ];

        for op in ops {
            let rendered = format!("{op:?}");
            assert!(
                !rendered.contains("secret-name.txt"),
                "a filename never renders: {rendered}"
            );
            assert!(
                !rendered.contains(&unredacted_key),
                "a sealed content key never renders: {rendered}"
            );
            assert!(
                rendered.contains("redacted"),
                "the withheld field is visible as a redaction: {rendered}"
            );
        }
    }

    fn at(ms: u64) -> UnixMillis {
        UnixMillis(ms)
    }

    fn staged(root: &[u8], plaintext_size: u64) -> StagedContent {
        StagedContent {
            root_cid: root.to_vec(),
            plaintext_size,
            sealed_content_key: b"sealed-key-blob".to_vec(),
            epoch: 3,
        }
    }

    #[test]
    fn every_op_round_trips_through_the_body_encoding() {
        let ops = vec![
            Op::create(
                id(1),
                id(0),
                "a.txt",
                NewNode::File {
                    content: Some(staged(b"stage", 11)),
                },
                3,
                at(1_000),
            ),
            Op::delete(id(2), 4, at(1_001), 7, false),
            Op::rename(id(3), "b.txt", 5, at(1_002)),
            Op::relink(
                id(4),
                id(0),
                id(9),
                6,
                at(1_003),
                ScopeCrossing::ExitsGrantedSource,
            ),
            Op::relink(id(8), id(0), id(9), 7, at(1_006), ScopeCrossing::Cross),
            Op::update_content(id(5), staged(b"stage2", 12), None, 8, at(1_004)),
            Op::move_node(
                id(6),
                id(0),
                id(9),
                "c.txt",
                Some(Replaced {
                    node: id(7),
                    sequence: 4,
                }),
                9,
                at(1_005),
                ScopeCrossing::Intra,
            ),
            Op::move_node(
                id(6),
                id(0),
                id(9),
                "c.txt",
                None,
                9,
                at(1_005),
                ScopeCrossing::Intra,
            ),
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
                NewNode::File {
                    content: Some(staged(b"k", 1)),
                },
                1,
                at(1),
            )
            .content_root_cid(),
            Some(&b"k"[..])
        );
        assert_eq!(
            Op::update_content(id(1), staged(b"k", 1), None, 1, at(1)).content_root_cid(),
            Some(&b"k"[..])
        );
        assert_eq!(Op::rename(id(1), "b", 1, at(1)).content_root_cid(), None);
        assert_eq!(
            Op::create(id(1), id(0), "d", NewNode::Folder, 1, at(1)).content_root_cid(),
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
                NewNode::File {
                    content: Some(staged(b"k", 1)),
                },
                1,
                at(1),
            )
            .pending_class(),
            Op::create(id(1), id(0), "a", NewNode::File { content: None }, 1, at(1))
                .pending_class(),
            Op::create(id(1), id(0), "d", NewNode::Folder, 1, at(1)).pending_class(),
            Op::delete(id(2), 1, at(1), 1, false).pending_class(),
            Op::rename(id(3), "b", 1, at(1)).pending_class(),
            Op::relink(id(4), id(0), id(9), 1, at(1), ScopeCrossing::Intra).pending_class(),
            Op::move_node(
                id(4),
                id(0),
                id(9),
                "b",
                None,
                1,
                at(1),
                ScopeCrossing::Intra,
            )
            .pending_class(),
            Op::update_content(id(5), staged(b"k", 1), None, 1, at(1)).pending_class(),
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
        Op::update_content(id(1), staged(b"root", 9), None, 1, at(5)).stamp_authored(&mut node);
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
