//! The kept-op judge: the fate of a kept op (ADR 0069). The judge reads
//! nothing itself. The drain does every read, gives the judge what it saw,
//! and applies the verdict at its one queue exit.

use std::collections::BTreeMap;

use cipherbox_core::seal::Version;
use zeroize::Zeroizing;

use crate::facade::NodeId;
use crate::seams::{OpId, UnixMillis};
use crate::sync::duration_millis;
use crate::sync::kept_op::{KEPT_OP_BOUND, KeptNote, KeptResult};
use crate::sync::op::{Op, OpKind};

/// The note of the op a pass publishes now, which its publish fills in.
#[derive(Default)]
pub(crate) struct NoteDraft {
    keeps: bool,
    parent: Option<NodeId>,
    result: Option<KeptResult>,
}

impl NoteDraft {
    /// The draft of an op of `kind` that writes under `parent`. A kind that
    /// needs a result keeps only once its publish records one
    /// ([`Self::with_result`]).
    pub(crate) fn begin(kind: &OpKind, parent: Option<NodeId>) -> Self {
        Self {
            keeps: keeps(kind) && !needs_result(kind),
            parent,
            result: None,
        }
    }

    /// Record the result the publish made, which makes the op keep.
    pub(crate) fn with_result(&mut self, result: KeptResult) {
        self.result = Some(result);
        self.keeps = true;
    }

    /// Whether the op stays queued as a kept op once its note or the
    /// published-op mark lands.
    pub(crate) fn keeps(&self) -> bool {
        self.keeps
    }

    /// The note of a publish under `scope` at `write_epoch`, at
    /// `published_at`. It takes the result.
    pub(crate) fn note(
        &mut self,
        scope: NodeId,
        write_epoch: u64,
        published_at: UnixMillis,
    ) -> KeptNote {
        KeptNote {
            scope: Some(scope),
            write_epoch,
            published_at,
            parent: self.parent,
            result: self.result.take(),
        }
    }

    /// Whether the op stays queued: its note landed, or the mark rose over
    /// an op that keeps.
    pub(crate) fn stays(&self, noted: bool, marked: bool) -> bool {
        noted || (marked && self.keeps)
    }
}

/// Whether an op of `kind` stays queued after its publish. The live tree
/// shows whether a create, a delete or a content edit landed. A rename, a move
/// and a version restore stay only with the result their note records
/// ([`needs_result`]), and a move only inside one scope. A version delete and a
/// prune leave at publish (ADR 0069 D2).
pub(crate) fn keeps(kind: &OpKind) -> bool {
    matches!(
        kind,
        OpKind::Create { .. } | OpKind::Delete { .. } | OpKind::UpdateContent { .. }
    ) || needs_result(kind)
}

/// Whether a kept op of `kind` needs the result in its note: the live node
/// alone cannot show whether a later writer overtook it. One with no result
/// leaves at publish.
pub(crate) fn needs_result(kind: &OpKind) -> bool {
    matches!(
        kind,
        OpKind::Rename { .. }
            | OpKind::Move { .. }
            | OpKind::Relink { .. }
            | OpKind::RestoreVersion { .. }
    )
}

/// What the live tree shows of a kept op's result after a flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeptOutcome {
    /// The live node shows the result: the op leaves with no apply.
    Landed,
    /// The live node shows the value before the op: the op applies again.
    Lost,
    /// The live node shows another value, from a later writer: the op leaves
    /// with no apply, so the later write stays.
    Overtaken,
}

/// The live value that a result is checked against. No `Debug`: a name is
/// plaintext.
#[derive(Clone, Copy)]
pub(crate) enum LiveValue<'a> {
    /// The name of the node under the folder its note names.
    Name(&'a str),
    /// The folder that holds the node, and its name there.
    Place(NodeId, &'a str),
    /// The head content CID of the file.
    Head(&'a [u8]),
    /// The node is not where the check reads it.
    Absent,
}

/// Compare a kept op's `result` with the `live` node. A later writer who
/// sets the value from before the op reads as [`KeptOutcome::Lost`].
pub(crate) fn kept_outcome(result: &KeptResult, live: LiveValue<'_>) -> KeptOutcome {
    let outcome = |landed: bool, lost: bool| {
        if landed {
            KeptOutcome::Landed
        } else if lost {
            KeptOutcome::Lost
        } else {
            KeptOutcome::Overtaken
        }
    };
    match (result, live) {
        (KeptResult::Rename { before, after }, LiveValue::Name(name)) => {
            outcome(name == after.as_str(), name == before.as_str())
        }
        (
            KeptResult::Move {
                from,
                from_name,
                to,
                to_name,
            },
            LiveValue::Place(parent, name),
        ) => outcome(
            parent == *to && name == to_name.as_str(),
            parent == *from && name == from_name.as_str(),
        ),
        (KeptResult::RestoreVersion { before, after }, LiveValue::Head(head)) => {
            outcome(head == after.as_slice(), head == before.as_slice())
        }
        _ => KeptOutcome::Overtaken,
    }
}

/// The live value a rename or a move under `parent` is checked against:
/// `place` is the folder that holds the node, and its name there.
pub(crate) fn live_place<'a>(
    result: &KeptResult,
    parent: NodeId,
    place: Option<&'a (NodeId, Zeroizing<String>)>,
) -> LiveValue<'a> {
    match (result, place) {
        (KeptResult::Rename { .. }, Some((holder, name))) if *holder == parent => {
            LiveValue::Name(name)
        }
        (KeptResult::Move { .. }, Some((holder, name))) => LiveValue::Place(*holder, name),
        _ => LiveValue::Absent,
    }
}

/// The live head of a file's version list, newest first.
pub(crate) fn live_head(versions: &[Version]) -> LiveValue<'_> {
    versions
        .first()
        .map_or(LiveValue::Absent, |head| LiveValue::Head(&head.content_cid))
}

/// Where a kept op's write scope stands for the pass that reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeptPlace {
    /// The pass writes the op's scope, rooted at `root`, whose write-epoch
    /// floor is `live_write_epoch`. `anchor_read_live` says the base read the
    /// folder the op writes under at its name of that epoch: only such a read
    /// can show the op from the live root.
    Writes {
        root: NodeId,
        live_write_epoch: u64,
        anchor_read_live: bool,
    },
    /// The op's scope, rooted at `root`, is a proved root that this device
    /// holds no write seed for: a revoke or a downgrade took it. The op does
    /// not apply again: the pass takes it out before the rebase. One that the
    /// moved tree decides leaves, and the valve charges any other on the
    /// keyless charge until it dead-letters (ADR 0069 D3).
    Keyless { root: NodeId },
    /// This pass cannot check the op at `root`: the boundary walk did not
    /// prove it, a gate-refused one included, or another pass writes it.
    /// `live_write_epoch` is its durable write-epoch floor. Only the root the
    /// op published under, at no higher floor than its note's, is no flip and
    /// runs the bound; a flip waits with no bound for a pass that can check it
    /// (ADR 0069 D5).
    Unchecked { root: NodeId, live_write_epoch: u64 },
    /// As [`Self::Unchecked`], at a granted root that no one granting identity
    /// names, so no floor can show it is no flip. It counts as a flip
    /// ([`shows_a_flip`]) and waits with no bound.
    Unnamespaced,
    /// Another pass, or none this tick, answers for the op's scope.
    Elsewhere,
}

impl KeptPlace {
    /// The scope root this place names, if any.
    pub(crate) fn root(self) -> Option<NodeId> {
        match self {
            Self::Writes { root, .. } | Self::Keyless { root } | Self::Unchecked { root, .. } => {
                Some(root)
            }
            Self::Unnamespaced | Self::Elsewhere => None,
        }
    }
}

/// What a pass does with one kept op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeptVerdict {
    /// It waits in the queue, out of this pass.
    Stay,
    /// It joins this pass, and the rebase onto the live tree decides: a landed
    /// op drops, a lost one applies again (ADR 0069 D3, D6). See
    /// [`KeptPlace::Keyless`] for an op under a keyless scope.
    Recheck,
    /// It waited out [`KEPT_OP_BOUND`] at its write epoch, and leaves.
    Expired,
}

/// Whether `place` shows a flip of the scope the op published under: a new
/// write epoch, another scope root, or a scope this device no longer writes
/// or cannot check.
pub(crate) fn shows_a_flip(note: &KeptNote, place: KeptPlace) -> bool {
    match place {
        KeptPlace::Keyless { .. } | KeptPlace::Unnamespaced => true,
        KeptPlace::Writes {
            root,
            live_write_epoch,
            ..
        } => live_write_epoch > note.write_epoch || note.scope.is_some_and(|scope| scope != root),
        KeptPlace::Unchecked {
            root,
            live_write_epoch,
        } => note.scope != Some(root) || live_write_epoch > note.write_epoch,
        KeptPlace::Elsewhere => false,
    }
}

/// The verdict on one kept op at `now`. A flip ([`shows_a_flip`]) waits for
/// the read of the folder at its new name and does not expire.
pub(crate) fn kept_verdict(note: &KeptNote, place: KeptPlace, now: UnixMillis) -> KeptVerdict {
    let flip = shows_a_flip(note, place);
    match place {
        KeptPlace::Keyless { .. } => return KeptVerdict::Recheck,
        KeptPlace::Writes {
            anchor_read_live: true,
            ..
        } if flip => return KeptVerdict::Recheck,
        _ if flip => return KeptVerdict::Stay,
        _ => {}
    }
    if now.0.saturating_sub(note.published_at.0) >= duration_millis(KEPT_OP_BOUND) {
        KeptVerdict::Expired
    } else {
        KeptVerdict::Stay
    }
}

/// The node a kept op anchors at: the parent of a create, the destination
/// of a restore, the folder its note names for a delete, a rename or a move,
/// and else the node itself.
pub(crate) fn kept_anchor(op: &Op, parent: Option<NodeId>) -> NodeId {
    match (&op.kind, parent) {
        (OpKind::Create { parent, .. }, _) => *parent,
        (OpKind::Restore { into, .. }, _) => *into,
        (
            OpKind::Delete { .. }
            | OpKind::Rename { .. }
            | OpKind::Move { .. }
            | OpKind::Relink { .. },
            Some(parent),
        ) => parent,
        _ => op.target,
    }
}

/// The folder a kept op writes under ([`KeptNote::parent`]), and else its
/// anchor. It differs from the anchor only for an edit and a version
/// restore, which anchor at their file.
pub(crate) fn kept_folder(op: &Op, parent: Option<NodeId>) -> NodeId {
    parent.unwrap_or_else(|| kept_anchor(op, parent))
}

/// How a later op of this device on the same node decides an earlier op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Overtaken {
    /// A later delete removes the node.
    ByDelete,
    /// A later bin restore cancels this delete.
    ByRestore,
}

/// The ops of `queue` that a later op of this device on the same node
/// decides: a later delete expires every earlier op on its node once a
/// flip shows, a later bin restore cancels that delete so the earlier
/// ops stay, and no other later op expires an earlier op (ADR 0069 D6). A
/// cancelled delete leaves at once; before a flip, a bin restore can still
/// cancel a delete, so the ops under it wait. A restore that publishes
/// cancels its delete durably (`Drain::publish_queue`).
pub(crate) fn overtaken_by_a_later_op(queue: &[(OpId, Op)]) -> BTreeMap<OpId, Overtaken> {
    let mut later: BTreeMap<NodeId, (bool, bool)> = BTreeMap::new();
    let mut overtaken = BTreeMap::new();
    for (op_id, op) in queue.iter().rev() {
        let (deleted, restoring) = later.entry(op.target).or_default();
        let delete = matches!(op.kind, OpKind::Delete { .. });
        if *deleted {
            overtaken.insert(*op_id, Overtaken::ByDelete);
        } else if delete && *restoring {
            overtaken.insert(*op_id, Overtaken::ByRestore);
        }
        if delete && !*deleted {
            *deleted = !*restoring;
            *restoring = false;
        }
        if matches!(op.kind, OpKind::Restore { .. }) && !*deleted {
            *restoring = true;
        }
    }
    overtaken
}

/// Whether the drain reads the anchor of a kept op itself: the folder its
/// note names for a delete, a rename or a move, which a flip moved to a new
/// name (`Drain::read_kept_parents`, `Drain::read_kept_places`).
pub(crate) fn reads_kept_parent(op: &Op, parent: Option<NodeId>) -> bool {
    parent.is_some()
        && matches!(
            op.kind,
            OpKind::Delete { .. }
                | OpKind::Rename { .. }
                | OpKind::Move { .. }
                | OpKind::Relink { .. }
        )
}

/// Whether a kept delete leaves: its folder is gone from the moved tree, or
/// the folder no longer links its node. A contested id leaves the base with
/// no read of its own, so it decides nothing.
pub(crate) fn delete_decided(
    folder_gone: bool,
    contested: bool,
    linked: Option<bool>,
) -> Option<bool> {
    if contested {
        return None;
    }
    if folder_gone {
        return Some(true);
    }
    linked.map(|alive| !alive)
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::sync::kept_op::KeptNotes;
    use crate::sync::provision::GENESIS_EPOCH;

    const PUBLISHED: UnixMillis = UnixMillis(1_000);

    fn note(write_epoch: u64) -> KeptNote {
        KeptNote {
            scope: Some(SCOPE),
            write_epoch,
            published_at: PUBLISHED,
            parent: None,
            result: None,
        }
    }

    fn at(after_publish: Duration) -> UnixMillis {
        PUBLISHED.saturating_add(after_publish)
    }

    fn here(live_write_epoch: u64, anchor_read_live: bool) -> KeptPlace {
        KeptPlace::Writes {
            root: SCOPE,
            live_write_epoch,
            anchor_read_live,
        }
    }

    const SCOPE: NodeId = NodeId([5; 16]);
    const PARENT: NodeId = NodeId([6; 16]);

    fn rename() -> KeptResult {
        KeptResult::Rename {
            before: Zeroizing::new("a".into()),
            after: Zeroizing::new("b".into()),
        }
    }

    #[test]
    fn a_kind_that_needs_a_result_keeps_only_with_one() {
        let kind = OpKind::Rename {
            new_name: "b".into(),
        };
        let mut draft = NoteDraft::begin(&kind, Some(PARENT));
        assert!(!draft.keeps());
        assert!(!draft.stays(false, true));
        draft.with_result(rename());
        assert!(draft.keeps());
        assert!(draft.stays(false, true));
        let note = draft.note(SCOPE, 3, UnixMillis(7));
        assert_eq!(note.parent, Some(PARENT));
        assert_eq!(note.result, Some(rename()));
        assert_eq!(draft.note(SCOPE, 3, UnixMillis(7)).result, None);
    }

    #[test]
    fn a_stored_note_keeps_the_op_whatever_the_mark() {
        let draft = NoteDraft::default();
        assert!(draft.stays(true, false));
        assert!(!draft.stays(false, true));
        assert!(!draft.stays(false, false));
    }

    const JUST_BEFORE: Duration = KEPT_OP_BOUND.saturating_sub(Duration::from_millis(1));

    #[test]
    fn an_op_waits_at_its_write_epoch_until_the_bound_and_then_leaves() {
        assert_eq!(
            kept_verdict(&note(2), here(2, true), at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(&note(2), here(2, true), at(KEPT_OP_BOUND)),
            KeptVerdict::Expired
        );
    }

    #[test]
    fn a_new_write_epoch_sends_the_op_to_the_rebase_before_the_bound() {
        assert_eq!(
            kept_verdict(&note(2), here(3, true), at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(&note(2), here(3, true), at(KEPT_OP_BOUND)),
            KeptVerdict::Recheck,
            "a flip seen after the bound still applies the op again"
        );
    }

    #[test]
    fn a_new_scope_root_at_the_same_epoch_is_a_flip() {
        let new_scope = KeptPlace::Writes {
            root: NodeId([6; 16]),
            live_write_epoch: 2,
            anchor_read_live: true,
        };
        assert_eq!(
            kept_verdict(&note(2), new_scope, at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
    }

    #[test]
    fn a_flip_waits_for_a_read_of_the_folder_at_its_new_name_and_does_not_expire() {
        assert_eq!(
            kept_verdict(&note(2), here(3, false), at(Duration::ZERO)),
            KeptVerdict::Stay,
            "a read from before the flip still shows the lost write"
        );
        assert_eq!(
            kept_verdict(&note(2), here(3, false), at(KEPT_OP_BOUND * 2)),
            KeptVerdict::Stay,
            "a device offline past the bound keeps the write for its first live read"
        );
    }

    #[test]
    fn a_scope_the_device_can_no_longer_write_sends_the_op_to_the_pass() {
        let keyless = KeptPlace::Keyless { root: SCOPE };
        assert_eq!(
            kept_verdict(&note(2), keyless, at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(&note(2), keyless, at(KEPT_OP_BOUND)),
            KeptVerdict::Recheck,
            "the pass, not the bound, decides"
        );
    }

    #[test]
    fn an_unchecked_root_at_the_notes_epoch_waits_out_the_bound() {
        let unproved = KeptPlace::Unchecked {
            root: SCOPE,
            live_write_epoch: 2,
        };
        assert_eq!(
            kept_verdict(&note(2), unproved, at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(&note(2), unproved, at(KEPT_OP_BOUND)),
            KeptVerdict::Expired
        );
    }

    #[test]
    fn an_unchecked_root_past_a_cut_keeps_the_op_past_the_bound() {
        let cut = KeptPlace::Unchecked {
            root: SCOPE,
            live_write_epoch: 3,
        };
        let other_root = KeptPlace::Unchecked {
            root: NodeId([6; 16]),
            live_write_epoch: 2,
        };
        for place in [cut, other_root] {
            assert_eq!(
                kept_verdict(&note(2), place, at(KEPT_OP_BOUND * 2)),
                KeptVerdict::Stay,
                "{place:?}"
            );
        }
    }

    #[test]
    fn another_pass_leaves_the_op_alone_until_the_bound() {
        assert_eq!(
            kept_verdict(&note(2), KeptPlace::Elsewhere, at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(&note(2), KeptPlace::Elsewhere, at(KEPT_OP_BOUND)),
            KeptVerdict::Expired
        );
    }

    #[test]
    fn an_op_with_no_note_gets_one_check_at_the_first_live_read_of_its_folder() {
        let mut notes = KeptNotes::default();
        let first = notes.note_at(OpId(3), PUBLISHED);
        assert!(notes.is_dirty(), "the first sight is recorded");
        assert_eq!(
            kept_verdict(&first, here(GENESIS_EPOCH, true), PUBLISHED),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(&first, here(GENESIS_EPOCH, false), at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(&first, KeptPlace::Elsewhere, at(KEPT_OP_BOUND)),
            KeptVerdict::Expired,
            "the bound runs from the first sight"
        );
        assert_eq!(
            notes.note_at(OpId(3), at(KEPT_OP_BOUND)),
            first,
            "a later sight keeps the first"
        );
    }

    fn text(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    #[test]
    fn a_kept_result_reads_landed_lost_or_overtaken_against_the_live_node() {
        const FROM: NodeId = NodeId([1; 16]);
        const TO: NodeId = NodeId([2; 16]);
        const OTHER: NodeId = NodeId([3; 16]);
        let rename = KeptResult::Rename {
            before: text("a"),
            after: text("b"),
        };
        let moved = KeptResult::Move {
            from: FROM,
            from_name: text("a"),
            to: TO,
            to_name: text("b"),
        };
        // A move that keeps its name reads by its parent.
        let relink = KeptResult::Move {
            from: FROM,
            from_name: text("a"),
            to: TO,
            to_name: text("a"),
        };
        let restore = KeptResult::RestoreVersion {
            before: vec![1; 4],
            after: vec![2; 4],
        };
        use KeptOutcome::{Landed, Lost, Overtaken};
        let cases: [(&KeptResult, LiveValue<'_>, KeptOutcome); 16] = [
            (&rename, LiveValue::Name("b"), Landed),
            (&rename, LiveValue::Name("a"), Lost),
            (&rename, LiveValue::Name("c"), Overtaken),
            (&rename, LiveValue::Absent, Overtaken),
            (&moved, LiveValue::Place(TO, "b"), Landed),
            (&moved, LiveValue::Place(FROM, "a"), Lost),
            (&moved, LiveValue::Place(TO, "a"), Overtaken),
            (&moved, LiveValue::Place(FROM, "b"), Overtaken),
            (&moved, LiveValue::Place(OTHER, "b"), Overtaken),
            (&moved, LiveValue::Absent, Overtaken),
            (&relink, LiveValue::Place(TO, "a"), Landed),
            (&relink, LiveValue::Place(FROM, "a"), Lost),
            (&restore, LiveValue::Head(&[2; 4]), Landed),
            (&restore, LiveValue::Head(&[1; 4]), Lost),
            (&restore, LiveValue::Head(&[3; 4]), Overtaken),
            (&restore, LiveValue::Name("b"), Overtaken),
        ];
        for (index, (result, live, outcome)) in cases.into_iter().enumerate() {
            assert_eq!(kept_outcome(result, live), outcome, "case {index}");
        }
    }

    #[test]
    fn only_a_rename_a_move_and_a_version_restore_need_a_result() {
        let restore = OpKind::RestoreVersion {
            content_cid: vec![1; 4],
        };
        let rename = OpKind::Rename {
            new_name: "b".to_owned(),
        };
        let delete_version = OpKind::DeleteVersion {
            content_cid: vec![1; 4],
        };
        assert!(keeps(&restore) && needs_result(&restore));
        assert!(keeps(&rename) && needs_result(&rename));
        assert!(!keeps(&delete_version) && !needs_result(&delete_version));
    }

    #[test]
    fn a_delete_whose_node_the_read_contested_decides_nothing() {
        assert_eq!(delete_decided(true, true, None), None);
        assert_eq!(delete_decided(false, true, Some(false)), None);
        assert_eq!(delete_decided(true, false, None), Some(true));
        assert_eq!(delete_decided(false, false, Some(false)), Some(true));
        assert_eq!(delete_decided(false, false, Some(true)), Some(false));
        assert_eq!(delete_decided(false, false, None), None);
    }
}
