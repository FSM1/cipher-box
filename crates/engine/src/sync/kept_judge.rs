//! The kept-op judge: the fate of a kept op (ADR 0069). The judge reads
//! nothing itself. The drain does every read, gives the judge what it saw,
//! and applies the verdict at its one queue exit.

use crate::facade::NodeId;
use crate::seams::UnixMillis;
use crate::sync::kept_op::{KeptNote, KeptResult, keeps, needs_result};
use crate::sync::op::OpKind;

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

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;

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
}
