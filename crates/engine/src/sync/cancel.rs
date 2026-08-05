//! The upload-cancel interlock shared by the facade and the drain.
//!
//! Cancel is **guaranteed until publish entry and refused after**, so it can
//! never mutate published state. Both halves of that guarantee are decided here,
//! each in one borrow with no await inside it: either the facade claims the op
//! first and the drain abandons its upload, or the drain claims it first and the
//! facade refuses. There is no third outcome.

use std::collections::BTreeSet;

use crate::seams::OpId;

/// The one op the drain is carrying, and how far it has got.
struct InFlight {
    op_id: OpId,
    /// The blocks confirmed on the network so far.
    ///
    /// Session-scoped by design: it is the only evidence a cancel has that a
    /// block was charged by *this* upload rather than by a version that has
    /// since published, and a retire without that evidence would unpin content
    /// a live record still names.
    confirmed: Vec<Vec<u8>>,
    /// Whether the version's record has been authored and PUT. Sticky across a
    /// retry: a PUT that did not confirm may still be live at the name.
    past_publish_entry: bool,
}

/// Which uploads the user cancelled, and what the drain is doing with the one
/// op it carries. The drain is strictly FIFO and stops at the first op it
/// cannot finish, so exactly one upload is ever in flight.
#[derive(Default)]
pub(crate) struct UploadCancels {
    /// Cancelled op ids. Held for the session: an op leaves the durable queue
    /// with its cancel and never returns, so nothing here is ever reused.
    cancelled: BTreeSet<OpId>,
    in_flight: Option<InFlight>,
}

impl UploadCancels {
    /// Claim `op_id` for cancellation. `false` once its record is publishing —
    /// the caller must refuse the cancel rather than compensate a published
    /// mutation.
    pub(crate) fn request(&mut self, op_id: OpId) -> bool {
        if self.carrying(op_id).is_some_and(|it| it.past_publish_entry) {
            return false;
        }
        self.cancelled.insert(op_id);
        true
    }

    /// Give the claim back, for a cancel that could not carry out its removals.
    /// The op stays queued, so leaving it claimed would halt every pass behind
    /// it forever.
    pub(crate) fn withdraw(&mut self, op_id: OpId) {
        self.cancelled.remove(&op_id);
    }

    /// Claim `op_id` for publishing, now that every block of its version is on
    /// the network. `false` if the user already cancelled it.
    pub(crate) fn enter_publish(&mut self, op_id: OpId) -> bool {
        if self.cancelled.contains(&op_id) {
            return false;
        }
        self.take_up(op_id).past_publish_entry = true;
        true
    }

    /// The op published and left the durable queue.
    pub(crate) fn published(&mut self, op_id: OpId) {
        if self.carrying(op_id).is_some() {
            self.in_flight = None;
        }
    }

    pub(crate) fn is_cancelled(&self, op_id: OpId) -> bool {
        self.cancelled.contains(&op_id)
    }

    /// Record one more block of `op_id`'s version as confirmed on the network.
    pub(crate) fn confirmed(&mut self, op_id: OpId, cid: &[u8]) {
        self.take_up(op_id).confirmed.push(cid.to_vec());
    }

    /// The blocks a cancel of `op_id` may retire.
    pub(crate) fn uploaded_by(&self, op_id: OpId) -> &[Vec<u8>] {
        self.carrying(op_id).map_or(&[], |it| &it.confirmed)
    }

    fn carrying(&self, op_id: OpId) -> Option<&InFlight> {
        self.in_flight.as_ref().filter(|it| it.op_id == op_id)
    }

    /// The in-flight record for `op_id`, starting a fresh one for a new op.
    fn take_up(&mut self, op_id: OpId) -> &mut InFlight {
        if self.carrying(op_id).is_none() {
            self.in_flight = Some(InFlight {
                op_id,
                confirmed: Vec::new(),
                past_publish_entry: false,
            });
        }
        self.in_flight.as_mut().expect("set just above")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancel_and_a_publish_entry_cannot_both_win_one_op() {
        let mut cancels = UploadCancels::default();
        assert!(cancels.enter_publish(OpId(1)));
        assert!(
            !cancels.request(OpId(1)),
            "the record is publishing; cancel must be refused"
        );

        let mut cancels = UploadCancels::default();
        assert!(cancels.request(OpId(1)));
        assert!(
            !cancels.enter_publish(OpId(1)),
            "the user cancelled first; the publish must abandon"
        );
    }

    /// A publish that did not confirm may still be live at the name, so the
    /// claim outlives the failed attempt and the op stays uncancellable.
    #[test]
    fn a_publish_claim_survives_an_attempt_that_did_not_confirm() {
        let mut cancels = UploadCancels::default();
        cancels.enter_publish(OpId(1));
        assert!(!cancels.request(OpId(1)));

        cancels.published(OpId(1));
        assert!(
            cancels.request(OpId(1)),
            "once the op published and left the queue the claim is spent"
        );
    }

    /// Only the blocks this session confirmed may be retired: a block an earlier
    /// session sent is indistinguishable from one a published version names.
    #[test]
    fn only_this_sessions_confirmed_blocks_are_retirable() {
        let mut cancels = UploadCancels::default();
        assert!(cancels.uploaded_by(OpId(1)).is_empty());

        cancels.confirmed(OpId(1), b"leaf-0");
        cancels.confirmed(OpId(1), b"leaf-1");
        assert_eq!(
            cancels.uploaded_by(OpId(1)),
            [b"leaf-0".to_vec(), b"leaf-1".to_vec()]
        );

        cancels.confirmed(OpId(2), b"other-0");
        assert!(
            cancels.uploaded_by(OpId(1)).is_empty(),
            "a new upload starts the list over"
        );
        assert_eq!(cancels.uploaded_by(OpId(2)), [b"other-0".to_vec()]);
    }

    /// The hold is per op: a cancel of a queued upload must not be refused
    /// because a different op happens to be publishing.
    #[test]
    fn publishing_one_op_does_not_refuse_a_cancel_of_another() {
        let mut cancels = UploadCancels::default();
        cancels.enter_publish(OpId(1));
        assert!(cancels.request(OpId(2)));
        assert!(cancels.is_cancelled(OpId(2)));
        assert!(!cancels.is_cancelled(OpId(1)));
    }
}
