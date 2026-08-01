//! The upload-cancel interlock shared by the facade and the drain (#824).
//!
//! Cancel is **guaranteed until publish entry and refused after**, so it can
//! never mutate published state. Both halves of that guarantee are decided here,
//! each in one borrow with no await inside it: either the facade claims the op
//! first and the drain abandons its upload, or the drain claims it first and the
//! facade refuses. There is no third outcome.

use std::collections::BTreeSet;

use crate::seams::OpId;

/// Which uploads the user cancelled, and which one has passed publish entry.
#[derive(Default)]
pub(crate) struct UploadCancels {
    /// Cancelled op ids. Held for the session: an op leaves the durable queue
    /// with its cancel and never returns, so nothing here is ever reused.
    cancelled: BTreeSet<OpId>,
    /// The op whose version has finished uploading and is now being published.
    publishing: Option<OpId>,
}

impl UploadCancels {
    /// Claim `op_id` for cancellation. `false` once its record is publishing —
    /// the caller must refuse the cancel rather than compensate a published
    /// mutation.
    pub(crate) fn request(&mut self, op_id: OpId) -> bool {
        if self.publishing == Some(op_id) {
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
        self.publishing = Some(op_id);
        true
    }

    /// The op has left the drain's hands, published or not.
    pub(crate) fn leave_publish(&mut self) {
        self.publishing = None;
    }

    pub(crate) fn is_cancelled(&self, op_id: OpId) -> bool {
        self.cancelled.contains(&op_id)
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

        cancels.leave_publish();
        let mut cancels = UploadCancels::default();
        assert!(cancels.request(OpId(1)));
        assert!(
            !cancels.enter_publish(OpId(1)),
            "the user cancelled first; the publish must abandon"
        );
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
