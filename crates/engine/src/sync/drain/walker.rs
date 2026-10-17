//! The two-sweep core of a walk that spans ticks. A first sweep reads each
//! node and finds its children. A second sweep reads each node again, and a
//! node read to another [`RecordMark`] moved during the walk. The walk proves
//! nothing until both sweeps complete, as blueprint/engine.md "Owner capture"
//! states. Each walk keeps its own policy: its read, its budget, and what a
//! visit marks.

use std::collections::BTreeSet;

use super::RecordMark;
use crate::facade::NodeId;

/// The nodes of one walk and how far its two sweeps went.
pub(crate) struct TwoSweep<K> {
    /// Each node the first sweep still reads.
    pub(super) pending: Vec<K>,
    pub(super) seen: BTreeSet<NodeId>,
    /// The nodes some folder names, as the walk's policy marks them.
    pub(super) linked: BTreeSet<NodeId>,
    /// Each node read, with the record read.
    pub(super) read: Vec<(K, RecordMark)>,
    /// How many of `read` the second sweep has confirmed.
    pub(super) confirmed: usize,
    /// The unanswered attempts at the walk's next read.
    pub(super) unanswered: u8,
    /// A folder names a child the walk cannot read, so the walk proves less
    /// than the whole subtree.
    pub(super) blind: bool,
}

/// Why a walk's read gave no record.
pub(super) enum ReadFault<F> {
    /// Any fault but a refusal, such as no answer: the read may land on a
    /// later tick.
    Unanswered,
    /// A refused record, or one served tied with other bytes at its sequence:
    /// what the walk read so far proves nothing.
    Untrusted,
    /// A verdict that ends the walk.
    Fatal(F),
}

/// The node bound a walk passed.
pub(super) struct Overflow;

/// Where one step left a walk.
pub(super) enum Swept<F> {
    /// Every node read, and read again to the same record unless the policy
    /// settles on the first sweep.
    Complete,
    /// The policy's budget gave no more reads.
    Paused,
    /// A node read to another record on the second sweep.
    Moved,
    Fault(ReadFault<F>),
    /// The policy's visit passed its node bound.
    Stopped(Overflow),
}

/// What one walk does that another does not.
pub(super) trait SweepPolicy<K> {
    /// What a read gives the visit.
    type Answer;

    /// Take one read from the walk's budget for the first sweep, or for the
    /// second when `confirming`. `false` when none is left.
    fn take_read(&mut self, confirming: bool) -> bool;

    /// Whether the first sweep alone settles the walk.
    fn settles_unconfirmed(&self, _sweep: &TwoSweep<K>) -> bool {
        false
    }

    /// Mark what one node of the first sweep names, and queue its children.
    fn visit(
        &mut self,
        sweep: &mut TwoSweep<K>,
        key: &K,
        answer: Self::Answer,
    ) -> Result<(), Overflow>;
}

impl<K: Clone> TwoSweep<K> {
    pub(super) fn new(first: K, id: NodeId) -> Self {
        Self {
            pending: vec![first],
            seen: BTreeSet::from([id]),
            linked: BTreeSet::new(),
            read: Vec::new(),
            confirmed: 0,
            unanswered: 0,
            blind: false,
        }
    }

    pub(super) fn complete(&self) -> bool {
        self.pending.is_empty() && self.confirmed == self.read.len()
    }

    /// The node the walk reads next: the last of `pending`, or `read[confirmed]`
    /// on the second sweep. Only for a walk that is not complete.
    pub(super) fn next_read(&self) -> &K {
        match self.pending.last() {
            Some(next) => next,
            None => &self.read[self.confirmed].0,
        }
    }

    /// Count an unanswered read. `true` at `limit` attempts.
    pub(super) fn unanswered_at(&mut self, limit: u8) -> bool {
        self.unanswered += 1;
        self.unanswered >= limit
    }

    /// Spend the policy's budget on the walk: the first sweep, then the
    /// second, through `read`, which answers the node's record mark.
    pub(super) async fn step<P: SweepPolicy<K>, F>(
        &mut self,
        policy: &mut P,
        read: impl AsyncFn(&P, &K) -> Result<(RecordMark, P::Answer), ReadFault<F>>,
    ) -> Swept<F> {
        loop {
            if self.complete() || (self.pending.is_empty() && policy.settles_unconfirmed(self)) {
                return Swept::Complete;
            }
            let confirming = self.pending.is_empty();
            if !policy.take_read(confirming) {
                return Swept::Paused;
            }
            let (mark, answer) = match read(policy, self.next_read()).await {
                Ok(read) => read,
                Err(fault) => return Swept::Fault(fault),
            };
            self.unanswered = 0;
            if confirming {
                if mark != self.read[self.confirmed].1 {
                    return Swept::Moved;
                }
                self.confirmed += 1;
                continue;
            }
            let key = self
                .pending
                .pop()
                .expect("a first-sweep read has a pending node");
            self.read.push((key.clone(), mark));
            if let Err(overflow) = policy.visit(self, &key, answer) {
                return Swept::Stopped(overflow);
            }
        }
    }
}
