//! The rendered read, memoized — the state law's two operands each carry a
//! generation, and one render answers for the pair (blueprint/engine.md "Sync
//! core: State law").
//!
//! A vfs pass renders per operation: a `ls -l` of one folder is a readdir plus
//! one lookup and one getattr per entry, and each of those rendered the whole
//! vault again. The overlay clones the base snapshot, so the cost is the vault,
//! not the folder.

use std::cell::{Cell, Ref, RefCell, RefMut};
use std::rc::Rc;

use crate::sync::model::Snapshot;

/// The gate-passing base snapshot (the state law's left operand) plus the
/// generation a memo keys on.
///
/// Every mutable borrow bumps the generation, so a repaint cannot leave a stale
/// render behind: the invalidation is a property of the type, not a duty of the
/// dozen paths that repaint the base. A borrow that turns out to change nothing
/// bumps too — an extra render is a cost, a missed one is a wrong answer.
pub(crate) struct BaseSnapshot {
    snapshot: RefCell<Snapshot>,
    generation: Cell<u64>,
}

impl BaseSnapshot {
    /// The cell holding `snapshot`, at its first generation.
    pub(crate) fn new(snapshot: Snapshot) -> Self {
        Self {
            snapshot: RefCell::new(snapshot),
            generation: Cell::new(0),
        }
    }

    /// Reads the base. Never bumps the generation.
    pub(crate) fn borrow(&self) -> Ref<'_, Snapshot> {
        self.snapshot.borrow()
    }

    /// Borrows the base for a repaint, bumping the generation.
    pub(crate) fn borrow_mut(&self) -> RefMut<'_, Snapshot> {
        self.generation.set(self.generation.get().wrapping_add(1));
        self.snapshot.borrow_mut()
    }

    /// The generation of the base a render must be keyed on.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.get()
    }
}

/// What one memoized render is the answer for: the base snapshot's generation
/// and the durable op queue's
/// ([`QueueGenerationStore`](crate::seams::QueueGenerationStore)). The two
/// operands of the state law are the render's only inputs, so a pair that still
/// holds means the render still holds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RenderKey {
    /// [`BaseSnapshot::generation`].
    pub(crate) base: u64,
    /// [`QueueGenerationStore::generation`](crate::seams::QueueGenerationStore::generation).
    pub(crate) queue: u64,
}

/// The one render the reads between two mutations share.
///
/// The rendered snapshot is plaintext metadata about the vault, so a session
/// that ends [`clears`](Self::clear) it with the rest of what the engine holds
/// (security rule 7).
#[derive(Default)]
pub(crate) struct RenderMemo {
    entry: Option<(RenderKey, Rc<Snapshot>)>,
}

impl RenderMemo {
    /// The render `key` is the answer for, if this memo holds it.
    pub(crate) fn hit(&self, key: RenderKey) -> Option<Rc<Snapshot>> {
        self.entry
            .as_ref()
            .filter(|(held, _)| *held == key)
            .map(|(_, rendered)| rendered.clone())
    }

    /// Files `rendered` under `key`.
    ///
    /// `key` must be the pair read **before** the inputs, never after: a
    /// mutation that lands mid-render then files the render under a generation
    /// pair that has already passed, and a passed pair is one no later read can
    /// ask for, because both generations only ever climb.
    pub(crate) fn fill(&mut self, key: RenderKey, rendered: Rc<Snapshot>) {
        self.entry = Some((key, rendered));
    }

    /// Drops the held render.
    pub(crate) fn clear(&mut self) {
        self.entry = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade::NodeId;

    const ROOT: NodeId = NodeId([0; 16]);

    fn key(base: u64, queue: u64) -> RenderKey {
        RenderKey { base, queue }
    }

    #[test]
    fn a_read_borrow_leaves_the_generation_where_it_was() {
        let base = BaseSnapshot::new(Snapshot::new(ROOT));
        let before = base.generation();

        assert_eq!(base.borrow().root, ROOT);

        assert_eq!(base.generation(), before);
    }

    #[test]
    fn every_repaint_borrow_bumps_the_generation() {
        let base = BaseSnapshot::new(Snapshot::new(ROOT));
        let before = base.generation();

        drop(base.borrow_mut());
        let once = base.generation();
        drop(base.borrow_mut());

        assert_ne!(once, before);
        assert_ne!(base.generation(), once);
    }

    #[test]
    fn a_render_is_served_only_for_the_pair_it_was_filed_under() {
        let mut memo = RenderMemo::default();
        let rendered = Rc::new(Snapshot::new(ROOT));

        memo.fill(key(1, 1), rendered.clone());

        assert!(memo.hit(key(1, 1)).is_some());
        assert!(memo.hit(key(2, 1)).is_none(), "a repainted base is a miss");
        assert!(memo.hit(key(1, 2)).is_none(), "a mutated queue is a miss");
    }

    #[test]
    fn a_cleared_memo_serves_nothing() {
        let mut memo = RenderMemo::default();
        memo.fill(key(1, 1), Rc::new(Snapshot::new(ROOT)));

        memo.clear();

        assert!(memo.hit(key(1, 1)).is_none());
    }
}
