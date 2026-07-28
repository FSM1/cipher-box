//! The rebase engine — FIFO replay of the op queue onto gate-passing state,
//! the five per-op race rules, dead-lettering, and dual-link observed repair
//! (blueprint/engine.md "Sync core: Per-op rebase rules"; CONTEXT.md).
//!
//! Replay is FIFO in performed order and rebases **only onto gate-passing
//! state** (#33 D5–D7): the caller resolves a fresh last-known-good snapshot
//! (every record through the adoption gate) and hands it here as the base. An
//! applied op advances the working base so later ops rebase onto the updated
//! state.
//!
//! The five races, one rule each:
//!
//! | Race                | Rule                                                       |
//! | ------------------- | ---------------------------------------------------------- |
//! | Delete vs edit      | Conditional delete: drop if the target advanced (edit wins)|
//! | Rename vs rename    | Parent-CAS serialized; the rebasing writer re-anchors, wins|
//! | Add vs add          | Always visible; the loser auto-suffixes `name (2).ext`     |
//! | Move                | Dest-first, presence-conditional source-remove; loser undoes|
//! | Dual-link           | Observed repair; the link counter picks the loser          |
//!
//! Terminally unrebasable ops (access revoked while offline) **dead-letter**
//! with their staged bytes preserved — nothing is silently dropped (#33 D6).

use std::collections::HashSet;

use crate::seams::OpId;
use crate::sync::model::{NodeMeta, Snapshot, collation_key, suffix_name};
use crate::sync::op::{Op, OpKind};

/// The highest auto-suffix a loser probes before dead-lettering — a folder
/// jammed with this many colliding siblings is pathological, not a routine
/// merge.
const MAX_SUFFIX_PROBE: u32 = 10_000;

/// How one op resolved against the working base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpResolution {
    /// The op applied onto the (possibly advanced) base.
    Applied {
        /// The name the op resolves to publish under — `Some` for create and
        /// rename (auto-suffixed when `suffixed`), `None` otherwise.
        effective_name: Option<String>,
        /// The add/add auto-suffix fired.
        suffixed: bool,
        /// A cross-scope relink that left a granted source scope: the source
        /// scope root whose scope-exit rotation is **queued** (this slice does
        /// not rotate — CONTEXT.md #632 scope).
        scope_exit_trigger: Option<crate::facade::NodeId>,
    },
    /// The op was dropped as a no-op or a lost race.
    Dropped(DropReason),
    /// The op is terminally unrebasable; the caller preserves its staged bytes.
    DeadLetter(DeadLetterReason),
}

/// Why a rebasing op was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Conditional delete: the target advanced past the op's snapshot by rebase
    /// time — the concurrent edit wins in both directions.
    TargetAdvanced,
    /// The mutation is already reflected in gate-passing state (e.g. a delete
    /// of an already-absent node, or a move already at its destination).
    AlreadySatisfied,
    /// A concurrent move won the child; this move undoes its own dest-add so
    /// no orphan and no duplicate survives.
    MoveRaceLost,
}

/// Why an op terminally dead-lettered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadLetterReason {
    /// The op's target/parent is absent from gate-passing state and cannot be
    /// recreated — its scope was revoked (or the node hard-deleted) while the
    /// op sat offline.
    TargetGone,
    /// A relink destination is absent from gate-passing state.
    DestinationGone,
    /// A folder is pathologically saturated with colliding names.
    SuffixExhausted,
    /// The durable op record failed to decode (corrupt or forward-version).
    Undecodable,
}

/// One applied op, resolved for republish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedOp {
    /// The durable-queue id.
    pub op_id: OpId,
    /// The op as journaled.
    pub op: Op,
    /// The resolved name to publish under (create/rename; auto-suffixed on a
    /// collision), `None` for ops that carry no name.
    pub effective_name: Option<String>,
    /// The add/add auto-suffix fired.
    pub suffixed: bool,
}

/// The full replay result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    /// Gate-passing base after every applied op — the state to publish from.
    pub rebased: Snapshot,
    /// Ops to (re)publish, in FIFO order.
    pub applied: Vec<AppliedOp>,
    /// Dropped ops (no-op or lost race) — silently discarded, never surfaced.
    pub dropped: Vec<(OpId, DropReason)>,
    /// Dead-lettered ops — surfaced to the host; staged bytes preserved.
    pub dead_letters: Vec<(OpId, DeadLetterReason)>,
    /// Scope-exit rotation triggers this replay queued (the source scope roots).
    pub scope_exit_triggers: Vec<crate::facade::NodeId>,
}

/// Decoded op-queue entries, in FIFO order.
pub type DecodedOps = Vec<(OpId, Op)>;

/// Op-queue entries that failed to decode, tagged for dead-lettering.
pub type UndecodableOps = Vec<(OpId, DeadLetterReason)>;

/// Decode a raw durable op queue, dead-lettering any entry that fails to
/// decode rather than aborting the whole replay.
pub fn decode_queue(raw: &[(OpId, Vec<u8>)]) -> (DecodedOps, UndecodableOps) {
    let mut ops = Vec::new();
    let mut dead = Vec::new();
    for (op_id, bytes) in raw {
        match Op::decode(bytes) {
            Ok(op) => ops.push((*op_id, op)),
            Err(_) => dead.push((*op_id, DeadLetterReason::Undecodable)),
        }
    }
    (ops, dead)
}

/// Replay `ops` FIFO onto the gate-passing base. `local` (the pre-rebase
/// overlay view) supplies node metadata for the edit-resurrects-a-delete case
/// — the only rule that must re-materialize a node the gate-passing base no
/// longer carries.
pub fn replay(gate_passing: &Snapshot, local: &Snapshot, ops: &[(OpId, Op)]) -> ReplayReport {
    // The one necessary clone: rebase advances `working` but must never mutate
    // the caller's gate-passing base.
    let mut working = gate_passing.clone();
    let mut applied = Vec::new();
    let mut dropped = Vec::new();
    let mut dead_letters = Vec::new();
    let mut scope_exit_triggers = Vec::new();

    for (op_id, op) in ops {
        match rebase_one(&mut working, local, op) {
            OpResolution::Applied {
                effective_name,
                suffixed,
                scope_exit_trigger,
            } => {
                if let Some(scope_root) = scope_exit_trigger {
                    scope_exit_triggers.push(scope_root);
                }
                applied.push(AppliedOp {
                    op_id: *op_id,
                    op: op.clone(),
                    effective_name,
                    suffixed,
                });
            }
            OpResolution::Dropped(reason) => dropped.push((*op_id, reason)),
            OpResolution::DeadLetter(reason) => dead_letters.push((*op_id, reason)),
        }
    }

    ReplayReport {
        rebased: working,
        applied,
        dropped,
        dead_letters,
        scope_exit_triggers,
    }
}

impl OpResolution {
    /// An applied op that carries no resolved name and no auto-suffix (delete,
    /// move, content edit); `scope_exit_trigger` is the queued source scope
    /// root, if any.
    fn applied(scope_exit_trigger: Option<crate::facade::NodeId>) -> Self {
        OpResolution::Applied {
            effective_name: None,
            suffixed: false,
            scope_exit_trigger,
        }
    }
}

/// Rebase one op onto the mutable working base and apply it. Returns the
/// resolution and, on `Applied`, mutates `working` to reflect it.
pub fn rebase_one(working: &mut Snapshot, local: &Snapshot, op: &Op) -> OpResolution {
    match &op.kind {
        OpKind::Create {
            parent, name, kind, ..
        } => rebase_create(working, op, *parent, name, *kind),
        OpKind::Delete { target_sequence } => rebase_delete(working, op, *target_sequence),
        OpKind::Rename { new_name } => rebase_rename(working, op, new_name),
        OpKind::Relink {
            from_parent,
            new_parent,
            exits_granted_source,
            ..
        } => rebase_relink(
            working,
            op,
            *from_parent,
            *new_parent,
            *exits_granted_source,
        ),
        OpKind::UpdateContent { .. } => rebase_update_content(working, local, op),
    }
}

/// Add vs add: always visible; the rebasing loser auto-suffixes.
fn rebase_create(
    working: &mut Snapshot,
    op: &Op,
    parent: crate::facade::NodeId,
    name: &str,
    kind: crate::facade::NodeKind,
) -> OpResolution {
    if working.contains(op.target) {
        // Our own create already landed remotely (confirmed by a prior resolve).
        return OpResolution::Dropped(DropReason::AlreadySatisfied);
    }
    if !working.contains(parent) {
        return OpResolution::DeadLetter(DeadLetterReason::TargetGone);
    }

    let (effective, suffixed) = match resolve_name(working, parent, name, op.target) {
        Some(resolved) => resolved,
        None => return OpResolution::DeadLetter(DeadLetterReason::SuffixExhausted),
    };

    working.upsert_node(NodeMeta::new(op.target, effective.clone(), kind));
    working.link_next(parent, op.target);
    OpResolution::Applied {
        effective_name: Some(effective),
        suffixed,
        scope_exit_trigger: None,
    }
}

/// Conditional delete: drop if the target advanced past the op's snapshot.
fn rebase_delete(working: &mut Snapshot, op: &Op, target_sequence: u64) -> OpResolution {
    match working.record_sequence(op.target) {
        None => OpResolution::Dropped(DropReason::AlreadySatisfied),
        Some(current) if current > target_sequence => {
            // The target advanced by a concurrent edit — edit wins, delete drops.
            OpResolution::Dropped(DropReason::TargetAdvanced)
        }
        Some(_) => {
            working.remove_node(op.target);
            OpResolution::applied(None)
        }
    }
}

/// Rename vs rename: serialized by the parent CAS; the rebasing writer
/// re-anchors onto the fresh base and publishes at a higher sequence, so it
/// wins. A rename into a name a concurrent add took auto-suffixes (one
/// comparator everywhere).
fn rebase_rename(working: &mut Snapshot, op: &Op, new_name: &str) -> OpResolution {
    if !working.contains(op.target) {
        return OpResolution::DeadLetter(DeadLetterReason::TargetGone);
    }
    let parent = working.parent_of(op.target);
    let (effective, suffixed) = match parent {
        Some(parent) => match resolve_name(working, parent, new_name, op.target) {
            Some(resolved) => resolved,
            None => return OpResolution::DeadLetter(DeadLetterReason::SuffixExhausted),
        },
        // The root has no parent scope to enforce sibling uniqueness against.
        None => (new_name.to_owned(), false),
    };
    if let Some(node) = working.node_mut(op.target) {
        node.name = effective.clone();
    }
    OpResolution::Applied {
        effective_name: Some(effective),
        suffixed,
        scope_exit_trigger: None,
    }
}

/// Move: dest-first publish, then a presence-conditional source-remove. A
/// concurrent move that already relocated the child makes this op the race
/// loser, which undoes its dest-add (no orphan, no duplicate).
fn rebase_relink(
    working: &mut Snapshot,
    op: &Op,
    from_parent: crate::facade::NodeId,
    new_parent: crate::facade::NodeId,
    exits_granted_source: bool,
) -> OpResolution {
    if !working.contains(op.target) {
        return OpResolution::DeadLetter(DeadLetterReason::TargetGone);
    }
    if !working.contains(new_parent) {
        return OpResolution::DeadLetter(DeadLetterReason::DestinationGone);
    }

    let scope_exit_trigger = exits_granted_source.then_some(from_parent);
    match working.parent_of(op.target) {
        // Already at the destination — our move (or an identical concurrent one)
        // already landed.
        Some(current) if current == new_parent => {
            OpResolution::Dropped(DropReason::AlreadySatisfied)
        }
        // Still under the source we moved from: the normal dest-first + remove.
        Some(current) if current == from_parent => {
            working.link_next(new_parent, op.target);
            working.unlink(from_parent, op.target);
            OpResolution::applied(scope_exit_trigger)
        }
        // A concurrent move relocated the child elsewhere: we are the race loser.
        Some(_) => OpResolution::Dropped(DropReason::MoveRaceLost),
        // No current parent (was at root / unlinked): dest-first still links it.
        None => {
            working.link_next(new_parent, op.target);
            OpResolution::applied(scope_exit_trigger)
        }
    }
}

/// Edit: applies onto a present target; onto a concurrently-deleted target the
/// edit **resurrects** it from the local overlay view (edit wins in both
/// directions). A target absent from both is a dead-letter.
fn rebase_update_content(working: &mut Snapshot, local: &Snapshot, op: &Op) -> OpResolution {
    if working.contains(op.target) {
        if let Some(node) = working.node_mut(op.target) {
            node.content_version = node.content_version.map(|count| count + 1);
        }
        return OpResolution::applied(None);
    }
    // Resurrect a concurrently-deleted node from local knowledge, re-linking it
    // under a parent that still exists in gate-passing state.
    match (local.node(op.target), local.parent_of(op.target)) {
        (Some(meta), Some(parent)) if working.contains(parent) => {
            // Re-link under the freed name only if it is still free: a concurrent
            // sibling may have taken it, so route through the one collision
            // resolver every other insert uses.
            let (effective, suffixed) = match resolve_name(working, parent, &meta.name, op.target) {
                Some(resolved) => resolved,
                None => return OpResolution::DeadLetter(DeadLetterReason::SuffixExhausted),
            };
            let mut resurrected = meta.clone();
            resurrected.name = effective.clone();
            resurrected.content_version = resurrected.content_version.map(|count| count + 1);
            working.upsert_node(resurrected);
            working.link_next(parent, op.target);
            OpResolution::Applied {
                effective_name: Some(effective),
                suffixed,
                scope_exit_trigger: None,
            }
        }
        _ => OpResolution::DeadLetter(DeadLetterReason::TargetGone),
    }
}

/// Resolve a create/rename name against a parent's siblings: the entered name
/// when free, else the lowest `name (n)` (n ≥ 2) that is free. `None` iff a
/// pathological folder exhausts the probe.
fn resolve_name(
    snap: &Snapshot,
    parent: crate::facade::NodeId,
    name: &str,
    exclude: crate::facade::NodeId,
) -> Option<(String, bool)> {
    // Fold the sibling collation keys once instead of rescanning the children on
    // every probe — identical to `name_taken`, which folds the same set.
    let taken: HashSet<String> = snap
        .children(parent)
        .into_iter()
        .filter(|child| child.id != exclude)
        .map(|child| collation_key(&child.name))
        .collect();
    if !taken.contains(&collation_key(name)) {
        return Some((name.to_owned(), false));
    }
    for n in 2..=MAX_SUFFIX_PROBE {
        let candidate = suffix_name(name, n);
        if !taken.contains(&collation_key(&candidate)) {
            return Some((candidate, true));
        }
    }
    None
}

/// A dual-link observed repair: the losing parents to unlink from one child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repair {
    /// The dual-linked child.
    pub child: crate::facade::NodeId,
    /// The losing parents (every link but the winner's).
    pub remove: Vec<crate::facade::NodeId>,
}

/// Scan for dual-link crash residue: any child linked in more than one parent.
/// The winner is the highest `link_counter` (ties by lowest parent id, a
/// total cross-platform-stable order); every other link is a loser to remove.
/// Any write-capable client that sees this publishes the fix (#33 D5).
pub fn observed_repair(snap: &Snapshot) -> Vec<Repair> {
    let mut repairs = Vec::new();
    let mut children: Vec<crate::facade::NodeId> = snap.links().iter().map(|l| l.child).collect();
    children.sort_unstable();
    children.dedup();

    for child in children {
        let links = snap.links_to(child);
        if links.len() < 2 {
            continue;
        }
        // The same dual-link tiebreak the model exposes — one comparator here too.
        let winner = snap
            .winning_link(child)
            .expect("a child with links has a winner");
        let remove: Vec<crate::facade::NodeId> = links
            .into_iter()
            .filter(|l| l.parent != winner.parent)
            .map(|l| l.parent)
            .collect();
        if !remove.is_empty() {
            repairs.push(Repair { child, remove });
        }
    }
    repairs
}

/// Apply observed repairs to a snapshot (unlinking each losing parent).
pub fn apply_repairs(snap: &mut Snapshot, repairs: &[Repair]) {
    for repair in repairs {
        for &parent in &repair.remove {
            snap.unlink(parent, repair.child);
        }
    }
}

/// How a confirm/resolve reconciles the local published head against the record
/// the network now shows at the same name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadReconciliation {
    /// The observed record is ours, or older/equal-and-identical: nothing
    /// diverged.
    Converged,
    /// A concurrent writer landed a strictly-higher record — the classic lost
    /// CAS race. Rebase local ops onto it and re-mint above `observed_sequence`.
    LostRaceHigher {
        /// The higher sequence a concurrent writer landed first.
        observed_sequence: u64,
    },
    /// A **different** record at the **same** sequence — a same-sequence
    /// split-brain. IPNS higher-sequence-wins cannot converge equal sequences,
    /// so the deterministic tiebreak decides: the loser rebases its local ops
    /// onto the winning sibling and re-mints at `sequence + 1`; the winner
    /// holds, and the loser's strictly-higher re-mint then supersedes it
    /// everywhere.
    SameSequenceDivergence {
        /// The contested sequence.
        sequence: u64,
        /// Whether our record won the deterministic tiebreak. When `false`, we
        /// rebase local ops onto the observed sibling and re-mint above
        /// `sequence`.
        local_wins: bool,
    },
}

/// Reconcile our published head (`local_record` at `local_sequence`) with a
/// sibling record observed at the same name (`observed_record` at
/// `observed_sequence`) — both already record-verified upstream by the gate.
///
/// Closes the same-sequence split-brain the publish confirm-by-re-resolve
/// cannot resolve by sequence alone (deferred from the net publish slice, #692):
/// the tiebreak is a total order over the exact verified record bytes every
/// client fetches, so all clients converge on the same canonical head with no
/// shared state (see [`HeadReconciliation::SameSequenceDivergence`]).
pub fn reconcile_head(
    local_record: &[u8],
    local_sequence: u64,
    observed_record: &[u8],
    observed_sequence: u64,
) -> HeadReconciliation {
    use core::cmp::Ordering;
    match observed_sequence.cmp(&local_sequence) {
        Ordering::Greater => HeadReconciliation::LostRaceHigher { observed_sequence },
        // Our head is strictly newer: the observed copy is stale, we are canonical.
        Ordering::Less => HeadReconciliation::Converged,
        // Same sequence: either an idempotent re-fetch of our own record, or a
        // genuine split-brain broken by the byte-order tiebreak (smaller wins).
        Ordering::Equal if observed_record == local_record => HeadReconciliation::Converged,
        Ordering::Equal => HeadReconciliation::SameSequenceDivergence {
            sequence: local_sequence,
            local_wins: local_record < observed_record,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade::{NodeId, NodeKind};

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    fn tree() -> Snapshot {
        Snapshot::new(id(0))
    }

    fn with_node(snap: &mut Snapshot, parent: NodeId, node: NodeId, name: &str, kind: NodeKind) {
        snap.upsert_node(NodeMeta::new(node, name, kind));
        snap.link(parent, node, 1);
    }

    #[test]
    fn conditional_delete_drops_when_the_target_advanced() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "f", NodeKind::File);
        base.node_mut(id(1)).unwrap().record_sequence = 5; // concurrent edit advanced it

        // The delete snapshotted the target at sequence 3.
        let local = base.clone();
        let res = rebase_one(&mut base, &local, &Op::delete(id(1), 1, 3));
        assert_eq!(res, OpResolution::Dropped(DropReason::TargetAdvanced));
        assert!(base.contains(id(1)), "edit wins — the node survives");
    }

    #[test]
    fn conditional_delete_applies_when_the_target_did_not_advance() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "f", NodeKind::File);
        base.node_mut(id(1)).unwrap().record_sequence = 3;

        let local = base.clone();
        let res = rebase_one(&mut base, &local, &Op::delete(id(1), 1, 3));
        assert!(matches!(res, OpResolution::Applied { .. }));
        assert!(!base.contains(id(1)));
    }

    #[test]
    fn edit_resurrects_a_concurrently_deleted_node() {
        let gate_passing = tree(); // the node was deleted remotely — absent here
        let mut local = tree(); // our overlay still holds it
        with_node(&mut local, id(0), id(1), "f", NodeKind::File);

        let mut working = gate_passing.clone();
        let res = rebase_one(
            &mut working,
            &local,
            &Op::update_content(id(1), b"k".to_vec(), 1),
        );
        assert!(matches!(res, OpResolution::Applied { .. }));
        assert!(working.contains(id(1)), "the edit resurrected the node");
        assert_eq!(working.parent_of(id(1)), Some(id(0)));
    }

    #[test]
    fn resurrection_auto_suffixes_when_a_concurrent_create_took_the_freed_name() {
        // Gate-passing state: the deleted node is gone, and a concurrent create
        // already landed a sibling under the freed name.
        let mut gate_passing = tree();
        with_node(&mut gate_passing, id(0), id(2), "f.txt", NodeKind::File);
        // Our overlay still holds the deleted node under its original name.
        let mut local = tree();
        with_node(&mut local, id(0), id(1), "f.txt", NodeKind::File);

        let mut working = gate_passing.clone();
        let res = rebase_one(
            &mut working,
            &local,
            &Op::update_content(id(1), b"k".to_vec(), 1),
        );
        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: Some("f (2).txt".to_owned()),
                suffixed: true,
                scope_exit_trigger: None,
            },
            "the resurrected node auto-suffixes off the taken name"
        );
        assert_eq!(working.node(id(1)).unwrap().name, "f (2).txt");
        // Both siblings survive with distinct collation keys.
        let keys: std::collections::HashSet<String> = working
            .children(id(0))
            .iter()
            .map(|n| collation_key(&n.name))
            .collect();
        assert_eq!(
            keys.len(),
            2,
            "distinct collation keys, no shadowed sibling"
        );
        assert!(
            working.contains(id(1)) && working.contains(id(2)),
            "both present"
        );
    }

    #[test]
    fn resurrection_dead_letters_under_a_saturated_parent() {
        fn node_id(n: u32) -> NodeId {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&n.to_le_bytes());
            NodeId(bytes)
        }
        // Saturate the parent with every name the probe would try: "f.txt" plus
        // "f (2).txt" .. "f (MAX).txt".
        let mut gate_passing = tree();
        with_node(
            &mut gate_passing,
            id(0),
            node_id(1),
            "f.txt",
            NodeKind::File,
        );
        for n in 2..=MAX_SUFFIX_PROBE {
            with_node(
                &mut gate_passing,
                id(0),
                node_id(n),
                &suffix_name("f.txt", n),
                NodeKind::File,
            );
        }
        // Our overlay still holds the concurrently-deleted node "f.txt".
        let mut local = tree();
        with_node(&mut local, id(0), id(1), "f.txt", NodeKind::File);

        let res = rebase_one(
            &mut gate_passing.clone(),
            &local,
            &Op::update_content(id(1), b"k".to_vec(), 1),
        );
        assert_eq!(
            res,
            OpResolution::DeadLetter(DeadLetterReason::SuffixExhausted)
        );
    }

    #[test]
    fn add_add_collision_auto_suffixes_the_loser() {
        let mut base = tree();
        // A concurrent add already took "a.txt" under the root.
        with_node(&mut base, id(0), id(1), "a.txt", NodeKind::File);

        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::create(id(2), id(0), "a.txt", NodeKind::File, 1, None),
        );
        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: Some("a (2).txt".to_owned()),
                suffixed: true,
                scope_exit_trigger: None,
            }
        );
        assert_eq!(base.node(id(2)).unwrap().name, "a (2).txt");
        // Both are visible.
        assert_eq!(base.children(id(0)).len(), 2);
    }

    #[test]
    fn rename_reanchors_onto_the_fresh_base_and_wins() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "start.txt", NodeKind::File);
        // A concurrent rename already moved it to "other.txt".
        base.node_mut(id(1)).unwrap().name = "other.txt".into();

        let local = base.clone();
        let res = rebase_one(&mut base, &local, &Op::rename(id(1), "final.txt", 1));
        assert!(matches!(
            res,
            OpResolution::Applied {
                suffixed: false,
                ..
            }
        ));
        assert_eq!(
            base.node(id(1)).unwrap().name,
            "final.txt",
            "the rebasing writer wins"
        );
    }

    #[test]
    fn move_dest_first_then_presence_conditional_source_remove() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "dir", NodeKind::Folder);
        with_node(&mut base, id(0), id(2), "f", NodeKind::File);

        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::relink(id(2), id(0), id(1), 1, false, false),
        );
        assert!(matches!(res, OpResolution::Applied { .. }));
        assert_eq!(base.parent_of(id(2)), Some(id(1)), "dest-linked");
        assert_eq!(base.children(id(0)).len(), 1, "source-removed, no orphan");
    }

    #[test]
    fn move_race_loser_undoes_its_dest_add() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "dirA", NodeKind::Folder);
        with_node(&mut base, id(0), id(2), "dirB", NodeKind::Folder);
        with_node(&mut base, id(0), id(3), "f", NodeKind::File);
        // A concurrent move already relocated the child into dirB.
        base.unlink(id(0), id(3));
        base.link(id(2), id(3), 2);

        // Our queued move was from root → dirA; the child is no longer at root.
        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::relink(id(3), id(0), id(1), 1, false, false),
        );
        assert_eq!(res, OpResolution::Dropped(DropReason::MoveRaceLost));
        assert_eq!(
            base.parent_of(id(3)),
            Some(id(2)),
            "the winning move stands"
        );
        assert!(base.children(id(1)).is_empty(), "no dest-add residue");
    }

    #[test]
    fn cross_scope_move_out_of_a_granted_scope_queues_a_trigger_only() {
        let mut base = tree();
        with_node(&mut base, id(0), id(5), "granted", NodeKind::Folder);
        with_node(&mut base, id(5), id(6), "dest", NodeKind::Folder);
        with_node(&mut base, id(5), id(7), "moved", NodeKind::File);

        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::relink(id(7), id(5), id(6), 1, true, true),
        );
        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: None,
                suffixed: false,
                scope_exit_trigger: Some(id(5)),
            },
            "the trigger is queued; no rotation happens in this slice"
        );
    }

    #[test]
    fn observed_repair_removes_the_lower_counter_link() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "p1", NodeKind::Folder);
        with_node(&mut base, id(0), id(2), "p2", NodeKind::Folder);
        base.upsert_node(NodeMeta::new(id(3), "child", NodeKind::File));
        base.link(id(1), id(3), 1);
        base.link(id(2), id(3), 2); // the winner

        let repairs = observed_repair(&base);
        assert_eq!(repairs.len(), 1);
        assert_eq!(repairs[0].child, id(3));
        apply_repairs(&mut base, &repairs);
        assert_eq!(base.links_to(id(3)).len(), 1);
        assert_eq!(base.parent_of(id(3)), Some(id(2)), "higher counter kept");
    }

    #[test]
    fn revoked_while_offline_op_dead_letters() {
        // Gate-passing state no longer carries the granted parent (access revoked).
        let gate_passing = tree();
        let res = rebase_one(
            &mut gate_passing.clone(),
            &gate_passing,
            &Op::create(
                id(9),
                id(8),
                "x.txt",
                NodeKind::File,
                1,
                Some(b"bytes".to_vec()),
            ),
        );
        assert_eq!(res, OpResolution::DeadLetter(DeadLetterReason::TargetGone));
    }

    #[test]
    fn replay_threads_the_base_and_buckets_every_outcome() {
        let mut gate_passing = tree();
        with_node(&mut gate_passing, id(0), id(1), "keep", NodeKind::Folder);

        let ops = vec![
            (
                OpId(1),
                Op::create(id(2), id(1), "a.txt", NodeKind::File, 1, None),
            ),
            (
                OpId(2),
                Op::create(id(3), id(1), "a.txt", NodeKind::File, 1, None),
            ), // collides → suffix
            (
                OpId(3),
                Op::create(id(4), id(99), "orphan", NodeKind::File, 1, None),
            ), // dead-letter
        ];
        let report = replay(&gate_passing, &gate_passing, &ops);

        assert_eq!(report.applied.len(), 2);
        assert!(report.applied[1].suffixed);
        assert_eq!(
            report.dead_letters,
            vec![(OpId(3), DeadLetterReason::TargetGone)]
        );
        assert_eq!(report.rebased.children(id(1)).len(), 2);
    }

    #[test]
    fn decode_queue_dead_letters_corrupt_entries() {
        let good = Op::rename(id(1), "n", 1).encode();
        let raw = vec![(OpId(1), good), (OpId(2), b"garbage".to_vec())];
        let (ops, dead) = decode_queue(&raw);
        assert_eq!(ops.len(), 1);
        assert_eq!(dead, vec![(OpId(2), DeadLetterReason::Undecodable)]);
    }

    #[test]
    fn reconcile_head_higher_sibling_is_a_lost_race() {
        assert_eq!(
            reconcile_head(b"local", 4, b"winner", 5),
            HeadReconciliation::LostRaceHigher {
                observed_sequence: 5
            }
        );
    }

    #[test]
    fn reconcile_head_lower_or_identical_sibling_is_converged() {
        // A strictly older observed copy — our head is canonical.
        assert_eq!(
            reconcile_head(b"local", 5, b"stale", 4),
            HeadReconciliation::Converged
        );
        // The same record re-fetched (our own PUT / a byte-stable re-PUT).
        assert_eq!(
            reconcile_head(b"same", 5, b"same", 5),
            HeadReconciliation::Converged
        );
    }

    #[test]
    fn reconcile_head_same_sequence_split_brain_is_broken_deterministically() {
        // Two different records at the same sequence: exactly one side wins, and
        // the two clients agree on which (the byte-order tiebreak is symmetric).
        let a = b"aaa-record";
        let b = b"bbb-record";
        let from_a = reconcile_head(a, 7, b, 7);
        let from_b = reconcile_head(b, 7, a, 7);
        assert_eq!(
            from_a,
            HeadReconciliation::SameSequenceDivergence {
                sequence: 7,
                local_wins: true
            },
            "the lexicographically-smaller record is canonical"
        );
        assert_eq!(
            from_b,
            HeadReconciliation::SameSequenceDivergence {
                sequence: 7,
                local_wins: false
            },
            "the other client sees itself as the loser and re-mints above"
        );
    }
}
