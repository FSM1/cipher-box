//! The rebase engine — FIFO replay of the op queue onto gate-passing state,
//! the five per-op race rules, dead-lettering, and dual-link observed repair
//! (blueprint/engine.md "Sync core: Per-op rebase rules"; CONTEXT.md "Sync and
//! refresh").
//!
//! Replay is FIFO in performed order and rebases **only onto gate-passing
//! state** (#33 D5–D7): the caller resolves a fresh last-known-good snapshot
//! (every record through the adoption gate) and hands it here as the base. An
//! applied op advances the working base so later ops rebase onto the updated
//! state.
//!
//! The six races, one rule each:
//!
//! | Race                | Rule                                                       |
//! | ------------------- | ---------------------------------------------------------- |
//! | Delete vs edit      | Conditional delete: drop if the target advanced (edit wins)|
//! | Edit vs edit        | Conditional edit: dead-letter if the target gained a version|
//! | Rename vs rename    | Parent-CAS serialized; the rebasing writer re-anchors, wins|
//! | Add vs add          | Always visible; the loser auto-suffixes `name (2).ext`     |
//! | Move                | Dest-first, presence-conditional source-remove; loser undoes|
//! | Dual-link           | Observed repair; the link counter picks the loser          |
//!
//! Terminally unrebasable ops (access revoked while offline) **dead-letter**
//! with their staged bytes preserved — nothing is silently dropped (#33 D6).

use core::num::NonZeroU64;

use core::fmt;

use cipherbox_core::codec::RedactedText;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::seams::OpId;
use crate::sync::model::{NodeMeta, Snapshot, TakenNames, collation_key, lowest_free_suffix};
#[cfg(test)]
use crate::sync::op::NewNode;
#[cfg(test)]
use crate::sync::op::ScopeCrossing;
use crate::sync::op::{Op, OpKind, Replaced};
use crate::sync::record::{RecordClass, RecordReader};

/// How one op resolved against the working base.
#[derive(Clone, PartialEq, Eq)]
pub enum OpResolution {
    /// The op applied onto the (possibly advanced) base.
    Applied {
        /// The name the op resolves to publish under — `Some` for create and
        /// rename (auto-suffixed when `suffixed`), `None` otherwise. Zeroizing
        /// because callers destructure the resolution, so the name outlives the
        /// value that carried it.
        effective_name: Option<Zeroizing<String>>,
        /// The add/add auto-suffix fired.
        suffixed: bool,
        /// The granted source scope root this op exited, resolved full-depth
        /// ([`enclosing_scope_root`]) — the root a
        /// [`ScopeExit`](crate::rotation::RotationTrigger::ScopeExit) rotation
        /// must cut.
        scope_exit_trigger: Option<crate::facade::NodeId>,
    },
    /// The op was dropped as a no-op or a lost race.
    Dropped {
        /// Why the op dropped.
        reason: DropReason,
        /// The granted source scope root this op's target had **already** left
        /// by rebase time. Carried only where the drop is itself evidence the
        /// exit happened — an already-satisfied relocation — because the seed is
        /// owed a cut whether or not this op had to publish the move.
        scope_exit_trigger: Option<crate::facade::NodeId>,
    },
    /// The op is terminally unrebasable; the caller preserves its staged bytes.
    DeadLetter(DeadLetterReason),
}

impl fmt::Debug for OpResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied {
                effective_name,
                suffixed,
                scope_exit_trigger,
            } => f
                .debug_struct("Applied")
                .field(
                    "effective_name",
                    &effective_name.as_deref().map(|name| RedactedText::of(name)),
                )
                .field("suffixed", suffixed)
                .field("scope_exit_trigger", scope_exit_trigger)
                .finish(),
            Self::Dropped {
                reason,
                scope_exit_trigger,
            } => f
                .debug_struct("Dropped")
                .field("reason", reason)
                .field("scope_exit_trigger", scope_exit_trigger)
                .finish(),
            Self::DeadLetter(reason) => f.debug_tuple("DeadLetter").field(reason).finish(),
        }
    }
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

/// Why an op terminally dead-lettered. Every reason but
/// [`Self::ContentUnrecoverable`] keeps the op's staged content, which is what
/// makes it a dead letter rather than a drop (CONTEXT.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadLetterReason {
    /// The op's target/parent is absent from gate-passing state and cannot be
    /// recreated — its scope was revoked (or the node hard-deleted) while the
    /// op sat offline.
    TargetGone,
    /// A relink destination is absent from gate-passing state.
    DestinationGone,
    /// A relink destination is the moved target itself or lies inside its
    /// subtree — the move would detach that subtree from the scope root.
    DestinationInsideTarget,
    /// A folder is pathologically saturated with colliding names.
    SuffixExhausted,
    /// The durable op record failed to decode: corrupt or truncated. A record
    /// this build merely cannot *interpret* — another identity's, a newer
    /// header format, or a newer intent grammar — is retained instead
    /// ([`RecordClass::Retained`]).
    Undecodable,
    /// The network refused the op's own bytes or its registration for a reason
    /// no retry changes — an over-cap payload, not a full account.
    PayloadRefused,
    /// The op's drain attempt budget ran out.
    AttemptsExhausted,
    /// Every attempt authored a head over the block ceiling reads enforce, so
    /// no retry and no rebase shrinks it — the node's own listing is larger than
    /// one record can carry, and splitting it is the remedy. Distinct from
    /// [`Self::AttemptsExhausted`] because a transport outage and a record that
    /// will never fit call for different member actions.
    HeadTooLarge,
    /// A concurrent publish gave the target a version this edit was not formed
    /// against. Publishing anyway would move the head off bytes this device
    /// never saw and no read path can reach again, so the edit refuses and
    /// keeps its own staged version instead (the conditional-edit rule).
    BaseSuperseded,
    /// The op's staged content can never publish: its per-version key will not
    /// open, its root block is gone or unreadable, or a leaf is missing from the
    /// middle of the block set. The content key is a KDF non-edge, so none of
    /// these is recoverable — the abandonment **releases** the version's staged
    /// blocks rather than preserving bytes no key opens.
    ContentUnrecoverable,
    /// The op is abandoned and its staged version could **not** be kept: this
    /// device holds a preserved dead-letter record another build wrote, which
    /// nothing may overwrite. Distinct from
    /// [`Self::ContentUnrecoverable`] because the version is intact — it is the
    /// set that would have held it that this build cannot read.
    PreservationRefused,
    /// The record plane already carries the node this create mints, while
    /// nothing durable on this device remembers publishing it — the shape a data
    /// directory restored from before its own drain has. Republishing would
    /// re-author a node the account may since have deleted, so the op is
    /// abandoned with its staged version kept.
    AlreadyPublished,
    /// A purge named a node gate-passing state still reaches through a live
    /// parent. The bin entry alone does not prove a node unlinked — a soft
    /// delete whose parent publish dead-lettered leaves one standing for a node
    /// the user still sees — so the purge refuses rather than destroying it.
    TargetStillLinked,
    /// Every attempt authored a scope root that fits the block ceiling but
    /// leaves no room for its own re-seal, so the owner's next revocation of
    /// that scope could never be authored. Distinct from [`Self::HeadTooLarge`]
    /// because the record is not too large, and the remedy is not to hold less:
    /// a shared folder's root reserves a fixed share of its record for the
    /// grant section a re-key rebuilds.
    ScopeRootNotResealable,
    /// The owner's bin index holds every entry one record can carry, so no
    /// further node can be binned until the retention sweep frees space.
    /// Distinct from [`Self::AttemptsExhausted`] because no retry shrinks the
    /// body, and the member's remedy is to empty the bin or to hard-delete.
    BinIndexFull,
    /// An op that would move a node into a scope no pass can seal it into: a
    /// relocation whose two ends now sit in two different interior scopes, or a
    /// restore into a scope other than the one that binned the node. A pass
    /// anchors on one scope and carries one interior end beside it, so neither
    /// re-seal has a pass to author it. The command refuses the relocation shape
    /// at journal time; a grant minted after the op was queued is what moves a
    /// boundary under one already journaled.
    CrossingUnauthorable,
}

/// One applied op, resolved for republish.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AppliedOp {
    /// The durable-queue id.
    #[zeroize(skip)]
    pub op_id: OpId,
    /// The op as journaled.
    pub op: Op,
    /// The resolved name to publish under (create/rename; auto-suffixed on a
    /// collision), `None` for ops that carry no name.
    pub effective_name: Option<String>,
    /// The add/add auto-suffix fired.
    #[zeroize(skip)]
    pub suffixed: bool,
    /// The destination node **this op** vacated, if any — a move that won the
    /// conditional delete against the node holding the name it took.
    ///
    /// Reported rather than re-derived from the rebased snapshot: a node can
    /// also leave that snapshot as the detached descendant of a delete earlier
    /// in the same pass ([`Snapshot::remove_deleted`]), and dropping *that*
    /// node's ref would unlink a node no conditional delete ever judged.
    #[zeroize(skip)]
    pub vacated: Option<crate::facade::NodeId>,
}

impl fmt::Debug for AppliedOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppliedOp")
            .field("op_id", &self.op_id)
            .field("op", &self.op)
            .field(
                "effective_name",
                &self.effective_name.as_deref().map(RedactedText::of),
            )
            .field("suffixed", &self.suffixed)
            .field("vacated", &self.vacated)
            .finish()
    }
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
    /// The granted source scope roots this replay exited, deduped and in
    /// first-seen order: N ops leaving one scope are one rotation, never N
    /// (blueprint/engine.md "Rotation primitives: Triggers").
    pub scope_exit_triggers: Vec<crate::facade::NodeId>,
}

/// Decoded op-queue entries, in FIFO order.
pub type DecodedOps = Vec<(OpId, Op)>;

/// Op-queue entries that failed to decode, tagged for dead-lettering.
pub type UndecodableOps = Vec<(OpId, DeadLetterReason)>;

/// One pass over the raw durable op queue for one identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueScan {
    /// This identity's ops, FIFO — the only entries that replay or render.
    pub mine: DecodedOps,
    /// Entries that failed to decode, tagged for dead-lettering and removal.
    pub undecodable: UndecodableOps,
    /// How many entries were held rather than read
    /// ([`RecordClass::Retained`]). They never replay, render, or get removed,
    /// and their staged bytes stay pinned — so this count is the only signal
    /// that the store holds work this session cannot account for.
    pub retained: usize,
}

/// Scan a raw durable op queue for one identity.
///
/// Only an [`Undecodable`](RecordClass::Undecodable) entry is dead-lettered —
/// and it is the caller that removes it. A
/// [`Retained`](RecordClass::Retained) entry is left untouched in the store.
pub fn decode_queue(reader: &RecordReader<'_>, raw: &[(OpId, Vec<u8>)]) -> QueueScan {
    let mut scan = QueueScan::default();
    for (op_id, bytes) in raw {
        match reader.classify(bytes) {
            RecordClass::Mine(op) => scan.mine.push((*op_id, op)),
            RecordClass::Retained(_) => scan.retained += 1,
            RecordClass::Undecodable(_) => scan
                .undecodable
                .push((*op_id, DeadLetterReason::Undecodable)),
        }
    }
    scan
}

/// A memo of one [`decode_queue`] pass: the decode is an HPKE open per record
/// this identity owns, and the queue is uncapped, so an un-memoized render pays
/// for the whole backlog.
///
/// Keyed on the reading identity plus the queue's high-water [`OpId`] and its
/// length — no enqueue or removal leaves both unchanged
/// ([`StagingStore`](crate::seams::StagingStore)). Nothing rewrites a queued
/// record's bytes, so a hit re-serves a verdict that still binds, sender
/// authentication included.
#[derive(Default)]
pub(crate) struct QueueScanMemo {
    key: Option<QueueKey>,
    scan: QueueScan,
}

/// The queue state a memoized scan is the answer for.
#[derive(PartialEq, Eq)]
struct QueueKey {
    owner_tag: [u8; 32],
    high_water: Option<OpId>,
    len: usize,
}

impl QueueScanMemo {
    /// The scan of `raw` for `reader`'s identity, running `decode` only when
    /// the memo does not already cover that exact queue.
    ///
    /// The key and the decode take the one `reader`, so a scan is always filed
    /// under the identity that opened it. `decode` is a parameter so a test can
    /// count the records a pass opened — the cost this memo exists to cut.
    pub(crate) fn scan(
        &mut self,
        reader: &RecordReader<'_>,
        raw: &[(OpId, Vec<u8>)],
        decode: impl FnOnce(&RecordReader<'_>, &[(OpId, Vec<u8>)]) -> QueueScan,
    ) -> &QueueScan {
        let key = QueueKey {
            owner_tag: reader.owner_tag(),
            high_water: raw.iter().map(|(op_id, _)| *op_id).max(),
            len: raw.len(),
        };
        if self.key.as_ref() != Some(&key) {
            self.scan = decode(reader, raw);
            self.key = Some(key);
        }
        &self.scan
    }
}

/// The two scope questions one replay asks, which are not the same set.
#[derive(Clone, Copy)]
pub struct ReplayScopes<'a> {
    /// What the session **knows**: every boundary it has proved, so a walk over
    /// link ancestry can say which scope owns a node
    /// ([`enclosing_scope_root`]).
    pub roots: &'a [crate::facade::NodeId],
    /// The one scope this pass **publishes under**, and so the one end a
    /// crossing may name beside an interior end. Also what an end reaching no
    /// listed root belongs to. Reading this set as the other turns a legitimate
    /// scope exit into a refusal, or the reverse.
    pub anchor: crate::facade::NodeId,
}

/// Replay `ops` FIFO onto the gate-passing base. `local` (the pre-rebase
/// overlay view) supplies node metadata for the edit-resurrects-a-delete case
/// — the only rule that must re-materialize a node the gate-passing base no
/// longer carries.
pub fn replay(
    gate_passing: &Snapshot,
    local: &Snapshot,
    ops: &[(OpId, Op)],
    scopes: ReplayScopes<'_>,
) -> ReplayReport {
    // The one necessary clone: rebase advances `working` but must never mutate
    // the caller's gate-passing base.
    let mut working = gate_passing.clone();
    let mut applied = Vec::new();
    let mut dropped = Vec::new();
    let mut dead_letters = Vec::new();
    let mut scope_exit_triggers: Vec<crate::facade::NodeId> = Vec::new();

    for (op_id, op) in ops {
        // Only this op mutates `working` across the call, so a node the move
        // named as replaced and that leaves between these two reads is one
        // *this* op vacated.
        let replacing = match op.kind {
            OpKind::Move { replacing, .. } => replacing.map(|replaced| replaced.node),
            _ => None,
        }
        .filter(|node| working.contains(*node));
        if names_three_scopes(&working, op, scopes) {
            dead_letters.push((*op_id, DeadLetterReason::CrossingUnauthorable));
            continue;
        }
        match rebase_one(&mut working, local, op, scopes.roots) {
            OpResolution::Applied {
                effective_name,
                suffixed,
                scope_exit_trigger,
            } => {
                queue_trigger(&mut scope_exit_triggers, scope_exit_trigger);
                applied.push(AppliedOp {
                    op_id: *op_id,
                    op: op.clone(),
                    effective_name: effective_name.map(|n| n.to_string()),
                    suffixed,
                    vacated: replacing.filter(|node| !working.contains(*node)),
                });
            }
            OpResolution::Dropped {
                reason,
                scope_exit_trigger,
            } => {
                queue_trigger(&mut scope_exit_triggers, scope_exit_trigger);
                dropped.push((*op_id, reason));
            }
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
    /// A drop that owes no scope-exit rotation — every reason but an
    /// already-satisfied relocation, which alone proves the target left.
    pub fn dropped(reason: DropReason) -> Self {
        OpResolution::Dropped {
            reason,
            scope_exit_trigger: None,
        }
    }

    /// An applied op that carries no resolved name and no auto-suffix (delete,
    /// relink, content edit); `scope_exit_trigger` is the resolved source scope
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
pub fn rebase_one(
    working: &mut Snapshot,
    local: &Snapshot,
    op: &Op,
    scope_roots: &[crate::facade::NodeId],
) -> OpResolution {
    let exit = ScopeExit::of(working, op, scope_roots);
    match &op.kind {
        OpKind::Create { parent, name, node } => {
            rebase_create(working, op, *parent, name, node.kind())
        }
        OpKind::Delete {
            target_sequence, ..
        } => rebase_delete(working, op, *target_sequence),
        OpKind::Rename { new_name } => rebase_rename(working, op, new_name),
        OpKind::Relink {
            from_parent,
            new_parent,
            ..
        } => rebase_relink(working, op, *from_parent, *new_parent, exit),
        OpKind::Move {
            from_parent,
            new_parent,
            new_name,
            replacing,
            ..
        } => rebase_move(
            working,
            op,
            *from_parent,
            *new_parent,
            new_name,
            *replacing,
            exit,
        ),
        OpKind::UpdateContent {
            base_version_cid, ..
        } => rebase_update_content(working, local, op, base_version_cid.as_deref()),
        OpKind::Restore { into, name, kind } => rebase_restore(working, op, *into, name, *kind),
        OpKind::Purge { .. } => rebase_purge(working, op),
        OpKind::Prune { keep_latest } => rebase_prune(working, op, *keep_latest),
    }
}

/// Restore: materialize a binned node at the destination the command resolved.
///
/// The destination rules are a move's, because the op is a relocation into a
/// tree location: a destination gate-passing state no longer holds is
/// [`DeadLetterReason::DestinationGone`], and a colliding name auto-suffixes on
/// the one comparator. A target the base already holds is a restore that landed.
fn rebase_restore(
    working: &mut Snapshot,
    op: &Op,
    into: crate::facade::NodeId,
    name: &str,
    kind: crate::facade::NodeKind,
) -> OpResolution {
    if working.contains(op.target) {
        // The relink landed and the entry drop did not, so the op is not
        // satisfied: dropping it here would strand the entry for a linked node,
        // and the next delete of that node would inherit its `deletedAt` and
        // expire at once. The drain finds the node linked and drops the entry.
        return OpResolution::applied(None);
    }
    if !working.contains(into) {
        return OpResolution::DeadLetter(DeadLetterReason::DestinationGone);
    }
    let Some((effective, suffixed)) = resolve_name(working, into, name, &[op.target]) else {
        return OpResolution::DeadLetter(DeadLetterReason::SuffixExhausted);
    };
    working.upsert_node(NodeMeta::new(op.target, effective.clone(), kind));
    working.link_next(into, op.target);
    OpResolution::Applied {
        effective_name: Some(Zeroizing::new(effective)),
        suffixed,
        scope_exit_trigger: None,
    }
}

/// Purge: the rebase half of the proof a purge destroys nothing live.
///
/// A soft delete writes the bin entry, then unlinks, then republishes the
/// parent. A parent publish that exhausts the attempt budget leaves the entry
/// standing for a node the user still sees in its folder, so the entry alone is
/// not evidence the node is unlinked. Gate-passing state that still holds the
/// node refuses the purge outright; the drain then re-checks the destination
/// parent's own record before it reclaims anything.
fn rebase_purge(working: &Snapshot, op: &Op) -> OpResolution {
    if working.contains(op.target) {
        return OpResolution::DeadLetter(DeadLetterReason::TargetStillLinked);
    }
    OpResolution::applied(None)
}

/// A prune anchors on no version: it keeps the newest `keep_latest` whatever
/// concurrent writers added, so a history that advanced under it still rebases.
/// A target gate-passing state no longer holds has nothing to shorten — its
/// versions retire with the node.
fn rebase_prune(working: &mut Snapshot, op: &Op, keep_latest: NonZeroU64) -> OpResolution {
    let Some(node) = working.node_mut(op.target) else {
        return OpResolution::dropped(DropReason::AlreadySatisfied);
    };
    node.content_version = node
        .content_version
        .map(|count| count.min(keep_latest.get()));
    OpResolution::applied(None)
}

/// Queue one scope root for a scope-exit rotation, deduped: N ops leaving one
/// granted source are one cut, at the position the first of them took.
fn queue_trigger(
    triggers: &mut Vec<crate::facade::NodeId>,
    scope_root: Option<crate::facade::NodeId>,
) {
    if let Some(scope_root) = scope_root
        && !triggers.contains(&scope_root)
    {
        triggers.push(scope_root);
    }
}

/// The scope root a relocation owes a scope-exit rotation, resolved against the
/// base before the rebase mutates it. Both readings are `None` for an op that
/// crosses no granted boundary.
#[derive(Debug, Clone, Copy, Default)]
struct ScopeExit {
    /// What an **applied** exit cuts: the full-depth walk, falling back to the
    /// snapshot root, because an exit this op performed must rotate something
    /// ([`enclosing_scope_root`]).
    applied: Option<crate::facade::NodeId>,
    /// What a **dropped** exit cuts: the walk's own answer alone. A drop is no
    /// evidence this op performed the exit, so a source folder a concurrent
    /// writer deleted must not escalate the fallback into a whole-vault cut.
    dropped: Option<crate::facade::NodeId>,
}

impl ScopeExit {
    fn of(base: &Snapshot, op: &Op, scope_roots: &[crate::facade::NodeId]) -> Self {
        let Some(from_parent) = op.scope_exit_source() else {
            return Self::default();
        };
        let found = enclosing_scope_root(base, from_parent, scope_roots);
        Self {
            applied: Some(found.unwrap_or(base.root)),
            dropped: found,
        }
    }
}

/// The listed scope root at or above `node`, walking it and then its ancestors
/// nearest-first — **full-depth** detection, so a node at depth N resolves the
/// same root a node at depth 1 does (blueprint/engine.md "Rotation primitives:
/// Triggers"; the one-level check is the v1 coverage hole).
///
/// `None` when the chain reaches no listed root. Each caller decides both
/// whether to list the vault root and what the absence means: the drain lists it
/// so every in-tree node resolves, while [`crate::facade`] leaves it off and
/// falls back to it when it classifies a relocation's crossing.
pub(crate) fn enclosing_scope_root(
    working: &Snapshot,
    node: crate::facade::NodeId,
    scope_roots: &[crate::facade::NodeId],
) -> Option<crate::facade::NodeId> {
    core::iter::once(node)
        .chain(working.ancestors(node))
        .find(|candidate| scope_roots.contains(candidate))
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
        return OpResolution::dropped(DropReason::AlreadySatisfied);
    }
    if !working.contains(parent) {
        return OpResolution::DeadLetter(DeadLetterReason::TargetGone);
    }

    let (effective, suffixed) = match resolve_name(working, parent, name, &[op.target]) {
        Some(resolved) => resolved,
        None => return OpResolution::DeadLetter(DeadLetterReason::SuffixExhausted),
    };

    working.upsert_node(NodeMeta::new(op.target, effective.clone(), kind));
    working.link_next(parent, op.target);
    OpResolution::Applied {
        effective_name: Some(Zeroizing::new(effective)),
        suffixed,
        scope_exit_trigger: None,
    }
}

/// Conditional delete: drop if the target advanced past the op's snapshot.
///
/// An applied delete takes the detached subtree with it
/// ([`Snapshot::remove_deleted`]), so a later op in the same pass that targets a
/// descendant resolves against the tree the user actually sees: it dead-letters
/// as `TargetGone` rather than rebasing onto a node no walk can reach.
fn rebase_delete(working: &mut Snapshot, op: &Op, target_sequence: u64) -> OpResolution {
    match working.record_sequence(op.target) {
        None => OpResolution::dropped(DropReason::AlreadySatisfied),
        Some(current) if current > target_sequence => {
            // The target advanced by a concurrent edit — edit wins, delete drops.
            OpResolution::dropped(DropReason::TargetAdvanced)
        }
        Some(_) => {
            working.remove_deleted(op.target);
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
        Some(parent) => match resolve_name(working, parent, new_name, &[op.target]) {
            Some(resolved) => resolved,
            None => return OpResolution::DeadLetter(DeadLetterReason::SuffixExhausted),
        },
        // The root has no parent scope to enforce sibling uniqueness against.
        None => (new_name.to_owned(), false),
    };
    if let Some(node) = working.node_mut(op.target) {
        node.rename(effective.clone());
    }
    OpResolution::Applied {
        effective_name: Some(Zeroizing::new(effective)),
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
    exit: ScopeExit,
) -> OpResolution {
    if let Some(dead_letter) = relocation_guards(working, op, new_parent) {
        return dead_letter;
    }

    match working.parent_of(op.target) {
        // Already at the destination — our move (or an identical concurrent one)
        // already landed.
        Some(current) if current == new_parent => OpResolution::Dropped {
            reason: DropReason::AlreadySatisfied,
            scope_exit_trigger: exit.dropped,
        },
        // Still under the source we moved from: the normal dest-first + remove.
        Some(current) if current == from_parent => {
            working.relocate(op.target, new_parent, None);
            OpResolution::applied(exit.applied)
        }
        // A concurrent move relocated the child elsewhere: we are the race loser.
        Some(_) => OpResolution::dropped(DropReason::MoveRaceLost),
        // No current parent (was at root / unlinked): dest-first still links it.
        None => {
            working.relocate(op.target, new_parent, None);
            OpResolution::applied(exit.applied)
        }
    }
}

/// What a relocation cannot rebase onto at all, in one place for the relink and
/// move rules: an absent target or destination, and a destination inside the
/// moved subtree — which detaches that subtree from the scope root with nothing
/// left to walk it from, so no later op could reach it (unrepresentable rather
/// than merely refused at publish).
fn relocation_guards(
    working: &Snapshot,
    op: &Op,
    new_parent: crate::facade::NodeId,
) -> Option<OpResolution> {
    let reason = if !working.contains(op.target) {
        DeadLetterReason::TargetGone
    } else if !working.contains(new_parent) {
        DeadLetterReason::DestinationGone
    } else if new_parent == op.target || working.ancestors(new_parent).contains(&op.target) {
        DeadLetterReason::DestinationInsideTarget
    } else {
        return None;
    };
    Some(OpResolution::DeadLetter(reason))
}

/// Whether a relocation names three scopes as the pass now resolves it — the
/// one crossing shape no pass can author.
///
/// A pass anchors on one scope and carries one interior end beside it
/// (`crate::sync::drain::DrainScope`), so a crossing neither end of which is
/// the anchor has no pass to author it. The command refuses that same shape at
/// journal time; what re-derives it here is a grant minted after the op was
/// queued, which moves a boundary under an end already journaled.
///
/// Re-derived rather than read off the op's own crossing field: the entry says
/// what was true when the caller acted, and this says what the pass about to
/// publish would have to seal. Charged, because no later tick makes a
/// three-scope crossing authorable.
fn names_three_scopes(working: &Snapshot, op: &Op, scopes: ReplayScopes<'_>) -> bool {
    let Some((from_parent, new_parent, _)) = op.relocation() else {
        return false;
    };
    let ends = [from_parent, new_parent]
        .map(|end| enclosing_scope_root(working, end, scopes.roots).unwrap_or(scopes.anchor));
    ends[0] != ends[1] && !ends.contains(&scopes.anchor)
}

/// Combined move: the relink rule's races, then the rename rule's collision
/// resolution, over a destination this op vacates first — which is what makes a
/// replace land under the entered name instead of auto-suffixing off the node
/// it is replacing. The replaced node drops under the conditional-delete rule,
/// so a concurrent edit to it still wins.
///
/// The vacate takes the replaced node's subtree ([`Snapshot::relocate`]), so a
/// later op in the same pass under that folder dead-letters as `TargetGone`,
/// exactly as [`rebase_delete`] states for the delete direction.
fn rebase_move(
    working: &mut Snapshot,
    op: &Op,
    from_parent: crate::facade::NodeId,
    new_parent: crate::facade::NodeId,
    new_name: &str,
    replacing: Option<Replaced>,
    exit: ScopeExit,
) -> OpResolution {
    if let Some(dead_letter) = relocation_guards(working, op, new_parent) {
        return dead_letter;
    }
    let current_parent = working.parent_of(op.target);
    // A concurrent move relocated the child somewhere this op never anchored
    // against: we are the race loser, and removing it from there would clobber
    // the winner.
    if current_parent.is_some_and(|current| current != from_parent && current != new_parent) {
        return OpResolution::dropped(DropReason::MoveRaceLost);
    }

    // The destination node this move may free — and it may free it only while
    // it is still the one holding the contested name. A node a concurrent
    // writer renamed or moved away is a bystander: the name is free and the
    // move simply takes it. Anchoring on the sequence alone would not see that,
    // because a name lives in the parent's child ref and renaming a node never
    // advances the node's own record sequence.
    let vacating = replacing.filter(|replaced| {
        // A node never replaces itself: the facade is a public surface, and
        // vacating the target would erase the very node this op moves.
        replaced.node != op.target
            && working.parent_of(replaced.node) == Some(new_parent)
            && working
                .node(replaced.node)
                .is_some_and(|node| collation_key(node.name()) == collation_key(new_name))
            // Conditional delete: a concurrent edit that advanced it wins.
            && working
                .record_sequence(replaced.node)
                .is_some_and(|current| current <= replaced.sequence)
    });

    // Already where it was going, under the name it was going to take, with
    // nothing left at the destination to vacate.
    if vacating.is_none()
        && current_parent == Some(new_parent)
        && working
            .node(op.target)
            .is_some_and(|n| n.name() == new_name)
    {
        return OpResolution::Dropped {
            reason: DropReason::AlreadySatisfied,
            scope_exit_trigger: exit.dropped,
        };
    }

    // Resolved before any mutation: an exhausted probe dead-letters, and a
    // dead-lettered op must leave the working base as it found it.
    let mut exclude = vec![op.target];
    exclude.extend(vacating.map(|replaced| replaced.node));
    let (effective, suffixed) = match resolve_name(working, new_parent, new_name, &exclude) {
        Some(resolved) => resolved,
        None => return OpResolution::DeadLetter(DeadLetterReason::SuffixExhausted),
    };

    working.relocate(
        op.target,
        new_parent,
        vacating.map(|replaced| replaced.node),
    );
    if let Some(node) = working.node_mut(op.target) {
        node.rename(effective.clone());
    }
    OpResolution::Applied {
        effective_name: Some(Zeroizing::new(effective)),
        suffixed,
        scope_exit_trigger: exit.applied,
    }
}

/// Edit: applies onto a present target; onto a concurrently-deleted target the
/// edit **resurrects** it from the local overlay view (edit wins in both
/// directions). A target absent from both is a dead-letter.
///
/// Conditional edit: a head this edit was not formed against is another
/// writer's, so the edit dead-letters rather than publishing over it. An
/// applied edit advances the head here, which is what makes the next queued
/// edit of the same file its successor rather than its rival. Judged only where
/// the base has actually projected a head — a pass can be stale about it, and
/// the authoritative check is the drain's, against the live record.
fn rebase_update_content(
    working: &mut Snapshot,
    local: &Snapshot,
    op: &Op,
    base_version_cid: Option<&[u8]>,
) -> OpResolution {
    let projected = working
        .node(op.target)
        .filter(|node| node.content_version.is_some());
    if projected.is_some_and(|node| node.head_content_cid.as_deref() != base_version_cid) {
        return OpResolution::DeadLetter(DeadLetterReason::BaseSuperseded);
    }
    if working.contains(op.target) {
        let authored = op.staged_content().map(|content| content.root_cid.clone());
        if let Some(node) = working.node_mut(op.target) {
            node.content_version = node.content_version.map(|count| count + 1);
            node.head_content_cid = authored;
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
            let (effective, suffixed) =
                match resolve_name(working, parent, meta.name(), &[op.target]) {
                    Some(resolved) => resolved,
                    None => return OpResolution::DeadLetter(DeadLetterReason::SuffixExhausted),
                };
            let mut resurrected = meta.clone();
            resurrected.rename(effective.clone());
            resurrected.content_version = resurrected.content_version.map(|count| count + 1);
            resurrected.head_content_cid = op.staged_content().map(|c| c.root_cid.clone());
            working.upsert_node(resurrected);
            working.link_next(parent, op.target);
            OpResolution::Applied {
                effective_name: Some(Zeroizing::new(effective)),
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
    exclude: &[crate::facade::NodeId],
) -> Option<(String, bool)> {
    // Fold the sibling collation keys once instead of rescanning the children on
    // every probe — identical to `name_taken`, which folds the same set.
    let mut taken: TakenNames = snap
        .children(parent)
        .into_iter()
        .filter(|child| !exclude.contains(&child.id))
        .map(|child| collation_key(child.name()).to_string())
        .collect();
    if !taken.holds(&collation_key(name)) {
        return Some((name.to_owned(), false));
    }
    lowest_free_suffix(name, 2, &mut taken).map(|(candidate, _)| (candidate.to_string(), true))
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
/// cannot resolve by sequence alone (deferred from the net publish slice):
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
    use crate::sync::model::{MAX_SUFFIX_PROBE, suffix_name};
    use crate::sync::record::{RecordSeal, encode_op_record};
    use cipherbox_core::suite::x25519::X25519Secret;
    use zeroize::Zeroizing;

    /// Journal time for ops whose narrative does not turn on it.
    const AT: crate::seams::UnixMillis = crate::seams::UnixMillis(0);

    fn staged_k() -> crate::sync::op::StagedContent {
        crate::sync::op::StagedContent {
            root_cid: b"k".to_vec(),
            plaintext_size: 1,
            sealed_content_key: b"sealed-key-blob".to_vec(),
            epoch: 1,
        }
    }

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    /// The one scope root these fixtures hang under — the full-depth
    /// scope-exit walk resolves against it.
    const SCOPE_ROOTS: &[NodeId] = &[NodeId([0; 16])];

    /// The vault root heads every root list here, and is the scope each replay
    /// publishes under.
    fn replay_scopes(roots: &[NodeId]) -> ReplayScopes<'_> {
        ReplayScopes {
            roots,
            anchor: roots[0],
        }
    }

    fn tree() -> Snapshot {
        Snapshot::new(id(0))
    }

    fn with_node(snap: &mut Snapshot, parent: NodeId, node: NodeId, name: &str, kind: NodeKind) {
        snap.upsert_node(NodeMeta::new(node, name, kind));
        snap.link(parent, node, 1);
    }

    /// The bin entry alone never licenses a purge. A soft delete whose parent
    /// republish dead-lettered leaves one standing for a node the user still
    /// sees in its folder, so gate-passing state decides ahead of the entry.
    #[test]
    fn a_purge_refuses_a_node_gate_passing_state_still_holds() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "notes.txt", NodeKind::File);
        let local = base.clone();
        assert_eq!(
            rebase_one(&mut base, &local, &Op::purge(id(1), 7, 1, AT), SCOPE_ROOTS),
            OpResolution::DeadLetter(DeadLetterReason::TargetStillLinked),
        );
        assert!(base.contains(id(1)), "and the node is left where it is");
    }

    /// A binned node is in no folder, so nothing in gate-passing state names it
    /// and the drain decides the rest.
    #[test]
    fn a_purge_of_an_unlinked_node_reaches_the_drain() {
        let mut base = tree();
        let local = base.clone();
        assert!(matches!(
            rebase_one(&mut base, &local, &Op::purge(id(1), 7, 1, AT), SCOPE_ROOTS),
            OpResolution::Applied { .. },
        ));
    }

    /// A restore materializes a node absent from every folder, so it is held to
    /// a move's destination rules and to the one name comparator.
    #[test]
    fn a_restore_lands_at_its_destination_and_auto_suffixes_a_taken_name() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "box", NodeKind::Folder);
        with_node(&mut base, id(1), id(2), "notes.txt", NodeKind::File);
        let local = base.clone();
        let resolved = rebase_one(
            &mut base,
            &local,
            &Op::restore(id(3), id(1), "notes.txt", NodeKind::File, 1, AT),
            SCOPE_ROOTS,
        );
        let OpResolution::Applied { effective_name, .. } = resolved else {
            panic!("a restore into a live folder applies");
        };
        assert_ne!(
            effective_name.as_deref().map(String::as_str),
            Some("notes.txt"),
            "the name the destination already holds is suffixed rather than duplicated",
        );
        assert_eq!(base.parent_of(id(3)), Some(id(1)));
    }

    /// A destination gate-passing state no longer holds is the same refusal a
    /// move gets, so the host is told the destination is what is missing.
    #[test]
    fn a_restore_into_a_destination_the_vault_lost_dead_letters() {
        let mut base = tree();
        let local = base.clone();
        assert_eq!(
            rebase_one(
                &mut base,
                &local,
                &Op::restore(id(3), id(9), "notes.txt", NodeKind::File, 1, AT),
                SCOPE_ROOTS,
            ),
            OpResolution::DeadLetter(DeadLetterReason::DestinationGone),
        );
    }

    #[test]
    fn conditional_delete_drops_when_the_target_advanced() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "f", NodeKind::File);
        base.node_mut(id(1)).unwrap().record_sequence = 5; // concurrent edit advanced it

        // The delete snapshotted the target at sequence 3.
        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::delete(id(1), 1, AT, 3, false),
            SCOPE_ROOTS,
        );
        assert_eq!(res, OpResolution::dropped(DropReason::TargetAdvanced));
        assert!(base.contains(id(1)), "edit wins — the node survives");
    }

    #[test]
    fn conditional_delete_applies_when_the_target_did_not_advance() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "f", NodeKind::File);
        base.node_mut(id(1)).unwrap().record_sequence = 3;

        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::delete(id(1), 1, AT, 3, false),
            SCOPE_ROOTS,
        );
        assert!(matches!(res, OpResolution::Applied { .. }));
        assert!(!base.contains(id(1)));
    }

    /// An applied folder delete takes its detached subtree out of the working
    /// base, so the pass's own later ops resolve against the tree the user sees.
    #[test]
    fn an_applied_delete_takes_its_detached_subtree_out_of_the_working_base() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "photos", NodeKind::Folder);
        with_node(&mut base, id(1), id(2), "trip", NodeKind::Folder);
        with_node(&mut base, id(2), id(3), "deep.bin", NodeKind::File);

        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::delete(id(1), 1, AT, 1, false),
            SCOPE_ROOTS,
        );

        assert!(matches!(res, OpResolution::Applied { .. }));
        assert!(!base.contains(id(2)), "no parentless descendant survives");
        assert!(!base.contains(id(3)));
    }

    /// The stated rebase decision for an op queued against a descendant of a
    /// folder this same pass deleted: the destination it anchored on is gone, so
    /// it dead-letters rather than publishing into a subtree no walk reaches.
    #[test]
    fn an_op_under_a_locally_deleted_folder_dead_letters() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "photos", NodeKind::Folder);
        with_node(&mut base, id(1), id(2), "trip.txt", NodeKind::File);

        let local = base.clone();
        rebase_one(
            &mut base,
            &local,
            &Op::delete(id(1), 1, AT, 1, false),
            SCOPE_ROOTS,
        );

        assert_eq!(
            rebase_one(
                &mut base,
                &local,
                &Op::rename(id(2), "n.txt", 1, AT),
                SCOPE_ROOTS
            ),
            OpResolution::DeadLetter(DeadLetterReason::TargetGone),
            "a rename of a detached descendant"
        );
        assert_eq!(
            rebase_one(
                &mut base,
                &local,
                &Op::create(id(4), id(2), "x", NewNode::Folder, 1, AT),
                SCOPE_ROOTS
            ),
            OpResolution::DeadLetter(DeadLetterReason::TargetGone),
            "a create under a detached descendant"
        );
        assert_eq!(
            rebase_one(
                &mut base,
                &local,
                &Op::delete(id(2), 1, AT, 1, false),
                SCOPE_ROOTS
            ),
            OpResolution::dropped(DropReason::AlreadySatisfied),
            "a delete of one — the unlink above it already satisfied it"
        );
    }

    /// The staged version a second edit authors, distinct from [`staged_k`] so
    /// the two heads are told apart by identity.
    fn staged_next() -> crate::sync::op::StagedContent {
        crate::sync::op::StagedContent {
            root_cid: b"next".to_vec(),
            ..staged_k()
        }
    }

    /// One edit-vs-edit fixture: a published file whose head the working base
    /// projects as `head`.
    fn edited_file(head: &[u8]) -> Snapshot {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "f.txt", NodeKind::File);
        let node = base.node_mut(id(1)).unwrap();
        node.content_version = Some(1);
        node.head_content_cid = Some(head.to_vec());
        base
    }

    #[test]
    fn conditional_edit_dead_letters_when_another_writer_took_the_head() {
        let mut working = edited_file(b"theirs");
        let local = working.clone();

        let res = rebase_one(
            &mut working,
            &local,
            &Op::update_content(id(1), staged_k(), Some(b"ours".to_vec()), 1, AT),
            SCOPE_ROOTS,
        );

        assert_eq!(
            res,
            OpResolution::DeadLetter(DeadLetterReason::BaseSuperseded)
        );
        assert_eq!(
            working.node(id(1)).unwrap().head_content_cid.as_deref(),
            Some(&b"theirs"[..]),
            "the concurrent version stands — the edit never applied over it"
        );
    }

    #[test]
    fn conditional_edit_applies_onto_the_version_it_was_formed_against() {
        let mut working = edited_file(b"head");
        let local = working.clone();

        let res = rebase_one(
            &mut working,
            &local,
            &Op::update_content(id(1), staged_k(), Some(b"head".to_vec()), 1, AT),
            SCOPE_ROOTS,
        );

        assert!(matches!(res, OpResolution::Applied { .. }));
        assert_eq!(working.node(id(1)).unwrap().content_version, Some(2));
        assert_eq!(
            working.node(id(1)).unwrap().head_content_cid,
            Some(staged_k().root_cid),
            "the applied edit is the head the next one anchors on"
        );
    }

    /// A base that has never projected the file's head judges nothing: the
    /// drain's live record decides.
    #[test]
    fn conditional_edit_defers_when_the_base_projected_no_head() {
        let mut working = tree();
        with_node(&mut working, id(0), id(1), "f.txt", NodeKind::File);
        let local = working.clone();

        let res = rebase_one(
            &mut working,
            &local,
            &Op::update_content(id(1), staged_k(), Some(b"head".to_vec()), 1, AT),
            SCOPE_ROOTS,
        );

        assert!(matches!(res, OpResolution::Applied { .. }));
    }

    /// Two edits of one file queued back to back: the first advances the
    /// working head, and the second — formed against that pending version — is
    /// its successor, not its rival.
    #[test]
    fn a_second_queued_edit_of_one_file_is_not_its_own_race() {
        let working = edited_file(b"head");
        let local = working.clone();
        let ops = [
            (
                OpId(1),
                Op::update_content(id(1), staged_k(), Some(b"head".to_vec()), 1, AT),
            ),
            (
                OpId(2),
                Op::update_content(id(1), staged_next(), Some(staged_k().root_cid), 1, AT),
            ),
        ];

        let report = replay(&working, &local, &ops, replay_scopes(SCOPE_ROOTS));

        assert!(report.dead_letters.is_empty(), "neither edit is a loser");
        assert_eq!(report.applied.len(), 2);
        assert_eq!(
            report.rebased.node(id(1)).unwrap().head_content_cid,
            Some(staged_next().root_cid)
        );
    }

    /// The second of two queued edits inherits the first one's fate: its anchor
    /// names a version that never published, so it cannot claim to be rebased
    /// on the head that beat it.
    #[test]
    fn a_second_queued_edit_dead_letters_behind_a_superseded_first() {
        let working = edited_file(b"theirs");
        let local = working.clone();
        let ops = [
            (
                OpId(1),
                Op::update_content(id(1), staged_k(), Some(b"ours".to_vec()), 1, AT),
            ),
            (
                OpId(2),
                Op::update_content(id(1), staged_next(), Some(staged_k().root_cid), 1, AT),
            ),
        ];

        let report = replay(&working, &local, &ops, replay_scopes(SCOPE_ROOTS));

        assert_eq!(
            report.dead_letters,
            vec![
                (OpId(1), DeadLetterReason::BaseSuperseded),
                (OpId(2), DeadLetterReason::BaseSuperseded),
            ]
        );
        assert!(report.applied.is_empty());
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
            &Op::update_content(id(1), staged_k(), None, 1, AT),
            SCOPE_ROOTS,
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
            &Op::update_content(id(1), staged_k(), None, 1, AT),
            SCOPE_ROOTS,
        );
        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: Some(Zeroizing::new("f (2).txt".to_owned())),
                suffixed: true,
                scope_exit_trigger: None,
            },
            "the resurrected node auto-suffixes off the taken name"
        );
        assert_eq!(working.node(id(1)).unwrap().name(), "f (2).txt");
        // Both siblings survive with distinct collation keys.
        let keys: std::collections::HashSet<String> = working
            .children(id(0))
            .iter()
            .map(|n| collation_key(n.name()).to_string())
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
            &Op::update_content(id(1), staged_k(), None, 1, AT),
            SCOPE_ROOTS,
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
            &Op::create(
                id(2),
                id(0),
                "a.txt",
                NewNode::File { content: None },
                1,
                AT,
            ),
            SCOPE_ROOTS,
        );
        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: Some(Zeroizing::new("a (2).txt".to_owned())),
                suffixed: true,
                scope_exit_trigger: None,
            }
        );
        assert_eq!(base.node(id(2)).unwrap().name(), "a (2).txt");
        // Both are visible.
        assert_eq!(base.children(id(0)).len(), 2);
    }

    /// The loser is re-authored under a name this device chose. One past the
    /// bound is dropped by the projection's narrow tier, which loses the member
    /// its own file — invisible and unremovable through the mount.
    #[test]
    fn an_add_add_loser_at_the_length_bound_stays_emittable() {
        let name = format!("{}.txt", "a".repeat(crate::name::MAX_NODE_NAME_BYTES - 4));
        let mut base = tree();
        with_node(&mut base, id(0), id(1), &name, NodeKind::File);

        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::create(id(2), id(0), &name, NewNode::File { content: None }, 1, AT),
            SCOPE_ROOTS,
        );

        let OpResolution::Applied {
            effective_name: Some(effective),
            suffixed: true,
            ..
        } = res
        else {
            panic!("the loser auto-suffixes: {res:?}");
        };
        assert!(
            crate::name::is_emittable(&effective),
            "{} bytes is past the bound",
            effective.len()
        );
        assert_eq!(base.children(id(0)).len(), 2, "both are visible");
    }

    #[test]
    fn rename_reanchors_onto_the_fresh_base_and_wins() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "start.txt", NodeKind::File);
        // A concurrent rename already moved it to "other.txt".
        base.node_mut(id(1)).unwrap().rename("other.txt");

        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::rename(id(1), "final.txt", 1, AT),
            SCOPE_ROOTS,
        );
        assert!(matches!(
            res,
            OpResolution::Applied {
                suffixed: false,
                ..
            }
        ));
        assert_eq!(
            base.node(id(1)).unwrap().name(),
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
            &Op::relink(id(2), id(0), id(1), 1, AT, ScopeCrossing::Intra),
            SCOPE_ROOTS,
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
            &Op::relink(id(3), id(0), id(1), 1, AT, ScopeCrossing::Intra),
            SCOPE_ROOTS,
        );
        assert_eq!(res, OpResolution::dropped(DropReason::MoveRaceLost));
        assert_eq!(
            base.parent_of(id(3)),
            Some(id(2)),
            "the winning move stands"
        );
        assert!(base.children(id(1)).is_empty(), "no dest-add residue");
    }

    /// `granted` (id 5) is a scope root holding a chain `a`/`b`/`c` down to
    /// depth 3, beside a sibling destination outside it.
    fn granted_scope() -> Snapshot {
        let mut base = tree();
        with_node(&mut base, id(0), id(5), "granted", NodeKind::Folder);
        with_node(&mut base, id(0), id(6), "dest", NodeKind::Folder);
        with_node(&mut base, id(5), id(10), "a", NodeKind::Folder);
        with_node(&mut base, id(10), id(11), "b", NodeKind::Folder);
        with_node(&mut base, id(11), id(12), "c", NodeKind::Folder);
        base
    }

    /// The scope roots for [`granted_scope`]: the vault root and the granted
    /// scope nested under it.
    const NESTED_ROOTS: &[NodeId] = &[NodeId([0; 16]), NodeId([5; 16])];

    /// A crossing is classified once, at journal time, and a grant minted since
    /// can move a boundary under either end. Re-derived here: a move that now
    /// names three scopes has no pass to author it, so it is terminal rather
    /// than a queue head no later tick clears.
    #[test]
    fn a_relocation_the_grants_moved_onto_three_scopes_dead_letters() {
        let mut base = granted_scope();
        with_node(&mut base, id(0), id(8), "other", NodeKind::Folder);
        with_node(&mut base, id(12), id(7), "moved", NodeKind::File);
        let local = base.clone();
        // Journaled intra-scope, before either grant cut a boundary.
        let ops = [(
            OpId(1),
            Op::relink(id(7), id(12), id(8), 1, AT, ScopeCrossing::Intra),
        )];
        let three = &[NodeId([0; 16]), NodeId([5; 16]), NodeId([8; 16])];

        let report = replay(&base, &local, &ops, replay_scopes(three));

        assert_eq!(
            report.dead_letters,
            [(OpId(1), DeadLetterReason::CrossingUnauthorable)],
            "the two ends now sit in two shared folders, and no pass carries three"
        );
        assert!(
            report.scope_exit_triggers.is_empty(),
            "and nothing was applied, so the exit it would have owed is not queued"
        );
    }

    /// The anchor is the one end a crossing may name beside an interior one.
    /// Reading the known set as the driving set would make this exit read as a
    /// three-scope crossing and refuse an op every pass can publish.
    #[test]
    fn an_exit_onto_the_anchor_stays_authorable() {
        let mut base = granted_scope();
        with_node(&mut base, id(12), id(7), "moved", NodeKind::File);
        let local = base.clone();
        let ops = [(
            OpId(1),
            Op::relink(
                id(7),
                id(12),
                id(6),
                1,
                AT,
                ScopeCrossing::ExitsGrantedSource,
            ),
        )];

        let report = replay(&base, &local, &ops, replay_scopes(NESTED_ROOTS));

        assert!(
            report.dead_letters.is_empty(),
            "the anchor is one of the ends"
        );
        assert_eq!(
            report.scope_exit_triggers,
            [id(5)],
            "and the granted scope it left is the one cut it owes"
        );
    }

    #[test]
    fn a_scope_exit_names_the_granted_root_at_depth_one_and_at_depth_n() {
        // The v1 coverage hole: a one-level check names `from_parent`, which is
        // the scope root only for the depth-1 move.
        for (from_parent, depth) in [(id(5), 1), (id(12), 4)] {
            let mut base = granted_scope();
            with_node(&mut base, from_parent, id(7), "moved", NodeKind::File);
            let local = base.clone();
            let res = rebase_one(
                &mut base,
                &local,
                &Op::relink(
                    id(7),
                    from_parent,
                    id(6),
                    1,
                    AT,
                    ScopeCrossing::ExitsGrantedSource,
                ),
                NESTED_ROOTS,
            );
            assert_eq!(
                res,
                OpResolution::Applied {
                    effective_name: None,
                    suffixed: false,
                    scope_exit_trigger: Some(id(5)),
                },
                "an exit from depth {depth} names the granted scope root"
            );
        }
    }

    #[test]
    fn a_cross_scope_move_with_rename_queues_the_same_trigger() {
        // A kernel rename journals `Move`, not `Relink`, so the desktop's whole
        // move surface would be blind to a scope exit if this did not fire.
        let mut base = granted_scope();
        with_node(&mut base, id(12), id(7), "moved", NodeKind::File);
        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(7),
                id(12),
                id(6),
                "renamed.txt",
                None,
                1,
                AT,
                ScopeCrossing::ExitsGrantedSource,
            ),
            NESTED_ROOTS,
        );
        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: Some(Zeroizing::new("renamed.txt".to_owned())),
                suffixed: false,
                scope_exit_trigger: Some(id(5)),
            }
        );
    }

    #[test]
    fn a_source_chain_reaching_no_listed_root_falls_back_to_the_snapshot_root() {
        // Rotating an enclosing root over-rotates; rotating nothing would leave
        // a revokee holding a live seed.
        let mut base = granted_scope();
        with_node(&mut base, id(12), id(7), "moved", NodeKind::File);
        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::relink(
                id(7),
                id(12),
                id(6),
                1,
                AT,
                ScopeCrossing::ExitsGrantedSource,
            ),
            &[],
        );
        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: None,
                suffixed: false,
                scope_exit_trigger: Some(id(0)),
            }
        );
    }

    #[test]
    fn a_move_that_loses_its_race_queues_no_trigger() {
        // The exit never happened here, so there is nothing to rotate for.
        let mut base = granted_scope();
        with_node(&mut base, id(11), id(7), "moved", NodeKind::File);
        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::relink(
                id(7),
                id(12),
                id(6),
                1,
                AT,
                ScopeCrossing::ExitsGrantedSource,
            ),
            NESTED_ROOTS,
        );
        assert_eq!(res, OpResolution::dropped(DropReason::MoveRaceLost));
    }

    /// The `(base, local)` pair for a move over `dir`/`f` plus an occupied
    /// destination name, with the replaced node at `sequence`.
    fn replace_tree(replaced_sequence: u64) -> Snapshot {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "dir", NodeKind::Folder);
        with_node(&mut base, id(0), id(2), "f.txt", NodeKind::File);
        with_node(&mut base, id(1), id(3), "target.txt", NodeKind::File);
        base.node_mut(id(3)).unwrap().record_sequence = replaced_sequence;
        base
    }

    fn replacing(sequence: u64) -> Option<Replaced> {
        Some(Replaced {
            node: id(3),
            sequence,
        })
    }

    #[test]
    fn a_move_that_replaces_lands_under_the_entered_name() {
        let mut base = replace_tree(1);
        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(0),
                id(1),
                "target.txt",
                replacing(1),
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );
        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: Some(Zeroizing::new("target.txt".to_owned())),
                suffixed: false,
                scope_exit_trigger: None,
            },
            "vacating the destination first is what keeps the entered name"
        );
        assert!(!base.contains(id(3)), "the replaced node is gone");
        assert_eq!(base.parent_of(id(2)), Some(id(1)));
        assert_eq!(base.node(id(2)).unwrap().name(), "target.txt");
        assert!(base.children(id(0)).iter().all(|c| c.id != id(2)));
    }

    /// The vacate is a delete, so it owes the delete's cascade: a descendant of
    /// the replaced folder still answering is a node no walk reaches.
    /// `replace_tree`'s destination node is a file, and a file holds no
    /// children: the vacate cascade only has something to take when the
    /// replaced node is a folder.
    fn replaced_folder_tree() -> Snapshot {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "dir", NodeKind::Folder);
        with_node(&mut base, id(0), id(2), "f.txt", NodeKind::File);
        with_node(&mut base, id(1), id(3), "target.txt", NodeKind::Folder);
        base
    }

    #[test]
    fn a_move_that_replaces_a_folder_takes_its_subtree() {
        let mut base = replaced_folder_tree();
        with_node(&mut base, id(3), id(4), "inner", NodeKind::Folder);
        with_node(&mut base, id(4), id(5), "deep.bin", NodeKind::File);
        let local = base.clone();

        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(0),
                id(1),
                "target.txt",
                replacing(1),
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );

        assert!(matches!(res, OpResolution::Applied { .. }));
        assert!(!base.contains(id(3)), "the replaced folder is gone");
        assert!(
            !base.contains(id(4)),
            "and no descendant is left parentless"
        );
        assert!(!base.contains(id(5)));
        assert_eq!(base.parent_of(id(2)), Some(id(1)));
    }

    /// The rebase decision for a later op under a vacated folder, stated the
    /// same way the delete direction states it: the node is gone from the
    /// working base, so the op has nothing to rebase onto.
    #[test]
    fn an_op_under_a_vacated_folder_dead_letters_as_target_gone() {
        let base = {
            let mut base = replaced_folder_tree();
            with_node(&mut base, id(3), id(4), "deep.bin", NodeKind::File);
            base
        };
        let local = base.clone();

        let report = replay(
            &base,
            &local,
            &[
                (
                    OpId(1),
                    Op::move_node(
                        id(2),
                        id(0),
                        id(1),
                        "target.txt",
                        replacing(1),
                        1,
                        AT,
                        ScopeCrossing::Intra,
                    ),
                ),
                (OpId(2), Op::rename(id(4), "renamed.bin", 1, AT)),
            ],
            replay_scopes(SCOPE_ROOTS),
        );

        assert_eq!(report.applied.len(), 1, "the move applies");
        assert_eq!(
            report.dead_letters,
            vec![(OpId(2), DeadLetterReason::TargetGone)],
            "the op under the vacated folder has nothing left to rebase onto"
        );
    }

    /// A move publishes dest-first, so the destination ref shares the wire with
    /// the source ref until the source-remove lands. The dest link must out-rank
    /// it, or the dual-link tiebreak falls to the lowest parent id and a reader
    /// can pick the parent this move left.
    #[test]
    fn a_cross_folder_move_links_above_the_source_it_has_not_removed_yet() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "dir", NodeKind::Folder);
        with_node(&mut base, id(0), id(2), "f.txt", NodeKind::File);
        base.link(id(0), id(2), 7);
        let local = base.clone();

        rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(0),
                id(1),
                "g.txt",
                None,
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );

        assert_eq!(
            base.winning_link(id(2)).map(|l| l.link_counter),
            Some(8),
            "the dest link supersedes the source counter it replaces"
        );
    }

    /// The ordering hazard: the replaced node is the moved target's own
    /// ancestor, so a cascade taken before the re-link would sweep the target.
    #[test]
    fn a_move_out_of_the_folder_it_replaces_keeps_its_target() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "target.txt", NodeKind::Folder);
        with_node(&mut base, id(1), id(2), "keep", NodeKind::Folder);
        with_node(&mut base, id(1), id(3), "sweep.bin", NodeKind::File);
        with_node(&mut base, id(2), id(4), "kept.bin", NodeKind::File);
        let local = base.clone();

        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(1),
                id(0),
                "target.txt",
                Some(Replaced {
                    node: id(1),
                    sequence: 1,
                }),
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );

        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: Some(Zeroizing::new("target.txt".to_owned())),
                suffixed: false,
                scope_exit_trigger: None,
            },
            "the target takes the name its own ancestor held"
        );
        assert_eq!(base.parent_of(id(2)), Some(id(0)), "the target survives");
        assert!(base.contains(id(4)), "and so does what it carries");
        assert!(!base.contains(id(1)), "the replaced ancestor is gone");
        assert!(!base.contains(id(3)), "and so is what it alone reached");
    }

    #[test]
    fn a_move_auto_suffixes_when_a_concurrent_edit_saves_the_node_it_would_replace() {
        // Conditional delete in both directions: the edit keeps the destination
        // and the mover lands beside it rather than over it.
        let mut base = replace_tree(9);
        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(0),
                id(1),
                "target.txt",
                replacing(1),
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );
        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: Some(Zeroizing::new("target (2).txt".to_owned())),
                suffixed: true,
                scope_exit_trigger: None,
            }
        );
        assert!(base.contains(id(3)), "the edited node survives");
        assert_eq!(base.node(id(2)).unwrap().name(), "target (2).txt");
    }

    #[test]
    fn a_move_spares_a_node_a_concurrent_writer_renamed_out_of_its_way() {
        // A name lives in the parent's child ref, so renaming a node never
        // advances the node's own sequence — the conditional-delete anchor
        // alone would see this as "unchanged" and destroy a bystander.
        let mut base = replace_tree(1);
        base.node_mut(id(3)).unwrap().rename("keep.txt");
        let local = base.clone();

        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(0),
                id(1),
                "target.txt",
                replacing(1),
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );
        assert_eq!(
            res,
            OpResolution::Applied {
                effective_name: Some(Zeroizing::new("target.txt".to_owned())),
                suffixed: false,
                scope_exit_trigger: None,
            },
            "the contested name is free, so the move just takes it"
        );
        assert!(base.contains(id(3)), "the renamed bystander survives");
        assert_eq!(base.node(id(3)).unwrap().name(), "keep.txt");
    }

    #[test]
    fn a_move_spares_a_node_a_concurrent_writer_moved_out_of_its_way() {
        let mut base = replace_tree(1);
        base.unlink(id(1), id(3));
        base.link(id(0), id(3), 2);
        let local = base.clone();

        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(0),
                id(1),
                "target.txt",
                replacing(1),
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );
        assert!(matches!(
            res,
            OpResolution::Applied {
                suffixed: false,
                ..
            }
        ));
        assert_eq!(
            base.parent_of(id(3)),
            Some(id(0)),
            "the relocated bystander is untouched where it now lives"
        );
    }

    #[test]
    fn a_move_that_names_its_own_target_as_the_replaced_node_keeps_it() {
        // `Command::Move` is a public facade surface; vacating the target would
        // erase the very node the op moves, and every later op on it would then
        // dead-letter as `TargetGone`.
        let mut base = replace_tree(1);
        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(0),
                id(0),
                "renamed.txt",
                Some(Replaced {
                    node: id(2),
                    sequence: 1,
                }),
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );
        assert!(matches!(res, OpResolution::Applied { .. }));
        assert!(base.contains(id(2)), "the target survives its own replace");
        assert_eq!(base.node(id(2)).unwrap().name(), "renamed.txt");
        assert_eq!(base.parent_of(id(2)), Some(id(0)));
    }

    #[test]
    fn a_move_renames_in_place_without_disturbing_the_link() {
        let mut base = replace_tree(1);
        let counter_before = base.winning_link(id(2)).unwrap().link_counter;
        let local = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(0),
                id(0),
                "g.txt",
                None,
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );
        assert!(matches!(
            res,
            OpResolution::Applied {
                suffixed: false,
                ..
            }
        ));
        assert_eq!(base.node(id(2)).unwrap().name(), "g.txt");
        assert_eq!(base.parent_of(id(2)), Some(id(0)));
        assert_eq!(
            base.winning_link(id(2)).unwrap().link_counter,
            counter_before,
            "a rename in place is not a relink"
        );
    }

    #[test]
    fn a_move_whose_child_a_concurrent_move_took_loses_the_race_untouched() {
        let mut base = replace_tree(1);
        with_node(&mut base, id(0), id(4), "elsewhere", NodeKind::Folder);
        base.unlink(id(0), id(2));
        base.link(id(4), id(2), 2);
        let local = base.clone();

        let before = base.clone();
        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(0),
                id(1),
                "target.txt",
                replacing(1),
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );
        assert_eq!(res, OpResolution::dropped(DropReason::MoveRaceLost));
        assert_eq!(
            base, before,
            "a dropped move must not have vacated the destination"
        );
    }

    #[test]
    fn a_move_dead_letters_rather_than_vacating_a_destination_it_cannot_reach() {
        let base = replace_tree(1);
        let cases = [
            (id(9), id(2), DeadLetterReason::DestinationGone),
            (id(1), id(9), DeadLetterReason::TargetGone),
        ];
        for (dest, target, reason) in cases {
            let mut working = base.clone();
            let res = rebase_one(
                &mut working,
                &base,
                &Op::move_node(
                    target,
                    id(0),
                    dest,
                    "target.txt",
                    replacing(1),
                    1,
                    AT,
                    ScopeCrossing::Intra,
                ),
                SCOPE_ROOTS,
            );
            assert_eq!(res, OpResolution::DeadLetter(reason));
            assert_eq!(working, base, "a dead letter changes nothing");
        }
    }

    #[test]
    fn a_move_already_landed_drops_as_satisfied() {
        let mut base = replace_tree(1);
        base.remove_deleted(id(3));
        base.unlink(id(0), id(2));
        base.link(id(1), id(2), 2);
        base.node_mut(id(2)).unwrap().rename("target.txt");
        let local = base.clone();

        let res = rebase_one(
            &mut base,
            &local,
            &Op::move_node(
                id(2),
                id(0),
                id(1),
                "target.txt",
                replacing(1),
                1,
                AT,
                ScopeCrossing::Intra,
            ),
            SCOPE_ROOTS,
        );
        assert_eq!(res, OpResolution::dropped(DropReason::AlreadySatisfied));
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
                NewNode::File {
                    content: Some(staged_k()),
                },
                1,
                AT,
            ),
            SCOPE_ROOTS,
        );
        assert_eq!(res, OpResolution::DeadLetter(DeadLetterReason::TargetGone));
    }

    #[test]
    fn a_relink_inside_the_moved_subtree_names_its_own_reason() {
        let mut base = tree();
        with_node(&mut base, id(0), id(1), "photos", NodeKind::Folder);
        with_node(&mut base, id(1), id(2), "2026", NodeKind::Folder);
        let local = base.clone();

        for dest in [id(1), id(2)] {
            let res = rebase_one(
                &mut base.clone(),
                &local,
                &Op::relink(id(1), id(0), dest, 1, AT, ScopeCrossing::Intra),
                SCOPE_ROOTS,
            );
            assert_eq!(
                res,
                OpResolution::DeadLetter(DeadLetterReason::DestinationInsideTarget),
                "a present destination inside the target is not a missing one"
            );
        }
    }

    /// A move reports the node **it** vacated, so the publisher drops that ref
    /// and no other. A node that merely left the rebased snapshot as the
    /// detached descendant of an earlier delete is not this move's to unlink —
    /// it never faced the conditional delete.
    #[test]
    fn a_move_reports_only_the_destination_it_vacated_itself() {
        let mut gate_passing = tree();
        with_node(&mut gate_passing, id(0), id(1), "doomed", NodeKind::Folder);
        with_node(&mut gate_passing, id(1), id(2), "under.txt", NodeKind::File);
        with_node(&mut gate_passing, id(0), id(3), "mover.txt", NodeKind::File);

        let replacing = Some(Replaced {
            node: id(2),
            sequence: 1,
        });
        let ops = vec![
            (OpId(1), Op::delete(id(1), 1, AT, 1, false)),
            (
                OpId(2),
                Op::move_node(
                    id(3),
                    id(0),
                    id(0),
                    "under.txt",
                    replacing,
                    1,
                    AT,
                    ScopeCrossing::Intra,
                ),
            ),
        ];
        let report = replay(
            &gate_passing,
            &gate_passing,
            &ops,
            replay_scopes(SCOPE_ROOTS),
        );

        assert_eq!(report.applied.len(), 2);
        assert!(
            !report.rebased.contains(id(2)),
            "the delete's cascade took it"
        );
        assert_eq!(
            report.applied[1].vacated, None,
            "but the move never vacated it, so its ref is not the move's to drop"
        );
    }

    /// The other direction: a move that really does win the conditional delete
    /// against the node holding its name reports it.
    #[test]
    fn a_move_that_wins_the_conditional_delete_reports_the_node_it_freed() {
        let mut gate_passing = tree();
        with_node(&mut gate_passing, id(0), id(1), "dest", NodeKind::Folder);
        with_node(&mut gate_passing, id(1), id(2), "taken.txt", NodeKind::File);
        with_node(&mut gate_passing, id(0), id(3), "mover.txt", NodeKind::File);

        let replacing = Some(Replaced {
            node: id(2),
            sequence: 1,
        });
        let ops = vec![(
            OpId(1),
            Op::move_node(
                id(3),
                id(0),
                id(1),
                "taken.txt",
                replacing,
                1,
                AT,
                ScopeCrossing::Intra,
            ),
        )];
        let report = replay(
            &gate_passing,
            &gate_passing,
            &ops,
            replay_scopes(SCOPE_ROOTS),
        );

        assert_eq!(report.applied[0].vacated, Some(id(2)));
        assert!(!report.rebased.contains(id(2)));
    }

    #[test]
    fn replay_threads_the_base_and_buckets_every_outcome() {
        let mut gate_passing = tree();
        with_node(&mut gate_passing, id(0), id(1), "keep", NodeKind::Folder);

        let ops = vec![
            (
                OpId(1),
                Op::create(
                    id(2),
                    id(1),
                    "a.txt",
                    NewNode::File { content: None },
                    1,
                    AT,
                ),
            ),
            (
                OpId(2),
                Op::create(
                    id(3),
                    id(1),
                    "a.txt",
                    NewNode::File { content: None },
                    1,
                    AT,
                ),
            ), // collides → suffix
            (
                OpId(3),
                Op::create(
                    id(4),
                    id(99),
                    "orphan",
                    NewNode::File { content: None },
                    1,
                    AT,
                ),
            ), // dead-letter
        ];
        let report = replay(
            &gate_passing,
            &gate_passing,
            &ops,
            replay_scopes(SCOPE_ROOTS),
        );

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
        let me = X25519Secret::from_scalar([1; 32]);
        let good = encode_op_record(
            RecordSeal {
                owner_enc_secret: &me,
                ephemeral_scalar: Zeroizing::new([2; 32]),
            },
            &Op::rename(id(1), "n", 1, AT),
        )
        .unwrap();
        let raw = vec![(OpId(1), good), (OpId(2), b"garbage".to_vec())];
        let scan = decode_queue(&RecordReader::new(&me), &raw);
        assert_eq!(scan.mine.len(), 1);
        assert_eq!(
            scan.undecodable,
            vec![(OpId(2), DeadLetterReason::Undecodable)]
        );
        assert_eq!(scan.retained, 0);
    }

    #[test]
    fn decode_queue_leaves_another_accounts_records_invisible() {
        let me = X25519Secret::from_scalar([1; 32]);
        let stranger = X25519Secret::from_scalar([2; 32]);
        let theirs = encode_op_record(
            RecordSeal {
                owner_enc_secret: &stranger,
                ephemeral_scalar: Zeroizing::new([3; 32]),
            },
            &Op::rename(id(1), "theirs", 1, AT),
        )
        .unwrap();

        let scan = decode_queue(&RecordReader::new(&me), &[(OpId(1), theirs)]);
        assert!(scan.mine.is_empty(), "never replayed");
        assert!(
            scan.undecodable.is_empty(),
            "never dead-lettered — the caller removes what it dead-letters"
        );
        assert_eq!(
            scan.retained, 1,
            "held records are counted, so the host can say the device is not empty"
        );
    }

    #[test]
    fn decode_queue_retains_records_this_build_cannot_interpret() {
        let me = X25519Secret::from_scalar([1; 32]);
        let mine = encode_op_record(
            RecordSeal {
                owner_enc_secret: &me,
                ephemeral_scalar: Zeroizing::new([2; 32]),
            },
            &Op::rename(id(1), "n", 1, AT),
        )
        .unwrap();

        // A newer header format, and a newer intent grammar under a seal that
        // opens. Neither may reach the dead-letter path, which removes.
        let newer_header = {
            let value = cipherbox_core::codec::decode(&mine).unwrap();
            let mut map = value.as_map().unwrap().clone();
            map.insert(
                "v",
                cipherbox_core::codec::Value::Unsigned(
                    cipherbox_core::seal::op_record::OP_RECORD_V + 1,
                ),
            );
            cipherbox_core::codec::encode(&cipherbox_core::codec::Value::Map(map)).unwrap()
        };
        let newer_grammar = cipherbox_core::seal::op_record::seal_op_record(
            &me,
            &[4; 32],
            None,
            b"{\"someFutureOp\":true}",
        )
        .unwrap();

        for (label, record) in [
            ("newer header", newer_header),
            ("newer grammar", newer_grammar),
        ] {
            let scan = decode_queue(&RecordReader::new(&me), &[(OpId(1), record)]);
            assert!(scan.mine.is_empty(), "{label} must not replay");
            assert!(
                scan.undecodable.is_empty(),
                "{label} must not be dead-lettered — that path removes it"
            );
            assert_eq!(scan.retained, 1, "{label} must be held");
        }
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

    // --- queue-scan memo: every test counts the records a decode pass opened,
    // because that count is the per-render HPKE cost ---

    mod queue_scan_memo {
        use super::*;
        use std::cell::Cell;

        fn owner(b: u8) -> X25519Secret {
            X25519Secret::from_scalar([b; 32])
        }

        /// One durable queue entry sealed to `secret`.
        fn entry(secret: &X25519Secret, op_id: u64) -> (OpId, Vec<u8>) {
            let record = encode_op_record(
                RecordSeal {
                    owner_enc_secret: secret,
                    ephemeral_scalar: Zeroizing::new([op_id as u8; 32]),
                },
                &Op::rename(id(op_id as u8), "n", 1, AT),
            )
            .unwrap();
            (OpId(op_id), record)
        }

        /// Scan through the memo, tallying every record the decode pass read.
        fn scan(
            memo: &mut QueueScanMemo,
            secret: &X25519Secret,
            raw: &[(OpId, Vec<u8>)],
            opened: &Cell<usize>,
        ) -> QueueScan {
            memo.scan(&RecordReader::new(secret), raw, |reader, raw| {
                opened.set(opened.get() + raw.len());
                decode_queue(reader, raw)
            })
            .clone()
        }

        #[test]
        fn an_unchanged_queue_is_opened_once_however_often_it_is_read() {
            let me = owner(1);
            let queue = vec![entry(&me, 1), entry(&me, 2)];
            let opened = Cell::new(0);
            let mut memo = QueueScanMemo::default();

            let first = scan(&mut memo, &me, &queue, &opened);
            for _ in 0..5 {
                assert_eq!(scan(&mut memo, &me, &queue, &opened), first);
            }
            assert_eq!(first.mine.len(), 2);
            assert_eq!(opened.get(), 2, "six reads, one open per record");
        }

        #[test]
        fn an_enqueued_op_is_read_on_the_next_scan() {
            let me = owner(2);
            let mut queue = vec![entry(&me, 1)];
            let opened = Cell::new(0);
            let mut memo = QueueScanMemo::default();
            scan(&mut memo, &me, &queue, &opened);

            queue.push(entry(&me, 2));
            assert_eq!(
                scan(&mut memo, &me, &queue, &opened).mine.len(),
                2,
                "the memo must not outlive an enqueue it did not perform"
            );
            assert_eq!(opened.get(), 3);
        }

        #[test]
        fn a_removed_op_is_gone_from_the_next_scan() {
            let me = owner(3);
            let mut queue = vec![entry(&me, 1), entry(&me, 2)];
            let opened = Cell::new(0);
            let mut memo = QueueScanMemo::default();
            scan(&mut memo, &me, &queue, &opened);

            queue.remove(0);
            assert_eq!(
                scan(&mut memo, &me, &queue, &opened).mine,
                vec![(OpId(2), Op::rename(id(2), "n", 1, AT))],
                "a drained op must never re-render off the memo"
            );
            assert_eq!(opened.get(), 3);
        }

        /// The one shape a length check alone would miss: the queue keeps its
        /// size while its contents turn over.
        #[test]
        fn a_removal_paired_with_an_enqueue_is_read_on_the_next_scan() {
            let me = owner(4);
            let mut queue = vec![entry(&me, 1), entry(&me, 2)];
            let opened = Cell::new(0);
            let mut memo = QueueScanMemo::default();
            scan(&mut memo, &me, &queue, &opened);

            queue.remove(0);
            queue.push(entry(&me, 3));
            assert_eq!(
                scan(&mut memo, &me, &queue, &opened)
                    .mine
                    .iter()
                    .map(|(op_id, _)| *op_id)
                    .collect::<Vec<_>>(),
                vec![OpId(2), OpId(3)]
            );
            assert_eq!(opened.get(), 4);
        }

        #[test]
        fn another_identity_never_reads_the_first_ones_scan() {
            let me = owner(5);
            let stranger = owner(6);
            let queue = vec![entry(&me, 1)];
            let opened = Cell::new(0);
            let mut memo = QueueScanMemo::default();
            assert_eq!(scan(&mut memo, &me, &queue, &opened).mine.len(), 1);

            let theirs = scan(&mut memo, &stranger, &queue, &opened);
            assert!(
                theirs.mine.is_empty() && theirs.retained == 1,
                "a memo hit must never hand one identity another's opened intent"
            );
            assert_eq!(opened.get(), 2, "the reading identity is part of the key");
        }
    }

    /// The name the rebase resolved for an op is still a filename, auto-suffix
    /// and all.
    #[test]
    fn debug_renders_no_effective_name() {
        let applied = AppliedOp {
            op_id: OpId(1),
            op: Op::rename(NodeId([1; 16]), "secret-name.txt", 1, AT),
            effective_name: Some("secret-name (2).txt".to_owned()),
            suffixed: true,
            vacated: None,
        };
        let rendered = format!("{applied:?}");

        assert!(
            !rendered.contains("secret-name"),
            "a filename never renders: {rendered}"
        );
        assert!(rendered.contains("AppliedOp"), "the shape survives");
        assert!(rendered.contains("redacted"), "{rendered}");
    }
}
