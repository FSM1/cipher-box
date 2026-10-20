//! The map step of a dissolve (ADR 0077 D3): a two-sweep walk of the cut
//! subtree that mints the copy's node ids.
//!
//! Membership rests on what the cut made fresh. The walk reads each node at
//! the name that the post-cut write seed of its scope derives, never at the
//! name a child ref carries, and the gate binds the node id and the scope id
//! into each record's AAD. A nested scope root counts only when the gated
//! index of the scope it sits in names it, and its root gate opens its ascent
//! link under the read seed of that scope. The map commits only after a
//! second sweep reads each node to the same record (blueprint/engine.md
//! "Owner capture").

use core::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildRef, Envelope, ReadBody, decode_grant_section, decode_write_body, grant_section_bytes,
    has_grant_section,
};
use cipherbox_core::suite::secret::ct_eq;
use zeroize::Zeroizing;

use super::walker::{Overflow, ReadFault, SweepPolicy, Swept, TwoSweep};
use super::{
    Anchor, Drain, DrainScope, Halt, LoadedNode, LoadedRoot, RecordMark, ScopeEnd, WalkAnchor,
    refuse_record, seal_open_failed, seam, seed_for_lagging, take_tick_read, walk_fault,
};
use crate::entropy::fresh_bytes;
use crate::facade::{NodeId, emit_trust_violation};
use crate::gate::{Adopted, GateError, GateRejection, GateStage, RejectionReason, floor};
use crate::net::fork::served_fork;
use crate::net::gated_read::{LeafRead, LeafRefusal};
use crate::net::rotation::unseal_write_body;
use crate::net::{
    Adopter, ChildAdopter, ResolveOutcome, RootAdopter, assemble_head_envelope, resolve_gated,
};
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SharerScopedFloorStore,
    SnapshotCache, StagingStore,
};
use crate::sync::dissolve_journal::{
    DissolveHeader, DissolveHold, DissolveJournal, DissolveStep, DissolveWriteError,
    DissolvedScope, HeaderSlot, MAX_PAGE_ENTRIES, MapPage, MapRow,
};
use crate::sync::kept_op::retain_pending;
use crate::sync::model::Snapshot;
use crate::sync::op::Op;
use crate::sync::rebase::decode_queue;
use crate::sync::record::RecordReader;
use crate::sync::tick::ResolveMode;

mod relink;
mod seal;

pub(crate) use seal::DissolveSeal;

/// The node records one tick reads for dissolve walks.
const MAX_DISSOLVE_WALK_READS: usize = 128;

/// The nodes one dissolve walk may hold. A walk past it stops the dissolve.
const MAX_DISSOLVE_WALK_NODES: usize = 65_536;

/// The unanswered attempts a dissolve walk makes at one read, one per tick,
/// before it starts again.
const MAX_DISSOLVE_READ_ATTEMPTS: u8 = 3;

/// One node of a dissolve walk: the node, the scope root whose end reads it,
/// and the walk index of the folder that names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WalkKey {
    node: NodeId,
    scope: NodeId,
    parent: Option<u32>,
}

/// What a scope root's read gives the walk.
pub(super) struct RootFacts {
    anchor: WalkAnchor,
    /// The scope roots that the gated `directChildScopeIndex` names. Empty
    /// when the root holds a row or another cut, which stops the walk.
    index: BTreeSet<NodeId>,
    /// The commitment holds a row.
    rows: bool,
    cut_epoch: u64,
}

/// One node as the record plane serves it now.
pub(super) struct DissolveRead {
    mark: RecordMark,
    children: Vec<ChildRef>,
    /// Set when the node is a scope root.
    root: Option<RootFacts>,
}

/// A child read that a gate passed outside the walked subtree.
#[derive(Debug)]
pub(super) enum Unmapped {
    /// The root gate passes the child as a scope root the dissolve does not
    /// cut: a folder shared after the cut, whose parent index can still be
    /// owed. The dissolve stops.
    NewScopeRoot,
    /// The child opens under another end of the tick that the dissolve does
    /// not cut: a node outside the subtree. The walk starts again.
    Outside,
}

/// What a walk holds of one end's material: a read cut moves the stamp, and a
/// name wave moves the root name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EndMark {
    root_name: String,
    stamp: Option<u64>,
}

impl EndMark {
    fn of(end: &ScopeEnd<'_>) -> Self {
        Self {
            root_name: end.root_name.as_str().to_owned(),
            stamp: end.read_seed_stamp,
        }
    }
}

/// The map walk of one dissolve entry, carried across ticks.
pub(crate) struct DissolveWalk {
    /// The scopes and the cut epochs of the header it walks. Another header
    /// starts the walk again.
    scopes: Vec<(NodeId, u64)>,
    sweep: TwoSweep<WalkKey>,
    anchors: BTreeMap<NodeId, WalkAnchor>,
    indexes: BTreeMap<NodeId, BTreeSet<NodeId>>,
    /// The material of each end whose root gave an anchor. Other material
    /// starts the walk again.
    marks: BTreeMap<NodeId, EndMark>,
    /// A gate refused a record of the walk, or the endpoints served a
    /// same-sequence fork. The walk reads no more until a new header or new
    /// material of a marked end. A refusal at the first root read marks no
    /// end, so that hold lasts until a new header.
    refused: bool,
    /// The copy started, so a scope that a gated index names and the
    /// dissolve does not cut joins the dissolve.
    joining: bool,
}

/// Why a first-sweep visit stopped the walk.
#[derive(Debug, PartialEq, Eq)]
enum MapHalt {
    /// A diamond, or a scope root that the gated index does not name yet:
    /// the next tick walks again.
    Restart,
    /// A row, a cut, or a scope root that the dissolve did not make.
    Concurrent,
    /// The walk passed its node bound.
    TooLarge,
    /// A gated index names these scopes, which the dissolve does not cut,
    /// after the copy started.
    Joined(BTreeSet<NodeId>),
}

/// Where one tick left a dissolve walk.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum MapStep {
    /// Reads remain for a later tick.
    Unfinished,
    /// Every node read twice to the same record.
    Complete,
    /// A node moved, a visit found a diamond or an unindexed root, or a read
    /// went unanswered too long: the next tick walks again.
    Restart,
    /// A gate refused a record, or the endpoints served a fork.
    Refused,
    /// The dissolve stops before the copy.
    Stop,
    /// Each scope that a gated index names and the dissolve does not cut
    /// joins the dissolve, which returns to its cut step (ADR 0077 D4).
    Join(Vec<NodeId>),
}

/// The floor-store key of the relink mark of the parent name `name`: the
/// highest sequence that a relink publish signed there. Each folder publish
/// at `name` signs above it, so none signs other bytes at a relink sequence.
pub(super) fn parent_mark_key(name: &[u8]) -> Vec<u8> {
    [b"dissolve-relink-parent/".as_slice(), name].concat()
}

fn scope_ids(header: &DissolveHeader) -> Vec<(NodeId, u64)> {
    header
        .scopes
        .iter()
        .map(|scope| (scope.scope_id, scope.cut_epoch))
        .collect()
}

/// Whether `child`, the end of a nested scope root, takes its ascent
/// authority from the read seed of `parent`.
fn ascends_from(parent: &ScopeEnd<'_>, child: &ScopeEnd<'_>) -> bool {
    child.ascent_node_seed.is_some_and(|seed| {
        ct_eq(
            kdf::node_seed(parent.read_scope_seed, &child.root.0).as_bytes(),
            seed,
        )
    })
}

/// Whether a cut scope root that holds `rows` at `cut_epoch` shows work that
/// the dissolve did not do, against `cut`, the cut epoch of the entry.
fn cut_overtaken(rows: bool, cut_epoch: u64, cut: Option<u64>) -> bool {
    rows || Some(cut_epoch) != cut
}

/// The cut epoch at which `header` cuts `scope`, `None` when it does not cut
/// it.
fn cut_epoch_of(header: &DissolveHeader, scope: NodeId) -> Option<u64> {
    header
        .scopes
        .iter()
        .find(|cut| cut.scope_id == scope)
        .map(|cut| cut.cut_epoch)
}

impl DissolveWalk {
    pub(super) fn new(header: &DissolveHeader, source_root: NodeId) -> Self {
        let first = WalkKey {
            node: source_root,
            scope: source_root,
            parent: None,
        };
        Self {
            scopes: scope_ids(header),
            sweep: TwoSweep::new(first, source_root),
            anchors: BTreeMap::new(),
            indexes: BTreeMap::new(),
            marks: BTreeMap::new(),
            refused: false,
            joining: header.copy_started,
        }
    }

    fn walks(&self, header: &DissolveHeader) -> bool {
        self.scopes == scope_ids(header) && self.joining == header.copy_started
    }

    /// Whether each end that gave an anchor still has the material it had. An
    /// end absent from the tick brings no material, and its reads go
    /// unanswered.
    fn keeps_material(&self, mark: impl Fn(NodeId) -> Option<EndMark>) -> bool {
        self.marks
            .iter()
            .all(|(scope, held)| mark(*scope).is_none_or(|now| now == *held))
    }

    /// Hold the material of each end whose root gave an anchor.
    fn note_material(&mut self, mark: impl Fn(NodeId) -> Option<EndMark>) {
        for scope in self.anchors.keys() {
            if !self.marks.contains_key(scope)
                && let Some(held) = mark(*scope)
            {
                self.marks.insert(*scope, held);
            }
        }
    }

    /// Spend reads from `left` on the walk, through `read`. `ascends` answers
    /// whether the end of the second scope root takes its ascent authority from
    /// the read seed of the first.
    pub(super) async fn step(
        &mut self,
        left: &Cell<usize>,
        bound: usize,
        ascends: &dyn Fn(NodeId, NodeId) -> bool,
        read: impl AsyncFn(&WalkKey, Option<Anchor<'_>>) -> Result<DissolveRead, ReadFault<Unmapped>>,
    ) -> MapStep {
        let Self {
            scopes,
            sweep,
            anchors,
            indexes,
            joining,
            ..
        } = self;
        let mut policy = DissolvePolicy {
            scopes,
            anchors,
            indexes,
            ascends,
            left,
            bound,
            joining: *joining,
            halt: None,
        };
        let swept = sweep
            .step(
                &mut policy,
                async |policy: &DissolvePolicy<'_>, key: &WalkKey| {
                    let anchor = policy.anchors.get(&key.scope).map(WalkAnchor::anchor);
                    let read = read(key, anchor).await?;
                    Ok((read.mark, read))
                },
            )
            .await;
        let halt = policy.halt;
        match swept {
            Swept::Complete => {
                // Each scope the header cuts is a node of the walked tree.
                if scopes.iter().all(|(scope, _)| sweep.seen.contains(scope)) {
                    MapStep::Complete
                } else {
                    MapStep::Stop
                }
            }
            Swept::Paused => MapStep::Unfinished,
            Swept::Moved => MapStep::Restart,
            Swept::Fault(ReadFault::Untrusted) => MapStep::Refused,
            Swept::Fault(ReadFault::Fatal(Unmapped::NewScopeRoot)) => MapStep::Stop,
            Swept::Fault(ReadFault::Fatal(Unmapped::Outside)) => MapStep::Restart,
            Swept::Fault(ReadFault::Unanswered) => {
                if sweep.unanswered_at(MAX_DISSOLVE_READ_ATTEMPTS) {
                    MapStep::Restart
                } else {
                    MapStep::Unfinished
                }
            }
            Swept::Stopped(Overflow) => match halt {
                Some(MapHalt::Restart) => MapStep::Restart,
                Some(MapHalt::Joined(scopes)) => MapStep::Join(scopes.into_iter().collect()),
                Some(MapHalt::Concurrent | MapHalt::TooLarge) | None => MapStep::Stop,
            },
        }
    }

    /// The map rows in walk order, which is one rooted tree in pre-order. The
    /// root row takes `new_root`; every other row takes the id that `mint`
    /// gives its old id.
    fn rows(
        &self,
        new_root: NodeId,
        name: impl Fn(&WalkKey) -> Option<Vec<u8>>,
        mut mint: impl FnMut(NodeId) -> Option<NodeId>,
    ) -> Option<Vec<MapRow>> {
        self.sweep
            .read
            .iter()
            .enumerate()
            .map(|(at, (key, _))| {
                Some(MapRow {
                    old: key.node,
                    new: if at == 0 { new_root } else { mint(key.node)? },
                    parent: key.parent,
                    old_name: name(key)?,
                })
            })
            .collect()
    }
}

/// A dissolve walk's policy for one tick.
struct DissolvePolicy<'p> {
    scopes: &'p [(NodeId, u64)],
    anchors: &'p mut BTreeMap<NodeId, WalkAnchor>,
    indexes: &'p mut BTreeMap<NodeId, BTreeSet<NodeId>>,
    ascends: &'p dyn Fn(NodeId, NodeId) -> bool,
    left: &'p Cell<usize>,
    bound: usize,
    joining: bool,
    halt: Option<MapHalt>,
}

impl DissolvePolicy<'_> {
    fn stop(&mut self, halt: MapHalt) -> Result<(), Overflow> {
        self.halt = Some(halt);
        Err(Overflow)
    }

    fn cuts(&self, node: NodeId) -> Option<u64> {
        self.scopes
            .iter()
            .find(|(scope, _)| *scope == node)
            .map(|(_, cut_epoch)| *cut_epoch)
    }
}

impl SweepPolicy<WalkKey> for DissolvePolicy<'_> {
    type Answer = DissolveRead;

    fn take_read(&mut self, _: bool) -> bool {
        take_tick_read(self.left)
    }

    /// Record what one node names. A scope root must hold no row at the cut
    /// epoch of its cut, and its index may name only scopes the dissolve cuts.
    /// A child that is one of those scopes is read under its own end; any
    /// other child is read under the end of the folder that names it.
    fn visit(
        &mut self,
        sweep: &mut TwoSweep<WalkKey>,
        key: &WalkKey,
        read: DissolveRead,
    ) -> Result<(), Overflow> {
        let at = u32::try_from(sweep.read.len() - 1).map_err(|_| Overflow)?;
        if let Some(root) = read.root {
            if cut_overtaken(root.rows, root.cut_epoch, self.cuts(key.node)) {
                return self.stop(MapHalt::Concurrent);
            }
            let uncut: BTreeSet<NodeId> = root
                .index
                .iter()
                .copied()
                .filter(|scope| self.cuts(*scope).is_none())
                .collect();
            if !uncut.is_empty() {
                if !self.joining {
                    return self.stop(MapHalt::Concurrent);
                }
                return self.stop(MapHalt::Joined(uncut));
            }
            self.anchors.insert(key.node, root.anchor);
            self.indexes.insert(key.node, root.index);
        }
        let Some(index) = self.indexes.get(&key.scope) else {
            return self.stop(MapHalt::Restart);
        };
        let mut next = Vec::with_capacity(read.children.len());
        for child in &read.children {
            let id = NodeId(child.id);
            if !sweep.seen.insert(id) {
                return self.stop(MapHalt::Restart);
            }
            let scope = if self.cuts(id).is_some() {
                if !index.contains(&id) || !(self.ascends)(key.scope, id) {
                    return self.stop(MapHalt::Restart);
                }
                id
            } else {
                key.scope
            };
            next.push(WalkKey {
                node: id,
                scope,
                parent: Some(at),
            });
        }
        sweep.pending.extend(next);
        if sweep.seen.len() > self.bound {
            return self.stop(MapHalt::TooLarge);
        }
        Ok(())
    }
}

/// Whether `op` writes a node at or below `root` in `base`: its target, or a
/// node whose next record its publish authors.
fn op_under(base: &Snapshot, root: NodeId, op: &Op) -> bool {
    let at_or_below = |node: &NodeId| *node == root || base.is_descendant_of(*node, root);
    at_or_below(&op.target)
        || op
            .authored_nodes(|| {
                base.links_ranked(op.target)
                    .iter()
                    .map(|link| link.parent)
                    .collect()
            })
            .iter()
            .any(at_or_below)
}

/// A drive of a dissolve's map step that did not settle. The entry waits for
/// the next tick.
struct NotDriven;

impl From<DissolveWriteError> for NotDriven {
    fn from(_: DissolveWriteError) -> Self {
        Self
    }
}

impl<T, H, C, F, S, St, Sch> Drain<'_, T, H, C, F, S, St, Sch>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    S: SnapshotCache,
    St: StagingStore,
    Sch: Scheduler + Clone + 'static,
{
    /// Drive the map, the seal and the relink step of each dissolve entry
    /// this owner holds over the tick's own `ends`, within one share of reads
    /// for the tick. An entry the drive cannot move waits for the next tick.
    pub(super) async fn drive_dissolves(&self, passes: &[DrainScope<'_>], ends: &[ScopeEnd<'_>]) {
        let Some(owner) = passes.iter().find(|scope| !scope.is_grafted()) else {
            return;
        };
        let journal = DissolveJournal::new(
            &self.seams.staging,
            self.bookkeeping_seal(owner),
            self.cells.dissolve,
        );
        let Ok(roots) = journal.roots().await else {
            return;
        };
        let left = Cell::new(MAX_DISSOLVE_WALK_READS);
        for root in roots {
            let _ = self.drive_map(owner, ends, &journal, root, &left).await;
            self.drive_seal(owner, ends, &journal, root, &left).await;
            self.drive_relink(owner, ends, &journal, root, &left).await;
        }
    }

    async fn drive_map(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        root: NodeId,
        left: &Cell<usize>,
    ) -> Result<(), NotDriven> {
        let header = match journal.header(root).await.map_err(|_| NotDriven)? {
            HeaderSlot::Own(header) if header.step == DissolveStep::Map => header,
            _ => {
                self.cells.dissolve_walks.borrow_mut().remove(&root);
                return Ok(());
            }
        };
        let Some(hold) = self.cells.dissolve.hold(root) else {
            return Ok(());
        };
        // The copy reads a subtree that no queued op still writes.
        if self
            .queue_writes_under(owner, root)
            .await
            .map_err(|_| NotDriven)?
        {
            return Ok(());
        }
        let end_of = |scope: NodeId| ends.iter().find(|end| end.root == scope);
        let mark_of = |scope: NodeId| end_of(scope).map(EndMark::of);
        // An anchor read under other material opens nothing under this tick's.
        let carried = self.cells.dissolve_walks.borrow_mut().remove(&root);
        let mut walk = carried
            .filter(|walk| walk.walks(&header) && walk.keeps_material(mark_of))
            .unwrap_or_else(|| DissolveWalk::new(&header, root));
        if walk.refused {
            self.cells.dissolve_walks.borrow_mut().insert(root, walk);
            return Ok(());
        }
        let ascends = |parent: NodeId, child: NodeId| {
            end_of(parent)
                .zip(end_of(child))
                .is_some_and(|(parent, child)| ascends_from(parent, child))
        };
        let step = walk
            .step(
                left,
                MAX_DISSOLVE_WALK_NODES,
                &ascends,
                async |key, anchor| self.dissolve_read(owner, ends, &header, key, anchor).await,
            )
            .await;
        walk.note_material(mark_of);
        match step {
            MapStep::Unfinished => {
                self.cells.dissolve_walks.borrow_mut().insert(root, walk);
                Ok(())
            }
            MapStep::Restart => Ok(()),
            MapStep::Refused => {
                walk.refused = true;
                self.cells.dissolve_walks.borrow_mut().insert(root, walk);
                Ok(())
            }
            // After the copy started, a stop keeps the entry and each copy.
            MapStep::Stop if header.copy_started => Ok(()),
            MapStep::Stop => Ok(journal.drop_entry(&hold, &header).await?),
            MapStep::Join(scopes) => {
                let mut joined = header.clone();
                joined.step = DissolveStep::Cut;
                joined
                    .scopes
                    .extend(scopes.into_iter().map(DissolvedScope::uncut));
                Ok(journal.commit(&hold, Some(&header), &joined).await?)
            }
            MapStep::Complete => self.commit_map(journal, &hold, &header, &walk, ends).await,
        }
    }

    /// Whether the owner's queue holds an op at or below `root` that is still
    /// to publish. A kept op already published its record.
    async fn queue_writes_under(&self, owner: &DrainScope<'_>, root: NodeId) -> Result<bool, Halt> {
        let raw = self.seams.staging.queued_ops().await.map_err(seam)?;
        let mut mine = decode_queue(&RecordReader::new(owner.enc_secret), &raw).mine;
        if mine.is_empty() {
            return Ok(false);
        }
        let drained = self.drained_mark(owner).await?;
        mine.retain(|(op_id, _)| drained.is_none_or(|mark| op_id.0 > mark));
        retain_pending(
            &self.seams.staging,
            self.bookkeeping_seal(owner),
            owner.enc_secret,
            &mut mine,
        )
        .await
        .map_err(seam)?;
        let base = self.cells.base.borrow();
        Ok(mine.iter().any(|(_, op)| op_under(&base, root, op)))
    }

    /// Write the map of a complete walk as a new generation, then commit the
    /// header at the seal step over it. A node of the live map keeps its new
    /// id, so a remap mints ids for new nodes only. A page of another
    /// generation is not part of the entry, so it goes after the commit.
    async fn commit_map(
        &self,
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &DissolveHeader,
        walk: &DissolveWalk,
        ends: &[ScopeEnd<'_>],
    ) -> Result<(), NotDriven> {
        let name = |key: &WalkKey| {
            let end = ends.iter().find(|end| end.root == key.scope)?;
            let name = if key.node == key.scope {
                end.root_name.clone()
            } else {
                end.write_name(&key.node.0)
            };
            Some(name.as_str().as_bytes().to_vec())
        };
        let live: BTreeMap<NodeId, NodeId> = if header.map_pages == 0 {
            BTreeMap::new()
        } else {
            journal
                .map(header.scopes[0].scope_id, header)
                .await?
                .into_iter()
                .flat_map(|page| page.rows)
                .map(|row| (row.old, row.new))
                .collect()
        };
        let mint = |old: NodeId| {
            live.get(&old).copied().or_else(|| {
                fresh_bytes(&mut *self.seams.entropy.borrow_mut(), "node id")
                    .ok()
                    .map(NodeId)
            })
        };
        let rows = walk.rows(header.new_root, name, mint).ok_or(NotDriven)?;
        let generation = header.map_gen.checked_add(1).ok_or(NotDriven)?;
        let mut pages = Vec::new();
        for (page, rows) in rows.chunks(MAX_PAGE_ENTRIES).enumerate() {
            pages.push(MapPage {
                generation,
                page: u16::try_from(page).map_err(|_| NotDriven)?,
                rows: rows.to_vec(),
            });
        }
        for page in &pages {
            journal.put_map_page(hold, page).await?;
        }
        let mut sealed = header.clone();
        sealed.step = DissolveStep::Seal;
        sealed.map_gen = generation;
        sealed.map_pages = u16::try_from(pages.len()).map_err(|_| NotDriven)?;
        sealed.rows = u32::try_from(rows.len()).map_err(|_| NotDriven)?;
        journal.commit(hold, Some(header), &sealed).await?;
        Ok(journal.drop_uncounted_pages(hold, &sealed).await?)
    }

    /// One node of a dissolve walk, read under the end of its scope through
    /// the gate from the record plane. A scope root that holds no row at the
    /// cut epoch of its cut also gives its gated index.
    async fn dissolve_read(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        header: &DissolveHeader,
        key: &WalkKey,
        anchor: Option<Anchor<'_>>,
    ) -> Result<DissolveRead, ReadFault<Unmapped>> {
        let end = ends
            .iter()
            .find(|end| end.root == key.scope)
            .ok_or(ReadFault::Unanswered)?;
        if key.node != end.root {
            let anchor = anchor.ok_or(ReadFault::Unanswered)?;
            return self
                .dissolve_child(owner, ends, header, end, anchor, key.node)
                .await;
        }
        let cut_epoch = cut_epoch_of(header, key.node);
        let (root, envelope) = self.dissolve_root(owner, end).await?;
        let commitment = root.state.commitment.as_ref().ok_or(ReadFault::Untrusted)?;
        let rows = !commitment.entries.is_empty();
        let cut = commitment.cut_epoch;
        let index = if rows || Some(cut) != cut_epoch {
            BTreeSet::new()
        } else {
            self.gated_index(end, &envelope).await?
        };
        Ok(DissolveRead {
            mark: RecordMark {
                sequence: root.state.observed.sequence(),
                digest: cipherbox_core::suite::hash::hash(&root.state.record),
            },
            children: root.state.children,
            root: Some(RootFacts {
                anchor: WalkAnchor {
                    epoch: root.epoch,
                    history_links: root.history_links,
                },
                index,
                rows,
                cut_epoch: cut,
            }),
        })
    }

    /// The scope roots that the write body of `end`'s root names.
    async fn gated_index(
        &self,
        end: &ScopeEnd<'_>,
        envelope: &Envelope,
    ) -> Result<BTreeSet<NodeId>, ReadFault<Unmapped>> {
        let section = grant_section_bytes(envelope)
            .and_then(|bytes| decode_grant_section(bytes).ok())
            .ok_or(ReadFault::Untrusted)?;
        let write_epoch = floor::write_epoch_floor(&end.floors(&self.seams.floors), &end.root.0)
            .await
            .ok()
            .flatten()
            .ok_or(ReadFault::Unanswered)?;
        // The gate checked the write body's signature, so a body that does not
        // unseal is material that lags a write cut: the next tick decides.
        let plaintext = unseal_write_body(
            envelope,
            &section,
            &end.root.0,
            end.write_scope_seed,
            write_epoch,
        )
        .ok_or(ReadFault::Unanswered)?;
        let body = decode_write_body(&plaintext).map_err(|_| {
            emit_trust_violation(
                &self.seams.events,
                end.root_name.as_str(),
                "dissolve-write-body-malformed",
            );
            ReadFault::Untrusted
        })?;
        Ok(body
            .direct_child_scope_index
            .iter()
            .map(|child| NodeId(child.scope_id))
            .collect())
    }

    /// One non-root node under `end`, read through the child gate at the name
    /// the end derives. A file body names no children.
    async fn dissolve_child(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        header: &DissolveHeader,
        end: &ScopeEnd<'_>,
        anchor: Anchor<'_>,
        node: NodeId,
    ) -> Result<DissolveRead, ReadFault<Unmapped>> {
        let loaded = self
            .gated_child(owner, ends, header, end, anchor, node)
            .await?;
        Ok(DissolveRead {
            mark: RecordMark {
                sequence: loaded.observed.sequence(),
                digest: cipherbox_core::suite::hash::hash(&loaded.record),
            },
            children: match loaded.body {
                ReadBody::Folder { children, .. } => children,
                ReadBody::File { .. } => Vec::new(),
            },
            root: None,
        })
    }

    /// [`Self::dissolve_child`] as the opened record.
    async fn gated_child(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        header: &DissolveHeader,
        end: &ScopeEnd<'_>,
        anchor: Anchor<'_>,
        node: NodeId,
    ) -> Result<LoadedNode, ReadFault<Unmapped>> {
        let plane = end.at(anchor.epoch);
        let name = end.write_name(&node.0);
        let floors = end.floors(&self.seams.floors);
        let adopter = self.child_adopter(&plane, &floors, node);
        let mut resolved = resolve_gated(
            &self.seams.transport,
            &self.seams.snapshot_cache,
            &adopter,
            &name,
            ResolveMode::NoCache,
        )
        .await
        .map_err(|_| ReadFault::Unanswered)?;
        if let ResolveOutcome::TrustViolation(rejection) = &resolved.resolved.outcome {
            // The child gate refuses every grant section. Only the root gate
            // tells a grant from abuse (blueprint/engine.md "Grant creation").
            if rejection.stage == GateStage::GrantSection {
                return Err(self.root_gate_read(owner, end, node, &name).await);
            }
            let other = adopter
                .unbound_scope()
                .map(NodeId)
                .filter(|scope| cut_epoch_of(header, *scope).is_none())
                .and_then(|scope| ends.iter().find(|end| end.root == scope))
                .filter(|other| other.write_name(&node.0) == name);
            if seal_open_failed(rejection)
                && let Some((other, bytes)) = other.zip(adopter.unbound_record())
            {
                return Err(self
                    .outside_read(
                        *other,
                        node,
                        &name,
                        &bytes,
                        &resolved.tied,
                        resolved.endpoint_failed,
                    )
                    .await);
            }
        }
        // The resolve gates a tie at the epoch floor only, so a tie that lags
        // the epoch floor is judged here under the seed of its own epoch.
        let endpoint_failed = resolved.endpoint_failed;
        let forked = resolved.resolved.fork.is_some();
        let tied = std::mem::take(&mut resolved.tied);
        let loaded = self
            .open_resolved_child(&plane, anchor, &adopter, name.clone(), resolved)
            .await
            .map_err(|fault| walk_fault(self.report_fault(&name, fault)))?;
        let forked = forked
            || self
                .held_fork(
                    end,
                    anchor,
                    &adopter,
                    &name,
                    &loaded.record,
                    &tied,
                    endpoint_failed,
                )
                .await;
        if forked {
            return Err(self.fork_at(&name, loaded.observed.sequence()));
        }
        Ok(loaded)
    }

    /// The root of `end` and its head envelope, read through its own gate as
    /// [`Self::walk_root`] reads it. A fork holds the read, and a tie is a fork
    /// only when the gate passes it (ADR 0066 D1): one fork event, and the read
    /// is untrusted. The root gate refuses a tie below the epoch floor.
    pub(super) async fn dissolve_root<E>(
        &self,
        owner: &DrainScope<'_>,
        end: &ScopeEnd<'_>,
    ) -> Result<(LoadedRoot, Envelope), ReadFault<E>> {
        let resolved = self
            .gated_scope_root(owner, end, ResolveMode::NoCache)
            .await
            .map_err(walk_fault)?;
        if let Some(fork) = &resolved.resolved.fork {
            return Err(self.fork_at(end.root_name, fork.sequence));
        }
        self.open_walk_root(owner, end, resolved).await
    }

    /// Report a same-sequence fork at `sequence` of `name`, which holds the
    /// walk.
    fn fork_at<E>(&self, name: &IpnsName, sequence: u64) -> ReadFault<E> {
        self.cells
            .forks
            .report(&self.seams.events, name.as_str(), sequence);
        ReadFault::Untrusted
    }

    /// Read `node` at `name` again for the root gate, under the ascent
    /// authority of `end`'s read seed. The child gate refuses every record
    /// with a grant section, so a root gate refusal of such a record is a
    /// refusal by both gates. A record with no grant section changed after the
    /// child gate read, and the walk reads it again on a later tick. A tie
    /// counts as a fork only when it passes the root gate (ADR 0066 D1).
    async fn root_gate_read(
        &self,
        owner: &DrainScope<'_>,
        end: &ScopeEnd<'_>,
        node: NodeId,
        name: &IpnsName,
    ) -> ReadFault<Unmapped> {
        let Ok(LeafRead {
            pick,
            bytes,
            tied,
            endpoint_failed,
        }) = LeafRead::fetch(&self.seams.transport, name).await
        else {
            return ReadFault::Unanswered;
        };
        let refused = |error: GateError| match LeafRefusal::of(error, endpoint_failed) {
            LeafRefusal::Seam(_) | LeafRefusal::Withheld => ReadFault::Unanswered,
            LeafRefusal::Rejected(rejection) => {
                refuse_record(&self.seams.events, name, &rejection);
                ReadFault::Untrusted
            }
        };
        match assemble_head_envelope(&self.seams.gateway, &self.seams.http, name, &bytes, None)
            .await
        {
            Ok((_, envelope, _)) if has_grant_section(&envelope) => {}
            Ok(_) => return ReadFault::Unanswered,
            Err(error) => return refused(error),
        }
        let floors = end.floors(&self.seams.floors);
        let parent_seed = kdf::node_seed(end.read_scope_seed, &node.0);
        let adopter = RootAdopter::new(
            &self.seams.gateway,
            &self.seams.http,
            &floors,
            owner.enc_secret,
            owner.owner_identity,
            node.0,
        )
        .under_parent_node_seed(Zeroizing::new(*parent_seed.as_bytes()));
        // The root gate with no commit: an adopt, or our own record at the
        // floor that recovers its material.
        let judge = async |bytes: &[u8]| match adopter.adopt(name, bytes).await {
            Ok(_) => Ok(true),
            Err(GateError::Rejected(GateRejection {
                reason: RejectionReason::SequenceNotNewer { floor, sequence },
                ..
            })) if floor == sequence => adopter
                .recover_own_scope_material(name, bytes)
                .await
                .map(|material| material.is_some()),
            Err(error) => Err(error),
        };
        match judge(&bytes).await {
            Ok(true) => {}
            Ok(false) => return ReadFault::Unanswered,
            Err(error) => return refused(error),
        }
        if served_fork(name, &pick, &tied, async |tie| {
            matches!(judge(tie).await, Ok(true))
        })
        .await
        {
            return self.fork_at(name, pick.sequence);
        }
        ReadFault::Fatal(Unmapped::NewScopeRoot)
    }

    /// Judge `bytes`, the record at `name` that the scope bind of the walked
    /// end refused, under `other`, the end its tag names and that derives the
    /// same name. A scope whose parent shares its write seed derives the
    /// parent's names, so the record of an outside node can stand at a name of
    /// the walked scope. The AAD binds the scope, so a hostile record does not
    /// open there. A tie counts as a fork only when it opens too (ADR 0066
    /// D1).
    async fn outside_read(
        &self,
        other: ScopeEnd<'_>,
        node: NodeId,
        name: &IpnsName,
        bytes: &[u8],
        tied: &[Vec<u8>],
        endpoint_failed: bool,
    ) -> ReadFault<Unmapped> {
        let Some((plane, root)) = self.ledger_plane(other).await else {
            return ReadFault::Unanswered;
        };
        let floors = other.floors(&self.seams.floors);
        let adopter = self.child_adopter(&plane, &floors, node);
        let opened = self
            .open_held(
                &other,
                root.anchor(),
                &adopter,
                name,
                bytes,
                endpoint_failed,
            )
            .await;
        let sequence = match opened {
            Ok((adopted, _)) => adopted.sequence,
            Err(Some(rejection)) => {
                refuse_record(&self.seams.events, name, &rejection);
                return ReadFault::Untrusted;
            }
            Err(None) => return ReadFault::Unanswered,
        };
        let forked = self
            .held_fork(
                &other,
                root.anchor(),
                &adopter,
                name,
                bytes,
                tied,
                endpoint_failed,
            )
            .await;
        if forked {
            return self.fork_at(name, sequence);
        }
        ReadFault::Fatal(Unmapped::Outside)
    }

    /// The child gate of `load_child_at` on held `bytes` under `end`, with no
    /// commit. A record below the epoch floor opens under the seed of its own
    /// epoch. `Err(None)` is a check that cannot run, or a record withheld
    /// while an endpoint failed (ADR 0071 D1).
    async fn open_held(
        &self,
        end: &ScopeEnd<'_>,
        anchor: Anchor<'_>,
        adopter: &ChildAdopter<'_, H, SharerScopedFloorStore<'_, F>>,
        name: &IpnsName,
        bytes: &[u8],
        endpoint_failed: bool,
    ) -> Result<(Adopted, Envelope), Option<GateRejection>> {
        let refused = |error: GateError| match LeafRefusal::of(error, endpoint_failed) {
            LeafRefusal::Seam(_) | LeafRefusal::Withheld => None,
            LeafRefusal::Rejected(rejection) => Some(rejection),
        };
        let lagging = match adopter.open_held(name, bytes).await {
            Ok(adopted) => return Ok(adopted),
            Err(GateError::Rejected(GateRejection {
                reason: RejectionReason::EpochBelowFloor { epoch, .. },
                ..
            })) => epoch,
            Err(error) => return Err(refused(error)),
        };
        let seed =
            seed_for_lagging(end.root.0, end.read_scope_seed, anchor, lagging).map_err(|_| None)?;
        adopter
            .open_interior_under(name, bytes, &seed)
            .await
            .map_err(refused)
    }

    /// Whether a tie in `tied` of the record `pick` opens through
    /// [`Self::open_held`]: a fork (ADR 0066 D1).
    #[expect(clippy::too_many_arguments, reason = "one held read of a tie")]
    async fn held_fork(
        &self,
        end: &ScopeEnd<'_>,
        anchor: Anchor<'_>,
        adopter: &ChildAdopter<'_, H, SharerScopedFloorStore<'_, F>>,
        name: &IpnsName,
        pick: &[u8],
        tied: &[Vec<u8>],
        endpoint_failed: bool,
    ) -> bool {
        if tied.is_empty() {
            return false;
        }
        let Ok(pick) = IpnsRecord::unmarshal(pick).and_then(|record| record.verify(name)) else {
            return false;
        };
        served_fork(name, &pick, tied, async |tie| {
            self.open_held(end, anchor, adopter, name, tie, endpoint_failed)
                .await
                .is_ok()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use cipherbox_core::seal::{NodeKind, PreservedFields};

    use super::*;
    use crate::sync::dissolve_journal::{DissolveBinding, check_map};
    use crate::testkit::block_on;

    const S: NodeId = NodeId([0x10; 16]);
    const N: NodeId = NodeId([0x20; 16]);
    const A: NodeId = NodeId([0x31; 16]);
    const B: NodeId = NodeId([0x32; 16]);
    const C: NodeId = NodeId([0x33; 16]);
    const F: NodeId = NodeId([0x34; 16]);
    const OUTSIDE: NodeId = NodeId([0x40; 16]);
    const NEW_ROOT: NodeId = NodeId([0x70; 16]);

    /// One node of a fake tree.
    #[derive(Clone)]
    struct Node {
        children: Vec<NodeId>,
        /// The index, the row flag and the cut epoch of a scope root.
        root: Option<(Vec<NodeId>, bool, u64)>,
        sequence: u64,
        refused: bool,
        /// The root gate passes the node as a scope root.
        promoted: bool,
    }

    fn folder(children: &[NodeId]) -> Node {
        Node {
            children: children.to_vec(),
            root: None,
            sequence: 1,
            refused: false,
            promoted: false,
        }
    }

    fn scope_root(children: &[NodeId], index: &[NodeId]) -> Node {
        Node {
            root: Some((index.to_vec(), false, 2)),
            ..folder(children)
        }
    }

    fn child(id: NodeId) -> ChildRef {
        ChildRef {
            id: id.0,
            name: "child".into(),
            // A carried name that no walk reads.
            ipns_name: b"k51carried".to_vec(),
            kind: NodeKind::Folder,
            link_counter: 0,
            unknown: PreservedFields::default(),
        }
    }

    /// A header at the map step that cuts `scopes`, `S` first, each at cut
    /// epoch 2.
    fn header(scopes: &[NodeId]) -> DissolveHeader {
        let binding = DissolveBinding {
            read_scope: NodeId([0x01; 16]),
            read_epoch: 1,
            restart_floor: 1,
            base_cut: 0,
            write_scope: NodeId([0x01; 16]),
            write_epoch: 1,
        };
        let scopes = scopes
            .iter()
            .map(|scope| DissolvedScope {
                cut_epoch: 2,
                cut_time: 1,
                final_landed: true,
                ..DissolvedScope::uncut(*scope)
            })
            .collect();
        let mut header = DissolveHeader::at_cut(NEW_ROOT, NodeId([0x01; 16]), binding, scopes);
        header.step = DissolveStep::Map;
        header
    }

    /// The tree S → [A → [F], N → [B]], with N a nested scope root.
    fn tree() -> BTreeMap<NodeId, Node> {
        BTreeMap::from([
            (S, scope_root(&[A, N], &[N])),
            (A, folder(&[F])),
            (F, folder(&[])),
            (N, scope_root(&[B], &[])),
            (B, folder(&[])),
        ])
    }

    /// A fake record plane for a walk, with every read the walk made.
    struct Fake {
        tree: RefCell<BTreeMap<NodeId, Node>>,
        reads: RefCell<Vec<WalkKey>>,
        ascends: bool,
    }

    impl Fake {
        fn new(tree: BTreeMap<NodeId, Node>) -> Self {
            Self {
                tree: RefCell::new(tree),
                reads: RefCell::new(Vec::new()),
                ascends: true,
            }
        }

        /// One tick of `walk` with `reads` reads and a node bound of `bound`.
        fn tick(&self, walk: &mut DissolveWalk, reads: usize, bound: usize) -> MapStep {
            let left = Cell::new(reads);
            let ascends = |_: NodeId, _: NodeId| self.ascends;
            block_on(walk.step(&left, bound, &ascends, async |key, _| {
                self.reads.borrow_mut().push(key.clone());
                let tree = self.tree.borrow();
                let node = tree.get(&key.node).ok_or(ReadFault::Unanswered)?;
                if node.refused {
                    return Err(ReadFault::Untrusted);
                }
                if node.promoted {
                    return Err(ReadFault::Fatal(Unmapped::NewScopeRoot));
                }
                let root = (key.node == key.scope)
                    .then(|| node.root.clone())
                    .flatten()
                    .map(|(index, rows, cut_epoch)| RootFacts {
                        anchor: WalkAnchor {
                            epoch: 1,
                            history_links: Vec::new(),
                        },
                        index: index.into_iter().collect(),
                        rows,
                        cut_epoch,
                    });
                Ok(DissolveRead {
                    mark: RecordMark {
                        sequence: node.sequence,
                        digest: [0; 32],
                    },
                    children: node.children.iter().copied().map(child).collect(),
                    root,
                })
            }))
        }

        /// One tick of `walk` with a share large enough for both sweeps.
        fn run(&self, walk: &mut DissolveWalk) -> MapStep {
            self.tick(walk, 64, MAX_DISSOLVE_WALK_NODES)
        }
    }

    fn walk(scopes: &[NodeId]) -> DissolveWalk {
        DissolveWalk::new(&header(scopes), S)
    }

    /// The rows of a complete walk, each named by its node and its scope.
    fn rows(walk: &DissolveWalk) -> Vec<MapRow> {
        let mut minted = 0x80;
        walk.rows(
            NEW_ROOT,
            |key| Some([key.node.0, key.scope.0].concat()),
            |_| {
                minted += 1;
                Some(NodeId([minted; 16]))
            },
        )
        .expect("each row is named and minted")
    }

    /// A complete walk maps each node once, in one rooted tree in pre-order,
    /// and reads a nested scope root's subtree under that scope.
    #[test]
    fn a_walk_maps_each_node_once_as_one_rooted_tree() {
        let fake = Fake::new(tree());
        let mut walk = walk(&[S, N]);

        assert_eq!(fake.run(&mut walk), MapStep::Complete);

        let rows = rows(&walk);
        let mut sealed = header(&[S, N]);
        sealed.step = DissolveStep::Seal;
        sealed.map_pages = 1;
        sealed.rows = u32::try_from(rows.len()).unwrap();
        let page = MapPage {
            generation: 0,
            page: 0,
            rows: rows.clone(),
        };
        assert_eq!(check_map(&sealed, S, &[page]), Ok(()));
        let old: BTreeSet<NodeId> = rows.iter().map(|row| row.old).collect();
        assert_eq!((rows.len(), old), (5, BTreeSet::from([S, A, F, N, B])));
        let scope_of = |node: NodeId| {
            fake.reads
                .borrow()
                .iter()
                .find(|key| key.node == node)
                .map(|key| key.scope)
        };
        assert_eq!(scope_of(B), Some(N), "a node below N reads under N");
        assert_eq!(scope_of(F), Some(S));
        assert_eq!(fake.reads.borrow().len(), 10, "two sweeps of five nodes");
        let b = rows.iter().find(|row| row.old == B).unwrap();
        assert_eq!(
            b.old_name,
            [B.0, N.0].concat(),
            "a row is named from its own scope, never from the carried name"
        );
    }

    /// A ref to a node outside the subtree reads at the name the post-cut
    /// seed derives, where no record of it stands. The walk never maps it, and
    /// starts again after its attempts.
    #[test]
    fn an_outside_ref_is_never_mapped() {
        let mut tree = tree();
        tree.get_mut(&A).unwrap().children.push(OUTSIDE);
        let fake = Fake::new(tree);
        let mut walk = walk(&[S, N]);

        let steps: Vec<MapStep> = (0..3).map(|_| fake.run(&mut walk)).collect();

        assert_eq!(
            steps,
            vec![MapStep::Unfinished, MapStep::Unfinished, MapStep::Restart]
        );
    }

    /// A nested scope root that the gated index of its scope does not name
    /// pauses the walk, which starts again on the next tick.
    #[test]
    fn a_nested_root_that_the_index_does_not_name_pauses_the_walk() {
        let mut tree = tree();
        tree.get_mut(&S).unwrap().root = Some((Vec::new(), false, 2));

        assert_eq!(Fake::new(tree).run(&mut walk(&[S, N])), MapStep::Restart);
    }

    /// A nested scope root whose end does not take its ascent authority from
    /// the walked scope pauses the walk.
    #[test]
    fn a_nested_root_of_another_scope_pauses_the_walk() {
        let mut fake = Fake::new(tree());
        fake.ascends = false;

        assert_eq!(fake.run(&mut walk(&[S, N])), MapStep::Restart);
    }

    /// A scope root that the gated index names and the dissolve does not cut
    /// is a folder shared after the cut: the dissolve stops before the copy.
    #[test]
    fn an_indexed_scope_the_dissolve_does_not_cut_stops_it() {
        assert_eq!(Fake::new(tree()).run(&mut walk(&[S])), MapStep::Stop);
    }

    /// A row, or a cut epoch other than the dissolve's own, at a cut scope
    /// root stops the dissolve.
    #[test]
    fn a_row_or_another_cut_at_a_scope_root_stops_the_walk() {
        for root in [(Vec::new(), true, 2), (Vec::new(), false, 3)] {
            let mut tree = tree();
            tree.get_mut(&N).unwrap().root = Some(root);

            assert_eq!(Fake::new(tree).run(&mut walk(&[S, N])), MapStep::Stop);
        }
    }

    /// A diamond and a cycle are both a second ref to a node the walk holds:
    /// the walk pauses and starts again.
    #[test]
    fn a_diamond_or_a_cycle_pauses_the_walk() {
        let mut diamond = tree();
        diamond.insert(C, folder(&[]));
        diamond.get_mut(&A).unwrap().children.push(C);
        diamond.get_mut(&F).unwrap().children.push(C);
        let mut cycle = tree();
        cycle.get_mut(&F).unwrap().children.push(S);

        for tree in [diamond, cycle] {
            assert_eq!(Fake::new(tree).run(&mut walk(&[S, N])), MapStep::Restart);
        }
    }

    /// A node read to another record on the second sweep moved during the
    /// walk, which starts again.
    #[test]
    fn a_node_that_moves_between_the_sweeps_restarts_the_walk() {
        let fake = Fake::new(tree());
        let mut walk = walk(&[S, N]);
        assert_eq!(
            fake.tick(&mut walk, 5, MAX_DISSOLVE_WALK_NODES),
            MapStep::Unfinished,
            "the first sweep ends"
        );
        fake.tree.borrow_mut().get_mut(&F).unwrap().sequence = 2;

        assert_eq!(fake.run(&mut walk), MapStep::Restart);
    }

    /// A walk spends at most its share of reads in one tick, and the next
    /// tick resumes it.
    #[test]
    fn a_walk_spends_its_share_and_resumes() {
        let fake = Fake::new(tree());
        let mut walk = walk(&[S, N]);

        assert_eq!(
            fake.tick(&mut walk, 3, MAX_DISSOLVE_WALK_NODES),
            MapStep::Unfinished
        );
        assert_eq!(fake.reads.borrow().len(), 3);
        assert_eq!(fake.run(&mut walk), MapStep::Complete);
        assert_eq!(
            fake.reads.borrow().len(),
            10,
            "each sweep reads each node once"
        );
    }

    /// A record that the gate refuses refuses the step, and the drive holds
    /// the walk on it.
    #[test]
    fn a_refused_record_refuses_the_step() {
        let mut tree = tree();
        tree.get_mut(&B).unwrap().refused = true;

        assert_eq!(Fake::new(tree).run(&mut walk(&[S, N])), MapStep::Refused);
    }

    /// A walk past its node bound stops the dissolve.
    #[test]
    fn a_walk_past_its_node_bound_stops() {
        assert_eq!(
            Fake::new(tree()).tick(&mut walk(&[S, N]), 64, 3),
            MapStep::Stop
        );
    }

    /// A cut scope that no folder of the walked tree names moved out of the
    /// subtree: the dissolve stops.
    #[test]
    fn a_cut_scope_the_walk_does_not_reach_stops_it() {
        let mut tree = tree();
        tree.get_mut(&S).unwrap().children = vec![A];

        assert_eq!(Fake::new(tree).run(&mut walk(&[S, N])), MapStep::Stop);
    }

    /// A walk belongs to one header: another cut epoch starts it again.
    #[test]
    fn a_walk_is_of_one_header() {
        let walk = walk(&[S, N]);
        let mut raised = header(&[S, N]);
        raised.scopes[1].cut_epoch = 3;

        assert!(walk.walks(&header(&[S, N])));
        assert!(!walk.walks(&raised));
    }

    /// A child that the root gate passes as a scope root the dissolve does
    /// not cut was shared after the cut: the dissolve stops.
    #[test]
    fn a_child_the_root_gate_passes_stops_the_dissolve() {
        let mut tree = tree();
        tree.get_mut(&F).unwrap().promoted = true;

        assert_eq!(Fake::new(tree).run(&mut walk(&[S, N])), MapStep::Stop);
    }

    fn mark(stamp: u64) -> EndMark {
        EndMark {
            root_name: "k51root".into(),
            stamp: Some(stamp),
        }
    }

    /// A walk keeps the material of each end that gave an anchor, and other
    /// material is another walk.
    #[test]
    fn a_walk_is_of_one_material() {
        let fake = Fake::new(tree());
        let mut walk = walk(&[S, N]);
        assert_eq!(
            fake.tick(&mut walk, 1, MAX_DISSOLVE_WALK_NODES),
            MapStep::Unfinished
        );
        walk.note_material(|_| Some(mark(2)));

        assert!(walk.keeps_material(|_| Some(mark(2))));
        assert!(
            !walk.keeps_material(|_| Some(mark(3))),
            "a read cut moves the stamp"
        );
        assert!(walk.keeps_material(|_| None), "an end absent from the tick");
        assert!(
            !walk.keeps_material(|_| Some(EndMark {
                root_name: "k51moved".into(),
                ..mark(2)
            })),
            "a name wave moves the root name"
        );
    }

    struct TestEnd {
        root: NodeId,
        root_name: cipherbox_core::ipns::IpnsName,
        read_scope_seed: Zeroizing<[u8; 32]>,
        write_scope_seed: Zeroizing<[u8; 32]>,
        ascent_node_seed: Option<Zeroizing<[u8; 32]>>,
    }

    impl TestEnd {
        fn new(root: NodeId, read_seed: u8, ascent_node_seed: Option<[u8; 32]>) -> Self {
            let write_scope_seed = Zeroizing::new([0x5A; 32]);
            Self {
                root,
                root_name: crate::rotation::derive_write_name(&write_scope_seed, &root.0),
                read_scope_seed: Zeroizing::new([read_seed; 32]),
                write_scope_seed,
                ascent_node_seed: ascent_node_seed.map(Zeroizing::new),
            }
        }

        fn end(&self) -> ScopeEnd<'_> {
            ScopeEnd {
                root: self.root,
                root_name: &self.root_name,
                read_scope_seed: &self.read_scope_seed,
                read_seed_stamp: Some(1),
                write_scope_seed: &self.write_scope_seed,
                write_seed_stamp: None,
                ascent_node_seed: self.ascent_node_seed.as_ref(),
                floor_namespace: crate::grants::grafted::FloorNamespace::Own,
            }
        }
    }

    /// A nested end ascends from its parent only when its ascent seed derives
    /// from the parent's read seed.
    #[test]
    fn a_nested_end_ascends_only_under_its_parent_read_seed() {
        let parent = TestEnd::new(S, 0x11, None);
        let other = TestEnd::new(S, 0x12, None);
        let ascent = *kdf::node_seed(&parent.read_scope_seed, &N.0).as_bytes();
        let nested = TestEnd::new(N, 0x21, Some(ascent));
        let wrong = TestEnd::new(N, 0x21, Some([0x6A; 32]));
        let unlinked = TestEnd::new(N, 0x21, None);

        assert!(ascends_from(&parent.end(), &nested.end()));
        assert!(!ascends_from(&other.end(), &nested.end()));
        assert!(!ascends_from(&parent.end(), &wrong.end()));
        assert!(!ascends_from(&parent.end(), &unlinked.end()));
    }

    /// The base S → [A → [F]] with OUTSIDE and its child C beside S.
    fn base() -> Snapshot {
        let mut base = Snapshot::new(NodeId([0x01; 16]));
        for (id, name) in [(S, "s"), (A, "a"), (F, "f"), (OUTSIDE, "o"), (C, "c")] {
            base.upsert_node(crate::sync::model::NodeMeta::new(
                id,
                name,
                crate::facade::NodeKind::Folder,
            ));
        }
        base.link(NodeId([0x01; 16]), S, 0);
        base.link(S, A, 0);
        base.link(A, F, 0);
        base.link(NodeId([0x01; 16]), OUTSIDE, 0);
        base.link(OUTSIDE, C, 0);
        base
    }

    /// An op writes under the subtree when its target, or any node whose
    /// next record it authors, sits at or below the root.
    #[test]
    fn an_op_writes_under_the_subtree_through_each_node_it_authors() {
        use crate::seams::UnixMillis;
        use crate::sync::op::ScopeCrossing;
        let base = base();
        let at = UnixMillis(1);
        let restore_in = Op::restore(B, A, "b", crate::facade::NodeKind::Folder, 0, at);
        let restore_out = Op::restore(B, OUTSIDE, "b", crate::facade::NodeKind::Folder, 0, at);
        let relink_in = Op::relink(C, OUTSIDE, F, 0, at, ScopeCrossing::Cross);
        let relink_out = Op::relink(F, A, OUTSIDE, 0, at, ScopeCrossing::Cross);
        let move_in = Op::move_node(C, OUTSIDE, A, "c", None, 0, at, ScopeCrossing::Cross);
        let move_out = Op::move_node(C, OUTSIDE, OUTSIDE, "d", None, 0, at, ScopeCrossing::Intra);

        assert!(
            op_under(&base, S, &restore_in),
            "a restore into the subtree"
        );
        assert!(!op_under(&base, S, &restore_out));
        assert!(op_under(&base, S, &relink_in), "a relink into the subtree");
        assert!(
            op_under(&base, S, &relink_out),
            "a relink out of the subtree"
        );
        assert!(op_under(&base, S, &move_in), "a move into the subtree");
        assert!(
            !op_under(&base, S, &move_out),
            "a rename beside the subtree"
        );
    }
}
