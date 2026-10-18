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
use core::convert::Infallible;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::kdf;
use cipherbox_core::seal::{ChildRef, decode_grant_section, grant_section_bytes};
use cipherbox_core::suite::secret::ct_eq;

use super::walker::{Overflow, ReadFault, SweepPolicy, Swept, TwoSweep};
use super::{
    Anchor, Drain, DrainScope, Halt, RecordMark, ScopeEnd, WalkAnchor, published_op_mark,
    resolved_bytes, seam, take_tick_read,
};
use crate::entropy::fresh_bytes;
use crate::facade::{NodeId, emit_trust_violation};
use crate::net::assemble_head_envelope;
use crate::net::rotation::write_plane_of;
use crate::rotation::ResolveFailure;
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SnapshotCache, StagingStore,
};
use crate::sync::dissolve_journal::{
    DissolveHeader, DissolveHold, DissolveJournal, DissolveStep, DissolveWriteError, HeaderSlot,
    MAX_PAGE_ENTRIES, MapPage, MapRow,
};
use crate::sync::kept_op::is_kept;
use crate::sync::op::OpKind;
use crate::sync::rebase::decode_queue;
use crate::sync::record::RecordReader;
use crate::sync::tick::ResolveMode;

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
    /// The scope roots that the gated `directChildScopeIndex` names.
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

/// The map walk of one dissolve entry, carried across ticks.
pub(crate) struct DissolveWalk {
    /// The scopes and the cut epochs of the header it walks. Another header
    /// starts the walk again.
    scopes: Vec<(NodeId, u64)>,
    sweep: TwoSweep<WalkKey>,
    anchors: BTreeMap<NodeId, WalkAnchor>,
    indexes: BTreeMap<NodeId, BTreeSet<NodeId>>,
    /// A gate refused a record of the walk, or the endpoints served a
    /// same-sequence fork. The walk reads no more this session.
    refused: bool,
}

/// Why a first-sweep visit stopped the walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MapHalt {
    /// A diamond, or a scope root that the gated index does not name yet:
    /// the next tick walks again.
    Pause,
    /// A row, a cut, or a scope root that the dissolve did not make.
    Concurrent,
    /// The walk passed its node bound.
    TooLarge,
}

/// Where one tick left a dissolve walk.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum MapStep {
    /// Reads remain for a later tick.
    Unfinished,
    /// Every node read twice to the same record.
    Complete,
    /// A node moved, the walk paused, or a read went unanswered too long.
    Restart,
    /// A gate refused a record, or the endpoints served a fork.
    Refused,
    /// The dissolve stops before the copy.
    Stop,
}

fn scope_ids(header: &DissolveHeader) -> Vec<(NodeId, u64)> {
    header
        .scopes
        .iter()
        .map(|scope| (scope.scope_id, scope.cut_epoch))
        .collect()
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
            refused: false,
        }
    }

    fn walks(&self, header: &DissolveHeader) -> bool {
        self.scopes == scope_ids(header)
    }

    /// Spend reads from `left` on the walk, through `read`. `ascends` answers
    /// whether the end of the second scope root takes its ascent authority from
    /// the read seed of the first.
    pub(super) async fn step(
        &mut self,
        left: &Cell<usize>,
        bound: usize,
        ascends: &dyn Fn(NodeId, NodeId) -> bool,
        read: impl AsyncFn(&WalkKey, Option<Anchor<'_>>) -> Result<DissolveRead, ReadFault<Infallible>>,
    ) -> MapStep {
        let Self {
            scopes,
            sweep,
            anchors,
            indexes,
            ..
        } = self;
        let mut policy = DissolvePolicy {
            scopes,
            anchors,
            indexes,
            ascends,
            left,
            bound,
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
            Swept::Fault(ReadFault::Fatal(never)) => match never {},
            Swept::Fault(ReadFault::Unanswered) => {
                if sweep.unanswered_at(MAX_DISSOLVE_READ_ATTEMPTS) {
                    MapStep::Restart
                } else {
                    MapStep::Unfinished
                }
            }
            Swept::Stopped(Overflow) => match halt {
                Some(MapHalt::Pause) => MapStep::Restart,
                Some(MapHalt::Concurrent | MapHalt::TooLarge) | None => MapStep::Stop,
            },
        }
    }

    /// The map rows in walk order, which is one rooted tree in pre-order. The
    /// root row takes `new_root`; every other row takes an id from `mint`.
    fn rows(
        &self,
        new_root: NodeId,
        name: impl Fn(&WalkKey) -> Option<Vec<u8>>,
        mut mint: impl FnMut() -> Option<NodeId>,
    ) -> Option<Vec<MapRow>> {
        self.sweep
            .read
            .iter()
            .enumerate()
            .map(|(at, (key, _))| {
                Some(MapRow {
                    old: key.node,
                    new: if at == 0 { new_root } else { mint()? },
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
            if root.rows
                || Some(root.cut_epoch) != self.cuts(key.node)
                || root.index.iter().any(|scope| self.cuts(*scope).is_none())
            {
                return self.stop(MapHalt::Concurrent);
            }
            self.anchors.insert(key.node, root.anchor);
            self.indexes.insert(key.node, root.index);
        }
        let Some(index) = self.indexes.get(&key.scope) else {
            return self.stop(MapHalt::Pause);
        };
        let mut next = Vec::with_capacity(read.children.len());
        for child in &read.children {
            let id = NodeId(child.id);
            if !sweep.seen.insert(id) {
                return self.stop(MapHalt::Pause);
            }
            let scope = if self.cuts(id).is_some() {
                if !index.contains(&id) || !(self.ascends)(key.scope, id) {
                    return self.stop(MapHalt::Pause);
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

/// Whether `op` names a node at or below `root` in `base`.
fn op_under(
    base: &crate::sync::model::Snapshot,
    root: NodeId,
    kind: &OpKind,
    target: NodeId,
) -> bool {
    let at_or_below = |node: NodeId| node == root || base.is_descendant_of(node, root);
    let parents = match kind {
        OpKind::Create { parent, .. } => vec![*parent],
        OpKind::Relink {
            from_parent,
            new_parent,
            ..
        }
        | OpKind::Move {
            from_parent,
            new_parent,
            ..
        } => vec![*from_parent, *new_parent],
        _ => Vec::new(),
    };
    at_or_below(target) || parents.into_iter().any(at_or_below)
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
    /// Drive the map step of each dissolve entry this owner holds, within one
    /// share of reads for the tick. An entry the drive cannot move waits for
    /// the next tick.
    pub(super) async fn drive_dissolve_maps(&self, passes: &[DrainScope<'_>]) {
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
        let ends: Vec<ScopeEnd<'_>> = passes
            .iter()
            .filter(|scope| !scope.is_grafted())
            .map(|scope| scope.source)
            .collect();
        let left = Cell::new(MAX_DISSOLVE_WALK_READS);
        for root in roots {
            let _ = self.drive_map(owner, &ends, &journal, root, &left).await;
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
            HeaderSlot::Own(header) if header.step == DissolveStep::Map && !header.copy_started => {
                header
            }
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
        let carried = self.cells.dissolve_walks.borrow_mut().remove(&root);
        let mut walk = carried
            .filter(|walk| walk.walks(&header))
            .unwrap_or_else(|| DissolveWalk::new(&header, root));
        if walk.refused {
            self.cells.dissolve_walks.borrow_mut().insert(root, walk);
            return Ok(());
        }
        let end_of = |scope: NodeId| ends.iter().find(|end| end.root == scope);
        let ascends = |parent: NodeId, child: NodeId| {
            end_of(parent)
                .zip(end_of(child).and_then(|end| end.ascent_node_seed))
                .is_some_and(|(parent, seed)| {
                    ct_eq(
                        kdf::node_seed(parent.read_scope_seed, &child.0).as_bytes(),
                        seed,
                    )
                })
        };
        let step = walk
            .step(
                left,
                MAX_DISSOLVE_WALK_NODES,
                &ascends,
                async |key, anchor| {
                    let end = end_of(key.scope).ok_or(ReadFault::Unanswered)?;
                    self.dissolve_read(owner, end, anchor, key.node).await
                },
            )
            .await;
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
            MapStep::Stop => Ok(journal.drop_entry(&hold, &header).await?),
            MapStep::Complete => self.commit_map(journal, &hold, &header, &walk, ends).await,
        }
    }

    /// Whether the owner's queue holds an op at or below `root` that is still
    /// to publish. A kept op already published its record.
    async fn queue_writes_under(&self, owner: &DrainScope<'_>, root: NodeId) -> Result<bool, Halt> {
        let raw = self.seams.staging.queued_ops().await.map_err(seam)?;
        let scan = decode_queue(&RecordReader::new(owner.enc_secret), &raw);
        if scan.mine.is_empty() {
            return Ok(false);
        }
        let drained = self.drained_mark(owner).await?;
        let published = published_op_mark(&self.seams.staging, owner.enc_secret)
            .await
            .map_err(seam)?;
        let notes = self.kept_notes(owner).await?;
        let base = self.cells.base.borrow();
        Ok(scan.mine.iter().any(|(op_id, op)| {
            drained.is_none_or(|mark| op_id.0 > mark)
                && !is_kept(*op_id, published, &notes)
                && op_under(&base, root, &op.kind, op.target)
        }))
    }

    /// Write the map of a complete walk as a new generation, then commit the
    /// header at the seal step over it. A page of another generation is not
    /// part of the entry, so it goes after the commit.
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
        let mint = || {
            fresh_bytes(&mut *self.seams.entropy.borrow_mut(), "node id")
                .ok()
                .map(NodeId)
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

    /// One node of a dissolve walk, read under `end` through the gate from
    /// the record plane. A scope root's read also opens its write body for
    /// the gated index.
    async fn dissolve_read(
        &self,
        owner: &DrainScope<'_>,
        end: &ScopeEnd<'_>,
        anchor: Option<Anchor<'_>>,
        node: NodeId,
    ) -> Result<DissolveRead, ReadFault<Infallible>> {
        if node != end.root {
            let read = self.walk_read(owner, end, anchor, node, true).await?;
            return Ok(DissolveRead {
                mark: read.mark,
                children: read.children,
                root: None,
            });
        }
        let fault = |halt: Halt| match halt {
            Halt::RecordRefused => ReadFault::Untrusted,
            _ => ReadFault::Unanswered,
        };
        let resolved = self
            .gated_scope_root(owner, end, ResolveMode::NoCache)
            .await
            .map_err(fault)?;
        if !resolved.tied.is_empty() {
            return Err(ReadFault::Untrusted);
        }
        let record = resolved_bytes(resolved, end.root_name, &self.seams.events).map_err(fault)?;
        let root = self
            .open_root_record(Some(owner), end, &record)
            .await
            .map_err(fault)?;
        let commitment = root.state.commitment.ok_or(ReadFault::Untrusted)?;
        let (_, envelope, _) = assemble_head_envelope(
            &self.seams.gateway,
            &self.seams.http,
            end.root_name,
            &record,
            None,
        )
        .await
        .map_err(|_| ReadFault::Unanswered)?;
        let section = grant_section_bytes(&envelope)
            .and_then(|bytes| decode_grant_section(bytes).ok())
            .ok_or(ReadFault::Untrusted)?;
        let (write_body, _) = write_plane_of(
            &end.floors(&self.seams.floors),
            &envelope,
            &section,
            end.write_scope_seed,
            end.root.0,
        )
        .await
        .map_err(|failure| match failure {
            ResolveFailure::Rejected => {
                emit_trust_violation(
                    &self.seams.events,
                    end.root_name.as_str(),
                    "dissolve-write-body-refused",
                );
                ReadFault::Untrusted
            }
            _ => ReadFault::Unanswered,
        })?;
        Ok(DissolveRead {
            mark: RecordMark {
                sequence: root.state.observed.sequence(),
                digest: cipherbox_core::suite::hash::hash(&record),
            },
            children: root.state.children,
            root: Some(RootFacts {
                anchor: WalkAnchor {
                    epoch: root.epoch,
                    history_links: root.history_links,
                },
                index: write_body
                    .direct_child_scope_index
                    .iter()
                    .map(|child| NodeId(child.scope_id))
                    .collect(),
                rows: !commitment.entries.is_empty(),
                cut_epoch: commitment.cut_epoch,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use cipherbox_core::seal::{NodeKind, PreservedFields};

    use super::*;
    use crate::sync::dissolve_journal::{DissolveBinding, DissolvedScope, check_map};
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
    }

    fn folder(children: &[NodeId]) -> Node {
        Node {
            children: children.to_vec(),
            root: None,
            sequence: 1,
            refused: false,
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
            || {
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

    /// A record that the gate refuses holds the walk.
    #[test]
    fn a_refused_record_holds_the_walk() {
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
}
