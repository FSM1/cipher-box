//! The seal step of a dissolve (ADR 0077 D3, D4): each mapped node seals
//! again under the destination at its new id, children first.
//!
//! A copy body is built new from the source body: the mapped ids, the same
//! labels, kinds and link counters, the names that the destination write
//! scope derives, and no carried field at any layer. Each tick first reads
//! the gated destination root and the write epoch floor (ADR 0077 D4), each
//! publish reads the write epoch floor again, and each name goes into the
//! name log before its first publish.
//!
//! Once every row is sealed, the confirm reads each row again: each source
//! folder must name the children that the map places in it, and each copy
//! must hold the body that its source gives now. A confirm that covers every
//! row closes the seal (`close_seal`).

use core::cell::Cell;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{ChildRef, PreservedFields, ReadBody};
use cipherbox_core::suite::secret::ct_eq;

use super::super::{
    Anchor, Drain, DrainScope, LoadedRoot, LostWinner, ScopeEnd, SealPlane, checked_content_cid,
    encode_content_cid_str, refuse_record, seal_open_failed, take_tick_read,
};
use super::{EndMark, cut_epoch_of, cut_overtaken};
use crate::facade::{NodeId, emit_trust_violation};
use crate::gate::floor;
use crate::net::gated_read::{LeafRead, Unserved};
use crate::net::{ChildAdopter, Observed, PointerConsult, PointerConsultError};
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SharerScopedFloorStore,
    SnapshotCache, StagingStore,
};
use crate::sync::dissolve_journal::{
    DissolveBinding, DissolveHeader, DissolveHold, DissolveJournal, DissolveStep,
    DissolveWriteError, HeaderSlot, LoggedName, MAX_PRIOR_BINDINGS, MapRow, NameLogPage,
    PriorBinding,
};
use crate::sync::drain::walker::ReadFault;
use crate::sync::pointer::POINTER_PAYLOAD_VERSION;
use crate::sync::tick::scope_root_of;

/// The seal of one dissolve entry, carried across ticks.
pub(crate) struct DissolveSeal {
    /// The live map, the destination and the material of the destination
    /// end that this run seals for. Another of any starts the run again.
    map_gen: u16,
    binding: DissolveBinding,
    mark: EndMark,
    /// The rows sealed under that destination, by map index.
    done: BTreeSet<u32>,
    /// The rows that a read after every row was sealed found sealed, with
    /// a source that the map still describes. Each row in it closes the seal.
    confirmed: BTreeSet<u32>,
    /// A gate refused a record, or the endpoints served a fork. The run
    /// publishes nothing more.
    refused: bool,
    /// The read scope and the write scope that a tick computed for a rebind
    /// that waits, and the number of that tick.
    rebind: Option<((NodeId, NodeId), u64)>,
}

impl DissolveSeal {
    fn new(header: &DissolveHeader, mark: EndMark) -> Self {
        Self {
            map_gen: header.map_gen,
            binding: header.binding,
            mark,
            done: BTreeSet::new(),
            confirmed: BTreeSet::new(),
            refused: false,
            rebind: None,
        }
    }

    fn seals(&self, header: &DissolveHeader, mark: &EndMark) -> bool {
        self.map_gen == header.map_gen && self.binding == header.binding && self.mark == *mark
    }
}

/// Why one tick of a seal stopped.
pub(super) enum SealFault {
    /// A read did not land, or the entry waits. The next tick reads again.
    Unanswered,
    /// A gate refused a record, or the endpoints served a fork. The event
    /// went out.
    Refused,
    /// A source node moved out of the subtree, or a folder of it was shared
    /// after the copy started: the entry returns to its map step.
    Remap,
}

impl From<DissolveWriteError> for SealFault {
    fn from(_: DissolveWriteError) -> Self {
        Self::Unanswered
    }
}

impl<E> From<ReadFault<E>> for SealFault {
    fn from(fault: ReadFault<E>) -> Self {
        match fault {
            ReadFault::Untrusted => Self::Refused,
            ReadFault::Unanswered | ReadFault::Fatal(_) => Self::Unanswered,
        }
    }
}

/// The destination of a seal tick, from the ends of the tick.
pub(super) struct Destination<'t, 'e> {
    ends: &'t [ScopeEnd<'e>],
    /// The end of each scope root from the destination up to the vault root.
    /// Each copy name derives from the seed that the destination shares with
    /// each scope up to `write`.
    pub(super) chain: Vec<&'t ScopeEnd<'e>>,
    pub(super) write: &'t ScopeEnd<'e>,
}

/// The header that the gated destination root at `epoch` and `cut_epoch`,
/// the read epoch `vouched` that the owner's pointer vouches, and the write
/// epoch floor `write_epoch` give `header`, with the copy marked as started.
/// `None` when a read lags the header or the pointer, so the tick waits.
///
/// Only the owner moves the cut epoch and the pointer, so only those move
/// `restart_floor`. A read rise alone is a grantee rise, and each sealed copy
/// stays (ADR 0077 D4).
pub(super) fn restarted(
    header: &DissolveHeader,
    epoch: u64,
    cut_epoch: u64,
    vouched: u64,
    write_epoch: u64,
) -> Option<DissolveHeader> {
    let was = header.binding;
    if epoch < was.read_epoch
        || cut_epoch < was.base_cut
        || vouched > epoch
        || write_epoch < was.write_epoch
    {
        return None;
    }
    let mut next = header.clone();
    next.copy_started = true;
    let binding = &mut next.binding;
    binding.read_epoch = epoch;
    if cut_epoch > was.base_cut {
        binding.base_cut = cut_epoch;
        binding.restart_floor = binding.restart_floor.max(epoch);
    }
    binding.restart_floor = binding.restart_floor.max(vouched);
    binding.write_epoch = write_epoch;
    Some(next)
}

/// The header that a new destination, `read_scope` and `write_scope`, gives
/// `header` (ADR 0077 D4): the former binding goes to `prior_bindings`, and
/// the D4 check of the tick reads the epochs of the new one. A new read scope
/// restarts every copy. `None` at a rebind past [`MAX_PRIOR_BINDINGS`], which
/// waits.
fn rebound(
    header: &DissolveHeader,
    read_scope: NodeId,
    write_scope: NodeId,
) -> Option<DissolveHeader> {
    let was = header.binding;
    if header.prior_bindings.len() >= MAX_PRIOR_BINDINGS {
        return None;
    }
    let mut next = header.clone();
    next.prior_bindings.push(PriorBinding {
        read_scope: was.read_scope,
        read_root: was.read_scope,
        read_epoch: was.read_epoch,
        restart_floor: was.restart_floor,
        write_scope: was.write_scope,
        write_epoch: was.write_epoch,
    });
    next.binding = if read_scope == was.read_scope {
        DissolveBinding {
            write_scope,
            write_epoch: 0,
            ..was
        }
    } else {
        DissolveBinding {
            read_scope,
            read_epoch: 0,
            restart_floor: 0,
            base_cut: 0,
            write_scope,
            write_epoch: 0,
        }
    };
    Some(next)
}

/// Whether a write cut is owed at `write`, or the owed record did not read.
/// An owed write cut moves the names off the seed of the ends (ADR 0077 D4).
fn owes_write_cut(owed: Option<&[NodeId]>, write: NodeId) -> bool {
    owed.is_none_or(|owed| owed.contains(&write))
}

/// Whether a copy publish may sign at the write floor `current`: the floor of
/// the header, and no post-wave raise above it that has not landed, which is
/// a write cut with no floor yet.
fn floor_holds(current: u64, header: u64, deferred: Option<u64>) -> bool {
    current == header && deferred.is_none_or(|epoch| epoch <= current)
}

/// The map index of each row, by its old id.
fn row_index(rows: &[MapRow]) -> BTreeMap<NodeId, u32> {
    (0u32..).zip(rows).map(|(at, row)| (row.old, at)).collect()
}

/// The scope root of each row: the row itself when it is a scope root that
/// `header` cuts, else the scope of its parent row.
fn row_scopes(header: &DissolveHeader, rows: &[MapRow]) -> Option<Vec<NodeId>> {
    let mut scopes: Vec<NodeId> = Vec::with_capacity(rows.len());
    for row in rows {
        let scope = if cut_epoch_of(header, row.old).is_some() {
            row.old
        } else {
            *scopes.get(usize::try_from(row.parent?).ok()?)?
        };
        scopes.push(scope);
    }
    Some(scopes)
}

/// The copy of `source`, the body of the row at `at`: each child ref that a
/// row of this folder maps, at its new id and at the name `name` derives for
/// it, and no carried field at any layer. A child that no row of this folder
/// maps is not part of the copy.
fn fresh_body(
    source: &ReadBody,
    at: u32,
    rows: &[MapRow],
    index: &BTreeMap<NodeId, u32>,
    name: impl Fn(&NodeId) -> IpnsName,
) -> ReadBody {
    match source {
        ReadBody::Folder {
            created_at,
            modified_at,
            children,
            ..
        } => ReadBody::Folder {
            created_at: *created_at,
            modified_at: *modified_at,
            children: children
                .iter()
                .filter_map(|child| {
                    let row = &rows[usize::try_from(*index.get(&NodeId(child.id))?).ok()?];
                    (row.parent == Some(at)).then(|| ChildRef {
                        id: row.new.0,
                        name: child.name.clone(),
                        ipns_name: name(&row.new).as_str().as_bytes().to_vec(),
                        kind: child.kind,
                        link_counter: child.link_counter,
                        unknown: PreservedFields::new(),
                    })
                })
                .collect(),
            unknown: PreservedFields::new(),
        },
        ReadBody::File {
            created_at,
            modified_at,
            versions,
            ..
        } => ReadBody::File {
            created_at: *created_at,
            modified_at: *modified_at,
            versions: versions
                .iter()
                .cloned()
                .map(|mut version| {
                    version.unknown = PreservedFields::new();
                    version
                })
                .collect(),
            unknown: PreservedFields::new(),
        },
    }
}

/// Whether the children of `source`, the body of the row at `at`, are the
/// old ids of the rows whose parent is that row.
fn maps_the_children(source: &ReadBody, at: u32, rows: &[MapRow]) -> bool {
    let ReadBody::Folder { children, .. } = source else {
        return rows.iter().all(|row| row.parent != Some(at));
    };
    let named: BTreeSet<NodeId> = children.iter().map(|child| NodeId(child.id)).collect();
    let mapped: BTreeSet<NodeId> = rows
        .iter()
        .filter(|row| row.parent == Some(at))
        .map(|row| row.old)
        .collect();
    named.len() == children.len() && named == mapped
}

/// One node this tick publishes.
struct SealJob {
    at: u32,
    node: NodeId,
    name: IpnsName,
    basis: Observed,
    body: ReadBody,
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
    /// Drive the seal step of the entry at `root` within the reads of `left`.
    pub(super) async fn drive_seal(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        root: NodeId,
        left: &Cell<usize>,
    ) {
        let header = match journal.header(root).await {
            Ok(HeaderSlot::Own(header)) if header.step == DissolveStep::Seal => header,
            Ok(_) => {
                self.cells.dissolve_seals.borrow_mut().remove(&root);
                return;
            }
            Err(_) => return,
        };
        let Some(hold) = self.cells.dissolve.hold(root) else {
            return;
        };
        let Some(target) = self.destination_of(owner, ends, header.relink_parent) else {
            return;
        };
        let Some(held_floors) = self.guards_hold(&target).await else {
            return;
        };
        let dest = target.chain[0];
        let mark = EndMark::of(dest);
        let carried = self.cells.dissolve_seals.borrow_mut().remove(&root);
        let binding = header.binding;
        let candidate = (dest.root, target.write.root);
        let (header, mut run) = if candidate == (binding.read_scope, binding.write_scope) {
            let run = carried
                .filter(|run| run.seals(&header, &mark))
                .unwrap_or_else(|| DissolveSeal::new(&header, mark.clone()));
            (header, run)
        } else {
            // The write scope comes from the seeds of the ends, which can
            // differ for one tick, so a change of it alone commits only when
            // two ticks in a row compute it. A walk that did not finish, or
            // did not prove the bound read scope, reads its nodes as its
            // parent's, so no read rebind commits off it.
            let confirmed = if dest.root == binding.read_scope {
                carried
                    .as_ref()
                    .and_then(|run| run.rebind)
                    .is_some_and(|(seen, at)| {
                        seen == candidate && at.checked_add(1) == Some(self.inputs.tick)
                    })
            } else {
                self.inputs.walk_complete
                    && !self
                        .inputs
                        .unproved_scope_roots
                        .contains(&binding.read_scope)
            };
            let next = rebound(&header, dest.root, target.write.root).filter(|_| confirmed);
            let committed = match next {
                Some(next) => journal
                    .commit(&hold, Some(&header), &next)
                    .await
                    .is_ok()
                    .then_some(next),
                None => None,
            };
            let Some(next) = committed else {
                // The run of the bound destination waits as it stands.
                let mut run = carried.unwrap_or_else(|| DissolveSeal::new(&header, mark));
                run.rebind = Some((candidate, self.inputs.tick));
                self.cells.dissolve_seals.borrow_mut().insert(root, run);
                return;
            };
            let run = DissolveSeal::new(&next, mark);
            (next, run)
        };
        if !run.refused
            && let Err(SealFault::Refused) = self
                .seal_tick(
                    owner,
                    &target,
                    &held_floors,
                    journal,
                    &hold,
                    header,
                    &mut run,
                    left,
                )
                .await
        {
            run.refused = true;
        }
        self.cells.dissolve_seals.borrow_mut().insert(root, run);
    }

    /// The write epoch floor of each end of `target`'s chain, or `None` when a
    /// write cut is owed at one of them or a floor does not hold its seed. A
    /// write cut anywhere up to the vault root can move the copy names, so no
    /// rebind commits and no copy publishes while one runs (ADR 0077 D4).
    pub(super) async fn guards_hold(&self, target: &Destination<'_, '_>) -> Option<Vec<u64>> {
        let mut floors = Vec::with_capacity(target.chain.len());
        for end in &target.chain {
            if owes_write_cut(self.inputs.owed_write_cuts, end.root) {
                return None;
            }
            floors.push(self.write_floor(end).await.ok()?);
        }
        Some(floors)
    }

    /// The write lease of each end of `target`'s chain, taken once each write
    /// floor still is the one in `held` with no deferred raise above it. A
    /// write cut moves each name, so no publish under the leases lands at a
    /// name of the old write seed (ADR 0077 D4).
    pub(super) async fn lease_the_chain(
        &self,
        target: &Destination<'_, '_>,
        held: &[u64],
    ) -> Result<Vec<floor::WriteEpochLease>, SealFault> {
        let mut leases = Vec::with_capacity(target.chain.len());
        for end in &target.chain {
            leases
                .push(floor::acquire_write_epoch_lease(&end.root.0).ok_or(SealFault::Unanswered)?);
        }
        for (end, held) in target.chain.iter().zip(held) {
            let current = self.write_floor(end).await?;
            let deferred = floor::owed_write_raise(&end.floors(&self.seams.floors), &end.root.0)
                .map_err(|_| SealFault::Unanswered)?;
            if !floor_holds(current, *held, deferred) {
                return Err(SealFault::Unanswered);
            }
        }
        Ok(leases)
    }

    /// One tick of the seal: the D4 check, then each row left, children
    /// first, within the reads of `left`.
    #[expect(clippy::too_many_arguments, reason = "one tick of one entry")]
    async fn seal_tick(
        &self,
        owner: &DrainScope<'_>,
        target: &Destination<'_, '_>,
        held_floors: &[u64],
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: DissolveHeader,
        run: &mut DissolveSeal,
        left: &Cell<usize>,
    ) -> Result<(), SealFault> {
        let root = header.scopes[0].scope_id;
        let (ends, dest) = (target.ends, target.chain[0]);
        let end_of = |scope: NodeId| ends.iter().find(|end| end.root == scope);
        let write_floor = target
            .chain
            .iter()
            .zip(held_floors)
            .find_map(|(end, floor)| (end.root == target.write.root).then_some(*floor))
            .ok_or(SealFault::Unanswered)?;
        if !take_tick_read(left) {
            return Ok(());
        }
        let (dest_root, _) = self.dissolve_root::<()>(owner, dest).await?;
        let cut_epoch = dest_root
            .state
            .commitment
            .as_ref()
            .map_or(0, |commitment| commitment.cut_epoch);
        let vouched = self.vouched_read_epoch(owner, dest, left).await?;
        let next = restarted(&header, dest_root.epoch, cut_epoch, vouched, write_floor)
            .ok_or(SealFault::Unanswered)?;
        if next != header {
            journal.commit(hold, Some(&header), &next).await?;
        }
        if run.binding != next.binding {
            *run = DissolveSeal::new(&next, run.mark.clone());
        }
        if run.done.is_empty() {
            journal.drop_uncounted_pages(hold, &next).await?;
        }
        let header = next;

        let rows: Vec<MapRow> = journal
            .map(root, &header)
            .await?
            .into_iter()
            .flat_map(|page| page.rows)
            .collect();
        let scopes = row_scopes(&header, &rows).ok_or(SealFault::Unanswered)?;
        let index = row_index(&rows);
        let plane = dest.at(header.binding.read_epoch);
        // Once every row is sealed, each row is read again: the confirm.
        let confirming = run.done.len() == rows.len();
        let mut source_roots: BTreeMap<NodeId, LoadedRoot> = BTreeMap::new();
        let mut jobs = Vec::new();
        let mut fault = None;
        for (at, (row, scope)) in rows.iter().zip(&scopes).enumerate().rev() {
            let at = u32::try_from(at).map_err(|_| SealFault::Unanswered)?;
            let held = if confirming {
                &run.confirmed
            } else {
                &run.done
            };
            if held.contains(&at) {
                continue;
            }
            let Some(end) = end_of(*scope) else {
                fault = Some(SealFault::Unanswered);
                break;
            };
            let source = match self
                .seal_source(
                    owner,
                    ends,
                    &header,
                    end,
                    row.old,
                    &mut source_roots,
                    left,
                    confirming,
                )
                .await
            {
                Ok(Some(source)) => source,
                Ok(None) => break,
                Err(error) => {
                    fault = Some(error);
                    break;
                }
            };
            // A source child that the map does not place in this folder, or
            // a mapped child that the source no longer names, sends the entry
            // back to its map step.
            if confirming && !maps_the_children(&source, at, &rows) {
                fault = Some(SealFault::Remap);
                break;
            }
            if !take_tick_read(left) {
                break;
            }
            let body = fresh_body(&source, at, &rows, &index, |id| dest.write_name(&id.0));
            let name = dest.write_name(&row.new.0);
            match self
                .probe_copy(
                    &plane,
                    dest_root.anchor(),
                    row.new,
                    &name,
                    &body,
                    &header,
                    ends,
                )
                .await
            {
                Ok(None) => {
                    run.done.insert(at);
                    if confirming {
                        run.confirmed.insert(at);
                    }
                }
                Ok(Some(basis)) => {
                    run.done.remove(&at);
                    jobs.push(SealJob {
                        at,
                        node: row.new,
                        name,
                        basis,
                        body,
                    });
                }
                Err(error) => {
                    fault = Some(error);
                    break;
                }
            }
        }
        // A refusal holds the whole batch, so no later fault hides it.
        match fault {
            Some(SealFault::Refused) => return Err(SealFault::Refused),
            Some(SealFault::Remap) => {
                let mut remap = header.clone();
                remap.step = DissolveStep::Map;
                journal.commit(hold, Some(&header), &remap).await?;
                return Ok(());
            }
            _ => {}
        }
        self.log_names(journal, hold, root, &jobs).await?;
        for job in jobs {
            let _leases = self.lease_the_chain(target, held_floors).await?;
            let content_cids = match &job.body {
                ReadBody::File { versions, .. } => versions
                    .iter()
                    .map(|version| {
                        checked_content_cid(&version.content_cid).map(encode_content_cid_str)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| SealFault::Unanswered)?,
                ReadBody::Folder { .. } => Vec::new(),
            };
            self.publish_node(
                owner,
                &plane,
                job.node,
                job.basis,
                false,
                &job.body,
                content_cids,
                PreservedFields::new(),
                PreservedFields::new(),
                None,
                LostWinner::Verdict,
            )
            .await
            .map_err(|_| SealFault::Unanswered)?;
            run.done.insert(job.at);
        }
        if let Some(fault) = fault {
            return Err(fault);
        }
        if run.confirmed.len() == rows.len() {
            self.close_seal(owner, ends, journal, hold, &header, left)
                .await?;
        }
        Ok(())
    }

    /// The destination of the relink parent `node` now: its nearest scope
    /// root, and the nearest scope root from there up whose write seed is not
    /// its parent scope's, or the vault root. `None` when the tick holds no end
    /// for a scope on the path to the vault root.
    pub(super) fn destination_of<'t, 'e>(
        &self,
        owner: &DrainScope<'_>,
        ends: &'t [ScopeEnd<'e>],
        node: NodeId,
    ) -> Option<Destination<'t, 'e>> {
        let base = self.cells.base.borrow();
        let roots: BTreeSet<NodeId> = owner.scope_roots.iter().copied().collect();
        let read = scope_root_of(&base, node, &roots);
        let chain = core::iter::once(read)
            .chain(
                base.ancestors(read)
                    .into_iter()
                    .filter(|scope| roots.contains(scope) || *scope == base.root),
            )
            .map(|scope| ends.iter().find(|end| end.root == scope))
            .collect::<Option<Vec<_>>>()?;
        let write = chain
            .windows(2)
            .find(|pair| !ct_eq(pair[0].write_scope_seed, pair[1].write_scope_seed))
            .map_or(chain.last().copied(), |pair| Some(pair[0]))?;
        Some(Destination { ends, chain, write })
    }

    /// The source body of the row at `node` under `end`, its scope. A scope
    /// root reads through its own gate once in a tick, into `roots`. In the
    /// confirm, its gated index may name only the scopes that `header` cuts.
    /// `None` when the tick has no reads left.
    #[expect(clippy::too_many_arguments, reason = "one source read of one row")]
    async fn seal_source(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        header: &DissolveHeader,
        end: &ScopeEnd<'_>,
        node: NodeId,
        roots: &mut BTreeMap<NodeId, LoadedRoot>,
        left: &Cell<usize>,
        confirming: bool,
    ) -> Result<Option<ReadBody>, SealFault> {
        let root = match roots.entry(end.root) {
            Entry::Occupied(slot) => slot.into_mut(),
            Entry::Vacant(slot) => {
                if !take_tick_read(left) {
                    return Ok(None);
                }
                let (root, envelope) = self.dissolve_root::<()>(owner, end).await?;
                // A row or another cut at a cut scope is work that the dissolve
                // did not do, and the seal waits.
                let commitment = root
                    .state
                    .commitment
                    .as_ref()
                    .ok_or(SealFault::Unanswered)?;
                if cut_overtaken(
                    !commitment.entries.is_empty(),
                    commitment.cut_epoch,
                    cut_epoch_of(header, end.root),
                ) {
                    return Err(SealFault::Unanswered);
                }
                if confirming
                    && self
                        .gated_index(end, &envelope)
                        .await?
                        .iter()
                        .any(|scope| cut_epoch_of(header, *scope).is_none())
                {
                    return Err(SealFault::Remap);
                }
                slot.insert(root)
            }
        };
        if node == end.root {
            let state = &root.state;
            return Ok(Some(ReadBody::Folder {
                created_at: state.created_at,
                modified_at: state.modified_at,
                children: state.children.clone(),
                unknown: PreservedFields::new(),
            }));
        }
        if !take_tick_read(left) {
            return Ok(None);
        }
        match self
            .gated_child(owner, ends, header, end, root.anchor(), node)
            .await
        {
            Ok(loaded) => Ok(Some(loaded.body)),
            Err(ReadFault::Fatal(_)) => Err(SealFault::Remap),
            Err(fault) => Err(fault.into()),
        }
    }

    /// The basis to publish the copy `body` of `node` over at `name` under
    /// `plane`, or `None` when the record there holds that body, sealed at an
    /// epoch from the restart floor of `header` to the plane's. The open
    /// commits nothing.
    #[expect(clippy::too_many_arguments, reason = "one probe of one copy name")]
    async fn probe_copy(
        &self,
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        node: NodeId,
        name: &IpnsName,
        body: &ReadBody,
        header: &DissolveHeader,
        ends: &[ScopeEnd<'_>],
    ) -> Result<Option<Observed>, SealFault> {
        let read = match LeafRead::fetch(&self.seams.transport, name).await {
            Ok(read) => read,
            Err(Unserved { absent: true, .. }) => {
                return Ok(Some(Observed::unread(name)));
            }
            Err(_) => return Err(SealFault::Unanswered),
        };
        let floors = plane.end.floors(&self.seams.floors);
        let adopter = self.copy_adopter(plane, &floors, node);
        let (adopted, envelope) = match self
            .open_held(
                &plane.end,
                anchor,
                &adopter,
                name,
                &read.bytes,
                read.endpoint_failed,
            )
            .await
        {
            Ok(opened) => opened,
            Err(Some(rejection)) => {
                let former = adopter
                    .unbound_scope()
                    .filter(|_| seal_open_failed(&rejection))
                    .and_then(|scope| {
                        header
                            .prior_bindings
                            .iter()
                            .find(|was| was.read_scope.0 == scope)
                    });
                if let Some(was) = former {
                    return self
                        .former_copy(ends, was.read_scope, node, name, &read)
                        .await;
                }
                refuse_record(&self.seams.events, name, &rejection);
                return Err(SealFault::Refused);
            }
            Err(None) => return Err(SealFault::Unanswered),
        };
        let bound = adopter.opened_scope() == Some(plane.end.root.0);
        if self
            .held_fork(
                &plane.end,
                anchor,
                &adopter,
                name,
                &read.bytes,
                &read.tied,
                read.endpoint_failed,
            )
            .await
        {
            return Err(self.fork_at::<()>(name, adopted.sequence).into());
        }

        // A kept copy carries no field at any layer, the envelope included.
        let sealed = bound
            && envelope.unknown.is_empty()
            && envelope.epoch_tag_unknown.is_empty()
            && (header.binding.restart_floor..=plane.epoch).contains(&adopted.epoch)
            && adopted.read_body == *body;
        Ok((!sealed).then(|| Observed::record(name, read.pick.sequence)))
    }

    /// The basis to publish over `read`, the record at the copy `name` of
    /// `node` whose tag names `scope`, a former destination. The record passes
    /// the gate of that scope with no commit, as a copy from before the rebind
    /// does, or it is refused there.
    async fn former_copy(
        &self,
        ends: &[ScopeEnd<'_>],
        scope: NodeId,
        node: NodeId,
        name: &IpnsName,
        read: &LeafRead,
    ) -> Result<Option<Observed>, SealFault> {
        let end = *ends
            .iter()
            .find(|end| end.root == scope)
            .ok_or(SealFault::Unanswered)?;
        let (plane, root) = self.ledger_plane(end).await.ok_or(SealFault::Unanswered)?;
        let floors = end.floors(&self.seams.floors);
        let adopter = self.copy_adopter(&plane, &floors, node);
        let (bytes, failed) = (&read.bytes, read.endpoint_failed);
        let sequence = match self
            .open_held(&end, root.anchor(), &adopter, name, bytes, failed)
            .await
        {
            Ok((adopted, _)) => adopted.sequence,
            Err(Some(rejection)) => {
                refuse_record(&self.seams.events, name, &rejection);
                return Err(SealFault::Refused);
            }
            Err(None) => return Err(SealFault::Unanswered),
        };
        if self
            .held_fork(
                &end,
                root.anchor(),
                &adopter,
                name,
                bytes,
                &read.tied,
                failed,
            )
            .await
        {
            return Err(self.fork_at::<()>(name, sequence).into());
        }
        Ok(Some(Observed::record(name, read.pick.sequence)))
    }

    /// The read epoch that the owner vouches for the destination `dest`:
    /// the `min_read_epoch` of its scope pointer, read under the trust rules
    /// of [`PointerConsult`], 0 for a scope never re-pointed, or the vouched
    /// floor of the vault root. A pointer that does not read pauses the tick.
    pub(super) async fn vouched_read_epoch(
        &self,
        owner: &DrainScope<'_>,
        dest: &ScopeEnd<'_>,
        left: &Cell<usize>,
    ) -> Result<u64, SealFault> {
        let scope = dest.root.0;
        let floors = dest.floors(&self.seams.floors);
        if dest.root == self.cells.base.borrow().root {
            return floor::vouched_floor(&floors, &scope)
                .await
                .map(Option::unwrap_or_default)
                .map_err(|_| SealFault::Unanswered);
        }
        let scope_keys = self.inputs.owner_pointers.ok_or(SealFault::Unanswered)?;
        if !take_tick_read(left) {
            return Err(SealFault::Unanswered);
        }
        let consult = PointerConsult {
            scope_keys,
            owner_identity: owner.owner_identity,
            payload_version: POINTER_PAYLOAD_VERSION,
        };
        match consult.read(&self.seams.transport, &floors, &scope).await {
            Ok(read) => Ok(read.map_or(0, |read| read.repoint.min_read_epoch)),
            Err(PointerConsultError::Unavailable) => Err(SealFault::Unanswered),
            Err(PointerConsultError::Rejected) => {
                let name = scope_keys.pointer_name(&scope);
                emit_trust_violation(
                    &self.seams.events,
                    name.as_str(),
                    "dissolve-scope-pointer-refused",
                );
                Err(SealFault::Refused)
            }
        }
    }

    /// The write epoch floor of `write`. A floor that does not read, or one
    /// above the stamp of the seed that derives the copy names, pauses the
    /// tick.
    async fn write_floor(&self, write: &ScopeEnd<'_>) -> Result<u64, SealFault> {
        floor::write_epoch_floor(&write.floors(&self.seams.floors), &write.root.0)
            .await
            .ok()
            .flatten()
            .filter(|floor| write.write_seed_stamp.is_some_and(|stamp| *floor <= stamp))
            .ok_or(SealFault::Unanswered)
    }

    /// The child adopter of a copy name: the destination scope alone. A copy
    /// takes a new id, so no owed-move scope of the destination binds it.
    pub(in crate::sync::drain) fn copy_adopter<'e>(
        &'e self,
        plane: &SealPlane<'_>,
        floors: &'e SharerScopedFloorStore<'e, F>,
        node: NodeId,
    ) -> ChildAdopter<'e, H, SharerScopedFloorStore<'e, F>> {
        ChildAdopter::new(
            &self.seams.gateway,
            &self.seams.http,
            floors,
            plane.end.root.0,
            plane.end.read_scope_seed.clone(),
            node.0,
        )
        .with_seed_stamp(Some(plane.epoch))
    }

    /// Append one name log page with each name of `jobs` that the log of the
    /// entry at `root` does not hold yet.
    async fn log_names(
        &self,
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        root: NodeId,
        jobs: &[SealJob],
    ) -> Result<(), SealFault> {
        if jobs.is_empty() {
            return Ok(());
        }
        let pages = journal.name_log(root).await?;
        let logged: BTreeSet<(NodeId, &[u8])> = pages
            .iter()
            .flat_map(|page| &page.entries)
            .map(|entry| (entry.id, entry.name.as_slice()))
            .collect();
        let entries: Vec<LoggedName> = jobs
            .iter()
            .filter(|job| !logged.contains(&(job.node, job.name.as_str().as_bytes())))
            .map(|job| LoggedName {
                id: job.node,
                name: job.name.as_str().as_bytes().to_vec(),
            })
            .collect();
        if entries.is_empty() {
            return Ok(());
        }
        let index = pages
            .last()
            .map_or(Some(0), |page| page.index.checked_add(1))
            .ok_or(SealFault::Unanswered)?;
        journal
            .append_name_log(hold, &NameLogPage { index, entries })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cipherbox_core::seal::{NodeKind, Version};

    use super::*;
    use crate::sync::dissolve_journal::DissolvedScope;

    const S: NodeId = NodeId([0x10; 16]);
    const N: NodeId = NodeId([0x20; 16]);
    const A: NodeId = NodeId([0x31; 16]);
    const B: NodeId = NodeId([0x32; 16]);

    fn header() -> DissolveHeader {
        let binding = DissolveBinding {
            read_scope: NodeId([0x01; 16]),
            read_epoch: 3,
            restart_floor: 3,
            base_cut: 2,
            write_scope: NodeId([0x01; 16]),
            write_epoch: 5,
        };
        let scopes = [S, N]
            .into_iter()
            .map(|scope| DissolvedScope {
                cut_epoch: 4,
                cut_time: 1,
                final_landed: true,
                ..DissolvedScope::uncut(scope)
            })
            .collect();
        let mut header =
            DissolveHeader::at_cut(NodeId([0x70; 16]), NodeId([0x01; 16]), binding, scopes);
        header.step = DissolveStep::Seal;
        header
    }

    fn row(old: NodeId, new: u8, parent: Option<u32>) -> MapRow {
        MapRow {
            old,
            new: NodeId([new; 16]),
            parent,
            old_name: b"k51old".to_vec(),
        }
    }

    /// The map S → [A, N → [B]].
    fn rows() -> Vec<MapRow> {
        vec![
            row(S, 0x70, None),
            row(A, 0x71, Some(0)),
            row(N, 0x72, Some(0)),
            row(B, 0x73, Some(2)),
        ]
    }

    /// Each predicate against an owed write cut refuses alone: the owed record
    /// at the start of the tick, and a raise that the lease deferred.
    #[test]
    fn each_owed_write_cut_predicate_refuses_alone() {
        let write = NodeId([1; 16]);
        assert!(!owes_write_cut(Some(&[]), write));
        assert!(owes_write_cut(Some(&[write]), write), "the owed record");
        assert!(
            owes_write_cut(None, write),
            "an owed record that does not read"
        );
        assert!(!owes_write_cut(Some(&[NodeId([2; 16])]), write));

        assert!(floor_holds(5, 5, None));
        assert!(!floor_holds(5, 5, Some(6)), "a deferred raise");
        assert!(floor_holds(6, 6, Some(6)), "a raise that landed");
        assert!(!floor_holds(6, 5, None), "a floor above the header");
    }

    /// The D4 rows that the gated destination root, the owner's pointer and
    /// the write floor show.
    #[test]
    fn each_destination_rise_restarts_the_binding_it_moves() {
        let held = header();
        let binding = |header: Option<DissolveHeader>| header.map(|header| header.binding);
        let was = held.binding;

        let same = restarted(&held, 3, 2, 3, 5).expect("no change");
        assert!(same.copy_started, "the first seal tick marks the copy");
        assert_eq!(same.binding, was);
        assert_eq!(
            binding(restarted(&held, 4, 2, 3, 5)),
            Some(DissolveBinding {
                read_epoch: 4,
                ..was
            }),
            "a grantee rise keeps the restart floor"
        );
        assert_eq!(
            binding(restarted(&held, 4, 2, 4, 5)),
            Some(DissolveBinding {
                read_epoch: 4,
                restart_floor: 4,
                ..was
            }),
            "a pointer rise seals each node below it again"
        );
        assert_eq!(
            binding(restarted(&held, 4, 3, 3, 5)),
            Some(DissolveBinding {
                read_epoch: 4,
                restart_floor: 4,
                base_cut: 3,
                ..was
            }),
            "an owner cut with the pointer left as it was moves the floor"
        );
        assert_eq!(
            binding(restarted(&held, 3, 3, 3, 5)),
            Some(DissolveBinding { base_cut: 3, ..was }),
            "a cut rise with no read rise keeps the read epoch and the floor"
        );
        assert_eq!(
            binding(restarted(&held, 3, 2, 3, 6)),
            Some(DissolveBinding {
                write_epoch: 6,
                ..was
            }),
            "a write rise keeps the read binding"
        );
        assert_eq!(
            binding(restarted(&held, 4, 3, 3, 6)),
            Some(DissolveBinding {
                read_epoch: 4,
                restart_floor: 4,
                base_cut: 3,
                write_epoch: 6,
                ..was
            }),
            "a read rise and a write rise in one write"
        );
        for (epoch, cut_epoch, vouched, write_epoch) in
            [(2, 2, 2, 5), (3, 1, 3, 5), (3, 2, 3, 4), (3, 2, 4, 5)]
        {
            assert!(
                restarted(&held, epoch, cut_epoch, vouched, write_epoch).is_none(),
                "a read that lags the header or the pointer waits"
            );
        }
    }

    /// An owner revoke with the pointer left as it was, then a grantee rise:
    /// the revoke moves the restart floor, and the grantee rise keeps it, so
    /// each copy sealed after the revoke stays.
    #[test]
    fn a_grantee_rise_after_a_revoke_with_an_old_pointer_keeps_the_floor() {
        let revoked = restarted(&header(), 4, 3, 3, 5).expect("the revoke reads");
        let risen = restarted(&revoked, 5, 3, 3, 5).expect("the grantee rise reads");

        assert_eq!(
            (risen.binding.read_epoch, risen.binding.restart_floor),
            (5, 4)
        );
    }

    /// A rebind keeps the former binding. A new read scope starts its
    /// epochs at zero for the D4 check to read, a new write scope alone keeps
    /// the read binding, and a rebind past the cap waits.
    #[test]
    fn a_rebind_keeps_the_former_binding_and_waits_past_the_cap() {
        let held = header();
        let was = held.binding;
        let other = NodeId([0x02; 16]);
        let former = PriorBinding {
            read_scope: was.read_scope,
            read_root: was.read_scope,
            read_epoch: was.read_epoch,
            restart_floor: was.restart_floor,
            write_scope: was.write_scope,
            write_epoch: was.write_epoch,
        };

        let read = rebound(&held, other, was.write_scope).expect("a first rebind");
        assert_eq!(read.prior_bindings, vec![former]);
        assert_eq!(
            read.binding,
            DissolveBinding {
                read_scope: other,
                read_epoch: 0,
                restart_floor: 0,
                base_cut: 0,
                write_scope: was.write_scope,
                write_epoch: 0,
            }
        );
        let write = rebound(&held, was.read_scope, other).expect("a write rebind");
        assert_eq!(
            write.binding,
            DissolveBinding {
                write_scope: other,
                write_epoch: 0,
                ..was
            }
        );
        let mut full = held;
        full.prior_bindings = vec![former; MAX_PRIOR_BINDINGS];
        assert!(
            rebound(&full, other, other).is_none(),
            "a fifth rebind waits"
        );
    }

    #[test]
    fn each_row_seals_under_its_nearest_cut_scope() {
        assert_eq!(row_scopes(&header(), &rows()), Some(vec![S, S, N, N]));
    }

    fn padding() -> PreservedFields {
        PreservedFields::from_iter([(
            "zzFuture".to_string(),
            cipherbox_core::codec::Value::Unsigned(7),
        )])
    }

    fn source_child(id: NodeId, name: &str) -> ChildRef {
        ChildRef {
            id: id.0,
            name: name.into(),
            ipns_name: b"k51carried".to_vec(),
            kind: NodeKind::Folder,
            link_counter: 4,
            unknown: padding(),
        }
    }

    fn name(id: &NodeId) -> IpnsName {
        crate::rotation::derive_write_name(&zeroize::Zeroizing::new([0x5a; 32]), &id.0)
    }

    /// A copy folder names each mapped child of its own row at its new id and
    /// derived name, keeps each label, kind and link counter, and carries no
    /// unknown field in the body or in any child ref.
    #[test]
    fn a_copy_folder_names_its_mapped_children_and_sheds_each_unknown_field() {
        let rows = rows();
        let index = row_index(&rows);
        let source = ReadBody::Folder {
            created_at: 11,
            modified_at: 12,
            children: vec![
                source_child(A, "a"),
                source_child(N, "n"),
                // A row of another folder: the map holds it elsewhere.
                source_child(B, "b"),
                // No row: a child that the map does not hold.
                source_child(NodeId([0x40; 16]), "late"),
            ],
            unknown: padding(),
        };

        let copy = fresh_body(&source, 0, &rows, &index, name);

        let child = |id: u8, label: &str| ChildRef {
            id: [id; 16],
            name: label.into(),
            ipns_name: name(&NodeId([id; 16])).as_str().as_bytes().to_vec(),
            kind: NodeKind::Folder,
            link_counter: 4,
            unknown: PreservedFields::new(),
        };
        assert_eq!(
            copy,
            ReadBody::Folder {
                created_at: 11,
                modified_at: 12,
                children: vec![child(0x71, "a"), child(0x72, "n")],
                unknown: PreservedFields::new(),
            }
        );
    }

    /// A copy file keeps each version and sheds the unknown fields of the body
    /// and of each version.
    #[test]
    fn a_copy_file_keeps_each_version_and_sheds_each_unknown_field() {
        let rows = rows();
        let index = row_index(&rows);
        let mut version = Version::new(b"cid".to_vec(), [0x33; 32], 9, 10);
        version.unknown = padding();
        let source = ReadBody::File {
            created_at: 1,
            modified_at: 2,
            versions: vec![version.clone()],
            unknown: padding(),
        };

        let ReadBody::File {
            created_at,
            modified_at,
            versions,
            unknown,
        } = fresh_body(&source, 1, &rows, &index, name)
        else {
            panic!("a file copies as a file");
        };

        assert_eq!((created_at, modified_at), (1, 2));
        assert!(unknown.is_empty());
        version.unknown = PreservedFields::new();
        assert_eq!(versions, vec![version]);
    }

    /// A row that the map holds as a folder with mapped children, and that
    /// the source now holds as a file, does not confirm: the confirm sends it
    /// back to the map. A file with no mapped child confirms.
    #[test]
    fn a_folder_that_reads_as_a_file_does_not_confirm() {
        let rows = rows();
        let file = ReadBody::File {
            created_at: 1,
            modified_at: 2,
            versions: Vec::new(),
            unknown: PreservedFields::new(),
        };

        assert!(!maps_the_children(&file, 2, &rows), "N maps B");
        assert!(maps_the_children(&file, 1, &rows), "A maps no child");
    }
}
