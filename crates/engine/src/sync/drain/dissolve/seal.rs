//! The seal step of a dissolve (ADR 0077 D3, D4): each mapped node seals
//! again under the destination at its new id, children first.
//!
//! A copy body is built new from the source body: the mapped ids, the same
//! labels, kinds and link counters, the names that the destination write
//! scope derives, and no carried field at any layer. Each tick first reads
//! the gated destination root and the write epoch floor (ADR 0077 D4), each
//! publish reads the write epoch floor again, and each name goes into the
//! name log before its first publish.

use core::cell::Cell;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{ChildRef, PreservedFields, ReadBody};
use cipherbox_core::suite::secret::ct_eq;

use super::super::{
    Anchor, Drain, DrainScope, LoadedRoot, LostWinner, ScopeEnd, SealPlane, checked_content_cid,
    encode_content_cid_str, refuse_record, take_tick_read,
};
use super::{EndMark, cut_epoch_of, cut_overtaken};
use crate::facade::NodeId;
use crate::gate::floor;
use crate::net::gated_read::{LeafRead, Unserved};
use crate::net::{ChildAdopter, Observed};
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SharerScopedFloorStore,
    SnapshotCache, StagingStore,
};
use crate::sync::dissolve_journal::{
    DissolveBinding, DissolveHeader, DissolveHold, DissolveJournal, DissolveStep,
    DissolveWriteError, HeaderSlot, LoggedName, MapRow, NameLogPage,
};
use crate::sync::drain::walker::ReadFault;
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
    /// A gate refused a record, or the endpoints served a fork. The run
    /// publishes nothing more.
    refused: bool,
}

impl DissolveSeal {
    fn new(header: &DissolveHeader, mark: EndMark) -> Self {
        Self {
            map_gen: header.map_gen,
            binding: header.binding,
            mark,
            done: BTreeSet::new(),
            refused: false,
        }
    }

    fn seals(&self, header: &DissolveHeader, mark: &EndMark) -> bool {
        self.map_gen == header.map_gen && self.binding == header.binding && self.mark == *mark
    }
}

/// Why one tick of a seal stopped.
enum SealFault {
    /// A read did not land, or the entry waits. The next tick reads again.
    Unanswered,
    /// A gate refused a record, or the endpoints served a fork. The event
    /// went out.
    Refused,
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

/// The header that the gated destination root at `epoch` and `cut_epoch`
/// and the write epoch floor `write_epoch` give `header`, with the copy
/// marked as started. `None` when a read lags the header, so the tick waits.
///
/// The seal cannot tell a grantee rise from an owner rise without the scope
/// pointer, so each read rise moves `restart_floor` to the new epoch, and
/// each node below it seals again.
fn restarted(
    header: &DissolveHeader,
    epoch: u64,
    cut_epoch: u64,
    write_epoch: u64,
) -> Option<DissolveHeader> {
    let was = header.binding;
    if epoch < was.read_epoch || cut_epoch < was.base_cut || write_epoch < was.write_epoch {
        return None;
    }
    let mut next = header.clone();
    next.copy_started = true;
    let binding = &mut next.binding;
    if epoch > was.read_epoch || cut_epoch > was.base_cut {
        binding.read_epoch = epoch;
        binding.restart_floor = was.restart_floor.max(epoch);
        binding.base_cut = cut_epoch;
    }
    binding.write_epoch = write_epoch;
    Some(next)
}

/// Whether a write cut is owed at `write`, or the owed record did not read.
/// An owed write cut moves the names off the seed of the ends (ADR 0077 D4).
fn owes_write_cut(owed: Option<&[NodeId]>, write: NodeId) -> bool {
    owed.is_none_or(|owed| owed.contains(&write))
}

/// Whether a copy publish may sign at the write floor `current`: the floor of
/// the header, and no raise that the lease deferred above it, which is a
/// write cut with no floor yet.
fn floor_holds(current: u64, header: u64, deferred: Option<u64>) -> bool {
    current == header && deferred.is_none_or(|epoch| epoch <= current)
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
        let Some(dest) = ends
            .iter()
            .find(|end| end.root == header.binding.read_scope)
        else {
            return;
        };
        let mark = EndMark::of(dest);
        let carried = self.cells.dissolve_seals.borrow_mut().remove(&root);
        let mut run = carried
            .filter(|run| run.seals(&header, &mark))
            .unwrap_or_else(|| DissolveSeal::new(&header, mark.clone()));
        if !run.refused
            && let Err(SealFault::Refused) = self
                .seal_tick(owner, ends, journal, &hold, header, dest, &mut run, left)
                .await
        {
            run.refused = true;
        }
        self.cells.dissolve_seals.borrow_mut().insert(root, run);
    }

    /// One tick of the seal: the D4 check, then each row left, children
    /// first, within the reads of `left`.
    #[expect(clippy::too_many_arguments, reason = "one tick of one entry")]
    async fn seal_tick(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: DissolveHeader,
        dest: &ScopeEnd<'_>,
        run: &mut DissolveSeal,
        left: &Cell<usize>,
    ) -> Result<(), SealFault> {
        let root = header.scopes[0].scope_id;
        let end_of = |scope: NodeId| ends.iter().find(|end| end.root == scope);
        let write = end_of(header.binding.write_scope).ok_or(SealFault::Unanswered)?;
        if owes_write_cut(self.inputs.owed_write_cuts, write.root) {
            return Err(SealFault::Unanswered);
        }
        // Each copy name derives from the write scope's seed, which the
        // destination end publishes under.
        if !ct_eq(dest.write_scope_seed, write.write_scope_seed) {
            return Err(SealFault::Unanswered);
        }
        // A grant on an ancestor of the relink parent changes the destination
        // (ADR 0077 D4), and the seal waits.
        let roots: BTreeSet<NodeId> = owner.scope_roots.iter().copied().collect();
        if scope_root_of(&self.cells.base.borrow(), header.relink_parent, &roots)
            != header.binding.read_scope
        {
            return Err(SealFault::Unanswered);
        }
        if !take_tick_read(left) {
            return Ok(());
        }
        let (dest_root, _) = self.walk_root::<()>(owner, dest, true).await?;
        let cut_epoch = dest_root
            .state
            .commitment
            .as_ref()
            .map_or(0, |commitment| commitment.cut_epoch);
        let write_epoch = self.write_floor(write).await?;
        let next = restarted(&header, dest_root.epoch, cut_epoch, write_epoch)
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
        let index: BTreeMap<NodeId, u32> =
            (0u32..).zip(&rows).map(|(at, row)| (row.old, at)).collect();
        let plane = dest.at(header.binding.read_epoch);
        let mut source_roots: BTreeMap<NodeId, LoadedRoot> = BTreeMap::new();
        let mut jobs = Vec::new();
        let mut fault = None;
        for (at, (row, scope)) in rows.iter().zip(&scopes).enumerate().rev() {
            let at = u32::try_from(at).map_err(|_| SealFault::Unanswered)?;
            if run.done.contains(&at) {
                continue;
            }
            let scope = *scope;
            let Some(end) = end_of(scope) else {
                fault = Some(SealFault::Unanswered);
                break;
            };
            let source = match self
                .seal_source(owner, ends, &header, end, row.old, &mut source_roots, left)
                .await
            {
                Ok(Some(source)) => source,
                Ok(None) => break,
                Err(error) => {
                    fault = Some(error);
                    break;
                }
            };
            let body = fresh_body(&source, at, &rows, &index, |id| dest.write_name(&id.0));
            if !take_tick_read(left) {
                break;
            }
            let name = dest.write_name(&row.new.0);
            match self
                .probe_copy(
                    &plane,
                    dest_root.anchor(),
                    row.new,
                    &name,
                    &body,
                    header.binding.restart_floor,
                )
                .await
            {
                Ok(None) => {
                    run.done.insert(at);
                }
                Ok(Some(basis)) => jobs.push(SealJob {
                    at,
                    node: row.new,
                    name,
                    basis,
                    body,
                }),
                Err(error) => {
                    fault = Some(error);
                    break;
                }
            }
        }
        // Each parent publishes after its children.
        self.log_names(journal, hold, root, &jobs).await?;
        for job in jobs {
            // A write cut moves each copy name: no publish lands at a name of
            // the old write seed (ADR 0077 D4). The lease holds the floor from
            // this check through the signature.
            let Some(_lease) = floor::acquire_write_epoch_lease(&write.root.0) else {
                return Err(SealFault::Unanswered);
            };
            let current = self.write_floor(write).await?;
            let deferred = floor::owed_write_raise(&write.root.0);
            if !floor_holds(current, header.binding.write_epoch, deferred) {
                return Err(SealFault::Unanswered);
            }
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
            if self
                .publish_node(
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
                .is_err()
            {
                return Err(SealFault::Unanswered);
            }
            run.done.insert(job.at);
        }
        fault.map_or(Ok(()), Err)
    }

    /// The source body of the row at `node` under `end`, its scope. A scope
    /// root reads through its own gate once in a tick, into `roots`. `None`
    /// when the tick has no reads left.
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
    ) -> Result<Option<ReadBody>, SealFault> {
        let root = match roots.entry(end.root) {
            Entry::Occupied(slot) => slot.into_mut(),
            Entry::Vacant(slot) => {
                if !take_tick_read(left) {
                    return Ok(None);
                }
                let (root, _) = self.walk_root::<()>(owner, end, true).await?;
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
        // A folder shared after the copy started is a stop of the read, and
        // the seal waits.
        let loaded = self
            .gated_child(owner, ends, header, end, root.anchor(), node)
            .await?;
        Ok(Some(loaded.body))
    }

    /// The basis to publish the copy `body` of `node` over at `name` under
    /// `plane`, or `None` when the record there holds that body, sealed at an
    /// epoch from `restart_floor` to the plane's. The open commits nothing.
    async fn probe_copy(
        &self,
        plane: &SealPlane<'_>,
        anchor: Anchor<'_>,
        node: NodeId,
        name: &IpnsName,
        body: &ReadBody,
        restart_floor: u64,
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
            return Err(self.fork_at(name, adopted.sequence).into());
        }

        // A kept copy carries no field at any layer, the envelope included.
        let sealed = bound
            && envelope.unknown.is_empty()
            && envelope.epoch_tag_unknown.is_empty()
            && (restart_floor..=plane.epoch).contains(&adopted.epoch)
            && adopted.read_body == *body;
        Ok((!sealed).then(|| Observed::record(name, read.pick.sequence)))
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

    /// Each guard against an owed write cut pauses the seal alone: the owed
    /// record at the start of the tick, and a raise that the lease deferred.
    #[test]
    fn each_owed_write_cut_guard_pauses_alone() {
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

    /// The D4 rows that the gated destination root and write floor show.
    #[test]
    fn each_destination_rise_restarts_the_binding_it_moves() {
        let held = header();
        let binding = |header: Option<DissolveHeader>| header.map(|header| header.binding);
        let was = held.binding;

        let same = restarted(&held, 3, 2, 5).expect("no change");
        assert!(same.copy_started, "the first seal tick marks the copy");
        assert_eq!(same.binding, was);
        assert_eq!(
            binding(restarted(&held, 4, 2, 5)),
            Some(DissolveBinding {
                read_epoch: 4,
                restart_floor: 4,
                ..was
            }),
            "a read rise seals each node below it again"
        );
        assert_eq!(
            binding(restarted(&held, 4, 3, 5)),
            Some(DissolveBinding {
                read_epoch: 4,
                restart_floor: 4,
                base_cut: 3,
                ..was
            }),
            "an owner cut moves the cut baseline too"
        );
        assert_eq!(
            binding(restarted(&held, 3, 3, 5)),
            Some(DissolveBinding { base_cut: 3, ..was }),
            "a cut rise with no read rise keeps the read epoch and the floor"
        );
        assert_eq!(
            binding(restarted(&held, 3, 2, 6)),
            Some(DissolveBinding {
                write_epoch: 6,
                ..was
            }),
            "a write rise keeps the read binding"
        );
        assert_eq!(
            binding(restarted(&held, 4, 3, 6)),
            Some(DissolveBinding {
                read_epoch: 4,
                restart_floor: 4,
                base_cut: 3,
                write_epoch: 6,
                ..was
            }),
            "a read rise and a write rise in one write"
        );
        for (epoch, cut_epoch, write_epoch) in [(2, 2, 5), (3, 1, 5), (3, 2, 4)] {
            assert!(
                restarted(&held, epoch, cut_epoch, write_epoch).is_none(),
                "a read that lags the header waits"
            );
        }
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
        let index = rows
            .iter()
            .zip(0u32..)
            .map(|(row, at)| (row.old, at))
            .collect();
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
        let index = rows
            .iter()
            .zip(0u32..)
            .map(|(row, at)| (row.old, at))
            .collect();
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
}
