//! The relink step of a dissolve (ADR 0077 D1): the relink parent names the
//! copy's root in place of the source root.
//!
//! A confirmed seal first records the final records of each cut scope, from
//! gated reads: the pointer name, the final root name, the head CID, and the
//! time until which each of them resolves. That time is one EOL term from
//! the scope's `cut_time` at least.
//!
//! The header holds `relink_sent` and the parent name before the publish
//! call, and the floor store holds the signed sequence before the PUT
//! ([`PutMark::SignedDurable`](crate::net::publish::PutMark)): at a mark of
//! the entry, and at a mark of the parent name that every entry shares. A
//! relink publish signs above both, so no relink publish signs other bytes at
//! a sequence that a relink publish of this device signed. Each tick reads
//! the gated parent first: a parent that names neither root parks the entry
//! once a relink was sent, and a parked entry keeps its copy. With no relink
//! sent, the copy is this device's alone, and its names retire (ADR 0077,
//! "Rotation primitives"), and a moved destination seals again (ADR 0077 D4).

use core::cell::Cell;
use std::collections::BTreeSet;

use cipherbox_core::ipns::{IpnsName, IpnsRecord, VerifiedRecord};
use cipherbox_core::seal::{ChildRef, PreservedFields};

use super::super::{Drain, DrainScope, Pass, ScopeEnd, folder_state, take_tick_read};
use super::seal::{Destination, SealFault, restarted};
use super::{CLOSE_READS_PER_SCOPE, NotDriven, ReadShare, cut_epoch_of, cut_overtaken};
use crate::facade::{Event, NodeId, OwedWorkClass, emit_trust_violation};
use crate::gate::floor;
use crate::net::eol::{EOL_WINDOW, remaining_millis};
use crate::net::publish::head_cid_from_value;
use crate::net::retire::retire;
use crate::net::{PointerConsult, PointerConsultError};
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SnapshotCache, StagingStore,
    UnixMillis,
};
use crate::sync::dissolve_journal::{
    DissolveBinding, DissolveHeader, DissolveHold, DissolveJournal, DissolveStep, DissolvedScope,
    HeaderSlot, MAX_RELINK_NAMES, Manifest,
};
use crate::sync::drain::walker::ReadFault;
use crate::sync::pointer::POINTER_PAYLOAD_VERSION;

/// The floor-store prefix of the relink mark of one entry.
const RELINK_MARK_PREFIX: &[u8] = b"dissolve-relink/";

/// The detail of the owed work that a lost scope pointer holds.
const DISSOLVE_POINTER_LOST: &str = "dissolve-scope-pointer-lost";

/// The `RotationWorkOwed` detail of an entry parked because its relink parent
/// left the bound write scope.
const DISSOLVE_RELINK_PARENT_MOVED: &str = "dissolve-relink-parent-moved";

/// The floor-store keys of the relink marks of the dissolve of `source_root`
/// at the parent name `name`: the mark of the entry, then the mark of the
/// name. Each holds the highest sequence that a relink publish signed there.
pub(super) fn relink_mark_keys(source_root: NodeId, name: &[u8]) -> [Vec<u8>; 2] {
    [
        [RELINK_MARK_PREFIX, &source_root.0, name].concat(),
        floor::relink_parent_mark_key(name),
    ]
}

/// The time, in scheduler milliseconds, until which a final record cut at
/// `cut_time` must resolve: one EOL term, less the second that the signed
/// EOL drops.
fn term_end(cut_time: u64) -> u64 {
    let window = u64::try_from(EOL_WINDOW.as_millis()).unwrap_or(u64::MAX);
    cut_time.saturating_add(window).saturating_sub(1_000)
}

/// `bytes`, a record at `name`, verified, and its signed EOL in scheduler
/// milliseconds.
fn signed_eol(name: &IpnsName, bytes: &[u8]) -> Option<(VerifiedRecord, u64)> {
    let record = IpnsRecord::unmarshal(bytes)
        .and_then(|record| record.verify(name))
        .ok()?;
    let eol = remaining_millis(UnixMillis(0), &record.validity)
        .and_then(|eol| u64::try_from(eol).ok())?;
    Some((record, eol))
}

/// Which of the copy's root and the source root the gated relink parent, or
/// the folders of a link proof, name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParentNames {
    /// The copy's root, and not the source root.
    Copy,
    /// The source root, and not the copy's root.
    Source,
    /// Neither root.
    Neither,
    /// Both roots.
    Both,
}

/// Whether the binding `now` that the destination gives moves the copy off
/// the binding `was` of the seal: a change other than a rise of the read
/// epoch, which a grantee rise moves alone.
fn moved(was: DissolveBinding, now: DissolveBinding) -> bool {
    DissolveBinding {
        read_epoch: was.read_epoch,
        ..now
    } != was
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
    /// Close a confirmed seal: read the final records of each cut scope, then
    /// commit `header` at the relink step with the manifest of each. A scope
    /// whose final records resolve for less than one term from its
    /// `cut_time` is noted for the owner pass to publish again, and the seal
    /// waits.
    pub(super) async fn close_seal(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &DissolveHeader,
        left: &Cell<usize>,
    ) -> Result<(), SealFault> {
        let mut next = header.clone();
        let mut short = BTreeSet::new();
        for scope in &mut next.scopes {
            let end = ends
                .iter()
                .find(|end| end.root == scope.scope_id)
                .ok_or(SealFault::Unanswered)?;
            let share =
                ReadShare::take(left, CLOSE_READS_PER_SCOPE).ok_or(SealFault::Unanswered)?;
            let manifest = self
                .final_records(owner, end, header, scope, &share.left)
                .await?;
            if manifest.hold_until < term_end(scope.cut_time) {
                short.insert(scope.scope_id);
            }
            scope.manifest = Some(manifest);
        }
        if !short.is_empty() {
            self.cells
                .dissolve
                .note_short_terms(header.scopes[0].scope_id, short);
            return Err(SealFault::Unanswered);
        }
        next.step = DissolveStep::Relink;
        journal.commit(hold, Some(header), &next).await?;
        Ok(())
    }

    /// The final records of `scope` under `end`, from gated reads: the root,
    /// which must hold no row at the cut epoch of the dissolve, and the
    /// scope pointer. A scope with no pointer and no sequence floor for it
    /// gives the root EOL.
    async fn final_records(
        &self,
        owner: &DrainScope<'_>,
        end: &ScopeEnd<'_>,
        header: &DissolveHeader,
        scope: &DissolvedScope,
        left: &Cell<usize>,
    ) -> Result<Manifest, SealFault> {
        let scope_keys = self.inputs.owner_pointers.ok_or(SealFault::Unanswered)?;
        if !take_tick_read(left) {
            return Err(SealFault::Unanswered);
        }
        let (root, _) = self.dissolve_root::<()>(owner, end).await?;
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
        let (record, mut hold_until) =
            signed_eol(end.root_name, &root.state.record).ok_or(SealFault::Unanswered)?;
        let head_cid = head_cid_from_value(&record.value).ok_or(SealFault::Unanswered)?;
        if !take_tick_read(left) {
            return Err(SealFault::Unanswered);
        }
        let pointer_name = scope_keys.pointer_name(&scope.scope_id.0);
        let consult = PointerConsult {
            scope_keys,
            owner_identity: owner.owner_identity,
            payload_version: POINTER_PAYLOAD_VERSION,
        };
        let floors = end.floors(&self.seams.floors);
        match consult
            .read(&self.seams.transport, &floors, &scope.scope_id.0)
            .await
        {
            Ok(Some(read)) => {
                let (_, eol) =
                    signed_eol(&pointer_name, &read.record_bytes).ok_or(SealFault::Unanswered)?;
                hold_until = hold_until.min(eol);
                self.cells.dissolve.found_pointer(scope.scope_id);
            }
            // A pointer that this device signed and that no endpoint serves
            // proves no term. Its repair needs an owner-vouched read floor,
            // so the close waits for the owner.
            Ok(None) => {
                if floor::sequence_floor(&floors, pointer_name.as_str().as_bytes())
                    .await
                    .map_err(|_| SealFault::Unanswered)?
                    .is_some()
                {
                    if self.cells.dissolve.note_lost_pointer(scope.scope_id) {
                        let _ = self.seams.events.unbounded_send(Event::RotationWorkOwed {
                            scope_root: scope.scope_id,
                            detail: DISSOLVE_POINTER_LOST.to_owned(),
                            retryable: true,
                            class: OwedWorkClass::Availability,
                        });
                    }
                    return Err(SealFault::Unanswered);
                }
            }
            Err(PointerConsultError::Unavailable) => return Err(SealFault::Unanswered),
            Err(PointerConsultError::Rejected) => {
                emit_trust_violation(
                    &self.seams.events,
                    pointer_name.as_str(),
                    "dissolve-scope-pointer-refused",
                );
                return Err(SealFault::Refused);
            }
        }
        Ok(Manifest {
            hold_until,
            pointer_name: pointer_name.as_str().as_bytes().to_vec(),
            final_root_name: end.root_name.as_str().as_bytes().to_vec(),
            head_cid: head_cid.into_bytes(),
            retired: false,
        })
    }

    /// Drive the relink step of the entry at `root` within the reads of
    /// `left`. An entry that parked reads its parent again in the next
    /// session.
    pub(super) async fn drive_relink(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        root: NodeId,
        left: &Cell<usize>,
    ) {
        let header = match journal.header(root).await {
            Ok(HeaderSlot::Own(header))
                if header.step == DissolveStep::Relink
                    && !(header.parked && self.cells.dissolve.parked_now(root)) =>
            {
                header
            }
            _ => {
                self.cells.dissolve_proofs.borrow_mut().remove(&root);
                return;
            }
        };
        let Some(hold) = self.cells.dissolve.hold(root) else {
            return;
        };
        let _ = self
            .relink_tick(owner, ends, journal, &hold, header, left)
            .await;
    }

    /// One tick of the relink: read the gated parent under the destination
    /// now, then act on what it names.
    async fn relink_tick(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: DissolveHeader,
        left: &Cell<usize>,
    ) -> Result<(), NotDriven> {
        let target = self
            .destination_of(owner, ends, header.relink_parent)
            .ok_or(NotDriven)?;
        let dest = *target.chain[0];
        let pass = match self.relink_parent(owner, ends, &header, &dest, left).await {
            Ok(pass) => pass,
            Err(ReadFault::Untrusted) if header.relink_sent => {
                return self.park(journal, hold, &header).await;
            }
            Err(_) => return Err(NotDriven),
        };
        let source = header.scopes[0].scope_id;
        let parent = pass.folder(header.relink_parent).map_err(|_| NotDriven)?;
        let names = |node: NodeId| parent.children.iter().any(|child| child.id == node.0);
        let named = match (names(header.new_root), names(source)) {
            (true, false) => ParentNames::Copy,
            (false, true) => ParentNames::Source,
            (false, false) => ParentNames::Neither,
            (true, true) => ParentNames::Both,
        };
        match named {
            ParentNames::Source => {
                self.cells.dissolve_proofs.borrow_mut().remove(&source);
                let floors = self.guards_hold(&target).await.ok_or(NotDriven)?;
                match self
                    .destination_moved(owner, &header, &target, &floors, &pass, left)
                    .await
                {
                    None => Err(NotDriven),
                    Some(true) if header.relink_sent => self.park(journal, hold, &header).await,
                    Some(true) => self.reseal(journal, hold, &header).await,
                    Some(false) => {
                        let scope = DrainScope {
                            source: dest,
                            destination: None,
                            ..*owner
                        };
                        self.relink(&scope, journal, hold, header, pass, &target, &floors)
                            .await
                    }
                }
            }
            ParentNames::Neither if !header.relink_sent => {
                self.forsake(journal, hold, &header).await
            }
            // A parent that names the copy proves no unlink of the source
            // root: another device can link it elsewhere before the relink
            // lands.
            ParentNames::Copy | ParentNames::Neither | ParentNames::Both => {
                // The proof must walk the write scope that the index removal
                // and the retire read, so a parent that left it parks the
                // entry once two ticks agree.
                let bound = header.binding;
                if target.write.root != bound.write_scope {
                    let candidate = (bound.read_scope, target.write.root);
                    let seen =
                        self.cells
                            .dissolve
                            .see_relink_rebind(source, candidate, self.inputs.tick);
                    if !self.rebind_confirmed(bound.read_scope, candidate, seen) {
                        return Err(NotDriven);
                    }
                    self.cells.dissolve_proofs.borrow_mut().remove(&source);
                    // The park commit can fail, so the event keeps its own
                    // session mark.
                    if self.cells.dissolve.note_parent_moved(source) {
                        let _ = self.seams.events.unbounded_send(Event::RotationWorkOwed {
                            scope_root: source,
                            detail: DISSOLVE_RELINK_PARENT_MOVED.to_owned(),
                            retryable: false,
                            class: OwedWorkClass::Capability,
                        });
                    }
                    return self.park(journal, hold, &header).await;
                }
                Box::pin(self.prove(owner, ends, journal, hold, &header, &target, named, left))
                    .await
            }
        }
    }

    /// Whether the destination moved since the seal: another read or write
    /// scope, an owner cut of the read scope, or a write cut of the write
    /// scope (ADR 0077 D4). A grantee rise keeps the copy, which the lazy wave
    /// carries after the relink. `None` while a read lags the header, and
    /// while a sent relink waits to confirm a change of scope.
    async fn destination_moved(
        &self,
        owner: &DrainScope<'_>,
        header: &DissolveHeader,
        target: &Destination<'_, '_>,
        floors: &[u64],
        pass: &Pass,
        left: &Cell<usize>,
    ) -> Option<bool> {
        let was = header.binding;
        let dest = target.chain[0];
        let candidate = (dest.root, target.write.root);
        if candidate != (was.read_scope, was.write_scope) {
            if !header.relink_sent {
                return Some(true);
            }
            // A park holds the entry, so it waits for the confirmation that a
            // rebind of the seal waits for.
            let seen = self.cells.dissolve.see_relink_rebind(
                header.scopes[0].scope_id,
                candidate,
                self.inputs.tick,
            );
            return self
                .rebind_confirmed(was.read_scope, candidate, seen)
                .then_some(true);
        }
        let write_floor = target
            .chain
            .iter()
            .zip(floors)
            .find_map(|(end, floor)| (end.root == target.write.root).then_some(*floor))?;
        let cut_epoch = pass
            .folder(dest.root)
            .ok()?
            .commitment
            .as_ref()
            .map_or(0, |commitment| commitment.cut_epoch);
        let vouched = self.vouched_read_epoch(owner, dest, left).await.ok()?;
        let next = restarted(header, pass.epoch, cut_epoch, vouched, write_floor)?;
        Some(moved(was, next.binding))
    }

    /// A pass over `dest` that holds the relink parent of `header`, read
    /// through the gate from the record plane. A same-sequence fork is
    /// [`ReadFault::Untrusted`].
    async fn relink_parent(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        header: &DissolveHeader,
        dest: &ScopeEnd<'_>,
        left: &Cell<usize>,
    ) -> Result<Pass, ReadFault<()>> {
        if !take_tick_read(left) {
            return Err(ReadFault::Unanswered);
        }
        let (root, _) = self.dissolve_root::<()>(owner, dest).await?;
        let mut pass = Pass {
            root: dest.root,
            epoch: root.epoch,
            history_links: root.history_links,
            second_ratchet: None,
            folders: Vec::new(),
            journalled: Vec::new(),
        };
        pass.insert(dest.root, root.state);
        if header.relink_parent != dest.root {
            if !take_tick_read(left) {
                return Err(ReadFault::Unanswered);
            }
            let loaded = self
                .gated_child(
                    owner,
                    ends,
                    header,
                    dest,
                    pass.anchor(),
                    header.relink_parent,
                )
                .await
                .map_err(|fault| match fault {
                    ReadFault::Untrusted => ReadFault::Untrusted,
                    ReadFault::Unanswered | ReadFault::Fatal(_) => ReadFault::Unanswered,
                })?;
            let state =
                folder_state(&dest.at(pass.epoch), loaded).map_err(|_| ReadFault::Unanswered)?;
            pass.insert(header.relink_parent, state);
        }
        Ok(pass)
    }

    /// Publish the relink parent with the copy's root in place of the source
    /// root, under the write leases of `target`'s chain at `floors`. The
    /// header holds `relink_sent` and the parent name first. A later tick
    /// proves the link.
    #[expect(clippy::too_many_arguments, reason = "one relink publish")]
    async fn relink(
        &self,
        scope: &DrainScope<'_>,
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: DissolveHeader,
        mut pass: Pass,
        target: &Destination<'_, '_>,
        floors: &[u64],
    ) -> Result<(), NotDriven> {
        let source = header.scopes[0].scope_id;
        let parent = header.relink_parent;
        let name = pass
            .folder(parent)
            .map_err(|_| NotDriven)?
            .name
            .as_str()
            .as_bytes()
            .to_vec();
        let _leases = self
            .lease_the_chain(target, floors)
            .await
            .map_err(|_| NotDriven)?;
        let listed = header.relink_names.contains(&name);
        let header = if header.relink_sent && listed && !header.parked {
            header
        } else {
            if !listed && header.relink_names.len() >= MAX_RELINK_NAMES {
                return self.park(journal, hold, &header).await;
            }
            let mut sent = header.clone();
            sent.relink_sent = true;
            sent.parked = false;
            if !listed {
                sent.relink_names.push(name.clone());
            }
            journal.commit(hold, Some(&header), &sent).await?;
            sent
        };
        let copy_name = scope.source.write_name(&header.new_root.0);
        let state = pass.folder_mut(parent).map_err(|_| NotDriven)?;
        for child in &mut state.children {
            if child.id == source.0 {
                *child = ChildRef {
                    id: header.new_root.0,
                    name: child.name.clone(),
                    ipns_name: copy_name.as_str().as_bytes().to_vec(),
                    kind: child.kind,
                    link_counter: child.link_counter,
                    unknown: PreservedFields::new(),
                };
            }
        }
        let modified_at = state.modified_at;
        let keys = relink_mark_keys(source, &name);
        self.publish_folder_marked(scope, &mut pass, parent, modified_at, None, Some(&keys))
            .await
            .map(|_| ())
            .map_err(|_| NotDriven)
    }

    /// No relink left this device, and the parent names neither root: retire
    /// each name the copy published at, then drop the entry.
    pub(super) async fn forsake(
        &self,
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &DissolveHeader,
    ) -> Result<(), NotDriven> {
        let names = journal
            .name_log(header.scopes[0].scope_id)
            .await?
            .into_iter()
            .flat_map(|page| page.entries)
            .map(|entry| String::from_utf8(entry.name).map_err(|_| NotDriven))
            .collect::<Result<Vec<_>, _>>()?;
        if !names.is_empty() {
            retire(&self.seams.api, &names)
                .await
                .map_err(|_| NotDriven)?;
        }
        Ok(journal.drop_entry(hold, header).await?)
    }

    /// No relink left this device, and the destination moved: the entry
    /// goes back to its seal, which binds the destination again and closes
    /// new manifests (ADR 0077 D4).
    async fn reseal(
        &self,
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &DissolveHeader,
    ) -> Result<(), NotDriven> {
        let mut next = header.clone();
        next.step = DissolveStep::Seal;
        next.parked = false;
        for scope in &mut next.scopes {
            scope.manifest = None;
        }
        Ok(journal.commit(hold, Some(header), &next).await?)
    }

    /// Mark the entry parked: its copy stays, and nothing retires.
    pub(super) async fn park(
        &self,
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &DissolveHeader,
    ) -> Result<(), NotDriven> {
        self.cells.dissolve.note_parked(header.scopes[0].scope_id);
        if header.parked {
            return Ok(());
        }
        let mut parked = header.clone();
        parked.parked = true;
        Ok(journal.commit(hold, Some(header), &parked).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> DissolveHeader {
        let binding = DissolveBinding {
            read_scope: NodeId([0x01; 16]),
            read_epoch: 3,
            restart_floor: 3,
            base_cut: 2,
            write_scope: NodeId([0x01; 16]),
            write_epoch: 5,
        };
        DissolveHeader::at_cut(
            NodeId([0x70; 16]),
            NodeId([0x01; 16]),
            binding,
            vec![DissolvedScope::uncut(NodeId([0x50; 16]))],
        )
    }

    /// ADR 0077 D4 before the relink: a grantee rise keeps the copy, and an
    /// owner cut, a pointer rise or a write cut moves it.
    #[test]
    fn only_a_grantee_rise_keeps_the_copy_at_the_relink() {
        let held = header();
        let moves = |epoch, cut_epoch, vouched, write_epoch| {
            let next = restarted(&held, epoch, cut_epoch, vouched, write_epoch).expect("no lag");
            moved(held.binding, next.binding)
        };

        assert!(!moves(3, 2, 3, 5), "no change");
        assert!(!moves(4, 2, 3, 5), "a grantee rise");
        assert!(moves(4, 3, 3, 5), "an owner cut");
        assert!(moves(4, 2, 4, 5), "a pointer rise");
        assert!(moves(3, 2, 3, 6), "a write cut");
    }
}
