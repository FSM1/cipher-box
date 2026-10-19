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
//! ([`PutMark::SignedDurable`](crate::net::publish::PutMark)). A relink
//! publish signs above that mark, so no retry signs other bytes at a sequence
//! that this device signed. Each tick reads the gated parent first: a parent
//! that names neither root parks the entry once a relink was sent, and a
//! parked entry keeps its copy. With no relink sent, the copy is this
//! device's alone, and its names retire (ADR 0077, "Rotation primitives").

use core::cell::Cell;
use std::collections::BTreeSet;

use cipherbox_core::ipns::{IpnsName, IpnsRecord, VerifiedRecord};
use cipherbox_core::seal::{ChildRef, PreservedFields};

use super::super::{Drain, DrainScope, Pass, ScopeEnd, folder_state, take_tick_read};
use super::seal::{Destination, SealFault, restarted};
use super::{NotDriven, cut_epoch_of, cut_overtaken};
use crate::facade::{NodeId, emit_trust_violation};
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

/// The floor-store prefix of a relink mark.
const RELINK_MARK_PREFIX: &[u8] = b"dissolve-relink/";

/// The floor-store key of the relink mark of the dissolve of `source_root`
/// at the parent name `name`: the highest sequence a relink publish signed
/// there.
fn relink_mark_key(source_root: NodeId, name: &[u8]) -> Vec<u8> {
    [RELINK_MARK_PREFIX, &source_root.0, name].concat()
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

/// What the gated relink parent names.
enum ParentNames {
    /// The copy's root, and not the source root.
    Copy,
    /// The source root, and not the copy's root.
    Source,
    /// Neither root.
    Neither,
    /// Both roots.
    Both,
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
            let manifest = self.final_records(owner, end, header, scope, left).await?;
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
    /// scope pointer. An absent pointer gives no EOL.
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
        match consult
            .read(
                &self.seams.transport,
                &end.floors(&self.seams.floors),
                &scope.scope_id.0,
            )
            .await
        {
            Ok(Some(read)) => {
                let (_, eol) =
                    signed_eol(&pointer_name, &read.record_bytes).ok_or(SealFault::Unanswered)?;
                hold_until = hold_until.min(eol);
            }
            Ok(None) => {}
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
    /// `left`. A parked entry waits.
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
                if header.step == DissolveStep::Relink && !header.parked =>
            {
                header
            }
            _ => return,
        };
        let Some(hold) = self.cells.dissolve.hold(root) else {
            return;
        };
        let _ = self
            .relink_tick(owner, ends, journal, &hold, header, left)
            .await;
    }

    /// One tick of the relink: read the gated parent under the bound
    /// destination, then act on what it names.
    async fn relink_tick(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: DissolveHeader,
        left: &Cell<usize>,
    ) -> Result<(), NotDriven> {
        let binding = header.binding;
        let target = self
            .destination_of(owner, ends, header.relink_parent)
            .ok_or(NotDriven)?;
        // The copy seals under the bound destination, and no rebind comes
        // after the seal.
        if (target.chain[0].root, target.write.root) != (binding.read_scope, binding.write_scope) {
            return Err(NotDriven);
        }
        let floors = self.guards_hold(&target).await.ok_or(NotDriven)?;
        let dest = *target.chain[0];
        let scope = DrainScope {
            source: dest,
            destination: None,
            ..*owner
        };
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
            ParentNames::Copy => {
                let mut next = header.clone();
                next.step = DissolveStep::Unindex;
                Ok(journal.commit(hold, Some(&header), &next).await?)
            }
            ParentNames::Source => {
                if !self
                    .keeps_binding(owner, &header, &target, &floors, &pass, left)
                    .await
                {
                    return Err(NotDriven);
                }
                self.relink(&scope, journal, hold, header, pass).await
            }
            ParentNames::Neither if !header.relink_sent => {
                self.forsake(journal, hold, &header).await
            }
            ParentNames::Neither | ParentNames::Both => self.park(journal, hold, &header).await,
        }
    }

    /// Whether the copy still stands at the names and under the floors that
    /// `header` binds: no owner cut of the destination read scope and no
    /// write cut of its write scope since the seal (ADR 0077 D4). A grantee
    /// rise keeps the copy, which the lazy wave carries after the relink.
    async fn keeps_binding(
        &self,
        owner: &DrainScope<'_>,
        header: &DissolveHeader,
        target: &Destination<'_, '_>,
        floors: &[u64],
        pass: &Pass,
        left: &Cell<usize>,
    ) -> bool {
        let dest = target.chain[0];
        let Some(write_floor) = target
            .chain
            .iter()
            .zip(floors)
            .find_map(|(end, floor)| (end.root == target.write.root).then_some(*floor))
        else {
            return false;
        };
        let Ok(root) = pass.folder(dest.root) else {
            return false;
        };
        let cut_epoch = root
            .commitment
            .as_ref()
            .map_or(0, |commitment| commitment.cut_epoch);
        let Ok(vouched) = self.vouched_read_epoch(owner, dest, left).await else {
            return false;
        };
        let was = header.binding;
        restarted(header, pass.epoch, cut_epoch, vouched, write_floor).is_some_and(|next| {
            DissolveBinding {
                read_epoch: was.read_epoch,
                ..next.binding
            } == was
        })
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
    /// root. The header holds `relink_sent` and the parent name first.
    async fn relink(
        &self,
        scope: &DrainScope<'_>,
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: DissolveHeader,
        mut pass: Pass,
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
        let header = if header.relink_sent && header.relink_names.contains(&name) {
            header
        } else {
            if header.relink_names.len() >= MAX_RELINK_NAMES {
                return self.park(journal, hold, &header).await;
            }
            let mut sent = header.clone();
            sent.relink_sent = true;
            if !sent.relink_names.contains(&name) {
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
        let key = relink_mark_key(source, &name);
        self.publish_folder_marked(scope, &mut pass, parent, modified_at, None, Some(&key))
            .await
            .map_err(|_| NotDriven)?;
        let mut next = header.clone();
        next.step = DissolveStep::Unindex;
        Ok(journal.commit(hold, Some(&header), &next).await?)
    }

    /// No relink left this device, and the parent names neither root: retire
    /// each name the copy published at, then drop the entry.
    async fn forsake(
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

    /// Mark the entry parked: its copy stays, and nothing retires.
    async fn park(
        &self,
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &DissolveHeader,
    ) -> Result<(), NotDriven> {
        let mut parked = header.clone();
        parked.parked = true;
        Ok(journal.commit(hold, Some(header), &parked).await?)
    }
}
