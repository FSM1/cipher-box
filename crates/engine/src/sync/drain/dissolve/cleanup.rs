//! The retire and the hold step of a dissolve (ADR 0077 D1; blueprint/api.md
//! "Pin/name registry").
//!
//! Once the gated root of the bound read scope shows the index removal, the
//! old names of the map retire one page a tick, then each name that the copy
//! published at and no row uses under the bound write scope, unless the link
//! proof kept every copy name or the bound write scope no longer derives
//! them. The final records of each cut scope resolve until its own
//! `hold_until`, and then retire.

use core::cell::Cell;

use super::super::{Drain, DrainScope, ScopeEnd, take_tick_read};
use super::{NotDriven, cut_epoch_of};
use crate::facade::{Event, NodeId, OwedWorkClass};
use crate::gate::floor;
use crate::net::liveness::HeldKey;
use crate::net::retire::retire;
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SnapshotCache, StagingStore,
};
use crate::sync::dissolve_journal::{
    DissolveHeader, DissolveHold, DissolveJournal, DissolveStep, HeaderSlot,
};

/// The `RotationWorkOwed` detail of a retire step whose bound read scope no
/// longer stands.
const DISSOLVE_READ_SCOPE_GONE: &str = "dissolve-read-scope-gone";

/// Each name of `names` as a string, or `None` when one is not UTF-8.
fn utf8<'n>(names: impl IntoIterator<Item = &'n Vec<u8>>) -> Option<Vec<String>> {
    names
        .into_iter()
        .map(|name| String::from_utf8(name.clone()).ok())
        .collect()
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
    /// Drive the retire or the hold step of the entry at `root` within the
    /// reads of `left`.
    pub(super) async fn drive_cleanup(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        root: NodeId,
        left: &Cell<usize>,
    ) {
        let header = match journal.header(root).await {
            Ok(HeaderSlot::Own(header)) if header.step >= DissolveStep::Retire => header,
            _ => return,
        };
        let Some(hold) = self.cells.dissolve.hold(root) else {
            return;
        };
        let _ = if header.step == DissolveStep::Retire {
            self.retire_tick(owner, ends, journal, &hold, &header, left)
                .await
        } else {
            self.hold_tick(ends, journal, &hold, &header).await
        };
    }

    /// One tick of the retire step: one map page, else one name log page,
    /// else the commit at the hold step. Each runs only while the bound read
    /// scope stands, its gated root names no cut scope in its index, and the
    /// write floors read (ADR 0041 D3). A bound read scope that no longer
    /// stands stops the entry, with one event.
    async fn retire_tick(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &DissolveHeader,
        left: &Cell<usize>,
    ) -> Result<(), NotDriven> {
        let source = header.scopes[0].scope_id;
        let bound = header.binding;
        // A tick that holds no end on the path can be one failed seam read,
        // so it waits with no event.
        let target = self
            .destination_of(owner, ends, bound.read_scope)
            .ok_or(NotDriven)?;
        if target.chain[0].root != bound.read_scope {
            if self.cells.dissolve.note_retire_stopped(source) {
                let _ = self.seams.events.unbounded_send(Event::RotationWorkOwed {
                    scope_root: source,
                    detail: DISSOLVE_READ_SCOPE_GONE.to_owned(),
                    retryable: false,
                    class: OwedWorkClass::Capability,
                });
            }
            return Err(NotDriven);
        }
        let dest = target.chain[0];
        if !take_tick_read(left) {
            return Err(NotDriven);
        }
        let (_, envelope) = self
            .dissolve_root::<()>(owner, dest)
            .await
            .map_err(|_| NotDriven)?;
        let index = self
            .gated_index(dest, &envelope)
            .await
            .map_err(|_| NotDriven)?;
        if header
            .scopes
            .iter()
            .any(|scope| index.contains(&scope.scope_id))
        {
            return Err(NotDriven);
        }
        let floors = self.guards_hold(&target).await.ok_or(NotDriven)?;
        let pages = journal.map(source, header).await?;
        if let Some(page) = pages.get(usize::from(header.retire_cursor)) {
            // The root name of each cut scope is a final record, which the
            // hold step retires.
            let rows = page
                .rows
                .iter()
                .filter(|row| cut_epoch_of(header, row.old).is_none());
            let names = utf8(rows.clone().map(|row| &row.old_name)).ok_or(NotDriven)?;
            retire(&self.seams.api, &names)
                .await
                .map_err(|_| NotDriven)?;
            for row in rows {
                self.cells
                    .held
                    .borrow_mut()
                    .remove(&HeldKey::Node(row.old.0));
            }
            let mut next = header.clone();
            next.retire_cursor += 1;
            return Ok(journal.commit(hold, Some(header), &next).await?);
        }
        if let Some(page) = journal.name_log(source).await?.first() {
            // After a write cut of the bound write scope, the logged names are
            // no longer the ones that it derives, so none is proved vacated.
            let vacates = !header.keep_names
                && target.write.root == bound.write_scope
                && target.chain.iter().zip(&floors).any(|(end, floor)| {
                    end.root == bound.write_scope && *floor == bound.write_epoch
                });
            let vacated = page
                .entries
                .iter()
                .filter(|entry| {
                    vacates && dest.write_name(&entry.id.0).as_str().as_bytes() != entry.name
                })
                .map(|entry| &entry.name);
            let names = utf8(vacated).ok_or(NotDriven)?;
            if !names.is_empty() {
                retire(&self.seams.api, &names)
                    .await
                    .map_err(|_| NotDriven)?;
            }
            return Ok(journal.drop_log_page(hold, header, page.index).await?);
        }
        let mut next = header.clone();
        next.step = DissolveStep::Hold;
        next.keep_names = false;
        next.map_pages = 0;
        next.rows = 0;
        next.retire_cursor = 0;
        journal.commit(hold, Some(header), &next).await?;
        Ok(journal.drop_uncounted_pages(hold, &next).await?)
    }

    /// One tick of the hold step: the final records of each cut scope whose
    /// `hold_until` the scheduler clock passed retire, after a floor read of
    /// their names. The entry goes when every scope retired.
    async fn hold_tick(
        &self,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &DissolveHeader,
    ) -> Result<(), NotDriven> {
        // The vault root end stands in each session, whatever became of the
        // destination over the term.
        let vault_root = self.cells.base.borrow().root;
        let floors = ends
            .iter()
            .find(|end| end.root == vault_root)
            .ok_or(NotDriven)?
            .floors(&self.seams.floors);
        let now = self.seams.scheduler.now().0;
        let mut next = header.clone();
        for scope in &mut next.scopes {
            let Some(manifest) = scope.manifest.as_mut() else {
                return Err(NotDriven);
            };
            if manifest.retired || now < manifest.hold_until {
                continue;
            }
            for name in [&manifest.pointer_name, &manifest.final_root_name] {
                floor::sequence_floor(&floors, name)
                    .await
                    .map_err(|_| NotDriven)?;
            }
            let names = utf8([
                &manifest.pointer_name,
                &manifest.final_root_name,
                &manifest.head_cid,
            ])
            .ok_or(NotDriven)?;
            retire(&self.seams.api, &names)
                .await
                .map_err(|_| NotDriven)?;
            manifest.retired = true;
        }
        if next.scopes.iter().all(|scope| {
            scope
                .manifest
                .as_ref()
                .is_some_and(|manifest| manifest.retired)
        }) {
            return Ok(journal.drop_entry(hold, header).await?);
        }
        if next != *header {
            journal.commit(hold, Some(header), &next).await?;
        }
        Ok(())
    }
}
