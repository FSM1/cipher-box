//! The focus-window folder refresh: the read leg that renders a folder **below**
//! the scope root (blueprint/engine.md "Sync core: focus-window tick").
//!
//! Each folder the window names resolves its own record cache-first through
//! [`resolve_child`], passes the [`ChildAdopter`] gate on this device's floors,
//! and merges into the base with [`project_folder`] — the root leg's merge
//! model, one level down.

use core::cell::RefCell;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::ReadBody;
use futures_channel::mpsc;
use zeroize::Zeroizing;

use super::child::{ChildAdopter, ChildResolveError, resolve_child};
use crate::content::Gateway;
use crate::facade::{Event, NodeId, NodeKind, emit_trust_violation};
use crate::gate::GateError;
use crate::seams::{FloorStore, Http, RecordTransport, SnapshotCache};
use crate::sync::model::Snapshot;
use crate::sync::project::project_folder;

/// The focus-window folder refresh over one owned scope's read material.
/// Borrows the content/record seams from the live session; the caller's read
/// seed is borrowed and never zeroized here.
pub(crate) struct FolderRefresh<'a, T, S, H, F> {
    pub(crate) transport: &'a T,
    pub(crate) snapshot_cache: &'a S,
    pub(crate) http: &'a H,
    pub(crate) floors: &'a F,
    pub(crate) gateway: &'a Gateway,
    /// The gate-passing base snapshot, merged into in place.
    pub(crate) base: &'a RefCell<Snapshot>,
    /// Where a fail-closed rejection on a focused folder is surfaced.
    pub(crate) events: &'a mpsc::UnboundedSender<Event>,
    /// The scope every focus folder is sealed under — the vault root scope;
    /// granted-subscope focus is a later slice.
    pub(crate) scope_id: [u8; 16],
    pub(crate) scope_read_seed: &'a Zeroizing<[u8; 32]>,
}

impl<T, S, H, F> FolderRefresh<'_, T, S, H, F>
where
    T: RecordTransport,
    S: SnapshotCache,
    H: Http,
    F: FloorStore,
{
    /// Merge each of `folders` into the base, reporting whether the base moved.
    /// They arrive nearest-first; the merge runs root-ward, so a parent that
    /// dropped a child unlinks it before the pass would project into it.
    ///
    /// Every failure is per-folder and non-fatal: an unresolvable record is
    /// availability staleness, a gate rejection is fail-closed and surfaced as
    /// [`Event::AttributableAbuse`], and both leave last-known-good rendering
    /// without stopping the pass.
    pub(crate) async fn run(&self, folders: &[NodeId]) -> bool {
        let mut changed = false;
        for folder in folders.iter().rev() {
            let Some(name) = self.folder_name(*folder) else {
                continue;
            };
            let adopter = ChildAdopter::new(
                self.gateway,
                self.http,
                self.floors,
                self.scope_id,
                self.scope_read_seed.clone(),
                folder.0,
            );
            let adopted =
                match resolve_child(self.transport, self.snapshot_cache, &adopter, &name).await {
                    Ok(adopted) => adopted,
                    // Availability: the base keeps rendering last-known-good.
                    Err(ChildResolveError::Unavailable(_))
                    | Err(ChildResolveError::Gate(GateError::Seam(_))) => continue,
                    Err(ChildResolveError::Gate(GateError::Rejected(rejection))) => {
                        emit_trust_violation(self.events, name.as_str(), &rejection.to_string());
                        continue;
                    }
                };
            let ReadBody::Folder {
                modified_at,
                children,
                ..
            } = &adopted.read_body
            else {
                // The parent's child ref said folder: a sealed file body is a
                // kind transplant, fail-closed.
                emit_trust_violation(
                    self.events,
                    name.as_str(),
                    "sealed file body behind a folder child ref",
                );
                continue;
            };
            changed |= project_folder(
                &mut self.base.borrow_mut(),
                *folder,
                children,
                adopted.sequence,
                *modified_at,
            );
        }
        changed
    }

    /// The folder's write-plane name as its parent's `ChildRef` carried it.
    /// `None` for a node absent from gate-passing state, a non-folder, or a ref
    /// whose bytes are not a canonical IPNS name.
    fn folder_name(&self, folder: NodeId) -> Option<IpnsName> {
        let base = self.base.borrow();
        let meta = base.node(folder)?;
        if meta.kind != NodeKind::Folder {
            return None;
        }
        IpnsName::parse(core::str::from_utf8(meta.ipns_name.as_deref()?).ok()?).ok()
    }
}
