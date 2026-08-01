//! The focus-window folder refresh: the read leg that renders a folder **below**
//! the scope root on a device that did not author it (blueprint/engine.md
//! "Sync core: focus-window tick").
//!
//! The vault-pointer leg lifts the root's direct children only, and the drain
//! only ever repaints folders this device published itself. Everything deeper
//! comes from here: each folder the focus window names resolves its own record
//! cache-first, passes the [`ChildAdopter`] gate on this device's floors, and
//! merges into the base through [`project_folder`] — the same merge model the
//! root leg uses, one level down. No new crypto and no new seam.

use core::cell::RefCell;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::ReadBody;
use zeroize::Zeroizing;

use super::child::ChildAdopter;
use super::resolve::{ResolveOutcome, resolve};
use crate::content::Gateway;
use crate::facade::{NodeId, NodeKind};
use crate::gate::Adopted;
use crate::seams::{FloorStore, Http, RecordTransport, SnapshotCache};
use crate::sync::model::Snapshot;
use crate::sync::project::project_folder;

/// What one focus-window folder pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct FolderRefreshReport {
    /// The folders whose gate-passing body merged into the base. The caller
    /// stamps these against its own clock — this module reads no time source
    /// (the determinism law).
    pub(crate) refreshed: Vec<NodeId>,
    /// Whether any merge actually changed the base, so the caller emits
    /// `SnapshotUpdated` on a real change and stays quiet otherwise.
    pub(crate) changed: bool,
}

/// The focus-window folder refresh over one owned scope's read material.
/// Borrows the content/record seams from the live session; the scope read seed
/// stays borrowed, so this pass zeroizes nothing the caller owns.
pub(crate) struct FolderRefresh<'a, T, S, H, F> {
    pub(crate) transport: &'a T,
    pub(crate) snapshot_cache: &'a S,
    pub(crate) http: &'a H,
    pub(crate) floors: &'a F,
    pub(crate) gateway: &'a Gateway,
    /// The gate-passing base snapshot, merged into in place.
    pub(crate) base: &'a RefCell<Snapshot>,
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
    /// Refresh `folders` in order, merging each gate-passing body into the base.
    /// Every failure mode is per-folder and non-fatal: an unresolvable record is
    /// availability staleness and a gate rejection is fail-closed — both leave
    /// last-known-good rendering and neither stops the pass.
    pub(crate) async fn run(&self, folders: &[NodeId]) -> FolderRefreshReport {
        let mut report = FolderRefreshReport::default();
        for folder in folders {
            if let Some(adopted) = self.adopt(*folder).await {
                let ReadBody::Folder {
                    modified_at,
                    children,
                    ..
                } = &adopted.read_body
                else {
                    // The parent's child ref said folder: a sealed file body is
                    // a kind transplant, fail-closed.
                    continue;
                };
                report.changed |= project_folder(
                    &mut self.base.borrow_mut(),
                    *folder,
                    children,
                    adopted.sequence,
                    *modified_at,
                );
                report.refreshed.push(*folder);
            }
        }
        report
    }

    /// One folder's cache-first gated resolve: the child gate on a strictly
    /// newer record, and an at-floor re-open of the current or cached bytes so a
    /// process that starts over durable floors still renders (the same two-step
    /// [`Engine::read_content`](crate::Engine::read_content) walks for a file).
    async fn adopt(&self, folder: NodeId) -> Option<Adopted> {
        let name = self.folder_name(folder)?;
        let adopter = ChildAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            self.scope_id,
            self.scope_read_seed.clone(),
            folder.0,
        );
        let resolved = resolve(self.transport, self.snapshot_cache, &adopter, &name)
            .await
            .ok()?;
        let record_bytes = match resolved.outcome {
            ResolveOutcome::Adopted(adopted) => return Some(adopted),
            ResolveOutcome::TrustViolation(_) => return None,
            ResolveOutcome::Current { record_bytes } => record_bytes,
            ResolveOutcome::NoUpdate => resolved.last_known_good?,
        };
        adopter.open_at_floor(&name, &record_bytes).await.ok()
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
        let name = meta.ipns_name.as_deref()?;
        IpnsName::parse(core::str::from_utf8(name).ok()?).ok()
    }
}
