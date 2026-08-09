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
use crate::gate::{GateError, RejectionReason};
use crate::seams::{FloorStore, Http, RecordTransport, SnapshotCache};
use crate::sync::model::Snapshot;
use crate::sync::project::project_folder;
use crate::sync::refresh::RefreshVerdict;
use crate::sync::tick::ResolveMode;

/// What one focus-folder pass did. The verdict is the pass's own read legs, kept
/// separate from the root's so a forced refresh reports every folder it was
/// asked to bring forward rather than the root alone.
pub(crate) struct FolderRefreshReport {
    /// Whether the base moved.
    pub(crate) changed: bool,
    /// The worst verdict any folder leg earned.
    pub(crate) verdict: RefreshVerdict,
}

impl FolderRefreshReport {
    fn fold(&mut self, verdict: RefreshVerdict) {
        self.verdict = self.verdict.worst(verdict);
    }
}

/// What a folder's gate rejection costs the pass, or `None` when it costs it
/// nothing.
///
/// A folder the lazy wave has not swept yet is epoch-lagged (CONTEXT.md): the
/// plane answered and the gate did its job, and only the sweep re-seals it —
/// which is why the sweep alone reads below the epoch stage
/// ([`Strictness::AtOrAboveFloor`](crate::gate::floor::Strictness)). Failing the
/// pass on it would report a *retryable* verdict for a state no retry clears,
/// and would fire on every refresh a user makes while a wave is in flight. It is
/// not abuse either, so nobody is accused. Every other rejection is attributable
/// and fail-closed.
fn rejection_verdict(reason: &RejectionReason) -> Option<RefreshVerdict> {
    match reason {
        RejectionReason::EpochBelowFloor { .. } => None,
        RejectionReason::Trust(_) | RejectionReason::SequenceNotNewer { .. } => {
            Some(RefreshVerdict::Rejected)
        }
    }
}

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
    /// How this pass resolves each folder's record: a manual refresh forces
    /// [`ResolveMode::NoCache`], so an unreachable record is reported as
    /// staleness rather than re-projected from cached bytes.
    pub(crate) mode: ResolveMode,
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
    /// availability staleness, an attributable gate rejection is fail-closed and
    /// surfaced as [`Event::AttributableAbuse`], and both leave last-known-good
    /// rendering without stopping the pass. Each still lands in the report, so
    /// the caller's verdict covers the folders as well as the root.
    pub(crate) async fn run(&self, folders: &[NodeId]) -> FolderRefreshReport {
        let mut report = FolderRefreshReport {
            changed: false,
            verdict: RefreshVerdict::Reconciled,
        };
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
            let adopted = match resolve_child(
                self.transport,
                self.snapshot_cache,
                &adopter,
                &name,
                self.mode,
            )
            .await
            {
                Ok(adopted) => adopted,
                // Availability: the base keeps rendering last-known-good.
                Err(
                    ChildResolveError::Unavailable(_) | ChildResolveError::Gate(GateError::Seam(_)),
                ) => {
                    report.fold(RefreshVerdict::Unreachable);
                    continue;
                }
                Err(ChildResolveError::Gate(GateError::Rejected(rejection))) => {
                    if let Some(verdict) = rejection_verdict(&rejection.reason) {
                        emit_trust_violation(self.events, name.as_str(), rejection);
                        report.fold(verdict);
                    }
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
                report.fold(RefreshVerdict::Rejected);
                continue;
            };
            report.changed |= project_folder(
                &mut self.base.borrow_mut(),
                *folder,
                children,
                adopted.sequence,
                *modified_at,
            );
        }
        report
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_epoch_lagged_folder_costs_the_pass_nothing() {
        assert_eq!(
            rejection_verdict(&RejectionReason::EpochBelowFloor { floor: 5, epoch: 4 }),
            None,
            "the sweep clears epoch lag; no retry of this pass can, so it fails nothing"
        );
        assert_eq!(
            rejection_verdict(&RejectionReason::SequenceNotNewer {
                floor: 5,
                sequence: 4,
            }),
            Some(RefreshVerdict::Rejected),
            "a replay is attributable and fail-closed"
        );
    }
}
