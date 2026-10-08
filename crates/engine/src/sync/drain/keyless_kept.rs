//! The read that tells a kept op under a keyless scope that the name wave
//! carried from one that it lost (ADR 0069 D3). A revoked or downgraded party
//! holds no write seed for the moved tree, but its bookmark can hold the scope
//! pointer name, and the pointer read key opens the re-point object there.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::suite::ecdsa::EcdsaVerifier;

use super::{Drain, DrainScope, lists_version, place_in};
use crate::facade::{NodeId, emit_trust_violation};
use crate::grants::grafted::FloorNamespace;
use crate::grants::link_read::held_scope_pointer;
use crate::grants::received_status::grafted_root_name;
use crate::grants::{ReceivedShareStore, StagingReceivedShareStore};
use crate::net::{FolderRefresh, FolderRefreshReport, GraftedLeg, PointerConsultError};
use crate::scope_seeds::{SeedFloor, StampedSeed, current_seed};
use crate::seams::{
    CredentialStore, FloorStore, Http, OpId, RecordTransport, Scheduler, SharerScopedFloorStore,
    SnapshotCache, StagingStore,
};
use crate::sync::kept_op::{KeptOps, KeptOutcome, KeptResult, kept_outcome, live_head, live_place};
use crate::sync::op::{Op, OpKind};
use crate::sync::refresh::RefreshVerdict;
use crate::sync::tick::ResolveMode;

/// The moved root of one keyless scope, as its scope pointer vouches for it,
/// with what a read below it runs under.
pub(super) struct MovedRoot {
    name: IpnsName,
    /// The write-epoch floor the pointer consult left in force.
    write_epoch: u64,
    namespace: FloorNamespace,
    seed: StampedSeed,
}

/// The moved roots one publish has read, by scope root. `None` for a scope
/// whose moved tree this device cannot read.
pub(super) type MovedRoots = BTreeMap<NodeId, Option<MovedRoot>>;

type MovedRefresh<'r, T, S, H, F> = FolderRefresh<'r, T, S, H, SharerScopedFloorStore<'r, F>>;

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
    /// Whether the moved tree of the keyless scope at `root` shows the kept
    /// op ([`Self::moved_outcome`]). Such an op leaves with no notice. `false`
    /// when the bookmark holds no scope pointer name or a read cannot tell,
    /// and the op takes the keyless charge.
    pub(super) async fn moved_tree_decides(
        &self,
        scope: &DrainScope<'_>,
        roots: &mut MovedRoots,
        kept: &KeptOps,
        (op_id, op): (OpId, &Op),
        root: NodeId,
    ) -> bool {
        if let Entry::Vacant(unread) = roots.entry(root) {
            unread.insert(self.moved_root(scope, root).await);
        }
        let Some(Some(moved)) = roots.get(&root) else {
            return false;
        };
        // The cut set lands before the wave and its re-point: a pointer at
        // no later write epoch than the op's can still name the old tree.
        if kept
            .write_epoch(op_id)
            .is_none_or(|noted| moved.write_epoch <= noted)
        {
            return false;
        }
        let floors = moved.namespace.view(&self.seams.floors);
        let scope_roots = self.cells.bookmarked_scope_roots.borrow().clone();
        let refresh = FolderRefresh {
            transport: &self.seams.transport,
            snapshot_cache: &self.seams.snapshot_cache,
            http: &self.seams.http,
            floors: &floors,
            gateway: &self.seams.gateway,
            base: self.cells.base,
            events: &self.seams.events,
            forks: self.cells.forks,
            scope_id: root.0,
            scope_read_seed: &moved.seed.seed,
            seed_stamp: Some(moved.seed.stamp),
            scope_root_name: Some(&moved.name),
            plane: Some(GraftedLeg {
                scope_roots: &scope_roots,
                claims: self.cells.grafted_claims,
            }),
            owed_move: None,
            mode: ResolveMode::NoCache,
            observed_at: self.seams.scheduler.now().0,
        };
        self.moved_outcome(&refresh, kept, op_id, op, root)
            .await
            .unwrap_or(false)
    }

    /// The root the scope pointer of `root`'s one bookmark vouches for, once
    /// the base lists the root's children from the record at that name.
    async fn moved_root(&self, scope: &DrainScope<'_>, root: NodeId) -> Option<MovedRoot> {
        let (_, namespace) = scope
            .granted_namespaces
            .iter()
            .find(|(granted, _)| *granted == root)?;
        let namespace = (*namespace)?;
        let floors = namespace.view(&self.seams.floors);
        let shares = StagingReceivedShareStore::new(
            &self.seams.staging,
            scope.enc_secret,
            &self.seams.entropy,
        )
        .load()
        .await
        .ok()?;
        let mut bookmarks = shares.iter().filter(|share| share.scope_id == root.0);
        let (Some(share), None) = (bookmarks.next(), bookmarks.next()) else {
            return None;
        };
        let owner = EcdsaVerifier::from_sec1(&share.sharer_identity_pk)?;
        let pointer = share.scope_pointer_name.as_ref()?;
        let (name, write_epoch) = match held_scope_pointer(
            &self.seams.transport,
            &floors,
            share,
            pointer,
            &owner,
        )
        .await
        {
            Ok(vouched) => vouched?,
            Err(PointerConsultError::Rejected) => {
                emit_trust_violation(
                    &self.seams.events,
                    grafted_root_name(&share.display_name, root).as_str(),
                    "the scope pointer's re-point object was refused",
                );
                return None;
            }
            Err(PointerConsultError::Unavailable) => return None,
        };
        let listed = self.cells.base.borrow().node(root)?.ipns_name.as_deref()
            == Some(name.as_str().as_bytes());
        if !listed {
            return None;
        }
        let seed = current_seed(
            &floors,
            self.cells.scope_read_seeds,
            &root.0,
            SeedFloor::Read,
        )
        .await?;
        Some(MovedRoot {
            name,
            write_epoch,
            namespace,
            seed,
        })
    }

    /// Whether the moved tree decides the op, or `None` when the read cannot
    /// tell. Only a delete reads an absent node as decided (ADR 0069 D6): for
    /// any other kind, absence can be a later delete, a move by the owner, or
    /// a write the wave lost. A rename, a move and a restore are decided only
    /// when the tree shows their own result: with no second apply, another
    /// value cannot tell a later writer from an earlier op of this device that
    /// the wave lost.
    async fn moved_outcome(
        &self,
        refresh: &MovedRefresh<'_, T, S, H, F>,
        kept: &KeptOps,
        op_id: OpId,
        op: &Op,
        root: NodeId,
    ) -> Option<bool> {
        // Whether the base links the op's node under `folder`: `None` when
        // it links the node only elsewhere, which an unread folder can hold.
        let linked = |folder: NodeId| {
            let base = self.cells.base.borrow();
            let links = base.links_ranked(op.target);
            if links.iter().any(|link| link.parent == folder) {
                Some(true)
            } else {
                links.is_empty().then_some(false)
            }
        };
        match &op.kind {
            OpKind::Delete { .. } => {
                // A contested id leaves the base with no read of its own.
                if self
                    .cells
                    .grafted_claims
                    .borrow()
                    .contested()
                    .contains(&op.target.0)
                {
                    return None;
                }
                let parent = kept.parent(op_id)?;
                let seen = self.cells.kept_chains.borrow().get(&op_id).cloned();
                if parent != root
                    && !self
                        .read_moved_folder(refresh, root, parent, seen.as_deref())
                        .await?
                {
                    return Some(true);
                }
                linked(parent).map(|alive| !alive)
            }
            OpKind::Create { parent, .. } => {
                self.reads_moved_folder(refresh, root, *parent).await?;
                linked(*parent).filter(|shown| *shown)
            }
            OpKind::UpdateContent { .. } | OpKind::RestoreVersion { .. } => {
                // The file's own record shows the op, so a root listing only
                // names the file here.
                let folder = self.cells.base.borrow().parent_of(op.target)?;
                if folder != root {
                    self.reads_moved_folder(refresh, root, folder).await?;
                }
                linked(folder).filter(|shown| *shown)?;
                let mut report = FolderRefreshReport::reconciled();
                let versions = refresh.read_file(op.target, &mut report).await?;
                match kept.result(op_id) {
                    Some(result) => {
                        Some(kept_outcome(result, live_head(&versions)) == KeptOutcome::Landed)
                    }
                    None => Some(lists_version(&versions, op.staged_content()?)),
                }
            }
            OpKind::Rename { .. } | OpKind::Move { .. } | OpKind::Relink { .. } => {
                let parent = kept.parent(op_id)?;
                let result = kept.result(op_id)?;
                let mut folders = vec![parent];
                if let KeptResult::Move { to, .. } = result
                    && *to != parent
                {
                    folders.push(*to);
                }
                for folder in folders {
                    self.reads_moved_folder(refresh, root, folder).await?;
                }
                let place = place_in(&self.cells.base.borrow(), op.target);
                Some(
                    kept_outcome(result, live_place(result, parent, place.as_ref()))
                        == KeptOutcome::Landed,
                )
            }
            _ => None,
        }
    }

    /// [`Self::read_moved_folder`], where a folder the moved tree no longer
    /// names cannot tell.
    async fn reads_moved_folder(
        &self,
        refresh: &MovedRefresh<'_, T, S, H, F>,
        root: NodeId,
        folder: NodeId,
    ) -> Option<()> {
        self.read_moved_folder(refresh, root, folder, None)
            .await?
            .then_some(())
    }

    /// Read `folder` and each folder between it and `root` in the moved tree,
    /// root first. Each name comes from the listing just read, so no read
    /// lands on the old tree. A folder the base no longer holds is placed by
    /// the chain this session saw it under ([`DrainCells::kept_chains`]).
    /// `Some(false)` when the healed root listing or a listing just read no
    /// longer names the next folder, and `None` when a folder's record does
    /// not pass the gate on this read, the folder cannot be placed below
    /// `root`, or `folder` is `root`, whose listing no read of this pass gated.
    async fn read_moved_folder(
        &self,
        refresh: &MovedRefresh<'_, T, S, H, F>,
        root: NodeId,
        folder: NodeId,
        seen: Option<&[NodeId]>,
    ) -> Option<bool> {
        if folder == root {
            return None;
        }
        let chain = {
            let base = self.cells.base.borrow();
            let mut chain = if base.contains(folder) {
                let mut chain = base.ancestors(folder);
                chain.reverse();
                chain.push(folder);
                chain
            } else {
                seen?.to_vec()
            };
            let at = chain.iter().position(|node| *node == root)?;
            chain.drain(..=at);
            chain
        };
        let mut above = root;
        for node in chain {
            {
                let base = self.cells.base.borrow();
                if !base.contains(node) {
                    let contested = self
                        .cells
                        .grafted_claims
                        .borrow()
                        .contested()
                        .contains(&node.0);
                    return (!contested).then_some(false);
                }
                if !base
                    .links_ranked(node)
                    .iter()
                    .any(|link| link.parent == above)
                {
                    return None;
                }
            }
            let mut report = FolderRefreshReport::reconciled();
            let gated = refresh.read_folder(node, &mut report).await;
            if !gated || report.verdict != RefreshVerdict::Reconciled || report.unread {
                return None;
            }
            above = node;
        }
        Some(true)
    }
}
