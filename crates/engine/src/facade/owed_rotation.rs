//! Owed rotation work (ADR 0063): the entry an owner command writes before its
//! first publish, and the re-drive that the sync pass and the same command run.
//!
//! Both run on the [`ConversionPass`], the one owner-action surface the tick
//! and a command share, and place each scope through its [`ConversionSites`].

use super::claim_conversion::{ConversionSites, Running};
use super::*;
use crate::grants::resume_owed_interior_move;
use crate::rotation::{NoBound, RotateOnCutError, WriteRotateError, owed_read_cut};
use crate::sync::owed_rotation::{
    EntryBound, OwedEntry, OwedRecordError, OwedRotation, OwedStep, ScopeHold,
};

/// What stopped one owed step: a key-material-free check, and its class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwedStop {
    pub(crate) detail: String,
    pub(crate) class: OwedWorkClass,
    /// The work can never land, so the entry is dropped.
    terminal: bool,
}

impl OwedStop {
    fn of(step: &'static str, error: &EngineError) -> Self {
        let class = OwedWorkClass::of(error);
        let label = match error {
            EngineError::MalformedInput { check } | EngineError::UnsupportedTarget { check } => {
                *check
            }
            _ if class == OwedWorkClass::Trust => "trust-violation",
            _ => "unavailable",
        };
        Self {
            detail: format!("{step}: {label}"),
            class,
            terminal: false,
        }
    }

    /// A post-step of a landed wave that did not run.
    pub(crate) fn of_post_step(error: &EngineError) -> Self {
        Self::of("owed-write-cut", error)
    }

    /// A grant step that stopped after its promotion publish.
    pub(crate) fn of_grant(error: &CreateGrantError) -> Self {
        Self {
            detail: error.check().to_owned(),
            class: OwedWorkClass::of(&EngineError::from_create_grant(error.clone())),
            terminal: false,
        }
    }

    /// Whether a later pass could clear what stopped the step.
    pub(crate) fn retryable(&self) -> bool {
        self.class == OwedWorkClass::Availability
    }

    fn refused(detail: &'static str) -> Self {
        Self {
            detail: detail.to_owned(),
            class: OwedWorkClass::Capability,
            terminal: false,
        }
    }

    /// A step a later pass may find able to land. What stopped it is
    /// writer-authored, so it is never grounds to drop the entry.
    fn pending(detail: &'static str) -> Self {
        Self {
            class: OwedWorkClass::Availability,
            ..Self::refused(detail)
        }
    }

    /// A step whose target is gone, so the work can never land.
    fn abandoned(detail: &'static str) -> Self {
        Self {
            terminal: true,
            ..Self::refused(detail)
        }
    }
}

/// What re-driving a command's own scope first found (ADR 0063 D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Redriven {
    /// No entry stood at the scope.
    NoEntry,
    /// An entry stood, and the re-drive finished it.
    Finished,
    /// An entry stood whose work can never land, and the re-drive dropped it.
    Dropped,
    /// An entry stands still.
    StillOwed,
}

/// The check a re-drive reports for a write cut that the published scope says
/// targets another write epoch.
const OWED_WAVE_AT_ANOTHER_EPOCH: &str = "owed-write-cut-at-another-write-epoch";

/// The check a re-drive reports for a delivery whose recipient left the
/// contact book.
const OWED_RECIPIENT_UNKNOWN: &str = "owed-grant-recipient-unknown";

/// The check a re-drive reports for an interior move whose folder does not sit
/// under the scope it left.
const OWED_MOVE_SOURCE_MOVED: &str = "owed-interior-move-source-moved";
/// Neither the enclosing scope's index nor the owner-signed scope pointer names
/// a root for the owed scope.
const OWED_SCOPE_NOT_INDEXED: &str = "owed-scope-not-indexed";
/// The published cut epoch is below the entry's, so its cut set never landed.
const OWED_CUT_NEVER_LANDED: &str = "owed-cut-never-landed";
/// The folder answers as no scope root, and nothing owner-signed proves the
/// promotion never ran.
const OWED_MOVE_NOT_PROMOTED: &str = "owed-interior-move-not-promoted";
/// The root claims the owed write epoch, and no owner-signed pointer vouches
/// for the root it moved to.
const OWED_WAVE_UNVOUCHED: &str = "owed-write-cut-unvouched";
/// The write-scope cut a re-drive ran reported no name wave.
const OWED_WAVE_NOT_RUN: &str = "owed-write-cut-ran-no-wave";

/// The write cut a cut authorized at `write_epoch` owes.
pub(super) fn owed_write_cut(write_epoch: u64) -> Result<OwedStep, EngineError> {
    Ok(OwedStep::WriteCut {
        write_epoch: write_epoch
            .checked_add(1)
            .ok_or_else(|| EngineError::from_rotation(WriteRotateError::EpochExhausted))?,
    })
}

impl EngineError {
    /// The refusal of an owed rotation entry that did not store before the
    /// first publish (ADR 0063 D2).
    pub(crate) fn from_owed_record(error: OwedRecordError) -> Self {
        EngineError::Seam {
            message: error.check().to_owned(),
        }
    }

    /// The retryable refusal of a command while owed work stands at its scope.
    pub(crate) fn rotation_work_owed() -> Self {
        Self::from_owed_record(OwedRecordError::Standing)
    }
}

impl<T, H, C, F, Sch, S, St> ConversionPass<'_, T, H, C, F, Sch, S, St>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    S: SnapshotCache,
    St: StagingStore,
{
    /// This session's owed rotation record.
    pub(crate) fn owed(&self) -> OwedRotation<'_, St> {
        OwedRotation::new(self.staging, self.seal(), self.enc_secret, self.owed)
    }

    /// Take `scope` for this driver, or the retryable [`EngineError::rotation_work_owed`]
    /// while another driver holds it.
    pub(crate) fn hold_owed(&self, scope: NodeId) -> Result<ScopeHold<'_>, EngineError> {
        self.owed
            .hold(scope)
            .ok_or_else(EngineError::rotation_work_owed)
    }

    /// Tell the host that work at `scope_root` is still owed.
    pub(crate) fn report_owed(&self, scope_root: NodeId, stop: OwedStop) {
        let _ = self.events.unbounded_send(Event::RotationWorkOwed {
            scope_root,
            retryable: stop.retryable(),
            detail: stop.detail,
            class: stop.class,
        });
    }

    /// Write the entry a command owes at `scope` before its first publish. A
    /// refused write stops the command there (ADR 0063 D2).
    pub(crate) async fn owe(&self, scope: NodeId, entry: OwedEntry) -> Result<(), EngineError> {
        self.owed()
            .owe(scope, entry)
            .await
            .map_err(EngineError::from_owed_record)
    }

    /// Leave `steps` owed at `scope`, and tell the host. A store that refuses
    /// leaves the entry holding the steps before them, which still re-drive.
    pub(crate) async fn stop_owed(&self, scope: NodeId, steps: Vec<OwedStep>, stop: OwedStop) {
        let _ = self.owed().leave(scope, steps).await;
        self.note_owed_stop(scope).await;
        self.report_owed(scope, stop);
    }

    /// Start the bound of ADR 0065 D3 at `scope`'s entry, if it has not
    /// started. A store that refuses leaves it unset, so a later stop sets it.
    async fn note_owed_stop(&self, scope: NodeId) {
        let _ = self.owed().note_stop(scope, self.scheduler.now()).await;
    }

    /// The bound of ADR 0065 D3 for one pass at `scope`'s entry. `None` when
    /// the record does not read, so no node is past it.
    pub(super) async fn owed_bound(&self, scope: NodeId) -> Option<EntryBound<'_>> {
        self.owed().bound(scope, self.scheduler.now()).await.ok()
    }

    /// Settle one re-drive of `scope`'s entry. An entry whose work can never
    /// land is dropped, and the host is told once why: only after the drop is
    /// durable, so a later pass that drops it again is the one that tells.
    async fn settle_redrive(&self, scope: NodeId, redriven: Result<(), OwedStop>) -> Redriven {
        match redriven {
            Ok(()) => Redriven::Finished,
            Err(stop) if stop.terminal && self.owed().clear(scope).await.is_ok() => {
                let _ = self.events.unbounded_send(Event::RotationWorkAbandoned {
                    scope_root: scope,
                    detail: stop.detail,
                });
                Redriven::Dropped
            }
            Err(stop) => {
                self.note_owed_stop(scope).await;
                self.report_owed(scope, stop);
                Redriven::StillOwed
            }
        }
    }

    /// Drive `cut` at `node` under an owed rotation entry (ADR 0063 D2, D5):
    /// the entry is durable before the first publish, and a step that stops
    /// after it, fail-closed or not, leaves the entry, tells the host, and
    /// answers `Ok(None)`. `write_epoch` is the write epoch of the record the
    /// cut was authorized against.
    ///
    /// A read-only cut clears its entry here. A cut that moves the write plane
    /// leaves it for the caller, which clears it after the post-steps. The
    /// caller holds the scope
    /// ([`OwedCell::hold`](crate::sync::owed_rotation::OwedCell::hold))
    /// across both.
    pub(super) async fn rotate_owed_cut(
        &self,
        node: NodeId,
        target: &OwnerScope,
        scope_root_name: &IpnsName,
        cut: &RevokedCommittedSet,
        vault_pointer_signer: Option<&Ed25519Signer>,
        write_epoch: u64,
    ) -> Result<Option<CutRotationReport>, EngineError> {
        let write = if cut.planes().write() {
            Some(owed_write_cut(write_epoch)?)
        } else {
            None
        };
        let steps: Vec<OwedStep> = cut
            .planes()
            .read()
            .then_some(OwedStep::ReadCut)
            .into_iter()
            .chain(write.clone())
            .collect();
        self.owe(
            node,
            OwedEntry {
                cut_epoch: cut.commitment.cut_epoch,
                first_stop: None,
                steps: steps.clone(),
            },
        )
        .await?;
        let report = match self
            .rotate_planes(node, target, scope_root_name, cut, vault_pointer_signer)
            .await
        {
            Ok(report) => report,
            // The wave runs last, so the cut set is published, and the floor
            // holds the gate at it: a replayed pre-cut root would read as a cut
            // that never landed.
            Err(error @ RotateOnCutError::Write(_)) => {
                let _ = record_cut_epoch_floor(
                    self.floors,
                    &target.scope.scope_id,
                    cut.commitment.cut_epoch,
                )
                .await;
                self.stop_owed(node, write.into_iter().collect(), cut_stop(error))
                    .await;
                return Ok(None);
            }
            // The wave moved the root first (ADR 0068 D3). A failed floor raise
            // is safe: the entry stays owed, and the re-drive raises the floor
            // before it clears the entry.
            Err(error @ RotateOnCutError::ReadAfterWrite(_)) => {
                let _ = record_cut_epoch_floor(
                    self.floors,
                    &target.scope.scope_id,
                    cut.commitment.cut_epoch,
                )
                .await;
                self.stop_owed(node, steps, cut_stop(error)).await;
                return Ok(None);
            }
            // The re-drive finishes or drops the entry (ADR 0068 D4).
            Err(error @ RotateOnCutError::WriteFirst(_)) => {
                return Err(EngineError::from_cut_rotation(error));
            }
            Err(error) => {
                return match self.cut_set_published(target, cut).await {
                    Some(true) => {
                        self.stop_owed(node, steps, cut_stop(error)).await;
                        Ok(None)
                    }
                    Some(false) => {
                        let _ = self.owed().clear(node).await;
                        Err(EngineError::from_cut_rotation(error))
                    }
                    // Unknown: the entry stands, and the re-drive drops it if
                    // the published root never carried the cut.
                    None => Err(EngineError::from_cut_rotation(error)),
                };
            }
        };
        if let Err(error) = record_cut_epoch_floor(
            self.floors,
            &target.scope.scope_id,
            cut.commitment.cut_epoch,
        )
        .await
        {
            self.stop_owed(
                node,
                write.into_iter().collect(),
                OwedStop::of("owed-cut-epoch-floor", &EngineError::from_seam(error)),
            )
            .await;
            return Ok(None);
        }
        if write.is_none() {
            let _ = self.owed().clear(node).await;
        }
        Ok(Some(report))
    }

    /// Whether the root at `target` carries `cut`'s set, which is the first
    /// publish of a revoke or a downgrade. `None` when the root does not read.
    async fn cut_set_published(
        &self,
        target: &OwnerScope,
        cut: &RevokedCommittedSet,
    ) -> Option<bool> {
        let bound = self.owed_bound(NodeId(target.scope.scope_id)).await;
        let current = self
            .cut_net(target, bound.as_ref().map_or(&NoBound, |b| b))
            .resolve_anchored(&target.scope)
            .await
            .ok()?;
        Some(current.commitment == cut.commitment && current.grant_ledger == cut.grant_ledger)
    }

    /// Re-drive every owed entry, and tell the host of each one still owed
    /// (ADR 0063 D3). A scope a command holds is left to the next pass, and
    /// each entry is read again under the hold, so the pass never drives an
    /// entry a command has replaced or cleared.
    pub(crate) async fn redrive_owed(&self, sites: &impl ConversionSites) {
        let Some(_running) = Running::take(self.running) else {
            return;
        };
        self.owed.next_pass();
        // A record that does not read is read again by the next pass.
        let Ok(scopes) = self.owed().scopes().await else {
            return;
        };
        for scope in scopes {
            let _ = self.redrive_scope(sites, scope).await;
        }
    }

    /// Re-drive the entry at `scope`, if one stands, before a command acts
    /// there (ADR 0063 D5), and tell the host when it is still owed. Refused
    /// with the retryable [`EngineError::rotation_work_owed`] while the pass drives it.
    pub(crate) async fn redrive_scope(
        &self,
        sites: &impl ConversionSites,
        scope: NodeId,
    ) -> Result<Redriven, EngineError> {
        let _hold = self.hold_owed(scope)?;
        let Some(entry) = self
            .owed()
            .entry(scope)
            .await
            .map_err(EngineError::from_seam)?
        else {
            return Ok(Redriven::NoEntry);
        };
        let redriven = self.redrive_entry(sites, scope, entry).await;
        Ok(self.settle_redrive(scope, redriven).await)
    }

    /// Drop the share pointer owed to `recipient` at `scope`.
    pub(crate) async fn cancel_owed_delivery(
        &self,
        scope: NodeId,
        recipient: &[u8; IDENTITY_PUBLIC_LEN],
    ) -> Result<(), EngineError> {
        let _hold = self.hold_owed(scope)?;
        self.owed()
            .cancel_delivery(scope, recipient)
            .await
            .map_err(EngineError::from_owed_record)
    }

    /// Replace the entry `standing` at `scope` with `entry` in one write, so
    /// owed work stands there throughout a re-run.
    pub(crate) async fn replace_owed(
        &self,
        scope: NodeId,
        standing: &OwedEntry,
        entry: OwedEntry,
    ) -> Result<(), EngineError> {
        self.owed()
            .replace(scope, standing, entry)
            .await
            .map_err(EngineError::from_owed_record)
    }

    /// Withdraw `entry`, which a command wrote at `scope` and stopped before
    /// its first publish: clear it, or put back the entry `over` it replaced.
    /// A write-back the store refuses is the command's answer, since the work
    /// it held would otherwise be lost in silence.
    pub(crate) async fn unowe(
        &self,
        scope: NodeId,
        entry: &OwedEntry,
        over: Option<OwedEntry>,
    ) -> Result<(), EngineError> {
        match over {
            None => {
                let _ = self.owed().clear(scope).await;
                Ok(())
            }
            Some(over) => self.replace_owed(scope, entry, over).await,
        }
    }

    /// `Ok` when the entry still owed at `scope` is a cut's, which a command
    /// whose own change already shows on the set may stand behind; otherwise
    /// the retryable refusal. Read under the hold, so no driver clears or
    /// replaces the entry between the read and the answer.
    pub(crate) async fn require_owed_cut(&self, scope: NodeId) -> Result<(), EngineError> {
        let _hold = self.hold_owed(scope)?;
        match self
            .owed()
            .entry(scope)
            .await
            .map_err(EngineError::from_seam)?
        {
            Some(entry) if entry.is_cut() => Ok(()),
            _ => Err(EngineError::rotation_work_owed()),
        }
    }

    /// The answer of a command whose own change already shows on the set
    /// after `redriven` (ADR 0063 D5): done when the re-drive finished it, the
    /// standing cut while it is still owed, and `shown` otherwise.
    pub(crate) async fn settle_shown(
        &self,
        scope: NodeId,
        redriven: Redriven,
        shown: EngineError,
    ) -> Result<(), EngineError> {
        match redriven {
            Redriven::Finished => Ok(()),
            Redriven::StillOwed => self.require_owed_cut(scope).await,
            Redriven::NoEntry | Redriven::Dropped => Err(shown),
        }
    }

    /// Run the steps `entry` still owes at `scope` in order, advancing the
    /// record as each lands, then its post-steps, then clear it. A cut whose
    /// set never landed owes nothing, and raises no floor (ADR 0063 D2).
    async fn redrive_entry(
        &self,
        sites: &impl ConversionSites,
        scope: NodeId,
        entry: OwedEntry,
    ) -> Result<(), OwedStop> {
        // The first step reuses the scope the check read: nothing published
        // since.
        let mut read = None;
        let mut steps = entry.steps.clone();
        if entry.cut_epoch > 0 {
            let published = self.owed_scope(sites, scope, "owed-cut", true).await?;
            if published.current.commitment.cut_epoch < entry.cut_epoch {
                return Err(OwedStop::abandoned(OWED_CUT_NEVER_LANDED));
            }
            // No step publishes at a root read from its last copy, so the
            // wave moves the root first (ADR 0068 D3).
            if published.fell_back {
                steps.sort_by_key(|step| !matches!(step, OwedStep::WriteCut { .. }));
            }
            read = Some(published);
        }
        for (at, step) in steps.iter().enumerate() {
            let read = read.take();
            match step {
                OwedStep::InteriorMove { left_scope } => {
                    self.redrive_interior_move(sites, scope, *left_scope).await
                }
                OwedStep::ReadCut => {
                    self.redrive_read_cut(sites, scope, entry.cut_epoch, read)
                        .await
                }
                OwedStep::WriteCut { write_epoch } => {
                    self.redrive_write_cut(sites, scope, *write_epoch, read)
                        .await
                }
                OwedStep::DeliverGrant {
                    recipient_identity_pk,
                    write,
                } => {
                    self.redrive_delivery(sites, scope, recipient_identity_pk, *write, read)
                        .await
                }
            }?;
            if let Some(next) = steps.get(at + 1) {
                let _ = if steps == entry.steps {
                    self.owed().advance_to(scope, next).await
                } else {
                    self.owed().leave(scope, steps[at + 1..].to_vec()).await
                };
            }
        }
        if entry.cut_epoch > 0 {
            record_cut_epoch_floor(self.floors, &scope.0, entry.cut_epoch)
                .await
                .map_err(|e| OwedStop::of("owed-cut-epoch-floor", &EngineError::from_seam(e)))?;
        }
        let _ = self.owed().clear(scope).await;
        Ok(())
    }

    /// The scope root at `node` where its owner-signed pointer vouches for it,
    /// gated, for the owed `step`. Below the vault root the place is read off
    /// the enclosing scope's index, or off the pointer where the index names
    /// none: a sync pass proves no material for a scope whose write cut
    /// stopped, because the write seed it holds does not derive the name the
    /// scope answers at.
    async fn owed_scope(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        step: &'static str,
        cut: bool,
    ) -> Result<OwedScope, OwedStop> {
        let stop = |e: EngineError| OwedStop::of(step, &e);
        let vouched = self.vouched_root(node).await.map_err(stop)?;
        let (placed, indexed) = if node == self.cut.vault_root {
            let placed = sites.place(node).await.map_err(stop)?;
            let indexed = Some(placed.scope.ipns_name.clone());
            (placed, indexed)
        } else {
            self.indexed_place(sites, node, vouched.as_ref())
                .await
                .map_err(stop)?
                .ok_or_else(|| OwedStop::pending(OWED_SCOPE_NOT_INDEXED))?
        };
        let target = match &vouched {
            Some(root) if root.as_str().as_bytes() != placed.scope.ipns_name.as_slice() => {
                OwnerScope {
                    scope: ChildScopeRef::new(node.0, root.as_str().as_bytes().to_vec()),
                    parent_node_seed: placed.parent_node_seed.clone(),
                    vouched: true,
                }
            }
            _ => placed,
        };
        let bound = self.owed_bound(node).await;
        let net = if cut {
            self.cut_net(&target, bound.as_ref().map_or(&NoBound, |b| b))
        } else {
            self.net(&target, PointerConsultArm::Refused)
        };
        let current = net
            .resolve_anchored(&target.scope)
            .await
            .map_err(|e| stop(EngineError::from_resolve_failure(e)))?;
        let fell_back = net
            .root_fallback
            .as_ref()
            .is_some_and(RootFallback::fell_back);
        Ok(OwedScope {
            indexed,
            target,
            current,
            pointer_placed: vouched.is_some(),
            fell_back,
        })
    }

    /// `read` when the caller holds it, else [`Self::owed_scope`] read now.
    async fn owed_scope_or(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        step: &'static str,
        read: Option<OwedScope>,
        cut: bool,
    ) -> Result<OwedScope, OwedStop> {
        match read {
            Some(read) => Ok(read),
            None => self.owed_scope(sites, node, step, cut).await,
        }
    }

    /// The scope root at `node` as the enclosing scope's index names it, with
    /// that name, else at `vouched` with no name, else `None`.
    async fn indexed_place(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        vouched: Option<&IpnsName>,
    ) -> Result<Option<(OwnerScope, Option<Vec<u8>>)>, EngineError> {
        let parent = sites.enclosing(node).await?;
        let enclosing = self
            .net(&parent, PointerConsultArm::Permitted)
            .resolve_anchored(&parent.scope)
            .await
            .map_err(EngineError::from_resolve_failure)?;
        let indexed = enclosing
            .direct_child_scope_index
            .iter()
            .find(|child| child.scope_id == node.0)
            .cloned();
        let name = indexed.as_ref().map(|child| child.ipns_name.clone());
        Ok(indexed
            .or_else(|| {
                vouched.map(|root| ChildScopeRef::new(node.0, root.as_str().as_bytes().to_vec()))
            })
            .map(|scope| (OwnerScope::indexed(&enclosing, scope), name)))
    }

    /// Re-seal the interior a stalled grant left in `left_scope` into the
    /// scope promoted at `node`, through the resume path of a grant against
    /// the promoted root, so an append stays an append (ADR 0026 D1).
    async fn redrive_interior_move(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        left_scope: NodeId,
    ) -> Result<(), OwedStop> {
        let step = "owed-interior-move";
        let stop = |e: EngineError| OwedStop::of(step, &e);
        let parent = sites.enclosing(node).await.map_err(stop)?;
        if parent.scope.scope_id != left_scope.0 {
            return Err(OwedStop::pending(OWED_MOVE_SOURCE_MOVED));
        }
        let net = self.net(&parent, PointerConsultArm::Permitted);
        let current = net
            .resolve_anchored(&parent.scope)
            .await
            .map_err(|e| stop(EngineError::from_resolve_failure(e)))?;
        let subtree = sites
            .child_scopes_inside(node, &current.direct_child_scope_index)
            .await
            .map_err(stop)?;
        let held = sites.held_outside(node).await.map_err(stop)?;
        let parent_node_seed = kdf::node_seed(&current.override_seed, &node.0);
        let pointer_read_key = self.scope_keys.pointer_read_key(&node.0);
        let pseudonym_signer = self.scope_keys.writer_pseudonym(&node.0);
        let grantee = GranteeScopePlan {
            v: current.v,
            scope_id: node.0,
            parent_node_seed: parent_node_seed.as_bytes(),
            owner_enc_pub: &current.owner_enc_pub,
            write_scope_seed: &current.write_scope_seed,
            write_cut: None,
            pointer_read_key: &pointer_read_key,
            subtree_child_index: &subtree,
            held_outside: &held,
        };
        let parent_plan = parent_scope_plan(&parent, &current, self.enc_secret);
        let owner = OwnerGrantKeys {
            enc_secret: self.enc_secret,
            identity_signer: self.identity,
            pseudonym_signer: &pseudonym_signer,
        };
        match resume_owed_interior_move(
            &mut SharedEntropy(self.entropy),
            &net,
            &grantee,
            &parent_plan,
            &owner,
        )
        .await
        {
            Ok(Some(_)) => Ok(()),
            // A parent-scope writer can publish a record at the folder's name,
            // so a root with no grant section does not prove the promotion
            // never ran.
            Ok(None) => Err(OwedStop::pending(OWED_MOVE_NOT_PROMOTED)),
            Err(e) => Err(OwedStop::of_grant(&e)),
        }
    }

    /// Run the read cascade the published cut set still owes at `node`.
    async fn redrive_read_cut(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        cut_epoch: u64,
        read: Option<OwedScope>,
    ) -> Result<(), OwedStop> {
        let step = "owed-read-cut";
        let stop = |e: EngineError| OwedStop::of(step, &e);
        let OwedScope {
            target, current, ..
        } = self.owed_scope_or(sites, node, step, read, true).await?;
        // Above the entry's epoch a later cut re-keyed the scope; at it, see
        // blueprint/engine.md "Owed rotation work".
        if current.commitment.cut_epoch > cut_epoch {
            return Ok(());
        }
        let scope_root_name = parsed_scope_name(&target.scope.ipns_name).map_err(stop)?;
        let cut = owed_read_cut(&GrantCutPlan::over(
            &current,
            &scope_root_name,
            self.identity,
        ))
        .map_err(|e| stop(EngineError::from_revoke(e)))?;
        self.rotate_planes(node, &target, &scope_root_name, &cut, None)
            .await
            .map_err(cut_stop)?;
        Ok(())
    }

    /// Run the name wave the scope at `node` still owes at `write_epoch`,
    /// unless it has landed, then its write-epoch floor raise and index
    /// re-point.
    async fn redrive_write_cut(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        write_epoch: u64,
        read: Option<OwedScope>,
    ) -> Result<(), OwedStop> {
        let step = "owed-write-cut";
        let stop = |e: EngineError| OwedStop::of(step, &e);
        let OwedScope {
            indexed,
            target,
            current,
            pointer_placed,
            ..
        } = self.owed_scope_or(sites, node, step, read, true).await?;
        let (root_name, landed_epoch) = if current.write_epoch >= write_epoch {
            // A landed wave re-points the scope pointer, and the floor never
            // takes an epoch only the root read off the wire states.
            if !pointer_placed {
                return Err(OwedStop::refused(OWED_WAVE_UNVOUCHED));
            }
            (
                parsed_scope_name(&target.scope.ipns_name).map_err(stop)?,
                current.write_epoch,
            )
        } else if current.write_epoch.checked_add(1) == Some(write_epoch) {
            let scope_root_name = parsed_scope_name(&target.scope.ipns_name).map_err(stop)?;
            let cut = cut_for_write_scope(&GrantCutPlan::over(
                &current,
                &scope_root_name,
                self.identity,
            ))
            .map_err(|e| stop(EngineError::from_revoke(e)))?;
            let write = self
                .rotate_planes(node, &target, &scope_root_name, &cut, None)
                .await
                .map_err(cut_stop)?
                .write
                .ok_or_else(|| OwedStop::refused(OWED_WAVE_NOT_RUN))?;
            (write.new_root_name, write.new_write_epoch)
        } else {
            return Err(OwedStop::refused(OWED_WAVE_AT_ANOTHER_EPOCH));
        };
        floor::advance_write_epoch_on_sight(self.floors, &node.0, landed_epoch)
            .await
            .map_err(|e| stop(EngineError::from_seam(e)))?;
        if indexed.as_deref() != Some(root_name.as_str().as_bytes()) {
            let parent = sites.enclosing(node).await.map_err(stop)?;
            self.repoint(&parent, node, &root_name)
                .await
                .map_err(stop)?;
        }
        Ok(())
    }

    /// Post the share pointer a grant still owes its recipient, at the name the
    /// scope answers at now.
    async fn redrive_delivery(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        recipient_identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
        write: bool,
        read: Option<OwedScope>,
    ) -> Result<(), OwedStop> {
        let step = "owed-grant-delivery";
        let stop = |e: EngineError| OwedStop::of(step, &e);
        let contacts = StagingContactStore::new(self.staging, self.enc_secret, self.entropy);
        let contact = match resolve_recipient(&contacts, recipient_identity_pk).await {
            Ok(contact) => contact,
            Err(ContactStoreError::RecipientNotImported) => {
                return Err(OwedStop::abandoned(OWED_RECIPIENT_UNKNOWN));
            }
            Err(e) => return Err(stop(EngineError::from_contact_store(e))),
        };
        let OwedScope { target, .. } = self.owed_scope_or(sites, node, step, read, false).await?;
        let display_name = sites.folder_name(node).await.map_err(stop)?;
        post_share_pointer_at(
            &mut SharedEntropy(self.entropy),
            self.api,
            self.identity,
            ENVELOPE_V,
            &GrantRecipient {
                contact: &contact,
                display_name,
                grantee_name: None,
            },
            if write {
                CommittedPermission::Write
            } else {
                CommittedPermission::Read
            },
            &parsed_scope_name(&target.scope.ipns_name).map_err(stop)?,
        )
        .await
        .map_err(|e| stop(EngineError::from_create_grant(e)))?;
        Ok(())
    }
}

/// The scope an owed step acts on: the name the parent's index gives it, if
/// any, and the root its pointer vouches for, gated.
struct OwedScope {
    indexed: Option<Vec<u8>>,
    target: OwnerScope,
    current: CascadeTarget,
    /// The owner-signed scope pointer names `target`.
    pointer_placed: bool,
    /// The read ran on the last copy of a root the gate refused (ADR 0068 D1).
    fell_back: bool,
}

/// The stop a plane rotation failure reports, classed as the command's own
/// verdict on it would be.
fn cut_stop(error: RotateOnCutError) -> OwedStop {
    OwedStop {
        detail: error.check().to_owned(),
        terminal: false,
        class: OwedWorkClass::of(&EngineError::from_cut_rotation(error)),
    }
}
