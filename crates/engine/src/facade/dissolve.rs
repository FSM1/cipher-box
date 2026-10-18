//! The cut step of a dissolve (ADR 0077 D1): each scope root that the
//! dissolve removes loses every grant row in one cut, deepest first, and its
//! final records publish again, so they hold for one more EOL term from the
//! scope's `cut_time`.
//!
//! The entry is the dissolve journal header ([`crate::sync::dissolve_journal`]).
//! The command and the sync pass drive it on the [`ConversionPass`]; an owed
//! rotation entry carries a cut that stops across a restart (ADR 0063), and
//! this step waits until it lands.

use super::claim_conversion::{ConversionSites, HeldRecord, OnRunning};
use super::owed_rotation::{OwedCut, OwedScope, OwedStop, owed_write_cut};
use super::*;
use crate::grants::{OwnerAuthority, committed_links};
use crate::net::cut::{republish_scope_pointer, reseal_root_in_place};
use crate::rotation::{
    CascadeError, CommittedSet, NoBound, WriteRotationOutcome, revoke_every_row,
};
#[cfg(any(test, feature = "test-kit"))]
use crate::sync::dissolve_journal::{DissolveBinding, DissolvedScope, MAX_DISSOLVED_SCOPES};
use crate::sync::dissolve_journal::{
    DissolveHeader, DissolveHold, DissolveJournal, DissolveStep, DissolveWriteError, HeaderSlot,
};
use crate::sync::owner_tag;

/// What one scope's cut reached in one drive.
enum ScopeCut {
    /// The scope holds no row, and its final records published again.
    Done,
    /// The scope waits for owed rotation work, a link conversion, or another
    /// driver.
    Waiting,
    /// A row appeared after the dissolve cut the scope.
    NewRow,
}

impl EngineError {
    fn from_dissolve_write(error: DissolveWriteError) -> Self {
        Self::Seam {
            message: error.check().to_owned(),
        }
    }

    fn from_owed_stop(stop: OwedStop) -> Self {
        match stop.class {
            OwedWorkClass::Trust => Self::TrustViolation {
                message: stop.detail,
            },
            OwedWorkClass::Availability | OwedWorkClass::Capability => Self::Seam {
                message: stop.detail,
            },
        }
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
    /// This owner's dissolve entries.
    pub(super) fn dissolve_journal(&self) -> DissolveJournal<'_, St> {
        DissolveJournal::new(
            self.staging,
            self.seal(),
            owner_tag(self.enc_secret),
            self.owed.dissolve(),
        )
    }

    /// Drive the cut step of each dissolve entry this owner holds. A failed
    /// drive leaves its entry for the next pass.
    pub(crate) async fn redrive_dissolve_cuts(
        &self,
        sites: &impl ConversionSites,
        pointers: &PointerIndex,
    ) {
        let Ok(roots) = self.dissolve_journal().roots().await else {
            return;
        };
        for root in roots {
            let _ = self.drive_dissolve_cut(sites, pointers, root).await;
        }
    }

    /// Drive the cut step of the entry at `root`. Answers the step the entry
    /// holds after the drive, or `None` when no entry stands there.
    pub(super) async fn drive_dissolve_cut(
        &self,
        sites: &impl ConversionSites,
        pointers: &PointerIndex,
        root: NodeId,
    ) -> Result<Option<DissolveStep>, EngineError> {
        let journal = self.dissolve_journal();
        let hold = self.owed.dissolve().hold(root);
        let mut header = match journal.header(root).await.map_err(EngineError::from_seam)? {
            HeaderSlot::Absent => return Ok(None),
            HeaderSlot::Own(header) => header,
            HeaderSlot::Foreign | HeaderSlot::Unreadable => {
                return Err(EngineError::from_dissolve_write(
                    DissolveWriteError::Blocked,
                ));
            }
        };
        let Some(hold) = hold.filter(|_| header.step == DissolveStep::Cut) else {
            return Ok(Some(header.step));
        };
        // A cut of a link row and a conversion of a claim on it exclude each
        // other (ADR 0023 D4).
        let Some(mut record) = self.hold_record(OnRunning::Refuse).await? else {
            return Ok(Some(DissolveStep::Cut));
        };
        let mut reached = Ok(ScopeCut::Done);
        for at in (0..header.scopes.len()).rev() {
            reached = self
                .cut_scope(sites, &journal, &hold, &mut header, at, &mut record)
                .await;
            if !matches!(reached, Ok(ScopeCut::Done)) {
                break;
            }
        }
        // A failed write leaves the entries for the next hold to retire.
        let _ = self.settle(record, pointers).await;
        match reached? {
            ScopeCut::Done => {
                let held = header.clone();
                header.step = DissolveStep::Map;
                journal
                    .commit(&hold, Some(&held), &header)
                    .await
                    .map_err(EngineError::from_dissolve_write)?;
                Ok(Some(DissolveStep::Map))
            }
            ScopeCut::Waiting => Ok(Some(DissolveStep::Cut)),
            ScopeCut::NewRow => {
                journal
                    .drop_entry(&hold, &header)
                    .await
                    .map_err(EngineError::from_dissolve_write)?;
                Ok(None)
            }
        }
    }

    /// Cut every row of `header.scopes[at]`, or find it cut, then publish its
    /// pointer, and its root when this drive cut nothing, again.
    async fn cut_scope(
        &self,
        sites: &impl ConversionSites,
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &mut DissolveHeader,
        at: usize,
        record: &mut HeldRecord<'_>,
    ) -> Result<ScopeCut, EngineError> {
        let scope = header.scopes[at].scope_id;
        let Some(_owed_hold) = self.owed.hold(scope) else {
            return Ok(ScopeCut::Waiting);
        };
        if self
            .owed()
            .entry(scope)
            .await
            .map_err(EngineError::from_seam)?
            .is_some()
        {
            return Ok(ScopeCut::Waiting);
        }
        // Before the first publish of this scope, so every final record it
        // signs carries an EOL past `cut_time` plus the EOL window.
        if header.scopes[at].cut_time == 0 {
            let held = header.clone();
            header.scopes[at].cut_time = self.scheduler.now().0;
            journal
                .commit(hold, Some(&held), header)
                .await
                .map_err(EngineError::from_dissolve_write)?;
        }
        let OwedScope {
            indexed,
            target,
            current,
            ..
        } = self
            .owed_scope(sites, scope, "dissolve-cut", true)
            .await
            .map_err(EngineError::from_owed_stop)?;
        let cut_epoch = header.scopes[at].cut_epoch;
        let rows = !current.commitment.entries.is_empty();
        if rows && cut_epoch != 0 && current.commitment.cut_epoch >= cut_epoch {
            return Ok(ScopeCut::NewRow);
        }
        let name = parsed_scope_name(&target.scope.ipns_name)?;
        let (target, landed) = if rows {
            let commitment_sig = parsed_commitment_sig(&current.commitment_sig)?;
            let links: Vec<[u8; IDENTITY_PUBLIC_LEN]> = committed_links(
                &OwnerAuthority {
                    identity_signer: self.identity,
                    enc_secret: self.enc_secret,
                },
                &bound_scope(&target, &current, &commitment_sig)?,
            )
            .map_err(EngineError::from_invite)?
            .iter()
            .map(|link| link.ephemeral_identity_pk)
            .collect();
            let pending = record.pending_links();
            if links.iter().any(|link| pending.contains(link)) {
                return Ok(ScopeCut::Waiting);
            }
            let cut = revoke_every_row(&GrantCutPlan::over(&current, &name, self.identity))
                .map_err(EngineError::from_revoke)?;
            let report = match self
                .rotate_owed_cut(
                    scope,
                    &target,
                    &name,
                    &cut,
                    None,
                    current.write_epoch,
                    sites.command(),
                )
                .await?
            {
                OwedCut::Ran(report) => *report,
                OwedCut::SetLanded | OwedCut::Unproved => return Ok(ScopeCut::Waiting),
            };
            record.retire_cut(&links);
            let target = match report.write {
                Some(write) => {
                    if let Err(error) = self
                        .after_dissolve_wave(sites, scope, indexed.as_deref(), &write)
                        .await
                    {
                        let steps = vec![owed_write_cut(current.write_epoch)?];
                        self.stop_owed(scope, steps, OwedStop::of_post_step(&error))
                            .await;
                        return Ok(ScopeCut::Waiting);
                    }
                    let _ = self.owed().clear(scope).await;
                    OwnerScope {
                        scope: ChildScopeRef::new(
                            scope.0,
                            write.new_root_name.as_str().as_bytes().to_vec(),
                        ),
                        ..target
                    }
                }
                None => target,
            };
            (target, cut.commitment.cut_epoch)
        } else {
            self.republish_root(sites, &target, &name).await?;
            (target, current.commitment.cut_epoch)
        };
        if cut_epoch == 0 && landed != 0 {
            let held = header.clone();
            header.scopes[at].cut_epoch = landed;
            journal
                .commit(hold, Some(&held), header)
                .await
                .map_err(EngineError::from_dissolve_write)?;
        }
        republish_scope_pointer(
            &self.net(&target, PointerConsultArm::Refused),
            self.cut.owner_pointer_seed,
            self.cut.held,
            scope.0,
        )
        .await
        .map_err(|error| EngineError::from_rotate(RotateError::Publish(error)))?;
        Ok(ScopeCut::Done)
    }

    /// The post-steps of the name wave `write` that a dissolve cut ran at
    /// `scope`: the write-epoch floor, then the parent's index entry.
    async fn after_dissolve_wave(
        &self,
        sites: &impl ConversionSites,
        scope: NodeId,
        indexed: Option<&[u8]>,
        write: &WriteRotationOutcome,
    ) -> Result<(), EngineError> {
        floor::advance_write_epoch_on_sight(self.floors, &scope.0, write.new_write_epoch)
            .await
            .map_err(EngineError::from_seam)?;
        if indexed != Some(write.new_root_name.as_str().as_bytes()) {
            let parent = sites.enclosing(scope).await?;
            self.repoint(&parent, scope, &write.new_root_name).await?;
        }
        Ok(())
    }

    /// Publish the root at `target` again at the next sequence with the same
    /// set, seed and read epoch, under a fresh EOL. Refused when the gated
    /// read finds a row, or reads a last copy.
    async fn republish_root(
        &self,
        sites: &impl ConversionSites,
        target: &OwnerScope,
        name: &IpnsName,
    ) -> Result<(), EngineError> {
        let wait = if sites.command() {
            RootWait::Command
        } else {
            RootWait::Bound(&NoBound)
        };
        let net = self.cut_net(target, wait);
        let current = net
            .resolve_anchored(&target.scope)
            .await
            .map_err(|e| EngineError::from_resolve_failure(e, "dissolve-final-root"))?;
        if net.fell_back() || !current.commitment.entries.is_empty() {
            return Err(EngineError::from_cut_rotation(RotateOnCutError::Read(
                CascadeError::Publish {
                    scope_id: target.scope.scope_id,
                    error: RotationPublishError::Superseded,
                },
            )));
        }
        reseal_root_in_place(
            &net,
            NodeId(target.scope.scope_id),
            name,
            target.parent_node_seed.as_deref(),
            &current,
            CommittedSet {
                commitment: &current.commitment,
                commitment_sig: &current.commitment_sig,
                grant_ledger: &current.grant_ledger,
                direct_child_scope_index: &current.direct_child_scope_index,
                revoked_recipients: &[],
            },
        )
        .await
        .map_err(|e| EngineError::from_cut_rotation(RotateOnCutError::Read(e)))
    }

    /// `root` and every scope root that a gated index names below it, in the
    /// order a walk from `root` reaches them.
    #[cfg(any(test, feature = "test-kit"))]
    async fn dissolved_scopes(
        &self,
        sites: &impl ConversionSites,
        root: NodeId,
    ) -> Result<Vec<DissolvedScope>, EngineError> {
        let mut scopes = vec![DissolvedScope::uncut(root)];
        let mut at = 0;
        while let Some(scope) = scopes.get(at).map(|scope| scope.scope_id) {
            let OwedScope { current, .. } = self
                .owed_scope(sites, scope, "dissolve-scopes", false)
                .await
                .map_err(EngineError::from_owed_stop)?;
            for child in &current.direct_child_scope_index {
                let child = NodeId(child.scope_id);
                if scopes.iter().all(|scope| scope.scope_id != child) {
                    scopes.push(DissolvedScope::uncut(child));
                }
            }
            if scopes.len() > MAX_DISSOLVED_SCOPES {
                return Err(EngineError::UnsupportedTarget {
                    check: "dissolve-subtree-too-large",
                });
            }
            at += 1;
        }
        Ok(scopes)
    }
}

impl<T: SeamTypes> Engine<T> {
    /// Start a dissolve of the scope root `root` at its cut step, with the
    /// destination `binding` under `relink_parent`, and drive the cut. Answers
    /// the step the entry holds after the drive, `None` when it went. An entry
    /// that stands already is driven as it is.
    #[cfg(any(test, feature = "test-kit"))]
    pub async fn dissolve_cut_for_test(
        &self,
        root: NodeId,
        relink_parent: NodeId,
        binding: DissolveBinding,
    ) -> Result<Option<DissolveStep>, EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let keys = self.pass_keys(session)?;
        let pass = self.conversion_pass(session, api, &keys);
        let sites = self.sites(session, api);
        let journal = pass.dissolve_journal();
        {
            let hold = pass
                .owed
                .dissolve()
                .hold(root)
                .ok_or_else(EngineError::rotation_work_owed)?;
            if journal.header(root).await.map_err(EngineError::from_seam)? == HeaderSlot::Absent {
                let scopes = pass.dissolved_scopes(&sites, root).await?;
                let header =
                    DissolveHeader::at_cut(self.mint_node_id()?, relink_parent, binding, scopes);
                journal
                    .commit(&hold, None, &header)
                    .await
                    .map_err(EngineError::from_dissolve_write)?;
            }
        }
        pass.drive_dissolve_cut(&sites, &self.scope_pointer_index(session), root)
            .await
    }

    /// The dissolve header that stands at `root`, if this owner's own entry
    /// holds one there.
    #[cfg(any(test, feature = "test-kit"))]
    pub async fn dissolve_header_for_test(
        &self,
        root: NodeId,
    ) -> Result<Option<DissolveHeader>, EngineError> {
        let session = self.session.as_ref().ok_or(EngineError::NotStarted)?;
        let api = self.api.as_ref().ok_or(EngineError::NotStarted)?;
        let keys = self.pass_keys(session)?;
        let pass = self.conversion_pass(session, api, &keys);
        Ok(
            match pass
                .dissolve_journal()
                .header(root)
                .await
                .map_err(EngineError::from_seam)?
            {
                HeaderSlot::Own(header) => Some(header),
                HeaderSlot::Absent | HeaderSlot::Foreign | HeaderSlot::Unreadable => None,
            },
        )
    }
}
