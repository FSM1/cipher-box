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
    CascadeError, CommittedSet, NoBound, WriteRotationOutcome, recut_from_last_copy,
};
#[cfg(any(test, feature = "test-kit"))]
use crate::sync::dissolve_journal::{DissolveBinding, DissolvedScope, MAX_DISSOLVED_SCOPES};
use crate::sync::dissolve_journal::{
    DissolveHeader, DissolveHold, DissolveJournal, DissolveStep, DissolveWriteError, HeaderSlot,
};

/// The detail of the one host event for a dissolve header that does not open.
pub(crate) const DISSOLVE_HEADER_UNREADABLE: &str = "dissolve-journal-header-unreadable";

/// What one scope's cut reached in one drive.
enum ScopeCut {
    /// The scope holds no row, and its final records published again.
    Done,
    /// The scope waits for owed rotation work, a link conversion, or another
    /// driver.
    Waiting,
    /// Work that the dissolve did not do landed on the scope, so the dissolve
    /// stops.
    Concurrent,
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
    fn dissolve_journal(&self) -> DissolveJournal<'_, St> {
        DissolveJournal::new(self.staging, self.seal(), self.owed.dissolve())
    }

    /// Drive the cut step of each dissolve entry this owner holds. A failed
    /// drive leaves its entry for the next pass, and a trust violation goes to
    /// the host.
    pub(crate) async fn redrive_dissolve_cuts(
        &self,
        sites: &impl ConversionSites,
        pointers: &PointerIndex,
    ) {
        let Ok(roots) = self.dissolve_journal().roots().await else {
            return;
        };
        for root in roots {
            if let Err(EngineError::TrustViolation { message }) =
                self.drive_dissolve_cut(sites, pointers, root).await
            {
                let _ = self.events.unbounded_send(Event::AttributableAbuse {
                    description: message,
                });
            }
        }
    }

    /// Drive the cut step of the entry at `root`. Answers the step the entry
    /// holds after the drive, or `None` when no entry stands there.
    async fn drive_dissolve_cut(
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
            HeaderSlot::Foreign => {
                return Err(EngineError::from_dissolve_write(
                    DissolveWriteError::Blocked,
                ));
            }
            // The bytes stay, and the entry stays blocked.
            HeaderSlot::Unreadable => {
                if self.owed.note_unreadable_dissolve(root) {
                    let _ = self.events.unbounded_send(Event::RotationWorkOwed {
                        scope_root: root,
                        detail: DISSOLVE_HEADER_UNREADABLE.to_owned(),
                        retryable: false,
                        class: OwedWorkClass::Capability,
                    });
                }
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
        let forgot = match reached {
            Ok(ScopeCut::Concurrent) => self.forget_landed(sites, &header).await,
            _ => Ok(true),
        };
        // A failed write leaves the entries for the next hold to retire.
        let _ = self.settle(record, pointers).await;
        match reached? {
            ScopeCut::Done => {
                self.commit_dissolve(&journal, &hold, &mut header, |header| {
                    header.step = DissolveStep::Map;
                })
                .await?;
                Ok(Some(DissolveStep::Map))
            }
            ScopeCut::Waiting => Ok(Some(DissolveStep::Cut)),
            ScopeCut::Concurrent => {
                if !forgot? {
                    return Ok(Some(DissolveStep::Cut));
                }
                journal
                    .drop_entry(&hold, &header)
                    .await
                    .map_err(EngineError::from_dissolve_write)?;
                Ok(None)
            }
        }
    }

    /// Commit `header` with `change` over the header it holds.
    async fn commit_dissolve(
        &self,
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &mut DissolveHeader,
        change: impl FnOnce(&mut DissolveHeader),
    ) -> Result<(), EngineError> {
        let held = header.clone();
        change(header);
        journal
            .commit(hold, Some(&held), header)
            .await
            .map_err(EngineError::from_dissolve_write)
    }

    /// Whether a dissolve entry at its cut step lists `scope`. The dissolve
    /// files no sweep of the scopes it cuts, also on an owed re-drive. A store
    /// fault proves neither answer, and a header that does not open may list
    /// `scope`, so its cut files no sweep and the idle sweep comes later.
    pub(super) async fn dissolving(&self, scope: NodeId) -> SeamResult<bool> {
        let journal = self.dissolve_journal();
        for root in journal.roots().await? {
            match journal.header(root).await? {
                HeaderSlot::Own(header) => {
                    if header.step == DissolveStep::Cut
                        && header.scopes.iter().any(|cut| cut.scope_id == scope)
                    {
                        return Ok(true);
                    }
                }
                HeaderSlot::Absent | HeaderSlot::Foreign => {}
                HeaderSlot::Unreadable => return Ok(true),
            }
        }
        Ok(false)
    }

    /// Whether an owed rotation entry names `scope`.
    async fn owes(&self, scope: NodeId) -> Result<bool, EngineError> {
        Ok(self
            .owed()
            .entry(scope)
            .await
            .map_err(EngineError::from_seam)?
            .is_some())
    }

    /// Cut every row of `header.scopes[at]`, or find it cut, then publish its
    /// final records again: its pointer, and its root when this drive cut
    /// nothing. A scope whose final records landed publishes nothing.
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
        if self.owes(scope).await? {
            return Ok(ScopeCut::Waiting);
        }
        let OwedScope {
            indexed,
            target,
            current,
            fell_back,
            ..
        } = self
            .owed_scope(sites, scope, "dissolve-cut", true)
            .await
            .map_err(EngineError::from_owed_stop)?;
        let rows = !current.commitment.entries.is_empty();
        let base = header.scopes[at].clone();
        let epoch = current.commitment.cut_epoch;
        // A nested root that another device moved out of the subtree is no
        // longer the dissolve's to cut.
        if at != 0 {
            let parent = NodeId(sites.enclosing(scope).await?.scope.scope_id);
            if header.scopes.iter().all(|cut| cut.scope_id != parent) {
                return Ok(ScopeCut::Concurrent);
            }
        }
        // After the baseline, a row at or above it, or a cut above it, is
        // work the dissolve did not do: a concurrent grant wins.
        if base.cut_time != 0 && (epoch > base.cut_epoch || rows && epoch >= base.cut_epoch) {
            return Ok(ScopeCut::Concurrent);
        }
        if base.final_landed {
            return Ok(ScopeCut::Done);
        }
        let name = parsed_scope_name(&target.scope.ipns_name)?;
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
        // A baseline that the scope never reached is cut to, so the guard
        // measures a row against an epoch that the scope holds.
        let short = base.cut_time != 0 && epoch < base.cut_epoch;
        let plan = GrantCutPlan::over(&current, &name, self.identity);
        // A last copy cannot prove that it holds no row, so it is cut too. The
        // read cascade refuses the refused root, so the name wave moves the
        // root off it first (ADR 0068 D1, D3, D5).
        let cut = (fell_back || rows || short)
            .then(|| recut_from_last_copy(&plan, fell_back))
            .transpose()
            .map_err(EngineError::from_revoke)?;
        // The baseline is durable before the first publish of the scope, for
        // the EOL term of the module header and for the guard above.
        let cut_epoch = cut.as_ref().map_or(epoch, |cut| cut.commitment.cut_epoch);
        if cut_epoch < base.cut_epoch {
            return Ok(ScopeCut::Concurrent);
        }
        if base.cut_time == 0 {
            let cut_time = self.scheduler.now().0;
            self.commit_dissolve(journal, hold, header, |header| {
                header.scopes[at].cut_epoch = cut_epoch;
                header.scopes[at].cut_time = cut_time;
            })
            .await?;
        }
        let target = match cut {
            Some(cut) => {
                let owed = self
                    .rotate_owed_cut(
                        scope,
                        &target,
                        &name,
                        &cut,
                        None,
                        current.write_epoch,
                        sites.command(),
                    )
                    .await?;
                // A raise waits for its cut set: one that never lands would hide
                // a grant made at the baseline it replaced. The link grants go
                // too, and a forget that fails answers after the raise, so the
                // next drive forgets again at the raised baseline.
                if owed != OwedCut::Unproved {
                    let forgot = self.forget_link_grants(scope).await;
                    if cut_epoch > header.scopes[at].cut_epoch {
                        self.commit_dissolve(journal, hold, header, |header| {
                            header.scopes[at].cut_epoch = cut_epoch;
                        })
                        .await?;
                    }
                    forgot?;
                }
                let Some(report) = owed.into_report() else {
                    return Ok(ScopeCut::Waiting);
                };
                record.retire_cut(&links);
                match report.write {
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
                        self.owed()
                            .clear(scope)
                            .await
                            .map_err(EngineError::from_owed_record)?;
                        OwnerScope {
                            scope: ChildScopeRef::new(
                                scope.0,
                                write.new_root_name.as_str().as_bytes().to_vec(),
                            ),
                            ..target
                        }
                    }
                    None => target,
                }
            }
            None => {
                self.republish_root(sites, &target, &name).await?;
                self.forget_link_grants(scope).await?;
                target
            }
        };
        if self.owes(scope).await? {
            return Ok(ScopeCut::Waiting);
        }
        republish_scope_pointer(
            &self.net(&target, PointerConsultArm::Refused),
            self.cut.owner_pointer_seed,
            self.cut.held,
            scope.0,
        )
        .await
        .map_err(|error| EngineError::from_rotate(RotateError::Publish(error)))?;
        self.commit_dissolve(journal, hold, header, |header| {
            header.scopes[at].final_landed = true;
        })
        .await?;
        Ok(ScopeCut::Done)
    }

    /// Before a stop drops the entry, forget the link grants of each scope
    /// that a cut at or above its baseline left with no row. Answers `false`
    /// while a listed scope owes a cut, so that cut lands first. A read or a
    /// forget that fails keeps the entry, so a later drive forgets again.
    async fn forget_landed(
        &self,
        sites: &impl ConversionSites,
        header: &DissolveHeader,
    ) -> Result<bool, EngineError> {
        let cut_scopes = || header.scopes.iter().filter(|cut| cut.cut_time != 0);
        for cut in cut_scopes() {
            if self.owes(cut.scope_id).await? {
                return Ok(false);
            }
        }
        for cut in cut_scopes() {
            let OwedScope {
                current, fell_back, ..
            } = self
                .owed_scope(sites, cut.scope_id, "dissolve-stop", true)
                .await
                .map_err(EngineError::from_owed_stop)?;
            // A last copy cannot prove that the scope holds no row.
            if !fell_back
                && current.commitment.entries.is_empty()
                && current.commitment.cut_epoch >= cut.cut_epoch
            {
                self.forget_link_grants(cut.scope_id).await?;
            }
        }
        Ok(true)
    }

    /// Drop the grant at `scope` from each contact a link sourced: the scope
    /// holds no row, so the book returns the room it took.
    async fn forget_link_grants(&self, scope: NodeId) -> Result<(), EngineError> {
        let contacts = StagingContactStore::new(self.staging, self.enc_secret, self.entropy);
        for (contact, source) in contacts
            .contacts_with_sources()
            .await
            .map_err(EngineError::from_contact_store)?
        {
            if source.is_some() {
                contacts
                    .forget_link_grant(&contact.identity_pk().to_sec1(), &scope.0)
                    .await
                    .map_err(EngineError::from_contact_store)?;
            }
        }
        Ok(())
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
        floor::advance_write_epoch_after_wave(self.floors, &scope.0, write.new_write_epoch)
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
                .owed_scope(sites, scope, "dissolve-scopes", true)
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
        let slot = pass
            .dissolve_journal()
            .header(root)
            .await
            .map_err(EngineError::from_seam)?;
        Ok(match slot {
            HeaderSlot::Own(header) => Some(header),
            HeaderSlot::Absent | HeaderSlot::Foreign | HeaderSlot::Unreadable => None,
        })
    }
}
