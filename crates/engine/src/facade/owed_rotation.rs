//! Owed rotation work (ADR 0063): the entry an owner command writes before its
//! first publish, and the re-drive that the sync pass and the same command run.
//!
//! Both run on the [`ConversionPass`], the one owner-action surface the tick
//! and a command share, and place each scope through its [`ConversionSites`].

use super::claim_conversion::{ConversionSites, Running};
use super::*;
use crate::grants::resume_owed_interior_move;
use crate::rotation::{RotateOnCutError, WriteRotateError, owed_read_cut};
use crate::sync::owed_rotation::{OwedEntry, OwedRecordError, OwedRotation, OwedStep};

/// What stopped one owed step: a key-material-free check, and whether a later
/// pass could clear it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwedStop {
    pub(crate) detail: String,
    pub(crate) retryable: bool,
}

impl OwedStop {
    fn of(step: &'static str, error: &EngineError) -> Self {
        let (class, retryable) = match error {
            EngineError::TrustViolation { .. } => ("trust-violation", false),
            EngineError::MalformedInput { check } | EngineError::UnsupportedTarget { check } => {
                (*check, false)
            }
            _ => ("unavailable", true),
        };
        Self {
            detail: format!("{step}: {class}"),
            retryable,
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
            retryable: error.class() == "availability",
        }
    }

    fn refused(detail: &'static str) -> Self {
        Self {
            detail: detail.to_owned(),
            retryable: false,
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
    /// An entry stands still: the command has nothing to add.
    StillOwed,
}

/// The check a re-drive reports for a write cut that the published scope says
/// targets another write epoch.
const OWED_WAVE_AT_ANOTHER_EPOCH: &str = "owed-write-cut-at-another-write-epoch";

/// The check a re-drive reports for a delivery whose recipient left the
/// contact book.
const OWED_RECIPIENT_UNKNOWN: &str = "owed-grant-recipient-unknown";

/// The check a re-drive reports for an interior move whose folder no longer
/// sits under the scope it left.
const OWED_MOVE_SOURCE_MOVED: &str = "owed-interior-move-source-moved";
/// The enclosing scope's index names no root for the owed scope.
const OWED_SCOPE_NOT_INDEXED: &str = "owed-scope-not-indexed";

impl EngineError {
    /// The refusal of an owed rotation entry that did not store before the
    /// first publish (ADR 0063 D2).
    fn from_owed_record(error: OwedRecordError) -> Self {
        EngineError::Seam {
            message: error.check().to_owned(),
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
    /// This session's owed rotation record.
    pub(crate) fn owed(&self) -> OwedRotation<'_, St> {
        OwedRotation {
            staging: self.staging,
            seal: self.seal(),
            enc_secret: self.enc_secret,
            cell: self.owed,
        }
    }

    /// Tell the host that work at `scope_root` is still owed.
    pub(crate) fn report_owed(&self, scope_root: NodeId, stop: OwedStop) {
        let _ = self.events.unbounded_send(Event::RotationWorkOwed {
            scope_root,
            detail: stop.detail,
            retryable: stop.retryable,
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
    /// leaves the session's copy holding them, which this pass still re-drives.
    pub(crate) async fn stop_owed(&self, scope: NodeId, steps: Vec<OwedStep>, stop: OwedStop) {
        if let Ok(Some(mut entry)) = self.owed().entry(scope).await {
            entry.steps = steps;
            let _ = self.owed().owe(scope, entry).await;
        }
        self.report_owed(scope, stop);
    }

    /// Drive `cut` at `node` under an owed rotation entry (ADR 0063 D2, D5):
    /// the entry is durable before the first publish, and a step that stops
    /// after it leaves the entry and answers `Ok(None)`. `write_epoch` is the
    /// write epoch of the record the cut was authorized against.
    ///
    /// A read-only cut clears its entry here. A cut that moves the write plane
    /// leaves it for the caller, which clears it after the post-steps.
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
            Some(OwedStep::WriteCut {
                write_epoch: write_epoch
                    .checked_add(1)
                    .ok_or_else(|| EngineError::from_rotation(WriteRotateError::EpochExhausted))?,
            })
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
                steps: steps.clone(),
            },
        )
        .await?;
        let report = match self
            .rotate_planes(node, target, scope_root_name, cut, vault_pointer_signer)
            .await
        {
            Ok(report) => report,
            // The wave runs last, so the cut set is published.
            Err(error @ RotateOnCutError::Write(_)) => {
                self.stop_owed(node, write.into_iter().collect(), cut_stop(&error))
                    .await;
                return Ok(None);
            }
            Err(error) => {
                return match self.cut_set_published(target, cut).await {
                    Some(true) => {
                        self.stop_owed(node, steps, cut_stop(&error)).await;
                        Ok(None)
                    }
                    Some(false) => {
                        let _ = self.owed().clear(node).await;
                        Err(EngineError::from_rotation(error))
                    }
                    // Unknown: the entry stands, and the re-drive drops it if
                    // the published root never carried the cut.
                    None => Err(EngineError::from_rotation(error)),
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
        let current = self
            .net(target, PointerConsultArm::Refused)
            .resolve_anchored(&target.scope)
            .await
            .ok()?;
        Some(current.commitment == cut.commitment && current.grant_ledger == cut.grant_ledger)
    }

    /// Re-drive every owed entry, and tell the host of each one still owed
    /// (ADR 0063 D3). A conversion pass or a command that holds [`Running`]
    /// may be driving the same scope, so the pass then leaves the record to
    /// the next pass.
    pub(crate) async fn redrive_owed(&self, sites: &impl ConversionSites) {
        let Some(_running) = Running::take(self.running) else {
            return;
        };
        // A record that does not read is read again by the next pass.
        let Ok(record) = self.owed().load().await else {
            return;
        };
        for (scope, entry) in record {
            if let Err(stop) = self.redrive_entry(sites, scope, entry).await {
                self.report_owed(scope, stop);
            }
        }
    }

    /// Re-drive the entry at `scope`, if one stands, before a command acts
    /// there (ADR 0063 D5), and tell the host when it is still owed.
    pub(crate) async fn redrive_scope(
        &self,
        sites: &impl ConversionSites,
        scope: NodeId,
    ) -> Result<Redriven, EngineError> {
        let Some(entry) = self
            .owed()
            .entry(scope)
            .await
            .map_err(EngineError::from_seam)?
        else {
            return Ok(Redriven::NoEntry);
        };
        let Some(_running) = Running::take(self.running) else {
            return Ok(Redriven::StillOwed);
        };
        match self.redrive_entry(sites, scope, entry).await {
            Ok(()) => Ok(Redriven::Finished),
            Err(stop) => {
                self.report_owed(scope, stop);
                Ok(Redriven::StillOwed)
            }
        }
    }

    /// Run the steps `entry` still owes at `scope` in order, advancing the
    /// record as each lands, then its post-steps, then clear it.
    async fn redrive_entry(
        &self,
        sites: &impl ConversionSites,
        scope: NodeId,
        entry: OwedEntry,
    ) -> Result<(), OwedStop> {
        for (at, step) in entry.steps.iter().enumerate() {
            let landed = match step {
                OwedStep::InteriorMove { left_scope } => {
                    self.redrive_interior_move(sites, scope, *left_scope).await
                }
                OwedStep::ReadCut => self.redrive_read_cut(sites, scope, entry.cut_epoch).await,
                OwedStep::WriteCut { write_epoch } => {
                    self.redrive_write_cut(sites, scope, *write_epoch).await
                }
                OwedStep::DeliverGrant {
                    recipient_identity_pk,
                    write,
                } => {
                    self.redrive_delivery(sites, scope, recipient_identity_pk, *write)
                        .await
                }
            }?;
            if landed == Landed::NothingOwed {
                let _ = self.owed().clear(scope).await;
                return Ok(());
            }
            if let Some(next) = entry.steps.get(at + 1) {
                let _ = self.owed().advance_to(scope, next).await;
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
    /// gated. Below the vault root the place is read off the enclosing scope's
    /// signed index: a sync pass proves no material for a scope whose write cut
    /// stopped, because the write seed it holds does not derive the name the
    /// scope answers at.
    async fn owed_scope(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
    ) -> Result<OwedScope, EngineError> {
        let placed = if node == self.cut.vault_root {
            sites.place(node).await?
        } else {
            self.indexed_place(sites, node).await?
        };
        let target = self
            .moved_root(node, &placed)
            .await?
            .unwrap_or_else(|| placed.clone());
        let current = self
            .net(&target, PointerConsultArm::Refused)
            .resolve_anchored(&target.scope)
            .await
            .map_err(EngineError::from_resolve_failure)?;
        Ok(OwedScope {
            indexed: placed.scope.ipns_name,
            target,
            current,
        })
    }

    /// The scope root at `node` as the enclosing scope's index names it.
    async fn indexed_place(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
    ) -> Result<OwnerScope, EngineError> {
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
            .cloned()
            .ok_or(EngineError::UnsupportedTarget {
                check: OWED_SCOPE_NOT_INDEXED,
            })?;
        Ok(OwnerScope::indexed(&enclosing, indexed))
    }

    /// Re-seal the interior a stalled grant left in `left_scope` into the
    /// scope promoted at `node`, through the resume path of a grant against
    /// the promoted root, so an append stays an append (ADR 0026 D1).
    async fn redrive_interior_move(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        left_scope: NodeId,
    ) -> Result<Landed, OwedStop> {
        let step = "owed-interior-move";
        let stop = |e: EngineError| OwedStop::of(step, &e);
        let parent = sites.enclosing(node).await.map_err(stop)?;
        if parent.scope.scope_id != left_scope.0 {
            return Err(OwedStop::refused(OWED_MOVE_SOURCE_MOVED));
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
        };
        let parent_plan = ParentScopePlan {
            identity: ScopeRootIdentity {
                v: current.v,
                scope_id: parent.scope.scope_id,
                ipns_name: &parent.scope.ipns_name,
                owner_enc_pub: &current.owner_enc_pub,
                owner_enc_secret: Some(self.enc_secret),
                ascent: parent
                    .parent_node_seed
                    .as_deref()
                    .map(AscentAuthority::ParentSeed),
                owes_ascent_link: current.carried_ascent_link,
                pseudonym_signer: &current.pseudonym_signer,
            },
            seeds: ResealSeeds {
                override_seed: &current.override_seed,
                read_epoch: current.current_read_epoch,
                prev: None,
                write_scope_seed: &current.write_scope_seed,
                write_epoch: current.write_epoch,
                write_history: WriteHistory::Carried(&current.write_history_link),
                pointer_read_key: &current.pointer_read_key,
            },
            commitment: &current.commitment,
            commitment_sig: &current.commitment_sig,
            grant_ledger: &current.grant_ledger,
            current_child_index: &current.direct_child_scope_index,
            carried_history_links: &current.carried_history_links,
        };
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
            Ok(Some(_)) => Ok(Landed::Step),
            // No root was promoted, so the grant never published.
            Ok(None) => Ok(Landed::NothingOwed),
            Err(e) => Err(OwedStop::of_grant(&e)),
        }
    }

    /// Run the read cascade the published cut set still owes at `node`.
    async fn redrive_read_cut(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        cut_epoch: u64,
    ) -> Result<Landed, OwedStop> {
        let stop = |e: EngineError| OwedStop::of("owed-read-cut", &e);
        let OwedScope {
            target, current, ..
        } = self.owed_scope(sites, node).await.map_err(stop)?;
        // Below the entry's epoch the cut set never landed; above it a later
        // cut re-keyed the scope.
        if current.commitment.cut_epoch < cut_epoch {
            return Ok(Landed::NothingOwed);
        }
        if current.commitment.cut_epoch > cut_epoch {
            return Ok(Landed::Step);
        }
        let scope_root_name = parsed_scope_name(&target.scope.ipns_name).map_err(stop)?;
        let cut = owed_read_cut(&GrantCutPlan {
            commitment: &current.commitment,
            commitment_sig: &current.commitment_sig,
            grant_ledger: &current.grant_ledger,
            scope_root_name: &scope_root_name,
            owner_signer: self.identity,
            pointer_read_key: &current.pointer_read_key,
        })
        .map_err(|e| stop(EngineError::from_revoke(e)))?;
        self.rotate_planes(node, &target, &scope_root_name, &cut, None)
            .await
            .map_err(|e| cut_stop(&e))?;
        Ok(Landed::Step)
    }

    /// Run the name wave the scope at `node` still owes at `write_epoch`,
    /// unless it has landed, then its write-epoch floor raise and index
    /// re-point.
    async fn redrive_write_cut(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        write_epoch: u64,
    ) -> Result<Landed, OwedStop> {
        let stop = |e: EngineError| OwedStop::of("owed-write-cut", &e);
        let OwedScope {
            indexed,
            target,
            current,
        } = self.owed_scope(sites, node).await.map_err(stop)?;
        let (root_name, landed_epoch) = if current.write_epoch >= write_epoch {
            (
                parsed_scope_name(&target.scope.ipns_name).map_err(stop)?,
                current.write_epoch,
            )
        } else if current.write_epoch.checked_add(1) == Some(write_epoch) {
            let scope_root_name = parsed_scope_name(&target.scope.ipns_name).map_err(stop)?;
            let cut = cut_for_write_scope(&GrantCutPlan {
                commitment: &current.commitment,
                commitment_sig: &current.commitment_sig,
                grant_ledger: &current.grant_ledger,
                scope_root_name: &scope_root_name,
                owner_signer: self.identity,
                pointer_read_key: &current.pointer_read_key,
            })
            .map_err(|e| stop(EngineError::from_revoke(e)))?;
            let write = self
                .rotate_planes(node, &target, &scope_root_name, &cut, None)
                .await
                .map_err(|e| cut_stop(&e))?
                .write
                .ok_or_else(|| OwedStop::refused("owed-write-cut-ran-no-wave"))?;
            (write.new_root_name, write.new_write_epoch)
        } else {
            return Err(OwedStop::refused(OWED_WAVE_AT_ANOTHER_EPOCH));
        };
        floor::advance_write_epoch_on_sight(self.floors, &node.0, landed_epoch)
            .await
            .map_err(|e| stop(EngineError::from_seam(e)))?;
        if indexed != root_name.as_str().as_bytes() {
            let parent = sites.enclosing(node).await.map_err(stop)?;
            self.repoint(&parent, node, &root_name)
                .await
                .map_err(stop)?;
        }
        Ok(Landed::Step)
    }

    /// Post the share pointer a grant still owes its recipient, at the name the
    /// scope answers at now.
    async fn redrive_delivery(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        recipient_identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
        write: bool,
    ) -> Result<Landed, OwedStop> {
        let stop = |e: EngineError| OwedStop::of("owed-grant-delivery", &e);
        let contacts = StagingContactStore::new(self.staging, self.enc_secret, self.entropy);
        let contact = match resolve_recipient(&contacts, recipient_identity_pk).await {
            Ok(contact) => contact,
            Err(ContactStoreError::RecipientNotImported) => {
                return Err(OwedStop::refused(OWED_RECIPIENT_UNKNOWN));
            }
            Err(e) => return Err(stop(EngineError::from_contact_store(e))),
        };
        let OwedScope { target, .. } = self.owed_scope(sites, node).await.map_err(stop)?;
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
        Ok(Landed::Step)
    }
}

/// How an owed step ended when it did not stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Landed {
    /// The step landed, now or before.
    Step,
    /// The published state shows the entry's first publish never landed, so
    /// nothing at all is owed.
    NothingOwed,
}

/// The scope an owed step acts on: the name the parent's index gives it, and
/// the root its pointer vouches for, gated.
struct OwedScope {
    indexed: Vec<u8>,
    target: OwnerScope,
    current: CascadeTarget,
}

/// The stop a plane rotation failure reports.
fn cut_stop(error: &RotateOnCutError) -> OwedStop {
    OwedStop {
        detail: error.check().to_owned(),
        retryable: error.is_retryable(),
    }
}
