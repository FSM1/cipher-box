//! The owner's expired-link sweep
//! ([ADR 0025](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0025-revocation-under-the-link-first-model.md)
//! D2, blueprint/engine.md "Triggers"): walk `directChildScopeIndex` from the
//! vault root with one resolve and one unseal per scope root, and cut every
//! link entry whose deadline the injected `now` has reached.
//!
//! The tick runs it on [`SyncTimingProfile::link_sweep_cadence`], after the
//! conversion pass, under [`Running`]. Each folder takes one cut for all its
//! expired links. Each cut resolves its scope root again right before it
//! signs, so a link that another owner device already cut costs nothing here.

use super::claim_conversion::HeldRecord;
use super::*;
use crate::grants::{CommittedLink, expired_links};

/// Why a sweep cut refuses: a link entry is always committed at `read`, so a
/// cut of expired links never moves the write plane.
const SWEEP_CUT_MOVES_THE_WRITE_PLANE: &str = "an expired-link cut named a write row";

/// The most cuts that land in one sweep. The rest wait for the next sweep, so
/// one sweep holds [`Running`] for a bounded time. A failed cut does not
/// count, so failures cannot hide the scope roots behind them.
pub(super) const MAX_SWEEP_CUTS: usize = 8;

/// What one sweep did.
#[derive(Debug, Default)]
pub(super) struct LinkSweepReport {
    /// Every scope root a cut re-keyed, the cut scope roots and their
    /// descendants.
    pub(super) rekeyed: Vec<NodeId>,
    /// The first trust violation, else the first failure. A failed walk or
    /// cut leaves its links for the next sweep.
    pub(super) failure: Option<EngineError>,
    /// Whether the sweep stopped at [`MAX_SWEEP_CUTS`] landed cuts with
    /// scope roots left to cut.
    pub(super) more: bool,
}

impl LinkSweepReport {
    fn fail(&mut self, error: EngineError) {
        let replaces = match &self.failure {
            None => true,
            Some(EngineError::TrustViolation { .. }) => false,
            Some(_) => matches!(error, EngineError::TrustViolation { .. }),
        };
        if replaces {
            self.failure = Some(error);
        }
    }
}

/// The committed-set cut of the expired links `tags`. Release-active: no
/// vault pointer signer rides a sweep cut, so a write wave here could not
/// re-point a moved vault root (AGENTS.md rule 8).
fn sweep_cut(
    plan: &GrantCutPlan<'_>,
    tags: &BTreeSet<[u8; 32]>,
) -> Result<RevokedCommittedSet, EngineError> {
    let cut = revoke_grants(plan, tags).map_err(EngineError::from_revoke)?;
    if cut.planes().write() {
        return Err(EngineError::Seam {
            message: SWEEP_CUT_MOVES_THE_WRITE_PLANE.to_owned(),
        });
    }
    Ok(cut)
}

/// Run `cut` over `due` deepest first until [`MAX_SWEEP_CUTS`] cuts land.
/// Answers whether scope roots were left. Deepest first: a cut re-keys its own
/// subtree only, so the placement the walk read for each shallower scope root
/// still stands.
async fn cut_deepest_first<T>(due: &[T], mut cut: impl AsyncFnMut(&T) -> bool) -> bool {
    let mut landed = 0;
    for target in due.iter().rev() {
        if landed == MAX_SWEEP_CUTS {
            return true;
        }
        if cut(target).await {
            landed += 1;
        }
    }
    false
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
    /// Walk the vault from `root_name` and cut expired links until
    /// [`MAX_SWEEP_CUTS`] cuts land. `None` while a pass or a cut holds
    /// [`Running`].
    pub(super) async fn sweep_links(
        &self,
        root_name: &IpnsName,
        pointers: &PointerIndex,
    ) -> Option<LinkSweepReport> {
        let mut report = LinkSweepReport::default();
        let mut held = match self.hold_record().await {
            Ok(Some(held)) => held,
            Ok(None) => return None,
            Err(e) => {
                report.fail(e);
                return Some(report);
            }
        };
        let now = self.scheduler.now();
        let pending = held.pending_links();
        let due = self
            .walk(root_name, now, &pending, &mut held, pointers, &mut report)
            .await;
        report.more = cut_deepest_first(&due, async |target| {
            match self.cut_expired(target, now, &pending).await {
                Ok((rekeyed, senders)) => {
                    report.rekeyed.extend(rekeyed);
                    held.retire_cut(&senders);
                    true
                }
                Err(e) => {
                    report.fail(e);
                    false
                }
            }
        })
        .await;
        if let Err(e) = self.settle(held, pointers).await {
            report.fail(e);
        }
        Some(report)
    }

    /// The links the set `current` publishes at `target` commits.
    fn committed_at(
        &self,
        target: &OwnerScope,
        current: &CascadeTarget,
    ) -> Result<Vec<CommittedLink>, EngineError> {
        let commitment_sig = parsed_commitment_sig(&current.commitment_sig)?;
        committed_links(
            &OwnerAuthority {
                identity_signer: self.identity,
                enc_secret: self.enc_secret,
            },
            &bound_scope(target, current, &commitment_sig)?,
        )
        .map_err(EngineError::from_invite)
    }

    /// The scope roots that carry an expired link, the vault root first, in
    /// walk order. Each scope root the walk reaches also retires the refused
    /// entries of the links it no longer commits.
    ///
    /// Each scope root resolves under the parent that named it, and counts as
    /// visited only once it passed the gate: an index entry that names a scope
    /// under the wrong parent fails there, and the parent that really holds it
    /// still reaches it. A scope root that no parent resolves is left, with its
    /// subtree, for the next sweep.
    async fn walk(
        &self,
        root_name: &IpnsName,
        now: UnixMillis,
        pending: &[[u8; IDENTITY_PUBLIC_LEN]],
        held: &mut HeldRecord<'_>,
        pointers: &PointerIndex,
        report: &mut LinkSweepReport,
    ) -> Vec<OwnerScope> {
        let mut visited = BTreeSet::new();
        let mut tried = BTreeSet::new();
        let root = self.cut.vault_root.0;
        // The vault root carries no ascent link, so it alone has no parent seed.
        let mut frontier = vec![(
            root,
            OwnerScope {
                scope: ChildScopeRef::new(root, root_name.as_str().as_bytes().to_vec()),
                parent_node_seed: None,
                vouched: true,
            },
        )];
        let mut due = Vec::new();
        while !frontier.is_empty() {
            let mut next = Vec::new();
            for (parent, target) in frontier {
                let id = target.scope.scope_id;
                if visited.contains(&id) || !tried.insert((parent, id)) {
                    continue;
                }
                let current = match self
                    .net(&target, PointerConsultArm::Refused)
                    .resolve_anchored(&target.scope)
                    .await
                {
                    Ok(current) => current,
                    Err(e) => {
                        report.fail(EngineError::from_resolve_failure(e));
                        continue;
                    }
                };
                visited.insert(id);
                next.extend(current.direct_child_scope_index.iter().map(|child| {
                    let seed = kdf::node_seed(&current.override_seed, &child.scope_id);
                    let child = OwnerScope {
                        scope: child.clone(),
                        parent_node_seed: Some(Zeroizing::new(*seed.as_bytes())),
                        vouched: true,
                    };
                    (id, child)
                }));
                match self.committed_at(&target, &current) {
                    Ok(links) => {
                        held.retire_uncommitted(NodeId(id), &links, pointers);
                        if !expired_links(&links, now, pending).is_empty() {
                            due.push(target);
                        }
                    }
                    Err(e) => report.fail(e),
                }
            }
            frontier = next;
        }
        due
    }

    /// Cut every expired link at `target` in one cut, over the record as it
    /// stands now. Answers the scope roots the cut re-keyed and the ephemeral
    /// identities of the links it cut.
    async fn cut_expired(
        &self,
        target: &OwnerScope,
        now: UnixMillis,
        pending: &[[u8; IDENTITY_PUBLIC_LEN]],
    ) -> Result<(Vec<NodeId>, Vec<[u8; IDENTITY_PUBLIC_LEN]>), EngineError> {
        let current = self
            .net(target, PointerConsultArm::Refused)
            .resolve_anchored(&target.scope)
            .await
            .map_err(EngineError::from_resolve_failure)?;
        let links = self.committed_at(target, &current)?;
        let tags = expired_links(&links, now, pending);
        if tags.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let scope_root_name = parsed_scope_name(&target.scope.ipns_name)?;
        let cut = sweep_cut(
            &GrantCutPlan {
                commitment: &current.commitment,
                commitment_sig: &current.commitment_sig,
                grant_ledger: &current.grant_ledger,
                scope_root_name: &scope_root_name,
                owner_signer: self.identity,
                pointer_read_key: &current.pointer_read_key,
            },
            &tags,
        )?;
        let node = NodeId(target.scope.scope_id);
        let report = self
            .rotate_cut(node, target, &scope_root_name, &cut, None)
            .await?;
        let rekeyed = report
            .read
            .map(|read| {
                read.rekeyed
                    .iter()
                    .map(|scope| NodeId(scope.scope_id))
                    .collect()
            })
            .unwrap_or_default();
        let senders = links
            .iter()
            .filter(|link| tags.contains(&link.tag))
            .map(|link| link.ephemeral_identity_pk)
            .collect();
        Ok((rekeyed, senders))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::invite::{EphemeralInvitee, LinkTerms, mint_invite_grant};
    use crate::grants::ledger::mint_grant_row;
    use crate::rotation::derive_write_name;
    use cipherbox_core::seal::{
        GrantSetCommitment, Permission as CorePermission, PreservedFields, sign_grant_set,
    };

    fn seam() -> EngineError {
        EngineError::Seam {
            message: "seam".to_owned(),
        }
    }

    /// Answers whether roots were left, and the order `cut` saw them in.
    fn cut_order(due: usize, lands: impl Fn(usize) -> bool) -> (bool, Vec<usize>) {
        let roots: Vec<usize> = (0..due).collect();
        let mut tried = Vec::new();
        let more = {
            let run = core::pin::pin!(cut_deepest_first(&roots, async |root| {
                tried.push(*root);
                lands(*root)
            }));
            let core::task::Poll::Ready(more) = run.poll(&mut core::task::Context::from_waker(
                core::task::Waker::noop(),
            )) else {
                panic!("the cuts are ready");
            };
            more
        };
        (more, tried)
    }

    /// Only a landed cut counts toward the cap, so eight cuts that fail on
    /// every sweep do not hide the ninth scope root, and a sweep that tried
    /// every root reports none left, which advances the cadence.
    #[test]
    fn failed_sweep_cuts_do_not_count_toward_the_cut_cap() {
        let (more, tried) = cut_order(MAX_SWEEP_CUTS + 1, |root| root == 0);
        assert_eq!(tried, (0..=MAX_SWEEP_CUTS).rev().collect::<Vec<_>>());
        assert!(!more, "the sweep tried every root");

        let (more, tried) = cut_order(MAX_SWEEP_CUTS + 1, |_| true);
        assert_eq!(tried.len(), MAX_SWEEP_CUTS);
        assert!(more, "the cap left the ninth root");
    }

    fn trust() -> EngineError {
        EngineError::TrustViolation {
            message: "trust".to_owned(),
        }
    }

    /// The abuse event reads the report, so a trust violation outranks any
    /// earlier failure and is never replaced.
    #[test]
    fn the_report_keeps_a_trust_violation_over_any_other_failure() {
        let mut report = LinkSweepReport::default();
        report.fail(seam());
        report.fail(trust());
        report.fail(seam());
        assert_eq!(report.failure, Some(trust()));

        let mut report = LinkSweepReport::default();
        report.fail(seam());
        report.fail(seam());
        assert_eq!(report.failure, Some(seam()));
    }

    /// A link entry is committed at `read` on both sides of the codec, so a
    /// sweep never names a write row. The refusal holds without that: fed a
    /// write row, the sweep cut refuses before anything rotates.
    #[test]
    fn a_sweep_cut_that_names_a_write_row_is_refused() {
        const SCOPE: [u8; 16] = [0x01; 16];
        const PRK: [u8; 32] = [0x66; 32];
        let owner = EcdsaSigner::from_scalar(&[0x33; 32]).unwrap();
        let enc = X25519Secret::from_scalar([0x5b; 32]);
        let name = derive_write_name(&[0x5a; 32], &SCOPE);
        let link = mint_invite_grant(
            &owner,
            &enc,
            &PRK,
            &EphemeralInvitee::from_secret(&[0x95; 32]).unwrap(),
            &SCOPE,
            &[0x5a; 32],
            &LinkTerms {
                deadline: UnixMillis(1_000),
                conversion_permission: CorePermission::Read,
                admission_cap: 5,
            },
        )
        .unwrap();
        let writer = mint_grant_row(
            &owner,
            &enc,
            &PRK,
            [0x13; 33],
            &X25519Secret::from_scalar([0x13; 32]).public(),
            &SCOPE,
            name.as_str().as_bytes(),
            CorePermission::Write,
        )
        .unwrap();
        let (link_tag, writer_tag) = (link.tag, writer.tag);
        let rows = [link, writer];
        let commitment = GrantSetCommitment {
            ipns_name: name.as_str().as_bytes().to_vec(),
            owner_pseudonym_pk: [0x88; 32],
            cut_epoch: 0,
            entries: rows.iter().map(|r| r.commitment_entry.clone()).collect(),
            unknown: PreservedFields::new(),
        };
        let commitment_sig = sign_grant_set(&owner, &commitment).unwrap().to_compact();
        let ledger: Vec<GrantLedgerEntry> = rows.into_iter().map(|r| r.ledger_entry).collect();
        let plan = GrantCutPlan {
            commitment: &commitment,
            commitment_sig: &commitment_sig,
            grant_ledger: &ledger,
            scope_root_name: &name,
            owner_signer: &owner,
            pointer_read_key: &PRK,
        };

        assert!(sweep_cut(&plan, &BTreeSet::from([link_tag])).is_ok());
        assert_eq!(
            sweep_cut(&plan, &BTreeSet::from([link_tag, writer_tag])).map(|_| ()),
            Err(EngineError::Seam {
                message: SWEEP_CUT_MOVES_THE_WRITE_PLANE.to_owned()
            })
        );
    }
}
