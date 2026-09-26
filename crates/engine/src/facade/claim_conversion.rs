//! The owner conversion pass (ADR 0023 D3–D7, ADR 0026 E1): any owner device
//! acks each claim item that names one of its scope pointers, holds the acked
//! claim as a conversion entry in its conversion record, and converts it into
//! a personal grant, with one root publish per folder per pass.
//!
//! The tick runs the pass on every pass, and [`Command::ConvertInviteClaims`]
//! runs it for one folder when the share dialog opens. Both drive the one
//! implementation here under the same cut authority; they differ only in how
//! they place a folder ([`ConversionSites`]).

use super::*;
use crate::grants::conversion::{
    ConversionRecord, ConversionRefusal, EntryState, Hold, MAX_CLAIM_PAYLOAD_BYTES,
    POINTER_RETRY_WINDOW, PointerDue, Verdict, load_conversions, persist_conversions,
};
use crate::grants::create::MINT_EPOCH;
use crate::grants::inbox::OwnedClaim;
use crate::grants::{
    AckedClaim, ClaimDisposition, CommittedLink, GrantRecipient, fingerprint_identity_key,
    link_of_sender, post_share_pointer_at,
};
use crate::net::rotation::{OnAccessMiss, OnAccessMisses, OwnerScopeKeys};
use crate::rotation::cut_for_write_scope;
use crate::sync::BookkeepingSeal;

/// The refusal a record change answers while a conversion pass runs.
pub(super) const CONVERSION_RUNNING: &str = "a-conversion-pass-is-running";

/// The failure of an intake that left a claim on the mailbox because the
/// conversion record is full.
pub(super) const CONVERSION_RECORD_FULL: &str = "the-conversion-record-is-full";

/// The failure of an intake that left a claim on the mailbox because the
/// conversion record did not persist before the delete.
pub(super) const CLAIM_NOT_HELD: &str = "a-claim-could-not-be-held";

/// What a conversion pass answers. An intake failure leaves a claim on the
/// mailbox; a conversion failure leaves its entry in the record.
pub(super) struct PassOutcome {
    pub(super) intake: Result<(), EngineError>,
    pub(super) conversion: Result<(), EngineError>,
}

impl PassOutcome {
    pub(super) fn unheld(e: EngineError) -> Self {
        Self {
            intake: Err(e),
            conversion: Ok(()),
        }
    }

    /// The first failure, the intake's before the conversion's.
    pub(super) fn into_result(self) -> Result<(), EngineError> {
        self.intake.and(self.conversion)
    }
}

/// The claim counts the snapshot and the sharing read show per scope root and
/// per link. In memory: the conversion record is the authority, and every pass
/// counts it again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaimCounts {
    /// Keyed by the scope root and the link's ephemeral identity, which
    /// signed the claim.
    pending: BTreeMap<(NodeId, [u8; IDENTITY_PUBLIC_LEN]), u32>,
    refused: BTreeMap<(NodeId, [u8; IDENTITY_PUBLIC_LEN]), u32>,
}

impl ClaimCounts {
    /// Count `record` at the scope root each entry's claim names.
    fn of(record: &ConversionRecord, pointers: &PointerIndex) -> Self {
        let mut counts = Self::default();
        for entry in record.entries() {
            let Some(node) = claimed_pointer(&entry.claim).and_then(|p| placed(pointers, &p))
            else {
                continue;
            };
            let counted = match entry.state {
                EntryState::Refused(_) => &mut counts.refused,
                EntryState::Acking | EntryState::Pending => &mut counts.pending,
                EntryState::PointerDue(_) => continue,
            };
            let count = counted.entry((node, entry.claim.sender)).or_default();
            *count = count.saturating_add(1);
        }
        counts
    }

    /// The conversions still pending at `node`, over every link.
    pub(crate) fn pending(&self, node: NodeId) -> u32 {
        self.pending
            .range((node, [0; IDENTITY_PUBLIC_LEN])..=(node, [u8::MAX; IDENTITY_PUBLIC_LEN]))
            .fold(0, |sum, (_, count)| sum.saturating_add(*count))
    }

    /// The conversions still pending at `node` that the link `link` signed.
    pub(crate) fn link_pending(&self, node: NodeId, link: &[u8; IDENTITY_PUBLIC_LEN]) -> u32 {
        self.pending.get(&(node, *link)).copied().unwrap_or(0)
    }

    /// The conversions refused at a cap at `node` that the link `link` signed.
    pub(crate) fn link_refused(&self, node: NodeId, link: &[u8; IDENTITY_PUBLIC_LEN]) -> u32 {
        self.refused.get(&(node, *link)).copied().unwrap_or(0)
    }
}

/// The scope pointer an acked claim names, or `None` for a payload that does
/// not decode.
pub(super) fn claimed_pointer(claim: &AckedClaim) -> Option<IpnsName> {
    InviteClaim::decode(&claim.payload)
        .ok()
        .map(|claim| claim.scope_pointer_name)
}

/// Each owned scope root under its scope pointer name, in canonical form.
pub(super) type PointerIndex = BTreeMap<String, NodeId>;

/// Each of `roots` under its scope pointer name, built once per pass.
pub(super) fn scope_pointer_index(
    keys: &dyn OwnerScopeKeys,
    roots: impl IntoIterator<Item = NodeId>,
) -> PointerIndex {
    roots
        .into_iter()
        .map(|root| (keys.pointer_name(&root.0).as_str().to_owned(), root))
        .collect()
}

/// The scope root `pointer` names in `index`.
pub(super) fn placed(index: &PointerIndex, pointer: &IpnsName) -> Option<NodeId> {
    index.get(pointer.as_str()).copied()
}

/// Where a conversion pass finds each folder it converts at.
pub(super) trait ConversionSites {
    /// The scope root at `node`, placed for a gated owner read.
    async fn place(&self, node: NodeId) -> Result<OwnerScope, EngineError>;

    /// The scope root whose direct-child-scope index names `node`.
    async fn enclosing(&self, node: NodeId) -> Result<OwnerScope, EngineError>;

    /// The folder label the claimant's share pointer carries.
    async fn folder_name(&self, node: NodeId) -> Result<String, EngineError>;
}

/// What a write-scope cut needs beyond the conversion itself (ADR 0024 D4).
/// The command and the tick hold the same.
pub(super) struct CutAuthority<'a> {
    /// Derives the scope pointer's name and its record signer.
    pub(super) owner_pointer_seed: &'a [u8; SECRET_LEN],
    /// The session's held set, which the write wave enrols the flipped scope
    /// pointer in.
    pub(super) held: &'a RefCell<HeldRecords>,
    pub(super) sweep: &'a SweepTaskFactory,
    pub(super) vault_root: NodeId,
}

/// The seams and the owner material one conversion pass runs on.
pub(super) struct ConversionPass<'a, T, H: Http, C: CredentialStore, F, Sch, S, St> {
    pub(super) transport: &'a T,
    pub(super) api: &'a ApiClient<H, C>,
    pub(super) gateway: &'a Gateway,
    pub(super) http: &'a H,
    pub(super) floors: &'a F,
    pub(super) snapshot_cache: &'a S,
    pub(super) events: &'a mpsc::UnboundedSender<Event>,
    pub(super) scheduler: &'a Sch,
    pub(super) profile: &'a SyncTimingProfile,
    /// The session's on-access consult misses ([`OnAccessMisses`]).
    pub(super) on_access_misses: &'a OnAccessMisses,
    pub(super) entropy: &'a RefCell<Box<dyn Entropy>>,
    pub(super) staging: &'a St,
    /// Signs the re-signed commitment, each minted row and each share pointer.
    pub(super) identity: &'a EcdsaSigner,
    pub(super) enc_secret: &'a X25519Secret,
    pub(super) owner_identity: &'a EcdsaVerifier,
    pub(super) scope_keys: &'a dyn OwnerScopeKeys,
    pub(super) cut: CutAuthority<'a>,
    /// Whether a walk this session named every scope root it holds. Until one
    /// has, a claim that names no known folder may name one not walked yet.
    pub(super) scope_roots_walked: &'a Cell<bool>,
    /// Where the pass leaves the counts it read off the record.
    pub(super) counts: &'a RefCell<ClaimCounts>,
    /// Set while a pass or a record change runs. The tick and a command share
    /// one record, so a second writer that overlapped the first could write
    /// back a record that lacks the claims the first acked.
    pub(super) running: &'a Cell<bool>,
}

/// Holds [`ConversionPass::running`] and clears it however the holder ends.
///
/// A cut of a link holds it too: the cut removes the link row a conversion
/// reads, so the cut and the pass exclude each other, and a link with a
/// pending conversion entry is never cut (ADR 0023 D4).
pub(super) struct Running<'a>(&'a Cell<bool>);

impl<'a> Running<'a> {
    /// The flag, or `None` while another holder has it.
    pub(super) fn take(flag: &'a Cell<bool>) -> Option<Self> {
        (!flag.replace(true)).then(|| Self(flag))
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

/// The conversion record, read under [`Running`] for a cut of a link.
/// [`ConversionPass::settle`] writes back the entries it retired.
pub(super) struct HeldRecord<'a> {
    _running: Running<'a>,
    record: ConversionRecord,
    retired: bool,
}

impl HeldRecord<'_> {
    /// The ephemeral identities that send a pending conversion entry.
    pub(super) fn pending_links(&self) -> Vec<[u8; IDENTITY_PUBLIC_LEN]> {
        self.record.pending().map(|claim| claim.sender).collect()
    }

    fn retire(&mut self, retired: impl Fn(&AckedClaim) -> bool) {
        if self.record.retire_refused(retired) > 0 {
            self.retired = true;
        }
    }

    /// Retire the refused entries the links in `cut` sent, once their cut
    /// landed.
    pub(super) fn retire_cut(&mut self, cut: &[[u8; IDENTITY_PUBLIC_LEN]]) {
        self.retire(|claim| cut.contains(&claim.sender));
    }

    /// Retire the refused entries at the scope root `node` that no link in
    /// `links`, the set it commits now, sent. This catches the entries of a
    /// landed cut whose own retire did not persist.
    pub(super) fn retire_uncommitted(
        &mut self,
        node: NodeId,
        links: &[CommittedLink],
        pointers: &PointerIndex,
    ) {
        self.retire(|claim| {
            claimed_pointer(claim).is_some_and(|pointer| placed(pointers, &pointer) == Some(node))
                && !links
                    .iter()
                    .any(|link| link.ephemeral_identity_pk == claim.sender)
        });
    }
}

/// One converted claim, held from its conversion to its delivery. The set
/// publishes once for the folder, so a delivery reads nothing off the record
/// its own claim converted against.
struct Delivery {
    /// The claim's index in the conversion record.
    at: usize,
    claimant: Contact,
    permission: CommittedPermission,
    outcome: ClaimOutcome,
    /// The name the claimant suggested, or empty.
    name: String,
    /// The claimant's identity-key fingerprint.
    fingerprint: String,
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
    fn seal(&self) -> BookkeepingSeal<'_> {
        BookkeepingSeal::new(self.enc_secret, self.entropy)
    }

    pub(super) fn keys(&self) -> OwnerRotationKeys<'_> {
        OwnerRotationKeys {
            enc_secret: self.enc_secret,
            identity: self.owner_identity,
            scope_keys: self.scope_keys,
        }
    }

    pub(super) fn net(
        &self,
        target: &OwnerScope,
        pointer_consult: PointerConsultArm,
    ) -> OwnerRotationNet<'_, T, H, C, F, Sch, Box<dyn Entropy>, S> {
        OwnerRotationNet {
            transport: self.transport,
            api: self.api,
            gateway: self.gateway,
            http: self.http,
            floors: self.floors,
            snapshot_cache: self.snapshot_cache,
            events: self.events,
            scheduler: self.scheduler,
            profile: self.profile,
            entropy: self.entropy,
            keys: self.keys(),
            ancestry: target.ancestry(),
            pointer_consult,
            on_access_misses: self.on_access_misses,
            payload_version: POINTER_PAYLOAD_VERSION,
            gated: GatedRoots::default(),
            swept: SweptScopeState::default(),
            moved_seed: MovedScopeSeed::default(),
        }
    }

    async fn load(&self) -> Result<ConversionRecord, EngineError> {
        load_conversions(self.staging, self.seal(), self.enc_secret, self.events)
            .await
            .map_err(EngineError::from_seam)
    }

    async fn persist(&self, record: &ConversionRecord) -> Result<(), EngineError> {
        persist_conversions(self.staging, self.seal(), self.enc_secret, record)
            .await
            .map_err(EngineError::from_seam)
    }

    /// Hold the pass off and read the record, for a cut of a link. `None`
    /// while a pass or another cut holds it.
    pub(super) async fn hold_record(&self) -> Result<Option<HeldRecord<'_>>, EngineError> {
        let Some(running) = Running::take(self.running) else {
            return Ok(None);
        };
        Ok(Some(HeldRecord {
            record: self.load().await?,
            _running: running,
            retired: false,
        }))
    }

    /// Write back the entries `held` retired, and release [`Running`].
    pub(super) async fn settle(
        &self,
        held: HeldRecord<'_>,
        pointers: &PointerIndex,
    ) -> Result<(), EngineError> {
        if held.retired {
            self.persist(&held.record).await?;
            self.show_counts(&held.record, pointers);
        }
        Ok(())
    }

    /// Drive `cut` at `node` through the planes it demands, then raise this
    /// device's cut-epoch floor: the gate raises it from any adopted record,
    /// and without this raise the owner accepts the pre-cut root a surviving
    /// write grantee republishes until its next resolve here.
    ///
    /// `vault_pointer_signer` re-points the vault pointer when a write wave
    /// moves the vault root.
    pub(super) async fn rotate_cut(
        &self,
        node: NodeId,
        target: &OwnerScope,
        scope_root_name: &IpnsName,
        cut: &RevokedCommittedSet,
        vault_pointer_signer: Option<&Ed25519Signer>,
    ) -> Result<CutRotationReport, EngineError> {
        let sweep = self.cut.sweep;
        let rotator = OwnerCutNet {
            transport: self.transport,
            api: self.api,
            gateway: self.gateway,
            http: self.http,
            floors: self.floors,
            snapshot_cache: self.snapshot_cache,
            events: self.events,
            scheduler: self.scheduler,
            profile: self.profile,
            on_access_misses: self.on_access_misses,
            entropy: self.entropy,
            keys: self.keys(),
            owner_signer: self.identity,
            owner_pointer_seed: self.cut.owner_pointer_seed,
            vault_pointer_signer,
            held: self.cut.held,
            payload_version: POINTER_PAYLOAD_VERSION,
            scope_root_name,
            scope_id: target.scope.scope_id,
            parent_node_seed: target.parent_node_seed.as_deref(),
            session_root_scope_id: self.cut.vault_root.0,
            sweep: &|| sweep(target.scope.clone(), target.parent_node_seed.clone()),
        };
        let report = rotate_on_cut(&rotator, node, cut)
            .await
            .map_err(EngineError::from_rotation)?;
        record_cut_epoch_floor(
            self.floors,
            &target.scope.scope_id,
            cut.commitment.cut_epoch,
        )
        .await
        .map_err(EngineError::from_seam)?;
        Ok(report)
    }

    /// Show the counts `record` holds, and repaint when they moved.
    pub(super) fn show_counts(&self, record: &ConversionRecord, pointers: &PointerIndex) {
        let counts = ClaimCounts::of(record, pointers);
        if *self.counts.borrow() != counts {
            *self.counts.borrow_mut() = counts;
            let _ = self.events.unbounded_send(Event::SnapshotUpdated);
        }
    }

    /// Ack every claim on `items` that names a folder `only` admits, hold the
    /// ones the ack removed, then convert every pending entry at those
    /// folders. `only` is `None` on the tick, which converts everywhere.
    /// `pointers` places each owned scope root by its scope pointer name.
    ///
    /// Every folder converts on its own: a failure at one leaves its entries
    /// pending for a later pass and does not stop the rest. The first
    /// conversion failure is the answer.
    pub(super) async fn run(
        &self,
        sites: &impl ConversionSites,
        pointers: &PointerIndex,
        items: Vec<OwnedClaim>,
        only: Option<NodeId>,
    ) -> PassOutcome {
        let Some(_running) = Running::take(self.running) else {
            return PassOutcome::unheld(EngineError::Seam {
                message: CONVERSION_RUNNING.to_owned(),
            });
        };
        let mut record = match self.load().await {
            Ok(record) => record,
            Err(e) => return PassOutcome::unheld(e),
        };
        let held = record.entries().len();
        let intake = self.intake(&mut record, items, only).await;
        let mut failure = None;

        let mut verdicts: Vec<Option<Verdict>> = vec![None; record.entries().len()];
        let mut folders: BTreeMap<NodeId, Vec<(usize, &AckedClaim)>> = BTreeMap::new();
        let mut due: BTreeMap<NodeId, Vec<(usize, &AckedClaim, PointerDue)>> = BTreeMap::new();
        for (at, entry) in record.entries().iter().enumerate() {
            // An entry this intake wrote whose delete gave no answer waits for
            // the next pass: that pass sees the item again, or holds the only
            // copy.
            if entry.refused().is_some() || (entry.state == EntryState::Acking && at >= held) {
                continue;
            }
            let pointer = claimed_pointer(&entry.claim);
            match pointer.as_ref().and_then(|p| placed(pointers, p)) {
                Some(node) if only.is_none_or(|only| only == node) => match entry.state {
                    EntryState::PointerDue(pointer) => {
                        due.entry(node)
                            .or_default()
                            .push((at, &entry.claim, pointer));
                    }
                    _ => folders.entry(node).or_default().push((at, &entry.claim)),
                },
                Some(_) => {}
                // A claim that does not decode never converts, and one that
                // names no folder a whole walk found names none this owner
                // holds.
                None if pointer.is_none() || (only.is_none() && self.scope_roots_walked.get()) => {
                    verdicts[at] = Some(Verdict::Settled);
                }
                None => {}
            }
        }
        for (node, claims) in folders {
            if let Err(e) = self.convert_at(sites, node, &claims, &mut verdicts).await {
                failure.get_or_insert(e);
            }
        }
        for (node, claims) in due {
            if let Err(e) = self.post_due(sites, node, &claims, &mut verdicts).await {
                failure.get_or_insert(e);
            }
        }

        if verdicts.iter().any(Option::is_some) {
            for _ in 0..record.apply(&verdicts) {
                let _ = self.events.unbounded_send(Event::RefusedClaimDropped);
            }
            if let Err(e) = self.persist(&record).await {
                failure.get_or_insert(e);
            }
        }
        self.show_counts(&record, pointers);
        PassOutcome {
            intake,
            conversion: failure.map_or(Ok(()), Err),
        }
    }

    /// Drop the refused entries `retired` names: the owner dismissed them, or
    /// the cut of their link ended them.
    pub(super) async fn retire_refused(
        &self,
        pointers: &PointerIndex,
        retired: impl Fn(&AckedClaim) -> bool,
    ) -> Result<(), EngineError> {
        let Some(_running) = Running::take(self.running) else {
            return Err(EngineError::Seam {
                message: CONVERSION_RUNNING.to_owned(),
            });
        };
        let mut record = self.load().await?;
        if record.retire_refused(retired) > 0 {
            self.persist(&record).await?;
        }
        self.show_counts(&record, pointers);
        Ok(())
    }

    /// Ack first, and hold a claim only when this call removed it (ADR 0023
    /// D5): two owner devices never both convert on an honest ack (ADR 0023
    /// E1). Each claim is written before its delete runs and again after it,
    /// because from the delete on the mailbox no longer has it. A full record
    /// acks nothing more: the rest wait on the mailbox, and the intake fails
    /// with [`CONVERSION_RECORD_FULL`]. A record that does not persist before
    /// the delete fails it with [`CLAIM_NOT_HELD`].
    async fn intake(
        &self,
        record: &mut ConversionRecord,
        items: Vec<OwnedClaim>,
        only: Option<NodeId>,
    ) -> Result<(), EngineError> {
        for OwnedClaim { item, scope_root } in items {
            if only.is_some_and(|only| only != scope_root) {
                continue;
            }
            // A payload the record cannot store is no claim: it leaves the
            // mailbox and is dropped.
            if item.payload.len() > MAX_CLAIM_PAYLOAD_BYTES {
                self.ack(&item.item_id).await?;
                continue;
            }
            let claim = AckedClaim {
                sender: item.sender_identity.to_sec1(),
                payload: item.payload,
                acked_at: self.scheduler.now(),
            };
            let Some(hold) = record.hold_for_ack(claim.clone()) else {
                return Err(EngineError::Seam {
                    message: CONVERSION_RECORD_FULL.to_owned(),
                });
            };
            if hold == Hold::Fresh && self.persist(record).await.is_err() {
                record.settle_ack(&claim, false);
                return Err(EngineError::Seam {
                    message: CLAIM_NOT_HELD.to_owned(),
                });
            }
            let removed = self.ack(&item.item_id).await?;
            if hold != Hold::Held {
                record.settle_ack(&claim, removed || hold == Hold::Resumed);
                self.persist(record).await?;
            }
        }
        Ok(())
    }

    async fn ack(&self, item_id: &str) -> Result<bool, EngineError> {
        self.api.ack(item_id).await.map_err(EngineError::from_seam)
    }

    /// Convert `claims` at the folder `node`, publish its root once, and
    /// deliver each grant. A claim settles when the record carries its row or
    /// when it can never convert, and a cap refuses it; any other failure
    /// leaves it pending for the whole conversion to run again.
    async fn convert_at(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        claims: &[(usize, &AckedClaim)],
        verdicts: &mut [Option<Verdict>],
    ) -> Result<(), EngineError> {
        let check = "convert-target-is-not-a-scope-root";
        let mut target = sites.place(node).await?;
        let mut net = self.net(&target, PointerConsultArm::Refused);
        let mut current = match net.resolve_anchored(&target.scope).await {
            Ok(current) => current,
            Err(ResolveFailure::Unavailable) => {
                let Some(moved) = self.moved_root(node, &target).await? else {
                    return Err(target.resolve_error(check, ResolveFailure::Unavailable));
                };
                target = moved;
                net = self.net(&target, PointerConsultArm::Refused);
                let current = net
                    .resolve_anchored(&target.scope)
                    .await
                    .map_err(|e| target.resolve_error(check, e))?;
                let moved_name = parsed_scope_name(&target.scope.ipns_name)?;
                self.repoint(&sites.enclosing(node).await?, node, &moved_name)
                    .await?;
                current
            }
            Err(e) => return Err(target.resolve_error(check, e)),
        };
        let authority = OwnerAuthority {
            identity_signer: self.identity,
            enc_secret: self.enc_secret,
        };
        let mut commitment_sig = parsed_commitment_sig(&current.commitment_sig)?;
        let links = committed_links(
            &authority,
            &bound_scope(&target, &current, &commitment_sig)?,
        )
        .map_err(EngineError::from_invite)?;
        enforce_committed_ledger(&current.commitment, &current.grant_ledger)
            .map_err(|v| EngineError::from_invite(InviteError::Authority(v)))?;

        let pointer = self.scope_keys.pointer_name(&target.scope.scope_id);
        // A write conversion hands the claimant the scope's write seed, so a
        // scope still under the seed it inherited gets its own first
        // (ADR 0024 D4). Every mint starts at write epoch 1, and every wave
        // moves it on. Only a claim that passes every check here asks for it.
        if current.write_epoch <= MINT_EPOCH {
            let bound = bound_scope(&target, &current, &commitment_sig)?;
            let writes = claims.iter().any(|(_, claim)| {
                link_of_sender(&links, &claim.sender).is_ok()
                    && convert_invite_claim(
                        &authority,
                        &bound,
                        &pointer,
                        &current.pointer_read_key,
                        claim,
                    )
                    .is_ok_and(|converted| {
                        converted.outcome == ClaimOutcome::Granted
                            && converted.row.commitment_entry.permission
                                == CommittedPermission::Write
                    })
            });
            if writes {
                target = self.cut_write_scope(sites, node, &target, &current).await?;
                net = self.net(&target, PointerConsultArm::Refused);
                current = net
                    .resolve_anchored(&target.scope)
                    .await
                    .map_err(EngineError::from_resolve_failure)?;
                commitment_sig = parsed_commitment_sig(&current.commitment_sig)?;
            }
        }

        let contacts = StagingContactStore::new(self.staging, self.enc_secret, self.entropy);
        let mut failure: Option<EngineError> = None;
        let mut deliveries: Vec<Delivery> = Vec::new();
        for &(at, claim) in claims {
            let converted = convert_invite_claim(
                &authority,
                &bound_scope(&target, &current, &commitment_sig)?,
                &pointer,
                &current.pointer_read_key,
                claim,
            );
            let ConvertedClaim {
                row,
                commitment,
                ledger,
                claimant,
                link,
                claimant_code,
                outcome,
            } = match converted {
                Ok(converted) => converted,
                Err(e) => match e.disposition() {
                    ClaimDisposition::Settle => {
                        verdicts[at] = Some(Verdict::Settled);
                        continue;
                    }
                    ClaimDisposition::Refused(refusal) => {
                        verdicts[at] = Some(Verdict::Refused(refusal));
                        continue;
                    }
                    ClaimDisposition::Retry => {
                        failure.get_or_insert(EngineError::from_invite(e));
                        break;
                    }
                },
            };
            // The converting device records the claimant, so it can cut the
            // grant it mints (ADR 0023 D8).
            let scope_id = &target.scope.scope_id;
            let recorded = match outcome {
                ClaimOutcome::Granted => {
                    contacts
                        .record_from_link(&claimant_code, &link, scope_id)
                        .await
                }
                ClaimOutcome::Unchanged => {
                    contacts
                        .record_unchanged_from_link(&claimant_code, &link, scope_id)
                        .await
                }
            };
            match recorded {
                Ok(_) => {}
                Err(
                    ContactStoreError::Full
                    | ContactStoreError::LinkBookFull { .. }
                    | ContactStoreError::LinkContactScopesFull,
                ) => {
                    verdicts[at] = Some(match outcome {
                        ClaimOutcome::Granted => {
                            Verdict::Refused(ConversionRefusal::ContactBookFull)
                        }
                        ClaimOutcome::Unchanged => Verdict::Settled,
                    });
                    continue;
                }
                Err(ContactStoreError::RecipientKeyChanged) => {
                    verdicts[at] = Some(Verdict::Refused(ConversionRefusal::RecipientKeyChanged));
                    continue;
                }
                Err(e) => {
                    failure.get_or_insert(EngineError::from_contact_store(e));
                    break;
                }
            }
            if outcome == ClaimOutcome::Granted {
                // The next claim converts against what this one changed, and
                // conversion authorises against the signature over the set it
                // is handed, so the set is re-signed per claim and published
                // once.
                commitment_sig = sign_grant_set(self.identity, &commitment).map_err(|_| {
                    EngineError::MalformedInput {
                        check: "converted-commitment-unsignable",
                    }
                })?;
                current.commitment_sig = commitment_sig.to_compact();
                current.commitment = commitment;
                current.grant_ledger = ledger;
            }
            deliveries.push(Delivery {
                at,
                claimant,
                permission: row.commitment_entry.permission,
                outcome,
                name: row
                    .ledger_entry
                    .grantee_name
                    .as_ref()
                    .map(|name| name.name().to_owned())
                    .unwrap_or_default(),
                fingerprint: fingerprint_identity_key(&row.ledger_entry.recipient_identity_pk)
                    .unwrap_or_default(),
            });
        }

        if deliveries
            .iter()
            .any(|delivery| delivery.outcome == ClaimOutcome::Granted)
        {
            publish_edited_set(
                &net,
                self.entropy,
                self.enc_secret,
                &target,
                &current,
                &commitment_sig,
            )
            .await?;
        }
        // The record carries every row now. An entry settles once its
        // pointer lands, and until then the pointer alone is posted again.
        let since = self.scheduler.now();
        let deliveries: Vec<(Delivery, PointerDue)> = deliveries
            .into_iter()
            .map(|delivery| {
                let pointer = PointerDue {
                    permission: delivery.permission,
                    grant_floor: (delivery.outcome == ClaimOutcome::Granted)
                        .then_some(current.current_read_epoch),
                    since,
                };
                verdicts[delivery.at] = Some(Verdict::PointerDue(pointer));
                (delivery, pointer)
            })
            .collect();
        let folder = sites.folder_name(node).await?;
        for (delivery, pointer) in deliveries {
            match self
                .deliver(&target, &folder, &delivery.claimant, pointer)
                .await
            {
                Ok(()) => verdicts[delivery.at] = Some(Verdict::Settled),
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
            if delivery.outcome == ClaimOutcome::Granted {
                let _ = self.events.unbounded_send(Event::GranteeJoined {
                    scope_root: node,
                    name: delivery.name,
                    fingerprint: delivery.fingerprint,
                });
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// Cut `target` into a write scope of its own (ADR 0024 D4), re-point its
    /// parent's index at the root the wave moved it to, and answer the scope
    /// there. A re-point that fails is repaired by the next pass
    /// ([`Self::moved_root`]).
    async fn cut_write_scope(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        target: &OwnerScope,
        current: &CascadeTarget,
    ) -> Result<OwnerScope, EngineError> {
        let scope_root_name = parsed_scope_name(&target.scope.ipns_name)?;
        let parent = sites.enclosing(node).await?;
        let cut = cut_for_write_scope(&GrantCutPlan {
            commitment: &current.commitment,
            commitment_sig: &current.commitment_sig,
            grant_ledger: &current.grant_ledger,
            scope_root_name: &scope_root_name,
            owner_signer: self.identity,
            pointer_read_key: &current.pointer_read_key,
        })
        .map_err(EngineError::from_revoke)?;
        // The vault root takes no link, so no conversion cuts it.
        let report = self
            .rotate_cut(node, target, &scope_root_name, &cut, None)
            .await?;
        let write = report.write.ok_or_else(|| EngineError::Seam {
            message: "the write-scope cut ran no write wave".to_owned(),
        })?;
        floor::advance_write_epoch_on_sight(
            self.floors,
            &target.scope.scope_id,
            write.new_write_epoch,
        )
        .await
        .map_err(EngineError::from_seam)?;

        self.repoint(&parent, node, &write.new_root_name).await?;
        Ok(OwnerScope {
            scope: ChildScopeRef::new(node.0, write.new_root_name.as_str().as_bytes().to_vec()),
            parent_node_seed: target.parent_node_seed.clone(),
            vouched: true,
        })
    }

    /// The scope root at `node` under the name its owner-signed scope pointer
    /// vouches, or `None` when the pointer vouches the name `target` holds. A
    /// write-scope cut moves the root before the parent's index names the
    /// move, so an index that missed the move names a superseded root.
    ///
    /// The resolve that failed first may have consulted the pointer on access
    /// already; its recorded answer stands in for a second read
    /// ([`OnAccessMisses`]).
    async fn moved_root(
        &self,
        node: NodeId,
        target: &OwnerScope,
    ) -> Result<Option<OwnerScope>, EngineError> {
        let rejected = || EngineError::TrustViolation {
            message: "scope pointer unauthenticated, or vouched below the write-epoch floor"
                .to_owned(),
        };
        let recent = self.on_access_misses.recent(
            &node.0,
            self.scheduler.now(),
            self.profile.pointer_consult_interval,
        );
        let vouched = match recent {
            Some(OnAccessMiss::Absent) => None,
            Some(OnAccessMiss::Vouched(root)) => Some(*root),
            Some(OnAccessMiss::Rejected) => return Err(rejected()),
            None => PointerConsult {
                scope_keys: self.scope_keys,
                owner_identity: self.owner_identity,
                payload_version: POINTER_PAYLOAD_VERSION,
            }
            .run(self.transport, self.floors, &node.0)
            .await
            .map_err(|failure| match failure {
                PointerConsultError::Unavailable => EngineError::Seam {
                    message: "the scope pointer is unavailable".to_owned(),
                },
                PointerConsultError::Rejected => rejected(),
            })?
            .map(|consulted| consulted.current_root),
        };
        Ok(vouched
            .filter(|root| root.as_str().as_bytes() != target.scope.ipns_name.as_slice())
            .map(|root| OwnerScope {
                scope: ChildScopeRef::new(node.0, root.as_str().as_bytes().to_vec()),
                parent_node_seed: target.parent_node_seed.clone(),
                vouched: true,
            }))
    }

    /// Publish `parent` with its index naming `moved` for the child `node`.
    async fn repoint(
        &self,
        parent: &OwnerScope,
        node: NodeId,
        moved: &IpnsName,
    ) -> Result<(), EngineError> {
        let parent_net = self.net(parent, PointerConsultArm::Permitted);
        let parent_record = parent_net
            .resolve_anchored(&parent.scope)
            .await
            .map_err(EngineError::from_resolve_failure)?;
        let resealed = reseal_with_moved_child(
            self.entropy,
            self.enc_secret,
            parent,
            &parent_record,
            node,
            moved,
        )?;
        parent_net
            .publish_scope_root(&resealed)
            .await
            .map_err(|e| EngineError::from_rotate(RotateError::Publish(e)))
    }

    /// Post the share pointer of each converted claim at `node` again. An
    /// entry settles when its pointer lands, or when the post still fails past
    /// [`POINTER_RETRY_WINDOW`].
    async fn post_due(
        &self,
        sites: &impl ConversionSites,
        node: NodeId,
        claims: &[(usize, &AckedClaim, PointerDue)],
        verdicts: &mut [Option<Verdict>],
    ) -> Result<(), EngineError> {
        let target = sites.place(node).await?;
        let folder = sites.folder_name(node).await?;
        let now = self.scheduler.now();
        let mut failure = None;
        for &(at, claim, pointer) in claims {
            // The entry converted, so its claim decoded and its contact
            // imported then.
            let Some(claimant) = InviteClaim::decode(&claim.payload)
                .ok()
                .and_then(|claim| import_contact(&claim.contact_code).ok())
            else {
                verdicts[at] = Some(Verdict::Settled);
                continue;
            };
            match self.deliver(&target, &folder, &claimant, pointer).await {
                Ok(()) => verdicts[at] = Some(Verdict::Settled),
                Err(_) if now.0 >= pointer.since.0.saturating_add(POINTER_RETRY_WINDOW) => {
                    verdicts[at] = Some(Verdict::Settled);
                }
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// Raise the grant floor of a grant this owner minted, then post the
    /// claimant the share pointer. The item's sender is the link's ephemeral
    /// identity, so the pointer goes to the contact the claim carried.
    async fn deliver(
        &self,
        target: &OwnerScope,
        folder: &str,
        claimant: &Contact,
        pointer: PointerDue,
    ) -> Result<(), EngineError> {
        // The owner's own grant decision, and the only evidence of one: this
        // owner minted the row, and the set carrying it landed. A row the set
        // already carried, which a committed write grantee authors, may not
        // lift a cut.
        if let Some(read_epoch) = pointer.grant_floor {
            record_grant_floor(
                self.floors,
                &target.scope.scope_id,
                &claimant.enc_subkey(),
                read_epoch,
            )
            .await
            .map_err(EngineError::from_seam)?;
        }
        post_share_pointer_at(
            &mut SharedEntropy(self.entropy),
            self.api,
            self.identity,
            ENVELOPE_V,
            &GrantRecipient {
                contact: claimant,
                display_name: folder.to_owned(),
                grantee_name: None,
            },
            pointer.permission,
            &parsed_scope_name(&target.scope.ipns_name)?,
        )
        .await
        .map_err(EngineError::from_create_grant)
    }
}

/// The command's sites: the engine's own owner walk, which places a folder
/// through the parent's direct-child-scope index.
pub(super) struct EngineSites<'a, T: SeamTypes> {
    pub(super) engine: &'a Engine<T>,
    pub(super) session: &'a SessionIdentity,
    pub(super) api: &'a Rc<ApiClient<T::Http, T::CredentialStore>>,
}

impl<T: SeamTypes> ConversionSites for EngineSites<'_, T> {
    async fn place(&self, node: NodeId) -> Result<OwnerScope, EngineError> {
        let owner_identity = self.session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(self.session);
        self.engine
            .owner_scope(
                node,
                self.api,
                OwnerRotationKeys {
                    enc_secret: self.session.enc_subkey(),
                    identity: &owner_identity,
                    scope_keys: &scope_keys,
                },
                "convert-target-is-not-a-scope-root",
                UnindexedScope::Derive,
            )
            .await
    }

    async fn enclosing(&self, node: NodeId) -> Result<OwnerScope, EngineError> {
        let owner_identity = self.session.owner_identity();
        let scope_keys = OwnerSessionKeys::new(self.session);
        let (scope, _, _) = self
            .engine
            .enclosing_scope(
                node,
                self.api,
                OwnerRotationKeys {
                    enc_secret: self.session.enc_subkey(),
                    identity: &owner_identity,
                    scope_keys: &scope_keys,
                },
                PointerConsultArm::Permitted,
            )
            .await?;
        Ok(scope)
    }

    async fn folder_name(&self, node: NodeId) -> Result<String, EngineError> {
        let rendered = self.engine.render().await?;
        share_display_name(&rendered, node)
    }
}

/// The tick's sites: the boundaries its own walk proved this pass.
pub(super) struct TickSites<'a> {
    pub(super) boundaries: &'a Boundaries<'a>,
    /// The vault root's current name.
    pub(super) root_name: &'a IpnsName,
    /// Whether a walk this session named every scope root. Until one has, an
    /// ancestor scope root may be missing from the boundaries.
    pub(super) walked: bool,
}

impl ConversionSites for TickSites<'_> {
    async fn place(&self, node: NodeId) -> Result<OwnerScope, EngineError> {
        let proved = self
            .boundaries
            .material
            .get(&node)
            .ok_or_else(|| EngineError::Seam {
                message: "the scope root is not walked this pass".to_owned(),
            })?;
        Ok(OwnerScope {
            scope: proved_scope_ref(node, proved),
            parent_node_seed: ascent_node_seed(
                &self.boundaries.base.borrow(),
                &self.boundaries.material,
                self.boundaries.root,
                self.boundaries.root_read_seed,
                node,
            ),
            vouched: true,
        })
    }

    async fn enclosing(&self, node: NodeId) -> Result<OwnerScope, EngineError> {
        if !self.walked {
            return Err(EngineError::Seam {
                message: "the scope roots are not all walked".to_owned(),
            });
        }
        let root = self.boundaries.root;
        let parent = self
            .boundaries
            .base
            .borrow()
            .ancestors(node)
            .into_iter()
            .find(|ancestor| *ancestor != root && self.boundaries.scope_roots.contains(ancestor));
        match parent {
            Some(parent) => self.place(parent).await,
            None => Ok(OwnerScope {
                scope: ChildScopeRef::new(root.0, self.root_name.as_str().as_bytes().to_vec()),
                parent_node_seed: None,
                vouched: true,
            }),
        }
    }

    async fn folder_name(&self, node: NodeId) -> Result<String, EngineError> {
        share_display_name(&self.boundaries.base.borrow(), node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cut and a pass exclude each other, and the flag frees when the
    /// holder ends.
    #[test]
    fn one_holder_at_a_time_and_the_flag_frees_on_drop() {
        let running = Cell::new(false);
        let held = Running::take(&running).expect("the flag is free");
        assert!(Running::take(&running).is_none(), "a second holder waits");
        assert!(
            running.get(),
            "and the refusal leaves the first holder's flag"
        );
        drop(held);
        assert!(!running.get());
        assert!(Running::take(&running).is_some());
    }
}
