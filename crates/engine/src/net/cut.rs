//! The owner's production [`CutRotator`] over the live net plane
//! (blueprint/engine.md "Rotation primitives: Triggers").
//!
//! One committed-set cut, driven through the planes it demands: the read arm is
//! the fresh-seed eager cascade over [`OwnerRotationNet`], the write arm the
//! name wave over [`WriteWaveNet`]. Both arms re-resolve the scope root first —
//! a cut carries no seeds, and the write arm must run off the read epoch the
//! cascade just published, not the one the caller last saw.

use core::cell::{Cell, RefCell};

use futures_channel::mpsc;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::ChildScopeRef;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SECRET_LEN;

use crate::api::ApiClient;
use crate::content::Gateway;
use crate::entropy::{Entropy, SharedEntropy};
use crate::facade::{Event, NodeId, saturating_count};
use crate::gate::floor;
use crate::net::liveness::HeldRecords;
use crate::net::rotation::{
    GatedRoots, GatedWaveReads, MovedScopeSeed, OnAccessMisses, OwnerRotationKeys,
    OwnerRotationNet, PointerConsultArm, RootFallback, RootReports, RootWait, RotationAncestry,
    SweptScopeState, WaveSubtree, WriteWaveNet,
};
use crate::profile::SyncTimingProfile;
use crate::rotation::{
    AscentAuthority, CascadeError, CascadeOutcome, CascadeTarget, CommittedSet, CutRotator,
    MAX_ROTATION_ATTEMPTS, NodeBound, ResealSeeds, ResealedScopeRoot, ResolveFailure, Retryable,
    RevokedCommittedSet, RotateScopePlan, RotateScopeWritePlan, RotationPublishError,
    ScopeRootIdentity, ScopeRootPublisher, WriteHistory, WritePublishError, WriteRotateError,
    WriteRotationOutcome, bounded, cascade_rotate_scope, derive_write_name, reseal_scope_root,
    rotate_scope_write,
};
use crate::seams::{
    BoxedTask, CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SnapshotCache,
};

/// The owner arm's committed-set cut over the live net plane.
///
/// Anchored at the vault root: `scope_root_name` is the name the cut was
/// authorized against, and a cut naming any other scope is refused before a
/// resolve ([`Self::scope`]).
pub(crate) struct OwnerCutNet<'a, T, H: Http, C: CredentialStore, F, Sch, E, S> {
    pub(crate) owner_seed_cache: Option<crate::grants::owner_entry::OwnerSeedCache<'a>>,
    // The seam bundle both planes run on; see the identically-named fields of
    // [`OwnerRotationNet`].
    pub transport: &'a T,
    pub api: &'a ApiClient<H, C>,
    pub gateway: &'a Gateway,
    pub http: &'a H,
    pub floors: &'a F,
    pub snapshot_cache: &'a S,
    pub events: &'a mpsc::UnboundedSender<Event>,
    pub scheduler: &'a Sch,
    pub profile: &'a SyncTimingProfile,
    pub on_access_misses: &'a OnAccessMisses,
    pub entropy: &'a RefCell<E>,
    /// The owner material both planes re-seal under.
    pub keys: OwnerRotationKeys<'a>,
    /// The owner identity signer: the write wave's owner-only gate verifies it
    /// against the authorized commitment, and it signs the re-point object.
    pub owner_signer: &'a EcdsaSigner,
    /// Derives the scope pointer's name and its record signer (owner-only).
    pub owner_pointer_seed: &'a [u8; SECRET_LEN],
    /// The session's vault-pointer record signer, or `None` when it adopted no
    /// vault pointer (see [`WriteWaveNet::vault_pointer_signer`]). Only a cut at
    /// [`session_root_scope_id`](Self::session_root_scope_id) hands it on.
    pub vault_pointer_signer: Option<&'a Ed25519Signer>,
    /// The session's held set, which the write wave enrols the flipped scope
    /// pointer in ([`WriteWaveNet`]).
    pub held: &'a RefCell<HeldRecords>,
    /// The pointer-payload envelope version.
    pub payload_version: u64,
    /// The scope root's `ipnsName` as the cut was authorized against it.
    pub scope_root_name: &'a IpnsName,
    /// The scope root under cut.
    pub scope_id: [u8; 16],
    /// The rotating root's own ancestor node seed, `None` at the vault root.
    ///
    /// An interior scope root carries an ascent link the gate verifies against a
    /// reader-derived keypair, so every gated read and every re-seal of one needs
    /// this seed; a vault root carries no link and is owed none.
    pub parent_node_seed: Option<&'a [u8; SECRET_LEN]>,
    /// The session's vault-anchor scope, which the write wave's
    /// repoint-regression check scopes its read-epoch stage to. Distinct from
    /// [`scope_id`](Self::scope_id) whenever the cut is anchored below the root.
    pub session_root_scope_id: [u8; 16],
    /// Builds the lazy-wave sweep task the read cascade enqueues once its cut is
    /// durable, over the scope reference the cascade read the root at.
    pub sweep: &'a dyn Fn(ChildScopeRef) -> BoxedTask,
    /// Notes each scope whose read cut the cascade made durable.
    pub cut_durable: &'a dyn Fn([u8; 16], u64),
    /// The cut's bound of ADR 0065 D3 ([`RotateScopeWritePlan::bound`]).
    pub bound: &'a dyn NodeBound,
    /// When the root fallback falls back ([`RootWait`]).
    pub root_wait: RootWait<'a>,
    /// The refused root records this session already reported.
    pub root_reports: &'a RootReports,
    /// What this cut's own root reads met ([`CutRootReads`]).
    pub root_reads: &'a CutRootReads,
}

/// Whether a root read of one cut fell back to the last copy, and the root a
/// wave of that cut moved to (ADR 0068 D3).
#[derive(Default)]
pub(crate) struct CutRootReads {
    fell_back: Cell<bool>,
    moved_root: RefCell<Option<IpnsName>>,
    put_sent: Cell<bool>,
}

impl CutRootReads {
    /// Whether this cut sent a PUT of its scope root's record.
    pub(crate) fn put_sent(&self) -> bool {
        self.put_sent.get()
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E, S> OwnerCutNet<'_, T, H, C, F, Sch, E, S>
where
    T: RecordTransport,
    F: FloorStore,
{
    /// The scope reference the cut names, or a fail-closed refusal when it names
    /// a scope other than the one this net was authorized against. A cut is
    /// bound to one scope root, so reading another under this net's name would
    /// re-key a scope nothing authorized.
    fn scope(&self, scope_root: NodeId) -> Result<ChildScopeRef, ResolveFailure> {
        if scope_root.0 != self.scope_id {
            return Err(ResolveFailure::Rejected);
        }
        let moved = self.root_reads.moved_root.borrow();
        let name = moved.as_ref().unwrap_or(self.scope_root_name);
        Ok(ChildScopeRef::new(
            scope_root.0,
            name.as_str().as_bytes().to_vec(),
        ))
    }

    /// Whether a root read of this cut fell back and the root still sits at
    /// the old name (ADR 0068 D3).
    fn at_refused_root(&self) -> bool {
        self.root_reads.fell_back.get() && self.root_reads.moved_root.borrow().is_none()
    }

    /// Re-drive one plane under the rotation caller contract's bound.
    ///
    /// The bound belongs to each plane, never to
    /// [`rotate_on_cut`](crate::rotation::rotate_on_cut): the driver is not
    /// idempotent — its read arm mints a fresh override seed every time it runs —
    /// so re-driving it after the read plane had already landed would burn an
    /// epoch per attempt and, once the write wave has moved the root, re-seal a
    /// name nothing resolves.
    async fn bounded<V, Err, A>(&self, attempt: A) -> Result<V, Err>
    where
        A: AsyncFnMut() -> Result<V, Err>,
        Err: Retryable,
        Sch: Scheduler,
    {
        bounded(
            self.scheduler,
            self.profile.poll_cadence,
            MAX_ROTATION_ATTEMPTS,
            attempt,
        )
        .await
    }

    /// A rotation net over this cut's seams, anchored at this cut's own scope —
    /// which is what decides the binding a gated root read must prove
    /// ([`OwnerRotationNet::resolve_anchored`]).
    fn rotation_net(&self) -> OwnerRotationNet<'_, T, H, C, F, Sch, E, S> {
        OwnerRotationNet {
            owner_seed_cache: self.owner_seed_cache.clone(),
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
            keys: OwnerRotationKeys {
                enc_secret: self.keys.enc_secret,
                identity: self.keys.identity,
                scope_keys: self.keys.scope_keys,
            },
            ancestry: RotationAncestry::default()
                .under_parent_node_seed(self.scope_id, self.parent_node_seed),
            pointer_consult: PointerConsultArm::Permitted,
            on_access_misses: self.on_access_misses,
            payload_version: self.payload_version,
            gated: GatedRoots::default(),
            swept: SweptScopeState::default(),
            moved_seed: MovedScopeSeed::default(),
            root_fallback: Some(
                RootFallback::new(self.scope_id, self.root_wait, self.root_reports)
                    .noting_root_puts(&self.root_reads.put_sent),
            ),
        }
    }

    /// `scope`'s root, gated through `net`, noting a read that fell back.
    async fn resolve_root(
        &self,
        net: &OwnerRotationNet<'_, T, H, C, F, Sch, E, S>,
        scope: &ChildScopeRef,
    ) -> Result<CascadeTarget, ResolveFailure>
    where
        Sch: Scheduler,
        S: SnapshotCache,
    {
        let current = net.resolve_anchored(scope).await;
        if net.fell_back() {
            self.root_reads.fell_back.set(true);
        }
        current
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E, S> CutRotator
    for OwnerCutNet<'_, T, H, C, F, Sch, E, S>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
    S: SnapshotCache,
{
    async fn publish_cut_set(
        &self,
        scope_root: NodeId,
        cut: &RevokedCommittedSet,
    ) -> Result<(), CascadeError> {
        let resolve_failed = |reason| CascadeError::Resolve {
            scope_id: scope_root.0,
            reason,
        };
        let scope = self.scope(scope_root).map_err(resolve_failed)?;
        self.bounded(async || {
            let net = self.rotation_net();
            let current = self
                .resolve_root(&net, &scope)
                .await
                .map_err(resolve_failed)?;
            if keeps_rows_over_a_copy(net.fell_back(), cut) {
                return Err(set_superseded(scope_root));
            }
            // Idempotent by comparison, never by assumption: a read cascade or a
            // grant mint may already have published this set, and republishing
            // would spend a CAS to change nothing.
            if current.commitment == cut.commitment && current.grant_ledger == cut.grant_ledger {
                return Ok(());
            }
            if superseded(&current, cut) {
                return Err(set_superseded(scope_root));
            }
            if self.at_refused_root() {
                return Err(resolve_failed(ResolveFailure::Rejected));
            }
            // The publisher derives this record's IPNS signer from the seed the
            // root's own owner-write blob carries, so a root whose seed does not
            // derive the name it sits at cannot be republished here — it would
            // sign under a key the name does not answer to. Only the grant
            // mint's interim state is shaped that way, and the comparison above
            // leaves it alone. Release-active (AGENTS.md rule 8).
            if derive_write_name(&current.write_scope_seed, &scope_root.0) != *self.scope_root_name
            {
                return Err(CascadeError::Publish {
                    scope_id: scope_root.0,
                    error: RotationPublishError::Rejected,
                });
            }
            // Metadata-only: the same override seed at the same read epoch, so
            // `prev = None` mints no history link and the read-epoch floor never
            // moves (blueprint/engine.md "rotateScopeWrite" — a write cut leaves
            // the read plane's clock alone).
            let section = reseal_scope_root(
                &mut *self.entropy.borrow_mut(),
                &ScopeRootIdentity {
                    v: current.v,
                    scope_id: scope_root.0,
                    ipns_name: self.scope_root_name.as_str().as_bytes(),
                    owner_enc_pub: &current.owner_enc_pub,
                    owner_enc_secret: Some(self.keys.enc_secret),
                    ascent: self.parent_node_seed.map(AscentAuthority::ParentSeed),
                    owes_ascent_link: current.carried_ascent_link,
                    pseudonym_signer: &current.pseudonym_signer,
                },
                &ResealSeeds {
                    override_seed: &current.override_seed,
                    read_epoch: current.current_read_epoch,
                    prev: None,
                    write_scope_seed: &current.write_scope_seed,
                    write_epoch: current.write_epoch,
                    write_history: WriteHistory::Carried(&current.write_history_link),
                    pointer_read_key: &current.pointer_read_key,
                },
                &CommittedSet {
                    commitment: &cut.commitment,
                    commitment_sig: &cut.commitment_sig,
                    grant_ledger: &cut.grant_ledger,
                    direct_child_scope_index: &current.direct_child_scope_index,
                    revoked_recipients: &cut.revoked_recipients,
                },
                &current.carried_history_links,
            )
            .map_err(|error| CascadeError::Reseal {
                scope_id: scope_root.0,
                error,
            })?;
            net.publish_scope_root(&ResealedScopeRoot {
                scope_id: scope_root.0,
                ipns_name: self.scope_root_name.as_str().as_bytes().to_vec(),
                read_epoch: current.current_read_epoch,
                write_epoch: current.write_epoch,
                section,
            })
            .await
            .map(drop)
            .map_err(|error| CascadeError::Publish {
                scope_id: scope_root.0,
                error,
            })
        })
        .await
    }

    async fn rotate_read_plane(
        &self,
        scope_root: NodeId,
        cut: &RevokedCommittedSet,
    ) -> Result<CascadeOutcome, CascadeError> {
        let resolve_failed = |reason| CascadeError::Resolve {
            scope_id: scope_root.0,
            reason,
        };
        let scope = self.scope(scope_root).map_err(resolve_failed)?;
        self.bounded(async || {
            // The gated read records the root's pre-cut seed and child index in
            // this net's own ancestry, which is what the walk gates each
            // descendant under — their published ascent links were sealed under
            // that seed, not the fresh one the cascade is about to mint. It also
            // parks the republish base the root's own publish then takes.
            let net = self.rotation_net();
            let current = self
                .resolve_root(&net, &scope)
                .await
                .map_err(resolve_failed)?;
            let moved = self.root_reads.moved_root.borrow().is_some();
            if !moved && superseded(&current, cut) {
                return Err(set_superseded(scope_root));
            }
            if self.at_refused_root() {
                return Err(resolve_failed(ResolveFailure::Rejected));
            }
            // At the moved root the wave already re-minted the cut set under the
            // new name; the cut still withholds its recipients.
            let (commitment, commitment_sig, grant_ledger) = if moved {
                (
                    &current.commitment,
                    &current.commitment_sig,
                    &current.grant_ledger,
                )
            } else {
                (&cut.commitment, &cut.commitment_sig, &cut.grant_ledger)
            };
            cascade_rotate_scope(
                &mut SharedEntropy(self.entropy),
                self.floors,
                self.scheduler,
                &net,
                &net,
                &RotateScopePlan {
                    identity: ScopeRootIdentity {
                        v: current.v,
                        scope_id: scope_root.0,
                        ipns_name: &scope.ipns_name,
                        owner_enc_pub: &current.owner_enc_pub,
                        owner_enc_secret: Some(self.keys.enc_secret),
                        ascent: self.parent_node_seed.map(AscentAuthority::ParentSeed),
                        owes_ascent_link: current.carried_ascent_link,
                        pseudonym_signer: &current.pseudonym_signer,
                    },
                    // The cut set, never the one the record carries: the absence of
                    // the cut party's row from the re-wrapped blobs *is* the
                    // revocation.
                    committed: CommittedSet {
                        commitment,
                        commitment_sig,
                        grant_ledger,
                        direct_child_scope_index: &current.direct_child_scope_index,
                        revoked_recipients: &cut.revoked_recipients,
                    },
                    current_override_seed: &current.override_seed,
                    current_read_epoch: current.current_read_epoch,
                    write_scope_seed: &current.write_scope_seed,
                    write_epoch: current.write_epoch,
                    write_history_link: &current.write_history_link,
                    pointer_read_key: &current.pointer_read_key,
                    carried_history_links: &current.carried_history_links,
                },
                || (self.sweep)(scope.clone()),
                self.cut_durable,
            )
            .await
        })
        .await
    }

    fn root_fell_back(&self) -> bool {
        self.root_reads.fell_back.get()
    }

    async fn rotate_write_plane(
        &self,
        scope_root: NodeId,
        cut: &RevokedCommittedSet,
    ) -> Result<WriteRotationOutcome, WriteRotateError> {
        let resolve_failed = |reason| WriteRotateError::Resolve {
            node_id: scope_root.0,
            reason,
        };
        let scope = self.scope(scope_root).map_err(resolve_failed)?;
        let _ = self.events.unbounded_send(Event::NameWaveStarted {
            scope_root,
            at: self.scheduler.now(),
        });
        let outcome = self
            .bounded(async || {
                // Re-read after the read arm: a full revoke re-keyed the scope, and
                // the wave derives every per-node read key from the seed that cut
                // published.
                let net = self.rotation_net();
                let current = self
                    .resolve_root(&net, &scope)
                    .await
                    .map_err(resolve_failed)?;
                // The wave re-mints the authorized set, so a root, or a last
                // copy, that carries a later one stops it.
                if superseded(&current, cut) || keeps_rows_over_a_copy(net.fell_back(), cut) {
                    return Err(WriteRotateError::Publish {
                        stage: "republish",
                        node_id: scope_root.0,
                        error: WritePublishError::Superseded,
                    });
                }
                // The durable floor is the owner-vouched `minReadEpoch` the re-point
                // carries; a scope that has never been rotated has none, and its record's
                // own epoch is the floor a reader would derive.
                let min_read_epoch = floor::read_epoch_floor(self.floors, &scope_root.0)
                    .await
                    .map_err(|_| resolve_failed(ResolveFailure::Unavailable))?
                    .unwrap_or(current.current_read_epoch);

                // The vault pointer names the session's root scope, so the anchor is
                // decided by which scope is under cut — never by whether this session
                // happens to hold the signer. A cold start that could not reach the
                // chain leaves the signer absent, and inferring "no anchor" from that
                // would report a wave complete with the anchor still on the old root.
                let is_vault_anchor = scope_root.0 == self.session_root_scope_id;
                let vault_pointer_signer = self.vault_pointer_signer.filter(|_| is_vault_anchor);
                let net = WriteWaveNet {
                    owner_seed_cache: self.owner_seed_cache.clone(),
                    transport: self.transport,
                    api: self.api,
                    gateway: self.gateway,
                    http: self.http,
                    floors: self.floors,
                    snapshot_cache: self.snapshot_cache,
                    scheduler: self.scheduler,
                    profile: self.profile,
                    entropy: self.entropy,
                    events: self.events,
                    scope_id: scope_root.0,
                    read_scope_seed: &current.override_seed,
                    read_seed_epoch: current.current_read_epoch,
                    parent_node_seed: self.parent_node_seed,
                    owner: self.owner_signer,
                    owner_enc_secret: self.keys.enc_secret,
                    scope_keys: self.keys.scope_keys,
                    authorized_commitment: &cut.commitment,
                    authorized_ledger: &cut.grant_ledger,
                    owner_pointer_seed: self.owner_pointer_seed,
                    vault_pointer_signer,
                    held: self.held,
                    payload_version: self.payload_version,
                    current_root_name: self.scope_root_name,
                    session_root_scope_id: self.session_root_scope_id,
                    gated_reads: GatedWaveReads::default(),
                    subtree: WaveSubtree::default(),
                    root_fallback: Some(RootFallback::new(
                        scope_root.0,
                        self.root_wait,
                        self.root_reports,
                    )),
                };
                rotate_scope_write(
                    &mut SharedEntropy(self.entropy),
                    &net,
                    &net,
                    &RotateScopeWritePlan {
                        scope_id: scope_root.0,
                        payload_version: self.payload_version,
                        owner_pointer_seed: self.owner_pointer_seed,
                        commitment: &cut.commitment,
                        commitment_sig: &cut.commitment_sig,
                        owner_identity_signer: self.owner_signer,
                        current_write_epoch: current.write_epoch,
                        min_read_epoch,
                        current_root_name: self.scope_root_name,
                        is_vault_anchor,
                        bound: self.bound,
                    },
                )
                .await
            })
            .await?;
        *self.root_reads.moved_root.borrow_mut() = Some(outcome.new_root_name.clone());
        for dropped in &outcome.dropped {
            let _ = self.events.unbounded_send(Event::NodeDropped {
                scope_root,
                node_id: NodeId(dropped.node_id),
                cause: dropped.cause,
            });
        }
        let _ = self.events.unbounded_send(Event::NameWaveEnded {
            scope_root,
            interior_nodes: saturating_count(outcome.interior_node_count),
            dropped: saturating_count(outcome.dropped.len()),
            at: self.scheduler.now(),
        });
        Ok(outcome)
    }
}

/// Whether `current` carries a set other than `cut`'s at `cut`'s cut epoch or
/// above: another cut or row landed after the cut was authorized, and running
/// it would drop that work.
fn superseded(current: &CascadeTarget, cut: &RevokedCommittedSet) -> bool {
    (current.commitment != cut.commitment || current.grant_ledger != cut.grant_ledger)
        && current.commitment.cut_epoch >= cut.commitment.cut_epoch
}

/// Whether a cut that keeps grant rows meets a root read from its last copy:
/// such a cut keeps no row (ADR 0068 D5), so it is refused, not run.
fn keeps_rows_over_a_copy(fell_back: bool, cut: &RevokedCommittedSet) -> bool {
    fell_back && !cut.commitment.entries.is_empty()
}

/// The retryable refusal of a cut that [`superseded`] or
/// [`keeps_rows_over_a_copy`] names.
fn set_superseded(scope_root: NodeId) -> CascadeError {
    CascadeError::Publish {
        scope_id: scope_root.0,
        error: RotationPublishError::Superseded,
    }
}
