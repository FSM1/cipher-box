//! The owner's production [`CutRotator`] over the live net plane
//! (blueprint/engine.md "Rotation primitives: Triggers").
//!
//! One committed-set cut, driven through the planes it demands: the read arm is
//! the fresh-seed eager cascade over [`OwnerRotationNet`], the write arm the
//! name wave over [`WriteWaveNet`]. Both arms re-resolve the scope root first —
//! a cut carries no seeds, and the write arm must run off the read epoch the
//! cascade just published, not the one the caller last saw.

use core::cell::RefCell;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::ChildScopeRef;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::secret::SECRET_LEN;

use crate::api::ApiClient;
use crate::content::Gateway;
use crate::entropy::{Entropy, SharedEntropy};
use crate::facade::NodeId;
use crate::gate::floor;
use crate::net::rotation::{
    GatedRoots, GatedWaveRoot, OwnerRotationKeys, OwnerRotationNet, RotationAncestry,
    SweptScopeState, WaveSubtree, WriteWaveNet,
};
use crate::profile::SyncTimingProfile;
use crate::rotation::{
    AscentAuthority, CascadeError, CascadeOutcome, CommittedSet, CutRotator, MAX_ROTATION_ATTEMPTS,
    ResolveFailure, Retryable, RevokedCommittedSet, RotateScopePlan, RotateScopeWritePlan,
    ScopeRootIdentity, WriteRotateError, WriteRotationOutcome, bounded, cascade_rotate_scope,
    rotate_scope_write,
};
use crate::seams::{BoxedTask, CredentialStore, FloorStore, Http, RecordTransport, Scheduler};

/// The owner arm's committed-set cut over the live net plane.
///
/// Anchored at the vault root: `scope_root_name` is the name the cut was
/// authorized against, and a cut naming any other scope is refused before a
/// resolve ([`Self::scope`]).
pub(crate) struct OwnerCutNet<'a, T, H: Http, C: CredentialStore, F, Sch, E> {
    // The seam bundle both planes run on; see the identically-named fields of
    // [`OwnerRotationNet`].
    pub transport: &'a T,
    pub api: &'a ApiClient<H, C>,
    pub gateway: &'a Gateway,
    pub http: &'a H,
    pub floors: &'a F,
    pub scheduler: &'a Sch,
    pub profile: &'a SyncTimingProfile,
    pub entropy: &'a RefCell<E>,
    /// The owner material both planes re-seal under.
    pub keys: OwnerRotationKeys<'a>,
    /// The owner identity signer: the write wave's owner-only gate verifies it
    /// against the authorized commitment, and it signs the re-point object.
    pub owner_signer: &'a EcdsaSigner,
    /// Derives the scope pointer's name and its record signer (owner-only).
    pub owner_pointer_seed: &'a [u8; SECRET_LEN],
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
    /// durable. Nullary: a cut is anchored at one scope root, and the task needs
    /// the name and ancestor seed that scope was read under, not just its id.
    pub sweep: &'a dyn Fn() -> BoxedTask,
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> OwnerCutNet<'_, T, H, C, F, Sch, E>
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
        Ok(ChildScopeRef::new(
            scope_root.0,
            self.scope_root_name.as_str().as_bytes().to_vec(),
        ))
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
    fn rotation_net(&self) -> OwnerRotationNet<'_, T, H, C, F, Sch, E> {
        OwnerRotationNet {
            transport: self.transport,
            api: self.api,
            gateway: self.gateway,
            http: self.http,
            floors: self.floors,
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
            owner_pointer_seed: Some(self.owner_pointer_seed),
            payload_version: self.payload_version,
            gated: GatedRoots::default(),
            swept: SweptScopeState::default(),
        }
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> CutRotator for OwnerCutNet<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
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
            let current = net.resolve_anchored(&scope).await.map_err(resolve_failed)?;
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
                        ipns_name: self.scope_root_name.as_str().as_bytes(),
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
                        commitment: &cut.commitment,
                        commitment_sig: &cut.commitment_sig,
                        grant_ledger: &cut.grant_ledger,
                        direct_child_scope_index: &current.direct_child_scope_index,
                    },
                    current_override_seed: &current.override_seed,
                    current_read_epoch: current.current_read_epoch,
                    write_scope_seed: &current.write_scope_seed,
                    write_epoch: current.write_epoch,
                    write_history_link: &current.write_history_link,
                    pointer_read_key: &current.pointer_read_key,
                    carried_history_links: &current.carried_history_links,
                },
                || (self.sweep)(),
            )
            .await
        })
        .await
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
        self.bounded(async || {
            // Re-read after the read arm: a full revoke re-keyed the scope, and
            // the wave derives every per-node read key from the seed that cut
            // published.
            let current = self
                .rotation_net()
                .resolve_anchored(&scope)
                .await
                .map_err(resolve_failed)?;
            // The durable floor is the owner-vouched `minReadEpoch` the re-point
            // carries; a scope that has never been rotated has none, and its record's
            // own epoch is the floor a reader would derive.
            let min_read_epoch = floor::read_epoch_floor(self.floors, &scope_root.0)
                .await
                .map_err(|_| resolve_failed(ResolveFailure::Unavailable))?
                .unwrap_or(current.current_read_epoch);

            let net = WriteWaveNet {
                transport: self.transport,
                api: self.api,
                gateway: self.gateway,
                http: self.http,
                floors: self.floors,
                scheduler: self.scheduler,
                profile: self.profile,
                entropy: self.entropy,
                scope_id: scope_root.0,
                read_scope_seed: &current.override_seed,
                parent_node_seed: self.parent_node_seed,
                owner: self.owner_signer,
                owner_enc_secret: self.keys.enc_secret,
                scope_keys: self.keys.scope_keys,
                authorized_commitment: &cut.commitment,
                owner_pointer_seed: self.owner_pointer_seed,
                payload_version: self.payload_version,
                current_root_name: self.scope_root_name,
                session_root_scope_id: self.session_root_scope_id,
                gated_root: GatedWaveRoot::default(),
                subtree: WaveSubtree::default(),
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
                },
            )
            .await
        })
        .await
    }
}
