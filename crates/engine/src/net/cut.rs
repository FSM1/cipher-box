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
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::X25519Secret;

use crate::api::ApiClient;
use crate::content::Gateway;
use crate::entropy::{Entropy, SharedEntropy};
use crate::facade::NodeId;
use crate::gate::floor;
use crate::net::rotation::{
    GatedRoots, GatedWaveRoot, OwnerRotationKeys, OwnerRotationNet, OwnerScopeKeys,
    RotationAncestry, SweptScopeState, WaveSubtree, WriteWaveNet,
};
use crate::profile::SyncTimingProfile;
use crate::rotation::{
    AscentAuthority, CascadeError, CascadeOutcome, CascadeResealResolver, CascadeTarget,
    CommittedSet, CutRotator, ResolveFailure, RevokedCommittedSet, RotateScopePlan,
    RotateScopeWritePlan, ScopeRootIdentity, WriteRotateError, WriteRotationOutcome,
    cascade_rotate_scope, rotate_scope_write,
};
use crate::seams::{BoxedTask, CredentialStore, FloorStore, Http, RecordTransport, Scheduler};

/// The owner arm's committed-set cut over the live net plane.
///
/// Anchored at the vault root: `scope_root_name` is the name the cut was
/// authorized against, and a cut naming any other scope is refused before a
/// resolve ([`Self::scope`]).
pub(crate) struct OwnerCutNet<'a, T, H: Http, C: CredentialStore, F, Sch, E> {
    /// The record-plane transport: fan-out GET for the read, CAS PUT for the
    /// publish.
    pub transport: &'a T,
    /// The API client: register-first, the head-block upload, and retirement.
    pub api: &'a ApiClient<H, C>,
    /// Content read sources for the head block.
    pub gateway: &'a Gateway,
    /// The HTTP seam the content fetch rides.
    pub http: &'a H,
    /// The durable floors the adoption gate reads and advances.
    pub floors: &'a F,
    /// The scheduler the publish pipeline's background re-PUT and the cut's
    /// lazy-wave sweep ride.
    pub scheduler: &'a Sch,
    /// The publish pipeline's timing policy.
    pub profile: &'a SyncTimingProfile,
    /// Injected entropy — the per-seal nonce source (determinism law).
    pub entropy: &'a RefCell<E>,
    /// Opens each scope root's owner blob, and the owner-blob recipient every
    /// re-seal wraps to.
    pub enc_secret: &'a X25519Secret,
    /// The owner-trust anchor the adoption gate checks each gated read against.
    pub owner_identity: &'a EcdsaVerifier,
    /// The owner identity signer: the write wave's owner-only gate verifies it
    /// against the authorized commitment, and it signs the re-point object.
    pub owner_signer: &'a EcdsaSigner,
    /// The two per-scope derivations a re-seal needs, and no wider capability.
    pub scope_keys: &'a dyn OwnerScopeKeys,
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
    /// durable.
    pub sweep: &'a dyn Fn([u8; 16]) -> BoxedTask,
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

    /// `ancestry` carrying this cut's own ancestor seed when it is anchored
    /// below the vault root.
    fn anchored(&self, ancestry: RotationAncestry) -> RotationAncestry {
        match self.parent_node_seed {
            Some(seed) => ancestry.under_parent_node_seed(self.scope_id, seed),
            None => ancestry,
        }
    }

    /// A rotation net over this cut's seams, carrying `ancestry`.
    fn rotation_net(&self, ancestry: RotationAncestry) -> OwnerRotationNet<'_, T, H, C, F, Sch, E> {
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
                enc_secret: self.enc_secret,
                identity: self.owner_identity,
                scope_keys: self.scope_keys,
            },
            ancestry,
            owner_pointer_seed: Some(self.owner_pointer_seed),
            payload_version: self.payload_version,
            gated: GatedRoots::default(),
            swept: SweptScopeState::default(),
        }
    }

    /// The scope root's current re-seal material, read through the adoption
    /// gate under the caller's own label and the binding its anchor demands: an
    /// interior root must prove its ascent link, the vault root has none.
    async fn resolve(&self, scope: &ChildScopeRef) -> Result<CascadeTarget, ResolveFailure> {
        let net = self.rotation_net(self.anchored(RotationAncestry::default()));
        match self.parent_node_seed {
            Some(_) => net.resolve(scope).await,
            None => net.resolve_vault_root(scope).await,
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
        let current = self.resolve(&scope).await.map_err(resolve_failed)?;

        // The descendants' published ascent links were sealed under the root's
        // pre-cut seed, so the walk gates each level under that seed, not the
        // fresh one the cascade is about to mint.
        let net = self.rotation_net(self.anchored(RotationAncestry::rooted_at(
            scope_root.0,
            &current.override_seed,
            &current.direct_child_scope_index,
        )));
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
                    owner_enc_secret: Some(self.enc_secret),
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
            || (self.sweep)(scope_root.0),
        )
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
        // Re-read after the read arm: a full revoke re-keyed the scope, and the
        // wave derives every per-node read key from the seed that cut published.
        let current = self.resolve(&scope).await.map_err(resolve_failed)?;
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
            owner_enc_secret: self.enc_secret,
            scope_keys: self.scope_keys,
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
    }
}
