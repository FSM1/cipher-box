//! The flat read-plane root cut over one already-assembled owner net, and the
//! tick's scope-exit arm that runs it at a boundary this vault owns
//! (blueprint/engine.md "Rotation primitives: Triggers").

use core::cell::RefCell;
use std::rc::Rc;

use cipherbox_core::seal::ChildScopeRef;
use futures_channel::mpsc;

use super::rotate::{RotateError, RotationOutcome, complete_cut, rotate_scope};
use super::sweep::{SweepKeys, SweepTaskFactory};
use super::{AscentAuthority, CommittedSet, ResolveFailure, RotateScopePlan, ScopeRootIdentity};
use crate::api::ApiClient;
use crate::content::read::Gateway;
use crate::entropy::{Entropy, SharedEntropy};
use crate::facade::{Event, NodeId};
use crate::net::rotation::{
    GatedRoots, MovedScopeSeed, OnAccessMisses, RotationAncestry, SweptScopeState,
};
use crate::net::{
    OwnerRotationKeys, OwnerRotationNet, PointerConsultArm, VaultPointerVoucher, VouchedRoot,
};
use crate::profile::SyncTimingProfile;
use crate::rotation::WalkedReadEpochs;
use crate::rotation::scope_material::{Boundaries, ascent_node_seed, proved_scope_ref};
use crate::seams::{
    BoxedTask, CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SnapshotCache,
};
use crate::sync::pointer::POINTER_PAYLOAD_VERSION;

/// What the tick's scope-exit arm needs to cut one interior scope of this vault.
///
/// The grantee arm ([`GranteeRotationNet`](crate::net::rotation::GranteeRotationNet))
/// cuts a scope a device holds a grant *for*. A relocation out of a folder this
/// vault granted leaves a scope the vault **owns**, so its plan is the owner's —
/// the same flat root cut `Engine::rotate_now` assembles.
pub(crate) struct ScopeExitArm<'a, T, H: Http, C: CredentialStore, F, Sch, E, S> {
    pub(crate) transport: &'a T,
    pub(crate) api: &'a ApiClient<H, C>,
    pub(crate) gateway: &'a Gateway,
    pub(crate) http: &'a H,
    pub(crate) floors: &'a F,
    pub(crate) snapshot_cache: &'a S,
    pub(crate) events: &'a mpsc::UnboundedSender<Event>,
    pub(crate) scheduler: &'a Sch,
    pub(crate) profile: &'a SyncTimingProfile,
    pub(crate) entropy: &'a RefCell<E>,
    /// The session's own rotation material, empty once it has torn down.
    pub(crate) keys: &'a RefCell<Option<Rc<SweepKeys>>>,
    /// The lazy-wave sweep every cut enqueues, emptied once the session has
    /// torn down.
    pub(crate) sweep: &'a RefCell<Option<SweepTaskFactory>>,
    /// The boundaries this session has proved and what they seal under.
    pub(crate) boundaries: &'a Boundaries<'a>,
    /// The read epoch each walked boundary sits at. A cut supersedes the epoch
    /// it names, so dropping that entry is what makes the next pass re-walk
    /// rather than seal under material the cut has replaced.
    pub(crate) walked_epochs: &'a RefCell<WalkedReadEpochs>,
    /// The session's on-access consult misses ([`OnAccessMisses`]).
    pub(crate) on_access_misses: &'a OnAccessMisses,
}

/// Run the flat [`RotationTrigger::ScopeExit`](super::RotationTrigger::ScopeExit) cut at one scope root this vault
/// owns.
///
/// A trigger naming a boundary this session has not proved is refused rather
/// than cut under material it would have to guess at.
pub(crate) async fn cut_exited_scope<T, H, C, F, Sch, E, S>(
    arm: ScopeExitArm<'_, T, H, C, F, Sch, E, S>,
    scope_root: NodeId,
) -> Result<RotationOutcome, RotateError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
    S: SnapshotCache,
{
    let (Some(keys), Some(sweep)) = (arm.keys.borrow().clone(), arm.sweep.borrow().clone()) else {
        return Err(RotateError::Resolve(ResolveFailure::Unavailable));
    };
    let proved = arm
        .boundaries
        .material
        .get(&scope_root)
        .ok_or(RotateError::Resolve(ResolveFailure::Rejected))?;
    let scope = proved_scope_ref(scope_root, proved);
    let ascent = ascent_node_seed(
        &arm.boundaries.base.borrow(),
        &arm.boundaries.material,
        arm.boundaries.root,
        arm.boundaries.root_read_seed,
        scope_root,
    );
    let net = OwnerRotationNet {
        transport: arm.transport,
        api: arm.api,
        gateway: arm.gateway,
        http: arm.http,
        floors: arm.floors,
        snapshot_cache: arm.snapshot_cache,
        events: arm.events,
        scheduler: arm.scheduler,
        profile: arm.profile,
        entropy: arm.entropy,
        keys: OwnerRotationKeys {
            enc_secret: &keys.enc_secret,
            identity: &keys.owner_identity,
            scope_keys: &keys.scope_keys,
        },
        ancestry: RotationAncestry::default()
            .under_parent_node_seed(scope_root.0, ascent.as_deref()),
        pointer_consult: PointerConsultArm::Refused,
        on_access_misses: arm.on_access_misses,
        payload_version: POINTER_PAYLOAD_VERSION,
        gated: GatedRoots::default(),
        swept: SweptScopeState::default(),
        moved_seed: MovedScopeSeed::default(),
        root_fallback: None,
    };
    // The cut about to run mints a fresh seed at a fresh epoch, so the walked
    // material for this scope is superseded the moment it lands. Standing the
    // walk down before the cut rather than after keeps a failed one from leaving
    // material a later pass would seal under.
    arm.walked_epochs.borrow_mut().remove(&scope_root);
    flat_root_cut(
        &net,
        None,
        FlatCut {
            scope: &scope,
            ascent: ascent.as_deref(),
            make_sweep: || sweep(scope.clone(), ascent.clone()),
        },
    )
    .await
}

/// The flat read-plane root cut, over one already-assembled owner net: gate the
/// scope root, re-seal the **unchanged** committed set under a fresh override
/// seed at the next epoch, publish under a compare-and-set, raise the epoch
/// floor, and enqueue the lazy wave.
///
/// `anchor` is the vault pointer when the scope is the vault root, and the cut
/// then vouches its epoch there between the publish and the floor raise
/// ([`VaultPointerVoucher`]).
///
/// The one plan a manual rotation and a scope exit share (blueprint/engine.md
/// "Triggers": both re-seal an unchanged committed set, so neither is the
/// revocation cascade). Only which scope, whose seams and which sweep differ.
pub(crate) async fn flat_root_cut<T, H, C, F, Sch, E, S>(
    net: &OwnerRotationNet<'_, T, H, C, F, Sch, E, S>,
    anchor: Option<&VaultPointerVoucher<'_, T, H, C, F, Sch, E>>,
    cut: FlatCut<'_, impl Fn() -> BoxedTask>,
) -> Result<RotationOutcome, RotateError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
    S: SnapshotCache,
{
    let FlatCut {
        scope,
        ascent,
        make_sweep,
    } = cut;
    // The resolve reads a cut with no ascent authority as the vault root's, and
    // that cut owes the vault pointer its epoch before the floor rises.
    if ascent.is_none() && anchor.is_none() {
        return Err(RotateError::Resolve(ResolveFailure::Unavailable));
    }
    let current = net
        .resolve_anchored(scope)
        .await
        .map_err(RotateError::Resolve)?;
    if let Some(anchor) = anchor {
        let vouched = anchor
            .standing(&scope.ipns_name)
            .await
            .map_err(RotateError::Publish)?;
        // A root published above the vouch is an earlier cut that never
        // vouched: finish that cut, since another would move the floor further
        // past the anchor.
        if current.current_read_epoch > vouched.min_read_epoch() {
            anchor
                .vouch_over(vouched, current.current_read_epoch)
                .await
                .map_err(RotateError::Publish)?;
            return complete_cut(
                net.floors,
                net.scheduler,
                &scope.scope_id,
                current.current_read_epoch,
                make_sweep,
            )
            .await;
        }
    }
    rotate_scope(
        &mut SharedEntropy(net.entropy),
        net.floors,
        net.scheduler,
        &VouchedRoot { root: net, anchor },
        &RotateScopePlan {
            identity: ScopeRootIdentity {
                v: current.v,
                scope_id: scope.scope_id,
                ipns_name: &scope.ipns_name,
                owner_enc_pub: &current.owner_enc_pub,
                owner_enc_secret: Some(net.keys.enc_secret),
                ascent: ascent.map(AscentAuthority::ParentSeed),
                owes_ascent_link: current.carried_ascent_link,
                pseudonym_signer: &current.pseudonym_signer,
            },
            committed: CommittedSet {
                commitment: &current.commitment,
                commitment_sig: &current.commitment_sig,
                grant_ledger: &current.grant_ledger,
                direct_child_scope_index: &current.direct_child_scope_index,
                revoked_recipients: &[],
            },
            current_override_seed: &current.override_seed,
            current_read_epoch: current.current_read_epoch,
            write_scope_seed: &current.write_scope_seed,
            write_epoch: current.write_epoch,
            write_history_link: &current.write_history_link,
            pointer_read_key: &current.pointer_read_key,
            carried_history_links: &current.carried_history_links,
        },
        make_sweep,
    )
    .await
}

/// What one flat root cut acts on: the scope it gates, the ascent authority that
/// scope's own record proves under, and the lazy wave the cut enqueues.
pub(crate) struct FlatCut<'a, S: Fn() -> BoxedTask> {
    pub(crate) scope: &'a ChildScopeRef,
    pub(crate) ascent: Option<&'a [u8; 32]>,
    pub(crate) make_sweep: S,
}
