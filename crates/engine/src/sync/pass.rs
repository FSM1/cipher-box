//! One sync pass (CONTEXT.md "Sync pass"; blueprint/engine.md "Sync core", "Liveness").
//!
//! [`TickPass::run`] is the body [`run_tick_loop`](crate::sync::tick::run_tick_loop)
//! calls once per tick. It reconciles the vault root and the focus window,
//! drains the op queue onto that state, pulls the mailbox, and converts
//! claims. Its [`PassReport`] carries the verdict the facade stamps the
//! staleness ladder from.

use core::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use cipherbox_core::hex::lower as hex_lower;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::Permission as CommittedPermission;
use cipherbox_core::suite::ecdsa::{EcdsaVerifier, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use futures_channel::mpsc;
use zeroize::Zeroizing;

use crate::bin_index::BinIndexKeys;
use crate::facade::claim_conversion::{
    ConversionPass, CutAuthority, PointerIndex, TickSites, placed, scope_pointer_index,
};
use crate::facade::{
    EngineError, Event, ForkSightings, MAX_FOCUS_FILES, NodeId, emit_trust_violation, memoized_scan,
};
use crate::grants::grafted::{
    BookmarkedPermissions, BookmarkedScopeRoots, ContestedNodes, FloorNamespace, GraftedPlane,
    GraftedSharers, evict_grafted_read_seeds, evict_grafted_write_seeds, floor_namespace,
    floor_view, is_own_scope,
};
use crate::grants::inbox::{OwnedClaim, ShareInbox};
use crate::grants::link_read::repost_held_claims;
use crate::grants::received_status::{ReceivedShareStatus, ScopeRender};
use crate::grants::{ContactStore, StagingContactStore};
use crate::net::author::ENVELOPE_V;
use crate::net::rotation::ScopeWritePlane;
use crate::net::{
    DescendantScopeRoot, FolderRefresh, GraftedLeg, HeldKey, HeldMaterial, HeldRecords,
    PointerConsult, PointerConsultError, ResolveOutcome, Resolved, RootAdopter, ScopeWalk,
    WalkFailure, WritePlaneDark, observed_at, refresh_base_from_resolved, resolve_and_hold,
};
use crate::rotation::scope_material::ScopeMaterial;
use crate::rotation::{
    Boundaries, ResolveFailure, RotateError, RotateOnExit, ScopeExitArm, SweepKeys,
    ascent_node_seed, cut_exited_scope, derive_write_name, install_walked_read_epochs,
};
use crate::scope_seeds::{
    ScopeSeeds, SeedFloor, SeedFloors, StampedSeed, cached_seed, cached_seed_in,
    cached_stamped_seed, cached_stamped_seed_in, current_seed, deposit_seed, deposit_write_seed,
    own_descendant_scopes, refresh_seed_floors, walked_boundary_material,
};
use crate::seams::{
    CredentialStore, FloorStore, Http, QueueGeneration, RecordTransport, Scheduler, SeamError,
    SharerScopedFloorStore, SnapshotCache, StagingStore, UnixMillis,
};
use crate::session::{SessionSecrets, SessionState};
use crate::settings::{
    PlacementDecision, SessionPlacement, adopt_settings_summary, bin_retention_days,
    load_settings_at, owner_bin_retention_days, owner_retention, redecide_placement,
    report_settings_verdict, summarize_settings,
};
use crate::sync::BookkeepingSeal;
use crate::sync::drain::{
    Drain, DrainScope, EngineSeams, EpochSeed, GrantedPass, ScopeEnd, SealPlane, TickInputs,
    TickScopes, hold_captures, published_op_mark,
};
use crate::sync::kept_op::keeps;
use crate::sync::model::Snapshot;
use crate::sync::op::{Op, OpKind};
use crate::sync::owed_rotation::OwedRotation;
use crate::sync::pointer::POINTER_PAYLOAD_VERSION;
use crate::sync::project::{UnlinkedChild, merge_root};
use crate::sync::rebase::{DropReason, QueueScanMemo, enclosing_scope_root, replay};
use crate::sync::record::RecordReader;
use crate::sync::refresh::{ManualRefresh, RefreshVerdict};
use crate::sync::render::BaseSnapshot;
use crate::sync::tick::{
    ResolveMode, TickCause, consult_scopes, consult_scopes_due, expire_focus_stamps,
    expire_touched_folders, focus_by_scope, focus_files, focus_scope_roots, nodes_in_scope,
    pace_due, queue_unprojected_children, resolve_mode, scope_root_of, scope_root_record_name,
    settle_focus_leg,
};

/// The tick's per-session inputs: the seam set, the session secrets, and the
/// pacing stamps one pass reads and advances.
pub(crate) struct TickPass<T, H: Http, C: CredentialStore, F, S, St, Sch> {
    pub(crate) seams: EngineSeams<T, H, C, F, S, St, Sch>,
    secrets: Rc<SessionSecrets>,
    alive: Rc<Cell<bool>>,
    pub(crate) manual: ManualRefresh,
    owner_identity: EcdsaVerifier,
    root_id: [u8; 16],
    settings_rechecked: Cell<UnixMillis>,
    link_swept: Cell<UnixMillis>,
}

/// What one pass reports to the loop that ran it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PassReport {
    /// The root leg's verdict. The ladder measures the record plane, which the
    /// root leg alone proves answered: one focused folder that did not is
    /// staleness on that folder, not a plane-wide outage.
    pub(crate) verdict: RefreshVerdict,
    /// The session is gone, so the loop stops.
    pub(crate) stop: bool,
}

impl PassReport {
    const STOPPED: Self = Self {
        verdict: RefreshVerdict::Unreachable,
        stop: true,
    };

    /// The record plane answered with gate-passing state.
    pub(crate) fn converged(self) -> bool {
        self.verdict == RefreshVerdict::Reconciled
    }
}

/// What the loop gate hands every later stage of one pass.
struct Pass {
    mode: ResolveMode,
    now: UnixMillis,
    /// The consult stage moves it to the anchor's owner-vouched current root.
    root_name: IpnsName,
    enc_subkey: X25519Secret,
    contact_label_seed: SecretBytes,
    bin_keys: Rc<BinIndexKeys>,
    settings_signer: Rc<Ed25519Signer>,
}

/// The passes one tick drains, owned for the drain that borrows them.
struct Assembly {
    write_seed: Option<Zeroizing<[u8; 32]>>,
    grafted: Vec<GraftedWritePass>,
    read_only_grafts: Vec<NodeId>,
    grafted_scope_roots: BookmarkedScopeRoots,
    grafted_contested: ContestedNodes,
    proved_roots: Vec<NodeId>,
    descendants: Vec<DescendantScopeRoot>,
}

/// The scope roots this pass's focus legs grouped by: the proved set and the
/// set a walk named without material, as the legs read them.
struct ScopeSets {
    proved: BTreeSet<NodeId>,
    unproved: BTreeSet<NodeId>,
}

/// What every scope leg of one tick or one navigation reads alike.
pub(crate) struct ScopeLegContext<'a, F> {
    pub(crate) floors: &'a F,
    pub(crate) sharers: &'a GraftedSharers,
    pub(crate) contact_label_seed: &'a SecretBytes,
    pub(crate) own_root: [u8; 16],
    /// This vault's own scope roots below its root. The own check and the
    /// floor namespace read this one set.
    pub(crate) own: &'a BTreeSet<NodeId>,
    pub(crate) unproved: &'a BTreeSet<NodeId>,
    pub(crate) base: &'a BaseSnapshot,
    pub(crate) root_name: Option<&'a IpnsName>,
}

/// One scope's leg material: the seed and floors its records unseal and gate
/// under, and the plane it reads on.
pub(crate) struct ScopeLegMaterial<'a, F> {
    pub(crate) seed: StampedSeed,
    pub(crate) floors: SharerScopedFloorStore<'a, F>,
    pub(crate) scope_root_name: Option<IpnsName>,
    /// `false` for a grafted scope, which reads on the grafted plane.
    pub(crate) own: bool,
}

/// Why a scope runs no leg.
pub(crate) enum NoScopeLeg {
    /// The pass is charged an outage: a boundary no walk proved material for
    /// ([`focus_scope_roots`]), or a scope this vault owns and holds no seed
    /// for, such as a promotion the last walk could not re-prove.
    Outage,
    /// Its rows wait for a pass that holds its material.
    Waiting,
}

impl<'a, F: FloorStore> ScopeLegContext<'a, F> {
    /// The material of `scope`'s leg. Its read seed passes the floor eviction
    /// against the floors the leg gates under ([`current_seed`]), so a floor
    /// raised since the start-of-pass eviction evicts it here.
    pub(crate) async fn material(
        &self,
        scope: NodeId,
        read_seeds: &RefCell<ScopeSeeds>,
    ) -> Result<ScopeLegMaterial<'a, F>, NoScopeLeg> {
        if self.unproved.contains(&scope) {
            return Err(NoScopeLeg::Outage);
        }
        let own = is_own_scope(&self.own_root, self.own, &scope.0);
        let floors = floor_view(
            self.floors,
            self.sharers,
            self.contact_label_seed,
            &self.own_root,
            self.own,
            &scope.0,
        )
        .ok_or(NoScopeLeg::Waiting)?;
        let Some(seed) = current_seed(&floors, read_seeds, &scope.0, SeedFloor::Read).await else {
            return Err(if own {
                NoScopeLeg::Outage
            } else {
                NoScopeLeg::Waiting
            });
        };
        let scope_root_name = scope_root_record_name(&self.base.borrow(), self.root_name, &scope.0);
        Ok(ScopeLegMaterial {
            seed,
            floors,
            scope_root_name,
            own,
        })
    }
}

/// What the mailbox pull hands the claim conversion.
struct MailboxPull {
    owner_keys: Option<Rc<SweepKeys>>,
    pointers: PointerIndex,
    claims: Option<Vec<OwnedClaim>>,
}

impl<T, H, C, F, S, St, Sch> TickPass<T, H, C, F, S, St, Sch>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    S: SnapshotCache,
    St: StagingStore + QueueGeneration,
    Sch: Scheduler + Clone + 'static,
{
    /// Start has just decided, so the first re-decide comes one interval on.
    pub(crate) fn new(
        seams: EngineSeams<T, H, C, F, S, St, Sch>,
        secrets: Rc<SessionSecrets>,
        alive: Rc<Cell<bool>>,
        manual: ManualRefresh,
        owner_identity: EcdsaVerifier,
        root_id: [u8; 16],
    ) -> Self {
        let settings_rechecked = Cell::new(seams.scheduler.now());
        let link_swept = Cell::new(seams.scheduler.now());
        Self {
            seams,
            secrets,
            alive,
            manual,
            owner_identity,
            root_id,
            settings_rechecked,
            link_swept,
        }
    }

    /// One tick, and its report: a stopped one once the session is gone.
    pub(crate) async fn run(&self, state: &SessionState, cause: TickCause) -> PassReport {
        let Some(mut pass) = self.loop_gate(state, cause) else {
            return PassReport::STOPPED;
        };
        let Some(decision) = self.redecide_settings(state, &pass).await else {
            return PassReport::STOPPED;
        };
        self.consult_scope_pointers(state, &mut pass).await;
        let (floors_before, grafted) = self.refresh_floors(state, &pass).await;
        let (resolved, read_seed) = self.adopt_root(state, &pass, &floors_before).await;
        let descendants = self.walk_scopes(state, &pass).await;
        let (folder_verdict, scopes) = self.refresh_focus(state, &pass, &grafted).await;
        let verdict = self.settle_verdict(state, &resolved, folder_verdict);
        let assembly = self
            .assemble_scopes(state, &pass, &scopes, descendants)
            .await;
        let boundaries = self
            .drain(state, &pass, &decision, &read_seed, &scopes, assembly)
            .await;
        let pulled = self.pull_mailbox(state, &pass, &boundaries).await;
        self.convert_claims(state, &pass, boundaries.as_ref(), pulled)
            .await;
        self.repost_claims(state, &pass).await;
        self.refresh_received_shares(state, &pass).await;
        PassReport {
            verdict,
            stop: false,
        }
    }

    /// The loop gate: the pass's own copy of every secret it runs under, or
    /// `None` once the session is gone.
    fn loop_gate(&self, state: &SessionState, cause: TickCause) -> Option<Pass> {
        if !self.alive.get() {
            return None;
        }
        let mode = resolve_mode(cause);
        // The session cell is the root's only current name: a wave
        // this session drove between passes has already moved it.
        let root_name = state.current_root_name.borrow().clone()?;
        // The pass owns a copy for exactly its own duration; the engine
        // emptied the cell if it is already gone.
        let enc_subkey = self.secrets.tick_enc_subkey.borrow().clone()?;
        let contact_label_seed = self.secrets.tick_contact_label_seed.borrow().clone()?;
        let bin_keys = self.secrets.tick_bin_keys.borrow().clone()?;
        let settings_signer = self.secrets.tick_settings_signer.borrow().clone()?;
        let now = self.seams.scheduler.now();
        Some(Pass {
            mode,
            now,
            root_name,
            enc_subkey,
            contact_label_seed,
            bin_keys,
            settings_signer,
        })
    }

    /// The settings re-decide, paced by the recheck interval, then the placement
    /// the pass drains under.
    async fn redecide_settings(
        &self,
        state: &SessionState,
        pass: &Pass,
    ) -> Option<PlacementDecision> {
        // What this paces is a revocation window
        // ([`redecide_placement`]).
        if pace_due(
            pass.now,
            self.settings_rechecked.get(),
            self.seams.profile.settings_recheck_interval,
        ) {
            self.settings_rechecked.set(pass.now);
            let observed = observed_at(&state.held_records, HeldKey::VaultSettings);
            let read = load_settings_at(
                &self.seams.transport,
                &self.seams.gateway,
                &self.seams.http,
                &self.seams.floors,
                &self.seams.snapshot_cache,
                &self.seams.scheduler,
                &self.seams.profile,
                &pass.enc_subkey,
                &pass.settings_signer,
            )
            .await;
            // A teardown that landed inside the load already
            // cleared the placement cell, which holds the member's
            // provider bearer, and the renewal slot, which holds
            // the record's signer. Writing either back would make
            // it resident again and re-arm the pass the cleared
            // cell stops below (security rules 1 and 7).
            if !self.alive.get() {
                return None;
            }
            let load = read.enrol(&state.held_records, observed);
            report_settings_verdict(&self.seams.events, &load);
            let held = state.placement.borrow().as_ref().map(|held| held.source);
            if let Some(decided) = redecide_placement(held, &load) {
                *state.placement.borrow_mut() = Some(decided);
                adopt_settings_summary(
                    summarize_settings(&load),
                    &state.settings_summary,
                    &self.seams.events,
                );
                state.byo_reconciled.set(false);
            }
        }
        // Carries the member's BYO bearer, so the pass owns a copy on the
        // same terms as the enc subkey the loop gate copied.
        let SessionPlacement { decision, .. } = state.placement.borrow().clone()?;
        Some(decision)
    }

    /// The polled pointer consult over the scopes due this pass.
    async fn consult_scope_pointers(&self, state: &SessionState, pass: &mut Pass) {
        // The polled pointer consult (#38 D4), ahead of the floor
        // refresh that follows so a write epoch this pass sights evicts the
        // seed it retired in the same pass.
        // A manual refresh resolves nocache everywhere, so it
        // consults every scope in the window rather than waiting out
        // the interval the poll leg is paced by.
        let consult_targets = match pass.mode {
            ResolveMode::NoCache => consult_scopes(&state.snapshot.borrow(), &state.focus.borrow()),
            ResolveMode::CacheFirst => consult_scopes_due(
                &state.snapshot.borrow(),
                &state.focus.borrow(),
                &state.pointer_consulted.borrow(),
                pass.now,
                &self.seams.profile,
            ),
        };
        if let Some(current_root) = consult_pointers(
            &self.seams.transport,
            &self.seams.floors,
            &self.secrets.sweep_keys,
            &self.seams.events,
            &state.pointer_consulted,
            ConsultWindow {
                scopes: consult_targets,
                anchor: NodeId(self.root_id),
                now: pass.now,
            },
        )
        .await
        {
            *state.current_root_name.borrow_mut() = Some(current_root.clone());
            pass.root_name = current_root;
        }
    }

    /// The seed-floor refresh: evict every seed a raised floor revoked, and report
    /// the floors the root adopt stamps with.
    async fn refresh_floors(
        &self,
        state: &SessionState,
        pass: &Pass,
    ) -> (SeedFloors, GraftedSharers) {
        // Before the steady-state hold consults them: a floor raised
        // since the last pass revokes the seeds this pass would
        // otherwise read and seal under. The floors it reports stamp
        // whatever this pass's own resolve recovers.
        let floors_before = refresh_seed_floors(
            &self.seams.floors,
            &self.root_id,
            &state.scope_read_seeds,
            &state.scope_write_seeds,
        )
        .await;
        let grafted = state.grafted_sharers.borrow().clone();
        let own_before =
            own_descendant_scopes(&state.descendant_scope_roots, &state.minted_scope_roots);
        evict_grafted_read_seeds(
            &self.seams.floors,
            &grafted,
            &pass.contact_label_seed,
            &self.root_id,
            &own_before,
            &state.scope_read_seeds,
        )
        .await;
        evict_grafted_write_seeds(
            &self.seams.floors,
            &grafted,
            &pass.contact_label_seed,
            &self.root_id,
            &own_before,
            &state.scope_write_seeds,
        )
        .await;
        (floors_before, grafted)
    }

    /// The root adopt: resolve the vault root through the gate, deposit the seeds
    /// it surfaces, and answer the root's read seed after it.
    async fn adopt_root(
        &self,
        state: &SessionState,
        pass: &Pass,
        floors_before: &SeedFloors,
    ) -> (Result<Resolved, SeamError>, Option<StampedSeed>) {
        let adopter = RootAdopter::new(
            &self.seams.gateway,
            &self.seams.http,
            &self.seams.floors,
            &pass.enc_subkey,
            &self.owner_identity,
            self.root_id,
        )
        .holding(steady_state_hold(
            &state.held_records,
            self.root_id,
            &pass.root_name,
            &state.scope_read_seeds,
            &state.scope_write_seeds,
        ));
        // Own-root material: the write-scope seed the owner cannot
        // re-derive rides the adopt (recovered from the owner-write-blob),
        // so the caller-side seed is `None` and the gate's authenticated
        // node id keys the hold. A resolve/gate failure is availability —
        // it never stops the loop (blueprint/engine.md "Liveness").
        let material = HeldMaterial {
            node_id: self.root_id,
            write_scope_seed: None,
        };
        // A gate-passing `Adopted` repaints the shared base cell and emits
        // `SnapshotUpdated`; `Current`/`NoUpdate`/`TrustViolation` leave
        // last-known-good intact (fail-closed for data).
        let mut held_resolve = resolve_and_hold(
            &self.seams.transport,
            &self.seams.snapshot_cache,
            &adopter,
            &pass.root_name,
            &state.held_records,
            &material,
            pass.mode,
        )
        .await;
        // A gate-passing adopt re-surfaces the scope seeds: refresh the
        // in-memory per-scope cells the child read pipeline and the
        // drain derive from.
        if let Ok(surfaced) = &mut held_resolve {
            if let Some(seed) = surfaced.read_scope_seed.take() {
                // An adopt names the epoch its own owner blob's seed
                // belongs to; an equal-floor `Current` recovery does not,
                // and takes the pre-resolve floor (see `deposit_seed`).
                let stamp = match &surfaced.resolved.outcome {
                    ResolveOutcome::Adopted(adopted) => Some(adopted.epoch),
                    _ => floors_before.read,
                };
                deposit_seed(
                    &state.scope_read_seeds,
                    self.root_id,
                    seed,
                    stamp,
                    FloorNamespace::Own,
                );
            }
            if let Some((node_id, seed)) = surfaced.write_scope_seed.take() {
                deposit_write_seed(
                    &state.scope_write_seeds,
                    node_id,
                    seed,
                    Some(&pass.root_name),
                    floors_before.write,
                    FloorNamespace::Own,
                );
            }
        }
        let resolved = held_resolve.map(|surfaced| surfaced.resolved);
        if let Ok(resolved) = &resolved {
            if let ResolveOutcome::TrustViolation(rejection) = &resolved.outcome {
                emit_trust_violation(&self.seams.events, pass.root_name.as_str(), rejection);
            }
            if let Some(fork) = resolved.fork {
                state.fork_sightings.report(
                    &self.seams.events,
                    pass.root_name.as_str(),
                    fork.sequence,
                );
            }
            let merged =
                refresh_base_from_resolved(&state.snapshot, NodeId(self.root_id), resolved);
            if merged.changed {
                let _ = self.seams.events.unbounded_send(Event::SnapshotUpdated);
            }
            hold_captures(
                &state.observed_unlinks,
                merged.observed_unlinks(self.root_id, NodeId(self.root_id), pass.now.0),
            );
        }
        let read_seed = cached_stamped_seed(&state.scope_read_seeds, &self.root_id);
        (resolved, read_seed)
    }

    /// The scope walk below the vault root, and the boundaries it proved.
    async fn walk_scopes(&self, state: &SessionState, pass: &Pass) -> Vec<DescendantScopeRoot> {
        // The held record is the root this pass reconciled, so the
        // walk needs no second read of either plane to start.
        let held_root = state
            .held_records
            .borrow()
            .get(&HeldKey::Node(self.root_id))
            .map(|record| (record.routing_key.clone(), record.record_bytes.clone()));
        // Cloned out of the cell: a `Ref` cannot be held across the
        // walk's awaits.
        let walk_keys = self.secrets.sweep_keys.borrow().clone();
        let mut descendants = Vec::new();
        let walk = walk_keys.as_ref().map(|keys| ScopeWalk {
            transport: &self.seams.transport,
            snapshot_cache: &self.seams.snapshot_cache,
            gateway: &self.seams.gateway,
            http: &self.seams.http,
            floors: &self.seams.floors,
            enc_secret: &pass.enc_subkey,
            identity: &self.owner_identity,
            scope_keys: &keys.scope_keys,
            payload_version: POINTER_PAYLOAD_VERSION,
        });
        if let Some(walk) = &walk
            && let Some((name, root_bytes)) = held_root
            && let Ok(name) = IpnsName::parse(&name)
        {
            let walked = walk
                .descendant_scope_roots(self.root_id, &name, &root_bytes)
                .await;
            let failure = walked
                .as_ref()
                .map_or_else(|met| Some(*met), |walked| walked.failure);
            *state.walk_refused_roots.borrow_mut() = walked
                .as_ref()
                .map(|walked| walked.refused.clone())
                .unwrap_or_default();
            if let Ok(walked) = walked {
                let departed = install_descendant_scopes(
                    &state.descendant_scope_roots,
                    &state.scope_read_seeds,
                    &state.scope_write_seeds,
                    &state.snapshot,
                    &self.seams.events,
                    &walked.proved,
                    pass.now.0,
                );
                hold_captures(&state.observed_unlinks, departed);
                install_walked_read_epochs(&state.walked_read_epochs, &walked.proved);
                *state.unfinished_write_cuts.borrow_mut() = walked
                    .proved
                    .iter()
                    .filter(|scope| scope.write_cut_unfinished)
                    .map(|scope| scope.scope_id)
                    .collect();
                report_forked_scopes(&state.fork_sightings, &self.seams.events, &walked.proved);
                install_unproved_scopes(
                    &state.unproved_scope_roots,
                    walked.proved.iter().map(|s| NodeId(s.scope_id)),
                    walked.unproved,
                );
                descendants = walked.proved;
                state.land_boundary_walk();
            }
            state
                .scope_roots_walked
                .set(failure.is_none() && state.unproved_scope_roots.borrow().is_empty());
            // The boundary set a rejection leaves is incomplete, and
            // what is missing from it reads as its parent's scope,
            // so the session refuses to classify a move at all until
            // a walk names the whole set again.
            match failure {
                None => state.boundary_walk_rejected.set(false),
                Some(rejected @ WalkFailure::Rejected { .. }) => {
                    state.reject_boundary_walk();
                    emit_trust_violation(&self.seams.events, name.as_str(), rejected);
                }
                Some(WalkFailure::Unavailable) => {}
            }
        }
        descendants
    }

    /// The focus-window legs, one per scope, and the scope sets they grouped by.
    async fn refresh_focus(
        &self,
        state: &SessionState,
        pass: &Pass,
        grafted: &GraftedSharers,
    ) -> (RefreshVerdict, ScopeSets) {
        expire_touched_folders(
            &mut state.focus.borrow_mut(),
            self.seams.scheduler.now(),
            &self.seams.profile,
        );
        expire_focus_stamps(
            &mut state.focus_refreshed.borrow_mut(),
            self.seams.scheduler.now(),
            &self.seams.profile,
        );
        // The focus window's folders below each scope root — the read
        // leg for a subtree this device did not author. It runs before
        // the drain, so the queue rebases onto the deepest state this
        // pass reconciled, not just the root's.
        //
        // Grouped by scope: a leg holds one scope's read material, so a
        // record sealed under another would fail its AAD-bound unseal
        // and be reported as abuse by an honest writer. A scope whose
        // seed this device has not recovered serves nothing, and its
        // files stay queued for the pass that can.
        let mut folder_verdict = RefreshVerdict::Reconciled;
        let mut attempted_files: Vec<NodeId> = Vec::new();
        let scopes = ScopeSets {
            proved: state.descendant_scope_roots.borrow().clone(),
            unproved: state.unproved_scope_roots.borrow().clone(),
        };
        let focus_scope_ids = focus_scope_roots(&scopes.proved, &scopes.unproved);
        let mut by_scope = focus_by_scope(
            &state.snapshot.borrow(),
            &state.focus.borrow(),
            &focus_scope_ids,
        );
        // A root this session minted carries a grant section before any walk
        // proves it, so its own record is no child of the enclosing scope. Its
        // interior stays on the walk's grouping: while its interior move is
        // owed, that interior is still sealed under the enclosing scope.
        {
            let minted = state.minted_scope_roots.borrow();
            for targets in by_scope.values_mut() {
                targets.folders.retain(|folder| !minted.contains(folder));
            }
        }
        // A window whose only folder in view is a scope root groups
        // no folder target of its own, because that root resolves on
        // its pointer leg. Its scope still needs a pass, so the rows
        // it lists reach the file leg below.
        for folder in state.focus.borrow().folders_in_view() {
            by_scope
                .entry(scope_root_of(
                    &state.snapshot.borrow(),
                    folder,
                    &focus_scope_ids,
                ))
                .or_default();
        }
        let scope_roots = state.bookmarked_scope_roots.borrow().clone();
        let legs = ScopeLegContext {
            floors: &self.seams.floors,
            sharers: grafted,
            contact_label_seed: &pass.contact_label_seed,
            own_root: self.root_id,
            own: &scopes.proved,
            unproved: &scopes.unproved,
            base: &state.snapshot,
            root_name: Some(&pass.root_name),
        };
        for (scope_root, targets) in by_scope {
            let material = match legs.material(scope_root, &state.scope_read_seeds).await {
                Ok(material) => material,
                Err(NoScopeLeg::Outage) => {
                    folder_verdict = folder_verdict.worst(RefreshVerdict::Unreachable);
                    continue;
                }
                Err(NoScopeLeg::Waiting) => continue,
            };
            let refresh = FolderRefresh {
                transport: &self.seams.transport,
                snapshot_cache: &self.seams.snapshot_cache,
                http: &self.seams.http,
                floors: &material.floors,
                gateway: &self.seams.gateway,
                base: &state.snapshot,
                events: &self.seams.events,
                forks: &state.fork_sightings,
                scope_id: scope_root.0,
                scope_read_seed: &material.seed.seed,
                seed_stamp: Some(material.seed.stamp),
                scope_root_name: material.scope_root_name.as_ref(),
                plane: (!material.own).then_some(GraftedLeg {
                    scope_roots: &scope_roots,
                    claims: &state.grafted_claims,
                }),
                mode: pass.mode,
                observed_at: pass.now.0,
            };
            let mut settle = |nodes: &[NodeId], report| {
                folder_verdict = folder_verdict.worst(settle_focus_leg(
                    &state.observed_unlinks,
                    &state.focus_refreshed,
                    &self.seams.events,
                    nodes,
                    report,
                    self.seams.scheduler.now(),
                ));
            };
            if !targets.folders.is_empty() {
                settle(&targets.folders, refresh.run(&targets.folders).await);
            }
            // The pass has just listed the folders in view, so a row
            // another device added joins the file leg below. Only
            // folders in view queue: an ancestor rides the folder
            // leg to walk the gate, not to be painted. The open
            // folder queues last, since the bound drops the oldest
            // entry and a merely touched folder must not evict it.
            let files = {
                let base_now = state.snapshot.borrow();
                let in_view = nodes_in_scope(
                    &base_now,
                    &focus_scope_ids,
                    scope_root,
                    state.focus.borrow().folders_in_view().collect(),
                );
                for folder in in_view.into_iter().rev() {
                    queue_unprojected_children(
                        &base_now,
                        &state.focus,
                        &state.focus_refreshed,
                        &self.seams.profile,
                        self.seams.scheduler.now(),
                        folder,
                    );
                }
                let host_queued = state.focus.borrow().host_queued();
                leg_file_share(
                    nodes_in_scope(
                        &base_now,
                        &focus_scope_ids,
                        scope_root,
                        focus_files(&base_now, &state.focus.borrow()),
                    ),
                    &attempted_files,
                    &host_queued,
                )
            };
            attempted_files.extend(files.iter().copied());
            if !files.is_empty() {
                settle(&files, refresh.run_files(&files).await);
            }
        }
        // Take only what this pass attempted. A lookup queues a file
        // while the refreshes above are awaited, and a wholesale
        // replacement would drop what arrived after the snapshot.
        state
            .focus
            .borrow_mut()
            .open_files
            .retain(|row| !attempted_files.contains(&row.node));
        (folder_verdict, scopes)
    }

    /// The verdict and manual settle: answer the manual requests, and report
    /// the root leg's verdict.
    fn settle_verdict(
        &self,
        state: &SessionState,
        resolved: &Result<Resolved, SeamError>,
        folder_verdict: RefreshVerdict,
    ) -> RefreshVerdict {
        // `Adopted`/`Current` are the reconciled outcomes: both prove the
        // record plane answered with gate-passing state, so both stamp
        // the ladder's `last_success` (#33 D4). A gate rejection is a
        // trust verdict, never the staleness the other failures are.
        let root_verdict = match resolved {
            Ok(r) => match &r.outcome {
                ResolveOutcome::Adopted(_) | ResolveOutcome::Current { .. } => {
                    RefreshVerdict::Reconciled
                }
                ResolveOutcome::TrustViolation(_) => RefreshVerdict::Rejected,
                ResolveOutcome::NoUpdate => RefreshVerdict::Unreachable,
            },
            Err(_) => RefreshVerdict::Unreachable,
        };
        // Answer the manual requests on every read leg the pass forced,
        // the focus window included — a refresh that left the folder in
        // view unresolved has not landed. The drain stage reports its own
        // progress through the op events.
        self.manual.settle(root_verdict.worst(folder_verdict));
        // A vault that keeps no bin captures no unlink either: the
        // owner turned the bin off, and an adoption carries no owner
        // command that could overrule that.
        if bin_retention_days(&state.settings_summary) == 0 {
            state.observed_unlinks.borrow_mut().clear();
            state.capture_proofs.borrow_mut().clear();
        }
        root_verdict
    }

    /// The scope assembly: every pass the drain runs, owned.
    async fn assemble_scopes(
        &self,
        state: &SessionState,
        pass: &Pass,
        scopes: &ScopeSets,
        descendants: Vec<DescendantScopeRoot>,
    ) -> Assembly {
        // The drain rides the same tick: it publishes onto exactly the
        // gate-passing state this pass just reconciled. Both scope seeds
        // are required — without them there is no name to publish under
        // and no key to seal with, so the queue simply waits.
        let write_seed = cached_seed(&state.scope_write_seeds, &self.root_id);
        let write_grafts = write_grant_sharers(
            &state.bookmarked_permissions.borrow(),
            &state.grafted_sharers.borrow(),
        );
        let sharer_encs = write_grant_sharer_encs(
            &StagingContactStore::new(&self.seams.staging, &pass.enc_subkey, &self.seams.entropy),
            write_grafts,
        )
        .await;
        // One pass per scope: a pass seals every record it publishes
        // at one scope root's epoch under that root's seeds.
        //
        // The boundary set is the session's, not this walk's. A
        // promotion a pass could not re-prove keeps its entry, so
        // the vault root's pass still stops at it rather than
        // claiming the whole suffix below it
        // ([`install_descendant_scopes`]).
        // A grafted root is no descendant of this vault's own
        // root, so no walk from that root proves it: it joins the
        // routing set from the bookmark instead, or an op below a
        // shared folder reaches no root at all.
        let grafted = {
            let sharers = state.grafted_sharers.borrow();
            grafted_write_passes(
                &state.snapshot,
                &state.bookmarked_permissions.borrow(),
                &sharers,
                &sharer_encs,
                |scope_id| {
                    floor_namespace(
                        &sharers,
                        &pass.contact_label_seed,
                        &self.root_id,
                        &scopes.proved,
                        scope_id,
                    )
                },
                &state.scope_read_seeds,
                &state.scope_write_seeds,
            )
        };
        let write_roots: BTreeSet<NodeId> = grafted.iter().map(|pass| pass.root).collect();
        // The snapshot's permission reads this set, so a host
        // repaints on the tick that proves or drops a write pass.
        if *state.grafted_write_roots.borrow() != write_roots {
            *state.grafted_write_roots.borrow_mut() = write_roots;
            let _ = self.seams.events.unbounded_send(Event::SnapshotUpdated);
        }
        // A graft this vault may only read — a read grant, or a write
        // grant the sharer cut — publishes an op below it on no
        // pass. Listed keyless, so the pass holding the identity's
        // charge dead-letters such an op rather than stall the
        // strict-FIFO head behind it.
        let read_only_grafts: Vec<NodeId> = state
            .bookmarked_permissions
            .borrow()
            .iter()
            .filter(|(scope_id, permission)| {
                **permission == CommittedPermission::Read
                    && !is_own_scope(&self.root_id, &scopes.proved, scope_id)
                    && !state
                        .minted_scope_roots
                        .borrow()
                        .contains(&NodeId(**scope_id))
                    && !scopes.unproved.contains(&NodeId(**scope_id))
            })
            .map(|(scope_id, _)| NodeId(*scope_id))
            .collect();
        // Owned for the drain, which awaits while it holds them.
        let grafted_scope_roots = state.bookmarked_scope_roots.borrow().clone();
        let grafted_contested = state.grafted_claims.borrow().contested().clone();
        let proved_roots: Vec<NodeId> = core::iter::once(NodeId(self.root_id))
            .chain(scopes.proved.iter().copied())
            .chain(grafted.iter().map(|pass| pass.root))
            .chain(read_only_grafts.iter().copied())
            .collect();
        Assembly {
            write_seed,
            grafted,
            read_only_grafts,
            grafted_scope_roots,
            grafted_contested,
            proved_roots,
            descendants,
        }
    }

    /// The per-scope drain, and the boundaries the later stages read.
    async fn drain<'a>(
        &'a self,
        state: &'a SessionState,
        pass: &Pass,
        decision: &PlacementDecision,
        read_seed: &'a Option<StampedSeed>,
        scopes: &ScopeSets,
        assembly: Assembly,
    ) -> Option<Boundaries<'a>> {
        let enc_subkey = &pass.enc_subkey;
        let Assembly {
            write_seed,
            grafted,
            read_only_grafts,
            grafted_scope_roots,
            grafted_contested,
            proved_roots,
            descendants,
        } = assembly;
        let vault_seeds = read_seed.as_ref().zip(write_seed.as_ref());
        let drivable: Vec<_> = descendants
            .iter()
            .filter_map(|scope| Some((scope, scope.write.as_ref().ok()?)))
            .collect();
        // A scope this pass merely could not reach is absent from
        // both lists: the valve waits on it rather than charging.
        let keyless_roots: Vec<NodeId> = descendants
            .iter()
            .filter(|scope| matches!(scope.write, Err(WritePlaneDark::Keyless)))
            .map(|scope| NodeId(scope.scope_id))
            .chain(read_only_grafts.iter().copied())
            .collect();
        // The vault-root pass's second end, and the cut a scope exit
        // owes: both read the boundaries this session knows, at the
        // material the walk proved for them.
        let boundaries = read_seed.as_ref().map(|root_read_seed| Boundaries {
            base: &state.snapshot,
            scope_roots: state
                .minted_scope_roots
                .borrow()
                .union(&scopes.proved)
                .copied()
                .collect(),
            material: walked_boundary_material(
                &state.walked_read_epochs,
                &state.scope_read_seeds,
                &state.scope_write_seeds,
            ),
            root: NodeId(self.root_id),
            root_read_seed: &root_read_seed.seed,
        });
        let second = match &boundaries {
            Some(boundaries) => {
                queued_second_end(
                    &self.seams.staging,
                    enc_subkey,
                    &state.queue_scan,
                    boundaries,
                )
                .await
            }
            None => None,
        };
        let exits = RotateOnExit(async |scope_root: NodeId| {
            let Some(boundaries) = &boundaries else {
                return Err(RotateError::Resolve(ResolveFailure::Unavailable));
            };
            cut_exited_scope(
                ScopeExitArm {
                    transport: &self.seams.transport,
                    api: &self.seams.api,
                    gateway: &self.seams.gateway,
                    http: &self.seams.http,
                    floors: &self.seams.floors,
                    snapshot_cache: &self.seams.snapshot_cache,
                    events: &self.seams.events,
                    scheduler: &self.seams.scheduler,
                    profile: &self.seams.profile,
                    entropy: &self.seams.entropy,
                    keys: &self.secrets.sweep_keys,
                    sweep: &state.sweep_tasks,
                    boundaries,
                    walked_epochs: &state.walked_read_epochs,
                    on_access_misses: &state.on_access_misses,
                },
                scope_root,
            )
            .await
        });
        let vault = vault_seeds.map(|(read_seed, write_seed)| DrainScope {
            source: vault_source(NodeId(self.root_id), &pass.root_name, read_seed, write_seed),
            destination: second.as_ref().map(|end| SealPlane {
                end: ScopeEnd {
                    root: end.root,
                    root_name: &end.name,
                    read_scope_seed: &end.material.read_scope_seed,
                    read_seed_stamp: None,
                    write_scope_seed: &end.material.write_scope_seed,
                    ascent_node_seed: end.ascent.as_ref(),
                    floor_namespace: FloorNamespace::Own,
                },
                epoch: end.material.read_epoch,
                epoch_seed: EpochSeed::Ratchet,
            }),
            scope_roots: &proved_roots,
            keyless_roots: &keyless_roots,
            charges_the_identity: false,
            enc_secret: enc_subkey,
            owner_identity: &self.owner_identity,
            granted: None,
        });
        let interior = drivable
            .iter()
            .map(|(scope, write)| DrainScope {
                source: interior_source(scope, write),
                destination: None,
                scope_roots: &proved_roots,
                keyless_roots: &keyless_roots,
                charges_the_identity: false,
                enc_secret: enc_subkey,
                owner_identity: &self.owner_identity,
                granted: None,
            })
            .collect();
        // A grafted pass has no second end: a crossing into or out
        // of a shared scope is the owner's cut to make, and this
        // vault holds no boundary material for one.
        let grafted_passes = grafted
            .iter()
            .map(|pass| DrainScope {
                source: pass.source(),
                destination: None,
                scope_roots: &proved_roots,
                keyless_roots: &keyless_roots,
                charges_the_identity: false,
                enc_secret: enc_subkey,
                owner_identity: &pass.sharer_identity,
                granted: Some(GrantedPass {
                    sharer_enc: &pass.sharer_enc,
                    plane: GraftedPlane {
                        scope_id: pass.root.0,
                        scope_roots: &grafted_scope_roots,
                        contested: &grafted_contested,
                    },
                }),
            })
            .collect();
        let owed_moves: Option<Vec<NodeId>> = OwedRotation::new(
            &self.seams.staging,
            BookkeepingSeal::new(enc_subkey, &*self.seams.entropy),
            enc_subkey,
            &state.owed_rotation,
        )
        .interior_moves()
        .await
        .ok()
        .map(|moves| moves.into_iter().map(|(scope, _)| scope).collect());
        let drain = Drain::new(
            &self.seams,
            state.drain_cells(),
            TickInputs {
                placement: decision,
                bin_keys: &pass.bin_keys,
                bin_retention_days: owner_bin_retention_days(&state.settings_summary),
                retention: owner_retention(&state.settings_summary),
                owed_moves: owed_moves.as_deref(),
            },
        );
        drain
            .run_tick(
                TickScopes {
                    vault,
                    interior,
                    grafted: grafted_passes,
                },
                &exits,
            )
            .await;
        boundaries
    }

    /// The mailbox pull, placed against the pointer index of the boundaries this
    /// pass knows.
    async fn pull_mailbox(
        &self,
        state: &SessionState,
        pass: &Pass,
        boundaries: &Option<Boundaries<'_>>,
    ) -> MailboxPull {
        // The mailbox pull leads the received-share refresh, so a share
        // this pass accepts is classified by that refresh rather than a
        // pass later.
        let owner_keys = self.secrets.sweep_keys.borrow().clone();
        let pointers = match (boundaries, &owner_keys) {
            (Some(boundaries), Some(keys)) => {
                scope_pointer_index(&keys.scope_keys, boundaries.scope_roots.iter().copied())
            }
            _ => PointerIndex::new(),
        };
        let claims = ShareInbox {
            mailbox: self.seams.api.as_ref(),
            transport: &self.seams.transport,
            gateway: &self.seams.gateway,
            http: &self.seams.http,
            floors: &self.seams.floors,
            enc_secret: &pass.enc_subkey,
            contact_label_seed: &pass.contact_label_seed,
            vault_root_scope: self.root_id,
            list_lock: &state.received_shares_lock,
        }
        .pull(
            &self.seams.staging,
            &self.seams.entropy,
            ENVELOPE_V,
            &|pointer| placed(&pointers, pointer),
            &self.seams.events,
        )
        .await;
        MailboxPull {
            owner_keys,
            pointers,
            claims,
        }
    }

    /// The claim conversion at the boundaries this pass's own walk proved, then
    /// the link sweep, paced by the link-sweep cadence.
    async fn convert_claims(
        &self,
        state: &SessionState,
        pass: &Pass,
        boundaries: Option<&Boundaries<'_>>,
        pulled: MailboxPull,
    ) {
        let MailboxPull {
            owner_keys,
            pointers,
            claims,
        } = pulled;
        // Any owner device converts on every pass (ADR 0023 D4), at
        // the boundaries this pass's own walk proved. A failed poll
        // still converts the claims already acked.
        let owner_signer = self.secrets.tick_owner_signer.borrow().clone();
        let sweep = state.sweep_tasks.borrow().clone();
        let vault_root_name = state.current_root_name.borrow().clone();
        let (Some(boundaries), Some(signer), Some(keys), Some(sweep), Some(root_name)) =
            (boundaries, owner_signer, owner_keys, sweep, vault_root_name)
        else {
            return;
        };
        let seams = &self.seams;
        let conversion = ConversionPass {
            transport: &seams.transport,
            api: seams.api.as_ref(),
            gateway: &seams.gateway,
            http: &seams.http,
            floors: &seams.floors,
            snapshot_cache: &seams.snapshot_cache,
            events: &seams.events,
            scheduler: &seams.scheduler,
            profile: &seams.profile,
            on_access_misses: &state.on_access_misses,
            entropy: &seams.entropy,
            staging: &seams.staging,
            identity: &signer,
            enc_secret: &pass.enc_subkey,
            owner_identity: &self.owner_identity,
            scope_keys: &keys.scope_keys,
            cut: CutAuthority {
                owner_pointer_seed: keys.scope_keys.pointer_seed(),
                held: &state.held_records,
                sweep: &sweep,
                vault_root: NodeId(self.root_id),
            },
            scope_roots_walked: &state.scope_roots_walked,
            counts: &state.pending_invite_claims,
            running: &state.conversion_running,
            owed: &state.owed_rotation,
        };
        let sites = TickSites {
            boundaries,
            root_name: &root_name,
            walked: state.scope_roots_walked.get(),
            refused_roots: state.walk_refused_roots.borrow().clone(),
        };
        conversion.redrive_owed(&sites).await;
        state.owed_rotation_driven.set(true);
        let converted = conversion
            .run(&sites, &pointers, claims.unwrap_or_default(), None)
            .await
            .into_result();
        if let Err(EngineError::TrustViolation { message }) = converted {
            let _ = seams.events.unbounded_send(Event::AttributableAbuse {
                description: message,
            });
        }
        // After the conversion above, so a claim acked this
        // pass converts before its link can be cut.
        if pace_due(
            pass.now,
            self.link_swept.get(),
            seams.profile.link_sweep_cadence,
        ) && let Some(swept) = conversion.sweep_links(&root_name, &pointers).await
        {
            // A capped sweep continues on the next tick.
            if !swept.more {
                self.link_swept.set(pass.now);
            }
            // A cut supersedes the material this session
            // walked for every scope root it re-keyed.
            let mut walked = state.walked_read_epochs.borrow_mut();
            for node in &swept.rekeyed {
                walked.remove(node);
            }
            drop(walked);
            if let Some(EngineError::TrustViolation { message }) = swept.failure {
                let _ = seams.events.unbounded_send(Event::AttributableAbuse {
                    description: message,
                });
            }
        }
    }

    /// The claim repost.
    async fn repost_claims(&self, state: &SessionState, pass: &Pass) {
        repost_held_claims(
            self.seams.api.as_ref(),
            &self.seams.staging,
            &self.seams.entropy,
            &pass.enc_subkey,
            &state.received_shares_lock,
            ENVELOPE_V,
            self.seams.scheduler.now(),
        )
        .await;
    }

    /// The received-share status refresh. Last, after the drain: the
    /// grantee's own read leg is the slowest in the pass, and a host refresh
    /// waits on nothing it reports.
    async fn refresh_received_shares(&self, state: &SessionState, pass: &Pass) {
        ReceivedShareStatus {
            transport: &self.seams.transport,
            gateway: &self.seams.gateway,
            http: &self.seams.http,
            floors: &self.seams.floors,
            enc_secret: &pass.enc_subkey,
            contact_label_seed: &pass.contact_label_seed,
            list_lock: &state.received_shares_lock,
            mode: pass.mode,
        }
        .refresh(
            &self.seams.staging,
            &self.seams.entropy,
            &state.received_verdicts,
            &ScopeRender {
                base: &state.snapshot,
                read_seeds: &state.scope_read_seeds,
                write_seeds: &state.scope_write_seeds,
                own_root: &self.root_id,
                own_descendants: &state.descendant_scope_roots,
                grafted_sharers: &state.grafted_sharers,
                scope_roots: &state.bookmarked_scope_roots,
                permissions: &state.bookmarked_permissions,
                claims: &state.grafted_claims,
                events: &self.seams.events,
            },
            pass.now,
            &self.seams.profile,
        )
        .await;
    }
}

/// The interior scope the **first** queued op that names one needs
/// ([`second_end_scope`]), with the material the tick's boundary walk proved for
/// it.
///
/// The ends are resolved from the base here, not read off the crossing the
/// command journaled. A grant minted after an op was queued turns an intra-scope
/// relink into one that leaves a scope somebody now reads, and moves a
/// boundary under a link a queued delete must still remove.
///
/// One pass carries one interior end and the queue drains strict FIFO, so the
/// first such op decides and no later one may take its place — an end resolved
/// for an op further back leaves the head walking a chain neither end roots,
/// which stalls it where no budget reaches. A head whose boundary this session
/// has proved no material for therefore answers `None`, and the drain charges
/// it.
///
/// The decode rides the session's own queue memo: it is an HPKE open per owned
/// record.
async fn queued_second_end<St: StagingStore + QueueGeneration>(
    staging: &St,
    enc_secret: &X25519Secret,
    memo: &RefCell<QueueScanMemo>,
    boundaries: &Boundaries<'_>,
) -> Option<SecondEnd> {
    let listed = &boundaries.scope_roots;
    if listed.is_empty() {
        return None;
    }
    let reader = RecordReader::new(enc_secret);
    let scan = memoized_scan(staging, &reader, memo).await.ok()?;
    if scan.mine.is_empty() {
        return None;
    }
    let published = published_op_mark(staging, enc_secret).await.ok()?;
    let base = boundaries.base.borrow();
    // A kept op that the base shows as landed is not one the drain applies,
    // so it does not decide (ADR 0069 D6).
    let scope = scan.mine.iter().find_map(|(op_id, op)| {
        let scope = second_end_scope(&base, op, listed)?;
        (published.is_none_or(|mark| op_id.0 > mark)
            || keeps(&op.kind)
                && !replay(&base, &base, &[(*op_id, op.clone())], listed)
                    .dropped
                    .iter()
                    .any(|(_, reason)| *reason == DropReason::AlreadySatisfied))
        .then_some(scope)
    })?;
    let proved = boundaries.material.get(&scope)?;
    Some(SecondEnd {
        ascent: ascent_node_seed(
            &base,
            &boundaries.material,
            boundaries.root,
            boundaries.root_read_seed,
            scope,
        ),
        name: derive_write_name(&proved.write_scope_seed, &scope.0),
        material: ScopeMaterial {
            read_scope_seed: proved.read_scope_seed.clone(),
            write_scope_seed: proved.write_scope_seed.clone(),
            read_epoch: proved.read_epoch,
        },
        root: scope,
    })
}

/// The interior end one pass carries, owned for exactly that pass so
/// [`ScopeEnd`] can borrow every part of it.
struct SecondEnd {
    /// The scope root, which is also the scope id its records bind.
    root: NodeId,
    /// What that scope seals and names under, off the boundary walk.
    material: ScopeMaterial,
    /// The name its scope root publishes at.
    name: IpnsName,
    /// The ascent authority its gate needs; `None` where this session cannot
    /// place the boundary, which the gate then refuses.
    ascent: Option<Zeroizing<[u8; 32]>>,
}

/// The record bytes already held for `name` under `node`, when the scope seeds
/// recovered alongside them are still in hand — the precondition for
/// [`RootAdopter::holding`]'s steady-state skip.
fn steady_state_hold(
    held: &RefCell<HeldRecords>,
    scope_root: [u8; 16],
    name: &IpnsName,
    read_seeds: &RefCell<ScopeSeeds>,
    write_seeds: &RefCell<ScopeSeeds>,
) -> Option<Vec<u8>> {
    if !read_seeds.borrow().contains_key(&scope_root)
        || !write_seeds.borrow().contains_key(&scope_root)
    {
        return None;
    }
    let held = held.borrow();
    let record = held.get(&HeldKey::Node(scope_root))?;
    (record.routing_key == name.as_str()).then(|| record.record_bytes.clone())
}

/// Every write-granted graft, with the identity that granted it.
fn write_grant_sharers(
    permissions: &BookmarkedPermissions,
    sharers: &GraftedSharers,
) -> Vec<([u8; 16], [u8; IDENTITY_PUBLIC_LEN])> {
    permissions
        .iter()
        .filter(|(_, permission)| **permission == CommittedPermission::Write)
        .filter_map(|(scope_id, _)| Some((*scope_id, *sharers.get(scope_id)?)))
        .collect()
}

/// Each write-granted graft's granting contact encryption subkey, by scope id.
///
/// Read from the verified contact book, never from a record, because it is the
/// ECDH peer that locates this device's grant blob. A sharer the book does not
/// hold yields no entry, so that scope drains nothing. A vault with no write
/// grant decodes no contact.
async fn write_grant_sharer_encs<C: ContactStore>(
    contacts: &C,
    grafts: Vec<([u8; 16], [u8; IDENTITY_PUBLIC_LEN])>,
) -> BTreeMap<[u8; 16], X25519Public> {
    if grafts.is_empty() {
        return BTreeMap::new();
    }
    let Ok(book) = contacts.contacts().await else {
        return BTreeMap::new();
    };
    grafts
        .into_iter()
        .filter_map(|(scope_id, sharer)| {
            let contact = book
                .iter()
                .find(|contact| contact.identity_pk().to_sec1() == sharer)?;
            Some((scope_id, contact.enc_subkey()))
        })
        .collect()
}

/// The interior scope one queued op needs a pass to hold beside its anchor: the
/// far end of a crossing, or the one interior boundary a delete's target is
/// linked from.
///
/// A delete unlinks its target from every folder that links it
/// (blueprint/engine.md "Delete branch"), so a link in an interior scope is an
/// end the pass owes. Links in two interior scopes are a span no pass pairs, and
/// naming one of them here would leave the other standing: the replay
/// dead-letters that shape instead.
fn second_end_scope(base: &Snapshot, op: &Op, listed: &[NodeId]) -> Option<NodeId> {
    if let Some((from_parent, new_parent, _)) = op.relocation() {
        let source = enclosing_scope_root(base, from_parent, listed);
        let destination = enclosing_scope_root(base, new_parent, listed);
        if source == destination {
            return None;
        }
        return source.or(destination);
    }
    if !matches!(op.kind, OpKind::Delete { .. }) {
        return None;
    }
    let mut interior = base
        .links_to(op.target)
        .into_iter()
        .filter_map(|link| enclosing_scope_root(base, link.parent, listed));
    let first = interior.next()?;
    interior.all(|root| root == first).then_some(first)
}

/// The share of the focus file queue one leg of a pass may spend: `queued` less
/// what the pass attempted on an earlier leg, and no more than the budget
/// [`MAX_FOCUS_FILES`] leaves.
///
/// The bound is per pass, not per leg (blueprint/desktop.md "Freshness"). Each
/// leg refills the queue with its own scope's rows, so the budget is charged
/// across the legs, and the newest rows take what is left of it. A bulk row
/// yields the budget to a row a host access named, whatever their queue order:
/// the fan-out over a large folder in view queues last and would otherwise
/// spend the whole pass on rows nobody is waiting on.
fn leg_file_share(
    mut queued: Vec<NodeId>,
    attempted: &[NodeId],
    host_queued: &BTreeSet<NodeId>,
) -> Vec<NodeId> {
    queued.retain(|node| !attempted.contains(node));
    let mut over = queued
        .len()
        .saturating_sub(MAX_FOCUS_FILES.saturating_sub(attempted.len()));
    let mut kept: Vec<NodeId> = Vec::with_capacity(queued.len());
    for node in queued {
        if over > 0 && !host_queued.contains(&node) {
            over -= 1;
            continue;
        }
        kept.push(node);
    }
    // Host rows alone still charge the budget: the origin orders the spend, it
    // does not lift the bound.
    kept.drain(..over);
    kept
}

/// One tick's pointer-consult window: the scopes due this pass
/// ([`consult_scopes_due`]), which of
/// them is the vault anchor, and the clock the stamps are taken from.
pub(crate) struct ConsultWindow {
    pub(crate) scopes: Vec<NodeId>,
    pub(crate) anchor: NodeId,
    pub(crate) now: UnixMillis,
}

/// The focus tick's polled scope-pointer consults (`crate::sync::pointer`:
/// "Consult discipline: polled, not fallback").
///
/// Each consult advances the scope's write-epoch floor on sight, which is what
/// evicts the `writeScopeSeed` a write-only rotation retired — that rotation
/// leaves the read epoch untouched, so the sweep's event-driven consult never
/// fires for it. An unavailable pointer leaves the stamp unset, so the next tick
/// retries rather than waiting out the interval.
///
/// Returns the vault anchor's owner-vouched current root when this pass
/// consulted one (see [`consult_scopes`]).
pub(crate) async fn consult_pointers<T: RecordTransport, F: FloorStore>(
    transport: &T,
    floors: &F,
    keys: &RefCell<Option<Rc<SweepKeys>>>,
    events: &mpsc::UnboundedSender<Event>,
    consulted: &RefCell<BTreeMap<NodeId, UnixMillis>>,
    window: ConsultWindow,
) -> Option<IpnsName> {
    // The pass owns a copy for exactly its own duration, on the same terms as
    // the tick's enc subkey: teardown empties the cell.
    let keys = keys.borrow().clone()?;
    let mut anchor_root = None;
    for scope in window.scopes {
        let consult = PointerConsult {
            scope_keys: &keys.scope_keys,
            owner_identity: &keys.owner_identity,
            payload_version: POINTER_PAYLOAD_VERSION,
        };
        match consult.run(transport, floors, &scope.0).await {
            Err(PointerConsultError::Unavailable) => continue,
            // A verdict is stable, so a refusal is stamped like a clean
            // consult: re-polling a rolled-back pointer every tick would
            // repeat its abuse event forever without changing it.
            Err(PointerConsultError::Rejected) => {
                consulted.borrow_mut().insert(scope, window.now);
                emit_trust_violation(
                    events,
                    &hex_lower(&scope.0),
                    "scope pointer unauthenticated, or vouched below the write-epoch floor",
                );
            }
            Ok(consult) => {
                consulted.borrow_mut().insert(scope, window.now);
                if scope == window.anchor {
                    anchor_root = consult.map(|consult| consult.current_root);
                }
            }
        }
    }
    anchor_root
}

/// The vault root's end, under the session's cached read seed and its stamp.
fn vault_source<'a>(
    root: NodeId,
    root_name: &'a IpnsName,
    read: &'a StampedSeed,
    write: &'a Zeroizing<[u8; 32]>,
) -> ScopeEnd<'a> {
    ScopeEnd {
        root,
        root_name,
        read_scope_seed: &read.seed,
        read_seed_stamp: Some(read.stamp),
        write_scope_seed: write,
        // The vault root carries no ascent link.
        ascent_node_seed: None,
        floor_namespace: FloorNamespace::Own,
    }
}

/// A proved descendant scope root's end, under the read seed the walk
/// recovered from the record it adopted, and so at that record's epoch.
fn interior_source<'a>(scope: &'a DescendantScopeRoot, write: &'a ScopeWritePlane) -> ScopeEnd<'a> {
    ScopeEnd {
        root: NodeId(scope.scope_id),
        root_name: &scope.name,
        read_scope_seed: &scope.read_scope_seed,
        read_seed_stamp: Some(scope.adopted.epoch),
        write_scope_seed: &write.seed,
        ascent_node_seed: Some(&scope.parent_node_seed),
        // A grant cut mints an interior scope root out of this vault's own
        // tree, so its floors are this identity's own.
        floor_namespace: FloorNamespace::Own,
    }
}

/// One grafted scope this session may author in, owned for the pass that
/// borrows it.
struct GraftedWritePass {
    root: NodeId,
    name: IpnsName,
    read_scope_seed: StampedSeed,
    write_scope_seed: Zeroizing<[u8; 32]>,
    /// The granting identity, which is the owner a grafted record's commitment
    /// and grant section verify under — never this vault's own.
    sharer_identity: EcdsaVerifier,
    /// The granting contact's encryption subkey, which locates this device's
    /// grant blob in the root the pass publishes and self-adopts.
    sharer_enc: X25519Public,
    /// The namespace this scope's epoch floors ratchet in, as
    /// [`floor_namespace`] picked it —
    /// the granting identity's on every pass a grafted root reaches here.
    floors: FloorNamespace,
}

impl GraftedWritePass {
    /// This scope's end, under the cached read seed and its stamp.
    fn source(&self) -> ScopeEnd<'_> {
        ScopeEnd {
            root: self.root,
            root_name: &self.name,
            read_scope_seed: &self.read_scope_seed.seed,
            read_seed_stamp: Some(self.read_scope_seed.stamp),
            write_scope_seed: &self.write_scope_seed,
            // A grantee enters by its own grant blob and holds no ancestor
            // seed to derive an ascent keypair from.
            ascent_node_seed: None,
            floor_namespace: self.floors,
        }
    }
}

/// Every grafted scope whose accepted grant the last pass found write-capable
/// and whose two seeds that pass recovered.
///
/// Four facts, all of them from the live resolve rather than the bookmark: the
/// owner's committed permission, both seeds, the sharer the floor namespace
/// answers under, and the name the graft rendered the root with. A fifth, the
/// granting contact's encryption subkey, comes from the verified contact book
/// (`write_grant_sharer_encs` in [`crate::sync::pass`]). A scope short of any
/// of them drains nothing this tick and waits for the pass that has them.
///
/// `namespace` is [`floor_namespace`]
/// bound to this pass's own root and proved set, so a bookmark that names one of
/// this vault's own roots yields no grafted pass rather than a pass that would
/// ratchet an own scope's floors under a sharer.
fn grafted_write_passes(
    base: &BaseSnapshot,
    permissions: &BookmarkedPermissions,
    sharers: &GraftedSharers,
    sharer_encs: &BTreeMap<[u8; 16], X25519Public>,
    namespace: impl Fn(&[u8; 16]) -> Option<FloorNamespace>,
    read_seeds: &RefCell<ScopeSeeds>,
    write_seeds: &RefCell<ScopeSeeds>,
) -> Vec<GraftedWritePass> {
    let base = base.borrow();
    permissions
        .iter()
        .filter(|(_, permission)| **permission == CommittedPermission::Write)
        .filter_map(|(scope_id, _)| {
            let root = NodeId(*scope_id);
            let name = base.node(root)?.ipns_name.as_deref()?;
            let floors = match namespace(scope_id)? {
                FloorNamespace::Own => return None,
                granted @ FloorNamespace::GrantedBy(_) => granted,
            };
            Some(GraftedWritePass {
                root,
                name: IpnsName::parse(core::str::from_utf8(name).ok()?).ok()?,
                read_scope_seed: cached_stamped_seed_in(read_seeds, scope_id, floors)?,
                write_scope_seed: cached_seed_in(write_seeds, scope_id, floors)?,
                sharer_identity: EcdsaVerifier::from_sec1(sharers.get(scope_id)?)?,
                sharer_enc: *sharer_encs.get(scope_id)?,
                floors,
            })
        })
        .collect()
}

/// Install what one walk proved: drop the seeds of every promotion it could not
/// re-prove, then deposit and project the ones it did.
///
/// The promotion set only grows. A promotion a pass cannot prove is an outage on
/// that scope's own leg, and forgetting it would regroup its whole subtree onto
/// the enclosing scope's seed, where every record fails its unseal and is
/// reported as abuse.
///
/// Each seed is stamped with the epoch its own recovery names: the read seed
/// with the record's, the write seed with the write-epoch floor its
/// owner-write-blob opened at (`deposit_seed`).
///
/// Answers the children each scope root stopped naming, stamped at
/// `observed_at`: an unlink a write grantee published at the root of the scope
/// it holds, which the owner's capture bins (CONTEXT.md "Owner capture").
fn install_descendant_scopes(
    known: &RefCell<BTreeSet<NodeId>>,
    read_seeds: &RefCell<ScopeSeeds>,
    write_seeds: &RefCell<ScopeSeeds>,
    base: &BaseSnapshot,
    events: &mpsc::UnboundedSender<Event>,
    proved: &[DescendantScopeRoot],
    observed_at: u64,
) -> Vec<UnlinkedChild> {
    let reached: BTreeSet<NodeId> = proved.iter().map(|s| NodeId(s.scope_id)).collect();
    let unproved: Vec<NodeId> = known.borrow().difference(&reached).copied().collect();
    for scope in unproved {
        for cell in [read_seeds, write_seeds] {
            cell.borrow_mut().remove(&scope.0);
        }
    }
    let promoted: BTreeSet<NodeId> = reached.difference(&known.borrow()).copied().collect();
    known.borrow_mut().extend(reached);
    let mut departed = Vec::new();
    for scope in proved {
        // Past this boundary the eviction pass reads the scope as this vault's
        // own and stops measuring its write seed against a granting identity's
        // floor (`evict_grafted_write_seeds`). A seed the graft left behind
        // would therefore be resident for good, so the promotion keeps only
        // what this walk itself proved.
        if promoted.contains(&NodeId(scope.scope_id)) {
            write_seeds.borrow_mut().remove(&scope.scope_id);
        }
        deposit_seed(
            read_seeds,
            scope.scope_id,
            scope.read_scope_seed.clone(),
            Some(scope.adopted.epoch),
            FloorNamespace::Own,
        );
        if let Ok(write) = &scope.write {
            deposit_write_seed(
                write_seeds,
                scope.scope_id,
                write.seed.clone(),
                Some(&scope.name),
                Some(write.epoch),
                FloorNamespace::Own,
            );
        }
        let root = NodeId(scope.scope_id);
        let merged = merge_root(&mut base.borrow_mut(), root, &scope.adopted);
        if merged.changed {
            let _ = events.unbounded_send(Event::SnapshotUpdated);
        }
        departed.extend(merged.observed_unlinks(scope.scope_id, root, observed_at));
    }
    departed
}

/// Report each scope whose root one walk read as a same-sequence fork.
fn report_forked_scopes(
    forks: &ForkSightings,
    events: &mpsc::UnboundedSender<Event>,
    proved: &[DescendantScopeRoot],
) {
    for (scope, fork) in proved
        .iter()
        .filter_map(|scope| scope.fork.map(|fork| (scope, fork)))
    {
        forks.report(events, scope.name.as_str(), fork.sequence);
    }
}

/// Record the boundaries one walk named without material, and release every
/// root the same walk proved: a proved root reads on its own leg from now on,
/// and a stale entry here would skip it as unreachable for the rest of the
/// session. Proof wins over a name: one parent's stale body can name a root
/// another parent's index proves in the same walk.
fn install_unproved_scopes(
    unproved: &RefCell<BTreeSet<NodeId>>,
    proved: impl IntoIterator<Item = NodeId>,
    named: BTreeSet<NodeId>,
) {
    let mut unproved = unproved.borrow_mut();
    unproved.extend(named);
    for scope in proved {
        unproved.remove(&scope);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::seal::ReadBody;

    use crate::facade::NodeKind;
    use crate::seams::SharerScopedFloorStore;
    use crate::sync::model::NodeMeta;

    /// A boundary a later walk proves reads on its own leg, so it must leave the
    /// unproved set; the focus leg skips every root that set still holds.
    #[test]
    fn a_walk_that_proves_an_unproved_boundary_releases_it() {
        let released = NodeId([3; 16]);
        let still_named = NodeId([4; 16]);
        let not_named = NodeId([5; 16]);
        let unproved = RefCell::new(BTreeSet::from([released, not_named]));

        install_unproved_scopes(&unproved, [released], BTreeSet::from([still_named]));

        assert_eq!(*unproved.borrow(), BTreeSet::from([still_named, not_named]));
    }

    /// One parent's stale body can name a root another parent's index proves in
    /// the same walk; the proof wins.
    #[test]
    fn a_root_one_walk_both_proves_and_names_stays_released() {
        let both = NodeId([6; 16]);
        let unproved = RefCell::new(BTreeSet::from([both]));

        install_unproved_scopes(&unproved, [both], BTreeSet::from([both]));

        assert!(unproved.borrow().is_empty());
    }

    mod grafted_passes {
        use super::*;

        use cipherbox_core::kdf;
        use cipherbox_core::seal::PreservedFields;
        use cipherbox_core::suite::ecdsa::EcdsaSigner;

        use crate::gate::Adopted;
        use crate::grants::grafted::GraftedSharers;
        use crate::net::rotation::WritePlaneDark;
        use crate::seams::ContactLabel;

        const VAULT_ROOT: NodeId = NodeId([0u8; 16]);
        const SHARED: [u8; 16] = [0x6a; 16];
        const WRITE_SCOPE_SEED: [u8; 32] = [0x77; 32];
        const READ_SCOPE_SEED: [u8; 32] = [0x11; 32];

        fn sharer() -> EcdsaSigner {
            EcdsaSigner::from_scalar(&[0x31; 32]).expect("valid scalar")
        }

        /// A render tree holding one grafted root, planted parentless under the
        /// vault root exactly as `merge_grafted` plants it.
        fn base() -> BaseSnapshot {
            let mut snapshot = Snapshot::new(VAULT_ROOT);
            let mut meta = NodeMeta::new(NodeId(SHARED), "shared", NodeKind::Folder);
            meta.ipns_name = Some(
                derive_write_name(&WRITE_SCOPE_SEED, &SHARED)
                    .as_str()
                    .as_bytes()
                    .to_vec(),
            );
            snapshot.upsert_node(meta);
            BaseSnapshot::new(snapshot)
        }

        fn sharers() -> GraftedSharers {
            GraftedSharers::from([(SHARED, sharer().verifying_key().to_sec1())])
        }

        fn encs() -> BTreeMap<[u8; 16], X25519Public> {
            BTreeMap::from([(SHARED, kdf::enc_subkey(&[0x31; 32]).public())])
        }

        fn seeds(scope_id: [u8; 16], seed: [u8; 32]) -> RefCell<ScopeSeeds> {
            let cell = RefCell::new(ScopeSeeds::new());
            let namespace = own_namespace(&sharers())(&scope_id).expect("SHARED has a sharer");
            deposit_seed(&cell, scope_id, Zeroizing::new(seed), Some(0), namespace);
            cell
        }

        fn label_seed() -> SecretBytes {
            kdf::contact_label_seed(&[0x4c; 32])
        }

        /// The namespace picker over a vault whose own tree holds the vault root
        /// alone, which is every case but the owned-arm test below.
        fn own_namespace(sharers: &GraftedSharers) -> impl Fn(&[u8; 16]) -> Option<FloorNamespace> {
            let sharers = sharers.clone();
            move |scope_id| {
                floor_namespace(
                    &sharers,
                    &label_seed(),
                    &VAULT_ROOT.0,
                    &BTreeSet::new(),
                    scope_id,
                )
            }
        }

        /// The whole point of the pass: a write grantee publishes under the
        /// shared scope's own material, so both seeds and the granting identity
        /// have to reach the drain.
        #[test]
        fn a_write_granted_graft_becomes_one_pass_on_the_sharers_own_material() {
            let passes = grafted_write_passes(
                &base(),
                &BookmarkedPermissions::from([(SHARED, CommittedPermission::Write)]),
                &sharers(),
                &encs(),
                own_namespace(&sharers()),
                &seeds(SHARED, READ_SCOPE_SEED),
                &seeds(SHARED, WRITE_SCOPE_SEED),
            );

            assert_eq!(passes.len(), 1);
            let pass = &passes[0];
            assert_eq!(pass.root, NodeId(SHARED));
            assert_eq!(pass.name, derive_write_name(&WRITE_SCOPE_SEED, &SHARED));
            assert_eq!(pass.sharer_identity, sharer().verifying_key());
            assert_eq!(
                pass.name,
                IpnsName::from_public_key(
                    &kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &SHARED).as_bytes())
                        .verifying_key()
                ),
                "the pass publishes under the name the shared root itself answers at",
            );

            let store = crate::testkit::fakes::InMemoryFloorStore::default();
            crate::testkit::block_on(pass.floors.view(&store).raise_epoch_floor(&SHARED, 9))
                .expect("the floor raises");
            let sharer_label = ContactLabel::of(&label_seed(), &sharer().verifying_key().to_sec1());
            assert_eq!(
                crate::testkit::block_on(
                    SharerScopedFloorStore::granted_by(&store, sharer_label).epoch_floor(&SHARED)
                )
                .expect("floor read"),
                Some(9),
                "the pass ratchets its epoch floors under the granting identity's label",
            );
            assert_eq!(
                crate::testkit::block_on(SharerScopedFloorStore::own(&store).epoch_floor(&SHARED))
                    .expect("floor read"),
                None,
                "and never in this vault's own namespace",
            );
        }

        /// Each of the five facts the pass needs comes from the live resolve or
        /// the verified contact book. A scope short of any one of them drains
        /// nothing rather than publishing under half a set.
        #[test]
        fn a_graft_short_of_any_of_the_passs_five_facts_drains_nothing() {
            let read = seeds(SHARED, READ_SCOPE_SEED);
            let write = seeds(SHARED, WRITE_SCOPE_SEED);
            let empty = RefCell::new(ScopeSeeds::new());
            let write_permitted =
                BookmarkedPermissions::from([(SHARED, CommittedPermission::Write)]);
            let other = FloorNamespace::GrantedBy(crate::seams::ContactLabel::of(
                &label_seed(),
                &[0x03; IDENTITY_PUBLIC_LEN],
            ));
            let foreign = |seed: [u8; 32]| {
                let cell = RefCell::new(ScopeSeeds::new());
                deposit_seed(&cell, SHARED, Zeroizing::new(seed), Some(0), other);
                cell
            };
            let (foreign_read, foreign_write) =
                (foreign(READ_SCOPE_SEED), foreign(WRITE_SCOPE_SEED));

            for (case, permissions, sharers, sharer_encs, read_seeds, write_seeds) in [
                (
                    "the commitment grants read",
                    BookmarkedPermissions::from([(SHARED, CommittedPermission::Read)]),
                    sharers(),
                    encs(),
                    &read,
                    &write,
                ),
                (
                    "no read seed was recovered",
                    write_permitted.clone(),
                    sharers(),
                    encs(),
                    &empty,
                    &write,
                ),
                (
                    "no write seed was recovered",
                    write_permitted.clone(),
                    sharers(),
                    encs(),
                    &read,
                    &empty,
                ),
                (
                    "no identity answers for the scope",
                    write_permitted.clone(),
                    GraftedSharers::new(),
                    encs(),
                    &read,
                    &write,
                ),
                (
                    "the contact book holds no key for the sharer",
                    write_permitted.clone(),
                    sharers(),
                    BTreeMap::new(),
                    &read,
                    &write,
                ),
                (
                    "the seeds were deposited under another sharer",
                    write_permitted.clone(),
                    sharers(),
                    encs(),
                    &foreign_read,
                    &foreign_write,
                ),
            ] {
                assert!(
                    grafted_write_passes(
                        &base(),
                        &permissions,
                        &sharers,
                        &sharer_encs,
                        own_namespace(&sharers),
                        read_seeds,
                        write_seeds,
                    )
                    .is_empty(),
                    "{case}",
                );
            }
        }

        /// The floor namespace is `floor_namespace`'s verdict, and its owned arm
        /// is decided ahead of the sharer map. A bookmark that names a scope
        /// root this vault owns therefore yields no grafted pass, so no pass
        /// ratchets an own scope's epoch floors under a contact label.
        #[test]
        fn a_bookmark_that_names_a_scope_this_vault_owns_drains_no_grafted_pass() {
            for (case, own_root, own_descendants) in [
                ("the vault root itself", SHARED, BTreeSet::new()),
                (
                    "a proved descendant scope root",
                    VAULT_ROOT.0,
                    BTreeSet::from([NodeId(SHARED)]),
                ),
            ] {
                assert!(
                    grafted_write_passes(
                        &base(),
                        &BookmarkedPermissions::from([(SHARED, CommittedPermission::Write)]),
                        &sharers(),
                        &encs(),
                        |scope_id| {
                            floor_namespace(
                                &sharers(),
                                &label_seed(),
                                &own_root,
                                &own_descendants,
                                scope_id,
                            )
                        },
                        &seeds(SHARED, READ_SCOPE_SEED),
                        &seeds(SHARED, WRITE_SCOPE_SEED),
                    )
                    .is_empty(),
                    "{case}",
                );
            }
        }

        /// One level as a boundary walk proved it, with `write` as the caller
        /// gives it.
        fn proved(write: Result<ScopeWritePlane, WritePlaneDark>) -> DescendantScopeRoot {
            DescendantScopeRoot {
                scope_id: SHARED,
                name: derive_write_name(&WRITE_SCOPE_SEED, &SHARED),
                parent_node_seed: Zeroizing::new([0x21; 32]),
                adopted: Adopted {
                    read_body: ReadBody::Folder {
                        created_at: 0,
                        modified_at: 0,
                        children: Vec::new(),
                        unknown: PreservedFields::new(),
                    },
                    sequence: 1,
                    epoch: 3,
                },
                read_scope_seed: Zeroizing::new(READ_SCOPE_SEED),
                write,
                write_cut_unfinished: false,
                fork: None,
            }
        }

        /// The vault root's end carries the stamp of the cached read seed, so
        /// the drain can tell a lag from a root the seed should open.
        #[test]
        fn the_vault_end_carries_its_cached_seeds_stamp() {
            let read = StampedSeed {
                seed: Zeroizing::new(READ_SCOPE_SEED),
                stamp: 5,
            };
            let write = Zeroizing::new(WRITE_SCOPE_SEED);
            let name = derive_write_name(&WRITE_SCOPE_SEED, &SHARED);

            let end = vault_source(NodeId(SHARED), &name, &read, &write);

            assert_eq!(end.read_seed_stamp, Some(5));
        }

        /// A descendant scope's end is stamped at the epoch of the record the
        /// walk recovered its read seed from.
        #[test]
        fn an_interior_end_carries_the_epoch_its_seed_was_recovered_at() {
            let scope = proved(Ok(ScopeWritePlane {
                seed: Zeroizing::new(WRITE_SCOPE_SEED),
                epoch: 1,
            }));
            let write = scope.write.as_ref().expect("a write plane");

            assert_eq!(
                interior_source(&scope, write).read_seed_stamp,
                Some(scope.adopted.epoch)
            );
        }

        /// A grafted pass's end carries the stamp its read seed was cached
        /// under.
        #[test]
        fn a_grafted_end_carries_its_cached_seeds_stamp() {
            let read = RefCell::new(ScopeSeeds::new());
            let namespace = own_namespace(&sharers())(&SHARED).expect("SHARED has a sharer");
            deposit_seed(
                &read,
                SHARED,
                Zeroizing::new(READ_SCOPE_SEED),
                Some(6),
                namespace,
            );

            let passes = grafted_write_passes(
                &base(),
                &BookmarkedPermissions::from([(SHARED, CommittedPermission::Write)]),
                &sharers(),
                &encs(),
                own_namespace(&sharers()),
                &read,
                &seeds(SHARED, WRITE_SCOPE_SEED),
            );

            assert_eq!(passes.len(), 1);
            assert_eq!(passes[0].source().read_seed_stamp, Some(6));
        }

        /// A walk reports each forked scope once per session, and no other.
        #[test]
        fn a_walk_reports_each_forked_scope_once() {
            let forks = ForkSightings::default();
            let (events, mut rx) = mpsc::unbounded();
            let forked = DescendantScopeRoot {
                fork: Some(crate::net::fork::Fork {
                    sequence: 1,
                    served: true,
                }),
                ..proved(Err(WritePlaneDark::Keyless))
            };
            let plain = DescendantScopeRoot {
                scope_id: [0x77; 16],
                name: derive_write_name(&WRITE_SCOPE_SEED, &[0x77; 16]),
                ..proved(Err(WritePlaneDark::Keyless))
            };
            let name = forked.name.as_str().to_owned();

            report_forked_scopes(&forks, &events, &[forked, plain]);
            report_forked_scopes(
                &forks,
                &events,
                &[DescendantScopeRoot {
                    fork: Some(crate::net::fork::Fork {
                        sequence: 1,
                        served: false,
                    }),
                    ..proved(Err(WritePlaneDark::Keyless))
                }],
            );
            drop(events);

            let sent: Vec<Event> = core::iter::from_fn(|| rx.try_recv().ok()).collect();
            assert_eq!(sent, [Event::SameSequenceFork { routing_key: name }]);
        }

        /// A scope a walk promotes into this vault's own set leaves its grafted
        /// write seed behind. Past that boundary the eviction pass never
        /// measures the entry again, so a seed the promotion cannot re-prove
        /// would publish under a sharer's material on this vault's own plane.
        ///
        /// The clear is the promotion's alone: a scope the set already holds
        /// keeps the seed of its last proved write plane through a pass that
        /// merely could not open one.
        #[test]
        fn a_promotion_that_proves_no_write_plane_drops_the_grafted_write_seed() {
            for (case, already_known, held) in [
                ("the walk promotes the scope", false, false),
                ("the set already holds the scope", true, true),
            ] {
                let known = RefCell::new(match already_known {
                    true => BTreeSet::from([NodeId(SHARED)]),
                    false => BTreeSet::new(),
                });
                let write_seeds = seeds(SHARED, WRITE_SCOPE_SEED);
                let (events, _rx) = mpsc::unbounded();

                install_descendant_scopes(
                    &known,
                    &seeds(SHARED, READ_SCOPE_SEED),
                    &write_seeds,
                    &base(),
                    &events,
                    &[proved(Err(WritePlaneDark::Keyless))],
                    0,
                );

                assert_eq!(write_seeds.borrow().contains_key(&SHARED), held, "{case}",);
            }
        }

        /// A promotion the walk did prove a write plane for keeps that plane:
        /// the clear above is the stale graft's, not the proved material's.
        #[test]
        fn a_promotion_that_proves_a_write_plane_holds_the_proved_seed() {
            let known = RefCell::new(BTreeSet::new());
            let write_seeds = RefCell::new(ScopeSeeds::new());
            let (events, _rx) = mpsc::unbounded();

            install_descendant_scopes(
                &known,
                &seeds(SHARED, READ_SCOPE_SEED),
                &write_seeds,
                &base(),
                &events,
                &[proved(Ok(ScopeWritePlane {
                    seed: Zeroizing::new(WRITE_SCOPE_SEED),
                    epoch: 2,
                }))],
                0,
            );

            assert!(write_seeds.borrow().contains_key(&SHARED));
        }

        /// A scope the render tree does not hold has no name to publish under:
        /// the graft carries it, and a revoked share leaves the tree.
        #[test]
        fn a_graft_the_render_tree_no_longer_holds_drains_nothing() {
            assert!(
                grafted_write_passes(
                    &BaseSnapshot::new(Snapshot::new(VAULT_ROOT)),
                    &BookmarkedPermissions::from([(SHARED, CommittedPermission::Write)]),
                    &sharers(),
                    &encs(),
                    own_namespace(&sharers()),
                    &seeds(SHARED, READ_SCOPE_SEED),
                    &seeds(SHARED, WRITE_SCOPE_SEED),
                )
                .is_empty()
            );
        }
    }

    /// The pass, not the leg, is what `MAX_FOCUS_FILES` bounds: a second leg
    /// takes only the budget the first one left, and the newest rows take it.
    #[test]
    fn a_legs_file_share_stays_inside_the_passes_own_budget() {
        let node = |n: u8| NodeId([n; 16]);
        let queued: Vec<NodeId> = (0..MAX_FOCUS_FILES as u8 + 4).map(node).collect();

        let none = BTreeSet::new();

        assert_eq!(
            leg_file_share(queued.clone(), &[], &none),
            queued[4..],
            "the first leg takes the newest rows the bound admits"
        );

        let attempted: Vec<NodeId> = (100..100 + MAX_FOCUS_FILES as u8 - 2).map(node).collect();
        assert_eq!(
            leg_file_share(queued.clone(), &attempted, &none),
            queued[queued.len() - 2..],
            "a later leg takes only what the earlier legs left"
        );
        let spent: Vec<NodeId> = (100..100 + MAX_FOCUS_FILES as u8).map(node).collect();
        assert!(
            leg_file_share(queued, &spent, &none).is_empty(),
            "a spent budget admits nothing more"
        );
    }

    /// A stat the host is waiting on keeps its place in the pass however many
    /// rows the fan-out over the folder in view queues behind it.
    #[test]
    fn a_legs_file_share_spends_a_bulk_row_before_a_host_queued_row() {
        let node = |n: u8| NodeId([n; 16]);
        let stat = node(200);
        // The host row is oldest, so the plain recency rule would drop it first.
        let mut queued = vec![stat];
        queued.extend((0..MAX_FOCUS_FILES as u8 + 4).map(node));
        let host_queued = BTreeSet::from([stat]);

        let share = leg_file_share(queued.clone(), &[], &host_queued);
        assert_eq!(share.len(), MAX_FOCUS_FILES);
        assert!(
            share.contains(&stat),
            "the fan-out yields the budget to the row a caller waits on"
        );
        assert!(
            !leg_file_share(queued, &[], &BTreeSet::new()).contains(&stat),
            "and the same pass drops it when no host access named it"
        );
    }

    /// Host rows alone still charge the budget: the origin orders the spend, it
    /// does not lift the bound.
    #[test]
    fn host_queued_rows_do_not_lift_the_passes_budget() {
        let node = |n: u8| NodeId([n; 16]);
        let queued: Vec<NodeId> = (0..MAX_FOCUS_FILES as u8 + 4).map(node).collect();
        let host_queued: BTreeSet<NodeId> = queued.iter().copied().collect();

        assert_eq!(
            leg_file_share(queued.clone(), &[], &host_queued),
            queued[4..],
            "with every row host-queued the newest still win"
        );
    }

    /// A row an earlier leg attempted does not ride a second leg of the same
    /// pass: the queue drains once, after every leg.
    #[test]
    fn a_legs_file_share_drops_what_the_pass_already_attempted() {
        let node = |n: u8| NodeId([n; 16]);
        let queued = vec![node(1), node(2), node(3)];

        assert_eq!(
            leg_file_share(queued, &[node(2)], &BTreeSet::new()),
            vec![node(1), node(3)],
            "the attempted row is gone, the rest keeps its order"
        );
    }

    /// A vault root holding two granted folders, one file in each, and one
    /// target the caller links where the case needs it.
    fn boundaries_fixture() -> (Snapshot, NodeId) {
        let root = NodeId([0; 16]);
        let mut base = Snapshot::new(root);
        for (parent, node, name) in [
            (root, NodeId([5; 16]), "granted"),
            (root, NodeId([8; 16]), "other"),
            (NodeId([5; 16]), NodeId([10; 16]), "inside-granted"),
            (NodeId([8; 16]), NodeId([9; 16]), "inside-other"),
            (root, NodeId([6; 16]), "plain"),
        ] {
            base.upsert_node(NodeMeta::new(node, name, NodeKind::Folder));
            base.link(parent, node, 1);
        }
        base.upsert_node(NodeMeta::new(NodeId([7; 16]), "shared.txt", NodeKind::File));
        (base, NodeId([7; 16]))
    }

    fn delete_of(target: NodeId) -> Op {
        Op::delete(target, 1, UnixMillis(0), 1, true)
    }

    /// A delete unlinks its target from every folder that links it, so the pass
    /// owes an end for the interior boundary one of those folders sits under.
    #[test]
    fn a_delete_names_the_one_granted_scope_its_target_is_linked_from() {
        let (mut base, target) = boundaries_fixture();
        base.link(NodeId([6; 16]), target, 1);
        base.link(NodeId([10; 16]), target, 2);

        assert_eq!(
            second_end_scope(
                &base,
                &delete_of(target),
                &[NodeId([5; 16]), NodeId([8; 16])]
            ),
            Some(NodeId([5; 16])),
            "the link outside every granted folder is the anchor's own"
        );
    }

    /// Naming one of two interior boundaries would leave the other's link
    /// standing, which is the span the replay refuses outright.
    #[test]
    fn a_delete_linked_from_two_granted_scopes_names_no_second_end() {
        let (mut base, target) = boundaries_fixture();
        base.link(NodeId([10; 16]), target, 1);
        base.link(NodeId([9; 16]), target, 2);

        assert_eq!(
            second_end_scope(
                &base,
                &delete_of(target),
                &[NodeId([5; 16]), NodeId([8; 16])]
            ),
            None,
            "no pass pairs two interior ends"
        );
    }

    /// Only a delete acts on every link its target has. Every other op acts on
    /// the one place the target already sits, so its links name no end.
    #[test]
    fn a_rename_of_a_target_linked_across_two_scopes_names_no_second_end() {
        let (mut base, target) = boundaries_fixture();
        base.link(NodeId([6; 16]), target, 1);
        base.link(NodeId([10; 16]), target, 2);

        assert_eq!(
            second_end_scope(
                &base,
                &Op::rename(target, "renamed.txt", 1, UnixMillis(0)),
                &[NodeId([5; 16]), NodeId([8; 16])]
            ),
            None,
            "the rename touches one child ref, not every link"
        );
    }

    /// Every link outside the listed boundaries is the anchor's, and a pass
    /// anchored there needs no second end at all.
    #[test]
    fn a_delete_linked_outside_every_granted_scope_names_no_second_end() {
        let (mut base, target) = boundaries_fixture();
        base.link(NodeId([6; 16]), target, 1);

        assert_eq!(
            second_end_scope(
                &base,
                &delete_of(target),
                &[NodeId([5; 16]), NodeId([8; 16])]
            ),
            None,
            "one end serves it"
        );
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;

    use cipherbox_core::content::{compute_cid, encode_content_cid_str};
    use cipherbox_core::ipns::IpnsRecord;
    use cipherbox_core::kdf;
    use cipherbox_core::seal::{PreservedFields, ReadBody, encode_envelope, seal_read_body};
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use futures_channel::mpsc;

    use crate::api::ApiClient;
    use crate::content::{ContentProfile, DAG_ROOT_CODEC};
    use crate::deadlines::DeadlinePolicy;
    use crate::facade::NodeKind;
    use crate::profile::SyncTimingProfile;
    use crate::rotation::derive_write_name;
    use crate::seams::{EndpointId, HttpResponse, OwnerScopedFloorStore, QueueGenerationStore};
    use crate::settings::Placement;
    use crate::storage_policy::StoragePolicy;
    use crate::sync::model::NodeMeta;
    use crate::testkit::account::{EOL, ROOT, SECRET, TTL_NANOS};
    use crate::testkit::fakes::{
        InMemoryCredentialStore, InMemoryFloorStore, InMemoryRecordStore, InMemorySnapshotCache,
        InMemoryStagingStore, ScriptedHttp, VirtualScheduler,
    };
    use crate::testkit::{
        OWNER_ROOT_EPOCH, OWNER_ROOT_POINTER_READ_KEY, OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootSpec,
        SeededEntropy, block_on, gateway, owner_root_fixture, owner_root_pseudonym, requested_cid,
        serve,
    };

    const ENDPOINT: &str = "fake:someguy";

    type FakePass = TickPass<
        InMemoryRecordStore,
        ScriptedHttp,
        InMemoryCredentialStore,
        OwnerScopedFloorStore<InMemoryFloorStore>,
        InMemorySnapshotCache,
        QueueGenerationStore<InMemoryStagingStore>,
        VirtualScheduler,
    >;

    /// A live session's pass over the vault root at [`root_name`].
    struct Harness {
        pass: FakePass,
        state: SessionState,
        /// Held open: an events channel whose receiver dropped refuses sends.
        events: mpsc::UnboundedReceiver<Event>,
        /// The store under the pass's owner-scoped floors, shared with it.
        floor_backing: InMemoryFloorStore,
    }

    fn harness(
        transport: InMemoryRecordStore,
        blocks: &BTreeMap<String, Vec<u8>>,
        alive: bool,
    ) -> Harness {
        let enc_subkey = kdf::enc_subkey(&SECRET);
        let contact_label_seed = kdf::contact_label_seed(&SECRET);
        let floor_backing = InMemoryFloorStore::default();
        let floors = OwnerScopedFloorStore::new(floor_backing.clone());
        floors.bind(&enc_subkey, &contact_label_seed);
        let (events, event_stream) = mpsc::unbounded();
        let seams = EngineSeams {
            transport,
            api: Rc::new(ApiClient::new(
                ScriptedHttp::default(),
                InMemoryCredentialStore::default(),
                "",
            )),
            floors,
            snapshot_cache: InMemorySnapshotCache::default(),
            staging: QueueGenerationStore::new(InMemoryStagingStore::default()),
            scheduler: VirtualScheduler::new(),
            http: serve(blocks),
            gateway: gateway(),
            entropy: Rc::new(RefCell::new(Box::new(SeededEntropy::new(42)))),
            events,
            deadlines: DeadlinePolicy::default(),
            profile: SyncTimingProfile::CI,
            storage_policy: StoragePolicy::CI,
            content_profile: ContentProfile::CI,
        };
        let secrets = SessionSecrets::default();
        *secrets.tick_enc_subkey.borrow_mut() = Some(enc_subkey);
        *secrets.tick_contact_label_seed.borrow_mut() = Some(contact_label_seed);
        *secrets.tick_bin_keys.borrow_mut() = Some(Rc::new(BinIndexKeys::derive(&SECRET)));
        *secrets.tick_settings_signer.borrow_mut() =
            Some(Rc::new(kdf::settings_ipns_keypair(&SECRET)));
        let state = SessionState::new();
        *state.current_root_name.borrow_mut() = Some(root_name());
        *state.placement.borrow_mut() = Some(SessionPlacement::member(Ok(Placement::Hosted)));
        let owner_identity = EcdsaSigner::from_scalar(&SECRET)
            .expect("valid scalar")
            .verifying_key();
        Harness {
            pass: TickPass::new(
                seams,
                Rc::new(secrets),
                Rc::new(Cell::new(alive)),
                ManualRefresh::default(),
                owner_identity,
                ROOT.0,
            ),
            state,
            events: event_stream,
            floor_backing,
        }
    }

    fn root_name() -> IpnsName {
        derive_write_name(&Zeroizing::new(OWNER_ROOT_WRITE_SCOPE_SEED), &ROOT.0)
    }

    fn unpublished() -> InMemoryRecordStore {
        InMemoryRecordStore::new(vec![EndpointId::new(ENDPOINT)])
    }

    /// The owner's vault root, published at [`root_name`], and the head block
    /// its record anchors.
    fn published_root() -> (InMemoryRecordStore, BTreeMap<String, Vec<u8>>) {
        let root = owner_root_fixture(OwnerRootSpec {
            owner_identity: &EcdsaSigner::from_scalar(&SECRET).expect("valid scalar"),
            owner_enc: &kdf::enc_subkey(&SECRET).public(),
            writer_pseudonym: &owner_root_pseudonym(),
            pointer_read_key: OWNER_ROOT_POINTER_READ_KEY,
            scope_id: ROOT.0,
            root_id: ROOT.0,
            children: Vec::new(),
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants: Vec::new(),
        });
        let signer =
            kdf::ipns_keypair(kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &ROOT.0).as_bytes());
        let value = format!("/ipfs/{}", root.head_cid_str);
        let record = IpnsRecord::create_v2(&signer, value.as_bytes(), 1, TTL_NANOS, EOL).marshal();
        let transport = unpublished();
        transport.seed_record(&EndpointId::new(ENDPOINT), root.name.as_str(), record);
        (
            transport,
            BTreeMap::from([(root.head_cid_str, root.head_block)]),
        )
    }

    #[test]
    fn a_pass_after_teardown_reports_a_stop() {
        let harness = harness(unpublished(), &BTreeMap::new(), false);

        let report = block_on(harness.pass.run(&harness.state, TickCause::Poll));

        assert_eq!(report, PassReport::STOPPED);
    }

    #[test]
    fn a_pass_with_no_placement_reports_a_stop() {
        let harness = harness(unpublished(), &BTreeMap::new(), true);
        *harness.state.placement.borrow_mut() = None;

        let report = block_on(harness.pass.run(&harness.state, TickCause::Poll));

        assert_eq!(report, PassReport::STOPPED);
    }

    #[test]
    fn a_pass_whose_root_no_endpoint_serves_reports_unreachable() {
        let harness = harness(unpublished(), &BTreeMap::new(), true);

        let report = block_on(harness.pass.run(&harness.state, TickCause::Poll));

        assert_eq!(
            report,
            PassReport {
                verdict: RefreshVerdict::Unreachable,
                stop: false,
            }
        );
        assert!(!report.converged());
    }

    #[test]
    fn a_pass_that_adopts_the_root_reports_converged() {
        let (transport, blocks) = published_root();
        let harness = harness(transport, &blocks, true);

        let report = block_on(harness.pass.run(&harness.state, TickCause::Poll));

        assert_eq!(
            report,
            PassReport {
                verdict: RefreshVerdict::Reconciled,
                stop: false,
            }
        );
        assert!(report.converged());
    }

    const PROMOTED: NodeId = NodeId([0xD1; 16]);
    const INSIDE: NodeId = NodeId([0xD2; 16]);
    const PROMOTED_WRITE_SEED: [u8; 32] = [0x5A; 32];
    const EPOCH: u64 = 1;
    const NEW_EPOCH: u64 = EPOCH + 1;
    const OLD_READ_SEED: [u8; 32] = [0x5B; 32];
    const NEW_READ_SEED: [u8; 32] = [0x5C; 32];

    /// `node`'s folder record, sealed in `PROMOTED` at `epoch` under
    /// `seal_seed` and published at its own name: the name, the head CID and
    /// the head block.
    fn sealed_folder(
        transport: &InMemoryRecordStore,
        node: NodeId,
        epoch: u64,
        seal_seed: [u8; 32],
    ) -> (IpnsName, String, Vec<u8>) {
        let node_seed = kdf::node_seed(&seal_seed, &node.0);
        let envelope = seal_read_body(
            kdf::read_key(node_seed.as_bytes()).as_bytes(),
            &[seal_seed[0] ^ node.0[0]; 24],
            1,
            node.0,
            PROMOTED.0,
            epoch,
            &ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children: Vec::new(),
                unknown: PreservedFields::new(),
            },
        )
        .expect("the body seals");
        let head_block = encode_envelope(&envelope).expect("the envelope encodes");
        let head_cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head_block));
        let name = derive_write_name(&PROMOTED_WRITE_SEED, &node.0);
        transport.seed_record(
            &EndpointId::new(ENDPOINT),
            name.as_str(),
            IpnsRecord::create_v2(
                &kdf::ipns_keypair(kdf::write_seed(&PROMOTED_WRITE_SEED, &node.0).as_bytes()),
                format!("/ipfs/{head_cid}").as_bytes(),
                1,
                TTL_NANOS,
                EOL,
            )
            .marshal(),
        );
        (name, head_cid, head_block)
    }

    /// Place the focused `folders` below the own promoted scope `PROMOTED`,
    /// with the scope's read-epoch floor at `floor` and `held` in the cache
    /// stamped `stamp`.
    fn focused_inside_promoted(
        harness: &Harness,
        folders: &[(NodeId, &IpnsName)],
        floor: u64,
        (held, stamp): ([u8; 32], u64),
    ) {
        block_on(
            harness
                .pass
                .seams
                .floors
                .raise_epoch_floor(&PROMOTED.0, floor),
        )
        .expect("the floor raises");
        let state = &harness.state;
        let now = harness.pass.seams.scheduler.now();
        {
            let mut base = state.snapshot.borrow_mut();
            base.upsert_node(NodeMeta::new(PROMOTED, "promoted", NodeKind::Folder));
            base.link(NodeId(ROOT.0), PROMOTED, 1);
            for (node, name) in folders {
                let mut folder = NodeMeta::new(*node, "inside", NodeKind::Folder);
                folder.ipns_name = Some(name.as_str().as_bytes().to_vec());
                base.upsert_node(folder);
                base.link(PROMOTED, *node, 1);
                state.focus.borrow_mut().touched_folders.insert(*node, now);
            }
        }
        state.descendant_scope_roots.borrow_mut().insert(PROMOTED);
        deposit_seed(
            &state.scope_read_seeds,
            PROMOTED.0,
            Zeroizing::new(held),
            Some(stamp),
            FloorNamespace::Own,
        );
    }

    /// One focused folder `INSIDE` sealed at `epoch` under `seal_seed`, over a
    /// floor at `floor` and a cache holding `held`.
    fn focused_inside(
        epoch: u64,
        seal_seed: [u8; 32],
        floor: u64,
        held: ([u8; 32], u64),
    ) -> Harness {
        let transport = unpublished();
        let (name, head_cid, head_block) = sealed_folder(&transport, INSIDE, epoch, seal_seed);
        let harness = harness(transport, &BTreeMap::from([(head_cid, head_block)]), true);
        focused_inside_promoted(&harness, &[(INSIDE, &name)], floor, held);
        harness
    }

    /// The focus legs of one pass, and whether they raised abuse.
    fn run_focus(harness: &mut Harness) -> (RefreshVerdict, bool) {
        let pass = harness
            .pass
            .loop_gate(&harness.state, TickCause::Poll)
            .expect("the session is live");
        let (verdict, _) = block_on(harness.pass.refresh_focus(
            &harness.state,
            &pass,
            &GraftedSharers::new(),
        ));
        let abuse = core::iter::from_fn(|| harness.events.try_recv().ok())
            .any(|event| matches!(event, Event::AttributableAbuse { .. }));
        (verdict, abuse)
    }

    /// The leg starts with a seed stamped below the floor. The record at the
    /// floor is honest, so the leg reports an outage and accuses nobody.
    #[test]
    fn a_floor_raised_during_the_pass_does_not_accuse_an_honest_writer() {
        let mut harness =
            focused_inside(NEW_EPOCH, NEW_READ_SEED, NEW_EPOCH, (OLD_READ_SEED, EPOCH));

        let (verdict, abuse) = run_focus(&mut harness);

        assert!(!abuse, "a seed below the floor accuses nobody");
        assert_eq!(verdict, RefreshVerdict::Unreachable);
        assert!(
            cached_seed(&harness.state.scope_read_seeds, &PROMOTED.0).is_none(),
            "the leg evicted the seed the floor revoked"
        );
    }

    /// The other arm: this device holds the seed of the floor epoch, so a
    /// record at the floor that does not open under it is tampering.
    #[test]
    fn a_record_at_the_floor_that_the_current_seed_cannot_open_stays_abuse() {
        let mut harness = focused_inside(
            NEW_EPOCH,
            OLD_READ_SEED,
            NEW_EPOCH,
            (NEW_READ_SEED, NEW_EPOCH),
        );

        let (verdict, abuse) = run_focus(&mut harness);

        assert!(abuse, "a body that does not open at the floor is abuse");
        assert_eq!(verdict, RefreshVerdict::Rejected);
    }

    /// A rotation on this device raises the floor while the leg waits on the
    /// network between two record resolves. The second record is honest at
    /// the new floor, so the leg accuses nobody.
    #[test]
    fn a_floor_raised_between_two_resolves_of_one_leg_accuses_nobody() {
        const SECOND: NodeId = NodeId([0xD3; 16]);
        let transport = unpublished();
        let (inside, inside_cid, inside_head) =
            sealed_folder(&transport, INSIDE, EPOCH, OLD_READ_SEED);
        let (second, second_cid, second_head) =
            sealed_folder(&transport, SECOND, NEW_EPOCH, NEW_READ_SEED);
        let mut harness = harness(transport, &BTreeMap::new(), true);
        focused_inside_promoted(
            &harness,
            &[(INSIDE, &inside), (SECOND, &second)],
            EPOCH,
            (OLD_READ_SEED, EPOCH),
        );
        let backing = harness.floor_backing.clone();
        let [floor_key] =
            <[Vec<u8>; 1]>::try_from(backing.epoch_keys()).expect("one scope holds an epoch floor");
        let blocks = BTreeMap::from([(inside_cid, inside_head), (second_cid.clone(), second_head)]);
        harness.pass.seams.http = ScriptedHttp::with_route(move |request| {
            let cid = requested_cid(&request.url);
            if cid == second_cid {
                block_on(backing.raise_epoch_floor(&floor_key, NEW_EPOCH))
                    .expect("the rotation raises the floor");
            }
            Some(blocks.get(&cid).cloned().map_or_else(
                || Err(SeamError::new("no such block")),
                |body| {
                    Ok(HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: body.into(),
                    })
                },
            ))
        });

        let (_, abuse) = run_focus(&mut harness);

        assert!(!abuse, "a record above the seed's stamp accuses nobody");
    }

    /// A vault that keeps no bin drops every held capture and every proof, so
    /// a later bin turned on starts each capture with a fresh walk.
    #[test]
    fn a_pass_at_retention_zero_drops_the_held_captures_and_their_proofs() {
        let (transport, blocks) = published_root();
        let harness = harness(transport, &blocks, true);
        *harness.state.settings_summary.borrow_mut() = Some(
            crate::settings::VaultSettings {
                bin_retention_days: 0,
                ..crate::settings::VaultSettings::default()
            }
            .summary(crate::settings::SettingsOrigin::Resolved),
        );
        harness
            .state
            .observed_unlinks
            .borrow_mut()
            .push(crate::sync::project::UnlinkedChild {
                scope_id: ROOT.0,
                parent: ROOT,
                node: NodeId([0x43; 16]),
                name: "departed.txt".to_owned(),
                kind: cipherbox_core::seal::NodeKind::File,
                ipns_name: Vec::new(),
                deleted_at: 9,
            });
        harness
            .state
            .capture_proofs
            .borrow_mut()
            .insert(ROOT, crate::sync::drain::CaptureProofs::default());

        block_on(harness.pass.run(&harness.state, TickCause::Poll));

        assert!(harness.state.observed_unlinks.borrow().is_empty());
        assert!(harness.state.capture_proofs.borrow().is_empty());
    }
}
