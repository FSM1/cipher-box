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

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::Permission as CommittedPermission;
use cipherbox_core::suite::ecdsa::{EcdsaVerifier, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use zeroize::Zeroizing;

use crate::bin_index::BinIndexKeys;
use crate::content::RetentionPolicy;
use crate::facade::claim_conversion::{
    ConversionPass, CutAuthority, PointerIndex, TickSites, placed, scope_pointer_index,
};
use crate::facade::{
    ConsultWindow, EngineError, Event, GraftedWritePass, NodeId, POINTER_PAYLOAD_VERSION,
    ScopeSeeds, SeedFloors, SweepKeys, adopt_settings_summary, bin_retention_days, cached_seed,
    consult_pointers, deposit_seed, deposit_write_seed, emit_trust_violation, focus_scope_roots,
    grafted_write_passes, install_descendant_scopes, install_unproved_scopes, leg_file_share,
    memoized_scan, nodes_in_scope, own_descendant_scopes, queue_unprojected_children,
    refresh_seed_floors, report_settings_verdict, scope_root_record_name, second_end_scope,
    settle_focus_leg, walked_boundary_material,
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
use crate::net::{
    DescendantScopeRoot, FolderRefresh, GraftedLeg, HeldKey, HeldMaterial, HeldRecords,
    ResolveOutcome, Resolved, RootAdopter, ScopeWalk, WalkFailure, WritePlaneDark, observed_at,
    refresh_base_from_resolved, resolve_and_hold,
};
use crate::rotation::scope_material::ScopeMaterial;
use crate::rotation::{
    Boundaries, ResolveFailure, RotateError, RotateOnExit, ScopeExitArm, ascent_node_seed,
    cut_exited_scope, derive_write_name, install_walked_read_epochs,
};
use crate::seams::{
    CredentialStore, FloorStore, Http, QueueGeneration, RecordTransport, Scheduler, SeamError,
    SnapshotCache, StagingStore, UnixMillis,
};
use crate::session::{SessionSecrets, SessionState};
use crate::settings::{
    PlacementDecision, SessionPlacement, SettingsOrigin, VaultSettingsSummary, load_settings_at,
    redecide_placement, summarize_settings,
};
use crate::sync::drain::{
    Drain, DrainScope, EngineSeams, GrantedPass, ScopeEnd, SealPlane, TickInputs, TickScopes,
    hold_captures,
};
use crate::sync::rebase::QueueScanMemo;
use crate::sync::record::RecordReader;
use crate::sync::refresh::{ManualRefresh, RefreshVerdict};
use crate::sync::tick::{
    ResolveMode, TickCause, consult_scopes, consult_scopes_due, expire_focus_stamps,
    expire_touched_folders, focus_by_scope, focus_files, pace_due, resolve_mode, scope_root_of,
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
            if let Some(decided) = redecide_placement(&load) {
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
    ) -> (Result<Resolved, SeamError>, Option<Zeroizing<[u8; 32]>>) {
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
        state.sync_status.borrow_mut().reconcile_in_flight = true;
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
                deposit_seed(&state.scope_read_seeds, self.root_id, seed, stamp);
            }
            if let Some((node_id, seed)) = surfaced.write_scope_seed.take() {
                deposit_write_seed(
                    &state.scope_write_seeds,
                    node_id,
                    seed,
                    Some(&pass.root_name),
                    floors_before.write,
                );
            }
        }
        let resolved = held_resolve.map(|surfaced| surfaced.resolved);
        if let Ok(resolved) = &resolved {
            if let ResolveOutcome::TrustViolation(rejection) = &resolved.outcome {
                emit_trust_violation(&self.seams.events, pass.root_name.as_str(), rejection);
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
        let read_seed = cached_seed(&state.scope_read_seeds, &self.root_id);
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
                install_unproved_scopes(
                    &state.unproved_scope_roots,
                    walked.proved.iter().map(|s| NodeId(s.scope_id)),
                    walked.unproved,
                );
                descendants = walked.proved;
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
                    state.boundary_walk_rejected.set(true);
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
        for (scope_root, targets) in by_scope {
            if scopes.unproved.contains(&scope_root) {
                // No material was ever proved for this boundary, so
                // its subtree waits for the walk that proves it
                // ([`focus_scope_roots`]).
                folder_verdict = folder_verdict.worst(RefreshVerdict::Unreachable);
                continue;
            }
            let own = is_own_scope(&self.root_id, &scopes.proved, &scope_root.0);
            let Some(scope_read_seed) = cached_seed(&state.scope_read_seeds, &scope_root.0) else {
                // A scope this vault owns and cannot read is an
                // outage on its own leg: a promotion the last
                // boundary walk could not re-prove keeps its place
                // in the proved set and loses its seed, so the
                // folders in view under it stay unread. Charge the
                // pass for them rather than reporting a window it
                // never read.
                if own {
                    folder_verdict = folder_verdict.worst(RefreshVerdict::Unreachable);
                }
                continue;
            };
            let Some(scope_floors) = floor_view(
                &self.seams.floors,
                grafted,
                &pass.contact_label_seed,
                &self.root_id,
                &scopes.proved,
                &scope_root.0,
            ) else {
                continue;
            };
            let scope_root_name = scope_root_record_name(
                &state.snapshot.borrow(),
                Some(&pass.root_name),
                &scope_root.0,
            );
            let refresh = FolderRefresh {
                transport: &self.seams.transport,
                snapshot_cache: &self.seams.snapshot_cache,
                http: &self.seams.http,
                floors: &scope_floors,
                gateway: &self.seams.gateway,
                base: &state.snapshot,
                events: &self.seams.events,
                scope_id: scope_root.0,
                scope_read_seed: &scope_read_seed,
                scope_root_name: scope_root_name.as_ref(),
                plane: (!own).then_some(GraftedLeg {
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
        read_seed: &'a Option<Zeroizing<[u8; 32]>>,
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
            root_read_seed,
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
            source: ScopeEnd {
                root: NodeId(self.root_id),
                root_name: &pass.root_name,
                read_scope_seed: read_seed,
                write_scope_seed: write_seed,
                // The vault root carries no ascent link.
                ascent_node_seed: None,
                floor_namespace: FloorNamespace::Own,
            },
            destination: second.as_ref().map(|end| SealPlane {
                end: ScopeEnd {
                    root: end.root,
                    root_name: &end.name,
                    read_scope_seed: &end.material.read_scope_seed,
                    write_scope_seed: &end.material.write_scope_seed,
                    ascent_node_seed: end.ascent.as_ref(),
                    floor_namespace: FloorNamespace::Own,
                },
                epoch: end.material.read_epoch,
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
                source: ScopeEnd {
                    root: NodeId(scope.scope_id),
                    root_name: &scope.name,
                    read_scope_seed: &scope.read_scope_seed,
                    write_scope_seed: &write.seed,
                    ascent_node_seed: Some(&scope.parent_node_seed),
                    // A grant cut mints an interior scope root out of
                    // this vault's own tree, so its floors are this
                    // identity's own.
                    floor_namespace: FloorNamespace::Own,
                },
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
                source: ScopeEnd {
                    root: pass.root,
                    root_name: &pass.name,
                    read_scope_seed: &pass.read_scope_seed,
                    write_scope_seed: &pass.write_scope_seed,
                    // A grantee enters by its own grant blob and holds
                    // no ancestor seed to derive an ascent keypair from.
                    ascent_node_seed: None,
                    floor_namespace: pass.floors,
                },
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
        let drain = Drain::new(
            &self.seams,
            state.drain_cells(),
            TickInputs {
                placement: decision,
                bin_keys: &pass.bin_keys,
                bin_retention_days: owner_bin_retention_days(&state.settings_summary),
                retention: owner_retention(&state.settings_summary),
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
        };
        let sites = TickSites {
            boundaries,
            root_name: &root_name,
            walked: state.scope_roots_walked.get(),
        };
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
    let base = boundaries.base.borrow();
    let scope = scan
        .mine
        .iter()
        .find_map(|(_, op)| second_end_scope(&base, op, listed))?;
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

/// The bin retention the owner actually chose, or `None` when this device's
/// settings load carried no member choice.
///
/// The delete branch takes the documented default because binning is the
/// reversible error ([`bin_retention_days`]); expiry destroys, so it acts only
/// on a retention this device can show is the owner's.
fn owner_bin_retention_days(summary: &RefCell<Option<VaultSettingsSummary>>) -> Option<u32> {
    let summary = summary.borrow();
    summary
        .as_ref()
        .filter(|summary| summary.origin != SettingsOrigin::Defaults)
        .map(|summary| summary.bin_retention_days)
}

/// The version retention the owner actually chose, or [`RetentionPolicy::KeepAll`]
/// when this device's settings load carried no member choice
/// (blueprint/engine.md "Content plane").
fn owner_retention(summary: &RefCell<Option<VaultSettingsSummary>>) -> RetentionPolicy {
    let summary = summary.borrow();
    summary
        .as_ref()
        .filter(|summary| summary.origin != SettingsOrigin::Defaults)
        .map_or(RetentionPolicy::KeepAll, |summary| summary.retention)
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

#[cfg(test)]
mod tests {
    use super::*;

    use cipherbox_core::ipns::IpnsRecord;
    use cipherbox_core::kdf;
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use futures_channel::mpsc;

    use crate::api::ApiClient;
    use crate::content::ContentProfile;
    use crate::deadlines::DeadlinePolicy;
    use crate::profile::SyncTimingProfile;
    use crate::rotation::derive_write_name;
    use crate::seams::{EndpointId, OwnerScopedFloorStore, QueueGenerationStore};
    use crate::settings::Placement;
    use crate::storage_policy::StoragePolicy;
    use crate::testkit::account::{EOL, ROOT, SECRET, TTL_NANOS};
    use crate::testkit::fakes::{
        InMemoryCredentialStore, InMemoryFloorStore, InMemoryRecordStore, InMemorySnapshotCache,
        InMemoryStagingStore, ScriptedHttp, VirtualScheduler,
    };
    use crate::testkit::{
        OWNER_ROOT_EPOCH, OWNER_ROOT_POINTER_READ_KEY, OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootSpec,
        SeededEntropy, block_on, gateway, owner_root_fixture, owner_root_pseudonym, serve,
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
        _events: mpsc::UnboundedReceiver<Event>,
    }

    fn harness(
        transport: InMemoryRecordStore,
        blocks: &BTreeMap<String, Vec<u8>>,
        alive: bool,
    ) -> Harness {
        let enc_subkey = kdf::enc_subkey(&SECRET);
        let contact_label_seed = kdf::contact_label_seed(&SECRET);
        let floors = OwnerScopedFloorStore::new(InMemoryFloorStore::default());
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
            _events: event_stream,
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
}
