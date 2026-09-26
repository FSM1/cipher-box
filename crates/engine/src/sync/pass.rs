//! One focus-window tick pass (blueprint/engine.md "Sync core", "Liveness").
//!
//! [`TickPass::run`] is the body [`run_tick_loop`](crate::sync::tick::run_tick_loop)
//! calls once per tick. It reconciles the vault root and the focus window,
//! drains the op queue onto that state, pulls the mailbox, converts claims,
//! and reports the staleness rung.

use core::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::Permission as CommittedPermission;
use cipherbox_core::suite::ecdsa::{EcdsaVerifier, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use zeroize::Zeroizing;

use crate::content::RetentionPolicy;
use crate::facade::claim_conversion::{
    ConversionPass, CutAuthority, PointerIndex, TickSites, placed, scope_pointer_index,
};
use crate::facade::{
    Boundaries, ConsultWindow, EngineError, Event, NodeId, POINTER_PAYLOAD_VERSION, ScopeSeeds,
    adopt_settings_summary, ascent_node_seed, bin_retention_days, cached_seed, consult_pointers,
    deposit_seed, deposit_write_seed, emit_trust_violation, focus_scope_roots,
    grafted_write_passes, install_descendant_scopes, install_unproved_scopes, leg_file_share,
    memoized_scan, nodes_in_scope, own_descendant_scopes, queue_unprojected_children,
    refresh_seed_floors, report_settings_verdict, scope_root_record_name, second_end_scope,
    settle_focus_leg, walked_boundary_material,
};
use crate::grants::grafted::{
    BookmarkedPermissions, FloorNamespace, GraftedPlane, GraftedSharers, evict_grafted_read_seeds,
    evict_grafted_write_seeds, floor_namespace, floor_view, is_own_scope,
};
use crate::grants::inbox::ShareInbox;
use crate::grants::link_read::repost_held_claims;
use crate::grants::received_status::{ReceivedShareStatus, ScopeRender};
use crate::grants::{ContactStore, StagingContactStore};
use crate::net::author::ENVELOPE_V;
use crate::net::{
    FolderRefresh, GraftedLeg, HeldKey, HeldMaterial, HeldRecords, ResolveOutcome, RootAdopter,
    ScopeWalk, WalkFailure, WritePlaneDark, observed_at, refresh_base_from_resolved,
    resolve_and_hold,
};
use crate::rotation::scope_material::ScopeMaterial;
use crate::rotation::{
    ResolveFailure, RotateError, RotateOnExit, ScopeExitArm, cut_exited_scope, derive_write_name,
    install_walked_read_epochs,
};
use crate::seams::{
    CredentialStore, FloorStore, Http, QueueGeneration, RecordTransport, Scheduler, SnapshotCache,
    StagingStore, UnixMillis,
};
use crate::session::{SessionSecrets, SessionState};
use crate::settings::{
    SessionPlacement, SettingsOrigin, VaultSettingsSummary, load_settings_at, redecide_placement,
    summarize_settings,
};
use crate::sync::drain::{
    Drain, DrainScope, EngineSeams, GrantedPass, ScopeEnd, SealPlane, TickInputs, TickScopes,
    hold_captures,
};
use crate::sync::rebase::QueueScanMemo;
use crate::sync::record::RecordReader;
use crate::sync::refresh::{ManualRefresh, RefreshVerdict};
use crate::sync::staleness::{Connectivity, classify};
use crate::sync::tick::{
    ResolveMode, TickCause, TickControl, consult_scopes, consult_scopes_due, expire_focus_stamps,
    expire_touched_folders, focus_by_scope, focus_files, pace_due, resolve_mode, scope_root_of,
};

/// The tick's per-session inputs: the seam set, the session secrets, and the
/// pacing stamps one pass reads and advances.
pub(crate) struct TickPass<T, H: Http, C: CredentialStore, F, S, St, Sch> {
    pub(crate) seams: EngineSeams<T, H, C, F, S, St, Sch>,
    pub(crate) secrets: Rc<SessionSecrets>,
    pub(crate) alive: Rc<Cell<bool>>,
    pub(crate) manual: ManualRefresh,
    pub(crate) owner_identity: EcdsaVerifier,
    pub(crate) root_id: [u8; 16],
    /// Start has just decided, so the first re-decide comes one interval on.
    pub(crate) settings_rechecked: Cell<UnixMillis>,
    pub(crate) link_swept: Cell<UnixMillis>,
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
    /// One tick: [`TickControl::Stop`] once the session is gone.
    pub(crate) async fn run(&self, state: &SessionState, cause: TickCause) -> TickControl {
        let EngineSeams {
            transport,
            api,
            floors,
            snapshot_cache,
            staging,
            scheduler,
            http,
            gateway,
            entropy,
            events,
            profile,
            ..
        } = &self.seams;
        let SessionState {
            observed_unlinks,
            scope_write_seeds,
            converged_tick,
            placement,
            settings_summary,
            byo_reconciled,
            held_records: held,
            snapshot: base,
            sync_status,
            scope_read_seeds,
            descendant_scope_roots: descendant_roots,
            unproved_scope_roots: unproved_roots,
            boundary_walk_rejected,
            scope_roots_walked,
            walked_read_epochs,
            current_root_name,
            focus,
            focus_refreshed,
            pointer_consulted,
            on_access_misses,
            received_verdicts,
            received_shares_lock,
            grafted_sharers,
            bookmarked_scope_roots,
            bookmarked_permissions,
            grafted_write_roots,
            grafted_claims,
            minted_scope_roots: minted_roots,
            pending_invite_claims,
            conversion_running,
            sweep_tasks,
            queue_scan,
            ..
        } = state;
        let SessionSecrets {
            tick_enc_subkey,
            tick_bin_keys,
            tick_settings_signer,
            tick_contact_label_seed,
            sweep_keys: consult_keys,
            tick_owner_signer,
        } = &*self.secrets;
        let alive = &self.alive;
        let manual = &self.manual;
        let owner_identity = self.owner_identity;
        let root_id = self.root_id;
        let settings_rechecked = &self.settings_rechecked;
        let link_swept = &self.link_swept;
        if !alive.get() {
            return TickControl::Stop;
        }
        let mode = resolve_mode(cause);
        // The session cell is the root's only current name: a wave
        // this session drove between passes has already moved it.
        let Some(mut root_name) = current_root_name.borrow().clone() else {
            return TickControl::Stop;
        };
        // The pass owns a copy for exactly its own duration; the engine
        // emptied the cell if it is already gone.
        let enc_subkey = tick_enc_subkey.borrow().clone();
        let Some(enc_subkey) = enc_subkey else {
            return TickControl::Stop;
        };
        let contact_label_seed = tick_contact_label_seed.borrow().clone();
        let Some(contact_label_seed) = contact_label_seed else {
            return TickControl::Stop;
        };
        let bin_keys = tick_bin_keys.borrow().clone();
        let Some(bin_keys) = bin_keys else {
            return TickControl::Stop;
        };
        let settings_signer = tick_settings_signer.borrow().clone();
        let Some(settings_signer) = settings_signer else {
            return TickControl::Stop;
        };
        let now = scheduler.now();
        // What this paces is a revocation window
        // ([`redecide_placement`]).
        if pace_due(
            now,
            settings_rechecked.get(),
            profile.settings_recheck_interval,
        ) {
            settings_rechecked.set(now);
            let observed = observed_at(held, HeldKey::VaultSettings);
            let read = load_settings_at(
                transport,
                gateway,
                http,
                floors,
                snapshot_cache,
                scheduler,
                profile,
                &enc_subkey,
                &settings_signer,
            )
            .await;
            // A teardown that landed inside the load already
            // cleared the placement cell, which holds the member's
            // provider bearer, and the renewal slot, which holds
            // the record's signer. Writing either back would make
            // it resident again and re-arm the pass the cleared
            // cell stops below (security rules 1 and 7).
            if !alive.get() {
                return TickControl::Stop;
            }
            let load = read.enrol(held, observed);
            report_settings_verdict(events, &load);
            if let Some(decided) = redecide_placement(&load) {
                *placement.borrow_mut() = Some(decided);
                adopt_settings_summary(summarize_settings(&load), settings_summary, events);
                byo_reconciled.set(false);
            }
        }
        // Carries the member's BYO bearer, so the pass owns a copy on the
        // same terms as the enc subkey above.
        let Some(SessionPlacement { decision, .. }) = placement.borrow().clone() else {
            return TickControl::Stop;
        };
        // The polled pointer consult (#38 D4), ahead of the floor
        // refresh below so a write epoch this pass sights evicts the
        // seed it retired in the same pass.
        // A manual refresh resolves nocache everywhere, so it
        // consults every scope in the window rather than waiting out
        // the interval the poll leg is paced by.
        let consult_targets = match mode {
            ResolveMode::NoCache => consult_scopes(&base.borrow(), &focus.borrow()),
            ResolveMode::CacheFirst => consult_scopes_due(
                &base.borrow(),
                &focus.borrow(),
                &pointer_consulted.borrow(),
                now,
                profile,
            ),
        };
        if let Some(current_root) = consult_pointers(
            transport,
            floors,
            consult_keys,
            events,
            pointer_consulted,
            ConsultWindow {
                scopes: consult_targets,
                anchor: NodeId(root_id),
                now,
            },
        )
        .await
        {
            *current_root_name.borrow_mut() = Some(current_root.clone());
            root_name = current_root;
        }
        // Before the steady-state hold consults them: a floor raised
        // since the last pass revokes the seeds this pass would
        // otherwise read and seal under. The floors it reports stamp
        // whatever this pass's own resolve recovers.
        let floors_before =
            refresh_seed_floors(floors, &root_id, scope_read_seeds, scope_write_seeds).await;
        let grafted = grafted_sharers.borrow().clone();
        let own_before = own_descendant_scopes(descendant_roots, minted_roots);
        evict_grafted_read_seeds(
            floors,
            &grafted,
            &contact_label_seed,
            &root_id,
            &own_before,
            scope_read_seeds,
        )
        .await;
        evict_grafted_write_seeds(
            floors,
            &grafted,
            &contact_label_seed,
            &root_id,
            &own_before,
            scope_write_seeds,
        )
        .await;
        let adopter =
            RootAdopter::new(gateway, http, floors, &enc_subkey, &owner_identity, root_id).holding(
                steady_state_hold(
                    held,
                    root_id,
                    &root_name,
                    scope_read_seeds,
                    scope_write_seeds,
                ),
            );
        // Own-root material: the write-scope seed the owner cannot
        // re-derive rides the adopt (recovered from the owner-write-blob),
        // so the caller-side seed is `None` and the gate's authenticated
        // node id keys the hold. A resolve/gate failure is availability —
        // it never stops the loop (blueprint/engine.md "Liveness").
        let material = HeldMaterial {
            node_id: root_id,
            write_scope_seed: None,
        };
        // A gate-passing `Adopted` repaints the shared base cell and emits
        // `SnapshotUpdated`; `Current`/`NoUpdate`/`TrustViolation` leave
        // last-known-good intact (fail-closed for data).
        sync_status.borrow_mut().reconcile_in_flight = true;
        let mut held_resolve = resolve_and_hold(
            transport,
            snapshot_cache,
            &adopter,
            &root_name,
            held,
            &material,
            mode,
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
                deposit_seed(scope_read_seeds, root_id, seed, stamp);
            }
            if let Some((node_id, seed)) = surfaced.write_scope_seed.take() {
                deposit_write_seed(
                    scope_write_seeds,
                    node_id,
                    seed,
                    Some(&root_name),
                    floors_before.write,
                );
            }
        }
        let resolved = held_resolve.map(|surfaced| surfaced.resolved);
        if let Ok(resolved) = &resolved {
            if let ResolveOutcome::TrustViolation(rejection) = &resolved.outcome {
                emit_trust_violation(events, root_name.as_str(), rejection);
            }
            let merged = refresh_base_from_resolved(base, NodeId(root_id), resolved);
            if merged.changed {
                let _ = events.unbounded_send(Event::SnapshotUpdated);
            }
            hold_captures(
                observed_unlinks,
                merged.observed_unlinks(root_id, NodeId(root_id), now.0),
            );
        }
        let read_seed = cached_seed(scope_read_seeds, &root_id);
        // The held record is the root this pass reconciled, so the
        // walk needs no second read of either plane to start.
        let held_root = held
            .borrow()
            .get(&HeldKey::Node(root_id))
            .map(|record| (record.routing_key.clone(), record.record_bytes.clone()));
        // Cloned out of the cell: a `Ref` cannot be held across the
        // walk's awaits.
        let walk_keys = consult_keys.borrow().clone();
        let mut descendants = Vec::new();
        let walk = walk_keys.as_ref().map(|keys| ScopeWalk {
            transport,
            snapshot_cache,
            gateway,
            http,
            floors,
            enc_secret: &enc_subkey,
            identity: &owner_identity,
            scope_keys: &keys.scope_keys,
            payload_version: POINTER_PAYLOAD_VERSION,
        });
        if let Some(walk) = &walk
            && let Some((name, root_bytes)) = held_root
            && let Ok(name) = IpnsName::parse(&name)
        {
            let walked = walk
                .descendant_scope_roots(root_id, &name, &root_bytes)
                .await;
            let failure = walked
                .as_ref()
                .map_or_else(|met| Some(*met), |walked| walked.failure);
            if let Ok(walked) = walked {
                let departed = install_descendant_scopes(
                    descendant_roots,
                    scope_read_seeds,
                    scope_write_seeds,
                    base,
                    events,
                    &walked.proved,
                    now.0,
                );
                hold_captures(observed_unlinks, departed);
                install_walked_read_epochs(walked_read_epochs, &walked.proved);
                install_unproved_scopes(
                    unproved_roots,
                    walked.proved.iter().map(|s| NodeId(s.scope_id)),
                    walked.unproved,
                );
                descendants = walked.proved;
            }
            scope_roots_walked.set(failure.is_none() && unproved_roots.borrow().is_empty());
            // The boundary set a rejection leaves is incomplete, and
            // what is missing from it reads as its parent's scope,
            // so the session refuses to classify a move at all until
            // a walk names the whole set again.
            match failure {
                None => boundary_walk_rejected.set(false),
                Some(rejected @ WalkFailure::Rejected { .. }) => {
                    boundary_walk_rejected.set(true);
                    emit_trust_violation(events, name.as_str(), rejected);
                }
                Some(WalkFailure::Unavailable) => {}
            }
        }
        expire_touched_folders(&mut focus.borrow_mut(), scheduler.now(), profile);
        expire_focus_stamps(&mut focus_refreshed.borrow_mut(), scheduler.now(), profile);
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
        let proved_scope_ids = descendant_roots.borrow().clone();
        let unproved_scope_ids = unproved_roots.borrow().clone();
        let focus_scope_ids = focus_scope_roots(&proved_scope_ids, &unproved_scope_ids);
        let mut by_scope = focus_by_scope(&base.borrow(), &focus.borrow(), &focus_scope_ids);
        // A window whose only folder in view is a scope root groups
        // no folder target of its own, because that root resolves on
        // its pointer leg. Its scope still needs a pass, so the rows
        // it lists reach the file leg below.
        for folder in focus.borrow().folders_in_view() {
            by_scope
                .entry(scope_root_of(&base.borrow(), folder, &focus_scope_ids))
                .or_default();
        }
        let scope_roots = bookmarked_scope_roots.borrow().clone();
        for (scope_root, targets) in by_scope {
            if unproved_scope_ids.contains(&scope_root) {
                // No material was ever proved for this boundary, so
                // its subtree waits for the walk that proves it
                // ([`focus_scope_roots`]).
                folder_verdict = folder_verdict.worst(RefreshVerdict::Unreachable);
                continue;
            }
            let own = is_own_scope(&root_id, &proved_scope_ids, &scope_root.0);
            let Some(scope_read_seed) = cached_seed(scope_read_seeds, &scope_root.0) else {
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
                floors,
                &grafted,
                &contact_label_seed,
                &root_id,
                &proved_scope_ids,
                &scope_root.0,
            ) else {
                continue;
            };
            let scope_root_name =
                scope_root_record_name(&base.borrow(), Some(&root_name), &scope_root.0);
            let refresh = FolderRefresh {
                transport,
                snapshot_cache,
                http,
                floors: &scope_floors,
                gateway,
                base,
                events,
                scope_id: scope_root.0,
                scope_read_seed: &scope_read_seed,
                scope_root_name: scope_root_name.as_ref(),
                plane: (!own).then_some(GraftedLeg {
                    scope_roots: &scope_roots,
                    claims: grafted_claims,
                }),
                mode,
                observed_at: now.0,
            };
            let mut settle = |nodes: &[NodeId], report| {
                folder_verdict = folder_verdict.worst(settle_focus_leg(
                    observed_unlinks,
                    focus_refreshed,
                    events,
                    nodes,
                    report,
                    scheduler.now(),
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
                let base_now = base.borrow();
                let in_view = nodes_in_scope(
                    &base_now,
                    &focus_scope_ids,
                    scope_root,
                    focus.borrow().folders_in_view().collect(),
                );
                for folder in in_view.into_iter().rev() {
                    queue_unprojected_children(
                        &base_now,
                        focus,
                        focus_refreshed,
                        profile,
                        scheduler.now(),
                        folder,
                    );
                }
                let host_queued = focus.borrow().host_queued();
                leg_file_share(
                    nodes_in_scope(
                        &base_now,
                        &focus_scope_ids,
                        scope_root,
                        focus_files(&base_now, &focus.borrow()),
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
        focus
            .borrow_mut()
            .open_files
            .retain(|row| !attempted_files.contains(&row.node));
        // `Adopted`/`Current` are the reconciled outcomes: both prove the
        // record plane answered with gate-passing state, so both stamp
        // the ladder's `last_success` (#33 D4). A gate rejection is a
        // trust verdict, never the staleness the other failures are.
        let root_verdict = match &resolved {
            Ok(r) => match &r.outcome {
                ResolveOutcome::Adopted(_) | ResolveOutcome::Current { .. } => {
                    RefreshVerdict::Reconciled
                }
                ResolveOutcome::TrustViolation(_) => RefreshVerdict::Rejected,
                ResolveOutcome::NoUpdate => RefreshVerdict::Unreachable,
            },
            Err(_) => RefreshVerdict::Unreachable,
        };
        // The ladder measures the record plane, which the root leg alone
        // proves answered: one focused folder that did not is staleness
        // on that folder, not a plane-wide outage.
        let reconciled = root_verdict == RefreshVerdict::Reconciled;
        // Answer the manual requests on every read leg the pass forced,
        // the focus window included — a refresh that left the folder in
        // view unresolved has not landed. The drain below reports its own
        // progress through the op events.
        manual.settle(root_verdict.worst(folder_verdict));
        // A vault that keeps no bin captures no unlink either: the
        // owner turned the bin off, and an adoption carries no owner
        // command that could overrule that.
        if bin_retention_days(settings_summary) == 0 {
            observed_unlinks.borrow_mut().clear();
        }
        // The drain rides the same tick: it publishes onto exactly the
        // gate-passing state this pass just reconciled. Both scope seeds
        // are required — without them there is no name to publish under
        // and no key to seal with, so the queue simply waits.
        let write_seed = cached_seed(scope_write_seeds, &root_id);
        let write_grafts =
            write_grant_sharers(&bookmarked_permissions.borrow(), &grafted_sharers.borrow());
        let sharer_encs = write_grant_sharer_encs(
            &StagingContactStore::new(staging, &enc_subkey, entropy),
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
            let sharers = grafted_sharers.borrow();
            grafted_write_passes(
                base,
                &bookmarked_permissions.borrow(),
                &sharers,
                &sharer_encs,
                |scope_id| {
                    floor_namespace(
                        &sharers,
                        &contact_label_seed,
                        &root_id,
                        &proved_scope_ids,
                        scope_id,
                    )
                },
                scope_read_seeds,
                scope_write_seeds,
            )
        };
        let write_roots: BTreeSet<NodeId> = grafted.iter().map(|pass| pass.root).collect();
        // The snapshot's permission reads this set, so a host
        // repaints on the tick that proves or drops a write pass.
        if *grafted_write_roots.borrow() != write_roots {
            *grafted_write_roots.borrow_mut() = write_roots;
            let _ = events.unbounded_send(Event::SnapshotUpdated);
        }
        // A graft this vault may only read — a read grant, or a write
        // grant the sharer cut — publishes an op below it on no
        // pass. Listed keyless, so the pass holding the identity's
        // charge dead-letters such an op rather than stall the
        // strict-FIFO head behind it.
        let read_only_grafts: Vec<NodeId> = bookmarked_permissions
            .borrow()
            .iter()
            .filter(|(scope_id, permission)| {
                **permission == CommittedPermission::Read
                    && !is_own_scope(&root_id, &proved_scope_ids, scope_id)
                    && !minted_roots.borrow().contains(&NodeId(**scope_id))
                    && !unproved_scope_ids.contains(&NodeId(**scope_id))
            })
            .map(|(scope_id, _)| NodeId(*scope_id))
            .collect();
        // Owned for the drain, which awaits while it holds them.
        let grafted_scope_roots = bookmarked_scope_roots.borrow().clone();
        let grafted_contested = grafted_claims.borrow().contested().clone();
        let proved_roots: Vec<NodeId> = core::iter::once(NodeId(root_id))
            .chain(proved_scope_ids.iter().copied())
            .chain(grafted.iter().map(|pass| pass.root))
            .chain(read_only_grafts.iter().copied())
            .collect();
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
            base,
            scope_roots: minted_roots
                .borrow()
                .union(&proved_scope_ids)
                .copied()
                .collect(),
            material: walked_boundary_material(
                walked_read_epochs,
                scope_read_seeds,
                scope_write_seeds,
            ),
            root: NodeId(root_id),
            root_read_seed,
        });
        let second = match &boundaries {
            Some(boundaries) => {
                queued_second_end(staging, &enc_subkey, queue_scan, boundaries).await
            }
            None => None,
        };
        let exits = RotateOnExit(async |scope_root: NodeId| {
            let Some(boundaries) = &boundaries else {
                return Err(RotateError::Resolve(ResolveFailure::Unavailable));
            };
            cut_exited_scope(
                ScopeExitArm {
                    transport,
                    api,
                    gateway,
                    http,
                    floors,
                    snapshot_cache,
                    events,
                    scheduler,
                    profile,
                    entropy,
                    keys: consult_keys,
                    sweep: sweep_tasks,
                    boundaries,
                    walked_epochs: walked_read_epochs,
                    on_access_misses,
                },
                scope_root,
            )
            .await
        });
        let vault = vault_seeds.map(|(read_seed, write_seed)| DrainScope {
            source: ScopeEnd {
                root: NodeId(root_id),
                root_name: &root_name,
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
            enc_secret: &enc_subkey,
            owner_identity: &owner_identity,
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
                enc_secret: &enc_subkey,
                owner_identity: &owner_identity,
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
                enc_secret: &enc_subkey,
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
                placement: &decision,
                bin_keys: &bin_keys,
                bin_retention_days: owner_bin_retention_days(settings_summary),
                retention: owner_retention(settings_summary),
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
        // Last, and after the drain above: the grantee's own read
        // leg is the slowest in the pass, and a host refresh waits
        // on nothing it reports.
        //
        // The mailbox pull leads it, so a share this pass accepts is
        // classified by the refresh below rather than a pass later.
        let owner_keys = consult_keys.borrow().clone();
        let pointers = match (&boundaries, &owner_keys) {
            (Some(boundaries), Some(keys)) => {
                scope_pointer_index(&keys.scope_keys, boundaries.scope_roots.iter().copied())
            }
            _ => PointerIndex::new(),
        };
        let claims = ShareInbox {
            mailbox: api.as_ref(),
            transport,
            gateway,
            http,
            floors,
            enc_secret: &enc_subkey,
            contact_label_seed: &contact_label_seed,
            vault_root_scope: root_id,
            list_lock: received_shares_lock,
        }
        .pull(
            staging,
            entropy,
            ENVELOPE_V,
            &|pointer| placed(&pointers, pointer),
            events,
        )
        .await;
        // Any owner device converts on every pass (ADR 0023 D4), at
        // the boundaries this pass's own walk proved. A failed poll
        // still converts the claims already acked.
        let owner_signer = tick_owner_signer.borrow().clone();
        let sweep = sweep_tasks.borrow().clone();
        let vault_root_name = current_root_name.borrow().clone();
        if let (Some(boundaries), Some(signer), Some(keys), Some(sweep), Some(root_name)) = (
            boundaries.as_ref(),
            owner_signer,
            owner_keys,
            sweep,
            vault_root_name,
        ) {
            let pass = ConversionPass {
                transport,
                api: api.as_ref(),
                gateway,
                http,
                floors,
                snapshot_cache,
                events,
                scheduler,
                profile,
                on_access_misses,
                entropy,
                staging,
                identity: &signer,
                enc_secret: &enc_subkey,
                owner_identity: &owner_identity,
                scope_keys: &keys.scope_keys,
                cut: CutAuthority {
                    owner_pointer_seed: keys.scope_keys.pointer_seed(),
                    held,
                    sweep: &sweep,
                    vault_root: NodeId(root_id),
                },
                scope_roots_walked,
                counts: pending_invite_claims,
                running: conversion_running,
            };
            let converted = pass
                .run(
                    &TickSites {
                        boundaries,
                        root_name: &root_name,
                        walked: scope_roots_walked.get(),
                    },
                    &pointers,
                    claims.unwrap_or_default(),
                    None,
                )
                .await
                .into_result();
            if let Err(EngineError::TrustViolation { message }) = converted {
                let _ = events.unbounded_send(Event::AttributableAbuse {
                    description: message,
                });
            }
            // After the conversion above, so a claim acked this
            // pass converts before its link can be cut.
            if pace_due(now, link_swept.get(), profile.link_sweep_cadence)
                && let Some(swept) = pass.sweep_links(&root_name, &pointers).await
            {
                // A capped sweep continues on the next tick.
                if !swept.more {
                    link_swept.set(now);
                }
                // A cut supersedes the material this session
                // walked for every scope root it re-keyed.
                let mut walked = walked_read_epochs.borrow_mut();
                for node in &swept.rekeyed {
                    walked.remove(node);
                }
                drop(walked);
                if let Some(EngineError::TrustViolation { message }) = swept.failure {
                    let _ = events.unbounded_send(Event::AttributableAbuse {
                        description: message,
                    });
                }
            }
        }
        repost_held_claims(
            api.as_ref(),
            staging,
            entropy,
            &enc_subkey,
            received_shares_lock,
            ENVELOPE_V,
            scheduler.now(),
        )
        .await;
        ReceivedShareStatus {
            transport,
            gateway,
            http,
            floors,
            enc_secret: &enc_subkey,
            contact_label_seed: &contact_label_seed,
            list_lock: received_shares_lock,
            mode,
        }
        .refresh(
            staging,
            entropy,
            received_verdicts,
            &ScopeRender {
                base,
                read_seeds: scope_read_seeds,
                write_seeds: scope_write_seeds,
                own_root: &root_id,
                own_descendants: descendant_roots,
                grafted_sharers,
                scope_roots: bookmarked_scope_roots,
                permissions: bookmarked_permissions,
                claims: grafted_claims,
                events,
            },
            now,
            profile,
        )
        .await;
        let mut status = sync_status.borrow_mut();
        status.reconcile_in_flight = false;
        if reconciled {
            status.last_success = Some(scheduler.now());
            // Set after the drain above, so the pass that converges
            // the base is never the pass that decides against it.
            converged_tick.set(true);
        }
        let rung = classify(
            scheduler.now(),
            status.last_success,
            status.reconcile_in_flight,
            Connectivity::Online,
            profile,
        );
        if status.reported != Some(rung) {
            status.reported = Some(rung);
            let _ = events.unbounded_send(Event::StalenessChanged { level: rung });
        }
        drop(status);
        TickControl::Continue
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
