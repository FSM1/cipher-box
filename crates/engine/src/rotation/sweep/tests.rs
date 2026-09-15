use super::sim::{FakeNet, id, name, node_ref, scope_ref};
use super::*;
use crate::profile::SyncTimingProfile;
use crate::seams::BoxedTask;
use crate::seams::UnixMillis;
use crate::testkit::fakes::VirtualScheduler;
use crate::testkit::{block_on, poll_tasks_until_parked};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

fn run(net: &FakeNet, root: u8) -> Result<SweepOutcome, SweepError> {
    block_on(sweep_pass(net, net, &scope_ref(root)))
}

// --- The epoch-lag predicate over interior nodes ---

#[test]
fn an_interior_node_behind_the_scope_epoch_is_resealed_to_it() {
    // scope root (epoch 5) -> A(01)@1 -> B(02)@1. Both interior nodes lag.
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[0x02])
        .node(0x02, 1, &[]);

    let outcome = run(&net, 0x00).expect("sweep");
    assert_eq!(outcome.converged, vec![id(0x01), id(0x02)]);
    assert_eq!(net.epoch(0x01), 5);
    assert_eq!(net.epoch(0x02), 5, "the walk reached the deeper level");
}

#[test]
fn a_node_already_at_the_scope_epoch_is_never_republished() {
    let net = FakeNet::new(5, &[0x01]).node(0x01, 5, &[]);
    let outcome = run(&net, 0x00).expect("sweep");
    assert_eq!(outcome.already_converged, vec![id(0x01)]);
    assert!(outcome.converged.is_empty());
    assert_eq!(net.publishes(0x01), 0);
}

#[test]
fn a_node_ahead_of_the_scope_epoch_is_never_republished() {
    let net = FakeNet::new(5, &[0x01]).node(0x01, 9, &[]);
    let outcome = run(&net, 0x00).expect("sweep");
    assert_eq!(outcome.already_converged, vec![id(0x01)]);
    assert_eq!(net.publishes(0x01), 0);
}

#[test]
fn rerunning_the_pass_is_an_idempotent_noop() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[0x02])
        .node(0x02, 1, &[]);
    let first = run(&net, 0x00).expect("first");
    assert_eq!(first.converged.len(), 2);

    let second = run(&net, 0x00).expect("second");
    assert!(second.converged.is_empty(), "nothing left to converge");
    assert_eq!(second.already_converged, vec![id(0x01), id(0x02)]);
    assert_eq!((net.publishes(0x01), net.publishes(0x02)), (1, 1));
}

#[test]
fn a_second_concurrent_sweeper_republishes_nothing() {
    let net = FakeNet::new(7, &[0x01])
        .node(0x01, 3, &[0x02])
        .node(0x02, 3, &[]);
    run(&net, 0x00).expect("sweeper 1");
    let counts = (net.publishes(0x01), net.publishes(0x02));

    let second = run(&net, 0x00).expect("sweeper 2");
    assert!(second.converged.is_empty());
    assert_eq!((net.publishes(0x01), net.publishes(0x02)), counts);
}

#[test]
fn the_publish_order_is_independent_of_the_bodys_child_order() {
    let converged = |order: &[u8]| {
        let net = FakeNet::new(5, order)
            .node(0x01, 1, &[])
            .node(0x02, 1, &[])
            .node(0x03, 1, &[]);
        run(&net, 0x00).expect("sweep").converged
    };
    assert_eq!(
        converged(&[0x03, 0x01, 0x02]),
        converged(&[0x01, 0x02, 0x03]),
    );
    assert_eq!(
        converged(&[0x03, 0x01, 0x02]),
        vec![id(0x01), id(0x02), id(0x03)],
    );
}

#[test]
fn a_cyclic_child_edge_terminates() {
    // A names B, B names A: a corrupt back-edge the walk must not follow.
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[0x02])
        .node(0x02, 1, &[0x01]);
    let outcome = run(&net, 0x00).expect("sweep");
    assert_eq!(outcome.converged, vec![id(0x01), id(0x02)]);
}

// --- The scope-root boundary ---

#[test]
fn the_walk_stops_at_a_descendant_scope_root_and_never_sweeps_it() {
    // The scope root names an interior node A(01) and a descendant scope
    // root S(0a) whose own subtree holds a lagging node D(0d). Neither S nor
    // anything below it is swept — that is the cascade's population.
    let net = FakeNet::new(5, &[0x01, 0x0a])
        .node(0x01, 1, &[])
        .scope_root(0x0a, true)
        .node(0x0d, 1, &[]);

    let outcome = run(&net, 0x00).expect("sweep");
    assert_eq!(outcome.converged, vec![id(0x01)], "only the interior node");
    assert_eq!(outcome.skipped_scope_roots, vec![id(0x0a)]);
    assert_eq!(net.publishes(0x0a), 0, "a scope root is never swept");
    assert_eq!(net.publishes(0x0d), 0, "nor is anything below it");
    assert_eq!(net.epoch(0x0d), 1, "the descendant scope kept its epoch");
}

#[test]
fn an_indexed_scope_root_is_not_resolved_as_an_interior_node() {
    // The index names S(0a), so the walk stops without a child resolve —
    // even though S's record would otherwise resolve as a scope root.
    let net = FakeNet::new(5, &[0x0a]).scope_root(0x0a, true);
    let outcome = run(&net, 0x00).expect("sweep");
    assert_eq!(outcome.skipped_scope_roots, vec![id(0x0a)]);
    assert!(
        outcome.flagged_indexes.is_empty(),
        "the index already names it"
    );
    assert_eq!(net.index_repairs.get(), 0);
}

// --- The direct-child-scope index self-heal (#38 D6) ---

#[test]
fn an_omitted_scope_root_is_repaired_and_flagged_with_no_node_resealed() {
    // S(0a) is a scope root the walk meets, absent from the index. Every
    // interior node is already at the scope epoch, so the repair lands with
    // nothing re-sealed — the self-heal no longer rides the epoch comparison.
    let net = FakeNet::new(5, &[0x01, 0x0a])
        .node(0x01, 5, &[])
        .scope_root(0x0a, false);

    let outcome = run(&net, 0x00).expect("sweep");
    assert_eq!(outcome.flagged_indexes, vec![id(0x0a)]);
    assert!(
        outcome.converged.is_empty(),
        "no node was re-sealed in the repairing pass"
    );
    assert_eq!(net.index_repairs.get(), 1);
    let repaired = net.state.borrow().repaired_index.clone().expect("repaired");
    assert_eq!(repaired, vec![scope_ref(0x0a)]);
}

#[test]
fn a_non_canonical_index_is_republished_canonical_with_nothing_omitted() {
    // The other half of the #38 D6 invariant: crash residue in the stored
    // index is repaired on the walk result too, with no scope root missing.
    let net = FakeNet::new(5, &[0x0a])
        .scope_root(0x0a, true)
        .duplicate_index_entry(0x0a);

    let outcome = run(&net, 0x00).expect("sweep");
    assert!(
        outcome.flagged_indexes.is_empty(),
        "no scope root was missing, so none is flagged"
    );
    assert_eq!(net.index_repairs.get(), 1);
    assert_eq!(
        net.state.borrow().repaired_index.clone().expect("repaired"),
        vec![scope_ref(0x0a)],
        "the duplicate is dropped"
    );
}

#[test]
fn a_repaired_index_is_not_flagged_again_on_the_next_pass() {
    let net = FakeNet::new(5, &[0x0a]).scope_root(0x0a, false);
    assert_eq!(run(&net, 0x00).expect("first").flagged_indexes.len(), 1);
    let again = run(&net, 0x00).expect("second");
    assert!(again.flagged_indexes.is_empty());
    assert_eq!(net.index_repairs.get(), 1, "no redundant republish");
}

#[test]
fn an_index_repair_that_lost_the_cas_is_not_flagged() {
    let net = FakeNet::new(5, &[0x0a]).scope_root(0x0a, false);
    net.state.borrow_mut().index_repair_fault = Some(RotationPublishError::LostRace);

    let outcome = run(&net, 0x00).expect("sweep");
    assert!(
        outcome.flagged_indexes.is_empty(),
        "a repair that never landed must not be reported"
    );
    assert_eq!(outcome.skipped_scope_roots, vec![id(0x0a)]);
}

#[test]
fn an_index_repair_that_did_not_land_fails_closed() {
    let net = FakeNet::new(5, &[0x0a]).scope_root(0x0a, false);
    net.state.borrow_mut().index_repair_fault = Some(RotationPublishError::NotPublished);

    let err = run(&net, 0x00).expect_err("fails closed");
    assert_eq!(err.check(), "index-repair-failed");
    assert!(err.is_retryable());
}

#[test]
fn the_index_repair_lands_before_a_node_publish_can_abort_the_pass() {
    // A(01) lags and can never publish; the repair still landed, because the
    // self-heal runs on the walk result rather than behind a re-seal.
    let net = FakeNet::new(5, &[0x01, 0x0a])
        .node(0x01, 1, &[])
        .scope_root(0x0a, false)
        .fault(0x01, RotationPublishError::NotPublished);

    let err = run(&net, 0x00).expect_err("the node publish aborts");
    assert_eq!(err.check(), "publish-failed");
    assert_eq!(net.index_repairs.get(), 1);
    assert!(net.state.borrow().repaired_index.is_some());
}

// --- The superseded verdict and the pointer consult (ADR 0003 D2) ---

#[test]
fn a_below_floor_scope_root_converges_after_the_pointer_consult() {
    // The scope root is asked at a name a write rotation has moved off: its
    // record is below the floor. The pointer re-points to the fresh name,
    // where the scope resolves and its lagging node converges.
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .superseded(0x00)
        .pointer_to(0x09);

    let outcome = run(&net, 0x00).expect("the consult converges the scope");
    assert_eq!(net.consults.get(), 1);
    assert_eq!(outcome.converged, vec![id(0x01)]);
}

#[test]
fn a_below_floor_scope_root_whose_fresh_record_still_lags_is_refused() {
    // The re-pointed record is below the floor too: fail closed, and never
    // consult a second time.
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .superseded(0x00)
        .superseded(0x09)
        .pointer_to(0x09);

    let err = run(&net, 0x00).expect_err("fails closed");
    assert_eq!(err.check(), "scope-root-unresolved");
    assert!(!err.is_retryable(), "a surviving supersede is fatal");
    assert_eq!(net.consults.get(), 1, "one consult, one re-resolve");
    assert_eq!(net.publishes(0x01), 0);
}

#[test]
fn a_below_floor_scope_root_with_no_pointer_is_refused() {
    let net = FakeNet::new(5, &[0x01]).node(0x01, 1, &[]).superseded(0x00);
    let err = run(&net, 0x00).expect_err("fails closed");
    assert!(matches!(
        err,
        SweepError::Scope {
            reason: SweepResolveFailure::Superseded,
            ..
        }
    ));
}

#[test]
fn a_forged_scope_root_is_refused_without_any_consult() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .forged(0x00)
        .pointer_to(0x09);
    let err = run(&net, 0x00).expect_err("fails closed");
    assert_eq!(err.check(), "scope-root-unresolved");
    assert!(!err.is_retryable());
    assert_eq!(net.consults.get(), 0, "a trust rejection never consults");
}

#[test]
fn a_consult_that_re_points_at_a_forged_record_is_refused() {
    // The consult cannot launder a forgery: the re-pointed record still
    // faces the gate.
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .superseded(0x00)
        .forged(0x09)
        .pointer_to(0x09);
    let err = run(&net, 0x00).expect_err("fails closed");
    assert!(matches!(
        err,
        SweepError::Scope {
            reason: SweepResolveFailure::Rejected,
            ..
        }
    ));
    assert_eq!(net.publishes(0x01), 0);
}

#[test]
fn an_encountered_scope_root_below_its_floor_is_repaired_at_the_repointed_name() {
    // S(0a) is missing from the index and its indexed-at name is stale. Only
    // the name the walk resolved current may be written into the index.
    let net = FakeNet::new(5, &[0x0a])
        .scope_root(0x0a, false)
        .superseded(0x0a)
        .pointer_to(0x0b);

    let outcome = run(&net, 0x00).expect("sweep");
    assert_eq!(outcome.flagged_indexes, vec![id(0x0a)]);
    let repaired = net.state.borrow().repaired_index.clone().expect("repaired");
    assert_eq!(
        repaired,
        vec![ChildScopeRef::new(id(0x0a), name(0x0b))],
        "the repair persists the re-pointed name, never the superseded one"
    );
}

// --- Nodes this pass cannot read ---

/// One node no seed opens, one a revoked writer's record fails the gate on,
/// one no fetch answers for, one a newer build wrote. The unit of progress
/// is a single interior node, so each is surfaced and stepped past rather
/// than costing every other node in the scope its convergence.
#[test]
fn an_unreadable_node_is_isolated_and_the_rest_still_converges() {
    for reason in [
        SweepResolveFailure::Unreadable,
        SweepResolveFailure::Rejected,
        SweepResolveFailure::Unavailable,
        SweepResolveFailure::VersionSkew,
    ] {
        let net = FakeNet::new(5, &[0x01, 0x02])
            .node(0x01, 1, &[])
            .node(0x02, 1, &[])
            .node_fault(0x01, reason);

        let outcome = run(&net, 0x00).expect("the pass completes");
        assert_eq!(outcome.unreachable, vec![(id(0x01), reason)]);
        assert_eq!(outcome.converged, vec![id(0x02)], "{reason}");
        assert_eq!(net.publishes(0x01), 0, "nothing to re-seal it from");
    }
}

#[test]
fn an_unreadable_nodes_subtree_is_not_walked() {
    // Its body is what named its children, so an unreadable node hides them.
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[0x02])
        .node(0x02, 1, &[])
        .node_fault(0x01, SweepResolveFailure::Unreadable);

    let outcome = run(&net, 0x00).expect("the pass completes");
    assert_eq!(
        outcome.unreachable,
        vec![(id(0x01), SweepResolveFailure::Unreadable)]
    );
    assert!(outcome.converged.is_empty());
    assert!(outcome.already_converged.is_empty());
}

// --- One node id, one name ---

#[test]
fn two_parents_naming_one_node_differently_abort_fail_closed() {
    // C2: converging the name we picked would leave the other live at the
    // old epoch — a hole no outcome bucket could describe.
    let net = FakeNet::new(5, &[0x01, 0x02])
        .node(0x01, 5, &[0x05])
        .node(0x02, 5, &[0x05])
        .node(0x05, 1, &[])
        .names_child(0x02, 0x05, "via-b");

    let err = run(&net, 0x00).expect_err("the conflict aborts");
    assert!(matches!(
        err,
        SweepError::Node {
            node_id,
            reason: SweepResolveFailure::ConflictingChildLabel,
        } if node_id == id(0x05)
    ));
    assert!(err.is_retryable(), "the re-point wave repairs both parents");
    assert_eq!(net.publishes(0x05), 0);
}

#[test]
fn two_parents_naming_one_node_identically_is_no_conflict() {
    let net = FakeNet::new(5, &[0x01, 0x02])
        .node(0x01, 5, &[0x05])
        .node(0x02, 5, &[0x05])
        .node(0x05, 1, &[]);
    let outcome = run(&net, 0x00).expect("a legitimate diamond converges");
    assert_eq!(outcome.converged, vec![id(0x05)]);
    assert_eq!(net.publishes(0x05), 1, "the shared node published once");
}

// --- Converging one subtree rather than the whole scope ---

#[test]
fn converge_subtree_walks_only_the_named_node_and_below() {
    // A(01) holds the subtree; B(02) lags elsewhere in the same scope and
    // must be left alone.
    let net = FakeNet::new(5, &[0x01, 0x02])
        .node(0x01, 5, &[0x03])
        .node(0x02, 1, &[])
        .node(0x03, 1, &[]);

    let outcome = block_on(converge_subtree(
        &net,
        &net,
        &scope_ref(0x00),
        block_on(net.resolve_scope(&scope_ref(0x00))).expect("the scope resolves"),
        &node_ref(0x01),
    ))
    .expect("the subtree converges");
    assert_eq!(outcome.converged, vec![id(0x03)]);
    assert_eq!(outcome.already_converged, vec![id(0x01)]);
    assert_eq!(net.publishes(0x02), 0, "a sibling subtree is untouched");
    assert_eq!(net.epoch(0x02), 1);
}

#[test]
fn converge_subtree_measures_the_named_node_itself() {
    let net = FakeNet::new(5, &[0x01]).node(0x01, 1, &[]);
    let outcome = block_on(converge_subtree(
        &net,
        &net,
        &scope_ref(0x00),
        block_on(net.resolve_scope(&scope_ref(0x00))).expect("the scope resolves"),
        &node_ref(0x01),
    ))
    .expect("converges");
    assert_eq!(outcome.converged, vec![id(0x01)]);
}

// --- Fail-closed completeness ---

/// Isolating a node must not cost the driver its retry: an availability
/// stall is the one isolated verdict another pass can still clear, so
/// `run_sweep` spends its budget on it rather than reporting a first-pass
/// `Ok` over a node it simply could not fetch.
#[test]
fn an_isolated_availability_stall_still_spends_the_drivers_passes() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .node_fault(0x01, SweepResolveFailure::Unavailable);
    let outcome = drive(&net, 3, 2).expect("the residual is surfaced, not an error");
    assert_eq!(
        outcome.unreachable,
        vec![(id(0x01), SweepResolveFailure::Unavailable)]
    );
}

/// A settled verdict is not worth another pass — no retry re-opens a node no
/// seed reaches, a record the gate refused, or a record at a version this
/// build cannot author — so the driver returns on the first pass with the
/// node surfaced.
#[test]
fn a_settled_isolation_does_not_spend_the_drivers_passes() {
    for reason in [
        SweepResolveFailure::Unreadable,
        SweepResolveFailure::Rejected,
        SweepResolveFailure::VersionSkew,
    ] {
        let net = FakeNet::new(5, &[0x01])
            .node(0x01, 1, &[])
            .node_fault(0x01, reason);
        let outcome = drive(&net, 3, 0).expect("the pass completes");
        assert_eq!(outcome.unreachable, vec![(id(0x01), reason)]);
    }
}

#[test]
fn a_node_that_did_not_publish_aborts_rather_than_claiming_convergence() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .fault(0x01, RotationPublishError::NotPublished);
    let err = run(&net, 0x00).expect_err("fails closed");
    assert!(matches!(err, SweepError::Publish { node_id, .. } if node_id == id(0x01)));
    assert!(err.is_retryable());
}

#[test]
fn a_publish_the_publisher_refused_is_never_retried() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .fault(0x01, RotationPublishError::Rejected);
    let err = run(&net, 0x00).expect_err("fails closed");
    assert!(!err.is_retryable(), "a trust rejection is fatal");
}

#[test]
fn a_partial_pass_resumes_without_stranding_a_node() {
    let net = FakeNet::new(5, &[0x01, 0x02])
        .node(0x01, 1, &[])
        .node(0x02, 1, &[])
        .fault(0x02, RotationPublishError::NotPublished);
    run(&net, 0x00).expect_err("aborts on B");
    assert_eq!(net.epoch(0x01), 5, "A converged before the abort");
    assert_eq!(net.epoch(0x02), 1);

    net.clear_fault(0x02);
    let outcome = run(&net, 0x00).expect("resume");
    assert_eq!(outcome.converged, vec![id(0x02)]);
    assert_eq!(outcome.already_converged, vec![id(0x01)]);
}

#[test]
fn a_lost_cas_race_drops_the_node_and_the_rest_still_converges() {
    let net = FakeNet::new(5, &[0x01, 0x02])
        .node(0x01, 1, &[])
        .node(0x02, 1, &[])
        .fault(0x01, RotationPublishError::LostRace);
    let outcome = run(&net, 0x00).expect("sweep");
    assert_eq!(outcome.dropped_lost_race, vec![id(0x01)]);
    assert_eq!(outcome.converged, vec![id(0x02)]);
}

// --- The idle-cadence driver ---

/// Drive the pass on a virtual clock, asserting that every re-run cost one
/// cadence sleep — time enters only through the scheduler seam.
fn drive(net: &FakeNet, max_passes: u32, expected_sleeps: u32) -> Result<SweepOutcome, SweepError> {
    drive_while(net, max_passes, expected_sleeps, &|| true)
}

/// [`drive`] under a caller-supplied liveness answer.
fn drive_while(
    net: &FakeNet,
    max_passes: u32,
    expected_sleeps: u32,
    still_running: &dyn Fn() -> bool,
) -> Result<SweepOutcome, SweepError> {
    let scheduler = VirtualScheduler::new().with_auto_advance();
    let result = block_on(run_sweep(
        &scheduler,
        net,
        net,
        &scope_ref(0x00),
        Duration::from_secs(30),
        max_passes,
        still_running,
    ));
    assert_eq!(
        scheduler.now(),
        UnixMillis(u64::from(expected_sleeps) * 30_000),
        "one cadence sleep per re-run",
    );
    result
}

#[test]
fn the_driver_loops_past_a_non_advancing_lost_race_until_it_wins() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .lost_race_next(0x01, 2);
    let outcome = drive(&net, 5, 2).expect("converges after two lost races");
    assert_eq!(outcome.converged, vec![id(0x01)]);
    assert!(outcome.dropped_lost_race.is_empty());
    assert_eq!(
        net.publishes(0x01),
        3,
        "two lost races, one winning publish"
    );
    assert_eq!(net.epoch(0x01), 5);
}

#[test]
fn the_driver_surfaces_a_residual_drop_on_cap_exhaustion() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .lost_race_next(0x01, 10);
    let outcome = drive(&net, 3, 2).expect("returns Ok with the residual surfaced");
    assert_eq!(outcome.dropped_lost_race, vec![id(0x01)]);
    assert!(outcome.converged.is_empty());
    assert_eq!(net.publishes(0x01), 3);
}

#[test]
fn the_driver_gives_up_on_a_persistent_availability_stall() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .fault(0x01, RotationPublishError::NotPublished);
    let err = drive(&net, 3, 2).expect_err("the stall surfaces");
    assert_eq!(err.check(), "publish-failed");
    assert_eq!(net.publishes(0x01), 3, "one attempt per allowed pass");
}

/// The wave belongs to the session that spawned it: once that session is
/// gone the driver stops at the next pass boundary, surfacing what the pass
/// it had already started produced rather than sweeping on.
#[test]
fn an_ended_session_stops_the_driver_at_the_next_pass_boundary() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .lost_race_next(0x01, 2);
    let outcome = drive_while(&net, 5, 0, &|| false).expect("the started pass still settles");
    assert_eq!(
        outcome.dropped_lost_race,
        vec![id(0x01)],
        "the pass in flight is absorbed, not discarded"
    );
    assert!(
        outcome.converged.is_empty(),
        "and the retry that would have won it never ran"
    );
    assert_eq!(
        net.publishes(0x01),
        1,
        "one pass, not the five the cap allows"
    );
}

/// The same boundary bounds the retry arm: an availability stall a live
/// session would re-drive is surfaced instead once the session has ended.
#[test]
fn an_ended_session_stops_the_drivers_retry_of_a_stall() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .fault(0x01, RotationPublishError::NotPublished);
    let err = drive_while(&net, 3, 0, &|| false).expect_err("the stall surfaces");
    assert_eq!(err.check(), "publish-failed");
    assert_eq!(net.publishes(0x01), 1, "the stall was not re-driven");
}

#[test]
fn the_driver_returns_a_trust_failure_immediately() {
    let net = FakeNet::new(5, &[0x01]).node(0x01, 1, &[]).forged(0x00);
    let err = drive(&net, 5, 0).expect_err("fatal");
    assert!(!err.is_retryable());
}

// --- Aggregating the driver's per-pass buckets ---

/// The host's only notice of an index self-heal is `flagged_indexes`, and a
/// pass that re-derives an already-repaired index flags nothing. A sibling
/// forcing a re-run must therefore not erase the flag an earlier pass earned.
#[test]
fn an_index_flag_from_an_early_pass_survives_a_later_one() {
    let net = FakeNet::new(5, &[0x01, 0x0a])
        .node(0x01, 1, &[])
        .scope_root(0x0a, false)
        .lost_race_next(0x01, 1);

    let outcome = drive(&net, 3, 1).expect("the driver converges on the second pass");
    assert_eq!(
        outcome.flagged_indexes,
        vec![id(0x0a)],
        "the pass-1 repair is still reported after the pass-2 re-run"
    );
    assert_eq!(net.index_repairs.get(), 1, "the repair itself ran once");
    assert_eq!(outcome.converged, vec![id(0x01)]);
    assert!(outcome.dropped_lost_race.is_empty());
}

/// A node the driver re-sealed did need work, however the final pass reads
/// it — reporting it as `already_converged` would claim the opposite.
#[test]
fn a_node_the_driver_resealed_is_never_reported_as_needing_no_work() {
    let net = FakeNet::new(5, &[0x01, 0x02])
        .node(0x01, 1, &[])
        .node(0x02, 1, &[])
        .lost_race_next(0x02, 1);

    let outcome = drive(&net, 3, 1).expect("converges");
    assert_eq!(outcome.converged, vec![id(0x01), id(0x02)]);
    assert!(
        outcome.already_converged.is_empty(),
        "both nodes lagged; neither is a no-op"
    );
}

/// A node a concurrent mint promotes to a descendant scope root between
/// passes belongs to the cascade now, not to this sweep. Leaving it in
/// `converged` too would let a host read it as swept interior state and skip
/// the cascade rotation — a revokee keeping a live seed.
#[test]
fn a_node_converged_early_then_minted_a_scope_root_is_reported_skipped_only() {
    let net = FakeNet::new(5, &[0x01, 0x02])
        .node(0x01, 1, &[])
        .node(0x02, 1, &[])
        .becomes_scope_root_after(0x01, 1)
        .lost_race_next(0x02, 1);

    let outcome = drive(&net, 3, 1).expect("converges on the second pass");

    assert_eq!(outcome.skipped_scope_roots, vec![id(0x01)]);
    assert_eq!(
        outcome.converged,
        vec![id(0x02)],
        "the final pass's verdict is the one that holds"
    );
    assert_eq!(
        outcome.flagged_indexes,
        vec![id(0x01)],
        "the index self-heal is a separate axis, not a competing bucket"
    );
}

/// `SweepOutcome` promises every node it reached in exactly one bucket. The
/// union must therefore yield to the final pass: a node an early pass
/// re-sealed but the final one cannot read is unreachable *now*, and
/// reporting it as converged too would contradict the residual a caller
/// proving convergence refuses on.
#[test]
fn a_node_converged_early_then_unreachable_late_is_reported_unreachable_only() {
    let net = FakeNet::new(5, &[0x01, 0x02])
        .node(0x01, 1, &[])
        .node(0x02, 1, &[])
        .node_fault_after(0x01, 1, SweepResolveFailure::Unavailable)
        .lost_race_next(0x02, 1);

    let outcome = drive(&net, 3, 2).expect("the residual is surfaced, not an error");

    assert_eq!(
        outcome.unreachable,
        vec![(id(0x01), SweepResolveFailure::Unavailable)]
    );
    assert!(
        !outcome.converged.contains(&id(0x01)),
        "the final pass's verdict is the one that holds"
    );
    assert_eq!(outcome.converged, vec![id(0x02)]);
}

// --- The idle-cadence Scheduler job (blueprint/engine.md "sweep") ---

/// The scopes and results a host would observe from the job, which has no
/// caller to read a return value.
type Reported = Rc<RefCell<Vec<([u8; 16], Result<SweepOutcome, SweepError>)>>>;

/// A round source that names `net`'s one scope `rounds` times, then stops.
fn rounds(count: usize) -> impl AsyncFnMut() -> Option<Vec<ChildScopeRef>> {
    let remaining = Cell::new(count);
    move || {
        let left = remaining.get();
        remaining.set(left.saturating_sub(1));
        async move { (left > 0).then(|| vec![scope_ref(0x00)]) }
    }
}

/// Run the job over `net`'s one scope for `count` rounds on an
/// auto-advancing clock, then stop it.
fn job(net: &FakeNet, count: usize, cadence: Duration) -> (Reported, VirtualScheduler) {
    let scheduler = VirtualScheduler::new().with_auto_advance();
    let seen: Reported = Reported::default();
    block_on(run_sweep_job(
        &scheduler,
        net,
        net,
        cadence,
        rounds(count),
        |scope: &ChildScopeRef, result: &Result<SweepOutcome, SweepError>| {
            seen.borrow_mut().push((scope.scope_id, result.clone()));
        },
    ));
    (seen, scheduler)
}

fn swept(seen: &Reported, round: usize) -> SweepOutcome {
    seen.borrow()[round].1.clone().expect("swept")
}

#[test]
fn an_idle_scope_converges_with_no_user_write() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[0x02])
        .node(0x02, 1, &[]);

    let (seen, _) = job(&net, 1, Duration::from_secs(30));

    assert_eq!(net.epoch(0x01), 5);
    assert_eq!(net.epoch(0x02), 5, "the wave reached the deeper level");
    assert_eq!(
        seen.borrow()[0].0,
        id(0x00),
        "the result is filed under the scope it swept"
    );
    assert_eq!(swept(&seen, 0).converged, vec![id(0x01), id(0x02)]);
}

#[test]
fn a_second_round_over_a_converged_scope_republishes_nothing() {
    let net = FakeNet::new(5, &[0x01]).node(0x01, 1, &[]);
    let (seen, _) = job(&net, 2, Duration::from_secs(30));

    assert_eq!(swept(&seen, 0).converged, vec![id(0x01)]);
    let second = swept(&seen, 1);
    assert!(second.converged.is_empty(), "nothing left to converge");
    assert_eq!(second.already_converged, vec![id(0x01)]);
    assert_eq!(net.publishes(0x01), 1, "no republish, no sequence bump");
}

/// Time enters the job only through the [`Scheduler`] seam, and the interval
/// is the injected profile's — never a constant in the job body.
#[test]
fn the_cadence_comes_from_the_injected_timing_profile() {
    for profile in [SyncTimingProfile::CI, SyncTimingProfile::PRODUCTION] {
        let net = FakeNet::new(5, &[0x01]).node(0x01, 1, &[]);
        let (_, scheduler) = job(&net, 2, profile.sweep_cadence);
        assert_eq!(
            scheduler.now(),
            UnixMillis(0).saturating_add(profile.sweep_cadence * 3),
            "one idle per round, plus the idle before the round that stops"
        );
    }
}

/// One contested scope must not stall the wave over every other, so the
/// round spends a single pass per scope and lets the next round retry.
#[test]
fn a_contested_scope_costs_one_pass_and_is_retried_by_the_next_round() {
    let net = FakeNet::new(5, &[0x01])
        .node(0x01, 1, &[])
        .lost_race_next(0x01, 1);

    let (seen, scheduler) = job(&net, 2, Duration::from_secs(30));

    assert_eq!(swept(&seen, 0).dropped_lost_race, vec![id(0x01)]);
    assert_eq!(swept(&seen, 1).converged, vec![id(0x01)]);
    assert_eq!(
        scheduler.now(),
        UnixMillis(90_000),
        "three idles, and no extra in-round retry sleep"
    );
}

#[test]
fn the_job_reports_a_failure_to_the_host_and_keeps_running() {
    let net = FakeNet::new(5, &[0x01]).node(0x01, 1, &[]).forged(0x00);
    let (seen, _) = job(&net, 2, Duration::from_secs(30));

    let seen = seen.borrow();
    assert_eq!(seen.len(), 2, "a failed round does not end the job");
    assert!(
        seen.iter().all(|(_, result)| matches!(
            result,
            Err(SweepError::Scope {
                reason: SweepResolveFailure::Rejected,
                ..
            })
        )),
        "the trust rejection reaches the host rather than a silent skip"
    );
}

#[test]
fn the_job_ends_when_a_round_names_no_scopes() {
    let net = FakeNet::new(5, &[0x01]).node(0x01, 1, &[]);
    let (seen, _) = job(&net, 0, Duration::from_secs(30));
    assert!(seen.borrow().is_empty());
}

/// The job idles before it sweeps, at the profile's coarser
/// `sweep_cadence`, so a whole focus-window poll cadence can elapse with the
/// job still parked — background hygiene never pre-empts interactive work.
#[test]
fn the_job_parks_across_a_focus_window_poll_tick() {
    let profile = SyncTimingProfile::CI;
    let scheduler = VirtualScheduler::new();
    let net = FakeNet::new(5, &[0x01]).node(0x01, 1, &[]);

    let mut tasks: Vec<BoxedTask> = vec![Box::pin({
        let scheduler = scheduler.clone();
        let net = net.clone();
        async move {
            run_sweep_job(
                &scheduler,
                &net,
                &net,
                profile.sweep_cadence,
                rounds(1),
                |_: &ChildScopeRef, _: &Result<SweepOutcome, SweepError>| {},
            )
            .await;
        }
    })];

    poll_tasks_until_parked(&mut tasks);
    assert_eq!(
        net.publishes(0x01),
        0,
        "the job idles before its first sweep"
    );

    scheduler.advance(profile.poll_cadence);
    poll_tasks_until_parked(&mut tasks);
    assert_eq!(
        net.publishes(0x01),
        0,
        "a poll tick passes, the job is parked"
    );

    scheduler.advance(profile.sweep_cadence - profile.poll_cadence);
    poll_tasks_until_parked(&mut tasks);
    assert_eq!(
        net.publishes(0x01),
        1,
        "the sweep fires at the sweep cadence"
    );
}
