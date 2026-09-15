use super::*;
use crate::testkit::block_on;
use std::cell::Cell;
use std::collections::HashMap;

fn sid(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn child(byte: u8) -> ChildScopeRef {
    ChildScopeRef::new(sid(byte), format!("ipns-{byte:02x}").into_bytes())
}

/// A `ChildScopeRef` with a caller-chosen `ipns_name`, to build a diamond
/// where one `scope_id` is reachable carrying differing `ipns_name` values.
fn child_named(scope_byte: u8, ipns_name: &str) -> ChildScopeRef {
    ChildScopeRef::new(sid(scope_byte), ipns_name.as_bytes().to_vec())
}

/// A fake resolver over a fixed adjacency map, counting resolves so tests can
/// assert each descendant is resolved at most once.
struct FakeResolver {
    adjacency: HashMap<[u8; 16], Result<Vec<ChildScopeRef>, ResolveFailure>>,
    calls: Cell<usize>,
}

impl FakeResolver {
    fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
            calls: Cell::new(0),
        }
    }

    fn with(mut self, parent: u8, children: &[u8]) -> Self {
        self.adjacency.insert(
            sid(parent),
            Ok(children.iter().map(|b| child(*b)).collect()),
        );
        self
    }

    /// Insert a parent whose stored children Vec is in a caller-chosen
    /// (possibly unsorted) order — to prove per-node output order does not
    /// affect the result.
    fn with_refs(mut self, parent: u8, children: Vec<ChildScopeRef>) -> Self {
        self.adjacency.insert(sid(parent), Ok(children));
        self
    }

    fn failing(mut self, parent: u8, reason: ResolveFailure) -> Self {
        self.adjacency.insert(sid(parent), Err(reason));
        self
    }
}

impl ChildIndexResolver for FakeResolver {
    async fn direct_child_index(
        &self,
        child: &ChildScopeRef,
    ) -> Result<Vec<ChildScopeRef>, ResolveFailure> {
        self.calls.set(self.calls.get() + 1);
        // A scope root not in the map is a leaf: no descendants.
        self.adjacency
            .get(&child.scope_id)
            .cloned()
            .unwrap_or_else(|| Ok(Vec::new()))
    }
}

fn ids(set: &EagerSet) -> Vec<[u8; 16]> {
    set.descendants().iter().map(|c| c.scope_id).collect()
}

#[test]
fn completeness_enumerates_multi_level_tree() {
    // root(0x00) -> A(0x01) -> B(0x02) -> C(0x03)
    let resolver = FakeResolver::new().with(0x01, &[0x02]).with(0x02, &[0x03]);
    let set = block_on(enumerate_eager_set(sid(0x00), &[child(0x01)], &resolver))
        .expect("complete tree enumerates");
    assert_eq!(ids(&set), vec![sid(0x01), sid(0x02), sid(0x03)]);
}

#[test]
fn completeness_wide_fanout() {
    let kids: Vec<u8> = (0x01..=0x20).collect();
    let resolver = FakeResolver::new().with(0x00, &kids);
    let root_index: Vec<ChildScopeRef> = kids.iter().map(|b| child(*b)).collect();
    let set = block_on(enumerate_eager_set(sid(0x00), &root_index, &resolver))
        .expect("wide fan-out enumerates");
    assert_eq!(set.len(), kids.len());
    let expected: Vec<[u8; 16]> = kids.iter().map(|b| sid(*b)).collect();
    assert_eq!(ids(&set), expected);
}

#[test]
fn completeness_diamond_shared_descendant_recorded_once() {
    // root -> A, B; both A and B -> D. D must appear exactly once and be
    // resolved exactly once.
    let resolver = FakeResolver::new().with(0x01, &[0x04]).with(0x02, &[0x04]);
    let set = block_on(enumerate_eager_set(
        sid(0x00),
        &[child(0x01), child(0x02)],
        &resolver,
    ))
    .expect("diamond enumerates");
    assert_eq!(ids(&set), vec![sid(0x01), sid(0x02), sid(0x04)]);
    // root not resolved (caller-held); A, B, D each resolved once.
    assert_eq!(resolver.calls.get(), 3, "shared descendant resolved once");
}

#[test]
fn cycle_back_edge_terminates() {
    // A -> B -> A (a corrupt/adversarial back-edge). Must terminate.
    let resolver = FakeResolver::new().with(0x01, &[0x02]).with(0x02, &[0x01]);
    let set = block_on(enumerate_eager_set(sid(0x00), &[child(0x01)], &resolver))
        .expect("cyclic index terminates");
    assert_eq!(ids(&set), vec![sid(0x01), sid(0x02)]);
}

#[test]
fn self_loop_terminates() {
    // A lists itself as its own child.
    let resolver = FakeResolver::new().with(0x01, &[0x01]);
    let set = block_on(enumerate_eager_set(sid(0x00), &[child(0x01)], &resolver))
        .expect("self-loop terminates");
    assert_eq!(ids(&set), vec![sid(0x01)]);
}

#[test]
fn back_edge_to_root_is_ignored_root_excluded() {
    // A -> root(0x00). The root is never a descendant of itself.
    let resolver = FakeResolver::new().with(0x01, &[0x00]);
    let set = block_on(enumerate_eager_set(sid(0x00), &[child(0x01)], &resolver))
        .expect("back-edge to root terminates");
    assert_eq!(ids(&set), vec![sid(0x01)]);
}

#[test]
fn empty_root_index_yields_empty_set() {
    let resolver = FakeResolver::new();
    let set = block_on(enumerate_eager_set(sid(0x00), &[], &resolver))
        .expect("leaf root enumerates empty");
    assert!(set.is_empty());
    assert_eq!(resolver.calls.get(), 0, "no descendants to resolve");
}

#[test]
fn determinism_order_is_scope_id_ascending() {
    // Feed the root index out of order; output must be ascending by scope_id.
    let resolver = FakeResolver::new();
    let set = block_on(enumerate_eager_set(
        sid(0x00),
        &[child(0x05), child(0x01), child(0x03)],
        &resolver,
    ))
    .expect("enumerates");
    assert_eq!(ids(&set), vec![sid(0x01), sid(0x03), sid(0x05)]);
}

#[test]
fn determinism_permutation_independent_output() {
    // Same tree, two different input orderings of both the root index and a
    // parent's returned children -> byte-identical eager sets.
    let tree = |root_index: Vec<ChildScopeRef>, a_children: Vec<ChildScopeRef>| {
        let resolver = FakeResolver::new()
            .with_refs(0x01, a_children)
            .with(0x02, &[0x06]);
        block_on(enumerate_eager_set(sid(0x00), &root_index, &resolver)).expect("enumerates")
    };
    let one = tree(
        vec![child(0x01), child(0x02)],
        vec![child(0x05), child(0x04)],
    );
    let two = tree(
        vec![child(0x02), child(0x01)],
        vec![child(0x04), child(0x05)],
    );
    assert_eq!(one, two, "output is permutation-independent");
    assert_eq!(
        ids(&one),
        vec![sid(0x01), sid(0x02), sid(0x04), sid(0x05), sid(0x06)]
    );
}

#[test]
fn c2_conflicting_ipns_name_aborts_fail_closed_permutation_independent() {
    // C2: root -> A(0x01), B(0x02); both parents list the same
    // descendant scope D(0x04) but carry DIFFERING ipns_name values. A
    // ChildScopeRef has no ordering signal, so first-seen would be a coin-flip
    // and picking the stale name is a silent revocation hole — the walk aborts
    // fail-closed naming D, identically under forward and reversed parent order.
    let build = |root_index: Vec<ChildScopeRef>| {
        let resolver = FakeResolver::new()
            .with_refs(0x01, vec![child_named(0x04, "via-a")])
            .with_refs(0x02, vec![child_named(0x04, "via-b")]);
        block_on(enumerate_eager_set(sid(0x00), &root_index, &resolver))
    };

    let forward = build(vec![child(0x01), child(0x02)]).expect_err("conflict aborts");
    let reversed = build(vec![child(0x02), child(0x01)]).expect_err("conflict aborts");

    assert_eq!(forward, reversed, "abort is permutation-independent");
    assert_eq!(forward.scope_id, sid(0x04), "the conflict names scope D");
    assert_eq!(forward.reason, ResolveFailure::ConflictingChildLabel);
}

#[test]
fn diamond_same_scope_and_ipns_name_resolves_once_no_abort() {
    // Regression (test E): a legitimate diamond — both parents list D(0x04) with
    // the SAME ipns_name — resolves D exactly once with no conflict abort.
    let build = |root_index: Vec<ChildScopeRef>| {
        let resolver = FakeResolver::new()
            .with_refs(0x01, vec![child_named(0x04, "via-shared")])
            .with_refs(0x02, vec![child_named(0x04, "via-shared")]);
        block_on(enumerate_eager_set(sid(0x00), &root_index, &resolver)).expect("enumerates")
    };
    let forward = build(vec![child(0x01), child(0x02)]);
    let reversed = build(vec![child(0x02), child(0x01)]);
    assert_eq!(
        forward, reversed,
        "shared-name diamond is order-independent"
    );
    assert_eq!(ids(&forward), vec![sid(0x01), sid(0x02), sid(0x04)]);
    let d_name = forward
        .descendants()
        .iter()
        .find(|c| c.scope_id == sid(0x04))
        .expect("D present")
        .ipns_name
        .clone();
    assert_eq!(d_name, b"via-shared");
}

#[test]
fn fail_closed_on_rejected_descendant_names_scope_and_reason() {
    // root -> A -> B, but B fails the adoption gate. The walk must abort,
    // naming B, not return {A} (which would silently drop B's subtree).
    let resolver = FakeResolver::new()
        .with(0x01, &[0x02])
        .failing(0x02, ResolveFailure::Rejected);
    let err = block_on(enumerate_eager_set(sid(0x00), &[child(0x01)], &resolver))
        .expect_err("rejected descendant fails closed");
    assert_eq!(err.scope_id, sid(0x02));
    assert_eq!(err.reason, ResolveFailure::Rejected);
}

#[test]
fn fail_closed_on_unavailable_descendant() {
    let resolver = FakeResolver::new().failing(0x01, ResolveFailure::Unavailable);
    let err = block_on(enumerate_eager_set(sid(0x00), &[child(0x01)], &resolver))
        .expect_err("unavailable descendant fails closed");
    assert_eq!(err.scope_id, sid(0x01));
    assert_eq!(err.reason, ResolveFailure::Unavailable);
}

#[test]
fn fail_closed_first_failure_bounds_resolves() {
    // A forged fan-out: A's index lists many children, the first of which is
    // forged. The walk stops at the first failure — an attacker cannot force
    // resolution of the whole injected fan-out.
    let many: Vec<u8> = (0x02..=0x40).collect();
    let resolver = FakeResolver::new()
        .with(0x01, &many)
        .failing(0x02, ResolveFailure::Rejected);
    let err = block_on(enumerate_eager_set(sid(0x00), &[child(0x01)], &resolver))
        .expect_err("first forgery fails closed");
    assert_eq!(err.scope_id, sid(0x02));
    // A(1 resolve) + B(the forged one, 1 resolve) = 2; the rest never touched.
    assert_eq!(resolver.calls.get(), 2, "walk stops at first failure");
}

#[test]
fn every_descendant_including_leaves_is_resolved() {
    // Completeness reads each descendant's OWN index, so even leaves are
    // resolved (their index is empty). root -> A -> {B(leaf), C(leaf)}.
    let resolver = FakeResolver::new().with(0x01, &[0x02, 0x03]);
    let set =
        block_on(enumerate_eager_set(sid(0x00), &[child(0x01)], &resolver)).expect("enumerates");
    assert_eq!(ids(&set), vec![sid(0x01), sid(0x02), sid(0x03)]);
    assert_eq!(resolver.calls.get(), 3, "A, B, C all resolved");
}

#[test]
fn error_display_is_hex_scope_and_reason() {
    let err = EnumerationError {
        scope_id: sid(0xab),
        reason: ResolveFailure::Rejected,
    };
    let msg = format!("{err}");
    assert!(msg.contains("abababababababababababababababab"));
    assert!(msg.contains("rejected"));
}
