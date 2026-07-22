//! Eager-set enumeration — the transitive closure of descendant scope roots a
//! read-plane rotation must fully rotate (blueprint/engine.md "rotateScope",
//! the **eager set law** #26 D2 as amended by #38 D5).
//!
//! # What it computes
//!
//! Given a scope root, the eager set is **every transitively-reachable
//! descendant scope root** — the F-4 cascade set. The root's level-1 adjacency
//! is its own write-body `direct_child_scope_index` (already in the rotator's
//! hand); every deeper level is read from *each descendant's own* write-body
//! index (blueprint/engine.md: "Enumeration walks the write-body's
//! direct-child-scope index", #38 D6). Cost is O(descendant scope count), never
//! tree size — a scope-less subtree contributes nothing to walk.
//!
//! The returned [`EagerSet`] holds the **descendants only**: the rotator already
//! holds the root and rotates it directly, so re-emitting it here would be
//! redundant. The root is still tracked internally so a back-edge to it
//! terminates.
//!
//! # Why completeness is a security property
//!
//! Read-plane rotation is how a revocation takes effect: an owner-revocation
//! rotation must re-seal *every* reachable descendant so no cached descendant
//! seed survives (blueprint/engine.md: "Cached descendant seeds are why
//! ascent-re-seal alone is insufficient"). A descendant silently missing from
//! the eager set is a **silent revocation hole**, not staleness — the revoked
//! party keeps a live seed. Completeness is therefore enforced fail-closed:
//!
//! - The walk resolves *every* discovered descendant. If any reachable
//!   descendant's index cannot be authoritatively obtained (its record fails the
//!   adoption gate, or is unavailable), the walk returns [`EnumerationError`]
//!   naming that scope — it **never** returns a partial set a caller could
//!   mistake for complete. `EagerSet` has no public constructor other than a
//!   successful walk, so "an incomplete eager set" is unrepresentable.
//! - This mirrors the adoption gate's own split (`GateError::Rejected` vs
//!   `Seam`): a trust rejection and a host-I/O failure are distinct
//!   ([`ResolveFailure`]) but *both* block a claim of completeness. A resolve
//!   failure is a fail-closed trust boundary, never mere staleness
//!   (AGENTS.md critical security rule 6).
//!
//! # Termination and bounding
//!
//! The graph is walked with a visited set keyed by `scope_id`: a scope root is
//! resolved at most once, so a cycle (a corrupt or adversarial index claiming a
//! back-edge) is skipped, not followed — the walk always terminates. No depth or
//! count cap is imposed: the eager set of a legitimately large owner tree must
//! not be rejected. A compromised descendant index that injects fake children
//! cannot amplify unboundedly either — each frontier is canonicalized and the
//! walk aborts at the first resolve that fails the gate, so at most the scopes
//! ordered before the first forgery's canonical position are resolved (bounded
//! by the genuinely gate-passing scopes the attacker controls), never an
//! unbounded injected fan-out.
//!
//! # Determinism
//!
//! The walk is pure: no clock, RNG, or I/O of its own — the sole impure edge is
//! the injected [`ChildIndexResolver`]. Output is ordered by `scope_id` byte
//! `Ord` (a [`BTreeMap`] keyed by `scope_id`, matching Slice 1's
//! [`canonicalize`](crate::grants::child_index::canonicalize) convention), and
//! each level is canonicalized before descent, so the first-seen entry for any
//! shared descendant is fixed regardless of input permutation. Replayed or
//! multi-writer runs converge to byte-identical output.

use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::seal::ChildScopeRef;

use crate::api::signer::hex_lower;
use crate::grants::child_index::canonicalize;

/// Why a descendant scope root's own direct-child index could not be
/// authoritatively obtained. Mirrors the adoption gate's `Rejected` vs `Seam`
/// split: both block a completeness claim, but a caller (rotate/sweep) may act
/// differently — a rejection is corruption/forgery, an unavailability is
/// retryable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveFailure {
    /// The descendant's record failed the adoption gate — a fail-closed trust
    /// violation (forged, corrupt, or revoked), never mere staleness.
    Rejected,
    /// The descendant's record could not be fetched or read — host I/O or
    /// availability. Retryable; not a trust verdict.
    Unavailable,
}

impl core::fmt::Display for ResolveFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResolveFailure::Rejected => f.write_str("descendant record rejected by adoption gate"),
            ResolveFailure::Unavailable => f.write_str("descendant record unavailable"),
        }
    }
}

/// A fail-closed enumeration failure: the walk could not prove the eager set
/// complete because one reachable descendant's index was unobtainable. Names the
/// offending scope and why. Returned instead of a partial set — a silently
/// dropped descendant is a silent revocation hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumerationError {
    /// The descendant scope root whose index could not be obtained.
    pub scope_id: [u8; 16],
    /// Why the resolve failed.
    pub reason: ResolveFailure,
}

impl core::fmt::Display for EnumerationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "eager-set enumeration incomplete: descendant scope [{}] unresolved: {}",
            hex_lower(&self.scope_id),
            self.reason
        )
    }
}

impl std::error::Error for EnumerationError {}

/// A **complete** eager set: every transitively-reachable descendant scope root
/// of some rotated root, ordered by `scope_id`. There is no public constructor
/// other than a successful [`enumerate_eager_set`], so an incomplete set is
/// unrepresentable — holding an `EagerSet` is proof the walk proved completeness.
/// The root scope itself is excluded (the rotator holds and rotates it directly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EagerSet {
    descendants: Vec<ChildScopeRef>,
}

impl EagerSet {
    /// The descendant scope roots, ascending by `scope_id`.
    pub fn descendants(&self) -> &[ChildScopeRef] {
        &self.descendants
    }

    /// Consume into the owned descendant list.
    pub fn into_descendants(self) -> Vec<ChildScopeRef> {
        self.descendants
    }

    /// Number of descendant scope roots in the cascade.
    pub fn len(&self) -> usize {
        self.descendants.len()
    }

    /// Whether the cascade has no descendants (the root is a leaf scope).
    pub fn is_empty(&self) -> bool {
        self.descendants.is_empty()
    }
}

/// The one impure edge of the walk: resolve + gate + unseal a descendant scope
/// root's write-body and yield its `direct_child_scope_index` (its next-level
/// adjacency). The traversal itself is pure and deterministic; only this edge
/// touches the network and the adoption gate. The real resolve/gate/unseal
/// wiring lands in a later slice / the facade — the walk depends only on this
/// contract, and tests fake it.
pub trait ChildIndexResolver {
    /// Return `child`'s own `direct_child_scope_index`, or a fail-closed
    /// [`ResolveFailure`] if its record cannot be authoritatively obtained. An
    /// empty `Vec` is a valid answer: a leaf scope root with no descendants.
    ///
    /// # Binding contract
    ///
    /// `ipns_name` is the **sole gated identity edge**: the adoption gate binds
    /// `ipns_name -> record` via the Ed25519 pubkey derived from the name.
    /// `scope_id` is a **trusted parent-index label** carried inside the parent's
    /// sealed + gated write-body index. The real resolver MUST derive each
    /// descendant's `scope_id` solely from that gated parent index entry, and
    /// MUST NEVER let a network-supplied source (e.g. a registry hint) influence
    /// `scope_id` independently of the gated parent record. The walk keys
    /// visited / dedup / rotation identity on `scope_id`, so an independently
    /// influenced `scope_id` would dedup or rotate the wrong scope key — a silent
    /// revocation hole defeating the eager-set completeness guarantee. Enforcement
    /// of this obligation in the real resolver-wiring slice is tracked in #745.
    async fn direct_child_index(
        &self,
        child: &ChildScopeRef,
    ) -> Result<Vec<ChildScopeRef>, ResolveFailure>;
}

/// Enumerate the eager set: the transitive closure of descendant scope roots
/// reachable from `root_scope_id`, whose level-1 adjacency is `root_child_index`
/// (the root's own, caller-held write-body index) and whose deeper levels the
/// `resolver` supplies from each descendant's own write-body.
///
/// Fail-closed and complete: returns [`EagerSet`] only if *every* reachable
/// descendant resolved; otherwise [`EnumerationError`] names the first
/// unresolved scope. Deterministic: output is ascending by `scope_id`,
/// permutation-independent, and terminates on any cyclic input.
pub async fn enumerate_eager_set<R: ChildIndexResolver>(
    root_scope_id: [u8; 16],
    root_child_index: &[ChildScopeRef],
    resolver: &R,
) -> Result<EagerSet, EnumerationError> {
    // Pre-seed the root so a descendant claiming it as a child (a back-edge to
    // the root) terminates without re-adding it — the root is not its own
    // descendant.
    let mut visited: BTreeSet<[u8; 16]> = BTreeSet::new();
    visited.insert(root_scope_id);

    // Keyed by scope_id: records each descendant exactly once and yields
    // ascending-scope_id order for free.
    let mut discovered: BTreeMap<[u8; 16], ChildScopeRef> = BTreeMap::new();

    // Canonicalize each level (sort + dedup by scope_id) before descending so
    // traversal order — and thus the first-seen entry for any shared descendant
    // reachable via multiple parents — is fixed independent of input order.
    let mut frontier = canonicalize(root_child_index);

    while !frontier.is_empty() {
        let mut next: Vec<ChildScopeRef> = Vec::new();
        for child in &frontier {
            // A scope_id already visited is a diamond re-encounter or a cycle
            // back-edge: never re-resolve it. This is the termination guarantee
            // and the O(distinct descendant count) bound.
            if !visited.insert(child.scope_id) {
                continue;
            }
            discovered.insert(child.scope_id, child.clone());
            // Fail-closed: an unresolvable reachable descendant aborts the walk
            // rather than shrinking the cascade — under-enumeration is a silent
            // revocation hole.
            let grandchildren =
                resolver
                    .direct_child_index(child)
                    .await
                    .map_err(|reason| EnumerationError {
                        scope_id: child.scope_id,
                        reason,
                    })?;
            next.extend(grandchildren);
        }
        frontier = canonicalize(&next);
    }

    Ok(EagerSet {
        descendants: discovered.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
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
    fn determinism_diamond_records_first_seen_ipns_name() {
        // root -> A(0x01), B(0x02); both parents list the same descendant scope
        // D(0x04) but carry DIFFERING ipns_name values. D is recorded exactly
        // once, and the recorded ChildScopeRef is the canonically-first
        // (lowest-scope_id, thus earliest-visited) parent A's ipns_name —
        // deterministically and independent of the root-index permutation.
        let build = |root_index: Vec<ChildScopeRef>| {
            let resolver = FakeResolver::new()
                .with_refs(0x01, vec![child_named(0x04, "via-a")])
                .with_refs(0x02, vec![child_named(0x04, "via-b")]);
            block_on(enumerate_eager_set(sid(0x00), &root_index, &resolver)).expect("enumerates")
        };
        let d_name = |set: &EagerSet| {
            set.descendants()
                .iter()
                .find(|c| c.scope_id == sid(0x04))
                .expect("D present")
                .ipns_name
                .clone()
        };

        let forward = build(vec![child(0x01), child(0x02)]);
        let reversed = build(vec![child(0x02), child(0x01)]);

        assert_eq!(
            forward, reversed,
            "first-seen content is permutation-independent"
        );
        assert_eq!(
            d_name(&forward),
            b"via-a",
            "canonically-first parent's ipns_name wins the first-seen record"
        );
        assert_eq!(ids(&forward), vec![sid(0x01), sid(0x02), sid(0x04)]);
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
        let set = block_on(enumerate_eager_set(sid(0x00), &[child(0x01)], &resolver))
            .expect("enumerates");
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
}
