//! Eager-set enumeration — the transitive closure of descendant scope roots a
//! read-plane rotation must fully rotate (blueprint/engine.md "rotateScope",
//! the **eager set law** #26 D2 as amended by #38 D5).
//!
//! # What it computes
//!
//! Given a scope root, the eager set is **every transitively-reachable
//! descendant scope root** — the F-4 cascade set. The root's level-1 adjacency is
//! its own write-body `direct_child_scope_index` (caller-held); each deeper level
//! is read from *each descendant's own* write-body index (#38 D6). Cost is
//! O(descendant scope count), never tree size. The returned [`EagerSet`] holds
//! the **descendants only** — the rotator holds and rotates the root directly —
//! though the root is tracked internally so a back-edge to it terminates.
//!
//! # Why completeness is a security property
//!
//! A revocation rotation must re-seal *every* reachable descendant so no cached
//! descendant seed survives; a descendant silently missing from the eager set is
//! a **silent revocation hole**, not staleness — the revoked party keeps a live
//! seed. Completeness is therefore fail-closed: the walk resolves every
//! discovered descendant, and any that cannot be authoritatively obtained (its
//! record fails the adoption gate, or is unavailable) returns [`EnumerationError`]
//! naming that scope, never a partial set. `EagerSet` has no public constructor
//! other than a successful walk, so an incomplete set is unrepresentable.
//! [`ResolveFailure`] mirrors the adoption gate's `Rejected` vs `Seam` split — a
//! trust rejection and a host-I/O failure are distinct but *both* block a
//! completeness claim; a resolve failure is a fail-closed trust boundary, never
//! staleness (AGENTS.md critical security rule 6).
//!
//! # Termination and bounding
//!
//! A `scope_id`-keyed visited set resolves each scope root at most once, so a
//! cycle (a corrupt/adversarial back-edge) is skipped, not followed — the walk
//! always terminates. No depth or count cap is imposed (a legitimately large
//! owner tree must not be rejected); an injected fake fan-out cannot amplify
//! unboundedly either, since each frontier is canonicalized and the walk aborts
//! at the first gate-failing resolve, bounding resolves to the gate-passing
//! scopes ordered before the first forgery.
//!
//! # Determinism
//!
//! The walk is pure — the sole impure edge is the injected [`ChildIndexResolver`].
//! Output is ordered by `scope_id` (a [`BTreeMap`], matching Slice 1's
//! [`canonicalize`](crate::grants::child_index::canonicalize) convention) and each
//! level is canonicalized before descent, so a shared descendant reached via
//! multiple parents is recorded once, permutation-independently — or, if those
//! parents disagree on its `ipns_name`, the walk aborts fail-closed (C2;
//! [`ResolveFailure::ConflictingChildLabel`]). Replayed or multi-writer runs
//! converge to byte-identical output.

use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::seal::ChildScopeRef;

use crate::grants::child_index::canonicalize;
use cipherbox_core::hex::lower as hex_lower;

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
    /// The same `scope_id` was reached via two parents carrying **different**
    /// `ipns_name` labels (C2). A [`ChildScopeRef`] carries no ordering
    /// signal, so first-seen-wins would be a coin-flip; picking the stale name in a
    /// revocation cascade re-keys a dead name and leaves the real descendant
    /// unrotated — a silent revocation hole. The walk aborts fail-closed instead.
    /// Retryable: converges once the write-rotation re-point wave repairs both
    /// parent indexes (engine.md #38 D6). The accept-freshest alternative would
    /// need a core schema change.
    ConflictingChildLabel,
}

impl ResolveFailure {
    /// The class label a reject vector carries for this failure.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Rejected => "trust",
            Self::Unavailable | Self::ConflictingChildLabel => "availability",
        }
    }
}

impl core::fmt::Display for ResolveFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResolveFailure::Rejected => f.write_str("descendant record rejected by adoption gate"),
            ResolveFailure::Unavailable => f.write_str("descendant record unavailable"),
            ResolveFailure::ConflictingChildLabel => {
                f.write_str("descendant scope_id reached with conflicting ipns_name labels")
            }
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
/// touches the network and the adoption gate. The production resolve/gate/unseal
/// wiring is [`crate::net::rotation::OwnerRotationNet`]; the walk depends only
/// on this contract, and tests fake it.
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
    /// revocation hole defeating the eager-set completeness guarantee.
    async fn direct_child_index(
        &self,
        child: &ChildScopeRef,
    ) -> Result<Vec<ChildScopeRef>, ResolveFailure>;
}

/// Bind each ref's `scope_id -> ipns_name` label into `labels`, aborting
/// fail-closed on the C2 conflict: a `scope_id` already bound to a **different**
/// `ipns_name`. Returns the conflicting `scope_id` on abort. The root is
/// skipped — a back-edge to it is ignored by the walk, never a labeled
/// descendant. Rationale for the hard abort lives on
/// [`ResolveFailure::ConflictingChildLabel`].
///
/// Call once **per parent index** (each already canonicalized), never over a
/// merged frontier. A single parent's own duplicate `scope_id` is crash residue
/// the [`canonicalize`] self-heal repairs first-seen (#38 D6) — only a
/// **cross-parent** disagreement, where neither parent is authoritative over the
/// other's label, is the revocation-hole conflict this abort exists to catch.
pub(crate) fn bind_child_labels<'a>(
    labels: &mut BTreeMap<[u8; 16], Vec<u8>>,
    refs: impl Iterator<Item = &'a ChildScopeRef>,
    root_scope_id: [u8; 16],
) -> Result<(), [u8; 16]> {
    for child in refs {
        if child.scope_id == root_scope_id {
            continue;
        }
        match labels.get(&child.scope_id) {
            Some(name) if name != &child.ipns_name => return Err(child.scope_id),
            Some(_) => {}
            None => {
                labels.insert(child.scope_id, child.ipns_name.clone());
            }
        }
    }
    Ok(())
}

/// Enumerate the eager set: the transitive closure of descendant scope roots
/// reachable from `root_scope_id`, whose level-1 adjacency is `root_child_index`
/// (the root's own, caller-held write-body index) and whose deeper levels the
/// `resolver` supplies from each descendant's own write-body.
///
/// Fail-closed and complete: returns [`EagerSet`] only if *every* reachable
/// descendant resolved; otherwise [`EnumerationError`] names the first
/// unresolved scope, or the first C2 label conflict
/// ([`ResolveFailure::ConflictingChildLabel`]). Deterministic: output is
/// ascending by `scope_id`, permutation-independent, and terminates on any cyclic
/// input.
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

    // The single authoritative `scope_id -> ipns_name` binding, bound per parent
    // index (see bind_child_labels).
    let mut labels: BTreeMap<[u8; 16], Vec<u8>> = BTreeMap::new();
    let conflict = |scope_id| EnumerationError {
        scope_id,
        reason: ResolveFailure::ConflictingChildLabel,
    };

    // Canonicalize each level (sort + dedup by scope_id) before descending so
    // traversal order — and thus the first-seen entry for any shared descendant
    // reachable via multiple parents — is fixed independent of input order.
    let mut frontier = canonicalize(root_child_index);
    bind_child_labels(&mut labels, frontier.iter(), root_scope_id).map_err(conflict)?;

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
            // Bind per-parent (see bind_child_labels).
            let canon = canonicalize(&grandchildren);
            bind_child_labels(&mut labels, canon.iter(), root_scope_id).map_err(conflict)?;
            next.extend(grandchildren);
        }
        frontier = canonicalize(&next);
    }

    Ok(EagerSet {
        descendants: discovered.into_values().collect(),
    })
}

#[cfg(test)]
mod tests;
