//! The sweep — the idempotent lazy wave over a scope's **interior nodes**
//! (blueprint/engine.md "sweep"; #26 D2, #38 D6,
//! [ADR 0003](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0003-sweep-population-and-below-floor-scope-roots.md)).
//!
//! # Population
//!
//! The work-list is the epoch-lag predicate over the nodes *inside* one scope: a
//! node whose envelope epoch is behind the scope root's current read epoch. The
//! walk descends the scope root's own read body and **stops at scope-root
//! boundaries** — a descendant scope root is an eager-set member the
//! [`cascade`](super::cascade) rotates, and is never swept. Each lagging node is
//! re-sealed at the scope's current epoch and CAS-published; a node already at
//! the epoch is a no-op, so a re-run changes nothing and concurrent sweepers are
//! safe under CAS.
//!
//! # A scope root below its own floor is superseded, never repaired
//!
//! Rotations publish before they raise the floor, so `recordEpoch < floor` on a
//! scope root cannot mean it lags — it means the name we asked at is not the
//! current one. It resolves to a distinct [`SweepResolveFailure::Superseded`]
//! verdict, routed through the scope-pointer consult (#38 D4) and re-resolved at
//! the re-pointed `currentRootName`, failing closed if the fresh record is still
//! below the floor. Admitting such a record would republish the scope's existing
//! override seed at the current epoch — a revocation bypass, not a repair.
//!
//! # Completeness is fail-closed
//!
//! The work-list is computed purely from published records, so a re-run
//! reconstructs it identically. A node that cannot be resolved, re-sealed or
//! published is never silently skipped: the pass aborts with a [`SweepError`]
//! naming it. The one spec-mandated per-node exception is a **lost CAS race** —
//! the loser drops the node and re-resolves, and since the winner may be an
//! ordinary metadata write that does not advance the epoch, a drop is not proof
//! of convergence; [`run_sweep`] re-runs until a pass drops nothing.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::seal::{ChildScopeRef, PreservedFields, ReadBody};

use super::eager_set::ResolveFailure;
use super::rotate::ScopeRootPublishError;
use crate::grants::child_index::repair_observed;
use crate::seams::Scheduler;
use cipherbox_core::hex::lower as hex_lower;

#[cfg(test)]
pub(crate) mod sim;

/// One node inside a scope, as the gated parent body named it. A node id locates
/// nothing on its own — only a gated parent's read body binds it to a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRef {
    /// The node id the parent's `ChildRef` carried.
    pub node_id: [u8; 16],
    /// That ref's opaque `ipnsName` bytes.
    pub ipns_name: Vec<u8>,
}

/// The swept scope as its scope root's gated read found it. Carries no key
/// material: re-sealing is the publisher's half of the seam, so the sweep never
/// holds a seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweptScope {
    /// The scope root's published read epoch — the epoch every interior node is
    /// measured against and re-sealed up to.
    pub current_read_epoch: u64,
    /// The scope root's own read-body children: the walk's level-1 frontier.
    pub children: Vec<NodeRef>,
    /// The committed direct-child-scope index — both the walk's scope-root
    /// boundary set and the index the self-heal repairs (#38 D6).
    pub direct_child_scope_index: Vec<ChildScopeRef>,
}

/// One interior node as the sweep's gated read found it. The body is carried
/// forward verbatim — a sweep re-seals metadata only, and content bytes are
/// never re-encrypted by any rotation path (#26 D6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweptNode {
    /// The published record's read epoch — the epoch-lag operand.
    pub current_read_epoch: u64,
    /// The node's unsealed read body.
    pub read_body: ReadBody,
    /// Top-level envelope fields a republish preserves byte-stable (#27 D10).
    pub carried_unknown: PreservedFields,
    /// `epochTag` fields a republish preserves byte-stable (#27 D10).
    pub carried_epoch_tag_unknown: PreservedFields,
}

/// What the walk found at one child of a swept node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweptChild {
    /// An ordinary interior node: sweepable, and descended into.
    Interior(SweptNode),
    /// The child's record is a **scope root**, carrying the name the resolver
    /// gated it current at. The walk stops here, and — when the scope's index
    /// does not name it — repairs the index with this name (#38 D6).
    ScopeRoot(ChildScopeRef),
}

/// Why a sweep read could not be authoritatively completed.
///
/// [`Superseded`](Self::Superseded) is the third verdict ADR 0003 adds: a scope
/// root below its own read-epoch floor is neither a trust violation the caller
/// must not retry nor a transport stall, but a stale name — routed through the
/// pointer consult.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepResolveFailure {
    /// The record failed the adoption gate — a fail-closed trust violation,
    /// never mere staleness.
    Rejected,
    /// The record could not be fetched or read — host I/O or availability.
    Unavailable,
    /// A scope root's record sits below its own durable read-epoch floor.
    Superseded,
}

impl From<ResolveFailure> for SweepResolveFailure {
    fn from(failure: ResolveFailure) -> Self {
        match failure {
            ResolveFailure::Unavailable => Self::Unavailable,
            ResolveFailure::Rejected | ResolveFailure::ConflictingChildLabel => Self::Rejected,
        }
    }
}

impl core::fmt::Display for SweepResolveFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rejected => f.write_str("record rejected by adoption gate"),
            Self::Unavailable => f.write_str("record unavailable"),
            Self::Superseded => f.write_str("scope root superseded: record below its own floor"),
        }
    }
}

impl SweepResolveFailure {
    /// Whether re-running the pass could clear this — availability only. A
    /// rejection is a trust violation, and a `Superseded` that survives the
    /// consult means the re-pointed record is below the floor too.
    fn is_retryable(self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

/// The read edge the sweep runs on: resolve + adoption-gate + unseal. The owner
/// arm is [`crate::net::rotation::OwnerRotationNet`].
///
/// # Binding contract (obligation on the real resolver)
///
/// Every record is gated under the **caller's own label** — the `scope_id` /
/// `node_id` the gated parent body named it by — so a record claiming another
/// identity is a transplant it rejects. No self-identifying id is returned; the
/// caller's ref stays the sole identity authority.
pub trait SweepResolver {
    /// Gate `scope`'s scope root and yield the scope's current sweep state.
    async fn resolve_scope(&self, scope: &ChildScopeRef)
    -> Result<SweptScope, SweepResolveFailure>;

    /// The scope's `currentRootName` from its owner-signed scope pointer
    /// (#38 D4). `None` means the scope has never been re-pointed, so there is
    /// no fresher name to re-resolve at.
    async fn consult_pointer(
        &self,
        scope_id: &[u8; 16],
    ) -> Result<Option<Vec<u8>>, SweepResolveFailure>;

    /// Resolve one child of a node already swept in this scope, at whatever
    /// epoch its record carries.
    async fn resolve_child(&self, child: &NodeRef) -> Result<SweptChild, SweepResolveFailure>;
}

/// One interior node being advanced to its scope's current epoch. The publisher
/// re-seals the carried body under the node's current read key and CAS-publishes
/// it; the sweep hands over no key material.
pub struct LaggingNode<'a> {
    /// The node id, as the gated parent body named it.
    pub node_id: [u8; 16],
    /// That parent ref's opaque `ipnsName` bytes — the publish destination.
    pub ipns_name: &'a [u8],
    /// The scope's current read epoch: what the node is re-sealed up to.
    pub read_epoch: u64,
    /// The body carried forward verbatim.
    pub read_body: &'a ReadBody,
    /// Envelope fields a republish preserves byte-stable (#27 D10).
    pub carried_unknown: &'a PreservedFields,
    /// `epochTag` fields a republish preserves byte-stable (#27 D10).
    pub carried_epoch_tag_unknown: &'a PreservedFields,
}

/// The write edge the sweep runs on. Both methods are register-first CAS
/// publishes; `Ok` means the record is durably the freshest at its name.
pub trait SweepPublisher {
    /// Re-seal `node`'s carried body at `node.read_epoch` and CAS-publish it.
    async fn publish_node(&self, node: &LaggingNode<'_>) -> Result<(), ScopeRootPublishError>;

    /// Republish `scope`'s scope root carrying `index` as its
    /// `directChildScopeIndex` — the #38 D6 self-heal. Metadata-only: the
    /// scope's existing seed at its current epoch, minting no seed, epoch or
    /// history link.
    async fn repair_child_scope_index(
        &self,
        scope: &ChildScopeRef,
        index: &[ChildScopeRef],
    ) -> Result<(), ScopeRootPublishError>;
}

/// A completed sweep pass. Every node the walk reached is accounted for in
/// exactly one bucket — the fail-closed guarantee made observable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Interior nodes that lagged and were re-sealed to the scope's epoch.
    pub converged: Vec<[u8; 16]>,
    /// Interior nodes already at the scope's epoch — no re-seal, a no-op.
    pub already_converged: Vec<[u8; 16]>,
    /// Interior nodes dropped because a concurrent writer won the CAS race.
    pub dropped_lost_race: Vec<[u8; 16]>,
    /// Descendant scope roots the walk stopped at: eager-set members the cascade
    /// rotates, never swept.
    pub skipped_scope_roots: Vec<[u8; 16]>,
    /// Scope roots the walk encountered that were missing from the scope's
    /// direct-child-scope index, repaired into it and **durably published** —
    /// "repaired and flagged" (#38 D6). A repair that loses the CAS is not
    /// flagged; it never landed.
    pub flagged_indexes: Vec<[u8; 16]>,
}

/// A fail-closed sweep failure, returned instead of a partial [`SweepOutcome`]
/// whenever the pass cannot account for every node the walk reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepError {
    /// The scope root could not be authoritatively resolved — including a
    /// `Superseded` verdict the pointer consult could not clear.
    Scope {
        /// The scope whose root could not be resolved.
        scope_id: [u8; 16],
        /// Why the resolve failed.
        reason: SweepResolveFailure,
    },
    /// A reachable node could not be authoritatively resolved.
    Node {
        /// The node that could not be resolved.
        node_id: [u8; 16],
        /// Why the resolve failed.
        reason: SweepResolveFailure,
    },
    /// A re-sealed interior node could not be published; nothing landed for it.
    Publish {
        /// The node whose record did not land.
        node_id: [u8; 16],
        /// The publish failure (never [`ScopeRootPublishError::LostRace`] — a
        /// lost race drops the node and re-resolves).
        error: ScopeRootPublishError,
    },
    /// The repaired direct-child-scope index could not be published.
    IndexRepair {
        /// The scope whose index repair did not land.
        scope_id: [u8; 16],
        /// The publish failure.
        error: ScopeRootPublishError,
    },
}

impl core::fmt::Display for SweepError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SweepError::Scope { scope_id, reason } => write!(
                f,
                "sweep scope-root resolve of [{}] failed: {reason}",
                hex_lower(scope_id)
            ),
            SweepError::Node { node_id, reason } => write!(
                f,
                "sweep resolve of node [{}] failed: {reason}",
                hex_lower(node_id)
            ),
            SweepError::Publish { node_id, error } => write!(
                f,
                "sweep publish of node [{}] failed: {error}",
                hex_lower(node_id)
            ),
            SweepError::IndexRepair { scope_id, error } => write!(
                f,
                "sweep index repair of scope [{}] failed: {error}",
                hex_lower(scope_id)
            ),
        }
    }
}

impl std::error::Error for SweepError {}

impl SweepError {
    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            SweepError::Scope { .. } => "scope-root-unresolved",
            SweepError::Node { .. } => "node-unresolved",
            SweepError::Publish { .. } => "publish-failed",
            SweepError::IndexRepair { .. } => "index-repair-failed",
        }
    }

    /// Whether re-running the idempotent pass could clear this failure — an
    /// availability stall — versus a trust violation, which no retry can fix.
    pub fn is_retryable(&self) -> bool {
        match self {
            SweepError::Scope { reason, .. } | SweepError::Node { reason, .. } => {
                reason.is_retryable()
            }
            SweepError::Publish { error, .. } | SweepError::IndexRepair { error, .. } => {
                error.is_retryable()
            }
        }
    }
}

/// Sort by node id and drop repeats, so the frontier — and thus the pass's
/// publish order — is independent of the order a parent body listed its
/// children in.
fn canonicalize_frontier(mut nodes: Vec<NodeRef>) -> Vec<NodeRef> {
    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    let mut seen: Option<[u8; 16]> = None;
    nodes.retain(|node| {
        if seen == Some(node.node_id) {
            false
        } else {
            seen = Some(node.node_id);
            true
        }
    });
    nodes
}

/// The in-scope children a swept body names.
fn body_children(body: &ReadBody) -> Vec<NodeRef> {
    match body {
        ReadBody::Folder { children, .. } => children
            .iter()
            .map(|child| NodeRef {
                node_id: child.id,
                ipns_name: child.ipns_name.clone(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Resolve `scope`'s root, routing a [`SweepResolveFailure::Superseded`] verdict
/// through the pointer consult and re-resolving at the re-pointed
/// `currentRootName`. Returns the ref the scope resolved current at, which is
/// the only name a repair may write into an index.
async fn resolve_scope_current<R: SweepResolver>(
    resolver: &R,
    scope: &ChildScopeRef,
) -> Result<(ChildScopeRef, SweptScope), SweepResolveFailure> {
    match resolver.resolve_scope(scope).await {
        Ok(swept) => Ok((scope.clone(), swept)),
        Err(SweepResolveFailure::Superseded) => {
            let repointed = repointed_ref(resolver, scope).await?;
            // One consult, one re-resolve: a fresh record still below the floor
            // fails closed here rather than consulting again.
            let swept = resolver.resolve_scope(&repointed).await?;
            Ok((repointed, swept))
        }
        Err(other) => Err(other),
    }
}

/// Resolve one child, routing the same superseded verdict through the consult.
/// Returns the ref the child resolved current at.
async fn resolve_child_current<R: SweepResolver>(
    resolver: &R,
    child: &NodeRef,
) -> Result<(NodeRef, SweptChild), SweepResolveFailure> {
    match resolver.resolve_child(child).await {
        Ok(found) => Ok((child.clone(), found)),
        Err(SweepResolveFailure::Superseded) => {
            let scope = ChildScopeRef::new(child.node_id, child.ipns_name.clone());
            let repointed = repointed_ref(resolver, &scope).await?;
            let node = NodeRef {
                node_id: child.node_id,
                ipns_name: repointed.ipns_name,
            };
            let found = resolver.resolve_child(&node).await?;
            Ok((node, found))
        }
        Err(other) => Err(other),
    }
}

/// The scope's `currentRootName` from its pointer. A scope with no pointer has
/// no fresher name, so the below-floor record is refused as it stands.
async fn repointed_ref<R: SweepResolver>(
    resolver: &R,
    scope: &ChildScopeRef,
) -> Result<ChildScopeRef, SweepResolveFailure> {
    let current = resolver
        .consult_pointer(&scope.scope_id)
        .await?
        .ok_or(SweepResolveFailure::Superseded)?;
    Ok(ChildScopeRef::new(scope.scope_id, current))
}

/// Run one idempotent sweep pass over `scope`'s interior nodes.
///
/// Resolves the scope root (consulting the pointer on a superseded verdict),
/// walks its read body stopping at every scope-root boundary, self-heals the
/// direct-child-scope index from the walk result, and re-seals every node whose
/// epoch lags the scope's. Returns a complete [`SweepOutcome`] or a fail-closed
/// [`SweepError`] — never a partial convergence claim.
pub async fn sweep_pass<R, P>(
    resolver: &R,
    publisher: &P,
    scope: &ChildScopeRef,
) -> Result<SweepOutcome, SweepError>
where
    R: SweepResolver,
    P: SweepPublisher,
{
    let (scope_ref, swept) = resolve_scope_current(resolver, scope)
        .await
        .map_err(|reason| SweepError::Scope {
            scope_id: scope.scope_id,
            reason,
        })?;

    let boundaries: BTreeSet<[u8; 16]> = swept
        .direct_child_scope_index
        .iter()
        .map(|child| child.scope_id)
        .collect();

    let mut outcome = SweepOutcome::default();
    // Keyed by node id: the walk resolves each node once, so a diamond or a
    // corrupt back-edge terminates rather than looping.
    let mut visited: BTreeSet<[u8; 16]> = BTreeSet::new();
    visited.insert(scope_ref.scope_id);
    // Scope roots the walk met that the index does not name (#38 D6), at the
    // name each resolved current at.
    let mut omitted: BTreeMap<[u8; 16], ChildScopeRef> = BTreeMap::new();
    let mut lagging: Vec<(NodeRef, SweptNode)> = Vec::new();

    let mut frontier = canonicalize_frontier(swept.children);
    while !frontier.is_empty() {
        let mut next: Vec<NodeRef> = Vec::new();
        for child in &frontier {
            if !visited.insert(child.node_id) {
                continue;
            }
            if boundaries.contains(&child.node_id) {
                outcome.skipped_scope_roots.push(child.node_id);
                continue;
            }
            let (resolved, found) =
                resolve_child_current(resolver, child)
                    .await
                    .map_err(|reason| SweepError::Node {
                        node_id: child.node_id,
                        reason,
                    })?;
            match found {
                SweptChild::ScopeRoot(scope_root) => {
                    outcome.skipped_scope_roots.push(child.node_id);
                    omitted.insert(child.node_id, scope_root);
                }
                SweptChild::Interior(node) => {
                    next.extend(body_children(&node.read_body));
                    if node.current_read_epoch >= swept.current_read_epoch {
                        outcome.already_converged.push(child.node_id);
                    } else {
                        lagging.push((resolved, node));
                    }
                }
            }
        }
        frontier = canonicalize_frontier(next);
    }

    // The self-heal runs on the walk result, before any epoch comparison is
    // acted on, so it lands whether or not this pass re-seals a node (#38 D6,
    // ADR 0003 D3).
    if !omitted.is_empty() {
        let mut index = swept.direct_child_scope_index.clone();
        for scope_root in omitted.values() {
            index = repair_observed(&index, scope_root.clone());
        }
        match publisher.repair_child_scope_index(&scope_ref, &index).await {
            Ok(()) => outcome.flagged_indexes.extend(omitted.keys().copied()),
            // Never landed, so never flagged; the next pass re-derives it.
            Err(ScopeRootPublishError::LostRace) => {}
            Err(error) => {
                return Err(SweepError::IndexRepair {
                    scope_id: scope_ref.scope_id,
                    error,
                });
            }
        }
    }

    for (node, swept_node) in &lagging {
        let lagging_node = LaggingNode {
            node_id: node.node_id,
            ipns_name: &node.ipns_name,
            read_epoch: swept.current_read_epoch,
            read_body: &swept_node.read_body,
            carried_unknown: &swept_node.carried_unknown,
            carried_epoch_tag_unknown: &swept_node.carried_epoch_tag_unknown,
        };
        match publisher.publish_node(&lagging_node).await {
            Ok(()) => outcome.converged.push(node.node_id),
            // The one spec-mandated non-abort per-node path. The winner may be a
            // non-advancing ordinary write, so the node is not proven converged;
            // `run_sweep` re-resolves it until a pass drops nothing.
            Err(ScopeRootPublishError::LostRace) => outcome.dropped_lost_race.push(node.node_id),
            Err(error) => {
                return Err(SweepError::Publish {
                    node_id: node.node_id,
                    error,
                });
            }
        }
    }

    Ok(outcome)
}

/// Drive the sweep as an idle-cadence job: run [`sweep_pass`] and re-run it, one
/// `cadence` sleep apart via the [`Scheduler`] seam, until a pass both succeeds
/// **and** drops nothing to a lost race — the point convergence is actually
/// confirmed — or the `max_passes` cap is hit. A retryable availability stall
/// re-runs; a trust failure returns immediately.
///
/// On cap exhaustion it returns the last availability `Err`, or — if the final
/// pass merely still had lost-race drops — `Ok` with those nodes surfaced in
/// [`SweepOutcome::dropped_lost_race`], so a host racing a persistently hot
/// writer sees the residual rather than a false "complete".
///
/// # Caller contract
///
/// An `Ok` outcome is convergence-complete **only when
/// [`SweepOutcome::dropped_lost_race`] is empty**. The returned outcome reflects
/// the **final** pass; earlier passes' work is durable on the network but is not
/// aggregated into it.
pub async fn run_sweep<S, R, P>(
    scheduler: &S,
    resolver: &R,
    publisher: &P,
    scope: &ChildScopeRef,
    cadence: Duration,
    max_passes: u32,
) -> Result<SweepOutcome, SweepError>
where
    S: Scheduler,
    R: SweepResolver,
    P: SweepPublisher,
{
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        match sweep_pass(resolver, publisher, scope).await {
            Ok(outcome) if outcome.dropped_lost_race.is_empty() => return Ok(outcome),
            Ok(outcome) => {
                if attempts >= max_passes {
                    return Ok(outcome);
                }
                scheduler.sleep(cadence).await;
            }
            Err(e) if e.is_retryable() && attempts < max_passes => {
                scheduler.sleep(cadence).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sim::{FakeNet, id, name, scope_ref};
    use super::*;
    use crate::seams::UnixMillis;
    use crate::testkit::block_on;
    use crate::testkit::fakes::VirtualScheduler;

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
            .scope_root(0x0a, true, &[0x0d])
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
        let net = FakeNet::new(5, &[0x0a]).scope_root(0x0a, true, &[]);
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
            .scope_root(0x0a, false, &[]);

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
    fn a_repaired_index_is_not_flagged_again_on_the_next_pass() {
        let net = FakeNet::new(5, &[0x0a]).scope_root(0x0a, false, &[]);
        assert_eq!(run(&net, 0x00).expect("first").flagged_indexes.len(), 1);
        let again = run(&net, 0x00).expect("second");
        assert!(again.flagged_indexes.is_empty());
        assert_eq!(net.index_repairs.get(), 1, "no redundant republish");
    }

    #[test]
    fn an_index_repair_that_lost_the_cas_is_not_flagged() {
        let net = FakeNet::new(5, &[0x0a]).scope_root(0x0a, false, &[]);
        net.state.borrow_mut().index_repair_fault = Some(ScopeRootPublishError::LostRace);

        let outcome = run(&net, 0x00).expect("sweep");
        assert!(
            outcome.flagged_indexes.is_empty(),
            "a repair that never landed must not be reported"
        );
        assert_eq!(outcome.skipped_scope_roots, vec![id(0x0a)]);
    }

    #[test]
    fn an_index_repair_that_did_not_land_fails_closed() {
        let net = FakeNet::new(5, &[0x0a]).scope_root(0x0a, false, &[]);
        net.state.borrow_mut().index_repair_fault = Some(ScopeRootPublishError::NotPublished);

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
            .scope_root(0x0a, false, &[])
            .fault(0x01, ScopeRootPublishError::NotPublished);

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
            .scope_root(0x0a, false, &[])
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

    // --- Fail-closed completeness ---

    #[test]
    fn a_rejected_node_aborts_the_pass_fatally() {
        let net = FakeNet::new(5, &[0x01, 0x02])
            .node(0x01, 1, &[])
            .node(0x02, 1, &[])
            .node_fault(0x02, SweepResolveFailure::Rejected);
        let err = run(&net, 0x00).expect_err("fails closed");
        assert_eq!(err.check(), "node-unresolved");
        assert!(!err.is_retryable());
        assert_eq!(net.publishes(0x01), 0, "nothing is published on an abort");
    }

    #[test]
    fn an_unavailable_node_aborts_retryably() {
        let net = FakeNet::new(5, &[0x01])
            .node(0x01, 1, &[])
            .node_fault(0x01, SweepResolveFailure::Unavailable);
        let err = run(&net, 0x00).expect_err("fails closed");
        assert!(err.is_retryable());
    }

    #[test]
    fn a_node_that_did_not_publish_aborts_rather_than_claiming_convergence() {
        let net = FakeNet::new(5, &[0x01])
            .node(0x01, 1, &[])
            .fault(0x01, ScopeRootPublishError::NotPublished);
        let err = run(&net, 0x00).expect_err("fails closed");
        assert!(matches!(err, SweepError::Publish { node_id, .. } if node_id == id(0x01)));
        assert!(err.is_retryable());
    }

    #[test]
    fn a_publish_the_publisher_refused_is_never_retried() {
        let net = FakeNet::new(5, &[0x01])
            .node(0x01, 1, &[])
            .fault(0x01, ScopeRootPublishError::Rejected);
        let err = run(&net, 0x00).expect_err("fails closed");
        assert!(!err.is_retryable(), "a trust rejection is fatal");
    }

    #[test]
    fn a_partial_pass_resumes_without_stranding_a_node() {
        let net = FakeNet::new(5, &[0x01, 0x02])
            .node(0x01, 1, &[])
            .node(0x02, 1, &[])
            .fault(0x02, ScopeRootPublishError::NotPublished);
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
            .fault(0x01, ScopeRootPublishError::LostRace);
        let outcome = run(&net, 0x00).expect("sweep");
        assert_eq!(outcome.dropped_lost_race, vec![id(0x01)]);
        assert_eq!(outcome.converged, vec![id(0x02)]);
    }

    // --- The idle-cadence driver ---

    /// Drive the pass on a virtual clock, asserting that every re-run cost one
    /// cadence sleep — time enters only through the scheduler seam.
    fn drive(
        net: &FakeNet,
        max_passes: u32,
        expected_sleeps: u32,
    ) -> Result<SweepOutcome, SweepError> {
        let scheduler = VirtualScheduler::new().with_auto_advance();
        let result = block_on(run_sweep(
            &scheduler,
            net,
            net,
            &scope_ref(0x00),
            Duration::from_secs(30),
            max_passes,
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
            .fault(0x01, ScopeRootPublishError::NotPublished);
        let err = drive(&net, 3, 2).expect_err("the stall surfaces");
        assert_eq!(err.check(), "publish-failed");
        assert_eq!(net.publishes(0x01), 3, "one attempt per allowed pass");
    }

    #[test]
    fn the_driver_returns_a_trust_failure_immediately() {
        let net = FakeNet::new(5, &[0x01])
            .node(0x01, 1, &[])
            .node_fault(0x01, SweepResolveFailure::Rejected);
        let err = drive(&net, 5, 0).expect_err("fatal");
        assert!(!err.is_retryable());
    }
}
