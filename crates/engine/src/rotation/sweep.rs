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
//! published is never silently skipped — it is either named by a [`SweepError`]
//! that aborts the pass, or bucketed in the outcome. Two buckets are per-node
//! rather than fatal, because the lazy wave's unit of progress is one interior
//! node: a **lost CAS race** ([`SweepOutcome::dropped_lost_race`]), whose winner
//! may be an ordinary metadata write that does not advance the epoch, and a node
//! this pass could not read at all ([`SweepOutcome::unreachable`]).
//! [`run_sweep`] re-runs while either is non-empty for a reason a retry could
//! clear; a caller needing the subtree proven converged refuses on both.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::seal::{ChildScopeRef, PreservedFields, ReadBody};

use super::eager_set::ResolveFailure;
use super::rotate::RotationPublishError;
use crate::grants::child_index::{canonicalize, repair_observed};
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
    /// That record's sequence: the CAS basis a re-seal must publish above, since
    /// nothing on this read path raises the name's durable sequence floor to it.
    pub sequence: u64,
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
    /// The node's body could not be opened at all: no seed on this scope's
    /// key-regression ratchet reaches the epoch its record claims — an epoch
    /// older than the retained window, a broken chain, or one above the scope
    /// root's own. Unreadable to every reader, so no retry can change it and it
    /// is not a verdict on the record's trustworthiness.
    Unreadable,
    /// The same node id was reached through two parents carrying **different**
    /// `ipnsName` labels — the read plane's C2 conflict
    /// ([`ResolveFailure::ConflictingChildLabel`]). Converging the one picked
    /// would leave the other name live at the old epoch, so the walk aborts.
    ConflictingChildLabel,
}

impl From<ResolveFailure> for SweepResolveFailure {
    fn from(failure: ResolveFailure) -> Self {
        match failure {
            ResolveFailure::Unavailable => Self::Unavailable,
            ResolveFailure::Rejected => Self::Rejected,
            ResolveFailure::ConflictingChildLabel => Self::ConflictingChildLabel,
        }
    }
}

impl core::fmt::Display for SweepResolveFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rejected => f.write_str("record rejected by adoption gate"),
            Self::Unavailable => f.write_str("record unavailable"),
            Self::Superseded => f.write_str("scope root superseded: record below its own floor"),
            Self::ConflictingChildLabel => {
                f.write_str("node id reached with conflicting ipnsName labels")
            }
            Self::Unreadable => f.write_str("node epoch beyond this scope's ratchet"),
        }
    }
}

impl SweepResolveFailure {
    /// Whether re-running the pass could clear this: an availability stall, or a
    /// C2 conflict the write-rotation re-point wave repairs. A rejection is a
    /// trust violation, and a `Superseded` that survives the consult means the
    /// re-pointed record is below the floor too.
    fn is_retryable(self) -> bool {
        matches!(self, Self::Unavailable | Self::ConflictingChildLabel)
    }

    /// Whether this condemns the one node it was raised on rather than the whole
    /// pass. The lazy wave's unit of progress is a single interior node, so a
    /// node nothing can re-seal or descend into is isolated
    /// ([`SweepOutcome::unreachable`]); a `Superseded` root and a C2 label
    /// conflict are statements about the scope, and still abort.
    fn isolates_the_node(self) -> bool {
        matches!(self, Self::Unreadable | Self::Rejected | Self::Unavailable)
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

    /// Resolve one child of a node inside `scope`, at whatever epoch its record
    /// carries. `scope` is the ref [`Self::resolve_scope`] proved current, and
    /// the only scope this child may be gated under.
    async fn resolve_child(
        &self,
        scope: &ChildScopeRef,
        child: &NodeRef,
    ) -> Result<SweptChild, SweepResolveFailure>;
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
    /// The sequence of the record this body came from — the CAS basis the
    /// re-seal must land above ([`SweptNode::sequence`]).
    pub sequence: u64,
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
    /// Re-seal `node`'s carried body at `node.read_epoch` and CAS-publish it,
    /// under `scope` — the ref [`SweepResolver::resolve_scope`] proved current.
    async fn publish_node(
        &self,
        scope: &ChildScopeRef,
        node: &LaggingNode<'_>,
    ) -> Result<(), RotationPublishError>;

    /// Republish `scope`'s scope root carrying `index` as its
    /// `directChildScopeIndex` — the #38 D6 self-heal. Metadata-only: the
    /// scope's existing seed at its current epoch, minting no seed, epoch or
    /// history link.
    async fn repair_child_scope_index(
        &self,
        scope: &ChildScopeRef,
        index: &[ChildScopeRef],
    ) -> Result<(), RotationPublishError>;
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
    /// Every node this pass could not read, with the verdict that condemned it
    /// ([`SweepResolveFailure::isolates_the_node`]). Neither swept nor descended
    /// into, so a caller that needs the subtree proven converged (grant
    /// creation) refuses on a non-empty list rather than reading an `Ok` outcome
    /// as complete. The reason rides along because a trust rejection and an
    /// availability stall are not the same answer: only the latter is worth
    /// another pass.
    pub unreachable: Vec<([u8; 16], SweepResolveFailure)>,
    /// Scope roots the walk encountered that were missing from the scope's
    /// direct-child-scope index, repaired into it and **durably published** —
    /// "repaired and flagged" (#38 D6). A repair that loses the CAS is not
    /// flagged; it never landed.
    pub flagged_indexes: Vec<[u8; 16]>,
}

impl SweepOutcome {
    /// Whether re-running the idempotent pass could still convert something: a
    /// lost race whose winner may not have advanced the epoch, or a node the
    /// pass could not read for a reason a retry clears. A node no seed opens and
    /// a record the gate refused are settled — another pass answers identically.
    fn worth_another_pass(&self) -> bool {
        !self.dropped_lost_race.is_empty()
            || self
                .unreachable
                .iter()
                .any(|(_, reason)| reason.is_retryable())
    }

    /// The nodes this pass could not read, without the verdicts — what a caller
    /// proving convergence names as unconverged.
    pub fn unreachable_nodes(&self) -> impl Iterator<Item = [u8; 16]> + '_ {
        self.unreachable.iter().map(|(node_id, _)| *node_id)
    }
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
        /// The publish failure (never [`RotationPublishError::LostRace`] — a
        /// lost race drops the node and re-resolves).
        error: RotationPublishError,
    },
    /// The repaired direct-child-scope index could not be published.
    IndexRepair {
        /// The scope whose index repair did not land.
        scope_id: [u8; 16],
        /// The publish failure.
        error: RotationPublishError,
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
    nodes.dedup_by_key(|node| node.node_id);
    nodes
}

/// The in-scope children a gated read body names — the walk's frontier rule,
/// stated once for both the pure pass and the production resolver.
pub(crate) fn body_children(body: &ReadBody) -> Vec<NodeRef> {
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
            // One consult, one re-resolve.
            let repointed = ChildScopeRef::new(
                scope.scope_id,
                repointed_name(resolver, &scope.scope_id).await?,
            );
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
    scope: &ChildScopeRef,
    child: &NodeRef,
) -> Result<(NodeRef, SweptChild), SweepResolveFailure> {
    match resolver.resolve_child(scope, child).await {
        Ok(found) => Ok((child.clone(), found)),
        Err(SweepResolveFailure::Superseded) => {
            let node = NodeRef {
                node_id: child.node_id,
                ipns_name: repointed_name(resolver, &child.node_id).await?,
            };
            let found = resolver.resolve_child(scope, &node).await?;
            Ok((node, found))
        }
        Err(other) => Err(other),
    }
}

/// The scope's `currentRootName` from its pointer. A scope with no pointer has
/// no fresher name, so the below-floor record is refused as it stands.
async fn repointed_name<R: SweepResolver>(
    resolver: &R,
    scope_id: &[u8; 16],
) -> Result<Vec<u8>, SweepResolveFailure> {
    resolver
        .consult_pointer(scope_id)
        .await?
        .ok_or(SweepResolveFailure::Superseded)
}

/// Run one idempotent sweep pass over `scope`'s whole interior.
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
    walk_and_converge(resolver, publisher, scope, None).await
}

/// Converge just the subtree rooted at `node` inside `scope` — grant creation's
/// gate, which owes the epoch-converged guarantee over the folder it is sharing
/// and not over the whole scope it happens to sit in (#26 D2).
///
/// `node` itself is measured against the scope's epoch too: the granted folder
/// is an interior node until the mint publishes its new scope root over it.
pub async fn converge_subtree<R, P>(
    resolver: &R,
    publisher: &P,
    scope: &ChildScopeRef,
    node: &NodeRef,
) -> Result<SweepOutcome, SweepError>
where
    R: SweepResolver,
    P: SweepPublisher,
{
    walk_and_converge(resolver, publisher, scope, Some(node)).await
}

/// The one pass both entry points run: gate the scope root, walk from `from`
/// (or from the root's own body), self-heal the index, re-seal what lags.
async fn walk_and_converge<R, P>(
    resolver: &R,
    publisher: &P,
    scope: &ChildScopeRef,
    from: Option<&NodeRef>,
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
    // The single authoritative `node_id -> ipnsName` binding for this walk
    // ([`SweepResolveFailure::ConflictingChildLabel`]).
    let mut labels: BTreeMap<[u8; 16], Vec<u8>> = BTreeMap::new();
    // Scope roots the walk met that the index does not name (#38 D6), at the
    // name each resolved current at.
    let mut omitted: Vec<ChildScopeRef> = Vec::new();
    let mut lagging: Vec<(NodeRef, SweptNode)> = Vec::new();

    let mut frontier = match from {
        Some(node) => vec![node.clone()],
        None => swept.children,
    };
    bind_labels(&mut labels, &frontier).map_err(conflict)?;
    frontier = canonicalize_frontier(frontier);

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
            let (resolved, found) = match resolve_child_current(resolver, &scope_ref, child).await {
                Ok(pair) => pair,
                Err(reason) if reason.isolates_the_node() => {
                    outcome.unreachable.push((child.node_id, reason));
                    continue;
                }
                Err(reason) => {
                    return Err(SweepError::Node {
                        node_id: child.node_id,
                        reason,
                    });
                }
            };
            match found {
                SweptChild::ScopeRoot(scope_root) => {
                    outcome.skipped_scope_roots.push(child.node_id);
                    omitted.push(scope_root);
                }
                SweptChild::Interior(node) => {
                    let grandchildren = body_children(&node.read_body);
                    bind_labels(&mut labels, &grandchildren).map_err(conflict)?;
                    next.extend(grandchildren);
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
    // ADR 0003 D3). It repairs the whole invariant: the index the scope commits
    // to is canonical and names every scope root the walk observed.
    let mut index = canonicalize(&swept.direct_child_scope_index);
    for scope_root in &omitted {
        index = repair_observed(&index, scope_root.clone());
    }
    if index != swept.direct_child_scope_index {
        match publisher.repair_child_scope_index(&scope_ref, &index).await {
            Ok(()) => outcome
                .flagged_indexes
                .extend(omitted.iter().map(|root| root.scope_id)),
            // Never landed, so never flagged; the next pass re-derives it.
            Err(RotationPublishError::LostRace) => {}
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
            sequence: swept_node.sequence,
            read_body: &swept_node.read_body,
            carried_unknown: &swept_node.carried_unknown,
            carried_epoch_tag_unknown: &swept_node.carried_epoch_tag_unknown,
        };
        match publisher.publish_node(&scope_ref, &lagging_node).await {
            Ok(()) => outcome.converged.push(node.node_id),
            // The one spec-mandated non-abort per-node path. The winner may be a
            // non-advancing ordinary write, so the node is not proven converged;
            // `run_sweep` re-resolves it until a pass drops nothing.
            Err(RotationPublishError::LostRace) => outcome.dropped_lost_race.push(node.node_id),
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

/// Bind each ref's `node_id -> ipnsName` into `labels`, aborting on the C2
/// conflict: an id already bound to a **different** name. Returns the
/// conflicting id.
fn bind_labels(labels: &mut BTreeMap<[u8; 16], Vec<u8>>, refs: &[NodeRef]) -> Result<(), [u8; 16]> {
    for node in refs {
        match labels.get(&node.node_id) {
            Some(name) if name != &node.ipns_name => return Err(node.node_id),
            Some(_) => {}
            None => {
                labels.insert(node.node_id, node.ipns_name.clone());
            }
        }
    }
    Ok(())
}

fn conflict(node_id: [u8; 16]) -> SweepError {
    SweepError::Node {
        node_id,
        reason: SweepResolveFailure::ConflictingChildLabel,
    }
}

/// [`run_sweep`]'s outcome accumulated across its passes.
///
/// Across the passes of a completed run, durable work is a **union**: a node
/// re-sealed — or an index repaired and flagged — in an early pass stays reported
/// even though the final pass finds it already at the epoch, so a sibling forcing
/// a re-run cannot erase the host's only notice of an index self-heal (#38 D6).
///
/// The buckets the final pass re-derives are that pass's alone: each is read back
/// from published records every pass, so an earlier pass's answer no longer
/// holds. The union yields to them — a node the final pass could not read, or
/// that now reads as a descendant scope root, is reported only there, keeping
/// [`SweepOutcome`]'s one-node-one-bucket guarantee true of the aggregate as well
/// as of each pass. `flagged_indexes` is not in that partition: it records an
/// index repair, which by construction co-occurs with a skipped scope root.
#[derive(Default)]
struct Cumulative {
    converged: BTreeSet<[u8; 16]>,
    flagged_indexes: BTreeSet<[u8; 16]>,
    last: SweepOutcome,
}

impl Cumulative {
    fn absorb(&mut self, pass: SweepOutcome) {
        self.converged.extend(pass.converged.iter().copied());
        self.flagged_indexes
            .extend(pass.flagged_indexes.iter().copied());
        self.last = pass;
    }

    fn finish(self) -> SweepOutcome {
        let Self {
            mut converged,
            flagged_indexes,
            last,
        } = self;
        let final_verdicts: BTreeSet<[u8; 16]> = last
            .dropped_lost_race
            .iter()
            .copied()
            .chain(last.unreachable_nodes())
            .chain(last.skipped_scope_roots.iter().copied())
            .collect();
        converged.retain(|node| !final_verdicts.contains(node));
        SweepOutcome {
            // A node an early pass re-sealed reads as already-at-epoch later;
            // counting it in both buckets would claim it never needed work.
            already_converged: last
                .already_converged
                .into_iter()
                .filter(|node| !converged.contains(node))
                .collect(),
            converged: converged.into_iter().collect(),
            flagged_indexes: flagged_indexes.into_iter().collect(),
            dropped_lost_race: last.dropped_lost_race,
            skipped_scope_roots: last.skipped_scope_roots,
            unreachable: last.unreachable,
        }
    }
}

/// Drive the sweep as an idle-cadence job: run [`sweep_pass`] and re-run it, one
/// `cadence` sleep apart via the [`Scheduler`] seam, until a pass succeeds
/// leaving nothing a retry could still convert — the point convergence is
/// actually confirmed — or the `max_passes` cap is hit. A retryable availability
/// stall re-runs; a trust failure returns immediately.
///
/// On cap exhaustion it returns the last availability `Err`, or `Ok` with the
/// residual surfaced, so a host racing a persistently hot writer — or a name it
/// cannot fetch — sees what is left rather than a false "complete".
///
/// # Caller contract
///
/// An `Ok` outcome is convergence-complete **only when both
/// [`SweepOutcome::dropped_lost_race`] and [`SweepOutcome::unreachable`] are
/// empty**. The buckets aggregate across passes per [`Cumulative`]. An `Err`
/// reports no outcome at all: earlier passes' work is durable on the network,
/// but the run makes no convergence claim over it.
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
    let mut cumulative = Cumulative::default();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        match sweep_pass(resolver, publisher, scope).await {
            Ok(pass) => {
                let again = pass.worth_another_pass();
                cumulative.absorb(pass);
                if !again || attempts >= max_passes {
                    return Ok(cumulative.finish());
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

/// Drive the lazy wave as the blueprint's idle-cadence [`Scheduler`] job: idle
/// one `cadence`, sweep every scope `round` names, hand each result to `report`,
/// and repeat until a round answers `None` — session end (blueprint/engine.md
/// "sweep"). Determinism law: the only time source is `scheduler.sleep`.
///
/// The idle comes **first**, so a freshly spawned job never sweeps in the same
/// wake as the cut or the poll tick that spawned it.
///
/// Each scope gets **one** pass per round. The round is itself the retry: the
/// wave is idempotent and comes back every `cadence`, so spending in-round
/// passes on a contested scope would only stall every other scope behind it.
/// `report` is how the index self-heal and the residual buckets reach a host
/// that has no return value to read.
pub async fn run_sweep_job<S, R, P>(
    scheduler: &S,
    resolver: &R,
    publisher: &P,
    cadence: Duration,
    mut round: impl AsyncFnMut() -> Option<Vec<ChildScopeRef>>,
    report: impl Fn(&ChildScopeRef, &Result<SweepOutcome, SweepError>),
) where
    S: Scheduler,
    R: SweepResolver,
    P: SweepPublisher,
{
    loop {
        scheduler.sleep(cadence).await;
        let Some(scopes) = round().await else {
            return;
        };
        for scope in &scopes {
            let result = run_sweep(scheduler, resolver, publisher, scope, cadence, 1).await;
            report(scope, &result);
        }
    }
}

#[cfg(test)]
mod tests {
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
    /// one no fetch answers for. The unit of progress is a single interior node,
    /// so each is surfaced and stepped past rather than costing every other node
    /// in the scope its convergence.
    #[test]
    fn an_unreadable_node_is_isolated_and_the_rest_still_converges() {
        for reason in [
            SweepResolveFailure::Unreadable,
            SweepResolveFailure::Rejected,
            SweepResolveFailure::Unavailable,
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
    /// seed reaches or a record the gate refused — so the driver returns on the
    /// first pass with the node surfaced.
    #[test]
    fn a_settled_isolation_does_not_spend_the_drivers_passes() {
        for reason in [
            SweepResolveFailure::Unreadable,
            SweepResolveFailure::Rejected,
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
            .fault(0x01, RotationPublishError::NotPublished);
        let err = drive(&net, 3, 2).expect_err("the stall surfaces");
        assert_eq!(err.check(), "publish-failed");
        assert_eq!(net.publishes(0x01), 3, "one attempt per allowed pass");
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
}
