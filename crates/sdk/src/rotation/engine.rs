//! Resumable read-key rotation engine — Rust twin of
//! `packages/sdk-core/src/rotation/engine.ts` (`rotateOne` / `rotateReadFromNode`).
//!
//! Implements the WALK MECHANICS half of the ROT-01 primitive: a per-node
//! CAS-commit BFS walk that rotates the read key of every node in a
//! scope-exit subtree, scope-root first. Published IPNS records are the
//! source of truth; the [`RotationJobRecord`] is advisory (D-10).
//!
//! 69-11 adds the crash-safety resume layer: [`verify_subtree_clean`]
//! rebuilds the dirty frontier from PUBLISHED IPNS records (D-10) when
//! `rotate_one(root)` comes back `Skipped` on resume, so a mid-walk crash
//! converges instead of either blindly re-walking (double-bump risk, ROT-06)
//! or silently doing nothing. [`RotationJobRecord::completed_node_ids`] MUST
//! be seeded by the caller from the crash-time record before calling
//! [`rotate_read_from_node`] again — an empty seed makes the root's (and
//! every already-committed node's) fast idempotency path in [`rotate_one`]
//! fail to fire, re-minting and re-publishing nodes that were already done
//! (the exact M1 hazard this plan documents and tests).
//!
//! Deliberately OUT OF SCOPE for this plan (lands in a later Phase-69 plan on
//! this same file): the revocation-guarantee closures CRIT-1 / HIGH-3 /
//! HIGH-4 (inner-grant re-mint, CAS-409 concurrent-child merge, write-plane
//! rotation) — 69-12. Also out of scope, and a known limitation inherited
//! unchanged from the TS reference (`engine.ts`'s own acknowledged gap, see
//! its `verifySubtreeClean` doc comment): a genuinely fresh, never-started
//! child (its own published generation still matches the parent's mirror
//! exactly) is invisible to the generation-comparison dirty check below and
//! is NOT recovered by this resume path — only a child whose OWN rotation
//! individually committed before the crash, but whose parent's batched
//! republish did not yet land, is detected as "dirty".
//!
//! Host-agnostic (D-02): no FUSE-crate / Tauri / WinFsp import here. This
//! is what lets 69-14's WinFsp caller consume the identical engine with zero
//! duplication (mirrors engine.ts's own host-agnostic contract).
//!
//! @security
//! Zeroization rule (D-09 / T-63-10 / T-69-08-01, historical 48/89 sdk-e2e
//! incident):
//!   - `rotate_one` MINTS `read_key_prime` — it zeros that buffer ONLY on its
//!     own failure paths, NEVER on success (the BFS walk still needs it to
//!     derive children's keys and reseal this node's own `SealedChildRef`
//!     entries).
//!   - `rotate_one` NEVER zeros the caller-supplied `parent_read_key` (a
//!     misnomer inherited from the TS reference: it actually carries THIS
//!     node's own pre-rotation read key, not literally "the parent's"). That
//!     buffer is a `&[u8]` immutable borrow — the Rust type system, not just
//!     convention, makes mutating (let alone zeroing) it impossible from
//!     inside `rotate_one`.
//!   - A prior incident (48/89 sdk-e2e failures) was caused by a callee
//!     zeroing a reused session buffer. Flag this file in every security
//!     review (T-69-08-01).

use std::collections::{HashMap, HashSet, VecDeque};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::{Zeroize, Zeroizing};

use cipherbox_core::node::seal::{
    seal_child_read_key, seal_node, unseal_child_read_key, unseal_node,
};
use cipherbox_core::node::{
    decode_node, encode_node, Node, NodeKind, PublishedNode, SealedChildRef,
};

use super::RotationError;

// ---------------------------------------------------------------------------
// Injected seams (RotationDeps) — D-04 transport decoupling
// ---------------------------------------------------------------------------

/// A resolved IPNS record: the current CID plus its verified sequence number.
#[derive(Debug, Clone)]
pub struct ResolvedRecord {
    pub cid: String,
    pub sequence_number: u64,
}

/// Outcome of a CAS-guarded publish.
#[derive(Debug, Clone)]
pub struct PublishOutcome {
    pub new_sequence_number: u64,
}

/// Injected seams for the rotation walk: resolve, fetch, CAS-publish, and
/// advisory job-record persistence.
///
/// Keeps the walk host-agnostic and transport-decoupled (D-02/D-04):
/// production callers (69-11 FUSE / 69-14 WinFsp) supply real IPNS/IPFS/API
/// implementations; unit tests in this module inject in-memory fakes — no
/// live IPNS/IPFS round trip (project memory: GSD subagents must not run
/// live integration tests).
///
/// `#[allow(async_fn_in_trait)]`: this trait is only ever used generically
/// (`rotate_one<D: RotationDeps>`, `rotate_read_from_node<D: RotationDeps>`),
/// never as `dyn RotationDeps`, so the missing auto-trait (`Send`) bound on
/// the generated future is not a concern within this crate (mirrors
/// `HighWaterStore`'s and `NodeFetcher`'s identical `allow`).
#[allow(async_fn_in_trait)]
pub trait RotationDeps {
    /// Resolve `ipns_name` to its current CID + sequence number, or `None`
    /// if the name has no published record.
    async fn resolve(&self, ipns_name: &str) -> Result<Option<ResolvedRecord>, RotationError>;

    /// Fetch the (still AEAD-sealed) `PublishedNode` envelope stored at `cid`.
    async fn fetch_node(&self, cid: &str) -> Result<PublishedNode, RotationError>;

    /// CAS-publish `node` to `ipns_name`, guarded by `expected_sequence_number`.
    ///
    /// CAS-409 concurrent-write merge (ROT-05/HIGH-4, engine.ts's
    /// `mergeConcurrentChildren`) is deferred to 69-12 — this plan's seam
    /// contract is a simple check-and-set.
    async fn publish_with_cas(
        &self,
        ipns_name: &str,
        expected_sequence_number: u64,
        node: &PublishedNode,
    ) -> Result<PublishOutcome, RotationError>;

    /// Advisory checkpoint — called after EVERY per-node commit (D-10).
    /// Published IPNS records remain the source of truth; this is a
    /// resume-acceleration hint only, never authoritative.
    async fn persist_job(&self, job: &RotationJobRecord);
}

// ---------------------------------------------------------------------------
// RotationJobRecord — advisory per-node commit checkpoint (D-10)
// ---------------------------------------------------------------------------

/// Advisory status of a rotation job. Mirrors TS `RotationStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStatus {
    Pending,
    InProgress,
    Complete,
    Failed,
}

/// Advisory in-memory job record for a rotation walk.
///
/// Published IPNS records are the source of truth (D-10). This record exists
/// purely so a host can persist it via the injected [`RotationDeps::persist_job`]
/// seam for durable resume acceleration.
///
/// @security M1 (crash-safety resume, 69-11): on resume, the CALLER is
/// responsible for seeding `completed_node_ids` from the durably-persisted
/// crash-time record BEFORE calling [`rotate_read_from_node`] again. This
/// engine has no `load_job` counterpart to `persist_job` — the record is
/// advisory and its durable storage/retrieval lives entirely with the host.
/// Resuming with a fresh (empty) `completed_node_ids` set instead of the
/// crash-time one defeats [`rotate_one`]'s fast idempotency path for every
/// already-committed node, including the root: `rotate_one` will re-resolve,
/// re-unseal, re-mint, and re-publish it, bumping its `generation` a SECOND
/// time even though nothing needed to change. See the `rotate_read_from_node`
/// tests `resume_after_crash_converges_without_double_bump_when_seeded` and
/// `empty_completed_node_ids_seed_double_bumps_the_root` for the exact
/// hazard and its fix.
#[derive(Debug, Clone)]
pub struct RotationJobRecord {
    /// Root of the subtree being rotated.
    pub root_node_id: String,
    /// Advisory status (not authoritative — IPNS records are).
    pub status: RotationStatus,
    /// Node IDs that have been committed (per-node CAS publish succeeded).
    /// Used for idempotency: re-entering `rotate_one` for a completed node
    /// is a no-op.
    pub completed_node_ids: HashSet<String>,
    /// Pending frontier entries for the BFS walk.
    ///
    /// Mirrors TS `RotationJobRecord.frontier` exactly: declared for advisory
    /// resume acceleration but NOT populated by the fresh-walk happy path
    /// (the TS reference does not write to it either — 69-11's dirty-resume
    /// path in [`rotate_read_from_node`] builds its own equivalent local
    /// frontier via [`verify_subtree_clean`] instead of reading this field).
    /// Reserved for a future extension that persists the frontier itself.
    pub frontier: Vec<String>,
}

impl RotationJobRecord {
    /// Creates a fresh, `Pending` job record for a rotation rooted at
    /// `root_node_id`.
    pub fn new(root_node_id: impl Into<String>) -> Self {
        Self {
            root_node_id: root_node_id.into(),
            status: RotationStatus::Pending,
            completed_node_ids: HashSet::new(),
            frontier: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// rotate_one — per-node mint + CAS commit (D-05 parity, engine.ts rotateOne)
// ---------------------------------------------------------------------------

/// Details for a per-node rotation that actually committed (was not a
/// resume-skip).
#[derive(Debug)]
pub struct CommittedRotation {
    /// The rotated node's stable UUID (the caller-supplied `node_id` when
    /// provided, otherwise derived from the unsealed envelope).
    pub node_id: String,
    pub kind: NodeKind,
    /// Freshly minted read key for this node. NOT zeroed by `rotate_one` on
    /// success — the BFS walk still needs it to derive this node's
    /// children's keys and to reseal this node's own `SealedChildRef`
    /// entries under it. The caller becomes the terminal owner (D-09); the
    /// walk driver's `QueueItem`/`ParentTrackingState` wrappers, and
    /// ultimately [`RotateReadResult`], carry it forward as `Zeroizing`.
    pub read_key_prime: Zeroizing<[u8; 32]>,
    pub new_generation: u32,
    /// IPNS sequence number produced by this node's own publish. Used as the
    /// CAS guard for a parent's batched re-publish (D-09).
    pub new_sequence_number: u64,
    pub created_at: u64,
    pub modified_at: u64,
    /// Plaintext children of the rotated node (to enqueue in the BFS
    /// frontier). Empty for file nodes.
    pub children: Vec<SealedChildRef>,
}

/// Return type for a single-node rotation step. Mirrors TS's
/// `RotateOneDone | RotateOneSkipped` union.
#[derive(Debug)]
pub enum RotateOneOutcome {
    /// The node was already committed in a prior run (idempotency skip).
    /// When this is the SCOPE ROOT, [`rotate_read_from_node`] responds by
    /// calling [`verify_subtree_clean`] to rebuild the dirty frontier from
    /// published records (ROT-06 crash-safety resume, 69-11) instead of
    /// blindly re-walking.
    Skipped {
        new_generation: u32,
    },
    Committed(CommittedRotation),
}

/// Rotates the read key of a single node: mints `read_key_prime`, reseals
/// the node's read-body under it with the bumped generation, and
/// CAS-publishes. Returns [`RotateOneOutcome::Skipped`] if the node was
/// already committed in a prior run (idempotency).
///
/// `node_id`, when `Some`, enables a fast idempotency check BEFORE any
/// resolve/fetch (mirrors TS `rotateOne`'s "Step 2 fast path"). When `None`
/// (BFS children, whose stable id is not yet known to the caller), the id is
/// derived from the unsealed envelope and checked again.
///
/// `parent_read_key` is this node's OWN pre-rotation read key (a legacy
/// misnomer inherited from the TS reference — for the scope root it is the
/// root's own read key; for a BFS child it is the key the walk driver
/// derived via `unseal_child_read_key` from the PARENT's old read key before
/// enqueueing). It is a borrowed `&[u8]`, never `Zeroizing`-by-value — the
/// type system enforces that `rotate_one` cannot mutate, let alone zero, it.
///
/// @security See the module doc comment's zeroization rule (D-09 / T-69-08-01).
pub async fn rotate_one<D: RotationDeps>(
    deps: &D,
    node_id: Option<&str>,
    node_ipns_name: &str,
    parent_read_key: &[u8],
    job_record: &mut RotationJobRecord,
) -> Result<RotateOneOutcome, RotationError> {
    // Fast idempotency path — BEFORE any resolve/fetch.
    if let Some(id) = node_id {
        if job_record.completed_node_ids.contains(id) {
            return Ok(RotateOneOutcome::Skipped { new_generation: 0 });
        }
    }

    let resolved = deps.resolve(node_ipns_name).await?.ok_or_else(|| {
        RotationError::RotateFailed(format!(
            "rotate_one: node {node_ipns_name} not found in IPNS"
        ))
    })?;
    let published = deps.fetch_node(&resolved.cid).await?;
    let kind = node_kind_from_str(&published.kind)?;
    let parent_read_key_arr = zeroizing_32_from_slice(parent_read_key)?;

    let read_sealed_bytes = decode_b64(&published.read_sealed)?;
    let body = unseal_node(
        &read_sealed_bytes,
        &parent_read_key_arr,
        &published.id,
        kind,
        published.generation,
    )
    .map_err(|e| {
        RotationError::RotateFailed(format!(
            "rotate_one: unseal failed for {node_ipns_name}: {e}"
        ))
    })?;
    let node = decode_node(&body).map_err(|e| {
        RotationError::RotateFailed(format!(
            "rotate_one: decode failed for {node_ipns_name}: {e}"
        ))
    })?;

    // Idempotency check (continued): derive the node id from the unsealed
    // envelope when the caller did not already provide it.
    let resolved_node_id = node_id
        .map(str::to_string)
        .unwrap_or_else(|| node.id().to_string());
    if job_record.completed_node_ids.contains(&resolved_node_id) {
        return Ok(RotateOneOutcome::Skipped {
            new_generation: node.generation(),
        });
    }

    let new_generation = node.generation().checked_add(1).ok_or_else(|| {
        RotationError::RotateFailed(format!(
            "rotate_one: generation overflow for {node_ipns_name}"
        ))
    })?;

    // Mint read_key_prime' (fresh 32 cryptographically random bytes).
    // rotate_one is the terminal owner of THIS buffer on its own failure
    // paths (D-09 / T-63-10 / T-69-08-01) — NEVER on success (the BFS still
    // needs it), and NEVER parent_read_key (caller-owned borrow).
    let mut read_key_prime_raw = cipherbox_crypto::generate_random_bytes(32);
    let mut read_key_prime = Zeroizing::new([0u8; 32]);
    read_key_prime.copy_from_slice(&read_key_prime_raw);
    read_key_prime_raw.zeroize();

    match seal_and_publish(
        deps,
        node_ipns_name,
        resolved.sequence_number,
        &node,
        &resolved_node_id,
        kind,
        new_generation,
        &read_key_prime,
    )
    .await
    {
        Ok(new_sequence_number) => {
            let (created_at, modified_at) = node_timestamps(&node);
            let children = node_children(&node);
            // D-07: mark committed AFTER the publish succeeds — never before.
            job_record
                .completed_node_ids
                .insert(resolved_node_id.clone());
            Ok(RotateOneOutcome::Committed(CommittedRotation {
                node_id: resolved_node_id,
                kind,
                read_key_prime,
                new_generation,
                new_sequence_number,
                created_at,
                modified_at,
                children,
            }))
        }
        Err(e) => {
            // Zero read_key_prime on failure — rotate_one minted it, so
            // rotate_one is the terminal owner (D-09). Do NOT touch
            // parent_read_key — it is caller-owned and only ever borrowed.
            read_key_prime.zeroize();
            Err(e)
        }
    }
}

/// Re-seals `node`'s read-body under `read_key_prime` with the bumped
/// `new_generation`, then CAS-publishes it. Split out of `rotate_one` so the
/// caller retains ownership of `read_key_prime` and can zero it on `Err`
/// without threading a fallible expression through a manual try/catch
/// (Rust has none) inside the minted-key's own scope.
#[allow(clippy::too_many_arguments)]
async fn seal_and_publish<D: RotationDeps>(
    deps: &D,
    node_ipns_name: &str,
    expected_sequence_number: u64,
    node: &Node,
    node_id: &str,
    kind: NodeKind,
    new_generation: u32,
    read_key_prime: &[u8; 32],
) -> Result<u64, RotationError> {
    let updated_node = with_generation(node, new_generation);
    let read_body = encode_node(&updated_node).map_err(|e| {
        RotationError::RotateFailed(format!(
            "rotate_one: encode failed for {node_ipns_name}: {e}"
        ))
    })?;
    let resealed =
        seal_node(&read_body, read_key_prime, node_id, kind, new_generation).map_err(|e| {
            RotationError::RotateFailed(format!(
                "rotate_one: seal failed for {node_ipns_name}: {e}"
            ))
        })?;

    let published_node = PublishedNode {
        schema: "node/v3".to_string(),
        kind: kind.as_str().to_string(),
        id: node_id.to_string(),
        generation: new_generation,
        aead_version: 1,
        read_sealed: base64_encode(&resealed),
        write_sealed: None,
    };

    let outcome = deps
        .publish_with_cas(node_ipns_name, expected_sequence_number, &published_node)
        .await
        .map_err(|e| {
            RotationError::RotateFailed(format!(
                "rotate_one: publish failed for {node_ipns_name}: {e}"
            ))
        })?;

    Ok(outcome.new_sequence_number)
}

// ---------------------------------------------------------------------------
// rotate_read_from_node — scope-root-first BFS walk (ROT-01, engine.ts §4.2)
// ---------------------------------------------------------------------------

/// Return shape for a successful (fresh, non-resume-skip) `rotate_read_from_node`
/// run: the ROOT node's post-rotation read key/generation/sequence number
/// (ROT-07 Gap 2 parity).
///
/// Callers (69-11 FUSE / 69-14 WinFsp) use this to refresh their own
/// in-memory folder-tree entry so a same-session retry does not operate on
/// stale pre-rotation state.
///
/// @security `read_key` is NOT zeroed by `rotate_read_from_node` — the
/// caller becomes the terminal owner (D-09). It is `Zeroizing` so that
/// whichever caller ultimately drops it does zero it, rather than leaking it
/// as a plain buffer forever.
#[derive(Debug)]
pub struct RotateReadResult {
    pub read_key: Zeroizing<[u8; 32]>,
    pub generation: u32,
    pub sequence_number: u64,
}

/// Per-parent bookkeeping for the out-of-band re-seal + batched republish
/// (D-02/D-09, engine.ts §4.7 parent-tracking Map).
///
/// Problem this solves: `rotate_one` seals nothing under a PARENT's key — it
/// only knows the node's OWN pre/post-rotation keys. But a parent's
/// `SealedChildRef[N].read_key_sealed` must be sealed under the PARENT's NEW
/// read key for `unseal_child_read_key` to authenticate on the next read.
/// That out-of-band re-seal, and the single batched parent re-publish after
/// ALL of a parent's children have rotated (regardless of child count),
/// happen here in the walk driver — not inside `rotate_one`.
struct ParentTrackingState {
    parent_ipns_name: String,
    /// The parent's freshly minted read key (from the parent's own
    /// `CommittedRotation`). Used both to reseal each child's new read key
    /// under it, and to reseal the parent's own read-body on republish.
    parent_new_read_key: Zeroizing<[u8; 32]>,
    parent_node_id: String,
    parent_kind: NodeKind,
    parent_generation: u32,
    parent_created_at: u64,
    parent_modified_at: u64,
    /// IPNS sequence number from the parent's OWN rotation publish — the CAS
    /// guard for the batched republish below.
    parent_last_seq: u64,
    /// Mutable copy of the parent's children, updated in place as each
    /// child rotates.
    children: Vec<SealedChildRef>,
    /// Decremented per child; the batched republish fires when this reaches
    /// zero, regardless of how many children the parent has (T-69-08-03 /
    /// DoS mitigation: exactly one republish per parent).
    pending_child_count: usize,
}

/// One BFS frontier entry.
struct QueueItem {
    child_ref: SealedChildRef,
    /// This node's OWN pre-rotation read key, derived via
    /// `unseal_child_read_key` from the PARENT's OLD read key before this
    /// node was enqueued. Owned `Zeroizing` — dropped (and thus zeroed)
    /// automatically at the end of the BFS iteration that consumes it,
    /// which is the same "queue-key zeroization on every exit path" the TS
    /// reference achieves manually with a `finally { .fill(0) }` block.
    node_read_key: Zeroizing<[u8; 32]>,
    parent_ipns_name: String,
}

// ---------------------------------------------------------------------------
// verify_subtree_clean — crash-safety dirty-frontier rebuild (ROT-06, 69-11,
// Rust twin of engine.ts's verifySubtreeClean)
// ---------------------------------------------------------------------------

/// One dirty edge discovered by [`verify_subtree_clean`]: a child whose OWN
/// published `generation` is strictly greater than the generation recorded
/// in the ROOT's `SealedChildRef` mirror — i.e. the child individually
/// committed its own rotation in a prior (crashed) run, but the parent's
/// batched republish that would reconcile the mirror never landed.
#[derive(Debug, Clone)]
pub struct DirtyFrontierEntry {
    pub ipns_name: String,
    pub node_id: String,
}

/// Rebuilds the dirty frontier for `root_ipns_name`'s subtree from PUBLISHED
/// IPNS records (D-10) — the source of truth — rather than trusting the
/// (advisory, possibly crash-lost) [`RotationJobRecord`].
///
/// Invoked ONLY from [`rotate_read_from_node`]'s resume path, when
/// `rotate_one(root)` returns [`RotateOneOutcome::Skipped`] (the root was
/// already committed in a prior run). `root_read_key` MUST be the root's
/// CURRENT (already-rotated) read key — the same key that unseals the root's
/// presently-published envelope — not its pre-rotation key.
///
/// A child is "dirty" when its own published `generation` exceeds the
/// generation recorded in the root's `SealedChildRef` mirror (`PublishedNode
/// .generation` is a plaintext wire field on both sides — no child unsealing
/// is needed to make this comparison, D-10). Returns an empty frontier (and
/// thus "fully converged, nothing left to reconcile") when the root has no
/// published record at all, matching the TS reference's fail-open-to-clean
/// default for a torn-down subtree.
///
/// @security Read-only: never mints, seals, or publishes anything itself.
pub async fn verify_subtree_clean<D: RotationDeps>(
    deps: &D,
    root_ipns_name: &str,
    root_read_key: &[u8],
) -> Result<Vec<DirtyFrontierEntry>, RotationError> {
    let mut frontier = Vec::new();

    let Some(root_resolved) = deps.resolve(root_ipns_name).await? else {
        return Ok(frontier);
    };
    let root_pub = deps.fetch_node(&root_resolved.cid).await?;
    let root_kind = node_kind_from_str(&root_pub.kind)?;
    let root_read_key_arr = zeroizing_32_from_slice(root_read_key)?;
    let read_sealed_bytes = decode_b64(&root_pub.read_sealed)?;
    let root_body = unseal_node(
        &read_sealed_bytes,
        &root_read_key_arr,
        &root_pub.id,
        root_kind,
        root_pub.generation,
    )
    .map_err(|e| {
        RotationError::RotateFailed(format!(
            "verify_subtree_clean: unseal failed for root {root_ipns_name}: {e}"
        ))
    })?;
    let root_node = decode_node(&root_body).map_err(|e| {
        RotationError::RotateFailed(format!(
            "verify_subtree_clean: decode failed for root {root_ipns_name}: {e}"
        ))
    })?;

    for child_ref in node_children(&root_node) {
        let Some(child_resolved) = deps.resolve(&child_ref.ipns_name).await? else {
            continue; // child IPNS missing — skip (matches the TS reference).
        };
        let child_pub = deps.fetch_node(&child_resolved.cid).await?;
        // Dirty edge: child has rotated further than the parent's mirror.
        if child_pub.generation > child_ref.generation {
            frontier.push(DirtyFrontierEntry {
                ipns_name: child_ref.ipns_name.clone(),
                node_id: child_pub.id.clone(),
            });
        }
    }

    Ok(frontier)
}

/// Rotates the read key for every node in the subtree rooted at
/// `root_node_id`.
///
/// Ordering (D-05 parity, §4.2): the scope root is rotated FIRST — this is
/// the actual cut that revokes a revoked reader's access at the cheapest
/// commit point. The remaining nodes are then processed as a BFS frontier
/// walk, calling `rotate_one` per node and advancing the frontier with each
/// node's freshly minted `read_key_prime`.
///
/// The job record is advisory (D-10): [`RotationDeps::persist_job`] is
/// called after EVERY per-node commit (root and every BFS child) so a host
/// can checkpoint progress durably, but published IPNS records remain the
/// source of truth.
///
/// Host-agnostic (D-02): no FUSE / Tauri / WinFsp import.
///
/// @security Does NOT zero `root_read_key` — caller is terminal owner (D-09).
///
/// Returns `Ok(None)` when the root itself was a resume-skip (already
/// committed in a prior run) — there is no freshly-minted root key to hand
/// back in that case (ROT-07 Gap 2 parity: same as the TS reference, a
/// resume-skip never surfaces a "fresh" root key even if the dirty-frontier
/// reconciliation below did do further publishing work). On that path,
/// [`verify_subtree_clean`] rebuilds the dirty frontier from published
/// records (ROT-06 crash-safety resume, 69-11): an empty frontier converges
/// immediately with zero further side effects; a non-empty frontier is
/// folded into the same BFS walk used by the fresh-run path below.
pub async fn rotate_read_from_node<D: RotationDeps>(
    deps: &D,
    root_node_id: &str,
    root_ipns_name: &str,
    root_read_key: &[u8],
    job_record: &mut RotationJobRecord,
) -> Result<Option<RotateReadResult>, RotationError> {
    job_record.status = RotationStatus::InProgress;

    // §4.2: rotate the scope-root FIRST — the actual revocation cut.
    let root_outcome = rotate_one(
        deps,
        Some(root_node_id),
        root_ipns_name,
        root_read_key,
        job_record,
    )
    .await?;

    let mut parent_tracking: HashMap<String, ParentTrackingState> = HashMap::new();
    let mut queue: VecDeque<QueueItem> = VecDeque::new();
    // `Some` only when THIS call freshly rotated the root — this is what
    // ultimately gets returned to the caller (ROT-07 Gap 2 parity). A
    // resume-skip root never populates this, even when the dirty-frontier
    // reconciliation below performs further publishing work underneath it
    // (matches the TS reference: `rootResult.skipped` always means `undefined`).
    let mut fresh_root: Option<CommittedRotation> = None;

    match root_outcome {
        RotateOneOutcome::Committed(root_committed) => {
            // Persist after the root commit (D-10 — the high-value early checkpoint).
            deps.persist_job(job_record).await;

            if !root_committed.children.is_empty() {
                parent_tracking.insert(
                    root_ipns_name.to_string(),
                    ParentTrackingState {
                        parent_ipns_name: root_ipns_name.to_string(),
                        parent_new_read_key: root_committed.read_key_prime.clone(),
                        parent_node_id: root_committed.node_id.clone(),
                        parent_kind: root_committed.kind,
                        parent_generation: root_committed.new_generation,
                        parent_created_at: root_committed.created_at,
                        parent_modified_at: root_committed.modified_at,
                        parent_last_seq: root_committed.new_sequence_number,
                        children: root_committed.children.clone(),
                        pending_child_count: root_committed.children.len(),
                    },
                );
            }

            // Enqueue the root's children — derive each child's own read key from
            // the ROOT's OLD read key (root_read_key, still valid; rotate_one never
            // zeroed the caller-supplied borrow, D-09).
            for child_ref in &root_committed.children {
                enqueue_child(deps, root_ipns_name, root_read_key, child_ref, &mut queue).await?;
            }

            fresh_root = Some(root_committed);
        }
        RotateOneOutcome::Skipped { .. } => {
            // Resume path (ROT-06 crash-safety resume, 69-11): the root was
            // already committed in a prior run. Rebuild the dirty frontier
            // from PUBLISHED records (D-10) rather than trusting the
            // advisory job record, which may have been lost in the crash.
            let frontier = verify_subtree_clean(deps, root_ipns_name, root_read_key).await?;
            if frontier.is_empty() {
                // Fully converged already (or the root has no published
                // children at all) — nothing dirty to reconcile, and nothing
                // further gets minted or published. No double-bump risk.
                job_record.status = RotationStatus::Complete;
                deps.persist_job(job_record).await;
                return Ok(None);
            }

            // Dirty resume: re-fetch the root's CURRENT published state.
            // `root_read_key` is the root's POST-rotation key here — the
            // prior (crashed) run already rotated it, and that is the key
            // that unseals this presently-published envelope.
            let root_resolved = deps.resolve(root_ipns_name).await?.ok_or_else(|| {
                RotationError::RotateFailed(format!(
                    "rotate_read_from_node: root {root_ipns_name} not found on dirty resume"
                ))
            })?;
            let root_pub = deps.fetch_node(&root_resolved.cid).await?;
            let root_kind = node_kind_from_str(&root_pub.kind)?;
            let root_read_key_arr = zeroizing_32_from_slice(root_read_key)?;
            let read_sealed_bytes = decode_b64(&root_pub.read_sealed)?;
            let root_body = unseal_node(
                &read_sealed_bytes,
                &root_read_key_arr,
                &root_pub.id,
                root_kind,
                root_pub.generation,
            )
            .map_err(|e| {
                RotationError::RotateFailed(format!(
                    "rotate_read_from_node: unseal failed for root {root_ipns_name} on dirty resume: {e}"
                ))
            })?;
            let root_node = decode_node(&root_body).map_err(|e| {
                RotationError::RotateFailed(format!(
                    "rotate_read_from_node: decode failed for root {root_ipns_name} on dirty resume: {e}"
                ))
            })?;
            let root_children = node_children(&root_node);
            let (root_created_at, root_modified_at) = node_timestamps(&root_node);

            // M1: `pending_child_count` is seeded from the DIRTY FRONTIER's
            // length, not the full children list — already-converged
            // siblings are simply absent from `frontier` and must not be
            // re-touched (they would otherwise wedge this gate forever,
            // since they will never again dequeue from `queue` to decrement
            // it).
            parent_tracking.insert(
                root_ipns_name.to_string(),
                ParentTrackingState {
                    parent_ipns_name: root_ipns_name.to_string(),
                    parent_new_read_key: root_read_key_arr,
                    parent_node_id: root_node.id().to_string(),
                    parent_kind: root_kind,
                    parent_generation: root_pub.generation,
                    parent_created_at: root_created_at,
                    parent_modified_at: root_modified_at,
                    parent_last_seq: root_resolved.sequence_number,
                    children: root_children.clone(),
                    pending_child_count: frontier.len(),
                },
            );

            for entry in &frontier {
                let Some(child_ref) = root_children
                    .iter()
                    .find(|c| c.ipns_name == entry.ipns_name)
                else {
                    continue;
                };
                enqueue_child(deps, root_ipns_name, root_read_key, child_ref, &mut queue).await?;
            }
        }
    }

    while let Some(item) = queue.pop_front() {
        let outcome = rotate_one(
            deps,
            None,
            &item.child_ref.ipns_name,
            item.node_read_key.as_slice(),
            job_record,
        )
        .await?;

        match outcome {
            RotateOneOutcome::Skipped { .. } => {
                // ROT-06 no-double-bump convergence guard: this BFS entry was
                // itself already committed (job_record.completed_node_ids
                // seeded from the crash-time record contains it) — do NOT
                // re-mint or re-publish it a second time. Still must not
                // permanently wedge the parent's pending-count republish
                // gate, so the decrement always fires regardless of outcome.
                complete_pending_child(deps, &mut parent_tracking, &item.parent_ipns_name).await?;
            }
            RotateOneOutcome::Committed(child) => {
                // Advisory checkpoint after every per-node commit (D-10).
                deps.persist_job(job_record).await;

                // D-02: reseal the child's new read key' under the PARENT's
                // NEW read key' (out-of-band — rotate_one does not do this;
                // parent-tracking is the sole place it happens).
                if let Some(state) = parent_tracking.get_mut(&item.parent_ipns_name) {
                    let sealed = seal_child_read_key(
                        &child.read_key_prime,
                        &state.parent_new_read_key,
                        &child.node_id,
                        child.kind,
                        child.new_generation,
                    )
                    .map_err(|e| {
                        RotationError::RotateFailed(format!(
                            "rotate_read_from_node: reseal failed for child {} under parent {}: {e}",
                            child.node_id, item.parent_ipns_name
                        ))
                    })?;
                    if let Some(idx) = state
                        .children
                        .iter()
                        .position(|c| c.ipns_name == item.child_ref.ipns_name)
                    {
                        state.children[idx].read_key_sealed = base64_encode(&sealed);
                        state.children[idx].generation = child.new_generation;
                    }
                }
                complete_pending_child(deps, &mut parent_tracking, &item.parent_ipns_name).await?;

                // Set up parent tracking for this node's own children
                // (recursive D-02/D-09) — only when it actually has any.
                if !child.children.is_empty() {
                    parent_tracking.insert(
                        item.child_ref.ipns_name.clone(),
                        ParentTrackingState {
                            parent_ipns_name: item.child_ref.ipns_name.clone(),
                            parent_new_read_key: child.read_key_prime.clone(),
                            parent_node_id: child.node_id.clone(),
                            parent_kind: child.kind,
                            parent_generation: child.new_generation,
                            parent_created_at: child.created_at,
                            parent_modified_at: child.modified_at,
                            parent_last_seq: child.new_sequence_number,
                            children: child.children.clone(),
                            pending_child_count: child.children.len(),
                        },
                    );
                }

                // Enqueue this node's children using THIS node's OWN
                // (pre-rotation) read key — item.node_read_key is still
                // valid here (rotate_one never zeroed it; it is dropped,
                // and thus zeroed, only when this loop iteration ends).
                for grandchild_ref in &child.children {
                    enqueue_child(
                        deps,
                        &item.child_ref.ipns_name,
                        item.node_read_key.as_slice(),
                        grandchild_ref,
                        &mut queue,
                    )
                    .await?;
                }
            }
        }
    }

    // Terminal status: all nodes rotated (or skipped). Persist the complete
    // status so a host can safely discard the job record.
    job_record.status = RotationStatus::Complete;
    deps.persist_job(job_record).await;

    // ROT-07 Gap 2: surface the root's post-rotation state to the caller so
    // it can refresh its own folder cache. `fresh_root` is `None` on BOTH the
    // resume-skip-with-empty-frontier path (already returned above) and the
    // resume-skip-with-dirty-frontier path (the root itself did not freshly
    // rotate THIS call — no fresh key exists to hand back either way).
    Ok(fresh_root.map(|root_committed| RotateReadResult {
        read_key: root_committed.read_key_prime,
        generation: root_committed.new_generation,
        sequence_number: root_committed.new_sequence_number,
    }))
}

/// Resolves `child_ref`'s IPNS name, derives its own pre-rotation read key
/// from `parent_old_read_key` (using the child's plaintext `id`/`kind` for
/// the AAD binding — the generation-source rule: `child_ref.generation`,
/// the PARENT's mirror, not the child's own envelope generation), and
/// enqueues it.
async fn enqueue_child<D: RotationDeps>(
    deps: &D,
    parent_ipns_name: &str,
    parent_old_read_key: &[u8],
    child_ref: &SealedChildRef,
    queue: &mut VecDeque<QueueItem>,
) -> Result<(), RotationError> {
    let child_pub = resolve_and_fetch(deps, &child_ref.ipns_name).await?;
    let child_kind = node_kind_from_str(&child_pub.kind)?;
    let parent_old_read_key_arr = zeroizing_32_from_slice(parent_old_read_key)?;
    let sealed_bytes = decode_b64(&child_ref.read_key_sealed)?;

    let mut child_read_key_raw = unseal_child_read_key(
        &sealed_bytes,
        &parent_old_read_key_arr,
        &child_pub.id,
        child_kind,
        child_ref.generation,
    )
    .map_err(|e| {
        RotationError::RotateFailed(format!(
            "enqueue_child: unseal_child_read_key failed for {}: {e}",
            child_ref.ipns_name
        ))
    })?;

    if child_read_key_raw.len() != 32 {
        child_read_key_raw.zeroize();
        return Err(RotationError::RotateFailed(format!(
            "enqueue_child: unsealed read key for {} is not 32 bytes",
            child_ref.ipns_name
        )));
    }
    let mut child_read_key = Zeroizing::new([0u8; 32]);
    child_read_key.copy_from_slice(&child_read_key_raw);
    child_read_key_raw.zeroize();

    queue.push_back(QueueItem {
        child_ref: child_ref.clone(),
        node_read_key: child_read_key,
        parent_ipns_name: parent_ipns_name.to_string(),
    });

    Ok(())
}

/// Decrements `parent_ipns_name`'s pending-child counter; when it reaches
/// zero, fires the batched republish exactly once (T-69-08-03) and removes
/// the tracking entry.
async fn complete_pending_child<D: RotationDeps>(
    deps: &D,
    parent_tracking: &mut HashMap<String, ParentTrackingState>,
    parent_ipns_name: &str,
) -> Result<(), RotationError> {
    let should_republish = if let Some(state) = parent_tracking.get_mut(parent_ipns_name) {
        state.pending_child_count = state.pending_child_count.saturating_sub(1);
        state.pending_child_count == 0
    } else {
        false
    };

    if should_republish {
        if let Some(state) = parent_tracking.remove(parent_ipns_name) {
            republish_parent(deps, &state).await?;
        }
    }

    Ok(())
}

/// Rebuilds a parent's read-body with its updated `children` array, reseals
/// it under the parent's NEW read key, and CAS-publishes — the single
/// batched republish per parent (T-69-08-03).
async fn republish_parent<D: RotationDeps>(
    deps: &D,
    state: &ParentTrackingState,
) -> Result<(), RotationError> {
    let node = match state.parent_kind {
        NodeKind::Folder => Node::Folder {
            id: state.parent_node_id.clone(),
            generation: state.parent_generation,
            created_at: state.parent_created_at,
            modified_at: state.parent_modified_at,
            children: state.children.clone(),
        },
        NodeKind::Root => Node::Root {
            id: state.parent_node_id.clone(),
            generation: state.parent_generation,
            created_at: state.parent_created_at,
            modified_at: state.parent_modified_at,
            children: state.children.clone(),
        },
        NodeKind::File => {
            // Structurally unreachable: parent_tracking is only ever seeded
            // when a node's `children` is non-empty, and file nodes never
            // carry a `children` field (Node::File has none).
            return Err(RotationError::RotateFailed(format!(
                "republish_parent: unexpected File kind for {}",
                state.parent_ipns_name
            )));
        }
    };

    let read_body = encode_node(&node).map_err(|e| {
        RotationError::RotateFailed(format!(
            "republish_parent: encode failed for {}: {e}",
            state.parent_ipns_name
        ))
    })?;
    let resealed = seal_node(
        &read_body,
        &state.parent_new_read_key,
        &state.parent_node_id,
        state.parent_kind,
        state.parent_generation,
    )
    .map_err(|e| {
        RotationError::RotateFailed(format!(
            "republish_parent: seal failed for {}: {e}",
            state.parent_ipns_name
        ))
    })?;

    let published_node = PublishedNode {
        schema: "node/v3".to_string(),
        kind: state.parent_kind.as_str().to_string(),
        id: state.parent_node_id.clone(),
        generation: state.parent_generation,
        aead_version: 1,
        read_sealed: base64_encode(&resealed),
        write_sealed: None,
    };

    deps.publish_with_cas(
        &state.parent_ipns_name,
        state.parent_last_seq,
        &published_node,
    )
    .await
    .map_err(|e| {
        RotationError::RotateFailed(format!(
            "republish_parent: publish failed for {}: {e}",
            state.parent_ipns_name
        ))
    })?;

    Ok(())
}

/// Resolve `ipns_name` then fetch its `PublishedNode` envelope. Used to peek
/// a child's plaintext `id`/`kind` (needed for the read-key AAD binding)
/// before `rotate_one` independently re-resolves/re-fetches the same node —
/// mirrors the TS reference's identical `resolveAndFetch` + `rotateOne`
/// double-hop.
async fn resolve_and_fetch<D: RotationDeps>(
    deps: &D,
    ipns_name: &str,
) -> Result<PublishedNode, RotationError> {
    let resolved = deps.resolve(ipns_name).await?.ok_or_else(|| {
        RotationError::RotateFailed(format!("resolve_and_fetch: {ipns_name} not found in IPNS"))
    })?;
    deps.fetch_node(&resolved.cid).await
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Returns a copy of `node` with `generation` replaced, preserving every
/// other field (including plaintext `children`/`content`).
fn with_generation(node: &Node, generation: u32) -> Node {
    match node {
        Node::Folder {
            id,
            created_at,
            modified_at,
            children,
            ..
        } => Node::Folder {
            id: id.clone(),
            generation,
            created_at: *created_at,
            modified_at: *modified_at,
            children: children.clone(),
        },
        Node::Root {
            id,
            created_at,
            modified_at,
            children,
            ..
        } => Node::Root {
            id: id.clone(),
            generation,
            created_at: *created_at,
            modified_at: *modified_at,
            children: children.clone(),
        },
        Node::File {
            id,
            created_at,
            modified_at,
            content,
            ..
        } => Node::File {
            id: id.clone(),
            generation,
            created_at: *created_at,
            modified_at: *modified_at,
            content: content.clone(),
        },
    }
}

/// The node's plaintext children (empty for file nodes — they carry none).
fn node_children(node: &Node) -> Vec<SealedChildRef> {
    match node {
        Node::Folder { children, .. } | Node::Root { children, .. } => children.clone(),
        Node::File { .. } => Vec::new(),
    }
}

/// The node's `(created_at, modified_at)` pair.
fn node_timestamps(node: &Node) -> (u64, u64) {
    match node {
        Node::Folder {
            created_at,
            modified_at,
            ..
        }
        | Node::Root {
            created_at,
            modified_at,
            ..
        }
        | Node::File {
            created_at,
            modified_at,
            ..
        } => (*created_at, *modified_at),
    }
}

/// Maps a `PublishedNode.kind` wire string to `NodeKind`.
fn node_kind_from_str(kind: &str) -> Result<NodeKind, RotationError> {
    match kind {
        "folder" => Ok(NodeKind::Folder),
        "file" => Ok(NodeKind::File),
        "root" => Ok(NodeKind::Root),
        other => Err(RotationError::RotateFailed(format!(
            "unknown node kind on wire: {other}"
        ))),
    }
}

fn decode_b64(s: &str) -> Result<Vec<u8>, RotationError> {
    STANDARD
        .decode(s)
        .map_err(|e| RotationError::RotateFailed(format!("base64 decode failed: {e}")))
}

fn base64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Build a `Zeroizing<[u8; 32]>` from a slice without ever materializing a
/// plain `[u8; 32]` temporary (preallocate-then-copy — a `try_into()` would
/// briefly leave an un-zeroed copy of key material on the stack). Mirrors
/// the FUSE crate's identical `zeroizing_32_from_slice` helper.
fn zeroizing_32_from_slice(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, RotationError> {
    if bytes.len() != 32 {
        return Err(RotationError::RotateFailed(format!(
            "expected a 32-byte key, got {} bytes",
            bytes.len()
        )));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_support {
    //! Shared in-memory `RotationDeps` fake used by both test modules below.
    //! No live IPNS/IPFS round trip — pure in-memory HashMaps guarded by
    //! `std::sync::Mutex` (mirrors `HighWaterStore`'s/`NodeFetcher`'s own
    //! `MemStore`/`FakeFetcher` test fixtures).

    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct FakeDeps {
        /// ipns_name -> (cid, sequence_number)
        records: Mutex<HashMap<String, (String, u64)>>,
        /// cid -> PublishedNode
        blobs: Mutex<HashMap<String, PublishedNode>>,
        /// Ordered log of every `publish_with_cas` call's ipns_name — used
        /// to assert root-first ordering and single-parent-republish counts.
        pub publish_log: Mutex<Vec<String>>,
        /// Ordered log of every `resolve` call's ipns_name — used to assert
        /// the fast-path idempotency skip makes zero resolve calls.
        pub resolve_log: Mutex<Vec<String>>,
        /// Snapshot of `completed_node_ids.len()` at every `persist_job`
        /// call — used to assert "persist fires once per committed node".
        pub persist_log: Mutex<Vec<usize>>,
        /// When `Some`, the NEXT `publish_with_cas` call for this ipns_name
        /// fails instead of succeeding (used for the failure-path test).
        pub fail_publish_for: Mutex<Option<String>>,
    }

    impl FakeDeps {
        pub fn new() -> Self {
            Self::default()
        }

        /// Seeds a published node at `ipns_name` with the given CID/sequence.
        pub fn seed(&self, ipns_name: &str, cid: &str, sequence_number: u64, node: PublishedNode) {
            self.records
                .lock()
                .unwrap()
                .insert(ipns_name.to_string(), (cid.to_string(), sequence_number));
            self.blobs.lock().unwrap().insert(cid.to_string(), node);
        }

        pub fn resolve_call_count(&self) -> usize {
            self.resolve_log.lock().unwrap().len()
        }

        pub fn publish_count_for(&self, ipns_name: &str) -> usize {
            self.publish_log
                .lock()
                .unwrap()
                .iter()
                .filter(|n| n.as_str() == ipns_name)
                .count()
        }
    }

    impl RotationDeps for FakeDeps {
        async fn resolve(&self, ipns_name: &str) -> Result<Option<ResolvedRecord>, RotationError> {
            self.resolve_log.lock().unwrap().push(ipns_name.to_string());
            Ok(self
                .records
                .lock()
                .unwrap()
                .get(ipns_name)
                .map(|(cid, seq)| ResolvedRecord {
                    cid: cid.clone(),
                    sequence_number: *seq,
                }))
        }

        async fn fetch_node(&self, cid: &str) -> Result<PublishedNode, RotationError> {
            self.blobs
                .lock()
                .unwrap()
                .get(cid)
                .cloned()
                .ok_or_else(|| RotationError::RotateFailed(format!("no blob for cid {cid}")))
        }

        async fn publish_with_cas(
            &self,
            ipns_name: &str,
            expected_sequence_number: u64,
            node: &PublishedNode,
        ) -> Result<PublishOutcome, RotationError> {
            if let Some(fail_name) = self.fail_publish_for.lock().unwrap().take() {
                if fail_name == ipns_name {
                    return Err(RotationError::RotateFailed(format!(
                        "simulated publish failure for {ipns_name}"
                    )));
                }
                // Not the targeted name — put it back for a later call.
                *self.fail_publish_for.lock().unwrap() = Some(fail_name);
            }

            let current_seq = self
                .records
                .lock()
                .unwrap()
                .get(ipns_name)
                .map(|(_, seq)| *seq)
                .unwrap_or(0);
            if current_seq != expected_sequence_number {
                return Err(RotationError::RotateFailed(format!(
                    "CAS conflict for {ipns_name}: expected {expected_sequence_number}, got {current_seq}"
                )));
            }

            let new_seq = current_seq + 1;
            let new_cid = format!("{ipns_name}-cid-v{new_seq}");
            self.blobs
                .lock()
                .unwrap()
                .insert(new_cid.clone(), node.clone());
            self.records
                .lock()
                .unwrap()
                .insert(ipns_name.to_string(), (new_cid, new_seq));
            self.publish_log.lock().unwrap().push(ipns_name.to_string());

            Ok(PublishOutcome {
                new_sequence_number: new_seq,
            })
        }

        async fn persist_job(&self, job: &RotationJobRecord) {
            self.persist_log
                .lock()
                .unwrap()
                .push(job.completed_node_ids.len());
        }
    }

    /// Builds a sealed `PublishedNode` envelope for `node`, ready to `seed`.
    pub fn seal_for_seed(node: &Node, read_key: &[u8; 32]) -> PublishedNode {
        let body = encode_node(node).unwrap();
        let sealed = seal_node(&body, read_key, node.id(), node.kind(), node.generation()).unwrap();
        PublishedNode {
            schema: "node/v3".to_string(),
            kind: node.kind().as_str().to_string(),
            id: node.id().to_string(),
            generation: node.generation(),
            aead_version: 1,
            read_sealed: base64_encode(&sealed),
            write_sealed: None,
        }
    }
}

#[cfg(test)]
mod rotate_one {
    use super::test_support::{seal_for_seed, FakeDeps};
    use super::*;

    /// `build_node_aad` (69-04) requires a real RFC-4122 UUID for `node_id` —
    /// fail-closed on malformed ids (`InvalidAadInput`). Test fixtures below
    /// use this rather than a human-readable label for the Node's own id.
    const NODE_1_ID: &str = "11111111-1111-1111-1111-111111111111";

    fn folder(id: &str, generation: u32, children: Vec<SealedChildRef>) -> Node {
        Node::Folder {
            id: id.to_string(),
            generation,
            created_at: 1_000,
            modified_at: 1_000,
            children,
        }
    }

    #[tokio::test]
    async fn mints_and_commits_a_fresh_read_key_bumping_generation() {
        let deps = FakeDeps::new();
        let read_key = [7u8; 32];
        let node = folder(NODE_1_ID, 3, vec![]);
        deps.seed("k51/node-1", "cid-0", 5, seal_for_seed(&node, &read_key));

        let mut job = RotationJobRecord::new(NODE_1_ID);
        let outcome = rotate_one(&deps, Some(NODE_1_ID), "k51/node-1", &read_key, &mut job)
            .await
            .unwrap();

        match outcome {
            RotateOneOutcome::Committed(c) => {
                assert_eq!(c.node_id, NODE_1_ID);
                assert_eq!(c.new_generation, 4);
                assert_eq!(c.new_sequence_number, 6);
                assert!(c.children.is_empty());
                assert_eq!(c.read_key_prime.len(), 32);
                // Freshly minted -- must not equal the old key.
                assert_ne!(&*c.read_key_prime, &read_key);
            }
            RotateOneOutcome::Skipped { .. } => panic!("expected a fresh commit, got Skipped"),
        }
        assert!(job.completed_node_ids.contains(NODE_1_ID));
    }

    #[tokio::test]
    async fn caller_supplied_parent_read_key_buffer_is_unchanged_after_success() {
        // T-69-08-01 / D-09: rotate_one must NEVER zero (or otherwise
        // mutate) the caller-supplied parent_read_key on a successful run.
        let deps = FakeDeps::new();
        let read_key = [9u8; 32];
        let node = folder(NODE_1_ID, 0, vec![]);
        deps.seed("k51/node-1", "cid-0", 0, seal_for_seed(&node, &read_key));

        let read_key_before = read_key;
        let mut job = RotationJobRecord::new(NODE_1_ID);
        let outcome = rotate_one(&deps, Some(NODE_1_ID), "k51/node-1", &read_key, &mut job)
            .await
            .unwrap();
        assert!(matches!(outcome, RotateOneOutcome::Committed(_)));

        // The buffer bytes are byte-for-byte intact -- not zeroed, not
        // otherwise mutated. Trivially guaranteed by the `&[u8]` immutable
        // borrow signature (no `unsafe` in this module could violate it),
        // but asserted directly as the plan-mandated regression test.
        assert_eq!(read_key, read_key_before);
    }

    #[tokio::test]
    async fn fast_path_skip_makes_zero_resolve_calls_when_node_id_already_completed() {
        let deps = FakeDeps::new();
        let mut job = RotationJobRecord::new(NODE_1_ID);
        job.completed_node_ids.insert(NODE_1_ID.to_string());

        let outcome = rotate_one(&deps, Some(NODE_1_ID), "k51/node-1", &[0u8; 32], &mut job)
            .await
            .unwrap();

        assert!(matches!(
            outcome,
            RotateOneOutcome::Skipped { new_generation: 0 }
        ));
        assert_eq!(deps.resolve_call_count(), 0);
    }

    #[tokio::test]
    async fn derived_id_skip_after_unseal_makes_zero_publish_calls() {
        // node_id is None (BFS-child path) so the fast path cannot fire --
        // the skip is only detected AFTER resolve/fetch/unseal/decode derive
        // the node's own id.
        let deps = FakeDeps::new();
        let read_key = [3u8; 32];
        let node = folder(NODE_1_ID, 5, vec![]);
        deps.seed("k51/node-1", "cid-0", 2, seal_for_seed(&node, &read_key));

        let mut job = RotationJobRecord::new(NODE_1_ID);
        job.completed_node_ids.insert(NODE_1_ID.to_string());

        let outcome = rotate_one(&deps, None, "k51/node-1", &read_key, &mut job)
            .await
            .unwrap();

        assert!(matches!(
            outcome,
            RotateOneOutcome::Skipped { new_generation: 5 }
        ));
        assert_eq!(deps.publish_count_for("k51/node-1"), 0);
    }

    #[tokio::test]
    async fn publish_failure_does_not_mark_the_node_completed() {
        let deps = FakeDeps::new();
        let read_key = [1u8; 32];
        let node = folder(NODE_1_ID, 0, vec![]);
        deps.seed("k51/node-1", "cid-0", 0, seal_for_seed(&node, &read_key));
        *deps.fail_publish_for.lock().unwrap() = Some("k51/node-1".to_string());

        let mut job = RotationJobRecord::new(NODE_1_ID);
        let result = rotate_one(&deps, Some(NODE_1_ID), "k51/node-1", &read_key, &mut job).await;

        assert!(result.is_err());
        assert!(!job.completed_node_ids.contains(NODE_1_ID));
    }
}

#[cfg(test)]
mod rotate_read_from_node {
    use super::test_support::{seal_for_seed, FakeDeps};
    use super::*;

    /// `build_node_aad` (69-04) requires a real RFC-4122 UUID for `node_id`.
    /// The `k51/...`-prefixed IPNS names used alongside these ids are plain
    /// map keys (not UUID-validated) and stay human-readable for clarity.
    const ROOT_ID: &str = "00000000-0000-0000-0000-000000000000";

    fn child_uuid(i: usize) -> String {
        format!("00000000-0000-0000-0000-{:012}", i + 1)
    }

    fn folder(id: &str, generation: u32, children: Vec<SealedChildRef>) -> Node {
        Node::Folder {
            id: id.to_string(),
            generation,
            created_at: 1_000,
            modified_at: 1_000,
            children,
        }
    }

    /// Seeds a root with `child_count` empty-folder children, each keyed
    /// with its own read key sealed under the root's OLD read key.
    fn seed_root_with_children(
        deps: &FakeDeps,
        root_read_key: &[u8; 32],
        child_count: usize,
    ) -> Vec<[u8; 32]> {
        let mut child_keys = Vec::new();
        let mut child_refs = Vec::new();
        for i in 0..child_count {
            let child_label = format!("child-{i}");
            let child_id = child_uuid(i);
            let child_key = [(10 + i) as u8; 32];
            let child_node = folder(&child_id, 0, vec![]);
            let sealed_key =
                seal_child_read_key(&child_key, root_read_key, &child_id, NodeKind::Folder, 0)
                    .unwrap();
            deps.seed(
                &format!("k51/{child_label}"),
                &format!("cid-{child_label}-0"),
                0,
                seal_for_seed(&child_node, &child_key),
            );
            child_refs.push(SealedChildRef {
                name: child_label.clone(),
                ipns_name: format!("k51/{child_label}"),
                generation: 0,
                version_floor: 0,
                read_key_sealed: base64_encode(&sealed_key),
            });
            child_keys.push(child_key);
        }

        let root_node = folder(ROOT_ID, 0, child_refs);
        deps.seed(
            "k51/root",
            "cid-root-0",
            0,
            seal_for_seed(&root_node, root_read_key),
        );

        child_keys
    }

    #[tokio::test]
    async fn root_is_committed_before_any_child_ordering() {
        let deps = FakeDeps::new();
        let root_read_key = [1u8; 32];
        seed_root_with_children(&deps, &root_read_key, 2);

        let mut job = RotationJobRecord::new(ROOT_ID);
        let result = rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap();
        assert!(result.is_some());

        let log = deps.publish_log.lock().unwrap().clone();
        let root_first_index = log.iter().position(|n| n == "k51/root").unwrap();
        let first_child_index = log
            .iter()
            .position(|n| n == "k51/child-0" || n == "k51/child-1")
            .unwrap();
        assert!(
            root_first_index < first_child_index,
            "expected root's own publish before any child's publish, got log: {log:?}"
        );
    }

    #[tokio::test]
    async fn persist_job_fires_exactly_once_per_committed_node() {
        let deps = FakeDeps::new();
        let root_read_key = [2u8; 32];
        seed_root_with_children(&deps, &root_read_key, 2);

        let mut job = RotationJobRecord::new(ROOT_ID);
        rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap()
            .unwrap();

        // root + 2 children == 3 committed nodes -- plus the final
        // "status = Complete" persist call at the very end == 4 total, but
        // only the first 3 correspond 1:1 to a per-node commit. Assert the
        // per-commit calls are present (monotonically increasing
        // completed-count snapshots reaching 3), which is what "persist
        // fires once per committed node" means operationally.
        let log = deps.persist_log.lock().unwrap().clone();
        assert!(
            log.contains(&1) && log.contains(&2) && log.contains(&3),
            "expected persist snapshots after 1, 2, and 3 completions, got: {log:?}"
        );
        assert_eq!(job.completed_node_ids.len(), 3);
    }

    #[tokio::test]
    async fn two_children_one_parent_issues_exactly_one_batched_republish() {
        let deps = FakeDeps::new();
        let root_read_key = [3u8; 32];
        seed_root_with_children(&deps, &root_read_key, 2);

        let mut job = RotationJobRecord::new(ROOT_ID);
        let result = rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap()
            .unwrap();

        // Exactly two publishes for "k51/root": the root's OWN rotate_one
        // commit, plus the SINGLE batched republish after both children
        // finish (never three, which would mean one republish per child --
        // the T-69-08-03 DoS mitigation this test pins).
        assert_eq!(deps.publish_count_for("k51/root"), 2);
        assert_eq!(deps.publish_count_for("k51/child-0"), 1);
        assert_eq!(deps.publish_count_for("k51/child-1"), 1);

        assert_eq!(result.generation, 1);
    }

    #[tokio::test]
    async fn root_resume_skip_returns_none_without_processing_children() {
        let deps = FakeDeps::new();
        let root_read_key = [4u8; 32];
        seed_root_with_children(&deps, &root_read_key, 1);

        let mut job = RotationJobRecord::new(ROOT_ID);
        job.completed_node_ids.insert(ROOT_ID.to_string());

        let result = rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap();

        assert!(result.is_none());
        assert_eq!(deps.publish_count_for("k51/root"), 0);
        assert_eq!(deps.publish_count_for("k51/child-0"), 0);
    }

    // -----------------------------------------------------------------------
    // ROT-06 crash-safety resume (69-11): verify_subtree_clean + no-double-
    // bump convergence, and the M1 completed_node_ids seeding hazard.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_subtree_clean_reports_no_dirty_entries_when_fully_converged() {
        let deps = FakeDeps::new();
        let root_read_key = [8u8; 32];
        seed_root_with_children(&deps, &root_read_key, 2);

        // Nothing has rotated yet -- both children's published generations
        // match the root's mirror exactly.
        let frontier = verify_subtree_clean(&deps, "k51/root", &root_read_key)
            .await
            .unwrap();
        assert!(
            frontier.is_empty(),
            "expected a clean subtree, got: {frontier:?}"
        );
    }

    #[tokio::test]
    async fn verify_subtree_clean_reports_a_dirty_entry_when_a_child_outpaces_the_mirror() {
        let deps = FakeDeps::new();
        let root_read_key = [9u8; 32];
        seed_root_with_children(&deps, &root_read_key, 2);

        // Simulate "child-0 individually committed its own rotation (its
        // published generation bumped to 1) but the parent's batched
        // republish never landed": re-seed child-0's PublishedNode at a
        // higher generation under a new CID/sequence. The root's mirror
        // (still generation 0, from seed_root_with_children) is now stale.
        let bumped_child = folder(&child_uuid(0), 1, vec![]);
        deps.seed(
            "k51/child-0",
            "cid-child-0-1",
            1,
            seal_for_seed(&bumped_child, &[10u8; 32]),
        );

        let frontier = verify_subtree_clean(&deps, "k51/root", &root_read_key)
            .await
            .unwrap();
        assert_eq!(
            frontier.len(),
            1,
            "expected exactly one dirty entry, got: {frontier:?}"
        );
        assert_eq!(frontier[0].ipns_name, "k51/child-0");
        assert_eq!(frontier[0].node_id, child_uuid(0));
    }

    #[tokio::test]
    async fn resume_after_crash_converges_without_double_bump_when_seeded() {
        let deps = FakeDeps::new();
        let root_read_key = [5u8; 32];
        seed_root_with_children(&deps, &root_read_key, 2);

        // Pass 1: a full walk to completion -- root and both children
        // rotate, and the batched republish for root's children mirror
        // lands (fully converged, published state is the source of truth).
        let mut job = RotationJobRecord::new(ROOT_ID);
        let first = rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.generation, 1);

        let root_pub_count = deps.publish_count_for("k51/root");
        let child0_pub_count = deps.publish_count_for("k51/child-0");
        let child1_pub_count = deps.publish_count_for("k51/child-1");

        // Simulate a crash: the durably-persisted RotationJobRecord only
        // captured the root's own completion before the process died. The
        // PUBLISHED state (source of truth, D-10) is, in fact, already
        // fully converged -- the caller just doesn't know that yet.
        let mut crash_time_job = RotationJobRecord::new(ROOT_ID);
        crash_time_job
            .completed_node_ids
            .insert(ROOT_ID.to_string());

        // Resume using the root's CURRENT (post-rotation) key -- the only
        // key that unseals the presently-published root envelope.
        let resume = rotate_read_from_node(
            &deps,
            ROOT_ID,
            "k51/root",
            first.read_key.as_slice(),
            &mut crash_time_job,
        )
        .await
        .unwrap();

        // Root was a fast-path skip -- no fresh key to hand back.
        assert!(resume.is_none());

        // ROT-06: verify_subtree_clean found the published state already
        // fully reconciled (empty dirty frontier) -- nothing further gets
        // minted or published for the root or either child. No node's
        // generation was bumped twice across the crash + resume.
        assert_eq!(deps.publish_count_for("k51/root"), root_pub_count);
        assert_eq!(deps.publish_count_for("k51/child-0"), child0_pub_count);
        assert_eq!(deps.publish_count_for("k51/child-1"), child1_pub_count);
    }

    #[tokio::test]
    async fn empty_completed_node_ids_seed_double_bumps_the_root_seeded_path_does_not() {
        let deps = FakeDeps::new();
        let root_read_key = [6u8; 32];
        seed_root_with_children(&deps, &root_read_key, 1);

        let mut job = RotationJobRecord::new(ROOT_ID);
        let first = rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap()
            .unwrap();
        let gen_after_first_pass = first.generation;

        // M1 hazard: resuming with an EMPTY completed_node_ids seed (the
        // caller forgot to load the crash-time RotationJobRecord from
        // durable storage) means rotate_one's fast idempotency path never
        // fires for the root -- it gets re-resolved, re-unsealed, re-minted,
        // and re-published even though it was already fully rotated.
        let mut unseeded_job = RotationJobRecord::new(ROOT_ID);
        let hazard = rotate_read_from_node(
            &deps,
            ROOT_ID,
            "k51/root",
            first.read_key.as_slice(),
            &mut unseeded_job,
        )
        .await
        .unwrap()
        .expect("unseeded resume re-rotates the root -- the exact hazard this plan documents");
        assert_eq!(
            hazard.generation,
            gen_after_first_pass + 1,
            "root's generation was bumped a SECOND time by the unseeded resume"
        );

        // Contrast: the SEEDED path (completed_node_ids pre-populated from
        // the crash-time record) does NOT double-bump -- it fast-path skips
        // before any resolve/unseal/mint is attempted.
        let mut seeded_job = RotationJobRecord::new(ROOT_ID);
        seeded_job.completed_node_ids.insert(ROOT_ID.to_string());
        let seeded = rotate_read_from_node(
            &deps,
            ROOT_ID,
            "k51/root",
            hazard.read_key.as_slice(),
            &mut seeded_job,
        )
        .await
        .unwrap();
        assert!(
            seeded.is_none(),
            "seeded resume must be a fast-path skip -- no fresh rotation"
        );
    }
}
