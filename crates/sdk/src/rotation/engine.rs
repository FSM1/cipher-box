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
//! 69-12 closes the three revocation-guarantee gaps left open above:
//! CRIT-1 (lazy file-key rotation, [`mint_file_key_on_rotate`]), HIGH-3
//! (inner-grant re-mint, [`re_mint_grants_rooted_at`]), and HIGH-4 (CAS-409
//! concurrent-child merge, [`merge_children`]/[`merge_concurrent_children`]).
//! Write-plane rotation remains out of scope (a later plan). Also out of
//! scope, and a known limitation inherited unchanged from the TS reference
//! (`engine.ts`'s own acknowledged gap, see its `verifySubtreeClean` doc
//! comment): a genuinely fresh, never-started child (its own published
//! generation still matches the parent's mirror exactly) is invisible to
//! the generation-comparison dirty check below and is NOT recovered by this
//! resume path — only a child whose OWN rotation individually committed
//! before the crash, but whose parent's batched republish did not yet land,
//! is detected as "dirty".
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

/// Outcome of a CAS-guarded publish that actually landed.
#[derive(Debug, Clone)]
pub struct PublishOutcome {
    pub new_sequence_number: u64,
}

/// Result of a single [`RotationDeps::publish_with_cas`] attempt (HIGH-4,
/// T-69-12-03).
///
/// Splitting "published" from "conflict" as an `Ok` variant (rather than
/// reporting a CAS-409 as an `Err`) is deliberate: a conflict is an
/// EXPECTED, recoverable outcome of the check-and-set contract, not a
/// transport/logic failure. [`seal_and_publish`]'s retry loop is the only
/// caller that inspects this distinction; every other publish failure
/// (network error, auth failure, etc.) still surfaces as `Err`.
#[derive(Debug, Clone)]
pub enum PublishAttempt {
    /// The CAS check passed; `node` is now the published record.
    Published(PublishOutcome),
    /// The CAS check failed: `remote` is the winning concurrent publish
    /// already live at the target IPNS name, and `current_sequence_number`
    /// is its sequence number. The caller MUST re-fetch, re-decode, and
    /// re-merge before retrying — NEVER blind-re-seal from a stale
    /// in-memory child list (T-69-12-03).
    Conflict {
        remote: PublishedNode,
        current_sequence_number: u64,
    },
}

/// One share/grant row rooted at a rotated node (HIGH-3, T-69-12-02).
///
/// Rust twin of the TS `GrantRemintCallbacks` query row shape
/// (`packages/sdk-core/src/rotation/engine.ts`). Deliberately carries raw
/// key bytes rather than any wire (hex/base64) encoding — decoding the
/// `crates/api-client` wire representation into this shape is the
/// PRODUCTION `RotationDeps` implementor's job (D-02/D-04: this module
/// stays transport-decoupled and never imports `cipherbox-api-client`
/// itself).
#[derive(Debug, Clone)]
pub struct GrantRow {
    pub share_id: String,
    /// Recipient's ECIES public key (raw bytes — not hex/base64 encoded).
    pub recipient_public_key: Vec<u8>,
    /// `true` when this grant has been revoked; a revoked recipient's row
    /// is deleted, NEVER re-minted (T-64-04b parity — re-minting a revoked
    /// recipient's encrypted key would defeat revocation).
    pub is_revoked: bool,
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
    /// Returns [`PublishAttempt::Conflict`] (not `Err`) on a CAS-409 — see
    /// [`PublishAttempt`]'s doc comment for why a conflict is a recoverable
    /// `Ok` outcome rather than a failure (ROT-05/HIGH-4, engine.ts's
    /// `mergeConcurrentChildren`, T-69-12-03).
    async fn publish_with_cas(
        &self,
        ipns_name: &str,
        expected_sequence_number: u64,
        node: &PublishedNode,
    ) -> Result<PublishAttempt, RotationError>;

    /// Advisory checkpoint — called after EVERY per-node commit (D-10).
    /// Published IPNS records remain the source of truth; this is a
    /// resume-acceleration hint only, never authoritative.
    async fn persist_job(&self, job: &RotationJobRecord);

    /// HIGH-3 (T-69-12-02): returns every grant/share whose root is
    /// `node_id` — INCLUDING an inner grant rooted at a subtree node deep
    /// inside the rotating tree, not just the scope root.
    ///
    /// Default no-op (empty): the clean happy-path (no grants shared out of
    /// this subtree at all) never touches this seam — mirrors the TS
    /// reference's `GrantRemintCallbacks` being an optional param (D-01
    /// conditional invocation / D-04 transport seam).
    async fn query_grants_rooted_at(&self, _node_id: &str) -> Result<Vec<GrantRow>, RotationError> {
        Ok(Vec::new())
    }

    /// HIGH-3: persists a re-minted `encryptedReadKey` (ECIES-wrapped new
    /// readKey) + the new generation for a non-revoked recipient's grant
    /// row. Default no-op.
    async fn update_grant(
        &self,
        _share_id: &str,
        _encrypted_read_key: &str,
        _new_generation: u32,
    ) -> Result<(), RotationError> {
        Ok(())
    }

    /// HIGH-3: hard-deletes a revoked recipient's grant row. Default no-op.
    async fn delete_grant(&self, _share_id: &str) -> Result<(), RotationError> {
        Ok(())
    }

    /// ECIES key-checkpoint seam (D-01/D-03, T-70.1-19, 70.1-08): persists a
    /// durable, recoverable checkpoint of a freshly minted `read_key_prime`
    /// BEFORE its owning node's publish lands, closing the
    /// "minted-then-lost-on-crash" window. Default no-op: a host with no
    /// checkpoint plane wired pays zero cost (mirrors the grant seam's own
    /// D-01 conditional-invocation-by-default-no-op contract).
    ///
    /// `wrapped_b64` is base64 of the raw key material FROM THE ENGINE'S
    /// PERSPECTIVE — per RESEARCH option (b) (Sharp Question 6.3), this
    /// engine stays key-material-free w.r.t. ECIES: a concrete production
    /// `RotationDeps` impl is the one that ECIES-wraps this under the
    /// owner's own pubkey before writing it at rest (and unwraps it again
    /// inside its own `get_wrapped_key`), so ciphertext — never plaintext —
    /// ever crosses this seam's actual storage boundary (T-70.1-21).
    async fn persist_wrapped_key(
        &self,
        _node_id: &str,
        _wrapped_b64: &str,
    ) -> Result<(), RotationError> {
        Ok(())
    }

    /// Recovers a previously persisted checkpoint (see `persist_wrapped_key`),
    /// returning `None` when nothing is checkpointed for `node_id` (expired,
    /// GC'd, or never persisted) — the caller surfaces
    /// [`RotationError::DirtyNodeUnrecoverable`] in that case (D-05).
    async fn get_wrapped_key(&self, _node_id: &str) -> Result<Option<String>, RotationError> {
        Ok(None)
    }

    /// Garbage-collects a checkpoint once it is no longer needed — called
    /// AFTER the node's parent mirror durably commits the node's current
    /// key (D-01), never before.
    async fn delete_wrapped_key(&self, _node_id: &str) -> Result<(), RotationError> {
        Ok(())
    }
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
    /// frontier). Empty for file nodes. HIGH-4 (T-69-12-03): reflects the
    /// FINAL (possibly CAS-409-merged) children list actually published —
    /// NOT the pre-rotation snapshot — so a concurrently-added child is
    /// both preserved in the published body AND enqueued for its own
    /// rotation/re-seal-under-the-new-parent-key by the BFS walk, exactly
    /// like any other child.
    pub children: Vec<SealedChildRef>,
    /// CRIT-1 (T-69-12-01): `true` when this rotation minted a fresh
    /// `fileKey` for a File node (always `true` for File, always `false`
    /// for Folder/Root — folder nodes carry no content key). Advisory: the
    /// actual re-encrypt-on-next-write is lazy (ADR 0002) and happens
    /// outside this engine; this flag is the host's cue to apply it.
    pub content_rekey_pending: bool,
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
    // Public entry point: no child-list override (BFS children + every existing
    // caller publish the node's own resolved children — the common case).
    rotate_one_inner(
        deps,
        node_id,
        node_ipns_name,
        parent_read_key,
        job_record,
        None,
    )
    .await
}

/// Implementation of [`rotate_one`] with an optional `children_override`
/// (70.1-13a coalescing): when `Some`, the node is re-sealed and published
/// with THIS `SealedChildRef` list instead of the one decoded from its
/// currently-published record. Used ONLY for the scope-root of a covered
/// scope-exit delete, so the rotation republishes the grant-root already
/// reflecting the post-delete child list (secret.txt removed) under the new
/// key — the single authoritative publish, with NO stale-key relink afterward
/// (the revocation-bypass fix). The override refs MUST be sealed under the
/// node's OWN pre-rotation (`parent_read_key`) read key, exactly as its
/// currently-published children are, so the BFS still derives each surviving
/// child's key via `unseal_child_read_key`.
async fn rotate_one_inner<D: RotationDeps>(
    deps: &D,
    node_id: Option<&str>,
    node_ipns_name: &str,
    parent_read_key: &[u8],
    job_record: &mut RotationJobRecord,
    children_override: Option<&[SealedChildRef]>,
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

    // CRIT-1 (T-69-12-01 / ADR 0002): a File node gets a freshly minted
    // fileKey placed directly into the resealed NodeContent — this rides
    // along in the SAME re-seal below, no separate publish, no eager
    // re-encrypt of already-published content. `content_rekey_pending` is
    // the advisory marker the host applies lazily on this node's next
    // write. Folder/Root nodes carry no content — no-op (`None`).
    let file_key_prime: Option<Zeroizing<[u8; 32]>> = if kind == NodeKind::File {
        Some(mint_file_key_on_rotate())
    } else {
        None
    };
    let content_rekey_pending = file_key_prime.is_some();

    // D-01/D-03 (T-70.1-19, 70.1-08): persist the ECIES checkpoint BEFORE
    // the child publish — closes the "minted-then-lost-on-crash" window. A
    // host with no checkpoint plane wired pays zero cost (default no-op).
    // `read_key_prime` crosses this seam as raw base64 — per RESEARCH
    // option (b), this engine stays key-material-free w.r.t. ECIES; a
    // concrete `RotationDeps` impl is the one that ECIES-wraps it under the
    // owner's own pubkey before writing it at rest.
    if let Err(e) = deps
        .persist_wrapped_key(&resolved_node_id, &base64_encode(read_key_prime.as_slice()))
        .await
    {
        read_key_prime.zeroize();
        return Err(e);
    }

    match seal_and_publish(
        deps,
        node_ipns_name,
        resolved.sequence_number,
        &node,
        &resolved_node_id,
        kind,
        new_generation,
        &read_key_prime,
        &parent_read_key_arr,
        file_key_prime.as_deref(),
        children_override,
    )
    .await
    {
        Ok((new_sequence_number, children)) => {
            let (created_at, modified_at) = node_timestamps(&node);

            // HIGH-3 (T-69-12-02): re-mint grants rooted at THIS node
            // BEFORE marking it completed — D-07 parity: a failure here
            // must not silently skip the node on resume.
            if let Err(e) =
                re_mint_grants_rooted_at(deps, &resolved_node_id, &read_key_prime, new_generation)
                    .await
            {
                read_key_prime.zeroize();
                return Err(e);
            }

            // D-07: mark committed AFTER the publish + grant re-mint succeed.
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
                content_rekey_pending,
            }))
        }
        Err(e) => {
            // Zero read_key_prime on failure — rotate_one minted it, so
            // rotate_one is the terminal owner (D-09). Do NOT touch
            // parent_read_key — it is caller-owned and only ever borrowed.
            // file_key_prime (Zeroizing) self-zeroes on drop below.
            read_key_prime.zeroize();
            Err(e)
        }
    }
}

/// CRIT-1 (T-69-12-01): mints a fresh 32-byte `fileKey` for a File node's
/// content, to be placed into the resealed `NodeContent` by the caller.
///
/// A holder of the OLD readKey/fileKey can still decrypt every version
/// already published under the OLD key (that ciphertext is presumed
/// leaked — ADR 0002 lazy revocation stance), but the NEXT published
/// version is encrypted under THIS fresh key, which the old holder never
/// receives.
///
/// @security Returns `Zeroizing` — NOT zeroed here. The caller (`rotate_one`)
/// consumes it via the re-seal on success, or lets it self-zero on drop on
/// any failure path (D-09 terminal-owner rule).
fn mint_file_key_on_rotate() -> Zeroizing<[u8; 32]> {
    let mut raw = cipherbox_crypto::generate_random_bytes(32);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&raw);
    raw.zeroize();
    key
}

/// HIGH-3 (T-69-12-02): re-mints the `encryptedReadKey` for every
/// non-revoked grant rooted at `node_id` — including an inner grant rooted
/// at a subtree node — and hard-deletes a revoked recipient's row.
///
/// Rust twin of `reMintGrantsRootedAt`
/// (`packages/sdk-core/src/rotation/engine.ts`). Called unconditionally
/// after every per-node commit (root and every BFS child): the default
/// no-op `RotationDeps::query_grants_rooted_at` makes this a zero-cost path
/// for any node with nothing shared out of it (D-01 conditional invocation
/// is satisfied by the seam's own default, not by a call-site branch).
///
/// @security ECIES-wraps the new readKey via `cipherbox_crypto::wrap_key`
/// — never hand-rolled key wrapping (T-64-04c parity). Does NOT zero
/// `new_read_key` — caller is terminal owner (D-09).
async fn re_mint_grants_rooted_at<D: RotationDeps>(
    deps: &D,
    node_id: &str,
    new_read_key: &[u8; 32],
    new_generation: u32,
) -> Result<(), RotationError> {
    let grants = deps.query_grants_rooted_at(node_id).await?;
    for grant in grants {
        if grant.is_revoked {
            // T-64-04b parity: re-minting a revoked recipient's encrypted
            // key would defeat revocation — delete the row instead.
            deps.delete_grant(&grant.share_id).await?;
        } else {
            let wrapped = cipherbox_crypto::wrap_key(new_read_key, &grant.recipient_public_key)
                .map_err(|e| {
                    RotationError::RotateFailed(format!(
                        "re_mint_grants_rooted_at: wrap_key failed for share {}: {e}",
                        grant.share_id
                    ))
                })?;
            // Share-grant `encryptedReadKey` is validated as even-length HEX by
            // the API (`/^(?:[0-9a-fA-F]{2})+$/`, `update-grant.dto.ts`) and
            // decoded via `Buffer.from(.., 'hex')` — must be hex, NOT base64.
            let encrypted_read_key = hex::encode(&wrapped);
            deps.update_grant(&grant.share_id, &encrypted_read_key, new_generation)
                .await?;
        }
    }
    Ok(())
}

/// Three-way merge of `SealedChildRef` lists — Rust twin of
/// `packages/sdk-core/src/folder/merge.ts`'s `mergeChildren` (ROT-05/HIGH-4,
/// T-69-12-03).
///
/// Union by `ipns_name`: `local` entries loaded first, `remote` entries
/// overwrite on conflict (remote wins — a concurrent add present only in
/// `remote` is never dropped). A `base` entry absent from BOTH `local` AND
/// `remote` is an intentional delete and is pruned from the result.
///
/// No crypto: operates purely on already-sealed `SealedChildRef` values.
fn merge_children(
    base: &[SealedChildRef],
    local: &[SealedChildRef],
    remote: &[SealedChildRef],
) -> Vec<SealedChildRef> {
    let mut merged: HashMap<String, SealedChildRef> = HashMap::new();
    for child in local {
        merged.insert(child.ipns_name.clone(), child.clone());
    }
    for child in remote {
        merged.insert(child.ipns_name.clone(), child.clone());
    }

    let local_names: HashSet<&str> = local.iter().map(|c| c.ipns_name.as_str()).collect();
    let remote_names: HashSet<&str> = remote.iter().map(|c| c.ipns_name.as_str()).collect();
    for child in base {
        if !local_names.contains(child.ipns_name.as_str())
            && !remote_names.contains(child.ipns_name.as_str())
        {
            merged.remove(&child.ipns_name);
        }
    }

    merged.into_values().collect()
}

/// HIGH-4 (T-69-12-03): re-decodes a CAS-409 conflict's winning `remote`
/// envelope under the OLD (pre-rotation) read key — it was sealed before
/// this rotation started — and three-way merges its children against the
/// pre-rotation base/local list via [`merge_children`].
///
/// `base_and_local_children` doubles as both the merge's `base` and `local`
/// arguments: `rotate_one` never adds or removes children on its own re-seal
/// (it only rotates keys/generation), so the node's pre-rotation children
/// snapshot IS both the CAS base and the local candidate here.
async fn merge_concurrent_children(
    remote: &PublishedNode,
    old_read_key: &[u8; 32],
    base_and_local_children: &[SealedChildRef],
) -> Result<Vec<SealedChildRef>, RotationError> {
    let remote_kind = node_kind_from_str(&remote.kind)?;
    let remote_sealed_bytes = decode_b64(&remote.read_sealed)?;
    let remote_body = unseal_node(
        &remote_sealed_bytes,
        old_read_key,
        &remote.id,
        remote_kind,
        remote.generation,
    )
    .map_err(|e| {
        RotationError::RotateFailed(format!("merge_concurrent_children: unseal failed: {e}"))
    })?;
    let remote_node = decode_node(&remote_body).map_err(|e| {
        RotationError::RotateFailed(format!("merge_concurrent_children: decode failed: {e}"))
    })?;
    let remote_children = node_children(&remote_node);
    Ok(merge_children(
        base_and_local_children,
        base_and_local_children,
        &remote_children,
    ))
}

/// Re-seals `node`'s read-body under `read_key_prime` with the bumped
/// `new_generation`, then CAS-publishes it, retrying with a HIGH-4 merge on
/// every CAS-409 (T-69-12-03) up to [`MAX_CAS_MERGE_ATTEMPTS`]. Split out of
/// `rotate_one` so the caller retains ownership of `read_key_prime` and can
/// zero it on `Err` without threading a fallible expression through a
/// manual try/catch (Rust has none) inside the minted-key's own scope.
///
/// Returns the final sequence number AND the final (possibly CAS-409-merged)
/// children list actually published — the caller threads this list into
/// `CommittedRotation.children` so a concurrently-added child is both
/// preserved in the published body and enqueued for its own rotation by the
/// BFS walk (never silently dropped, T-69-12-03).
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
    old_read_key: &[u8; 32],
    file_key_prime: Option<&[u8; 32]>,
    children_override: Option<&[SealedChildRef]>,
) -> Result<(u64, Vec<SealedChildRef>), RotationError> {
    /// HIGH-4 (T-69-12-03): bounds the CAS-409 retry-merge loop so a
    /// pathologically contended node cannot spin forever (mirrors the TS
    /// reference's `publishWithCas({ maxAttempts: 3 })`).
    const MAX_CAS_MERGE_ATTEMPTS: u32 = 3;

    // 70.1-13a: the caller-supplied post-delete child list (covered scope-exit
    // coalescing) takes precedence over the node's own resolved children, so
    // the rotation republishes the grant-root already reflecting the deletion.
    let mut current_children =
        children_override.map_or_else(|| node_children(node), <[SealedChildRef]>::to_vec);
    let mut current_expected_seq = expected_sequence_number;

    for attempt in 1..=MAX_CAS_MERGE_ATTEMPTS {
        let updated_node =
            build_resealed_node(node, new_generation, &current_children, file_key_prime);
        let read_body = encode_node(&updated_node).map_err(|e| {
            RotationError::RotateFailed(format!(
                "rotate_one: encode failed for {node_ipns_name}: {e}"
            ))
        })?;
        let resealed = seal_node(&read_body, read_key_prime, node_id, kind, new_generation)
            .map_err(|e| {
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

        match deps
            .publish_with_cas(node_ipns_name, current_expected_seq, &published_node)
            .await
            .map_err(|e| {
                RotationError::RotateFailed(format!(
                    "rotate_one: publish failed for {node_ipns_name}: {e}"
                ))
            })? {
            PublishAttempt::Published(outcome) => {
                return Ok((outcome.new_sequence_number, current_children));
            }
            PublishAttempt::Conflict {
                remote,
                current_sequence_number,
            } => {
                if attempt == MAX_CAS_MERGE_ATTEMPTS {
                    return Err(RotationError::RotateFailed(format!(
                        "rotate_one: exhausted {MAX_CAS_MERGE_ATTEMPTS} CAS-409 merge retries for {node_ipns_name}"
                    )));
                }
                current_children =
                    merge_concurrent_children(&remote, old_read_key, &current_children).await?;
                current_expected_seq = current_sequence_number;
                // Retry the seal+publish with the merged children.
            }
        }
    }

    unreachable!("seal_and_publish loop always returns or errors within MAX_CAS_MERGE_ATTEMPTS")
}

// ---------------------------------------------------------------------------
// rotate_read_from_node — scope-root-first BFS walk (ROT-01, engine.ts §4.2)
// ---------------------------------------------------------------------------

/// A single rotated node's post-rotation read key/generation/sequence
/// number, keyed by `ipns_name` inside [`RotateReadResult::rotated_nodes`]
/// (74-01, SC1 — deep scope-exit key refresh).
///
/// Rust twin of TS `RotatedNodeKey` (`packages/sdk-core/src/rotation/engine.ts`,
/// plan 74-02) — the LOCKED cross-language field contract keeps these two
/// shapes field-for-field identical (camelCase on the TS side).
///
/// @security `read_key` is NOT zeroed here — same terminal-owner rule as
/// [`RotateReadResult::read_key`] (D-09): the caller (FUSE/WinFsp inode
/// refresh) becomes the terminal owner.
#[derive(Debug, Clone)]
pub struct RotatedNodeKey {
    pub ipns_name: String,
    pub read_key: Zeroizing<[u8; 32]>,
    pub generation: u32,
    pub sequence_number: u64,
}

/// Return shape for a successful (fresh, non-resume-skip) `rotate_read_from_node`
/// run: the ROOT node's post-rotation read key/generation/sequence number
/// (ROT-07 Gap 2 parity), PLUS every rotated node's post-rotation key
/// (74-01, SC1 — deep scope-exit key refresh).
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
    /// EVERY rotated node's post-rotation read key, keyed by `ipns_name` —
    /// not just the grant root's (additive; `read_key`/`generation`/
    /// `sequence_number` above remain the root-convenience accessors, kept
    /// to avoid churn to existing call sites). Populated at both the root
    /// commit hook and the BFS child commit hook inside
    /// `rotate_read_from_node_inner`, plus the `repair_dirty_node`
    /// crash-resume repair hook (which recovers an already-rotated node's
    /// CURRENT key via its ECIES checkpoint rather than minting a fresh
    /// one — still the node's valid post-rotation key from the caller's
    /// perspective, so it belongs in this same map).
    pub rotated_nodes: HashMap<String, RotatedNodeKey>,
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
    /// Node ids with a pending ECIES checkpoint (D-01, 70.1-08) that must be
    /// GC'd via `delete_wrapped_key` once THIS parent's batched republish
    /// actually lands — never eagerly before that commit is durable.
    /// Populated for both a normally-committed child (`rotate_one` always
    /// persists a checkpoint before its own publish) and a repaired dirty
    /// child (`repair_dirty_node`).
    pending_checkpoint_node_ids: Vec<String>,
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
    ///
    /// `None` ONLY for a dirty item (`is_dirty_item: true` — Plan 70.1-10
    /// fix): `collect_dirty_frontier` never decrypts a dirty edge (see
    /// [`DirtyFrontierEntry::node_read_key`]), so there is no key material to
    /// carry forward. `repair_dirty_node` never reads this field — it
    /// recovers the real key via the ECIES checkpoint instead.
    node_read_key: Option<Zeroizing<[u8; 32]>>,
    parent_ipns_name: String,
    /// This node's own stable UUID — known at enqueue time for both a
    /// normal child (`enqueue_child` already resolves+fetches to derive the
    /// AAD-binding id) and a dirty-frontier item (`DirtyFrontierEntry`
    /// already carries it). Used by [`repair_dirty_node`] to address the
    /// ECIES checkpoint seam (`RotationDeps::get_wrapped_key`) without a
    /// redundant extra resolve.
    node_id: String,
    /// `true` only for an item enqueued via [`enqueue_dirty_frontier_entry`]
    /// (D-05, 70.1-08): its `node_read_key` is always `None` (Plan 70.1-10
    /// fix) — the BFS routes it to [`repair_dirty_node`] instead of ever
    /// feeding a key into `rotate_one`/`unseal_node`. Always `false` for a
    /// normal [`enqueue_child`] item, which always carries `Some(..)`.
    is_dirty_item: bool,
}

// ---------------------------------------------------------------------------
// verify_subtree_clean — crash-safety dirty-frontier rebuild (ROT-06, 69-11,
// Rust twin of engine.ts's verifySubtreeClean)
// ---------------------------------------------------------------------------

/// One dirty edge discovered by [`verify_subtree_clean`], at ANY depth
/// (D-12): a child whose OWN published `generation` is strictly greater than
/// the generation recorded in its PARENT's `SealedChildRef` mirror — i.e.
/// the child individually committed its own rotation in a prior (crashed)
/// run, but the parent's batched republish that would reconcile the mirror
/// never landed.
///
/// Widened (D-12, Rust twin of TS's `DirtyFrontierItem`, `engine.ts:587-597`)
/// to carry everything a depth-aware consumer needs to seed its BFS queue
/// directly at this node, without assuming it is an immediate child of the
/// scope root:
/// - `parent_ipns_name` — this node's REAL parent (may be any depth below
///   root), not necessarily the scope root.
/// - `node_read_key` — ALWAYS `None` (Plan 70.1-10 / T1 AEAD-crash regression
///   fix): `collect_dirty_frontier` identifies a dirty edge via a PLAINTEXT
///   generation comparison alone and never attempts to decrypt the dirty
///   edge's `read_key_sealed` — that stale ref may be sealed under a key that
///   no longer matches the current parent chain (e.g. the parent ALSO
///   rotated in this same walk), which fails closed with an AEAD
///   authentication error before the dirtiness check would ever run.
///   `repair_dirty_node` recovers this node's CURRENT valid key via the ECIES
///   checkpoint plane keyed by `node_id` — NEVER via this field. Retained
///   (rather than removed) so `QueueItem`'s shape stays uniform between dirty
///   and normal entries; consumers MUST NOT rely on it being populated.
/// - `child_pub_kind` / `enqueued_generation` — the child's published kind
///   and the parent-mirror generation captured when this dirty edge was
///   found.
#[derive(Debug, Clone)]
pub struct DirtyFrontierEntry {
    pub ipns_name: String,
    pub node_id: String,
    pub parent_ipns_name: String,
    pub node_read_key: Option<Zeroizing<[u8; 32]>>,
    pub child_pub_kind: NodeKind,
    pub enqueued_generation: u32,
}

/// Outcome of a [`verify_subtree_clean`] walk (D-12) — Rust twin of the TS
/// `{ isDirty, frontier }` return shape (`engine.ts:648-653`).
///
/// `is_dirty` is the DISTINCT signal a caller must check instead of
/// `frontier.is_empty()`: a missing root is `{ is_dirty: true, frontier: []
/// }` — the same empty `Vec` shape as a genuinely fully-converged subtree,
/// but NOT the same meaning. Conflating the two (the pre-D-12 bug) silently
/// treats "the root record is gone" as "nothing left to reconcile."
#[derive(Debug, Clone)]
pub struct VerifySubtreeOutcome {
    pub is_dirty: bool,
    pub frontier: Vec<DirtyFrontierEntry>,
}

/// Read-only child read-key derivation shared by [`enqueue_child`] (the BFS
/// walk driver) and [`collect_dirty_frontier`] (the verify walk) — D-12.
/// Both derive a child's own pre-rotation read key from its parent's read
/// key via [`unseal_child_read_key`], using the child's plaintext `id`/
/// `kind` for the AAD binding and the PARENT's mirror `generation` (never
/// the child's own envelope generation) as the generation-source rule
/// requires.
fn derive_child_read_key(
    parent_read_key: &[u8],
    child_ref: &SealedChildRef,
    child_id: &str,
    child_kind: NodeKind,
) -> Result<Zeroizing<[u8; 32]>, RotationError> {
    let parent_read_key_arr = zeroizing_32_from_slice(parent_read_key)?;
    let sealed_bytes = decode_b64(&child_ref.read_key_sealed)?;

    let mut child_read_key_raw = unseal_child_read_key(
        &sealed_bytes,
        &parent_read_key_arr,
        child_id,
        child_kind,
        child_ref.generation,
    )
    .map_err(|e| {
        RotationError::RotateFailed(format!(
            "derive_child_read_key: unseal_child_read_key failed for {}: {e}",
            child_ref.ipns_name
        ))
    })?;

    if child_read_key_raw.len() != 32 {
        child_read_key_raw.zeroize();
        return Err(RotationError::RotateFailed(format!(
            "derive_child_read_key: unsealed read key for {} is not 32 bytes",
            child_ref.ipns_name
        )));
    }
    let mut child_read_key = Zeroizing::new([0u8; 32]);
    child_read_key.copy_from_slice(&child_read_key_raw);
    child_read_key_raw.zeroize();

    Ok(child_read_key)
}

/// Recursive full-subtree dirty-edge walk backing [`verify_subtree_clean`]
/// (D-12) — Rust twin of the TS `collectDirtyFrontier` recursion CONTRACT
/// (`engine.ts:648-704`): recurse below CLEAN folder edges only, STOP below
/// a DIRTY edge. Dirtiness is determined via a PLAINTEXT `generation`
/// comparison ALONE (Plan 70.1-10 / T1 AEAD-crash regression fix) — NO
/// decryption is attempted for a dirty edge. The dirty edge's
/// `read_key_sealed` may be sealed under a key that no longer matches the
/// current parent chain (e.g. the parent ALSO rotated in this same walk) —
/// attempting the decrypt anyway fails closed with an AEAD authentication
/// error before the dirtiness comparison would ever run, which is exactly
/// the bug this ordering fixes. There is no cryptographic recovery path for
/// a key genuinely lost to an interrupted prior run from this read-only walk
/// alone (RESEARCH.md Pitfall 4) — a dirty node is recorded in the frontier
/// with no key material (see [`DirtyFrontierEntry::node_read_key`]) and left
/// for the BFS's own checkpoint-repair path (`repair_dirty_node`) to resolve
/// safely on resume.
///
/// Implemented as an explicit work-stack rather than a literally recursive
/// `async fn` (Rust cannot size a self-referential `async fn`'s state
/// machine without heap-boxing every recursive call); traversal order is
/// otherwise immaterial — every reachable node below a clean edge is still
/// visited exactly once.
///
/// @security Read-only: never mints, seals, or publishes anything itself. A
/// CLEAN edge's derived key is scoped entirely to this walk and is zeroed
/// (via `Zeroizing`'s `Drop`) once it falls out of scope, since this walk is
/// never its terminal owner (D-09); a DIRTY edge never has a derived key at
/// all (Plan 70.1-10 fix), so there is nothing to move into its frontier
/// entry.
async fn collect_dirty_frontier<D: RotationDeps>(
    deps: &D,
    root_ipns_name: &str,
    root_children: &[SealedChildRef],
    root_read_key: &Zeroizing<[u8; 32]>,
    frontier: &mut Vec<DirtyFrontierEntry>,
) -> Result<(), RotationError> {
    let mut stack: Vec<(String, SealedChildRef, Zeroizing<[u8; 32]>)> = root_children
        .iter()
        .map(|c| (root_ipns_name.to_string(), c.clone(), root_read_key.clone()))
        .collect();

    while let Some((parent_ipns_name, child_ref, parent_read_key)) = stack.pop() {
        let Some(child_resolved) = deps.resolve(&child_ref.ipns_name).await? else {
            continue; // missing non-root child — data inconsistency, not root-dirty (mirrors the TS reference).
        };
        let child_pub = deps.fetch_node(&child_resolved.cid).await?;
        let child_kind = node_kind_from_str(&child_pub.kind)?;

        // T1 AEAD-crash regression fix (Plan 70.1-10): compare generations —
        // both PLAINTEXT fields of the wire envelope/mirror — BEFORE ever
        // attempting to decrypt `child_ref.read_key_sealed`. A dirty edge's
        // stale ref may be sealed under a key that no longer matches
        // `parent_read_key` (the parent may have ALSO rotated in this same
        // walk), which makes `derive_child_read_key` fail closed with an AEAD
        // decryption error BEFORE this comparison would ever run if attempted
        // first — exactly the bug this ordering fixes.
        if child_pub.generation > child_ref.generation {
            frontier.push(DirtyFrontierEntry {
                ipns_name: child_ref.ipns_name.clone(),
                node_id: child_pub.id.clone(),
                parent_ipns_name,
                // No decrypt attempted for a dirty edge (see field docstring) —
                // `repair_dirty_node` recovers the current key via the ECIES
                // checkpoint plane, never via this field.
                node_read_key: None,
                child_pub_kind: child_kind,
                enqueued_generation: child_ref.generation,
            });
            continue; // MUST NOT descend below a dirty edge — see docstring.
        }

        // Clean edge: parent mirror is up to date, so child_ref.read_key_sealed
        // is PROVABLY sealed under parent_read_key — safe to decrypt now.
        let child_read_key = derive_child_read_key(
            parent_read_key.as_slice(),
            &child_ref,
            &child_pub.id,
            child_kind,
        )?;

        // The derived key IS provably the child's current valid key (parent
        // mirror is up to date) — recurse into folder children only to find
        // dirty edges deeper in the subtree.
        if child_kind == NodeKind::Folder {
            let read_sealed_bytes = decode_b64(&child_pub.read_sealed)?;
            let child_body = unseal_node(
                &read_sealed_bytes,
                &child_read_key,
                &child_pub.id,
                child_kind,
                child_pub.generation,
            )
            .map_err(|e| {
                RotationError::RotateFailed(format!(
                    "collect_dirty_frontier: unseal failed for {}: {e}",
                    child_ref.ipns_name
                ))
            })?;
            let child_node = decode_node(&child_body).map_err(|e| {
                RotationError::RotateFailed(format!(
                    "collect_dirty_frontier: decode failed for {}: {e}",
                    child_ref.ipns_name
                ))
            })?;
            for grandchild_ref in node_children(&child_node) {
                stack.push((
                    child_ref.ipns_name.clone(),
                    grandchild_ref,
                    child_read_key.clone(),
                ));
            }
        }
        // `child_read_key` drops (and zeroizes) here for a CLEAN edge — this
        // walk never returns a clean edge's key to any caller (D-09).
    }

    Ok(())
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
/// Recurses the FULL subtree (D-12, not just the root's immediate children):
/// a child is "dirty" when its own published `generation` exceeds the
/// generation recorded in its PARENT's `SealedChildRef` mirror
/// (`PublishedNode.generation` is a plaintext wire field on both sides — no
/// child unsealing is needed to make this comparison, D-10). A MISSING root
/// record is surfaced as `is_dirty: true` (D-12) — never silently treated as
/// "fully converged" — matching the TS reference's `{ isDirty: true,
/// frontier: [] }` contract (`engine.ts:631`); the caller's dirty-resume
/// branch re-resolves the root itself and raises a descriptive,
/// actionable error when it too finds the root missing.
///
/// @security Read-only: never mints, seals, or publishes anything itself.
pub async fn verify_subtree_clean<D: RotationDeps>(
    deps: &D,
    root_ipns_name: &str,
    root_read_key: &[u8],
) -> Result<VerifySubtreeOutcome, RotationError> {
    let Some(root_resolved) = deps.resolve(root_ipns_name).await? else {
        // D-12 / T-70.1-10: a missing root MUST NOT be conflated with
        // "clean" — surface it as dirty with an empty (nothing discoverable)
        // frontier.
        return Ok(VerifySubtreeOutcome {
            is_dirty: true,
            frontier: Vec::new(),
        });
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

    let mut frontier = Vec::new();
    collect_dirty_frontier(
        deps,
        root_ipns_name,
        &node_children(&root_node),
        &root_read_key_arr,
        &mut frontier,
    )
    .await?;

    Ok(VerifySubtreeOutcome {
        is_dirty: !frontier.is_empty(),
        frontier,
    })
}

// ---------------------------------------------------------------------------
// SC#1/SC#2 (Plan 70.1-06, D-11): depth-aware dirty-frontier CONSUMPTION.
//
// Bug A: the pre-70.1-06 dirty-resume loop seeded ONE root-only
// `ParentTrackingState` and matched each frontier entry against
// `root_children` — any depth>=2 entry's real parent is an INTERMEDIATE
// node, never found there, so it was silently `continue`d (dropped, worse
// than TS — not even decremented, wedging `pending_child_count` forever).
//
// Bug B: `complete_pending_child` silently no-ops when the parent isn't
// tracked instead of seeding it — a depth>=2 entry's real (intermediate)
// parent's batched republish would never fire even if the entry itself WERE
// somehow enqueued.
//
// Fix shape (Rust twin of `engine.ts`'s `findParentNodeByIpnsName` /
// `resolveParentTrackingState`, `engine.ts:602-646` / `:1387-1418`): a
// "seed-or-find `ParentTrackingState` for an arbitrary `parent_ipns_name`"
// primitive, built on a walk-from-root helper that generalizes the
// root-only seed to ANY depth.
// ---------------------------------------------------------------------------

/// Result of locating an arbitrary node by walking down from the scope root
/// (SC#1, D-11): the unsealed [`Node`], its resolved IPNS record, and its
/// OWN read key (an owned `Zeroizing` — the caller becomes its terminal
/// owner, D-09).
struct FoundNode {
    node: Node,
    resolved: ResolvedRecord,
    read_key: Zeroizing<[u8; 32]>,
}

/// Walks from `start_ipns_name` (the scope root, using `start_read_key`)
/// down to `target_ipns_name`, deriving each level's read key via the SAME
/// key-chain primitive [`collect_dirty_frontier`] uses
/// ([`derive_child_read_key`]). By construction, every ancestor between the
/// scope root and a [`DirtyFrontierEntry`]'s real parent IS clean
/// (`collect_dirty_frontier` stops recursing below a dirty edge), so this
/// walk always finds a resolvable path down to a target sourced from the
/// frontier.
///
/// Implemented as an explicit work-stack rather than literal recursion — the
/// same reason [`collect_dirty_frontier`] is (Rust cannot size a
/// self-referential `async fn`'s state machine without heap-boxing every
/// recursive call); traversal order is otherwise immaterial.
///
/// @security Read-only: never mints, seals, or publishes anything itself.
/// Every level's derived key except the MATCH's own is dropped (and thus
/// zeroized) once that stack frame's iteration ends without being pushed
/// onward — mirrors `collect_dirty_frontier`'s own zeroization discipline.
///
/// Returns `Ok(None)` when the target cannot be found (data inconsistency)
/// — callers apply the file's existing fail-closed accounting convention.
async fn find_node_by_ipns_name<D: RotationDeps>(
    deps: &D,
    start_ipns_name: &str,
    start_read_key: &Zeroizing<[u8; 32]>,
    target_ipns_name: &str,
) -> Result<Option<FoundNode>, RotationError> {
    let mut stack: Vec<(String, Zeroizing<[u8; 32]>)> =
        vec![(start_ipns_name.to_string(), start_read_key.clone())];

    while let Some((ipns_name, read_key)) = stack.pop() {
        let Some(resolved) = deps.resolve(&ipns_name).await? else {
            continue; // missing node -- data inconsistency, fail-closed skip.
        };
        let published = deps.fetch_node(&resolved.cid).await?;
        let kind = node_kind_from_str(&published.kind)?;
        let read_sealed_bytes = decode_b64(&published.read_sealed)?;
        let body = unseal_node(
            &read_sealed_bytes,
            &read_key,
            &published.id,
            kind,
            published.generation,
        )
        .map_err(|e| {
            RotationError::RotateFailed(format!(
                "find_node_by_ipns_name: unseal failed for {ipns_name}: {e}"
            ))
        })?;
        let node = decode_node(&body).map_err(|e| {
            RotationError::RotateFailed(format!(
                "find_node_by_ipns_name: decode failed for {ipns_name}: {e}"
            ))
        })?;

        if ipns_name == target_ipns_name {
            return Ok(Some(FoundNode {
                node,
                resolved,
                read_key,
            }));
        }

        if kind == NodeKind::Folder || kind == NodeKind::Root {
            for child_ref in node_children(&node) {
                let child_pub = resolve_and_fetch(deps, &child_ref.ipns_name).await?;
                let child_kind = node_kind_from_str(&child_pub.kind)?;

                // Plan 70.1-10 fix (T1 AEAD-crash regression): a dirty sibling
                // branch (parent mirror stale) can never lead to the search
                // target — by `collect_dirty_frontier`'s own contract every
                // `DirtyFrontierEntry`'s real parent is reached via a provably
                // CLEAN path from root — so skip it without attempting the
                // unseal (which could fail closed with an AEAD authentication
                // error if this branch's stale ref is sealed under a
                // different key than `read_key`).
                if child_pub.generation > child_ref.generation {
                    continue;
                }
                if child_kind != NodeKind::Folder && child_kind != NodeKind::Root {
                    continue;
                }

                let child_key = derive_child_read_key(
                    read_key.as_slice(),
                    &child_ref,
                    &child_pub.id,
                    child_kind,
                )?;
                stack.push((child_ref.ipns_name.clone(), child_key));
            }
        }
        // `read_key` drops (and zeroizes) here for every non-matching level.
    }

    Ok(None)
}

/// SC#1 (Bug A fix, D-11): given an arbitrary `parent_ipns_name` discovered
/// via a [`DirtyFrontierEntry`] at ANY depth, resolve+unseal that parent
/// (walking down from `root_ipns_name` via [`find_node_by_ipns_name`]) and
/// produce-or-find its [`ParentTrackingState`]. Generalizes the root-only
/// seed previously inlined in the dirty-resume branch — root itself is just
/// another entry in `parent_tracking`.
///
/// Returns `Ok(true)` when `parent_tracking` now has (or already had) an
/// entry for `parent_ipns_name`; `Ok(false)` when the parent could not be
/// found walking from root (data inconsistency) — callers apply the file's
/// existing fail-closed accounting convention (drop this frontier entry's
/// count, matching the missing-child-record precedent elsewhere in this
/// file, e.g. `collect_dirty_frontier`'s missing-child skip).
///
/// `pending_child_count` is seeded to 0 — callers set the real count (the
/// frontier-group size for the dirty-resume branch, or 1 for a single lazy
/// decrement in the BFS loop's fallback) after this returns, since the
/// correct count depends on the caller's own context.
async fn seed_or_find_parent_tracking_state<D: RotationDeps>(
    deps: &D,
    root_ipns_name: &str,
    root_read_key: &Zeroizing<[u8; 32]>,
    parent_tracking: &mut HashMap<String, ParentTrackingState>,
    parent_ipns_name: &str,
) -> Result<bool, RotationError> {
    if parent_tracking.contains_key(parent_ipns_name) {
        return Ok(true);
    }

    let Some(found) =
        find_node_by_ipns_name(deps, root_ipns_name, root_read_key, parent_ipns_name).await?
    else {
        return Ok(false);
    };

    let kind = found.node.kind();
    let (created_at, modified_at) = node_timestamps(&found.node);
    let children = node_children(&found.node);
    parent_tracking.insert(
        parent_ipns_name.to_string(),
        ParentTrackingState {
            parent_ipns_name: parent_ipns_name.to_string(),
            parent_new_read_key: found.read_key,
            parent_node_id: found.node.id().to_string(),
            parent_kind: kind,
            parent_generation: found.node.generation(),
            parent_created_at: created_at,
            parent_modified_at: modified_at,
            parent_last_seq: found.resolved.sequence_number,
            children,
            pending_child_count: 0,
            pending_checkpoint_node_ids: Vec::new(),
        },
    );
    Ok(true)
}

/// Enqueues a [`DirtyFrontierEntry`] directly onto the BFS queue (SC#1,
/// D-11) — the entry already carries its own pre-rotation read key
/// (engine-derived via `collect_dirty_frontier`'s shared key-chain walk), so
/// no additional resolve/unseal is needed here, unlike [`enqueue_child`].
/// Builds a minimal `SealedChildRef` stub — only `ipns_name`/`generation`
/// are read by the BFS loop itself (`rotate_one` re-derives the node's real
/// id/kind from its own unsealed envelope); `read_key_sealed` is never
/// re-derived from this stub.
///
/// Deduped by `ipns_name` against an item already queued (e.g. a depth-1
/// dirty edge ALSO covered by the normal children-enqueue loop in the
/// fresh/committed branch) so it is not double-processed.
fn enqueue_dirty_frontier_entry(entry: DirtyFrontierEntry, queue: &mut VecDeque<QueueItem>) {
    if queue
        .iter()
        .any(|q| q.child_ref.ipns_name == entry.ipns_name)
    {
        // Deduped -- `entry.node_read_key` drops (and zeroizes) here; this
        // walk never returns or reuses a discarded frontier entry's key
        // (D-09).
        return;
    }
    queue.push_back(QueueItem {
        child_ref: SealedChildRef {
            name: entry.ipns_name.clone(),
            ipns_name: entry.ipns_name,
            generation: entry.enqueued_generation,
            version_floor: 0,
            read_key_sealed: String::new(),
        },
        node_read_key: entry.node_read_key,
        parent_ipns_name: entry.parent_ipns_name,
        node_id: entry.node_id,
        is_dirty_item: true,
    });
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
///
/// SC#1/SC#2 (Plan 70.1-06, D-11): the pre-rotation dirty-frontier probe now
/// runs UNCONDITIONALLY — not only on a resume-Skip — mirroring `engine.ts`'s
/// `preRotationDirtyFrontier` computed BEFORE `rotateOne(root)`
/// (`engine.ts:1092-1094`). `rotate_one` never mutates a node's CHILDREN
/// mirror (only re-seals its OWN body), so the same frontier remains valid
/// for BOTH branches below: reused as-is on a Skip, and folded into the
/// normal/fresh walk so a dirty tail left by a lost prior run is recovered
/// even on a genuinely fresh job record with no memory of that prior run.
/// Depth-aware consumption (a depth>=2 entry's real parent is an
/// intermediate node, not necessarily root) is handled by
/// [`seed_or_find_parent_tracking_state`] / [`enqueue_dirty_frontier_entry`].
pub async fn rotate_read_from_node<D: RotationDeps>(
    deps: &D,
    root_node_id: &str,
    root_ipns_name: &str,
    root_read_key: &[u8],
    job_record: &mut RotationJobRecord,
) -> Result<Option<RotateReadResult>, RotationError> {
    rotate_read_from_node_inner(
        deps,
        root_node_id,
        root_ipns_name,
        root_read_key,
        job_record,
        None,
    )
    .await
}

/// 70.1-13a coalescing variant: rotates the scope-root's subtree but publishes
/// the ROOT's own record with `root_children` in place of its
/// currently-published child list. Used by the covered scope-exit delete path
/// so the rotation is the SINGLE authoritative grant-root publish that already
/// reflects the deletion (secret.txt removed) under the new read key — no
/// separate, stale-key parent relink afterward (the revocation-bypass fix).
///
/// `root_children` MUST be sealed under `root_read_key` (the root's
/// pre-rotation key), exactly as the root's currently-published children are,
/// so the BFS derives each surviving child's key via `unseal_child_read_key`.
/// A surviving child absent from `root_children` (the deleted node) is neither
/// republished in the root body nor enqueued for rotation.
pub async fn rotate_read_from_node_with_root_children<D: RotationDeps>(
    deps: &D,
    root_node_id: &str,
    root_ipns_name: &str,
    root_read_key: &[u8],
    job_record: &mut RotationJobRecord,
    root_children: Vec<SealedChildRef>,
) -> Result<Option<RotateReadResult>, RotationError> {
    rotate_read_from_node_inner(
        deps,
        root_node_id,
        root_ipns_name,
        root_read_key,
        job_record,
        Some(root_children),
    )
    .await
}

async fn rotate_read_from_node_inner<D: RotationDeps>(
    deps: &D,
    root_node_id: &str,
    root_ipns_name: &str,
    root_read_key: &[u8],
    job_record: &mut RotationJobRecord,
    root_children_override: Option<Vec<SealedChildRef>>,
) -> Result<Option<RotateReadResult>, RotationError> {
    job_record.status = RotationStatus::InProgress;

    // Keep BOTH the dirty signal and the frontier (70.1 CodeRabbit finding 7):
    // a missing/unresolvable root returns `{ is_dirty: true, frontier: [] }`, so
    // the empty-frontier convergence short-circuit on the resume/Skipped branch
    // below must consult `is_dirty` — otherwise a missing root would be mistaken
    // for "already converged" instead of failing closed.
    let pre_rotation_outcome = verify_subtree_clean(deps, root_ipns_name, root_read_key).await?;
    let pre_rotation_dirty = pre_rotation_outcome.is_dirty;
    let pre_rotation_frontier = pre_rotation_outcome.frontier;

    // §4.2: rotate the scope-root FIRST — the actual revocation cut.
    // 70.1-13a: on a covered scope-exit delete the root is republished with the
    // post-delete child list (`root_children_override`), so this single publish
    // already reflects the deletion under the new key.
    let root_outcome = rotate_one_inner(
        deps,
        Some(root_node_id),
        root_ipns_name,
        root_read_key,
        job_record,
        root_children_override.as_deref(),
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

    // 74-01 (SC1): every rotated node's post-rotation key, keyed by
    // ipns_name — populated at the root commit hook below, the BFS child
    // commit hook, and the repair_dirty_node crash-resume hook. Additive to
    // `fresh_root`/the top-level `read_key` convenience field, not a
    // replacement for either.
    let mut rotated_nodes: HashMap<String, RotatedNodeKey> = HashMap::new();

    // An owned, defensive copy of root's CURRENTLY-valid read key — needed
    // by `seed_or_find_parent_tracking_state`'s walk-from-root primitive on
    // BOTH branches below (root did not rotate on the Skip branch; on the
    // Committed branch this is still root's key AT THE TIME the frontier
    // above was computed, which is what a lazily-discovered intermediate
    // parent's own `SealedChildRef` mirror is sealed under).
    let root_read_key_owned = zeroizing_32_from_slice(root_read_key)?;

    match root_outcome {
        RotateOneOutcome::Committed(root_committed) => {
            // Persist after the root commit (D-10 — the high-value early checkpoint).
            deps.persist_job(job_record).await;

            // D-01 (70.1-08): the root has no parent mirror to wait on — its
            // own publish above IS the durable landing, so its checkpoint is
            // GC'd immediately rather than deferred to a batched republish.
            deps.delete_wrapped_key(&root_committed.node_id).await?;

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
                        pending_checkpoint_node_ids: Vec::new(),
                    },
                );
            }

            // Enqueue the root's children — derive each child's own read key from
            // the ROOT's OLD read key (root_read_key, still valid; rotate_one never
            // zeroed the caller-supplied borrow, D-09).
            for child_ref in &root_committed.children {
                enqueue_child(deps, root_ipns_name, root_read_key, child_ref, &mut queue).await?;
            }

            // SC#1/SC#2 (D-11): fold the pre-rotation dirty frontier into the
            // normal/fresh walk too — closes the Rust structural gap the TS
            // engine already closed (a dirty tail left by a lost prior run,
            // discovered even though THIS job record has no memory of it). A
            // dirty depth-1 edge is deduped against the loop above; a dirty
            // edge below a CLEAN depth-1 parent is otherwise only reachable
            // once that parent's OWN rotation discovers its real children —
            // the shared BFS loop below no longer convergence-skips a
            // dirty-tail item, so this still converges.
            for entry in pre_rotation_frontier {
                enqueue_dirty_frontier_entry(entry, &mut queue);
            }

            // 74-01 (SC1): surface the root's own post-rotation key into the
            // per-node map (keyed by ipns_name, threaded in here at the call
            // site — CommittedRotation itself stays host-agnostic and never
            // gains an ipns_name field, per RESEARCH Pitfall 1).
            rotated_nodes.insert(
                root_ipns_name.to_string(),
                RotatedNodeKey {
                    ipns_name: root_ipns_name.to_string(),
                    read_key: root_committed.read_key_prime.clone(),
                    generation: root_committed.new_generation,
                    sequence_number: root_committed.new_sequence_number,
                },
            );

            fresh_root = Some(root_committed);
        }
        RotateOneOutcome::Skipped { .. } => {
            // Resume path (ROT-06 crash-safety resume, 69-11): the root was
            // already committed in a prior run. Reuse the ALREADY-COMPUTED
            // pre-rotation frontier (SC#1/SC#2, D-11) instead of re-running
            // verify_subtree_clean a second time — root_read_key is
            // unchanged on this branch (root did not rotate this run), so
            // the frontier computed above with it remains valid.
            let frontier = pre_rotation_frontier;
            if frontier.is_empty() && !pre_rotation_dirty {
                // Fully converged already (or the root has no published
                // children at all) — nothing dirty to reconcile, and nothing
                // further gets minted or published. No double-bump risk.
                //
                // `!pre_rotation_dirty` guards the missing/unresolvable-root case
                // (finding 7): that returns an empty frontier WITH `is_dirty`, and
                // must NOT be mis-marked Complete — it falls through to the dirty
                // resume below, which fails closed on the `resolve(...)?` miss.
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
            let root_read_key_arr = root_read_key_owned.clone();
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

            // SC#1 (Bug A fix, D-11): seed a `ParentTrackingState` per
            // DISTINCT REAL parent in the frontier — generalizes the
            // previous root-only seed. Root itself is just another entry.
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
                    // Seeded to 0, not frontier.len() — a depth>=2 entry's
                    // real parent is an intermediate node, NOT root; mixing
                    // every depth into root's own counter is the exact
                    // mis-attribution Bug A fix removes. Set to the count of
                    // root-DIRECT dirty items only, below (0 if none).
                    pending_child_count: 0,
                    pending_checkpoint_node_ids: Vec::new(),
                },
            );

            let mut count_by_parent: HashMap<String, usize> = HashMap::new();
            for entry in &frontier {
                *count_by_parent
                    .entry(entry.parent_ipns_name.clone())
                    .or_insert(0) += 1;
            }

            for (parent_name, count) in &count_by_parent {
                if parent_name.as_str() == root_ipns_name {
                    if let Some(state) = parent_tracking.get_mut(root_ipns_name) {
                        state.pending_child_count = *count;
                    }
                    continue;
                }
                let found = seed_or_find_parent_tracking_state(
                    deps,
                    root_ipns_name,
                    &root_read_key_owned,
                    &mut parent_tracking,
                    parent_name,
                )
                .await?;
                if found {
                    if let Some(state) = parent_tracking.get_mut(parent_name) {
                        state.pending_child_count = *count;
                    }
                }
                // else: fail-closed drop (data inconsistency — the parent
                // could not be resolved walking from root); matches the
                // file's existing convention for a missing/unresolvable node
                // elsewhere (e.g. collect_dirty_frontier's missing-child skip).
            }

            if let Some(state) = parent_tracking.get(root_ipns_name) {
                if state.pending_child_count == 0 {
                    // No root-direct dirty items this run — root's own
                    // mirror needs no update. Nothing will ever decrement
                    // this entry to trigger teardown, so clean it up now
                    // instead of leaving a live tracking entry for the rest
                    // of this call.
                    parent_tracking.remove(root_ipns_name);
                }
            }

            for entry in frontier {
                enqueue_dirty_frontier_entry(entry, &mut queue);
            }
        }
    }

    while let Some(item) = queue.pop_front() {
        // SC#2 (Bug B fix, D-11): guarantee a depth>=2 item's parent has a
        // chance to seed its OWN parent_tracking entry before this item is
        // genuinely consumed. The normal-branch fold enqueues root's
        // children FIRST, then appends every pre-rotation dirty-frontier
        // item regardless of depth — so a deep dirty node can dequeue
        // before its own (also not-yet-processed) parent. Root-direct items
        // are NEVER deferred, so this recursion is bounded by tree depth.
        if item.parent_ipns_name != root_ipns_name
            && !parent_tracking.contains_key(&item.parent_ipns_name)
            && queue
                .iter()
                .any(|q| q.child_ref.ipns_name == item.parent_ipns_name)
        {
            queue.push_back(item);
            continue;
        }

        // D-05 (T-70.1-20 / Plan 70.1-10): an already-rotated dirty node's
        // `node_read_key` is ALWAYS `None` — `collect_dirty_frontier` never
        // decrypts a dirty edge at all (its stale ref may be sealed under a
        // key that no longer matches the current parent chain, e.g. the
        // parent ALSO rotated in this same walk — decrypting it anyway would
        // fail closed with an opaque AEAD authentication error). Route it to
        // the ECIES checkpoint repair path instead.
        //
        // D-01 conditional invocation (mirrors the TS reference, 70.1-05):
        // repair only actually engages when a checkpoint is genuinely FOUND
        // (`get_wrapped_key` returns `Some`). Plan 70.1-10 fix: since there is
        // no decrypted key to fall back to any more, a host with NO
        // checkpoint plane wired (`get_wrapped_key` returns `None`) can no
        // longer attempt a "safe double rotation" for a dirty item — there is
        // no key material left to attempt it with. Fail closed with
        // `DirtyNodeUnrecoverable` instead of silently misbehaving.
        if item.is_dirty_item {
            let Some(raw_b64) = deps.get_wrapped_key(&item.node_id).await? else {
                return Err(RotationError::DirtyNodeUnrecoverable {
                    node_id: item.node_id.clone(),
                });
            };
            repair_dirty_node(
                deps,
                &item,
                &raw_b64,
                root_ipns_name,
                &root_read_key_owned,
                &mut parent_tracking,
                &mut queue,
                &mut rotated_nodes,
            )
            .await?;
            complete_pending_child(deps, &mut parent_tracking, &item.parent_ipns_name).await?;
            continue;
        }

        // Invariant: only a non-dirty item reaches this point, and a
        // non-dirty item (`enqueue_child`) always carries `Some(..)`.
        let Some(node_read_key) = item.node_read_key.as_ref() else {
            return Err(RotationError::RotateFailed(format!(
                "rotate_read_from_node: internal invariant violated — non-dirty queue item for \
                 {} has no node_read_key",
                item.child_ref.ipns_name
            )));
        };

        let outcome = rotate_one(
            deps,
            None,
            &item.child_ref.ipns_name,
            node_read_key.as_slice(),
            job_record,
        )
        .await
        .map_err(|e| {
            if item.is_dirty_item {
                // Unreachable: dirty items are routed to repair_dirty_node
                // above and never fall through to this call. Retained for
                // defensive symmetry only.
                RotationError::DirtyNodeUnrecoverable {
                    node_id: item.node_id.clone(),
                }
            } else {
                e
            }
        })?;

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

                // 74-01 (SC1): surface this child's post-rotation key into
                // the per-node map, keyed by its ipns_name (item.child_ref
                // is the same QueueItem that carries CommittedRotation's
                // otherwise-missing ipns_name — threaded in here at the call
                // site, per RESEARCH Pitfall 1).
                rotated_nodes.insert(
                    item.child_ref.ipns_name.clone(),
                    RotatedNodeKey {
                        ipns_name: item.child_ref.ipns_name.clone(),
                        read_key: child.read_key_prime.clone(),
                        generation: child.new_generation,
                        sequence_number: child.new_sequence_number,
                    },
                );

                // SC#2 (Bug B fix, D-11): the requeue guard above handles the
                // COMMON ordering race; as a defensive fallback (e.g. an
                // orphaned/unreachable parent_ipns_name the guard couldn't
                // wait on), lazily resolve+seed the parent via the shared
                // primitive instead of silently dropping this entire
                // re-seal+decrement block (the pre-70.1-06 no-op this fix
                // closes).
                if !parent_tracking.contains_key(&item.parent_ipns_name) {
                    let found = seed_or_find_parent_tracking_state(
                        deps,
                        root_ipns_name,
                        &root_read_key_owned,
                        &mut parent_tracking,
                        &item.parent_ipns_name,
                    )
                    .await?;
                    if found {
                        // Lazily discovered — this decrement accounts for
                        // exactly this one child. If a sibling dirty item
                        // under the same parent is discovered later,
                        // seed_or_find_parent_tracking_state returns this
                        // SAME entry (as long as it has not already reached
                        // zero and torn down).
                        if let Some(state) = parent_tracking.get_mut(&item.parent_ipns_name) {
                            state.pending_child_count = 1;
                        }
                    }
                }

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
                    // D-01 (70.1-08): this child's checkpoint (persisted by
                    // rotate_one's own persist-before-publish step) is only
                    // GC'd once THIS parent's batched republish lands —
                    // registered here, consumed in `complete_pending_child`.
                    state
                        .pending_checkpoint_node_ids
                        .push(child.node_id.clone());
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
                            pending_checkpoint_node_ids: Vec::new(),
                        },
                    );
                }

                // Enqueue this node's children using THIS node's OWN
                // (pre-rotation) read key — node_read_key is still valid here
                // (rotate_one never zeroed it; it is dropped, and thus
                // zeroed, only when this loop iteration ends).
                for grandchild_ref in &child.children {
                    enqueue_child(
                        deps,
                        &item.child_ref.ipns_name,
                        node_read_key.as_slice(),
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
        rotated_nodes,
    }))
}

/// D-05 (T-70.1-20, 70.1-08): repairs an already-rotated dirty node —
/// discovered by `verify_subtree_clean`/`collect_dirty_frontier` and
/// enqueued via [`enqueue_dirty_frontier_entry`] — via the ECIES key
/// checkpoint (`RotationDeps::get_wrapped_key`). `item.node_read_key` is
/// ALWAYS `None` for a dirty item (Plan 70.1-10 fix): `collect_dirty_frontier`
/// never decrypts a dirty edge at all, so there is no stale key to avoid
/// feeding in any more — this function never reads `item.node_read_key`.
///
/// Recovers the node's ACTUAL current read key from the checkpoint,
/// re-seals ONLY the real parent's `SealedChildRef` mirror under it
/// (mirroring the normal Committed branch's out-of-band reseal in
/// [`rotate_read_from_node`]), and seeds the repaired node's OWN
/// `ParentTrackingState` so its children still enqueue this same walk. The
/// checkpoint itself is registered onto the parent's
/// `pending_checkpoint_node_ids` for GC once that parent's mirror commit
/// actually lands (`complete_pending_child`/`republish_parent`) — never
/// eagerly here, before that commit is durable.
///
/// Called ONLY when the caller has already confirmed a checkpoint exists
/// (`get_wrapped_key` returned `Some(raw_b64)`) — the caller (the BFS loop in
/// [`rotate_read_from_node`]) owns the conditional-invocation gate (D-01) and
/// the `None` (no checkpoint) fail-closed path: Plan 70.1-10 fix removed the
/// old "fall through to `rotate_one` with a decrypted-but-possibly-stale key"
/// fallback — since no key is ever decrypted for a dirty edge any more, the
/// caller surfaces [`RotationError::DirtyNodeUnrecoverable`] directly when no
/// checkpoint is found, with no attempt in between (mirrors
/// `collect_dirty_frontier`'s own stop-below-a-dirty-edge convention: this
/// file never claims a recovery path it cannot cryptographically back).
///
/// @security `item.node_read_key` is never touched here at all (it is
/// `None` for every dirty item). The RECOVERED key is the node's own current
/// (correct) key — using it to `unseal_node` is expected and
/// safe, unlike feeding in the stale one.
async fn repair_dirty_node<D: RotationDeps>(
    deps: &D,
    item: &QueueItem,
    raw_b64: &str,
    root_ipns_name: &str,
    root_read_key: &Zeroizing<[u8; 32]>,
    parent_tracking: &mut HashMap<String, ParentTrackingState>,
    queue: &mut VecDeque<QueueItem>,
    rotated_nodes: &mut HashMap<String, RotatedNodeKey>,
) -> Result<(), RotationError> {
    let raw_bytes = decode_b64(raw_b64)?;
    let recovered_key = zeroizing_32_from_slice(&raw_bytes)?;

    let resolved = deps
        .resolve(&item.child_ref.ipns_name)
        .await?
        .ok_or_else(|| {
            RotationError::RotateFailed(format!(
                "repair_dirty_node: {} not found in IPNS during repair",
                item.child_ref.ipns_name
            ))
        })?;
    let published = deps.fetch_node(&resolved.cid).await?;
    let kind = node_kind_from_str(&published.kind)?;
    let read_sealed_bytes = decode_b64(&published.read_sealed)?;
    let body = unseal_node(
        &read_sealed_bytes,
        &recovered_key,
        &published.id,
        kind,
        published.generation,
    )
    .map_err(|e| {
        RotationError::RotateFailed(format!(
            "repair_dirty_node: recovered checkpoint failed to unseal {}: {e}",
            item.child_ref.ipns_name
        ))
    })?;
    let node = decode_node(&body).map_err(|e| {
        RotationError::RotateFailed(format!(
            "repair_dirty_node: decode failed for {}: {e}",
            item.child_ref.ipns_name
        ))
    })?;
    let children = node_children(&node);
    let (created_at, modified_at) = node_timestamps(&node);

    // 74-01 (SC1, RESEARCH Open Question 1): a repaired dirty node's
    // recovered key IS its current, valid post-rotation key (recovered from
    // the ECIES checkpoint of a rotation that already committed in a prior,
    // crashed run) — surface it into the same per-node map the normal
    // Committed branches populate, so a FUSE/WinFsp inode refresh sees this
    // node too after a crash-resume repair.
    rotated_nodes.insert(
        item.child_ref.ipns_name.clone(),
        RotatedNodeKey {
            ipns_name: item.child_ref.ipns_name.clone(),
            read_key: recovered_key.clone(),
            generation: published.generation,
            sequence_number: resolved.sequence_number,
        },
    );

    // SC#2-style defensive fallback (D-11 precedent): the ordering guard in
    // the BFS loop handles the common case, but a repair item's real parent
    // may still be unreached here (e.g. an orphaned parent_ipns_name) —
    // lazily resolve+seed it via the shared primitive rather than silently
    // dropping this entire reseal.
    if !parent_tracking.contains_key(&item.parent_ipns_name) {
        seed_or_find_parent_tracking_state(
            deps,
            root_ipns_name,
            root_read_key,
            parent_tracking,
            &item.parent_ipns_name,
        )
        .await?;
    }

    if let Some(state) = parent_tracking.get_mut(&item.parent_ipns_name) {
        let sealed = seal_child_read_key(
            &recovered_key,
            &state.parent_new_read_key,
            &published.id,
            kind,
            published.generation,
        )
        .map_err(|e| {
            RotationError::RotateFailed(format!(
                "repair_dirty_node: reseal failed for {} under parent {}: {e}",
                published.id, item.parent_ipns_name
            ))
        })?;
        if let Some(idx) = state
            .children
            .iter()
            .position(|c| c.ipns_name == item.child_ref.ipns_name)
        {
            state.children[idx].read_key_sealed = base64_encode(&sealed);
            state.children[idx].generation = published.generation;
        }
        state.pending_checkpoint_node_ids.push(published.id.clone());
    }

    if !children.is_empty() {
        parent_tracking.insert(
            item.child_ref.ipns_name.clone(),
            ParentTrackingState {
                parent_ipns_name: item.child_ref.ipns_name.clone(),
                parent_new_read_key: recovered_key.clone(),
                parent_node_id: published.id.clone(),
                parent_kind: kind,
                parent_generation: published.generation,
                parent_created_at: created_at,
                parent_modified_at: modified_at,
                parent_last_seq: resolved.sequence_number,
                children: children.clone(),
                pending_child_count: children.len(),
                pending_checkpoint_node_ids: Vec::new(),
            },
        );
    }

    for grandchild_ref in &children {
        enqueue_child(
            deps,
            &item.child_ref.ipns_name,
            recovered_key.as_slice(),
            grandchild_ref,
            queue,
        )
        .await?;
    }

    Ok(())
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

    // D-12: shared with `collect_dirty_frontier`'s read-only verify walk.
    let child_read_key =
        derive_child_read_key(parent_old_read_key, child_ref, &child_pub.id, child_kind)?;

    queue.push_back(QueueItem {
        child_ref: child_ref.clone(),
        node_read_key: Some(child_read_key),
        parent_ipns_name: parent_ipns_name.to_string(),
        node_id: child_pub.id,
        is_dirty_item: false,
    });

    Ok(())
}

/// Decrements `parent_ipns_name`'s pending-child counter; when it reaches
/// zero, fires the batched republish exactly once (T-69-08-03), GCs every
/// checkpoint the now-durable republish covers (D-01, 70.1-08), and removes
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
            // D-01: only GC a checkpoint AFTER the parent mirror that
            // covers it durably commits — never before.
            for node_id in &state.pending_checkpoint_node_ids {
                deps.delete_wrapped_key(node_id).await?;
            }
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

    match deps
        .publish_with_cas(
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
        })? {
        PublishAttempt::Published(_) => Ok(()),
        // HIGH-4's CAS-409 retry-merge is a rotate_one-only capability in
        // this plan (T-69-12-03 scopes it there explicitly) — the batched
        // parent republish still fails closed on a concurrent conflict
        // rather than silently dropping data.
        PublishAttempt::Conflict { .. } => Err(RotationError::RotateFailed(format!(
            "republish_parent: CAS conflict for {} (concurrent-merge retry is not yet wired to the batched parent republish)",
            state.parent_ipns_name
        ))),
    }
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

/// Returns a copy of `node` with `generation` replaced, `children` replaced
/// by `children_override` (Folder/Root only — ignored for File, which
/// carries no children field), and — when `file_key_prime` is `Some` (File
/// nodes only, CRIT-1 T-69-12-01) — `content.file_key` swapped to the
/// freshly minted key, zeroing the old one first (D-09 hygiene: `node` is a
/// fresh `unseal_node` output owned by this call, not a caller-reused
/// buffer, so wiping its old content key here is safe).
///
/// `children_override` carries the FINAL (possibly HIGH-4-merged) children
/// list, not necessarily `node`'s own pre-rotation snapshot — see
/// `seal_and_publish`'s retry loop.
fn build_resealed_node(
    node: &Node,
    generation: u32,
    children_override: &[SealedChildRef],
    file_key_prime: Option<&[u8; 32]>,
) -> Node {
    match node {
        Node::Folder {
            id,
            created_at,
            modified_at,
            ..
        } => Node::Folder {
            id: id.clone(),
            generation,
            created_at: *created_at,
            modified_at: *modified_at,
            children: children_override.to_vec(),
        },
        Node::Root {
            id,
            created_at,
            modified_at,
            ..
        } => Node::Root {
            id: id.clone(),
            generation,
            created_at: *created_at,
            modified_at: *modified_at,
            children: children_override.to_vec(),
        },
        Node::File {
            id,
            created_at,
            modified_at,
            content,
            ..
        } => {
            let mut new_content = content.clone();
            if let Some(fk) = file_key_prime {
                new_content.file_key.zeroize();
                new_content.file_key = fk.to_vec();
            }
            Node::File {
                id: id.clone(),
                generation,
                created_at: *created_at,
                modified_at: *modified_at,
                content: new_content,
            }
        }
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

    /// One entry in [`FakeDeps::call_log`] — a chronologically ordered
    /// record spanning BOTH the checkpoint seam and `publish_with_cas`, used
    /// to assert cross-call ordering invariants (D-13: persist-before-
    /// publish, consumed-on-resume, GC'd-after-mirror-commit) that separate
    /// per-verb logs (`publish_log`, etc.) cannot express on their own.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CallLogEvent {
        Publish(String),
        PersistWrappedKey(String),
        GetWrappedKey(String),
        DeleteWrappedKey(String),
    }

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
        /// When `Some((ipns_name, remote))`, the NEXT `publish_with_cas`
        /// call for `ipns_name` reports a HIGH-4 CAS-409 conflict against
        /// `remote` instead of succeeding normally — used to simulate "a
        /// concurrent writer added a child mid-rotation" (T-69-12-03). Real
        /// interleaving is not exercised by these in-memory fakes; this is
        /// the deterministic stand-in.
        pub inject_conflict_for: Mutex<Option<(String, PublishedNode)>>,
        /// node_id -> grant rows returned by `query_grants_rooted_at`
        /// (HIGH-3, T-69-12-02). Absent entries return an empty list (the
        /// trait's own default), matching "no grants shared out of this
        /// node".
        pub grants_by_node: Mutex<HashMap<String, Vec<GrantRow>>>,
        /// Ordered log of every `update_grant` call:
        /// `(share_id, encrypted_read_key, new_generation)`.
        pub updated_grants: Mutex<Vec<(String, String, u32)>>,
        /// Ordered log of every `delete_grant` call's `share_id`.
        pub deleted_grants: Mutex<Vec<String>>,
        /// node_id -> base64(ECIES ciphertext) — the ECIES key-checkpoint
        /// store (D-01/D-03, 70.1-08). Wrapped here (not by the engine,
        /// which stays key-material-free per RESEARCH option (b)) using
        /// `owner_pk`/`owner_sk`, simulating what a production
        /// `RotationDeps` impl's own checkpoint store would do.
        checkpoints: Mutex<HashMap<String, String>>,
        /// Chronologically ordered cross-verb call log — see
        /// [`CallLogEvent`].
        pub call_log: Mutex<Vec<CallLogEvent>>,
        /// This fake's own ECIES identity keypair, standing in for the
        /// production adapter's vault/owner keypair (70.1-08 checkpoint
        /// seam). Generated fresh per `FakeDeps` instance.
        owner_sk: ecies::SecretKey,
        owner_pk: ecies::PublicKey,
    }

    impl FakeDeps {
        pub fn new() -> Self {
            let (owner_sk, owner_pk) = ecies::utils::generate_keypair();
            Self {
                records: Mutex::new(HashMap::new()),
                blobs: Mutex::new(HashMap::new()),
                publish_log: Mutex::new(Vec::new()),
                resolve_log: Mutex::new(Vec::new()),
                persist_log: Mutex::new(Vec::new()),
                fail_publish_for: Mutex::new(None),
                inject_conflict_for: Mutex::new(None),
                grants_by_node: Mutex::new(HashMap::new()),
                updated_grants: Mutex::new(Vec::new()),
                deleted_grants: Mutex::new(Vec::new()),
                checkpoints: Mutex::new(HashMap::new()),
                call_log: Mutex::new(Vec::new()),
                owner_sk,
                owner_pk,
            }
        }

        /// Seeds a published node at `ipns_name` with the given CID/sequence.
        pub fn seed(&self, ipns_name: &str, cid: &str, sequence_number: u64, node: PublishedNode) {
            self.records
                .lock()
                .unwrap()
                .insert(ipns_name.to_string(), (cid.to_string(), sequence_number));
            self.blobs.lock().unwrap().insert(cid.to_string(), node);
        }

        /// Registers `grants` as the rows returned for `node_id` by
        /// `query_grants_rooted_at` (HIGH-3 test seam).
        pub fn seed_grants(&self, node_id: &str, grants: Vec<GrantRow>) {
            self.grants_by_node
                .lock()
                .unwrap()
                .insert(node_id.to_string(), grants);
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
        ) -> Result<PublishAttempt, RotationError> {
            if let Some(fail_name) = self.fail_publish_for.lock().unwrap().take() {
                if fail_name == ipns_name {
                    return Err(RotationError::RotateFailed(format!(
                        "simulated publish failure for {ipns_name}"
                    )));
                }
                // Not the targeted name — put it back for a later call.
                *self.fail_publish_for.lock().unwrap() = Some(fail_name);
            }

            if let Some((name, remote)) = self.inject_conflict_for.lock().unwrap().take() {
                if name == ipns_name {
                    // Advance the backing store's seq/cid to the injected
                    // remote so the RETRY publish (after merge) succeeds
                    // against this same "current" state.
                    let current_seq = self
                        .records
                        .lock()
                        .unwrap()
                        .get(ipns_name)
                        .map(|(_, seq)| *seq)
                        .unwrap_or(0);
                    let new_seq = current_seq + 1;
                    let new_cid = format!("{ipns_name}-conflict-cid-v{new_seq}");
                    self.blobs
                        .lock()
                        .unwrap()
                        .insert(new_cid.clone(), remote.clone());
                    self.records
                        .lock()
                        .unwrap()
                        .insert(ipns_name.to_string(), (new_cid, new_seq));
                    return Ok(PublishAttempt::Conflict {
                        remote,
                        current_sequence_number: new_seq,
                    });
                }
                // Not the targeted name — put it back for a later call.
                *self.inject_conflict_for.lock().unwrap() = Some((name, remote));
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
            self.call_log
                .lock()
                .unwrap()
                .push(CallLogEvent::Publish(ipns_name.to_string()));

            Ok(PublishAttempt::Published(PublishOutcome {
                new_sequence_number: new_seq,
            }))
        }

        async fn persist_job(&self, job: &RotationJobRecord) {
            self.persist_log
                .lock()
                .unwrap()
                .push(job.completed_node_ids.len());
        }

        async fn query_grants_rooted_at(
            &self,
            node_id: &str,
        ) -> Result<Vec<GrantRow>, RotationError> {
            Ok(self
                .grants_by_node
                .lock()
                .unwrap()
                .get(node_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn update_grant(
            &self,
            share_id: &str,
            encrypted_read_key: &str,
            new_generation: u32,
        ) -> Result<(), RotationError> {
            self.updated_grants.lock().unwrap().push((
                share_id.to_string(),
                encrypted_read_key.to_string(),
                new_generation,
            ));
            Ok(())
        }

        async fn delete_grant(&self, share_id: &str) -> Result<(), RotationError> {
            self.deleted_grants
                .lock()
                .unwrap()
                .push(share_id.to_string());
            Ok(())
        }

        /// ECIES-wraps the incoming raw key (base64, from the engine's
        /// key-material-free perspective) under `owner_pk` and stores the
        /// resulting ciphertext — simulating a production adapter's own
        /// checkpoint store (RESEARCH option (b), Sharp Question 6.3).
        async fn persist_wrapped_key(
            &self,
            node_id: &str,
            wrapped_b64: &str,
        ) -> Result<(), RotationError> {
            let raw = decode_b64(wrapped_b64).map_err(|e| {
                RotationError::RotateFailed(format!("persist_wrapped_key: bad base64: {e}"))
            })?;
            let ciphertext =
                cipherbox_crypto::wrap_key(&raw, &self.owner_pk.serialize()).map_err(|e| {
                    RotationError::RotateFailed(format!("persist_wrapped_key: wrap failed: {e}"))
                })?;
            self.checkpoints
                .lock()
                .unwrap()
                .insert(node_id.to_string(), base64_encode(&ciphertext));
            self.call_log
                .lock()
                .unwrap()
                .push(CallLogEvent::PersistWrappedKey(node_id.to_string()));
            Ok(())
        }

        /// Looks up the checkpoint (if any) and ECIES-unwraps it via
        /// `owner_sk`, returning the raw key material as base64 (already
        /// unwrapped — the engine's repair path never touches ECIES itself,
        /// per the same key-material-free boundary as `persist_wrapped_key`).
        async fn get_wrapped_key(&self, node_id: &str) -> Result<Option<String>, RotationError> {
            self.call_log
                .lock()
                .unwrap()
                .push(CallLogEvent::GetWrappedKey(node_id.to_string()));
            let Some(ciphertext_b64) = self.checkpoints.lock().unwrap().get(node_id).cloned()
            else {
                return Ok(None);
            };
            let ciphertext = decode_b64(&ciphertext_b64).map_err(|e| {
                RotationError::RotateFailed(format!("get_wrapped_key: bad base64: {e}"))
            })?;
            let raw = cipherbox_crypto::unwrap_key(&ciphertext, &self.owner_sk.serialize())
                .map_err(|e| {
                    RotationError::RotateFailed(format!("get_wrapped_key: unwrap failed: {e}"))
                })?;
            Ok(Some(base64_encode(raw.as_slice())))
        }

        async fn delete_wrapped_key(&self, node_id: &str) -> Result<(), RotationError> {
            self.checkpoints.lock().unwrap().remove(node_id);
            self.call_log
                .lock()
                .unwrap()
                .push(CallLogEvent::DeleteWrappedKey(node_id.to_string()));
            Ok(())
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

    // -----------------------------------------------------------------------
    // CRIT-1 (T-69-12-01): lazy content-key rotation on a File node.
    // -----------------------------------------------------------------------

    fn file_node(id: &str, generation: u32, file_key: Vec<u8>) -> Node {
        Node::File {
            id: id.to_string(),
            generation,
            created_at: 2_000,
            modified_at: 2_000,
            content: cipherbox_core::node::NodeContent {
                cid: "cid-v1".to_string(),
                file_iv: "aaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                size: 42,
                mime_type: "text/plain".to_string(),
                encryption_mode: "GCM".to_string(),
                file_key,
                versions: vec![],
            },
        }
    }

    #[tokio::test]
    async fn crit1_file_rotation_mints_fresh_file_key_and_sets_pending_marker() {
        let deps = FakeDeps::new();
        let read_key = [4u8; 32];
        let old_file_key = vec![9u8; 32];
        let node = file_node(NODE_1_ID, 0, old_file_key.clone());
        deps.seed("k51/file-1", "cid-0", 0, seal_for_seed(&node, &read_key));

        let mut job = RotationJobRecord::new(NODE_1_ID);
        let outcome = rotate_one(&deps, Some(NODE_1_ID), "k51/file-1", &read_key, &mut job)
            .await
            .unwrap();

        let committed = match outcome {
            RotateOneOutcome::Committed(c) => c,
            RotateOneOutcome::Skipped { .. } => panic!("expected a fresh commit, got Skipped"),
        };
        assert!(
            committed.content_rekey_pending,
            "CRIT-1: File rotation must set the content_rekey_pending marker"
        );
        assert!(
            committed.children.is_empty(),
            "File nodes carry no children"
        );

        // Recover the fresh fileKey from what was actually published.
        let resolved = deps.resolve("k51/file-1").await.unwrap().unwrap();
        let published = deps.fetch_node(&resolved.cid).await.unwrap();
        let sealed_bytes = decode_b64(&published.read_sealed).unwrap();
        let body = unseal_node(
            &sealed_bytes,
            &committed.read_key_prime,
            NODE_1_ID,
            NodeKind::File,
            committed.new_generation,
        )
        .unwrap();
        let republished = decode_node(&body).unwrap();
        let new_file_key = match republished {
            Node::File { content, .. } => content.file_key,
            _ => panic!("expected a File node"),
        };
        assert_ne!(
            new_file_key, old_file_key,
            "CRIT-1: a fresh fileKey must be minted on rotate"
        );

        // A holder of the OLD fileKey cannot decrypt the NEXT published version.
        let old_key_arr = zeroizing_32_from_slice(&old_file_key).unwrap();
        let new_key_arr = zeroizing_32_from_slice(&new_file_key).unwrap();
        let iv = [1u8; 12];
        let plaintext = b"next version content";
        let ciphertext = cipherbox_crypto::encrypt_aes_gcm(plaintext, &new_key_arr, &iv).unwrap();
        assert!(
            cipherbox_crypto::decrypt_aes_gcm(&ciphertext, &old_key_arr, &iv).is_err(),
            "CRIT-1: old fileKey must NOT decrypt content encrypted under the new fileKey"
        );
        assert_eq!(
            cipherbox_crypto::decrypt_aes_gcm(&ciphertext, &new_key_arr, &iv).unwrap(),
            plaintext
        );

        // No eager re-encrypt: exactly one publish for this node (the
        // rotation's own re-seal) — no separate "re-encrypt existing
        // content" publish call.
        assert_eq!(deps.publish_count_for("k51/file-1"), 1);
    }

    #[tokio::test]
    async fn crit1_folder_rotation_never_sets_content_rekey_pending() {
        let deps = FakeDeps::new();
        let read_key = [5u8; 32];
        let node = folder(NODE_1_ID, 0, vec![]);
        deps.seed("k51/node-1", "cid-0", 0, seal_for_seed(&node, &read_key));

        let mut job = RotationJobRecord::new(NODE_1_ID);
        let outcome = rotate_one(&deps, Some(NODE_1_ID), "k51/node-1", &read_key, &mut job)
            .await
            .unwrap();

        match outcome {
            RotateOneOutcome::Committed(c) => assert!(
                !c.content_rekey_pending,
                "Folder nodes carry no content — must never set content_rekey_pending"
            ),
            RotateOneOutcome::Skipped { .. } => panic!("expected a fresh commit"),
        }
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

    /// 70.1-13a coalescing: a covered scope-exit delete of the grant-root's
    /// ONLY child passes an EMPTY `root_children` override, so the rotation
    /// publishes the grant-root EXACTLY ONCE (empty, under the new key) — no
    /// batched `republish_parent` (there are no surviving children to track),
    /// and the deleted child is NOT enqueued/republished. This is the single
    /// authoritative publish that replaces the old rotate_one + republish_parent
    /// (+2) + stale-key relink (+1) sequence.
    #[tokio::test]
    async fn override_empty_children_publishes_root_once_and_skips_deleted_child() {
        let deps = FakeDeps::new();
        let root_read_key = [1u8; 32];
        // Grant-root has ONE child (the file about to be deleted).
        seed_root_with_children(&deps, &root_read_key, 1);

        let mut job = RotationJobRecord::new(ROOT_ID);
        let result = rotate_read_from_node_with_root_children(
            &deps,
            ROOT_ID,
            "k51/root",
            &root_read_key,
            &mut job,
            Vec::new(), // post-delete child list: empty
        )
        .await
        .unwrap();

        assert!(
            result.is_some(),
            "a fresh root rotation returns its new key"
        );
        assert_eq!(
            deps.publish_count_for("k51/root"),
            1,
            "coalesced covered scope-exit publishes the grant-root exactly once"
        );
        assert_eq!(
            deps.publish_count_for("k51/child-0"),
            0,
            "the deleted child is excluded from the override, so it is never rotated/republished"
        );
    }

    /// 70.1-13a: with a SURVIVING sibling, the override drops only the deleted
    /// child. The grant-root is published twice (rotate_one + the batched
    /// republish_parent that re-mirrors the rotated sibling under the new key),
    /// the surviving sibling is rotated once, and the deleted child is never
    /// touched. This is the correct, non-clobbering mirror the stale-key relink
    /// could never produce.
    #[tokio::test]
    async fn override_drops_only_the_deleted_child_and_rekeys_survivors() {
        let deps = FakeDeps::new();
        let root_read_key = [1u8; 32];
        // Two children: child-0 (deleted) and child-1 (survives).
        let _child_keys = seed_root_with_children(&deps, &root_read_key, 2);

        // Rebuild the survivor's ref (child-1) exactly as it was sealed under
        // the OLD root key, so the BFS can derive its key.
        let survivor_id = child_uuid(1);
        let survivor_key = [11u8; 32];
        let survivor_sealed = seal_child_read_key(
            &survivor_key,
            &root_read_key,
            &survivor_id,
            NodeKind::Folder,
            0,
        )
        .unwrap();
        let override_children = vec![SealedChildRef {
            name: "child-1".to_string(),
            ipns_name: "k51/child-1".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&survivor_sealed),
        }];

        let mut job = RotationJobRecord::new(ROOT_ID);
        rotate_read_from_node_with_root_children(
            &deps,
            ROOT_ID,
            "k51/root",
            &root_read_key,
            &mut job,
            override_children,
        )
        .await
        .unwrap();

        assert_eq!(
            deps.publish_count_for("k51/root"),
            2,
            "root: rotate_one + one batched republish_parent to re-mirror the survivor"
        );
        assert_eq!(
            deps.publish_count_for("k51/child-1"),
            1,
            "the surviving sibling is rotated exactly once"
        );
        assert_eq!(
            deps.publish_count_for("k51/child-0"),
            0,
            "the deleted child is never rotated/republished"
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
        let outcome = verify_subtree_clean(&deps, "k51/root", &root_read_key)
            .await
            .unwrap();
        assert!(
            !outcome.is_dirty,
            "expected a clean subtree, got: {:?}",
            outcome.frontier
        );
        assert!(
            outcome.frontier.is_empty(),
            "expected a clean subtree, got: {:?}",
            outcome.frontier
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

        let outcome = verify_subtree_clean(&deps, "k51/root", &root_read_key)
            .await
            .unwrap();
        assert!(outcome.is_dirty);
        let frontier = outcome.frontier;
        assert_eq!(
            frontier.len(),
            1,
            "expected exactly one dirty entry, got: {frontier:?}"
        );
        assert_eq!(frontier[0].ipns_name, "k51/child-0");
        assert_eq!(frontier[0].node_id, child_uuid(0));
        assert_eq!(
            frontier[0].parent_ipns_name, "k51/root",
            "child-0's parent is the root at this depth"
        );
    }

    // -----------------------------------------------------------------------
    // D-12 structural catch-up (70.1-04): a `parent_ipns_name`-carrying
    // frontier, a recursive `verify_subtree_clean` (recurse below clean
    // edges, stop below dirty edges), and missing-root-treated-as-dirty.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_subtree_clean_recurses_and_reports_a_deep_dirty_edge_with_its_real_parent() {
        let deps = FakeDeps::new();
        let root_read_key = [20u8; 32];

        // depth-1: A, clean, child of root.
        let a_id = child_uuid(100);
        let a_key = [21u8; 32];
        // depth-2: B, clean, child of A.
        let b_id = child_uuid(101);
        let b_key = [22u8; 32];
        // depth-3: C, DIRTY, child of B -- outpaces B's mirror. A non-
        // recursive verify (the current naive implementation) would never
        // descend past A's own immediate children and would miss this
        // entirely.
        let c_id = child_uuid(102);
        let c_key = [23u8; 32];

        let c_sealed_key = seal_child_read_key(&c_key, &b_key, &c_id, NodeKind::Folder, 0).unwrap();
        let c_ref = SealedChildRef {
            name: "c".to_string(),
            ipns_name: "k51/deep-c".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&c_sealed_key),
        };
        // C's OWN published node is at generation 1 -- it individually
        // committed its own rotation before a crash truncated the batched
        // republish chain that would have bumped B's mirror of it.
        let c_node = folder(&c_id, 1, vec![]);
        deps.seed(
            "k51/deep-c",
            "cid-deep-c-1",
            1,
            seal_for_seed(&c_node, &c_key),
        );

        let b_sealed_key = seal_child_read_key(&b_key, &a_key, &b_id, NodeKind::Folder, 0).unwrap();
        let b_ref = SealedChildRef {
            name: "b".to_string(),
            ipns_name: "k51/mid-b".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&b_sealed_key),
        };
        let b_node = folder(&b_id, 0, vec![c_ref]);
        deps.seed(
            "k51/mid-b",
            "cid-mid-b-0",
            0,
            seal_for_seed(&b_node, &b_key),
        );

        let a_sealed_key =
            seal_child_read_key(&a_key, &root_read_key, &a_id, NodeKind::Folder, 0).unwrap();
        let a_ref = SealedChildRef {
            name: "a".to_string(),
            ipns_name: "k51/mid-a".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&a_sealed_key),
        };
        let a_node = folder(&a_id, 0, vec![b_ref]);
        deps.seed(
            "k51/mid-a",
            "cid-mid-a-0",
            0,
            seal_for_seed(&a_node, &a_key),
        );

        let root_node = folder(ROOT_ID, 0, vec![a_ref]);
        deps.seed(
            "k51/root",
            "cid-root-0",
            0,
            seal_for_seed(&root_node, &root_read_key),
        );

        let outcome = verify_subtree_clean(&deps, "k51/root", &root_read_key)
            .await
            .unwrap();

        assert!(
            outcome.is_dirty,
            "a depth-3 dirty edge must mark the whole outcome dirty"
        );
        assert_eq!(
            outcome.frontier.len(),
            1,
            "a non-recursive verify would miss the depth-3 edge entirely, got: {:?}",
            outcome.frontier
        );
        let entry = &outcome.frontier[0];
        assert_eq!(entry.ipns_name, "k51/deep-c");
        assert_eq!(entry.node_id, c_id);
        assert_eq!(
            entry.parent_ipns_name, "k51/mid-b",
            "the dirty edge's real parent is B (depth-2), not the scope root"
        );
    }

    #[tokio::test]
    async fn verify_subtree_clean_treats_a_missing_root_as_dirty_not_converged() {
        let deps = FakeDeps::new();
        let root_read_key = [24u8; 32];
        // No seed for "k51/ghost-root" at all -- the root has no published
        // record (e.g. a torn-down subtree, or a crash before the very
        // first publish).

        let outcome = verify_subtree_clean(&deps, "k51/ghost-root", &root_read_key)
            .await
            .unwrap();

        assert!(
            outcome.is_dirty,
            "a missing root must be surfaced as dirty, never an empty converged frontier"
        );
        assert!(
            outcome.frontier.is_empty(),
            "a missing root has no discoverable frontier -- but MUST NOT be conflated with clean"
        );
    }

    // -----------------------------------------------------------------------
    // SC#1/SC#2 (Plan 70.1-06, D-11): depth-aware dirty-resume CONSUMPTION --
    // Bug A (the dirty-resume loop's `root_children.iter().find(...)` +
    // `continue` silently drops any depth>=2 entry) and Bug B
    // (`complete_pending_child` silently no-ops instead of the REAL
    // intermediate parent republishing) exercised end-to-end through
    // `rotate_read_from_node`'s Skip-root resume branch -- not just
    // `verify_subtree_clean`'s detection, which the D-12 tests above already
    // cover. Modeled on `resume_after_crash_converges_without_double_bump_when_seeded`
    // below.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sc1_depth2_dirty_entry_consumption_republishes_real_intermediate_parent_not_root() {
        let deps = FakeDeps::new();
        let root_read_key = [40u8; 32];

        // depth-1: A, clean, direct child of root.
        let a_id = child_uuid(200);
        let a_key = [41u8; 32];
        // depth-2: B, DIRTY, child of A -- A's own mirror of B is stale
        // (generation 0) while B individually committed its OWN rotation to
        // generation 1 in a SIMULATED prior (crashed) run below (Plan
        // 70.1-10 fix: the dirty check is now plaintext-only and never
        // decrypts a dirty edge, so B's real current key can ONLY be
        // recovered via the ECIES checkpoint that a genuine prior `rotate_one`
        // call persists -- a directly-seeded fixture with no such checkpoint
        // is no longer a reachable "safe double rotation", it fails closed).
        let b_id = child_uuid(201);
        let b_key_old = [42u8; 32];

        let b_node = folder(&b_id, 0, vec![]);
        deps.seed("k51/b", "cid-b-0", 0, seal_for_seed(&b_node, &b_key_old));

        // --- Simulate the crashed prior run: B individually commits its OWN
        // rotation (mint + persist checkpoint + publish) via a REAL
        // `rotate_one` call, exactly as `d13_*` does for its depth-3 node --
        // this is what actually persists the checkpoint `repair_dirty_node`
        // recovers on resume below.
        let mut prior_job = RotationJobRecord::new(b_id.clone());
        let prior_outcome = rotate_one(&deps, Some(&b_id), "k51/b", &b_key_old, &mut prior_job)
            .await
            .unwrap();
        assert!(
            matches!(prior_outcome, RotateOneOutcome::Committed(ref c) if c.new_generation == 1),
            "expected B's prior run to commit to generation 1"
        );

        // A's mirror of B is left STALE at generation 0, sealed under B's OLD
        // (pre-rotation) key -- the crash truncated A's own batched republish
        // that would have reconciled it.
        let b_sealed_key =
            seal_child_read_key(&b_key_old, &a_key, &b_id, NodeKind::Folder, 0).unwrap();
        let b_ref = SealedChildRef {
            name: "b".to_string(),
            ipns_name: "k51/b".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&b_sealed_key),
        };
        let a_node = folder(&a_id, 0, vec![b_ref]);
        deps.seed("k51/a", "cid-a-0", 0, seal_for_seed(&a_node, &a_key));

        let a_sealed_key =
            seal_child_read_key(&a_key, &root_read_key, &a_id, NodeKind::Folder, 0).unwrap();
        let a_ref = SealedChildRef {
            name: "a".to_string(),
            ipns_name: "k51/a".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&a_sealed_key),
        };
        let root_node = folder(ROOT_ID, 0, vec![a_ref]);
        deps.seed(
            "k51/root",
            "cid-root-0",
            0,
            seal_for_seed(&root_node, &root_read_key),
        );

        // Resume: root already committed (fast-path Skip) -- the dirty tail
        // below it (B, real parent A) is what this run must reconcile.
        let mut job = RotationJobRecord::new(ROOT_ID);
        job.completed_node_ids.insert(ROOT_ID.to_string());

        rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap();

        assert_eq!(
            deps.publish_count_for("k51/b"),
            1,
            "B was consumed exactly once -- via the SIMULATED prior crashed run's own \
             rotate_one commit; the resumed walk repairs A's mirror via the ECIES \
             checkpoint WITHOUT re-rotating B's own body a second time (Plan 70.1-10)"
        );
        assert_eq!(
            deps.publish_count_for("k51/a"),
            1,
            "A (B's REAL parent) must republish exactly once to absorb B's decrement -- \
             Bug A's root_children.find(...) drop would leave this at 0"
        );
        assert_eq!(
            deps.publish_count_for("k51/root"),
            0,
            "root must NOT carry a wedged or mis-attributed pending count -- root itself \
             was a pure resume-skip with no root-direct dirty children this run"
        );

        // Confirm A's mirror of B was actually fixed (not just "some publish
        // happened") -- unseal A's newly-republished body and check B's ref
        // now reflects B's CURRENT generation.
        let a_resolved = deps.resolve("k51/a").await.unwrap().unwrap();
        let a_pub = deps.fetch_node(&a_resolved.cid).await.unwrap();
        let a_sealed_bytes = decode_b64(&a_pub.read_sealed).unwrap();
        let a_body = unseal_node(
            &a_sealed_bytes,
            &a_key,
            &a_id,
            NodeKind::Folder,
            a_pub.generation,
        )
        .unwrap();
        let a_node_after = decode_node(&a_body).unwrap();
        let b_ref_after = node_children(&a_node_after)
            .into_iter()
            .find(|c| c.ipns_name == "k51/b")
            .unwrap();
        assert_eq!(
            b_ref_after.generation, 1,
            "A's mirror of B must reflect B's CURRENT (checkpoint-recovered) generation \
             from the ONE real rotation B underwent (in the simulated prior crashed run)"
        );
    }

    #[tokio::test]
    async fn sc2_depth3_dirty_entry_decrement_is_not_dropped_across_two_intermediate_hops() {
        let deps = FakeDeps::new();
        let root_read_key = [50u8; 32];

        // depth-1: A, clean, direct child of root.
        let a_id = child_uuid(210);
        let a_key = [51u8; 32];
        // depth-2: A2, clean, child of A -- found only by walking THROUGH A
        // (exercises the seed-or-find primitive's multi-hop descent, not a
        // single root->child hop like the SC#1 test above).
        let a2_id = child_uuid(211);
        let a2_key = [52u8; 32];
        // depth-3: C, DIRTY, child of A2 -- individually rotated below (a
        // SIMULATED prior crashed run, mirroring `d13_*`/`sc1_*`) so its
        // checkpoint is genuinely persisted for `repair_dirty_node` to
        // recover on resume (Plan 70.1-10 fix: the dirty check is now
        // plaintext-only and never decrypts a dirty edge).
        let c_id = child_uuid(212);
        let c_key_old = [53u8; 32];

        let c_node = folder(&c_id, 0, vec![]);
        deps.seed("k51/c", "cid-c-0", 0, seal_for_seed(&c_node, &c_key_old));

        let mut prior_job = RotationJobRecord::new(c_id.clone());
        let prior_outcome = rotate_one(&deps, Some(&c_id), "k51/c", &c_key_old, &mut prior_job)
            .await
            .unwrap();
        assert!(
            matches!(prior_outcome, RotateOneOutcome::Committed(ref c) if c.new_generation == 1),
            "expected C's prior run to commit to generation 1"
        );

        let c_sealed_key =
            seal_child_read_key(&c_key_old, &a2_key, &c_id, NodeKind::Folder, 0).unwrap();
        let c_ref = SealedChildRef {
            name: "c".to_string(),
            ipns_name: "k51/c".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&c_sealed_key),
        };
        let a2_node = folder(&a2_id, 0, vec![c_ref]);
        deps.seed("k51/a2", "cid-a2-0", 0, seal_for_seed(&a2_node, &a2_key));

        let a2_sealed_key =
            seal_child_read_key(&a2_key, &a_key, &a2_id, NodeKind::Folder, 0).unwrap();
        let a2_ref = SealedChildRef {
            name: "a2".to_string(),
            ipns_name: "k51/a2".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&a2_sealed_key),
        };
        let a_node = folder(&a_id, 0, vec![a2_ref]);
        deps.seed("k51/a", "cid-a-0", 0, seal_for_seed(&a_node, &a_key));

        let a_sealed_key =
            seal_child_read_key(&a_key, &root_read_key, &a_id, NodeKind::Folder, 0).unwrap();
        let a_ref = SealedChildRef {
            name: "a".to_string(),
            ipns_name: "k51/a".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&a_sealed_key),
        };
        let root_node = folder(ROOT_ID, 0, vec![a_ref]);
        deps.seed(
            "k51/root",
            "cid-root-0",
            0,
            seal_for_seed(&root_node, &root_read_key),
        );

        let mut job = RotationJobRecord::new(ROOT_ID);
        job.completed_node_ids.insert(ROOT_ID.to_string());

        rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap();

        assert_eq!(
            deps.publish_count_for("k51/c"),
            1,
            "the depth-3 dirty entry must be consumed exactly once"
        );
        assert_eq!(
            deps.publish_count_for("k51/a2"),
            1,
            "A2 (C's REAL parent, itself found by walking THROUGH A) must republish \
             exactly once -- complete_pending_child must not drop this decrement"
        );
        assert_eq!(
            deps.publish_count_for("k51/a"),
            0,
            "A must not be touched -- it has no root-direct dirty children this run"
        );
        assert_eq!(
            deps.publish_count_for("k51/root"),
            0,
            "root must not carry a mis-attributed pending count"
        );
    }

    #[tokio::test]
    async fn plan_70_1_10_dirty_edge_whose_parent_also_rotated_never_attempts_decrypt() {
        // root -[clean]-> A -[DIRTY]-> B
        //
        // Reproduces the T1 AEAD-crash regression directly (Plan 70.1-10): A's
        // OWN identity key ALSO changes in this same history (a real prior
        // `rotate_one` call for A, independent of B's own prior rotation),
        // while A's mirror-of-B entry is left sealed under A's OLD key (A's
        // own batched republish reflecting B's rotation never landed -- only
        // an out-of-band `seal_child_read_key` call, which never happens
        // here, would have updated it). The PRE-FIX implementation decrypted
        // the stale B ref with A's CURRENT key BEFORE comparing generations,
        // failing closed with an AEAD authentication error instead of ever
        // discovering the dirty edge. The fix must never attempt this decrypt
        // for a dirty edge at all.
        let deps = FakeDeps::new();
        let root_read_key = [70u8; 32];

        let a_id = child_uuid(220);
        let a_key_old = [71u8; 32];
        let b_id = child_uuid(221);
        let b_key_old = [72u8; 32];

        // B individually commits its OWN prior rotation -- entirely
        // independent of A's own rotation below.
        let b_node = folder(&b_id, 0, vec![]);
        deps.seed("k51/b3", "cid-b3-0", 0, seal_for_seed(&b_node, &b_key_old));
        let mut b_prior_job = RotationJobRecord::new(b_id.clone());
        rotate_one(&deps, Some(&b_id), "k51/b3", &b_key_old, &mut b_prior_job)
            .await
            .unwrap();

        // A's mirror-of-B, sealed under A's OLD key -- never updated after
        // A's own later rotation below.
        let b_sealed_under_a_old =
            seal_child_read_key(&b_key_old, &a_key_old, &b_id, NodeKind::Folder, 0).unwrap();
        let b_ref = SealedChildRef {
            name: "b3".to_string(),
            ipns_name: "k51/b3".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&b_sealed_under_a_old),
        };

        // A carries that stale B ref, then individually commits its OWN
        // prior rotation -- A's identity key changes (a_key_old ->
        // a_key_new), but its re-sealed body still carries the UNCHANGED
        // (stale) B ref byte-for-byte.
        let a_node = folder(&a_id, 0, vec![b_ref]);
        deps.seed("k51/a3", "cid-a3-0", 0, seal_for_seed(&a_node, &a_key_old));
        let mut a_prior_job = RotationJobRecord::new(a_id.clone());
        let a_prior_outcome =
            rotate_one(&deps, Some(&a_id), "k51/a3", &a_key_old, &mut a_prior_job)
                .await
                .unwrap();
        let a_key_new = match a_prior_outcome {
            RotateOneOutcome::Committed(c) => {
                assert_eq!(c.new_generation, 1);
                c.read_key_prime.clone()
            }
            RotateOneOutcome::Skipped { .. } => panic!("expected A's prior run to commit"),
        };

        // Root's mirror of A IS up to date (a separate, already-landed
        // republish reflecting A's OWN rotation) -- a CLEAN edge, sealed
        // under A's NEW key.
        let a_sealed_key =
            seal_child_read_key(&a_key_new, &root_read_key, &a_id, NodeKind::Folder, 1).unwrap();
        let a_ref = SealedChildRef {
            name: "a3".to_string(),
            ipns_name: "k51/a3".to_string(),
            generation: 1,
            version_floor: 0,
            read_key_sealed: base64_encode(&a_sealed_key),
        };
        let root_node = folder(ROOT_ID, 0, vec![a_ref]);
        deps.seed(
            "k51/root3",
            "cid-root3-0",
            0,
            seal_for_seed(&root_node, &root_read_key),
        );

        let mut job = RotationJobRecord::new(ROOT_ID);
        job.completed_node_ids.insert(ROOT_ID.to_string());

        // Pre-fix, this call would FAIL with an AEAD authentication error
        // while attempting to decrypt B's stale ref under A's NEW key.
        // Post-fix, it resolves and correctly repairs the dirty edge via the
        // checkpoint.
        rotate_read_from_node(&deps, ROOT_ID, "k51/root3", &root_read_key, &mut job)
            .await
            .expect("must not fail decrypting the dirty edge's stale ref");

        assert_eq!(
            deps.publish_count_for("k51/a3"),
            2,
            "A publishes once for its OWN prior rotation, once more for the batched \
             republish absorbing B's mirror repair"
        );
        assert_eq!(
            deps.publish_count_for("k51/b3"),
            1,
            "B is never re-rotated by the resumed walk -- only its mirror entry in A \
             is repaired via the ECIES checkpoint"
        );
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

    // -----------------------------------------------------------------------
    // HIGH-3 (T-69-12-02): inner-grant re-mint rooted at a subtree node.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn high3_inner_grant_at_a_child_is_re_minted_and_revoked_recipient_is_cut() {
        let deps = FakeDeps::new();
        let root_read_key = [7u8; 32];
        seed_root_with_children(&deps, &root_read_key, 1);

        // An inner grant rooted at child-0 -- a leaf deep in the rotating
        // tree, NOT the scope root -- must still be reached by HIGH-3.
        let (active_sk, active_pk) = ecies::utils::generate_keypair();
        let (_revoked_sk, revoked_pk) = ecies::utils::generate_keypair();
        deps.seed_grants(
            &child_uuid(0),
            vec![
                GrantRow {
                    share_id: "share-active".to_string(),
                    recipient_public_key: active_pk.serialize().to_vec(),
                    is_revoked: false,
                },
                GrantRow {
                    share_id: "share-revoked".to_string(),
                    recipient_public_key: revoked_pk.serialize().to_vec(),
                    is_revoked: true,
                },
            ],
        );

        let mut job = RotationJobRecord::new(ROOT_ID);
        let result = rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            deps.deleted_grants.lock().unwrap().clone(),
            vec!["share-revoked".to_string()],
            "HIGH-3: a revoked recipient's row must be deleted, never re-minted"
        );

        let updated = deps.updated_grants.lock().unwrap().clone();
        assert_eq!(
            updated.len(),
            1,
            "exactly the non-revoked share is re-minted, got: {updated:?}"
        );
        let (share_id, encrypted_read_key, new_generation) = &updated[0];
        assert_eq!(share_id, "share-active");
        assert_eq!(*new_generation, 1);

        // Recover child-0's ACTUAL new readKey via the normal parent-chain
        // path (root's new readKey -> SealedChildRef -> unseal_child_read_key)
        // and confirm it matches what was ECIES-wrapped for the survivor.
        let root_resolved = deps.resolve("k51/root").await.unwrap().unwrap();
        let root_pub = deps.fetch_node(&root_resolved.cid).await.unwrap();
        let root_sealed = decode_b64(&root_pub.read_sealed).unwrap();
        let root_body = unseal_node(
            &root_sealed,
            &result.read_key,
            ROOT_ID,
            NodeKind::Folder,
            result.generation,
        )
        .unwrap();
        let root_node = decode_node(&root_body).unwrap();
        let children = node_children(&root_node);
        let child_ref = children
            .iter()
            .find(|c| c.ipns_name == "k51/child-0")
            .unwrap();
        let child_sealed_key = decode_b64(&child_ref.read_key_sealed).unwrap();
        let child_new_read_key = unseal_child_read_key(
            &child_sealed_key,
            &result.read_key,
            &child_uuid(0),
            NodeKind::Folder,
            child_ref.generation,
        )
        .unwrap();

        // The share-grant `encryptedReadKey` is wire-encoded as HEX (the API
        // validates `/^(?:[0-9a-fA-F]{2})+$/` and decodes via
        // `Buffer.from(.., 'hex')`), NOT base64.
        assert!(
            !encrypted_read_key.is_empty()
                && encrypted_read_key.len() % 2 == 0
                && encrypted_read_key
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit()),
            "re-minted encryptedReadKey must be valid even-length hex, got: {encrypted_read_key}"
        );
        let wrapped_bytes = hex::decode(encrypted_read_key).unwrap();
        let unwrapped =
            cipherbox_crypto::unwrap_key(&wrapped_bytes, &active_sk.serialize()).unwrap();
        assert_eq!(
            unwrapped.as_slice(),
            child_new_read_key.as_slice(),
            "the re-minted encrypted key must wrap child-0's ACTUAL new readKey"
        );
    }

    // -----------------------------------------------------------------------
    // HIGH-4 (T-69-12-03): CAS-409 concurrent-add re-fetch + re-merge.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn high4_concurrent_add_mid_rotation_is_merged_not_dropped() {
        let deps = FakeDeps::new();
        let root_read_key = [8u8; 32];
        seed_root_with_children(&deps, &root_read_key, 1);

        // Simulate "a concurrent writer added a NEW child (child-concurrent)
        // to root while THIS rotation was in flight": a remote PublishedNode
        // at root's PRE-rotation generation, sealed under the SAME (OLD)
        // root read key -- the concurrent writer wasn't rotating, just
        // adding a child via a normal write.
        let concurrent_child_key = [77u8; 32];
        let concurrent_child_id = child_uuid(99);
        let concurrent_child_node = folder(&concurrent_child_id, 0, vec![]);
        deps.seed(
            "k51/child-concurrent",
            "cid-child-concurrent-0",
            0,
            seal_for_seed(&concurrent_child_node, &concurrent_child_key),
        );
        let concurrent_sealed_key = seal_child_read_key(
            &concurrent_child_key,
            &root_read_key,
            &concurrent_child_id,
            NodeKind::Folder,
            0,
        )
        .unwrap();

        let remote_root_node = folder(
            ROOT_ID,
            0,
            vec![
                SealedChildRef {
                    name: "child-0".to_string(),
                    ipns_name: "k51/child-0".to_string(),
                    generation: 0,
                    version_floor: 0,
                    read_key_sealed: base64_encode(
                        &seal_child_read_key(
                            &[10u8; 32],
                            &root_read_key,
                            &child_uuid(0),
                            NodeKind::Folder,
                            0,
                        )
                        .unwrap(),
                    ),
                },
                SealedChildRef {
                    name: "concurrent-child".to_string(),
                    ipns_name: "k51/child-concurrent".to_string(),
                    generation: 0,
                    version_floor: 0,
                    read_key_sealed: base64_encode(&concurrent_sealed_key),
                },
            ],
        );
        let remote_published = seal_for_seed(&remote_root_node, &root_read_key);

        *deps.inject_conflict_for.lock().unwrap() =
            Some(("k51/root".to_string(), remote_published));

        let mut job = RotationJobRecord::new(ROOT_ID);
        let result = rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap()
            .unwrap();

        // Fetch the FINAL published root and confirm the concurrently-added
        // child survived the rotation's merge -- never silently dropped.
        let root_resolved = deps.resolve("k51/root").await.unwrap().unwrap();
        let root_pub = deps.fetch_node(&root_resolved.cid).await.unwrap();
        let root_sealed = decode_b64(&root_pub.read_sealed).unwrap();
        let root_body = unseal_node(
            &root_sealed,
            &result.read_key,
            ROOT_ID,
            NodeKind::Folder,
            result.generation,
        )
        .unwrap();
        let root_node = decode_node(&root_body).unwrap();
        let children = node_children(&root_node);

        assert!(
            children
                .iter()
                .any(|c| c.ipns_name == "k51/child-concurrent"),
            "HIGH-4: a child added concurrently mid-rotation must be present \
             in the completed parent, got: {children:?}"
        );
        assert!(
            children.iter().any(|c| c.ipns_name == "k51/child-0"),
            "the original child must also survive the merge"
        );
    }

    // -----------------------------------------------------------------------
    // D-13 (Plan 70.1-08): ECIES key-checkpoint seam + dirty-node repair.
    // An already-rotated dirty node's STALE (parent-mirror-derived) key must
    // NEVER be fed into `rotate_one`/`unseal_node` (T-70.1-20) -- the BFS
    // must detect it and repair via the checkpoint instead.
    // -----------------------------------------------------------------------

    use super::test_support::CallLogEvent;

    #[tokio::test]
    async fn d13_depth3_post_crash_dirty_node_converges_via_ecies_checkpoint_repair() {
        let deps = FakeDeps::new();
        let root_read_key = [60u8; 32];

        // depth-1: A, clean, direct child of root.
        let a_id = child_uuid(300);
        let a_key = [61u8; 32];
        // depth-2: B, clean (as far as A's mirror knows) -- but B is the
        // REAL parent of the depth-3 dirty node C, and also has a second,
        // untouched clean child D (fan-out >= 2).
        let b_id = child_uuid(301);
        let b_key = [62u8; 32];
        // depth-3: C -- individually rotated below (simulating the crashed
        // prior run) BEFORE the resumed walk -- its OWN key changes to a
        // genuinely fresh, independently minted value, but B's mirror of it
        // is left stale (the crash truncates the batched parent republish
        // that would have reconciled it).
        let c_id = child_uuid(302);
        let c_key_old = [63u8; 32];
        // depth-3: D, B's OTHER child -- untouched, proves fan-out >= 2 does
        // not cause a spurious extra republish or touch root/A.
        let d_id = child_uuid(303);
        let d_key = [64u8; 32];

        deps.seed(
            "k51/deep-d",
            "cid-deep-d-0",
            0,
            seal_for_seed(&folder(&d_id, 0, vec![]), &d_key),
        );
        deps.seed(
            "k51/deep-c",
            "cid-deep-c-0",
            0,
            seal_for_seed(&folder(&c_id, 0, vec![]), &c_key_old),
        );

        let c_sealed_key =
            seal_child_read_key(&c_key_old, &b_key, &c_id, NodeKind::Folder, 0).unwrap();
        let c_ref = SealedChildRef {
            name: "deep-c".to_string(),
            ipns_name: "k51/deep-c".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&c_sealed_key),
        };
        let d_sealed_key = seal_child_read_key(&d_key, &b_key, &d_id, NodeKind::Folder, 0).unwrap();
        let d_ref = SealedChildRef {
            name: "deep-d".to_string(),
            ipns_name: "k51/deep-d".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&d_sealed_key),
        };
        deps.seed(
            "k51/mid-b",
            "cid-mid-b-0",
            0,
            seal_for_seed(&folder(&b_id, 0, vec![c_ref, d_ref]), &b_key),
        );

        let b_sealed_key = seal_child_read_key(&b_key, &a_key, &b_id, NodeKind::Folder, 0).unwrap();
        let b_ref = SealedChildRef {
            name: "mid-b".to_string(),
            ipns_name: "k51/mid-b".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&b_sealed_key),
        };
        deps.seed(
            "k51/mid-a",
            "cid-mid-a-0",
            0,
            seal_for_seed(&folder(&a_id, 0, vec![b_ref]), &a_key),
        );

        let a_sealed_key =
            seal_child_read_key(&a_key, &root_read_key, &a_id, NodeKind::Folder, 0).unwrap();
        let a_ref = SealedChildRef {
            name: "mid-a".to_string(),
            ipns_name: "k51/mid-a".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&a_sealed_key),
        };
        deps.seed(
            "k51/root",
            "cid-root-0",
            0,
            seal_for_seed(&folder(ROOT_ID, 0, vec![a_ref]), &root_read_key),
        );

        // --- STEP 1: simulate the crashed prior run -- C individually
        // commits its OWN rotation (mint + persist checkpoint + publish),
        // but the crash happens before B's batched republish reconciles
        // B's mirror of C.
        let mut prior_job = RotationJobRecord::new(c_id.clone());
        let prior_outcome =
            rotate_one(&deps, Some(&c_id), "k51/deep-c", &c_key_old, &mut prior_job)
                .await
                .unwrap();
        let c_key_new = match prior_outcome {
            RotateOneOutcome::Committed(c) => {
                assert_eq!(c.new_generation, 1);
                c.read_key_prime.clone()
            }
            RotateOneOutcome::Skipped { .. } => panic!("expected C's prior run to commit"),
        };

        // --- STEP 2: resume the FULL walk. Root already committed
        // pre-crash (fast-path Skip); the dirty tail (C, real parent B) is
        // what this run must reconcile.
        let mut job = RotationJobRecord::new(ROOT_ID);
        job.completed_node_ids.insert(ROOT_ID.to_string());

        let result = rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "root was a pure resume-skip -- no fresh root key"
        );

        // --- Assertion 1: owner navigability -- a normal owner who only
        // knows the ROOT's read key can still navigate the FULL updated
        // chain down to C's CURRENT published body.
        let root_resolved = deps.resolve("k51/root").await.unwrap().unwrap();
        let root_pub = deps.fetch_node(&root_resolved.cid).await.unwrap();
        let root_body = unseal_node(
            &decode_b64(&root_pub.read_sealed).unwrap(),
            &root_read_key,
            ROOT_ID,
            NodeKind::Folder,
            root_pub.generation,
        )
        .unwrap();
        let a_ref_now = node_children(&decode_node(&root_body).unwrap())
            .into_iter()
            .find(|c| c.ipns_name == "k51/mid-a")
            .unwrap();
        let a_key_derived =
            derive_child_read_key(&root_read_key, &a_ref_now, &a_id, NodeKind::Folder).unwrap();
        assert_eq!(&*a_key_derived, &a_key);

        let a_resolved = deps.resolve("k51/mid-a").await.unwrap().unwrap();
        let a_pub = deps.fetch_node(&a_resolved.cid).await.unwrap();
        let a_body = unseal_node(
            &decode_b64(&a_pub.read_sealed).unwrap(),
            &a_key_derived,
            &a_id,
            NodeKind::Folder,
            a_pub.generation,
        )
        .unwrap();
        let b_ref_now = node_children(&decode_node(&a_body).unwrap())
            .into_iter()
            .find(|c| c.ipns_name == "k51/mid-b")
            .unwrap();
        let b_key_derived = derive_child_read_key(
            a_key_derived.as_slice(),
            &b_ref_now,
            &b_id,
            NodeKind::Folder,
        )
        .unwrap();
        assert_eq!(&*b_key_derived, &b_key);

        let b_resolved = deps.resolve("k51/mid-b").await.unwrap().unwrap();
        let b_pub = deps.fetch_node(&b_resolved.cid).await.unwrap();
        let b_body = unseal_node(
            &decode_b64(&b_pub.read_sealed).unwrap(),
            &b_key_derived,
            &b_id,
            NodeKind::Folder,
            b_pub.generation,
        )
        .unwrap();
        let b_children_now = node_children(&decode_node(&b_body).unwrap());
        let c_ref_now = b_children_now
            .iter()
            .find(|c| c.ipns_name == "k51/deep-c")
            .unwrap();
        assert_eq!(
            c_ref_now.generation, 1,
            "B's mirror of C must be repaired to reflect C's CURRENT generation"
        );
        let d_ref_now = b_children_now
            .iter()
            .find(|c| c.ipns_name == "k51/deep-d")
            .unwrap();
        assert_eq!(
            d_ref_now.generation, 0,
            "D (B's untouched sibling) must be left alone"
        );

        let c_key_derived =
            derive_child_read_key(b_key_derived.as_slice(), c_ref_now, &c_id, NodeKind::Folder)
                .unwrap();
        let c_resolved = deps.resolve("k51/deep-c").await.unwrap().unwrap();
        let c_pub = deps.fetch_node(&c_resolved.cid).await.unwrap();
        let c_sealed_bytes = decode_b64(&c_pub.read_sealed).unwrap();
        unseal_node(
            &c_sealed_bytes,
            &c_key_derived,
            &c_id,
            NodeKind::Folder,
            c_pub.generation,
        )
        .expect("owner navigability: the repaired chain must unseal C's CURRENT body");
        assert_eq!(&*c_key_derived, &*c_key_new);

        // --- Assertion 2: revoked-reader cut -- the STALE pre-crash key
        // (c_key_old, still what a stale/revoked reader would hold) MUST
        // NOT unseal C's CURRENT published body.
        assert!(
            unseal_node(
                &c_sealed_bytes,
                &c_key_old,
                &c_id,
                NodeKind::Folder,
                c_pub.generation
            )
            .is_err(),
            "the OLD (pre-rotation) key must fail to unseal C's CURRENT body"
        );

        // --- Assertion 3: no spurious extra republish / root+A untouched.
        assert_eq!(deps.publish_count_for("k51/root"), 0);
        assert_eq!(deps.publish_count_for("k51/mid-a"), 0);
        assert_eq!(
            deps.publish_count_for("k51/mid-b"),
            1,
            "B must republish EXACTLY once to absorb C's repair, despite fan-out >= 2"
        );

        // --- Assertion 4: ECIES checkpoint lifecycle, via the ordered call
        // log (persisted-before-publish, consumed-on-resume,
        // GC'd-after-mirror-commit).
        let log = deps.call_log.lock().unwrap().clone();
        let persist_idx = log
            .iter()
            .position(|e| *e == CallLogEvent::PersistWrappedKey(c_id.clone()))
            .expect("persist_wrapped_key must have been called for C");
        let step1_publish_idx = log
            .iter()
            .position(|e| *e == CallLogEvent::Publish("k51/deep-c".to_string()))
            .expect("C's own (step-1) publish must be in the log");
        assert!(
            persist_idx < step1_publish_idx,
            "the checkpoint MUST be persisted BEFORE C's own publish (D-03), got: {log:?}"
        );

        let get_idx = log
            .iter()
            .position(|e| *e == CallLogEvent::GetWrappedKey(c_id.clone()))
            .expect("get_wrapped_key must be consumed on resume");
        assert!(
            get_idx > step1_publish_idx,
            "checkpoint must be consumed AFTER it was persisted"
        );

        let mid_b_publish_idx = log
            .iter()
            .rposition(|e| *e == CallLogEvent::Publish("k51/mid-b".to_string()))
            .expect("B's republish must be in the log");
        let delete_idx = log
            .iter()
            .position(|e| *e == CallLogEvent::DeleteWrappedKey(c_id.clone()))
            .expect("delete_wrapped_key must GC the checkpoint");
        assert!(
            delete_idx > mid_b_publish_idx,
            "the checkpoint must be GC'd AFTER the parent mirror commit, got: {log:?}"
        );
    }

    #[tokio::test]
    async fn d13_multi_dirty_edge_lost_key_window_repairs_both_children_with_one_republish() {
        let deps = FakeDeps::new();
        let root_read_key = [80u8; 32];

        let b_id = child_uuid(320);
        let b_key = [81u8; 32];
        let c1_id = child_uuid(321);
        let c1_key_old = [82u8; 32];
        let c2_id = child_uuid(322);
        let c2_key_old = [83u8; 32];

        deps.seed(
            "k51/multi-c1",
            "cid-multi-c1-0",
            0,
            seal_for_seed(&folder(&c1_id, 0, vec![]), &c1_key_old),
        );
        deps.seed(
            "k51/multi-c2",
            "cid-multi-c2-0",
            0,
            seal_for_seed(&folder(&c2_id, 0, vec![]), &c2_key_old),
        );

        let c1_sealed_key =
            seal_child_read_key(&c1_key_old, &b_key, &c1_id, NodeKind::Folder, 0).unwrap();
        let c1_ref = SealedChildRef {
            name: "multi-c1".to_string(),
            ipns_name: "k51/multi-c1".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&c1_sealed_key),
        };
        let c2_sealed_key =
            seal_child_read_key(&c2_key_old, &b_key, &c2_id, NodeKind::Folder, 0).unwrap();
        let c2_ref = SealedChildRef {
            name: "multi-c2".to_string(),
            ipns_name: "k51/multi-c2".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&c2_sealed_key),
        };
        deps.seed(
            "k51/multi-b",
            "cid-multi-b-0",
            0,
            seal_for_seed(&folder(&b_id, 0, vec![c1_ref, c2_ref]), &b_key),
        );

        let b_sealed_key =
            seal_child_read_key(&b_key, &root_read_key, &b_id, NodeKind::Folder, 0).unwrap();
        let b_ref = SealedChildRef {
            name: "multi-b".to_string(),
            ipns_name: "k51/multi-b".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&b_sealed_key),
        };
        deps.seed(
            "k51/root",
            "cid-multi-root-0",
            0,
            seal_for_seed(&folder(ROOT_ID, 0, vec![b_ref]), &root_read_key),
        );

        // Simulate the crashed prior run individually rotating BOTH
        // children (the LOST-KEY window this variant targets -- NOT a
        // concurrent-add race against `republish_parent`'s own CAS-409
        // fail-closed path, which stays untouched by this plan).
        let mut prior_job1 = RotationJobRecord::new(c1_id.clone());
        rotate_one(
            &deps,
            Some(&c1_id),
            "k51/multi-c1",
            &c1_key_old,
            &mut prior_job1,
        )
        .await
        .unwrap();
        let mut prior_job2 = RotationJobRecord::new(c2_id.clone());
        rotate_one(
            &deps,
            Some(&c2_id),
            "k51/multi-c2",
            &c2_key_old,
            &mut prior_job2,
        )
        .await
        .unwrap();

        let mut job = RotationJobRecord::new(ROOT_ID);
        job.completed_node_ids.insert(ROOT_ID.to_string());
        let result = rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap();
        assert!(result.is_none());

        assert_eq!(deps.publish_count_for("k51/root"), 0);
        assert_eq!(
            deps.publish_count_for("k51/multi-b"),
            1,
            "B must republish EXACTLY once even with TWO dirty children \
             (T-69-08-03 DoS mitigation extends to the repair path)"
        );

        let log = deps.call_log.lock().unwrap().clone();
        assert!(log.contains(&CallLogEvent::GetWrappedKey(c1_id.clone())));
        assert!(log.contains(&CallLogEvent::GetWrappedKey(c2_id.clone())));
        assert!(log.contains(&CallLogEvent::DeleteWrappedKey(c1_id.clone())));
        assert!(log.contains(&CallLogEvent::DeleteWrappedKey(c2_id.clone())));

        let b_resolved = deps.resolve("k51/multi-b").await.unwrap().unwrap();
        let b_pub = deps.fetch_node(&b_resolved.cid).await.unwrap();
        let b_body = unseal_node(
            &decode_b64(&b_pub.read_sealed).unwrap(),
            &b_key,
            &b_id,
            NodeKind::Folder,
            b_pub.generation,
        )
        .unwrap();
        let children_now = node_children(&decode_node(&b_body).unwrap());
        assert_eq!(
            children_now
                .iter()
                .find(|c| c.ipns_name == "k51/multi-c1")
                .unwrap()
                .generation,
            1
        );
        assert_eq!(
            children_now
                .iter()
                .find(|c| c.ipns_name == "k51/multi-c2")
                .unwrap()
                .generation,
            1
        );
    }

    // -------------------------------------------------------------------
    // Todo 1 (74-01, SC1): RotateReadResult must surface EVERY rotated
    // node's post-rotation read key, keyed by ipns_name -- not just the
    // grant root's. A >=2-level tree (grant-root -> folderB -> fileC) must
    // yield a `rotated_nodes` map containing all three levels.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_read_surfaces_every_rotated_node_key_for_a_deep_tree() {
        let deps = FakeDeps::new();
        let root_read_key = [30u8; 32];
        let folder_b_id = child_uuid(200);
        let folder_b_key = [31u8; 32];
        let file_c_id = child_uuid(201);
        let file_c_key = [32u8; 32];

        // depth-2 leaf: fileC, child of folderB.
        let file_c_node = Node::File {
            id: file_c_id.clone(),
            generation: 0,
            created_at: 3_000,
            modified_at: 3_000,
            content: cipherbox_core::node::NodeContent {
                cid: "cid-file-c-content".to_string(),
                file_iv: "bbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                size: 10,
                mime_type: "text/plain".to_string(),
                encryption_mode: "GCM".to_string(),
                file_key: vec![99u8; 32],
                versions: vec![],
            },
        };
        deps.seed(
            "k51/file-c",
            "cid-file-c-0",
            0,
            seal_for_seed(&file_c_node, &file_c_key),
        );

        let c_sealed_key =
            seal_child_read_key(&file_c_key, &folder_b_key, &file_c_id, NodeKind::File, 0).unwrap();
        let c_ref = SealedChildRef {
            name: "file-c".to_string(),
            ipns_name: "k51/file-c".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&c_sealed_key),
        };

        // depth-1: folderB, child of root, itself parenting fileC.
        let folder_b_node = folder(&folder_b_id, 0, vec![c_ref]);
        deps.seed(
            "k51/folder-b",
            "cid-folder-b-0",
            0,
            seal_for_seed(&folder_b_node, &folder_b_key),
        );

        let b_sealed_key = seal_child_read_key(
            &folder_b_key,
            &root_read_key,
            &folder_b_id,
            NodeKind::Folder,
            0,
        )
        .unwrap();
        let b_ref = SealedChildRef {
            name: "folder-b".to_string(),
            ipns_name: "k51/folder-b".to_string(),
            generation: 0,
            version_floor: 0,
            read_key_sealed: base64_encode(&b_sealed_key),
        };

        let root_node = folder(ROOT_ID, 0, vec![b_ref]);
        deps.seed(
            "k51/root",
            "cid-root-0",
            0,
            seal_for_seed(&root_node, &root_read_key),
        );

        let mut job = RotationJobRecord::new(ROOT_ID);
        let result = rotate_read_from_node(&deps, ROOT_ID, "k51/root", &root_read_key, &mut job)
            .await
            .unwrap()
            .expect("a fresh root rotation must return Some(RotateReadResult)");

        // Every rotated node's ipns_name must be present in the map -- root,
        // folderB, AND fileC -- not just the grant root (this is the exact
        // deep-scope-exit gap this plan closes).
        for ipns_name in ["k51/root", "k51/folder-b", "k51/file-c"] {
            let entry = result
                .rotated_nodes
                .get(ipns_name)
                .unwrap_or_else(|| panic!("rotated_nodes missing entry for {ipns_name}"));
            assert_eq!(entry.ipns_name, ipns_name);
            assert_eq!(entry.read_key.len(), 32);
            assert_ne!(entry.read_key.as_slice(), [0u8; 32].as_slice());
        }

        let root_entry = &result.rotated_nodes["k51/root"];
        assert_ne!(root_entry.read_key.as_slice(), root_read_key.as_slice());
        let folder_b_entry = &result.rotated_nodes["k51/folder-b"];
        assert_ne!(folder_b_entry.read_key.as_slice(), folder_b_key.as_slice());
        let file_c_entry = &result.rotated_nodes["k51/file-c"];
        assert_ne!(file_c_entry.read_key.as_slice(), file_c_key.as_slice());

        // Root-convenience top-level fields must still equal the grant
        // root's own map entry (existing behavior unchanged).
        assert_eq!(result.read_key.as_slice(), root_entry.read_key.as_slice());
        assert_eq!(result.generation, root_entry.generation);
        assert_eq!(result.sequence_number, root_entry.sequence_number);

        assert_eq!(
            result.rotated_nodes.len(),
            3,
            "expected exactly root+folderB+fileC, got: {:?}",
            result.rotated_nodes.keys().collect::<Vec<_>>()
        );
    }
}
