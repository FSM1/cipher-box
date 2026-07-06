//! Resumable read-key rotation engine — Rust twin of
//! `packages/sdk-core/src/rotation/engine.ts` (`rotateOne` / `rotateReadFromNode`).
//!
//! Implements the WALK MECHANICS half of the ROT-01 primitive: a per-node
//! CAS-commit BFS walk that rotates the read key of every node in a
//! scope-exit subtree, scope-root first. Published IPNS records are the
//! source of truth; the [`RotationJobRecord`] is advisory (D-10).
//!
//! Deliberately OUT OF SCOPE for this plan (lands in later Phase-69 plans on
//! this same file): crash-safety dirty-frontier resume (`verifySubtreeClean`
//! twin, 69-11), the ROT-06 no-double-bump convergence guard beyond a basic
//! pending-count decrement, and the revocation-guarantee closures CRIT-1 /
//! HIGH-3 / HIGH-4 (inner-grant re-mint, CAS-409 concurrent-child merge,
//! write-plane rotation) — 69-12.
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

use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::{Zeroize, Zeroizing};

use cipherbox_core::node::seal::{seal_node, unseal_node};
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
/// seam for durable resume acceleration (69-11 extends this with real
/// crash-safety semantics); a fresh walk never depends on it being read back.
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
    /// resume acceleration but NOT populated by the fresh-walk happy path in
    /// this plan (the TS reference does not write to it either — only a
    /// dirty-resume path, 69-11's crash-safety extension, seeds an
    /// equivalent local frontier). Reserved for that extension.
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
    /// Full dirty-frontier resume reconstruction (ROT-06 convergence guard)
    /// is 69-11's crash-safety extension — this plan only detects and
    /// reports the skip.
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
    use std::collections::HashMap;
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
