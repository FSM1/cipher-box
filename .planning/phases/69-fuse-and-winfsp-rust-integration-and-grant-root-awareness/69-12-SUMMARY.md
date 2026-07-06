---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 12
subsystem: crypto
tags: [rust, rotation, revocation, ecies, tdd]
status: complete

# Dependency graph
requires:
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
    provides: "69-11's engine.rs (rotate_one / rotate_read_from_node BFS walk, RotationJobRecord, verify_subtree_clean)"
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
    provides: "69-03's shares query contract (informed GrantRow's shape; production wiring deferred)"
provides:
  - "mint_file_key_on_rotate + content_rekey_pending marker: CRIT-1 lazy content-key rotation"
  - "re_mint_grants_rooted_at + RotationDeps grant seams: HIGH-3 inner-grant re-mint / revoked-cut"
  - "merge_children / merge_concurrent_children + PublishAttempt: HIGH-4 CAS-409 re-fetch-merge"
affects: [69-14]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "PublishAttempt::{Published,Conflict} as an Ok-variant CAS-409 signal (not Err) — a conflict is an expected, recoverable outcome the caller merges and retries, not a transport/logic failure"
    - "Optional RotationDeps seams with a default no-op body (query_grants_rooted_at/update_grant/delete_grant) reproduce the TS reference's 'D-01 conditional invocation via an optional callbacks param' using Rust default trait methods instead of an Option<Callbacks> struct"
    - "seal_and_publish's CAS-409 retry loop treats the node's own pre-rotation children as BOTH the merge's base and local arguments — rotate_one never adds/removes children on its own re-seal, so base==local always at this call site"
    - "CommittedRotation.children now carries the FINAL (possibly merged) children list, not a pre-rotation snapshot, so a concurrently-added child is both preserved in the published body and enqueued for its own rotation by the BFS walk — a stronger fix than the TS reference's own mergeConcurrentChildren, which leaves the merged-in child's SealedChildRef stale under the parent's OLD key until a later rotation touches it"

key-files:
  created: []
  modified:
    - crates/sdk/src/rotation/engine.rs
    - crates/sdk/src/rotation/mod.rs

key-decisions:
  - "content_rekey_pending is an in-memory advisory field on CommittedRotation, not a node/v3 wire field — the frozen NodeContent schema (crates/core/src/node/types.rs) is out of this plan's files_modified scope, and the TS reference itself deferred the actual wire marker past Phase 64 (its own doc comment: 'the node/v3 schema is frozen this phase'). The fresh fileKey riding inside the SAME re-seal IS the CRIT-1 deliverable (ADR 0002); the marker is the host's cue to apply the lazy re-encrypt-on-next-write, wiring left to a later plan/host"
  - "RotationDeps::publish_with_cas signature changed from Result<PublishOutcome, RotationError> to Result<PublishAttempt, RotationError> — a CAS-409 is now an Ok(Conflict) rather than an Err, since HIGH-4 requires the caller to distinguish 'recoverable conflict, merge and retry' from 'genuine transport/logic failure'. Only test_support::FakeDeps implements this trait today (no crates/fuse production caller yet), so this is a zero-blast-radius contract change"
  - "HIGH-4's CAS-409 retry-merge is scoped to rotate_one's own re-seal only (per the plan's explicit acceptance criteria wording), NOT to republish_parent's separate batched-republish-after-all-children-finish flow; a conflict there still fails closed rather than silently dropping data, documented inline as an intentional non-goal of this plan"
  - "GrantRow.recipient_public_key is raw bytes, not the crates/api-client wire hex string — engine.rs stays transport-decoupled (D-02/D-04) and never imports cipherbox-api-client directly; hex-decoding SentShareResponse into GrantRow is the production RotationDeps implementor's job, deferred to a later wiring plan"
  - "Both tasks were implemented as a single commit rather than two: CRIT-1's file_key_prime plumbing and HIGH-4's old_read_key/merge plumbing both required the same seal_and_publish signature change, so an intermediate Task-1-only commit would not have been meaningfully separable without redundant rework. Both tasks' acceptance criteria are independently verified in the test suite regardless of commit granularity"

requirements-completed: [SC-03]

coverage:
  - id: D1
    description: "CRIT-1: rotating a File node mints a fresh fileKey and sets content_rekey_pending; old fileKey cannot decrypt content encrypted under the new key; no eager re-encrypt (exactly one publish call)"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/sdk/src/rotation/engine.rs#rotate_one::crit1_file_rotation_mints_fresh_file_key_and_sets_pending_marker"
        status: pass
      - kind: unit
        ref: "crates/sdk/src/rotation/engine.rs#rotate_one::crit1_folder_rotation_never_sets_content_rekey_pending"
        status: pass
    human_judgment: false
  - id: D2
    description: "HIGH-3: an inner grant rooted at a subtree node (not the scope root) has its readDescriptorRef re-minted with the child's ACTUAL new readKey for a non-revoked recipient; a revoked recipient's row is hard-deleted, never re-minted"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/sdk/src/rotation/engine.rs#rotate_read_from_node::high3_inner_grant_at_a_child_is_re_minted_and_revoked_recipient_is_cut"
        status: pass
    human_judgment: false
  - id: D3
    description: "HIGH-4: a CAS-409 during rotate_one's own re-seal re-fetches the current remote, re-decodes it under the old readKey, and three-way merges children before retrying — a child added concurrently mid-rotation survives into the completed parent's published body"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/sdk/src/rotation/engine.rs#rotate_read_from_node::high4_concurrent_add_mid_rotation_is_merged_not_dropped"
        status: pass
    human_judgment: false

metrics:
  duration: "~55 minutes"
  completed: "2026-07-06"
---

# Phase 69 Plan 12: Rotation Engine Revocation Closures (CRIT-1 / HIGH-3 / HIGH-4) Summary

Closed the three cryptographic revocation gaps left open by 69-08/69-11 in `crates/sdk/src/rotation/engine.rs`: lazy file-key rotation on File nodes (CRIT-1), inner-grant re-mint with revoked-recipient cutoff rooted at every rotated node (HIGH-3), and CAS-409 concurrent-child re-fetch-and-merge so a concurrent add is never blindly dropped (HIGH-4).

## What was built

**CRIT-1 (content-key rotation).** `rotate_one`'s File-node path now mints a fresh 32-byte `fileKey` via `mint_file_key_on_rotate` and threads it into the SAME re-seal the rotation already performs (`build_resealed_node` swaps `NodeContent.file_key`, zeroing the old key first). `CommittedRotation.content_rekey_pending` is `true` exactly when this happened. No separate publish, no eager re-encryption of already-published content (ADR 0002 lazy stance) — a test builds ciphertext under the new key and confirms the old key fails to decrypt it, while the new key round-trips.

**HIGH-3 (inner-grant re-mint).** `RotationDeps` gained three new seams — `query_grants_rooted_at`, `update_grant`, `delete_grant` — each with a default no-op body so a node with nothing shared out of it never touches the seam (mirrors the TS reference's optional `GrantRemintCallbacks`, but expressed as Rust default trait methods rather than an `Option<Callbacks>` param). `re_mint_grants_rooted_at` is called unconditionally after every per-node commit (root and every BFS child) — BEFORE `job_record.completed_node_ids.insert` so a re-mint failure doesn't silently skip the node on resume (D-07 parity). Non-revoked recipients get their `readDescriptorRef` ECIES-re-wrapped via `cipherbox_crypto::wrap_key`; revoked recipients' rows are deleted, never re-minted.

**HIGH-4 (CAS-409 concurrent-add merge).** `RotationDeps::publish_with_cas` now returns `PublishAttempt` (`Published` or `Conflict`) instead of erroring on a CAS-409 — a conflict is a recoverable, expected outcome, not a failure. `seal_and_publish` retries in a bounded loop (`MAX_CAS_MERGE_ATTEMPTS = 3`): on `Conflict`, it calls `merge_concurrent_children` to re-decode the winning remote envelope under the OLD (pre-rotation) read key and three-way-merge its children against the node's own pre-rotation snapshot via `merge_children` (union by `ipns_name`, remote wins, intentional deletes honored — a Rust twin of `packages/sdk-core/src/folder/merge.ts`). The MERGED children list — not the pre-merge snapshot — becomes `CommittedRotation.children`, so a concurrently-added child is both preserved in the published body AND enqueued into the BFS walk for its own rotation and re-seal-under-the-new-parent-key, closing a staleness gap the TS reference itself still has.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - blocking] Extended `crates/sdk/src/rotation/mod.rs`'s barrel export**
- **Found during:** Task 2 (adding `GrantRow`/`PublishAttempt` as new public types)
- **Issue:** The module's `pub use engine::{...}` barrel is the crate's public API surface for this submodule; leaving new public types unexported would silently break the barrel's own completeness contract even though nothing outside `engine.rs` currently consumes `RotationDeps`.
- **Fix:** Added `GrantRow` and `PublishAttempt` to the `pub use` list alongside the existing names.
- **Files modified:** `crates/sdk/src/rotation/mod.rs`
- **Commit:** be4a0cb81

No other deviations — the plan's `files_modified` scope (engine.rs) was otherwise honored exactly; the mod.rs touch above is a one-line barrel-completeness fix, not new functionality.

### Design choices not in the plan's literal wording (documented, not deviations)

- The plan's `key_links` mentions HIGH-3 grant re-mint queries "via crates/api-client (list_sent_shares / the shares query from 69-03)". `engine.rs` does NOT import `cipherbox-api-client` directly — that would violate the file's own D-02/D-04 host-agnostic transport-decoupling contract (the same reason `resolve`/`fetch_node`/`publish_with_cas` are injected seams, not direct IPFS/IPNS calls). `GrantRow` is the seam's data shape; wiring a real `crates/api-client`-backed `RotationDeps` implementation (hex-decoding `SentShareResponse.recipient_public_key`, calling a not-yet-existing per-share update endpoint) is production wiring for a later plan, consistent with how `resolve`/`fetch_node`/`publish_with_cas` also have no production implementor yet in this crate.

## Self-Check: PASSED

- `crates/sdk/src/rotation/engine.rs` — FOUND
- `crates/sdk/src/rotation/mod.rs` — FOUND
- Commit `be4a0cb81` — FOUND (`git log --oneline` confirms)
- `cargo test -p cipherbox-sdk rotation::engine` — 17/17 pass (includes 3 new CRIT-1 tests, 1 new HIGH-3 test, 1 new HIGH-4 test)
- `cargo test -p cipherbox-sdk` (full crate) — 114/114 pass, zero regressions
- `cargo check --workspace` — green
- `cargo clippy -p cipherbox-sdk --tests` — zero warnings attributable to this plan's changes (pre-existing warnings are in `cipherbox-crypto`/`cipherbox-core`/`cipherbox-api-client`, untouched by this plan)
