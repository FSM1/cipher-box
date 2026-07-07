---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 13
subsystem: crypto
tags: [rust, fuse, rotation, grant-scope, revocation, ipns, sc2]

# Dependency graph
requires:
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
    provides: "69-05 has_covering_grant/maybe_rotate_on_scope_exit; 69-07 grant_scope helpers (ancestor_ipns_chain/build_coverage_params/grant_root_for/SentSharesCache); 69-08 rotate_read_from_node; 69-09/69-10 node/v3 model + FUSE flip"
provides:
  - "Grant-scope-gated Unix delete/rmdir/rename (replaces the unconditional revoke_shares_blocking)"
  - "gate_scope_exit + run_scope_exit_gate: the one SC#3/ROT-02 rule, shared by every delete/rename site"
  - "rotate_read_on_scope_exit: the D-07-dual-keyed read-key rotation seam (fail-closed, live-wiring deferred)"
  - "SC#2 removal of the re-encrypt-on-move dead path + a CI grep gate enforcing its absence (non-Windows tree)"
affects: [69-14]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Injectable rotate closure (FnOnce(String) -> Fut) on the gate so spy tests assert exact rotation call counts without a live RotationDeps — mirrors the sdk maybe_rotate_on_scope_exit spy"
    - "Grant-scope gate CONSUMES grant_root_for (which wraps has_covering_grant) — no per-platform predicate copy (research landmine 10)"
    - "Fail-closed rotation seam: a covered scope-exit whose rotation cannot complete returns Err -> EIO, never a silent delete without the revocation cut"

key-files:
  created: []
  modified:
    - crates/fuse/src/write_ops/grant_scope.rs
    - crates/fuse/src/write_ops/implementation/delete.rs
    - crates/fuse/src/write_ops/implementation/rename.rs
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/content_ops.rs
    - crates/fuse/src/operations.rs
    - .github/workflows/ci.yml

key-decisions:
  - "The gate branches on grant_root_for (not maybe_rotate_on_scope_exit directly) so the matched grant-root ipns_name is threaded into the rotate seam; grant_root_for wraps has_covering_grant, so the shared predicate is still the single source of truth (plan permits 'branch on has_covering_grant directly')"
  - "rotate_read_on_scope_exit fails CLOSED (Err -> EIO) rather than completing a shared-scope-exit delete without rotating. No production RotationDeps implementor exists anywhere in the workspace (verified: only the engine's in-crate FakeDeps) — a live rotate_read_from_node call is not constructible in this plan. Preserving fail-closed is strictly no worse than the replaced revoke behavior and secure by default. Private deletes (the common case) are fully correct with zero rotation."
  - "publish_file_metadata is KEPT (grep-confirmed): it is the live per-file publish path for the Windows write handlers (platform/windows). Only the re-encrypt-on-move helper and its retry machinery were dead after the flip and were removed."
  - "D-08 (Q3 Model a) is honored by construction: removing the unconditional revoke means a write-recipient's out-of-scope delete/move now unlinks+bins ONLY, with no cross-principal revoke and no new schema."

requirements-completed: [SC-02, SC-03]
---

# Phase 69 Plan 13: Grant-Scope-Gated Unix Delete/Rename + SC#2 Re-encrypt-on-Move Deletion + D-07 Summary

Unix `unlink`/`rmdir`/cross-folder `rename` now gate on grant coverage: a private mutation is a pure parent relink with ZERO rotation, while a shared-scope exit rotates the read key from the matched grant-root ancestor EXACTLY ONCE — replacing the unconditional `revoke_shares_blocking`. The re-encrypt-on-move dead path is deleted (non-Windows) and CI-gated. D-07 dual-keying (write plane = `uuid_from_ino`/childId, read plane = grant-root `ipns_name`) is threaded distinctly and flagged for security review.

## What was built

### Task 1 — grant-root gate on delete/rename (commit `04ddc148e`)
- Added `gate_scope_exit<F, Fut>` to `grant_scope.rs`: walks `ancestor_ipns_chain`, builds `CoverageParams` via `build_coverage_params`, and branches on `grant_root_for` — `None` → `NoRotation` (private, pure relink); `Some(grant_root)` → invoke the injected `rotate` closure EXACTLY ONCE with the matched grant-root ipns_name. CONSUMES the 69-05/69-07 shared modules; no local predicate.
- Added `rotate_read_on_scope_exit` (the production rotate seam) and `run_scope_exit_gate(fs, ino)` (the single driver shared by every delete/rename site; reads the local sent-shares cache synchronously, `block_on`s the gate on the fuser thread — the same pattern the replaced revoke used).
- `delete.rs`: replaced BOTH unconditional `revoke_shares_blocking` call sites (unlink ~159, rmdir ~329) with `run_scope_exit_gate`. Fail-closed: rotation failure → EIO, delete aborts.
- `rename.rs`: added the gate for cross-folder moves (source-subtree scope-exit), computed on the SOURCE ancestry BEFORE any mutation.
- Spy-based tests (the reachable gate): private delete → 0 rotate; shared-scope exit → exactly 1 rotate at `grant_root_for`; multiple grant roots → still exactly 1; rotate error propagates (fail-closed); D-07 read/write-plane distinctness. Rewrote the 3 delete handler tests for the new semantics (private-succeeds-zero-rotation / shared-fails-closed).

### Task 2 — SC#2 delete re-encrypt-on-move + CI gate (commit `c0dc0f499`)
- Deleted the re-encrypt-on-move helper + its retry machinery (bounded-attempt const, backoff fn, outcome enum, resolve-and-fetch) and 2 backoff unit tests from `metadata.rs`; removed the now-unused `publish_file_metadata` import.
- `rename.rs`: removed the caller + its capture block — a cross-folder move is now a pure `SealedChildRef` relink.
- Removed the `lib.rs` re-export and the Unix `operations.rs` `publish_file_metadata` re-export (no Unix caller remains).
- Updated stale `content_ops.rs` comments.
- Added the SC#2 grep gate to `ci.yml` alongside the existing SC#6 gate, scoped `grep -v platform/windows` (+ a comment-content filter) until 69-14; updated the SC#6 comment (its reencrypt sc6-allow site is gone → two sanctioned sites remain).

## How the grant gate replaced revoke_shares_blocking

The old code called `revoke_shares_blocking` unconditionally on every unlink/rmdir and returned EIO on failure — the ROT-02 over-rotation anti-pattern (research landmine 9). The gate replaces it with a single decision:

- **Private (no covering grant):** `gate_scope_exit` returns `NoRotation` WITHOUT invoking the rotate seam. The existing `update_folder_metadata(parent)` (parent-only republish) is the entire durable effect — ZERO rotation, ZERO extra IPNS publishes. Proven by `gate_scope_exit_private_delete_triggers_zero_rotations` (spy count 0) and the handler test `unlink_private_delete_succeeds_with_zero_rotation` (was EIO, now succeeds).
- **Shared-scope exit (covering grant):** `rotate` is invoked EXACTLY ONCE at `grant_root_for` (closest leaf-first matching ancestor). Proven by `gate_scope_exit_shared_exit_rotates_exactly_once_at_grant_root` (spy count 1, grant_root == "k51folderA") and `..._multiple_grant_roots_rotate_once` (still 1).

## publish_file_metadata: kept, not deleted

Grep-confirmed still-referenced by the live Windows per-file publish path:
`crates/fuse/src/platform/windows/operations.rs:272` (re-export) → `platform/windows/write_ops.rs:979` (call). Only the re-encrypt-on-move helper consumed it on the Unix side, and that consumer is gone. `publish_file_node` (the node/v3 live publish) is untouched.

## D-07 dual-keying + security-review markers

`SECURITY-REVIEW: D-07` markers sit on `run_scope_exit_gate`, `rotate_read_on_scope_exit`, and both delete handler gate sites. The write plane (`crate::fs::uuid_from_ino(ino)` = `WriteChildRef.child_id`) and the read plane (grant-root `ipns_name` = `SealedChildRef.ipns_name`) are threaded as SEPARATE parameters into the rotate seam and never conflated. Test `d07_read_plane_grant_root_ipns_and_write_plane_child_id_are_distinct` asserts they are distinct values from distinct key spaces. **`crates/fuse/src/write_ops/` is flagged for explicit security review** (D-07 HARD CONSTRAINT; T-69-13-01).

## Green-boundary evidence (verified in this worktree)

| Check | Result |
|-------|--------|
| `cargo check --workspace` (default + `--features fuse`) | GREEN, no warnings |
| `cargo test -p cipherbox-fuse` | 96 passed, 0 failed (incl. all new spy/gate/D-07 tests) |
| `cargo test -p cipherbox-sdk` | 132 passed, 0 failed |
| `grep -rn spawn_file_meta_reencrypt crates/fuse/src \| grep -v platform/windows` | EMPTY |
| `revoke_shares_blocking` unconditional call sites in delete.rs | GONE (only comments/def-for-Windows remain) |
| SC#2 CI gate present in ci.yml (non-Windows), alongside SC#6 | YES |

SC#2 CI-gate command:
```
grep -rn 'spawn_file_meta_reencrypt' crates/fuse/src | grep -v 'platform/windows' | grep -vE ':[0-9]+:[[:space:]]*//'
```

## Deviations from Plan

- **[Rule 3 - Blocking] Removed the unused `publish_file_metadata` re-export in `operations.rs`.** After deleting the re-encrypt-on-move helper, the Unix `operations::implementation` re-export of `publish_file_metadata` became unused → an `unused import` warning (would fail a `-D warnings` lane). Removed it from the Unix path only; the Windows module keeps its own re-export. Not in the plan's file list but a direct consequence of the SC#2 deletion.
- **[Rule 3 - Blocking] Reverted out-of-scope rustfmt drift.** The base tree was not rustfmt-clean; formatting the edited files surfaced unrelated reformat in 8 files I never touched (`helpers.rs`, `file_handle.rs`, `platform/*`, `write_ops/mod.rs`). `git checkout --` reverted them so the commits carry only intended changes (repo convention: executor strands out-of-scope fmt drift).
- **Plan's line anchors were approximate.** `publish_file_metadata` was in `content_ops.rs:172`, not `metadata.rs:928`; the reencrypt block spanned `metadata.rs:612-845`. Located precisely by grep before editing.

## Known limitation / residual E2E risk (NOT overclaiming runtime correctness)

**`rotate_read_on_scope_exit` is a fail-closed seam, not a live rotation.** No production `cipherbox_sdk::rotation::engine::RotationDeps` implementor exists anywhere in the workspace — verified via `grep -rn 'impl RotationDeps'` (only the engine's in-crate `FakeDeps` test double). A live `rotate_read_from_node` call is therefore not constructible in this plan; building the deps impl (IPNS resolve-verify + node fetch/unseal + CAS publish + wire→GrantRow decode + job persistence) plus its own test coverage is a standalone live-wiring plan (matches the known ROT-07 live-wiring gap). Consequences:

- **Private deletes/moves: fully correct** (zero rotation, succeed).
- **Shared-scope-exit deletes/moves on Unix: currently EIO (fail-closed)** until the RotationDeps live-wiring lands. This is secure (never a silent revocation bypass) but is a functional gap vs. legacy revoke-based shared deletes. The desktop-e2e cannot run here (root-key recovery unwired / phase-63 stub — accepted deferral), so the spy-based rotation-count tests + the merged sdk rotation-engine unit tests are the reachable gate. Runtime correctness of the eventual live rotation is NOT claimed by this plan.

## Threat model dispositions addressed
- T-69-13-01 (childId/ipnsName conflation): mitigated — D-07 threaded distinctly, security-review markers + write_ops flagged, distinctness test.
- T-69-13-02 (missing rotation on shared exit): gate calls the rotate seam EXACTLY ONCE on covered exits (spy-proven); live rotation deferred (residual above).
- T-69-13-03 (over-rotation on private delete): mitigated — zero-rotation invariant, unconditional revoke REPLACED (spy count 0).
- T-69-13-04 (per-platform predicate drift): mitigated — CONSUMES shared grant_scope + rotation::scope, no local predicate.
- T-69-13-05 (D-08 residual): accept — ADR 0002; out-of-scope delete unlinks+bins only, no cross-principal revoke.

## Self-Check: PASSED
- SUMMARY.md written to the phase dir.
- Commits `04ddc148e`, `c0dc0f499` present in `git log` on branch `worktree-agent-a9110c2b13480cd9b`.
- Committed tree: `cargo check --workspace` green; fuse 96 / sdk 132 tests pass; SC#2 gate empty.
