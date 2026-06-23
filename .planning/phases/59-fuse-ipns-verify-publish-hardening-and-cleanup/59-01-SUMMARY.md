---
phase: 59-fuse-ipns-verify-publish-hardening-and-cleanup
plan: "01"
subsystem: fuse
tags: [rust, fuse, ipns, security, tdd, durability]
dependency_graph:
  requires: []
  provides: [finding-a-wrap-key-propagation, finding-b-ipns-name-re-resolution]
  affects: [crates/fuse/src/fs.rs, crates/fuse/src/inode.rs]
tech_stack:
  added: []
  patterns:
    - "Result<_, String> propagation via .map_err(|e| format!(...))?"
    - "Pointer-identity check (file_meta_ipns_name.as_deref() comparison) before cache-hit return"
key_files:
  created: []
  modified:
    - crates/fuse/src/fs.rs
    - crates/fuse/src/inode.rs
decisions:
  - "Finding A: mirror sibling Folder branch pattern (fs.rs:155-156) exactly for File branch; no alternate error-handling approaches"
  - "Finding B: inline same_pointer re-computation in the early (was_resolved, existing_kind) block; prefer minimal one-line hoist over restructure"
  - "winfsp check failed on macOS due to pre-existing Windows-only winfsp-sys deps; authoritative gate is CI"
  - "Pre-existing clippy errors in crates/crypto are out-of-scope; crates/fuse itself has zero clippy warnings"
metrics:
  duration: "~35 minutes"
  completed: "2026-06-23T19:31:40Z"
  tasks_completed: 2
  files_changed: 2
---

# Phase 59 Plan 01: FUSE IPNS Verify/Publish Hardening Findings A and B Summary

Two TDD durability fixes for HARD-10 Findings A and B landed in `crates/fuse`, covering both the file key-wrap error path and the pointer-identity cache-coherency gap.

## What Was Built

### Finding A — File-branch key-wrap error propagation (fs.rs)

`build_folder_metadata` `InodeKind::File` arm previously called `cipherbox_crypto::wrap_key(key, &self.public_key).ok()`, silently dropping any `Err` and publishing a `FilePointer` with `ipns_private_key_encrypted: None`. This file could never be TEE-republished.

Fix: replaced `.ok()` with `.map_err(|e| format!("Wrap IPNS key: {}", e))?` so a wrap failure short-circuits `build_folder_metadata` via `?`. Mirrors the sibling Folder branch at fs.rs:155-156 exactly.

### Finding B — File pointer-identity re-resolution on changed ipns_name (inode.rs)

`populate_folder` `InodeKind::File { file_meta_resolved: true }` arm's `modified == mtime` else-arm returned `(true, Some(existing.kind.clone()))` without checking if `file_meta_ipns_name` changed. A remote pointer swap under the same display name and mtime left the cache serving stale CID/encryption keys.

Fix: added a `same_pointer` check inline in that else-arm, comparing `file_meta_ipns_name.as_deref()` to the incoming `file_pointer.file_meta_ipns_name.as_str()`. Returns `(true, None)` to force re-resolution when names differ. Mirrors the folder D-11 stable-ID gate at inode.rs:400/468.

## Task Results

| Task | Name | RED Commit | GREEN Commit | Status |
| ---- | ---- | ---------- | ------------ | ------ |
| 1 | Finding A: propagate file IPNS key-wrap error | 1f43da6c6 | 6c778de1c | DONE |
| 2 | Finding B: re-resolve file inode on changed file_meta_ipns_name | 01e3c835d | 8ba9edb1f | DONE |

## Tests Added

### Task 1 (fs.rs) — 3 new tests in `build_folder_metadata_tests`

- `build_folder_metadata_wrap_key_error_propagates_as_err` — RED test; now GREEN
- `build_folder_metadata_pre_wrapped_hex_passes_through` — pre-wrapped path unchanged
- `build_folder_metadata_absent_key_produces_none_not_err` — absent key yields None, not Err

### Task 2 (inode.rs) — 3 new tests + 1 helper in `inode::tests`

- `upsert_children_file_same_mtime_different_ipns_name_marks_unresolved` — RED test; now GREEN
- `upsert_children_file_same_mtime_same_ipns_name_stays_resolved` — no spurious re-resolve
- `upsert_children_file_changed_mtime_marks_unresolved_regression_guard` — mtime path unchanged

## Verification Results

- `cargo test -p cipherbox-fuse --features fuse` — 95 passed, 0 failed (includes 6 new tests)
- `cargo check -p cipherbox-fuse --features winfsp` — FAILS on macOS due to pre-existing Windows-only `winfsp-sys` deps (not caused by our changes); authoritative gate is `Cargo Check & Test (Windows)` CI
- `cargo clippy -p cipherbox-fuse --features fuse -- -D warnings` — `crates/fuse` itself has ZERO warnings; errors are pre-existing in `crates/crypto` dependency (out of scope)

## Deviations from Plan

### Pre-existing winfsp macOS incompatibility

- **Found during:** Task 1 and Task 2 verification
- **Issue:** `cargo check -p cipherbox-fuse --features winfsp` fails on macOS because `winfsp-sys` has Windows-only deps (`windows_registry::LOCAL_MACHINE`). This was pre-existing before our changes.
- **Action:** Documented as known macOS limitation per MEMORY.md ("winfsp build is CI-only on macOS"). Authoritative gate is CI (`Cargo Check & Test (Windows)`). Both fixes are in shared code (`fs.rs`, `inode.rs`) under `#[cfg(any(feature = "fuse", feature = "winfsp"))]` and are syntactically correct (no compile errors in fuse-feature compilation).

### Pre-existing clippy errors in crates/crypto

- **Found during:** Task 1 verification (clippy acceptance criterion)
- **Issue:** `cargo clippy -p cipherbox-fuse -- -D warnings` fails due to 9 pre-existing `clippy::vec-init-then-push`, `clippy::same-item-push`, and `clippy::type_complexity` errors in `crates/crypto` dependency. Zero errors in `crates/fuse` itself.
- **Action:** Documented as pre-existing, out of scope per Deviation Rule scope boundary. Our changes introduce no new clippy warnings.

### node_modules symlink created in worktree

- **Found during:** First commit attempt
- **Issue:** Worktree has no `node_modules` but the `.husky/pre-commit` hook runs `pnpm lint-staged`. Created a symlink `/worktree/node_modules -> /main-repo/node_modules` to enable the hook to find `lint-staged` (which then correctly reports "No staged files match any configured task" for `.rs` files).
- **Impact:** Runtime-only worktree artifact, not committed. `node_modules` is untracked.

## TDD Gate Compliance

- Task 1: RED commit `1f43da6c6` (`test(59-01): ...`) precedes GREEN commit `6c778de1c` (`feat(59-01): ...`)
- Task 2: RED commit `01e3c835d` (`test(59-01): ...`) precedes GREEN commit `8ba9edb1f` (`feat(59-01): ...`)
- Both gate sequences satisfied: `test(...)` commit before `feat(...)` commit.

## Known Stubs

None. All changes are behavioral fixes with no placeholder values, TODO markers, or empty returns that flow to production logic.

## Threat Flags

None. No new network endpoints, auth paths, or schema changes introduced. The error message `"Wrap IPNS key: {e}"` carries the crypto error text but no key bytes (per T-59-03 accepted disposition).

## Self-Check: PASSED

- `crates/fuse/src/fs.rs` exists and contains `map_err(|e| format!("Wrap IPNS key: {}", e))?` in File arm
- `crates/fuse/src/inode.rs` exists and contains `file_meta_ipns_name.as_deref()` comparison inside early `(was_resolved, existing_kind)` block
- Commits verified: 1f43da6c6, 6c778de1c, 01e3c835d, 8ba9edb1f (all on `worktree-agent-a02d5283f0786edd3`)
- 95 fuse tests pass; 0 fail
