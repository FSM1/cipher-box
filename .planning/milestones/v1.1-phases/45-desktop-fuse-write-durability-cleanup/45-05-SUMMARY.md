---
phase: 45-desktop-fuse-write-durability-cleanup
plan: "05"
subsystem: crates/fuse
tags: [refactor, replay, crash-recovery, memoize, publish, journal, fuse, winfsp]
dependency_graph:
  requires: ["45-04"]
  provides:
    - publish_file_metadata-called-from-replay
    - resolve_folder_key_cached
    - folder_key_cache-per-replay-call
    - T-45-07-extended-with-cached-wrapper
  affects:
    - crates/fuse/src/lib.rs
tech_stack:
  added: []
  patterns:
    - conditional-use-import-by-feature-flag
    - memoize-with-per-call-local-hashmap
    - delegate-to-shared-publish-helper
key_files:
  created: []
  modified:
    - crates/fuse/src/lib.rs
key-decisions:
  - "Conditional use imports route replay to fuse -> operations::implementation and winfsp (without fuse) -> platform::windows::operations::implementation; avoids moving or duplicating publish_file_metadata"
  - "is_first_publish flag computed locally via resolve_ipns_for_replay (from Plan 04) before calling publish_file_metadata; the shared fn does not determine first-publish — it receives it as a bool"
  - "folder_key_cache seeded with root key in replay_for_vault so root-shortcut lookups (folder_ipns_name == root_ipns_name) never enter resolve_folder_key at all"
  - "T-45-07 extended to call resolve_folder_key_cached (not resolve_folder_key directly) and assert single cache entry after two lookups of same name; Plan-01 placeholder comment removed"
requirements-completed: ["#15", "#20"]
duration: 12min
completed: 2026-06-15
---

# Phase 45 Plan 05: publish_file_metadata Reuse and resolve_folder_key Memoization Summary

**Replay path refactored: 80-line inline publish block replaced by shared publish_file_metadata call (#20) and N-BFS per entry cut to one-BFS-per-distinct-parent via a per-call memoizing cache seeded with root key (#15)**

## Performance

- **Duration:** 12 min
- **Started:** 2026-06-15T01:00:00Z
- **Completed:** 2026-06-15T01:12:00Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- `replay_upload_entry` now calls the shared `publish_file_metadata` after ECIES-unwrap and `is_first_publish` determination; the 80-line inline encrypt/upload/IPNS-record/TEE-wrap/publish block is gone
- `replay_for_vault` creates a `folder_key_cache: HashMap<String, Vec<u8>>` seeded with the root key and threads it as `&mut` into `replay_mkdir_entry` and `replay_upload_entry`; `resolve_folder_key_cached` wrapper serves cache hits without BFS
- T-45-07 (`resolve_folder_key_cache_resolves_shared_parent_once`) extended to call `resolve_folder_key_cached` and assert exact cache entry count — confirms the memoization invariant

## Task Commits

1. **Task 1: Reuse publish_file_metadata in replay_upload_entry (#20) AND Task 2: Memoize resolve_folder_key (#15)** - `efb42a92e` (refactor)

## Files Created/Modified

- `crates/fuse/src/lib.rs` — conditional use imports for `publish_file_metadata`; `folder_key_cache` in `replay_for_vault`; new `resolve_folder_key_cached` wrapper; updated signatures for `replay_mkdir_entry` and `replay_upload_entry`; inline publish block removed from `replay_upload_entry`; T-45-07 extended

## Decisions Made

- Conditional `use` imports (`#[cfg(feature = "fuse")]` and `#[cfg(all(feature = "winfsp", not(feature = "fuse")))]`) route replay to the correct platform's `publish_file_metadata` without moving or duplicating the function body. This is the minimal change that compiles both feature builds.
- `is_first_publish` is determined locally (via `resolve_ipns_for_replay` from Plan 04) before calling `publish_file_metadata` because the shared function does not classify the resolve outcome — it receives `is_first_publish: bool` as a parameter.
- The cache is seeded with the root key in `replay_for_vault` so that root-folder lookups (the most common case) hit the cache even on the first call, bypassing `resolve_folder_key` entirely.
- Tasks 1 and 2 are committed together (single atomic commit) because both refactor the same replay functions and their changes are tightly coupled at the `replay_upload_entry` and `replay_mkdir_entry` signatures.

## Deviations from Plan

None — plan executed exactly as written. Both tasks completed in a single commit without deviation.

## Known Stubs

None. No production stubs introduced.

## Threat Flags

None. No new network endpoints, auth paths, or schema changes.

- T-45-05-INT (Integrity): ECIES-unwrap and `is_first_publish` stay local; the shared `publish_file_metadata` handles remaining steps identically to the inline code it replaces. Behavior preserved: 44 tests green.
- T-45-05-DUR (Durability): `publish_file_metadata` performs TEE enrollment when `is_first_publish=true`; the `IpnsResolveOutcome::NotFound` path (from Plan 04) correctly sets `is_first_publish=true` so enrollment is not skipped.
- T-45-05-INFO (Information disclosure): `folder_key_cache` is function-local in `replay_for_vault`, dropped on return, never stored on `CipherBoxFS` or any other struct.

## Self-Check: PASSED

- `publish_file_metadata` called in `replay_upload_entry`: FOUND (grep -n line 1801)
- No `IpnsPublishRequest` in `replay_upload_entry` body: CONFIRMED (all remaining uses are in other functions)
- `async fn resolve_folder_key_cached` in lib.rs: FOUND (line 1430)
- `folder_key_cache` declared inside `replay_for_vault`: FOUND (line 1203)
- `folder_key_cache` NOT in any struct definition: CONFIRMED
- `replay_mkdir_entry` calls `resolve_folder_key_cached`: FOUND (line 1612)
- `replay_upload_entry` calls `resolve_folder_key_cached`: FOUND (line 1723)
- `MAX_RESOLVE_NODES` still in `resolve_folder_key`: FOUND (line 1362)
- `cargo test -p cipherbox-fuse --no-default-features --features fuse`: 44 passed, 0 failed
- `cargo check --workspace`: Finished (exit 0)
- `cargo fmt --check -p cipherbox-fuse`: clean
- Commit efb42a92e: FOUND in git log
