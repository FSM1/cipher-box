---
phase: 45-desktop-fuse-write-durability-cleanup
plan: "01"
subsystem: crates/sdk, crates/fuse
tags: [test, characterization, write-durability, crash-recovery, journal, replay]
dependency_graph:
  requires: []
  provides: [T-45-01, T-45-02, T-45-03, T-45-06, T-45-07, T-45-08]
  affects: [crates/sdk/src/queue.rs, crates/fuse/src/lib.rs]
tech_stack:
  added: []
  patterns: [sync-test-in-cfg-test, tokio-test-async, make-temp-queue-pid-counter]
key_files:
  created: []
  modified:
    - crates/sdk/src/queue.rs
    - crates/fuse/src/lib.rs
decisions:
  - "make_temp_queue uses pid+counter (not tid+counter) to prevent inter-run temp dir collisions"
  - "T-45-07 uses root-shortcut path (folder_ipns_name==root_ipns_name) for deterministic result without network"
  - "T-45-08 placed in crates/fuse/src/lib.rs (not apps/desktop) to keep characterization tests co-located with the function under test"
metrics:
  duration: 8min
  completed: 2026-06-15
  tasks: 2
  files: 2
---

# Phase 45 Plan 01: Write-Durability + Crash-Recovery Test Safety Net Summary

Six characterization tests (T-45-01/02/03/06/07/08) assert current Phase-43/44 journal and
replay behavior so downstream Phase-45 refactor plans have a green oracle for "no behavior change."
No production code was changed.

## Tasks Completed

### Task 1: Crash/partial/retry-exhaustion durability tests (T-45-01, T-45-02, T-45-03)

Added to `crates/sdk/src/queue.rs` `#[cfg(test)] mod tests`:

- `crash_mid_write_entry_survives_reload` (T-45-01): puts entry, drops WriteQueue WITHOUT
  remove(), constructs a fresh WriteQueue on the same dir, asserts load_all_for_vault returns
  1 Pending entry. Proves fsync-before-ack crash-recovery guarantee.
- `partial_journal_write_is_skipped_not_panicked` (T-45-02): writes first-half of a valid
  entry's JSON bytes to `<id>.json` directly, puts one good entry, asserts only the good entry
  is returned and no panic. Pins V5/T-43-03 skip-with-warn behavior.
- `retry_exhaustion_keeps_failed_entry_on_disk` (T-45-03): calls record_failure 4 times on a
  max_retries=3 queue, reloading current entry each call; asserts final status is Failed and
  load_all_for_vault still returns 1 entry (D-09 never-silently-drop invariant).

Commit: `32cfed605`

### Task 2: Replay-skip-failed / folder-key-cache / merge tests (T-45-06, T-45-07, T-45-08)

Added to `crates/fuse/src/lib.rs` `#[cfg(test)] mod tests`:

- `replay_for_vault_does_not_touch_failed_entries` (T-45-06): puts a pre-Failed entry, runs
  replay_for_vault against non-routable API, asserts entry count remains 1 after replay. Pins
  the skip-Failed path in replay_for_vault (lib.rs:902).
- `resolve_folder_key_cache_resolves_shared_parent_once` (T-45-07): calls private
  `super::resolve_folder_key` twice using the root-shortcut path (folder==root, zero network),
  asserts both return identical bytes equal to root_folder_key. Marked with `// #15 will extend`
  comment for the cache-validation extension.
- `merge_folder_children_unions_new_and_existing` (T-45-08): builds local=[existing(v_local),
  new] and remote=[existing(v_remote)] with same file_meta_ipns_name, asserts merged.len()==2
  and existing carries the local name. Characterizes the merge semantics fetch_merge_publish_parent
  relies on.

Commit: `f6e56624c`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed make_temp_queue() temp-dir collision under --test-threads=4**

- **Found during:** Task 1 full suite run (46 tests, --test-threads=4)
- **Issue:** `make_temp_queue()` used `format!("cipherbox-journal-test-{}-{}", seq, tid_num)`
  where `seq` resets to 0 per binary invocation and `tid_num` extracts digits from
  `ThreadId(N)`. On macOS, thread IDs are small sequential numbers (1-4 for 4 threads).
  Across test runs, counter+threadid combinations repeat, and `create_dir_all` silently
  succeeds on already-existing dirs — leaving stale `.json` files from prior runs that
  contaminate `load_all_for_vault` assertions. `park_on_max_retries` (vault "k51vault")
  saw 2 files (its new `park1.json` plus a stale `retry1.json`) and failed with `left:2 right:1`.
- **Fix:** Changed to `format!("cipherbox-journal-test-{}-{}", pid, seq)` — process ID is
  unique per invocation, eliminating cross-run collisions.
- **Files modified:** `crates/sdk/src/queue.rs`
- **Commit:** `32cfed605`

**2. [Rule 1 - Format] Applied cargo fmt to queue.rs (Task 1 commit pre-fmt)**

- **Found during:** Task 2 (cargo fmt --check revealed Task 1 commit was not fmt-clean)
- **Fix:** Applied `cargo fmt -p cipherbox-sdk` and included the result in Task 2 commit
  alongside the lib.rs changes.
- **Files modified:** `crates/sdk/src/queue.rs` (import ordering, line-wrap style)
- **Commit:** `f6e56624c`

## Known Stubs

None. This plan adds test-only code; no production stubs introduced.

## Threat Flags

None. This plan adds only `#[cfg(test)]` code; zero new production surface area.

## Self-Check: PASSED

- `fn crash_mid_write_entry_survives_reload` in crates/sdk/src/queue.rs: FOUND
- `fn partial_journal_write_is_skipped_not_panicked` in crates/sdk/src/queue.rs: FOUND
- `fn retry_exhaustion_keeps_failed_entry_on_disk` in crates/sdk/src/queue.rs: FOUND
- `fn replay_for_vault_does_not_touch_failed_entries` in crates/fuse/src/lib.rs: FOUND
- `fn resolve_folder_key_cache_resolves_shared_parent_once` in crates/fuse/src/lib.rs: FOUND
- `fn merge_folder_children_unions_new_and_existing` in crates/fuse/src/lib.rs: FOUND
- Commit 32cfed605: FOUND
- Commit f6e56624c: FOUND
- `cargo test -p cipherbox-sdk -- --test-threads=4`: 46 passed, 0 failed
- `cargo test -p cipherbox-fuse --no-default-features --features fuse`: 43 passed, 0 failed
