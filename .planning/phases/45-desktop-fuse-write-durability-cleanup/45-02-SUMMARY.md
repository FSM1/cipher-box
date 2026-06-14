---
phase: 45-desktop-fuse-write-durability-cleanup
plan: "02"
subsystem: desktop-fuse
tags: [refactor, rust, desktop, fuse, journal, hygiene]
dependency_graph:
  requires: []
  provides: [default_journal_dir, JOURNAL_MAX_RETRIES]
  affects:
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/commands/sync.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
tech_stack:
  added: []
  patterns: [shared-constant, shared-helper-fn, path-construction, unit-test-pin]
key_files:
  created: []
  modified:
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/commands/sync.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
decisions:
  - "default_journal_dir() placed in fuse/mod.rs (not a new journal.rs) to keep it co-located with the FUSE mount path that owns the canonical definition"
  - "JOURNAL_MAX_RETRIES defined as pub const u32 = 5 in the same file for discoverability"
  - "Windows winfsp mount path (fuse/windows/mod.rs) updated as a Rule-2 extension — it was the third undiscovered duplicate not explicitly listed in the plan but required for the acceptance criterion (no literal 5 remains)"
  - "create_dir_all and 0o700 permissions kept at each call site — helper returns PathBuf only (pure path construction, no side effects)"
metrics:
  duration: "~8min"
  completed: "2026-06-15"
  tasks_completed: 1
  files_modified: 3
---

# Phase 45 Plan 02: Extract Journal Dir Helper Summary

Extract `default_journal_dir()` + `JOURNAL_MAX_RETRIES` into one shared helper so the FUSE mount path and sync daemon share a single source of truth for journal configuration.

## What Was Built

Added `pub fn default_journal_dir() -> std::path::PathBuf` and `pub const JOURNAL_MAX_RETRIES: u32 = 5` to `apps/desktop/src-tauri/src/fuse/mod.rs`. Routed all three `WriteQueue::new` call sites (fuse mount, winfsp mount, sync daemon) through these shared symbols. Added unit test `default_journal_dir_ends_with_cipherbox_cb_journal` that pins the `cipherbox/cb-journal` path tail without asserting the environment-dependent prefix.

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | Add default_journal_dir + JOURNAL_MAX_RETRIES and route all call sites | 4171ed5b1 | fuse/mod.rs, commands/sync.rs, fuse/windows/mod.rs |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Coverage] Fixed third duplicate call site in fuse/windows/mod.rs**

- **Found during:** Task 1 — acceptance criteria check (`grep -rn 'WriteQueue::new' ... | grep -c ', 5)'` returned 1 instead of 0 after patching the two planned sites)
- **Issue:** `apps/desktop/src-tauri/src/fuse/windows/mod.rs` contained a third inline `dirs::data_local_dir()...join("cb-journal")` chain with the literal `5`, not listed in the plan but identical to the pattern being extracted
- **Fix:** Updated windows/mod.rs to call `crate::fuse::default_journal_dir()` and `crate::fuse::JOURNAL_MAX_RETRIES`, completing the elimination of all duplicate path chains
- **Files modified:** `apps/desktop/src-tauri/src/fuse/windows/mod.rs`
- **Commit:** 4171ed5b1 (combined with task commit)

## Verification

- `cargo build --no-default-features --features fuse`: PASS
- `cargo test --no-default-features --features fuse`: 23/23 PASS
- New test `default_journal_dir_ends_with_cipherbox_cb_journal`: PASS
- `grep -rn 'WriteQueue::new' apps/desktop/src-tauri/src | grep -c ', 5)'`: 0 (no literal 5 remains)
- `grep -c 'pub fn default_journal_dir' fuse/mod.rs`: 1
- `grep -c 'pub const JOURNAL_MAX_RETRIES' fuse/mod.rs`: 1
- `grep -c 'default_journal_dir' commands/sync.rs`: 1
- `grep -c 'JOURNAL_MAX_RETRIES' commands/sync.rs`: 1
- No inline `cb-journal` chain in sync.rs outside comments: 0

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, or file access patterns introduced. The refactor narrows surface by removing path drift class.

## Self-Check: PASSED

- [x] `apps/desktop/src-tauri/src/fuse/mod.rs` contains `pub fn default_journal_dir` (grep confirmed)
- [x] `apps/desktop/src-tauri/src/fuse/mod.rs` contains `pub const JOURNAL_MAX_RETRIES` (grep confirmed)
- [x] `apps/desktop/src-tauri/src/commands/sync.rs` references both symbols (grep confirmed)
- [x] `apps/desktop/src-tauri/src/fuse/windows/mod.rs` references both symbols (updated)
- [x] Commit 4171ed5b1 exists in git log
- [x] All 23 tests pass; new path-tail test passes
