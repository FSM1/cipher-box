---
phase: "55"
plan: "03"
subsystem: "desktop/fuse, crates/fuse"
tags: ["refactor", "dedup", "cross-platform", "rust", "fuse", "winfsp"]
dependency_graph:
  requires: ["55-01", "55-02"]
  provides: ["shared-content-ops", "shared-poll", "shared-prepopulate"]
  affects: ["crates/fuse", "apps/desktop/src-tauri/src/fuse"]
tech_stack:
  added: []
  patterns:
    - "cfg-gated shared module for cross-platform Rust helpers"
    - "Re-export path normalization for cipherbox_core"
    - "Scoped FilePointer resolution via get_unresolved_file_pointers_for_parent"
key_files:
  created:
    - "crates/fuse/src/content_ops.rs"
    - "crates/fuse/src/poll.rs"
    - "crates/fuse/src/platform/windows/content_fetch.rs"
    - "apps/desktop/src-tauri/src/fuse/prepopulate.rs"
  modified:
    - "crates/fuse/src/lib.rs"
    - "crates/fuse/src/operations.rs"
    - "crates/fuse/src/read_ops.rs"
    - "crates/fuse/src/platform/windows/operations.rs"
    - "crates/fuse/src/platform/windows/read_ops.rs"
    - "crates/fuse/src/platform/windows/mod.rs"
    - "apps/desktop/src-tauri/src/fuse/mod.rs"
    - "apps/desktop/src-tauri/src/fuse/windows/mod.rs"
decisions:
  - "A2: Async helpers only in content_ops.rs — sync wrappers stay per-platform (3s vs 10s timeout divergence is intentional)"
  - "A3: Normalized to re-export paths + match arms + get_unresolved_file_pointers_for_parent throughout"
  - "poll_filepointer_resolution gated fuse-only (takes &mut CipherBoxFS, incompatible with Windows Arc<Mutex<>> pattern)"
  - "PollResult enum gated any(fuse,winfsp) so both platforms can name the type"
  - "handle_release stays at line 682 in read_ops.rs (CR-04/D-04 invariant preserved)"
metrics:
  duration: "~45 minutes (active execution; cross-session)"
  completed: "2026-06-21"
  tasks_completed: 3
  files_changed: 12
---

# Phase 55 Plan 03: Cross-Platform Dedup Refactor Summary

Hoisted shared async crypto/IPNS helpers to `content_ops.rs`, extracted `poll.rs` and `content_fetch.rs` for read-path dedup, and normalized the macOS+Windows prepopulate blocks into a single shared `prepopulate_filesystem` function.

## Tasks Completed

### Task 1: Hoist shared async crypto helpers to content_ops.rs

Extracted `fetch_and_decrypt_content_async` and `publish_file_metadata` from both `operations.rs` (macOS, ~108 LoC) and `platform/windows/operations.rs` (Windows, ~155 LoC) into a new `crates/fuse/src/content_ops.rs` under `#[cfg(any(feature = "fuse", feature = "winfsp"))]`. Both platform files now re-export from `crate::content_ops`. The sync wrapper `fetch_and_decrypt_file_content` stays per-platform (A2 deviation: 3s vs 10s timeout is intentional).

Commit: `85a92b542`

### Task 2: Dedupe read paths

Created three modules:

- `crates/fuse/src/poll.rs` — `PollResult` enum (`any(fuse,winfsp)`) and `poll_filepointer_resolution` fn (`fuse` only, takes `&mut CipherBoxFS`)
- `crates/fuse/src/platform/windows/content_fetch.rs` — `spawn_content_prefetch` deduping 2x prefetch closures in windows/read_ops.rs
- Refactored `read_ops.rs` to use `poll::{poll_filepointer_resolution, PollResult}` and a local `spawn_content_prefetch_fuse` helper replacing 3x inline spawn blocks

`handle_release` confirmed at line 682 (CR-04/D-04 invariant preserved).

Commit: `8d2a7707a`

### Task 3: Extract shared prepopulate_filesystem

Created `apps/desktop/src-tauri/src/fuse/prepopulate.rs` holding the normalized `prepopulate_filesystem` async fn used by both macOS (`fuse/mod.rs`) and Windows (`fuse/windows/mod.rs`) mount functions. The macOS block (~85 LoC) and Windows block (~250 LoC) are replaced by a single shared call.

`cargo build -p cipherbox-desktop` passes. `cargo test -p cipherbox-fuse` 64/64.

Commit: `e1531d26d`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Missing FILEPOINTER_POLL_TIMEOUT references after constant removal (Task 2)**

- Found during: Task 2 read_ops.rs edit
- Issue: Two remaining `FILEPOINTER_POLL_TIMEOUT.as_secs()` references (in handle_open and handle_read) after removing the local constant
- Fix: Replaced both with literal `5` (the constant's value)
- Files modified: `crates/fuse/src/read_ops.rs`
- Commit: `8d2a7707a`

### Scope Decisions (Planned Deviations)

**A2: Timeout divergence — sync wrapper stays per-platform**

- macOS `fetch_and_decrypt_file_content` uses private `block_with_timeout` (3s, FUSE single-thread constraint)
- Windows `fetch_and_decrypt_file_content` uses `crate::block_with_timeout` (10s, runtime.rs)
- Only the two async helpers moved to `content_ops.rs`; sync wrappers intentionally NOT unified

**A3: Prepopulate blocks were NOT byte-identical**

- macOS: `cipherbox_core::decrypt_metadata_from_ipfs_public` (re-export), if-let chains, `get_unresolved_file_pointers()`
- Windows: `cipherbox_core::decrypt::decrypt_metadata_from_ipfs_public` (submodule path), nested match, `get_unresolved_file_pointers_for_parent(ino)`
- Normalized to: direct re-export paths, consistent match arms, `get_unresolved_file_pointers_for_parent` throughout (more precise; macOS now uses scoped variant)

**Windows winfsp build: CI-gated only**

Cannot compile winfsp feature on macOS. Windows path correctness verified by inspection (`MutexGuard<CipherBoxFS>` implements `DerefMut<Target=CipherBoxFS>`, so `&mut guard` coerces correctly).

## Verification Results

- `cargo test -p cipherbox-fuse`: 64 passed, 0 failed
- `cargo build -p cipherbox-desktop`: Finished (fuse feature, macOS)
- `handle_release` at line 682 in `read_ops.rs` (confirmed)
- No public API changes (HARD-06 preserved)

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, or trust boundary changes. All changes are pure structural refactoring of existing crypto paths.

## Self-Check: PASSED

Files created:
- `crates/fuse/src/content_ops.rs` FOUND
- `crates/fuse/src/poll.rs` FOUND
- `crates/fuse/src/platform/windows/content_fetch.rs` FOUND
- `apps/desktop/src-tauri/src/fuse/prepopulate.rs` FOUND

Commits:
- `85a92b542` FOUND
- `8d2a7707a` FOUND
- `e1531d26d` FOUND
