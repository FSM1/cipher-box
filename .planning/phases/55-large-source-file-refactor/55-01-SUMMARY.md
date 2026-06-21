---
phase: "55"
plan: "01"
subsystem: "fuse"
tags: ["refactor", "rust", "module-decomposition", "cipherbox-fuse"]
dependency_graph:
  requires: []
  provides: ["crates/fuse/src/runtime.rs", "crates/fuse/src/events.rs", "crates/fuse/src/publish.rs", "crates/fuse/src/metadata.rs", "crates/fuse/src/fs.rs", "crates/fuse/src/replay.rs"]
  affects: ["crates/fuse/src/lib.rs", "crates/fuse/src/read_ops.rs"]
tech_stack:
  added: []
  patterns: ["multi-file Rust inherent impl", "cfg-gated module declarations", "pub use re-export pattern", "pub(crate) cross-module visibility"]
key_files:
  created:
    - crates/fuse/src/runtime.rs
    - crates/fuse/src/events.rs
    - crates/fuse/src/publish.rs
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/replay.rs
  modified:
    - crates/fuse/src/lib.rs
    - crates/fuse/src/read_ops.rs
decisions:
  - "handler_harness_tests and durability_characterization_tests stay in lib.rs (RESEARCH Pitfall 3 - fuse-gated test modules that reference test_support stay in crate root)"
  - "decrypt_journal_name made pub(crate) in replay.rs so durability_characterization_tests can reference it via crate::replay::decrypt_journal_name"
  - "winfsp build verification done by cfg-gate inspection only - winfsp-sys is Windows-only, cannot compile on macOS host; CI-gated on Windows runners"
metrics:
  duration: "~2 sessions"
  completed: "2026-06-21T03:58:22Z"
  tasks_completed: 3
  files_created: 6
  files_modified: 2
---

# Phase 55 Plan 01: Large Source File Refactor (lib.rs Decomposition) Summary

Decomposed `crates/fuse/src/lib.rs` from ~3300 LoC into 6 focused sibling modules, reducing the crate root to a ~74 LoC file of cfg-gated module declarations and re-exports. Pure refactor — no public API changes, no behavior changes.

## Tasks Completed

### Task 1 - Extract runtime.rs, events.rs, publish.rs (commit c489a4e84)

Pre-existing work, committed before this session.

- `runtime.rs`: `NETWORK_TIMEOUT` const + `block_with_timeout` pub fn
- `events.rs`: `PendingRefresh`, `PendingContent`, `PendingFilePointer`, `FsEvent`, `UploadComplete`, `spawn_metadata_refresh`
- `publish.rs`: `PublishQueueEntry`, `next_file_publish_sequence` (ungated, pure utility), `resolve_ipns_for_replay` (pub(crate)), `classify_resolve_outcome` (pub(crate)), `PublishCoordinator` + impl. Contains own `mod tests` with classify/sequence tests.

### Task 2 - Extract metadata.rs and fs.rs (commit c960f1078)

- `metadata.rs`: `encrypt_metadata_to_json`, `merge_folder_children`, `spawn_metadata_publish`, `spawn_bin_entry_publish`, `REENCRYPT_MAX_ATTEMPTS`, `ReencryptOutcome`, `resolve_and_fetch_file_meta`, `spawn_file_meta_reencrypt`. Contains T-45-08 merge tests.
- `fs.rs`: `CipherBoxFS` struct (all fields `pub` - desktop crate constructs via struct literal), `impl CipherBoxFS` (all methods), `uuid_from_ino` (private), `mount_point` (pub).
- lib.rs reduced from ~3300 to ~2128 LoC.

Build: `cargo build -p cipherbox-fuse` passed. Tests: 64 passed, 0 failed.

### Task 3 - Extract replay.rs, slim lib.rs to ~74 LoC (commit e0ea845d3)

- `replay.rs`: `replay_for_vault` (pub), `resolve_folder_key`, `resolve_folder_key_cached`, `fetch_merge_publish_parent`, `publish_child_folder_metadata`, `replay_mkdir_entry`, `decrypt_journal_name` (pub(crate)), `replay_upload_entry`. Contains all replay tests: T-45-06, T-45-07, REQ-4, REQ-5 transient, REQ-5 strict, T-45-05, F2.
- lib.rs reduced from ~2128 to ~74 LoC production declarations. `handler_harness_tests` and `durability_characterization_tests` remain in lib.rs per RESEARCH Pitfall 3.
- `read_ops.rs`: fixed `crate::NETWORK_TIMEOUT` to `crate::runtime::NETWORK_TIMEOUT` (Rule 3 auto-fix).

Build: `cargo build -p cipherbox-fuse` passed. Tests: 64 passed, 0 failed.

## Final lib.rs Structure (~74 LoC production code)

```
mod cache, constants, error, file_handle, helpers, inode, journal_helpers
cfg(fuse): dir_ops, operations, read_ops, write_ops
mod platform
cfg(fuse|winfsp): runtime, events, publish, metadata, fs, replay
cfg(test,fuse): test_support
pub use re-exports: all public items from all modules
cfg(test,fuse): handler_harness_tests   [stays - Pitfall 3]
cfg(test,fuse): durability_characterization_tests  [stays - Pitfall 3]
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] crate::NETWORK_TIMEOUT path broken in read_ops.rs**

- Found during: Task 3
- Issue: `read_ops.rs` referenced `crate::NETWORK_TIMEOUT` which was previously accessible because lib.rs had a module-scoped `use runtime::NETWORK_TIMEOUT`. After removing the replay block from lib.rs, that use was gone.
- Fix: Changed `crate::NETWORK_TIMEOUT` to `crate::runtime::NETWORK_TIMEOUT` in `read_ops.rs`.
- Files modified: `crates/fuse/src/read_ops.rs`
- Commit: e0ea845d3

**2. [Rule 3 - Blocking] decrypt_journal_name cross-module visibility**

- Found during: Task 3 (anticipated during design)
- Issue: `durability_characterization_tests` in lib.rs called `super::decrypt_journal_name` which moved to `replay.rs`. `super::` from a lib.rs inline test module resolves to the crate root, not `replay::`.
- Fix: Made `decrypt_journal_name` `pub(crate)` in `replay.rs`. Updated 4 call sites in `durability_characterization_tests` to use `crate::replay::decrypt_journal_name`.
- Files modified: `crates/fuse/src/replay.rs`, `crates/fuse/src/lib.rs`
- Commit: e0ea845d3

## winfsp Build Note

`cargo build -p cipherbox-fuse --no-default-features --features winfsp` cannot run on the macOS host because `winfsp-sys` and `windows-future` are Windows-only crates. Verification is CI-gated on Windows runners. Every item moved to the new modules retains its original `#[cfg(any(feature = "fuse", feature = "winfsp"))]` gate verbatim. The `publish_file_metadata` cfg-branched use shim in `replay.rs` is byte-identical to the original in lib.rs.

## Known Stubs

None. Pure code motion refactor.

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes.

## Self-Check: PASSED

- `crates/fuse/src/replay.rs` exists: FOUND
- `crates/fuse/src/metadata.rs` exists: FOUND
- `crates/fuse/src/fs.rs` exists: FOUND
- lib.rs production code ~74 LoC (before test modules): VERIFIED
- Task 1 commit c489a4e84: pre-existing, confirmed in git log
- Task 2 commit c960f1078: FOUND
- Task 3 commit e0ea845d3: FOUND
- 64 tests pass after each task: VERIFIED
