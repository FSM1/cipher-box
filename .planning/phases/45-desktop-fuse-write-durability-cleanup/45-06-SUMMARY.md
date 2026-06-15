---
phase: 45
plan: "06"
subsystem: fuse
tags: [refactor, journal, helpers, upload, mkdir, cross-platform]
dependency_graph:
  requires: [45-01, 45-02, 45-03, 45-04, 45-05]
  provides: [journal-helpers-module]
  affects: [cipherbox-fuse]
tech_stack:
  added: []
  patterns: [shared-builder-pattern, feature-gated-module, zeroizing-key-material]
key_files:
  created:
    - crates/fuse/src/journal_helpers.rs
  modified:
    - crates/fuse/src/lib.rs
    - crates/fuse/src/read_ops.rs
    - crates/fuse/src/write_ops.rs
    - crates/fuse/src/platform/windows/write_ops.rs
decisions:
  - Helper takes &OpenFileHandle directly because open_files entry is removed before call
  - WinFsp write_gen read AFTER closure bump; fuser read BEFORE via result field
  - build_mkdir_journal_entry called AFTER child inode inserted so build_folder_metadata sees new child
  - Zeroizing<Vec<u8>> passed directly (no double-wrap) from generate_ed25519_keypair callers
metrics:
  duration: ~90m
  completed: 2026-06-15
  tasks_completed: 2
  files_changed: 5
---

# Phase 45 Plan 06: Journal Helpers Consolidation Summary

Consolidated duplicated journal entry build logic from four call sites (fuser upload, winfsp upload, fuser mkdir, winfsp mkdir) into a shared `journal_helpers.rs` module with two builder methods on `CipherBoxFS`.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create journal_helpers.rs + wire upload paths | b3e4be52a | journal_helpers.rs, lib.rs, read_ops.rs, platform/windows/write_ops.rs |
| 2 | Add mkdir builder + wire mkdir paths | b3e4be52a | write_ops.rs, platform/windows/write_ops.rs |

Both tasks committed atomically since all changes were implemented together.

## What Was Built

`crates/fuse/src/journal_helpers.rs` - new module feature-gated with `#[cfg(any(feature = "fuse", feature = "winfsp"))]` containing:

### `build_upload_journal_entry(&self, ino: u64, handle: &OpenFileHandle, is_new_file: bool) -> Result<UploadJournalResult, String>`

Shared steps: AES-256-GCM encryption of file content, ECIES key wrap, per-file IPNS name resolution, `JournalOp::UploadFile` + `JournalEntry` construction. Returns `UploadJournalResult` with all fields needed for spawn block and inode mutations.

### `build_mkdir_journal_entry(&self, parent_ino, child_ino, name, folder_key, ipns_name, ipns_private_key, encrypted_folder_key_hex) -> Result<MkdirJournalResult, String>`

Shared steps: folder metadata JSON serialization, IPNS name resolution for parent, `JournalOp::MkdirPublish` + `JournalEntry` construction. Returns `MkdirJournalResult` with all fields for spawn block.

### Platform-specific logic retained in callers

- fuser `handle_release`: reply, inode mutations, `pending_content.insert`, `queue_publish`, spawn
- winfsp `handle_cleanup`: `write_generation += 1` bump before closure, `write_gen` read after bump from inode
- fuser/winfsp `handle_mkdir` / `handle_create` dir branch: inode insertion, `reply_entry`/`FileInfo` return, spawn

## Deviations from Plan

None - plan executed exactly as written.

## Security Verification

- Helper returns ciphertext only; plaintext file bytes are zeroized before return via `Zeroizing` wrapper
- ECIES key wrapping happens exactly once in the helper; callers do not re-wrap
- `ipns_private_key` field in `MkdirJournalResult` is `Zeroizing<Vec<u8>>`; callers use `(*key).clone()` to dereference into spawn block without leaking
- No plaintext keys logged or returned in struct fields

## Test Results

All 44 crash-recovery tests pass:

```
cargo test -p cipherbox-fuse --no-default-features --features fuse
test result: ok. 44 passed; 0 failed
```

`cargo check --workspace` exits 0. `cargo fmt --check` clean.

Pre-existing winfsp macOS cross-compile failures (`IMarshal`, `windows_registry`) confirmed pre-existing via git stash; not caused by this work.

## Self-Check: PASSED

- journal_helpers.rs: FOUND
- lib.rs mod declaration: FOUND
- Commit b3e4be52a: FOUND (git log confirmed)
- 44/44 tests: PASSED
- cargo check --workspace: PASSED
- cargo fmt --check: PASSED
