---
phase: 43-fuse-write-durability
plan: "01"
subsystem: sdk
tags:
  - rust
  - write-journal
  - durability
  - tdd
  - fuse
dependency_graph:
  requires: []
  provides:
    - cipherbox-sdk::WriteQueue (persist-backed)
    - cipherbox-sdk::JournalEntry
    - cipherbox-sdk::JournalOp
    - cipherbox-sdk::JournalEntryStatus
    - cipherbox-sdk::SyncStatus::WriteParked
  affects:
    - crates/sdk/src/queue.rs
    - crates/sdk/src/state.rs
    - crates/sdk/src/lib.rs
    - crates/sdk/src/sync.rs
tech_stack:
  added: []
  patterns:
    - path-backed journal with fsync barrier (sync_all)
    - serde JSON serialization for journal entries
    - vault-scoped entry filtering
    - park-on-max-retries (D-09)
    - MkdirPublish-before-UploadFile replay ordering (D-08)
key_files:
  created: []
  modified:
    - crates/sdk/src/queue.rs
    - crates/sdk/src/state.rs
    - crates/sdk/src/lib.rs
    - crates/sdk/src/sync.rs
decisions:
  - WriteQueue.journal_dir marked pub(crate) to allow test assertions on file paths without exposing to external crates
  - tempfile crate avoided (not a workspace dep); unique test dirs use SystemTime nanos + thread ID length as suffix to satisfy zero-new-deps constraint
  - sync.rs write-queue drain logic removed from SyncDaemon (FUSE layer owns drain, Plan 43-02+)
metrics:
  duration: 9min
  completed: 2026-06-12
  tasks: 3
  files: 4
---

# Phase 43 Plan 01: Durable Write Journal Summary

Persist-backed WriteQueue with fsync barrier, vault-scoped replay, park-on-failure, and MkdirPublish-before-UploadFile ordering. Replaces the in-memory VecDeque that lost queued writes on app quit.

## What Was Built

### New Public API Surface

`crates/sdk/src/queue.rs`:

- `JournalOp` enum with `UploadFile` (ciphertext_b64, wrapped_key_hex, iv_hex, file_meta_ipns_name, file_ipns_key_hex, parent_folder_ipns_name, filename, size, created_at_ms) and `MkdirPublish` (child_ipns_name, child_folder_key_hex, child_ipns_key_hex, parent_folder_ipns_name, name, created_at_ms). No ino/parent_ino fields (D-02).
- `JournalEntryStatus` enum with `Pending`, `InProgress`, `Failed { last_error: String }` (D-09)
- `JournalEntry` struct with id, vault_root_ipns, op, retries, status
- `WriteQueue::new(journal_dir: PathBuf, max_retries: u32)`
- `WriteQueue::put(&self, entry: &JournalEntry)` with serialize + write + `sync_all()` + 0o600 (D-04, T-43-02)
- `WriteQueue::remove(&self, id: &str)` idempotent
- `WriteQueue::load_all_for_vault(&self, vault_root_ipns: &str)` with skip-on-malformed and vault filter (D-07, T-43-03, V5)
- `WriteQueue::update_status(&self, id, status)`
- `WriteQueue::record_failure(&self, entry, error)` park-or-retry (D-09)
- `WriteQueue::ordered_for_replay(entries: Vec<JournalEntry>)` MkdirPublish before UploadFile (D-08)

`crates/sdk/src/state.rs`:

- `SyncStatus::WriteParked { pending: u32, failed: u32 }` added after Error (D-10)

### Removed Symbols

- `QueuedWrite` struct (had parent_ino, Instant fields)
- `UploadHandler` trait
- `WriteQueue::enqueue`, `process`, `is_empty`, `len`

## TDD Gate Compliance

All 3 tasks use the same file; tests committed as one RED commit, implemented in one GREEN commit.

| Gate | Commit | Notes |
| ---- | ------ | ----- |
| RED | b3be9d31d | test(43-01): failing tests — compilation fails, types missing |
| GREEN | ea287b42a | feat(43-01): 14 queue + 6 state tests pass |

## Test Results

```
cargo test -p cipherbox-sdk -- queue: 14 passed
cargo test -p cipherbox-sdk -- state: 6 passed
```

Tests covered:

- `upload_entry_round_trips`, `mkdir_entry_round_trips` — D-05 serde round-trip
- `journal_no_plaintext` — D-05 no plaintext/parent_ino in JSON
- `failed_status_round_trips` — JournalEntryStatus::Failed preservation
- `journal_put_load` — put writes file, load returns it
- `load_all_for_vault_excludes_foreign_vault` — D-07 vault scoping, foreign file stays on disk
- `journal_remove` — idempotent remove
- `update_status_persists_new_status` — status overwrite persisted
- `park_on_max_retries` — D-09 entry remains on disk as Failed
- `record_failure_below_max_increments_retries` — retry increment
- `malformed_json_is_skipped_not_panicked` — V5 / T-43-03 resilience
- `replay_order_mkdir_before_upload` — D-08 ordering guarantee
- `replay_order_preserves_relative_order_within_group` — stable sort within group
- `sync_status_write_parked_variant` — D-10 WriteParked construct/compare

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed sync.rs write_queue call sites**

- Found during: GREEN implementation
- Issue: `sync.rs` called `write_queue.is_empty()` and `write_queue.len()` which were removed in the rewrite
- Fix: Replaced the queue-drain block in `SyncDaemon::sync_cycle()` with a log comment; FUSE layer (Plans 43-02+) owns journal drain
- Files modified: `crates/sdk/src/sync.rs`
- Commit: ea287b42a

**2. [Rule 3 - Blocking] tempfile not a workspace dependency**

- Found during: RED test writing
- Issue: Plan suggested `tempfile::TempDir` but `tempfile` is not in the workspace Cargo.toml
- Fix: Used `std::env::temp_dir()` with SystemTime nanos + thread ID length as unique suffix
- Files modified: `crates/sdk/src/queue.rs` (test helpers only)

## Known Stubs

None. Journal types, persistence, and ordering are fully implemented. Integration into FUSE write/release handlers is deferred to Plans 43-02 and 43-03 by design.

## Threat Surface Scan

No new network endpoints, auth paths, or trust-boundary schema changes. All threat register mitigations implemented:

- T-43-01: ciphertext_b64 + wrapped_key_hex + iv_hex only — enforced by `journal_no_plaintext` test
- T-43-02: 0o600 permissions in `put()` on Unix
- T-43-03: serde errors skip-with-warn, never panic — enforced by `malformed_json_is_skipped_not_panicked`
- T-43-04: Failed entries kept on disk, never dropped — enforced by `park_on_max_retries`

## Self-Check: PASSED

All created/modified files exist on disk. Both RED and GREEN commits verified in git log.
