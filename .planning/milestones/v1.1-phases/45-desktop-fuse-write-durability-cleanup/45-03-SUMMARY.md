---
phase: 45-desktop-fuse-write-durability-cleanup
plan: "03"
subsystem: crates/sdk, crates/fuse
tags: [refactor, tdd, serde-compat, journal, crash-recovery, option-sentinel]
dependency_graph:
  requires: ["45-01"]
  provides: [deser_opt_string, file_meta_ipns_name-Option, T-45-04, T-45-04-compat]
  affects:
    - crates/sdk/src/queue.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/read_ops.rs
    - crates/fuse/src/platform/windows/write_ops.rs
tech_stack:
  added: []
  patterns:
    - tdd-red-green-commit
    - serde-deserialize_with-compat-shim
    - option-instead-of-empty-string-sentinel
key_files:
  created: []
  modified:
    - crates/sdk/src/queue.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/read_ops.rs
    - crates/fuse/src/platform/windows/write_ops.rs
decisions:
  - "Step 4 (FilePointer merge) uses unwrap_or_default() for file_meta_ipns_name because FilePointer.file_meta_ipns_name is String (core type); preserves old empty-string behavior for files without per-file IPNS"
  - "Per-file IPNS publish block (Step 3) wrapped in if let Some(name) = file_meta_ipns_name INSIDE the existing file_ipns_key_hex guard — double guard matches the semantic intent (both must be present to publish)"
  - "winfsp check errors are pre-existing macOS platform compilation failures in winfsp-sys/windows-future — not caused by this change; our write_ops.rs change is logically correct"
metrics:
  duration: 7min
  completed: 2026-06-15
  tasks: 2
  files: 4
---

# Phase 45 Plan 03: Option<String> Sentinel + Serde-Compat Deserializer Summary

Replace the empty-string `file_meta_ipns_name` sentinel in `JournalOp::UploadFile` with
`Option<String>` and add a serde-compat deserializer so pre-Phase-45 on-disk journals
written with `""` still replay as `None`. TDD: RED tests committed first (compile error
on `String` vs `Option<String>`), then GREEN implementation.

## Tasks Completed

### Task 1 (TDD): RED+GREEN — Option<String> sentinel + serde-compat deserializer in queue.rs

#### RED commit (252f362f3)

Added two failing tests to `crates/sdk/src/queue.rs` `#[cfg(test)] mod tests`:

- `upload_entry_none_ipns_round_trips` (T-45-04): builds UploadFile with
  `file_meta_ipns_name: None`, serializes to JSON, deserializes back, asserts field
  is `None`. Failed with `E0308: expected Option<String>, found String`.
- `legacy_empty_string_ipns_loads_as_none` (T-45-04-compat): hand-written raw JSON
  strings for three cases: `""` → `None`, `"k51..."` → `Some("k51...")`. Failed at
  compile time (type mismatch). JSON authored by hand because the new type can no
  longer produce `""` during serialization.

#### GREEN commit (1397ea11e)

- Added `fn deser_opt_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error>`:
  deserializes `Option<String>`, then `.filter(|v| !v.is_empty())` maps `""` → `None`.
- Changed `JournalOp::UploadFile.file_meta_ipns_name: String` to
  `#[serde(default, deserialize_with = "deser_opt_string")] file_meta_ipns_name: Option<String>`.
- Updated `make_upload_entry` test helper and all test constructors (3 sites) to `Some("...")`.
- 48 cipherbox-sdk tests pass (46 existing + T-45-04 + T-45-04-compat).

### Task 2: Propagate Option<String> through fuser + winfsp write paths and replay

Commit: `392874406`

- `crates/fuse/src/read_ops.rs`: removed `let file_meta_ipns_name_str = file_meta_ipns_name.clone().unwrap_or_default();` (3-line sentinel block); changed `file_meta_ipns_name: file_meta_ipns_name_str` → `file_meta_ipns_name: file_meta_ipns_name.clone()` in the JournalOp::UploadFile constructor.
- `crates/fuse/src/platform/windows/write_ops.rs`: same change for the winfsp path.
- `crates/fuse/src/lib.rs`:
  - Changed `replay_upload_entry` parameter from `file_meta_ipns_name: &str` to `file_meta_ipns_name: Option<&str>`.
  - Wrapped the per-file IPNS publish block (Step 3) in `if let Some(file_meta_ipns_name) = file_meta_ipns_name { ... }` INSIDE the existing `file_ipns_key_hex` guard — when `None`, the publish block is skipped, preserving the absent-name → no-per-file-publish behavior (T-45-03-DUR).
  - Added `let file_meta_ipns_name_str = file_meta_ipns_name.unwrap_or_default();` before Step 4 (FilePointer construction) to preserve the existing empty-string behavior for files without per-file IPNS when merging into parent.
  - Updated call site to pass `file_meta_ipns_name.as_deref()`.
  - Updated T-45-06 and `replay_records_failure_and_parks_at_max_retries` test fixtures to `Some("...")`.
- 43 cipherbox-fuse tests pass; 48 cipherbox-sdk tests pass.

## Deviations from Plan

None — plan executed exactly as written. The `unwrap_or_default()` in Step 4 is the
minimal behavior-preserving approach for FilePointer construction (the plan says
"preserving the existing skip-when-absent behavior" — this is the Step 3 guard, not Step 4).

## Known Stubs

None. No production stubs introduced.

## Threat Flags

None. No new network endpoints, auth paths, or schema changes beyond what the plan
covered. The serde compat shim (T-45-03-INT) is implemented and verified by T-45-04-compat.

## TDD Gate Compliance

- RED commit `252f362f3`: `test(45-03): add RED tests T-45-04 and T-45-04-compat` — PRESENT
- GREEN commit `1397ea11e`: `feat(45-03): change file_meta_ipns_name to Option<String>` — PRESENT
- REFACTOR: not needed (implementation was clean on first pass)

## Self-Check: PASSED

- `fn deser_opt_string` in crates/sdk/src/queue.rs: FOUND (grep -c == 1)
- `file_meta_ipns_name: Option<String>` in crates/sdk/src/queue.rs: FOUND (grep -c == 1)
- `deserialize_with = "deser_opt_string"` in crates/sdk/src/queue.rs: FOUND (grep -c == 1)
- `fn upload_entry_none_ipns_round_trips` in crates/sdk/src/queue.rs: FOUND (grep -c == 1)
- `fn legacy_empty_string_ipns_loads_as_none` in crates/sdk/src/queue.rs: FOUND (grep -c == 1)
- `file_meta_ipns_name: Option<&str>` in crates/fuse/src/lib.rs: FOUND (grep -c == 1)
- No `file_meta_ipns_name.*unwrap_or_default` in read_ops.rs: CONFIRMED (grep returned empty)
- No `file_meta_ipns_name.*unwrap_or_default` in windows/write_ops.rs: CONFIRMED
- `cargo test -p cipherbox-sdk -- --test-threads=4`: 48 passed, 0 failed
- `cargo test -p cipherbox-fuse --no-default-features --features fuse`: 43 passed, 0 failed
- Commit 252f362f3 (RED): FOUND
- Commit 1397ea11e (GREEN): FOUND
- Commit 392874406 (Task 2): FOUND
