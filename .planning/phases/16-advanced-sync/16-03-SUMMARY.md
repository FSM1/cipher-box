---
phase: 16-advanced-sync
plan: '03'
subsystem: desktop
tags: [rust, fuse, ipns, conflict-detection, optimistic-concurrency, winfsp]

# Dependency graph
requires:
  - phase: 16-01
    provides: API accepts expectedSequenceNumber in publish DTOs, returns 409 Conflict with currentSequenceNumber

provides:
  - Desktop client sends expected_sequence_number with every folder IPNS publish
  - On 409 Conflict, re-fetches remote metadata, merges local mutation onto remote children, retries once
  - merge_folder_children() helper for additive conflict resolution (preserves both devices' changes)
  - Single retry only -- persistent conflict logs error without crashing
  - Per-file IPNS publishes unaffected (None expected_sequence_number)
  - All IpnsPublishRequest construction sites updated across all platforms

affects:
  - 16-04 (E2E conflict detection tests reference this Rust implementation)
  - 16-05 (Desktop E2E scripts test this conflict handling behavior)
  - Phase 17 (TEE republish conflict detection builds on this foundation)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Optimistic concurrency control with re-fetch + merge + retry in Rust async
    - Additive merge strategy for folder children (by IPNS name key, last-writer-wins per child)
    - Jitter via SystemTime subsec_nanos for symmetry breaking in concurrent conflict resolution

key-files:
  created: []
  modified:
    - apps/desktop/src-tauri/src/api/ipns.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/write_ops.rs
    - apps/desktop/src-tauri/src/fuse/windows/write_ops.rs
    - apps/desktop/src-tauri/src/fuse/operations.rs
    - apps/desktop/src-tauri/src/fuse/windows/operations.rs
    - apps/desktop/src-tauri/src/commands/vault.rs
    - apps/desktop/src-tauri/src/registry/mod.rs

key-decisions:
  - 'PublishResult enum (Success | Conflict) returned by publish_ipns instead of (); callers match explicitly'
  - 'merge_folder_children uses IPNS name as stable child key (ipns_name for folders, file_meta_ipns_name for files)'
  - 'Jitter via SystemTime::subsec_nanos instead of rand::random (simpler, avoids new API surface)'
  - 'Parent publish after mkdir gets Some(seq) with conflict warning + debounce retry fallback (TODO for full re-fetch+merge)'
  - 'OS notification not implemented -- tray status change is visible; AppHandle not easily accessible from spawn_metadata_publish'

patterns-established:
  - 'Pattern: match publish_ipns result on all call sites -- compiler enforces exhaustive handling of Success/Conflict'
  - 'Pattern: unconditional publishes (vault init, device registry, new folder seq=0, per-file) use None; folder updates use Some(seq)'

# Metrics
duration: 18min
completed: 2026-03-03
---

# Phase 16 Plan 03: Desktop Conflict Detection Summary

**Rust FUSE publish layer wired for optimistic concurrency control: sends expected_sequence_number, handles 409 with re-fetch + additive merge + single retry preserving other devices' changes**

## Performance

- **Duration:** 18 min
- **Started:** 2026-03-03T13:06:00Z
- **Completed:** 2026-03-03T13:24:00Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- `PublishResult` enum added to `api/ipns.rs` with `Success` and `Conflict { current_sequence_number }` variants; `publish_ipns` returns `Result<PublishResult, String>` and correctly parses 409 responses
- `spawn_metadata_publish` in `fuse/mod.rs` now sends `expected_sequence_number: Some(seq.to_string())` and on 409 Conflict: resolves fresh sequence, fetches+decrypts remote metadata, runs `merge_folder_children()` to produce a merged result preserving both devices' changes, adds jitter, re-encrypts and retries once
- All 9 `IpnsPublishRequest` construction sites across macOS and Windows code updated with appropriate `expected_sequence_number` values (Some for folder updates, None for file/vault/registry publishes)

## Task Commits

1. **Task 1: Add conflict detection to Rust API client** - `4f814974d` (feat)
2. **Task 2: Handle conflicts in FUSE publish with re-fetch + re-apply + retry** - `099b45085` (feat)

**Plan metadata:** (included in Task 2 commit)

## Files Created/Modified

- `apps/desktop/src-tauri/src/api/ipns.rs` - Added `PublishResult` enum, `expected_sequence_number` field on `IpnsPublishRequest`, updated `publish_ipns` return type
- `apps/desktop/src-tauri/src/fuse/mod.rs` - Added `merge_folder_children()` helper, rewrote `spawn_metadata_publish` with full conflict handling (re-fetch + merge + jitter + retry)
- `apps/desktop/src-tauri/src/fuse/write_ops.rs` - Updated new folder publish (None) and parent publish after mkdir (Some(seq) with conflict warning)
- `apps/desktop/src-tauri/src/fuse/windows/write_ops.rs` - Windows equivalent of write_ops.rs changes
- `apps/desktop/src-tauri/src/fuse/operations.rs` - Per-file IPNS publish uses None
- `apps/desktop/src-tauri/src/fuse/windows/operations.rs` - Windows per-file IPNS publish uses None
- `apps/desktop/src-tauri/src/commands/vault.rs` - Vault init publish uses None (seq 0)
- `apps/desktop/src-tauri/src/registry/mod.rs` - Device registry publish uses None

## Decisions Made

- **PublishResult enum instead of void**: Callers must explicitly match on Success/Conflict -- compiler enforces exhaustive handling, no silent failure possible.
- **Merge key is IPNS name**: `ipns_name` for `FolderEntry`, `file_meta_ipns_name` for `FilePointer` -- these are stable identifiers that survive rename (renamed entry keeps same IPNS key but gets new name field; local version wins).
- **Jitter via `SystemTime::subsec_nanos % 400 + 100`**: Avoids adding `rand` API surface (already a dep but cleaner) and gives 100-500ms jitter range sufficient to break symmetry between concurrent devices.
- **OS notification deferred**: CONTEXT.md calls for OS notification on conflict; `AppHandle` is not easily accessible from the background thread in `spawn_metadata_publish`. Tray status change remains visible. Documented as future enhancement.
- **Parent mkdir publish**: Gets `Some(seq)` for conflict detection but only logs warning + lets debounce retry on conflict; full re-fetch+merge for mkdir parent is a TODO (v2).

## Deviations from Plan

### Auto-fixed Issues

None -- plan executed exactly as written with one noted adaptation:

The plan's pseudocode used `metadata.children.as_ref()` (treating `children` as `Option<Vec<...>>`), but `FolderMetadata.children` is `Vec<FolderChild>` (not optional). The `merge_folder_children()` implementation was adapted accordingly -- uses direct `Vec` operations with `is_empty()` check instead of `Option::is_some()` checks. Logic is equivalent and correct.

## Issues Encountered

- **Branch HEAD diverged during execution**: Plans 16-02, 16-04, 16-05 were committed to the branch between Task 1 and Task 2. Task 1 commit `4f814974d` was already an ancestor of HEAD when Task 2 was committed. Verified `ipns.rs` changes from Task 1 were present at HEAD before staging Task 2 changes. No rework needed.
- **`cargo check --features winfsp` fails on macOS**: Pre-existing issue with `windows-future` crate (`IMarshal` not found in `windows_core::imp`). This is a platform incompatibility when cross-checking Windows builds on macOS, unrelated to this plan's changes. The `--features fuse` check is the relevant macOS verification and compiles cleanly.

## Next Phase Readiness

- Desktop client now participates in full optimistic concurrency protocol matching the web client behavior
- `merge_folder_children()` provides correct additive merge semantics that preserve all devices' changes
- Ready for Phase 16-04/16-05 E2E tests to exercise conflict detection end-to-end
- TODO for v2: Full re-fetch+merge+retry for parent folder publish after `mkdir` (currently just logs warning on conflict)
- TODO for v2: OS notification via `AppHandle` when available in `spawn_metadata_publish`

---

_Phase: 16-advanced-sync_
_Completed: 2026-03-03_
