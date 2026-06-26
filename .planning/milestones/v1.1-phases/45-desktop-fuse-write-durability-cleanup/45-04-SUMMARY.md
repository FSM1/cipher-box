---
phase: 45-desktop-fuse-write-durability-cleanup
plan: "04"
subsystem: crates/fuse
tags: [refactor, tdd, typed-error, ipns, replay, crash-recovery]
dependency_graph:
  requires: ["45-03"]
  provides: [IpnsResolveOutcome, resolve_ipns_for_replay, T-45-05]
  affects:
    - crates/fuse/src/error.rs
    - crates/fuse/src/lib.rs
tech_stack:
  added: []
  patterns:
    - tdd-red-green-commit
    - typed-outcome-enum-over-string-match
key_files:
  created: []
  modified:
    - crates/fuse/src/error.rs
    - crates/fuse/src/lib.rs
decisions:
  - "IpnsResolveOutcome lives in error.rs with #[derive(Debug)] only — NOT thiserror::Error because it is an outcome, not an error"
  - "resolve_ipns_for_replay preserves both contains(not found) and contains(404) predicates from the original string match to avoid any classification regression"
  - "Bin publish path (spawn_bin_entry_publish:572) intentionally left unchanged per scope guard in plan objective"
  - "winfsp cargo check errors are pre-existing macOS platform failures in winfsp-sys/windows-future, not caused by this change (same as 45-03)"
metrics:
  duration: 8min
  completed: 2026-06-15
  tasks: 1
  files: 2
---

# Phase 45 Plan 04: Typed IpnsResolveOutcome Enum Summary

Replace the stringly-typed `e.to_lowercase().contains("not found")` match in the
replay per-file publish path (#19) with a typed `IpnsResolveOutcome` enum and a
`resolve_ipns_for_replay` wrapper that classifies the resolve result once.
Behavior is byte-for-byte identical: NotFound -> first-publish/seq-0; Error ->
retain entry and return the error.

## Tasks Completed

### Task 1 (TDD): RED+GREEN — add IpnsResolveOutcome and classify in replay

#### RED commit (35209baa3)

Added `not_found_outcome_drives_first_publish` (T-45-05) to the `#[cfg(test)] mod tests`
block in `crates/fuse/src/lib.rs`. The test exercises each `IpnsResolveOutcome` variant
and asserts the resulting `(is_first_publish, new_seq)` using `next_file_publish_sequence`
directly — hermetic, no network required. Failed to compile because `IpnsResolveOutcome`
was not yet defined in `error.rs`.

#### GREEN commit (c75161fd4)

- Added `pub enum IpnsResolveOutcome { Found(u64), NotFound, Error(String) }` with
  `#[derive(Debug)]` only to `crates/fuse/src/error.rs` — plain outcome enum, not thiserror.
- Added `async fn resolve_ipns_for_replay(coordinator, api, ipns_name) -> IpnsResolveOutcome`
  in `crates/fuse/src/lib.rs`: wraps `coordinator.resolve_sequence(...)` and maps
  `Ok(seq)` -> `Found(seq)`, `Err(e)` matching not-found/404 -> `NotFound`, other
  `Err(e)` -> `Error(e)`. Preserves both `.contains("not found")` and `.contains("404")`
  predicates from the original match to avoid classification regression.
- Replaced the `match coordinator.resolve_sequence(...).await { Ok(current_seq) => ..., Err(e) if e.to_lowercase().contains("not found") => ..., Err(e) => ... }`
  block in `replay_upload_entry` with `match resolve_ipns_for_replay(...).await { Found(...) => ..., NotFound => ..., Error(e) => ... }`.
  Log lines and `(is_first_publish, new_seq)` tuple preserved exactly.
- The bin publish path at `spawn_bin_entry_publish:572` is unchanged per scope guard.
- Full fuse test suite: 44 passed (was 43 — T-45-05 added 1).

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None. No production stubs introduced.

## Threat Flags

None. No new network endpoints, auth paths, or schema changes. The `resolve_ipns_for_replay`
wrapper preserves the exact classification predicate (T-45-04-INT threat mitigated by T-45-05
pinning NotFound->seq-0 and Error->retain).

## TDD Gate Compliance

- RED commit `35209baa3`: `test(45-04): add RED test T-45-05 not_found_outcome_drives_first_publish` — PRESENT
- GREEN commit `c75161fd4`: `feat(45-04): add IpnsResolveOutcome enum and resolve_ipns_for_replay wrapper` — PRESENT
- REFACTOR: not needed (implementation was clean on first pass)

## Self-Check: PASSED

- `pub enum IpnsResolveOutcome` in crates/fuse/src/error.rs: FOUND (grep -c == 1)
- All three variants Found/NotFound/Error in error.rs: FOUND (grep -c == 13)
- `async fn resolve_ipns_for_replay` in crates/fuse/src/lib.rs: FOUND (grep -c == 3)
- `IpnsResolveOutcome::NotFound` in crates/fuse/src/lib.rs: FOUND (grep -c == 6)
- `e.to_lowercase().contains("not found")` absent from replay_upload_entry: CONFIRMED (only in resolve_ipns_for_replay wrapper and bin path)
- Bin path at line 572 unchanged: CONFIRMED
- `cargo test -p cipherbox-fuse --no-default-features --features fuse`: 44 passed, 0 failed
- `cargo check --workspace`: Finished (macOS platform winfsp errors are pre-existing, unchanged)
- Commit 35209baa3 (RED): FOUND
- Commit c75161fd4 (GREEN): FOUND
