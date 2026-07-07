---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 02
subsystem: rust-sdk
tags: [rust, rotation, anti-rollback, durability, sdk, tdd]

# Dependency graph
requires:
  - phase: 68
    provides: "packages/sdk/src/state/rotation-high-water.ts (TS reference implementation, ROT-07)"
provides:
  - "crates/sdk::rotation::high_water::RotationHighWater — fail-closed durable anti-rollback gate over an injected HighWaterStore seam"
  - "crates/sdk::floor_store::JsonSidecarFloorStore — durable JSON-sidecar HighWaterStore impl, restart-survival proven"
affects: [69-06, fuse-list-folder, rust-resolve-path]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Native async fn in trait (Rust 1.75+ AFIT), `#[allow(async_fn_in_trait)]` since the trait is only ever used generically (never `dyn`) within this crate"
    - "Two independent HighWaterStore instances (generation, seq) rather than one two-column store — mirrors TS's two-store constructor shape"
    - "Atomic sidecar write: temp file (0600 via OpenOptionsExt) + fsync + rename + parent-dir fsync, extending crates/sdk/src/queue.rs's fsync discipline with a rename step for true all-or-nothing atomicity"

key-files:
  created:
    - crates/sdk/src/rotation/mod.rs
    - crates/sdk/src/rotation/high_water.rs
    - crates/sdk/src/floor_store.rs
  modified:
    - crates/sdk/src/lib.rs

key-decisions:
  - "EnforceResolvedParams uses i64 (not u64) for seq/generation/version_floor — these are live, not-yet-validated inputs from the resolve path; Rust has no integer NaN, so the TS 'NaN' defense collapses to the negative-value check on i64. Stored floors remain u64 (HighWaterStore::get/put) since a validated/persisted floor is always non-negative."
  - "RotationError is a 3-variant thiserror enum (GenerationRegression / SequenceRegression / InvalidFloorValue) rather than reusing the TS pattern of folding invalid-input into the regression errors with a floor=-1 sentinel — gives callers a precise match instead of a magic sentinel."
  - "Two floors (generation, seq) are two independent JsonSidecarFloorStore instances over two different sidecar filenames (rotation-high-water-generation.json / rotation-high-water-seq.json) rather than one file with two columns — keeps JsonSidecarFloorStore a single-purpose `{nodeId: value}` map store, reusable for either floor."
  - "JsonSidecarFloorStore::put swallows write I/O errors after logging via log::error! (matches the TS Promise<void> contract's exception-not-Result shape) rather than threading a Result through every RotationHighWater call site — a durability defect (a bump not persisting) is distinct from a correctness defect (enforce_resolved's accept/reject decision, which is unaffected)."

requirements-completed: [SC-04]

coverage:
  - id: D1
    description: "RotationHighWater.enforce_resolved fail-closed gate: rejects invalid live input before floor comparison, rejects generation regression, applies cold-device versionFloor vs warm seq-floor branch correctly, bumps both floors monotonic-max on a valid forward resolve"
    requirement: "SC-04"
    verification:
      - kind: unit
        ref: "crates/sdk/src/rotation/high_water.rs#rotation::high_water::tests (10 tests: cold_device_applies_version_floor_gate, cold_device_rejects_below_version_floor, warm_device_applies_seq_floor_not_version_floor, warm_device_rejects_seq_regression, generation_regression_is_rejected_even_with_valid_seq, invalid_generation_input_rejected_before_any_floor_comparison, invalid_seq_input_rejected_before_floor_comparison, valid_forward_resolve_bumps_both_floors_monotonic_max, seed_from_grant_never_lowers_the_generation_floor, is_valid_floor_value_rejects_negative)"
        status: pass
    human_judgment: false
  - id: D2
    description: "JsonSidecarFloorStore persists floors durably across a simulated daemon restart (struct drop + recreate over the same journal-dir path), writes atomically (temp file + rename, 0600), and never produces a torn/partial JSON file"
    requirement: "SC-04"
    verification:
      - kind: unit
        ref: "crates/sdk/src/floor_store.rs#floor_store::tests::floor_store_restart"
        status: pass
      - kind: unit
        ref: "crates/sdk/src/floor_store.rs#floor_store::tests::survives_restart_end_to_end_through_rotation_high_water"
        status: pass
      - kind: unit
        ref: "crates/sdk/src/floor_store.rs#floor_store::tests::no_partial_json_survives_a_write"
        status: pass
      - kind: other
        ref: "grep -n 'sled|redb|rusqlite' crates/sdk/Cargo.toml (empty — D-03 no new storage dep)"
        status: pass
    human_judgment: false

# Metrics
duration: 8min
completed: 2026-07-06
status: complete
---

# Phase 69 Plan 02: Rust ROT-07 Durable Anti-Rollback Floor Summary

**Ported the TS `RotationHighWater`/`HighWaterStore` anti-rollback gate (ROT-07) to `crates/sdk` with a fail-closed `enforce_resolved` and a durable JSON-sidecar floor store proven to survive daemon restart.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-07-06T02:57:43Z
- **Completed:** 2026-07-06T03:05:33Z
- **Tasks:** 2 (both TDD)
- **Files modified:** 4 (3 created, 1 modified)

## Accomplishments

- `crates/sdk/src/rotation/high_water.rs`: `RotationHighWater<S: HighWaterStore>` with `enforce_resolved` enforcing the exact TS ordering — validate live input → generation-floor check → cold-device-versionFloor-or-warm-seq-floor branch → bump both floors monotonic-max
- `HighWaterStore` trait (native async fn in trait) as the dependency-injection seam; `RotationError` thiserror enum with `GenerationRegression` / `SequenceRegression` / `InvalidFloorValue` variants
- `crates/sdk/src/floor_store.rs`: `JsonSidecarFloorStore`, a durable `HighWaterStore` impl backed by an atomically-written JSON sidecar (temp file + rename, 0600 perms via `OpenOptionsExt`) — no new storage dependency
- 16 new unit tests (10 for the gate logic over an in-memory store, 6 for the durable sidecar store including an end-to-end restart-survival proof through `RotationHighWater` itself)
- `pub mod rotation;` and `pub mod floor_store;` wired into `crates/sdk/src/lib.rs`; full crate re-export of the new public symbols

## Task Commits

Each task was committed atomically:

1. **Task 1: RotationHighWater gate + HighWaterStore trait (fail-closed enforce_resolved)** - `04b3e10a8` (feat)
2. **Task 2: JSON-sidecar durable floor store + restart-survival test (D-03)** - `be98df614` (feat)

_Both tasks were `tdd="true"`; unit tests were written together with the implementation in the same commit per task (the plan's `<action>` for each task specified writing the implementation plus its `#[cfg(test)]`/`#[tokio::test]` coverage as one deliverable, not a separate RED-then-GREEN commit pair)._

## Files Created/Modified

- `crates/sdk/src/rotation/mod.rs` - Rotation module barrel, re-exports `HighWaterStore`, `RotationHighWater`, `EnforceResolvedParams`, `RotationError`
- `crates/sdk/src/rotation/high_water.rs` - The ported ROT-07 fail-closed anti-rollback gate + 10 unit tests
- `crates/sdk/src/floor_store.rs` - `JsonSidecarFloorStore` durable sidecar `HighWaterStore` impl + 6 unit tests
- `crates/sdk/src/lib.rs` - Added `pub mod rotation;` / `pub mod floor_store;` and re-exports

## Decisions Made

- `EnforceResolvedParams` fields are `i64`, not `u64` — they carry live, not-yet-validated resolve-path input (mirrors the TS "reject NaN/negative before comparing" defense; Rust's `i64` has no NaN, so only the negative-value branch is meaningfully testable, which the plan's acceptance criteria explicitly anticipated as a "NaN-analog" test)
- `RotationError` is a 3-variant enum (`GenerationRegression` / `SequenceRegression` / `InvalidFloorValue`) rather than the TS pattern of overloading the regression errors with a `floor: -1` sentinel for invalid input
- Two independent `JsonSidecarFloorStore` instances (one per floor, via `for_generation`/`for_seq` constructors pointing at two different sidecar filenames) rather than a single two-column store file
- `JsonSidecarFloorStore::put` logs and swallows I/O errors (`log::error!`) instead of returning `Result`, matching the trait's TS-mirrored `Promise<void>` shape — a floor-bump durability failure is distinct from `enforce_resolved`'s already-decided accept/reject outcome

## Deviations from Plan

None — plan executed exactly as written. The atomic-write mechanism in `floor_store.rs` (temp file + rename + fsync) is a slightly stronger guarantee than `crates/sdk/src/queue.rs`'s existing `WriteQueue::put` (which writes-in-place via `create+truncate`, no rename), added because the plan's own acceptance criteria explicitly required `grep -n 'rename|OpenOptionsExt' crates/sdk/src/floor_store.rs` to show a rename-based atomic path — this is a plan-specified requirement, not an unplanned deviation.

## Issues Encountered

- The worktree had no `node_modules` installed, which made the husky pre-commit hook fail (`lint-staged` binary not found) on the first commit attempt. Ran `pnpm install --frozen-lockfile` in the worktree (matches project memory: worktree subagents must `pnpm i`, not rely on a symlinked/inherited `node_modules`), then the commit succeeded on retry with no other changes.
- `#[async_fn_in_trait]` lint fired on the initial `HighWaterStore` trait definition (Rust discourages `async fn` in public traits because the auto-trait/`Send` bound on the generated future can't be specified). Added `#[allow(async_fn_in_trait)]` with a doc comment explaining the trait is only ever used generically (`RotationHighWater<S: HighWaterStore>`), never as `dyn HighWaterStore`, so the missing bound is not a concern in this crate.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `crates/sdk::rotation::RotationHighWater` and `crates/sdk::floor_store::JsonSidecarFloorStore` are ready to be wired into the Rust `list_folder` resolve path (69-06) as the SC#4 durable anti-rollback gate — the FUSE daemon supplies a journal-dir path to `JsonSidecarFloorStore::for_generation`/`for_seq`, constructs a `RotationHighWater` over them, and calls `enforce_resolved` before every unseal.
- No blockers. `cargo test -p cipherbox-sdk` (75 tests) and `cargo check --workspace` both pass cleanly with these additions; `cargo clippy -p cipherbox-sdk --lib` and `cargo fmt -p cipherbox-sdk -- --check` show zero issues in the new files.

---
*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Completed: 2026-07-06*

## Self-Check: PASSED

All created files and commit hashes verified present on disk / in git log.
