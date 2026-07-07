---
phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl
plan: 02
subsystem: rotation-durability
tags: [rust, tokio, floor-store, anti-rollback, concurrency, fail-closed, indexeddb]

# Dependency graph
requires:
  - phase: 69
    provides: RotationHighWater durable anti-rollback floor (generation/seq) on both TS and Rust
provides:
  - Atomic, non-blocking, fail-closed JsonSidecarFloorStore (crates/sdk)
  - Guarded RotationHighWater::bump_floor call sites (Rust)
  - Documented TS/Rust floor-store atomicity parity contract
affects: [70-03, 70-04, 70-05, rotation-durability, fuse-daemon]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "tokio::sync::Mutex + tokio::task::spawn_blocking around a whole load-modify-write critical section, computing max(existing, candidate) inside the lock"
    - "Bounded fail-closed sentinel (i64::MAX as u64, never u64::MAX) for a corrupt-but-present sidecar, avoiding an i64 cast wraparound that would otherwise defeat every regression check"

key-files:
  created: []
  modified:
    - crates/sdk/src/floor_store.rs
    - crates/sdk/src/rotation/high_water.rs
    - packages/sdk/src/state/rotation-high-water.ts

key-decisions:
  - "Corrupt-sidecar fail-closed signal stays within the existing HighWaterStore trait shape (Option<u64> for get, () for put) via a bounded sentinel value, rather than changing the trait to Result — avoids rippling into listing.rs's production gating code and adapter.rs's tests, which are out of this plan's scope"
  - "bump_floor call sites in high_water.rs are additionally guarded by a per-RotationHighWater-instance tokio::sync::Mutex, on top of (not instead of) the store's own authoritative max-preserving atomicity"
  - "TS idbPut was verified already max-preserving inside one IndexedDB transaction; no functional TS change made, only a docstring recording the parity contract"

patterns-established:
  - "Cross-language atomic max-preserving write (SC#5): compute max(existing, candidate) INSIDE the store's own locked/transactional critical section, never trusting an outer orchestration layer's separate read"

requirements-completed: ["SC#5"]

coverage:
  - id: D1
    description: "Concurrent JsonSidecarFloorStore::put on the SAME node_id preserves the monotonic-max floor with no lost updates"
    requirement: "SC#5"
    verification:
      - kind: unit
        ref: "crates/sdk/src/floor_store.rs#concurrent_puts_same_node_id_no_lost_update"
        status: pass
    human_judgment: false
  - id: D2
    description: "Concurrent JsonSidecarFloorStore::put on DIFFERENT node_ids preserves the full node->floor map with no lost updates"
    requirement: "SC#5"
    verification:
      - kind: unit
        ref: "crates/sdk/src/floor_store.rs#concurrent_puts_different_node_ids_no_lost_update"
        status: pass
    human_judgment: false
  - id: D3
    description: "A corrupt/unparseable sidecar fails closed (enforce_resolved rejects) rather than silently resetting to cold-first-contact"
    requirement: "SC#5"
    verification:
      - kind: unit
        ref: "crates/sdk/src/floor_store.rs#corrupt_sidecar_fails_closed"
        status: pass
    human_judgment: false
  - id: D4
    description: "JsonSidecarFloorStore's blocking filesystem I/O runs inside tokio::task::spawn_blocking, holding the tokio::sync::Mutex only around the load-modify-write critical section"
    requirement: "SC#5"
    verification:
      - kind: other
        ref: "static review: grep -n spawn_blocking crates/sdk/src/floor_store.rs (2 call sites, both inside get/put's locked critical section)"
        status: pass
    human_judgment: false
  - id: D5
    description: "TS/Rust floor-store atomicity parity confirmed and documented; no behavioral divergence between the twins"
    requirement: "SC#5"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/rotation-high-water.test.ts (25 tests, unchanged, still green)"
        status: pass
    human_judgment: false

duration: 45min
completed: 2026-07-07
status: complete
---

# Phase 70 Plan 02: Durable Floor Store Concurrency Summary

**Atomic, non-blocking, fail-closed `JsonSidecarFloorStore` (tokio::sync::Mutex + spawn_blocking, max-preserving write, bounded fail-closed sentinel) with a documented already-correct TS twin**

## Performance

- **Duration:** ~45 min
- **Completed:** 2026-07-07
- **Tasks:** 3 (RED, GREEN, TS parity doc)
- **Files modified:** 3

## Accomplishments

- `JsonSidecarFloorStore::get`/`put` now hold a `tokio::sync::Mutex` around the whole load-modify-write critical section, with all blocking filesystem read/write/rename/fsync work moved into `tokio::task::spawn_blocking` so the executor is never blocked while the lock is held.
- `put` computes `max(existing, candidate)` **inside** the locked critical section (re-reading the map fresh under the lock, not trusting a caller's stale outer read) — mirroring the already-correct TS `idbPut` pattern. Concurrent `put`s on the same or different `node_id`s can no longer lost-update each other or the map.
- A present-but-unparseable sidecar now fails closed instead of silently degrading to an empty cold-start map: `get` reports every node under that store as maximally floored (a bounded `i64::MAX`-valued sentinel, deliberately never `u64::MAX` — see Decisions), forcing `enforce_resolved`'s generation/seq comparisons to reject until the sidecar is repaired or removed. `put` refuses to write over a corrupt sidecar rather than silently clobbering other nodes' floors.
- `RotationHighWater`'s `bump_generation`/`bump_seq`/`seed_from_grant`/`enforce_resolved`'s bump step are now guarded by a per-instance `tokio::sync::Mutex`, serializing this orchestration layer's own read-compare-write window against concurrent bumps on the same instance.
- Verified the TS `idbPut` adapter (`apps/web/src/services/rotation-state.service.ts`) was already max-preserving inside a single IndexedDB `readwrite` transaction; documented the TS/Rust behavioral-equivalence contract in `rotation-high-water.ts`'s module docstring, including an explicit note that the cross-store bump sequencing (generation-store then seq-store, sequential awaits) is an accepted doc-only residual, not a fix target.

## Task Commits

1. **Task 1 (RED): Rust concurrency + fail-closed tests** - `ac861e7b2` (test)
2. **Task 2 (GREEN): Atomic, non-blocking, fail-closed store + guarded bump_floor** - `14e5aae07` (feat)
3. **Task 3: TS/Rust parity verification + docstring note** - `62da65d26` (docs)

_TDD-typed plan: RED confirmed 2 of 3 new tests failing against the unfixed store (`corrupt_sidecar_fails_closed`, `concurrent_puts_same_node_id_no_lost_update`); the third concurrency test's flake window is timing-dependent and passed on that particular run, exactly as the plan anticipated ("the concurrency tests may flake/lose-update")._

## Files Created/Modified

- `crates/sdk/src/floor_store.rs` - `tokio::sync::Mutex` + `spawn_blocking` on `get`/`put`; max-preserving write inside the lock; bounded fail-closed sentinel on corrupt-sidecar detection; three new `#[tokio::test]` fns
- `crates/sdk/src/rotation/high_water.rs` - `bump_lock: Arc<Mutex<()>>` field on `RotationHighWater`; guards `bump_generation`, `bump_seq`, `seed_from_grant`, and `enforce_resolved`'s step-4 bump
- `packages/sdk/src/state/rotation-high-water.ts` - module docstring records the TS/Rust atomicity-ownership contract and the doc-only cross-store-sequencing residual (no functional change)

## Decisions Made

- **Fail-closed signal stays within the existing `Option<u64>`/`()` trait shape.** The plan's threat model described the corrupt-sidecar test as asserting `Err`, but `HighWaterStore::get`/`put`'s signatures are consumed directly by `crates/sdk/src/listing.rs` (production gating code, `get_generation_floor` at 3 call sites) and by `adapter.rs`'s tests — both explicitly out of this plan's `files_modified` scope. Changing the trait to `Result`-returning would have forced edits to those files just to keep the crate compiling. Instead, a corrupt-but-present sidecar makes `get` return a bounded sentinel value (`i64::MAX as u64`) for every node under that store. Traced through both real gating call sites (`list_folder`'s self-referential generation check, and `resolve_child`'s parent-mirror-sourced generation check): the sentinel forces `enforce_resolved` to reject via `SequenceRegression` and/or `GenerationRegression` (the existing `RotationError` variants — no new variant needed) in every case that matters for the anti-rollback defense, with zero ripple into `listing.rs`/`adapter.rs`.
- **Why `i64::MAX`, not `u64::MAX`:** `high_water.rs`'s regression checks cast the stored floor `as i64` for comparison against live `i64` input. `u64::MAX as i64` wraps to `-1` in Rust's `as` cast semantics, which would make every `attempted < floor` comparison false — the *opposite* of fail-closed. `i64::MAX` stays positive under that cast and exceeds any legitimate live input, guaranteeing rejection.
- **`put` refuses to write over a corrupt sidecar** rather than treating it as an empty map and overwriting with just the incoming entry — that would silently discard every other node's persisted floor, which is itself a T-70-04-class regression for those other nodes.
- **`bump_floor` in `high_water.rs` is guarded defense-in-depth**, not the sole source of correctness — the store's own internal locked max-preserving write already guarantees the final persisted value is correct under concurrent `bump_floor` interleavings (each `put` independently recomputes `max` under its own lock). The added `bump_lock` additionally keeps `bump_floor`'s *return value* and this orchestration layer's read-then-decide window consistent, per the plan's explicit instruction.
- **No TS functional change.** `idbPut`'s existing read-back-inside-the-same-transaction-then-`Math.max`-then-`put` pattern was verified already correct and is the reference the Rust fix was ported from — only a docstring note was added.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking, scoped] Avoided a HighWaterStore trait signature change that would have broken out-of-scope files**
- **Found during:** Task 2 design (before writing code)
- **Issue:** A literal reading of the plan's threat-model text ("`corrupt_sidecar_fails_closed` asserts `Err`") suggested changing `HighWaterStore::get`/`put` to `Result`-returning. Tracing actual call sites showed this would require editing `crates/sdk/src/listing.rs` (production gating logic, 3 call sites) and `crates/sdk/src/adapter.rs` (existing passing tests asserting `Option<u64>` equality) — both outside `70-02`'s `files_modified`.
- **Fix:** Implemented the fail-closed signal via a bounded in-band sentinel value instead (see Decisions above), satisfying the plan's must-haves ("get / enforce_resolved returns Err (or a documented fail-closed signal)") without touching `listing.rs`/`adapter.rs` at all. Verified by running `listing::` and `adapter::` test modules — all 20 pre-existing tests still pass unmodified.
- **Files modified:** None beyond the plan's three `files_modified` (no incidental changes needed).
- **Verification:** `cargo test -p cipherbox-sdk listing::` (16 passed), `cargo test -p cipherbox-sdk adapter::` (4 passed), both unmodified and green.
- **Committed in:** `14e5aae07` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 scoped design choice, Rule 3)
**Impact on plan:** No scope creep — the alternative design achieves the identical security property (fail-closed on corrupt sidecar) with a strictly smaller blast radius, and every plan acceptance criterion is still met verbatim.

## Issues Encountered

- **Self-inflicted `git stash -u` during TS verification** (before Task 3's commit): ran `git stash -u` to compare tsc output against a clean base, which stashed the uncommitted `rotation-high-water.ts` docstring edit. Immediately caught via the harness's post-stash system reminder and recovered with `git stash pop` before any further work — the edit was restored intact and verified via `git diff --stat` before committing. No data loss; documented here per the destructive-git-operations reporting norm even though this ran on the main working tree, not a worktree.
- **cargo fmt drift:** running `cargo fmt -p cipherbox-sdk` reformatted 5 out-of-scope files (`client.rs`, `registry.rs`, `rotation/engine.rs`, `state.rs`, `sync.rs`) as the plan's critical_constraints anticipated. Reverted via `git checkout --` before every commit; `git diff --stat` confirmed only the 3 plan-scoped files in every commit.
- **Pre-existing, unrelated `@cipherbox/sdk` tsc errors** in `integration.test.ts`, `move-in-shared-folder.test.ts`, `shared-folder-tree.test.ts`, `upload-batch.test.ts` (all last touched in commit `1fb8996a2`, unrelated to this plan) — confirmed zero tsc errors in `rotation-high-water.ts` itself (`grep -i rotation-high-water` on the tsc output: no matches). Matches the known project issue "cross-package dist staleness." Left untouched per SCOPE BOUNDARY (out-of-scope pre-existing failures, not caused by this plan's docstring-only change).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC#5 (durable floor store concurrency/fail-closed) is complete and independently verified on both the Rust and TS sides.
- `crates/sdk/src/listing.rs` and `adapter.rs` are untouched and still pass their full existing test suites — no ripple into other Phase 70 plans' scope.
- Remaining Phase 70 success criteria (SC#1-#4, SC#6 — merge policy, subtree verification, fresh-record resume, grant threading, zeroization) are independent of this plan's changes and unblocked.

## Self-Check: PASSED

All created/modified files and all three task commit hashes verified present on disk / in git log.

---
*Phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl*
*Completed: 2026-07-07*
