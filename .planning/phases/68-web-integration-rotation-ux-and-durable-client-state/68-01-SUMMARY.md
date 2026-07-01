---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 01
subsystem: sdk
tags: [vitest, tdd, rotation, ipns, anti-rollback, high-water]

# Dependency graph
requires: []
provides:
  - "createRotationHighWater — durable monotonic-max generation + seq floors over an injected HighWaterStore seam"
  - "enforceResolved — fail-closed pre-unseal regression gate with cold-device versionFloor"
  - "GenerationRegressionError / SequenceRegressionError distinguishable error classes"
affects: [68-06, 68-09, 68-10]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Injected HighWaterStore seam (get/put) with no in-instance cache — every read/write goes through the store so a fresh instance over the same backing store observes prior state"
    - "Monotonic-max floor: read-then-compare-then-conditional-put, never writes a lower value"
    - "V5 fail-closed validation: non-negative-safe-integer guard treats malformed stored values as absent, never coerced to a low floor"

key-files:
  created:
    - packages/sdk/src/state/rotation-high-water.ts
    - packages/sdk/src/__tests__/rotation-high-water.test.ts
  modified:
    - packages/sdk/src/index.ts

key-decisions:
  - "Split the single PLAN.md test file into two TDD cycles matching the two tasks: Task 1 committed only the state-machine tests/impl (monotonic-max, seed, validation, restart-persistence); Task 2 appended the enforceResolved tests/impl (regression gate, cold-device versionFloor) in a second RED->GREEN pair, keeping each test/feat commit pair scoped to its task."
  - "enforceResolved checks generation regression before seq regression so a cross-generation rollback is always reported as GenerationRegressionError even when the seq also happens to be lower."

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "createRotationHighWater exposes monotonic-max generation + seq floors over an injected HighWaterStore; a lower candidate never lowers a stored floor"
    requirement: ROT-07
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/rotation-high-water.test.ts#createRotationHighWater — generation floor (monotonic-max)"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/rotation-high-water.test.ts#createRotationHighWater — seq floor (monotonic-max)"
        status: pass
    human_judgment: false
  - id: D2
    description: "A fresh state-machine instance over the SAME backing store observes a previously-written floor and rejects a downgrade (restart/persistence semantics at the logic tier)"
    requirement: ROT-07
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/rotation-high-water.test.ts#createRotationHighWater — restart/persistence (SC#1 logic tier)"
        status: pass
    human_judgment: false
  - id: D3
    description: "enforceResolved throws a distinguishable GenerationRegressionError / SequenceRegressionError on any regression and bumps monotonic-max otherwise (fail-closed, never silent)"
    requirement: ROT-07
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/rotation-high-water.test.ts#enforceResolved — fail-closed regression gate (SC#4 / D-05 / §7.3 test 13/14)"
        status: pass
    human_judgment: false
  - id: D4
    description: "First-contact (no local high-water yet) with a seq below the owner-vouched versionFloor is rejected (§7.3 test 14 cold-device)"
    requirement: ROT-07
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/rotation-high-water.test.ts#enforceResolved — §7.3 test 14 cold-device"
        status: pass
    human_judgment: false
  - id: D5
    description: "A malformed / negative / non-numeric stored value is treated as absent (V5 fail-closed), never coerced to a low floor"
    requirement: ROT-07
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/rotation-high-water.test.ts#createRotationHighWater — malformed stored value treated as absent (V5 fail-closed)"
        status: pass
    human_judgment: false

# Metrics
duration: 25min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 01: Durable Rotation High-Water State Machine Summary

**Injected-store monotonic-max generation/seq floors plus a fail-closed enforceResolved regression gate, hoisted into `@cipherbox/sdk` and unit-tested with Vitest (20 tests, no browser).**

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-01T16:06:00Z
- **Completed:** 2026-07-01T16:31:32Z
- **Tasks:** 2
- **Files modified:** 3 (2 created, 1 modified)

## Accomplishments

- `createRotationHighWater(generationStore, seqStore)` durable monotonic-max state machine over an injected `HighWaterStore` seam (`get`/`put`), with no in-instance cache — a fresh instance over the same backing store observes prior floors (restart/persistence proven at the logic tier).
- `seedFromGrant` owner-vouched first-contact seed that only raises the generation floor, never lowers it.
- `enforceResolved` fail-closed pre-unseal gate: throws `GenerationRegressionError` on cross-generation rollback, `SequenceRegressionError` on within-generation seq rollback or cold-device `versionFloor` violation, and bumps both floors monotonic-max on a healthy resolve. It is a pure pass/throw decision — never returns or computes an AAD/unseal parameter (Pitfall 5).
- V5 fail-closed validation: negative, fractional, `NaN`, or non-numeric stored values are treated as absent, never coerced to a low floor.
- Module exported from the `@cipherbox/sdk` barrel (`createRotationHighWater`, `HighWaterStore`, `RotationHighWater`, `EnforceResolvedParams`, `GenerationRegressionError`, `SequenceRegressionError`) for the web IndexedDB adapter (68-06) to consume.

## Task Commits

Each task was executed as an explicit RED -> GREEN TDD cycle with a dedicated commit per phase:

1. **Task 1: state machine (monotonic-max, seed, validation, restart-persistence)**
   - `1bc1db80e` (test) — RED: failing tests for the state machine, confirmed failing on `Cannot find module` before implementation existed
   - `10c38eafb` (feat) — GREEN: `createRotationHighWater` implementation, 14/14 targeted tests passing
2. **Task 2: enforceResolved fail-closed gate + barrel export**
   - `f81a6d64e` (test) — RED: failing tests for `enforceResolved`/error classes, confirmed 6 new tests failing (`enforceResolved is not a function`, `is not a constructor`) while the 14 prior tests still passed
   - `34dad965a` (feat) — GREEN: `enforceResolved`, `GenerationRegressionError`, `SequenceRegressionError`, and the barrel export; 20/20 targeted tests passing, full `@cipherbox/sdk` suite green (230 passed / 49 skipped, no regressions)

_Note: this is a `type: tdd` plan — both tasks followed RED (test commit) -> GREEN (feat commit); no refactor commit was needed._

## Files Created/Modified

- `packages/sdk/src/state/rotation-high-water.ts` - `HighWaterStore` interface, `createRotationHighWater`, `enforceResolved`, `GenerationRegressionError`, `SequenceRegressionError`
- `packages/sdk/src/__tests__/rotation-high-water.test.ts` - 20 Vitest cases across monotonic-max, seed, restart-persistence, V5 validation, and the fail-closed regression gate
- `packages/sdk/src/index.ts` - barrel export of the new module's public surface

## Decisions Made

- Split the plan's single described test file into two TDD cycles matching the two tasks (state machine, then `enforceResolved`), so each `test(...)`/`feat(...)` commit pair stays scoped to its task rather than bundling both tasks' tests into one RED commit.
- `enforceResolved` checks the generation floor before the seq floor, so a resolve that regresses on both dimensions is reported as `GenerationRegressionError` (the higher-severity M1 cross-generation defense) rather than being masked by the seq check.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

`pnpm --filter @cipherbox/sdk build` initially failed with `Cannot find module '@cipherbox/api-client'` etc. — this is the known cross-package dist staleness issue (dependency packages had no `dist/` in this fresh worktree, unrelated to this plan's changes). Resolved by building `@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/api-client`, and `@cipherbox/sdk-core` in dependency order before building `@cipherbox/sdk`; no source changes were needed.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `createRotationHighWater` and `enforceResolved` are exported from `@cipherbox/sdk` and ready for 68-06 to supply the concrete IndexedDB-backed `HighWaterStore` and wire `enforceResolved` into `resolveIpnsRecord`.
- The distinguishable `GenerationRegressionError` / `SequenceRegressionError` classes are ready for 68-09's toast layer to pattern-match on.
- No blockers. This plan touches only `packages/sdk`; `apps/web` has zero new test files (`find apps/web/src -name "*.spec.ts"` stays empty), consistent with the phase's SDK-tier test-strategy doctrine.

---
*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Completed: 2026-07-01*
