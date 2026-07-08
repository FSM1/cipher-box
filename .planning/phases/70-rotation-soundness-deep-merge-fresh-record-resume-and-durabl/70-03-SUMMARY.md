---
phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl
plan: 03
subsystem: ui
tags: [indexeddb, rotation, badge, web-e2e, playwright]

# Dependency graph
requires:
  - phase: 68-rotation-web-glue-and-durability
    provides: rotation-driver.service.ts's persistJob/progress badge wiring and durable IndexedDB job checkpoint
provides:
  - "Per-root Set<string> badge tracking in rotation-driver.service.ts (activeRootNodeIds) replacing the single-root scalar"
  - "Cached shared IndexedDB connection promise for the rotation job-checkpoint store (openJobDB), invalidated on onversionchange/close"
  - "web-e2e coverage proving the concurrent-root badge lifecycle (badge resets only after both roots finish)"
affects: [70-web-glue-verification, future rotation badge/UX work]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Per-root Set<string> tracking for badge-lifecycle state instead of a single-root scalar"
    - "Module-level cached Promise<IDBDatabase> with onversionchange/onclose invalidation, mirroring rotation-state.service.ts's openRotationDB idiom"

key-files:
  created: []
  modified:
    - apps/web/src/services/rotation-driver.service.ts
    - tests/web-e2e/tests/rotation-ux.spec.ts

key-decisions:
  - "progress('rotated'/'complete') cannot delete a specific root from activeRootNodeIds (the callback carries no rootNodeId) — it only resets the badge if the set is ALREADY empty, deferring to persistJob's terminal branch as the authoritative per-root drain"
  - "Exposed closeJobDB() for future logout wiring but did NOT wire it into lib/clear-user-stores.ts — that file is outside this plan's files_modified scope"

patterns-established:
  - "Badge-lifecycle Set tracking: add on first non-terminal persistJob per root, delete on terminal persistJob, reset badge only when the set drains to empty"

requirements-completed: ["SC#6"]

coverage:
  - id: D1
    description: "activeRootNodeIds Set replaces the single-root scalar; badge resets only when the set drains"
    requirement: "SC#6"
    verification:
      - kind: automated_ui
        ref: "tests/web-e2e/tests/rotation-ux.spec.ts#badge stays active across two concurrent-root rotations and only resets once BOTH finish (SC#6)"
        status: unknown
      - kind: other
        ref: "cd apps/web && pnpm exec tsc --noEmit -p tsconfig.json"
        status: pass
    human_judgment: true
    rationale: "The new Playwright case was authored and statically typechecked but NOT executed (full web-e2e run requires the docker stack, out of scope per executor constraints) — verification status is unknown until the stack-gated wave/phase run exercises it."
  - id: D2
    description: "Job-checkpoint IndexedDB connection is a cached shared open-promise instead of a fresh connection per checkpoint call"
    requirement: "SC#6"
    verification:
      - kind: other
        ref: "cd apps/web && pnpm exec tsc --noEmit -p tsconfig.json"
        status: pass
    human_judgment: true
    rationale: "Connection caching/invalidation behavior (onversionchange/onclose) has no unit-test coverage per apps/web's no-unit-test doctrine (SC#5) and is not directly exercised by the new e2e case beyond indirect use via persistJob; a human/stack-gated run is the only practical verification of real browser IndexedDB connection lifecycle."

# Metrics
duration: ~20min
completed: 2026-07-07
status: complete
---

# Phase 70 Plan 03: Rotation Badge Per-Root Set + Cached IDB Connection Summary

**Replaced rotation-driver.service.ts's single-root badge scalar with a per-root `Set<string>` and cached the job-checkpoint IndexedDB connection, fixing badge misclassification and a per-call connection leak under concurrent rotations.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-07T20:11:29Z
- **Tasks:** 2/2 completed
- **Files modified:** 2

## Accomplishments
- `activeRootNodeIds: Set<string>` replaces the module-global `activeRootNodeId: string | null` in `rotation-driver.service.ts` — `persistJob` adds a root on its first non-terminal checkpoint and deletes it on the terminal (complete/failed) checkpoint; the badge resets only when the set drains to empty, so a finishing root no longer clobbers another root's still-in-flight badge.
- `resumeInterruptedRotation` now seeds ALL in-progress checkpoint roots into the set (previously only the first).
- `progress('rotated'/'complete')` — which carries no `rootNodeId` — now only resets the badge when the set is already empty, deferring per-root drain authority to `persistJob`.
- `openJobDB()` now returns a cached, shared `Promise<IDBDatabase>` instead of opening a fresh connection on every `persistJob`/`deleteJobCheckpoint`/`getAllJobCheckpoints` call; the cache is invalidated on `onversionchange` and `onclose` so a stale/closed connection is never reused. A `closeJobDB()` export is available for future logout wiring.
- `tests/web-e2e/tests/rotation-ux.spec.ts` extended with a new case driving the real `persistJob` callback (via `buildRotationClientCallbacks()`) for two distinct root node ids overlapping in time, asserting the badge stays visible until BOTH roots reach a terminal status.

## Task Commits

1. **Task 1: activeRootNodeId -> Set + cached IDB connection** - `a1b63bf3c` (fix)
2. **Task 2: Extend rotation-ux web-e2e for 2 concurrent roots** - `9347ed9f2` (test)

**Plan metadata:** (this commit)

## Files Created/Modified
- `apps/web/src/services/rotation-driver.service.ts` - Set-based per-root badge tracking (`activeRootNodeIds`), cached `openJobDB()` connection promise with `onversionchange`/`onclose` invalidation, new `closeJobDB()` export
- `tests/web-e2e/tests/rotation-ux.spec.ts` - new 2-concurrent-root badge-lifecycle Playwright case

## Decisions Made
- `progress()`'s terminal branch cannot surgically remove a single root from the Set (no `rootNodeId` parameter on that callback) — it defers to `persistJob`'s terminal branch as the sole authority for draining the set, only resetting the badge itself when the set is already empty. This preserves the SC#6 invariant through both signal paths without changing the `RotationClientCallbacks` type.
- `closeJobDB()` is exported but intentionally NOT wired into `apps/web/src/lib/clear-user-stores.ts`'s logout flow in this plan — that file is outside 70-03's `files_modified` scope; wiring it is a small follow-up for a future plan/todo if desired.

## Deviations from Plan

None - plan executed exactly as written. Both fixes (Set-based tracking, cached IDB connection) and the extended e2e case match the plan's `<action>` and `<acceptance_criteria>` exactly.

## Issues Encountered
- The plan's Task 2 read_first pointed at `rotation-state.service.ts`'s `openRotationDB` as the "already-correct" connection-caching reference, but on inspection that function does NOT cache its connection (each `idbGet`/`idbPut` calls it fresh) — only its `idbPut`'s single-atomic-transaction max-preserving write is the correct, reusable idiom (documented separately in 70-PATTERNS.md's Shared Patterns section for the Rust port). The actual cached-connection-promise implementation in `rotation-driver.service.ts` was built fresh, following the plan's acceptance criteria directly rather than copying non-existent caching code from the referenced file.
- Existing tests in `rotation-ux.spec.ts` use a two-step `const modPath = '...'; await import(modPath)` idiom rather than an inline string literal in `import(...)` specifically to avoid TypeScript's static module resolution (a literal string argument to `import()` triggers `tsc` to try to resolve the module path and fails with TS2307, since these paths are Vite-dev-server-relative, not real filesystem module specifiers from the Playwright project's perspective). The new test initially used the inline-literal form and failed `tsc --noEmit`; fixed to match the established two-step pattern.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- SC#6's web-glue defects (badge misclassification under concurrent rotations, per-call IDB connection leak) are closed.
- The new `badge stays active across two concurrent-root rotations` Playwright case is authored and statically typechecked but has NOT been executed — the full `pnpm --filter web test:e2e -- rotation-ux` run (with the standard docker stack up) is deferred to the stack-gated wave/phase verification, per this plan's explicit scope constraint.
- `closeJobDB()` is available but unwired; a future todo could wire it into `clear-user-stores.ts`'s logout flow for symmetry with the `onversionchange`/`onclose` invalidation already in place.

---
*Phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl*
*Completed: 2026-07-07*

## Self-Check: PASSED

- FOUND: apps/web/src/services/rotation-driver.service.ts
- FOUND: tests/web-e2e/tests/rotation-ux.spec.ts
- FOUND: .planning/phases/70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl/70-03-SUMMARY.md
- FOUND commit: a1b63bf3c
- FOUND commit: 9347ed9f2
