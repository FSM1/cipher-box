---
phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl
plan: 01
subsystem: sdk-core
tags: [rotation, merge, sealedchildref, tdd, elevation-of-privilege]

# Dependency graph
requires: []
provides:
  - mergeRotatedChildren(base, local, remote) — rotation-only local-wins three-way merge
  - barrel export of mergeRotatedChildren from packages/sdk-core/src/rotation/index.ts
affects: [70-04, 70-05, 70-06, engine.ts rotation call sites, folder/registration.ts]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Rotation-only local-wins merge as a separate function (never a flag on the generic remote-wins mergeChildren) to make the local-wins policy syntactically impossible to invoke from a non-rotation call site"

key-files:
  created:
    - packages/sdk-core/src/rotation/merge.ts
    - packages/sdk-core/src/__tests__/rotation/merge.test.ts
  modified:
    - packages/sdk-core/src/rotation/index.ts

key-decisions:
  - "mergeRotatedChildren is a wholly separate exported function from folder/merge.ts's mergeChildren, not a flag — closes the merge-downgrade Elevation-of-Privilege gap (T-70-01)"
  - "Concurrent-delete-during-rotation resurrection (T-70-02) is an accepted, self-healing residual — documented in a code comment and asserted as KNOWN behavior in the test suite, not fixed"

patterns-established:
  - "Pattern: rotation-only merge policies live in packages/sdk-core/src/rotation/merge.ts as isolated pure functions, re-exported from the rotation barrel; engine.ts itself stays out of any index.ts barrel"

requirements-completed: ["SC#1"]

coverage:
  - id: D1
    description: "mergeRotatedChildren local-wins-on-conflict preserves the rotation's D-02 re-seal so a rotated child survives a merge where remote still holds the old-key seal"
    requirement: "SC#1"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/merge.test.ts#local wins on conflict"
        status: pass
    human_judgment: false
  - id: D2
    description: "remote-only-add-included: a concurrent add present only in remote is picked up under its pre-rotation seal"
    requirement: "SC#1"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/merge.test.ts#remote-only add is included"
        status: pass
    human_judgment: false
  - id: D3
    description: "base-only-omission-dropped: an intentional delete (absent from both local and remote) is honoured, not resurrected"
    requirement: "SC#1"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/merge.test.ts#base-only omission is dropped"
        status: pass
    human_judgment: false
  - id: D4
    description: "Documented residual: concurrent-delete-during-rotation resurrection (T-70-02) is asserted as known, accepted behavior, not fixed"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/merge.test.ts#documented residual"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-07-07
status: complete
---

# Phase 70 Plan 01: Rotation-Only Deep Merge (mergeRotatedChildren) Summary

**Isolated local-wins three-way merge for rotation CAS-409 re-merges, closing the merge-downgrade Elevation-of-Privilege gap (T-70-01) by making local-wins syntactically impossible to invoke from non-rotation call sites**

## Performance

- **Duration:** 12 min
- **Started:** 2026-07-07T19:44:00Z
- **Completed:** 2026-07-07T19:46:35Z
- **Tasks:** 2
- **Files modified:** 3 (2 created, 1 modified)

## Accomplishments
- `mergeRotatedChildren(base, local, remote)` implemented as an isolated pure function in `packages/sdk-core/src/rotation/merge.ts`, distinct from `folder/merge.ts`'s remote-wins `mergeChildren`
- Local-wins conflict policy verified by unit test: a rotated child's new-key seal survives a re-merge against a remote still holding the pre-rotation seal
- Remote-only concurrent adds included; base-only intentional deletes dropped
- Concurrent-delete-during-rotation resurrection (T-70-02) documented as an accepted, self-healing residual — asserted as known behavior in the test suite, not "fixed"
- Re-exported from the rotation barrel (`packages/sdk-core/src/rotation/index.ts`) so `engine.ts` and `registration.ts` can import it in follow-on plans; `engine.ts` itself was NOT added to any barrel

## Task Commits

Each task was committed atomically (TDD RED/GREEN):

1. **Task 1 (RED): Author mergeRotatedChildren unit tests** - `cb9a9907e` (test)
2. **Task 2 (GREEN): Implement mergeRotatedChildren + barrel export** - `e5f5f7c0e` (feat)

## Files Created/Modified
- `packages/sdk-core/src/rotation/merge.ts` - New: `mergeRotatedChildren`, rotation-only local-wins three-way merge
- `packages/sdk-core/src/__tests__/rotation/merge.test.ts` - New: 4-case unit suite (local-wins, remote-add, base-drop, documented residual)
- `packages/sdk-core/src/rotation/index.ts` - Added `export { mergeRotatedChildren } from './merge';`

## Decisions Made
- `mergeRotatedChildren` kept as a wholly separate exported function (not a flag on `mergeChildren`) per the plan's explicit prohibition, preserving `folder/merge.ts`'s remote-wins default unchanged for every non-rotation caller
- The concurrent-delete resurrection residual (T-70-02) was left unresolved by design — commented in `merge.ts`'s local-insert loop and asserted as KNOWN behavior (not a bug) in the test suite, matching the plan's explicit prohibition against solving that edge here

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. `pnpm --filter @cipherbox/sdk-core exec tsc --noEmit` reports 50 pre-existing errors confined entirely to `src/__tests__/share/grant.test.ts` (unrelated to this plan's files); confirmed identical error count before and after this plan's changes via `git stash`/`git stash pop` comparison — out of scope per the deviation rules' scope boundary, not touched.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

`mergeRotatedChildren` is ready to be wired into `engine.ts`'s `mergeConcurrentChildren` (SC#1 site A) and `folder/registration.ts`'s `updateFolderMetadataAndPublish` merge closure (SC#1 site B) in later plans (70-04/70-05/70-06 per the phase pattern map). `folder/merge.ts::mergeChildren` remains completely unchanged (verified via `git diff --stat`).

---
*Phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl*
*Completed: 2026-07-07*

## Self-Check: PASSED

All created/modified files found on disk; all 3 commits (cb9a9907e, e5f5f7c0e, 9e400ad93) verified present in git log.
