---
phase: 79-web-kind-discrimination-completion-and-deferred-test-revival
plan: 01
subsystem: api
tags: [sdk, folder-listing, resolvedchild, typescript]

# Dependency graph
requires:
  - phase: 68.2
    provides: "ResolvedChild type and resolveChildren() SDK-owned listing projection"
provides:
  - "ResolvedChild.createdAt: number (mandatory), sourced from Node.createdAt in resolveChildren()"
  - "SDK-layer proof (unit test assertion) that createdAt threads from Node envelope through to the listing projection"
affects: [79-web-kind-discrimination-completion-and-deferred-test-revival]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Mandatory field addition to ResolvedChild mirrors the existing modifiedAt pattern (same unseal, same object literal, no new codec/seal call)"

key-files:
  created: []
  modified:
    - packages/sdk/src/folder-listing.ts
    - packages/sdk/src/__tests__/folder-listing.test.ts

key-decisions:
  - "createdAt added as mandatory (no ?), mirroring modifiedAt, not size's optionality -- per plan's explicit instruction and RESEARCH's SC2 requirement"
  - "SealedChildRef and NodeContent left untouched -- SealedChildRef is frozen (packages/core/src/node/types.ts:76-83), Node.createdAt is already top-level so no new codec/seal work was needed"

patterns-established:
  - "New mandatory ResolvedChild fields ride the same unseal as kind/modifiedAt/size in resolveChildren()'s single push -- no per-field unseal calls"

requirements-completed: []

coverage:
  - id: D1
    description: "ResolvedChild.createdAt is a mandatory field sourced from Node.createdAt, populated in resolveChildren()"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/folder-listing.test.ts#listFolder returns one ResolvedChild per child ... file carries size+modifiedAt, folder has size undefined"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/folder-listing.test.ts#listSharedFolder(shareId, path) returns ResolvedChild[] for an INTERMEDIATE folder, not forced to a file leaf"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/folder-listing.test.ts#emits ResolvedChild[] (kind pre-resolved) on folder:loaded"
        status: pass
    human_judgment: false
  - id: D2
    description: "packages/sdk typechecks and its full vitest suite passes with the new mandatory field"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk typecheck (tsc --noEmit, exit 0)"
        status: pass
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test (411 passed, 3 pre-existing skips, exit 0)"
        status: pass
    human_judgment: false

# Metrics
duration: 8min
completed: 2026-07-11
status: complete
---

# Phase 79 Plan 01: SDK createdAt Foundation Summary

**Added mandatory `ResolvedChild.createdAt: number` sourced from the already-unsealed `Node.createdAt` in `resolveChildren()`, closing the SDK-side gap so `packages/sdk` typechecks and its full 411-test vitest suite passes with the new field wired end-to-end.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-07-11T23:26:33+02:00
- **Completed:** 2026-07-11T23:34:42+02:00
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- `ResolvedChild` type gained a mandatory `createdAt: number` field (immediately after `modifiedAt`), with the module doc comment updated to list it.
- `resolveChildren()`'s result push now assigns `createdAt: node.createdAt` alongside the existing `modifiedAt: node.modifiedAt` -- same already-unsealed `node`, same object literal, zero new codec/seal work.
- `folder-listing.test.ts`'s three `resolveChildren`-output `toEqual` assertions updated to include `createdAt`, plus one explicit assertion (`expect(fileEntry?.createdAt).toBe(now)`) proving the SDK-layer SC2 wiring.
- Confirmed no other test file in the plan's blast radius (`client.test.ts`, `client-shared-write.test.ts`, `folder-reresolve.test.ts`) needed changes -- their `modifiedAt: 0`/`modifiedAt: 1234` literals are `Node` fixture fields (already carrying `createdAt` independently), not `ResolvedChild` object literals.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add mandatory createdAt to ResolvedChild and populate it in resolveChildren()** - `812ea1597` (feat)
2. **Task 2: Fix every packages/sdk ResolvedChild literal and assert createdAt is threaded** - `8a4c2debf` (test)

**Plan metadata:** (see final commit in this response)

## Files Created/Modified
- `packages/sdk/src/folder-listing.ts` - Added `createdAt: number` to `ResolvedChild` type; `resolveChildren()` now assigns `createdAt: node.createdAt`; updated module doc comment.
- `packages/sdk/src/__tests__/folder-listing.test.ts` - Added `createdAt` to three `ResolvedChild`-shaped `toEqual` assertions; added an explicit `createdAt` wiring assertion.

## Decisions Made
- `createdAt` is mandatory (no `?`), matching `modifiedAt`'s mandatory-ness rather than `size`'s optionality -- required by SC2 and the plan's explicit instruction.
- `SealedChildRef` and `NodeContent` were left untouched: `SealedChildRef` is frozen per its doc comment (reverted precedent `ba3e0229a`), and `Node.createdAt` is already a top-level mandatory field, so `NodeContent` needed no change.

## Deviations from Plan

None - plan executed exactly as written. `pnpm --filter @cipherbox/sdk typecheck` did not flag any `ResolvedChild` object literals in `client.test.ts`, `client-shared-write.test.ts`, or `folder-reresolve.test.ts` because none of those files construct `ResolvedChild` literals directly against the typed interface (TypeScript's excess/missing-property check does not apply to `expect().toEqual()`'s generically-inferred argument). The actual gap surfaced at test-runtime instead: three `folder-listing.test.ts` assertions failed with `AssertionError: expected { …(7) } to deeply equal { …(6) }` once `resolveChildren()` started returning the extra field. This is the same blast-radius fix the plan anticipated (Task 2's acceptance criteria: "packages/sdk typechecks ... AND the full vitest suite passes") -- just discovered via `pnpm test` rather than `pnpm typecheck`, which the plan's action step explicitly allowed for ("Re-run typecheck + test until both are green").

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `ResolvedChild.createdAt` is now available for the web layer (`FileDetails.tsx`/`FolderDetails.tsx` Created-date rows and their `toResolvedChildView` fallback-default sites) to consume in later plans of this phase, per `79-PATTERNS.md`.
- No blockers. `packages/sdk` typechecks and its full test suite (411 passed, 3 pre-existing skips) is green.

---
*Phase: 79-web-kind-discrimination-completion-and-deferred-test-revival*
*Completed: 2026-07-11*

## Self-Check: PASSED

All created/modified files and both task commits verified present on disk and in git log.
