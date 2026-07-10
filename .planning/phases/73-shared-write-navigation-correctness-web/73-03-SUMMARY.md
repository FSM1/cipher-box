---
phase: 73-shared-write-navigation-correctness-web
plan: 03
subsystem: ui
tags: [react, drag-and-drop, shared-folders, file-browser]

requires:
  - phase: 68-shared-listing-resolution
    provides: isFileRefResolved / resolvedByIpnsName pattern (68.2-15) already established in SharedFileBrowser
provides:
  - Correctly-kinded shared drag payloads (SharedFolderRow.handleDragStart classifies via the resolved listing, not a bare-ref isFileRef call)
affects: [shared-folder-drag-drop, file-browser]

tech-stack:
  added: []
  patterns:
    - "isFileRefResolved(ref, resolvedByIpnsName) replaces isFileRef(bareRef) at any call site that only holds a SealedChildRef but has access to the paired resolved-listing map"

key-files:
  created: []
  modified:
    - apps/web/src/components/file-browser/SharedFolderRow.tsx
    - apps/web/src/components/file-browser/SharedFileBrowser.tsx

key-decisions:
  - "Threaded resolvedByIpnsName as a new required prop on SharedFolderRow rather than making it optional, since SharedFileBrowser already computes and has it available at the single call site."

patterns-established: []

requirements-completed: [SC5]

coverage:
  - id: D1
    description: "SharedFolderRow's drag-payload kind is derived from the resolved listing via isFileRefResolved, not isFileRef on a bare SealedChildRef"
    requirement: SC5
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/web exec tsc -b (typecheck passes with the new resolvedByIpnsName prop threaded through)"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-10
status: complete
---

# Phase 73 Plan 03: Shared drag-payload kind classification fix Summary

**Fixed `SharedFolderRow.tsx#handleDragStart` to classify drag-payload `type` from the SDK-resolved listing (`isFileRefResolved`) instead of calling `isFileRef` on a bare `SealedChildRef`, which has been unconditionally `false` since the 68.2-11 kind-cache removal — every dragged shared item was previously mistyped `'folder'`.**

## Performance

- **Duration:** 15 min
- **Started:** 2026-07-10T19:04:00Z
- **Completed:** 2026-07-10T19:19:37Z
- **Tasks:** 1 completed
- **Files modified:** 2

## Accomplishments

- `SharedFolderRowProps` now declares a required `resolvedByIpnsName: Map<string, ResolvedChild>` prop.
- `handleDragStart`'s two drag-payload `type` computations (multi-select branch and single-item branch) now call `isFileRefResolved(ref, resolvedByIpnsName)` instead of `isFileRef(ref)` on the bare `SealedChildRef`.
- `resolvedByIpnsName` added to the `handleDragStart` `useCallback` dependency array.
- `SharedFileBrowser.tsx` threads its already-computed `resolvedByIpnsName` map into the `<SharedFolderRow>` call site (the same map already used for the `resolved=` prop and the existing `isFileRefResolved` calls at the double-click and download-menu sites).
- Line-81 `isFolder` display logic (`!isFileRef(resolved ?? item)`) left byte-unchanged, as scoped — it already reads from `ResolvedChild.kind` when available and is out of scope for this fix.

## Task Commits

Each task was committed atomically:

1. **Task 1: Thread resolvedByIpnsName into SharedFolderRow and use isFileRefResolved in the drag handler** - `8a1218735` (fix)

**Plan metadata:** committed together with this SUMMARY (see final commit below).

## Files Created/Modified

- `apps/web/src/components/file-browser/SharedFolderRow.tsx` - Added `resolvedByIpnsName` prop; `handleDragStart` now classifies drag-payload kind via `isFileRefResolved` against the resolved listing instead of `isFileRef` on a bare ref.
- `apps/web/src/components/file-browser/SharedFileBrowser.tsx` - Passes `resolvedByIpnsName={resolvedByIpnsName}` at the `<SharedFolderRow>` call site.

## Decisions Made

- `resolvedByIpnsName` was added as a required (non-optional) prop rather than optional with a default empty map, since the single call site (`SharedFileBrowser.tsx`) always has the map computed and available — matching the plan's "purely additive prop-threading" framing without introducing a silent-fallback code path that could mask a future missed call site.

## Deviations from Plan

None - plan executed exactly as written. `isFileRef` import was kept (still used at line 89 for the `isFolder` display logic, out of scope per the plan's scope guard).

## Issues Encountered

None. `pnpm install` plus the root `pnpm typecheck` build-ordered chain (crypto -> core -> api-client -> sdk-core -> sdk) were run first since this was a fresh worktree checkout with no `node_modules`/`dist`, then `pnpm --filter @cipherbox/web exec tsc -b` was run per the plan's verification command and passed with no errors. Prettier required reformatting the two multi-line ternaries in `SharedFolderRow.tsx` (lines now wrapped across 3 lines each per the project's print width) — applied via `pnpm exec prettier --write` before commit; the pre-commit lint-staged hook also ran `eslint --fix` + `prettier --write` on the staged files with no additional changes needed.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

SC5 is fully satisfied. No blockers for other phase-73 plans; this plan had `depends_on: []` and no dependents were noted in the phase's wave plan.

---

*Phase: 73-shared-write-navigation-correctness-web*
*Completed: 2026-07-10*
