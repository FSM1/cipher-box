---
phase: 79-web-kind-discrimination-completion-and-deferred-test-revival
plan: 05
subsystem: ui
tags: [react, typescript, file-browser, kind-discrimination, shared-content]

# Dependency graph
requires:
  - phase: 79-01
    provides: "ResolvedChild.createdAt mandatory field, added to the SDK-resolved listing model"
provides:
  - "Folders-first sort in SharedFileBrowser.tsx driven by resolved kind (isFileRefResolved)"
  - "resolvedByIpnsName prop threaded into SharedMoveDialog for kind-correct cycle guard"
  - "SharedMoveDialog's movedFolderIds filtered to actual folder-kind items"
affects: [79-06, 79-07, 79-08]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "isFileRefResolved(item, resolvedByIpnsName) as the single canonical kind-discrimination lookup, no local isFolder reimplementation"
    - "SharedFileBrowser has no upload-in-progress virtual rows, so sortItems needs no '_uploading' short-circuit (unlike FileList.tsx)"

key-files:
  created: []
  modified:
    - apps/web/src/components/file-browser/SharedFileBrowser.tsx
    - apps/web/src/components/file-browser/SharedMoveDialog.tsx

key-decisions:
  - "Deleted the stale TODO(phase 63) on the top-level list-view ContextMenu's onDownload without adding a kind gate there: list-view items are raw top-level shares with no resolved-kind data in scope, and handleDownload already navigates to the share uniformly for both file and folder shares -- the marker described existing-correct behavior, not a gap."
  - "Left SharedMoveDialog's single-item title hardcoded to 'Move Folder' -- out of this plan's task scope (not called out in the plan's action/acceptance criteria); flagged as a pre-existing cosmetic gap, not fixed to avoid scope creep."

patterns-established:
  - "resolvedByIpnsName threaded as a new required prop into SharedMoveDialog, fed by SharedFileBrowser's existing resolvedByIpnsName useMemo (both render sites: single-item move and batch move)"

requirements-completed: []

coverage:
  - id: SC1a
    description: "SharedFileBrowser sorts folders first from resolved kind"
    verification:
      - kind: other
        ref: "grep -rn \"phase 63|phase 65\" apps/web/src/components/file-browser/SharedFileBrowser.tsx (zero matches) + tsc -b (no new errors attributable to this file)"
        status: pass
    human_judgment: true
    rationale: "apps/web UI is not unit-tested in this repo (logic lives in packages/sdk, UI covered by web-e2e); folders-first sort is a visual/behavioral outcome best confirmed via manual/Puppeteer verification per the plan's <verification> section."
  - id: SC1b
    description: "SharedMoveDialog's cannot-move-into-own-subtree cycle guard only treats actual folder-kind items as folders"
    verification:
      - kind: other
        ref: "grep -rn \"phase 63|phase 65\" apps/web/src/components/file-browser/SharedMoveDialog.tsx (zero matches) + tsc -b (no new errors attributable to this file)"
        status: pass
    human_judgment: true
    rationale: "Cycle-guard correctness (a file no longer disabling destinations) is only observable via a live move-dialog interaction in the untested UI layer; no automated harness exists for this repo's web app."
  - id: artifact-resolvedByIpnsName-prop
    description: "SharedMoveDialog declares a new resolvedByIpnsName prop, fed from both SharedFileBrowser render sites (~846/861)"
    verification:
      - kind: other
        ref: "grep -n resolvedByIpnsName apps/web/src/components/file-browser/SharedMoveDialog.tsx apps/web/src/components/file-browser/SharedFileBrowser.tsx"
        status: pass
    human_judgment: false

# Metrics
duration: 20min
completed: 2026-07-11
status: complete
---

# Phase 79 Plan 05: Restore Folders-First Sort and Fix SharedMoveDialog Cycle Guard Summary

**Re-enabled folders-first sort in the shared file browser and filtered SharedMoveDialog's cannot-move-into-own-subtree cycle guard to actual folder-kind items, threading a new resolvedByIpnsName prop between the two components.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-07-11T23:40:00Z
- **Completed:** 2026-07-12T00:00:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- `sortItems` in `SharedFileBrowser.tsx` now sorts folders before files, computing kind via `isFileRefResolved(item, resolvedByIpnsName)`, then falling back to `localeCompare` for a stable alphabetical order within each group -- no `'_uploading'` short-circuit needed since this file has no in-progress-upload virtual rows
- The `sortedChildren = sortItems(folderChildren)` call site now passes the file's already-computed `resolvedByIpnsName` map as a second argument
- Both `SharedMoveDialog` render sites (single-item move dialog and batch move dialog) now pass `resolvedByIpnsName` down as a new required prop
- `SharedMoveDialog.tsx` gained the `resolvedByIpnsName: Map<string, ResolvedChild>` prop; `movedFolderIds` now filters the moved items via `!isFileRefResolved(m, resolvedByIpnsName)` before collecting their `ipnsName`s, so a file being moved can no longer disable destinations in the cycle guard
- All `TODO(phase 63)` markers removed from both files (2 in `SharedFileBrowser.tsx`, 2 in `SharedMoveDialog.tsx`)

## Task Commits

Each task was committed atomically:

1. **Task 1: Folders-first sort in SharedFileBrowser + thread resolvedByIpnsName to SharedMoveDialog** - `6d6a80cf7` (feat)
2. **Task 2: Filter SharedMoveDialog's cycle guard to actual folder-kind items** - `a39ab55df` (fix)

_Note: Per worktree instructions for this execution, STATE.md/ROADMAP.md were not touched and no separate plan-metadata commit was made; SUMMARY.md is committed as part of this task's follow-up._

## Files Created/Modified
- `apps/web/src/components/file-browser/SharedFileBrowser.tsx` - folders-first `sortItems` (2-arg signature), passes `resolvedByIpnsName` into both `SharedMoveDialog` render sites, removed stale phase-63 markers
- `apps/web/src/components/file-browser/SharedMoveDialog.tsx` - new `resolvedByIpnsName` prop, `movedFolderIds` filtered to folder-kind items via `isFileRefResolved`, removed stale phase-63 markers

## Decisions Made
- The `ContextMenu`'s top-level list-view `onDownload` TODO was resolved by deletion only, without adding a kind gate: at that render site, `contextMenu.item` is a synthesized `SealedChildRef` built from a raw top-level share (`sharedItems`), and there is no `resolvedByIpnsName` map in scope for top-level shares (that map is built from `resolvedChildren`, which is scoped to the currently-open folder's children). `handleDownload` already routes uniformly for both file and folder shares (navigates to the share via `navigateToShare` in list view), so the comment described intentional existing behavior rather than a gap requiring a fix.
- Left `SharedMoveDialog`'s single-item dialog `title` hardcoded to `'Move Folder'` regardless of the moved item's actual kind. The plan's Task 2 scope was specifically the cycle-guard filter and prop threading, not the title/label text; fixing this cosmetic mismatch was out of scope and risked scope creep beyond the plan's stated `<action>`.

## Deviations from Plan

None - plan executed exactly as written. Both tasks matched the plan's `<action>` and `79-PATTERNS.md` guidance precisely; no Rule 1-4 auto-fixes were needed.

## Issues Encountered

None specific to this plan. Pre-existing `tsc -b` errors in `DetailsDialog.tsx` and three test fixture files (`useSharedWriteOps.test.ts`, `useSyncPolling.test.ts`, `folder.store.test.ts`) surfaced during verification -- these stem from Plan 01's mandatory `ResolvedChild.createdAt` field and are out of this plan's `files_modified` scope (owned by Plans 79-07/79-08 per the worktree execution instructions). Confirmed zero new errors attributable to `SharedFileBrowser.tsx`/`SharedMoveDialog.tsx`.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- SC1 (kind discrimination at the shared listing + move-dialog sites) satisfied for both `SharedFileBrowser.tsx` and `SharedMoveDialog.tsx`.
- Manual/Puppeteer visual verification (shared folder listing groups folders first; move dialog does not disable file-only destinations) is deferred to the phase-level verification gate per the plan's `<verification>` section -- apps/web UI is not unit-tested in this repo.
- No blockers for downstream plans in this phase.

---
*Phase: 79-web-kind-discrimination-completion-and-deferred-test-revival*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: apps/web/src/components/file-browser/SharedFileBrowser.tsx
- FOUND: apps/web/src/components/file-browser/SharedMoveDialog.tsx
- FOUND: .planning/phases/79-web-kind-discrimination-completion-and-deferred-test-revival/79-05-SUMMARY.md
- FOUND commit: 6d6a80cf7
- FOUND commit: a39ab55df
