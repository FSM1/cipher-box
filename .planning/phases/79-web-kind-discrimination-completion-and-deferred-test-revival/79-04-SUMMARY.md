---
phase: 79-web-kind-discrimination-completion-and-deferred-test-revival
plan: 04
subsystem: ui
tags: [react, typescript, drag-and-drop, file-browser, kind-discrimination]

# Dependency graph
requires:
  - phase: 79-01
    provides: "ResolvedChild.createdAt mandatory field, added to the SDK-resolved listing model"
provides:
  - "Folders-first sort in FileList.tsx driven by resolved kind (isFileRefResolved)"
  - "Folder-only drop targets (onDrop/onExternalFileDrop) re-enabled per row"
  - "Kind-aware multi-select drag payload in FileListItem.tsx"
  - "createdAt: 0 sentinel added to FileList's synthetic ResolvedChild fallback"
affects: [79-05, 79-06, 79-07, 79-08]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "isFileRefResolved(item, resolvedByIpnsName) as the single canonical kind-discrimination lookup, no local isFolder reimplementation"
    - "'_uploading' in item short-circuit BEFORE isFileRefResolved lookup for UploadVirtualEntry rows (empty ipnsName would otherwise map-miss to folder-safe default)"

key-files:
  created: []
  modified:
    - apps/web/src/components/file-browser/FileList.tsx
    - apps/web/src/components/file-browser/FileListItem.tsx

key-decisions:
  - "Followed 79-PATTERNS.md verbatim for sortItems/onDrop/onExternalFileDrop shapes; no deviation needed"
  - "Single-item drag branch reuses the already-computed isFolder value (from `resolved`) rather than re-deriving via resolvedByIpnsName, since it's the same information for that row"

patterns-established:
  - "resolvedByIpnsName threaded as a new prop into FileListItem, mirroring the SharedFileBrowser/SharedFolderRow precedent (resolved + resolvedByIpnsName passed together)"

requirements-completed: []

coverage:
  - id: D1
    description: "FileList sorts folders before files using resolved kind, with in-progress uploads always treated as files"
    verification:
      - kind: other
        ref: "grep -rn \"phase 63|phase 65\" apps/web/src/components/file-browser/FileList.tsx (zero matches) + tsc -b (no new errors in FileList.tsx)"
        status: pass
    human_judgment: true
    rationale: "apps/web UI is not unit-tested in this repo (logic lives in packages/sdk, UI covered by web-e2e); folders-first sort and drop-target rendering are visual/behavioral outcomes best confirmed via manual/Puppeteer verification per the plan's <verification> section."
  - id: D2
    description: "Only folder rows accept onDrop/onExternalFileDrop; file rows get undefined handlers"
    verification:
      - kind: other
        ref: "grep -rn \"phase 63|phase 65\" apps/web/src/components/file-browser/FileList.tsx (zero matches) + tsc -b (no new errors)"
        status: pass
    human_judgment: true
    rationale: "Same as D1 -- drop-target gating is a runtime/visual behavior in an untested UI layer; requires manual/Puppeteer confirmation per plan verification section."
  - id: D3
    description: "FileListItem multi-select drag payload uses the real per-item kind via isFileRefResolved instead of a hardcoded 'folder' stub"
    verification:
      - kind: other
        ref: "grep -rn \"phase 63|phase 65\" apps/web/src/components/file-browser/FileListItem.tsx (zero matches) + tsc -b (no new errors)"
        status: pass
    human_judgment: true
    rationale: "Drag payload correctness is only observable via a live drag interaction in the untested UI layer; no automated harness exists for this repo's web app."
  - id: D4
    description: "toResolvedChildView synthetic fallback carries createdAt so FileList typechecks under the mandatory ResolvedChild.createdAt field"
    verification:
      - kind: other
        ref: "tsc -b: zero errors attributable to FileList.tsx (createdAt: 0 added next to modifiedAt: 0)"
        status: pass
    human_judgment: false

# Metrics
duration: 25min
completed: 2026-07-11
status: complete
---

# Phase 79 Plan 04: Restore Folders-First Sort and Drag-Drop in FileList Summary

**Re-enabled folders-first sort and folder-only drag-drop in the private file browser, and threaded the real per-item kind into FileListItem's multi-select drag payload -- both disabled since the Phase-62 SealedChildRef cutover.**

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-11T21:52:00Z
- **Completed:** 2026-07-11T22:17:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- `sortItems` in `FileList.tsx` now sorts folders before files, computing kind via `isFileRefResolved(item, resolvedByIpnsName)`, with an explicit `'_uploading' in item` short-circuit so in-progress `UploadVirtualEntry` rows (empty `ipnsName`) are never mis-sorted as folders by the map-miss default
- `onDrop`/`onExternalFileDrop` re-enabled per row in `FileList.tsx`, gated on `isFileRefResolved` so only folder rows accept a drop (files get `undefined` handlers, matching the existing `FileListItem` drag-over/drop guard on `isFolder`)
- `toResolvedChildView`'s synthetic `ResolvedChild` fallback now includes `createdAt: 0` alongside the existing `modifiedAt: 0` sentinel, satisfying the mandatory field added in Plan 01
- `FileListItem.tsx` gained a `resolvedByIpnsName: Map<string, ResolvedChild>` prop; the multi-select drag branch now computes each dragged item's real kind via `isFileRefResolved(i, resolvedByIpnsName)` instead of hardcoding `'folder'`
- All `TODO(phase 63)` markers removed from both files (5 in FileListItem.tsx, 4 in FileList.tsx)

## Task Commits

Each task was committed atomically:

1. **Task 1: Restore folders-first sort + drag-drop + createdAt fallback in FileList.tsx** - `9371bdc` (feat)
2. **Task 2: Kind-aware multi-select drag payload in FileListItem.tsx** - `77cf724` (feat)

_Note: Per worktree instructions for this execution, STATE.md/ROADMAP.md were not touched and no separate plan-metadata commit was made; SUMMARY.md is committed as part of this task's follow-up._

## Files Created/Modified
- `apps/web/src/components/file-browser/FileList.tsx` - folders-first `sortItems`, re-enabled `onDrop`/`onExternalFileDrop`, `createdAt: 0` sentinel, passes `resolvedByIpnsName` to `FileListItem`
- `apps/web/src/components/file-browser/FileListItem.tsx` - new `resolvedByIpnsName` prop, multi-select drag payload now derives real per-item kind

## Decisions Made
- Followed `79-PATTERNS.md`'s exact comparator/handler shapes for `sortItems` and `onDrop`/`onExternalFileDrop` -- no deviation from the researched pattern was needed.
- In `FileListItem`'s single-item drag branch, reused the row's already-computed `isFolder` (derived from `resolved`, this row's own `ResolvedChild`) rather than re-deriving it through `resolvedByIpnsName` -- same value, avoids a redundant map lookup for the common (non-multi-select) case.

## Deviations from Plan

None - plan executed exactly as written. Both tasks matched the plan's `<action>` and `79-PATTERNS.md` guidance precisely; no Rule 1-4 auto-fixes were needed.

## Issues Encountered

None. Pre-existing `tsc -b` errors in `DetailsDialog.tsx` and three test files (`useSharedWriteOps.test.ts`, `useSyncPolling.test.ts`, `folder.store.test.ts`) surfaced during verification -- these stem from Plan 01's mandatory `ResolvedChild.createdAt` field and are out of this plan's `files_modified` scope (owned by Plans 79-07/79-08 per grep against all phase-79 plan files). Confirmed zero new errors attributable to `FileList.tsx`/`FileListItem.tsx`.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- SC1 (kind discrimination at listing/drag sites) and SC2 (fallback consistency) both satisfied for `FileList.tsx`/`FileListItem.tsx`.
- Manual/Puppeteer visual verification (folders render before files; only folder rows show a drop affordance) is deferred to the phase-level verification gate per the plan's `<verification>` section -- apps/web UI is not unit-tested in this repo.
- No blockers for downstream plans in this phase.

---
*Phase: 79-web-kind-discrimination-completion-and-deferred-test-revival*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: apps/web/src/components/file-browser/FileList.tsx
- FOUND: apps/web/src/components/file-browser/FileListItem.tsx
- FOUND: .planning/phases/79-web-kind-discrimination-completion-and-deferred-test-revival/79-04-SUMMARY.md
- FOUND commit: 9371bdc
- FOUND commit: 77cf724
