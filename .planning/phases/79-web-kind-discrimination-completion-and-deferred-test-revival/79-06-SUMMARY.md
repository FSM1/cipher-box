---
phase: 79-web-kind-discrimination-completion-and-deferred-test-revival
plan: 06
subsystem: ui
tags: [react, typescript, file-browser, kind-discrimination, dialogs]

# Dependency graph
requires:
  - phase: 79-01
    provides: "ResolvedChild.createdAt mandatory field on the SDK-resolved listing model"
  - phase: 79-02
    provides: "resolvedByIpnsName exposed from useFileBrowserActions + isFileRefResolved kind lookup"
provides:
  - "FileBrowser threads the real resolved kind into RenameDialog/ConfirmDialog/ShareDialog/MoveDialog"
  - "ShareDialog kind prop gating the folder trailing-slash display suffix"
  - "MoveDialog resolvedByIpnsName prop; cycle guard filtered to actual folder-kind items"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "isFileRefResolved(item, resolvedByIpnsName) as the single canonical kind lookup at every private-browser dialog site (no local isFolder reimplementation)"
    - "Coupled prop-wiring committed atomically so required-prop cross-references typecheck as a unit"

key-files:
  created: []
  modified:
    - apps/web/src/components/file-browser/FileBrowser.tsx
    - apps/web/src/components/file-browser/ShareDialog.tsx
    - apps/web/src/components/file-browser/MoveDialog.tsx

key-decisions:
  - "ShareDialog line-548 upgrade/downgrade marker deleted as stray (not backed by kind logic): the upgrade/downgrade controls are read-vs-write PERMISSION UI, shown for both files and folders, unrelated to item kind. Replaced with a clarifying comment; no kind-conditional logic added."
  - "MoveDialog single-item title left kind-neutral ('Move Item') and the stale marker comment removed: the plan scoped Task 3 to the cycle-guard filter + prop threading, and 'Move Item' is correct for both files and folders (matches the 79-05 precedent that left SharedMoveDialog's title out of scope). No scope creep into per-kind title text."

patterns-established:
  - "resolvedByIpnsName threaded as a new required prop into MoveDialog (both single + batch render sites), fed from useFileBrowserActions' existing resolvedByIpnsName map"
  - "kind threaded as a new required prop into ShareDialog, computed once in FileBrowser via isFileRefResolved"

requirements-completed: []

coverage:
  - id: SC1-rename-delete-share-kind
    description: "rename/delete/share dialogs label the real kind, not a hardcoded folder"
    verification:
      - kind: other
        ref: "grep -rn \"phase 63|phase 65\" on FileBrowser.tsx/ShareDialog.tsx/MoveDialog.tsx returns zero; tsc -b shows no new errors for these files"
        status: pass
    human_judgment: true
    rationale: "apps/web UI is not unit-tested in this repo (logic lives in packages/sdk, UI covered by web-e2e); the visible label/title correctness is a phase-gate manual/Puppeteer check."
  - id: SC1-sharedialog-slash-suffix
    description: "ShareDialog trailing-slash suffix appears only for actual folders"
    verification:
      - kind: other
        ref: "itemDisplayName = kind === 'folder' ? `${item.name}/` : item.name"
        status: pass
    human_judgment: false
  - id: SC1-movedialog-cycle-guard
    description: "MoveDialog cycle guard only treats actual folder-kind items as folders"
    verification:
      - kind: other
        ref: "folderItemIds = items.filter((i) => !isFileRefResolved(i, resolvedByIpnsName)).map(...)"
        status: pass
    human_judgment: false

# Metrics
duration: 12min
completed: 2026-07-12
status: complete
---

# Phase 79 Plan 06: Kind-Aware Private-Browser Dialogs Summary

**FileBrowser now resolves each dialog subject's real file-vs-folder kind via `isFileRefResolved` and threads it into RenameDialog, ConfirmDialog, ShareDialog, and both MoveDialog renders, removing all hardcoded folder labels and every `TODO(phase 63)` marker in the three files.**

## Performance

- **Duration:** 12 min
- **Tasks:** 3 (committed as one atomic commit — coupled required props)
- **Files modified:** 3

## Accomplishments

- FileBrowser computes `renameItemType`, `deleteIsFolder`, and `shareKind` once from `actions.resolvedByIpnsName` via `isFileRefResolved`; a still-loading miss stays folder-safe.
- RenameDialog `itemType` and ConfirmDialog `title` now branch on the real kind ("Rename File"/"Rename Folder", "Delete File?"/"Delete Folder?"); the delete message drops the "files and subfolders inside" clause for files.
- ShareDialog gained a required `kind: 'file' | 'folder'` prop; `itemDisplayName` appends the trailing `/` only for folders.
- MoveDialog gained a required `resolvedByIpnsName: Map<string, ResolvedChild>` prop; `buildFolderList` filters the moved items to folder-kind items (`!isFileRefResolved`) before building the `folderItemIds` cycle-guard set, so a file being moved can no longer disable destinations.
- All 7 `TODO(phase 63)` markers removed (3 in FileBrowser, 2 in ShareDialog, 2 in MoveDialog).

## Task Commits

Committed as one atomic commit because FileBrowser passes the new **required** `kind`/`resolvedByIpnsName` props to ShareDialog/MoveDialog — splitting per task would leave an intermediate commit that fails typecheck (missing required prop / undeclared prop).

1. **Tasks 1-3 (atomic):** `d31f87b51` (feat)

_Per this worktree's execution convention, STATE.md/ROADMAP.md are updated in a batched wave-tracking commit; SUMMARY.md is committed separately._

## Files Created/Modified

- `apps/web/src/components/file-browser/FileBrowser.tsx` — kind computations + kind-aware Rename/Confirm/Share/Move wiring, markers removed
- `apps/web/src/components/file-browser/ShareDialog.tsx` — new `kind` prop, folder-only slash suffix, stray permission-UI marker removed
- `apps/web/src/components/file-browser/MoveDialog.tsx` — new `resolvedByIpnsName` prop, folder-kind-filtered cycle guard, markers removed

## Decisions Made

- ShareDialog's line-548 marker was a stray comment conflating read-vs-write permission UI with file-vs-folder kind. Upgrade/downgrade controls apply to both files and folders, so the comment was deleted (replaced with a clarifying note) and no kind gate was added.
- MoveDialog's single-item title stays kind-neutral ("Move Item"); only the stale marker comment was removed. Per-kind title text was out of the plan's Task 3 scope (cycle guard + prop), consistent with 79-05's handling of SharedMoveDialog.

## Deviations from Plan

- Task granularity: the three tasks were committed as a single atomic commit rather than three, because the plan's `<objective>` requires the prop wiring to "typecheck as a unit" — the new props are required and cross-referenced. No content deviation.

## Issues Encountered

- The 4 pre-existing `tsc -b` errors (DetailsDialog.tsx + three ResolvedChild test fixtures) from Plan 01's mandatory `createdAt` remain; they are owned by Plans 79-07/79-08. Confirmed zero new errors attributable to the three files this plan touched.

## User Setup Required

None.

## Next Phase Readiness

- SC1 satisfied for all private-browser dialogs.
- Manual/Puppeteer visual verification (kind-correct titles/messages/suffixes, file-safe move guard) is deferred to the phase-level gate — apps/web UI is not unit-tested in this repo.

---
*Phase: 79-web-kind-discrimination-completion-and-deferred-test-revival*
*Completed: 2026-07-12*

## Self-Check: PASSED

- FOUND: apps/web/src/components/file-browser/FileBrowser.tsx
- FOUND: apps/web/src/components/file-browser/ShareDialog.tsx
- FOUND: apps/web/src/components/file-browser/MoveDialog.tsx
- FOUND: .planning/phases/79-web-kind-discrimination-completion-and-deferred-test-revival/79-06-SUMMARY.md
- FOUND commit: d31f87b51
