---
phase: 49-shared-folder-move-intra-share-and-usefoldernavigation-unwra
plan: "04"
subsystem: ui
tags: [react, shared-folder, batch-move, drag-and-drop, multi-select, selection, a11y]

requires:
  - phase: 49-03
    provides: moveItemHandler + SharedMoveDialog + onMove baseline

provides:
  - batchMoveItemsHandler in useSharedWriteOps (loop over moveInSharedFolder per item)
  - Multi-select state in SharedFileBrowser (selectedIds, selectedItems, multiSelectActive, clearSelection)
  - SelectionActionBar wired in folder view for write shares
  - SharedMoveDialog items prop (batch mode: title/label auto-adapt)
  - Drag-and-drop move onto SharedFolderRow (handleDragStart/handleDrop, application/json payload)
  - handleDropOnFolder-equivalent routing in SharedFileBrowser (single->moveItem, multi->batchMoveItems)

affects:
  - REQ-6 (batch + drag move parity with private vault)

tech-stack:
  added: []
  patterns:
    - "batchMoveItemsHandler: runWrite shell wrapping per-item moveInSharedFolder loop (mirrors useFolderMutations.handleMoveItems)"
    - "Multi-select: Set<string> selectedIds + useMemo selectedItems + clearSelection (mirrors useFileBrowserActions :218-235)"
    - "SharedMoveDialog item|items prop shape (mirrors private MoveDialog :20-21)"
    - "SharedFolderRow drag source: multi-select-aware application/json {items,parentId} payload (mirrors FileListItem :160-177)"
    - "SharedFolderRow drop target: folder-only, internal vs external distinguished by dataTransfer.types.includes('application/json') (mirrors FileListItem :275-317)"

key-files:
  created: []
  modified:
    - apps/web/src/hooks/useSharedWriteOps.ts
    - apps/web/src/hooks/useSharedNavigation.ts
    - apps/web/src/components/file-browser/SharedFileBrowser.tsx
    - apps/web/src/components/file-browser/SharedMoveDialog.tsx
    - apps/web/src/components/file-browser/SharedFolderRow.tsx

key-decisions:
  - "batchMoveItemsHandler clearSelection called AFTER runWrite completes (not inside the loop) so selection only clears on full success"
  - "SharedFolderRow handleDrop ignores payload parentId for write guard — drop target row's id/ipnsName is authoritative (T-49-12)"
  - "External file upload drop (container-level handleDrop) preserved; SharedFolderRow does not intercept it (jsonData absence falls through)"
  - "onMoveItemTo callback pattern keeps SharedFolderRow decoupled from move handler identity"
  - "SelectionActionBar onDelete/onDownload are no-ops stubs; only onMove is wired (batch delete/download scope is REQ-6 move parity only)"

requirements-completed: [REQ-6]

duration: ~26min
completed: "2026-06-18"
---

# Phase 49 Plan 04: Batch + drag move parity for shared folder view Summary

**Multi-select selection state + batch move loop + SharedMoveDialog items prop + drag-and-drop onto SharedFolderRow — all mirroring private vault analogs without new SDK ops**

## Performance

- **Duration:** ~26 min
- **Started:** 2026-06-18T01:37:00Z
- **Completed:** 2026-06-18T02:03:38Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- Added `batchMoveItemsHandler` to `useSharedWriteOps`: loops `client.moveInSharedFolder` per item inside a single `runWrite`, stops on first failure with `p.setError`, calls `clearSelection` on full success — mirrors `useFolderMutations.handleMoveItems` exactly
- Added `batchMoveItems` to `UseSharedNavigationReturn` type and exposed via `...writeOps` spread
- Added multi-select selection state to `SharedFileBrowser`: `selectedIds: Set<string>`, `selectedItems` (useMemo filter), `multiSelectActive`, `clearSelection`, `handleSelect` (Ctrl/Cmd+click), `handleBatchMoveClick`; prune-on-navigate effect and clear-on-share-change effect
- Wired `SelectionActionBar` into folder view (write shares only, `multiSelectActive` guard)
- Extended `SharedMoveDialog` with optional `items?: FolderChild[]` prop; `isBatchMode` flag auto-adapts title ("Move N items") and label (mirrors private `MoveDialog :174-179`)
- Mounted batch-mode `SharedMoveDialog` in `SharedFileBrowser` opened from `handleBatchMoveClick`, routing `onConfirm` to `batchMoveItems`
- Rewrote `SharedFolderRow` with drag source (`handleDragStart`: multi-select-aware `application/json {items,parentId}` payload), drop target (`handleDrop`: folder-only, internal vs external distinguished by payload presence, routes via `onMoveItemTo` callback), `handleDragOver`/`handleDragLeave` visual affordance, and `onSelect` click handler for Ctrl/Cmd+click selection
- `SharedFileBrowser` passes `onMoveItemTo` to each row, routing single item to `moveItem` and multi-selection to `batchMoveItems`

## Task Commits

1. **Task 1: Multi-select + SelectionActionBar + batchMoveItemsHandler** - `63afb91a1`
2. **Task 2: SharedMoveDialog items prop + batch confirm routing** - `01881d50e`
3. **Task 3: Drag-and-drop onto SharedFolderRow** - `706d4f3a5`

## Files Modified

- `apps/web/src/hooks/useSharedWriteOps.ts` — Added `batchMoveItemsHandler`; exported as `batchMoveItems`
- `apps/web/src/hooks/useSharedNavigation.ts` — Added `batchMoveItems` to `UseSharedNavigationReturn` type
- `apps/web/src/components/file-browser/SharedFileBrowser.tsx` — Multi-select state, SelectionActionBar wiring, batch move dialog, onMoveItemTo routing
- `apps/web/src/components/file-browser/SharedMoveDialog.tsx` — Optional `items` prop, `isBatchMode`, auto-adapted title/label
- `apps/web/src/components/file-browser/SharedFolderRow.tsx` — handleDragStart/handleDrop/handleDragOver/handleDragLeave, onSelect, isSelected, onMoveItemTo

## Decisions Made

- `batchMoveItemsHandler` calls `clearSelection` after `runWrite` completes (post-loop), not inside the loop — selection clears on full success only
- `handleDrop` in `SharedFolderRow` uses the drop target row's `id`/`ipnsName` (not the payload's `parentId`) as the authoritative destination, per T-49-12
- External file upload drop path (container `handleDrop`) preserved: `SharedFolderRow` returns early when `jsonData` is absent, letting the container `handleDrop` handle `files`
- `SelectionActionBar` `onDelete`/`onDownload` are no-op stubs (`() => {}`); only `onMove` is wired — batch delete/download are not part of REQ-6

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written.

## Issues Encountered

None.

## Self-Check

### Created files exist

- [x] `batchMoveItemsHandler` in `useSharedWriteOps.ts` — line 216; loops `moveInSharedFolder`
- [x] `selectedIds` in `SharedFileBrowser.tsx` — line 143
- [x] `multiSelectActive` in `SharedFileBrowser.tsx` — line 149
- [x] `clearSelection` in `SharedFileBrowser.tsx` — line 151
- [x] `SelectionActionBar` wired in `SharedFileBrowser.tsx` — line 642
- [x] `items` prop in `SharedMoveDialog.tsx` — line 26
- [x] `isBatchMode` + title/label branch — lines 55, 139, 144
- [x] `handleDrop` in `SharedFolderRow.tsx` — line 116
- [x] `handleDragStart` in `SharedFolderRow.tsx` — line 70
- [x] `application/json` in `SharedFolderRow.tsx` — line 83

### Commits exist

- [x] `63afb91a1` — feat(49-04): multi-select state + SelectionActionBar + batchMoveItemsHandler
- [x] `01881d50e` — feat(49-04): SharedMoveDialog accepts items prop + batch confirm routing
- [x] `706d4f3a5` — feat(49-04): add drag-and-drop move onto SharedFolderRow

### Test status

- 7 test files, 51 tests passed
- TypeScript: `tsc -b` clean

## Self-Check: PASSED

## Known Stubs

- `SelectionActionBar` `onDelete` and `onDownload` callbacks in `SharedFileBrowser` are `() => {}` no-ops — batch delete and batch download for the shared view are not part of REQ-6 (batch + drag MOVE parity). These are intentional stubs; future plans can wire them by following the same pattern.

## Threat Flags

No new network endpoints or trust boundaries beyond the plan's threat model (T-49-11, T-49-12, T-49-13 all mitigated in implementation).
