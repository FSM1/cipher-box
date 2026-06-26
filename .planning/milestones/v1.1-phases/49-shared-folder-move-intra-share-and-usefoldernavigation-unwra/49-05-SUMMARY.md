---
phase: 49-shared-folder-move-intra-share-and-usefoldernavigation-unwra
plan: "05"
subsystem: testing
tags: [playwright, e2e, shared-folder, move, decrypt-survival, two-account, page-object]

requires:
  - phase: 49-03
    provides: SharedMoveDialog component + onMove wired in SharedFileBrowser folder-view ContextMenu

provides:
  - SharedMoveDialogPage page object (tests/web-e2e/page-objects/file-browser/shared-move-dialog.page.ts)
  - shared-folder-move.spec.ts: two-account Alice/Bob within-share move + decrypt-survival e2e (REQ-5)

affects:
  - main-push web-e2e gate (spec runs on push to main / manual dispatch; requires local docker stack)

tech-stack:
  added: []
  patterns:
    - "readContentViaEditor helper: right-click -> Edit -> waitForContentLoaded -> getContent (decrypt-on-read, not list visibility)"
    - "SharedMoveDialogPage.waitForTreeLoaded() polls loading indicator hidden + listbox visible before folder selection"
    - "alice.page.reload({waitUntil:'networkidle'}) before owner re-reads (cross-client IPNS propagation pattern)"
    - "test.describe.serial with two-account createWalletTestAccount setup (mirrors writable-shares.spec.ts)"

key-files:
  created:
    - tests/web-e2e/page-objects/file-browser/shared-move-dialog.page.ts
    - tests/web-e2e/tests/shared-folder-move.spec.ts

key-decisions:
  - "SharedMoveDialogPage.dialog() scoped via .move-dialog-folder-list filter to avoid collision with private MoveDialog when both could theoretically be mounted"
  - "getFolderItem targets .shared-move-dialog-folder-item (more specific than .move-dialog-folder-item) to match SharedMoveDialog markup exactly"
  - "readContentViaEditor helper dispatches rightClickFolderItem vs rightClickItem based on isinstance check (shared vs private file browser page)"
  - "Alice verifies content via private FileListPage+FileListPage (not SharedFileBrowserPage) — owner reads own files via the vault browser, not the shared view"

requirements-completed: [REQ-5]

duration: ~12min
completed: "2026-06-18"
---

# Phase 49 Plan 05: Shared-folder intra-share move e2e Summary

**Two-account Alice/Bob e2e: Bob moves a file between subfolders of a read-write shared folder via SharedMoveDialog; content decrypts via TextEditorDialogPage.getContent() for both Bob and Alice after IPNS cross-client sync (T-49-14 mitigated)**

## Performance

- **Duration:** ~12 min
- **Started:** 2026-06-18T04:00:00Z
- **Completed:** 2026-06-18T04:12:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Created `SharedMoveDialogPage` page object mirroring `MoveDialogPage` shape: `dialog()` scoped by `.move-dialog-folder-list` filter, `getFolderItem()` targeting `.shared-move-dialog-folder-item` rows (role=button), `waitForTreeLoaded()` guarding subtree enumeration, `move()` helper for the full select+confirm+close flow
- Created `shared-folder-move.spec.ts` as `test.describe.serial` with two-account setup (Alice/Bob via `createWalletTestAccount`/`closeWalletTestAccounts`): Alice creates parent folder + subfolder + text file, shares read-write with Bob; Bob moves file via SharedMoveDialog; spec asserts (1) file disappears from source, (2) file appears in subfolder, (3) `readContentViaEditor` (TextEditorDialogPage.getContent) returns correct content for Bob, (4) `alice.page.reload({waitUntil:'networkidle'})` + Alice navigates subfolder + same decrypt assertion
- TypeScript: `pnpm --filter web-e2e exec tsc --noEmit` clean on both files

## Task Commits

1. **Task 1: SharedMoveDialogPage page object** - `7288eea0f` (test)
2. **Task 2: shared-folder-move.spec.ts** - `c201ec12b` (test)

## Files Created/Modified

- `tests/web-e2e/page-objects/file-browser/shared-move-dialog.page.ts` — NEW: page object for SharedMoveDialog (waitForTreeLoaded, selectFolder, clickMove, move helper)
- `tests/web-e2e/tests/shared-folder-move.spec.ts` — NEW: two-account move + decrypt-survival e2e (test.describe.serial, readContentViaEditor for Bob + Alice)

## Decisions Made

- `SharedMoveDialogPage.dialog()` uses `.move-dialog-folder-list` filter (same approach as `MoveDialogPage`) rather than a unique dialog wrapper selector, since `SharedMoveDialog` renders inside `Modal` without a distinguishing outer class
- `getFolderItem()` targets `.shared-move-dialog-folder-item` (not `.move-dialog-folder-item` alone) to precisely match the additional class that `SharedMoveDialog` adds to its rows
- `readContentViaEditor` dispatches on `instanceof SharedFileBrowserPage` to route `rightClickFolderItem` vs `rightClickItem` — Alice uses the private `FileListPage`, Bob uses `SharedFileBrowserPage`

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## Self-Check

### Created files exist

- [x] `tests/web-e2e/page-objects/file-browser/shared-move-dialog.page.ts` — exports `SharedMoveDialogPage`
- [x] `tests/web-e2e/tests/shared-folder-move.spec.ts` — `test.describe.serial`
- [x] `getContent` appears in shared-folder-move.spec.ts (grep: line 88)
- [x] `networkidle` appears in shared-folder-move.spec.ts (grep: line 300)
- [x] Both files typecheck: `pnpm --filter web-e2e exec tsc --noEmit` clean

### Commits exist

- [x] `7288eea0f` — test(49-05): add SharedMoveDialogPage page object
- [x] `c201ec12b` — test(49-05): shared-folder intra-share move + decrypt-survival e2e

## Self-Check: PASSED

## Known Stubs

None — both files are complete authoring artifacts. The e2e runs live against the docker stack (main-push gated); the spec is not a stub.

## Threat Flags

No new network endpoints or trust boundaries. This plan only adds test files; the T-49-14 mitigation is the implementation in plans 49-01 through 49-03 (SDK reencryptFileMetadataForFolderChange + SharedMoveDialog). This spec verifies that mitigation end-to-end.
