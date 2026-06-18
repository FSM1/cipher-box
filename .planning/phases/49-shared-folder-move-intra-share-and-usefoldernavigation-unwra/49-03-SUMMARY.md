---
phase: 49-shared-folder-move-intra-share-and-usefoldernavigation-unwra
plan: "03"
subsystem: ui
tags: [react, shared-folder, move, dialog, a11y, sdk-integration, write-ops]

requires:
  - phase: 49-01
    provides: CipherBoxClient.moveInSharedFolder + enumerateSharedSubtree SDK methods

provides:
  - moveItemHandler in useSharedWriteOps routing through runWrite -> client.moveInSharedFolder
  - SharedFolderClient Pick allowlist with moveInSharedFolder + enumerateSharedSubtree
  - SharedMoveDialog component with DFS shared-subtree picker backed by enumerateSharedSubtree
  - onMove wired into SharedFileBrowser folder-view ContextMenu (write permission only)

affects:
  - 49-04 (batch + drag move extends moveItemHandler and SharedMoveDialog from this plan)

tech-stack:
  added: []
  patterns:
    - "runWrite dispatch pattern for new shared write ops (mirrors deleteItemHandler)"
    - "SharedMoveDialog lazy-loads via useEffect gated on open && shareId"
    - "Folder-view only onMove: list-view synthetic items stay readOnly with no onMove (T-49-09)"
    - "role=button + onKeyDown Enter/Space + :focus-visible for interactive picker rows (a11y)"

key-files:
  created:
    - apps/web/src/components/file-browser/SharedMoveDialog.tsx
  modified:
    - apps/web/src/hooks/shared-folder-projection.ts
    - apps/web/src/hooks/useSharedWriteOps.ts
    - apps/web/src/hooks/useSharedNavigation.ts
    - apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts
    - apps/web/src/components/file-browser/SharedFileBrowser.tsx
    - apps/web/src/styles/dialogs.css

key-decisions:
  - "onMove wired for files only in folder-view ContextMenu; folders excluded (intra-share file move is REQ-3; folder move is out of scope for this plan)"
  - "currentFolderId for SharedMoveDialog derived from breadcrumbs last entry (not a separate state field)"
  - "vi.fn<() => Promise<void>>() used (not the deprecated 2-arg generic) for vitest 3.x compat"
  - "moveItem in useSharedNavigation return type ensures TypeScript enforces the contract end-to-end"

requirements-completed: [REQ-3]

duration: 11min
completed: "2026-06-18"
---

# Phase 49 Plan 03: Shared-folder move web UI Summary

**Single-item intra-share file move UX: moveItemHandler via runWrite->SDK, SharedMoveDialog with enumerateSharedSubtree picker, and onMove wired into SharedFileBrowser folder-view ContextMenu**

## Performance

- **Duration:** ~11 min
- **Started:** 2026-06-18T03:37:20+02:00
- **Completed:** 2026-06-18T03:47:00+02:00
- **Tasks:** 4
- **Files modified:** 7

## Accomplishments

- Added `moveInSharedFolder` and `enumerateSharedSubtree` to the `SharedFolderClient` Pick union in `shared-folder-projection.ts` so projection types accept the new SDK methods
- Added `moveItemHandler` to `useSharedWriteOps` routing through `runWrite` → `client.moveInSharedFolder`; exposed as `moveItem` in `useSharedNavigation` return
- Built `SharedMoveDialog` (220 lines): loads full shared subtree lazily via `enumerateSharedSubtree`, disables read-only and current-folder rows, a11y-compliant picker rows (role=button + onKeyDown + :focus-visible)
- Wired `onMove` on the folder-view ContextMenu in `SharedFileBrowser` (write permission + file item only); list-view synthetic items unchanged (T-49-09)
- Extended `useSharedWriteOps.test.ts` with 3 new `moveItemHandler` cases (routes through runWrite, surfaces errors, guards absent keypair) — scoped run green

## Task Commits

1. **Task 1: Pick allowlist + moveItemHandler** - `eb1c9bb12` (feat)
2. **Task 2: moveItemHandler unit case** - `fd18f1f98` (test) + `7604c36a7` (fix type in same file)
3. **Task 3: SharedMoveDialog** - `7604c36a7` (feat)
4. **Task 4: Wire onMove into SharedFileBrowser** - `48ec008f2` (feat)

## Files Created/Modified

- `apps/web/src/hooks/shared-folder-projection.ts` - Added `moveInSharedFolder` + `enumerateSharedSubtree` to SharedFolderClient Pick
- `apps/web/src/hooks/useSharedWriteOps.ts` - Added `moveItemHandler` via runWrite; exported as `moveItem`
- `apps/web/src/hooks/useSharedNavigation.ts` - Added `moveItem` to `UseSharedNavigationReturn` type
- `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts` - Added vi.mock stubs + 3 moveItemHandler test cases
- `apps/web/src/components/file-browser/SharedMoveDialog.tsx` - NEW: shared subtree picker dialog
- `apps/web/src/components/file-browser/SharedFileBrowser.tsx` - Added onMove to folder-view ContextMenu + mounted SharedMoveDialog
- `apps/web/src/styles/dialogs.css` - Added .shared-move-dialog-folder-item:focus-visible + readonly badge style

## Decisions Made

- `onMove` wired only for `item.type === 'file'` in the folder-view ContextMenu; moving folders is out of scope for REQ-3 (single-item file move)
- `currentFolderId` for `SharedMoveDialog` derived from `breadcrumbs[breadcrumbs.length - 1]?.id ?? currentShareId ?? ''` — breadcrumbs encode the navigation path so no separate state is needed
- `vi.fn<() => Promise<void>>()` (single type arg) used because vitest 3.x deprecated the 2-arg `vi.fn<Args[], Return>()` generic form

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] vi.fn generic corrected for vitest 3.x**

- **Found during:** Task 2 (test authoring) + Task 3 typecheck
- **Issue:** `vi.fn<[string, unknown], Promise<void>>()` is the deprecated 2-arg form rejected by the project's vitest 3.x; TypeScript emitted `Expected 0-1 type arguments, but got 2`
- **Fix:** Changed to `vi.fn<() => Promise<void>>()` (function-signature form) and added `as unknown as [...]` cast on the `mock.calls[0]` assertion
- **Files modified:** `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts`
- **Verification:** `tsc --noEmit` clean; scoped test run green
- **Committed in:** `7604c36a7` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - type error)
**Impact on plan:** Minor type-compatibility fix, no scope change.

## Issues Encountered

None beyond the vitest type deviation above.

## Self-Check

### Created files exist

- [x] `apps/web/src/components/file-browser/SharedMoveDialog.tsx` — 220 lines, exports SharedMoveDialog, no useFolderStore
- [x] `enumerateSharedSubtree` in SharedMoveDialog — grep matches line 72
- [x] `moveInSharedFolder` + `enumerateSharedSubtree` in shared-folder-projection.ts — lines 38-39
- [x] `moveItemHandler` in useSharedWriteOps.ts — line 189
- [x] `onMove` in SharedFileBrowser.tsx folder-view block — line 712
- [x] `SharedMoveDialog` mounted in SharedFileBrowser.tsx — line 723

### Commits exist

- [x] `eb1c9bb12` — feat(49-03): Pick allowlist + moveItemHandler
- [x] `fd18f1f98` — test(49-03): moveItemHandler unit case
- [x] `7604c36a7` — feat(49-03): SharedMoveDialog + test type fix
- [x] `48ec008f2` — feat(49-03): wire onMove into SharedFileBrowser

### Test status

- Scoped run `-- useSharedWriteOps`: 12 tests passed (7 files, 51 tests total)
- TypeScript: `tsc --noEmit` clean

## Self-Check: PASSED

## Known Stubs

None — all handlers fully wired. SharedMoveDialog loads real data from `enumerateSharedSubtree`.

## Threat Flags

No new network endpoints or trust boundaries beyond the plan's threat model. The `enumerateSharedSubtree` call and `moveInSharedFolder` routing were already accounted for in T-49-08 and T-49-09.
