---
phase: 44-ipns-conflict-handling
plan: "06"
subsystem: sdk-core / sdk / web
tags:
  - ipns
  - conflict-resolution
  - lost-update
  - cr-01
  - folder-children
dependency_graph:
  requires:
    - 44-02
    - 44-04
    - 44-05
  provides:
    - publishedChildren field on updateFolderMetadataAndPublish return
    - CR-01 closed: merged children adopted at all SDK + web store-write sites
  affects:
    - packages/sdk-core/src/folder/index.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/bin/index.ts
    - packages/sdk/src/share/shared-write.ts
    - apps/web/src/hooks/useSharedWriteOps.ts
    - apps/web/src/hooks/useFileOperations.ts
    - apps/web/src/hooks/useFileVersions.ts
tech_stack:
  added: []
  patterns:
    - publishedChildren: FolderChild[] surfaced from updateFolderMetadataAndPublish and adopted at all call sites
key_files:
  created: []
  modified:
    - packages/sdk-core/src/folder/index.ts
    - packages/sdk-core/src/__tests__/folder.test.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/bin/index.ts
    - packages/sdk/src/share/shared-write.ts
    - packages/sdk/src/__tests__/bin.test.ts
    - packages/sdk/src/__tests__/client.test.ts
    - packages/sdk/src/__tests__/client-extended.test.ts
    - packages/sdk/src/__tests__/client-pinning.test.ts
    - packages/sdk/src/__tests__/client-upload-concurrency.test.ts
    - packages/sdk/src/__tests__/upload-batch.test.ts
    - apps/web/src/hooks/useSharedWriteOps.ts
    - apps/web/src/hooks/useFileOperations.ts
    - apps/web/src/hooks/useFileVersions.ts
decisions:
  - "Return currentLocalChildren as publishedChildren — reuses the exact variable that was just encrypted and published, proving the returned set is identical to what was published (no alias)"
  - "Test mocks in sdk test suite updated to include publishedChildren: [] — allows type system to catch any future site that drops the adoption"
  - "useSharedWriteOps adopts publishedChildren into both folderChildrenRef.current and setFolderChildren (8 lines total = 4 handlers x 2) so both the ref (used by withConflictRetry on next retry) and React state converge on the merged set"
metrics:
  duration: "~25 minutes"
  completed: "2026-06-13"
  tasks_completed: 3
  tasks_total: 3
  files_changed: 14
---

# Phase 44 Plan 06: CR-01 publishedChildren adoption Summary

Surface the merged children from `updateFolderMetadataAndPublish` and adopt them at every SDK + web store-write call site, closing the one-write-later lost-update regression identified in the verification gap analysis.

## What Was Done

### Task 1: sdk-core return type + WR-08 folder test

- Widened `updateFolderMetadataAndPublish` return type from `Promise<{ cid; newSequenceNumber }>` to `Promise<{ cid; newSequenceNumber; publishedChildren: FolderChild[] }>`.
- The success return now includes `publishedChildren: currentLocalChildren` — reusing the exact variable that was just published (the merged set after a 409 merge, the input children on a clean first-attempt publish).
- Added a new WR-08 folder conflict test that uses non-empty `baseChildren` to exercise the three-way merge path. Asserts that `result.publishedChildren` contains both the local-only child (`local-2`) and the remote-only child (`remote-3`) after a 409 merge.
- All 15 folder tests pass.

### Task 2: SDK callers adopt and forward publishedChildren

**client.ts (8 sites):**

- `createFolder`: adopts `publishedChildren` for `parent.children` and `folder:updated` event children.
- `renameItem`: adopts `publishedChildren`.
- `moveItem`: uses `destResult.publishedChildren` and `sourceResult.publishedChildren` for dest/source state and both `folder:updated` events.
- `deleteItem`: adopts `publishedChildren`.
- `uploadFile`: destructures `publishedChildren` from `folderResult.value`, adopts for state and `folder:updated` event.
- `addManyFiles`: destructures `publishedChildren` from `folderResult.value`, adopts for state and `folder:updated` event.

**bin/index.ts (2 sites):**

- `addToBin`: adopts `publishedChildren` for `folder.children`.
- `restoreFromBin`: adopts `publishedChildren` for `targetFolder.children`.

**shared-write.ts (4 folder functions):**

- `uploadToSharedFolder`: returns `publishedChildren` alongside `updatedChildren`.
- `createSharedSubfolder`: returns `publishedChildren`.
- `renameInSharedFolder`: returns `publishedChildren`.
- `deleteFromSharedFolder`: returns `publishedChildren`.

All sdk test mocks updated to include `publishedChildren: []` in `mockResolvedValue` return shapes. `pnpm --filter @cipherbox/sdk exec tsc --noEmit` passes.

### Task 3: Web hooks adopt publishedChildren

- `useSharedWriteOps.ts`: All 4 handlers (upload, createFolder, rename, delete) adopt `result.publishedChildren` into both `p.folderChildrenRef.current` and `p.setFolderChildren()` — ensuring the ref used by `withConflictRetry` on the next retry and the React state both converge on the merged set.
- `useFileOperations.ts`: The file-edit fire-and-forget `.then` now destructures `{ newSequenceNumber, publishedChildren }` and calls `updateFolderChildren(parentId, publishedChildren)` alongside `updateFolderSequence`.
- `useFileVersions.ts`: Both lazy-migration fire-and-forget paths (restore + delete) adopt `publishedChildren` via `updateFolderChildren` in their `.then` blocks. `isConflictExhausted` catches preserved unchanged.

`pnpm --filter @cipherbox/web exec tsc --noEmit` passes.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] SDK test mocks missing publishedChildren field**

- **Found during:** Task 2 type-check
- **Issue:** 22 test mock calls to `mockResolvedValue({ cid, newSequenceNumber })` lacked the new required `publishedChildren` field, causing `tsc --noEmit` to fail across 5 test files.
- **Fix:** Added `publishedChildren: []` to all 22 mock return values in `bin.test.ts`, `client.test.ts`, `client-extended.test.ts`, `client-pinning.test.ts`, `client-upload-concurrency.test.ts`, and `upload-batch.test.ts`.
- **Files modified:** 6 test files in `packages/sdk/src/__tests__/`
- **Commit:** `a0ca59fc7`

**2. [Rule 3 - Blocking] Missing package dists required build order**

- **Found during:** Task 1 test run
- **Issue:** `@cipherbox/crypto` and `@cipherbox/core` had no dist built in the worktree; vitest resolved `@cipherbox/crypto` via `node_modules` entry point to the unbuilt package.
- **Fix:** Built `@cipherbox/crypto` then `@cipherbox/core` before running folder tests. Built `@cipherbox/api-client` then `@cipherbox/sdk-core` before Task 2 type-check. Built `@cipherbox/sdk` before Task 3 web type-check.
- **No code changes** — build-environment bootstrapping only.

## Known Stubs

None. All publishedChildren adoptions wire real data from the return value.

## Threat Flags

No new network endpoints, auth paths, or trust boundaries introduced. The changes are purely a return-type widening and downstream adoption.

## Self-Check: PASSED
