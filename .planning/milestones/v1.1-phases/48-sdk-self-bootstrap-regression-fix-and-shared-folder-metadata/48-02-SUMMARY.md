---
phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
plan: "02"
subsystem: web
tags: [web, sdk, cleanup, folder-state, refactor]
dependency_graph:
  requires: ["48-01"]
  provides: ["REQ-2"]
  affects: ["apps/web/src/hooks", "apps/web/src/lib/sdk-provider.ts"]
tech_stack:
  added: []
  patterns: ["SDK self-bootstrap via requireFolder chokepoint replaces web-side folder pre-seeding"]
key_files:
  created: []
  modified:
    - apps/web/src/lib/sdk-provider.ts
    - apps/web/src/hooks/useFolderMutations.ts
    - apps/web/src/hooks/useFileOperations.ts
    - apps/web/src/hooks/useFileVersions.ts
    - apps/web/src/hooks/useDropUpload.ts
decisions:
  - "useFolderNavigation.ts required no change: the key-unwrap there (folderKey/ipnsPrivateKey) serves the display metadata-load path (fetchAndDecryptMetadata + Zustand store population), not SDK seeding. No ensureFolderRegistered call was present in the current file."
  - "The in-loop re-registration in handleDeleteItems (freshParent = getParentFolder; if freshParent ensureFolderRegistered) was removed along with the comment noting it; the SDK client handles sequence state internally between sequential deletes."
metrics:
  duration: "2 minutes"
  completed: "2026-06-16"
  tasks_completed: 2
  tasks_total: 3
  files_modified: 5
---

# Phase 48 Plan 02: Remove Web Folder-Seeding (REQ-2) Summary

One-liner: Deleted `ensureFolderRegistered` definition and all 14 call sites; web hooks now rely solely on the SDK `requireFolder` self-bootstrap chokepoint (PR #498).

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | Delete ensureFolderRegistered call sites + definition | df1223bf3 | sdk-provider.ts, useFolderMutations.ts, useFileOperations.ts, useFileVersions.ts, useDropUpload.ts |
| 2 | Remove duplicate web-side key-unwrap pre-seed in useFolderNavigation | df1223bf3 (no-op — see deviation) | useFolderNavigation.ts (unchanged) |

## Task 3: UAT Pending

Cold-reload UAT (Task 3 checkpoint) is pending orchestrator web-e2e re-dispatch. The automated verify (typecheck + lint) is green; runtime verification requires a live stack.

## What Changed

### sdk-provider.ts

- Removed `ensureFolderRegistered` function (38 lines) and its doc comment
- Removed `import type { FolderNode } from '../stores/folder.store'` (now unused)
- `getSdkClient`, `hasSdkClient`, `initSdkClient`, `destroySdkClient`, `reconfigurePinning` are unchanged

### useFolderMutations.ts

Removed 10 `ensureFolderRegistered` calls and the symbol from the import:

- `handleCreate`: removed "Ensure parent is registered in SDK's FolderTree" block
- `handleRename`: removed "Ensure parent is registered in SDK" block
- `handleMove`: removed "Ensure both folders are registered in SDK" block (2 calls)
- `handleMoveItems`: removed "Ensure both folders are registered in SDK" block (2 calls)
- `handleDelete`: removed "Ensure parent is registered in SDK" block
- `handleDeleteItems`: removed initial "Ensure parent is registered in SDK" block + in-loop re-registration (`freshParent` fetch + `ensureFolderRegistered(freshParent)`)

### useFileOperations.ts

Removed 1 call (`ensureFolderRegistered(parentFolder)` + its 4-line comment block) and updated import.

### useFileVersions.ts

Removed 2 calls (one in `handleRestoreVersion`, one in `handleDeleteVersion`) each with their 4-line comment blocks. Updated import.

### useDropUpload.ts

Removed 1 call (`ensureFolderRegistered(parentFolder)`) and updated import. Updated comment from "Resolve parent folder and ensure it's registered in the SDK" to "Resolve parent folder".

## Deviations from Plan

### Task 2: useFolderNavigation.ts — no change required

The plan described removing a "duplicate web-side key-unwrap pre-seed block at useFolderNavigation.ts:233-240 that existed to register the folder into the SDK folderTree." Reading the current file (modified by commit f6b13db2b for the latestPathname route-guard), the unwrap of `folderKey` and `ipnsPrivateKey` at the corresponding location serves exclusively the IPNS metadata-load path (`fetchAndDecryptMetadata` + Zustand `setFolder` for display). There is no call to `ensureFolderRegistered` or `client.registerFolder` anywhere in `useFolderNavigation.ts`. The "pre-seed" described in the plan was either already removed in a prior commit or was confused with another file. No change was needed; Task 2 was a no-op.

## Risk Assessment

The removed seeders covered every folder mutation entry point. The SDK `requireFolder` chokepoint (PR #498 `ensureFolderLoaded`/`requireFolder`) now must self-bootstrap for all cold-reload scenarios. The sequence-guard fix from REQ-1 (Plan 48-01) prevents `loadFolder` from overwriting fresher in-memory state with a stale IPNS snapshot, which was the original regression risk. The UAT checkpoint (Task 3) must verify each former seed site works cold:

- Upload (useDropUpload)
- File replace (useFileOperations)
- Version restore/delete (useFileVersions)
- Folder create/rename/move/delete/batch-delete (useFolderMutations)

## Stubs

None — this is a pure deletion plan with no new symbols or placeholder paths.

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes introduced. The deletion eliminates a potential desync surface (web-side `registerFolder` could diverge from SDK's internal sequence), reducing the threat surface. T-48-04 (DoS via "Folder not loaded" gap) and T-48-05 (key exposure via redundant in-memory unwrap+seed) are both closed by this plan.

## Self-Check

### Files present:
- apps/web/src/lib/sdk-provider.ts — FOUND (ensureFolderRegistered removed)
- apps/web/src/hooks/useFolderMutations.ts — FOUND
- apps/web/src/hooks/useFileOperations.ts — FOUND
- apps/web/src/hooks/useFileVersions.ts — FOUND
- apps/web/src/hooks/useDropUpload.ts — FOUND

### Zero ensureFolderRegistered references: PASSED (grep returns empty)

### Commit present: df1223bf3 — PASSED

### Typecheck: PASSED (tsc --noEmit clean)

### Lint: PASSED (eslint clean)

## Self-Check: PASSED
