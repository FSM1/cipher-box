---
phase: 44-ipns-conflict-handling
plan: "05"
subsystem: web
tags:
  - conflict-handling
  - baseChildren
  - cas-publish
  - web-hooks
  - lost-update-fix
dependency_graph:
  requires:
    - updateFolderMetadataAndPublish baseChildren param (44-02)
    - updateFileMetadata new return shape with internal CAS publish (44-03)
  provides:
    - useFileOperations file-edit path on new updateFileMetadata contract
    - 3 folder re-publish call sites passing pre-mutation baseChildren
    - ConflictError-specific logging in all web hook folder re-publish catches
  affects:
    - apps/web/src/hooks/useFileOperations.ts
    - apps/web/src/hooks/useFileVersions.ts
tech_stack:
  added: []
  patterns:
    - baseChildren: parentFolder.children snapshot before mutation
    - isConflictExhausted-gated logging in fire-and-forget catches
    - updateFileMetadata from @cipherbox/sdk-core (internal CAS publish, Plan 03 contract)
    - maxVersionsPerFile from vault settings store (Phase 39 user-configurable cap)
key_files:
  created: []
  modified:
    - apps/web/src/hooks/useFileOperations.ts
    - apps/web/src/hooks/useFileVersions.ts
decisions:
  - "Switched updateFileMetadata import in useFileOperations from web service layer to @cipherbox/sdk-core to consume the new CAS/internal-publish contract"
  - "Removed redundant replaceFileInFolder call after updateFileMetadata (file IPNS published inside sdk-core now)"
  - "isConflictExhausted used in all 3 folder re-publish catches for conflict-specific logging without changing fire-and-forget behavior"
metrics:
  duration: "~15m"
  completed: "2026-06-13"
  tasks_completed: 2
  files_created: 0
  files_modified: 2
---

# Phase 44 Plan 05: Web Hook Call Sites Caller Adoption Summary

Web hook callers updated for the D-08 baseChildren sweep: 3 folder re-publish sites pass
pre-mutation snapshots enabling three-way merge on 409; useFileOperations file-edit path
switched to sdk-core updateFileMetadata with internal CAS publish and vault maxVersionsPerFile.

## What Was Built

### Task 1: useFileOperations.ts — folder re-publish baseChildren + file CAS rewire (D-08)

`apps/web/src/hooks/useFileOperations.ts` modified:

- Removed `replaceFileInFolder` from `@cipherbox/sdk-core` imports (no longer needed for file edit path)
- Removed `updateFileMetadata` from `../services/file-metadata.service` import (replaced by sdk-core version)
- Added `updateFileMetadata`, `isConflictExhausted` to `@cipherbox/sdk-core` imports
- Added `useVaultSettingsStore` import from `../stores/vault-settings.store`
- **File-edit path (handleUpdateFile):** Updated destructuring from old `{ ipnsRecord, prunedCids }` to `{ prunedCids }` — the new sdk-core `updateFileMetadata` returns `{ ipnsName, metadataCid, newSequenceNumber, prunedCids }` and publishes internally
- Removed the separate `replaceFileInFolder` call (file IPNS record published inside `updateFileMetadata` now — single publish, no double-publish)
- Added `maxVersionsPerFile: useVaultSettingsStore.getState().settings.maxVersionsPerFile` to `updateFileMetadata` call (T-44-19: honors user-configured Phase 39 cap)
- Added `ctx: getSdkClient().getContext()` to `updateFileMetadata` call (required by sdk-core version)
- **Fire-and-forget folder re-publish (line ~461):** Added `baseChildren: parentFolder.children` (pre-mutation children — `updatedChildren` is the post-map set; the original `parentFolder.children` is the correct base for three-way merge on 409)
- `.catch` updated to distinguish `ConflictError` via `isConflictExhausted(err)` (T-44-18) with a specific conflict message; generic warn path preserved for non-conflict errors

### Task 2: useFileVersions.ts — 2 lazy-migration folder re-publishes baseChildren (D-08)

`apps/web/src/hooks/useFileVersions.ts` modified:

- Added `isConflictExhausted` to `@cipherbox/sdk-core` import
- **restoreVersion path (line ~126):** Added `baseChildren: parentFolder.children` to lazy-migration `updateFolderMetadataAndPublish`; `.catch` updated with `isConflictExhausted` gated conflict-specific log
- **deleteVersion path (line ~251):** Added `baseChildren: parentFolder.children` to lazy-migration `updateFolderMetadataAndPublish`; same `.catch` pattern
- Both calls remain fire-and-forget (`.then/.catch`, not awaited in the main path)
- No changes to `crates/` — D-09 deferred Rust parity confirmed

### Acceptance Criteria Verification

- `grep -q "baseChildren: parentFolder.children" apps/web/src/hooks/useFileOperations.ts` — PASS
- updateFileMetadata destructuring no longer references `ipnsRecord` — PASS (remaining `ipnsRecord` refs are from `createFileMetadata` for new-file adds, not file edits)
- `replaceFileInFolder` not called in file-edit path — PASS (call removed, file published inside sdk-core)
- `grep -q "maxVersionsPerFile" apps/web/src/hooks/useFileOperations.ts` — PASS
- `grep -q "isConflictExhausted" apps/web/src/hooks/useFileOperations.ts` — PASS
- `grep -c "baseChildren: parentFolder.children" apps/web/src/hooks/useFileVersions.ts` returns 2 — PASS
- Both useFileVersions calls remain fire-and-forget — PASS
- `git diff --name-only` shows no `crates/` paths — PASS
- `pnpm --filter @cipherbox/web exec tsc --noEmit` — no errors in `useFileOperations.ts` or `useFileVersions.ts` (remaining errors are pre-existing @cipherbox/sdk DTS failure from Plan 04 parallel work and unrelated implicit-any)

## Deviations from Plan

### Import Source Change: updateFileMetadata

The plan stated "rewire to the new Plan 03 updateFileMetadata return shape." The web service layer (`services/file-metadata.service.ts`) has its own `updateFileMetadata` that still returns the old `{ ipnsRecord, prunedCids }` shape (it does not delegate to sdk-core). The plan's intent was to consume the sdk-core CAS contract, which required switching the import from the web service to `@cipherbox/sdk-core` directly.

- **Found during:** Task 1 analysis
- **Fix:** Replaced `updateFileMetadata` import from `../services/file-metadata.service` with `updateFileMetadata` from `@cipherbox/sdk-core`; removed `FileIpnsRecordPayload` type import from service (no longer needed in this hook); removed `replaceFileInFolder` call
- **Files modified:** `apps/web/src/hooks/useFileOperations.ts`
- **Commits:** `c5a0e4be5`

This is a Rule 2 adjustment (critical correctness requirement) — using the web service version would have bypassed the CAS conflict-merge logic entirely.

## Threat Surface Scan

Threat mitigations from plan applied:

| Threat | Status |
| --- | --- |
| T-44-17: web folder re-publish union fallback | Mitigated — 3 call sites pass `baseChildren: parentFolder.children`; 409 path now three-way merges instead of union-fallback |
| T-44-18: ConflictError in web logs | Mitigated — `isConflictExhausted`-gated logging in all 3 catches; no plaintext child data in ConflictError |
| T-44-19: web file edit maxVersionsPerFile bypass | Mitigated — `maxVersionsPerFile: useVaultSettingsStore.getState().settings.maxVersionsPerFile` passed to updateFileMetadata |

No new network endpoints, auth paths, file access patterns, or schema changes introduced.

## Self-Check: PASSED

- `apps/web/src/hooks/useFileOperations.ts` modified, exists on disk
- `apps/web/src/hooks/useFileVersions.ts` modified, exists on disk
- Task 1 commit `c5a0e4be5` verified in git log
- Task 2 commit `ade0c265f` verified in git log
- No errors in `useFileOperations.ts` or `useFileVersions.ts` from `pnpm --filter @cipherbox/web exec tsc --noEmit`
- `grep -c "baseChildren: parentFolder.children"` returns 1 in useFileOperations and 2 in useFileVersions (3 total)
- `grep -q "maxVersionsPerFile"` passes in useFileOperations
- `grep -q "isConflictExhausted"` passes in both files
- No `crates/` paths in git diff
