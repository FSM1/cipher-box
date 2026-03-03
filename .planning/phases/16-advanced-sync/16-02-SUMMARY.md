---
phase: 16-advanced-sync
plan: 02
subsystem: ui
tags: [ipns, conflict-detection, optimistic-locking, sync, zustand, react-hooks]

# Dependency graph
requires:
  - phase: 16-01
    provides: expectedSequenceNumber in publish DTOs, 409 ConflictException on mismatch
provides:
  - Web client sends expectedSequenceNumber on every folder IPNS publish
  - 409 conflict handling with re-sync + retry in all mutation hooks
  - isConflictError utility for detecting 409 from Orval error shape
  - conflict SyncStatus type with setConflict/clearConflict actions
  - Amber spinning SyncIndicator during conflict re-sync
  - checkAndRotateIfNeeded handles 409 gracefully without crashing
affects: [16-03, 16-04, 16-05]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Re-sync pattern: resolveIpnsRecord -> fetchAndDecryptMetadata -> update store -> retry'
    - 'Stale closure prevention: useFolderStore.getState() in retry path (not closure values)'
    - 'Single retry with 100-500ms random jitter to break symmetry in concurrent conflicts'

key-files:
  created:
    - apps/web/src/lib/errors.ts
  modified:
    - apps/web/src/services/ipns.service.ts
    - apps/web/src/services/folder.service.ts
    - apps/web/src/hooks/useFolderMutations.ts
    - apps/web/src/hooks/useFileOperations.ts
    - apps/web/src/stores/sync.store.ts
    - apps/web/src/components/file-browser/SyncIndicator.tsx
    - apps/web/src/App.css

key-decisions:
  - 'isConflictError checks .status === 409 on thrown Error objects (custom-instance pattern, not response wrapper)'
  - 'getConflictSequenceNumber returns undefined -- custom-instance does not attach response body to thrown Error'
  - 'resyncFolder() shared between useFolderMutations and useFileOperations (not extracted to service -- hooks-level concern)'
  - 'handleUpdateFile has no conflict detection -- publishes only per-file IPNS record, no folder metadata touched'
  - 'handleCreate uses closure folder entry for new folder IPNS (0n sequence, not subject to conflict)'
  - 'buildFolderIpnsRecord return type extended with expectedSequenceNumber: string (not optional) for type safety'

patterns-established:
  - 'Conflict retry: try -> catch isConflictError -> setConflict -> resyncFolder -> jitter -> retry -> clearConflict'
  - 'Re-sync works for root and subfolders identically via resolveIpnsRecord(folderIpnsName)'
  - 'Per-file IPNS publishes: no expectedSequenceNumber (last-write-wins per CONTEXT.md)'
  - 'Folder publishes: expectedSequenceNumber = pre-increment sequenceNumber.toString()'

# Metrics
duration: 12min
completed: 2026-03-03
---

# Phase 16 Plan 02: Web Client Conflict Detection Summary

**Web client sends expectedSequenceNumber on all folder IPNS publishes; 409 conflict triggers re-sync + retry with amber SyncIndicator, covering all mutation and file-upload paths**

## Performance

- **Duration:** 12 min
- **Started:** 2026-03-03T12:05:37Z
- **Completed:** 2026-03-03T12:17:00Z
- **Tasks:** 3
- **Files modified:** 8

## Accomplishments

- Added `isConflictError()` utility matching the Orval custom-instance error shape (`.status === 409` on thrown Error)
- Threaded `expectedSequenceNumber` through the publish chain: `updateFolderMetadata` and `buildFolderIpnsRecord` pass the pre-increment sequence; per-file records do not
- All folder mutation handlers (create, rename, move, moveItems, delete, deleteItems) and file add handlers (addFile, addFiles) catch 409 and re-sync the specific folder before retrying
- `checkAndRotateIfNeeded` catches 409 gracefully during lazy rotation, logs warning, returns new key, defers metadata publish to next sync
- Sync store extended with `'conflict'` status, `conflictMessage`, `setConflict()`, `clearConflict()` -- SyncIndicator shows amber spinning icon during re-sync

## Task Commits

Each task was committed atomically:

1. **Task 1: Conflict error utility** - `c6ce8c510` (feat)
2. **Task 2: Service layer wiring** - `776869d3e` (feat)
3. **Task 3: Hooks, store, and UI** - `373be4e67` (captured in parallel agent commit)

## Files Created/Modified

- `apps/web/src/lib/errors.ts` - `isConflictError()` and `getConflictSequenceNumber()` utilities
- `apps/web/src/services/ipns.service.ts` - `createAndPublishIpnsRecord` and `batchPublishIpnsRecords` accept and forward `expectedSequenceNumber`
- `apps/web/src/services/folder.service.ts` - `updateFolderMetadata` passes pre-increment sequence; `buildFolderIpnsRecord` includes it in folder batch record; `checkAndRotateIfNeeded` handles 409 with graceful log + return
- `apps/web/src/hooks/useFolderMutations.ts` - All mutation handlers with conflict retry; `resyncFolder()` helper for IPNS re-resolution
- `apps/web/src/hooks/useFileOperations.ts` - `addFile`/`addFiles` with conflict retry; `updateFile` unchanged (file-only publish)
- `apps/web/src/stores/sync.store.ts` - `'conflict'` status type, `conflictMessage`, `setConflict()`, `clearConflict()`
- `apps/web/src/components/file-browser/SyncIndicator.tsx` - Amber spinning icon for conflict state
- `apps/web/src/App.css` - `.sync-indicator-icon--conflict` with amber color

## Decisions Made

- **isConflictError shape:** Checks `.status === 409` directly on the thrown Error object. The Orval custom-instance attaches `status` as a property: `(err as Error & { status: number }).status = response.status`. No response wrapper or nested `.response.status` needed.
- **getConflictSequenceNumber returns undefined:** The custom-instance does not parse the 409 response body. Callers re-sync via IPNS resolution (resolveIpnsRecord) rather than using the server's currentSequenceNumber hint.
- **handleUpdateFile skips conflict detection:** File content updates publish only the per-file IPNS record. Folder metadata is untouched, so no 409 is possible from the folder publish path.
- **buildFolderIpnsRecord type:** Return type extended to `FileIpnsRecordPayload & { recordType: 'folder'; expectedSequenceNumber: string }` (required, not optional) for type safety since folder records always have this field.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] buildFolderIpnsRecord return type needed updating**

- **Found during:** Task 2 (service layer wiring)
- **Issue:** TypeScript error TS2353 -- `expectedSequenceNumber` not in `FileIpnsRecordPayload & { recordType: 'folder' }` type
- **Fix:** Extended return type annotation to include `expectedSequenceNumber: string`
- **Files modified:** `apps/web/src/services/folder.service.ts`
- **Verification:** `pnpm --filter web build` passes
- **Committed in:** `776869d3e` (Task 2 commit)

**2. [Rule 1 - Bug] handleMoveItems performBatchMove return type used nullable getter**

- **Found during:** Task 3 (hooks wiring)
- **Issue:** TypeScript error TS2339 -- `ReturnType<typeof getDestFolder>['children']` fails because getDestFolder returns `FolderNode | null`
- **Fix:** Changed return type to use `FolderNode['children']` directly
- **Files modified:** `apps/web/src/hooks/useFolderMutations.ts`
- **Verification:** `pnpm --filter web build` passes
- **Committed in:** `373be4e67` (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (2 Rule 1 - Bug, both TypeScript type annotation issues)
**Impact on plan:** Both fixes were minor type annotation corrections, no behavior change.

## Issues Encountered

- Parallel agent activity on the branch: Task 3 commit (`373be4e67`) was labeled as `docs(16-03)` by the commit hook due to concurrent agent execution. All 8 files were correctly committed; only the commit message scope differs.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Web client conflict detection complete. Plan 16-03 (desktop FUSE) and 16-04 (E2E tests) were completed concurrently by parallel agents.
- All folder publish paths in the web client send `expectedSequenceNumber`
- Per-file IPNS publishes correctly omit `expectedSequenceNumber`
- SyncIndicator shows amber state during conflict re-sync

---

_Phase: 16-advanced-sync_
_Completed: 2026-03-03_
