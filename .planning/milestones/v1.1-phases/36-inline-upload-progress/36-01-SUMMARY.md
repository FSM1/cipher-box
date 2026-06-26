---
phase: 36-inline-upload-progress
plan: 01
subsystem: ui
tags: [zustand, react, upload, per-file-state, cancel-token]

# Dependency graph
requires: []
provides:
  - 'Per-file upload state management with PerFileUpload type and Map-based tracking'
  - 'Per-file actions: addFile, updateFileProgress, setFileStatus, setFileComplete, removeFile, cancelFile, retryFile'
  - 'Independent cancel tokens per file upload'
  - 'useDropUpload and upload.service using per-file store actions'
  - 'useFileUpload hook deriving batch-level fields from per-file Map'
affects: [36-02-PLAN]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Map-based per-entity state in Zustand store (new Map() spread for immutable updates)'
    - 'Per-file CancelToken.source() for independent cancellation'
    - 'Batch-level derivation from per-entity Map (useFileUpload backward compat)'

key-files:
  created: []
  modified:
    - apps/web/src/stores/upload.store.ts
    - apps/web/src/hooks/useDropUpload.ts
    - apps/web/src/services/upload.service.ts
    - apps/web/src/hooks/useFileUpload.ts
    - apps/web/src/stores/__tests__/upload-error-recovery.test.ts

key-decisions:
  - 'Per-file Map with new Map() spread for Zustand immutable re-render triggers'
  - 'cancelFile sets status to cancelled but does NOT remove from Map (UI layer controls removal timing)'
  - 'setFileComplete sets status and progress=100 but does NOT remove (UI controls completion animation timing)'
  - 'retryFile resets to encrypting with fresh CancelToken (UI triggers actual re-upload)'
  - 'useFileUpload derives batch-level fields from Map for backward compat (no active consumers but compiles cleanly)'

patterns-established:
  - 'Per-file upload state: Map<string, PerFileUpload> with unique ID format upload-{filename}-{timestamp}'
  - 'Always use getState() for store reads inside async upload callbacks (stale closure prevention)'

requirements-completed: []

# Metrics
duration: 2min
completed: 2026-03-30
---

# Phase 36 Plan 01: Upload Store Per-File Tracking Summary

**Refactored upload Zustand store from batch-level to per-file Map tracking with independent cancel tokens, progress, and error state per file**

## Performance

- **Duration:** 2 min (verification of pre-committed work)
- **Started:** 2026-03-30T02:19:07Z
- **Completed:** 2026-03-30T02:21:27Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Replaced batch-level upload state (status, progress, currentFile, totalFiles, completedFiles) with per-file `Map<string, PerFileUpload>` tracking
- Each upload file gets unique ID, independent CancelToken, independent progress/status/error tracking
- Updated all upload consumers (useDropUpload, upload.service, useFileUpload) to use per-file store actions
- Rewritten error recovery tests pass with new per-file API (12 tests passing)
- PendingReplacements workflow preserved unchanged

## Task Commits

Each task was committed atomically:

1. **Task 1: Refactor upload store to per-file tracking and rewrite error recovery tests** - `78b1394` (feat)
2. **Task 2: Update upload loop in useDropUpload, upload.service, and useFileUpload** - `aea4b24` (feat)
3. **Style fix: Prettier formatting** - `e9bac40` (style)

## Files Created/Modified

- `apps/web/src/stores/upload.store.ts` - Per-file upload state management with PerFileUpload type, Map-based tracking, and all per-file actions
- `apps/web/src/hooks/useDropUpload.ts` - Upload loop using per-file addFile/updateFileProgress/setFileComplete with independent cancel tokens
- `apps/web/src/services/upload.service.ts` - Upload service using per-file store actions
- `apps/web/src/hooks/useFileUpload.ts` - Hook derives batch-level fields from per-file Map for backward compatibility
- `apps/web/src/stores/__tests__/upload-error-recovery.test.ts` - Error recovery and pending replacements tests rewritten for per-file API

## Decisions Made

- Per-file Map uses `new Map(state.files)` spread pattern for Zustand immutable re-render triggers
- `cancelFile` sets status to 'cancelled' but does NOT remove the entry from the Map -- the UI layer controls removal timing (D-08 specifies immediate removal from UI)
- `setFileComplete` sets status to 'complete' and progress to 100 but does NOT remove -- the UI controls the 1000ms green flash timer before calling removeFile (D-05)
- `retryFile` resets to 'encrypting' with a fresh CancelToken.source() -- the actual re-upload is triggered from the UI component
- `useFileUpload` derives batch-level fields from the Map for backward compatibility even though it has no active consumers

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Known Stubs

None - all data paths are fully wired.

## Next Phase Readiness

- Per-file store contract is stable and exported (`PerFileUpload` type, all per-file actions)
- Plan 02 can now build `UploadListItem` component subscribing to individual file entries via `useUploadStore(s => s.files.get(fileId))`
- Plan 02 can merge upload entries into `FileList` sorted items using `targetFolderId` for folder-scoped display

## Self-Check: PASSED

- All 5 modified files exist on disk
- All 3 task commits found in git history (78b1394, aea4b24, e9bac40)
- SUMMARY.md created at expected path

---

_Phase: 36-inline-upload-progress_
_Completed: 2026-03-30_
