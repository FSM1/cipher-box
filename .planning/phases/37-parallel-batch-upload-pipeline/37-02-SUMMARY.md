---
phase: 37-parallel-batch-upload-pipeline
plan: 02
subsystem: ui
tags: [web-worker, encryption, batch-upload, transferable, zero-copy]

requires:
  - phase: 37-parallel-batch-upload-pipeline-01
    provides: SDK uploadFiles() batch method with encryptFn parameter and ExternalEncryptFn type

provides:
  - Web Worker for AES-GCM/CTR file encryption (off main thread)
  - EncryptionWorkerService wrapper with ExternalEncryptFn factory
  - Batch upload integration in useDropUpload hook via client.uploadFiles()

affects: [upload-pipeline, web-performance, file-browser]

tech-stack:
  added: []
  patterns: [web-worker-encryption, transferable-arraybuffer, correlation-id-promise-pattern]

key-files:
  created:
    - apps/web/src/workers/encrypt.worker.ts
    - apps/web/src/services/encrypt-worker.service.ts
  modified:
    - apps/web/src/hooks/useDropUpload.ts
    - apps/web/src/lib/sdk-provider.ts
    - apps/web/tsconfig.json

key-decisions:
  - 'Singleton EncryptionWorkerService with lazy Worker creation -- one Worker instance shared across all uploads'
  - 'Transferable ArrayBuffer transfers in both directions for zero-copy data passing between threads'
  - 'Correlation ID pattern (enc-{counter}-{timestamp}) for multiplexing concurrent encrypt operations on single Worker'
  - 'Duplicate file handling remains on old encrypt+upload path since duplicates bypass SDK folder registration'

patterns-established:
  - 'Web Worker encryption offloading: use EncryptionWorkerService.createEncryptFn() to get ExternalEncryptFn'
  - 'Worker lifecycle: getEncryptionWorker() for lazy init, destroyEncryptionWorker() on logout/destroy'

requirements-completed: [D-07, D-08, D-11]

duration: 5min
completed: 2026-03-30
---

# Phase 37 Plan 02: Web Worker Encryption and Batch Upload Integration Summary

**Web Worker encryption offloading with Transferable zero-copy transfers, wired into SDK batch uploadFiles() via ExternalEncryptFn**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-30T16:37:53Z
- **Completed:** 2026-03-30T16:43:39Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- File encryption moved off main thread into dedicated Web Worker using @cipherbox/crypto primitives
- EncryptionWorkerService provides Promise-based API with correlation IDs for concurrent operations
- useDropUpload rewired from sequential uploadFile() loop to single uploadFiles() batch call
- Per-file progress/error/complete callbacks properly wired to Zustand upload store
- Worker terminated on logout via destroyEncryptionWorker() in SDK client destroy path

## Task Commits

Each task was committed atomically:

1. **Task 1: Create encrypt Web Worker and main-thread wrapper service** - `c982d16ca` (feat)
2. **Task 2: Rewire useDropUpload to call client.uploadFiles() for batch uploads** - `d1bb57191` (feat)

## Files Created/Modified

- `apps/web/src/workers/encrypt.worker.ts` - Web Worker for AES-GCM/CTR encryption with Transferable buffer transfers
- `apps/web/src/services/encrypt-worker.service.ts` - Main-thread wrapper with Promise API, correlation IDs, ExternalEncryptFn factory
- `apps/web/src/hooks/useDropUpload.ts` - Rewired to use client.uploadFiles() with encryptFn for batch uploads
- `apps/web/src/lib/sdk-provider.ts` - Added destroyEncryptionWorker() call on SDK client destroy
- `apps/web/tsconfig.json` - Excluded encrypt.worker.ts from main compilation

## Decisions Made

- Used singleton EncryptionWorkerService with lazy Worker creation to avoid spawning Workers when no uploads happen
- Transferable ArrayBuffer transfers used in both directions (main->worker and worker->main) for zero-copy performance
- Correlation ID format `enc-{counter}-{timestamp}` enables multiplexing concurrent encrypt operations on a single Worker
- Duplicate file handling intentionally left on old encrypt+upload path because duplicates don't go through SDK folder registration (staged for Replace dialog instead)
- `currentDupUploadId` variable scoped to catch block for error reporting on duplicate file failures only (new file errors handled via batch callbacks)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Encryption Worker and batch upload pipeline fully wired
- Ready for end-to-end testing with multi-file drops
- Ready for Plan 03 (if any) or phase verification

## Self-Check: PASSED

All created files verified present. All commit hashes verified in git log.

---

_Phase: 37-parallel-batch-upload-pipeline_
_Completed: 2026-03-30_
