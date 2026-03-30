---
phase: 37-parallel-batch-upload-pipeline
plan: 01
subsystem: sdk
tags: [p-limit, concurrency, batch-upload, ipns, parallel-pipeline]

# Dependency graph
requires:
  - phase: 19.1-extract-core-crypto-sdk-as-shared-package
    provides: '@cipherbox/sdk-core upload/folder operations'
  - phase: 36-inline-upload-progress
    provides: 'Per-file upload progress UI and store infrastructure'
provides:
  - 'uploadFiles() batch method on CipherBoxClient with p-limit concurrency pool'
  - 'ExternalEncryptFn type for Web Worker encryption offloading'
  - 'files:batchUploaded SDK event for batch completion notification'
  - 'Stale-children re-read pattern for concurrent folder publish safety'
affects: [37-02-PLAN, web-upload-hooks, desktop-batch-upload]

# Tech tracking
tech-stack:
  added: [p-limit@7.3.0]
  patterns: [p-limit-concurrency-pool, stale-children-re-read, batch-settle-partition]

key-files:
  created:
    - packages/sdk/src/__tests__/upload-batch.test.ts
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk-core/src/upload/index.ts
    - packages/sdk-core/src/index.ts
    - packages/sdk/src/events.ts
    - packages/sdk/package.json
    - pnpm-lock.yaml

key-decisions:
  - 'encryptFn uses separate internal fileKeyInternal variable to avoid clearing caller-owned keys'
  - 'Batch publish failures are non-critical (same pattern as single uploadFile)'
  - 'Re-wrap file keys for share recipients uses batch approach (all keys at once)'

patterns-established:
  - 'p-limit concurrency pool: const limit = pLimit(N); Promise.allSettled(items.map(i => limit(() => work(i))))'
  - 'Stale-children re-read: loadFolderMetadata() before final publish to mitigate race with concurrent devices'
  - 'Settle partition: separate fulfilled/rejected from Promise.allSettled for partial failure handling'
  - 'ExternalEncryptFn callback: optional encryption delegate for Web Worker offload without changing upload pipeline'

requirements-completed: [D-01, D-02, D-03, D-04, D-05, D-06, D-09, D-10, D-12]

# Metrics
duration: 8min
completed: 2026-03-30
---

# Phase 37 Plan 01: SDK Batch Upload Pipeline Summary

**Batch uploadFiles() method with p-limit concurrency pool of 3, single folder IPNS publish per batch, stale-children re-read, and ExternalEncryptFn support for Web Worker offloading**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-30T16:24:22Z
- **Completed:** 2026-03-30T16:32:29Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Implemented `uploadFiles()` batch method on `CipherBoxClient` that reduces folder IPNS publishes from O(N) to O(1) per batch
- Added `ExternalEncryptFn` type and optional `encryptFn` parameter to `sdkCore.uploadFile()` for Web Worker encryption offloading
- Added `files:batchUploaded` event to SdkEvent union for batch completion notification
- 12 new unit tests (2 for encryptFn, 10 for batch orchestration) covering concurrency, partial failure, stale-children re-read, callbacks, event emission, and key cleanup

## Task Commits

Each task was committed atomically:

1. **Task 1: Add p-limit dependency, encryptFn param, and batch event type** - `426120ee5` (feat)
2. **Task 2: Implement uploadFiles() batch method with unit tests** - `0562ed410` (feat)

## Files Created/Modified

- `packages/sdk-core/src/upload/index.ts` - Added ExternalEncryptFn type and encryptFn parameter to uploadFile()
- `packages/sdk-core/src/index.ts` - Export ExternalEncryptFn type
- `packages/sdk-core/src/__tests__/upload.test.ts` - 2 new tests for encryptFn behavior
- `packages/sdk/package.json` - Added p-limit@7.3.0 dependency
- `packages/sdk/src/events.ts` - Added files:batchUploaded event variant
- `packages/sdk/src/client.ts` - Added UPLOAD_CONCURRENCY const, pLimit import, uploadFiles() method (~200 lines)
- `packages/sdk/src/__tests__/upload-batch.test.ts` - 10 unit tests for batch upload orchestration
- `pnpm-lock.yaml` - Updated lockfile for p-limit

## Decisions Made

- Used `fileKeyInternal` variable pattern: only allocate and clear internal file key when encryptFn is NOT provided, since the caller owns the key returned by encryptFn
- Batch IPNS publish failures treated as non-critical (consistent with existing single-file uploadFile pattern)
- Share key re-wrapping done in batch for all successful files at once (single reWrapNewItems call with array)
- File keys cleared in finally block after all post-upload work (re-wrapping, events) completes

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Worktree packages were not built initially (pre-existing workspace state). Required building @cipherbox/crypto, @cipherbox/core, @cipherbox/api-client, and @cipherbox/sdk-core before tests could run. Not a code issue, just workspace initialization.
- integration.test.ts failures are pre-existing (requires running API server). All 146 unit tests pass.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `uploadFiles()` method is ready for integration in Plan 02 (Web Worker encryption + web app hook integration)
- `ExternalEncryptFn` type is exported and ready for Web Worker implementation
- `files:batchUploaded` event is available for Zustand store subscription

---

## Self-Check: PASSED

All files verified present, all commits verified in git log, all code features verified in source.

_Phase: 37-parallel-batch-upload-pipeline_
_Completed: 2026-03-30_
