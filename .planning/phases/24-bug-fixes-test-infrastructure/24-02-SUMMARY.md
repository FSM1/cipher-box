---
phase: 24-bug-fixes-test-infrastructure
plan: 02
subsystem: testing
tags: [load-testing, sdk-core, ipns, vitest, headless]

# Dependency graph
requires:
  - phase: 22-performance-baselines
    provides: load test harness (client-pool, metrics, thresholds, reporter)
provides:
  - headless sdk-core load test workloads (IPNS, upload, folder read)
  - 401 interceptor with automatic token refresh for long-running load tests
  - createSdkContext helper for building SdkContext from PoolClient
affects: [load-testing, performance-baselines]

# Tech tracking
tech-stack:
  added: []
  patterns: [headless sdk-core load testing, 401 interceptor with shared refresh promise]

key-files:
  created:
    - tests/load/src/workloads/sdk-core-workload.ts
    - tests/load/src/scenarios/sdk-upload-pipeline.test.ts
    - tests/load/src/scenarios/sdk-ipns-contention.test.ts
    - tests/load/src/scenarios/sdk-folder-read.test.ts
  modified:
    - tests/load/src/harness/client-pool.ts

key-decisions:
  - 'Used loadFolderMetadata (IPNS resolve + fetch + decrypt) instead of raw fetchAndDecryptMetadata for folder read workload to capture full read path'
  - 'Adapted uploadFile workload to match actual sdk-core signature (fileId + userPublicKey required, no IPNS publish in upload function)'
  - 'Error pattern follows file-workload.ts: measure() records errors automatically, outer try/catch logs and continues'

patterns-established:
  - 'Headless sdk-core workload pattern: prepareSdkClient() -> run*Workload() with MetricsCollector'
  - '401 interceptor via createSdkContext with shared refreshPromise for concurrent token refresh coalescing'

requirements-completed: [TEST-01, TEST-03]

# Metrics
duration: 4min
completed: 2026-03-25
---

# Phase 24 Plan 02: Headless SDK-Core Load Tests Summary

**Headless sdk-core load tests with 401 interceptor for IPNS contention, upload pipeline, and folder read bottleneck isolation**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-25T22:54:13Z
- **Completed:** 2026-03-25T22:58:57Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Added createSdkContext helper with 401 interceptor that automatically re-authenticates via /auth/test-login with shared promise for concurrent request coalescing
- Created 3 headless load test scenarios that call sdk-core functions directly, bypassing CipherBoxClient overhead for precise bottleneck isolation
- Built shared sdk-core-workload module with prepareSdkClient, runIpnsPublishWorkload, runUploadPipelineWorkload, and runFolderReadWorkload

## Task Commits

Each task was committed atomically:

1. **Task 1: Add 401 interceptor to client-pool + createSdkContext helper** - `37ba581f6` (feat)
2. **Task 2: Create headless sdk-core workloads and 3 load test scenarios** - `0c8a7a731` (feat)

## Files Created/Modified

- `tests/load/src/harness/client-pool.ts` - Added reAuthenticate(), createSdkContext() with 401 interceptor and THROTTLE_BYPASS support
- `tests/load/src/workloads/sdk-core-workload.ts` - Shared headless workload helpers using sdk-core directly
- `tests/load/src/scenarios/sdk-upload-pipeline.test.ts` - Upload pipeline isolation test (encrypt + pin + IPNS publish)
- `tests/load/src/scenarios/sdk-ipns-contention.test.ts` - IPNS publish/resolve contention test at 10+ concurrent clients
- `tests/load/src/scenarios/sdk-folder-read.test.ts` - Folder metadata read path test (IPNS resolve + IPFS fetch + decrypt)

## Decisions Made

- Used `loadFolderMetadata` (which resolves IPNS then fetches and decrypts) instead of raw `fetchAndDecryptMetadata` (which takes a CID) for folder read workload, capturing the full read path including IPNS resolution latency
- Adapted upload workload to match actual `sdkCore.uploadFile` signature which requires `fileId` (UUID) and `userPublicKey` -- the plan's proposed signature omitted these required params and included IPNS params that aren't part of the upload function
- Used try/catch around `measure()` calls matching the file-workload.ts pattern where errors are recorded by measure (success: false) and the outer catch logs and continues to the next iteration

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected uploadFile parameter signature**

- **Found during:** Task 2 (sdk-core-workload.ts creation)
- **Issue:** Plan proposed `{ctx, folderKey, ipnsPrivateKey, ipnsName, data, fileName, mimeType}` but actual `sdkCore.uploadFile` takes `{data, fileId, mimeType, folderKey, userPublicKey, ctx}` -- no ipnsName/ipnsPrivateKey/fileName params, requires fileId and userPublicKey
- **Fix:** Used correct signature with `crypto.randomUUID()` for fileId and `pc.publicKey` for userPublicKey; clear returned fileKey after use
- **Files modified:** tests/load/src/workloads/sdk-core-workload.ts
- **Verification:** `tsc --noEmit` passes
- **Committed in:** 0c8a7a731

**2. [Rule 1 - Bug] Corrected fetchAndDecryptMetadata usage**

- **Found during:** Task 2 (sdk-core-workload.ts creation)
- **Issue:** Plan proposed `sdkCore.fetchAndDecryptMetadata({ipnsName, folderKey, ctx})` but actual function takes `(cid, folderKey, ctx)` -- a CID, not IPNS name
- **Fix:** Used `sdkCore.loadFolderMetadata({ipnsName, folderKey, ctx})` which does IPNS resolve + fetch + decrypt (the intended full read path)
- **Files modified:** tests/load/src/workloads/sdk-core-workload.ts
- **Verification:** `tsc --noEmit` passes
- **Committed in:** 0c8a7a731

**3. [Rule 1 - Bug] Removed recordError calls**

- **Found during:** Task 2 (sdk-core-workload.ts creation)
- **Issue:** Plan used `pc.metrics.recordError()` which does not exist on MetricsCollector
- **Fix:** Used try/catch around `measure()` (which records errors automatically as success: false), matching the file-workload.ts pattern
- **Files modified:** tests/load/src/workloads/sdk-core-workload.ts
- **Verification:** `tsc --noEmit` passes
- **Committed in:** 0c8a7a731

---

**Total deviations:** 3 auto-fixed (3 bugs -- plan proposed incorrect function signatures)
**Impact on plan:** All auto-fixes were necessary for type-checking and correct sdk-core usage. No scope creep.

## Issues Encountered

- Pre-existing type errors in `byo-file-workload.ts` (missing `cid` variable) -- out of scope, not caused by this plan
- Pre-existing type errors with pinning provider exports from sdk-core resolved by rebuilding sdk-core dist (stale build artifacts)

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All 3 headless load test scenarios are ready to run against a live API + IPFS backend
- The 401 interceptor enables long-running load tests without JWT expiry failures
- Scenarios can be executed with: `cd tests/load && npx vitest run src/scenarios/sdk-*.test.ts`

## Self-Check: PASSED

- All 5 source files verified present on disk
- Both task commits (37ba581f6, 0c8a7a731) verified in git log

---

_Phase: 24-bug-fixes-test-infrastructure_
_Completed: 2026-03-25_
