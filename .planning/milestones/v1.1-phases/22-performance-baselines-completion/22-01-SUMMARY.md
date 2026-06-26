---
phase: 22-performance-baselines-completion
plan: 01
subsystem: sdk
tags: [performance-api, instrumentation, withPerf, vitest, sdk-core]

# Dependency graph
requires:
  - phase: 19.1
    provides: sdk-core package with upload, download, IPFS, IPNS, folder modules
provides:
  - Performance API instrumentation for 10 sdk-core async functions
  - perf.ts module with withPerf, markStart, markEnd utilities
  - Environment-gated instrumentation (no-op in production)
affects: [22-02-journey-timing, 22-03-load-testing, web-devtools-performance]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      withPerf async wrapper for transparent Performance API marks,
      PERF_ENABLED module-level constant for environment gating,
    ]

key-files:
  created:
    - packages/sdk-core/src/perf.ts
    - packages/sdk-core/src/__tests__/perf.test.ts
  modified:
    - packages/sdk-core/src/upload/index.ts
    - packages/sdk-core/src/download/index.ts
    - packages/sdk-core/src/ipfs/index.ts
    - packages/sdk-core/src/ipns/index.ts
    - packages/sdk-core/src/folder/index.ts

key-decisions:
  - 'PERF_ENABLED evaluated at module load as constant (not per-call check) for zero overhead in production'
  - 'perf.ts is internal to sdk-core (not exported via index.ts) -- consumers do not import it directly'

patterns-established:
  - 'withPerf wrapper: wrap async function body, preserves signatures and error propagation'
  - 'Mark naming: cipherbox:{domain}:{operation} (e.g., cipherbox:ipfs:upload)'

requirements-completed: [PERF-05]

# Metrics
duration: 8min
completed: 2026-03-25
---

# Phase 22 Plan 01: SDK Performance Instrumentation Summary

**Performance API marks/measures added to 10 sdk-core async functions with environment-gated withPerf wrapper and TDD-verified cleanup**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-25T01:34:47Z
- **Completed:** 2026-03-25T01:42:26Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Created `perf.ts` module with `withPerf`, `markStart`, `markEnd` -- zero-overhead in production via `PERF_ENABLED` constant
- Instrumented all 10 target async functions across 5 modules (upload, download, IPFS, IPNS, folder)
- 6 new unit tests covering environment gating, mark cleanup, error propagation, and return value passthrough
- All 34 sdk-core tests pass, CJS + ESM build succeeds

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): Failing perf tests** - `8da4fc91d` (test)
2. **Task 1 (GREEN): perf.ts implementation** - `36f835bc3` (feat)
3. **Task 2: Instrument 10 functions** - `1fc6cf6ec` (feat)

## Files Created/Modified

- `packages/sdk-core/src/perf.ts` - Performance API wrapper with withPerf, markStart, markEnd (environment-gated)
- `packages/sdk-core/src/__tests__/perf.test.ts` - 6 unit tests for perf module
- `packages/sdk-core/src/upload/index.ts` - uploadFile wrapped with `upload:full`
- `packages/sdk-core/src/download/index.ts` - downloadAndDecrypt wrapped with `download:full`
- `packages/sdk-core/src/ipfs/index.ts` - addToIpfs (`ipfs:upload`) and fetchFromIpfs (`ipfs:download`) wrapped
- `packages/sdk-core/src/ipns/index.ts` - createAndPublishIpnsRecord (`ipns:publish`), batchPublishIpnsRecords (`ipns:batch-publish`), resolveIpnsRecord (`ipns:resolve`) wrapped
- `packages/sdk-core/src/folder/index.ts` - fetchAndDecryptMetadata (`folder:fetch-decrypt`), loadFolderMetadata (`folder:load`), updateFolderMetadataAndPublish (`folder:update-publish`) wrapped

## Decisions Made

- `PERF_ENABLED` is a module-level constant evaluated once at load time. This means instrumentation state is fixed for the lifetime of the module import. The `__CIPHERBOX_PERF__` global allows explicit opt-in for production debugging without changing NODE_ENV.
- `perf.ts` is internal to sdk-core -- not exported via `index.ts`. Consumers see no API change.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All 10 sdk-core functions now emit Performance API marks in dev/test environments
- Browser DevTools Performance tab will show `cipherbox:*` entries during user journeys
- Ready for Plan 22-02 (journey timing baselines) and Plan 22-03 (load testing thresholds)

## Self-Check: PASSED

All 7 files verified present. All 3 commits (8da4fc91d, 36f835bc3, 1fc6cf6ec) verified in history.

---

_Phase: 22-performance-baselines-completion_
_Completed: 2026-03-25_
