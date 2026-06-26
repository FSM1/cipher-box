---
phase: 18-performance-instrumentation
plan: 01
subsystem: api
tags: [prometheus, prom-client, histogram, metrics, ipfs, ipns, tee, performance]

# Dependency graph
requires:
  - phase: 10-monitoring-infrastructure
    provides: MetricsService with Prometheus registry and HTTP request duration histogram
provides:
  - cipherbox_ipfs_ipns_duration_seconds histogram (resolve/publish/pin/cat operations)
  - cipherbox_republish_batch_duration_seconds histogram (TEE batch processing)
  - Timing instrumentation on IpnsService, IpfsController, RepublishProcessor
affects: [18-02-grafana-dashboards, 22-client-load-testing]

# Tech tracking
tech-stack:
  added: []
  patterns: [startTimer/endTimer pattern for Prometheus histogram observations with labeled results]

key-files:
  created:
    - apps/api/src/metrics/metrics.service.spec.ts
  modified:
    - apps/api/src/metrics/metrics.service.ts
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns.service.spec.ts
    - apps/api/src/ipfs/ipfs.controller.ts
    - apps/api/src/ipfs/ipfs.controller.spec.ts
    - apps/api/src/republish/republish.processor.ts
    - apps/api/src/republish/republish.processor.spec.ts
    - packages/api-client/openapi.json

key-decisions:
  - 'IPFS/IPNS histogram buckets span 1ms-30s with exponential spacing for mixed fast/slow operations'
  - 'Republish batch histogram buckets span 1s-120s for long-running batch processing'
  - 'Source label (db/network) only applies to resolve operations; empty string for others'
  - 'TEE provider hardcoded to mock for now; will become config-driven when Phala TEE is deployed'
  - 'Partial batch failures (processRepublishBatch returns with some failed entries) count as success; only thrown exceptions count as error'

patterns-established:
  - 'startTimer/endTimer pattern: call startTimer with static labels at method entry, end with dynamic result label in finally/catch blocks'
  - 'Source tracking: resolve operations set source=db or source=network based on which data source produced the final result'

requirements-completed: [PERF-01, PERF-02, PERF-04]

# Metrics
duration: 7min
completed: 2026-03-07
---

# Phase 18 Plan 01: Performance Instrumentation Summary

**Prometheus duration histograms for IPFS/IPNS operations (resolve/publish/pin/cat) and TEE republish batches with operation/result/source label dimensions**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-07T05:12:21Z
- **Completed:** 2026-03-07T05:19:34Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Registered `cipherbox_ipfs_ipns_duration_seconds` histogram with operation/result/source labels and 14-bucket exponential spacing (1ms-30s)
- Registered `cipherbox_republish_batch_duration_seconds` histogram with tee_provider/result labels and 10-bucket extended tier (1s-120s)
- Instrumented IpnsService (resolve with db/network source tracking, publish), IpfsController (pin, cat), and RepublishProcessor (batch) with timing wrappers
- Created MetricsService unit tests (9 tests) and added 12 timing-specific tests across IpnsService, IpfsController, and RepublishProcessor specs
- All 689 API tests pass with zero regressions

## Task Commits

Each task was committed atomically:

1. **Task 1: Add histogram definitions to MetricsService** (TDD)
   - `8186538` test(18-01): add failing tests for IPFS/IPNS and republish duration histograms (RED)
   - `758a5a9` feat(18-01): add IPFS/IPNS and republish batch duration histograms to MetricsService (GREEN)

2. **Task 2: Instrument IpnsService, IpfsController, and RepublishProcessor** - `bedb10a` (feat)

## Files Created/Modified

- `apps/api/src/metrics/metrics.service.ts` - Added ipfsIpnsDuration and republishBatchDuration histogram definitions
- `apps/api/src/metrics/metrics.service.spec.ts` - NEW: 9 unit tests for histogram registration, labels, and startTimer pattern
- `apps/api/src/ipns/ipns.service.ts` - Added MetricsService injection and timing wrappers on resolveRecord/publishRecord
- `apps/api/src/ipns/ipns.service.spec.ts` - Added MetricsService mock and 5 timing-specific tests
- `apps/api/src/ipfs/ipfs.controller.ts` - Added timing wrappers on pinFile and getFile calls
- `apps/api/src/ipfs/ipfs.controller.spec.ts` - Added ipfsIpnsDuration mock and 4 timing-specific tests
- `apps/api/src/republish/republish.processor.ts` - Added timing wrapper on processRepublishBatch
- `apps/api/src/republish/republish.processor.spec.ts` - Added republishBatchDuration mock and 3 timing-specific tests
- `packages/api-client/openapi.json` - Regenerated (formatting update from api:generate)

## Decisions Made

- IPFS/IPNS histogram uses combined fast+slow bucket tier (1ms-30s) covering both fast DB lookups and slow network operations
- Republish batch histogram uses extended bucket tier (1s-120s) for long-running TEE batch processing
- Source label tracks 'db' vs 'network' for resolve operations only; empty string for pin/cat/publish where source is irrelevant
- TEE provider label hardcoded to 'mock' for now; will become config-driven when Phala TEE deploys
- Partial batch failures (some entries fail, but processRepublishBatch resolves successfully) are recorded as result='success'; only thrown exceptions are result='error'
- MetricsModule is global, so no module import changes needed for IpnsModule

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Pre-commit hook required `pnpm api:generate` after modifying IpfsController -- the hook correctly detected API source changes without regenerated client files. Resolved by running api:generate before committing Task 2.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Duration histograms are registered and actively collecting observations from all IPFS/IPNS and TEE operations
- Plan 02 can build Grafana dashboards to visualize these metrics (p50/p95/p99 latency panels)
- Label cardinality is conservative: 4 operations x 3 results x 2 sources = 24 max for IPFS/IPNS; 1 provider x 2 results = 2 for TEE (total 26, well under 30 target)

## Self-Check: PASSED

All 9 files verified present. All 3 commit hashes verified in git log.

---

_Phase: 18-performance-instrumentation_
_Completed: 2026-03-07_
