---
phase: 19-ipns-resolution-improvement
plan: 02
subsystem: api
tags: [prometheus, metrics, ipns, histogram, latency]

# Dependency graph
requires:
  - phase: 18-performance-instrumentation
    provides: MetricsService with Prometheus registry and histogram pattern
provides:
  - ipnsResolveDuration Prometheus histogram with source labels (network/db_cache/network_stale)
  - ipnsPublishDuration Prometheus histogram with outcome labels (success/error/timeout)
  - Timing instrumentation in IpnsService.resolveRecord() and publishRecord()
affects: [19-ipns-resolution-improvement, 22-client-load-testing]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      process.hrtime.bigint() for sub-millisecond timing,
      finally-block for guaranteed metric observation,
    ]

key-files:
  created: []
  modified:
    - apps/api/src/metrics/metrics.service.ts
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns.service.spec.ts
    - apps/api/src/ipns/__tests__/ipns.integration.spec.ts
    - apps/api/src/ipns/__tests__/ipns.security.spec.ts

key-decisions:
  - 'Resolve buckets 50ms-30s, publish buckets 100ms-60s tuned to IPNS operation characteristics'
  - 'No histogram observation on null resolve results (not found) to avoid polluting latency data'
  - 'AbortError detection via error.name for timeout classification in publish metrics'

patterns-established:
  - 'process.hrtime.bigint() timing pattern for Prometheus histogram observation in service methods'
  - 'finally-block pattern for guaranteed publish duration observation regardless of outcome'

requirements-completed: [IPNS-04]

# Metrics
duration: 5min
completed: 2026-03-07
---

# Phase 19 Plan 02: IPNS Latency Metrics Summary

**Prometheus latency histograms for IPNS resolve (source-labeled) and publish (outcome-labeled) operations with process.hrtime.bigint() timing**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-07T06:46:21Z
- **Completed:** 2026-03-07T06:51:56Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Added two new Prometheus histograms (cipherbox_ipns_resolve_duration_seconds, cipherbox_ipns_publish_duration_seconds) to MetricsService
- Instrumented IpnsService.resolveRecord() with timing that labels every non-null resolution path (network, db_cache, network_stale)
- Instrumented IpnsService.publishRecord() with timing for delegated routing calls (success, error, timeout)
- Added 9 new test cases verifying histogram observation behavior across all resolution and publish paths
- Updated MetricsService mocks in all 3 IPNS test suites (unit, integration, security)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add IPNS latency histograms to MetricsService** - `b6fc489cd` (feat)
2. **Task 2: Instrument IpnsService with timing and update tests** - `4a30fd59b` (feat)

## Files Created/Modified

- `apps/api/src/metrics/metrics.service.ts` - Added ipnsResolveDuration and ipnsPublishDuration histogram definitions
- `apps/api/src/ipns/ipns.service.ts` - Added MetricsService injection and timing instrumentation in resolveRecord() and publishRecord()
- `apps/api/src/ipns/ipns.service.spec.ts` - Added MetricsService mock and 9 new test cases for histogram observation
- `apps/api/src/ipns/__tests__/ipns.integration.spec.ts` - Added ipnsResolveDuration/ipnsPublishDuration to all 3 mock MetricsService objects
- `apps/api/src/ipns/__tests__/ipns.security.spec.ts` - Added ipnsResolveDuration/ipnsPublishDuration to mock MetricsService

## Decisions Made

- Resolve histogram buckets start at 50ms (fast local Someguy) up to 30s (timeout + DB fallback), while publish buckets start at 100ms up to 60s (publish is slower than resolve) -- tuned per CONTEXT.md research
- Null resolve results (not found in network or DB) do not record a histogram observation to avoid polluting latency data with non-meaningful measurements
- AbortError detection uses `error.name === 'AbortError'` to distinguish timeout from generic errors in publish metrics
- Used `finally` block for publish timing to guarantee observation regardless of outcome

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- IPNS latency histograms are registered and ready for baseline collection
- When Someguy routing provider is deployed (Plan 01 or later), these histograms will capture p50/p95/p99 latency distributions
- Phase 22 (client + load testing) can use these metrics for performance validation

## Self-Check: PASSED

- All 5 modified files exist on disk
- Task 1 commit b6fc489cd verified
- Task 2 commit 4a30fd59b verified
- 130/130 IPNS tests pass (5 test suites)

---

_Phase: 19-ipns-resolution-improvement_
_Completed: 2026-03-07_
