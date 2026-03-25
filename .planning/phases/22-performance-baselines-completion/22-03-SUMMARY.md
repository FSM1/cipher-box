---
phase: 22-performance-baselines-completion
plan: 03
subsystem: testing
tags: [load-testing, thresholds, capacity-planning, vitest, performance]

# Dependency graph
requires:
  - phase: 19.2-ipfs-upload-performance
    provides: Post-optimization baselines (upload throughput, mixed workload, three-point comparison)
  - phase: 18-performance-instrumentation
    provides: Server-side Prometheus baselines and histogram data
  - phase: 19-someguy-ipns-sidecar
    provides: IPNS resolution baselines with Someguy sidecar
provides:
  - ThresholdConfig type and checkThresholds function for automated load test regression detection
  - Pass/fail threshold assertions integrated into all 5 load test scenarios
  - Comprehensive capacity model document with observed limits, bottleneck analysis, scaling recommendations
affects: [load-testing, ci-workflow, documentation]

# Tech tracking
tech-stack:
  added: []
  patterns: [threshold-assertion-pattern, capacity-model-documentation]

key-files:
  created:
    - tests/load/src/harness/thresholds.ts
    - tests/load/src/harness/thresholds.test.ts
    - docs/CAPACITY.md
  modified:
    - tests/load/src/scenarios/upload-throughput.test.ts
    - tests/load/src/scenarios/mixed-workload.test.ts
    - tests/load/src/scenarios/ipns-publish-storm.test.ts
    - tests/load/src/scenarios/sustained-load.test.ts
    - tests/load/src/scenarios/spike-test.test.ts

key-decisions:
  - 'Thresholds set at 2-3x observed baselines to avoid CI flakiness while catching regressions'
  - 'Spike test thresholds are most generous (15s p95, 15% error) since it intentionally overloads'
  - 'Threshold checks use vitest expect() for clear failure messages in CI output'

patterns-established:
  - 'Threshold assertion pattern: define ThresholdConfig[], call checkThresholds after aggregateAndReport, expect(result.passed).toBe(true)'
  - 'Capacity documentation pattern: observed limits, bottleneck analysis, scaling triggers, growth formulas'

requirements-completed: [PERF-07, PERF-08]

# Metrics
duration: 8min
completed: 2026-03-25
---

# Phase 22 Plan 03: Thresholds and Capacity Model Summary

**Automated pass/fail thresholds integrated into all 5 load test scenarios with checkThresholds module, plus comprehensive capacity document consolidating Phase 18/19/19.2 baselines into growth projections and scaling recommendations**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-25T01:34:54Z
- **Completed:** 2026-03-25T01:43:35Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Created `thresholds.ts` module with `ThresholdConfig` type and `checkThresholds` function that compares metrics against p95 latency and error rate limits
- Integrated threshold assertions into all 5 load test scenarios (upload-throughput, mixed-workload, ipns-publish-storm, sustained-load, spike-test) using vitest `expect()` for clear CI failure messages
- Created `docs/CAPACITY.md` with 347 lines covering observed limits from 3 baseline phases, infrastructure bottleneck analysis, scaling recommendations with trigger thresholds, growth projections with formulas, and cost estimates
- 5 unit tests covering pass, fail (p95), fail (error rate), skip missing operations, and violation message content

## Task Commits

Each task was committed atomically:

1. **Task 1: Create thresholds module and integrate into all 5 scenarios (TDD)**
   - `6f458d79e` test(22-03): add failing tests for threshold checking module
   - `5a862345b` feat(22-03): implement threshold checking module
   - `868f6101a` feat(22-03): integrate threshold checks into all 5 load test scenarios
2. **Task 2: Create docs/CAPACITY.md** - `7cbed457c` docs(22-03): create comprehensive capacity model document

## Files Created/Modified

- `tests/load/src/harness/thresholds.ts` - ThresholdConfig type, ThresholdResult type, checkThresholds function
- `tests/load/src/harness/thresholds.test.ts` - 5 unit tests for threshold checking
- `tests/load/src/scenarios/upload-throughput.test.ts` - Added threshold check (uploadFile p95 <= 10s, error <= 5%)
- `tests/load/src/scenarios/mixed-workload.test.ts` - Added threshold check (uploadFile p95 <= 10s, createFolder p95 <= 5s, error <= 10%)
- `tests/load/src/scenarios/ipns-publish-storm.test.ts` - Added threshold check (createFolder p95 <= 10s, error <= 10%)
- `tests/load/src/scenarios/sustained-load.test.ts` - Added threshold check (uploadFile p95 <= 10s, createFolder p95 <= 5s, error <= 5%)
- `tests/load/src/scenarios/spike-test.test.ts` - Added threshold check on burst phase (p95 <= 15s, error <= 15%)
- `docs/CAPACITY.md` - Comprehensive capacity model with observed limits, bottlenecks, scaling recommendations, growth projections

## Decisions Made

- Thresholds set at 2-3x observed Phase 19.2 baselines (e.g., upload p95 threshold 10,000ms vs observed 2,841ms) to avoid false positives from normal variance while still catching significant regressions
- Spike test uses the most generous thresholds (15s/15%) since it intentionally overloads the system
- Mixed workload allows higher error rates (10%) than upload-throughput (5%) based on historical behavior
- Used vitest `expect()` assertion for threshold violation (not just `console.warn`) so CI actually fails on breach
- Capacity document follows existing `docs/` markdown style with tables, numbered sections, and TOC

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All PERF requirements (05-08) are now complete across Phase 22's three plans
- Load test harness has automated regression detection via thresholds
- Capacity model document provides operators with scaling guidance
- CI workflow (`load-test.yml`) surfaces threshold violations automatically

## Self-Check: PASSED

All files exist, all commits verified.

---

_Phase: 22-performance-baselines-completion_
_Completed: 2026-03-25_
