---
phase: 21-byo-ipfs-node-support
plan: 07
subsystem: testing
tags: [load-testing, benchmarking, ipfs, byo, performance, k6]

# Dependency graph
requires:
  - phase: 21-byo-ipfs-node-support (plans 01-03)
    provides: PinningProvider interface, KuboProvider, PsaProvider, register-cid endpoint, DualPinProvider, SDK client orchestration
  - phase: 19.2-ipfs-upload-performance-optimization
    provides: Existing load test harness (client-pool, metrics, reporter, file-workload)
provides:
  - BYO-mode file upload workload for load testing (pin -> register-cid -> IPNS publish path)
  - BYO-aware client pool extension with env-var-driven external provider config
  - BYO upload throughput scenario with per-operation latency breakdown
  - BYO capacity ceiling scenario with stepped concurrency (50-1000 clients)
  - Mixed CipherBox+BYO workload scenario with per-segment metric reporting
affects: [22-performance-baselines-completion]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      env-var-gated BYO scenarios that skip gracefully when no provider configured,
      per-segment metric reporting for mixed workloads,
    ]

key-files:
  created:
    - tests/load/src/workloads/byo-file-workload.ts
    - tests/load/src/scenarios/byo-upload-throughput.test.ts
    - tests/load/src/scenarios/byo-capacity-ceiling.test.ts
    - tests/load/src/scenarios/byo-mixed-workload.test.ts
  modified:
    - tests/load/src/harness/client-pool.ts

key-decisions:
  - 'Task 4 (benchmark execution) deferred -- requires real external IPFS provider infrastructure not available at plan time'
  - 'BYO scenarios skip gracefully when BYO_IPFS_ENDPOINT not set (no CI failures)'
  - 'Mixed workload reports CB-only and BYO segments separately to isolate cross-impact'

patterns-established:
  - 'Env-var-gated load test scenarios: skip with warning when infrastructure unavailable'
  - 'Per-segment metric reporting: separate aggregateAndReport calls for each client type in mixed scenarios'

requirements-completed: [BYO-01, BYO-02, BYO-05]

# Metrics
duration: 5min
completed: 2026-03-25
---

# Phase 21 Plan 07: BYO Performance Benchmarking Summary

**BYO-IPFS load test scenarios with per-operation latency breakdown, stepped capacity ceiling, and mixed CB+BYO workload reporting -- benchmark execution deferred pending external provider infrastructure**

## Performance

- **Duration:** ~5 min (tasks 1-3 executed; task 4 deferred)
- **Started:** 2026-03-24T20:01:00Z
- **Completed:** 2026-03-25T00:00:00Z (task 4 skipped)
- **Tasks:** 3/4 (1 deferred)
- **Files modified:** 5

## Accomplishments

- BYO file workload exercises the full BYO upload path (pin -> register-cid -> IPNS publish) with per-operation metric recording, including separate PSA transient relay path
- Client pool extended with BYO-aware pool creation using env-var-driven external provider config (BYO_IPFS_ENDPOINT, BYO_IPFS_AUTH_TOKEN, BYO_IPFS_PROTOCOL)
- Three new load test scenarios: BYO upload throughput, BYO capacity ceiling (50-1000 stepped concurrency), and mixed CipherBox+BYO workload with per-segment reporting
- All scenarios skip gracefully when BYO_IPFS_ENDPOINT is not configured, ensuring no CI failures

## Task Commits

Each task was committed atomically:

1. **Task 1: BYO file workload and client-pool extension** - `95e53910b` (feat)
2. **Task 2: BYO upload throughput and capacity ceiling scenarios** - `cf17cd0d1` (feat)
3. **Task 3: Mixed CipherBox+BYO workload scenario** - `49864ded2` (feat)
4. **Task 4: Run benchmarks against real external provider and capture baselines** - SKIPPED (deferred -- requires external IPFS provider infrastructure)

## Files Created/Modified

- `tests/load/src/workloads/byo-file-workload.ts` - BYO-mode file upload workload with Kubo and PSA paths, per-operation metric recording
- `tests/load/src/harness/client-pool.ts` - Extended with ByoPoolClient interface and createByoClientPool function
- `tests/load/src/scenarios/byo-upload-throughput.test.ts` - BYO upload throughput scenario with configurable client count
- `tests/load/src/scenarios/byo-capacity-ceiling.test.ts` - Stepped concurrency increase (50/100/200/500/1000) to find API capacity ceiling
- `tests/load/src/scenarios/byo-mixed-workload.test.ts` - Mixed CipherBox-only + BYO concurrent workload with per-segment metric reporting

## Decisions Made

- **Task 4 deferred:** Benchmark execution requires a real external IPFS provider (Pinata, Filebase, or self-hosted Kubo with external endpoint). User chose to skip this task; baselines document (.planning/baselines/21-byo-baselines.md) will be created when provider infrastructure is available.
- **Env-var gating:** All BYO scenarios check for BYO_IPFS_ENDPOINT and skip gracefully with a console warning when not set, preventing CI failures.
- **Per-segment reporting:** Mixed workload scenario reports CB-only and BYO segments separately via distinct aggregateAndReport calls, enabling direct comparison of cross-impact metrics.

## Deviations from Plan

None for tasks 1-3 -- plan executed exactly as written. Task 4 deferred by user decision (not a deviation from execution, but a scope decision).

## Deferred Items

- **Benchmark execution and baselines capture (Task 4):** Create `.planning/baselines/21-byo-baselines.md` with per-operation latency breakdown, capacity ceiling table, mixed workload per-segment metrics, and comparison to 19.2 baselines. Requires: external IPFS provider account configured, API and infrastructure running.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required for the test code itself. Running the benchmarks (deferred Task 4) requires:

- External IPFS provider account (Pinata, Filebase, or self-hosted Kubo)
- Environment variables: BYO_IPFS_ENDPOINT, BYO_IPFS_AUTH_TOKEN, BYO_IPFS_PROTOCOL, BYO_IPFS_PROVIDER_NAME

## Next Phase Readiness

- Phase 21 (BYO-IPFS Node Support) is complete at the code level -- all 7 plans have code committed
- Benchmark baselines (21-07 Task 4) can be captured independently when provider infrastructure is available
- Phase 22 (Performance Baselines Completion) can proceed; BYO benchmark scenarios are ready to run

## Self-Check: PASSED

- All 5 created/modified files verified on disk
- All 3 task commits verified in git log (95e53910b, cf17cd0d1, 49864ded2)
- SUMMARY.md exists at expected path

---

_Phase: 21-byo-ipfs-node-support_
_Completed: 2026-03-25_
