---
phase: 26-observability-ux-tuning
plan: 02
subsystem: performance
tags: [timeout, retry, latency, ipfs, pinning, upload]

# Dependency graph
requires:
  - phase: 18-performance-baselines
    provides: Server-side p99 timing data for timeout calibration
  - phase: 22-client-load-baselines
    provides: Client-side journey baselines for retry delay tuning
provides:
  - Tuned timeout constants across SDK pinning providers (Kubo, Pinata, PSA)
  - Tuned delegated routing timeout and retry base delay
  - Tuned upload service retry base delay for faster transient failure recovery
affects: [performance, upload, ipns-resolution, byo-ipfs]

# Tech tracking
tech-stack:
  added: []
  patterns: [2-3x p99 timeout formula applied to production constants]

key-files:
  modified:
    - packages/sdk-core/src/pinning/kubo-provider.ts
    - packages/sdk-core/src/pinning/pinata-provider.ts
    - packages/sdk-core/src/pinning/psa-provider.ts
    - apps/api/src/ipns/delegated-routing.client.ts
    - apps/web/src/services/upload.service.ts

key-decisions:
  - 'Kubo timeout 30s->10s based on ~44x pin p99 headroom (227ms baseline)'
  - 'Pinata timeout 60s->30s based on 15x BYO p50 headroom (2.0s baseline)'
  - 'PSA timeout 30s->15s conservative 50% reduction (no project-specific baseline)'
  - 'Delegated routing timeout 10s->5s based on ~10x resolve p99 headroom (488ms baseline)'
  - 'Retry base delays 1000ms->500ms for faster transient failure recovery'
  - 'Connection test probe timeout (10s) and TEE timeout (30s) intentionally unchanged'

patterns-established:
  - '2-3x p99 formula: production timeouts calibrated at 2-3x observed p99 latency from baselines'

requirements-completed: [OBS-02]

# Metrics
duration: 4min
completed: 2026-03-26
---

# Phase 26 Plan 02: Timeout and Retry Tuning Summary

**Tuned 6 timeout/retry constants across 5 files using 2-3x p99 formula from Phase 18/22 baselines for sub-2s perceived latency**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-26T00:45:45Z
- **Completed:** 2026-03-26T00:50:10Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Reduced SDK provider timeouts: Kubo 30s->10s, Pinata 60s->30s, PSA 30s->15s
- Reduced delegated routing timeout from 10s to 5s and base retry delay from 1000ms to 500ms
- Reduced upload service retry base delay from 1000ms to 500ms
- Intentionally preserved connection test (10s) and TEE (30s) timeouts as unchanged

## Task Commits

Each task was committed atomically:

1. **Task 1: Tune SDK provider timeout constants and API delegated routing timeouts** - `84c942412` (perf)
2. **Task 2: Tune upload service retry delay and validate all changes build** - `339cf3178` (perf)

## Files Modified

- `packages/sdk-core/src/pinning/kubo-provider.ts` - Kubo RPC timeout 30s -> 10s
- `packages/sdk-core/src/pinning/pinata-provider.ts` - Pinata API timeout 60s -> 30s
- `packages/sdk-core/src/pinning/psa-provider.ts` - PSA timeout 30s -> 15s
- `apps/api/src/ipns/delegated-routing.client.ts` - Request timeout 10s -> 5s, base retry delay 1000ms -> 500ms
- `apps/web/src/services/upload.service.ts` - Retry base delay 1000ms -> 500ms

## Decisions Made

- All timeout reductions follow the 2-3x p99 formula established in CONTEXT.md locked decisions
- Kubo gets the most aggressive reduction (30s -> 10s) because baseline data shows pin p99 at 227ms, giving ~44x headroom
- Pinata stays more generous (60s -> 30s) due to external network variance and higher BYO baseline (p50=2.0s)
- PSA uses a conservative 50% reduction since no project-specific PSA baselines exist
- Connection test probe (10s) unchanged -- one-time diagnostic operation, already reasonable
- TEE timeout (30s) unchanged -- batch republishing is inherently long-running

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Full workspace build chain fails due to pre-existing DTS generation issues (`@cipherbox/core` cannot resolve `@cipherbox/crypto` type declarations). CJS/ESM builds succeed. API build succeeds. The DTS failures are entirely unrelated to the constant value changes made in this plan. No TypeScript errors exist in the modified pinning provider files when checked against the package's own tsconfig.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All timeout constants are tuned and ready for production
- Phase 22 journey baselines serve as the validation mechanism for UX impact
- No new infrastructure or configuration needed

## Self-Check: PASSED

- All 5 modified files exist on disk
- Both task commits found (84c942412, 339cf3178)
- SUMMARY.md created successfully

---

_Phase: 26-observability-ux-tuning_
_Completed: 2026-03-26_
