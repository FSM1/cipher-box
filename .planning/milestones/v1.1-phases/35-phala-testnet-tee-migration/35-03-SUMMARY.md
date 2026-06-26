---
phase: 35-phala-testnet-tee-migration
plan: 03
subsystem: infra
tags: [phala, dstack-sdk, prometheus, prom-client, structured-logging, tee, docker]

# Dependency graph
requires:
  - phase: 35-01
    provides: TEE worker moved to apps/tee-worker with shared package integration
provides:
  - '@phala/dstack-sdk installed as real dependency with defensive CVM key derivation'
  - 'Phala Cloud CVM docker-compose for deployment'
  - 'Prometheus metrics endpoint (GET /metrics) with cipherbox_tee_* prefix'
  - 'HTTP request duration histogram, republish and migration counters'
  - 'Structured JSON logger replacing all console.log/console.error'
affects: [35-04, 35-05, 35-06]

# Tech tracking
tech-stack:
  added: ['@phala/dstack-sdk@^0.5.7', 'prom-client@^15.1.3']
  patterns: ['cipherbox_tee_* Prometheus metric naming', 'Newline-delimited JSON structured logging', 'Defensive SDK return type handling']

key-files:
  created:
    - apps/tee-worker/docker-compose.phala.yml
    - apps/tee-worker/src/middleware/metrics.ts
    - apps/tee-worker/src/routes/metrics.ts
    - apps/tee-worker/src/services/logger.ts
  modified:
    - apps/tee-worker/package.json
    - apps/tee-worker/src/services/tee-keys.ts
    - apps/tee-worker/docker-compose.yml
    - apps/tee-worker/src/index.ts
    - apps/tee-worker/src/routes/republish.ts
    - apps/tee-worker/src/routes/migrate.ts
    - apps/tee-worker/src/routes/public-key.ts
    - apps/tee-worker/src/routes/connection-test.ts

key-decisions:
  - 'Removed custom dstack-sdk.d.ts since SDK ships own types'
  - 'Defensive CVM key derivation handles both key (v0.5+) and asUint8Array (legacy) return types'
  - 'Metrics use cipherbox_tee_* prefix for Grafana dashboard coexistence with API metrics'
  - 'Structured logger has zero external dependencies (JSON.stringify to stdout/stderr)'

patterns-established:
  - 'cipherbox_tee_* Prometheus metric prefix for TEE worker metrics coexisting with API cipherbox_* metrics'
  - 'Newline-delimited JSON structured logging for log aggregator compatibility'

requirements-completed: []

# Metrics
duration: 8min
completed: 2026-03-29
---

# Phase 35 Plan 03: CVM Integration and Observability Summary

**dstack SDK installed with defensive CVM key derivation, Phala CVM docker-compose, Prometheus metrics (HTTP duration + operation counters), and structured JSON logging**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-29T11:15:34Z
- **Completed:** 2026-03-29T11:23:54Z
- **Tasks:** 4
- **Files modified:** 14

## Accomplishments

- Installed @phala/dstack-sdk as real dependency with defensive handling for both SDK v0.5+ (key: Uint8Array) and legacy (asUint8Array()) return types
- Created Phala CVM docker-compose.phala.yml with identity preservation warning; updated existing compose from tappd.sock to dstack.sock
- Added Prometheus metrics endpoint with HTTP request duration histogram, republish entries counter, and migration CIDs counter (all with cipherbox_tee_* prefix)
- Replaced all console.log/console.error with structured JSON logger (zero external dependencies, newline-delimited JSON to stdout/stderr)

## Task Commits

Each task was committed atomically:

1. **Task 1: Install dstack SDK and update CVM code path** - `1b95d7bcd` (feat)
2. **Task 2: Create Phala CVM docker-compose and update existing compose** - `5bad6b3b0` (feat)
3. **Task 3: Add Prometheus metrics with prom-client** - `278dc1255` (feat)
4. **Task 4: Add structured JSON logging** - `04484c814` (feat)

## Files Created/Modified

- `apps/tee-worker/package.json` - Added @phala/dstack-sdk and prom-client dependencies
- `apps/tee-worker/src/services/tee-keys.ts` - Defensive CVM key derivation handling both SDK return types
- `apps/tee-worker/src/types/dstack-sdk.d.ts` - Removed (SDK ships own types)
- `apps/tee-worker/docker-compose.yml` - Updated socket path from tappd.sock to dstack.sock
- `apps/tee-worker/docker-compose.phala.yml` - New Phala Cloud CVM deployment compose file
- `apps/tee-worker/src/middleware/metrics.ts` - Prometheus HTTP metrics middleware and operation counters
- `apps/tee-worker/src/routes/metrics.ts` - GET /metrics endpoint for Prometheus scraping
- `apps/tee-worker/src/services/logger.ts` - Minimal structured JSON logger
- `apps/tee-worker/src/index.ts` - Wired metrics middleware, metrics route, and logger
- `apps/tee-worker/src/routes/republish.ts` - Added republish counter increments and logger
- `apps/tee-worker/src/routes/migrate.ts` - Added migration counter increments and logger
- `apps/tee-worker/src/routes/public-key.ts` - Replaced console.error with logger
- `apps/tee-worker/src/routes/connection-test.ts` - Replaced console.error with logger

## Decisions Made

- **Removed custom type declarations:** @phala/dstack-sdk@0.5.7 ships its own TypeScript types in dist/node/index.d.ts, making the custom dstack-sdk.d.ts unnecessary and potentially conflicting
- **Defensive key extraction:** SDK v0.5+ GetKeyResponse has `key: Uint8Array` directly; older versions used `asUint8Array()`. Code checks both at runtime via `unknown` cast to avoid TypeScript narrowing issues
- **Zero-dependency logger:** Structured JSON logging uses only process.stdout.write/process.stderr.write with JSON.stringify -- no pino, winston, or other logging framework needed for a small TEE worker
- **Metric naming convention:** Uses `cipherbox_tee_*` prefix so TEE worker and API metrics can coexist on the same Grafana dashboard (API uses `cipherbox_*` prefix)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Shared packages (@cipherbox/crypto, @cipherbox/core, @cipherbox/sdk-core) needed to be built before tsc --noEmit could pass -- resolved by running build steps in dependency order

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- TEE worker is ready for Phala Cloud CVM deployment with observability
- Plan 04 (CI/CD pipeline) can build on docker-compose.phala.yml and the Dockerfile
- Plan 05 (testnet deployment) can deploy with Prometheus metrics enabled

## Self-Check: PASSED

All 9 created/modified files verified present. All 4 task commits verified in git log.

---

_Phase: 35-phala-testnet-tee-migration_
_Completed: 2026-03-29_
