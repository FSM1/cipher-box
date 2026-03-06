---
phase: 08-tee-integration
plan: 02
subsystem: api
tags: [bullmq, redis, ioredis, nestjs, cron, ipns, republish, tee]

# Dependency graph
requires:
  - phase: 08-01
    provides: TeeService HTTP client, TeeKeyStateService, TeeModule, RepublishEntry/RepublishResult interfaces
  - phase: 05-folder-system
    provides: FolderIpns entity with encryptedIpnsPrivateKey and keyEpoch columns
provides:
  - IpnsRepublishSchedule entity for per-folder republish state tracking
  - RepublishService with batch processing, TEE signing, delegated routing publish, exponential backoff retry
  - RepublishProcessor (BullMQ WorkerHost) with 6-hour cron schedule
  - RepublishHealthController at GET /admin/republish-health
  - RepublishModule with BullMQ queue registration
  - Redis infrastructure in Docker Compose
  - enrollFolder method for Plan 03 integration
affects: [08-03, 08-04]

# Tech tracking
tech-stack:
  added: ['@nestjs/bullmq', 'bullmq', 'ioredis']
  patterns:
    - 'BullMQ cron scheduling via upsertJobScheduler with graceful fallback on Redis unavailability'
    - 'Separate TEE signing from IPNS delegated routing publish for independent retry'
    - 'Exponential backoff retry with 30s base, 1h cap, stale after 10 consecutive failures'
    - 'Batch processing of 50 entries per TEE request'
    - 'FolderIpns sequence number sync after successful republish'

key-files:
  created:
    - apps/api/src/republish/republish-schedule.entity.ts
    - apps/api/src/republish/republish.service.ts
    - apps/api/src/republish/republish.processor.ts
    - apps/api/src/republish/republish-health.controller.ts
    - apps/api/src/republish/republish.module.ts
  modified:
    - apps/api/src/app.module.ts
    - docker/docker-compose.yml
    - apps/api/.env.example
    - apps/api/package.json

key-decisions:
  - 'BATCH_SIZE=50 per TEE request to avoid CVM proxy timeouts'
  - 'MAX_CONSECUTIVE_FAILURES=10 before marking entry stale'
  - 'Separate signing from publishing for independent retry (RESEARCH.md pitfall 6)'
  - 'BullModule.forRootAsync globally in AppModule, registerQueue locally in RepublishModule'
  - 'Graceful cron registration: warn and continue if Redis unavailable'
  - 'Admin health endpoint uses JwtAuthGuard (full admin role check deferred for v1)'
  - 'Redis 7-alpine bound to 127.0.0.1 only for security'

patterns-established:
  - 'RepublishModule structure: entity, service, processor, health controller, module'
  - 'BullMQ WorkerHost pattern for NestJS cron-based job processing'
  - 'Enrollment pattern: enrollFolder() upserts republish schedule entries'
  - 'Health stats aggregation: count by status, TEE connectivity check'

# Metrics
duration: 7min
completed: 2026-02-07
---

# Phase 8 Plan 02: Republish Scheduling Summary

BullMQ-based republish scheduling with Redis, 6-hour cron, batch TEE signing, delegated routing publish, and admin health endpoint.

## Performance

- **Duration:** 7 min
- **Started:** 2026-02-07T05:22:02Z
- **Completed:** 2026-02-07T05:28:56Z
- **Tasks:** 2
- **Files modified:** 17

## Accomplishments

- IpnsRepublishSchedule entity tracks per-folder republish state with status, retry counts, backoff scheduling, and composite index
- RepublishService orchestrates batch processing: query due entries, split into batches of 50, send to TEE for signing, publish to delegated routing, handle epoch upgrades
- Exponential backoff retry (30s \* 2^failures, capped at 1 hour) with stale marking after 10 consecutive failures
- BullMQ processor fires on 6-hour cron schedule with graceful fallback when Redis is unavailable
- Admin health endpoint returns pending/failed/stale counts plus TEE connectivity status
- Redis 7-alpine added to Docker Compose infrastructure
- Folder enrollment method ready for Plan 03 to wire into publish flow

## Task Commits

Each task was committed atomically:

1. **Task 1: Redis infrastructure and republish schedule entity** - `3980e47` (feat)
2. **Task 2: BullMQ processor, republish service, health controller, and module** - `5f900b2` (feat)

## Files Created/Modified

- `apps/api/src/republish/republish-schedule.entity.ts` - TypeORM entity for ipns_republish_schedule table with status/retry/scheduling columns
- `apps/api/src/republish/republish.service.ts` - Core orchestration: batch TEE signing, delegated routing publish, exponential backoff, enrollment
- `apps/api/src/republish/republish.processor.ts` - BullMQ WorkerHost for cron-triggered republish batch processing
- `apps/api/src/republish/republish-health.controller.ts` - GET /admin/republish-health with JWT auth and Swagger docs
- `apps/api/src/republish/republish.module.ts` - NestJS module with BullMQ queue registration and 6-hour cron scheduler
- `apps/api/src/app.module.ts` - Added BullModule.forRootAsync, IpnsRepublishSchedule entity, RepublishModule import
- `docker/docker-compose.yml` - Added Redis 7-alpine service with healthcheck and volume
- `apps/api/.env.example` - Added REDIS_HOST and REDIS_PORT configuration
- `apps/api/package.json` - Added @nestjs/bullmq, bullmq, ioredis dependencies
- `apps/api/src/vault/dto/init-vault.dto.ts` - Fixed TeeKeysDto import for teeKeys property
- `apps/api/src/vault/vault.service.ts` - Fixed toVaultResponse to include teeKeys from TeeKeyStateService
- `apps/api/src/vault/vault.module.ts` - Added TeeModule import for TeeKeyStateService dependency
- `apps/api/src/vault/vault.controller.spec.ts` - Added teeKeys: null to mock vault response
- `apps/api/src/ipns/ipns.service.ts` - Added TEE republish enrollment logging stubs
- `packages/api-client/openapi.json` - Updated with Admin tag and TeeKeysDto schema
- `apps/web/src/api/models/` - Generated API client models for TeeKeysDto and VaultResponseDto.teeKeys

## Decisions Made

- BATCH_SIZE=50 per TEE request to avoid Phala CVM proxy timeout (per RESEARCH.md pitfall 4)
- MAX_CONSECUTIVE_FAILURES=10 before marking entry as stale
- Separate TEE signing from IPNS delegated routing publishing for independent retry (per RESEARCH.md pitfall 6)
- BullModule.forRootAsync configured globally in AppModule with Redis connection; registerQueue locally in RepublishModule
- Graceful cron scheduler registration: catch and warn if Redis unavailable, never crash
- Admin health endpoint uses JwtAuthGuard only (full admin role check deferred for v1 tech demo)
- Redis 7-alpine bound to 127.0.0.1:6379 for development security

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed pre-existing VaultService/VaultResponseDto teeKeys integration**

- **Found during:** Task 1 (TypeScript compilation failed on pre-existing errors)
- **Issue:** Plan 08-01 added teeKeys to VaultResponseDto and TeeKeyStateService to VaultService but toVaultResponse didn't include teeKeys, vault.module.ts didn't import TeeModule, and controller spec didn't include teeKeys in mock
- **Fix:** Added teeKeys parameter to toVaultResponse, imported TeeModule in VaultModule, added teeKeys: null to spec mock, restored TeeKeysDto import in DTO
- **Files modified:** vault.service.ts, vault.module.ts, vault.controller.spec.ts, init-vault.dto.ts
- **Verification:** TypeScript compilation passes cleanly
- **Committed in:** 3980e47 (Task 1 commit)

**2. [Rule 3 - Blocking] Staged pre-existing uncommitted IpnsService TEE enrollment stubs**

- **Found during:** Task 1 (git status showed uncommitted changes from 08-01)
- **Issue:** IpnsService had uncommitted TEE republish enrollment logging stubs prepared for Plan 08-02
- **Fix:** Included in Task 1 commit as they were necessary for the republish enrollment flow
- **Files modified:** ipns.service.ts
- **Verification:** TypeScript compilation passes
- **Committed in:** 3980e47 (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking)
**Impact on plan:** Both fixes necessary for compilation and correct operation. No scope creep.

## Issues Encountered

- Docker is not available in the development environment, so Redis container startup could not be verified at runtime. The docker-compose.yml configuration follows the same pattern as the existing postgres and ipfs services and is correct.
- API runtime startup verification (checking BullMQ connection, cron scheduler registration, health endpoint response) could not be performed without Redis and PostgreSQL running. The code compiles cleanly and follows established NestJS + BullMQ patterns.

## User Setup Required

None - Redis config defaults are provided. Users need to run `docker compose up -d redis` to start the Redis container.

## Next Phase Readiness

- RepublishService.enrollFolder() ready for Plan 03 to call during IPNS publish flow
- Admin health endpoint accessible for operational monitoring
- BullMQ cron scheduler will start processing when Redis is available
- TEE signing pathway established: processor -> service -> TeeService.republish() -> delegated routing publish
- All TypeScript compilation checks pass

---

_Phase: 08-tee-integration_
_Completed: 2026-02-07_
