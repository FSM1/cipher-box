---
phase: 21-byo-ipfs-node-support
plan: 05
subsystem: api, tee
tags: [bullmq, typeorm, migration, tee, ecies, ssrf-protection, express]

# Dependency graph
requires:
  - phase: 21-02
    provides: PinnedCid entity, isByoUser vault flag, CID registration endpoint
  - phase: 21-03
    provides: DualPinProvider, ByoIpfsConfig type, PinningConfig, mode-aware upload
provides:
  - PinMigration entity with status, progress counters, encrypted provider configs
  - MigrationService with full lifecycle management (start, pause, resume, cancel)
  - MigrationController REST endpoints protected by JwtAuthGuard
  - MigrationProcessor BullMQ worker for batch CID migration via TEE
  - TEE /migrate endpoint for in-enclave provider credential decryption and CID transfer
  - Database migration for pin_migrations table
  - 17 unit tests for MigrationService
affects: [21-06, 21-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      BullMQ processor for long-running migration jobs,
      SSRF protection for user-provided URLs,
      Uint8Array credential zeroing in TEE,
    ]

key-files:
  created:
    - apps/api/src/migration/migration.entity.ts
    - apps/api/src/migration/migration.service.ts
    - apps/api/src/migration/migration.service.spec.ts
    - apps/api/src/migration/migration.controller.ts
    - apps/api/src/migration/migration.processor.ts
    - apps/api/src/migration/migration.module.ts
    - apps/api/src/migration/dto/start-migration.dto.ts
    - apps/api/src/migration/dto/migration-status.dto.ts
    - apps/api/src/migrations/1742000000000-AddPinMigrations.ts
    - tee-worker/src/routes/migrate.ts
    - tee-worker/src/services/migration-worker.ts
  modified:
    - apps/api/src/app.module.ts
    - tee-worker/src/index.ts

key-decisions:
  - 'Migration uses existing BullMQ pattern (same as republish) with pin-migration queue name'
  - 'TEE migration worker uses epoch-based ECIES decryption via getKeypair() rather than separate key parameter'
  - 'SSRF protection validates both URL structure and DNS resolution to block private IPs and rebinding attacks'
  - 'Combined per-task commits with api-client regeneration due to pre-commit hook requirements'

patterns-established:
  - 'BullMQ processor checks migration status before each batch for pause/resume/cancel support'
  - 'TEE credential zeroing: Uint8Array.fill(0) in finally block for all auth tokens and decrypted configs'
  - 'SSRF validation: validateEndpointUrl() for URL structure + validateResolvedIp() for DNS rebinding'

requirements-completed: [BYO-03]

# Metrics
duration: 9min
completed: 2026-03-24
---

# Phase 21 Plan 05: Pin Migration Backend Summary

**TEE-based pin migration infrastructure with BullMQ orchestration, ECIES credential decryption, SSRF-protected provider transfer, and 17 unit tests**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-24T14:37:24Z
- **Completed:** 2026-03-24T14:46:45Z
- **Tasks:** 2
- **Files modified:** 13

## Accomplishments

- PinMigration entity and service manage full migration lifecycle (start, pause, resume, cancel, progress tracking)
- BullMQ processor batches CIDs and calls TEE worker via HTTP with pause/cancel checks between batches
- TEE /migrate endpoint decrypts ECIES-encrypted provider configs in-enclave, transfers encrypted blobs, verifies CID integrity
- SSRF protection on user-provided endpoint URLs (HTTPS-only, private IP blocking, DNS rebinding checks)
- All auth tokens processed as Uint8Array and zeroed with .fill(0) in finally blocks
- 17 MigrationService unit tests covering all lifecycle operations

## Task Commits

Each task was committed atomically:

1. **Task 1: Migration entity, service, controller, BullMQ processor, module, and unit tests** - `fe1b6f4cb` (feat)
2. **Task 2: TEE worker migration endpoint and migration worker service** - `32bbae396` (feat)

## Files Created/Modified

- `apps/api/src/migration/migration.entity.ts` - PinMigration entity with status, progress, encrypted configs
- `apps/api/src/migration/migration.service.ts` - Migration lifecycle: start, pause, resume, cancel, updateProgress
- `apps/api/src/migration/migration.service.spec.ts` - 17 unit tests for MigrationService
- `apps/api/src/migration/migration.controller.ts` - REST endpoints: POST start, GET status, POST pause/resume/cancel
- `apps/api/src/migration/migration.processor.ts` - BullMQ processor batching CIDs and calling TEE worker
- `apps/api/src/migration/migration.module.ts` - NestJS module wiring entity, service, controller, processor
- `apps/api/src/migration/dto/start-migration.dto.ts` - DTO with ECIES-encrypted source/dest configs
- `apps/api/src/migration/dto/migration-status.dto.ts` - DTO for migration status response
- `apps/api/src/migrations/1742000000000-AddPinMigrations.ts` - CREATE TABLE IF NOT EXISTS pin_migrations
- `apps/api/src/app.module.ts` - Added MigrationModule and PinMigration entity
- `tee-worker/src/routes/migrate.ts` - POST /migrate endpoint for batch CID migration
- `tee-worker/src/services/migration-worker.ts` - Core migration logic with SSRF protection and credential zeroing
- `tee-worker/src/index.ts` - Registered /migrate route with auth middleware

## Decisions Made

- Migration uses existing BullMQ pattern (same as republish) with `pin-migration` queue name for consistency
- TEE migration worker uses epoch-based ECIES decryption via `getKeypair()` rather than a separate key parameter, since provider configs are encrypted with the TEE epoch public key
- SSRF protection validates both URL structure and DNS resolution to block private IPs and rebinding attacks
- Pre-commit hook required api:generate for controller/DTO changes, so Task 1 includes regenerated client files

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Pre-commit hook required API client regeneration**

- **Found during:** Task 1 (committing migration controller and DTOs)
- **Issue:** Pre-commit hook checks for regenerated API client when controllers/DTOs are staged
- **Fix:** Ran `pnpm openapi:generate && pnpm --filter @cipherbox/api-client generate && pnpm --filter @cipherbox/api-client build`
- **Files modified:** packages/api-client/openapi.json (generated files auto-staged by lint-staged)
- **Verification:** Commit succeeded with all files
- **Committed in:** fe1b6f4cb (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Auto-fix necessary to satisfy pre-commit hook. No scope creep.

## Issues Encountered

- TEE worker `tsc --noEmit` reports pre-existing module resolution errors (@types/node, express, eciesjs not found) across all files. New files have only the same pre-existing errors (28 existing + 6 new from same root cause). Not a regression.
- `pnpm api:generate` lint:fix step fails on pre-existing ESLint error in unrelated file (`react-hooks/exhaustive-deps` rule not found). Worked around by running the generation steps individually.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Migration backend infrastructure complete, ready for UI integration in Plan 06
- TEE /migrate endpoint ready for integration testing
- MigrationController endpoints available for client SDK to call

---

## Self-Check: PASSED

All 13 files verified present. Both task commits (fe1b6f4cb, 32bbae396) found in git history.

_Phase: 21-byo-ipfs-node-support_
_Completed: 2026-03-24_
