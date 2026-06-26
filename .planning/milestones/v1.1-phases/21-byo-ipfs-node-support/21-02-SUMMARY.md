---
phase: 21-byo-ipfs-node-support
plan: 02
subsystem: api
tags: [nestjs, ipfs, quota, byo, typeorm, migration]

# Dependency graph
requires:
  - phase: 21-byo-ipfs-node-support
    provides: PinningProvider interface (plan 01)
provides:
  - POST /ipfs/register-cid endpoint for BYO CID registration
  - Advisory quota mode (non-enforced) for BYO users
  - isByoUser flag on vault entity with migration
  - isUserByo() and setByoStatus() methods on VaultService
  - advisory boolean field on QuotaResponseDto
affects: [21-03, 21-04, 21-05, 21-06, 21-07]

# Tech tracking
tech-stack:
  added: []
  patterns: [advisory-quota-mode, byo-user-gate]

key-files:
  created:
    - apps/api/src/ipfs/dto/register-cid.dto.ts
    - apps/api/src/migrations/1740600000000-AddByoUserFlag.ts
    - packages/api-client/src/models/registerCidDto.ts
    - packages/api-client/src/models/registerCidResponseDto.ts
  modified:
    - apps/api/src/ipfs/ipfs.controller.ts
    - apps/api/src/ipfs/dto/index.ts
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/vault/dto/quota.dto.ts
    - apps/api/src/vault/entities/vault.entity.ts
    - apps/api/src/ipfs/ipfs.controller.spec.ts
    - apps/api/src/vault/vault.service.spec.ts
    - packages/api-client/openapi.json
    - packages/api-client/src/generated/ipfs/ipfs.ts
    - packages/api-client/src/models/index.ts
    - packages/api-client/src/models/quotaResponseDto.ts

key-decisions:
  - 'CID registration gated to BYO users only via ForbiddenException (non-BYO users cannot bypass upload relay)'
  - 'Advisory quota mode: checkQuota returns true unconditionally for BYO users, getQuota includes advisory boolean'
  - 'Rate limit of 100 register-cid calls per hour per user to prevent DB storage abuse'
  - 'Combined implementation and api-client regeneration into single commit due to pre-commit hook enforcement'

patterns-established:
  - 'BYO user gate: isUserByo() check before BYO-only endpoints'
  - 'Advisory quota pattern: advisory boolean flag distinguishes enforced vs informational quota'

requirements-completed: [BYO-07]

# Metrics
duration: 6min
completed: 2026-03-24
---

# Phase 21 Plan 02: CID Registration and Advisory Quota Summary

**POST /ipfs/register-cid endpoint with BYO-user gate, advisory quota mode bypassing enforcement for BYO users, and isByoUser vault flag with migration**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-24T14:10:57Z
- **Completed:** 2026-03-24T14:17:51Z
- **Tasks:** 2
- **Files modified:** 15

## Accomplishments

- Created POST /ipfs/register-cid endpoint with CID format validation (CIDv0/CIDv1), size cap (100MB), BYO-user authorization gate, and rate limiting (100/hour)
- Made VaultService.checkQuota() return true unconditionally for BYO users (advisory-only quota)
- Added advisory boolean field to QuotaResponseDto so clients distinguish enforced vs informational quota
- Added isByoUser column to vaults table with idempotent IF NOT EXISTS migration
- Added isUserByo() and setByoStatus() methods to VaultService
- Wrote 13 new unit tests covering registerCid, isUserByo, setByoStatus, BYO quota bypass, and advisory flag

## Task Commits

Each task was committed atomically:

1. **Task 1: Add RegisterCid endpoint, advisory quota mode, and isByoUser flag** - `4ed75b6d0` (feat)
2. **Task 2: Unit tests for CID registration and advisory quota** - `3d328749d` (test)

## Files Created/Modified

- `apps/api/src/ipfs/dto/register-cid.dto.ts` - RegisterCidDto with CID format validation and size constraints
- `apps/api/src/ipfs/ipfs.controller.ts` - POST /ipfs/register-cid endpoint with BYO gate and rate limiting
- `apps/api/src/ipfs/dto/index.ts` - Barrel export for new DTOs
- `apps/api/src/vault/vault.service.ts` - isUserByo(), setByoStatus(), advisory quota in getQuota/checkQuota
- `apps/api/src/vault/dto/quota.dto.ts` - Added advisory boolean field
- `apps/api/src/vault/entities/vault.entity.ts` - Added isByoUser column
- `apps/api/src/migrations/1740600000000-AddByoUserFlag.ts` - Migration for is_byo_user column
- `apps/api/src/ipfs/ipfs.controller.spec.ts` - 4 new tests for registerCid endpoint
- `apps/api/src/vault/vault.service.spec.ts` - 9 new tests for BYO methods and advisory quota
- `packages/api-client/` - Regenerated OpenAPI spec and typed client with new endpoint/models

## Decisions Made

- CID registration gated to BYO users only (ForbiddenException) -- prevents non-BYO users from bypassing the upload relay and quota enforcement
- Advisory quota: checkQuota() always returns true for BYO, getQuota() includes `advisory: boolean` flag
- Rate limit of 100 register-cid calls per hour per user to prevent bulk CID insertion DB abuse
- Combined feat commit with api-client regeneration due to pre-commit hook requiring client sync

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Updated existing vault.service.spec.ts assertions for advisory field**

- **Found during:** Task 1 (implementation)
- **Issue:** Existing getQuota tests expected 3-field response object; new advisory field caused 5 test failures
- **Fix:** Added `advisory: false` to all existing getQuota test assertions
- **Files modified:** apps/api/src/vault/vault.service.spec.ts
- **Verification:** All 43 existing tests pass
- **Committed in:** 4ed75b6d0 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 bug fix)
**Impact on plan:** Necessary update to existing tests after DTO schema change. No scope creep.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Register-cid endpoint ready for BYO client integration
- Advisory quota mode ready for UI quota display
- isByoUser flag ready for vault configuration endpoint (plan 03+)
- api-client regenerated with new types for frontend consumption

---

_Phase: 21-byo-ipfs-node-support_
_Completed: 2026-03-24_

## Self-Check: PASSED

All 10 key files verified present. Both task commits (4ed75b6d0, 3d328749d) verified in git log.
