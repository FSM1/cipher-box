---
phase: 29-infrastructure-hardening
plan: 01
subsystem: api
tags: [nestjs, ipns, tee, republish, openapi, orval]

requires:
  - phase: 25-desktop-enhancements
    provides: RepublishService.unenrollIpns() method
provides:
  - POST /ipns/unenroll batch endpoint (up to 200 IPNS names)
  - BatchUnenrollIpnsDto and BatchUnenrollIpnsResponseDto types
  - ipnsControllerUnenrollBatch in @cipherbox/api-client
affects: [29-02, sdk, delete-flow]

tech-stack:
  added: []
  patterns: [batch-unenroll-pattern matching batch-publish]

key-files:
  created:
    - apps/api/src/ipns/dto/unenroll.dto.ts
    - packages/api-client/src/models/batchUnenrollIpnsDto.ts
    - packages/api-client/src/models/batchUnenrollIpnsResponseDto.ts
  modified:
    - apps/api/src/ipns/dto/index.ts
    - apps/api/src/ipns/ipns.controller.ts
    - apps/api/src/ipns/ipns.service.ts
    - packages/api-client/src/generated/ipns/ipns.ts

key-decisions:
  - 'Followed batch-publish pattern: ArrayMaxSize(200), per-item error handling with warn logging'
  - 'Throttle at 5 per minute matching batch-publish limit'

patterns-established:
  - 'Batch unenroll follows same DTO validation and error handling as batch publish'

requirements-completed: []

duration: 5min
completed: 2026-03-28
---

# Plan 29-01: IPNS Batch Unenroll API Endpoint Summary

**POST /ipns/unenroll endpoint with BatchUnenrollIpnsDto validation, IpnsService.unenrollBatch, and regenerated API client**

## Performance

- **Duration:** 5 min
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Created unenroll DTO with IPNS name validation (regex, array max 200)
- Added unenrollBatch method to IpnsService delegating to RepublishService.unenrollIpns
- Added POST /ipns/unenroll endpoint to IpnsController with JWT auth and throttling
- Regenerated API client exposing ipnsControllerUnenrollBatch function

## Task Commits

1. **Task 1: Create DTO and endpoint** - `0efaaaea4` (feat)
2. **Task 2: Regenerate API client** - `c7b1d56e4` (chore)

## Files Created/Modified

- `apps/api/src/ipns/dto/unenroll.dto.ts` - BatchUnenrollIpnsDto and response DTO
- `apps/api/src/ipns/dto/index.ts` - Re-export new DTOs
- `apps/api/src/ipns/ipns.controller.ts` - POST /ipns/unenroll endpoint
- `apps/api/src/ipns/ipns.service.ts` - unenrollBatch method
- `packages/api-client/src/generated/ipns/ipns.ts` - Generated unenroll client function
- `packages/api-client/src/models/batchUnenrollIpnsDto.ts` - Generated model
- `packages/api-client/src/models/batchUnenrollIpnsResponseDto.ts` - Generated model

## Decisions Made

None - followed plan as specified

## Deviations from Plan

None - plan executed exactly as written

## Issues Encountered

None

## Next Phase Readiness

- API endpoint ready for SDK integration (Plan 29-02)
- API client function ipnsControllerUnenrollBatch available for import

---

_Phase: 29-infrastructure-hardening_
_Completed: 2026-03-28_
