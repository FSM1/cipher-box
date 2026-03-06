---
phase: 05-folder-system
plan: 01
subsystem: api
tags: [ipns, delegated-routing, typeorm, nestjs]

# Dependency graph
requires:
  - phase: 04-file-storage
    provides: IPFS upload/download, Vault entity
  - phase: 02-authentication
    provides: JwtAuthGuard, User entity
provides:
  - POST /ipns/publish endpoint for pre-signed IPNS records
  - FolderIpns entity tracking all folder IPNS names and CIDs
  - IpnsService with delegated routing client
  - Encrypted IPNS key storage for TEE republishing
affects: [05-02, 05-03, 08-tee-republishing]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Delegated routing API for IPNS publishing
    - Backend tracking of folder IPNS for redundancy
    - Exponential backoff retry for rate limits

key-files:
  created:
    - apps/api/src/ipns/entities/folder-ipns.entity.ts
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns.controller.ts
    - apps/api/src/ipns/ipns.module.ts
    - apps/api/src/ipns/dto/publish.dto.ts
  modified:
    - apps/api/src/app.module.ts
    - apps/api/scripts/generate-openapi.ts
    - packages/api-client/openapi.json

key-decisions:
  - 'Unique constraint on (userId, ipnsName) for folder tracking'
  - 'Sequence number as bigint string to handle large values'
  - 'Exponential backoff retry (max 3) for delegated routing'
  - 'encryptedIpnsPrivateKey required only on first publish'

patterns-established:
  - 'IPNS records pre-signed by client, relayed by backend'
  - 'Backend tracks all folder IPNS names for TEE republishing'

# Metrics
duration: 4min
completed: 2026-01-21
---

# Phase 5 Plan 01: Backend IPNS Module Summary

**POST /ipns/publish endpoint relaying pre-signed IPNS records to delegated-ipfs.dev with database tracking for TEE republishing**

## Performance

- **Duration:** 4 min
- **Started:** 2026-01-21T03:26:38Z
- **Completed:** 2026-01-21T03:30:40Z
- **Tasks:** 3
- **Files modified:** 9

## Accomplishments

- FolderIpns entity with unique (userId, ipnsName) constraint for tracking all folders
- IpnsService with delegated routing client and exponential backoff retry
- POST /ipns/publish endpoint with proper authentication and validation
- API client regenerated with typed ipns.publishRecord() method

## Task Commits

Each task was committed atomically:

1. **Task 1: Create FolderIpns entity and DTOs** - `b68dcb4` (feat)
2. **Task 2: Create IpnsService with delegated routing** - `eecb0ee` (feat)
3. **Task 3: Create IpnsController and IpnsModule** - `765b594` (feat)

## Files Created/Modified

- `apps/api/src/ipns/entities/folder-ipns.entity.ts` - FolderIpns entity with all fields for tracking
- `apps/api/src/ipns/entities/index.ts` - Entity exports
- `apps/api/src/ipns/dto/publish.dto.ts` - PublishIpnsDto and PublishIpnsResponseDto
- `apps/api/src/ipns/dto/index.ts` - DTO exports
- `apps/api/src/ipns/ipns.service.ts` - Service with delegated routing and folder tracking
- `apps/api/src/ipns/ipns.controller.ts` - POST /ipns/publish endpoint
- `apps/api/src/ipns/ipns.module.ts` - Module configuration with exports
- `apps/api/src/app.module.ts` - Added IpnsModule and FolderIpns entity
- `apps/api/scripts/generate-openapi.ts` - Added IpnsController and IpnsService

## Decisions Made

- **sequenceNumber as bigint string:** TypeORM returns bigint as string to avoid JavaScript precision issues; service increments using BigInt()
- **encryptedIpnsPrivateKey only on first publish:** Reduces payload size for updates; key stored once and reused for TEE republishing
- **Uint8Array body cast:** TypeScript 5.9 requires explicit cast for fetch body parameter
- **DELEGATED_ROUTING_URL configurable:** Default to delegated-ipfs.dev but allow override for testing

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed Uint8Array type for fetch body**

- **Found during:** Task 2 (IpnsService implementation)
- **Issue:** TypeScript 5.9 doesn't accept Uint8Array directly as fetch body
- **Fix:** Cast `recordBytes as unknown as BodyInit`
- **Files modified:** apps/api/src/ipns/ipns.service.ts
- **Verification:** Build passes
- **Committed in:** eecb0ee (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** TypeScript strictness required explicit cast. No scope creep.

## Issues Encountered

None - plan executed smoothly.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Backend IPNS module complete, ready for client-side IPNS record creation (Plan 02)
- FolderIpns entity tracks all folders for TEE republishing (Phase 8)
- API client has typed publishRecord() method for web integration

---

_Phase: 05-folder-system_
_Completed: 2026-01-21_
