---
phase: 15-link-sharing
plan: 01
subsystem: api
tags: [nestjs, typeorm, invite-links, ecies, ephemeral-key, migration]

# Dependency graph
requires:
  - phase: 14
    provides: Share/ShareKey entities, SharesService.createShare(), SharesModule
provides:
  - ShareInvite entity with token, encryptedKey, encryptedChildKeys (JSONB), status lifecycle
  - Migration 1740400000000 creates share_invites table idempotently
  - InvitesController at /invites (public status + authenticated data + claim)
  - ShareInvitesController at /shares/invites (authenticated create/list/revoke)
  - 6 invite service methods on SharesService
  - Orval-generated API client for invites and share-invites endpoints
affects:
  - 15-02 (frontend invite service uses generated API client)
  - 15-03 (ShareDialog and InvitePage consume invite endpoints)
  - 15-04 (E2E tests exercise invite endpoints)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Two-controller pattern for mixed auth endpoints (public + authenticated under different prefixes)'
    - 'Auto-expire on read pattern for short-lived invite records (Phase 12.4 DeviceApproval pattern)'
    - 'Atomic UPDATE for single-claim race condition prevention'

key-files:
  created:
    - apps/api/src/shares/entities/share-invite.entity.ts
    - apps/api/src/shares/invites.controller.ts
    - apps/api/src/shares/share-invites.controller.ts
    - apps/api/src/shares/dto/create-invite.dto.ts
    - apps/api/src/shares/dto/claim-invite.dto.ts
    - apps/api/src/shares/dto/invite-response.dto.ts
    - apps/api/src/migrations/1740400000000-AddShareInvites.ts
    - apps/web/src/api/invites/invites.ts
    - apps/web/src/api/share-invites/share-invites.ts
  modified:
    - apps/api/src/shares/shares.service.ts
    - apps/api/src/shares/shares.module.ts
    - apps/api/src/app.module.ts
    - apps/api/scripts/generate-openapi.ts
    - apps/api/src/shares/entities/index.ts

key-decisions:
  - 'Two controller classes for mixed auth: InvitesController (no class-level guard) and ShareInvitesController (class-level JwtAuthGuard)'
  - 'Authenticated GET /invites/:token/data for claim flow: separate from public status check'
  - 'Hard-delete expired invites on read (not soft-delete): consistent with auto-cleanup pattern'

patterns-established:
  - 'Two-controller pattern: When a single NestJS module needs both public and authenticated endpoints at different route prefixes, create separate controller classes'
  - 'Atomic single-claim via UPDATE WHERE: prevents race conditions without pessimistic locking'

# Metrics
duration: 7min
completed: 2026-02-23
---

# Phase 15 Plan 01: Invite Link Backend Summary

**ShareInvite entity, migration, two controllers (public + authenticated), 6 invite service methods with atomic single-claim and auto-expire on read**

## Performance

- **Duration:** 7 min
- **Started:** 2026-02-23T00:42:42Z
- **Completed:** 2026-02-23T00:50:26Z
- **Tasks:** 2
- **Files modified:** 27

## Accomplishments

- ShareInvite entity with all columns (token, encryptedKey, encryptedChildKeys JSONB, status, expiresAt, claimedBy, maxClaims)
- Migration 1740400000000 creates share_invites table with IF NOT EXISTS, unique token constraint, FK to users, indexes
- InvitesController at /invites: public status check (no auth), authenticated data fetch (returns encrypted keys), authenticated claim
- ShareInvitesController at /shares/invites: authenticated create, list by ipnsName, revoke by inviteId
- SharesService extended with 6 invite methods: createInvite, getInviteStatus, getInviteForClaim, claimInvite, getInvitesForItem, revokeInvite
- Claim flow creates standard Phase 14 Share + ShareKey records from re-wrapped keys
- Orval-generated API client includes invites and share-invites endpoints

## Task Commits

Each task was committed atomically:

1. **Task 1: ShareInvite entity, migration, and DTOs** - `ce31cf418` (feat)
2. **Task 2: Two controller classes, service methods, and module registration** - `f6468bf74` (feat)

## Files Created/Modified

- `apps/api/src/shares/entities/share-invite.entity.ts` - ShareInvite TypeORM entity with all columns
- `apps/api/src/shares/entities/index.ts` - Updated to export ShareInvite
- `apps/api/src/migrations/1740400000000-AddShareInvites.ts` - CREATE TABLE IF NOT EXISTS migration
- `apps/api/src/shares/dto/create-invite.dto.ts` - CreateInviteDto with class-validator decorators
- `apps/api/src/shares/dto/claim-invite.dto.ts` - ClaimInviteDto for re-wrapped keys
- `apps/api/src/shares/dto/invite-response.dto.ts` - InviteResponseDto, InviteStatusResponseDto, InviteDataResponseDto
- `apps/api/src/shares/invites.controller.ts` - Public-facing controller at /invites (no class-level auth)
- `apps/api/src/shares/share-invites.controller.ts` - Authenticated controller at /shares/invites
- `apps/api/src/shares/shares.service.ts` - Extended with 6 invite methods + ShareInvite repository
- `apps/api/src/shares/shares.module.ts` - ShareInvite in forFeature, both controllers registered
- `apps/api/src/app.module.ts` - ShareInvite added to entities array
- `apps/api/scripts/generate-openapi.ts` - Both controllers, mock repo, API tags added
- `apps/web/src/api/invites/invites.ts` - Generated Orval client for /invites endpoints
- `apps/web/src/api/share-invites/share-invites.ts` - Generated Orval client for /shares/invites endpoints
- `packages/api-client/openapi.json` - Updated OpenAPI spec with invite endpoints

## Decisions Made

- Two controller classes for mixed auth: InvitesController at /invites (no class-level JwtAuthGuard -- individual endpoints opt in) and ShareInvitesController at /shares/invites (class-level JwtAuthGuard). NestJS requires one @Controller() per class for different path prefixes.
- Authenticated GET /invites/:token/data is a separate endpoint from public GET /invites/:token. The public endpoint returns only status (opaque). The data endpoint requires auth and returns encryptedKey + encryptedChildKeys for the claim flow.
- Hard-delete expired invites on read (not soft-delete or status change). Consistent with Phase 12.4 DeviceApproval auto-expire pattern but simplified since invites have no audit value.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Backend invite infrastructure complete, ready for Plan 15-02 (API client regen + frontend invite service with ephemeral key bridge crypto)
- Generated API client already available for frontend consumption
- No blockers

---

_Phase: 15-link-sharing_
_Completed: 2026-02-23_
