---
phase: 27-writable-shares-poc
plan: 01
subsystem: api
tags: [typeorm, nestjs, shares, ipns, ecies, authorization]

# Dependency graph
requires:
  - phase: 14-sharing
    provides: Share entity, SharesService, SharesController, IPNS publish infrastructure
provides:
  - Share entity with permission and encryptedIpnsKey columns
  - DB migration for writable share columns
  - UpdatePermissionDto and PATCH /shares/:shareId/permission endpoint
  - findActiveWriteShare service method for IPNS publish authorization
  - IPNS publish authorization expanded to write-share recipients
  - Regenerated API client with permission types
affects: [27-02, 27-03, web-sharing-ui, desktop-sharing, sdk-shares]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Write-share authorization fallback in IPNS publish path
    - Permission upgrade/downgrade with ECIES key management
    - TEE enrollment uses FolderIpns owner userId (not authenticated user)

key-files:
  created:
    - apps/api/src/migrations/1743000000000-AddWritableShares.ts
    - apps/api/src/shares/dto/update-permission.dto.ts
    - packages/api-client/src/models/updatePermissionDto.ts
    - packages/api-client/src/models/updatePermissionDtoPermission.ts
    - packages/api-client/src/models/createShareDtoPermission.ts
    - packages/api-client/src/models/createShareResponseDtoPermission.ts
    - packages/api-client/src/models/receivedShareResponseDtoPermission.ts
    - packages/api-client/src/models/receivedShareResponseDtoEncryptedIpnsKey.ts
    - packages/api-client/src/models/sentShareResponseDtoPermission.ts
  modified:
    - apps/api/src/shares/entities/share.entity.ts
    - apps/api/src/shares/dto/create-share.dto.ts
    - apps/api/src/shares/dto/share-response.dto.ts
    - apps/api/src/shares/shares.service.ts
    - apps/api/src/shares/shares.controller.ts
    - apps/api/src/ipns/ipns.module.ts
    - apps/api/src/ipns/ipns.service.ts
    - packages/api-client/openapi.json
    - packages/api-client/src/generated/shares/shares.ts
    - packages/api-client/src/models/createShareDto.ts
    - packages/api-client/src/models/createShareResponseDto.ts
    - packages/api-client/src/models/receivedShareResponseDto.ts
    - packages/api-client/src/models/sentShareResponseDto.ts
    - packages/api-client/src/models/index.ts

key-decisions:
  - 'Write-share authorization in upsertFolderIpns does not throw ForbiddenException when no write share exists -- falls through to existing create-new-entry path to preserve backward compatibility for owner first publish'
  - 'TEE enrollFolder uses existing.userId (FolderIpns owner) instead of authenticated userId to ensure republishing is attributed to the correct owner'
  - 'API client regenerated in Task 1 commit due to pre-commit hook requiring entity/dto/controller changes to include generated client files'

patterns-established:
  - 'Write-share IPNS publish pattern: recipient updates owner FolderIpns row, not creating their own'
  - 'Permission upgrade requires ECIES-wrapped IPNS key; downgrade clears it to null'

requirements-completed: [SHARE-01, SHARE-02, SHARE-03, SHARE-04]

# Metrics
duration: 6min
completed: 2026-03-26
---

# Phase 27 Plan 01: Backend Writable Shares Summary

**Share entity extended with permission/encryptedIpnsKey columns, IPNS publish authorization expanded for write-share recipients, API client regenerated with UpdatePermissionDto types**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-26T04:16:52Z
- **Completed:** 2026-03-26T04:23:31Z
- **Tasks:** 2
- **Files modified:** 23

## Accomplishments

- Share entity supports read/write permission with backward-compatible default
- Write-share recipients can publish to shared IPNS names by updating the owner's FolderIpns record
- Owner can upgrade shares to write (with ECIES-wrapped IPNS key) and downgrade to read (clearing key)
- TEE republishing enrollment correctly attributes to the FolderIpns owner, not the write-share recipient
- API client fully regenerated with new permission types and UpdatePermissionDto

## Task Commits

Each task was committed atomically:

1. **Task 1: Share entity, migration, DTOs, and service methods** - `6e47258` (feat)
2. **Task 2: IPNS publish authorization expansion and API client regeneration** - `e92accb` (feat)

## Files Created/Modified

- `apps/api/src/shares/entities/share.entity.ts` - Added permission and encryptedIpnsKey columns
- `apps/api/src/migrations/1743000000000-AddWritableShares.ts` - Idempotent migration for new columns
- `apps/api/src/shares/dto/create-share.dto.ts` - Added optional permission and encryptedIpnsKey fields
- `apps/api/src/shares/dto/update-permission.dto.ts` - New DTO for permission upgrade/downgrade
- `apps/api/src/shares/dto/share-response.dto.ts` - Added permission to all response DTOs, encryptedIpnsKey to ReceivedShareResponseDto
- `apps/api/src/shares/shares.service.ts` - Added updatePermission and findActiveWriteShare methods
- `apps/api/src/shares/shares.controller.ts` - Added PATCH :shareId/permission endpoint, updated response mappings
- `apps/api/src/ipns/ipns.module.ts` - Imported SharesModule for cross-module access
- `apps/api/src/ipns/ipns.service.ts` - Injected SharesService, added write-share authorization fallback in upsertFolderIpns
- `packages/api-client/src/models/updatePermissionDto.ts` - Generated UpdatePermissionDto type
- `packages/api-client/openapi.json` - Regenerated OpenAPI spec with new endpoints and types

## Decisions Made

- **Write-share authorization fallback preserves backward compatibility:** When `getFolderIpns(userId, ipnsName)` returns null and no write share exists, the code falls through to the create-new-entry path instead of throwing ForbiddenException. This preserves the existing behavior where any authenticated user can publish to any IPNS name (creating their own entry), while enabling write-share recipients to update the owner's record when a write share exists.
- **TEE enrollment uses FolderIpns owner:** Changed `enrollFolder(userId, ...)` to `enrollFolder(existing.userId, ...)` to ensure TEE republishing is attributed to the actual IPNS name owner, not the write-share recipient.
- **Combined API client regeneration with Task 1:** The pre-commit hook requires api-client regeneration when entity/DTO/controller files change, so the generated client was included in the Task 1 commit rather than deferring to Task 2.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Pre-commit hook requires API client regeneration with entity/DTO changes**

- **Found during:** Task 1 (Share entity, migration, DTOs)
- **Issue:** Pre-commit hook blocks commits when API source files change but generated client files are not staged
- **Fix:** Ran `pnpm api:generate` and included generated client files in Task 1 commit
- **Files modified:** packages/api-client/\* (9 new files, 6 modified files)
- **Verification:** Commit succeeded with pre-commit hook passing
- **Committed in:** 6e47258 (Task 1 commit)

**2. [Rule 1 - Bug] Write-share authorization would block owner's first IPNS publish**

- **Found during:** Task 2 (IPNS publish authorization)
- **Issue:** Plan specified throwing ForbiddenException when no write share exists, but this would prevent the owner from creating their first FolderIpns entry (which also has no write share)
- **Fix:** Changed to fall-through pattern: only look up owner's FolderIpns when a write share IS found; otherwise fall through to existing create-new-entry path
- **Files modified:** apps/api/src/ipns/ipns.service.ts
- **Verification:** TypeScript compilation passes, flow preserves backward compatibility
- **Committed in:** e92accb (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 blocking, 1 bug)
**Impact on plan:** Both fixes necessary for correctness. No scope creep.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Backend API fully supports writable shares: schema extended, authorization expanded, API client regenerated
- Plan 27-02 (client-side crypto for write shares) can proceed using the new UpdatePermissionDto and permission fields
- Plan 27-03 (E2E tests) can proceed with the PATCH /shares/:shareId/permission endpoint

---

## Self-Check: PASSED

All 11 key files verified present. Both commit hashes (6e47258, e92accb) confirmed in git log.

---

_Phase: 27-writable-shares-poc_
_Completed: 2026-03-26_
