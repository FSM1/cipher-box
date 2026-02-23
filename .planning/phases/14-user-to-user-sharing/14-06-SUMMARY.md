---
phase: 14-user-to-user-sharing
plan: 06
subsystem: api, crypto
tags: [ecies, key-rotation, share-keys, lazy-rotation, ipns, re-wrapping]

# Dependency graph
requires:
  - phase: 14-03
    provides: Share service, share store, Orval API client for share endpoints
  - phase: 14-05
    provides: Post-upload re-wrapping hooks already committed with shared browsing
provides:
  - Post-upload and post-create share key re-wrapping for recipients
  - Lazy key rotation after share revocation (detect, rotate, re-wrap, hard-delete)
  - Three new API endpoints for rotation lifecycle (pending-rotations, encrypted-key update, complete-rotation)
  - checkAndRotateIfNeeded integration point in folder.service.ts
affects: [15-link-sharing, 14-uat]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Dynamic import() for circular dependency avoidance between folder.service and share.service'
    - 'Fire-and-forget IIFE pattern for non-blocking post-upload re-wrapping'
    - 'Lazy key rotation: revoke sets revokedAt, rotation deferred to next modification'

key-files:
  created:
    - apps/api/src/shares/dto/update-encrypted-key.dto.ts
  modified:
    - apps/web/src/services/share.service.ts
    - apps/web/src/services/folder.service.ts
    - apps/web/src/hooks/useFolder.ts
    - apps/api/src/shares/shares.controller.ts
    - apps/api/src/shares/shares.service.ts
    - apps/api/src/shares/dto/index.ts

key-decisions:
  - 'Dynamic import() in checkAndRotateIfNeeded to avoid circular dependency'
  - 'Lazy rotation re-encrypts metadata but defers parent folderKeyEncrypted update to caller'
  - 'Post-upload re-wrapping is fire-and-forget with console.warn on failure'

patterns-established:
  - 'Dynamic import() pattern: use await import() for same-layer service dependencies that would create circular imports'
  - 'Rotation protocol: checkPendingRotation -> executeLazyRotation -> re-encrypt metadata -> update parent'

# Metrics
duration: 8min
completed: 2026-02-21
---

# Phase 14 Plan 06: Post-Upload Re-Wrapping & Lazy Key Rotation Summary

**ECIES re-wrapping hooks for post-upload/create key propagation and lazy folderKey rotation after share revocation**

## Performance

- **Duration:** 8 min
- **Started:** 2026-02-21T15:15:00Z
- **Completed:** 2026-02-21T15:23:36Z
- **Tasks:** 2
- **Files modified:** 9

## Accomplishments

- Post-upload and post-create hooks re-wrap new file/folder keys for all share recipients automatically
- Lazy key rotation flow: revoke sets revokedAt, next folder modification generates new folderKey, re-encrypts metadata, re-wraps for remaining recipients, hard-deletes revoked records
- Three new backend endpoints for rotation lifecycle: GET /shares/pending-rotations, PATCH /shares/:shareId/encrypted-key, DELETE /shares/:shareId/complete-rotation
- checkAndRotateIfNeeded in folder.service.ts provides integration point for rotation before modifications

## Task Commits

Both tasks were committed in the previous session as part of Plan 14-05 execution (the work was done ahead of the plan boundary):

1. **Task 1: Post-upload and post-create share key propagation** - `5237b3198` (feat) + `eb824f678` (fix)
   - reWrapForRecipients, hasActiveShares, findCoveringShares in share.service.ts
   - Post-upload/post-create hooks in useFolder.ts
   - Build error fixes for unused imports
2. **Task 2: Lazy key rotation on folder modification after revoke** - `d87a06ce6` (feat)
   - Backend controller endpoints + UpdateEncryptedKeyDto
   - Backend service methods (updateShareEncryptedKey, completeRotation with sharerId)
   - checkAndRotateIfNeeded in folder.service.ts
   - Regenerated API client

## Files Created/Modified

- `apps/web/src/services/share.service.ts` - Added reWrapForRecipients, findCoveringShares, hasActiveShares, fetchPendingRotations, checkPendingRotation, executeLazyRotation, updateShareKey, completeShareRotation
- `apps/web/src/services/folder.service.ts` - Added checkAndRotateIfNeeded with dynamic import for circular dep avoidance
- `apps/web/src/hooks/useFolder.ts` - Post-upload/post-create fire-and-forget re-wrapping hooks in handleAddFile, handleAddFiles, handleCreate
- `apps/api/src/shares/shares.controller.ts` - Added 3 new endpoints (pending-rotations, encrypted-key, complete-rotation)
- `apps/api/src/shares/shares.service.ts` - Added updateShareEncryptedKey, updated completeRotation with sharerId validation
- `apps/api/src/shares/dto/update-encrypted-key.dto.ts` - New DTO for encrypted key update
- `apps/api/src/shares/dto/index.ts` - Export UpdateEncryptedKeyDto
- `apps/web/src/api/shares/shares.ts` - Regenerated with 3 new generated functions
- `packages/api-client/openapi.json` - Updated OpenAPI spec

## Decisions Made

| Decision                                                     | Rationale                                                                                                                                                                      |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Dynamic `import()` in checkAndRotateIfNeeded                 | share.service imports from folder.store; folder.service importing from share.service at module level creates circular dependency. Dynamic import defers resolution to runtime. |
| Lazy rotation defers parent metadata update to caller        | checkAndRotateIfNeeded does not know the parent folder context. The caller (useFolder hook) must update the parent's folderKeyEncrypted entry after rotation.                  |
| Post-upload re-wrapping is fire-and-forget                   | Non-blocking: failures logged but never delay upload completion. Recipients get keys on retry or next share key fetch.                                                         |
| executeLazyRotation delegates folder re-encryption to caller | The share service doesn't have IPNS private key or publishing infrastructure; folder.service handles the actual metadata re-encryption.                                        |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed unused imports causing build failure**

- **Found during:** Task 1 verification
- **Issue:** SharedFileBrowser.tsx had unused imports (useMemo, FolderEntry) and unused variable (currentShareId). useSharedNavigation.ts had unused fileKey variable.
- **Fix:** Removed unused imports and variables
- **Files modified:** SharedFileBrowser.tsx, useSharedNavigation.ts
- **Verification:** `pnpm --filter web build` passes
- **Committed in:** `eb824f678`

**2. [Rule 3 - Blocking] Backend controller missing endpoints for rotation**

- **Found during:** Task 2
- **Issue:** shares.service.ts had getPendingRotations and completeRotation methods, but the controller had no endpoints exposing them. Also missing updateShareEncryptedKey endpoint.
- **Fix:** Added 3 new controller endpoints and UpdateEncryptedKeyDto
- **Files modified:** shares.controller.ts, shares.service.ts, update-encrypted-key.dto.ts, dto/index.ts
- **Verification:** `pnpm --filter api build` passes, API client regenerated
- **Committed in:** `d87a06ce6`

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking)
**Impact on plan:** Both fixes necessary for correct operation. No scope creep.

## Issues Encountered

- **Task 1 already completed in Plan 14-05 commit:** The previous session committed Task 1 work (reWrapForRecipients, post-upload hooks) as part of the 14-05 commit `5237b3198`. This plan verified the work was complete rather than re-implementing it.
- **Linter removes unused imports:** The ESLint auto-fix (via lint-staged) removes imports for functions not yet referenced. Adding the import and usage in the same edit avoids this. For folder.service.ts, the dynamic `import()` pattern naturally avoids this issue since there is no top-level import statement.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All 6 plans for Phase 14 are now complete
- The sharing infrastructure is fully implemented: entities, DTOs, service, controller, share dialog, shared browsing, post-upload re-wrapping, and lazy key rotation
- Ready for UAT testing of the complete sharing flow
- No blockers

---

_Phase: 14-user-to-user-sharing_
_Completed: 2026-02-21_
