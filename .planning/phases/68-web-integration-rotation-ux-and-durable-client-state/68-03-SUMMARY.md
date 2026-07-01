---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 03
subsystem: api
tags: [nestjs, typeorm, class-validator, orval, api-client, shares]

# Dependency graph
requires:
  - phase: 68-web-integration-rotation-ux-and-durable-client-state
    provides: reMintGrantsRootedAt / GrantRemintCallbacks.updateGrantFn contract (68-01/68-02 client-side rotation orchestration)
provides:
  - "PATCH /shares/:shareId/grant owner-only route persisting rotated readDescriptorRef + rootGeneration"
  - "Regenerated @cipherbox/api-client sharesControllerUpdateGrant function + UpdateGrantDto model"
affects: [68-07-owner-reconcile]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Owner-mutation route family (updateShareItemName / updateGrant): find -> sharerId ownership check -> mutate -> save, 404/403 via NotFoundException/ForbiddenException"

key-files:
  created:
    - apps/api/src/shares/dto/update-grant.dto.ts
    - packages/api-client/src/models/updateGrantDto.ts
  modified:
    - apps/api/src/shares/shares.controller.ts
    - apps/api/src/shares/shares.service.ts
    - apps/api/src/shares/shares.controller.spec.ts
    - packages/api-client/src/generated/shares/shares.ts
    - packages/api-client/src/models/index.ts
    - packages/api-client/openapi.json

key-decisions:
  - "Mirrored the updateShareItemName route/service idiom exactly (owner-only check, 204, ParseUUIDPipe) rather than introducing a new pattern"
  - "rootGeneration validated with the same IsNonNegativeBigIntConstraint used by CreateShareDto/CreateInviteDto (duplicated locally, matching existing DTO-file convention rather than extracting a shared validator)"

patterns-established:
  - "Owner-only PATCH grant-mutation route: class-validated hex descriptor + numeric-string generation, service does find/ownership-check/mutate/save"

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "PATCH /shares/:shareId/grant returns 204 and persists readDescriptorRef + rootGeneration when called by the owner (sharerId)"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/shares.controller.spec.ts#updateGrant > delegates shareId, req.user.id, readDescriptorRef and rootGeneration to the service and returns 204"
        status: pass
    human_judgment: false
  - id: D2
    description: "Non-owner update attempt returns 403 (ForbiddenException); unknown shareId returns 404 (NotFoundException)"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/shares.controller.spec.ts#updateGrant > propagates ForbiddenException when a non-sharer attempts the update"
        status: pass
      - kind: unit
        ref: "apps/api/src/shares/shares.controller.spec.ts#updateGrant > propagates NotFoundException when the share is missing"
        status: pass
    human_judgment: false
  - id: D3
    description: "Regenerated @cipherbox/api-client exposes sharesControllerUpdateGrant function and UpdateGrantDto model, committed alongside the API change"
    requirement: "ROT-07"
    verification:
      - kind: other
        ref: "grep -c sharesControllerUpdateGrant packages/api-client/src/generated/shares/shares.ts (returns 2); test -f packages/api-client/src/models/updateGrantDto.ts; grep /shares/{shareId}/grant packages/api-client/openapi.json"
        status: pass
    human_judgment: false

# Metrics
duration: 25min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 03: Owner-Only Grant Update Route Summary

**PATCH /shares/:shareId/grant persists a rotated readDescriptorRef + rootGeneration for the sharer, closing the D-10/D-11 API gap that GrantRemintCallbacks.updateGrantFn needs for 68-07's owner reconcile.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-07-01T16:31:37Z
- **Tasks:** 2 completed
- **Files modified:** 9 (3 created, 6 modified)

## Accomplishments
- Added `UpdateGrantDto` (hex-validated `readDescriptorRef`, numeric-string `rootGeneration` bounded to signed 64-bit range) mirroring the `CreateShareDto`/`UpdateItemNameDto` validator idioms
- Added `PATCH :shareId/grant` controller route and `SharesService.updateGrant` with owner-only (`sharerId`) authorization: 204 on success, 403 for non-owner, 404 for unknown share
- Followed RED->GREEN TDD: wrote and committed 3 failing controller-spec tests first (verified failure with `controller.updateGrant is not a function`), then implemented to green (22/22 passing)
- Ran `pnpm api:generate` and committed the regenerated `@cipherbox/api-client` (`sharesControllerUpdateGrant` function, `UpdateGrantDto` model, `openapi.json` `/shares/{shareId}/grant` path) alongside the API change, satisfying `scripts/check-api-client.sh`

## Task Commits

Each task was committed atomically (TDD plan type — RED/GREEN gate):

1. **Task 1 RED: failing tests** - `ff617b09c` (test)
2. **Task 1 GREEN: route + DTO + service** - `e44ffd353` (feat)
3. **Task 2: regenerate api-client** - `4437ea307` (chore)

_TDD Gate Compliance: RED commit (`ff617b09c`) precedes GREEN commit (`e44ffd353`) in git log; no separate refactor commit was needed._

## Files Created/Modified
- `apps/api/src/shares/dto/update-grant.dto.ts` - `UpdateGrantDto` (hex readDescriptorRef, numeric-string rootGeneration with bigint-range validator)
- `apps/api/src/shares/shares.controller.ts` - `PATCH :shareId/grant` route (`updateGrant`)
- `apps/api/src/shares/shares.service.ts` - `updateGrant(shareId, sharerId, readDescriptorRef, rootGeneration)` service method
- `apps/api/src/shares/shares.controller.spec.ts` - 3 new tests (204 delegation, 403, 404) under `describe('updateGrant', ...)`
- `packages/api-client/src/generated/shares/shares.ts` - generated `sharesControllerUpdateGrant`
- `packages/api-client/src/models/updateGrantDto.ts` - generated `UpdateGrantDto` interface
- `packages/api-client/src/models/index.ts` - barrel export for `updateGrantDto`
- `packages/api-client/openapi.json` - regenerated spec including `/shares/{shareId}/grant`

## Decisions Made
- Mirrored `updateShareItemName`'s decorator stack and service shape exactly, per the plan's explicit instruction, rather than introducing a new response/error convention.
- Duplicated the `IsNonNegativeBigIntConstraint` validator locally in `update-grant.dto.ts` (as `create-share.dto.ts` and `create-invite.dto.ts` already do independently) rather than extracting a shared validator module — consistent with the existing per-DTO-file convention in this codebase, avoiding an unplanned refactor.

## Deviations from Plan

None - plan executed exactly as written. `pnpm api:generate` ran successfully in the worktree (no DB/service dependency was needed for this command), so no hand-sync fallback was required.

One incidental note: `pnpm --filter @cipherbox/api build` initially failed with `Cannot find module '@cipherbox/crypto'` because the worktree's `packages/crypto` dist was stale (pre-existing cross-package dist staleness, unrelated to this plan's changes). Ran `pnpm --filter @cipherbox/crypto build` first to unblock the verification build; no source changes were made to resolve this, and it does not affect the committed diff.

## Issues Encountered
None - all verification commands (controller spec tests, API build, acceptance-criteria greps) passed on first pass after the RED/GREEN cycle.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- The `updateGrant` service method and `sharesControllerUpdateGrant` typed client function are ready for 68-07's owner reconcile (`GrantRemintCallbacks.updateGrantFn`) to call.
- No blockers identified for downstream plans.

---
*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Completed: 2026-07-01*
