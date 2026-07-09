---
phase: 71-share-invite-security-and-ipns-data-integrity-api
plan: 08
subsystem: api
tags: [typeorm, nestjs, jest, query-builder, shares]

# Dependency graph
requires:
  - phase: 71-06
    provides: shares.service.ts revokeForItems method with the sibling invite-revoke .update() query-builder block
provides:
  - revokeForItems share-deletion path rewritten to a single createQueryBuilder().delete().from(Share)...execute()
affects: [shares-service, revoke-flows]

# Tech tracking
tech-stack:
  added: []
  patterns: [direct query-builder DELETE mirroring the sibling UPDATE block instead of find+remove]

key-files:
  created: []
  modified:
    - apps/api/src/shares/shares.service.ts
    - apps/api/src/shares/shares.service.spec.ts

key-decisions:
  - "revokeForItems' share half now issues a direct createQueryBuilder().delete().from(Share)...execute() scoped to sharer_id + share_root_ipns_name, instead of manager.find + manager.remove"
  - "revokedShares is sourced from the DELETE result's affected count (?? 0), matching the existing invite UPDATE's affected-count pattern"
  - "Removed the now-unused In import from typeorm in both shares.service.ts and shares.service.spec.ts"

patterns-established:
  - "Bulk revoke/delete operations on entities with no hooks/cascades/subscribers should use a scoped query-builder DELETE rather than load-then-remove"

requirements-completed: [D-08, SC#5]

coverage:
  - id: D1
    description: "revokeForItems deletes matching shares via a single query-builder DELETE (not find+remove), scoped to sharer_id + share_root_ipns_name, and returns affected-count-based revokedShares/revokedInvites"
    requirement: "SC#5"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/shares.service.spec.ts#revokeForItems deletes matching shares via a single query-builder DELETE and revokes active invites in a transaction"
        status: pass
      - kind: unit
        ref: "apps/api/src/shares/shares.service.spec.ts#revokeForItems returns zero revoked shares when no shares match but still revokes invites"
        status: pass
      - kind: unit
        ref: "apps/api/src/shares/shares.service.spec.ts#revokeForItems treats an undefined affected count as zero for both shares and invites"
        status: pass
      - kind: unit
        ref: "apps/api/src/shares/shares.service.spec.ts#revokeForItems returns zero counts and skips the transaction for an empty name list"
        status: pass
    human_judgment: false

# Metrics
duration: 12min
completed: 2026-07-09
status: complete
---

# Phase 71 Plan 08: Direct DELETE for revokeForItems Summary

**Replaced `revokeForItems`'s `manager.find(Share)` + `manager.remove(shares)` with a single `createQueryBuilder().delete().from(Share)...execute()` scoped to `sharer_id` + the renamed `share_root_ipns_name` column, mirroring the sibling invite-revoke `.update()` block in the same transaction.**

## Performance

- **Duration:** ~12 min
- **Completed:** 2026-07-09
- **Tasks:** 1 (TDD: RED then GREEN)
- **Files modified:** 2

## Accomplishments

- `revokeForItems` now issues one DELETE for the share half of the bulk revoke instead of loading full `bytea` encrypted-key rows into memory before removing them — pushes the work into the DB tier for large subtree revokes
- `revokedShares` sourced from the DELETE's `affected` count (`?? 0`), matching the existing invite-UPDATE `affected`-count pattern
- Removed the now-dead `In` import from `typeorm` in both the service and its spec
- Preserved caller scoping (`sharer_id = :sharerId`) and the renamed `share_root_ipns_name` binding style already used by the adjacent invite UPDATE

## Task Commits

TDD gate sequence (RED then GREEN):

1. **Task 1 RED: failing test for revokeForItems direct DELETE** - `bc07bc5fe` (test)
2. **Task 1 GREEN: direct DELETE implementation** - `44cf469f9` (feat)

_Both commits address the single plan task; RED sequenced two `queryBuilder.execute` mocks (share DELETE, then invite UPDATE) and asserted `manager.find`/`manager.remove` are never called — confirmed failing against the pre-existing find+remove implementation before GREEN swapped it in._

## Files Created/Modified

- `apps/api/src/shares/shares.service.ts` - `revokeForItems` share-deletion path rewritten to a scoped query-builder DELETE; removed unused `In` import
- `apps/api/src/shares/shares.service.spec.ts` - `describe('revokeForItems')` rewritten to sequence `queryBuilder.execute` mocks (DELETE then UPDATE) and assert `manager.find`/`manager.remove` are not called; `queryBuilder` mock gained `delete`/`from` methods; removed unused `In` import

## Decisions Made

- Kept the DELETE and UPDATE as two separate `manager.createQueryBuilder()` calls within the same transaction (matching the plan's explicit action text), rather than trying to combine them into one query-builder chain — TypeORM query builders are single-purpose per verb (`.delete()` vs `.update()`) and can't be composed into one call anyway.
- Sequenced the mocked `queryBuilder.execute` resolved values (`mockResolvedValueOnce` x2) rather than distinguishing by call arguments, since the same mock `queryBuilder` object is returned by every `manager.createQueryBuilder()` call — this mirrors how the real TypeORM manager would behave under test doubles.

## Deviations from Plan

None - plan executed exactly as written (RED/GREEN TDD flow, single task, files_modified matched exactly).

## Issues Encountered

`pnpm --filter @cipherbox/api exec tsc --noEmit` surfaces pre-existing, unrelated typecheck errors (stale/missing `packages/crypto/dist` module resolution, two pre-existing `ipns.service.ts` null-narrowing errors, and an `HttpArgumentsHost` import mismatch in `http-metrics.interceptor.spec.ts`). None reference `shares.service.ts` or `shares.service.spec.ts`. Confirmed via `tsc --noEmit | grep -i shares.service` returning no hits. Out of scope for this plan per the executor's scope boundary — logged in `.planning/phases/71-share-invite-security-and-ipns-data-integrity-api/deferred-items.md`, not fixed.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

SC#5 closed. `revokeForItems` bulk-revoke now issues a single scoped DELETE for shares (mirroring the invite UPDATE) instead of a find+remove round-trip, while preserving returned counts and caller scoping. No DTO/endpoint shape change, so no `api-client` regeneration was needed. No blockers for downstream phase-71 plans.

---
*Phase: 71-share-invite-security-and-ipns-data-integrity-api*
*Completed: 2026-07-09*

## Self-Check: PASSED

- FOUND: apps/api/src/shares/shares.service.ts
- FOUND: apps/api/src/shares/shares.service.spec.ts
- FOUND: .planning/phases/71-share-invite-security-and-ipns-data-integrity-api/71-08-SUMMARY.md
- FOUND commit: bc07bc5fe (test)
- FOUND commit: 44cf469f9 (feat)
- FOUND commit: d117a911c (docs)
