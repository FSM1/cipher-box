---
phase: 77-crypto-hygiene-and-terminology-canonicalization
plan: 04
subsystem: api
tags: [nestjs, typeorm, access-control, refactor]

# Dependency graph
requires:
  - phase: 71
    provides: root-ownership authorization gate (D-01/SC#1) originally inlined in createShare and createInvite
provides:
  - Single shared assertRootOwnership(ipnsRecordRepo, ipnsName, userId) helper in apps/api/src/shares/root-ownership.util.ts
  - shares.service.ts createShare and share-invite.service.ts createInvite both delegate to the helper
affects: [77-crypto-hygiene-and-terminology-canonicalization]

# Tech tracking
tech-stack:
  added: []
  patterns: [plain exported async function extraction (no new @Injectable/DI) for a duplicated authorization gate]

key-files:
  created: [apps/api/src/shares/root-ownership.util.ts]
  modified: [apps/api/src/shares/shares.service.ts, apps/api/src/shares/share-invite.service.ts]

key-decisions:
  - "Extracted as a plain exported function, not an @Injectable service — both callers already have ipnsRecordRepo injected, so no new DI wiring was needed"

patterns-established:
  - "Duplicated access-control gates get extracted into a plain util function taking the already-injected repo as a parameter, not wrapped in a new service class"

requirements-completed: [SC3]

coverage:
  - id: D1
    description: "Single shared assertRootOwnership helper backs both createShare and createInvite root-ownership gates, with identical ForbiddenException behavior"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/shares.service.spec.ts (ForbiddenException-on-non-owner test, unmodified)"
        status: pass
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts (ForbiddenException-on-non-owner test, unmodified)"
        status: pass
      - kind: other
        ref: "grep -rn 'You are not the registered owner' apps/api/src — exactly 1 match (root-ownership.util.ts)"
        status: pass
    human_judgment: false

# Metrics
duration: 6min
completed: 2026-07-11
status: complete
---

# Phase 77 Plan 04: Extract assertRootOwnership Shared Helper Summary

**Consolidated the duplicated Phase-71 root-ownership authorization gate from `shares.service.ts` and `share-invite.service.ts` into a single exported `assertRootOwnership` function in `apps/api/src/shares/root-ownership.util.ts`.**

## Performance

- **Duration:** 6 min
- **Started:** 2026-07-11T08:37:00Z
- **Completed:** 2026-07-11T08:43:33Z
- **Tasks:** 2 completed
- **Files modified:** 3 (1 created, 2 modified)

## Accomplishments
- Created `assertRootOwnership(ipnsRecordRepo, ipnsName, userId)` — a plain exported async function (no `@Injectable`, no new DI wiring) that performs the identical `ipnsRecordRepo.findOne({ where: { ipnsName, userId } })` query and throws `ForbiddenException('You are not the registered owner of this node')` when no row is found
- `shares.service.ts` `createShare` now delegates to `assertRootOwnership(this.ipnsRecordRepo, dto.shareRootIpnsName, sharerId)`
- `share-invite.service.ts` `createInvite` now delegates to `assertRootOwnership(this.ipnsRecordRepo, dto.shareRootIpnsName, sharerId)`
- Confirmed exactly one source location throws the ownership-error message (the new helper) via `grep -rn "You are not the registered owner" apps/api/src`
- Both existing ownership specs (`shares.service.spec.ts`, `share-invite.service.spec.ts`) pass unmodified against the extracted helper — proving no behavior change

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract assertRootOwnership and delegate both call sites** - `e67302cea` (refactor)
2. **Task 2: Prove the existing ownership specs pass unmodified against the helper** - no commit (behavioral gate only; both specs passed as-is, no edits required)

**Plan metadata:** (this commit)

## Files Created/Modified
- `apps/api/src/shares/root-ownership.util.ts` - New shared `assertRootOwnership` helper (plain function, imports `Repository`/`ForbiddenException`/`IpnsRecord`)
- `apps/api/src/shares/shares.service.ts` - `createShare` replaces its inline ownership block with a call to `assertRootOwnership`
- `apps/api/src/shares/share-invite.service.ts` - `createInvite` replaces its inline ownership block with a call to `assertRootOwnership`

## Decisions Made
- Kept the helper as a plain exported function rather than an `@Injectable()` — both call sites already inject `ipnsRecordRepo` via `@InjectRepository(IpnsRecord)`, so passing it as a parameter avoids any new DI/module wiring, matching the plan's explicit constraint.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- `assertRootOwnership` is now the single auditable authorization gate for root-ownership checks in the shares/invite flow; future call sites needing the same gate can import it directly.
- No blockers for subsequent 77-* plans.

---
*Phase: 77-crypto-hygiene-and-terminology-canonicalization*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: apps/api/src/shares/root-ownership.util.ts
- FOUND: e67302cea (Task 1 commit)
- FOUND: 77-04-SUMMARY.md
