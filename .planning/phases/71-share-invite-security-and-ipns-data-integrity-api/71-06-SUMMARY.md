---
phase: 71-share-invite-security-and-ipns-data-integrity-api
plan: 06
subsystem: api
tags: [nestjs, typeorm, authorization, shares, ipns]

# Dependency graph
requires:
  - phase: 71-01
    provides: renamed share plane (encryptedReadKey/encryptedWriteKey/shareRootIpnsName) that this plan's DTOs and entity fields build on
provides:
  - Server-side child-ownership gate on createInvite (D-01/SC#1)
  - Server-side child-ownership gate on createShare (D-01/SC#1)
  - IpnsRecord repository DI wiring in SharesModule/ShareInviteService/SharesService
affects: [shares, share-invite, ipns]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Root-ownership gate: single indexed ipnsRecordRepo.findOne({ where: { ipnsName, userId } }) before persist, ForbiddenException(403) on miss — defense-in-depth atop the cryptographic key-wrapping boundary, not an authority elevation"

key-files:
  created: []
  modified:
    - apps/api/src/shares/shares.module.ts
    - apps/api/src/shares/share-invite.service.ts
    - apps/api/src/shares/shares.service.ts
    - apps/api/src/shares/share-invite.service.spec.ts
    - apps/api/src/shares/shares.service.spec.ts

key-decisions:
  - "D-01 (amended): ownership source is ipns_records.user_id (creator marker), not vaults — vaults only records the vault root, never child shares"
  - "D-02 residual gap documented in code comments: only shareRootIpnsName ownership is server-verified; rootNodeId stays client-asserted"
  - "createShare gate placed at the very top of the method (fail-fast), before the recipient lookup"

patterns-established:
  - "Child-ownership gate pattern: query the ipns_records creator marker keyed by (ipnsName, userId) as a cheap anti-spoof check layered atop the real cryptographic access boundary (a forged grant for content the caller lacks keys to is cryptographically inert)"

requirements-completed: [D-01, D-02, D-09, SC#1]

coverage:
  - id: D1
    description: "createInvite rejects with 403 ForbiddenException when the caller did not register dto.shareRootIpnsName in ipns_records"
    requirement: "D-01"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts#createInvite — root-ownership gate (D-01/SC#1) > throws ForbiddenException when the caller did not register shareRootIpnsName in ipns_records"
        status: pass
    human_judgment: false
  - id: D2
    description: "createInvite persists the invite when the caller IS the registered owner of the shared node"
    requirement: "D-01"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts#createInvite — root-ownership gate (D-01/SC#1) > persists the invite when the caller IS the registered owner of shareRootIpnsName"
        status: pass
    human_judgment: false
  - id: D3
    description: "createShare rejects with 403 ForbiddenException when the caller did not register dto.shareRootIpnsName in ipns_records, fail-fast before the recipient lookup"
    requirement: "D-01"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/shares.service.spec.ts#createShare > throws ForbiddenException when the caller did not register shareRootIpnsName in ipns_records (D-01/SC#1)"
        status: pass
    human_judgment: false
  - id: D4
    description: "createShare persists the share when the caller IS the registered owner; all pre-existing recipient/self/duplicate/23505 checks remain green"
    requirement: "D-01"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/shares.service.spec.ts#createShare (all 9 pre-existing + new cases)"
        status: pass
    human_judgment: false
  - id: D5
    description: "ShareInviteService and SharesService both resolve the IpnsRecord repository at Nest bootstrap via shares.module forFeature"
    requirement: "D-01"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts and shares.service.spec.ts full suite compile+run (DI resolves cleanly)"
        status: pass
    human_judgment: false
  - id: D6
    description: "createInvite mechanics coverage (token generated, expiresAt future, DTO fields copied) for D-09"
    requirement: "D-09"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts#createInvite — root-ownership gate (D-01/SC#1) > generates a token, sets a future expiresAt, and copies DTO fields (mechanics, D-09)"
        status: pass
    human_judgment: false

duration: ~20min
completed: 2026-07-09
status: complete
---

# Phase 71 Plan 06: Share/Invite Root-Ownership Gate Summary

**Server-side child-ownership gate on both createInvite and createShare, verifying the caller registered `shareRootIpnsName` via `ipns_records` before persisting a grant, closing SC#1.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-09
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- `SharesModule` now registers `IpnsRecord` in `TypeOrmModule.forFeature`, and both `ShareInviteService` and `SharesService` inject an `IpnsRecord` repository.
- `createInvite` performs a single indexed `ipnsRecordRepo.findOne({ where: { ipnsName: dto.shareRootIpnsName, userId: sharerId } })` lookup before persisting, rejecting with `ForbiddenException` (403) on a miss.
- `createShare` performs the identical gate as the very first step (fail-fast, before the recipient lookup), preserving all pre-existing recipient/self/duplicate/`23505`-race checks unchanged after it.
- Both services now carry an in-code comment documenting the D-02 residual gap: only `shareRootIpnsName` ownership is server-verified; `rootNodeId` stays client-asserted for this phase.
- `share-invite.service.spec.ts` gained real `createInvite` coverage (reject/accept/mechanics — D-09), previously untested.

## Task Commits

Each task was committed atomically (Task 2 and 3 as TDD RED/GREEN pairs):

1. **Task 1: Wire IpnsRecord repository into both share services + specs** - `6c0849ecb` (feat)
2. **Task 2: createInvite root-ownership gate (D-01) — RED** - `15192381b` (test)
2. **Task 2: createInvite root-ownership gate (D-01) — GREEN** - `456a4ebdd` (feat)
3. **Task 3: createShare root-ownership gate (D-01) — RED** - `782c09af1` (test)
3. **Task 3: createShare root-ownership gate (D-01) — GREEN** - `497838202` (feat)

_TDD tasks committed as separate RED (test) → GREEN (feat) commits per the plan-level tdd_mode gate._

## Files Created/Modified

- `apps/api/src/shares/shares.module.ts` - registers `IpnsRecord` in `TypeOrmModule.forFeature`
- `apps/api/src/shares/share-invite.service.ts` - injects `IpnsRecordRepository`, adds root-ownership gate to `createInvite`
- `apps/api/src/shares/shares.service.ts` - injects `IpnsRecordRepository`, adds root-ownership gate (fail-fast) to `createShare`
- `apps/api/src/shares/share-invite.service.spec.ts` - adds `mockIpnsRecordRepo` + `getRepositoryToken(IpnsRecord)` provider, new `createInvite — root-ownership gate (D-01/SC#1)` describe block (reject/accept/mechanics)
- `apps/api/src/shares/shares.service.spec.ts` - adds `ipnsRecordRepo` mock + `getRepositoryToken(IpnsRecord)` provider, new `createShare` reject test

## Decisions Made

- Followed CONTEXT.md D-01 (AMENDED): ownership source is `ipns_records.user_id`, not `vaults` — `vaults` structurally cannot verify child-node ownership since it only ever holds one row per user (the vault root).
- D-02 kept as documented residual gap in code comments on both services (no `rootNodeId` server-side verification this phase — deferred).
- `createShare`'s gate placed at the top of the method (before recipient lookup) per plan's fail-fast instruction; verified via a test asserting `userRepo.findOne` is never called on rejection.

## Deviations from Plan

None - plan executed exactly as written. TDD RED/GREEN task-level commits split per the `tdd="true"` task attribute and `tdd_mode: true` phase config; each RED commit was confirmed actually failing before the corresponding GREEN commit landed (verified via direct `jest` runs, not the pnpm wrapper — the project's `pnpm test` script double-wraps `--` args and silently swallows `--testPathPattern`, so `npx jest --testPathPattern=...` was used directly for all RED/GREEN verification in this plan; this is a test-runner-invocation detail only, no test or source content was affected).

## Issues Encountered

None blocking. `pnpm --filter @cipherbox/api test -- --testPathPattern=...` only ran a subset of the target suites due to `pnpm run`'s extra `--` interacting with the `jest --passWithNoTests` script wrapper; switched to `npx jest --testPathPattern=...` from `apps/api/` directly, which is equivalent and ran both target suites correctly (confirmed 45/45 passing, and 83/83 for the full `shares/` directory).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC#1 is fully closed on both issuance paths (createInvite + createShare); D-02's residual half-pair gap is documented, not fixed (deferred to a future key-possession-proof phase per CONTEXT.md).
- No DTO/endpoint shape changes in this plan — `pnpm api:generate` was not required and was not run.
- `apps/api` typecheck confirmed clean for all files touched by this plan (pre-existing unrelated errors in `ipns/` and `metrics/` modules from other wave-1 work are out of scope for 71-06).

## Self-Check: PASSED

All 5 modified source files and the SUMMARY.md itself confirmed present on disk. All 6 commit hashes (`6c0849ecb`, `15192381b`, `456a4ebdd`, `782c09af1`, `497838202`, `fae766692`) confirmed present in `git log --oneline --all`.

---
*Phase: 71-share-invite-security-and-ipns-data-integrity-api*
*Completed: 2026-07-09*
