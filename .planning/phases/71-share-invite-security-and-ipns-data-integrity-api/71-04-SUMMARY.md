---
phase: 71-share-invite-security-and-ipns-data-integrity-api
plan: 04
subsystem: api
tags: [nestjs, typeorm, ipns, postgres, typescript]

# Dependency graph
requires:
  - phase: 67-tee-lease-renewer-contract-rewrite
    provides: TEE lease-renewer (renewIpnsRecordEol) as a standalone UPDATE that never calls upsertIpnsRecord — the structural fact D-05 relies on
provides:
  - Same-seq CID-equivocation guard in upsertIpnsRecord (D-05)
  - First-publish 23505-unique-violation → 409 translation (D-06)
affects: [71-05, ipns-service, sc4-data-integrity]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Same-seq idempotent republish gated on metadataCid equality, not sequence equality alone (D-05)"
    - "err.code / err.driverError.code === '23505' idiom for Postgres unique-violation translation (mirrors shares.service.ts), never QueryFailedError instanceof"

key-files:
  created: []
  modified:
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns.service.spec.ts

key-decisions:
  - "D-05 guard placed inside the existing same-seq branch, before isIdempotentRepublish is set — throws BadRequestException(400) only when metadataCid !== existing.latestCid, preserving the genuine TEE same-CID idempotent retry path"
  - "D-06 first-publish save() wrapped in try/catch reading err.code / err.driverError.code, translating 23505 to ConflictException({statusCode:409, message:'IPNS record already exists'}); any other error is re-thrown unchanged"

patterns-established:
  - "D-05: same-sequence republish equivocation guard — CID-conditional, not sequence-conditional"
  - "D-06: shares.service.ts-style 23505 catch idiom now also used in ipns.service.ts"

requirements-completed: [D-05, D-06, "SC#4"]

coverage:
  - id: D1
    description: "Same-seq republish with a DIFFERENT CID rejects with BadRequestException (400); same-seq republish with the SAME CID still succeeds with no sequence bump (idempotent retry preserved)"
    requirement: "D-05"
    verification:
      - kind: unit
        ref: "apps/api/src/ipns/ipns.service.spec.ts#upsertFolderIpns D-09 embedded-sequence gate > rejects same-seq republish with a DIFFERENT CID (D-05: equivocation)"
        status: pass
      - kind: unit
        ref: "apps/api/src/ipns/ipns.service.spec.ts#upsertFolderIpns D-09 embedded-sequence gate > allows idempotent republish (embedded = DB seq, SAME CID) without incrementing DB sequenceNumber"
        status: pass
    human_judgment: false
  - id: D2
    description: "First-publish INSERT that races into a Postgres 23505 unique-violation is translated to ConflictException (409), not a raw 500; a non-23505 save error is re-thrown unchanged"
    requirement: "D-06"
    verification:
      - kind: unit
        ref: "apps/api/src/ipns/ipns.service.spec.ts#first-publish INSERT-race translation (D-06/SC#4) > translates a Postgres 23505 unique-violation on first-publish save into ConflictException (409)"
        status: pass
      - kind: unit
        ref: "apps/api/src/ipns/ipns.service.spec.ts#first-publish INSERT-race translation (D-06/SC#4) > re-throws a non-23505 first-publish save error unchanged"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-09
status: complete
---

# Phase 71 Plan 04: IPNS same-seq CID equivocation guard + first-publish 23505 race translation Summary

**Closed SC#4's two IPNS data-integrity edges in `upsertIpnsRecord`: same-seq republish now rejects a divergent CID with 400 while preserving idempotent same-CID retries (D-05), and a first-publish unique-violation race now returns a clean 409 instead of an ambiguous 500 (D-06).**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-07-09T21:07:00Z (approx)
- **Completed:** 2026-07-09T21:27:17Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- D-05: `upsertIpnsRecord`'s same-seq branch now throws `BadRequestException` when the incoming `metadataCid` diverges from `existing.latestCid` at the same sequence — closing a silent-overwrite equivocation gap — while a genuine same-CID TEE re-sign retry still succeeds with `sequence_number` unchanged.
- D-06: the first-publish INSERT (`this.ipnsRecordRepository.save(folder)`) is now wrapped in try/catch; a Postgres `23505` unique-violation (concurrent first-publish race) is translated into `ConflictException({statusCode: 409, message: 'IPNS record already exists'})`; any other save error is re-thrown unchanged.
- Rewrote the stale "Pitfall 4" test (previously asserting a different-CID same-seq republish silently overwrote `latestCid`) into two cases: rejects-different-CID (400) and allows-same-CID (idempotent, no seq bump) — plus a spec comment documenting the structural TEE lease-renewer guard (`republish.service.ts` `renewIpnsRecordEol` performs a standalone UPDATE and never calls `upsertIpnsRecord`, so it structurally cannot hit this branch).
- Added a new `describe('first-publish INSERT-race translation (D-06/SC#4)')` block with the 23505→409 case and the non-23505-rethrown case.
- Corrected the stale comment at the same-seq branch to state `latestCid` is preserved only for same-CID idempotent retries, not unconditionally.

## Task Commits

Each task was committed atomically:

1. **Task 1: Same-seq CID-equivocation guard (D-05) — RED then GREEN** - `fce56a073` (feat)
2. **Task 2: First-publish INSERT-race 23505 → 409 (D-06) — RED then GREEN** - `f97326e6c` (feat)

_Both tasks are TDD (`tdd="true"`); RED was confirmed by running the full spec suite before each implementation edit and observing only the newly-added test(s) fail, then GREEN was confirmed by the full suite passing (109/109) after each fix._

## Files Created/Modified
- `apps/api/src/ipns/ipns.service.ts` - Added D-05 same-CID equivocation guard inside the same-seq branch of `upsertIpnsRecord`; wrapped the first-publish `save(folder)` call in try/catch translating Postgres `23505` to a 409 `ConflictException` (D-06)
- `apps/api/src/ipns/ipns.service.spec.ts` - Rewrote the stale "Pitfall 4" idempotent-republish test into a rejects-different-CID case + an allows-same-CID case with the TEE-renewal structural guard comment; added a new `describe` block covering the 23505→409 translation and the non-23505-rethrown path

## Decisions Made
- D-05 guard gates strictly on `metadataCid !== existing.latestCid`, never on `embeddedSeq === dbSeq` alone, per the plan's `key_links` constraint — a blanket same-seq reject was explicitly avoided since it would break the genuine TEE re-sign idempotent path.
- D-06 uses the established `err.code` / `err.driverError.code === '23505'` idiom (mirroring `shares.service.ts:77-87`) rather than `QueryFailedError instanceof`, per the plan's constraint that the latter does not reliably survive the TypeORM driver boundary.
- The real concurrent-race proof (two actual parallel INSERTs hitting the constraint) is deferred to 71-05's sdk-e2e coverage, as scoped by the plan; this plan proves the translation logic via a mocked `save()` rejection.

## Deviations from Plan

None - plan executed exactly as written. Both tasks' acceptance criteria (guard location via grep, RED/GREEN test pairs, comment corrections, full spec suite passing) were met without needing any Rule 1-4 auto-fixes.

## Issues Encountered

**Local test environment cold-start (not a plan deviation, environment-only):** the worktree had no `node_modules` and `@cipherbox/crypto` had no built `dist/` (a fresh worktree clone), which the spec file's `jest.mock('@cipherbox/crypto', ...)` requires to resolve. Ran `pnpm i` at the repo root and `pnpm --filter @cipherbox/crypto build` before the first test run; this is routine worktree setup, not a code change, and was not committed as part of either task.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC#4's unit-side data-integrity edges are closed for `upsertIpnsRecord`; the real concurrent-race scenario (two genuinely parallel publish calls) is proven end-to-end in 71-05 via sdk-e2e, as this plan's `<verification>` section specifies.
- No API DTO/endpoint/controller surface changed — `pnpm api:generate` was not required for this plan (confirmed: only `ipns.service.ts` internal logic and its spec changed).
- `apps/api` full typecheck was run and shows only two pre-existing, out-of-scope errors (`ipns-verify-cache.spec.ts`, `http-metrics.interceptor.spec.ts`) unrelated to this plan's files — not touched, per scope-boundary rules.

---
*Phase: 71-share-invite-security-and-ipns-data-integrity-api*
*Completed: 2026-07-09*
