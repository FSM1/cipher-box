---
phase: 77-crypto-hygiene-and-terminology-canonicalization
plan: 03
subsystem: api
tags: [tee, ipns, terminology-canonicalization, republish, wire-contract]

# Dependency graph
requires:
  - phase: 67-tee-lease-renewer-contract-rewrite
    provides: The TEE republish HTTP contract (RepublishEntry/RepublishResult) between apps/api and apps/tee-worker
provides:
  - The TEE republish wire contract field is renamed encryptedIpnsKey -> encryptedIpnsPrivateKey across apps/api (relay) and apps/tee-worker (worker), matching the already-canonical DB column name
affects: [77-crypto-hygiene-and-terminology-canonicalization, tee, republish]

# Tech tracking
tech-stack:
  added: []
  patterns: []

key-files:
  created: []
  modified:
    - apps/api/src/tee/tee.service.ts
    - apps/api/src/republish/republish.service.ts
    - apps/api/src/tee/tee.service.spec.ts
    - apps/api/src/republish/republish.service.spec.ts
    - apps/tee-worker/src/routes/republish.ts
    - apps/tee-worker/src/services/key-manager.ts
    - apps/tee-worker/src/__tests__/republish.test.ts

key-decisions:
  - "Renamed decryptWithFallback's encryptedIpnsKey param in key-manager.ts alongside decryptIpnsKey's, since Task 1's acceptance criteria required zero occurrences of the old name anywhere in key-manager.ts (grep-scoped to the whole file, not just decryptIpnsKey's signature)"

patterns-established: []

requirements-completed: [SC3]

coverage:
  - id: D1
    description: "TEE republish wire contract field renamed encryptedIpnsKey -> encryptedIpnsPrivateKey across RepublishEntry (relay), the tee-worker request body, and decryptIpnsKey/decryptWithFallback params, in lockstep so the contract never disagrees"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "apps/api/src/tee/tee.service.spec.ts (72 tests incl. tee.service.spec.ts + republish.service.spec.ts combined)"
        status: pass
      - kind: unit
        ref: "apps/tee-worker/src/__tests__/republish.test.ts (76 passed, 8 todo)"
        status: pass
      - kind: other
        ref: "pnpm --filter @cipherbox/api exec tsc --noEmit -p tsconfig.json && pnpm --filter cipherbox-tee-worker exec tsc --noEmit -p tsconfig.json"
        status: pass
    human_judgment: false
  - id: D2
    description: "Negative not.toHaveProperty assertions in republish.service.spec.ts updated to the canonical property name so they keep proving the schedule row omits the wrapped key"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "apps/api/src/republish/republish.service.spec.ts (4x not.toHaveProperty('encryptedIpnsPrivateKey'))"
        status: pass
    human_judgment: false

# Metrics
duration: 5min
completed: 2026-07-11
status: complete
---

# Phase 77 Plan 03: TEE Wire-Contract Field Canonicalization Summary

**Renamed the TEE republish wire field `encryptedIpnsKey` to the canonical `encryptedIpnsPrivateKey` in lockstep across the API relay and the tee-worker, with zero behavior change.**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-07-11T10:25:00+02:00 (approx)
- **Completed:** 2026-07-11T10:30:38+02:00
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments
- `RepublishEntry.encryptedIpnsKey` renamed to `encryptedIpnsPrivateKey` in `apps/api/src/tee/tee.service.ts`, the object built in `apps/api/src/republish/republish.service.ts`'s `teeEntries` map, and the request-body type + decode call in `apps/tee-worker/src/routes/republish.ts` — all changed in a single commit so the wire contract never disagrees between relay and worker.
- `decryptIpnsKey(...)` and `decryptWithFallback(...)` parameters (plus JSDoc) renamed to `encryptedIpnsPrivateKey` in `apps/tee-worker/src/services/key-manager.ts`.
- All three affected spec files (`tee.service.spec.ts`, `republish.service.spec.ts`, `republish.test.ts`) updated to the canonical name, including 4 negative `.not.toHaveProperty('encryptedIpnsPrivateKey')` assertions that would have silently stopped proving anything if left on the stale name.
- `apps/api` and `apps/tee-worker` both typecheck clean; 72 API tests and 76 tee-worker tests (8 todo) pass.

## Task Commits

Each task was committed atomically:

1. **Task 1: Rename the wire field across the API relay + tee-worker in lockstep** - `b0ef9c08b` (refactor)
2. **Task 2: Update TEE/republish specs (incl. negative property assertions) and prove green** - `e58c604e3` (test)

## Files Created/Modified
- `apps/api/src/tee/tee.service.ts` - `RepublishEntry.encryptedIpnsKey` field renamed to `encryptedIpnsPrivateKey`
- `apps/api/src/republish/republish.service.ts` - `teeEntries` map now builds the wire object with key `encryptedIpnsPrivateKey` (value unchanged: `record.encryptedIpnsPrivateKey!.toString('base64')`)
- `apps/tee-worker/src/routes/republish.ts` - Local `RepublishEntry` interface field renamed; decode call renamed to `entry.encryptedIpnsPrivateKey`
- `apps/tee-worker/src/services/key-manager.ts` - `decryptIpnsKey` and `decryptWithFallback` params (+ JSDoc + internal references) renamed
- `apps/api/src/tee/tee.service.spec.ts` - Fixture field renamed
- `apps/api/src/republish/republish.service.spec.ts` - Fixture + 4 negative property assertions renamed
- `apps/tee-worker/src/__tests__/republish.test.ts` - `makeEntry()` helper and ~18 call sites renamed

## Decisions Made
- `decryptWithFallback`'s parameter (not just `decryptIpnsKey`'s) was renamed even though the plan's `<action>` text only explicitly named `decryptIpnsKey(...)`. Task 1's acceptance criteria grep-scopes the entire `key-manager.ts` file for zero occurrences of `encryptedIpnsKey`, and `decryptWithFallback` shares the same param name and calls `decryptIpnsKey` internally — renaming only one would have left a mismatched param name mid-file and failed the acceptance grep.

## Deviations from Plan

None — plan executed exactly as written. The one interpretive decision above (renaming `decryptWithFallback`'s param alongside `decryptIpnsKey`'s) is a direct consequence of the plan's own acceptance criteria, not a deviation from it.

Note: the plan's `<verify>` blocks specified `pnpm --filter cipherbox-api typecheck` / `pnpm --filter cipherbox-api test`, but the actual package name is `@cipherbox/api` (not `cipherbox-api`) and neither `apps/api` nor `apps/tee-worker` has a `typecheck` script defined. Verification was performed with equivalent commands (`pnpm --filter @cipherbox/api exec tsc --noEmit -p tsconfig.json`, `pnpm --filter @cipherbox/api test -- tee.service.spec.ts republish.service.spec.ts`, `pnpm --filter cipherbox-tee-worker exec tsc --noEmit -p tsconfig.json`, `pnpm --filter cipherbox-tee-worker test -- republish.test.ts`) that satisfy the same acceptance criteria (exit 0, all specs green). This is a benign verify-command correction, not a code change.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- The TEE republish wire contract now uses the canonical `encryptedIpnsPrivateKey` name end-to-end (relay + worker + specs), matching the CLAUDE.md terminology standard and the already-canonical `ipns_records.encrypted_ipns_private_key` DB column.
- No entity, migration, or OpenAPI/api-client surface changed — this plan is purely an internal rename with no cross-package regeneration required.
- Ready for the next plan in Phase 77's terminology-canonicalization sequence.

---
*Phase: 77-crypto-hygiene-and-terminology-canonicalization*
*Completed: 2026-07-11*
