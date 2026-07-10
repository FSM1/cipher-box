---
phase: 73-shared-write-navigation-correctness-web
plan: 02
subsystem: sdk-core
tags: [ipns, sdk-core, error-handling, vitest, shared-write]

requires:
  - phase: 73-shared-write-navigation-correctness-web
    provides: "73-RESEARCH.md / 73-PATTERNS.md — the SC4 gap map and the 404-catch idiom this plan mirrors"
provides:
  - "createAndPublishIpnsRecord catches a real 410 (IPNS_TOMBSTONED) and returns { success:false, sequenceNumber:0n, tombstoned:true } instead of letting a raw AxiosError propagate"
  - "Vitest proof of the 410->tombstoned mapping and a non-410-rethrow regression guard"
affects: [73-05-plan-publishNodeFn-mapping, 73-08-plan]

tech-stack:
  added: []
  patterns:
    - "try/catch around ipnsControllerPublishRecord mirrors the existing status-extraction idiom in resolveIpnsRecord (anyError.status ?? anyError.response?.status)"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/ipns/index.ts
    - packages/sdk-core/src/__tests__/ipns.test.ts

key-decisions:
  - "410 is the ONLY status mapped to tombstoned:true; every other status/error rethrows unchanged (no silent swallow of publish failures)"
  - "Return type extended additively with tombstoned?: boolean — existing callers unaffected (field is absent/undefined on the 2xx path)"
  - "No zeroing introduced in the new catch branch — the D-05/T-47-01 caller-owns-key contract is preserved verbatim"

patterns-established:
  - "SC4(a) transport mapping: catch a specific HTTP status crossing an SDK->API trust boundary and translate it into a typed result field, rather than letting the raw transport error leak to callers"

requirements-completed: [SC4]

coverage:
  - id: D1
    description: "createAndPublishIpnsRecord maps a real 410 (IPNS_TOMBSTONED) rejection from ipnsControllerPublishRecord into { success:false, sequenceNumber:0n, tombstoned:true } instead of throwing"
    requirement: "SC4"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/ipns.test.ts#SC4(a): maps a 410 rejection to { success:false, tombstoned:true }"
        status: pass
    human_judgment: false
  - id: D2
    description: "A non-410 rejection (e.g. 500) still rethrows unchanged; no swallowing of other publish failures"
    requirement: "SC4"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/ipns.test.ts#SC4(a) regression: a non-410 rejection (500) still rethrows unchanged"
        status: pass
    human_judgment: false
  - id: D3
    description: "The 2xx success path is unchanged (tombstoned absent/undefined) and the caller-owned ipnsPrivateKey buffer is never zeroed by this callee, on either the success or throw path"
    requirement: "SC4"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/ipns.test.ts#createAndPublishIpnsRecord caller-owns-key (S3/D-05) > A / B"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-07-10
status: complete
---

# Phase 73 Plan 02: createAndPublishIpnsRecord 410-to-tombstoned mapping Summary

**createAndPublishIpnsRecord now catches a real IPNS_TOMBSTONED 410 and returns `{ success:false, sequenceNumber:0n, tombstoned:true }`, proven by two new Vitest cases plus the existing 369-test sdk-core suite staying green.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-07-10T21:17:00Z (approx, first RED test run)
- **Completed:** 2026-07-10T21:18:53Z
- **Tasks:** 2 completed (RED, GREEN)
- **Files modified:** 2

## Accomplishments

- `createAndPublishIpnsRecord`'s `ipnsControllerPublishRecord` call is now wrapped in try/catch, reusing the exact status-extraction idiom already used by `resolveIpnsRecord`'s 404 handling
- A 410 response now surfaces as a typed `tombstoned: true` result instead of an uncaught `AxiosError` — this is the deepest of SC4's four stacked gaps and the sole transport-layer dependency for plan 73-05's `publishNodeFn` mapping
- Return type extended additively (`tombstoned?: boolean`) so no existing caller's type signature breaks
- Regression guard added confirming non-410 errors (500, generic `Error`) still propagate unchanged — no swallowing

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): add failing 410-tombstoned and non-410-rethrow tests** - `ef2492aeb` (test)
2. **Task 2 (GREEN): map 410 to tombstoned in createAndPublishIpnsRecord** - `73fd3b491` (feat)

_Note: this plan is `type: tdd` at the plan level — RED then GREEN, no separate REFACTOR commit was needed (the GREEN implementation was already minimal)._

## Files Created/Modified

- `packages/sdk-core/src/ipns/index.ts` - `createAndPublishIpnsRecord`'s publish call wrapped in try/catch; 410 maps to `{ success:false, sequenceNumber:0n, tombstoned:true }`; return type extended with `tombstoned?: boolean`
- `packages/sdk-core/src/__tests__/ipns.test.ts` - two new cases under `describe('createAndPublishIpnsRecord', ...)`: the 410-tombstoned mapping and the non-410-rethrow regression guard

## Decisions Made

- Only `status === 410` maps to `tombstoned:true`; every other status or error type rethrows unchanged (threat T-73-02-01 disposition: mitigate)
- No key zeroing was added anywhere in the new catch branch — the D-05/T-47-01 caller-owns-key contract (`ipnsPrivateKey` buffer reuse across publishes/CAS retries) is preserved verbatim, and both pre-existing S3 guard tests (`does NOT zero ... after a successful publish` / `... when publish throws`) still pass unmodified (threat T-73-02-02 disposition: mitigate)

## Deviations from Plan

None - plan executed exactly as written. The plan's own acceptance criteria (RED fails only on the 410 case, GREEN passes, full suite green, no D-05 block changes, no new `.fill(0)`) were all met without needing any auto-fixes.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The `tombstoned?: boolean` field on `createAndPublishIpnsRecord`'s return value is now live and is the sole signal plan 73-05's `publishNodeFn` needs to raise `CannotWriteUntilRefetchError`
- Full `packages/sdk-core` suite (369 tests, 32 files) and `tsc --noEmit` both pass with these changes; no regressions in `resolveIpnsRecord` or any other IPNS consumer
- `pnpm api:generate` was not required — no `apps/api` code was touched, no OpenAPI surface change

---

*Phase: 73-shared-write-navigation-correctness-web*
*Completed: 2026-07-10*

## Self-Check: PASSED

- FOUND: packages/sdk-core/src/ipns/index.ts
- FOUND: packages/sdk-core/src/__tests__/ipns.test.ts
- FOUND: .planning/phases/73-shared-write-navigation-correctness-web/73-02-SUMMARY.md
- FOUND commit: ef2492aeb (test)
- FOUND commit: 73fd3b491 (feat)
