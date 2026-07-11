---
phase: 77-crypto-hygiene-and-terminology-canonicalization
plan: 08
subsystem: crypto
tags: [base64, dedup, sdk-core, rotation, share, ecies]

# Dependency graph
requires:
  - phase: 77-01
    provides: hoisted bytesToBase64/base64ToBytes codec in packages/crypto/src/utils/encoding.ts
provides:
  - rotation/engine.ts, share/grant.ts, share/navigate.ts import the shared @cipherbox/crypto base64 codec instead of defining local copies
affects: [77-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "vitest mocks of @cipherbox/crypto use importOriginal + spread when the mocked module also exports pure helpers (bytesToBase64/base64ToBytes) that must keep their real behavior under test"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/share/grant.ts
    - packages/sdk-core/src/share/navigate.ts
    - packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts
    - packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts
    - packages/sdk-core/src/__tests__/share/grant.test.ts
    - packages/sdk-core/src/__tests__/share/navigate.test.ts

key-decisions:
  - "Imported bytesToBase64/base64ToBytes directly from @cipherbox/crypto in all 3 files (no intermediate share/codec.ts re-export), matching the existing hexToBytes/bytesToHex import convention"
  - "4 vitest full-replacement mocks of @cipherbox/crypto (grant-remint, write-revocation, share/grant, share/navigate tests) switched to the importOriginal + spread pattern already used in file-node.test.ts, so the real base64 codec runs under mocked wrapKey/unwrapKey/reWrapKey — required because these files now import bytesToBase64/base64ToBytes from the mocked module"

patterns-established: []

requirements-completed: [SC2]

coverage:
  - id: D1
    description: "rotation/engine.ts, share/grant.ts, share/navigate.ts base64 duplicates removed and rewired to @cipherbox/crypto; no local codec body remains"
    requirement: "SC2"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk-core test (370 passed, 12 skipped, 0 failed)"
        status: pass
      - kind: other
        ref: "grep -rn 'function bytesToBase64|function base64ToBytes|const CHUNK_SIZE' across the 3 files returns 0 matches"
        status: pass
    human_judgment: false
  - id: D2
    description: "Rotation and share encode/decode round-trips still pass (no behavior change)"
    requirement: "SC2"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk-core test — src/__tests__/rotation/engine.test.ts (56 tests), src/__tests__/rotation/grant-remint.test.ts (4 tests), src/__tests__/rotation/write-revocation.test.ts (8 tests), src/__tests__/share/grant.test.ts (18 tests), src/__tests__/share/navigate.test.ts (7 tests)"
        status: pass
      - kind: other
        ref: "pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk-core typecheck"
        status: pass
    human_judgment: false

duration: 10min
completed: 2026-07-11
status: complete
---

# Phase 77 Plan 08: Dedup rotation/share base64 helpers onto shared crypto codec Summary

**rotation/engine.ts, share/grant.ts, and share/navigate.ts now import bytesToBase64/base64ToBytes from @cipherbox/crypto instead of each defining their own copy**

## Performance

- **Duration:** ~10 min
- **Completed:** 2026-07-11T09:29:53Z
- **Tasks:** 1
- **Files modified:** 7 (3 source + 4 test)

## Accomplishments
- Removed the local `bytesToBase64`/`base64ToBytes` function bodies (and the stale "dedup ... deferred" comment) from `rotation/engine.ts`, `share/grant.ts`, and `share/navigate.ts`
- All 3 files now import the hoisted base64 codec directly from `@cipherbox/crypto` (Plan 77-01), matching the existing `hexToBytes`/`bytesToHex` import convention — no intermediate `share/codec.ts` re-export was created
- sdk-core build, typecheck, and full unit suite (370 tests) stay green — no behavior change

## Task Commits

1. **Task 1: Replace the rotation/share base64 duplicates with the shared crypto import** - `b6f2c4a06` (refactor)

**Plan metadata:** (this commit)

## Files Created/Modified
- `packages/sdk-core/src/rotation/engine.ts` - imports `bytesToBase64`/`base64ToBytes` from `@cipherbox/crypto`; local definitions and stale dedup-deferred comment removed
- `packages/sdk-core/src/share/grant.ts` - imports `bytesToBase64`/`base64ToBytes` from `@cipherbox/crypto`; local definitions removed
- `packages/sdk-core/src/share/navigate.ts` - imports `base64ToBytes` from `@cipherbox/crypto`; local definition removed
- `packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts` - `vi.mock('@cipherbox/crypto', ...)` switched to `importOriginal` + spread so the real codec still runs
- `packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts` - same mock fix
- `packages/sdk-core/src/__tests__/share/grant.test.ts` - same mock fix
- `packages/sdk-core/src/__tests__/share/navigate.test.ts` - same mock fix

## Decisions Made
- Imported directly from `@cipherbox/crypto` in all 3 files rather than creating a `share/codec.ts` re-export, per RESEARCH guidance and to match the existing `hexToBytes`/`bytesToHex` convention.
- Updated the 4 test files' full-replacement `vi.mock('@cipherbox/crypto', ...)` factories to use `importOriginal` + spread (the pattern already established in `file-node.test.ts`) instead of adding `vi.fn()`/manual `btoa`/`atob` reimplementations for `bytesToBase64`/`base64ToBytes` — this keeps the tests exercising the real, single canonical codec rather than a third copy.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated 4 vitest crypto mocks to keep the suite green**
- **Found during:** Task 1 (verification step — `pnpm --filter @cipherbox/sdk-core test`)
- **Issue:** `rotation/grant-remint.test.ts`, `rotation/write-revocation.test.ts`, `share/grant.test.ts`, and `share/navigate.test.ts` each fully replace the `@cipherbox/crypto` module via `vi.mock('@cipherbox/crypto', () => ({...}))` without `bytesToBase64`/`base64ToBytes`. Once `engine.ts`/`grant.ts`/`navigate.ts` started importing those two functions from `@cipherbox/crypto`, the mocked module no longer exported them, and every test exercising the base64 path failed with `[vitest] No "base64ToBytes" export is defined on the "@cipherbox/crypto" mock`.
- **Fix:** Converted each of the 4 `vi.mock('@cipherbox/crypto', ...)` factories to the `async (importOriginal) => ({ ...actual, <mocked fns> })` pattern already used in `file-node.test.ts`, so the real base64 codec is used while `wrapKey`/`unwrapKey`/`reWrapKey`/etc. remain mocked.
- **Files modified:** `packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts`, `packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts`, `packages/sdk-core/src/__tests__/share/grant.test.ts`, `packages/sdk-core/src/__tests__/share/navigate.test.ts`
- **Verification:** `pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk-core test` — 370 passed, 12 skipped, 0 failed
- **Committed in:** `b6f2c4a06` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary to keep the sdk-core suite green per the plan's own acceptance criteria; no scope creep beyond the 3 files/tests directly touched by the codec swap.

## Issues Encountered
None beyond the auto-fixed mock issue above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- The rotation/share base64 duplicates are fully collapsed onto `@cipherbox/crypto`. The 4th duplicate (`packages/sdk-core/src/file/index.ts`) remains for Plan 77-09, which bundles it with a field-rename touching the same file.

---
*Phase: 77-crypto-hygiene-and-terminology-canonicalization*
*Completed: 2026-07-11*
