---
phase: 16-advanced-sync
plan: 04
subsystem: testing
tags: [playwright, e2e, conflict-detection, ipns, optimistic-concurrency]

# Dependency graph
requires:
  - phase: 16-01-optimistic-concurrency
    provides: API expectedSequenceNumber field and 409 Conflict response
  - phase: 16-02-web-client-conflict-handling
    provides: Web client re-sync + retry logic on 409 (tests written against spec)
provides:
  - Playwright E2E test suite for conflict detection scenarios
  - bumpServerSequence helper utility for simulating concurrent device publishes
  - 3 E2E tests: upload with stale seq, create folder with stale seq, negative per-file test
affects: [ci, e2e-suite, 16-05]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'bumpServerSequence pattern: resolve current CID + unconditional publish to advance server-side sequence number'
    - 'Negative test pattern: verify per-file IPNS updates bypass conflict detection'

key-files:
  created:
    - tests/e2e/tests/conflict-detection.spec.ts
    - tests/e2e/utils/conflict-helpers.ts
  modified: []

key-decisions:
  - 'bumpServerSequence uses unconditional publish (no expectedSequenceNumber) to simulate another device -- simpler than matching exact expected sequence'
  - 'Test 3 uses TextEditorDialog save (handleUpdateFile) which publishes only per-file IPNS, not folder IPNS -- confirms no conflict'
  - 'test.slow() applied to all conflict tests to accommodate re-sync latency'

patterns-established:
  - 'API sequence bump via resolve-then-unconditional-publish: reliable way to make client sequence stale without needing IPNS key material'
  - 'Dummy base64 record pattern for test-only publishes: documents expected delegated routing warning in JSDoc'

# Metrics
duration: 10min
completed: 2026-03-03
---

# Phase 16 Plan 04: Conflict Detection E2E Tests Summary

**Playwright E2E tests for IPNS conflict detection: bumpServerSequence helper + 3 tests covering upload, folder creation, and negative per-file scenarios**

## Performance

- **Duration:** 10 min
- **Started:** 2026-03-03T12:05:55Z
- **Completed:** 2026-03-03T12:15:55Z
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments

- Created `conflict-helpers.ts` with `bumpServerSequence` function that increments the server-side folder sequence number via direct API calls (resolve + unconditional publish)
- Created `conflict-detection.spec.ts` with 3 serial E2E tests covering all conflict detection scenarios from the plan spec
- Tests follow existing patterns: `test.describe.serial`, page objects, `loginViaTestEndpoint`/`loginViaEmail` fallback, `createTestTextFile` for upload data
- TypeScript compiles without errors

## Task Commits

Each task was committed atomically:

1. **Task 1: Create conflict helper utility and E2E test suite** - `50e33795a` (test)

**Plan metadata:** (to be added in final commit)

## Files Created/Modified

- `tests/e2e/utils/conflict-helpers.ts` - `bumpServerSequence` helper that resolves current root folder CID then calls unconditional publish to advance DB sequence number, simulating another device publishing
- `tests/e2e/tests/conflict-detection.spec.ts` - 3 serial E2E tests: (1) upload file with stale sequence -> auto re-sync -> file visible; (2) create folder with stale parent sequence -> auto re-sync -> folder visible; (3) negative: per-file text editor save does NOT trigger conflict even with stale folder sequence

## Decisions Made

- `bumpServerSequence` uses the unconditional publish path (omitting `expectedSequenceNumber`) rather than trying to match the current sequence for the bump itself. This is simpler and does not require the test to have access to IPNS private key material for signing a real record.
- Dummy base64 record string is used for the bump publish. The API logs a delegated routing warning (invalid IPNS record format) but the DB sequence increment succeeds. JSDoc documents this expected behavior.
- Test 3 (negative) uses the `TextEditorDialogPage` save flow which calls `handleUpdateFile` -- this publishes only the per-file IPNS record, not the folder IPNS record, so it bypasses conflict detection entirely.

## Deviations from Plan

None - plan executed exactly as written.

The only minor implementation difference from the plan was using `textEditorDialog.setContent()` and `textEditorDialog.waitForContentLoaded()` (the actual method names in the page object) rather than the plan's pseudocode `clearAndType()`. This is expected -- the plan specifies behavior, not exact method names.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required. Tests require API + frontend running locally for full execution.

## Next Phase Readiness

- Conflict detection E2E tests ready to run once Plans 16-02 (web client conflict handling) is merged
- Tests will fail until Plan 16-02's `expectedSequenceNumber` passing + 409 handling is merged (the `bumpServerSequence` helper will succeed, but the web client won't re-sync/retry, so operations will appear stuck)
- Phase 16 will be complete once all 5 plans (01-05) are merged

---

_Phase: 16-advanced-sync_
_Completed: 2026-03-03_
