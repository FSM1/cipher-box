---
phase: 34-e2e-test-expansion-staging-baselines
plan: 01
subsystem: testing
tags: [playwright, e2e, cleanup, account-deletion, afterAll]

# Dependency graph
requires:
  - phase: 16-wallet-login-e2e
    provides: wallet-login-helpers and multi-account-wallet test utilities
provides:
  - Shared deleteAccountViaPage helper for test account teardown
  - All 10 web-e2e specs now clean up accounts in afterAll hooks
  - closeWalletTestAccounts integrates account deletion before context close
affects: [34-02, 34-03, 34-04, web-e2e-tests]

# Tech tracking
tech-stack:
  added: []
  patterns: [best-effort afterAll cleanup, page.evaluate API calls for teardown]

key-files:
  created:
    - tests/web-e2e/utils/cleanup-helpers.ts
  modified:
    - tests/web-e2e/utils/multi-account-wallet.ts
    - tests/web-e2e/tests/full-workflow.spec.ts
    - tests/web-e2e/tests/search-workflow.spec.ts
    - tests/web-e2e/tests/recycle-bin.spec.ts
    - tests/web-e2e/tests/mfa-flows.spec.ts
    - tests/web-e2e/tests/conflict-detection.spec.ts
    - tests/web-e2e/tests/wallet-login.spec.ts
    - tests/web-e2e/tests/journey-timing.spec.ts

key-decisions:
  - 'Local fallback URL http://localhost:3000 instead of staging URL for deleteAccountViaPage (environment-agnostic helper)'
  - 'wallet-login.spec.ts uses afterEach instead of afterAll because it uses Playwright fixture-based pages, not shared contexts'
  - 'conflict-detection.spec.ts deletes once via primary page since both sessions share same wallet identity'

patterns-established:
  - 'Best-effort afterAll cleanup: catch all errors, console.warn, never throw'
  - 'Account deletion before context.close: page must be navigable for API fetch calls'
  - 'Multi-account cleanup via closeWalletTestAccounts includes deletion automatically'

requirements-completed: []

# Metrics
duration: 3min
completed: 2026-03-29
---

# Phase 34 Plan 01: E2E Account Cleanup Summary

**Shared deleteAccountViaPage helper wired into all 10 web-e2e specs to prevent orphaned test accounts in the database**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-29T01:53:47Z
- **Completed:** 2026-03-29T01:57:31Z
- **Tasks:** 2
- **Files modified:** 9

## Accomplishments

- Created `cleanup-helpers.ts` with `deleteAccountViaPage` that calls /auth/refresh + DELETE /auth/account via page.evaluate, with full try/catch best-effort error handling
- Updated `closeWalletTestAccounts` in multi-account-wallet.ts to delete accounts before closing browser contexts, with per-account error isolation
- Wired account deletion into all 10 spec files: 6 single-account specs via direct import, 4 multi-account specs via closeWalletTestAccounts integration

## Task Commits

Each task was committed atomically:

1. **Task 1: Create shared deleteAccountViaPage helper** - `4f951af8e` (test)
2. **Task 2: Wire deleteAccountViaPage into all 10 spec afterAll hooks** - `81cd6e4b3` (test)

## Files Created/Modified

- `tests/web-e2e/utils/cleanup-helpers.ts` - Shared deleteAccountViaPage helper (new file)
- `tests/web-e2e/utils/multi-account-wallet.ts` - closeWalletTestAccounts now deletes accounts before closing contexts
- `tests/web-e2e/tests/full-workflow.spec.ts` - Added deleteAccountViaPage in afterAll
- `tests/web-e2e/tests/search-workflow.spec.ts` - Added deleteAccountViaPage in afterAll
- `tests/web-e2e/tests/recycle-bin.spec.ts` - Added deleteAccountViaPage in afterAll
- `tests/web-e2e/tests/mfa-flows.spec.ts` - Added deleteAccountViaPage in afterAll
- `tests/web-e2e/tests/conflict-detection.spec.ts` - Added deleteAccountViaPage in afterAll
- `tests/web-e2e/tests/wallet-login.spec.ts` - Added deleteAccountViaPage in afterEach for TC09
- `tests/web-e2e/tests/journey-timing.spec.ts` - Added deleteAccountViaPage for Alice + closeWalletTestAccounts for Bob

## Decisions Made

- Used `http://localhost:3000` as final fallback URL instead of staging URL so the helper works in all environments
- wallet-login.spec.ts uses `afterEach` (not `afterAll`) because it uses Playwright's built-in `{ page }` test fixtures rather than shared contexts
- conflict-detection.spec.ts only needs one deletion call since both the primary session and device B share the same wallet identity (same backend userId)
- Multi-account specs (sharing-workflow, writable-shares, invite-link-workflow) needed no spec-level changes since `closeWalletTestAccounts` was updated centrally in Task 1

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Account cleanup infrastructure is in place for all existing specs
- New E2E specs in subsequent plans (34-02, 34-03, 34-04) can import deleteAccountViaPage directly
- Staging environment will no longer accumulate orphaned test accounts from E2E runs

## Self-Check: PASSED

- All created files exist on disk
- All commit hashes found in git log

---

_Phase: 34-e2e-test-expansion-staging-baselines_
_Completed: 2026-03-29_
