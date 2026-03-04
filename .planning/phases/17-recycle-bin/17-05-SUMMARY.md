---
phase: 17-recycle-bin
plan: 05
subsystem: testing
tags: [playwright, e2e, recycle-bin, fuse, powershell, bash]

# Dependency graph
requires:
  - phase: 17-03
    provides: Web app bin UI (BinBrowser, BinListItem, BinEmptyState, ConfirmDialog)
  - phase: 17-04
    provides: Desktop FUSE bin entry creation (soft-delete via unlink/rmdir)
provides:
  - Playwright E2E test suite covering full web app bin lifecycle (6 test cases)
  - BinPage page object for reusable bin interactions in future tests
  - Desktop E2E bash script verifying FUSE delete creates recoverable soft-delete
  - Desktop E2E PowerShell equivalent for Windows CI
  - Updated run-all orchestrators with Step 5 (recycle bin)
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'BinPage page object encapsulates bin navigation, item listing, context menu, and composite actions'
    - 'Desktop bin test uses auth + vault API check to verify bin infrastructure without requiring ECIES decryption in bash'

key-files:
  created:
    - tests/e2e/page-objects/pages/bin.page.ts
    - tests/e2e/tests/recycle-bin.spec.ts
    - tests/e2e-desktop/scripts/test-recycle-bin.sh
    - tests/e2e-desktop/scripts/test-recycle-bin.ps1
  modified:
    - tests/e2e/page-objects/index.ts
    - tests/e2e-desktop/scripts/run-all.sh
    - tests/e2e-desktop/scripts/run-all.ps1

key-decisions:
  - 'Desktop test verifies soft-delete indirectly (file gone from mount + API reachable) since ECIES decryption of bin metadata is not feasible in bash'
  - 'Web E2E tests use serial describe to share auth session across all 6 test cases'

patterns-established:
  - 'BinPage follows same page-object-per-page pattern as InvitePageObject (tests/e2e/page-objects/pages/)'
  - 'Desktop bin test follows same pass/fail counter + auth setup pattern as test-round-trip.sh'

# Metrics
duration: 5min
completed: 2026-03-04
---

# Phase 17 Plan 05: E2E Recycle Bin Tests Summary

**Playwright E2E suite with 6 test cases covering full bin lifecycle, plus desktop bash/PowerShell scripts verifying FUSE soft-delete behavior**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-04T02:23:22Z
- **Completed:** 2026-03-04T02:28:31Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Created BinPage page object with navigation, item querying, context menu actions, and composite methods (restore, permanent delete, empty bin)
- Created recycle-bin.spec.ts with 6 serial test cases: delete-to-bin, restore, permanent delete, empty bin, metadata display, sidebar navigation
- Created desktop E2E scripts (bash + PowerShell) testing FUSE delete -> file removed -> API reachable
- Updated run-all orchestrators on both platforms with Step 5 (recycle bin)

## Task Commits

Each task was committed atomically:

1. **Task 1: Create web app bin E2E tests** - `0c968836e` (feat)
2. **Task 2: Create desktop E2E recycle bin test scripts** - `96527a6d1` (feat)

## Files Created/Modified

- `tests/e2e/page-objects/pages/bin.page.ts` - BinPage page object for bin browser interactions (170 lines)
- `tests/e2e/tests/recycle-bin.spec.ts` - Playwright E2E test suite with 6 test cases (312 lines)
- `tests/e2e/page-objects/index.ts` - Added BinPage barrel export
- `tests/e2e-desktop/scripts/test-recycle-bin.sh` - Bash E2E script for FUSE bin testing (135 lines)
- `tests/e2e-desktop/scripts/test-recycle-bin.ps1` - PowerShell equivalent for Windows (158 lines)
- `tests/e2e-desktop/scripts/run-all.sh` - Added Step 5 recycle bin
- `tests/e2e-desktop/scripts/run-all.ps1` - Added Step 5 recycle bin

## Decisions Made

- Desktop E2E tests verify soft-delete indirectly rather than decrypting ECIES bin metadata in bash. Rationale: ECIES decryption requires Node.js crypto libraries not available in bash; the web E2E tests handle full bin content verification.
- Web E2E tests use `test.describe.serial` to share a single auth session. Rationale: follows the pattern from conflict-detection.spec.ts; avoids repeated auth overhead across 6 test cases.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 17 (Recycle Bin) is now fully complete with all 5 plans executed
- Web app: bin crypto, store, hooks, UI, and E2E tests all in place
- Desktop: bin crypto, FUSE integration, and E2E tests all in place
- Ready for phase completion and PR to main

---

_Phase: 17-recycle-bin_
_Completed: 2026-03-04_
