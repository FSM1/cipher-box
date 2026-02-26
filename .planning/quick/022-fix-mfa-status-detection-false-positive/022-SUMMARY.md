---
phase: quick-022
plan: 01
subsystem: auth
tags: [web3auth, mfa, core-kit, useMfa]

# Dependency graph
requires:
  - phase: 12.4
    provides: MFA enrollment and status detection (useMfa.ts)
provides:
  - Correct MFA status detection (false for fresh accounts, true after enrollment)
affects: [SecurityTab, MFA enrollment wizard, device approval prompt]

# Tech tracking
tech-stack:
  added: []
  patterns: []

key-files:
  created: []
  modified:
    - apps/web/src/hooks/useMfa.ts

key-decisions:
  - 'totalFactors > 2 threshold: every Core Kit account has 2 default factors (JWT verifier share + hashedShare cloud custodial key), so >= 2 is always true'

patterns-established: []

# Metrics
duration: 2min
completed: 2026-02-26
---

# Quick Task 022: Fix MFA Status Detection False Positive Summary

**Changed MFA detection threshold from `>= 2` to `> 2` to account for 2 default Core Kit factors (JWT verifier + hashedShare)**

## Performance

- **Duration:** 2 min
- **Started:** 2026-02-26T18:56:02Z
- **Completed:** 2026-02-26T18:57:45Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Fixed false-positive MFA status: fresh accounts no longer show [ENABLED]
- Updated JSDoc comment explaining the 2-default-factor reasoning
- SecurityTab, MfaEnrollmentWizard, and DeviceApprovalModal all consume `isMfaEnabled` from the store -- no downstream changes needed

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix MFA status threshold check and update comment** - `ff850e0e7` (fix)

## Files Created/Modified

- `apps/web/src/hooks/useMfa.ts` - Changed `details.totalFactors >= 2` to `details.totalFactors > 2` and updated JSDoc comment

## Decisions Made

- Threshold `> 2` is correct because every Web3Auth MPC Core Kit account starts with exactly 2 factors: the JWT verifier share and the hashedShare (cloud custodial key). After `enableMFA()`, the hashedShare is deleted and replaced by device + recovery factors, pushing totalFactors to 3+.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- MFA status detection is now accurate
- No follow-up work needed

---

_Quick task: 022-fix-mfa-status-detection-false-positive_
_Completed: 2026-02-26_
