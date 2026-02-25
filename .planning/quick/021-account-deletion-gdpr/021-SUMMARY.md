---
phase: quick
plan: 021
subsystem: auth
tags: [gdpr, account-deletion, security-tab, cascade-delete]

# Dependency graph
requires:
  - phase: 12.4
    provides: SecurityTab component with MFA enrollment
provides:
  - DELETE /auth/account endpoint with JWT auth and typed confirmation
  - Danger Zone UI in SecurityTab with type-to-confirm dialog
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Type-to-confirm destructive action pattern (type "DELETE" to enable button)

key-files:
  created:
    - apps/api/src/auth/dto/delete-account.dto.ts
  modified:
    - apps/api/src/auth/auth.controller.ts
    - apps/api/src/auth/auth.service.ts
    - apps/api/src/auth/auth.module.ts
    - apps/web/src/components/mfa/SecurityTab.tsx
    - apps/web/src/lib/api/auth.ts
    - apps/web/src/App.css

key-decisions:
  - 'IPFS unpin before cascade delete -- fetch pinned CIDs and unpin from Kubo (best-effort) before removing DB records'
  - 'ON DELETE CASCADE handles all DB cleanup -- no manual deletion of related records needed'
  - 'Type-to-confirm pattern (type DELETE) prevents accidental account deletion'
  - 'Full logout flow after deletion clears crypto keys, Core Kit session, and all stores'

patterns-established:
  - 'Type-to-confirm for destructive actions: require user to type exact string before enabling confirm button'

# Metrics
duration: 3min
completed: 2026-02-25
---

# Quick Task 021: Account Deletion (GDPR) Summary

DELETE /auth/account endpoint with CASCADE cleanup and Danger Zone UI requiring typed "DELETE" confirmation.

## Performance

- **Duration:** 3 min
- **Started:** 2026-02-25T13:23:29Z
- **Completed:** 2026-02-25T13:26:55Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Backend DELETE /auth/account endpoint with JWT auth and confirmation validation
- IPFS unpin: fetches all pinned CIDs and unpins from local Kubo node (best-effort) before cascade delete
- ON DELETE CASCADE handles all related DB record cleanup (auth_methods, refresh_tokens, vaults, shares, etc.)
- Danger Zone UI in SecurityTab with red terminal aesthetic (#EF4444 red, #001a11 bg)
- Type-to-confirm dialog requiring exact string "DELETE" before deletion proceeds
- Full logout flow after deletion (clear crypto keys, Core Kit session, all stores, redirect to login)
- API client regenerated with new endpoint

## Task Commits

Each task was committed atomically:

1. **Task 1: Backend DELETE /auth/account endpoint** - `2034a907d` (feat)
2. **Task 2: Frontend Danger Zone UI in SecurityTab** - `f55e89f55` (feat)
3. **Task 3: IPFS unpin on account deletion** - `8ae01ddda` (feat)

## Files Created/Modified

- `apps/api/src/auth/dto/delete-account.dto.ts` - DeleteAccountDto and DeleteAccountResponseDto with class-validator decorators
- `apps/api/src/auth/auth.service.ts` - deleteAccount method using userRepository.delete with CASCADE
- `apps/api/src/auth/auth.controller.ts` - DELETE /auth/account endpoint with confirmation validation and cookie clearing
- `apps/web/src/lib/api/auth.ts` - deleteAccount method in authApi wrapper
- `apps/web/src/components/mfa/SecurityTab.tsx` - Danger Zone section with type-to-confirm dialog
- `apps/web/src/App.css` - 22 CSS rules for danger zone styling (red terminal aesthetic)

## Decisions Made

- ON DELETE CASCADE handles all cleanup -- single `userRepository.delete(userId)` removes user + all FK-referenced records
- Type-to-confirm pattern prevents accidental deletion -- button disabled until exact "DELETE" string entered
- Full logout flow reuses existing `useAuth().logout()` after server-side deletion completes
- Danger Zone section renders outside MFA wizard ternary so it's always visible regardless of MFA state

## Deviations from Plan

None - plan executed exactly as written. Task 1 was already committed prior to execution.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Account deletion feature complete end-to-end
- No migration needed (ON DELETE CASCADE already exists on all FK references to users.id)
- Feature ready for PR review

---

_Quick task: 021-account-deletion-gdpr_
_Completed: 2026-02-25_
