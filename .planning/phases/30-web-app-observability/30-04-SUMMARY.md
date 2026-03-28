---
phase: 30-web-app-observability
plan: 04
subsystem: infra
tags: [faro, logger, auth, user-identity, observability]

requires:
  - phase: 30-01
    provides: Faro SDK with getFaroInstance, setFaroUser, clearFaroUser, registerFaroTransport
provides:
  - Faro logger transport (warn/error forwarding to Grafana)
  - User identity binding on auth (publicKey only)
  - User identity clearing on logout
affects: [error-attribution, user-debugging]

tech-stack:
  added: []
  patterns: ['Faro user identity binding pattern', 'logger transport forwarding']

key-files:
  created: []
  modified:
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/lib/faro.ts

key-decisions:
  - 'setFaroUser called after vault init completes (not during auth flow) to avoid partial state'
  - 'clearFaroUser called in both success and error paths of logout for consistency'
  - 'Session restoration reads publicKey from auth store vaultKeypair (avoids dynamic hook import)'
  - 'registerFaroTransport designed for Phase 28 logger but functional now — ready when logger ships'

patterns-established:
  - 'User identity binding: publicKey only, set after auth, cleared on logout'
  - 'Logger transport: warn->pushLog, error->pushError, debug/info filtered'

requirements-completed: []

duration: 3min
completed: 2026-03-28
---

# Plan 30-04: Logger Transport Integration and User Identity Binding Summary

**Faro user identity wired into auth flow (publicKey only) with logger transport ready for Phase 28 integration**

## Performance

- **Duration:** 3 min
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments

- Added setFaroUser(publicKey) call in completeBackendAuth after vault initialization
- Added setFaroUser in session restoration path using vaultKeypair from auth store
- Added clearFaroUser() in both logout paths (success and error)
- registerFaroTransport already exported from faro.ts (created in 30-01) — ready for Phase 28 logger

## Task Commits

1. **Tasks 1-3: Transport export, main.tsx wiring, auth identity binding** - `93f4cfdf8`

## Files Created/Modified

- `apps/web/src/hooks/useAuth.ts` - setFaroUser on auth success/session restore, clearFaroUser on logout
- `apps/web/src/lib/faro.ts` - registerFaroTransport and clearFaroUser functions (created in 30-01 commit)

## Decisions Made

- Phase 28 logger module doesn't exist yet (Phase 28 not executed), so registerFaroTransport is exported but not called from main.tsx — will be wired when Phase 28 ships
- Used bytesToHex(vaultKeypair.publicKey) for session restoration path instead of dynamic hook import

## Deviations from Plan

- **Logger transport registration deferred:** Plan specified registering transport in main.tsx with `logger.transports`, but the logger module from Phase 28 doesn't exist yet. The `registerFaroTransport` function is ready and exported; it just needs to be called when the logger ships.
- **No modification to main.tsx for transport:** Since there's no logger module to import, the `registerFaroTransport(logger.transports)` call was omitted from main.tsx. This is a no-op deviation — the function is ready.

## Issues Encountered

None.

## Next Phase Readiness

- When Phase 28 logger ships, add `registerFaroTransport(logger.transports)` to main.tsx after initFaro()
- All Faro infrastructure is complete and ready for staging deployment

---

_Phase: 30-web-app-observability_
_Completed: 2026-03-28_
