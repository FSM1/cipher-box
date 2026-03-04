# Quick Task 023: Summary

## Changes

1. **`apps/web/src/stores/quota.store.ts`** — Added `reset()` method to clear quota state on logout (resets to 0 used / 500 MiB limit / no error)
2. **`apps/web/src/hooks/useAuth.ts`** — Added `useShareStore.getState().clearShares()` and `useQuotaStore.getState().reset()` to both try and catch paths of the logout function

## Verification

- `pnpm --filter web build` passes (no type errors, no runtime issues)

## Tech Debt Closed

- Share store stale data across sessions: FIXED
- Quota store stale data across sessions: FIXED
