# Quick Task 023: M2 Tech Debt — Store Logout Cleanup

## Task

Fix 2 tech debt items from M2 milestone audit:

1. **Share store not cleared on logout** — `clearShares()` exists in `share.store.ts:93` but never called in `useAuth.ts` logout sequence
2. **Quota store not cleared on logout** — No `reset()` method exists; quota data persists across sessions

## Changes

### 1. Add `reset()` to quota store (`apps/web/src/stores/quota.store.ts`)

- Add `reset: () => void` to `QuotaState` type
- Implement `reset()` that restores all fields to initial values (0 used, 500 MiB limit, no error)

### 2. Wire both stores into logout (`apps/web/src/hooks/useAuth.ts`)

- Import `useShareStore` and `useQuotaStore`
- Call `useShareStore.getState().clearShares()` in logout (both try and catch paths)
- Call `useQuotaStore.getState().reset()` in logout (both try and catch paths)

## Verification

- `pnpm --filter web build` passes
