---
created: 2026-03-24T07:05
title: Fix session restore race conditions (auth/refresh + vault init)
area: web
files:
  - apps/web/src/lib/api-config.ts
  - apps/web/src/hooks/useAuth.ts
---

## Problem

On page reload, two cascading race conditions break session restore:

### Layer 1: Auth/refresh token race

Multiple React effects fire simultaneously after reload, each triggering `POST /auth/refresh`. The first response rotates the refresh token, causing subsequent calls to fail with 401.

Observed: 6 concurrent refresh calls — 2 returned 401, 4 returned 200.

```text
T=1143ms  POST /auth/refresh  536ms  401  (stale token)
T=1143ms  POST /auth/refresh  543ms  401  (stale token)
T=1143ms  POST /auth/refresh  827ms  200
T=1143ms  POST /auth/refresh  845ms  200  (redundant)
T=1143ms  POST /auth/refresh  849ms  200  (redundant)
T=1143ms  POST /auth/refresh  853ms  200  (redundant)
```

### Layer 2: Vault init race (downstream)

Multiple successful refresh responses mean multiple effects proceed to call `initializeOrLoadVault()` concurrently. Both see `getVault()` → 404 (first hasn't committed yet), both attempt vault init:

```text
1. Effect A: getVault() → 404 → initVault() → publishes IPNS + inserts DB ✓
2. Effect B: getVault() → 404 → initVault() → duplicate key constraint ✗
   → "UQ_folder_ipns_user_ipns" violation at VaultService.initializeVault
   → Error caught → coreKitLogout() → user kicked to login screen
```

This breaks E2E test 3.7 (`Page reload preserves session and reloads root folder`) consistently on CI.

## Evidence

- **Auth/refresh race:** Staging performance baseline (`.planning/perf/staging-baseline-2026-03-24.md`, Scenario 3)
- **Vault init race:** CI E2E failure — `duplicate key value violates unique constraint "UQ_folder_ipns_user_ipns"` at `vault.service.ts:87`, observed across multiple test workers
- **CI run:** <https://github.com/FSM1/cipher-box/actions/runs/23476805860/job/68313756720>

## Solution

Both layers need the **shared-Promise deduplication pattern** (same approach as `PublishCoordinator` for IPNS publishes):

### Fix 1: Auth/refresh deduplication (`auth.ts`)

```typescript
let refreshPromise: Promise<TokenPair> | null = null;

async function refreshAccessToken(): Promise<TokenPair> {
  if (refreshPromise) return refreshPromise;
  refreshPromise = doRefresh().finally(() => {
    refreshPromise = null;
  });
  return refreshPromise;
}
```

### Fix 2: Vault init deduplication (`useAuth.ts`)

```typescript
let vaultInitPromise: Promise<void> | null = null;

const initializeOrLoadVault = async () => {
  if (vaultInitPromise) return vaultInitPromise;
  vaultInitPromise = doInitializeOrLoadVault().finally(() => {
    vaultInitPromise = null;
  });
  return vaultInitPromise;
};
```

Fix 1 is the root cause fix (eliminates the concurrent token refresh). Fix 2 is defense-in-depth (protects against any other code path that might call vault init concurrently).

## Impact

- **High severity** — blocks CI (E2E test 3.7 fails consistently)
- Reduces 6 auth/refresh API calls to 1 on every page reload
- Eliminates duplicate vault init attempts
- Eliminates spurious 401 errors and duplicate key constraint errors in logs
