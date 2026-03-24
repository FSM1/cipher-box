---
created: 2026-03-24T07:05
title: Deduplicate concurrent auth/refresh token calls on page reload
area: web
files:
  - apps/web/src/lib/api/auth.ts
  - apps/web/src/hooks/useAuth.ts
---

## Problem

On page reload, the app fires multiple concurrent `POST /auth/refresh` calls (observed: 6 simultaneous requests). The first one to arrive invalidates the refresh token, causing subsequent calls to fail with 401. Of 6 calls observed:

- 2 returned 401 (stale token, already rotated)
- 4 returned 200 (race winners, redundant work)

This wastes server resources and can cause auth failures if the 401 responses are processed before the 200 responses, triggering spurious logout.

## Evidence

Discovered during staging performance baseline measurement (2026-03-24). See `.planning/perf/staging-baseline-2026-03-24.md`, Scenario 3 (Session Restore).

Waterfall from Playwright E2E:

```text
T=1143ms  POST /auth/refresh  536ms  401
T=1143ms  POST /auth/refresh  543ms  401
T=1143ms  POST /auth/refresh  827ms  200
T=1143ms  POST /auth/refresh  845ms  200
T=1143ms  POST /auth/refresh  849ms  200
T=1143ms  POST /auth/refresh  853ms  200
```

All 6 requests fired at the same timestamp — classic concurrent refresh race.

## Solution

Share a single in-flight refresh Promise so concurrent callers await the same request:

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

This is the same pattern used for IPNS publish deduplication (`PublishCoordinator`).

## Impact

- Low severity (auth still works — the 200 responses win the race)
- Reduces 6 API calls to 1 on every page reload
- Eliminates spurious 401 errors in logs
