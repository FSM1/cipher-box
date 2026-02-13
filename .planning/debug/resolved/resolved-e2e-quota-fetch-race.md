---
status: diagnosed
trigger: 'e2e test failing after adding useEffect fetchQuota to StorageQuota component'
created: 2026-02-10T00:00:00Z
updated: 2026-02-10T00:01:00Z
symptoms_prefilled: true
goal: find_root_cause_only
---

## Current Focus

hypothesis: CONFIRMED - fetchQuota fires before auth token is available after page reload, racing with session restoration's refresh token call; with server-side token rotation one refresh fails, and if the interceptor's fails it calls logout()
test: Traced full code path through 8 source files
expecting: N/A - root cause confirmed
next_action: Return diagnosis

## Symptoms

expected: e2e test full-workflow.spec.ts passes after adding useEffect fetchQuota to StorageQuota
actual: e2e test reportedly failing in CI after the change
errors: Likely 401 on GET /vault/quota triggering refresh race -> logout -> session destroyed
reproduction: Run e2e test full-workflow.spec.ts, observe test 3.7+ after page.reload()
started: After adding useEffect(() => { fetchQuota(); }, [fetchQuota]) to StorageQuota.tsx

## Eliminated

## Evidence

- timestamp: 2026-02-10T00:00:10Z
  checked: VaultController (apps/api/src/vault/vault.controller.ts)
  found: @UseGuards(JwtAuthGuard) at controller level, GET /vault/quota requires valid JWT
  implication: Any request to /vault/quota without a valid access token returns 401

- timestamp: 2026-02-10T00:00:15Z
  checked: StorageQuota.tsx and AppSidebar.tsx
  found: StorageQuota fires fetchQuota() unconditionally on mount via useEffect with no auth check
  implication: If StorageQuota mounts before auth is ready, fetchQuota sends unauthenticated request

- timestamp: 2026-02-10T00:00:20Z
  checked: FilesPage.tsx loading state (lines 24-29)
  found: Loading state renders <AppShell> which includes <AppSidebar> -> <StorageQuota>
  implication: StorageQuota mounts and fires fetchQuota DURING auth restoration, before token is available

- timestamp: 2026-02-10T00:00:25Z
  checked: routes/index.tsx
  found: No route-level auth guard; /files renders FilesPage directly
  implication: Auth protection is component-level only (useAuth hook in FilesPage)

- timestamp: 2026-02-10T00:00:30Z
  checked: API client interceptor (apps/web/src/lib/api/client.ts lines 27-77)
  found: 401 interceptor creates refreshPromise to POST /auth/refresh; on refresh FAILURE the catch handler calls logout() clearing ALL stores (lines 57-65)
  implication: If fetchQuota's 401 -> refresh fails, the app logs out completely

- timestamp: 2026-02-10T00:00:35Z
  checked: useAuth.ts restoreSession (lines 341-453)
  found: Session restoration also calls authApi.refresh() (line 385 for E2E, line 413 for normal). Both paths go through apiClient which uses the same refresh cookie.
  implication: Two concurrent POST /auth/refresh calls race against each other

- timestamp: 2026-02-10T00:00:40Z
  checked: TokenService.rotateRefreshToken (apps/api/src/auth/services/token.service.ts lines 48-94)
  found: Server uses refresh token rotation - old token is revoked (line 89: validToken.revokedAt = new Date()) before new tokens are created (line 93)
  implication: Two concurrent refresh calls using the same token: first succeeds and revokes token, second fails with UnauthorizedException('Invalid refresh token')

- timestamp: 2026-02-10T00:00:45Z
  checked: E2E test setup (playwright.config.ts, test files)
  found: No **e2e_test_mode** flag set by tests. Tests use real Web3Auth login flow.
  implication: After reload, normal (non-E2E) session restoration path applies

- timestamp: 2026-02-10T00:00:50Z
  checked: auth.store.ts
  found: accessToken stored in memory only (not localStorage), wiped on page reload
  implication: After page.reload() in test 3.7, accessToken is null until session restoration completes

## Resolution

root_cause: |
After page.reload() in test 3.7, the StorageQuota component mounts (rendered by AppShell
even during FilesPage's loading state) and immediately fires fetchQuota() via useEffect.
At this point, accessToken is null (Zustand memory-only store was wiped by reload).

The request chain is:

1. fetchQuota() -> GET /vault/quota (no auth header, token is null)
2. Server returns 401 (JwtAuthGuard rejects)
3. Axios 401 interceptor fires -> POST /auth/refresh (using valid refresh cookie)
4. Meanwhile, useAuth's restoreSession also fires -> POST /auth/refresh (same cookie)
5. Server uses refresh token rotation (token.service.ts line 89): first call succeeds
   and REVOKES the old token, second call fails with 'Invalid refresh token'
6. If the interceptor's refresh call is the one that fails (loses the race), its .catch()
   handler (client.ts lines 57-65) calls useAuthStore.getState().logout(), clearing ALL
   stores and destroying the session
7. All subsequent e2e tests fail because the user is logged out

The race is non-deterministic but biased: useAuth's restoreSession effect typically fires
after StorageQuota's effect (React processes child effects first), but the interceptor's
refresh is triggered only after the GET /vault/quota round-trip returns 401. By that time,
useAuth's refresh may already be in-flight or completed, having rotated the token.

fix: |
Guard fetchQuota() in StorageQuota with an auth check. Only fetch when there is an
authenticated session with an access token available:

In apps/web/src/components/layout/StorageQuota.tsx:

```tsx
import { useEffect } from 'react';
import { useQuotaStore } from '../../stores/quota.store';
import { useAuthStore } from '../../stores/auth.store';

export function StorageQuota() {
  const { usedBytes, limitBytes, fetchQuota } = useQuotaStore();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  useEffect(() => {
    if (isAuthenticated) {
      fetchQuota();
    }
  }, [fetchQuota, isAuthenticated]);
  // ... rest unchanged
}
```

This ensures fetchQuota() only fires once isAuthenticated is true (i.e., after session
restoration has set the access token). No 401, no refresh race, no accidental logout.

verification:
files_changed: []
