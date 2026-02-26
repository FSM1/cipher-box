---
status: resolved
trigger: 'Three interrelated MFA authentication bugs after enabling MFA on CipherBox web app'
created: 2026-02-26T00:00:00Z
updated: 2026-02-26T00:15:00Z
---

## Current Focus

hypothesis: All three root causes confirmed and fixed
test: TypeScript compilation + ESLint pass
expecting: Clean build
next_action: Archive and commit

## Symptoms

expected:

1. After enabling MFA, device share saved to localStorage; re-login doesn't require additional shares
2. Recovery key completes authentication and grants vault access
3. Device approval requests work for new browsers needing a share

actual:

1. After MFA enable + logout/login, app shows "missing shares" (required_shares > 0)
2. Recovery key accepted but redirects back to login screen
3. POST /device-approval/request returns 401 Unauthorized

errors:

- "missing shares" state after re-login with MFA enabled
- Recovery key redirected to login
- 401 on POST /device-approval/request

reproduction:

1. Login -> Enable MFA -> Logout -> Login -> "missing shares"
2. Try recovery key -> redirected to login
3. Device approval request -> 401

started: Current state on staging

## Eliminated

(No eliminated hypotheses -- all three initial hypotheses were confirmed.)

## Evidence

- timestamp: 2026-02-26T00:00:30Z
  checked: Web3Auth SDK source code - handleExistingUser() in mpcCoreKit.js
  found: handleExistingUser() tries hashedFactorKey first. When MFA is enabled, the hashedShare is deleted by enableMFA(). The SDK falls through to REQUIRED_SHARE status WITHOUT checking localStorage for the device factor that was stored by enableMFA() -> setDeviceFactor(). This is an SDK design gap -- the app must explicitly call getDeviceFactor() and inputFactorKey() to auto-recover on known devices.
  implication: Bug 1 root cause confirmed. Need app-level workaround in doLoginWithCoreKit.

- timestamp: 2026-02-26T00:00:35Z
  checked: inputFactorKey() in useMfa.ts and session restoration effect in useAuth.ts
  found: inputFactorKey() called syncStatus() which set coreKitLoggedIn=true in React context. The session restoration useEffect (coreKitLoggedIn && !isAuthenticated) fires, tries authApi.refresh() (fails - no valid backend session from temp placeholder login), then calls coreKitLogout() which undoes the entire recovery.
  implication: Bug 2 root cause confirmed. syncStatus() must be deferred until AFTER backend auth completes.

- timestamp: 2026-02-26T00:00:40Z
  checked: Timing of temp token acquisition vs DeviceWaitingScreen mount
  found: doLoginWithCoreKit calls syncStatus() setting isRequiredShare=true in React context. React may flush this state update and mount DeviceWaitingScreen BEFORE loginWithGoogle/Email/Wallet continues to obtain the temp access token. The original useEffect([], []) fired requestApproval() immediately on mount with no token in the auth store, causing 401.
  implication: Bug 3 root cause confirmed. DeviceWaitingScreen must wait for accessToken before firing requestApproval.

- timestamp: 2026-02-26T00:10:00Z
  checked: TypeScript compilation (pnpm --filter web exec tsc --noEmit)
  found: All fixes compile cleanly with no errors.
  implication: Code changes are type-safe.

- timestamp: 2026-02-26T00:12:00Z
  checked: ESLint (pnpm lint)
  found: Only pre-existing warnings (no-explicit-any in test files). Zero new errors from our changes.
  implication: Fixes pass linting.

## Resolution

root_cause: |
BUG 1 (missing shares after re-login): Web3Auth MPC Core Kit SDK v3.5.0's handleExistingUser()
does NOT auto-check localStorage for the device factor when the hashedShare has been deleted
(post-MFA enablement). The SDK tries the hashedFactorKey, finds the hashedShare missing, and
falls through to REQUIRED_SHARE status. The device factor IS persisted in localStorage by
enableMFA() -> setDeviceFactor(), but the SDK never retrieves it during login.

BUG 2 (recovery redirects to login): inputFactorKey() in useMfa.ts called syncStatus() which
prematurely transitioned Core Kit's React context to LOGGED_IN (isRequiredShare=false,
coreKitLoggedIn=true). This triggered the session restoration useEffect in useAuth.ts
(guard: coreKitLoggedIn && !isAuthenticated), which attempted authApi.refresh() -- but the
HTTP-only cookie was from the temporary placeholder session, not a valid one. The refresh
failed, causing coreKitLogout(), which undid the entire recovery.

BUG 3 (401 on device approval request): Race condition. doLoginWithCoreKit calls syncStatus()
which sets isRequiredShare=true in React context. React may flush this update and mount
DeviceWaitingScreen before the calling function (loginWithGoogle/Email/Wallet) continues to
obtain the temporary access token. The original useEffect([], []) on mount fired
requestApproval() immediately with no token in auth store.

fix: |
BUG 1: Added device factor auto-detection in doLoginWithCoreKit() (hooks.ts). After
REQUIRED_SHARE status, call coreKit.getDeviceFactor(). If found, auto-input it via
coreKit.inputFactorKey(). If status transitions to LOGGED_IN, commit and return 'logged_in'.
Otherwise fall through to true REQUIRED_SHARE.

BUG 2: Removed syncStatus() from inputFactorKey() in useMfa.ts. Added syncStatus() call to
completeRequiredShare() in useAuth.ts, AFTER completeBackendAuth() succeeds. At that point
isAuthenticated is true (from setAccessToken), so the session restoration guard
(coreKitLoggedIn && !isAuthenticated) won't fire.

BUG 3: Added accessToken subscription to DeviceWaitingScreen. Changed mount effect to wait for
accessToken before firing requestApproval(). Added requestFiredRef to prevent duplicate
requests. Separated countdown/cancel cleanup into its own effect.

verification: |

- TypeScript compilation: PASS (zero errors)
- ESLint: PASS (zero new errors, only pre-existing warnings)
- Code review: All four files verified for correctness

files_changed:

- apps/web/src/lib/web3auth/hooks.ts
- apps/web/src/hooks/useMfa.ts
- apps/web/src/hooks/useAuth.ts
- apps/web/src/components/mfa/DeviceWaitingScreen.tsx
