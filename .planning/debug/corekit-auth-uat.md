# Debug Session: CoreKit Auth Flow UAT

**Created:** 2026-02-16
**Status:** IN PROGRESS — ISSUE-001 RESOLVED, resuming UAT
**Scope:** Full E2E auth flow verification after CoreKit refactor (Phases 12-12.4)

## Test Results

| TC | Description | Status | Notes |
|----|-------------|--------|-------|
| 01 | Login page initial render | PASS | All elements render: heading, Google (disabled/not configured), email input + SEND OTP, wallet button, footer, [CONNECTED] status |
| 02 | Email login - happy path | PASS | ISSUE-001 fixed (useRef), ISSUE-003 fixed (persistent JWKS key), env fixed (Kubo→192.168.133.114, mock IPNS router). Fresh user: OTP→verify→loginWithJWT(3.6s)→commit→#/files with empty vault |
| 03 | Email login - invalid OTP | - | |
| 04 | Email login - back navigation | - | |
| 05 | Email login - OTP resend | - | |
| 06 | Email login - rate limiting | - | |
| 07 | Google login - happy path | - | |
| 08 | Google login - popup blocked | - | |
| 09 | Wallet login - happy path | - | |
| 10 | Wallet login - cancel | - | |
| 11 | Wallet login - no wallet | - | |
| 12 | Wallet login - reject signature | - | |
| 13 | Session restoration (refresh) | PASS* | *Session restoration from a previous CoreKit session works: `/auth/refresh` returns 200, vault loads. But this only works with pre-existing localStorage session — cannot create new sessions due to ISSUE-001 |
| 14 | Already authenticated redirect | - | |
| 15 | MFA login - REQUIRED_SHARE | - | |
| 16 | MFA login - cross-device approval | - | |
| 17 | MFA login - approve request | - | |
| 18 | MFA login - deny request | - | |
| 19 | MFA login - retry after denial | - | |
| 20 | MFA login - request expiry | - | |
| 21 | MFA login - recovery phrase | - | |
| 22 | MFA login - invalid recovery | - | |
| 23 | MFA login - recovery back nav | - | |
| 24 | MFA enrollment prompt | - | |
| 25 | MFA enrollment - setup MFA | - | |
| 26 | MFA enrollment - full wizard | - | |
| 27 | Authorized devices list | - | |
| 28 | Revoke device | - | |
| 29 | Revoke device - blocked | - | |
| 30 | Recovery phrase regeneration | - | |
| 31 | Recovery phrase regen - cancel | - | |
| 32 | Logout | PASS | User menu -> [logout] clears session, returns to login page. CoreKit session + backend cookie cleared |
| 33 | Logout - backend down | - | |
| 34 | DeviceApprovalModal - multiple | - | |
| 35 | DeviceApprovalModal - tab visibility | - | |
| 36 | New user vault initialization | - | |

## Issues Found

### ISSUE-001: Browser tab crash during login — RESOLVED

**Severity:** Critical — blocked all fresh login flows
**Reproducibility:** 3/3 attempts
**Branch:** `fix/auth-publickey-format`
**Resolution:** Fixed in `useDeviceApproval.ts`

**Root cause:** NOT CoreKit `loginWithJWT` — it was a dependency oscillation bug in `useDeviceApproval.ts`.

`pollPendingRequests` used `isPollingPending` (React state) in its `useCallback` deps. The `DeviceApprovalModal` useEffect depended on `pollPendingRequests` and its cleanup called `stopApproverPolling()` which reset `isPollingPending` to false. This created an infinite render loop:
1. Effect fires -> `pollPendingRequests()` -> sets `isPollingPending=true` -> re-render
2. `pollPendingRequests` gets new identity (dep changed) -> effect cleanup fires -> `stopApproverPolling()` sets `isPollingPending=false` -> re-render
3. Repeat forever — each cycle fires an immediate HTTP request to `/device-approval/pending`

Result: 12,962 failed requests -> `ERR_INSUFFICIENT_RESOURCES` -> browser tab crash.

**Fix:** Converted `isPollingPending` from `useState` to `useRef`. Refs don't trigger re-renders or change callback identities, breaking the oscillation.

**Lesson:** When a tab freezes "after X", check what ELSE activates when X runs. The DeviceApprovalModal polling started because auth state changed during login, not because of anything in CoreKit itself.

### ISSUE-002: Dev OTP mismatch with E2E test credentials

**Severity:** Low (documentation/tooling)

**Description:** The `tests/e2e/.env` file contains a static OTP `851527` for `test_account_4718@example.com`, but the dev API generates random OTPs each time (via `randomInt()` in `EmailOtpService`). The E2E OTP is only valid for the Playwright E2E test framework (which presumably has a way to bypass/match), not for manual UAT.

**Impact:** Initial TC02 attempt used the wrong OTP, leading to 401 from `/auth/identity/email/verify-otp`. Login appeared successful only because of session restoration (TC13) from a pre-existing CoreKit session.

**Fix:** For manual UAT, always read the dev OTP from API logs: `grep "DEV OTP" <api-log-file> | tail -1`

## Session Log

### 2026-02-16 16:29 — Session Start

- **Environment setup:**
  - API started on port 3000 (PostgreSQL/Redis on 192.168.133.114)
  - Frontend started on port 5176 (Vite picked 5176 instead of 5173)
  - Added `http://localhost:5176` to `WEB_APP_URL` in `apps/api/.env` for CORS
  - ngrok tunnel already active: `https://1c18-2003-fb-ef11-51b8-44dc-5045-9733-7e48.ngrok-free.app`

### 2026-02-16 16:34 — TC01 Login Page Render

- Navigated to `http://localhost:5176`
- After ~8s init, login page renders with all expected elements
- Status bar shows "[CONNECTED]"
- Google button disabled (expected — not configured in dev)
- Email input + SEND OTP enabled after init
- Wallet button enabled
- **Result: PASS**

### 2026-02-16 16:35 — TC02 Attempt 1 (incorrect OTP)

- Entered email `test_account_4718@example.com`, OTP `851527` (from e2e .env)
- `/auth/identity/email/verify-otp` returned 401 (API generated OTP was `788335`)
- User still redirected to `#/files` — this was session restoration (TC13) from pre-existing CoreKit localStorage, not a successful login
- Console errors: 2x 401 from verify-otp, 1x `[useAuth] Email login failed: AxiosError`
- Vault sync stuck on "resolving ipns records" (known IPNS issue)
- **Discovered ISSUE-002** (OTP mismatch)

### 2026-02-16 16:38 — Logout + TC02 Attempt 2

- Logged out via user menu -> [logout]
- **TC32 Logout: PASS** (returned to login page, session cleared)
- Re-entered email, sent OTP, read dev OTP `216548` from API logs
- Verified OTP -> API returned 200, `IdentityController` logged successful JWT issuance
- CoreKit `loginWithJWT` started -> browser tab froze
- After ~35s, tab crashed completely (Playwright connection lost)
- **Discovered ISSUE-001** (loginWithJWT crash)

### 2026-02-16 17:19 — TC02 Attempt 3 (fresh storage)

- Killed Chrome, relaunched, cleared localStorage/sessionStorage
- CoreKit init completed without freeze (no stale session to restore)
- Re-entered email, sent OTP, read dev OTP `564756`
- Verified OTP -> `loginWithJWT` started -> tab froze -> crashed at ~30s
- **Confirmed ISSUE-001 is reproducible** (2/2 clean attempts)

### 2026-02-16 17:22 — TC02 Attempt 4 (confirmation)

- Used `browser_run_code` to clear storage + reload atomically
- Login page rendered cleanly, entered email, sent OTP, read dev OTP `781258`
- Verified OTP -> `loginWithJWT` started -> tab crashed at ~30s
- **ISSUE-001 confirmed 3/3 attempts**
- UAT blocked pending resolution
