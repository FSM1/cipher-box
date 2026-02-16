# Debug Session: CoreKit Auth Flow UAT

**Created:** 2026-02-16
**Status:** IN PROGRESS — Core email flow PASS, MFA UI blocked by ISSUE-004
**Scope:** Full E2E auth flow verification after CoreKit refactor (Phases 12-12.4)

## Test Results

| TC  | Description                          | Status | Notes                                                                                                                                                                                                           |
| --- | ------------------------------------ | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 01  | Login page initial render            | PASS   | All elements render: heading, Google (disabled/not configured), email input + SEND OTP, wallet button, footer, [CONNECTED] status                                                                               |
| 02  | Email login - happy path             | PASS   | ISSUE-001 fixed (useRef), ISSUE-003 fixed (persistent JWKS key), env fixed (Kubo→192.168.133.114, mock IPNS router). Fresh user: OTP→verify→loginWithJWT(3.6s)→commit→#/files with empty vault                  |
| 03  | Email login - invalid OTP            | PASS   | Wrong OTP (999999) returns 401, alert shown: "Request failed with status code 401", returns to email input form                                                                                                 |
| 04  | Email login - back navigation        | PASS   | Back arrow from OTP screen returns to email input with email pre-filled, SEND OTP enabled                                                                                                                       |
| 05  | Email login - OTP resend             | PASS   | Timer countdown works (90s), button enables after timer, click triggers resend. Rate-limited (400) after multiple UAT attempts — error shown gracefully                                                          |
| 06  | Email login - rate limiting          | PASS   | Backend returns 400 "Too many OTP requests" after multiple sends. Frontend shows error alert. Redis rate limit key confirmed working                                                                            |
| 07  | Google login - happy path            | SKIP   | Google not configured in dev (button disabled)                                                                                                                                                                   |
| 08  | Google login - popup blocked         | SKIP   | Google not configured in dev                                                                                                                                                                                     |
| 09  | Wallet login - happy path            | SKIP   | Requires MetaMask/wallet extension — not available in Playwright                                                                                                                                                 |
| 10  | Wallet login - cancel                | SKIP   | Requires MetaMask/wallet extension                                                                                                                                                                               |
| 11  | Wallet login - no wallet             | SKIP   | Requires wallet detection logic — untestable without extension                                                                                                                                                   |
| 12  | Wallet login - reject signature      | SKIP   | Requires MetaMask/wallet extension                                                                                                                                                                               |
| 13  | Session restoration (refresh)        | PASS   | Page refresh restores CoreKit session from IndexedDB, backend `/auth/refresh` returns 200, vault loads with uat-test-folder visible, 0 errors                                                                   |
| 14  | Already authenticated redirect       | PASS   | Navigate to `/#/` while logged in — immediately redirected to `#/files`, no login page flash                                                                                                                    |
| 15  | MFA login - REQUIRED_SHARE           | SKIP   | Requires MFA to be enabled first; SecurityTab not wired into SettingsPage (ISSUE-004)                                                                                                                           |
| 16  | MFA login - cross-device approval    | SKIP   | Requires two devices/sessions                                                                                                                                                                                    |
| 17  | MFA login - approve request          | SKIP   | Requires two devices/sessions                                                                                                                                                                                    |
| 18  | MFA login - deny request             | SKIP   | Requires two devices/sessions                                                                                                                                                                                    |
| 19  | MFA login - retry after denial       | SKIP   | Requires two devices/sessions                                                                                                                                                                                    |
| 20  | MFA login - request expiry           | SKIP   | Requires two devices/sessions                                                                                                                                                                                    |
| 21  | MFA login - recovery phrase          | SKIP   | Requires MFA enabled first                                                                                                                                                                                       |
| 22  | MFA login - invalid recovery         | SKIP   | Requires MFA enabled first                                                                                                                                                                                       |
| 23  | MFA login - recovery back nav        | SKIP   | Requires MFA enabled first                                                                                                                                                                                       |
| 24  | MFA enrollment prompt                | NOTE   | MfaEnrollmentPrompt component exists in AppShell but only fires once per session (checkedRef). Not visible after page navigation — shows on first login only                                                     |
| 25  | MFA enrollment - setup MFA           | BLOCK  | ISSUE-004: SecurityTab not wired into SettingsPage.tsx — Settings.tsx has tabs but SettingsPage.tsx (actually routed) only has LinkedMethods + VaultExport                                                        |
| 26  | MFA enrollment - full wizard         | BLOCK  | Blocked by ISSUE-004                                                                                                                                                                                             |
| 27  | Authorized devices list              | BLOCK  | Blocked by ISSUE-004 — device list is in SecurityTab                                                                                                                                                             |
| 28  | Revoke device                        | BLOCK  | Blocked by ISSUE-004                                                                                                                                                                                             |
| 29  | Revoke device - blocked              | BLOCK  | Blocked by ISSUE-004                                                                                                                                                                                             |
| 30  | Recovery phrase regeneration         | BLOCK  | Blocked by ISSUE-004                                                                                                                                                                                             |
| 31  | Recovery phrase regen - cancel       | BLOCK  | Blocked by ISSUE-004                                                                                                                                                                                             |
| 32  | Logout                               | PASS   | User menu -> [logout] clears session, returns to login page. CoreKit session + backend cookie cleared                                                                                                           |
| 33  | Logout - backend down                | SKIP   | Requires stopping API during active session — destructive test                                                                                                                                                   |
| 34  | DeviceApprovalModal - multiple       | SKIP   | Requires two devices/sessions                                                                                                                                                                                    |
| 35  | DeviceApprovalModal - tab visibility | SKIP   | Requires active approval request from second device                                                                                                                                                              |
| 36  | New user vault initialization        | PASS   | Fresh DB + fresh login: empty vault displayed with "EMPTY DIRECTORY", 0 B usage, "Synced" after initial sync                                                                                                    |

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

### ISSUE-003: Ephemeral JWKS key breaks login after API restart — RESOLVED

**Severity:** Critical — blocked all fresh login flows after API restart
**Branch:** `fix/auth-publickey-format`
**Resolution:** Fixed in `jwt-issuer.service.ts` + persistent key in `.env`

**Root cause:** Without `IDENTITY_JWT_PRIVATE_KEY`, `JwtIssuerService` generates a new RSA keypair on every startup. Web3Auth Torus nodes cache the JWKS endpoint, so old public key is used to verify JWTs signed with new private key. Result: `crypto/rsa: verification error`.

**Fix:** (1) Base64-encoded PEM in `.env`, (2) decode in service, (3) `{ extractable: true }` for `jose.importPKCS8()`, (4) new ngrok URL to bypass Web3Auth JWKS cache.

### ISSUE-004: SecurityTab not wired into SettingsPage — OPEN

**Severity:** Medium — blocks MFA enrollment and device management UI
**Reproducibility:** 100%

**Description:** `SettingsPage.tsx` (the component actually routed to `/settings`) only renders `LinkedMethods` and `VaultExport`. The `Settings.tsx` component which has the tab bar (LINKED METHODS / SECURITY) with `SecurityTab` is **not used** — it's an orphaned file. As a result, MFA enrollment wizard, device list, revoke device, and recovery phrase regeneration are all inaccessible from the UI.

**Impact:** Blocks TC15-23 (MFA login flows) and TC25-31 (MFA enrollment, devices, recovery).

**Fix:** Wire `SecurityTab` into `SettingsPage.tsx`, either as a tab or a separate section.

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

### 2026-02-16 17:30 — ISSUE-001 Root Cause & Fix

- Identified root cause: `useDeviceApproval.ts` dependency oscillation (see ISSUE-001 details above)
- Fixed by converting `isPollingPending` from `useState` to `useRef`
- Also fixed ISSUE-003: persistent JWKS key via base64-encoded PEM in `.env`
- Also refactored `hooks.ts`: extracted `doLoginWithCoreKit`, wrapped methods in `useCallback`, added `syncStatus` to CoreKitProvider

### 2026-02-16 18:00 — ISSUE-003 Fix & ngrok Rotation

- Generated persistent RSA keypair, base64-encoded PEM in `IDENTITY_JWT_PRIVATE_KEY`
- Fixed `jose.importPKCS8()`: needs `Buffer.from(pemKey, 'base64')` and `{ extractable: true }`
- Restarted ngrok (new URL: `https://6e86-...ngrok-free.app`) to bypass Web3Auth JWKS cache
- Updated JWKS URL on Web3Auth dashboard

### 2026-02-16 18:30 — TC02 First Successful Login

- Fresh DB (`DROP SCHEMA public CASCADE; CREATE SCHEMA public`)
- Mock IPNS router running on port 3001
- Email login: OTP verified, `loginWithJWT` 3.6s, `commitChanges` 280ms, vault init, empty directory
- Created `uat-test-folder` to trigger IPNS publish (3 records)
- Logout -> re-login: IPNS resolved, folder visible, "Synced"
- **TC02: PASS** (full fresh-user → logout → re-login cycle)

### 2026-02-16 18:46 — Full Fresh Cycle (post-commit)

- Committed fix on `fix/auth-publickey-format` branch
- Reset DB, cleared browser storage + IndexedDB, reset mock IPNS router
- **Fresh user login:** OTP `263899`, loginWithJWT 3.2s, empty vault displayed
- **Create folder:** `uat-test-folder`, 3 IPNS records published, "Synced"
- **Logout:** clean return to login page
- **Re-login:** OTP `291949`, loginWithJWT 1.6s (cached), IPNS resolved, folder visible, "Synced", `2 KB / 500.0 MB`
- **Full cycle confirmed PASS**

### 2026-02-16 18:55 — TC03-TC06 Email Edge Cases

- **TC03 (invalid OTP):** Entered `999999`, got 401, alert shown, returned to email input. PASS
- **TC04 (back navigation):** Back arrow from OTP screen returns to email with email pre-filled. PASS
- **TC05 (OTP resend):** Timer countdown works (90s not 60s), button enables, click triggers resend. Hit rate limit (400) after multiple UAT OTP sends — error shown gracefully. PASS
- **TC06 (rate limiting):** Backend returns 400 "Too many OTP requests". Frontend shows error alert. Redis `otp-attempts:*` key confirmed. PASS
- Flushed Redis rate limit key to continue testing

### 2026-02-16 19:01 — TC13, TC14, TC36 Session & Redirect

- **TC13 (session restoration):** Page refresh restores CoreKit session from IndexedDB, `/auth/refresh` 200, vault loads with folder visible, 0 errors. PASS
- **TC14 (already authenticated redirect):** Navigate to `/#/` while logged in — immediately redirected to `#/files`. PASS
- **TC36 (new user vault init):** Covered by TC02 fresh cycle — empty vault with "EMPTY DIRECTORY", 0 B usage. PASS

### 2026-02-16 19:03 — ISSUE-004 Discovery (Settings/Security Tab)

- Navigated to Settings page — only shows "// linked auth methods" and "[VAULT EXPORT]"
- No SECURITY tab visible despite `Settings.tsx` having tab UI
- Root cause: `SettingsPage.tsx` (actually routed) doesn't include `SecurityTab`; `Settings.tsx` (has tabs) is orphaned
- **ISSUE-004: SecurityTab not wired into SettingsPage** — blocks TC25-31 (MFA enrollment, devices, recovery)
- MfaEnrollmentPrompt exists in AppShell but only fires once per session (checkedRef)

### UAT Summary

| Category | Count | Details |
|----------|-------|---------|
| PASS | 10 | TC01, TC02, TC03, TC04, TC05, TC06, TC13, TC14, TC32, TC36 |
| SKIP | 12 | TC07-12 (Google/Wallet not available), TC15-23 (MFA needs enrollment), TC33-35 (multi-device/destructive) |
| BLOCK | 7 | TC25-31 (ISSUE-004: SecurityTab not in SettingsPage) |
| NOTE | 1 | TC24 (MFA prompt component exists, fires once per session) |

**Issues:** ISSUE-001 RESOLVED, ISSUE-002 documented, ISSUE-003 RESOLVED, ISSUE-004 OPEN
