# Debug Session: CoreKit Auth Flow UAT

**Created:** 2026-02-16
**Status:** IN PROGRESS — BLOCKED on ISSUE-001
**Scope:** Full E2E auth flow verification after CoreKit refactor (Phases 12-12.4)

## Test Results

| TC | Description | Status | Notes |
|----|-------------|--------|-------|
| 01 | Login page initial render | PASS | All elements render: heading, Google (disabled/not configured), email input + SEND OTP, wallet button, footer, [CONNECTED] status |
| 02 | Email login - happy path | BLOCKED | See ISSUE-001. OTP verification + CipherBox JWT issuance works, but CoreKit `loginWithJWT` freezes/crashes the browser tab |
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

### ISSUE-001: CoreKit `loginWithJWT` freezes/crashes browser tab (BLOCKER)

**Severity:** Critical — blocks all fresh login flows
**Reproducibility:** 3/3 attempts
**Branch:** `fix/auth-publickey-format`

**Symptoms:**
- After successful CipherBox JWT issuance (OTP verified, `IdentityController` logs `Email OTP login`), calling `coreKit.loginWithJWT()` causes the browser tab to become completely unresponsive
- Playwright screenshots, snapshots, and evaluate calls all timeout (5s)
- After ~30s the Chrome renderer process crashes entirely ("Target page, context or browser has been closed")
- The page shows "initializing..." with no further updates

**Backend side is fine:**
- `/auth/identity/email/send-otp` -> 200
- `/auth/identity/email/verify-otp` -> 200 (when using correct dev OTP from API logs)
- `IdentityController` logs successful JWT issuance
- JWKS endpoint (`/auth/.well-known/jwks.json`) is reachable through ngrok and returns valid RSA public key

**What works:**
- Session restoration from a pre-existing CoreKit localStorage session (via `/auth/refresh`)
- This means CoreKit is initialized correctly and the SDK loads fine
- The issue is specifically with fresh `loginWithJWT` (TSS DKG ceremony)

**Likely cause:**
- The TSS DKG (Distributed Key Generation) ceremony triggered by `loginWithJWT` for a first-time login is either:
  1. Crashing the WASM-based `@toruslabs/tss-dkls-lib` computation
  2. Failing silently during JWT verification against JWKS via ngrok (though JWKS is reachable)
  3. Hitting a timeout/error in the Web3Auth TSS network that causes an unrecoverable state

**Environment:**
- ngrok URL: `https://1c18-2003-fb-ef11-51b8-44dc-5045-9733-7e48.ngrok-free.app`
- API: localhost:3000 (ephemeral RS256 keypair — regenerated on each restart)
- Frontend: localhost:5176
- Web3Auth network: DEVNET
- Verifier: `cipherbox-identity`

**Next steps to investigate:**
1. Check if this is reproducible in a real browser (not Playwright-controlled)
2. Open Chrome DevTools -> Network tab manually to see if `loginWithJWT` is making/failing network requests
3. Check the Web3Auth dashboard verifier configuration — especially the JWKS URL
4. Try with a stable IDENTITY_JWT_PRIVATE_KEY (not ephemeral) to rule out key rotation issues
5. Check @web3auth/mpc-core-kit SDK version for known issues

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
