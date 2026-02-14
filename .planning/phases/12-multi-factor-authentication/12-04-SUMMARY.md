# Plan 12-04: Custom Login UI — SUMMARY

## Status: COMPLETE

## Tasks Completed

### Task 1: Google OAuth Button + Email OTP Form Components

- Created `GoogleLoginButton.tsx` using GIS library with dynamic script loading
- Created `EmailLoginForm.tsx` with two-step flow (email -> OTP)
- Updated component index exports
- Terminal aesthetic: green-on-black, monospace, accessible
- Commits: 22c1d8b, 845e1eb

### Task 2: Update Login Page to Use Custom Auth UI

- Updated `Login.tsx` with CipherBox-branded layout (heading, tagline, auth methods)
- Replaced Web3Auth modal with Google button + email OTP form
- Added "// or" divider between auth methods
- Deprecated AuthButton.tsx
- Commits: 22c1d8b, 845e1eb

### Task 3: Checkpoint Verification — PASSED

- Login page renders with CIPHERBOX heading, tagline, Google button, email form
- Email OTP flow tested end-to-end: enter email -> send OTP -> enter code -> verify -> Core Kit login -> vault init -> redirect to /files
- Terminal aesthetic confirmed (green-on-black, monospace, matrix background)
- Google button shows "[GOOGLE - NOT CONFIGURED]" disabled state (expected without VITE_GOOGLE_CLIENT_ID)

## Deviations

### Critical Fix: Core Kit `corekit` Login Type (commit 18e1808)

During checkpoint testing, discovered Core Kit SDK v3.5.0 doesn't have `authenticateUser()` method. The `coreKit.signatures` contain session management tokens, NOT verifiable JWTs.

**Fix applied:**

- Added `'corekit'` login type to `LoginDto` and `LoginRequest`
- Backend `AuthService` verifies CipherBox-issued JWT against own JWKS for corekit logins
- Frontend hooks return `cipherboxJwt` from login methods
- `completeBackendAuth` sends CipherBox JWT with `loginType: 'corekit'` instead of extracting from signatures
- Narrowed `Web3AuthVerifierService` parameter types (corekit never reaches Web3Auth verification)

## Files Modified

- `apps/web/src/components/auth/GoogleLoginButton.tsx` (created)
- `apps/web/src/components/auth/EmailLoginForm.tsx` (created)
- `apps/web/src/components/auth/index.ts` (updated exports)
- `apps/web/src/routes/Login.tsx` (rewrote with custom auth UI)
- `apps/web/src/hooks/useAuth.ts` (corekit login type, pass cipherboxJwt)
- `apps/web/src/lib/api/auth.ts` (corekit in LoginRequest type)
- `apps/web/src/lib/web3auth/hooks.ts` (return cipherboxJwt from login methods)
- `apps/api/src/auth/auth.service.ts` (corekit JWT verification via own JWKS)
- `apps/api/src/auth/dto/login.dto.ts` (corekit login type)
- `apps/api/src/auth/services/web3auth-verifier.service.ts` (narrowed parameter types)
- `packages/api-client/openapi.json` (regenerated)
