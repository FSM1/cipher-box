---
phase: 12-core-kit-identity-provider
plan: 03
subsystem: auth
tags:
  [web3auth, mpc-core-kit, loginWithJWT, custom-verifier, core-kit-auth-flow, placeholder-publickey]

# Dependency graph
requires:
  - phase: 12-core-kit-identity-provider-01
    provides: Identity provider backend (JWKS, Google login, email OTP endpoints)
  - phase: 12-core-kit-identity-provider-02
    provides: Core Kit singleton and React context provider
provides:
  - useCoreKitAuth hook with loginWithGoogle, loginWithEmailOtp, getVaultKeypair, logout
  - useAuth hook rewritten for Core Kit (loginWithGoogle, loginWithEmail, session restore)
  - CoreKitProvider mounted in app render tree
  - Identity provider API client methods (identityGoogle, identityEmailSendOtp, identityEmailVerify)
  - Backend placeholder publicKey resolution (pending-core-kit-{userId} -> real publicKey)
  - Web3Auth session JWT extraction from coreKit.signatures
affects: [12-core-kit-identity-provider-04, 12-core-kit-identity-provider-05]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'CipherBox identity JWT -> loginWithJWT -> session JWT -> backend /auth/login'
    - 'coreKit.signatures[0].data for Web3Auth-signed JWT (no authenticateUser on Core Kit)'
    - 'Placeholder publicKey resolution via Like query in auth.service.ts login()'

key-files:
  created: []
  modified:
    - apps/web/src/lib/web3auth/hooks.ts
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/lib/api/auth.ts
    - apps/web/src/main.tsx
    - apps/api/src/auth/auth.service.ts
    - apps/web/src/components/auth/LinkedMethods.tsx
    - apps/web/src/components/layout/UserMenu.tsx

key-decisions:
  - 'Extract Web3Auth session JWT from coreKit.signatures[0].data instead of authenticateUser() (not available in Core Kit SDK)'
  - 'Placeholder publicKey resolved via Like query with pending-core-kit-{verifierId} pattern'
  - 'Legacy login() kept as no-op for AuthButton compatibility until Plan 04 Login UI'
  - 'E2E test mode removed (TODO for Plan 05 Task 3)'
  - 'External wallet login removed from active flow (deferred to Phase 12.3 SIWE)'
  - 'Method linking disabled in LinkedMethods (deferred to Phase 12.3)'
  - 'UserInfo from PnP removed; user display deferred to Plan 04'

patterns-established:
  - 'Core Kit auth flow: identity endpoint -> CipherBox JWT -> loginWithJWT -> signatures -> /auth/login'
  - 'Session restoration: if coreKitLoggedIn && !isAuthenticated -> refresh token -> load vault'
  - 'REQUIRED_SHARE handled as warning (Phase 12.4 adds MFA challenge UI)'

# Metrics
duration: 9min
completed: 2026-02-12
---

# Phase 12 Plan 03: Core Kit Auth Flow Wiring Summary

Frontend auth hooks rewritten for Core Kit loginWithJWT with CipherBox identity JWTs, CoreKitProvider mounted in app, backend placeholder publicKey resolution, session JWT extracted from coreKit.signatures

## Performance

- **Duration:** 9 min
- **Started:** 2026-02-12T12:33:05Z
- **Completed:** 2026-02-12T12:42:35Z
- **Tasks:** 3 (1 manual checkpoint + 2 auto)
- **Files modified:** 7

## Accomplishments

- Rewrote `hooks.ts` with `useCoreKitAuth` providing loginWithGoogle, loginWithEmailOtp, getVaultKeypair, getPublicKeyHex, logout via Core Kit SDK
- Extended `auth.ts` API client with identity provider endpoints (identityGoogle, identityEmailSendOtp, identityEmailVerify)
- Rewrote `useAuth.ts` for Core Kit: full login flow from identity endpoint through loginWithJWT to backend auth, session restoration from Core Kit localStorage, vault init from TSS exported key
- Mounted `CoreKitProvider` in `main.tsx`, removed PnP `Web3AuthProviderWrapper` and `WagmiProvider`
- Added placeholder publicKey resolution in backend `login()` -- finds `pending-core-kit-{userId}` users and updates to real Core Kit-derived publicKey
- Discovered and worked around missing `authenticateUser()` in Core Kit SDK by extracting session JWT from `coreKit.signatures[0]`

## Task Commits

Each task was committed atomically:

1. **Task 1: Configure Web3Auth Dashboard Custom Verifier** - N/A (manual dashboard configuration, verified `cipherbox-identity` verifier active)
2. **Task 2: Core Kit Auth Hooks + API Client Extensions** - `acb66e6` (feat)
3. **Task 3: Backend publicKey Placeholder Resolution + Rewrite useAuth + Mount CoreKitProvider** - `cec0991` (feat)

## Files Created/Modified

- `apps/web/src/lib/web3auth/hooks.ts` - Complete rewrite: useCoreKitAuth with loginWithJWT-based auth methods
- `apps/web/src/lib/api/auth.ts` - Extended with identityGoogle, identityEmailSendOtp, identityEmailVerify
- `apps/web/src/hooks/useAuth.ts` - Complete rewrite: loginWithGoogle, loginWithEmail, session restore via Core Kit
- `apps/web/src/main.tsx` - Swapped Web3AuthProviderWrapper/WagmiProvider for CoreKitProvider
- `apps/api/src/auth/auth.service.ts` - Added placeholder publicKey resolution via Like query
- `apps/web/src/components/auth/LinkedMethods.tsx` - Disabled PnP-dependent method linking (deferred to Phase 12.3)
- `apps/web/src/components/layout/UserMenu.tsx` - Removed PnP userInfo dependency

## Decisions Made

1. **Session JWT from coreKit.signatures instead of authenticateUser()** -- The MPC Core Kit SDK does not expose `authenticateUser()` (that's a PnP-only method). Core Kit stores Web3Auth-signed session JWTs in `coreKit.signatures[]` as JSON strings with `{ data: <JWT>, sig: <signature> }`. Extracting `signatures[0].data` provides the same ES256 JWT that PnP's `authenticateUser()` returns, verifiable against `https://api-auth.web3auth.io/jwks`.

2. **Like query for placeholder publicKey lookup** -- Used TypeORM `Like('pending-core-kit-${verifierId}%')` instead of exact match because the identity provider appends a timestamp to the placeholder. The `%` wildcard handles this safely since `verifierId` is a UUID.

3. **Legacy login() as no-op** -- Kept `login()` as a backward-compatible no-op that warns about the new method-specific entry points. AuthButton still calls it. Plan 04 will replace the Login UI entirely.

4. **E2E test mode removed** -- The PnP-specific E2E session restoration logic was removed. Plan 05 will implement E2E test support for Core Kit.

5. **External wallet login deferred** -- Removed from active flow (Phase 12.3 SIWE will implement wallet login via Core Kit).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] LinkedMethods.tsx imported removed useAuthFlow**

- **Found during:** Task 2 (hooks.ts rewrite)
- **Issue:** `LinkedMethods.tsx` imported `useAuthFlow` for PnP-based method linking which no longer exists
- **Fix:** Removed PnP dependency, disabled method linking with descriptive message (deferred to Phase 12.3)
- **Files modified:** apps/web/src/components/auth/LinkedMethods.tsx
- **Verification:** `pnpm --filter web build` passes
- **Committed in:** acb66e6 (Task 2 commit)

**2. [Rule 1 - Bug] Core Kit SDK lacks authenticateUser() method**

- **Found during:** Task 3 (useAuth.ts rewrite)
- **Issue:** Plan assumed `coreKit.authenticateUser()` exists (PnP SDK method). MPC Core Kit SDK v3.5.0 does not expose this method.
- **Fix:** Extract Web3Auth session JWT from `coreKit.signatures[0]` instead. Each signature entry is `{ data: <JWT>, sig: <signature> }` where `data` is the ES256 JWT from Web3Auth nodes.
- **Files modified:** apps/web/src/hooks/useAuth.ts
- **Verification:** TypeScript compilation passes, JWT format compatible with existing backend verifier
- **Committed in:** cec0991 (Task 3 commit)

**3. [Rule 3 - Blocking] UserMenu.tsx accessed .email on null userInfo**

- **Found during:** Task 3 (useAuth.ts rewrite)
- **Issue:** `UserMenu.tsx` accessed `userInfo?.email` but useAuth now returns `null` for userInfo (PnP user info removed). TypeScript error: `Property 'email' does not exist on type 'never'`
- **Fix:** Removed userInfo dependency, hardcoded 'User' with TODO for Plan 04
- **Files modified:** apps/web/src/components/layout/UserMenu.tsx
- **Verification:** `pnpm --filter web build` passes
- **Committed in:** cec0991 (Task 3 commit)

---

**Total deviations:** 3 auto-fixed (1 bug, 2 blocking)
**Impact on plan:** All auto-fixes necessary for correct compilation and Core Kit SDK compatibility. No scope creep.

## Authentication Gates

During execution, these authentication requirements were handled:

1. Task 1: Web3Auth Dashboard custom verifier configuration
   - Verifier name `cipherbox-identity` confirmed on dashboard
   - JWKS endpoint verified working via ngrok tunnel
   - Resumed after user confirmation

## Issues Encountered

None beyond the auto-fixed deviations above.

## User Setup Required

None - Web3Auth dashboard configuration (Task 1) was completed manually before Task 2/3 execution.

## Next Phase Readiness

- Core Kit auth flow is fully wired: identity endpoints -> loginWithJWT -> backend auth
- Ready for Plan 04 (Login UI) which will build the custom login page calling loginWithGoogle/loginWithEmail
- Ready for Plan 05 (PnP Cleanup + E2E) which will remove all PnP SDK code and restore E2E test support
- REQUIRED_SHARE status is logged but not handled (Phase 12.4 MFA work)
- External wallet login via SIWE deferred to Phase 12.3
- Method linking disabled until Phase 12.3

---

_Phase: 12-core-kit-identity-provider_
_Completed: 2026-02-12_
