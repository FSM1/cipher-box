---
phase: 12-core-kit-identity-provider
plan: 01
subsystem: auth
tags: [jwt, rs256, jose, jwks, google-oauth, email-otp, redis, argon2, identity-provider]

# Dependency graph
requires:
  - phase: 04-authentication
    provides: User entity, AuthMethod entity, auth module structure, token service
provides:
  - JwtIssuerService with RS256 keypair management and JWT signing
  - GoogleOAuthService for Google idToken verification
  - EmailOtpService for OTP generation with argon2 hashing and Redis storage
  - IdentityController with JWKS, Google login, and email OTP endpoints
  - CipherBox identity JWT format (iss=cipherbox, aud=web3auth, sub=userId)
  - OpenAPI spec and web API client for identity endpoints
affects: [12-02, 12-03, 12-04, 12-05]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'CipherBox as identity provider: all auth methods produce JWT with sub=userId'
    - 'RS256 keypair from IDENTITY_JWT_PRIVATE_KEY env var (ephemeral in dev)'
    - 'Google JWKS verification via jose.createRemoteJWKSet'
    - 'OTP stored as argon2 hash in Redis with 5min TTL'
    - 'Cross-auth-method email linking (Google user logs in with email -> same user)'

key-files:
  created:
    - apps/api/src/auth/services/jwt-issuer.service.ts
    - apps/api/src/auth/services/google-oauth.service.ts
    - apps/api/src/auth/services/email-otp.service.ts
    - apps/api/src/auth/controllers/identity.controller.ts
    - apps/api/src/auth/dto/identity.dto.ts
    - apps/web/src/api/identity/identity.ts
  modified:
    - apps/api/src/auth/auth.module.ts
    - apps/api/scripts/generate-openapi.ts
    - packages/api-client/openapi.json
    - apps/web/src/api/models/index.ts

key-decisions:
  - 'Used jose library (not @nestjs/jwt) for identity JWTs -- separate signing keys and audience from internal access tokens'
  - 'Placeholder publicKey pattern: pending-core-kit-{timestamp} for new identity-provider users'
  - 'Cross-auth-method email linking: if same email exists under different auth method type, link to existing user'
  - 'OTP rate limiting: 5 send attempts per email per 15min (Redis) + 5 verify attempts per OTP'

patterns-established:
  - 'Identity provider JWT format: {iss: cipherbox, aud: web3auth, sub: userId, exp: 5min, alg: RS256}'
  - 'JWKS endpoint at GET /auth/.well-known/jwks.json with 1hr cache'
  - 'ioredis direct client for key-value operations (not via BullMQ)'

# Metrics
duration: 10min
completed: 2026-02-12
---

# Phase 12 Plan 01: CipherBox Identity Provider Backend Summary

RS256 JWT issuer with JWKS endpoint, Google OAuth verification, and email OTP flow -- CipherBox backend as sole identity provider for Web3Auth.

## Performance

- **Duration:** 10 min
- **Started:** 2026-02-12T03:21:13Z
- **Completed:** 2026-02-12T03:31:31Z
- **Tasks:** 2
- **Files modified:** 14

## Accomplishments

- JWKS endpoint serving RS256 public key at /auth/.well-known/jwks.json
- Google OAuth login endpoint that verifies Google idTokens and returns CipherBox JWTs
- Email OTP flow (send + verify) with argon2-hashed codes in Redis, rate limiting, and single-use enforcement
- All CipherBox JWTs contain iss=cipherbox, aud=web3auth, sub=userId (UUID), 5min expiry
- OpenAPI spec and web API client regenerated with all new identity endpoints

## Task Commits

Each task was committed atomically:

1. **Task 1: JWT Issuer Service + JWKS Endpoint** - `99d7c5e` (feat)
2. **Task 2: Google OAuth + Email OTP + Identity Endpoints** - `2ed78ac` (feat)

## Files Created/Modified

- `apps/api/src/auth/services/jwt-issuer.service.ts` - RS256 keypair management, JWT signing, JWKS data
- `apps/api/src/auth/services/google-oauth.service.ts` - Google idToken verification via Google JWKS
- `apps/api/src/auth/services/email-otp.service.ts` - OTP generation, argon2 hashing, Redis storage
- `apps/api/src/auth/controllers/identity.controller.ts` - JWKS + Google login + email OTP endpoints
- `apps/api/src/auth/dto/identity.dto.ts` - Request/response DTOs with class-validator decorators
- `apps/api/src/auth/auth.module.ts` - Registered new services and controller
- `apps/api/scripts/generate-openapi.ts` - Added IdentityController and mock providers for OpenAPI gen
- `packages/api-client/openapi.json` - Updated with identity endpoints
- `apps/web/src/api/identity/identity.ts` - Generated identity API client
- `apps/web/src/api/models/*.ts` - Generated DTO model types

## Decisions Made

- Used `jose` library for identity JWTs (not `@nestjs/jwt`) because identity JWTs have different signing keys (RS256 vs HS256) and different audience (web3auth vs internal)
- Placeholder publicKey `pending-core-kit-{timestamp}` for users created via identity provider -- real publicKey updated on first Core Kit login
- Cross-auth-method email linking: if a user signed up with Google and later logs in with email using the same address, they get linked to the same user account automatically
- Fixed jose v6 type incompatibility: `KeyLike` no longer exported, replaced with `CryptoKey | KeyObject`
- Used `Object.fromEntries(Object.entries().filter())` instead of destructuring to strip RSA private fields (avoids eslint unused-var errors)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed jose v6 type incompatibility**

- **Found during:** Task 1
- **Issue:** `jose.KeyLike` type no longer exists in jose v6.1.3, causing TypeScript compilation failure
- **Fix:** Changed type to `jose.CryptoKey | jose.KeyObject`, removed unused `publicKey` field
- **Files modified:** apps/api/src/auth/services/jwt-issuer.service.ts
- **Verification:** `pnpm --filter api build` passes
- **Committed in:** 99d7c5e

**2. [Rule 1 - Bug] Fixed eslint unused-var errors in RSA private field stripping**

- **Found during:** Task 1
- **Issue:** Destructuring `{ d, p, q, dp, dq, qi, ...rest }` triggers unused-var lint errors
- **Fix:** Used `Object.fromEntries(Object.entries().filter())` to programmatically strip private fields
- **Files modified:** apps/api/src/auth/services/jwt-issuer.service.ts
- **Verification:** Lint passes in pre-commit hook
- **Committed in:** 99d7c5e

**3. [Rule 3 - Blocking] Added IdentityController to OpenAPI generator**

- **Found during:** Task 2
- **Issue:** The `generate-openapi.ts` script didn't include IdentityController, so `pnpm api:generate` produced no identity endpoints in the web client
- **Fix:** Added IdentityController, mock providers for JwtIssuerService/GoogleOAuthService/EmailOtpService, and proper `getRepositoryToken()` mocks. Also added 'Identity' tag to Swagger builder.
- **Files modified:** apps/api/scripts/generate-openapi.ts
- **Verification:** `pnpm api:generate` generates identity endpoints in web client
- **Committed in:** 2ed78ac

---

**Total deviations:** 3 auto-fixed (2 bugs, 1 blocking)
**Impact on plan:** All auto-fixes necessary for correctness and functionality. No scope creep.

## Issues Encountered

None beyond the auto-fixed deviations above.

## User Setup Required

None - no external service configuration required. In dev, IDENTITY_JWT_PRIVATE_KEY env var is optional (ephemeral keypair generated automatically). Redis must be running for OTP flow (already required for BullMQ).

## Next Phase Readiness

- Identity provider backend is complete and serving JWKS
- Ready for Plan 02 (Web3Auth custom verifier configuration) which will point Web3Auth at this JWKS endpoint
- Ready for Plan 03+ which will use the identity JWT to initialize Core Kit
- Existing PnP auth flow remains untouched (backward compatible)
- The placeholder publicKey pattern needs to be handled in Core Kit login (Plan 03/04)

---

_Phase: 12-core-kit-identity-provider_
_Completed: 2026-02-12_
