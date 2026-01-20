---
phase: 02-authentication
plan: 01
subsystem: auth
tags: [nestjs, jwt, passport, web3auth, argon2, typeorm]

# Dependency graph
requires:
  - phase: 01-foundation
    provides: NestJS app scaffold, TypeORM configuration, OpenAPI generation
provides:
  - Backend auth module with Web3Auth JWT verification
  - User, RefreshToken, AuthMethod TypeORM entities
  - POST /auth/login, /auth/refresh, /auth/logout endpoints
  - JWT-based route protection with guards
  - Token rotation with argon2 hashing
affects: [02-authentication, 03-vault, 04-files]

# Tech tracking
tech-stack:
  added: [jose, argon2, @nestjs/jwt, @nestjs/passport, passport, passport-jwt]
  patterns: [dual JWKS verification, token rotation, guard-based route protection]

key-files:
  created:
    - apps/api/src/auth/auth.module.ts
    - apps/api/src/auth/auth.controller.ts
    - apps/api/src/auth/auth.service.ts
    - apps/api/src/auth/entities/user.entity.ts
    - apps/api/src/auth/entities/refresh-token.entity.ts
    - apps/api/src/auth/entities/auth-method.entity.ts
    - apps/api/src/auth/services/web3auth-verifier.service.ts
    - apps/api/src/auth/services/token.service.ts
    - apps/api/src/auth/strategies/jwt.strategy.ts
    - apps/api/src/auth/guards/jwt-auth.guard.ts
  modified:
    - apps/api/src/app.module.ts
    - apps/api/scripts/generate-openapi.ts
    - packages/api-client/openapi.json

key-decisions:
  - "Dual JWKS endpoints for social vs external wallet login types"
  - "Refresh tokens searched across all users for better UX (no expired access token needed)"
  - "Token rotation on every refresh for security"
  - "AuthMethod entity tracks login providers per user"

patterns-established:
  - "Web3Auth verification with type-specific JWKS endpoints"
  - "Argon2 hashing for refresh token storage"
  - "JwtAuthGuard for protected routes"

# Metrics
duration: 5min
completed: 2026-01-20
---

# Phase 02 Plan 01: Backend Auth Module Summary

**Web3Auth JWT verification with dual JWKS, user/token entities, and auth endpoints (login/refresh/logout) with JWT guards**

## Performance

- **Duration:** 5 min
- **Started:** 2026-01-20T10:44:08Z
- **Completed:** 2026-01-20T10:49:01Z
- **Tasks:** 3
- **Files modified:** 14

## Accomplishments

- Complete backend authentication module with Web3Auth token verification
- User, RefreshToken, and AuthMethod TypeORM entities with proper relations
- Token service with argon2 hashing and secure rotation
- JWT strategy and guard for protected route access
- OpenAPI spec updated with auth endpoints, API client regenerated

## Task Commits

Each task was committed atomically:

1. **Task 1: Create auth entities and install dependencies** - `1570465` (feat)
2. **Task 2: Create auth services (Web3Auth verifier and token service)** - `0f5fd4a` (feat)
3. **Task 3: Create auth controller, JWT strategy, and wire module** - `3d9aa67` (feat)

## Files Created/Modified

**Entities:**

- `apps/api/src/auth/entities/user.entity.ts` - User with publicKey, relations to tokens and auth methods
- `apps/api/src/auth/entities/refresh-token.entity.ts` - Refresh token with argon2 hash storage
- `apps/api/src/auth/entities/auth-method.entity.ts` - Auth method linking users to login providers

**Services:**

- `apps/api/src/auth/services/web3auth-verifier.service.ts` - Web3Auth JWT verification with dual JWKS
- `apps/api/src/auth/services/token.service.ts` - Token creation, rotation, and revocation

**Controller & Module:**

- `apps/api/src/auth/auth.controller.ts` - POST /auth/login, /auth/refresh, /auth/logout
- `apps/api/src/auth/auth.service.ts` - Business logic orchestrating services
- `apps/api/src/auth/auth.module.ts` - Module wiring all dependencies

**Strategy & Guard:**

- `apps/api/src/auth/strategies/jwt.strategy.ts` - Passport JWT strategy
- `apps/api/src/auth/guards/jwt-auth.guard.ts` - Route protection guard

**App Integration:**

- `apps/api/src/app.module.ts` - AuthModule imported, entities registered

**API Spec:**

- `apps/api/scripts/generate-openapi.ts` - Updated to include auth endpoints
- `packages/api-client/openapi.json` - Regenerated with auth endpoints
- `apps/web/src/api/auth/auth.ts` - Generated auth API client hooks

## Decisions Made

1. **Dual JWKS endpoints** - Web3Auth uses different JWKS endpoints for social logins vs external wallets. Service selects correct endpoint based on loginType.

2. **Refresh without access token** - The refreshByToken method searches all active tokens to find the owner, allowing refresh even when access token is expired. More user-friendly than requiring expired token in header.

3. **Token rotation on refresh** - Every refresh operation invalidates the old token and issues a new one. Prevents token reuse attacks.

4. **AuthMethod entity** - Tracks which login providers each user has used, enabling future multi-provider support.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - all tasks completed successfully.

## User Setup Required

None - no external service configuration required. JWT_SECRET added to .env.example for reference.

## Next Phase Readiness

- Auth endpoints ready for frontend integration
- JWT guards available for protecting future endpoints
- Database will create users, refresh_tokens, auth_methods tables on first run
- Frontend plan (02-02) can now integrate with these endpoints

---

_Phase: 02-authentication_
_Completed: 2026-01-20_
