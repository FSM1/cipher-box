---
phase: 02-authentication
plan: 03
subsystem: auth
tags: [react-hooks, zustand, cookie-parser, http-only-cookies, route-protection]

# Dependency graph
requires:
  - phase: 02-01
    provides: Backend auth module with login/refresh/logout endpoints
  - phase: 02-02
    provides: Web3Auth Modal SDK integration with React hooks
provides:
  - Complete login flow wiring Web3Auth modal to backend auth
  - HTTP-only cookie refresh token storage (XSS prevention)
  - useAuth hook for frontend authentication orchestration
  - AuthButton with "Continue with [method]" returning user UX
  - LogoutButton with immediate logout
  - Protected Dashboard route with redirect guards
affects: [03-vault, 04-keys, 05-folders, 06-files]

# Tech tracking
tech-stack:
  added: [cookie-parser]
  patterns:
    - HTTP-only cookie for refresh token (path=/auth)
    - useAuth hook orchestrating Web3Auth + backend flow
    - Route protection via useEffect redirect guards

key-files:
  created:
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/components/auth/AuthButton.tsx
    - apps/web/src/components/auth/LogoutButton.tsx
    - apps/web/src/components/auth/index.ts
  modified:
    - apps/api/src/auth/auth.controller.ts
    - apps/api/src/auth/auth.service.ts
    - apps/api/src/auth/dto/login.dto.ts
    - apps/api/src/auth/dto/token.dto.ts
    - apps/api/src/main.ts
    - apps/web/src/lib/api/auth.ts
    - apps/web/src/routes/Login.tsx
    - apps/web/src/routes/Dashboard.tsx
    - apps/web/src/routes/index.tsx

key-decisions:
  - 'HTTP-only cookie with path=/auth for refresh token storage'
  - 'Separate internal types (LoginServiceResult, RefreshServiceResult) from API DTOs'
  - 'CORS credentials enabled for cross-origin cookie handling'

patterns-established:
  - 'useAuth hook pattern for complete auth flow orchestration'
  - 'Route protection via useEffect redirect guards'
  - 'AuthButton shows last auth method for returning users'

# Metrics
duration: 5min
completed: 2026-01-20
---

# Phase 02 Plan 03: Complete Auth Flow Summary

**HTTP-only cookie refresh tokens with useAuth hook wiring Web3Auth modal to backend auth, protected routes, and returning user UX**

## Performance

- **Duration:** 5 min
- **Started:** 2026-01-20T10:51:13Z
- **Completed:** 2026-01-20T10:56:12Z
- **Tasks:** 3
- **Files modified:** 15

## Accomplishments

- Backend now stores refresh tokens in HTTP-only cookies (secure, httpOnly, sameSite, path=/auth)
- useAuth hook orchestrates complete login flow: Web3Auth modal -> getIdToken -> backend auth -> store token
- AuthButton shows "Continue with [method]" for returning users (e.g., "Continue with Google")
- LogoutButton triggers immediate logout without confirmation
- Dashboard protected with redirect to login when not authenticated
- Login page redirects to dashboard when already authenticated
- Silent token refresh via axios interceptor queue pattern

## Task Commits

Each task was committed atomically:

1. **Task 1: Update backend for HTTP-only cookies** - `172222a` (feat)
2. **Task 2: Create auth hook and UI components** - `53d2436` (feat)
3. **Task 3: Update login and dashboard pages** - `08e39fc` (feat)
4. **OpenAPI regeneration** - `209d8f0` (chore)

## Files Created/Modified

**Backend:**

- `apps/api/src/main.ts` - Added cookie-parser middleware, CORS credentials
- `apps/api/src/auth/auth.controller.ts` - Set/clear refresh token in HTTP-only cookie
- `apps/api/src/auth/auth.service.ts` - Updated types for internal service results
- `apps/api/src/auth/dto/login.dto.ts` - Removed refreshToken from LoginResponseDto
- `apps/api/src/auth/dto/token.dto.ts` - Removed refreshToken from TokenResponseDto
- `apps/api/src/auth/dto/index.ts` - Export new internal types

**Frontend:**

- `apps/web/src/hooks/useAuth.ts` - Complete auth flow hook
- `apps/web/src/components/auth/AuthButton.tsx` - Sign In button with returning user UX
- `apps/web/src/components/auth/LogoutButton.tsx` - Immediate logout button
- `apps/web/src/components/auth/index.ts` - Component exports
- `apps/web/src/lib/api/auth.ts` - Updated to match new API response shapes
- `apps/web/src/routes/Login.tsx` - Landing page with AuthButton
- `apps/web/src/routes/Dashboard.tsx` - Protected page with LogoutButton
- `apps/web/src/routes/index.tsx` - Updated route paths

**API Client:**

- `packages/api-client/openapi.json` - Regenerated spec
- `apps/web/src/api/auth/auth.ts` - Regenerated client hooks

## Decisions Made

1. **HTTP-only cookie with path=/auth** - Refresh token only sent to auth endpoints, reducing attack surface for CSRF.

2. **Internal service types** - Created `LoginServiceResult` and `RefreshServiceResult` types separate from API DTOs. Service returns full data (including refreshToken), controller extracts what goes to cookie vs response body.

3. **CORS credentials enabled** - `withCredentials: true` on axios client allows cross-origin cookie handling between frontend (port 5173) and backend (port 3000).

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - all tasks completed successfully.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Complete end-to-end auth flow ready for testing with valid Web3Auth client ID
- Users can sign in via Web3Auth modal (social or wallet)
- Backend authenticates and issues tokens
- Access token in memory, refresh token in HTTP-only cookie
- Dashboard protected, login redirects appropriately
- Ready for Phase 02-04 (protected routes and session management) or Phase 03 (vault operations)

---

_Phase: 02-authentication_
_Completed: 2026-01-20_
