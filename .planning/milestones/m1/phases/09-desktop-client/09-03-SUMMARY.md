---
phase: 09-desktop-client
plan: 03
subsystem: auth
tags: [nestjs, jwt, refresh-token, desktop, tauri, x-client-type, cookie]

# Dependency graph
requires:
  - phase: 02-authentication
    provides: Cookie-based refresh token auth flow
provides:
  - Body-based refresh token support for desktop clients via X-Client-Type header
  - DesktopRefreshDto for body-based refresh requests
  - Optional refreshToken field in LoginResponseDto and TokenResponseDto
affects: [09-desktop-client]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'X-Client-Type header detection for client-specific token delivery'
    - 'Dual-path auth: cookie (web) vs body (desktop) refresh tokens'

key-files:
  created:
    - apps/web/src/api/models/desktopRefreshDto.ts
  modified:
    - apps/api/src/auth/auth.controller.ts
    - apps/api/src/auth/dto/token.dto.ts
    - apps/api/src/auth/dto/login.dto.ts
    - apps/api/src/auth/auth.controller.spec.ts
    - apps/web/src/api/auth/auth.ts
    - apps/web/src/api/models/loginResponseDto.ts
    - apps/web/src/api/models/tokenResponseDto.ts
    - apps/web/src/api/models/index.ts
    - packages/api-client/openapi.json

key-decisions:
  - 'X-Client-Type: desktop header selects body-based token delivery'
  - 'No AuthService changes - controller-only modification for token delivery'
  - 'DesktopRefreshDto with optional refreshToken for body-based refresh'

patterns-established:
  - 'X-Client-Type header pattern: detect client type for conditional behavior'
  - 'Dual-path controller: same service call, different token delivery mechanism'

# Metrics
duration: 5min
completed: 2026-02-08
---

# Phase 9 Plan 3: Desktop Auth Endpoints Summary

Body-based refresh token support via X-Client-Type: desktop header for login, refresh, and logout endpoints.

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-07T23:15:56Z
- **Completed:** 2026-02-07T23:21:10Z
- **Tasks:** 2
- **Files modified:** 10

## Accomplishments

- Auth controller detects `X-Client-Type: desktop` header and switches token delivery from cookies to response body
- Login returns `refreshToken` in response body for desktop clients, no Set-Cookie
- Refresh reads `refreshToken` from request body for desktop clients, returns new tokens in body
- Logout skips cookie clearing for desktop clients
- 8 new desktop-specific tests added alongside 18 existing web flow regression tests
- OpenAPI spec and typed API client regenerated for frontend sync

## Task Commits

Each task was committed atomically:

1. **Task 1: Add desktop client support to auth endpoints** - `f2d53fe` (feat)
2. **Task 2: Update auth controller tests for desktop client flow** - `e9e8a2b` (test)

## Files Created/Modified

- `apps/api/src/auth/auth.controller.ts` - Modified login/refresh/logout to detect X-Client-Type: desktop header
- `apps/api/src/auth/dto/token.dto.ts` - Added DesktopRefreshDto class and optional refreshToken to TokenResponseDto
- `apps/api/src/auth/dto/login.dto.ts` - Added optional refreshToken to LoginResponseDto
- `apps/api/src/auth/auth.controller.spec.ts` - Added 8 desktop client test cases, updated existing tests for new method signatures
- `apps/web/src/api/models/desktopRefreshDto.ts` - Generated DesktopRefreshDto type for API client
- `apps/web/src/api/auth/auth.ts` - Regenerated auth API client with new types
- `apps/web/src/api/models/loginResponseDto.ts` - Updated with optional refreshToken field
- `apps/web/src/api/models/tokenResponseDto.ts` - Updated with optional refreshToken field
- `apps/web/src/api/models/index.ts` - Updated barrel export with DesktopRefreshDto
- `packages/api-client/openapi.json` - Updated OpenAPI spec with new DTOs and optional fields

## Decisions Made

- **X-Client-Type: desktop header for client detection** - Simple header-based approach, no auth mechanism changes needed
- **Controller-only changes, no AuthService modifications** - The service already returns refreshToken; only the delivery mechanism (cookie vs body) changes
- **DesktopRefreshDto with optional refreshToken** - Allows the same endpoint to accept both empty body (web) and body with refreshToken (desktop)
- **Existing test updates in Task 1** - Updated existing test method signatures to pass mock request objects with headers, ensuring they pass with the new controller signatures

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Desktop auth endpoints ready for Tauri client integration
- API client regenerated with new types for desktop refresh flow
- All 361 API tests pass (18 suites), no regressions

---

_Phase: 09-desktop-client_
_Completed: 2026-02-08_
