---
phase: 21-byo-ipfs-node-support
plan: 09
subsystem: api, tee
tags: [ecies, connection-test, ssrf, tee-worker, express, nestjs]

# Dependency graph
requires:
  - phase: 21-byo-ipfs-node-support
    provides: TEE migration worker with ECIES decryption and SSRF validation patterns
provides:
  - POST /tee/connection-test API endpoint for server-side IPFS provider probing
  - TEE worker /connection-test route with ECIES decryption and credential zeroing
  - Shared SSRF validation module reused by migration and connection-test routes
  - ConnectionTest component using TEE-routed testing (eliminates CORS issues)
  - Generated api-client with teeControllerConnectionTest function
affects: [21-byo-ipfs-node-support, web-settings, tee-worker]

# Tech tracking
tech-stack:
  added: []
  patterns: [TEE-routed connection test, shared SSRF validation module]

key-files:
  created:
    - tee-worker/src/routes/connection-test.ts
    - tee-worker/src/services/ssrf-validation.ts
    - apps/api/src/tee/tee.controller.ts
    - apps/api/src/tee/dto/connection-test.dto.ts
    - packages/api-client/src/generated/tee/tee.ts
  modified:
    - tee-worker/src/index.ts
    - tee-worker/src/services/migration-worker.ts
    - apps/api/src/tee/tee.service.ts
    - apps/api/src/tee/tee.module.ts
    - apps/api/scripts/generate-openapi.ts
    - apps/web/src/components/settings/ConnectionTest.tsx
    - packages/api-client/src/index.ts

key-decisions:
  - 'Added connectionTest method to existing TeeService rather than inlining fetch in controller (follows existing service pattern)'
  - 'Created TeeController since TEE module had no controller yet (needed for API endpoint)'
  - 'Extracted SSRF validation to shared module rather than duplicating in connection-test route'
  - 'Used generated api-client function (teeControllerConnectionTest) for web component instead of raw fetch'
  - 'Removed CORS error UI handling since server-side testing eliminates CORS issues entirely'

patterns-established:
  - 'TEE worker shared SSRF validation: both migration and connection-test routes import from ssrf-validation.ts'
  - 'TEE controller pattern: controller -> service -> TEE worker forwarding with auth headers'

requirements-completed: [BYO-05]

# Metrics
duration: 9min
completed: 2026-03-25
---

# Phase 21 Plan 09: TEE-Routed Connection Test Summary

**Server-side connection test via TEE worker eliminates browser CORS blocking; credentials ECIES-encrypted before leaving browser, decrypted only in-enclave**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-25T00:46:42Z
- **Completed:** 2026-03-25T00:56:05Z
- **Tasks:** 3
- **Files modified:** 17

## Accomplishments

- TEE worker /connection-test endpoint that decrypts ECIES-encrypted provider config, validates SSRF, probes Kubo and PSA endpoints server-side, and zeroes credentials
- API POST /tee/connection-test with rate limiting, DTO validation, and generated api-client function
- ConnectionTest component updated to encrypt credentials with TEE public key and route tests server-side, eliminating CORS blocking entirely
- SSRF validation extracted to shared module used by both migration and connection-test routes

## Task Commits

Each task was committed atomically:

1. **Task 1: TEE worker /connection-test endpoint** - `ed8ac42fd` (feat)
2. **Task 2: API POST /tee/connection-test endpoint** - `47c6daf5d` (feat)
3. **Task 3: Update ConnectionTest component to use TEE-routed endpoint** - `c29c58bcb` (feat)

## Files Created/Modified

- `tee-worker/src/routes/connection-test.ts` - TEE worker endpoint: ECIES decrypt, SSRF validate, probe Kubo/PSA
- `tee-worker/src/services/ssrf-validation.ts` - Shared SSRF protection (extracted from migration-worker)
- `tee-worker/src/services/migration-worker.ts` - Updated to import shared SSRF validation
- `tee-worker/src/index.ts` - Register connection-test route with auth middleware
- `apps/api/src/tee/tee.controller.ts` - New NestJS controller with POST /tee/connection-test
- `apps/api/src/tee/dto/connection-test.dto.ts` - Request/response DTOs with validation
- `apps/api/src/tee/tee.service.ts` - Added connectionTest forwarding method
- `apps/api/src/tee/tee.module.ts` - Registered TeeController
- `apps/api/scripts/generate-openapi.ts` - Added TeeController to OpenAPI generation
- `apps/web/src/components/settings/ConnectionTest.tsx` - TEE-routed testing with ECIES encryption
- `packages/api-client/src/generated/tee/tee.ts` - Generated teeControllerConnectionTest function
- `packages/api-client/src/index.ts` - Added tee export

## Decisions Made

- Added connectionTest method to existing TeeService rather than inlining fetch logic in controller (follows codebase's service-layer pattern where TeeService handles all TEE worker communication)
- Created TeeController since TEE module had no controller previously (only had service + entities)
- Extracted SSRF validation to shared ssrf-validation.ts module to avoid code duplication between migration and connection-test
- Used generated api-client function for web component rather than raw customInstance (type-safe, consistent with orval pattern)
- Removed CORS error UI handling (corsError, corsInstructions) from ConnectionTest since server-side testing eliminates CORS entirely
- Browser-side testConnection() preserved in sdk-core for desktop/CLI/fallback use

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added TeeController to OpenAPI generation script**

- **Found during:** Task 2 (API endpoint)
- **Issue:** generate-openapi.ts manually lists controllers; new TeeController was not in the generated OpenAPI spec
- **Fix:** Added TeeController import and registration to generate-openapi.ts, re-ran api:generate
- **Files modified:** apps/api/scripts/generate-openapi.ts
- **Verification:** packages/api-client/src/generated/tee/tee.ts exists with teeControllerConnectionTest
- **Committed in:** 47c6daf5d (Task 2 commit)

**2. [Rule 3 - Blocking] Added tee export to api-client index.ts**

- **Found during:** Task 3 (ConnectionTest component)
- **Issue:** api-client/src/index.ts did not export the generated tee module
- **Fix:** Added `export * from './generated/tee/tee'` to index.ts and rebuilt package
- **Files modified:** packages/api-client/src/index.ts
- **Verification:** teeControllerConnectionTest importable from @cipherbox/api-client
- **Committed in:** c29c58bcb (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** Both fixes necessary for the generated api-client to be usable. No scope creep.

## Issues Encountered

None - execution proceeded smoothly.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- TEE-routed connection test complete; StorageTab now tests connections server-side
- Browser-side testConnection() preserved for SDK consumers outside the web app
- Shared SSRF validation module available for any future TEE routes that accept user-provided URLs

## Self-Check: PASSED

All created files verified present. All 3 task commits verified in git log. SUMMARY.md exists.

---

_Phase: 21-byo-ipfs-node-support_
_Completed: 2026-03-25_
