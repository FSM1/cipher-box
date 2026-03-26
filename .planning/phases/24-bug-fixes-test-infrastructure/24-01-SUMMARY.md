---
phase: 24-bug-fixes-test-infrastructure
plan: 01
subsystem: sdk, core, auth
tags: [ipns, bin, registry, migration, tdd, crypto, validation]

# Dependency graph
requires:
  - phase: 19.1-sdk-extraction
    provides: '@cipherbox/sdk bin module, @cipherbox/core registry module'
provides:
  - Bin IPNS auto-repair with publishWithVerify retry/verify pattern
  - Device registry v1->v2 migration with lenient read / strict write
  - Fixed ipHash computation in useAuth.ts (SHA-256 of placeholder)
affects: [desktop, sdk-core, device-registry, staging]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'publishWithVerify: resolve-back verification after IPNS publish with exponential backoff'
    - 'Schema migration: lenient v1 read + strict v2 write in validateDeviceRegistry'
    - 'validateDeviceEntryBase: shared base validation without ipHash for v1 migration path'

key-files:
  created: []
  modified:
    - packages/sdk/src/bin/index.ts
    - packages/sdk/src/__tests__/bin.test.ts
    - packages/core/src/registry/schema.ts
    - packages/core/src/registry/types.ts
    - packages/core/src/registry/index.ts
    - packages/core/src/index.ts
    - packages/core/src/__tests__/registry.test.ts
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/services/device-registry.service.ts
    - docs/METADATA_SCHEMAS.md

key-decisions:
  - 'publishWithVerify does not throw on verification failure -- record may propagate eventually'
  - 'v1 empty ipHash filled with 64-char zero placeholder (not random hash) for traceability'
  - 'New registries created as v2 from the start (device-registry.service.ts updated)'
  - 'useAuth.ts ipHash uses SHA-256 of 0.0.0.0 placeholder (privacy-preserving, no real IP)'

patterns-established:
  - 'publishWithVerify: wrap IPNS publish with resolve-back verification loop'
  - 'Schema versioned migration: accept old version on read, always write latest version'

requirements-completed: [BUGFIX-01, BUGFIX-02]

# Metrics
duration: 10min
completed: 2026-03-25
---

# Phase 24 Plan 01: Bug Fixes Summary

**Bin IPNS auto-repair with publishWithVerify + device registry v2 schema migration with lenient v1 read**

## Performance

- **Duration:** 10 min
- **Started:** 2026-03-25T22:54:05Z
- **Completed:** 2026-03-25T23:05:00Z
- **Tasks:** 2
- **Files modified:** 10

## Accomplishments

- Bin IPNS 404 fixed: loadBin auto-repairs by publishing empty bin with sequenceNumber 1 when resolveIpnsRecord returns null
- saveBinMetadata uses publishWithVerify for all bin IPNS publishes with resolve-back verification and exponential backoff retry
- Device registry v2 schema: validates both v1 and v2, v1 migrated to v2 with lenient ipHash handling (empty string -> zero placeholder)
- Fixed ipHash in useAuth.ts: computes SHA-256 of '0.0.0.0' instead of passing empty string
- New registries created as v2 from the start
- METADATA_SCHEMAS.md updated with v2 version history per evolution protocol

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix bin IPNS 404 -- auto-repair + publishWithVerify** - `abc46d9a7` (fix)
2. **Task 2: Fix device registry format error -- v2 schema + ipHash** - `ccc4c65a2` (fix)

_Note: Both tasks followed TDD with tests written first (RED), implementation second (GREEN)._

## Files Created/Modified

- `packages/sdk/src/bin/index.ts` - Added publishWithVerify helper, loadBin auto-repair on null IPNS
- `packages/sdk/src/__tests__/bin.test.ts` - Updated/added 4 tests: auto-repair, publishWithVerify verify, retry
- `packages/core/src/registry/schema.ts` - Rewritten: migrateV1ToV2, validateV2Registry, validateDeviceEntryBase
- `packages/core/src/registry/types.ts` - Added DeviceRegistryVersion type, version field now 'v1' | 'v2'
- `packages/core/src/registry/index.ts` - Export DeviceRegistryVersion
- `packages/core/src/index.ts` - Export DeviceRegistryVersion from top-level barrel
- `packages/core/src/__tests__/registry.test.ts` - Updated/added 8 tests: v2 acceptance, v1 migration, strict validation
- `apps/web/src/hooks/useAuth.ts` - SHA-256 ipHash instead of empty string
- `apps/web/src/services/device-registry.service.ts` - New registries created as v2
- `docs/METADATA_SCHEMAS.md` - DeviceRegistry section updated for v1/v2, version history table

## Decisions Made

- publishWithVerify does not throw on verification failure after all retries -- the publish succeeded, verification just couldn't confirm propagation. Record may propagate eventually.
- v1 empty ipHash filled with 64-char zero placeholder ('0'.repeat(64)) for traceability rather than random hash.
- New registries created as v2 from the start (device-registry.service.ts updated in addition to schema changes).
- useAuth.ts ipHash uses SHA-256 of '0.0.0.0' placeholder -- privacy-preserving, no real IP address exposed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Updated device-registry.service.ts to create v2 registries**

- **Found during:** Task 2 (registry v2 schema implementation)
- **Issue:** device-registry.service.ts creates new registries with `version: 'v1'` -- plan's must_have says "Device registry always writes v2 format" but didn't explicitly list this file
- **Fix:** Changed `version: 'v1'` to `version: 'v2'` in the new registry creation path
- **Files modified:** apps/web/src/services/device-registry.service.ts
- **Verification:** TypeScript compiles, v2 is a valid value for DeviceRegistryVersion type
- **Committed in:** ccc4c65a2 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 missing critical)
**Impact on plan:** Auto-fix necessary for correctness -- new registries should write v2 from the start, not rely on migration on next read.

## Issues Encountered

- Pre-commit markdownlint hook caught that the METADATA_SCHEMAS.md table of contents anchor needed updating after section header changed from "DeviceRegistry (v1)" to "DeviceRegistry (v1/v2)". Fixed the anchor link and recommitted successfully.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Both bugs fixed with unit tests verifying the new behavior
- Bin auto-repair pattern (publishWithVerify) can be reused for other IPNS publish operations
- Registry v2 migration pattern established for future schema evolution
- Ready for Plan 02 (headless sdk-core load tests) and Plan 03 (recovery tool E2E)

---

## Self-Check: PASSED

All 10 modified files exist. Both task commits (abc46d9a7, ccc4c65a2) verified in git history. Summary file created.

---

_Phase: 24-bug-fixes-test-infrastructure_
_Completed: 2026-03-25_
