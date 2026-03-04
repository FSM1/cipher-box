---
phase: 17-recycle-bin
plan: 01
subsystem: crypto, api
tags: [ecies, hkdf, ipns, recycle-bin, nestjs-config]

# Dependency graph
requires:
  - phase: 12.2
    provides: Device registry IPNS derivation and ECIES encryption pattern
provides:
  - RecycleBinMetadata and BinEntry types in @cipherbox/crypto
  - HKDF derivation for bin IPNS keypair (cipherbox-recycle-bin-ipns-v1)
  - ECIES encrypt/decrypt for bin metadata blob
  - Runtime schema validator for bin metadata
  - GET /vault/config endpoint returning recycleBinRetentionDays
affects: [17-02 bin store and service, 17-03 web UI, 17-04 desktop FUSE soft-delete]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Bin metadata follows DeviceRegistry ECIES pattern (not AES-GCM like folders)'
    - 'HKDF domain separation with cipherbox-recycle-bin-ipns-v1 info string'
    - 'Environment-configurable retention via RECYCLE_BIN_RETENTION_DAYS with default 30'

key-files:
  created:
    - packages/crypto/src/bin/types.ts
    - packages/crypto/src/bin/derive-ipns.ts
    - packages/crypto/src/bin/encrypt.ts
    - packages/crypto/src/bin/schema.ts
    - packages/crypto/src/bin/index.ts
    - apps/api/src/vault/dto/vault-config.dto.ts
    - apps/web/src/api/models/vaultConfigResponseDto.ts
  modified:
    - packages/crypto/src/index.ts
    - apps/api/src/vault/vault.controller.ts
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/vault/vault.controller.spec.ts
    - apps/api/src/vault/vault.service.spec.ts
    - apps/api/src/vault/dto/index.ts
    - apps/web/src/api/vault/vault.ts
    - apps/web/src/api/models/index.ts
    - packages/api-client/openapi.json

key-decisions:
  - 'Bin metadata uses ECIES encryption (same as DeviceRegistry, not AES-GCM like folders)'
  - 'HKDF info string: cipherbox-recycle-bin-ipns-v1 with salt CipherBox-v1'
  - 'Schema validation is lenient on filePointer/folderEntry presence (optional regardless of itemType)'
  - 'GET /vault/config is synchronous (no async, no DB query)'
  - 'ConfigService default 30 days, overridable via RECYCLE_BIN_RETENTION_DAYS env var'

patterns-established:
  - 'Bin module follows exact same structure as registry module: types, derive-ipns, encrypt, schema, index'
  - 'VaultConfigResponseDto pattern for future config fields'

# Metrics
duration: 7min
completed: 2026-03-04
---

# Phase 17 Plan 01: Bin Metadata Crypto Primitives & Config API Summary

**RecycleBinMetadata/BinEntry types with HKDF-derived IPNS keypair, ECIES encryption, schema validation, and GET /vault/config endpoint returning environment-configurable retention days**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-04T01:14:24Z
- **Completed:** 2026-03-04T01:21:23Z
- **Tasks:** 2
- **Files modified:** 17

## Accomplishments

- Created complete `packages/crypto/src/bin/` module with types, HKDF derivation, ECIES encrypt/decrypt, and runtime schema validation -- following the DeviceRegistry pattern exactly
- Added `GET /vault/config` endpoint returning `{ recycleBinRetentionDays }` from environment config (default 30, staging 2)
- Regenerated API client with typed `getConfig` function for the web app
- All 241 crypto tests and 633 API tests pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Create bin metadata crypto module** - `43efc8441` (feat)
2. **Task 2: Add retention config API endpoint** - `61be668be` (feat)

## Files Created/Modified

- `packages/crypto/src/bin/types.ts` - RecycleBinMetadata and BinEntry type definitions
- `packages/crypto/src/bin/derive-ipns.ts` - HKDF derivation for bin IPNS keypair
- `packages/crypto/src/bin/encrypt.ts` - ECIES encrypt/decrypt for bin metadata blob
- `packages/crypto/src/bin/schema.ts` - Runtime validation for decrypted bin metadata
- `packages/crypto/src/bin/index.ts` - Barrel exports for bin module
- `packages/crypto/src/index.ts` - Added bin module exports to package root
- `apps/api/src/vault/dto/vault-config.dto.ts` - VaultConfigResponseDto with Swagger decorators
- `apps/api/src/vault/dto/index.ts` - Added vault-config.dto export
- `apps/api/src/vault/vault.controller.ts` - Added GET /vault/config endpoint
- `apps/api/src/vault/vault.service.ts` - Added ConfigService injection and getConfig method
- `apps/api/src/vault/vault.controller.spec.ts` - Tests for getConfig controller method
- `apps/api/src/vault/vault.service.spec.ts` - Tests for getConfig service method
- `apps/web/src/api/vault/vault.ts` - Regenerated with getConfig function
- `apps/web/src/api/models/vaultConfigResponseDto.ts` - Generated DTO type
- `apps/web/src/api/models/index.ts` - Updated model exports
- `packages/api-client/openapi.json` - Updated OpenAPI spec

## Decisions Made

- Bin metadata uses ECIES encryption (same as DeviceRegistry), not AES-GCM like regular folders. Rationale: bin is a single user-scoped record, no per-record symmetric key to manage.
- Schema validation is lenient on `filePointer`/`folderEntry` presence: they are optional regardless of `itemType` to allow schema evolution without breaking existing entries.
- `GET /vault/config` is synchronous (no database query), just reads from environment via ConfigService.
- ConfigService default is 30 days. Staging deployments should set `RECYCLE_BIN_RETENTION_DAYS=2`.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Bin crypto primitives ready for use by web app bin service (Plan 02)
- Config endpoint ready for client to fetch retention period on login
- No blockers for Plan 02 (bin store, service, and delete flow modifications)

---

_Phase: 17-recycle-bin_
_Completed: 2026-03-04_
