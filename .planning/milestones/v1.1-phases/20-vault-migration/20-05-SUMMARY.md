---
phase: 20-vault-migration
plan: 05
subsystem: api
tags: [typeorm, migration, vault, dto, openapi, security-surface]

# Dependency graph
requires:
  - phase: 20-vault-migration (plans 01-04)
    provides: v2 blob format support, lazy migration, dual-read clients
provides:
  - DB migration dropping encrypted_root_folder_key, encrypted_root_ipns_private_key, migrated_at columns
  - Simplified vault entity with zero crypto columns
  - Simplified InitVaultDto requiring only ownerPublicKey and rootIpnsName
  - VaultResponseDto and VaultExportDto without crypto fields
  - Removed POST /vault/migrate endpoint and migrateVault service method
  - Regenerated API client without vaultControllerMigrateVault
affects: [20-06 client dead code removal, desktop vault.rs types, web useAuth.ts]

# Tech tracking
tech-stack:
  added: []
  patterns: [zero-crypto-material vault schema]

key-files:
  created:
    - apps/api/src/migrations/1740700000000-DropVaultCryptoColumns.ts
  modified:
    - apps/api/src/vault/entities/vault.entity.ts
    - apps/api/src/vault/dto/init-vault.dto.ts
    - apps/api/src/vault/dto/vault-export.dto.ts
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/vault/vault.controller.ts
    - apps/api/src/vault/vault.controller.spec.ts
    - apps/api/src/vault/vault.service.spec.ts
    - packages/api-client/openapi.json
    - packages/api-client/src/generated/vault/vault.ts
    - packages/api-client/src/models/initVaultDto.ts
    - packages/api-client/src/models/vaultExportDto.ts
    - packages/api-client/src/models/vaultResponseDto.ts

key-decisions:
  - 'Combined per-task commits into single commit for Task 1 due to pre-commit hook requiring api-client regeneration with entity/dto/controller changes'
  - 'Controller spec updated as Rule 3 deviation since removed DTO fields would break TypeScript compilation of test fixtures'

patterns-established:
  - 'Zero-crypto vault: server stores only ownerPublicKey and rootIpnsName, all crypto material lives in IPFS v2 blobs'

requirements-completed: [VAULT-01, VAULT-02, VAULT-03, VAULT-04, VAULT-05, VAULT-06]

# Metrics
duration: 6min
completed: 2026-03-24
---

# Phase 20 Plan 05: Drop Vault Crypto Columns Summary

**DB migration dropping 3 crypto columns, removal of POST /vault/migrate endpoint, simplified vault entity/DTOs/service to zero-crypto-material schema, regenerated API client**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-24T03:06:01Z
- **Completed:** 2026-03-24T03:13:00Z
- **Tasks:** 2
- **Files modified:** 13

## Accomplishments

- Created DB migration (1740700000000) to drop encrypted_root_folder_key, encrypted_root_ipns_private_key, and migrated_at columns from vaults table
- Removed migrateVault method from vault service and POST /vault/migrate from controller, eliminating dead migration infrastructure
- Simplified InitVaultDto to only require ownerPublicKey and rootIpnsName (no crypto material sent to server)
- Removed crypto fields from VaultResponseDto, VaultExportDto, and vault entity
- Regenerated API client without vaultControllerMigrateVault function
- Updated all 41 vault service tests and 9 controller tests to match simplified schema

## Task Commits

Each task was committed atomically:

1. **Task 1: DB migration + entity/DTO/service/controller cleanup + API client regen** - `02d1f68` (feat)
2. **Task 2: Update vault service tests for simplified schema** - `ffadcf1` (test)

## Files Created/Modified

- `apps/api/src/migrations/1740700000000-DropVaultCryptoColumns.ts` - New migration dropping 3 dead columns
- `apps/api/src/vault/entities/vault.entity.ts` - Removed encryptedRootFolderKey, encryptedRootIpnsPrivateKey, migratedAt
- `apps/api/src/vault/dto/init-vault.dto.ts` - Simplified InitVaultDto and VaultResponseDto
- `apps/api/src/vault/dto/vault-export.dto.ts` - Removed crypto fields from export DTO
- `apps/api/src/vault/vault.service.ts` - Removed migrateVault, simplified initializeVault/getExportData/toVaultResponse
- `apps/api/src/vault/vault.controller.ts` - Removed POST /vault/migrate endpoint
- `apps/api/src/vault/vault.controller.spec.ts` - Updated test fixtures for simplified DTOs
- `apps/api/src/vault/vault.service.spec.ts` - Removed all crypto field references and migration tests
- `packages/api-client/openapi.json` - Regenerated without migrate endpoint
- `packages/api-client/src/generated/vault/vault.ts` - Regenerated without vaultControllerMigrateVault
- `packages/api-client/src/models/initVaultDto.ts` - Regenerated without crypto fields
- `packages/api-client/src/models/vaultExportDto.ts` - Regenerated without crypto fields
- `packages/api-client/src/models/vaultResponseDto.ts` - Regenerated without crypto fields or migratedAt

## Decisions Made

- Combined all Task 1 changes (entity, DTOs, controller, service, migration, API client) into a single commit due to the pre-commit hook (scripts/check-api-client.sh) requiring API client regeneration alongside entity/DTO changes
- Updated vault.controller.spec.ts as part of Task 1 (Rule 3 deviation) since the typed InitVaultDto and VaultResponseDto fixtures would fail TypeScript compilation with the removed fields

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated vault.controller.spec.ts test fixtures**

- **Found during:** Task 1 (entity/DTO/service/controller changes)
- **Issue:** vault.controller.spec.ts uses typed `InitVaultDto` and object literals matching `VaultResponseDto` -- removing fields from the DTOs would break TypeScript compilation of tests
- **Fix:** Removed encryptedRootFolderKey, encryptedRootIpnsPrivateKey from initVaultDto and mockVaultResponse test fixtures
- **Files modified:** apps/api/src/vault/vault.controller.spec.ts
- **Verification:** `npx jest --testPathPattern=vault.controller --no-coverage` -- 9 tests pass
- **Committed in:** 02d1f68 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Controller spec fix was necessary for test compilation. No scope creep.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 20-06 (client dead code removal) can proceed -- API client is regenerated without migrate function
- Web client (useAuth.ts) still imports vaultControllerMigrateVault which will be cleaned up in Plan 20-06
- Desktop client types will be updated in Plan 20-06

## Self-Check: PASSED

- FOUND: apps/api/src/migrations/1740700000000-DropVaultCryptoColumns.ts
- FOUND: .planning/phases/20-vault-migration/20-05-SUMMARY.md
- FOUND: commit 02d1f68 (Task 1)
- FOUND: commit ffadcf1 (Task 2)

---

_Phase: 20-vault-migration_
_Completed: 2026-03-24_
