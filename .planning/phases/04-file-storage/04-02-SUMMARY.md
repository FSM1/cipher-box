---
phase: 04-file-storage
plan: 02
subsystem: api
tags: [vault, quota, typeorm, postgresql, ecies, ipns]

# Dependency graph
requires:
  - phase: 03-03
    provides: ECIES key wrapping, vault initialization types
  - phase: 02-01
    provides: User entity, JwtAuthGuard
provides:
  - Vault entity for encrypted key storage (zero-knowledge)
  - PinnedCid entity for storage quota tracking
  - VaultService with quota management
  - VaultController with /vault/init, /vault, /vault/quota endpoints
  - QUOTA_LIMIT_BYTES constant (500 MiB)
affects:
  - 04-03 (IPFS pinning uses VaultService.recordPin/recordUnpin)
  - 05-folder-operations (uses Vault for folder key storage)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Hex-encoded byte fields in DTOs (decode to Buffer in service)'
    - 'ECIES-wrapped keys stored as BYTEA in PostgreSQL'
    - 'Quota tracking via SUM(sizeBytes) aggregation'
    - 'Idempotent pin/unpin with ON CONFLICT DO NOTHING'

key-files:
  created:
    - apps/api/src/vault/entities/vault.entity.ts
    - apps/api/src/vault/entities/pinned-cid.entity.ts
    - apps/api/src/vault/entities/index.ts
    - apps/api/src/vault/dto/init-vault.dto.ts
    - apps/api/src/vault/dto/quota.dto.ts
    - apps/api/src/vault/dto/index.ts
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/vault/vault.controller.ts
    - apps/api/src/vault/vault.module.ts
  modified:
    - apps/api/src/app.module.ts
    - apps/api/scripts/generate-openapi.ts
    - packages/api-client/openapi.json

key-decisions:
  - 'Vault stores encrypted keys as BYTEA columns (not strings)'
  - 'PinnedCid uses unique(userId, cid) constraint for idempotency'
  - 'Quota is calculated via SUM aggregation (no cached field)'
  - 'DTOs use hex-encoded strings for byte fields'
  - 'VaultService exported for use in IPFS module'

patterns-established:
  - 'toVaultResponse() pattern for entity-to-DTO conversion with hex encoding'
  - 'findVault returns null vs getVault throws NotFoundException'
  - 'recordPin/recordUnpin are idempotent operations'

# Metrics
duration: 6min
completed: 2026-01-20
---

# Phase 4 Plan 02: Vault Management Summary

**VaultModule with vault initialization, encrypted key storage, and 500 MiB quota tracking using PostgreSQL**

## Performance

- **Duration:** 6 min
- **Started:** 2026-01-20T20:15:08Z
- **Completed:** 2026-01-20T20:20:57Z
- **Tasks:** 3
- **Files created/modified:** 12

## Accomplishments

- Vault entity storing ECIES-wrapped keys (ownerPublicKey, encryptedRootFolderKey, encryptedRootIpnsPrivateKey)
- PinnedCid entity for per-user storage tracking with unique(userId, cid) constraint
- VaultService with quota management: checkQuota, recordPin, recordUnpin
- Three protected endpoints: POST /vault/init, GET /vault, GET /vault/quota
- QUOTA_LIMIT_BYTES = 500 _ 1024 _ 1024 (524,288,000 bytes)

## Task Commits

Each task was committed atomically:

1. **Task 1: Create Vault and PinnedCid entities** - `e164c63` (feat)
2. **Task 2: Create VaultService with quota management** - `b33149e` (feat)
3. **Task 3: Create VaultController and VaultModule** - `6f62b88` (feat)

## Files Created/Modified

### Entities

- `apps/api/src/vault/entities/vault.entity.ts` - Vault table with encrypted keys
- `apps/api/src/vault/entities/pinned-cid.entity.ts` - PinnedCid for quota tracking
- `apps/api/src/vault/entities/index.ts` - Barrel export

### DTOs

- `apps/api/src/vault/dto/init-vault.dto.ts` - InitVaultDto, VaultResponseDto
- `apps/api/src/vault/dto/quota.dto.ts` - QuotaResponseDto
- `apps/api/src/vault/dto/index.ts` - Barrel export

### Service and Controller

- `apps/api/src/vault/vault.service.ts` - Business logic with quota management
- `apps/api/src/vault/vault.controller.ts` - REST endpoints with JwtAuthGuard
- `apps/api/src/vault/vault.module.ts` - Module configuration

### Integration

- `apps/api/src/app.module.ts` - Added VaultModule, Vault, PinnedCid entities
- `apps/api/scripts/generate-openapi.ts` - Added VaultController/Service
- `packages/api-client/openapi.json` - Updated with /vault endpoints

## Decisions Made

1. **Vault stores encrypted keys as BYTEA** - Direct binary storage instead of hex strings in database; hex encoding only at API boundary
2. **PinnedCid sizeBytes as bigint** - TypeORM returns as string to avoid JavaScript number precision issues
3. **Quota calculated on-demand** - SUM(sizeBytes) query rather than cached field, acceptable for 500 MiB limit
4. **DTOs use hex-encoded strings** - Consistent with other CipherBox APIs, easy for frontend to handle
5. **VaultService exported from module** - Allows IpfsModule to use recordPin/recordUnpin

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - all tasks executed without blocking issues.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- VaultModule ready for integration with IPFS file upload (04-03)
- VaultService.recordPin/recordUnpin available for quota tracking during uploads
- VaultService.checkQuota can reject uploads exceeding 500 MiB limit
- Entities added to TypeORM synchronize (tables created on app start)

---

_Phase: 04-file-storage_
_Completed: 2026-01-20_
