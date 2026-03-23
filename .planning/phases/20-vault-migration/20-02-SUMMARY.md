---
phase: 20-vault-migration
plan: 02
subsystem: api
tags: [typeorm, migration, nestjs, vault, dto, swagger]

# Dependency graph
requires:
  - phase: 20-vault-migration/01
    provides: Vault blob v2 binary format (serialize/deserialize/detect) in @cipherbox/core
provides:
  - DB migration adding migrated_at column and making crypto columns nullable
  - Vault entity with nullable encryptedRootFolderKey and encryptedRootIpnsPrivateKey
  - POST /vault/migrate endpoint (idempotent, stamps migratedAt, NULLs crypto columns)
  - Optional encryptedRootIpnsPrivateKey on vault init for v2 vaults
  - VaultResponseDto with migratedAt field for client migration detection
  - Regenerated API client with vaultControllerMigrateVault function
affects: [20-vault-migration/03, 20-vault-migration/04]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Nullable crypto columns pattern: Buffer | null on entity, string | null on DTO, optional chaining in service'
    - 'Idempotent migration endpoint: check-then-skip for already-migrated vaults'

key-files:
  created:
    - apps/api/src/migrations/1740600000000-AddVaultMigratedAt.ts
    - packages/api-client/src/models/vaultExportDtoEncryptedRootFolderKey.ts
    - packages/api-client/src/models/vaultExportDtoEncryptedRootIpnsPrivateKey.ts
    - packages/api-client/src/models/vaultResponseDtoEncryptedRootFolderKey.ts
    - packages/api-client/src/models/vaultResponseDtoEncryptedRootIpnsPrivateKey.ts
  modified:
    - apps/api/src/vault/entities/vault.entity.ts
    - apps/api/src/vault/dto/init-vault.dto.ts
    - apps/api/src/vault/dto/vault-export.dto.ts
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/vault/vault.controller.ts
    - packages/api-client/openapi.json
    - packages/api-client/src/generated/vault/vault.ts
    - packages/api-client/src/models/index.ts
    - packages/api-client/src/models/initVaultDto.ts
    - packages/api-client/src/models/vaultResponseDto.ts
    - packages/api-client/src/models/vaultExportDto.ts

key-decisions:
  - 'Combined all 3 tasks into single commit due to pre-commit hook requiring api-client regeneration with any entity/dto/controller change'
  - 'VaultExportDto crypto fields made nullable (string | null) to correctly reflect migrated user state'

patterns-established:
  - 'Nullable crypto column pattern: entity Buffer | null, DTO string | null, service uses optional chaining (?.) with nullish coalescing (?? null)'
  - 'Idempotent migration endpoint: check migratedAt, early return if set, otherwise update and NULL crypto columns'

requirements-completed: [VAULT-02, VAULT-03, VAULT-04]

# Metrics
duration: 17min
completed: 2026-03-23
---

# Phase 20 Plan 02: Server-Side Vault Migration API Summary

**DB migration for migrated_at column, POST /vault/migrate endpoint, optional IPNS key on init, and nullable crypto columns across entity/DTOs/service/export**

## Performance

- **Duration:** 17 min
- **Started:** 2026-03-23T21:18:59Z
- **Completed:** 2026-03-23T21:36:00Z
- **Tasks:** 3
- **Files modified:** 16

## Accomplishments

- DB migration 1740600000000 adds migrated_at column and makes crypto columns nullable (idempotent with IF NOT EXISTS)
- POST /vault/migrate endpoint stamps migratedAt and NULLs both encryptedRootFolderKey and encryptedRootIpnsPrivateKey (idempotent)
- InitVaultDto.encryptedRootIpnsPrivateKey now optional for v2 vault initialization
- VaultResponseDto includes migratedAt field so clients can determine read path (DB vs IPFS)
- VaultExportDto handles migrated users returning null for crypto fields
- API client regenerated with vaultControllerMigrateVault function and updated type models

## Task Commits

All tasks committed together (pre-commit hook requires api-client files with entity/dto/controller changes):

1. **Tasks 1-3: DB migration, entity/DTO/service updates, controller endpoint, API client** - `c208d929f` (feat)

**Plan metadata:** (pending final commit)

## Files Created/Modified

- `apps/api/src/migrations/1740600000000-AddVaultMigratedAt.ts` - DB migration adding migrated_at, making crypto columns nullable
- `apps/api/src/vault/entities/vault.entity.ts` - Vault entity with nullable crypto columns and migratedAt
- `apps/api/src/vault/dto/init-vault.dto.ts` - Optional encryptedRootIpnsPrivateKey, VaultResponseDto with migratedAt
- `apps/api/src/vault/dto/vault-export.dto.ts` - Nullable crypto fields for migrated users
- `apps/api/src/vault/vault.service.ts` - migrateVault method, nullable handling in toVaultResponse/getExportData
- `apps/api/src/vault/vault.controller.ts` - POST /vault/migrate endpoint
- `packages/api-client/openapi.json` - Updated OpenAPI spec
- `packages/api-client/src/generated/vault/vault.ts` - Generated vaultControllerMigrateVault function
- `packages/api-client/src/models/vaultResponseDto.ts` - Updated with migratedAt and nullable fields
- `packages/api-client/src/models/initVaultDto.ts` - Optional encryptedRootIpnsPrivateKey

## Decisions Made

- **Combined commit for all 3 tasks:** Pre-commit hook (scripts/check-api-client.sh) requires packages/api-client/openapi.json to be staged when any .entity.ts, .dto.ts, or .controller.ts file is staged. This makes per-task atomic commits impractical when tasks span entity, DTO, and controller changes. All tasks committed together with detailed commit message documenting each task's changes.
- **VaultExportDto made nullable:** Plan mentioned "Update VaultExportDto if needed" -- confirmed that export must return null for migrated users whose crypto columns are NULLed, so both fields changed to `string | null`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Pre-commit hook requires api-client regeneration with entity/dto/controller changes**

- **Found during:** Task 1 commit attempt
- **Issue:** Pre-commit hook (scripts/check-api-client.sh) blocks commits of .entity.ts/.dto.ts/.controller.ts files unless packages/api-client/openapi.json is also staged
- **Fix:** Combined all 3 tasks into a single commit with api-client regeneration, preserving the logical grouping in the commit message
- **Files modified:** All 16 files committed together
- **Verification:** Commit succeeded with pre-commit hook passing
- **Committed in:** c208d929f

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Task-level atomicity traded for commit-level correctness. All task work is complete and verified individually. No scope creep.

## Issues Encountered

- Accidental `git restore --staged` on untracked desktop Rust files from Plan 20-01 caused unexpected unstaging of all files, requiring re-staging. The spurious commit `bd1459717` was soft-reset and recommitted properly.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Server-side vault migration infrastructure is complete
- Plan 20-03 (client-side migration flow) can now call POST /vault/migrate and read migratedAt from GET /vault
- Plan 20-04 (integration testing) can verify the full migration flow end-to-end
- Desktop Rust vault blob files from Plan 20-01 remain uncommitted in working tree (out of scope for this plan)

## Self-Check: PASSED

All created files verified on disk. Commit c208d929f verified in git log. SUMMARY.md created.

---

_Phase: 20-vault-migration_
_Completed: 2026-03-23_
