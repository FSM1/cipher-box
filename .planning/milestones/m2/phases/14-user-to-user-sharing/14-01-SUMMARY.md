---
phase: 14-user-to-user-sharing
plan: 01
subsystem: crypto, database
tags: [ecies, secp256k1, typeorm, sharing, re-wrapping]

# Dependency graph
requires:
  - phase: 12.6-per-file-ipns
    provides: Per-file IPNS metadata split enabling file-level sharing
  - phase: 03-encryption
    provides: ECIES wrapKey/unwrapKey functions used by reWrapKey
provides:
  - reWrapKey() function for ECIES key re-wrapping in sharing flows
  - Share TypeORM entity for share relationship records
  - ShareKey TypeORM entity for re-wrapped descendant keys
  - KEY_REWRAP_FAILED error code in CryptoErrorCode type
affects:
  - 14-02 (shares module, service, controller will use these entities)
  - 14-03 (share dialog will call reWrapKey from client)
  - 14-04 (shared browsing will query share records)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'ECIES re-wrapping: unwrap with owner key, re-wrap with recipient key, zero plaintext'
    - 'Soft-delete revokedAt for lazy key rotation on share revocation'
    - 'Dual-table share architecture: shares (relationship) + share_keys (descendant keys)'

key-files:
  created:
    - packages/crypto/src/ecies/rewrap.ts
    - packages/crypto/src/__tests__/rewrap.test.ts
    - apps/api/src/shares/entities/share.entity.ts
    - apps/api/src/shares/entities/share-key.entity.ts
    - apps/api/src/shares/entities/index.ts
  modified:
    - packages/crypto/src/ecies/index.ts
    - packages/crypto/src/index.ts
    - packages/crypto/src/types.ts

key-decisions:
  - 'KEY_REWRAP_FAILED added to CryptoErrorCode for re-wrapping error classification'
  - 'itemName stored as plaintext in share record (minimal privacy impact per RESEARCH.md)'
  - 'revokedAt soft-delete enables lazy key rotation without separate tracking table'

patterns-established:
  - 'reWrapKey pattern: try/finally ensures plaintext key zeroed even on error'
  - 'Share entity Unique(sharer, recipient, ipnsName) prevents duplicate shares'
  - 'ShareKey CASCADE from Share ensures revocation cleans up all re-wrapped keys'

# Metrics
duration: 7min
completed: 2026-02-21
---

# Phase 14 Plan 01: Crypto Foundation & Share Entities Summary

**reWrapKey ECIES utility with 4 test vectors plus Share/ShareKey TypeORM entities for user-to-user sharing**

## Performance

- **Duration:** 7 min
- **Started:** 2026-02-21T07:04:01Z
- **Completed:** 2026-02-21T07:11:00Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- reWrapKey function that unwraps with owner's private key and re-wraps with recipient's public key, with plaintext key zeroed from memory
- Share entity modeling the share relationship with soft-delete for lazy key rotation
- ShareKey entity for storing re-wrapped descendant keys with CASCADE delete
- 4 comprehensive test vectors covering round-trip, multi-recipient, wrong key, and invalid pubkey scenarios

## Task Commits

Each task was committed atomically:

1. **Task 1: Create reWrapKey crypto utility with tests** - `2eddb7614` (feat)
2. **Task 2: Create Share and ShareKey TypeORM entities** - `23a6332c1` (feat)

## Files Created/Modified

- `packages/crypto/src/ecies/rewrap.ts` - reWrapKey function: unwrap + re-wrap + zero plaintext
- `packages/crypto/src/__tests__/rewrap.test.ts` - 4 test vectors for re-wrapping correctness
- `packages/crypto/src/ecies/index.ts` - Added reWrapKey export
- `packages/crypto/src/index.ts` - Added reWrapKey to package exports
- `packages/crypto/src/types.ts` - Added KEY_REWRAP_FAILED error code
- `apps/api/src/shares/entities/share.entity.ts` - Share TypeORM entity with user relations
- `apps/api/src/shares/entities/share-key.entity.ts` - ShareKey entity with CASCADE delete
- `apps/api/src/shares/entities/index.ts` - Barrel export for share entities

## Decisions Made

- Added KEY_REWRAP_FAILED to CryptoErrorCode type for specific re-wrapping error classification
- Entities not registered in app.module.ts yet (deferred to Plan 02 when shares module is created)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Pre-commit hook required `pnpm api:generate` when staging API entity files, even though entities are not yet registered in app.module.ts. Generated openapi.json had only formatting changes (no functional impact).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- reWrapKey is exported and tested, ready for client-side sharing flows in Plan 03+
- Share and ShareKey entities are ready for service/controller wiring in Plan 02
- Entities need to be registered in shares.module.ts (Plan 02)

---

_Phase: 14-user-to-user-sharing_
_Completed: 2026-02-21_
