---
phase: 08-tee-integration
plan: 03
subsystem: api, ui
tags: [tee, ecies, secp256k1, ipns, vault, wrapKey, nestjs, react]

# Dependency graph
requires:
  - phase: 08-tee-integration (plan 01)
    provides: TeeKeyStateService, TeeKeysDto, TeeModule for TEE epoch key management
  - phase: 05-folder-system
    provides: FolderIpns entity with encryptedIpnsPrivateKey/keyEpoch columns, IPNS publish flow
  - phase: 03-core-encryption
    provides: wrapKey (ECIES), hexToBytes/bytesToHex utilities
provides:
  - Backend returns TEE public keys in vault GET/init responses (API-08)
  - Client stores TEE keys from vault response in auth store on login
  - Client ECIES-encrypts IPNS private key with TEE public key on folder creation (TEE-02)
  - Encrypted IPNS key sent to backend on first folder IPNS publish
  - Backend logs TEE enrollment readiness (TODO for RepublishService wiring in 08-02)
  - API client regenerated with TeeKeysDto in VaultResponseDto
affects: [08-02, 08-04]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'TEE key delivery via vault response (VaultResponseDto.teeKeys)'
    - 'Client-side ECIES encryption of IPNS key with TEE public key using wrapKey'
    - 'TEE-encrypted key sent only on first IPNS publish for each folder'
    - 'Initial empty IPNS record published for new folders with TEE-encrypted key'

key-files:
  created: []
  modified:
    - apps/api/src/vault/dto/init-vault.dto.ts
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/vault/vault.module.ts
    - apps/api/src/ipns/ipns.service.ts
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/hooks/useFolder.ts
    - apps/web/src/services/folder.service.ts
    - apps/web/src/lib/api/vault.ts
    - apps/web/src/api/models/vaultResponseDto.ts

key-decisions:
  - 'TEE keys delivered via existing vault endpoint (no separate endpoint needed)'
  - 'wrapKey reused for TEE encryption (same ECIES as user key wrapping)'
  - 'Initial empty IPNS publish on folder creation to immediately enroll for TEE republishing'
  - 'Root folder TEE enrollment deferred (handled during subfolder creation flow only)'
  - 'RepublishService enrollment wiring deferred to plan 08-02 (TODO stubs added)'

patterns-established:
  - 'TEE key flow: vault response -> auth store -> folder creation -> IPNS publish'
  - 'Backward compatible TEE integration: all paths work with teeKeys=null'

# Metrics
duration: 7min
completed: 2026-02-07
---

# Phase 8 Plan 03: Client-Backend TEE Key Flow Summary

**ECIES-encrypted IPNS keys sent to backend on folder creation for TEE republish enrollment, with TEE public keys delivered via vault response on login.**

## Performance

- **Duration:** 7 min
- **Started:** 2026-02-07T05:22:21Z
- **Completed:** 2026-02-07T05:28:48Z
- **Tasks:** 2
- **Files modified:** 9

## Accomplishments

- Backend delivers TEE epoch public keys in every vault response (GET /vault, POST /vault/init) via new teeKeys field in VaultResponseDto
- Client stores TEE keys from vault response in auth store on login, available for all subsequent folder operations
- Client encrypts IPNS private key with TEE public key (ECIES secp256k1) during folder creation, sending it on first IPNS publish
- New folders publish an initial empty IPNS record with TEE-encrypted key to enable immediate republish enrollment
- Full backward compatibility: all paths work when teeKeys is null (TEE not initialized)

## Task Commits

Each task was committed atomically:

1. **Task 1: Backend returns TEE keys on vault fetch and auto-enrolls on publish** - `3980e47` (feat) -- Note: included in prior 08-02 partial execution
2. **Task 2: Client encrypts IPNS keys with TEE public key on publish** - `2db0bd0` (feat)

## Files Created/Modified

- `apps/api/src/vault/dto/init-vault.dto.ts` - Added teeKeys field (TeeKeysDto | null) to VaultResponseDto
- `apps/api/src/vault/vault.service.ts` - Injected TeeKeyStateService, fetch TEE keys in all vault response methods
- `apps/api/src/vault/vault.module.ts` - Imported TeeModule for TeeKeyStateService dependency
- `apps/api/src/ipns/ipns.service.ts` - Added TEE enrollment logging stubs in upsertFolderIpns
- `apps/web/src/hooks/useAuth.ts` - Store TEE keys from vault response after login/vault load
- `apps/web/src/hooks/useFolder.ts` - Wire TEE-encrypted key from createFolder to first IPNS publish
- `apps/web/src/services/folder.service.ts` - ECIES-encrypt IPNS private key with TEE public key during folder creation
- `apps/web/src/lib/api/vault.ts` - Updated VaultResponse type with teeKeys field
- `apps/web/src/api/models/vaultResponseDto.ts` - Generated: teeKeys in VaultResponseDto

## Decisions Made

- **TEE keys via vault endpoint:** Delivered through existing GET /vault and POST /vault/init endpoints rather than a separate TEE key endpoint -- fewer round trips on login
- **wrapKey reuse:** Same ECIES wrapKey function used for both user key wrapping and TEE key wrapping -- same secp256k1 uncompressed format
- **Initial empty IPNS publish:** New folders publish an empty IPNS record immediately on creation to deliver TEE-encrypted key to backend for enrollment
- **Root folder TEE enrollment deferred:** Root folder's IPNS key is created during vault init; TEE enrollment for root will be handled in 08-04 or as follow-up
- **RepublishService wiring deferred:** Since RepublishService/RepublishModule don't exist yet (created by 08-02), enrollment is logged but not wired

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Task 1 already committed in prior 08-02 partial execution**

- **Found during:** Task 1
- **Issue:** Commit `3980e47` from a partial 08-02 execution already included all Task 1 changes (VaultResponseDto teeKeys, VaultService injection, VaultModule import, IpnsService enrollment stubs, API client regeneration)
- **Fix:** Verified existing commit contains all required changes, skipped re-committing
- **Files affected:** All Task 1 files
- **Verification:** TypeScript compilation passes, generated API types include teeKeys

**2. [Rule 3 - Blocking] RepublishService does not exist yet**

- **Found during:** Task 1 (IpnsService auto-enrollment)
- **Issue:** Plan references RepublishService.enrollFolder but the republish module hasn't been created yet (that's plan 08-02's responsibility)
- **Fix:** Added TODO stubs with logging instead of actual enrollment call. The wiring will happen when 08-02 creates the RepublishService
- **Files affected:** apps/api/src/ipns/ipns.service.ts
- **Verification:** API compiles and runs without RepublishService dependency

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** Both deviations handled correctly. Task 1 was pre-committed by a prior session. RepublishService enrollment deferred to 08-02 with clear TODO. No scope creep.

## Issues Encountered

None - both tasks executed smoothly despite the Task 1 pre-commit situation.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Client-to-backend TEE key flow complete for subfolder creation
- Plan 08-02 should wire RepublishService.enrollFolder call in IpnsService when creating the republish module
- Plan 08-04 should handle root folder TEE enrollment and any remaining edge cases
- API client types are up to date with TeeKeysDto

---

_Phase: 08-tee-integration_
_Completed: 2026-02-07_
